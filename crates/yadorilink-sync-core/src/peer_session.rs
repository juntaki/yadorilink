//! The peer-to-peer sync protocol driver: runs over one
//! `yadorilink_transport::PeerChannel`, exchanging file indexes
//! and blocks directly with one peer device, with no central server
//! involved. One `PeerSyncSession` per connected peer (a peer
//! being offline only affects its own session, never blocks sync with
//! other reachable peers).
//!
//! ## Trust boundary: an authorized peer is not necessarily benign
//!
//! Every function in this module that handles data from `self.channel`
//! treats the connected peer as **authorized but untrusted**: it has
//! passed coordination-plane auth and its blocks pass the existing
//! hash+size check (`block_data_matches`), but its *choices* — what to
//! advertise in an index, what version vector or `mtime_unix_nanos` to
//! claim, what presence to report, what path to name — are adversarial
//! input, not trusted metadata. `reconcile_one_file`/`reconcile_files_if_
//! authorized` bound version-vector counter growth and incoming-index
//! cardinality (security hardening, security hardening); `resolve_and_apply_conflict`
//! bounds the accepted `mtime` skew (security hardening);
//! `handle_presence_signal` binds a presence signal to the authenticated
//! `peer_device_id` and validates its path (security hardening); `materialize`/
//! `hydrate_file_with_timeout` re-verify the resolved write target stays
//! under the sync root (security hardening). See `version_vector.rs`'s and
//! `conflict.rs`'s doc comments for why the version-vector and mtime
//! mitigations are explicitly **partial**, not a claim of full prevention
//! — a mutually-untrusted peer can always lie about its own causal
//! history to some degree; these bound the damage rather than eliminate it.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, Semaphore};
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::BlockStore;
use yadorilink_transport::PeerChannel;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::adaptive_window::AdaptiveWindow;
use crate::chunker::{
    apply_exec_bit, reconstruct_file, verify_write_target_within_canonical_root,
    verify_write_target_within_root, write_placeholder, MAX_BLOCK_SIZE,
};
use crate::conflict::{
    a_is_loser, combined_block_hash, is_conflict_copy_of, resolve_conflict_names,
};
use crate::content_crypto::{self, GroupKey};
use crate::error::SyncError;
use crate::hazard;
use crate::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use crate::index::SyncState;
use crate::materialization::check_disk_headroom;
use crate::presence::PresenceEvent;
use crate::rate_limiter::RateLimiters;
use crate::types::{
    BlockInfo, FileRecord, LinkMode, MaterializationPolicy, MaterializationState, RecordKind,
};
use crate::version_vector::{VvOrdering, MAX_VV_COUNTER_JUMP_PER_MESSAGE};

/// SEC-13 (see `run`'s recv loop, where this actually gates
/// concurrently-spawned inbound message handlers): the fixed, non-adaptive
/// per-peer concurrency ceiling. `AdaptiveWindow`'s `max` is constructed
/// to never exceed this — the
/// adaptive in-flight fetch window (`adaptive_window` field below) grows
/// and shrinks freely below it, but this remains the hard upper bound
/// nothing in this module can adapt past, so the new controller composes
/// with (rather than reintroduces a way around) the existing DoS bound.
const MAX_IN_FLIGHT_MESSAGES_PER_PEER: usize = 64;

/// Purely observational —
/// logged once (on the transition across this size, not repeatedly) when
/// `run`'s recv-loop's permit-wait queue (`pending`) grows past it, so a
/// peer sending faster than this device can drain becomes visible rather
/// than silently consuming more memory. NOT an enforced cap: `pending` is
/// deliberately unbounded (see its own doc comment in `run`) since capping
/// it would just relocate the exact deadlock this change fixes to a higher
/// threshold. Chosen as "clearly abnormal for any real catch-up batch"
/// (a laptop offline for weeks might have thousands of changed files, but
/// not tens of thousands in one connection's queue) rather than tuned
/// against a specific measurement.
const PENDING_QUEUE_WARN_THRESHOLD: usize = 10_000;

/// The adaptive window's starting
/// point for a fresh session — matches the pre-adaptive fixed lane count
/// `yadorilink-daemon::hydration`'s multi-peer dispatcher used
/// unconditionally before this change (`PER_PEER_IN_FLIGHT_WINDOW`), so
/// day-one throughput for an as-yet-unobserved peer is unchanged; the
/// window only diverges once real RTT/timeout signals arrive on this
/// session.
const ADAPTIVE_WINDOW_INITIAL: usize = 4;

/// The adaptive window's floor —
/// even a badly degraded peer keeps at least one in-flight `fetch_block`
/// slot, rather than being starved to zero (which would need a separate
/// "peer is unusable, stop trying" decision this controller doesn't make).
const ADAPTIVE_WINDOW_MIN: usize = 1;

/// security hardening: caps on how many `FileRecord`s, and how many total blocks
/// across all of them, a single incoming `FullIndex`/`IndexUpdate` message
/// may carry. Without this, a malicious/compromised group member can
/// advertise an index of arbitrarily many / arbitrarily large files —
/// every block is real, hash-valid content (the existing
/// `block_data_matches` check passes; dedup doesn't help since the
/// content is distinct), so nothing else stops an Eager folder group
/// (which has no `max_local_size_bytes` cap by default) from eagerly
/// fetching and writing all of it, exhausting local disk. A message
/// beyond either cap is rejected outright (`reconcile_files_if_authorized`
/// logs and drops it, processing none of its records) rather than
/// partially processed — the peer's next full-index resend (already
/// relied on elsewhere for eventual consistency) is expected to bring a
/// legitimately large folder within bounds via multiple smaller
/// `IndexUpdate`s, or the operator can split the group.
///
/// Chosen high enough that no legitimate single sync message (even an
/// initial `FullIndex` for a folder with tens of thousands of ordinary
/// files) should ever approach them — this is an admission ceiling
/// against a malicious advertisement, not a tuned-for-typical-workload
/// limit. Raw free-space enforcement itself is intentionally **not**
/// re-specified here; a minimum free-space headroom checked before every
/// write is owned by a separate, concurrent resource-governance mechanism —
/// this is the orthogonal, upstream control that limits how much a single
/// advertisement can demand before that guard even comes into play.
const MAX_FILES_PER_INDEX_MESSAGE: usize = 100_000;
const MAX_BLOCKS_PER_INDEX_MESSAGE: usize = 2_000_000;

/// zstd's low/fast compression level, used for
/// every trial/send compression pass in this module (block payloads and
/// index-exchange payloads alike) — chosen because the compression pass
/// runs synchronously in the send path (albeit off the async runtime, via
/// `spawn_blocking`) for every candidate payload and must not become the
/// sync engine's bottleneck.
const COMPRESSION_LEVEL: i32 = 3;

/// The sender always performs one low-level (`COMPRESSION_
/// LEVEL`) trial compression pass on a candidate payload, then keeps the
/// compressed form only if it beats this fraction of the raw size — a
/// "try-compress-and-compare" heuristic, not a separate entropy-sampling
/// pre-pass. This deliberately rejects that alternative (sampling first): it
/// would add a second full pass over the data for marginal savings over
/// just running the cheap level-3 pass once and checking the result size.
/// Already-compressed/incompressible content (media, archives, encrypted
/// files) naturally fails this check and is sent raw, at the cost of one
/// cheap compression attempt — never a second, wasted full-ratio pass.
const COMPRESSION_SKIP_THRESHOLD: f64 = 0.95;

/// A documented (not precisely derived)
/// ceiling on how large a decompressed `Index`/`IndexUpdate` payload may
/// be. Index messages aren't bounded by `MAX_BLOCK_SIZE` (that's a
/// per-block cap) the way `BlockResponse.data` is, so this exists purely
/// as this module's decompression-bomb guard for index payloads, applied
/// before the existing `MAX_FILES_PER_INDEX_MESSAGE`/
/// `MAX_BLOCKS_PER_INDEX_MESSAGE` cardinality check even gets a chance to
/// run (that check only sees an already-decoded message). Chosen
/// comfortably above any legitimate index at the cardinality caps
/// (100_000 files, 2_000_000 blocks worth of `FileInfo`/`BlockInfo`
/// encoding) while still bounding memory against a genuine bomb — the same
/// "admission ceiling, not a tuned-for-typical-workload limit" spirit as
/// those constants' own doc comment.
const MAX_DECOMPRESSED_INDEX_SIZE: usize = 256 * 1024 * 1024;

/// Compresses `data` at `COMPRESSION_
/// LEVEL` and keeps the compressed form only when it beats `COMPRESSION_
/// SKIP_THRESHOLD` of the raw size — otherwise (including on an
/// encoder error, or empty input, both treated as "not worth compressing"
/// rather than propagated, since sending raw bytes is always a safe
/// fallback) returns the original bytes tagged `Compression::None`. Pure
/// and synchronous — real CPU work for a multi-hundred-KB block, so every
/// caller in this module runs it inside `tokio::task::spawn_blocking`,
/// alongside the existing block-store I/O (PERF-1's same reasoning),
/// never directly on an async runtime worker thread.
fn compress_block(data: &[u8]) -> (Vec<u8>, proto::Compression) {
    if data.is_empty() {
        return (Vec::new(), proto::Compression::None);
    }
    match zstd::stream::encode_all(data, COMPRESSION_LEVEL) {
        Ok(compressed)
            if (compressed.len() as f64) < (data.len() as f64) * COMPRESSION_SKIP_THRESHOLD =>
        {
            (compressed, proto::Compression::Zstd)
        }
        _ => (data.to_vec(), proto::Compression::None),
    }
}

/// A decompression-bomb
/// bound: decompresses `data` per `declared_compression`, never
/// materializing more than `max_size + 1` bytes regardless of what the
/// compressed payload claims to expand to. This reads through a
/// `Read::take`-limited streaming decoder rather than an unbounded
/// `decode_all`-style call, so a hostile payload can't force this device
/// to allocate memory proportional to its *claimed* decompressed size
/// before this function gets a chance to reject it — the cap is enforced
/// during decompression, not after the fact on an already-materialized
/// buffer.
///
/// Callers treat an `Err` here the same way `ensure_blocks_present`
/// already treats a hash/size mismatch (`block_data_matches` returning
/// false) or a rejected index message: logged, the payload discarded, no
/// partial use of it — see `PeerSyncSession::handle_block_response`'s and
/// `PeerSyncSession::decode_index_files`'s doc comments for exactly which
/// existing reject-and-reassign path each reuses.
fn decompress_block(
    data: &[u8],
    declared_compression: proto::Compression,
    max_size: usize,
) -> Result<Vec<u8>, SyncError> {
    match declared_compression {
        proto::Compression::None => Ok(data.to_vec()),
        proto::Compression::Zstd => {
            let decoder = zstd::stream::read::Decoder::new(data).map_err(SyncError::Io)?;
            let mut limited = decoder.take(max_size as u64 + 1);
            let mut out = Vec::new();
            limited.read_to_end(&mut out).map_err(SyncError::Io)?;
            if out.len() > max_size {
                return Err(SyncError::from(std::io::Error::other(format!(
                    "decompressed payload exceeds the {max_size}-byte maximum \
                     (decompression-bomb guard)"
                ))));
            }
            Ok(out)
        }
    }
}

/// security hardening: the cardinality-cap check behind
/// `reconcile_files_if_authorized`, factored out as a free function taking
/// explicit `max_files`/`max_blocks` so it's unit-testable
/// (`cardinality_cap_tests` below) against small synthetic caps instead of
/// needing to build a `proto::FileInfo` list actually approaching the real
/// (deliberately huge) `MAX_FILES_PER_INDEX_MESSAGE`/
/// `MAX_BLOCKS_PER_INDEX_MESSAGE` constants just to exercise the boundary
/// logic itself.
fn index_message_exceeds_cardinality_cap(
    files: &[proto::FileInfo],
    max_files: usize,
    max_blocks: usize,
) -> bool {
    let total_blocks: usize = files.iter().map(|f| f.blocks.len()).sum();
    files.len() > max_files || total_blocks > max_blocks
}

/// security hardening: a per-(session, group) ceiling on how many blocks this
/// session will *eagerly* fetch and write for one folder group over its
/// lifetime — independent of, and in addition to, the per-message caps
/// above (those bound one large message; this bounds cumulative eager
/// admission across many smaller messages from the same connected peer,
/// e.g. a burst of `IndexUpdate`s each just under the per-message cap).
/// Once exhausted, further records that would otherwise be eagerly
/// fetched fall back to writing a placeholder instead (the same behavior
/// as an `OnDemand` group) — content is not lost or refused forever, it's
/// simply not eagerly pulled beyond the budget; an explicit pin still
/// always fetches (a deliberate, user-initiated request bypasses this
/// admission budget, same as it already bypasses the materialization
/// policy check below). Resets when this session ends (a new connection
/// starts a fresh budget) — bounding how much any *one* session can push
/// onto local disk eagerly, not a permanent per-group ceiling (that's
/// `max_local_size_bytes`, reactive eviction, and (out of scope here)
/// the separate free-space headroom mechanism).
const MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION: u64 = 200_000;

/// security hardening: the actual admission bookkeeping behind
/// `PeerSyncSession::admit_eager_blocks`, factored out as a free function
/// over an explicit `admission` map and `max_per_group` ceiling so it's
/// unit-testable (`eager_admission_tests` below) without constructing a
/// full `PeerSyncSession` (channel, state, store, ...) just to exercise
/// pure counter bookkeeping that never touches any of those. Attempts to
/// admit `block_count` more blocks for `group_id`; on success the group's
/// cumulative counter is incremented by `block_count` and `true` is
/// returned, on failure (would exceed `max_per_group`) the counter is left
/// unchanged and `false` is returned — the caller falls back to a
/// placeholder instead of eagerly fetching.
fn admit_eager_blocks_impl(
    admission: &mut HashMap<String, u64>,
    group_id: &str,
    block_count: u64,
    max_per_group: u64,
) -> bool {
    let used = admission.entry(group_id.to_string()).or_insert(0);
    match used.saturating_add(block_count) {
        new_total if new_total <= max_per_group => {
            *used = new_total;
            true
        }
        _ => false,
    }
}

/// PERF-5: cap on how many records from one incoming `FullIndex`/
/// `IndexUpdate` `reconcile_files` reconciles concurrently — see that
/// function's doc comment for why concurrent processing of *different*
/// paths is safe here. Bounded (not "spawn one task per record
/// unconditionally") for the same reason `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
/// bounds concurrently-spawned message handlers: a single large `FullIndex`
/// (an initial sync of a folder with thousands of files) shouldn't spawn
/// thousands of tasks — many of them concurrently awaiting a block-fetch
/// round trip from this same peer connection — all at once.
const MAX_CONCURRENT_RECONCILES: usize = 16;

// PERF-6: the payload waiters carry `Bytes`, not `Vec<u8>` — SEC-25 lets
// several concurrent local callers await the *same* in-flight block hash
// at once (multi-waiter), and `handle_block_response` below has to fan the
// one response out to every waiter. With `Vec<u8>` that fan-out was a full
// `payload.clone()` (a real memcpy of the whole block) per extra waiter;
// `Bytes::clone()` is a cheap refcounted handle to the same backing
// allocation, so N waiters for one hash now share one buffer instead of
// each getting an owned copy.
type PendingBlockRequests = StdMutex<HashMap<Vec<u8>, Vec<oneshot::Sender<FetchOutcome>>>>;

/// `handle_block_response` already
/// knows, in the moment, whether a peer's response was an explicit
/// `not_found` versus received-but-rejected (decompression failure, a
/// decompression-bomb bound exceeded) — this preserves that distinction
/// through to `fetch_block_raw`'s callers instead of collapsing both into
/// the same `None`, specifically so `ensure_blocks_present` can retry the
/// former (a transient race — the peer may simply not have finished
/// indexing/materializing this content yet) without also retrying the
/// latter (a bad/oversized/corrupt payload that won't become valid by
/// asking again — retrying it would only give a slow or malicious peer a
/// second, third, fourth chance to waste this device's time). `fetch_block`
/// (the existing public API, still used by `yadorilink-daemon`'s multi-peer
/// hydration dispatcher, which already has its own faster "try a different
/// peer" fallback for either case and doesn't need this distinction) keeps
/// collapsing both into `None`, unchanged.
#[derive(Clone, Debug)]
enum FetchOutcome {
    Found(Bytes),
    /// The peer explicitly reported `not_found`, or the request's reply
    /// channel closed without ever answering (e.g. the session ended).
    NotFound,
    /// A response arrived but this device could not use it (decompression
    /// failure, decompression-bomb bound exceeded, a malformed ciphertext
    /// nonce, or similar) — deliberately distinct from `NotFound` (see
    /// this enum's own doc comment).
    Unusable,
}

impl FetchOutcome {
    fn into_bytes(self) -> Option<Bytes> {
        match self {
            FetchOutcome::Found(data) => Some(data),
            FetchOutcome::NotFound | FetchOutcome::Unusable => None,
        }
    }
}

/// COR-9: `fetch_block` used to `insert` into `pending_block_requests` and
/// rely solely on `handle_block_response` to `remove` it — but a caller
/// wrapping `fetch_block` in a timeout (as `hydrate_file`/
/// `ensure_blocks_present` both do) drops the `fetch_block` future, and
/// therefore its local `rx`, without ever running `handle_block_response`
/// for that hash. Nothing else ever removed the now-orphaned entry, so a
/// timed-out or cancelled fetch leaked one `HashMap` entry forever — on a
/// long-running daemon with an unreachable peer, unboundedly. This RAII
/// guard removes its entry on drop, but only when the sender is
/// `is_closed()` (its matching `rx` was dropped without ever receiving a
/// response) — the ordinary, already-fulfilled-by-`handle_block_response`
/// path already removed the entry itself, so the guard's own drop then
/// finds nothing there and no-ops; and if a *newer* request for the same
/// hash was inserted in between (two concurrent fetches for an
/// identical block, SEC-25's territory), that still-open sender remains
/// in the per-hash waiter list while only closed waiters are pruned.
struct PendingBlockGuard<'a> {
    pending: &'a PendingBlockRequests,
    hash: Vec<u8>,
}

impl Drop for PendingBlockGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(waiters) = pending.get_mut(&self.hash) else { return };
        waiters.retain(|tx| !tx.is_closed());
        if waiters.is_empty() {
            pending.remove(&self.hash);
        }
    }
}

/// What a ciphertext `BlockRequest`
/// waiter (`fetch_block_from_storage_peer`) receives once a matching
/// `BlockResponse` with `is_ciphertext = true` arrives — the raw
/// ciphertext bytes plus the nonce needed to decrypt them (`content_
/// crypto::decrypt_block`). Deliberately a *separate* waiter map/payload
/// type from `PendingBlockRequests`/`Bytes` above, not a shared one: the
/// ordinary plaintext path (`fetch_block`, `handle_block_response`'s
/// non-ciphertext branch) is completely untouched by this addition, per
/// the encrypted-peer spec's "a group with no untrusted peers behaves
/// exactly as today" — the two waiter mechanisms only interact at the
/// single `handle_block_response` dispatch point, which branches on the
/// wire's own `resp.is_ciphertext` flag to decide which map a given
/// response resolves against (a hash collision between the two spaces
/// cannot cross-resolve into the wrong map, since only one map is ever
/// consulted per response).
#[derive(Clone)]
struct CiphertextBlockPayload {
    data: Bytes,
    nonce: [u8; content_crypto::NONCE_LEN],
}

type PendingCiphertextBlockRequests =
    StdMutex<HashMap<Vec<u8>, Vec<oneshot::Sender<Option<CiphertextBlockPayload>>>>>;

/// ciphertext_hash -> the AEAD nonce it was stored with, shared
/// across every `PeerSyncSession` a storage-only device runs — see
/// `PeerSyncSession::set_ciphertext_nonce_cache`'s doc comment.
pub type CiphertextNonceCache = Arc<StdMutex<HashMap<Vec<u8>, [u8; content_crypto::NONCE_LEN]>>>;

/// The ciphertext-waiter analogue of `PendingBlockGuard` — same leak-guard
/// rationale (COR-9), duplicated rather than made generic over both waiter
/// maps so the plaintext path's existing type stays untouched.
struct PendingCiphertextBlockGuard<'a> {
    pending: &'a PendingCiphertextBlockRequests,
    hash: Vec<u8>,
}

impl Drop for PendingCiphertextBlockGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(waiters) = pending.get_mut(&self.hash) else { return };
        waiters.retain(|tx| !tx.is_closed());
        if waiters.is_empty() {
            pending.remove(&self.hash);
        }
    }
}

/// Materializes a non-deleted symlink
/// record at `group_id`/`record.path` under `root`. Factored out as a
/// free function (explicit `state`/`root`/`group_id`/`record` rather than
/// a `PeerSyncSession` receiver) purely for direct unit-testability — the
/// same reason `index_message_exceeds_cardinality_cap`/
/// `admit_eager_blocks_impl` above are free functions: a symlink record
/// carries no blocks at all (D1), so materializing one needs no
/// peer/channel access whatsoever, unlike ordinary file
/// materialization/hydration.
///
/// **Wire-schema gap, documented rather than papered over**: today's
/// `proto::FileInfo` (`yadorilink-ipc-proto`, not yet implemented) carries
/// no `record_kind`/`symlink_target` field,
/// so a peer's incoming index message cannot yet actually tell this
/// device "this path is a symlink" — `PeerSyncSession::materialize`
/// (this function's only caller) decides whether to route a given path
/// through here by consulting `SyncState::get_record_kind`, i.e. *this
/// device's own already-recorded* classification for that path. That is
/// correct and sufficient once a peer's advertised kind is wired
/// through to a `set_record_kind` call before reconciliation reaches this
/// point (the natural extension seam); until then, this function is real,
/// tested, and ready, but a symlink genuinely cannot cross the wire from
/// a peer that classified it during section 2's scan/watch path on a
/// *different* device.
fn materialize_symlink_at(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    windows_opt_in: bool,
    origin_device_id: &str,
) -> Result<(), SyncError> {
    state.upsert_file_with_origin(group_id, record, origin_device_id)?;
    let out_path = root.join(&record.path);
    // security hardening defense-in-depth, same as every other materialization
    // write path in this module — see `verify_write_target_within_root`'s
    // doc comment.
    verify_write_target_within_root(&out_path, root)?;

    let Some(target) = state.get_symlink_target(group_id, &record.path)? else {
        // No target recorded for a record classified as a symlink — there
        // is nothing safe to create. The index row is still updated above
        // (so a later correction still syncs normally), but skip the
        // on-disk write rather than create a broken/empty link.
        tracing::warn!(
            path = %record.path,
            group_id,
            "symlink record has no recorded target; skipping on-disk materialization"
        );
        return Ok(());
    };

    #[cfg(unix)]
    {
        let _ = windows_opt_in; // only meaningful on Windows
        crate::chunker::materialize_symlink(&out_path, &target)
    }
    #[cfg(windows)]
    {
        // Default is skip-with-visible-status — the record was
        // already adopted into the index above (so it still syncs
        // correctly onward to a POSIX peer), but nothing is written to
        // disk here unless this link explicitly opted in.
        if windows_opt_in {
            crate::chunker::materialize_symlink_windows(&out_path, &target)
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = target;
        Ok(())
    }
}

/// If `record`'s block list is byte-identical
/// to what's already indexed locally for this path (content provably
/// unchanged — the same block hashes, in the same order, describe both),
/// this applies just the owner-executable bit currently recorded in the
/// local index for the path and updates the index row's own
/// version/mtime/deleted bookkeeping — without calling
/// `ensure_blocks_present` or `reconstruct_file` at all, i.e. without any
/// network round trip or full-file rewrite. Returns whether the fast path
/// applied; `false` means the caller must fall through to ordinary
/// fetch/reconstruct handling (no local record existed yet for this path,
/// the content actually changed, or the file is unexpectedly missing from
/// disk — see the disk/index divergence note below).
///
/// See `materialize_symlink_at`'s doc comment for the same wire-schema
/// caveat: `proto::FileInfo` has no exec-bit field yet, so
/// "the bit this applies" is this device's own already-recorded value for
/// the path, not literally something read off the incoming wire message.
/// This is still exactly the mechanism the receiving side needs — once a
/// peer's advertised bit is wired through to a `set_exec_bit` call ahead
/// of reconciliation, this fast path picks it up correctly with no
/// further changes.
///
/// This fast path assumes the
/// file is still sitting on disk from whenever it was last actually
/// written (this function itself never writes content) — that assumption
/// can be false (e.g. a real local deletion raced this incoming record,
/// with the local watcher/debounce pipeline not having indexed that
/// deletion yet). The disk-existence check below runs *before* the index
/// write commits, specifically so a stale-but-plausible-looking local
/// index row can never be refreshed into a permanently wrong "hydrated
/// and present" state — falling through to the caller's ordinary
/// reconstruct path (which actually (re)writes the file) is always safe
/// here, just slower than the fast path in the common case. The previous
/// version of this function instead committed the index write first and
/// only discovered a missing file afterward, incidentally, via
/// `apply_exec_bit`'s Unix-only `fs::metadata` call — whose error was
/// silently logged and discarded by the caller (`reconcile_one_file`'s
/// own caller, a `tracing::warn!` with no rollback), and which never
/// fired at all on Windows (`apply_exec_bit` is a no-op there), making
/// the corruption completely silent on that platform.
fn try_apply_metadata_only_update(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
) -> Result<bool, SyncError> {
    let Some(local) = state.get_file(group_id, &record.path)? else { return Ok(false) };
    if local.deleted || record.blocks.is_empty() || local.blocks != record.blocks {
        return Ok(false);
    }
    let out_path = root.join(&record.path);
    verify_write_target_within_root(&out_path, root)?;
    if !out_path.exists() {
        return Ok(false);
    }
    state.upsert_file_with_origin(group_id, record, origin_device_id)?;
    apply_exec_bit(&out_path, state.get_exec_bit(group_id, &record.path)?)?;
    Ok(true)
}

/// Under `madsim`, `SystemTime::now()` reads a per-seed *virtual* clock
/// (madsim intercepts `gettimeofday`/`clock_gettime`) — but a real
/// filesystem's `mtime` does not go through that interception (the kernel
/// stamps it independently at write time), so a real-fs write during a
/// DST run gets a *real* wall-clock mtime while `now_unix_nanos()` reads
/// madsim's *virtual*, epoch-relative one. Comparing the two (`clamp_
/// future_mtime`/`a_is_loser` in `conflict.rs`) puts every mtime far in
/// virtual-"now"'s future, so the skew clamp fires unconditionally — an
/// unrealistic regime (production has both on the same real clock) that
/// also amplifies otherwise-tiny scheduling jitter (e.g. the r2d2 SQLite
/// connection pool's background thread, which runs on a real, non-
/// deterministically-scheduled OS thread) into a visibly different tie-
/// break outcome across replays of the *same* seed. This override lets a
/// DST harness put `now_unix_nanos()` back on the *same* synthetic
/// timeline it also stamps onto its own written files' mtimes (see
/// `dst_two_device_chaos.rs`'s round loop), closing both the fidelity gap
/// and the replay non-determinism it was quietly amplifying. Unset in
/// production and in any test that never calls `set_test_clock_override`
/// — `now_unix_nanos()` then falls through to the real `SystemTime::now()`
/// exactly as before this existed.
#[cfg(madsim)]
static DETERMINISTIC_CLOCK_OVERRIDE: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
    std::sync::OnceLock::new();

/// Test-only: pins `now_unix_nanos()` (every call site, process-wide) to
/// `nanos` until the next call. Safe as a single un-scoped override only
/// because of this crate's own DST convention (`dst_two_device_chaos.rs`'s
/// doc comment): one network-touching `#[test]` fn per binary, seeds run
/// strictly sequentially within it — never two scenarios' clocks racing
/// in the same process.
#[cfg(madsim)]
pub fn set_test_clock_override(nanos: i64) {
    DETERMINISTIC_CLOCK_OVERRIDE
        .get_or_init(|| std::sync::atomic::AtomicI64::new(nanos))
        .store(nanos, std::sync::atomic::Ordering::SeqCst);
}

/// The current wall-clock time as
/// `held_since_unix_nanos` — same shape as `resolve_and_apply_conflict`'s
/// own `now_unix_nanos` need (kept as a small shared free function rather
/// than duplicated further, since `hold_record`'s and `hydrate_file_with_
/// timeout`'s hazard branches both need it too).
fn now_unix_nanos() -> i64 {
    #[cfg(madsim)]
    if let Some(override_nanos) = DETERMINISTIC_CLOCK_OVERRIDE.get() {
        return override_nanos.load(std::sync::atomic::Ordering::SeqCst);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// A thin wrapper so every call site below
/// needs only one `#[allow(deprecated)]`, not nine. `madsim`'s tokio
/// shim marks `spawn_blocking` deprecated ("blocking function is not
/// allowed in simulation") because it still runs on a real, non-
/// simulated OS thread under madsim rather than being scheduled
/// deterministically — a known, tracked gap (disk/CPU-bound block-store
/// I/O determinism is deferred to a future `MaterializeIo` abstraction),
/// not something this wrapper is meant to silently paper
/// over for good.
#[allow(deprecated)]
fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// Bounded retry
/// parameters for a `reconcile_one_file` call failing transiently — see
/// its call site's doc comment (the `in_flight.spawn` dispatch loop) for
/// the specific race this is sized for. Same shape as the
/// `NOT_FOUND_RETRY_*` constants used for block-fetch retries
/// (bounded attempts, fixed delay with jitter to avoid synchronized retry
/// bursts) — free functions/constants rather than `PeerSyncSession`
/// associated items since the retry loop lives inside a `'static`
/// `tokio::spawn`'d closure, not a `&self` method.
const RECONCILE_RETRY_ATTEMPTS: u32 = 5;
const RECONCILE_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const RECONCILE_RETRY_JITTER_FRACTION: f64 = 0.25;

fn reconcile_retry_delay() -> std::time::Duration {
    let jitter =
        rand::random_range(-RECONCILE_RETRY_JITTER_FRACTION..=RECONCILE_RETRY_JITTER_FRACTION);
    RECONCILE_RETRY_BASE_DELAY.mul_f64(1.0 + jitter)
}

/// Lets `reconcile_one_file`
/// ask whether the path it's about to reconcile against a peer's update
/// has a local change still sitting, undispatched, in that link's debounce
/// accumulator (`debounce::run_debouncer`'s `FlushPathRequest` handling) —
/// and if so, force it to flush and be captured into the index *before*
/// `reconcile_one_file`'s version-vector `compare()` runs or `materialize`
/// writes to the path, so a peer's write or tombstone for the same path
/// can never race ahead of it.
///
/// `yadorilink-sync-core` has no concept of the debounce accumulator or its
/// channels at all (`debounce.rs` knows nothing about indexing/peers, and
/// the accumulator itself is owned per-link by `yadorilink-daemon::
/// link_manager`, not by this crate) — so this is expressed as a
/// caller-injected trait object, the same "daemon injects real behavior
/// into a session after construction" shape as `rate_limiters`/
/// `headroom_override_bytes`/`full_index_resync_interval` above, rather
/// than a new constructor parameter every existing call site (every test,
/// every daemon construction site) would otherwise need to grow.
///
/// A manually-written `Pin<Box<dyn Future>>`-returning method, not an
/// `async fn`, since this needs to be *dyn*-callable through
/// `Arc<dyn PendingLocalChangeFlush>` — native `async fn` in traits isn't
/// object-safe without this same boilerplate, and this crate has no
/// `async_trait` dependency to hide it behind.
pub trait PendingLocalChangeFlush: Send + Sync {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// Like `flush_pending_local_change`, but for the *other* case-variant
    /// path that would collide with `rel_path` on a case-insensitive
    /// filesystem, rather than `rel_path` itself — see
    /// `PeerSyncSession::flush_case_fold_sibling_before_reconcile`'s doc
    /// comment for why this exists as a separate call.
    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// The actual hazard-detection logic
/// behind `PeerSyncSession::hazard_reason_for`, factored out as a free
/// function (explicit `state`/`root`/`group_id`/`record`/`policy` rather
/// than a `PeerSyncSession` receiver) for the same reason
/// `materialize_symlink_at`/`try_apply_metadata_only_update` above are
/// free functions: direct unit-testability with just a `SyncState` +
/// tempdir, no live `PeerChannel` needed (`hazard_reason_tests` below).
///
/// Composes `hazard::invalid_name_reason` and
/// `hazard::case_fold_collision` (only even queried when
/// `hazard::is_case_insensitive_filesystem` says `root`'s filesystem
/// actually needs the check) — `None` means safe to materialize normally.
///
/// Taking an explicit `policy` (rather than hardcoding `NamePolicy::
/// local()` here) is what makes a "held on a Windows-policy test
/// target, materializes normally on a POSIX-policy test target, from the
/// same index state" scenario directly testable in one process regardless
/// of which platform actually runs the test suite —
/// `PeerSyncSession::hazard_reason_for` (this function's only production
/// caller) always passes `hazard::NamePolicy::local()`.
///
/// Computed fresh on every call — not itself cached beyond
/// `is_case_insensitive_filesystem`'s own per-root probe cache — so a
/// record whose hazard has since resolved (the colliding sibling was
/// renamed/deleted, or an invalid name was fixed at the source) is
/// correctly recognized as no-longer-hazardous the next time this path is
/// reconciled. A peer's periodic full-index resend (already relied on
/// elsewhere for eventual consistency) is what actually triggers that next
/// reconcile — this crate has no separate "re-check every held file"
/// sweep; documented as a gap, not an oversight.
fn hazard_reason_for_policy(
    state: &SyncState,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    policy: hazard::NamePolicy,
) -> Result<Option<String>, SyncError> {
    if let Some(reason) = hazard::invalid_name_reason(policy, &record.path) {
        return Ok(Some(reason));
    }
    if hazard::is_case_insensitive_filesystem(root) {
        let siblings = state.list_files(group_id)?;
        if let Some(colliding) = hazard::case_fold_collision(&record.path, &siblings) {
            return Ok(Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_CASE_COLLISION,
                colliding.path
            )));
        }
    }
    Ok(None)
}

/// The actual held-state bookkeeping
/// behind `PeerSyncSession::hold`, factored out the same way as
/// `hazard_reason_for_policy` above for direct unit-testability. Adopts
/// `record` into the index (`upsert_file` — a held record keeps
/// participating in ordinary index exchange/forwarding, since
/// `reconcile_one_file`'s callers `forward` a record regardless of what
/// `materialize` itself did with it) and marks it held with `reason`
/// (`SyncState::set_held`), without ever reaching an atomic on-disk write
/// step for this path. Never renames, never writes under any alternate
/// name — the only two effects this has are an
/// index upsert and a held-state write; see
/// `no_hazard_ever_writes_under_any_alternate_name` (in
/// `tests/peer_session.rs`) for a regression test asserting exactly that
/// through the real, wire-driven `materialize` path.
fn hold_record(
    state: &SyncState,
    group_id: &str,
    record: &FileRecord,
    reason: &str,
    origin_device_id: &str,
) -> Result<(), SyncError> {
    state.upsert_file_with_origin(group_id, record, origin_device_id)?;
    state.set_held(group_id, &record.path, reason, now_unix_nanos())?;
    tracing::info!(
        path = %record.path,
        group_id,
        reason,
        "holding file due to a filename hazard (case-fold collision or platform-invalid \
         name); not materialized under any name on this device"
    );
    Ok(())
}

/// Closes a wire-serialization gap (see
/// `types.rs`'s doc comments on both `FileRecord`/`proto::FileInfo` `From`
/// impls for the full story): maps the wire enum's raw `i32` (an unknown
/// or absent value decodes as `Unspecified`, proto3's zero value) onto this
/// crate's own `RecordKind`, treating `Unspecified` the same as `File` —
/// exactly the "pre-this-change record" compatibility behavior
/// `sync.proto`'s `RecordKind` doc comment specifies.
fn domain_record_kind_from_proto(raw: i32) -> RecordKind {
    match proto::RecordKind::try_from(raw).unwrap_or(proto::RecordKind::Unspecified) {
        proto::RecordKind::Symlink => RecordKind::Symlink,
        proto::RecordKind::Directory => RecordKind::Directory,
        proto::RecordKind::Unspecified | proto::RecordKind::File => RecordKind::File,
    }
}

/// The reverse mapping of `domain_record_kind_from_proto`, used on the
/// sending side (`file_info_for_record`) to populate an outgoing
/// `proto::FileInfo.record_kind` from this device's own indexed
/// `RecordKind`.
fn proto_record_kind_from_domain(kind: RecordKind) -> proto::RecordKind {
    match kind {
        RecordKind::File => proto::RecordKind::File,
        RecordKind::Directory => proto::RecordKind::Directory,
        RecordKind::Symlink => proto::RecordKind::Symlink,
    }
}

/// The four symlink/exec-bit fields carried on an incoming peer's
/// `proto::FileInfo` (fields 7-10) that `FileRecord`'s
/// `From<proto::FileInfo>` conversion structurally cannot carry (see
/// `types.rs`). Captured from the *original* `proto::FileInfo` before that
/// conversion runs (`reconcile_files` does this), and threaded alongside
/// the resulting `FileRecord` through `reconcile_one_file`/
/// `resolve_and_apply_conflict` so `apply_incoming_wire_metadata` can
/// persist it into `SyncState` at the record's *final* path — which can
/// differ from the wire path when a concurrent-edit conflict renames it —
/// immediately before `materialize` is called, since `materialize`'s own
/// symlink dispatch (`SyncState::get_record_kind`) reads the local index,
/// never the wire message directly.
#[derive(Clone, Debug)]
struct IncomingWireMeta {
    record_kind: RecordKind,
    symlink_target: Option<String>,
    symlink_out_of_root: bool,
    exec_bit: bool,
    /// The device that
    /// actually produced this incoming record's content, per the sending
    /// peer's own `SyncState::get_origin_device_id` lookup (see
    /// `file_info_for_record`). `None` when absent/empty on the wire — an
    /// older peer that predates this field, or a row that peer never
    /// recorded an origin for — callers fall back to `self.peer_device_id`
    /// in that case, matching the pre-this-fix assumption.
    origin_device_id: Option<String>,
}

impl From<&proto::FileInfo> for IncomingWireMeta {
    fn from(info: &proto::FileInfo) -> Self {
        IncomingWireMeta {
            record_kind: domain_record_kind_from_proto(info.record_kind),
            symlink_target: info.symlink_target.clone(),
            symlink_out_of_root: info.symlink_out_of_root_or_absolute,
            exec_bit: info.exec_bit,
            origin_device_id: (!info.origin_device_id.is_empty())
                .then(|| info.origin_device_id.clone()),
        }
    }
}

/// Closes a wire-serialization handoff gap (see `types.rs`'s doc comments
/// for the precise gap this fills):
/// persists an incoming peer's advertised `record_kind`/`symlink_target`/
/// `symlink_out_of_root`/`exec_bit` into `SyncState` at `record.path`,
/// which must be `record`'s *final* target path (post-conflict-rename, if
/// any) — the same path `materialize` is about to be called for.
///
/// **Correctness-critical: never upserts `record`'s real content fields
/// over an existing row.** Every one of the four setters below is an
/// `UPDATE ... WHERE group_id = ?, path = ?` that errors with
/// `SyncError::NotFound` if no row exists yet for this path (see
/// `index.rs`'s `set_record_kind`/etc. doc comments), so *some* row must
/// exist first. The first, broken version of this function called
/// `state.upsert_file(group_id, record)` unconditionally to guarantee
/// that — which introduced a real regression, caught by this change's own
/// two-peer wire test (`tests/peer_session.rs`): `materialize`'s
/// `try_apply_metadata_only_update` fast-paths whenever the
/// path's *already-indexed* blocks equal the incoming record's blocks,
/// skipping the real fetch/write and just chmod'ing the (assumed
/// already-on-disk) file. Pre-upserting `record` here made that
/// comparison compare `record` against itself — trivially equal, every
/// time, for *every* brand-new file — so the fast path fired for a file
/// whose content was never actually written to disk, and the chmod call
/// failed with `ENOENT`. The fix: only create a row when none exists yet
/// (a path this device has genuinely never seen before), and when
/// creating one, use an **empty block list** regardless of `record`'s
/// real blocks — structurally guaranteed to differ from any real,
/// non-empty content the same message is about to deliver, so
/// `try_apply_metadata_only_update`'s comparison (or its own
/// `record.blocks.is_empty()` guard, for a genuinely empty file) correctly
/// falls through to a real fetch/write. When a row *does* already exist
/// (an update to a previously-seen path), it is left completely untouched
/// here — its old content fields are exactly what `try_apply_metadata_
/// only_update` needs to compare the incoming record against.
///
/// Factored out as a free function (matching `materialize_symlink_at`/
/// `try_apply_metadata_only_update`/`hazard_reason_for_policy` before it)
/// for direct unit-testability without a live `PeerChannel`.
fn apply_incoming_wire_metadata(
    state: &SyncState,
    group_id: &str,
    record: &FileRecord,
    meta: &IncomingWireMeta,
) -> Result<(), SyncError> {
    // This was `state.upsert_file(group_id, &FileRecord
    // { blocks: Vec::new(), ..record.clone() })` guarded by the same
    // `is_none()` check — that call now goes through the version-retaining
    // `upsert_file_in_tx` path, which would otherwise record
    // this empty bootstrap row as a genuine (if short-lived) superseded
    // version once `materialize` immediately upserts the real content
    // moments later, leaving every peer-adopted file's history with a
    // spurious empty first version. `ensure_bootstrap_row_for_metadata`
    // creates the same kind of scaffold row `SyncState`'s own
    // `files_supersede_prior_current` trigger recognizes and *deletes*
    // (rather than supersedes) on the next real upsert — see that
    // function's and the trigger's doc comments for the full mechanism.
    state.ensure_bootstrap_row_for_metadata(group_id, &record.path)?;
    state.set_record_kind(group_id, &record.path, meta.record_kind)?;
    state.set_symlink_target(group_id, &record.path, meta.symlink_target.as_deref())?;
    state.set_symlink_out_of_root(group_id, &record.path, meta.symlink_out_of_root)?;
    state.set_exec_bit(group_id, &record.path, meta.exec_bit)?;
    Ok(())
}

/// On-demand sync's default hydration timeout.
pub const DEFAULT_HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default interval between
/// this session's periodic, self-initiated full-index resends to its peer
/// (see `run`'s independent resync task, and `send_full_index`, which this
/// reuses verbatim). Exists because `ClusterConfig`/the initial
/// `send_full_index` in `run` is otherwise sent exactly once per session —
/// if a reconcile attempt is dropped after timing out while
/// `MAX_IN_FLIGHT_MESSAGES_PER_PEER` is saturated (see `reconcile_one_file`'s
/// `eager_admitted` branch doc comment for the exact head-of-line-blocking
/// mechanism: the recv loop can be stuck acquiring a permit for an ordinary
/// control message while the very `BlockResponse`s that would free up
/// permits are queued behind it on the same connection), nothing else ever
/// revisits that path — the device silently never converges until a daemon
/// restart, which re-triggers the identical race under the same burst
/// (verified via `load_many_small_files`/`live_burst_batching`, which
/// reproduced
/// a genuinely *permanent* stall, file counts flat for 5+ minutes past the
/// old 180s timeout). A periodic resync is self-healing by construction —
/// it re-discovers and re-reconciles ANY path that fell out of sync for ANY
/// reason, not just this specific failure mode (deliberately riding an
/// existing mechanism) — at the cost of re-sending the *entire*
/// index (bandwidth proportional to total linked-folder file count, not
/// just the burst size) every interval, for the life of the session.
///
/// The exact value was left to whoever implemented
/// this, explicitly prioritizing "keeps `live_burst_batching`/
/// `load_many_small_files` genuinely (not just accidentally) passing within
/// their current test timeouts" over a conservative 10-15 minute figure:
/// those two daemon E2E tests exercise
/// this exact stall through the real `yadorilink-daemon` stack with no way
/// to inject a shorter test-only interval, and their `CONVERGENCE_TIMEOUT`
/// is 180s (already loosened once for
/// environmental slowness — raising it again to accommodate a
/// double-digit-minutes interval would just be re-hiding this same bug
/// under a bigger number). 90 seconds leaves roughly half of that 180s
/// budget for the resync to fire and the handful of still-missing files to
/// actually reconcile afterward, while still being infrequent enough (40
/// resends/hour) that the bandwidth cost documented in the README's
/// "Content-defined chunking"/"Transfer compression"-style section is
/// honest about the trade-off rather than negligible. A deployment
/// syncing a very large linked folder over a slow/metered link should
/// increase this via `set_full_index_resync_interval`.
pub const DEFAULT_FULL_INDEX_RESYNC_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(90);

/// This session's *current*
/// view of which folder groups its peer is authorized for, as distinct
/// from `PeerSyncSession::shared_group_ids` (the snapshot captured once at
/// construction from whatever netmap/ACL state was available at connect
/// time — still used for the initial `ClusterConfig`/`FullIndex` handshake
/// in `run`, since which groups to open a session for at all is a
/// connect-time decision, not a per-request one).
///
/// Push model, not per-request coordination-plane checks:
/// nothing in this crate ever calls back to the coordination plane to
/// populate or consult this. It is a purely local, cheaply-read cache — a
/// `Mutex`-guarded `HashSet` lookup per request, no I/O, no network round
/// trip — that a caller outside this crate (the daemon's netmap-diff-driven
/// teardown reaction) is expected to keep in sync
/// with the actual current netmap/ACL state via
/// `PeerSyncSession::revoke_group`/`grant_group`/`set_authorized_groups`
/// whenever a netmap update changes this peer's authorized groups. Until
/// that daemon-level wiring calls one of those, this starts out — and
/// remains — identical to `shared_group_ids`, i.e. every existing caller
/// that never touches the new methods sees exactly the pre-existing
/// behavior.
#[derive(Debug)]
struct LiveGroupAuthorization {
    groups: StdMutex<std::collections::HashSet<String>>,
}

impl LiveGroupAuthorization {
    fn new(initial: &[String]) -> Self {
        Self { groups: StdMutex::new(initial.iter().cloned().collect()) }
    }

    fn contains(&self, group_id: &str) -> bool {
        self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(group_id)
    }

    fn revoke(&self, group_id: &str) {
        self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(group_id);
    }

    fn grant(&self, group_id: &str) {
        self.groups
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string());
    }

    fn set(&self, group_ids: impl IntoIterator<Item = String>) {
        *self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            group_ids.into_iter().collect();
    }
}

/// The permission this (local) device has
/// granted its peer for one shared folder group. Kept as a small
/// crate-local enum rather than a shared coordination type: this crate only
/// knows about authorized folder groups, not accounts or ACL storage. The
/// caller feeds it group ids and roles computed
/// elsewhere) is expected to translate a `coordination.proto`
/// `ShareRole`/`PeerInfo.shared_group_roles` entry into this before calling
/// `set_peer_role`/`set_peer_roles` below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Read,
    Write,
}

/// This session's current view of the role
/// (`PeerRole::Read` or `PeerRole::Write`) this peer holds for each shared
/// folder group — i.e. the permission *this* (local, sharer) device
/// granted the peer, consulted by `reconcile_files_if_authorized` to
/// decide whether to accept an inbound index update from this peer at
/// all. Mirrors `LiveGroupAuthorization` in every respect (see its doc
/// comment): a purely local, cheaply-read `Mutex`-guarded map — no I/O, no
/// coordination-plane round trip — that a caller outside this crate is
/// expected to keep in sync with the current ACL/netmap role state via
/// `PeerSyncSession::set_peer_role`/`set_peer_roles` whenever a netmap
/// update changes this peer's role for a group (a `read`/`write` role
/// change takes effect on the very next message, not only
/// at session setup).
///
/// A group with no entry defaults to `PeerRole::Write` (`role_for`) —
/// matching the `acl.role` column's own default for pre-existing,
/// same-account edges — so every existing caller that never touches
/// `set_peer_role`/`set_peer_roles` sees exactly the pre-existing (full
/// read-write) behavior, the same backward-compatibility guarantee
/// `LiveGroupAuthorization` documents for `shares_group`.
#[derive(Debug)]
struct LiveGroupRoles {
    roles: StdMutex<HashMap<String, PeerRole>>,
}

impl LiveGroupRoles {
    fn new() -> Self {
        Self { roles: StdMutex::new(HashMap::new()) }
    }

    fn role_for(&self, group_id: &str) -> PeerRole {
        self.roles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
            .copied()
            .unwrap_or(PeerRole::Write)
    }

    fn set(&self, group_id: &str, role: PeerRole) {
        self.roles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), role);
    }

    fn set_all(&self, roles: impl IntoIterator<Item = (String, PeerRole)>) {
        *self.roles.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            roles.into_iter().collect();
    }
}

/// This session's current view of
/// whether *this peer* is flagged storage-only (untrusted) for each shared
/// folder group — populated from the coordination plane's ACL/netmap the
/// same way `LiveGroupRoles` is (see that struct's doc comment for the
/// full rationale; this mirrors it exactly, including the "live,
/// mutable-after-construction, no coordination-plane round trip per
/// lookup" shape). A group missing from this map defaults to `false`
/// (trusted) — the encrypted-peer spec's "a group with no untrusted peers
/// behaves exactly as today" invariant: nothing in this crate ever treats
/// an absent entry as storage-only, so a caller that never calls
/// `set_storage_only`/`set_storage_only_flags` (every existing test and
/// call site, until a daemon-level netmap reaction populates this) sees
/// exactly today's plaintext-everywhere behavior.
#[derive(Debug)]
struct LiveStorageOnlyFlags {
    flags: StdMutex<HashMap<String, bool>>,
}

impl LiveStorageOnlyFlags {
    fn new() -> Self {
        Self { flags: StdMutex::new(HashMap::new()) }
    }

    fn is_storage_only(&self, group_id: &str) -> bool {
        self.flags
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
            .copied()
            .unwrap_or(false)
    }

    fn set(&self, group_id: &str, storage_only: bool) {
        self.flags
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), storage_only);
    }

    fn set_all(&self, flags: impl IntoIterator<Item = (String, bool)>) {
        *self.flags.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            flags.into_iter().collect();
    }
}

/// The group content-encryption key this device holds for one
/// folder group, plus whether that group uses convergent (deterministic
/// nonce, cross-device/cross-file dedup on the untrusted peer) or
/// non-convergent (random nonce, no dedup — the per-group opt-out for
/// higher-sensitivity groups) block encryption. `None` for a group in
/// `PeerSyncSession::group_keys` — meaning either "no untrusted storage
/// peer is configured for this group at all" (the common case; behaves
/// exactly as today) or "this device is itself the storage-only device for
/// this group" (see `local_storage_only_groups`) — both leave `send_full_
/// index`/`handle_ciphertext_block_request` unable to produce plaintext-
/// derived ciphertext, which is the safe direction for an ambiguous state
/// to fail in.
#[derive(Clone)]
struct GroupKeyState {
    key: GroupKey,
    convergent: bool,
}

pub struct PeerSyncSession {
    channel: Arc<PeerChannel>,
    local_device_id: String,
    peer_device_id: String,
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
    /// Folder groups both this device and the peer are authorized for
    /// (determined by the caller from the coordination plane's ACLs —
    /// this crate has no concept of authorization itself).
    shared_group_ids: Vec<String>,
    /// The session's live,
    /// mutable-after-construction view of peer authorization, consulted by
    /// `shares_group` (and therefore by every per-request authorization
    /// check that calls it — `handle_block_request`,
    /// `reconcile_files_if_authorized`, `handle_presence_signal`) instead
    /// of `shared_group_ids` above. See `LiveGroupAuthorization`'s doc
    /// comment for why this is a separate field rather than a replacement
    /// for `shared_group_ids`.
    live_authorized_groups: LiveGroupAuthorization,
    /// This session's live, mutable-after-
    /// construction view of the *role* (read/write) this peer holds per
    /// shared group — consulted by `reconcile_files_if_authorized`
    /// alongside (not instead of) `live_authorized_groups`: a group must
    /// both be currently authorized (`shares_group`) *and* not held at
    /// `PeerRole::Read` for this session to accept an inbound index update
    /// for it. See `LiveGroupRoles`'s doc comment.
    live_group_roles: LiveGroupRoles,
    /// This session's live view of
    /// whether *this peer* is flagged storage-only for each shared group —
    /// see `LiveStorageOnlyFlags`'s doc comment. Consulted by `send_full_
    /// index`/`send_index_update` (switch to the encrypted-index wire
    /// shape and never plaintext) and `handle_block_request` (switch to
    /// re-encrypting on the fly and never serving plaintext).
    live_storage_only_flags: LiveStorageOnlyFlags,
    /// The complementary local-side fact: whether *this* (local) device is itself
    /// the storage-only device for a group — i.e. holds no group content
    /// key and no plaintext/`FileRecord`s for it at all, only whatever
    /// opaque `EncryptedFileEntry`/ciphertext-block bytes peers hand it.
    /// Deliberately a separate, explicit, locally-configured fact (not
    /// inferred from "no entry in `group_keys`", which a perfectly ordinary
    /// trusted device also has for any group with no untrusted peer
    /// configured at all) — set once by whatever constructs this session
    /// for a device provisioned as a storage-only node ("an
    /// always-on backup/availability node on hardware you do not fully
    /// trust"), never inferred.
    local_storage_only_groups: StdMutex<std::collections::HashSet<String>>,
    /// This device's own group content key (`K_g`) and
    /// convergent-mode setting, per shared group it holds one for — see
    /// `GroupKeyState`'s doc comment. Populated by `set_group_key` (a
    /// caller-driven setter, mirroring `set_rate_limiters`'s "daemon
    /// injects real state after construction" pattern) or by successfully
    /// unwrapping a peer-delivered `WrappedGroupKey` (`handle_wrapped_
    /// group_key`). Never populated from, or read by, anything that
    /// touches the coordination plane — this crate has no coordination
    /// client at all (see `shared_group_ids`'s doc comment for the
    /// existing precedent of this crate's coordination-plane-blindness).
    group_keys: StdMutex<HashMap<String, GroupKeyState>>,
    /// This device's own X25519 identity secret, used to unwrap
    /// an incoming `WrappedGroupKey` (`content_crypto::unwrap_group_key`)
    /// and to wrap outgoing ones (`send_wrapped_group_key`). `None` until
    /// a caller sets it (`set_local_identity_secret`) — a session with no
    /// identity secret configured simply cannot send or receive wrapped
    /// keys yet (logged and ignored, never a panic or an error that tears
    /// down the session), which is the documented, honest scope limit for
    /// this pass: wiring a real device's actual WireGuard identity secret
    /// into every constructed session is daemon-level orchestration this
    /// crate does not attempt.
    local_identity_secret: StdMutex<Option<StaticSecret>>,
    /// Whether this peer has advertised understanding of the
    /// ciphertext block-addressing/encrypted-index wire shapes at all —
    /// see `record_peer_encryption_support`'s doc comment. Distinct from
    /// `live_storage_only_flags` (which is a per-group ACL fact about the
    /// peer's *trust level*, not a wire capability): a peer could in
    /// principle be flagged storage-only yet running a build old enough
    /// to not understand `EncryptedIndex`/`is_ciphertext` at all, in which
    /// case (see `send_full_index`'s storage-only branch) this device
    /// still never falls back to sending it plaintext — it simply cannot
    /// usefully sync that group with it.
    peer_supports_encrypted_storage_peer: std::sync::atomic::AtomicBool,
    /// This peer's advertised `supports_
    /// reliable_delivery` from its handshake `ClusterConfig` — mirrors
    /// `peer_supports_encrypted_storage_peer`'s pattern exactly. This
    /// build always supports it (there is no local equivalent of
    /// `compression_negotiated`'s "and we support it too" check — reliable
    /// delivery has no capability variant, it's simply present or absent),
    /// so once this flips true, `record_peer_reliable_delivery_support`
    /// immediately calls `self.channel.enable_reliable_delivery()`.
    peer_supports_reliable_delivery: std::sync::atomic::AtomicBool,
    /// Set (never
    /// cleared) the first time *any* `ClusterConfig` is received from this
    /// peer, regardless of what it advertises — distinct from `peer_
    /// supports_reliable_delivery` (which only reflects an old peer's or
    /// this peer's own actual capability). **Not** the retry loop's stop
    /// condition (an earlier draft of this design used it that way and
    /// that was a real bug — see `peer_acked_my_cluster_config`'s doc
    /// comment): receiving something from the peer is no evidence the
    /// peer received anything from *us*, so under asymmetric datagram
    /// loss that stop condition let the broken direction's sender give up
    /// immediately (seed 593). This flag's only remaining purpose is
    /// supplying this device's own outgoing `acked_peer_cluster_config`
    /// value in `cluster_config_message` — "yes, I've received *your*
    /// handshake" — which is a different claim from "you've received
    /// mine."
    peer_handshake_received: std::sync::atomic::AtomicBool,
    /// Paired with
    /// `peer_handshake_received` — `notify_one`'d right after the flag is
    /// stored, so `spawn_cluster_config_retry`'s backoff wait can race a
    /// `notified()` against its `sleep` and return as soon as the
    /// handshake completes, rather than always riding out the full
    /// backoff before re-checking. `Notify::notify_one` stores a permit
    /// when nobody is currently waiting, so this is race-free regardless
    /// of whether the flag flips before or after the retry task calls
    /// `notified()`. This matters beyond latency: a `sleep` that actually
    /// *fires* is a real scheduled event in the DST runtime, while one
    /// that's cancelled early via `select!` never fires at all — keeping
    /// this task's footprint close to zero in the common fast-handshake
    /// case, the same class of fix that resolved the earlier
    /// `reliable_tick` seed590 regression (a timer's mere *presence*, not
    /// its logic, was perturbing scheduling).
    handshake_notify: tokio::sync::Notify,
    /// The real stop condition for `spawn_cluster_config_
    /// retry` and the periodic-resync re-offer. Set true only when an
    /// incoming `ClusterConfig` carries `acked_peer_cluster_config: true`
    /// — i.e. the peer has *itself* received a `ClusterConfig` from this
    /// device, not merely "this device received something from the peer"
    /// (that weaker signal is `peer_handshake_received`, which remains
    /// only to compute this device's own outgoing `acked_peer_cluster_
    /// config` value). Under asymmetric datagram loss (seed 593: b→a
    /// traffic flows fine, a→b is persistently dropped), `peer_handshake_
    /// received` flips true on the healthy side almost immediately and,
    /// if used as the stop condition, silently gives up retrying the
    /// broken direction — exactly defeating this retry loop's purpose.
    /// This flag only flips once the peer has explicitly echoed back
    /// proof that this device's own advertisement got through.
    peer_acked_my_cluster_config: std::sync::atomic::AtomicBool,
    /// The last `EncryptedIndex`/`EncryptedIndexUpdate`
    /// entries learned from this peer for each group, cached verbatim
    /// (never decrypted or re-derived) — used two ways: (a) when this
    /// device is itself storage-only for the group (`local_storage_only_
    /// groups`), this is literally its own "index" to re-serve to other
    /// peers on its *own* `send_full_index`/`send_index_update` (a
    /// storage-only device has no `FileRecord`s of its own to build an
    /// index from — it only ever has what it was handed); (b) as a cache
    /// a trusted device could extend to locate which ciphertext hash on
    /// this peer corresponds to a plaintext block it needs (not consumed
    /// this way yet in this pass — see `handle_encrypted_index`'s doc
    /// comment on scope).
    storage_peer_index_cache: StdMutex<HashMap<String, Vec<proto::EncryptedFileEntry>>>,
    /// ciphertext_hash -> the AEAD nonce it was originally
    /// received with, for ciphertext blocks this device stored while
    /// acting as a storage-only device (`local_storage_only_groups`). The
    /// `BlockStore` trait only stores raw bytes keyed by content hash —
    /// nothing in it carries a second, separate piece of metadata per
    /// block — so the nonce needed to re-serve/decrypt a stored ciphertext
    /// block later (`serve_stored_ciphertext_block`) is kept here rather
    /// than persisted alongside the ciphertext on disk.
    ///
    /// A storage-only device runs one `PeerSyncSession` per connected
    /// peer, but a block it *learns* via one peer's session must be
    /// re-servable to a *different* peer's session later (the
    /// "relay" role is meaningless otherwise) — so this cannot be purely
    /// per-session state. Mirrors `rate_limiters`'s `StdMutex<Arc<_>>`
    /// shape exactly: defaults to a private, per-session cache (fine for a
    /// session tested in isolation), and `set_ciphertext_nonce_cache` lets
    /// a caller that manages multiple sessions for the same physical
    /// device (the daemon layer, or a multi-session test) inject one
    /// shared cache so every session for that device sees the same
    /// nonces.
    ///
    /// **Documented scope limit for this pass:** still in-memory only, not
    /// durable across a process restart — a real storage-only device
    /// deployment would need the nonce persisted next to its ciphertext
    /// (e.g. a sidecar file/column in `yadorilink-local-storage`), which
    /// this crate does not implement.
    ciphertext_nonces: StdMutex<CiphertextNonceCache>,
    /// group_id -> local linked directory, for the shared groups above.
    sync_roots: HashMap<String, PathBuf>,
    /// security hardening: `sync_roots`, pre-canonicalized once at construction —
    /// `verify_write_target_within_canonical_root` is called on every
    /// eager materialize/hydrate, a per-peer-message-concurrency-bounded
    /// hot path (see that function's doc comment), so resolving each
    /// root's canonical form once up front (rather than on every single
    /// call) avoids repeatedly paying that cost. Falls back to the raw
    /// (uncanonicalized) path for a group whose root can't be
    /// canonicalized at construction time (e.g. doesn't exist yet) —
    /// `verify_write_target_within_canonical_root` still functions
    /// correctly in that case, just without the caching benefit until a
    /// later call succeeds in creating it.
    canonical_sync_roots: HashMap<String, PathBuf>,
    /// This device's own effective ignore
    /// pattern set for each shared group, keyed the same way as
    /// `sync_roots`. Ignore patterns are device-local and unsynced —
    /// this is *this* device's filter on what it accepts
    /// from a peer, entirely independent of whatever the sending peer (or
    /// this device's other peers) chooses to do with the same path.
    /// Loaded once at construction, the same way `canonical_sync_roots` is
    /// (see that field's doc comment) — a `.yadorilinkignore` edit takes
    /// effect for incoming records on this peer's *next* session (a fresh
    /// `PeerSyncSession`), not live mid-session; local scanning/watching
    /// (`link_manager`'s executor) picks up the edit immediately, which is
    /// the primary path this covers.
    ignore_sets: HashMap<String, Arc<EffectiveIgnoreSet>>,
    pending_block_requests: PendingBlockRequests,
    /// The ciphertext-fetch analogue of `pending_block_
    /// requests` — see `PendingCiphertextBlockRequests`'s doc comment for
    /// why this is a separate map rather than sharing the plaintext one.
    pending_ciphertext_block_requests: PendingCiphertextBlockRequests,
    /// Records this session adopted or resolved from *this* peer, handed
    /// off here so the caller can forward them on to this device's *other*
    /// peer sessions — full mesh propagation needs this explicit forwarding
    /// step; a record arriving from one peer does not otherwise reach any
    /// other peer this device is connected to. `None` for callers (tests,
    /// mainly) that don't need multi-peer forwarding.
    forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
    /// Edit-presence signals received from *this* peer, handed off here
    /// the same way `forward_tx` hands off adopted file records —
    /// the daemon layer owns tracking "which files are reported
    /// open, by which device" and surfacing it, since that's in-memory,
    /// per-device state, not something `yadorilink-sync-core` itself persists.
    presence_tx: Option<mpsc::UnboundedSender<PresenceEvent>>,
    /// security hardening: group_id -> cumulative blocks admitted to eager fetch
    /// so far this session — see `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`.
    eager_admission: StdMutex<HashMap<String, u64>>,
    /// This session's upload/
    /// download token buckets, gating `handle_block_request`'s outbound
    /// send and `fetch_block`'s inbound receive respectively. Starts
    /// unlimited (mirroring every other field here that needs a
    /// mutable-after-construction default — see `live_authorized_groups`);
    /// `set_rate_limiters` replaces it with the daemon's shared, global
    /// pair (`yadorilink-daemon::peer_orchestrator`) so every session, and
    /// the daemon's hydration dispatcher (which calls `fetch_block`
    /// directly — the same choke point), draw down one ceiling per
    /// direction rather than each getting an independent full-rate
    /// allowance. Wrapped in a mutex (not `ArcSwap`) since this
    /// is only read once per block send/receive, not a hot per-byte path.
    rate_limiters: StdMutex<Arc<RateLimiters>>,
    /// Explicit disk-space headroom
    /// override for this session's own hydration/materialization preflight
    /// (`materialize`'s eager-fetch branch) — `None` means "use the default
    /// `max(1 GiB, 5%)` formula" once `headroom_enforced` (below) is set.
    /// Live-reloadable the same way `rate_limiters` is.
    headroom_override_bytes: StdMutex<Option<u64>>,
    /// Mirrors `FsBlockStore::headroom_enforced` exactly (see its doc
    /// comment for the full rationale): `false` by default so the ~15
    /// existing `tests/peer_session.rs`/inline-test call sites that
    /// construct a session directly against a tempdir (entirely unrelated
    /// to disk-pressure behavior) aren't newly exposed to this real
    /// machine's actual free space via the default formula. Only
    /// `yadorilink-daemon` (`peer_orchestrator.rs`) turns
    /// this on for real sessions.
    headroom_enforced: std::sync::atomic::AtomicBool,
    /// Whether this session's peer has
    /// advertised zstd support in its handshake `ClusterConfig`.
    /// The local device always advertises support once this code exists
    /// (see `run`'s handshake send), so negotiation reduces to "has the
    /// peer said it can receive compressed payloads too" (
    /// both sides must advertise). Starts `false` — matching every other
    /// mutable-after-construction session field's safe default, see
    /// `headroom_enforced`'s doc comment for the same pattern — so nothing
    /// is sent compressed until/unless the peer's `ClusterConfig` is
    /// actually received and says otherwise; an old peer that never sets
    /// `supported_compression` (or sets it to an empty list) leaves this
    /// `false` for the session's whole lifetime, which is exactly "always
    /// send this peer uncompressed data."
    peer_supports_compression: std::sync::atomic::AtomicBool,
    /// This session's AIMD in-flight
    /// block-fetch window controller — see `adaptive_window` module doc
    /// comment. Fed real outcomes by `fetch_block` (success + observed
    /// RTT) and by `record_fetch_timeout` (a caller-observed missing
    /// reply); read by `fetch_window` — the daemon's multi-peer dispatcher
    /// consults this in place of the old fixed per-candidate lane count.
    adaptive_window: AdaptiveWindow,
    /// The interval `run`'s
    /// independent periodic-resync task waits between re-sending a full
    /// index to this peer for each shared group -- see
    /// `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`'s doc comment for why this
    /// exists at all. Mutable-after-construction (`StdMutex`, mirroring
    /// `headroom_override_bytes`'s exact shape) rather than a constructor
    /// parameter so every existing call site (every test, every daemon
    /// construction site) keeps compiling and behaving identically --
    /// `set_full_index_resync_interval` is the opt-in override.
    full_index_resync_interval: StdMutex<std::time::Duration>,
    /// This session's
    /// caller-injected way to force-flush a path's pending local debounce
    /// entry before reconciling it against a peer update — see
    /// `PendingLocalChangeFlush`'s doc comment. `None` (the default for
    /// every existing test/call site, same as `rate_limiters` et al.
    /// before their own setter is called) makes `reconcile_one_file`'s
    /// guard a no-op, i.e. today's pre-fix behavior — only
    /// `yadorilink-daemon`'s real construction site wires up an actual
    /// handle (`set_pending_local_change_flush`).
    pending_local_change_flush: StdMutex<Option<Arc<dyn PendingLocalChangeFlush>>>,
}

impl PeerSyncSession {
    pub fn new(
        channel: Arc<PeerChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
    ) -> Arc<Self> {
        Self::new_with_forwarding(
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            sync_roots,
            None,
            None,
        )
    }

    /// Like `new`, but forwards every record this session adopts or
    /// resolves from its peer to `forward_tx` as `(group_id, record)` (see
    /// `forward_tx`'s doc comment), and every presence signal received
    /// from its peer to `presence_tx` (see `presence_tx`'s doc comment).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_forwarding(
        channel: Arc<PeerChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
        forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
        presence_tx: Option<mpsc::UnboundedSender<PresenceEvent>>,
    ) -> Arc<Self> {
        // security hardening: best-effort pre-canonicalize each sync root once —
        // see `canonical_sync_roots`'s doc comment. A group whose root
        // can't be created/canonicalized right now (rare — a missing
        // parent, a permissions issue) is simply left out of the cache;
        // `sync_root_canonical` falls back to resolving it fresh on every
        // call for that group rather than risking a stale/incorrect
        // cached value.
        let canonical_sync_roots = sync_roots
            .iter()
            .filter_map(|(group_id, root)| {
                std::fs::create_dir_all(root).ok()?;
                let canonical = std::fs::canonicalize(root).ok()?;
                Some((group_id.clone(), canonical))
            })
            .collect();
        // Load each shared group's effective
        // ignore set from its link root — same source `link_manager`'s
        // watcher/scanner already read `.yadorilinkignore` from
        // (`EffectiveIgnoreSet::load_for_link_root`). A load failure (rare
        // — an I/O error other than "file not found", which itself
        // already falls back to defaults-only inside `load_for_link_root`)
        // falls back to the built-in defaults rather than no filtering at
        // all, so a transient read error never widens what this device
        // accepts from a peer.
        let ignore_sets = sync_roots
            .iter()
            .map(|(group_id, root)| {
                let set = EffectiveIgnoreSet::load_for_link_root(root)
                    .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only());
                (group_id.clone(), Arc::new(set))
            })
            .collect();
        let live_authorized_groups = LiveGroupAuthorization::new(&shared_group_ids);
        let live_group_roles = LiveGroupRoles::new();
        Arc::new(Self {
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            live_authorized_groups,
            live_group_roles,
            live_storage_only_flags: LiveStorageOnlyFlags::new(),
            local_storage_only_groups: StdMutex::new(std::collections::HashSet::new()),
            group_keys: StdMutex::new(HashMap::new()),
            local_identity_secret: StdMutex::new(None),
            peer_supports_encrypted_storage_peer: std::sync::atomic::AtomicBool::new(false),
            peer_supports_reliable_delivery: std::sync::atomic::AtomicBool::new(false),
            peer_handshake_received: std::sync::atomic::AtomicBool::new(false),
            handshake_notify: tokio::sync::Notify::new(),
            peer_acked_my_cluster_config: std::sync::atomic::AtomicBool::new(false),
            storage_peer_index_cache: StdMutex::new(HashMap::new()),
            ciphertext_nonces: StdMutex::new(Arc::new(StdMutex::new(HashMap::new()))),
            sync_roots,
            canonical_sync_roots,
            ignore_sets,
            pending_block_requests: StdMutex::new(HashMap::new()),
            pending_ciphertext_block_requests: StdMutex::new(HashMap::new()),
            forward_tx,
            presence_tx,
            eager_admission: StdMutex::new(HashMap::new()),
            rate_limiters: StdMutex::new(Arc::new(RateLimiters::unlimited())),
            headroom_override_bytes: StdMutex::new(None),
            headroom_enforced: std::sync::atomic::AtomicBool::new(false),
            peer_supports_compression: std::sync::atomic::AtomicBool::new(false),
            adaptive_window: AdaptiveWindow::new(
                ADAPTIVE_WINDOW_INITIAL,
                ADAPTIVE_WINDOW_MIN,
                MAX_IN_FLIGHT_MESSAGES_PER_PEER,
                MAX_IN_FLIGHT_MESSAGES_PER_PEER,
            ),
            full_index_resync_interval: StdMutex::new(DEFAULT_FULL_INDEX_RESYNC_INTERVAL),
            pending_local_change_flush: StdMutex::new(None),
        })
    }

    /// Replaces this session's upload/download token buckets with
    /// the daemon's shared, global pair (see `RateLimiters`'s doc comment)
    /// so this session's block sends/receives draw down the same ceiling
    /// every other session — and the daemon's hydration dispatcher, which
    /// calls `fetch_block` directly — shares, rather than
    /// getting an independent full-rate allowance. Mirrors
    /// `set_authorized_groups`'s mutable-after-construction pattern:
    /// existing constructors are unchanged, and the daemon injects the
    /// shared limiters once a session is constructed (`peer_orchestrator.rs`).
    pub fn set_rate_limiters(&self, limiters: Arc<RateLimiters>) {
        *self.rate_limiters.lock().unwrap_or_else(|p| p.into_inner()) = limiters;
    }

    fn rate_limiters(&self) -> Arc<RateLimiters> {
        self.rate_limiters.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Sets this session's disk-headroom override (`None` =
    /// default formula) — live-reloadable, applied on the next preflight
    /// check.
    pub fn set_headroom_override_bytes(&self, headroom_bytes: Option<u64>) {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = headroom_bytes;
    }

    fn headroom_override_bytes(&self) -> Option<u64> {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Overrides this session's
    /// periodic full-index resync interval (default
    /// `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`) -- mirrors
    /// `set_headroom_override_bytes`'s "mutable-after-construction,
    /// daemon/test may override post-construction" pattern exactly. Must be
    /// called before `run` is spawned to take effect for that session's
    /// resync task (the task reads this once at startup, the same way
    /// `run`'s recv loop reads `MAX_IN_FLIGHT_MESSAGES_PER_PEER` once via
    /// the semaphore it constructs) -- a change after `run` is already
    /// running has no effect on that session's already-scheduled timer.
    pub fn set_full_index_resync_interval(&self, interval: std::time::Duration) {
        *self.full_index_resync_interval.lock().unwrap_or_else(|p| p.into_inner()) = interval;
    }

    fn full_index_resync_interval(&self) -> std::time::Duration {
        *self.full_index_resync_interval.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Turns this session's materialize-time disk-headroom preflight on or
    /// off — see `headroom_enforced`'s doc comment. `yadorilink-daemon`
    /// calls this with `true` once per constructed session.
    pub fn set_headroom_enforced(&self, enforced: bool) {
        self.headroom_enforced.store(enforced, std::sync::atomic::Ordering::Relaxed);
    }

    fn headroom_enforced(&self) -> bool {
        self.headroom_enforced.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Injects this session's
    /// real way to force-flush a path's pending local debounce entry
    /// (`PendingLocalChangeFlush`'s doc comment) — mirrors
    /// `set_rate_limiters`'s "daemon injects real behavior after
    /// construction" pattern exactly. Every existing test/call site that
    /// never calls this keeps behaving exactly as before (the guard is a
    /// no-op with no handle set).
    pub fn set_pending_local_change_flush(&self, handle: Arc<dyn PendingLocalChangeFlush>) {
        *self.pending_local_change_flush.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
    }

    /// `reconcile_one_file`'s guard: if a handle is set and it reports a
    /// pending, undispatched local entry for `rel_path`, that entry is now
    /// captured into the index by the time this returns. Called *before*
    /// `reconcile_one_file` acquires `SyncState::path_lock` for the same
    /// path — the handle's own flush goes through the ordinary
    /// `LocalChangeProcessor::process_event_with_ignore` dispatch, which
    /// acquires that same lock itself, so calling this while already
    /// holding it (as `reconcile_one_file` does for the rest of its body,
    /// including every `materialize`/`resolve_and_apply_conflict` call
    /// downstream of it) would deadlock. Because every `materialize` call
    /// in this module happens from within `reconcile_one_file`'s
    /// already-locked body, this single guard — run once, up front —
    /// covers both the "materialize-side" and
    /// "`reconcile_one_file`-side" serialization requirements: by the time
    /// any downstream `materialize` call writes to disk, a local change
    /// that was still pending here has already been indexed.
    async fn flush_pending_local_change_before_reconcile(&self, group_id: &str, rel_path: &str) {
        let handle =
            self.pending_local_change_flush.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(handle) = handle else { return };
        tracing::debug!(
            group_id,
            path = rel_path,
            peer = %self.peer_device_id,
            "checking this link's debounce accumulator for a pending local change before reconciling this path against a peer update"
        );
        handle.flush_pending_local_change(group_id, rel_path).await;
    }

    /// Like `flush_pending_local_change_before_reconcile` above, but for
    /// the *other* case-variant path that would collide with `rel_path` on
    /// a case-insensitive filesystem.
    ///
    /// Without this, `hazard_reason_for`'s `state.list_files(group_id)`
    /// read (used to detect a case-fold collision before materializing an
    /// incoming record — see `hazard_reason_for_policy`) only sees what's
    /// already indexed in `SyncState`. A local write to the colliding
    /// sibling name, still sitting undispatched in this link's debounce
    /// accumulator, is invisible to that read — so the incoming record
    /// for the other case-variant can materialize for real (no collision
    /// detected) instead of being held, silently overwriting/losing this
    /// device's own not-yet-indexed write with no conflict artifact at
    /// all. Same failure shape `flush_pending_local_change_before_
    /// reconcile` already closes for the exact-same-path case, just
    /// reached via case-fold adjacency instead of path identity.
    ///
    /// Only meaningful (and only called) when `hazard::is_case_insensitive_
    /// filesystem` is true for this group's root — on a case-sensitive
    /// filesystem, two differently-cased names are simply unrelated
    /// files, and this extra round trip would have nothing to find.
    async fn flush_case_fold_sibling_before_reconcile(&self, group_id: &str, rel_path: &str) {
        if !hazard::is_case_insensitive_filesystem(&self.sync_root(group_id)) {
            return;
        }
        let handle =
            self.pending_local_change_flush.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(handle) = handle else { return };
        tracing::debug!(
            group_id,
            path = rel_path,
            peer = %self.peer_device_id,
            "checking this link's debounce accumulator for a pending case-fold sibling change before reconciling this path against a peer update"
        );
        handle.flush_case_fold_sibling(group_id, rel_path).await;
    }

    /// Records this peer's advertised
    /// compression support from its handshake `ClusterConfig` — called
    /// from `handle_message`'s `ClusterConfig` arm (previously a
    /// receipt-only no-op; see this module's doc comment). A `ClusterConfig`
    /// advertising `Compression::Zstd` anywhere in `supported_compression`
    /// marks the peer as zstd-capable for the rest of this session; an old
    /// peer, or a new peer that (unusually) advertises nothing, leaves
    /// `peer_supports_compression` at its `false` default.
    fn record_peer_compression_support(&self, supported: &[i32]) {
        if supported.contains(&(proto::Compression::Zstd as i32)) {
            self.peer_supports_compression.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether this session should compress outgoing block/index payloads
    /// to this peer. Both sides must support compression;
    /// the local device always does once this code exists (`run` always
    /// advertises `Compression::Zstd`), so this reduces to exactly "has the
    /// peer advertised support" — `record_peer_compression_support`'s
    /// result. Public so tests can observe negotiation directly, the same
    /// way `shares_group`/`peer_role` are public for their own live
    /// per-session state.
    pub fn compression_negotiated(&self) -> bool {
        self.peer_supports_compression.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this peer's
    /// advertised `supports_encrypted_storage_peer` from its handshake
    /// `ClusterConfig` — mirrors `record_peer_compression_support`'s
    /// pattern exactly. An old peer, or one that doesn't set the field,
    /// leaves this `false` for the session's whole lifetime.
    fn record_peer_encryption_support(&self, supported: bool) {
        if supported {
            self.peer_supports_encrypted_storage_peer
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether this peer understands the ciphertext/encrypted-index wire
    /// shapes at all. Public so tests can observe it directly, mirroring
    /// `compression_negotiated`.
    pub fn encryption_negotiated(&self) -> bool {
        self.peer_supports_encrypted_storage_peer.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this peer's advertised
    /// `supports_reliable_delivery` from its handshake `ClusterConfig` —
    /// mirrors `record_peer_encryption_support`'s pattern. This build
    /// always supports it, so confirming the peer does too is the whole
    /// negotiation: immediately enables the underlying channel's
    /// reliable-delivery framing for this device's own outbound sends
    /// (`PeerChannel::enable_reliable_delivery`'s doc comment covers why
    /// the *receiving* side never needed to wait for this).
    fn record_peer_reliable_delivery_support(&self, supported: bool) {
        if supported {
            self.peer_supports_reliable_delivery.store(true, std::sync::atomic::Ordering::Relaxed);
            self.channel.enable_reliable_delivery();
        }
    }

    /// Whether this peer understands the reliable-delivery wire framing.
    /// Public so tests can observe it directly, mirroring
    /// `compression_negotiated`/`encryption_negotiated`.
    pub fn reliable_delivery_negotiated(&self) -> bool {
        self.peer_supports_reliable_delivery.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Marks (or clears) whether *this session's peer* is
    /// flagged storage-only for `group_id`, effective for the very next
    /// index/block exchange — the storage-only analogue of `set_peer_role`,
    /// expected to be driven the same way (a daemon-level netmap-diff
    /// reaction translating `PeerInfo.storage_only_group_ids` into this
    /// call). See `LiveStorageOnlyFlags`'s doc comment for the
    /// missing-entry-defaults-to-trusted contract.
    pub fn set_storage_only(&self, group_id: &str, storage_only: bool) {
        self.live_storage_only_flags.set(group_id, storage_only);
    }

    /// Replaces every currently-tracked storage-only flag at once — the
    /// storage-only analogue of `set_peer_roles`.
    pub fn set_storage_only_flags(&self, flags: impl IntoIterator<Item = (String, bool)>) {
        self.live_storage_only_flags.set_all(flags);
    }

    /// Whether this session's peer is currently flagged storage-only for
    /// `group_id`. Public so tests and callers can observe it directly,
    /// mirroring `shares_group`/`peer_role`.
    pub fn peer_is_storage_only(&self, group_id: &str) -> bool {
        self.live_storage_only_flags.is_storage_only(group_id)
    }

    /// Marks (or clears) whether *this local device* is itself
    /// the storage-only device for `group_id` — see `local_storage_only_
    /// groups`'s doc comment for why this is explicit rather than inferred.
    /// Expected to be set once, at construction/provisioning time, by
    /// whatever configures a device to run as a storage-only node — not a
    /// live, netmap-driven fact the way `set_storage_only` (about the
    /// *peer*) is.
    pub fn set_local_storage_only(&self, group_id: &str, storage_only: bool) {
        let mut groups = self.local_storage_only_groups.lock().unwrap_or_else(|p| p.into_inner());
        if storage_only {
            groups.insert(group_id.to_string());
        } else {
            groups.remove(group_id);
        }
    }

    /// Whether this local device is itself the storage-only device for
    /// `group_id`.
    pub fn is_locally_storage_only(&self, group_id: &str) -> bool {
        self.local_storage_only_groups.lock().unwrap_or_else(|p| p.into_inner()).contains(group_id)
    }

    /// Installs this device's group content key for
    /// `group_id` (and its convergent-mode setting), replacing any
    /// previous key for that group — called by a caller-driven setter
    /// (mirroring `set_rate_limiters`), or by `handle_wrapped_group_key`
    /// after successfully unwrapping a peer-delivered `WrappedGroupKey`.
    pub fn set_group_key(&self, group_id: &str, key: GroupKey, convergent: bool) {
        self.group_keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_string(), GroupKeyState { key, convergent });
    }

    /// This device's group content key state for `group_id`, if any.
    fn group_key_for(&self, group_id: &str) -> Option<GroupKeyState> {
        self.group_keys.lock().unwrap_or_else(|p| p.into_inner()).get(group_id).cloned()
    }

    /// Installs a *shared* ciphertext-nonce cache, replacing this
    /// session's private default one — see `ciphertext_nonces`'s doc
    /// comment. Call this with the same `Arc` on every `PeerSyncSession`
    /// constructed for the same physical storage-only device (across all
    /// of its peer connections) so a block learned via one peer is
    /// re-servable to another.
    pub fn set_ciphertext_nonce_cache(&self, shared: CiphertextNonceCache) {
        *self.ciphertext_nonces.lock().unwrap_or_else(|p| p.into_inner()) = shared;
    }

    fn ciphertext_nonce_cache(&self) -> CiphertextNonceCache {
        self.ciphertext_nonces.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Installs this device's own X25519 identity secret, needed
    /// to send (`send_wrapped_group_key`) or receive (`handle_wrapped_
    /// group_key`) a wrapped group key. See `local_identity_secret`'s doc
    /// comment for the documented scope limit on how this gets populated
    /// in a real deployment.
    pub fn set_local_identity_secret(&self, secret: StaticSecret) {
        *self.local_identity_secret.lock().unwrap_or_else(|p| p.into_inner()) = Some(secret);
    }

    fn local_identity_secret(&self) -> Option<StaticSecret> {
        self.local_identity_secret.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Wraps this device's `group_id` content key to `peer_
    /// identity_public` (this session's peer's X25519 identity key) and
    /// sends it — the peer-to-peer key-distribution path this system
    /// requires ("wrapped copies may transit via peers", never the
    /// coordination plane; this type, `proto::WrappedGroupKey`, lives only
    /// in `sync.proto`, never `coordination.proto`). Refuses outright, and
    /// never sends anything, if this peer is flagged storage-only for
    /// `group_id` — the encrypted-peer spec's "Key is never sent to an
    /// untrusted peer" requirement, enforced at the one and only call site
    /// that could ever emit this message. Also refuses if no local
    /// identity secret is configured (`set_local_identity_secret`) or no
    /// group key is held for this group — both `Ok(())` no-ops (nothing to
    /// send), not errors, since a caller retrying later (once state is
    /// configured) is the expected recovery, not a hard failure.
    pub async fn send_wrapped_group_key(
        &self,
        group_id: &str,
        peer_identity_public: &X25519PublicKey,
        key_epoch: u32,
    ) -> Result<(), SyncError> {
        if self.peer_is_storage_only(group_id) {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "refusing to send the group content key to a peer flagged storage-only"
            );
            return Ok(());
        }
        let Some(secret) = self.local_identity_secret() else {
            tracing::debug!(
                group_id,
                "no local identity secret configured -- cannot wrap/send the group content key \
                 yet"
            );
            return Ok(());
        };
        let Some(key_state) = self.group_key_for(group_id) else {
            tracing::debug!(group_id, "no group content key held locally -- nothing to send");
            return Ok(());
        };
        let wrapped = content_crypto::wrap_group_key(&key_state.key, &secret, peer_identity_public)
            .map_err(|e| SyncError::Chunking(format!("failed to wrap group key: {e}")))?;
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::WrappedGroupKey(proto::WrappedGroupKey {
                folder_group_id: group_id.to_string(),
                key_epoch,
                sender_identity_public: wrapped.sender_identity_public.to_vec(),
                ephemeral_public: wrapped.ephemeral_public.to_vec(),
                nonce: wrapped.nonce.to_vec(),
                ciphertext: wrapped.ciphertext,
            })),
        })
        .await
    }

    /// The receive side of `send_wrapped_group_key` — unwraps an
    /// incoming `WrappedGroupKey` with this device's own identity secret
    /// and, on success, installs it via `set_group_key` (defaulting to
    /// convergent mode; the per-group non-convergent opt-out is not
    /// itself carried on this wire message in this pass). Silently ignored (logged, not an error) if no local
    /// identity secret is configured, or unwrap fails (wrong recipient, a
    /// tampered/foreign wrap, or a genuinely malformed message) — never a
    /// panic, and never treated as a reason to tear down the session.
    fn handle_wrapped_group_key(&self, wrapped: proto::WrappedGroupKey) -> Result<(), SyncError> {
        if !self.shares_group(&wrapped.folder_group_id) {
            tracing::warn!(
                group_id = %wrapped.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring wrapped group key for an unauthorized/unshared folder group"
            );
            return Ok(());
        }
        let Some(secret) = self.local_identity_secret() else {
            tracing::debug!(
                group_id = %wrapped.folder_group_id,
                "received a wrapped group key but no local identity secret is configured -- \
                 ignoring"
            );
            return Ok(());
        };
        let (Ok(sender_identity_public), Ok(ephemeral_public)) = (
            <[u8; 32]>::try_from(wrapped.sender_identity_public.as_slice()),
            <[u8; 32]>::try_from(wrapped.ephemeral_public.as_slice()),
        ) else {
            tracing::warn!(
                group_id = %wrapped.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring malformed wrapped group key (bad public key length)"
            );
            return Ok(());
        };
        let content_wrapped = content_crypto::WrappedGroupKey {
            sender_identity_public,
            ephemeral_public,
            nonce: match <[u8; content_crypto::NONCE_LEN]>::try_from(wrapped.nonce.as_slice()) {
                Ok(n) => n,
                Err(_) => {
                    tracing::warn!(
                        group_id = %wrapped.folder_group_id,
                        peer = %self.peer_device_id,
                        "ignoring malformed wrapped group key (bad nonce length)"
                    );
                    return Ok(());
                }
            },
            ciphertext: wrapped.ciphertext,
        };
        match content_crypto::unwrap_group_key(&content_wrapped, &secret) {
            Ok(key) => {
                // Defaults to convergent — see this function's
                // doc comment on the documented scope limit.
                self.set_group_key(&wrapped.folder_group_id, key, true);
                Ok(())
            }
            Err(_) => {
                tracing::warn!(
                    group_id = %wrapped.folder_group_id,
                    peer = %self.peer_device_id,
                    "failed to unwrap a received group key (wrong recipient, tampered, or \
                     foreign wrap) -- ignoring"
                );
                Ok(())
            }
        }
    }

    /// The current recommended number
    /// of concurrent in-flight `fetch_block` requests to this peer, per
    /// this session's `AdaptiveWindow` (see that module's doc comment).
    /// `yadorilink-daemon::hydration`'s multi-peer dispatcher calls this
    /// once per fetch dispatch, in place of the old fixed
    /// `PER_PEER_IN_FLIGHT_WINDOW` lane count, so a fast/healthy session
    /// gets more concurrent lanes and a slow/lossy one gets fewer — always
    /// within `[ADAPTIVE_WINDOW_MIN, MAX_IN_FLIGHT_MESSAGES_PER_PEER]`
    /// (the window's clamp). Public for the same reason
    /// `compression_negotiated` is: an observable piece of session state a
    /// caller outside this module needs to act on.
    pub fn fetch_window(&self) -> usize {
        self.adaptive_window.current()
    }

    /// Records that a `fetch_block`
    /// request to this peer went unanswered within the *caller's* own
    /// timeout — an AIMD loss/timeout signal, backing this session's
    /// adaptive window off multiplicatively (`AdaptiveWindow::on_timeout`).
    ///
    /// This can't be observed from inside `fetch_block` itself: a caller
    /// wrapping the call in `tokio::time::timeout` (as
    /// `yadorilink-daemon::hydration`'s per-block bound already does, and
    /// as `hydrate_file_with_timeout`'s whole-batch bound does indirectly)
    /// drops the `fetch_block` future — and therefore its local `rx.await`
    /// — the instant the timeout fires, the same reason `PendingBlockGuard`
    /// exists (see its doc comment) rather than `fetch_block` ever getting
    /// a chance to run its own "it never answered" branch. Callers that
    /// impose their own bound on `fetch_block` are expected to call this
    /// when that bound is exceeded, mirroring how they already reassign a
    /// timed-out block to another candidate (e.g.
    /// `BlockWorkQueue::mark_timed_out`).
    pub fn record_fetch_timeout(&self) {
        self.adaptive_window.on_timeout();
    }

    /// Whether `path` matches this device's
    /// own effective ignore pattern set for `group_id` (built-in defaults
    /// plus this device's `.yadorilinkignore`, if any). A group with no
    /// entry in `ignore_sets` (not one of `sync_roots`) is never ignored
    /// by this check — that shouldn't happen for a group this session
    /// actually shares, since `ignore_sets` is derived from the same
    /// `sync_roots` map `shares_group`'s caller relies on.
    ///
    /// This is a purely local filter (ignore patterns are
    /// device-local, never synced) — it decides what *this* device does
    /// with an incoming record (skip materializing/indexing/forwarding
    /// it), and has no effect on what the sending peer, or this device's
    /// other peers, do with the same path.
    fn is_locally_ignored(&self, group_id: &str, path: &str) -> bool {
        self.ignore_sets
            .get(group_id)
            .is_some_and(|set| is_ignore_file_relative_path(path) || set.is_ignored(path, false))
    }

    /// Hands `record` to `forward_tx`, if set — a full mesh needs every
    /// peer session to relay what it learns to this device's other peers.
    fn forward(&self, group_id: &str, record: &FileRecord) {
        if let Some(tx) = &self.forward_tx {
            let _ = tx.send((group_id.to_string(), record.clone()));
        }
    }

    /// security hardening: attempts to admit `block_count` more blocks to eager
    /// fetch for `group_id` under this session's cumulative budget
    /// (`MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`), returning whether the
    /// admission succeeded. On success, the group's counter is
    /// incremented by `block_count`; on failure, the counter is
    /// unchanged and the caller is expected to fall back to a
    /// placeholder instead of fetching.
    fn admit_eager_blocks(&self, group_id: &str, block_count: u64) -> bool {
        let mut admission =
            self.eager_admission.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        admit_eager_blocks_impl(
            &mut admission,
            group_id,
            block_count,
            MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION,
        )
    }

    /// Sends a presence signal to this peer — the caller
    /// (`link_manager`) is responsible for periodic TTL refresh while
    /// still editing.
    pub async fn send_presence_signal(
        &self,
        group_id: &str,
        path: &str,
        editing: bool,
        ttl_seconds: u32,
    ) -> Result<(), SyncError> {
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::Presence(proto::PresenceSignal {
                folder_group_id: group_id.to_string(),
                path: path.to_string(),
                device_id: self.local_device_id.clone(),
                editing,
                ttl_seconds,
            })),
        })
        .await
    }

    /// Builds this
    /// device's `ClusterConfig` handshake message fresh each call (cheap —
    /// no state beyond cloning `shared_group_ids`) so both the initial
    /// retransmit loop (`send_cluster_config_until_peer_seen`) and the
    /// periodic-resync re-offer (`run`'s resync task) send byte-identical,
    /// idempotent content rather than duplicating this construction.
    fn cluster_config_message(&self) -> proto::SyncMessage {
        proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                folder_group_ids: self.shared_group_ids.clone(),
                known_peer_device_ids: vec![self.local_device_id.clone()],
                // This build always
                // supports zstd, so it always advertises it — the peer's
                // own advertisement (recorded in `handle_message`'s
                // `ClusterConfig` arm) is the other half of the
                // both-sides-must-advertise negotiation.
                supported_compression: vec![proto::Compression::Zstd as i32],
                // This build
                // always understands the ciphertext/encrypted-index wire
                // shapes, so it always advertises that too — mirrors the
                // compression advertisement immediately above exactly.
                supports_encrypted_storage_peer: true,
                // This build always
                // understands the marker-byte reliable-delivery framing,
                // so it always advertises that too. `run`'s handshake
                // retransmit loop below is what makes this actually likely to
                // reach the peer on a lossy link, rather than depending on
                // a single fire-and-forget send surviving.
                supports_reliable_delivery: true,
                // True once this device has
                // itself received a `ClusterConfig` from this peer —
                // lets the peer distinguish "you received from me" from
                // "I received from you" instead of conflating them. See
                // `peer_acked_my_cluster_config`'s doc comment.
                acked_peer_cluster_config: self
                    .peer_handshake_received
                    .load(std::sync::atomic::Ordering::Relaxed),
            })),
        }
    }

    /// Bounded,
    /// exponentially-backed-off re-sends of this device's `ClusterConfig`,
    /// run in the background (spawned by `run`, holding only a `Weak`
    /// reference — same lifetime story as the periodic resync task below,
    /// see its own doc comment) so a peer that hasn't been seen yet does
    /// NOT delay `run`'s own startup (`send_full_index`, the recv loop) —
    /// the *first* send already happened synchronously in `run` before
    /// this task is spawned; this only covers the *retries*. Stops as soon
    /// as `peer_acked_my_cluster_config` flips true (the peer has
    /// confirmed receipt of this device's own advertisement — a real
    /// bidirectional signal, not just "this device heard something from
    /// the peer"; see that field's doc comment for why the distinction
    /// matters under asymmetric loss) or the attempt budget is exhausted.
    /// Deliberately small and self-contained:
    /// this bootstraps negotiation over a lossy link *before* reliable
    /// delivery itself can be relied on to retransmit anything (a chicken-
    /// and-egg this loop exists specifically to avoid), so it cannot reuse
    /// the ARQ's own RTT-adaptive retransmit machinery. On a lossy link,
    /// exhausting the budget here just means this loop gives up — the
    /// periodic full-index resync's own re-offer (see `run`'s resync task)
    /// is the longer-horizon backstop for a peer that was unreachable for
    /// this whole initial window.
    const HANDSHAKE_RETRY_ATTEMPTS: u32 = 5;
    /// 2s, not e.g. 200ms: still trivially fast relative to the 90s
    /// periodic-resync backstop this loop supplements, but comfortably
    /// above the short "no further message arrives" quiet-window
    /// assertions several existing integration tests already make
    /// (typically a few hundred ms) — this loop's retries are a real,
    /// observable side effect (an extra `ClusterConfig` datagram) once a
    /// peer stops answering, and a delay this generous means a real
    /// exchange finishing within ~2s (essentially every test, and every
    /// healthy real connection) never overlaps with a retry firing.
    const HANDSHAKE_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

    fn spawn_cluster_config_retry(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak_self = Arc::downgrade(self);
        tokio::spawn(async move {
            // The first attempt (index 0) was already sent synchronously
            // by `run` before this task was spawned — retries start at 1.
            for attempt in 1..Self::HANDSHAKE_RETRY_ATTEMPTS {
                let backoff = 2u32.saturating_pow(attempt - 1).min(8);
                {
                    let Some(session) = weak_self.upgrade() else { return };
                    if session
                        .peer_acked_my_cluster_config
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return;
                    }
                    // Race the backoff sleep against the handshake
                    // notification (see `handshake_notify`'s doc comment).
                    // `notify_one` fires on *every* incoming `ClusterConfig`
                    // (not only ones that actually carry the confirmation
                    // this loop is waiting for), so `notified()` resolving
                    // does NOT by itself mean it's time to stop — it just
                    // means "recheck now" instead of riding out the full
                    // backoff. The common case — the peer's own
                    // `ClusterConfig` arrives well before this backoff
                    // elapses — still never lets the `sleep` actually
                    // fire; it's cancelled by `select!` either way.
                    tokio::select! {
                        _ = session.handshake_notify.notified() => {}
                        _ = tokio::time::sleep(Self::HANDSHAKE_RETRY_BASE_DELAY * backoff) => {}
                    }
                }
                let Some(session) = weak_self.upgrade() else { return };
                if session.peer_acked_my_cluster_config.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let _ = session.send(session.cluster_config_message()).await;
            }
        })
    }

    /// Runs the session: sends the initial handshake + full index for each
    /// shared folder group, then dispatches incoming messages
    /// until the channel closes. Intended to run for the session's whole
    /// lifetime as a background task.
    pub async fn run(self: Arc<Self>) -> Result<(), SyncError> {
        self.send(self.cluster_config_message()).await?;
        // The above is
        // this device's *first* handshake attempt, sent synchronously
        // (unchanged timing from before this hardening — `send_full_index`
        // right below is never delayed by it). `spawn_cluster_config_retry`
        // covers *retries* only, entirely in the background, so a peer
        // that's slow or never sends its own `ClusterConfig` back (a bare
        // test double with no reciprocal `run()`, or a genuinely
        // unreachable peer) does not hold up this function's own startup.
        let handshake_retry_handle = self.spawn_cluster_config_retry();

        for group_id in &self.shared_group_ids {
            self.send_full_index(group_id).await?;
        }

        // An independent task, not
        // another branch of this function's own recv loop. This is
        // deliberate, not just a style choice: the whole reason a resync is
        // needed is that this session's recv loop can itself be stuck (see
        // `reconcile_one_file`'s `eager_admitted` branch doc comment) for
        // the entire span between one incoming message and the next, well
        // past when a resync should fire. Folding the timer into a
        // `select!` alongside `self.channel.recv()` below would not help —
        // once a `select!` iteration picks the recv branch, this whole
        // function's body (including the blocking `acquire_owned().await`
        // a few lines down) runs to completion before `select!` is
        // consulted again, so a timer branch in the same loop would be
        // just as stuck as the recv loop it's meant to route around. A
        // separate task's own await points are entirely independent of
        // this one's, so it keeps ticking (and keeps calling
        // `send_full_index`, which only ever calls `self.channel.send` --
        // never gated by `message_slots` below) regardless of what state
        // this function's own loop is in.
        //
        // Holds only a `Weak` reference: this task must not be the reason
        // the session (and its `PeerChannel`/`SyncState`/`BlockStore`
        // handles) outlives every other owner -- once the last strong
        // `Arc<PeerSyncSession>` elsewhere (e.g. the daemon's `sessions`
        // map) drops, `upgrade()` starts failing and this task exits on
        // its own, the same lifetime story as if it had never been
        // spawned. `run`'s own exit path additionally aborts it directly
        // (see below) so a session torn down while this task happens to
        // be mid-tick doesn't leave it running even briefly longer than
        // necessary.
        let resync_handle = {
            let weak_self = Arc::downgrade(&self);
            tokio::spawn(async move {
                loop {
                    let interval = match weak_self.upgrade() {
                        Some(session) => session.full_index_resync_interval(),
                        None => return,
                    };
                    tokio::time::sleep(interval).await;
                    let Some(session) = weak_self.upgrade() else { return };
                    // The initial bounded handshake retry
                    // (`send_cluster_config_until_peer_seen`) is a
                    // best-effort bootstrap over a span of a few seconds —
                    // a peer that was unreachable for that whole window
                    // (not merely lossy) would otherwise never see this
                    // device's `ClusterConfig` again for the rest of the
                    // session. Piggybacking a re-offer on this already-
                    // existing periodic resync (`DEFAULT_FULL_INDEX_
                    // RESYNC_INTERVAL`, 90s) gives negotiation a long-
                    // horizon backstop too, at no extra wire-format cost
                    // (idempotent, same message either way). Stops once
                    // `peer_acked_my_cluster_config` flips true, same
                    // condition the initial loop uses (see that field's
                    // doc comment for why this — not `peer_handshake_
                    // received` — is the correct signal).
                    if !session
                        .peer_acked_my_cluster_config
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Err(e) = session.send(session.cluster_config_message()).await {
                            tracing::warn!(
                                peer = %session.peer_device_id,
                                error = %e,
                                "periodic full-index resync failed to re-offer ClusterConfig"
                            );
                        }
                    }
                    for group_id in &session.shared_group_ids {
                        // Skip a group this peer's authorization
                        // was revoked for mid-session -- the initial
                        // handshake above sends unconditionally (a
                        // construction-time decision already vetted by
                        // whoever built this session), but a resync fires
                        // much later in the session's life, when
                        // `live_authorized_groups` may have since diverged
                        // from that snapshot (`shares_group`'s doc
                        // comment). Everything else this resync's `FullIndex`
                        // is subject to on arrival (paused links,
                        // send-only/receive-only mode, read-only peer
                        // role) is already enforced on the *receiving*
                        // side by `reconcile_files_if_authorized` -- the
                        // exact same gate any other index message goes
                        // through, since this is nothing but an ordinary
                        // `send_full_index` call.
                        if !session.shares_group(group_id) {
                            continue;
                        }
                        if let Err(e) = session.send_full_index(group_id).await {
                            tracing::warn!(
                                group_id,
                                peer = %session.peer_device_id,
                                error = %e,
                                "periodic full-index resync failed to send"
                            );
                        }
                    }
                }
            })
        };

        let message_slots = Arc::new(Semaphore::new(MAX_IN_FLIGHT_MESSAGES_PER_PEER));
        // A message that's
        // been read off the wire but can't get a `message_slots` permit yet
        // queues here instead of the recv loop blocking on `acquire_owned`
        // in-line. This is the fix for a real, confirmed-permanent deadlock
        // (not just slowness): the OLD structure decoded one message, and
        // if it wasn't a `BlockResponse` (already handled with no permit,
        // see below) it blocked the *entire loop* on `acquire_owned().await`
        // before ever calling `self.channel.recv()` again — so a
        // `BlockResponse` sitting right behind it on the wire, which is
        // exactly what would free a permit and break the stall, could never
        // even be read, let alone processed. `ensure_blocks_present`'s own
        // doc comment predicted this exact failure mode and suggested this
        // exact fix (a separate intake path so the recv loop is never
        // head-of-line-blocked behind its own eager fetches).
        //
        // Deliberately an unbounded `VecDeque`, not a capped one: a cap just
        // relocates the identical deadlock to a higher threshold (blocking
        // to *push into* a full cap is exactly as fatal as blocking on
        // `acquire_owned` was) rather than fixing it. The concurrency bound
        // that actually matters — at most `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
        // `handle_message` calls ever running at once — is unchanged; this
        // queue only ever holds cheap, already-decoded `SyncMessage`s
        // waiting their turn, never a running task or a held permit.
        // Unbounded growth under a deliberately hostile flood is a
        // different, pre-existing concern already owned by other layers
        // (per-message size caps, rate limiting, resource governance)
        // — this change's job is only to make permit exhaustion transient
        // instead of a permanent deadlock, not to re-derive those bounds.
        let mut pending: VecDeque<proto::SyncMessage> = VecDeque::new();
        loop {
            tokio::select! {
                maybe_bytes = self.channel.recv() => {
                    let Some(bytes) = maybe_bytes else { break };
                    let msg = match proto::SyncMessage::decode(bytes.as_slice()) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to decode SyncMessage, ignoring");
                            continue;
                        }
                    };
                    match msg.payload {
                        Some(proto::sync_message::Payload::BlockResponse(resp)) => {
                            // Never queued, never gated on a permit — this
                            // is the message type that *frees* permits
                            // (see `ensure_blocks_present`'s callers), and
                            // this `select!` arm runs regardless of how
                            // full `pending` or `message_slots` currently
                            // are, which is exactly what closes the
                            // deadlock: reading further off the wire never
                            // depends on downstream permit availability.
                            // Confirmed `handle_block_response`'s only
                            // await point is a `spawn_blocking` zstd
                            // decompression bounded by `MAX_BLOCK_SIZE` —
                            // a fixed, finite CPU computation, not a wait
                            // on `message_slots` or on another inbound
                            // message, so it cannot itself join this
                            // deadlock's dependency cycle (it can add a
                            // small, bounded per-response delay, not an
                            // unbounded one).
                            self.handle_block_response(resp).await;
                        }
                        payload => {
                            pending.push_back(proto::SyncMessage { payload });
                            // Observability, not a bound: a legitimate
                            // large catch-up batch can genuinely need to
                            // queue more than `MAX_IN_FLIGHT_MESSAGES_PER_
                            // PEER` messages at once (see `pending`'s doc
                            // comment above for why this stays uncapped),
                            // but sustained, unbounded growth here would
                            // still be worth knowing about — surfaced as a
                            // warning rather than silently invisible
                            // memory growth. Real flow control (not
                            // pulling more from a peer than can currently
                            // be processed) is a separate, tracked
                            // fast-follow, not this change's job.
                            if pending.len() == PENDING_QUEUE_WARN_THRESHOLD {
                                tracing::warn!(
                                    peer = %self.peer_device_id,
                                    queued = pending.len(),
                                    "recv loop's permit-wait queue has grown large; a peer may be \
                                     sending faster than this device can process"
                                );
                            }
                        }
                    }
                }
                // SEC-13: bounds concurrently-spawned message-handler tasks
                // per peer so a flood can't exhaust memory/FDs — but a
                // *waiting* acquire (backpressure onto `pending`, which
                // only grows, never drops a message), not `try_acquire`
                // (drop-on-saturation, what this originally did, and
                // caused a real repro: a burst of legitimate messages
                // intermittently dropped `IndexUpdate`s under load,
                // surfacing as spurious hydration timeouts in
                // `multi_peer_hydration` integration tests). Only polled
                // once something is actually queued — see `pending`'s doc
                // comment above for why this branch, unlike the old
                // in-line `acquire_owned`, can never block the sibling
                // branch above from continuing to drain the wire.
                acquired = message_slots.clone().acquire_owned(), if !pending.is_empty() => {
                    let permit = match acquired {
                        Ok(permit) => permit,
                        Err(_closed) => break,
                    };
                    let msg = pending
                        .pop_front()
                        .expect("guarded by `if !pending.is_empty()` above");
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = this.handle_message(msg).await {
                            tracing::warn!(error = %e, "error handling sync message");
                        }
                    });
                }
            }
        }
        // The recv loop above is
        // this session's whole reason to exist -- once it's done (channel
        // closed), the periodic resync task has nothing left to resync
        // towards and must not keep running (and keep this `Arc` alive via
        // its own `Weak::upgrade` calls succeeding against *other* strong
        // owners, e.g. the daemon's `sessions` map, for up to one more full
        // interval after this session is otherwise finished).
        resync_handle.abort();
        // Same
        // reasoning as `resync_handle.abort()` immediately above -- a
        // finished session has nothing left to bootstrap negotiation for.
        // A no-op if the retry loop already finished on its own (peer
        // seen, or attempts exhausted).
        handshake_retry_handle.abort();
        Ok(())
    }

    async fn send(&self, msg: proto::SyncMessage) -> Result<(), SyncError> {
        self.channel.send(msg.encode_to_vec()).await?;
        Ok(())
    }

    /// Closes a wire-serialization gap on the
    /// *sending* side: `FileRecord::into()` alone can't populate
    /// `proto::FileInfo`'s `record_kind`/`symlink_target`/
    /// `symlink_out_of_root_or_absolute`/`exec_bit` fields (see
    /// `types.rs`'s `From<FileRecord>` doc comment — it structurally has
    /// no `SyncState` access), so this builds the base conversion via
    /// `.into()` and then overwrites those four fields from a direct
    /// `SyncState` lookup for `record.path`/`group_id`, the same source
    /// `materialize_symlink_at`/`try_apply_metadata_only_update` already
    /// consult on the receiving end. Four extra point-queries per record
    /// (matching the cost `control_socket.rs`'s `list_link_statuses`
    /// already documents accepting for its own per-file `SyncState`
    /// lookups) — acceptable for `send_full_index`/`send_index_update`,
    /// which run once per connection/change, not in a tight per-block loop.
    fn file_info_for_record(
        &self,
        group_id: &str,
        record: FileRecord,
    ) -> Result<proto::FileInfo, SyncError> {
        let record_kind = self.state.get_record_kind(group_id, &record.path)?.unwrap_or_default();
        let symlink_target = self.state.get_symlink_target(group_id, &record.path)?;
        let symlink_out_of_root = self.state.get_symlink_out_of_root(group_id, &record.path)?;
        let exec_bit = self.state.get_exec_bit(group_id, &record.path)?;
        // This device's own
        // record of who actually produced this path's current content —
        // see `IncomingWireMeta`'s doc comment for how the receiving side
        // uses this.
        let origin_device_id = self.state.get_origin_device_id(group_id, &record.path)?;
        let mut info: proto::FileInfo = record.into();
        info.record_kind = proto_record_kind_from_domain(record_kind) as i32;
        info.symlink_target = symlink_target;
        info.symlink_out_of_root_or_absolute = symlink_out_of_root;
        info.exec_bit = exec_bit;
        info.origin_device_id = origin_device_id.unwrap_or_default();
        Ok(info)
    }

    async fn send_full_index(&self, group_id: &str) -> Result<(), SyncError> {
        // Everything below this
        // branch — the entire pre-existing plaintext `Index` path — is
        // untouched; a group with no untrusted peer, and a session where
        // this local device isn't itself storage-only, takes exactly the
        // same route it always has (encrypted-peer spec: "a group with no
        // untrusted peers behaves exactly as today").
        if let Some(entries) = self.encrypted_index_entries_for_send(group_id).await? {
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::EncryptedFullIndex(
                        proto::EncryptedIndex {
                            folder_group_id: group_id.to_string(),
                            files: entries,
                        },
                    )),
                })
                .await;
        }
        let files = self.state.list_files(group_id)?;
        let mut file_infos = Vec::with_capacity(files.len());
        for record in files {
            file_infos.push(self.file_info_for_record(group_id, record)?);
        }
        let (files, compressed_files, compression) = self.compress_index_files(file_infos).await;
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::FullIndex(proto::Index {
                folder_group_id: group_id.to_string(),
                files,
                compression: compression as i32,
                compressed_files,
            })),
        })
        .await
    }

    /// Sends only the changed files, rather than a full index —
    /// called by the local-change pipeline after a watched-folder edit.
    pub async fn send_index_update(
        &self,
        group_id: &str,
        changed: Vec<FileRecord>,
    ) -> Result<(), SyncError> {
        // Same additive branch as
        // `send_full_index` above — see its comment.
        if let Some(entries) = self.encrypted_index_entries_for_send(group_id).await? {
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::EncryptedIndexUpdate(
                        proto::EncryptedIndexUpdate {
                            folder_group_id: group_id.to_string(),
                            changed_files: entries,
                        },
                    )),
                })
                .await;
        }
        let mut file_infos = Vec::with_capacity(changed.len());
        for record in changed {
            file_infos.push(self.file_info_for_record(group_id, record)?);
        }
        let (changed_files, compressed_changed_files, compression) =
            self.compress_index_files(file_infos).await;
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::IndexUpdate(proto::IndexUpdate {
                folder_group_id: group_id.to_string(),
                changed_files,
                compression: compression as i32,
                compressed_changed_files,
            })),
        })
        .await
    }

    /// The shared "should this
    /// group's index go out encrypted to this peer, and if so, what?"
    /// decision for both `send_full_index` and `send_index_update`.
    /// Returns `None` to mean "no, use the ordinary plaintext path
    /// unchanged" (the common case; see each caller's own doc comment).
    /// Returns `Some(entries)` — possibly empty — in the two cases where a
    /// plaintext send would be wrong or impossible:
    ///
    /// - This local device is itself storage-only for `group_id`
    ///   (`is_locally_storage_only`): it has no `FileRecord`s to build a
    ///   plaintext index from at all — it re-serves whatever it has cached
    ///   from `storage_peer_index_cache` verbatim (the "relay"
    ///   role; possibly empty if it hasn't learned anything about this
    ///   group yet).
    /// - This session's peer is flagged storage-only for `group_id` and a
    ///   group content key is available: builds a fresh `EncryptedIndex`
    ///   from this device's own current plaintext state.
    ///
    /// If the peer is flagged storage-only but **no** group content key is
    /// available, this logs a warning and returns `Some(vec![])` — an
    /// empty encrypted index, not a fallback to plaintext. Never sending
    /// this group's index to this peer at all (i.e. `None`, on the ground
    /// that "well, then there's nothing sensible to do") would leave this
    /// peer as a normal Syncthing-like blind spot that just times out;
    /// instead this makes the "storage-only peer configured but no key
    /// wired yet" state explicit and content-blind, matching the
    /// encrypted-peer spec's "the trusted device never sends the group
    /// content key or any plaintext to that peer" requirement literally
    /// even in this half-configured state.
    async fn encrypted_index_entries_for_send(
        &self,
        group_id: &str,
    ) -> Result<Option<Vec<proto::EncryptedFileEntry>>, SyncError> {
        if self.is_locally_storage_only(group_id) {
            let cached = self
                .storage_peer_index_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(group_id)
                .cloned()
                .unwrap_or_default();
            return Ok(Some(cached));
        }
        if !self.peer_is_storage_only(group_id) {
            return Ok(None);
        }
        let Some(key_state) = self.group_key_for(group_id) else {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "peer is flagged storage-only for this group but no group content key is \
                 available locally -- sending an empty encrypted index rather than ever \
                 falling back to plaintext"
            );
            return Ok(Some(Vec::new()));
        };
        Ok(Some(self.build_encrypted_index_entries(group_id, &key_state)?))
    }

    /// Builds this device's current plaintext state for
    /// `group_id` into `EncryptedFileEntry`s, one per `FileRecord`. Reads
    /// and encrypts every referenced block's plaintext content from this
    /// device's own store — a real, disclosed cost (see `content_crypto`'s
    /// convergent-determinism doc comment, which this function relies on
    /// for `handle_ciphertext_block_request` to later re-derive the same
    /// ciphertext hashes on demand): unlike the ordinary plaintext index
    /// (`file_info_for_record`, metadata-only), building an encrypted index
    /// is O(total bytes in the group), not O(file count), since a
    /// ciphertext's hash cannot be known without actually encrypting the
    /// real bytes. Accepted for this pass (correctness first; no caching
    /// of previously-computed ciphertext hashes — not required for this
    /// pass), and disclosed here rather than hidden.
    fn build_encrypted_index_entries(
        &self,
        group_id: &str,
        key_state: &GroupKeyState,
    ) -> Result<Vec<proto::EncryptedFileEntry>, SyncError> {
        let records = self.state.list_files(group_id)?;
        records.iter().map(|record| self.encrypt_file_record(record, key_state)).collect()
    }

    /// Encrypts one `FileRecord` into an `EncryptedFileEntry` —
    /// the path and ordered plaintext block-hash list under `encrypted_
    /// file_meta` (only a trusted device holding `key_state.key` can
    /// decrypt this back to a `proto::PlaintextFileMeta`), and each block
    /// re-encrypted individually (`content_crypto::encrypt_
    /// block`) purely to learn its ciphertext hash/size for the visible
    /// `CiphertextBlockInfo` list — the untrusted peer never sees the
    /// ciphertext bytes themselves until it later requests one by hash
    /// (`handle_ciphertext_block_request`).
    fn encrypt_file_record(
        &self,
        record: &FileRecord,
        key_state: &GroupKeyState,
    ) -> Result<proto::EncryptedFileEntry, SyncError> {
        let meta = proto::PlaintextFileMeta {
            path: record.path.clone(),
            block_hashes: record.blocks.iter().map(|b| b.hash.clone()).collect(),
            deleted: record.deleted,
        };
        let (file_meta_nonce, encrypted_file_meta) =
            content_crypto::encrypt_metadata(&key_state.key, &meta.encode_to_vec())
                .map_err(|e| SyncError::Chunking(format!("failed to encrypt file meta: {e}")))?;

        let mut blocks = Vec::with_capacity(record.blocks.len());
        for block in &record.blocks {
            let hash_hex = hex::encode(&block.hash);
            let plaintext = self.store.get(&hash_hex)?;
            let encrypted = content_crypto::encrypt_block(
                &key_state.key,
                &block.hash,
                &plaintext,
                key_state.convergent,
            )
            .map_err(|e| SyncError::Chunking(format!("failed to encrypt block: {e}")))?;
            blocks.push(proto::CiphertextBlockInfo {
                ciphertext_hash: encrypted.ciphertext_hash().to_vec(),
                size: encrypted.ciphertext.len() as u32,
            });
        }

        Ok(proto::EncryptedFileEntry {
            encrypted_file_meta,
            file_meta_nonce: file_meta_nonce.to_vec(),
            blocks,
            deleted: record.deleted,
        })
    }

    /// Turns an outgoing `Vec<proto::
    /// FileInfo>` into the `(files, compressed_files, compression)` triple
    /// `send_full_index`/`send_index_update` each fold into their own
    /// message shape (`Index.files`/`compressed_files` and
    /// `IndexUpdate.changed_files`/`compressed_changed_files` play the
    /// identical role — see `sync.proto`'s doc comment on
    /// `Index.compressed_files`). When compression isn't negotiated with
    /// this peer, or there's nothing to send, this is a no-op passthrough
    /// (`files` unchanged, `Compression::None`).
    ///
    /// Otherwise, `files` is encoded as a temporary inner `Index`
    /// submessage purely to get a byte buffer `compress_block` can operate
    /// on (its own `folder_group_id`/`compression` are irrelevant — only
    /// its `files` list is ever read back out, by `decode_index_files`),
    /// then compressed off the async runtime exactly like a block payload
    /// (the same `spawn_blocking` pattern used elsewhere). `files` is cloned before
    /// that move so the original, uncompressed list is still on hand
    /// afterward if `compress_block` decides compression wasn't worth it
    /// (D3's adaptive skip) or the blocking task panics — this never loses
    /// data, unlike trying to recover `files` by re-decoding after the
    /// fact. Index sends aren't a tight per-block loop (`file_info_for_
    /// record`'s doc comment already accepts a comparable per-send cost),
    /// so the extra clone is not a hot-path concern.
    async fn compress_index_files(
        &self,
        files: Vec<proto::FileInfo>,
    ) -> (Vec<proto::FileInfo>, Vec<u8>, proto::Compression) {
        if !self.compression_negotiated() || files.is_empty() {
            return (files, Vec::new(), proto::Compression::None);
        }
        let encoded = proto::Index {
            folder_group_id: String::new(),
            files: files.clone(),
            compression: proto::Compression::None as i32,
            compressed_files: Vec::new(),
        }
        .encode_to_vec();
        match spawn_blocking(move || compress_block(&encoded)).await {
            Ok((compressed, proto::Compression::Zstd)) => {
                (Vec::new(), compressed, proto::Compression::Zstd)
            }
            // Not worth compressing (D3), or the blocking task panicked
            // (folded into "send raw", mirroring `handle_block_request`'s
            // own panic fallback below) — `files` (cloned above) is still
            // intact either way.
            _ => (files, Vec::new(), proto::Compression::None),
        }
    }

    /// Recovers the real `Vec<proto::
    /// FileInfo>` for an incoming `Index`/`IndexUpdate`, decompressing
    /// `compressed_bytes` (off the async runtime — the same `spawn_blocking`
    /// pattern as every other compress/decompress call in this module)
    /// when `compression` says to, bounded by `MAX_DECOMPRESSED_INDEX_SIZE`
    /// (this module's index-specific decompression-bomb guard — see that
    /// constant's doc comment for why it isn't `MAX_BLOCK_SIZE`).
    ///
    /// `None` means the whole message must be dropped: on a decompression
    /// failure (corrupt payload, or the bomb bound exceeded) or a
    /// decompressed payload that doesn't decode as a valid inner `Index`,
    /// this is rejected exactly the way `reconcile_files_if_authorized`'s
    /// cardinality-cap check already rejects an oversized/malformed
    /// message: logged, dropped wholesale, no partial processing — the
    /// peer's next full-index resend is relied on for eventual
    /// consistency, same as that existing rejection. `Some(files)` is
    /// either the passthrough `files` (uncompressed case) or the decoded
    /// inner index's `files` (compressed case).
    async fn decode_index_files(
        &self,
        files: Vec<proto::FileInfo>,
        compressed_bytes: Vec<u8>,
        compression: i32,
    ) -> Option<Vec<proto::FileInfo>> {
        let compression =
            proto::Compression::try_from(compression).unwrap_or(proto::Compression::None);
        if compression == proto::Compression::None {
            return Some(files);
        }
        match spawn_blocking(move || {
            decompress_block(&compressed_bytes, compression, MAX_DECOMPRESSED_INDEX_SIZE)
        })
        .await
        {
            Ok(Ok(decoded)) => match proto::Index::decode(decoded.as_slice()) {
                Ok(inner) => Some(inner.files),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        peer = %self.peer_device_id,
                        "rejecting index message: decompressed payload did not decode as a \
                         valid inner index"
                    );
                    None
                }
            },
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    peer = %self.peer_device_id,
                    "rejecting index message: failed to decompress (corrupt payload or \
                     decompression-bomb bound exceeded)"
                );
                None
            }
            Err(join_err) => {
                tracing::warn!(
                    error = %join_err,
                    peer = %self.peer_device_id,
                    "rejecting index message: decompression task panicked"
                );
                None
            }
        }
    }

    /// Handles an incoming `EncryptedIndex`/`EncryptedIndexUpdate`
    /// from this session's peer. Always caches the entries verbatim (never
    /// decrypted or re-derived) in `storage_peer_index_cache`, for two
    /// reasons depending on this local device's own role:
    ///
    /// - If this local device is itself storage-only for `group_id`
    ///   (`is_locally_storage_only`): it holds no group content key and no
    ///   `FileRecord`s at all, so this cache *is* its own index for the
    ///   group — the same entries get re-served verbatim on this device's
    ///   own next `send_full_index`/`send_index_update` for a *different*
    ///   peer (the "relay" role). This branch also fetches any
    ///   referenced ciphertext block this device doesn't already hold,
    ///   verifying only the ciphertext's own content hash (it has no
    ///   plaintext hash to check against — it never decrypts anything).
    /// - Otherwise (a normal trusted device, whether or not it holds a
    ///   group key for this session's peer): this is cache-only bookkeeping
    ///   for this pass. A trusted device's actual block needs are driven by
    ///   its own materialization/hydration logic calling `fetch_block_from_
    ///   storage_peer` directly with a specific `(ciphertext_hash,
    ///   plaintext_hash)` pair it already knows about — eagerly walking
    ///   every entry this handler sees and fetching it would defeat this
    ///   crate's existing eager-admission bounds (security hardening). Decrypting
    ///   `encrypted_file_meta` here to learn per-block plaintext hashes for
    ///   that lookup, so a trusted device can locate ciphertext for a block
    ///   it doesn't yet have `ciphertext_hash` for by any other means, is a
    ///   documented follow-up — not
    ///   implemented in this pass.
    ///
    /// Guarded by `shares_group` exactly like `reconcile_files_if_authorized`
    /// (its plaintext-index counterpart) — a peer could otherwise name any
    /// `group_id` string, including one this device isn't authorized for or
    /// doesn't even know about, and have it cached/acted on.
    async fn handle_encrypted_index(
        &self,
        group_id: String,
        entries: Vec<proto::EncryptedFileEntry>,
    ) -> Result<(), SyncError> {
        if !self.shares_group(&group_id) {
            tracing::warn!(
                group_id = %group_id,
                peer = %self.peer_device_id,
                "ignoring encrypted index message for unauthorized/unshared folder group"
            );
            return Ok(());
        }
        self.storage_peer_index_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.clone(), entries.clone());

        if !self.is_locally_storage_only(&group_id) {
            return Ok(());
        }

        for entry in entries {
            for block in entry.blocks {
                let hash_hex = hex::encode(&block.ciphertext_hash);
                if self.store.exists(&hash_hex)? {
                    continue; // already held -- dedup, no network round-trip
                }
                match self.fetch_raw_ciphertext_block(&group_id, &block.ciphertext_hash).await? {
                    Some(payload)
                        if payload.data.len() == block.size as usize
                            && Sha256::digest(&payload.data).as_slice()
                                == block.ciphertext_hash.as_slice() =>
                    {
                        let store = self.store.clone();
                        let data = payload.data.clone();
                        let put_result = spawn_blocking(move || store.put(&data)).await;
                        match put_result {
                            Ok(Ok(_hash)) => {
                                // See `ciphertext_nonces`'s doc comment: kept
                                // in the (potentially cross-session-shared)
                                // nonce cache so this device can re-serve
                                // the block to a *different* peer later
                                // (`serve_stored_ciphertext_block`) without
                                // knowing the group key.
                                self.ciphertext_nonce_cache()
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .insert(block.ciphertext_hash.clone(), payload.nonce);
                            }
                            Ok(Err(e)) => return Err(e.into()),
                            Err(join_err) => {
                                return Err(SyncError::from(std::io::Error::other(format!(
                                    "ciphertext block store write task panicked: {join_err}"
                                ))))
                            }
                        }
                    }
                    Some(_) => {
                        tracing::warn!(
                            group_id = %group_id,
                            peer = %self.peer_device_id,
                            hash = %hex::encode(&block.ciphertext_hash),
                            "peer returned ciphertext block data that did not match its own \
                             declared hash/size; not storing"
                        );
                    }
                    None => {
                        tracing::warn!(
                            group_id = %group_id,
                            peer = %self.peer_device_id,
                            hash = %hex::encode(&block.ciphertext_hash),
                            "peer reported ciphertext block as not_found"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether `group_id` is one this session's peer is *currently*
    /// authorized (per the coordination plane's ACL) to sync with us.
    ///
    /// sync-engine spec "Block Requests Are Authorized Against Actual Group
    /// Membership":
    /// reads `live_authorized_groups`, not the `shared_group_ids` snapshot
    /// captured once at session construction — every caller of this method
    /// (`handle_block_request`, `reconcile_files_if_authorized`,
    /// `handle_presence_signal`) already calls it fresh on every single
    /// incoming request/message, so re-pointing its data source at a
    /// live-updatable set is what turns "checked once at session start"
    /// into "re-validated against current state at processing time" for
    /// all of them, with no change needed at any call site. Cheap on the
    /// common (still-authorized) path — one `Mutex`-guarded `HashSet`
    /// lookup, no coordination-plane round trip — consistent with a
    /// push model.
    pub fn shares_group(&self, group_id: &str) -> bool {
        self.live_authorized_groups.contains(group_id)
    }

    /// Withdraws this peer's
    /// authorization for `group_id`, effective for the very next request
    /// `shares_group` is asked about — called by daemon-level
    /// netmap-diff-driven teardown when a netmap
    /// update removes this peer's edge for `group_id` (`share revoke`), or
    /// once per remaining shared group when the peer is removed entirely
    /// (`device remove`). Does not touch `shared_group_ids` (the
    /// construction-time snapshot `run` already used for its one-time
    /// initial handshake) or tear down the underlying `PeerChannel` — that
    /// transport-level teardown is a separate, independent reaction to the
    /// same netmap update, not this method's job.
    pub fn revoke_group(&self, group_id: &str) {
        self.live_authorized_groups.revoke(group_id);
    }

    /// The inverse of `revoke_group`: grants (or re-grants) this peer's
    /// authorization for `group_id`, effective for the next request. Kept
    /// symmetric with `revoke_group` for a netmap update that adds a group
    /// edge, e.g. `share grant` while this session is already established.
    pub fn grant_group(&self, group_id: &str) {
        self.live_authorized_groups.grant(group_id);
    }

    /// Replaces the entire live-authorized-group set at once — useful when
    /// the caller already has the full, current list of groups this peer
    /// shares (e.g. recomputed from a fresh netmap) rather than a single
    /// added/removed edge.
    pub fn set_authorized_groups(&self, group_ids: impl IntoIterator<Item = String>) {
        self.live_authorized_groups.set(group_ids);
    }

    /// This peer's *current* role
    /// (`PeerRole::Read` or `PeerRole::Write`) for `group_id`, as granted
    /// by this (local) device — defaults to `PeerRole::Write` for a group
    /// with no role set (see `LiveGroupRoles`'s doc comment on why that's
    /// the correct backward-compatible default). Public so tests and a
    /// future daemon-level caller can both observe the current state, the
    /// same way `shares_group` is public.
    pub fn peer_role(&self, group_id: &str) -> PeerRole {
        self.live_group_roles.role_for(group_id)
    }

    /// Sets (or changes) this peer's role for `group_id`, effective for the
    /// very next message `reconcile_files_if_authorized` processes for it —
    /// mirrors `grant_group`/`revoke_group`'s "effective immediately, no
    /// transport teardown required" contract (a role that is
    /// downgraded takes effect on the next message, not only at
    /// session setup). The hook a daemon-level netmap-diff reaction is
    /// expected to call when a netmap update changes this peer's role for
    /// an already-shared group.
    pub fn set_peer_role(&self, group_id: &str, role: PeerRole) {
        self.live_group_roles.set(group_id, role);
    }

    /// Replaces every currently-tracked peer role at once — the role
    /// analogue of `set_authorized_groups`, useful when the caller already
    /// has the full, current `(group_id, role)` set for this peer (e.g.
    /// recomputed from a fresh netmap) rather than a single changed edge.
    /// A group_id omitted from `roles` reverts to the `PeerRole::Write`
    /// default on the next `peer_role` lookup.
    pub fn set_peer_roles(&self, roles: impl IntoIterator<Item = (String, PeerRole)>) {
        self.live_group_roles.set_all(roles);
    }

    /// PERF-5: takes an owned `Arc<Self>` (not `&self`) — the previous
    /// `&self` receiver only ever needed to live as long as this call, but
    /// `reconcile_files`'s bounded-concurrent processing (below) needs to
    /// clone a session handle into each spawned task, which requires an
    /// owned `Arc` to clone from in the first place. Every caller of this
    /// already has an `Arc<Self>` in hand (`run`'s recv loop clones one per
    /// spawned message-handler task anyway), so this is a free change at
    /// every call site.
    async fn handle_message(self: Arc<Self>, msg: proto::SyncMessage) -> Result<(), SyncError> {
        use proto::sync_message::Payload;
        match msg.payload {
            // No longer informational
            // only — records the peer's advertised compression support.
            Some(Payload::ClusterConfig(config)) => {
                // Set
                // unconditionally, regardless of what this specific
                // `ClusterConfig` advertises — used only to compute this
                // device's own outgoing `acked_peer_cluster_config` (see
                // `cluster_config_message`), NOT as the retry loop's own
                // stop condition (that's `peer_acked_my_cluster_config`
                // below — see its doc comment for why the two must be
                // kept separate).
                self.peer_handshake_received.store(true, std::sync::atomic::Ordering::Relaxed);
                if config.acked_peer_cluster_config {
                    self.peer_acked_my_cluster_config
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                self.handshake_notify.notify_one();
                self.record_peer_compression_support(&config.supported_compression);
                self.record_peer_encryption_support(config.supports_encrypted_storage_peer);
                self.record_peer_reliable_delivery_support(config.supports_reliable_delivery);
                Ok(())
            }
            Some(Payload::EncryptedFullIndex(index)) => {
                self.handle_encrypted_index(index.folder_group_id, index.files).await
            }
            Some(Payload::EncryptedIndexUpdate(update)) => {
                self.handle_encrypted_index(update.folder_group_id, update.changed_files).await
            }
            Some(Payload::WrappedGroupKey(wrapped)) => self.handle_wrapped_group_key(wrapped),
            Some(Payload::FullIndex(index)) => {
                let group_id = index.folder_group_id;
                let Some(files) = self
                    .decode_index_files(index.files, index.compressed_files, index.compression)
                    .await
                else {
                    return Ok(());
                };
                self.reconcile_files_if_authorized(&group_id, files).await
            }
            Some(Payload::IndexUpdate(update)) => {
                let group_id = update.folder_group_id;
                let Some(files) = self
                    .decode_index_files(
                        update.changed_files,
                        update.compressed_changed_files,
                        update.compression,
                    )
                    .await
                else {
                    return Ok(());
                };
                self.reconcile_files_if_authorized(&group_id, files).await
            }
            Some(Payload::BlockRequest(req)) => self.handle_block_request(req).await,
            Some(Payload::BlockResponse(resp)) => {
                self.handle_block_response(resp).await;
                Ok(())
            }
            Some(Payload::Presence(signal)) => {
                self.handle_presence_signal(signal);
                Ok(())
            }
            // Also covers a peer running a *newer* protocol version that
            // added a oneof variant this build doesn't know about yet:
            // prost decodes an unrecognized oneof case as an
            // unset `payload`, landing here rather than failing to
            // decode — so a peer this build can't fully understand is
            // simply ignored, never an error.
            None => Ok(()),
        }
    }

    /// security hardening: an authorized peer's session is only ever authenticated
    /// as *itself* (`self.peer_device_id`) — sharing a folder group grants
    /// no authority to speak for any other device, so a signal claiming a
    /// different `device_id` is spoofing "who is editing", and a signal
    /// whose `path` isn't a safe relative path (the same check applied on
    /// the sync-reconciliation path, `is_safe_relative_path`, but
    /// previously not here) could surface arbitrary/unsafe path strings
    /// to the UI. Both are dropped outright rather than overridden/
    /// sanitized in place — a mismatch or unsafe path is already
    /// sufficient grounds to distrust the whole signal.
    fn handle_presence_signal(&self, signal: proto::PresenceSignal) {
        if !self.shares_group(&signal.folder_group_id) {
            tracing::warn!(
                group_id = %signal.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring presence signal for unauthorized/unshared folder group"
            );
            return;
        }
        if signal.device_id != self.peer_device_id {
            tracing::warn!(
                claimed_device_id = %signal.device_id,
                peer = %self.peer_device_id,
                "ignoring presence signal: claimed device_id does not match the authenticated peer"
            );
            return;
        }
        if !is_safe_relative_path(&signal.path) {
            tracing::warn!(
                path = %signal.path,
                peer = %self.peer_device_id,
                "ignoring presence signal with an unsafe path"
            );
            return;
        }
        if let Some(tx) = &self.presence_tx {
            let _ = tx.send(PresenceEvent {
                group_id: signal.folder_group_id,
                path: signal.path,
                device_id: signal.device_id,
                editing: signal.editing,
                ttl_seconds: signal.ttl_seconds,
            });
        }
    }

    /// Guards every incoming index message against a peer sending data for
    /// a folder group it (or we) aren't actually authorized to share —
    /// `shares_group` checks this session's *current*
    /// `live_authorized_groups`, not just the ACL-verified intersection
    /// established at session construction time, so an index update from a
    /// peer whose authorization for `group_id` was revoked mid-session is
    /// rejected here even though the message arrived over an
    /// already-established, not-yet-torn-down transport channel — not
    /// something a peer can widen by simply naming a different group_id in
    /// a message, nor something a revocation has to wait for transport
    /// teardown to stop.
    async fn reconcile_files_if_authorized(
        self: Arc<Self>,
        group_id: &str,
        files: Vec<proto::FileInfo>,
    ) -> Result<(), SyncError> {
        if !self.shares_group(group_id) {
            tracing::warn!(group_id, peer = %self.peer_device_id, "ignoring index message for unauthorized/unshared folder group");
            return Ok(());
        }
        // A peer this device has shared
        // `group_id` to at role `read` is a consumer only — it may
        // receive our index/blocks (`send_full_index`/`send_index_update`/
        // `handle_block_request` are unaffected by role, per the spec's "serve
        // index and block reads to that peer"), but its own inbound index
        // updates/writes must never be accepted into our copy, since a
        // read-only sharee shouldn't be able to push changes into the
        // shared folder. Checked here (not just at session construction)
        // for the same reason `shares_group` above is: `peer_role` reads
        // the live, mutable-after-construction `live_group_roles`, so a
        // role downgraded write -> read mid-session is enforced starting
        // with the very next `FullIndex`/`IndexUpdate`, not only for
        // sessions established after the downgrade ("takes effect on
        // the next message, not only at session setup"). Dropped the same
        // way an unauthorized-group message is dropped above — logged, no
        // partial application, no error surfaced back to the peer (a
        // malicious/misbehaving read-only peer gets no signal distinguishing
        // "rejected for role" from "rejected for authorization", by design).
        if self.peer_role(group_id) == PeerRole::Read {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring index message from a read-only peer: read-role sharees may not push \
                 changes into the shared folder"
            );
            return Ok(());
        }
        // Pause "trumps everything
        // regardless of mode" — a paused link neither sends
        // (the daemon's pre-existing `announce_local_change` gate) nor
        // applies (this gate, new: nothing in this module previously
        // consulted `paused` at all on the incoming-apply path). Dropped
        // the same way an unauthorized-group/read-role message is dropped
        // above: logged, no partial application, no divergence recorded —
        // a *paused* link isn't "gated by mode", it's suspended entirely,
        // so this intentionally doesn't call `record_out_of_sync` the way
        // a `send-only` link's mode gate does; resuming re-syncs via the
        // peer's own next full-index resend, the same eventual-consistency
        // path `resume_link`/`set_link_mode_and_reconcile` already rely on.
        if self.state.is_paused_for_group(group_id)? {
            tracing::debug!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring index message for a paused link"
            );
            return Ok(());
        }
        // security hardening: bound the cardinality of a single incoming index
        // message before doing any work on it — see
        // `MAX_FILES_PER_INDEX_MESSAGE`/`MAX_BLOCKS_PER_INDEX_MESSAGE`'s
        // doc comment. Rejected wholesale (not truncated to the cap):
        // truncation would silently process an arbitrary subset chosen by
        // message order, which is itself peer-influenceable and gives no
        // stronger a guarantee than rejecting outright, whereas rejecting
        // is simple, sets a hard ceiling per message, and relies on the
        // same eventual-consistency resend behavior `reconcile_files`
        // already leans on elsewhere in this module.
        if index_message_exceeds_cardinality_cap(
            &files,
            MAX_FILES_PER_INDEX_MESSAGE,
            MAX_BLOCKS_PER_INDEX_MESSAGE,
        ) {
            let total_blocks: usize = files.iter().map(|f| f.blocks.len()).sum();
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                file_count = files.len(),
                total_blocks,
                "rejecting index message exceeding cardinality cap \
                 (file count and/or total block count)"
            );
            return Ok(());
        }
        self.reconcile_files(group_id, files).await
    }

    async fn handle_block_request(&self, req: proto::BlockRequest) -> Result<(), SyncError> {
        // A block store is shared across all folder groups on this device,
        // so a hash by itself doesn't imply group
        // membership — without this check a peer could fetch any block
        // this device holds, from any group, by guessing/observing a
        // hash, regardless of what it's actually authorized to sync.
        //
        // `shares_group` is
        // called fresh on every single incoming `BlockRequest` (this
        // function has no per-session cache of its own answer), and reads
        // `live_authorized_groups` rather than the construction-time
        // `shared_group_ids` snapshot — so a group edge revoked by a
        // netmap update that lands *after* this session started, and
        // *before* this particular request is processed, is already
        // reflected here, even though the transport-level tunnel/peer
        // channel this request arrived over has not been torn down (that's
        // a separate, independent reaction to the same netmap update).
        // The lookup itself stays a local, in-memory
        // `Mutex`-guarded `HashSet` check — no coordination-plane round
        // trip is made per request, consistent with a push model.
        if !self.shares_group(&req.folder_group_id) {
            tracing::warn!(group_id = %req.folder_group_id, peer = %self.peer_device_id, "ignoring block request for unauthorized/unshared folder group");
            let response = proto::BlockResponse {
                block_hash: req.block_hash,
                data: vec![],
                not_found: true,
                compression: proto::Compression::None as i32,
                ..Default::default()
            };
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                })
                .await;
        }
        // This peer's own request for
        // `req.block_hash` is only meaningful as a *ciphertext* hash when
        // it's flagged storage-only for the group — `block_request_is_
        // referenced` below checks a *plaintext* block's presence in a
        // `FileRecord`, which has no meaning for a ciphertext hash, so this
        // branches into its own self-contained path before reaching it (or
        // the plaintext `self.store` lookup after it) at all. See
        // `handle_ciphertext_block_request`'s doc comment for why this
        // never falls back to serving plaintext on any failure path.
        if self.live_storage_only_flags.is_storage_only(&req.folder_group_id) {
            return self.handle_ciphertext_block_request(req).await;
        }
        // The other direction — *this local device* is itself
        // storage-only for the group, so it holds no `FileRecord`s to
        // check `req.block_hash` against at all (it only ever has
        // whatever opaque ciphertext blobs peers handed it, addressed by
        // their own content hash) — `block_request_is_referenced` below
        // would incorrectly refuse every request in this role. Serving
        // directly by content hash (skipping that plaintext-specific
        // check) is exactly the untrusted peer's designed role: "still
        // content-address, dedup, and serve" to any authorized
        // requester, without ever decrypting or knowing what the bytes are.
        if self.is_locally_storage_only(&req.folder_group_id) {
            return self.serve_stored_ciphertext_block(req).await;
        }
        if !self.block_request_is_referenced(&req)? {
            tracing::warn!(
                group_id = %req.folder_group_id,
                path = %req.file_path,
                peer = %self.peer_device_id,
                hash = %hex::encode(&req.block_hash),
                "refusing block request not referenced by the requested file record"
            );
            let response = proto::BlockResponse {
                block_hash: req.block_hash,
                data: vec![],
                not_found: true,
                compression: proto::Compression::None as i32,
                ..Default::default()
            };
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                })
                .await;
        }
        let hash_hex = hex::encode(&req.block_hash);
        // PERF-1: `BlockStore::get` does synchronous `std::fs` I/O plus a
        // full-content SHA-256 re-hash (verify-on-read) — calling it
        // directly here would block whichever tokio worker thread is
        // running this spawned message-handler task, stalling every other
        // peer's message handling/heartbeats on that worker for the
        // duration of the read. `spawn_blocking` moves it to the blocking
        // thread pool instead. A `JoinError` (the blocking closure
        // panicking) is folded into the same `not_found` response as any
        // other read failure — the pre-existing behavior for *any* error
        // from `store.get`, so this doesn't add a new observable outcome,
        // it just also covers a panic without taking the whole recv loop
        // down with it.
        let store = self.store.clone();
        let get_result = spawn_blocking(move || store.get(&hash_hex)).await;
        let response = match get_result {
            Ok(Ok(data)) => {
                // Compress the fetched
                // bytes off the async runtime — `spawn_blocking`, the same
                // PERF-1 reasoning as the `store.get` call just above,
                // since zstd compression of a multi-hundred-KB block is
                // real CPU work — but only when this session's peer has
                // negotiated compression support; `compress_
                // block` itself decides whether compression was actually
                // worth sending (D3's adaptive skip).
                let compress_result = if self.compression_negotiated() {
                    spawn_blocking(move || compress_block(&data)).await
                } else {
                    Ok((data, proto::Compression::None))
                };
                match compress_result {
                    Ok((data, compression)) => proto::BlockResponse {
                        block_hash: req.block_hash,
                        data,
                        not_found: false,
                        compression: compression as i32,
                        ..Default::default()
                    },
                    // A panicking compression task is folded into
                    // `not_found`, mirroring how a panicking `store.get`
                    // below already is (see that match arm's doc comment)
                    // — this doesn't add a new observable failure mode, it
                    // reuses the existing one.
                    Err(_join_err) => proto::BlockResponse {
                        block_hash: req.block_hash,
                        data: vec![],
                        not_found: true,
                        compression: proto::Compression::None as i32,
                        ..Default::default()
                    },
                }
            }
            Ok(Err(_)) | Err(_) => proto::BlockResponse {
                block_hash: req.block_hash,
                data: vec![],
                not_found: true,
                compression: proto::Compression::None as i32,
                ..Default::default()
            },
        };
        // Gate the outbound block
        // *payload* on the upload bucket, consuming tokens for the actual
        // bytes about to be transmitted, before the send proceeds
        // ("awaiting bucket refill rather than dropping or erroring").
        // A `not_found` response carries no data (`acquire(0)` is a no-op
        // fast path — see `TokenBucket::acquire`), so this never delays the
        // control-flow-shaped "no, I don't have it" replies.
        if !response.not_found {
            self.rate_limiters().upload.acquire(response.data.len() as u64).await;
        }
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::BlockResponse(response)),
        })
        .await
    }

    /// Serves a storage-only peer's request for `req.block_hash`
    /// (a *ciphertext* hash) by re-encrypting the matching plaintext block
    /// on the fly from this device's own plaintext store and replying with
    /// `data` carrying AEAD ciphertext, `is_ciphertext = true`, and the
    /// nonce needed to decrypt it. Never persists ciphertext locally (this
    /// device is trusted — it keeps only its ordinary plaintext store; this
    /// is not a general encrypt-at-rest
    /// feature for trusted devices) and never falls back to plaintext on
    /// any failure: with no group content key available, or no matching
    /// block found, this replies `not_found` exactly like an ordinary
    /// missing-block response, never the plaintext bytes.
    ///
    /// Convergent encryption is what makes re-deriving `H(ct)`
    /// on every request tractable at all: `ct = AEAD(K_g, KDF(K_g, h),
    /// plaintext)` is a pure function of `(K_g, h, plaintext)`, so this
    /// device never needs a persisted `h -> ciphertext_hash` index — it
    /// can always recompute the same ciphertext (and thus the same
    /// ciphertext hash) on demand from data it already has. The documented
    /// cost of that simplicity: with no such index, this scans every block
    /// of every file in the group and re-encrypts each until one's
    /// ciphertext hash matches (or none do) — O(group size) per single
    /// ciphertext block request, not O(1). Acceptable for this pass
    /// (correctness first; a persisted index isn't required for this pass),
    /// and disclosed here plainly rather than hidden, matching this
    /// change's other disclosed trade-offs (metadata leakage, equal-block
    /// correlation, rotation cost).
    async fn handle_ciphertext_block_request(
        &self,
        req: proto::BlockRequest,
    ) -> Result<(), SyncError> {
        let not_found_response = |block_hash: Vec<u8>| proto::BlockResponse {
            block_hash,
            data: vec![],
            not_found: true,
            ..Default::default()
        };
        let Some(key_state) = self.group_key_for(&req.folder_group_id) else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "no group content key available locally -- refusing storage-only peer's block \
                 request rather than ever serving plaintext"
            );
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(not_found_response(
                        req.block_hash,
                    ))),
                })
                .await;
        };

        let files = self.state.list_files(&req.folder_group_id)?;
        for record in files {
            for block in &record.blocks {
                let store = self.store.clone();
                let hash_hex = hex::encode(&block.hash);
                let plaintext = match spawn_blocking(move || store.get(&hash_hex)).await {
                    Ok(Ok(data)) => data,
                    _ => continue,
                };
                let Ok(encrypted) = content_crypto::encrypt_block(
                    &key_state.key,
                    &block.hash,
                    &plaintext,
                    key_state.convergent,
                ) else {
                    continue;
                };
                if encrypted.ciphertext_hash().as_slice() != req.block_hash.as_slice() {
                    continue;
                }
                let response = proto::BlockResponse {
                    block_hash: req.block_hash,
                    data: encrypted.ciphertext,
                    not_found: false,
                    is_ciphertext: true,
                    ciphertext_nonce: encrypted.nonce.to_vec(),
                    ..Default::default()
                };
                self.rate_limiters().upload.acquire(response.data.len() as u64).await;
                return self
                    .send(proto::SyncMessage {
                        payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                    })
                    .await;
            }
        }
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::BlockResponse(not_found_response(
                req.block_hash,
            ))),
        })
        .await
    }

    /// Serves `req.block_hash` (a ciphertext hash) directly from
    /// this device's own store, for when *this local device* is itself the
    /// storage-only device for the group — see `handle_block_request`'s
    /// branch immediately above for why this skips `block_request_is_
    /// referenced` (there are no `FileRecord`s to check here at all). Never
    /// decrypts anything (this device may hold no group key at all) — it
    /// just serves back whatever ciphertext bytes and nonce it has on
    /// file, exactly matching the "storage peer serves blocks back to
    /// trusted devices who decrypt and verify them locally" design.
    async fn serve_stored_ciphertext_block(
        &self,
        req: proto::BlockRequest,
    ) -> Result<(), SyncError> {
        let not_found_response = proto::BlockResponse {
            block_hash: req.block_hash.clone(),
            data: vec![],
            not_found: true,
            ..Default::default()
        };
        let hash_hex = hex::encode(&req.block_hash);
        let Some(nonce) = self
            .ciphertext_nonce_cache()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&req.block_hash)
            .copied()
        else {
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(not_found_response)),
                })
                .await;
        };
        let store = self.store.clone();
        let get_result = spawn_blocking(move || store.get(&hash_hex)).await;
        let response = match get_result {
            Ok(Ok(data)) => proto::BlockResponse {
                block_hash: req.block_hash,
                data,
                not_found: false,
                is_ciphertext: true,
                ciphertext_nonce: nonce.to_vec(),
                ..Default::default()
            },
            _ => not_found_response,
        };
        if !response.not_found {
            self.rate_limiters().upload.acquire(response.data.len() as u64).await;
        }
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::BlockResponse(response)),
        })
        .await
    }

    fn block_request_is_referenced(&self, req: &proto::BlockRequest) -> Result<bool, SyncError> {
        let Some(record) = self.state.get_file(&req.folder_group_id, &req.file_path)? else {
            return Ok(false);
        };
        if record.deleted {
            return Ok(false);
        }
        Ok(record.blocks.iter().any(|block| block.hash == req.block_hash))
    }

    /// Decompresses `resp.data` per its
    /// declared `compression` (off the async runtime — `spawn_blocking`,
    /// the same PERF-1 reasoning as every other compress/
    /// decompress call in this module) before waking any waiter, so
    /// `ensure_blocks_present`'s existing hash/size check always
    /// verifies against decompressed bytes, and `fetch_block`'s callers
    /// (this crate's own `hydrate_file`/`ensure_blocks_present`, and the
    /// daemon's multi-peer hydration dispatcher — see `fetch_block`'s doc
    /// comment) never see a still-compressed payload; compression stays
    /// completely invisible past this point.
    ///
    /// On a decompression failure (corrupt payload, or the decompression-
    /// bomb bound exceeded), every waiter is woken with
    /// `FetchOutcome::Unusable`, not `FetchOutcome::NotFound` — see that
    /// enum's own doc comment for why
    /// this distinction now matters to `ensure_blocks_present` specifically,
    /// even though every *other* consumer of a fetch result (the plain
    /// `fetch_block` wrapper, and the daemon's `fetch_blocks_from_sessions`
    /// reassigning to another candidate peer) still collapses both into
    /// the same "this peer did not supply a usable block" outcome, exactly
    /// as before this change.
    async fn handle_block_response(&self, resp: proto::BlockResponse) {
        // A ciphertext response
        // resolves against the separate `pending_ciphertext_block_requests`
        // waiter map, carrying its nonce through — see
        // `PendingCiphertextBlockRequests`'s doc comment for why this is a
        // sibling branch rather than folded into the logic below, which is
        // otherwise completely unchanged from before this change existed.
        if resp.is_ciphertext {
            self.handle_ciphertext_block_response(resp);
            return;
        }
        let waiters = {
            let mut pending =
                self.pending_block_requests.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.remove(&resp.block_hash)
        };
        let Some(waiters) = waiters else { return };
        let payload = if resp.not_found {
            FetchOutcome::NotFound
        } else {
            let compression =
                proto::Compression::try_from(resp.compression).unwrap_or(proto::Compression::None);
            // Only route through `spawn_blocking`
            // when there's real decompression work to do. `Compression::
            // None` is a trivial passthrough (`decompress_block` itself
            // just clones the bytes for that case) — forcing every single
            // block response, compressed or not, through a blocking-pool
            // round trip would add real scheduling latency to what used to
            // be an immediate, synchronous fast path, for the overwhelming
            // majority of responses (an unnegotiated peer, or a block
            // `compress_block` decided wasn't worth compressing). The
            // PERF-1 "off the async runtime" reasoning applies to
            // actual CPU-bound zstd work, not a no-op passthrough.
            if compression == proto::Compression::None {
                FetchOutcome::Found(Bytes::from(resp.data))
            } else {
                let data = resp.data;
                let block_hash = resp.block_hash.clone();
                match spawn_blocking(move || decompress_block(&data, compression, MAX_BLOCK_SIZE))
                    .await
                {
                    // `Bytes::from(Vec<u8>)` reuses the existing allocation,
                    // no copy. Every waiter beyond the first then gets a
                    // cheap refcount `clone()` of that same `Bytes` instead
                    // of its own full copy of the block (PERF-6; see
                    // `PendingBlockRequests`'s doc comment) — unaffected by
                    // decompression happening first.
                    Ok(Ok(decompressed)) => FetchOutcome::Found(Bytes::from(decompressed)),
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            hash = %hex::encode(&block_hash),
                            peer = %self.peer_device_id,
                            "rejecting block response: failed to decompress (corrupt payload or \
                             decompression-bomb bound exceeded); treating this peer as not \
                             having the block"
                        );
                        FetchOutcome::Unusable
                    }
                    Err(_join_err) => FetchOutcome::Unusable,
                }
            }
        };
        for tx in waiters {
            let _ = tx.send(payload.clone());
        }
    }

    /// Requests a block from the peer and awaits the matching response,
    /// fulfilled by `handle_block_response` running concurrently on the
    /// same session's recv loop. Public: the low-level per-block fetch
    /// primitive the daemon's
    /// multi-session hydration dispatcher (`yadorilink-daemon::hydration`)
    /// calls directly across several sessions concurrently, rather than
    /// each session fetching a whole file's blocks sequentially on its
    /// own. Does not write to the block store — the caller does that with
    /// the returned data, so callers coordinating across multiple
    /// sessions decide for themselves when/whether to persist a result.
    /// Returns `Bytes` (PERF-6), not `Vec<u8>` — see `PendingBlockRequests`'s
    /// doc comment for why: it's a cheap, refcounted clone of the same
    /// underlying data `handle_block_response` already holds, not a copy.
    ///
    /// This collapses `FetchOutcome::
    /// NotFound`/`Unusable` into the same `None` as before this change —
    /// unchanged for this function's existing callers (the daemon's
    /// multi-peer dispatcher, which already has its own "try a different
    /// peer" fallback for either case). `ensure_blocks_present` calls
    /// `fetch_block_raw` directly instead, to see the distinction and
    /// retry only `NotFound` — see that function's and `FetchOutcome`'s
    /// doc comments.
    pub async fn fetch_block(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<Option<Bytes>, SyncError> {
        Ok(self.fetch_block_raw(group_id, file_path, hash).await?.into_bytes())
    }

    async fn fetch_block_raw(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<FetchOutcome, SyncError> {
        let (tx, rx) = oneshot::channel();
        self.pending_block_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(hash.to_vec())
            .or_default()
            .push(tx);
        let _guard =
            PendingBlockGuard { pending: &self.pending_block_requests, hash: hash.to_vec() };
        // Measured from just before
        // the request goes out to the response actually arriving — the
        // real block-request-to-response round trip the adaptive
        // window is driven by.
        let started_at = std::time::Instant::now();
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                folder_group_id: group_id.to_string(),
                file_path: file_path.to_string(),
                block_hash: hash.to_vec(),
            })),
        })
        .await?;
        // Only an actual reply from
        // the peer (a real block, or an explicit not_found) is fed to the
        // adaptive window as an RTT sample — `rx.await` returning `Err`
        // means the sender was dropped without ever answering (e.g. this
        // session ending), which is neither a healthy round trip nor the
        // ambiguous "no reply within a caller's own bound" signal
        // `record_fetch_timeout` covers, so it's left alone rather than
        // double-counted as either.
        let result = match rx.await {
            Ok(payload) => {
                self.adaptive_window.on_success(started_at.elapsed());
                payload
            }
            Err(_recv_error) => FetchOutcome::NotFound,
        };
        // Gate the received block
        // *payload* on the download bucket. The bytes have already crossed
        // the wire by this point (gating happens at the session/
        // transfer layer, not the transport itself — this can't literally
        // delay wire bytes without deep transport hooks), but debiting here
        // throttles the *pace* of subsequent fetches: every caller of this
        // function — `ensure_blocks_present`'s eager-fetch loop below, and
        // the daemon's multi-peer hydration dispatcher, which calls this
        // directly as its single per-block choke point ("one
        // global ceiling") — awaits this call before issuing its next
        // request, so a saturated download bucket naturally caps aggregate
        // throughput across every concurrent peer/lane sharing it. Neither
        // a not-found nor an unusable-payload result carries billable
        // bytes (`acquire(0)` is a no-op), so neither is ever delayed here.
        if let FetchOutcome::Found(data) = &result {
            self.rate_limiters().download.acquire(data.len() as u64).await;
        }
        Ok(result)
    }

    /// Resolves a waiter registered by `fetch_block_from_
    /// storage_peer` against a `BlockResponse` with `is_ciphertext = true`
    /// — the ciphertext-fetch analogue of the plaintext-path resolution
    /// just above, kept entirely separate (see `PendingCiphertextBlockRequests`'s
    /// doc comment). A malformed nonce length (a peer sending nonsense, or
    /// a bug) resolves as `None` — "this peer did not supply a usable
    /// block" — the same reject-and-treat-as-unavailable signal a
    /// decompression failure or hash mismatch already uses elsewhere.
    fn handle_ciphertext_block_response(&self, resp: proto::BlockResponse) {
        let waiters = {
            let mut pending = self
                .pending_ciphertext_block_requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.remove(&resp.block_hash)
        };
        let Some(waiters) = waiters else { return };
        let payload = if resp.not_found {
            None
        } else if resp.ciphertext_nonce.len() != content_crypto::NONCE_LEN {
            tracing::warn!(
                peer = %self.peer_device_id,
                hash = %hex::encode(&resp.block_hash),
                nonce_len = resp.ciphertext_nonce.len(),
                "rejecting ciphertext block response: malformed nonce length; treating this \
                 peer as not having the block"
            );
            None
        } else {
            let mut nonce = [0u8; content_crypto::NONCE_LEN];
            nonce.copy_from_slice(&resp.ciphertext_nonce);
            Some(CiphertextBlockPayload { data: Bytes::from(resp.data), nonce })
        };
        for tx in waiters {
            let _ = tx.send(payload.clone());
        }
    }

    /// Fetches a ciphertext block (by `H(ciphertext)`) from
    /// this session's peer — which must be flagged storage-only for
    /// `group_id` in the caller's own bookkeeping (this method itself does
    /// not check that; it is meaningful to call whenever the peer is known
    /// to hold ciphertext, which today is precisely a storage-only peer) —
    /// decrypts the response with this device's group content key, and
    /// verifies the decrypted plaintext's content hash against
    /// `plaintext_hash` (`h`, the trusted block identity from this
    /// device's own index) before returning it.
    ///
    /// Returns `Ok(None)` — never the wrong bytes — whenever anything about
    /// the response can't be trusted: no group key available locally, the
    /// peer reported `not_found`, AEAD authentication failed (tampered or
    /// foreign ciphertext), or the decrypted plaintext's hash doesn't match
    /// `plaintext_hash` (the encrypted-peer spec's "A malicious storage
    /// peer returning wrong bytes is detected" scenario — see `content_
    /// crypto::decrypt_block`'s doc comment on why AEAD authentication
    /// alone cannot catch a peer substituting a different, validly-
    /// encrypted block). This mirrors `fetch_block`'s own `Ok(None)` =
    /// "peer did not supply a usable block" contract exactly, so a caller
    /// already built to retry `fetch_block` against another candidate peer
    /// on `Ok(None)` (this crate's `ensure_blocks_present`, or the daemon's
    /// multi-peer hydration dispatcher) can react to this the identical
    /// way — the existing reject-and-reassign path, reused rather than
    /// replaced.
    /// The low-level ciphertext fetch primitive — requests
    /// `ciphertext_hash` from this session's peer and returns the raw
    /// ciphertext bytes plus nonce, with **no decryption or plaintext-hash
    /// verification** (that's `fetch_block_from_storage_peer`'s job, for a
    /// trusted device that holds a group key). Split out specifically so a
    /// *locally storage-only* device (`is_locally_storage_only`) — which
    /// has no group key and must never attempt to decrypt anything — can
    /// still fetch and persist opaque ciphertext blocks it's missing
    /// (`handle_encrypted_index`'s locally-storage-only branch), registering
    /// its waiter in the same ciphertext waiter map (`pending_ciphertext_
    /// block_requests`) `handle_ciphertext_block_response` resolves against
    /// — using the plain `fetch_block`/`pending_block_requests` machinery
    /// here instead would never be woken, since a `BlockResponse` with
    /// `is_ciphertext = true` is dispatched only to the ciphertext map (see
    /// `handle_block_response`'s branch).
    async fn fetch_raw_ciphertext_block(
        &self,
        group_id: &str,
        ciphertext_hash: &[u8],
    ) -> Result<Option<CiphertextBlockPayload>, SyncError> {
        let (tx, rx) = oneshot::channel();
        self.pending_ciphertext_block_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(ciphertext_hash.to_vec())
            .or_default()
            .push(tx);
        let _guard = PendingCiphertextBlockGuard {
            pending: &self.pending_ciphertext_block_requests,
            hash: ciphertext_hash.to_vec(),
        };
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::BlockRequest(proto::BlockRequest {
                folder_group_id: group_id.to_string(),
                file_path: String::new(),
                block_hash: ciphertext_hash.to_vec(),
            })),
        })
        .await?;
        Ok(rx.await.unwrap_or(None))
    }

    pub async fn fetch_block_from_storage_peer(
        &self,
        group_id: &str,
        ciphertext_hash: &[u8],
        plaintext_hash: &[u8],
    ) -> Result<Option<Bytes>, SyncError> {
        let Some(key_state) = self.group_key_for(group_id) else {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "no group content key available locally -- cannot fetch/decrypt from this \
                 storage peer"
            );
            return Ok(None);
        };

        let Some(payload) = self.fetch_raw_ciphertext_block(group_id, ciphertext_hash).await?
        else {
            return Ok(None);
        };

        let plaintext =
            match content_crypto::decrypt_block(&key_state.key, &payload.nonce, &payload.data) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    tracing::warn!(
                        group_id,
                        peer = %self.peer_device_id,
                        ciphertext_hash = %hex::encode(ciphertext_hash),
                        "storage peer returned ciphertext that failed AEAD decryption (tampered, \
                         wrong key, or wrong nonce) -- rejecting, not persisting"
                    );
                    return Ok(None);
                }
            };
        // The critical post-decrypt check — AEAD authentication
        // alone only proves this ciphertext was produced under this
        // group's key with this nonce, not that it's the block actually
        // requested (see `content_crypto::decrypt_block`'s doc comment).
        let actual_hash = Sha256::digest(&plaintext);
        if actual_hash.as_slice() != plaintext_hash {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                ciphertext_hash = %hex::encode(ciphertext_hash),
                "storage peer returned a block whose decrypted plaintext hash did not match \
                 the expected content identity -- rejecting, not persisting"
            );
            return Ok(None);
        }
        // Gate the received (decrypted)
        // payload on the download bucket, mirroring `fetch_block`'s
        // identical accounting for the plaintext path.
        self.rate_limiters().download.acquire(plaintext.len() as u64).await;
        Ok(Some(Bytes::from(plaintext)))
    }

    /// Bounded retry for a "peer did
    /// not supply a usable block" response inside `ensure_blocks_present`
    /// (not inside `fetch_block` itself, and not with a finer-grained
    /// retry-reason taxonomy — see that function's doc comment for both
    /// of those decisions). 5 total attempts (1 initial + 4 retries),
    /// ~100ms apart with jitter to avoid synchronized retry bursts when
    /// many files conflict at once, is generous enough to absorb the
    /// observed race (which resolves once the other side's own
    /// materialize/upsert completes, observed well under a second even on
    /// a resource-constrained real machine) while keeping a genuinely-
    /// unusable block's added worst-case latency small (well under 1s).
    const NOT_FOUND_RETRY_ATTEMPTS: u32 = 5;
    const NOT_FOUND_RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
    const NOT_FOUND_RETRY_JITTER_FRACTION: f64 = 0.25;

    fn not_found_retry_delay() -> std::time::Duration {
        let jitter = rand::random_range(
            -Self::NOT_FOUND_RETRY_JITTER_FRACTION..=Self::NOT_FOUND_RETRY_JITTER_FRACTION,
        );
        Self::NOT_FOUND_RETRY_BASE_DELAY.mul_f64(1.0 + jitter)
    }

    /// Fetches only the blocks not already held locally (
    /// missing-block computation; local dedup — a block already
    /// present, from any file/version, is never re-requested). Returns
    /// whether every block ended up present locally — `false` if this
    /// peer reported any as not found, which `hydrate_file` uses to know a
    /// fetch is incomplete, not just to log it.
    ///
    /// Retries a bounded number of
    /// times (`NOT_FOUND_RETRY_ATTEMPTS`) before accepting a
    /// `FetchOutcome::NotFound` as final — see `FetchOutcome`'s own doc
    /// comment for why this specifically retries `NotFound` and not
    /// `Unusable` (a decompression failure or similar). Two devices
    /// independently resolving the same conflict compute the same
    /// deterministic conflict-copy path (`conflict::resolve_conflict_names`)
    /// and can each request the other's content for it directly — one
    /// side's request can legitimately arrive before the other side's own
    /// `resolve_and_apply_conflict` has finished materializing/upserting
    /// that exact record locally, so `block_request_is_referenced` finds
    /// nothing yet and refuses with `not_found`. That's a transient race
    /// at the file-record/index layer, not a real content absence — the
    /// requested block's bytes are typically already sitting in the
    /// responding peer's own block store the whole time (it's that
    /// device's own prior edit); what's missing is the index entry
    /// linking the new conflict-copy path to those bytes. Since this
    /// retry is bounded (not indefinite), a block genuinely absent from
    /// every peer still fails — just after a few hundred milliseconds of
    /// retries instead of on the first attempt — so
    /// `a_block_missing_from_every_peer_fails_hydration_cleanly` is
    /// unaffected in outcome, only in exact timing. This intentionally
    /// does NOT retry inside `fetch_block`/`fetch_block_raw` itself: the
    /// *other* caller of `fetch_block` (`yadorilink-daemon`'s multi-peer
    /// hydration dispatcher, `hydration.rs`) already has its own, faster
    /// "this peer doesn't have it — reassign to a different candidate
    /// peer" strategy for the exact same signal, and stacking a same-peer
    /// retry underneath that would only slow down an already-correct
    /// fallback.
    async fn ensure_blocks_present(
        &self,
        group_id: &str,
        file_path: &str,
        blocks: &[BlockInfo],
    ) -> Result<bool, SyncError> {
        // Batched presence check rather than probing one
        // hash at a time — most of a hydration's blocks are typically
        // already-known-missing (that's the point of a placeholder), so
        // this collapses what would otherwise be N separate local-storage
        // calls interleaved with network fetches into one upfront query.
        let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = self.store.present_blocks(&hashes)?;

        let mut all_present = true;
        for (block, already_present) in blocks.iter().zip(present) {
            if already_present {
                continue; // already held — dedup, no network round-trip
            }
            let mut attempt = 0;
            let fetched = loop {
                attempt += 1;
                match self.fetch_block_raw(group_id, file_path, &block.hash).await? {
                    FetchOutcome::Found(data) => break Some(data),
                    FetchOutcome::NotFound if attempt < Self::NOT_FOUND_RETRY_ATTEMPTS => {
                        tokio::time::sleep(Self::not_found_retry_delay()).await;
                    }
                    FetchOutcome::NotFound | FetchOutcome::Unusable => break None,
                }
            };
            match fetched {
                Some(data) => {
                    if !block_data_matches(block, &data) {
                        tracing::warn!(
                            file_path,
                            hash = %hex::encode(&block.hash),
                            peer = %self.peer_device_id,
                            "peer returned block data that did not match the expected hash/size"
                        );
                        all_present = false;
                        continue;
                    }
                    // PERF-1: `BlockStore::put` does synchronous `std::fs`
                    // I/O plus a SHA-256 hash of the whole block — same
                    // async-runtime-blocking concern as `handle_block_request`'s
                    // `store.get` above, so it gets the same `spawn_blocking`
                    // treatment. `data` (now `Bytes`, PERF-6) derefs to
                    // `&[u8]` for `BlockStore::put`'s `&[u8]` parameter.
                    let store = self.store.clone();
                    let put_result = spawn_blocking(move || store.put(&data)).await;
                    match put_result {
                        Ok(Ok(_hash)) => {}
                        Ok(Err(e)) => return Err(e.into()),
                        Err(join_err) => {
                            return Err(SyncError::from(std::io::Error::other(format!(
                                "block store write task panicked: {join_err}"
                            ))))
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        file_path,
                        attempts = attempt,
                        "peer reported block as not_found after retrying; sync incomplete for this file"
                    );
                    all_present = false;
                }
            }
        }
        Ok(all_present)
    }

    /// On-access hydration: fetches a
    /// placeholder file's blocks from this peer and materializes its full
    /// content, transitioning `Placeholder → Hydrating → Hydrated`. Bounded
    /// by a fixed timeout so a caller blocked on this (e.g. an
    /// OS read callback) never hangs indefinitely on an unresponsive peer.
    ///
    /// Returns `Ok(())` once content is fully written; `Err(HydrationFailed)`
    /// if this peer didn't have every block within the timeout — the file
    /// is left as (or reverted to) `Placeholder` either way, so a caller
    /// trying a *different* peer's session can simply retry.
    pub async fn hydrate_file(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.hydrate_file_with_timeout(group_id, path, DEFAULT_HYDRATION_TIMEOUT).await
    }

    /// Like `hydrate_file`, with an explicit timeout — production callers
    /// use the default (30s); tests use a much shorter one so
    /// the "no reachable peer" case doesn't make the suite slow.
    pub async fn hydrate_file_with_timeout(
        &self,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<(), SyncError> {
        let Some(record) = self.state.get_file(group_id, path)? else {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        };
        if record.deleted {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }

        self.state.set_materialization_state(group_id, path, MaterializationState::Hydrating)?;

        let outcome = tokio::time::timeout(
            timeout,
            self.ensure_blocks_present(group_id, path, &record.blocks),
        )
        .await;

        let all_present = match outcome {
            Ok(Ok(all_present)) => all_present,
            Ok(Err(e)) => {
                // A real error (not just missing blocks) — still revert
                // state below before propagating, so the file isn't left
                // stuck at `Hydrating`.
                let _ = self.state.set_materialization_state(
                    group_id,
                    path,
                    MaterializationState::Placeholder,
                );
                return Err(e);
            }
            Err(_timed_out) => false,
        };

        if !all_present {
            self.state.set_materialization_state(
                group_id,
                path,
                MaterializationState::Placeholder,
            )?;
            return Err(SyncError::HydrationFailed(path.to_string()));
        }

        // Same hazard short-circuit as
        // `materialize` — every block was just fetched into this device's
        // block store above regardless (so it can still serve them onward
        // to another peer), but the atomic reconstruct-to-disk
        // write below must never run for a hazardous name. Reverts back
        // to `Placeholder` (content genuinely isn't on disk under this
        // name) rather than leaving the row stuck at `Hydrating`, and
        // returns `Ok(())` rather than an error — the blocks really were
        // hydrated successfully; only local materialization was withheld.
        if let Some(reason) = self.hazard_reason_for(group_id, &record)? {
            self.state.set_materialization_state(
                group_id,
                path,
                MaterializationState::Placeholder,
            )?;
            self.state.set_held(group_id, path, &reason, now_unix_nanos())?;
            tracing::info!(
                path = %path,
                group_id,
                reason = %reason,
                "hydration fetched all blocks but the file is held due to a filename hazard; \
                 not materialized on this device"
            );
            return Ok(());
        }
        self.state.clear_held(group_id, path)?;

        let out_path = self.local_file_path(group_id, path);
        // security hardening defense-in-depth — see `materialize`'s matching call
        // for what this does and does not close.
        self.verify_write_target(group_id, &out_path)?;
        // Preflight before the
        // temp-then-rename write below begins — see
        // `preflight_disk_headroom`'s doc comment.
        self.preflight_disk_headroom(group_id, &out_path, record.size)?;
        reconstruct_file(self.store.as_ref(), &out_path, &record.blocks)?;
        // Apply the owner-executable bit
        // currently recorded for this path (POSIX: real chmod; no-op,
        // no error, on Windows) — hydration is a materialization path
        // just like `materialize` below, so it gets the same treatment.
        apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, path)?)?;
        self.state.set_materialization_state(group_id, path, MaterializationState::Hydrated)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.state.touch_last_accessed(group_id, path, now)?;
        Ok(())
    }

    /// Pins `path` and, if it isn't already `Hydrated`, hydrates it from
    /// this peer — the spec's "Pinning forces hydration".
    /// Unpinning needs no peer at all and is just
    /// `SyncState::set_pinned(..., false)`, called directly by callers
    /// that have a `SyncState` handle.
    pub async fn pin_and_hydrate_file(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.state.set_pinned(group_id, path, true)?;
        if self.state.get_materialization_state(group_id, path)?
            != Some(MaterializationState::Hydrated)
        {
            self.hydrate_file(group_id, path).await?;
        }
        Ok(())
    }

    /// PERF-5: reconciles up to `MAX_CONCURRENT_RECONCILES` records
    /// concurrently via a bounded `JoinSet`, rather than one at a time —
    /// same "`JoinSet` + cap" bounded-concurrency shape already used by
    /// `yadorilink-daemon::hydration::fetch_blocks_from_sessions`'s worker
    /// pool and SEC-13's per-peer message semaphore, for consistency.
    /// Concurrent processing of *different* paths from the same incoming
    /// batch is exactly what COR-5's per-`(group_id, path)` `path_lock`
    /// was designed to allow: it only ever serializes two operations on
    /// the *same* path (a local save racing a peer's version for that
    /// path) — unrelated paths were never meant to contend with each
    /// other, and nothing else in `reconcile_one_file`/`materialize`
    /// shares mutable state across records (`forward`/presence use
    /// `mpsc` channels, safe from concurrent senders; `upsert_file` etc.
    /// go through `SyncState`'s own connection pool, safe for concurrent
    /// callers).
    ///
    /// A single record's error is logged and does not abort the rest of
    /// the batch — previously, the serial loop's `?` meant one failing
    /// record silently skipped every record *after* it in the same
    /// message. That was never a documented guarantee (nothing here
    /// relies on in-batch ordering), and eventual consistency already
    /// tolerates a record not landing on this particular pass (the peer
    /// resends its full index periodically) — so attempting every record
    /// is strictly no worse, and recovers more of the batch on a
    /// transient per-record failure.
    ///
    /// PERF-3: the group's materialization policy is looked up once for
    /// the whole batch here, not once per record inside `materialize` —
    /// it's per-*group* config, not per-path state, so re-reading it
    /// identically for every single record in a large `FullIndex` was a
    /// redundant DB round-trip per file.
    ///
    /// A single batched
    /// `SyncState::get_files_by_paths` call (see this function's body)
    /// replaces what used to be a `get_file` point query per record
    /// inside `reconcile_one_file` — but only as a *skip-eligibility*
    /// hint (`reconcile_needed`), not as the authoritative read a
    /// record's actual adopt/conflict-resolve decision is made from.
    /// COR-5 requires that decision's `local` read to happen *after*
    /// acquiring `path_lock`, not before, so a concurrent local save that
    /// ran while this device was waiting for the lock is reflected in the
    /// comparison — which rules out ever batching the authoritative
    /// read-compare-write itself across records (that would need a new
    /// index.rs primitive and/or a locking redesign, still out of scope
    /// here). What the batched snapshot *can* safely do, and what
    /// `reconcile_needed` uses it for, is prove a record is a definite
    /// no-op (this device's already-known version already dominates the
    /// incoming one) without ever touching `path_lock` or `SyncState`
    /// again for it — see that function's doc comment for why a stale
    /// snapshot can only ever make that call *more* conservative, never
    /// less.
    async fn reconcile_files(
        self: Arc<Self>,
        group_id: &str,
        incoming: Vec<proto::FileInfo>,
    ) -> Result<(), SyncError> {
        let policy = self
            .state
            .materialization_policy_for_group(group_id)?
            .unwrap_or(MaterializationPolicy::Eager);
        // Looked up once for the whole
        // batch, PERF-3 style, same reasoning as `policy` immediately
        // above — this is per-*group* config, not per-record state, so
        // re-reading it once per record inside `reconcile_one_file` would
        // be a redundant DB round-trip per file.
        let mode = self.state.link_mode_for_group(group_id)?.unwrap_or(LinkMode::SendReceive);

        // Decode and apply the
        // cheap, purely-local path-safety/ignore filters for the whole
        // incoming batch first (unchanged from before — neither check
        // touches `SyncState`), then issue *one* batched index lookup
        // (`get_files_by_paths`) for every surviving path, in place of
        // what used to be a `get_file` point query per record buried
        // inside `reconcile_one_file`. `reconcile_needed` below then
        // decides, from that single batched snapshot, which records are
        // provably already in sync and can be skipped outright — turning
        // the common "an incoming `FullIndex`/`IndexUpdate` is mostly
        // already-synced records" case from O(records) store round-trips
        // into one, while every record that might actually need adopting
        // or conflict-resolving still goes through the exact same
        // correctly-locked `reconcile_one_file` path as before (see that
        // function's and `reconcile_needed`'s doc comments for why the
        // batched snapshot can only ever cause a *safe* skip, never an
        // incorrect one).
        let mut retained: Vec<(FileRecord, IncomingWireMeta)> = Vec::with_capacity(incoming.len());
        for file_info in incoming {
            // Captured from the
            // original `proto::FileInfo` before `.into()` below drops it —
            // see `IncomingWireMeta`'s doc comment.
            let incoming_meta = IncomingWireMeta::from(&file_info);
            let incoming_record: FileRecord = file_info.into();
            if !is_safe_relative_path(&incoming_record.path) {
                tracing::warn!(
                    path = %incoming_record.path,
                    peer = %self.peer_device_id,
                    "ignoring file record with an unsafe path (absolute or containing '..') — \
                     folder-group authorization does not grant filesystem-wide write access"
                );
                continue;
            }

            // A record for a path matching
            // this device's own ignore patterns is dropped here, before
            // any materialization/indexing/forwarding work — it is never
            // written to disk, never added to the local index, and never
            // re-announced to this device's other peers. This is purely
            // local: the sending peer, and this device's other peers, are
            // unaffected — they may still hold and continue to sync this
            // same path with each other.
            if self.is_locally_ignored(group_id, &incoming_record.path) {
                tracing::debug!(
                    path = %incoming_record.path,
                    group_id,
                    peer = %self.peer_device_id,
                    "dropping incoming record for a path matching this device's ignore patterns"
                );
                continue;
            }

            retained.push((incoming_record, incoming_meta));
        }

        let paths: Vec<String> = retained.iter().map(|(record, _)| record.path.clone()).collect();
        let prefetched = self.state.get_files_by_paths(group_id, &paths)?;

        // `FuturesUnordered<JoinHandle<_>>`
        // rather than `tokio::task::JoinSet` — needed for compatibility with
        // the deterministic-simulation test setup, whose `madsim`-based
        // tokio shim has no `JoinSet` at all. Each pushed `tokio::spawn(..)` still runs
        // as its own independently-scheduled task exactly as `JoinSet`
        // would; `FuturesUnordered` here only replaces `JoinSet`'s
        // "poll whichever join handle finishes first" bookkeeping.
        let mut in_flight: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();
        let mut in_flight_count = 0usize;
        for (incoming_record, incoming_meta) in retained {
            let needs_repair_backstop = match prefetched.get(&incoming_record.path) {
                Some(local)
                    if matches!(
                        local.version.compare(&incoming_record.version),
                        VvOrdering::Equal | VvOrdering::After
                    ) =>
                {
                    self.eager_live_record_needs_rehydrate(group_id, local, policy)?
                }
                _ => false,
            };
            if !needs_repair_backstop
                && !reconcile_needed(prefetched.get(&incoming_record.path), &incoming_record)
            {
                continue;
            }

            if in_flight_count >= MAX_CONCURRENT_RECONCILES && in_flight.next().await.is_some() {
                in_flight_count -= 1;
            }

            let this = self.clone();
            let group_id = group_id.to_string();
            in_flight.push(tokio::spawn(async move {
                // A
                // transient error here — most commonly a `SyncState`
                // write hitting `SQLITE_BUSY`/`DatabaseLocked` under real
                // concurrent load (this reconcile loop's own
                // `MAX_CONCURRENT_RECONCILES` in-flight tasks, the local
                // debounce executor, and the periodic materialization-
                // repair task all contending for the same device's
                // connection pool) even after `retry_on_database_locked`'s
                // own bounded retries (`index.rs`) are exhausted — used to
                // be a silent, single-attempt, permanent drop: this
                // specific incoming record would simply never be applied,
                // with no retry and no requeue, leaving this device's
                // index permanently stuck at whatever it had before. Same
                // shape as `ensure_blocks_present`'s own
                // bounded-retry fix: a bounded retry with jitter
                // for a transient condition that resolves shortly after,
                // not an indefinite one.
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    match this
                        .reconcile_one_file(
                            &group_id,
                            incoming_record.clone(),
                            incoming_meta.clone(),
                            policy,
                            mode,
                        )
                        .await
                    {
                        Ok(()) => break,
                        Err(e) if attempt < RECONCILE_RETRY_ATTEMPTS => {
                            tokio::time::sleep(reconcile_retry_delay()).await;
                            tracing::debug!(
                                error = %e,
                                attempt,
                                group_id = %group_id,
                                path = %incoming_record.path,
                                "retrying a failed reconcile of one file from peer index"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                attempts = attempt,
                                group_id = %group_id,
                                path = %incoming_record.path,
                                "error reconciling a file from peer index after retrying"
                            );
                            break;
                        }
                    }
                }
            }));
            in_flight_count += 1;
        }
        while in_flight.next().await.is_some() {}
        Ok(())
    }

    async fn reconcile_one_file(
        &self,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
        mode: LinkMode,
    ) -> Result<(), SyncError> {
        // Must run *before*
        // `path_lock` below is acquired (see
        // `flush_pending_local_change_before_reconcile`'s doc comment for
        // why) — this is what makes sure `local` (read further down, once
        // the lock is held) already reflects a same-path local edit that
        // was still sitting undispatched in this link's debounce
        // accumulator a moment ago, so the version-vector `compare()` below
        // correctly sees it as `Concurrent` rather than missing it
        // entirely, and every `materialize` call downstream of this
        // function never overwrites its on-disk content ahead of it being
        // captured.
        self.flush_pending_local_change_before_reconcile(group_id, &incoming.path).await;
        // Same rationale and timing as the call above, but for a
        // differently-cased sibling path this device may have its own
        // not-yet-indexed local write for — see this method's own doc
        // comment for why the exact-path flush above isn't enough on a
        // case-insensitive filesystem.
        self.flush_case_fold_sibling_before_reconcile(group_id, &incoming.path).await;

        // COR-5: held for this whole function, including the `.await`s
        // inside `materialize` (a block fetch can take real time) — see
        // `SyncState::path_lock`'s doc comment for the local-save-vs-
        // incoming-peer-version race this closes. `local` is read here,
        // *after* acquiring the lock, not before, so a concurrent local
        // save that ran while this device was waiting for the lock is
        // reflected in the comparison below rather than compared against
        // stale state.
        let path_lock = self.state.path_lock(group_id, &incoming.path);
        let _guard = path_lock.lock().await;

        // The device that
        // actually produced `incoming`'s content, per the sending peer's
        // own `SyncState::get_origin_device_id` lookup (`file_info_for_
        // record`) — not necessarily `self.peer_device_id` if this peer
        // is relaying a *third* device's content rather than sending its
        // own. Falls back to `self.peer_device_id` for a peer that
        // predates this field (empty/absent on the wire).
        let incoming_origin =
            meta.origin_device_id.clone().unwrap_or_else(|| self.peer_device_id.clone());

        let local = self.state.get_file(group_id, &incoming.path)?;

        let Some(local) = local else {
            // A send-only link
            // never applies an incoming change — including the "never seen
            // this path before" case, and including a tombstone for a path
            // this device never had (`incoming.deleted`; gated identically
            // to content per the "Tombstones" handling, since
            // nothing branches on `deleted` before this point). Recorded as
            // out-of-sync rather than adopted; no conflict copy, no write
            // to disk, no forward to this device's other peers — local
            // state (here, "no file at all") stays authoritative until an
            // explicit `override`.
            if mode == LinkMode::SendOnly {
                self.state.record_out_of_sync(group_id, &incoming.path, now_unix_nanos())?;
                return Ok(());
            }
            // Persist the peer's
            // advertised kind/target/exec-bit into the index *before*
            // `materialize` runs — its own symlink dispatch reads
            // `SyncState::get_record_kind` for this exact path, so this
            // must land first, not after.
            apply_incoming_wire_metadata(&self.state, group_id, &incoming, &meta)?;
            // We've never seen this path: adopt it outright (`materialize`
            // now handles a tombstone-for-a-file-we-never-had correctly
            // too — COR-3/COR-6 — recording the row without ever touching
            // a file that was never on disk here in the first place).
            self.materialize(group_id, &incoming, policy, &incoming_origin).await?;
            // Full mesh: this device's *other* peers need to learn about
            // this file too, not just the one that sent it (see
            // `forward_tx`'s doc comment).
            self.forward(group_id, &incoming);
            return Ok(());
        };

        // security hardening: sanitize the peer-supplied version vector against
        // the last version this device actually accepted for this file
        // *before* using it for a causality comparison — see
        // `version_vector.rs`'s trust-boundary doc comment and
        // `VersionVector::sanitize_against`. A no-op for ordinary honest
        // growth; bounds (does not fully prevent) a peer forcing an
        // implausible one-shot counter jump to fake a `Before` result and
        // silently overwrite a genuine concurrent local edit.
        let sanitized_version = local.version.sanitize_against(
            &incoming.version,
            &self.local_device_id,
            MAX_VV_COUNTER_JUMP_PER_MESSAGE,
        );

        match local.version.compare(&sanitized_version) {
            VvOrdering::Equal => {
                if self.eager_live_record_needs_rehydrate(group_id, &local, policy)? {
                    self.hydrate_file_with_timeout(
                        group_id,
                        &local.path,
                        DEFAULT_HYDRATION_TIMEOUT,
                    )
                    .await?;
                }
                Ok(())
            }
            VvOrdering::After => {
                if self.eager_live_record_needs_rehydrate(group_id, &local, policy)? {
                    self.hydrate_file_with_timeout(
                        group_id,
                        &local.path,
                        DEFAULT_HYDRATION_TIMEOUT,
                    )
                    .await?;
                }
                Ok(())
            }
            VvOrdering::Before => {
                // Peer has new
                // information for a path this device already has — on a
                // send-only link this is exactly the divergence this system
                // describes ("an incoming index update that differs from
                // local is not applied ... recorded as an out-of-sync
                // item"), including when `incoming.deleted` (a gated
                // tombstone). Local content, and the local index
                // row, are left completely untouched.
                if mode == LinkMode::SendOnly {
                    self.state.record_out_of_sync(group_id, &incoming.path, now_unix_nanos())?;
                    return Ok(());
                }
                // Peer is ahead: adopt their version. COR-6: this used to
                // ignore `remove_file`'s result (`let _ = ...`) — if the
                // file was locked/open (a real occurrence on Windows) or
                // otherwise couldn't be removed, the index still recorded
                // `deleted=true` while the file remained; the next scan
                // then saw an on-disk file with no matching *not-deleted*
                // index entry, treated it as a brand-new local edit
                // (self-echo suppression is gated on `!existing.deleted`),
                // and resurrected + re-propagated it. `materialize` now
                // surfaces a real removal failure as an error instead of
                // silently discarding it.
                //
                // Same as the
                // never-seen branch above — must land before `materialize`.
                apply_incoming_wire_metadata(&self.state, group_id, &incoming, &meta)?;
                self.materialize(group_id, &incoming, policy, &incoming_origin).await?;
                self.forward(group_id, &incoming);
                Ok(())
            }
            VvOrdering::Concurrent => {
                // The design is
                // explicit that "send-only never conflict-copies an
                // incoming change" — a genuine concurrent edit is still
                // divergence (the incoming record differs from local), just
                // recorded rather than resolved via the normal
                // rename-the-loser conflict machinery, which would
                // otherwise write a new conflict-copy file to disk (an
                // "apply", exactly what send-only must not do).
                if mode == LinkMode::SendOnly {
                    self.state.record_out_of_sync(group_id, &incoming.path, now_unix_nanos())?;
                    return Ok(());
                }
                self.resolve_and_apply_conflict(group_id, local, incoming, meta, policy).await
            }
        }
    }

    /// On a genuine concurrent edit, keep both copies —
    /// deterministically rename the older-mtime one to a conflict-marked
    /// filename, which then propagates to all peers as an ordinary file.
    async fn resolve_and_apply_conflict(
        &self,
        group_id: &str,
        local: FileRecord,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        // security hardening: both the canonical-name decision
        // (`resolve_conflict_names`) and the content-winner decision
        // (`local_is_loser` below) must agree on which side wins, so both
        // go through the same `now_unix_nanos`-bounded `a_is_loser` — see
        // `conflict.rs`'s trust-boundary doc comment for why an unbounded
        // peer-supplied `mtime_unix_nanos` (e.g. `i64::MAX`) can no longer
        // unilaterally win the real filename, and why the tie-break stays
        // on device id rather than "prefer local". Goes through the same
        // shared `now_unix_nanos()` (not a re-inlined `SystemTime::now()`)
        // so a DST harness's `set_test_clock_override` reaches this call
        // site too -- see that function's doc comment.
        let now_unix_nanos = now_unix_nanos();
        // `local`/`incoming`
        // do not always genuinely originate from `self.local_device_id`/
        // `self.peer_device_id` — under a 3-or-more-way concurrent edit,
        // either side can already be a *previous* pairwise resolution
        // round's winner (some other device's content this device or
        // peer adopted), and naming/tie-breaking on session-relative
        // identity rather than true origin causes different devices to
        // materialize different content under the "same" deterministic
        // conflict-copy name. `local_origin`/`incoming_origin` fall back
        // to the old session-relative assumption only when no recorded
        // origin exists (a record predating this fix, or the very first
        // resolution round, where they coincide anyway).
        let local_origin = self
            .state
            .get_origin_device_id(group_id, &local.path)?
            .unwrap_or_else(|| self.local_device_id.clone());
        let incoming_origin =
            meta.origin_device_id.clone().unwrap_or_else(|| self.peer_device_id.clone());
        // The loser's content hash
        // is threaded in alongside its mtime/device-id so `conflict_copy_path`
        // can append a collision-proof disambiguator — see `conflict.rs`'s
        // top-level doc comment for why a truncated-second timestamp plus
        // device-id alone isn't unique per losing *content*. Computed for
        // both sides unconditionally (cheap: just hashing the already-known
        // per-block hashes, no re-read of file bytes), since which side
        // loses isn't known until `resolve_conflict_names` runs.
        let (winner_path, loser_conflict_path) = resolve_conflict_names(
            &local.path,
            local.mtime_unix_nanos,
            &local_origin,
            &combined_block_hash(&local.blocks),
            incoming.mtime_unix_nanos,
            &incoming_origin,
            &combined_block_hash(&incoming.blocks),
            now_unix_nanos,
        );
        let local_is_loser = a_is_loser(
            local.mtime_unix_nanos,
            &local_origin,
            incoming.mtime_unix_nanos,
            &incoming_origin,
            now_unix_nanos,
        );

        let merged_version = local.version.merge(&incoming.version);

        // Assign each side (local's own record vs. the peer's incoming
        // record) its final target path (the real filename for the
        // winner, a conflict-marked name for the loser) without yet
        // deciding *materialization order* — see below for why that's
        // handled separately from the winner/loser assignment itself.
        let (local_final_path, incoming_final_path) = if local_is_loser {
            (loser_conflict_path, winner_path)
        } else {
            (winner_path, loser_conflict_path)
        };
        let local_deleted = local.deleted;
        let incoming_deleted = incoming.deleted;
        // Captured before `local`/`incoming` are partially moved into
        // `local_record`/`incoming_record` below -- the *original*,
        // pre-resolution path both sides shared, needed as the stem to
        // match existing conflict-copies against (not `local_final_path`/
        // `incoming_final_path`, which is the *destination* name this
        // resolution is about to assign, not what a prior resolution's
        // conflict-copy would have been named after).
        let original_path = local.path.clone();
        let local_record =
            FileRecord { path: local_final_path, version: merged_version.clone(), ..local };
        let incoming_record =
            FileRecord { path: incoming_final_path, version: merged_version, ..incoming };

        // PROTOTYPE guard -- verifying a
        // hypothesis before this becomes a properly-specced fix. Root
        // cause: this function has no idempotency check against a
        // conflict-copy it already wrote for this exact losing content.
        // `resolve_conflict_names`/`conflict_copy_path` derive the
        // conflict-copy's filename from the loser's *mtime*, which gets a
        // fresh wall-clock value every time the loser's content is
        // re-materialized — so if this same conflict is ever reprocessed
        // (observed: the self-echo-race class, `materialize`'s own doc
        // comment below, ~4337-4347 — writing a file causes this device's
        // own watcher to re-index it as a "new" local edit, re-bumping
        // this device's version and re-entering `Concurrent` against an
        // already-resolved peer record; triggered in a DST heat-run by
        // `ensure_blocks_present`'s 30s hydration timeout forcing a
        // retry), the *same losing bytes* get a *second*, differently-
        // named conflict-copy file instead of being recognized as already
        // preserved. Before materializing whichever side is the loser,
        // check whether a live (non-deleted), non-hazardous conflict-copy
        // already indexed under this same original path's stem already
        // holds this exact content (`combined_block_hash`) — if so, that
        // content is already durably preserved; materializing another copy
        // would only be a duplicate, not a new preservation.
        let loser_already_conflict_copied = |original_path: &str, loser_blocks: &[BlockInfo]| {
            let loser_hash = combined_block_hash(loser_blocks);
            self.state.list_files(group_id).is_ok_and(|files| {
                files.iter().any(|f| {
                    !f.deleted
                        && is_conflict_copy_of(&f.path, original_path)
                        && combined_block_hash(&f.blocks) == loser_hash
                })
            })
        };

        // Materialize `local`'s own record *first*, regardless of whether
        // it's the winner or the loser this round: its content is always
        // already present in this device's own block store (it's this
        // device's own prior edit or an already-adopted version — never
        // something that needs fetching from the peer), so there's no
        // reason to make anything wait on it. `incoming`'s record, by
        // contrast, may need to fetch blocks from the peer this device
        // doesn't have yet.
        //
        // This ordering matters beyond raw throughput: the *peer*, in its
        // own symmetric `resolve_and_apply_conflict` for this same
        // conflict, may need to fetch *this device's* losing copy's
        // content from *this* session — which depends on this device
        // having already `upsert_file`'d (inside `materialize`) a record
        // for that conflict-copy path. Materializing the local,
        // already-present side first gets that index entry in place as
        // fast as possible, rather than leaving it queued behind this
        // device's own potentially-slower fetch of the peer's content —
        // closing a real (if narrow) race between the two peers'
        // independent, concurrent conflict resolutions.
        //
        // A tombstone that lost the conflict is skipped (COR-3: "conflict
        // copy of a deletion" is meaningless, and would otherwise
        // materialize as an empty ghost file at a brand-new path that
        // then keeps propagating to every peer) — but a tombstone that
        // *won* is always materialized (a real, valid "peer's delete wins
        // the concurrent edit" outcome). A loser whose exact content is
        // already preserved as an existing conflict-copy is likewise
        // skipped (the dedup guard above) -- re-materializing it would
        // only fabricate a duplicate, not preserve anything new.
        let skip_local = local_is_loser
            && (local_deleted
                || loser_already_conflict_copied(&original_path, &local_record.blocks));
        let skip_incoming = !local_is_loser
            && (incoming_deleted
                || loser_already_conflict_copied(&original_path, &incoming_record.blocks));
        if !skip_local {
            // **Documented partial
            // coverage**: `local_record` keeps whatever kind/target/exec-bit
            // is already indexed under `local.path` today, but if this
            // side lost the conflict its final path (`local_final_path`
            // above) is a brand-new conflict-marked name — a fresh row
            // `materialize`'s own `upsert_file` creates from scratch, with
            // no metadata carried over from the old path. A losing
            // symlink/exec-bit local record in a *concurrent-edit
            // conflict* is therefore not proven to keep its kind/exec-bit
            // across the rename by this change; the far more common
            // "adopt"/"peer is ahead" paths above (and the losing side
            // being a tombstone, `skip_local`) are unaffected. Not fixed
            // here: doing so needs a read of `local`'s pre-rename metadata
            // and a write under the new path, which is straightforward but
            // out of this fix's tested scope — left as a known gap rather
            // than silently assumed correct.
            // `local_origin`
            // (not unconditionally `self.local_device_id` — see this
            // function's own doc comment above) is whichever device
            // actually produced `local_record`'s content, so the stored
            // `origin_device_id` and the conflict-copy name it drove stay
            // consistent even when `local` was itself an earlier round's
            // adopted winner rather than this device's own edit.
            self.materialize(group_id, &local_record, policy, &local_origin).await?;
            // This device's other peers (including ones not involved in
            // the conflict at all) need this resolution too — otherwise
            // it never leaves this one pairwise session (see
            // `forward_tx`'s doc comment).
            self.forward(group_id, &local_record);
        }
        if !skip_incoming {
            // `incoming_record`'s
            // final path may differ from the original wire path (a
            // conflict rename), so this applies `meta` — captured from the
            // peer's original `proto::FileInfo` — at that final path,
            // immediately before `materialize` reads it back via
            // `SyncState::get_record_kind`.
            apply_incoming_wire_metadata(&self.state, group_id, &incoming_record, &meta)?;
            self.materialize(group_id, &incoming_record, policy, &incoming_origin).await?;
            self.forward(group_id, &incoming_record);
        }

        Ok(())
    }

    /// Adopts `record` (already at its final target path/version) into the
    /// local index, and either fetches its full content or writes a
    /// placeholder, depending on the folder group's materialization
    /// policy — `Eager` always fetches; `OnDemand`
    /// writes a placeholder unless this exact path is individually pinned.
    ///
    /// Order matters: this device's *own* local watcher will see the write
    /// below as an ordinary filesystem event, indistinguishable from a
    /// genuine local edit except by comparing against what's already
    /// indexed (`local_change::process_event`'s self-echo suppression).
    /// That comparison only works if the index already reflects `record`
    /// *before* the write happens — otherwise there's a race where the
    /// watcher's task processes the event before `upsert_file` (a separate
    /// task) has run, finds nothing indexed yet, and misindexes this as a
    /// brand-new local file under this device's own version, which then
    /// looks like a concurrent edit to every peer (found via a
    /// load test, intermittently, exactly this race).
    ///
    /// `policy` (PERF-3) is looked up once by the caller's batch
    /// (`reconcile_files`) rather than re-read here per record — see that
    /// function's doc comment. Passing it in changes nothing about *which*
    /// policy applies to a given record within one incoming batch (the
    /// group's policy doesn't vary per-file), only how many times it's
    /// fetched from the index.
    ///
    /// The free-form `held_reason`
    /// `record.path` must be held under right now, or `None` if
    /// materializing it is safe. Thin wrapper over `hazard_reason_for_
    /// policy` (see that free function's doc comment for the actual
    /// logic and why it's factored out), always evaluated against this
    /// device's real local platform (`hazard::NamePolicy::local`).
    fn hazard_reason_for(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<Option<String>, SyncError> {
        hazard_reason_for_policy(
            &self.state,
            &self.sync_root(group_id),
            group_id,
            record,
            hazard::NamePolicy::local(),
        )
    }

    /// Thin wrapper over `hold_record`
    /// (see that free function's doc comment) using this session's own
    /// `SyncState`.
    fn hold(
        &self,
        group_id: &str,
        record: &FileRecord,
        reason: &str,
        origin_device_id: &str,
    ) -> Result<(), SyncError> {
        hold_record(&self.state, group_id, record, reason, origin_device_id)
    }

    /// `origin_device_id` is the local device id for a local record being
    /// re-materialized
    /// (`resolve_and_apply_conflict`'s `local_record` side of a conflict)
    /// or the sending peer's device id for a genuinely adopted remote
    /// version — always supplied by the caller (`reconcile_one_file`/
    /// `resolve_and_apply_conflict`), never inferred here, matching the
    /// principle of "recorded directly at write time rather than inferred
    /// from a version-vector diff".
    async fn materialize(
        &self,
        group_id: &str,
        record: &FileRecord,
        policy: MaterializationPolicy,
        origin_device_id: &str,
    ) -> Result<(), SyncError> {
        // COR-3: a tombstone (`deleted=true, blocks=[]`) materialized via
        // the ordinary path below unconditionally fetches/reconstructs —
        // writing a 0-byte file at the path while the index records
        // `deleted=true`, an on-disk ghost file disagreeing with its own
        // index row. Handle deletion explicitly instead: remove the file
        // first (already gone is not an error — that's the common case,
        // since most tombstones arrive after the originating device's own
        // delete already ran locally), and only then record the
        // tombstone. Order matters (COR-6): recording the tombstone
        // *before* a removal that then fails (a locked/open file, common
        // on Windows) leaves the index saying `deleted=true` while the
        // file still exists — the next scan sees an on-disk file with no
        // matching not-deleted index entry and resurrects + re-propagates
        // it as a brand-new local edit. Removing first means a failure
        // here surfaces as a real error without corrupting the index.
        if record.deleted {
            let out_path = self.local_file_path(group_id, &record.path);
            // `std::fs::remove_file` on a
            // symlink path is a plain `unlink()` of that directory entry
            // — it removes the link itself and never follows it to
            // touch whatever the link points at, symlink or not. This is
            // exactly the "tombstone removes the link, never the
            // target" requirement, and needs no kind-specific branching
            // here: the same call is already correct for a symlink
            // record's tombstone as it is for a regular file's. See
            // `tests/peer_session.rs`'s
            // `symlink_tombstone_removes_link_but_never_its_target` for
            // a real assertion of this against an actual target file.
            match std::fs::remove_file(&out_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(SyncError::from(e)),
            }
            // A held file that's later
            // tombstoned must not leave an orphaned held entry once its
            // index row no longer represents a live, on-disk file —
            // `clear_held` is documented as a safe no-op when the path
            // was never held, so this is safe to call unconditionally.
            self.state.clear_held(group_id, &record.path)?;
            return self.state.upsert_file_with_origin(group_id, record, origin_device_id);
        }

        // Computed once, ahead of every
        // dispatch branch below (symlink, metadata-only fast path, eager
        // fetch, placeholder) — a hazard must short-circuit before *any*
        // of those reach their own atomic temp-write step, not just the
        // ordinary-file ones. See `hazard_reason_for`'s doc comment.
        let hazard_reason = self.hazard_reason_for(group_id, record)?;

        // A path this device's own index
        // already classifies as a symlink (`SyncState::get_record_kind`
        // — see `materialize_symlink_at`'s doc comment for why this,
        // not a wire-carried kind, is the correct source today) never
        // goes through the ordinary block-fetch/reconstruct path below —
        // it carries no content blocks at all.
        if self.state.get_record_kind(group_id, &record.path)?.unwrap_or_default()
            == RecordKind::Symlink
        {
            if let Some(reason) = &hazard_reason {
                return self.hold(group_id, record, reason, origin_device_id);
            }
            // A path that's no longer hazardous (e.g. a previously
            // colliding sibling was itself renamed/removed since the last
            // time this path was reconciled) must not keep a stale held
            // entry once it actually materializes normally again.
            self.state.clear_held(group_id, &record.path)?;
            let windows_opt_in = self.state.windows_symlink_opt_in_for_group(group_id)?;
            return materialize_symlink_at(
                &self.state,
                &self.sync_root(group_id),
                group_id,
                record,
                windows_opt_in,
                origin_device_id,
            );
        }

        // Content-identical fast path — if
        // this exact block list is already what's indexed locally for
        // this path, skip the whole fetch/reconstruct cycle below
        // entirely and just make sure the on-disk exec bit matches the
        // index (see `try_apply_metadata_only_update`'s doc comment for
        // the wire-schema caveat this still operates under). Skipped
        // entirely when hazardous: applying a chmod through this path
        // assumes the file already exists on disk under this exact name,
        // which is never true for a held file — falling through to the
        // eager/placeholder branch below routes it through `hold` instead.
        if hazard_reason.is_none()
            && try_apply_metadata_only_update(
                &self.state,
                &self.sync_root(group_id),
                group_id,
                record,
                origin_device_id,
            )?
        {
            self.state.clear_held(group_id, &record.path)?;
            return Ok(());
        }

        // A brand-new path was never pinned before; `is_pinned` on a
        // not-yet-indexed row simply returns `false`, so this is safe to
        // check unconditionally regardless of whether `record` is a new
        // adoption or an update to a path already in the index.
        let pinned = self.state.is_pinned(group_id, &record.path)?;

        // security hardening: an explicit pin always fetches (a deliberate,
        // user-initiated request bypasses the eager-fetch admission
        // budget, same as it already bypasses the materialization policy
        // check itself). Plain policy-driven eager fetch is additionally
        // gated on this session's per-group budget — see
        // `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`'s doc comment; once
        // exhausted, this falls through to the placeholder branch below
        // instead of continuing to fetch.
        let eager_admitted = pinned
            || (policy == MaterializationPolicy::Eager
                && self.admit_eager_blocks(group_id, record.blocks.len() as u64));

        if eager_admitted {
            // Bounded, same budget as the daemon's explicit hydrate path
            // (`DEFAULT_HYDRATION_TIMEOUT`/`HYDRATION_TIMEOUT` in
            // `yadorilink-daemon::hydration`). Unbounded here was a real
            // deadlock risk once SEC-13 added a bounded per-peer
            // in-flight-message semaphore (`MAX_IN_FLIGHT_MESSAGES_PER_PEER`,
            // `run`'s recv loop): this whole function runs inside a
            // spawned message handler that holds one of those permits,
            // and `ensure_blocks_present` awaits a `BlockResponse` from
            // *this same peer connection* — if enough concurrent eager
            // materializations (e.g. every file in a large initial
            // `FullIndex`) exhaust the semaphore, the recv loop itself
            // blocks acquiring the next permit and can never reach the
            // very `BlockResponse` these in-flight fetches are waiting
            // for, deadlocking permanently (nothing else was watching
            // this call to break the cycle). A bounded timeout turns
            // that into a bounded failure instead: this reconcile is
            // simply retried on the peer's next full-index resend
            // (design's normal eventual-consistency path), and — same as
            // the semaphore fix in `run`'s recv loop — the permit gets
            // released either way, unblocking the recv loop and letting
            // still-queued `BlockResponse`s (and everything after them)
            // through.
            //
            // "simply retried on the peer's
            // next full-index resend" above was aspirational, not actually
            // true, until `run`'s periodic resync task was added —
            // before it, `send_full_index` was only ever called once per
            // session, so a reconcile that timed out here this way was
            // dropped for the life of the session, not retried at all (see
            // `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`'s doc comment for why 90s
            // was chosen). The periodic resync is a safety net around this
            // contention, not a fix to it — a possible, separate follow-up
            // for whoever next touches this area: decouple the recv loop's
            // read of a control-plane message (an `IndexUpdate`/`FullIndex`/
            // `BlockRequest`, i.e. anything that isn't itself a
            // `BlockResponse`) from the `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
            // slot materialization also contends for — e.g. a small,
            // separate reservation carved out for control messages, so the
            // recv loop can never be head-of-line-blocked behind eager
            // fetches on its own connection in the first place, matching
            // resource governance's "control messages must never be
            // delayed even while both buckets are saturated" precedent.
            tokio::time::timeout(
                DEFAULT_HYDRATION_TIMEOUT,
                self.ensure_blocks_present(group_id, &record.path, &record.blocks),
            )
            .await
            .map_err(|_elapsed| SyncError::HydrationFailed(record.path.clone()))??;
            // The block fetch above always
            // runs, hazardous or not — this device may be another peer's
            // only currently-reachable source for these blocks even
            // though it can't write them to disk under this name itself
            // ("blocks still requested/served to peers"). Only
            // the write step below is skipped for a held record.
            if let Some(reason) = &hazard_reason {
                return self.hold(group_id, record, reason, origin_device_id);
            }
            self.state.upsert_file_with_origin(group_id, record, origin_device_id)?;
            self.state.clear_held(group_id, &record.path)?;
            let out_path = self.local_file_path(group_id, &record.path);
            // security hardening defense-in-depth: `is_safe_relative_path` (in
            // `reconcile_files`) already blocks `..`/absolute components,
            // but a *symlink* at an intermediate path component is
            // followed by the plain `create`/`rename` calls inside
            // `reconstruct_file`, which could otherwise land the write
            // outside `group_id`'s sync root. See `verify_write_target_
            // within_root`'s doc comment for what this does and does not
            // close.
            self.verify_write_target(group_id, &out_path)?;
            // Preflight before the
            // temp-then-rename write below begins — see
            // `preflight_disk_headroom`'s doc comment.
            self.preflight_disk_headroom(group_id, &out_path, record.size)?;
            reconstruct_file(self.store.as_ref(), &out_path, &record.blocks)?;
            // Apply the owner-executable bit
            // currently recorded for this path (POSIX: real chmod;
            // no-op, no error, on Windows).
            apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)
        } else {
            // OnDemand/not-pinned is the
            // placeholder path — but a placeholder is still a real
            // on-disk artifact created *under this path's exact name*, so
            // a hazardous record must not get one either (held
            // means no on-disk artifact under this name at all, full
            // content or placeholder alike; never any alternate name).
            if let Some(reason) = &hazard_reason {
                return self.hold(group_id, record, reason, origin_device_id);
            }
            // OnDemand and not pinned: no block fetch at all — the whole
            // point of a placeholder is deferring that until access.
            self.state.upsert_file_with_origin(group_id, record, origin_device_id)?;
            self.state.clear_held(group_id, &record.path)?;
            self.state.set_materialization_state(
                group_id,
                &record.path,
                MaterializationState::Placeholder,
            )?;
            let out_path = self.local_file_path(group_id, &record.path);
            // security hardening defense-in-depth — see the comment above.
            self.verify_write_target(group_id, &out_path)?;
            write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
            // A placeholder still gets the recorded exec bit
            // applied now — `hydrate_file_with_timeout` re-applies it
            // again once real content lands, so this is never lost
            // across the placeholder → hydrated transition either.
            apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)
        }
    }

    fn local_file_path(&self, group_id: &str, path: &str) -> PathBuf {
        self.sync_root(group_id).join(path)
    }

    fn eager_live_record_needs_rehydrate(
        &self,
        group_id: &str,
        record: &FileRecord,
        policy: MaterializationPolicy,
    ) -> Result<bool, SyncError> {
        if policy != MaterializationPolicy::Eager || record.deleted {
            return Ok(false);
        }
        if self.state.get_record_kind(group_id, &record.path)?.unwrap_or_default()
            != RecordKind::File
        {
            return Ok(false);
        }
        if self.state.get_materialization_state(group_id, &record.path)?
            != Some(MaterializationState::Hydrated)
        {
            return Ok(true);
        }

        let out_path = self.local_file_path(group_id, &record.path);
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        Ok(on_disk_size != Some(record.size))
    }

    /// `group_id`'s local linked directory (security hardening: the root
    /// `verify_write_target` checks resolved write targets stay under).
    fn sync_root(&self, group_id: &str) -> PathBuf {
        self.sync_roots.get(group_id).cloned().unwrap_or_default()
    }

    /// security hardening defense-in-depth check before writing through `out_path`
    /// — see `chunker::verify_write_target_within_canonical_root`'s doc
    /// comment. Uses the cached canonical root (`canonical_sync_roots`)
    /// when available (the common case, avoiding a repeated
    /// canonicalize-the-whole-root cost on this per-peer-message hot
    /// path); falls back to resolving `group_id`'s root fresh for the
    /// rare case it wasn't cached at session construction time.
    fn verify_write_target(&self, group_id: &str, out_path: &Path) -> Result<(), SyncError> {
        let raw_root = self.sync_root(group_id);
        // Fast path: security hardening is specifically about a symlink at an
        // *intermediate* directory component between the sync root and
        // the file — when `out_path`'s parent *is* the sync root itself
        // (an ordinary top-level file, no subdirectory in `record.path`
        // at all), there is no intermediate component that could be such
        // a symlink, so the expensive canonicalize round trip has nothing
        // to catch here. Purely structural (no filesystem access) — safe
        // to check before paying for the syscalls below, and matters in
        // practice: this runs on every eager materialize/hydrate, a
        // per-peer-message-concurrency-bounded hot path where two peers
        // can legitimately race each other fetching each other's content
        // for the two sides of the same conflict.
        if out_path.parent() == Some(raw_root.as_path()) {
            return Ok(());
        }
        match self.canonical_sync_roots.get(group_id) {
            Some(canonical_root) => {
                verify_write_target_within_canonical_root(out_path, canonical_root)
            }
            None => verify_write_target_within_root(out_path, &raw_root),
        }
    }

    /// Disk-space headroom preflight
    /// before a hydration fetch or a materialize-to-temp-and-rename write
    /// begins, scoped to the volume hosting `group_id`'s local sync root —
    /// called from both of this session's write paths that reach
    /// `reconstruct_file` (`hydrate_file_with_timeout`'s single-session
    /// hydration, and `materialize`'s eager-fetch branch). A no-op (fast
    /// path, no filesystem query) when `headroom_enforced` hasn't been
    /// turned on — see that field's doc comment for why a bare/test session
    /// doesn't enforce this by default.
    fn preflight_disk_headroom(
        &self,
        group_id: &str,
        target_path: &Path,
        additional_bytes: u64,
    ) -> Result<(), SyncError> {
        if !self.headroom_enforced() {
            return Ok(());
        }
        check_disk_headroom(
            &self.sync_root(group_id),
            target_path,
            additional_bytes,
            self.headroom_override_bytes(),
        )
    }
}

fn block_data_matches(block: &BlockInfo, data: &[u8]) -> bool {
    if data.len() != block.size as usize {
        return false;
    }
    let digest = Sha256::digest(data);
    digest[..] == block.hash[..]
}

/// Rejects a peer-supplied `FileRecord.path` unless every component is an
/// ordinary path segment — no `..`, no absolute-path root/prefix (a
/// Windows drive letter, a leading `/`). Being authorized to sync a folder
/// group only grants access to *that folder*; without this check, a path
/// like `"../../../.ssh/authorized_keys"` or `"/etc/passwd"` would let any
/// device sharing the group write (via `materialize`) or delete (via a
/// tombstone) an arbitrary file anywhere on the receiving device's
/// filesystem, well outside the synced directory — `PathBuf::join` with an
/// absolute path silently discards the base entirely, and `..` components
/// aren't otherwise neutralized anywhere in the reconciliation path.
fn is_safe_relative_path(path: &str) -> bool {
    use std::path::Component;
    if path.is_empty() {
        return false;
    }
    std::path::Path::new(path).components().all(|c| matches!(c, Component::Normal(_)))
}

/// Whether `incoming` might
/// actually need `reconcile_one_file`'s real, `path_lock`-guarded
/// read-compare-write, given `prefetched_local` — a *possibly stale*
/// snapshot of this device's local record for the same path, taken by one
/// batched `SyncState::get_files_by_paths` call before any `path_lock` is
/// acquired for this batch (`reconcile_files`).
///
/// `None` (no local record was found for this path at prefetch time)
/// always returns `true`: either this path is genuinely new, or a
/// concurrent local save created it after the prefetch ran — either way,
/// only the real locked path can tell which, so this never guesses.
///
/// `Some(local)` returns `false` (safe to skip) only when `local`'s
/// version already dominates `incoming`'s (`Equal` or `After` — "we've
/// already seen this exact version, or something newer"). This is safe
/// even though `local` may be stale by the time this runs, because a
/// `VersionVector` only ever grows monotonically (`increment`/`merge`,
/// see `version_vector.rs` — no operation ever decreases a counter): if a
/// *stale* local snapshot already dominates `incoming`, the *true,
/// current* local version — being component-wise greater-than-or-equal
/// to that stale snapshot — must dominate it too. So a skip decided here
/// can only ever be correct; the reverse (skipping a record that a fresh
/// read would have shown actually needs adopting or conflict-resolving)
/// is not reachable. Any other prefetched ordering (`Before` or
/// `Concurrent`) conservatively falls through to the real locked path,
/// exactly as if no batching happened at all.
fn reconcile_needed(prefetched_local: Option<&FileRecord>, incoming: &FileRecord) -> bool {
    match prefetched_local {
        None => true,
        Some(local) => !matches!(
            local.version.compare(&incoming.version),
            VvOrdering::Equal | VvOrdering::After
        ),
    }
}

#[cfg(test)]
mod reconcile_needed_tests {
    use super::reconcile_needed;
    use crate::types::FileRecord;
    use crate::version_vector::VersionVector;

    fn record(path: &str, version: VersionVector) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    #[test]
    fn no_prefetched_local_record_always_needs_the_real_locked_path() {
        let mut incoming_version = VersionVector::new();
        incoming_version.increment("peer");
        let incoming = record("a.txt", incoming_version);
        assert!(reconcile_needed(None, &incoming));
    }

    #[test]
    fn equal_versions_are_skipped_as_a_definite_no_op() {
        let mut v = VersionVector::new();
        v.increment("peer");
        let local = record("a.txt", v.clone());
        let incoming = record("a.txt", v);
        assert!(!reconcile_needed(Some(&local), &incoming));
    }

    #[test]
    fn local_strictly_ahead_of_incoming_is_skipped() {
        let mut local_version = VersionVector::new();
        local_version.increment("peer");
        local_version.increment("peer"); // {peer: 2}
        let mut incoming_version = VersionVector::new();
        incoming_version.increment("peer"); // {peer: 1}
        let local = record("a.txt", local_version);
        let incoming = record("a.txt", incoming_version);
        assert!(!reconcile_needed(Some(&local), &incoming));
    }

    #[test]
    fn incoming_ahead_of_local_still_needs_the_real_locked_path() {
        let mut local_version = VersionVector::new();
        local_version.increment("peer"); // {peer: 1}
        let mut incoming_version = VersionVector::new();
        incoming_version.increment("peer");
        incoming_version.increment("peer"); // {peer: 2}
        let local = record("a.txt", local_version);
        let incoming = record("a.txt", incoming_version);
        assert!(reconcile_needed(Some(&local), &incoming));
    }

    #[test]
    fn concurrent_versions_still_need_the_real_locked_path() {
        let mut local_version = VersionVector::new();
        local_version.increment("local"); // {local: 1}
        let mut incoming_version = VersionVector::new();
        incoming_version.increment("peer"); // {peer: 1}
        let local = record("a.txt", local_version);
        let incoming = record("a.txt", incoming_version);
        assert!(reconcile_needed(Some(&local), &incoming));
    }

    /// The core safety argument from `reconcile_needed`'s doc comment,
    /// exercised directly: a *stale* local snapshot that already
    /// dominates `incoming` remains a valid reason to skip even after the
    /// *true* local version has grown further in the meantime (simulating
    /// a concurrent local save that landed between the batched prefetch
    /// and this check) — the version only ever grows, so "dominates"
    /// stays true.
    #[test]
    fn a_stale_but_still_dominating_snapshot_is_still_safe_to_skip() {
        let mut incoming_version = VersionVector::new();
        incoming_version.increment("peer"); // {peer: 1}
        let incoming = record("a.txt", incoming_version);

        let mut stale_local_version = VersionVector::new();
        stale_local_version.increment("peer"); // {peer: 1} — Equal to incoming
        let stale_local = record("a.txt", stale_local_version.clone());
        assert!(!reconcile_needed(Some(&stale_local), &incoming));

        // The "true" current local version grew further after the
        // prefetch (e.g. a concurrent local edit) — still dominates
        // `incoming`, so the skip decision remains correct.
        let mut grown_local_version = stale_local_version;
        grown_local_version.increment("local");
        let grown_local = record("a.txt", grown_local_version);
        assert!(!reconcile_needed(Some(&grown_local), &incoming));
    }
}

#[cfg(test)]
mod pending_block_guard_tests {
    use super::{Bytes, FetchOutcome, HashMap, PendingBlockGuard};
    use tokio::sync::oneshot;

    /// COR-9: dropping the guard without ever fulfilling the request
    /// (simulating a caller-side timeout/cancellation, which drops the
    /// `rx` and thus closes `tx`) must remove the now-orphaned entry.
    #[test]
    fn drop_without_fulfillment_removes_the_orphaned_entry() {
        let pending = std::sync::Mutex::new(HashMap::new());
        let (tx, rx) = oneshot::channel::<FetchOutcome>();
        pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(vec![1, 2, 3], vec![tx]);

        {
            let _guard = PendingBlockGuard { pending: &pending, hash: vec![1, 2, 3] };
            drop(rx); // simulates the caller's future (and its rx) being dropped by a timeout
        }

        assert!(pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    /// The ordinary, successful path: `handle_block_response` already
    /// removed the entry before the guard drops — the guard must find
    /// nothing there and not panic or otherwise misbehave.
    #[test]
    fn drop_after_normal_fulfillment_is_a_no_op() {
        let pending = std::sync::Mutex::new(HashMap::new());
        let (tx, _rx) = oneshot::channel::<FetchOutcome>();
        pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(vec![1, 2, 3], vec![tx]);

        // Simulates `handle_block_response`: removes and fulfills.
        let removed =
            pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&vec![1, 2, 3]);
        for tx in removed.unwrap() {
            tx.send(FetchOutcome::Found(Bytes::from_static(b"data"))).unwrap();
        }

        let _guard = PendingBlockGuard { pending: &pending, hash: vec![1, 2, 3] };
        drop(_guard);

        assert!(pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    /// A second request for the *same* hash is held in the waiter list —
    /// the first guard's drop must prune only its closed sender, not yank
    /// the still-open second request out of the map.
    #[test]
    fn drop_prunes_only_closed_waiters_for_the_same_hash() {
        let pending = std::sync::Mutex::new(HashMap::new());
        let (tx1, rx1) = oneshot::channel::<FetchOutcome>();
        let (tx2, _rx2) = oneshot::channel::<FetchOutcome>();
        pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(vec![9], vec![tx1, tx2]);
        drop(rx1);

        let guard1 = PendingBlockGuard { pending: &pending, hash: vec![9] };
        drop(guard1);

        let pending = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let waiters = pending.get(&vec![9]).unwrap();
        assert_eq!(waiters.len(), 1, "the second, still-open waiter must survive");
    }
}

/// SEC-5: a peer
/// could return data for a block that doesn't actually match what was
/// requested (wrong content, truncated, or an outright malicious/corrupt
/// response) — `ensure_blocks_present` must never accept and persist it
/// as though it were the real block.
#[cfg(test)]
mod block_data_matches_tests {
    use super::{block_data_matches, BlockInfo};
    use sha2::{Digest, Sha256};

    fn block_for(data: &[u8]) -> BlockInfo {
        BlockInfo { hash: Sha256::digest(data).to_vec(), offset: 0, size: data.len() as u32 }
    }

    #[test]
    fn matching_data_is_accepted() {
        let data = b"real block content";
        assert!(block_data_matches(&block_for(data), data));
    }

    #[test]
    fn wrong_content_with_the_same_length_is_rejected() {
        let real = b"aaaaaaaaaaaaaaaaaaaa";
        let junk = b"bbbbbbbbbbbbbbbbbbbb";
        assert_eq!(real.len(), junk.len());
        assert!(!block_data_matches(&block_for(real), junk));
    }

    #[test]
    fn truncated_data_is_rejected() {
        let full = b"real block content";
        let expected = block_for(full);
        assert!(!block_data_matches(&expected, &full[..full.len() - 1]));
    }

    #[test]
    fn empty_response_for_a_nonempty_block_is_rejected() {
        let expected = block_for(b"real block content");
        assert!(!block_data_matches(&expected, &[]));
    }
}

#[cfg(test)]
mod path_safety_tests {
    use super::is_safe_relative_path;

    #[test]
    fn ordinary_relative_paths_are_safe() {
        assert!(is_safe_relative_path("hello.txt"));
        assert!(is_safe_relative_path("nested/dir/file.txt"));
    }

    #[test]
    fn parent_dir_traversal_is_rejected() {
        assert!(!is_safe_relative_path("../outside.txt"));
        assert!(!is_safe_relative_path("nested/../../outside.txt"));
        assert!(!is_safe_relative_path("../../../.ssh/authorized_keys"));
    }

    #[test]
    fn absolute_paths_are_rejected() {
        assert!(!is_safe_relative_path("/etc/passwd"));
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(!is_safe_relative_path(""));
    }
}

/// security hardening: the incoming-index cardinality cap
/// (`index_message_exceeds_cardinality_cap`, wired into
/// `reconcile_files_if_authorized`) — exercised against small synthetic
/// `max_files`/`max_blocks` rather than the real (deliberately huge)
/// `MAX_FILES_PER_INDEX_MESSAGE`/`MAX_BLOCKS_PER_INDEX_MESSAGE` constants,
/// so the boundary logic itself is tested cheaply and deterministically.
#[cfg(test)]
mod cardinality_cap_tests {
    use super::{index_message_exceeds_cardinality_cap, proto};

    fn file_with_blocks(n: usize) -> proto::FileInfo {
        proto::FileInfo {
            blocks: (0..n).map(|_| proto::BlockInfo::default()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn within_both_caps_is_accepted() {
        let files = vec![file_with_blocks(2), file_with_blocks(2)];
        assert!(!index_message_exceeds_cardinality_cap(&files, 5, 10));
    }

    #[test]
    fn exactly_at_both_caps_is_accepted() {
        // 3 files, 2+2+1 = 5 blocks — exactly at max_files=3, max_blocks=5.
        let files = vec![file_with_blocks(2), file_with_blocks(2), file_with_blocks(1)];
        assert!(!index_message_exceeds_cardinality_cap(&files, 3, 5));
    }

    #[test]
    fn one_file_over_the_file_count_cap_is_rejected() {
        let files = vec![file_with_blocks(0), file_with_blocks(0), file_with_blocks(0)];
        assert!(index_message_exceeds_cardinality_cap(&files, 2, 1000));
    }

    #[test]
    fn one_block_over_the_total_block_cap_is_rejected() {
        // A single file whose own block count alone exceeds max_blocks —
        // the real attack shape this guards against (arbitrarily many
        // blocks doesn't require arbitrarily many files).
        let files = vec![file_with_blocks(11)];
        assert!(index_message_exceeds_cardinality_cap(&files, 1000, 10));
    }

    #[test]
    fn block_count_is_summed_across_files_not_checked_per_file() {
        // No single file exceeds max_blocks=10 alone, but their sum (12)
        // does — the cap must bound the *message total*, not the largest
        // individual file, or a peer could split one oversized index into
        // many just-under-the-per-file-cap files to evade it.
        let files = vec![file_with_blocks(6), file_with_blocks(6)];
        assert!(index_message_exceeds_cardinality_cap(&files, 1000, 10));
    }

    #[test]
    fn empty_index_is_accepted() {
        assert!(!index_message_exceeds_cardinality_cap(&[], 0, 0));
    }
}

/// security hardening: the per-(session, group) eager-fetch admission
/// budget (`admit_eager_blocks_impl`, wired into
/// `PeerSyncSession::admit_eager_blocks`) — exercised against a small
/// synthetic `max_per_group` rather than the real (deliberately huge)
/// `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`, for the same reason as
/// `cardinality_cap_tests` above.
#[cfg(test)]
mod eager_admission_tests {
    use super::{admit_eager_blocks_impl, HashMap};

    #[test]
    fn admits_while_under_budget() {
        let mut admission = HashMap::new();
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 3, 10));
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 3, 10));
        assert_eq!(*admission.get("group-a").unwrap(), 6);
    }

    #[test]
    fn admits_exactly_up_to_the_ceiling() {
        let mut admission = HashMap::new();
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 10, 10));
        assert_eq!(*admission.get("group-a").unwrap(), 10);
    }

    #[test]
    fn denies_once_the_ceiling_would_be_exceeded_and_leaves_the_counter_unchanged() {
        let mut admission = HashMap::new();
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 8, 10));
        // 8 + 5 = 13 > 10: denied, and the counter must stay at 8, not
        // partially advance — a denied admission fetches nothing at all.
        assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 5, 10));
        assert_eq!(*admission.get("group-a").unwrap(), 8);
    }

    #[test]
    fn budget_is_cumulative_across_many_smaller_admissions_from_the_same_peer() {
        // The doc comment's specific concern: a burst of `IndexUpdate`s
        // each individually small must still be bounded in aggregate.
        let mut admission = HashMap::new();
        for _ in 0..10 {
            assert!(admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
        }
        assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
    }

    #[test]
    fn each_group_has_an_independent_budget() {
        let mut admission = HashMap::new();
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 10, 10));
        assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
        // group-b's budget is untouched by group-a's exhaustion.
        assert!(admit_eager_blocks_impl(&mut admission, "group-b", 10, 10));
    }

    #[test]
    fn an_oversized_single_request_does_not_overflow_the_counter() {
        // saturating_add guards against a pathological single block_count
        // near u64::MAX wrapping the cumulative counter back into budget.
        let mut admission = HashMap::new();
        assert!(!admit_eager_blocks_impl(&mut admission, "group-a", u64::MAX, 10));
        assert_eq!(*admission.get("group-a").unwrap(), 0);
    }
}

/// `materialize_symlink_at` and
/// `try_apply_metadata_only_update`, exercised directly against a
/// `SyncState` + tempdir — no `PeerSyncSession`/channel needed, since
/// neither function touches the network (see both functions' doc
/// comments for why, and for the wire-schema gap they operate under).
#[cfg(test)]
mod symlink_and_metadata_only_update_tests {
    use super::{
        materialize_symlink_at, try_apply_metadata_only_update, BlockInfo, FileRecord, RecordKind,
        SyncState,
    };
    use crate::version_vector::VersionVector;

    fn symlink_record(path: &str) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    fn file_record_with_block(path: &str, hash_byte: u8) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 5,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 5 }],
            deleted: false,
        }
    }

    /// Given a path this device's own index already classifies
    /// as a symlink with a recorded target, `materialize_symlink_at`
    /// creates a real on-disk symlink and keeps the index row in sync.
    #[cfg(unix)]
    #[test]
    fn materialize_symlink_at_creates_a_real_symlink_and_upserts_index() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let record = symlink_record("link.txt");
        state.upsert_file("group-1", &record).unwrap();
        state.set_record_kind("group-1", "link.txt", RecordKind::Symlink).unwrap();
        state.set_symlink_target("group-1", "link.txt", Some("target.txt")).unwrap();

        materialize_symlink_at(&state, root.path(), "group-1", &record, false, "device-a").unwrap();

        let out_path = root.path().join("link.txt");
        assert!(
            std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
            "must be a real symlink on disk"
        );
        assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
        assert!(!state.get_file("group-1", "link.txt").unwrap().unwrap().deleted);
    }

    /// A symlink record with no recorded target (shouldn't normally
    /// happen, but must be handled defensively) must never create a
    /// broken/empty placeholder on disk — the index row still gets
    /// updated, just nothing is written to the filesystem.
    #[test]
    fn materialize_symlink_at_with_no_target_recorded_skips_disk_write_but_still_indexes() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let record = symlink_record("mystery-link");
        state.upsert_file("group-1", &record).unwrap();
        state.set_record_kind("group-1", "mystery-link", RecordKind::Symlink).unwrap();
        // symlink_target deliberately left unset.

        materialize_symlink_at(&state, root.path(), "group-1", &record, false, "device-a").unwrap();

        assert!(
            !root.path().join("mystery-link").exists(),
            "must not create anything on disk without a recorded target"
        );
        assert_eq!(
            state.get_record_kind("group-1", "mystery-link").unwrap(),
            Some(RecordKind::Symlink)
        );
    }

    /// When the incoming record's block list is byte-identical
    /// to what's already indexed locally, the fast path applies just the
    /// exec bit (via a real chmod) and index bookkeeping (mtime/version),
    /// leaving the file's actual content bytes completely untouched.
    #[cfg(unix)]
    #[test]
    fn metadata_only_fast_path_applies_exec_bit_without_touching_content() {
        use std::os::unix::fs::PermissionsExt;

        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        let local = file_record_with_block("script.sh", 0xAB);
        state.upsert_file("group-1", &local).unwrap();

        let out_path = root.path().join("script.sh");
        std::fs::write(&out_path, b"hello").unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Simulates this device's own index already knowing the target
        // exec bit for this path — see `try_apply_metadata_only_update`'s
        // doc comment on the wire-schema gap this stands in for.
        state.set_exec_bit("group-1", "script.sh", true).unwrap();

        let mut incoming = file_record_with_block("script.sh", 0xAB); // identical block hash
        incoming.mtime_unix_nanos = 999;
        incoming.version.increment("device-b");

        let applied =
            try_apply_metadata_only_update(&state, root.path(), "group-1", &incoming, "device-a")
                .unwrap();
        assert!(applied, "an identical block list must take the metadata-only fast path");

        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o744, "exec bit must be applied via chmod");
        assert_eq!(std::fs::read(&out_path).unwrap(), b"hello", "content bytes must be untouched");

        let stored = state.get_file("group-1", "script.sh").unwrap().unwrap();
        assert_eq!(stored.mtime_unix_nanos, 999, "index bookkeeping must still be updated");
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_with_no_prior_local_record() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let record = file_record_with_block("new.bin", 0x11);

        let applied =
            try_apply_metadata_only_update(&state, root.path(), "group-1", &record, "device-a")
                .unwrap();
        assert!(!applied, "brand-new adoption has nothing to compare against");
        assert!(
            state.get_file("group-1", "new.bin").unwrap().is_none(),
            "the fast path must not upsert anything when it doesn't apply"
        );
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_when_content_actually_changed() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let local = file_record_with_block("doc.txt", 0x11);
        state.upsert_file("group-1", &local).unwrap();

        let mut incoming = file_record_with_block("doc.txt", 0x22); // different hash = real content change
        incoming.version.increment("device-b");

        let applied =
            try_apply_metadata_only_update(&state, root.path(), "group-1", &incoming, "device-a")
                .unwrap();
        assert!(!applied, "a genuinely different block list must not take the metadata-only path");
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_to_a_deleted_local_record() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut local = file_record_with_block("gone.bin", 0x33);
        local.deleted = true;
        state.upsert_file("group-1", &local).unwrap();

        let mut incoming = file_record_with_block("gone.bin", 0x33);
        incoming.version.increment("device-b");

        let applied =
            try_apply_metadata_only_update(&state, root.path(), "group-1", &incoming, "device-a")
                .unwrap();
        assert!(!applied, "a tombstoned local record must fall through to ordinary handling");
    }
}

/// `hazard_reason_for_policy` and
/// `hold_record`, exercised directly against a `SyncState` + tempdir — no
/// `PeerSyncSession`/channel needed, same reasoning as
/// `symlink_and_metadata_only_update_tests` above. Real,
/// wire-driven end-to-end coverage of the full `materialize`/
/// `hydrate_file_with_timeout` wiring (forwarding to other peers, block
/// serving) lives in `tests/peer_session.rs`.
#[cfg(test)]
mod hazard_reason_tests {
    use super::{hazard_reason_for_policy, hold_record, FileRecord};
    use crate::hazard::NamePolicy;
    use crate::index::SyncState;
    use crate::version_vector::VersionVector;

    fn record(path: &str) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    /// An incoming record whose path case-folds identically to
    /// an already-indexed sibling, but isn't byte-identical to it, is a
    /// case-fold-collision hazard on a case-insensitive filesystem --
    /// `hazard_reason_for_policy` itself only even runs this check when
    /// `hazard::is_case_insensitive_filesystem(root)` says so (this
    /// module's own doc comment), so the test skips outright on a
    /// genuinely case-sensitive tempdir (e.g. a Linux ext4 CI runner)
    /// rather than asserting a hazard that correctly cannot occur there.
    #[test]
    fn case_fold_collision_with_an_existing_sibling_is_a_hazard() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        if !crate::hazard::is_case_insensitive_filesystem(root.path()) {
            eprintln!("skipping: {} is case-sensitive here", root.path().display());
            return;
        }
        state.upsert_file("group-1", &record("Photo.jpg")).unwrap();

        let reason = hazard_reason_for_policy(
            &state,
            root.path(),
            "group-1",
            &record("photo.jpg"),
            NamePolicy::Posix,
        )
        .unwrap();

        let reason = reason.expect("a differently-cased sibling must be flagged as a hazard");
        assert!(reason.starts_with(crate::hazard::HELD_REASON_CASE_COLLISION));
        assert!(reason.contains("Photo.jpg"), "reason should name the colliding sibling: {reason}");
    }

    /// The exact inverse of the above: re-adopting a path identical to
    /// what's already indexed for it (an ordinary update, not a new
    /// arrival) must never be flagged as colliding with itself.
    #[test]
    fn updating_the_same_path_is_never_a_self_collision() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        state.upsert_file("group-1", &record("Photo.jpg")).unwrap();

        let reason = hazard_reason_for_policy(
            &state,
            root.path(),
            "group-1",
            &record("Photo.jpg"),
            NamePolicy::Posix,
        )
        .unwrap();
        assert_eq!(reason, None);
    }

    /// An ordinary, non-colliding, non-reserved name is never a hazard
    /// under either policy.
    #[test]
    fn an_ordinary_name_is_never_a_hazard() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        for policy in [NamePolicy::Posix, NamePolicy::Windows] {
            let reason = hazard_reason_for_policy(
                &state,
                root.path(),
                "group-1",
                &record("notes.txt"),
                policy,
            )
            .unwrap();
            assert_eq!(reason, None, "{policy:?}");
        }
    }

    /// The exact scenario this test targets — the *same*
    /// index state (a record named after a Windows-reserved device name)
    /// is held under `NamePolicy::Windows` and materializes normally
    /// (`None`, i.e. not a hazard) under `NamePolicy::Posix`, proving the
    /// "gated on the local platform" requirement without needing to
    /// actually compile or run this suite on real Windows.
    #[test]
    fn windows_reserved_name_is_held_on_windows_policy_and_clear_on_posix_policy() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let incoming = record("CON.txt");

        let windows_reason = hazard_reason_for_policy(
            &state,
            root.path(),
            "group-1",
            &incoming,
            NamePolicy::Windows,
        )
        .unwrap();
        assert!(windows_reason.unwrap().starts_with(crate::hazard::HELD_REASON_INVALID_NAME));

        let posix_reason =
            hazard_reason_for_policy(&state, root.path(), "group-1", &incoming, NamePolicy::Posix)
                .unwrap();
        assert_eq!(
            posix_reason, None,
            "the exact same name is completely valid on a POSIX filesystem"
        );
    }

    /// `hold_record` upserts the record (so it keeps
    /// participating in index exchange) and sets held state, without
    /// creating anything on disk.
    #[test]
    fn hold_record_upserts_and_marks_held_without_touching_disk() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let incoming = record("CON.txt");

        hold_record(
            &state,
            "group-1",
            &incoming,
            "invalid_name: reserved device name 'CON'",
            "device-a",
        )
        .unwrap();

        let stored = state.get_file("group-1", "CON.txt").unwrap();
        assert!(stored.is_some(), "the relevant behavior: a held record must still be indexed");
        assert!(!stored.unwrap().deleted);

        let held = state.get_held_state("group-1", "CON.txt").unwrap().unwrap();
        assert!(held.reason.starts_with("invalid_name"));
        assert!(held.since_unix_nanos > 0);

        assert!(
            !root.path().join("CON.txt").exists(),
            "a held record must never be written to disk"
        );
    }

    /// The regression test this explicitly
    /// calls for — a real, pre-existing sibling is already on disk;
    /// holding a case-fold-colliding incoming record for it must never
    /// produce a written file under any name at all, not the hazardous
    /// name and not some auto-generated alternate (`"photo (1).jpg"`,
    /// `"photo_2.jpg"`, ...) — this crate implements no automatic
    /// rename/escape path. Asserted by enumerating the whole directory
    /// afterward, not just checking the one hazardous name's own
    /// non-existence, so an unexpected alternate-named file would fail
    /// this test too.
    #[test]
    fn hold_record_never_writes_under_any_alternate_name() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        // Same case-sensitivity dependency as case_fold_collision_with_an_
        // existing_sibling_is_a_hazard above -- see its doc comment.
        if !crate::hazard::is_case_insensitive_filesystem(root.path()) {
            eprintln!("skipping: {} is case-sensitive here", root.path().display());
            return;
        }
        std::fs::write(root.path().join("Photo.jpg"), b"original").unwrap();
        state.upsert_file("group-1", &record("Photo.jpg")).unwrap();

        let incoming = record("photo.jpg");
        let reason =
            hazard_reason_for_policy(&state, root.path(), "group-1", &incoming, NamePolicy::Posix)
                .unwrap()
                .expect("case-fold collision must be detected");
        hold_record(&state, "group-1", &incoming, &reason, "device-a").unwrap();

        let mut entries: Vec<String> = std::fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec!["Photo.jpg".to_string()],
            "no alternate/renamed variant of the held file may ever appear on disk"
        );
        assert_eq!(std::fs::read(root.path().join("Photo.jpg")).unwrap(), b"original");
    }
}

/// `compress_block`/`decompress_block`
/// exercised directly — no `PeerSyncSession`/channel needed, mirroring
/// every other free-function test module above.
#[cfg(test)]
mod compression_codec_tests {
    use super::{compress_block, decompress_block, proto};

    /// D3's adaptive-skip heuristic: uniformly random bytes have no
    /// exploitable redundancy, so a zstd level-3 pass shouldn't beat the
    /// documented 95% threshold — the sender must fall back to raw rather
    /// than pay for a compressed form that isn't meaningfully smaller.
    #[test]
    fn incompressible_random_bytes_are_sent_raw() {
        // A simple xorshift PRNG is enough here — no external `rand`
        // dependency needed just to get high-entropy bytes for this test.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let data: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect();

        let (out, compression) = compress_block(&data);

        assert_eq!(compression, proto::Compression::None);
        assert_eq!(out, data, "raw fallback must return the original bytes unchanged");
    }

    /// Already-zstd-compressed content is itself close to incompressible
    /// (compressed bytes look like high-entropy noise to a second pass) —
    /// matching the design's "already-compressed content is sent raw, spending
    /// only the one cheap trial-compression pass."
    #[test]
    fn already_compressed_bytes_are_sent_raw() {
        let source = b"the quick brown fox jumps over the lazy dog ".repeat(500);
        let already_compressed = zstd::stream::encode_all(source.as_slice(), 19).unwrap();

        let (out, compression) = compress_block(&already_compressed);

        assert_eq!(compression, proto::Compression::None);
        assert_eq!(out, already_compressed);
    }

    /// The positive case: highly repetitive synthetic text (the shape of
    /// real source-tree/log/DB-dump content this feature targets) compresses
    /// well past the 95% threshold and must be sent compressed.
    #[test]
    fn highly_repetitive_text_is_compressed() {
        let data = "the quick brown fox jumps over the lazy dog\n".repeat(10_000);

        let (out, compression) = compress_block(data.as_bytes());

        assert_eq!(compression, proto::Compression::Zstd);
        assert!(
            out.len() < data.len() / 10,
            "highly repetitive text should compress to well under 10% of its raw size, got \
             {} of {} bytes",
            out.len(),
            data.len()
        );
    }

    /// Empty input is never worth compressing (zstd's own frame overhead
    /// alone would make a compressed form larger than nothing).
    #[test]
    fn empty_input_is_sent_raw() {
        let (out, compression) = compress_block(&[]);
        assert_eq!(compression, proto::Compression::None);
        assert!(out.is_empty());
    }

    /// Round trip: whatever `compress_block` decides to do, `decompress_block`
    /// must recover the exact original bytes.
    #[test]
    fn compress_then_decompress_round_trips_exactly() {
        let data = "abcdefgh".repeat(20_000);
        let (out, compression) = compress_block(data.as_bytes());
        assert_eq!(compression, proto::Compression::Zstd, "sanity: this input must compress");

        let recovered = decompress_block(&out, compression, 10 * 1024 * 1024).unwrap();
        assert_eq!(recovered, data.as_bytes());
    }

    /// `Compression::None` is a pure passthrough — the byte-identity path
    /// every pre-this-change / negotiation-declined block/index message
    /// takes.
    #[test]
    fn none_compression_is_a_passthrough() {
        let data = b"uncompressed content".to_vec();
        let recovered = decompress_block(&data, proto::Compression::None, 4).unwrap();
        assert_eq!(recovered, data, "None must pass bytes through even past `max_size`");
    }

    /// The decompression-bomb bound: a small
    /// compressed payload that *claims* to expand far past `max_size` must
    /// be rejected, not decompressed into memory. Compresses 64 MiB of
    /// zeros (a classic zstd bomb shape — trivially compressible) down to
    /// a few hundred bytes, then asks `decompress_block` to bound it to a
    /// 1 KiB ceiling. If this function fully materialized the claimed
    /// output before checking the size, this test would need ~64 MiB and
    /// noticeable wall-clock time to complete; instead it must return an
    /// error promptly, having never buffered more than `max_size + 1`
    /// bytes (the `Read::take` bound baked into the implementation).
    #[test]
    fn decompression_bomb_is_rejected_without_materializing_the_full_output() {
        // Level 3 (not a high level) is enough: all-zero input compresses
        // to a tiny fraction of its size at any level, and keeping this
        // fast avoids adding CPU load to the suite under parallel test
        // execution.
        let huge_zeros = vec![0u8; 64 * 1024 * 1024];
        let bomb = zstd::stream::encode_all(huge_zeros.as_slice(), 3).unwrap();
        assert!(
            bomb.len() < 8192,
            "sanity: the bomb payload itself must be tiny relative to its claimed output"
        );
        drop(huge_zeros);

        let max_size = 1024;
        let start = std::time::Instant::now();
        let result = decompress_block(&bomb, proto::Compression::Zstd, max_size);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "a payload exceeding max_size must be rejected, not accepted");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "bounded decompression must not spend time producing megabytes of output it will \
             discard; took {elapsed:?}"
        );
    }

    /// A payload that is not valid zstd at all (never decompressed
    /// successfully by any peer, honest or not) must also be rejected
    /// cleanly rather than panicking.
    #[test]
    fn corrupt_non_zstd_payload_is_rejected() {
        let garbage = vec![0xFFu8; 128];
        let result = decompress_block(&garbage, proto::Compression::Zstd, 1024 * 1024);
        assert!(result.is_err());
    }

    /// A payload that decompresses to exactly `max_size` bytes (not one
    /// byte over) must be accepted — the bound is inclusive, matching
    /// `MAX_BLOCK_SIZE`'s own role as an upper bound on legitimate block
    /// content.
    #[test]
    fn decompressed_size_exactly_at_the_bound_is_accepted() {
        let data = vec![0x7Au8; 1024];
        let compressed = zstd::stream::encode_all(data.as_slice(), 3).unwrap();
        let recovered = decompress_block(&compressed, proto::Compression::Zstd, 1024).unwrap();
        assert_eq!(recovered, data);
    }
}

/// Bytes-on-wire and wall-clock
/// cost for `compress_block` — the exact codec `handle_block_request`/
/// `send_full_index`/`send_index_update` all call — against two
/// representative workloads: a source-tree-like text corpus (compression's
/// target case) and a photo/media-like
/// incompressible corpus (the adaptive-skip heuristic's target case,
/// confirming the adaptive skip heuristic keeps the regression
/// negligible). `#[ignore]`d, matching this crate's convention for
/// cost-heavy checks that don't belong in the default `cargo test` run —
/// invoke explicitly with:
///
/// ```text
/// cargo test -p yadorilink-sync-core --lib -- --ignored --nocapture bytes_on_wire_and_cost_source_tree_vs_media
/// ```
///
/// One real run's printed output was recorded as the
/// acceptance evidence for this feature.
#[cfg(test)]
mod compression_benchmark {
    use super::compress_block;

    #[test]
    #[ignore]
    fn bytes_on_wire_and_cost_source_tree_vs_media() {
        // "source tree" stand-in: many small, highly repetitive Rust-like
        // source files concatenated into one corpus — representative of
        // source trees, documents, logs, and DB dumps as the target
        // workload shape.
        let mut source_tree = Vec::new();
        for i in 0..2000 {
            source_tree.extend_from_slice(
                format!(
                    "use std::fmt;\n\npub struct Item{i} {{\n    pub id: u64,\n    pub \
                     name: String,\n}}\n\nimpl fmt::Display for Item{i} {{\n    fn fmt(&self, \
                     f: &mut fmt::Formatter<'_>) -> fmt::Result {{\n        write!(f, \
                     \"Item{{}}\", self.id)\n    }}\n}}\n\n"
                )
                .as_bytes(),
            );
        }

        // "media" stand-in: high-entropy bytes — the shape an
        // already-compressed photo/video/archive has on the wire, sized to
        // match the source-tree corpus for a fair side-by-side comparison.
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let media: Vec<u8> = (0..source_tree.len())
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state & 0xFF) as u8
            })
            .collect();

        for (label, corpus) in
            [("source-tree-like text", &source_tree), ("media-like (incompressible)", &media)]
        {
            let start = std::time::Instant::now();
            let (out, compression) = compress_block(corpus);
            let elapsed = start.elapsed();
            let ratio = 100.0 * out.len() as f64 / corpus.len() as f64;
            println!(
                "{label}: raw={} bytes, wire={} bytes ({ratio:.1}% of raw), \
                 compression={compression:?}, compress_block took {elapsed:?}",
                corpus.len(),
                out.len(),
            );
        }
    }
}
