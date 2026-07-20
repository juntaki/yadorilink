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
//! claim, what path to name — are adversarial
//! input, not trusted metadata. `reconcile_one_file`/`reconcile_files_if_
//! authorized` bound version-vector counter growth and incoming-index
//! cardinality; `resolve_and_apply_conflict` bounds the accepted `mtime`
//! skew; `materialize`/
//! `hydrate_file_with_timeout` re-verify the resolved write target stays
//! under the sync root. See `version_vector.rs`'s and
//! `conflict.rs`'s doc comments for why the version-vector and mtime
//! mitigations are explicitly **partial**, not a claim of full prevention
//! — a mutually-untrusted peer can always lie about its own causal
//! history to some degree; these bound the damage rather than eliminate it.

use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, Semaphore};
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::BlockStore;
use yadorilink_transport::PeerChannel;

use crate::adaptive_window::AdaptiveWindow;
use crate::change::{
    Change, ChangeHash, DeviceId, FileVersion, FolderGroupId, Op, VersionBlock, VersionHash,
};
use crate::chunker::{
    apply_exec_bit, reconstruct_file, verify_write_target_within_canonical_root,
    verify_write_target_within_root, write_placeholder, MAX_BLOCK_SIZE,
};
use crate::compaction;
use crate::conflict::{conflict_copy_path_for_losing_change, dag_conflict_loser_is_a};
use crate::dag_store::AdmitOutcome;
use crate::error::SyncError;
use crate::hazard;
use crate::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use crate::index::{LinkGate, SyncState};
use crate::materialization::check_disk_headroom;
use crate::rate_limiter::RateLimiters;
use crate::rebootstrap::RebootstrapRequired;
use crate::types::{
    BlockInfo, FileRecord, MaterializationPolicy, MaterializationState, RecordKind,
};
use crate::version_vector::{VvOrdering, MAX_VV_COUNTER_JUMP_PER_MESSAGE};

/// (see `run`'s recv loop, where this actually gates
/// concurrently-spawned inbound message handlers): the fixed, non-adaptive
/// per-peer concurrency ceiling. `AdaptiveWindow`'s `max` is constructed
/// to never exceed this — the
/// adaptive in-flight fetch window (`adaptive_window` field below) grows
/// and shrinks freely below it, but this remains the hard upper bound
/// nothing in this module can adapt past, so the new controller composes
/// with (rather than reintroduces a way around) the existing DoS bound.
const MAX_IN_FLIGHT_MESSAGES_PER_PEER: usize = 64;

/// Hard per-session bound for decoded ordinary messages waiting on a handler
/// permit. BlockResponse uses the independent control lane and is never queued,
/// so rejecting an ordinary-message flood at this limit cannot recreate the
/// response/permit deadlock this queue was introduced to avoid.
const MAX_PENDING_MESSAGE_BYTES_PER_PEER: usize = 64 * 1024 * 1024;

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

/// Compresses `data` at `COMPRESSION_
/// LEVEL` and keeps the compressed form only when it beats `COMPRESSION_
/// SKIP_THRESHOLD` of the raw size — otherwise (including on an
/// encoder error, or empty input, both treated as "not worth compressing"
/// rather than propagated, since sending raw bytes is always a safe
/// fallback) returns the original bytes tagged `Compression::None`. Pure
/// and synchronous — real CPU work for a multi-hundred-KB block, so every
/// caller in this module runs it inside `tokio::task::spawn_blocking`,
/// alongside the existing block-store I/O (same reasoning),
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

/// a per-(session, group) ceiling on how many blocks this
/// session will *eagerly* fetch and write for one folder group over its
/// lifetime — independent of, and in addition to, the per-message caps
/// above (those bound one large message; this bounds cumulative eager
/// admission across many smaller messages from the same connected peer,
/// e.g. a burst of change batches each just under the per-message cap).
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

/// the actual admission bookkeeping behind
/// `PeerSyncSession::admit_eager_blocks`, factored out as a free function
/// over an explicit `admission` map and `max_per_group` ceiling so it's
/// unit-testable (`eager_admission_tests` below) without constructing a
/// full `PeerSyncSession` (channel, state, store,...) just to exercise
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

/// Cap on how many materialization-audit records are re-driven concurrently.
/// Bounded (not "spawn one task per record
/// unconditionally") for the same reason `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
/// bounds concurrently-spawned message handlers: a large audit shouldn't spawn
/// thousands of tasks — many of them concurrently awaiting a block-fetch
/// round trip from this same peer connection — all at once.
const MAX_CONCURRENT_RECONCILES: usize = 16;

/// Upper bound on the number of encoded changes carried in a single
/// `ChangeBatch`, so one wire message can never be made unboundedly large
/// — the change-history analogue of `MAX_FILES_PER_INDEX_MESSAGE`. A
/// requester that needs more than this walks the ancestry in additional
/// rounds (each round bounded by the same cap), so catch-up cost stays
/// proportional to the divergence without any single message being a DoS
/// lever.
const MAX_CHANGES_PER_BATCH: usize = 1_000;

// the payload waiters carry `Bytes`, not `Vec<u8>` — lets
// several concurrent local callers await the *same* in-flight block hash
// at once (multi-waiter), and `handle_block_response` below has to fan the
// one response out to every waiter. With `Vec<u8>` that fan-out was a full
// `payload.clone` (a real memcpy of the whole block) per extra waiter;
// `Bytes::clone` is a cheap refcounted handle to the same backing
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
    /// failure, decompression-bomb bound exceeded, or similar) —
    /// deliberately distinct from `NotFound` (see this enum's own doc
    /// comment).
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

/// `fetch_block` used to `insert` into `pending_block_requests` and
/// rely solely on `handle_block_response` to `remove` it — but a caller
/// wrapping `fetch_block` in a timeout (as `hydrate_file`/
/// `ensure_blocks_present` both do) drops the `fetch_block` future, and
/// therefore its local `rx`, without ever running `handle_block_response`
/// for that hash. Nothing else ever removed the now-orphaned entry, so a
/// timed-out or cancelled fetch leaked one `HashMap` entry forever — on a
/// long-running daemon with an unreachable peer, unboundedly. This RAII
/// guard removes its entry on drop, but only when the sender is
/// `is_closed` (its matching `rx` was dropped without ever receiving a
/// response) — the ordinary, already-fulfilled-by-`handle_block_response`
/// path already removed the entry itself, so the guard's own drop then
/// finds nothing there and no-ops; and if a *newer* request for the same
/// hash was inserted in between (two concurrent fetches for an
/// identical block, territory), that still-open sender remains
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

/// Materializes a non-deleted symlink
/// record at `group_id`/`record.path` under `root`. Factored out as a
/// free function (explicit `state`/`root`/`group_id`/`record` rather than
/// a `PeerSyncSession` receiver) purely for direct unit-testability — the
/// same reason `index_message_exceeds_cardinality_cap`/
/// `admit_eager_blocks_impl` above are free functions: a symlink record
/// carries no blocks at all, so materializing one needs no
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
    // defense-in-depth, same as every other materialization
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
    // The index can get ahead of the disk when a prior materialization wrote
    // its row and then failed. Existence alone is also insufficient: a stale
    // or partially-written file at this path must take the normal reconstruct
    // path, not be accepted as a metadata-only update.
    if !crate::materialization::disk_bytes_match_indexed_blocks(&out_path, &record.blocks)? {
        return Ok(false);
    }
    state.upsert_file_with_origin(group_id, record, origin_device_id)?;
    apply_exec_bit(&out_path, state.get_exec_bit(group_id, &record.path)?)?;
    Ok(true)
}

/// Under `madsim`, `SystemTime::now` reads a per-seed *virtual* clock
/// (madsim intercepts `gettimeofday`/`clock_gettime`) — but a real
/// filesystem's `mtime` does not go through that interception (the kernel
/// stamps it independently at write time), so a real-fs write during a
/// DST run gets a *real* wall-clock mtime while `now_unix_nanos` reads
/// madsim's *virtual*, epoch-relative one. Comparing the two (`clamp_
/// future_mtime`/`a_is_loser` in `conflict.rs`) puts every mtime far in
/// virtual-"now"'s future, so the skew clamp fires unconditionally — an
/// unrealistic regime (production has both on the same real clock) that
/// also amplifies otherwise-tiny scheduling jitter (e.g. the r2d2 SQLite
/// connection pool's background thread, which runs on a real, non-
/// deterministically-scheduled OS thread) into a visibly different tie-
/// break outcome across replays of the *same* seed. This override lets a
/// DST harness put `now_unix_nanos` back on the *same* synthetic
/// timeline it also stamps onto its own written files' mtimes (see
/// `dst_two_device_chaos.rs`'s round loop), closing both the fidelity gap
/// and the replay non-determinism it was quietly amplifying. Unset in
/// production and in any test that never calls `set_test_clock_override`
/// — `now_unix_nanos` then falls through to the real `SystemTime::now`
/// exactly as before this existed.
#[cfg(madsim)]
static DETERMINISTIC_CLOCK_OVERRIDE: std::sync::OnceLock<std::sync::atomic::AtomicI64> =
    std::sync::OnceLock::new();

/// Test-only: pins `now_unix_nanos` (every call site, process-wide) to
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
#[cfg(not(madsim))]
#[allow(deprecated)]
fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// Under the deterministic simulator `spawn_blocking` would run `f` on a
/// real, non-simulated OS thread pool whose completion time bleeds into the
/// virtual clock non-deterministically. Running the identical work inline and
/// handing back an already-ready future drives the exact same result while
/// keeping every `spawn_blocking(...).await` call site below scheduled
/// deterministically. Every site awaits the handle immediately, so eager
/// inline execution is behavior-preserving; the `Ok`-wrapped
/// `Result<R, JoinError>` matches the await output shape the production
/// `JoinHandle` yields, so no call site needs to change.
#[cfg(madsim)]
fn spawn_blocking<F, R>(f: F) -> std::future::Ready<Result<R, tokio::task::JoinError>>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    std::future::ready(Ok(f()))
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
/// `reconcile_one_file`'s version-vector `compare` runs or `materialize`
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

/// A target device's answer to its own `HandoffLeaseResponder`, carrying
/// exactly what `HandoffLeaseGrant` (the wire message) needs: the
/// coordination-plane-issued lease id, the digest of the durability-root set
/// the target actually verified and pinned against that lease, and its
/// expiry. Kept as a plain struct here (rather than depending on the wire
/// `proto::HandoffLeaseGrant` type directly) so `HandoffLeaseResponder`
/// implementors don't need to reason about wire framing, mirroring how
/// `request_version_present`'s own `bool` return keeps its callers wire-free.
#[derive(Debug, Clone)]
pub struct PeerHandoffLeaseGrant {
    pub lease_id: String,
    /// This device's own durability-roots digest: the 32-byte SHA-256 over
    /// the sorted `(path, change::VersionHash)` set of every durability root
    /// it retains — the same digest a source-side readiness check computes.
    pub root_digest: [u8; 32],
    pub expires_at_unix: i64,
}

/// Lets a `PeerSyncSession` answer an incoming `HandoffLeaseRequest` by
/// bridging to the daemon's own coordination-plane-backed lease machinery —
/// `yadorilink-sync-core` has no coordination client and no concept of a
/// handoff lease at all (that lives entirely in `yadorilink-daemon`'s
/// `DaemonState`/`coordination_client`), so this is the same caller-injected
/// trait-object shape as `PendingLocalChangeFlush` above, for the same
/// reason (an `async fn` in a trait isn't object-safe without this
/// boilerplate, and this crate has no `async_trait` dependency).
///
/// Returns `None` when this device could not obtain a live lease this round
/// (its own readiness check failed, it has no coordination-plane config, the
/// coordination-plane request itself failed, or the atomic local pin
/// aborted) — the responder answers the peer `granted = false` in every one
/// of those cases, exactly as if the request had never been understood at
/// all, never distinguishing the reason over the wire.
pub trait HandoffLeaseResponder: Send + Sync {
    fn request_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>>;

    fn release_handoff_lease<'a>(
        &'a self,
        group_id: &'a str,
        lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// A prepared re-bootstrap response, ready to sign into the wire message: the
/// signed `RebootstrapRequired` protocol object plus the encoded snapshot
/// bytes it is bound to (via `manifest.checkpoint.snapshot_hash`). Kept as a
/// plain struct here, like `PeerHandoffLeaseGrant` above, so `RebootstrapHandler`
/// implementors don't need to reason about wire framing.
#[derive(Debug, Clone)]
pub struct PreparedRebootstrap {
    pub required: RebootstrapRequired,
    pub snapshot_bytes: Vec<u8>,
}

/// Lets a `PeerSyncSession` answer an incoming re-bootstrap request and
/// process an incoming re-bootstrap response, bridging to the daemon's own
/// signing identity and pinned-key trust resolver — `yadorilink-sync-core`
/// has no process identity of its own (that lives entirely in
/// `yadorilink-daemon`'s `DaemonState`), so this is the same
/// caller-injected trait-object shape as `HandoffLeaseResponder` above.
/// Every method is synchronous (no live coordination-plane round trip is
/// needed unlike the handoff-lease case), so it does not need the
/// `Pin<Box<dyn Future<...>>>` shape those methods use for object safety.
pub trait RebootstrapHandler: Send + Sync {
    /// Builds a signed `RebootstrapRequired` + snapshot response for a peer
    /// that asked this device for history it has evidence was intentionally
    /// pruned. `Ok(None)` when this device has no such evidence (the
    /// unknown-vs-pruned boundary `prepare_rebootstrap_required` preserves),
    /// or when this device has no signing key configured yet.
    fn prepare_rebootstrap(
        &self,
        group_id: &str,
        requested_hash: ChangeHash,
    ) -> Result<Option<PreparedRebootstrap>, SyncError>;

    /// Verifies an incoming `RebootstrapRequired`'s signature and internal
    /// structure against this device's trust resolver, before its snapshot
    /// bytes are even decoded. Callers must run this before
    /// `install_rebootstrap`.
    fn verify_rebootstrap(&self, required: &RebootstrapRequired) -> Result<(), SyncError>;

    /// Verifies the snapshot content and atomically installs it as the new
    /// HistoryBase. Callers must have already run `verify_rebootstrap` (and,
    /// for the wire path, confirmed the connected peer's authenticated
    /// identity matches `required.manifest.signer_device_id` — this trait
    /// has no session identity of its own to check that against).
    fn install_rebootstrap(
        &self,
        required: &RebootstrapRequired,
        snapshot_bytes: &[u8],
    ) -> Result<(), SyncError>;
}

/// Caller-injected guard factory that lets a session serialize creation of
/// new block references with daemon-level physical deletion. The returned
/// guard remains held until dropped; production injects `DaemonState`, while
/// standalone sync-core users that do not run daemon GC need no provider.
pub trait BlockWriteActivityProvider: Send + Sync {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_>;
}

/// A device's answer to its own `HandoffTicketResponder`, carrying exactly
/// what `HandoffTicketGrant` (the wire message) needs. Unlike
/// `PeerHandoffLeaseGrant`, there is no `root_digest` here: the requester
/// (the operating device removing/revoking this one) has no root set of its
/// own to compare against -- it trusts `granted` as this device's own
/// authenticated attestation of ITS OWN roots. `lease_id`/`target_device_id`
/// are both `None` when the device's root set was empty (vacuously ready --
/// nothing to hand off), and both `Some` otherwise: `target_device_id` is
/// the confirming peer (C) the lease was obtained from, which the operating
/// device must present alongside `lease_id` to the coordination plane's
/// lease-guarded role-loss commit -- a lease id alone does not identify
/// which `(group, target)` pair to atomically re-verify it against.
#[derive(Debug, Clone)]
pub struct PeerHandoffTicketGrant {
    pub lease_id: Option<String>,
    pub target_device_id: Option<String>,
    pub expires_at_unix: i64,
}

/// Lets a `PeerSyncSession` answer an incoming `HandoffTicketRequest` by
/// bridging to the daemon's own removed-device-ticket machinery
/// (`DaemonState::obtain_own_handoff_ticket`), the same caller-injected
/// trait-object shape as `HandoffLeaseResponder` above and for the same
/// reason. Returns `None` when this device could not obtain a live lease
/// for its own root set this round (no confirming peer holds its whole
/// root set, its own coordination-plane request failed, etc.) -- the
/// responder answers the peer `granted = false` in every one of those
/// cases, exactly as `HandoffLeaseResponder` already does.
pub trait HandoffTicketResponder: Send + Sync {
    fn request_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>>;

    fn release_handoff_ticket<'a>(
        &'a self,
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
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
/// local` here) is what makes a "held on a Windows-policy test
/// target, materializes normally on a POSIX-policy test target, from the
/// same index state" scenario directly testable in one process regardless
/// of which platform actually runs the test suite —
/// `PeerSyncSession::hazard_reason_for` (this function's only production
/// caller) always passes `hazard::NamePolicy::local`.
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
/// `UPDATE... WHERE group_id = ?, path = ?` that errors with
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
/// `record.blocks.is_empty` guard, for a genuinely empty file) correctly
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
    // { blocks: Vec::new,..record.clone })` guarded by the same
    // `is_none` check — that call now goes through the version-retaining
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

static MATERIALIZATION_AUDITS_IN_FLIGHT: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

struct MaterializationAuditGuard {
    key: String,
}

impl MaterializationAuditGuard {
    fn try_acquire(state: &Arc<SyncState>, group_id: &str) -> Option<Self> {
        let key = format!("{:p}:{group_id}", Arc::as_ptr(state));
        let in_flight = MATERIALIZATION_AUDITS_IN_FLIGHT.get_or_init(Default::default);
        let mut in_flight = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !in_flight.insert(key.clone()) {
            return None;
        }
        Some(Self { key })
    }
}

impl Drop for MaterializationAuditGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = MATERIALIZATION_AUDITS_IN_FLIGHT.get() {
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
        }
    }
}

/// This session's *current*
/// view of which folder groups its peer is authorized for, as distinct
/// from `PeerSyncSession::shared_group_ids` (the snapshot captured once at
/// construction from whatever netmap/ACL state was available at connect
/// time — still used for the initial `ClusterConfig` handshake
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

/// Outcome of `apply_locked_record`: the incoming record was either fully
/// handled without a conflict (adopted / peer-ahead / already-current /
/// never-seen), or it is genuinely concurrent with the local record and the
/// caller must decide how to resolve it. No surviving caller turns
/// `Concurrent` into a resolution: the DAG engine resolves concurrency by
/// (lamport, change-hash) before a record ever reaches here, and the
/// materialization-audit path treats it as unreachable.
enum LockedRecordOutcome {
    Settled,
    /// Carries only the local record, for the caller's diagnostic log: no
    /// surviving caller resolves a concurrency here, so the incoming record
    /// and its wire metadata would be dead payload.
    Concurrent {
        local: FileRecord,
    },
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
    /// `reconcile_files_if_authorized`) instead
    /// of `shared_group_ids` above. See `LiveGroupAuthorization`'s doc
    /// comment for why this is a separate field rather than a replacement
    /// for `shared_group_ids`.
    live_authorized_groups: LiveGroupAuthorization,
    /// This peer's advertised `supports_
    /// reliable_delivery` from its handshake `ClusterConfig`. This
    /// build always supports it (there is no local equivalent of
    /// `compression_negotiated`'s "and we support it too" check — reliable
    /// delivery has no capability variant, it's simply present or absent),
    /// so once this flips true, `record_peer_reliable_delivery_support`
    /// immediately calls `self.channel.enable_reliable_delivery`.
    peer_supports_reliable_delivery: std::sync::atomic::AtomicBool,
    /// This peer's advertised `supports_version_present` from its handshake
    /// `ClusterConfig` — mirrors `peer_supports_reliable_delivery`'s pattern.
    /// Starts `false`, and an old peer that predates this field leaves it
    /// `false` for the whole session: unlike a both-sides-advertise
    /// negotiation, this is a fail-safe *skip*, not a fallback behavior —
    /// such a peer silently drops an unrecognized `VersionPresentQuery`
    /// oneof case rather than replying (see `handle_message`'s doc comment
    /// on that decode behavior), so querying it anyway would only burn its
    /// full request timeout for nothing. `confirm_version_present_via_peer`
    /// (`yadorilink-daemon::daemon_state`) checks
    /// `version_present_negotiated` before ever sending a query to this
    /// peer.
    peer_supports_version_present: std::sync::atomic::AtomicBool,
    /// This peer's advertised `supports_version_hash_exact` from its
    /// handshake `ClusterConfig` — a strictly narrower capability than
    /// `peer_supports_version_present` above: a peer can implement the
    /// query/ack exchange itself while still running a build from before
    /// its responder required an exact `change::VersionHash` match
    /// (`holds_version_durably`'s step 3), in which case it would answer a
    /// `for_handoff = true` whole-group durability-handoff query on
    /// block-hash agreement alone. Starts `false`, and an old peer that
    /// predates this field leaves it `false` for the whole session — the
    /// same fail-safe-skip treatment as `peer_supports_version_present`.
    /// `yadorilink_daemon::daemon_state::peer_holds_entire_group` checks
    /// `version_hash_exact_negotiated` before ever sending a `for_handoff =
    /// true` query to this peer, rather than sending it and trusting a
    /// `present = true` answer that might only reflect a block-hash
    /// coincidence.
    peer_supports_version_hash_exact: std::sync::atomic::AtomicBool,
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
    /// `notified` against its `sleep` and return as soon as the
    /// handshake completes, rather than always riding out the full
    /// backoff before re-checking. `Notify::notify_one` stores a permit
    /// when nobody is currently waiting, so this is race-free regardless
    /// of whether the flag flips before or after the retry task calls
    /// `notified`. This matters beyond latency: a `sleep` that actually
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
    /// group_id -> (raw root, its canonical form), a pure cache in front of
    /// `std::fs::canonicalize`. `verify_write_target_within_canonical_root` is
    /// called on every eager materialize/hydrate, a
    /// per-peer-message-concurrency-bounded hot path (see that function's doc
    /// comment), so resolving each root's canonical form once (rather than on
    /// every single call) avoids repeatedly paying that cost.
    ///
    /// Only a cache, and deliberately not a source of truth for *where* a
    /// group's root is: that is read live from the link table by `sync_root`,
    /// because a session outlives the link it was constructed for (see
    /// `sync_root`'s doc comment). Each entry therefore carries the raw root it
    /// was derived from, and is used only when that still matches what the link
    /// table says right now — otherwise it is re-canonicalized, so a relinked
    /// folder can never be validated against its old root's canonical form.
    ///
    /// A group whose root can't be canonicalized (e.g. an unmounted volume) is
    /// simply absent; `verify_write_target` falls back to the raw path, which
    /// `verify_write_target_within_root` still checks correctly.
    canonical_sync_roots: StdMutex<HashMap<String, (PathBuf, PathBuf)>>,
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
    /// Correlates outstanding `VersionPresentQuery` requests to the oneshot
    /// `request_version_present` awaits: request_id -> reply sender. Backs the
    /// on-demand custody gate — a device confirms a full replica durably holds
    /// a version's blocks before reclaiming its own cached copy.
    pending_version_present: StdMutex<HashMap<u64, oneshot::Sender<bool>>>,
    /// Monotonic id used to correlate a `VersionPresentQuery` with its reply.
    next_present_request_id: std::sync::atomic::AtomicU64,
    /// Records this session adopted or resolved from *this* peer, handed
    /// off here so the caller can forward them on to this device's *other*
    /// peer sessions — full mesh propagation needs this explicit forwarding
    /// step; a record arriving from one peer does not otherwise reach any
    /// other peer this device is connected to. `None` for callers (tests,
    /// mainly) that don't need multi-peer forwarding.
    forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
    /// group_id -> cumulative blocks admitted to eager fetch
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
    /// Whether this peer has advertised understanding of the
    /// change-history DAG wire shapes (`HeadsAnnounce`/`ChangeRequest`/
    /// `ChangeBatch`) in its handshake `ClusterConfig` — the
    /// change-history analogue of `peer_supports_compression` et al.
    /// Starts `false`; a peer that never sets `supports_change_dag` leaves
    /// it `false` for the whole session, and since the legacy index
    /// exchange no longer exists such a peer simply never converges — there
    /// is no peer<->peer version handshake to fail loudly on. Both sides
    /// must advertise (this build always does, once a change store is
    /// wired), so this reduces to "has the peer said it speaks the DAG
    /// too."
    peer_supports_change_dag: std::sync::atomic::AtomicBool,
    /// Injected supplier of per-device pinned signing keys + write
    /// authorization, used to verify an incoming change before admitting it
    /// (see `ChangeAuthenticator`). `None` for every pre-DAG call site
    /// (tests, older daemon wiring) — a session with no authenticator can
    /// still announce heads and serve already-stored changes, but never
    /// admits an unverifiable incoming change. The change-history *store*
    /// itself is `self.state` (the same `SyncState`/SQLite the index lives
    /// in), so no separate store handle is needed.
    change_authenticator: StdMutex<Option<Arc<dyn ChangeAuthenticator>>>,
    /// Correlates outstanding `HandoffLeaseRequest`s to the oneshot
    /// `request_handoff_lease_from_peer` awaits: request_id -> reply sender.
    /// Mirrors `pending_version_present` exactly, one map per exchange since
    /// the two request ids are drawn from independent counters.
    pending_handoff_lease: StdMutex<HashMap<u64, oneshot::Sender<Option<PeerHandoffLeaseGrant>>>>,
    /// Monotonic id used to correlate a `HandoffLeaseRequest` with its reply.
    next_handoff_lease_request_id: std::sync::atomic::AtomicU64,
    /// This session's caller-injected bridge to the daemon's own
    /// coordination-plane-backed lease machinery (`DaemonState::request_
    /// handoff_lease`) — see `HandoffLeaseResponder`'s doc comment. `None`
    /// (the default for every existing test/call site, same as
    /// `pending_local_change_flush` et al. before their own setter is
    /// called) makes an incoming `HandoffLeaseRequest` answer `granted =
    /// false` rather than panic or hang.
    handoff_lease_responder: StdMutex<Option<Arc<dyn HandoffLeaseResponder>>>,
    /// Correlates outstanding `RebootstrapSnapshotRequest`s to the oneshot
    /// `request_rebootstrap_snapshot_from_peer` awaits: request_id ->
    /// reply sender. Mirrors `pending_handoff_lease` exactly.
    pending_rebootstrap_snapshot:
        StdMutex<HashMap<u64, oneshot::Sender<Option<PreparedRebootstrap>>>>,
    /// Monotonic id used to correlate a `RebootstrapSnapshotRequest` with
    /// its reply.
    next_rebootstrap_snapshot_request_id: std::sync::atomic::AtomicU64,
    /// This session's caller-injected bridge to the daemon's own signing
    /// identity and pinned-key trust resolver — see `RebootstrapHandler`'s
    /// doc comment. `None` (the default for every existing test/call site)
    /// makes an incoming `RebootstrapSnapshotRequest` answer `granted =
    /// false` rather than panic or hang.
    rebootstrap_handler: StdMutex<Option<Arc<dyn RebootstrapHandler>>>,
    block_write_activity_provider: StdMutex<Option<Arc<dyn BlockWriteActivityProvider>>>,
    /// Correlates outstanding `HandoffTicketRequest`s to the oneshot
    /// `request_handoff_ticket_from_peer` awaits: request_id -> reply
    /// sender. Mirrors `pending_handoff_lease` exactly, one map per
    /// exchange since the two request ids are drawn from independent
    /// counters.
    pending_handoff_ticket: StdMutex<HashMap<u64, oneshot::Sender<Option<PeerHandoffTicketGrant>>>>,
    /// Monotonic id used to correlate a `HandoffTicketRequest` with its
    /// reply.
    next_handoff_ticket_request_id: std::sync::atomic::AtomicU64,
    /// This session's caller-injected bridge to the daemon's own
    /// removed-device-ticket machinery (`DaemonState::obtain_own_handoff_
    /// ticket`) -- see `HandoffTicketResponder`'s doc comment. `None` (the
    /// default for every existing test/call site, same as
    /// `handoff_lease_responder` before its own setter is called) makes an
    /// incoming `HandoffTicketRequest` answer `granted = false` rather than
    /// panic or hang.
    handoff_ticket_responder: StdMutex<Option<Arc<dyn HandoffTicketResponder>>>,
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
        )
    }

    /// Like `new`, but forwards every record this session adopts or
    /// resolves from its peer to `forward_tx` as `(group_id, record)` (see
    /// `forward_tx`'s doc comment).
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
    ) -> Arc<Self> {
        // best-effort pre-canonicalize each sync root once —
        // see `canonical_sync_roots`'s doc comment. A group whose root
        // can't be canonicalized right now (rare — a missing
        // parent, a permissions issue) is simply left out of the cache;
        // it is resolved fresh on the next call for that group rather
        // than risking a stale/incorrect cached value.
        //
        // Deliberately does NOT create the root. An existing link's root
        // is the user's folder: it was created when the link was made, so
        // finding it missing here means something is wrong (most often an
        // external volume whose mountpoint is gone), not that setup is
        // owed. Creating it would rebuild the user's folder as an empty
        // directory on the internal disk, which makes a broken link look
        // healthy, hides the real fault from the status surface, and lets
        // peer content start filling the boot volume in place of the
        // detached one. Leaving the path absent lets the failure be seen
        // and reported as what it is.
        let canonical_sync_roots = StdMutex::new(
            sync_roots
                .iter()
                .filter_map(|(group_id, root)| {
                    let canonical = std::fs::canonicalize(root).ok()?;
                    Some((group_id.clone(), (root.clone(), canonical)))
                })
                .collect(),
        );
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
        Arc::new(Self {
            channel,
            local_device_id,
            peer_device_id,
            state,
            store,
            shared_group_ids,
            live_authorized_groups,
            peer_supports_reliable_delivery: std::sync::atomic::AtomicBool::new(false),
            peer_supports_version_present: std::sync::atomic::AtomicBool::new(false),
            peer_supports_version_hash_exact: std::sync::atomic::AtomicBool::new(false),
            peer_handshake_received: std::sync::atomic::AtomicBool::new(false),
            handshake_notify: tokio::sync::Notify::new(),
            peer_acked_my_cluster_config: std::sync::atomic::AtomicBool::new(false),
            canonical_sync_roots,
            ignore_sets,
            pending_block_requests: StdMutex::new(HashMap::new()),
            pending_version_present: StdMutex::new(HashMap::new()),
            next_present_request_id: std::sync::atomic::AtomicU64::new(1),
            forward_tx,
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
            peer_supports_change_dag: std::sync::atomic::AtomicBool::new(false),
            change_authenticator: StdMutex::new(None),
            pending_handoff_lease: StdMutex::new(HashMap::new()),
            next_handoff_lease_request_id: std::sync::atomic::AtomicU64::new(1),
            handoff_lease_responder: StdMutex::new(None),
            pending_rebootstrap_snapshot: StdMutex::new(HashMap::new()),
            next_rebootstrap_snapshot_request_id: std::sync::atomic::AtomicU64::new(1),
            rebootstrap_handler: StdMutex::new(None),
            block_write_activity_provider: StdMutex::new(None),
            pending_handoff_ticket: StdMutex::new(HashMap::new()),
            next_handoff_ticket_request_id: std::sync::atomic::AtomicU64::new(1),
            handoff_ticket_responder: StdMutex::new(None),
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
        // No root for this group means nothing of ours is on disk to collide
        // with, so there is no case-fold sibling to flush.
        let Ok(root) = self.sync_root(group_id) else {
            return;
        };
        if !hazard::is_case_insensitive_filesystem(&root) {
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
    /// way `shares_group` is public for its own live
    /// per-session state.
    pub fn compression_negotiated(&self) -> bool {
        self.peer_supports_compression.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this peer's advertised
    /// `supports_reliable_delivery` from its handshake `ClusterConfig` —
    /// mirrors `record_peer_compression_support`'s pattern. This build
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
    /// `compression_negotiated`.
    pub fn reliable_delivery_negotiated(&self) -> bool {
        self.peer_supports_reliable_delivery.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this peer's advertised `supports_version_present` from its
    /// handshake `ClusterConfig` — mirrors `record_peer_reliable_delivery_
    /// support`'s pattern, minus that method's side effect (there is no
    /// local channel state to flip here, just the flag itself). This build
    /// always supports the query on the answering side, so confirming the
    /// peer does too is the whole negotiation.
    fn record_peer_version_present_support(&self, supported: bool) {
        if supported {
            self.peer_supports_version_present.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether this peer has advertised support for the `VersionPresentQuery`/
    /// `VersionPresentAck` exchange. Public so callers can skip a
    /// non-supporting peer before ever sending a query — see
    /// `peer_supports_version_present`'s doc comment for why skipping,
    /// rather than querying and waiting out the timeout, is required for a
    /// peer that hasn't advertised this.
    pub fn version_present_negotiated(&self) -> bool {
        self.peer_supports_version_present.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records this peer's advertised `supports_version_hash_exact` from its
    /// handshake `ClusterConfig` — mirrors `record_peer_version_present_
    /// support`'s pattern. This build always enforces the exact-hash check
    /// on the answering side (`holds_version_durably`), so confirming the
    /// peer does too is the whole negotiation.
    fn record_peer_version_hash_exact_support(&self, supported: bool) {
        if supported {
            self.peer_supports_version_hash_exact.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether this peer has advertised that its `VersionPresentQuery`
    /// responder enforces an exact `change::VersionHash` match, not just a
    /// `block_hashes`/`block_sizes` match. Public so the whole-group
    /// durability-handoff querier (`yadorilink_daemon::daemon_state::
    /// peer_holds_entire_group`) can skip a peer that hasn't advertised this
    /// — see `peer_supports_version_hash_exact`'s doc comment for why
    /// sending it a `for_handoff = true` query anyway would risk trusting a
    /// block-hash coincidence as exact-version proof.
    pub fn version_hash_exact_negotiated(&self) -> bool {
        self.peer_supports_version_hash_exact.load(std::sync::atomic::Ordering::Relaxed)
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

    /// attempts to admit `block_count` more blocks to eager
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
                // This build always understands the change-history wire
                // shapes and carries the store (`self.state`), so it always
                // advertises support — mirrors the compression
                // advertisement above. The peer's own `supports_change_dag`
                // (recorded in `handle_message`'s `ClusterConfig` arm) is the
                // other half of the both-sides-advertise negotiation.
                supports_change_dag: true,
                // This build always implements the
                // `VersionPresentQuery`/`VersionPresentAck` custody-confirmation
                // exchange, so it always advertises that too — see
                // `peer_supports_version_present`'s doc comment for why an old
                // peer that never sets this must be skipped rather than
                // queried.
                supports_version_present: true,
                // This build's `VersionPresentQuery` responder
                // (`holds_version_durably`) always enforces an exact
                // `change::VersionHash` match, so it always advertises that
                // too — a strictly narrower claim than `supports_version_
                // present` above (see `peer_supports_version_hash_exact`'s
                // doc comment for why a peer lacking this must be skipped
                // for whole-group durability-handoff queries rather than
                // queried and its block-hash-only answer trusted as
                // exact-version proof).
                supports_version_hash_exact: true,
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
                    // this loop is waiting for), so `notified` resolving
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

    /// Runs the session: sends the initial handshake, then dispatches
    /// incoming messages until the channel closes. Intended to run for the
    /// session's whole lifetime as a background task.
    ///
    /// Startup propagation is not driven from here: the session-start heads
    /// exchange fires from the `ClusterConfig` receive arm, once negotiation
    /// has actually confirmed the peer speaks the DAG. Announcing from here
    /// instead would race that handshake — this device's own `ClusterConfig`
    /// is sent, not acknowledged, by the time this function continues.
    pub async fn run(self: Arc<Self>) -> Result<(), SyncError> {
        self.send(self.cluster_config_message()).await?;
        // The above is
        // this device's *first* handshake attempt, sent synchronously.
        // `spawn_cluster_config_retry` covers *retries* only, entirely in
        // the background, so a peer that's slow or never sends its own
        // `ClusterConfig` back (a bare test double with no reciprocal
        // `run`, or a genuinely unreachable peer) does not hold up this
        // function's own startup.
        let handshake_retry_handle = self.spawn_cluster_config_retry();

        // An independent task, not
        // another branch of this function's own recv loop. This is
        // deliberate, not just a style choice: the whole reason a resync is
        // needed is that this session's recv loop can itself be stuck (see
        // `reconcile_one_file`'s `eager_admitted` branch doc comment) for
        // the entire span between one incoming message and the next, well
        // past when a resync should fire. Folding the timer into a
        // `select!` alongside `self.channel.recv` below would not help —
        // once a `select!` iteration picks the recv branch, this whole
        // function's body (including the blocking `acquire_owned.await`
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
        // map) drops, `upgrade` starts failing and this task exits on
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
                        // whoever built this session), but an audit fires
                        // much later in the session's life, when
                        // `live_authorized_groups` may have since diverged
                        // from that snapshot (`shares_group`'s doc
                        // comment).
                        if !session.shares_group(group_id) {
                            continue;
                        }
                        // A periodic *frontier audit*: re-announcing heads is
                        // enough to re-discover and re-reconcile any path
                        // whose earlier reconciliation was dropped or missed
                        // (e.g. under a transient in-flight-bound
                        // saturation), at a cost proportional to the
                        // divergence rather than resending the whole index.
                        //
                        // Gated on negotiation for the same reason the
                        // session-start announce is (see the `ClusterConfig`
                        // receive arm): `send_heads_announce` itself sends
                        // unconditionally, so without this check the audit
                        // would speculatively announce at a peer that has not
                        // advertised the DAG. Such a peer is instead served
                        // by the `ClusterConfig` re-offer above, which keeps
                        // retrying negotiation for the session's whole life.
                        if !session.change_dag_negotiated() {
                            continue;
                        }
                        if let Err(e) = session.send_heads_announce(group_id).await {
                            tracing::warn!(
                                group_id,
                                peer = %session.peer_device_id,
                                error = %e,
                                "periodic reconcile audit failed to send"
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
        // see below) it blocked the *entire loop* on `acquire_owned.await`
        // before ever calling `self.channel.recv` again — so a
        // `BlockResponse` sitting right behind it on the wire, which is
        // exactly what would free a permit and break the stall, could never
        // even be read, let alone processed. `ensure_blocks_present`'s own
        // doc comment predicted this exact failure mode and suggested this
        // exact fix (a separate intake path so the recv loop is never
        // head-of-line-blocked behind its own eager fetches).
        //
        // This queue is byte-capped without ever blocking its producer. On
        // exhaustion the hostile/overloaded session is terminated; the
        // BlockResponse control lane above never enters this queue, so it can
        // still free permits up to the instant the session is rejected. The concurrency bound
        // that actually matters — at most `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
        // `handle_message` calls ever running at once — is unchanged; this
        // queue only ever holds cheap, already-decoded `SyncMessage`s
        // waiting their turn, never a running task or a held permit.
        // Unbounded growth under a deliberately hostile flood is a
        // different, pre-existing concern already owned by other layers
        // (per-message size caps, rate limiting, resource governance)
        // — this change's job is only to make permit exhaustion transient
        // instead of a permanent deadlock, not to re-derive those bounds.
        let mut pending: VecDeque<(proto::SyncMessage, usize)> = VecDeque::new();
        let mut pending_bytes = 0usize;
        loop {
            tokio::select! {
                maybe_bytes = self.channel.recv() => {
                    let Some(bytes) = maybe_bytes else { break };
                    let wire_len = bytes.len();
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
                            let Some(next_bytes) = pending_bytes.checked_add(wire_len) else {
                                tracing::warn!(peer = %self.peer_device_id, "peer intake byte accounting overflow; closing session");
                                break;
                            };
                            if next_bytes > MAX_PENDING_MESSAGE_BYTES_PER_PEER {
                                tracing::warn!(
                                    peer = %self.peer_device_id,
                                    queued_bytes = pending_bytes,
                                    incoming_bytes = wire_len,
                                    limit = MAX_PENDING_MESSAGE_BYTES_PER_PEER,
                                    "peer exceeded pending-message byte budget; closing session"
                                );
                                break;
                            }
                            pending_bytes = next_bytes;
                            pending.push_back((proto::SyncMessage { payload }, wire_len));
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
                // bounds concurrently-spawned message-handler tasks
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
                    let (msg, wire_len) = pending
                        .pop_front()
                        .expect("guarded by `if !pending.is_empty()` above");
                    pending_bytes = pending_bytes.saturating_sub(wire_len);
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
        // reasoning as `resync_handle.abort` immediately above -- a
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
    /// *sending* side: `FileRecord::into` alone can't populate
    /// `proto::FileInfo`'s `record_kind`/`symlink_target`/
    /// `symlink_out_of_root_or_absolute`/`exec_bit` fields (see
    /// `types.rs`'s `From<FileRecord>` doc comment — it structurally has
    /// no `SyncState` access), so this builds the base conversion via
    /// `.into` and then overwrites those four fields from a direct
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

    /// Whether `group_id` is one this session's peer is *currently*
    /// authorized (per the coordination plane's ACL) to sync with us.
    ///
    /// sync-engine spec "Block Requests Are Authorized Against Actual Group
    /// Membership":
    /// reads `live_authorized_groups`, not the `shared_group_ids` snapshot
    /// captured once at session construction — every caller of this method
    /// (`handle_block_request`, `reconcile_files_if_authorized`) already
    /// calls it fresh on every single
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

    pub async fn replace_coordination_candidates(&self, candidates: Vec<std::net::SocketAddr>) {
        self.channel.replace_coordination_candidates(candidates).await;
    }

    /// takes an owned `Arc<Self>` (not `&self`) — the previous
    /// `&self` receiver only ever needed to live as long as this call, but
    /// `reconcile_files`'s bounded-concurrent processing (below) needs to
    /// clone a session handle into each spawned task, which requires an
    /// owned `Arc` to clone from in the first place. Every caller of this
    /// already has an `Arc<Self>` in hand (`run`'s recv loop clones one per
    /// spawned message-handler task anyway), so this is a free change at
    /// every call site.
    /// Installs the supplier of pinned signing keys + write authorization
    /// this session uses to verify incoming changes, the same
    /// mutable-after-construction way `set_rate_limiters` installs the
    /// shared token buckets. Every pre-DAG call site that never sets one
    /// keeps working: it just never admits an unverifiable incoming change.
    pub fn set_change_authenticator(&self, authenticator: Arc<dyn ChangeAuthenticator>) {
        *self.change_authenticator.lock().unwrap_or_else(|p| p.into_inner()) = Some(authenticator);
    }

    fn change_authenticator(&self) -> Option<Arc<dyn ChangeAuthenticator>> {
        self.change_authenticator.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Injects this session's real bridge to the daemon's coordination-
    /// plane-backed handoff-lease machinery — see `HandoffLeaseResponder`'s
    /// doc comment. Mirrors `set_pending_local_change_flush`'s "daemon
    /// injects real behavior after construction" pattern exactly. Every
    /// existing test/call site that never calls this keeps working: an
    /// incoming `HandoffLeaseRequest` simply answers `granted = false`.
    pub fn set_handoff_lease_responder(&self, responder: Arc<dyn HandoffLeaseResponder>) {
        *self.handoff_lease_responder.lock().unwrap_or_else(|p| p.into_inner()) = Some(responder);
    }

    fn handoff_lease_responder(&self) -> Option<Arc<dyn HandoffLeaseResponder>> {
        self.handoff_lease_responder.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Injects this session's real bridge to the daemon's own signing
    /// identity and pinned-key trust resolver — see `RebootstrapHandler`'s
    /// doc comment. Mirrors `set_handoff_lease_responder`'s pattern exactly.
    /// Every existing test/call site that never calls this keeps working: an
    /// incoming `RebootstrapSnapshotRequest` simply answers `granted = false`.
    pub fn set_rebootstrap_handler(&self, handler: Arc<dyn RebootstrapHandler>) {
        *self.rebootstrap_handler.lock().unwrap_or_else(|p| p.into_inner()) = Some(handler);
    }

    fn rebootstrap_handler(&self) -> Option<Arc<dyn RebootstrapHandler>> {
        self.rebootstrap_handler.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn set_block_write_activity_provider(&self, provider: Arc<dyn BlockWriteActivityProvider>) {
        *self.block_write_activity_provider.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(provider);
    }

    fn block_write_activity_provider(&self) -> Option<Arc<dyn BlockWriteActivityProvider>> {
        self.block_write_activity_provider.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Injects this session's real bridge to the daemon's removed-device-
    /// ticket machinery — see `HandoffTicketResponder`'s doc comment. Mirrors
    /// `set_handoff_lease_responder`'s "daemon injects real behavior after
    /// construction" pattern exactly. Every existing test/call site that
    /// never calls this keeps working: an incoming `HandoffTicketRequest`
    /// simply answers `granted = false`.
    pub fn set_handoff_ticket_responder(&self, responder: Arc<dyn HandoffTicketResponder>) {
        *self.handoff_ticket_responder.lock().unwrap_or_else(|p| p.into_inner()) = Some(responder);
    }

    fn handoff_ticket_responder(&self) -> Option<Arc<dyn HandoffTicketResponder>> {
        self.handoff_ticket_responder.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Records this peer's advertised `supports_change_dag` from its
    /// handshake `ClusterConfig` — mirrors `record_peer_compression_
    /// support`'s pattern. An old peer, or one that doesn't set the field,
    /// leaves this `false` for the session's whole lifetime.
    fn record_peer_change_dag_support(&self, supported: bool) {
        if supported {
            self.peer_supports_change_dag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Whether this session reconciles via the change-history DAG rather
    /// through the change-history DAG: this build always speaks it and carries
    /// the store (`self.state`), so this reduces to "has the peer
    /// advertised support too." Public so tests and callers can observe
    /// negotiation directly, mirroring `compression_negotiated`.
    pub fn change_dag_negotiated(&self) -> bool {
        self.peer_supports_change_dag.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True once the peer has sent any cluster configuration. Combined with
    /// `change_dag_negotiated`, this distinguishes "negotiation pending" from
    /// a completed handshake with an incompatible pre-DAG peer.
    pub fn peer_handshake_received(&self) -> bool {
        self.peer_handshake_received.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Announces this device's current DAG heads for `group_id` to the
    /// peer, the message that makes catch-up cost proportional to the
    /// divergence (the receiver diffs these against its own store and asks
    /// only for what it is missing).
    async fn send_heads_announce(&self, group_id: &str) -> Result<(), SyncError> {
        let heads = self.state.dag_group_heads(group_id)?;
        // This device's own acknowledged frontier head, so the receiver can
        // advance its record of what this device holds (compaction
        // bookkeeping). Empty when none is recorded yet.
        let frontier_hint =
            match self.state.dag_get_device_frontier(group_id, &self.local_device_id)? {
                Some(h) => change_hash_to_wire(&h),
                None => Vec::new(),
            };
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HeadsAnnounce(proto::HeadsAnnounce {
                folder_group_id: group_id.to_string(),
                heads: heads.iter().map(change_hash_to_wire).collect(),
                frontier_hint,
            })),
        })
        .await
    }

    /// Records this device's own current heads as its acknowledged frontier
    /// for the group. Nothing else advances the local frontier, yet
    /// `send_heads_announce` reads it back as the `frontier_hint` and history
    /// compaction needs it to know what this device provably holds — so this
    /// is called whenever the local head set advances (a local commit, or
    /// applying a peer's changes).
    fn record_local_frontier(&self, group_id: &str) -> Result<(), SyncError> {
        let heads = self.state.dag_group_heads(group_id)?;
        compaction::record_acknowledged_frontier(
            &*self.state,
            &FolderGroupId::from(group_id),
            &DeviceId::from(self.local_device_id.as_str()),
            &heads,
        )
    }

    /// Called by the local-change pipeline after a committed local edit
    /// (the change-history analogue of the daemon's `send_index_update`
    /// fan-out): re-announces heads so the peer learns about the new change
    /// immediately rather than waiting for the next periodic audit. Only
    /// announces to a peer this session has negotiated the DAG with; a
    /// legacy peer is still served by the daemon's ordinary
    /// `send_index_update`.
    pub async fn announce_local_commit(&self, group_id: &str) -> Result<(), SyncError> {
        if !self.change_dag_negotiated() || !self.shares_group(group_id) {
            return Ok(());
        }
        // The commit advanced this device's own heads — record its frontier
        // before announcing so the hint it sends is current.
        if let Err(e) = self.record_local_frontier(group_id) {
            tracing::warn!(group_id, error = %e, "failed to record local frontier before announce");
        }
        self.send_heads_announce(group_id).await
    }

    /// A peer announced its heads for `group_id`. Diff them against the
    /// local store and request the ancestry closure this device is missing.
    /// Authorization is checked exactly like every other inbound
    /// group-scoped message (`shares_group`) — a heads announce for a group
    /// this session isn't currently authorized for is dropped.
    async fn handle_heads_announce(&self, announce: proto::HeadsAnnounce) -> Result<(), SyncError> {
        let group_id = announce.folder_group_id;
        if !self.shares_group(&group_id) {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring heads announce for unauthorized/unshared folder group"
            );
            return Ok(());
        }
        let announced: Vec<ChangeHash> =
            announce.heads.iter().filter_map(|b| change_hash_from_wire(b)).collect();
        // The peer's announced heads are its acknowledged frontier for the
        // group — record the full set (not just the single frontier_hint) so
        // history compaction sees every concurrent head and can prune as much
        // as is provably safe.
        if let Err(e) = compaction::record_acknowledged_frontier(
            &*self.state,
            &FolderGroupId::from(group_id.as_str()),
            &DeviceId::from(self.peer_device_id.as_str()),
            &announced,
        ) {
            tracing::warn!(group_id, peer = %self.peer_device_id, error = %e, "failed to record peer frontier");
        }
        let mut missing: Vec<ChangeHash> = Vec::new();
        for h in &announced {
            if !self.state.dag_has_change(h)? {
                missing.push(*h);
            }
        }
        if missing.is_empty() {
            // Already-known heads: nothing to fetch in this direction
            // (spec's "already-known changes are not re-fetched").
            return Ok(());
        }
        self.request_changes(&group_id, &missing).await
    }

    /// Periodic DAG resync's local repair backstop. A heads announce keeps
    /// network catch-up proportional to divergence, but it carries no file
    /// metadata when both sides already know the same heads. Re-run the
    /// ordinary reconcile path only for locally tracked repair candidates so
    /// eager live records demoted to placeholders/hydrating still rehydrate
    /// without making every peer session scan and re-query the whole group.
    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<(), SyncError> {
        // This audit re-drives materialization, so it needs the same
        // fail-closed link gate the incoming-batch path uses: for an unlinked
        // group there is no folder to repair towards, and re-projecting into
        // one would be exactly the write the unlink was meant to stop.
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(());
        }
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(());
        };

        // Restart/backstop half of the projection-durability guarantee: re-drive
        // any change still marked unapplied (a crash between admission and
        // projection, or a projection that failed on a transient disk/block
        // fault) so it makes forward progress without waiting to be re-delivered.
        if let Err(e) = self.reproject_unapplied_changes(group_id).await {
            tracing::warn!(group_id, error = %e, "failed to re-project unapplied changes during audit");
        }

        let paths = self.state.list_materialization_repair_candidates(group_id)?;
        if paths.is_empty() {
            return Ok(());
        }

        let files = self.state.get_files_by_paths(group_id, &paths)?;
        let mut file_infos = Vec::with_capacity(files.len());
        for record in files.into_values() {
            if record.deleted {
                continue;
            }
            file_infos.push(self.file_info_for_record(group_id, record)?);
        }
        if file_infos.is_empty() {
            return Ok(());
        }
        self.rematerialize_local_records(group_id, file_infos).await
    }

    /// Re-projects every admitted-but-not-yet-applied change for `group_id` —
    /// the restart/backstop half of the projection-durability guarantee. A
    /// change is left `applied = 0` whenever its path projection has not
    /// succeeded (a crash between admission and projection, or a projection
    /// attempt that failed on a transient disk-full / missing-block / I/O
    /// fault). This lists those changes, re-runs their paths through the same
    /// conflict-copy-aware fold `handle_change_batch` uses, and marks each
    /// applied once its own paths land. The `applied` flag is the durable,
    /// restart-surviving retry state, so no separate job table is needed.
    /// Idempotent and cheap when nothing is pending.
    pub async fn reproject_unapplied_changes(&self, group_id: &str) -> Result<(), SyncError> {
        let unapplied = self.state.dag_list_unapplied_changes(group_id)?;
        if unapplied.is_empty() {
            return Ok(());
        }
        tracing::info!(
            group_id,
            count = unapplied.len(),
            "re-projecting admitted-but-unapplied changes"
        );
        let mut per_change: Vec<(ChangeHash, std::collections::BTreeSet<String>)> = Vec::new();
        let mut all_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for change in &unapplied {
            let mut change_paths = std::collections::BTreeSet::new();
            for op in &change.ops {
                collect_op_paths(op, &mut all_paths);
                collect_op_paths(op, &mut change_paths);
            }
            per_change.push((change.compute_hash(), change_paths));
        }
        let failed = self.reconcile_group_paths(group_id, all_paths).await?;
        for (hash, change_paths) in &per_change {
            if change_projection_succeeded(change_paths, &failed) {
                if let Err(e) = self.state.dag_mark_applied(hash) {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "failed to mark a re-projected change applied"
                    );
                }
            }
        }
        Ok(())
    }

    /// Serves the changes a peer asked for out of the local store. This is
    /// the store-and-forward serving path: a change is served purely
    /// because it is present in the store, with **no special casing on
    /// which device originated it** — so a change A produced is served to C
    /// by B exactly as if B had produced it, which is what lets C converge
    /// without ever connecting to A. The stored bytes are relayed verbatim,
    /// carrying the original signature, so the receiver re-verifies them
    /// exactly as if they came straight from the origin.
    async fn handle_change_request(&self, req: proto::ChangeRequest) -> Result<(), SyncError> {
        let group_id = req.folder_group_id;
        if !self.shares_group(&group_id) {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring change request for unauthorized/unshared folder group"
            );
            return Ok(());
        }
        // Serve in bounded batches: a want-list larger than one batch is
        // split across several `ChangeBatch` messages, each capped at
        // `MAX_CHANGES_PER_BATCH`, so no single reply can be made
        // unboundedly large.
        let mut batch: Vec<Vec<u8>> = Vec::new();
        for want in &req.want {
            let Some(hash) = change_hash_from_wire(want) else { continue };
            if let Some(encoded) = self.state.dag_get_encoded(&hash)? {
                batch.push(encoded);
                if batch.len() >= MAX_CHANGES_PER_BATCH {
                    let taken = std::mem::take(&mut batch);
                    let versions = self.file_versions_for_changes(&taken)?;
                    self.send_change_batch(&group_id, taken, versions).await?;
                }
            }
        }
        if !batch.is_empty() {
            let versions = self.file_versions_for_changes(&batch)?;
            self.send_change_batch(&group_id, batch, versions).await?;
        }
        Ok(())
    }

    /// Gathers the canonical encodings of every file version referenced by
    /// `encoded_changes`' content ops, deduplicated. A create/update/move op
    /// names a version only by hash; these are the version bytes a receiver
    /// needs to materialize the surviving content, so they ride in the same
    /// batch as the changes that reference them. A version this device does
    /// not hold is simply omitted — the change still transfers, and the
    /// receiver holds it until a batch carries the version too.
    fn file_versions_for_changes(
        &self,
        encoded_changes: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, SyncError> {
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        for encoded in encoded_changes {
            let Ok(change) = Change::from_wire_bytes(encoded) else { continue };
            for op in &change.ops {
                let Some(version_hash) = op_version_hash(op) else { continue };
                if !seen.insert(version_hash.0) {
                    continue;
                }
                if let Some(version) =
                    self.state.dag_get_file_version(change.group_id.as_str(), &version_hash)?
                {
                    out.push(version.canonical_encoding());
                }
            }
        }
        Ok(out)
    }

    async fn send_change_batch(
        &self,
        group_id: &str,
        changes: Vec<Vec<u8>>,
        file_versions: Vec<Vec<u8>>,
    ) -> Result<(), SyncError> {
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ChangeBatch(proto::ChangeBatch {
                folder_group_id: group_id.to_string(),
                changes,
                // Changes are sent uncompressed for now; the wire format
                // reserves `compressed_changes` for a later pass that reuses
                // the existing zstd negotiation, exactly as the index path
                // does. An old-format-agnostic receiver reads `changes`
                // directly whenever `compression == NONE`.
                compression: proto::Compression::None as i32,
                compressed_changes: Vec::new(),
                file_versions,
            })),
        })
        .await
    }

    async fn request_changes(&self, group_id: &str, want: &[ChangeHash]) -> Result<(), SyncError> {
        if want.is_empty() {
            return Ok(());
        }
        // Chunk the want-list so a single request message is bounded the
        // same way a served batch is.
        for chunk in want.chunks(MAX_CHANGES_PER_BATCH) {
            self.send(proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::ChangeRequest(proto::ChangeRequest {
                    folder_group_id: group_id.to_string(),
                    want: chunk.iter().map(change_hash_to_wire).collect(),
                })),
            })
            .await?;
        }
        Ok(())
    }

    /// Applies a batch of changes received from the peer. Every change is
    /// verified and appended through the store (which rejects a change
    /// whose hash or signature doesn't check, or whose author isn't
    /// authorized for the group — an invalid change never enters the store
    /// and so can never be forwarded onward). A change whose parents aren't
    /// all present yet is held in the store's bounded orphanage and its
    /// missing parents are requested, so the ancestry walk completes
    /// oldest-first over as many rounds as the divergence needs.
    ///
    /// The same live authorization and link-state gates apply here: an
    /// unauthorized or revoked peer cannot push changes into the group, and
    /// a paused link neither applies nor forwards.
    async fn handle_change_batch(&self, batch: proto::ChangeBatch) -> Result<(), SyncError> {
        let group_id = batch.folder_group_id;
        if !self.shares_group(&group_id) {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring change batch for unauthorized/unshared folder group"
            );
            return Ok(());
        }
        // The link-table gate, consulted once for the batch.
        if !self.may_apply_incoming_change(&group_id, "change batch")? {
            return Ok(());
        }
        // Wait for this group's startup reconciliation to finish before applying
        // any peer change. The startup disk scan reads an old whole-index
        // snapshot and batch-commits records derived from it without holding
        // per-path locks; admitting a peer change for the same path in that
        // window would let the scan's later stale-snapshot commit clobber it,
        // turning a concurrent conflict into a last-writer overwrite. The wait
        // holds no path lock, is per-group (an unrelated ready group is never
        // blocked), and is a no-op once startup has completed.
        if let Err(failed) = self.state.wait_group_ready(&group_id).await {
            // Fail-closed: the group's startup did not complete, so the index
            // may be half-built (un-indexed files, an un-redriven dirty
            // journal). Do NOT admit this batch over it — defer, leaving the
            // changes unapplied so they are re-delivered once a fresh startup
            // succeeds (peers re-send, and the periodic frontier audit
            // re-discovers any remaining gap). This preserves local state
            // rather than risking a stale-snapshot overwrite of it.
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                reason = %failed.reason,
                "deferring peer change batch: group startup has not completed successfully"
            );
            return Ok(());
        }
        if batch.changes.len() > MAX_CHANGES_PER_BATCH {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                change_count = batch.changes.len(),
                "rejecting change batch exceeding the per-message cap"
            );
            return Ok(());
        }
        // Compression for the change stream is a reserved-but-not-yet-used
        // wire feature (see `send_change_batch`); a batch that arrives
        // compressed from some future peer is skipped rather than
        // mis-applied, and re-discovered by the periodic frontier audit.
        if batch.changes.is_empty() && !batch.compressed_changes.is_empty() {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring compressed change batch; change-stream compression not yet supported"
            );
            return Ok(());
        }
        // Without a pinned-key/authorization supplier this session cannot
        // verify a change, and an unverified change must never enter the
        // store, so the whole batch is held for a later session once keys
        // are pinned (the periodic audit re-requests). This is the trust
        // rule that DAG sync with a device is unavailable until its signing
        // key is pinned.
        let Some(auth) = self.change_authenticator() else {
            tracing::debug!(
                group_id,
                peer = %self.peer_device_id,
                "no change authenticator wired; cannot verify incoming changes yet"
            );
            return Ok(());
        };

        // Decode versions into an untrusted, in-memory staging map. Nothing is
        // persisted until a signed, authorized change in this batch actually
        // references the hash. This prevents an unauthenticated envelope from
        // poisoning another group's version namespace or disclosing its blocks.
        let mut staged_versions = std::collections::BTreeMap::new();
        for encoded in &batch.file_versions {
            let version = match FileVersion::from_canonical_encoding(encoded) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        peer = %self.peer_device_id,
                        error = %e,
                        "ignoring undecodable file version in batch"
                    );
                    continue;
                }
            };
            staged_versions.insert(version.version_hash, version);
        }

        let mut missing_parents: Vec<ChangeHash> = Vec::new();
        let mut affected_paths: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        // Each newly-applied change paired with the concrete paths its own ops
        // touch. A change is only marked `applied` once *every* one of those
        // paths (and any conflict copy derived from them) has actually
        // projected — see the gating after `reconcile_group_paths` below — so a
        // projection that WARNs on disk-full / a missing block / an I/O error
        // no longer flips the flag and defeats the unapplied-reprojection net.
        let mut admitted: Vec<(ChangeHash, std::collections::BTreeSet<String>)> = Vec::new();
        for encoded in &batch.changes {
            let change = match Change::from_wire_bytes(encoded) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        peer = %self.peer_device_id,
                        error = %e,
                        "ignoring undecodable change in batch"
                    );
                    continue;
                }
            };
            // A change naming a different group than the batch envelope is
            // dropped — authorization is per group, so a mismatched envelope
            // must never let a change ride into a group under another
            // group's authorization check.
            if change.group_id.as_str() != group_id.as_str() {
                tracing::warn!(
                    group_id,
                    peer = %self.peer_device_id,
                    "ignoring change whose group_id does not match the batch envelope"
                );
                continue;
            }
            // Verify hash + signature (against the author's pinned key) +
            // that the author is authorized to write the group, BEFORE the
            // change is ever admitted to the store. An invalid change never
            // enters the store and so can never be forwarded onward — this
            // is what makes store-and-forward through an untrusted
            // intermediary safe.
            let claimed_hash = change.change_hash();
            let Some(key_bytes) = auth.signing_key(change.device_id.as_str()) else {
                tracing::warn!(
                    group_id,
                    author = %change.device_id.as_str(),
                    peer = %self.peer_device_id,
                    "dropping change from a device with no pinned signing key"
                );
                continue;
            };
            let public_key = match crate::change::verifying_key_from_bytes(&key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(error = %e, "pinned signing key is malformed; dropping change");
                    continue;
                }
            };
            if let Err(e) =
                crate::change::verify_change(&change, &claimed_hash, &public_key, |_, _| true)
            {
                tracing::warn!(
                    group_id,
                    author = %change.device_id.as_str(),
                    peer = %self.peer_device_id,
                    error = %e,
                    "rejected an invalid change (hash/signature/authorization) — not stored"
                );
                continue;
            }
            let signing_key_fingerprint: [u8; 32] = Sha256::digest(key_bytes).into();
            if !auth.accepts_change_auth(
                change.device_id.as_str(),
                change.group_id.as_str(),
                signing_key_fingerprint,
                crate::change::ChangeAuth {
                    auth_seq: change.auth_seq,
                    auth_epoch: change.auth_epoch,
                    policy_head_hash: change.policy_head_hash,
                },
            ) {
                tracing::warn!(
                    group_id,
                    author = %change.device_id.as_str(),
                    peer = %self.peer_device_id,
                    auth_seq = change.auth_seq,
                    auth_epoch = change.auth_epoch,
                    "rejected a change whose author did not hold write authorization at the \
                     policy state it pinned at creation time"
                );
                continue;
            }
            // Causal monotonicity of the pinned authorization coordinate.
            // `accepts_change_auth` above proves the author held write
            // authority at the seq THE AUTHOR PINNED — but that seq is
            // author-chosen. A device revoked at policy seq N, still holding
            // its signing key, can craft a new change stamped with an OLDER
            // grant seq M < N (plus the epoch and policy-head hash from M),
            // sign it, and have any current member relay it: the policy replay
            // backing `accepts_change_auth` is bounded by the author's own
            // `auth_seq`, so the revoke at N > M is never consulted and the
            // change is admitted. Close that by requiring the pinned
            // coordinate to be non-decreasing along causal order — a change
            // must pin an `auth_seq`/`auth_epoch` at least as new as the
            // maximum pinned by any of its DAG parents.
            //
            // Why this is exactly right (neither too strict nor too loose):
            //  - It REJECTS the revoked-writer attack. To be causally newer
            //    than its own revoke the attacker must fork off post-revoke
            //    heads, whose parents pin seq >= N; stamping M < N then fails
            //    `M >= max(parent auth_seq)`.
            //  - It ADMITS a legitimately-delayed change from a still-valid
            //    writer. Such a change is concurrent with, or ancestral to,
            //    the revoke, so its parents also pin <= M and monotonicity
            //    holds — the delay alone never trips the check.
            //
            // IRREDUCIBLE RESIDUE: a revoked writer can still author a change
            // *concurrent with* its own revoke by forking from pre-revoke
            // heads (whose parents pin <= M). That is indistinguishable from a
            // legitimate delayed edit and is the accepted offline-authoring
            // window. Monotonicity confines the attacker to the pre-revoke
            // causal frontier: they can never author anything that causally
            // FOLLOWS a post-revoke change.
            //
            // Fail-closed and orphan-safe:
            //  - A PLACEHOLDER stamp (genuine pre-policy bootstrap, seq 0)
            //    carries no real coordinate and is exempt; a first change has
            //    no parents to violate, and once real policy exists
            //    `accepts_change_auth` already rejects a PLACEHOLDER stamp.
            //  - For a real-auth change every parent's pinned coordinate must
            //    be READABLE from the store. If a parent is absent (the change
            //    is an orphan) or its record cannot be read, the change is
            //    HELD — its missing parents are re-requested and it is
            //    re-checked once its ancestry lands — rather than admitted on
            //    trust. This is what stops the orphan-first evasion: a
            //    monotonicity-unverified change never enters the store, so it
            //    can never be silently promoted (and thus forwarded) when its
            //    post-revoke parents arrive in a later round.
            let incoming_auth = crate::change::ChangeAuth {
                auth_seq: change.auth_seq,
                auth_epoch: change.auth_epoch,
                policy_head_hash: change.policy_head_hash,
            };
            if incoming_auth != crate::change::ChangeAuth::PLACEHOLDER {
                let mut max_parent_seq = 0u64;
                let mut max_parent_epoch = 0u64;
                let mut parent_pin_unreadable = false;
                for parent in &change.parents {
                    match self.state.dag_get_change(parent) {
                        Ok(Some(parent_change)) => {
                            max_parent_seq = max_parent_seq.max(parent_change.auth_seq);
                            max_parent_epoch = max_parent_epoch.max(parent_change.auth_epoch);
                        }
                        Ok(None) | Err(_) => {
                            parent_pin_unreadable = true;
                            break;
                        }
                    }
                }
                if parent_pin_unreadable {
                    // Hold, don't admit: re-request the missing ancestry so the
                    // change is re-delivered and re-checked once every parent's
                    // pinned coordinate is readable.
                    for parent in &change.parents {
                        if !self.state.dag_has_change(parent)? {
                            missing_parents.push(*parent);
                        }
                    }
                    tracing::warn!(
                        group_id,
                        author = %change.device_id.as_str(),
                        peer = %self.peer_device_id,
                        "holding a change until all of its parents are present so its \
                         authorization pin can be checked for causal monotonicity"
                    );
                    continue;
                }
                if change.auth_seq < max_parent_seq || change.auth_epoch < max_parent_epoch {
                    tracing::warn!(
                        group_id,
                        author = %change.device_id.as_str(),
                        peer = %self.peer_device_id,
                        auth_seq = change.auth_seq,
                        auth_epoch = change.auth_epoch,
                        max_parent_auth_seq = max_parent_seq,
                        max_parent_auth_epoch = max_parent_epoch,
                        "rejected a change that pins older write authorization than one of its \
                         DAG parents — authorization pins must not decrease along causal order"
                    );
                    continue;
                }
            }
            // Gather only versions vouched for by this authenticated change.
            // They remain in memory until the DAG admission transaction below.
            let mut referenced_versions = Vec::new();
            for op in &change.ops {
                let Some(version_hash) = op_version_hash(op) else { continue };
                if let Some(version) = staged_versions.get(&version_hash) {
                    referenced_versions.push(version.clone());
                }
            }
            // A content op references its version only by hash. That version
            // must be resolvable — carried in this batch (stored just above) or
            // already held — before the change is admitted, or a later
            // reconcile could not build the surviving file record. A change
            // whose version is missing is deliberately NOT admitted: this
            // device's heads never advance to include it, so the next heads
            // exchange re-requests it, and a well-behaved sender re-sends it
            // together with the version. This is the same hold/re-request
            // discipline the orphanage gives a change missing a parent.
            //
            // A version already stored for this group or staged by this batch
            // satisfies availability. Staged bytes are committed atomically
            // with admission below; an admission failure leaves neither the
            // change nor its versions behind.
            let mut missing_version: Option<VersionHash> = None;
            for op in &change.ops {
                let Some(version_hash) = op_version_hash(op) else { continue };
                if !staged_versions.contains_key(&version_hash)
                    && !self.state.dag_has_file_version(&group_id, &version_hash)?
                {
                    missing_version = Some(version_hash);
                    break;
                }
            }
            if let Some(version_hash) = missing_version {
                tracing::warn!(
                    group_id,
                    author = %change.device_id.as_str(),
                    peer = %self.peer_device_id,
                    version = %version_hash.to_hex(),
                    "holding a change whose referenced file version is missing from the batch; \
                     it will be re-requested"
                );
                continue;
            }
            // Capture any local disk edit that predates this received change
            // before admitting the change into the DAG.  Flushing only during
            // materialization is too late: local emission would then select
            // the just-admitted remote change as a parent and turn a genuine
            // concurrent edit into a causal descendant, silently suppressing
            // the conflict copy.  Do this only after the change and every
            // referenced version have passed authentication/admission gates,
            // so an untrusted peer cannot drive arbitrary-path filesystem I/O.
            let mut incoming_paths = std::collections::BTreeSet::new();
            for op in &change.ops {
                collect_op_paths(op, &mut incoming_paths);
            }
            for path in incoming_paths {
                self.flush_pending_local_change_before_reconcile(&group_id, &path).await;
                self.flush_case_fold_sibling_before_reconcile(&group_id, &path).await;
            }
            // The change is authentic; admit it as durable-but-not-yet-
            // projected (`applied = false`). `admit_change` is idempotent and
            // holds the change in the bounded orphanage if its parents aren't
            // all present yet (auto-promoting once they arrive). The DAG is
            // the source of truth; the materialized index is a derived,
            // recomputable projection, so admit and materialize need not share
            // a transaction — a crash between them just re-projects on restart
            // from the changes still marked unapplied.
            match self.state.dag_admit_change_with_versions(&change, &referenced_versions, false) {
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        author = %change.device_id.as_str(),
                        peer = %self.peer_device_id,
                        error = %e,
                        "rejected a change at DAG admission"
                    );
                    continue;
                }
                Ok(result) => match result.outcome {
                    AdmitOutcome::Applied => {
                        // Fold the paths of EVERY change that became durable in
                        // this admission — the current change AND any orphan its
                        // arrival unblocked — into both the batch projection seed
                        // (`affected_paths`) and the applied-gating list
                        // (`admitted`). A promoted orphan touches paths the
                        // current change does not: if a child editing one path
                        // arrives first (orphaned), then its parent editing a
                        // different path arrives and promotes the child, folding
                        // only the parent's paths here would leave the child's
                        // path unmaterialized until the periodic reprojection
                        // backstop ran — a lag of up to a full audit cycle.
                        // Folding every promoted hash makes the immediate
                        // projection cover the child's path too, and gates each
                        // promoted orphan's `applied` flag on its own paths
                        // landing.
                        for hash in &result.newly_admitted {
                            // Reuse the in-hand change for the current hash; a
                            // promoted orphan's ops are fetched from the store by
                            // hash (it was just appended there).
                            let admitted_change = if *hash == claimed_hash {
                                Some(change.clone())
                            } else {
                                self.state.dag_get_change(hash)?
                            };
                            let Some(admitted_change) = admitted_change else {
                                // A change appended moments ago should be present;
                                // only a concurrent prune could remove it, and the
                                // reprojection backstop covers that gap. Skip it
                                // rather than fail the whole batch.
                                continue;
                            };
                            let mut change_paths = std::collections::BTreeSet::new();
                            for op in &admitted_change.ops {
                                collect_op_paths(op, &mut affected_paths);
                                collect_op_paths(op, &mut change_paths);
                            }
                            admitted.push((*hash, change_paths));
                        }
                    }
                    AdmitOutcome::Orphaned => {
                        // Ask the peer for the parents this change descends from
                        // that we don't yet hold, so the walk completes
                        // oldest-first over further rounds.
                        for parent in &change.parents {
                            if !self.state.dag_has_change(parent)? {
                                missing_parents.push(*parent);
                            }
                        }
                    }
                },
            }
        }

        // Project: re-materialize every path a newly-applied change touched
        // (plus the conflict-copy paths they derive) through one
        // conflict-copy-aware fixpoint fold. `reconcile_group_paths` no longer
        // aborts the whole batch on one path's write failure — it returns the
        // set of paths whose projection did NOT succeed (disk-full, missing
        // block, I/O, materialize failure) so a change is only marked applied
        // once its own paths actually landed.
        match self.reconcile_group_paths(&group_id, affected_paths).await {
            Ok(failed_paths) => {
                // Flip the applied flag *only* for a change whose every path
                // projected. A change with any failed path (or a failed
                // conflict copy derived from one of its paths) stays `applied =
                // 0`, so the unapplied-reprojection backstop re-drives it until
                // it lands — that safety net is exactly what unconditionally
                // marking applied used to defeat. Leaving it unapplied is
                // idempotent: a re-projection re-runs the same deterministic
                // fold to the same result.
                for (hash, change_paths) in &admitted {
                    if change_projection_succeeded(change_paths, &failed_paths) {
                        if let Err(e) = self.state.dag_mark_applied(hash) {
                            tracing::warn!(group_id, error = %e, "failed to mark a change applied");
                        }
                    } else {
                        tracing::warn!(
                            group_id,
                            change = %hash.to_hex(),
                            "leaving a change unapplied: one or more of its paths failed to \
                             project; the unapplied-reprojection backstop will retry it"
                        );
                    }
                }
            }
            Err(e) => {
                // A non-path-specific reconcile error (e.g. a DAG/DB read
                // failure): mark nothing applied. Every admitted change stays
                // `applied = 0` and re-projects next time — fail closed.
                tracing::warn!(
                    group_id,
                    error = %e,
                    "failed to reconcile change-history paths; leaving admitted changes \
                     unapplied for re-projection"
                );
            }
        }
        // Applying the batch advanced this device's own heads — record its
        // frontier so its next heads announce carries a current hint and
        // compaction sees what this device now holds.
        if !admitted.is_empty() {
            if let Err(e) = self.record_local_frontier(&group_id) {
                tracing::warn!(group_id, error = %e, "failed to record local frontier after apply");
            }
        }

        if !missing_parents.is_empty() {
            missing_parents.sort_unstable();
            missing_parents.dedup();
            self.request_changes(&group_id, &missing_parents).await?;
        }
        Ok(())
    }

    /// Projects a set of touched paths into the materialized index through one
    /// conflict-copy-aware fixpoint fold — the engine's counterpart to the
    /// property suite's `fold_materialize`, so the two cannot disagree on
    /// nested-overlap corners.
    ///
    /// A conflict copy is content the *losing* change materializes at a derived
    /// path; that path is first-class, so it is folded together with any change
    /// that directly touches it (with cross-supersession), and it is only
    /// (re)materialized if it survives — a delete of a conflict copy sticks, and
    /// a conflict-copy path independently edited resolves as an ordinary path.
    /// The fixpoint discovers derived copy paths (bounded: copy names embed the
    /// losing version hash), then a single pass materializes each path's result:
    /// *absent* → a deletion (the no-resurrection guarantee), *present* → the
    /// winning content head via the session's block-fetch machinery.
    async fn reconcile_group_paths(
        &self,
        group_id: &str,
        seed_paths: std::collections::BTreeSet<String>,
    ) -> Result<std::collections::BTreeSet<String>, SyncError> {
        // copy_path -> the losing content head that materializes there.
        let mut derived: std::collections::BTreeMap<String, PathHead> =
            std::collections::BTreeMap::new();
        loop {
            let mut next = derived.clone();
            let paths: std::collections::BTreeSet<String> =
                seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
            for path in &paths {
                // Derive nothing from a path this device ignores. A conflict
                // copy carries the losing head's content to a *different* name
                // (it embeds the version hash), and that derived name will not
                // generally match the pattern that excluded the original — a
                // literal `secret.log` rule does not match
                // `secret (conflict …).log`. Resolving an ignored path here
                // would therefore launder its content past the user's own
                // filter under a name they never wrote a rule for. Skipping it
                // in the fixpoint is what keeps the exclusion airtight; the
                // materialize pass below re-checks each derived name on its own
                // merits, so a copy path that is itself ignored is dropped too.
                if self.is_locally_ignored(group_id, path) {
                    continue;
                }
                let inputs = self.combined_heads(group_id, path, derived.get(path))?;
                if inputs.is_empty() {
                    continue;
                }
                if let PathResolution::Present { conflict_copies, .. } =
                    resolve_path_heads(path, &inputs)
                {
                    for cc in conflict_copies {
                        next.insert(cc.path.clone(), inputs[cc.head].clone());
                    }
                }
            }
            // `derived` only ever grows, so a stable size means a fixpoint.
            if next.len() == derived.len() {
                break;
            }
            derived = next;
        }

        let paths: std::collections::BTreeSet<String> =
            seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
        // Fail closed on the link table rather than defaulting the policy: a
        // missing row used to resolve to `Eager`, so an unlinked folder was the
        // *most* aggressive materialization target in the system.
        //
        // Report every path as unprojected rather than returning "none failed":
        // this function's result is the set the caller must NOT mark applied, so
        // an empty set here would record the batch as projected into a folder
        // that was never written to, and a later relink would never re-project
        // it.
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(paths);
        };
        // Paths whose projection did not complete. A per-path write failure
        // (disk-full, missing block, I/O, materialize error) is collected here
        // and the sweep continues, rather than `?`-aborting the whole batch:
        // the caller marks only changes whose paths all succeeded as applied,
        // and the rest re-project later. Non-path-specific errors (a DAG/DB
        // read failing) still propagate, since they are not attributable to one
        // path and mean nothing projected reliably.
        let mut failed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for path in &paths {
            // This device's own ignore patterns filter what the change DAG is
            // allowed to project onto this disk, exactly as they filtered the
            // legacy wire's incoming records (`legacy_index_convergence`'s
            // `reconcile_one_file`). Without this the DAG path — which every
            // pair of current-build peers negotiates — writes and indexes a
            // peer's file that matches this device's `.yadorilinkignore`.
            //
            // Deliberately NOT added to `failed`: `failed` means "retry this",
            // and an ignored path is a decision, not a fault. Recording it as a
            // failure would hold its change at `applied = 0` forever, so the
            // reprojection backstop would re-drive it every cycle and the
            // change would never retire. Skipping as a *success* lets the
            // change mark applied and this device's heads advance past it — so
            // the next heads exchange shows the peer we already hold it and it
            // is never re-sent. The DAG settles; the bytes just never land.
            //
            // Uniform across Present and Absent (tombstone) alike, matching the
            // legacy filter, which dropped the record before ever reading its
            // `deleted` flag: an ignored path is simply not a path this device
            // accepts peer decisions about, in either direction. A tombstone for
            // a path ignored from the start is a no-op anyway (nothing was ever
            // indexed to delete); for a path materialized *before* it became
            // ignored, declining the delete leaves the user's local copy intact,
            // which is the safe half of an unavoidable ambiguity — the ignore
            // set is device-local, so no peer can know to stop sending, and
            // honoring a remote delete against a locally-excluded path would let
            // a purely local config edit turn into remote-triggered data loss.
            // Nothing is evicted here for the same reason: an already-
            // materialized file that later becomes ignored keeps its bytes and
            // its index row (they agree — the file really is on disk), so it
            // never takes the "index row for a file the user does not have"
            // shape that gets misread as an offline delete.
            if self.is_locally_ignored(group_id, path) {
                tracing::debug!(
                    group_id,
                    path = %path,
                    peer = %self.peer_device_id,
                    "not projecting a change-DAG path matching this device's ignore patterns"
                );
                continue;
            }
            let mut inputs = self.combined_heads(group_id, path, derived.get(path))?;
            if inputs.is_empty() {
                continue;
            }
            let mut resolution = resolve_path_heads(path, &inputs);
            if matches!(resolution, PathResolution::Absent) {
                // A path resolves Absent only when every live head is a
                // tombstone (no content head survives). Before acting on that
                // as a delete, capture any local edit to this path that is
                // still sitting undispatched in this link's debounce
                // accumulator. The admission loop in `handle_change_batch`
                // flushes only the paths in the *triggering* change's own ops;
                // a path folded into this projection by a promoted orphan
                // (whose parent touched a different path) is never flushed
                // there. Left unflushed, a genuine concurrent local edit is
                // invisible to the resolution above, which then reads the path
                // as Absent and deletes it — losing the edit with no conflict
                // copy. Flush it now (before any delete and before any path
                // lock — the flush dispatches through the ordinary local-change
                // path, which takes the path lock itself, and this branch holds
                // no lock here, so there is no deadlock), then re-resolve. The
                // now-live local content head turns the resolution into
                // Present, so the file is kept instead of deleted — exactly the
                // same flush `materialize_dag_content_head` performs for the
                // Present branch, hoisted ahead of the resolution so it can
                // still flip a delete decision. (Because Absent means there was
                // no content head at all, a flushed edit adds exactly one, so
                // the re-resolution never yields a conflict copy here.)
                self.flush_pending_local_change_before_reconcile(group_id, path).await;
                self.flush_case_fold_sibling_before_reconcile(group_id, path).await;
                inputs = self.combined_heads(group_id, path, derived.get(path))?;
                if inputs.is_empty() {
                    continue;
                }
                resolution = resolve_path_heads(path, &inputs);
            }
            match resolution {
                PathResolution::Absent => {
                    // Every live head removed the path — materialize the deletion
                    // if the index still shows it live. A stale content change
                    // that is an ancestor of the tombstone never reaches the live
                    // set, so this can never resurrect a deleted file.
                    let still_live =
                        self.state.get_file(group_id, path)?.map(|r| !r.deleted).unwrap_or(false);
                    if still_live {
                        let record = FileRecord {
                            path: path.clone(),
                            size: 0,
                            mtime_unix_nanos: 0,
                            version: crate::version_vector::VersionVector::new(),
                            blocks: Vec::new(),
                            deleted: true,
                        };
                        // A DAG tombstone is a materialization operation, not
                        // merely an index update.  Going straight to
                        // `upsert_file` leaves the old bytes on disk while the
                        // index says they are deleted; route through the same
                        // removal path as legacy peer reconciliation so an I/O
                        // failure keeps the change unapplied for retry.
                        if let Err(e) =
                            self.materialize(group_id, &record, policy, &self.peer_device_id).await
                        {
                            tracing::warn!(
                                group_id,
                                path = %path,
                                error = %e,
                                "failed to project a deletion; leaving its change(s) unapplied"
                            );
                            failed.insert(path.clone());
                        }
                    }
                }
                PathResolution::Present { winner, .. } => {
                    if let Err(e) = self
                        .materialize_dag_content_head(group_id, path, &inputs[winner], policy)
                        .await
                    {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            error = %e,
                            "failed to project a path; leaving its change(s) unapplied for retry"
                        );
                        failed.insert(path.clone());
                    }
                }
            }
        }
        Ok(failed)
    }

    /// The combined live heads for one path: the changes that directly touch
    /// it (each reduced to its op effect at the path) plus an optional derived
    /// content head — the content a losing change of some other path
    /// materializes at this conflict-copy path. Cross-supersession runs across
    /// the whole set, so a direct change that descends from the derived losing
    /// head supersedes it (a delete of a conflict copy removes it), and a
    /// derived head that descends from a direct head supersedes that one.
    fn combined_heads(
        &self,
        group_id: &str,
        path: &str,
        derived_head: Option<&PathHead>,
    ) -> Result<Vec<PathHead>, SyncError> {
        let direct = self.store_live_heads_for_path(group_id, path)?;
        // (change hash, head) for every candidate — direct heads plus the
        // optional derived head.
        let mut cands: Vec<([u8; 32], PathHead)> = Vec::new();
        for c in &direct {
            if let Some(h) = path_head_from_change(c, path) {
                cands.push((c.change_hash().0, h));
            }
        }
        if let Some(dh) = derived_head {
            cands.push((dh.change_hash, dh.clone()));
        }
        // A candidate is superseded iff another candidate change descends from
        // it. (Direct heads are already live among themselves, but the derived
        // head can supersede or be superseded by a direct head.)
        let mut live = Vec::new();
        for i in 0..cands.len() {
            let mut superseded = false;
            for j in 0..cands.len() {
                if i != j
                    && self
                        .state
                        .dag_is_ancestor(&ChangeHash(cands[i].0), &ChangeHash(cands[j].0))?
                {
                    superseded = true;
                    break;
                }
            }
            if !superseded {
                live.push(cands[i].1.clone());
            }
        }
        Ok(live)
    }

    /// Materializes one resolved content head at `target_path`: resolves its
    /// version hash to the stored `FileVersion`, builds a `FileRecord` from the
    /// version's block list/size/metadata, persists the record's kind/symlink/
    /// exec metadata (so `materialize`'s symlink dispatch and metadata-only
    /// fast path see it), then hands the record to `materialize`.
    ///
    /// The `FileVersion` records each block's content hash and real size
    /// (canonical encoding v2), so the built `FileRecord`'s blocks carry real
    /// sizes and prefix-sum offsets and block fetch validates by both size and
    /// content hash before materialization.
    async fn materialize_dag_content_head(
        &self,
        group_id: &str,
        target_path: &str,
        head: &PathHead,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity =
            activity_provider.as_ref().map(|provider| provider.begin_block_write_activity());
        // A removing head (tombstone / move-away source) lands no content; only
        // content heads reach here, but guard defensively.
        let Some(content) = head.content.as_ref() else { return Ok(()) };
        let version_hash = VersionHash(content.version_hash);
        let Some(version) = self.state.dag_get_file_version(group_id, &version_hash)? else {
            // Admission gated on the version being present, so this only
            // happens if it was pruned in between — skip; a later heads
            // exchange re-drives this path once the version is re-supplied.
            tracing::warn!(
                group_id,
                path = target_path,
                version = %version_hash.to_hex(),
                "file version for a resolved content head is missing; skipping materialize"
            );
            return Ok(());
        };
        let record = file_record_from_version(target_path, &version);
        let meta = IncomingWireMeta {
            record_kind: version.meta.record_kind,
            symlink_target: version.meta.symlink_target.clone(),
            // A version does not carry the out-of-root flag (it is advisory,
            // never gated on); default it, matching a legacy record whose
            // sender predates the field.
            symlink_out_of_root: false,
            exec_bit: version.meta.exec_bit,
            origin_device_id: Some(head.device_id.clone()),
        };
        // Flush any same-path (and case-fold sibling) local edit still sitting
        // in this link's debounce accumulator *before* taking the path lock —
        // the same ordering the legacy reconcile relies on so a not-yet-indexed
        // local write is captured (into the index and the DAG) rather than
        // silently overwritten by this materialize.
        self.flush_pending_local_change_before_reconcile(group_id, target_path).await;
        self.flush_case_fold_sibling_before_reconcile(group_id, target_path).await;
        // Held across the whole materialize (including its block-fetch awaits),
        // closing the local-save-vs-incoming-version race exactly as the legacy
        // path does.
        let path_lock = self.state.path_lock(group_id, target_path);
        let _guard = path_lock.lock().await;
        // If this path already holds exactly this version's content, there is
        // nothing to fetch or rewrite. Skipping here matters beyond saving
        // work: re-running the projection, or resolving to a version this
        // device itself authored, must not overwrite an existing, richer index
        // row (real version vector, real per-block sizes) with the projection's
        // placeholder metadata.
        if let Some(local) = self.state.get_file(group_id, target_path)? {
            let same_content = !local.deleted
                && local.blocks.len() == version.blocks.len()
                && local.blocks.iter().zip(&version.blocks).all(|(b, vb)| b.hash == vb.hash.0);
            if same_content {
                // Content equality does not imply version equality: exec-bit,
                // symlink, or mtime-only changes are part of FileVersion
                // identity. Apply the DAG winner's metadata while preserving
                // the richer legacy VersionVector already projected locally.
                // Returning here without this step leaves replicas with the
                // same bytes but permanently divergent permissions.
                let metadata_record = FileRecord { version: local.version, ..record.clone() };
                apply_incoming_wire_metadata(&self.state, group_id, &metadata_record, &meta)?;
                if try_apply_metadata_only_update(
                    &self.state,
                    &self.sync_root(group_id)?,
                    group_id,
                    &metadata_record,
                    &head.device_id,
                )? {
                    return Ok(());
                }
            }
        }
        apply_incoming_wire_metadata(&self.state, group_id, &record, &meta)?;
        self.materialize(group_id, &record, policy, &head.device_id).await
    }

    /// The live heads for `path`: changes that touch it and have no
    /// descendant that also touches it. Walks the ancestry from the group's
    /// current heads, stopping each lineage at the first change that touches
    /// the path (anything above it on that lineage is superseded for the
    /// path), then drops any candidate that is an ancestor of another
    /// candidate — leaving exactly the non-superseded path-touching changes.
    fn store_live_heads_for_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<Change>, SyncError> {
        let mut candidates: Vec<Change> = Vec::new();
        let mut visited: std::collections::HashSet<ChangeHash> = std::collections::HashSet::new();
        let mut stack: Vec<ChangeHash> = self.state.dag_group_heads(group_id)?;
        while let Some(h) = stack.pop() {
            if !visited.insert(h) {
                continue;
            }
            let Some(change) = self.state.dag_get_change(&h)? else { continue };
            if change_touches_path(&change, path) {
                candidates.push(change);
            } else {
                for parent in &change.parents {
                    stack.push(*parent);
                }
            }
        }
        let hashes: Vec<ChangeHash> = candidates.iter().map(|c| c.change_hash()).collect();
        let mut live = Vec::new();
        for i in 0..candidates.len() {
            let mut superseded = false;
            for j in 0..candidates.len() {
                if i != j && self.state.dag_is_ancestor(&hashes[i], &hashes[j])? {
                    superseded = true;
                    break;
                }
            }
            if !superseded {
                live.push(candidates[i].clone());
            }
        }
        Ok(live)
    }

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
                self.record_peer_reliable_delivery_support(config.supports_reliable_delivery);
                self.record_peer_version_present_support(config.supports_version_present);
                self.record_peer_version_hash_exact_support(config.supports_version_hash_exact);
                // Once both sides have advertised the change-history
                // protocol, the session-start heads exchange is the whole of
                // startup propagation between these two peers. Driven from
                // here rather than from `run`'s startup so it fires only
                // after negotiation has actually confirmed the peer speaks the
                // DAG, never speculatively at a peer that will ignore it.
                self.record_peer_change_dag_support(config.supports_change_dag);
                if self.change_dag_negotiated() {
                    for group_id in self.shared_group_ids.clone() {
                        if let Err(e) = self.send_heads_announce(&group_id).await {
                            tracing::warn!(
                                group_id,
                                peer = %self.peer_device_id,
                                error = %e,
                                "failed to announce change-history heads after negotiation"
                            );
                        }
                    }
                }
                Ok(())
            }
            Some(Payload::BlockRequest(req)) => self.handle_block_request(req).await,
            Some(Payload::BlockResponse(resp)) => {
                self.handle_block_response(resp).await;
                Ok(())
            }
            Some(Payload::HeadsAnnounce(announce)) => self.handle_heads_announce(announce).await,
            Some(Payload::ChangeRequest(req)) => self.handle_change_request(req).await,
            Some(Payload::ChangeBatch(batch)) => self.handle_change_batch(batch).await,
            Some(Payload::VersionPresentQuery(query)) => {
                self.handle_version_present_query(query).await
            }
            Some(Payload::VersionPresentAck(ack)) => {
                self.handle_version_present_ack(ack);
                Ok(())
            }
            Some(Payload::HandoffLeaseRequest(req)) => self.handle_handoff_lease_request(req).await,
            Some(Payload::HandoffLeaseGrant(grant)) => {
                self.handle_handoff_lease_grant(grant);
                Ok(())
            }
            Some(Payload::HandoffTicketRequest(req)) => {
                self.handle_handoff_ticket_request(req).await
            }
            Some(Payload::HandoffTicketGrant(grant)) => {
                self.handle_handoff_ticket_grant(grant);
                Ok(())
            }
            Some(Payload::HandoffLeaseRelease(release)) => {
                self.handle_handoff_lease_release(release).await
            }
            Some(Payload::HandoffTicketRelease(release)) => {
                self.handle_handoff_ticket_release(release).await
            }
            Some(Payload::RebootstrapSnapshotRequest(req)) => {
                self.handle_rebootstrap_snapshot_request(req).await
            }
            Some(Payload::RebootstrapSnapshotResponse(resp)) => {
                self.handle_rebootstrap_snapshot_response(resp);
                Ok(())
            }
            // Also covers a peer running a *newer* protocol version that
            // added a oneof variant this build doesn't know about yet, and
            // an old peer still sending the removed `full_index`/
            // `index_update` (`SyncMessage` fields 2-3, now reserved): prost
            // decodes an unrecognized oneof case as an unset `payload`,
            // landing here rather than failing to decode — so a peer this
            // build can't fully understand is simply ignored, never an
            // error.
            None => Ok(()),
        }
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
            };
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                })
                .await;
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
            };
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                })
                .await;
        }
        if !self.state.group_has_block_provenance(&req.folder_group_id, &req.block_hash)? {
            tracing::warn!(
                group_id = %req.folder_group_id,
                path = %req.file_path,
                peer = %self.peer_device_id,
                hash = %hex::encode(&req.block_hash),
                "refusing block request without verified group provenance"
            );
            let response = proto::BlockResponse {
                block_hash: req.block_hash,
                data: vec![],
                not_found: true,
                compression: proto::Compression::None as i32,
            };
            return self
                .send(proto::SyncMessage {
                    payload: Some(proto::sync_message::Payload::BlockResponse(response)),
                })
                .await;
        }
        let hash_hex = hex::encode(&req.block_hash);
        // `BlockStore::get` does synchronous `std::fs` I/O plus a
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
                // reasoning as the `store.get` call just above,
                // since zstd compression of a multi-hundred-KB block is
                // real CPU work — but only when this session's peer has
                // negotiated compression support; `compress_
                // block` itself decides whether compression was actually
                // worth sending (adaptive skip).
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
                    },
                }
            }
            Ok(Err(_)) | Err(_) => proto::BlockResponse {
                block_hash: req.block_hash,
                data: vec![],
                not_found: true,
                compression: proto::Compression::None as i32,
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

    fn block_request_is_referenced(&self, req: &proto::BlockRequest) -> Result<bool, SyncError> {
        if let Some(record) = self.state.get_file(&req.folder_group_id, &req.file_path)? {
            if !record.deleted && record.blocks.iter().any(|block| block.hash == req.block_hash) {
                return Ok(true);
            }
        }
        Ok(self
            .state
            .dag_group_file_version_references_block(&req.folder_group_id, &req.block_hash)?
            || self
                .state
                .group_retained_version_references_block(&req.folder_group_id, &req.block_hash)?)
    }

    /// Decompresses `resp.data` per its
    /// declared `compression` (off the async runtime — `spawn_blocking`,
    /// the same reasoning as every other compress/
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
            // "off the async runtime" reasoning applies to
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
                    // cheap refcount `clone` of that same `Bytes` instead
                    // of its own full copy of the block (; see
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
    /// Returns `Bytes`, not `Vec<u8>` — see `PendingBlockRequests`'s
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

    /// Asks this peer whether it durably holds the exact file version
    /// identified by `version_hash` — the change-DAG's own `change::
    /// VersionHash`, SHA-256 of the version's canonical `FileVersion`
    /// encoding (ordered block list with per-block size, total size, and
    /// metadata) — and returns its answer. `blocks` restates the same
    /// version's ordered block list (hash + size) so the responder can run
    /// its explicit block/size check and `get()` verification loop without a
    /// second round trip; the caller passes both explicitly rather than
    /// letting this function re-derive them, since the caller is the one
    /// pinning the exact version being confirmed (see `DaemonState::
    /// confirm_version_present_via_peer` / `peer_holds_entire_group`'s doc
    /// comments for why re-deriving here would risk attributing an in-flight
    /// confirmation to a version a concurrent local edit already replaced).
    /// The reply is trusted because it arrives over this authenticated peer
    /// channel from a device the netmap has confirmed a full-replica member
    /// of the group; a peer that does not answer within a bounded time does
    /// not confirm custody (returns `false`, fail closed). Never involves the
    /// coordination plane.
    ///
    /// `for_handoff` selects which of the responder's versions may satisfy the
    /// query (see `VersionPresentQuery.for_handoff`'s wire doc):
    /// - `false` for the on-demand per-file eviction custody gate: a device
    ///   reclaims its last cached copy of a file's CURRENT version only when a
    ///   full replica confirms that same content is *its own current* version,
    ///   never merely a retained (superseded/trashed) one that retention could
    ///   later reclaim.
    /// - `true` for the whole-group durability handoff: the peer may confirm
    ///   the queried version against any version it still retains, so retained
    ///   durability roots (not just current heads) are covered by the handoff.
    pub async fn request_version_present(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
        for_handoff: bool,
    ) -> bool {
        let request_id =
            self.next_present_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_version_present
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, tx);

        // Remove this request's pending entry on EVERY exit from here, including
        // if this future is cancelled/dropped before it resolves — e.g. a
        // concurrent fan-out (`confirm_version_present_via_peer`) drops the
        // remaining queries once one peer confirms. Without this a dropped query
        // whose peer never replies would leak its entry: `handle_version_
        // present_ack` only removes an entry on an actual reply, and the timeout
        // arm below never runs for a cancelled future.
        struct PendingGuard<'a> {
            map: &'a StdMutex<HashMap<u64, oneshot::Sender<bool>>>,
            request_id: u64,
        }
        impl Drop for PendingGuard<'_> {
            fn drop(&mut self) {
                self.map.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.request_id);
            }
        }
        let _pending_guard = PendingGuard { map: &self.pending_version_present, request_id };

        let sent = self
            .send(proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::VersionPresentQuery(
                    proto::VersionPresentQuery {
                        request_id,
                        folder_group_id: group_id.to_string(),
                        file_path: file_path.to_string(),
                        block_hashes: blocks.iter().map(|b| b.hash.0.clone()).collect(),
                        for_handoff,
                        version_hash: version_hash.as_bytes().to_vec(),
                        block_sizes: blocks.iter().map(|b| b.size).collect(),
                    },
                )),
            })
            .await;
        if sent.is_err() {
            return false;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(present)) => present,
            _ => false,
        }
    }

    /// Answers a peer's `VersionPresentQuery`: whether this device can be
    /// trusted, right now, as a durable full-replica holder of exactly the
    /// queried version — the precondition for the on-demand querier to reclaim
    /// its own last cached copy. See [`Self::holds_version_durably`] for the
    /// (deliberately strict) conditions; anything short of all of them answers a
    /// fail-closed `false`.
    async fn handle_version_present_query(
        &self,
        query: proto::VersionPresentQuery,
    ) -> Result<(), SyncError> {
        let present = self.holds_version_durably(&query);
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::VersionPresentAck(
                proto::VersionPresentAck {
                    request_id: query.request_id,
                    folder_group_id: query.folder_group_id,
                    file_path: query.file_path,
                    present,
                    // Reserved for a future signed attestation; intentionally
                    // empty for now. Trust today is the authenticated peer
                    // channel plus the querier's post-reply re-verification of
                    // this responder's current authorization — not a signature.
                    signature: Vec::new(),
                },
            )),
        })
        .await
    }

    /// Whether this device durably holds *exactly* the queried version and can
    /// be relied on as the group's copy of it. Every condition must hold, or the
    /// answer is a fail-closed `false` — a bare "a block with this hash exists"
    /// check would confirm a corrupt/truncated block, a hash that only lives in
    /// another group or a transient cache, or a version this device is not an
    /// authoritative holder of, any of which could lure the querier into
    /// deleting its last good copy.
    ///
    /// Checked in order:
    /// 1. this device is actually `Eager` for the group;
    /// 2. a live (non-deleted) durability root exists for `(group, path)` in
    ///    the state set `for_handoff` allows (current-only for eviction, any
    ///    of current/superseded/trashed for a handoff);
    /// 3. the `change::VersionHash` recomputed from that root — via
    ///    `FileVersion::from_index_row` + `compute_hash()`, the SAME
    ///    computation the change-DAG itself uses to identify a version —
    ///    equals the query's `version_hash`. This is the identity check, and
    ///    it alone is authoritative: two versions can share every block hash
    ///    while differing in size, mtime, exec bit, symlink target, or record
    ///    kind, and only the full recomputed hash tells those apart;
    /// 4. the query's ordered block list and each block's declared size match
    ///    the matched root's — already implied by step 3 (blocks and sizes
    ///    are inputs to the hash), kept as an explicit check rather than
    ///    relying solely on the hash comparing correctly;
    /// 5. every block has verified provenance for the queried group;
    /// 6. every block in the matched root passes full `get()` checksum
    ///    verification (never merely `exists()`), so a corrupt or truncated
    ///    block answers `false` here instead of being reported present.
    fn holds_version_durably(&self, query: &proto::VersionPresentQuery) -> bool {
        // 1. This device must be a full replica (Eager) of the group. An
        //    on-demand device may hold these blocks only transiently and can
        //    evict them at any moment, so it must never authorize a peer to drop
        //    its own copy on the strength of this device's cache.
        if !matches!(
            self.state.materialization_policy_for_group(&query.folder_group_id),
            Ok(Some(MaterializationPolicy::Eager))
        ) {
            return false;
        }
        // The query must carry a real 32-byte `change::VersionHash` — a query
        // from a peer built before this field existed (or any malformed
        // value) cannot be identity-matched, so it fails closed rather than
        // falling back to a block-hash-only comparison.
        let Ok(query_hash_bytes): Result<[u8; 32], _> = query.version_hash.as_slice().try_into()
        else {
            return false;
        };
        let query_hash = VersionHash(query_hash_bytes);

        // 2 + 3. Find a durability root at this path — in the state set
        //    `for_handoff` allows — whose OWN recomputed `change::VersionHash`
        //    matches the query. WHICH versions qualify depends on what the
        //    querier is proving, and the two must not be conflated:
        //
        //    - Eviction custody (`for_handoff == false`): only this device's
        //      CURRENT record may match. An on-demand device reclaiming its
        //      last cached copy of a file's current version must be backed by a
        //      full replica whose *current* version is that same content. A
        //      merely retained (superseded/trashed) match is unsafe here: that
        //      retained row can expire under version retention and be
        //      reclaimed, leaving the device that already dropped its cache
        //      with no durable holder at all.
        //    - Whole-group handoff (`for_handoff == true`): any version this
        //      device still retains may match — current, superseded, or trashed
        //      alike — since a handoff must attest coverage of every durability
        //      root of the group, retained history included.
        //
        //    A `deleted` tombstone row's own block list is always empty, so it
        //    never matches, and a version this device has fully forgotten (past
        //    retention) correctly answers `false`.
        let matching_blocks: Vec<BlockInfo> = if query.for_handoff {
            let versions = match self.state.list_versions(&query.folder_group_id, &query.file_path)
            {
                Ok(versions) => versions,
                Err(_) => return false,
            };
            match versions.into_iter().find(|v| !v.deleted && v.version_hash == query_hash) {
                Some(v) => v.blocks,
                None => return false,
            }
        } else {
            // Read the current row's blocks AND metadata in ONE atomic
            // statement — never stitched across `get_file` + separate
            // `get_record_kind`/`get_symlink_target`/`get_exec_bit` reads,
            // which could tear across a concurrent metadata/content
            // transition and yield a `change::VersionHash` no single row ever
            // held (a hybrid identity the block/`get()` checks would not
            // catch, since they verify blocks, not metadata).
            let record = match self
                .state
                .get_current_version_record(&query.folder_group_id, &query.file_path)
            {
                Ok(Some(record)) if !record.deleted => record,
                // On-disk corruption of the serving row now surfaces as an
                // `Err` (the current-version read fails closed instead of
                // masking a corrupt block list as empty). Log it before
                // refusing to serve so the corruption is observable, rather
                // than being swallowed by the catch-all `return false`.
                Err(error) => {
                    tracing::warn!(
                        group_id = %query.folder_group_id,
                        path = %query.file_path,
                        error = %error,
                        "refusing to serve block: current version record is unreadable"
                    );
                    return false;
                }
                Ok(_) => return false,
            };
            let version = record.to_file_version();
            if version.version_hash != query_hash {
                return false;
            }
            record.blocks
        };

        // 4. Explicit block-list/size check. Subsumed by the `version_hash`
        //    equality above (blocks and per-block sizes are inputs to that
        //    hash), but kept explicit and obvious rather than relying solely
        //    on the hash comparison never having a bug.
        if matching_blocks.len() != query.block_hashes.len()
            || matching_blocks.len() != query.block_sizes.len()
            || !matching_blocks.iter().zip(query.block_hashes.iter().zip(&query.block_sizes)).all(
                |(b, (queried_hash, queried_size))| {
                    &b.hash == queried_hash && b.size == *queried_size
                },
            )
        {
            return false;
        }

        // 5. Physical presence in the global content-addressed store does not
        //    prove this device obtained the bytes through the queried group.
        //    Without provenance, a block from another group could create a
        //    false custody attestation and induce the querier to evict the
        //    group's last genuinely retrievable copy.
        if !matching_blocks.iter().all(|b| {
            matches!(
                self.state.group_has_block_provenance(&query.folder_group_id, &b.hash),
                Ok(true)
            )
        }) {
            return false;
        }

        // 6. Every block must pass full checksum verification, not just a
        //    path-existence check: `get` re-hashes the bytes (and drops a torn
        //    block), so a corrupt or truncated block answers `false` here rather
        //    than being reported as durably present.
        matching_blocks.iter().all(|b| self.store.get(&hex::encode(&b.hash)).is_ok())
    }

    /// Resolves the pending `request_version_present` awaiting this reply.
    fn handle_version_present_ack(&self, ack: proto::VersionPresentAck) {
        if let Some(tx) = self
            .pending_version_present
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&ack.request_id)
        {
            let _ = tx.send(ack.present);
        }
    }

    /// Sends a `HandoffLeaseRequest` to this peer and awaits the
    /// `HandoffLeaseGrant` reply, bounded by the same timeout
    /// `request_version_present` uses. The caller (the daemon's source-side
    /// role-loss orchestration) is expected to only ever call this against a
    /// peer it has already confirmed, via the whole-group durability-handoff
    /// `VersionPresentQuery`, holds every root it itself holds.
    ///
    /// Returns `None` on any failure to obtain a genuinely granted lease:
    /// send failure, timeout (this also covers a peer running a build that
    /// predates this message — it decodes as an unrecognized `SyncMessage`
    /// oneof case and is silently dropped, so it never replies and this
    /// simply times out), an explicit `granted = false` answer, an empty
    /// `lease_id`, or a `root_digest` that isn't exactly 32 bytes. This
    /// method only carries the wire round trip -- it does NOT compare the
    /// returned digest against anything; the caller does that itself,
    /// daemon-local, against its own already-known digest.
    pub async fn request_handoff_lease_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffLeaseGrant> {
        let request_id =
            self.next_handoff_lease_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_handoff_lease.lock().unwrap_or_else(|p| p.into_inner()).insert(request_id, tx);

        // Same leak-avoidance shape as `request_version_present`'s own
        // `PendingGuard` -- removes this request's pending entry on every
        // exit path, including cancellation, so a dropped/cancelled call
        // never leaves a stale sender behind for `handle_handoff_lease_grant`
        // to find nobody listening on.
        struct PendingGuard<'a> {
            map: &'a StdMutex<HashMap<u64, oneshot::Sender<Option<PeerHandoffLeaseGrant>>>>,
            request_id: u64,
        }
        impl Drop for PendingGuard<'_> {
            fn drop(&mut self) {
                self.map.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.request_id);
            }
        }
        let _pending_guard = PendingGuard { map: &self.pending_handoff_lease, request_id };

        let sent = self
            .send(proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::HandoffLeaseRequest(
                    proto::HandoffLeaseRequest {
                        request_id,
                        folder_group_id: group_id.to_string(),
                    },
                )),
            })
            .await;
        if sent.is_err() {
            return None;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(grant)) => grant,
            _ => None,
        }
    }

    /// Answers a peer's `HandoffLeaseRequest` by delegating to the injected
    /// [`HandoffLeaseResponder`] (the daemon's real coordination-plane-backed
    /// lease machinery). No responder installed (every test/call site that
    /// never calls `set_handoff_lease_responder`) answers `granted = false`,
    /// the same fail-closed default a responder itself returns on any local
    /// failure.
    async fn handle_handoff_lease_request(
        self: Arc<Self>,
        req: proto::HandoffLeaseRequest,
    ) -> Result<(), SyncError> {
        // Same authorization gate `handle_block_request` applies before
        // touching anything group-scoped: a peer's live session membership
        // can narrow mid-session (revocation), so this is re-checked fresh
        // on every request rather than trusted from construction time. An
        // unauthorized group answers `granted = false` without ever
        // consulting the injected responder (no coordination-plane round
        // trip for a group this peer has no business asking about).
        let grant = if self.shares_group(&req.folder_group_id) {
            match self.handoff_lease_responder() {
                Some(responder) => responder.request_handoff_lease(&req.folder_group_id).await,
                None => None,
            }
        } else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff lease request for unauthorized/unshared folder group"
            );
            None
        };
        let reply = match grant {
            Some(g) => proto::HandoffLeaseGrant {
                request_id: req.request_id,
                granted: true,
                lease_id: g.lease_id,
                root_digest: g.root_digest.to_vec(),
                expires_at_unix: g.expires_at_unix,
            },
            None => proto::HandoffLeaseGrant {
                request_id: req.request_id,
                granted: false,
                lease_id: String::new(),
                root_digest: Vec::new(),
                expires_at_unix: 0,
            },
        };
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseGrant(reply)),
        })
        .await
    }

    /// Resolves the pending `request_handoff_lease_from_peer` awaiting this
    /// reply. A malformed `root_digest` (anything other than exactly 32
    /// bytes) is treated identically to `granted = false` -- fail closed
    /// rather than guess.
    fn handle_handoff_lease_grant(&self, grant: proto::HandoffLeaseGrant) {
        let parsed = if grant.granted && !grant.lease_id.is_empty() {
            <[u8; 32]>::try_from(grant.root_digest.as_slice()).ok().map(|root_digest| {
                PeerHandoffLeaseGrant {
                    lease_id: grant.lease_id,
                    root_digest,
                    expires_at_unix: grant.expires_at_unix,
                }
            })
        } else {
            None
        };
        if let Some(tx) = self
            .pending_handoff_lease
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&grant.request_id)
        {
            let _ = tx.send(parsed);
        }
    }

    /// Sends a `RebootstrapSnapshotRequest` to this peer and awaits the
    /// `RebootstrapSnapshotResponse` reply, bounded by the same timeout
    /// `request_handoff_lease_from_peer` uses.
    ///
    /// Returns `None` on any failure to obtain a genuinely granted snapshot:
    /// send failure, timeout (this also covers a peer running a build that
    /// predates this message — it decodes as an unrecognized `SyncMessage`
    /// oneof case and is silently dropped, so it never replies and this
    /// simply times out), an explicit `granted = false` answer, a malformed
    /// `required_encoded`, or a decoded `RebootstrapRequired` whose claimed
    /// signer does not match this session's authenticated peer (see
    /// `handle_rebootstrap_snapshot_response`). This method only carries the
    /// wire round trip — it does NOT itself verify the signature or install
    /// anything; the caller must run `RebootstrapHandler::verify_rebootstrap`
    /// then `install_rebootstrap` on the result.
    pub async fn request_rebootstrap_snapshot_from_peer(
        &self,
        group_id: &str,
        requested_hash: ChangeHash,
    ) -> Option<PreparedRebootstrap> {
        let request_id = self
            .next_rebootstrap_snapshot_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_rebootstrap_snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, tx);

        // Same leak-avoidance shape as `request_handoff_lease_from_peer`'s
        // own `PendingGuard` — removes this request's pending entry on every
        // exit path, including cancellation, so a dropped/cancelled call
        // never leaves a stale sender behind for
        // `handle_rebootstrap_snapshot_response` to find nobody listening on.
        struct PendingGuard<'a> {
            map: &'a StdMutex<HashMap<u64, oneshot::Sender<Option<PreparedRebootstrap>>>>,
            request_id: u64,
        }
        impl Drop for PendingGuard<'_> {
            fn drop(&mut self) {
                self.map.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.request_id);
            }
        }
        let _pending_guard = PendingGuard { map: &self.pending_rebootstrap_snapshot, request_id };

        let sent = self
            .send(proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::RebootstrapSnapshotRequest(
                    proto::RebootstrapSnapshotRequest {
                        request_id,
                        folder_group_id: group_id.to_string(),
                        requested_hash: requested_hash.0.to_vec(),
                    },
                )),
            })
            .await;
        if sent.is_err() {
            return None;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(prepared)) => prepared,
            _ => None,
        }
    }

    /// Answers a peer's `RebootstrapSnapshotRequest` by delegating to the
    /// injected [`RebootstrapHandler`] (the daemon's real signing-identity-
    /// and pinned-key-backed re-bootstrap machinery). No handler installed,
    /// or the handler reports no local evidence this hash was pruned,
    /// answers `granted = false` — the same fail-closed default the
    /// unknown-vs-pruned boundary already preserves locally.
    async fn handle_rebootstrap_snapshot_request(
        self: Arc<Self>,
        req: proto::RebootstrapSnapshotRequest,
    ) -> Result<(), SyncError> {
        // Same authorization gate `handle_handoff_lease_request` applies
        // before touching anything group-scoped: a peer's live session
        // membership can narrow mid-session (revocation), so this is
        // re-checked fresh on every request rather than trusted from
        // construction time.
        let prepared = if self.shares_group(&req.folder_group_id) {
            match <[u8; 32]>::try_from(req.requested_hash.as_slice()) {
                Ok(hash_bytes) => match self.rebootstrap_handler() {
                    Some(handler) => handler
                        .prepare_rebootstrap(&req.folder_group_id, ChangeHash(hash_bytes))
                        .unwrap_or_else(|error| {
                            tracing::error!(
                                group_id = %req.folder_group_id,
                                peer = %self.peer_device_id,
                                %error,
                                "failed to prepare re-bootstrap snapshot response"
                            );
                            None
                        }),
                    None => None,
                },
                Err(_) => {
                    tracing::warn!(
                        peer = %self.peer_device_id,
                        "re-bootstrap snapshot request has a malformed requested_hash"
                    );
                    None
                }
            }
        } else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring re-bootstrap snapshot request for unauthorized/unshared folder group"
            );
            None
        };
        let reply = match prepared {
            Some(p) => proto::RebootstrapSnapshotResponse {
                request_id: req.request_id,
                granted: true,
                required_encoded: p.required.canonical_encoding(),
                snapshot_bytes: p.snapshot_bytes,
            },
            None => proto::RebootstrapSnapshotResponse {
                request_id: req.request_id,
                granted: false,
                required_encoded: Vec::new(),
                snapshot_bytes: Vec::new(),
            },
        };
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::RebootstrapSnapshotResponse(reply)),
        })
        .await
    }

    /// Resolves the pending `request_rebootstrap_snapshot_from_peer`
    /// awaiting this reply. A malformed `required_encoded` is treated
    /// identically to `granted = false` — fail closed rather than guess.
    ///
    /// Also enforces that the decoded `RebootstrapRequired`'s claimed
    /// `manifest.signer_device_id` matches `self.peer_device_id` — this
    /// session's own authenticated peer identity. Without this check, a
    /// misbehaving or compromised peer could forward a genuinely-signed
    /// manifest from some OTHER device and have it silently accepted as
    /// this session's own answer, letting the requester install a
    /// HistoryBase whose signer was never the device it actually asked.
    /// Verifying the manifest's *signature* alone does not catch this: the
    /// signature can be perfectly valid for a different, uninvolved signer.
    fn handle_rebootstrap_snapshot_response(&self, resp: proto::RebootstrapSnapshotResponse) {
        let parsed = if resp.granted {
            RebootstrapRequired::decode(&resp.required_encoded).ok().and_then(|required| {
                if required.manifest.signer_device_id.as_str() != self.peer_device_id {
                    tracing::warn!(
                        peer = %self.peer_device_id,
                        claimed_signer = required.manifest.signer_device_id.as_str(),
                        "ignoring re-bootstrap snapshot response: claimed signer does not match \
                         the connected peer"
                    );
                    return None;
                }
                Some(PreparedRebootstrap { required, snapshot_bytes: resp.snapshot_bytes })
            })
        } else {
            None
        };
        if let Some(tx) = self
            .pending_rebootstrap_snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&resp.request_id)
        {
            let _ = tx.send(parsed);
        }
    }

    /// Best-effort, one-way release of a lease this peer granted earlier.
    /// The target validates current group membership before touching either
    /// half of the id-only lease reservation.
    pub async fn release_handoff_lease_to_peer(
        &self,
        group_id: &str,
        lease_id: &str,
    ) -> Result<(), SyncError> {
        let request_id =
            self.next_handoff_lease_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseRelease(
                proto::HandoffLeaseRelease {
                    request_id,
                    folder_group_id: group_id.to_string(),
                    lease_id: lease_id.to_string(),
                },
            )),
        })
        .await
    }

    async fn handle_handoff_lease_release(
        self: Arc<Self>,
        release: proto::HandoffLeaseRelease,
    ) -> Result<(), SyncError> {
        if self.shares_group(&release.folder_group_id) {
            if let Some(responder) = self.handoff_lease_responder() {
                responder.release_handoff_lease(&release.folder_group_id, &release.lease_id).await;
            }
        } else {
            tracing::warn!(
                group_id = %release.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff lease release for unauthorized/unshared folder group"
            );
        }
        Ok(())
    }

    /// Sends a `HandoffTicketRequest` to this peer (the device being
    /// removed/revoked) and awaits the `HandoffTicketGrant` reply, bounded
    /// by the same timeout `request_handoff_lease_from_peer` uses. The
    /// caller is the OPERATING device's daemon (X), asking a DIFFERENT
    /// device (B, this session's peer) to attest and hand off its own
    /// roots — see `HandoffTicketResponder`'s doc comment for the trust
    /// model.
    ///
    /// Returns `None` on any failure to obtain a genuinely granted ticket:
    /// send failure, timeout (this also covers a peer running a build that
    /// predates this message — it decodes as an unrecognized `SyncMessage`
    /// oneof case and is silently dropped, so it never replies and this
    /// simply times out), or an explicit `granted = false` answer. X never
    /// distinguishes these over the wire — every one of them means "cannot
    /// lift the cross-device fail-closed gate for this group this round."
    pub async fn request_handoff_ticket_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        let request_id =
            self.next_handoff_ticket_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending_handoff_ticket
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(request_id, tx);

        // Same leak-avoidance shape as `request_handoff_lease_from_peer`'s
        // own `PendingGuard` -- removes this request's pending entry on
        // every exit path, including cancellation, so a dropped/cancelled
        // call never leaves a stale sender behind for
        // `handle_handoff_ticket_grant` to find nobody listening on.
        struct PendingGuard<'a> {
            map: &'a StdMutex<HashMap<u64, oneshot::Sender<Option<PeerHandoffTicketGrant>>>>,
            request_id: u64,
        }
        impl Drop for PendingGuard<'_> {
            fn drop(&mut self) {
                self.map.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.request_id);
            }
        }
        let _pending_guard = PendingGuard { map: &self.pending_handoff_ticket, request_id };

        let sent = self
            .send(proto::SyncMessage {
                payload: Some(proto::sync_message::Payload::HandoffTicketRequest(
                    proto::HandoffTicketRequest {
                        request_id,
                        folder_group_id: group_id.to_string(),
                    },
                )),
            })
            .await;
        if sent.is_err() {
            return None;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(grant)) => grant,
            _ => None,
        }
    }

    /// Best-effort cancellation of a removed-device ticket. The peer that
    /// created the ticket remains responsible for routing the final lease
    /// release to the target that owns it.
    pub async fn release_handoff_ticket_to_peer(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) -> Result<(), SyncError> {
        let request_id =
            self.next_handoff_ticket_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketRelease(
                proto::HandoffTicketRelease {
                    request_id,
                    folder_group_id: group_id.to_string(),
                    target_device_id: target_device_id.to_string(),
                    lease_id: lease_id.to_string(),
                },
            )),
        })
        .await
    }

    async fn handle_handoff_ticket_release(
        self: Arc<Self>,
        release: proto::HandoffTicketRelease,
    ) -> Result<(), SyncError> {
        if self.shares_group(&release.folder_group_id) {
            if let Some(responder) = self.handoff_ticket_responder() {
                responder
                    .release_handoff_ticket(
                        &release.folder_group_id,
                        &release.target_device_id,
                        &release.lease_id,
                    )
                    .await;
            }
        } else {
            tracing::warn!(
                group_id = %release.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff ticket release for unauthorized/unshared folder group"
            );
        }
        Ok(())
    }

    /// Answers a peer's `HandoffTicketRequest` by delegating to the
    /// injected [`HandoffTicketResponder`] (the daemon's real removed-
    /// device-ticket machinery, running THIS device's own attestation of
    /// ITS OWN roots — the peer asking is the operating device removing
    /// this one). No responder installed (every test/call site that never
    /// calls `set_handoff_ticket_responder`) answers `granted = false`, the
    /// same fail-closed default a responder itself returns on any local
    /// failure.
    async fn handle_handoff_ticket_request(
        self: Arc<Self>,
        req: proto::HandoffTicketRequest,
    ) -> Result<(), SyncError> {
        // Same authorization gate `handle_handoff_lease_request` applies:
        // this peer's live session membership can narrow mid-session
        // (revocation), so this is re-checked fresh on every request rather
        // than trusted from construction time. An unauthorized group
        // answers `granted = false` without ever consulting the injected
        // responder.
        let grant = if self.shares_group(&req.folder_group_id) {
            match self.handoff_ticket_responder() {
                Some(responder) => responder.request_handoff_ticket(&req.folder_group_id).await,
                None => None,
            }
        } else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff ticket request for unauthorized/unshared folder group"
            );
            None
        };
        let reply = match grant {
            Some(g) => proto::HandoffTicketGrant {
                request_id: req.request_id,
                granted: true,
                lease_id: g.lease_id.unwrap_or_default(),
                expires_at_unix: g.expires_at_unix,
                target_device_id: g.target_device_id.unwrap_or_default(),
            },
            None => proto::HandoffTicketGrant {
                request_id: req.request_id,
                granted: false,
                lease_id: String::new(),
                expires_at_unix: 0,
                target_device_id: String::new(),
            },
        };
        self.send(proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketGrant(reply)),
        })
        .await
    }

    /// Resolves the pending `request_handoff_ticket_from_peer` awaiting this
    /// reply.
    fn handle_handoff_ticket_grant(&self, grant: proto::HandoffTicketGrant) {
        let parsed = if grant.granted {
            Some(PeerHandoffTicketGrant {
                lease_id: if grant.lease_id.is_empty() { None } else { Some(grant.lease_id) },
                target_device_id: if grant.target_device_id.is_empty() {
                    None
                } else {
                    Some(grant.target_device_id)
                },
                expires_at_unix: grant.expires_at_unix,
            })
        } else {
            None
        };
        if let Some(tx) = self
            .pending_handoff_ticket
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&grant.request_id)
        {
            let _ = tx.send(parsed);
        }
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
            // A physical hit may belong only to another group. Treat it as
            // missing until this group has independently obtained the bytes.
            if already_present && self.state.group_has_block_provenance(group_id, &block.hash)? {
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
                    // `BlockStore::put` does synchronous `std::fs`
                    // I/O plus a SHA-256 hash of the whole block — same
                    // async-runtime-blocking concern as `handle_block_request`'s
                    // `store.get` above, so it gets the same `spawn_blocking`
                    // treatment. `data` (now `Bytes`) derefs to
                    // `&[u8]` for `BlockStore::put`'s `&[u8]` parameter.
                    let store = self.store.clone();
                    let put_result = spawn_blocking(move || store.put(&data)).await;
                    match put_result {
                        Ok(Ok(_hash)) => self.state.record_group_block_provenance(
                            group_id,
                            std::slice::from_ref(&block.hash),
                        )?,
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
    /// Returns `Ok()` once content is fully written; `Err(HydrationFailed)`
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
        // returns `Ok()` rather than an error — the blocks really were
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

        let out_path = self.local_file_path(group_id, path)?;
        // defense-in-depth — see `materialize`'s matching call
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

    /// The locked, per-record convergence core shared by the two callers that
    /// must never diverge on how a peer's record is compared against and
    /// materialized over the local one: the legacy wire path
    /// (`legacy_index_convergence::reconcile_one_file`) and the
    /// materialization-audit re-drive (`rematerialize_one_record`). It performs
    /// the version-vector comparison and every NON-conflicting outcome (adopt /
    /// peer-ahead / already-current rehydrate / never-seen) inline, and hands a
    /// genuine `Concurrent` result back to the caller rather than resolving it
    /// here — so the single mtime-based conflict resolver stays reachable only
    /// from the gated legacy wire path (see `legacy_index_convergence`).
    ///
    /// PRECONDITION: the caller MUST already hold
    /// `self.state.path_lock(group_id, &incoming.path)` for the entire call and
    /// MUST have run the pre-lock pending-local-change flushes. `local` is read
    /// here, under that lock, so a concurrent local save is reflected in the
    /// comparison rather than raced against it.
    async fn apply_locked_record(
        &self,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<LockedRecordOutcome, SyncError> {
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
            // Persist the peer's
            // advertised kind/target/exec-bit into the index *before*
            // `materialize` runs — its own symlink dispatch reads
            // `SyncState::get_record_kind` for this exact path, so this
            // must land first, not after.
            apply_incoming_wire_metadata(&self.state, group_id, &incoming, &meta)?;
            // We've never seen this path: adopt it outright (`materialize`
            // now handles a tombstone-for-a-file-we-never-had correctly
            // too — — recording the row without ever touching
            // a file that was never on disk here in the first place).
            self.materialize(group_id, &incoming, policy, &incoming_origin).await?;
            // Full mesh: this device's *other* peers need to learn about
            // this file too, not just the one that sent it (see
            // `forward_tx`'s doc comment).
            self.forward(group_id, &incoming);
            return Ok(LockedRecordOutcome::Settled);
        };

        // sanitize the peer-supplied version vector against
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
                Ok(LockedRecordOutcome::Settled)
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
                Ok(LockedRecordOutcome::Settled)
            }
            VvOrdering::Before => {
                // Peer is ahead: adopt their version. this used to
                // ignore `remove_file`'s result (`let _ =...`) — if the
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
                Ok(LockedRecordOutcome::Settled)
            }
            VvOrdering::Concurrent => Ok(LockedRecordOutcome::Concurrent { local }),
        }
    }

    /// The materialization-audit driver. Each record is re-driven through
    /// `rematerialize_one_record` (materialize-only, no conflict resolver). Used by
    /// `reconcile_local_materialization_audit` to repair missing on-disk
    /// materializations for records this device already holds without changing
    /// DAG conflict state.
    async fn rematerialize_local_records(
        self: Arc<Self>,
        group_id: &str,
        incoming: Vec<proto::FileInfo>,
    ) -> Result<(), SyncError> {
        // Fail closed rather than defaulting a missing link row to `Eager` —
        // see `reconcile_group_paths`. There is nothing to rematerialize into
        // for a group this device holds no live link for.
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(());
        };

        // Decode and apply the
        // cheap, purely-local path-safety/ignore filters for the whole
        // incoming batch first (unchanged from before — neither check
        // touches `SyncState`), then issue *one* batched index lookup
        // (`get_files_by_paths`) for every surviving path, in place of
        // what used to be a `get_file` point query per record buried
        // inside `reconcile_one_file`. `reconcile_needed` below then
        // decides, from that single batched snapshot, which records are
        // provably already in sync and can be skipped outright — turning
        // the common "an audit batch is mostly already-synced records" case
        // from O(records) store round-trips
        // into one, while every record that might actually need adopting
        // or conflict-resolving still goes through the exact same
        // correctly-locked `reconcile_one_file` path as before (see that
        // function's and `reconcile_needed`'s doc comments for why the
        // batched snapshot can only ever cause a *safe* skip, never an
        // incorrect one).
        let mut retained: Vec<(FileRecord, IncomingWireMeta)> = Vec::with_capacity(incoming.len());
        for file_info in incoming {
            // Captured from the
            // original `proto::FileInfo` before `.into` below drops it —
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
                        .rematerialize_one_record(
                            &group_id,
                            incoming_record.clone(),
                            incoming_meta.clone(),
                            policy,
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
    /// The materialization-audit counterpart to
    /// `legacy_index_convergence::reconcile_one_file`: re-drives a record built
    /// from THIS device's own index rows back through `apply_locked_record` to
    /// repair a missing/placeholder on-disk materialization, but WITHOUT the
    /// legacy conflict resolver. Because `incoming` is a snapshot of this
    /// device's own committed row, its version vector can only equal or trail
    /// the local row it is compared against, so the `Concurrent` arm is
    /// unreachable here; it is treated as a hard invariant violation rather
    /// than silently resolved, keeping the mtime resolver off the audit path.
    async fn rematerialize_one_record(
        &self,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity =
            activity_provider.as_ref().map(|provider| provider.begin_block_write_activity());
        // Must run *before*
        // `path_lock` below is acquired (see
        // `flush_pending_local_change_before_reconcile`'s doc comment for
        // why) — this is what makes sure `local` (read further down, once
        // the lock is held) already reflects a same-path local edit that
        // was still sitting undispatched in this link's debounce
        // accumulator a moment ago, so the version-vector `compare` below
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

        // held for this whole function, including the `.await`s
        // inside `materialize` (a block fetch can take real time) — see
        // `SyncState::path_lock`'s doc comment for the local-save-vs-
        // incoming-peer-version race this closes. `local` is read here,
        // *after* acquiring the lock, not before, so a concurrent local
        // save that ran while this device was waiting for the lock is
        // reflected in the comparison below rather than compared against
        // stale state.
        let path_lock = self.state.path_lock(group_id, &incoming.path);
        let _guard = path_lock.lock().await;
        match self.apply_locked_record(group_id, incoming, meta, policy).await? {
            LockedRecordOutcome::Settled => Ok(()),
            LockedRecordOutcome::Concurrent { local, .. } => {
                debug_assert!(
                    false,
                    "materialization audit reached the concurrent-conflict path for a record \
                     built from this device's own index rows; incoming must never be concurrent \
                     with local here"
                );
                tracing::warn!(
                    group_id,
                    path = %local.path,
                    peer = %self.peer_device_id,
                    "materialization audit unexpectedly saw a concurrent record; skipping \
                     without legacy conflict resolution"
                );
                Ok(())
            }
        }
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
    /// `policy` is looked up once by the caller's batch
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
            &self.sync_root(group_id)?,
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
        // Peer input is never authority to adopt a folder. The watcher/link
        // path may adopt during explicit startup, but every peer-driven disk
        // mutation must prove that the already-adopted marker/token pair still
        // matches before it removes, creates, truncates, or renames anything.
        let sync_root = self.sync_root(group_id)?;
        crate::root_identity::VerifiedRoot::verify(&sync_root, group_id, &self.state)?;
        // a tombstone (`deleted=true, blocks=[]`) materialized via
        // the ordinary path below unconditionally fetches/reconstructs —
        // writing a 0-byte file at the path while the index records
        // `deleted=true`, an on-disk ghost file disagreeing with its own
        // index row. Handle deletion explicitly instead: remove the file
        // first (already gone is not an error — that's the common case,
        // since most tombstones arrive after the originating device's own
        // delete already ran locally), and only then record the
        // tombstone. Order matters: recording the tombstone
        // *before* a removal that then fails (a locked/open file, common
        // on Windows) leaves the index saying `deleted=true` while the
        // file still exists — the next scan sees an on-disk file with no
        // matching not-deleted index entry and resurrects + re-propagates
        // it as a brand-new local edit. Removing first means a failure
        // here surfaces as a real error without corrupting the index.
        if record.deleted {
            let out_path = self.local_file_path(group_id, &record.path)?;
            // `std::fs::remove_file` on a
            // symlink path is a plain `unlink` of that directory entry
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
                &self.sync_root(group_id)?,
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
                &self.sync_root(group_id)?,
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

        // an explicit pin always fetches (a deliberate,
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
            // deadlock risk once added a bounded per-peer
            // in-flight-message semaphore (`MAX_IN_FLIGHT_MESSAGES_PER_PEER`,
            // `run`'s recv loop): this whole function runs inside a
            // spawned message handler that holds one of those permits,
            // and `ensure_blocks_present` awaits a `BlockResponse` from
            // *this same peer connection* — if enough concurrent eager
            // materializations from a large catch-up exhaust the semaphore, the
            // recv loop itself
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
            // read of a control-plane message (for example a `BlockRequest`,
            // i.e. anything that isn't itself a
            // `BlockResponse`) from the `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
            // slot materialization also contends for — e.g. a small,
            // separate reservation carved out for control messages, so the
            // recv loop can never be head-of-line-blocked behind eager
            // fetches on its own connection in the first place, matching
            // resource governance's "control messages must never be
            // delayed even while both buckets are saturated" precedent.
            let all_present = tokio::time::timeout(
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
            // Do not record unfetched content as hydrated:
            // `ensure_blocks_present` returns `false` (not an error) when a
            // peer could not supply one or more of this record's blocks
            // (reported not-found/unusable, or returned bytes failing
            // integrity verification). Committing a `Hydrated` row and
            // running `reconstruct_file` here would then fail at
            // `store.get(<missing block>)` mid-loop, orphaning its temp file
            // and leaving a live-but-fileless `Hydrated` row — which
            // `repair_interrupted_materializations` (blocks still absent)
            // demotes to an empty placeholder, silently destroying a
            // still-pending write (for a losing conflict copy, its only
            // preservation). Instead record a retriable `Placeholder` — the
            // exact `all_present == false` handling `hydrate_file_with_timeout`
            // already uses — so the fetch is retried on a later reconcile
            // (`eager_live_record_needs_rehydrate`) and recovery never
            // clobbers it. Reuses the not-admitted branch's placeholder path.
            if !all_present {
                self.state.upsert_file_with_origin(group_id, record, origin_device_id)?;
                self.state.clear_held(group_id, &record.path)?;
                self.state.set_materialization_state(
                    group_id,
                    &record.path,
                    MaterializationState::Placeholder,
                )?;
                let out_path = self.local_file_path(group_id, &record.path)?;
                self.verify_write_target(group_id, &out_path)?;
                write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
                return apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?);
            }
            // Open the single sanctioned materialization-intent seam BEFORE
            // committing the brand-new row below. `upsert_file_with_origin`
            // INSERTs a fresh row that defaults to `Hydrated`, and that commit
            // is durable (`PRAGMA synchronous = FULL`) — so a crash *after* it
            // but before the temp-write-then-rename lands would otherwise leave
            // a `Hydrated` row with no file on disk, its blocks present, and no
            // intent. Startup/periodic repair reads exactly that state as an
            // offline deletion and tombstones the path, destroying a
            // just-received file group-wide. `MaterializationIntentGuard::open`
            // writes a durable intent first — the same seam
            // `reconstruct_file_journaled` uses for repair's own writes — so
            // repair instead sees the intent and reconstructs from the
            // locally-present blocks. The guard is cleared the instant the
            // rename is durable (below) or when this write is demoted to a
            // `Placeholder`; an early `?` return on a failed write drops it
            // without clearing, leaving the intent for repair.
            let intent_target_hash = crate::materialization::intent_target_hash(&record.blocks);
            let intent_guard = crate::materialization::MaterializationIntentGuard::open(
                &self.state,
                group_id,
                &record.path,
                &intent_target_hash,
            )?;
            self.state.upsert_file_with_origin(group_id, record, origin_device_id)?;
            // Invariant (the whole point of the seam): a brand-new `Hydrated`
            // content row is never committed for a not-yet-written file without
            // a preceding durable intent. Any future edit that reorders or drops
            // the guard above trips this in debug/test builds.
            debug_assert!(
                self.state.has_materialization_intent(group_id, &record.path).unwrap_or(false),
                "materialize committed a Hydrated content row with a pending file write but no \
                 open materialization intent — the journaled write seam was bypassed"
            );
            self.state.clear_held(group_id, &record.path)?;
            let out_path = self.local_file_path(group_id, &record.path)?;
            // defense-in-depth: `is_safe_relative_path` (in
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
            // Guard the one-shot reconstruct. `reconstruct_file` reads every
            // block back through `store.get` mid-loop, so a *transient* block-
            // store read error (an EIO) fails the whole assembly *after* the
            // live row was already committed at the top of this branch — which,
            // left unhandled, orphans the temp file and leaves a live+Hydrated
            // row with no file on disk (a losing conflict copy would then be
            // permanently lost, since `repair_interrupted_materializations` /
            // the reconcile re-drive do not reliably revisit a same-device
            // conflict copy the peer never echoes back). The bytes are always
            // durably present in *this* device's own block store by now (the
            // eager fetch above stored them, or — for a losing conflict copy —
            // they are this device's own prior edit, per this function's
            // "content is always already present" invariant), so the correct
            // response to a transient read error is to retry the assembly in
            // place: a retry re-reads those same content-addressed blocks on a
            // later, non-faulting read. Retry a bounded number of times, then
            // fall back to the same retriable `Placeholder` the `all_present ==
            // false` branch uses (so a genuinely-stuck read still never leaves a
            // fileless Hydrated row).
            const MAX_RECONSTRUCT_RETRIES: u32 = 20;
            const RECONSTRUCT_RETRY_BACKOFF: std::time::Duration =
                std::time::Duration::from_millis(50);
            let mut recon = reconstruct_file(self.store.as_ref(), &out_path, &record.blocks);
            let mut attempts = 0u32;
            while recon.is_err() && attempts < MAX_RECONSTRUCT_RETRIES {
                attempts += 1;
                // Short backoff before re-reading the already-present blocks.
                // Under the deterministic simulator this advances virtual time
                // (letting any interfering condition clear) at no real cost.
                tokio::time::sleep(RECONSTRUCT_RETRY_BACKOFF).await;
                recon = reconstruct_file(self.store.as_ref(), &out_path, &record.blocks);
            }
            if let Err(e) = recon {
                tracing::warn!(
                    group_id,
                    path = %record.path,
                    error = %e,
                    attempts,
                    "reconstruct after eager fetch still failing; demoting to retriable placeholder"
                );
                self.state.set_materialization_state(
                    group_id,
                    &record.path,
                    MaterializationState::Placeholder,
                )?;
                // A `Placeholder` is not an in-progress write — clear the intent
                // now (mirrors repair's placeholder arms). Cleared before the
                // placeholder disk write below so that even a failure writing
                // the placeholder cannot leave a stale intent: the row is already
                // `Placeholder`, which repair skips, and a later offline delete
                // of this path must not be misread as a crash to reconstruct.
                intent_guard.clear()?;
                self.verify_write_target(group_id, &out_path)?;
                write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
                return apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?);
            }
            // The temp-write-then-rename completed durably — clear the intent
            // NOW, before the post-write metadata touch below. Clearing only
            // after `apply_exec_bit` would leak the intent whenever reading or
            // applying the exec bit errored (a real `chmod` on POSIX) even though
            // the file is durably on disk and `Hydrated`; a later genuine offline
            // delete of that path would then read `missing + intent present` and
            // wrongly resurrect it from the blocks. This is exactly
            // `reconstruct_file_journaled`'s "clear right after the rename"
            // ordering.
            intent_guard.clear()?;
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
            let out_path = self.local_file_path(group_id, &record.path)?;
            // defense-in-depth — see the comment above.
            self.verify_write_target(group_id, &out_path)?;
            write_placeholder(&out_path, record.size, record.mtime_unix_nanos)?;
            // A placeholder still gets the recorded exec bit
            // applied now — `hydrate_file_with_timeout` re-applies it
            // again once real content lands, so this is never lost
            // across the placeholder → hydrated transition either.
            apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)
        }
    }

    fn local_file_path(&self, group_id: &str, path: &str) -> Result<PathBuf, SyncError> {
        Ok(self.sync_root(group_id)?.join(path))
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

        let out_path = self.local_file_path(group_id, &record.path)?;
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        Ok(on_disk_size != Some(record.size))
    }

    /// The link-table gate every incoming peer apply must pass before it
    /// touches this device's state for `group_id`. `false` (with the reason logged
    /// as `what`) means the apply must not proceed.
    ///
    /// `shares_group` is not a substitute and must not be mistaken for one: it
    /// is netmap-derived, and unlinking a folder deliberately leaves the
    /// device's membership of the group intact, so it stays true for a folder
    /// the user has detached. The link row is the only record that this device
    /// has a folder for the group at all.
    ///
    /// This gates the *index* write, not just the file write. `sync_root`
    /// already fails closed for an unlinked group, so no file can be written
    /// either way — but an index that records a peer's file for a folder this
    /// device no longer has is not harmless: a later relink's startup scan
    /// would find an index entry with no file on disk and read that as a local
    /// deletion to propagate to the peers that still have it.
    fn may_apply_incoming_change(&self, group_id: &str, what: &str) -> Result<bool, SyncError> {
        match self.state.link_gate_for_group(group_id)? {
            LinkGate::Live { .. } => Ok(true),
            LinkGate::Paused { .. } => {
                tracing::debug!(group_id, peer = %self.peer_device_id, "ignoring {what} for a paused link");
                Ok(false)
            }
            LinkGate::NoLiveLink => {
                // Nothing tears this session down when the user unlinks, so a
                // live session keeps receiving traffic for a folder that is no
                // longer linked. Drop rather than defer: there is no folder to
                // apply into, and if the user relinks, startup reconciliation
                // re-derives the state from disk.
                tracing::info!(
                    group_id,
                    peer = %self.peer_device_id,
                    "dropping {what}: this device holds no live link for the folder group"
                );
                Ok(false)
            }
        }
    }

    /// `group_id`'s local linked directory (the root
    /// `verify_write_target` checks resolved write targets stay under).
    ///
    /// Read from the live link table on every call rather than from a map
    /// frozen when the session was constructed. A session outlives the link it
    /// was built for: nothing tears a peer session down when the user unlinks a
    /// folder, so a session that owned its own root went on writing into — and
    /// running the `remove_file` of an incoming tombstone inside — a folder the
    /// link table no longer had any row for. The root is the link's property,
    /// not the session's, and a session that cannot re-derive it from the link
    /// table has no business writing at all. The same lookup fixes the milder
    /// version of the bug for free: a root that *moved* is now followed rather
    /// than written to at its old path.
    ///
    /// Fails closed for a group with no live link. Defaulting to
    /// an empty path instead is quietly catastrophic in two compounding ways:
    /// `local_file_path` joins onto it and yields a *relative* path, so every
    /// write for the group lands under the process's working directory instead
    /// of the user's folder; and `verify_write_target`'s fast path then waves it
    /// through, because an empty root is trivially the parent of a bare
    /// filename. The defense-in-depth check is bypassed in exactly the case it
    /// exists for. There is no safe path to write when the root is unknown, so
    /// this must stay a `Result` rather than acquire a default.
    ///
    /// A *paused* link still resolves: pause is a reversible sync gate, and the
    /// folder is still linked and still where the row says it is. Refusing to
    /// apply while paused is the batch gate's job (`handle_change_batch`), not
    /// this function's — read-only callers legitimately need a paused link's
    /// root.
    fn sync_root(&self, group_id: &str) -> Result<PathBuf, SyncError> {
        match self.state.link_gate_for_group(group_id)? {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                Ok(PathBuf::from(local_path))
            }
            LinkGate::NoLiveLink => Err(SyncError::PathEscapesRoot(format!(
                "no live link for group {group_id}; refusing to resolve a local path"
            ))),
        }
    }

    /// `raw_root`'s canonical form, cached per group — see
    /// `canonical_sync_roots`'s doc comment for why canonicalizing on every
    /// call is worth avoiding.
    ///
    /// Keyed by the raw root the caller just resolved, not merely by group: a
    /// cache that remembered only "group → canonical" would keep handing back
    /// the canonical form of a *previous* root after a relink, which is exactly
    /// the stale-root failure `sync_root` now resolves live to avoid. A
    /// mismatch re-canonicalizes rather than trusting the entry.
    ///
    /// `None` when the root cannot be canonicalized (most often: it does not
    /// exist, e.g. an external volume that is not mounted). The caller falls
    /// back to the non-canonical containment check rather than treating this as
    /// permission to write.
    fn canonical_sync_root(&self, group_id: &str, raw_root: &Path) -> Option<PathBuf> {
        let mut cache =
            self.canonical_sync_roots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((cached_raw, canonical)) = cache.get(group_id) {
            if cached_raw == raw_root {
                return Some(canonical.clone());
            }
        }
        let canonical = std::fs::canonicalize(raw_root).ok()?;
        cache.insert(group_id.to_string(), (raw_root.to_path_buf(), canonical.clone()));
        Some(canonical)
    }

    /// defense-in-depth check before writing through `out_path`
    /// — see `chunker::verify_write_target_within_canonical_root`'s doc
    /// comment. Uses the cached canonical root (`canonical_sync_roots`)
    /// when available (the common case, avoiding a repeated
    /// canonicalize-the-whole-root cost on this per-peer-message hot
    /// path); falls back to resolving `group_id`'s root fresh for the
    /// rare case it wasn't cached at session construction time.
    fn verify_write_target(&self, group_id: &str, out_path: &Path) -> Result<(), SyncError> {
        // Resolve the root first and fail closed on an unknown group: with the
        // old empty-path default, `out_path` was a bare relative filename whose
        // parent is `""` -- exactly the empty root -- so the fast path below
        // returned Ok and this check passed trivially for the one case it most
        // needed to reject.
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        // Fast path: is specifically about a symlink at an
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
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => {
                verify_write_target_within_canonical_root(out_path, &canonical_root)
            }
            None => verify_write_target_within_root(out_path, raw_root),
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
            &self.sync_root(group_id)?,
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
/// Supplies the trust material the change-history protocol needs to verify
/// an incoming change before admitting it: the pinned signing key of the
/// device that authored the change, and whether that device is authorized
/// to write the group. Both are netmap-derived facts this crate has no
/// direct access to (it has no coordination client), so the daemon injects
/// an implementation via `set_change_authenticator`, mirroring how
/// `set_rate_limiters` injects the shared token buckets.
///
/// Until an authenticator is present, this session cannot verify changes,
/// so it never admits one it received — matching the trust rule that DAG
/// sync with a device is unavailable until that device's signing key is
/// pinned. Serving already-verified changes out of the store and announcing
/// heads do not need it.
pub trait ChangeAuthenticator: Send + Sync {
    /// The pinned 32-byte Ed25519 verifying key for `device_id`, or `None`
    /// if this device has not pinned a signing key for it yet.
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Whether `device_id` is authorized to write `group_id`.
    fn is_writer(&self, device_id: &str, group_id: &str) -> bool;
    /// Whether the change's signed authorization stamp is acceptable for this
    /// author/group under the locally retained policy state. Implementations
    /// that have not yet retained policy logs may fall back to `is_writer`;
    /// callers still invoke this after signature verification so the stamp is
    /// authenticated.
    fn accepts_change_auth(
        &self,
        device_id: &str,
        group_id: &str,
        signing_key_fingerprint: [u8; 32],
        auth: crate::change::ChangeAuth,
    ) -> bool {
        let _ = signing_key_fingerprint;
        let _ = auth;
        self.is_writer(device_id, group_id)
    }
}

/// Converts a wire-encoded change hash (a length-prefixed `bytes` field)
/// into a `ChangeHash`, or `None` if it isn't exactly 32 bytes — a
/// malformed hash from a peer is dropped, never applied.
fn change_hash_from_wire(bytes: &[u8]) -> Option<ChangeHash> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(ChangeHash(arr))
}

/// The inverse of `change_hash_from_wire`.
fn change_hash_to_wire(hash: &ChangeHash) -> Vec<u8> {
    hash.0.to_vec()
}

/// The content version an op references, or `None` for a delete (which lands
/// no content).
fn op_version_hash(op: &Op) -> Option<VersionHash> {
    match op {
        Op::Create { version, .. } | Op::Update { version, .. } | Op::Move { version, .. } => {
            Some(*version)
        }
        Op::Delete { .. } => None,
    }
}

/// Builds a materializable `FileRecord` for `path` from a resolved
/// `FileVersion`. Each block carries its real `size` (canonical encoding v2
/// records a per-block size) and a prefix-sum `offset`, so the built record is
/// suitable for the derived materialized index. The version
/// vector is empty because causality in the change-history model is DAG
/// ancestry, not a version vector; the index row is only a DAG projection.
fn file_record_from_version(path: &str, version: &FileVersion) -> FileRecord {
    let mut offset = 0u64;
    let blocks = version
        .blocks
        .iter()
        .map(|vb| {
            let block = BlockInfo { hash: vb.hash.0.clone(), offset, size: vb.size };
            offset = offset.saturating_add(vb.size as u64);
            block
        })
        .collect();
    FileRecord {
        path: path.to_string(),
        size: version.size,
        mtime_unix_nanos: version.meta.mtime_unix_nanos,
        version: crate::version_vector::VersionVector::new(),
        blocks,
        deleted: false,
    }
}

/// Records every path an op touches into `set` (both endpoints of a move).
fn collect_op_paths(op: &Op, set: &mut std::collections::BTreeSet<String>) {
    match op {
        Op::Create { path, .. } | Op::Update { path, .. } | Op::Delete { path } => {
            set.insert(path.as_str().to_string());
        }
        Op::Move { from, to, .. } => {
            set.insert(from.as_str().to_string());
            set.insert(to.as_str().to_string());
        }
    }
}

/// Whether every path a change projects landed successfully, given the set of
/// paths whose projection failed this batch. A change is treated as fully
/// applied only when none of its own op paths failed AND no failed path is a
/// conflict copy derived from one of them — a losing change materializes its
/// content at a derived conflict-copy path, so a failure there means that
/// change has not fully projected either. Conservative by construction: any
/// related failure withholds the applied flag so the change re-projects,
/// never marking a change applied whose on-disk effect is incomplete.
fn change_projection_succeeded(
    change_paths: &std::collections::BTreeSet<String>,
    failed_paths: &std::collections::BTreeSet<String>,
) -> bool {
    if failed_paths.is_empty() {
        return true;
    }
    for p in change_paths {
        if failed_paths.contains(p) {
            return false;
        }
        if failed_paths.iter().any(|f| crate::conflict::is_conflict_copy_of(f, p)) {
            return false;
        }
    }
    true
}

/// Whether any of a change's ops touches `path`.
fn change_touches_path(change: &Change, path: &str) -> bool {
    change.ops.iter().any(|op| match op {
        Op::Create { path: p, .. } | Op::Update { path: p, .. } | Op::Delete { path: p } => {
            p.as_str() == path
        }
        Op::Move { from, to, .. } => from.as_str() == path || to.as_str() == path,
    })
}

/// Builds the head a change contributes to `path` — a content head if it
/// lands content there, a removing head if it deletes/moves it away — or
/// `None` if the change does not touch `path`. A `Move` is a hint desugared
/// to `Delete{from}` + `Create{to}`: it removes `from` and lands content at
/// `to`, so concurrency resolves per desugared path (no special Move-vs-Move
/// rule — two moves to the same target conflict there like any content; to
/// different targets, both land). The `version_hash` comes straight from the
/// op; `mtime` is a deterministic placeholder (0), since the winner is chosen
/// by `(lamport, change_hash)` and the conflict-copy stamp derived from it is
/// then identical on every replica (the file's real mtime lives in the version
/// metadata resolved on the content path).
fn path_head_from_change(change: &Change, path: &str) -> Option<PathHead> {
    let mut touches = false;
    let mut content: Option<[u8; 32]> = None;
    for op in &change.ops {
        match op {
            Op::Create { path: p, version } | Op::Update { path: p, version }
                if p.as_str() == path =>
            {
                touches = true;
                content = Some(version.0);
            }
            Op::Delete { path: p } if p.as_str() == path => {
                touches = true;
                content = None;
            }
            Op::Move { to, version, .. } if to.as_str() == path => {
                touches = true;
                content = Some(version.0);
            }
            Op::Move { from, .. } if from.as_str() == path => {
                touches = true;
            }
            _ => {}
        }
    }
    if !touches {
        return None;
    }
    Some(PathHead {
        change_hash: change.change_hash().0,
        lamport: change.lamport,
        device_id: change.device_id.as_str().to_string(),
        content: content.map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
    })
}

/// One live head competing to own — or to remove — a single path `P`,
/// after the ancestry fold has already dropped every change an applied
/// descendant supersedes. Every field is taken verbatim from the signed,
/// content-addressed change (and the file version it produced), so
/// `resolve_path_heads` below is a pure function of the change set and
/// lands identically on every replica with no communication.
#[derive(Clone, Debug)]
pub struct PathHead {
    pub change_hash: [u8; 32],
    pub lamport: u64,
    pub device_id: String,
    /// The content this head lands at `P`, or `None` when this head removes
    /// `P` — a tombstone, or the source side of a move away from `P`.
    pub content: Option<PathHeadContent>,
}

#[derive(Clone, Debug)]
pub struct PathHeadContent {
    /// Content address of the file version — doubles as the deterministic
    /// conflict-copy disambiguator (`hash8`).
    pub version_hash: [u8; 32],
    /// The version's recorded mtime, used only to format the human-readable
    /// stamp in a conflict-copy filename. Part of the signed version, not a
    /// wall-clock read taken now, so it is identical on every replica.
    pub mtime_unix_nanos: i64,
}

/// A losing content head materialized as a conflict copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictCopy {
    /// Index into the `heads` slice passed to `resolve_path_heads`.
    pub head: usize,
    /// The conflict-copy path — a pure function of the losing change.
    pub path: String,
}

/// The deterministic outcome of materializing one path from its live heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathResolution {
    /// Every live head removed the path (all tombstones / moves-away) — the
    /// path is absent. A stale content head that is an *ancestor* of a
    /// tombstone never reaches here (the fold dropped it as superseded), so
    /// this can never resurrect a deleted file.
    Absent,
    /// The path holds `winner`'s content; each losing content head is
    /// materialized as a conflict copy at the returned path.
    Present { winner: usize, conflict_copies: Vec<ConflictCopy> },
}

/// The deterministic per-path materialization fold, expressed as a pure
/// function so both the reconciliation driver and the property-test
/// reference model resolve concurrency identically:
///
/// - **Content vs. tombstone** keeps the content: a tombstone that is
///   merely *concurrent* with a content head is acknowledged (it already
///   superseded whatever it descended from) but does not remove the
///   concurrent content, so only content heads contest the path.
/// - **Content vs. content** (including move-vs-move landing at the same
///   target) picks the highest `(lamport, change_hash)` as the winner
///   (`dag_conflict_loser_is_a`); every other content head becomes a
///   conflict copy whose name is a pure function of that losing change
///   (`conflict_copy_path_for_losing_change`).
/// - **All-tombstone** → the path is absent.
///
/// `heads` must be the *live* heads for `path` (non-superseded changes
/// whose ops touch `path`, with a move contributing a removing head at its
/// source and a content head at its destination). Order does not matter —
/// the winner is chosen by the total order over `(lamport, change_hash)`,
/// so any permutation of `heads` yields the same resolution, which is the
/// commutativity the SEC suite checks.
pub fn resolve_path_heads(path: &str, heads: &[PathHead]) -> PathResolution {
    let content_heads: Vec<usize> =
        heads.iter().enumerate().filter(|(_, h)| h.content.is_some()).map(|(i, _)| i).collect();
    if content_heads.is_empty() {
        return PathResolution::Absent;
    }
    // Winner = highest `(lamport, change_hash)`. `dag_conflict_loser_is_a`
    // is a strict total order over distinct changes (distinct changes have
    // distinct canonical hashes), so this max is unambiguous and identical
    // on every replica.
    let winner = *content_heads
        .iter()
        .max_by(|&&a, &&b| {
            if dag_conflict_loser_is_a(
                heads[a].lamport,
                &heads[a].change_hash,
                heads[b].lamport,
                &heads[b].change_hash,
            ) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        })
        .expect("content_heads is non-empty");
    let winner_version = heads[winner].content.as_ref().expect("content head").version_hash;
    // Identical-content collapse: concurrent content heads that resolve the
    // path to the *same* version hash are one equivalence class — byte-identical
    // content is not a conflict, so they produce no conflict copy between them
    // (this is what stops a per-device initial import of the same tree from
    // materializing a copy storm). A conflict copy is emitted only *between*
    // classes with genuinely different content: one per distinct other version
    // hash, its representative being that class's own `(lamport, change_hash)`
    // max — chosen deterministically so every replica names it identically.
    let mut reps: std::collections::BTreeMap<[u8; 32], usize> = std::collections::BTreeMap::new();
    for &i in &content_heads {
        let vh = heads[i].content.as_ref().expect("content head").version_hash;
        if vh == winner_version {
            continue;
        }
        match reps.get(&vh) {
            None => {
                reps.insert(vh, i);
            }
            Some(&rep) => {
                if dag_conflict_loser_is_a(
                    heads[rep].lamport,
                    &heads[rep].change_hash,
                    heads[i].lamport,
                    &heads[i].change_hash,
                ) {
                    reps.insert(vh, i);
                }
            }
        }
    }
    let conflict_copies = reps
        .values()
        .map(|&i| {
            let content = heads[i].content.as_ref().expect("filtered to content heads");
            ConflictCopy {
                head: i,
                path: conflict_copy_path_for_losing_change(
                    path,
                    &heads[i].device_id,
                    content.mtime_unix_nanos,
                    &content.version_hash,
                ),
            }
        })
        .collect();
    PathResolution::Present { winner, conflict_copies }
}

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

    /// dropping the guard without ever fulfilling the request
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

/// a peer
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

/// the per-(session, group) eager-fetch admission
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

        let mut local = file_record_with_block("script.sh", 0xAB);
        local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
        state.upsert_file("group-1", &local).unwrap();

        let out_path = root.path().join("script.sh");
        std::fs::write(&out_path, b"hello").unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Simulates this device's own index already knowing the target
        // exec bit for this path — see `try_apply_metadata_only_update`'s
        // doc comment on the wire-schema gap this stands in for.
        state.set_exec_bit("group-1", "script.sh", true).unwrap();

        let mut incoming = local.clone();
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
    fn metadata_only_fast_path_rejects_index_match_when_disk_bytes_do_not_match() {
        let state = SyncState::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut record = file_record_with_block("partial.bin", 0xAB);
        record.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
        state.upsert_file("group-1", &record).unwrap();
        std::fs::write(root.path().join("partial.bin"), b"wrong").unwrap();

        let applied =
            try_apply_metadata_only_update(&state, root.path(), "group-1", &record, "device-a")
                .unwrap();

        assert!(!applied, "an interrupted materialization must take the reconstruct path");
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
        assert!(stored.is_some(), ": a held record must still be indexed");
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
    /// `"photo_2.jpg"`,...) — this crate implements no automatic
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

    /// adaptive-skip heuristic: uniformly random bytes have no
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

#[cfg(test)]
mod dag_resolution_tests {
    use super::{resolve_path_heads, ConflictCopy, PathHead, PathHeadContent, PathResolution};

    fn content_head(hash_byte: u8, lamport: u64, device: &str, mtime: i64) -> PathHead {
        PathHead {
            change_hash: [hash_byte; 32],
            lamport,
            device_id: device.to_string(),
            content: Some(PathHeadContent {
                version_hash: [hash_byte; 32],
                mtime_unix_nanos: mtime,
            }),
        }
    }

    fn tombstone_head(hash_byte: u8, lamport: u64, device: &str) -> PathHead {
        PathHead {
            change_hash: [hash_byte; 32],
            lamport,
            device_id: device.to_string(),
            content: None,
        }
    }

    #[test]
    fn single_content_head_holds_the_path() {
        let heads = [content_head(1, 3, "device-a", 100)];
        assert_eq!(
            resolve_path_heads("f.txt", &heads),
            PathResolution::Present { winner: 0, conflict_copies: vec![] }
        );
    }

    #[test]
    fn single_tombstone_leaves_the_path_absent() {
        let heads = [tombstone_head(1, 3, "device-a")];
        assert_eq!(resolve_path_heads("f.txt", &heads), PathResolution::Absent);
    }

    #[test]
    fn concurrent_content_keeps_higher_lamport_and_conflicts_the_loser() {
        // head 0 lamport 5, head 1 lamport 7 -> head 1 wins, head 0 is the
        // conflict copy.
        let heads = [content_head(1, 5, "device-a", 100), content_head(2, 7, "device-b", 200)];
        match resolve_path_heads("report.docx", &heads) {
            PathResolution::Present { winner, conflict_copies } => {
                assert_eq!(winner, 1);
                assert_eq!(conflict_copies.len(), 1);
                assert_eq!(conflict_copies[0].head, 0);
                assert!(conflict_copies[0].path.starts_with("report (conflicted copy"));
                assert!(conflict_copies[0].path.contains("device-a"));
                assert!(conflict_copies[0].path.ends_with(".docx"));
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn resolution_is_independent_of_head_order() {
        let a = content_head(0xAA, 5, "device-a", 100);
        let b = content_head(0xBB, 5, "device-b", 200);
        let forward = resolve_path_heads("f.bin", &[a.clone(), b.clone()]);
        let reversed = resolve_path_heads("f.bin", &[b, a]);
        // Same winning *content* and same conflict-copy *name* regardless of
        // the order the heads were presented in — the commutativity the SEC
        // suite relies on. (Winner index flips with the reordering; the
        // materialized path/name does not.)
        let name = |r: &PathResolution| match r {
            PathResolution::Present { conflict_copies, .. } => conflict_copies[0].path.clone(),
            PathResolution::Absent => "<absent>".to_string(),
        };
        assert_eq!(name(&forward), name(&reversed));
    }

    #[test]
    fn content_beats_a_concurrent_tombstone() {
        // A delete concurrent with an edit: the content survives, the
        // tombstone is acknowledged without producing a conflict copy.
        let heads = [content_head(1, 4, "device-a", 100), tombstone_head(2, 6, "device-b")];
        assert_eq!(
            resolve_path_heads("f.txt", &heads),
            PathResolution::Present { winner: 0, conflict_copies: vec![] }
        );
    }

    #[test]
    fn three_way_content_conflict_yields_two_copies() {
        let heads = [
            content_head(1, 5, "device-a", 100),
            content_head(2, 5, "device-b", 200),
            content_head(3, 5, "device-c", 300),
        ];
        match resolve_path_heads("f.txt", &heads) {
            PathResolution::Present { winner, conflict_copies } => {
                // Equal lamports -> highest change hash (0x03) wins.
                assert_eq!(winner, 2);
                let mut losers: Vec<ConflictCopy> = conflict_copies;
                losers.sort_by_key(|c| c.head);
                assert_eq!(losers.iter().map(|c| c.head).collect::<Vec<_>>(), vec![0, 1]);
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    fn content_head_vh(change: u8, lamport: u64, device: &str, version_hash: u8) -> PathHead {
        PathHead {
            change_hash: [change; 32],
            lamport,
            device_id: device.to_string(),
            content: Some(PathHeadContent {
                version_hash: [version_hash; 32],
                mtime_unix_nanos: 0,
            }),
        }
    }

    #[test]
    fn identical_content_heads_collapse_without_a_conflict_copy() {
        // Two concurrent heads with distinct change identities but the SAME
        // content (version hash) are one equivalence class — no conflict copy.
        let heads = [content_head_vh(1, 5, "device-a", 9), content_head_vh(2, 5, "device-b", 9)];
        match resolve_path_heads("f.txt", &heads) {
            PathResolution::Present { conflict_copies, .. } => {
                assert!(
                    conflict_copies.is_empty(),
                    "byte-identical content must not produce a conflict copy: {conflict_copies:?}"
                );
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn one_conflict_copy_per_distinct_content_class() {
        // Winner class (vh 9) + two heads of class vh 7 + one of class vh 5:
        // exactly two copies (one per losing class), not three.
        let heads = [
            content_head_vh(10, 9, "d", 9), // winner (highest lamport)
            content_head_vh(1, 5, "a", 7),
            content_head_vh(2, 5, "b", 7),
            content_head_vh(3, 5, "c", 5),
        ];
        match resolve_path_heads("f.txt", &heads) {
            PathResolution::Present { winner, conflict_copies } => {
                assert_eq!(winner, 0);
                assert_eq!(
                    conflict_copies.len(),
                    2,
                    "one conflict copy per losing content class: {conflict_copies:?}"
                );
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }
}

/// End-to-end coverage of the immediate projection of a promoted orphan
/// within a single `handle_change_batch` call. This is the one test module
/// here that constructs a real `PeerSyncSession` (with a live, deliberately
/// unreachable loopback channel that never needs a peer on the other end),
/// because the behavior under test lives inside `handle_change_batch` itself:
/// a change that arrives before its ancestry is buffered, and the later
/// arrival of its parent — in the SAME batch — both applies the parent and
/// promotes the child, so both changes' paths must materialize in that one
/// call rather than waiting for the periodic reprojection audit.
#[cfg(test)]
mod promoted_orphan_projection_tests {
    use super::{ChangeAuthenticator, PeerSyncSession};
    use crate::change::{
        Change, ChangeAuth, DeviceId, FileMeta, FileVersion, FolderGroupId, Op, SyncPath,
    };
    use crate::dag_store::{self, ChangeEmitter};
    use crate::index::SyncState;
    use crate::types::RecordKind;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::FsBlockStore;

    const GROUP: &str = "shared-group";

    /// A permissive authenticator that pins one author's verifying key and
    /// treats it as a writer — the trust material the daemon would normally
    /// inject from the coordination plane's netmap.
    struct TestAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version() -> FileVersion {
        // Zero-block content, so materialization writes an empty file with no
        // block fetch — the projection under test does not depend on content
        // transfer, only on which paths get projected.
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Create { path: SyncPath(path.into()), version: version.version_hash }
    }

    /// Builds the two signed changes an author would emit — a root editing
    /// `a.txt`, then a child editing `b.txt` that descends from it — by
    /// running the real local-emission path against a throwaway store.
    fn build_parent_then_child(signing_key: &SigningKey) -> (Change, Change, FileVersion) {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let version = empty_version();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let parent = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("a.txt", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();
        let child = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("b.txt", &version)],
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();
        (parent, child, version)
    }

    /// Constructs a live channel that has no reachable peer. `handle_change_
    /// batch` may enqueue an outbound change-request for a still-missing
    /// parent; sending on this channel simply queues the datagram (the send
    /// half stays open), so the call under test completes without a peer.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// The regression this targets: two changes touching DIFFERENT paths,
    /// delivered child-first within one batch, must BOTH project immediately.
    /// The child editing `b.txt` arrives before its parent, so it is orphaned;
    /// the parent editing `a.txt` arrives next in the same batch, applies, and
    /// promotes the child. Before the fix, only the parent's path (`a.txt`) was
    /// folded into the batch's projection, so `b.txt` did not materialize until
    /// the 90-second reprojection audit ran. This asserts both paths have file
    /// records and both changes are marked applied right after the single call.
    #[tokio::test]
    async fn unauthenticated_batch_cannot_persist_file_versions() {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
        );
        let version = empty_version();
        session
            .handle_change_batch(proto::ChangeBatch {
                folder_group_id: GROUP.to_string(),
                changes: vec![],
                compression: proto::Compression::None as i32,
                compressed_changes: vec![],
                file_versions: vec![version.canonical_encoding()],
            })
            .await
            .unwrap();
        assert!(!state.dag_has_file_version(GROUP, &version.version_hash).unwrap());
    }

    #[tokio::test]
    async fn rejected_lamport_change_cannot_persist_or_authorize_its_file_version() {
        use crate::change::{BlockHash, VersionBlock};

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, _, parent_version) = build_parent_then_child(&signing_key);
        let block_hash = vec![0x5a; 32];
        let poisoned_version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        // `parent.lamport` is the only valid predecessor maximum. Supplying a
        // much larger value creates a correctly signed change that fails DAG
        // admission only after signature and writer authorization succeed.
        let rejected = Change::create_signed(
            vec![parent.compute_hash()],
            parent.lamport + 99,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".into()),
            FolderGroupId(GROUP.into()),
            vec![create_op("poison.bin", &poisoned_version)],
            &signing_key,
        );

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
        );
        session.set_change_authenticator(Arc::new(TestAuthenticator {
            author_device_id: "device-a".to_string(),
            author_verifying_key,
        }));

        session
            .handle_change_batch(proto::ChangeBatch {
                folder_group_id: GROUP.to_string(),
                changes: vec![parent.to_wire_bytes(), rejected.to_wire_bytes()],
                compression: proto::Compression::None as i32,
                compressed_changes: Vec::new(),
                file_versions: vec![
                    parent_version.canonical_encoding(),
                    poisoned_version.canonical_encoding(),
                ],
            })
            .await
            .unwrap();

        assert!(state.dag_has_change(&parent.compute_hash()).unwrap());
        assert!(!state.dag_has_change(&rejected.compute_hash()).unwrap());
        assert!(!state.dag_has_file_version(GROUP, &poisoned_version.version_hash).unwrap());
        assert!(!state.dag_group_file_version_references_block(GROUP, &block_hash).unwrap());
    }

    #[tokio::test]
    async fn reverse_ordered_batch_projects_both_paths_immediately() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_parent_then_child(&signing_key);

        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );
        session.set_change_authenticator(Arc::new(TestAuthenticator {
            author_device_id: "device-a".to_string(),
            author_verifying_key,
        }));

        // Reverse order: the child (b.txt) precedes its parent (a.txt) in the
        // batch, so the child is processed first and orphaned, then the parent
        // lands and promotes it — all in this one call.
        let batch = proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: vec![child.to_wire_bytes(), parent.to_wire_bytes()],
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };
        session.handle_change_batch(batch).await.unwrap();

        // Both changes are durable...
        assert!(state.dag_has_change(&parent.compute_hash()).unwrap());
        assert!(state.dag_has_change(&child.compute_hash()).unwrap());
        // ...both paths were projected into the materialized index immediately,
        // without relying on the periodic reprojection audit...
        assert!(
            state.get_file(GROUP, "a.txt").unwrap().is_some(),
            "the parent's path must be materialized"
        );
        assert!(
            state.get_file(GROUP, "b.txt").unwrap().is_some(),
            "the promoted orphan's path must be materialized in the same batch"
        );
        // ...and both changes are marked applied, so the backstop has nothing
        // left to re-drive.
        assert!(
            state.dag_list_unapplied_changes(GROUP).unwrap().is_empty(),
            "both the parent and the promoted orphan must be marked applied immediately"
        );
    }

    /// The real peer-apply entry point (`handle_change_batch`) must wait on the
    /// group's startup barrier before admitting any change, so an incoming peer
    /// change cannot race the startup scan's un-path-locked commit. A closed
    /// barrier blocks the call; `mark_group_ready` releases it.
    #[tokio::test]
    async fn handle_change_batch_waits_for_group_startup_barrier() {
        let store_dir = tempfile::tempdir().unwrap();
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        // A live link, but deliberately no `mark_group_ready` yet -- this test
        // owns the barrier's lifecycle below. The link row itself is required:
        // the apply path refuses a group with no live link before it ever
        // reaches the barrier, so without it there would be no parking to
        // observe.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);

        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Close the barrier, as `start_link_watch` does before the peer
        // orchestrator can run.
        let generation = state.begin_group_startup(GROUP);

        let empty_batch = || proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: vec![],
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![],
        };

        // Closed: the admission call must not complete.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                session.handle_change_batch(empty_batch()),
            )
            .await
            .is_err(),
            "handle_change_batch must park on the group's startup barrier"
        );

        // Startup done: it proceeds.
        state.mark_group_ready(GROUP, generation);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session.handle_change_batch(empty_batch()),
        )
        .await
        .expect("handle_change_batch must proceed once the group is ready")
        .unwrap();
    }
}

/// Deterministic regression coverage for the flush-before-reconcile guard on
/// the DAG `ChangeBatch` admission/projection path — the counterpart to the
/// wire-driven `tests/dst_peer_reconcile_race.rs`, but exercising
/// `handle_change_batch`/`reconcile_group_paths` directly (no simulated
/// network, no debounce timer), so the outcome is a pure function of the
/// sequence of `handle_change_batch` calls and cannot flake on handshake
/// timing. Both scenarios stage a genuine, still-pending local edit through a
/// real `LocalChangeProcessor` (the same emission path production drives from
/// the debounce accumulator) exposed via `set_pending_local_change_flush`.
///
/// - `concurrent_edit_*`: a remote content change to P is admitted while a
///   local edit to P is pending. The admission-loop flush (which covers the
///   triggering change's own paths) captures the edit, so it becomes a
///   genuinely concurrent change and materializes as a conflict copy instead
///   of being overwritten. The no-flush variant produces no conflict copy and
///   the index adopts the remote content — the edit is untracked/lost.
/// - `promoted_orphan_tombstone_*`: the GAP this fix closes. An orphaned
///   tombstone of P is promoted by a parent that touches a *different* path Q,
///   so the admission-loop flush covers Q, never P. Only the flush hoisted
///   ahead of the Absent (tombstone) resolution in `reconcile_group_paths`
///   can capture P's pending edit before the delete — without it, P is
///   silently deleted.
#[cfg(test)]
mod reconcile_group_paths_flush_tests {
    use super::{ChangeAuthenticator, PeerSyncSession, PendingLocalChangeFlush};
    use crate::change::{Change, ChangeAuth, FileMeta, FileVersion, Op, SyncPath};
    use crate::dag_store::{self, ChangeEmitter};
    use crate::index::SyncState;
    use crate::local_change::LocalChangeProcessor;
    use crate::types::RecordKind;
    use crate::watcher::{FsChangeEvent, FsChangeKind};
    use ed25519_dalek::SigningKey;
    use std::collections::{BTreeSet, HashMap};
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    const GROUP: &str = "flush-guard-group";
    const REMOTE: &str = "device-remote";
    const LOCAL: &str = "device-local";
    const P: &str = "p.txt";
    const Q: &str = "q.txt";
    const LOCAL_EDIT: &[u8] = b"device-local's genuine concurrent edit";

    fn remote_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn local_key() -> SigningKey {
        SigningKey::from_bytes(&[8u8; 32])
    }

    struct TestAuthenticator {
        author_verifying_key: [u8; 32],
    }
    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == REMOTE).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    /// Zero-block content: materialization writes an empty file with no block
    /// fetch, so a remote change carrying only this version's metadata (never
    /// its blocks, exactly like the real wire) always materializes.
    fn empty_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    /// A live channel with no reachable peer: `handle_change_batch` may enqueue
    /// an outbound change-request for a missing parent; the send simply queues.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        Arc::new(
            yadorilink_transport::PeerChannel::connect(
                local_secret,
                peer_public,
                0,
                Vec::new(),
                hub,
            )
            .await
            .unwrap(),
        )
    }

    fn batch_of(changes: &[&Change], versions: &[&FileVersion]) -> proto::ChangeBatch {
        proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: changes.iter().map(|c| c.to_wire_bytes()).collect(),
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: versions.iter().map(|v| v.canonical_encoding()).collect(),
        }
    }

    /// The remote author's real, signed emission chain, built on a throwaway
    /// sender store so each change carries the correct parents/lamports.
    /// `ops_chain` is emitted oldest-first; each entry descends from the prior.
    fn emit_remote_chain(version: &FileVersion, ops_chain: Vec<Vec<Op>>) -> Vec<Change> {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        dag_store::put_file_version(&sender, GROUP, version).unwrap();
        let emitter = ChangeEmitter::new(REMOTE, remote_key());
        ops_chain
            .into_iter()
            .map(|ops| {
                dag_store::emit_local_change(&sender, GROUP, ops, ChangeAuth::PLACEHOLDER, &emitter)
                    .unwrap()
            })
            .collect()
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Create { path: SyncPath(path.into()), version: version.version_hash }
    }
    fn update_op(path: &str, version: &FileVersion) -> Op {
        Op::Update { path: SyncPath(path.into()), version: version.version_hash }
    }
    fn delete_op(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.into()) }
    }

    /// Stands in for the daemon's `LinkFlushHandle`: when asked to flush a path
    /// that is marked pending, it dispatches the on-disk edit through the real
    /// `LocalChangeProcessor` emission path (index + DAG), exactly as a real
    /// debounce flush would. `pending` models what is sitting undispatched in
    /// the accumulator; `calls` records every path the session asked to flush,
    /// so a test can witness that the reconcile-site guard actually fired.
    struct RecordingFlush {
        processor: Arc<LocalChangeProcessor>,
        root: PathBuf,
        pending: Mutex<BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
    }
    impl RecordingFlush {
        fn new(processor: Arc<LocalChangeProcessor>, root: PathBuf) -> Self {
            Self {
                processor,
                root,
                pending: Mutex::new(BTreeSet::new()),
                calls: Mutex::new(vec![]),
            }
        }
        fn mark_pending(&self, rel: &str) {
            self.pending.lock().unwrap().insert(rel.to_string());
        }
        fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }
    impl PendingLocalChangeFlush for RecordingFlush {
        fn flush_pending_local_change<'a>(
            &'a self,
            group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(rel_path.to_string());
                // Drop the guard before the await below.
                let is_pending = self.pending.lock().unwrap().remove(rel_path);
                if is_pending {
                    let event = FsChangeEvent {
                        path: self.root.join(rel_path),
                        kind: FsChangeKind::CreatedOrModified,
                    };
                    let _ = self.processor.process_event(group_id, &self.root, &event).await;
                }
            })
        }
        fn flush_case_fold_sibling<'a>(
            &'a self,
            _group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            // On a case-insensitive filesystem (e.g. the macOS test host) the
            // session also probes for a colliding sibling; this scenario stages
            // no case-fold sibling, so it is a recorded no-op.
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("casefold:{rel_path}"));
            })
        }
    }

    struct Harness {
        session: Arc<PeerSyncSession>,
        state: Arc<SyncState>,
        sync_root: PathBuf,
        local_processor: Arc<LocalChangeProcessor>,
        _root_dir: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
    }

    async fn setup() -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        // A live link always reaches Ready in a real daemon: app::run starts a
        // watcher for every link at boot, and add_link starts one immediately.
        // Peer apply for a live link that never registered a gate defers, so a
        // test that skipped this would be exercising a state the daemon does
        // not produce.
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        let session = PeerSyncSession::new(
            unreachable_channel().await,
            LOCAL.to_string(),
            REMOTE.to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );
        session.set_change_authenticator(Arc::new(TestAuthenticator {
            author_verifying_key: remote_key().verifying_key().to_bytes(),
        }));

        // The local-edit emitter shares the session's state AND block store, so
        // a flushed local edit is a live DAG head the reconcile reads and its
        // content is fetchable when materialized.
        let local_processor = Arc::new(
            LocalChangeProcessor::new(state.clone(), store.clone(), LOCAL.to_string())
                .with_change_emitter(Arc::new(ChangeEmitter::new(LOCAL, local_key()))),
        );

        Harness {
            session,
            state,
            sync_root,
            local_processor,
            _root_dir: root_dir,
            _store_dir: store_dir,
        }
    }

    fn conflict_copy_files(root: &Path) -> Vec<PathBuf> {
        let mut out = vec![];
        if let Ok(entries) = std::fs::read_dir(root) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().contains("(conflicted copy") {
                    out.push(e.path());
                }
            }
        }
        out
    }

    /// The local edit survives if it is present either as live `p.txt` or as a
    /// conflict-copy sibling — the two legitimate no-data-loss outcomes.
    fn local_edit_present(root: &Path, expected: &[u8]) -> bool {
        if std::fs::read(root.join(P)).map(|c| c == expected).unwrap_or(false) {
            return true;
        }
        conflict_copy_files(root)
            .iter()
            .any(|p| std::fs::read(p).map(|c| c == expected).unwrap_or(false))
    }

    /// Scenario (a): a genuinely concurrent local edit to P is captured by the
    /// admission-loop flush (P is the incoming change's own path) and preserved
    /// as a conflict copy rather than silently overwritten.
    #[tokio::test]
    async fn concurrent_edit_via_change_batch_preserves_local_edit_as_conflict_copy() {
        let h = setup().await;
        let version = empty_version();
        // C0 creates P (baseline), R updates P concurrently with the local edit.
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![update_op(P, &version)]],
        );
        let (c0, r) = (&chain[0], &chain[1]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "baseline P must materialize");

        let flush = Arc::new(RecordingFlush::new(h.local_processor.clone(), h.sync_root.clone()));
        h.session.set_pending_local_change_flush(flush.clone());

        // A real, still-pending local edit to P: bytes on disk, marked pending.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        flush.mark_pending(P);

        // R (remote update to P) is admitted. Its own path is P, so the
        // admission loop flushes P first, turning the pending edit into a
        // genuinely concurrent change.
        h.session.handle_change_batch(batch_of(&[r], &[&version])).await.unwrap();

        let copies = conflict_copy_files(&h.sync_root);
        assert_eq!(copies.len(), 1, "exactly one conflict copy expected; found {copies:?}");
        assert!(
            local_edit_present(&h.sync_root, LOCAL_EDIT),
            "the local edit must survive as live content or a conflict copy"
        );
    }

    /// Scenario (a), no-flush variant: without the flush wired, the pending
    /// edit is invisible; the remote content wins with no conflict copy and the
    /// index no longer tracks the local edit. Pins that the flush is
    /// load-bearing for the admission path.
    #[tokio::test]
    async fn concurrent_edit_via_change_batch_without_flush_loses_local_edit() {
        let h = setup().await;
        let version = empty_version();
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![update_op(P, &version)]],
        );
        let (c0, r) = (&chain[0], &chain[1]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        // Local edit on disk, but no flush handle wired: nothing dispatches it.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();

        h.session.handle_change_batch(batch_of(&[r], &[&version])).await.unwrap();

        assert!(
            conflict_copy_files(&h.sync_root).is_empty(),
            "no flush => no concurrent change => no conflict copy"
        );
        let rec = h.state.get_file(GROUP, P).unwrap().unwrap();
        assert!(
            !rec.deleted && rec.blocks.is_empty(),
            "the index adopted the remote (empty) content; the local edit is untracked/lost"
        );
    }

    /// Scenario (b) — the GAP-1 regression: an orphaned tombstone of P is
    /// promoted by a parent touching a DIFFERENT path Q, so the admission-loop
    /// flush never covers P. Only the flush hoisted ahead of the Absent
    /// (tombstone) resolution in `reconcile_group_paths` captures P's pending
    /// edit before the delete. Without that fix this test fails: P is deleted
    /// and the reconcile-site flush is never asked for P.
    #[tokio::test]
    async fn promoted_orphan_tombstone_flushes_pending_local_edit_before_delete() {
        let h = setup().await;
        let version = empty_version();
        // Chain: C0 create P -> Par create Q -> O delete P. O descends from Par.
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![create_op(Q, &version)], vec![delete_op(P)]],
        );
        let (c0, par, o) = (&chain[0], &chain[1], &chain[2]);

        // Baseline: adopt C0 so P is live on disk and in the index.
        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "baseline P must materialize");

        let flush = Arc::new(RecordingFlush::new(h.local_processor.clone(), h.sync_root.clone()));
        h.session.set_pending_local_change_flush(flush.clone());

        // O (delete P) arrives BEFORE its parent Par -> orphaned/held. Nothing
        // is pending yet, so the admission-loop flush of O's own path (P) is a
        // no-op: the local edit only lands afterwards.
        h.session.handle_change_batch(batch_of(&[o], &[])).await.unwrap();
        assert!(h.sync_root.join(P).exists(), "O is orphaned; P must not be deleted yet");

        // NOW the genuine local edit to P lands in the accumulator.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        flush.mark_pending(P);
        // Drop the pre-edit admission-loop flush calls so the assertion below is
        // strictly about the reconcile-site flush.
        flush.take_calls();

        // Par (touches Q) arrives, admits, and promotes O. The admission loop
        // flushes only Q, never P — so the reconcile Absent-branch flush is the
        // sole line of defense for P's pending edit.
        h.session.handle_change_batch(batch_of(&[par], &[&version])).await.unwrap();

        let calls = flush.take_calls();
        assert!(
            calls.iter().any(|c| c == P),
            "reconcile_group_paths must flush P before acting on its Absent (tombstone) \
             resolution; recorded calls: {calls:?}"
        );
        assert!(
            h.sync_root.join(P).exists(),
            "the concurrent local edit must survive the promoted-orphan tombstone, not be deleted"
        );
        assert_eq!(
            std::fs::read(h.sync_root.join(P)).unwrap(),
            LOCAL_EDIT,
            "P must still hold the local edit's content"
        );
        let rec = h.state.get_file(GROUP, P).unwrap().unwrap();
        assert!(!rec.deleted, "P must remain live in the index, not tombstoned");
    }

    /// Scenario (b), no-flush variant: with no handle wired, the reconcile-site
    /// flush is a no-op, so the promoted tombstone deletes P — the exact
    /// pre-fix data loss. Confirms the flush call is what saves the edit.
    #[tokio::test]
    async fn promoted_orphan_tombstone_without_flush_deletes_pending_local_edit() {
        let h = setup().await;
        let version = empty_version();
        let chain = emit_remote_chain(
            &version,
            vec![vec![create_op(P, &version)], vec![create_op(Q, &version)], vec![delete_op(P)]],
        );
        let (c0, par, o) = (&chain[0], &chain[1], &chain[2]);

        h.session.handle_change_batch(batch_of(&[c0], &[&version])).await.unwrap();
        h.session.handle_change_batch(batch_of(&[o], &[])).await.unwrap();
        // Local edit on disk, but no flush handle wired.
        std::fs::write(h.sync_root.join(P), LOCAL_EDIT).unwrap();
        h.session.handle_change_batch(batch_of(&[par], &[&version])).await.unwrap();

        // No flush => the tombstone wins and P is deleted from the index.
        let rec = h.state.get_file(GROUP, P).unwrap().unwrap();
        assert!(rec.deleted, "without the flush the promoted tombstone deletes P");
    }
}

/// `ClusterConfig.supports_version_hash_exact` negotiation and the
/// `holds_version_durably` responder behavior it exists to let a querier
/// reason about — a peer's advertised capability must default to
/// unsupported and only flip once a handshake actually claims it, and the
/// responder's own exact-`change::VersionHash` matching (introduced by the
/// durability-confirmation redesign this capability bit follows up on) must
/// stay exactly as strict as before: this capability bit only changes which
/// peers a whole-group durability-handoff QUERIER trusts, never how the
/// RESPONDER itself verifies a query.
#[cfg(test)]
mod version_hash_exact_capability_tests {
    use super::PeerSyncSession;
    use crate::index::SyncState;
    use crate::types::{BlockInfo, FileRecord, MaterializationPolicy, MaterializationState};
    use crate::version_vector::VersionVector;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    const GROUP: &str = "handoff-group";

    /// A live channel to nowhere, sufficient to construct a `PeerSyncSession`
    /// for a purely local, no-network test — mirrors `promoted_orphan_
    /// projection_tests::unreachable_channel`.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// Claims a sync root for the group, as linking the folder does. Tests that
    /// index a file and then run a scan or repair need this: an unmarked root
    /// whose indexed files are all absent is indistinguishable from an unmounted
    /// volume, and is refused.
    fn adopt_root(state: &SyncState, group: &str, root: &std::path::Path) {
        crate::root_identity::VerifiedRoot::open(root, group, state).unwrap();
    }

    async fn new_session(
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Arc<PeerSyncSession> {
        PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state,
            store,
            vec![GROUP.to_string()],
            HashMap::new(),
        )
    }

    /// A session holding no sync root for a group must refuse to resolve a
    /// local path for it, not fall back to a relative one.
    ///
    /// `new_session` above builds exactly that shape: shared groups, empty
    /// `sync_roots`. With the old empty-path default, `local_file_path` returned
    /// a bare relative `"file.txt"`, so every write for the group landed under
    /// the process's working directory instead of the user's folder — and
    /// `verify_write_target` could not catch it, because its fast path asks
    /// whether the target's parent IS the root, and `""` is trivially the parent
    /// of `"file.txt"`. Both the path and its guard failed open together.
    #[tokio::test]
    async fn missing_sync_root_refuses_to_resolve_a_local_path() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        let resolved = session.local_file_path(GROUP, "file.txt");
        assert!(
            resolved.is_err(),
            "a group with no sync root must not resolve to a path at all; got {resolved:?}"
        );

        // The write guard must refuse too, rather than waving through a
        // working-directory-relative target.
        let verified = session.verify_write_target(GROUP, std::path::Path::new("file.txt"));
        assert!(
            verified.is_err(),
            "the write-target guard must reject a target it cannot prove is under a known root"
        );
    }

    /// A freshly constructed session — never having run a `ClusterConfig`
    /// handshake at all, the same starting state as a session that DID run
    /// one against a peer predating this field (which always leaves it
    /// `false`) — must report the capability as not negotiated. Recording an
    /// advertisement of `true` then flips it, mirroring `record_peer_
    /// version_present_support`'s pattern this field's negotiation copies.
    #[tokio::test]
    async fn defaults_unsupported_and_flips_once_advertised() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        assert!(
            !session.version_hash_exact_negotiated(),
            "a session that never completed the handshake must default to unsupported, exactly \
             like a peer that predates the field"
        );

        session.record_peer_version_hash_exact_support(true);
        assert!(
            session.version_hash_exact_negotiated(),
            "recording a peer's advertised support must flip the negotiated flag"
        );

        // A `false` advertisement (or none at all) must never clear an
        // already-recorded `true` — the field only ever latches on, exactly
        // like every other one-shot capability flag in this file.
        session.record_peer_version_hash_exact_support(false);
        assert!(
            session.version_hash_exact_negotiated(),
            "a later false/absent advertisement must not un-negotiate an already-confirmed \
             capability"
        );
    }

    /// This build's own outgoing handshake always advertises the capability
    /// — it always enforces the exact-hash check on the answering side, so
    /// advertising anything else would be a lie a peer could rely on.
    #[tokio::test]
    async fn this_build_always_advertises_the_capability() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        let msg = session.cluster_config_message();
        let Some(proto::sync_message::Payload::ClusterConfig(config)) = msg.payload else {
            panic!("cluster_config_message must produce a ClusterConfig payload");
        };
        assert!(
            config.supports_version_hash_exact,
            "this build's responder always enforces the exact-version-hash check, so it must \
             always advertise that capability"
        );
    }

    /// Regression lock on `holds_version_durably`'s pre-existing behavior:
    /// this capability-bit follow-up changes nothing about how the
    /// RESPONDER itself verifies a query. A retained version whose block
    /// list happens to coincide with the query's (here, because only the
    /// mtime differs) must still be rejected when the queried `version_hash`
    /// does not equal that retained version's actual identity; the exact
    /// matching hash is still accepted; and an absent `version_hash` (a
    /// querier built before that field existed) still fails closed rather
    /// than falling back to a block-hash-only match.
    #[tokio::test]
    async fn holds_version_durably_requires_exact_hash_and_group_provenance() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // `holds_version_durably`'s first condition requires this device be
        // a full replica (Eager materialization policy, the default) of the
        // group.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();

        let content = b"same bytes, different metadata";
        let hash_hex = store.put(content).unwrap();
        let hash_bytes = hex::decode(hash_hex.as_str()).unwrap();

        let mut version = VersionVector::new();
        version.increment("device-a");
        let record = FileRecord {
            path: "a.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            version,
            blocks: vec![BlockInfo {
                hash: hash_bytes.clone(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        };
        state.upsert_file(GROUP, &record).unwrap();
        let retained = state.list_versions(GROUP, "a.bin").unwrap();
        assert_eq!(retained.len(), 1, "the single upsert retains exactly one version");
        let actual_version_hash = retained[0].version_hash.0.to_vec();

        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );

        let base_query = proto::VersionPresentQuery {
            request_id: 1,
            folder_group_id: GROUP.to_string(),
            file_path: "a.bin".to_string(),
            block_hashes: vec![hash_bytes],
            for_handoff: true,
            version_hash: Vec::new(),
            block_sizes: vec![content.len() as u32],
        };

        let mismatched =
            proto::VersionPresentQuery { version_hash: vec![0xEEu8; 32], ..base_query.clone() };
        assert!(
            !session.holds_version_durably(&mismatched),
            "block_hashes matching alone must not satisfy a for_handoff query whose \
             version_hash does not equal the retained version's actual identity"
        );

        let matching =
            proto::VersionPresentQuery { version_hash: actual_version_hash, ..base_query.clone() };
        assert!(
            !session.holds_version_durably(&matching),
            "global block presence without this group's provenance must not prove custody"
        );

        state
            .record_group_block_provenance(GROUP, std::slice::from_ref(&matching.block_hashes[0]))
            .unwrap();
        assert!(
            session.holds_version_durably(&matching),
            "the retained version's own exact version_hash alongside matching block_hashes/\
             block_sizes and group provenance must be confirmed present"
        );

        assert!(
            !session.holds_version_durably(&base_query),
            "an absent version_hash (a querier that predates the field) must still fail closed, \
             not fall back to a block-hash-only match"
        );
    }

    /// Regression (data-loss): the LIVE peer-receive materialize path must
    /// itself journal a durable materialization intent, so a crash *after* it
    /// commits a brand-new `Hydrated` row but *before* the temp-write-then-rename
    /// lands is recovered by reconstructing the file — never misclassified as an
    /// offline delete and tombstoned group-wide.
    ///
    /// This drives the REAL `PeerSyncSession::materialize` eager path for a
    /// brand-new received file and simulates the crash by forcing the
    /// post-upsert disk-headroom preflight to fail: an error injected AFTER the
    /// durable row commit but BEFORE any file write, which leaves exactly the
    /// on-disk/index state a real crash-before-rename leaves — a `Hydrated` row,
    /// its blocks present locally, and no file on disk. Crucially it writes NO
    /// intent by hand; the whole point is that `materialize` must have written
    /// it. On the pre-fix code the live path wrote no intent, so this same state
    /// was read as an offline delete and the fresh file was tombstoned — the
    /// test is RED there and GREEN once the live path journals the intent.
    #[tokio::test]
    async fn live_materialize_crash_before_rename_is_reconstructed_not_deleted() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        // The received content is already in this device's block store (the
        // eager fetch completed before the simulated crash), so
        // `ensure_blocks_present` short-circuits with no peer round trip and the
        // reconstruct during repair needs no network.
        let content = b"a freshly received file the crash must not destroy".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let mut version = VersionVector::new();
        version.increment("device-a");
        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            version,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // Force the post-upsert headroom preflight (which runs AFTER the durable
        // `Hydrated` row commit and BEFORE the reconstruct-to-disk write) to
        // fail, standing in for a process kill in that exact window. An
        // impossible headroom reserve guarantees `check_disk_headroom` rejects.
        session.set_headroom_enforced(true);
        session.set_headroom_override_bytes(Some(u64::MAX));

        // Drive the REAL eager materialize path. It must return the injected
        // disk-pressure error, having already committed the row.
        let out_path = sync_root.join("doc.txt");
        let result =
            session.materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a").await;
        assert!(result.is_err(), "the injected preflight failure must surface as an error");

        // The crash-before-rename state, produced entirely by the live path:
        // Hydrated row, blocks present, no file on disk — and, with the fix in
        // place, a materialization intent the live path wrote itself.
        assert_eq!(
            state.get_materialization_state(GROUP, "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated),
            "the durable row must have committed as Hydrated before the crash window"
        );
        assert!(!out_path.exists(), "no file was written before the simulated crash");
        assert!(
            state.has_materialization_intent(GROUP, "doc.txt").unwrap(),
            "the LIVE materialize path must journal a durable intent before committing the \
             brand-new Hydrated row, so a crash in this window is recoverable"
        );

        // Repair (the production plain, no-emitter variant the daemon's startup/
        // periodic sweep runs) must RECONSTRUCT from the present blocks — never
        // classify this as an offline delete.
        let report = crate::materialization::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
        )
        .unwrap();

        assert_eq!(
            report.reconstructed,
            vec!["doc.txt".to_string()],
            "a live-materialize crash-before-rename must be reconstructed"
        );
        assert!(
            report.offline_deleted.is_empty(),
            "the fresh file must NOT be misclassified as an offline deletion"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            content,
            "the reconstructed file must have exactly the received bytes"
        );
        assert!(
            state.get_file(GROUP, "doc.txt").unwrap().is_some_and(|r| !r.deleted),
            "the index row must remain a live (not-deleted) record — no tombstone"
        );
    }

    /// The converse guardrail on the same seam: a FULLY successful live
    /// materialize must CLEAR its intent (right after the durable rename, before
    /// the post-write exec-bit touch), so the intent can never linger under a
    /// `Hydrated`+present file. If it lingered, a later genuine offline delete of
    /// that path would read `missing + intent present` and wrongly resurrect the
    /// file from its still-present blocks — the exact misclassification the
    /// journal exists to prevent, in the opposite direction. This drives the real
    /// `materialize` to success, asserts no intent remains, then deletes the file
    /// offline and asserts repair classifies it as a delete, not a reconstruct.
    #[tokio::test]
    async fn live_materialize_success_clears_intent_so_a_later_offline_delete_is_not_resurrected() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        let content = b"received, materialized cleanly, later deleted offline".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();

        let mut version = VersionVector::new();
        version.increment("device-a");
        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            version,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&sync_root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
        );

        // No injected fault: the real eager materialize runs to completion.
        let out_path = sync_root.join("doc.txt");
        session
            .materialize(GROUP, &record, MaterializationPolicy::Eager, "device-a")
            .await
            .expect("a clean materialize must succeed");
        assert_eq!(std::fs::read(&out_path).unwrap(), content, "the file must be materialized");
        assert_eq!(
            state.get_materialization_state(GROUP, "doc.txt").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        // The crux: the success path cleared the intent after the durable rename.
        assert!(
            !state.has_materialization_intent(GROUP, "doc.txt").unwrap(),
            "a completed materialize must leave NO materialization intent"
        );

        // The user deletes the file while the daemon is stopped. The row is still
        // Hydrated, blocks still present, and — because the intent was cleared —
        // this is a genuine offline delete, not a crash.
        std::fs::remove_file(&out_path).unwrap();
        let report = crate::materialization::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
        )
        .unwrap();

        assert!(
            report.reconstructed.is_empty(),
            "a cleanly-materialized-then-offline-deleted file must NOT be reconstructed"
        );
        assert_eq!(
            report.offline_deleted,
            vec!["doc.txt".to_string()],
            "the missing file with no intent must be classified as an offline deletion"
        );
        assert!(!out_path.exists(), "repair must not resurrect the offline-deleted file");
    }
}

/// The `HandoffLeaseRequest`/`HandoffLeaseGrant` peer-to-peer wire exchange:
/// a real requester session talking to a real responder session over a live
/// (loopback) `PeerChannel` pair, mirroring `yadorilink-daemon`'s own
/// `connect_two_daemons`/`spawn_paired_session` test harness but pared down
/// to just what this exchange needs (no change-DAG signing, no forwarding).
/// The digest-comparison decision itself is source-daemon-side
/// (`yadorilink-daemon`'s `handoff_lease_grant_matches_digest`, unit-tested
/// there) — these tests cover only the wire round trip and the responder's
/// authorization/no-responder-installed fail-closed defaults.
#[cfg(test)]
mod handoff_lease_wire_tests {
    use super::{HandoffLeaseResponder, PeerHandoffLeaseGrant, PeerSyncSession};
    use crate::index::SyncState;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    const GROUP: &str = "handoff-lease-group";

    /// A fixed-answer `HandoffLeaseResponder`: returns whatever
    /// `Option<PeerHandoffLeaseGrant>` it was constructed with, regardless of
    /// which group is asked about — enough to prove the wire round trip
    /// carries a real responder's answer faithfully in both directions.
    struct FixedResponder(Option<PeerHandoffLeaseGrant>);
    impl HandoffLeaseResponder for FixedResponder {
        fn request_handoff_lease<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }

        fn release_handoff_lease<'a>(
            &'a self,
            _group_id: &'a str,
            _lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }
    }

    struct ReleaseRecordingResponder(tokio::sync::mpsc::UnboundedSender<(String, String)>);
    impl HandoffLeaseResponder for ReleaseRecordingResponder {
        fn request_handoff_lease<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
            Box::pin(async { None })
        }

        fn release_handoff_lease<'a>(
            &'a self,
            group_id: &'a str,
            lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let tx = self.0.clone();
            let group_id = group_id.to_string();
            let lease_id = lease_id.to_string();
            Box::pin(async move {
                let _ = tx.send((group_id, lease_id));
            })
        }
    }

    /// Two real, loopback-UDP-connected sessions sharing `GROUP`: `device-a`
    /// (the requester in every test below) and `device-b` (the responder).
    /// Both `run()` loops are spawned so each side actually processes the
    /// other's messages, the same "live pair" shape
    /// `promoted_orphan_projection_tests`/`version_hash_exact_capability_
    /// tests` use for a single unreachable-peer session, extended to a real
    /// two-sided connection.
    async fn connected_pair() -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
        use boringtun::x25519::{PublicKey, StaticSecret};

        let mut secret_a_bytes = [0u8; 32];
        rand::fill(&mut secret_a_bytes);
        let secret_a = StaticSecret::from(secret_a_bytes);
        let public_a = PublicKey::from(&secret_a);
        let mut secret_b_bytes = [0u8; 32];
        rand::fill(&mut secret_b_bytes);
        let secret_b = StaticSecret::from(secret_b_bytes);
        let public_b = PublicKey::from(&secret_b);

        let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        let hub_a = yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a));
        let hub_b = yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b));

        let channel_a =
            yadorilink_transport::PeerChannel::connect(secret_a, public_b, 0, vec![addr_b], hub_a)
                .await
                .unwrap();
        let channel_b =
            yadorilink_transport::PeerChannel::connect(secret_b, public_a, 0, vec![addr_a], hub_b)
                .await
                .unwrap();

        let store_dir_a = tempfile::tempdir().unwrap();
        let store_dir_b = tempfile::tempdir().unwrap();
        let store_a: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-a".to_string(),
            "device-b".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-a".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
        );

        tokio::spawn({
            let session = session_a.clone();
            async move {
                let _ = session.run().await;
            }
        });
        tokio::spawn({
            let session = session_b.clone();
            async move {
                let _ = session.run().await;
            }
        });
        // Let the handshake / initial index exchange settle before a test
        // sends its real request, matching the same short settle-wait
        // `yadorilink-daemon`'s own paired-session integration tests use.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        (session_a, session_b)
    }

    /// The normal-handoff path's wire half: the responder's real
    /// `HandoffLeaseResponder` grants a lease, and the requester receives
    /// exactly that lease id, root digest, and expiry back — faithfully, not
    /// merely a truthy/falsy bit. (The requester does not itself compare the
    /// digest against anything; that decision is source-daemon-side and
    /// unit-tested directly there — see this module's doc comment.)
    #[tokio::test]
    async fn requester_receives_the_responders_real_grant() {
        let (session_a, session_b) = connected_pair().await;
        let expected_digest = [42u8; 32];
        session_b.set_handoff_lease_responder(Arc::new(FixedResponder(Some(
            PeerHandoffLeaseGrant {
                lease_id: "lease-1".to_string(),
                root_digest: expected_digest,
                expires_at_unix: 999,
            },
        ))));

        let grant = session_a
            .request_handoff_lease_from_peer(GROUP)
            .await
            .expect("a responder that grants a lease must be relayed back to the requester");
        assert_eq!(grant.lease_id, "lease-1");
        assert_eq!(grant.root_digest, expected_digest);
        assert_eq!(grant.expires_at_unix, 999);
    }

    #[tokio::test]
    async fn requester_can_release_a_granted_lease_by_id() {
        let (session_a, session_b) = connected_pair().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        session_b.set_handoff_lease_responder(Arc::new(ReleaseRecordingResponder(tx)));

        session_a.release_handoff_lease_to_peer(GROUP, "lease-mismatch").await.unwrap();

        let released = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("release message should arrive")
            .expect("release recorder should remain open");
        assert_eq!(released, (GROUP.to_string(), "lease-mismatch".to_string()));
    }

    /// A responder that explicitly declines (its own readiness check
    /// failed, no coordination-plane config, etc.) must relay `None` back to
    /// the requester, not a falsely-successful grant.
    #[tokio::test]
    async fn requester_gets_none_when_the_responder_declines() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_lease_responder(Arc::new(FixedResponder(None)));

        assert!(
            session_a.request_handoff_lease_from_peer(GROUP).await.is_none(),
            "an explicit decline from the responder must never surface as a grant"
        );
    }

    /// No responder installed at all (every pre-this-change test/call site,
    /// and a build too old to have this feature) must answer `granted =
    /// false` — the same fail-closed default an installed-but-declining
    /// responder produces above, never left unanswered or panicking.
    #[tokio::test]
    async fn requester_gets_none_when_the_peer_has_no_responder_installed() {
        let (session_a, _session_b) = connected_pair().await;
        // Deliberately never call `set_handoff_lease_responder` on `_session_b`.
        assert!(
            session_a.request_handoff_lease_from_peer(GROUP).await.is_none(),
            "no installed responder must fail closed, not hang or panic"
        );
    }

    /// A request for a group the two sessions do NOT share must be refused
    /// without ever consulting the responder — mirrors `handle_block_
    /// request`'s own unauthorized-group check. Proven by pointing the
    /// request at a group name neither session was constructed with, while
    /// the responder is set up to grant unconditionally: if authorization
    /// were skipped, this would spuriously succeed.
    #[tokio::test]
    async fn requester_gets_none_for_an_unshared_group_even_if_the_responder_would_grant() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_lease_responder(Arc::new(FixedResponder(Some(
            PeerHandoffLeaseGrant {
                lease_id: "lease-should-never-be-seen".to_string(),
                root_digest: [1u8; 32],
                expires_at_unix: 999,
            },
        ))));

        assert!(
            session_a.request_handoff_lease_from_peer("some-other-group").await.is_none(),
            "a group neither session shares must never yield a grant, regardless of what an \
             installed responder would otherwise answer"
        );
    }

    /// `handle_handoff_lease_grant`'s own fail-closed parsing: a malformed
    /// (not exactly 32 bytes) `root_digest` on an otherwise-`granted = true`
    /// reply must resolve the pending request to `None`, not panic or
    /// silently truncate/pad the digest. Exercised directly (no wire needed)
    /// since this is pure parsing logic on an already-decoded message.
    #[tokio::test]
    async fn malformed_root_digest_length_fails_closed_rather_than_panicking() {
        let (session_a, _session_b) = connected_pair().await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        session_a.pending_handoff_lease.lock().unwrap_or_else(|p| p.into_inner()).insert(4242, tx);
        session_a.handle_handoff_lease_grant(proto::HandoffLeaseGrant {
            request_id: 4242,
            granted: true,
            lease_id: "lease-x".to_string(),
            root_digest: vec![1, 2, 3], // not 32 bytes
            expires_at_unix: 100,
        });
        assert!(
            rx.await.unwrap().is_none(),
            "a malformed root_digest must resolve the pending request to None, not panic"
        );
    }
}

/// The `HandoffTicketRequest`/`HandoffTicketGrant` peer-to-peer wire
/// exchange — the removed-device-ticket counterpart to
/// `handoff_lease_wire_tests` above, same harness, pared down the same way.
/// The "B attests its own roots, not X's" trust decision lives entirely in
/// what a real `HandoffTicketResponder` (`DaemonState`) computes -- these
/// tests cover only the wire round trip and the responder's authorization/
/// no-responder-installed fail-closed defaults, exactly like their
/// `handoff_lease` counterparts.
#[cfg(test)]
mod handoff_ticket_wire_tests {
    use super::{HandoffTicketResponder, PeerHandoffTicketGrant, PeerSyncSession};
    use crate::index::SyncState;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    const GROUP: &str = "handoff-ticket-group";

    /// A fixed-answer `HandoffTicketResponder`: returns whatever
    /// `Option<PeerHandoffTicketGrant>` it was constructed with, regardless
    /// of which group is asked about — enough to prove the wire round trip
    /// carries a real responder's answer faithfully in both directions.
    struct FixedResponder(Option<PeerHandoffTicketGrant>);
    impl HandoffTicketResponder for FixedResponder {
        fn request_handoff_ticket<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }

        fn release_handoff_ticket<'a>(
            &'a self,
            _group_id: &'a str,
            _target_device_id: &'a str,
            _lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }
    }

    struct ReleaseRecordingResponder(tokio::sync::mpsc::UnboundedSender<(String, String, String)>);
    impl HandoffTicketResponder for ReleaseRecordingResponder {
        fn request_handoff_ticket<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
            Box::pin(async { None })
        }

        fn release_handoff_ticket<'a>(
            &'a self,
            group_id: &'a str,
            target_device_id: &'a str,
            lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let tx = self.0.clone();
            let values = (group_id.to_string(), target_device_id.to_string(), lease_id.to_string());
            Box::pin(async move {
                let _ = tx.send(values);
            })
        }
    }

    /// Same loopback-UDP two-session harness as `handoff_lease_wire_tests::
    /// connected_pair`, duplicated locally (rather than shared) so this
    /// module stays self-contained the same way its sibling is -- neither
    /// module depends on the other's private test helpers.
    async fn connected_pair() -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
        use boringtun::x25519::{PublicKey, StaticSecret};

        let mut secret_a_bytes = [0u8; 32];
        rand::fill(&mut secret_a_bytes);
        let secret_a = StaticSecret::from(secret_a_bytes);
        let public_a = PublicKey::from(&secret_a);
        let mut secret_b_bytes = [0u8; 32];
        rand::fill(&mut secret_b_bytes);
        let secret_b = StaticSecret::from(secret_b_bytes);
        let public_b = PublicKey::from(&secret_b);

        let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        let hub_a = yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a));
        let hub_b = yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b));

        let channel_a =
            yadorilink_transport::PeerChannel::connect(secret_a, public_b, 0, vec![addr_b], hub_a)
                .await
                .unwrap();
        let channel_b =
            yadorilink_transport::PeerChannel::connect(secret_b, public_a, 0, vec![addr_a], hub_b)
                .await
                .unwrap();

        let store_dir_a = tempfile::tempdir().unwrap();
        let store_dir_b = tempfile::tempdir().unwrap();
        let store_a: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-x".to_string(),
            "device-b".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-x".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
        );

        tokio::spawn({
            let session = session_a.clone();
            async move {
                let _ = session.run().await;
            }
        });
        tokio::spawn({
            let session = session_b.clone();
            async move {
                let _ = session.run().await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        (session_a, session_b)
    }

    /// The operating device (X, `session_a`) asks the removed device (B,
    /// `session_b`) for a ticket; B's real `HandoffTicketResponder` grants
    /// one, and X receives exactly that lease id and expiry back.
    #[tokio::test]
    async fn requester_receives_the_responders_real_grant() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_ticket_responder(Arc::new(FixedResponder(Some(
            PeerHandoffTicketGrant {
                lease_id: Some("ticket-lease-1".to_string()),
                target_device_id: Some("device-c".to_string()),
                expires_at_unix: 999,
            },
        ))));

        let grant = session_a
            .request_handoff_ticket_from_peer(GROUP)
            .await
            .expect("a responder that grants a ticket must be relayed back to the requester");
        assert_eq!(grant.lease_id.as_deref(), Some("ticket-lease-1"));
        assert_eq!(grant.target_device_id.as_deref(), Some("device-c"));
        assert_eq!(grant.expires_at_unix, 999);
    }

    #[tokio::test]
    async fn requester_can_release_an_unconsumed_ticket_by_ids() {
        let (session_a, session_b) = connected_pair().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        session_b.set_handoff_ticket_responder(Arc::new(ReleaseRecordingResponder(tx)));

        session_a.release_handoff_ticket_to_peer(GROUP, "device-c", "lease-partial").await.unwrap();

        let released = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("ticket release should arrive")
            .expect("release recorder should remain open");
        assert_eq!(
            released,
            (GROUP.to_string(), "device-c".to_string(), "lease-partial".to_string())
        );
    }

    /// A vacuously-ready empty root set: B grants with no `lease_id` at all
    /// (nothing to hand off) -- must still surface as `granted = true` with
    /// `lease_id = None`, not collapse to "not granted".
    #[tokio::test]
    async fn a_grant_with_no_lease_id_still_relays_as_granted() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_ticket_responder(Arc::new(FixedResponder(Some(
            PeerHandoffTicketGrant { lease_id: None, target_device_id: None, expires_at_unix: 0 },
        ))));

        let grant = session_a
            .request_handoff_ticket_from_peer(GROUP)
            .await
            .expect("an empty-root-set grant is still a grant");
        assert_eq!(grant.lease_id, None);
        assert_eq!(grant.target_device_id, None);
    }

    /// A responder that explicitly declines (B could not pin its own roots
    /// at any confirmed peer) must relay `None` back to the requester, not a
    /// falsely-successful grant.
    #[tokio::test]
    async fn requester_gets_none_when_the_responder_declines() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_ticket_responder(Arc::new(FixedResponder(None)));

        assert!(
            session_a.request_handoff_ticket_from_peer(GROUP).await.is_none(),
            "an explicit decline from the responder must never surface as a grant"
        );
    }

    /// No responder installed at all (every pre-this-change test/call site,
    /// and a build too old to have this feature) must answer `granted =
    /// false` — the same fail-closed default an installed-but-declining
    /// responder produces above, never left unanswered or panicking. This is
    /// also exactly the OFFLINE-equivalent wire behavior: a peer that never
    /// wires up a ticket responder answers indistinguishably from one that
    /// tried and failed.
    #[tokio::test]
    async fn requester_gets_none_when_the_peer_has_no_responder_installed() {
        let (session_a, _session_b) = connected_pair().await;
        assert!(
            session_a.request_handoff_ticket_from_peer(GROUP).await.is_none(),
            "no installed responder must fail closed, not hang or panic"
        );
    }

    /// A request for a group the two sessions do NOT share must be refused
    /// without ever consulting the responder — mirrors `handle_handoff_
    /// lease_request`'s own unauthorized-group check.
    #[tokio::test]
    async fn requester_gets_none_for_an_unshared_group_even_if_the_responder_would_grant() {
        let (session_a, session_b) = connected_pair().await;
        session_b.set_handoff_ticket_responder(Arc::new(FixedResponder(Some(
            PeerHandoffTicketGrant {
                lease_id: Some("ticket-should-never-be-seen".to_string()),
                target_device_id: Some("device-c".to_string()),
                expires_at_unix: 999,
            },
        ))));

        assert!(
            session_a.request_handoff_ticket_from_peer("some-other-group").await.is_none(),
            "a group neither session shares must never yield a grant, regardless of what an \
             installed responder would otherwise answer"
        );
    }
}

/// The `RebootstrapSnapshotRequest`/`RebootstrapSnapshotResponse` peer-to-
/// peer wire exchange — same loopback-UDP two-session harness as
/// `handoff_lease_wire_tests`/`handoff_ticket_wire_tests`, duplicated
/// locally the same way. `RebootstrapHandler`'s methods are synchronous (no
/// live coordination-plane round trip, unlike the handoff-lease/ticket
/// case), so the fixed test double here is simpler than those modules'
/// `FixedResponder`. The signer-authorization/trust decisions themselves are
/// daemon-side (`DaemonRebootstrapHandler`, unit-tested in
/// `yadorilink-daemon::rebootstrap_handler`) — these tests cover the wire
/// round trip, the handler-authorization/no-handler-installed fail-closed
/// defaults, and `handle_rebootstrap_snapshot_response`'s own
/// session-identity check (Issue A: a response must be discarded if its
/// claimed signer does not match the actual connected peer, even when the
/// signature itself is perfectly valid for a different device).
#[cfg(test)]
mod rebootstrap_wire_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    use super::{PeerSyncSession, PreparedRebootstrap, RebootstrapHandler};
    use crate::change::{ChangeHash, DeviceId, FolderGroupId};
    use crate::compaction::Checkpoint;
    use crate::index::SyncState;
    use crate::rebootstrap::{RebootstrapRequired, SnapshotManifest};

    const GROUP: &str = "rebootstrap-group";

    fn prepared_signed_by(signer: &str, key: &SigningKey) -> PreparedRebootstrap {
        let frontier = ChangeHash([9u8; 32]);
        let checkpoint = Checkpoint::new(FolderGroupId(GROUP.into()), vec![frontier], [1u8; 32]);
        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![frontier],
            None,
            DeviceId(signer.into()),
            key,
        )
        .unwrap();
        let required = RebootstrapRequired::new_signed(ChangeHash([2u8; 32]), manifest, key);
        PreparedRebootstrap { required, snapshot_bytes: vec![7, 7, 7] }
    }

    /// Returns whatever `Option<PreparedRebootstrap>` it was constructed
    /// with, regardless of which group/hash is asked about — enough to
    /// prove the wire round trip carries a real handler's answer faithfully.
    struct FixedHandler(Option<PreparedRebootstrap>);
    impl RebootstrapHandler for FixedHandler {
        fn prepare_rebootstrap(
            &self,
            _group_id: &str,
            _requested_hash: ChangeHash,
        ) -> Result<Option<PreparedRebootstrap>, crate::SyncError> {
            Ok(self.0.clone())
        }

        fn verify_rebootstrap(
            &self,
            _required: &RebootstrapRequired,
        ) -> Result<(), crate::SyncError> {
            Ok(())
        }

        fn install_rebootstrap(
            &self,
            _required: &RebootstrapRequired,
            _snapshot_bytes: &[u8],
        ) -> Result<(), crate::SyncError> {
            Ok(())
        }
    }

    /// Same loopback-UDP two-session harness as `handoff_lease_wire_tests::
    /// connected_pair`, duplicated locally, session_a is `device-a` (the
    /// requester in every test below), session_b is `device-b` (the
    /// responder).
    async fn connected_pair() -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
        use boringtun::x25519::{PublicKey, StaticSecret};

        let mut secret_a_bytes = [0u8; 32];
        rand::fill(&mut secret_a_bytes);
        let secret_a = StaticSecret::from(secret_a_bytes);
        let public_a = PublicKey::from(&secret_a);
        let mut secret_b_bytes = [0u8; 32];
        rand::fill(&mut secret_b_bytes);
        let secret_b = StaticSecret::from(secret_b_bytes);
        let public_b = PublicKey::from(&secret_b);

        let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        let hub_a = yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a));
        let hub_b = yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b));

        let channel_a =
            yadorilink_transport::PeerChannel::connect(secret_a, public_b, 0, vec![addr_b], hub_a)
                .await
                .unwrap();
        let channel_b =
            yadorilink_transport::PeerChannel::connect(secret_b, public_a, 0, vec![addr_a], hub_b)
                .await
                .unwrap();

        let store_dir_a = tempfile::tempdir().unwrap();
        let store_dir_b = tempfile::tempdir().unwrap();
        let store_a: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-a".to_string(),
            "device-b".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-a".to_string(),
            Arc::new(SyncState::open_in_memory().unwrap()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
        );

        tokio::spawn({
            let session = session_a.clone();
            async move {
                let _ = session.run().await;
            }
        });
        tokio::spawn({
            let session = session_b.clone();
            async move {
                let _ = session.run().await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        (session_a, session_b)
    }

    /// The requester receives exactly the responder's real prepared
    /// snapshot: the same signed `RebootstrapRequired` and snapshot bytes,
    /// carried faithfully over the wire.
    #[tokio::test]
    async fn requester_receives_the_responders_real_prepared_snapshot() {
        let (session_a, session_b) = connected_pair().await;
        let key = SigningKey::from_bytes(&[11u8; 32]);
        // Signed by "device-b" -- the actual connected peer of session_a --
        // so this exercises the success path, not the session-identity
        // mismatch case covered separately below.
        let prepared = prepared_signed_by("device-b", &key);
        let expected_required = prepared.required.clone();
        session_b.set_rebootstrap_handler(Arc::new(FixedHandler(Some(prepared))));

        let received = session_a
            .request_rebootstrap_snapshot_from_peer(GROUP, ChangeHash([3u8; 32]))
            .await
            .expect("a handler that prepares a snapshot must be relayed back to the requester");
        assert_eq!(received.required, expected_required);
        assert_eq!(received.snapshot_bytes, vec![7, 7, 7]);
    }

    /// No handler installed at all must answer `granted = false` -- fail
    /// closed, never hang or panic.
    #[tokio::test]
    async fn requester_gets_none_when_the_peer_has_no_handler_installed() {
        let (session_a, _session_b) = connected_pair().await;
        assert!(
            session_a
                .request_rebootstrap_snapshot_from_peer(GROUP, ChangeHash([3u8; 32]))
                .await
                .is_none(),
            "no installed handler must fail closed, not hang or panic"
        );
    }

    /// A request for a group the two sessions do NOT share must be refused
    /// without ever consulting the handler.
    #[tokio::test]
    async fn requester_gets_none_for_an_unshared_group_even_if_the_handler_would_grant() {
        let (session_a, session_b) = connected_pair().await;
        let key = SigningKey::from_bytes(&[11u8; 32]);
        session_b.set_rebootstrap_handler(Arc::new(FixedHandler(Some(prepared_signed_by(
            "device-b", &key,
        )))));

        assert!(
            session_a
                .request_rebootstrap_snapshot_from_peer("some-other-group", ChangeHash([3u8; 32]))
                .await
                .is_none(),
            "a group neither session shares must never yield a response, regardless of what an \
             installed handler would otherwise answer"
        );
    }

    /// Issue A: a response whose decoded `RebootstrapRequired` claims to be
    /// signed by some device OTHER than the session's actual connected peer
    /// must be discarded, even though the signature itself is perfectly
    /// valid (it really was signed by that other device's key) -- a relay
    /// or a misbehaving peer forwarding a genuinely-signed manifest from a
    /// THIRD device must not have it accepted as if THIS peer vouched for
    /// it. Proven over the real wire: `session_b` (whose actual identity is
    /// "device-b") answers with a manifest claiming "device-c" signed it.
    #[tokio::test]
    async fn session_identity_mismatch_is_rejected_even_with_a_valid_signature() {
        let (session_a, session_b) = connected_pair().await;
        let other_device_key = SigningKey::from_bytes(&[12u8; 32]);
        let impersonating_prepared = prepared_signed_by("device-c", &other_device_key);
        session_b.set_rebootstrap_handler(Arc::new(FixedHandler(Some(impersonating_prepared))));

        assert!(
            session_a
                .request_rebootstrap_snapshot_from_peer(GROUP, ChangeHash([3u8; 32]))
                .await
                .is_none(),
            "a response claiming a signer other than the actual connected peer must be \
             discarded, not relayed to the caller"
        );
    }
}

/// Reproduces, at the wire-negotiation layer, the restart bug
/// `local_change.rs`'s `offline_edit_after_existing_dag_history_must_
/// append_new_head_on_restart` proves at the index/DAG layer: a change-
/// history-aware peer only ever learns about a remote edit through a
/// `HeadsAnnounce` (never a legacy full-index resync, once both sides have
/// negotiated the DAG). If the local device's restart sequence updates its
/// index for an offline edit without appending a matching DAG change (see
/// `dag_import`'s module doc on why `ensure_initial_import` is a no-op once
/// a group already has history), the heads it then announces are byte-
/// identical to what it announced before the edit — so a peer that already
/// holds that pre-edit history has nothing to request and never converges,
/// even though the announcer's own on-disk file and local index have moved
/// on.
///
/// No real two-way network round trip is needed to prove this: a peer's
/// only DAG-negotiated route to new content is `handle_heads_announce`
/// computing which of the announced heads it doesn't already have
/// (`peer_session.rs`'s own `handle_heads_announce`, called directly here)
/// and requesting exactly those — so an announce carrying only already-known
/// heads is observable proof the peer was never told about the edit,
/// without depending on any live send/receive timing.
#[cfg(test)]
mod dag_negotiated_restart_regression_tests {
    use super::{change_hash_to_wire, ChangeAuthenticator, PeerSyncSession};
    use crate::change::Op;
    use crate::dag_import;
    use crate::dag_store::ChangeEmitter;
    use crate::ignore_patterns::EffectiveIgnoreSet;
    use crate::index::SyncState;
    use crate::local_change::LocalChangeProcessor;
    use crate::watcher::{FsChangeEvent, FsChangeKind};
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::{BlockStore, FsBlockStore};

    const GROUP: &str = "restart-dag-negotiated-group";

    /// Pins one author's verifying key and treats it as a writer — the same
    /// shape `promoted_orphan_projection_tests`' `TestAuthenticator` uses.
    struct TestAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for TestAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    /// A live channel with no reachable peer on the other end, exactly as
    /// `promoted_orphan_projection_tests::unreachable_channel` builds one:
    /// sending on it simply queues a datagram nobody reads (the send half
    /// stays open), which is all `handle_heads_announce` needs to run its
    /// real request-computation logic without a live two-sided connection.
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    #[tokio::test]
    async fn startup_scan_change_must_reach_dag_negotiated_peer() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let author_verifying_key = signing_key.verifying_key().to_bytes();

        // ---- The local device: existing DAG history, then an offline edit
        // ---- picked up only by the restart scan.
        let store_dir_a = tempfile::tempdir().unwrap();
        let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let state_a = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();

        let emitter = Arc::new(ChangeEmitter::new("device-a", signing_key.clone()));
        let processor =
            LocalChangeProcessor::new(state_a.clone(), store_a.clone(), "device-a".to_string())
                .with_change_emitter(emitter.clone());

        let file_path = root.join("notes.txt");
        std::fs::write(&file_path, b"version one").unwrap();
        processor
            .process_event(
                GROUP,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();
        let heads_v1 = state_a.dag_group_heads(GROUP).unwrap();
        assert_eq!(heads_v1.len(), 1, "sanity: one DAG head after the initial live edit");
        let change_v1 = state_a.dag_get_change(&heads_v1[0]).unwrap().unwrap();
        let version_hash_v1 = match &change_v1.ops[0] {
            Op::Create { version, .. } => *version,
            other => panic!("expected the initial edit to be a Create op, got {other:?}"),
        };
        let version_v1 = state_a.dag_get_file_version(GROUP, &version_hash_v1).unwrap().unwrap();

        // ---- The peer: a change-history-aware device that already synced
        // ---- up to the pre-restart head, exactly as if it had connected
        // ---- and pulled it earlier.
        let store_dir_b = tempfile::tempdir().unwrap();
        let store_b: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());
        // Retain a handle to the peer's block store so the test can supply the
        // block content the peer would fetch over a live channel — the
        // `unreachable_channel` delivers no `BlockResponse`, so without this the
        // peer's records stay content-less bootstrap scaffolds that never
        // materialize either version's bytes.
        let store_b_seed = store_b.clone();
        let state_b = Arc::new(SyncState::open_in_memory().unwrap());
        let peer_root_dir = tempfile::tempdir().unwrap();
        let peer_root = peer_root_dir.path().canonicalize().unwrap();
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state_b.add_link(&peer_root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&peer_root, GROUP, &state_b).unwrap();
        let generation = state_b.begin_group_startup(GROUP);
        state_b.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), peer_root)]);

        let session_b = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state_b.clone(),
            store_b,
            vec![GROUP.to_string()],
            sync_roots,
        );
        session_b.set_change_authenticator(Arc::new(TestAuthenticator {
            author_device_id: "device-a".to_string(),
            author_verifying_key,
        }));

        // The peer fetches v1's block content as part of pulling the
        // pre-restart head (a live channel carries it in a `BlockResponse`).
        store_b_seed.put(b"version one").unwrap();
        let batch = proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: vec![change_v1.to_wire_bytes()],
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![version_v1.canonical_encoding()],
        };
        session_b.handle_change_batch(batch).await.unwrap();
        assert!(
            state_b.dag_has_change(&heads_v1[0]).unwrap(),
            "sanity: the peer admitted the pre-restart change the normal way"
        );
        let peer_record_v1 = state_b.get_file(GROUP, "notes.txt").unwrap().unwrap();

        // ---- The local device "restarts": the file was edited offline, so
        // ---- only the startup scan (never a live `process_event`) notices
        // ---- it, exactly mirroring `local_change.rs`'s own restart test.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records =
            processor.scan_existing_files_with_ignore(GROUP, &root, &ignore_set).unwrap();
        assert!(!scan_records.is_empty(), "sanity: the restart scan must notice the offline edit");
        dag_import::ensure_initial_import(&state_a, GROUP, &emitter).unwrap();
        let heads_after_restart = state_a.dag_group_heads(GROUP).unwrap();

        // ---- The local device announces its (possibly stale) heads to the
        // ---- DAG-negotiated peer, exactly as `announce_local_commit`/the
        // ---- daemon's post-restart announce would.
        let announce = proto::HeadsAnnounce {
            folder_group_id: GROUP.to_string(),
            heads: heads_after_restart.iter().map(change_hash_to_wire).collect(),
            frontier_hint: Vec::new(),
        };
        session_b.handle_heads_announce(announce).await.unwrap();

        // The fix advanced the announced heads past what the peer holds, so
        // the announce identified a genuinely missing change the peer now
        // knows to request (with the bug the announced heads were byte-
        // identical to the peer's, so it had nothing to ask for and never
        // converged). `handle_heads_announce` requested exactly that change
        // over the channel; serve the response the announcer would send back
        // over a live connection — the change plus its file version — since
        // the test's `unreachable_channel` carries no reply of its own.
        assert_ne!(
            heads_after_restart, heads_v1,
            "the restart scan must advance the announced heads so the peer has the offline \
             edit to request"
        );
        assert!(
            !state_b.dag_has_change(&heads_after_restart[0]).unwrap(),
            "sanity: the peer is missing the newly-announced change before it is served"
        );
        let change_v2 = state_a.dag_get_change(&heads_after_restart[0]).unwrap().unwrap();
        let version_hash_v2 = change_v2
            .ops
            .iter()
            .find_map(|op| match op {
                Op::Create { version, .. } | Op::Update { version, .. } => Some(*version),
                _ => None,
            })
            .expect("the offline edit change must carry a content op");
        let version_v2 = state_a.dag_get_file_version(GROUP, &version_hash_v2).unwrap().unwrap();
        // The peer fetches the offline edit's block content, exactly as it
        // would over a live channel in response to the change request the
        // announce triggered above.
        store_b_seed.put(b"version two, edited while the daemon was stopped").unwrap();
        let batch_v2 = proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: vec![change_v2.to_wire_bytes()],
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![version_v2.canonical_encoding()],
        };
        session_b.handle_change_batch(batch_v2).await.unwrap();

        // ---- The peer must have learned about the offline edit. It must
        // ---- not still be sitting on the pre-restart (V1) content.
        let peer_record_after = state_b.get_file(GROUP, "notes.txt").unwrap().unwrap();
        assert_ne!(
            peer_record_after.blocks, peer_record_v1.blocks,
            "a DAG-heads-negotiated peer must receive the offline edit the restart scan \
             reconciled locally, not remain stuck on the pre-restart content because the \
             announced heads never advanced past what the peer already has"
        );
    }
}

/// Convergence coverage for the single-authority property the DAG engine now
/// holds outright: a concurrent edit resolves to the same winner regardless of
/// arrival order, and the materialization-audit backstop keeps repairing
/// missing on-disk content without ever resolving a concurrency. All in-process
/// and deterministic: the sessions run over a live-but-unreachable loopback
/// channel and are driven by direct `handle_message` / `handle_change_batch`
/// calls, never real datagram delivery, so nothing depends on network timing.
#[cfg(test)]
mod dag_convergence_authority_tests {
    use super::{ChangeAuthenticator, PeerSyncSession};

    use crate::change::{Change, ChangeAuth, FileMeta, FileVersion, Op, SyncPath};
    use crate::dag_store::{self, ChangeEmitter};
    use crate::index::SyncState;
    use crate::types::{FileRecord, RecordKind};
    use crate::version_vector::VersionVector;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::FsBlockStore;

    const GROUP: &str = "shared-group";
    const OLD_MTIME: i64 = 1_000; // lamport WINNER carries the OLDER mtime …
    const NEW_MTIME: i64 = 9_000; // … and the mtime winner is the lamport LOSER.

    struct Harness {
        session: Arc<PeerSyncSession>,
        state: Arc<SyncState>,
        _root: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    /// A live channel with no reachable peer: sends just queue on the open send
    /// half, so a call under test never blocks on a peer. (Same shape as the
    /// promoted-orphan projection tests.)
    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    async fn harness(local: &str, peer: &str, dag_negotiated: bool) -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.add_link(&root.to_string_lossy(), GROUP).unwrap();
        crate::root_identity::VerifiedRoot::open(&root, GROUP, &state).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), root.clone())]);
        let session = PeerSyncSession::new(
            unreachable_channel().await,
            local.to_string(),
            peer.to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );
        if dag_negotiated {
            session.record_peer_change_dag_support(true);
            assert!(session.change_dag_negotiated());
        }
        Harness { session, state, _root: root_dir, _store_dir: store_dir, root }
    }

    fn version_of(device: &str) -> VersionVector {
        let mut v = VersionVector::new();
        v.increment(device);
        v
    }

    fn empty_record(path: &str, mtime: i64, version: VersionVector) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: mtime,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    /// The materialization-audit backstop must keep repairing missing on-disk
    /// content for records this device already holds — on a change-DAG session —
    /// via the materialize-only `rematerialize_local_records` routine. This is
    /// the audit path that stays after the second convergence engine is gone; it
    /// only ever materializes what the DAG already projected, never resolves a
    /// concurrent edit.
    #[tokio::test]
    async fn materialization_audit_runs_on_dag_session() {
        let h = harness("device-d", "device-p", /*dag*/ true).await;
        // An indexed (empty-content) record whose on-disk file is missing — the
        // shape the audit exists to repair.
        let rec = empty_record("audit.txt", OLD_MTIME, version_of("device-d"));
        h.state.upsert_file(GROUP, &rec).unwrap();
        let on_disk = h.root.join("audit.txt");
        assert!(!on_disk.exists(), "precondition: the file is not yet materialized");

        let file_info = h.session.file_info_for_record(GROUP, rec).unwrap();
        h.session.clone().rematerialize_local_records(GROUP, vec![file_info]).await.unwrap();

        assert!(on_disk.exists(), "the audit must re-materialize the missing file");
    }

    // ---- CORE: DAG-decided winner is order-independent and the gate keeps the
    // legacy mtime path from overriding it. ----

    struct MultiAuthenticator {
        keys: HashMap<String, [u8; 32]>,
    }
    impl ChangeAuthenticator for MultiAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            self.keys.get(device_id).copied()
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Create { path: SyncPath(path.into()), version: version.version_hash }
    }

    /// Two genuinely concurrent Create-`file.bin` changes with mtime INVERTED
    /// against lamport: device-a's change carries the higher lamport (a warm-up
    /// change raises its clock) but the OLDER mtime, device-b's carries the
    /// lower lamport but the NEWER mtime. The DAG winner is therefore device-a
    /// (higher lamport) while the mtime resolver would pick device-b.
    fn concurrent_changes() -> (Change, Change, Change, FileVersion, FileVersion, FileVersion) {
        let key_a = SigningKey::from_bytes(&[7u8; 32]);
        let key_b = SigningKey::from_bytes(&[8u8; 32]);
        let warm_v = empty_version(500);
        let va = empty_version(OLD_MTIME);
        let vb = empty_version(NEW_MTIME);

        let conn_a = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_a).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &warm_v).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &va).unwrap();
        let emitter_a = ChangeEmitter::new("device-a", key_a);
        let warm = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("warmup.txt", &warm_v)],
            ChangeAuth::PLACEHOLDER,
            &emitter_a,
        )
        .unwrap();
        let change_a = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("file.bin", &va)],
            ChangeAuth::PLACEHOLDER,
            &emitter_a,
        )
        .unwrap();

        let conn_b = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_b).unwrap();
        dag_store::put_file_version(&conn_b, GROUP, &vb).unwrap();
        let emitter_b = ChangeEmitter::new("device-b", key_b);
        let change_b = dag_store::emit_local_change(
            &conn_b,
            GROUP,
            vec![create_op("file.bin", &vb)],
            ChangeAuth::PLACEHOLDER,
            &emitter_b,
        )
        .unwrap();

        assert!(
            change_a.lamport > change_b.lamport,
            "test setup: device-a's change must carry the higher lamport ({} vs {})",
            change_a.lamport,
            change_b.lamport
        );
        (warm, change_a, change_b, warm_v, va, vb)
    }

    fn change_batch(changes: Vec<&Change>, versions: Vec<&FileVersion>) -> proto::ChangeBatch {
        proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: changes.into_iter().map(|c| c.to_wire_bytes()).collect(),
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: versions.into_iter().map(|v| v.canonical_encoding()).collect(),
        }
    }

    async fn converge_via_change_batch(reversed_batch: bool) -> i64 {
        let (warm, change_a, change_b, warm_v, va, vb) = concurrent_changes();
        let h = harness("device-d", "device-p", /*dag*/ true).await;
        h.session.set_change_authenticator(Arc::new(MultiAuthenticator {
            keys: HashMap::from([
                (
                    "device-a".to_string(),
                    SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes(),
                ),
                (
                    "device-b".to_string(),
                    SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes(),
                ),
            ]),
        }));

        // The two genuinely concurrent Create-`file.bin` changes arrive in one
        // batch, forward or reversed; the DAG must converge to the lamport winner
        // (device-a, OLD_MTIME) either way — the newer-mtime edit never wins.
        let batch = if reversed_batch {
            change_batch(vec![&change_b, &change_a, &warm], vec![&vb, &va, &warm_v])
        } else {
            change_batch(vec![&warm, &change_a, &change_b], vec![&warm_v, &va, &vb])
        };
        h.session.handle_change_batch(batch).await.unwrap();

        h.state.get_file(GROUP, "file.bin").unwrap().unwrap().mtime_unix_nanos
    }

    #[tokio::test]
    async fn dag_peers_converge_same_winner_regardless_of_arrival_order() {
        // Whether the concurrent changes arrive in forward or reversed batch
        // order, the change-DAG session converges to the LAMPORT winner
        // (device-a, OLD_MTIME); mtime never decides.
        let forward = converge_via_change_batch(false).await;
        let reversed = converge_via_change_batch(true).await;
        assert_eq!(forward, OLD_MTIME, "forward batch must keep the lamport winner");
        assert_eq!(reversed, OLD_MTIME, "reversed batch must keep the lamport winner");
        assert_eq!(forward, reversed, "the winner must be identical regardless of arrival order");
    }
}

/// Admission-time enforcement that a change's pinned authorization coordinate
/// is non-decreasing along causal order. Without it, a device revoked at
/// policy seq N (still holding its signing key) could craft a new change,
/// stamp an OLDER grant seq M < N it once held, sign it, and have any current
/// member relay it — honest receivers would admit it because the policy replay
/// behind `accepts_change_auth` is bounded by the author-chosen `auth_seq`, so
/// the later revoke is never consulted. Requiring `auth_seq >= max(parent
/// auth_seq)` at admission closes that: to be causally newer than its own
/// revoke the attacker must build on post-revoke heads (which pin seq >= N),
/// and the older stamp then loses to the parent floor.
#[cfg(test)]
mod authorization_monotonicity_tests {
    use super::{ChangeAuthenticator, PeerSyncSession};
    use crate::change::{Change, ChangeAuth, FileMeta, FileVersion, Op, SyncPath};
    use crate::dag_store::{self, ChangeEmitter};
    use crate::index::SyncState;
    use crate::types::RecordKind;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::TempDir;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::FsBlockStore;

    const GROUP: &str = "shared-group";

    /// A permissive authenticator: it pins the author's key and treats it as a
    /// writer, and (via the trait default) accepts any authorization stamp.
    /// The monotonicity rule under test lives in `handle_change_batch` itself
    /// and is enforced independently of the authenticator, so a permissive
    /// authenticator isolates it: whatever passes here does so purely on the
    /// parent-pin comparison, not on policy replay.
    struct PermissiveAuthenticator {
        author_device_id: String,
        author_verifying_key: [u8; 32],
    }

    impl ChangeAuthenticator for PermissiveAuthenticator {
        fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
            (device_id == self.author_device_id).then_some(self.author_verifying_key)
        }
        fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
            true
        }
    }

    fn empty_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Create { path: SyncPath(path.into()), version: version.version_hash }
    }

    fn real_auth(seq: u64, epoch: u64) -> ChangeAuth {
        // A non-PLACEHOLDER pin. `policy_head_hash` is set to a distinct
        // non-zero marker so the stamp differs from `ChangeAuth::PLACEHOLDER`
        // (the exemption is keyed on the whole stamp being the placeholder).
        ChangeAuth { auth_seq: seq, auth_epoch: epoch, policy_head_hash: [seq as u8 ^ 0xA5; 32] }
    }

    /// Builds a signed root editing `a.txt` (pinning `parent_auth`) and a
    /// signed child editing `b.txt` that descends from it (pinning
    /// `child_auth`), by running the real local-emission path against a
    /// throwaway store so the child genuinely names the root as its parent.
    fn build_chain(
        signing_key: &SigningKey,
        parent_auth: ChangeAuth,
        child_auth: ChangeAuth,
    ) -> (Change, Change, FileVersion) {
        let sender = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let version = empty_version();
        dag_store::put_file_version(&sender, GROUP, &version).unwrap();
        let emitter = ChangeEmitter::new("device-a", signing_key.clone());
        let parent = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("a.txt", &version)],
            parent_auth,
            &emitter,
        )
        .unwrap();
        let child = dag_store::emit_local_change(
            &sender,
            GROUP,
            vec![create_op("b.txt", &version)],
            child_auth,
            &emitter,
        )
        .unwrap();
        // The child must genuinely descend from the parent for the causal
        // check to have anything to compare against.
        assert_eq!(child.parents, vec![parent.compute_hash()], "child must name the root parent");
        (parent, child, version)
    }

    async fn unreachable_channel() -> Arc<yadorilink_transport::PeerChannel> {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let local_secret = StaticSecret::from(secret_bytes);
        let local_public = PublicKey::from(&local_secret);
        let peer_public = PublicKey::from(&StaticSecret::from([9u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, Some(local_public));
        let channel = yadorilink_transport::PeerChannel::connect(
            local_secret,
            peer_public,
            0,
            Vec::new(),
            hub,
        )
        .await
        .unwrap();
        Arc::new(channel)
    }

    /// Feeds `changes` (in the given order) as one batch to a fresh receiver
    /// and returns its `SyncState`. The temp dirs are returned so they outlive
    /// the call; assertions read the in-memory index, which persists
    /// regardless of the on-disk root.
    async fn admit_batch(
        changes: &[Change],
        version: &FileVersion,
        author_verifying_key: [u8; 32],
    ) -> (Arc<SyncState>, TempDir, TempDir) {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        let generation = state.begin_group_startup(GROUP);
        state.mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);

        let session = PeerSyncSession::new(
            unreachable_channel().await,
            "device-b".to_string(),
            "device-a".to_string(),
            state.clone(),
            store,
            vec![GROUP.to_string()],
            sync_roots,
        );
        session.set_change_authenticator(Arc::new(PermissiveAuthenticator {
            author_device_id: "device-a".to_string(),
            author_verifying_key,
        }));

        let batch = proto::ChangeBatch {
            folder_group_id: GROUP.to_string(),
            changes: changes.iter().map(|c| c.to_wire_bytes()).collect(),
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        };
        session.handle_change_batch(batch).await.unwrap();
        (state, root_dir, store_dir)
    }

    /// The attack: a device revoked at seq N=10 forks off a post-revoke head
    /// (the root here pins seq 10, epoch 2) but stamps its own change with the
    /// OLD grant seq M=3 (epoch 1) it held before the revoke. Delivered
    /// parent-first so the parent's pin is already in the store when the child
    /// is checked, the child must be REJECTED and never enter the store.
    #[tokio::test]
    async fn revoked_writer_building_on_post_revoke_head_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(10, 2), real_auth(3, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.dag_has_change(&parent.compute_hash()).unwrap(),
            "the honest post-revoke head is admitted"
        );
        assert!(
            !state.dag_has_change(&child.compute_hash()).unwrap(),
            "the revoked writer's older-pinned change must NOT enter the store"
        );
        assert!(
            state.get_file(GROUP, "a.txt").unwrap().is_some(),
            "the parent's path materializes"
        );
        assert!(
            state.get_file(GROUP, "b.txt").unwrap().is_none(),
            "the rejected change's path must never materialize"
        );
    }

    /// The orphan-first evasion: the same attack but delivered child-first, so
    /// the malicious change arrives before its post-revoke parent. It must be
    /// HELD (its parents can't be read yet, so monotonicity can't be verified)
    /// rather than buffered — otherwise the later arrival of the honest parent
    /// would silently promote it. The parent still lands; the child never does.
    #[tokio::test]
    async fn revoked_writer_orphan_first_ordering_is_held_not_promoted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(10, 2), real_auth(3, 1));

        // Child first, then its parent — the ordering that would exploit the
        // orphan buffer's promote-without-re-auth path.
        let (state, _root, _store) =
            admit_batch(&[child.clone(), parent.clone()], &version, verifying_key).await;

        assert!(
            state.dag_has_change(&parent.compute_hash()).unwrap(),
            "the honest parent still lands"
        );
        assert!(
            !state.dag_has_change(&child.compute_hash()).unwrap(),
            "a held, monotonicity-unverified change must never be promoted into the store"
        );
        assert!(
            state.get_file(GROUP, "b.txt").unwrap().is_none(),
            "the held change's path must never materialize"
        );
    }

    /// A legitimately-delayed change from a still-valid writer, authored
    /// offline concurrent with the revoke: its parent pins seq M=3 and it also
    /// pins seq 3, arriving after the revoke would have advanced the log. Its
    /// parents pin <= M, so monotonicity holds and it is ADMITTED — the fix
    /// must not punish honest delay.
    #[tokio::test]
    async fn legitimately_delayed_change_concurrent_with_revoke_is_admitted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(3, 1), real_auth(3, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.dag_has_change(&child.compute_hash()).unwrap(),
            "a change that pins the same coordinate as its parent must be admitted"
        );
        assert!(
            state.get_file(GROUP, "b.txt").unwrap().is_some(),
            "the delayed change's path materializes"
        );
    }

    /// The ordinary forward case: a child pins a strictly newer coordinate
    /// than its parent (seq 3 -> seq 5). Non-decreasing pins are admitted.
    #[tokio::test]
    async fn monotonic_normal_changes_admitted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let (parent, child, version) = build_chain(&signing_key, real_auth(3, 1), real_auth(5, 1));

        let (state, _root, _store) =
            admit_batch(&[parent.clone(), child.clone()], &version, verifying_key).await;

        assert!(
            state.dag_has_change(&child.compute_hash()).unwrap(),
            "a change pinning a newer coordinate than its parent must be admitted"
        );
        assert!(
            state.get_file(GROUP, "b.txt").unwrap().is_some(),
            "the forward change's path materializes"
        );
    }
}
