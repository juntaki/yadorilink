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
//! advertise in an index, what authoring hash or `mtime_unix_nanos` to
//! claim, what path to name — are adversarial input, not trusted metadata.
//! Authoring hashes are accepted only when present in this group's verified
//! retained/pruned DAG history; `reconcile_files_if_authorized` bounds
//! incoming-index cardinality; `resolve_and_apply_conflict` bounds `mtime`
//! skew; `materialize`/
//! `hydrate_file_with_timeout` re-verify the resolved write target stays
//! under the sync root. See `conflict.rs` for the remaining wall-clock trust
//! boundary; causal ordering itself is cryptographically bound to DAG
//! ancestry rather than a peer-asserted counter.

use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::adaptive_window::AdaptiveWindow;
use crate::error::PeerSessionError;
use crate::hazard;
use crate::rate_limiter::RateLimiters;
use yadorilink_local_storage::check_disk_headroom;
use yadorilink_local_storage::create_or_defer_placeholder;
use yadorilink_local_storage::PlaceholderIdentityToRecord;
use yadorilink_local_storage::{
    apply_exec_bit, reconstruct_file, verify_delete_target_within_canonical_root,
    verify_delete_target_within_root, verify_write_target_within_canonical_root,
    verify_write_target_within_root,
};
use yadorilink_replica_domain::admission::ChangeOrdering;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::file::{FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::rebootstrap::RebootstrapRequired;
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_replica_engine::change_ops::{collect_op_paths, op_version_hash};
use yadorilink_replica_engine::conflict::{
    change_touches_path, path_head_from_change, resolve_path_heads, PathHead, PathResolution,
};
use yadorilink_replica_engine::outcomes::{
    CausalAuthOutcome, ChangeAdmissionOutcome, ChangeAdmissionRejection,
};
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

/// Mirrors `yadorilink-sync-core`'s own `chunker::MAX_BLOCK_SIZE` (moved
/// out of this file's scope in Phase 7D-6's crate split) as a `usize` --
/// every call site here compares or casts against `usize`/`u64` lengths.
const MAX_BLOCK_SIZE: usize = yadorilink_replica_domain::limits::MAX_BLOCK_SIZE_BYTES as usize;

/// (see `run`'s recv loop, where this actually gates
/// concurrently-spawned inbound message handlers): the fixed, non-adaptive
/// per-peer concurrency ceiling. `AdaptiveWindow`'s `max` is constructed
/// to never exceed this — the
/// adaptive in-flight fetch window (`adaptive_window` field below) grows
/// and shrinks freely below it, but this remains the hard upper bound
/// nothing in this module can adapt past, so the new controller composes
/// with (rather than reintroduces a way around) the existing DoS bound.
const MAX_IN_FLIGHT_MESSAGES_PER_PEER: usize = 64;

// `BlockRequest` deliberately shares neither this semaphore nor a FIFO
// permit pool of its own for its actual SERVICE: it is spawned immediately
// on arrival (see `run`'s recv loop, the `Payload::BlockRequest` arm's own
// doc comment) rather than queued behind a local permit pool, for two
// reasons in combination -- (1) CONV-5: a `BlockRequest` handler can
// genuinely block for a long time (stage 2's `handle_block_request_with_
// credit` awaits a possibly-gated disk read), and a local permit pool
// shared with control/metadata messages would let a flood of those starve
// this session's control traffic; (2) real concurrency control and
// cross-peer/cross-group fairness both live in the shared
// `BlockServeEngine` (`acquire_dispatch_turn`) now, which every session
// funnels into -- a FIFO-by-arrival PER-SESSION QUEUE here would just
// reintroduce a second, uncoordinated head-of-line-blocking point in front
// of that device-wide fairness (confirmed, reproduced:
// `stage2_block_serve_contract.rs`'s
// `late_small_requests_from_another_peer_and_group_cut_ahead_of_a_large_
// backlog` and `stalled_content_requests_do_not_delay_control_messages_
// on_the_same_session`).
//
// `BlockServeEngine::try_begin_examination` (below) is a DIFFERENT thing
// and does not reintroduce that problem: it is a non-blocking (`try_
// acquire`, never queues) cap on EXAMINATION only -- the authorization/
// reference/provenance checks that run before a request ever reaches
// `acquire_dispatch_turn` -- released the moment those checks finish,
// before dispatch/service begins, not held for the request's whole
// service. See that method's own doc for the full rationale, including
// the still-open device-wide-only limitation: it has no notion of which
// peer is consuming the budget, so a single authorized-but-untrusted peer
// refilling it fast enough could in principle keep other peers' requests
// rejected at the door even though the fair dispatch queue would gladly
// serve them. A peer/group-aware pre-admission scheme (or a per-peer
// sub-cap sized against real measured legitimate-burst sizes, not a
// guessed constant) is tracked as a follow-up, not implemented here --
// see this crate's H ledger.

/// One `BlockRequest`'s worth of examination-admission slot, held so
/// `handle_block_request` can release it (a plain `drop`) once examination
/// finishes, before dispatch/service begins. `None` only when no
/// `BlockServeEngine` was installed at all (see `run`'s recv loop, the
/// `None` arm of its own `block_serve_engine()` match) — there is nothing
/// to hold in that case, since `try_begin_examination` was never called.
struct BlockExaminationPermits {
    _device_wide: Option<crate::block_serve::ExaminationPermit>,
}

/// Hard per-session bound for decoded ordinary messages waiting on a handler
/// permit. BlockReply uses the independent control lane and is never queued,
/// so rejecting an ordinary-message flood at this limit cannot recreate the
/// reply/permit deadlock this queue was introduced to avoid.
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
fn compress_block(data: &[u8]) -> (Vec<u8>, i32) {
    if data.is_empty() {
        return (Vec::new(), yadorilink_sync_wire::COMPRESSION_NONE);
    }
    match zstd::stream::encode_all(data, COMPRESSION_LEVEL) {
        Ok(compressed)
            if (compressed.len() as f64) < (data.len() as f64) * COMPRESSION_SKIP_THRESHOLD =>
        {
            (compressed, yadorilink_sync_wire::COMPRESSION_ZSTD)
        }
        _ => (data.to_vec(), yadorilink_sync_wire::COMPRESSION_NONE),
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
    declared_compression: i32,
    max_size: usize,
) -> Result<Vec<u8>, PeerSessionError> {
    match declared_compression {
        yadorilink_sync_wire::COMPRESSION_ZSTD => {
            let decoder = zstd::stream::read::Decoder::new(data).map_err(PeerSessionError::Io)?;
            let mut limited = decoder.take(max_size as u64 + 1);
            let mut out = Vec::new();
            limited.read_to_end(&mut out).map_err(PeerSessionError::Io)?;
            if out.len() > max_size {
                return Err(PeerSessionError::from(std::io::Error::other(format!(
                    "decompressed payload exceeds the {max_size}-byte maximum \
                     (decompression-bomb guard)"
                ))));
            }
            Ok(out)
        }
        // Unrecognized values are treated the same as `COMPRESSION_NONE` --
        // a trivial passthrough, never a hard error (matches the previous
        // `Compression::try_from(..).unwrap_or(Compression::None)` fallback).
        _ => Ok(data.to_vec()),
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

/// Correlates an outstanding `BlockReply`-answered request to its waiter by
/// `BlockRequest.request_id`/`BlockReply.request_id` -- exactly one entry
/// per request, never shared, so two different folder groups that happen
/// to reference the same content hash and legitimately get DIFFERENT
/// outcomes (one has provenance and is `found`, the other doesn't and is
/// `rejected`) can never be cross-wired the way keying purely by
/// `block_hash` would allow. See `BlockReply.request_id`'s own doc
/// comment. The waiter payload carries `Bytes`, not `Vec<u8>`, so
/// `handle_block_reply` can hand it off without an extra copy.
type PendingBlockRequestsById = StdMutex<HashMap<u64, oneshot::Sender<FetchOutcome>>>;

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
/// Whether one `materialize` (or `materialize_dag_content_head`) call
/// actually settled its path, or merely deferred it. A real, confirmed bug
/// (see `fix/conflict-copy-convergence-obligation-20260723`): `materialize`
/// returning plain `Ok(())` for BOTH "fully materialized" AND "wrote a
/// retriable Placeholder because an eager fetch could not get every block"
/// meant a caller treating any `Ok(())` as success (as the Convergence
/// Engine's per-job completion check effectively did, one layer up) could
/// mark a job done while the actual content was never verified to match
/// the resolved winner. This distinction exists so a caller can tell the
/// two apart and never treat the latter as done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializeResult {
    /// This path's outcome is final for this attempt: content fully
    /// materialized and disk-verified, a tombstone deletion completed, a
    /// CREATE/symlink hazard correctly moved the record to `hold`
    /// (`hold_record` upserts the incoming record, so the row itself now
    /// carries the held change's own authoring identity), or an on-demand
    /// (not eager/pinned) placeholder was intentionally written (deferring
    /// content by design, not because a fetch failed).
    ///
    /// NOT what a hazardous TOMBSTONE reports when it holds an existing
    /// genuine live row rather than deleting it: `set_held` there only
    /// stamps `held_reason` onto the row without adopting the incoming
    /// tombstone's identity (see the `if record.deleted` branch's own doc
    /// comment for why), so nothing durable records that a deletion is
    /// pending -- that case reports `RetryRequired` instead, specifically
    /// so `reproject_unapplied_changes` keeps re-examining it.
    Settled,
    /// This path is NOT done: an eager/pinned fetch could not obtain every
    /// block (a retriable `Placeholder` was written instead), a local
    /// reconstruct failed even after its own retries, the resolved
    /// version's blocks were not locally available to plan against at
    /// all, or a hazardous tombstone held/dropped without ever recording
    /// the pending deletion durably (see `Settled`'s own doc comment). A
    /// caller must retry, never treat this as success.
    RetryRequired,
}

/// Outcome of one `retire_conflict_copies_only` attempt for a group.
/// Exists so a generation-tracked caller (`engine_wrapper.rs`'s
/// `RetirementWake`) can tell "this pass genuinely verified the frontier
/// generation it targeted" from every way it might not have -- a plain
/// `bool`/`Result<(), _>` return collapsed all three into "ran" vs
/// "errored", which is exactly the shape that let a guard-busy skip get
/// treated as a completed pass (see `RetirementWake`'s own doc comment for
/// the resulting lost-wakeup bug this type closes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementAttempt {
    /// Every copy-shaped file this pass examined was either justified by
    /// the current frontier or successfully retired. Only this variant
    /// means the caller may call `RetirementWake::complete` for the
    /// generation this pass targeted. `retired` counts how many copies
    /// were actually removed (informational only, not part of the
    /// completion contract).
    Settled { retired: usize },
    /// `RetirementAuditGuard` contention: another retirement pass for this
    /// same group already holds it, so this pass did not run at all. Not
    /// an error -- that other pass's own retire step covers SOME
    /// evaluation of this group, but not necessarily the frontier
    /// generation this pass was asked to verify.
    Busy,
    /// The pass ran, but at least one copy's tombstone `materialize`
    /// returned `MaterializeResult::RetryRequired` or errored -- that
    /// copy's justification was never actually re-verified against the
    /// targeted frontier, so the pass as a whole did not settle it.
    RetryRequired,
    /// The pass ran and every copy it examined resolved cleanly, but this
    /// device's own admitted DAG frontier for the group was different
    /// after the pass than before it started -- see
    /// `retire_conflict_copies_only`'s own doc comment for exactly what is
    /// compared and why. Every decision this pass made (justified/
    /// unjustified, retire/retain) was made against SOME frontier that
    /// existed during the pass, but not provably the one the caller's
    /// generation was meant to verify, so it must not be treated as a
    /// completion of that generation -- not "undo what this pass did"
    /// (already-correct-for-some-real-frontier mutations are left as they
    /// are), but "do not trust this pass's verdict as final; run again
    /// against the CURRENT frontier."
    FrontierChanged,
}

/// The outcome of one `reconcile_group_paths` call, split into two
/// explicit, disjoint sets rather than a single "failed" set — a real,
/// confirmed bug this shape exists to make structurally impossible (see
/// `fix/conflict-copy-convergence-obligation-20260723`): a path absent from
/// a single "failed" set reads as "succeeded", which is true only if every
/// branch that *doesn't* explicitly fail also explicitly records success. A
/// path this call never actually examined (an early-return branch nobody
/// remembered to record) silently inherited "succeeded" for free. With two
/// explicit sets, a path in neither is a visible bug (see
/// `reconcile_paths_directly`'s caller-side handling), never a silent,
/// accidental success.
///
/// `settled`: this path's outcome is final for this attempt — content
/// verified to match the current resolution, a tombstone deletion completed
/// (or was already reflected), an ignore-policy decision, or a hazard/
/// on-demand placeholder correctly recorded as such.
///
/// `retry`: this path is NOT done and must be tried again — a real error,
/// an eager/pinned fetch that could not obtain every block, or this call
/// read a state (no live heads at all for a path it was asked to resolve)
/// it cannot currently make a positive claim about.
///
/// Every path this call is asked to resolve (`seed_paths`, plus every
/// conflict-copy/tombstone path the fixpoint derives from them) ends up in
/// EXACTLY one of these two sets — never both, never neither.
#[derive(Debug, Default, Clone)]
pub struct ProjectionAttempt {
    settled: std::collections::BTreeSet<String>,
    retry: std::collections::BTreeSet<String>,
}

impl ProjectionAttempt {
    /// Whether `path` is in `settled` — the ONLY way a caller should ever
    /// decide a path succeeded. Never infer success from `path` simply not
    /// being in `retry`.
    pub fn is_settled(&self, path: &str) -> bool {
        self.settled.contains(path)
    }

    /// Whether `path` is in `retry`.
    pub fn needs_retry(&self, path: &str) -> bool {
        self.retry.contains(path)
    }

    /// Whether any path in `retry` is a conflict copy derived from `path`
    /// -- a direct path is not itself done if the losing content it
    /// produced as a conflict copy still needs another attempt.
    fn any_retry_path_is_conflict_copy_of(&self, path: &str) -> bool {
        self.retry.iter().any(|p| yadorilink_replica_domain::conflict::is_conflict_copy_of(p, path))
    }

    /// Whether `path` is fully resolved by this attempt: settled AND no
    /// conflict copy derived from it is still outstanding in `retry`. This
    /// is the one predicate any caller (including `yadorilink-daemon`'s
    /// Convergence Engine) should use to decide a job for `path` is done —
    /// `is_settled` alone is not enough, since a seed path can settle while
    /// the losing content it produced at a derived conflict-copy path still
    /// needs another attempt (an independent review caught the Convergence
    /// Engine doing exactly that: retiring a job on `is_settled` alone and
    /// silently dropping the still-outstanding conflict-copy obligation).
    /// Mirrors `change_projection_succeeded`'s per-path predicate exactly.
    pub fn path_fully_resolved(&self, path: &str) -> bool {
        self.is_settled(path) && !self.any_retry_path_is_conflict_copy_of(path)
    }
}

#[cfg(test)]
mod projection_attempt_tests {
    use super::ProjectionAttempt;

    /// Regression test for a confirmed bug an independent review caught
    /// (see `fix/conflict-copy-convergence-obligation-20260723`): the
    /// Convergence Engine (`yadorilink-daemon`'s `process_group`) used to
    /// retire a job as soon as its own seed path was `settled`, ignoring
    /// whether a conflict copy derived from that path was still in
    /// `retry` -- silently dropping the still-outstanding obligation.
    /// `path_fully_resolved` must return `false` in exactly this case, even
    /// though `is_settled` alone would say `true`.
    #[test]
    fn path_fully_resolved_is_false_when_its_derived_conflict_copy_still_needs_retry() {
        let copy_path = yadorilink_replica_domain::conflict::conflict_copy_path(
            "shared.bin",
            0,
            "device-2",
            &[0x3c, 0x58, 0xcc, 0xc5],
        );
        let attempt = ProjectionAttempt {
            settled: std::collections::BTreeSet::from(["shared.bin".to_string()]),
            retry: std::collections::BTreeSet::from([copy_path]),
        };
        assert!(attempt.is_settled("shared.bin"), "sanity: the seed path itself did settle");
        assert!(
            !attempt.path_fully_resolved("shared.bin"),
            "a settled seed path must not read as fully resolved while its own \
             derived conflict copy is still outstanding in retry"
        );
    }

    /// The positive case: once neither the seed path nor any conflict copy
    /// derived from it remains in `retry`, `path_fully_resolved` agrees with
    /// `is_settled`.
    #[test]
    fn path_fully_resolved_is_true_when_settled_with_no_outstanding_conflict_copy() {
        let attempt = ProjectionAttempt {
            settled: std::collections::BTreeSet::from(["shared.bin".to_string()]),
            retry: std::collections::BTreeSet::new(),
        };
        assert!(attempt.path_fully_resolved("shared.bin"));
    }

    /// A `retry` entry that is NOT a conflict copy of `path` (an unrelated
    /// path happening to also need retry this attempt) must not affect
    /// `path`'s own resolution.
    #[test]
    fn path_fully_resolved_ignores_an_unrelated_retry_path() {
        let attempt = ProjectionAttempt {
            settled: std::collections::BTreeSet::from(["shared.bin".to_string()]),
            retry: std::collections::BTreeSet::from(["unrelated.txt".to_string()]),
        };
        assert!(attempt.path_fully_resolved("shared.bin"));
    }
}

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
    /// No reply at all arrived within `fetch_block_raw`'s own
    /// `FETCH_RESPONSE_TIMEOUT` — deliberately distinct from `NotFound`
    /// (an explicit, fast refusal): this means the request went out and
    /// nothing came back, which is a much heavier signal (a slow/
    /// unresponsive peer or connection, not a quick index-not-updated-yet
    /// race) that should fail fast rather than retry the same peer, unlike
    /// `NotFound`'s bounded same-peer retry in `ensure_blocks_present`.
    TimedOut,
    /// The peer answered with `BlockReply.Busy`: its serve queue for this
    /// block is at its in-flight credit limit right now, not permanently
    /// absent. Deliberately distinct from every other variant
    /// — a caller must not treat this as `NotFound`/`Unusable` (this peer
    /// may well have the block) nor immediately fail over to another peer
    /// the way `TimedOut` warrants (retrying the SAME peer after
    /// `retry_after_ms` is usually cheaper than reconnecting elsewhere) —
    /// see `ensure_blocks_present`'s own handling.
    Busy {
        retry_after_ms: u32,
    },
    /// The peer answered with `BlockReply.Redirect`: it does not hold this
    /// block itself but named other devices that might. Advisory only —
    /// collapses to the same "this peer cannot supply it" signal as
    /// `NotFound` for a caller that doesn't act on `candidate_device_ids`
    /// itself, but is kept distinct so a caller that DOES want to steer its
    /// next attempt (the daemon's multi-peer hydration dispatcher) can.
    Redirect {
        candidate_device_ids: Vec<String>,
    },
    /// The peer answered with `BlockReply.Rejected`: a hard denial (missing
    /// authorization/provenance, or a malformed request) that retrying
    /// will not resolve -- deliberately distinct from `NotFound`, which
    /// `ensure_blocks_present` retries against the same peer up to
    /// `NOT_FOUND_RETRY_ATTEMPTS` times on the theory that a "not
    /// referenced yet" race commonly clears within a second. Collapsing
    /// `Rejected` into `NotFound` (the pre-this-variant behavior) meant a
    /// permanent authorization denial got the identical bounded-retry
    /// treatment as a transient index-not-updated-yet race, needlessly
    /// re-asking a peer that will never answer differently.
    Rejected {
        reason: String,
    },
}

impl FetchOutcome {
    fn into_bytes(self) -> Option<Bytes> {
        match self {
            FetchOutcome::Found(data) => Some(data),
            FetchOutcome::NotFound
            | FetchOutcome::Unusable
            | FetchOutcome::TimedOut
            | FetchOutcome::Busy { .. }
            | FetchOutcome::Rejected { .. }
            | FetchOutcome::Redirect { .. } => None,
        }
    }
}

/// `fetch_block` used to `insert` into `pending_block_requests_by_id` and
/// rely solely on `handle_block_reply` to `remove` it — but a caller
/// wrapping `fetch_block` in a timeout (as `hydrate_file`/
/// `ensure_blocks_present` both do) drops the `fetch_block` future, and
/// therefore its local `rx`, without ever running `handle_block_reply` for
/// that request. Nothing else ever removed the now-orphaned entry, so a
/// timed-out or cancelled fetch leaked one `HashMap` entry forever — on a
/// long-running daemon with an unreachable peer, unboundedly. This RAII
/// guard removes its entry on drop, but only when the sender is
/// `is_closed` (its matching `rx` was dropped without ever receiving a
/// reply) — the ordinary, already-fulfilled-by-`handle_block_reply` path
/// already removed the entry itself, so the guard's own drop then finds
/// nothing there and no-ops.
struct PendingBlockGuard<'a> {
    pending: &'a PendingBlockRequestsById,
    request_id: u64,
}

impl Drop for PendingBlockGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending.get(&self.request_id).is_some_and(|tx| tx.is_closed()) {
            pending.remove(&self.request_id);
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
struct SymlinkMaterialization<'a, 'permit> {
    state: &'a dyn crate::ports::PeerReplicaStatePort,
    root: &'a Path,
    group_id: &'a str,
    windows_opt_in: bool,
    origin_device_id: &'a str,
    authoring_change_hash: Option<&'a ChangeHash>,
    permit: &'a RootCommitPermit<'permit>,
}

fn materialize_symlink_at(
    context: SymlinkMaterialization<'_, '_>,
    record: &FileRecord,
) -> Result<(), PeerSessionError> {
    let SymlinkMaterialization {
        state,
        root,
        group_id,
        windows_opt_in,
        origin_device_id,
        authoring_change_hash,
        permit,
    } = context;
    match authoring_change_hash {
        Some(hash) => state.upsert_file_with_origin_and_author(
            group_id,
            record,
            origin_device_id,
            hash,
            permit,
        )?,
        None => state.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
    }
    let out_path = root.join(&record.path);
    // A free function, not a `PeerSyncSession` method, so it cannot go
    // through `self.verify_write_target` (which already orders these
    // the same way) -- re-verify directly here for the same reason that
    // method does: a colliding long-running eager sync could see this
    // root's mountpoint unmounted and replaced between the record's own
    // admission and this write. This MUST run before
    // `verify_write_target_within_root` below, not after: that call is
    // not a pure check, it `create_dir_all`s `root` and `out_path`'s
    // parent as a side effect, so calling it first would create
    // directories on a possibly-wrong replacement volume before its
    // identity has even been confirmed.
    state.verify_root(root, group_id)?;
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
        Ok(yadorilink_local_storage::materialize_symlink(&out_path, &target)?)
    }
    #[cfg(windows)]
    {
        // Default is skip-with-visible-status — the record was
        // already adopted into the index above (so it still syncs
        // correctly onward to a POSIX peer), but nothing is written to
        // disk here unless this link explicitly opted in.
        if windows_opt_in {
            Ok(yadorilink_local_storage::materialize_symlink_windows(&out_path, &target)?)
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
    state: &dyn crate::ports::PeerReplicaStatePort,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
    permit: &RootCommitPermit<'_>,
) -> Result<bool, PeerSessionError> {
    let Some(local) = state.get_file(group_id, &record.path)? else { return Ok(false) };
    if local.deleted || record.blocks.is_empty() || local.blocks != record.blocks {
        return Ok(false);
    }
    let out_path = root.join(&record.path);
    // Re-verify root identity before `verify_write_target_within_root`
    // below, not just once right before the chmod further down: that
    // call is not a pure check, it `create_dir_all`s `root` and
    // `out_path`'s parent as a side effect, so calling it first would
    // create directories on a possibly-wrong replacement volume before
    // its identity has even been confirmed, even though this function
    // may still return `Ok(false)` afterward without ever reaching the
    // chmod.
    state.verify_root(root, group_id)?;
    verify_write_target_within_root(&out_path, root)?;
    // The index can get ahead of the disk when a prior materialization wrote
    // its row and then failed. Existence alone is also insufficient: a stale
    // or partially-written file at this path must take the normal reconstruct
    // path, not be accepted as a metadata-only update.
    if !yadorilink_local_storage::disk_bytes_match_indexed_blocks(&out_path, &record.blocks)? {
        return Ok(false);
    }
    // Re-verify root identity right before the chmod below -- the same
    // gap `self.verify_write_target` closes for every other write path
    // in this module, but this is a free function so it cannot call that
    // method. `disk_bytes_match_indexed_blocks` above can take real time
    // hashing every block of a large file; a root swap during that read
    // must not go undetected right up to the point this function commits
    // the index update and mutates permissions on whatever is now at
    // `out_path`.
    match authoring_change_hash {
        Some(hash) => state.upsert_file_with_origin_and_author(
            group_id,
            record,
            origin_device_id,
            hash,
            permit,
        )?,
        None => state.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
    }
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
/// Outcome of a targeted local-flush round trip
/// (`PendingLocalChangeFlush::flush_pending_local_change` /
/// `flush_case_fold_sibling`), through this link's debounce-accumulator
/// channel. That channel is small and shared by every concurrent peer
/// message handler reconciling a path against this link — under a
/// duplicate-delivery storm it can back up, so the round trip is bounded
/// rather than awaited unconditionally. `Settled` means the local side is
/// safely accounted for (flushed, or genuinely nothing pending) and the
/// peer change may proceed to DAG admission. `RetryRequired` means this
/// round trip could not complete its bound (the enqueue or the reply timed
/// out) — the local pending edit's state relative to the incoming peer
/// change is unknown, so admitting the peer change now would risk silently
/// clobbering it; the caller must defer this change instead (it will be
/// re-requested by anti-entropy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingLocalFlushOutcome {
    Settled,
    RetryRequired,
}

pub trait PendingLocalChangeFlush: Send + Sync {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;

    /// Like `flush_pending_local_change`, but for the *other* case-variant
    /// path that would collide with `rel_path` on a case-insensitive
    /// filesystem, rather than `rel_path` itself — see
    /// `PeerSyncSession::flush_case_fold_sibling_before_reconcile`'s doc
    /// comment for why this exists as a separate call.
    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>>;
}

/// Mirrors `PendingLocalChangeFlush`'s injection shape exactly (see that
/// trait's own doc comment for why this crate needs the daemon to inject
/// per-group lookups like this rather than depending on `yadorilink-daemon`
/// directly), for a different seam: every `SyncState` mutation
/// `PeerSyncSession` makes (peer-driven index/DAG/materialization-state
/// writes) requires a `root_commit::RootCommitPermit`, minted from a
/// `LinkOperation` admitted against the per-link `root_commit::RootLease`
/// this provides for `group_id`. `None` means this device has no live,
/// established link for that group right now -- the caller must treat that
/// exactly like any other "this link isn't available" failure, never
/// synthesize a permissive fallback lease.
pub trait RootCommitAuthorityProvider: Send + Sync {
    fn root_lease_for(
        &self,
        group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>>;
}

/// Test-only default installed by [`PeerSyncSession::new_with_forwarding`]
/// so that the hundreds of existing tests that construct a session and
/// exercise a real mutation path (`materialize`, `hold`, ...) without ever
/// calling `set_root_commit_authority_provider` keep working unchanged --
/// mirroring `RootCommitPermit::for_tests()`'s own "a test that doesn't
/// care about lifecycle shouldn't have to thread one through" rationale.
/// Still goes through a real `RootLease` (just one with no real
/// `SyncRootLock` behind it), so this is not a bypass of the lease
/// mechanism -- a production build has no equivalent default; see the
/// `cfg` at this field's initializer below.
#[cfg(any(test, feature = "test-support"))]
struct AlwaysValidRootCommitAuthorityProvider;

#[cfg(any(test, feature = "test-support"))]
impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        Some(Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()))
    }
}

/// Deny-by-default implementation of `RootCommitAuthorityProvider`, used by
/// [`PeerSyncSessionOneTimeDeps::denied`] as the production-safe default for
/// the `root_commit_authority_provider` one-time dependency -- reports no
/// live link for any group, matching what an absent provider used to mean
/// before this field became mandatory-at-construction. Mirrors
/// `yadorilink_sync_core::peer_session::DenyRootCommitAuthorityProvider`
/// (the public wrapper's own equivalent, used by `PeerSyncSessionDeps::
/// standalone()`); duplicated here rather than shared because the
/// implementation module must not depend on the public wrapper module that
/// depends on it.
struct DenyRootCommitAuthorityProvider;

impl RootCommitAuthorityProvider for DenyRootCommitAuthorityProvider {
    fn root_lease_for(
        &self,
        _group_id: &str,
    ) -> Option<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        None
    }
}

/// Deny/no-op-by-default implementations of this session's other 6 one-time
/// capability traits, used by [`PeerSyncSessionOneTimeDeps::denied`]. Each
/// mirrors the wrapper's own private equivalent in `peer_session_public.rs`
/// (`NoopPendingLocalChangeFlush`, `DenyAllChangeAuthenticator`,
/// `DenyHandoffLeaseResponder`, `DenyRebootstrapHandler`,
/// `NoopBlockWriteActivityProvider`, `DenyHandoffTicketResponder`)
/// exactly -- duplicated for the same layering reason as
/// `DenyRootCommitAuthorityProvider` above.
struct DeniedPendingLocalChangeFlush;

impl PendingLocalChangeFlush for DeniedPendingLocalChangeFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async { PendingLocalFlushOutcome::Settled })
    }
}

struct DeniedChangeAuthenticator;

impl ChangeAuthenticator for DeniedChangeAuthenticator {
    fn signing_key(&self, _device_id: &str) -> Option<[u8; 32]> {
        None
    }

    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        false
    }

    fn accepts_change_auth(
        &self,
        _device_id: &str,
        _group_id: &str,
        _signing_key_fingerprint: [u8; 32],
        _auth: yadorilink_replica_domain::change::ChangeAuth,
    ) -> bool {
        false
    }
}

struct DeniedHandoffLeaseResponder;

impl HandoffLeaseResponder for DeniedHandoffLeaseResponder {
    fn request_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
        Box::pin(async { None })
    }

    fn release_handoff_lease<'a>(
        &'a self,
        _group_id: &'a str,
        _lease_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct DeniedRebootstrapHandler;

impl RebootstrapHandler for DeniedRebootstrapHandler {
    fn prepare_rebootstrap(
        &self,
        _group_id: &str,
        _requested_hash: ChangeHash,
    ) -> Result<Option<PreparedRebootstrap>, PeerSessionError> {
        Ok(None)
    }

    fn verify_rebootstrap(&self, _required: &RebootstrapRequired) -> Result<(), PeerSessionError> {
        Err(PeerSessionError::InvalidInput(
            "re-bootstrap is unavailable without an explicit trust integration".to_string(),
        ))
    }

    fn install_rebootstrap(
        &self,
        _required: &RebootstrapRequired,
        _snapshot_bytes: &[u8],
    ) -> Result<(), PeerSessionError> {
        Err(PeerSessionError::InvalidInput(
            "re-bootstrap is unavailable without an explicit trust integration".to_string(),
        ))
    }
}

struct DeniedBlockWriteActivityProvider;

impl BlockWriteActivityProvider for DeniedBlockWriteActivityProvider {
    fn begin_block_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }
}

struct DeniedHandoffTicketResponder;

impl HandoffTicketResponder for DeniedHandoffTicketResponder {
    fn request_handoff_ticket<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
        Box::pin(async { None })
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

/// This session's 8 one-time, construction-only capability injections --
/// see each field's own doc comment on `PeerSyncSession` for what it gates.
/// Grouped into one struct (instead of 8 more positional parameters on
/// `PeerSyncSession::new_with_forwarding`) so a call site that only cares
/// about overriding one or two of them can start from
/// [`Self::denied`]/[`Self::test_permissive`] and use struct-update syntax
/// rather than repeating all 8 positionally every time.
pub struct PeerSyncSessionOneTimeDeps {
    pub pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    pub root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    pub change_authenticator: Arc<dyn ChangeAuthenticator>,
    pub handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
    pub rebootstrap_handler: Arc<dyn RebootstrapHandler>,
    pub block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
    pub handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    /// Unlike the other 7 fields, has no universal non-`None` default --
    /// see the `change_emitter` field's own doc comment.
    pub change_emitter: Option<Arc<yadorilink_replica_domain::admission::ChangeEmitter>>,
}

impl PeerSyncSessionOneTimeDeps {
    /// Fail-closed/no-op defaults for every field but `change_emitter`
    /// (left `None`, its own only safe default) -- mirrors
    /// `PeerSyncSessionDeps::standalone()`'s own defaults exactly, for a
    /// caller that constructs a session directly against this crate's
    /// implementation module without daemon wiring.
    pub fn denied() -> Self {
        Self {
            pending_local_change_flush: Arc::new(DeniedPendingLocalChangeFlush),
            root_commit_authority_provider: Arc::new(DenyRootCommitAuthorityProvider),
            change_authenticator: Arc::new(DeniedChangeAuthenticator),
            handoff_lease_responder: Arc::new(DeniedHandoffLeaseResponder),
            rebootstrap_handler: Arc::new(DeniedRebootstrapHandler),
            block_write_activity_provider: Arc::new(DeniedBlockWriteActivityProvider),
            handoff_ticket_responder: Arc::new(DeniedHandoffTicketResponder),
            change_emitter: None,
        }
    }

    /// Like [`Self::denied`], but with `root_commit_authority_provider`
    /// replaced by the permissive [`AlwaysValidRootCommitAuthorityProvider`]
    /// -- the default `PeerSyncSession::new`/`new_with_forwarding` used to
    /// install automatically under `#[cfg(any(test, feature =
    /// "test-support"))]` before this field became a constructor argument.
    /// Tests that construct a session directly through this module's
    /// `new_with_forwarding` and only need to override one of the other 7
    /// fields should start from this, not `denied()`, to keep the same
    /// permissive root-commit-authority behavior every other test in this
    /// file already relies on implicitly via `PeerSyncSession::new`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_permissive() -> Self {
        Self {
            root_commit_authority_provider: Arc::new(AlwaysValidRootCommitAuthorityProvider),
            ..Self::denied()
        }
    }
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
    ) -> Result<Option<PreparedRebootstrap>, PeerSessionError>;

    /// Verifies an incoming `RebootstrapRequired`'s signature and internal
    /// structure against this device's trust resolver, before its snapshot
    /// bytes are even decoded. Callers must run this before
    /// `install_rebootstrap`.
    fn verify_rebootstrap(&self, required: &RebootstrapRequired) -> Result<(), PeerSessionError>;

    /// Verifies the snapshot content and atomically installs it as the new
    /// HistoryBase. Callers must have already run `verify_rebootstrap` (and,
    /// for the wire path, confirmed the connected peer's authenticated
    /// identity matches `required.manifest.signer_device_id` — this trait
    /// has no session identity of its own to check that against).
    fn install_rebootstrap(
        &self,
        required: &RebootstrapRequired,
        snapshot_bytes: &[u8],
    ) -> Result<(), PeerSessionError>;
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
/// Composes `hazard::invalid_name_reason`, `hazard::case_fold_collision`
/// (only even queried when `hazard::is_case_insensitive_filesystem` says
/// `root`'s filesystem actually needs the check) and `hazard::
/// normalization_collision` (independently gated on `hazard::is_
/// normalization_insensitive_filesystem` — the two probes are separate
/// axes, see that function's own doc comment for why) — `None` means safe
/// to materialize normally.
///
/// Taking an explicit `policy` (rather than hardcoding `NamePolicy::
/// local` here) is what makes a "held on a Windows-policy test
/// target, materializes normally on a POSIX-policy test target, from the
/// same index state" scenario directly testable in one process regardless
/// of which platform actually runs the test suite —
/// `PeerSyncSession::hazard_reason_for` (this function's only production
/// caller) always passes `hazard::NamePolicy::local`.
///
/// Computed fresh on every call — `is_case_insensitive_filesystem` itself
/// re-probes on every call too (see its doc comment for why it is not
/// cached) — so a record whose hazard has since resolved (the colliding
/// sibling was
/// renamed/deleted, or an invalid name was fixed at the source) is
/// correctly recognized as no-longer-hazardous the next time this path is
/// reconciled. A peer's periodic full-index resend (already relied on
/// elsewhere for eventual consistency) is what actually triggers that next
/// reconcile — this crate has no separate "re-check every held file"
/// sweep; documented as a gap, not an oversight.
/// Cheap "did anything else write to this path" fingerprint, sampled either
/// side of a block fetch. `None` means the path does not exist; comparing
/// two samples answers "did this file change underneath us", never "what
/// does it contain". `pub`, not `pub(crate)`: `yadorilink-daemon`'s
/// `hydration.rs` reuses this exact function for its own before/after
/// block-fetch revalidation, the identical race shape one level up (a
/// daemon-orchestrated hydration's block fetch, rather than
/// `PeerSyncSession::materialize`'s eager fetch) — see that module's own
/// call sites, not just this one's.
///
/// **What it can and cannot catch.** Length plus mtime is not a content hash,
/// and deliberately so: hashing would mean a full extra read of the target on
/// every eager materialize, on the hot path, to defend a narrow race. The
/// limits, checked rather than assumed:
///
/// - Under the DST harnesses this is exact. `dst_support::clock::HarnessClock::
///   next_mtime` is strictly monotonic (its own `next_mtime_is_strictly_
///   monotonic` test asserts it) and `fs_ops::write` stamps every local write
///   through it, so a racing write always moves the mtime — a same-length
///   overwrite can never slip past.
/// - In production the residual is a same-length write landing inside the
///   filesystem's mtime granularity. `ctime` closes most of that on unix: a
///   real write always advances it, and unlike mtime it cannot be back-dated
///   by ordinary means, so a same-length same-mtime overwrite still trips this.
///   What remains uncovered is a same-length write on a non-unix filesystem
///   whose mtime granularity is coarser than the write window.
///
/// Erring toward *over*-detection is the safe direction here: a false positive
/// costs one `RetryRequired` round trip, while a false negative silently
/// destroys a user's edit. That is also why `ctime` moving for a reason other
/// than a data write (a `chmod`, a rename into place) is deliberately treated
/// as "something touched this path, decline and re-resolve" rather than
/// filtered out.
pub fn disk_race_fingerprint(
    path: &Path,
) -> Option<(u64, Option<std::time::SystemTime>, i64, i64)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let (ctime, ctime_nsec) = {
        use std::os::unix::fs::MetadataExt as _;
        (meta.ctime(), meta.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (ctime, ctime_nsec) = (0i64, 0i64);
    Some((meta.len(), meta.modified().ok(), ctime, ctime_nsec))
}

fn hazard_reason_for_policy(
    state: &dyn crate::ports::PeerReplicaStatePort,
    root: &Path,
    group_id: &str,
    record: &FileRecord,
    policy: hazard::NamePolicy,
) -> Result<Option<String>, PeerSessionError> {
    if let Some(reason) = hazard::invalid_name_reason(policy, &record.path) {
        return Ok(Some(reason));
    }
    // Both probes are real filesystem round trips (deliberately uncached --
    // see `is_case_insensitive_filesystem`'s doc comment), so each is taken
    // once here and reused across the three checks below rather than
    // re-probed per check.
    let case_insensitive = hazard::is_case_insensitive_filesystem(root);
    let normalization_insensitive = hazard::is_normalization_insensitive_filesystem(root);
    if case_insensitive {
        let siblings = state.list_files(group_id)?;
        if let Some(colliding) = hazard::case_fold_collision(&record.path, &siblings) {
            return Ok(Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_CASE_COLLISION,
                colliding.path
            )));
        }
    }
    // Independent axis from the case-insensitivity check above — a volume's
    // normalization-sensitivity is probed and applied separately, since
    // the two do not necessarily move together (see `hazard::is_
    // normalization_insensitive_filesystem`'s doc comment).
    if normalization_insensitive {
        let siblings = state.list_files(group_id)?;
        if let Some(colliding) = hazard::normalization_collision(&record.path, &siblings) {
            return Ok(Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_NORMALIZATION_COLLISION,
                colliding.path
            )));
        }
    }
    // A pair that differs on BOTH the case-fold AND normalization axes at
    // once (e.g. "Café.txt" vs "café.txt") escapes both single-axis checks
    // above independently, but collides to one physical file when the
    // volume is simultaneously case-insensitive AND
    // normalization-insensitive -- the macOS default (both HFS+ and
    // APFS). See `hazard::canonical_fold`'s doc comment for why neither
    // check above, run alone, can catch this pair.
    if case_insensitive && normalization_insensitive {
        let siblings = state.list_files(group_id)?;
        if let Some(colliding) = hazard::case_and_normalization_collision(&record.path, &siblings) {
            return Ok(Some(format!(
                "{}: collides with existing '{}'",
                hazard::HELD_REASON_CASE_AND_NORMALIZATION_COLLISION,
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
    state: &dyn crate::ports::PeerReplicaStatePort,
    group_id: &str,
    record: &FileRecord,
    reason: &str,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
    permit: &RootCommitPermit<'_>,
) -> Result<(), PeerSessionError> {
    match authoring_change_hash {
        Some(hash) => state.upsert_file_with_origin_and_author(
            group_id,
            record,
            origin_device_id,
            hash,
            permit,
        )?,
        None => state.upsert_file_with_origin(group_id, record, origin_device_id, permit)?,
    }
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

/// The symlink/exec-bit/authoring metadata paired with an incoming peer's
/// `FileRecord` (the wire's `proto::FileInfo` fields 7-10 in
/// `ProtobufPeerWireCodec`'s decode, or the equivalent local-audit fields
/// from `file_info_for_record`) that `FileRecord` itself cannot carry (see
/// `yadorilink_local_storage::chunker::owner_exec_bit_from_metadata`'s doc
/// comment for the owner-exec-bit half of this gap). Threaded alongside the
/// resulting `FileRecord` through
/// `reconcile_one_file`/`resolve_and_apply_conflict` so
/// `apply_incoming_wire_metadata` can persist it into `SyncState` at the
/// record's *final* path — which can differ from the wire path when a
/// concurrent-edit conflict renames it — immediately before `materialize`
/// is called, since `materialize`'s own symlink dispatch
/// (`SyncState::get_record_kind`) reads the local index, never the wire
/// message directly.
#[derive(Clone, Debug)]
pub struct IncomingWireMeta {
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub exec_bit: bool,
    /// The device that
    /// actually produced this incoming record's content, per the sending
    /// peer's own `SyncState::get_origin_device_id` lookup (see
    /// `file_info_for_record`). `None` when absent/empty on the wire — an
    /// older peer that predates this field, or a row that peer never
    /// recorded an origin for — callers fall back to `self.peer_device_id`
    /// in that case, matching the pre-this-fix assumption.
    pub origin_device_id: Option<String>,
    /// Required causal identity of the retained DAG change that authored
    /// this projection. A missing or malformed value is rejected; there is
    /// no version-vector compatibility fallback.
    pub authoring_change_hash: Option<ChangeHash>,
}

/// Closes a wire-serialization handoff gap (see `IncomingWireMeta`'s own doc
/// comment above for the precise gap this fills):
/// persists an incoming peer's advertised `record_kind`/`symlink_target`/
/// `symlink_out_of_root`/`exec_bit` into `SyncState` at `record.path`,
/// which must be `record`'s *final* target path (post-conflict-rename, if
/// any) — the same path `materialize` is about to be called for.
///
/// **Correctness-critical: never upserts `record`'s real content fields
/// over an existing row.** Every one of the four setters below is an
/// `UPDATE... WHERE group_id = ?, path = ?` that errors with
/// `PeerSessionError::NotFound` if no row exists yet for this path (see
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
pub fn apply_incoming_wire_metadata(
    state: &dyn crate::ports::PeerReplicaStatePort,
    group_id: &str,
    record: &FileRecord,
    meta: &IncomingWireMeta,
    permit: &RootCommitPermit<'_>,
) -> Result<(), PeerSessionError> {
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
    state.set_record_kind(group_id, &record.path, meta.record_kind, permit)?;
    state.set_symlink_target(group_id, &record.path, meta.symlink_target.as_deref())?;
    state.set_symlink_out_of_root(group_id, &record.path, meta.symlink_out_of_root)?;
    state.set_exec_bit(group_id, &record.path, meta.exec_bit, permit)?;
    Ok(())
}

/// On-demand sync's default hydration timeout.
pub const DEFAULT_HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Neutral cadence shared by low-frequency convergence maintenance: a
/// session periodically re-announces its signed DAG frontier, while the
/// daemon's disk-reconcile backstop performs its independent add-only root
/// walk. The legacy FullIndex protocol no longer exists; sharing this
/// duration does not couple the two jobs or send an index. Ninety seconds
/// bounds recovery latency without making either maintenance scan/chatty
/// enough to dominate normal synchronization.
pub const DEFAULT_MAINTENANCE_RECONCILE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(90);

/// Jitter applied to each periodic full-index-resync tick (see the
/// `resync_handle` loop in `run`), same shape as `RECONCILE_RETRY_JITTER_
/// FRACTION`/`NOT_FOUND_RETRY_JITTER_FRACTION`. Every session in a device's
/// mesh starts its resync timer at nearly the same wall-clock moment
/// (`connect_all_pairs`-style setup wires every pairing in a tight loop),
/// so an un-jittered fixed interval keeps them ticking in lockstep for the
/// rest of the session -- for an N-device full mesh that is N*(N-1)/2
/// sessions all issuing their periodic heads-announce (and the SQLite
/// index read backing it) within the same instant, every interval, for as
/// long as the session lives. Jitter applied fresh each tick (not just
/// once at startup) lets sessions drift apart from whatever lockstep they
/// started in, spreading that load across the interval instead of bursting
/// it -- the same synchronized-thundering-herd concern the two retry-delay
/// jitters above already guard against, just at a coarser (per-session-
/// timer, not per-retry) granularity.
const FULL_INDEX_RESYNC_JITTER_FRACTION: f64 = 0.25;

fn jittered_full_index_resync_interval(base: std::time::Duration) -> std::time::Duration {
    let jitter =
        rand::random_range(-FULL_INDEX_RESYNC_JITTER_FRACTION..=FULL_INDEX_RESYNC_JITTER_FRACTION);
    base.mul_f64(1.0 + jitter)
}

static MATERIALIZATION_AUDITS_IN_FLIGHT: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

/// Diagnostic correlation id, shared by `reconcile_local_materialization_
/// audit` and `reconcile_paths_directly`, for the `taguchi_row_14`
/// intermittent-stall investigation (see
/// `fix/conflict-copy-convergence-obligation-20260723`) — a single global
/// counter (not per-device, not per-mechanism) so every log line from a
/// given call, from either entry point, across every device in a single
/// multi-device test process, carries one unambiguous id.
static NEXT_AUDIT_ATTEMPT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_audit_attempt_id() -> u64 {
    NEXT_AUDIT_ATTEMPT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `retire_conflict_copies_only`'s whole-pass frontier freshness check --
/// factored out to a pure function so its exact semantics (a plain slice
/// comparison; any number of intermediate admissions during the pass
/// collapses to the same before/after mismatch as a single one) can be
/// tested without any async execution, DAG store, or session plumbing.
/// `dag_group_heads`'s own `ORDER BY change_hash` makes two reads of an
/// unchanged frontier compare equal regardless of admission order, so this
/// never needs to sort its inputs itself.
fn frontier_changed_during_pass(before: &[ChangeHash], after: &[ChangeHash]) -> bool {
    before != after
}

#[cfg(test)]
mod frontier_freshness_tests {
    use super::*;

    fn hash(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    /// Case 1: an unchanged frontier is the only shape
    /// `retire_conflict_copies_only` may report its inner outcome as-is --
    /// this is what lets a genuinely `Settled` pass complete its
    /// generation.
    #[test]
    fn unchanged_frontier_is_not_reported_as_changed() {
        let before = vec![hash(1), hash(2)];
        let after = vec![hash(1), hash(2)];
        assert!(!frontier_changed_during_pass(&before, &after));
    }

    /// Case 2: any admission during the pass -- growing the frontier, not
    /// just replacing a head -- must be caught, since a caller that
    /// completed the generation anyway would never re-evaluate the newly
    /// admitted change's effect on justification.
    #[test]
    fn a_frontier_that_gained_a_head_during_the_pass_is_reported_as_changed() {
        let before = vec![hash(1)];
        let after = vec![hash(1), hash(2)];
        assert!(frontier_changed_during_pass(&before, &after));
    }

    /// A head superseded mid-pass (frontier shrinks by one, gains a
    /// different one) must equally be caught -- not just a pure growth.
    #[test]
    fn a_frontier_whose_heads_were_replaced_during_the_pass_is_reported_as_changed() {
        let before = vec![hash(1), hash(2)];
        let after = vec![hash(1), hash(3)];
        assert!(frontier_changed_during_pass(&before, &after));
    }

    /// Case 4: multiple intermediate admissions during one pass (e.g. two
    /// separate peer changes landing back to back) still collapse to a
    /// single before/after mismatch -- there is no per-admission tracking
    /// to lose count of; only the endpoints of the pass are ever compared,
    /// so no intermediate change can be coalesced away and missed.
    #[test]
    fn multiple_intermediate_admissions_still_trip_the_check() {
        let before = vec![hash(1)];
        let mid = vec![hash(1), hash(2)];
        let after = vec![hash(1), hash(2), hash(3)];
        assert!(frontier_changed_during_pass(&before, &mid));
        assert!(frontier_changed_during_pass(&before, &after));
        assert!(frontier_changed_during_pass(&mid, &after));
    }
}

struct MaterializationAuditGuard {
    key: String,
}

impl MaterializationAuditGuard {
    fn try_acquire(
        state: &Arc<dyn crate::ports::PeerReplicaStatePort>,
        group_id: &str,
    ) -> Option<Self> {
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

static RETIREMENT_AUDITS_IN_FLIGHT: OnceLock<StdMutex<HashSet<String>>> = OnceLock::new();

/// `retire_conflict_copies_only`'s own single-flight, deliberately a
/// SEPARATE key space from `MaterializationAuditGuard` rather than sharing
/// its key. Before this, retirement contended with `reconcile_local_
/// materialization_audit`/`reconcile_paths_directly` for the exact same
/// per-group slot: a full audit or direct path reconciliation already in
/// flight for a group made every retirement pass against it report `Busy`
/// for that entire duration, even though retirement's own physical
/// mutation is already independently serialized per-path by `state.
/// path_lock` (see `retire_unjustified_ephemeral_conflict_copies`'s own
/// path-lock acquisition, and `reconcile_group_paths`'/`apply_locked_
/// record`'s matching ones) -- the group-wide guard was serializing far
/// more than the one thing (two writers racing the SAME path) that
/// actually needed serializing. Only retirement passes now contend with
/// each other; a long-running full audit no longer blocks retirement's own
/// progress, and vice versa.
struct RetirementAuditGuard {
    key: String,
}

impl RetirementAuditGuard {
    fn try_acquire(
        state: &Arc<dyn crate::ports::PeerReplicaStatePort>,
        group_id: &str,
    ) -> Option<Self> {
        let key = format!("{:p}:{group_id}", Arc::as_ptr(state));
        let in_flight = RETIREMENT_AUDITS_IN_FLIGHT.get_or_init(Default::default);
        let mut in_flight = in_flight.lock().unwrap_or_else(|p| p.into_inner());
        if !in_flight.insert(key.clone()) {
            return None;
        }
        Some(Self { key })
    }
}

impl Drop for RetirementAuditGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = RETIREMENT_AUDITS_IN_FLIGHT.get() {
            in_flight.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
        }
    }
}

#[cfg(test)]
mod retirement_audit_guard_tests {
    use super::*;
    use crate::test_support::FakeReplicaState;

    /// The core Commit-4 regression: before `RetirementAuditGuard` existed,
    /// `retire_conflict_copies_only` shared `MaterializationAuditGuard`'s
    /// key, so a full audit already in flight for a group made every
    /// retirement pass against it report `Busy` for the entire duration.
    /// A held `MaterializationAuditGuard` must no longer block
    /// `RetirementAuditGuard::try_acquire` for the SAME state+group.
    #[test]
    fn retirement_guard_is_independent_of_a_held_materialization_guard() {
        let state: Arc<dyn crate::ports::PeerReplicaStatePort> = FakeReplicaState::new_arc();
        let _materialization_guard = MaterializationAuditGuard::try_acquire(&state, "group-a")
            .expect("materialization guard must be free at test start");
        let retirement_guard = RetirementAuditGuard::try_acquire(&state, "group-a");
        assert!(
            retirement_guard.is_some(),
            "a held MaterializationAuditGuard must not block RetirementAuditGuard"
        );
    }

    /// The reverse must also hold: a held `RetirementAuditGuard` must not
    /// block `MaterializationAuditGuard::try_acquire` for the same
    /// state+group -- the two key spaces are fully independent, not just
    /// independent in one direction.
    #[test]
    fn materialization_guard_is_independent_of_a_held_retirement_guard() {
        let state: Arc<dyn crate::ports::PeerReplicaStatePort> = FakeReplicaState::new_arc();
        let _retirement_guard = RetirementAuditGuard::try_acquire(&state, "group-a")
            .expect("retirement guard must be free at test start");
        let materialization_guard = MaterializationAuditGuard::try_acquire(&state, "group-a");
        assert!(
            materialization_guard.is_some(),
            "a held RetirementAuditGuard must not block MaterializationAuditGuard"
        );
    }

    /// `RetirementAuditGuard` must still single-flight against ITSELF per
    /// group -- decoupling from `MaterializationAuditGuard` must not
    /// accidentally drop retirement's own single-flight entirely.
    #[test]
    fn retirement_guard_still_excludes_a_second_retirement_pass_for_the_same_group() {
        let state: Arc<dyn crate::ports::PeerReplicaStatePort> = FakeReplicaState::new_arc();
        let _first = RetirementAuditGuard::try_acquire(&state, "group-a")
            .expect("first retirement guard must be free at test start");
        assert!(
            RetirementAuditGuard::try_acquire(&state, "group-a").is_none(),
            "two retirement passes for the same group must still contend"
        );
    }

    /// A different group under the same state must never contend with
    /// either guard -- the key is per-(state, group), not per-state alone.
    #[test]
    fn retirement_guard_does_not_contend_across_different_groups() {
        let state: Arc<dyn crate::ports::PeerReplicaStatePort> = FakeReplicaState::new_arc();
        let _guard_a = RetirementAuditGuard::try_acquire(&state, "group-a")
            .expect("group-a's retirement guard must be free at test start");
        assert!(
            RetirementAuditGuard::try_acquire(&state, "group-b").is_some(),
            "a held retirement guard for group-a must not block group-b"
        );
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

/// Outcome of `hydrate_file`/`hydrate_file_with_timeout`. A plain `Ok(())`
/// used to mean "bytes fetched AND written to disk under this name" in
/// every case except one: a filename hazard discovered after every block
/// was already fetched into the local block store reverts the row to
/// `Placeholder` and returns success anyway (the blocks really were
/// fetched; only the physical write was withheld) -- see the hazard
/// short-circuit inside `hydrate_file_with_timeout`. That collapsed two
/// meaningfully different outcomes into one signal: `pin_and_hydrate_file`
/// (whose own doc says "pinning forces hydration") could report success
/// while the pinned file still had no content on disk at all. This type
/// exists so a caller can tell the two apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrationOutcome {
    /// Content is fully written to disk under this path's name.
    Hydrated,
    /// Every block was fetched into the local block store (so this device
    /// can still serve them onward to another peer), but a filename
    /// hazard withheld the physical write. The row is back at
    /// `Placeholder`, held, exactly as if hydration had never been
    /// attempted -- a caller relying on "hydration means the file is now
    /// on disk" must not treat this the same as `Hydrated`.
    Held { reason: String },
}

/// RAII guard for `hydrate_file_with_timeout`'s `Hydrating` window: reverts
/// the row back to `Placeholder` on drop unless `committed` is set first.
/// Every fallible step between marking a row `Hydrating` and either
/// `commit`ing it (a genuine `Hydrated`) or hitting one of the two
/// already-handled non-error exits (fetch failure, hazard-hold — both of
/// which also just let this guard's drop do the revert) used to leave the
/// row stuck at `Hydrating` on any other error, with no independent
/// recovery: the materialization audit that could otherwise notice and
/// repair it needs a connected peer to even run (see the "no connected
/// peer" scheduling gate this same review round flagged as a separate,
/// larger gap).
pub struct HydratingStateGuard<'a> {
    pub state: &'a dyn crate::ports::PeerReplicaStatePort,
    pub group_id: &'a str,
    pub path: &'a str,
    /// This attempt's own authoring identity, captured before it set
    /// `Hydrating` — see the guard's `Drop` impl for why a state-only CAS
    /// isn't enough on its own.
    pub authoring_change_hash: Option<ChangeHash>,
    pub committed: bool,
}

impl Drop for HydratingStateGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // A conditional transition bound to BOTH the expected state
            // (`Hydrating`) AND this attempt's own authoring identity, not
            // a blind `set_materialization_state`. State alone is not
            // enough: `hydrate_file_with_timeout` takes no per-path lock
            // of its own, so two concurrent calls for the same path can
            // race, and a state-only CAS cannot tell "this row is still
            // the SAME version this attempt started with, just still
            // `Hydrating`" apart from "a NEWER version of this path
            // became current mid-hydration and happened to also land in
            // `Hydrating` before this attempt's cleanup ran" (a peer's
            // concurrent update superseding the row). Binding to the
            // authoring identity too means this only ever reverts the
            // exact version this attempt was hydrating, never a
            // different one that happens to share the same state value.
            //
            // Best-effort on error: this already runs during unwind from
            // a `?` elsewhere in the same function, so a second failure
            // here has nowhere better to go than a log line -- matching
            // every other best-effort revert-on-drop path in this crate.
            match self.state.transition_materialization_state_if_same_authoring(
                self.group_id,
                self.path,
                MaterializationState::Hydrating,
                self.authoring_change_hash.as_ref(),
                MaterializationState::Placeholder,
            ) {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        group_id = self.group_id,
                        path = self.path,
                        error = %e,
                        "failed to revert an aborted hydration's materialization state back to \
                         Placeholder; row may be stuck at Hydrating"
                    );
                }
            }
        }
    }
}

/// Outcome of `apply_locked_record`: the incoming record was either fully
/// handled without a conflict (adopted / peer-ahead / already-current /
/// never-seen), or it is genuinely concurrent with the local record and the
/// caller must decide how to resolve it. No surviving caller turns
/// `Concurrent` into a resolution: the DAG engine resolves concurrency by
/// (lamport, change-hash) before a record ever reaches here, and the
/// materialization-audit path treats it as unreachable.
#[derive(Debug)]
pub enum LockedRecordOutcome {
    Settled,
    /// `materialize` reported `MaterializeResult::RetryRequired` for this
    /// record: an eager/pinned fetch could not obtain every block, a
    /// hazard-collision tombstone dropped or held without actually
    /// deleting anything, or some other "not done" outcome
    /// `MaterializeResult`'s own doc comment describes. Every caller of
    /// `apply_locked_record` used to call `self.materialize(...).await?`
    /// and discard its `Ok` value entirely, always returning `Settled`
    /// regardless -- silently collapsing exactly the distinction
    /// `MaterializeResult` exists to preserve, the same class of bug
    /// `reconcile_group_paths`'s `Absent` branch had on the DAG side (see
    /// that fix's own doc comment for the `dag_mark_applied`/periodic-
    /// reprojection consequence of getting this wrong).
    RetryRequired,
    /// Carries only the local record, for the caller's diagnostic log: no
    /// surviving caller resolves a concurrency here, so the incoming record
    /// and its wire metadata would be dead payload.
    Concurrent {
        local: FileRecord,
    },
}

pub struct PeerSyncSession {
    channel: Arc<dyn crate::ports::PeerMessageChannel>,
    /// The sole protobuf/wire-format implementation this crate has (Phase
    /// 7C.5) -- held as `Arc<dyn PeerWireCodec>` rather than the concrete
    /// `ProtobufPeerWireCodec` so that swapping in a different codec (a
    /// fake for tests, or a future format) never touches this struct's own
    /// field type, only what `new_with_forwarding` constructs. Not yet a
    /// constructor parameter: every real caller wants the same protobuf
    /// codec today, so `new_with_forwarding` builds it internally rather
    /// than adding a 10th positional argument every call site would have
    /// to pass identically.
    codec: Arc<dyn yadorilink_sync_wire::PeerWireCodec>,
    local_device_id: String,
    peer_device_id: String,
    state: Arc<dyn crate::ports::PeerReplicaStatePort>,
    // On the `BlockContentStore` port: three call sites (`materialize`'s and
    // `hydrate_file_with_timeout`'s reconstruct steps) forward this straight
    // into `chunker::reconstruct_file`, which now takes `&dyn
    // BlockContentStore` — the same port `materialization.rs`'s
    // `reconstruct_file_journaled`/`repair_interrupted_materializations_inner`
    // forward into, so this field only ever needs `get`/`put`/
    // `present_blocks`.
    store: Arc<dyn crate::ports::BlockContentStore>,
    /// DAG/index-mutation logic that is true regardless of which peer sent
    /// the message, extracted out of this file's own handlers one handler
    /// at a time into `yadorilink-replica-engine` -- see that crate's own
    /// doc comment. Cheap to construct (just an `Arc` clone of `state`
    /// above and an `Arc` clone of `store` above wrapped in this crate's
    /// port adapters), so it is built once at construction time rather
    /// than lazily.
    pub replica_engine: yadorilink_replica_engine::PeerReplicaEngine,
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
    /// This session's shared, device-wide block-serving credit/coalescing
    /// engine, set once by `DaemonState` after construction (see
    /// `block_serve::BlockServeEngine`'s own doc comment for why this is a
    /// setter rather than a constructor parameter). `None` until set, and
    /// for every test that never calls the setter -- `handle_block_request`
    /// falls back to today's ungated direct-serve behavior whenever this is
    /// `None`, regardless of what the peer advertised.
    block_serve_engine: std::sync::Mutex<Option<Arc<crate::block_serve::BlockServeEngine>>>,
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
    pending_block_requests_by_id: PendingBlockRequestsById,
    /// Monotonic id used to correlate a `BlockRequest` with its
    /// `BlockReply`. Starts at 1 so `0` (a legacy/unset default) never
    /// collides with a real one.
    next_block_request_id: std::sync::atomic::AtomicU64,
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
    /// `DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`'s doc comment for why this
    /// exists at all. Mutable-after-construction (`StdMutex`, mirroring
    /// `headroom_override_bytes`'s exact shape) rather than a constructor
    /// parameter so every existing call site (every test, every daemon
    /// construction site) keeps compiling and behaving identically --
    /// `set_full_index_resync_interval` is the opt-in override.
    full_index_resync_interval: StdMutex<std::time::Duration>,
    /// This session's
    /// caller-injected way to force-flush a path's pending local debounce
    /// entry before reconciling it against a peer update — see
    /// `PendingLocalChangeFlush`'s doc comment. Set once at construction
    /// (`PeerSyncSessionOneTimeDeps`); a caller with nothing real to inject
    /// passes a no-op implementation, which makes `reconcile_one_file`'s
    /// guard a no-op, i.e. the same behavior an absent handle used to
    /// produce. Only `yadorilink-daemon`'s real construction site wires up
    /// an actual handle.
    pending_local_change_flush: Arc<dyn PendingLocalChangeFlush>,
    /// This session's caller-injected way to obtain a `RootCommitPermit`
    /// authority for a group -- see `RootCommitAuthorityProvider`'s doc
    /// comment. Set once at construction; a caller with no real per-link
    /// fence lookup passes a deny-by-default implementation, so every gated
    /// `SyncState` mutation this session attempts fails closed with
    /// `PeerSessionError::NotFound` (no link available) rather than silently
    /// constructing a permissive fallback permit. Only `yadorilink-daemon`'s
    /// real construction site wires up the actual per-link fence lookup.
    root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
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
    /// (see `ChangeAuthenticator`). Set once at construction; a caller with
    /// no real authenticator passes a deny-by-default implementation, so a
    /// session with no real authenticator can still announce heads and
    /// serve already-stored changes, but never admits an unverifiable
    /// incoming change. The change-history *store* itself is `self.state`
    /// (the same `SyncState`/SQLite the index lives in), so no separate
    /// store handle is needed.
    change_authenticator: Arc<dyn ChangeAuthenticator>,
    /// Correlates outstanding `HandoffLeaseRequest`s to the oneshot
    /// `request_handoff_lease_from_peer` awaits: request_id -> reply sender.
    /// Mirrors `pending_version_present` exactly, one map per exchange since
    /// the two request ids are drawn from independent counters.
    pending_handoff_lease: StdMutex<HashMap<u64, oneshot::Sender<Option<PeerHandoffLeaseGrant>>>>,
    /// Monotonic id used to correlate a `HandoffLeaseRequest` with its reply.
    next_handoff_lease_request_id: std::sync::atomic::AtomicU64,
    /// This session's caller-injected bridge to the daemon's own
    /// coordination-plane-backed lease machinery (`DaemonState::request_
    /// handoff_lease`) — see `HandoffLeaseResponder`'s doc comment. Set once
    /// at construction; a caller with no real responder passes a
    /// deny-by-default implementation, so an incoming `HandoffLeaseRequest`
    /// answers `granted = false` rather than panic or hang.
    handoff_lease_responder: Arc<dyn HandoffLeaseResponder>,
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
    /// doc comment. Set once at construction; a caller with no real handler
    /// passes a deny-by-default implementation, so an incoming
    /// `RebootstrapSnapshotRequest` answers `granted = false` rather than
    /// panic or hang.
    rebootstrap_handler: Arc<dyn RebootstrapHandler>,
    block_write_activity_provider: Arc<dyn BlockWriteActivityProvider>,
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
    /// ticket`) -- see `HandoffTicketResponder`'s doc comment. Set once at
    /// construction; a caller with no real responder passes a
    /// deny-by-default implementation, so an incoming `HandoffTicketRequest`
    /// answers `granted = false` rather than panic or hang.
    handoff_ticket_responder: Arc<dyn HandoffTicketResponder>,
    /// This session's real signing capability — a device id bound to its
    /// own Ed25519 private key (`dag_store::ChangeEmitter`) — used to author
    /// a captured change for content this device's own materialize path
    /// displaces into the reserved namespace during custody transfer (see
    /// `captured_authoring`'s module doc: retention alone hides the content
    /// from every other device until an authored change publishes it).
    /// Set once at construction (unlike the other 7 one-time capabilities,
    /// this one genuinely has no universal non-`None` default: a device
    /// with no signing key yet has no substitute to fall back to). `None`
    /// for every existing test/call site that has not wired a key
    /// (mirrors `change_authenticator`'s own old default exactly — that
    /// field verifies what arrives, this one signs what this device
    /// originates, and both start absent). A device that has not wired a
    /// key here MUST retain and leave the content unauthored rather than
    /// proceed as if the write happened; it must never fall back to
    /// signing with some other key or skipping the signature.
    /// `change_emitter()` returning `None` is that signal, and every future
    /// caller is required to treat it as "not yet safe to author," the same
    /// fail-closed contract `link_manager::ensure_initial_change_history`
    /// already applies to a registered device with no signing key.
    change_emitter: Option<Arc<yadorilink_replica_domain::admission::ChangeEmitter>>,
}

impl PeerSyncSession {
    /// This build's own protocol generation -- see
    /// `ClusterConfig.protocol_version`'s own doc comment for what a bump
    /// means and why it's a one-way refusal gate, not an additive
    /// capability negotiation.
    pub const PROTOCOL_VERSION: u32 = 2;

    /// The lowest `ClusterConfig.protocol_version` this build will
    /// continue exchanging group authorization with. A peer reporting
    /// anything below this (including the proto3 default `0`, i.e. a peer
    /// that predates the field entirely) only ever spoke the removed
    /// `BlockResponse`/hash-only-correlated block-serving path -- there is
    /// no fallback to negotiate down to (see `ClusterConfig.protocol_
    /// version`'s own doc comment), so such a peer has every currently-
    /// granted group authorization withdrawn instead of being served on a
    /// best-effort basis (`handle_message`'s `ClusterConfig` arm).
    const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

    /// Convenience constructor: `forward_tx` is `None` and this session's 8
    /// one-time capability injections default to
    /// `PeerSyncSessionOneTimeDeps::test_permissive()` under `#[cfg(any(test,
    /// feature = "test-support"))]` (a permissive `root_commit_authority_
    /// provider`, deny/no-op everything else -- the same defaults every
    /// pre-existing test/call site that constructs a session this way
    /// implicitly relied on) or `PeerSyncSessionOneTimeDeps::denied()`
    /// otherwise. A caller that needs to override any of the 8 should call
    /// `new_with_forwarding` directly instead.
    pub fn new(
        channel: Arc<dyn crate::ports::PeerMessageChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<dyn crate::ports::PeerReplicaStatePort>,
        store: Arc<dyn crate::ports::BlockContentStore>,
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
            {
                #[cfg(any(test, feature = "test-support"))]
                {
                    PeerSyncSessionOneTimeDeps::test_permissive()
                }
                #[cfg(not(any(test, feature = "test-support")))]
                {
                    PeerSyncSessionOneTimeDeps::denied()
                }
            },
        )
    }

    /// Like `new`, but forwards every record this session adopts or
    /// resolves from its peer to `forward_tx` as `(group_id, record)` (see
    /// `forward_tx`'s doc comment), and takes this session's 8 one-time
    /// capability injections explicitly (see `PeerSyncSessionOneTimeDeps`'s
    /// own doc comment) instead of defaulting them.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_forwarding(
        channel: Arc<dyn crate::ports::PeerMessageChannel>,
        local_device_id: String,
        peer_device_id: String,
        state: Arc<dyn crate::ports::PeerReplicaStatePort>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        shared_group_ids: Vec<String>,
        sync_roots: HashMap<String, PathBuf>,
        forward_tx: Option<mpsc::UnboundedSender<(String, FileRecord)>>,
        one_time_deps: PeerSyncSessionOneTimeDeps,
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
        let replica_state_adapter = std::sync::Arc::new(
            crate::replica_engine_ports::PeerReplicaStateAdapter(state.clone()),
        );
        let replica_engine = yadorilink_replica_engine::PeerReplicaEngine::new(
            yadorilink_replica_engine::ReplicaEngineDependencies {
                history: replica_state_adapter.clone(),
                admission: replica_state_adapter.clone(),
                frontier: replica_state_adapter,
                durability: std::sync::Arc::new(
                    crate::replica_engine_ports::DurabilityEvidenceAdapter {
                        state: state.clone(),
                        store: store.clone(),
                    },
                ),
            },
        );
        Arc::new(Self {
            channel,
            codec: Arc::new(yadorilink_sync_wire::ProtobufPeerWireCodec),
            local_device_id,
            peer_device_id,
            state,
            store,
            replica_engine,
            shared_group_ids,
            live_authorized_groups,
            peer_supports_reliable_delivery: std::sync::atomic::AtomicBool::new(false),
            peer_supports_version_present: std::sync::atomic::AtomicBool::new(false),
            peer_supports_version_hash_exact: std::sync::atomic::AtomicBool::new(false),
            block_serve_engine: std::sync::Mutex::new(None),
            peer_handshake_received: std::sync::atomic::AtomicBool::new(false),
            handshake_notify: tokio::sync::Notify::new(),
            peer_acked_my_cluster_config: std::sync::atomic::AtomicBool::new(false),
            canonical_sync_roots,
            ignore_sets,
            pending_block_requests_by_id: StdMutex::new(HashMap::new()),
            next_block_request_id: std::sync::atomic::AtomicU64::new(1),
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
            full_index_resync_interval: StdMutex::new(DEFAULT_MAINTENANCE_RECONCILE_INTERVAL),
            pending_local_change_flush: one_time_deps.pending_local_change_flush,
            root_commit_authority_provider: one_time_deps.root_commit_authority_provider,
            peer_supports_change_dag: std::sync::atomic::AtomicBool::new(false),
            change_authenticator: one_time_deps.change_authenticator,
            pending_handoff_lease: StdMutex::new(HashMap::new()),
            next_handoff_lease_request_id: std::sync::atomic::AtomicU64::new(1),
            handoff_lease_responder: one_time_deps.handoff_lease_responder,
            pending_rebootstrap_snapshot: StdMutex::new(HashMap::new()),
            next_rebootstrap_snapshot_request_id: std::sync::atomic::AtomicU64::new(1),
            rebootstrap_handler: one_time_deps.rebootstrap_handler,
            block_write_activity_provider: one_time_deps.block_write_activity_provider,
            pending_handoff_ticket: StdMutex::new(HashMap::new()),
            next_handoff_ticket_request_id: std::sync::atomic::AtomicU64::new(1),
            handoff_ticket_responder: one_time_deps.handoff_ticket_responder,
            change_emitter: one_time_deps.change_emitter,
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
    /// `DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`) -- mirrors
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

    /// The `RootLease` for `group_id` from this session's injected
    /// provider, or `Err(PeerSessionError::NotFound)` if the provider reports no
    /// live link for this group -- fail closed, never a permissive fallback
    /// lease. A caller with no real per-link fence lookup is constructed
    /// with a deny-by-default provider (see `PeerSyncSessionOneTimeDeps::
    /// denied`), which reports no live link for every group and so hits
    /// this same `NotFound` outcome unconditionally.
    fn root_lease_for(
        &self,
        group_id: &str,
    ) -> Result<Arc<yadorilink_root_authority::root_commit::RootLease>, PeerSessionError> {
        self.root_commit_authority_provider.root_lease_for(group_id).ok_or_else(|| {
            PeerSessionError::NotFound(format!(
                "no live root-commit authority for group {group_id} (no established link, \
                 or no provider injected)"
            ))
        })
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
    async fn flush_pending_local_change_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let handle = self.pending_local_change_flush.clone();
        // Marks that the guard was reached for this path — the first fork
        // when a local write is lost despite this guard existing. A missing
        // trace line here means the guard never ran on that route at all,
        // which is a different bug from it running and finding nothing.
        crate::dst_trace(rel_path, || {
            format!(
                "flush guard entered on {} (peer={})",
                self.local_device_id, self.peer_device_id
            )
        });
        tracing::debug!(
            group_id,
            path = rel_path,
            peer = %self.peer_device_id,
            "checking this link's debounce accumulator for a pending local change before reconciling this path against a peer update"
        );
        handle.flush_pending_local_change(group_id, rel_path).await
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
    async fn flush_case_fold_sibling_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        // No root for this group means nothing of ours is on disk to collide
        // with, so there is no case-fold sibling to flush.
        let Ok(root) = self.sync_root(group_id) else {
            return PendingLocalFlushOutcome::Settled;
        };
        if !hazard::is_case_insensitive_filesystem(&root) {
            return PendingLocalFlushOutcome::Settled;
        }
        let handle = self.pending_local_change_flush.clone();
        tracing::debug!(
            group_id,
            path = rel_path,
            peer = %self.peer_device_id,
            "checking this link's debounce accumulator for a pending case-fold sibling change before reconciling this path against a peer update"
        );
        handle.flush_case_fold_sibling(group_id, rel_path).await
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
        if supported.contains(&yadorilink_sync_wire::COMPRESSION_ZSTD) {
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
    pub fn record_peer_version_hash_exact_support(&self, supported: bool) {
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

    /// Installs this session's device-wide block-serve engine, set once by
    /// `DaemonState` after construction — see `block_serve::BlockServeEngine`'s
    /// own doc comment for why this is a post-construction setter rather
    /// than a constructor parameter.
    pub fn set_block_serve_engine(&self, engine: Arc<crate::block_serve::BlockServeEngine>) {
        *self.block_serve_engine.lock().unwrap_or_else(|p| p.into_inner()) = Some(engine);
    }

    fn block_serve_engine(&self) -> Option<Arc<crate::block_serve::BlockServeEngine>> {
        self.block_serve_engine.lock().unwrap_or_else(|p| p.into_inner()).clone()
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
    pub fn cluster_config_message(&self) -> yadorilink_sync_wire::OutboundFrame {
        // `None` (no engine set: a session that doesn't care about block
        // serving, or a real session before `DaemonState` finishes
        // constructing its shared engine) advertises all-zero hints --
        // there's no capability flag gating this anymore
        // (`protocol_version` below is the only thing a peer checks), but a
        // session with nothing installed genuinely has nothing real to
        // report.
        let serve_hints = self
            .block_serve_engine()
            .map(|engine| engine.advertised_hints())
            .unwrap_or(crate::block_serve::ServeCreditHints {
                max_inflight_requests: 0,
                max_inflight_bytes: 0,
                available_worker_slots: 0,
                estimated_queue_delay_ms: 0,
            });
        yadorilink_sync_wire::OutboundFrame::ClusterConfig(
            yadorilink_sync_wire::ClusterConfigOutboundFrame {
                folder_group_ids: self.shared_group_ids.clone(),
                known_peer_device_ids: vec![self.local_device_id.clone()],
                // This build always
                // supports zstd, so it always advertises it — the peer's
                // own advertisement (recorded in `handle_message`'s
                // `ClusterConfig` arm) is the other half of the
                // both-sides-must-advertise negotiation.
                supported_compression: vec![yadorilink_sync_wire::COMPRESSION_ZSTD],
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
                max_inflight_requests: serve_hints.max_inflight_requests,
                max_inflight_bytes: serve_hints.max_inflight_bytes,
                available_worker_slots: serve_hints.available_worker_slots,
                estimated_queue_delay_ms: serve_hints.estimated_queue_delay_ms,
                // This build's own protocol generation -- see that field's
                // own doc comment for why this is a one-way "refuse
                // entirely below this" gate, not a `supports_*`-style
                // both-sides-negotiate-down capability.
                protocol_version: Self::PROTOCOL_VERSION,
            },
        )
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

    /// How often this session re-sends `ClusterConfig` PURELY to refresh
    /// its serve-credit hints (`ServeCreditHints`'s four fields) --
    /// independent of `peer_acked_my_cluster_config`'s negotiation-
    /// bootstrap semantics (`spawn_cluster_config_retry`/the periodic
    /// resync's own re-offer below BOTH stop sending entirely once that
    /// flips true, since their job -- making sure the peer eventually
    /// learns this device's capabilities -- is already done at that point)
    /// and independent of `DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`'s much
    /// coarser 90s cadence (measured too slow for a peer's own source-
    /// selection to react to this device quieting down or becoming busy).
    /// `BlockServeEngine::advertised_hints` recomputes fresh on every call,
    /// so without a resend independent of the one-shot handshake a peer
    /// would see only this device's STARTUP load for the rest of a long-
    /// running connection's lifetime.
    const CREDIT_HINT_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

    fn spawn_credit_hint_refresh(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak_self = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Self::CREDIT_HINT_REFRESH_INTERVAL).await;
                let Some(session) = weak_self.upgrade() else { return };
                // Nothing meaningful to refresh without an engine of this
                // device's own.
                if session.block_serve_engine().is_none() {
                    continue;
                }
                if let Err(e) = session.send_frame(session.cluster_config_message()).await {
                    tracing::warn!(
                        peer = %session.peer_device_id,
                        error = %e,
                        "periodic serve-credit hint refresh failed to send ClusterConfig"
                    );
                }
            }
        })
    }

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
                let _ = session.send_frame(session.cluster_config_message()).await;
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
    pub async fn run(self: Arc<Self>) -> Result<(), PeerSessionError> {
        self.send_frame(self.cluster_config_message()).await?;
        // The above is
        // this device's *first* handshake attempt, sent synchronously.
        // `spawn_cluster_config_retry` covers *retries* only, entirely in
        // the background, so a peer that's slow or never sends its own
        // `ClusterConfig` back (a bare test double with no reciprocal
        // `run`, or a genuinely unreachable peer) does not hold up this
        // function's own startup.
        let handshake_retry_handle = self.spawn_cluster_config_retry();
        let credit_hint_refresh_handle = self.spawn_credit_hint_refresh();

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
                    tokio::time::sleep(jittered_full_index_resync_interval(interval)).await;
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
                        if let Err(e) = session.send_frame(session.cluster_config_message()).await {
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
        // BlockReply control lane above never enters this queue, so it can
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
        let mut pending: VecDeque<(yadorilink_sync_wire::InboundFrame, usize)> = VecDeque::new();
        let mut pending_bytes = 0usize;
        loop {
            tokio::select! {
                maybe_bytes = self.channel.recv() => {
                    let Some(bytes) = maybe_bytes else { break };
                    let wire_len = bytes.len();
                    let frame = match self.codec.decode(bytes.as_slice()) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to decode sync frame, ignoring");
                            continue;
                        }
                    };
                    match frame {
                        // Never queued, never gated on a permit — this is
                        // the message type that *frees* permits (see
                        // `ensure_blocks_present`'s callers), and this
                        // `select!` arm runs regardless of how full
                        // `pending` or `message_slots` currently are, which
                        // is exactly what closes the deadlock: reading
                        // further off the wire never depends on downstream
                        // permit availability. Confirmed
                        // `handle_block_reply`'s only await point is a
                        // `spawn_blocking` zstd decompression bounded by
                        // `MAX_BLOCK_SIZE` — a fixed, finite CPU
                        // computation, not a wait on `message_slots` or on
                        // another inbound message, so it cannot itself join
                        // this deadlock's dependency cycle (it can add a
                        // small, bounded per-response delay, not an
                        // unbounded one).
                        yadorilink_sync_wire::InboundFrame::BlockReply(reply) => {
                            self.handle_block_reply(reply).await;
                        }
                        // CONV-5: `BlockRequest` is spawned immediately,
                        // never queued behind (or gated by the same permit
                        // pool as) `pending`'s control/metadata traffic
                        // below -- exactly like `BlockReply` above, except
                        // spawned rather than run inline,
                        // since real serving work (a possibly-gated disk
                        // read) can genuinely take a while, unlike those two
                        // fast reply handlers. This is deliberately NOT
                        // itself bounded by a local FIFO semaphore/queue the
                        // way `pending`'s messages are: real concurrency
                        // control and cross-peer/cross-group fairness both
                        // live in the shared `BlockServeEngine` now
                        // (`acquire_dispatch_turn`), which every session
                        // funnels into -- a per-session FIFO queue here
                        // would just reintroduce a second, uncoordinated
                        // FIFO-by-arrival head-of-line-blocking point in
                        // front of that device-wide fairness (confirmed,
                        // reproduced: a same-peer request for a different
                        // group waited behind dozens of already-queued
                        // same-group requests here even though the shared
                        // engine was ready to serve it fairly).
                        //
                        // A non-blocking pre-admission BUDGET is not the
                        // same thing as a FIFO queue, and the absence of one
                        // here left a real gap: `acquire_dispatch_turn`'s
                        // own queue-full rejection only bounds requests that
                        // have already paid for a spawned task plus the
                        // `shares_group`/reference/provenance checks
                        // `handle_block_request` runs before ever reaching
                        // it, so an authorized-but-flooding peer grew all of
                        // that unboundedly. `try_begin_examination` closes
                        // it: `try_acquire_owned` is instant (succeeds or
                        // fails immediately), so an admitted request is
                        // never made to wait behind another one here --
                        // service order is still decided entirely by the
                        // shared engine below.
                        yadorilink_sync_wire::InboundFrame::BlockRequest(req) => {
                            match self.block_serve_engine() {
                                Some(engine) => match engine.try_begin_examination() {
                                    Ok(device_wide_permit) => {
                                        let this = self.clone();
                                        let permits = BlockExaminationPermits {
                                            _device_wide: Some(device_wide_permit),
                                        };
                                        tokio::spawn(async move {
                                            if let Err(e) =
                                                this.handle_block_request(req, permits).await
                                            {
                                                tracing::warn!(error = %e, "error handling block request");
                                            }
                                        });
                                    }
                                    Err(busy) => {
                                        // No spawn here, deliberately: this
                                        // arm runs on every request from a
                                        // possibly-flooding peer, so a
                                        // spawned task that then blocks on
                                        // `send` against a stalled/non-
                                        // draining peer would just relocate
                                        // the unbounded-task growth
                                        // `try_begin_examination` exists to
                                        // prevent. `try_send_block_reply_
                                        // busy` is instant and never blocks;
                                        // a dropped reply on a full outbound
                                        // queue is fine -- the requester's
                                        // own bounded retry loop recovers.
                                        let _ = self.try_send_block_reply_busy(&req, busy);
                                    }
                                },
                                // No engine wired yet: `handle_block_request`
                                // itself fails closed on this (see `set_
                                // block_serve_engine`'s doc comment) --
                                // spawn unconditionally so that fail-closed
                                // rejection still reaches the requester.
                                None => {
                                    let this = self.clone();
                                    let permits = BlockExaminationPermits { _device_wide: None };
                                    tokio::spawn(async move {
                                        if let Err(e) =
                                            this.handle_block_request(req, permits).await
                                        {
                                            tracing::warn!(error = %e, "error handling block request");
                                        }
                                    });
                                }
                            }
                        }
                        other => {
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
                            pending.push_back((other, wire_len));
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
        // Same reasoning again -- nothing left to refresh hints towards.
        credit_hint_refresh_handle.abort();
        Ok(())
    }

    /// Encodes `frame` through this session's `codec` and sends the
    /// resulting bytes over `channel`. The sole way to send an outbound
    /// message (Phase 7C.5 commit 4) -- every send call site in this file
    /// now builds an `OutboundFrame`, not `proto::SyncMessage` directly.
    async fn send_frame(
        &self,
        frame: yadorilink_sync_wire::OutboundFrame,
    ) -> Result<(), PeerSessionError> {
        // Never expected in practice -- every OutboundFrame variant maps to
        // a real proto message (see ProtobufPeerWireCodec::encode's own
        // doc comment) -- but WireError isn't a PeerSessionError variant (peer_wire
        // is a lower-level, protobuf-free-boundary module that must not
        // know about this crate's own top-level error type), so an encode
        // failure still needs an explicit conversion.
        let bytes =
            self.codec.encode(frame).map_err(|e| PeerSessionError::InvalidInput(e.to_string()))?;
        self.channel.send(bytes).await?;
        Ok(())
    }

    /// Non-blocking, non-spawning counterpart to [`Self::send_frame`] —
    /// see `PeerChannel::try_send`'s own doc for why a hot admission-
    /// control path must use this, not a spawned task around the blocking
    /// `send_frame`. `bool`, not `Result`: a dropped best-effort reply on
    /// a full or dead outbound queue is an expected, silent outcome here,
    /// not a caller error to propagate. A genuine encode failure (`frame`
    /// cannot be represented on the wire -- never expected in practice,
    /// since every `OutboundFrame` variant maps to a real proto message)
    /// is treated the same as a full queue: dropped, not propagated,
    /// since this primitive's callers already treat `false` as
    /// best-effort.
    fn try_send_frame(&self, frame: yadorilink_sync_wire::OutboundFrame) -> bool {
        match self.codec.encode(frame) {
            Ok(bytes) => self.channel.try_send(bytes),
            Err(_) => false,
        }
    }

    /// Pairs `record` with its own symlink/exec-bit/authoring metadata for
    /// the local materialization-repair path (`reconcile_local_
    /// materialization_audit` / `rematerialize_local_records`): `record`
    /// alone carries no `record_kind`/`symlink_target`/
    /// `symlink_out_of_root`/`exec_bit`/authoring fields, so this issues a
    /// direct `SyncState` lookup for `record.path`/`group_id`, the same
    /// source `materialize_symlink_at`/`try_apply_metadata_only_update`
    /// already consult on the receiving end. This is purely an in-process
    /// pairing (never serialized) — four extra point-queries per record
    /// (matching the cost `control_socket.rs`'s `list_link_statuses`
    /// already documents accepting for its own per-file `SyncState`
    /// lookups) — acceptable for this audit path, which runs once per
    /// repair pass, not in a tight per-block loop.
    pub fn file_info_for_record(
        &self,
        group_id: &str,
        record: FileRecord,
    ) -> Result<(FileRecord, IncomingWireMeta), PeerSessionError> {
        let record_kind = self.state.get_record_kind(group_id, &record.path)?.unwrap_or_default();
        let symlink_target = self.state.get_symlink_target(group_id, &record.path)?;
        let symlink_out_of_root = self.state.get_symlink_out_of_root(group_id, &record.path)?;
        let exec_bit = self.state.get_exec_bit(group_id, &record.path)?;
        // This device's own
        // record of who actually produced this path's current content —
        // see `IncomingWireMeta`'s doc comment for how the receiving side
        // uses this.
        let origin_device_id = self.state.get_origin_device_id(group_id, &record.path)?;
        let authoring_change_hash =
            self.state.get_authoring_change_hash(group_id, &record.path)?.ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "current row {group_id}/{} has no authoring change identity",
                    record.path
                ))
            })?;
        let meta = IncomingWireMeta {
            record_kind,
            symlink_target,
            symlink_out_of_root,
            exec_bit,
            origin_device_id,
            authoring_change_hash: Some(authoring_change_hash),
        };
        Ok((record, meta))
    }

    /// Returns true only when retained, group-matching DAG history proves
    /// that `incoming` is already represented by `local`. Any missing or
    /// unverifiable identity forces the locked path instead of falling back
    /// to the passive version-vector field.
    fn authoring_proves_redundant(
        &self,
        group_id: &str,
        local: &FileRecord,
        incoming: &FileRecord,
        meta: &IncomingWireMeta,
    ) -> Result<bool, PeerSessionError> {
        let Some(incoming_hash) = meta.authoring_change_hash.as_ref() else {
            return Ok(false);
        };
        match self.state.current_authoring_relation(group_id, &local.path, incoming_hash)? {
            Some(ChangeOrdering::Equal) => {
                // `same_record_content` only compares `FileRecord`'s own
                // fields (deleted/size/mtime/blocks) -- an independent
                // review's finding: under the identical authoring change,
                // this device's own `record_kind`/`symlink_target`/
                // `exec_bit` can still have diverged from what that
                // change actually specifies (a regular file that got
                // reclassified as a symlink or vice versa, a different
                // symlink target, a lost exec bit, or an interrupted
                // materialization that left the index ahead of disk for
                // one of these fields specifically). Content equality
                // alone must not short-circuit reconciliation for a path
                // whose non-content metadata still needs repairing.
                let local_kind =
                    self.state.get_record_kind(group_id, &local.path)?.unwrap_or_default();
                let local_symlink_target = self.state.get_symlink_target(group_id, &local.path)?;
                let local_exec_bit = self.state.get_exec_bit(group_id, &local.path)?;
                Ok(same_record_content(local, incoming)
                    && local_kind == meta.record_kind
                    && local_symlink_target == meta.symlink_target
                    && local_exec_bit == meta.exec_bit)
            }
            Some(ChangeOrdering::After) => Ok(true),
            Some(ChangeOrdering::Before | ChangeOrdering::Concurrent) | None => Ok(false),
        }
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
    fn change_authenticator(&self) -> Arc<dyn ChangeAuthenticator> {
        self.change_authenticator.clone()
    }

    /// This session's real signing capability, or `None` if it was never
    /// wired (every pre-authoring test/call site, and a production session
    /// for a device with no signing key yet — see the `change_emitter`
    /// field's own doc comment). A future caller authoring a captured
    /// change during materialize MUST treat `None` as "retain, do not
    /// author" — never substitute a different key, and never proceed as
    /// though the write happened.
    ///
    /// Not yet called from non-test code: `materialize` does not route
    /// through `captured_authoring` yet (a separate, explicitly deferred
    /// task), so this accessor currently has no production reader. It is
    /// exercised by `change_emitter_defaults_to_none_and_set_change_emitter_
    /// installs_one` below.
    #[allow(dead_code)]
    pub fn change_emitter(
        &self,
    ) -> Option<Arc<yadorilink_replica_domain::admission::ChangeEmitter>> {
        self.change_emitter.clone()
    }

    fn handoff_lease_responder(&self) -> Arc<dyn HandoffLeaseResponder> {
        self.handoff_lease_responder.clone()
    }

    fn rebootstrap_handler(&self) -> Arc<dyn RebootstrapHandler> {
        self.rebootstrap_handler.clone()
    }

    fn block_write_activity_provider(&self) -> Arc<dyn BlockWriteActivityProvider> {
        self.block_write_activity_provider.clone()
    }

    fn handoff_ticket_responder(&self) -> Arc<dyn HandoffTicketResponder> {
        self.handoff_ticket_responder.clone()
    }

    /// Records this peer's advertised `supports_change_dag` from its
    /// handshake `ClusterConfig` — mirrors `record_peer_compression_
    /// support`'s pattern. An old peer, or one that doesn't set the field,
    /// leaves this `false` for the session's whole lifetime.
    pub fn record_peer_change_dag_support(&self, supported: bool) {
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
    async fn send_heads_announce(&self, group_id: &str) -> Result<(), PeerSessionError> {
        let heads = self.state.dag_group_heads(group_id)?;
        // This device's own acknowledged frontier head, so the receiver can
        // advance its record of what this device holds (compaction
        // bookkeeping). Empty when none is recorded yet.
        let frontier_hint =
            match self.state.dag_get_device_frontier(group_id, &self.local_device_id)? {
                Some(h) => change_hash_to_wire(&h),
                None => Vec::new(),
            };
        self.send_frame(yadorilink_sync_wire::OutboundFrame::HeadsAnnounce(
            yadorilink_sync_wire::HeadsAnnounceOutboundFrame {
                folder_group_id: group_id.to_string(),
                heads: heads.iter().map(change_hash_to_wire).collect(),
                frontier_hint,
            },
        ))
        .await
    }

    /// Called by the local-change pipeline after a committed local edit
    /// (the change-history analogue of the daemon's `send_index_update`
    /// fan-out): re-announces heads so the peer learns about the new change
    /// immediately rather than waiting for the next periodic audit. Only
    /// announces to a peer this session has negotiated the DAG with; a
    /// legacy peer is still served by the daemon's ordinary
    /// `send_index_update`.
    pub async fn announce_local_commit(&self, group_id: &str) -> Result<(), PeerSessionError> {
        if !self.change_dag_negotiated() || !self.shares_group(group_id) {
            return Ok(());
        }
        // The commit advanced this device's own heads — record its frontier
        // before announcing so the hint it sends is current.
        if let Err(e) = self.replica_engine.record_local_frontier(
            &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string()),
            &yadorilink_replica_domain::ids::DeviceId(self.local_device_id.clone()),
        ) {
            tracing::warn!(group_id, error = %e, "failed to record local frontier before announce");
        }
        // A locally-authored commit advanced this device's own frontier the
        // same way an admitted incoming batch does -- see the identical
        // call in the incoming-batch path for why retirement needs to know.
        self.state.notify_retirement_wake(group_id);
        self.send_heads_announce(group_id).await
    }

    /// A peer announced its heads for `group_id`. Diff them against the
    /// local store and request the ancestry closure this device is missing.
    /// Authorization is checked exactly like every other inbound
    /// group-scoped message (`shares_group`) — a heads announce for a group
    /// this session isn't currently authorized for is dropped.
    pub async fn handle_heads_announce(
        &self,
        announce: yadorilink_sync_wire::HeadsAnnounceFrame,
    ) -> Result<(), PeerSessionError> {
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
        // group, and the ancestor frontier still missing behind them (a
        // head that is buffered but stuck behind a never-arrived ancestor
        // would otherwise never be re-requested again -- see
        // `PeerReplicaEngine::record_frontier_and_find_missing`'s own doc
        // comment) is pure DAG-state work true regardless of which peer
        // announced -- that part lives on `PeerReplicaEngine`.
        let evaluation = self.replica_engine.record_frontier_and_find_missing(
            &yadorilink_replica_domain::ids::FolderGroupId(group_id.clone()),
            &yadorilink_replica_domain::ids::DeviceId(self.peer_device_id.clone()),
            &announced,
        )?;
        if let Some(warning) = evaluation.record_warning {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                error = %warning.message,
                "failed to record peer frontier"
            );
        }
        let missing = evaluation.missing;
        if missing.is_empty() {
            // Already-known heads: nothing to fetch in this direction
            // (spec's "already-known changes are not re-fetched").
            return Ok(());
        }
        self.request_changes(&group_id, &missing).await
    }

    /// Standalone entry point for the retirement step alone -- see
    /// `retire_unjustified_ephemeral_conflict_copies`'s own doc comment for
    /// what it does and why. `engine_wrapper.rs`'s event-driven retirement
    /// loop calls this directly instead of the full `reconcile_local_
    /// materialization_audit` below, which also re-drives unapplied-change
    /// reprojection and materialization-repair candidates -- heavier work
    /// a frontier-changed/job-completed retirement trigger has no bearing
    /// on. Single-flights per group through its OWN `RetirementAuditGuard`
    /// key -- a SEPARATE key space from `reconcile_local_materialization_
    /// audit`/`reconcile_paths_directly`'s `MaterializationAuditGuard`, so
    /// a full audit already in flight for a group no longer makes THIS
    /// call report `RetirementAttempt::Busy`; only two retirement passes
    /// for the same group ever contend with each other. See
    /// `RetirementAuditGuard`'s own doc comment for why that coarser
    /// group-wide sharing was never actually load-bearing for correctness,
    /// and `RetirementAttempt`'s own doc comment for what each variant
    /// means for a generation-tracked caller.
    ///
    /// Whole-pass frontier freshness: `frontier_before` is this device's
    /// own admitted DAG heads for `group_id`, read right after the
    /// `RetirementAuditGuard` is acquired (before any copy is examined);
    /// `frontier_after` is the same read again right after the retirement
    /// pass returns (after every mutation it made is durable). If they
    /// differ, some OTHER admission (a peer's change arriving, or a local
    /// edit) landed while this pass was evaluating justification against
    /// whatever frontier was current when it started -- every individual
    /// decision inside the pass was locally consistent with SOME real
    /// frontier, but not provably the one current when the pass returns,
    /// so the whole pass reports `RetirementAttempt::FrontierChanged`
    /// instead of its own inner outcome, even if that inner outcome was
    /// `Settled`. This deliberately does not attempt a per-copy freshness
    /// recheck immediately before each delete (Commit 5's own scope is the
    /// whole-pass guard only) -- see `retire_unjustified_ephemeral_
    /// conflict_copies`'s own doc comment for why a copy this pass
    /// mutated is never left in a worse state than before, only
    /// potentially stale, and a caller that does not complete the
    /// generation on `FrontierChanged` gets exactly the re-evaluation
    /// against the CURRENT frontier that closes the gap.
    pub async fn retire_conflict_copies_only(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(RetirementAttempt::Settled { retired: 0 });
        }
        let Some(_guard) = RetirementAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(RetirementAttempt::Busy);
        };
        let frontier_before = self.state.dag_group_heads(group_id)?;
        let audit_attempt_id = next_audit_attempt_id();
        let outcome =
            self.retire_unjustified_ephemeral_conflict_copies(group_id, audit_attempt_id).await?;
        let frontier_after = self.state.dag_group_heads(group_id)?;
        if frontier_changed_during_pass(&frontier_before, &frontier_after) {
            return Ok(RetirementAttempt::FrontierChanged);
        }
        Ok(outcome)
    }

    /// Periodic DAG resync's local repair backstop. A heads announce keeps
    /// network catch-up proportional to divergence, but it carries no file
    /// metadata when both sides already know the same heads. Re-run the
    /// ordinary reconcile path only for locally tracked repair candidates so
    /// eager live records demoted to placeholders/hydrating still rehydrate
    /// without making every peer session scan and re-query the whole group.
    /// Returns `Ok(true)` if this call actually ran the audit (whether or
    /// not it found anything to do), `Ok(false)` if it was skipped because
    /// another audit for the same group is already in flight
    /// (`MaterializationAuditGuard` contention). Callers that use a skip as
    /// a signal for their own bookkeeping (the Convergence Engine's
    /// `run_once`, see `engine.rs`) need this distinction: a caller that
    /// cannot tell a skip from "ran and made no progress" would otherwise
    /// treat a contended tick as a failed materialization attempt and apply
    /// backoff for it, needlessly delaying a job that never actually got a
    /// chance to run this tick.
    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            "materialization audit attempt starting"
        );
        // This audit re-drives materialization, so it needs the same
        // fail-closed link gate the incoming-batch path uses: for an unlinked
        // group there is no folder to repair towards, and re-projecting into
        // one would be exactly the write the unlink was meant to stop.
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(true);
        }
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(false);
        };

        // Restart/backstop half of the projection-durability guarantee: re-drive
        // any change still marked unapplied (a crash between admission and
        // projection, or a projection that failed on a transient disk/block
        // fault) so it makes forward progress without waiting to be re-delivered.
        if let Err(e) = self.reproject_unapplied_changes(group_id, audit_attempt_id).await {
            tracing::warn!(group_id, error = %e, "failed to re-project unapplied changes during audit");
        }

        if let Err(e) =
            self.retire_unjustified_ephemeral_conflict_copies(group_id, audit_attempt_id).await
        {
            tracing::warn!(
                group_id,
                error = %e,
                "failed to retire unjustified ephemeral conflict copies during audit"
            );
        }

        let paths = self.state.list_materialization_repair_candidates(group_id)?;
        if paths.is_empty() {
            return Ok(true);
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
            return Ok(true);
        }
        self.rematerialize_local_records(group_id, file_infos).await?;
        Ok(true)
    }

    /// Re-resolves `paths` directly against this device's CURRENT DAG heads
    /// and returns a positive `ProjectionAttempt`, bypassing
    /// `reproject_unapplied_changes`'s dependency on `dag_list_unapplied_
    /// changes` entirely. This is the Convergence Engine's own per-job
    /// completion oracle (`engine.rs`'s `process_group`) — a confirmed,
    /// reproduced bug this method exists to close (see
    /// `fix/conflict-copy-convergence-obligation-20260723`): the engine
    /// used to ask "is `path` still touched by an unapplied DAG change?"
    /// (`unapplied_change_paths`), but a change retires from that set the
    /// moment its OWN projection succeeds once — independent of whether a
    /// *later* admission changed the correct resolution, and independent of
    /// whether this device's local resolution was ever actually
    /// re-verified against disk. A claimed job whose path's underlying
    /// change had already retired was therefore never re-examined by
    /// ANYTHING again once claimed, regardless of the job table's own
    /// state. Calling `reconcile_group_paths` directly for exactly the
    /// paths the engine cares about closes that gap unconditionally: it
    /// always re-resolves against current heads and re-verifies disk,
    /// with no dependency on any change's `applied` flag.
    ///
    /// Returns `Ok(None)` if skipped due to `MaterializationAuditGuard`
    /// contention (another audit for this group is already in flight) or
    /// an unlinked group — mirroring `reconcile_local_materialization_
    /// audit`'s skip semantics so the engine can tell "learned nothing
    /// reliable this tick" from "ran, and here is what it found" (see that
    /// function's own doc comment for why the distinction matters).
    pub async fn reconcile_paths_directly(
        &self,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(None);
        }
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(None);
        };
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            paths = ?paths,
            "direct path reconciliation attempt starting"
        );
        let attempt = self.reconcile_group_paths(group_id, paths, audit_attempt_id).await?;
        Ok(Some(attempt))
    }

    /// Removes locally-materialized conflict copies that are pure artifacts
    /// of a *transient* frontier: (a) no admitted change carries the copy
    /// path (it exists only because this device's projection fixpoint
    /// happened to run at a moment when its losing head was live), and (b)
    /// the CURRENT frontier's resolution of the base path no longer derives
    /// it (the loser has since been superseded — typically by its own
    /// author's next edit, which closes the conflict window without any
    /// cross-branch merge and therefore without any carrier obligation).
    ///
    /// This closes a confirmed, reproduced convergence divergence (seed
    /// `1254137095109609298` under contention, and ~1-in-3 locally with the
    /// repair sweep active from t=0): devices reconcile at whatever
    /// intermediate frontiers their arrival order produces, so a device
    /// that passed through the transient concurrent moment materializes and
    /// indexes the copy while a device that first reconciled after the
    /// window closed never derives it — four identical DAGs, identical
    /// resolutions, permanently different file sets, and nothing on either
    /// side ever changes its mind. Retiring the unjustified copy makes
    /// every device converge on the durable-plus-currently-justified copy
    /// set: a copy for a loser that is STILL live stays (condition (b))
    /// until the retroactive repair loop makes it durable, and a copy any
    /// change carries stays permanently (condition (a)).
    ///
    /// Safety: a user file that merely mimics the copy naming is protected
    /// by (a) — its own creation/edit emits a change carrying the path
    /// (the same argument that lets `backfill_missing_history` skip
    /// copy-shaped paths). Before deleting, any same-path local edit still
    /// sitting in the debounce accumulator is flushed and history re-read
    /// (the flushed change then protects it), a path still in the dirty
    /// journal is skipped outright (its pending change is not yet
    /// re-driven), and the whole check-then-delete runs under the path
    /// lock, mirroring `reconcile_group_paths`' Absent-branch discipline.
    ///
    /// Returns `RetirementAttempt::Settled` only if every copy-shaped file
    /// this pass examined was either justified or successfully retired.
    /// One copy's tombstone `materialize` returning `MaterializeResult::
    /// RetryRequired` (transient block/disk condition) makes the WHOLE
    /// pass `RetirementAttempt::RetryRequired`, even if every other copy
    /// settled cleanly: the caller uses this to decide whether it may
    /// consider the frontier generation it targeted fully verified, and a
    /// pass that skipped even one copy's re-evaluation has not verified
    /// it. The operation is idempotent regardless -- a copy already
    /// retired by an earlier pass this same call just does not appear in
    /// `copy_shaped` on the next one.
    async fn retire_unjustified_ephemeral_conflict_copies(
        &self,
        group_id: &str,
        audit_attempt_id: u64,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(RetirementAttempt::Settled { retired: 0 });
        };
        let copy_shaped: Vec<FileRecord> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .filter(|r| {
                !r.deleted && yadorilink_replica_domain::conflict::is_conflict_copy_path(&r.path)
            })
            .collect();
        if copy_shaped.is_empty() {
            return Ok(RetirementAttempt::Settled { retired: 0 });
        }
        let mut retired = 0usize;
        let mut retry_required = false;
        let history = self.state.dag_group_history_paths(group_id)?;
        for record in copy_shaped {
            if history.contains(&record.path) {
                continue;
            }
            if self.state.is_path_dirty(group_id, &record.path)? {
                continue;
            }
            let base = yadorilink_replica_domain::conflict::conflict_copy_source_path(&record.path);
            let inputs = self.combined_heads(group_id, &base, None)?;
            let justified = match resolve_path_heads(&base, &inputs) {
                PathResolution::Present { conflict_copies, .. } => {
                    conflict_copies.iter().any(|cc| cc.path == record.path)
                }
                PathResolution::Absent => false,
            };
            if justified {
                continue;
            }
            self.flush_pending_local_change_before_reconcile(group_id, &record.path).await;
            if self.state.dag_group_history_paths(group_id)?.contains(&record.path) {
                // The flush just made a real local edit of this path durable
                // -- it is user content now, not an ephemeral artifact.
                continue;
            }
            let path_lock = self.state.path_lock(group_id, &record.path);
            let _guard = path_lock.lock().await;
            let still_live =
                self.state.get_file(group_id, &record.path)?.map(|r| !r.deleted).unwrap_or(false);
            if !still_live {
                continue;
            }
            let tombstone = FileRecord {
                path: record.path.clone(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            };
            match self.materialize(group_id, &tombstone, policy, &self.peer_device_id, None).await {
                Ok(MaterializeResult::Settled) => {
                    retired += 1;
                    tracing::info!(
                        group_id,
                        path = %record.path,
                        audit_attempt_id,
                        "retired an ephemeral conflict copy no longer justified by the current frontier"
                    )
                }
                // `RetryRequired` is not a retirement -- the copy is still
                // live, so the next audit re-evaluates it -- but it also
                // means THIS pass never verified this copy's justification
                // against the frontier it targeted, so the whole pass must
                // report `RetryRequired`, not `Settled`: a caller that
                // completed its target generation on a pass that silently
                // skipped a copy's re-evaluation would never re-examine it
                // again unless some unrelated future event happened to
                // re-mark the group dirty.
                Ok(MaterializeResult::RetryRequired) => {
                    retry_required = true;
                    tracing::debug!(
                        group_id,
                        path = %record.path,
                        audit_attempt_id,
                        "deferred retiring an ephemeral conflict copy; will re-evaluate next audit"
                    )
                }
                // Same reasoning as `RetryRequired` above: a transient
                // per-copy failure must not let the pass as a whole report
                // `Settled` for a generation whose frontier this copy was
                // never actually re-verified against.
                Err(e) => {
                    retry_required = true;
                    tracing::warn!(
                        group_id,
                        path = %record.path,
                        error = %e,
                        "failed to retire an unjustified ephemeral conflict copy; will retry next audit"
                    )
                }
            }
        }
        Ok(if retry_required {
            RetirementAttempt::RetryRequired
        } else {
            RetirementAttempt::Settled { retired }
        })
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
    pub async fn reproject_unapplied_changes(
        &self,
        group_id: &str,
        audit_attempt_id: u64,
    ) -> Result<ProjectionAttempt, PeerSessionError> {
        let unapplied = self.state.dag_list_unapplied_changes(group_id)?;
        if unapplied.is_empty() {
            return Ok(ProjectionAttempt::default());
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
        let attempt = self.reconcile_group_paths(group_id, all_paths, audit_attempt_id).await?;
        for (hash, change_paths) in &per_change {
            let succeeded = change_projection_succeeded(change_paths, &attempt);
            tracing::debug!(
                local_device_id = %self.local_device_id,
                group_id,
                audit_attempt_id,
                change_hash = %hex::encode(hash.0),
                change_paths = ?change_paths,
                succeeded,
                "unapplied-change projection outcome this attempt"
            );
            if succeeded {
                if let Err(e) = self.state.dag_mark_applied(hash) {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "failed to mark a re-projected change applied"
                    );
                }
            }
        }
        Ok(attempt)
    }

    /// Serves the changes a peer asked for out of the local store. This is
    /// the store-and-forward serving path: a change is served purely
    /// because it is present in the store, with **no special casing on
    /// which device originated it** — so a change A produced is served to C
    /// by B exactly as if B had produced it, which is what lets C converge
    /// without ever connecting to A. The stored bytes are relayed verbatim,
    /// carrying the original signature, so the receiver re-verifies them
    /// exactly as if they came straight from the origin.
    async fn handle_change_request(
        &self,
        req: yadorilink_sync_wire::ChangeRequestFrame,
    ) -> Result<(), PeerSessionError> {
        let group_id = req.folder_group_id;
        if !self.shares_group(&group_id) {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring change request for unauthorized/unshared folder group"
            );
            return Ok(());
        }
        // Decode every requested hash off the wire (session-side: cheap,
        // wire-format-specific, and `change_hash_from_wire` is also used by
        // `handle_heads_announce` elsewhere in this file). Expanding each
        // decoded hash into its full retained ancestor closure, truncating
        // to the batch cap, and gathering the encoded change bytes plus
        // their referenced file versions is pure DAG-state work true
        // regardless of which peer asked -- that part lives on
        // `PeerReplicaEngine` (see its own doc comment).
        let hashes: Vec<ChangeHash> =
            req.want.iter().filter_map(|want| change_hash_from_wire(want)).collect();
        let (batch, versions) = self.replica_engine.changes_for_request(
            &yadorilink_replica_domain::ids::FolderGroupId(group_id.clone()),
            &hashes,
            MAX_CHANGES_PER_BATCH,
        )?;
        if !batch.is_empty() {
            self.send_change_batch(&group_id, batch, versions).await?;
        }
        Ok(())
    }

    async fn send_change_batch(
        &self,
        group_id: &str,
        changes: Vec<Vec<u8>>,
        file_versions: Vec<Vec<u8>>,
    ) -> Result<(), PeerSessionError> {
        // Changes are sent uncompressed for now; the wire format
        // reserves `compressed_changes` for a later pass that reuses
        // the existing zstd negotiation, exactly as the index path
        // does. An old-format-agnostic receiver reads `changes`
        // directly whenever `compression == NONE`.
        self.send_frame(yadorilink_sync_wire::OutboundFrame::ChangeBatch(
            yadorilink_sync_wire::ChangeBatchOutboundFrame {
                folder_group_id: group_id.to_string(),
                changes,
                compressed_changes: Vec::new(),
                file_versions,
            },
        ))
        .await
    }

    async fn request_changes(
        &self,
        group_id: &str,
        want: &[ChangeHash],
    ) -> Result<(), PeerSessionError> {
        if want.is_empty() {
            return Ok(());
        }
        // Chunk the want-list so a single request message is bounded the
        // same way a served batch is.
        for chunk in want.chunks(MAX_CHANGES_PER_BATCH) {
            self.send_frame(yadorilink_sync_wire::OutboundFrame::ChangeRequest(
                yadorilink_sync_wire::ChangeRequestFrame {
                    folder_group_id: group_id.to_string(),
                    want: chunk.iter().map(change_hash_to_wire).collect(),
                },
            ))
            .await?;
        }
        Ok(())
    }

    /// Decodes `file_versions` into an untrusted, in-memory staging map,
    /// keyed by version hash. Nothing is persisted until a signed,
    /// authorized change in the same batch actually references the hash --
    /// this prevents an unauthenticated envelope from poisoning another
    /// group's version namespace or disclosing its blocks.
    fn decode_batch_file_versions(
        &self,
        encoded_versions: &[Vec<u8>],
    ) -> std::collections::BTreeMap<VersionHash, FileVersion> {
        let mut staged_versions = std::collections::BTreeMap::new();
        for encoded in encoded_versions {
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
        staged_versions
    }

    /// Decodes one wire-encoded change and authenticates it: hash/signature
    /// against the author's pinned key, then writer authorization at the
    /// pinned policy coordinate. Does NOT check causal monotonicity of that
    /// pin against DAG parents (see `check_causal_auth_monotonicity`) or
    /// version/parent availability -- those need DAG state, checked
    /// separately as their own stages. Returns `None` (already logged) for
    /// a change that fails any of these checks, or whose `group_id` does
    /// not match the batch envelope.
    ///
    /// Without a real pinned-key/authorization supplier this session
    /// cannot verify a change, and an unverified change must never enter
    /// the store: a caller with no real authenticator is constructed with
    /// a deny-by-default one (`PeerSyncSessionOneTimeDeps::denied`), whose
    /// `signing_key` always answers `None` -- this per-change guard then
    /// drops every change in the batch individually rather than holding
    /// the whole batch up front, but the outcome is the same: nothing from
    /// an unverifiable batch is ever admitted.
    fn authenticate_incoming_change(&self, group_id: &str, encoded: &[u8]) -> Option<Change> {
        let auth = self.change_authenticator();
        let change = match Change::from_wire_bytes(encoded) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    peer = %self.peer_device_id,
                    error = %e,
                    "ignoring undecodable change in batch"
                );
                return None;
            }
        };
        // A change naming a different group than the batch envelope is
        // dropped — authorization is per group, so a mismatched envelope
        // must never let a change ride into a group under another group's
        // authorization check.
        if change.group_id.as_str() != group_id {
            tracing::warn!(
                group_id,
                peer = %self.peer_device_id,
                "ignoring change whose group_id does not match the batch envelope"
            );
            return None;
        }
        // Verify hash + signature (against the author's pinned key) + that
        // the author is authorized to write the group, BEFORE the change
        // is ever admitted to the store. An invalid change never enters
        // the store and so can never be forwarded onward — this is what
        // makes store-and-forward through an untrusted intermediary safe.
        let claimed_hash = change.change_hash();
        let Some(key_bytes) = auth.signing_key(change.device_id.as_str()) else {
            tracing::warn!(
                group_id,
                author = %change.device_id.as_str(),
                peer = %self.peer_device_id,
                "dropping change from a device with no pinned signing key"
            );
            return None;
        };
        let public_key =
            match yadorilink_replica_domain::change::verifying_key_from_bytes(&key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(error = %e, "pinned signing key is malformed; dropping change");
                    return None;
                }
            };
        if let Err(e) = yadorilink_replica_domain::change::verify_change(
            &change,
            &claimed_hash,
            &public_key,
            |_, _| true,
        ) {
            tracing::warn!(
                group_id,
                author = %change.device_id.as_str(),
                peer = %self.peer_device_id,
                error = %e,
                "rejected an invalid change (hash/signature/authorization) — not stored"
            );
            return None;
        }
        let signing_key_fingerprint: [u8; 32] = Sha256::digest(key_bytes).into();
        if !auth.accepts_change_auth(
            change.device_id.as_str(),
            change.group_id.as_str(),
            signing_key_fingerprint,
            yadorilink_replica_domain::change::ChangeAuth {
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
            return None;
        }
        Some(change)
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
    ///
    /// Broken into named per-stage helpers above (Phase 7B): this body is
    /// now the control-flow skeleton (batch-level gates, the per-change
    /// loop's ordering, and batch settlement), with each stage's actual
    /// work — decode, authenticate, causal-monotonicity check, version
    /// availability, DAG admission, materialization enqueue — living in
    /// its own named method. Execution order and every log message are
    /// unchanged from before this split.
    pub async fn handle_change_batch(
        &self,
        batch: yadorilink_sync_wire::ChangeBatchFrame,
    ) -> Result<(), PeerSessionError> {
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

        let staged_versions = self.decode_batch_file_versions(&batch.file_versions);

        let mut missing_parents: Vec<ChangeHash> = Vec::new();
        let mut affected_paths: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        // Each newly-applied change paired with the concrete paths its own ops
        // touch. A change is only marked `applied` once *every* one of those
        // paths (and any conflict copy derived from them) has actually
        // projected — this fn no longer gates that itself (materialization is
        // deferred to the Convergence Engine, below), but the same rule still
        // holds wherever `applied` is flipped (`reconcile_local_materialization_audit`
        // / `reproject_unapplied_changes`): a projection that fails on
        // disk-full / a missing block / an I/O error leaves the change
        // unapplied so the reprojection backstop keeps retrying it.
        let mut admitted: Vec<yadorilink_replica_engine::outcomes::AdmittedChange> = Vec::new();
        // Already-known changes redelivered by anti-entropy that are worth
        // re-planning materialization for even though they add nothing to
        // `admitted` itself -- see the `dag_has_change` fast-path's own doc
        // comment below for why. Kept separate from `admitted` because
        // `admitted.is_empty()` also gates frontier recording and the
        // retirement wake, which must stay scoped to genuinely new
        // admissions from this receipt.
        let mut redelivered_known: Vec<yadorilink_replica_engine::outcomes::AdmittedChange> =
            Vec::new();
        for encoded in &batch.changes {
            let Some(change) = self.authenticate_incoming_change(&group_id, encoded) else {
                continue;
            };
            let claimed_hash = change.change_hash();

            match self.replica_engine.check_causal_auth_monotonicity(&change)? {
                CausalAuthOutcome::Exempt | CausalAuthOutcome::Accepted => {}
                CausalAuthOutcome::Hold { missing_parents: held_parents } => {
                    tracing::warn!(
                        group_id,
                        author = %change.device_id.as_str(),
                        peer = %self.peer_device_id,
                        "holding a change until all of its parents are present so its \
                         authorization pin can be checked for causal monotonicity"
                    );
                    missing_parents.extend(held_parents);
                    continue;
                }
                CausalAuthOutcome::Rejected {
                    auth_seq,
                    auth_epoch,
                    max_parent_auth_seq,
                    max_parent_auth_epoch,
                } => {
                    tracing::warn!(
                        group_id,
                        author = %change.device_id.as_str(),
                        peer = %self.peer_device_id,
                        auth_seq,
                        auth_epoch,
                        max_parent_auth_seq,
                        max_parent_auth_epoch,
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

            if let Some(version_hash) = self.replica_engine.missing_referenced_version(
                &yadorilink_replica_domain::ids::FolderGroupId(group_id.clone()),
                &change,
                &staged_versions,
            )? {
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

            // A change already durably admitted (whether or not its own
            // projection has succeeded yet -- `dag_list_unapplied_changes`'s
            // durable retry backstop owns that separately) has nothing left
            // for this receipt to do as far as DAG admission goes:
            // re-running it through the local-flush barrier below cannot
            // change DAG admission and only spends that barrier's bounded
            // budget on gossip this device has already seen. Anti-entropy
            // resends the same change on every heads announce until this
            // device's frontier catches up, so under a duplicate-delivery
            // storm this fast-path is what keeps the targeted-flush channel
            // from staying saturated by re-flushing the same paths on every
            // redundant redelivery.
            //
            // It must NOT also skip materialization re-triggering, though.
            // A path's materialization job can reach `Completed`/
            // `Superseded` against whatever was the live winner at THAT
            // moment, then later be overtaken by a still-newer head this
            // device already admitted -- but `materialization_claim_
            // runnable_jobs` and the periodic repair sweep both structurally
            // skip a job/file already in a terminal state, so nothing else
            // ever re-examines it. Confirmed via `row14_strict_acceptance`
            // (`fix/conflict-copy-convergence-obligation-20260723`): CI's
            // slower daemon-e2e runner reliably reproduced two devices stuck
            // forever with stale-but-`Completed` `shared.bin` jobs, despite
            // their own DAG already holding the true winner and every
            // device otherwise agreeing on the DAG. Redelivery of an
            // already-known change is exactly the recurring signal that
            // should re-arm a stale terminal job -- skip the (expensive)
            // per-path local-flush barrier below, but still let this
            // change's touched paths go through the same enqueue call as a
            // freshly-admitted one. `materialization_enqueue_pending`'s own
            // `ON CONFLICT` clause is a cheap, idempotent no-op when nothing
            // has actually changed, so this does not reopen the flush-
            // channel-saturation hazard the skip above still guards
            // against.
            if self.state.dag_has_change(&claimed_hash)? {
                let mut touched_paths = std::collections::BTreeSet::new();
                for op in &change.ops {
                    collect_op_paths(op, &mut touched_paths);
                }
                if !touched_paths.is_empty() {
                    affected_paths.extend(touched_paths.iter().cloned());
                    redelivered_known.push(yadorilink_replica_engine::outcomes::AdmittedChange {
                        hash: claimed_hash,
                        lamport: change.lamport,
                        touched_paths,
                    });
                }
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
            let mut flush_retry_required = false;
            for path in incoming_paths {
                if self.flush_pending_local_change_before_reconcile(&group_id, &path).await
                    == PendingLocalFlushOutcome::RetryRequired
                {
                    flush_retry_required = true;
                }
                if self.flush_case_fold_sibling_before_reconcile(&group_id, &path).await
                    == PendingLocalFlushOutcome::RetryRequired
                {
                    flush_retry_required = true;
                }
            }
            if flush_retry_required {
                // The local-flush round trip above could not confirm this
                // path's local state within its bound (the debounce
                // accumulator's targeted-flush channel is backed up).
                // Admitting the peer change now, without knowing whether a
                // local edit for the same path is still unflushed, risks
                // silently clobbering that local edit instead of producing
                // a conflict copy for it. Defer: skip admission for this
                // change and let anti-entropy re-deliver it once the local
                // side has drained.
                tracing::warn!(
                    group_id,
                    author = %change.device_id.as_str(),
                    peer = %self.peer_device_id,
                    "deferring a change at admission -- this link's debounce accumulator did \
                     not confirm local-flush state within its bound; it will be re-requested"
                );
                continue;
            }

            match self.replica_engine.admit_authenticated_change(
                &change,
                claimed_hash,
                &referenced_versions,
            )? {
                ChangeAdmissionOutcome::Rejected { reason } => {
                    match reason {
                        ChangeAdmissionRejection::ReservedNamespaceCollision { path } => {
                            // Permanent, not transient: already durably
                            // recorded as rejected (`dag_store::
                            // rejected_changes`), so it will not be
                            // re-requested from any peer on a future heads
                            // announce.
                            tracing::error!(
                                group_id,
                                author = %change.device_id.as_str(),
                                peer = %self.peer_device_id,
                                path,
                                "permanently rejected a change at DAG admission: reserved-namespace \
                                 collision; this path will never sync until it is renamed on disk"
                            );
                        }
                        ChangeAdmissionRejection::NonPortablePath { path } => {
                            tracing::error!(
                                group_id,
                                author = %change.device_id.as_str(),
                                peer = %self.peer_device_id,
                                path,
                                "permanently rejected a change at DAG admission: path is not portable \
                                 to every platform this group may sync to; this path will never sync \
                                 until it is renamed"
                            );
                        }
                        ChangeAdmissionRejection::StorageFailure { message } => {
                            tracing::warn!(
                                group_id,
                                author = %change.device_id.as_str(),
                                peer = %self.peer_device_id,
                                error = %message,
                                "rejected a change at DAG admission"
                            );
                        }
                    }
                    continue;
                }
                ChangeAdmissionOutcome::Orphaned { missing_parents: orphan_parents } => {
                    missing_parents.extend(orphan_parents);
                }
                ChangeAdmissionOutcome::Applied { admitted: newly_admitted } => {
                    for change in newly_admitted {
                        affected_paths.extend(change.touched_paths.iter().cloned());
                        admitted.push(change);
                    }
                }
            }
        }

        // `redelivered_known` first, `admitted` last -- `plan_batch_
        // materialization` picks whichever entry touches a given path LAST
        // by plain iteration order, not by lamport (see its own doc
        // comment), so a genuinely fresh admission from THIS receipt must
        // always be the one that wins for any path it also touches. Putting
        // `admitted` last preserves that existing invariant exactly;
        // `redelivered_known` only ever supplies a path's trigger when
        // nothing newly admitted this batch also touched it.
        let plan_input: Vec<yadorilink_replica_engine::outcomes::AdmittedChange> =
            redelivered_known.iter().cloned().chain(admitted.iter().cloned()).collect();
        let plans = yadorilink_replica_engine::materialization_plan::plan_batch_materialization(
            &plan_input,
            &affected_paths,
        );
        // Deliberately the real (non-deterministic-clock-override) wall
        // clock, matching this call site's pre-move `state_model::
        // now_unix_nanos` -- distinct from this file's own `now_unix_nanos`
        // free function above, which is `#[cfg(madsim)]`-overridable for
        // DST replay determinism (see its doc comment); this materialization-
        // enqueue timestamp was never wired to that override.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        for plan in &plans {
            crate::dst_trace(&plan.path, || {
                format!(
                    "admitted batch touching path on {}: latest change={} lamport={}",
                    self.local_device_id,
                    hex::encode(&plan.trigger_change.0[..4]),
                    plan.trigger_lamport,
                )
            });
            match self.state.materialization_enqueue_pending(
                &group_id,
                &plan.path,
                &plan.trigger_change.0,
                plan.trigger_lamport,
                now,
            ) {
                Ok(()) => {
                    tracing::debug!(
                        local_device_id = %self.local_device_id,
                        group_id,
                        job_path = %plan.path,
                        job_version_hash = %hex::encode(plan.trigger_change.0),
                        "direct-path materialization job enqueued"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        group_id,
                        path = %plan.path,
                        error = %e,
                        "failed to enqueue a materialization job for an admitted change; the \
                         periodic audit backstop will still pick this path up"
                    );
                }
            }
        }
        if !affected_paths.is_empty() {
            self.state.notify_materialization_wake();
        }

        // Applying the batch advanced this device's own heads — record its
        // frontier so its next heads announce carries a current hint and
        // compaction sees what this device now holds.
        if !admitted.is_empty() {
            if let Err(e) = self.replica_engine.record_local_frontier(
                &yadorilink_replica_domain::ids::FolderGroupId(group_id.clone()),
                &yadorilink_replica_domain::ids::DeviceId(self.local_device_id.clone()),
            ) {
                tracing::warn!(group_id, error = %e, "failed to record local frontier after apply");
            }
            // The frontier just advanced -- some previously-live conflict
            // copy may have just lost its justification (its loser was
            // just superseded) or some previously-unjustified copy may have
            // just become required again. Either way the retirement loop
            // needs to re-evaluate this group promptly rather than waiting
            // for its own periodic backstop poll.
            self.state.notify_retirement_wake(&group_id);
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
        audit_attempt_id: u64,
    ) -> Result<ProjectionAttempt, PeerSessionError> {
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
                        if !derived.contains_key(&cc.path) {
                            // Diagnostic-only: correlates a conflict-copy
                            // output back to the seed path that produced it
                            // and the losing change it carries, for the
                            // `taguchi_row_14` intermittent-stall
                            // investigation (see
                            // `fix/conflict-copy-convergence-obligation-20260723`).
                            tracing::debug!(
                                local_device_id = %self.local_device_id,
                                group_id,
                                audit_attempt_id,
                                derived_from_path = %path,
                                resolved_output_path = %cc.path,
                                conflict_loser_change_hash = %hex::encode(inputs[cc.head].change_hash),
                                conflict_loser_device_id = %inputs[cc.head].device_id,
                                "conflict-copy output discovered by resolution fixpoint"
                            );
                        }
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
            return Ok(ProjectionAttempt { settled: Default::default(), retry: paths });
        };
        // Every path this call resolves lands in exactly one of these two
        // sets by the end of the loop below — see `ProjectionAttempt`'s own
        // doc comment for why that invariant matters. A per-path write
        // failure (disk-full, missing block, I/O, materialize error) goes to
        // `retry` and the sweep continues, rather than `?`-aborting the
        // whole batch: the caller marks only changes whose paths are ALL in
        // `settled` as applied, and the rest re-project later.
        // Non-path-specific errors (a DAG/DB read failing) still propagate
        // via `?`, since they are not attributable to one path and mean
        // nothing projected reliably.
        let mut settled: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut retry: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
                settled.insert(path.clone());
                continue;
            }
            let mut inputs = self.combined_heads(group_id, path, derived.get(path))?;
            if inputs.is_empty() {
                // No live heads at all for a path this call was asked to
                // resolve — genuinely ambiguous (this device's own DAG
                // state may simply be behind), not a positive proof of
                // anything. Fail closed: `retry`, never `settled` (see
                // `ProjectionAttempt`'s own doc comment).
                retry.insert(path.clone());
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
                    // Same reasoning as the first `inputs.is_empty()` check
                    // above: ambiguous, not a positive proof — `retry`.
                    retry.insert(path.clone());
                    continue;
                }
                resolution = resolve_path_heads(path, &inputs);
            }
            crate::dst_trace(path, || {
                let heads: Vec<String> = inputs
                    .iter()
                    .map(|h| {
                        format!(
                            "{}@{}{}",
                            hex::encode(&h.change_hash[..4]),
                            h.device_id,
                            if h.content.is_some() { "" } else { ":tomb" }
                        )
                    })
                    .collect();
                let outcome = match &resolution {
                    PathResolution::Absent => "Absent".to_string(),
                    PathResolution::Present { winner, conflict_copies } => format!(
                        "Present winner={} copies={}",
                        hex::encode(&inputs[*winner].change_hash[..4]),
                        conflict_copies.len()
                    ),
                };
                format!("reconcile on {}: heads={heads:?} -> {outcome}", self.local_device_id)
            });
            match resolution {
                PathResolution::Absent => {
                    let tombstone_author = ChangeHash(
                        inputs
                            .iter()
                            .map(|head| head.change_hash)
                            .max()
                            .expect("Absent resolution has at least one head"),
                    );
                    // Every live head removed the path — materialize the deletion
                    // if the index still shows it live. A stale content change
                    // that is an ancestor of the tombstone never reaches the live
                    // set, so this can never resurrect a deleted file.
                    //
                    // Held across the still-live check AND the materialize call
                    // below, matching `materialize_dag_content_head`'s identical
                    // discipline for the Present branch (see its own comment on
                    // why). Without this, a concurrent local write to this same
                    // path -- e.g. the filename being reused by a brand-new
                    // local create shortly after this device's own earlier
                    // delete, which `local_change.rs`'s own commit path takes
                    // this same lock for -- can interleave between the check and
                    // the previously-unlocked materialize() below: the new
                    // create's content and index row land first, then this
                    // stale tombstone's materialize() removes that brand-new
                    // file and overwrites its live index row with `deleted:
                    // true` -- an index-says-deleted/disk-had-content mismatch
                    // that no later re-resolution can detect, since every
                    // device involved already believes it is consistent.
                    // Confirmed as the actual cause of a real, reproduced
                    // divergence: four devices with byte-identical DAG heads
                    // each ended up with their own un-merged local tombstone
                    // for the same repeatedly-recreated path.
                    let path_lock = self.state.path_lock(group_id, path);
                    let _guard = path_lock.lock().await;
                    let still_live =
                        self.state.get_file(group_id, path)?.map(|r| !r.deleted).unwrap_or(false);
                    if still_live {
                        let record = FileRecord {
                            path: path.clone(),
                            size: 0,
                            mtime_unix_nanos: 0,
                            blocks: Vec::new(),
                            deleted: true,
                        };
                        // A DAG tombstone is a materialization operation, not
                        // merely an index update.  Going straight to
                        // `upsert_file` leaves the old bytes on disk while the
                        // index says they are deleted; route through the same
                        // removal path as legacy peer reconciliation so an I/O
                        // failure keeps the change unapplied for retry.
                        match self
                            .materialize(
                                group_id,
                                &record,
                                policy,
                                &self.peer_device_id,
                                Some(&tombstone_author),
                            )
                            .await
                        {
                            Ok(MaterializeResult::Settled) => {
                                settled.insert(path.clone());
                            }
                            // Matches the `Present` branch's identical
                            // distinction just below: a hazard-collision
                            // tombstone that dropped without applying
                            // anything reports `RetryRequired`, and this
                            // branch must not fold that into `settled` --
                            // this was the only caller of `materialize` for
                            // a deletion that collapsed every `Ok(_)` into
                            // "done", silently discarding the distinction
                            // `MaterializeResult` exists to preserve.
                            Ok(MaterializeResult::RetryRequired) => {
                                retry.insert(path.clone());
                            }
                            Err(e) => {
                                tracing::warn!(
                                    group_id,
                                    path = %path,
                                    error = %e,
                                    "failed to project a deletion; leaving its change(s) unapplied"
                                );
                                retry.insert(path.clone());
                            }
                        }
                    } else {
                        // Already not live -- the deletion is already
                        // reflected, nothing to do this attempt.
                        if self.state.get_file(group_id, path)?.is_some() {
                            self.state.set_authoring_change_hash(
                                group_id,
                                path,
                                &tombstone_author,
                            )?;
                        }
                        settled.insert(path.clone());
                    }
                }
                PathResolution::Present { winner, .. } => {
                    match self
                        .materialize_dag_content_head(
                            group_id,
                            path,
                            &inputs[winner],
                            policy,
                            derived.get(path),
                        )
                        .await
                    {
                        Ok(MaterializeResult::Settled) => {
                            settled.insert(path.clone());
                        }
                        Ok(MaterializeResult::RetryRequired) => {
                            retry.insert(path.clone());
                        }
                        Err(e) => {
                            tracing::warn!(
                                group_id,
                                path = %path,
                                error = %e,
                                "failed to project a path; leaving its change(s) unapplied for retry"
                            );
                            retry.insert(path.clone());
                        }
                    }
                }
            }
        }
        // Every path examined above must land in exactly one of the two
        // sets — see `ProjectionAttempt`'s own doc comment. This should be
        // unreachable given the match above is exhaustive and every arm
        // inserts into one set or the other; kept as a loud, visible signal
        // (not a silent "treat as settled") in case a future edit
        // reintroduces a branch that forgets to record an outcome.
        for path in &paths {
            if !settled.contains(path) && !retry.contains(path) {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    audit_attempt_id,
                    path = %path,
                    "reconcile_group_paths examined a path but recorded neither settled nor retry \
                     for it; treating as retry, never as an accidental success"
                );
                retry.insert(path.clone());
            }
        }
        if !retry.is_empty() {
            // Diagnostic-only: splits `retry` into direct (a raw seed path)
            // vs. derived (a synthetic conflict-copy path) for the
            // `taguchi_row_14` intermittent-stall investigation — see
            // `fix/conflict-copy-convergence-obligation-20260723`.
            let retry_direct: Vec<&String> =
                retry.iter().filter(|p| seed_paths.contains(*p)).collect();
            let retry_derived: Vec<&String> =
                retry.iter().filter(|p| !seed_paths.contains(*p)).collect();
            tracing::debug!(
                local_device_id = %self.local_device_id,
                group_id,
                audit_attempt_id,
                retry_direct = ?retry_direct,
                retry_derived = ?retry_derived,
                "reconcile_group_paths finished with unresolved paths this attempt"
            );
        }
        Ok(ProjectionAttempt { settled, retry })
    }

    /// The combined live heads for one path: the changes that directly touch
    /// it (each reduced to its op effect at the path) plus an optional derived
    /// content head — the content a losing change of some other path
    /// materializes at this conflict-copy path. Cross-supersession runs across
    /// the whole set, so a direct change that descends from the derived losing
    /// head supersedes it (a delete of a conflict copy removes it), and a
    /// derived head that descends from a direct head supersedes that one.
    /// Diagnostic-only public wrapper over `combined_heads`, for
    /// out-of-band snapshot tooling (see
    /// `fix/conflict-copy-convergence-obligation-20260723`'s three-layer
    /// classification: change-closure vs. DAG-management vs. projection-
    /// trigger). Identical result regardless of which peer session it's
    /// called through — this reads purely local state (`self.state`), not
    /// anything session-specific.
    pub fn diagnostic_path_heads(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<PathHead>, PeerSessionError> {
        self.combined_heads(group_id, path, None)
    }

    fn combined_heads(
        &self,
        group_id: &str,
        path: &str,
        derived_head: Option<&PathHead>,
    ) -> Result<Vec<PathHead>, PeerSessionError> {
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
    pub async fn materialize_dag_content_head(
        &self,
        group_id: &str,
        target_path: &str,
        head: &PathHead,
        policy: MaterializationPolicy,
        derived: Option<&PathHead>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity = activity_provider.begin_block_write_activity();
        // A removing head (tombstone / move-away source) lands no content; only
        // content heads reach here, but guard defensively -- nothing to do,
        // trivially settled.
        let Some(_) = head.content.as_ref() else {
            return Ok(MaterializeResult::Settled);
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
        // CONV-7's freshness principle applied INSIDE the path lock: the
        // resolution that elected `head` ran before this lock was acquired,
        // and a newer change for this path can land in between — most
        // dangerously this device's OWN local tombstone (a user deleting or
        // renaming the file away), whose emission removes the file, writes
        // the deleted index row, and admits the change already `applied`.
        // Writing the pre-lock winner anyway resurrects content the newer
        // change just removed on this very device, and because a locally
        // authored change is never reprojected, nothing re-examines the path
        // afterwards — captured live (single-path DST trace, three-device
        // mesh chaos seed 1000005) as a deterministic terminal divergence:
        // the device that authored a rename's tombstone re-materialized the
        // pre-rename winner an instant later and kept, forever, a live file
        // every peer had deleted, under byte-identical DAG heads. Re-resolve
        // under the lock (with the caller's derived-copy context, so a
        // fixpoint-derived conflict copy re-validates against the same
        // inputs that elected it) and decline a head that is no longer the
        // current winner; `RetryRequired` keeps the caller from recording
        // the path as settled on the strength of a write that did not
        // happen, and whichever change superseded `head` drives (or already
        // drove) the path's real projection through its own admission.
        let fresh = self.combined_heads(group_id, target_path, derived)?;
        let effective_head = match resolve_path_heads(target_path, &fresh) {
            PathResolution::Present { winner, .. }
                if fresh[winner].change_hash == head.change_hash =>
            {
                head.clone()
            }
            PathResolution::Present { winner, .. } => {
                // The winner moved to a NEWER content head while this call
                // waited for the lock. Rather than declining and paying a
                // whole retry round-trip (decline → caller marks retry →
                // next audit re-resolves → re-materializes — measurable
                // churn under exactly the contention that produces these
                // races), upgrade in place: this call already holds the
                // path lock, so materializing the fresh winner here is the
                // same write the retry would eventually perform, minus the
                // window in which the path sits stale.
                crate::dst_trace(target_path, || {
                    format!(
                        "stale materialize upgraded on {}: head {} superseded by winner {}",
                        self.local_device_id,
                        hex::encode(&head.change_hash[..4]),
                        hex::encode(&fresh[winner].change_hash[..4]),
                    )
                });
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    path = %target_path,
                    stale_head = %hex::encode(&head.change_hash[..4]),
                    fresh_head = %hex::encode(&fresh[winner].change_hash[..4]),
                    "materialize upgraded under the path lock to the current winner"
                );
                fresh[winner].clone()
            }
            PathResolution::Absent => {
                crate::dst_trace(target_path, || {
                    format!(
                        "stale materialize declined on {}: head {} is now fully removed",
                        self.local_device_id,
                        hex::encode(&head.change_hash[..4]),
                    )
                });
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    path = %target_path,
                    stale_head = %hex::encode(&head.change_hash[..4]),
                    "declining a materialize whose path a newer tombstone removed before \
                     the path lock was acquired"
                );
                return Ok(MaterializeResult::RetryRequired);
            }
        };
        let Some(content) = effective_head.content.as_ref() else {
            return Ok(MaterializeResult::Settled);
        };
        let version_hash = VersionHash(content.version_hash);
        let Some(version) = self.state.dag_get_file_version(group_id, &version_hash)? else {
            // Admission gated on the version being present, so this only
            // happens if it was pruned in between — skip; a later heads
            // exchange re-drives this path once the version is re-supplied.
            // NOT settled: content was never verified/written, so a caller
            // must not treat this as done (see `MaterializeResult`'s own
            // doc comment).
            tracing::warn!(
                group_id,
                path = target_path,
                version = %version_hash.to_hex(),
                "file version for a resolved content head is missing; skipping materialize"
            );
            return Ok(MaterializeResult::RetryRequired);
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
            origin_device_id: Some(effective_head.device_id.clone()),
            authoring_change_hash: Some(ChangeHash(effective_head.change_hash)),
        };
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
            // The index alone is not proof the fast path is safe: it only
            // means this device's LAST INDEXING pass produced a record whose
            // block list happens to match the winner's. A raw filesystem
            // write to this same path (e.g. a concurrent local edit) changes
            // the actual bytes on disk immediately, but is only reflected in
            // the index once the watcher/debounce pipeline processes it —
            // which can lag behind an incoming remote materialize attempt
            // that runs in the meantime. Trusting a stale index here would
            // silently skip the real write, permanently leaving the wrong
            // bytes on disk with the index and DAG both agreeing the path is
            // "done" — nothing else would ever re-examine it. Verify actual
            // disk bytes hash-match the winner's blocks before trusting this
            // fast path; skip the check only for record kinds with no
            // content blocks to verify (symlink/directory), where it would
            // be meaningless (and `disk_bytes_match_indexed_blocks` assumes
            // a regular file). A verification failure (including "file
            // vanished") falls through to the real write below, same as
            // `same_content` being false to begin with.
            let same_content = same_content
                && (version.blocks.is_empty()
                    || yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &self.sync_root(group_id)?.join(target_path),
                        &record.blocks,
                    )?);
            if same_content {
                // Content equality does not imply version equality: exec-bit,
                // symlink, or mtime-only changes are part of FileVersion
                // identity, so the DAG winner's metadata still has to be
                // applied here. Returning without this step leaves replicas
                // with the same bytes but permanently divergent permissions.
                let metadata_record = record.clone();
                let authority = self.root_lease_for(group_id)?;
                let authority_op = authority.begin_operation()?;
                let permit = authority_op.permit();
                apply_incoming_wire_metadata(
                    self.state.as_ref(),
                    group_id,
                    &metadata_record,
                    &meta,
                    &permit,
                )?;
                if try_apply_metadata_only_update(
                    self.state.as_ref(),
                    &self.sync_root(group_id)?,
                    group_id,
                    &metadata_record,
                    &effective_head.device_id,
                    meta.authoring_change_hash.as_ref(),
                    &permit,
                )? {
                    return Ok(MaterializeResult::Settled);
                }
            }
        }
        {
            let authority = self.root_lease_for(group_id)?;
            let authority_op = authority.begin_operation()?;
            let permit = authority_op.permit();
            apply_incoming_wire_metadata(self.state.as_ref(), group_id, &record, &meta, &permit)?;
        }
        // Return `materialize`'s own result unchanged: it reports
        // `RetryRequired` for every "not done yet" shape (blocks not
        // fetchable this attempt, decline under the path lock, or a
        // hazardous TOMBSTONE holding a genuine live row rather than
        // deleting it — see the `if record.deleted` branch's own doc
        // comment for why that specific case is not durable), and
        // collapsing any of those to `Settled` here marks the change
        // applied with content that never landed — a live index row with
        // no file on disk that nothing ever re-examines. A CREATE/symlink
        // hazard hold for a content record like this one is different:
        // `hold_record` fully upserts the incoming record (including its
        // own authoring identity), so that case is a genuinely durable
        // `Settled` outcome, not one this comment needs to call out. The
        // authoring identity needs no follow-up write either: `materialize`
        // persists it atomically with the row in every branch that writes
        // one.
        self.materialize(
            group_id,
            &record,
            policy,
            &effective_head.device_id,
            meta.authoring_change_hash.as_ref(),
        )
        .await
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
    ) -> Result<Vec<Change>, PeerSessionError> {
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

    /// The mandatory capability-negotiation handshake. Extracted verbatim
    /// from `handle_message`'s own `ClusterConfig` match arm (Phase 7C-7) --
    /// same two-stage `peer_handshake_received`/`peer_acked_my_cluster_
    /// config` bookkeeping, same `protocol_version` refusal gate, same
    /// change-DAG-negotiated heads announce, unchanged.
    async fn handle_cluster_config(
        &self,
        config: yadorilink_sync_wire::ClusterConfigFrame,
    ) -> Result<(), PeerSessionError> {
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
            self.peer_acked_my_cluster_config.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.handshake_notify.notify_one();
        self.record_peer_compression_support(&config.supported_compression);
        self.record_peer_reliable_delivery_support(config.supports_reliable_delivery);
        self.record_peer_version_present_support(config.supports_version_present);
        self.record_peer_version_hash_exact_support(config.supports_version_hash_exact);
        // `protocol_version` is a one-way refusal gate, not an
        // additive `supports_*` capability -- a peer below
        // `MIN_SUPPORTED_PROTOCOL_VERSION` (including the proto3
        // default `0`, i.e. one old enough to predate the field
        // entirely) only ever spoke the removed `BlockResponse`/
        // hash-only-correlated block-serving path, which this
        // build cannot fall back to. Withdraw every currently-
        // granted group authorization for it outright rather than
        // continue serving/syncing on a best-effort basis -- see
        // `MIN_SUPPORTED_PROTOCOL_VERSION`'s own doc comment.
        if config.protocol_version < Self::MIN_SUPPORTED_PROTOCOL_VERSION {
            tracing::error!(
                local_device_id = %self.local_device_id,
                peer = %self.peer_device_id,
                peer_protocol_version = config.protocol_version,
                min_supported = Self::MIN_SUPPORTED_PROTOCOL_VERSION,
                "refusing to sync with a peer whose protocol version predates the \
                 current block-serving wire format -- withdrawing all group \
                 authorization for this peer"
            );
            self.set_authorized_groups(std::iter::empty());
            return Ok(());
        }
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

    /// Dispatches one already-decoded inbound frame -- `run`'s recv loop is
    /// this function's sole caller (Phase 7C.5), having already routed
    /// `BlockRequest`/`BlockReply` to their own special-cased lanes before
    /// anything reaches here (see that `match`'s own doc comments for why:
    /// examination-admission and deadlock-avoidance concerns that don't
    /// apply to any other message family). Every arm below used to convert
    /// its own `proto::X` payload via `XFrame::try_from(..).expect(..)` at
    /// the unpacking site; now that `run`'s recv loop decodes the whole
    /// envelope through `PeerWireCodec` up front, `frame` arrives already
    /// typed and those conversions are gone.
    async fn handle_message(
        self: Arc<Self>,
        frame: yadorilink_sync_wire::InboundFrame,
    ) -> Result<(), PeerSessionError> {
        use yadorilink_sync_wire::InboundFrame;
        match frame {
            // No longer informational
            // only — records the peer's advertised compression support.
            InboundFrame::ClusterConfig(config) => self.handle_cluster_config(config).await,
            InboundFrame::BlockRequest(req) => {
                // Unreachable in production (`run`'s recv loop intercepts
                // `BlockRequest` before it ever reaches this dispatch,
                // doing its own examination-admission check there — see
                // that match arm's own doc). Kept for the same reason the
                // dispatch already had this fallback pre-7C.5: exhaustive
                // per-frame dispatch is cheap to keep correct, and no
                // caller should ever be able to bypass admission by
                // reaching this arm directly. Performs the identical
                // admission check inline for consistency.
                let device_wide_permit = match self.block_serve_engine() {
                    Some(engine) => match engine.try_begin_examination() {
                        Ok(permit) => Some(permit),
                        Err(busy) => {
                            let _ = self.try_send_block_reply_busy(&req, busy);
                            return Ok(());
                        }
                    },
                    None => None,
                };
                let permits = BlockExaminationPermits { _device_wide: device_wide_permit };
                self.handle_block_request(req, permits).await
            }
            InboundFrame::BlockReply(reply) => {
                // Unreachable in production -- see the BlockRequest arm's
                // own comment; `run`'s recv loop handles BlockReply inline
                // before this dispatch is ever reached.
                self.handle_block_reply(reply).await;
                Ok(())
            }
            InboundFrame::HeadsAnnounce(announce) => self.handle_heads_announce(announce).await,
            InboundFrame::ChangeRequest(req) => self.handle_change_request(req).await,
            InboundFrame::ChangeBatch(batch) => self.handle_change_batch(batch).await,
            InboundFrame::VersionPresentQuery(query) => {
                self.handle_version_present_query(query).await
            }
            InboundFrame::VersionPresentAck(ack) => {
                self.handle_version_present_ack(ack);
                Ok(())
            }
            InboundFrame::HandoffLeaseRequest(req) => self.handle_handoff_lease_request(req).await,
            InboundFrame::HandoffLeaseGrant(grant) => {
                self.handle_handoff_lease_grant(grant);
                Ok(())
            }
            InboundFrame::HandoffTicketRequest(req) => {
                self.handle_handoff_ticket_request(req).await
            }
            InboundFrame::HandoffTicketGrant(grant) => {
                self.handle_handoff_ticket_grant(grant);
                Ok(())
            }
            InboundFrame::HandoffLeaseRelease(release) => {
                self.handle_handoff_lease_release(release).await
            }
            InboundFrame::HandoffTicketRelease(release) => {
                self.handle_handoff_ticket_release(release).await
            }
            InboundFrame::RebootstrapSnapshotRequest(req) => {
                self.handle_rebootstrap_snapshot_request(req).await
            }
            InboundFrame::RebootstrapSnapshotResponse(resp) => {
                self.handle_rebootstrap_snapshot_response(resp);
                Ok(())
            }
            // Covers a genuinely empty `SyncMessage.payload` oneof, a peer
            // running a *newer* protocol version that added a oneof
            // variant this build doesn't know about yet, and an old peer
            // still sending the removed `full_index`/`index_update`
            // (`SyncMessage` fields 2-3, now reserved): `ProtobufPeerWireCodec::decode`
            // maps all three to `Unknown` rather than an error -- so a peer
            // this build can't fully understand is simply ignored, never a
            // decode failure.
            InboundFrame::Unknown { .. } => Ok(()),
        }
    }

    /// Sends a hard-rejection reply for `req` — an authorization or
    /// provenance failure discovered before any real serving would begin,
    /// which retrying is not expected to resolve (unlike
    /// `send_block_request_dont_have`'s race-prone "not referenced" case).
    /// `BlockReply.Rejected` (with `reason` and the echoed `request_id`) is
    /// distinguishable from "don't have it" or "busy" — see
    /// `BlockReply.rejected`'s own doc comment.
    async fn send_block_request_rejected(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
        reason: &str,
    ) -> Result<(), PeerSessionError> {
        self.send_frame(Self::block_request_rejected_frame(req, reason)).await
    }

    /// Non-blocking counterpart to [`Self::send_block_request_rejected`] —
    /// required at every call site inside `handle_block_request` that runs
    /// BEFORE `examination_permits` is dropped (the authorization/
    /// provenance checks): a blocking `send_frame` there would hold a
    /// device-wide examination-admission permit hostage to a stalled/non-
    /// draining peer's outbound queue, exactly the failure mode `try_begin_
    /// examination` and `try_send_block_reply_busy` both exist to prevent.
    /// See `try_send_block_reply_busy`'s own doc for why `bool` (a dropped
    /// best-effort reply is expected, not an error to propagate).
    fn try_send_block_request_rejected(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
        reason: &str,
    ) -> bool {
        self.try_send_frame(Self::block_request_rejected_frame(req, reason))
    }

    fn block_request_rejected_frame(
        req: &yadorilink_sync_wire::BlockRequestFrame,
        reason: &str,
    ) -> yadorilink_sync_wire::OutboundFrame {
        yadorilink_sync_wire::OutboundFrame::BlockReply(
            yadorilink_sync_wire::BlockReplyOutboundFrame {
                block_hash: req.block_hash.clone(),
                outcome: yadorilink_sync_wire::BlockReplyOutboundOutcome::Rejected {
                    reason: reason.to_string(),
                },
                request_id: req.request_id,
            },
        )
    }

    /// Non-blocking "don't have it" reply for `req` — a soft, possibly
    /// transient miss (e.g. the requester's own record of this path/hash
    /// briefly racing this device's in-flight materialize) that a bounded
    /// retry may resolve, unlike `send_block_request_rejected`'s hard
    /// failures. See `try_send_block_request_rejected`'s own doc for why
    /// this is non-blocking: its only caller runs before `examination_
    /// permits` is dropped.
    fn try_send_block_request_dont_have(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
    ) -> bool {
        self.try_send_frame(Self::block_request_dont_have_frame(req))
    }

    fn block_request_dont_have_frame(
        req: &yadorilink_sync_wire::BlockRequestFrame,
    ) -> yadorilink_sync_wire::OutboundFrame {
        yadorilink_sync_wire::OutboundFrame::BlockReply(
            yadorilink_sync_wire::BlockReplyOutboundFrame {
                block_hash: req.block_hash.clone(),
                outcome: yadorilink_sync_wire::BlockReplyOutboundOutcome::DontHave,
                request_id: req.request_id,
            },
        )
    }

    async fn handle_block_request(
        &self,
        req: yadorilink_sync_wire::BlockRequestFrame,
        examination_permits: BlockExaminationPermits,
    ) -> Result<(), PeerSessionError> {
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
        // Every branch below returns before `handle_block_request_with_
        // credit`'s dispatch/serve phase, so it is still within
        // EXAMINATION -- `examination_permits` must be dropped, and any
        // reply sent non-blocking (`try_send_*`, never the blocking
        // `send_*`/`.await`), before returning. Holding the permit across a
        // blocking send here would let an authorized-but-untrusted peer
        // that keeps sending requests doomed to fail one of these checks
        // (an unshared group, an unreferenced hash, no provenance) — cheap
        // for THIS device to detect, but each one still spawned only after
        // winning a device-wide examination permit — hold that permit
        // hostage to its own stalled outbound queue, denying every other
        // peer's requests an examination slot. See `try_send_block_reply_
        // busy`'s own doc for why `try_send` (never blocks, never queues)
        // is the right primitive and a dropped best-effort reply here is an
        // accepted, silent outcome.
        if !self.shares_group(&req.folder_group_id) {
            tracing::warn!(group_id = %req.folder_group_id, peer = %self.peer_device_id, "ignoring block request for unauthorized/unshared folder group");
            drop(examination_permits);
            let _ = self.try_send_block_request_rejected(
                &req,
                "requester is not authorized for this folder group",
            );
            return Ok(());
        }
        if !self.block_request_is_referenced(&req)? {
            tracing::warn!(
                local_device_id = %self.local_device_id,
                group_id = %req.folder_group_id,
                path = %req.file_path,
                peer = %self.peer_device_id,
                hash = %hex::encode(&req.block_hash),
                "refusing block request not referenced by the requested file record"
            );
            // Not a hard rejection: the requester's own record of this
            // path/hash may simply be racing this device's own in-flight
            // materialize/upsert (`ensure_blocks_present`'s bounded
            // `NOT_FOUND_RETRY_ATTEMPTS` exists specifically to absorb
            // that), so this answers `dont_have`/`not_found`, not
            // `rejected` -- a retry shortly after may well succeed.
            drop(examination_permits);
            let _ = self.try_send_block_request_dont_have(&req);
            return Ok(());
        }
        if !self.state.group_has_block_provenance(&req.folder_group_id, &req.block_hash)? {
            tracing::warn!(
                local_device_id = %self.local_device_id,
                group_id = %req.folder_group_id,
                path = %req.file_path,
                peer = %self.peer_device_id,
                hash = %hex::encode(&req.block_hash),
                "refusing block request without verified group provenance"
            );
            drop(examination_permits);
            let _ = self.try_send_block_request_rejected(
                &req,
                "no verified group provenance for this block",
            );
            return Ok(());
        }
        // Every check above (authorization, reference, provenance) is
        // shared regardless of what happens next. Serving itself always
        // goes through the credit-gated, coalesced path -- there is no
        // more direct-serve fallback (see `ClusterConfig.protocol_version`'s
        // own doc comment for why this reply shape is no longer
        // negotiated). A session with no engine installed at all (a
        // programming error in this codebase's own construction -- every
        // real `DaemonState`-backed session always has one; see
        // `set_block_serve_engine`'s doc comment) fails closed with
        // `Rejected` rather than a panic in this spawned per-message task.
        //
        // EXAMINATION (everything above this line) is done -- release both
        // permits explicitly, here, rather than letting them ride along
        // until this whole function returns. `handle_block_request_with_
        // credit` below waits for a fair dispatch turn (up to `DISPATCH_
        // WAIT_BUDGET`), then does a possibly-gated disk read and sends the
        // reply -- genuinely slow work that has nothing to do with
        // examination admission. Holding an examination permit through all
        // of that would let one busy-but-legitimate request tie up an
        // examination slot for far longer than examining it actually takes,
        // eating into the SAME budget meant to bound how fast NEW requests
        // can be examined -- exactly the failure mode named in this
        // struct's own doc: a peer whose requests are simply slow to
        // service (not malicious) could still starve other peers' requests
        // at the door for the whole service duration, not just the
        // examination one.
        drop(examination_permits);
        match self.block_serve_engine() {
            Some(engine) => self.handle_block_request_with_credit(req, engine).await,
            None => {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    peer = %self.peer_device_id,
                    group_id = %req.folder_group_id,
                    "refusing a block request: this session has no BlockServeEngine installed"
                );
                self.send_block_request_rejected(&req, "source has no serving engine installed")
                    .await
            }
        }
    }

    /// The credit-gated, coalesced block-serving path -- the only one this
    /// build has, once this session has an engine installed. Called only
    /// after `handle_block_request`'s own authorization/reference/
    /// provenance checks already passed.
    ///
    /// Admits against the block's own declared size
    /// (`block_request_declared_size`) when it's cheaply known from the
    /// live `FileRecord` -- the common case -- falling back to
    /// `MAX_BLOCK_SIZE` as a pessimistic worst-case reservation only when
    /// it isn't (the reference was established via the DAG/retained-
    /// version path instead, which exposes no size without a real read).
    /// Reserving the theoretical maximum for EVERY request regardless of
    /// real size would make a device's own advertised byte budgets
    /// massively over-conservative for the common case of many small
    /// blocks (confirmed: 72 concurrent 16 KiB requests against
    /// `MAX_BLOCK_SIZE` = 16 MiB each spuriously exhausted a 512 MiB
    /// global budget and returned `Busy` for blocks this device had
    /// trivially serviceable room for). Released once the reply has been
    /// sent (`ServeCreditGuard`'s drop).
    /// Upper bound on how long this handler waits for a fair dispatch turn
    /// before giving up and answering `Busy` instead of continuing to wait.
    /// Must stay comfortably under `FETCH_RESPONSE_TIMEOUT` (the
    /// requester's own response deadline) with enough margin left for the
    /// `Busy` reply's own network RTT to arrive before that deadline fires
    /// -- otherwise every congested request loses this race by
    /// construction: the source is still waiting in `FairDispatchQueue`
    /// when the requester has already given up and moved on, and `Busy`'s
    /// entire point (an EXPLICIT, actionable "try again shortly with this
    /// hint" versus a silent timeout) never actually gets used under the
    /// exact congestion it exists for.
    const DISPATCH_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

    async fn handle_block_request_with_credit(
        &self,
        req: yadorilink_sync_wire::BlockRequestFrame,
        engine: Arc<crate::block_serve::BlockServeEngine>,
    ) -> Result<(), PeerSessionError> {
        // Computed BEFORE waiting for a dispatch turn -- a cheap, local
        // `FileRecord` lookup (or a pessimistic fallback constant), not a
        // credit reservation, so computing it first does not reintroduce
        // "credit held hostage while merely waiting a turn" (see
        // `acquire_dispatch_turn`'s own doc comment): only `try_admit`
        // below actually reserves anything. `FairDispatchQueue` needs this
        // size up front to pick fairly by bytes granted, not request count
        // (see that queue's own doc comment).
        let declared_size = self.block_request_declared_size(&req);
        let reserve_bytes = declared_size.map(u64::from).unwrap_or(MAX_BLOCK_SIZE as u64);
        // Waits for a fair turn BEFORE reserving any byte credit -- see
        // `acquire_dispatch_turn`'s own doc comment for why this ordering
        // matters: byte credit must never be held hostage while a request
        // is merely waiting its turn in the fairness queue. This is what
        // actually provides cross-peer/cross-group fairness;
        // `BlockServeCredit`'s byte budgets alone cannot (see
        // `FairDispatchQueue`'s own doc comment).
        //
        // Bounded by `DISPATCH_WAIT_BUDGET`, not awaited unboundedly: an
        // unbounded wait here defeats `Busy`'s whole purpose under the
        // congestion it exists for (see that constant's own doc comment),
        // and would let an authorized peer that floods requests pile up
        // arbitrarily many waiting tasks otherwise (mitigated further by
        // `FairDispatchQueue`'s own `max_waiting` cap, which can also
        // reject this outright with no wait at all). Dropping the timed-
        // out future here is safe regardless of whether a turn had
        // already been granted moments before the deadline -- see
        // `FairDispatchQueue::acquire`'s own doc comment.
        let dispatch_guard = match tokio::time::timeout(
            Self::DISPATCH_WAIT_BUDGET,
            engine.acquire_dispatch_turn(&self.peer_device_id, &req.folder_group_id, reserve_bytes),
        )
        .await
        {
            Ok(Ok(guard)) => guard,
            Ok(Err(busy)) => return self.send_block_reply_busy(&req, busy).await,
            Err(_elapsed) => {
                return self
                    .send_block_reply_busy(
                        &req,
                        crate::block_serve::ServeBusy {
                            retry_after_ms: Self::DISPATCH_WAIT_BUDGET.as_millis() as u32,
                            queue_depth: 0,
                        },
                    )
                    .await;
            }
        };
        let _dispatch_guard = dispatch_guard;
        // The dispatch wait above can take up to `DISPATCH_WAIT_BUDGET` --
        // long enough for a netmap update to revoke this peer's
        // authorization for this group while this request was merely
        // waiting its turn. `handle_block_request`'s own `shares_group`
        // check only covers the instant this function was first entered;
        // re-checking here, immediately after the wait and before any
        // credit is reserved or the block is actually read/sent, closes
        // the disclosure window a since-revoked peer would otherwise get
        // for up to that entire wait.
        if !self.shares_group(&req.folder_group_id) {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "peer's authorization for this folder group was revoked while its request \
                 waited for a dispatch turn; refusing"
            );
            return self
                .send_block_request_rejected(
                    &req,
                    "requester is not authorized for this folder group",
                )
                .await;
        }
        let credit_guard =
            match engine.try_admit(&self.peer_device_id, &req.folder_group_id, reserve_bytes) {
                Ok(guard) => guard,
                Err(busy) => return self.send_block_reply_busy(&req, busy).await,
            };

        let compression_negotiated = self.compression_negotiated();
        // `Some(exact)` when `block_request_declared_size` found a real
        // declared size (the common case) -- the stored bytes must match
        // it EXACTLY, since a hash commits to specific bytes of a specific
        // length. `None` when this request fell back to `MAX_BLOCK_SIZE`
        // (the DAG/retained-version path, which exposes no exact size) --
        // there the stored bytes only need to fit under that pessimistic
        // reservation, not match it exactly.
        let expected_size = declared_size.map(u64::from);
        // `compression_negotiated` AND `expected_size` are both part of
        // the coalescing key itself -- see `coalesce_cell`'s own doc
        // comment for why a session that hasn't negotiated compression
        // must never share a cached entry with one that has, and why two
        // requesters disagreeing on expected size (one correctly sized,
        // one corrupted/understated) must never share a cell either.
        let cell = engine.coalesce_cell(
            &req.folder_group_id,
            &req.block_hash,
            compression_negotiated,
            expected_size,
        );
        let store = self.store.clone();
        let hash_hex = hex::encode(&req.block_hash);
        // `get_or_init` guarantees exactly one call to this closure runs
        // per still-live cell, regardless of how many concurrent
        // requesters (across every session on this device) are awaiting
        // the same `(group_id, hash)` -- every waiter beyond the first
        // gets this same result by reference (`Bytes`'s cheap refcount
        // clone), not its own copy of the read/verify/compress work.
        let result = cell
            .get_or_init(|| async move {
                let read_result = spawn_blocking(move || store.get(&hash_hex)).await;
                let data = match read_result {
                    Ok(Ok(data)) => data,
                    Ok(Err(e)) => {
                        return Err(crate::block_serve::CoalesceFailure::ReadFailed(e.to_string()))
                    }
                    Err(join_err) => {
                        return Err(crate::block_serve::CoalesceFailure::ReadFailed(
                            join_err.to_string(),
                        ))
                    }
                };
                // Serve-boundary invariant check: the credit this request
                // reserved (`reserve_bytes`, from `block_request_declared_size`
                // or `MAX_BLOCK_SIZE`) is only meaningful if the bytes this
                // device is ABOUT to send actually match what was
                // reserved for. `BlockStore::get` already verifies the
                // read bytes hash to the requested `block_hash` (so this
                // isn't re-checking content correctness), but nothing
                // upstream of this point cross-checks the read's LENGTH
                // against the size the referencing version declared for
                // this hash -- a corrupted/inconsistent index could
                // otherwise let a request bypass its own credit
                // reservation by referencing a hash whose real stored size
                // is larger than what was ever charged against the
                // per-peer/per-group/global budgets.
                let actual_len = data.len() as u64;
                let size_ok = match expected_size {
                    Some(expected) => actual_len == expected,
                    None => actual_len <= MAX_BLOCK_SIZE as u64,
                };
                if !size_ok {
                    return Err(crate::block_serve::CoalesceFailure::SizeMismatch(format!(
                        "stored block is {actual_len} bytes, expected {}",
                        expected_size
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| format!("<= {MAX_BLOCK_SIZE}"))
                    )));
                }
                if compression_negotiated {
                    match spawn_blocking(move || compress_block(&data)).await {
                        Ok((data, compression)) => Ok((Bytes::from(data), compression)),
                        Err(join_err) => Err(crate::block_serve::CoalesceFailure::ReadFailed(
                            join_err.to_string(),
                        )),
                    }
                } else {
                    Ok((Bytes::from(data), yadorilink_sync_wire::COMPRESSION_NONE))
                }
            })
            .await
            .clone();

        let outcome = match result {
            Ok((data, compression)) => {
                // Gate the outbound payload on the upload bucket before the
                // send proceeds -- consumes tokens for the actual bytes
                // about to be transmitted, awaiting bucket refill rather
                // than dropping.
                self.rate_limiters().upload.acquire(data.len() as u64).await;
                yadorilink_sync_wire::BlockReplyOutboundOutcome::Found {
                    data: data.to_vec(),
                    compression,
                }
            }
            Err(crate::block_serve::CoalesceFailure::ReadFailed(_)) => {
                yadorilink_sync_wire::BlockReplyOutboundOutcome::DontHave
            }
            Err(crate::block_serve::CoalesceFailure::SizeMismatch(reason)) => {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    group_id = %req.folder_group_id,
                    hash = %hex::encode(&req.block_hash),
                    reason,
                    "refusing to serve a block whose stored size does not match its declared \
                     size -- local index/store inconsistency"
                );
                yadorilink_sync_wire::BlockReplyOutboundOutcome::Rejected { reason }
            }
        };
        let send_result = self
            .send_frame(yadorilink_sync_wire::OutboundFrame::BlockReply(
                yadorilink_sync_wire::BlockReplyOutboundFrame {
                    block_hash: req.block_hash,
                    outcome,
                    request_id: req.request_id,
                },
            ))
            .await;
        drop(credit_guard);
        send_result
    }

    async fn send_block_reply_busy(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
        busy: crate::block_serve::ServeBusy,
    ) -> Result<(), PeerSessionError> {
        self.send_frame(Self::block_reply_busy_frame(req, busy)).await
    }

    /// Non-blocking counterpart to [`Self::send_block_reply_busy`], for the
    /// `try_begin_examination` pre-admission rejection in `run`'s recv loop
    /// specifically: that path runs on every incoming `BlockRequest` from a
    /// possibly-flooding peer, BEFORE any per-request work is bounded, so it
    /// must never spawn a task that then blocks on `send_frame` — a stalled
    /// or deliberately-not-draining peer would turn that spawn into exactly
    /// the unbounded-task growth `try_begin_examination` exists to prevent,
    /// just moved one step later. Returns whether the reply was actually
    /// enqueued; a `false` (outbound queue full, or the peer's send loop is
    /// already gone) is silently dropped by the caller — the requester's
    /// own bounded retry loop is what recovers from a missing reply, not
    /// this call succeeding.
    fn try_send_block_reply_busy(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
        busy: crate::block_serve::ServeBusy,
    ) -> bool {
        self.try_send_frame(Self::block_reply_busy_frame(req, busy))
    }

    fn block_reply_busy_frame(
        req: &yadorilink_sync_wire::BlockRequestFrame,
        busy: crate::block_serve::ServeBusy,
    ) -> yadorilink_sync_wire::OutboundFrame {
        yadorilink_sync_wire::OutboundFrame::BlockReply(
            yadorilink_sync_wire::BlockReplyOutboundFrame {
                block_hash: req.block_hash.clone(),
                outcome: yadorilink_sync_wire::BlockReplyOutboundOutcome::Busy {
                    retry_after_ms: busy.retry_after_ms,
                    queue_depth: busy.queue_depth,
                },
                request_id: req.request_id,
            },
        )
    }

    /// The block's own declared size, from the live `FileRecord`'s block
    /// list if it's referenced there -- the common case, and the same
    /// lookup `block_request_is_referenced` already does. `None` when the
    /// reference was only established via the DAG/retained-version path
    /// (rare: the live record was superseded or the path was deleted
    /// after the version this hash belongs to was last live), which
    /// exposes no size without a real read; the caller falls back to a
    /// pessimistic estimate in that case.
    fn block_request_declared_size(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
    ) -> Option<u32> {
        let record = self.state.get_file(&req.folder_group_id, &req.file_path).ok().flatten()?;
        if record.deleted {
            return None;
        }
        record.blocks.iter().find(|block| block.hash == req.block_hash).map(|block| block.size)
    }

    fn block_request_is_referenced(
        &self,
        req: &yadorilink_sync_wire::BlockRequestFrame,
    ) -> Result<bool, PeerSessionError> {
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

    /// Decompresses `data` per its declared `compression` (off the async
    /// runtime — same reasoning as every other compress/decompress call in
    /// this module) into a `FetchOutcome::Found`, or `Unusable` on a
    /// decompression failure. Used by `handle_block_reply`
    /// (`BlockReplyFound.data`).
    async fn resolve_block_bytes(
        &self,
        block_hash: Vec<u8>,
        data: Vec<u8>,
        compression: i32,
    ) -> FetchOutcome {
        // Only route through `spawn_blocking` when there's real
        // decompression work to do. `COMPRESSION_NONE` (and any other
        // unrecognized value) is a trivial passthrough (`decompress_block`
        // itself just clones the bytes for that case) — forcing every
        // single block reply, compressed or not, through a blocking-pool
        // round trip would add real scheduling latency to what used to be
        // an immediate, synchronous fast path, for the overwhelming
        // majority of responses (an unnegotiated peer, or a block
        // `compress_block` decided wasn't worth compressing). The "off the
        // async runtime" reasoning applies to actual CPU-bound zstd work,
        // not a no-op passthrough.
        if compression != yadorilink_sync_wire::COMPRESSION_ZSTD {
            return FetchOutcome::Found(Bytes::from(data));
        }
        match spawn_blocking(move || decompress_block(&data, compression, MAX_BLOCK_SIZE)).await {
            // `Bytes::from(Vec<u8>)` reuses the existing allocation, no
            // copy. Every waiter beyond the first then gets a cheap
            // refcount `clone` of that same `Bytes` instead of its own full
            // copy of the block (see `PendingBlockRequests`'s doc comment)
            // — unaffected by decompression happening first.
            Ok(Ok(decompressed)) => FetchOutcome::Found(Bytes::from(decompressed)),
            Ok(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    hash = %hex::encode(&block_hash),
                    peer = %self.peer_device_id,
                    "rejecting block reply: failed to decompress (corrupt payload or \
                     decompression-bomb bound exceeded); treating this peer as not having the \
                     block"
                );
                FetchOutcome::Unusable
            }
            Err(_join_err) => FetchOutcome::Unusable,
        }
    }

    /// Handles the richer `BlockReply` (only ever sent by a peer that has
    /// negotiated `supports_block_serve_credit`) — resolves the ONE waiter
    /// registered in `pending_block_requests_by_id` under
    /// `reply.request_id`. Unlike legacy `BlockResponse` (handled by
    /// `handle_block_response`, correlated by `block_hash` alone because
    /// that wire shape carries nothing else), this never fans out to more
    /// than one waiter: a negotiated peer's responder always echoes the
    /// exact `request_id` this session's `fetch_block_raw` assigned, so
    /// two different folder groups concurrently requesting the identical
    /// content hash — and legitimately getting DIFFERENT outcomes, e.g.
    /// one has provenance and gets `found` while the other doesn't and
    /// gets `rejected` — are never cross-wired the way a hash-only lookup
    /// would allow (see `PendingBlockRequestsById`'s own doc comment). The
    /// two message shapes are otherwise independent on the wire (added
    /// alongside, not replacing, `BlockResponse`); a single session only
    /// ever receives the one its peer actually negotiated to send.
    async fn handle_block_reply(&self, reply: yadorilink_sync_wire::BlockReplyFrame) {
        use yadorilink_sync_wire::BlockReplyOutcomeFrame as Outcome;
        let tx = {
            let mut pending = self
                .pending_block_requests_by_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.remove(&reply.request_id)
        };
        let Some(tx) = tx else { return };
        let payload = match reply.outcome {
            Some(Outcome::Found { data, compression }) => {
                self.resolve_block_bytes(reply.block_hash, data, compression).await
            }
            Some(Outcome::DontHave) | None => FetchOutcome::NotFound,
            Some(Outcome::Busy { retry_after_ms }) => FetchOutcome::Busy { retry_after_ms },
            Some(Outcome::Redirect { candidate_device_ids }) => {
                FetchOutcome::Redirect { candidate_device_ids }
            }
            Some(Outcome::Rejected { reason }) => {
                tracing::warn!(
                    peer = %self.peer_device_id,
                    hash = %hex::encode(&reply.block_hash),
                    reason = %reason,
                    "block request rejected by peer"
                );
                FetchOutcome::Rejected { reason }
            }
        };
        let _ = tx.send(payload);
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
    /// NotFound`/`Unusable`/`TimedOut`/`Redirect` into the same `None` as
    /// before this change — unchanged for this function's existing callers
    /// (the daemon's multi-peer dispatcher, which already has its own "try
    /// a different peer" fallback for any of them). `ensure_blocks_present`
    /// calls `fetch_block_raw` directly instead, to see the distinction and
    /// retry `NotFound` (which this function does not) — see that
    /// function's and `FetchOutcome`'s doc comments.
    ///
    /// `Busy` alone gets a bounded same-peer retry here (mirroring
    /// `ensure_blocks_present`'s own, with the same `BUSY_RETRY_ATTEMPTS`/
    /// `BUSY_RETRY_MAX_DELAY`), rather than collapsing straight to `None`
    /// like every other non-`Found` outcome: `FetchOutcome::Busy`'s own doc
    /// comment states a caller must not treat it as a permanent miss and
    /// fail over elsewhere the way `TimedOut` warrants, since retrying the
    /// SAME peer after its own `retry_after_ms` hint is usually cheaper —
    /// a caller that skipped this and went straight to `into_bytes` would
    /// treat ordinary, temporary dispatch-queue backpressure (see
    /// `handle_block_request_with_credit`'s `DISPATCH_WAIT_BUDGET`) as a
    /// permanent failure the single-source caller has no other peer to
    /// fall back to for.
    pub async fn fetch_block(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<Option<Bytes>, PeerSessionError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.fetch_block_raw(group_id, file_path, hash).await? {
                FetchOutcome::Busy { retry_after_ms } if attempt < Self::BUSY_RETRY_ATTEMPTS => {
                    let delay = std::time::Duration::from_millis(retry_after_ms.into())
                        .min(Self::BUSY_RETRY_MAX_DELAY);
                    tokio::time::sleep(delay).await;
                }
                outcome => return Ok(outcome.into_bytes()),
            }
        }
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
            .send_frame(yadorilink_sync_wire::OutboundFrame::VersionPresentQuery(
                yadorilink_sync_wire::VersionPresentQueryFrame {
                    request_id,
                    folder_group_id: group_id.to_string(),
                    file_path: file_path.to_string(),
                    block_hashes: blocks.iter().map(|b| b.hash.0.clone()).collect(),
                    for_handoff,
                    version_hash: version_hash.as_bytes().to_vec(),
                    block_sizes: blocks.iter().map(|b| b.size).collect(),
                },
            ))
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
    /// its own last cached copy. See
    /// [`PeerReplicaEngine::holds_version_durably`](yadorilink_replica_engine::PeerReplicaEngine::holds_version_durably)
    /// for the (deliberately strict) conditions; anything short of all of
    /// them answers a fail-closed `false`.
    async fn handle_version_present_query(
        &self,
        query: yadorilink_sync_wire::VersionPresentQueryFrame,
    ) -> Result<(), PeerSessionError> {
        // `PeerReplicaEngine` has no protobuf dependency, so the wire query
        // is converted to its domain equivalent here rather than passed
        // through directly.
        let evaluation =
            self.replica_engine.holds_version_durably(&durable_version_query_from_wire(&query));
        if let Some(warning) = &evaluation.warning {
            tracing::warn!(
                group_id = %query.folder_group_id,
                path = %query.file_path,
                error = %warning.message,
                "refusing to serve block: current version record is unreadable"
            );
        }
        let present = evaluation.present;
        self.send_frame(yadorilink_sync_wire::OutboundFrame::VersionPresentAck(
            yadorilink_sync_wire::VersionPresentAckOutboundFrame {
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
        ))
        .await
    }

    /// Resolves the pending `request_version_present` awaiting this reply.
    /// Takes the protobuf-free `peer_wire` domain frame (Phase 7C's first
    /// production migration -- see `crate::peer_wire`'s own doc comment):
    /// the caller converts the just-decoded `proto::VersionPresentAck` at
    /// the point it unpacks the oneof, this handler itself has no
    /// protobuf dependency.
    fn handle_version_present_ack(&self, ack: yadorilink_sync_wire::VersionPresentAckFrame) {
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
            .send_frame(yadorilink_sync_wire::OutboundFrame::HandoffLeaseRequest(
                yadorilink_sync_wire::HandoffLeaseRequestFrame {
                    request_id,
                    folder_group_id: group_id.to_string(),
                },
            ))
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
        req: yadorilink_sync_wire::HandoffLeaseRequestFrame,
    ) -> Result<(), PeerSessionError> {
        // Same authorization gate `handle_block_request` applies before
        // touching anything group-scoped: a peer's live session membership
        // can narrow mid-session (revocation), so this is re-checked fresh
        // on every request rather than trusted from construction time. An
        // unauthorized group answers `granted = false` without ever
        // consulting the injected responder (no coordination-plane round
        // trip for a group this peer has no business asking about).
        let grant = if self.shares_group(&req.folder_group_id) {
            self.handoff_lease_responder().request_handoff_lease(&req.folder_group_id).await
        } else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff lease request for unauthorized/unshared folder group"
            );
            None
        };
        let reply = match grant {
            Some(g) => yadorilink_sync_wire::HandoffLeaseGrantFrame {
                request_id: req.request_id,
                granted: true,
                lease_id: g.lease_id,
                root_digest: g.root_digest.to_vec(),
                expires_at_unix: g.expires_at_unix,
            },
            None => yadorilink_sync_wire::HandoffLeaseGrantFrame {
                request_id: req.request_id,
                granted: false,
                lease_id: String::new(),
                root_digest: Vec::new(),
                expires_at_unix: 0,
            },
        };
        self.send_frame(yadorilink_sync_wire::OutboundFrame::HandoffLeaseGrant(reply)).await
    }

    /// Resolves the pending `request_handoff_lease_from_peer` awaiting this
    /// reply. A malformed `root_digest` (anything other than exactly 32
    /// bytes) is treated identically to `granted = false` -- fail closed
    /// rather than guess.
    fn handle_handoff_lease_grant(&self, grant: yadorilink_sync_wire::HandoffLeaseGrantFrame) {
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
            .send_frame(yadorilink_sync_wire::OutboundFrame::RebootstrapSnapshotRequest(
                yadorilink_sync_wire::RebootstrapSnapshotRequestFrame {
                    request_id,
                    folder_group_id: group_id.to_string(),
                    requested_hash: requested_hash.0.to_vec(),
                },
            ))
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
        req: yadorilink_sync_wire::RebootstrapSnapshotRequestFrame,
    ) -> Result<(), PeerSessionError> {
        // Same authorization gate `handle_handoff_lease_request` applies
        // before touching anything group-scoped: a peer's live session
        // membership can narrow mid-session (revocation), so this is
        // re-checked fresh on every request rather than trusted from
        // construction time.
        let prepared = if self.shares_group(&req.folder_group_id) {
            match <[u8; 32]>::try_from(req.requested_hash.as_slice()) {
                Ok(hash_bytes) => self
                    .rebootstrap_handler()
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
            Some(p) => yadorilink_sync_wire::RebootstrapSnapshotResponseFrame {
                request_id: req.request_id,
                granted: true,
                required_encoded: p.required.canonical_encoding(),
                snapshot_bytes: p.snapshot_bytes,
            },
            None => yadorilink_sync_wire::RebootstrapSnapshotResponseFrame {
                request_id: req.request_id,
                granted: false,
                required_encoded: Vec::new(),
                snapshot_bytes: Vec::new(),
            },
        };
        self.send_frame(yadorilink_sync_wire::OutboundFrame::RebootstrapSnapshotResponse(reply))
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
    fn handle_rebootstrap_snapshot_response(
        &self,
        resp: yadorilink_sync_wire::RebootstrapSnapshotResponseFrame,
    ) {
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
    ) -> Result<(), PeerSessionError> {
        let request_id =
            self.next_handoff_lease_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send_frame(yadorilink_sync_wire::OutboundFrame::HandoffLeaseRelease(
            yadorilink_sync_wire::HandoffLeaseReleaseOutboundFrame {
                request_id,
                folder_group_id: group_id.to_string(),
                lease_id: lease_id.to_string(),
            },
        ))
        .await
    }

    async fn handle_handoff_lease_release(
        self: Arc<Self>,
        release: yadorilink_sync_wire::HandoffLeaseReleaseFrame,
    ) -> Result<(), PeerSessionError> {
        if self.shares_group(&release.folder_group_id) {
            self.handoff_lease_responder()
                .release_handoff_lease(&release.folder_group_id, &release.lease_id)
                .await;
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
            .send_frame(yadorilink_sync_wire::OutboundFrame::HandoffTicketRequest(
                yadorilink_sync_wire::HandoffTicketRequestFrame {
                    request_id,
                    folder_group_id: group_id.to_string(),
                },
            ))
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
    ) -> Result<(), PeerSessionError> {
        let request_id =
            self.next_handoff_ticket_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.send_frame(yadorilink_sync_wire::OutboundFrame::HandoffTicketRelease(
            yadorilink_sync_wire::HandoffTicketReleaseOutboundFrame {
                request_id,
                folder_group_id: group_id.to_string(),
                target_device_id: target_device_id.to_string(),
                lease_id: lease_id.to_string(),
            },
        ))
        .await
    }

    async fn handle_handoff_ticket_release(
        self: Arc<Self>,
        release: yadorilink_sync_wire::HandoffTicketReleaseFrame,
    ) -> Result<(), PeerSessionError> {
        if self.shares_group(&release.folder_group_id) {
            self.handoff_ticket_responder()
                .release_handoff_ticket(
                    &release.folder_group_id,
                    &release.target_device_id,
                    &release.lease_id,
                )
                .await;
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
        req: yadorilink_sync_wire::HandoffTicketRequestFrame,
    ) -> Result<(), PeerSessionError> {
        // Same authorization gate `handle_handoff_lease_request` applies:
        // this peer's live session membership can narrow mid-session
        // (revocation), so this is re-checked fresh on every request rather
        // than trusted from construction time. An unauthorized group
        // answers `granted = false` without ever consulting the injected
        // responder.
        let grant = if self.shares_group(&req.folder_group_id) {
            self.handoff_ticket_responder().request_handoff_ticket(&req.folder_group_id).await
        } else {
            tracing::warn!(
                group_id = %req.folder_group_id,
                peer = %self.peer_device_id,
                "ignoring handoff ticket request for unauthorized/unshared folder group"
            );
            None
        };
        let reply = match grant {
            Some(g) => yadorilink_sync_wire::HandoffTicketGrantFrame {
                request_id: req.request_id,
                granted: true,
                lease_id: g.lease_id.unwrap_or_default(),
                expires_at_unix: g.expires_at_unix,
                target_device_id: g.target_device_id.unwrap_or_default(),
            },
            None => yadorilink_sync_wire::HandoffTicketGrantFrame {
                request_id: req.request_id,
                granted: false,
                lease_id: String::new(),
                expires_at_unix: 0,
                target_device_id: String::new(),
            },
        };
        self.send_frame(yadorilink_sync_wire::OutboundFrame::HandoffTicketGrant(reply)).await
    }

    /// Resolves the pending `request_handoff_ticket_from_peer` awaiting this
    /// reply.
    fn handle_handoff_ticket_grant(&self, grant: yadorilink_sync_wire::HandoffTicketGrantFrame) {
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

    /// How long `fetch_block_raw` waits for *any* reply (found, not-found,
    /// or unusable) to one `BlockRequest` before giving up on this attempt
    /// entirely. Without this, a peer that never replies at all (as
    /// opposed to replying `not_found`) left `rx.await` unbounded here,
    /// relying entirely on whichever *external* timeout a caller happened
    /// to wrap the whole call in -- `ensure_blocks_present` has no such
    /// per-request wrap, only `materialize_dag_content_head`'s
    /// whole-batch `DEFAULT_HYDRATION_TIMEOUT` (30s) around the *entire*
    /// `ensure_blocks_present` call. A confirmed, reproduced regression
    /// (see `fix/conflict-copy-convergence-obligation-20260723`): the
    /// Convergence Engine's own concurrent audit calls measurably hit this
    /// exact 30s ceiling on individual attempts, and with up to
    /// `MAX_PEERS_PER_TICK` (2) candidates tried sequentially per tick,
    /// a single `process_group` call was measured taking over 60s --
    /// comfortably enough, across just two such ticks, to trip a 90s
    /// stall detector even before considering any other cause. Matches
    /// `yadorilink-daemon::hydration`'s own `PER_BLOCK_FETCH_TIMEOUT`
    /// (5s) -- the value this codebase already considers reasonable for
    /// one block's own round trip, independent of this being a different
    /// crate/caller.
    const FETCH_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Registers this fetch's waiter under a fresh `request_id`. The
    /// responder always echoes it back on whichever `BlockReply` it sends
    /// (see `PendingBlockRequestsById`'s own doc comment), so every
    /// request gets its own id and its own independent, unambiguous
    /// answer -- no coalescing needed at this layer.
    fn register_block_fetch_waiter(
        &self,
    ) -> (oneshot::Receiver<FetchOutcome>, PendingBlockGuard<'_>, u64) {
        let (tx, rx) = oneshot::channel();
        let request_id =
            self.next_block_request_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pending_block_requests_by_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(request_id, tx);
        let guard = PendingBlockGuard { pending: &self.pending_block_requests_by_id, request_id };
        (rx, guard, request_id)
    }

    async fn fetch_block_raw(
        &self,
        group_id: &str,
        file_path: &str,
        hash: &[u8],
    ) -> Result<FetchOutcome, PeerSessionError> {
        let (rx, _guard, request_id) = self.register_block_fetch_waiter();
        // Measured from just before
        // the request goes out to the response actually arriving — the
        // real block-request-to-response round trip the adaptive
        // window is driven by.
        let started_at = std::time::Instant::now();
        self.send_frame(yadorilink_sync_wire::OutboundFrame::BlockRequest(
            yadorilink_sync_wire::BlockRequestFrame {
                folder_group_id: group_id.to_string(),
                file_path: file_path.to_string(),
                block_hash: hash.to_vec(),
                request_id,
            },
        ))
        .await?;
        // Only an actual reply from
        // the peer feeds the adaptive window, and ONLY per its real
        // outcome, never unconditionally just because the oneshot resolved
        // without erroring — `rx.await` returning `Err` means the sender
        // was dropped without ever answering (e.g. this session ending),
        // which is neither a healthy round trip nor a genuine timeout, so
        // it's left alone rather than double-counted as either. A real
        // timeout (no reply within `FETCH_RESPONSE_TIMEOUT`) IS fed to the
        // adaptive window here, directly — unlike the external-timeout
        // case `record_fetch_timeout`'s own doc comment describes (a
        // caller's own wrap drops this future before it ever gets a chance
        // to observe anything), this timeout fires *inside*
        // `fetch_block_raw` itself, so it can record the signal
        // immediately rather than relying on a caller to notice and call
        // back in.
        let result = match tokio::time::timeout(Self::FETCH_RESPONSE_TIMEOUT, rx).await {
            Ok(Ok(payload)) => {
                // `Busy` in particular must NEVER reach `on_success`: the
                // peer answered quickly, but explicitly said it could NOT
                // serve this request right now -- a fast `Busy` reply is
                // not evidence the link/peer can sustain more concurrent
                // requests, it's the opposite (see `on_congestion`'s own
                // doc comment for the runaway-growth this would otherwise
                // cause). `NotFound`/`Unusable`/`Rejected`/`Redirect` are
                // all real, prompt answers too, just not ones that say
                // anything about whether MORE concurrent requests would be
                // sustainable, so none of them feed the window either way.
                match &payload {
                    FetchOutcome::Found(_) => self.adaptive_window.on_success(started_at.elapsed()),
                    FetchOutcome::Busy { .. } => self.adaptive_window.on_congestion(),
                    FetchOutcome::NotFound
                    | FetchOutcome::Unusable
                    | FetchOutcome::Rejected { .. }
                    | FetchOutcome::Redirect { .. }
                    | FetchOutcome::TimedOut => {}
                }
                payload
            }
            Ok(Err(_recv_error)) => FetchOutcome::NotFound,
            Err(_elapsed) => {
                self.adaptive_window.on_timeout();
                FetchOutcome::TimedOut
            }
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

    /// Bound on how many times a `BlockReply.Busy` answer is retried against
    /// the SAME peer before giving up on it, mirroring `NOT_FOUND_RETRY_
    /// ATTEMPTS`'s reasoning: `Busy` means this peer plausibly has the
    /// block but is temporarily over its own serve-credit limit, which
    /// (unlike `NotFound`'s index-not-updated-yet race) can legitimately
    /// take longer than a fixed short delay to clear, so each wait honors
    /// the peer's own `retry_after_ms` hint rather than a fixed backoff —
    /// but the retry itself is still bounded, since a persistently
    /// overloaded peer should eventually hand off to the caller's own
    /// peer-rotation rather than retry forever.
    const BUSY_RETRY_ATTEMPTS: u32 = 5;
    /// Upper bound on how long a single `Busy` wait is trusted for, so a
    /// misbehaving or malicious peer cannot stall a fetch indefinitely by
    /// advertising an enormous `retry_after_ms`.
    const BUSY_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

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
    ) -> Result<bool, PeerSessionError> {
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
                let outcome = self.fetch_block_raw(group_id, file_path, &block.hash).await?;
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    candidate_peer_id = %self.peer_device_id,
                    file_path,
                    hash = %hex::encode(&block.hash),
                    attempt,
                    outcome = ?outcome,
                    "block fetch attempt"
                );
                match outcome {
                    FetchOutcome::Found(data) => break Some(data),
                    FetchOutcome::NotFound if attempt < Self::NOT_FOUND_RETRY_ATTEMPTS => {
                        tokio::time::sleep(Self::not_found_retry_delay()).await;
                    }
                    // `TimedOut` is deliberately NOT retried here, unlike
                    // `NotFound`: a bounded same-peer retry makes sense for
                    // a fast index-not-updated-yet race (resolves in well
                    // under a second), but a peer that already didn't
                    // reply within `FETCH_RESPONSE_TIMEOUT` once is a much
                    // heavier signal (a slow/unresponsive connection, not
                    // a quick race) -- retrying it here would just burn
                    // another `FETCH_RESPONSE_TIMEOUT` for likely the same
                    // outcome. Fail fast instead and let the caller's own
                    // peer-rotation (the Convergence Engine tries a
                    // different candidate session on its next attempt)
                    // handle it.
                    FetchOutcome::Busy { retry_after_ms }
                        if attempt < Self::BUSY_RETRY_ATTEMPTS =>
                    {
                        let delay = std::time::Duration::from_millis(retry_after_ms.into())
                            .min(Self::BUSY_RETRY_MAX_DELAY);
                        tokio::time::sleep(delay).await;
                    }
                    // A `Redirect` names OTHER devices as likely holders —
                    // retrying this same peer again would just re-ask
                    // someone who already said "not me". Fail fast (like
                    // `NotFound`/`Unusable`/`TimedOut` below) and let the
                    // caller's own peer-rotation try elsewhere; steering
                    // toward `candidate_device_ids` specifically is the
                    // multi-peer hydration dispatcher's job (stage 3), not
                    // this single-session retry loop's -- logged here only
                    // so the hint isn't silently discarded before stage 3
                    // exists to act on it.
                    FetchOutcome::Redirect { ref candidate_device_ids } => {
                        tracing::debug!(
                            local_device_id = %self.local_device_id,
                            candidate_peer_id = %self.peer_device_id,
                            file_path,
                            hash = %hex::encode(&block.hash),
                            candidates = ?candidate_device_ids,
                            "peer redirected this block request; not yet acted on by this \
                             single-session retry loop"
                        );
                        break None;
                    }
                    // A hard denial (missing authorization/provenance, or a
                    // malformed request) -- retrying this same peer will
                    // not resolve it, unlike `NotFound`'s racy "not
                    // referenced yet" case just above. Fail fast rather
                    // than burning `NOT_FOUND_RETRY_ATTEMPTS`-worth of
                    // pointless re-asks against a peer that will answer
                    // identically every time.
                    FetchOutcome::Rejected { ref reason } => {
                        tracing::debug!(
                            local_device_id = %self.local_device_id,
                            candidate_peer_id = %self.peer_device_id,
                            file_path,
                            hash = %hex::encode(&block.hash),
                            reason,
                            "peer rejected this block request; not retrying"
                        );
                        break None;
                    }
                    FetchOutcome::NotFound
                    | FetchOutcome::Unusable
                    | FetchOutcome::TimedOut
                    | FetchOutcome::Busy { .. } => break None,
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
                            return Err(PeerSessionError::from(std::io::Error::other(format!(
                                "block store write task panicked: {join_err}"
                            ))))
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        local_device_id = %self.local_device_id,
                        candidate_peer_id = %self.peer_device_id,
                        file_path,
                        hash = %hex::encode(&block.hash),
                        attempts = attempt,
                        "peer reported block as not_found after retrying; sync incomplete for this file"
                    );
                    all_present = false;
                    // Fail fast for the REST of this path's blocks against
                    // THIS peer -- a confirmed, reproduced regression (see
                    // `fix/conflict-copy-convergence-obligation-20260723`):
                    // this peer has already shown it cannot supply this
                    // path's content, so continuing to serially probe every
                    // remaining block (each with its own bounded retry
                    // loop) only accumulates latency for a result already
                    // known to be `false`. Scoped to THIS path only, not
                    // this whole peer session -- a different path may still
                    // be fully servable by the same peer.
                    break;
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
    /// Returns `Ok(HydrationOutcome::Hydrated)` once content is fully
    /// written; `Ok(HydrationOutcome::Held { .. })` if every block was
    /// fetched but a filename hazard withheld the physical write (see that
    /// variant's own doc comment — a caller must not treat this the same
    /// as `Hydrated`); `Err(HydrationFailed)` if this peer didn't have
    /// every block within the timeout. The file is left as (or reverted
    /// to) `Placeholder` in both the `Held` and `Err` cases, so a caller
    /// trying a *different* peer's session can simply retry.
    pub async fn hydrate_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        self.hydrate_file_with_timeout(group_id, path, DEFAULT_HYDRATION_TIMEOUT).await
    }

    /// Like `hydrate_file`, with an explicit timeout — production callers
    /// use the default (30s); tests use a much shorter one so
    /// the "no reachable peer" case doesn't make the suite slow.
    ///
    /// Takes `SyncState::path_lock` for the whole attempt, same as every
    /// other per-path materialization entry point (`rematerialize_one_
    /// record`'s doc comment explains why) — an independent review's own
    /// residual to the authoring-bound identity checks above: those make
    /// this attempt correctly REFUSE to claim `Hydrated` for a row a
    /// concurrent update has superseded, but `reconstruct_file`'s
    /// temp-then-rename write itself is not undone by that refusal, so
    /// two genuinely concurrent hydration/materialize attempts for the
    /// SAME path could still interleave their renames -- this attempt's
    /// stale rename landing AFTER a concurrent, legitimate materialize's
    /// correct one, leaving disk holding old bytes under a row the index
    /// (correctly, this time) still calls `Hydrated`. Serializing on the
    /// same lock every other writer for this path already takes closes
    /// that at the root: only one such attempt for a given path can ever
    /// be physically writing at a time.
    pub async fn hydrate_file_with_timeout(
        &self,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = path_lock.lock().await;
        self.hydrate_file_with_timeout_locked(group_id, path, timeout).await
    }

    /// The actual hydration body, assuming the caller already holds
    /// `SyncState::path_lock` for `path` -- used directly by
    /// `apply_locked_record`'s `Equal`/`After` rehydrate branches, whose
    /// only caller (`rematerialize_one_record`) already holds that same
    /// lock for its whole body; calling the public, lock-acquiring
    /// `hydrate_file_with_timeout` from there would deadlock on
    /// `tokio::sync::Mutex`'s non-reentrant lock.
    async fn hydrate_file_with_timeout_locked(
        &self,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        let Some(record) = self.state.get_file(group_id, path)? else {
            return Err(PeerSessionError::NotFound(format!("file {group_id}/{path}")));
        };
        if record.deleted {
            return Err(PeerSessionError::NotFound(format!("file {group_id}/{path}")));
        }

        // Captured BEFORE this attempt marks the row `Hydrating`, so the
        // guard below reverts only if the row is still exactly this
        // attempt's own version when it drops -- see `HydratingStateGuard`'s
        // own doc comment.
        let authoring_change_hash = self.state.get_authoring_change_hash(group_id, path)?;
        let out_path = self.local_file_path(group_id, path)?;
        // Captured BEFORE the (possibly multi-second) block fetch below,
        // for the identical reason the daemon's own `hydrate_inner`
        // captures `initial_disk_identity`: an independent review's
        // finding that this function re-verified the authoring identity
        // before its physical write but never checked disk identity at
        // all. A `Placeholder` row already has a real sparse file on disk
        // (`chunker::write_placeholder`, written when the row was first
        // set to `Placeholder`); if an external editor writes real
        // content into that same-named file while this attempt is mid-
        // fetch -- `path_lock` is held for this whole attempt, but an
        // editor writing directly to the file does not go through
        // `path_lock` at all -- the authoring-hash re-check alone cannot
        // detect it (the index row's authoring identity hasn't changed,
        // only the bytes on disk have). Re-checked just before
        // `reconstruct_file` below; a mismatch means this attempt must
        // not overwrite what's now on disk.
        let initial_disk_identity = disk_race_fingerprint(&out_path);
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        self.state.set_materialization_state(
            group_id,
            path,
            MaterializationState::Hydrating,
            &root_commit_permit,
        )?;
        // Reverts the row back to `Placeholder` on drop unless `commit`ed
        // -- every `?` between here and the end of this function used to
        // leave the row stuck at `Hydrating` forever on a real error
        // (a hazard-check I/O/DB failure, `clear_held`, root/containment
        // verification, disk-headroom preflight, the reconstruct itself,
        // or the exec-bit apply). The two outcomes that already had their
        // own explicit revert (fetch failure, hazard-hold) construct and
        // immediately drop their own guard too, so every exit path is
        // covered by exactly one mechanism instead of some exits
        // remembering to revert and others not.
        let mut hydrating_guard = HydratingStateGuard {
            state: self.state.as_ref(),
            group_id,
            path,
            authoring_change_hash,
            committed: false,
        };

        let outcome = tokio::time::timeout(
            timeout,
            self.ensure_blocks_present(group_id, path, &record.blocks),
        )
        .await;

        let all_present = match outcome {
            Ok(Ok(all_present)) => all_present,
            Ok(Err(e)) => return Err(e),
            Err(_timed_out) => false,
        };

        if !all_present {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }

        // Same hazard short-circuit as
        // `materialize` — every block was just fetched into this device's
        // block store above regardless (so it can still serve them onward
        // to another peer), but the atomic reconstruct-to-disk
        // write below must never run for a hazardous name. Reverts back
        // to `Placeholder` (content genuinely isn't on disk under this
        // name) rather than leaving the row stuck at `Hydrating`, and
        // returns `Ok(Held)` rather than an error — the blocks really were
        // hydrated successfully; only local materialization was withheld,
        // and the caller must not read this as indistinguishable from a
        // genuine `Hydrated`.
        if let Some(reason) = self.hazard_reason_for(group_id, &record)? {
            self.state.set_held(group_id, path, &reason, now_unix_nanos())?;
            tracing::info!(
                path = %path,
                group_id,
                reason = %reason,
                "hydration fetched all blocks but the file is held due to a filename hazard; \
                 not materialized on this device"
            );
            // The guard's own drop reverts to `Placeholder` -- this is
            // exactly that "hazard, not error" exit, not a rollback of
            // something that failed.
            return Ok(HydrationOutcome::Held { reason });
        }
        self.state.clear_held(group_id, path)?;

        // Re-validate this attempt's captured authoring identity BEFORE
        // the physical write below -- an independent review's own deeper
        // counter-scenario to the rollback-only fix above: a concurrent
        // peer update can supersede this row with a genuinely newer
        // version at any point during the (up to `timeout`-long) block
        // fetch above, and this attempt is still working off `record`,
        // the OLD version read at the very start. Without this check,
        // reconstructing and committing here would write the OLD
        // version's bytes to disk and then mark the NOW-current (newer)
        // row `Hydrated` -- index says the new version is fully
        // materialized while disk actually holds the old one. Failing
        // here is not a real hydration failure (the blocks this attempt
        // fetched are still valid and stored for the version it started
        // with); the caller retries and a fresh call picks up the
        // current version correctly.
        if self.state.get_authoring_change_hash(group_id, path)? != authoring_change_hash {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        // The authoring-identity re-check above catches a concurrent PEER
        // update superseding this row; it says nothing about a concurrent
        // LOCAL edit, which never touches the index's authoring column at
        // all until the watcher gets around to processing it (and the
        // watcher's own DAG-authoring path is itself serialized behind
        // this same `path_lock`, so it cannot even run until this attempt
        // finishes). Re-checking disk identity here closes that gap: if
        // an external editor wrote real content into the placeholder
        // file while this attempt was mid-fetch, disk no longer matches
        // what this attempt captured before starting, and reconstructing
        // now would silently discard that edit the moment the watcher is
        // finally unblocked and reads it as already-gone.
        if disk_race_fingerprint(&out_path) != initial_disk_identity {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        // defense-in-depth — see `materialize`'s matching call
        // for what this does and does not close.
        self.verify_write_target(group_id, &out_path)?;
        // Preflight before the
        // temp-then-rename write below begins — see
        // `preflight_disk_headroom`'s doc comment.
        self.preflight_disk_headroom(group_id, &out_path, record.size)?;
        reconstruct_file(self.store.as_ref(), &out_path, &record.blocks, record.mtime_unix_nanos)?;
        // Apply the owner-executable bit
        // currently recorded for this path (POSIX: real chmod; no-op,
        // no error, on Windows) — hydration is a materialization path
        // just like `materialize` below, so it gets the same treatment.
        apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, path)?)?;
        // Author-bound, not a blind `set_materialization_state`, for the
        // identical reason `HydratingStateGuard`'s own revert-on-drop is:
        // a concurrent update could still have superseded this row in the
        // narrow window between the re-check just above and this commit.
        // If the row has moved on, this attempt's just-written bytes on
        // disk are stale for whatever version is now current -- do not
        // claim `Hydrated` for a version this attempt never actually
        // materialized.
        if !self.state.transition_materialization_state_if_same_authoring(
            group_id,
            path,
            MaterializationState::Hydrating,
            authoring_change_hash.as_ref(),
            MaterializationState::Hydrated,
        )? {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        hydrating_guard.committed = true;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.state.touch_last_accessed(group_id, path, now)?;
        Ok(HydrationOutcome::Hydrated)
    }

    /// Pins `path` and, if it isn't already `Hydrated`, hydrates it from
    /// this peer — the spec's "Pinning forces hydration".
    /// Unpinning needs no peer at all and is just
    /// `SyncState::set_pinned(..., false)`, called directly by callers
    /// that have a `SyncState` handle.
    ///
    /// Returns `hydrate_file`'s own outcome (or `Hydrated` directly, with
    /// no hydration attempt, if the path was already `Hydrated`) rather
    /// than collapsing it to `Ok(())`: a hazard-collision `Held` result
    /// means "pinning" did NOT actually force hydration despite this
    /// call's own doc comment's promise — the pinned row still has no
    /// content on disk. A caller must surface that distinctly, not read a
    /// forced-pin as having silently succeeded.
    pub async fn pin_and_hydrate_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        self.state.set_pinned(group_id, path, true)?;
        if self.state.get_materialization_state(group_id, path)?
            == Some(MaterializationState::Hydrated)
        {
            return Ok(HydrationOutcome::Hydrated);
        }
        self.hydrate_file(group_id, path).await
    }

    /// The locked, per-record convergence core shared by the two callers that
    /// must never diverge on how a peer's record is compared against and
    /// materialized over the local one: the legacy wire path
    /// (`legacy_index_convergence::reconcile_one_file`) and the
    /// materialization-audit re-drive (`rematerialize_one_record`). It performs
    /// the verified DAG-ancestry comparison and every NON-conflicting outcome (adopt /
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
    pub async fn apply_locked_record(
        &self,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<LockedRecordOutcome, PeerSessionError> {
        let incoming_author = meta.authoring_change_hash.as_ref().ok_or_else(|| {
            PeerSessionError::InvalidInput(format!(
                "incoming record {group_id}/{} has no valid authoring_change_hash",
                incoming.path
            ))
        })?;
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        if !self.state.dag_has_change_or_pruned(group_id, incoming_author)? {
            return Err(PeerSessionError::InvalidInput(format!(
                "incoming record {group_id}/{} references an unverified authoring change",
                incoming.path
            )));
        }
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
            // must land first, not after. Skipped for a tombstone: a
            // delete has no kind/target/exec-bit to dispatch on (the
            // `record.deleted` branch in `materialize` runs unconditionally
            // first, before any kind-based dispatch), and bootstrapping a
            // `version_seq = 0` scaffold row here just to immediately drop
            // it (a hazard-collision tombstone for a path this device has
            // no genuine content at settles without upserting anything —
            // see `materialize`'s tombstone branch) left the scaffold
            // behind with a NULL `authoring_change_hash`: the next record
            // for this same path took the `Some(local)` branch above
            // instead of this never-seen branch, and `get_authoring_
            // change_hash` returning `Ok(None)` for that column turned into
            // `PeerSessionError::CorruptState` at its `ok_or_else` a few lines up.
            if !incoming.deleted {
                apply_incoming_wire_metadata(
                    self.state.as_ref(),
                    group_id,
                    &incoming,
                    &meta,
                    &root_commit_permit,
                )?;
            }
            // We've never seen this path: adopt it outright (`materialize`
            // now handles a tombstone-for-a-file-we-never-had correctly
            // too — — recording the row without ever touching
            // a file that was never on disk here in the first place).
            let outcome = self
                .materialize(group_id, &incoming, policy, &incoming_origin, Some(incoming_author))
                .await?;
            // Full mesh: this device's *other* peers need to learn about
            // this file too, not just the one that sent it (see
            // `forward_tx`'s doc comment). Forwarded regardless of
            // `outcome`: even a not-yet-settled record's identity is worth
            // this device's other peers learning about, and `materialize`
            // itself is what actually gates whatever content lands where.
            self.forward(group_id, &incoming);
            return Ok(match outcome {
                MaterializeResult::Settled => LockedRecordOutcome::Settled,
                MaterializeResult::RetryRequired => LockedRecordOutcome::RetryRequired,
            });
        };

        let local_author =
            self.state.get_authoring_change_hash(group_id, &local.path)?.ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "current row {group_id}/{} has no authoring change identity",
                    local.path
                ))
            })?;
        let ordering = self
            .state
            .dag_compare_authoring(group_id, &local_author, incoming_author)?
            .ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "current or incoming row {group_id}/{} references an unverified authoring change",
                    local.path
                ))
            })?;

        match ordering {
            ChangeOrdering::Equal => {
                if !same_record_content(&local, &incoming) {
                    return Err(PeerSessionError::CorruptState(format!(
                        "authoring change identity maps to different content for {group_id}/{}",
                        local.path
                    )));
                }
                // `same_record_content` only proves content (deleted/
                // size/mtime/blocks) matches -- an independent review's
                // finding, the same gap `authoring_proves_redundant`'s
                // own `Equal` branch had (see that function's doc
                // comment): this device's own `record_kind`/
                // `symlink_target`/`exec_bit` can still have diverged
                // from what the identical authoring change actually
                // specifies (an interrupted materialization, or manual
                // local drift), and reaching this branch at all means
                // that OTHER fix already decided this record needs a
                // real look, not a skip -- so this is the one place
                // left that must actually repair the divergence, not
                // just detect it and fall through to a no-op.
                if !incoming.deleted {
                    let local_kind =
                        self.state.get_record_kind(group_id, &local.path)?.unwrap_or_default();
                    let local_symlink_target =
                        self.state.get_symlink_target(group_id, &local.path)?;
                    let local_exec_bit = self.state.get_exec_bit(group_id, &local.path)?;
                    let metadata_diverged = local_kind != meta.record_kind
                        || local_symlink_target != meta.symlink_target
                        || local_exec_bit != meta.exec_bit;
                    if metadata_diverged {
                        apply_incoming_wire_metadata(
                            self.state.as_ref(),
                            group_id,
                            &local,
                            &meta,
                            &root_commit_permit,
                        )?;
                        match meta.record_kind {
                            RecordKind::File => {
                                let root = self.sync_root(group_id)?;
                                let out_path = root.join(&local.path);
                                self.verify_write_target(group_id, &out_path)?;
                                apply_exec_bit(&out_path, meta.exec_bit)?;
                            }
                            RecordKind::Symlink => {
                                let windows_opt_in =
                                    self.state.windows_symlink_opt_in_for_group(group_id)?;
                                materialize_symlink_at(
                                    SymlinkMaterialization {
                                        state: self.state.as_ref(),
                                        root: &self.sync_root(group_id)?,
                                        group_id,
                                        windows_opt_in,
                                        origin_device_id: &incoming_origin,
                                        authoring_change_hash: Some(incoming_author),
                                        permit: &root_commit_permit,
                                    },
                                    &local,
                                )?;
                            }
                            // Nothing physical to reapply for a
                            // directory beyond the index columns
                            // `apply_incoming_wire_metadata` above
                            // already fixed.
                            RecordKind::Directory => {}
                        }
                    }
                }
                if self.eager_live_record_needs_rehydrate(group_id, &local, policy)? {
                    // `_locked`: this branch's only caller
                    // (`rematerialize_one_record`) already holds
                    // `path_lock` for `local.path` -- see
                    // `hydrate_file_with_timeout_locked`'s own doc
                    // comment for why the lock-acquiring public wrapper
                    // would deadlock here.
                    self.hydrate_file_with_timeout_locked(
                        group_id,
                        &local.path,
                        DEFAULT_HYDRATION_TIMEOUT,
                    )
                    .await?;
                }
                Ok(LockedRecordOutcome::Settled)
            }
            ChangeOrdering::After => {
                if self.eager_live_record_needs_rehydrate(group_id, &local, policy)? {
                    // `_locked`: this branch's only caller
                    // (`rematerialize_one_record`) already holds
                    // `path_lock` for `local.path` -- see
                    // `hydrate_file_with_timeout_locked`'s own doc
                    // comment for why the lock-acquiring public wrapper
                    // would deadlock here.
                    self.hydrate_file_with_timeout_locked(
                        group_id,
                        &local.path,
                        DEFAULT_HYDRATION_TIMEOUT,
                    )
                    .await?;
                }
                Ok(LockedRecordOutcome::Settled)
            }
            ChangeOrdering::Before => {
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
                // never-seen branch above — must land before `materialize`,
                // and is skipped for a tombstone for the same reason (see
                // that branch's comment): applying kind/target/exec-bit
                // metadata onto the still-existing row moments before a
                // hazard-hold decision would leave a "mixed" row behind —
                // old content and authoring, but the incoming tombstone's
                // pre-delete metadata — if `materialize` decides to hold
                // rather than delete.
                if !incoming.deleted {
                    apply_incoming_wire_metadata(
                        self.state.as_ref(),
                        group_id,
                        &incoming,
                        &meta,
                        &root_commit_permit,
                    )?;
                }
                let outcome = self
                    .materialize(
                        group_id,
                        &incoming,
                        policy,
                        &incoming_origin,
                        Some(incoming_author),
                    )
                    .await?;
                self.forward(group_id, &incoming);
                Ok(match outcome {
                    MaterializeResult::Settled => LockedRecordOutcome::Settled,
                    MaterializeResult::RetryRequired => LockedRecordOutcome::RetryRequired,
                })
            }
            ChangeOrdering::Concurrent => Ok(LockedRecordOutcome::Concurrent { local }),
        }
    }

    /// The materialization-audit driver. Each record is re-driven through
    /// `rematerialize_one_record` (materialize-only, no conflict resolver). Used by
    /// `reconcile_local_materialization_audit` to repair missing on-disk
    /// materializations for records this device already holds without changing
    /// DAG conflict state.
    pub async fn rematerialize_local_records(
        self: Arc<Self>,
        group_id: &str,
        incoming: Vec<(FileRecord, IncomingWireMeta)>,
    ) -> Result<(), PeerSessionError> {
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
        // inside `reconcile_one_file`. `authoring_proves_redundant` then
        // decides, from that single batched snapshot, which records are
        // provably already in sync and can be skipped outright — turning
        // the common "an audit batch is mostly already-synced records" case
        // from O(records) store round-trips
        // into one, while every record that might actually need adopting
        // or conflict-resolving still goes through the exact same
        // correctly-locked `reconcile_one_file` path as before (see that
        // function's and `authoring_proves_redundant`'s doc comments for why the
        // batched snapshot can only ever cause a *safe* skip, never an
        // incorrect one).
        let mut retained: Vec<(FileRecord, IncomingWireMeta)> = Vec::with_capacity(incoming.len());
        for (incoming_record, incoming_meta) in incoming {
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
            let causally_redundant = match prefetched.get(&incoming_record.path) {
                Some(local) => self.authoring_proves_redundant(
                    group_id,
                    local,
                    &incoming_record,
                    &incoming_meta,
                )?,
                None => false,
            };
            let needs_repair_backstop = match prefetched.get(&incoming_record.path) {
                Some(local) if causally_redundant => {
                    self.eager_live_record_needs_rehydrate(group_id, local, policy)?
                }
                _ => false,
            };
            if !needs_repair_backstop && causally_redundant {
                continue;
            }

            if in_flight_count >= MAX_CONCURRENT_RECONCILES && in_flight.next().await.is_some() {
                in_flight_count -= 1;
            }

            let this = self.clone();
            let group_id = group_id.to_string();
            in_flight.push(tokio::spawn(async move {
                // A
                // transient error here — historically a `SyncState` write
                // hitting `SQLITE_BUSY`/`DatabaseLocked` under real
                // concurrent load (this reconcile loop's own
                // `MAX_CONCURRENT_RECONCILES` in-flight tasks, the local
                // debounce executor, and the periodic materialization-
                // repair task all contending for the same device's
                // connection pool) even past `retry_on_database_locked`'s
                // bounded retries; `SyncState`'s writer gate has since made
                // that own-process shape structurally impossible, but the
                // retry stays for every other transient failure here
                // (block fetch over a flapping transport, filesystem I/O).
                // Such a failure used to
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
    ) -> Result<(), PeerSessionError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity = activity_provider.begin_block_write_activity();
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
            // Not silently folded into `Ok(())` as `Settled` was before:
            // this audit's own re-candidacy for `path` next tick is driven
            // by `SyncState::list_materialization_repair_candidates`'s own
            // `materialization_state` column, not by this return value, so
            // a genuinely-still-placeholder path is naturally re-picked-up
            // regardless -- but logging this as an unqualified success
            // would have made a real, still-unresolved repair attempt
            // indistinguishable from one that actually completed.
            LockedRecordOutcome::RetryRequired => {
                tracing::debug!(
                    group_id,
                    peer = %self.peer_device_id,
                    "materialization audit re-drive did not settle this record this attempt; \
                     it stays a repair candidate for the next audit tick"
                );
                Ok(())
            }
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
    ) -> Result<Option<String>, PeerSessionError> {
        hazard_reason_for_policy(
            self.state.as_ref(),
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
        authoring_change_hash: Option<&ChangeHash>,
    ) -> Result<(), PeerSessionError> {
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        hold_record(
            self.state.as_ref(),
            group_id,
            record,
            reason,
            origin_device_id,
            authoring_change_hash,
            &permit,
        )
    }

    /// `origin_device_id` is the local device id for a local record being
    /// re-materialized
    /// (`resolve_and_apply_conflict`'s `local_record` side of a conflict)
    /// or the sending peer's device id for a genuinely adopted remote
    /// version — always supplied by the caller (`reconcile_one_file`/
    /// `resolve_and_apply_conflict`), never inferred here, matching the
    /// principle of "recorded directly at write time rather than inferred
    /// from a version-vector diff".
    fn persist_materialized_record(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
    ) -> Result<(), PeerSessionError> {
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        match authoring_change_hash {
            Some(hash) => self.state.upsert_file_with_origin_and_author(
                group_id,
                record,
                origin_device_id,
                hash,
                &permit,
            ),
            None => self.state.upsert_file_with_origin(group_id, record, origin_device_id, &permit),
        }
    }

    pub async fn materialize(
        &self,
        group_id: &str,
        record: &FileRecord,
        policy: MaterializationPolicy,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        crate::dst_trace(&record.path, || {
            format!(
                "materialize on {}: deleted={} blocks={} origin={origin_device_id}",
                self.local_device_id,
                record.deleted,
                record.blocks.len()
            )
        });
        // Peer input is never authority to adopt a folder. The watcher/link
        // path may adopt during explicit startup, but every peer-driven disk
        // mutation must prove that the already-adopted marker/token pair still
        // matches before it removes, creates, truncates, or renames anything.
        let sync_root = self.sync_root(group_id)?;
        self.state.verify_root(&sync_root, group_id)?;
        // Defense-in-depth: `dag_store::admit_change` already rejects any
        // change naming a versioned reserved-namespace artefact before it
        // is admitted (`apply_locked_record`'s only proof of `record`'s
        // provenance is that its authoring change is present, which says
        // nothing about when that change was admitted — a change written
        // before this check existed, or one that reached the index through
        // some other future path, must not get a second chance to reach
        // disk here). No caller of this function may materialize an
        // artefact component no matter how `record.path` got here.
        //
        // Deliberately `path_has_artefact_component_in_wire_path`, NOT the
        // host-`Path` form `path_has_artefact_component`: `record.path` is
        // peer-authored, not walked off this device's own disk, so
        // resolving it through this process's own `std::path::Path` would
        // make this check depend on which OS is running it — see that
        // function's doc comment. Also NOT the broader exclusion
        // predicate: a legacy `.yadorilink-tmp.`-marked path can be a
        // genuine user file (the marker is a substring match, and
        // `materialization::cleanup_stale_temp_files` already refuses to
        // delete exactly such a look-alike) or an already-admitted change
        // from before this module existed — either way it must still
        // materialize, matching admission's own choice of predicate. See
        // `reserved_namespace`'s "Two predicates, not one".
        //
        // ALSO rejects `sync_root_lock::wire_path_names_sync_root_lock`, for
        // the identical wire-vs-host reason and the identical defense-in-
        // depth rationale as the artefact check above — `dag_store::
        // admit_change`'s `validate_no_reserved_paths` already rejects this
        // at admission, but a change admitted before that check existed (or
        // through a future path that skips it) must not get a second chance
        // to reach disk here. Without this, a peer materializing
        // `.yadorilink-root.lock` replaces the on-disk lock file out from
        // under this device's own live OS lock (held on the now-unlinked
        // inode on Unix), and a second daemon then locks the fresh file
        // materialization just created at the same path — two processes each
        // believing they exclusively own this sync root, exactly the state
        // `sync_root_lock` exists to make unreachable.
        if yadorilink_root_authority::reserved_namespace::path_has_artefact_component_in_wire_path(
            &record.path,
        ) || yadorilink_root_authority::sync_root_lock::wire_path_names_sync_root_lock(
            &record.path,
        ) {
            return Err(PeerSessionError::ReservedNamespaceCollision(record.path.clone()));
        }
        // Same defense-in-depth reasoning as the reserved-artefact/lock
        // check above, for a different hazard: `record.path` may name a
        // path that cannot be faithfully stored on a Windows device at all
        // (a trailing '.'/' ' component — see
        // `path_has_non_portable_wire_component`'s doc comment).
        // `dag_store::admit_change` already refuses this at admission, but
        // a record whose authoring change was admitted before this check
        // existed (or reached the index through some other future path)
        // must not get a second chance to reach disk here — writing it
        // would let this path silently alias a different on-disk name than
        // the one this device's own index believes it just materialized.
        if yadorilink_root_authority::reserved_namespace::path_has_non_portable_wire_component(
            &record.path,
        ) {
            return Err(PeerSessionError::NonPortablePath(record.path.clone()));
        }
        // Computed once, ahead of every
        // dispatch branch below (symlink, metadata-only fast path, eager
        // fetch, placeholder, AND the tombstone branch immediately below) —
        // a hazard must short-circuit before *any* of those reach their own
        // atomic temp-write step or physical delete, not just the
        // ordinary-file ones. See `hazard_reason_for`'s doc comment.
        // `hazard_reason_for_policy` compares `record.path` against
        // siblings regardless of `record.deleted`, so this is meaningful
        // for a tombstone too: a case-fold/Unicode-normalization collision
        // makes it genuinely ambiguous which physical file a delete for
        // this logical path would remove, and a delete is less reversible
        // than a wrong write (no peer re-send recovers deleted bytes), so
        // it needs the same guard, not an exemption.
        let hazard_reason = self.hazard_reason_for(group_id, record)?;

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
            // A hazardous tombstone must NOT go through the ordinary
            // `hold` path used below for non-delete records: `hold_record`
            // upserts the INCOMING record as-is, and for a tombstone that
            // means writing `deleted=true` over whatever row already
            // exists at `record.path` -- while `remove_file` is
            // deliberately never called, so any content already on disk
            // there is untouched. That is exactly the "index says
            // deleted, disk still has the file" divergence this same
            // branch's own comment above already identifies as dangerous
            // (a later scan reads it as a brand-new local edit and
            // resurrects + re-propagates it) -- for a held CREATE this
            // divergence is intentional and accounted for (disk keeps
            // whatever it had, index tracks the latest known-but-unwritten
            // metadata), but for a held DELETE it recreates the exact
            // hazard the ordering comment above was written to prevent.
            // So: only mark the existing row held, in place, without
            // adopting the incoming tombstone's fields. If there is no
            // GENUINE content row for this path, there is nothing on disk
            // to diverge from and the tombstone is simply dropped.
            //
            // "Genuine" is `has_real_current_row`, not `get_file(...)
            // .is_some()`: `apply_locked_record`'s caller no longer
            // bootstraps a metadata scaffold for a tombstone record (a
            // tombstone has no kind/target/exec-bit to materialize), but a
            // scaffold can still exist here from an earlier, unrelated
            // record at the same path (e.g. a held CREATE's own bootstrap),
            // so this check stays defense-in-depth rather than relying on
            // that invariant alone.
            //
            // A dropped tombstone reports `Settled` or `RetryRequired`
            // depending on WHY there was no genuine row to hold, not
            // uniformly: an already-deleted genuine row (the redelivery
            // case just below) means this exact deletion already converged
            // -- nothing is pending, so `Settled` is correct and reporting
            // `RetryRequired` would just churn forever on a redundant
            // resend. Every other case -- a genuine LIVE row moved to
            // `held`, or a scaffold/no row at all -- means the deletion has
            // NOT converged anywhere yet, so a caller must not treat this
            // path as resolved for this attempt.
            //
            // The held-live-row case looks superficially like "a hazard
            // correctly moved the record to hold", which `MaterializeResult`'s
            // own doc comment reserves for `Settled`. It is not: `set_held`
            // only stamps `held_reason`/`held_since_unix_nanos` onto the
            // EXISTING (still-live) row -- it records neither the pending
            // tombstone's authoring identity nor that a deletion is even
            // pending, so nothing downstream can tell "this path is
            // durably resolved" from "this path has a live file that
            // happens to carry a hold reason". Reporting `Settled` here
            // fed straight into `reconcile_group_paths`'s `Absent` branch,
            // whose caller (`reproject_unapplied_changes`) marks the
            // tombstone's own DAG change permanently `applied` the moment
            // its path is seen `settled` -- which stops that change from
            // ever being re-examined by this crate's only periodic
            // convergence sweep (`dag_list_unapplied_changes`), even though
            // nothing was actually deleted. `RetryRequired` keeps the
            // change `applied = 0`, so the periodic audit keeps retrying
            // this exact path (cheap: just this hazard check plus a
            // `set_held` UPDATE) until the collision genuinely clears --
            // no dependency on the original sending peer still being
            // connected, or on any peer resending at all.
            if let Some(reason) = &hazard_reason {
                let has_real_row = self.state.has_real_current_row(group_id, &record.path)?;
                let existing = self.state.get_file(group_id, &record.path)?;
                match existing {
                    Some(row) if has_real_row && !row.deleted => {
                        // `RetryRequired` (below) means the periodic
                        // materialization audit re-enters this exact
                        // branch on every tick while the collision
                        // persists (see this `if let Some(reason)`
                        // block's own doc comment) -- calling `set_held`
                        // unconditionally on every one of those re-drives
                        // would stamp a fresh `now_unix_nanos()` each
                        // time, so a path held for hours would always
                        // read as "held since a moment ago". Only stamp
                        // when the reason actually changes (a first hold,
                        // or the collision shifted to a different sibling)
                        // so `held_since_unix_nanos` reflects when THIS
                        // hold reason first applied, not when it was last
                        // re-confirmed.
                        let already_held = self
                            .state
                            .get_held_state(group_id, &record.path)?
                            .is_some_and(|held| held.reason == *reason);
                        if !already_held {
                            self.state.set_held(
                                group_id,
                                &record.path,
                                reason,
                                now_unix_nanos(),
                            )?;
                        }
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    // Already a genuine tombstone, not a scaffold: holding
                    // it would be the "orphaned held entry on a
                    // tombstoned path" state `clear_held`'s own doc
                    // comment says this crate deliberately avoids --
                    // reachable if this exact tombstone already landed
                    // once (clearing any prior hold) and a peer's
                    // periodic resend redelivers it after a fresh
                    // collision appears.
                    //
                    // "Already converged" only holds if the row's
                    // authoring identity actually matches this exact
                    // incoming tombstone. Defense-in-depth, not a live
                    // production fix: `apply_locked_record`'s
                    // `ChangeOrdering::Before` branch is this sub-case's
                    // only conceivable caller, and its only current
                    // caller (`rematerialize_one_record`, the
                    // materialization audit) already filters out every
                    // `deleted` record before this could ever run --
                    // `reconcile_local_materialization_audit`'s own
                    // `if record.deleted { continue; }` plus its
                    // `list_materialization_repair_candidates` query's
                    // `AND f.deleted = 0` -- so this branch is unreachable
                    // by any caller in this codebase today. Kept correct
                    // anyway for a future caller (a strictly newer
                    // descendant tombstone -- e.g. a later device
                    // re-tombstones an already-deleted path, minting a new
                    // change on top of the one this row was last stamped
                    // with) that reaches it without the same filtering:
                    // fast-pathing to `Settled` without updating
                    // `authoring_change_hash` would leave the row's
                    // authoring identity stuck at the OLD tombstone
                    // forever, with every future `dag_compare_authoring`
                    // call against it re-entering this same branch. NOTE:
                    // this write trusts its caller for causal ordering --
                    // it does not itself verify the supplied hash is
                    // newer, only that it differs, so any FUTURE caller of
                    // this branch must guarantee ordering the same way
                    // `ChangeOrdering::Before` does before ever reaching
                    // here. Advancing the column is otherwise safe: it
                    // only touches the index column, never disk or
                    // `deleted`, so it carries none of the "index says
                    // deleted, disk has content" risk this whole branch
                    // exists to avoid.
                    Some(row) if has_real_row && row.deleted => {
                        if let Some(hash) = authoring_change_hash {
                            let current =
                                self.state.get_authoring_change_hash(group_id, &record.path)?;
                            if current.as_ref() != Some(hash) {
                                self.state.set_authoring_change_hash(
                                    group_id,
                                    &record.path,
                                    hash,
                                )?;
                            }
                        }
                        return Ok(MaterializeResult::Settled);
                    }
                    _ => return Ok(MaterializeResult::RetryRequired),
                }
            }
            let out_path = self.local_file_path(group_id, &record.path)?;
            // Same defense-in-depth as every write branch's
            // `verify_write_target` call: an intermediate directory symlink
            // can redirect this lexically-safe (`..`-free,
            // non-absolute) path outside `group_id`'s sync root, and
            // `remove_file` follows that symlink chain exactly as
            // `create`/`rename` do. See `verify_delete_target`'s doc
            // comment.
            self.verify_delete_target(group_id, &out_path)?;
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
                Err(e) => return Err(PeerSessionError::from(e)),
            }
            // A held file that's later
            // tombstoned must not leave an orphaned held entry once its
            // index row no longer represents a live, on-disk file —
            // `clear_held` is documented as a safe no-op when the path
            // was never held, so this is safe to call unconditionally.
            self.state.clear_held(group_id, &record.path)?;
            self.persist_materialized_record(
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
            )?;
            return Ok(MaterializeResult::Settled);
        }

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
                self.hold(group_id, record, reason, origin_device_id, authoring_change_hash)?;
                return Ok(MaterializeResult::Settled);
            }
            // A path that's no longer hazardous (e.g. a previously
            // colliding sibling was itself renamed/removed since the last
            // time this path was reconciled) must not keep a stale held
            // entry once it actually materializes normally again.
            self.state.clear_held(group_id, &record.path)?;
            let windows_opt_in = self.state.windows_symlink_opt_in_for_group(group_id)?;
            materialize_symlink_at(
                SymlinkMaterialization {
                    state: self.state.as_ref(),
                    root: &self.sync_root(group_id)?,
                    group_id,
                    windows_opt_in,
                    origin_device_id,
                    authoring_change_hash,
                    permit: &root_commit_permit,
                },
                record,
            )?;
            return Ok(MaterializeResult::Settled);
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
                self.state.as_ref(),
                &self.sync_root(group_id)?,
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
                &root_commit_permit,
            )?
        {
            self.state.clear_held(group_id, &record.path)?;
            return Ok(MaterializeResult::Settled);
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
            // Snapshot the on-disk state of this path *before* the
            // potentially-slow block fetch below, so it can be re-checked
            // right before this materialize actually writes anything (see
            // that re-check's own comment for why: `path_lock` is held for
            // this whole call, but it only serializes *this device's own*
            // SyncState-mediated writes -- it is not, and cannot be, an OS
            // file lock, so a genuine local edit (a real user's editor, or
            // this scenario's `solo-write`) can still land directly on disk
            // while `ensure_blocks_present` awaits a peer's `BlockResponse`.
            // Confirmed, reproduced: a local write that races into exactly
            // this window is silently clobbered by this materialize's own
            // later rename, then permanently invisible to every later
            // check -- `flush_pending_local_change_before_reconcile`
            // (already run by every caller before taking `path_lock`) only
            // catches an edit that was *already* pending at that moment; it
            // cannot see one that has not happened yet, and calling it again
            // from inside this locked call would deadlock (see its own doc
            // comment). A cheap metadata snapshot, re-compared once the
            // fetch returns, is the only place left to catch this without
            // restructuring the lock discipline the rest of this function
            // (and its caller) relies on.
            let out_path_for_race_check = self.local_file_path(group_id, &record.path)?;
            let pre_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
            // The second fork: by the time an incoming change is about to be
            // written, are this device's own local bytes still on disk? If a
            // local write is lost despite the flush guard running, the length
            // here says whether the guard looked too late (bytes already
            // replaced) or the guard looked in the wrong place (bytes still
            // present and about to be overwritten by this call).
            crate::dst_trace(&record.path, || {
                format!(
                    "materialize about to write on {} (origin={}): on_disk_len={:?} incoming_len={}",
                    self.local_device_id,
                    origin_device_id,
                    pre_fetch_disk_state.as_ref().map(|(len, ..)| *len),
                    record.size
                )
            });
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
            // `DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`'s doc comment for why 90s
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
            .map_err(|_elapsed| PeerSessionError::HydrationFailed(record.path.clone()))??;
            // The block fetch above always
            // runs, hazardous or not — this device may be another peer's
            // only currently-reachable source for these blocks even
            // though it can't write them to disk under this name itself
            // ("blocks still requested/served to peers"). Only
            // the write step below is skipped for a held record.
            if let Some(reason) = &hazard_reason {
                self.hold(group_id, record, reason, origin_device_id, authoring_change_hash)?;
                return Ok(MaterializeResult::Settled);
            }
            // Re-check the snapshot taken before the fetch above: if this
            // path's on-disk state changed while this call awaited the
            // peer, something else wrote to it independently of this
            // materialize -- almost certainly this device's own local
            // watcher/debounce pipeline, still queued behind `path_lock`
            // and unable to run until this call returns. Proceeding would
            // silently overwrite that write with no error, no conflict
            // copy, and (once the watcher's own flush eventually runs
            // against the post-overwrite bytes, which now match exactly
            // what this materialize is about to commit) no trace at all —
            // the confirmed mechanism behind a materialize-vs-local-edit
            // race this check exists to close. Decline instead: `Retry
            // Required` sends this back through the ordinary reconcile
            // retry path, by which point `path_lock` has been released,
            // the queued local write has committed its own change, and
            // the next resolution correctly sees both as concurrent.
            let post_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
            if post_fetch_disk_state != pre_fetch_disk_state {
                tracing::info!(
                    group_id,
                    path = %record.path,
                    "declining a materialize whose target changed on disk while this device \
                     fetched blocks from a peer; leaving it for retry so the racing local edit \
                     is not silently overwritten"
                );
                return Ok(MaterializeResult::RetryRequired);
            }
            // LAST LINE OF DEFENCE BEFORE THE BYTES ARE GONE.
            //
            // Everything upstream of here tries to get a local edit
            // *authored* before an incoming change lands on the same path:
            // `flush_pending_local_change_before_reconcile` force-flushes the
            // debounce accumulator, `capture_undiscovered_local_change` falls
            // back to reading the path off disk, and the metadata CAS above
            // catches a write that slips in during the block fetch. Each is
            // scheduling-dependent, and measurably none of them closes the
            // case where the write lands on disk *before* this materialize
            // started and its watcher event has not been processed yet.
            //
            // This check is not scheduling-dependent: it asks the bytes
            // themselves. If the file on disk no longer matches the content
            // this device has indexed for it, someone wrote to it outside the
            // index -- an unauthored local edit -- and overwriting it destroys
            // it permanently. Permanently is not hyperbole: after the rename
            // the edit exists nowhere (not on disk, not in the block store),
            // and the watcher's own flush then chunks the *remote* bytes,
            // finds them equal to what was just indexed, and suppresses the
            // whole thing as a self-echo (`local_change.rs`'s block-equality
            // check). No error, no conflict copy, no trace. That is why no
            // fix on the flush side can work -- there is nothing left to
            // recover by then.
            //
            // Compare against `local_row` (what this device believes is on
            // disk right now), NOT `record` (the incoming content this call
            // is about to install).
            //
            // Reproduced and traced on `dst_network_fault_chaos` seed
            // 3298840609: a solo write landed while the previous round's race
            // winner was still materialising over it, was overwritten before
            // it could author, and left the harness reading back the previous
            // round's authoring hash -- two ops sharing one hash, which
            // `oracle::supersedes` refuses to treat as superseding, surfacing
            // as `[NoLoss]`.
            //
            // Cost: one content hash of the destination, and only for a path
            // that already exists as a `Hydrated` regular file. Skipped for
            // `Placeholder`/`Hydrating`/`Evicting` rows, whose whole point is
            // to disagree with their file, and for tombstones. Deliberately
            // paid: the alternative is silently destroying user data.
            //
            // A narrow TOCTOU window remains between this hash and the rename
            // below -- there is no portable "rename only if the destination
            // still hashes to X". The metadata CAS above is kept precisely as
            // a second, cheaper net across that window. Closing it fully
            // would mean preserving the displaced bytes before replacing them
            // (quarantine-on-divergence), which changes conflict semantics
            // and needs its own crash-recovery design; noted, not attempted.
            //
            // A path that no longer exists at all is NOT the same finding as
            // one whose bytes diverge, and must not be declined the same
            // way. A missing `out_path_for_race_check` is not proof anyone
            // wrote an unauthored edit -- it is equally consistent with this
            // path's *parent* having been renamed or removed by a local
            // operation whose watcher event has not reached this device's
            // local pipeline yet (confirmed, reproduced:
            // `dst_directory_move_edit_race.rs`'s `CbBeforeDirDispatch`
            // ordering hung forever on exactly this call site treating
            // `Absent` the same as `PresentButDifferent`, permanently
            // declining a legitimate fast-forward materialize with nothing
            // left to ever change the outcome). Declining forever on an
            // absent path is safe to avoid here specifically because
            // `flush_pending_local_change_before_reconcile` (called on
            // `record.path` above, before `path_lock` was even taken) has
            // already force-flushed any debounce entry keyed on this exact
            // path -- so a genuine, still-unflushed single-file local
            // deletion of THIS path cannot be what produced the absence; the
            // only thing an exact-path flush structurally cannot discover
            // and dispatch first is an ancestor-directory-level event, which
            // is exactly the case this guard must let through. Resurrecting
            // a file whose deletion truly wasn't caught by any of that is
            // still recoverable, unlike destroying divergent bytes: the
            // local pipeline's own Removed-event handling re-stats before
            // dispatch and will still author the deletion once it runs.
            let locally_hydrated = matches!(
                self.state.get_materialization_state(group_id, &record.path),
                Ok(Some(MaterializationState::Hydrated))
            );
            if locally_hydrated {
                if let Some(local_row) = self.state.get_file(group_id, &record.path)? {
                    if !local_row.deleted && !local_row.blocks.is_empty() {
                        if let yadorilink_local_storage::DiskContentComparison::PresentButDifferent =
                            yadorilink_local_storage::disk_content_comparison(
                                &out_path_for_race_check,
                                &local_row.blocks,
                            )?
                        {
                            tracing::info!(
                                group_id,
                                path = %record.path,
                                "declining a materialize whose target no longer matches this \
                                 device's indexed content; an unauthored local edit is on disk \
                                 and overwriting it would destroy it silently"
                            );
                            crate::dst_trace(&record.path, || {
                                format!(
                                    "materialize DECLINED on {}: on-disk bytes diverge from \
                                     indexed content -- unauthored local edit protected",
                                    self.local_device_id
                                )
                            });
                            return Ok(MaterializeResult::RetryRequired);
                        }
                    }
                }
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
                self.persist_materialized_record(
                    group_id,
                    record,
                    origin_device_id,
                    authoring_change_hash,
                )?;
                self.state.clear_held(group_id, &record.path)?;
                self.state.set_materialization_state(
                    group_id,
                    &record.path,
                    MaterializationState::Placeholder,
                    &root_commit_permit,
                )?;
                let out_path = self.local_file_path(group_id, &record.path)?;
                self.verify_write_target(group_id, &out_path)?;
                match create_or_defer_placeholder(&out_path, record.size, record.mtime_unix_nanos)?
                {
                    PlaceholderIdentityToRecord::Record { identity, provider_kind } => {
                        self.state.record_placeholder_generation(
                            group_id,
                            &record.path,
                            identity,
                            provider_kind,
                            &root_commit_permit,
                        )?
                    }
                    PlaceholderIdentityToRecord::Clear => self.state.clear_placeholder_generation(
                        group_id,
                        &record.path,
                        &root_commit_permit,
                    )?,
                }
                apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)?;
                // Eager/pinned wanted real content but not every block was
                // available -- this is a retriable Placeholder, not a
                // settled outcome (the confirmed bug this type exists to
                // close: see `MaterializeResult`'s own doc comment).
                return Ok(MaterializeResult::RetryRequired);
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
            let intent_target_hash = yadorilink_local_storage::intent_target_hash(&record.blocks);
            let intent_guard = self.state.open_materialization_intent_guard(
                group_id,
                &record.path,
                &intent_target_hash,
                &root_commit_permit,
            )?;
            self.persist_materialized_record(
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
            )?;
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
            let mut recon = reconstruct_file(
                self.store.as_ref(),
                &out_path,
                &record.blocks,
                record.mtime_unix_nanos,
            );
            let mut attempts = 0u32;
            while recon.is_err() && attempts < MAX_RECONSTRUCT_RETRIES {
                attempts += 1;
                // Short backoff before re-reading the already-present blocks.
                // Under the deterministic simulator this advances virtual time
                // (letting any interfering condition clear) at no real cost.
                tokio::time::sleep(RECONSTRUCT_RETRY_BACKOFF).await;
                // Re-verify root identity before EVERY retry, not just the
                // single check before the first attempt above: up to
                // `MAX_RECONSTRUCT_RETRIES * RECONSTRUCT_RETRY_BACKOFF`
                // (~1s) elapses across this loop, during which the same
                // unmount-and-replace window `verify_write_target`'s own
                // re-check exists to close could still open between two
                // retries. A verify failure here surfaces as a real error
                // (not a demotion to `Placeholder`) since a replaced root
                // is not a transient, retriable condition.
                self.verify_write_target(group_id, &out_path)?;
                recon = reconstruct_file(
                    self.store.as_ref(),
                    &out_path,
                    &record.blocks,
                    record.mtime_unix_nanos,
                );
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
                    &root_commit_permit,
                )?;
                // A `Placeholder` is not an in-progress write — clear the intent
                // now (mirrors repair's placeholder arms). Cleared before the
                // placeholder disk write below so that even a failure writing
                // the placeholder cannot leave a stale intent: the row is already
                // `Placeholder`, which repair skips, and a later offline delete
                // of this path must not be misread as a crash to reconstruct.
                intent_guard.clear()?;
                self.verify_write_target(group_id, &out_path)?;
                match create_or_defer_placeholder(&out_path, record.size, record.mtime_unix_nanos)?
                {
                    PlaceholderIdentityToRecord::Record { identity, provider_kind } => {
                        self.state.record_placeholder_generation(
                            group_id,
                            &record.path,
                            identity,
                            provider_kind,
                            &root_commit_permit,
                        )?
                    }
                    PlaceholderIdentityToRecord::Clear => self.state.clear_placeholder_generation(
                        group_id,
                        &record.path,
                        &root_commit_permit,
                    )?,
                }
                apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)?;
                // Reconstruct never actually succeeded despite the blocks
                // being fetched -- demoted to a retriable Placeholder, not
                // a settled outcome (same reasoning as the `!all_present`
                // branch above).
                return Ok(MaterializeResult::RetryRequired);
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
            apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)?;
            Ok(MaterializeResult::Settled)
        } else {
            // OnDemand/not-pinned is the
            // placeholder path — but a placeholder is still a real
            // on-disk artifact created *under this path's exact name*, so
            // a hazardous record must not get one either (held
            // means no on-disk artifact under this name at all, full
            // content or placeholder alike; never any alternate name).
            if let Some(reason) = &hazard_reason {
                self.hold(group_id, record, reason, origin_device_id, authoring_change_hash)?;
                return Ok(MaterializeResult::Settled);
            }
            // OnDemand and not pinned: no block fetch at all — the whole
            // point of a placeholder is deferring that until access.
            self.persist_materialized_record(
                group_id,
                record,
                origin_device_id,
                authoring_change_hash,
            )?;
            self.state.clear_held(group_id, &record.path)?;
            self.state.set_materialization_state(
                group_id,
                &record.path,
                MaterializationState::Placeholder,
                &root_commit_permit,
            )?;
            let out_path = self.local_file_path(group_id, &record.path)?;
            // defense-in-depth — see the comment above.
            self.verify_write_target(group_id, &out_path)?;
            match create_or_defer_placeholder(&out_path, record.size, record.mtime_unix_nanos)? {
                PlaceholderIdentityToRecord::Record { identity, provider_kind } => {
                    self.state.record_placeholder_generation(
                        group_id,
                        &record.path,
                        identity,
                        provider_kind,
                        &root_commit_permit,
                    )?
                }
                PlaceholderIdentityToRecord::Clear => self.state.clear_placeholder_generation(
                    group_id,
                    &record.path,
                    &root_commit_permit,
                )?,
            }
            // A placeholder still gets the recorded exec bit
            // applied now — `hydrate_file_with_timeout` re-applies it
            // again once real content lands, so this is never lost
            // across the placeholder → hydrated transition either. This
            // IS a settled outcome (unlike the eager/pinned placeholder
            // above): on-demand policy deliberately defers content until
            // access, it did not want the blocks now and fail to get
            // them.
            apply_exec_bit(&out_path, self.state.get_exec_bit(group_id, &record.path)?)?;
            Ok(MaterializeResult::Settled)
        }
    }

    pub fn local_file_path(&self, group_id: &str, path: &str) -> Result<PathBuf, PeerSessionError> {
        Ok(self.sync_root(group_id)?.join(path))
    }

    fn eager_live_record_needs_rehydrate(
        &self,
        group_id: &str,
        record: &FileRecord,
        policy: MaterializationPolicy,
    ) -> Result<bool, PeerSessionError> {
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
    fn may_apply_incoming_change(
        &self,
        group_id: &str,
        what: &str,
    ) -> Result<bool, PeerSessionError> {
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
    fn sync_root(&self, group_id: &str) -> Result<PathBuf, PeerSessionError> {
        match self.state.link_gate_for_group(group_id)? {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                Ok(PathBuf::from(local_path))
            }
            LinkGate::NoLiveLink => Err(PeerSessionError::PathEscapesRoot(format!(
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
    ///
    /// Also re-runs `VerifiedRoot::verify` — `materialize`'s own
    /// verification at its own start proves the root's identity BEFORE
    /// any block fetch, but a fetch can run for up to
    /// `DEFAULT_HYDRATION_TIMEOUT` (30s), during which the mountpoint
    /// this device resolved as the sync root can be unmounted and
    /// replaced (a fresh empty directory, or a different volume) without
    /// changing anything a bare `canonicalize`/containment check can see
    /// — a replaced mountpoint's path still resolves and still contains
    /// `out_path` lexically. Since this function already runs immediately
    /// before every physical write in every `materialize`/`hydrate_file_
    /// with_timeout` branch, re-verifying identity here (not just
    /// containment) closes that window at its narrowest point, for both
    /// callers, in one place — cheap enough to run unconditionally: one
    /// canonicalize, one lock, and one marker-file read, not a directory
    /// walk.
    pub fn verify_write_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        // Resolve the root first and fail closed on an unknown group: with the
        // old empty-path default, `out_path` was a bare relative filename whose
        // parent is `""` -- exactly the empty root -- so the fast path below
        // returned Ok and this check passed trivially for the one case it most
        // needed to reject.
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
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
                Ok(verify_write_target_within_canonical_root(out_path, &canonical_root)?)
            }
            None => Ok(verify_write_target_within_root(out_path, raw_root)?),
        }
    }

    /// Delete-side counterpart to `verify_write_target`: the tombstone
    /// branch calls this before `remove_file` for exactly the same reason
    /// every write branch calls `verify_write_target` first — an
    /// intermediate directory symlink can redirect a lexically-safe,
    /// `..`-free `record.path` outside `group_id`'s sync root, and
    /// `remove_file` follows that symlink chain just as `create`/`rename`
    /// do. See `chunker::verify_delete_target_within_root`'s doc comment
    /// for why this never creates directories as a side effect, unlike the
    /// write version. Also re-runs `VerifiedRoot::verify` for the same
    /// reason `verify_write_target` does — see that function's own doc
    /// comment.
    fn verify_delete_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => {
                Ok(verify_delete_target_within_canonical_root(out_path, &canonical_root)?)
            }
            None => Ok(verify_delete_target_within_root(out_path, raw_root)?),
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
    ) -> Result<(), PeerSessionError> {
        if !self.headroom_enforced() {
            return Ok(());
        }
        Ok(check_disk_headroom(
            &self.sync_root(group_id)?,
            target_path,
            additional_bytes,
            self.headroom_override_bytes(),
        )?)
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
        auth: yadorilink_replica_domain::change::ChangeAuth,
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
pub fn change_hash_to_wire(hash: &ChangeHash) -> Vec<u8> {
    hash.0.to_vec()
}

/// Converts a wire `VersionPresentQuery` into `PeerReplicaEngine`'s
/// protobuf-free domain equivalent -- shared by `handle_version_present_query`
/// and this file's own test of `holds_version_durably`, so both go through
/// the exact same conversion the production path uses. Takes the
/// `peer_wire` frame (not the raw wire type directly) now that
/// `handle_version_present_query` itself has no protobuf dependency --
/// `request_id` (present on the frame, absent here, same as before) stays
/// on the session side.
pub fn durable_version_query_from_wire(
    query: &yadorilink_sync_wire::VersionPresentQueryFrame,
) -> yadorilink_replica_engine::DurableVersionQuery {
    yadorilink_replica_engine::DurableVersionQuery {
        folder_group_id: query.folder_group_id.clone(),
        file_path: query.file_path.clone(),
        block_hashes: query.block_hashes.clone(),
        for_handoff: query.for_handoff,
        version_hash: query.version_hash.clone(),
        block_sizes: query.block_sizes.clone(),
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
        blocks,
        deleted: false,
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
    attempt: &ProjectionAttempt,
) -> bool {
    change_paths.iter().all(|p| attempt.path_fully_resolved(p))
}

// `change_touches_path`, `PathHead`, `PathHeadContent`, `ConflictCopy`,
// `PathResolution`, `resolve_path_heads`, and `path_head_from_change` moved to
// `crate::conflict` (see `fix/conflict-copy-convergence-obligation-20260723`):
// they are pure functions of a `Change`/DAG state with no
// `PeerSyncSession`-specific dependency, and `dag_store`'s new conflict-copy
// authoring/validation code (which cannot depend on this module) needs them
// too.

/// Content identity of two index rows used to corroborate equal authoring
/// identity: the deletion flag, size, mtime, and the ordered
/// block hash/size sequence — the same components `FileVersion`'s canonical
/// version hash commits to at this layer. Paths are deliberately not
/// compared (every caller already scopes to a single path); block offsets
/// are a prefix sum of the sizes, so comparing them would be redundant.
fn same_record_content(a: &FileRecord, b: &FileRecord) -> bool {
    a.deleted == b.deleted
        && a.size == b.size
        && a.mtime_unix_nanos == b.mtime_unix_nanos
        && a.blocks.len() == b.blocks.len()
        && a.blocks.iter().zip(&b.blocks).all(|(x, y)| x.hash == y.hash && x.size == y.size)
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
        pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(7, tx);

        {
            let _guard = PendingBlockGuard { pending: &pending, request_id: 7 };
            drop(rx); // simulates the caller's future (and its rx) being dropped by a timeout
        }

        assert!(pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    /// The ordinary, successful path: `handle_block_reply` already removed
    /// the entry before the guard drops — the guard must find nothing
    /// there and not panic or otherwise misbehave.
    #[test]
    fn drop_after_normal_fulfillment_is_a_no_op() {
        let pending = std::sync::Mutex::new(HashMap::new());
        let (tx, _rx) = oneshot::channel::<FetchOutcome>();
        pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(7, tx);

        // Simulates `handle_block_reply`: removes and fulfills.
        let removed = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&7);
        removed.unwrap().send(FetchOutcome::Found(Bytes::from_static(b"data"))).unwrap();

        let _guard = PendingBlockGuard { pending: &pending, request_id: 7 };
        drop(_guard);

        assert!(pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    /// A DIFFERENT request's entry must survive this guard's drop -- each
    /// `request_id` is independent, unlike the old hash-keyed table's
    /// shared waiter list.
    #[test]
    fn drop_never_touches_a_different_requests_entry() {
        let pending = std::sync::Mutex::new(HashMap::new());
        let (tx1, rx1) = oneshot::channel::<FetchOutcome>();
        let (tx2, _rx2) = oneshot::channel::<FetchOutcome>();
        pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(1, tx1);
        pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(2, tx2);
        drop(rx1);

        let guard1 = PendingBlockGuard { pending: &pending, request_id: 1 };
        drop(guard1);

        let pending = pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!pending.contains_key(&1), "the cancelled request's own entry must be removed");
        assert!(pending.contains_key(&2), "an unrelated request's entry must survive");
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
        SymlinkMaterialization,
    };
    use crate::ports::PeerReplicaStatePort;
    use crate::test_support::FakeReplicaState;

    fn symlink_record(path: &str) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        }
    }

    fn file_record_with_block(path: &str, hash_byte: u8) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 5,
            mtime_unix_nanos: 0,
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
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");
        let record = symlink_record("link.txt");
        state.seed_file("group-1", &record);
        state
            .set_record_kind(
                "group-1",
                "link.txt",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state.set_symlink_target("group-1", "link.txt", Some(b"target.txt")).unwrap();

        materialize_symlink_at(
            SymlinkMaterialization {
                state: &state,
                root: root.path(),
                group_id: "group-1",
                windows_opt_in: false,
                origin_device_id: "device-a",
                authoring_change_hash: None,
                permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            },
            &record,
        )
        .unwrap();

        let out_path = root.path().join("link.txt");
        assert!(
            std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
            "must be a real symlink on disk"
        );
        assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
        assert!(!state.get_file("group-1", "link.txt").unwrap().unwrap().deleted);
    }

    /// A free function, not a `PeerSyncSession` method, so it cannot go
    /// through `self.verify_write_target` (which additionally re-verifies
    /// `VerifiedRoot` identity) -- this must re-verify directly instead of
    /// relying only on `verify_write_target_within_root`'s lexical
    /// containment check, which cannot detect a root whose mountpoint has
    /// been replaced.
    #[test]
    fn materialize_symlink_at_refuses_a_root_whose_marker_no_longer_matches() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");
        let record = symlink_record("link.txt");
        state.seed_file("group-1", &record);
        state
            .set_record_kind(
                "group-1",
                "link.txt",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state.set_symlink_target("group-1", "link.txt", Some(b"target.txt")).unwrap();

        std::fs::remove_file(
            root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = materialize_symlink_at(
            SymlinkMaterialization {
                state: &state,
                root: root.path(),
                group_id: "group-1",
                windows_opt_in: false,
                origin_device_id: "device-a",
                authoring_change_hash: None,
                permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            },
            &record,
        );
        assert!(
            result.is_err(),
            "a symlink write under a root whose marker no longer matches must be refused"
        );
        assert!(
            !root.path().join("link.txt").exists(),
            "nothing must be written when root identity fails to verify"
        );
    }

    /// An independent review's finding: `verify_write_target_within_root`
    /// is not a pure check -- it `create_dir_all`s the sync root and the
    /// target's parent directory as a side effect. If `VerifiedRoot::
    /// verify` ran AFTER that call instead of before, a root whose
    /// mountpoint was unmounted and replaced by something else at the
    /// same path would still get a brand-new directory created on it
    /// (for a nested path whose parent doesn't exist yet) before the
    /// identity mismatch was ever detected -- mutating the wrong
    /// filesystem despite the write itself being correctly refused.
    #[test]
    fn materialize_symlink_at_creates_no_directories_under_a_root_whose_marker_no_longer_matches() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");
        let record = symlink_record("sub/nested/link.txt");
        state.seed_file("group-1", &record);
        state
            .set_record_kind(
                "group-1",
                "sub/nested/link.txt",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state.set_symlink_target("group-1", "sub/nested/link.txt", Some(b"target.txt")).unwrap();

        std::fs::remove_file(
            root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = materialize_symlink_at(
            SymlinkMaterialization {
                state: &state,
                root: root.path(),
                group_id: "group-1",
                windows_opt_in: false,
                origin_device_id: "device-a",
                authoring_change_hash: None,
                permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            },
            &record,
        );
        assert!(
            result.is_err(),
            "a symlink write under a root whose marker no longer matches must be refused"
        );
        assert!(
            !root.path().join("sub").exists(),
            "no directory must be created under a root that fails identity verification, even \
             for a nested path whose parent doesn't exist yet"
        );
    }

    /// A symlink record with no recorded target (shouldn't normally
    /// happen, but must be handled defensively) must never create a
    /// broken/empty placeholder on disk — the index row still gets
    /// updated, just nothing is written to the filesystem.
    #[test]
    fn materialize_symlink_at_with_no_target_recorded_skips_disk_write_but_still_indexes() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");
        let record = symlink_record("mystery-link");
        state.seed_file("group-1", &record);
        state
            .set_record_kind(
                "group-1",
                "mystery-link",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // symlink_target deliberately left unset.

        materialize_symlink_at(
            SymlinkMaterialization {
                state: &state,
                root: root.path(),
                group_id: "group-1",
                windows_opt_in: false,
                origin_device_id: "device-a",
                authoring_change_hash: None,
                permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            },
            &record,
        )
        .unwrap();

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

        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");

        let mut local = file_record_with_block("script.sh", 0xAB);
        local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
        state.seed_file("group-1", &local);

        let out_path = root.path().join("script.sh");
        std::fs::write(&out_path, b"hello").unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Simulates this device's own index already knowing the target
        // exec bit for this path — see `try_apply_metadata_only_update`'s
        // doc comment on the wire-schema gap this stands in for.
        state
            .set_exec_bit(
                "group-1",
                "script.sh",
                true,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let mut incoming = local.clone();
        incoming.mtime_unix_nanos = 999;

        let applied = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &incoming,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        assert!(applied, "an identical block list must take the metadata-only fast path");

        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o744, "exec bit must be applied via chmod");
        assert_eq!(std::fs::read(&out_path).unwrap(), b"hello", "content bytes must be untouched");

        let stored = state.get_file("group-1", "script.sh").unwrap().unwrap();
        assert_eq!(stored.mtime_unix_nanos, 999, "index bookkeeping must still be updated");
    }

    /// A free function, not a `PeerSyncSession` method -- cannot go
    /// through `self.verify_write_target`'s `VerifiedRoot` re-check, so
    /// this must re-verify directly right before the chmod, not rely
    /// only on the earlier lexical-containment check.
    #[cfg(unix)]
    #[test]
    fn metadata_only_fast_path_refuses_a_root_whose_marker_no_longer_matches() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");

        let mut local = file_record_with_block("script.sh", 0xAB);
        local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
        state.seed_file("group-1", &local);

        let out_path = root.path().join("script.sh");
        std::fs::write(&out_path, b"hello").unwrap();
        state
            .set_exec_bit(
                "group-1",
                "script.sh",
                true,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        std::fs::remove_file(
            root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let mut incoming = local.clone();
        incoming.mtime_unix_nanos = 999;
        let result = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &incoming,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        );
        assert!(
            result.is_err(),
            "a metadata-only update under a root whose marker no longer matches must be refused"
        );
    }

    #[test]
    fn metadata_only_fast_path_rejects_index_match_when_disk_bytes_do_not_match() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.add_link(Some(root.path()), "group-1");
        let mut record = file_record_with_block("partial.bin", 0xAB);
        record.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
        state.seed_file("group-1", &record);
        std::fs::write(root.path().join("partial.bin"), b"wrong").unwrap();

        let applied = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &record,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        assert!(!applied, "an interrupted materialization must take the reconstruct path");
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_with_no_prior_local_record() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        let record = file_record_with_block("new.bin", 0x11);

        let applied = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &record,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        assert!(!applied, "brand-new adoption has nothing to compare against");
        assert!(
            state.get_file("group-1", "new.bin").unwrap().is_none(),
            "the fast path must not upsert anything when it doesn't apply"
        );
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_when_content_actually_changed() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        let local = file_record_with_block("doc.txt", 0x11);
        state.seed_file("group-1", &local);

        let incoming = file_record_with_block("doc.txt", 0x22); // different hash = real content change

        let applied = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &incoming,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
        assert!(!applied, "a genuinely different block list must not take the metadata-only path");
    }

    #[test]
    fn metadata_only_fast_path_does_not_apply_to_a_deleted_local_record() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        let mut local = file_record_with_block("gone.bin", 0x33);
        local.deleted = true;
        state.seed_file("group-1", &local);

        let incoming = file_record_with_block("gone.bin", 0x33);

        let applied = try_apply_metadata_only_update(
            &state,
            root.path(),
            "group-1",
            &incoming,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
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
    use crate::ports::PeerReplicaStatePort;
    use crate::test_support::FakeReplicaState;

    fn record(path: &str) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
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
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        if !crate::hazard::is_case_insensitive_filesystem(root.path()) {
            eprintln!("skipping: {} is case-sensitive here", root.path().display());
            return;
        }
        state.seed_file("group-1", &record("Photo.jpg"));

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

    /// The `normalization_collision` counterpart to the case-fold hazard
    /// test above: an incoming record whose path is a different Unicode
    /// normalization form of an already-indexed sibling's path is a hazard
    /// on a normalization-insensitive filesystem, gated the identical way
    /// (`hazard::is_normalization_insensitive_filesystem(root)`), skipping
    /// on a host where the tempdir's volume doesn't actually alias the two
    /// spellings.
    #[test]
    fn normalization_collision_with_an_existing_sibling_is_a_hazard() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        if !crate::hazard::is_normalization_insensitive_filesystem(root.path()) {
            eprintln!("skipping: {} is normalization-sensitive here", root.path().display());
            return;
        }
        let composed = "caf\u{e9}.txt";
        let decomposed = "cafe\u{301}.txt";
        state.seed_file("group-1", &record(composed));

        let reason = hazard_reason_for_policy(
            &state,
            root.path(),
            "group-1",
            &record(decomposed),
            NamePolicy::Posix,
        )
        .unwrap();

        let reason = reason.expect("a differently-normalized sibling must be flagged as a hazard");
        assert!(reason.starts_with(crate::hazard::HELD_REASON_NORMALIZATION_COLLISION));
        assert!(reason.contains(composed), "reason should name the colliding sibling: {reason}");
    }

    /// The exact inverse of the above: re-adopting a path identical to
    /// what's already indexed for it (an ordinary update, not a new
    /// arrival) must never be flagged as colliding with itself.
    #[test]
    fn updating_the_same_path_is_never_a_self_collision() {
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        state.seed_file("group-1", &record("Photo.jpg"));

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
        let state = FakeReplicaState::new();
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
        let state = FakeReplicaState::new();
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
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        let incoming = record("CON.txt");

        hold_record(
            &state,
            "group-1",
            &incoming,
            "invalid_name: reserved device name 'CON'",
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
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
        let state = FakeReplicaState::new();
        let root = tempfile::tempdir().unwrap();
        // Same case-sensitivity dependency as case_fold_collision_with_an_
        // existing_sibling_is_a_hazard above -- see its doc comment.
        if !crate::hazard::is_case_insensitive_filesystem(root.path()) {
            eprintln!("skipping: {} is case-sensitive here", root.path().display());
            return;
        }
        std::fs::write(root.path().join("Photo.jpg"), b"original").unwrap();
        state.seed_file("group-1", &record("Photo.jpg"));

        let incoming = record("photo.jpg");
        let reason =
            hazard_reason_for_policy(&state, root.path(), "group-1", &incoming, NamePolicy::Posix)
                .unwrap()
                .expect("case-fold collision must be detected");
        hold_record(
            &state,
            "group-1",
            &incoming,
            &reason,
            "device-a",
            None,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

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
    use super::{compress_block, decompress_block};

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

        assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
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

        assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
        assert_eq!(out, already_compressed);
    }

    /// The positive case: highly repetitive synthetic text (the shape of
    /// real source-tree/log/DB-dump content this feature targets) compresses
    /// well past the 95% threshold and must be sent compressed.
    #[test]
    fn highly_repetitive_text_is_compressed() {
        let data = "the quick brown fox jumps over the lazy dog\n".repeat(10_000);

        let (out, compression) = compress_block(data.as_bytes());

        assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_ZSTD);
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
        assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
        assert!(out.is_empty());
    }

    /// Round trip: whatever `compress_block` decides to do, `decompress_block`
    /// must recover the exact original bytes.
    #[test]
    fn compress_then_decompress_round_trips_exactly() {
        let data = "abcdefgh".repeat(20_000);
        let (out, compression) = compress_block(data.as_bytes());
        assert_eq!(
            compression,
            yadorilink_sync_wire::COMPRESSION_ZSTD,
            "sanity: this input must compress"
        );

        let recovered = decompress_block(&out, compression, 10 * 1024 * 1024).unwrap();
        assert_eq!(recovered, data.as_bytes());
    }

    /// `Compression::None` is a pure passthrough — the byte-identity path
    /// every pre-this-change / negotiation-declined block/index message
    /// takes.
    #[test]
    fn none_compression_is_a_passthrough() {
        let data = b"uncompressed content".to_vec();
        let recovered = decompress_block(&data, yadorilink_sync_wire::COMPRESSION_NONE, 4).unwrap();
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
        let result = decompress_block(&bomb, yadorilink_sync_wire::COMPRESSION_ZSTD, max_size);
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
        let result =
            decompress_block(&garbage, yadorilink_sync_wire::COMPRESSION_ZSTD, 1024 * 1024);
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
        let recovered =
            decompress_block(&compressed, yadorilink_sync_wire::COMPRESSION_ZSTD, 1024).unwrap();
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
    use yadorilink_replica_engine::conflict::{
        resolve_path_heads, ConflictCopy, PathHead, PathHeadContent, PathResolution,
    };

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
///
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
///
/// `ClusterConfig.supports_version_hash_exact` negotiation and the
/// `holds_version_durably` responder behavior it exists to let a querier
/// reason about — a peer's advertised capability must default to
/// unsupported and only flip once a handshake actually claims it, and the
/// responder's own exact-`change::VersionHash` matching (introduced by the
/// durability-confirmation redesign this capability bit follows up on) must
/// stay exactly as strict as before: this capability bit only changes which
/// peers a whole-group durability-handoff QUERIER trusts, never how the
/// RESPONDER itself verifies a query.
///
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
    use super::{
        HandoffLeaseResponder, PeerHandoffLeaseGrant, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };

    use crate::test_support::FakeReplicaState;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use yadorilink_local_storage::FsBlockStore;

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
        connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps::test_permissive()).await
    }

    /// Like `connected_pair`, but takes `session_b`'s 8 one-time capability
    /// injections explicitly instead of defaulting them -- for a test that
    /// needs `session_b` to answer with a specific responder/handler. The
    /// responder is only ever consulted once the test itself sends the
    /// request that reaches it (after the handshake settle-wait below), so
    /// installing it at construction rather than after `connected_pair`
    /// used to return is behaviorally identical.
    async fn connected_pair_with_session_b_deps(
        session_b_deps: PeerSyncSessionOneTimeDeps,
    ) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
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
        let store_a: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-a".to_string(),
            "device-b".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new_with_forwarding(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-a".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
            None,
            session_b_deps,
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
        let expected_digest = [42u8; 32];
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_lease_responder: Arc::new(FixedResponder(Some(PeerHandoffLeaseGrant {
                    lease_id: "lease-1".to_string(),
                    root_digest: expected_digest,
                    expires_at_unix: 999,
                }))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_lease_responder: Arc::new(ReleaseRecordingResponder(tx)),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_lease_responder: Arc::new(FixedResponder(None)),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_lease_responder: Arc::new(FixedResponder(Some(PeerHandoffLeaseGrant {
                    lease_id: "lease-should-never-be-seen".to_string(),
                    root_digest: [1u8; 32],
                    expires_at_unix: 999,
                }))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        session_a.handle_handoff_lease_grant(yadorilink_sync_wire::HandoffLeaseGrantFrame {
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
    use super::{
        HandoffTicketResponder, PeerHandoffTicketGrant, PeerSyncSession, PeerSyncSessionOneTimeDeps,
    };

    use crate::test_support::FakeReplicaState;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use yadorilink_local_storage::FsBlockStore;

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
        connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps::test_permissive()).await
    }

    /// Like `connected_pair`, but takes `session_b`'s 8 one-time capability
    /// injections explicitly -- see the matching helper in the
    /// `handoff_lease` submodule above for why installing at construction
    /// rather than after `connected_pair` returns is behaviorally identical.
    async fn connected_pair_with_session_b_deps(
        session_b_deps: PeerSyncSessionOneTimeDeps,
    ) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
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
        let store_a: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-x".to_string(),
            "device-b".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new_with_forwarding(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-x".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
            None,
            session_b_deps,
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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_ticket_responder: Arc::new(FixedResponder(Some(PeerHandoffTicketGrant {
                    lease_id: Some("ticket-lease-1".to_string()),
                    target_device_id: Some("device-c".to_string()),
                    expires_at_unix: 999,
                }))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_ticket_responder: Arc::new(ReleaseRecordingResponder(tx)),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_ticket_responder: Arc::new(FixedResponder(Some(PeerHandoffTicketGrant {
                    lease_id: None,
                    target_device_id: None,
                    expires_at_unix: 0,
                }))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_ticket_responder: Arc::new(FixedResponder(None)),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                handoff_ticket_responder: Arc::new(FixedResponder(Some(PeerHandoffTicketGrant {
                    lease_id: Some("ticket-should-never-be-seen".to_string()),
                    target_device_id: Some("device-c".to_string()),
                    expires_at_unix: 999,
                }))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
    use yadorilink_local_storage::FsBlockStore;

    use super::{
        PeerSyncSession, PeerSyncSessionOneTimeDeps, PreparedRebootstrap, RebootstrapHandler,
    };
    use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};
    use yadorilink_replica_domain::rebootstrap::Checkpoint;

    use crate::test_support::FakeReplicaState;
    use yadorilink_replica_domain::rebootstrap::{RebootstrapRequired, SnapshotManifest};

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
        ) -> Result<Option<PreparedRebootstrap>, crate::PeerSessionError> {
            Ok(self.0.clone())
        }

        fn verify_rebootstrap(
            &self,
            _required: &RebootstrapRequired,
        ) -> Result<(), crate::PeerSessionError> {
            Ok(())
        }

        fn install_rebootstrap(
            &self,
            _required: &RebootstrapRequired,
            _snapshot_bytes: &[u8],
        ) -> Result<(), crate::PeerSessionError> {
            Ok(())
        }
    }

    /// Same loopback-UDP two-session harness as `handoff_lease_wire_tests::
    /// connected_pair`, duplicated locally, session_a is `device-a` (the
    /// requester in every test below), session_b is `device-b` (the
    /// responder).
    async fn connected_pair() -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
        connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps::test_permissive()).await
    }

    /// Like `connected_pair`, but takes `session_b`'s 8 one-time capability
    /// injections explicitly -- see the matching helper in the
    /// `handoff_lease` submodule above for why installing at construction
    /// rather than after `connected_pair` returns is behaviorally identical.
    async fn connected_pair_with_session_b_deps(
        session_b_deps: PeerSyncSessionOneTimeDeps,
    ) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
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
        let store_a: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
        let store_b: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());

        let session_a = PeerSyncSession::new(
            Arc::new(channel_a),
            "device-a".to_string(),
            "device-b".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_a,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        let session_b = PeerSyncSession::new_with_forwarding(
            Arc::new(channel_b),
            "device-b".to_string(),
            "device-a".to_string(),
            Arc::new(FakeReplicaState::new()),
            store_b,
            vec![GROUP.to_string()],
            HashMap::new(),
            None,
            session_b_deps,
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
        let key = SigningKey::from_bytes(&[11u8; 32]);
        // Signed by "device-b" -- the actual connected peer of session_a --
        // so this exercises the success path, not the session-identity
        // mismatch case covered separately below.
        let prepared = prepared_signed_by("device-b", &key);
        let expected_required = prepared.required.clone();
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                rebootstrap_handler: Arc::new(FixedHandler(Some(prepared))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                rebootstrap_handler: Arc::new(FixedHandler(Some(prepared_signed_by(
                    "device-b", &key,
                )))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
        let other_device_key = SigningKey::from_bytes(&[12u8; 32]);
        let impersonating_prepared = prepared_signed_by("device-c", &other_device_key);
        let (session_a, _session_b) =
            connected_pair_with_session_b_deps(PeerSyncSessionOneTimeDeps {
                rebootstrap_handler: Arc::new(FixedHandler(Some(impersonating_prepared))),
                ..PeerSyncSessionOneTimeDeps::test_permissive()
            })
            .await;

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
///
/// Convergence coverage for the single-authority property the DAG engine now
/// holds outright: a concurrent edit resolves to the same winner regardless of
/// arrival order, and the materialization-audit backstop keeps repairing
/// missing on-disk content without ever resolving a concurrency. All in-process
/// and deterministic: the sessions run over a live-but-unreachable loopback
/// channel and are driven by direct `handle_message` / `handle_change_batch`
/// calls, never real datagram delivery, so nothing depends on network timing.
///
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
///
#[cfg(all(test, unix))]
mod disk_race_fingerprint_tests {
    use super::disk_race_fingerprint;

    /// How many write+observe cycles
    /// [`ctime_can_distinguish_back_to_back_writes`] samples before
    /// concluding this filesystem's ctime clock cannot be relied on to
    /// separate two back-to-back writes to the same file. Same technique,
    /// and the same sample count, as `fs_capabilities`'s
    /// `probe_birth_time_granularity`: a coarse clock reliably collides at
    /// least once across this many samples, and this is cheap enough to
    /// run inline in a unit test.
    const CTIME_GRANULARITY_SAMPLE_COUNT: usize = 32;

    /// Measures, empirically and inline, whether `path`'s filesystem
    /// advances ctime finely enough to distinguish two consecutive writes
    /// to the same file — the specific clock `disk_race_fingerprint`
    /// leans on once mtime has been restored to an identical value (see
    /// the test below). Deliberately NOT `cfg(target_os = ...)`: this is a
    /// filesystem property, not an OS property — an overlayfs mount on
    /// Linux and APFS on macOS differ for reasons the target triple
    /// doesn't capture, and `fs_capabilities`'s own birth-time granularity
    /// probe is not reused here because a birth-time clock and a ctime
    /// clock are not assumed to share a resolution; this measures ctime
    /// directly instead of assuming.
    ///
    /// `path` must already exist. Writes to it repeatedly (content only —
    /// ctime advances on any metadata-affecting change, not specifically
    /// on a length change, so the probe writes are not required to match
    /// any particular length) and looks for two consecutive samples whose
    /// `disk_race_fingerprint` is byte-identical: a collision is the only
    /// observation a coarse clock can produce that a fine one cannot (the
    /// same reasoning `probe_birth_time_granularity`'s own doc comment
    /// gives for treating collision, not small-delta, as the sole proof).
    fn ctime_can_distinguish_back_to_back_writes(path: &std::path::Path) -> bool {
        let mut previous = disk_race_fingerprint(path);
        for i in 0..CTIME_GRANULARITY_SAMPLE_COUNT {
            std::fs::write(path, format!("granularity-probe-{i}").as_bytes()).unwrap();
            let sample = disk_race_fingerprint(path);
            if sample == previous {
                return false;
            }
            previous = sample;
        }
        true
    }

    /// The case the original `(len, mtime)` form of this check could not
    /// see: an overwrite of exactly the same length whose mtime is then
    /// restored to the original value. A real local editor doing a
    /// same-size in-place write inside the filesystem's mtime granularity
    /// presents this way, and letting it through means `materialize`
    /// silently destroys that edit — the failure mode the check exists to
    /// prevent, so it must not be the one case it misses.
    ///
    /// With the mtime restored, only ctime can still distinguish the
    /// writes — and ctime's real-world resolution varies by filesystem,
    /// not by OS (measured: overlayfs on x86_64 Linux advances ctime in
    /// ~4ms quanta, so a tight write-restore-observe sequence can complete
    /// inside one tick; APFS on macOS does not exhibit this). Where this
    /// run's filesystem can distinguish two back-to-back writes (proven
    /// empirically by [`ctime_can_distinguish_back_to_back_writes`], not
    /// assumed from `cfg(target_os = ...)`), the fingerprint itself must
    /// still change, exactly as before. Where it cannot, the fingerprint
    /// provably has no observable signal left to detect the overwrite
    /// with — `stat` reports nothing else that differs — so this asserts
    /// the guard that actually protects the user in that case instead:
    /// `yadorilink_local_storage::disk_bytes_match_indexed_blocks` is
    /// content-based, not clock-based, and correctly reports that the
    /// on-disk bytes no longer match what was indexed.
    ///
    /// Known residual, stated rather than silently assumed away: in
    /// production, `materialize`'s content-hash guard (`peer_session.rs`,
    /// gated on `local_row` — see the `locally_hydrated` check ahead of
    /// its `disk_bytes_match_indexed_blocks` call) only runs when the
    /// path's materialization state is already `Hydrated`. For
    /// `Placeholder`/`Hydrating`/`Evicting` — states whose whole point is
    /// to disagree with what's on disk — neither guard catches a
    /// same-tick, same-length overwrite with a restored mtime on a
    /// coarse-ctime filesystem. That gap is not fixed here: closing it is
    /// exactly what atomic preimage capture removes the race window for,
    /// not something a metadata or content check performed after the fact
    /// can close.
    #[test]
    fn a_same_length_overwrite_with_a_restored_mtime_still_changes_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("same-length.bin");
        std::fs::write(&path, b"AAAA").unwrap();

        let probe_path = dir.path().join("granularity-probe.bin");
        std::fs::write(&probe_path, b"seed").unwrap();
        let ctime_is_fine = ctime_can_distinguish_back_to_back_writes(&probe_path);
        // Diagnostic only, unconditional: which branch a given CI runner's
        // filesystem actually took is exactly the fact this test's own
        // history (a residual gap discovered by mismatched CI/local
        // behavior) shows is worth having in the log rather than inferred
        // after the fact.
        eprintln!(
            "disk_race_fingerprint_tests: this filesystem's ctime clock is {}",
            if ctime_is_fine {
                "fine (metadata fingerprint assertion)"
            } else {
                "coarse (content-hash fallback assertion)"
            }
        );

        let before = disk_race_fingerprint(&path).expect("file exists");
        let original_mtime = std::fs::symlink_metadata(&path).unwrap().modified().unwrap();

        std::fs::write(&path, b"BBBB").unwrap();
        // Restore the mtime exactly, the same way `dst_support::fs_ops::stamp`
        // does — no extra dependency, and it proves the mtime really is
        // byte-identical rather than merely close.
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().modified().unwrap(),
            original_mtime,
            "precondition: the mtime was restored exactly, so only ctime can betray the write"
        );
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().len(),
            4,
            "precondition: the overwrite kept the length identical"
        );

        let after = disk_race_fingerprint(&path).expect("file still exists");

        if ctime_is_fine {
            assert_ne!(
                before, after,
                "a same-length overwrite with a restored mtime must still be detected on a \
                 filesystem whose ctime clock can distinguish it -- letting it through is \
                 exactly the silent local-edit loss this guards"
            );
        } else {
            // The metadata fingerprint provably cannot see this write: len,
            // mtime, and (on this filesystem, per the probe above) ctime are
            // all identical to `before`. That is not a bug in the
            // fingerprint -- there is nothing left in `stat` for it to read.
            // Assert the guard that actually catches this case instead.
            let original_block = yadorilink_replica_domain::file::BlockInfo {
                hash: {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(b"AAAA").to_vec()
                },
                offset: 0,
                size: 4,
            };
            let content_still_matches_original =
                yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                    &path,
                    std::slice::from_ref(&original_block),
                )
                .unwrap();
            assert!(
                !content_still_matches_original,
                "the metadata fingerprint has no signal left on this coarse-ctime filesystem, \
                 so the content-hash guard must be the one to catch the overwrite instead"
            );
        }
    }

    /// The other direction: an untouched file must fingerprint identically,
    /// or every eager materialize would decline itself into a retry loop on
    /// a path nobody is racing.
    #[test]
    fn an_untouched_file_fingerprints_identically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("untouched.bin");
        std::fs::write(&path, b"stable").unwrap();

        let first = disk_race_fingerprint(&path);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = disk_race_fingerprint(&path);

        assert_eq!(first, second, "an untouched file must not look like a racing write");
    }

    /// A path that does not exist fingerprints as `None` on both samples,
    /// so a materialize creating a brand-new file is never declined.
    #[test]
    fn a_missing_path_fingerprints_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(disk_race_fingerprint(&dir.path().join("absent.bin")), None);
    }
}

/// Phase 7D-6 exit characterization: the frontier-write-failure-continues-
/// with-warning behavior `announce_local_commit` and `handle_change_batch`
/// both document at their own `tracing::warn!` call sites ("failed to
/// record local frontier before/after ..."). Neither caller propagates a
/// failed `record_acknowledged_frontier` write as its own error -- a
/// transient frontier-persistence failure must never abort the announce (or,
/// for `handle_change_batch`, the already-admitted changes) it's attached
/// to. No `PeerSyncSession` test anywhere else in this crate exercises this
/// path today (the two call sites' `Err(e)` arms were previously only
/// covered indirectly, by the fake never failing at all).
#[cfg(test)]
mod frontier_write_failure_tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex as StdMutex};

    use yadorilink_local_storage::FsBlockStore;

    use super::PeerSyncSession;
    use crate::test_support::FakeReplicaState;

    const GROUP: &str = "frontier-write-failure-group";

    /// Records every frame this device tried to send, without any real
    /// transport -- this module only needs to observe *that* a send was
    /// attempted after the injected frontier-write failure, not carry
    /// bytes to a real peer.
    #[derive(Default)]
    struct RecordingChannel {
        sent: StdMutex<Vec<Vec<u8>>>,
    }

    impl RecordingChannel {
        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap_or_else(|p| p.into_inner()).len()
        }
    }

    #[async_trait::async_trait]
    impl crate::ports::PeerMessageChannel for RecordingChannel {
        async fn send(&self, payload: Vec<u8>) -> Result<(), yadorilink_transport::TransportError> {
            self.sent.lock().unwrap_or_else(|p| p.into_inner()).push(payload);
            Ok(())
        }

        fn try_send(&self, payload: Vec<u8>) -> bool {
            self.sent.lock().unwrap_or_else(|p| p.into_inner()).push(payload);
            true
        }

        async fn recv(&self) -> Option<Vec<u8>> {
            std::future::pending().await
        }

        fn enable_reliable_delivery(&self) {}

        async fn replace_coordination_candidates(&self, _candidates: Vec<std::net::SocketAddr>) {}
    }

    #[tokio::test]
    async fn announce_local_commit_still_sends_heads_announce_after_a_frontier_write_failure() {
        let state = Arc::new(FakeReplicaState::new());
        state.set_record_acknowledged_frontier_fails(true);
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn crate::ports::BlockContentStore> =
            Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let channel = Arc::new(RecordingChannel::default());

        let session = PeerSyncSession::new(
            channel.clone(),
            "device-a".to_string(),
            "device-b".to_string(),
            state,
            store,
            vec![GROUP.to_string()],
            HashMap::new(),
        );
        // `announce_local_commit` only announces to a peer this session has
        // negotiated the change-DAG with (see its own doc comment) -- this
        // build always speaks it, so only the peer's side needs recording.
        session.record_peer_change_dag_support(true);

        let result = session.announce_local_commit(GROUP).await;

        assert!(
            result.is_ok(),
            "a frontier-write failure must be logged (tracing::warn!), not propagated: {result:?}"
        );
        assert_eq!(
            channel.sent_count(),
            1,
            "the HeadsAnnounce this method exists to send must still go out despite the \
             frontier write having failed first"
        );
    }
}
