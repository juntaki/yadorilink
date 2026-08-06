//! Daemon-level orchestration for on-demand-sync's hydrate/pin/unpin/evict
//! operations: the sync-core primitives
//! (`PeerSyncSession::fetch_block`, `materialization::evict_file`) are
//! each scoped to one peer or pure local state — this module is what picks
//! *which* connected peer(s) to hydrate from, and resolves a folder group
//! to its local root path for the operations that need one.
//!
//! Hydration no longer tries one whole-file transfer per
//! peer sequentially. A file's missing blocks are
//! partitioned across every currently-reachable, authorized peer session
//! and fetched concurrently, with a block a peer reports not-found
//! reassigned to a different peer rather than failing the whole attempt,
//! and a single file-level deadline covering the entire dispatch.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

use crate::sync_error::SyncError;
use futures_util::stream::{FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};
use yadorilink_filesystem_sync::materialization_eviction::{
    evict_file, run_disk_pressure_eviction_sweep, MaterializationContext,
};
use yadorilink_local_storage::{apply_exec_bit, reconstruct_file};
use yadorilink_local_storage::{disk_bytes_match_indexed_blocks, BlockStore, StorageError};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::BlockInfo;
#[cfg(test)]
use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

use crate::daemon_state::DaemonState;

/// A single deadline for the *entire* multi-session dispatch —
/// supersedes what used to be `PeerSyncSession::hydrate_file`'s per-session
/// timeout for the daemon-orchestrated hydration path. Same value as
/// `PeerSyncSession::DEFAULT_HYDRATION_TIMEOUT` (unchanged budget, moved
/// ownership).
const HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-block bound on a single `PeerSyncSession::fetch_block` call inside
/// `fetch_blocks_from_sessions`'s worker loop. Diagnosed
/// via an instrumented, reproducible run of
/// `yadorilink-daemon/tests/multi_peer_hydration.rs`: `fetch_block` sends its
/// `BlockRequest` and the peer's `handle_block_request` logs a successful
/// `send` of the matching `BlockResponse` (so the peer *did* answer), yet
/// the requester's `PeerChannel::recv` loop never observes that response
/// arriving — an occasional lost/undelivered message on an otherwise fully
/// responsive, connected session, reproducible specifically under this
/// test's burst of several simultaneous peer connections. Before this
/// constant existed, a worker's `session.fetch_block(...).await` had no
/// bound of its own, so one unlucky request silently ate the *entire*
/// file-level `HYDRATION_TIMEOUT` budget — that worker's task simply never
/// returned, `workers.join_next` never observed it finish, and the whole
/// dispatch (every other, already-successful block included) sat blocked
/// until the outer deadline in `hydrate_with_timeout` finally tore
/// everything down, turning one dropped response into a full-file failure
/// instead of a quick reassignment. `BlockWorkQueue::mark_not_found`
/// already exists precisely to reassign a block a peer explicitly reports
/// missing to a different candidate (or retry it later); wrapping each
/// fetch in this timeout and routing an expired one through the same
/// `mark_not_found` path extends that existing resilience to a request
/// that never gets *any* answer, not just an explicit not-found one —
/// without touching `PeerSyncSession` or the transport layer itself.
/// Deliberately much shorter than `HYDRATION_TIMEOUT`: the whole point is
/// to free up a stuck worker to try the next candidate long before the
/// file-level deadline would otherwise be spent waiting on it alone.
const PER_BLOCK_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long an idle worker (one whose last `pop_for` came back empty while
/// `BlockWorkQueue::has_outstanding` was still true) sleeps before
/// re-checking the queue — see `BlockWorkQueue::outstanding`'s doc comment
/// for the worker-starvation race this polling avoids. Short relative to
/// `PER_BLOCK_FETCH_TIMEOUT` so a block freed up by a timed-out peer is
/// picked up by a waiting idle worker almost immediately, not after a
/// meaningful further delay.
const WORKER_IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Reuses `peer_session::disk_race_fingerprint` rather than the plain
/// `(size, mtime)` pair this module used to compute locally: size+mtime
/// alone lets a same-size edit landing within the filesystem's mtime
/// granularity (or from an editor that preserves mtime) slip past the
/// commit-time revalidation below undetected, silently overwriting a
/// concurrent local edit with the just-hydrated remote content — the same
/// race `disk_race_fingerprint`'s own doc comment describes and adds
/// `ctime` to close (unix; the residual gap on other platforms is
/// documented there, not re-derived here).
type DiskIdentity = Option<(u64, Option<std::time::SystemTime>, i64, i64)>;

fn disk_identity(path: &std::path::Path) -> Result<DiskIdentity, SyncError> {
    Ok(yadorilink_peer_session::peer_session::disk_race_fingerprint(path))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HydrationCommitDecision {
    Commit,
    AlreadyComplete,
    Stale,
}

fn hydration_commit_decision(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    expected_record: &yadorilink_replica_domain::file::FileRecord,
    expected_root: &std::path::Path,
    out_path: &std::path::Path,
    expected_disk_identity: DiskIdentity,
) -> Result<HydrationCommitDecision, SyncError> {
    if state.replica_coordinator.file_index_repository().get_file(group_id, path)?.as_ref()
        != Some(expected_record)
        || state.replica_coordinator.dirty_path_repository().is_path_dirty(group_id, path)?
    {
        return Ok(HydrationCommitDecision::Stale);
    }
    // `out_path` was resolved from `expected_root` at hydration start, before
    // the (possibly multi-second) block fetch. `local_root_for_group` reads
    // the live link table fresh every call (see its own doc comment) rather
    // than caching, so re-resolving here and comparing catches a group that
    // was unlinked and relinked elsewhere -- or simply unlinked outright --
    // during the fetch: without this, the commit below would still write to
    // `out_path`, a root the live link table no longer has any row for.
    // `peer_session::PeerSyncSession::sync_root` already applies this same
    // "re-read on every write, never trust a root captured earlier" rule for
    // its own materialize path; this closes the same gap for hydration.
    if local_root_for_group(state, group_id).ok().as_deref() != Some(expected_root) {
        return Ok(HydrationCommitDecision::Stale);
    }
    match state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?
    {
        Some(MaterializationState::Hydrated)
            if disk_bytes_match_indexed_blocks(out_path, &expected_record.blocks)? =>
        {
            Ok(HydrationCommitDecision::AlreadyComplete)
        }
        Some(MaterializationState::Hydrating)
            if disk_identity(out_path)? == expected_disk_identity =>
        {
            Ok(HydrationCommitDecision::Commit)
        }
        _ => Ok(HydrationCommitDecision::Stale),
    }
}

/// Narrow capability `HydrationStateGuard` needs from whatever holds the
/// materialization-state table -- deliberately just this one accessor, not
/// the full `MaterializationStatePort`/`MaterializationExecutionPort`
/// surface, mirroring `yadorilink_sync_core::materialization::
/// MaterializationIntentJournal`'s own narrow-trait shape (same crate-local
/// pattern: prove the type owns the one repository handle this guard's
/// `Drop` needs, nothing more). Only `ReplicaCoordinator` implements this
/// today -- an `impl` for `yadorilink_sync_core::index::SyncState` used to
/// exist here too, but had zero callers (production or test; every
/// `HydrationStateGuard` construction, including this file's own test
/// fixtures, already goes through `ReplicaCoordinator`) and was removed
/// rather than kept as an unused compatibility shim.
trait MaterializationStateAccess {
    fn materialization_state_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationStateRepository;
}

impl MaterializationStateAccess for crate::replica_coordinator::ReplicaCoordinator {
    fn materialization_state_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationStateRepository {
        crate::replica_coordinator::ReplicaCoordinator::materialization_state_repository(self)
    }
}

struct HydrationStateGuard<'a, T: MaterializationStateAccess> {
    state: &'a T,
    group_id: &'a str,
    path: &'a str,
    /// This attempt's own authoring identity, captured before it marked
    /// the row `Hydrating` -- see `Drop`'s own doc comment for why a
    /// state-only CAS is not enough on its own (the identical reasoning
    /// `peer_session::HydratingStateGuard` documents for sync-core's own
    /// hydration path).
    authoring_change_hash: Option<yadorilink_replica_domain::ids::ChangeHash>,
    completed: bool,
}

impl<'a, T: MaterializationStateAccess> HydrationStateGuard<'a, T> {
    fn new(
        state: &'a T,
        group_id: &'a str,
        path: &'a str,
        authoring_change_hash: Option<yadorilink_replica_domain::ids::ChangeHash>,
    ) -> Self {
        Self { state, group_id, path, authoring_change_hash, completed: false }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl<T: MaterializationStateAccess> Drop for HydrationStateGuard<'_, T> {
    fn drop(&mut self) {
        if !self.completed {
            // Authoring-bound, not a state-only CAS. `hydrate_inner` now
            // holds `path_lock` for its whole attempt (see that
            // function's own doc comment on `_path_guard` for why this
            // changed from an earlier release-then-reacquire design), so
            // two attempts for the same path can no longer be mid-flight
            // at once at all -- but this binding is kept regardless as
            // defense-in-depth against any future caller that constructs
            // this guard without holding that same lock for its whole
            // duration, and because `Drop` itself cannot await the lock
            // even if the surrounding function does: a state-only CAS
            // firing from an unlocked `Drop` could still, in principle,
            // race a differently-authored row it has no way to
            // distinguish from its own.
            let _ = self
                .state
                .materialization_state_repository()
                .transition_materialization_state_if_same_authoring(
                    self.group_id,
                    self.path,
                    MaterializationState::Hydrating,
                    self.authoring_change_hash.as_ref(),
                    MaterializationState::Placeholder,
                );
        }
    }
}

// In-flight window: `fetch_blocks_from_sessions` runs several
// worker "lanes" concurrently *per candidate session*, not just one.
// Before this change, each peer session could have at most one `fetch_block`
// request outstanding at a time — the request round-trip (bounded by real
// network RTT, not local CPU) was fully serialized per peer, so a single
// high-latency peer trickled blocks in one at a time no matter how many
// blocks it actually held. `PeerSyncSession::fetch_block` already supports
// several concurrent in-flight requests to the *same* peer correctly
// (`pending_block_requests` is keyed by hash with a waiter list per hash,
// with a multi-waiter design) — nothing about the session itself
// required this one-at-a-time pattern, it was purely an artifact of
// spawning exactly one worker task per candidate here. Running several
// lanes per candidate lets that same session pipeline multiple
// outstanding `BlockRequest`s, amortizing RTT across the window instead of
// paying it once per block. `BlockWorkQueue::pop_for`/`mark_not_found`/
// `mark_timed_out`/`resolve_fetched` are all keyed per popped block, not
// per worker, so multiple lanes sharing one `peer_id` need no changes
// there: each lane only ever resolves the specific block it itself popped.
//
// The lane count was originally fixed at a flat constant (4) for every
// candidate, with no adaptation to observed conditions: "fast links are
// throttled below their capacity; slow/lossy links are pushed past
// theirs." The lane
// count is now read per-candidate from `PeerSyncSession::fetch_window`
// (see that method's doc comment and `yadorilink_sync_core::
// adaptive_window`) instead of this constant — each session's own AIMD
// controller, fed real RTT/timeout signals from every `fetch_block` call
// across every hydration this daemon runs (the controller lives on the
// session, not on one dispatch), decides how many lanes that specific peer
// gets this round. `PeerSyncSession` seeds a new session's controller at
// this same value (`ADAPTIVE_WINDOW_INITIAL`), so day-one behavior for an
// unobserved peer is unchanged; it only diverges once real conditions are
// observed. See `fetch_blocks_from_sessions`'s lane-spawning loop below for
// the actual call site.

/// Shared, mutex-guarded work queue for multi-session block dispatch
/// tracking which blocks remain to fetch and, per block, which
/// candidate peer device ids have already tried and failed to provide it —
/// so a not-found response reassigns the block to a different candidate
/// instead of giving up, and a block every candidate has tried is
/// correctly recognized as exhausted rather than retried forever.
struct BlockWorkQueue {
    queue: VecDeque<BlockInfo>,
    tried_by: HashMap<Vec<u8>, HashSet<String>>,
    /// Blocks every candidate has tried and failed to provide — tracked
    /// separately from `queue` (which only ever holds work still worth
    /// attempting), so `remaining` can report them as still-missing
    /// instead of them silently vanishing once dropped from `queue`.
    exhausted: Vec<BlockInfo>,
    /// Count of blocks currently checked out by a worker (returned from
    /// `pop_for`, not yet resolved via `mark_not_found` or
    /// `resolve_fetched`) — a worker-starvation race found alongside
    /// `PER_BLOCK_FETCH_TIMEOUT`: `fetch_blocks_from_sessions`'s workers
    /// used to exit for good the first time `pop_for` came back empty. With
    /// a fast-failing peer that's harmless (a `mark_not_found` reassignment
    /// arrives within milliseconds, long before the other workers could
    /// plausibly have drained the queue and exited already). But
    /// `PER_BLOCK_FETCH_TIMEOUT` can leave a block checked out for several
    /// real seconds before a stuck request is finally treated as
    /// not-found and requeued — plenty of time for every *other* worker to
    /// finish its own share, see an empty queue, and exit permanently.
    /// Once every worker has exited, the block that finally gets requeued
    /// has no one left to claim it, and `fetch_blocks_from_sessions`
    /// wrongly reports it as still-missing even though another,
    /// already-idle candidate never got a real chance at it (reproduced by
    /// `yadorilink-daemon/tests/multi_peer_hydration.rs`). While `outstanding`
    /// is nonzero, an idle worker must keep polling instead of exiting,
    /// since resolving that outstanding block might put more work back in
    /// `queue`; only once it reaches zero (nothing left in flight anywhere)
    /// is an empty `queue` actually final.
    outstanding: usize,
    /// `(block hash, peer_id) -> (not eligible again until, consecutive
    /// timeout count)`, populated by `mark_timed_out`. A timeout is
    /// ambiguous (the peer might genuinely have the block and just be
    /// slow/busy right now — see `mark_timed_out`'s own doc comment), so
    /// unlike `mark_not_found` it must not stop retrying that peer. But
    /// without *some* delay, `pop_for` lets the very next lane re-pop the
    /// identical block for the identical peer with zero cooldown — if the
    /// timeout happened because that peer's own read/hash/compress queue
    /// is backed up (several peers requesting the same hot block at once
    /// is the common case, not a single stuck request), an immediate
    /// retry lands on the same congestion and can time out again, and a
    /// pile of lanes doing this at once amplifies the very congestion
    /// that caused the first timeout instead of giving it a chance to
    /// drain. This is jittered exponential backoff *per (block, peer)
    /// pair*, not a broad session-level penalty: a different peer (or
    /// this same peer for a different block) is never held back by it.
    timeout_backoff: HashMap<(Vec<u8>, String), (tokio::time::Instant, u32)>,
}

/// `mark_timed_out` backoff schedule: `TIMEOUT_BACKOFF_BASE * 2^(n-1)`
/// (n = consecutive timeouts so far for this (block, peer) pair), capped at
/// `TIMEOUT_BACKOFF_CAP`, with the same +/-25% jitter shape as
/// `yadorilink_peer_session::peer_session`'s `RECONCILE_RETRY_JITTER_FRACTION`/
/// `NOT_FOUND_RETRY_JITTER_FRACTION` (avoids every lane waiting on the same
/// peer synchronizing their retries right back onto it at once). 1s/2s/4s/
/// capped-at-8s keeps the *first* retry fast (a single slow response is
/// still common and shouldn't be penalized much) while meaningfully spacing
/// out repeated hits on a peer that keeps timing out.
const TIMEOUT_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(1);
const TIMEOUT_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(8);
const TIMEOUT_BACKOFF_JITTER_FRACTION: f64 = 0.25;

fn timeout_backoff_delay(consecutive_timeouts: u32) -> std::time::Duration {
    let scale = 1u64 << consecutive_timeouts.saturating_sub(1).min(20);
    let backed_off = TIMEOUT_BACKOFF_BASE.saturating_mul(scale as u32).min(TIMEOUT_BACKOFF_CAP);
    let jitter =
        rand::random_range(-TIMEOUT_BACKOFF_JITTER_FRACTION..=TIMEOUT_BACKOFF_JITTER_FRACTION);
    backed_off.mul_f64((1.0 + jitter).max(0.0))
}

impl BlockWorkQueue {
    fn new(blocks: Vec<BlockInfo>) -> Self {
        Self {
            queue: blocks.into(),
            tried_by: HashMap::new(),
            exhausted: Vec::new(),
            outstanding: 0,
            timeout_backoff: HashMap::new(),
        }
    }

    /// Pops a block `peer_id` hasn't tried yet and isn't currently cooling
    /// down on (see `timeout_backoff`), cycling past (but not discarding)
    /// ones it has — those stay queued for another worker. `None` if this
    /// worker has no eligible work available right now. Every `Some`
    /// returned here must eventually be paired with exactly one of
    /// `mark_not_found`/`mark_timed_out`/`resolve_fetched`, which keeps
    /// `outstanding` (see its doc comment) accurate.
    fn pop_for(&mut self, peer_id: &str) -> Option<BlockInfo> {
        let now = tokio::time::Instant::now();
        let len = self.queue.len();
        for _ in 0..len {
            let block = self.queue.pop_front()?;
            let already_tried =
                self.tried_by.get(&block.hash).is_some_and(|tried| tried.contains(peer_id));
            if already_tried {
                self.queue.push_back(block);
                continue;
            }
            let cooling_down = self
                .timeout_backoff
                .get(&(block.hash.clone(), peer_id.to_string()))
                .is_some_and(|(not_before, _)| now < *not_before);
            if cooling_down {
                self.queue.push_back(block);
                continue;
            }
            self.outstanding += 1;
            return Some(block);
        }
        None
    }

    /// Whether any block popped via `pop_for` is still unresolved — see
    /// `outstanding`'s doc comment. Callers should keep polling rather than
    /// give up on an empty `queue` while this is true.
    fn has_outstanding(&self) -> bool {
        self.outstanding > 0
    }

    /// Whether any block currently in `queue` is only unavailable because
    /// of a not-yet-expired `timeout_backoff` cooldown (as opposed to
    /// every remaining candidate having genuinely never tried it, which
    /// `pop_for` would hand out immediately). Without this, every lane's
    /// `pop_for` returning `None` while a block is merely cooling down
    /// looks identical to the queue being truly empty — see
    /// `fetch_blocks_from_sessions`'s worker-exit check, which must treat
    /// this the same as `has_outstanding` and keep polling rather than
    /// exit early and report a still-recoverable block as missing.
    fn has_pending_backoff(&self) -> bool {
        let now = tokio::time::Instant::now();
        self.timeout_backoff.values().any(|(not_before, _)| now < *not_before)
    }

    /// Resolves a block `pop_for` returned as successfully fetched and
    /// stored — the counterpart to `mark_not_found` for the success path,
    /// which never re-touches `queue`/`tried_by` but must still release its
    /// `outstanding` slot (see that field's doc comment).
    fn resolve_fetched(&mut self) {
        self.outstanding -= 1;
    }

    /// Records that `peer_id` tried `block` and it wasn't there; requeues
    /// it unless every one of `all_candidates` has now tried it —
    /// genuinely unavailable from any currently-reachable peer, so it
    /// moves to `exhausted` (surfacing in `remaining`'s still-missing
    /// report) instead of being retried forever. Use this only for an
    /// unambiguous "not there" signal (an explicit not-found reply or a
    /// hash mismatch) — see
    /// `mark_timed_out` for a response that never arrived at all.
    fn mark_not_found(&mut self, block: BlockInfo, peer_id: &str, all_candidates: &[String]) {
        self.outstanding -= 1;
        let tried = self.tried_by.entry(block.hash.clone()).or_default();
        tried.insert(peer_id.to_string());
        if all_candidates.iter().all(|c| tried.contains(c)) {
            self.exhausted.push(block);
        } else {
            self.queue.push_back(block);
        }
    }

    /// Requeues `block` after `peer_id`'s request for it went
    /// unanswered within `PER_BLOCK_FETCH_TIMEOUT` — deliberately
    /// **not** recorded in `tried_by`, unlike `mark_not_found`. A
    /// timeout is ambiguous (the peer might genuinely have the block and
    /// just answered slowly, or the response was lost in transit — real,
    /// observed transport-layer message loss under concurrent-connection
    /// bursts, not just a theoretical concern) rather than a definitive
    /// "this peer doesn't have it." Treating a timeout the same as an
    /// explicit not-found (the original behavior) meant a block held by
    /// only *one* reachable candidate became permanently unrecoverable
    /// the moment that single candidate's response merely arrived late
    /// once — `exhausted` after exactly one `all_candidates.len == 1`
    /// timeout, with no other peer to reassign to and no path back to
    /// retrying the same one. Not marking `tried_by` here means the
    /// block is immediately eligible for *any* peer to pick up again,
    /// including the one that just timed out — still bounded overall by
    /// the outer file-level `HYDRATION_TIMEOUT`, which a peer stuck in a
    /// genuine timeout loop will eventually hit.
    fn mark_timed_out(&mut self, block: BlockInfo, peer_id: &str) {
        self.outstanding -= 1;
        let key = (block.hash.clone(), peer_id.to_string());
        let consecutive_timeouts = self.timeout_backoff.get(&key).map_or(0, |(_, n)| *n) + 1;
        let not_before = tokio::time::Instant::now() + timeout_backoff_delay(consecutive_timeouts);
        self.timeout_backoff.insert(key, (not_before, consecutive_timeouts));
        self.queue.push_back(block);
    }

    /// Everything that ended up unfetched: work still queued (shouldn't
    /// normally happen once every worker has run out of untried blocks,
    /// but included for safety) plus everything exhausted.
    fn remaining(self) -> Vec<BlockInfo> {
        self.queue.into_iter().chain(self.exhausted).collect()
    }

    /// Called only by `PoppedBlock::drop` when a worker died between
    /// `pop_for` and reaching one of `resolve_fetched`/`mark_not_found`/
    /// `mark_timed_out` -- an independent review's finding: this crate's
    /// own `remaining()` only ever reports `queue`/`exhausted`, never
    /// `outstanding`, so a block a worker popped and then never resolved
    /// (a panic mid-flight, e.g. in `block_data_matches` or anywhere else
    /// in the worker's own loop body) silently vanished from EVERY
    /// tracking set at once: not in `queue`, not `exhausted`, and
    /// `outstanding` never decremented back to let `has_outstanding`
    /// ever go false again either. The caller (`fetch_blocks_from_
    /// sessions`'s own caller) computes "successfully fetched" as
    /// `missing - remaining()`, so a vanished block would be silently
    /// counted as fetched and have its provenance recorded even though it
    /// was never actually written to the block store. Unlike
    /// `mark_not_found`, this must NOT record anything in `tried_by` (a
    /// worker panic is not evidence the peer lacks the block) and unlike
    /// `mark_timed_out`, it must NOT arm the peer's cooldown backoff
    /// either (same reasoning) -- it is a neutral "this attempt never
    /// actually happened" requeue, safe for any other worker (including
    /// the same peer) to immediately retry.
    fn requeue_after_worker_panic(&mut self, block: BlockInfo) {
        self.outstanding -= 1;
        self.queue.push_back(block);
    }
}

/// RAII wrapper around one block popped from a shared `BlockWorkQueue` via
/// `pop_for` -- see `BlockWorkQueue::requeue_after_worker_panic`'s own doc
/// comment for the exact bug this closes. Every `Some` `pop_for` returns
/// must eventually be resolved via exactly one of `resolve_fetched`/
/// `mark_not_found`/`mark_timed_out` (each consumes `self`, matching the
/// underlying `BlockWorkQueue` methods' own contract); if none of them
/// ever runs -- most notably because the worker task itself panicked
/// somewhere in between -- `Drop` requeues the block instead of leaving it
/// silently unaccounted for in every tracking set at once.
struct PoppedBlock {
    work: Arc<StdMutex<BlockWorkQueue>>,
    block: Option<BlockInfo>,
}

impl PoppedBlock {
    /// Pops one block for `peer_id` (if any is currently eligible) and
    /// reports, in the same lock acquisition the old inline
    /// `pop_for`-plus-pending-check code used, whether the caller should
    /// keep polling on a `None` rather than treat it as final -- see the
    /// call site's own comment for why `None` alone is not decisive.
    fn pop_for(work: &Arc<StdMutex<BlockWorkQueue>>, peer_id: &str) -> (Option<Self>, bool) {
        let mut q = work.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let popped = q.pop_for(peer_id);
        let still_pending = q.has_outstanding() || q.has_pending_backoff();
        (popped.map(|block| Self { work: work.clone(), block: Some(block) }), still_pending)
    }

    fn block(&self) -> &BlockInfo {
        self.block.as_ref().expect("PoppedBlock used after being resolved")
    }

    fn resolve_fetched(mut self) {
        self.block.take().expect("PoppedBlock resolved twice");
        self.work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).resolve_fetched();
    }

    fn mark_not_found(mut self, peer_id: &str, all_candidates: &[String]) {
        let block = self.block.take().expect("PoppedBlock resolved twice");
        self.work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(
            block,
            peer_id,
            all_candidates,
        );
    }

    fn mark_timed_out(mut self, peer_id: &str) {
        let block = self.block.take().expect("PoppedBlock resolved twice");
        self.work
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .mark_timed_out(block, peer_id);
    }
}

impl Drop for PoppedBlock {
    fn drop(&mut self) {
        if let Some(block) = self.block.take() {
            self.work
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .requeue_after_worker_panic(block);
        }
    }
}

/// Fetches `missing` by partitioning it across every session in
/// `candidates`, one worker task per session running concurrently.
/// A block a session reports not-found is reassigned to a
/// different candidate rather than abandoned. Fetched block data is
/// written to `block_store` as it arrives. Returns whatever couldn't be
/// fetched from *any* candidate — empty if everything was retrieved.
///
/// `progress` and `recent_errors` are the same lightweight, additive
/// observation hooks described in `crate::transfer_progress`/
/// `crate::recent_errors`'s own doc comments — this is the single choke
/// point every block fetch for a file already passes through, so it's
/// also where per-transfer progress, block-fetch latency, and a
/// block-integrity mismatch are recorded, without otherwise changing this
/// dispatcher's existing rate-limit/adaptive-window/reassignment behavior.
#[derive(Debug)]
enum BlockDispatchFatal {
    /// The peer supplied valid bytes, but this device could not persist them.
    /// This is a local storage failure and must never count against the peer.
    Storage(yadorilink_local_storage::StorageError),
    /// A local blocking/worker task failed before it could report a storage
    /// result. Also local infrastructure, never a peer not-found signal.
    WorkerTask(String),
}

impl BlockDispatchFatal {
    fn into_sync_error(self) -> SyncError {
        match self {
            Self::Storage(error) => SyncError::from(error),
            Self::WorkerTask(message) => SyncError::CorruptState(message),
        }
    }
}

fn record_dispatch_fatal(
    slot: &Arc<StdMutex<Option<BlockDispatchFatal>>>,
    error: BlockDispatchFatal,
) {
    let mut slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_none() {
        *slot = Some(error);
    }
}

fn dispatch_has_failed(slot: &Arc<StdMutex<Option<BlockDispatchFatal>>>) -> bool {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_some()
}

async fn fetch_blocks_from_sessions(
    group_id: &str,
    file_path: &str,
    missing: Vec<BlockInfo>,
    candidates: &[(String, Arc<PeerSyncSession>)],
    block_store: Arc<dyn BlockStore + Send + Sync>,
    progress: crate::transfer_progress::TransferProgressTracker,
    recent_errors: crate::recent_errors::RecentErrorLog,
) -> Result<Vec<BlockInfo>, SyncError> {
    if missing.is_empty() || candidates.is_empty() {
        return Ok(missing);
    }

    let candidate_ids: Vec<String> = candidates.iter().map(|(id, _)| id.clone()).collect();
    let work = Arc::new(StdMutex::new(BlockWorkQueue::new(missing)));
    let fatal = Arc::new(StdMutex::new(None::<BlockDispatchFatal>));

    // `FuturesUnordered<JoinHandle<_>>` rather than `tokio::task::JoinSet`
    // — `madsim`'s tokio shim has no `JoinSet` at all, and the sync-core
    // reconcile loop (`peer_session.rs`) already uses this exact
    // substitution. Each pushed `tokio::spawn(..)` still runs as its own
    // independently-scheduled task exactly as `JoinSet` would; this only
    // replaces `JoinSet`'s "poll whichever join handle finishes first"
    // bookkeeping. Every worker is drained to completion below before this
    // returns, so there is no abort-on-drop difference to preserve.
    let mut workers: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();
    // Several lanes per candidate, not one — see the comment
    // block above `BlockWorkQueue` for the rationale. The
    // lane count
    // itself is no longer a fixed constant: each session's own adaptive
    // window (`fetch_window`) decides how many lanes *that* candidate gets
    // this round, based on RTT/timeout signals observed on that session
    // across every hydration so far — a fast/healthy peer gets more
    // concurrent lanes, a slow/lossy one gets fewer, and neither can ever
    // exceed the fixed security ceiling `fetch_window` itself is clamped
    // to. Extra lanes beyond what a given candidate actually
    // has work for are harmless: `pop_for` returning `(None, false)`
    // (queue empty, nothing outstanding anywhere) makes an idle lane exit
    // immediately, same as before.
    for (peer_id, session) in candidates {
        for _lane in 0..session.fetch_window() {
            let work = work.clone();
            let block_store = block_store.clone();
            let peer_id = peer_id.clone();
            let session = session.clone();
            let candidate_ids = candidate_ids.clone();
            let group_id = group_id.to_string();
            let file_path = file_path.to_string();
            let progress = progress.clone();
            let recent_errors = recent_errors.clone();
            let fatal = fatal.clone();
            workers.push(tokio::spawn(async move {
            loop {
                if dispatch_has_failed(&fatal) {
                    break;
                }
                // `PoppedBlock::pop_for` takes its own lock, held only
                // long enough to pop and read the pending flags -- fully
                // released before any `.await` below (never hold a std
                // `Mutex` guard across an await). From here on, `guard`
                // itself is responsible for `block`'s accounting: every
                // exit from this loop iteration must consume it via
                // exactly one of `resolve_fetched`/`mark_not_found`/
                // `mark_timed_out`, or -- the case those three exist
                // alongside `Drop` to cover -- if this worker task panics
                // anywhere before doing so, `guard`'s own `Drop` requeues
                // the block instead of it silently vanishing from every
                // tracking set at once (see `BlockWorkQueue::requeue_
                // after_worker_panic`'s doc comment).
                let (popped, still_pending) = PoppedBlock::pop_for(&work, &peer_id);
                let guard = match (popped, still_pending) {
                    (Some(guard), _) => guard,
                    // Either another worker still has a block checked out
                    // (see `outstanding`'s doc comment) or a block is
                    // sitting in `queue` cooling down after a timeout (see
                    // `has_pending_backoff`'s doc comment) -- either way
                    // `pop_for` coming back `None` right now isn't
                    // necessarily final.
                    (None, true) => {
                        tokio::time::sleep(WORKER_IDLE_POLL_INTERVAL).await;
                        continue;
                    }
                    (None, false) => break, // queue empty, nothing outstanding or cooling down: truly done
                };
                let block = guard.block().clone();
                // Measured across the whole bounded attempt (success,
                // not-found, request error, or timeout alike) —
                // `yadorilink_block_fetch_seconds` is "how long a
                // block-fetch round trip took," not just the
                // successful-outcome subset.
                let fetch_started = std::time::Instant::now();
                let outcome = tokio::time::timeout(
                    PER_BLOCK_FETCH_TIMEOUT,
                    session.fetch_block(&group_id, &file_path, &block.hash),
                )
                .await;
                progress.observe_block_fetch_seconds(fetch_started.elapsed().as_secs_f64());
                match outcome {
                    Ok(Ok(Some(data))) => {
                        if !block_data_matches(&block, &data) {
                            tracing::warn!(
                                peer = %peer_id,
                                file_path = %file_path,
                                hash = %hex::encode(&block.hash),
                                "peer returned block data that did not match the expected hash/size"
                            );
                            recent_errors.record("block_integrity", "hydration");
                            guard.mark_not_found(&peer_id, &candidate_ids);
                            continue;
                        }
                        let data_len = data.len() as u64;
                        // `BlockStore::put` is synchronous
                        // `std::fs` I/O plus a full SHA-256 hash — move it
                        // off this tokio worker thread so a big/slow write
                        // doesn't stall every other task (other peers'
                        // messages, other lanes' fetches) sharing it.
                        let put_result = {
                            let block_store = block_store.clone();
                            // Production offloads the synchronous `std::fs` +
                            // SHA-256 block write onto Tokio's blocking pool so
                            // a big/slow write can't stall this worker. The
                            // deterministic simulator has no such pool, and
                            // running it on a real OS thread would bleed
                            // non-simulated timing into the virtual clock, so
                            // run the identical write inline and wrap it in the
                            // same `Result<_, JoinError>` shape the match below
                            // expects.
                            #[cfg(not(madsim))]
                            {
                                tokio::task::spawn_blocking(move || block_store.put(&data)).await
                            }
                            #[cfg(madsim)]
                            {
                                Ok::<_, tokio::task::JoinError>(block_store.put(&data))
                            }
                        };
                        match put_result {
                            Ok(Ok(_)) => {
                                // Counted as done only once the bytes are
                                // actually persisted locally.
                                progress.record_block_done(&group_id, &file_path, data_len, &peer_id);
                                guard.resolve_fetched()
                            }
                            Ok(Err(error)) => {
                                tracing::error!(
                                    error = %error,
                                    peer = %peer_id,
                                    file_path = %file_path,
                                    "peer supplied a valid block but local persistence failed"
                                );
                                recent_errors.record("storage", "hydration_local_persist");
                                record_dispatch_fatal(&fatal, BlockDispatchFatal::Storage(error));
                                // Dropping the guard neutrally requeues the block.
                                // It does NOT mark this peer as lacking it.
                                drop(guard);
                                break;
                            }
                            Err(join_error) => {
                                tracing::error!(
                                    error = %join_error,
                                    peer = %peer_id,
                                    file_path = %file_path,
                                    "local block-store write task failed"
                                );
                                recent_errors.record("corrupt_state", "hydration_local_persist");
                                record_dispatch_fatal(
                                    &fatal,
                                    BlockDispatchFatal::WorkerTask(format!(
                                        "local block-store write task failed while hydrating {group_id}/{file_path}: {join_error}"
                                    )),
                                );
                                drop(guard);
                                break;
                            }
                        }
                    }
                    Ok(Ok(None)) => {
                        guard.mark_not_found(&peer_id, &candidate_ids);
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %error,
                            peer = %peer_id,
                            "block fetch request failed transiently; reassigning without recording peer not-found"
                        );
                        recent_errors.record("transport", "hydration");
                        // A request/transport failure says nothing about
                        // whether this peer has the block. Reuse the retryable
                        // backoff path rather than permanently adding it to
                        // `tried_by` and possibly exhausting all peers.
                        guard.mark_timed_out(&peer_id);
                    }
                    Err(_elapsed) => {
                        // See `PER_BLOCK_FETCH_TIMEOUT`'s doc comment: this
                        // peer never answered at all (as distinct from
                        // `Ok(Ok(None))`, an explicit not-found reply). Uses
                        // `mark_timed_out`, not `mark_not_found` — see that
                        // method's doc comment for why a mere timeout must
                        // not permanently write this peer off for this
                        // block, only reassign it (possibly back to the
                        // same peer) so one stuck/lost request can't make a
                        // block unrecoverable when it happens to be the
                        // only reachable holder.
                        //
                        // Also feeds this as a loss/timeout signal to the
                        // session's own adaptive window (`fetch_window`'s doc
                        // comment) — `fetch_block`'s future was dropped by
                        // this very `tokio::time::timeout` the instant it
                        // fired, so the session itself never got a chance
                        // to observe this outcome on its own; this is the
                        // one place that can tell it.
                        tracing::warn!(
                            peer = %peer_id,
                            timeout = ?PER_BLOCK_FETCH_TIMEOUT,
                            "block fetch timed out waiting for this peer's response; reassigning"
                        );
                        session.record_fetch_timeout();
                        guard.mark_timed_out(&peer_id);
                    }
                }
            }
        }));
        }
    }
    while let Some(joined) = workers.next().await {
        if let Err(join_error) = joined {
            record_dispatch_fatal(
                &fatal,
                BlockDispatchFatal::WorkerTask(format!(
                    "hydration worker task failed before completing its local bookkeeping: {join_error}"
                )),
            );
        }
    }

    if let Some(error) = fatal.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take() {
        return Err(error.into_sync_error());
    }

    Ok(Arc::into_inner(work)
        .expect("all worker tasks have completed, no other Arc clones remain")
        .into_inner()
        .unwrap()
        .remaining())
}

/// Hydrates `path` in `group_id` by partitioning its missing blocks across
/// every currently-connected, authorized peer session and fetching
/// concurrently, bounded by one file-level
/// `HYDRATION_TIMEOUT`. Reverts to `Placeholder` and returns
/// `HydrationFailed` if the deadline elapses or any block remains
/// unavailable from every candidate.
pub async fn hydrate(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    hydrate_with_timeout(state, group_id, path, HYDRATION_TIMEOUT).await
}

/// Like `hydrate`, with an explicit deadline — production callers use the
/// default (30s); tests use a much shorter one to verify the deadline
/// bounds the *whole* multi-session dispatch without waiting out the real
/// production budget.
pub async fn hydrate_with_timeout(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    timeout: std::time::Duration,
) -> Result<(), SyncError> {
    // `tokio::time::timeout` dropping the `hydrate_inner` future on
    // elapse runs that future's own local drop glue exactly like any
    // other Rust value drop -- including `HydrationStateGuard`'s
    // authoring-bound revert-on-drop, which by this point is the ONLY
    // thing responsible for reverting a still-`Hydrating` row back to
    // `Placeholder`. This used to ALSO blindly force `Placeholder` here,
    // unconditionally, AFTER that drop already ran -- if `hydrate_inner`
    // had raced past the guard's own `complete()` (a successful commit)
    // just before the deadline fired, this blind write would silently
    // downgrade a row this same attempt had just correctly finished
    // hydrating. Letting the guard be the sole authority (bound to the
    // authoring identity captured before marking `Hydrating`) means a
    // completed commit, or a DIFFERENT concurrent attempt's own
    // legitimate `Hydrating` row, is never touched here.
    let result = tokio::time::timeout(timeout, hydrate_inner(state, group_id, path))
        .await
        .unwrap_or(Err(SyncError::HydrationFailed(path.to_string())));
    // Every hydration failure (disk pressure, no reachable candidate,
    // timed-out/incomplete fetch, or anything else `hydrate_inner` can
    // return) lands in the recent-error ring buffer here, centrally —
    // `SyncError::category`'s doc comment for why this is safe to record
    // unconditionally (never derived from `Display`, so never a
    // path/volume/hash).
    if let Err(e) = &result {
        state.telemetry.record_recent_error(e.category(), "hydration");
    }
    result
}

async fn hydrate_inner(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    // Hydration is a materialization write (block-store reads plus a
    // `reconstruct_file` disk write) — held for this whole function's
    // duration so an update install never starts mid-hydration.
    let _write_activity = state.begin_write_activity();
    let Some(initial_record) =
        state.replica_coordinator.file_index_repository().get_file(group_id, path)?
    else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if initial_record.deleted {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    }
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let root_commit_permit = root_op.permit();

    let root = local_root_for_group(state, group_id)?;

    // Disk-space preflight before hydration starts fetching anything at
    // all, scoped to the volume hosting this link's local folder —
    // checked before setting `Hydrating` (a link that's about to fail
    // preflight shouldn't announce "hydrating" to a concurrent status
    // query first) and before any peer is contacted, so disk pressure
    // never wastes a network round trip. A no-op fast path when the
    // daemon hasn't opted into headroom
    // enforcement at all — see
    // `DaemonState::disk_headroom_enforcement_enabled`'s doc comment for
    // why that's not just always-on (this same function is exercised
    // directly by several daemon integration tests that write real
    // content, e.g. `multi_peer_hydration.rs`).
    if state.disk_headroom_enforcement_enabled() {
        let headroom_override = state.governance_config.load_or_default().headroom_override_bytes;
        preflight_disk_pressure(
            state,
            group_id,
            path,
            &root,
            initial_record.size,
            headroom_override,
        )?;
    }

    let out_path = root.join(path);
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    // Held for this whole function's remaining duration, including the
    // block fetch below -- NOT released and reacquired around it. This
    // used to release the lock during the (possibly multi-second) fetch
    // and only reacquire it before `hydration_commit_decision`, matching
    // sync-core's OWN hydration path before its round-10 fix (see that
    // fix's own doc comment for the identical reasoning): two concurrent
    // hydration attempts for the SAME version (same authoring hash, so
    // the authoring-bound guard/CAS above cannot tell them apart -- that
    // binds to the FILE VERSION, not to "this specific attempt") could
    // both be mid-flight unlocked at once, and a slower attempt's guard
    // dropping (on timeout or a missing-block failure) could revert the
    // row to `Placeholder` via a direct, lock-independent SQL write --
    // `Drop` is sync and cannot itself await the lock -- while a faster,
    // genuinely successful concurrent attempt was still between
    // `reconstruct_file` completing and its own final CAS, discovering
    // the row already reverted and failing despite disk now holding
    // fully correct content. Holding this lock for the whole attempt
    // makes that interleaving impossible: only one hydration attempt for
    // a given path can be in flight at all, matching every other writer
    // in this codebase (`materialize`, `reconcile_group_paths`,
    // sync-core's own `hydrate_file_with_timeout`) that already holds
    // its equivalent lock for its whole attempt, not just its commit.
    let _path_guard = path_lock.lock().await;
    let Some(current) =
        state.replica_coordinator.file_index_repository().get_file(group_id, path)?
    else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if current.deleted || current != initial_record {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    // Only a regular `File` ever goes through the placeholder/hydrate
    // cycle at all -- a symlink or directory record is always eagerly
    // materialized in full the moment it's adopted
    // (`peer_session::materialize_symlink_at`), never left as a
    // blocks-empty `Placeholder` stand-in waiting for this function.
    // `hydrate` is reachable for an arbitrary caller-supplied path with
    // no upstream kind filtering (the shell IPC `HydrateRequest` handler
    // just resolves a path to a `(group_id, rel_path)` pair and calls
    // straight through — see `shell_ipc::handle_message`), so this
    // function must defend itself: falling through to `reconstruct_file`
    // below for a non-`File` kind would call it with this record's
    // `blocks` list (always empty for a symlink, since a symlink's
    // target is never chunked) and clobber the real on-disk symlink/
    // directory at `out_path` with an empty regular file. Nothing to
    // hydrate for a kind that is never a placeholder in the first place.
    if state
        .replica_coordinator
        .file_index_repository()
        .get_record_kind(group_id, path)?
        .unwrap_or_default()
        != yadorilink_replica_domain::file::RecordKind::File
    {
        return Ok(());
    }
    // Idempotent fast path: `hydrate` must be safe to call on a path
    // that is already fully materialized — its only production caller
    // (the shell IPC `HydrateRequest` handler) tracks no per-path
    // hydration state of its own and has no way to avoid asking for a
    // path that's already `Hydrated`. Without this check, the
    // unconditional `set_materialization_state(Hydrating)` below would
    // still fire, `hydration_commit_decision` would still select
    // `Commit` once (trivially, since every block is already local)
    // `resolve_blocks_local_first` returns, and `reconstruct_file` would
    // still overwrite `out_path` with the *indexed* blocks — silently
    // discarding any local edit an editor wrote after this row was last
    // hydrated but before its own watcher event reaches the index (disk
    // content is not re-derived here; an already-`Hydrated` row is this
    // function's signal that there is nothing left for it to do, exactly
    // as `pin`'s own `already_hydrated` short-circuit already treats it).
    if state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path)?
        == Some(MaterializationState::Hydrated)
    {
        return Ok(());
    }
    // Captured here, under the same lock that just proved `current`
    // is this exact version -- see `HydrationStateGuard`'s own doc
    // comment for why its revert-on-drop must bind to this instead of
    // just the `Hydrating` state value.
    let authoring_change_hash = state
        .replica_coordinator
        .file_index_repository()
        .get_authoring_change_hash(group_id, path)?;
    let initial_disk_identity = disk_identity(&out_path)?;
    state.replica_coordinator.materialization_state_repository().set_materialization_state(
        group_id,
        path,
        MaterializationState::Hydrating,
        &root_commit_permit,
    )?;
    let record = current;
    let mut hydration_state = HydrationStateGuard::new(
        state.replica_coordinator.as_ref(),
        group_id,
        path,
        authoring_change_hash,
    );

    // Local-present-first resolution (shared with `restore_to_version_inner`
    // via `resolve_blocks_local_first`): blocks already cached locally are
    // never fetched, so a placeholder whose blocks are all present and intact
    // hydrates with no peer contacted at all — i.e. it succeeds offline. A
    // peer is required only for genuinely-missing (or locally-corrupt) blocks.
    let still_missing = resolve_blocks_local_first(state, group_id, path, &record.blocks).await?;

    if !still_missing.is_empty() {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }

    match hydration_commit_decision(
        state,
        group_id,
        path,
        &record,
        &root,
        &out_path,
        initial_disk_identity,
    )? {
        HydrationCommitDecision::Commit => {
            // `hydration_commit_decision` above re-reads the link table and
            // compares `local_root_for_group` against `expected_root`, but
            // that only proves the group's CONFIGURED root path didn't
            // change -- it cannot detect an external volume being
            // unmounted and replaced by something else at the SAME
            // mountpoint path during the (possibly multi-second) block
            // fetch, which leaves that comparison trivially equal. See
            // `peer_session::PeerSyncSession::verify_write_target`'s own
            // doc comment for the identical gap sync-core's own hydration
            // path closes this same way.
            //
            // This MUST run before `verify_write_target_within_root` below,
            // not after: that call is not a pure check, it `create_dir_
            // all`s `root` and `out_path`'s parent as a side effect (an
            // independent review caught this exact ordering bug) -- calling
            // it first would create directories on a possibly-wrong
            // replacement volume before its identity had even been
            // confirmed, defeating the point of re-verifying at all.
            yadorilink_root_authority::root_identity::VerifiedRoot::verify(
                &root,
                group_id,
                state.replica_coordinator.as_ref(),
            )?;
            // `reconstruct_file` does no escape-checking of its own -- it is
            // always the caller's job (see its own doc comment). The
            // ordinary `peer_session::materialize`/`hydrate_file_with_timeout`
            // write paths already call `verify_write_target` before their
            // own `reconstruct_file`; this path did not, so an intermediate
            // directory symlink planted under `root` (a local actor, or a
            // TOCTOU race) could redirect this write outside the sync root
            // -- the write-side twin of the tombstone escape this module's
            // `verify_delete_target` closes on the delete side.
            yadorilink_local_storage::verify_write_target_within_root(&out_path, &root)?;
            reconstruct_file(
                &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                    state.block_store.clone(),
                ),
                &out_path,
                &record.blocks,
                record.mtime_unix_nanos,
            )?;
            // Apply the owner-executable bit currently recorded for this
            // path (POSIX: real chmod; no-op, no error, on Windows) --
            // hydration is a materialization path just like sync-core's
            // own `hydrate_file_with_timeout_locked`, which already does
            // this in the identical spot. Without this, an executable
            // file's exec bit was silently lost on every daemon-side
            // on-demand hydration: the index kept the correct bit, but
            // disk never got it applied after `reconstruct_file`.
            apply_exec_bit(
                &out_path,
                state.replica_coordinator.file_index_repository().get_exec_bit(group_id, path)?,
            )?;
            // Author-bound, not a blind `set_materialization_state`, for
            // the identical reason `HydrationStateGuard`'s own
            // revert-on-drop is: `hydration_commit_decision` proved the
            // row still matched a moment ago, but a concurrent update
            // could still land in the narrow window between that check
            // and this commit while this same `path_lock` acquisition is
            // held (the decision and this write are not one atomic
            // step). If the row has moved on, this attempt's just-written
            // bytes on disk are stale for whatever version is now
            // current -- do not claim `Hydrated` for a version this
            // attempt never actually materialized.
            if !state
                .replica_coordinator
                .materialization_state_repository()
                .transition_materialization_state_if_same_authoring(
                    group_id,
                    path,
                    MaterializationState::Hydrating,
                    authoring_change_hash.as_ref(),
                    MaterializationState::Hydrated,
                )?
            {
                return Err(SyncError::HydrationFailed(path.to_string()));
            }
        }
        HydrationCommitDecision::AlreadyComplete => {}
        HydrationCommitDecision::Stale => {
            return Err(SyncError::HydrationFailed(path.to_string()));
        }
    }
    hydration_state.complete();
    // A snappier recovery signal beyond the periodic backoff re-check
    // — any successful hydration on this link proves its
    // volume currently has headroom, so a stale Degraded entry (if any)
    // can clear immediately rather than waiting out the next scheduled
    // re-check. A no-op if the link wasn't degraded.
    state.clear_link_degraded(&root.to_string_lossy());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    state.replica_coordinator.file_index_repository().touch_last_accessed(group_id, path, now)?;
    Ok(())
}

/// Fails cleanly with `SyncError::DiskPressure` (and marks `group_id`'s
/// link Degraded) if hydrating `path` (a write of
/// `required_bytes`, the file's full size) would breach the configured
/// headroom on the volume hosting `root`. Before failing, if `group_id`'s
/// link is `OnDemand`, runs the disk-pressure-triggered eviction sweep
/// and re-checks once — giving it a chance to free enough
/// space for the operation to still succeed: the sweep runs and completes
/// before a pending hydration/materialization is failed.
fn preflight_disk_pressure(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    root: &std::path::Path,
    required_bytes: u64,
    headroom_override: Option<u64>,
) -> Result<(), SyncError> {
    let initial = yadorilink_local_storage::free_space::classify_volume(root, headroom_override)?;
    if !initial.would_breach(required_bytes) {
        return Ok(());
    }

    // the sweep only applies to (and only makes sense for) an
    // OnDemand link — an Eager link has no placeholder/hydrated-content
    // distinction to evict from.
    let is_on_demand = state
        .replica_coordinator
        .link_repository()
        .list_links()?
        .into_iter()
        .find(|l| l.group_id == group_id)
        .is_some_and(|l| l.materialization_policy == MaterializationPolicy::OnDemand);
    if is_on_demand {
        // This branch only runs for an OnDemand link, so this device is not a
        // full replica of the group; custody is consulted per file so the sweep
        // never deletes a block a full replica isn't confirmed to hold.
        //
        // The sweep is blocking work: it parks on the `BlockLivenessGate`
        // condvar (`begin_reference_write`/`begin_physical_deletion`) and does
        // synchronous SQLite/block-store I/O. `preflight_disk_pressure` is
        // invoked directly from the async `hydrate` path, so run the sweep
        // through `block_in_place` when a multi-thread worker is available —
        // otherwise concurrent on-demand hydrations under disk pressure would
        // park a tokio worker on the gate while a sibling hydration holds the
        // gate mid-await, starving the pool. This mirrors the offload guard the
        // GC sweep already uses; see `gc::run_sweep_with_grace_cutoff`.
        let run_sweep = || {
            if !state.on_demand_pipeline_is_connected() {
                tracing::warn!(
                    group_id,
                    "disk-pressure eviction sweep: on-demand placeholder pipeline is not \
                     connected; refusing to evict"
                );
                return;
            }
            match state.root_lease_for(group_id) {
                Ok(root_lease) => match root_lease.begin_operation() {
                    Ok(root_op) => {
                        // `DaemonState::block_store` is already an erased
                        // `Arc<dyn BlockStore + Send + Sync>`, so it needs
                        // the adapter to reach `&dyn BlockReclamationStore`
                        // — see `gc::run_sweep_sync`'s matching comment.
                        let block_reclamation =
                            crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                                state.block_store.clone(),
                            );
                        let _ = run_disk_pressure_eviction_sweep(
                            MaterializationContext {
                                state: state.replica_coordinator.as_ref(),
                                liveness_gate: state.block_liveness_gate(),
                                store: &block_reclamation,
                                root,
                                permit: &root_op.permit(),
                            },
                            group_id,
                            false,
                            headroom_override,
                            state,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            group_id,
                            "disk-pressure eviction sweep: root lease refused a new operation"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        group_id,
                        "disk-pressure eviction sweep: no live root lease for this link"
                    );
                }
            }
        };
        #[cfg(not(madsim))]
        {
            match tokio::runtime::Handle::try_current() {
                Ok(handle)
                    if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
                {
                    tokio::task::block_in_place(run_sweep);
                }
                // No multi-thread worker to offload onto (current-thread
                // runtime, or called outside a runtime): the plain synchronous
                // path is correct and cannot starve a worker pool.
                _ => run_sweep(),
            }
        }
        // The deterministic simulator runs a single-threaded runtime and its
        // tokio shim exposes neither `runtime_flavor()` nor `block_in_place`,
        // so always take the plain synchronous path there — identical result to
        // the `_ =>` branch above.
        #[cfg(madsim)]
        {
            run_sweep();
        }
    }

    let after_sweep =
        yadorilink_local_storage::free_space::classify_volume(root, headroom_override)?;
    if !after_sweep.would_breach(required_bytes) {
        return Ok(());
    }

    let err = SyncError::DiskPressure {
        path: root.join(path).display().to_string(),
        volume: root.display().to_string(),
        available_bytes: after_sweep.available_bytes,
        headroom_bytes: after_sweep.headroom_bytes,
    };
    state.mark_link_degraded(&root.to_string_lossy(), err.to_string());
    Err(err)
}

/// Pins `path`, hydrating it first (via the same multi-session dispatch as
/// `hydrate`) if it isn't already `Hydrated`. If the file is
/// already `Hydrated`, this only sets the pin flag and never needs a peer
/// at all.
pub async fn pin(state: &Arc<DaemonState>, group_id: &str, path: &str) -> Result<(), SyncError> {
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    {
        let _path_guard = path_lock.lock().await;
        let already_hydrated = state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, path)?
            == Some(MaterializationState::Hydrated);
        state.replica_coordinator.file_index_repository().set_pinned(group_id, path, true)?;
        if already_hydrated {
            return Ok(());
        }
    }

    // Set the pin flag regardless of whether hydration succeeds below, so
    // it takes effect the moment a peer *does* become available, matching
    // the previous sequential implementation's behavior.
    hydrate(state, group_id, path).await
}

/// Unpins `path` — pure local state, no peer needed (spec "Unpinning
/// allows eviction").
pub async fn unpin(state: &DaemonState, group_id: &str, path: &str) -> Result<(), SyncError> {
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    let _path_guard = path_lock.lock().await;
    Ok(state.replica_coordinator.file_index_repository().set_pinned(group_id, path, false)?)
}

/// Manually evicts `path` back to a placeholder (spec "Manual Eviction").
/// Resolves `group_id` to its local root path via the registered link.
pub fn evict(state: &DaemonState, group_id: &str, path: &str) -> Result<(), SyncError> {
    // Demoting a fully-materialized file to a placeholder is only safe to
    // reverse (re-fetch on next access) if a real OS-transparent placeholder
    // provider is actually watching the result -- see `placeholder_backend`'s
    // own doc for what "connected" requires and why an ordinary sparse file
    // does not qualify on its own. Checked here (the daemon-side entry
    // point), not inside `materialization::evict_file` itself, mirroring
    // where `finish_link_setup`/`set_storage_mode` gate OnDemand creation --
    // that function's own extensive test suite exercises the mechanism
    // directly and must stay reachable without a live provider.
    if !state.on_demand_pipeline_is_connected() {
        return Err(SyncError::EvictionRejected(format!(
            "{path}: eviction is unavailable in this build (on-demand placeholder pipeline is \
             not connected)"
        )));
    }
    let root = local_root_for_group(state, group_id)?;
    let is_full_replica = state.is_local_full_replica(group_id);
    let root_lease = state.root_lease_for(group_id)?;
    let root_op = root_lease.begin_operation()?;
    let root_commit_permit = root_op.permit();
    // See `run_disk_pressure_eviction_sweep`'s call site above / `gc::
    // run_sweep_sync`'s comment: `state.block_store` is an already-erased
    // `Arc<dyn BlockStore + Send + Sync>`, so it needs the adapter to reach
    // `&dyn BlockReclamationStore`.
    let block_reclamation =
        crate::adapters::block_store_ports::BlockStorePortsAdapter::new(state.block_store.clone());
    evict_file(
        MaterializationContext {
            state: state.replica_coordinator.as_ref(),
            liveness_gate: state.block_liveness_gate(),
            store: &block_reclamation,
            root: &root,
            permit: &root_commit_permit,
        },
        group_id,
        path,
        is_full_replica,
        state,
    )
    .map(|_| ())
    .map_err(SyncError::from)
}

// --- restore engine ---

/// Resolves `version_seq`'s content — verifying local
/// presence of every block it references and, for any missing block,
/// attempting a peer fetch scoped to those hashes via the same
/// multi-session dispatch `hydrate` uses — and, on success, writes it to
/// disk and indexes it through the *ordinary* local-change path:
/// a brand-new current version, with the local device's version-
/// vector counter bumped and the change broadcast to peers exactly like
/// any other local edit. Never mutates or reorders any existing version
/// row; a concurrent edit racing this (adopted from a peer while this
/// runs) is caught by the same `SyncState::path_lock`-guarded read-
/// compare-write section `LocalChangeProcessor::process_event`/
/// `PeerSyncSession::reconcile_one_file` already use, so it resolves via
/// the existing version-vector conflict machinery with no restore-
/// specific special-casing.
///
/// Fails with `SyncError::VersionContentUnavailable` (never a generic I/O
/// or not-found error) and makes no index or on-disk change if some block
/// the version needs is missing locally and unavailable from every
/// currently-reachable, authorized peer within the timeout.
pub async fn restore_to_version(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
) -> Result<(), SyncError> {
    restore_to_version_with_timeout(state, group_id, path, version_seq, HYDRATION_TIMEOUT).await
}

/// Like `restore_to_version`, with an explicit deadline — production
/// callers use the default (30s, matching `hydrate`'s own default); tests
/// use a much shorter one so the "no reachable peer" case doesn't make the
/// suite slow.
pub async fn restore_to_version_with_timeout(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
    timeout: std::time::Duration,
) -> Result<(), SyncError> {
    tokio::time::timeout(timeout, restore_to_version_inner(state, group_id, path, version_seq))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(SyncError::VersionContentUnavailable(format!("{group_id}/{path}@{version_seq}")))
        })
}

async fn restore_to_version_inner(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    version_seq: i64,
) -> Result<(), SyncError> {
    // A materialization write (`reconstruct_file`) plus an index write,
    // same treatment as `hydrate_inner`'s guard above; also covers
    // `restore_trashed`, which calls through to this same function.
    let _write_activity = state.begin_write_activity();
    // Restore both reads the current record (to compute the new
    // version vector correctly) and writes new content — the exact same
    // read-compare-write shape `process_event`/`reconcile_one_file` are
    // already serialized against each other for, via this same lock. See
    // `SyncState::path_lock`'s doc comment for the race this closes.
    let path_lock = state.replica_coordinator.path_lock_registry().path_lock(group_id, path);
    let _guard = path_lock.lock().await;

    let Some(version) = state.replica_coordinator.file_index_repository().get_version(
        group_id,
        path,
        version_seq,
    )?
    else {
        return Err(SyncError::NotFound(format!("version {version_seq} of {group_id}/{path}")));
    };
    if version.deleted {
        // A tombstone row itself carries no restorable content — the
        // caller wants `restore_trashed`, which resolves to the trashed
        // row's own `version_seq` (the last real content before the
        // delete), not this one.
        return Err(SyncError::NotFound(format!(
            "version {version_seq} of {group_id}/{path} is a deletion, not restorable content"
        )));
    }

    let root = local_root_for_group(state, group_id)?;

    // A version restore is the same kind of block-fetch transfer as an
    // ordinary hydration: it resolves the version's blocks through the exact
    // same local-present-first path (`resolve_blocks_local_first`), so a
    // version whose blocks are all still cached locally restores with no peer
    // contacted, and only genuinely-missing (or locally-corrupt) blocks are
    // fetched from a reachable peer.
    let still_missing = resolve_blocks_local_first(state, group_id, path, &version.blocks).await?;
    if !still_missing.is_empty() {
        let err = SyncError::VersionContentUnavailable(format!("{group_id}/{path}@{version_seq}"));
        state.telemetry.record_recent_error(err.category(), "restore_version");
        return Err(err);
    }

    let expected_current_version_seq = state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)?
        .into_iter()
        .find(|candidate| {
            candidate.state == yadorilink_replica_domain::session_state::VersionState::Current
        })
        .map(|candidate| candidate.version_seq);
    let now_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let new_record = yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size: version.size,
        mtime_unix_nanos: now_unix_nanos,
        blocks: version.blocks.clone(),
        deleted: false,
    };
    let restored_file_version = yadorilink_replica_domain::file::FileVersion::from_index_row(
        version.blocks.clone(),
        version.size,
        now_unix_nanos,
        version.record_kind,
        version.exec_bit,
        version.symlink_target.clone(),
    );
    let signing_key = state.device_signing_key().ok_or_else(|| {
        SyncError::CorruptState(format!(
            "registered device {} has no signing key; refusing DAG-less restore",
            state.device_id
        ))
    })?;
    let emitter =
        yadorilink_sync_sqlite::dag_store::ChangeEmitter::new(state.device_id.clone(), signing_key);
    let operation_id = uuid::Uuid::new_v4().to_string();
    state.replica_coordinator.record_restore_operation_emitting_change(
        &yadorilink_filesystem_sync::materialization_types::RestoreOperation {
            operation_id: operation_id.clone(),
            group_id: group_id.to_string(),
            path: path.to_string(),
            target_version_seq: version_seq,
            expected_current_version_seq,
            state:
                yadorilink_filesystem_sync::materialization_types::RestoreOperationState::Prepared,
            record: new_record.clone(),
            origin_device_id: state.device_id.clone(),
            authoring_change_hash: None,
            // Carried through to `commit_restore_operation`, which applies
            // it to the `current` row via the same atomic
            // `apply_local_meta_columns_in_tx` every other local content
            // emission uses -- restoring a symlink/executable version must
            // not just recreate the right bytes/link on disk (this
            // function's own record-kind dispatch below already does
            // that), the index's own classification of the path has to
            // move too, or a later caller trusting `record_kind` (like
            // `hydrate_inner`'s own kind guard) would still treat it as
            // whatever it was before the restore. `symlink_out_of_root` is
            // not carried by `VersionRecord` (a purely local, wire-only
            // classification computed from a live filesystem scan, not
            // versioned history) -- `false` is the same safe default used
            // at every other call site that constructs this without a
            // fresh scan to hand.
            meta: yadorilink_replica_domain::session_state::LocalFileMetaColumns {
                record_kind: version.record_kind,
                symlink_target: version.symlink_target.clone(),
                symlink_out_of_root: false,
                exec_bit: version.exec_bit,
            },
        },
        &restored_file_version,
        &emitter,
    )?;

    // The journal above is durable before the atomic replacement. Any error
    // from reconstruction is therefore ambiguous by design: leave the row for
    // startup reconciliation, which verifies the disk bytes before deciding
    // whether to commit or discard the intended index version.
    //
    // Two checks belong here, both mirroring `hydrate_inner`'s equivalent
    // guards for the identical shape of race (a block fetch above can take
    // several seconds, same as ordinary hydration):
    // - re-resolve the group's root fresh (`local_root_for_group` never
    //   caches) to catch an unlink/relink that happened during the fetch,
    //   rather than trusting the `root` captured before it;
    // - `verify_write_target_within_root` before `reconstruct_file`, which
    //   does no escape-checking of its own -- an intermediate directory
    //   symlink under `root` could otherwise redirect this write outside
    //   the sync root, same as `hydrate_inner`'s equivalent gap.
    if local_root_for_group(state, group_id).ok().as_deref() != Some(root.as_path()) {
        return Err(SyncError::HydrationFailed(path.to_string()));
    }
    let out_path = root.join(path);
    // Re-resolving the link table's root path above only proves the
    // group's CONFIGURED root didn't change -- it cannot detect an
    // external volume being unmounted and replaced by something else at
    // the SAME mountpoint path during the fetch, which leaves that
    // comparison trivially equal. The same gap `hydrate_inner`'s own
    // `VerifiedRoot::verify` call closes for ordinary hydration.
    //
    // This MUST run before `verify_write_target_within_root` below, not
    // after: that call is not a pure check, it `create_dir_all`s `root`
    // and `out_path`'s parent as a side effect (an independent review
    // caught this exact ordering bug) -- calling it first would create
    // directories on a possibly-wrong replacement volume before its
    // identity had even been confirmed.
    yadorilink_root_authority::root_identity::VerifiedRoot::verify(
        &root,
        group_id,
        state.replica_coordinator.as_ref(),
    )?;
    yadorilink_local_storage::verify_write_target_within_root(&out_path, &root)?;
    // A restored version carries its own `record_kind`/`exec_bit`/
    // `symlink_target` (captured per-row, not just for the `current` row
    // -- see `VersionRecord::record_kind`'s own doc comment), but this
    // used to always call `reconstruct_file` unconditionally regardless
    // of kind: restoring a symlink or executable version silently wrote
    // (or rewrote) an ordinary, non-executable regular file instead --
    // an independent review's finding. Dispatch on the version's own
    // kind, matching `peer_session::materialize`'s and
    // `materialize_symlink_at`'s established per-kind materialization.
    match version.record_kind {
        yadorilink_replica_domain::file::RecordKind::File => {
            reconstruct_file(
                &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                    state.block_store.clone(),
                ),
                &out_path,
                &version.blocks,
                // Not `version.mtime_unix_nanos` (that historical version's
                // own original authored time) — a restore is authored by
                // THIS device right now, same as `new_record.mtime_unix_
                // nanos` above, which is what gets indexed for it. Stamping
                // disk to match keeps the same on-disk/indexed-mtime
                // invariant `reconstruct_file`'s own doc comment describes.
                now_unix_nanos,
            )?;
            apply_exec_bit(&out_path, version.exec_bit)?;
        }
        yadorilink_replica_domain::file::RecordKind::Symlink => match &version.symlink_target {
            Some(target) => {
                #[cfg(unix)]
                {
                    yadorilink_local_storage::materialize_symlink(&out_path, target)?;
                }
                #[cfg(windows)]
                {
                    if state.replica_coordinator.windows_symlink_opt_in_for_group(group_id)? {
                        yadorilink_local_storage::materialize_symlink_windows(&out_path, target)?;
                    }
                }
                #[cfg(not(any(unix, windows)))]
                {
                    let _ = target;
                }
            }
            None => {
                // No target recorded for this version -- nothing safe to
                // create on disk, matching `materialize_symlink_at`'s own
                // defensive handling of the same case.
            }
        },
        yadorilink_replica_domain::file::RecordKind::Directory => {
            std::fs::create_dir_all(&out_path)?;
        }
    }
    state
        .replica_coordinator
        .restore_operation_repository()
        .mark_restore_disk_committed(&operation_id)?;
    let committed = match state
        .replica_coordinator
        .restore_operation_repository()
        .commit_restore_operation(&operation_id)?
    {
        yadorilink_filesystem_sync::materialization_types::RestoreCommitOutcome::Committed(
            record,
        ) => record,
        yadorilink_filesystem_sync::materialization_types::RestoreCommitOutcome::Missing => {
            return Err(SyncError::CorruptState(format!(
                "restore operation disappeared before index commit: {operation_id}"
            )));
        }
        yadorilink_filesystem_sync::materialization_types::RestoreCommitOutcome::Superseded => {
            return Err(SyncError::CorruptState(format!(
                "restore base changed before index commit: {group_id}/{path}"
            )));
        }
    };
    // Same fan-out as `DaemonState::broadcast_change`'s other callers
    // (`announce_local_change`, the forward-rebroadcast task): connected
    // peers see this exactly like any other local edit (spec "Restored
    // content propagates like a normal edit").
    state.broadcast_change(group_id, vec![committed]).await;
    Ok(())
}

/// restores a trashed file — the last version before its
/// deletion (`SyncState::list_trashed`'s own `version_seq`, always the
/// *most recent* trashed row for `path` — see that method's doc comment)
/// — as a new current version via `restore_to_version` above. The file
/// becomes live again; the trashed row itself is left exactly as it was
/// (: restore never mutates existing version rows) — it simply
/// stops being "the last version before the current tombstone" once a
/// newer current version supersedes the tombstone.
pub async fn restore_trashed(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    let trashed = state.replica_coordinator.file_index_repository().list_trashed(group_id)?;
    let entry = trashed
        .into_iter()
        .find(|t| t.path == path)
        .ok_or_else(|| SyncError::NotFound(format!("no trashed file at {group_id}/{path}")))?;
    restore_to_version(state, group_id, path, entry.version_seq).await
}

/// spec "Restore without a version defaults to the most recent superseded
/// version": the `--version`-omitted default for `yadorilink restore
/// <path>`. `None` if the path has no superseded version to
/// restore to (only ever a `current` row, or no row at all).
pub fn most_recent_superseded_version_seq(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<Option<i64>, SyncError> {
    Ok(state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)?
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Superseded)
        .map(|v| v.version_seq))
}

/// Currently-connected, authorized-for-`group_id` sessions, paired with
/// their peer device id (the `BlockWorkQueue`'s "tried-by" key) — the
/// `state.peers.sessions` map is already keyed by device id, so this just
/// filters and preserves that pairing instead of discarding it.
pub(crate) fn candidate_sessions(
    state: &DaemonState,
    group_id: &str,
) -> Vec<(String, Arc<PeerSyncSession>)> {
    state.peers.sessions_for_group(group_id)
}

/// Resolves every block `blocks` references to a locally-present,
/// checksum-valid copy, fetching only genuinely-needed blocks from
/// currently-reachable peers. Shared by `hydrate_inner` and
/// `restore_to_version_inner` so the resolution *ordering* lives in exactly
/// one place instead of being duplicated (and previously diverging) between
/// the two.
///
/// Local-present-first: a block already cached locally is never fetched, so
/// content whose blocks are all present (and intact) resolves without
/// contacting any peer at all and therefore succeeds while offline. A peer
/// is consulted only for blocks that are missing — or that exist locally
/// but fail their checksum (corruption): those are treated as missing so a
/// peer holding a good copy repairs them (the fetch path's `put` overwrites
/// the corrupt bytes). The corruption check runs only when a peer is
/// actually reachable to fix it; with no candidate peer a corrupt-but-
/// present block is left in place for the ordinary corrupt-repair path
/// rather than forcing a pointless fetch attempt.
///
/// Returns the blocks still unavailable after any fetch — empty means every
/// block is now present locally. The caller maps a non-empty result to its
/// own operation-specific error (`HydrationFailed` vs
/// `VersionContentUnavailable`).
async fn resolve_blocks_local_first(
    state: &DaemonState,
    group_id: &str,
    path: &str,
    blocks: &[BlockInfo],
) -> Result<Vec<BlockInfo>, SyncError> {
    let hashes: Vec<String> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let present = state.block_store.present_blocks(&hashes)?;
    let candidates = candidate_sessions(state, group_id);

    let mut missing = Vec::new();
    for ((block, hash), already_present) in blocks.iter().zip(hashes.iter()).zip(present) {
        let has_group_provenance = state
            .replica_coordinator
            .sqlite()
            .dag_group_has_block_provenance(group_id, &block.hash)?;
        if !already_present || !has_group_provenance {
            missing.push(block.clone());
            continue;
        }
        // Present locally: only re-fetch if it's actually corrupt AND a
        // peer is reachable to supply a good copy. `get` verifies the
        // stored bytes against their hash; a `ChecksumMismatch` means the
        // on-disk block is corrupt, so it must be treated as missing
        // rather than counted as already-satisfied.
        if !candidates.is_empty()
            && matches!(state.block_store.get(hash), Err(StorageError::ChecksumMismatch { .. }))
        {
            missing.push(block.clone());
        }
    }

    if missing.is_empty() {
        return Ok(Vec::new());
    }

    // Registers this file as an active transfer for the *missing* blocks
    // only (already-present blocks never touch the network, so they're not
    // part of "progress" toward completing this fetch) — torn down
    // automatically (whatever the outcome) once `_progress_guard` drops.
    let bytes_total: u64 = missing.iter().map(|b| b.size as u64).sum();
    let blocks_total = missing.len() as u64;
    let _progress_guard = state.telemetry.begin_transfer(group_id, path, bytes_total, blocks_total);

    let unresolved = fetch_blocks_from_sessions(
        group_id,
        path,
        missing.clone(),
        &candidates,
        state.block_store.clone(),
        state.telemetry.transfer_progress_handle(),
        state.telemetry.recent_errors_handle(),
    )
    .await?;

    // Only successful fetches reach this point absent from `unresolved`:
    // the dispatcher verifies hash+size and persists bytes before resolving
    // work. Record provenance now, never when metadata is merely received.
    let unresolved_hashes: HashSet<&[u8]> =
        unresolved.iter().map(|block| block.hash.as_slice()).collect();
    let fetched_hashes: Vec<Vec<u8>> = missing
        .iter()
        .filter(|block| !unresolved_hashes.contains(block.hash.as_slice()))
        .map(|block| block.hash.clone())
        .collect();
    state
        .replica_coordinator
        .change_history_repository()
        .record_group_block_provenance(group_id, &fetched_hashes)?;
    Ok(unresolved)
}

fn local_root_for_group(
    state: &DaemonState,
    group_id: &str,
) -> Result<std::path::PathBuf, SyncError> {
    // Delegates rather than scanning `list_links` itself: an unordered `.find()`
    // silently took the FIRST match when a group had two live links, which is a
    // guess about which folder the user's files belong in. An orphaned link's
    // coordination-side authorization is gone -- treated the same as "no link
    // registered" here (the primitive filters `orphaned` for us), so hydration
    // never fetches/writes on-demand content into a folder that is no longer a
    // live sync target.
    state
        .replica_coordinator
        .link_repository()
        .live_link_local_path_for_group(group_id)?
        .map(std::path::PathBuf::from)
        .ok_or_else(|| SyncError::NotFound(format!("no link registered for group {group_id}")))
}

fn block_data_matches(block: &BlockInfo, data: &[u8]) -> bool {
    if data.len() != block.size as usize {
        return false;
    }
    let digest = Sha256::digest(data);
    digest[..] == block.hash[..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use sha2::{Digest, Sha256};
    use yadorilink_local_storage::FsBlockStore;

    fn block(hash_byte: u8) -> BlockInfo {
        BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 100 }
    }

    fn state_with_link(local_path: &str, group_id: &str) -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        sync_state.link_repository().add_link(local_path, group_id).unwrap();
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// An orphaned link resolves the same as "no link registered for this
    /// group" -- hydration must never fetch/write on-demand content into a
    /// folder that is no longer a live sync target, even though the link
    /// row itself is still present (and its files untouched).
    #[tokio::test]
    async fn local_root_for_group_treats_an_orphaned_link_as_absent() {
        let state = state_with_link("/home/alice/Photos", "group-1");

        assert_eq!(
            local_root_for_group(&state, "group-1").unwrap(),
            std::path::PathBuf::from("/home/alice/Photos")
        );

        state
            .replica_coordinator
            .link_repository()
            .mark_link_orphaned("/home/alice/Photos")
            .unwrap();

        assert!(
            local_root_for_group(&state, "group-1").is_err(),
            "an orphaned link must resolve the same as no link at all"
        );
    }

    /// `HydrationStateGuard`'s revert-on-drop must not clobber a
    /// DIFFERENT hydration attempt's own legitimate `Hydrating` row for
    /// the same path. `hydrate_inner` now holds `path_lock` for its whole
    /// attempt, so two attempts for the SAME path can no longer be
    /// mid-flight unlocked at once -- but `Drop` itself cannot await that
    /// (or any) lock, so this binding is defense-in-depth against any
    /// future caller of this guard that doesn't hold the lock for its
    /// whole duration the way `hydrate_inner` does today. A state-only
    /// CAS cannot tell "still my own in-flight attempt" apart from "a
    /// different attempt that happens to also be `Hydrating` right
    /// now" -- only binding to the authoring identity captured before
    /// marking `Hydrating` closes that.
    #[tokio::test]
    async fn hydration_state_guard_does_not_clobber_a_differently_authored_hydrating_row() {
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        sync_state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "doc.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        let old_hash = yadorilink_replica_domain::ids::ChangeHash([1u8; 32]);
        sync_state
            .file_index_repository()
            .set_authoring_change_hash("group-1", "doc.txt", &old_hash)
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "doc.txt",
                MaterializationState::Hydrating,
                &permit,
            )
            .unwrap();

        // This (stale) attempt's own guard, capturing the OLD identity --
        // as `hydrate_inner` does before marking the row `Hydrating`.
        let guard =
            HydrationStateGuard::new(sync_state.as_ref(), "group-1", "doc.txt", Some(old_hash));

        // A different, concurrent attempt supersedes the row with a
        // genuinely newer version and starts its OWN hydration --
        // landing back at `Hydrating`, but for a different identity.
        let new_hash = yadorilink_replica_domain::ids::ChangeHash([2u8; 32]);
        sync_state
            .file_index_repository()
            .set_authoring_change_hash("group-1", "doc.txt", &new_hash)
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "doc.txt",
                MaterializationState::Hydrating,
                &permit,
            )
            .unwrap();

        // The stale attempt's guard now drops (never `complete()`d) --
        // state alone matches (`Hydrating`), but the authoring identity
        // does not, so this must be a no-op.
        drop(guard);

        assert_eq!(
            sync_state
                .materialization_state_repository()
                .get_materialization_state("group-1", "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrating),
            "a stale attempt's guard must not touch a newer version's own in-flight hydration \
             just because the state value happens to match"
        );
        assert_eq!(
            sync_state
                .file_index_repository()
                .get_authoring_change_hash("group-1", "doc.txt")
                .unwrap(),
            Some(new_hash),
            "the newer version's identity must be untouched"
        );
    }

    /// Two concurrent `hydrate_inner` calls for the SAME path and the
    /// SAME version (same authoring hash) must not race destructively --
    /// an independent review's own counter-scenario to the authoring-
    /// bound guard alone: authoring identity distinguishes one FILE
    /// VERSION from another, not one in-flight ATTEMPT from another, so
    /// two attempts for the identical version are indistinguishable to
    /// that binding. `hydrate_inner` now holds `path_lock` for its whole
    /// duration specifically to close this: only one such attempt can be
    /// in flight for a path at a time, so a slower attempt's own guard
    /// can never drop while a faster, concurrent attempt for the same
    /// version is still between `reconstruct_file` and its own final
    /// commit. Both blocks are already locally present (seeded directly,
    /// with provenance recorded) so this test needs no live peer and no
    /// injected timing. `path_lock` fully serializes the two attempts,
    /// so the second call only ever starts after the first has
    /// committed; it re-marks the row `Hydrating` and redundantly
    /// reconstructs rather than short-circuiting via `AlreadyComplete`
    /// (there is no pre-lock fast path for an already-`Hydrated` row),
    /// but both attempts still converge on the same correct end state.
    /// Per an independent review: on the default single-threaded test
    /// runtime, with both blocks resolving synchronously from local
    /// state, this test cannot force the two attempts to interleave
    /// inside the locked region -- it verifies the end state is correct
    /// under strict serialization, not that a genuine interleaving is
    /// handled safely. The race-closing argument rests on `path_lock`
    /// being a real, shared, non-reentrant mutex (a structural
    /// guarantee), not on this test empirically reproducing the race.
    #[tokio::test]
    async fn concurrent_hydrations_of_the_same_version_do_not_race() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        sync_state
            .link_repository()
            .add_link(&root_dir.path().to_string_lossy(), "group-1")
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root_dir.path(),
            "group-1",
            sync_state.as_ref(),
        )
        .unwrap();

        let content = b"concurrent hydration content";
        let hash = Sha256::digest(content).to_vec();
        store.put(content).unwrap();
        sync_state
            .change_history_repository()
            .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
            .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "doc.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "doc.txt",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();

        let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
        state.install_test_root_commit_authority("group-1");

        let state_a = state.clone();
        let state_b = state.clone();
        let task_a =
            tokio::spawn(async move { hydrate_inner(&state_a, "group-1", "doc.txt").await });
        let task_b =
            tokio::spawn(async move { hydrate_inner(&state_b, "group-1", "doc.txt").await });

        let (result_a, result_b) = tokio::join!(task_a, task_b);

        assert!(result_a.unwrap().is_ok(), "concurrent attempt A must succeed");
        assert!(result_b.unwrap().is_ok(), "concurrent attempt B must succeed");
        assert_eq!(
            sync_state
                .materialization_state_repository()
                .get_materialization_state("group-1", "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "the row must end up genuinely Hydrated, not stuck at Placeholder despite correct \
             disk content"
        );
        assert_eq!(
            std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
            content,
            "disk content must be exactly what was hydrated"
        );
    }

    /// An independent review's counter-scenario: `hydrate` (the shell IPC
    /// `HydrateRequest` handler's only entry point, per
    /// `shell_ipc::handle_message`) is reachable for an arbitrary caller-
    /// supplied path with no upstream check on whether that path is
    /// already fully materialized -- a real client cannot be trusted to
    /// only ever ask for a genuine `Placeholder`. Before this fast path,
    /// `hydrate_inner` would still unconditionally mark an already-
    /// `Hydrated` row `Hydrating` and reconstruct it from the *indexed*
    /// blocks, silently overwriting any content an editor wrote to disk
    /// after the row was last hydrated but before its own watcher event
    /// reached the index.
    #[tokio::test]
    async fn hydrate_of_an_already_hydrated_path_is_a_no_op_and_never_touches_disk() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        sync_state
            .link_repository()
            .add_link(&root_dir.path().to_string_lossy(), "group-1")
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root_dir.path(),
            "group-1",
            sync_state.as_ref(),
        )
        .unwrap();

        let indexed_content = b"indexed content from the last real hydration";
        let hash = Sha256::digest(indexed_content).to_vec();
        store.put(indexed_content).unwrap();
        sync_state
            .change_history_repository()
            .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
            .unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "doc.txt".into(),
                    size: indexed_content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: indexed_content.len() as u32 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "doc.txt",
                MaterializationState::Hydrated,
                &permit,
            )
            .unwrap();

        // An unnoticed local edit: disk now differs from the indexed
        // blocks, but nothing has reprocessed this path through the local
        // watcher yet. A stray `HydrateRequest` for this same path must
        // not touch it.
        let edited_content = b"an editor's unsaved-by-the-index-yet edit";
        std::fs::write(root_dir.path().join("doc.txt"), edited_content).unwrap();

        let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
        state.install_test_root_commit_authority("group-1");
        hydrate_inner(&state, "group-1", "doc.txt").await.unwrap();

        assert_eq!(
            std::fs::read(root_dir.path().join("doc.txt")).unwrap(),
            edited_content,
            "an already-Hydrated row must never be reconstructed from its indexed blocks"
        );
        assert_eq!(
            sync_state
                .materialization_state_repository()
                .get_materialization_state("group-1", "doc.txt")
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "the row's state must be left exactly as it was"
        );
    }

    /// A symlink or directory record is never a `Placeholder` waiting on
    /// `hydrate` -- it is always fully materialized the moment it's
    /// adopted (`peer_session::materialize_symlink_at`). Before this kind
    /// guard, `hydrate_inner` had no way to know a given path wasn't an
    /// ordinary file, so it would call `reconstruct_file` with this
    /// record's (always-empty, for a symlink) block list, replacing the
    /// real on-disk symlink with an empty regular file.
    #[tokio::test]
    async fn hydrate_of_a_symlink_path_never_replaces_it_with_a_regular_file() {
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        sync_state
            .link_repository()
            .add_link(&root_dir.path().to_string_lossy(), "group-1")
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root_dir.path(),
            "group-1",
            sync_state.as_ref(),
        )
        .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "link.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        sync_state
            .file_index_repository()
            .set_record_kind(
                "group-1",
                "link.txt",
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &permit,
            )
            .unwrap();
        std::os::unix::fs::symlink("target.txt", root_dir.path().join("link.txt")).unwrap();

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
        state.install_test_root_commit_authority("group-1");
        hydrate_inner(&state, "group-1", "link.txt").await.unwrap();

        let out_path = root_dir.path().join("link.txt");
        assert!(
            std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
            "hydrate must never replace a symlink record's on-disk symlink"
        );
        assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
    }

    /// An independent review's finding: `verify_write_target_within_root`
    /// is not a pure check -- it `create_dir_all`s the sync root and the
    /// target's parent directory as a side effect. If `VerifiedRoot::
    /// verify` ran AFTER that call instead of before, a root whose
    /// mountpoint was unmounted and replaced by something else at the
    /// same path would still get a brand-new directory created on it
    /// (for a nested path whose parent doesn't exist yet) before the
    /// identity mismatch was ever detected.
    #[tokio::test]
    async fn hydrate_creates_no_directories_under_a_root_whose_marker_no_longer_matches() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        sync_state
            .link_repository()
            .add_link(&root_dir.path().to_string_lossy(), "group-1")
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root_dir.path(),
            "group-1",
            sync_state.as_ref(),
        )
        .unwrap();

        let content = b"nested placeholder content";
        let hash = Sha256::digest(content).to_vec();
        store.put(content).unwrap();
        sync_state
            .change_history_repository()
            .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
            .unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "sub/nested/doc.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "sub/nested/doc.txt",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();

        std::fs::remove_file(
            root_dir.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
        let result = hydrate_inner(&state, "group-1", "sub/nested/doc.txt").await;

        assert!(
            result.is_err(),
            "hydration under a root whose marker no longer matches must be refused"
        );
        assert!(
            !root_dir.path().join("sub").exists(),
            "no directory must be created under a root that fails identity verification, even \
             for a nested path whose parent doesn't exist yet"
        );
    }

    /// An independent review's finding: sync-core's own
    /// `hydrate_file_with_timeout_locked` applies the recorded exec bit
    /// right after `reconstruct_file`, but the daemon's `hydrate_inner`
    /// never did -- the index kept the correct bit, but disk never got
    /// it applied after an on-demand hydration.
    #[cfg(unix)]
    #[tokio::test]
    async fn hydrate_applies_the_recorded_exec_bit_after_reconstruct() {
        use std::os::unix::fs::PermissionsExt;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        sync_state
            .link_repository()
            .add_link(&root_dir.path().to_string_lossy(), "group-1")
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root_dir.path(),
            "group-1",
            sync_state.as_ref(),
        )
        .unwrap();

        let content = b"#!/bin/sh\necho hi\n";
        let hash = Sha256::digest(content).to_vec();
        store.put(content).unwrap();
        sync_state
            .change_history_repository()
            .record_group_block_provenance("group-1", std::slice::from_ref(&hash))
            .unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        sync_state
            .file_index_repository()
            .upsert_file(
                "group-1",
                &yadorilink_replica_domain::file::FileRecord {
                    path: "run.sh".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &permit,
            )
            .unwrap();
        sync_state
            .file_index_repository()
            .set_exec_bit("group-1", "run.sh", true, &permit)
            .unwrap();
        sync_state
            .materialization_state_repository()
            .set_materialization_state(
                "group-1",
                "run.sh",
                MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();

        let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
        state.install_test_root_commit_authority("group-1");
        hydrate_inner(&state, "group-1", "run.sh").await.unwrap();

        let mode = std::fs::metadata(root_dir.path().join("run.sh")).unwrap().permissions().mode();
        assert_ne!(
            mode & 0o100,
            0,
            "hydration must apply the recorded exec bit, not just fetch the content"
        );
    }

    fn block_for_data(data: &[u8]) -> BlockInfo {
        BlockInfo { hash: Sha256::digest(data).to_vec(), offset: 0, size: data.len() as u32 }
    }

    #[test]
    fn block_data_matches_requires_expected_hash_and_size() {
        let data = b"valid block bytes";
        let block = block_for_data(data);
        assert!(block_data_matches(&block, data));
        assert!(!block_data_matches(&block, b"different bytes"));

        let wrong_size = BlockInfo { size: block.size + 1, ..block };
        assert!(!block_data_matches(&wrong_size, data));
    }

    /// Blocks split across two peers each holding a disjoint subset
    /// resolve correctly — each peer only ever pops blocks it hasn't
    /// tried yet, and different peers can pop
    /// different blocks from the same queue without stepping on each other.
    #[test]
    fn disjoint_subsets_resolve_independently() {
        let mut queue = BlockWorkQueue::new(vec![block(1), block(2)]);
        let first = queue.pop_for("peer-a").unwrap();
        let second = queue.pop_for("peer-b").unwrap();
        assert_ne!(first.hash, second.hash, "two peers should not pop the same block concurrently");
        assert!(queue.pop_for("peer-a").is_none());
        assert!(queue.pop_for("peer-b").is_none());
    }

    /// A block not-found on one peer is requeued and successfully served
    /// by a different candidate that hasn't tried it yet.
    #[test]
    fn not_found_block_is_reassigned_to_a_different_peer() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        let b = queue.pop_for("peer-a").unwrap();
        queue.mark_not_found(b, "peer-a", &["peer-a".into(), "peer-b".into()]);

        // peer-a already tried it — must not get it again.
        assert!(queue.pop_for("peer-a").is_none());
        // peer-b hasn't tried it yet — must be offered it.
        let retried = queue.pop_for("peer-b").unwrap();
        assert_eq!(retried.hash, block(1).hash);
    }

    /// A block a peer merely timed out on (as opposed to explicitly
    /// reported not-found) must not be immediately re-offered to that same
    /// peer -- see `timeout_backoff`'s doc comment for why an unthrottled
    /// immediate retry can amplify the very congestion that caused the
    /// timeout. A different peer is unaffected by another peer's cooldown.
    #[test]
    fn timed_out_block_cools_down_before_the_same_peer_can_retry_it() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        let b = queue.pop_for("peer-a").unwrap();
        queue.mark_timed_out(b, "peer-a");

        assert!(
            queue.pop_for("peer-a").is_none(),
            "peer-a just timed out on this block and must cool down before retrying it"
        );
        let retried = queue.pop_for("peer-b").unwrap();
        assert_eq!(
            retried.hash,
            block(1).hash,
            "a different peer's own cooldown is independent and must not be held back"
        );
    }

    /// `has_pending_backoff` must report a block cooling down after a
    /// timeout so a worker whose own `pop_for` just returned `None` knows
    /// to keep polling rather than conclude the queue is genuinely empty
    /// (see `has_pending_backoff`'s own doc comment).
    #[test]
    fn has_pending_backoff_reflects_a_block_cooling_down_after_a_timeout() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        assert!(!queue.has_pending_backoff(), "nothing has timed out yet");

        let b = queue.pop_for("peer-a").unwrap();
        queue.mark_timed_out(b, "peer-a");
        assert!(queue.has_pending_backoff(), "peer-a's block is now cooling down");
    }

    /// A block missing from every candidate is correctly reported as
    /// still-missing (dropped from the queue) rather than retried forever.
    #[test]
    fn block_missing_from_every_candidate_is_dropped_not_retried_forever() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        let candidates = vec!["peer-a".to_string(), "peer-b".to_string()];

        let b = queue.pop_for("peer-a").unwrap();
        queue.mark_not_found(b, "peer-a", &candidates);
        let b = queue.pop_for("peer-b").unwrap();
        queue.mark_not_found(b, "peer-b", &candidates);

        assert!(queue.pop_for("peer-a").is_none());
        assert!(queue.pop_for("peer-b").is_none());
        assert_eq!(
            queue.remaining(),
            vec![block(1)],
            "exhausted block must surface as still-missing"
        );
    }

    /// An empty missing-block list is a no-op — `fetch_blocks_from_sessions`
    /// itself short-circuits before ever touching the queue, but the queue
    /// type must also behave sanely if constructed empty.
    #[test]
    fn empty_queue_has_nothing_to_pop() {
        let mut queue = BlockWorkQueue::new(vec![]);
        assert!(queue.pop_for("peer-a").is_none());
        assert!(queue.remaining().is_empty());
    }

    /// Worker-starvation race: a block checked out via
    /// `pop_for` but not yet resolved must be reflected as `outstanding`,
    /// even though the queue itself is momentarily empty — this is exactly
    /// what tells a `fetch_blocks_from_sessions` worker with nothing left
    /// to pop that giving up right now would be premature, since the
    /// checked-out block could still turn back into queued work.
    #[test]
    fn has_outstanding_reflects_a_block_still_checked_out() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        assert!(!queue.has_outstanding(), "nothing checked out yet");

        let b = queue.pop_for("peer-a").unwrap();
        assert!(queue.has_outstanding(), "peer-a is holding the only block");
        assert!(
            queue.pop_for("peer-b").is_none(),
            "queue is empty while peer-a still holds the block"
        );

        queue.mark_not_found(b, "peer-a", &["peer-a".into(), "peer-b".into()]);
        assert!(!queue.has_outstanding(), "resolved (as not-found) — no longer outstanding");
        assert!(
            queue.pop_for("peer-b").is_some(),
            "requeued by mark_not_found and now available to a different peer"
        );
    }

    /// The success path (`resolve_fetched`) must release `outstanding` just
    /// like the not-found path does — it's the only other way a checked-out
    /// block gets resolved, and forgetting to call it would leave
    /// `has_outstanding` permanently (and wrongly) true, stalling every
    /// other worker in an endless idle-poll once the real work is done.
    #[test]
    fn resolve_fetched_clears_outstanding_on_success() {
        let mut queue = BlockWorkQueue::new(vec![block(1)]);
        let _b = queue.pop_for("peer-a").unwrap();
        assert!(queue.has_outstanding());

        queue.resolve_fetched();
        assert!(!queue.has_outstanding());
    }

    /// An independent review's finding: before `PoppedBlock` existed,
    /// `remaining()` (`queue` + `exhausted`) had no way to account for a
    /// block popped via `pop_for` and never resolved -- e.g. a worker
    /// task panicking somewhere in its own loop body between the pop and
    /// whichever of `resolve_fetched`/`mark_not_found`/`mark_timed_out`
    /// it was heading toward. That block would vanish from every
    /// tracking set at once: not `queue`, not `exhausted`, `outstanding`
    /// never decremented -- and `fetch_blocks_from_sessions`'s own caller
    /// computes "successfully fetched" as `missing - remaining()`, so a
    /// vanished block would be silently counted as fetched and have its
    /// provenance recorded despite never being written to the block
    /// store. `PoppedBlock::drop`, simulated directly here without
    /// needing a real panic, must requeue instead.
    #[test]
    fn a_popped_block_dropped_without_being_resolved_is_requeued_not_lost() {
        let work = Arc::new(StdMutex::new(BlockWorkQueue::new(vec![block(1)])));
        let (popped, _still_pending) = PoppedBlock::pop_for(&work, "peer-a");
        let guard = popped.expect("the only block is eligible for peer-a");
        assert_eq!(work.lock().unwrap().outstanding, 1, "pop_for must mark the block outstanding");

        drop(guard); // simulates the owning worker task panicking here

        let q = work.lock().unwrap();
        assert_eq!(q.outstanding, 0, "an unresolved drop must release outstanding");
        assert_eq!(q.queue.len(), 1, "the block must be requeued, not lost");
        drop(q);

        // Requeued with no `tried_by` penalty against peer-a and no
        // cooldown backoff either -- a worker panic is not evidence
        // about the peer, so the exact same peer must be immediately
        // eligible to retry it.
        let (popped_again, _) = PoppedBlock::pop_for(&work, "peer-a");
        assert!(
            popped_again.is_some(),
            "the requeued block must still be immediately eligible for the same peer"
        );
    }

    #[tokio::test]
    async fn fetch_blocks_from_sessions_is_a_no_op_for_empty_missing_list() {
        let result = fetch_blocks_from_sessions(
            "group-1",
            "file.bin",
            vec![],
            &[],
            Arc::new(
                yadorilink_local_storage::FsBlockStore::new(tempfile::tempdir().unwrap().path())
                    .unwrap(),
            ),
            crate::transfer_progress::TransferProgressTracker::new(),
            crate::recent_errors::RecentErrorLog::new(),
        )
        .await;
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fetch_blocks_from_sessions_returns_missing_blocks_when_no_candidates() {
        let store = Arc::new(
            yadorilink_local_storage::FsBlockStore::new(tempfile::tempdir().unwrap().path())
                .unwrap(),
        );
        let missing = vec![block(1), block(2)];
        let result = fetch_blocks_from_sessions(
            "group-1",
            "file.bin",
            missing.clone(),
            &[],
            store,
            crate::transfer_progress::TransferProgressTracker::new(),
            crate::recent_errors::RecentErrorLog::new(),
        )
        .await;
        assert_eq!(result.unwrap(), missing, "with no candidate sessions, nothing can be fetched");
    }

    // --- disk-space preflight tests ---

    const GROUP: &str = "group-1";
    const PATH: &str = "big.bin";

    /// The returned `TempDir` backs the *block store*, kept alive for the
    /// caller's whole test — never used as a link root itself (each test
    /// creates its own separate `tempfile::tempdir` for that, so a
    /// "leaves nothing on disk under the link root" assertion isn't
    /// confused by the block store's own directory tree living alongside it).
    fn test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-under-test".to_string(), sync_state, store);
        (state, store_dir)
    }

    /// Registers a link at `root` and indexes a hydrated file record for it.
    fn seed_link(
        state: &DaemonState,
        root: &std::path::Path,
        on_demand: bool,
        size: u64,
    ) -> yadorilink_replica_domain::file::FileRecord {
        let local_path = root.to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        // `evict_file` now verifies the root's adopted identity before
        // touching it -- without this, eviction fails closed on every
        // caller of this fixture, silently (callers here use `let _ =
        // preflight_disk_pressure(...)`), leaving the file materialized
        // and masking the actual eviction-path assertions this fixture
        // exists to exercise.
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root,
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();
        if on_demand {
            state
                .replica_coordinator
                .link_repository()
                .set_materialization_policy(
                    &local_path,
                    yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
                )
                .unwrap();
        }
        let record = yadorilink_replica_domain::file::FileRecord {
            path: PATH.to_string(),
            size,
            mtime_unix_nanos: 0,
            blocks: vec![block_for_data(&vec![0u8; size as usize])],
            deleted: false,
        };
        // Record the seeded version as originating on a peer ("device-seed",
        // matching the version-vector author above), not this device. On-demand
        // cache reclamation only confirms custody for peer-origin content, so
        // eviction-path tests need a real peer origin here.
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &record, "device-seed", &permit)
            .unwrap();
        record
    }

    #[tokio::test]
    async fn hydration_commit_rejects_a_disk_edit_after_its_initial_snapshot() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        let out_path = root.path().join(PATH);
        let initial_identity = disk_identity(&out_path).unwrap();

        std::fs::write(&out_path, b"local edit while hydration fetched blocks").unwrap();

        assert!(
            hydration_commit_decision(
                &state,
                GROUP,
                PATH,
                &record,
                root.path(),
                &out_path,
                initial_identity,
            )
            .unwrap()
                == HydrationCommitDecision::Stale,
            "a changed disk identity must prevent stale hydration from overwriting local bytes"
        );
    }

    #[tokio::test]
    async fn hydration_commit_rejects_a_journaled_local_edit() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        let out_path = root.path().join(PATH);
        let initial_identity = disk_identity(&out_path).unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .dirty_path_repository()
            .record_dirty_path(GROUP, PATH, "created_or_modified", 1, &permit)
            .unwrap();

        assert!(
            hydration_commit_decision(
                &state,
                GROUP,
                PATH,
                &record,
                root.path(),
                &out_path,
                initial_identity,
            )
            .unwrap()
                == HydrationCommitDecision::Stale,
            "a dirty-journal entry must prevent stale hydration commit"
        );
    }

    /// The gap the old `(size, mtime)`-only `DiskIdentity` could not see: a
    /// same-size overwrite whose mtime is restored exactly. Only `ctime`
    /// can still distinguish it (see `peer_session::disk_race_fingerprint`'s
    /// own doc comment) -- proves `hydration_commit_decision` now goes
    /// through that stronger fingerprint rather than the weaker local pair
    /// it used to compute. Skips gracefully, like
    /// `peer_session.rs`'s own `disk_race_fingerprint` tests, if this
    /// filesystem's ctime granularity happens not to distinguish a
    /// same-tick write-restore-observe sequence.
    #[cfg(unix)]
    fn raw_ctime(path: &std::path::Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.ctime(), meta.ctime_nsec())
    }

    #[tokio::test]
    async fn hydration_commit_rejects_a_same_size_same_mtime_edit_ctime_permitting() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 4);
        let out_path = root.path().join(PATH);

        std::fs::write(&out_path, b"AAAA").unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrating, &permit)
            .unwrap();
        let initial_identity = disk_identity(&out_path).unwrap();
        let original_mtime = std::fs::symlink_metadata(&out_path).unwrap().modified().unwrap();
        #[cfg(unix)]
        let ctime_before = raw_ctime(&out_path);

        std::fs::write(&out_path, b"BBBB").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&out_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&out_path).unwrap().modified().unwrap(),
            original_mtime,
            "precondition: the mtime was restored exactly, so only ctime can betray the write"
        );
        // Independent of `disk_identity`/`disk_race_fingerprint` (the
        // function under test) on purpose: reads raw `ctime` off metadata
        // directly, so this skip-if-coarse check stays meaningful even if
        // `disk_identity` itself were ever weakened back to a (size, mtime)
        // pair -- comparing two `disk_identity()` calls here for the skip
        // condition would make it tautological with the assertion below and
        // silently stop testing anything the moment the fix regressed.
        #[cfg(unix)]
        if raw_ctime(&out_path) == ctime_before {
            eprintln!(
                "skipping: this filesystem's ctime granularity could not distinguish a \
                 same-tick write-restore-observe sequence"
            );
            return;
        }
        #[cfg(not(unix))]
        {
            eprintln!("skipping: ctime is unix-only, this fix has no residual coverage here");
            return;
        }

        assert_eq!(
            hydration_commit_decision(
                &state,
                GROUP,
                PATH,
                &record,
                root.path(),
                &out_path,
                initial_identity,
            )
            .unwrap(),
            HydrationCommitDecision::Stale,
            "a same-size, same-mtime local edit must still be caught via ctime and must prevent \
             a stale hydration commit from overwriting it"
        );
    }

    /// `hydrate_inner` captures the group's root once at hydration start and
    /// reuses it for the whole (possibly multi-second) block-fetch window.
    /// If the group is unlinked and relinked to a different root during
    /// that window, the commit must refuse rather than write to the now
    /// no-longer-linked root `out_path` was built from --
    /// `local_root_for_group` re-reads the live link table fresh on every
    /// call (see its own doc comment), so re-resolving and comparing here
    /// is enough to catch it.
    #[tokio::test]
    async fn hydration_commit_rejects_after_the_group_is_relinked_elsewhere() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        let out_path = root.path().join(PATH);
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrating, &permit)
            .unwrap();
        let initial_identity = disk_identity(&out_path).unwrap();

        state
            .replica_coordinator
            .link_repository()
            .remove_link(&root.path().to_string_lossy())
            .unwrap();
        let new_root = tempfile::tempdir().unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&new_root.path().to_string_lossy(), GROUP)
            .unwrap();

        assert_eq!(
            hydration_commit_decision(
                &state,
                GROUP,
                PATH,
                &record,
                root.path(),
                &out_path,
                initial_identity,
            )
            .unwrap(),
            HydrationCommitDecision::Stale,
            "a group relinked to a different root during the fetch must not let hydration \
             commit to the now-stale root"
        );
    }

    /// a preflight that would breach headroom fails with
    /// `DiskPressure` and marks the link Degraded — forced deterministically
    /// via a headroom override far larger than any real disk's free space
    /// (this crate's tests must not depend on the host machine's actual
    /// free space; confirmed a real concern elsewhere in this change).
    #[tokio::test]
    async fn preflight_disk_pressure_rejects_and_marks_degraded_when_it_would_breach() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        seed_link(&state, root.path(), false, 1000);

        let err =
            preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(u64::MAX / 2))
                .unwrap_err();
        assert!(matches!(err, SyncError::DiskPressure { .. }));
        assert!(state.is_link_degraded(&root.path().to_string_lossy()));
    }

    /// The converse: a write comfortably under headroom (a zero-byte
    /// override) is allowed and never marks the link degraded.
    #[tokio::test]
    async fn preflight_disk_pressure_allows_a_write_under_headroom() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        seed_link(&state, root.path(), false, 1000);

        preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(0)).unwrap();
        assert!(!state.is_link_degraded(&root.path().to_string_lossy()));
    }

    /// Under disk pressure, an `OnDemand` link's eviction
    /// sweep runs *before* the preflight fails — evicting an
    /// already-hydrated, unpinned file back to a placeholder. Doesn't
    /// assert the overall preflight then succeeds (that depends on freeing
    /// enough *real* bytes to satisfy an intentionally enormous forced
    /// headroom, not practical to stage in a test); asserts the sweep
    /// itself ran, which is the behavior this actually adds.
    #[tokio::test]
    async fn preflight_disk_pressure_runs_eviction_sweep_for_on_demand_link_first() {
        let _pipeline_connected =
            yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        state.install_test_root_commit_authority(GROUP);
        let block_hash = state.block_store.put(&vec![0u8; 1000]).unwrap();
        // Materialize it as "hydrated" on disk and record an access time so
        // it's a real eviction candidate (least-recently-used).
        std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated, &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .touch_last_accessed(GROUP, PATH, 100)
            .unwrap();
        // An instantaneous peer confirmation is deliberately insufficient for
        // physical CAS deletion until durable remote custody leases exist.
        state.set_custody_confirmer(std::sync::Arc::new(
            |_: &str,
             _: &str,
             _: &yadorilink_replica_domain::ids::VersionHash,
             _: &[VersionBlock]| { true },
        ));

        let _ = preflight_disk_pressure(
            &state,
            GROUP,
            PATH,
            root.path(),
            record.size,
            Some(u64::MAX / 2),
        );

        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state(GROUP, PATH)
                .unwrap(),
            Some(MaterializationState::Placeholder),
            "the disk-pressure-triggered eviction sweep should have evicted the only candidate"
        );
        assert!(
            state.block_store.exists(&block_hash).unwrap(),
            "without a durable remote custody lease, placeholdering must retain the CAS block"
        );
    }

    /// a pinned file is never evicted by the disk-pressure sweep,
    /// even when it's the only OnDemand content on a pressured volume.
    #[tokio::test]
    async fn preflight_disk_pressure_never_evicts_a_pinned_file() {
        // Otherwise the on-demand-pipeline gate alone would make this
        // assertion pass vacuously (nothing evicted because eviction is
        // refused outright, not because pinning was honored) -- see
        // `preflight_disk_pressure`'s own doc comment for the gate this
        // enables past.
        let _pipeline_connected =
            yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        state.install_test_root_commit_authority(GROUP);
        std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated, &permit)
            .unwrap();
        state.replica_coordinator.file_index_repository().set_pinned(GROUP, PATH, true).unwrap();

        let _ = preflight_disk_pressure(
            &state,
            GROUP,
            PATH,
            root.path(),
            record.size,
            Some(u64::MAX / 2),
        );

        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state(GROUP, PATH)
                .unwrap(),
            Some(MaterializationState::Hydrated),
            "a pinned file must never be evicted by the disk-pressure trigger"
        );
    }

    /// A `DiskPressure` rejection leaves no partial temp file
    /// under the link root — the preflight runs (and fails) before
    /// `reconstruct_file`'s temp-path-then-rename write ever begins.
    #[tokio::test]
    async fn preflight_disk_pressure_rejection_leaves_no_partial_temp_file() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        seed_link(&state, root.path(), false, 1000);

        let _ = preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(u64::MAX / 2));

        // The root-identity marker `seed_link`'s adoption wrote is
        // legitimate infrastructure, not a partial materialization
        // artefact -- excluded from sync and never something a preflight
        // rejection is responsible for cleaning up.
        let entries: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .filter(|entry| {
                entry.as_ref().is_ok_and(|e| {
                    !yadorilink_root_authority::root_identity::is_root_marker_relative_path(
                        e.file_name(),
                    )
                })
            })
            .collect();
        assert!(
            entries.is_empty(),
            "a rejected preflight must leave nothing on disk under the link root, found {entries:?}"
        );
    }

    /// disk pressure on one file's preflight doesn't affect a
    /// second, independent file on an unrelated (unpressured) volume —
    /// modeled here as two calls with different headroom overrides against
    /// two different roots, since `preflight_disk_pressure` is inherently
    /// scoped to the `root` it's given.
    #[tokio::test]
    async fn disk_pressure_on_one_link_does_not_affect_another() {
        let (state, _store_dir) = test_state();
        let root_a = tempfile::tempdir().unwrap();
        seed_link(&state, root_a.path(), false, 1000);
        let root_b = tempfile::tempdir().unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root_b.path().to_string_lossy(), "group-2")
            .unwrap();
        let record_b = yadorilink_replica_domain::file::FileRecord {
            path: "other.bin".to_string(),
            size: 500,
            mtime_unix_nanos: 0,
            blocks: vec![block_for_data(&[1u8; 500])],
            deleted: false,
        };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file("group-2", &record_b, &permit)
            .unwrap();

        let err_a =
            preflight_disk_pressure(&state, GROUP, PATH, root_a.path(), 1000, Some(u64::MAX / 2))
                .unwrap_err();
        assert!(matches!(err_a, SyncError::DiskPressure { .. }));
        assert!(state.is_link_degraded(&root_a.path().to_string_lossy()));

        // The second link's volume was never checked, let alone marked —
        // a completely independent `preflight_disk_pressure` call for it
        // (0 headroom required) still succeeds.
        preflight_disk_pressure(&state, "group-2", "other.bin", root_b.path(), 500, Some(0))
            .unwrap();
        assert!(!state.is_link_degraded(&root_b.path().to_string_lossy()));
    }

    // --- restore engine ---

    /// Writes `data`'s block into `state`'s block store, records it as
    /// obtained through `group_id` (mirroring what `LocalChangeProcessor`
    /// does for a real local edit — see `record_group_block_provenance`'s
    /// doc comment), and returns the `BlockInfo` describing it — the
    /// restore tests' equivalent of `seed_link`, but for a version whose
    /// content actually needs to be present (or deliberately absent) in the
    /// block store, not just referenced by an index row the way `seed_link`'s
    /// single-block records are.
    fn put_block(state: &DaemonState, group_id: &str, data: &[u8]) -> BlockInfo {
        let hash = state.block_store.put(data).unwrap();
        let hash_bytes = hex::decode(&hash).unwrap();
        state
            .replica_coordinator
            .change_history_repository()
            .record_group_block_provenance(group_id, std::slice::from_ref(&hash_bytes))
            .unwrap();
        BlockInfo { hash: hash_bytes, offset: 0, size: data.len() as u32 }
    }

    fn record_with_blocks(
        path: &str,
        blocks: Vec<BlockInfo>,
        size: u64,
    ) -> yadorilink_replica_domain::file::FileRecord {
        yadorilink_replica_domain::file::FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 0,
            blocks,
            deleted: false,
        }
    }

    /// restoring a version whose blocks are all still present
    /// locally succeeds without needing any peer, writes the restored
    /// content to disk, and — the load-bearing assertion —
    /// creates a **new** version rather than mutating the one being
    /// restored: the original version-1 row is unchanged and still
    /// queryable, and the restored content becomes version 3 (not a
    /// renumbered/rewritten version 1).
    #[tokio::test]
    async fn restore_to_version_of_a_fully_local_version_succeeds_and_creates_a_new_version() {
        let (state, _store_dir) = test_state();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        // Local edits route through `replica_coordinator`
        // (`LocalChangeProcessor` is built from it, not `sync_state`, since
        // 7D-10.7) -- mirror the override there too, or this test's real
        // provider (wired by `DaemonState::new`/`build`) fires instead and
        // requires actual group-policy setup this fixture doesn't have.
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let v1_block = put_block(&state, GROUP, b"version one content");
        let v1 = record_with_blocks(PATH, vec![v1_block.clone()], 19);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();

        let v2_block = put_block(&state, GROUP, b"version two content!!");
        let v2 = record_with_blocks(PATH, vec![v2_block], 21);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
            .unwrap();

        // Restore back to version 1's content.
        restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

        assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"version one content");

        let versions = state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
        assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite an old one");
        assert_eq!(versions[0].version_seq, 3, "the restored content is the newest version");
        assert_eq!(versions[0].blocks, vec![v1_block]);
        assert_eq!(
            versions[0].state,
            yadorilink_replica_domain::session_state::VersionState::Current
        );
        let author = state
            .replica_coordinator
            .file_index_repository()
            .get_authoring_change_hash(GROUP, PATH)
            .unwrap();
        assert!(author.is_some(), "restore must publish its own DAG author identity");
        assert!(state
            .replica_coordinator
            .change_history_repository()
            .dag_has_change_or_pruned(GROUP, &author.unwrap())
            .unwrap());
        // Version 1 itself is completely untouched.
        let original_v1 = versions.iter().find(|v| v.version_seq == 1).unwrap();
        assert_eq!(original_v1.size, 19);
    }

    /// An independent review's finding: `VersionRecord` carries its own
    /// per-row `record_kind`/`symlink_target`/`exec_bit` (captured at the
    /// time that row was current, not just read live off the `current`
    /// row -- see `VersionRecord::record_kind`'s own doc comment), but
    /// restore used to ignore all three and unconditionally call
    /// `reconstruct_file`, which always writes an ordinary regular file.
    /// Restoring a symlink version must recreate a real symlink, not an
    /// empty regular file.
    #[tokio::test]
    async fn restoring_a_symlink_version_recreates_a_real_symlink_not_an_empty_regular_file() {
        let (state, _store_dir) = test_state();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        // Local edits route through `replica_coordinator`
        // (`LocalChangeProcessor` is built from it, not `sync_state`, since
        // 7D-10.7) -- mirror the override there too, or this test's real
        // provider (wired by `DaemonState::new`/`build`) fires instead and
        // requires actual group-policy setup this fixture doesn't have.
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        // Version 1: a symlink.
        let v1 = record_with_blocks(PATH, vec![], 0);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(
                GROUP,
                PATH,
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &permit,
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_symlink_target(GROUP, PATH, Some(b"v1-target"))
            .unwrap();

        // Version 2: an ordinary regular file, superseding the symlink.
        let v2_block = put_block(&state, GROUP, b"version two content");
        let v2 = record_with_blocks(PATH, vec![v2_block], 20);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(
                GROUP,
                PATH,
                yadorilink_replica_domain::file::RecordKind::File,
                &permit,
            )
            .unwrap();

        // Restore back to the symlink version.
        restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

        let out_path = root.path().join(PATH);
        assert!(
            std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
            "restoring a symlink version must recreate a real symlink"
        );
        assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("v1-target"));
        // The `current` row's own classification must move too -- not just
        // the disk write. A review's finding: `commit_restore_operation`
        // used to only `upsert_file_in_tx` (a bare `FileRecord`, which has
        // no room for `record_kind`), leaving the index still saying
        // `File` even after a symlink was correctly recreated on disk. A
        // later `hydrate_inner` trusting that stale `record_kind` (its own
        // kind guard added this round) would then treat the just-restored
        // symlink as an ordinary file and could destroy it.
        assert_eq!(
            state.replica_coordinator.file_index_repository().get_record_kind(GROUP, PATH).unwrap(),
            Some(yadorilink_replica_domain::file::RecordKind::Symlink),
            "the current row's record_kind must be updated to match the restored version"
        );
        assert_eq!(
            state
                .replica_coordinator
                .file_index_repository()
                .get_symlink_target(GROUP, PATH)
                .unwrap(),
            Some(b"v1-target".to_vec()),
            "the current row's symlink_target must be updated to match the restored version"
        );
    }

    /// The specific danger a stale `current` row classification creates:
    /// without updating `record_kind` at restore commit time, a later
    /// ordinary `hydrate` for the same path would read the STALE `File`
    /// classification, pass `hydrate_inner`'s own kind guard (added this
    /// round specifically to protect symlinks from exactly this), and
    /// destroy the symlink this test just restored.
    #[tokio::test]
    async fn hydrate_after_a_symlink_restore_does_not_destroy_it() {
        let (state, _store_dir) = test_state();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        // Local edits route through `replica_coordinator`
        // (`LocalChangeProcessor` is built from it, not `sync_state`, since
        // 7D-10.7) -- mirror the override there too, or this test's real
        // provider (wired by `DaemonState::new`/`build`) fires instead and
        // requires actual group-policy setup this fixture doesn't have.
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        state.install_test_root_commit_authority(GROUP);
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let v1 = record_with_blocks(PATH, vec![], 0);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(
                GROUP,
                PATH,
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &permit,
            )
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_symlink_target(GROUP, PATH, Some(b"v1-target"))
            .unwrap();

        let v2_block = put_block(&state, GROUP, b"version two content");
        let v2 = record_with_blocks(PATH, vec![v2_block], 20);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(
                GROUP,
                PATH,
                yadorilink_replica_domain::file::RecordKind::File,
                &permit,
            )
            .unwrap();

        restore_to_version(&state, GROUP, PATH, 1).await.unwrap();
        // Deliberately `Placeholder`, not `Hydrated`, so this test isolates
        // the kind guard specifically rather than being saved by the
        // separate already-`Hydrated` fast path: if `record_kind` were
        // still stale (`File`) because the restore commit hadn't updated
        // it, the kind guard would silently do nothing and hydration would
        // fall through to `reconstruct_file` with this symlink's empty
        // block list, destroying it.
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, MaterializationState::Placeholder, &permit)
            .unwrap();

        hydrate_inner(&state, GROUP, PATH).await.unwrap();

        let out_path = root.path().join(PATH);
        assert!(
            std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
            "a later hydrate must never destroy a just-restored symlink"
        );
    }

    /// `restore_to_version_inner`'s `reconstruct_file` call has no
    /// escape-checking of its own (see `reconstruct_file`'s doc comment --
    /// it is always the caller's job). If an intermediate directory
    /// component of `path` is a symlink out of the sync root, the write
    /// must be refused rather than following it -- the write-side twin of
    /// the tombstone symlink-escape guard `verify_delete_target` closes on
    /// the delete side, and the same gap `hydrate_inner`'s own
    /// `verify_write_target_within_root` call closes for ordinary
    /// hydration. Verified against a REAL file living entirely outside the
    /// sync root, so a regression here shows up as real data loss in the
    /// assertions, not a passing-by-accident check.
    #[cfg(unix)]
    #[tokio::test]
    async fn restore_refuses_to_write_through_an_intermediate_directory_symlink() {
        let (state, _store_dir) = test_state();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]));
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        // Local edits route through `replica_coordinator`
        // (`LocalChangeProcessor` is built from it, not `sync_state`, since
        // 7D-10.7) -- mirror the override there too, or this test's real
        // provider (wired by `DaemonState::new`/`build`) fires instead and
        // requires actual group-policy setup this fixture doesn't have.
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();

        // A real, valuable file living entirely outside the sync root.
        let outside_dir = tempfile::tempdir().unwrap();
        let victim_path = outside_dir.path().join("victim.txt");
        std::fs::write(&victim_path, b"do not overwrite me").unwrap();

        // An intermediate directory symlink inside the sync root,
        // redirecting "external/*" to the outside directory.
        std::os::unix::fs::symlink(outside_dir.path(), root.path().join("external")).unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let escaping_path = "external/victim.txt";
        let v1_block = put_block(&state, GROUP, b"version one content");
        let v1 = record_with_blocks(escaping_path, vec![v1_block.clone()], 19);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();
        let v2_block = put_block(&state, GROUP, b"version two content!!");
        let v2 = record_with_blocks(escaping_path, vec![v2_block], 21);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
            .unwrap();

        let result = restore_to_version(&state, GROUP, escaping_path, 1).await;
        assert!(result.is_err(), "a restore through an intermediate symlink must be refused");
        assert_eq!(
            std::fs::read(&victim_path).unwrap(),
            b"do not overwrite me",
            "a restore must never write through an intermediate directory symlink out of the \
             sync root"
        );
    }

    /// A version whose blocks are missing locally and
    /// unavailable from any peer (none connected here) fails with the
    /// specific `VersionContentUnavailable` error — not a generic
    /// I/O/not-found error — and leaves both the index and the on-disk
    /// file completely untouched.
    #[tokio::test]
    async fn restore_fails_clearly_when_no_peer_holds_the_missing_blocks() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();

        // A version referencing a block that was never actually written to
        // this device's block store (as if evicted, or an on-demand link
        // that never fetched it) — `record_with_blocks` only builds the
        // `BlockInfo`/index row, it never calls `put_block`.
        let phantom_block =
            BlockInfo { hash: Sha256::digest(b"never fetched").to_vec(), offset: 0, size: 13 };
        let v1 = record_with_blocks(PATH, vec![phantom_block], 13);
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();

        let err = restore_to_version_with_timeout(
            &state,
            GROUP,
            PATH,
            1,
            std::time::Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, SyncError::VersionContentUnavailable(_)),
            "expected a specific version-content error, got {err:?}"
        );

        assert!(
            !root.path().join(PATH).exists(),
            "a failed restore must not leave a partial file on disk"
        );
        let versions = state.replica_coordinator.sqlite().dag_list_versions(GROUP, PATH).unwrap();
        assert_eq!(versions.len(), 1, "a failed restore must not add or change any version row");
    }

    /// Restoring a trashed file recovers its last version
    /// before deletion as a new current version, and the file is live
    /// again — the `trash restore` path (`SyncState::mark_deleted` is this
    /// crate's local-delete primitive, exercised directly here rather than
    /// through the full watcher, matching this module's other tests'
    /// direct-`SyncState`-manipulation style).
    #[tokio::test]
    async fn restore_trashed_recovers_a_deleted_files_last_content_as_a_new_current_version() {
        let (state, _store_dir) = test_state();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]));
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        // Local edits route through `replica_coordinator`
        // (`LocalChangeProcessor` is built from it, not `sync_state`, since
        // 7D-10.7) -- mirror the override there too, or this test's real
        // provider (wired by `DaemonState::new`/`build`) fires instead and
        // requires actual group-policy setup this fixture doesn't have.
        state.replica_coordinator.set_local_change_auth_provider(Arc::new(|_| {
            Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER)
        }));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let block = put_block(&state, GROUP, b"about to be deleted");
        let v1 = record_with_blocks(PATH, vec![block], 19);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .mark_deleted(GROUP, PATH, "device-a", &permit)
            .unwrap();

        assert!(
            state
                .replica_coordinator
                .file_index_repository()
                .get_file(GROUP, PATH)
                .unwrap()
                .unwrap()
                .deleted
        );
        assert_eq!(
            state.replica_coordinator.file_index_repository().list_trashed(GROUP).unwrap().len(),
            1
        );

        restore_trashed(&state, GROUP, PATH).await.unwrap();

        assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"about to be deleted");
        let current = state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, PATH)
            .unwrap()
            .unwrap();
        assert!(!current.deleted, "the file must be live again after a trash restore");
    }

    /// `yadorilink restore <path>` without `--version` resolves
    /// to the most recent *superseded* version, not the current one (there
    /// would be nothing to restore *to* if it picked the current version)
    /// and not an older superseded version if a newer one exists.
    #[tokio::test]
    async fn most_recent_superseded_version_seq_picks_the_newest_non_current_version() {
        let (state, _store_dir) = test_state();
        state.replica_coordinator.link_repository().add_link("/tmp/unused", GROUP).unwrap();
        assert_eq!(
            most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
            None,
            "no rows at all yet"
        );

        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        let v1 = record_with_blocks(PATH, vec![], 0);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v1, "device-a", &permit)
            .unwrap();
        assert_eq!(
            most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
            None,
            "only a current version exists, nothing superseded yet"
        );

        let v2 = record_with_blocks(PATH, vec![], 0);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v2, "device-a", &permit)
            .unwrap();
        let v3 = record_with_blocks(PATH, vec![], 0);
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin(GROUP, &v3, "device-a", &permit)
            .unwrap();

        assert_eq!(most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(), Some(2));
    }
}
