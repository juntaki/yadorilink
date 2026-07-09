//! Daemon-level orchestration for on-demand-sync's hydrate/pin/unpin/evict
//! operations (D6): the sync-core primitives
//! (`PeerSyncSession::fetch_block`, `materialization::evict_file`) are
//! each scoped to one peer or pure local state — this module is what picks
//! *which* connected peer(s) to hydrate from, and resolves a folder group
//! to its local root path for the operations that need one.
//!
//! D5: hydration no longer tries one whole-file transfer per
//! peer sequentially. A file's missing blocks are
//! partitioned across every currently-reachable, authorized peer session
//! and fetched concurrently, with a block a peer reports not-found
//! reassigned to a different peer rather than failing the whole attempt,
//! and a single file-level deadline covering the entire dispatch.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};

use sha2::{Digest, Sha256};
use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::chunker::reconstruct_file;
use yadorilink_sync_core::materialization::{evict_file, run_disk_pressure_eviction_sweep};
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::types::{BlockInfo, MaterializationPolicy, MaterializationState};
use yadorilink_sync_core::SyncError;

use crate::daemon_state::DaemonState;

/// A single deadline for the *entire* multi-session dispatch () —
/// supersedes what used to be `PeerSyncSession::hydrate_file`'s per-session
/// timeout for the daemon-orchestrated hydration path. Same value as
/// `PeerSyncSession::DEFAULT_HYDRATION_TIMEOUT` (unchanged budget, moved
/// ownership).
const HYDRATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-block bound on a single `PeerSyncSession::fetch_block` call inside
/// `fetch_blocks_from_sessions`'s worker loop (COR-5 follow-up). Diagnosed
/// via an instrumented, reproducible run of
/// `yadorilink-daemon/tests/multi_peer_hydration.rs`: `fetch_block` sends its
/// `BlockRequest` and the peer's `handle_block_request` logs a successful
/// `send()` of the matching `BlockResponse` (so the peer *did* answer), yet
/// the requester's `PeerChannel::recv()` loop never observes that response
/// arriving — an occasional lost/undelivered message on an otherwise fully
/// responsive, connected session, reproducible specifically under this
/// test's burst of several simultaneous peer connections. Before this
/// constant existed, a worker's `session.fetch_block(...).await` had no
/// bound of its own, so one unlucky request silently ate the *entire*
/// file-level `HYDRATION_TIMEOUT` budget — that worker's task simply never
/// returned, `workers.join_next()` never observed it finish, and the whole
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

// PERF-5 (in-flight window): `fetch_blocks_from_sessions` runs several
// worker "lanes" concurrently *per candidate session*, not just one.
// Before PERF-5, each peer session could have at most one `fetch_block`
// request outstanding at a time — the request round-trip (bounded by real
// network RTT, not local CPU) was fully serialized per peer, so a single
// high-latency peer trickled blocks in one at a time no matter how many
// blocks it actually held. `PeerSyncSession::fetch_block` already supports
// several concurrent in-flight requests to the *same* peer correctly
// (`pending_block_requests` is keyed by hash with a waiter list per hash,
// SEC-25's multi-waiter design) — nothing about the session itself
// required this one-at-a-time pattern, it was purely an artifact of
// spawning exactly one worker task per candidate here. Running several
// lanes per candidate lets that same session pipeline multiple
// outstanding `BlockRequest`s, amortizing RTT across the window instead of
// paying it once per block. `BlockWorkQueue::pop_for`/`mark_not_found`/
// `mark_timed_out`/`resolve_fetched` are all keyed per popped block, not
// per worker, so multiple lanes sharing one `peer_id` need no changes
// there: each lane only ever resolves the specific block it itself popped.
//
// PERF-5 originally fixed this lane count at a flat constant (4) for every
// candidate, with no adaptation to observed conditions: "fast links are
// throttled below their capacity; slow/lossy links are pushed past
// theirs." The lane
// count is now read per-candidate from `PeerSyncSession::fetch_window()`
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
/// (): tracks which blocks remain to fetch and, per block, which
/// candidate peer device ids have already tried and failed to provide it —
/// so a not-found response reassigns the block to a different candidate
/// instead of giving up, and a block every candidate has tried is
/// correctly recognized as exhausted rather than retried forever.
struct BlockWorkQueue {
    queue: VecDeque<BlockInfo>,
    tried_by: HashMap<Vec<u8>, HashSet<String>>,
    /// Blocks every candidate has tried and failed to provide — tracked
    /// separately from `queue` (which only ever holds work still worth
    /// attempting), so `remaining()` can report them as still-missing
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
}

impl BlockWorkQueue {
    fn new(blocks: Vec<BlockInfo>) -> Self {
        Self {
            queue: blocks.into(),
            tried_by: HashMap::new(),
            exhausted: Vec::new(),
            outstanding: 0,
        }
    }

    /// Pops a block `peer_id` hasn't tried yet, cycling past (but not
    /// discarding) ones it has — those stay queued for another worker.
    /// `None` if this worker has no untried work available right now.
    /// Every `Some` returned here must eventually be paired with exactly
    /// one of `mark_not_found`/`resolve_fetched`, which keeps
    /// `outstanding` (see its doc comment) accurate.
    fn pop_for(&mut self, peer_id: &str) -> Option<BlockInfo> {
        let len = self.queue.len();
        for _ in 0..len {
            let block = self.queue.pop_front()?;
            let already_tried =
                self.tried_by.get(&block.hash).is_some_and(|tried| tried.contains(peer_id));
            if already_tried {
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
    /// moves to `exhausted` (surfacing in `remaining()`'s still-missing
    /// report) instead of being retried forever. Use this only for an
    /// unambiguous "not there" signal (an explicit not-found reply, a
    /// hash mismatch, a local store-write failure) — see
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
    /// once — `exhausted` after exactly one `all_candidates.len() == 1`
    /// timeout, with no other peer to reassign to and no path back to
    /// retrying the same one. Not marking `tried_by` here means the
    /// block is immediately eligible for *any* peer to pick up again,
    /// including the one that just timed out — still bounded overall by
    /// the outer file-level `HYDRATION_TIMEOUT`, which a peer stuck in a
    /// genuine timeout loop will eventually hit.
    fn mark_timed_out(&mut self, block: BlockInfo) {
        self.outstanding -= 1;
        self.queue.push_back(block);
    }

    /// Everything that ended up unfetched: work still queued (shouldn't
    /// normally happen once every worker has run out of untried blocks,
    /// but included for safety) plus everything exhausted.
    fn remaining(self) -> Vec<BlockInfo> {
        self.queue.into_iter().chain(self.exhausted).collect()
    }
}

/// Fetches `missing` by partitioning it across every session in
/// `candidates`, one worker task per session running concurrently (design
/// D1-D3). A block a session reports not-found is reassigned to a
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
async fn fetch_blocks_from_sessions(
    group_id: &str,
    file_path: &str,
    missing: Vec<BlockInfo>,
    candidates: &[(String, Arc<PeerSyncSession>)],
    block_store: Arc<dyn BlockStore + Send + Sync>,
    progress: crate::transfer_progress::TransferProgressTracker,
    recent_errors: crate::recent_errors::RecentErrorLog,
) -> Vec<BlockInfo> {
    if missing.is_empty() || candidates.is_empty() {
        return missing;
    }

    let candidate_ids: Vec<String> = candidates.iter().map(|(id, _)| id.clone()).collect();
    let work = Arc::new(StdMutex::new(BlockWorkQueue::new(missing)));

    let mut workers = tokio::task::JoinSet::new();
    // PERF-5: several lanes per candidate, not one — see the comment
    // block above `BlockWorkQueue` for the original PERF-5 rationale. The
    // lane count
    // itself is no longer a fixed constant: each session's own adaptive
    // window (`fetch_window`) decides how many lanes *that* candidate gets
    // this round, based on RTT/timeout signals observed on that session
    // across every hydration so far — a fast/healthy peer gets more
    // concurrent lanes, a slow/lossy one gets fewer, and neither can ever
    // exceed the fixed security ceiling `fetch_window` itself is clamped
    // to (task 1.2). Extra lanes beyond what a given candidate actually
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
            workers.spawn(async move {
            loop {
                // Scoped so the `MutexGuard` is fully dropped before any
                // `.await` below (both for correctness — never hold a
                // std `Mutex` guard across an await — and because a
                // `MutexGuard` isn't `Send`, which `JoinSet::spawn`
                // requires of this whole future).
                let popped_and_outstanding = {
                    let mut q = work.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let popped = q.pop_for(&peer_id);
                    (popped, q.has_outstanding())
                };
                let block = match popped_and_outstanding {
                    (Some(block), _) => block,
                    (None, true) => {
                        // See `BlockWorkQueue::outstanding`'s doc comment:
                        // another worker still has a block checked out
                        // (possibly mid-`PER_BLOCK_FETCH_TIMEOUT`) that
                        // could turn back into queued work once it
                        // resolves — an empty `queue` right now isn't
                        // necessarily final, so poll instead of exiting.
                        tokio::time::sleep(WORKER_IDLE_POLL_INTERVAL).await;
                        continue;
                    }
                    (None, false) => break, // queue empty, nothing outstanding anywhere: truly done
                };
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
                            work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(block, &peer_id, &candidate_ids);
                            continue;
                        }
                        let data_len = data.len() as u64;
                        // PERF-1: `BlockStore::put` is synchronous
                        // `std::fs` I/O plus a full SHA-256 hash — move it
                        // off this tokio worker thread so a big/slow write
                        // doesn't stall every other task (other peers'
                        // messages, other lanes' fetches) sharing it.
                        let put_result = {
                            let block_store = block_store.clone();
                            tokio::task::spawn_blocking(move || block_store.put(&data)).await
                        };
                        match put_result {
                            Ok(Ok(_)) => {
                                // counted as "done" only once the
                                // block is actually durably stored — written
                                // to the block store as it arrives.
                                progress.record_block_done(&group_id, &file_path, data_len, &peer_id);
                                work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).resolve_fetched()
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(error = %e, peer = %peer_id, "failed to store a fetched block");
                                work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(block, &peer_id, &candidate_ids);
                            }
                            Err(join_err) => {
                                tracing::warn!(error = %join_err, peer = %peer_id, "block store write task panicked");
                                work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(block, &peer_id, &candidate_ids);
                            }
                        }
                    }
                    Ok(Ok(None)) => {
                        work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(block, &peer_id, &candidate_ids);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, peer = %peer_id, "block fetch request failed; treating as not found for this peer");
                        work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_not_found(block, &peer_id, &candidate_ids);
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
                        work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).mark_timed_out(block);
                    }
                }
            }
        });
        }
    }
    while workers.join_next().await.is_some() {}

    Arc::into_inner(work)
        .expect("all worker tasks have completed, no other Arc clones remain")
        .into_inner()
        .unwrap()
        .remaining()
}

/// Hydrates `path` in `group_id` by partitioning its missing blocks across
/// every currently-connected, authorized peer session and fetching
/// concurrently (D5), bounded by one file-level
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
    let result = tokio::time::timeout(timeout, hydrate_inner(state, group_id, path))
        .await
        .unwrap_or_else(|_elapsed| {
            let _ = state.sync_state.set_materialization_state(
                group_id,
                path,
                MaterializationState::Placeholder,
            );
            Err(SyncError::HydrationFailed(path.to_string()))
        });
    // Every hydration failure (disk pressure, no reachable candidate,
    // timed-out/incomplete fetch, or anything else `hydrate_inner` can
    // return) lands in the recent-error ring buffer here, centrally —
    // `SyncError::category`'s doc comment for why this is safe to record
    // unconditionally (never derived from `Display`, so never a
    // path/volume/hash).
    if let Err(e) = &result {
        state.recent_errors.record(e.category(), "hydration");
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
    let Some(record) = state.sync_state.get_file(group_id, path)? else {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    };
    if record.deleted {
        return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
    }

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
        preflight_disk_pressure(state, group_id, path, &root, record.size, headroom_override)?;
    }

    state.sync_state.set_materialization_state(group_id, path, MaterializationState::Hydrating)?;

    let candidates = candidate_sessions(state, group_id);
    if candidates.is_empty() {
        state.sync_state.set_materialization_state(
            group_id,
            path,
            MaterializationState::Placeholder,
        )?;
        return Err(SyncError::HydrationFailed(path.to_string()));
    }

    let hashes: Vec<_> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let present = state.block_store.present_blocks(&hashes)?;
    let missing: Vec<BlockInfo> = record
        .blocks
        .iter()
        .zip(present)
        .filter(|(_, already_present)| !already_present)
        .map(|(block, _)| block.clone())
        .collect();

    // Registers this file as an active transfer for the *missing* blocks
    // only (already-present blocks never touch the network, so they're
    // not part of "progress" toward completing this fetch) — torn down
    // automatically (whatever the outcome) once `_progress_guard` drops at
    // the end of this function or via the outer `hydrate_with_timeout`
    // timeout cancelling this future.
    let bytes_total: u64 = missing.iter().map(|b| b.size as u64).sum();
    let blocks_total = missing.len() as u64;
    let _progress_guard = state.transfer_progress.begin(group_id, path, bytes_total, blocks_total);

    let still_missing = fetch_blocks_from_sessions(
        group_id,
        path,
        missing,
        &candidates,
        state.block_store.clone(),
        state.transfer_progress.clone(),
        state.recent_errors.clone(),
    )
    .await;

    if !still_missing.is_empty() {
        state.sync_state.set_materialization_state(
            group_id,
            path,
            MaterializationState::Placeholder,
        )?;
        return Err(SyncError::HydrationFailed(path.to_string()));
    }

    let out_path = root.join(path);
    reconstruct_file(state.block_store.as_ref(), &out_path, &record.blocks)?;
    state.sync_state.set_materialization_state(group_id, path, MaterializationState::Hydrated)?;
    // A snappier recovery signal beyond the periodic backoff re-check
    // (task 3.5) — any successful hydration on this link proves its
    // volume currently has headroom, so a stale Degraded entry (if any)
    // can clear immediately rather than waiting out the next scheduled
    // re-check. A no-op if the link wasn't degraded.
    state.clear_link_degraded(&root.to_string_lossy());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    state.sync_state.touch_last_accessed(group_id, path, now)?;
    Ok(())
}

/// Fails cleanly with `SyncError::DiskPressure` (and marks `group_id`'s
/// link Degraded, task 3.4) if hydrating `path` (a write of
/// `required_bytes`, the file's full size) would breach the configured
/// headroom on the volume hosting `root`. Before failing, if `group_id`'s
/// link is `OnDemand`, runs the disk-pressure-triggered eviction sweep
/// (task 4.1) and re-checks once — giving it a chance to free enough
/// space for the operation to still succeed: the sweep runs and completes
/// before a pending hydration/materialization is failed (task 4.2).
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
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.group_id == group_id)
        .is_some_and(|l| l.materialization_policy == MaterializationPolicy::OnDemand);
    if is_on_demand {
        let _ =
            run_disk_pressure_eviction_sweep(&state.sync_state, root, group_id, headroom_override);
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
/// `hydrate`, ) if it isn't already `Hydrated`. If the file is
/// already `Hydrated`, this only sets the pin flag and never needs a peer
/// at all.
pub async fn pin(state: &Arc<DaemonState>, group_id: &str, path: &str) -> Result<(), SyncError> {
    let already_hydrated = state.sync_state.get_materialization_state(group_id, path)?
        == Some(MaterializationState::Hydrated);
    if already_hydrated {
        return state.sync_state.set_pinned(group_id, path, true);
    }

    // Set the pin flag regardless of whether hydration succeeds below, so
    // it takes effect the moment a peer *does* become available, matching
    // the previous sequential implementation's behavior.
    state.sync_state.set_pinned(group_id, path, true)?;
    hydrate(state, group_id, path).await
}

/// Unpins `path` — pure local state, no peer needed (spec "Unpinning
/// allows eviction").
pub fn unpin(state: &DaemonState, group_id: &str, path: &str) -> Result<(), SyncError> {
    state.sync_state.set_pinned(group_id, path, false)
}

/// Manually evicts `path` back to a placeholder (spec "Manual Eviction").
/// Resolves `group_id` to its local root path via the registered link.
pub fn evict(state: &DaemonState, group_id: &str, path: &str) -> Result<(), SyncError> {
    // A block-store/materialization mutation, same as `hydrate_inner`'s
    // guard above.
    let _write_activity = state.begin_write_activity();
    let root = local_root_for_group(state, group_id)?;
    evict_file(&state.sync_state, &root, group_id, path)
}

// --- restore engine ---

/// 3.3: resolves `version_seq`'s content — verifying local
/// presence of every block it references and, for any missing block,
/// attempting a peer fetch scoped to those hashes via the same
/// multi-session dispatch `hydrate` uses — and, on success, writes it to
/// disk and indexes it through the *ordinary* local-change path (design
/// D3): a brand-new current version, with the local device's version-
/// vector counter bumped and the change broadcast to peers exactly like
/// any other local edit. Never mutates or reorders any existing version
/// row; a concurrent edit racing this (adopted from a peer while this
/// runs) is caught by the same `SyncState::path_lock`-guarded read-
/// compare-write section `LocalChangeProcessor::process_event`/
/// `PeerSyncSession::reconcile_one_file` already use, so it resolves via
/// the existing version-vector conflict machinery with no restore-
/// specific special-casing (task 3.5).
///
/// Fails with `SyncError::VersionContentUnavailable` (never a generic I/O
/// or not-found error) and makes no index or on-disk change if some block
/// the version needs is missing locally and unavailable from every
/// currently-reachable, authorized peer within the timeout (task 3.3).
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
    // COR-5: restore both reads the current record (to compute the new
    // version vector correctly) and writes new content — the exact same
    // read-compare-write shape `process_event`/`reconcile_one_file` are
    // already serialized against each other for, via this same lock. See
    // `SyncState::path_lock`'s doc comment for the race this closes.
    let path_lock = state.sync_state.path_lock(group_id, path);
    let _guard = path_lock.lock().await;

    let Some(version) = state.sync_state.get_version(group_id, path, version_seq)? else {
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

    let hashes: Vec<_> = version.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let present = state.block_store.present_blocks(&hashes)?;
    let missing: Vec<BlockInfo> = version
        .blocks
        .iter()
        .zip(present)
        .filter(|(_, already_present)| !already_present)
        .map(|(block, _)| block.clone())
        .collect();

    if !missing.is_empty() {
        let candidates = candidate_sessions(state, group_id);
        // A version restore is the same kind of block-fetch transfer as
        // an ordinary hydration — see `hydrate_inner`'s identical
        // `begin`/guard usage just above.
        let bytes_total: u64 = missing.iter().map(|b| b.size as u64).sum();
        let blocks_total = missing.len() as u64;
        let _progress_guard =
            state.transfer_progress.begin(group_id, path, bytes_total, blocks_total);
        let still_missing = fetch_blocks_from_sessions(
            group_id,
            path,
            missing,
            &candidates,
            state.block_store.clone(),
            state.transfer_progress.clone(),
            state.recent_errors.clone(),
        )
        .await;
        if !still_missing.is_empty() {
            let err =
                SyncError::VersionContentUnavailable(format!("{group_id}/{path}@{version_seq}"));
            state.recent_errors.record(err.category(), "restore_version");
            return Err(err);
        }
    }

    // Content is fully resolved locally now — write it to disk and adopt
    // it as an ordinary new local version. No index or on-disk change was
    // made above this point, matching task 3.3's "no partial change on
    // failure" requirement.
    let out_path = root.join(path);
    reconstruct_file(state.block_store.as_ref(), &out_path, &version.blocks)?;

    let current = state.sync_state.get_file(group_id, path)?;
    let mut new_version = current.map(|c| c.version).unwrap_or_default();
    new_version.increment(&state.device_id);
    let now_unix_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let new_record = yadorilink_sync_core::types::FileRecord {
        path: path.to_string(),
        size: version.size,
        mtime_unix_nanos: now_unix_nanos,
        version: new_version,
        blocks: version.blocks,
        deleted: false,
    };
    state.sync_state.upsert_file_with_origin(group_id, &new_record, &state.device_id)?;
    // Same fan-out as `DaemonState::broadcast_change`'s other callers
    // (`announce_local_change`, the forward-rebroadcast task): connected
    // peers see this exactly like any other local edit (spec "Restored
    // content propagates like a normal edit").
    state.broadcast_change(group_id, vec![new_record]).await;
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
    let trashed = state.sync_state.list_trashed(group_id)?;
    let entry = trashed
        .into_iter()
        .find(|t| t.path == path)
        .ok_or_else(|| SyncError::NotFound(format!("no trashed file at {group_id}/{path}")))?;
    restore_to_version(state, group_id, path, entry.version_seq).await
}

/// spec "Restore without a version defaults to the most recent superseded
/// version": the `--version`-omitted default for `yadorilink restore
/// <path>` (task 6.2). `None` if the path has no superseded version to
/// restore to (only ever a `current` row, or no row at all).
pub fn most_recent_superseded_version_seq(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<Option<i64>, SyncError> {
    Ok(state
        .sync_state
        .list_versions(group_id, path)?
        .into_iter()
        .find(|v| v.state == yadorilink_sync_core::index::VersionState::Superseded)
        .map(|v| v.version_seq))
}

/// Currently-connected, authorized-for-`group_id` sessions, paired with
/// their peer device id (the `BlockWorkQueue`'s "tried-by" key) — the
/// `state.sessions` map is already keyed by device id, so this just
/// filters and preserves that pairing instead of discarding it.
fn candidate_sessions(state: &DaemonState, group_id: &str) -> Vec<(String, Arc<PeerSyncSession>)> {
    state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|(_, session)| session.shares_group(group_id))
        .map(|(device_id, session)| (device_id.clone(), session.clone()))
        .collect()
}

fn local_root_for_group(
    state: &DaemonState,
    group_id: &str,
) -> Result<std::path::PathBuf, SyncError> {
    let links = state.sync_state.list_links()?;
    links
        .into_iter()
        .find(|l| l.group_id == group_id)
        .map(|l| std::path::PathBuf::from(l.local_path))
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
    use sha2::{Digest, Sha256};

    fn block(hash_byte: u8) -> BlockInfo {
        BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 100 }
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

    /// COR-5 follow-up (worker-starvation race): a block checked out via
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
        assert!(result.is_empty());
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
        assert_eq!(result, missing, "with no candidate sessions, nothing can be fetched");
    }

    // --- disk-space preflight tests (task 3.6) ---

    const GROUP: &str = "group-1";
    const PATH: &str = "big.bin";

    /// The returned `TempDir` backs the *block store*, kept alive for the
    /// caller's whole test — never used as a link root itself (each test
    /// creates its own separate `tempfile::tempdir()` for that, so a
    /// "leaves nothing on disk under the link root" assertion isn't
    /// confused by the block store's own directory tree living alongside it).
    fn test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state =
            Arc::new(yadorilink_sync_core::index::SyncState::open_in_memory().unwrap());
        let state = DaemonState::new("device-under-test".to_string(), sync_state, store);
        (state, store_dir)
    }

    /// Registers a link at `root` and indexes a hydrated file record for it.
    fn seed_link(
        state: &DaemonState,
        root: &std::path::Path,
        on_demand: bool,
        size: u64,
    ) -> yadorilink_sync_core::types::FileRecord {
        let local_path = root.to_string_lossy().to_string();
        state.sync_state.add_link(&local_path, GROUP).unwrap();
        if on_demand {
            state
                .sync_state
                .set_materialization_policy(
                    &local_path,
                    yadorilink_sync_core::types::MaterializationPolicy::OnDemand,
                )
                .unwrap();
        }
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-seed");
        let record = yadorilink_sync_core::types::FileRecord {
            path: PATH.to_string(),
            size,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![block_for_data(&vec![0u8; size as usize])],
            deleted: false,
        };
        state.sync_state.upsert_file(GROUP, &record).unwrap();
        record
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

    /// task 4.1/4.2: under disk pressure, an `OnDemand` link's eviction
    /// sweep runs *before* the preflight fails — evicting an
    /// already-hydrated, unpinned file back to a placeholder. Doesn't
    /// assert the overall preflight then succeeds (that depends on freeing
    /// enough *real* bytes to satisfy an intentionally enormous forced
    /// headroom, not practical to stage in a test); asserts the sweep
    /// itself ran, which is the behavior task 4.1/4.2 actually adds.
    #[tokio::test]
    async fn preflight_disk_pressure_runs_eviction_sweep_for_on_demand_link_first() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        // Materialize it as "hydrated" on disk and record an access time so
        // it's a real eviction candidate (least-recently-used).
        std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
        state
            .sync_state
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated)
            .unwrap();
        state.sync_state.touch_last_accessed(GROUP, PATH, 100).unwrap();

        let _ = preflight_disk_pressure(
            &state,
            GROUP,
            PATH,
            root.path(),
            record.size,
            Some(u64::MAX / 2),
        );

        assert_eq!(
            state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
            Some(MaterializationState::Placeholder),
            "the disk-pressure-triggered eviction sweep should have evicted the only candidate"
        );
    }

    /// a pinned file is never evicted by the disk-pressure sweep,
    /// even when it's the only OnDemand content on a pressured volume.
    #[tokio::test]
    async fn preflight_disk_pressure_never_evicts_a_pinned_file() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let record = seed_link(&state, root.path(), true, 1000);
        std::fs::write(root.path().join(PATH), vec![0u8; 1000]).unwrap();
        state
            .sync_state
            .set_materialization_state(GROUP, PATH, MaterializationState::Hydrated)
            .unwrap();
        state.sync_state.set_pinned(GROUP, PATH, true).unwrap();

        let _ = preflight_disk_pressure(
            &state,
            GROUP,
            PATH,
            root.path(),
            record.size,
            Some(u64::MAX / 2),
        );

        assert_eq!(
            state.sync_state.get_materialization_state(GROUP, PATH).unwrap(),
            Some(MaterializationState::Hydrated),
            "a pinned file must never be evicted by the disk-pressure trigger"
        );
    }

    /// task 3.3/3.6: a `DiskPressure` rejection leaves no partial temp file
    /// under the link root — the preflight runs (and fails) before
    /// `reconstruct_file`'s temp-path-then-rename write ever begins.
    #[tokio::test]
    async fn preflight_disk_pressure_rejection_leaves_no_partial_temp_file() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        seed_link(&state, root.path(), false, 1000);

        let _ = preflight_disk_pressure(&state, GROUP, PATH, root.path(), 1000, Some(u64::MAX / 2));

        let entries: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
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
        state.sync_state.add_link(&root_b.path().to_string_lossy(), "group-2").unwrap();
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-seed");
        let record_b = yadorilink_sync_core::types::FileRecord {
            path: "other.bin".to_string(),
            size: 500,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![block_for_data(&[1u8; 500])],
            deleted: false,
        };
        state.sync_state.upsert_file("group-2", &record_b).unwrap();

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

    /// Writes `data`'s block into `state`'s block store and returns the
    /// `BlockInfo` describing it — the restore tests' equivalent of
    /// `seed_link`, but for a version whose content actually needs to be
    /// present (or deliberately absent) in the block store, not just
    /// referenced by an index row the way `seed_link`'s single-block
    /// records are.
    fn put_block(state: &DaemonState, data: &[u8]) -> BlockInfo {
        let hash = state.block_store.put(data).unwrap();
        BlockInfo { hash: hex::decode(hash).unwrap(), offset: 0, size: data.len() as u32 }
    }

    fn record_with_blocks(
        path: &str,
        device_id: &str,
        version_counter: u64,
        blocks: Vec<BlockInfo>,
        size: u64,
    ) -> yadorilink_sync_core::types::FileRecord {
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        for _ in 0..version_counter {
            version.increment(device_id);
        }
        yadorilink_sync_core::types::FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 0,
            version,
            blocks,
            deleted: false,
        }
    }

    /// restoring a version whose blocks are all still present
    /// locally succeeds without needing any peer, writes the restored
    /// content to disk, and — the load-bearing assertion () —
    /// creates a **new** version rather than mutating the one being
    /// restored: the original version-1 row is unchanged and still
    /// queryable, and the restored content becomes version 3 (not a
    /// renumbered/rewritten version 1).
    #[tokio::test]
    async fn restore_to_version_of_a_fully_local_version_succeeds_and_creates_a_new_version() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.sync_state.add_link(&local_path, GROUP).unwrap();

        let v1_block = put_block(&state, b"version one content");
        let v1 = record_with_blocks(PATH, "device-a", 1, vec![v1_block.clone()], 20);
        state.sync_state.upsert_file_with_origin(GROUP, &v1, "device-a").unwrap();

        let v2_block = put_block(&state, b"version two content!!");
        let v2 = record_with_blocks(PATH, "device-a", 2, vec![v2_block], 21);
        state.sync_state.upsert_file_with_origin(GROUP, &v2, "device-a").unwrap();

        // Restore back to version 1's content.
        restore_to_version(&state, GROUP, PATH, 1).await.unwrap();

        assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"version one content");

        let versions = state.sync_state.list_versions(GROUP, PATH).unwrap();
        assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite an old one");
        assert_eq!(versions[0].version_seq, 3, "the restored content is the newest version");
        assert_eq!(versions[0].blocks, vec![v1_block]);
        assert_eq!(versions[0].state, yadorilink_sync_core::index::VersionState::Current);
        // Version 1 itself is completely untouched.
        let original_v1 = versions.iter().find(|v| v.version_seq == 1).unwrap();
        assert_eq!(original_v1.size, 20);
    }

    /// task 3.3/3.6: a version whose blocks are missing locally and
    /// unavailable from any peer (none connected here) fails with the
    /// specific `VersionContentUnavailable` error — not a generic
    /// I/O/not-found error — and leaves both the index and the on-disk
    /// file completely untouched.
    #[tokio::test]
    async fn restore_fails_clearly_when_no_peer_holds_the_missing_blocks() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.sync_state.add_link(&local_path, GROUP).unwrap();

        // A version referencing a block that was never actually written to
        // this device's block store (as if evicted, or an on-demand link
        // that never fetched it) — `record_with_blocks` only builds the
        // `BlockInfo`/index row, it never calls `put_block`.
        let phantom_block =
            BlockInfo { hash: Sha256::digest(b"never fetched").to_vec(), offset: 0, size: 13 };
        let v1 = record_with_blocks(PATH, "device-a", 1, vec![phantom_block], 13);
        state.sync_state.upsert_file_with_origin(GROUP, &v1, "device-a").unwrap();

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
        let versions = state.sync_state.list_versions(GROUP, PATH).unwrap();
        assert_eq!(versions.len(), 1, "a failed restore must not add or change any version row");
    }

    /// task 3.4/3.6: restoring a trashed file recovers its last version
    /// before deletion as a new current version, and the file is live
    /// again — the `trash restore` path (`SyncState::mark_deleted` is this
    /// crate's local-delete primitive, exercised directly here rather than
    /// through the full watcher, matching this module's other tests'
    /// direct-`SyncState`-manipulation style).
    #[tokio::test]
    async fn restore_trashed_recovers_a_deleted_files_last_content_as_a_new_current_version() {
        let (state, _store_dir) = test_state();
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.sync_state.add_link(&local_path, GROUP).unwrap();

        let block = put_block(&state, b"about to be deleted");
        let v1 = record_with_blocks(PATH, "device-a", 1, vec![block], 19);
        state.sync_state.upsert_file_with_origin(GROUP, &v1, "device-a").unwrap();
        state.sync_state.mark_deleted(GROUP, PATH, "device-a").unwrap();

        assert!(state.sync_state.get_file(GROUP, PATH).unwrap().unwrap().deleted);
        assert_eq!(state.sync_state.list_trashed(GROUP).unwrap().len(), 1);

        restore_trashed(&state, GROUP, PATH).await.unwrap();

        assert_eq!(std::fs::read(root.path().join(PATH)).unwrap(), b"about to be deleted");
        let current = state.sync_state.get_file(GROUP, PATH).unwrap().unwrap();
        assert!(!current.deleted, "the file must be live again after a trash restore");
    }

    /// `yadorilink restore <path>` without `--version` resolves
    /// to the most recent *superseded* version, not the current one (there
    /// would be nothing to restore *to* if it picked the current version)
    /// and not an older superseded version if a newer one exists.
    #[tokio::test]
    async fn most_recent_superseded_version_seq_picks_the_newest_non_current_version() {
        let (state, _store_dir) = test_state();
        state.sync_state.add_link("/tmp/unused", GROUP).unwrap();
        assert_eq!(
            most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
            None,
            "no rows at all yet"
        );

        let v1 = record_with_blocks(PATH, "device-a", 1, vec![], 0);
        state.sync_state.upsert_file_with_origin(GROUP, &v1, "device-a").unwrap();
        assert_eq!(
            most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(),
            None,
            "only a current version exists, nothing superseded yet"
        );

        let v2 = record_with_blocks(PATH, "device-a", 2, vec![], 0);
        state.sync_state.upsert_file_with_origin(GROUP, &v2, "device-a").unwrap();
        let v3 = record_with_blocks(PATH, "device-a", 3, vec![], 0);
        state.sync_state.upsert_file_with_origin(GROUP, &v3, "device-a").unwrap();

        assert_eq!(most_recent_superseded_version_seq(&state, GROUP, PATH).unwrap(), Some(2));
    }
}
