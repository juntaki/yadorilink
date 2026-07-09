//! Block-store garbage collection: idle-triggered and on-demand
//! mark-and-sweep scheduling, daemon-wide "only one sweep at a
//! time" coordination, and last-run bookkeeping for `yadorilink status`/
//! `gc [--dry-run]`. Mirrors this crate's existing dispatch-module
//! convention (`folder_ops`, `update_ipc`, `reporting_ipc`): this module
//! owns the actual GC logic, `control_socket.rs` only translates to/from
//! the wire types.
//!
//! Liveness is computed fresh from the index
//! (`SyncState::live_block_hashes`) on every sweep rather than
//! transactionally refcounted, so this module needs no persisted state of
//! its own beyond simple bookkeeping counters (below) — a crash mid-sweep
//! just leaves some already-deleted blocks deleted and the rest
//! untouched, safely resumed by the next sweep (content-addressed
//! `delete()` is idempotent).

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_local_storage::GcReport;

use crate::daemon_state::DaemonState;

/// "Comfortably larger than normal sync-burst duration" — the daemon must
/// have seen no local-change/peer-reconciliation/hydration activity for
/// at least this long before an idle-triggered sweep may run at all. A
/// documented starting point (the exact constant is left to
/// implementation), not a value tuned against production telemetry.
pub const GC_IDLE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// "Comfortably larger than the normal local-change/hydration processing
/// latency between a block write and its index commit" — a stored block
/// whose on-disk mtime is newer than this is
/// never swept even if it currently looks unreferenced, since the index
/// row that will reference it may simply not have committed yet (every
/// block-write path writes the block before the referencing index row
/// commits — see `SyncState::live_block_hashes`'s doc comment).
pub const GC_GRACE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How often the idle scheduler re-checks whether it's been idle long
/// enough to sweep — independent of `GC_IDLE_THRESHOLD` (this is only the
/// poll cadence), short enough that a sweep starts promptly once the
/// daemon does go idle.
pub const GC_IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Daemon-wide GC coordination and last-run bookkeeping —
/// one instance lives on `DaemonState`, shared by the idle scheduler and
/// every on-demand `gc`/`gc --dry-run` request, so both go through the
/// exact same mutual-exclusion and reporting state.
pub struct GcState {
    /// "only one sweep runs at a time daemon-wide" — claimed via
    /// `compare_exchange` in `run_sweep` regardless of which trigger (idle
    /// scheduler vs. on-demand IPC request) is attempting it, so an
    /// on-demand trigger firing mid-idle-sweep never starts a second,
    /// concurrent sweep.
    running: AtomicBool,
    /// Unix seconds of the last *real* (non-dry-run) sweep's completion;
    /// `0` if none has ever completed since this daemon's block store was
    /// created.
    last_run_unix: AtomicI64,
    last_blocks_deleted: AtomicU64,
    last_bytes_reclaimed: AtomicU64,
    /// The most recently *computed* delete-set size: reset to `0`
    /// immediately after a real sweep (everything reclaimable as of that
    /// snapshot was just reclaimed), or left at the reported delete-set
    /// size after a `gc --dry-run` — going stale as new writes/deletes
    /// happen until the next sweep/dry-run computes it again (this is
    /// disclosed dry-run behavior — modulo the ordinary passage of time —
    /// not a bug). Backs
    /// `StatusResponse.gc_reclaimable_estimate_bytes`.
    reclaimable_estimate_bytes: AtomicU64,
}

impl Default for GcState {
    fn default() -> Self {
        Self::new()
    }
}

impl GcState {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            last_run_unix: AtomicI64::new(0),
            last_blocks_deleted: AtomicU64::new(0),
            last_bytes_reclaimed: AtomicU64::new(0),
            reclaimable_estimate_bytes: AtomicU64::new(0),
        }
    }

    pub fn last_run_unix(&self) -> i64 {
        self.last_run_unix.load(Ordering::SeqCst)
    }

    pub fn last_blocks_deleted(&self) -> u64 {
        self.last_blocks_deleted.load(Ordering::SeqCst)
    }

    pub fn last_bytes_reclaimed(&self) -> u64 {
        self.last_bytes_reclaimed.load(Ordering::SeqCst)
    }

    pub fn reclaimable_estimate_bytes(&self) -> u64 {
        self.reclaimable_estimate_bytes.load(Ordering::SeqCst)
    }
}

/// RAII guard releasing `GcState::running` on drop — mirrors
/// `BroadcastGuard`/`WriteActivityGuard` (`daemon_state.rs`) so a sweep
/// that returns early via `?` (or, in principle, panics) still gets
/// counted back out, never wedging every future sweep attempt behind a
/// permanently-stuck flag.
struct GcRunGuard<'a> {
    running: &'a AtomicBool,
}

impl Drop for GcRunGuard<'_> {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Why a requested sweep did not run (or did not complete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcTriggerError {
    /// Another sweep (idle-triggered or on-demand) is
    /// already in progress.
    AlreadyRunning,
    /// GC "runs after sync activity quiesces or on an explicit command,
    /// never mid-burst" — a sync-critical write
    /// (`DaemonState::is_write_safe_point`) was in flight at the moment
    /// this sweep was attempted.
    SyncBurstInProgress,
    /// The live-set query or the sweep itself failed.
    Failed(String),
}

impl std::fmt::Display for GcTriggerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcTriggerError::AlreadyRunning => {
                write!(f, "a garbage-collection sweep is already in progress; try again shortly")
            }
            GcTriggerError::SyncBurstInProgress => write!(
                f,
                "sync activity is in progress; garbage collection was skipped to avoid \
                 contention -- try again once idle, or wait for the next automatic sweep"
            ),
            GcTriggerError::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GcTriggerError {}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Runs one sweep (real or `--dry-run`) against this
/// daemon's block store, enforcing both daemon-wide invariants this
/// change requires — never two sweeps at once, never
/// concurrently with a sync-critical write ("never mid-burst") —
/// regardless of whether the caller is the idle scheduler
/// or an on-demand `gc`/`gc --dry-run` IPC request (an
/// on-demand trigger firing during an idle-triggered attempt does not
/// double-run).
///
/// PERF-8-style runtime hygiene, mirroring `FsBlockStore::present_blocks`:
/// the actual sweep is synchronous, batch-throttled blocking I/O
/// (`FsBlockStore::sweep`'s own pacing sleep between batches,
/// `SyncState::live_block_hashes`'s SQLite scan) — run through
/// `block_in_place` off the async caller's own poll when a multi-threaded
/// tokio runtime is current, so a large sweep never stalls the runtime's
/// other work (the control socket, peer sessions, ...) for its duration.
pub async fn run_sweep(state: Arc<DaemonState>, dry_run: bool) -> Result<GcReport, GcTriggerError> {
    run_sweep_with_grace_cutoff(state, dry_run, SystemTime::now() - GC_GRACE_WINDOW).await
}

/// Parameterized by the grace cutoff directly (rather than always deriving
/// it from `GC_GRACE_WINDOW`) so this module's own tests can exercise a
/// real deletion without waiting out the real multi-minute grace window —
/// mirrors `fs_backend.rs`'s own sweep tests, which likewise pass an
/// explicit `grace_cutoff` (e.g. `SystemTime::now() + 1s`) rather than a
/// duration. `run_sweep` above is the only production call site and
/// always uses the real `GC_GRACE_WINDOW`.
async fn run_sweep_with_grace_cutoff(
    state: Arc<DaemonState>,
    dry_run: bool,
    grace_cutoff: SystemTime,
) -> Result<GcReport, GcTriggerError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| run_sweep_sync(&state, dry_run, grace_cutoff))
        }
        _ => run_sweep_sync(&state, dry_run, grace_cutoff),
    }
}

fn run_sweep_sync(
    state: &DaemonState,
    dry_run: bool,
    grace_cutoff: SystemTime,
) -> Result<GcReport, GcTriggerError> {
    if state.gc.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err(GcTriggerError::AlreadyRunning);
    }
    let _guard = GcRunGuard { running: &state.gc.running };

    // "Never mid-burst" — checked *after* claiming `running` (so a
    // genuinely concurrent attempt observes the more specific
    // `AlreadyRunning` rather than this) but before any real work starts.
    // A manual `gc` bypasses the *idle wait*, not this check: bypassing
    // the idle wait does not bypass the "never concurrently with another
    // sweep" invariant; never running during active sync IO is a
    // stronger, always-on invariant, not just a property of the idle
    // trigger.
    if !state.is_write_safe_point() {
        return Err(GcTriggerError::SyncBurstInProgress);
    }

    // `live_block_hashes` already includes every retained
    // version/trash record's blocks (any `deleted = 0` row,
    // current or superseded/trashed alike — see its own doc comment), so
    // no separate version-history extra-roots call is needed here yet;
    // `live_block_hashes_with_extra_roots` remains available as the
    // the documented seam for a future root category that
    // isn't already representable as a `files` row.
    let live =
        state.sync_state.live_block_hashes().map_err(|e| GcTriggerError::Failed(e.to_string()))?;
    let report = state
        .block_store
        .sweep(&live, grace_cutoff, dry_run)
        .map_err(|e| GcTriggerError::Failed(e.to_string()))?;

    if dry_run {
        state.gc.reclaimable_estimate_bytes.store(report.bytes_reclaimed, Ordering::SeqCst);
    } else {
        state.gc.last_run_unix.store(now_unix(), Ordering::SeqCst);
        state.gc.last_blocks_deleted.store(report.blocks_deleted, Ordering::SeqCst);
        state.gc.last_bytes_reclaimed.store(report.bytes_reclaimed, Ordering::SeqCst);
        // Everything reclaimable as of this snapshot was just reclaimed.
        state.gc.reclaimable_estimate_bytes.store(0, Ordering::SeqCst);
    }
    Ok(report)
}

/// the idle scheduler's single tick — called on
/// `GC_IDLE_POLL_INTERVAL` by the periodic task `DaemonState::new` spawns,
/// and called directly (with an injected `idle_threshold`) by this
/// module's own tests so they never have to wait out the real
/// multi-minute `GC_IDLE_THRESHOLD`. Returns `None` when not idle long
/// enough to attempt a sweep at all; `Some(_)` with the attempt's outcome
/// otherwise. `AlreadyRunning`/`SyncBurstInProgress` are expected, benign
/// outcomes for the scheduler specifically (an on-demand sweep may
/// already be running, or activity may have resumed in the gap between
/// the idle check and the attempt) — the caller logs those at `debug`,
/// reserving `warn` for `Failed`.
pub async fn maybe_run_idle_sweep(
    state: &Arc<DaemonState>,
    idle_threshold: Duration,
) -> Option<Result<GcReport, GcTriggerError>> {
    if state.idle_duration() < idle_threshold {
        return None;
    }
    Some(run_sweep(state.clone(), false).await)
}

/// resolves `materialization::run_eviction_sweep`'s previously
/// entirely-absent periodic caller — `run_eviction_sweep` existed but
/// had no periodic caller in the daemon at all. Runs on the same
/// idle-scheduler cadence as the GC sweep above: every `OnDemand` link
/// with a configured `max_local_size_bytes` cap gets that cap enforced
/// here too, not only reactively on measured disk-space pressure
/// (`run_disk_pressure_eviction_sweep`, already wired from
/// `hydration.rs`'s materialize path) or never at all between hydrations.
/// Deliberately not gated on `idle_duration`/`is_write_safe_point` the way
/// the GC sweep above is — eviction only ever demotes an already-hydrated
/// file back to a placeholder (index write + one file rename), the same
/// bounded, synchronous-SQLite-and-filesystem-only shape as
/// `run_retention_expiry_sweep`, not the store-wide directory walk GC's
/// sweep performs, so it does not compete for IO the way this change's
/// own scheduling logic exists to protect against.
///
/// Logs (rather than propagates) a per-link failure so one link's error
/// never stops the sweep from covering the rest, mirroring
/// `run_retention_expiry_sweep`'s own per-link error handling.
pub fn run_periodic_capacity_eviction_sweep(state: &DaemonState) {
    let links = match state.sync_state.list_links() {
        Ok(links) => links,
        Err(e) => {
            tracing::warn!(error = %e, "periodic capacity-eviction sweep: failed to list links");
            return;
        }
    };
    for link in links {
        if link.materialization_policy
            != yadorilink_sync_core::types::MaterializationPolicy::OnDemand
            || link.max_local_size_bytes.is_none()
        {
            continue;
        }
        let root = std::path::Path::new(&link.local_path);
        match yadorilink_sync_core::materialization::run_eviction_sweep(
            &state.sync_state,
            root,
            &link.group_id,
            link.max_local_size_bytes,
        ) {
            Ok(evicted) if !evicted.is_empty() => {
                tracing::debug!(
                    group_id = %link.group_id,
                    local_path = %link.local_path,
                    evicted_count = evicted.len(),
                    "periodic capacity-eviction sweep evicted files back to placeholders"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = %e,
                group_id = %link.group_id,
                local_path = %link.local_path,
                "periodic capacity-eviction sweep failed for this link"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering as TestOrdering;

    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    use super::*;

    /// Returns the `TempDir` guard alongside the state — must stay alive
    /// for the whole test (real sweep/usage tests in this module do
    /// genuine filesystem I/O against the block store's root), unlike a
    /// helper that drops it before returning, which would delete the root
    /// directory out from under a later `FsBlockStore` operation.
    fn test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        (DaemonState::new("device-a".into(), sync_state, store), store_dir)
    }

    /// GC must not start while a sync burst is active —
    /// simulated here exactly the way `link_manager`'s flush
    /// executor and `hydration.rs`'s hydrate/evict/restore paths mark
    /// activity in production (`begin_write_activity`'s RAII guard), not
    /// by directly poking the write-safe-point flag.
    #[tokio::test]
    async fn sweep_does_not_run_while_a_sync_critical_write_is_in_progress() {
        let (state, _dir) = test_state();
        let _write_guard = state.begin_write_activity();

        let result = run_sweep(state.clone(), false).await;

        assert_eq!(result, Err(GcTriggerError::SyncBurstInProgress));
    }

    /// a sweep already in flight (flag pre-claimed here,
    /// standing in for a concurrently-running real sweep) makes a second
    /// attempt observe `AlreadyRunning` rather than running a second,
    /// concurrent sweep.
    #[tokio::test]
    async fn a_second_sweep_attempt_is_rejected_while_one_is_already_running() {
        let (state, _dir) = test_state();
        state.gc.running.store(true, TestOrdering::SeqCst);

        let result = run_sweep(state.clone(), false).await;

        assert_eq!(result, Err(GcTriggerError::AlreadyRunning));
    }

    /// Exercised with real concurrent tasks (not just the
    /// flag pre-claimed by hand, as above) across multiple linked
    /// folders: however the two attempts interleave, at most one may
    /// actually run a sweep — the other must observe `AlreadyRunning`,
    /// never a second concurrent run.
    ///
    /// Writes enough orphaned blocks that `FsBlockStore::sweep`'s own
    /// batch-pacing sleep (`GC_SWEEP_BATCH_DELAY` per `GC_SWEEP_BATCH_SIZE`
    /// blocks) guarantees the winning task's critical section stays open
    /// for tens of milliseconds — without this, an essentially-instant
    /// sweep over an empty store could let both spawned tasks complete
    /// sequentially without ever actually overlapping, making the test
    /// pass by luck even if the mutual-exclusion logic were broken (the
    /// first version of this test did exactly that and flaked). This
    /// makes the overlap window large enough, relative to the
    /// microsecond-scale cost of a competing task's own `compare_exchange`
    /// attempt, that the two are reliably observed racing for real.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_sweep_runs_at_a_time_across_multiple_linked_folders() {
        let (state, _dir) = test_state();
        state.sync_state.add_link("/tmp/yadorilink-gc-test-a", "group-a").unwrap();
        state.sync_state.add_link("/tmp/yadorilink-gc-test-b", "group-b").unwrap();
        for i in 0..10_000u32 {
            state.block_store.put(format!("orphaned block {i}").as_bytes()).unwrap();
        }

        let a = state.clone();
        let b = state.clone();
        let (r1, r2) =
            tokio::join!(tokio::spawn(run_sweep(a, false)), tokio::spawn(run_sweep(b, false)),);
        let outcomes = [r1.unwrap(), r2.unwrap()];

        let ok_count = outcomes.iter().filter(|r| r.is_ok()).count();
        let already_running_count =
            outcomes.iter().filter(|r| **r == Err(GcTriggerError::AlreadyRunning)).count();
        assert_eq!(
            ok_count, 1,
            "exactly one concurrent sweep attempt must actually run: {outcomes:?}"
        );
        assert_eq!(
            already_running_count, 1,
            "the other concurrent attempt must observe AlreadyRunning, not also run: {outcomes:?}"
        );
    }

    /// a freshly-constructed daemon (activity recorded as "now")
    /// must not fire an idle sweep even against a threshold far shorter
    /// than the real `GC_IDLE_THRESHOLD`.
    #[tokio::test]
    async fn idle_sweep_does_not_fire_before_the_threshold_elapses() {
        let (state, _dir) = test_state();

        let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(3600)).await;

        assert!(
            outcome.is_none(),
            "must not attempt a sweep while still within the idle threshold"
        );
    }

    /// once idle past the threshold, the scheduler tick actually
    /// runs a (real, non-dry-run) sweep.
    #[tokio::test]
    async fn idle_sweep_fires_once_idle_past_the_threshold() {
        let (state, _dir) = test_state();
        state.set_last_activity_unix_for_test(now_unix() - 3600);

        let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(60)).await;

        assert!(matches!(outcome, Some(Ok(_))), "expected a completed sweep, got {outcome:?}");
        assert!(state.gc.last_run_unix() > 0, "a real sweep must record its completion time");
    }

    /// a daemon idle past the threshold, but with sync activity
    /// actively in progress right now, still must not sweep — idle-ness
    /// alone is not sufficient; the two conditions are independent —
    /// this waits for both the idle period and no in-flight
    /// hydration/materialization. Starts the write guard *first* (as
    /// production does — `begin_write_activity` itself records "now" as
    /// the last-activity time) and only afterward backdates
    /// `last_activity_unix`, simulating a long-running write/hydration
    /// whose start has already receded past the idle threshold while it's
    /// still in flight — exactly the case `is_write_safe_point`'s own
    /// check inside `run_sweep` exists for, distinct from (and not made
    /// redundant by) the idle-scheduler's own idle-duration gate.
    #[tokio::test]
    async fn idle_sweep_is_skipped_when_a_write_is_in_progress_even_if_idle() {
        let (state, _dir) = test_state();
        let _write_guard = state.begin_write_activity();
        state.set_last_activity_unix_for_test(now_unix() - 3600);

        let outcome = maybe_run_idle_sweep(&state, Duration::from_secs(60)).await;

        assert_eq!(outcome, Some(Err(GcTriggerError::SyncBurstInProgress)));
    }

    /// An on-demand `gc` trigger firing while
    /// an idle-triggered sweep is already underway (simulated here by
    /// pre-claiming the flag, as the idle scheduler's own `run_sweep` call
    /// would have done) must not start a second, concurrent sweep.
    #[tokio::test]
    async fn on_demand_trigger_during_an_idle_sweep_does_not_double_run() {
        let (state, _dir) = test_state();
        state.set_last_activity_unix_for_test(now_unix() - 3600);
        state.gc.running.store(true, TestOrdering::SeqCst); // idle sweep already in flight

        let manual = run_sweep(state.clone(), false).await;

        assert_eq!(manual, Err(GcTriggerError::AlreadyRunning));
    }

    /// `--dry-run` computes the exact same delete set a real sweep would,
    /// without deleting anything or updating
    /// `last_run_unix`, but does update the reclaimable estimate. Uses
    /// `run_sweep_with_grace_cutoff` directly (a future cutoff, mirroring
    /// `fs_backend.rs`'s own sweep tests) so this doesn't depend on
    /// waiting out the real multi-minute `GC_GRACE_WINDOW` — that
    /// grace-window mechanics themselves are already covered by
    /// `yadorilink-local-storage`'s own sweep unit tests (section 2).
    #[tokio::test]
    async fn dry_run_reports_without_deleting_or_advancing_last_run() {
        let (state, _dir) = test_state();
        let hash = state.block_store.put(b"orphaned block, never referenced").unwrap();
        let future_cutoff = SystemTime::now() + Duration::from_secs(1);

        let report = run_sweep_with_grace_cutoff(state.clone(), true, future_cutoff).await.unwrap();

        assert_eq!(report.blocks_deleted, 1);
        assert!(state.block_store.exists(&hash).unwrap(), "dry-run must not actually delete");
        assert_eq!(state.gc.last_run_unix(), 0, "dry-run must not count as a completed real sweep");
        assert_eq!(state.gc.reclaimable_estimate_bytes(), report.bytes_reclaimed);
    }

    /// The mirror case: a real (non-dry-run) sweep actually deletes the
    /// orphaned block and records `last_run_unix`/the reclaimed counts,
    /// resetting the reclaimable estimate back to 0 (everything
    /// reclaimable as of that snapshot was just reclaimed).
    #[tokio::test]
    async fn real_sweep_deletes_and_records_last_run_bookkeeping() {
        let (state, _dir) = test_state();
        let hash = state.block_store.put(b"orphaned block, never referenced").unwrap();
        let future_cutoff = SystemTime::now() + Duration::from_secs(1);

        let report =
            run_sweep_with_grace_cutoff(state.clone(), false, future_cutoff).await.unwrap();

        assert_eq!(report.blocks_deleted, 1);
        assert!(!state.block_store.exists(&hash).unwrap(), "a real sweep must actually delete");
        assert!(state.gc.last_run_unix() > 0);
        assert_eq!(state.gc.last_blocks_deleted(), 1);
        assert_eq!(state.gc.last_bytes_reclaimed(), report.bytes_reclaimed);
        assert_eq!(state.gc.reclaimable_estimate_bytes(), 0);
    }
}
