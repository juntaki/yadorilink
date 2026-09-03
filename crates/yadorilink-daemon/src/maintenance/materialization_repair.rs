//! `MaterializationRepairJob` -- relocated byte-identically from this
//! crate's former `daemon_state::spawn_materialization_repair_scheduler`.
//! Periodic, daemon-wide live repair pass: for every non-orphaned link's
//! group, backfills any change history a policy-withheld initial import
//! omitted, then asks one connected peer (round-robin across
//! `materialization_repair_cursors`, so a slow/incomplete peer is never
//! selected forever) to reconcile this device's local materialization
//! audit against its own. Interval-only -- no startup-immediate run
//! (see the inventory's own "no new startup runs" constraint); this
//! job's sweep never ran at startup before this reorganization, and
//! still doesn't.
//!
//! Holds a full `Arc<DaemonState>` rather than a narrower bundle: its
//! real dependencies (`sync_state`, `peers`, `materialization_repair_
//! cursors`, `backfill_missing_change_history`) span daemon-wide
//! coordination state broader than any existing narrow port, and
//! inventing a new bespoke port for one job's sake would be exactly the
//! kind of speculative abstraction this pass is meant to avoid --
//! mirrors `LinkRuntimeController::start_inner`'s own periodic
//! materialization-repair task, which for the identical reason
//! (`DaemonState::root_lease_for`) also keeps a full `Arc<DaemonState>`
//! instead of the narrower `LinkRuntimeDependencies` bundle the rest of
//! that module tree uses.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::DaemonState;
use crate::maintenance::MaintenanceTrigger;

pub(crate) struct MaterializationRepairJob {
    state: Arc<DaemonState>,
}

impl MaterializationRepairJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// Read fresh on every call (mirrors `PeerSyncSession`'s own
    /// `resync_handle` loop reading `maintenance_reconcile_interval()` fresh
    /// each time) rather than a `tokio::time::interval` fixed once at
    /// spawn time, so `set_materialization_repair_sweep_interval` takes
    /// effect on the very next sleep -- see
    /// `DaemonState::materialization_repair_sweep_interval`'s own doc for
    /// why a fixed-period interval would make that setter silently inert
    /// for an already-running daemon (every test call site).
    pub(crate) fn sweep_interval(&self) -> Duration {
        self.state.materialization_repair_sweep_interval()
    }

    pub(crate) async fn run_once(&self, _trigger: MaintenanceTrigger) {
        // Test-only panic-injection seam, proving the restart-supervision
        // fix this pairs with (`spawn_materialization_repair_task` below,
        // via `spawn_restarting`) actually recovers a real panic in this
        // exact call path -- not just exercising `spawn_restarting`'s own
        // already-tested generic mechanism in isolation. Compiled out
        // entirely in production; zero behavioral effect outside `#[cfg(test)]`.
        #[cfg(test)]
        {
            let flag = TEST_PANIC_ON_NEXT_RUN_ONCE.swap(false, std::sync::atomic::Ordering::SeqCst);
            if flag {
                panic!("materialization repair: test-injected panic");
            }
        }
        let state = &self.state;
        let groups: HashSet<String> = match state.replica_coordinator.link_repository().list_links()
        {
            // An orphaned link's coordination-side authorization is
            // confirmed gone, so there is no valid peer edge left to
            // request a repair from -- skip it the same way a paused
            // link's watcher already keeps it out of this set in
            // practice (no `LinkFlushHandle` to drive repair against).
            Ok(links) => {
                links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "materialization repair failed to list links");
                return;
            }
        };
        for group_id in groups {
            state.backfill_missing_change_history(&group_id).await;
            // `changes.applied` compatibility sweep: group-scoped,
            // peer-independent by design -- deliberately BEFORE the
            // live-candidate check below, since it must still run for a
            // group with zero connected peers. It used to live inside
            // `PeerSyncSession::reconcile_local_materialization_audit`,
            // which every call site here only reaches once a live
            // candidate is already found; a group whose obligations all
            // drained while disconnected would then never run the sweep
            // again until a peer reconnected, leaving stale `applied = 0`
            // rows indefinitely -- a real violation of the invariant that
            // this column must never permanently mislead external
            // tooling, even though nothing scheduling-relevant depends on
            // it.
            if let Err(e) = state
                .replica_coordinator
                .sqlite()
                .dag_reconcile_compatibility_applied_flag_for_group(&group_id)
            {
                tracing::warn!(
                    local_device_id = %state.device_id,
                    group_id,
                    error = %e,
                    "materialization repair: failed to reconcile the changes.applied \
                     compatibility flag"
                );
            }
            let candidates = state.peers.sessions_for_group(&group_id);
            if candidates.is_empty() {
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    "materialization repair: no live peer sessions for this group this sweep"
                );
                continue;
            }
            let start = {
                let mut cursors =
                    state.materialization_repair_cursors.lock().unwrap_or_else(|p| p.into_inner());
                let cursor = cursors.entry(group_id.clone()).or_insert(0);
                let start = *cursor % candidates.len();
                *cursor = (start + 1) % candidates.len();
                start
            };
            // M5-A soak-closure durability investigation: full per-sweep
            // trace (ordered candidate list, cursor start, which peer got
            // asked, and that peer's own result) to distinguish real
            // round-robin starvation from genuinely unrepairable content --
            // see the tracked comment on `randomized_soak_converges_with_
            // no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
            let ordered_candidates: Vec<&str> =
                candidates.iter().map(|(id, _)| id.as_str()).collect();
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                ?ordered_candidates,
                start,
                "materialization repair: sweep starting"
            );
            // M5-A soak-closure durability investigation: stopping at the
            // first `Ok(_)` was a real starvation bug, not just an
            // efficiency choice -- `reconcile_local_materialization_audit`
            // returns `Ok(true)` for "the audit ran without an outer I/O
            // error", not "this device's materialization is now complete"
            // (a per-file `RetryRequired` is intentionally folded into
            // `Ok(())` inside `rematerialize_one_record`, since
            // re-candidacy is driven by `list_materialization_repair_
            // candidates`'s own DB state, not this return value). Soak
            // logs (seed 12552500466593081697) showed a full-replica
            // device asking the same first-in-list peer every sweep for
            // the entire run and never once trying its other two live
            // peers, because that first peer's audit reliably returned
            // `Ok(_)` (itself only partially materialized, so it had
            // nothing to contribute) and the loop broke immediately. Every
            // live candidate is now asked every sweep -- bounded by this
            // group's live session count, same as before -- so a peer that
            // actually holds the missing content is never starved out by
            // an earlier peer's no-op success.
            let mut any_ok = false;
            let mut last_error = None;
            for offset in 0..candidates.len() {
                let (peer_id, session) = &candidates[(start + offset) % candidates.len()];
                let result = session.clone().reconcile_local_materialization_audit(&group_id).await;
                tracing::debug!(
                    local_device_id = %state.device_id,
                    group_id,
                    peer = %peer_id,
                    offset,
                    ok = result.is_ok(),
                    "materialization repair: peer attempt finished"
                );
                match result {
                    Ok(_) => any_ok = true,
                    Err(e) => {
                        tracing::warn!(
                            group_id,
                            peer = %peer_id,
                            error = %e,
                            "materialization repair peer failed; trying another peer"
                        );
                        last_error = Some(e);
                    }
                }
            }
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id,
                any_ok,
                "materialization repair: sweep finished"
            );
            if !any_ok {
                if let Some(e) = last_error {
                    tracing::warn!(
                        group_id,
                        error = %e,
                        "materialization repair failed for every available peer"
                    );
                }
            }
        }
        // Paired with `TEST_PANIC_ON_NEXT_RUN_ONCE` above -- only reached on
        // a normal (non-panicking) completion, so a test can distinguish
        // "this call panicked" from "this call ran to completion" by
        // watching this counter rather than the panic itself.
        #[cfg(test)]
        TEST_RUN_ONCE_COMPLETIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) static TEST_PANIC_ON_NEXT_RUN_ONCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(crate) static TEST_RUN_ONCE_COMPLETIONS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// Spawns the periodic materialization-repair sweep as a restartable task
/// -- extracted from `maintenance_coordinator::run` into its own function
/// so the spawn wiring (specifically: does a panic in `run_once` actually
/// get recovered, not just logged-and-abandoned) is directly testable
/// without spinning up every other task that coordinator also spawns.
/// `spawn_restarting`, not `spawn_logged`: this job is the sole mechanism
/// that re-arms an OnDemand->Eager materialization-policy promotion (and
/// the hazard/ignore-recheck-adjacent repair-candidate class of work), so
/// an unhandled panic anywhere in `run_once`'s own call path must not
/// silently and permanently disable it for the rest of the process's life.
pub(crate) fn spawn_materialization_repair_task(
    state: Arc<DaemonState>,
) -> tokio::task::JoinHandle<()> {
    crate::supervise::spawn_restarting(
        "daemon-state-materialization-repair",
        crate::supervise::BackoffConfig::MATERIALIZATION_REPAIR,
        move || {
            let materialization_repair_job = MaterializationRepairJob::new(state.clone());
            async move {
                loop {
                    tokio::time::sleep(materialization_repair_job.sweep_interval()).await;
                    materialization_repair_job.run_once(MaintenanceTrigger::Interval).await;
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// The regression this whole seam exists for: a panic inside
    /// `run_once` must not silently and permanently kill materialization
    /// repair for the rest of the process's life -- `spawn_restarting`
    /// must recover it. Proven end to end through the REAL spawn wiring
    /// (`spawn_materialization_repair_task`), not just by re-exercising
    /// `spawn_restarting`'s own already-tested generic mechanism in
    /// isolation: empirically verified RED by temporarily replacing this
    /// file's `spawn_restarting` call with a bare, unsupervised
    /// `tokio::spawn` (no restart mechanism at all) and confirming this
    /// test then fails -- not `spawn_logged`, whose closure-per-call
    /// signature does not even match `spawn_restarting`'s
    /// factory-that-returns-a-future one, so it would not compile as a
    /// drop-in swap here.
    #[tokio::test]
    async fn a_panic_in_run_once_is_recovered_not_left_permanently_dead() {
        let _guard = crate::test_support::CONFIG_ENV_MUTEX.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            yadorilink_local_storage::FsBlockStore::new(dir.path().join("blocks")).unwrap(),
        );
        let sync_state = Arc::new(
            crate::replica_coordinator::ReplicaCoordinator::open(dir.path().join("sync.sqlite3"))
                .unwrap(),
        );
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        // `build`, not `new`: `new` also starts `MaintenanceCoordinator`,
        // which spawns its own independent materialization-repair task
        // (via the real, unmodified `spawn_restarting`) racing this test's
        // own `spawn_materialization_repair_task` call below for the same
        // panic-injection statics -- exactly the kind of confound that
        // would let this test pass even if `spawn_materialization_repair_task`
        // itself lost its restart supervision. `build` constructs `state`
        // with no background tasks, so the task started below is the only
        // one that can possibly recover the injected panic.
        let state = DaemonState::build("device-under-test".into(), sync_state, store).state;
        // Fast enough that the test doesn't sit through a real production
        // interval, without being so fast it races the panic injection
        // below (the very first sleep must still land after
        // `TEST_PANIC_ON_NEXT_RUN_ONCE` is set).
        state.set_materialization_repair_sweep_interval(std::time::Duration::from_millis(20));

        TEST_RUN_ONCE_COMPLETIONS.store(0, Ordering::SeqCst);
        TEST_PANIC_ON_NEXT_RUN_ONCE.store(true, Ordering::SeqCst);

        let _handle = spawn_materialization_repair_task(state.clone());

        // Bounded wait comfortably past MATERIALIZATION_REPAIR's own 1s
        // restart backoff plus the 20ms sweep interval: long enough for
        // "panic, restart-backoff, one real completion" to happen at least
        // once if (and only if) the restart supervision actually works.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let recovered = loop {
            if TEST_RUN_ONCE_COMPLETIONS.load(Ordering::SeqCst) >= 1 {
                break true;
            }
            if tokio::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        assert!(
            recovered,
            "run_once never completed after its first (injected) panic -- spawn_restarting did \
             not recover it, exactly the silent-permanent-death bug this task's own restart \
             supervision exists to prevent"
        );
        // The panic must have genuinely happened (not been skipped by a
        // race) for this to be a real regression test rather than a
        // trivially-true one.
        assert!(
            !TEST_PANIC_ON_NEXT_RUN_ONCE.load(Ordering::SeqCst),
            "sanity: the injected panic flag must have been consumed by a real run_once call"
        );
    }
}
