//! Owns spawning every one of this daemon's periodic background
//! maintenance tasks: the update-check scheduler, the pending-report retry
//! sweep, materialization repair, the Convergence Engine's own scheduler
//! loop, forward-rebroadcast, degraded-link recheck, retention expiry,
//! membership recovery, the disk-reconcile backstop, and the idle-triggered
//! GC scheduler.
//!
//! Phase 2B Step 5 (daemon runtime decomposition): this is a relocation of
//! the SPAWNING CODE out of `DaemonState::new`'s own body into its own
//! named module -- `DaemonState::new` now calls `start` as a single line
//! instead of inlining ~200 lines of spawn setup. It is deliberately NOT
//! yet a relocation of the CALL SITE itself (still invoked from inside
//! `new`, not from `app.rs`/`DaemonContext` after construction returns):
//! `forward_rx` (the local `mpsc::Receiver` half of the change-forwarding
//! channel `new` constructs) is consumed directly by one of these tasks
//! and isn't stored anywhere on `DaemonState`, so moving the call site out
//! of `new` would require either widening `DaemonState::new`'s own return
//! type or storing `forward_rx` behind an `Option`/`Mutex` purely to hand
//! it back out again -- a real signature change touching every one of
//! `DaemonState::new`'s call sites (production and every test in this
//! crate) for no behavioral gain in this step. Left for a later pass, once
//! `DaemonContext` threading itself (the deferred remainder of Step 1)
//! is worth doing.
//!
//! Phase 4: 7 of these 10 tasks (#1-3, #6-10 in
//! `docs/design/phase4-maintenance-inventory.md`'s own table) are now
//! named job types under `crate::maintenance`, each with a `run_once`
//! method holding the sweep/check logic that used to be inlined directly
//! in this file's spawned closures. This module's own remaining job is
//! exactly what its name says: construct each job (deriving its narrow
//! dependencies from `state`), then spawn a small loop per job that calls
//! `run_once` -- every loop-shape/interval/supervision-strategy choice
//! below (`spawn_logged` vs `spawn_restarting`, which jobs run once
//! immediately at startup, which don't) is unchanged from before this
//! reorganization; only the sweep bodies moved out to their own files.
//! `#4` (`convergence-engine-scheduler`) and `#5` (`forward-rebroadcast`)
//! are untouched -- see each one's own comment below for why.
//!
//! No queue unification, no `ConvergenceWork` enum, no priority
//! scheduling, no dedup, no event-driven enqueue -- every task below keeps
//! its own independent spawn, own interval, own supervision strategy
//! (`spawn_logged` vs `spawn_restarting`), completely unchanged.

use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_replica_domain::file::FileRecord;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::{
    DaemonState, RETENTION_EXPIRY_SWEEP_INTERVAL, ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL,
};
use crate::maintenance::degraded_link_recheck::DegradedLinkRecheckJob;
use crate::maintenance::disk_reconcile_backstop::DiskReconcileBackstopJob;
use crate::maintenance::gc_idle::GcIdleJob;
use crate::maintenance::materialization_repair::MaterializationRepairJob;
use crate::maintenance::membership_recovery::MembershipRecoveryJob;
use crate::maintenance::retention_expiry::RetentionExpiryJob;
#[cfg(not(any(madsim, test)))]
use crate::maintenance::update_check::UpdateCheckJob;
use crate::maintenance::MaintenanceTrigger;
use crate::supervise;

/// Spawns every periodic background maintenance task this daemon runs for
/// the rest of its life. Called once, synchronously, from
/// `DaemonState::new` right after `state` itself is fully constructed.
pub(crate) fn start(
    state: &Arc<DaemonState>,
    mut forward_rx: mpsc::UnboundedReceiver<(String, FileRecord)>,
) {
    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    // Periodic background update
    // checks with jitter, honoring `automatic_checks_enabled` (a
    // disabled policy just means this loop's iteration is a no-op,
    // not that the loop stops running — `yadorilink update check`
    // must still work regardless, per the spec's "Automatic checks
    // disabled" scenario). A failed check retries sooner
    // (`UPDATE_CHECK_RETRY`'s shorter, doubling backoff) than the
    // steady-state success interval (`UPDATE_CHECK_INTERVAL`).
    // The periodic update-check scheduler is the daemon's only startup
    // path that performs a real outbound HTTP request (`reqwest`, via
    // `UpdateManager::check_now`). The deterministic simulator does not
    // virtualize `reqwest`, and there is no update endpoint to reach
    // in-sim, so this loop is not spawned there — its absence is inert
    // (an operator-facing background maintenance task, not part of the
    // sync data path). Production (`not(madsim)`) is unchanged; the
    // `UpdateManager` itself is still constructed regardless so
    // `yadorilink update check` and control-socket requests work.
    // Unit tests construct many short-lived states in one process. Starting
    // a real, immediate HTTP check for each one both leaks work past the
    // test body and can overwrite the update-policy fixture another test
    // is asserting. Integration tests still compile this crate normally,
    // so production-like scheduler coverage remains available there.
    #[cfg(not(any(madsim, test)))]
    {
        let update_check_job = UpdateCheckJob::new(state.update_manager.clone());
        supervise::spawn_logged("daemon-state-update-check-scheduler", async move {
            let mut consecutive_failures: u32 = 0;
            let mut trigger = MaintenanceTrigger::Startup;
            loop {
                // Periodic update checks at daemon startup
                // and on an interval — the startup check runs first
                // (immediately, no delay), and every subsequent iteration
                // waits out the jittered steady-state interval, or a
                // shorter jittered backoff after a failure.
                match update_check_job.run_once(trigger).await {
                    None => {}
                    Some(Ok(_)) => consecutive_failures = 0,
                    Some(Err(e)) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        tracing::warn!(error = %e, consecutive_failures, "update check failed");
                    }
                }
                trigger = MaintenanceTrigger::Interval;
                let delay = if consecutive_failures == 0 {
                    supervise::BackoffConfig::UPDATE_CHECK_INTERVAL.next(0)
                } else {
                    supervise::BackoffConfig::UPDATE_CHECK_RETRY.next(consecutive_failures - 1)
                };
                tokio::time::sleep(delay).await;
            }
        });
    }
    // The background queue-retry
    // sweep, spawned unconditionally like the other periodic tasks
    // below — it is a no-op (no network call at all) until the user
    // opts into `queue_retry_enabled` and configures an endpoint, so
    // spawning it for every `DaemonState` (including test call sites)
    // is inert, matching how the pending-broadcast-retry task below is
    // already spawned unconditionally. `reporting_retry::spawn_periodic`
    // now constructs its own `ReportingRetryJob` internally -- see that
    // module's own doc for why this stays a thin wrapper rather than
    // moving under `crate::maintenance`.
    crate::reporting_retry::spawn_periodic(state.clone());
    // Materialization repair: interval-only, no startup-immediate run
    // (see the inventory's own "no new startup runs" constraint) -- the
    // loop below still reads `sweep_interval()` fresh on every tick, not
    // a `tokio::time::interval` fixed at spawn time, so
    // `set_materialization_repair_sweep_interval` still takes effect on
    // the very next sleep, exactly as before this task moved the sweep
    // body into `MaterializationRepairJob::run_once`.
    {
        let materialization_repair_job = MaterializationRepairJob::new(state.clone());
        supervise::spawn_logged("daemon-state-materialization-repair", async move {
            loop {
                tokio::time::sleep(materialization_repair_job.sweep_interval()).await;
                materialization_repair_job.run_once(MaintenanceTrigger::Interval).await;
            }
        });
    }
    // The Convergence Engine's own scheduler loop: drives
    // `materialization_jobs` rows `handle_change_batch` enqueues, on its
    // own schedule, never under a `message_slots` permit. Unlike the
    // other background tasks here (`spawn_logged`, no restart), a silent
    // stop of this one loop halts all materialization for every group
    // for the rest of the daemon's life — `spawn_restarting` is used
    // deliberately so a panic/error here recovers instead of silently
    // wedging the daemon. Out of Phase 4's own scope (the inventory's
    // own #4 row): already isolated via `spawn_restarting`, with no
    // `run_once`/interval shape to extract it into -- left exactly as-is.
    {
        let convergence_state = state.clone();
        crate::supervise::spawn_restarting(
            "convergence-engine-scheduler",
            crate::supervise::BackoffConfig::CONVERGENCE_ENGINE,
            move || crate::convergence::engine::run(convergence_state.clone()),
        );
    }
    // Every one of `DaemonState`'s own background tasks
    // used to be a bare `tokio::spawn` with its `JoinHandle` dropped —
    // a panic partway through a single forwarded record
    // would silently stop mesh propagation
    // for the rest of the process's life with no log line at all.
    // `supervise::spawn_logged` doesn't restart these (unlike the
    // reconnect loops in `peer_orchestrator`/`yadorilink-transport`,
    // these consume an owned `mpsc::Receiver` that can't be recreated
    // per attempt the way `spawn_restarting`'s `make_task` expects),
    // but it does guarantee a loud `error`-level log naming the task
    // if it ever exits or panics, instead of a zombie behavior gap.
    // Not given a named job type (the inventory's own #5 row, "a
    // lighter-touch pass"): this task is channel-owned, draining an
    // `mpsc::Receiver` until it closes, with no periodic interval and no
    // `run_once`-shaped "one unit of work" to extract -- it already is
    // exactly one small, explicit loop, and wrapping it in a struct
    // holding a single owned, non-cloneable `Receiver` field plus one
    // method that does the same drain-forever loop body would be
    // indirection without a second caller or narrower dependency to show
    // for it.
    let task_state = state.clone();
    supervise::spawn_logged("daemon-state-forward-rebroadcast", async move {
        while let Some((group_id, record)) = forward_rx.recv().await {
            // A record forwarded here is
            // exactly a peer session having just adopted/resolved an
            // incoming file — this is this crate's "peer-reconciliation
            // activity" signal for the GC idle scheduler.
            task_state.record_activity();
            task_state.broadcast_change(&group_id, vec![record]).await;
        }
        Ok(())
    });
    // A dedicated, short-interval poll for every currently-Degraded
    // link whose backoff window has elapsed. The whole point of
    // `BackoffConfig::DEGRADED_LINK_RECHECK`'s 5s *initial* interval is
    // a link that degrades and recovers quickly getting checked again
    // promptly, so this must not be folded into a slower housekeeping
    // cadence.
    {
        let degraded_link_recheck_job = DegradedLinkRecheckJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-degraded-link-recheck", async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                degraded_link_recheck_job.run_once(MaintenanceTrigger::Interval);
            }
        });
    }
    // The retention-expiry sweep —
    // "scheduled periodically... and on daemon startup". Once
    // immediately (a daemon that was down for a while, or one whose
    // retention policy just changed, shouldn't wait a full interval
    // before its first sweep), then on a bounded interval. A
    // relatively long interval (unlike the 2s degraded-link recheck
    // above, which reacts to a transient, user-visible condition) is
    // appropriate here: retention expiry is a slow-moving housekeeping
    // concern — a version that's `RETENTION_EXPIRY_SWEEP_INTERVAL`
    // late to be swept is not a correctness problem, only a delayed
    // storage reclamation, and the actual space reclamation is
    // deferred to the block-store GC regardless (this sweep only
    // ever drops the *index* row). Both this startup call and the
    // spawned loop's own periodic call now go through the same
    // `RetentionExpiryJob::run_once`.
    let retention_expiry_job = RetentionExpiryJob::new(controller.clone());
    retention_expiry_job.run_once(MaintenanceTrigger::Startup);
    {
        let retention_expiry_job = retention_expiry_job.clone();
        supervise::spawn_logged("daemon-state-retention-expiry-sweep", async move {
            loop {
                tokio::time::sleep(RETENTION_EXPIRY_SWEEP_INTERVAL).await;
                retention_expiry_job.run_once(MaintenanceTrigger::Interval);
            }
        });
    }
    // Fix-saga: startup + periodic reconciliation of any membership-
    // related recovery journal left mid-flight by a crash or an
    // unconfirmable coordination-plane call — role-loss (this device's
    // own demote/unlink), unknown-scope, and ambiguous membership
    // operations were previously three independent supervised loops on
    // this same interval; collapsed into one so the number of periodic
    // sweep owners doesn't keep growing with every new recovery journal.
    // Unlike the retention sweep above, this one is async (each sub-sweep
    // makes coordination-plane HTTP calls), so "run once immediately, then
    // on an interval" is expressed as a single spawned loop that sweeps at
    // the top before its first sleep, rather than a separate blocking
    // call ahead of the spawn -- both that first, immediate sweep and
    // every later periodic one now go through the same
    // `MembershipRecoveryJob::run_once`.
    {
        let membership_recovery_job = MembershipRecoveryJob::new(state.clone());
        supervise::spawn_logged("daemon-state-membership-recovery-sweep", async move {
            let mut trigger = MaintenanceTrigger::Startup;
            loop {
                membership_recovery_job.run_once(trigger).await;
                trigger = MaintenanceTrigger::Interval;
                tokio::time::sleep(ROLE_LOSS_RECONCILIATION_SWEEP_INTERVAL).await;
            }
        });
    }
    // Piggy-backs on the same cadence as
    // `PeerSyncSession`'s own periodic DAG-frontier maintenance
    // (`DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`) rather than a new,
    // independent timer. Not run once immediately at startup the way the
    // retention sweep above is: `start_link_watch`'s own initial
    // `scan_existing_files` already indexes everything present on disk
    // at daemon start, so an immediate add-only pass here would find
    // nothing new; the first sweep only matters once a watcher has had
    // a chance to miss something.
    {
        let disk_reconcile_backstop_job = DiskReconcileBackstopJob::new(controller.clone());
        supervise::spawn_logged("daemon-state-disk-reconcile-backstop-sweep", async move {
            loop {
                tokio::time::sleep(
                    yadorilink_peer_session::peer_session::DEFAULT_MAINTENANCE_RECONCILE_INTERVAL,
                )
                .await;
                disk_reconcile_backstop_job.run_once(MaintenanceTrigger::Interval).await;
            }
        });
    }
    // The idle-triggered GC scheduler,
    // modeled on this same `spawn_logged` periodic-task shape as every
    // other sweep in this file. Shares its poll tick with the
    // previously-uncalled `run_eviction_sweep` — see
    // `gc::run_periodic_capacity_eviction_sweep`'s doc comment for why
    // that one doesn't need the same idle/write-safe-point gating GC
    // itself does.
    {
        let gc_idle_job = GcIdleJob::new(state.clone());
        supervise::spawn_logged("daemon-state-gc-idle-scheduler", async move {
            loop {
                tokio::time::sleep(crate::gc::GC_IDLE_POLL_INTERVAL).await;
                gc_idle_job.run_once(MaintenanceTrigger::Interval).await;
            }
        });
    }
}
