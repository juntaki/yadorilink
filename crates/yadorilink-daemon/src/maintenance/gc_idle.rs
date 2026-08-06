//! `GcIdleJob` -- the idle-triggered GC scheduler's single tick, sharing
//! its poll tick with the periodic capacity-eviction sweep (see
//! `gc::run_periodic_capacity_eviction_sweep`'s own doc for why that one
//! doesn't need the same idle/write-safe-point gating GC itself does).
//! Interval-only -- no startup-immediate run.
//!
//! Holds a full `Arc<DaemonState>`: both `gc::maybe_run_idle_sweep` and
//! `gc::run_periodic_capacity_eviction_sweep` take the full state today
//! (idle-duration tracking, the sync/block-store index, `gc` scheduling
//! state), and neither is behind a narrower port.

use std::sync::Arc;

use crate::daemon_state::{run_blocking_sweep_offloaded, DaemonState};
use crate::maintenance::MaintenanceTrigger;

pub(crate) struct GcIdleJob {
    state: Arc<DaemonState>,
}

impl GcIdleJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) async fn run_once(&self, _trigger: MaintenanceTrigger) {
        let state = &self.state;
        match crate::gc::maybe_run_idle_sweep(state, crate::gc::GC_IDLE_THRESHOLD).await {
            None => {}
            Some(Ok(report)) if report.blocks_deleted > 0 => {
                tracing::info!(
                    blocks_deleted = report.blocks_deleted,
                    bytes_reclaimed = report.bytes_reclaimed,
                    "idle-triggered GC sweep reclaimed blocks"
                );
            }
            Some(Ok(_)) => {}
            // Benign: either another sweep (on-demand or this same loop's
            // previous still-running iteration -- shouldn't happen given
            // the `.await` above, but the invariant holds either way) is
            // in flight, or activity resumed between the idle check and
            // the attempt.
            Some(Err(
                crate::gc::GcTriggerError::AlreadyRunning
                | crate::gc::GcTriggerError::SyncBurstInProgress,
            )) => {}
            Some(Err(e @ crate::gc::GcTriggerError::Failed(_))) => {
                tracing::warn!(error = %e, "idle-triggered GC sweep failed");
            }
        }
        run_blocking_sweep_offloaded(|| crate::gc::run_periodic_capacity_eviction_sweep(state));
    }
}
