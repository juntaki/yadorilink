//! `DurabilityConfirmationJob` -- the M4 background sweep that turns
//! `DaemonState::group_durability_status`'s `Healthy` from a local-only
//! heuristic into real peer-confirmed evidence: periodically re-runs
//! `full_replica_handoff_ready_digest_and_peer` (the existing whole-group,
//! exact-version-hash, generation-stability-checked handoff-readiness
//! check) for every linked group and caches the result via
//! `DaemonState::refresh_custody_confirmation`.
//!
//! Structurally mirrors `MaterializationRepairJob` -- same shape (a struct
//! holding `Arc<DaemonState>`, a `sweep_interval()` accessor read fresh
//! each sleep, an `async fn run_once`), same reason (an existing,
//! independently-tested peer round-trip is the correctness-bearing part;
//! this job only owns *when* it runs, not *how* the check itself works).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::DaemonState;
use crate::maintenance::MaintenanceTrigger;

pub(crate) struct DurabilityConfirmationJob {
    state: Arc<DaemonState>,
}

impl DurabilityConfirmationJob {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) fn sweep_interval(&self) -> Duration {
        self.state.custody_confirmation_sweep_interval()
    }

    /// Re-confirms whole-group custody for every non-orphaned linked
    /// group. Every round writes a record either way (`Confirmed` or
    /// `NotConfirmed` -- see `CustodyConfirmationOutcome`'s own doc
    /// comment): a `NotConfirmed` round never itself produces `Healthy`
    /// (only a fresh `Confirmed` record does), but it DOES mark the group
    /// as having been swept at least once, which is what lets
    /// `classify` distinguish "checked, found nothing" (eligible for the
    /// structural `KnownMissing` conclusion) from "never checked yet"
    /// (must stay `DurabilityUnknown` regardless of how the structural
    /// peer check would otherwise read).
    pub(crate) async fn run_once(&self, _trigger: MaintenanceTrigger) {
        let state = &self.state;
        let groups: HashSet<String> = match state.replica_coordinator.link_repository().list_links()
        {
            Ok(links) => {
                links.into_iter().filter(|link| !link.orphaned).map(|link| link.group_id).collect()
            }
            Err(e) => {
                tracing::warn!(error = %e, "durability confirmation sweep failed to list links");
                return;
            }
        };
        for group_id in groups {
            state.refresh_custody_confirmation(&group_id).await;
        }
    }
}
