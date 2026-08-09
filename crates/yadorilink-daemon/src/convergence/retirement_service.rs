//! Runs the ephemeral-conflict-copy retirement audit for one group at a
//! time, without going through any live peer session. Extracted out of
//! `engine_wrapper.rs`'s `run_retirement_pass`, which used to pick among
//! `crate::hydration::candidate_sessions` (this device's currently-
//! connected peer sessions for a group) purely because `retire_conflict_
//! copies_only` happened to live on `PeerSyncSession` -- see
//! `DaemonState::local_retirement_session`'s own doc comment for why that
//! dependency was never actually load-bearing for retirement's own
//! decision, which is driven entirely by local DAG/file-index/disk state.
//!
//! Deliberately thin: this commit moves WHICH session object runs the
//! audit (a cached local-only one, not a live peer's), not the audit logic
//! itself, nor the `MaterializationAuditGuard` contention `RetirementAttempt::
//! Busy` still reports -- that guard is still shared with `reconcile_local_
//! materialization_audit`/`reconcile_paths_directly` through `PeerSyncSession`
//! internals unchanged. A dedicated retirement-only single-flight (so a full
//! audit in flight can no longer make a retirement pass report `Busy` at
//! all) is later work, not this one.
use std::sync::Arc;

use yadorilink_peer_session::peer_session::RetirementAttempt;
use yadorilink_peer_session::PeerSessionError;

use crate::daemon_state::DaemonState;

pub struct ConvergenceRetirementService {
    state: Arc<DaemonState>,
}

impl ConvergenceRetirementService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// Runs `PeerSyncSession::retire_conflict_copies_only` for `group_id`
    /// against this device's own cached local-only session (`DaemonState::
    /// local_retirement_session`) -- see that method's and `RetirementAttempt`'s
    /// own doc comments for what each outcome means to a caller tracking
    /// completion by generation.
    pub async fn reconcile_group(
        &self,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        let session = self.state.local_retirement_session(group_id);
        session.retire_conflict_copies_only(group_id).await
    }
}
