//! Runs the ephemeral-conflict-copy retirement audit for one group at a
//! time. Extracted out of `engine_wrapper.rs`'s `run_retirement_pass`,
//! which used to pick among `crate::hydration::candidate_sessions` (this
//! device's currently-connected peer sessions for a group) purely because
//! `retire_conflict_copies_only` happened to live on `PeerSyncSession`.
//! It no longer does: retirement's decision is driven entirely by local
//! DAG/file-index/disk state, and it now runs on the executor that owns
//! exactly that — see `DaemonState::local_convergence`.

use std::sync::Arc;

use crate::local_convergence::types::RetirementAttempt;
use yadorilink_peer_session::PeerSessionError;

use crate::daemon_state::DaemonState;

pub struct ConvergenceRetirementService {
    state: Arc<DaemonState>,
}

impl ConvergenceRetirementService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    /// Retires `group_id`'s unjustified ephemeral conflict copies.
    ///
    /// Runs on this device's own local convergence executor, because the
    /// decision is a function of local durable state alone: which copies the
    /// current frontier still justifies, on this device's DAG, file index and
    /// disk.
    ///
    /// This used to pick a session — a live peer's when one existed, a
    /// synthetic local one otherwise — and neither was ever an input to the
    /// decision. The preference existed to *avoid* the fallback: constructing
    /// the synthetic session ran `NetmapChangeAuthenticator::new` ->
    /// `validate_linked_history_best_effort`, which could transiently
    /// quarantine every other connected session's authorization for this
    /// group, and because that session was cached per group per process there
    /// was no later tick to self-heal from it. With no session to construct,
    /// there is no side effect to dodge.
    ///
    /// See `RetirementAttempt`'s own doc comment for what each outcome means
    /// to a caller tracking completion by generation.
    pub async fn reconcile_group(
        &self,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        // No candidate session to pick. Retirement is decided from this
        // device's own durable state, so which peer happened to be connected
        // was never an input — selecting one was only ever a way to reach
        // local behaviour that lived on a session, and to avoid the
        // authorization side effect of manufacturing one when none existed.
        self.state.local_convergence().retire_conflict_copies_only(group_id).await
    }
}

#[cfg(test)]
mod tests;
