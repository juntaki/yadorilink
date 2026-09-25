use std::path::Path;

use yadorilink_local_storage::create_or_defer_placeholder;
use yadorilink_peer_session::PeerSessionError;

use super::MaterializationPlan;

impl super::super::LocalConvergenceExecutor {
    /// The placeholder write every placeholder-recording lane shares: verify
    /// the target, bump this path's mutation fence under `fence_reason`,
    /// write (or, on Windows, defer) the placeholder, and record the
    /// identity it was given. Returns whether the write was deferred to a
    /// separate process, in which case nothing is on disk under this name
    /// yet.
    pub(super) fn write_placeholder(
        &self,
        plan: &MaterializationPlan<'_>,
        out_path: &Path,
        fence_reason: &'static str,
    ) -> Result<bool, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        self.verify_write_target(group_id, out_path)?;
        self.state.dag_bump_mutation_fence(group_id, &record.path, fence_reason)?;
        let placeholder_outcome =
            create_or_defer_placeholder(out_path, record.size, record.mtime_unix_nanos)?;
        let placeholder_deferred = placeholder_outcome.is_deferred_to_a_separate_process();
        self.state
            .record_placeholder_identity(
                group_id,
                &record.path,
                placeholder_outcome,
                root_commit_permit,
            )
            .map_err(PeerSessionError::from)?;
        Ok(placeholder_deferred)
    }
}
