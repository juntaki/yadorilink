use std::sync::Arc;

use crate::sync_error::SyncError;

use super::ports::VersionRestorePort;

pub(crate) struct VersionRestoreService {
    port: Arc<dyn VersionRestorePort>,
}

impl VersionRestoreService {
    pub(crate) fn new(port: Arc<dyn VersionRestorePort>) -> Self {
        Self { port }
    }

    /// Restores `path` to `version_seq`, or -- when absent -- the most
    /// recent superseded version (spec "Restore without a version
    /// defaults to the most recent superseded version"). `Ok(false)`
    /// means there was no superseded version to restore to (a clear,
    /// distinguishable outcome, not an error).
    pub(crate) async fn restore_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: Option<i64>,
    ) -> Result<bool, SyncError> {
        let version_seq = match version_seq {
            Some(v) => v,
            None => match self.port.most_recent_superseded_version_seq(group_id, path)? {
                Some(v) => v,
                None => return Ok(false),
            },
        };
        self.port.restore_to_version(group_id, path, version_seq).await?;
        Ok(true)
    }

    pub(crate) async fn restore_trashed(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncError> {
        self.port.restore_trashed(group_id, path).await
    }
}
