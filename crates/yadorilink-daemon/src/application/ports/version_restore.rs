//! What `VersionRestoreService` needs from `hydration`'s restore engine --
//! a distinct port from `MaterializationPort`: restoring a specific
//! retained version (or the most recent trashed one) is a different use
//! case from hydrate/pin/unpin/evict, not a variation of it.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

pub(crate) trait VersionRestorePort: Send + Sync {
    /// `Ok(None)` when no superseded version exists to restore to --
    /// distinct from an error reading the version history.
    fn most_recent_superseded_version_seq(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<i64>, SyncError>;

    fn restore_to_version<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        version_seq: i64,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    fn restore_trashed<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;
}
