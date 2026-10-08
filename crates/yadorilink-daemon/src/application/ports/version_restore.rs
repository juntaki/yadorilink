//! What `VersionRestoreService` needs from `hydration`'s restore engine --
//! a distinct port from `MaterializationPort`: restoring a specific
//! retained version (or the most recent trashed one) is a different use
//! case from hydrate/evict, not a variation of it.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

/// What a folder restore did: the trashed entries it put back, the ones
/// it could not (with why), and whether the recursive operation it
/// restores is only partly known here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrashOperationRestore {
    pub restored: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub partial: bool,
}

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

    /// Restores every trashed entry the recursive operation that removed
    /// the trashed entry at `path` removed.
    fn restore_trashed_operation<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<TrashOperationRestore, SyncError>>;
}
