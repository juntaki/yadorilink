//! What `MaterializationService` needs from the on-disk materialization
//! engine (the `hydration` module), expressed as a port so `application`
//! never imports the hydration or daemon-state modules directly.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

pub(crate) trait MaterializationPort: Send + Sync {
    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    fn pin<'a>(&'a self, group_id: &'a str, path: &'a str) -> BoxFuture<'a, Result<(), SyncError>>;

    fn unpin<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    /// Synchronous: eviction is a local index/block-store operation with no
    /// remote round trip, unlike `hydrate`/`pin`/`unpin`.
    fn evict(&self, group_id: &str, path: &str) -> Result<(), SyncError>;
}
