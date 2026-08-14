//! What `MaterializationService` needs from the on-disk materialization
//! engine (the `hydration` module), expressed as a port so `application`
//! never imports the hydration or daemon-state modules directly.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

/// M4 Pass 4: `MaterializationService::evict`'s own truthful outcome DTO --
/// this port's own vocabulary (see this module's doc comment: `application`
/// never imports the hydration/daemon-state/filesystem-sync layers
/// directly), decoupled from but mirroring `yadorilink_filesystem_sync::
/// materialization_eviction::EvictionOutcome`'s own fields. Exists because
/// the eviction control-socket path used to discard this entirely
/// (`.map(|_| ())`), so a request that daemon-side silently did nothing --
/// the file was pinned, busy, not fully hydrated, or changed on disk right
/// before the commit -- still returned a bare `Ok`, and the CLI printed
/// "Evicted" regardless. `dehydrated: false` is the one fact that closes
/// that gap: the caller can no longer claim success without evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvictOutcome {
    /// Whether the on-disk file was actually reduced to a placeholder.
    /// `false` means this call left the file exactly as it was --
    /// nothing was freed, regardless of the exact reason (pinned, busy,
    /// not yet `Hydrated`, or its on-disk identity changed out from under
    /// the request).
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
}

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
    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError>;
}
