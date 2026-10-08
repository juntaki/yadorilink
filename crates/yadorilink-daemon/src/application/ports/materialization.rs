//! What the hydrate/evict/status control commands need from the on-disk materialization
//! engine (the `hydration` module), expressed as a port so `application`
//! never imports the hydration or daemon-state modules directly.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

/// `MaterializationPort::evict`'s own truthful outcome DTO --
/// this port's own vocabulary (see this module's doc comment: `application`
/// never imports the hydration/daemon-state/filesystem-sync layers
/// directly), decoupled from but mirroring `yadorilink_filesystem_sync::
/// materialization_eviction::EvictionOutcome`'s own fields. Exists because
/// the eviction control-socket path used to discard this entirely
/// (`.map(|_| ())`), so a request that daemon-side silently did nothing --
/// the file was busy, not fully hydrated, or changed on disk right
/// before the commit -- still returned a bare `Ok`, and the CLI printed
/// "Evicted" regardless. `dehydrated: false` is the one fact that closes
/// that gap: the caller can no longer claim success without evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvictOutcome {
    /// Whether the on-disk file was actually reduced to a placeholder.
    /// `false` means this call left the file exactly as it was --
    /// nothing was freed, regardless of the exact reason (busy, not yet
    /// `Present`, or its on-disk identity changed out from under the
    /// request).
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
}

/// The transition a path is in the middle of, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalTransition {
    None,
    Hydrating,
    Evicting,
}

/// What stands on this device for one path: two independent facts, decoupled
/// from the persisted `MaterializationState` (per this module's own doc
/// comment, never import that layer directly).
///
/// * `object_present`: a physical local object stands at the path or is being
///   detached (a `Present` or `Evicting` row). `Hydrating` and `Remote` rows
///   report false.
/// * `current_content_present`: a usable proof names the current version, so
///   the bytes are usable. Implies `object_present`; false while a transition
///   is under way and whenever the evidence cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalPresence {
    pub object_present: bool,
    pub current_content_present: bool,
    pub transition: LocalTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaterializationStatusSummary {
    pub state: LocalPresence,
}

/// A request to assemble the CURRENT version of one file into a temp file (a provider root's
/// sink: the OS takes the bytes, the daemon writes no user-visible path).
pub(crate) struct TempMaterialization<'a> {
    pub group_id: &'a str,
    pub path: &'a str,
    /// `Some` only when the caller names a version; it must still be current.
    pub requested_version: Option<yadorilink_replica_domain::ids::VersionHash>,
    /// A file name inside the daemon's staging directory; the assembly is built beside it.
    pub staging_file: &'a std::path::Path,
}

/// A fully written, verified, fsynced file in the staging directory.
#[derive(Debug)]
pub(crate) struct TempAssembly {
    pub assembled: std::path::PathBuf,
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    pub size: u64,
}

#[derive(Debug)]
pub(crate) enum TempOutcome {
    Assembled(TempAssembly),
    /// The named version is not the current one, or the version kept moving while it was
    /// assembled. Old bytes are never returned.
    VersionOutOfDate,
}

pub(crate) trait MaterializationPort: Send + Sync {
    /// Assembles the current version into a staging temp file. The same hydration body as
    /// `hydrate`, with a different sink.
    fn materialize_to_temp<'a>(
        &'a self,
        request: TempMaterialization<'a>,
    ) -> BoxFuture<'a, Result<TempOutcome, SyncError>>;

    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    /// Synchronous: eviction is a local index/block-store operation with no
    /// remote round trip, unlike `hydrate`.
    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError>;

    /// Synchronous, same reasoning as `evict`: a plain local index read,
    /// never a peer round trip. `None` means the daemon has no
    /// materialization-state row for this path at all.
    fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError>;
}
