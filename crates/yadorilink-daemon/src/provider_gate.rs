//! The per-root provider decision, replacing the global "placeholder pipeline is
//! connected" switch.
//!
//! A root's provider declaration lives on its link. The direct-filesystem pipeline (scan,
//! watcher, flush, hydration, authoring from disk) is for PLAIN roots only: a provider
//! root, ready or not, is closed to it until the provider projection exists (the OS owns
//! the local copy; scanning it would read absence as deletion), and a link that declares a
//! provider whose state is missing is refused with "rebootstrap required".
//!
//! The model: a `ProviderKind::None` root runs the direct-filesystem pipeline and NEVER enters the File
//! Provider capability (it has no on-demand mechanism, so it never holds dataless items); a
//! `MacFileProvider` root may only when `PROVIDER_ROOTS_ENABLED` is on and its readiness
//! evidence says Ready. There is no global switch.

use yadorilink_replica_domain::session_state::Readiness;
use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;

/// Fails closed unless the group is a plain root. Called by every entry that would start,
/// hydrate, evict, author or tombstone from a directory.
pub(crate) fn require_filesystem_root(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
) -> Result<(), SyncError> {
    coordinator
        .provider_repository()
        .require_plain(group_id)
        .map_err(|e| SyncError::NotFilesystemRoot(e.to_string()))
}

/// THE switch for provider-backed roots (macOS File Provider). It is on; it gates the creation of
/// provider folders and whether a provider root may hold dataless items. Provider folders are still
/// refused on a platform without a File Provider. Nothing else is gated by a global.
pub(crate) const PROVIDER_ROOTS_ENABLED: bool = true;

/// The switch as the code consults it: the constant, or always on under `cfg(test)` (tests that need the
/// switch off use the per-daemon override).
pub(crate) fn provider_roots_enabled() -> bool {
    PROVIDER_ROOTS_ENABLED || cfg!(test)
}

/// Whether the root may run OnDemand (hold dataless items, evict): only a READY provider root, and only
/// while the provider-roots switch is on. A plain root never may; a read error answers `false` (fail closed).
pub(crate) fn root_allows_on_demand(coordinator: &ReplicaCoordinator, group_id: &str) -> bool {
    provider_roots_enabled()
        && matches!(
            coordinator.provider_repository().declaration_for_group(group_id),
            Ok(ProviderDeclaration::Provider(root)) if root.readiness() == Readiness::Ready
        )
}

#[cfg(test)]
mod tests;
