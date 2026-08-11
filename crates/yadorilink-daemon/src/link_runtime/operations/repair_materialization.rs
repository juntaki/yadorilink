//! Interrupted-materialization/restore-operation repair for one link,
//! admitted through its `RootLease`. Deduplicates a "begin a `LinkOperation`,
//! mint a permit, call the sync-core repair function" ceremony that used to
//! be written out three times: once for restore-operation reconciliation and
//! once for materialization repair at link-startup
//! (the daemon's own `LinkRuntimeController::start_inner`), and again for materialization
//! repair on the periodic live-repair task. All three now share this module,
//! so a caller cannot forget to hold the operation across the repair call --
//! there is no other way to reach `materialization::repair_interrupted_
//! materializations`/`reconcile_restore_operations` from this crate.
//!
//! Deliberately does NOT bundle restore-operation reconciliation and
//! materialization repair into a single call: the two callers need
//! different failure handling (restore-operation reconciliation errors are
//! hard startup failures for this link; materialization-repair errors are
//! soft, deferring only this boot's tombstone emission -- see each
//! function's own return type and each call site's own handling).

use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_filesystem_sync::materialization_repair::{
    MaterializationRepairReport, RestoreRecoveryReport,
};
use yadorilink_local_storage::BlockStore;
use yadorilink_root_authority::root_commit::RootLease;

use crate::replica_coordinator::ReplicaCoordinator;

/// Reconciles any restore operation this link's index still has an open
/// intent for. Admits its own `LinkOperation` from `root_lease`, held for
/// the whole call.
///
/// Phase 7D-10.5: repointed from `&Arc<SyncState>` to
/// `&Arc<ReplicaCoordinator>` -- both free functions this delegates to take
/// `&dyn MaterializationExecutionPort`, which `ReplicaCoordinator` now
/// implements (this same pass), so a real `Arc<ReplicaCoordinator>`
/// coerces here exactly the way `Arc<SyncState>` used to.
pub(crate) fn reconcile_restore_operations(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    root_lease: &Arc<RootLease>,
    root: &Path,
    group_id: &str,
) -> Result<RestoreRecoveryReport, SyncError> {
    let op = root_lease.begin_operation()?;
    // `reconcile_restore_operations` now returns `yadorilink_filesystem_sync::
    // materialization_execution::MaterializationExecutionError` (Phase 7D-9C,
    // sixth pass -- it moved out of sync-core alongside `evict_file`'s own
    // earlier move in this sub-phase) -- mapped at this one boundary via the
    // same `impl From<MaterializationExecutionError> for SyncError` bridge
    // `hydration.rs::evict` already uses.
    yadorilink_filesystem_sync::materialization_repair::reconcile_restore_operations(
        replica_coordinator.as_ref(),
        root,
        group_id,
        &op.permit(),
    )
    .map_err(SyncError::from)
}

/// Repairs any `Hydrated`-but-disk-inconsistent row this link's index has --
/// see `yadorilink_sync_core::materialization::repair_interrupted_
/// materializations`'s own doc for exactly what crash window this closes.
/// Admits its own `LinkOperation` from `root_lease`, held across both the
/// (potentially slow) disk walk/reconstruct work and the commits it makes.
///
/// A prior pass (7D-10.5's first attempt) found this one, unlike
/// `reconcile_restore_operations` above, was NOT safe to repoint to
/// `&Arc<ReplicaCoordinator>` even though it type-checked:
/// `repair_interrupted_materializations_inner`
/// (`yadorilink-filesystem-sync::materialization_repair`) calls
/// `state.path_lock(group_id, path)`, and at the time `ReplicaCoordinator`
/// constructed its OWN, separate `PathLockRegistry` instance
/// (`ReplicaCoordinator::from_database`) rather than sharing `SyncState`'s
/// -- so this call site and `yadorilink-local-capture::LocalChangeProcessor`
/// (which still locks through `SyncState`'s own registry, via the fourth
/// port, `LocalMutationStore`) would have locked through two non-cooperating
/// `Mutex`es for the same logical path.
///
/// Phase 7D-10.5's shared-registry fix
/// (`yadorilink_sync_core::index::SyncState::path_lock_registry_handle`/
/// `startup_readiness_handle`, threaded through
/// `ReplicaCoordinator::from_database`) closes that gap:
/// `ReplicaCoordinator::path_lock_registry()` is now the SAME live registry
/// `SyncState::path_lock_registry()` is, so this repoint no longer splits
/// the per-path lock. Re-verified against the 5 tests the prior pass found
/// hanging (`adapters::runtime::link_runtime_controller::tests::*`, symptom
/// `"the initial scan must finish: Elapsed(())"`) -- all pass cleanly now.
pub(crate) fn repair_interrupted_materializations(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    block_store: &Arc<dyn BlockStore + Send + Sync>,
    root_lease: &Arc<RootLease>,
    root: &Path,
    group_id: &str,
) -> Result<MaterializationRepairReport, SyncError> {
    let op = root_lease.begin_operation()?;
    // See `reconcile_restore_operations` above for the same error-type note.
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        replica_coordinator.as_ref(),
        &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(block_store.clone()),
        root,
        group_id,
        &op.permit(),
    )
    .map_err(SyncError::from)
}

/// M1-5: backfills a persisted placeholder identity for every path this
/// link's index still shows as `Placeholder` with none recorded -- see
/// `yadorilink_filesystem_sync::materialization_repair::
/// backfill_placeholder_generations`'s own doc comment for the crash
/// window this closes. Admits its own `LinkOperation` from `root_lease`,
/// same shape as `repair_interrupted_materializations` above.
pub(crate) fn backfill_placeholder_generations(
    replica_coordinator: &Arc<ReplicaCoordinator>,
    root_lease: &Arc<RootLease>,
    root: &Path,
    group_id: &str,
) -> Result<usize, SyncError> {
    let op = root_lease.begin_operation()?;
    yadorilink_filesystem_sync::materialization_repair::backfill_placeholder_generations(
        replica_coordinator.as_ref(),
        root,
        group_id,
        &op.permit(),
    )
    .map_err(SyncError::from)
}
