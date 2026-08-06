//! `impl yadorilink_filesystem_sync::materialization_execution::
//! MaterializationExecutionPort for ReplicaCoordinator` -- Phase 7D-10.5,
//! unblocked by 7D-10.4's `MaterializationIntentGuard` generalization.
//! Byte-identical in logic to `yadorilink-sync-core`'s own `impl
//! MaterializationExecutionPort for SyncState`
//! (`crates/yadorilink-sync-core/src/ports/materialization_execution_impl.rs`),
//! against `ReplicaCoordinator`'s own accessors. The three snapshot methods
//! and `reclaim_cached_blocks` delegate the same way the `SyncState` impl
//! does: through this same crate's own `MaterializationStatePort` impl
//! (`materialization_state.rs`, this pass) for the snapshots, and through
//! `yadorilink_sync_sqlite::block_deletion::BlockDeletionCoordinator`
//! (`MaterializationStatePort` and `block_deletion` both relocated there
//! from `yadorilink-sync-core`, see `docs/design/phase7d10-exit-report.md`'s
//! "item 1" addendum) for block reclamation.

use std::path::Path;
use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_filesystem_sync::materialization_execution::{
    EvictionEligibilitySnapshot as ExecEvictionEligibilitySnapshot,
    EvictionRevalidationSnapshot as ExecEvictionRevalidationSnapshot,
    MaterializationExecutionError, MaterializationExecutionPort, OpenMaterializationIntent,
    RepairRowSnapshot as ExecRepairRowSnapshot,
};
use yadorilink_filesystem_sync::materialization_types::{
    EvictableFile, RestoreCommitOutcome, RestoreOperation,
};
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::materialization_state_port::MaterializationStatePort;

use super::ReplicaCoordinator;

impl MaterializationExecutionPort for ReplicaCoordinator {
    fn get_exec_bit(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self.file_index_repository().get_exec_bit(group_id, path).map_err(SyncError::from)?)
    }

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError> {
        Ok(self.file_index_repository().get_file(group_id, path).map_err(SyncError::from)?)
    }

    fn list_evictable_files(
        &self,
        group_id: &str,
    ) -> Result<Vec<EvictableFile>, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .list_evictable_files(group_id)
            .map_err(SyncError::from)?)
    }

    fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .hydrated_usage_bytes(group_id)
            .map_err(SyncError::from)?)
    }

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .file_index_repository()
            .touch_last_accessed(group_id, path, unix_ts)
            .map_err(SyncError::from)?)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<String, MaterializationState>,
        MaterializationExecutionError,
    > {
        Ok(self
            .materialization_state_repository()
            .list_materialization_states(group_id)
            .map_err(SyncError::from)?)
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .has_materialization_intent(group_id, path)
            .map_err(SyncError::from)?)
    }

    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .clear_materialization_intent(group_id, path, permit)
            .map_err(SyncError::from)?)
    }

    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_job_repository()
            .begin_materialization_intent(group_id, path, target_version_hash, permit)
            .map_err(SyncError::from)?)
    }

    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, MaterializationExecutionError> {
        Ok(ReplicaCoordinator::mark_deleted_emitting_change(
            self,
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            emitter,
            permit,
        )?)
    }

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .dirty_path_repository()
            .record_dirty_path(group_id, path, change_kind, observed_at_unix_nanos, permit)
            .map_err(SyncError::from)?)
    }

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .set_materialization_state(group_id, path, state, permit)
            .map_err(SyncError::from)?)
    }

    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError> {
        Ok(self
            .materialization_state_repository()
            .transition_materialization_state(group_id, path, expected, next, permit)
            .map_err(SyncError::from)?)
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .list_restore_operations(group_id)
            .map_err(SyncError::from)?)
    }

    fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .commit_restore_operation(operation_id)
            .map_err(SyncError::from)?)
    }

    fn discard_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), MaterializationExecutionError> {
        Ok(self
            .restore_operation_repository()
            .discard_restore_operation(operation_id)
            .map_err(SyncError::from)?)
    }

    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::verify(root, group_id, self)?)
    }

    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError> {
        Ok(VerifiedRoot::open(root, group_id, self)?)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError> {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )
        .map_err(SyncError::from)?;
        Ok(Box::new(guard))
    }

    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionEligibilitySnapshot, MaterializationExecutionError> {
        let snapshot =
            <ReplicaCoordinator as MaterializationStatePort>::eviction_eligibility_snapshot(
                self, group_id, path,
            )
            .map_err(SyncError::from)?;
        Ok(ExecEvictionEligibilitySnapshot {
            pinned: snapshot.pinned,
            current_version: snapshot.current_version,
            record_kind: snapshot.record_kind,
        })
    }

    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecEvictionRevalidationSnapshot, MaterializationExecutionError> {
        let snapshot =
            <ReplicaCoordinator as MaterializationStatePort>::eviction_revalidation_snapshot(
                self, group_id, path,
            )
            .map_err(SyncError::from)?;
        Ok(ExecEvictionRevalidationSnapshot {
            current_version: snapshot.current_version,
            pinned: snapshot.pinned,
            materialization_state: snapshot.materialization_state,
            path_dirty: snapshot.path_dirty,
        })
    }

    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ExecRepairRowSnapshot, MaterializationExecutionError> {
        let snapshot = <ReplicaCoordinator as MaterializationStatePort>::repair_row_snapshot(
            self, group_id, path,
        )
        .map_err(SyncError::from)?;
        Ok(ExecRepairRowSnapshot {
            materialization_state: snapshot.materialization_state,
            record_kind: snapshot.record_kind,
            file: snapshot.file,
        })
    }

    fn reclaim_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError> {
        Ok(yadorilink_sync_sqlite::block_deletion::BlockDeletionCoordinator::new(store)
            .reclaim_cached_blocks(deletion_guard, custody, self)
            .map_err(SyncError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the impl above lets a real `Arc<ReplicaCoordinator>`
    /// unsize-coerce to `Arc<dyn MaterializationExecutionPort>`, and that
    /// calls through the coerced handle still dispatch correctly -- same
    /// shape as `materialization_state::tests::
    /// arc_replica_coordinator_coerces_to_port_trait` for the wider port
    /// this one narrows.
    #[test]
    fn arc_replica_coordinator_coerces_to_execution_port_trait() {
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let port: Arc<dyn MaterializationExecutionPort> = coordinator;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }
}
