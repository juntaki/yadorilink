//! `impl yadorilink_sync_sqlite::MaterializationStatePort for
//! ReplicaCoordinator` -- Phase 7D-10.5, unblocked by 7D-10.4's
//! `MaterializationIntentGuard` generalization (this trait's
//! `open_materialization_intent_guard` was the one method that needed it).
//! Every other method is byte-identical in logic to `yadorilink-sync-core`'s
//! own `impl MaterializationStatePort for SyncState`
//! (`crates/yadorilink-sync-core/src/ports/materialization_state.rs`) --
//! same delegate shape, against `ReplicaCoordinator`'s own accessors
//! (already present since 7D-10.2/10.3) instead of `SyncState`'s. The three
//! `eviction_*_snapshot`/`repair_row_snapshot` methods are NOT overridden
//! here, matching `SyncState`'s own impl, which also relies on the trait's
//! provided defaults.
//!
//! Trait DEFINITION relocated to `yadorilink-sync-sqlite` in Phase 7D-10
//! (see `docs/design/phase7d10-exit-report.md`'s 2026-08-06 "item 1"
//! addendum) -- every method here now returns `yadorilink_sync_sqlite::
//! SyncSqliteError` directly, not `yadorilink_sync_core::SyncError` (what
//! this file used before the trait's own relocation). `mark_deleted_emitting_change`
//! inlines its `local_emission_auth` pre-check and repository write
//! directly (same shape as `yadorilink-sync-core`'s own impl) instead of
//! routing through the wider, `crate::sync_error::SyncError`-returning
//! `ReplicaCoordinator::mark_deleted_emitting_change` inherent method below
//! in `replica_coordinator.rs`, which keeps its own other callers working
//! unchanged. `open_materialization_intent_guard` needs no conversion
//! either: `MaterializationIntentGuard::open` already returns
//! `SyncSqliteError` directly (narrowed from `SyncError`, Phase 7D-10).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_filesystem_sync::materialization_types::{
    EvictableFile, RestoreCommitOutcome, RestoreOperation,
};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::CurrentVersionRecord;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::{
    MaterializationStatePort, OpenMaterializationIntent, SyncSqliteError,
};

use super::ReplicaCoordinator;

impl MaterializationStatePort for ReplicaCoordinator {
    fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().is_pinned(group_id, path)
    }

    fn blocks_referenced_outside_current_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<std::collections::HashSet<yadorilink_local_storage::ContentHash>, SyncSqliteError>
    {
        self.materialization_state_repository()
            .blocks_referenced_outside_current_file(group_id, path)
    }

    fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, SyncSqliteError> {
        self.sqlite().dag_get_current_version_record(group_id, path)
    }

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError> {
        self.file_index_repository().get_record_kind(group_id, path)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError> {
        self.file_index_repository().get_file(group_id, path)
    }

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().get_materialization_state(group_id, path)
    }

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.materialization_state_repository()
            .set_materialization_state(group_id, path, state, permit)
    }

    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError> {
        self.materialization_state_repository()
            .transition_materialization_state(group_id, path, expected, next, permit)
    }

    fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.dirty_path_repository().is_path_dirty(group_id, path)
    }

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().get_exec_bit(group_id, path)
    }

    fn list_evictable_files(&self, group_id: &str) -> Result<Vec<EvictableFile>, SyncSqliteError> {
        self.materialization_state_repository().list_evictable_files(group_id)
    }

    fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, SyncSqliteError> {
        self.materialization_state_repository().hydrated_usage_bytes(group_id)
    }

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().touch_last_accessed(group_id, path, unix_ts)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().list_materialization_states(group_id)
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.materialization_job_repository().has_materialization_intent(group_id, path)
    }

    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.materialization_job_repository().clear_materialization_intent(group_id, path, permit)
    }

    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.materialization_job_repository().begin_materialization_intent(
            group_id,
            path,
            target_version_hash,
            permit,
        )
    }

    fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().mark_deleted(group_id, path, device_id, permit)
    }

    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let auth = ReplicaCoordinator::local_emission_auth(self, group_id)?;
        Ok(self.file_index_repository().mark_deleted_emitting_change(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            emitter,
            permit,
            auth,
        )?)
    }

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().record_dirty_path(
            group_id,
            path,
            change_kind,
            observed_at_unix_nanos,
            permit,
        )
    }

    fn list_dirty_paths(
        &self,
        group_id: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::DirtyPath>, SyncSqliteError> {
        self.dirty_path_repository().list_dirty_paths(group_id)
    }

    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_exec_bit(group_id, path, exec_bit, permit)
    }

    fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_pinned(group_id, path, pinned)
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError> {
        self.sqlite().dag_get_change(hash)
    }

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.sqlite().dag_group_heads(group_id)
    }

    fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().upsert_file(group_id, record, permit)
    }

    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().upsert_file_with_origin(
            group_id,
            record,
            origin_device_id,
            permit,
        )
    }

    fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, SyncSqliteError> {
        self.sqlite().dag_list_versions(group_id, path)
    }

    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, SyncSqliteError> {
        self.restore_operation_repository().list_restore_operations(group_id)
    }

    fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, SyncSqliteError> {
        self.restore_operation_repository().commit_restore_operation(operation_id)
    }

    fn discard_restore_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.restore_operation_repository().discard_restore_operation(operation_id)
    }

    fn verify_root(&self, root: &Path, group_id: &str) -> Result<VerifiedRoot, SyncSqliteError> {
        Ok(VerifiedRoot::verify(root, group_id, self)?)
    }

    fn open_root(&self, root: &Path, group_id: &str) -> Result<VerifiedRoot, SyncSqliteError> {
        Ok(VerifiedRoot::open(root, group_id, self)?)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, SyncSqliteError> {
        let guard = crate::materialization_intent::MaterializationIntentGuard::open(
            self,
            group_id,
            path,
            target_version_hash,
            permit,
        )?;
        Ok(Box::new(guard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves the direct impl above lets a real `Arc<ReplicaCoordinator>`
    /// unsize-coerce to `Arc<dyn MaterializationStatePort>`, and that calls
    /// through the coerced handle still dispatch correctly -- mirrors
    /// `yadorilink-sync-core`'s own `arc_sync_state_coerces_to_port_trait`.
    #[test]
    fn arc_replica_coordinator_coerces_to_port_trait() {
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let port: Arc<dyn MaterializationStatePort> = coordinator;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }
}
