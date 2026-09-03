//! `impl LocalMutationStore for ReplicaCoordinator` -- Phase 7D-10.5's
//! `LocalMutationStore` port investigation (the "fourth port"
//! `docs/design/phase7d10-exit-report.md`'s earlier addenda named as the
//! reason several `link_runtime` call sites had to stay pinned to
//! `Arc<SyncState>`: `yadorilink-local-capture::LocalChangeProcessor` needs a
//! concrete `Arc<dyn LocalMutationStore>`, and only `SyncState` implemented
//! it, so any call site that needed to mutually exclude against local
//! capture (via `path_lock`) could not move to `ReplicaCoordinator` without
//! splitting that mutual exclusion across two non-cooperating registries).
//!
//! That blocker is now closed on two fronts, both prerequisites this impl
//! relies on rather than re-derives:
//!   - The shared-registry fix in `replica_coordinator.rs`'s own
//!     `from_database` doc comment: `ReplicaCoordinator::path_lock_registry()`
//!     is the SAME live `PathLockRegistry` `SyncState::path_lock_registry()`
//!     is, not an independent instance.
//!   - `ReplicaCoordinator` already implements `RootVerificationStatePort`
//!     (Phase 7D-10.2), which `verify_root`/`open_root` below need to pass to
//!     `VerifiedRoot::verify`/`VerifiedRoot::open`.
//!
//! Every method below is a verbatim copy of `impl LocalMutationStore for
//! SyncState`'s own body
//! (`crates/yadorilink-local-capture/src/ports/local_mutation.rs`),
//! substituting `ReplicaCoordinator::<accessor>(self)` for
//! `SyncState::<accessor>(self)` against this struct's own already-existing
//! accessors (all of them predate this pass -- no new accessor needed).
//! Legal under the orphan rule the same way `MaterializationIntentJournal`'s
//! impl in this same file's parent module is: the trait is foreign
//! (`yadorilink-local-capture`), but `ReplicaCoordinator` is local to this
//! crate.
//!
//! `build_change_processor` (`link_runtime/startup.rs`) is now this port's
//! one production call site (`LinkRuntimeDependencies::replica_coordinator`),
//! since `DaemonState.sync_state`'s own removal.
//!
//! `LocalMutationStore`'s associated error surface narrowed from
//! `yadorilink_sync_core::SyncError` to `yadorilink_sync_sqlite::
//! SyncSqliteError` (Phase 7D-10): every method below either delegates
//! directly to a `yadorilink-sync-sqlite` repository call (already native
//! `SyncSqliteError`, no conversion needed) or, for the three
//! `*_emitting_change` methods, inlines the `local_emission_auth`
//! precondition check plus the repository write directly instead of
//! delegating through the wider `ReplicaCoordinator::upsert_file_emitting_
//! change`/etc. inherent methods (which still return `crate::sync_error::
//! SyncError`, the daemon-wide catch-all) -- `SyncSqliteError` already has
//! `From<yadorilink_replica_domain::change::PolicyUnavailable>` (added
//! alongside `MaterializationStatePort`'s identical narrowing, see
//! `docs/design/phase7d10-exit-report.md`'s "item 1" addendum), so
//! `local_emission_auth`'s own `PolicyUnavailable` error converts losslessly
//! without needing the wider `SyncError` type at all. `SyncState`'s own
//! `impl LocalMutationStore for SyncState`
//! (`yadorilink-local-capture/src/ports/local_mutation.rs`) narrowed the
//! same way, so both implementations of this one trait still agree.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_local_capture::ports::{LocalChangeEmission, LocalMutationStore};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{
    ChangeContent, DirtyPath, LocalFileMetaColumns, MaterializationState, PreparedLocalMutation,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::ReplicaCoordinator;

impl LocalMutationStore for ReplicaCoordinator {
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        ReplicaCoordinator::path_lock_registry(self).path_lock(group_id, path)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError> {
        self.file_index_repository().get_file(group_id, path)
    }

    fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        self.file_index_repository().get_authoring_change_hash(group_id, path)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().list_materialization_states(group_id)
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
        self.materialization_state_repository().set_materialization_state(
            group_id, path, state, permit,
        )
    }

    fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<
        HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
        SyncSqliteError,
    > {
        self.materialization_state_repository().list_placeholder_generations(group_id)
    }

    fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>, SyncSqliteError>
    {
        self.materialization_state_repository().get_placeholder_generation(group_id, path)
    }

    /// M2-2: delegates to `crate::placeholder_inspect_windows`, the only
    /// module in this crate allowed to make a real `CfGetPlaceholderInfo`
    /// call -- see that module's own doc comment for why this daemon
    /// process, not `yadorilink-cfapi-host.exe`, makes the call directly.
    /// The `#[cfg(not(windows))]` arm is unreachable in practice:
    /// `local_change.rs`'s dirty-detection verdict only ever calls this
    /// method from its own `#[cfg(windows)]` branch, so this body exists
    /// solely to keep the trait implementable (and this crate compiling)
    /// on every other platform.
    fn inspect_windows_placeholder(
        &self,
        path: &Path,
        expected_generation: u64,
    ) -> yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus {
        #[cfg(windows)]
        {
            crate::placeholder_inspect_windows::inspect_placeholder(path, expected_generation)
        }
        #[cfg(not(windows))]
        {
            let _ = (path, expected_generation);
            unreachable!(
                "inspect_windows_placeholder is only ever called from local_change.rs's own \
                 #[cfg(windows)] branch"
            )
        }
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.materialization_intent_repository().has_materialization_intent(group_id, path)
    }

    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        // While a projection obligation exists for this path, an absent
        // local file must not yet be interpreted as an offline user
        // deletion -- any row at all (pending or the parked
        // `ignore_blocked`) means the path is still being placed locally.
        Ok(self.sqlite().dag_lookup_projection_obligation(group_id, path)?.is_some())
    }

    fn is_held(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        Ok(self.materialization_state_repository().get_held_state(group_id, path)?.is_some())
    }

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError> {
        self.file_index_repository().get_record_kind(group_id, path)
    }

    fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_record_kind(group_id, path, kind, permit)
    }

    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.file_index_repository().get_symlink_target(group_id, path)
    }

    fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_symlink_target(group_id, path, target)
    }

    fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_symlink_out_of_root(group_id, path, out_of_root)
    }

    fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, SyncSqliteError> {
        self.file_index_repository().get_unix_mode(group_id, path)
    }

    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SyncSqliteError> {
        self.file_index_repository().get_xattrs(group_id, path)
    }

    fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<
            yadorilink_filesystem_sync::materialization_execution::MaterializedFingerprint,
        >,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.materialization_state_repository().record_materialized_fingerprint(
            group_id,
            path,
            fingerprint,
            permit,
        )
    }

    fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_unix_mode(group_id, path, unix_mode, permit)
    }

    fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().set_xattrs(group_id, path, xattrs, permit)
    }

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.sqlite().dag_group_heads(group_id)
    }

    fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        filesystem_identity: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        emission: LocalChangeEmission<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().upsert_file_emitting_change(
            group_id,
            record,
            origin_device_id,
            content,
            meta,
            filesystem_identity,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
                emitter: emission.emitter,
                permit: emission.permit,
                auth,
            },
        )
    }

    fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().commit_local_mutations_batch(
            group_id,
            mutations,
            evidence,
            origin_device_id,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
                emitter: emission.emitter,
                permit: emission.permit,
                auth,
            },
        )
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

    fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().upsert_files_batch(group_id, records, origin_device_id, permit)
    }

    fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        emission: LocalChangeEmission<'_>,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().upsert_files_batch_emitting_change(
            group_id,
            records,
            origin_device_id,
            content,
            metas,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
                emitter: emission.emitter,
                permit: emission.permit,
                auth,
            },
        )
    }

    fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.file_index_repository().mark_deleted_at(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            permit,
        )
    }

    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        publish_absent_proof: bool,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().mark_deleted_emitting_change(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            publish_absent_proof,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext { emitter, permit, auth },
        )
    }

    fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().remove_file(group_id, path, permit)
    }

    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError> {
        self.change_history_repository().record_group_block_provenance(group_id, block_hashes)
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

    fn record_dirty_paths_batch(
        &self,
        group_id: &str,
        entries: &[(String, String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().record_dirty_paths_batch(group_id, entries, permit)
    }

    fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().mark_dirty_path_attempt(group_id, path, last_error, permit)
    }

    fn clear_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().clear_dirty_path(group_id, path, permit)
    }

    fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.dirty_path_repository().clear_dirty_paths_conditional_batch(group_id, entries, permit)
    }

    fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError> {
        self.dirty_path_repository().list_dirty_paths(group_id)
    }

    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        self.file_index_repository().list_files(group_id)
    }

    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(root, group_id, self)
            .map_err(SyncSqliteError::from)
    }

    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group_id, self)
            .map_err(SyncSqliteError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves a real `Arc<ReplicaCoordinator>` unsize-coerces to `Arc<dyn
    /// LocalMutationStore>` and dispatches correctly -- mirrors
    /// `yadorilink-local-capture`'s own `arc_sync_state_coerces_to_port_trait`.
    #[test]
    fn arc_replica_coordinator_coerces_to_local_mutation_store() {
        let coordinator: Arc<ReplicaCoordinator> =
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let port: Arc<dyn LocalMutationStore> = coordinator;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }

    /// A lock taken through `LocalMutationStore::path_lock` and a lock taken
    /// through the coordinator's own `path_lock_registry()` for the
    /// identical `(group_id, path)` must be the literal same `Arc`, or the
    /// two do not actually serialize against each other. This used to be
    /// checked cross-crate against a live `SyncState`'s registry (the
    /// registries had to be the SAME `Arc` while `DaemonState` could still
    /// hold both a `SyncState` and a `ReplicaCoordinator` simultaneously) --
    /// `DaemonState` has not held a `SyncState` since Phase 7D-10.9, so
    /// `ReplicaCoordinator` now owns its own independent
    /// `crate::sync_runtime::path_locks::PathLockRegistry`
    /// (`docs/design/phase7d10-exit-report.md`'s addendum on this), and the
    /// only invariant left to prove is internal self-consistency.
    #[test]
    fn path_lock_is_shared_across_the_coordinators_own_accessors() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();

        let via_trait = LocalMutationStore::path_lock(&coordinator, "group-a", "path/a.txt");
        let via_registry = coordinator.path_lock_registry().path_lock("group-a", "path/a.txt");

        assert!(
            Arc::ptr_eq(&via_trait, &via_registry),
            "ReplicaCoordinator's LocalMutationStore::path_lock must resolve through its own \
             path_lock_registry(), or local capture and anything reached through \
             ReplicaCoordinator no longer mutually exclude on the same path"
        );
    }
}
