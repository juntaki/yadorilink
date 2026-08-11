//! `TestReplica` -- a thin, crate-local wrapper around
//! `yadorilink_daemon::replica_coordinator::ReplicaCoordinator` that this
//! crate's own `#[cfg(test)]` code (in `local_change.rs` and
//! `ports/local_mutation.rs`) uses to build a real, database-backed
//! `LocalMutationStore` fixture.
//!
//! Why a wrapper, not `ReplicaCoordinator` directly: `LocalMutationStore`
//! is defined in *this* crate. Coercing `Arc<ReplicaCoordinator>` straight
//! to `Arc<dyn LocalMutationStore>` from inside this crate's own
//! `#[cfg(test)]` code does not compile -- rustc reports "there are
//! multiple different versions of crate `yadorilink_local_capture` in the
//! dependency graph". This crate's own `--lib` test target is a SEPARATE
//! compilation from the plain library artifact `yadorilink-daemon` (a dev
//! dependency here) links against for its own `impl LocalMutationStore for
//! ReplicaCoordinator` (`yadorilink-daemon/src/replica_coordinator/
//! local_mutation.rs`) -- so that impl and this crate's own test code
//! disagree about which `LocalMutationStore` trait (from which
//! compilation) they mean, even though the source is identical. External
//! `tests/*.rs` integration binaries do not have this problem (they link
//! the plain library normally, the same one `ReplicaCoordinator`'s impl
//! was built against) -- see `tests/materialization_local_capture.rs`'s own
//! doc comment for the identical reasoning this crate already established
//! for `SyncState`/`yadorilink-sync-core` before Phase 7D-10 deleted it.
//!
//! `TestReplica` sidesteps the problem: it is a type local to *this*
//! crate's own compilation (test or not), so `impl LocalMutationStore for
//! TestReplica` is an ordinary, single-compilation-unit impl with no
//! cross-crate identity mismatch. It `Deref`s to `ReplicaCoordinator` for
//! every accessor this crate's tests call directly
//! (`link_repository()`, `file_index_repository()`, `sqlite()`, etc. --
//! all real `pub fn`s on `ReplicaCoordinator`, callable across the crate
//! boundary with no trait-identity issue since they return concrete
//! `yadorilink-sync-sqlite` types, not a `yadorilink-local-capture` trait
//! object), and its `LocalMutationStore` impl body is a verbatim copy of
//! `ReplicaCoordinator`'s own (`yadorilink-daemon/src/replica_coordinator/
//! local_mutation.rs`), delegating to those same accessors.
//!
//! `local_change_auth_provider`/`local_emission_auth` are NOT reached via
//! `ReplicaCoordinator`: that pair is `pub(crate)` to `yadorilink-daemon`
//! (not visible here), so `TestReplica` keeps its own copy of the same
//! trivial "call the configured provider, or fall back to
//! `ChangeAuth::PLACEHOLDER`" logic, backed by its own field. Its own
//! `set_local_change_auth_provider` inherent method shadows
//! `ReplicaCoordinator`'s (Rust always prefers an inherent method over a
//! `Deref` target's), so `state.set_local_change_auth_provider(..)` in this
//! crate's tests configures *this* copy, which is what
//! `TestReplica`'s own `LocalMutationStore::upsert_file_emitting_change`/
//! `upsert_files_batch_emitting_change`/`mark_deleted_emitting_change`
//! actually consult.

use std::sync::{Arc, Mutex};

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::change::{ChangeAuth, PolicyUnavailable};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{
    ChangeContent, DirtyPath, LocalFileMetaColumns, MaterializationState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::ports::LocalMutationStore;

type LocalChangeAuthProvider =
    dyn Fn(&str) -> Result<ChangeAuth, PolicyUnavailable> + Send + Sync + 'static;

pub(crate) struct TestReplica {
    inner: Arc<ReplicaCoordinator>,
    local_change_auth_provider: Mutex<Option<Arc<LocalChangeAuthProvider>>>,
    /// M2-2: `inspect_windows_placeholder` is a live `CfGetPlaceholderInfo`
    /// call in production (`yadorilink-daemon::placeholder_inspect_windows`,
    /// Windows-only) -- nothing this crate's own `#[cfg(test)]` code can
    /// exercise against a real placeholder, on any platform. Configurable
    /// via `set_windows_placeholder_inspect_result` so a test can pin
    /// exactly the verdict `local_change.rs`'s Windows dirty-detection
    /// branch should see; defaults to `Unknown`, matching this whole
    /// mechanism's own fail-closed contract for a scenario nothing has set
    /// up an expectation for.
    windows_placeholder_inspect_result:
        Mutex<yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus>,
}

impl TestReplica {
    pub(crate) fn open_in_memory() -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        Ok(Self {
            inner: Arc::new(ReplicaCoordinator::open_in_memory()?),
            local_change_auth_provider: Mutex::new(None),
            windows_placeholder_inspect_result: Mutex::new(
                yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus::Unknown,
            ),
        })
    }

    /// Configures the verdict `LocalMutationStore::inspect_windows_placeholder`
    /// returns for every subsequent call on this `TestReplica`, regardless
    /// of `path`/`expected_generation` -- coarse (not per-path), matching
    /// this fixture's one-scenario-per-test usage. Its only caller
    /// (`local_change.rs`'s `untouched_placeholder_verdict_windows_tests`)
    /// is itself `#[cfg(all(test, windows))]`, so this has no caller at
    /// all on a non-Windows build -- not dead code, just untriggered on
    /// this platform.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn set_windows_placeholder_inspect_result(
        &self,
        result: yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus,
    ) {
        *self.windows_placeholder_inspect_result.lock().unwrap_or_else(|p| p.into_inner()) = result;
    }

    /// The wrapped `ReplicaCoordinator` directly -- for callers (e.g.
    /// `dag_import::ensure_initial_import`) that need a concrete
    /// `&ReplicaCoordinator` to satisfy a `yadorilink-daemon`-defined trait
    /// bound (`DagImportSource`), which `Deref` coercion alone does not
    /// reach through for a generic parameter.
    pub(crate) fn coordinator(&self) -> &ReplicaCoordinator {
        &self.inner
    }

    pub(crate) fn set_local_change_auth_provider(&self, provider: Arc<LocalChangeAuthProvider>) {
        *self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    fn local_emission_auth(&self, group_id: &str) -> Result<ChangeAuth, PolicyUnavailable> {
        match self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok(ChangeAuth::PLACEHOLDER),
        }
    }
}

impl std::ops::Deref for TestReplica {
    type Target = ReplicaCoordinator;
    fn deref(&self) -> &ReplicaCoordinator {
        &self.inner
    }
}

impl LocalMutationStore for TestReplica {
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_lock_registry().path_lock(group_id, path)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError> {
        self.file_index_repository().get_file(group_id, path)
    }

    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().list_materialization_states(group_id)
    }

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError> {
        self.materialization_state_repository().get_materialization_state(group_id, path)
    }

    fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<
        std::collections::HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
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

    fn inspect_windows_placeholder(
        &self,
        path: &std::path::Path,
        expected_generation: u64,
    ) -> yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus {
        let _ = (path, expected_generation);
        *self.windows_placeholder_inspect_result.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.materialization_job_repository().has_materialization_intent(group_id, path)
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

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().get_exec_bit(group_id, path)
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
        emission: crate::ports::LocalChangeEmission<'_, '_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().upsert_file_emitting_change(
            group_id,
            record,
            origin_device_id,
            content,
            meta,
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
        emission: crate::ports::LocalChangeEmission<'_, '_>,
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
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let auth = self.local_emission_auth(group_id).map_err(SyncSqliteError::from)?;
        self.file_index_repository().mark_deleted_emitting_change(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
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

    fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError> {
        self.dirty_path_repository().list_dirty_paths(group_id)
    }

    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        self.file_index_repository().list_files(group_id)
    }

    fn verify_root(
        &self,
        root: &std::path::Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::verify(
            root,
            group_id,
            self.inner.as_ref(),
        )
        .map_err(SyncSqliteError::from)
    }

    fn open_root(
        &self,
        root: &std::path::Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError> {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root,
            group_id,
            self.inner.as_ref(),
        )
        .map_err(SyncSqliteError::from)
    }
}
