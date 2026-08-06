//! `ReplicaCoordinator` -- the daemon-owned composition-root type Phase
//! 7D-10.2 introduces as the eventual replacement for
//! `yadorilink_sync_core::index::SyncState`'s permanently-remaining 17
//! production methods and five `ports/` trait impls, per
//! `docs/design/phase7d10-elimination-plan.md` §2.3.
//!
//! # Why this exists, and why it does NOT wrap or get wrapped by `SyncState`
//!
//! The plan's own text describes the target shape as "`SyncState`'s methods
//! become thin forwards to [a `ReplicaCoordinator`] it now holds" --
//! evaluated fresh against this workspace's actual crate graph, that exact
//! mechanism is not implementable: `yadorilink-daemon` already depends on
//! `yadorilink-sync-core` (`Cargo.toml`), so `SyncState` (defined in
//! `yadorilink-sync-core`) cannot hold a field of type `ReplicaCoordinator`
//! (defined here, in `yadorilink-daemon`) without `yadorilink-sync-core`
//! depending back on `yadorilink-daemon` -- an unresolvable dependency
//! cycle. Reversing the wrapping direction (`ReplicaCoordinator` holds
//! `Arc<SyncState>` and forwards into it) would compile, but would leave
//! the real logic permanently in `yadorilink-sync-core`, defeating this
//! whole phase's purpose (that crate must eventually be deletable).
//!
//! This struct instead holds its OWN fields, built fresh from the SAME
//! underlying `Arc<SyncDatabase>` `SyncState` already opened (via
//! `SyncState::database`, added alongside this struct) -- never a second,
//! independently-opened `SyncDatabase` against the same file, which would
//! split the in-process writer-serialization gate across two pools.
//! `SyncState`'s own 17 methods and five port impls are left completely
//! UNCHANGED in `yadorilink-sync-core` (not deleted, not turned into
//! forwards) because every one of that crate's own remaining internal
//! callers (`dag_import.rs`, `recovery.rs`, `materialization.rs`,
//! `block_deletion.rs`, the ports/ impls' own trait objects) still needs a
//! fully-functional concrete `SyncState`, and none of them are repointed to
//! `ReplicaCoordinator` in this sub-phase (that is 7D-10.3's job). The
//! result is real, tested, additive duplication for this transitional
//! period, not forwarding -- see `docs/design/phase7d10-exit-report.md`'s
//! 7D-10.2 addendum for the full reasoning and the one port-impl caveat
//! below.
//!
//! # Scope actually delivered this pass: 17 methods + 2 of 5 port impls
//!
//! All 17 of `SyncState`'s permanently-remaining production methods (per
//! `phase7d9f-exit-report.md` §14.3) are reproduced verbatim below. Of the
//! five `ports/` trait impls the plan names, only two -- `impl
//! RootVerificationStatePort for ReplicaCoordinator` and `impl
//! AuthenticatedHistorySource for ReplicaCoordinator` -- are included here.
//!
//! The other three (`PeerReplicaStatePort`, `MaterializationStatePort`,
//! `MaterializationExecutionPort`) each have one method,
//! `open_materialization_intent_guard`, whose trait signature returns (or,
//! for `PeerReplicaStatePort`, boxes) `yadorilink_sync_core::materialization
//! ::MaterializationIntentGuard<'a>` -- a `#[must_use]` safety-critical type
//! (its own doc comment: "an intent guard that is neither cleared nor
//! deliberately dropped leaves a durable materialization intent behind")
//! whose constructor is `pub(crate)` to `yadorilink-sync-core` AND, by
//! explicit documented design choice (not an oversight -- see that struct's
//! own field doc comment), hardwired to hold a concrete `&'a SyncState`
//! rather than `&'a dyn MaterializationStatePort`. Reproducing these three
//! impls for `ReplicaCoordinator` therefore requires either genericizing
//! that guard (reversing a deliberate prior design decision, and one shared
//! by a trait -- `MaterializationExecutionPort`, from
//! `yadorilink-filesystem-sync` -- whose own return type would need to
//! change too) or duplicating the guard's own begin/clear journal logic a
//! second time outside the one module
//! `scripts/check-materialization-journal.py` polices as the sanctioned
//! single seam for it. Both are real design decisions with data-loss-safety
//! stakes, not mechanical relocation -- out of this pass's discretion, and
//! flagged as this sub-phase's one open follow-up rather than rushed.

mod local_mutation;
mod materialization_execution;
mod materialization_state;
mod peer_replica_state;

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::recovery_snapshot::RecoverySnapshotReader;
use crate::sync_error::SyncError;
use crate::sync_runtime::materialization_wake::MaterializationWake;
use crate::sync_runtime::path_locks::PathLockRegistry;
use crate::sync_runtime::schema::{post_dag_schema, pre_dag_schema};
use crate::sync_runtime::startup_readiness::StartupReadinessRegistry;
use yadorilink_filesystem_sync::materialization_types::RestoreOperation;
use yadorilink_local_capture::ports::LocalChangeEmission;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PolicyUnavailable};
use yadorilink_replica_domain::file::{FileRecord, FileVersion};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};
use yadorilink_replica_domain::session_state::ChangeContent;
use yadorilink_replica_domain::session_state::{
    LocalFileMetaColumns, RetroactiveRepairOutcome, StartupFailed,
};
use yadorilink_replica_engine::authenticated_history::AuthenticatedHistorySource;
use yadorilink_replica_engine::compaction::{
    Checkpoint, CheckpointStore, CompactionDagStore, DeviceFrontierStore,
};
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_root_authority::error::RootAuthorityError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::RootVerificationStatePort;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

pub(crate) type LocalChangeAuthProvider =
    dyn Fn(&str) -> Result<ChangeAuth, PolicyUnavailable> + Send + Sync + 'static;
/// Local copy of what was `yadorilink_sync_core::index::RepairElectionProvider`
/// -- a plain type alias with no logic of its own (see that module's
/// definition), so Phase 7D-10's final deletion pass redefines it here
/// rather than relocating anything.
pub type RepairElectionProvider = dyn Fn(
        &str,
        yadorilink_replica_engine::repair_election::RepairObligationId,
    ) -> Result<
        yadorilink_replica_engine::repair_election::RepairElectionContext,
        PolicyUnavailable,
    > + Send
    + Sync
    + 'static;

/// See this module's own doc comment for why this struct's fields exactly
/// mirror `SyncState`'s current field list (`phase7d10-elimination-plan.md`
/// §2.2) rather than forwarding to it.
pub struct ReplicaCoordinator {
    database: Arc<SyncDatabase>,
    sqlite: Arc<yadorilink_sync_sqlite::SqliteSyncStore>,
    link_repository: yadorilink_sync_sqlite::link::LinkRepository,
    enrollment_repository: yadorilink_sync_sqlite::enrollment::EnrollmentRepository,
    file_index_repository: yadorilink_sync_sqlite::file_index::FileIndexRepository,
    materialization_state_repository: yadorilink_sync_sqlite::MaterializationStateRepository,
    change_history_repository: yadorilink_sync_sqlite::ChangeHistoryRepository,
    materialization_job_repository: yadorilink_sync_sqlite::MaterializationJobRepository,
    policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository,
    dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository,
    restore_operation_repository: yadorilink_sync_sqlite::RestoreOperationRepository,
    handoff_lease_repository: yadorilink_sync_sqlite::HandoffLeaseRepository,
    rebootstrap_store_repository: yadorilink_sync_sqlite::RebootstrapStoreRepository,
    role_loss_operation_repository: yadorilink_sync_sqlite::RoleLossOperationRepository,
    membership_operation_repository: yadorilink_sync_sqlite::MembershipOperationRepository,
    recovery_snapshot_reader: RecoverySnapshotReader,
    /// This crate's own independent `PathLockRegistry` (`crate::sync_runtime::
    /// path_locks`), not `yadorilink-sync-core`'s copy: `SyncState` has no
    /// remaining production callers workspace-wide (`DaemonState` no longer
    /// holds a `SyncState` at all), so the two types never need to serialize
    /// against each other in a live process any more -- see
    /// `docs/design/phase7d10-exit-report.md`'s addendum on this for the
    /// full invariant re-derivation.
    path_lock_registry: Arc<PathLockRegistry>,
    /// This crate's own independent `StartupReadinessRegistry`, for the same
    /// reason as `path_lock_registry` above.
    startup_readiness: Arc<StartupReadinessRegistry>,
    local_change_auth_provider: Mutex<Option<Arc<LocalChangeAuthProvider>>>,
    repair_election_provider: Mutex<Option<Arc<RepairElectionProvider>>>,
    root_adoption_lock: Mutex<()>,
    materialization_wake: MaterializationWake,
}

/// Same schema-bootstrap sequencing as `yadorilink_sync_core::index`'s
/// private `schema_init` (that crate is the composition root for the
/// `pre_dag_schema` -> `yadorilink_sqlite_runtime::init_schema` ->
/// `post_dag_schema` ordering; see its own doc comment for why). Used by
/// [`ReplicaCoordinator::open_in_memory`] below, the one constructor that
/// opens a database from scratch rather than sharing a live `SyncState`'s
/// already-open one.
fn schema_init(conn: &Connection) -> Result<(), yadorilink_sqlite_runtime::DatabaseError> {
    pre_dag_schema(conn)?;
    yadorilink_sqlite_runtime::init_schema(conn)?;
    post_dag_schema(conn)?;
    Ok(())
}

impl ReplicaCoordinator {
    /// Builds every repository field fresh, against the SAME already-open
    /// `database` a `SyncState` in the same process opened (via
    /// [`yadorilink_sync_core::index::SyncState::database`]) -- reusing its
    /// connection pool and in-process writer-serialization gate rather than
    /// opening a second, independent one against the same file. Mirrors
    /// `SyncState::open`/`open_in_memory`'s own field construction
    /// verbatim, minus the `SyncDatabase::open(..)` call itself (the
    /// database is received already-open, not opened here).
    ///
    /// `path_lock_registry`/`startup_readiness` are still accepted as
    /// caller-supplied `Arc`s (not constructed fresh inside this function)
    /// so callers can still share one registry pair across multiple
    /// `ReplicaCoordinator`s built against the same database within THIS
    /// crate. Historically (Phase 7D-10.5) this parameter existed so a
    /// `ReplicaCoordinator` could share the exact same registries a live
    /// `SyncState` in the same process already owned -- `LocalChangeProcessor`
    /// reached them through `SyncState`/`LocalMutationStore`, and anything
    /// reached through `ReplicaCoordinator` had to serialize against that
    /// SAME lock/generation state or the two would give no real mutual
    /// exclusion against each other. That coupling no longer applies:
    /// `DaemonState` has not held a `SyncState` since Phase 7D-10.9, so no
    /// production path can observe a `SyncState`'s registries and a
    /// `ReplicaCoordinator`'s diverge -- `path_lock_registry`/
    /// `startup_readiness` here are this crate's own independent copies
    /// (`crate::sync_runtime`), not `yadorilink-sync-core`'s.
    pub fn from_database(
        database: Arc<SyncDatabase>,
        path_lock_registry: Arc<PathLockRegistry>,
        startup_readiness: Arc<StartupReadinessRegistry>,
    ) -> Self {
        let sqlite = Arc::new(yadorilink_sync_sqlite::SqliteSyncStore::new(database.clone()));
        Self {
            sqlite,
            link_repository: yadorilink_sync_sqlite::link::LinkRepository::new(database.clone()),
            enrollment_repository: yadorilink_sync_sqlite::enrollment::EnrollmentRepository::new(
                database.clone(),
            ),
            file_index_repository: yadorilink_sync_sqlite::file_index::FileIndexRepository::new(
                database.clone(),
            ),
            materialization_state_repository:
                yadorilink_sync_sqlite::MaterializationStateRepository::new(database.clone()),
            change_history_repository: yadorilink_sync_sqlite::ChangeHistoryRepository::new(
                database.clone(),
            ),
            materialization_job_repository:
                yadorilink_sync_sqlite::MaterializationJobRepository::new(database.clone()),
            policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository::new(
                database.clone(),
            ),
            dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository::new(
                database.clone(),
            ),
            restore_operation_repository: yadorilink_sync_sqlite::RestoreOperationRepository::new(
                database.clone(),
            ),
            handoff_lease_repository: yadorilink_sync_sqlite::HandoffLeaseRepository::new(
                database.clone(),
            ),
            rebootstrap_store_repository: yadorilink_sync_sqlite::RebootstrapStoreRepository::new(
                database.clone(),
            ),
            role_loss_operation_repository:
                yadorilink_sync_sqlite::RoleLossOperationRepository::new(database.clone()),
            membership_operation_repository:
                yadorilink_sync_sqlite::MembershipOperationRepository::new(database.clone()),
            recovery_snapshot_reader: RecoverySnapshotReader::new(database.clone()),
            database,
            path_lock_registry,
            startup_readiness,
            local_change_auth_provider: Mutex::new(None),
            repair_election_provider: Mutex::new(None),
            root_adoption_lock: Mutex::new(()),
            materialization_wake: MaterializationWake::new(),
        }
    }

    /// Opens a standalone, freshly-schema'd in-memory database and builds a
    /// `ReplicaCoordinator` directly against it -- with its own fresh
    /// `PathLockRegistry`/`StartupReadinessRegistry` (this crate's own
    /// independent copies; there is no `SyncState` in this process at all).
    /// For test fixtures ONLY: `app::run` (the one production caller)
    /// instead goes through [`ReplicaCoordinator::open`], which likewise
    /// builds its own fresh registries via [`ReplicaCoordinator::from_database`]
    /// -- see that constructor's own doc comment for the registry-sharing
    /// parameter's now-historical rationale. Added for
    /// `yadorilink-peer-session`'s test fixtures (Phase 7D-10, correcting
    /// that crate's tests off directly constructing
    /// `yadorilink_sync_core::index::SyncState` -- see
    /// `docs/design/phase7d10-exit-report.md`'s addendum on this fix for
    /// why the earlier dev-dependency-cycle reasoning that blocked this was
    /// wrong), mirroring `SyncState::open_in_memory`'s own field
    /// construction (both ultimately call the same `schema_init` sequence
    /// against a fresh `SyncDatabase::open_in_memory`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory() -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        let database = Arc::new(SyncDatabase::open_in_memory(schema_init)?);
        Ok(Self::from_database(
            database,
            Arc::new(PathLockRegistry::new()),
            Arc::new(StartupReadinessRegistry::new()),
        ))
    }

    /// Opens (or creates) a real on-disk database at `path` and builds a
    /// `ReplicaCoordinator` directly against it, with its own fresh
    /// `PathLockRegistry`/`StartupReadinessRegistry` -- the production
    /// counterpart to [`Self::open_in_memory`] above, mirroring
    /// `yadorilink_sync_core::index::SyncState::open`'s own field
    /// construction (both ultimately call the same `schema_init` sequence
    /// against `SyncDatabase::open`). Phase 7D-10.9: added so
    /// `yadorilink-daemon`'s own composition root (`app::run`) can build its
    /// one `ReplicaCoordinator` without going through a `SyncState` it no
    /// longer constructs.
    pub fn open(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, yadorilink_sqlite_runtime::DatabaseError> {
        let database = Arc::new(SyncDatabase::open(path, schema_init)?);
        Ok(Self::from_database(
            database,
            Arc::new(PathLockRegistry::new()),
            Arc::new(StartupReadinessRegistry::new()),
        ))
    }

    // --- Accessors needed by the port impls below (not part of the 17,
    // but required so this struct's own field-owning shape can support
    // them without exposing the fields directly -- same accessor pattern
    // `SyncState` itself uses). ---

    pub fn link_repository(&self) -> &yadorilink_sync_sqlite::link::LinkRepository {
        &self.link_repository
    }

    pub fn file_index_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::file_index::FileIndexRepository {
        &self.file_index_repository
    }

    pub fn materialization_state_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationStateRepository {
        &self.materialization_state_repository
    }

    pub fn sqlite(&self) -> &yadorilink_sync_sqlite::SqliteSyncStore {
        &self.sqlite
    }

    pub fn rebootstrap_store_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RebootstrapStoreRepository {
        &self.rebootstrap_store_repository
    }

    // --- Remaining repository/registry accessors (Phase 7D-10.3): mirror
    // the five accessors above -- mechanical, no logic of their own -- so
    // daemon callers whose only obstacle was "this field is private" can
    // repoint from `SyncState` to `ReplicaCoordinator` for the same
    // underlying database. See `docs/design/phase7d10-exit-report.md`'s
    // 7D-10.3 addendum for which callers this actually unblocks. ---

    pub fn database(&self) -> Arc<SyncDatabase> {
        self.database.clone()
    }

    pub fn enrollment_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::enrollment::EnrollmentRepository {
        &self.enrollment_repository
    }

    pub fn change_history_repository(&self) -> &yadorilink_sync_sqlite::ChangeHistoryRepository {
        &self.change_history_repository
    }

    pub fn materialization_job_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationJobRepository {
        &self.materialization_job_repository
    }

    pub fn policy_watermark_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::PolicyWatermarkRepository {
        &self.policy_watermark_repository
    }

    pub fn dirty_path_repository(&self) -> &yadorilink_sync_sqlite::DirtyPathRepository {
        &self.dirty_path_repository
    }

    pub fn restore_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RestoreOperationRepository {
        &self.restore_operation_repository
    }

    pub fn handoff_lease_repository(&self) -> &yadorilink_sync_sqlite::HandoffLeaseRepository {
        &self.handoff_lease_repository
    }

    pub fn role_loss_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RoleLossOperationRepository {
        &self.role_loss_operation_repository
    }

    pub fn membership_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MembershipOperationRepository {
        &self.membership_operation_repository
    }

    pub fn recovery_snapshot_reader(&self) -> &RecoverySnapshotReader {
        &self.recovery_snapshot_reader
    }

    /// See `yadorilink_sync_core::index::SyncState::
    /// plant_malformed_membership_operation_for_test`'s own doc comment --
    /// verbatim copy against this struct's own
    /// `membership_operation_repository` accessor, for
    /// `yadorilink-daemon`'s own recovery-inventory tests now that they no
    /// longer construct a `SyncState` fixture.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_membership_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.membership_operation_repository
            .plant_malformed_membership_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// See `yadorilink_sync_core::index::SyncState::
    /// plant_malformed_role_loss_operation_for_test`'s own doc comment --
    /// verbatim copy against this struct's own
    /// `role_loss_operation_repository` accessor.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_role_loss_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.role_loss_operation_repository
            .plant_malformed_role_loss_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// See `yadorilink_sync_core::index::SyncState::
    /// add_link_with_pending_enrollment_for_test`'s own doc comment --
    /// verbatim copy against this struct's own `enrollment_repository`
    /// accessor, for `tests/root_identity_verification.rs`
    /// (`yadorilink-root-authority`) now that it constructs a
    /// `ReplicaCoordinator` fixture instead of a `SyncState`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn add_link_with_pending_enrollment_for_test(
        &self,
        local_path: &str,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> Result<(), SyncError> {
        let marker = yadorilink_replica_domain::session_state::PendingEnrollment {
            operation_id: operation_id.to_string(),
            kind: yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            group_id: group_id.to_string(),
            device_id: device_id.to_string(),
            local_path: local_path.to_string(),
        };
        self.enrollment_repository
            .add_link_with_pending_enrollment(local_path, group_id, &marker)
            .map_err(SyncError::from)
    }

    pub fn path_lock_registry(&self) -> &PathLockRegistry {
        &self.path_lock_registry
    }

    pub fn startup_readiness(&self) -> &StartupReadinessRegistry {
        &self.startup_readiness
    }

    pub fn materialization_wake(&self) -> &MaterializationWake {
        &self.materialization_wake
    }

    // --- The 17 permanently-remaining `SyncState` production methods,
    // reproduced verbatim (per `phase7d9f-exit-report.md` §14.3's
    // authoritative list, re-verified fresh against `index.rs` for this
    // pass). ---

    pub fn set_local_change_auth_provider(&self, provider: Arc<LocalChangeAuthProvider>) {
        *self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    pub fn set_repair_election_provider(&self, provider: Arc<RepairElectionProvider>) {
        *self.repair_election_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    /// See `SyncState::local_emission_auth`'s own doc comment. `pub(crate)`,
    /// not private: `replica_coordinator/materialization_state.rs`'s own
    /// `impl MaterializationStatePort for ReplicaCoordinator::
    /// mark_deleted_emitting_change` (Phase 7D-10, once the trait's return
    /// type narrowed off the wide `SyncError`) inlines this same pre-check
    /// directly instead of routing through `ReplicaCoordinator::
    /// mark_deleted_emitting_change` below, so it needs to call this from
    /// outside this module.
    pub(crate) fn local_emission_auth(
        &self,
        group_id: &str,
    ) -> Result<ChangeAuth, PolicyUnavailable> {
        match self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok(ChangeAuth::PLACEHOLDER),
        }
    }

    /// See `SyncState::absent_gate_verdict`'s own doc comment.
    fn absent_gate_verdict(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.link_repository.has_live_link_for_group(group_id).map_err(SyncError::from) {
            Ok(false) => Ok(()),
            Ok(true) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason:
                    "link is live but its startup never registered a gate (watcher start failed \
                         or has not run yet); deferring peer apply until startup completes"
                        .to_string(),
            }),
            Err(e) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason: format!(
                    "cannot read the link table to decide whether startup is owed: {e}"
                ),
            }),
        }
    }

    /// See `SyncState::wait_group_ready`'s own doc comment.
    pub async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.startup_readiness.wait_group_ready(group_id).await {
            Some(result) => result,
            None => self.absent_gate_verdict(group_id),
        }
    }

    /// See `SyncState::upsert_file_emitting_change`'s own doc comment.
    pub fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        emission: LocalChangeEmission<'_, '_>,
    ) -> Result<ChangeHash, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        Ok(self.file_index_repository.upsert_file_emitting_change(
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
        )?)
    }

    /// See `SyncState::upsert_files_batch_emitting_change`'s own doc
    /// comment.
    pub fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        emission: LocalChangeEmission<'_, '_>,
    ) -> Result<Option<ChangeHash>, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        Ok(self.file_index_repository.upsert_files_batch_emitting_change(
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
        )?)
    }

    /// See `SyncState::mark_deleted_emitting_change`'s own doc comment.
    pub fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        Ok(self.file_index_repository.mark_deleted_emitting_change(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext { emitter, permit, auth },
        )?)
    }

    /// See `SyncState::append_initial_import`'s own doc comment.
    pub fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<Option<usize>, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        self.change_history_repository
            .append_initial_import(group_id, batches, versions, emitter, auth)
            .map_err(SyncError::from)
    }

    /// See `SyncState::append_history_backfill`'s own doc comment.
    pub fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        self.change_history_repository
            .append_history_backfill(group_id, ops, versions, emitter, auth)
            .map_err(SyncError::from)
    }

    /// See `SyncState::root_adoption_lock`'s own doc comment.
    pub fn root_adoption_lock(&self) -> &Mutex<()> {
        &self.root_adoption_lock
    }

    /// See `SyncState::record_restore_operation_emitting_change`'s own doc
    /// comment.
    pub fn record_restore_operation_emitting_change(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        let auth = self.local_emission_auth(&operation.group_id)?;
        self.restore_operation_repository
            .record_restore_operation_emitting_change(operation, version, emitter, auth)
            .map_err(SyncError::from)
    }

    /// See `SyncState::expire_superseded_and_trashed_versions`'s own doc
    /// comment.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncError> {
        let now_unix_seconds = now_unix_nanos / 1_000_000_000;
        let pinned = self
            .handoff_lease_repository
            .leased_version_keys_for_group(group_id, now_unix_seconds)?;
        Ok(self.file_index_repository.expire_superseded_and_trashed_versions(
            group_id,
            now_unix_nanos,
            &pinned,
        )?)
    }

    /// See `SyncState::install_rebootstrap_snapshot`'s own doc comment
    /// (`index/rebootstrap_store/base.rs`).
    pub fn install_rebootstrap_snapshot(
        &self,
        manifest: &yadorilink_replica_engine::rebootstrap::SnapshotManifest,
        snapshot_bytes: &[u8],
        local_emitter: Option<&ChangeEmitter>,
    ) -> Result<(), SyncError> {
        let group_id_owned = manifest.group_id.as_str().to_string();
        let local_auth =
            local_emitter.map(|_| self.local_emission_auth(&group_id_owned)).transpose()?;

        self.database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                yadorilink_sync_sqlite::rebootstrap_store::install_rebootstrap_snapshot(
                    tx,
                    manifest,
                    snapshot_bytes,
                    local_emitter,
                    local_auth,
                )
            })
            .map_err(SyncError::from)
    }

    /// See `SyncState::repair_retroactive_conflict_copy_obligations`'s own
    /// doc comment (`index/rebootstrap_store/retroactive_conflict_store.rs`).
    pub fn repair_retroactive_conflict_copy_obligations(
        &self,
        group_id: &str,
        emitter: &ChangeEmitter,
        eligible_rank: usize,
    ) -> Result<RetroactiveRepairOutcome, SyncError> {
        use yadorilink_sync_sqlite::retroactive_conflict::{
            plan_retroactive_merge, RetroactiveMergeOutcome,
        };

        let outcome = self.database.write_immediate(|tx| {
            let outcome = plan_retroactive_merge(tx, group_id)?;

            let plan = match outcome {
                RetroactiveMergeOutcome::PathObligationTooLarge { path } => {
                    let mut committed_frontier =
                        yadorilink_sync_sqlite::dag_store::group_heads(tx, group_id)?;
                    committed_frontier.sort();
                    return Ok(RetroactiveRepairOutcome::PermanentlyBlocked {
                        path,
                        committed_frontier,
                    });
                }
                RetroactiveMergeOutcome::Plan(plan) => plan,
            };

            if !plan.direct_ops.is_empty() {
                let provider =
                    self.repair_election_provider.lock().unwrap_or_else(|p| p.into_inner()).clone();
                let mut election_contexts = Vec::new();
                if let Some(provider) = provider {
                    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
                    let obligation_id =
                        yadorilink_replica_engine::repair_election::RepairObligationId::compute_set(
                            &group,
                            &plan.obligations,
                        );
                    election_contexts.push(provider(group_id, obligation_id)?);
                    let local_rank =
                        election_contexts.iter().filter_map(|ctx| ctx.local_rank()).min();
                    if local_rank.is_none_or(|rank| rank > eligible_rank) {
                        let mut committed_frontier =
                            yadorilink_sync_sqlite::dag_store::group_heads(tx, group_id)?;
                        committed_frontier.sort();
                        return Ok(RetroactiveRepairOutcome::AwaitingFailover {
                            local_rank,
                            committed_frontier,
                        });
                    }
                }

                let auth = self.local_emission_auth(group_id)?;
                let fingerprint = emitter.signing_key_fingerprint();
                if election_contexts.iter().any(|context| {
                    context.expected_auth() != auth
                        || context.local_device_id() != emitter.device_id()
                        || context.local_key_fingerprint() != fingerprint
                }) {
                    return Err(SyncError::PolicyUnavailable);
                }

                yadorilink_sync_sqlite::dag_store::emit_retroactive_repair(
                    tx,
                    group_id,
                    plan.direct_ops,
                    plan.obligations,
                    auth,
                    emitter,
                )?;
                if self.local_emission_auth(group_id)? != auth {
                    return Err(SyncError::PolicyUnavailable);
                }
            }

            let mut committed_frontier =
                yadorilink_sync_sqlite::dag_store::group_heads(tx, group_id)?;
            committed_frontier.sort();
            Ok(if plan.source_paths.is_empty() {
                RetroactiveRepairOutcome::NothingToDo { committed_frontier }
            } else {
                RetroactiveRepairOutcome::Repaired {
                    repaired_paths: plan.source_paths,
                    committed_frontier,
                }
            })
        })?;

        if matches!(outcome, RetroactiveRepairOutcome::Repaired { .. }) {
            self.materialization_wake.notify_materialization_wake();
        }
        Ok(outcome)
    }
}

// --- Port impls (2 of the plan's 5 -- see this module's own doc comment
// for why the other three are deferred). ---

impl RootVerificationStatePort for ReplicaCoordinator {
    fn root_adoption_lock(&self) -> &Mutex<()> {
        ReplicaCoordinator::root_adoption_lock(self)
    }

    fn link_root_token_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, RootAuthorityError> {
        Ok(self.link_repository.link_root_token_for_group(group_id).map_err(SyncError::from)?)
    }

    fn set_link_root_token_for_group(
        &self,
        group_id: &str,
        root_token: &str,
    ) -> Result<(), RootAuthorityError> {
        Ok(self
            .link_repository
            .set_link_root_token_for_group(group_id, root_token)
            .map_err(SyncError::from)?)
    }

    fn ensure_unambiguous_group(&self, group_id: &str) -> Result<(), RootAuthorityError> {
        Ok(self.link_repository.ensure_unambiguous_group(group_id).map_err(SyncError::from)?)
    }

    fn live_files(&self, group_id: &str) -> Result<Vec<FileRecord>, RootAuthorityError> {
        Ok(self
            .file_index_repository
            .list_files(group_id)
            .map_err(SyncError::from)?
            .into_iter()
            .filter(|r| !r.deleted)
            .collect())
    }

    fn indexed_path_is_corroborated(
        &self,
        root: &std::path::Path,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, RootAuthorityError> {
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::session_state::MaterializationState;

        let disk_path = root.join(&record.path);
        let Ok(metadata) = disk_path.symlink_metadata() else {
            return Ok(false);
        };
        let kind = self
            .file_index_repository
            .get_record_kind(group_id, &record.path)
            .map_err(SyncError::from)?
            .unwrap_or_default();
        Ok(match kind {
            RecordKind::Directory => metadata.file_type().is_dir(),
            RecordKind::Symlink => {
                metadata.file_type().is_symlink()
                    && std::fs::read_link(&disk_path).ok().map(|target| {
                        yadorilink_root_authority::fs_identity::target_to_bytes(&target)
                    }) == self
                        .file_index_repository
                        .get_symlink_target(group_id, &record.path)
                        .map_err(SyncError::from)?
            }
            RecordKind::File => {
                if !metadata.file_type().is_file() {
                    false
                } else {
                    match self
                        .materialization_state_repository
                        .get_materialization_state(group_id, &record.path)
                        .map_err(SyncError::from)?
                    {
                        Some(MaterializationState::Placeholder) => metadata.len() == record.size,
                        Some(MaterializationState::Hydrating)
                        | Some(MaterializationState::Evicting) => false,
                        _ => {
                            metadata.len() == record.size
                                && yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                                    &disk_path,
                                    &record.blocks,
                                )
                                .map_err(|e| RootAuthorityError::corrupt_state(e.to_string()))?
                        }
                    }
                }
            }
        })
    }
}

impl AuthenticatedHistorySource for ReplicaCoordinator {
    type Error = SyncError;

    fn retained_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self.sqlite.dag_group_heads(group_id)?)
    }

    fn retained_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncError> {
        Ok(self.sqlite.dag_get_change(hash)?)
    }

    fn compacted_parent_auth(
        &self,
        group_id: &str,
        child_hash: &ChangeHash,
        parent_hash: &ChangeHash,
    ) -> Result<Option<(u64, u64)>, SyncError> {
        self.rebootstrap_store_repository
            .compacted_parent_auth(group_id, child_hash, parent_hash)
            .map_err(SyncError::from)
    }
}

// --- History-compaction store wiring (Phase 7D-10.3): byte-identical to
// `impl {CompactionDagStore,DeviceFrontierStore,CheckpointStore} for
// SyncState` (`yadorilink-sync-core/src/index.rs`) -- these three traits are
// storage-agnostic (`yadorilink_replica_engine::compaction`'s own doc
// comment), so `ReplicaCoordinator` implements them the same way `SyncState`
// does, delegating to the same `self.sqlite`/`self.database` this struct
// already owns. Unlike the five `ports/` impls Phase 7D-10.2 could only move
// two of, these three have no `MaterializationIntentGuard` dependency, so
// nothing blocks reproducing all three here.
impl CompactionDagStore for ReplicaCoordinator {
    fn heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite.group_heads(group).map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn parents(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite.parents_of(change).map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn contains_change(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.sqlite.has_change(change).map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }
}

impl DeviceFrontierStore for ReplicaCoordinator {
    fn set_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        self.sqlite
            .set_device_frontier(group, device, frontier)
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn get_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite
            .get_device_frontier(group, device)
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn remove_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<(), ReplicaEngineError> {
        self.sqlite
            .remove_device_frontier(group, device)
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }
}

impl CheckpointStore for ReplicaCoordinator {
    fn latest_checkpoint(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<Checkpoint>, ReplicaEngineError> {
        self.database
            .read(|conn| yadorilink_sync_sqlite::dag_store::latest_checkpoint(conn, group.as_str()))
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn commit_prune(
        &self,
        checkpoint: &Checkpoint,
        pruned: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        self.database
            .write_immediate(|tx| {
                yadorilink_sync_sqlite::dag_store::commit_prune(tx, checkpoint, pruned)
            })
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }

    fn history_base_previous_checkpoint_hash(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<[u8; 32]>, ReplicaEngineError> {
        self.rebootstrap_store_repository
            .history_base_previous_checkpoint_hash(group.as_str())
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }
}

// --- Materialization-intent journal (Phase 7D-10.4): proves
// `crate::materialization_intent::MaterializationIntentGuard`'s
// generalization away from a hardwired concrete `&SyncState` (per that
// module's own doc comment) actually reaches `ReplicaCoordinator`, not just
// `SyncState`. This impl is legal under Rust's orphan rule even though the
// trait is foreign (defined in `yadorilink-sync-core`): `ReplicaCoordinator`
// is local to this crate. Written here, not in `yadorilink-sync-core`,
// because that crate cannot name `ReplicaCoordinator` (the reverse
// dependency direction is forbidden by this whole initiative's boundary
// rules -- see this module's own top doc comment). Only this one accessor is
// exposed: `ReplicaCoordinator`'s own `MaterializationJobRepository`
// instance (`materialization_job_repository`, added 7D-10.3), constructed
// against the SAME underlying `Arc<SyncDatabase>` a live `SyncState` in the
// same process already opened (`from_database`'s own doc comment) -- so the
// journal table this seam writes to is identical to `SyncState`'s, not a
// second, divergent one.
//
// Reproducing the three `ports/` trait impls
// (`PeerReplicaStatePort`/`MaterializationStatePort`/
// `MaterializationExecutionPort`) for `ReplicaCoordinator` in full is
// deliberately NOT done in this pass -- each is ~30-50 delegate methods
// mirroring the rest of this struct's existing accessors, a mechanical sweep
// of the same size and shape as 7D-10.2/10.3's own dedicated passes, now
// finally unblocked by this impl but still its own scoped unit of work. See
// `docs/design/phase7d10-exit-report.md`'s 7D-10.4 addendum.
impl crate::materialization_intent::MaterializationIntentJournal for ReplicaCoordinator {
    fn materialization_job_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationJobRepository {
        &self.materialization_job_repository
    }
}

// Phase 7D-10: `crate::recovery::RecoveryInventorySource` -- relocated here
// from `yadorilink-sync-core::recovery` alongside its one real implementor,
// this impl.
impl crate::recovery::RecoveryInventorySource for ReplicaCoordinator {
    fn enrollment_repository(&self) -> &yadorilink_sync_sqlite::enrollment::EnrollmentRepository {
        ReplicaCoordinator::enrollment_repository(self)
    }

    fn membership_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MembershipOperationRepository {
        ReplicaCoordinator::membership_operation_repository(self)
    }

    fn role_loss_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RoleLossOperationRepository {
        ReplicaCoordinator::role_loss_operation_repository(self)
    }
}

// Phase 7D-10.5: `dag_import.rs` itself has now physically relocated to
// `crate::dag_import` -- the last two genuinely-blocked production
// `&SyncState` dependencies (`link_runtime/startup.rs`'s
// `ensure_initial_import` call and `daemon_state.rs`'s
// `backfill_missing_history` call) already passed a `&ReplicaCoordinator`
// exclusively in production, so moving the module itself changes only which
// crate it compiles in, not any call site's behavior.
impl crate::dag_import::DagImportSource for ReplicaCoordinator {
    fn sqlite(&self) -> &yadorilink_sync_sqlite::SqliteSyncStore {
        ReplicaCoordinator::sqlite(self)
    }

    fn file_index_repository(&self) -> &yadorilink_sync_sqlite::file_index::FileIndexRepository {
        ReplicaCoordinator::file_index_repository(self)
    }

    fn change_history_repository(&self) -> &yadorilink_sync_sqlite::ChangeHistoryRepository {
        ReplicaCoordinator::change_history_repository(self)
    }

    fn path_lock(&self, group_id: &str, path: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        ReplicaCoordinator::path_lock_registry(self).path_lock(group_id, path)
    }

    fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<Option<usize>, SyncError> {
        ReplicaCoordinator::append_initial_import(self, group_id, batches, versions, emitter)
    }

    fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        ReplicaCoordinator::append_history_backfill(self, group_id, ops, versions, emitter)
    }
}

#[cfg(test)]
mod dag_import_source_tests {
    use super::*;
    use crate::dag_import::{ensure_initial_import, ImportOutcome};

    /// End-to-end proof that `ensure_initial_import` converts a real index
    /// into signed history when called through a `ReplicaCoordinator` --
    /// not merely that the trait bound type-checks. Previously built the
    /// coordinator from a live `SyncState`'s own `Arc<SyncDatabase>` and
    /// re-checked the result through that original handle, to prove the two
    /// types shared one database during their transitional coexistence;
    /// `SyncState` was deleted in Phase 7D-10's final elimination pass (the
    /// coexistence invariant itself was independently re-verified moot
    /// beforehand -- see this file's own history), so this test now builds
    /// and reads back through a single `ReplicaCoordinator` directly.
    #[test]
    fn ensure_initial_import_runs_against_a_replica_coordinator() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let record = FileRecord {
            path: "a.txt".into(),
            size: 3,
            mtime_unix_nanos: 1,
            blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                hash: vec![1, 2, 3],
                offset: 0,
                size: 3,
            }],
            deleted: false,
        };
        coordinator
            .file_index_repository()
            .upsert_file("g", &record, &RootCommitPermit::for_tests())
            .unwrap();

        let emitter =
            ChangeEmitter::new("device-A", ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]));
        let outcome = ensure_initial_import(&coordinator, "g", &emitter).unwrap();
        assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

        let heads = coordinator.sqlite().dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1);
    }
}

#[cfg(test)]
mod materialization_intent_journal_tests {
    use super::*;
    use crate::materialization_intent::MaterializationIntentGuard;

    /// End-to-end proof that the generalized guard opens and clears a real,
    /// durable intent against a `ReplicaCoordinator`-backed
    /// `MaterializationJobRepository` -- not merely that the trait bound
    /// type-checks. Previously built the coordinator against a live
    /// `SyncState`'s already-open `Arc<SyncDatabase>` to mirror production's
    /// then-transitional dual-wiring; `SyncState` was deleted in Phase
    /// 7D-10's final elimination pass, so this now builds the coordinator
    /// directly.
    #[test]
    fn guard_opens_and_clears_against_replica_coordinator() {
        let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let permit = RootCommitPermit::for_tests();

        assert!(!coordinator
            .materialization_job_repository()
            .has_materialization_intent("group-1", "a.bin")
            .unwrap());

        let guard = MaterializationIntentGuard::open(
            &coordinator,
            "group-1",
            "a.bin",
            b"target-version-hash",
            &permit,
        )
        .unwrap();
        assert!(coordinator
            .materialization_job_repository()
            .has_materialization_intent("group-1", "a.bin")
            .unwrap());

        guard.clear().unwrap();
        assert!(!coordinator
            .materialization_job_repository()
            .has_materialization_intent("group-1", "a.bin")
            .unwrap());
    }
}
