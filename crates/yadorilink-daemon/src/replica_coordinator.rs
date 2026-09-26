//! `ReplicaCoordinator` is the daemon's composition-root type: it owns the
//! per-table SQLite repositories, the shared connection pool, the path-lock
//! and startup-readiness registries, and the wake channels that drive the
//! materialization/retirement/hazard-recheck loops.
//!
//! # Field ownership
//!
//! Every field here is built fresh in [`ReplicaCoordinator::from_database`]
//! against one shared `Arc<SyncDatabase>` -- never open a second,
//! independent `SyncDatabase` against the same on-disk file, which would
//! split the in-process writer-serialization gate across two connection
//! pools and defeat the mutual exclusion it exists to provide. Callers that
//! need more than one `ReplicaCoordinator` over the same database (for
//! example multiple test fixtures) must share one `Arc<SyncDatabase>` and
//! pass it to `from_database` rather than opening the file twice.
//!
//! # Port impls
//!
//! `ReplicaCoordinator` implements the storage ports the replica/peer
//! session engine depends on. `RootVerificationStatePort` is implemented
//! directly below; `MaterializationExecutionPort` is a large, mechanical
//! set of delegate methods and lives in its own submodule
//! (`materialization_execution`). Custody-verified block reclamation is an
//! inherent operation, in `block_reclamation`. The
//! replica-state operations the local convergence executor drives are
//! inherent methods, in `peer_replica_state`. The materialization-semantic
//! compositions a lane used to assemble from those raw primitives (intent,
//! fence, state, held, proof, placeholder identity) are owner operations,
//! in `materialization_owner`.

mod block_reclamation;
pub mod engine_ports;
mod local_mutation;
mod materialization_execution;
mod materialization_owner;
mod peer_replica_state;

// Test-only: lets `gc.rs`/`hydration.rs`'s own unit tests reach
// `materialization_execution`'s Windows-native-dehydrate bypass without
// that private submodule itself becoming `pub(crate)` -- see that
// function's own doc comment. Plain `cfg(test)`, not `any(test, feature =
// "test-support"))]`: the function it re-exports is itself `cfg(test)`-only
// (no caller outside this crate's own unit tests needs it), so gating the
// re-export any wider would just be an unused `pub(crate) use` in a build
// that has `test-support` on but `cfg(test)` off.
#[cfg(test)]
pub(crate) use materialization_execution::set_test_windows_dehydrate_confirmed_for_path;
// Test-only: `hydration.rs`'s unit tests arm the access-hydration guard
// directly, without its entry CAS, to simulate an attempt in flight.
#[cfg(test)]
pub(crate) use materialization_owner::AccessHydration;
// Test-only: the ordinary-batch directory-lane tests age an intent past it.
#[cfg(test)]
pub(crate) use materialization_owner::STALE_STRUCTURAL_INTENT_AGE;

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::recovery_snapshot::RecoverySnapshotReader;
use crate::sync_error::SyncError;
use crate::sync_runtime::materialization_wake::MaterializationWake;
use crate::sync_runtime::path_locks::PathLockRegistry;
use crate::sync_runtime::retirement_wake::RetirementWake;
use crate::sync_runtime::schema::{post_dag_schema, pre_dag_schema};
use crate::sync_runtime::startup_readiness::StartupReadinessRegistry;
use yadorilink_replica_domain::change::{Op, PolicyUnavailable};
use yadorilink_replica_domain::file::{FileRecord, FileVersion};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};
use yadorilink_replica_domain::session_state::ChangeContent;
use yadorilink_replica_domain::session_state::RestoreOperation;
use yadorilink_replica_domain::session_state::{
    LocalFileMetaColumns, RetroactiveRepairOutcome, StartupFailed,
};
use yadorilink_replica_engine::compaction::{
    Checkpoint, CheckpointStore, CompactionDagStore, DeviceFrontierStore,
};
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_root_authority::error::RootAuthorityError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::RootVerificationStatePort;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

/// Resolves this device's current verified policy_head for a group, or
/// `Err(PolicyUnavailable)` when this device's own policy view for the
/// group is not currently trustworthy (stale/invalid verification, or the
/// group has not resolved yet). NOT a writer-authorization decision --
/// under `AuthorizationCheckpoint` admission, writer authorization happens only at
/// checkpoint issuance; local emission (offline authoring) is always
/// available to any device regardless of writer role, so this gate exists
/// purely to avoid emitting against a policy view this device cannot
/// currently vouch for, and to give the repair-election consistency check
/// (`RepairElectionContext::expected_policy_head`) a value to compare
/// against.
pub(crate) type LocalPolicyHeadProvider =
    dyn Fn(&str) -> Result<[u8; 32], PolicyUnavailable> + Send + Sync + 'static;

#[derive(Clone, Copy)]
pub struct ReplicaChangeEmission<'a> {
    pub emitter: &'a ChangeEmitter,
    pub permit: &'a RootCommitPermit<'a>,
}
/// Policy hook that resolves the local repair-election context for a group
/// and obligation set (see `repair_retroactive_conflict_copy_obligations`
/// below). A plain function-pointer type alias with no logic of its own.
pub type RepairElectionProvider = dyn Fn(
        &str,
        yadorilink_replica_engine::repair_election::RepairObligationId,
    ) -> Result<
        yadorilink_replica_engine::repair_election::RepairElectionContext,
        PolicyUnavailable,
    > + Send
    + Sync
    + 'static;

/// The daemon's composition-root state: SQLite repositories, connection
/// pool, and the registries/wake channels used to coordinate concurrent
/// access to them. See the module doc comment above for field-ownership
/// invariants.
pub struct ReplicaCoordinator {
    database: Arc<SyncDatabase>,
    sqlite: Arc<yadorilink_sync_sqlite::SqliteSyncStore>,
    link_repository: yadorilink_sync_sqlite::link::LinkRepository,
    enrollment_repository: yadorilink_sync_sqlite::enrollment::EnrollmentRepository,
    file_index_repository: yadorilink_sync_sqlite::file_index::FileIndexRepository,
    materialization_state_repository: yadorilink_sync_sqlite::MaterializationStateRepository,
    change_history_repository: yadorilink_sync_sqlite::ChangeHistoryRepository,
    materialization_intent_repository: yadorilink_sync_sqlite::MaterializationIntentRepository,
    policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository,
    offline_peer_authorization_repository:
        yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository,
    offline_group_policy_log_repository: yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository,
    dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository,
    paused_item_repository: yadorilink_sync_sqlite::PausedItemRepository,
    snapshot_install_hold_repository: yadorilink_sync_sqlite::SnapshotInstallHoldRepository,
    restore_operation_repository: yadorilink_sync_sqlite::RestoreOperationRepository,
    handoff_lease_repository: yadorilink_sync_sqlite::HandoffLeaseRepository,
    rebootstrap_store_repository: yadorilink_sync_sqlite::RebootstrapStoreRepository,
    role_loss_operation_repository: yadorilink_sync_sqlite::RoleLossOperationRepository,
    membership_operation_repository: yadorilink_sync_sqlite::MembershipOperationRepository,
    recovery_snapshot_reader: RecoverySnapshotReader,
    /// Per-`(group_id, path)` locks serializing local-change indexing
    /// against peer reconciliation for the same path (`crate::sync_runtime::
    /// path_locks`).
    path_lock_registry: Arc<PathLockRegistry>,
    /// Tracks per-group startup readiness so peer-apply (and other
    /// post-startup mutators) can wait until the group's startup
    /// reconciliation has published its results before touching that
    /// group's paths (`crate::sync_runtime::startup_readiness`).
    startup_readiness: Arc<StartupReadinessRegistry>,
    local_policy_head_provider: Mutex<Option<Arc<LocalPolicyHeadProvider>>>,
    repair_election_provider: Mutex<Option<Arc<RepairElectionProvider>>>,
    root_adoption_lock: Mutex<()>,
    /// Test-only observation and injection seam -- see
    /// `test_observers`'s own module doc. `#[cfg(test)]`, so neither the
    /// field nor anything that touches it exists in a production build.
    #[cfg(test)]
    pub(crate) test_observers: crate::replica_coordinator::test_observers::TestObservers,
    materialization_wake: MaterializationWake,
    retirement_wake: RetirementWake,
    /// Same per-group dirty/generation shape as `retirement_wake` (a
    /// separate `RetirementWake` instance, not shared -- `pending`/
    /// `complete` are consumer-specific, so retirement's own loop
    /// completing a generation must never clear the hazard-recheck loop's
    /// independent one, and vice versa), driving `HazardHeld` liveness: a
    /// held path has no re-arm event of its own when the sibling that
    /// caused its hold changes, so this reuses the same "DAG frontier
    /// advanced or a materialization job completed" wake points that
    /// already fire `retirement_wake` to trigger a re-check sweep instead.
    hazard_recheck_wake: RetirementWake,
}

/// Runs schema setup in the fixed order the DAG-store schema depends on:
/// `pre_dag_schema`, then `yadorilink_sqlite_runtime::init_schema`, then
/// `post_dag_schema`. Used by [`ReplicaCoordinator::open`] and
/// [`ReplicaCoordinator::open_in_memory`] below, the two constructors that
/// open a database from scratch.
fn schema_init(conn: &Connection) -> Result<(), yadorilink_sqlite_runtime::DatabaseError> {
    // This database's generation policy, declared by its owner and checked
    // before a single statement runs against it. Must come first: once
    // `pre_dag_schema` has run, "has this database any tables?" can no
    // longer tell a brand-new file from one an un-stamping build wrote.
    yadorilink_sqlite_runtime::check_replica_schema_generation(conn)?;
    pre_dag_schema(conn)?;
    yadorilink_sqlite_runtime::init_schema(conn)?;
    post_dag_schema(conn)?;
    Ok(())
}

impl ReplicaCoordinator {
    /// Builds every repository field fresh against the given already-open
    /// `database`, reusing its connection pool and in-process
    /// writer-serialization gate rather than opening a second, independent
    /// `SyncDatabase` against the same file.
    ///
    /// `path_lock_registry`/`startup_readiness` are caller-supplied `Arc`s
    /// (not constructed fresh here) so multiple `ReplicaCoordinator`s built
    /// against the same database can share one registry pair -- sharing is
    /// what gives them real mutual exclusion against each other; two
    /// separate registries would each serialize only their own caller's
    /// access and let concurrent access through the other one race.
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
            materialization_intent_repository:
                yadorilink_sync_sqlite::MaterializationIntentRepository::new(database.clone()),
            policy_watermark_repository: yadorilink_sync_sqlite::PolicyWatermarkRepository::new(
                database.clone(),
            ),
            offline_peer_authorization_repository:
                yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository::new(database.clone()),
            offline_group_policy_log_repository:
                yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository::new(database.clone()),
            dirty_path_repository: yadorilink_sync_sqlite::DirtyPathRepository::new(
                database.clone(),
            ),
            paused_item_repository: yadorilink_sync_sqlite::PausedItemRepository::new(
                database.clone(),
            ),
            snapshot_install_hold_repository:
                yadorilink_sync_sqlite::SnapshotInstallHoldRepository::new(database.clone()),
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
            local_policy_head_provider: Mutex::new(None),
            repair_election_provider: Mutex::new(None),
            root_adoption_lock: Mutex::new(()),
            #[cfg(test)]
            test_observers: Default::default(),
            materialization_wake: MaterializationWake::new(),
            retirement_wake: RetirementWake::new(),
            hazard_recheck_wake: RetirementWake::new(),
        }
    }

    /// Opens a standalone, freshly-schema'd in-memory database and builds a
    /// `ReplicaCoordinator` directly against it, with its own fresh
    /// `PathLockRegistry`/`StartupReadinessRegistry`. For test fixtures
    /// only -- the one production caller (`app::run`) goes through
    /// [`ReplicaCoordinator::open`] instead.
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
    /// counterpart to [`Self::open_in_memory`] above. This is how the
    /// daemon's composition root (`app::run`) builds its one
    /// `ReplicaCoordinator`.
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

    // --- Accessors needed by the port impls below, so callers can reach
    // individual repositories without the fields themselves being public. ---

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

    // --- Remaining repository/registry accessors: mechanical, no logic of
    // their own -- expose each field so callers outside this module can
    // reach the repository for the same underlying database. ---

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

    pub fn materialization_intent_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MaterializationIntentRepository {
        &self.materialization_intent_repository
    }

    pub fn policy_watermark_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::PolicyWatermarkRepository {
        &self.policy_watermark_repository
    }

    /// This device's last-known-good record of what a live netmap last
    /// authorized each peer for -- see the repository's own module doc for
    /// why it is a cache of an already-made decision and not an authority.
    pub fn offline_peer_authorization_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::OfflinePeerAuthorizationRepository {
        &self.offline_peer_authorization_repository
    }

    /// The raw signed policy log the coordination plane last sent for each
    /// group -- see the repository's own module doc for why storing it
    /// grants nothing (it is re-verified against the pinned service key and
    /// the rollback watermark before any of it is believed).
    pub fn offline_group_policy_log_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::OfflineGroupPolicyLogRepository {
        &self.offline_group_policy_log_repository
    }

    pub fn dirty_path_repository(&self) -> &yadorilink_sync_sqlite::DirtyPathRepository {
        &self.dirty_path_repository
    }

    /// The items paused from the shell context menu -- see
    /// `yadorilink_sync_sqlite::paused_items` for what a pause holds.
    pub fn paused_item_repository(&self) -> &yadorilink_sync_sqlite::PausedItemRepository {
        &self.paused_item_repository
    }

    /// The paths a snapshot install replaced and has not yet reconciled on
    /// disk -- see `yadorilink_sync_sqlite::snapshot_install_hold`.
    pub fn snapshot_install_hold_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::SnapshotInstallHoldRepository {
        &self.snapshot_install_hold_repository
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

    /// Test-only helper: plants a malformed membership-operation row so
    /// recovery-inventory tests can exercise the "malformed operation
    /// detected" path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_membership_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.membership_operation_repository
            .plant_malformed_membership_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// Test-only helper: plants a malformed role-loss-operation row so
    /// recovery-inventory tests can exercise the "malformed operation
    /// detected" path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn plant_malformed_role_loss_operation_for_test(
        &self,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        self.role_loss_operation_repository
            .plant_malformed_role_loss_operation_for_test(operation_id)
            .map_err(SyncError::from)
    }

    /// Test-only helper: adds a link row with a pending "join" enrollment
    /// marker attached, for tests that need a link in that intermediate
    /// state without driving the real enrollment flow.
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

    pub fn retirement_wake(&self) -> &RetirementWake {
        &self.retirement_wake
    }

    pub fn hazard_recheck_wake(&self) -> &RetirementWake {
        &self.hazard_recheck_wake
    }

    // --- Group/change-history mutation methods: local-emission-gated
    // writes into the file index, change history, and restore-operation
    // tables (see `local_policy_head` below for the gate they all share).
    // ---

    pub fn set_local_policy_head_provider(&self, provider: Arc<LocalPolicyHeadProvider>) {
        *self.local_policy_head_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    pub fn set_repair_election_provider(&self, provider: Arc<RepairElectionProvider>) {
        *self.repair_election_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    /// This device's current verified policy_head for `group_id`, or
    /// `Err(PolicyUnavailable)` when this device's own policy view is not
    /// currently trustworthy -- see [`LocalPolicyHeadProvider`]'s own doc
    /// comment for why this is a data-availability gate, not a writer
    /// check. `pub(crate)`, not private: port impls in this module's
    /// submodules (e.g. `local_mutation`) inline this same pre-check
    /// directly where their trait method's error type is narrower than
    /// `mark_deleted_emitting_change` below can return.
    pub(crate) fn local_policy_head(&self, group_id: &str) -> Result<[u8; 32], PolicyUnavailable> {
        match self.local_policy_head_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok([0u8; 32]),
        }
    }

    /// Fallback when no startup-readiness gate has been registered yet for
    /// `group_id`: succeeds only if the group has no live link at all (so
    /// there is nothing to wait on), otherwise reports that startup is
    /// owed but has not run.
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

    /// Waits for `group_id`'s startup (initial import/backfill) to finish
    /// before returning, so peer-applied changes are not processed before
    /// local state is ready. Falls back to [`Self::absent_gate_verdict`]
    /// if no readiness gate was ever registered for this group.
    pub async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.startup_readiness.wait_group_ready(group_id).await {
            Some(result) => result,
            None => self.absent_gate_verdict(group_id),
        }
    }

    /// Upserts a single file record and emits the corresponding change,
    /// after checking local-emission authorization for `group_id`.
    // Forwards `file_index_repository`'s own identically-shaped, widely-
    // called port method; grouping these into a params struct is out of
    // scope for a lint cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        filesystem_identity: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        emission: ReplicaChangeEmission<'_>,
    ) -> Result<ChangeHash, SyncError> {
        self.local_policy_head(group_id)?;
        Ok(self.file_index_repository.upsert_file_emitting_change(
            group_id,
            record,
            origin_device_id,
            content,
            meta,
            filesystem_identity,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
                emitter: emission.emitter,
                permit: emission.permit,
            },
        )?)
    }

    /// Marks `path` deleted and emits the corresponding change, after
    /// checking local-emission authorization for `group_id`.
    // Forwards `file_index_repository`'s own identically-shaped, widely-
    // called port method; grouping these into a params struct is out of
    // scope for a lint cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        publish_absent_proof: bool,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
    ) -> Result<ChangeHash, SyncError> {
        self.local_policy_head(group_id)?;
        Ok(self.file_index_repository.mark_deleted_emitting_change(
            group_id,
            path,
            device_id,
            observed_at_unix_nanos,
            publish_absent_proof,
            yadorilink_sync_sqlite::file_index::ChangeEmissionContext { emitter, permit },
        )?)
    }

    /// Appends a group's initial-import op batches to change history,
    /// after checking local-emission authorization for `group_id`.
    pub fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
        known_excluded: &std::collections::HashSet<String>,
        actual_state: &std::collections::HashMap<
            String,
            yadorilink_sync_sqlite::file_index::ImportedActualState,
        >,
    ) -> Result<yadorilink_sync_sqlite::ImportAppendOutcome, SyncError> {
        self.local_policy_head(group_id)?;
        self.change_history_repository
            .append_initial_import(
                group_id,
                batches,
                versions,
                emitter,
                known_excluded,
                actual_state,
            )
            .map_err(SyncError::from)
    }

    /// Appends a single backfilled change to history, after checking
    /// local-emission authorization for `group_id`.
    pub fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        self.local_policy_head(group_id)?;
        self.change_history_repository
            .append_history_backfill(group_id, ops, versions, emitter)
            .map_err(SyncError::from)
    }

    /// Serializes root-identity adoption for this replica: `open` and
    /// `verify` in `yadorilink_root_authority::root_identity` both take
    /// this lock so `verify` can never observe a torn marker/persisted-
    /// token pair from a concurrent `open` still in flight.
    pub fn root_adoption_lock(&self) -> &Mutex<()> {
        &self.root_adoption_lock
    }

    /// Records a restore operation and emits the corresponding change,
    /// after checking local-emission authorization for the operation's
    /// group. `permit` is verified inside the recording transaction.
    pub fn record_restore_operation_emitting_change(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
    ) -> Result<ChangeHash, SyncError> {
        self.local_policy_head(&operation.group_id)?;
        self.restore_operation_repository
            .record_restore_operation_emitting_change(operation, version, emitter, permit)
            .map_err(SyncError::from)
    }

    /// [`Self::record_restore_operation_emitting_change`], deciding in the
    /// same transaction whether the restore writes its entry itself --
    /// see [`yadorilink_sync_sqlite::restore_operation::RestoreOperationRepository::record_restore_placing`].
    pub fn record_restore_placing(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
        disk_allows_in_place: bool,
    ) -> Result<(ChangeHash, yadorilink_sync_sqlite::restore_operation::RestorePlacement), SyncError>
    {
        self.local_policy_head(&operation.group_id)?;
        self.restore_operation_repository
            .record_restore_placing(operation, version, emitter, permit, disk_allows_in_place)
            .map_err(SyncError::from)
    }

    /// Expires superseded/trashed file versions older than
    /// `now_unix_nanos`, excluding any version keys currently pinned by a
    /// handoff lease.
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

    /// Test fixtures only: installs the base `manifest` names, with the
    /// snapshot `snapshot_bytes` encodes, by the same atomic epoch reset a
    /// merge commits (`yadorilink_sync_sqlite::rebootstrap_store::
    /// install_base_for_tests`), in one write transaction. Nothing here
    /// verifies the manifest, the signer or the witnesses: production
    /// reaches this install only through [`Self::commit_foreign_merge`],
    /// after `DaemonRebootstrapHandler::verify_foreign_base`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_base_for_tests(
        &self,
        manifest: &yadorilink_replica_engine::rebootstrap::SnapshotManifest,
        snapshot_bytes: &[u8],
    ) -> Result<(), yadorilink_sync_sqlite::rebootstrap_store::ForeignMergeError> {
        let snapshot =
            yadorilink_replica_engine::rebootstrap_snapshot::RebootstrapSnapshot::decode(
                snapshot_bytes,
            )
            .map_err(yadorilink_sync_sqlite::SyncSqliteError::from)?;
        self.database.write_immediate(|tx| {
            yadorilink_sync_sqlite::rebootstrap_store::install_base_for_tests(
                tx,
                &manifest.checkpoint,
                &snapshot,
            )
        })
    }

    /// Merges a verified foreign base into this device's history for its
    /// group, in one write transaction
    /// (`yadorilink_sync_sqlite::rebootstrap_store::commit_foreign_merge`):
    /// this device's own base is re-verified inside the transaction, and
    /// the base the two histories' joined summary stands on is installed
    /// with the atomic epoch reset -- or nothing changes when this device
    /// already holds the other history.
    ///
    /// Authors nothing. Refused while history compaction is disabled.
    pub fn commit_foreign_merge(
        &self,
        returning: &yadorilink_sync_sqlite::rebootstrap_store::VerifiedBaseSummary,
    ) -> Result<
        yadorilink_sync_sqlite::rebootstrap_store::CommittedMerge,
        yadorilink_sync_sqlite::rebootstrap_store::ForeignMergeError,
    > {
        self.database.write_immediate(|tx| {
            yadorilink_sync_sqlite::rebootstrap_store::commit_foreign_merge(tx, returning)
        })
    }

    /// Plans and applies retroactive conflict-copy repairs for `group_id`:
    /// computes the merge plan, consults the repair-election provider (if
    /// any) to decide whether this device is eligible to author the
    /// repair, emits the resulting ops, and wakes materialization on
    /// success (`yadorilink_sync_sqlite::retroactive_conflict::plan_retroactive_merge`).
    pub fn repair_retroactive_conflict_copy_obligations(
        &self,
        group_id: &str,
        emitter: &ChangeEmitter,
        eligible_rank: usize,
    ) -> Result<RetroactiveRepairOutcome, SyncError> {
        use yadorilink_sync_sqlite::retroactive_conflict::{
            plan_retroactive_merge, RetroactiveMergeOutcome,
        };

        // PLAN — read-only, with no writer transaction held. This is the
        // expensive half: a traversal of the frontier-reachable DAG, decoding
        // every reachable change. Run under the writer gate it was measured
        // holding that gate for 366 of one 348-second window across 46 passes,
        // starving every other writer in the daemon.
        // One snapshot for the whole traversal. `read` opens no transaction,
        // so a plan built through it could observe a different database
        // between one statement and the next and describe a state that never
        // existed at any instant.
        let planning_started = std::time::Instant::now();
        let outcome =
            self.database.read_snapshot::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                plan_retroactive_merge(conn, group_id)
            })?;
        // Worth watching rather than guarding. In WAL mode a long-lived
        // DEFERRED reader blocks no writer, but it does stop checkpointing
        // from reclaiming the frames it still needs — so a planner that runs
        // for minutes shows up as WAL growth rather than as contention, and
        // that is invisible unless the duration is recorded somewhere.
        tracing::debug!(
            %group_id,
            snapshot_held_ms = planning_started.elapsed().as_millis() as u64,
            "retroactive repair planning snapshot released"
        );

        let plan = match outcome {
            RetroactiveMergeOutcome::PathObligationTooLarge(blocked) => {
                // Rechecked before being reported as permanent, on the same
                // principle as an ordinary plan. The caller caches permanence
                // keyed on the frontier, and the state this verdict was
                // computed against includes durable conflict-copy provenance
                // and the retained-history boundary — neither of which
                // disturbs the frontier when it moves. Reporting it unchecked
                // would suppress the re-plan a provenance change should cause.
                let staleness =
                    self.database.read_snapshot::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                        |conn| blocked.revalidate(conn, group_id),
                    )?;
                if let Some(reason) = staleness {
                    return Ok(RetroactiveRepairOutcome::PlanStale { reason });
                }
                return Ok(RetroactiveRepairOutcome::PermanentlyBlocked {
                    path: blocked.path.clone(),
                    committed_frontier: blocked.frontier().heads().to_vec(),
                });
            }
            RetroactiveMergeOutcome::Plan(plan) => plan,
        };

        if plan.direct_ops.is_empty() {
            return Ok(RetroactiveRepairOutcome::NothingToDo {
                committed_frontier: plan.frontier.heads().to_vec(),
            });
        }

        // The election consults a provider that may do real work of its own.
        // It ran inside the write transaction before, which put whatever that
        // provider does under the writer gate too.
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
            let local_rank = election_contexts.iter().filter_map(|ctx| ctx.local_rank()).min();
            if local_rank.is_none_or(|rank| rank > eligible_rank) {
                return Ok(RetroactiveRepairOutcome::AwaitingFailover {
                    local_rank,
                    committed_frontier: plan.frontier.heads().to_vec(),
                });
            }
        }

        let policy_head = self.local_policy_head(group_id)?;
        let fingerprint = emitter.signing_key_fingerprint();
        if election_contexts.iter().any(|context| {
            context.expected_policy_head() != policy_head
                || context.local_device_id() != emitter.device_id()
                || context.local_key_fingerprint() != fingerprint
        }) {
            return Err(SyncError::PolicyUnavailable);
        }

        // COMMIT — short, and holding only what emission needs. Everything
        // above was computed against `plan.frontier`; if that frontier has
        // moved, the plan describes a view that no longer exists and nothing
        // may be written from it.
        let source_paths = plan.source_paths.clone();
        let outcome = self.database.write_immediate(|tx| {
            // The frontier token, and then a re-run of the plan's own
            // derivation. The frontier alone would be a proxy: planning also
            // reads durable conflict-copy provenance and the retained-history
            // boundary, and treating an unmoved frontier as proof that those
            // are unmoved too would be reasoning from a coincidence.
            if let Some(reason) = plan.revalidate(tx, group_id)? {
                tracing::debug!(%group_id, ?reason, "retroactive repair plan went stale");
                return Ok(RetroactiveRepairOutcome::PlanStale { reason });
            }

            yadorilink_sync_sqlite::dag_store::emit_retroactive_repair(
                tx,
                group_id,
                plan.direct_ops.clone(),
                plan.obligations.clone(),
                emitter,
            )?;
            if self.local_policy_head(group_id)? != policy_head {
                return Err(SyncError::PolicyUnavailable);
            }

            let mut committed_frontier =
                yadorilink_sync_sqlite::dag_store::group_heads(tx, group_id)?;
            committed_frontier.sort();
            Ok(RetroactiveRepairOutcome::Repaired {
                repaired_paths: source_paths.clone(),
                committed_frontier,
            })
        })?;

        if matches!(outcome, RetroactiveRepairOutcome::Repaired { .. }) {
            self.materialization_wake.notify_materialization_wake();
        }
        Ok(outcome)
    }
}

// --- Port impls implemented directly in this file (the other three live
// in the `peer_replica_state`, `materialization_state`, and
// `materialization_execution` submodules -- see the module doc above). ---

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

// --- History-compaction store wiring: `CompactionDagStore`,
// `DeviceFrontierStore`, and `CheckpointStore` (`yadorilink_replica_engine::
// compaction`) delegate to `self.sqlite`/`self.database`, the same handles
// the rest of this struct's methods use. ---
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
}

#[cfg(test)]
mod dag_import_tests;

#[cfg(test)]
pub(crate) mod test_observers;

#[cfg(test)]
mod materialization_intent_tests;

#[cfg(test)]
mod root_permit_commit_tests;
