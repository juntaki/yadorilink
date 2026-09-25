//! The single adapter owning all YadoriLink-specific SQLite persistence:
//! application schema, repository SQL, row/domain-type mapping, and every
//! cross-table atomic transaction this application needs (both remote
//! change admission and the wider local-authoring commit span tables from
//! several domains, which is why these don't cleanly split into separate
//! crates by domain).
//!
//! Built on `yadorilink-sqlite-runtime`'s connection pool/writer-gate/
//! transaction mechanics, which knows nothing about this crate's schema or
//! domain types. Implements ports declared in `yadorilink-replica-engine`
//! without those port traits knowing this crate exists.
//!
//! Deliberately does NOT own: domain decision logic (whether a conflict
//! copy is required, which execution fence to bump, whether a
//! materialization job is needed) -- callers decide, this crate only
//! persists already-decided writes atomically.

pub mod authorization_witness_gc;
pub mod base_advertisement;
pub mod change_history;
pub mod dag_store;
pub mod desired_state;
pub mod dirty_path;
pub mod enrollment;
mod error;
pub mod exact_materialized_commit;
pub mod file_identity_codec;
pub mod file_index;
mod frontier;
pub mod handoff_lease;
pub mod link;
pub mod local_capture_provenance;
mod materialization_intent_repository;
mod materialization_state;
pub mod materialized_generation;
pub mod membership_operation;
pub mod offline_group_policy_log;
pub mod offline_peer_authorization;
pub mod paused_items;
pub mod policy_watermark;
pub mod projection_obligations;
pub mod rebootstrap_store;
pub mod remote_admission;
mod replica_history;
pub mod restore_operation;
pub mod retroactive_conflict;
pub mod rewind_plan;
pub mod role_loss_operation;
pub mod snapshot_install_hold;
mod store;
pub mod structural_origin;
mod types;
pub mod verified_change_store;
pub mod write_through;

pub use change_history::{
    ChangeHistoryRepository, ImportAppendOutcome, PendingAdmission, REMOTE_ADMISSION_BATCH_SIZE,
};
pub use dirty_path::DirtyPathRepository;
pub use enrollment::EnrollmentRepository;
pub use error::SyncSqliteError;
pub use handoff_lease::HandoffLeaseRepository;
pub use materialization_intent_repository::MaterializationIntentRepository;
pub use materialization_state::{
    ContentHash, MaterializationCounts, MaterializationStateRepository,
    RecordedPlaceholderGeneration,
};
pub use membership_operation::MembershipOperationRepository;
pub use offline_group_policy_log::{OfflineGroupPolicyLog, OfflineGroupPolicyLogRepository};
pub use offline_peer_authorization::{
    OfflinePeerAuthorization, OfflinePeerAuthorizationRepository, OfflineSnapshotVersions,
};
pub use paused_items::PausedItemRepository;
pub use policy_watermark::{PolicyWatermark, PolicyWatermarkRepository};
pub use rebootstrap_store::RebootstrapStoreRepository;
pub use restore_operation::RestoreOperationRepository;
pub use role_loss_operation::RoleLossOperationRepository;
pub use snapshot_install_hold::SnapshotInstallHoldRepository;

/// A plain duplicate rather than a shared cross-crate helper: five lines,
/// no state, not worth its own module.
pub(crate) fn read_inventory_operation_id(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<String>> {
    match row.get_ref(column)? {
        rusqlite::types::ValueRef::Text(bytes) => {
            Ok(std::str::from_utf8(bytes).ok().map(str::to_owned))
        }
        _ => Ok(None),
    }
}
pub use store::{read_canonical_current_row, CanonicalCurrentRow, SqliteSyncStore};
pub use types::{CurrentVersionSnapshot, RetainedVersion, RetainedVersionState};
