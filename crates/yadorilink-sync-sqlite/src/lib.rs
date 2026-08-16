//! The single adapter owning all YadoriLink-specific SQLite persistence:
//! application schema, repository SQL, row/domain-type mapping, and every
//! cross-table atomic transaction this application needs (both remote
//! change admission and the wider local-authoring commit -- see
//! `docs/design/phase7d5-local-authoring-transaction.md` for why these
//! don't cleanly split into separate crates by domain).
//!
//! Built on `yadorilink-sqlite-runtime`'s connection pool/writer-gate/
//! transaction mechanics, which knows nothing about this crate's schema or
//! domain types. Implements ports declared in `yadorilink-replica-engine`
//! (and, as later commits land, `LocalMutationStore`/`MaterializationStatePort`-
//! shaped ports) without those port traits knowing this crate exists.
//!
//! Deliberately does NOT own: domain decision logic (whether a conflict
//! copy is required, which execution fence to bump, whether a
//! materialization job is needed) -- callers decide, this crate only
//! persists already-decided writes atomically.

pub mod block_deletion;
pub mod captured_authoring;
pub mod change_history;
pub mod commit_window;
pub mod dag_store;
pub mod dirty_path;
pub mod early_physical_recovery;
pub mod enrollment;
mod error;
pub mod file_identity_codec;
pub mod file_index;
pub mod filesystem_transaction;
mod frontier;
pub mod handoff_lease;
pub mod link;
mod materialization_job_repository;
mod materialization_jobs;
mod materialization_state;
pub mod materialization_state_port;
pub mod materialized_generation;
pub mod membership_operation;
pub mod policy_watermark;
pub mod rebootstrap_store;
mod replica_history;
pub mod resolution_planning;
pub mod restore_operation;
pub mod retained_obligation;
pub mod retroactive_conflict;
pub mod role_loss_operation;
mod store;
mod types;

pub use change_history::ChangeHistoryRepository;
pub use dirty_path::DirtyPathRepository;
pub use enrollment::EnrollmentRepository;
pub use error::SyncSqliteError;
pub use handoff_lease::HandoffLeaseRepository;
pub use materialization_job_repository::MaterializationJobRepository;
pub use materialization_state::{
    ContentHash, MaterializationCounts, MaterializationStateRepository, MaterializedFingerprint,
    RecordedPlaceholderGeneration,
};
pub use materialization_state_port::{
    EvictionEligibilitySnapshot, EvictionRevalidationSnapshot, MaterializationStatePort,
    OpenMaterializationIntent, RepairRowSnapshot,
};
pub use membership_operation::MembershipOperationRepository;
pub use policy_watermark::{PolicyWatermark, PolicyWatermarkRepository};
pub use rebootstrap_store::RebootstrapStoreRepository;
pub use restore_operation::RestoreOperationRepository;
pub use role_loss_operation::RoleLossOperationRepository;

/// Reads `column` as TEXT without trusting its SQLite storage class -- the
/// exact same helper `yadorilink-sync-core::repository::mod.rs` used to
/// define (see this doc comment's own prior wording there for the full "why
/// not just `row.get::<_, String>`" reasoning) before `enrollment` (its last
/// caller) moved here (Phase 7D-9F, ninth pass) alongside
/// `membership_operation`/`role_loss_operation`'s own earlier move. A plain
/// duplicate rather than a shared cross-crate helper: five lines, no state,
/// not worth its own module.
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
pub use materialization_jobs::{
    claim_runnable_jobs, enqueue_pending, get_job, init_materialization_jobs_schema,
    list_unfinished_jobs, mark_backoff, mark_superseded_if_version_matches, recover_after_restart,
    reschedule_after_skip, transition, MaterializationJob, MaterializationJobState,
};
pub use store::SqliteSyncStore;
pub use types::{CurrentVersionSnapshot, RetainedVersion, RetainedVersionState};
