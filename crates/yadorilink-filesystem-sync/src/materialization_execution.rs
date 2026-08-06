//! The capability surface `evict_file`'s function family (and, once moved,
//! `repair_interrupted_materializations`/`reconcile_restore_operations`/
//! `quarantine_dirty_disk_file`) needs from `yadorilink-sync-core`'s
//! `SyncState` -- a narrower trait than that crate's own
//! `ports::MaterializationStatePort` (647 lines, 38 methods), which mixes
//! this filesystem-lifecycle-flavored surface with SQL/DAG-flavored methods
//! (`dag_get_change`/`mark_deleted`/`upsert_file`/...) that belong on
//! `yadorilink-sync-sqlite`/`yadorilink-replica-engine` instead, and which
//! leaks a `yadorilink-sync-sqlite` concrete type
//! (`mark_deleted_emitting_change`'s `ChangeEmitter` parameter) that this
//! crate must never depend on. Covers exactly the method surface a direct
//! grep of every `state.<method>(` call in `materialization.rs`'s
//! `evict_file`-through-`quarantine_dirty_disk_file` production code found
//! (Phase 7D-9C's fourth-pass exit report, §10.3), plus one narrow delegate
//! (`reclaim_cached_blocks`) added for the same "concrete type a trait
//! object can't produce" reason as `open_materialization_intent_guard`
//! below: `yadorilink-sync-core`'s own `BlockDeletionCoordinator::
//! reclaim_cached_blocks` still needs `&dyn
//! yadorilink_sync_core::ports::MaterializationStatePort` (the *wider*
//! trait), which this crate cannot name without depending back on
//! sync-core -- routing the call through a method on this port instead lets
//! `impl MaterializationExecutionPort for SyncState` perform the concrete
//! call internally, where `self` already satisfies the wider trait.
//!
//! `impl MaterializationExecutionPort for SyncState` stays in
//! `yadorilink-sync-core` (orphan rule -- `SyncState` is sync-core-local),
//! mirroring `PeerReplicaStatePort`/`LocalMutationStore`'s own precedent
//! exactly: the trait *definition* crosses the crate line, the impl does
//! not.

use std::path::Path;
use std::sync::Arc;

use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use crate::block_liveness::BlockPhysicalDeletionGuard;
use crate::materialization_types::{EvictableFile, RestoreCommitOutcome, RestoreOperation};

/// An open, durably-recorded materialization intent for one path, returned
/// by [`MaterializationExecutionPort::open_materialization_intent_guard`].
/// Opaque here (the concrete guard is `yadorilink-sync-core`'s own
/// `MaterializationIntentGuard<'_>`, which borrows a concrete `&SyncState` a
/// trait object can't name) -- the only operation any caller ever performs
/// on one is clearing it once the write it guards is durable. Dropping
/// without calling `clear` is itself meaningful: the intent stays recorded,
/// so the next repair pass treats a missing file at this path as a crash to
/// recover, not an offline delete. Mirrors
/// `yadorilink-peer-session::ports::OpenMaterializationIntent` exactly --
/// `MaterializationIntentGuard` implements both marker traits, one per
/// consumer crate, since neither consumer can depend on the other.
pub trait OpenMaterializationIntent: Send {
    fn clear(self: Box<Self>) -> Result<(), MaterializationExecutionError>;
}

/// The unconditional, pre-lock reads `evict_file` performs to decide
/// whether a path is even a candidate for eviction at all -- pinned status,
/// the atomic current-version snapshot, and the record's kind. Grouped into
/// one semantic read because `evict_file` always performs all three
/// together, in this order, with no intervening mutation between them.
#[derive(Debug, Clone)]
pub struct EvictionEligibilitySnapshot {
    pub pinned: bool,
    pub current_version: Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>,
    pub record_kind: Option<RecordKind>,
}

/// The reads `evict_file` re-performs *after* acquiring the per-path lock,
/// to re-verify nothing raced the eligibility check above before the
/// placeholder write commits -- this IS the "permit/lease re-verification
/// point" this module's behavioral invariants require stay pinned to this
/// precise point in the control flow.
#[derive(Debug, Clone)]
pub struct EvictionRevalidationSnapshot {
    pub current_version: Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>,
    pub pinned: bool,
    pub materialization_state: Option<MaterializationState>,
    pub path_dirty: bool,
}

/// The reads `repair_interrupted_materializations_inner`'s per-path loop
/// re-performs under the path lock, before deciding whether a `Hydrated`
/// row is a genuine interrupted-materialization candidate.
#[derive(Debug, Clone)]
pub struct RepairRowSnapshot {
    pub materialization_state: Option<MaterializationState>,
    pub record_kind: Option<RecordKind>,
    pub file: Option<FileRecord>,
}

/// This crate's own error type for the materialization/eviction/repair
/// filesystem-execution path -- `yadorilink-sync-core`'s `SyncError` cannot
/// be reused here without a forbidden dependency edge back onto sync-core
/// (this crate is a dependency OF sync-core, not the reverse). Every
/// variant mirrors one `SyncError` variant `materialization.rs`'s
/// `evict_file` family actually constructs or matches on, same message
/// text, so error reporting stays byte-identical for anything wrapping the
/// message string -- same shape as `yadorilink-peer-session`'s
/// `PeerSessionError`. `yadorilink-sync-core`'s own
/// `impl MaterializationExecutionPort for SyncState` bridges `SyncError` ->
/// this type at the port boundary; `impl From<MaterializationExecutionError>
/// for SyncError` (in sync-core, since `SyncError` is the foreign type from
/// this crate's perspective) bridges the other direction for any sync-core
/// caller of the moved functions that still needs `SyncError`.
#[derive(Debug, thiserror::Error)]
pub enum MaterializationExecutionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt local state: {0}")]
    CorruptState(String),

    #[error("eviction of {0:?} was rejected")]
    EvictionRejected(String),

    /// The group's policy has not loaded this run, so a change-emitting
    /// write withheld its emission rather than stamp a placeholder-auth
    /// change. See `yadorilink_replica_domain::change::PolicyUnavailable`.
    #[error("no verified policy is currently loaded for this group")]
    PolicyUnavailable,

    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    #[error("disk pressure on {volume}: {available_bytes} bytes available, {headroom_bytes} required for {path}")]
    DiskPressure { path: String, volume: String, available_bytes: u64, headroom_bytes: u64 },

    // No `#[from]` -- `StorageError::DiskPressure`/`PathEscapesRoot` special-case
    // into the two variants above instead of being buried in this generic
    // variant, so a caller matching on `MaterializationExecutionError` alone
    // can still tell them apart without reaching into the wrapped
    // `StorageError`. Mirrors `SyncError`/`PeerSessionError`'s own identical
    // reasoning.
    #[error("storage error: {0}")]
    Storage(yadorilink_local_storage::StorageError),

    #[error("root authority error: {0}")]
    RootAuthority(#[from] yadorilink_root_authority::RootAuthorityError),
}

impl From<yadorilink_local_storage::StorageError> for MaterializationExecutionError {
    fn from(error: yadorilink_local_storage::StorageError) -> Self {
        match error {
            yadorilink_local_storage::StorageError::DiskPressure {
                path,
                volume,
                available_bytes,
                headroom_bytes,
            } => MaterializationExecutionError::DiskPressure {
                path: path.display().to_string(),
                volume: volume.display().to_string(),
                available_bytes,
                headroom_bytes,
            },
            yadorilink_local_storage::StorageError::PathEscapesRoot(path) => {
                MaterializationExecutionError::PathEscapesRoot(path)
            }
            other => MaterializationExecutionError::Storage(other),
        }
    }
}

/// Capability surface `evict_file`'s function family needs: deciding which
/// files to evict, tracking the durable materialization-write-in-progress
/// intent journal that disambiguates a crash from an offline delete, and
/// replaying the crash-safe restore journal -- the filesystem-lifecycle
/// subset of `yadorilink-sync-core::ports::MaterializationStatePort`'s
/// wider surface (see this module's own doc comment for why the wider trait
/// itself does not move).
pub trait MaterializationExecutionPort: Send + Sync {
    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, MaterializationExecutionError>;

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError>;

    /// Hydrated, unpinned, non-deleted files for `group_id`, ordered
    /// least-recently-accessed first -- the automatic eviction sweep's
    /// candidate list, in eviction order.
    fn list_evictable_files(
        &self,
        group_id: &str,
    ) -> Result<Vec<EvictableFile>, MaterializationExecutionError>;

    /// Total on-disk size of every hydrated file (pinned or not) -- the
    /// eviction sweep's usage figure, which must include pinned files even
    /// though `list_evictable_files` excludes them as candidates.
    fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, MaterializationExecutionError>;

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), MaterializationExecutionError>;

    /// Every file's materialization state for a group, in one query.
    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, MaterializationState>, MaterializationExecutionError>;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Clears the durable materialization-write-in-progress intent once the
    /// write + rename + fsync has completed for `(group_id, path)`.
    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError>;

    /// Records the durable materialization-write-in-progress intent, which
    /// MUST be committed before the temp-write-then-rename that
    /// materializes content begins.
    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError>;

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction. Returns `Err(PolicyUnavailable)` when the
    /// group's policy has not loaded this run, in which case the emission
    /// was withheld, not attempted-and-failed.
    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<yadorilink_replica_domain::ids::ChangeHash, MaterializationExecutionError>;

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError>;

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), MaterializationExecutionError>;

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected`.
    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Acquires the per-`(group_id, path)` lock so a materialization write
    /// cannot race a concurrent local capture or peer reconciliation of the
    /// same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// Every open crash-safe restore-journal entry for `group_id`.
    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, MaterializationExecutionError>;

    /// Atomically publishes the exact journaled restore version and removes
    /// its recovery marker.
    fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, MaterializationExecutionError>;

    /// Drops a restore-journal entry that recovery determined no longer
    /// needs replaying.
    fn discard_restore_operation(&self, operation_id: &str) -> Result<(), MaterializationExecutionError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token. Added as a narrow delegate because
    /// `VerifiedRoot::verify` takes a concrete `&SyncState`, which a trait
    /// object can't produce.
    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Establishes a root's identity, which may silently adopt an
    /// unmarked-but-corroborated root. Added as a narrow delegate for the
    /// same reason as `verify_root` above.
    fn open_root(&self, root: &Path, group_id: &str) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)`. Added as a narrow delegate (rather than exposing
    /// `&SyncState` itself) because the concrete guard borrows a concrete
    /// `&'a SyncState`, which a trait object can't produce; the
    /// implementation runs inside `impl MaterializationExecutionPort for
    /// SyncState`, where `self` already is that concrete `&SyncState`.
    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, MaterializationExecutionError>;

    /// Semantic-operation read replacing `evict_file`'s three unconditional
    /// pre-lock CRUD reads with one snapshot-shaped call. See
    /// [`EvictionEligibilitySnapshot`]'s own doc comment.
    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionEligibilitySnapshot, MaterializationExecutionError>;

    /// Semantic-operation read replacing the four-CRUD-call re-verification
    /// `evict_file` performs immediately after acquiring the per-path lock
    /// -- the "permit/lease re-verification point". See
    /// [`EvictionRevalidationSnapshot`]'s own doc comment.
    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionRevalidationSnapshot, MaterializationExecutionError>;

    /// Semantic-operation read replacing the three-CRUD-call re-check
    /// `repair_interrupted_materializations_inner`'s per-path loop performs
    /// under the path lock. See [`RepairRowSnapshot`]'s own doc comment.
    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<RepairRowSnapshot, MaterializationExecutionError>;

    /// Narrow delegate for `yadorilink-sync-core::block_deletion::
    /// BlockDeletionCoordinator::reclaim_cached_blocks`, which still needs
    /// `&dyn yadorilink_sync_core::ports::MaterializationStatePort` (the
    /// wider trait) -- this crate cannot name that trait without depending
    /// back on sync-core, so the call is routed through this port method
    /// instead, exactly like `open_materialization_intent_guard` above.
    /// `impl MaterializationExecutionPort for SyncState` performs the
    /// concrete call internally, where `self` already satisfies the wider
    /// trait.
    fn reclaim_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError>;
}
