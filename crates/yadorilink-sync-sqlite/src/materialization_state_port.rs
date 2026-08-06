//! `MaterializationStatePort` -- the capability surface the on-demand-sync
//! materialization engine (`yadorilink-sync-core`'s `materialization.rs`)
//! needs: materialization-job/intent tracking, materialization-state
//! get/set, eviction-candidate queries, and the crash-safe restore journal.
//! Relocated here from `yadorilink-sync-core` (Phase 7D-10) -- 36 of its 38
//! methods already delegated directly to a `yadorilink-sync-sqlite`
//! repository call with no logic beyond an error-type conversion, and this
//! crate already depends on every other type the trait's signatures name
//! (`yadorilink-root-authority`, `yadorilink-replica-domain`,
//! `yadorilink-filesystem-sync`'s `materialization_types`). See
//! `docs/design/phase7d10-exit-report.md`'s 2026-08-06 "item 1" addendum
//! for the full investigation this move is based on, including why
//! `yadorilink-filesystem-sync` (the other ledger-hinted destination) is
//! structurally ruled out: this trait's `mark_deleted_emitting_change`
//! method needs a concrete `yadorilink-sync-sqlite::dag_store::ChangeEmitter`
//! parameter, and `yadorilink-sync-sqlite` already depends on
//! `yadorilink-filesystem-sync` (never the reverse), so only this crate can
//! host both.
//!
//! Every method returns [`crate::SyncSqliteError`] directly now, not
//! `yadorilink-sync-core`'s wider `SyncError` catch-all the trait declared
//! before this move -- both `yadorilink-sync-core::SyncError` and
//! `yadorilink-daemon::sync_error::SyncError` already have
//! `From<SyncSqliteError>`, so every existing call site keeps converting at
//! its own boundary exactly as before, just one hop shorter.
//!
//! `SyncState` (`yadorilink-sync-core::index::SyncState`) and
//! `ReplicaCoordinator` (`yadorilink-daemon::replica_coordinator::
//! ReplicaCoordinator`) implement this trait in their own crates -- Rust's
//! orphan rule permits a foreign trait implemented for a local type, and
//! both those crates already depend on this one.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{CurrentVersionRecord, MaterializationState};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_root_authority::root_identity::VerifiedRoot;

use crate::dag_store::ChangeEmitter;
use crate::SyncSqliteError;
use yadorilink_filesystem_sync::materialization_types::{
    EvictableFile, RestoreCommitOutcome, RestoreOperation,
};

/// The unconditional, pre-lock reads `materialization::evict_file` performs
/// to decide whether a path is even a candidate for eviction at all --
/// pinned status, the atomic current-version snapshot, and the record's
/// kind. Grouped into one semantic read because `evict_file` always
/// performs all three together, in this order, with no intervening
/// mutation between them; packaging them does not change their consistency
/// (each is still the same independent read it was before -- this is not a
/// new transactional guarantee), only how many separate trait calls the
/// caller makes.
#[derive(Debug, Clone)]
pub struct EvictionEligibilitySnapshot {
    pub pinned: bool,
    pub current_version: Option<CurrentVersionRecord>,
    pub record_kind: Option<RecordKind>,
}

/// The reads `materialization::evict_file` re-performs *after* acquiring
/// the per-path lock, to re-verify nothing raced the eligibility check
/// above before the placeholder write commits -- the exact "permit/lease
/// re-verification point" this module's behavioral invariants require stay
/// pinned to this precise point in the control flow. Grouping these into
/// one snapshot does not move, widen, or narrow that re-verification
/// point.
#[derive(Debug, Clone)]
pub struct EvictionRevalidationSnapshot {
    pub current_version: Option<CurrentVersionRecord>,
    pub pinned: bool,
    pub materialization_state: Option<MaterializationState>,
    pub path_dirty: bool,
}

/// The reads `materialization::repair_interrupted_materializations_inner`'s
/// per-path loop re-performs under the path lock, before deciding whether a
/// `Hydrated` row is a genuine interrupted-materialization candidate.
#[derive(Debug, Clone)]
pub struct RepairRowSnapshot {
    pub materialization_state: Option<MaterializationState>,
    pub record_kind: Option<RecordKind>,
    pub file: Option<FileRecord>,
}

/// The opaque return type of [`MaterializationStatePort::
/// open_materialization_intent_guard`] -- mirrors
/// `yadorilink-peer-session::ports::OpenMaterializationIntent`/
/// `yadorilink-filesystem-sync::materialization_execution::
/// OpenMaterializationIntent`, one marker trait per consumer crate, so
/// `yadorilink-sync-core::materialization::MaterializationIntentGuard`
/// (which stays in `yadorilink-sync-core` -- see that module's own doc
/// comment) can implement all of them without any of the consumer crates
/// depending on each other. The `impl` for `MaterializationIntentGuard` is
/// written in `yadorilink-sync-core`, where the guard type itself lives --
/// legal under the orphan rule, the same way the other two marker-trait
/// impls already are.
pub trait OpenMaterializationIntent {
    fn clear(self: Box<Self>) -> Result<(), SyncSqliteError>;
}

/// Capability surface the materialization/on-demand-sync engine needs:
/// deciding which files to evict or hydrate, tracking the durable
/// materialization-write-in-progress intent journal that disambiguates a
/// crash from an offline delete, and replaying the crash-safe restore
/// journal.
pub trait MaterializationStatePort: Send + Sync {
    fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    /// Every block hash `path` currently references that's ALSO referenced
    /// by some other indexed row (any group, any state) -- used by block
    /// reclamation to avoid freeing a block another row still needs, even
    /// one this specific eviction knows nothing about.
    fn blocks_referenced_outside_current_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<std::collections::HashSet<yadorilink_local_storage::ContentHash>, SyncSqliteError>;

    /// The atomic-write-identity read used before evicting a file -- carries
    /// every column needed to rebuild the version identity without tearing
    /// across a concurrent metadata/content transition.
    fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, SyncSqliteError>;

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError>;

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError>;

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError>;

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected` -- the eviction rollback guard uses this
    /// so it never clobbers a newer transition performed by another
    /// operation while eviction was in flight.
    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError>;

    fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    /// Hydrated, unpinned, non-deleted files for `group_id`, ordered
    /// least-recently-accessed first -- the automatic eviction sweep's
    /// candidate list, in eviction order.
    fn list_evictable_files(&self, group_id: &str) -> Result<Vec<EvictableFile>, SyncSqliteError>;

    /// Total on-disk size of every hydrated file (pinned or not) -- the
    /// eviction sweep's usage figure, which must include pinned files even
    /// though `list_evictable_files` excludes them as candidates.
    fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, SyncSqliteError>;

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), SyncSqliteError>;

    /// Every file's materialization state for a group, in one query -- used
    /// by the reconciliation pass to decide which paths need a
    /// pending-materialization job without one lookup per path.
    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError>;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError>;

    /// Clears the durable materialization-write-in-progress intent once the
    /// write + rename + fsync has completed for `(group_id, path)`.
    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Records the durable materialization-write-in-progress intent, which
    /// MUST be committed before the temp-write-then-rename that
    /// materializes content begins, so a crash between the two leaves the
    /// intent durably present for startup repair to find.
    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Tombstones a path with "now" as the observed time -- the
    /// reconciliation pass's plain delete write when materializing a
    /// deletion that arrived without a pre-recorded observation time.
    fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction -- used when the engine itself must originate
    /// a deletion (e.g. repairing a divergent placeholder) rather than only
    /// materializing an already-admitted one.
    ///
    /// Real error surface: `local_emission_auth`'s
    /// `PolicyUnavailable` pre-check, then a `yadorilink-sync-sqlite`
    /// repository write -- both already fold losslessly into
    /// `SyncSqliteError` (see its own `PolicyUnavailable` variant).
    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncSqliteError>;

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn list_dirty_paths(
        &self,
        group_id: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::DirtyPath>, SyncSqliteError>;

    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), SyncSqliteError>;

    /// Acquires the per-`(group_id, path)` lock so a materialization write
    /// cannot race a concurrent local capture or peer reconciliation of the
    /// same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// A stored change decoded from its persisted bytes -- consulted while
    /// materializing a version to recover the change that authored it.
    fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError>;

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError>;

    fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Every retained version of `path` -- consulted while resolving which
    /// version's bytes to materialize for a restore.
    fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, SyncSqliteError>;

    /// Every open crash-safe restore-journal entry for `group_id` -- the
    /// engine's own startup recovery pass replays these.
    fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, SyncSqliteError>;

    /// Atomically publishes the exact journaled restore version and removes
    /// its recovery marker, so a second recovery pass observes no row and
    /// cannot double-apply it.
    fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, SyncSqliteError>;

    /// Drops a restore-journal entry that recovery determined no longer
    /// needs replaying (e.g. superseded by a later write).
    fn discard_restore_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token rather than silently adopting an
    /// unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::verify`].
    /// Added as a narrow delegate because `VerifiedRoot::verify` takes a
    /// concrete backing type, which a trait object can't produce.
    fn verify_root(&self, root: &Path, group_id: &str) -> Result<VerifiedRoot, SyncSqliteError>;

    /// Establishes a root's identity, which may silently adopt an
    /// unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::open`].
    /// Added as a narrow delegate for the same reason as `verify_root`
    /// above.
    fn open_root(&self, root: &Path, group_id: &str) -> Result<VerifiedRoot, SyncSqliteError>;

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)` before repair reconstructs a file's bytes from
    /// its indexed blocks and commits a fresh `Hydrated` row. See
    /// `yadorilink_sync_core::materialization::MaterializationIntentGuard::
    /// open`. Returns the opaque [`OpenMaterializationIntent`] marker (same
    /// shape as `PeerReplicaStatePort`/`MaterializationExecutionPort`'s own
    /// equivalent methods) rather than the concrete guard type directly, so
    /// this trait's return type does not pin the guard's backing type to
    /// one implementor.
    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, SyncSqliteError>;

    /// Semantic-operation read replacing `evict_file`'s three unconditional
    /// pre-lock CRUD reads (`is_pinned`/`get_current_version_record`/
    /// `get_record_kind`) with one snapshot-shaped call. A provided
    /// default (not overridden by either implementor) so every existing
    /// implementor keeps working unchanged; the grouping is purely a
    /// caller-side ergonomic collapse, not a new atomicity guarantee -- see
    /// [`EvictionEligibilitySnapshot`]'s own doc comment.
    fn eviction_eligibility_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionEligibilitySnapshot, SyncSqliteError> {
        Ok(EvictionEligibilitySnapshot {
            pinned: self.is_pinned(group_id, path)?,
            current_version: self.get_current_version_record(group_id, path)?,
            record_kind: self.get_record_kind(group_id, path)?,
        })
    }

    /// Semantic-operation read replacing the four-CRUD-call re-verification
    /// `evict_file` performs immediately after acquiring the per-path lock,
    /// right before it commits the placeholder write -- see
    /// [`EvictionRevalidationSnapshot`]'s own doc comment for why this is
    /// exactly the "permit/lease re-verification point" the module's
    /// behavioral invariants pin in place, unmoved by this grouping.
    fn eviction_revalidation_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictionRevalidationSnapshot, SyncSqliteError> {
        Ok(EvictionRevalidationSnapshot {
            current_version: self.get_current_version_record(group_id, path)?,
            pinned: self.is_pinned(group_id, path)?,
            materialization_state: self.get_materialization_state(group_id, path)?,
            path_dirty: self.is_path_dirty(group_id, path)?,
        })
    }

    /// Semantic-operation read replacing the three-CRUD-call re-check
    /// `repair_interrupted_materializations_inner`'s per-path loop performs
    /// under the path lock -- see [`RepairRowSnapshot`]'s own doc comment.
    fn repair_row_snapshot(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<RepairRowSnapshot, SyncSqliteError> {
        Ok(RepairRowSnapshot {
            materialization_state: self.get_materialization_state(group_id, path)?,
            record_kind: self.get_record_kind(group_id, path)?,
            file: self.get_file(group_id, path)?,
        })
    }
}
