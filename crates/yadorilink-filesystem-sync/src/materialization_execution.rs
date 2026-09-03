//! The capability surface `evict_file`'s function family
//! (`materialization_eviction.rs`) and `repair_interrupted_materializations`/
//! `reconcile_restore_operations`/`quarantine_dirty_disk_file`'s
//! (`materialization_repair.rs`) need from whatever concrete state backs
//! them -- a narrower trait than `yadorilink-sync-sqlite`'s own
//! `MaterializationStatePort` (38 methods), which mixes this
//! filesystem-lifecycle-flavored surface with SQL/DAG-flavored methods
//! (`dag_get_change`/`mark_deleted`/`upsert_file`/...) that belong on
//! `yadorilink-sync-sqlite`/`yadorilink-replica-engine` instead, and which
//! leaks a `yadorilink-sync-sqlite` concrete type
//! (`mark_deleted_emitting_change`'s `ChangeEmitter` parameter) that this
//! crate must never depend on. Covers exactly the method surface a direct
//! grep of every `state.<method>(` call across those two files' production
//! code finds (originally enumerated in Phase 7D-9C's fourth-pass exit
//! report, §10.3, back when this code still lived in a single
//! `materialization.rs`), plus one narrow delegate (`reclaim_cached_blocks`)
//! added for the same "concrete type a trait object can't produce" reason
//! as `open_materialization_intent_guard` below: `yadorilink-sync-sqlite`'s
//! own `BlockDeletionCoordinator::reclaim_cached_blocks` still needs `&dyn
//! yadorilink_sync_sqlite::MaterializationStatePort` (the *wider* trait),
//! which this crate cannot name without depending on `yadorilink-sync-
//! sqlite`, which itself already depends on this crate -- routing the call
//! through a method on this port instead lets `impl
//! MaterializationExecutionPort for ReplicaCoordinator` perform the
//! concrete call internally, where `self` already satisfies the wider
//! trait.
//!
//! `impl MaterializationExecutionPort for ReplicaCoordinator` stays in
//! `yadorilink-daemon` (orphan rule -- `ReplicaCoordinator` is
//! daemon-local), mirroring `PeerReplicaStatePort`/`LocalMutationStore`'s
//! own precedent exactly: the trait *definition* crosses the crate line,
//! the impl does not.

use std::path::Path;
use std::sync::Arc;

use yadorilink_local_storage::{BlockReclamationStore, GcReport, PlaceholderDiskIdentity};
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
/// Opaque here (the concrete guard is `yadorilink-daemon`'s own
/// `MaterializationIntentGuard<'_>`, which borrows a concrete
/// `&ReplicaCoordinator` a trait object can't name) -- the only operation
/// any caller ever performs on one is clearing it once the write it guards
/// is durable. Dropping without calling `clear` is itself meaningful: the
/// intent stays recorded, so the next repair pass treats a missing file at
/// this path as a crash to recover, not an offline delete. Mirrors
/// `yadorilink-peer-session::ports::OpenMaterializationIntent` and
/// `yadorilink-sync-sqlite`'s own `OpenMaterializationIntent` exactly --
/// `MaterializationIntentGuard` implements one marker trait per consumer
/// crate, since none of the three can depend on either of the others.
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
/// filesystem-execution path -- `yadorilink-daemon`'s `SyncError` cannot be
/// reused here without a forbidden dependency edge back onto that crate
/// (this crate is a dependency OF `yadorilink-daemon`, not the reverse).
/// Every variant mirrors one `SyncError` variant the `evict_file` family
/// (`materialization_eviction.rs`/`materialization_repair.rs`) actually
/// constructs or matches on, same message text, so error reporting stays
/// byte-identical for anything wrapping the message string -- same shape as
/// `yadorilink-peer-session`'s `PeerSessionError`. `yadorilink-daemon`'s own
/// `impl From<SyncError> for MaterializationExecutionError` bridges
/// `SyncError` -> this type at the port boundary (used inside `impl
/// MaterializationExecutionPort for ReplicaCoordinator`'s own `?`-sites);
/// `impl From<MaterializationExecutionError> for SyncError` (in
/// `yadorilink-daemon`, since `SyncError` is the foreign type from this
/// crate's perspective) bridges the other direction for any caller of the
/// `evict_file` family that still needs a plain `SyncError`.
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

    /// M2-3b: a `dehydrate_windows_placeholder` call's outcome could not be
    /// determined -- a Codex-review finding on this method's own doc
    /// comment claiming "every returned error means dehydration did NOT
    /// happen" was false as originally written: `dehydrate_server`
    /// performs the real `CfDehydratePlaceholder` call BEFORE writing its
    /// response, so a transport-level failure (timeout, a dropped pipe,
    /// the response never arriving) can happen AFTER the native dehydrate
    /// already succeeded server-side -- the daemon genuinely cannot tell
    /// the two apart from a bare I/O error or timeout. Unlike
    /// `EvictionRejected` (a coherent response was received, so the
    /// server's own logic ran to completion and its answer is trusted),
    /// this variant must NOT be treated as "the file is still fully
    /// materialized" -- `evict_file`'s caller must leave the row in
    /// `Evicting` rather than roll it back to `Hydrated`, since `Evicting`
    /// is the state `reset_stale_evicting_to_placeholder`'s startup
    /// recovery already safely resolves regardless of which of the two
    /// real outcomes actually happened (see that function's own doc
    /// comment; M2-3b's design never mints a fresh identity on eviction,
    /// which is exactly what makes resolving to `Placeholder` safe in
    /// both cases).
    #[error("eviction outcome for {0:?} could not be confirmed")]
    EvictionOutcomeAmbiguous(String),

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
/// subset of `yadorilink-sync-sqlite`'s own `MaterializationStatePort`'s
/// wider surface (see this module's own doc comment for why the wider trait
/// itself does not move into this crate).
/// Duplicated from `yadorilink_sync_sqlite::MaterializedFingerprint` rather
/// than adding a dependency on that crate solely for this alias -- same
/// "duplicate small leaf types rather than force an awkward dependency"
/// precedent this trait's own `PlaceholderDiskIdentity`-adjacent methods
/// already follow, and matches `yadorilink-peer-session`'s own independent
/// duplication of the identical alias.
pub type MaterializedFingerprint = (u64, Option<std::time::SystemTime>, i64, i64);

pub trait MaterializationExecutionPort: Send + Sync {
    fn get_unix_mode(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<u32>, MaterializationExecutionError>;

    /// See `yadorilink_replica_domain::file::FileMeta::xattrs`'s own doc
    /// comment -- the same allow-listed extended attributes `get_unix_mode`
    /// above applies for the recorded permission bits.
    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, MaterializationExecutionError>;

    fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, MaterializationExecutionError>;

    /// The raw, unresolved symlink target bytes recorded for `path` --
    /// `None` when there is no row, the row is not a symlink, or no
    /// target was ever recorded for a symlink-classified row. Repair's
    /// own symlink-recovery path (`materialization_repair.rs`) uses this
    /// to know what to recreate.
    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, MaterializationExecutionError>;

    /// Whether `group_id`'s link has opted in to writing real Windows
    /// symlinks -- see `yadorilink-peer-session`'s identically-named
    /// method (the live materialize path's own policy source) for the
    /// full reasoning. Repair's symlink-recovery path must respect the
    /// same policy the live path does, or it could write a real symlink
    /// on a Windows link that has explicitly opted out.
    fn windows_symlink_opt_in_for_group(
        &self,
        group_id: &str,
    ) -> Result<bool, MaterializationExecutionError>;

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
    ) -> Result<
        std::collections::HashMap<String, MaterializationState>,
        MaterializationExecutionError,
    >;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Whether `path` currently has ANY row at all in the projection-
    /// obligation worklist (any state, including the parked
    /// `ignore_blocked` state) -- a live, per-path, always-authoritative
    /// read; never cached or snapshotted.
    ///
    /// While a projection obligation exists for a path, an absent local
    /// file must not yet be interpreted as an offline user deletion: the
    /// Convergence Engine still considers this path's desired state
    /// unsettled (freshly admitted, mid-materialize-retry, or otherwise
    /// not yet placed -- see this method's own callers for the "not yet
    /// settled, not settled-but-wrong" scope this signal covers, and does
    /// not). This is a SEPARATE signal from `has_materialization_intent`/
    /// `list_materialization_intent_paths`: an intent exists only for the
    /// narrow window of one in-flight physical write, while an obligation
    /// can be outstanding long before any write is ever attempted (or
    /// after one that keeps retrying) -- repair must check both, not
    /// either alone, before concluding a missing-with-no-intent path was
    /// genuinely deleted.
    ///
    /// Deliberately per-path, not a whole-pass snapshot the way
    /// `list_materialization_intent_paths` is: that shape trades staleness
    /// risk for cost on the (very common) `outstanding_intents` case,
    /// which is fine there -- see that method's own doc comment -- because
    /// its worst case is merely deferring a moot cleanup by one pass. This
    /// method instead gates the tombstone-vs-reconstruct DECISION itself, on
    /// only the rare rows that are already `Hydrated`-but-disk-mismatched,
    /// where a stale miss could let a real, still-unsettled path fall
    /// through to be wrongly resolved. On that small a candidate set, one
    /// extra authoritative read per row costs nothing worth trading
    /// correctness for.
    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, MaterializationExecutionError>;

    /// Every path in `group_id` that currently carries a materialization
    /// intent, as one read.
    ///
    /// The intent journal is empty in steady state -- an intent exists only
    /// between a materialize opening one and the same materialize clearing it,
    /// or after a crash in that window. A sweep over the whole group therefore
    /// wants to know the (tiny) set ONCE rather than asking, or blindly
    /// writing, per path: see `materialization_repair`'s own use of this.
    fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, MaterializationExecutionError>;

    /// Clears the durable materialization-write-in-progress intent once the
    /// write + rename + fsync has completed for `(group_id, path)`.
    fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// Records the durable materialization-write-in-progress intent, which
    /// MUST be committed before the temp-write-then-rename that
    /// materializes content begins.
    fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit,
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
        publish_absent_proof: bool,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
    ) -> Result<yadorilink_replica_domain::ids::ChangeHash, MaterializationExecutionError>;

    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected`.
    fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
        permit: &RootCommitPermit,
    ) -> Result<bool, MaterializationExecutionError>;

    /// M5-A review follow-up (blocker #56, second round): records the disk
    /// identity of the exact bytes this device just wrote via a successful
    /// `reconstruct_file`, alongside that same call's `Hydrated`
    /// transition -- always called right after `reconstruct_file_
    /// journaled` succeeds in this module's own repair path, exactly like
    /// the live peer materialize/hydrate paths already do at their own
    /// equivalent call sites. See `yadorilink_sync_sqlite::
    /// materialization_state::MaterializationStateRepository::
    /// record_materialized_fingerprint`'s own doc comment for the full
    /// reasoning.
    fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<MaterializedFingerprint>,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// Records the identity of the exact on-disk object a `write_placeholder`
    /// call just created for `(group_id, path)` (M1-2) -- always called
    /// alongside that same call's `set_materialization_state(Placeholder)`.
    /// See `yadorilink_sync_sqlite::materialization_state::
    /// MaterializationStateRepository::record_placeholder_generation`'s own
    /// doc comment.
    fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// Like [`Self::record_placeholder_generation`], but only if nothing is
    /// recorded yet -- a concurrent winner's value is kept instead of being
    /// overwritten. M2-3a's Windows placeholder-creation path (via
    /// `yadorilink_local_storage::create_or_defer_placeholder`'s
    /// `RecordIfAbsent` outcome) MUST use this, never the unconditional
    /// version: on Windows, real on-disk placeholder creation is deferred
    /// to a second process (`cfapi-host.exe`) that a concurrent
    /// `ListFolderFilesRequest` backfill can already have supplied a
    /// generation to, and an unconditional overwrite here would silently
    /// orphan whatever that process already used. See
    /// `yadorilink_sync_sqlite::materialization_state::
    /// MaterializationStateRepository::record_placeholder_generation_if_absent`'s
    /// own doc comment.
    fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit,
    ) -> Result<PlaceholderDiskIdentity, MaterializationExecutionError>;

    /// Clears any placeholder identity recorded for `(group_id, path)` -- a
    /// no-op if none was recorded. See
    /// `MaterializationStateRepository::clear_placeholder_generation`'s own
    /// doc comment for when callers must call this.
    fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), MaterializationExecutionError>;

    /// The identity currently recorded on `(group_id, path)`'s row,
    /// regardless of its current `materialization_state` -- unlike
    /// [`Self::record_placeholder_generation`]'s read counterpart in
    /// `MaterializationStateRepository::get_placeholder_generation` (gated to
    /// `materialization_state = 'placeholder'`, so it deliberately returns
    /// nothing once a row has hydrated), no production call site clears
    /// `placeholder_dev`/`placeholder_ino`/`placeholder_provider_kind` on the
    /// `Placeholder` -> `Hydrated` transition -- they are simply left in
    /// place until an explicit [`Self::clear_placeholder_generation`] call.
    /// M2-3b's Windows eviction path relies on exactly that: it reads a
    /// `Hydrated` file's still-recorded generation here as the expected
    /// identity to pass into the native dehydrate call -- an extra
    /// defense-in-depth check on top of the disk-content revalidation
    /// `evict_file` already performs, not a substitute for it.
    fn get_recorded_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<(PlaceholderDiskIdentity, String)>, MaterializationExecutionError>;

    /// M2-3b: asks the real Windows CfAPI provider process
    /// (`yadorilink-cfapi-host.exe`) to natively dehydrate the placeholder
    /// at `out_path` (an absolute path), blocking until it confirms
    /// success or failure. `expected_generation`: the generation
    /// [`Self::get_recorded_placeholder_identity`] returned for this row,
    /// passed through as a defense-in-depth ABA guard (see
    /// `shell-ext/windows/src/cfapi.rs::dehydrate_placeholder`'s own doc
    /// comment) -- `None` skips that guard. `materialization_eviction::
    /// evict_to_placeholder`'s Windows arm gates the `Placeholder`
    /// transition and block reclamation on this call's success; its
    /// non-Windows arm never calls it at all.
    ///
    /// An implementor MUST return
    /// [`MaterializationExecutionError::EvictionOutcomeAmbiguous`], never
    /// [`MaterializationExecutionError::EvictionRejected`], for any
    /// failure mode that cannot positively rule out the native dehydrate
    /// having actually succeeded (a transport timeout, a dropped
    /// connection, a response that never arrived) -- see that variant's
    /// own doc comment for why `evict_file`'s caller handles the two
    /// differently.
    ///
    /// The default implementation (used by every platform except Windows,
    /// where nothing calls this) fails closed with `EvictionRejected` --
    /// there is no real provider to ask at all, so there is no ambiguity:
    /// dehydration definitely did not happen.
    fn dehydrate_windows_placeholder(
        &self,
        _path: &str,
        _out_path: &Path,
        _expected_generation: Option<u64>,
    ) -> Result<(), MaterializationExecutionError> {
        Err(MaterializationExecutionError::EvictionRejected(
            "native Windows placeholder dehydration is not supported on this platform".to_string(),
        ))
    }

    /// Every still-`Placeholder` path in `group_id` with no recorded
    /// identity -- see `MaterializationStateRepository::
    /// list_placeholder_paths_missing_generation`'s own doc comment for
    /// the crash window this exists to close.
    fn list_placeholder_paths_missing_generation(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, MaterializationExecutionError>;

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
    fn discard_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), MaterializationExecutionError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token. Added as a narrow delegate because
    /// `VerifiedRoot::verify` needs `&dyn RootVerificationStatePort`, and a
    /// caller holding only `&dyn MaterializationExecutionPort` cannot
    /// produce one -- Rust does not let a trait object be treated as a
    /// different trait object its own trait was never declared to imply.
    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Establishes a root's identity, which may silently adopt an
    /// unmarked-but-corroborated root. Added as a narrow delegate for the
    /// same reason as `verify_root` above.
    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<VerifiedRoot, MaterializationExecutionError>;

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)`. Added as a narrow delegate (rather than exposing
    /// `&ReplicaCoordinator` itself) because the concrete guard borrows a
    /// concrete `&'a ReplicaCoordinator`, which a trait object can't
    /// produce; the implementation runs inside `impl
    /// MaterializationExecutionPort for ReplicaCoordinator`, where `self`
    /// already is that concrete `&ReplicaCoordinator`.
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

    /// Narrow delegate for `yadorilink-sync-sqlite::block_deletion::
    /// BlockDeletionCoordinator::reclaim_cached_blocks`, which still needs
    /// `&dyn yadorilink_sync_sqlite::MaterializationStatePort` (the wider
    /// trait) -- this crate cannot name that trait without depending on
    /// `yadorilink-sync-sqlite`, which itself already depends on this crate
    /// (a forbidden cycle), so the call is routed through this port method
    /// instead, exactly like `open_materialization_intent_guard` above.
    /// `impl MaterializationExecutionPort for ReplicaCoordinator` performs
    /// the concrete call internally, where `self` already satisfies the
    /// wider trait.
    fn reclaim_verified_cached_blocks(
        &self,
        deletion_guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, MaterializationExecutionError>;

    /// Bumps `path`'s filesystem-side mutation fence, invalidating any
    /// actual-state proof
    /// `path_materialized_generations` may hold for it. `evict_file` has no
    /// DAG-frontier proof of its own to publish under (it is a pure
    /// disk-state transition, hydrated content -> placeholder), so it only
    /// ever calls this, never a publish -- same treatment as on-demand
    /// hydration (`PeerReplicaStatePort::dag_bump_mutation_fence`, this
    /// port's sibling in `yadorilink-peer-session`). Must be called inside
    /// `path`'s lock, before the first mutating syscall.
    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, MaterializationExecutionError>;
}
