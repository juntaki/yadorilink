//! Pure value types describing a link's write-gate state, a hydration
//! hold, materialization state/policy, a startup-readiness failure, and a
//! current-version snapshot. Moved out of `yadorilink-sync-core` in Phase
//! 7D-6: each is either returned by `PeerReplicaStatePort`'s own methods,
//! or otherwise needed directly by `yadorilink-peer-session`'s production
//! code, while remaining just as load-bearing for `yadorilink-sync-core`'s
//! own local-authoring/materialization code that stays behind -- pure data,
//! no SQL, so hoisting here (rather than duplicating) keeps exactly one
//! definition.

use serde::{Deserialize, Serialize};

use crate::change::Op;
use crate::file::{BlockInfo, FileRecord, FileVersion, RecordKind, VersionBlock};
use crate::ids::{ChangeHash, VersionHash};

fn unknown_persisted_enum(kind: &str, value: &str) -> ! {
    panic!("corrupt local state: unknown persisted {kind} value {value:?}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationState {
    Hydrated,
    Placeholder,
    Hydrating,
    Evicting,
}

impl MaterializationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Hydrated => "hydrated",
            Self::Placeholder => "placeholder",
            Self::Hydrating => "hydrating",
            Self::Evicting => "evicting",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "hydrated" => Self::Hydrated,
            "placeholder" => Self::Placeholder,
            "hydrating" => Self::Hydrating,
            "evicting" => Self::Evicting,
            other => unknown_persisted_enum("materialization state", other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationPolicy {
    Eager,
    OnDemand,
}

impl MaterializationPolicy {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::OnDemand => "ondemand",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "eager" => Self::Eager,
            "ondemand" => Self::OnDemand,
            other => unknown_persisted_enum("materialization policy", other),
        }
    }
}

/// Whether a folder group's link currently accepts peer-applied writes at
/// all. No permissive default: a caller that wants to write must match
/// [`LinkGate::Live`] and thereby prove a live link exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGate {
    /// A live, unpaused, non-orphaned link. `local_path` is the root the
    /// apply must write under.
    Live { local_path: String, policy: MaterializationPolicy },
    /// A live link the user paused. Pause stops both directions, but is
    /// reversible and leaves the link -- and its root -- in place.
    Paused { local_path: String },
    /// No live link for this group on this device: never linked, unlinked,
    /// or orphaned. The apply must not touch the filesystem.
    NoLiveLink,
}

/// Which of a path's retained rows this one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionState {
    /// The live version of the file at this path right now (or, if the
    /// file is deleted, the tombstone itself).
    Current,
    /// A version this file had before a later edit (local or adopted)
    /// superseded it.
    Superseded,
    /// The file's last live content before it was deleted — recoverable
    /// via `trash restore` until retention expires.
    Trashed,
}

impl VersionState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            VersionState::Current => "current",
            VersionState::Superseded => "superseded",
            VersionState::Trashed => "trashed",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "superseded" => VersionState::Superseded,
            "trashed" => VersionState::Trashed,
            _ => VersionState::Current,
        }
    }
}

/// One retained version of a file, as returned by `SyncState::list_versions`/
/// `SyncState::get_version` — the CLI's `yadorilink versions <path>` and the
/// restore engine's per-version lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionRecord {
    pub path: String,
    pub version_seq: i64,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
    pub state: VersionState,
    pub origin_device_id: Option<String>,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    pub version_hash: VersionHash,
}

/// Why a path is held (excluded from materialization-state transitions)
/// and since when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldState {
    pub reason: String,
    pub since_unix_nanos: i64,
}

/// The `state = 'current'` row of a file, read as one atomic statement --
/// every column a `FileVersion` identity binds, from a single coherent row
/// so the derived `change::VersionHash` can never be a torn hybrid of two
/// rows.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentVersionRecord {
    pub blocks: Vec<BlockInfo>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub deleted: bool,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

impl CurrentVersionRecord {
    /// Reconstructs the exact `FileVersion` this current row describes and
    /// derives its `change::VersionHash` via `FileVersion::compute_hash()`.
    /// Because every field came from one atomic read, the returned identity
    /// is always one a single row actually held.
    pub fn to_file_version(&self) -> FileVersion {
        FileVersion::from_index_row(
            self.blocks.clone(),
            self.size,
            self.mtime_unix_nanos,
            self.record_kind,
            self.unix_mode,
            self.symlink_target.clone(),
            self.xattrs.clone(),
        )
    }
}

/// Returned when a group's latest startup ended in `Failed`. Peer-apply
/// callers must treat this as "do NOT admit the change" (defer / skip),
/// never as permission to apply against the half-built index a failed
/// startup left behind.
#[derive(Clone, Debug)]
pub struct StartupFailed {
    pub group_id: String,
    pub reason: String,
}

impl std::fmt::Display for StartupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group {} startup did not complete: {}", self.group_id, self.reason)
    }
}

impl std::error::Error for StartupFailed {}

/// The result of one retroactive-conflict repair attempt against one SQLite
/// snapshot. The caller (the daemon's repair loop) needs this three-way
/// distinction, not just success/failure, to decide whether
/// `committed_frontier` is safe to cache: caching it suppresses
/// re-examining this exact frontier until a new head arrives, which is
/// correct for `NothingToDo` and `PermanentlyBlocked` (both describe a
/// frontier that produces the same result every time it's re-examined) but
/// would be wrong for an ordinary transient `Err` (a database error
/// unrelated to this frontier's own content, which deserves an
/// unconditional retry on the very next poll). Moved out of
/// `yadorilink-sync-core` (Phase 7D-10): pure data (no SQL, no `SyncState`
/// coupling), needed identically by `yadorilink-sync-core`'s own
/// `SyncState::repair_retroactive_conflict_copy_obligations` and
/// `yadorilink-daemon`'s independently-written
/// `ReplicaCoordinator::repair_retroactive_conflict_copy_obligations` --
/// hoisting here (rather than duplicating) keeps exactly one definition.
#[derive(Debug)]
pub enum RetroactiveRepairOutcome {
    /// Authored and committed a merge-resolution carrier for these paths.
    Repaired { repaired_paths: Vec<String>, committed_frontier: Vec<ChangeHash> },
    /// This device is not elected for any currently-eligible path, or every
    /// eligible path was already repaired.
    NothingToDo { committed_frontier: Vec<ChangeHash> },
    /// `path` has an eligible obligation, but it alone exceeds the bounded
    /// change size and splitting one path's obligation across multiple
    /// carriers is not implemented -- retrying against this exact frontier
    /// can only ever reproduce this same result.
    PermanentlyBlocked { path: String, committed_frontier: Vec<ChangeHash> },
    /// A repair exists, but this device's deterministic rank has not reached
    /// the driver's current failover threshold (or it is not authorized).
    AwaitingFailover { local_rank: Option<usize>, committed_frontier: Vec<ChangeHash> },
}

/// The DAG-facing content of a local edit: the ops to sign into the emitted
/// `Change`, and the `FileVersion`s those ops reference (written to
/// `file_versions` in the same transaction as the change/index update).
/// Moved out of `yadorilink-sync-core`'s `state_model`, alongside
/// `file_index.rs`'s move into
/// `yadorilink-sync-sqlite` -- pure data, no SQL, needed by both that
/// module and `yadorilink-sync-core`'s own local-authoring code that stays
/// behind.
pub struct ChangeContent<'a> {
    pub ops: Vec<Op>,
    pub versions: &'a [FileVersion],
}

/// One path's fully-prepared local mutation for a bounded batched commit
/// (`commit_local_mutations_batch`) — content already read, chunked, and
/// hashed; the `FileRecord`/`Op`/`FileVersion`/metadata it will become
/// already decided; not yet written anywhere. Deliberately minimal: no
/// lock, no disk fingerprint, no staleness bookkeeping — those require a
/// filesystem/tokio dependency this crate does not have, so
/// `yadorilink-local-capture` (which prepares these and knows the caller's
/// per-path lock) owns that half, revalidating a mutation is still current
/// before including it in a batch. Each variant still becomes its own
/// signed DAG `Change` when committed — a batch of N of these must never
/// collapse into one multi-op `Change` (that changes causal/apply
/// granularity for what were N independent local edits).
#[derive(Debug)]
pub enum PreparedLocalMutation {
    Upsert {
        record: FileRecord,
        op: Op,
        version: FileVersion,
        meta: Option<LocalFileMetaColumns>,
    },
    Delete {
        record: FileRecord,
        op: Op,
    },
}

impl PreparedLocalMutation {
    pub fn record(&self) -> &FileRecord {
        match self {
            PreparedLocalMutation::Upsert { record, .. } => record,
            PreparedLocalMutation::Delete { record, .. } => record,
        }
    }
}

/// The local-only per-file metadata columns a local content emission writes
/// alongside its `FileRecord`. Folded into the emitting transaction (rather
/// than applied as separate post-commit `set_record_kind`/`set_symlink_*`/
/// `set_unix_mode` updates) so the materialized index row can never lag the
/// `FileVersion` the emitted change carries across a crash between the
/// commit and the setters. The kind/target/exec-bit values mirror exactly
/// the [`crate::file::FileMeta`] the emitted `FileVersion` carries;
/// `symlink_out_of_root` is an additional purely-local classification
/// never sent on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileMetaColumns {
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub unix_mode: Option<u32>,
    /// See `FileMeta::xattrs`'s own doc comment -- already sorted by
    /// name and filtered to the capture-side allow-list by the caller.
    pub xattrs: Vec<(String, Vec<u8>)>,
}

/// One user-recoverable durability root — one retained version at `path`
/// (current, superseded, or trashed) a full-replica handoff must be able to
/// hand off. `version_hash` is the [`crate::change::VersionHash`] — the
/// SHA-256 of this version's canonical `FileVersion` encoding (its ordered
/// block list with each block's size, its total size, and its metadata:
/// mtime, exec bit, symlink target, record kind) — computed by
/// reconstructing a `FileVersion` from this row via
/// [`FileVersion::from_index_row`] and calling `compute_hash()`. This is
/// the SAME hash the change-DAG itself uses to identify a version;
/// durability never invents a separate wire identifier. `blocks` is
/// carried alongside (not folded away once the hash is known) because a
/// peer confirmation still needs the ordered block list — with per-block
/// sizes — for its own explicit block/size check and its `get()`
/// checksum-verification loop. See
/// `SyncState::enumerate_group_durability_roots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoot {
    pub path: String,
    pub blocks: Vec<VersionBlock>,
    pub version_hash: VersionHash,
}

/// The result of `SyncState::enumerate_group_durability_roots`: the full
/// root set plus a stable digest over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoots {
    pub roots: Vec<DurabilityRoot>,
    /// SHA-256 over the roots sorted by `(path, version_hash)`. Stable
    /// regardless of the order SQL returns rows in, so two enumerations of
    /// the same underlying set produce the same digest. `version_hash`
    /// binds the ordered block list, each block's size, and the version's
    /// metadata, so a chunk reorder or a metadata-only change (mtime, exec
    /// bit, symlink target, record kind) changes the digest exactly as it
    /// changes the version identity a peer confirms against. See
    /// `yadorilink_sync_sqlite::file_index::durability_roots_digest`.
    pub digest: [u8; 32],
}

/// What `SyncState::backfill_materialized_generations` did, broken down by
/// exactly why each skipped row was skipped — see that method's doc for
/// what each category means. Every current row for the group falls into
/// exactly one of these four buckets, so summing all four fields gives the
/// group's total current-row count at the time of the call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaterializedGenerationBackfillReport {
    pub populated: u64,
    pub skipped_no_authoring_hash: u64,
    pub skipped_not_confirmed_materialized: u64,
    pub skipped_deleted_tombstones: u64,
}

/// spec "CLI Trash Commands": one deleted-but-still-recoverable file, as
/// returned by `SyncState::list_trashed`.
#[derive(Debug, Clone, PartialEq)]
pub struct TrashedFile {
    pub path: String,
    /// The `version_seq` of the retained last-live-content row — what
    /// `trash restore` restores to by default.
    pub version_seq: i64,
    pub last_known_size: u64,
    pub origin_device_id: Option<String>,
    /// When the deletion itself (the tombstone's own `current` row) was
    /// recorded.
    pub deleted_at_unix_nanos: i64,
}

/// One currently-live conflicted-copy file, as returned by
/// `SyncState::list_live_conflict_copies` — the single source of truth
/// both `FileHistoryQueryService::list_conflicts` and
/// `LinkStatusReadPort::list_links`'s `conflict_count` read from, so the
/// two can never disagree about which paths count.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictCopyFile {
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
}

/// One journaled local edit awaiting durable processing into the index +
/// change DAG — see the `local_dirty_paths` table. `change_kind` is the
/// serialized `yadorilink-sync-core::watcher::FsChangeKind`
/// (`"created_or_modified"` / `"removed"`) of the most recent watcher event
/// for the path, and `observed_at_unix_nanos` its observation time, so a
/// startup/retry re-drive can reconstruct the exact `FsChangeEvent` the
/// debounce executor would have processed. Moved out of
/// `yadorilink-sync-core`'s `state_model` in Phase 7D-8.2 -- a plain
/// struct, zero SQL/fs dependency, the same move shape 7D-7.6 already
/// applied to `ChangeContent`/`DurabilityRoot`/`DurabilityRoots`/
/// `LocalFileMetaColumns`/`MaterializedGenerationBackfillReport`/
/// `TrashedFile` above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyPath {
    pub path: String,
    pub change_kind: String,
    pub observed_at_unix_nanos: i64,
    pub attempts: u32,
}

// The following types moved out of `yadorilink-sync-core::state_model`
// (Phase 7D-9E, third pass): `FolderLink`, `RoleLossOperationParams`, the
// `RoleLossOperation` cluster, and the `MembershipOperation` cluster are
// plain persisted value types with no `SyncState`/SQL dependency of their
// own. At the time of this move, their sibling `PendingEnrollment`/
// `EnrollmentOperation` cluster stayed behind in `state_model.rs`/`types.rs`
// (tightly coupled to `crate::types::EnrollmentKind`, then still local to
// `yadorilink-sync-core`) and `InventoryScanResult<T>` also stayed (it
// depends on `crate::recovery::InvalidRecoveryOperation`, itself still
// pending). Both of those blockers were later resolved -- see the
// `EnrollmentKind`/`PendingEnrollment`/`EnrollmentOperation` cluster's own
// move note further down this file (Phase 7D-9F, ninth pass) and
// `recovery.rs`'s `InvalidRecoveryOperation`/`RecoveryDomain` move (Phase
// 7D-9F, eighth pass).
// Re-exported at the matching `state_model`/`index` path in
// `yadorilink-sync-core` so every existing caller (`yadorilink-daemon`'s
// persistence/application layers, `yadorilink-sync-core`'s own
// `recovery.rs`) keeps resolving unchanged.

/// The fields of a role-loss operation row not already carried by its
/// `(operation_id, group_id)` key.
pub struct RoleLossOperationParams<'a> {
    pub source_device_id: &'a str,
    pub target_device_id: &'a str,
    pub lease_id: Option<&'a str>,
    pub action: RoleLossAction,
    pub local_path: Option<&'a str>,
    pub now_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderLink {
    pub local_path: String,
    pub group_id: String,
    pub paused: bool,
    pub materialization_policy: MaterializationPolicy,
    /// Automatic-eviction disk-usage cap in bytes, if configured.
    pub max_local_size_bytes: Option<i64>,
    /// Whether this link's coordination-side authorization has been
    /// confirmed permanently gone (its group/ACL row was cancelled or
    /// removed server-side) -- distinct from `paused`, which is a
    /// reversible, user-chosen sync gate that leaves the coordination-side
    /// authorization intact. Set only once reconciliation confirms the
    /// activation for this link's [`PendingEnrollment`] came back `Deleted`
    /// -- see [`SyncState::mark_link_orphaned`]. An orphaned link's on-disk
    /// files are never touched or deleted; only its participation in sync
    /// stops.
    pub orphaned: bool,
}

/// A durable journal row for an in-flight full-replica role-loss operation
/// (demote/unlink) this device is driving as the SOURCE device. Written
/// before the coordination-worker role-loss commit
/// (`coordination_client::commit_handoff_role_loss`) and only removed once
/// the operation's outcome is fully settled, so a crash — or a local
/// failure landing AFTER the Worker commit already succeeded — is always
/// reconciled automatically instead of left as a silent split state (Worker
/// thinks this device demoted; local storage still thinks it's eager).
///
/// State machine:
///
/// ```text
/// Prepared ──(Worker returns definite 4xx rejection)──> [row deleted]
///     │
///     │ (Worker commit succeeds OR response is ambiguous/lost)
///     v
/// WorkerCommitted/Prepared ──(local commit succeeds)──> LocalCommitted ──> [row deleted]
///     │
///     │ (local commit fails: digest mismatch or a storage error)
///     v
/// Compensating ──(Worker revert succeeds)──> Completed ──> [row deleted]
///     │
///     │ (Worker revert fails / unreachable)
///     v
/// Compensating (retried by the reconciliation sweep, never abandoned)
/// ```
///
/// `LocalCommitted` and `Completed` are terminal and are deleted
/// immediately after being written on the normal path; they only persist
/// across a restart if the process crashed in the narrow window between
/// that write and the follow-up delete, in which case the reconciliation
/// sweep's own handling of them is a plain delete (see that sweep's doc
/// comment) — the operation's real outcome was already reached by the
/// preceding write.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleLossOperation {
    pub operation_id: String,
    pub group_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub lease_id: Option<String>,
    pub worker_membership_generation: Option<i64>,
    pub action: RoleLossAction,
    pub state: RoleLossOperationState,
    /// The local link path this operation concerns, when known (unlink
    /// always has one; demote does too, since it also flips a specific
    /// link's materialization policy).
    pub local_path: Option<String>,
    pub attempts: i64,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Which local operation this device was performing when it drove the
/// Worker-side role-loss commit — recorded for diagnosis/logging.
/// `commit_handoff_role_loss`'s Worker-side statement is `"demote"` for
/// both `Demote` and `Unlink` today (both only narrow this device's
/// `storage_mode` to on-demand; unlink does not remove group membership),
/// so both compensate identically — reverting `storage_mode` back to
/// `eager` — see `daemon_state::compensate_role_loss_operation`. `Revoke`
/// is reserved for `durability_force`'s cross-device removal path, which
/// this change does not wire to this journal (that path still uses the
/// pre-existing plain `/revoke` call, not `commit_handoff_role_loss`); a
/// row is never written with this action today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossAction {
    Demote,
    Unlink,
    Revoke,
}

impl RoleLossAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossAction::Demote => "demote",
            RoleLossAction::Unlink => "unlink",
            RoleLossAction::Revoke => "revoke",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "unlink" => RoleLossAction::Unlink,
            "revoke" => RoleLossAction::Revoke,
            _ => RoleLossAction::Demote,
        }
    }

    /// Strict counterpart to [`Self::from_db_str`] -- that lenient parse
    /// silently coerces any unrecognized string to `Demote`, which is the
    /// right fail-safe default for the reconciliation sweep (an unrecognized
    /// action must still be treated as SOME action rather than crash the
    /// sweep) but the wrong behavior for a read-only inventory, which must
    /// surface a genuinely corrupt row as `invalid` rather than silently
    /// misreport it as a `Demote` it never was.
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "demote" => Ok(RoleLossAction::Demote),
            "unlink" => Ok(RoleLossAction::Unlink),
            "revoke" => Ok(RoleLossAction::Revoke),
            other => Err(format!("unknown role-loss action: {other}")),
        }
    }
}

/// Which state a [`RoleLossOperation`] is in — see its doc comment for the
/// full state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossOperationState {
    /// Journal row written; the coordination-worker role-loss commit has
    /// not yet been attempted (or its outcome is not yet known to this
    /// process — e.g. a crash mid-request). The reconciliation sweep
    /// treats a `Prepared` row found at startup the same as
    /// `WorkerCommitted`: it cannot locally distinguish "the request never
    /// reached the Worker" from "it reached and committed but the reply
    /// was lost", and asserting `eager` on the Worker is safe either way
    /// (a no-op if the Worker never committed, a correcting revert if it
    /// did) — see that sweep's doc comment.
    Prepared,
    /// The coordination-worker role-loss commit succeeded; the matching
    /// local policy/link change has not yet been attempted (or its outcome
    /// is not yet known — the crash-between-Worker-commit-and-local-commit
    /// case the whole journal exists for).
    WorkerCommitted,
    /// The local policy/link change also succeeded — the operation
    /// completed normally. Terminal; the row is deleted immediately after
    /// this state is written.
    LocalCommitted,
    /// The local change failed (digest mismatch or a storage error) after
    /// the Worker commit already succeeded; a compensating revert (Worker
    /// `storage_mode` back to `eager`) is in flight or pending retry.
    /// Never abandoned: the reconciliation sweep retries a `Compensating`
    /// row indefinitely until the revert is confirmed.
    Compensating,
    /// The compensating revert succeeded — the split state was corrected
    /// and the source device is confirmed `eager` again, both locally and
    /// on the Worker. Terminal; the row is deleted immediately after this
    /// state is written.
    Completed,
}

impl RoleLossOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossOperationState::Prepared => "prepared",
            RoleLossOperationState::WorkerCommitted => "worker_committed",
            RoleLossOperationState::LocalCommitted => "local_committed",
            RoleLossOperationState::Compensating => "compensating",
            RoleLossOperationState::Completed => "completed",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "worker_committed" => RoleLossOperationState::WorkerCommitted,
            "local_committed" => RoleLossOperationState::LocalCommitted,
            "compensating" => RoleLossOperationState::Compensating,
            "completed" => RoleLossOperationState::Completed,
            _ => RoleLossOperationState::Prepared,
        }
    }

    /// Strict counterpart to [`Self::from_db_str`] -- see
    /// [`RoleLossAction::try_from_db_str`]'s doc comment for why the lenient
    /// parse's silent-default behavior is wrong for a read-only inventory.
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "prepared" => Ok(RoleLossOperationState::Prepared),
            "worker_committed" => Ok(RoleLossOperationState::WorkerCommitted),
            "local_committed" => Ok(RoleLossOperationState::LocalCommitted),
            "compensating" => Ok(RoleLossOperationState::Compensating),
            "completed" => Ok(RoleLossOperationState::Completed),
            other => Err(format!("unknown role-loss operation state: {other}")),
        }
    }
}

/// A durable journal row for an account-membership operation this device
/// drives against ANOTHER device (revoke from one group, or remove from the
/// whole account) — see the `membership_operations` table's own migration
/// comment for the full rationale. One row can span several groups at once
/// (account-wide removal), unlike [`RoleLossOperation`]; `group_ids`,
/// `target_device_ids`, and `lease_ids` are index-parallel.
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipOperation {
    pub operation_id: String,
    pub action: MembershipOperationAction,
    pub commit_mode: MembershipCommitMode,
    pub removed_device_id: String,
    pub group_ids: Vec<String>,
    pub target_device_ids: Vec<String>,
    pub lease_ids: Vec<Option<String>>,
    pub state: MembershipOperationState,
    /// Whether the set of folder groups this operation puts at risk is
    /// known -- separate from `state` (which tracks only the REMOTE
    /// mutation's own outcome). A `--force` removal whose eager-group
    /// enumeration failed is `Unknown` regardless of what its remote
    /// mutation is currently doing (`Prepared`, `Ambiguous`, ...); an
    /// ordinary ticket-bound or plain mutation is always `Known`. See the
    /// review this separation implements: "Remote outcomeとdurability
    /// scopeは別概念として扱います".
    pub durability_scope: MembershipDurabilityScope,
    /// Folder groups to latch [`GroupDurabilityStatus::Unknown`]
    /// once (and only once) this operation's remote mutation is CONFIRMED
    /// committed -- never latched pre-commit, so a definitely-rejected or
    /// conflicting mutation never leaves a false-positive latch behind.
    /// Empty for every mode except a `--force` plain revoke/remove that
    /// proceeded past a KNOWN but unready set of groups (unrelated to
    /// `durability_scope`, which tracks the separate "the group LIST itself
    /// is unknown" case).
    pub latch_group_ids: Vec<String>,
    pub last_error: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperationAction {
    Revoke,
    RemoveDevice,
}

impl MembershipOperationAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipOperationAction::Revoke => "revoke",
            MembershipOperationAction::RemoveDevice => "remove-device",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "revoke" => Ok(MembershipOperationAction::Revoke),
            "remove-device" => Ok(MembershipOperationAction::RemoveDevice),
            other => Err(format!("unknown membership operation action: {other}")),
        }
    }
}

/// Which remote request shape a [`MembershipOperation`] row's commit
/// actually sends -- distinct from `action` (which side of membership
/// changed) because the SAME action can be driven two different ways
/// (e.g. `Revoke` via a plain unguarded call or via a ticket/lease-guarded
/// one). A reconciler that needs to resend the original request (see
/// `membership_operations`' own migration comment on the Worker side)
/// needs this to know which endpoint/body shape to reconstruct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipCommitMode {
    /// `POST /shares/groups/:groupId/revoke` -- no ticket/lease.
    PlainRevoke,
    /// `POST /shares/groups/:groupId/handoff/commit` (action `"revoke"`) --
    /// ticket/lease-guarded, single group.
    GuardedRevoke,
    /// `DELETE /devices/:deviceId` -- no ticket/lease, no group list
    /// (unverified or verified-empty scope).
    PlainRemoveDevice,
    /// `POST /devices/:deviceId/handoff-remove` -- one ticket/lease per
    /// group, all-or-nothing.
    HandoffRemoveDevice,
}

impl MembershipCommitMode {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipCommitMode::PlainRevoke => "plain-revoke",
            MembershipCommitMode::GuardedRevoke => "guarded-revoke",
            MembershipCommitMode::PlainRemoveDevice => "plain-remove-device",
            MembershipCommitMode::HandoffRemoveDevice => "handoff-remove-device",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "plain-revoke" => Ok(MembershipCommitMode::PlainRevoke),
            "guarded-revoke" => Ok(MembershipCommitMode::GuardedRevoke),
            "plain-remove-device" => Ok(MembershipCommitMode::PlainRemoveDevice),
            "handoff-remove-device" => Ok(MembershipCommitMode::HandoffRemoveDevice),
            other => Err(format!("unknown membership commit mode: {other}")),
        }
    }
}

/// Whether the blast radius (which folder groups) a [`MembershipOperation`]
/// puts at risk is known. See [`MembershipOperation::durability_scope`]'s
/// own doc comment for why this is tracked separately from `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipDurabilityScope {
    Known,
    Unknown,
}

impl MembershipDurabilityScope {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipDurabilityScope::Known => "known",
            MembershipDurabilityScope::Unknown => "unknown",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "known" => Ok(MembershipDurabilityScope::Known),
            "unknown" => Ok(MembershipDurabilityScope::Unknown),
            other => Err(format!("unknown membership durability scope: {other}")),
        }
    }
}

/// Which state a [`MembershipOperation`]'s REMOTE mutation is in -- see
/// [`MembershipOperation::durability_scope`] for the separate blast-radius
/// axis.
///
/// ```text
/// Prepared ── (commit outcome could not be confirmed) ──> Ambiguous
///     │                                                        │
///     │                                     (a later lookup/resend resolves it)
///     v                                                        v
/// Committed, but a post-commit local            Completed / DefinitelyRejected
/// step (e.g. a force latch) failed:                    (row deleted)
///     v
/// LocalSettlementPending ── (retried by the next sweep) ──> Completed
///
/// A local/remote request-identity mismatch, a malformed journal row, or an
/// operation_id conflict moves a row to RecoveryBlocked instead of any of
/// the above -- never settled automatically, always left for operator
/// attention.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperationState {
    /// The journal row has been durably written; the coordination-plane
    /// commit itself has not yet been attempted (or its outcome is not yet
    /// known to this process — e.g. a crash mid-request). Written BEFORE
    /// the commit call, so a crash between "Worker received the commit" and
    /// "daemon advances this row" still leaves a `Prepared` row behind
    /// rather than nothing at all — mirrors
    /// [`RoleLossOperationState::Prepared`]'s own reasoning exactly.
    Prepared,
    /// The coordination-plane commit's outcome could not be confirmed
    /// (transport failure, 5xx, or an unparseable success body) — it may
    /// already have committed. Tickets stay held and the caller must not
    /// fall through to a plain revoke/remove until this is resolved.
    Ambiguous,
    /// The remote mutation is confirmed committed, but a REQUIRED local
    /// follow-up (e.g. latching a forced group's durability as unknown)
    /// failed and must be retried -- the row must not be discarded until
    /// that local step also succeeds.
    LocalSettlementPending,
    /// The operation is confirmed to have completed on the coordination
    /// plane. Terminal; the row is deleted once observed.
    Completed,
    /// The operation is confirmed to have been rejected before any commit
    /// happened. Terminal; the row is deleted once observed.
    DefinitelyRejected,
    /// Automatic recovery has been refused: an operation_id conflict, a
    /// local/remote request-identity mismatch, or a malformed journal row.
    /// Excluded from periodic resend/settlement; requires operator
    /// attention to clear.
    RecoveryBlocked,
}

impl MembershipOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipOperationState::Prepared => "prepared",
            MembershipOperationState::Ambiguous => "ambiguous",
            MembershipOperationState::LocalSettlementPending => "local-settlement-pending",
            MembershipOperationState::Completed => "completed",
            MembershipOperationState::DefinitelyRejected => "definitely_rejected",
            MembershipOperationState::RecoveryBlocked => "recovery-blocked",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "prepared" => Ok(MembershipOperationState::Prepared),
            "ambiguous" => Ok(MembershipOperationState::Ambiguous),
            "local-settlement-pending" => Ok(MembershipOperationState::LocalSettlementPending),
            "completed" => Ok(MembershipOperationState::Completed),
            "definitely_rejected" => Ok(MembershipOperationState::DefinitelyRejected),
            "recovery-blocked" => Ok(MembershipOperationState::RecoveryBlocked),
            other => Err(format!("unknown membership operation state: {other}")),
        }
    }
}

/// A `membership_operations` row whose contents could not be decoded --
/// e.g. an unrecognized enum string, or a group/target/lease shape that
/// doesn't match its `commit_mode`. Carries just enough to let the caller
/// mark it `RecoveryBlocked` without ever having successfully parsed it.
#[derive(Debug, Clone)]
pub struct InvalidMembershipOperation {
    pub operation_id: String,
    /// See [`InvalidEnrollmentOperation::raw_state`]'s doc comment.
    pub raw_state: Option<String>,
    pub detail: String,
}

/// The result of scanning `membership_operations` for a set of states: rows
/// that decoded successfully, and rows that didn't -- kept separate so ONE
/// malformed row can never abort recovery for every other, valid row in the
/// same sweep. See [`SyncState::scan_membership_operations_in_states`].
#[derive(Debug, Clone, Default)]
pub struct MembershipOperationScan {
    pub valid: Vec<MembershipOperation>,
    pub invalid: Vec<InvalidMembershipOperation>,
}

// The `PendingEnrollment`/`EnrollmentOperation` cluster below moved out of
// `yadorilink-sync-core::state_model`/`types` (Phase 7D-9F, ninth pass),
// mirroring the `RoleLossOperation`/`MembershipOperation` clusters' own move
// above (7D-9E, third pass). Both of this cluster's original blockers are
// gone: `crate::recovery::InvalidRecoveryOperation`/`RecoveryDomain` moved
// here first (7D-9F, eighth pass), and `EnrollmentKind` itself has no
// dependency of its own on anything still left in `yadorilink-sync-core` --
// its "coupled to this crate's own DB string representation" reasoning
// applied equally to `RoleLossAction`/`MembershipOperationAction`, which
// already moved, so it did not justify staying behind on its own. Re-exported
// at the matching `state_model`/`types`/`index` path in `yadorilink-sync-core`
// so every existing caller (`yadorilink-daemon`'s application/persistence
// layers, `yadorilink-sync-core`'s own `repository`/`recovery` modules) keeps
// resolving unchanged.

/// Which local action opened a `pending_enrollments`/`enrollment_operations`
/// row -- a brand-new folder group (`Create`) or joining one an invitation
/// named (`Join`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentKind {
    Create,
    Join,
}

impl EnrollmentKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Join => "join",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "create" => Self::Create,
            "join" => Self::Join,
            other => unknown_persisted_enum("enrollment kind", other),
        }
    }

    /// Same mapping as [`Self::from_db_str`], but returns `Err` instead of
    /// panicking -- for a caller (the `enrollment_operations` journal) that
    /// must isolate one malformed row to `RecoveryBlocked` rather than
    /// crashing the whole reconciliation sweep on it.
    pub fn try_from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "create" => Ok(Self::Create),
            "join" => Ok(Self::Join),
            other => Err(format!("unknown enrollment kind: {other}")),
        }
    }
}

/// One outstanding local link with an unconfirmed coordination-plane
/// activation -- the crash-safety net for a create/join whose local link
/// is already committed but whose matching server-side activation was
/// never confirmed (the caller was killed in that exact window). Persisted
/// in the same SQLite database as `FolderLink` so the two can be written in
/// a single transaction (`SyncState::add_link_with_pending_enrollment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub operation_id: String,
    pub kind: EnrollmentKind,
    pub group_id: String,
    pub device_id: String,
    pub local_path: String,
}

/// A `pending_enrollments` row whose contents could not be decoded (an
/// unrecognized `kind` string) -- mirrors [`InvalidEnrollmentOperation`].
#[derive(Debug, Clone)]
pub struct InvalidPendingEnrollment {
    pub operation_id: String,
    pub detail: String,
}

/// The result of scanning `pending_enrollments`: rows that decoded
/// successfully, and rows that didn't -- mirrors [`EnrollmentOperationScan`]
/// so one malformed marker can never abort reconciliation for every other
/// marker in the same sweep.
#[derive(Debug, Clone, Default)]
pub struct PendingEnrollmentScan {
    pub valid: Vec<PendingEnrollment>,
    pub invalid: Vec<InvalidPendingEnrollment>,
}

/// The durable pre-prepare enrollment journal -- opened BEFORE the first
/// coordination-plane prepare call and carrying enough request identity to
/// replay prepare or cancel safely, not just a late `CancelPending`
/// backstop for a `link()` failure. See `enrollment_operations`' own
/// migration comment for the full state-machine rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentOperation {
    pub operation_id: String,
    pub kind: EnrollmentKind,
    /// `None` until coordination prepare confirms one (only possible for a
    /// `Create` row still in `PreparePending`; a `Join` row always has one
    /// from the moment its journal row is opened).
    pub group_id: Option<String>,
    /// Only meaningful for a `Create` row in `PreparePending` -- needed to
    /// resend the exact same prepare request. Always `None` for `Join`.
    pub group_name: Option<String>,
    pub device_id: String,
    pub local_path: String,
    /// `"eager"` or `"on-demand"`.
    pub storage_mode: String,
    pub state: EnrollmentOperationState,
    pub last_error: Option<String>,
    pub attempts: i64,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Which stage of the create/join enrollment saga a journal row is in.
///
/// ```text
/// PreparePending ── (prepare confirmed) ──> Prepared
///     │                                         │
///     │                        (link + pending_enrollment commit atomically)
///     │                                         v
///     │                                LocalSetupPending ── (setup confirmed) ──> ActivationPending
///     │                                         │                                        │
///     │                              (setup failed, rolled back)                (activation reconciler
///     │                                         v                                  owns this row now)
///     │                                    CancelPending                                  │
///     │                                         ^                                         │
///     │                                         └──────────── (link/marker lost) ─────────┘
///     │                                                                                    │
///     │                                                                          (row cleanup) ──> (deleted)
///     │
///     └─ (no local link exists) ──> CancelPending ── (cancel confirmed) ──> (deleted)
///
/// A malformed row, an operation_id conflict, or a local/remote identity
/// mismatch moves a row to RecoveryBlocked instead of any of the above --
/// never settled automatically, always left for operator attention.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentOperationState {
    /// Written before the first coordination prepare call.
    PreparePending,
    /// Coordination prepare is confirmed; `group_id` is known. No local
    /// link handoff has been confirmed yet.
    Prepared,
    /// The local link + `pending_enrollments` marker were committed
    /// atomically, but the fallible post-commit setup (watcher
    /// registration, on-demand materialization config) has not yet been
    /// confirmed. Remote activation must NEVER be attempted while a row is
    /// in this state -- see `EnrollmentOperationState`'s own module-level
    /// doc for the phantom-full-replica race this state exists to close.
    LocalSetupPending,
    /// Local setup is confirmed complete; remote activation may now be
    /// attempted. Responsibility has moved to `pending_enrollments`.
    ActivationPending,
    /// The local link was not committed (or a committed setup was rolled
    /// back); the remote Pending authorization must be cancelled.
    CancelPending,
    /// Automatic recovery is forbidden.
    RecoveryBlocked,
}

impl EnrollmentOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            EnrollmentOperationState::PreparePending => "prepare_pending",
            EnrollmentOperationState::Prepared => "prepared",
            EnrollmentOperationState::LocalSetupPending => "local_setup_pending",
            EnrollmentOperationState::ActivationPending => "activation_pending",
            EnrollmentOperationState::CancelPending => "cancel_pending",
            EnrollmentOperationState::RecoveryBlocked => "recovery_blocked",
        }
    }

    pub fn try_from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "prepare_pending" => Ok(EnrollmentOperationState::PreparePending),
            "prepared" => Ok(EnrollmentOperationState::Prepared),
            "local_setup_pending" => Ok(EnrollmentOperationState::LocalSetupPending),
            "activation_pending" => Ok(EnrollmentOperationState::ActivationPending),
            "cancel_pending" => Ok(EnrollmentOperationState::CancelPending),
            "recovery_blocked" => Ok(EnrollmentOperationState::RecoveryBlocked),
            other => Err(format!("unknown enrollment operation state: {other}")),
        }
    }
}

/// An `enrollment_operations` row whose contents could not be decoded (an
/// unrecognized enum string, or a shape that doesn't match its own `kind`/
/// `state`) -- mirrors [`InvalidMembershipOperation`].
#[derive(Debug, Clone)]
pub struct InvalidEnrollmentOperation {
    pub operation_id: String,
    /// The raw, un-decoded `state` column value, when the row itself could
    /// still be read (`None` only if reading the column itself failed).
    /// Diagnostic-only -- lets `recovery show` display the exact persisted
    /// state of a forward-version or corrupt row instead of just `detail`'s
    /// prose.
    pub raw_state: Option<String>,
    pub detail: String,
}

/// The result of scanning `enrollment_operations`: rows that decoded
/// successfully, and rows that didn't -- mirrors [`MembershipOperationScan`]
/// so one malformed row can never abort recovery for every other row in the
/// same sweep.
#[derive(Debug, Clone, Default)]
pub struct EnrollmentOperationScan {
    pub valid: Vec<EnrollmentOperation>,
    pub invalid: Vec<InvalidEnrollmentOperation>,
}

#[cfg(test)]
mod tests {
    use super::{EnrollmentKind, MaterializationPolicy, MaterializationState};
    use crate::file::RecordKind;

    #[test]
    fn persisted_enum_values_are_exact() {
        assert_eq!(EnrollmentKind::from_db_str("create"), EnrollmentKind::Create);
        assert_eq!(EnrollmentKind::from_db_str("join"), EnrollmentKind::Join);
        assert_eq!(MaterializationState::from_db_str("hydrated"), MaterializationState::Hydrated);
        assert_eq!(
            MaterializationState::from_db_str("placeholder"),
            MaterializationState::Placeholder
        );
        assert_eq!(MaterializationPolicy::from_db_str("eager"), MaterializationPolicy::Eager);
        assert_eq!(MaterializationPolicy::from_db_str("ondemand"), MaterializationPolicy::OnDemand);
        assert_eq!(RecordKind::from_db_str("file"), RecordKind::File);
    }

    #[test]
    #[should_panic(expected = "unknown persisted materialization state")]
    fn unknown_materialization_state_is_not_coerced() {
        let _ = MaterializationState::from_db_str("future-state");
    }

    #[test]
    #[should_panic(expected = "unknown persisted materialization policy")]
    fn unknown_materialization_policy_is_not_coerced() {
        let _ = MaterializationPolicy::from_db_str("future-policy");
    }

    #[test]
    #[should_panic(expected = "unknown persisted enrollment kind")]
    fn unknown_enrollment_kind_is_not_coerced() {
        let _ = EnrollmentKind::from_db_str("future-kind");
    }
}
