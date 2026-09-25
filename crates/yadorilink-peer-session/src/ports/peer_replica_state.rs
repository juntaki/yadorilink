//! The types the replica-state operations exchange: row snapshots, the
//! exact state a materialization commits, the guard a version-bound writer
//! commits under, and the prepared projected mutations. The operations
//! themselves live on the daemon's `ReplicaCoordinator`.

use crate::error::PeerSessionError;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::MaterializationState;

/// The materialization state a physical write leaves on a row for the
/// window between committing the row and proving what landed on disk --
/// named once, because everything that has to agree on it is in a
/// different place: the transaction that writes it, the guard the
/// finishing commit runs under, the startup reset that must leave such a
/// row alone, and startup repair, which owns any row a crash leaves in
/// it.
///
/// Three lanes write it: the projected-upserts batch, the unbatched
/// eager/pinned content write, and the symlink write.
///
/// `Hydrating`, not `Hydrated`. The row is committed before the bytes are
/// published, deliberately -- that ordering is what lets an intent
/// distinguish a crash mid-write from an offline deletion, and what the
/// local watcher's self-echo suppression depends on. But the window is
/// not brief: a batch writes up to a bounded number of paths, and for the
/// whole of it every row in the batch claimed to hold content that was
/// still in a temp file. `Hydrating` says what is true -- a write for
/// this version is in flight -- and leaves `Hydrated` to the commit that
/// can prove it.
pub const MATERIALIZATION_IN_FLIGHT_STATE: MaterializationState = MaterializationState::Hydrating;

/// One incarnation of a path's `state = 'current'` row, carrying every
/// column a materialization payload or a version identity is built from.
///
/// Two producers read their payload out of this device's own index rather
/// than receiving it: the local materialization audit, and peer
/// hydration, which is asked to place the row it is given. A wire record
/// comes with its own metadata and a DAG projection derives everything
/// from the resolved version, but these two have to go and read the row
/// -- and both used to read it more than once. The audit read it eight
/// times -- `get_files_by_paths` for the content, then
/// `get_record_kind`, `get_symlink_target`, `get_symlink_out_of_root`,
/// `get_unix_mode`, `get_xattrs`, `get_origin_device_id` and
/// `get_authoring_change_hash` one at a time; hydration read the version
/// and then the authoring hash, in two transactions, under a comment
/// claiming it was one. Neither had any isolation spanning its reads. A
/// writer landing in between produced a payload whose content came from
/// one incarnation of the row and whose metadata or authoring identity
/// came from another: a value that was never true of anything, from which
/// a `version_hash` could then be derived that named no version any row
/// had ever held.
///
/// Making the payload the sole source of what gets written is not enough
/// on its own while the payload itself can be stitched together this way.
/// So this is ONE statement, and the fields that decide a version
/// (`record`'s blocks/size/mtime, plus `record_kind`, `unix_mode`,
/// `symlink_target`, `xattrs`) and the identity that names it
/// (`authoring_change_hash`) cannot come from different moments by
/// construction.
///
/// This is a producer's read, not a guard's. A caller that wants one
/// column to answer "is this still current?" should keep using the
/// single-column accessor.
#[derive(Debug, Clone)]
pub struct CurrentRowSnapshot {
    pub path: String,
    pub record: FileRecord,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    pub origin_device_id: Option<String>,
    /// `None` for a row that has no authoring identity yet -- the
    /// bootstrap scaffold, and a device rebootstrapped from a checkpoint
    /// snapshot. A legitimate, transient shape the audit skips rather
    /// than treating as corruption; see
    /// `reconcile_local_materialization_audit`.
    pub authoring_change_hash: Option<ChangeHash>,
    /// The materialization state this same incarnation carries -- so a
    /// caller that is about to CAS the state forward can name the value
    /// it actually observed instead of writing blind.
    pub materialization_state: Option<MaterializationState>,
}

impl CurrentRowSnapshot {
    /// The version this incarnation is, derived the one canonical way
    /// from the columns that decide it -- all of which came from the same
    /// statement as each other.
    pub fn to_file_version(&self) -> FileVersion {
        FileVersion::from_index_row(
            self.record.blocks.clone(),
            self.record.size,
            self.record.mtime_unix_nanos,
            self.record_kind,
            self.unix_mode,
            self.symlink_target.clone(),
            self.xattrs.clone(),
        )
    }
}

/// One path's already-block-fetched-and-reconstructed-to-temp upsert,
/// ready for a bounded batch publish (receiver-side materialization
/// batching). Carries everything `ReplicaCoordinator::
/// open_projected_upserts_batch` needs to commit this path's optimistic
/// (not-yet-on-disk) `Hydrated` row+intent -- built entirely from work
/// that needs no path lock (resolving the DAG winner, fetching blocks,
/// reconstructing to a temp file via
/// `yadorilink_local_storage::reconstruct_file_to_temp`), so a caller can
/// prepare several of these concurrently/independently before ever
/// acquiring any path's lock.
///
/// The crash-ordering invariant this preserves is identical to a single
/// unbatched `materialize()` call's: the row+intent (`open_projected_
/// upserts_batch`) must commit BEFORE `tmp_path` is published to
/// `out_path`, and the fingerprint+intent-clear (`finalize_projected_
/// mutations_batch`) must commit only AFTER that publish -- just batched
/// across up to a bounded number of paths in each of those two steps,
/// instead of committing one path's steps at a time.
pub struct PreparedProjectedUpsert {
    pub rel_path: String,
    pub tmp_path: std::path::PathBuf,
    pub out_path: std::path::PathBuf,
    pub record: FileRecord,
    pub origin_device_id: String,
    pub authoring_change_hash: Option<ChangeHash>,
    pub target_version_hash: Vec<u8>,
    /// The incoming wire metadata (record kind / symlink target /
    /// symlink-out-of-root / unix mode / xattrs) this upsert's `FileVersion`
    /// carries, captured once here at prepare time rather than re-fetched
    /// during revalidation -- a `FileVersion`'s metadata is part of its own
    /// content-addressed identity (see `version_hash`'s own hashing), so it
    /// can never differ between the prepare and commit steps for the same
    /// version and needs no re-lookup. `open_projected_upserts_batch`
    /// applies this atomically alongside the row/intent it commits, so
    /// revalidation itself (`revalidate_ordinary_upsert`) stays pure
    /// read-only -- no `writer_gate` acquisition of its own per candidate.
    pub metadata: yadorilink_replica_domain::session_state::LocalFileMetaColumns,
    /// The same conflict-copy-fixpoint-derived synthetic head
    /// `reconcile_group_paths` would have passed as `combined_heads`'s own
    /// `derived_head` argument for this path, if any -- `Some` only for a
    /// path that is itself a conflict-copy output (its content comes from
    /// a *losing* change materialized under a derived name, never from any
    /// DAG change that directly touches this exact path). Required for a
    /// caller's own re-resolution to see this path as `Present` at all: a
    /// pure conflict-copy path has no direct change touching it, so
    /// `combined_heads` with `derived_head: None` returns empty for it.
    pub derived_head: Option<yadorilink_replica_engine::conflict::PathHead>,
    /// Cross-file provenance batching: every block hash `ensure_
    /// blocks_present_collecting` newly fetched and durably `store.put`
    /// while preparing THIS candidate -- never flushed by the prepare
    /// step itself. `try_commit_ordinary_batch` collects these
    /// (deduplicated) across every candidate in its own bounded commit
    /// chunk and issues ONE `record_group_block_provenance` call for the
    /// whole chunk, instead of one call per file. Empty for a candidate
    /// that needed no new fetches (every block was already local and
    /// provenanced).
    pub newly_fetched_block_hashes: Vec<Vec<u8>>,
    /// The exact version this upsert's temp file was built from.
    ///
    /// Not `target_version_hash` above, which is a digest over the block
    /// list for the materialization intent and is a different value
    /// entirely. This is the `FileVersion`'s own identity, carried from
    /// the moment the payload was produced.
    ///
    /// The proof for a write must name what the write put on disk, and
    /// the only thing that knows that is the payload. Reading it from the
    /// row instead -- at any point, however early -- asks a question
    /// about the row rather than about the bytes, and the row can move
    /// underneath while keeping its authoring identity.
    /// The whole version, not just its hash: the exactness gate also
    /// compares the replicated xattrs on disk against what the write was
    /// supposed to apply, and those must come from the payload for the
    /// same reason the identity does.
    pub written_version: FileVersion,
    /// The path's own resolved frontier, as `revalidate_ordinary_upsert`
    /// read it under this batch's path lock immediately before the write
    /// -- the frontier this physical write actually realizes.
    ///
    /// Empty until revalidation fills it in. It used to be one
    /// group-wide `dag_group_heads()` read shared by the whole batch,
    /// which is a different claim: the group's frontier at some moment
    /// near the writes, rather than the resolution each individual write
    /// carried out. Those diverge exactly when they matter -- a batch
    /// spans many paths and takes real time, and a change admitted for an
    /// unrelated path moves the group frontier without changing what any
    /// of these writes realized.
    pub realized_causal_basis: Vec<ChangeHash>,
}

/// One [`PreparedProjectedUpsert`]'s outcome once its temp file has been
/// published to `out_path` -- everything `ReplicaCoordinator::
/// finalize_projected_mutations_batch` needs is just the path and the
/// fingerprint of what's now durably on disk; the row/intent were already
/// committed by `open_projected_upserts_batch`.
pub struct FinishedProjectedUpsert {
    pub rel_path: String,
    /// What this path was written as.
    pub kind: yadorilink_replica_domain::file::RecordKind,
    /// The version this write materialized -- the proof is published FOR
    /// this version. Publishing a versionless generation instead makes the
    /// row unusable as evidence for any desired resolution, because the
    /// resolved-path-state hash encodes version presence, so zero-work
    /// settlement can never match it and the path is re-materialized
    /// forever.
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    /// The mutation generation this write bumped the fence to. The proof
    /// must be published under exactly this epoch: it is what the
    /// obligation's own settlement evidence CASes on, so anything that
    /// advances the fence between the write and the publish defeats it.
    pub mutation_generation: i64,
    /// The disk identity observed after this path's write. `None` when the
    /// observation failed -- the proof is still published, without an
    /// identity, since usability is decided by the fence, not by this.
    pub observed_identity: Option<yadorilink_root_authority::fs_identity::FileIdentity>,
    /// The frontier this write realized, carried from the candidate's own
    /// revalidation -- see `PreparedProjectedUpsert::realized_causal_basis`.
    pub causal_basis: Vec<ChangeHash>,
    /// The authoring identity the row carried when this candidate was
    /// revalidated, and the state the open-batch transaction left it in.
    /// The finalizer commits only while the row still satisfies both: a
    /// path superseded during the batch's writes gets no proof and keeps
    /// its intent, rather than being stamped for a version it has moved
    /// off.
    pub expected_authoring: Option<ChangeHash>,
    pub expected_state: MaterializationState,
}

/// One path's tombstone, ready for a bounded batch publish. Unlike an
/// upsert, a delete needs no intent (see `materialize()`'s own tombstone
/// branch: `remove_file` runs BEFORE any DB write, since a delete is
/// idempotent and safe to redo, with no "row says done but file isn't yet"
/// hazard window to protect against) -- its whole commit (tombstone row +
/// held-state clear) happens in `ReplicaCoordinator::
/// finalize_projected_mutations_batch`, after `out_path` has already been
/// removed from disk.
pub struct PreparedProjectedDelete {
    pub rel_path: String,
    pub out_path: std::path::PathBuf,
    pub record: FileRecord,
    pub origin_device_id: String,
    pub authoring_change_hash: Option<ChangeHash>,
}

/// An open, durably-recorded materialization intent for one path, returned
/// by `ReplicaCoordinator::open_materialization_intent_guard`.
/// Dropping without calling `clear` is itself meaningful: the intent stays
/// recorded, so the next repair pass treats a missing file at this path as
/// a crash to recover, not an offline delete.
pub trait OpenMaterializationIntent: Send {
    fn clear(self: Box<Self>) -> Result<(), PeerSessionError>;
}

/// A checked shape for what `ReplicaCoordinator::dag_publish_
/// materialized_generation_if_fence_current` may ever publish. Only the
/// EXACT outcomes are constructible -- there is no constructor that
/// could publish a placeholder as if it were real content; that false
/// combination is unrepresentable by this type, not merely discouraged.
/// A scheduler-level settlement
/// (`SettlementEvidence::PolicyPlaceholder`/`HazardHeld`/`IgnoreExcluded`)
/// has no `ExactActualState` value to convert to at all -- see
/// `SettlementEvidence::as_exact_actual_state` in `peer_session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExactActualState {
    /// Disk holds the exact desired object at the exact desired version.
    /// `identity` is `Option`, matching the persistence layer's own
    /// optional `filesystem_identity` -- absence never blocks a
    /// publication; the CAS on the mutation fence alone fences the
    /// evidence (decision 3d).
    Object {
        kind: RecordKind,
        version: yadorilink_replica_domain::ids::VersionHash,
        // Boxed to keep this variant's size close to `Absent`'s (clippy
        // large_enum_variant): `FileIdentity` is comparatively large and
        // only this arm carries it.
        identity: Box<Option<yadorilink_root_authority::fs_identity::FileIdentity>>,
    },
    /// Disk holds the exact desired absence.
    Absent,
    /// The path has no explicit entry of its own to hold, and disk holds
    /// the directory its live descendants need there: a structural
    /// directory. It names no version -- it is derived from the tree, never
    /// replicated -- so it proves exactly one thing: a directory stands at
    /// the path while the namespace requires one.
    StructuralDirectory {
        // Boxed for the same reason as `Object`'s.
        identity: Box<Option<yadorilink_root_authority::fs_identity::FileIdentity>>,
    },
}

/// The row condition a version-bound writer requires to still hold at
/// commit time -- see
/// `ReplicaCoordinator::commit_internal_materialized_state_if_fence_current`.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedAuthoring<'a> {
    /// The state the row must still be in, normally `Hydrating`.
    pub state: MaterializationState,
    /// The authoring hash it must still carry. `None` means it must still
    /// carry none, which is not the same as "any".
    pub authoring_change_hash: Option<&'a ChangeHash>,
    /// The version the current row must still name, checked explicitly
    /// rather than inferred from the authoring hash. `None` skips it.
    ///
    /// Any caller whose version was read in an earlier transaction than
    /// the commit -- which includes every writer that fetches or
    /// reconstructs content in between -- passes it, because a
    /// supersession can keep the authoring hash while changing the content
    /// the version is derived from.
    pub expected_version: Option<&'a yadorilink_replica_domain::ids::VersionHash>,
}

/// One Change ready for DAG admission through
/// `ReplicaCoordinator::dag_admit_change_batch_with_versions`.
///
/// A named struct rather than a tuple because it carries two independent
/// booleans that mean completely different things, and a positional swap
/// between them would be a silent security regression rather than a
/// compile error.
pub struct DagAdmission<'a> {
    pub change: &'a Change,
    pub versions: &'a [FileVersion],
    /// Whether the Change has already been projected onto the filesystem.
    /// Always `false` on the remote-admission path (admission is
    /// durable-but-not-yet-projected; the Convergence Engine projects
    /// later).
    /// This Change's already-verified `AuthorizationCheckpoint` evidence,
    /// written atomically with the Change's own admission, so a crash
    /// never strands a remote Change as an accidental Pending row.
    pub evidence: yadorilink_replica_engine::ports::ChangeEvidence,
}
