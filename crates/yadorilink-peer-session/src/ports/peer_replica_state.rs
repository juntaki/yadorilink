//! The capability surface `PeerSyncSession` (`peer_session.rs`) needs from
//! `SyncState`: shared-projection reads, change admission, peer-driven index
//! commits, path-lock acquisition, and startup-readiness waits. Every method
//! below is called by `peer_session.rs` today via `self.state.<method>`,
//! surveyed directly from that file rather than sketched from `SyncState`'s
//! full method list.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::error::PeerSessionError;
use yadorilink_replica_domain::admission::{AdmitResult, ChangeOrdering};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{
    CurrentVersionRecord, HeldState, LinkGate, LocalFileMetaColumns, MaterializationPolicy,
    MaterializationState, StartupFailed,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

/// Duplicated from `yadorilink_sync_sqlite::MaterializedFingerprint` rather
/// than depending on that crate from production code solely for this type
/// alias (that dependency is dev-only here) -- same "duplicate small leaf
/// types rather than force an awkward dependency" precedent this crate's
/// own `ContentHash`/`yadorilink-sync-sqlite::materialization_state::
/// ContentHash` pair already established independently of each other.
pub type MaterializedFingerprint = (u64, Option<std::time::SystemTime>, i64, i64);

/// One path's already-block-fetched-and-reconstructed-to-temp upsert,
/// ready for a bounded batch publish (C4-6: receiver-side materialization
/// batching). Carries everything [`PeerReplicaStatePort::
/// open_projected_upserts_batch`] needs to commit this path's optimistic
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
    /// C4-7: the incoming wire metadata (record kind / symlink target /
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
    /// M6PHASE cross-file provenance batching: every block hash `ensure_
    /// blocks_present_collecting` newly fetched and durably `store.put`
    /// while preparing THIS candidate -- never flushed by the prepare
    /// step itself. `try_commit_ordinary_batch` collects these
    /// (deduplicated) across every candidate in its own bounded commit
    /// chunk and issues ONE `record_group_block_provenance` call for the
    /// whole chunk, instead of one call per file. Empty for a candidate
    /// that needed no new fetches (every block was already local and
    /// provenanced).
    pub newly_fetched_block_hashes: Vec<Vec<u8>>,
}

/// One [`PreparedProjectedUpsert`]'s outcome once its temp file has been
/// published to `out_path` -- everything [`PeerReplicaStatePort::
/// finalize_projected_mutations_batch`] needs is just the path and the
/// fingerprint of what's now durably on disk; the row/intent were already
/// committed by `open_projected_upserts_batch`.
pub struct FinishedProjectedUpsert {
    pub rel_path: String,
    pub fingerprint: Option<MaterializedFingerprint>,
}

/// One path's tombstone, ready for a bounded batch publish. Unlike an
/// upsert, a delete needs no intent (see `materialize()`'s own tombstone
/// branch: `remove_file` runs BEFORE any DB write, since a delete is
/// idempotent and safe to redo, with no "row says done but file isn't yet"
/// hazard window to protect against) -- its whole commit (tombstone row +
/// held-state clear) happens in [`PeerReplicaStatePort::
/// finalize_projected_mutations_batch`], after `out_path` has already been
/// removed from disk.
pub struct PreparedProjectedDelete {
    pub rel_path: String,
    pub out_path: std::path::PathBuf,
    pub record: FileRecord,
    pub origin_device_id: String,
    pub authoring_change_hash: Option<ChangeHash>,
}

/// An open, durably-recorded materialization intent for one path, returned
/// by [`PeerReplicaStatePort::open_materialization_intent_guard`]. Opaque
/// here (the concrete guard is `yadorilink-sync-core`'s own
/// `MaterializationIntentGuard<'_>`, which borrows a concrete `&SyncState`
/// a trait object can't name) -- the only operation any caller ever
/// performs on one is clearing it once the write it guards is durable.
/// Dropping without calling `clear` is itself meaningful: the intent stays
/// recorded, so the next repair pass treats a missing file at this path as
/// a crash to recover, not an offline delete.
pub trait OpenMaterializationIntent: Send {
    fn clear(self: Box<Self>) -> Result<(), PeerSessionError>;
}

/// A checked shape for what [`PeerReplicaStatePort::dag_publish_
/// materialized_generation_if_fence_current`] may ever publish. Only the
/// two EXACT outcomes are constructible -- there is no constructor that
/// could publish a placeholder as if it were real content; that false
/// combination is unrepresentable by this type, not merely discouraged.
/// A scheduler-level settlement
/// (`SettlementEvidence::PolicyPlaceholder`/`HazardHeld`/`IgnoreExcluded`)
/// has no `ExactActualState` value to convert to at all -- see
/// `SettlementEvidence::as_exact_actual_state` in `peer_session_impl`.
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
        identity: Option<yadorilink_root_authority::fs_identity::FileIdentity>,
    },
    /// Disk holds the exact desired absence.
    Absent,
}

/// Capability surface `PeerSyncSession` needs to reconcile files with a peer:
/// read the shared projection, admit verified changes into the DAG, commit
/// peer-originated file versions into the index, and coordinate with local
/// mutation via the path lock and startup-readiness barrier. `#[async_trait]`
/// only because [`wait_group_ready`](Self::wait_group_ready) is async — every
/// other method stays a plain sync fn, matching `SyncState`'s own shape.
#[async_trait::async_trait]
pub trait PeerReplicaStatePort: Send + Sync {
    /// Awaits the group's startup-readiness gate before any peer-apply step
    /// may proceed — must be called before acquiring any path lock so it can
    /// never deadlock against the startup writer (see
    /// `SyncState::wait_group_ready`'s own doc comment for the full ordering
    /// requirement).
    async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed>;

    /// Acquires the per-`(group_id, path)` lock serializing this peer
    /// reconciliation against a concurrent local save of the same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// Whether `group_id`'s folder link currently accepts peer-applied
    /// writes at all (paused/orphaned/live) — checked before reconciling any
    /// file for the group.
    fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, PeerSessionError>;

    /// The group's configured on-demand-sync materialization policy, used to
    /// decide whether an incoming file should be hydrated eagerly or left a
    /// placeholder.
    fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, PeerSessionError>;

    /// Whether this device has opted a group into materializing peer
    /// symlinks as real Windows symlinks (vs. placeholder files).
    fn windows_symlink_opt_in_for_group(&self, group_id: &str) -> Result<bool, PeerSessionError>;

    /// The current row for `(group_id, path)`, read before deciding whether
    /// an incoming peer version supersedes it.
    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, PeerSessionError>;

    /// Batched form of `get_file` for reconciling many incoming paths from
    /// one peer message without one query per path.
    fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, PeerSessionError>;

    /// Whether `(group_id, path)` has a genuine current row this device
    /// actually indexed, as opposed to no row or only the bootstrap
    /// scaffold — distinguishes "never seen this path" from "seen it, it's
    /// a tombstone" while applying incoming wire metadata.
    fn has_real_current_row(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError>;

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, PeerSessionError>;

    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, PeerSessionError>;

    fn get_symlink_out_of_root(&self, group_id: &str, path: &str)
        -> Result<bool, PeerSessionError>;

    fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, PeerSessionError>;

    /// The replicated extended attributes currently recorded for `path`
    /// (C1.2a) -- sorted by name, already filtered to the capture-side
    /// allow-list. See `FileMeta::xattrs`'s own doc comment.
    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PeerSessionError>;

    /// The device that produced `path`'s current content, consulted when
    /// deciding whether an incoming record actually changes anything.
    fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError>;

    fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError>;

    /// Attaches verified DAG authorship to the current row once reconcile
    /// has admitted the change that produced it.
    fn set_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
        hash: &ChangeHash,
    ) -> Result<(), PeerSessionError>;

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, PeerSessionError>;

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Version-and-authoring-guarded materialization-state transition, used
    /// by the hydration cleanup path so a stale attempt cannot roll back a
    /// newer version's state.
    fn transition_materialization_state_if_same_authoring(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        expected_authoring_hash: Option<&ChangeHash>,
        next: MaterializationState,
    ) -> Result<bool, PeerSessionError>;

    /// M5-A review follow-up (blocker #56): records the disk identity of
    /// the exact bytes this device just wrote via a successful
    /// `reconstruct_file`, alongside that same call's `Hydrated`
    /// transition -- always called right after `reconstruct_file`
    /// succeeds. See `yadorilink_sync_sqlite::materialization_state::
    /// MaterializationStateRepository::record_materialized_fingerprint`'s
    /// own doc comment for the full reasoning and the fail-closed `None`
    /// semantics.
    fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<MaterializedFingerprint>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

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
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Like [`Self::record_placeholder_generation`], but only if nothing is
    /// recorded yet -- a concurrent winner's value is kept instead of being
    /// overwritten. M2-3a's Windows placeholder-creation path (via
    /// `yadorilink_local_storage::create_or_defer_placeholder`'s
    /// `RecordIfAbsent` outcome) MUST use this, never the unconditional
    /// version: on Windows, real on-disk placeholder creation is deferred
    /// to a second process (`cfapi-host.exe`) that a concurrent
    /// `ListFolderFilesRequest` backfill can already have supplied a
    /// generation to, and an unconditional overwrite here would silently
    /// orphan whatever that process already used.
    fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        provider_kind: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, PeerSessionError>;

    /// Clears any placeholder identity recorded for `(group_id, path)` -- a
    /// no-op if none was recorded. See
    /// `MaterializationStateRepository::clear_placeholder_generation`'s own
    /// doc comment for when callers must call this.
    fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError>;

    fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), PeerSessionError>;

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), PeerSessionError>;

    fn clear_held(&self, group_id: &str, path: &str) -> Result<(), PeerSessionError>;

    fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), PeerSessionError>;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError>;

    /// Paths whose index row already admits it has no bytes — reconcile's
    /// on-demand-sync repair audit re-drives exactly these through an
    /// ordinary peer fetch.
    fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, PeerSessionError>;

    /// Wakes the Convergence Engine's scheduler loop promptly after
    /// enqueuing a pending job, instead of waiting for its fallback poll.
    fn notify_materialization_wake(&self);

    /// Marks `group_id` dirty for the ephemeral conflict-copy retirement
    /// loop and wakes it promptly, instead of waiting for its own periodic
    /// backstop poll. Callers: an admitted batch that actually advanced
    /// this device's frontier, and a materialization job reaching
    /// `Completed` -- see `RetirementWake`'s own doc comment for why those
    /// two are exactly the events after which a conflict copy can become
    /// unjustified.
    fn notify_retirement_wake(&self, group_id: &str);

    /// Marks `group_id` dirty for the `HazardHeld` re-check sweep and wakes
    /// it promptly, instead of waiting for its own periodic backstop poll.
    /// Same two callers as `notify_retirement_wake`, for the same reason:
    /// an admitted batch that actually advanced this device's frontier, or
    /// a materialization job reaching `Completed`, are exactly the events
    /// after which a SIBLING path's change could clear a held path's
    /// hazard -- see `MaterializationStateRepository::list_held_paths`'s
    /// own doc comment for why nothing else ever re-visits a held path on
    /// its own.
    fn notify_hazard_recheck_wake(&self, group_id: &str);

    fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError>;

    /// Every retained version of `path`, newest-first — used by
    /// `DurabilityEvidencePort::retained_roots` (`replica_engine_ports.rs`)
    /// to derive the durability-root set for a path.
    fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, PeerSessionError>;

    /// Commits a peer-originated version onto the index, recording the
    /// sending peer as origin. The plain (non-authoring) form, used when no
    /// verified DAG change accompanies the write.
    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Same as `upsert_file_with_origin`, but additionally attaches the
    /// already-admitted DAG change that authored this projection, in one
    /// transaction.
    fn upsert_file_with_origin_and_author(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Block hashes this device has previously obtained through `group_id` —
    /// consulted before trusting a peer's claim that it can serve a block.
    fn group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError>;

    /// Batched form of [`group_has_block_provenance`](Self::group_has_block_provenance)
    /// — one query for many hashes instead of one query per hash. Returns
    /// the SUBSET of `block_hashes` that have recorded provenance for
    /// `group_id`; a hash absent from the returned set has none (same
    /// meaning as that hash's own single-hash call returning `false`).
    /// `ensure_blocks_present`'s dedup path uses this instead of looping
    /// the single-hash form once per block.
    fn group_has_block_provenance_batch(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>, PeerSessionError>;

    /// Records blocks this device actually obtained through the group during
    /// reconciliation (never called for peer-claimed-only metadata).
    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError>;

    /// Records that `peer_device_id` EXPLICITLY, definitively refused a
    /// fetch of `path` AT `version_hash` for lack of verified provenance on
    /// that exact version -- deliberately distinct both from a transient
    /// miss (`NotFound`/`TimedOut`/`Busy`) and from any OTHER `Rejected`
    /// reason, neither of which must ever call this. M5-A soak-closure
    /// durability investigation, review follow-up: this is the evidence
    /// `DurabilityFacts::known_unobtainable_required_content` needs to
    /// positively confirm no currently-authorized peer can serve the exact
    /// CURRENT version's content, rather than inferring it from
    /// connectivity/timing alone or conflating it with a since-superseded
    /// version's refusals (why this is keyed by `version_hash`, not just
    /// `path`).
    fn record_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
        reason: &str,
        refused_at_unix_nanos: i64,
    ) -> Result<(), PeerSessionError>;

    /// Deletes any refusal previously recorded for `peer_device_id` against
    /// `path` at `version_hash` -- called on a SUCCESSFUL fetch, so a peer
    /// that once refused a version but has since obtained it can never be
    /// read as still refusing it.
    fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), PeerSessionError>;

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, PeerSessionError>;

    /// Paths represented anywhere in this group's retained history — used to
    /// decide whether an incoming path is genuinely new.
    fn dag_group_history_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError>;

    fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, PeerSessionError>;

    /// Whether `hash` is already durably admitted to the retained store
    /// (applied or unapplied-but-admitted — see `dag_list_unapplied_changes`'s
    /// own doc for that distinction). Deliberately narrower than
    /// `dag_has_change_or_pruned`: this does not also treat a *pruned*
    /// change as present, since a caller using this to short-circuit a
    /// duplicate re-delivery must not conflate "already admitted" with
    /// "was pruned, and receiving its full body again would re-trigger
    /// rebootstrap/compaction semantics" — those are different situations
    /// with different correct responses, and folding them together here
    /// would silently change which one a duplicate-detection caller gets.
    fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, PeerSessionError>;

    fn dag_has_change_or_pruned(
        &self,
        group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, PeerSessionError>;

    /// Reads the current row's author and compares it against an incoming
    /// change's author on one connection — the large-index reconcile
    /// prefilter's hot-path check.
    fn current_authoring_relation(
        &self,
        group_id: &str,
        path: &str,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError>;

    /// The true missing ancestor frontier reachable from a set of incoming
    /// heads, walking through buffered orphans — decides what reconcile must
    /// still request from the peer before it can admit the head changes.
    fn dag_missing_ancestor_frontier(
        &self,
        roots: Vec<ChangeHash>,
    ) -> Result<Vec<ChangeHash>, PeerSessionError>;

    fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, PeerSessionError>;

    /// A stored change's raw encoded bytes, for relaying it onward to
    /// another peer with its original signature intact.
    fn dag_get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, PeerSessionError>;

    fn dag_has_file_version(
        &self,
        group_id: &str,
        hash: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, PeerSessionError>;

    fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<Option<FileVersion>, PeerSessionError>;

    fn dag_parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, PeerSessionError>;

    fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, PeerSessionError>;

    /// Atomically persists a verified peer change's referenced versions and
    /// admits the change — reconcile's actual DAG-write step. Verification
    /// (hash + signature + authorization) happens in the caller, not here.
    fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<AdmitResult, PeerSessionError>;

    /// Bounded micro-batch sibling of [`Self::dag_admit_change_with_
    /// versions`]: admits every item in `items`, in order, returning one
    /// result per item -- see `yadorilink_sync_sqlite::
    /// ChangeHistoryRepository::dag_admit_change_batch_with_versions`'s own
    /// doc comment for the exact per-item guarantees a real implementation
    /// must preserve (atomicity, failure isolation, ordering). Default
    /// implementation calls [`Self::dag_admit_change_with_versions`] once
    /// per item -- byte-identical to before this method existed, so any
    /// implementor that does not override it (today: `test_support.rs`'s
    /// fake) keeps working unchanged.
    fn dag_admit_change_batch_with_versions(
        &self,
        items: &[(&Change, &[FileVersion], bool)],
    ) -> Vec<Result<AdmitResult, PeerSessionError>> {
        items
            .iter()
            .map(|(change, versions, applied)| {
                self.dag_admit_change_with_versions(change, versions, *applied)
            })
            .collect()
    }

    /// Marks an admitted change as materialized into the index, once
    /// reconcile has finished projecting it.
    fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), PeerSessionError>;

    /// C4-12 decision 3d/PROJ-8: durably bumps `(group_id, path)`'s
    /// filesystem-side mutation fence (independent of the DAG-side
    /// `invalidation_generation`) and returns the new value. A single
    /// atomic statement, never a read followed by a write, so two
    /// concurrent callers always receive two distinct values -- this is a
    /// staleness detector, never a mutual-exclusion primitive; callers MUST
    /// still hold this path's own lock for the mutation itself.
    ///
    /// Call this from inside the SAME path-lock critical section as the
    /// physical mutation it fences, before the first mutating syscall, and
    /// only once the decision to mutate has actually been made.
    /// `mutation_kind` is a short diagnostic label (e.g. `"materialize"`,
    /// `"retire"`); it plays no role in any correctness check.
    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        mutation_kind: &str,
    ) -> Result<i64, PeerSessionError>;

    /// Reads `(group_id, path)`'s current mutation-fence value WITHOUT
    /// bumping it (creating it at generation 0 first if absent), for a
    /// content-identical verification that changes no bytes (decision 3d:
    /// "verification snapshots, it does not bump"). The observation of
    /// disk and this call MUST happen as one atomic step under the path's
    /// lock.
    fn dag_snapshot_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, PeerSessionError>;

    /// CAS-publish for a real physical mutation or a content-identical
    /// verification's evidence (decision 3e): writes the actual-state
    /// generation for `(group_id, path)` only if its CURRENT mutation-fence
    /// value still equals `expected_mutation_generation` -- the epoch the
    /// caller captured via [`Self::dag_bump_mutation_fence`]/
    /// [`Self::dag_snapshot_mutation_fence`] before it acted. Returns
    /// `Ok(false)` (not an error) when the CAS fails -- some other mutator
    /// has already bumped the fence since, so this attempt's evidence is
    /// stale and must not be published as current.
    fn dag_publish_materialized_generation_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        causal_basis: &[ChangeHash],
        state: ExactActualState,
        expected_mutation_generation: i64,
    ) -> Result<bool, PeerSessionError>;

    /// The zero-work-close pre-check: without any block fetch or disk
    /// write, determines whether `path` already, verifiably, holds the
    /// state `resolution`/`winner_version_hash` describes -- a usable
    /// `path_materialized_generations` record (fail-closed against the
    /// filesystem-side mutation fence, same as every other reader of that
    /// table) whose content matches the desired hash for this resolution,
    /// AND whose recorded filesystem identity re-verifies against live
    /// disk right now. `Some((state, mutation_generation))` authorizes
    /// skipping physical work for THIS decision only -- it is not itself a
    /// completion, never republishes, and never refreshes the record; the
    /// caller must still close via the same compound completion a real
    /// materialization would use, re-establishing currency at the actual
    /// moment of close. `None` means "not confirmable, do the real work"
    /// and must never be treated as an error or a proof of anything.
    ///
    /// The disk revalidation's birth-time-granularity input is expected to
    /// come from a per-group cache the implementation maintains, populated
    /// by one real probe the first time any path in that group is checked
    /// and reused for the rest of the process's lifetime -- never a fixed
    /// `Coarse` assumption. A fixed `Coarse` assumption was tried and
    /// rejected: on a filesystem that does not expose `generation_or_usn`
    /// (unprivileged `FS_IOC_GETVERSION` is commonly unavailable, and never
    /// available on overlayfs), `Coarse` treats even a perfectly matching
    /// birth time as `Ambiguous`, so this check could never confirm
    /// anything at all on such a filesystem, not merely miss an
    /// optimization on it. A per-call probe was also rejected: it performs
    /// its own file creation/deletion, which is itself physical work and
    /// would defeat the "zero work" guarantee this check exists to
    /// provide -- amortizing it to once per group keeps the steady-state
    /// cost at zero.
    fn dag_zero_work_settlement_if_already_current(
        &self,
        group_id: &str,
        path: &str,
        resolution: &yadorilink_replica_engine::conflict::PathResolution,
        winner_version_hash: Option<&yadorilink_replica_domain::ids::VersionHash>,
    ) -> Result<Option<(ExactActualState, i64)>, PeerSessionError>;

    /// Whether `(group_id, path)` has a usable `path_materialized_generations`
    /// record at all -- exactly the fence-checked point lookup
    /// [`Self::dag_zero_work_settlement_if_already_current`] performs before
    /// anything else, and whose absence makes that method return `None`
    /// unconditionally.
    ///
    /// Exposed separately so a caller can ask the cheap question FIRST. The
    /// settlement check's own inputs (a path's resolved DAG heads) cost an
    /// ancestry walk to compute, and on a device that has materialized
    /// nothing for a path yet -- every path on a replica catching up to a
    /// bulk import -- that walk is provably wasted: the O(1) lookup that
    /// follows it can only answer "no". `false` here is therefore never a
    /// weaker answer than running the full check, it is the same answer
    /// reached without paying for it.
    ///
    /// Advisory in the safe direction only. A record appearing between this
    /// call and a later one merely means the caller does the ordinary work it
    /// would have done anyway -- which is what `None` from the settlement
    /// check already means -- never that a needed write is skipped.
    fn dag_has_usable_materialized_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError>;

    fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError>;

    /// Opens the single sanctioned materialization-intent seam for
    /// `(group_id, path)` before a peer-driven materialize commits a fresh
    /// `Hydrated` row and writes the file's bytes. See
    /// [`crate::materialization::MaterializationIntentGuard::open`]. Added
    /// as a narrow delegate (rather than exposing `&SyncState` itself)
    /// because `MaterializationIntentGuard<'a>` borrows a concrete
    /// `&'a SyncState`, which a trait object can't produce; the
    /// implementation below runs inside `impl PeerReplicaStatePort for
    /// SyncState`, where `self` already is that concrete `&SyncState`.
    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        target_version_hash: &[u8],
        permit: &'a RootCommitPermit<'a>,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, PeerSessionError>;

    /// C4-6: commits a bounded batch of [`PreparedProjectedUpsert`]s'
    /// optimistic (not-yet-on-disk) rows in ONE transaction -- opening each
    /// one's materialization intent, upserting its `Hydrated` row, and
    /// clearing any prior held state, for every upsert in the batch. MUST
    /// run, and its transaction MUST commit, before ANY of these upserts'
    /// `tmp_path` is published to `out_path` -- see `PreparedProjectedUpsert`'s
    /// own doc comment for the crash-ordering invariant this preserves, and
    /// [`Self::finalize_projected_mutations_batch`] for the matching
    /// after-publish half.
    fn open_projected_upserts_batch(
        &self,
        group_id: &str,
        upserts: &[PreparedProjectedUpsert],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// C4-6: after every upsert in `finished_upserts` has had its temp file
    /// published to its final path (and every delete in `deletes` has had
    /// its `out_path` removed from disk), commits ALL of the following in
    /// ONE transaction: each finished upsert's fingerprint + intent-clear,
    /// and each delete's tombstone row + held-state clear. See
    /// [`Self::open_projected_upserts_batch`] for the matching before-
    /// publish half and the crash-ordering invariant both together
    /// preserve.
    fn finalize_projected_mutations_batch(
        &self,
        group_id: &str,
        finished_upserts: &[FinishedProjectedUpsert],
        deletes: &[PreparedProjectedDelete],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token. See
    /// [`crate::root_identity::VerifiedRoot::verify`]. Added as a narrow
    /// delegate for the same reason as `open_materialization_intent_guard`
    /// above: `VerifiedRoot::verify` takes a concrete `&SyncState`, which a
    /// trait object can't produce.
    /// Fails closed if `root`'s on-disk identity no longer matches the
    /// group's stored marker (a replaced/swapped mountpoint). The verified
    /// identity value itself is never used by any production caller --
    /// every call site only needs the pass/fail outcome -- so this
    /// deliberately returns `()`, not the verified-root value.
    fn verify_root(&self, root: &Path, group_id: &str) -> Result<(), PeerSessionError>;

    /// Every currently indexed file row for `group_id`, used by the
    /// filename-hazard checks (case-fold / normalization collisions)
    /// before a peer-driven write lands.
    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, PeerSessionError>;

    /// Compares two authoring identities against this group's retained DAG
    /// history. `None` means at least one hash is not verified
    /// retained/pruned history for this group.
    fn dag_compare_authoring(
        &self,
        group_id: &str,
        local: &ChangeHash,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError>;

    /// Whether any admitted `FileVersion` in `group_id`'s change history
    /// references `block_hash` — consulted before a block can be safely
    /// reclaimed.
    fn dag_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError>;

    /// Whether any current or retained materialized index version in
    /// `group_id` references `block_hash`.
    fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError>;

    /// The atomic-write-identity read for `(group_id, path)`'s current row,
    /// used to answer a peer's durability-handoff query with an identity
    /// that can't tear across a concurrent metadata/content transition. See
    /// [`crate::index::SyncState::get_current_version_record`].
    fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, PeerSessionError>;

    /// The current held-state row for `(group_id, path)`, if any.
    fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, PeerSessionError>;

    /// Creates the `version_seq = 0` scaffold row a never-before-seen path
    /// needs before wire-only metadata (kind/symlink-target/exec-bit) can
    /// be attached to it. A no-op if a current row already exists.
    fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), PeerSessionError>;

    /// Sets `(group_id, path)`'s indexed `RecordKind` (file/directory/symlink).
    fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Sets `(group_id, path)`'s raw, unresolved symlink target bytes.
    fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), PeerSessionError>;

    /// Sets whether `(group_id, path)`'s symlink target resolves outside
    /// the linked folder's root.
    fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), PeerSessionError>;

    /// Sets `(group_id, path)`'s replicated Unix permission bits (`None` if
    /// the authoring version carries no Unix permission info).
    fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Sets `(group_id, path)`'s replicated extended attributes (C1.2a) --
    /// empty if the authoring version carries none. See [`get_xattrs`]'s
    /// own doc comment for the allow-list this always mirrors.
    fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// C4-7: applies every incoming-wire-metadata field for `(group_id,
    /// path)` -- bootstrap row if needed, then record_kind/symlink_target/
    /// symlink_out_of_root/unix_mode/xattrs -- in ONE transaction, instead
    /// of the up to 6 separate `writer_gate` acquisitions calling
    /// `ensure_bootstrap_row_for_metadata` + the 5 setters above
    /// individually costs. The single sanctioned entry point for
    /// `peer_session.rs`'s `apply_incoming_wire_metadata` hot path; the
    /// individual setters above stay for any other caller that genuinely
    /// only needs one field.
    fn apply_incoming_metadata_atomic(
        &self,
        group_id: &str,
        path: &str,
        meta: &LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// C4-7 phase 2: the full row (blocks/size/mtime/deleted/origin/
    /// authoring identity) plus every metadata column, in ONE
    /// transaction -- for a peer-projection candidate whose content
    /// already matches what's on disk and in the index, but whose row/
    /// metadata/authoring/origin still needs updating. Replaces two
    /// separate `writer_gate` acquisitions (`upsert_file_with_origin[_
    /// and_author]` + `apply_incoming_metadata_atomic`) with one.
    fn apply_projected_row_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        meta: &LocalFileMetaColumns,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError>;

    /// Records `device`'s acknowledged frontier for `group`, normalized
    /// (sorted, deduplicated). See
    /// [`crate::compaction::record_acknowledged_frontier`]. Added as a
    /// narrow delegate because that free function is generic over
    /// `S: DeviceFrontierStore`, a bound only the concrete `SyncState`
    /// satisfies (a trait object can't implement a foreign generic bound);
    /// the implementation below runs inside `impl PeerReplicaStatePort for
    /// SyncState`, where `self` already is that concrete `&SyncState`.
    fn record_acknowledged_frontier(
        &self,
        group: &yadorilink_replica_domain::ids::FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), PeerSessionError>;

    /// TEMPORARY (block-not-found root-cause investigation, remove once
    /// closed): a human-readable dump of `(group_id, path)`'s current
    /// `projection_obligations` row, if any -- `None` when there is no
    /// obligation for this path right now. Used only by
    /// `fetch_and_store_one_block`'s one-shot requester-side diagnostic on
    /// the first retry-exhausted block fetch.
    fn diagnostic_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError>;
}
