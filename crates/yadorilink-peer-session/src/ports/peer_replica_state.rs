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
    CurrentVersionRecord, HeldState, LinkGate, MaterializationPolicy, MaterializationState,
    StartupFailed,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

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

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError>;

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

    /// Upserts a `Pending` materialization job for an incoming version — the
    /// single write reconcile performs in place of eagerly materializing
    /// inline.
    fn materialization_enqueue_pending(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &[u8],
        trigger_lamport: u64,
        now: i64,
    ) -> Result<(), PeerSessionError>;

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

    /// Records blocks this device actually obtained through the group during
    /// reconciliation (never called for peer-claimed-only metadata).
    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError>;

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, PeerSessionError>;

    /// Paths represented anywhere in this group's retained history — used to
    /// decide whether an incoming path is genuinely new.
    fn dag_group_history_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError>;

    fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, PeerSessionError>;

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

    /// Marks an admitted change as materialized into the index, once
    /// reconcile has finished projecting it.
    fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), PeerSessionError>;

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

    /// Sets `(group_id, path)`'s owner-executable bit.
    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
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
}
