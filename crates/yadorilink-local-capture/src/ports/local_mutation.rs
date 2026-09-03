//! The capability surface `LocalChangeProcessor` (`local_change.rs`) needs
//! from a replica-state type: committing a detected local edit (upsert or
//! delete) as a DAG-emitting index write, plus the dirty-path journal that
//! survives a crash between detection and that commit. Every method below is
//! called by `local_change.rs` today via `self.state.<method>`, surveyed
//! directly from that file. Three additions beyond that original survey:
//! `list_files`, used by the two production `scan_existing_files`/reconcile
//! call sites; and `verify_root`/`open_root`, added because
//! `VerifiedRoot::verify`/`VerifiedRoot::open` need a concrete replica-state
//! reference that a trait object can't produce, so the port grows a delegate
//! that performs the concrete call internally instead of exposing the
//! concrete type.
//!
//! `yadorilink-daemon`'s `ReplicaCoordinator` is this trait's sole
//! implementor (`yadorilink-daemon/src/replica_coordinator/local_mutation.rs`)
//! since Phase 7D-10's sync-core deletion pass -- this crate no longer
//! depends on `yadorilink-sync-core`/`SyncState` at all, including in tests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_domain::session_state::{
    ChangeContent, DirtyPath, LocalFileMetaColumns, PreparedLocalMutation,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::SyncSqliteError;

#[derive(Clone, Copy)]
pub struct LocalChangeEmission<'a> {
    pub emitter: &'a ChangeEmitter,
    pub permit: &'a RootCommitPermit<'a>,
}

/// Capability surface `LocalChangeProcessor` needs to turn a detected local
/// filesystem event into a committed index row plus DAG change, and to
/// journal the attempt durably across the read/blockify/put/index+DAG step
/// so a crash or block-store fault cannot silently drop the edit.
pub trait LocalMutationStore: Send + Sync {
    /// Acquires the per-`(group_id, path)` lock serializing this local
    /// capture against a concurrent peer reconciliation of the same path.
    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>>;

    /// The current row for `path`, read before deciding whether a detected
    /// filesystem event actually represents new content.
    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncSqliteError>;

    /// The current row's authoring identity: which `Change` last authored
    /// it, if any. A precise "has anything committed a new version of this
    /// row since I last looked" signal — every commit (this device's own or
    /// a peer's) stamps a fresh, distinct hash, even when the new version's
    /// `FileRecord` fields (size/mtime/blocks) happen to coincide with the
    /// old one (a metadata-only change, or content that happens to hash the
    /// same). Used by batched-commit revalidation
    /// (`flush_pending_batch`) alongside [`Self::get_file`] rather than
    /// instead of it, since a `FileRecord` comparison alone cannot catch
    /// this case.
    fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError>;

    /// Bulk materialization-state lookup for a whole group — used by
    /// `scan_existing_files` so deciding whether an on-disk entry is a
    /// never-chunk placeholder costs one query for the whole scan.
    fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<HashMap<String, MaterializationState>, SyncSqliteError>;

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncSqliteError>;

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError>;

    /// Whether `(group_id, path)` still has an unsettled `projection_
    /// obligations` row -- distinct from `has_materialization_intent`
    /// above, which only covers the narrower window a
    /// `MaterializationIntentGuard` protects (a `materialize()` call
    /// already in flight). A path can have a durably-committed, non-deleted
    /// index row with an obligation that has not yet settled at all -- no
    /// intent has ever been opened for it, but it is just as much "we know
    /// about this file and are still placing it locally" as an in-flight
    /// intent is. An M5-A finding: the startup reconciliation scan's own
    /// `has_materialization_intent` check alone is not enough to protect
    /// this state; a newly-arrived DAG record whose obligation is still
    /// unsettled when a restart's scan runs was silently tombstoned before
    /// this check existed. While an obligation exists for a path, an
    /// absent local file must not yet be interpreted as an offline user
    /// deletion.
    fn has_unsettled_projection_obligation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError>;

    /// Bulk placeholder-identity lookup for a whole group -- used by
    /// `scan_existing_files` for the same reason as
    /// `list_materialization_states`: one query for the whole scan instead
    /// of one per file. Only paths whose row is currently `Placeholder`
    /// AND carries a recorded identity appear here -- see
    /// `MaterializationStateRepository::list_placeholder_generations`'s own
    /// doc comment for why the state gate matters.
    fn list_placeholder_generations(
        &self,
        group_id: &str,
    ) -> Result<
        HashMap<String, yadorilink_sync_sqlite::RecordedPlaceholderGeneration>,
        SyncSqliteError,
    >;

    fn get_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_sync_sqlite::RecordedPlaceholderGeneration>, SyncSqliteError>;

    /// M2-2: the ONLY way `local_change.rs`'s Windows dirty-detection
    /// verdict may be `Untouched` -- a live query against the real CfAPI
    /// placeholder at `path`, asking whether its OS-tracked
    /// `CF_PLACEHOLDER_STATE_IN_SYNC` bit is set AND its current
    /// `FileIdentity` still decodes to exactly `expected_generation`.
    /// Never a local heuristic (no size/mtime comparison anywhere in this
    /// call): any failure to confirm both -- the path isn't a real
    /// placeholder, the identity doesn't decode, the API call itself
    /// fails -- must come back as
    /// [`yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus::Unknown`],
    /// which every caller treats exactly like `Dirty` (fail-closed).
    ///
    /// `path` is the absolute on-disk path, not a `group_id`/relative-path
    /// pair like every other method on this trait -- this is a live OS
    /// call (`CreateFileW`+`CfGetPlaceholderInfo`), not an index query, so
    /// it needs the same real filesystem path `local_change.rs` already
    /// has in hand from its own `lstat`, not a re-resolution through the
    /// index.
    fn inspect_windows_placeholder(
        &self,
        path: &Path,
        expected_generation: u64,
    ) -> yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus;

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError>;

    fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError>;

    fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), SyncSqliteError>;

    fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), SyncSqliteError>;

    fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, SyncSqliteError>;

    /// See [`yadorilink_replica_domain::file::FileMeta::xattrs`]'s own doc
    /// comment -- the currently-indexed replicated extended attributes for
    /// `(group_id, path)`, empty for any row with none recorded.
    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SyncSqliteError>;

    /// M5-A review follow-up (blocker #56, second round): records the disk
    /// identity of the exact bytes a locally-authored commit just verified
    /// are on disk RIGHT NOW for this path -- called right after a
    /// successful local-edit commit (`upsert_file_emitting_change`/
    /// `upsert_files_batch`/their batch siblings), using the same fresh
    /// `disk_race_fingerprint` stat this scan already paid for. Without
    /// this, a version bump from an ordinary local edit silently drops the
    /// row back to "Hydrated with no proven fingerprint" -- the exact
    /// unproven state `hydrate_inner`'s already-Hydrated shortcut treats
    /// as safe to reconstruct over, reopening the clobber this fix exists
    /// to close for every file that has ever been locally edited even
    /// once. See `yadorilink_sync_sqlite::materialization_state::
    /// MaterializationStateRepository::record_materialized_fingerprint`'s
    /// own doc comment for the full reasoning.
    fn record_materialized_fingerprint(
        &self,
        group_id: &str,
        path: &str,
        fingerprint: Option<
            yadorilink_filesystem_sync::materialization_execution::MaterializedFingerprint,
        >,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// See [`get_xattrs`](Self::get_xattrs)'s own doc comment -- sets
    /// `(group_id, path)`'s replicated extended attributes.
    fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// The group's current heads — consulted when a detected local edit
    /// needs the change it emits to chain off the right parent.
    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError>;

    /// Commits a local create/update and appends the signed DAG change
    /// describing it, in one transaction — the primary write for a captured
    /// local edit.
    ///
    /// `filesystem_identity`: `Some` only when the caller has a strong
    /// `FileIdentity` freshly observed from the real path, immediately
    /// before this call, with disk fingerprint/index state/authoring
    /// identity all independently reconfirmed unchanged since the content
    /// was read — see `yadorilink_sync_sqlite::file_index::
    /// FileIndexRepository::upsert_file_emitting_change`'s own doc comment
    /// for the full precondition list and what passing `Some` here
    /// actually commits (an exact actual-state proof, in the SAME
    /// transaction, so the Convergence Engine's zero-work pre-check can
    /// recognize this device's own locally-authored content as already
    /// correct). `None` is always correct/safe — it simply forgoes that
    /// optimization for this call.
    fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        filesystem_identity: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        emission: LocalChangeEmission<'_>,
    ) -> Result<ChangeHash, SyncSqliteError>;

    /// Commits a bounded batch of already-prepared, already-revalidated
    /// local mutations in one transaction — the batched counterpart to
    /// [`Self::upsert_file_emitting_change`]/[`Self::mark_deleted_emitting_change`].
    /// See `yadorilink_sync_sqlite::file_index::FileIndexRepository::
    /// commit_local_mutations_batch`'s own doc for the correctness
    /// preconditions the caller must have already established (disk/index
    /// revalidation, path locks held for the whole call) before reaching
    /// this method — this trait cannot enforce either. `evidence`, when
    /// non-empty, must be aligned 1:1 with `mutations` — see that same
    /// method's own doc comment and
    /// `yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence`'s
    /// doc comment.
    fn commit_local_mutations_batch(
        &self,
        group_id: &str,
        mutations: &[PreparedLocalMutation],
        evidence: &[Option<yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence>],
        origin_device_id: &str,
        emission: LocalChangeEmission<'_>,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError>;

    /// Plain (non-emitting) upsert, used for local writes that do not need
    /// their own DAG change (e.g. metadata-only reconciliation writes local
    /// capture performs alongside a peer-authored row).
    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Batch upsert for an initial folder scan, one transaction per chunk —
    /// `scan_existing_files`'s bulk-write path.
    fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Batch upsert under a single DAG change, for a large initial scan that
    /// must emit history rather than write silently.
    fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        emission: LocalChangeEmission<'_>,
    ) -> Result<Option<ChangeHash>, SyncSqliteError>;

    /// Tombstones a path with "now" as the observed time — the plain local
    /// delete path when no debounce-recorded observation time applies.
    fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction — the debounced local-deletion dispatch path,
    /// which stamps the debounce accumulator's own observed time rather
    /// than "now at dispatch time" (see `mark_deleted_at`'s doc comment for
    /// why that distinction matters for conflict ordering).
    ///
    /// `publish_absent_proof`: `true` only when the caller has revalidated
    /// the path as still absent immediately before this call — commits an
    /// exact `Absent` actual-state proof in the SAME transaction, same
    /// reasoning as `upsert_file_emitting_change`'s `filesystem_identity`
    /// parameter. `false` is always correct/safe.
    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        publish_absent_proof: bool,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit<'_>,
    ) -> Result<ChangeHash, SyncSqliteError>;

    fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError>;

    /// Records blocks this device actually obtained by reading them off
    /// local disk during capture (as opposed to receiving them from a peer).
    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError>;

    /// Journals `path` as a detected-but-not-yet-processed local edit,
    /// before the read/blockify/put/index+DAG step runs, so a crash or fault
    /// mid-processing cannot drop the edit.
    fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Journals every `(path, change_kind, observed_at_unix_nanos)` in
    /// `entries` in one durable transaction, before any of their
    /// block-store/index work runs -- the batched form of
    /// [`Self::record_dirty_path`], letting a whole debounce-flush batch
    /// share one commit instead of paying one per path.
    fn record_dirty_paths_batch(
        &self,
        group_id: &str,
        entries: &[(String, String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Records that a processing attempt for `path` failed, leaving the
    /// dirty row in place for retry.
    fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Clears `path` from the dirty journal once its processing step has
    /// committed.
    fn clear_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Clears every `(path, observed_at_unix_nanos)` in `entries` from the
    /// dirty journal in one durable transaction, but only the exact
    /// observation each entry names -- the batched, conditional form of
    /// [`Self::clear_dirty_path`]. See the concrete `DirtyPathRepository`
    /// method of the same name for why the condition matters: it must never
    /// erase a newer, not-yet-processed event for the same path.
    fn clear_dirty_paths_conditional_batch(
        &self,
        group_id: &str,
        entries: &[(String, i64)],
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// Every currently journaled dirty path for `group_id`, oldest-first —
    /// the startup rescan worklist that re-drives edits a crash interrupted.
    fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError>;

    /// Every currently indexed file row for `group_id` — the baseline a
    /// disk-vs-index reconcile diffs against.
    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError>;

    /// Re-verifies an already-established root's identity, requiring the
    /// persisted root-identity token rather than silently adopting an
    /// unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::verify`].
    fn verify_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError>;

    /// Establishes a root's identity for the one-time initial scan, which
    /// may silently adopt an unmarked-but-corroborated root. See
    /// [`yadorilink_root_authority::root_identity::VerifiedRoot::open`].
    fn open_root(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<yadorilink_root_authority::root_identity::VerifiedRoot, SyncSqliteError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proves this crate's own `TestReplica` -- a thin wrapper around
    /// `yadorilink-daemon`'s `ReplicaCoordinator`, this trait's sole
    /// production implementor since Phase 7D-10's sync-core deletion (see
    /// `test_support`'s own doc comment for why the wrapper, not a bare
    /// `ReplicaCoordinator`, is needed from this crate's own internal
    /// `#[cfg(test)]` code) -- unsize-coerces a real `Arc<TestReplica>` to
    /// `Arc<dyn LocalMutationStore>`, and that calls through the coerced
    /// handle still dispatch to the real methods (both the infallible lock
    /// accessor and a fallible query against a real, empty in-memory index).
    #[test]
    fn arc_test_replica_coerces_to_port_trait() {
        use crate::test_support::TestReplica;

        let state: Arc<TestReplica> = Arc::new(TestReplica::open_in_memory().unwrap());
        let port: Arc<dyn LocalMutationStore> = state;

        let _lock = port.path_lock("group-a", "path/a.txt");
        assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
    }
}
