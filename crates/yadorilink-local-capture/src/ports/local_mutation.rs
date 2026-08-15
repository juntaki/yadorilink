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
use yadorilink_replica_domain::session_state::{ChangeContent, DirtyPath, LocalFileMetaColumns};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::SyncSqliteError;

#[derive(Clone, Copy)]
pub struct LocalChangeEmission<'a, 'permit> {
    pub emitter: &'a ChangeEmitter,
    pub permit: &'a RootCommitPermit<'permit>,
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

    /// Whether `(group_id, path)` has a non-terminal (not `Completed`/
    /// `Superseded`) row in the materialization job queue -- distinct from
    /// `has_materialization_intent` above, which only covers the narrower
    /// window a `MaterializationIntentGuard` protects (a `materialize()`
    /// call already in flight). A path can have a durably-committed,
    /// non-deleted index row with a QUEUED job that has not yet reached
    /// `materialize()` at all (e.g. still `Pending`/`Backoff` after a
    /// transient dispatch failure) -- no intent has ever been opened for
    /// it, but it is just as much "we know about this file and are still
    /// placing it locally" as an in-flight intent is. An M5-A finding: the
    /// startup reconciliation scan's own `has_materialization_intent` check
    /// alone is not enough to protect this state; a newly-arrived DAG
    /// record whose materialization job is still queued when a restart's
    /// scan runs was silently tombstoned before this check existed.
    fn has_pending_materialization_job(
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

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError>;

    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError>;

    /// The group's current heads — consulted when a detected local edit
    /// needs the change it emits to chain off the right parent.
    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError>;

    /// Commits a local create/update and appends the signed DAG change
    /// describing it, in one transaction — the primary write for a captured
    /// local edit.
    fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        emission: LocalChangeEmission<'_, '_>,
    ) -> Result<ChangeHash, SyncSqliteError>;

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
        emission: LocalChangeEmission<'_, '_>,
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
    fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
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
