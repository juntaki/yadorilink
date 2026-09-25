#![cfg(test)]
//! Restoring a trashed entry into a tree that changed shape since it was
//! deleted.
//!
//! The restore puts the entry back into the replicated state. Where it
//! lands on disk is the namespace's to decide, exactly as for any other
//! change: a file whose path now has to be a directory (something lives
//! below it) is placed beside that directory under its conflict-copy name,
//! and a file whose ancestor is now a file of its own makes that ancestor
//! the directory and moves the ancestor file aside. Neither the restored
//! entry nor what now occupies its path is lost, and the restore never
//! writes over a directory or through a file.

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};
use yadorilink_replica_engine::namespace::{PhysicalNode, Placement};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::desired_state::DesiredPathState;

const GROUP: &str = "group-1";

struct Fixture {
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
        let sync_state =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-under-test".to_string(), sync_state, store);
        state.set_device_signing_key(SigningKey::from_bytes(&[31u8; 32]));
        state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().to_string();
        state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
        state.install_test_root_commit_authority(GROUP);
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();
        Self { state, root, _store_dir: store_dir }
    }

    fn path(&self, rel: &str) -> std::path::PathBuf {
        self.root.path().join(rel)
    }

    /// Stores `bytes` as a block this device holds and returns the row a
    /// file of that content indexes as, plus its version.
    fn content(&self, path: &str, bytes: &[u8]) -> (FileRecord, FileVersion) {
        let hash = self.state.block_store.put(bytes).unwrap();
        let hash_bytes = hex::decode(&hash).unwrap();
        self.state
            .replica_coordinator
            .change_history_repository()
            .record_group_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
            .unwrap();
        let block = BlockInfo { hash: hash_bytes, offset: 0, size: bytes.len() as u32 };
        let record = FileRecord {
            path: path.to_string(),
            size: bytes.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![block.clone()],
            deleted: false,
        };
        let version = FileVersion::from_index_row(
            vec![block],
            bytes.len() as u64,
            0,
            RecordKind::File,
            None,
            None,
            Vec::new(),
        );
        (record, version)
    }

    /// A peer's change carrying `ops`, on top of everything held here.
    fn peer_change(&self, ops: Vec<Op>, versions: &[&FileVersion]) -> ChangeHash {
        let peer = ChangeEmitter::new("device-peer", SigningKey::from_bytes(&[9u8; 32]));
        let parents = self.state.replica_coordinator.dag_group_heads(GROUP).unwrap();
        self.state
            .replica_coordinator
            .database()
            .write(|conn| {
                for version in versions {
                    yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
                }
                yadorilink_sync_sqlite::dag_store::emit_local_change_onto(
                    conn,
                    GROUP,
                    parents.clone(),
                    ops.clone(),
                    &peer,
                )
            })
            .unwrap()
            .compute_hash()
    }

    /// Projects `change`'s effect at `record.path` into the index, as
    /// materializing it would.
    fn index(&self, record: &FileRecord, change: &ChangeHash) {
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        self.state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin_and_author(GROUP, record, "device-peer", change, &permit)
            .unwrap();
    }

    fn index_deleted(&self, path: &str, change: &ChangeHash) {
        let mut record = self
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, path)
            .unwrap()
            .expect("a live row to delete");
        record.deleted = true;
        record.mtime_unix_nanos = 1;
        self.index(&record, change);
    }

    fn desired(&self, path: &str) -> DesiredPathState {
        self.state.replica_coordinator.sqlite().dag_desired_path_state(GROUP, path).unwrap()
    }

    /// The version this device's restore put at `path`: its own live head
    /// there.
    fn restored_version_at(&self, path: &str) -> [u8; 32] {
        let heads = self
            .state
            .replica_coordinator
            .change_history_repository()
            .dag_path_live_heads(GROUP, path)
            .unwrap();
        assert_eq!(heads.len(), 1, "the restore is authored on top of every head: {heads:?}");
        assert_eq!(heads[0].device_id, "device-under-test", "the live head is the restore's");
        heads[0].content.as_ref().expect("the restore puts content").version_hash
    }

    /// The restored entry's placement is left to the ordinary projection:
    /// its obligation is open for the Convergence Engine.
    fn placement_is_owed(&self, path: &str) {
        let obligation = self
            .state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, path)
            .unwrap()
            .expect("the restore's change opened an obligation");
        assert_eq!(obligation.state, "pending", "{obligation:?}");
    }

    fn no_restore_left_journaled(&self) {
        let journal = self
            .state
            .replica_coordinator
            .restore_operation_repository()
            .list_restore_operations(GROUP)
            .unwrap();
        assert!(journal.is_empty(), "nothing is left for startup recovery: {journal:?}");
    }
}

fn put(path: &str, version: &FileVersion) -> Op {
    Op::Put {
        path: SyncPath(path.into()),
        version: VersionHash(version.version_hash.0),
        origin: PutOrigin::Direct,
    }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

/// File `a` was deleted; since then a peer's `a/x` made `a` a directory.
/// Restoring `a` brings the file back beside the directory, under its
/// conflict-copy name, and leaves the directory and `a/x` alone.
#[tokio::test]
async fn restore_trashed_file_whose_path_is_now_a_structural_directory_keeps_both() {
    let f = Fixture::new();
    let (a_row, a_version) = f.content("a", b"the file that was deleted");
    let (x_row, x_version) = f.content("a/x", b"what lives below a now");
    let c = f.peer_change(vec![put("a", &a_version)], &[&a_version]);
    f.index(&a_row, &c);
    let c = f.peer_change(vec![delete("a")], &[]);
    f.index_deleted("a", &c);
    let c = f.peer_change(vec![put("a/x", &x_version)], &[&x_version]);
    f.index(&x_row, &c);
    std::fs::create_dir(f.path("a")).unwrap();
    std::fs::write(f.path("a/x"), b"what lives below a now").unwrap();

    restore_trashed(&f.state, GROUP, "a").await.expect("the restore is accepted");

    assert!(std::fs::symlink_metadata(f.path("a")).unwrap().is_dir(), "a stays a directory");
    assert_eq!(std::fs::read(f.path("a/x")).unwrap(), b"what lives below a now");
    let restored = f.restored_version_at("a");
    assert_eq!(f.desired("a"), DesiredPathState::StructuralDirectory);
    let root_level =
        f.state.replica_coordinator.sqlite().dag_desired_level_projection(GROUP, "").unwrap();
    let relocated: Vec<_> = root_level
        .nodes()
        .iter()
        .filter_map(|(path, node)| match node {
            PhysicalNode::Entry(entry) if entry.source == "a" => {
                Some((path.clone(), entry.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(relocated.len(), 1, "{relocated:?}");
    assert_eq!(relocated[0].1.version_hash, restored);
    assert!(matches!(relocated[0].1.placement, Placement::Relocated), "{relocated:?}");
    f.no_restore_left_journaled();
    f.placement_is_owed("a");
}

/// `a/x` was deleted; since then `a` became a file. Restoring `a/x` makes
/// `a` the directory holding it and moves the file `a` aside -- the
/// restore itself writes neither through the file nor over it.
#[tokio::test]
async fn restore_trashed_child_under_a_live_file_ancestor_keeps_both() {
    let f = Fixture::new();
    let (x_row, x_version) = f.content("a/x", b"the child that was deleted");
    let (a_row, a_version) = f.content("a", b"the file a became");
    let c = f.peer_change(vec![put("a/x", &x_version)], &[&x_version]);
    f.index(&x_row, &c);
    let c = f.peer_change(vec![delete("a/x")], &[]);
    f.index_deleted("a/x", &c);
    let c = f.peer_change(vec![put("a", &a_version)], &[&a_version]);
    f.index(&a_row, &c);
    std::fs::write(f.path("a"), b"the file a became").unwrap();

    restore_trashed(&f.state, GROUP, "a/x").await.expect("the restore is accepted");

    assert_eq!(
        std::fs::read(f.path("a")).unwrap(),
        b"the file a became",
        "the restore does not touch the file in the way"
    );
    let restored = f.restored_version_at("a/x");
    assert_eq!(
        f.desired("a/x"),
        DesiredPathState::Entry { kind: RecordKind::File, version: VersionHash(restored) }
    );
    assert_eq!(f.desired("a"), DesiredPathState::StructuralDirectory);
    f.no_restore_left_journaled();
    f.placement_is_owed("a/x");
}

const RM_AUTHOR: &str = "device-rm-author";

fn rm_author_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

impl Fixture {
    fn admit(&self, change: &yadorilink_replica_domain::change::Change) -> ChangeHash {
        self.state
            .replica_coordinator
            .database()
            .write(|conn| {
                let result = yadorilink_sync_sqlite::dag_store::admit_change(conn, change)?;
                assert_eq!(
                    result.outcome,
                    yadorilink_sync_sqlite::dag_store::AdmitOutcome::Applied
                );
                Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        change.compute_hash()
    }

    fn trashed_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .state
            .replica_coordinator
            .file_index_repository()
            .list_trashed(GROUP)
            .unwrap()
            .into_iter()
            .map(|t| t.path)
            .collect();
        paths.sort();
        paths
    }
}

/// `album/a.jpg`, `album/b.jpg` and `other.txt` live; then `rm -rf album`
/// as a recursive operation of `part_count` parts, of which only the first
/// is here, removing the album files it lists; and `other.txt` deleted on
/// its own. Returns the album files the recorded part removed.
fn seed_recursive_delete(f: &Fixture, part_count: u32) -> Vec<&'static str> {
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
    use yadorilink_replica_domain::recursive_operation::{
        EffectSetHash, RecursiveOperation, RecursiveOperationId, RecursiveOperationKind,
    };
    use yadorilink_replica_domain::test_authoring::{
        create_recursive_part_for_tests, create_signed_for_tests,
    };
    let files = ["album/a.jpg", "album/b.jpg", "other.txt"];
    let contents: Vec<(FileRecord, FileVersion)> =
        files.iter().map(|path| f.content(path, format!("bytes of {path}").as_bytes())).collect();
    f.state
        .replica_coordinator
        .database()
        .write(|conn| {
            for (_, version) in &contents {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
    let create = create_signed_for_tests(
        vec![],
        0,
        DeviceId(RM_AUTHOR.into()),
        FolderGroupId(GROUP.into()),
        files.iter().zip(&contents).map(|(path, (_, version))| put(path, version)).collect(),
        &rm_author_key(),
    );
    let created = f.admit(&create);
    for (record, _) in &contents {
        f.index(record, &created);
    }
    // Every part lists the whole observed set's hash; this device holds
    // only the part that removes the two album files.
    let removed = vec!["album/a.jpg", "album/b.jpg"];
    let effects: Vec<Op> = removed.iter().map(|path| delete(path)).collect();
    let mut observed = effects.clone();
    if part_count > 1 {
        observed.push(delete("album/c.jpg"));
    }
    let rm = create_recursive_part_for_tests(
        vec![created],
        create.lamport,
        DeviceId(RM_AUTHOR.into()),
        FolderGroupId(GROUP.into()),
        RecursiveOperation {
            operation_id: RecursiveOperationId([0x42; 16]),
            kind: RecursiveOperationKind::RmTree { root: SyncPath("album".into()) },
            part_index: 0,
            part_count,
            effect_set_hash: EffectSetHash::of_effects(&observed),
        },
        effects,
        &rm_author_key(),
    );
    let rm_hash = f.admit(&rm);
    for path in &removed {
        f.index_deleted(path, &rm_hash);
    }
    let plain = create_signed_for_tests(
        vec![rm_hash],
        rm.lamport,
        DeviceId(RM_AUTHOR.into()),
        FolderGroupId(GROUP.into()),
        vec![delete("other.txt")],
        &rm_author_key(),
    );
    let plain_hash = f.admit(&plain);
    f.index_deleted("other.txt", &plain_hash);
    removed
}

/// A folder restore puts back every entry the recursive delete that
/// removed the named one removed -- read from the trashed versions
/// themselves -- and nothing another delete removed.
#[tokio::test]
async fn restore_trashed_operation_restores_every_entry_the_recursive_delete_removed() {
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let f = Fixture::new();
    let removed = seed_recursive_delete(&f, 1);

    let outcome = restore_trashed_operation(&f.state, GROUP, "album/b.jpg")
        .await
        .expect("the folder restore runs");

    assert_eq!(outcome.restored, removed);
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert!(!outcome.partial, "every part of the operation is here");
    for path in &removed {
        assert_eq!(std::fs::read(f.path(path)).unwrap(), format!("bytes of {path}").as_bytes());
    }
    assert_eq!(f.trashed_paths(), vec!["other.txt".to_string()]);
}

/// Parts of the operation this device has not received are not guessed
/// at: the restore puts back what the recorded parts removed and says it
/// is partial.
#[tokio::test]
async fn a_folder_restore_missing_a_part_of_its_operation_reports_partial() {
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let f = Fixture::new();
    let removed = seed_recursive_delete(&f, 2);

    let outcome = restore_trashed_operation(&f.state, GROUP, "album/a.jpg")
        .await
        .expect("the folder restore runs");

    assert_eq!(outcome.restored, removed);
    assert!(outcome.partial, "one of the operation's two parts never arrived");
}

/// An entry not removed by a recursive operation has no folder to restore.
#[tokio::test]
async fn a_folder_restore_of_an_entry_deleted_on_its_own_is_refused() {
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let f = Fixture::new();
    seed_recursive_delete(&f, 1);

    let error = restore_trashed_operation(&f.state, GROUP, "other.txt")
        .await
        .expect_err("other.txt was deleted on its own");
    assert!(matches!(error, SyncError::NotFound(_)), "{error:?}");
    assert_eq!(
        f.trashed_paths(),
        vec!["album/a.jpg".to_string(), "album/b.jpg".to_string(), "other.txt".to_string()],
        "a refused folder restore restores nothing"
    );
}

impl Fixture {
    fn set_kind(&self, path: &str, kind: RecordKind) {
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        self.state
            .replica_coordinator
            .file_index_repository()
            .set_record_kind(GROUP, path, kind, &permit)
            .unwrap();
    }

    /// The `version_seq` of `path`'s one retained, non-deleted version of
    /// `kind`.
    fn version_seq_of_kind(&self, path: &str, kind: RecordKind) -> i64 {
        let versions: Vec<_> = self
            .state
            .replica_coordinator
            .sqlite()
            .dag_list_versions(GROUP, path)
            .unwrap()
            .into_iter()
            .filter(|v| v.record_kind == kind && !v.deleted)
            .collect();
        assert_eq!(versions.len(), 1, "{versions:?}");
        versions[0].version_seq
    }
}

fn directory_version() -> (FileVersion, FileRecord) {
    let version = FileVersion::from_index_row(
        Vec::new(),
        0,
        0,
        RecordKind::Directory,
        None,
        None,
        Vec::new(),
    );
    let record = FileRecord {
        path: String::new(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    (version, record)
}

/// Directory `a` was deleted; since then a peer made `a` a file. Restoring
/// the directory's version supersedes the file in the history, and where
/// the directory lands -- the file is in its way -- is the projection's
/// to settle. The restore neither fails on the file after its change is
/// live nor writes anything itself.
#[tokio::test]
async fn restore_directory_over_a_synced_file_at_its_path_is_left_to_the_projection() {
    let f = Fixture::new();
    let (dir_version, mut dir_row) = directory_version();
    dir_row.path = "a".into();
    let (file_row, file_version) = f.content("a", b"the file a became");
    let c = f.peer_change(vec![put("a", &dir_version)], &[&dir_version]);
    f.index(&dir_row, &c);
    f.set_kind("a", RecordKind::Directory);
    let c = f.peer_change(vec![delete("a")], &[]);
    f.index_deleted("a", &c);
    let c = f.peer_change(vec![put("a", &file_version)], &[&file_version]);
    f.index(&file_row, &c);
    f.set_kind("a", RecordKind::File);
    std::fs::write(f.path("a"), b"the file a became").unwrap();
    let dir_seq = f.version_seq_of_kind("a", RecordKind::Directory);

    restore_to_version(&f.state, GROUP, "a", dir_seq)
        .await
        .expect("the restore is accepted, not failed after its change is live");

    assert_eq!(
        std::fs::read(f.path("a")).unwrap(),
        b"the file a became",
        "the restore does not write over or through the file in the way"
    );
    let restored = f.restored_version_at("a");
    assert_eq!(
        f.desired("a"),
        DesiredPathState::ExplicitDirectory { version: VersionHash(restored) }
    );
    f.no_restore_left_journaled();
    f.placement_is_owed("a");
}

/// The decision that a restore is the projection's to place is taken in
/// the transaction that authors its change, and that transaction writes no
/// journal row for it: there is no moment at which a crash leaves startup
/// recovery a row for a write that was never going to happen (whose path
/// may run through a file, which recovery's write-target check refuses).
/// A restore the namespace keeps at its own path is journaled as before.
#[tokio::test]
async fn a_restore_left_to_the_projection_is_never_journaled() {
    use yadorilink_replica_domain::session_state::{
        LocalFileMetaColumns, RestoreOperation, RestoreOperationState,
    };
    use yadorilink_sync_sqlite::restore_operation::RestorePlacement;
    let f = Fixture::new();
    let (x_row, x_version) = f.content("a/x", b"the child that was deleted");
    let (a_row, a_version) = f.content("a", b"the file a became");
    let c = f.peer_change(vec![put("a/x", &x_version)], &[&x_version]);
    f.index(&x_row, &c);
    let c = f.peer_change(vec![delete("a/x")], &[]);
    f.index_deleted("a/x", &c);
    let c = f.peer_change(vec![put("a", &a_version)], &[&a_version]);
    f.index(&a_row, &c);
    let (b_row, b_version) = f.content("b", b"a file restored where nothing is in the way");

    let emitter = ChangeEmitter::new("device-under-test", SigningKey::from_bytes(&[31u8; 32]));
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let record = |path: &str, row: &FileRecord| {
        let mut row = row.clone();
        row.path = path.into();
        RestoreOperation {
            operation_id: format!("op-{path}"),
            group_id: GROUP.into(),
            path: path.into(),
            target_version_seq: 1,
            expected_current_version_seq: None,
            state: RestoreOperationState::Prepared,
            record: row,
            origin_device_id: "device-under-test".into(),
            authoring_change_hash: None,
            meta: LocalFileMetaColumns {
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: None,
                xattrs: Vec::new(),
            },
        }
    };

    // The synced file `a` in the way on disk hands `a/x` to the projection.
    let (_, placement) = f
        .state
        .replica_coordinator
        .record_restore_placing(&record("a/x", &x_row), &x_version, &emitter, &permit, false)
        .unwrap();
    assert_eq!(placement, RestorePlacement::Projection);
    f.no_restore_left_journaled();

    let (_, placement) = f
        .state
        .replica_coordinator
        .record_restore_placing(&record("b", &b_row), &b_version, &emitter, &permit, true)
        .unwrap();
    assert_eq!(placement, RestorePlacement::InPlace);
    let journal = f
        .state
        .replica_coordinator
        .restore_operation_repository()
        .list_restore_operations(GROUP)
        .unwrap();
    assert_eq!(journal.iter().map(|op| op.path.as_str()).collect::<Vec<_>>(), vec!["b"]);
}

/// A restore the projection places is done as far as the trash is
/// concerned: the entry is live in the history, so it is no longer listed
/// as trashed, and restoring it again finds nothing to restore rather than
/// authoring a second change.
#[tokio::test]
async fn a_restore_left_to_the_projection_leaves_the_trash() {
    let f = Fixture::new();
    let (a_row, a_version) = f.content("a", b"the file that was deleted");
    let (x_row, x_version) = f.content("a/x", b"what lives below a now");
    let c = f.peer_change(vec![put("a", &a_version)], &[&a_version]);
    f.index(&a_row, &c);
    let c = f.peer_change(vec![delete("a")], &[]);
    f.index_deleted("a", &c);
    let c = f.peer_change(vec![put("a/x", &x_version)], &[&x_version]);
    f.index(&x_row, &c);
    std::fs::create_dir(f.path("a")).unwrap();
    std::fs::write(f.path("a/x"), b"what lives below a now").unwrap();
    assert_eq!(f.trashed_paths(), vec!["a".to_string()]);

    restore_trashed(&f.state, GROUP, "a").await.expect("the restore is accepted");

    assert!(f.trashed_paths().is_empty(), "{:?}", f.trashed_paths());
    let again = restore_trashed(&f.state, GROUP, "a").await.expect_err("nothing left to restore");
    assert!(matches!(again, SyncError::NotFound(_)), "{again:?}");
    f.restored_version_at("a");
}

/// Admits one recursive-operation part by the rm author, carrying all of
/// `effects` (the whole observed set), on top of `parents`.
fn recursive_part(
    f: &Fixture,
    parents: Vec<ChangeHash>,
    lamport: u64,
    kind: yadorilink_replica_domain::recursive_operation::RecursiveOperationKind,
    effects: Vec<Op>,
) -> (ChangeHash, u64) {
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
    use yadorilink_replica_domain::recursive_operation::{
        EffectSetHash, RecursiveOperation, RecursiveOperationId,
    };
    let part = yadorilink_replica_domain::test_authoring::create_recursive_part_for_tests(
        parents,
        lamport,
        DeviceId(RM_AUTHOR.into()),
        FolderGroupId(GROUP.into()),
        RecursiveOperation {
            operation_id: RecursiveOperationId([0x43; 16]),
            kind,
            part_index: 0,
            part_count: 1,
            effect_set_hash: EffectSetHash::of_effects(&effects),
        },
        effects,
        &rm_author_key(),
    );
    (f.admit(&part), part.lamport)
}

/// The rm author's plain change creating `entries` (path, version).
fn create_entries(f: &Fixture, entries: &[(&str, &FileVersion)]) -> (ChangeHash, u64) {
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
    f.state
        .replica_coordinator
        .database()
        .write(|conn| {
            for (_, version) in entries {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
    let create = yadorilink_replica_domain::test_authoring::create_signed_for_tests(
        vec![],
        0,
        DeviceId(RM_AUTHOR.into()),
        FolderGroupId(GROUP.into()),
        entries.iter().map(|(path, version)| put(path, version)).collect(),
        &rm_author_key(),
    );
    (f.admit(&create), create.lamport)
}

/// `rm -rf album` removes the explicit `album` directory entry along with
/// the files in it. The directory's trashed version carries the operation
/// too, so the folder restore puts it back -- first, before what was
/// inside it -- as the explicit directory it was, and the files under it.
/// A directory the delete left on disk because it held content this device
/// never synced is restored where it stands, the local content kept,
/// and its status is the live entry's, not the retained one's.
#[tokio::test]
async fn a_folder_restore_puts_back_the_explicit_directory_the_recursive_delete_removed() {
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let f = Fixture::new();
    let (album_version, mut album_row) = directory_version();
    album_row.path = "album".into();
    let (a_row, a_version) = f.content("album/a.jpg", b"bytes of album/a.jpg");
    let (b_row, b_version) = f.content("album/b.jpg", b"bytes of album/b.jpg");
    let (created, lamport) = create_entries(
        &f,
        &[("album", &album_version), ("album/a.jpg", &a_version), ("album/b.jpg", &b_version)],
    );
    f.index(&album_row, &created);
    f.set_kind("album", RecordKind::Directory);
    f.index(&a_row, &created);
    f.index(&b_row, &created);
    let (rm, _) = recursive_part(
        &f,
        vec![created],
        lamport,
        RecursiveOperationKind::RmTree { root: SyncPath("album".into()) },
        vec![delete("album"), delete("album/a.jpg"), delete("album/b.jpg")],
    );
    for path in ["album/a.jpg", "album/b.jpg", "album"] {
        f.index_deleted(path, &rm);
    }
    // The delete kept `album` on disk for a file never synced.
    std::fs::create_dir(f.path("album")).unwrap();
    std::fs::write(f.path("album/notes.txt"), b"never synced").unwrap();
    f.state
        .replica_coordinator
        .sqlite()
        .record_retained_directory(
            GROUP,
            "album",
            yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT,
            None,
            1,
        )
        .unwrap();
    let trashed = f.state.replica_coordinator.file_index_repository().list_trashed(GROUP).unwrap();
    let album = trashed.iter().find(|t| t.path == "album").expect("album is in the trash");
    assert_eq!(album.record_kind, RecordKind::Directory);
    assert!(album.deleted_by_operation.is_some(), "the directory's row names the operation");

    let outcome = restore_trashed_operation(&f.state, GROUP, "album/a.jpg")
        .await
        .expect("the folder restore runs");

    assert_eq!(outcome.restored, vec!["album", "album/a.jpg", "album/b.jpg"]);
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert!(!outcome.partial);
    assert!(std::fs::symlink_metadata(f.path("album")).unwrap().is_dir());
    assert_eq!(std::fs::read(f.path("album/a.jpg")).unwrap(), b"bytes of album/a.jpg");
    assert_eq!(std::fs::read(f.path("album/b.jpg")).unwrap(), b"bytes of album/b.jpg");
    assert_eq!(std::fs::read(f.path("album/notes.txt")).unwrap(), b"never synced");
    let restored = f.restored_version_at("album");
    assert_eq!(
        f.desired("album"),
        DesiredPathState::ExplicitDirectory { version: VersionHash(restored) }
    );
    assert!(f.trashed_paths().is_empty(), "{:?}", f.trashed_paths());
    let status = crate::shell_status::resolve_status_detail(
        &f.state.replica_coordinator,
        &f.path("album").to_string_lossy(),
    );
    assert_eq!(status.state, yadorilink_ipc_proto::shellipc::SyncState::Synced);
    assert_eq!(status.detail, None, "album is a live entry again, not a retained directory");
}

/// `mv album pics` as one rename operation: the sources are trashed by the
/// rename. A folder restore of them puts them back at their old paths,
/// beside the renamed directory -- a copy, not an undo of the rename:
/// `pics` and what is in it stay where they are.
#[tokio::test]
async fn a_folder_restore_of_a_directory_rename_puts_the_sources_back_beside_the_destination() {
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let f = Fixture::new();
    let (a_row, a_version) = f.content("album/a.jpg", b"bytes of a");
    let (b_row, b_version) = f.content("album/b.jpg", b"bytes of b");
    let (created, lamport) =
        create_entries(&f, &[("album/a.jpg", &a_version), ("album/b.jpg", &b_version)]);
    f.index(&a_row, &created);
    f.index(&b_row, &created);
    let (renamed, _) = recursive_part(
        &f,
        vec![created],
        lamport,
        RecursiveOperationKind::RenameTree {
            from: SyncPath("album".into()),
            to: SyncPath("pics".into()),
        },
        vec![
            delete("album/a.jpg"),
            delete("album/b.jpg"),
            put("pics/a.jpg", &a_version),
            put("pics/b.jpg", &b_version),
        ],
    );
    for path in ["album/a.jpg", "album/b.jpg"] {
        f.index_deleted(path, &renamed);
    }
    for (row, dest) in [(&a_row, "pics/a.jpg"), (&b_row, "pics/b.jpg")] {
        let mut row = row.clone();
        row.path = dest.into();
        f.index(&row, &renamed);
    }
    std::fs::create_dir(f.path("pics")).unwrap();
    std::fs::write(f.path("pics/a.jpg"), b"bytes of a").unwrap();
    std::fs::write(f.path("pics/b.jpg"), b"bytes of b").unwrap();

    let outcome = restore_trashed_operation(&f.state, GROUP, "album/b.jpg")
        .await
        .expect("the folder restore runs");

    assert_eq!(outcome.restored, vec!["album/a.jpg", "album/b.jpg"]);
    assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
    assert_eq!(std::fs::read(f.path("album/a.jpg")).unwrap(), b"bytes of a");
    assert_eq!(std::fs::read(f.path("album/b.jpg")).unwrap(), b"bytes of b");
    assert_eq!(std::fs::read(f.path("pics/a.jpg")).unwrap(), b"bytes of a");
    assert_eq!(std::fs::read(f.path("pics/b.jpg")).unwrap(), b"bytes of b");
    let index = f.state.replica_coordinator.file_index_repository();
    for dest in ["pics/a.jpg", "pics/b.jpg"] {
        assert!(index.get_file(GROUP, dest).unwrap().is_some_and(|row| !row.deleted), "{dest}");
    }
    assert!(f.trashed_paths().is_empty(), "{:?}", f.trashed_paths());
}
