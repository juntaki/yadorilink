#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::recursive_operation::{
    EffectSetHash, RecursiveOperation, RecursiveOperationKind,
};
use yadorilink_replica_domain::test_authoring::{
    create_recursive_part_for_tests, create_signed_for_tests, reset_author_sequences,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";
const DEVICE: &str = "device-a";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            dag_store::init_conflict_copy_provenance_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

fn version() -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn record(path: &str, deleted: bool) -> FileRecord {
    FileRecord { path: path.into(), size: 0, mtime_unix_nanos: 0, blocks: Vec::new(), deleted }
}

fn admit(db: &SyncDatabase, change: &Change) {
    db.write::<_, SyncSqliteError>(|conn| {
        let result = dag_store::admit_change(conn, change)?;
        assert_eq!(result.outcome, dag_store::AdmitOutcome::Applied, "admission must succeed");
        Ok(())
    })
    .unwrap();
}

/// Writes `a/x`, `a/y` and `b` live, each authored by one admitted change,
/// and returns that change.
fn seed_live_files(db: &Arc<SyncDatabase>, repo: &FileIndexRepository) -> Change {
    let v = version();
    db.write::<_, SyncSqliteError>(|conn| dag_store::put_file_version(conn, GROUP, &v)).unwrap();
    let put = |path: &str| Op::Put {
        path: SyncPath(path.into()),
        version: v.version_hash,
        origin: PutOrigin::Direct,
    };
    let create = create_signed_for_tests(
        vec![],
        0,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![put("a/x"), put("a/y"), put("b")],
        &key(),
    );
    admit(db, &create);
    for path in ["a/x", "a/y", "b"] {
        repo.upsert_file_with_origin_and_author(
            GROUP,
            &record(path, false),
            DEVICE,
            &create.compute_hash(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    }
    create
}

#[test]
fn a_file_trashed_by_a_recursive_delete_names_that_operation() {
    reset_author_sequences();
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let create = seed_live_files(&db, &repo);

    let delete = |path: &str| Op::Delete { path: SyncPath(path.into()) };
    let effects = vec![delete("a/x"), delete("a/y")];
    let operation = RecursiveOperation {
        operation_id: RecursiveOperationId([0x42; 16]),
        kind: RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
        part_index: 0,
        part_count: 1,
        effect_set_hash: EffectSetHash::of_effects(&effects),
    };
    let rm = create_recursive_part_for_tests(
        vec![create.compute_hash()],
        create.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        operation,
        effects,
        &key(),
    );
    admit(&db, &rm);
    let plain = create_signed_for_tests(
        vec![rm.compute_hash()],
        rm.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![delete("b")],
        &key(),
    );
    admit(&db, &plain);
    for (path, by) in [("a/x", &rm), ("a/y", &rm), ("b", &plain)] {
        repo.upsert_file_with_origin_and_author(
            GROUP,
            &record(path, true),
            DEVICE,
            &by.compute_hash(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    }

    let operation_ref = RecursiveOperationRef {
        author: DeviceId(DEVICE.into()),
        operation_id: RecursiveOperationId([0x42; 16]),
    };
    let mut trashed = repo.list_trashed(GROUP).unwrap();
    trashed.sort_by(|x, y| x.path.cmp(&y.path));
    assert_eq!(
        trashed
            .iter()
            .map(|t| (t.path.as_str(), t.deleted_by_operation.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("a/x", Some(operation_ref.clone())),
            ("a/y", Some(operation_ref.clone())),
            ("b", None),
        ]
    );
    let restore_set = repo.list_trashed_by_recursive_operation(GROUP, &operation_ref).unwrap();
    assert_eq!(restore_set.iter().map(|t| t.path.as_str()).collect::<Vec<_>>(), vec!["a/x", "a/y"]);
}

fn operation_ref() -> RecursiveOperationRef {
    RecursiveOperationRef {
        author: DeviceId(DEVICE.into()),
        operation_id: RecursiveOperationId([0x42; 16]),
    }
}

/// `rm -rf a` over the seeded files as one part, then `a/x` and `a/y`
/// tombstoned by it. Returns the part.
fn rm_tree_a(db: &Arc<SyncDatabase>, repo: &FileIndexRepository, after: &Change) -> Change {
    let delete = |path: &str| Op::Delete { path: SyncPath(path.into()) };
    let effects = vec![delete("a/x"), delete("a/y")];
    let rm = create_recursive_part_for_tests(
        vec![after.compute_hash()],
        after.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        RecursiveOperation {
            operation_id: RecursiveOperationId([0x42; 16]),
            kind: RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
            part_index: 0,
            part_count: 1,
            effect_set_hash: EffectSetHash::of_effects(&effects),
        },
        effects,
        &key(),
    );
    admit(db, &rm);
    for path in ["a/x", "a/y"] {
        repo.upsert_file_with_origin_and_author(
            GROUP,
            &record(path, true),
            DEVICE,
            &rm.compute_hash(),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    }
    rm
}

/// A path the operation deleted, then restored, edited and deleted again by
/// something else, is no longer the operation's to restore: its latest
/// trashed version is the later one, and putting back the operation's older
/// version would lose the edit.
#[test]
fn a_path_deleted_again_after_a_restore_leaves_the_operations_set() {
    reset_author_sequences();
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let create = seed_live_files(&db, &repo);
    let rm = rm_tree_a(&db, &repo, &create);

    let v = version();
    let restore = create_signed_for_tests(
        vec![rm.compute_hash()],
        rm.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Put {
            path: SyncPath("a/x".into()),
            version: v.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key(),
    );
    admit(&db, &restore);
    repo.upsert_file_with_origin_and_author(
        GROUP,
        &FileRecord { size: 7, ..record("a/x", false) },
        DEVICE,
        &restore.compute_hash(),
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    let delete_again = create_signed_for_tests(
        vec![restore.compute_hash()],
        restore.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Delete { path: SyncPath("a/x".into()) }],
        &key(),
    );
    admit(&db, &delete_again);
    repo.upsert_file_with_origin_and_author(
        GROUP,
        &record("a/x", true),
        DEVICE,
        &delete_again.compute_hash(),
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    let restore_set = repo.list_trashed_by_recursive_operation(GROUP, &operation_ref()).unwrap();
    assert_eq!(restore_set.iter().map(|t| t.path.as_str()).collect::<Vec<_>>(), vec!["a/y"]);
    let trashed = repo.list_trashed(GROUP).unwrap();
    let x = trashed.iter().find(|t| t.path == "a/x").unwrap();
    assert_eq!((x.last_known_size, x.deleted_by_operation.clone()), (7, None));
}

/// The set is read from the trashed rows, so it is still there once the
/// change that deleted them has been compacted away.
#[test]
fn the_operations_set_outlives_its_compacted_part() {
    reset_author_sequences();
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let create = seed_live_files(&db, &repo);
    let rm = rm_tree_a(&db, &repo, &create);
    let later = create_signed_for_tests(
        vec![rm.compute_hash()],
        rm.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Delete { path: SyncPath("elsewhere".into()) }],
        &key(),
    );
    admit(&db, &later);

    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId(GROUP.into()),
        vec![later.compute_hash()],
        [0u8; 32],
    );
    db.write::<_, SyncSqliteError>(|conn| {
        dag_store::commit_prune(conn, &checkpoint, &[create.compute_hash(), rm.compute_hash()])
    })
    .unwrap();
    let rm_held = db
        .read::<_, SyncSqliteError>(|conn| dag_store::has_change(conn, &rm.compute_hash()))
        .unwrap();
    assert!(!rm_held, "the part's change is compacted away");

    let restore_set = repo.list_trashed_by_recursive_operation(GROUP, &operation_ref()).unwrap();
    assert_eq!(restore_set.iter().map(|t| t.path.as_str()).collect::<Vec<_>>(), vec!["a/x", "a/y"]);
}
