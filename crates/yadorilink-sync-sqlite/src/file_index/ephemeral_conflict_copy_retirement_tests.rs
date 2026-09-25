#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";

/// Full schema: DAG tables first (`yadorilink_sqlite_runtime::init_schema`
/// assumes `changes`/`pruned_changes` already exist, per its own doc
/// comment), then the real `files` table with its authoring-identity
/// triggers -- the identical pattern `materialization_state.rs`'s
/// `held_state_tests::open_full_test_db` already uses for the same
/// reason.
fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            dag_store::init_conflict_copy_provenance_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            // Reached by `upsert_files_batch` below: a scanned record
            // with no observed identity retires whatever actual-state
            // proof the path already had, which needs the fence table
            // production always opens.
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn permit() -> RootCommitPermit<'static> {
    RootCommitPermit::for_tests()
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

/// Admits one real, signed DAG change touching an unrelated path --
/// enough to make `EXISTS(SELECT 1 FROM changes WHERE group_id = ...)`
/// true for this group, which is the trigger's own precondition (it is
/// scoped to the whole group, not to the specific path being written).
fn admit_one_real_change(db: &SyncDatabase) {
    db.write::<_, SyncSqliteError>(|conn| {
        let version = FileVersion::new(
            Vec::<VersionBlock>::new(),
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        dag_store::put_file_version(conn, GROUP, &version)?;
        let change = create_signed_for_tests(
            vec![],
            0,
            DeviceId("device-real".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath("unrelated.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key(1),
        );
        let result = dag_store::admit_change(conn, &change)?;
        assert_eq!(result.outcome, dag_store::AdmitOutcome::Applied, "admission must succeed");
        Ok(())
    })
    .unwrap();
}

const EPHEMERAL_PATH: &str = "shared (conflicted copy, 1970-01-01-000000, device-3, aabbccdd).bin";

/// Pins the rejection of the write shape a `materialize_tombstone(...,
/// None, ...)` call from `retire_unjustified_ephemeral_conflict_copies`
/// would produce -- a fresh 'current' tombstone row for a path no admitted
/// change has ever touched, with no authoring identity -- once the group
/// already has DAG history. It must be rejected, not silently accepted
/// with a corrupt authoring identity.
#[test]
fn a_tombstone_upsert_with_no_authoring_identity_is_rejected_once_the_group_has_dag_history() {
    let db = open_full_test_db();
    admit_one_real_change(&db);
    let repo = FileIndexRepository::new(db.clone());

    let tombstone = FileRecord {
        path: EPHEMERAL_PATH.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: true,
    };
    let err = repo.upsert_file_with_origin(GROUP, &tombstone, "device-0", &permit()).expect_err(
        "a fresh 'current' row with no authoring identity must be rejected once this \
             group has DAG history -- the exact failure retirement's old tombstone call hit",
    );
    assert!(
        err.to_string().contains("requires verified authoring identity"),
        "unexpected error: {err}"
    );
    assert!(
        repo.get_file(GROUP, EPHEMERAL_PATH).unwrap().is_none(),
        "the rejected write must leave no partial row behind"
    );
}

/// GREEN: `remove_file` -- the fix's actual code path, via `erase_local_
/// only_file` -- retires the identical shape (a live, non-DAG-backed
/// row) cleanly, needing no authoring identity at all, because it erases
/// the row instead of asserting a tombstone fact the DAG never backed.
#[test]
fn remove_file_retires_a_non_dag_backed_row_with_no_authoring_identity() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    // Created BEFORE any DAG history exists in the group, exactly like
    // the old ephemeral projection fixpoint's own local-only writes
    // (`dag_store::conflict_authoring`'s own module doc) -- these never
    // carry a real authoring identity either.
    let live_copy = FileRecord {
        path: EPHEMERAL_PATH.to_string(),
        size: 4,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    repo.upsert_file_with_origin(GROUP, &live_copy, "device-3", &permit()).unwrap();

    // History now exists -- exactly the condition that makes the
    // test's tombstone-upsert attempt fail -- but erasure needs no
    // authoring identity at all.
    admit_one_real_change(&db);

    let removed = repo.remove_file(GROUP, EPHEMERAL_PATH, &permit()).unwrap();
    assert!(removed, "remove_file must report that a row was actually erased");
    assert!(
        repo.get_file(GROUP, EPHEMERAL_PATH).unwrap().is_none(),
        "the row must be gone, not tombstoned"
    );
}

/// Pins the authoring-identity transition across a group's first DAG
/// change. `upsert_files_batch` is the real production API
/// `reconcile_disk_with_ignore` calls for a brand-new link's first scan
/// while the group's DAG is still empty (`yadorilink-local-capture`'s
/// own doc comment: "A group whose DAG is still empty is deliberately
/// left to the chunked initial import that runs right after the scan").
/// It writes `authoring_change_hash: None` deliberately, because the
/// trigger's own WHEN clause does not fire yet -- there is no
/// `changes`/`pruned_changes` row for the group at all. Nothing revisits
/// that row once the group's first DAG change is admitted through a
/// separate path. The row is left exactly as valid SQL, exactly as
/// `files_require_authoring_identity_on_insert`'s WHEN clause allowed at
/// the time -- and exactly what the next whole-database `init_schema`
/// pass (run unconditionally on every real `SyncDatabase::open`) now
/// rejects.
#[test]
fn a_files_row_from_upsert_files_batch_before_dag_history_fails_the_next_schema_init() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    // Steps 2-4: a legitimate `files` row, `version_seq > 0`, written
    // through the real "first scan of a brand-new link" API while the
    // group's DAG is still empty. Accepted -- correctly, for the state
    // as it is right then.
    let record = FileRecord {
        path: "bulk-scanned.txt".to_string(),
        size: 5,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    repo.upsert_files_batch(GROUP, &[record], "device-0", &[], &[], &permit())
        .expect("accepted while the group's DAG is still empty");
    assert!(repo.get_file(GROUP, "bulk-scanned.txt").unwrap().is_some());

    // Step 5/6: the group's first real, admitted DAG change, through a
    // wholly unrelated path -- the row above is never touched again.
    admit_one_real_change(&db);

    // Step 7: the real whole-database integrity check every
    // `SyncDatabase::open` runs as part of `init_schema`, re-invoked on
    // the same connection -- the identical check a real process
    // restart performs via `SyncDatabase::open`'s own `schema_init`
    // callback, not a substitute for it.
    let result: Result<(), SyncSqliteError> = db.write(|conn| {
        yadorilink_sqlite_runtime::init_schema(conn)
            .map_err(|e| SyncSqliteError::CorruptState(e.to_string()))
    });

    // Step 8.
    let err = result.expect_err(
        "a files row admitted while the group's DAG was empty, left untouched once the \
         group became DAG-backed, must fail the next schema-init pass",
    );
    assert!(
        err.to_string().contains("lack verified authoring identity"),
        "unexpected error: {err}"
    );
}
