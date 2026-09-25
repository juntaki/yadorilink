#![cfg(test)]

use super::*;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};

/// Full schema: DAG tables first (`yadorilink_sqlite_runtime::
/// init_schema` assumes `changes`/`pruned_changes` already exist, per
/// its own doc comment), then the real `files` table -- mirrors
/// `materialization_state.rs`'s own `held_state_tests::
/// open_full_test_db`.
fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn snapshot_file(path: &str) -> SnapshotFile {
    SnapshotFile {
        record: FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        },
        version_seq: 1,
        state: SnapshotVersionState::Current,
        origin_device_id: Some("device-a".to_string()),
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
        authoring_change_hash: None,
    }
}

/// The ninth route in the "row claims content is really on disk (or
/// genuinely needs protecting) but nothing protects it" bug family:
/// `SnapshotFile` (wire-derived, peer-shared) carries no held/pinned
/// fields at all, so a rebootstrap-snapshot install's DELETE+re-INSERT
/// of `files` must explicitly carry these purely-local columns
/// forward itself for a path that survives the install as a live
/// current row -- nothing else ever will.
#[test]
fn a_held_and_pinned_path_survives_a_snapshot_install() {
    let db = open_full_test_db();
    let repo = crate::materialization_state::MaterializationStateRepository::new(db.clone());
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
             VALUES ('group-1', 'held.txt', 0, 0, '[]')",
            [],
        )?;
        conn.execute(
            "UPDATE files SET pinned = 1 WHERE group_id = 'group-1' AND path = 'held.txt'",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    repo.set_held("group-1", "held.txt", "case_collision", 1000).unwrap();

    let files = vec![snapshot_file("held.txt")];
    db.write::<_, SyncSqliteError>(|conn| {
        replace_group_files_from_snapshot(conn, "group-1", &files)
    })
    .unwrap();

    assert_eq!(
        repo.get_held_state("group-1", "held.txt").unwrap().map(|h| h.reason),
        Some("case_collision".to_string()),
        "a hazard hold must survive a rebootstrap-snapshot install for a path the snapshot \
         still carries as a live current row"
    );
    let pinned: bool = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT pinned FROM files WHERE group_id = 'group-1' AND path = 'held.txt' \
                 AND state = 'current'",
                [],
                |r| r.get::<_, i64>(0),
            )? != 0)
        })
        .unwrap();
    assert!(pinned, "pinned must survive a rebootstrap-snapshot install the same way");
}

/// The inverse: a path the snapshot no longer carries as a live
/// current row must NOT resurrect a stale hold or pin -- there is no
/// live row left to protect, and the row is about to be classified
/// `hydrated`, not `placeholder`, by this same function's own
/// materialization_state branch just above. Covers both shapes of
/// "no longer live-current": entirely absent from the snapshot, and
/// present but as a `Current`-but-deleted tombstone -- the latter is
/// the one that actually exercises `is_live_current`'s own
/// `!file.record.deleted` half; the former never reaches that check
/// at all (the path is simply never visited by the insert loop),
/// which alone would not have caught a regression in that condition.
#[test]
fn a_held_path_the_snapshot_no_longer_carries_as_current_does_not_resurrect_the_hold() {
    let db = open_full_test_db();
    let repo = crate::materialization_state::MaterializationStateRepository::new(db.clone());
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
             VALUES ('group-1', 'gone.txt', 0, 0, '[]')",
            [],
        )?;
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json) \
             VALUES ('group-1', 'deleted-upstream.txt', 0, 0, '[]')",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    repo.set_held("group-1", "gone.txt", "case_collision", 1000).unwrap();
    repo.set_held("group-1", "deleted-upstream.txt", "case_collision", 1000).unwrap();

    // "gone.txt" is entirely absent from the incoming snapshot;
    // "deleted-upstream.txt" IS present, but as a Current-but-deleted
    // tombstone, not a live row -- the shape `is_live_current` itself
    // must refuse to treat as still needing hold/pin protection.
    let mut deleted_file = snapshot_file("deleted-upstream.txt");
    deleted_file.record.deleted = true;
    let files = vec![deleted_file];
    db.write::<_, SyncSqliteError>(|conn| {
        replace_group_files_from_snapshot(conn, "group-1", &files)
    })
    .unwrap();

    assert!(
        repo.get_held_state("group-1", "gone.txt").unwrap().is_none(),
        "a path the snapshot no longer mentions at all must not still read as held \
         afterward"
    );
    assert!(
        repo.get_held_state("group-1", "deleted-upstream.txt").unwrap().is_none(),
        "a path the snapshot now carries as a deleted tombstone must not still read as \
         held afterward"
    );
}

/// `pinned` and `held_reason` are captured under the same condition
/// but carried forward differently: a pin is path-keyed user intent,
/// not content-keyed, so it must survive a delete-then-resurrect at
/// this exact path the same way `upsert_file_in_tx`'s own ordinary
/// carry-forward already does unconditionally -- unlike a hold, which
/// is meaningless for a row this device itself already believes is
/// deleted, and so does NOT survive. This device had "gone-but-
/// pinned.txt" pinned and then (per its own local index) deleted it;
/// the incoming snapshot now resurrects that exact path as live
/// current content. The resurrected row must come back pinned; it
/// must NOT come back held.
#[test]
fn a_pin_survives_a_delete_then_resurrect_but_a_hold_does_not() {
    let db = open_full_test_db();
    let repo = crate::materialization_state::MaterializationStateRepository::new(db.clone());
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
             VALUES ('group-1', 'gone-but-pinned.txt', 0, 0, '[]', 1)",
            [],
        )?;
        conn.execute(
            "UPDATE files SET pinned = 1 WHERE group_id = 'group-1' AND path = \
             'gone-but-pinned.txt'",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    // `set_held` requires no genuine live-row precondition of its own
    // -- setting it here on an already-`deleted = 1` row directly
    // models "this device held it, then later (independently) came to
    // believe it was deleted," the exact stale-combination this test
    // exists to refuse resurrecting.
    repo.set_held("group-1", "gone-but-pinned.txt", "case_collision", 1000).unwrap();

    let files = vec![snapshot_file("gone-but-pinned.txt")];
    db.write::<_, SyncSqliteError>(|conn| {
        replace_group_files_from_snapshot(conn, "group-1", &files)
    })
    .unwrap();

    let pinned: bool = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT pinned FROM files WHERE group_id = 'group-1' AND \
                 path = 'gone-but-pinned.txt' AND state = 'current'",
                [],
                |r| r.get::<_, i64>(0),
            )? != 0)
        })
        .unwrap();
    assert!(
        pinned,
        "a pin must survive a delete-then-resurrect at this path, matching upsert_file_in_tx's \
         own unconditional carry-forward for the ordinary (non-rebootstrap) case"
    );
    assert!(
        repo.get_held_state("group-1", "gone-but-pinned.txt").unwrap().is_none(),
        "a hold must NOT survive a delete-then-resurrect -- it protected a row this device \
         itself already believed was deleted, which is not the same claim as the resurrected \
         row"
    );
}
