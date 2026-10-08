#![cfg(test)]

use super::*;

const GROUP: &str = "g";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
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

fn seed(db: &SyncDatabase, path: &str, record_kind: RecordKind, state: MaterializationState) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
             deleted, record_kind, materialization_state) \
             VALUES (?1, ?2, 0, 0, '[]', 0, ?3, ?4)",
            rusqlite::params![GROUP, path, record_kind.as_db_str(), state.as_db_str()],
        )?;
        Ok(())
    })
    .unwrap();
}

/// `yadorilink status` summarizes files by materialization state. A
/// directory has no content to hydrate or evict, so counting it would
/// inflate the file totals; a symlink keeps being counted, since it has a
/// materialization state of its own that durability health reads.
#[test]
fn materialization_counts_do_not_count_directories() {
    let db = open_full_test_db();
    seed(&db, "a.txt", RecordKind::File, MaterializationState::Present);
    seed(&db, "b.txt", RecordKind::File, MaterializationState::Remote);
    seed(&db, "link", RecordKind::Symlink, MaterializationState::Present);
    seed(&db, "album", RecordKind::Directory, MaterializationState::Present);
    seed(&db, "empty", RecordKind::Directory, MaterializationState::Remote);

    let counts = MaterializationStateRepository::new(db).materialization_counts(GROUP).unwrap();

    assert_eq!((counts.hydrated, counts.placeholder, counts.hydrating), (2, 1, 0));
}

/// A directory reads as the least materialized state of the files below it.
#[test]
fn a_directory_takes_the_least_materialized_state_below_it() {
    let db = open_full_test_db();
    seed(&db, "album", RecordKind::Directory, MaterializationState::Remote);
    seed(&db, "album/a.jpg", RecordKind::File, MaterializationState::Present);
    seed(&db, "empty", RecordKind::Directory, MaterializationState::Remote);
    let materialization = MaterializationStateRepository::new(db.clone());
    let state =
        |prefix: &str| materialization.directory_materialization_state(GROUP, prefix).unwrap();
    assert_eq!(state("album"), MaterializationState::Present);
    assert_eq!(state("empty"), MaterializationState::Present, "nothing to fetch");
    seed(&db, "album/sub/b.jpg", RecordKind::File, MaterializationState::Remote);
    assert_eq!(state("album"), MaterializationState::Remote);
    assert_eq!(state(""), MaterializationState::Remote);
    seed(&db, "album/c.jpg", RecordKind::File, MaterializationState::Hydrating);
    assert_eq!(state("album"), MaterializationState::Hydrating);
}
