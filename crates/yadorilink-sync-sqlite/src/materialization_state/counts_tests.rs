#![cfg(test)]

use super::*;

const GROUP: &str = "g";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::dag_store::init_dag_schema(conn).map_err(|e| {
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
    seed(&db, "a.txt", RecordKind::File, MaterializationState::Hydrated);
    seed(&db, "b.txt", RecordKind::File, MaterializationState::Placeholder);
    seed(&db, "link", RecordKind::Symlink, MaterializationState::Hydrated);
    seed(&db, "album", RecordKind::Directory, MaterializationState::Hydrated);
    seed(&db, "empty", RecordKind::Directory, MaterializationState::Placeholder);

    let counts = MaterializationStateRepository::new(db).materialization_counts(GROUP).unwrap();

    assert_eq!((counts.hydrated, counts.placeholder, counts.hydrating), (2, 1, 0));
}
