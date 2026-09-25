#![cfg(test)]

//! A pinned directory is a policy over a prefix: what is below it counts as
//! pinned, including entries that arrive after the pin, for every reader
//! that asks whether a file may be evicted or is owed its bytes.

use super::*;
use yadorilink_replica_domain::session_state::MaterializationState;

const GROUP: &str = "g";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            dag_store::init_dag_schema(conn).map_err(|e| {
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

fn insert(db: &SyncDatabase, path: &str, kind: RecordKind, materialization: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state, record_kind, materialization_state) \
             VALUES (?1, ?2, 1, 0, '[]', 0, 1, 'current', ?3, ?4)",
            rusqlite::params![GROUP, path, kind.as_db_str(), materialization],
        )?;
        Ok(())
    })
    .unwrap();
}

fn link(db: &SyncDatabase, policy: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO links (local_path, group_id, materialization_policy) \
             VALUES ('/tmp/pinned', ?1, ?2)",
            rusqlite::params![GROUP, policy],
        )?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_pinned_directory_pins_what_is_below_it_and_nothing_else() {
    let db = open_full_test_db();
    insert(&db, "album", RecordKind::Directory, "hydrated");
    insert(&db, "album/a.jpg", RecordKind::File, "hydrated");
    insert(&db, "album/sub/b.jpg", RecordKind::File, "placeholder");
    // Sorts right after `album/`'s range, and shares its first characters.
    insert(&db, "album0/c.jpg", RecordKind::File, "hydrated");
    insert(&db, "albums.txt", RecordKind::File, "hydrated");
    let index = FileIndexRepository::new(db.clone());

    index.set_directory_pinned(GROUP, "album", true).unwrap();
    for path in ["album", "album/a.jpg", "album/sub/b.jpg", "album/later.jpg"] {
        assert!(index.is_pinned(GROUP, path).unwrap(), "{path}");
        assert!(index.is_directory_pinned(GROUP, path).unwrap(), "{path}");
    }
    for path in ["album0/c.jpg", "albums.txt", ""] {
        assert!(!index.is_pinned(GROUP, path).unwrap(), "{path}");
    }
    assert_eq!(
        index.pinned_directory_above(GROUP, "album/sub/b.jpg").unwrap().as_deref(),
        Some("album")
    );
    assert_eq!(index.pinned_directory_above(GROUP, "album").unwrap(), None, "not above itself");
    assert_eq!(
        index.list_live_files_under(GROUP, "album").unwrap(),
        ["album/a.jpg", "album/sub/b.jpg"]
    );

    index.set_directory_pinned(GROUP, "album", false).unwrap();
    assert!(!index.is_pinned(GROUP, "album/a.jpg").unwrap());
}

#[test]
fn the_link_root_is_the_empty_prefix() {
    let db = open_full_test_db();
    insert(&db, "a.txt", RecordKind::File, "hydrated");
    insert(&db, "dir/b.txt", RecordKind::File, "hydrated");
    let index = FileIndexRepository::new(db.clone());
    index.set_directory_pinned(GROUP, "", true).unwrap();
    assert!(index.is_pinned(GROUP, "a.txt").unwrap());
    assert!(index.is_pinned(GROUP, "dir/b.txt").unwrap());
    assert_eq!(index.list_live_files_under(GROUP, "").unwrap(), ["a.txt", "dir/b.txt"]);
}

/// A directory name holding `%` or `_` is matched literally, not as a
/// pattern.
#[test]
fn a_directory_name_is_not_a_pattern() {
    let db = open_full_test_db();
    insert(&db, "a_b/x.txt", RecordKind::File, "hydrated");
    insert(&db, "aXb/y.txt", RecordKind::File, "hydrated");
    let index = FileIndexRepository::new(db.clone());
    index.set_directory_pinned(GROUP, "a_b", true).unwrap();
    assert!(index.is_pinned(GROUP, "a_b/x.txt").unwrap());
    assert!(!index.is_pinned(GROUP, "aXb/y.txt").unwrap());
}

/// The eviction sweep never picks a file below a pinned directory, and a
/// placeholder there -- one that arrived after the pin included -- is owed
/// its bytes in an on-demand folder; the directory entry itself is not.
#[test]
fn eviction_and_repair_honor_a_pinned_directory() {
    let db = open_full_test_db();
    link(&db, "on_demand");
    insert(&db, "album", RecordKind::Directory, "placeholder");
    insert(&db, "album/a.jpg", RecordKind::File, "hydrated");
    insert(&db, "album/b.jpg", RecordKind::File, "placeholder");
    insert(&db, "other/c.jpg", RecordKind::File, "hydrated");
    insert(&db, "other/d.jpg", RecordKind::File, "placeholder");
    let index = FileIndexRepository::new(db.clone());
    let materialization = crate::materialization_state::MaterializationStateRepository::new(db);

    let evictable =
        |m: &crate::materialization_state::MaterializationStateRepository| -> Vec<String> {
            m.list_evictable_files(GROUP).unwrap().into_iter().map(|f| f.path).collect()
        };
    assert_eq!(evictable(&materialization), ["album/a.jpg", "other/c.jpg"]);
    assert!(materialization.list_materialization_repair_candidates(GROUP).unwrap().is_empty());

    index.set_directory_pinned(GROUP, "album", true).unwrap();
    assert_eq!(evictable(&materialization), ["other/c.jpg"]);
    assert_eq!(
        materialization.list_materialization_repair_candidates(GROUP).unwrap(),
        ["album/b.jpg"]
    );
}

#[test]
fn a_directory_takes_the_least_materialized_state_below_it() {
    let db = open_full_test_db();
    insert(&db, "album", RecordKind::Directory, "placeholder");
    insert(&db, "album/a.jpg", RecordKind::File, "hydrated");
    insert(&db, "empty", RecordKind::Directory, "placeholder");
    let materialization =
        crate::materialization_state::MaterializationStateRepository::new(db.clone());
    let state =
        |prefix: &str| materialization.directory_materialization_state(GROUP, prefix).unwrap();
    assert_eq!(state("album"), MaterializationState::Hydrated);
    assert_eq!(state("empty"), MaterializationState::Hydrated, "nothing to fetch");
    insert(&db, "album/sub/b.jpg", RecordKind::File, "placeholder");
    assert_eq!(state("album"), MaterializationState::Placeholder);
    assert_eq!(state(""), MaterializationState::Placeholder);
    insert(&db, "album/c.jpg", RecordKind::File, "hydrating");
    assert_eq!(state("album"), MaterializationState::Hydrating);
}

/// A folder's policy keeps the folder and what is below it, not a file
/// that later takes the folder's name: that file is neither pinned, nor
/// kept from the eviction sweep, nor fetched by the repair pass.
#[test]
fn a_file_that_takes_a_pinned_folders_name_is_not_kept_by_it() {
    let db = open_full_test_db();
    link(&db, "on_demand");
    insert(&db, "docs", RecordKind::File, "hydrated");
    insert(&db, "notes", RecordKind::File, "placeholder");
    let index = FileIndexRepository::new(db.clone());
    let materialization = crate::materialization_state::MaterializationStateRepository::new(db);
    index.set_directory_pinned(GROUP, "docs", true).unwrap();
    index.set_directory_pinned(GROUP, "notes", true).unwrap();

    assert!(!index.is_pinned(GROUP, "docs").unwrap());
    assert!(index.is_pinned(GROUP, "docs/later.txt").unwrap(), "still covers what is below");
    let evictable: Vec<String> =
        materialization.list_evictable_files(GROUP).unwrap().into_iter().map(|f| f.path).collect();
    assert_eq!(evictable, ["docs"]);
    assert!(materialization.list_materialization_repair_candidates(GROUP).unwrap().is_empty());
}

/// Removing a policy says whether there was one to remove.
#[test]
fn releasing_a_directory_pin_reports_whether_one_was_set() {
    let db = open_full_test_db();
    let index = FileIndexRepository::new(db);
    assert!(!index.set_directory_pinned(GROUP, "gone", false).unwrap());
    index.set_directory_pinned(GROUP, "gone", true).unwrap();
    assert!(index.set_directory_pinned(GROUP, "gone", false).unwrap());
}
