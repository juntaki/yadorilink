#![cfg(test)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;

fn schema_init(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS pruned_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);",
    )?;
    crate::schema::init_schema(conn)
}

fn open_test_db(path: &std::path::Path) -> SyncDatabase {
    SyncDatabase::open(path, schema_init).expect("open")
}

#[test]
fn repositories_sharing_database_do_not_race_independent_writer_gates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = Arc::new(open_test_db(&dir.path().join("writer-gate-regression.sqlite3")));

    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch(
                "CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY);",
            )?)
        })
        .expect("create tables");

    let long_writer_started = Arc::new(AtomicBool::new(false));
    let long_writer_database = database.clone();
    let long_writer_flag = long_writer_started.clone();
    let long_writer = std::thread::spawn(move || {
        long_writer_database.write_immediate::<_, DatabaseError>(|tx| {
            tx.execute("INSERT INTO a (id) VALUES (1)", [])?;
            long_writer_flag.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Ok::<(), DatabaseError>(())
        })
    });

    while !long_writer_started.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(5));
    }

    // While the long writer_immediate transaction on table `a` is still
    // held, a short write on table `b` through the SAME shared
    // `SyncDatabase` must still succeed -- serialized behind the
    // writer_gate, never `SQLITE_LOCKED`.
    let short_write_result = database.write::<_, DatabaseError>(|conn: &mut Connection| {
        Ok(conn.execute("INSERT INTO b (id) VALUES (2)", [])?)
    });

    long_writer.join().expect("long writer thread panicked").expect("long writer");
    short_write_result.expect(
        "a write on one table must succeed while another write_immediate transaction is \
         held on a different table through the same shared writer_gate, not \
         SQLITE_LOCKED/SQLITE_BUSY",
    );

    let b_count: i64 = database
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM b", [], |row| row.get(0))?)
        })
        .expect("read back");
    assert_eq!(b_count, 1);
}

/// The writer_gate must release even when the write closure itself
/// returns an error -- otherwise one failed write would permanently
/// wedge every subsequent write on this `SyncDatabase`.
#[test]
fn writer_gate_releases_after_an_operation_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = open_test_db(&dir.path().join("writer-gate-error-release.sqlite3"));
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
        })
        .expect("create table");

    let failing: Result<(), DatabaseError> =
        database.write::<_, DatabaseError>(|conn: &mut Connection| {
            conn.execute("INSERT INTO t (id) VALUES (1)", [])?;
            Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
        });
    assert!(failing.is_err());

    // The gate must not be wedged: this write must still go through.
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute("INSERT INTO t (id) VALUES (2)", [])?)
        })
        .expect("writer_gate must have been released after the prior error");
}

/// `write_immediate` must leave no partial write behind on failure --
/// the transaction rolls back rather than committing a half-applied
/// operation.
#[test]
fn write_immediate_leaves_no_partial_write_on_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let database = open_test_db(&dir.path().join("write-immediate-rollback.sqlite3"));
    database
        .write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
        })
        .expect("create table");

    let failing: Result<(), DatabaseError> = database.write_immediate::<_, DatabaseError>(|tx| {
        tx.execute("INSERT INTO t (id) VALUES (1)", [])?;
        Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
    });
    assert!(failing.is_err());

    let count: i64 = database
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))?)
        })
        .expect("read back");
    assert_eq!(count, 0, "a failed write_immediate must not leave a partial row committed");
}

/// Data and schema must both survive a close-and-reopen of the same
/// file-backed database.
#[test]
fn data_and_schema_survive_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen-survives.sqlite3");
    {
        let database = open_test_db(&path);
        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?;
                Ok(conn.execute("INSERT INTO t (id) VALUES (42)", [])?)
            })
            .expect("create + insert");
    }

    let reopened = open_test_db(&path);
    let value: i64 = reopened
        .read::<i64, DatabaseError>(|conn| {
            Ok(conn.query_row("SELECT id FROM t", [], |row| row.get(0))?)
        })
        .expect("read back after reopen");
    assert_eq!(value, 42);
}

/// Opening the same database twice in a row (schema already present)
/// must not fail -- `init_schema`'s own `CREATE TABLE IF NOT EXISTS`
/// migrations must be idempotent, not just safe to run once.
#[test]
fn schema_initialization_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idempotent-init.sqlite3");
    let _first = open_test_db(&path);
    let _second = open_test_db(&path);
}
