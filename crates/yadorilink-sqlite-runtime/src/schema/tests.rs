#![cfg(test)]

use rusqlite::Connection;

use super::*;

fn stub_dag_tables(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS pruned_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS group_history_bases (group_id TEXT NOT NULL, history_base BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_path_heads (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL);",
    )?;
    Ok(())
}

/// The authoring-identity triggers reference `changes`/`pruned_changes`
/// -- this crate's own `init_schema` no longer creates them (that is
/// now exclusively the caller's responsibility, sequenced before this
/// call), so it must fail cleanly, not panic or silently skip the
/// triggers, when they don't already exist.
#[test]
fn init_schema_fails_without_caller_supplied_dag_tables() {
    let conn = Connection::open_in_memory().expect("open");
    let result = init_schema(&conn);
    assert!(
        result.is_err(),
        "init_schema must fail when changes/pruned_changes don't already exist"
    );
}

/// When the caller has already created `changes`/`pruned_changes`
/// before calling `init_schema` (as `SyncDatabase::open`'s composed
/// `schema_init` closure does), the core schema -- including the
/// triggers that reference them -- succeeds.
#[test]
fn init_schema_succeeds_when_caller_supplied_dag_tables_already_exist() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema");
    assert!(table_exists(&conn, "changes").unwrap());
}

/// `files.admitted_at_unix_nanos` lands on a fresh database and is
/// NULLable with no default -- both halves matter. The column's
/// presence is what Folder Rewind's read-only planning layer reads;
/// its NULLability is what lets an unstamped row be reported as
/// unanswerable instead of being coerced to a value that would read as
/// a confident (and wrong) answer.
#[test]
fn admitted_at_unix_nanos_is_present_and_nullable_with_no_default() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema");

    let mut stmt = conn.prepare("PRAGMA table_info(files)").unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut found = false;
    while let Some(row) = rows.next().unwrap() {
        if row.get::<_, String>(1).unwrap() == "admitted_at_unix_nanos" {
            found = true;
            assert_eq!(row.get::<_, i64>(3).unwrap(), 0, "must not be NOT NULL");
            assert_eq!(
                row.get::<_, Option<String>>(4).unwrap(),
                None,
                "must have no column default"
            );
        }
    }
    assert!(found, "the v26 migration must add files.admitted_at_unix_nanos");
}

/// Running `init_schema` twice in a row (schema already present) must
/// not fail -- the `CREATE TABLE IF NOT EXISTS` migrations are
/// idempotent, not just safe to run once.
#[test]
fn init_schema_is_idempotent() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("first init_schema");
    init_schema(&conn).expect("second init_schema");
}

/// [`SCHEMA_VERSION`] v25's own doc comment: a changed column default
/// (`materialization_state`, `'hydrated'` -> `'placeholder'`) has no
/// retroactive effect on rows an older binary already wrote, and there
/// is no honest query-level backfill for them -- the no-compat-path
/// version gate is what actually closes that gap, by refusing to
/// reopen (and therefore never trusting) a database stamped by any
/// pre-v25 binary. This is the generic mechanism every prior version
/// bump in this file already relies on for the identical reason, but
/// it had no direct test of its own -- add one now, since this
/// specific version bump's whole legacy-row story depends on it
/// actually refusing, not just being documented to.
#[test]
fn a_database_stamped_by_an_older_binary_is_refused_not_silently_reopened() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema establishes the current version");
    conn.pragma_update(None, "user_version", SCHEMA_VERSION - 1)
        .expect("simulate a database an older binary stamped");

    let result = init_schema(&conn);

    assert!(
        result.is_err(),
        "a database stamped by an older binary (and therefore possibly holding legacy \
         `Hydrated`-with-no-content rows this version's new column default cannot \
         retroactively fix) must be refused at open, not silently reopened and migrated in \
         place"
    );
}

/// The case `check_schema_version_supported` alone cannot see, and
/// which accepting `user_version == 0` unconditionally used to admit.
#[test]
fn a_database_with_tables_but_no_version_stamp_is_refused() {
    let conn = Connection::open_in_memory().expect("open");
    stub_dag_tables(&conn).expect("stub dag tables");
    init_schema(&conn).expect("init_schema establishes the current version");
    conn.pragma_update(None, "user_version", 0)
        .expect("simulate a database written before versions were stamped");

    let result = check_replica_schema_generation(&conn);

    assert!(
        result.is_err(),
        "a database holding tables but no version stamp must be refused: this build cannot \
         establish what shape it is in, and adopting it in place is exactly the silent \
         migration this codebase does not do"
    );
}

/// The other half: a genuinely brand-new file still opens.
#[test]
fn a_brand_new_database_passes_the_replica_generation_check() {
    let conn = Connection::open_in_memory().expect("open");

    check_replica_schema_generation(&conn)
        .expect("an empty database at user_version 0 is a first run, not a stale one");
}
