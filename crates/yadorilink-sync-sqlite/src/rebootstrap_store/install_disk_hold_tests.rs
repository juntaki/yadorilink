#![cfg(test)]

use super::base_install_tests::{install, open, snapshot_row};
use super::*;

const GROUP: &str = "group-install-hold";

/// A current, live, `Hydrated` row for `path` as this device had placed it
/// before an install.
fn placed_row(conn: &Connection, path: &str, size: u64) {
    conn.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
         version_seq, state, materialization_state) \
         VALUES (?1, ?2, ?3, 0, '[]', 0, 1, 'current', 'hydrated')",
        params![GROUP, path, size as i64],
    )
    .unwrap();
}

/// The projection scheduler must not claim a path whose disk the install
/// has not reconciled: projecting the installed version would overwrite
/// whatever is there, and what is there may be an edit nobody has
/// captured yet.
#[test]
fn a_path_an_install_replaced_is_not_claimed_for_projection_until_reconciled() {
    let mut conn = open();
    placed_row(&conn, "doc.txt", 5);
    install(
        &mut conn,
        GROUP,
        vec![snapshot_row("doc.txt", 7, SnapshotVersionState::Current, false, 9)],
    );
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        &conn,
        GROUP,
        &["doc.txt"],
        0,
    )
    .unwrap();

    let claimed =
        crate::projection_obligations::claim_runnable_obligations(&conn, i64::MAX, 100, 100)
            .unwrap();

    assert!(
        claimed.iter().all(|claim| claim.path != "doc.txt"),
        "the scheduler claimed a path whose disk still holds the replaced version: {claimed:?}"
    );
}
