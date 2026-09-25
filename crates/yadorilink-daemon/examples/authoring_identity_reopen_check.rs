//! Standalone reopen-and-check for the SIGKILL crash-consistency proof.
//! Usage: `authoring_identity_reopen_check <db_path>`
//! Reopens `db_path` through the real production
//! `ReplicaCoordinator::open` path and prints the same
//! invalid-authoring-rows count the startup validator itself computes.

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;

fn invalid_authoring_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM files f
         WHERE f.state = 'current' AND f.version_seq > 0
           AND (EXISTS(SELECT 1 FROM changes c WHERE c.group_id = f.group_id)
                OR EXISTS(SELECT 1 FROM pruned_changes pc WHERE pc.group_id = f.group_id))
           AND (f.authoring_change_hash IS NULL
                OR length(f.authoring_change_hash) != 32
                OR NOT EXISTS(
                    SELECT 1 FROM changes c
                     WHERE c.group_id = f.group_id
                       AND c.change_hash = f.authoring_change_hash
                    UNION ALL
                    SELECT 1 FROM pruned_changes pc
                     WHERE pc.group_id = f.group_id
                       AND pc.change_hash = f.authoring_change_hash
                ))",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let db_path = &args[1];
    match ReplicaCoordinator::open(db_path) {
        Ok(_coordinator) => {
            let conn = rusqlite::Connection::open(db_path).unwrap();
            let invalid = invalid_authoring_rows(&conn);
            println!("REOPEN_OK invalid_authoring_rows={invalid}");
        }
        Err(e) => {
            println!("REOPEN_FAILED error={e}");
            std::process::exit(1);
        }
    }
}
