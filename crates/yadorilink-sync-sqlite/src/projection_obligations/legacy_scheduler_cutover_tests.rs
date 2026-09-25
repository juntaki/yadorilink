#![cfg(test)]

use super::*;
use crate::dag_store;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&c).unwrap();
    c
}

fn delete_op(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.to_string()) }
}

/// Deletes the obligation `emit_local_change`'s own admission just
/// created for `path`, to exercise the code that has to cope with a
/// retained change whose obligation row is missing.
fn strip_obligation(conn: &Connection, group_id: &str, path: &str) {
    conn.execute(
        "DELETE FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
    )
    .unwrap();
}
