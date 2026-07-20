use rusqlite::Connection;
use yadorilink_sync_core::change::{ChangeAuth, FolderGroupId, Op, SyncPath};
use yadorilink_sync_core::compaction::Checkpoint;
use yadorilink_sync_core::dag_store::{
    commit_prune, emit_local_change, init_dag_schema, ChangeEmitter,
};

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]))
}

/// RED: `commit_prune` deletes a pruned change's `change_parents` edges as
/// both child and parent -- a legitimate outcome of ordinary compaction, not
/// corruption. A surviving child's own encoded `parents` field still lists
/// the pruned hash (it is part of the immutable signed body), so the next
/// startup's retained-history repair must not treat that disagreement
/// between `change.parents` and `change_parents` as fail-closed corruption.
#[test]
fn schema_init_survives_a_normal_compaction_prune() {
    let conn = conn();
    let parent = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("parent.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let child = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("child.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    let checkpoint =
        Checkpoint::new(FolderGroupId("g".into()), vec![child.compute_hash()], [0u8; 32]);
    commit_prune(&conn, &checkpoint, std::slice::from_ref(&parent.compute_hash())).unwrap();

    init_dag_schema(&conn)
        .expect("a normal compaction prune must not make the next startup fail closed");
}
