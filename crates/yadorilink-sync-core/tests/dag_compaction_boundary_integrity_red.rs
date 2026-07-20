use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_sync_core::change::{Change, ChangeAuth, DeviceId, FolderGroupId, Op, SyncPath};
use yadorilink_sync_core::compaction::Checkpoint;
use yadorilink_sync_core::dag_store::{
    admit_change, commit_prune, emit_local_change, has_change, init_dag_schema, ChangeEmitter,
};
use yadorilink_sync_core::SyncError;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", SigningKey::from_bytes(&[42u8; 32]))
}

fn two_change_chain(
    conn: &Connection,
) -> (yadorilink_sync_core::change::Change, yadorilink_sync_core::change::Change) {
    let first = emit_local_change(
        conn,
        "g",
        vec![Op::Delete { path: SyncPath("first.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let second = emit_local_change(
        conn,
        "g",
        vec![Op::Delete { path: SyncPath("second.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    (first, second)
}

#[test]
fn schema_init_fails_closed_when_retained_parent_row_disappears_without_checkpoint() {
    let conn = conn();
    let (parent, _child) = two_change_chain(&conn);
    conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&parent.compute_hash().0[..]])
        .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("a dangling parent edge without a checkpoint boundary is history loss");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[test]
fn schema_init_fails_closed_when_parent_row_and_edge_disappear_without_checkpoint() {
    let conn = conn();
    let (parent, child) = two_change_chain(&conn);
    let parent_hash = parent.compute_hash();
    let child_hash = child.compute_hash();
    conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&parent_hash.0[..]]).unwrap();
    conn.execute(
        "DELETE FROM change_parents WHERE child_hash = ?1 AND parent_hash = ?2",
        rusqlite::params![&child_hash.0[..], &parent_hash.0[..]],
    )
    .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("missing parent metadata is not evidence that the parent was compacted");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[test]
fn restart_accepts_surviving_non_checkpoint_branch_whose_parent_was_pruned() {
    let conn = conn();
    let root = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("root.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let root_hash = root.compute_hash();

    let branch_a = Change::create_signed(
        vec![root_hash],
        root.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-b".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("a.bin".into()) }],
        &SigningKey::from_bytes(&[1u8; 32]),
    );
    let branch_b = Change::create_signed(
        vec![root_hash],
        root.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-c".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("b.bin".into()) }],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    admit_change(&conn, &branch_a, true).unwrap();
    admit_change(&conn, &branch_b, true).unwrap();

    // This models a valid concurrent-prune boundary: the common root is
    // dominated/prunable, branch_a is the checkpoint cut, while branch_b is a
    // surviving non-prunable concurrent branch. branch_b is NOT in the
    // checkpoint frontier but legitimately loses its live edge to the pruned
    // root. The prune tombstone + copied edge skeleton must prove that boundary.
    let checkpoint =
        Checkpoint::new(FolderGroupId("g".into()), vec![branch_a.compute_hash()], [0x33u8; 32]);
    commit_prune(&conn, &checkpoint, &[root_hash]).unwrap();
    assert!(!has_change(&conn, &root_hash).unwrap());
    assert!(has_change(&conn, &branch_b.compute_hash()).unwrap());

    init_dag_schema(&conn)
        .expect("a retained concurrent branch may legitimately reference an explicitly tombstoned pruned parent");
}

#[test]
fn replay_of_an_explicitly_pruned_change_does_not_resurrect_history() {
    let conn = conn();
    let (root, child) = two_change_chain(&conn);
    let root_hash = root.compute_hash();
    let checkpoint =
        Checkpoint::new(FolderGroupId("g".into()), vec![child.compute_hash()], [0x44u8; 32]);
    commit_prune(&conn, &checkpoint, &[root_hash]).unwrap();
    assert!(!has_change(&conn, &root_hash).unwrap());

    let error = admit_change(&conn, &root, true).expect_err(
        "a stale peer must not be able to re-admit a Change this replica already pruned",
    );
    assert!(matches!(error, SyncError::NotFound(_)));
    assert!(!has_change(&conn, &root_hash).unwrap());
}

#[test]
fn completed_prune_context_does_not_authorize_a_later_unrelated_history_deletion() {
    let conn = conn();
    let root = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("root.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let middle = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("middle.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let leaf = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("leaf.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    let checkpoint =
        Checkpoint::new(FolderGroupId("g".into()), vec![middle.compute_hash()], [0x55u8; 32]);
    commit_prune(&conn, &checkpoint, &[root.compute_hash()]).unwrap();

    // The prune context must have closed at the sweep. This later direct loss
    // of a different retained parent is corruption, not part of that old prune.
    conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&middle.compute_hash().0[..]])
        .unwrap();
    conn.execute(
        "DELETE FROM change_parents WHERE child_hash = ?1 AND parent_hash = ?2",
        rusqlite::params![&leaf.compute_hash().0[..], &middle.compute_hash().0[..]],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err(
        "a completed checkpoint must not grant prune authority to later unrelated deletes",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: a change with two parents -- one still live, one legitimately
/// tombstoned by a real prune -- must still have its Lamport value checked
/// against `max(parent lamports) + 1`. A partially-missing parent set must
/// never short-circuit the Lamport check merely because resolving every
/// parent's lamport (live or tombstoned) succeeded.
#[test]
fn schema_init_fails_closed_on_lamport_mismatch_with_one_live_and_one_pruned_parent() {
    let conn = conn();
    let root = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("root.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let root_hash = root.compute_hash();
    // Emitted (not hand-built), so its lamport is whatever the store's own
    // rule computes -- this test cares about the merge's lamport being
    // wrong, not about hand-deriving branch_a's correct one.
    let branch_a = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("a.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    // Prune the root while branch_a (its live sibling reference) survives.
    let checkpoint =
        Checkpoint::new(FolderGroupId("g".into()), vec![branch_a.compute_hash()], [0x66u8; 32]);
    commit_prune(&conn, &checkpoint, &[root_hash]).unwrap();
    assert!(!has_change(&conn, &root_hash).unwrap());
    assert!(has_change(&conn, &branch_a.compute_hash()).unwrap());

    // A merge change directly referencing both the live branch_a and the
    // now-pruned root, with a lamport that does not equal
    // max(branch_a.lamport, root.lamport) + 1. Inserted directly (not via
    // `admit_change`) since a genuine merge could only have been authored
    // this way from stale-but-real ancestry -- exactly what a startup repair
    // pass must independently distrust.
    let merge = Change::create_signed(
        vec![branch_a.compute_hash(), root_hash],
        99,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-c".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("merge.bin".into()) }],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    let merge_hash = merge.compute_hash();
    conn.execute(
        "INSERT INTO changes (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'g', 'device-c', 99, ?2, 1)",
        rusqlite::params![&merge_hash.0[..], merge.to_wire_bytes()],
    )
    .unwrap();
    for parent in [branch_a.compute_hash(), root_hash] {
        conn.execute(
            "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
            rusqlite::params![&merge_hash.0[..], &parent.0[..]],
        )
        .unwrap();
    }

    let error = init_dag_schema(&conn).expect_err(
        "a lamport mismatch must fail closed even when only one of two parents was pruned",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}
