use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_sync_core::change::{
    Change, ChangeAuth, ChangeHash, DeviceId, FolderGroupId, Op, SyncPath,
};
use yadorilink_sync_core::dag_store::{
    admit_change, emit_local_change, group_heads, init_dag_schema, AdmitOutcome, ChangeEmitter,
};
use yadorilink_sync_core::SyncError;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", signing_key())
}

fn assert_frontier_repaired_or_refused(
    conn: &Connection,
    group_id: &str,
    mut expected: Vec<ChangeHash>,
) {
    match init_dag_schema(conn) {
        Err(SyncError::CorruptState(_)) => {}
        Err(error) => panic!("unexpected startup error: {error}"),
        Ok(()) => {
            let mut actual = group_heads(conn, group_id).unwrap();
            actual.sort();
            expected.sort();
            assert_eq!(
                actual, expected,
                "startup must either reconstruct the exact retained DAG frontier or fail closed"
            );
        }
    }
}

/// RED: losing only one member of a concurrent frontier is subtler than losing
/// every head. Local emission still sees a non-empty, same-group parent set and
/// silently signs causality that omits the other retained branch.
#[test]
fn schema_init_repairs_or_refuses_incomplete_concurrent_group_frontier() {
    let conn = conn();
    let signing = signing_key();
    let left = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("left.bin".into()) }],
        &signing,
    );
    let right = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-b".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("right.bin".into()) }],
        &signing,
    );

    assert_eq!(admit_change(&conn, &left, true).unwrap().outcome, AdmitOutcome::Applied);
    assert_eq!(admit_change(&conn, &right, true).unwrap().outcome, AdmitOutcome::Applied);

    conn.execute(
        "DELETE FROM group_heads WHERE group_id = 'g' AND change_hash = ?1",
        [&right.compute_hash().0[..]],
    )
    .unwrap();

    assert_frontier_repaired_or_refused(
        &conn,
        "g",
        vec![left.compute_hash(), right.compute_hash()],
    );
}

/// RED: a superseded ancestor reinserted into `group_heads` is not a frontier.
/// It passes current same-group/presence checks and changes the parent set this
/// device signs, so startup must reconstruct the exact leaf set or refuse it.
#[test]
fn schema_init_repairs_or_refuses_superseded_ancestor_in_group_frontier() {
    let conn = conn();
    let first = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("first.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let second = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("second.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO group_heads (group_id, change_hash) VALUES ('g', ?1)",
        [&first.compute_hash().0[..]],
    )
    .unwrap();

    assert_frontier_repaired_or_refused(&conn, "g", vec![second.compute_hash()]);
}

/// RED: a `change_parents` edge naming a child that was never admitted --
/// either a still-buffered orphan, or one `ORPHAN_BOUND` eviction removed
/// from `orphan_changes` without also removing its edges -- must not make
/// startup's frontier reconstruction think its parent has a real descendant.
/// Otherwise a genuinely-current leaf silently drops out of `group_heads`,
/// and the next local edit signs causality that omits it.
#[test]
fn schema_init_keeps_a_head_whose_only_child_edge_belongs_to_a_change_that_was_never_admitted() {
    let conn = conn();
    let parent = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("parent.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    let ghost_child = ChangeHash([0x77u8; 32]);
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&ghost_child.0[..], &parent.compute_hash().0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();
    assert_eq!(
        group_heads(&conn, "g").unwrap(),
        vec![parent.compute_hash()],
        "a ghost child edge from a never-admitted change must not drop a real leaf from group_heads"
    );
}

/// RED: a `group_heads` row for a group with zero retained `changes` rows --
/// e.g. left over from a re-bootstrap install of a group that was later fully
/// pruned, or any other path that touches `group_heads` without a matching
/// `changes` row -- must not survive startup as a ghost head. A ghost head
/// makes the group look non-empty (blocking a legitimate fresh re-bootstrap)
/// and would be signed as a parent by the next local change if it were ever
/// admitted for that group.
#[test]
fn schema_init_removes_a_ghost_group_heads_row_for_a_group_with_no_retained_history() {
    let conn = conn();
    let ghost_head = ChangeHash([0x88u8; 32]);
    conn.execute(
        "INSERT INTO group_heads (group_id, change_hash) VALUES ('empty-group', ?1)",
        [&ghost_head.0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();
    assert_eq!(
        group_heads(&conn, "empty-group").unwrap(),
        Vec::<ChangeHash>::new(),
        "a group_heads row with no backing changes row must not survive startup repair"
    );
}
