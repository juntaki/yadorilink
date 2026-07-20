use rusqlite::Connection;
use yadorilink_sync_core::change::FolderGroupId;
use yadorilink_sync_core::compaction::Checkpoint;
use yadorilink_sync_core::dag_store::init_dag_schema;
use yadorilink_sync_core::SyncError;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn insert_checkpoint(conn: &Connection, checkpoint: &Checkpoint, seq: i64) {
    let hash = checkpoint.checkpoint_hash();
    conn.execute(
        "INSERT INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &hash.0[..],
            checkpoint.group_id.as_str(),
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding(),
            seq,
        ],
    )
    .unwrap();
}

#[test]
fn schema_init_fails_closed_on_pruned_change_without_its_claimed_checkpoint() {
    let conn = conn();
    conn.execute(
        "INSERT INTO pruned_changes (group_id, change_hash, checkpoint_hash, lamport) \
         VALUES ('g', ?1, ?2, 1)",
        rusqlite::params![vec![0x11u8; 32], vec![0x22u8; 32]],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err(
        "a prune tombstone is not proof unless its checkpoint exists for the same group",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[test]
fn schema_init_fails_closed_on_pruned_edge_not_owned_by_that_checkpoint_prune() {
    let conn = conn();
    let checkpoint = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x33u8; 32]);
    insert_checkpoint(&conn, &checkpoint, 1);
    let checkpoint_hash = checkpoint.checkpoint_hash();

    conn.execute(
        "INSERT INTO pruned_change_parents \
         (group_id, child_hash, parent_hash, checkpoint_hash) VALUES ('g', ?1, ?2, ?3)",
        rusqlite::params![vec![0x44u8; 32], vec![0x55u8; 32], &checkpoint_hash.0[..],],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err(
        "an edge proof must be tied to a child or parent tombstone created by the same checkpoint prune",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[test]
fn schema_init_validates_old_checkpoints_still_referenced_by_prune_history() {
    let conn = conn();
    let old = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x66u8; 32]);
    let latest = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x77u8; 32]);
    insert_checkpoint(&conn, &old, 1);
    insert_checkpoint(&conn, &latest, 2);

    // Corrupt only the older row. A latest-only checkpoint read would miss
    // this, but prune tombstones may continue to cite the older checkpoint.
    conn.execute(
        "UPDATE change_checkpoints SET snapshot_hash = ?2 WHERE checkpoint_hash = ?1",
        rusqlite::params![&old.checkpoint_hash().0[..], vec![0x88u8; 32]],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err(
        "startup must validate every checkpoint that can anchor retained prune history",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}
