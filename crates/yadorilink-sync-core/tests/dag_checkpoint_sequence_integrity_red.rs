use rusqlite::Connection;
use yadorilink_sync_core::change::FolderGroupId;
use yadorilink_sync_core::compaction::Checkpoint;
use yadorilink_sync_core::dag_store::{init_dag_schema, latest_checkpoint};
use yadorilink_sync_core::SyncError;

#[test]
fn latest_checkpoint_fails_closed_when_multiple_rows_share_the_latest_sequence() {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();

    let left = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x11u8; 32]);
    let right = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x22u8; 32]);
    for checkpoint in [&left, &right] {
        let hash = checkpoint.checkpoint_hash();
        conn.execute(
            "INSERT INTO change_checkpoints \
             (checkpoint_hash, group_id, snapshot_hash, encoded, seq) \
             VALUES (?1, 'g', ?2, ?3, 7)",
            rusqlite::params![
                &hash.0[..],
                &checkpoint.snapshot_hash[..],
                checkpoint.canonical_encoding(),
            ],
        )
        .unwrap();
    }

    let error = latest_checkpoint(&conn, "g").expect_err(
        "two competing rows at the highest sequence cannot define one authoritative snapshot",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}
