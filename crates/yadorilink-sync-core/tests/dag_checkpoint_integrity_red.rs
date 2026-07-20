use rusqlite::Connection;
use yadorilink_sync_core::change::{ChangeHash, FolderGroupId};
use yadorilink_sync_core::compaction::Checkpoint;
use yadorilink_sync_core::dag_store::{init_dag_schema, latest_checkpoint};

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

/// RED: the checkpoint primary key is content-addressed identity. A valid
/// encoded checkpoint stored under a different key must not be accepted.
#[test]
fn latest_checkpoint_rejects_storage_key_mismatch() {
    let conn = conn();
    let checkpoint = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x11u8; 32]);
    let wrong_hash = [0x99u8; 32];
    assert_ne!(wrong_hash, checkpoint.checkpoint_hash().0);

    conn.execute(
        "INSERT INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, 'g', ?2, ?3, 1)",
        rusqlite::params![
            &wrong_hash[..],
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding()
        ],
    )
    .unwrap();

    latest_checkpoint(&conn, "g")
        .expect_err("checkpoint content must hash back to its storage key");
}

/// RED: the SQL group scope must agree with the canonical checkpoint body. A
/// row must not become another group's checkpoint by changing only `group_id`.
#[test]
fn latest_checkpoint_rejects_group_metadata_mismatch() {
    let conn = conn();
    let checkpoint = Checkpoint::new(FolderGroupId("other-group".into()), vec![], [0x22u8; 32]);
    let hash = checkpoint.checkpoint_hash();

    conn.execute(
        "INSERT INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, 'g', ?2, ?3, 1)",
        rusqlite::params![
            &hash.0[..],
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding()
        ],
    )
    .unwrap();

    latest_checkpoint(&conn, "g")
        .expect_err("checkpoint row group_id must match the canonical checkpoint body");
}

/// RED: `snapshot_hash` is duplicated in the row and canonical body. Those two
/// representations must not be allowed to drift, because re-bootstrap logic
/// must have one authoritative snapshot identity.
#[test]
fn latest_checkpoint_rejects_snapshot_metadata_mismatch() {
    let conn = conn();
    let checkpoint = Checkpoint::new(FolderGroupId("g".into()), vec![], [0x33u8; 32]);
    let hash = checkpoint.checkpoint_hash();
    let wrong_snapshot = [0x55u8; 32];

    conn.execute(
        "INSERT INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, 'g', ?2, ?3, 1)",
        rusqlite::params![&hash.0[..], &wrong_snapshot[..], checkpoint.canonical_encoding()],
    )
    .unwrap();

    latest_checkpoint(&conn, "g")
        .expect_err("checkpoint row snapshot_hash must match the canonical checkpoint body");
}

/// RED: unlike `Change`/`FileVersion`, the checkpoint decoder reads the
/// frontier's `u32` entry count and feeds it straight to
/// `Vec::with_capacity` with no bound check first. A corrupt or hostile
/// count should be a clean decode error, not a multi-gigabyte allocation
/// attempt.
#[test]
fn checkpoint_decode_rejects_a_hostile_frontier_count_before_allocating() {
    let checkpoint = Checkpoint::new(FolderGroupId("g".into()), vec![], [0u8; 32]);
    let mut bytes = checkpoint.canonical_encoding();
    // Frontier count sits right after the 8-byte domain tag and the
    // 4-byte-length-prefixed single-character group id "g".
    let count_offset = 8 + 4 + 1;
    bytes[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());

    Checkpoint::decode(&bytes).expect_err(
        "a frontier count far exceeding any plausible size must be rejected before it can size \
         an allocation",
    );
}

/// RED: `new` always normalizes the frontier to ascending, deduped order
/// before encoding, but `decode` never checks that the order it read back
/// actually is that. Decode/re-encode is order-preserving, so a checkpoint
/// whose frontier was corrupted or hand-crafted out of order still hashes
/// back to its own storage key -- `latest_checkpoint`'s identity check alone
/// cannot catch this.
#[test]
fn checkpoint_decode_rejects_a_non_ascending_frontier() {
    let mut checkpoint = Checkpoint::new(
        FolderGroupId("g".into()),
        vec![ChangeHash([0x01u8; 32]), ChangeHash([0x02u8; 32])],
        [0u8; 32],
    );
    checkpoint.frontier.reverse();
    let bytes = checkpoint.canonical_encoding();

    Checkpoint::decode(&bytes).expect_err(
        "a non-ascending frontier must be rejected to match the documented canonical encoding",
    );
}
