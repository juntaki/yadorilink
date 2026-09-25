use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sync_sqlite::dag_store::init_dag_schema;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// Pins: `change_parents` is derived from the orphan's signed body. An extra
/// bogus edge can keep the orphan permanently non-ready in the SQL prefilter,
/// so startup must discard the best-effort orphan and all of its child edges.
#[test]
fn schema_init_drops_orphan_when_parent_edges_disagree_with_encoded_change() {
    let conn = conn();
    let signing = signing_key();
    let parent = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("parent.bin".into()) }],
        &signing,
    );
    let orphan = create_signed_for_tests(
        vec![parent.compute_hash()],
        parent.lamport,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("child.bin".into()) }],
        &signing,
    );
    let orphan_hash = orphan.compute_hash();

    conn.execute(
        "INSERT INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, received_seq) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 0)",
        rusqlite::params![&orphan_hash.0[..], orphan.lamport as i64, orphan.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&orphan_hash.0[..], &parent.compute_hash().0[..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&orphan_hash.0[..], &[0x91u8; 32][..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();

    let orphan_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM orphan_changes WHERE change_hash = ?1",
            [&orphan_hash.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    let edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM change_parents WHERE child_hash = ?1",
            [&orphan_hash.0[..]],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(orphan_count, 0, "an ancestry-poisoned orphan must be discarded");
    assert_eq!(edge_count, 0, "discarding the orphan must remove every child edge");
}

/// Pins: decoding is not structural validation. A buffered Change with an unsafe
/// path must not survive startup and later become admissible when its parent
/// arrives.
#[test]
fn schema_init_drops_structurally_invalid_orphan() {
    let conn = conn();
    let signing = signing_key();
    let missing_parent = ChangeHash([0x44u8; 32]);
    let orphan = create_signed_for_tests(
        vec![missing_parent],
        1,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("../escape.bin".into()) }],
        &signing,
    );
    let hash = orphan.compute_hash();

    conn.execute(
        "INSERT INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, received_seq) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 0)",
        rusqlite::params![&hash.0[..], orphan.lamport as i64, orphan.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&hash.0[..], &missing_parent.0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM orphan_changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "a structurally invalid orphan must be discarded");
}
