use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_sync_core::change::{Change, ChangeAuth, DeviceId, FolderGroupId, Op, SyncPath};
use yadorilink_sync_core::dag_store::init_dag_schema;
use yadorilink_sync_core::SyncError;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// RED: startup repair currently decodes retained bytes but must also apply the
/// same store-independent structural validation used at peer admission. A row
/// can be perfectly self-consistent at the SQL/hash level while still carrying
/// an unsafe path that should never be durable admitted history.
#[test]
fn schema_init_fails_closed_on_structurally_invalid_retained_change() {
    let conn = conn();
    let signing = signing_key();
    let change = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("../escape.bin".into()) }],
        &signing,
    );
    let hash = change.compute_hash();

    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 1)",
        rusqlite::params![&hash.0[..], change.lamport as i64, change.to_wire_bytes()],
    )
    .unwrap();
    conn.execute("INSERT INTO group_heads (group_id, change_hash) VALUES ('g', ?1)", [&hash.0[..]])
        .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("structurally invalid retained history must fail closed at startup");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: startup repair verifies a retained change's storage key, row
/// metadata, structure, and `change_parents` edges against its own encoded
/// body, but never the same cross-group-parent invariant peer admission
/// enforces via `validate_present_parent_shape`. A row can be self-consistent
/// at every one of those checks while still declaring a parent that belongs
/// to a different group.
#[test]
fn schema_init_fails_closed_on_retained_change_with_a_cross_group_parent() {
    let conn = conn();
    let signing = signing_key();
    let foreign_parent = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("group-b".into()),
        vec![Op::Delete { path: SyncPath("b.bin".into()) }],
        &signing,
    );
    let foreign_hash = foreign_parent.compute_hash();
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'group-b', 'device-a', ?2, ?3, 1)",
        rusqlite::params![
            &foreign_hash.0[..],
            foreign_parent.lamport as i64,
            foreign_parent.to_wire_bytes()
        ],
    )
    .unwrap();

    let child = Change::create_signed(
        vec![foreign_hash],
        foreign_parent.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("group-a".into()),
        vec![Op::Delete { path: SyncPath("a.bin".into()) }],
        &signing,
    );
    let child_hash = child.compute_hash();
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'group-a', 'device-a', ?2, ?3, 1)",
        rusqlite::params![&child_hash.0[..], child.lamport as i64, child.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&child_hash.0[..], &foreign_hash.0[..]],
    )
    .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("a retained change whose parent belongs to a different group must fail closed");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: `changes.applied` has no SQL constraint and startup repair never
/// reads or validates it, but `list_unapplied` keys retry off `applied = 0`
/// exactly and materialization-complete logic keys off `applied = 1`
/// exactly. A third value is invisible to both and drops the row out of
/// retry forever.
#[test]
fn schema_init_fails_closed_on_an_invalid_applied_value() {
    let conn = conn();
    let signing = signing_key();
    let change = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("a.bin".into()) }],
        &signing,
    );
    let hash = change.compute_hash();
    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 2)",
        rusqlite::params![&hash.0[..], change.lamport as i64, change.to_wire_bytes()],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err(
        "an out-of-range applied value must fail closed rather than silently drop out of retry",
    );
    assert!(matches!(error, SyncError::CorruptState(_)));
}
