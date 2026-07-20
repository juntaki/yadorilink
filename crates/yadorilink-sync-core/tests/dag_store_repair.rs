use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_sync_core::change::{
    Change, ChangeAuth, DeviceId, FileMeta, FileVersion, FolderGroupId, Op, SyncPath,
};
use yadorilink_sync_core::dag_store::{
    admit_change, emit_local_change, get_file_version, init_dag_schema, promote_orphans,
    put_file_version, AdmitOutcome, ChangeEmitter,
};
use yadorilink_sync_core::types::RecordKind;
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

fn test_version() -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    )
}

#[test]
fn schema_init_drops_unrepairable_orphan_and_child_parent_edges() {
    let conn = conn();
    let signing = signing_key();
    let missing_version = test_version();

    let parent = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("old.bin".into()) }],
        &signing,
    );
    let orphan = Change::create_signed(
        vec![parent.compute_hash()],
        parent.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Create {
            path: SyncPath("new.bin".into()),
            version: missing_version.version_hash,
        }],
        &signing,
    );
    let orphan_hash = orphan.compute_hash();

    conn.execute(
        "INSERT INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, applied, received_seq) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 0, 1)",
        rusqlite::params![&orphan_hash.0[..], orphan.lamport as i64, orphan.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&orphan_hash.0[..], &parent.compute_hash().0[..]],
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
    assert_eq!(orphan_count, 0);
    assert_eq!(edge_count, 0);

    assert_eq!(admit_change(&conn, &parent, false).unwrap().outcome, AdmitOutcome::Applied);
}

#[test]
fn schema_init_replaces_corrupt_group_row_from_valid_cross_group_source() {
    let conn = conn();
    let version = test_version();

    put_file_version(&conn, "group-a", &version).unwrap();
    put_file_version(&conn, "group-b", &version).unwrap();
    emit_local_change(
        &conn,
        "group-b",
        vec![Op::Create { path: SyncPath("b".into()), version: version.version_hash }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    conn.execute(
        "UPDATE file_versions SET encoded = ?1 \
         WHERE group_id = 'group-b' AND version_hash = ?2",
        rusqlite::params![b"corrupt-version".as_slice(), &version.version_hash.0[..]],
    )
    .unwrap();
    assert!(get_file_version(&conn, "group-b", &version.version_hash).is_err());

    init_dag_schema(&conn).unwrap();

    assert_eq!(
        get_file_version(&conn, "group-b", &version.version_hash).unwrap().unwrap(),
        version
    );
}

#[test]
fn schema_init_fails_closed_when_admitted_version_has_no_valid_source() {
    let conn = conn();
    let version = test_version();

    put_file_version(&conn, "group-a", &version).unwrap();
    emit_local_change(
        &conn,
        "group-a",
        vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    conn.execute(
        "UPDATE file_versions SET encoded = ?1 \
         WHERE group_id = 'group-a' AND version_hash = ?2",
        rusqlite::params![b"corrupt-version".as_slice(), &version.version_hash.0[..]],
    )
    .unwrap();

    let error = init_dag_schema(&conn).expect_err("admitted history must fail closed");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: the durable row key is itself part of the content-addressed identity.
/// A valid encoded Change stored under a different hash must not survive startup
/// as admitted history, because every hash-keyed lookup then refers to a row
/// whose canonical bytes identify a different Change.
#[test]
fn schema_init_fails_closed_when_admitted_change_storage_key_disagrees_with_encoded_hash() {
    let conn = conn();
    let signing = signing_key();
    let change = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("old.bin".into()) }],
        &signing,
    );
    let stored_hash = [0xa5u8; 32];
    assert_ne!(stored_hash, change.compute_hash().0);

    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 1)",
        rusqlite::params![&stored_hash[..], change.lamport as i64, change.to_wire_bytes()],
    )
    .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("admitted history stored under the wrong hash must fail closed");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: the denormalized row metadata is used to scope and order retained
/// history. It must agree with the signed canonical Change rather than silently
/// creating one identity for SQL queries and another identity when decoded.
#[test]
fn schema_init_fails_closed_when_admitted_row_metadata_disagrees_with_encoded_change() {
    let conn = conn();
    let signing = signing_key();
    let change = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("group-a".into()),
        vec![Op::Delete { path: SyncPath("old.bin".into()) }],
        &signing,
    );
    let hash = change.compute_hash();

    conn.execute(
        "INSERT INTO changes \
         (change_hash, group_id, device_id, lamport, encoded, applied) \
         VALUES (?1, 'group-b', 'device-b', ?2, ?3, 1)",
        rusqlite::params![&hash.0[..], change.lamport as i64 + 7, change.to_wire_bytes()],
    )
    .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("retained row metadata must match the signed canonical change");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: a buffered orphan has two identities today: the SQLite storage key and
/// the hash of its encoded Change. Startup repair must reject the row when they
/// disagree and remove the child-edge metadata keyed by the corrupt storage key.
#[test]
fn schema_init_drops_orphan_whose_storage_key_disagrees_with_encoded_hash() {
    let conn = conn();
    let signing = signing_key();
    let parent = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("parent.bin".into()) }],
        &signing,
    );
    let orphan = Change::create_signed(
        vec![parent.compute_hash()],
        parent.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("child.bin".into()) }],
        &signing,
    );
    let stored_hash = [0x5au8; 32];
    assert_ne!(stored_hash, orphan.compute_hash().0);

    conn.execute(
        "INSERT INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, applied, received_seq) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 0, 1)",
        rusqlite::params![&stored_hash[..], orphan.lamport as i64, orphan.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&stored_hash[..], &parent.compute_hash().0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();

    let orphan_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM orphan_changes WHERE change_hash = ?1",
            [&stored_hash[..]],
            |row| row.get(0),
        )
        .unwrap();
    let edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM change_parents WHERE child_hash = ?1",
            [&stored_hash[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(orphan_count, 0, "a hash-mismatched orphan must be discarded");
    assert_eq!(edge_count, 0, "discarding the orphan must clean its stored-key edges");
}

/// RED: if a malformed orphan row reaches promotion, the current code can
/// delete the row by its bogus storage key, append the decoded Change by its
/// real hash, and leave the old child->parent edge behind forever. Promotion
/// must not create such ghost ancestry.
#[test]
fn promoting_hash_mismatched_orphan_does_not_leave_ghost_parent_edges() {
    let conn = conn();
    let signing = signing_key();
    let parent = Change::create_signed(
        vec![],
        0,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("parent.bin".into()) }],
        &signing,
    );
    assert_eq!(admit_change(&conn, &parent, false).unwrap().outcome, AdmitOutcome::Applied);

    let orphan = Change::create_signed(
        vec![parent.compute_hash()],
        parent.lamport,
        ChangeAuth::PLACEHOLDER,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("child.bin".into()) }],
        &signing,
    );
    let stored_hash = [0x3cu8; 32];
    assert_ne!(stored_hash, orphan.compute_hash().0);

    conn.execute(
        "INSERT INTO orphan_changes \
         (change_hash, group_id, device_id, lamport, encoded, applied, received_seq) \
         VALUES (?1, 'g', 'device-a', ?2, ?3, 0, 1)",
        rusqlite::params![&stored_hash[..], orphan.lamport as i64, orphan.to_wire_bytes()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&stored_hash[..], &parent.compute_hash().0[..]],
    )
    .unwrap();

    let promoted = promote_orphans(&conn).unwrap();
    assert_eq!(promoted, vec![orphan.compute_hash()]);

    let ghost_edge_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM change_parents WHERE child_hash = ?1",
            [&stored_hash[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ghost_edge_count, 0, "promotion must not leave ancestry under a bogus row key");
}

/// RED: `change_parents` is a derived index of the signed Change body. If it is
/// corrupted independently, ancestry and orphan readiness can disagree with the
/// canonical history while every encoded Change remains individually valid.
#[test]
fn schema_init_fails_closed_when_parent_edges_disagree_with_encoded_change() {
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
    assert_eq!(second.parents, vec![first.compute_hash()]);

    conn.execute(
        "DELETE FROM change_parents WHERE child_hash = ?1",
        [&second.compute_hash().0[..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&second.compute_hash().0[..], &[0x77u8; 32][..]],
    )
    .unwrap();

    let error = init_dag_schema(&conn)
        .expect_err("stored parent edges must agree with the signed canonical Change");
    assert!(matches!(error, SyncError::CorruptState(_)));
}

/// RED: `group_heads` is trusted by local emission without re-validating that a
/// head belongs to the target group. A corrupt cross-group head therefore makes
/// this device sign a new Change whose parent belongs to a different history.
#[test]
fn local_emit_refuses_cross_group_head_injected_into_group_frontier() {
    let conn = conn();
    emit_local_change(
        &conn,
        "group-a",
        vec![Op::Delete { path: SyncPath("a.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    let foreign_head = emit_local_change(
        &conn,
        "group-b",
        vec![Op::Delete { path: SyncPath("b.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    conn.execute(
        "INSERT OR IGNORE INTO group_heads (group_id, change_hash) VALUES ('group-a', ?1)",
        [&foreign_head.compute_hash().0[..]],
    )
    .unwrap();

    assert!(
        emit_local_change(
            &conn,
            "group-a",
            vec![Op::Delete { path: SyncPath("next.bin".into()) }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .is_err(),
        "local emission must refuse a frontier containing a head from another group"
    );
}

/// RED: losing the derived `group_heads` row while retained history still exists
/// must not make the next local edit look like a fresh root. Otherwise a single
/// SQLite-index inconsistency silently forks the signed history at Lamport 1.
#[test]
fn local_emit_refuses_missing_head_when_retained_history_exists() {
    let conn = conn();
    emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("first.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();
    conn.execute("DELETE FROM group_heads WHERE group_id = 'g'", []).unwrap();

    assert!(
        emit_local_change(
            &conn,
            "g",
            vec![Op::Delete { path: SyncPath("second.bin".into()) }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .is_err(),
        "retained history with no head must fail closed instead of emitting a new root"
    );
}
