use rusqlite::Connection;
use yadorilink_sync_core::change::{
    BlockHash, ChangeAuth, FileMeta, FileVersion, Op, SyncPath, VersionBlock,
};
use yadorilink_sync_core::dag_store::{
    emit_local_change, group_file_version_references_block, init_dag_schema, put_file_version,
    ChangeEmitter,
};
use yadorilink_sync_core::types::RecordKind;
use yadorilink_sync_core::SyncError;

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]))
}

/// RED: `change_file_versions` is an authorization index used when deciding
/// whether a group's retained history justifies serving a physical block. An
/// extra relation absent from the signed Change.ops must be removed or rejected;
/// otherwise unrelated retained metadata can manufacture block-serving rights.
#[test]
fn schema_init_repairs_or_refuses_extra_change_file_version_authorization() {
    let conn = conn();
    let block_hash = vec![0xabu8; 32];
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 3 }],
        3,
        FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    );
    put_file_version(&conn, "g", &version).unwrap();

    let change = emit_local_change(
        &conn,
        "g",
        vec![Op::Delete { path: SyncPath("unrelated.bin".into()) }],
        ChangeAuth::PLACEHOLDER,
        &emitter(),
    )
    .unwrap();

    conn.execute(
        "INSERT INTO change_file_versions (group_id, change_hash, version_hash) \
         VALUES ('g', ?1, ?2)",
        rusqlite::params![&change.compute_hash().0[..], &version.version_hash.0[..]],
    )
    .unwrap();

    assert!(group_file_version_references_block(&conn, "g", &block_hash).unwrap());

    match init_dag_schema(&conn) {
        Err(SyncError::CorruptState(_)) => {}
        Err(error) => panic!("unexpected startup error: {error}"),
        Ok(()) => assert!(
            !group_file_version_references_block(&conn, "g", &block_hash).unwrap(),
            "startup must remove authorization relations not justified by signed Change.ops"
        ),
    }
}
