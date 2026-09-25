#![cfg(test)]

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

use super::{init_verified_change_schema, VerifiedChangeBundle, VerifiedCheckpoint};
use crate::dag_store::init_dag_schema;

/// Stage inside a transaction, as every caller must. Every test here
/// used to pass a bare connection, so they all modelled a caller with
/// no transaction -- the same gap that hid the real one.
pub(crate) fn stage_in_tx(
    c: &Connection,
    bundles: &[VerifiedChangeBundle],
    now_unix_nanos: i64,
) -> Result<Vec<yadorilink_replica_domain::ids::ChangeHash>, crate::error::SyncSqliteError> {
    let tx = c.unchecked_transaction()?;
    let staged = super::stage_verified_bundles(&tx, bundles, now_unix_nanos)?;
    tx.commit()?;
    Ok(staged)
}

pub(crate) const GROUP: &str = "g";
const AUTHOR_KEY: [u8; 32] = [0xAA; 32];

/// The DAG tables first, then `yadorilink_sqlite_runtime::init_schema`
/// (which assumes `changes` already exists), matching the daemon's own
/// bootstrap order. `local_dirty_paths` — the local capture barrier —
/// comes from that second step.
pub(crate) fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    crate::materialized_generation::init_materialized_generation_schema(&c).unwrap();
    init_verified_change_schema(&c).unwrap();
    c
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A Change touching `paths`, so a test can move a path's capture fence
/// underneath it. `Delete` is used rather than `Put` because it
/// references no `FileVersion`, which admission would otherwise require
/// to be present.
pub(crate) fn change_touching(
    parents: Vec<yadorilink_replica_domain::ids::ChangeHash>,
    lamport: u64,
    paths: &[&str],
) -> Change {
    create_signed_for_tests(
        parents,
        lamport,
        DeviceId("device-A".into()),
        FolderGroupId(GROUP.into()),
        paths.iter().map(|path| Op::Delete { path: SyncPath((*path).into()) }).collect(),
        &key(),
    )
}

/// A real, structurally valid version — the hash is derived from the
/// content, never invented.
pub(crate) fn a_file_version(seed: u8) -> yadorilink_replica_domain::file::FileVersion {
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
    FileVersion::new(
        vec![VersionBlock {
            hash: yadorilink_replica_domain::ids::BlockHash(vec![seed; 32]),
            size: 1024,
        }],
        1024,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// A Change that writes content, and so refers to a file version.
pub(crate) fn change_putting(
    path: &str,
    version: &yadorilink_replica_domain::file::FileVersion,
) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: yadorilink_replica_domain::change::PutOrigin::Direct,
        }],
        &key(),
    )
}

pub(crate) fn checkpoint(tag: u8) -> VerifiedCheckpoint {
    let mut checkpoint_hash = [0u8; 32];
    checkpoint_hash[0] = tag;
    VerifiedCheckpoint {
        checkpoint_hash,
        group_id: FolderGroupId(GROUP.into()),
        device_id: "device-A".into(),
        checkpoint_seq: tag as u64,
        encoded: vec![tag; 8],
        signature: vec![tag; 64],
        author_signing_public_key: AUTHOR_KEY,
    }
}

pub(crate) fn bundle(change: Change, checkpoint: VerifiedCheckpoint) -> VerifiedChangeBundle {
    VerifiedChangeBundle {
        encoded: change.to_wire_bytes(),
        change,
        checkpoint,
        merkle_proof: vec![0xEE; 4],
        // `change_touching` builds deletes, which refer to no file
        // version, so the exact-set contract is satisfied by carrying
        // none. A fixture that writes content must carry its versions —
        // see `bundle_carrying`.
        versions: Vec::new(),
    }
}

pub(crate) fn bundle_carrying(
    change: Change,
    checkpoint: VerifiedCheckpoint,
    versions: Vec<yadorilink_replica_domain::file::FileVersion>,
) -> VerifiedChangeBundle {
    VerifiedChangeBundle { versions, ..bundle(change, checkpoint) }
}
