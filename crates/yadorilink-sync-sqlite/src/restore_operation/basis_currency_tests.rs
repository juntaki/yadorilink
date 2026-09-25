#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::file::{FileMeta, RecordKind, VersionBlock};
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";
const PATH: &str = "notes.txt";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn version(mtime_unix_nanos: i64) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// A restore authors its `Put` in one transaction and only later -- after
/// fetching blocks, re-verifying the root and bumping the path's fence --
/// writes the bytes. Any failure in between leaves the change authored
/// and the write undone. If the path's materialized basis survives that
/// window, it still reads as current while naming a frontier the restore
/// has already moved past, and the device's next edit of the path is
/// parented on it: the edit and the restore then stand as two concurrent
/// heads of one path by one author, which the rest of the history model
/// treats as impossible.
///
/// So the emission itself must retire the basis, in its own transaction.
#[test]
fn a_restore_emission_retires_the_paths_basis_in_its_own_transaction() {
    let db = open_full_test_db();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32]));

    // The path as last placed: authored by this device, with a proof whose
    // basis is exactly that authoring change.
    let placed = version(1);
    let placed_change = db
        .write::<_, SyncSqliteError>(|conn| {
            let change = dag_store::emit_local_change(
                conn,
                GROUP,
                vec![Op::Put {
                    path: SyncPath(PATH.to_string()),
                    version: placed.version_hash,
                    origin: PutOrigin::Direct,
                }],
                &emitter,
            )?;
            dag_store::put_file_version(conn, GROUP, &placed)?;
            crate::materialized_generation::record_materialized_generation(
                conn,
                GROUP,
                PATH,
                &[change.compute_hash()],
                crate::materialized_generation::MaterializedObjectKind::RegularFile,
                Some(&placed.version_hash),
                None,
                0,
            )?;
            Ok(change.compute_hash())
        })
        .unwrap();

    let restored = version(2);
    let restore_change = RestoreOperationRepository::new(db.clone())
        .record_restore_operation_emitting_change(
            &RestoreOperation {
                operation_id: "op-1".to_string(),
                group_id: GROUP.to_string(),
                path: PATH.to_string(),
                target_version_seq: 1,
                expected_current_version_seq: None,
                state: RestoreOperationState::Prepared,
                record: FileRecord {
                    path: PATH.to_string(),
                    size: 0,
                    mtime_unix_nanos: 2,
                    blocks: Vec::new(),
                    deleted: false,
                },
                origin_device_id: "device-a".to_string(),
                authoring_change_hash: None,
                meta: LocalFileMetaColumns {
                    record_kind: RecordKind::File,
                    symlink_target: None,
                    symlink_out_of_root: false,
                    unix_mode: None,
                    xattrs: Vec::new(),
                },
            },
            &restored,
            &emitter,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The restore stops here: nothing wrote the bytes or bumped the fence.
    let basis = db
        .write::<_, SyncSqliteError>(|conn| {
            let Some(generation) =
                crate::materialized_generation::lookup_materialized_generation(conn, GROUP, PATH)?
            else {
                return Ok(None);
            };
            dag_store::lookup_causal_basis_members(conn, &generation.causal_basis_id.0)
        })
        .unwrap();
    assert!(
        basis.as_ref().is_none_or(|members| members.contains(&restore_change)),
        "after the restore authored {}, the path's basis must be retired or contain it; it \
         still reads as current and names only {:?} (placed as {})",
        restore_change.to_hex(),
        basis.map(|m| m.iter().map(|h| h.to_hex()).collect::<Vec<_>>()),
        placed_change.to_hex(),
    );
}
