#![cfg(test)]

use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};

use super::*;

const GROUP: &str = "g";
const BLOCK: [u8; 32] = [7; 32];

/// A file-backed database: a read snapshot only means something where a
/// writer on another connection can commit while the read is open.
fn open_file_db(dir: &tempfile::TempDir) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(dir.path().join("index.db"), |conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open file-backed db"),
    )
}

fn version_with_block() -> FileVersion {
    FileVersion::new(
        vec![yadorilink_replica_domain::file::VersionBlock {
            hash: BlockHash(BLOCK.to_vec()),
            size: 4,
        }],
        4,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// A block that is referenced at every instant must be in the live set, even
/// when the reference moves from a retained `files` row to a native head while
/// the set is being computed: the heads half is read first (no head yet), the
/// head is then admitted and retention drops the old row, and the rows half is
/// read last (no row any more). Computed from two separate reads the block
/// appears in neither half and the sweep would delete it.
#[test]
fn a_block_moving_from_a_row_to_a_head_mid_computation_stays_live() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    let blocks_json =
        serde_json::to_string(&[BlockInfo { hash: BLOCK.to_vec(), offset: 0, size: 4 }]).unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        crate::dag_store::put_file_version(conn, GROUP, &version)?;
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
             VALUES (?1, 'old.txt', 4, 0, ?2, 0)",
            rusqlite::params![GROUP, blocks_json],
        )?;
        Ok(())
    })
    .unwrap();
    let repository = MaterializationStateRepository::new(db.clone());
    let VersionHash(version_hash) = version.version_hash;

    let live = repository
        .live_block_hashes_including_native_heads_between(|| {
            db.write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO native_heads \
                     (group_id, path, author, incarnation, seq, version, provenance) \
                     VALUES (?1, 'new.txt', 'device', ?2, 1, ?3, ?4)",
                    rusqlite::params![GROUP, vec![1u8; 16], version_hash.to_vec(), vec![0u8; 32]],
                )?;
                conn.execute("DELETE FROM files WHERE path = 'old.txt'", [])?;
                Ok(())
            })
            .unwrap();
        })
        .unwrap();

    assert!(live.contains(&hex::encode(BLOCK)), "the block was referenced throughout: {live:?}");
}
