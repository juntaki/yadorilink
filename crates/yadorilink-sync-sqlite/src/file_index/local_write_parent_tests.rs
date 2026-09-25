#![cfg(test)]

//! Which versions of a path a local write may claim as its causal past
//! when the path is indexed but its materialized basis is unknown.
//!
//! Admission writes only the DAG, never `files`, so a peer's version of
//! an indexed path can be a live head that this device has not projected
//! and whose content the user never saw. A local write signed onto the
//! plain frontier then descends from it, supersedes it, and no conflict
//! copy is derived for it: the peer's content is lost on every replica.

use super::*;
use crate::materialized_generation::{
    forget_group_materialized_generations, lookup_materialized_generation,
};
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_root_authority::fs_identity::{
    FileIdentity, ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";
const PATH: &str = "doc.txt";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            dag_store::init_conflict_copy_provenance_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            crate::projection_obligations::init_projection_obligations_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32]))
}

fn observed_identity(inode: u64) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode },
        object_kind: ObjectKind::RegularFile,
        generation_or_usn: Some(1),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 0,
        }),
        observed_size: 0,
        metadata_fingerprint: [inode as u8; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

fn meta() -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: Some(0o644),
        xattrs: Vec::new(),
    }
}

fn file_version(mtime_unix_nanos: i64) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn record_at(mtime_unix_nanos: i64) -> FileRecord {
    FileRecord {
        path: PATH.to_string(),
        size: 0,
        mtime_unix_nanos,
        blocks: Vec::new(),
        deleted: false,
    }
}

fn put(version: &FileVersion) -> Op {
    Op::Put {
        path: SyncPath(PATH.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    }
}

/// A local write of `PATH` through the unbatched commit, observed on disk
/// so it publishes an actual-state proof -- a materialized basis.
fn write_unbatched(repo: &FileIndexRepository, mtime_unix_nanos: i64) -> ChangeHash {
    let version = file_version(mtime_unix_nanos);
    let emitter = emitter();
    let permit = RootCommitPermit::for_tests();
    repo.upsert_file_emitting_change(
        GROUP,
        &record_at(mtime_unix_nanos),
        "device-a",
        ChangeContent { ops: vec![put(&version)], versions: std::slice::from_ref(&version) },
        Some(&meta()),
        Some(&observed_identity(mtime_unix_nanos as u64)),
        ChangeEmissionContext { emitter: &emitter, permit: &permit },
    )
    .expect("the local write must commit")
}

/// A local write of `PATH` through the batched commit, with no evidence of
/// what is on disk.
fn write_batched(repo: &FileIndexRepository, mtime_unix_nanos: i64) -> ChangeHash {
    let version = file_version(mtime_unix_nanos);
    let emitter = emitter();
    let permit = RootCommitPermit::for_tests();
    repo.commit_local_mutations_batch(
        GROUP,
        &[PreparedLocalMutation::Upsert {
            record: record_at(mtime_unix_nanos),
            op: put(&version),
            version: version.clone(),
            meta: Some(meta()),
        }],
        &[None],
        "device-a",
        ChangeEmissionContext { emitter: &emitter, permit: &permit },
    )
    .expect("the batch must commit");
    repo.get_authoring_change_hash(GROUP, PATH).unwrap().expect("the batch authored the path")
}

/// A peer's edit of `PATH` on top of `parent`, admitted into the DAG
/// only, the way admission leaves it until reconciliation projects it.
fn admit_peer_edit_on(db: &SyncDatabase, parent: ChangeHash, mtime_unix_nanos: i64) -> ChangeHash {
    let version = file_version(mtime_unix_nanos);
    db.write::<_, SyncSqliteError>(|conn| {
        let lamport = dag_store::lamport_of(conn, &parent)?.expect("the parent is retained");
        let change = create_signed_for_tests(
            vec![parent],
            lamport,
            DeviceId("device-b".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![put(&version)],
            &SigningKey::from_bytes(&[42u8; 32]),
        );
        dag_store::put_file_version(conn, GROUP, &version)?;
        let admitted = dag_store::admit_change(conn, &change)?;
        assert_eq!(admitted.outcome, dag_store::AdmitOutcome::Applied);
        Ok(change.compute_hash())
    })
    .unwrap()
}

fn is_ancestor(db: &SyncDatabase, ancestor: &ChangeHash, descendant: &ChangeHash) -> bool {
    db.write::<_, SyncSqliteError>(|conn| dag_store::is_ancestor(conn, ancestor, descendant))
        .unwrap()
}

fn live_heads(db: &SyncDatabase) -> Vec<[u8; 32]> {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(dag_store::path_frontier::live_path_heads(conn, GROUP, PATH)?
            .into_iter()
            .map(|head| head.change_hash)
            .collect())
    })
    .unwrap()
}

fn has_basis(db: &SyncDatabase) -> bool {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(lookup_materialized_generation(conn, GROUP, PATH)?.is_some())
    })
    .unwrap()
}

/// `local` kept the version it was written over and did not claim the
/// peer's unprojected edit: both are live heads.
fn assert_concurrent_with_the_unseen_edit(
    db: &SyncDatabase,
    seen: &ChangeHash,
    peer: &ChangeHash,
    local: &ChangeHash,
) {
    assert!(
        !is_ancestor(db, peer, local),
        "the local write was signed as a descendant of a peer edit this device never \
         projected, so the peer's content is superseded with no conflict copy"
    );
    assert!(
        is_ancestor(db, seen, local),
        "the local write must still descend from the version this device indexed"
    );
    let heads = live_heads(db);
    assert!(heads.contains(&peer.0), "the peer's edit must stay a live head");
    assert!(heads.contains(&local.0), "the local write must be a live head");
}

/// A prune or history-base install forgets every materialized basis but
/// keeps the index row. A batched local edit committed after one, with a
/// peer's edit admitted and not yet projected, has no basis to sign onto.
#[test]
fn a_batched_edit_whose_basis_was_forgotten_does_not_claim_an_unprojected_peer_edit() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let a = write_unbatched(&repo, 1);
    db.write::<_, SyncSqliteError>(|conn| {
        forget_group_materialized_generations(conn, GROUP, "history-pruned", 0)
    })
    .unwrap();
    assert!(!has_basis(&db), "sanity: the prune forgot the path's basis");
    let r = admit_peer_edit_on(&db, a, 2);

    let l = write_batched(&repo, 3);

    assert_concurrent_with_the_unseen_edit(&db, &a, &r, &l);
}

/// The unbatched commit never consults a basis. A local edit of an
/// indexed path committed through it -- a file captured straight from disk
/// because a peer's change for it is about to be applied -- is signed
/// after that change was admitted and before it is projected.
#[test]
fn an_unbatched_edit_does_not_claim_an_unprojected_peer_edit() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let a = write_unbatched(&repo, 1);
    let r = admit_peer_edit_on(&db, a, 2);

    let l = write_unbatched(&repo, 3);

    assert_concurrent_with_the_unseen_edit(&db, &a, &r, &l);
}

/// The other side of the rule: a peer edit this device has projected is a
/// version it has shown, and a local edit written over it supersedes it.
#[test]
fn an_edit_over_a_projected_peer_edit_descends_from_it() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let a = write_unbatched(&repo, 1);
    let r = admit_peer_edit_on(&db, a, 2);
    repo.upsert_file_with_origin_and_author(
        GROUP,
        &record_at(2),
        "device-b",
        &r,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    let l = write_unbatched(&repo, 3);

    assert!(is_ancestor(&db, &r, &l), "a projected peer edit is the local edit's causal past");
    assert_eq!(live_heads(&db), vec![l.0]);
}

fn put_at(path: &str, version: &FileVersion) -> Op {
    Op::Put {
        path: SyncPath(path.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    }
}

fn record_of(path: &str, mtime_unix_nanos: i64, deleted: bool) -> FileRecord {
    FileRecord { path: path.to_string(), size: 0, mtime_unix_nanos, blocks: Vec::new(), deleted }
}

/// A peer's edit of `path` on top of `parent`, admitted into the DAG only.
fn admit_peer_edit_of(
    db: &SyncDatabase,
    path: &str,
    parent: ChangeHash,
    mtime_unix_nanos: i64,
) -> ChangeHash {
    let version = file_version(mtime_unix_nanos);
    db.write::<_, SyncSqliteError>(|conn| {
        let lamport = dag_store::lamport_of(conn, &parent)?.expect("the parent is retained");
        let change = create_signed_for_tests(
            vec![parent],
            lamport,
            DeviceId("device-b".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![put_at(path, &version)],
            &SigningKey::from_bytes(&[42u8; 32]),
        );
        dag_store::put_file_version(conn, GROUP, &version)?;
        let admitted = dag_store::admit_change(conn, &change)?;
        assert_eq!(admitted.outcome, dag_store::AdmitOutcome::Applied);
        Ok(change.compute_hash())
    })
    .unwrap()
}

fn live_heads_of(db: &SyncDatabase, path: &str) -> Vec<[u8; 32]> {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(dag_store::path_frontier::live_path_heads(conn, GROUP, path)?
            .into_iter()
            .map(|head| head.change_hash)
            .collect())
    })
    .unwrap()
}

/// One part of a recursive delete touching two paths: one whose
/// materialized basis is known, one whose basis is unknown. A peer's edit
/// of each was admitted and not projected. The part is parented on both
/// versions this device observed and on neither peer edit: taking the
/// frontier for the unknown path must not claim the known path's unseen
/// edit either, so both peer edits stay live, concurrent with the delete.
#[test]
fn a_recursive_part_consumes_every_observed_basis_and_no_unseen_head() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let emitter = emitter();
    let permit = RootCommitPermit::for_tests();

    let known_version = file_version(1);
    let known = repo
        .upsert_file_emitting_change(
            GROUP,
            &record_of("d/known", 1, false),
            "device-a",
            ChangeContent {
                ops: vec![put_at("d/known", &known_version)],
                versions: std::slice::from_ref(&known_version),
            },
            Some(&meta()),
            Some(&observed_identity(1)),
            ChangeEmissionContext { emitter: &emitter, permit: &permit },
        )
        .unwrap();
    let unknown_version = file_version(2);
    let unknown = repo
        .commit_local_mutations_batch(
            GROUP,
            &[PreparedLocalMutation::Upsert {
                record: record_of("d/unknown", 2, false),
                op: put_at("d/unknown", &unknown_version),
                version: unknown_version.clone(),
                meta: Some(meta()),
            }],
            &[None],
            "device-a",
            ChangeEmissionContext { emitter: &emitter, permit: &permit },
        )
        .unwrap()[0];
    let peer_known = admit_peer_edit_of(&db, "d/known", known, 3);
    let peer_unknown = admit_peer_edit_of(&db, "d/unknown", unknown, 4);

    let deletes: Vec<PreparedLocalMutation> = ["d/known", "d/unknown"]
        .into_iter()
        .map(|path| PreparedLocalMutation::Delete {
            record: record_of(path, 5, true),
            op: Op::Delete { path: SyncPath(path.to_string()) },
        })
        .collect();
    let parts = repo
        .commit_recursive_operation(
            GROUP,
            RecursiveOperationKind::RmTree { root: SyncPath("d".into()) },
            &deletes,
            &[],
            "device-a",
            ChangeEmissionContext { emitter: &emitter, permit: &permit },
        )
        .unwrap();
    assert_eq!(parts.len(), 1);
    let part = parts[0];

    for (seen, peer, path) in [(known, peer_known, "d/known"), (unknown, peer_unknown, "d/unknown")]
    {
        assert!(is_ancestor(&db, &seen, &part), "{path}: the observed version was not consumed");
        assert!(!is_ancestor(&db, &peer, &part), "{path}: the delete claimed an unseen edit");
        let heads = live_heads_of(&db, path);
        assert!(heads.contains(&peer.0), "{path}: the peer's edit must stay live");
        assert!(heads.contains(&part.0), "{path}: the delete must be live");
    }
}
