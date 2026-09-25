#![cfg(test)]

use super::*;
use crate::materialized_generation::{
    lookup_materialized_generation, lookup_materialized_generation_diagnostic,
    MaterializedObjectKind,
};
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_root_authority::fs_identity::{
    FileIdentity, ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";
const PATH: &str = "notes.txt";

/// Full schema, including the `files` authoring-identity triggers and
/// the actual-state/fence tables, so these exercise the same write
/// chokepoint production does.
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

fn permit() -> RootCommitPermit<'static> {
    RootCommitPermit::for_tests()
}

fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32]))
}

fn emission<'a>(
    emitter: &'a ChangeEmitter,
    permit: &'a RootCommitPermit<'a>,
) -> ChangeEmissionContext<'a> {
    ChangeEmissionContext { emitter, permit }
}

/// A plausible observation of the path on disk. The tests never touch a
/// real filesystem: what matters is that the writer either had an
/// identity to publish or did not.
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
        observed_size: 4,
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

/// Writes one local version of `PATH`, publishing an actual-state proof
/// for it only when `identity` is `Some` -- the two shapes local
/// capture actually produces, chosen by whether it managed to observe
/// the path under its own lock.
fn emit_version(
    repo: &FileIndexRepository,
    mtime_unix_nanos: i64,
    identity: Option<FileIdentity>,
) -> FileVersion {
    let version = file_version(mtime_unix_nanos);
    let emitter = emitter();
    let permit = permit();
    repo.upsert_file_emitting_change(
        GROUP,
        &record_at(mtime_unix_nanos),
        "device-a",
        ChangeContent {
            ops: vec![Op::Put {
                path: SyncPath(PATH.to_string()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            versions: std::slice::from_ref(&version),
        },
        Some(&meta()),
        identity.as_ref(),
        emission(&emitter, &permit),
    )
    .expect("the local emission must commit");
    version
}

fn materialization_state(db: &SyncDatabase) -> MaterializationState {
    db.write::<_, SyncSqliteError>(|conn| {
        let value: String = conn.query_row(
            "SELECT materialization_state FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            rusqlite::params![GROUP, PATH],
            |r| r.get(0),
        )?;
        Ok(MaterializationState::from_db_str(&value))
    })
    .expect("the current row must exist")
}

/// The proof a correctness-relevant reader is allowed to see: `None`
/// once the path's fence has moved past the epoch it was published
/// under.
fn usable_proof_version(db: &SyncDatabase) -> Option<Option<VersionHash>> {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(lookup_materialized_generation(conn, GROUP, PATH)?.map(|basis| basis.version))
    })
    .unwrap()
}

fn diagnostic_proof_kind(db: &SyncDatabase) -> Option<MaterializedObjectKind> {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(lookup_materialized_generation_diagnostic(conn, GROUP, PATH)?
            .map(|basis| basis.object_kind))
    })
    .unwrap()
}

/// The shape the writers are supposed to produce when local capture did
/// observe the path: the proof names the version this very change put
/// there, and the claim that rests on it is stamped in the same
/// transaction.
#[test]
fn an_observed_local_edit_commits_its_exact_proof_and_its_claim_together() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));

    assert_eq!(
        materialization_state(&db),
        MaterializationState::Hydrated,
        "an emission that published its proof must also stamp the claim it earns"
    );
    assert_eq!(
        usable_proof_version(&db),
        Some(Some(v1.version_hash)),
        "the proof must be usable and must name the version this change put at the path"
    );
}

/// Regression 1. V1 is `Hydrated` with a proof naming it; V2 is a local
/// edit nobody observed. V2 must not inherit V1's claim, and V1's proof
/// must stop being usable -- it describes bytes that are no longer what
/// this path means.
#[test]
fn an_unobserved_local_edit_inherits_neither_the_claim_nor_the_previous_proof() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));
    assert_eq!(materialization_state(&db), MaterializationState::Hydrated);
    assert_eq!(usable_proof_version(&db), Some(Some(v1.version_hash)));

    let v2 = emit_version(&repo, 2, None);
    assert_ne!(v1.version_hash, v2.version_hash, "the two versions must really differ");

    assert_eq!(
        materialization_state(&db),
        MaterializationState::Placeholder,
        "a version this device never observed on disk must not claim to be materialized, \
         however the row it superseded was marked"
    );
    assert_eq!(
        usable_proof_version(&db),
        None,
        "V1's proof describes content the path has moved off; no correctness-relevant \
         reader may still see it as current"
    );
    assert_eq!(
        diagnostic_proof_kind(&db),
        Some(MaterializedObjectKind::RegularFile),
        "invalidation retires the proof by moving the fence, it does not erase the record \
         of what this device last believed"
    );
}

/// Regression 2. The non-emitting delete -- a watcher-observed removal
/// committed without a change, and without anyone revalidating absence
/// under this path's lock. The tombstone inherits `Hydrated` from the
/// live row it supersedes, so without an explicit retirement the path's
/// last present proof stays readable as the truth about a file that is
/// gone.
#[test]
fn a_non_emitting_local_delete_does_not_leave_the_present_proof_usable() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));
    assert_eq!(materialization_state(&db), MaterializationState::Hydrated);
    assert_eq!(usable_proof_version(&db), Some(Some(v1.version_hash)));

    repo.mark_deleted_at(GROUP, PATH, "device-a", 5, &permit()).expect("the tombstone must commit");

    assert!(
        repo.get_file(GROUP, PATH).unwrap().expect("a tombstone row").deleted,
        "the path must really be tombstoned"
    );
    assert_eq!(
        usable_proof_version(&db),
        None,
        "the proof says this path holds a regular file; the transaction that tombstoned it \
         must retire that claim in the same commit"
    );
    assert_ne!(
        materialization_state(&db),
        MaterializationState::Hydrated,
        "a tombstone holds no content and must not inherit a claim to"
    );
}

/// The same shape through the emitting delete, for the caller that
/// declines to publish absence because it could not revalidate the
/// path -- the orphaned-directory cleanup's own case.
#[test]
fn an_emitting_delete_without_an_absence_proof_still_retires_the_present_one() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    emit_version(&repo, 1, Some(observed_identity(11)));
    let emitter = emitter();
    let permit = permit();
    repo.mark_deleted_emitting_change(
        GROUP,
        PATH,
        "device-a",
        5,
        false,
        emission(&emitter, &permit),
    )
    .expect("the tombstone must commit");

    assert_eq!(usable_proof_version(&db), None);
    assert_ne!(materialization_state(&db), MaterializationState::Hydrated);
}

/// And when the caller DID revalidate absence: the proof it publishes
/// is the absent one, which is usable -- absence is a first-class
/// materialized state -- while the claim to hold content still goes.
#[test]
fn a_proven_local_delete_publishes_absence_without_claiming_hydrated() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    emit_version(&repo, 1, Some(observed_identity(11)));
    let emitter = emitter();
    let permit = permit();
    repo.mark_deleted_emitting_change(
        GROUP,
        PATH,
        "device-a",
        5,
        true,
        emission(&emitter, &permit),
    )
    .expect("the tombstone must commit");

    assert_eq!(
        usable_proof_version(&db),
        Some(None),
        "an absent generation is usable and carries no version"
    );
    assert_eq!(diagnostic_proof_kind(&db), Some(MaterializedObjectKind::Absent));
    assert_ne!(
        materialization_state(&db),
        MaterializationState::Hydrated,
        "an exactly-absent path holds no content, so it may not claim to"
    );
}

/// The batched live-edit path -- the production hot path for an
/// ordinary local edit -- has the same two shapes and the same
/// obligation.
#[test]
fn a_batched_local_edit_with_no_evidence_retires_the_previous_proof() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));
    assert_eq!(usable_proof_version(&db), Some(Some(v1.version_hash)));

    let v2 = file_version(2);
    let emitter = emitter();
    let permit = permit();
    repo.commit_local_mutations_batch(
        GROUP,
        &[PreparedLocalMutation::Upsert {
            record: record_at(2),
            op: Op::Put {
                path: SyncPath(PATH.to_string()),
                version: v2.version_hash,
                origin: PutOrigin::Direct,
            },
            version: v2.clone(),
            meta: Some(meta()),
        }],
        &[None],
        "device-a",
        emission(&emitter, &permit),
    )
    .expect("the batch must commit");

    assert_eq!(materialization_state(&db), MaterializationState::Placeholder);
    assert_eq!(usable_proof_version(&db), None);
}

/// ... and publishes the exact proof for the version it committed when
/// the batch did carry evidence.
#[test]
fn a_batched_local_edit_with_evidence_proves_the_version_it_committed() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    emit_version(&repo, 1, Some(observed_identity(11)));

    let v2 = file_version(2);
    let emitter = emitter();
    let permit = permit();
    repo.commit_local_mutations_batch(
        GROUP,
        &[PreparedLocalMutation::Upsert {
            record: record_at(2),
            op: Op::Put {
                path: SyncPath(PATH.to_string()),
                version: v2.version_hash,
                origin: PutOrigin::Direct,
            },
            version: v2.clone(),
            meta: Some(meta()),
        }],
        &[Some(LocalCaptureActualStateEvidence::Present {
            filesystem_identity: observed_identity(12),
        })],
        "device-a",
        emission(&emitter, &permit),
    )
    .expect("the batch must commit");

    assert_eq!(materialization_state(&db), MaterializationState::Hydrated);
    assert_eq!(usable_proof_version(&db), Some(Some(v2.version_hash)));
}

/// The non-emitting scan batch -- an unregistered device with no
/// signing key, writing rows without a DAG behind them -- used to
/// publish its proofs with no version at all. A versionless proof for
/// a present object is not a weaker proof: `resolved_path_state_hash`
/// encodes version presence, so it matches no desired resolution and
/// can close nothing, while looking healthy enough that no repair pass
/// goes near it. The path is then re-materialized forever.
#[test]
fn the_non_emitting_scan_batch_publishes_a_versioned_proof() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let version = file_version(1);
    repo.upsert_files_batch(
        GROUP,
        &[record_at(1)],
        "device-a",
        &[Some(meta())],
        &[Some(ImportedActualState {
            filesystem_identity: observed_identity(11),
            record_kind: RecordKind::File,
            version_hash: version.version_hash,
        })],
        &permit(),
    )
    .expect("the scan batch must commit");

    assert_eq!(materialization_state(&db), MaterializationState::Hydrated);
    assert_eq!(
        usable_proof_version(&db),
        Some(Some(version.version_hash)),
        "the proof must name the version the scan derived for these bytes"
    );
}

/// The same batch for a path it could not observe: no proof, and no
/// claim carried forward from whatever the row used to be.
#[test]
fn the_non_emitting_scan_batch_retires_what_it_cannot_observe() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));
    assert_eq!(usable_proof_version(&db), Some(Some(v1.version_hash)));

    repo.upsert_files_batch(
        GROUP,
        &[record_at(2)],
        "device-a",
        &[Some(meta())],
        &[None],
        &permit(),
    )
    .expect("the scan batch must commit");

    assert_eq!(materialization_state(&db), MaterializationState::Placeholder);
    assert_eq!(usable_proof_version(&db), None);
}

/// A change whose ops and versions disagree is a caller that built them
/// inconsistently. It gets no proof -- and, since the row it superseded
/// may have had one, it does not get to keep that one either.
#[test]
fn an_emission_whose_version_the_change_does_not_carry_proves_nothing() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());

    let v1 = emit_version(&repo, 1, Some(observed_identity(11)));
    assert_eq!(usable_proof_version(&db), Some(Some(v1.version_hash)));

    let v2 = file_version(2);
    let unrelated = file_version(99);
    let emitter = emitter();
    let permit = permit();
    repo.upsert_file_emitting_change(
        GROUP,
        &record_at(2),
        "device-a",
        ChangeContent {
            ops: vec![Op::Put {
                path: SyncPath(PATH.to_string()),
                version: v2.version_hash,
                origin: PutOrigin::Direct,
            }],
            // The op names v2; the change carries some other version.
            versions: std::slice::from_ref(&unrelated),
        },
        Some(&meta()),
        Some(&observed_identity(12)),
        emission(&emitter, &permit),
    )
    .expect("the emission itself still commits");

    assert_eq!(materialization_state(&db), MaterializationState::Placeholder);
    assert_eq!(usable_proof_version(&db), None);
}

/// Every capture route records that the change it emits was read off this
/// device's own disk -- with or without a proof of what disk held, since an
/// unprovable capture is still a capture -- and each newer capture of the
/// path replaces the record. A change authored through the plain emission
/// seam (a restore, a repair, a backfill) is not recorded: its purpose is
/// to change the disk, not to describe it.
#[test]
fn every_capture_route_records_its_change_as_read_off_this_disk() {
    let db = open_full_test_db();
    let repo = FileIndexRepository::new(db.clone());
    let emitter = emitter();
    let permit = permit();
    let is_capture = |hash: &ChangeHash| {
        db.read(|conn| crate::local_capture_provenance::is_local_capture(conn, GROUP, PATH, hash))
            .unwrap()
    };
    let authored = || repo.get_authoring_change_hash(GROUP, PATH).unwrap().unwrap();

    emit_version(&repo, 1, None);
    let single = authored();
    assert!(is_capture(&single), "a single-path capture, even an unprovable one");

    let v2 = file_version(2);
    repo.commit_local_mutations_batch(
        GROUP,
        &[PreparedLocalMutation::Upsert {
            record: record_at(2),
            op: Op::Put {
                path: SyncPath(PATH.to_string()),
                version: v2.version_hash,
                origin: PutOrigin::Direct,
            },
            version: v2.clone(),
            meta: Some(meta()),
        }],
        &[],
        "device-a",
        emission(&emitter, &permit),
    )
    .unwrap();
    let batched = authored();
    assert!(is_capture(&batched), "the batched live-edit capture");
    assert!(!is_capture(&single), "a newer capture of the path replaces the record");

    let v3 = file_version(3);
    repo.upsert_files_batch_emitting_change(
        GROUP,
        &[record_at(3)],
        "device-a",
        ChangeContent {
            ops: vec![Op::Put {
                path: SyncPath(PATH.to_string()),
                version: v3.version_hash,
                origin: PutOrigin::Direct,
            }],
            versions: std::slice::from_ref(&v3),
        },
        &[],
        &std::collections::HashMap::new(),
        emission(&emitter, &permit),
    )
    .unwrap();
    assert!(is_capture(&authored()), "the scan's batched capture");
    let scanned = authored();

    let mut tombstone = record_at(4);
    tombstone.deleted = true;
    let batched_deletes = repo
        .commit_local_mutations_batch(
            GROUP,
            &[PreparedLocalMutation::Delete {
                record: tombstone,
                op: Op::Delete { path: SyncPath(PATH.to_string()) },
            }],
            &[Some(LocalCaptureActualStateEvidence::Absent)],
            "device-a",
            emission(&emitter, &permit),
        )
        .unwrap();
    assert_eq!(batched_deletes.len(), 1);
    assert_eq!(authored(), batched_deletes[0], "sanity: the row names the batched deletion");
    assert!(is_capture(&batched_deletes[0]), "the batched live-edit capture of a deletion");
    assert!(!is_capture(&scanned), "a newer capture of the path replaces the record");

    let deleted = repo
        .mark_deleted_emitting_change(
            GROUP,
            PATH,
            "device-a",
            4,
            false,
            emission(&emitter, &permit),
        )
        .unwrap();
    assert!(is_capture(&deleted), "a captured deletion");

    let v5 = file_version(5);
    let restored = db
        .write(|conn| {
            dag_store::put_file_version(conn, GROUP, &v5)?;
            dag_store::emit_local_change(
                conn,
                GROUP,
                vec![Op::Put {
                    path: SyncPath(PATH.to_string()),
                    version: v5.version_hash,
                    origin: PutOrigin::Direct,
                }],
                &emitter,
            )
        })
        .unwrap()
        .compute_hash();
    assert!(!is_capture(&restored), "a change authored to change the disk is not a capture");
}
