#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::Op;
use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

fn schema_init(conn: &Connection) -> Result<(), DatabaseError> {
    dag_store::init_dag_schema(conn).map_err(|e| DatabaseError::CorruptSchema(e.to_string()))?;
    // Every local-capture write settles the path's actual state one way
    // or the other -- publishing a proof, or retiring the one that is
    // there by advancing the fence -- so a fixture that reaches those
    // writers needs these tables for the same reason production opens
    // them unconditionally.
    crate::materialized_generation::init_materialized_generation_schema(conn)
        .map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
}

fn open_test_repo() -> ChangeHistoryRepository {
    let database = Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"));
    ChangeHistoryRepository::new(database)
}

/// One write transaction on a database no test repository here uses --
/// what a sibling test running on another thread does to its own database
/// at an arbitrary moment. A writer-gate count that claims to describe one
/// repository must not move when this runs.
fn write_to_unrelated_database() {
    let bystander = SyncDatabase::open_in_memory(|_| Ok(())).expect("open bystander db");
    bystander
        .write(|conn| conn.execute_batch("CREATE TABLE t (x INTEGER)").map_err(DatabaseError::from))
        .expect("bystander write");
}

fn create_op(path: &str) -> Op {
    Op::Delete { path: yadorilink_replica_domain::ids::SyncPath(path.to_string()) }
}

// `dag_admit_change_batch_with_versions` regression coverage. See that method's own doc comment for
// the guarantees these five tests each check.

/// Batch amplification: N healthy remote Changes admitted through the
/// OLD one-call-per-Change path cause N writer_gate acquisitions; the
/// SAME N Changes admitted through the new batched path, chunked at
/// `REMOTE_ADMISSION_BATCH_SIZE`, must cause only `ceil(N /
/// REMOTE_ADMISSION_BATCH_SIZE)`. Confirmed genuinely RED by calling
/// `dag_admit_change_with_versions` once per item instead of chunking
/// through the batch method: the batched-path assertion below then
/// fails (17 acquisitions instead of 3), since the whole reduction is
/// exactly what did not exist before this fix.
#[test]
fn batched_admission_reduces_writer_gate_acquisitions_to_ceil_n_over_batch_size() {
    let sender = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender).unwrap();
    let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[11u8; 32]));
    // Deliberately not a multiple of REMOTE_ADMISSION_BATCH_SIZE (8), to
    // prove the batching rounds UP (ceil), not down.
    let n = 17;
    let changes: Vec<Change> = (0..n)
        .map(|i| {
            dag_store::emit_local_change(&sender, "g", vec![create_op(&format!("p{i}"))], &em)
                .unwrap()
        })
        .collect();

    // OLD path, for direct comparison in the same test: N calls, N
    // acquisitions -- unaffected by this fix, still correct.
    let sequential_repo = open_test_repo();
    let before = sequential_repo.database.write_transaction_count();
    for change in &changes {
        sequential_repo.dag_admit_change(change).unwrap();
    }
    write_to_unrelated_database();
    let sequential_acquisitions = sequential_repo.database.write_transaction_count() - before;
    assert_eq!(
        sequential_acquisitions, n as u64,
        "sanity: the pre-existing one-call-per-Change path must still take one gate \
         acquisition per Change"
    );

    // NEW path: chunk into REMOTE_ADMISSION_BATCH_SIZE-sized micro-batches.
    let batched_repo = open_test_repo();
    let before = batched_repo.database.write_transaction_count();
    let items: Vec<PendingAdmission> = changes
        .iter()
        .map(|c| PendingAdmission { change: c, versions: &[], evidence: None })
        .collect();
    for chunk in items.chunks(REMOTE_ADMISSION_BATCH_SIZE) {
        for result in batched_repo.dag_admit_change_batch_with_versions(chunk) {
            assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
        }
    }
    write_to_unrelated_database();
    let batched_acquisitions = batched_repo.database.write_transaction_count() - before;
    let expected = (n as u64).div_ceil(REMOTE_ADMISSION_BATCH_SIZE as u64);
    assert_eq!(
        batched_acquisitions, expected,
        "{n} Changes chunked at {REMOTE_ADMISSION_BATCH_SIZE} must take ceil({n} / \
         {REMOTE_ADMISSION_BATCH_SIZE}) = {expected} gate acquisitions, not {n}"
    );
}

/// Parent/orphan chain, out-of-order, inside one micro-batch: admitting
/// `[leaf, parent]` (child before its own parent) in ONE batch call must
/// produce the identical final state sequential admission of the same
/// two items, in the same order, would -- leaf buffers as an orphan on
/// its own item, then gets promoted as a side effect of parent's own
/// admission a moment later, ALL inside the same outer transaction (the
/// promotion sees the leaf's own already-committed-to-the-outer-
/// transaction buffered row, exactly as it would see a separately
/// committed one). Confirmed genuinely RED by admitting `parent` before
/// `leaf` in the item slice instead (reversing the order the real bug
/// this batching change could introduce would get wrong): the
/// assertions below (leaf `Orphaned` at its own index, parent's
/// `newly_admitted` containing leaf's hash) fail under that reversed
/// order, proving this test actually depends on order being preserved
/// rather than passing vacuously regardless of it.
#[test]
fn out_of_order_parent_child_inside_one_micro_batch_promotes_exactly_as_sequential_admission_would()
{
    let sender = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender).unwrap();
    let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[33u8; 32]));
    let parent =
        dag_store::emit_local_change(&sender, "g", vec![create_op("parent")], &em).unwrap();
    let leaf = dag_store::emit_local_change(&sender, "g", vec![create_op("leaf")], &em).unwrap();

    let repo = open_test_repo();
    // leaf BEFORE parent -- the out-of-order arrival this test targets.
    let items = [
        PendingAdmission { change: &leaf, versions: &[], evidence: None },
        PendingAdmission { change: &parent, versions: &[], evidence: None },
    ];
    let mut results = repo.dag_admit_change_batch_with_versions(&items).into_iter();
    let leaf_result = results.next().unwrap().unwrap();
    let parent_result = results.next().unwrap().unwrap();

    assert_eq!(
        leaf_result.outcome,
        dag_store::AdmitOutcome::Orphaned,
        "leaf's own item result must show Orphaned -- its parent had not been admitted yet \
         at leaf's own position in the batch"
    );
    assert_eq!(
        parent_result.outcome,
        dag_store::AdmitOutcome::Applied,
        "parent must admit cleanly"
    );
    assert!(
        parent_result.newly_admitted.contains(&leaf.compute_hash()),
        "parent's own AdmitResult must report leaf as promoted alongside it -- the same \
         `newly_admitted` shape sequential admission (admit leaf, then admit parent) would \
         produce, since promote_orphans finds leaf already buffered in the same outer \
         transaction"
    );
    repo.database
        .read::<_, SyncSqliteError>(|conn| {
            assert!(
                dag_store::has_change(conn, &leaf.compute_hash()).unwrap(),
                "leaf must be durably promoted, not left buffered, once its own micro-batch \
                 completes"
            );
            Ok(())
        })
        .unwrap();
}

/// Projection: every genuinely admitted Change in a micro-batch must
/// still bump the correct `projection_obligations` row for the paths
/// its own ops touch -- the bump happens inside `admit_change` itself
/// (unchanged by this fix), but this test proves it still fires when
/// `admit_change` runs against a `Savepoint` instead of directly
/// against the outer `Transaction`.
#[test]
fn batched_admission_still_bumps_projection_obligations_for_touched_paths() {
    let sender = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender).unwrap();
    let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[44u8; 32]));
    let a = dag_store::emit_local_change(&sender, "g", vec![create_op("path-a")], &em).unwrap();
    let b = dag_store::emit_local_change(&sender, "g", vec![create_op("path-b")], &em).unwrap();

    let repo = open_test_repo();
    let items = [
        PendingAdmission { change: &a, versions: &[], evidence: None },
        PendingAdmission { change: &b, versions: &[], evidence: None },
    ];
    for result in repo.dag_admit_change_batch_with_versions(&items) {
        assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
    }
    repo.database
        .read::<_, SyncSqliteError>(|conn| {
            for path in ["path-a", "path-b"] {
                let obligation =
                    crate::projection_obligations::lookup_projection_obligation(conn, "g", path)
                        .unwrap();
                assert!(
                    obligation.is_some(),
                    "{path} must have a projection obligation after batched admission"
                );
                assert!(
                    obligation.unwrap().invalidation_generation >= 1,
                    "{path}'s obligation must show a genuine invalidation, not a placeholder \
                     row"
                );
            }
            Ok(())
        })
        .unwrap();
}

/// Duplicate replay: re-admitting an already-admitted Change alongside a
/// genuinely new one, in the same micro-batch, must not bump the
/// already-admitted one's obligation a second time ("a Change
/// receipt is not a projection event," still enforced per-item inside a
/// batch) -- while the genuinely new Change still gets its own bump.
#[test]
fn duplicate_replay_inside_a_batch_does_not_double_bump_its_own_obligation() {
    let sender = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender).unwrap();
    let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[55u8; 32]));
    let already_known =
        dag_store::emit_local_change(&sender, "g", vec![create_op("path-known")], &em).unwrap();
    let genuinely_new =
        dag_store::emit_local_change(&sender, "g", vec![create_op("path-new")], &em).unwrap();

    let repo = open_test_repo();
    repo.dag_admit_change(&already_known).unwrap();
    let generation_before = repo
        .database
        .read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-known")
        })
        .unwrap()
        .unwrap()
        .invalidation_generation;

    let items = [
        PendingAdmission { change: &already_known, versions: &[], evidence: None },
        PendingAdmission { change: &genuinely_new, versions: &[], evidence: None },
    ];
    for result in repo.dag_admit_change_batch_with_versions(&items) {
        assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
    }

    let generation_after = repo
        .database
        .read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-known")
        })
        .unwrap()
        .unwrap()
        .invalidation_generation;
    assert_eq!(
        generation_before, generation_after,
        "re-delivering an already-admitted Change inside a batch must not bump its \
         obligation's invalidation_generation again"
    );

    let new_obligation = repo
        .database
        .read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-new")
        })
        .unwrap();
    assert!(
        new_obligation.is_some(),
        "the genuinely new Change in the same batch must still get its own obligation"
    );
}

// --- `append_initial_import`'s in-transaction freshness check ---

use crate::file_index::FileIndexRepository;
use yadorilink_replica_domain::file::{FileMeta, FileRecord, RecordKind};
use yadorilink_root_authority::root_commit::RootCommitPermit;

/// Full schema (DAG tables + the real `files` table and its
/// authoring-identity triggers), matching `file_index.rs`'s own
/// `open_full_test_db` -- needed here because, unlike this module's
/// other tests, `append_initial_import`'s new freshness check reads
/// `files` directly.
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
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

/// RED->GREEN for Race A (the `ensure_initial_import` snapshot race):
/// `batches` built from a snapshot that missed a row which is, at
/// commit time, still unbound and still uncovered by those `batches`.
/// Committing anyway would make the group DAG-backed while that row
/// stays permanently unauthored. It must refuse to commit and report `StaleSnapshot`
/// instead, leaving every row exactly as it was.
#[test]
fn append_initial_import_refuses_to_commit_when_a_row_is_missing_from_its_own_snapshot() {
    let db = open_full_test_db();
    let file_index = FileIndexRepository::new(db.clone());
    let history = ChangeHistoryRepository::new(db.clone());
    let permit = RootCommitPermit::for_tests();

    // Two rows exist and are unbound (DAG still empty). `batches` below
    // covers only ONE of them -- as if the snapshot that built it was
    // taken before the second row's scan chunk landed.
    file_index
        .upsert_files_batch(
            "g",
            &[
                FileRecord {
                    path: "covered.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
                FileRecord {
                    path: "missed.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(),
                    deleted: false,
                },
            ],
            "device-0",
            &[],
            &[],
            &permit,
        )
        .expect("accepted while the group's DAG is still empty");

    let version = FileVersion::new(
        Vec::new(),
        1,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let batches = vec![vec![Op::Put {
        path: yadorilink_replica_domain::ids::SyncPath("covered.txt".into()),
        version: version.version_hash,
        origin: yadorilink_replica_domain::change::PutOrigin::Direct,
    }]];
    let em = ChangeEmitter::new("device-0", SigningKey::from_bytes(&[7u8; 32]));

    let outcome = history
        .append_initial_import(
            "g",
            &batches,
            std::slice::from_ref(&version),
            &em,
            &HashSet::new(),
            &std::collections::HashMap::new(),
        )
        .expect("the call itself must not error -- refusing to commit is a normal outcome");
    assert_eq!(
        outcome,
        ImportAppendOutcome::StaleSnapshot,
        "must refuse rather than commit an import that leaves `missed.txt` permanently unbound"
    );

    // Nothing committed: the group is still exactly as un-DAG-backed as
    // it was, and BOTH rows are still unbound -- not just the missed one.
    assert!(
        db.read::<_, SyncSqliteError>(|conn| dag_store::group_heads(conn, "g")).unwrap().is_empty(),
        "a refused import must not leave a partial head behind"
    );
    let still_unbound = file_index.list_unauthored_current_paths("g").unwrap();
    assert_eq!(
        still_unbound.len(),
        2,
        "a refused import must leave every row exactly as unbound as it found it: {still_unbound:?}"
    );
}

/// GREEN companion: the same shape, but `batches` covers every
/// currently-unbound row -- must commit normally.
#[test]
fn append_initial_import_commits_when_its_snapshot_matches_every_unbound_row() {
    let db = open_full_test_db();
    let file_index = FileIndexRepository::new(db.clone());
    let history = ChangeHistoryRepository::new(db.clone());
    let permit = RootCommitPermit::for_tests();

    file_index
        .upsert_files_batch(
            "g",
            &[FileRecord {
                path: "covered.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            }],
            "device-0",
            &[],
            &[],
            &permit,
        )
        .unwrap();

    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let batches = vec![vec![Op::Put {
        path: yadorilink_replica_domain::ids::SyncPath("covered.txt".into()),
        version: version.version_hash,
        origin: yadorilink_replica_domain::change::PutOrigin::Direct,
    }]];
    let em = ChangeEmitter::new("device-0", SigningKey::from_bytes(&[7u8; 32]));

    let outcome = history
        .append_initial_import(
            "g",
            &batches,
            std::slice::from_ref(&version),
            &em,
            &HashSet::new(),
            &std::collections::HashMap::new(),
        )
        .unwrap();
    assert_eq!(outcome, ImportAppendOutcome::Committed(1));
    assert!(file_index.list_unauthored_current_paths("g").unwrap().is_empty());
}

/// The initial import binds rows the scan read off this device's own disk,
/// so the change it emits for such a row is a capture of that disk, just as
/// the scan's own emission would have been -- including for a row whose disk
/// state the import could not prove (no observation for it).
#[test]
fn append_initial_import_records_the_rows_it_binds_as_captures() {
    let db = open_full_test_db();
    let file_index = FileIndexRepository::new(db.clone());
    let history = ChangeHistoryRepository::new(db.clone());
    let permit = RootCommitPermit::for_tests();
    file_index
        .upsert_files_batch(
            "g",
            &[FileRecord {
                path: "scanned.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            }],
            "device-0",
            &[],
            &[],
            &permit,
        )
        .unwrap();
    let version = FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let put = |path: &str| Op::Put {
        path: yadorilink_replica_domain::ids::SyncPath(path.into()),
        version: version.version_hash,
        origin: yadorilink_replica_domain::change::PutOrigin::Direct,
    };
    let em = ChangeEmitter::new("device-0", SigningKey::from_bytes(&[7u8; 32]));

    let outcome = history
        .append_initial_import(
            "g",
            &[vec![put("scanned.txt")]],
            std::slice::from_ref(&version),
            &em,
            &HashSet::new(),
            &std::collections::HashMap::new(),
        )
        .unwrap();

    assert_eq!(outcome, ImportAppendOutcome::Committed(1));
    let import = file_index.get_authoring_change_hash("g", "scanned.txt").unwrap().unwrap();
    let is_capture = db
        .read(|conn| {
            crate::local_capture_provenance::is_local_capture(conn, "g", "scanned.txt", &import)
        })
        .unwrap();
    assert!(is_capture, "a row the import bound was read off this disk");
}

/// A change the author chain refuses, admitted through the batch method the
/// replica coordinator's own admission port calls, must come back settled:
/// never retained, never buffered, and never asked of a peer again.
///
/// The lower-level `dag_store::admit_change` already has this coverage. It
/// is repeated here because this is the path production actually takes for
/// remote changes -- the coordinator's admission port calls this method and
/// nothing else -- and because the two differ in the one way that can lose
/// the record: this method wraps the whole chunk in an outer transaction it
/// commits itself. A durable record written inside the verdict but rolled
/// back with the chunk would look identical from inside `dag_store` and
/// still leave the hash re-requested at every heads exchange.
///
/// The refusal is the ordinary one: three changes by one author arrive
/// together, and the third sits at the right sequence but names its
/// author's FIRST change as its predecessor rather than its tip. Its DAG
/// parents are all present in the same batch, so nothing holds it as an
/// orphan; the author chain is the only thing that can decide it.
#[test]
fn a_refusal_through_the_coordinators_admission_port_is_settled_not_re_requested() {
    let sender = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender).unwrap();
    let signing = SigningKey::from_bytes(&[41u8; 32]);
    let em = ChangeEmitter::new("device-A", signing.clone());
    let a1 = dag_store::emit_local_change(&sender, "g", vec![create_op("a1")], &em).unwrap();
    let a2 = dag_store::emit_local_change(&sender, "g", vec![create_op("a2")], &em).unwrap();

    // Sequence 3 is exactly the position the author chain expects next, so
    // the naming is the only thing wrong with it.
    let misnamed = Change::create_signed(
        vec![a2.compute_hash()],
        a2.lamport,
        yadorilink_replica_domain::ids::DeviceId("device-A".to_owned()),
        yadorilink_replica_domain::ids::AuthorSeq(3),
        Some(a1.compute_hash()),
        yadorilink_replica_domain::ids::FolderGroupId("g".to_owned()),
        yadorilink_replica_domain::rebootstrap::HistoryEpoch::Genesis,
        vec![create_op("misnamed")],
        &signing,
    );
    let misnamed_hash = misnamed.compute_hash();

    let repo = open_test_repo();
    assert!(
        !repo.dag_has_change_or_buffered_orphan(&misnamed_hash).unwrap(),
        "sanity: before the batch runs this hash is one we would still ask a peer for"
    );

    let items = [
        PendingAdmission { change: &a1, versions: &[], evidence: None },
        PendingAdmission { change: &a2, versions: &[], evidence: None },
        PendingAdmission { change: &misnamed, versions: &[], evidence: None },
    ];
    let mut results = repo.dag_admit_change_batch_with_versions(&items).into_iter();
    assert!(matches!(results.next().unwrap().unwrap().outcome, dag_store::AdmitOutcome::Applied));
    assert!(matches!(results.next().unwrap().unwrap().outcome, dag_store::AdmitOutcome::Applied));
    let refused = results.next().unwrap().unwrap().outcome;
    assert!(
        matches!(
            refused,
            dag_store::AdmitOutcome::RefusedAuthorChain(
                dag_store::AuthorChainRefusal::AuthorPrevMismatch { .. }
            )
        ),
        "got {refused:?}"
    );

    assert!(!repo.dag_has_change(&misnamed_hash).unwrap(), "the refused change is not retained");
    assert!(
        repo.dag_has_change_or_buffered_orphan(&misnamed_hash).unwrap(),
        "yet it is settled after the chunk committed: a peer must not be asked for it again"
    );
}

/// A change refused for a path it names, admitted through the batch method
/// the replica coordinator's admission port calls, must leave the refusal
/// durable and release whatever was buffered waiting on it.
///
/// The batch method runs admission inside a transaction it opens and commits
/// itself, and a refusal returned as an error rolls that transaction back
/// with everything written inside the verdict: the durable rejection row and
/// the release of the changes held against the refused hash. The refused
/// hash would then be reported missing and asked of a peer at every heads
/// exchange, and the change waiting on it would stay held forever. A bare
/// connection autocommits each statement and cannot show this, so the
/// lower-level `dag_store` coverage passes either way.
///
/// B:1 names A:1 as its DAG parent and arrives first, so it is held. A:1
/// names a path containing a colon, which no Windows replica can store.
#[test]
fn a_path_refusal_through_the_coordinators_admission_port_is_durable_and_releases_its_dependents() {
    let group = yadorilink_replica_domain::ids::FolderGroupId("g".to_owned());
    let key_a = SigningKey::from_bytes(&[43u8; 32]);
    let key_b = SigningKey::from_bytes(&[44u8; 32]);
    let a1 = Change::create_signed(
        vec![],
        1,
        yadorilink_replica_domain::ids::DeviceId("device-A".to_owned()),
        yadorilink_replica_domain::ids::AuthorSeq(1),
        None,
        group.clone(),
        yadorilink_replica_domain::rebootstrap::HistoryEpoch::Genesis,
        vec![create_op("notes:draft.txt")],
        &key_a,
    );
    let b1 = Change::create_signed(
        vec![a1.compute_hash()],
        2,
        yadorilink_replica_domain::ids::DeviceId("device-B".to_owned()),
        yadorilink_replica_domain::ids::AuthorSeq(1),
        None,
        group,
        yadorilink_replica_domain::rebootstrap::HistoryEpoch::Genesis,
        vec![create_op("b1")],
        &key_b,
    );
    let (a1_hash, b1_hash) = (a1.compute_hash(), b1.compute_hash());

    let repo = open_test_repo();
    let held = repo
        .dag_admit_change_batch_with_versions(&[PendingAdmission {
            change: &b1,
            versions: &[],
            evidence: None,
        }])
        .remove(0)
        .unwrap();
    assert!(matches!(held.outcome, dag_store::AdmitOutcome::Orphaned), "got {held:?}");

    let refused = repo
        .dag_admit_change_batch_with_versions(&[PendingAdmission {
            change: &a1,
            versions: &[],
            evidence: None,
        }])
        .remove(0);
    assert!(
        matches!(
            refused,
            Ok(dag_store::AdmitResult {
                outcome: dag_store::AdmitOutcome::RefusedPath(
                    dag_store::PathRefusal::NonPortablePath { .. }
                ),
                ..
            })
        ),
        "a non-portable path must be refused, and as an outcome so the batch commits: \
         got {refused:?}"
    );

    assert!(!repo.dag_has_change(&a1_hash).unwrap(), "the refused change is not retained");
    assert!(
        repo.dag_has_change_or_buffered_orphan(&a1_hash).unwrap(),
        "the refusal must survive the batch's own transaction: a peer must not be asked for \
         A:1 again"
    );
    assert!(
        !repo.dag_has_change_or_buffered_orphan(&b1_hash).unwrap(),
        "B:1 waits on a parent that can never arrive, so the refusal must release it"
    );

    // A peer that still holds B:1 sends it again. Its parent can never be
    // held here, so it is refused rather than buffered behind a name that
    // is already settled.
    let redelivered = repo
        .dag_admit_change_batch_with_versions(&[PendingAdmission {
            change: &b1,
            versions: &[],
            evidence: None,
        }])
        .remove(0)
        .unwrap();
    assert_eq!(
        redelivered.outcome,
        dag_store::AdmitOutcome::RefusedBehindRejectedParent { parent: a1_hash },
        "a redelivered B:1 must be refused, not held again: got {redelivered:?}"
    );
    assert!(
        repo.dag_has_change_or_buffered_orphan(&b1_hash).unwrap(),
        "and settled: a peer must not be asked for B:1 again either"
    );
}
