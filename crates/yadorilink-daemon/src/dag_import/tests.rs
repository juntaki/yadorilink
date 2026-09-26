#![cfg(test)]

use super::*;

/// `import_create_op` against the live current row for `path` -- the
/// production shape, where the op and the version come from one read
/// of one incarnation.
fn op_for(
    state: &ReplicaCoordinator,
    path: &str,
) -> (Op, FileVersion, yadorilink_replica_domain::file::RecordKind) {
    let row = state
        .file_index_repository()
        .canonical_current_row("g", path)
        .expect("canonical current row")
        .expect("a seeded row");
    import_create_op(path, &row)
}

use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::BlockHash;
fn emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-A", SigningKey::from_bytes(&[9u8; 32]))
}

/// A record describing exactly what is on disk at `abs`, so an import
/// of it is the ordinary, unraced case.
fn record_matching_disk(rel: &str, abs: &std::path::Path) -> FileRecord {
    let meta = std::fs::metadata(abs).unwrap();
    let mtime =
        meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64;
    FileRecord {
        path: rel.into(),
        size: meta.len(),
        mtime_unix_nanos: mtime,
        blocks: vec![BlockInfo { hash: vec![7, 7, 7], offset: 0, size: meta.len() as u32 }],
        deleted: false,
    }
}

fn has_proof(state: &ReplicaCoordinator, group: &str, path: &str) -> bool {
    state.sqlite().dag_lookup_materialized_generation(group, path).unwrap().is_some()
}

/// The stronger form of the same race: an overwrite that leaves the
/// file looking untouched.
///
/// Size and mtime are what cheap checks compare, and both can be
/// identical after an in-place overwrite -- same length, and an mtime
/// restored to what it was. A fingerprint taken around the identity
/// observation does not help either: it proves nothing changed during
/// that observation, which is true, because the change already
/// happened before it started.
///
/// What is actually missing is a link between the two halves of the
/// proof. The version comes from the scan, possibly long ago; the
/// identity comes from now. Nothing establishes that they describe the
/// same bytes. Only reading what is on disk now and comparing it to
/// what the index recorded can establish that, so that is what the
/// import does before it vouches for anything.
#[test]
fn an_import_writes_no_proof_when_an_overwrite_left_size_and_mtime_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let abs = root.path().join("silent.txt");
    std::fs::write(&abs, b"AAAAAAAA").unwrap();

    // The index knows this path as the bytes currently there, with
    // real block hashes over them -- exactly what a scan records.
    let meta = std::fs::metadata(&abs).unwrap();
    let mtime =
        meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64;
    use sha2::Digest as _;
    let record = FileRecord {
        path: "silent.txt".into(),
        size: 8,
        mtime_unix_nanos: mtime,
        blocks: vec![BlockInfo {
            hash: sha2::Sha256::digest(b"AAAAAAAA").to_vec(),
            offset: 0,
            size: 8,
        }],
        deleted: false,
    };
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Overwritten in place with different bytes of the same length,
    // and the mtime put back. Nothing about the file's metadata now
    // says it was touched.
    std::fs::write(&abs, b"BBBBBBBB").unwrap();
    // Opened for writing: Windows refuses to set times through a read-only
    // handle.
    let restored = std::fs::File::options().write(true).open(&abs).unwrap();
    restored
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(meta.accessed().unwrap())
                .set_modified(meta.modified().unwrap()),
        )
        .unwrap();
    drop(restored);

    let now = std::fs::metadata(&abs).unwrap();
    assert_eq!(now.len(), record.size, "sanity: the overwrite must not change the size");
    assert!(
        metadata_mtime_matches(&now, record.mtime_unix_nanos),
        "sanity: the mtime must have been restored, or this tests nothing new"
    );

    ensure_initial_import(&state, "g", &emitter(), Some(root.path())).unwrap();

    assert!(
        !has_proof(&state, "g", "silent.txt"),
        "an overwrite that restored size and mtime still changed the content -- the import \
         must not vouch for a version it can no longer show is on disk"
    );
}

/// An import must not vouch for content that is no longer on disk.
///
/// The version an import writes into history comes from the index,
/// recorded when the folder was scanned. The proof that the path is
/// already materialized comes from observing the file now. Those are
/// two observations of the same path at two different times, and
/// nothing about the second one says the bytes still match the first.
///
/// Overwrite the file in place between them and both halves still look
/// individually fine: the version is a real version, the identity is a
/// real identity of a real object at that path, and because an in-place
/// overwrite keeps the inode, identity revalidation against disk can
/// even confirm it. The proof then asserts that the path already holds
/// the old content, and the obligation to actually put that content
/// there is closed -- leaving the wrong bytes on disk, permanently,
/// with nothing left that would notice.
///
/// No proof is the status quo. A wrong proof is not.
#[test]
fn an_import_writes_no_proof_for_a_file_that_changed_since_it_was_scanned() {
    let root = tempfile::tempdir().unwrap();
    let abs = root.path().join("raced.txt");
    std::fs::write(&abs, b"content A").unwrap();

    // The index knows this path as content A, exactly as a scan would
    // have left it.
    let record = record_matching_disk("raced.txt", &abs);
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Something overwrites it in place -- same path, same inode,
    // different bytes -- before the import runs.
    let before = std::fs::metadata(&abs).unwrap();
    std::fs::write(&abs, b"content B is a different length entirely").unwrap();
    let after = std::fs::metadata(&abs).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(before.ino(), after.ino(), "sanity: the overwrite must reuse the inode");
    }

    let outcome = ensure_initial_import(&state, "g", &emitter(), Some(root.path())).unwrap();
    assert!(
        matches!(outcome, ImportOutcome::Imported { .. }),
        "the import itself must still run: the version it records is a real one, and \
         refusing to import would strand the path entirely"
    );

    assert!(
        !has_proof(&state, "g", "raced.txt"),
        "the import must not claim a path is already materialized when what is on disk is \
         not what it just put into history"
    );
}

fn live(path: &str) -> FileRecord {
    FileRecord {
        path: path.into(),
        size: 3,
        mtime_unix_nanos: 1,
        blocks: vec![BlockInfo { hash: vec![1, 2, 3], offset: 0, size: 3 }],
        deleted: false,
    }
}

fn tombstone(path: &str) -> FileRecord {
    FileRecord { path: path.into(), size: 0, mtime_unix_nanos: 5, blocks: vec![], deleted: true }
}

#[test]
fn converts_live_and_tombstoned_records_in_one_change() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("a.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &tombstone("gone.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 2 });

    // Exactly one root head, whose change carries a Create for the live
    // file and a Delete for the tombstone.
    let heads = state.sqlite().dag_group_heads("g").unwrap();
    assert_eq!(heads.len(), 1);
    let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
    assert_eq!(
        state.file_index_repository().get_authoring_change_hash("g", "a.txt").unwrap(),
        Some(heads[0])
    );
    assert_eq!(
        state.file_index_repository().get_authoring_change_hash("g", "gone.txt").unwrap(),
        Some(heads[0])
    );
    assert!(change.parents.is_empty());
    assert!(change
        .ops
        .iter()
        .any(|op| matches!(op, Op::Put { path, .. } if path.as_str() == "a.txt")));
    assert!(change
        .ops
        .iter()
        .any(|op| matches!(op, Op::Delete { path } if path.as_str() == "gone.txt")));
}

#[test]
fn dag_backed_current_rows_require_a_verified_authoring_identity() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let seeded = live("seeded.txt");
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &seeded,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let (op, version, _) = op_for(&state, &seeded.path);
    let author = state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

    let error = state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("identity-less.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .map_err(SyncError::from)
        .expect_err("a DAG-backed group must reject a current row with no author");
    assert!(matches!(error, SyncError::Db(_)), "{error:?}");

    state
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            "g",
            &live("identified.txt"),
            "device-A",
            &author,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(
        state.file_index_repository().get_authoring_change_hash("g", "identified.txt").unwrap(),
        Some(author)
    );
}

#[test]
fn import_version_hash_matches_live_emission() {
    // The create op's version hash must equal what a normal local edit
    // would have emitted for the same record, so the two never diverge.
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let record = live("a.txt");
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (op, _version, _) = op_for(&state, &record.path);
    let Op::Put { version, .. } = op else { panic!("expected a put op") };

    let expected = FileVersion::new(
        record
            .blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect(),
        record.size,
        FileMeta {
            mtime_unix_nanos: record.mtime_unix_nanos,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
    .version_hash;
    assert_eq!(version, expected);
}

#[test]
fn import_preserves_a_stored_directory_kind() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let mut record = live("folder");
    record.size = 0;
    record.blocks.clear();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_record_kind(
            "g",
            "folder",
            RecordKind::Directory,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (_, version, _) = op_for(&state, &record.path);
    assert_eq!(version.meta.record_kind, RecordKind::Directory);
}

/// The one-time import mints a directory's version from its index row,
/// which carries the size and mtime this device's filesystem reported.
/// Those are not part of a directory's identity: the imported version
/// must be the canonical one every other device derives for the same
/// directory, and it must pass the validation a peer applies on receipt.
#[test]
fn import_of_a_directory_row_mints_the_canonical_directory_version() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let mut record = live("folder");
    record.size = 96;
    record.mtime_unix_nanos = 1_700_000_000_000_000_001;
    record.blocks.clear();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_record_kind(
            "g",
            "folder",
            RecordKind::Directory,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let (_, version, _) = op_for(&state, &record.path);
    assert_eq!(version.size, 0);
    assert_eq!(version.meta.mtime_unix_nanos, 0);
    version.verify_hash().expect("an imported directory version must be admissible");
}

/// Regression test for a confirmed, reproduced convergence-killer (see
/// `backfill_missing_history`'s own comment on the conflict-copy
/// filter): a projection-derived conflict copy is indexed on every
/// observing device before any change carries it, and the coverage
/// audit used to read that window as "indexed path missing from
/// history" and mint a per-device `Direct` create for it — several
/// devices concurrently, for the same copy path. The carrier is the
/// retroactive conflict-copy repair's to emit, so the audit must skip
/// conflict-copy-shaped paths entirely (also on repeat calls: the path
/// must not keep the audit reporting work forever), while still
/// repairing an ordinary path in the same pass.
#[tokio::test]
async fn backfill_skips_a_derived_conflict_copy_path_but_repairs_an_ordinary_one() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.set_local_policy_head_provider(std::sync::Arc::new(|_| Ok([4u8; 32])));
    // Seed one head so this exercises the mid-life coverage audit, not
    // initial import.
    let seeded = live("seeded.txt");
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &seeded,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let (op, version, _) = op_for(&state, &seeded.path);
    let seed_author = state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

    let copy_path = yadorilink_replica_domain::conflict::conflict_copy_path(
        "chaos-05.bin",
        1_000,
        "device-B",
        &[0xf6, 0xca, 0xc4, 0xff],
    );
    state
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            "g",
            &live(&copy_path),
            "device-A",
            &seed_author,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            "g",
            &live("ordinary.bin"),
            "device-A",
            &seed_author,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::Backfilled { paths: 1 }
    );
    let history = state.change_history_repository().dag_group_history_paths("g").unwrap();
    assert!(history.contains("ordinary.bin"), "the ordinary gap must still be repaired");
    assert!(
        !history.contains(&copy_path),
        "a derived conflict copy must never be minted into history by the coverage audit"
    );
    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::NothingMissing,
        "the skipped copy path must not keep the audit claiming outstanding work"
    );
}

/// The mid-life coverage audit's own version of the initial-import
/// test above: a pre-existing index row that collides with the
/// reserved artefact namespace must never be backfilled into history,
/// while an ordinary coverage gap around it is still repaired, and the
/// audit must not keep reporting outstanding work once the only
/// remaining gap is the permanently-skipped collision.
#[tokio::test]
async fn backfill_skips_a_pre_existing_reserved_namespace_collision_but_repairs_an_ordinary_one() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.set_local_policy_head_provider(std::sync::Arc::new(|_| Ok([4u8; 32])));
    let seeded = live("seeded.txt");
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &seeded,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let (op, version, _) = op_for(&state, &seeded.path);
    let seed_author = state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();

    let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
        yadorilink_root_authority::reserved_namespace::ArtefactKind::Backup,
        "cafef00d",
    )
    .unwrap();
    state
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            "g",
            &live(&artefact_path),
            "device-A",
            &seed_author,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file_with_origin_and_author(
            "g",
            &live("ordinary.bin"),
            "device-A",
            &seed_author,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::Backfilled { paths: 1 }
    );
    let history = state.change_history_repository().dag_group_history_paths("g").unwrap();
    assert!(history.contains("ordinary.bin"), "the ordinary gap must still be repaired");
    assert!(
        !history.contains(&artefact_path),
        "a reserved-namespace collision must never be minted into history by the coverage audit"
    );
    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::NothingMissing,
        "the permanently-skipped collision must not keep the audit claiming outstanding work"
    );
}

#[tokio::test]
async fn audit_repairs_policy_withheld_initial_import_after_another_path_creates_a_head() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let policy_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready = policy_ready.clone();
    state.set_local_policy_head_provider(std::sync::Arc::new(move |_| {
        if ready.load(std::sync::atomic::Ordering::SeqCst) {
            Ok([4u8; 32])
        } else {
            Err(yadorilink_replica_domain::change::PolicyUnavailable)
        }
    }));
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("missed.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(matches!(
        ensure_initial_import(&state, "g", &emitter(), None),
        Err(SyncError::PolicyUnavailable)
    ));

    policy_ready.store(true, std::sync::atomic::Ordering::SeqCst);
    let other = live("later.txt");
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &other,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let (op, version, _) = op_for(&state, &other.path);
    state.append_history_backfill("g", vec![op], &[version], &emitter()).unwrap();
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);

    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::Backfilled { paths: 1 }
    );
    assert!(state
        .change_history_repository()
        .dag_group_history_paths("g")
        .unwrap()
        .contains("missed.txt"));
    assert_eq!(
        backfill_missing_history(&state, "g", &emitter()).await.unwrap(),
        BackfillOutcome::NothingMissing
    );
}

#[test]
fn second_run_does_not_duplicate_history() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("a.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    assert_eq!(
        ensure_initial_import(&state, "g", &emitter(), None).unwrap(),
        ImportOutcome::Imported { changes: 1, ops: 1 }
    );
    let head_after_first = state.sqlite().dag_group_heads("g").unwrap();

    assert_eq!(
        ensure_initial_import(&state, "g", &emitter(), None).unwrap(),
        ImportOutcome::AlreadyInitialized
    );
    // No second root injected: the head set is byte-identical.
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), head_after_first);
}

/// A pre-upgrade database can already hold an index row for a path
/// that collides with the reserved artefact namespace — it was
/// ordinary content before this module's exclusion existed. Initial
/// import must skip that one row (never turn it into signed history)
/// while still importing every ordinary row around it, matching
/// admission's own artefact-only rejection: the blocked path is
/// reported (via a log line this test doesn't assert on directly) but
/// import does not error or stall for the rest of the index.
#[test]
fn ensure_initial_import_skips_a_pre_existing_reserved_namespace_collision() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
        yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
        "deadbeef",
    )
    .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("a.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live(&artefact_path),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

    let heads = state.sqlite().dag_group_heads("g").unwrap();
    assert_eq!(heads.len(), 1);
    let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
    assert!(
        change
            .ops
            .iter()
            .all(|op| !matches!(op, Op::Put { path, .. } if path.as_str() == artefact_path)),
        "the colliding path must never appear in signed history: {:?}",
        change.ops
    );
    assert!(change
        .ops
        .iter()
        .any(|op| matches!(op, Op::Put { path, .. } if path.as_str() == "a.txt")));
}

/// A database predating the sync-root lock's exclusion could hold an
/// indexed row for it (see the module-level rationale on
/// `path_must_never_enter_history`) — pins that the one-shot initial
/// import still skips it exactly as it does a versioned artefact.
#[test]
fn ensure_initial_import_skips_a_pre_existing_sync_root_lock_row() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let lock_path = yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME;
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live("a.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "g",
            &live(lock_path),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 1 });

    let heads = state.sqlite().dag_group_heads("g").unwrap();
    let change = state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
    assert!(
        change
            .ops
            .iter()
            .all(|op| !matches!(op, Op::Put { path, .. } if path.as_str() == lock_path)),
        "the sync-root lock path must never appear in signed history: {:?}",
        change.ops
    );
}

#[test]
fn empty_index_imports_nothing() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    assert_eq!(
        ensure_initial_import(&state, "g", &emitter(), None).unwrap(),
        ImportOutcome::NothingToImport
    );
    assert!(state.sqlite().dag_group_heads("g").unwrap().is_empty());
}

#[test]
fn large_index_splits_into_bounded_chain() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let count = IMPORT_BATCH_OP_LIMIT + 5;
    for i in 0..count {
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live(&format!("f{i:05}.txt")),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }
    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 2, ops: count });
    // A linear chain converges to a single head regardless of how many
    // changes it took to carry every op.
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);
}

/// Walks the linear parent chain from `head` back to the root, returning
/// every change on it (head-first). Asserts each non-root step has exactly
/// one parent, so a non-linear DAG fails loudly rather than silently
/// truncating the walk.
fn linear_chain_to_root(
    state: &ReplicaCoordinator,
    head: yadorilink_replica_domain::ids::ChangeHash,
) -> Vec<yadorilink_replica_domain::change::Change> {
    let mut chain = Vec::new();
    let mut cursor = Some(head);
    while let Some(hash) = cursor {
        let change = state.sqlite().dag_get_change(&hash).unwrap().unwrap();
        cursor = match change.parents.as_slice() {
            [] => None,
            [parent] => Some(*parent),
            more => {
                panic!("expected a linear chain, found a change with {} parents", more.len())
            }
        };
        chain.push(change);
    }
    chain
}

/// Byte cap: an initial import of FEWER than `IMPORT_BATCH_OP_LIMIT` files
/// whose ops encode to more than `change::MAX_CHANGE_OP_BYTES` (long paths)
/// must still split into MULTIPLE chained changes — proving the split is
/// driven by encoded size, not op count alone. Op count alone would leave a
/// single multi-hundred-KiB root change no wire message could deliver,
/// stranding the whole group's history permanently un-propagatable.
#[test]
fn import_splits_by_encoded_bytes_into_a_chain() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    // ~289 bytes/op * 1000 ops ≈ 282 KiB > 256 KiB, yet 1000 < 1024 ops,
    // so only the byte cap can split this — the op-count cap cannot.
    let n = 1000usize;
    assert!(n < IMPORT_BATCH_OP_LIMIT, "this test must stay under the op-count cap");
    for i in 0..n {
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live(&format!("d/{:0>250}", i)),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    let ImportOutcome::Imported { changes, ops } = outcome else {
        panic!("expected an import, got {outcome:?}");
    };
    assert_eq!(ops, n, "every file must be imported exactly once");
    assert!(
        changes >= 2,
        "a >256 KiB import of {n} (< op-count-cap) files must split by bytes \
         into >= 2 changes, got {changes}"
    );

    // The chunk chain converges on a single head and is linear to the root.
    let heads = state.sqlite().dag_group_heads("g").unwrap();
    assert_eq!(heads.len(), 1, "the chunk chain must converge on a single head");
    let chain = linear_chain_to_root(&state, heads[0]);
    assert_eq!(chain.len(), changes, "walked chain length must equal the emitted change count");

    let mut total_ops = 0usize;
    for change in &chain {
        assert!(
            change.ops.len() <= IMPORT_BATCH_OP_LIMIT,
            "every chunk must stay within the op-count bound"
        );
        let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
        assert!(
            bytes <= MAX_CHANGE_OP_BYTES,
            "every chunk must stay within the byte bound, got {bytes}"
        );
        total_ops += change.ops.len();
    }
    assert_eq!(total_ops, n, "the chain's ops must cover every file exactly once");
}

/// Teeth for the byte cap: a normal small import — well within both bounds
/// — must still be a SINGLE change, so the dual-bound loop never
/// over-splits an ordinary folder into a needless chain.
#[test]
fn small_import_is_a_single_change() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    for i in 0..8 {
        state
            .file_index_repository()
            .upsert_file(
                "g",
                &live(&format!("f{i}.txt")),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }
    let outcome = ensure_initial_import(&state, "g", &emitter(), None).unwrap();
    assert_eq!(outcome, ImportOutcome::Imported { changes: 1, ops: 8 });
    assert_eq!(state.sqlite().dag_group_heads("g").unwrap().len(), 1);
}
