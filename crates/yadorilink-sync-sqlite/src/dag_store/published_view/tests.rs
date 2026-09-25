#![cfg(test)]

use super::*;
use crate::dag_store::{admit_change, frontier_index, init_dag_schema, retained_history_integrity};
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    c
}

/// `files` is NOT part of `init_dag_schema` (it belongs to
/// `yadorilink_sqlite_runtime::init_schema`, a lower crate this one
/// depends on) -- this mirrors
/// `materialization_state.rs::held_state_tests::open_full_test_db`'s
/// exact composition order (DAG tables first, since `init_schema`
/// assumes `changes` already exists).
fn full_schema_conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

#[allow(clippy::too_many_arguments)]
fn insert_file_row(
    c: &Connection,
    group_id: &str,
    path: &str,
    version_seq: u64,
    state: &str,
    authoring_change_hash: Option<&ChangeHash>,
    deleted: bool,
    size: u64,
) {
    c.execute(
        "INSERT INTO files \
         (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
          version_seq, state, authoring_change_hash) \
         VALUES (?1, ?2, ?3, 0, '[]', ?4, ?5, ?6, ?7)",
        rusqlite::params![
            group_id,
            path,
            size as i64,
            deleted as i64,
            version_seq as i64,
            state,
            authoring_change_hash.map(|h| h.0.to_vec()),
        ],
    )
    .unwrap();
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn root_change(group: &str) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId(group.into()),
        vec![],
        &key(),
    )
}

fn child_change(group: &str, parent: &Change) -> Change {
    create_signed_for_tests(
        vec![parent.compute_hash()],
        parent.lamport,
        DeviceId("device-A".into()),
        FolderGroupId(group.into()),
        vec![],
        &key(),
    )
}

/// A root Change authored by a device OTHER than "device-A" -- for
/// tests that must prove a batching/filtering function does not
/// silently fold another device's admitted-but-unpublished Change
/// into "device-A"'s own set.
fn root_change_by(group: &str, device_id: &str) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId(device_id.into()),
        FolderGroupId(group.into()),
        vec![],
        &key(),
    )
}

fn dummy_checkpoint_hash(tag: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = tag;
    h
}

/// Fixed stand-in author signing key -- these tests exercise
/// evidence-attachment/idempotency mechanics, not key/fingerprint
/// verification (that lives in `authorization_checkpoint`'s own tests),
/// so every call site here reuses the same dummy key.
const AUTHOR_KEY: [u8; 32] = [0xAA; 32];

#[test]
fn an_admitted_change_with_no_evidence_is_not_published() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();

    assert!(!is_published(&c, &hash).unwrap());
    assert_eq!(published_group_heads(&c, "g").unwrap(), Vec::new());
    assert_eq!(published_encoded_change(&c, &hash).unwrap(), None);
}

#[test]
fn the_raw_functions_are_unaware_of_publication_status() {
    // Pins the contract split: the raw functions are completely
    // unaware of publication status, which is why every externally
    // observable read goes through the `published_*` functions
    // instead. If this test ever starts failing because
    // group_heads/get_encoded themselves became publication-aware,
    // revisit which callers rely on the raw view -- don't just
    // delete it.
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();

    assert_eq!(frontier_index::group_heads(&c, "g").unwrap(), vec![hash]);
    assert!(retained_history_integrity::get_encoded(&c, &hash).unwrap().is_some());
    // ...while the published_* view already correctly excludes it:
    assert!(!is_published(&c, &hash).unwrap());
}

#[test]
fn attaching_evidence_makes_a_change_published() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();
    let checkpoint_hash = dummy_checkpoint_hash(1);

    attach_authorization_evidence(
        &c,
        &checkpoint_hash,
        "g",
        "device-A",
        1,
        b"checkpoint-bytes",
        b"signature-bytes",
        &AUTHOR_KEY,
        &[(hash, b"merkle-proof-bytes".to_vec())],
    )
    .unwrap();

    assert!(is_published(&c, &hash).unwrap());
    assert_eq!(published_group_heads(&c, "g").unwrap(), vec![hash]);
    assert_eq!(
        published_encoded_change(&c, &hash).unwrap(),
        retained_history_integrity::get_encoded(&c, &hash).unwrap()
    );
}

#[test]
fn a_published_change_with_only_an_unpublished_child_still_counts_as_a_published_head() {
    // The property a naive "filter the group_heads TABLE by a
    // pending flag" implementation would get wrong: an unpublished
    // child must not make its published parent disappear from
    // published_group_heads, since a receiver who can't see the
    // child yet must still see the parent as the current frontier.
    let c = conn();
    let parent = root_change("g");
    let child = child_change("g", &parent);
    admit_change(&c, &parent).unwrap();
    admit_change(&c, &child).unwrap();
    let parent_hash = parent.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(2),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(parent_hash, b"proof".to_vec())],
    )
    .unwrap();
    // child intentionally left unpublished.

    assert_eq!(published_group_heads(&c, "g").unwrap(), vec![parent_hash]);
}

#[test]
fn publishing_the_child_advances_the_published_head_past_its_published_parent() {
    let c = conn();
    let parent = root_change("g");
    let child = child_change("g", &parent);
    admit_change(&c, &parent).unwrap();
    admit_change(&c, &child).unwrap();
    let parent_hash = parent.compute_hash();
    let child_hash = child.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(3),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(parent_hash, b"proof-parent".to_vec()), (child_hash, b"proof-child".to_vec())],
    )
    .unwrap();

    assert_eq!(published_group_heads(&c, "g").unwrap(), vec![child_hash]);
}

#[test]
fn attaching_evidence_for_the_same_checkpoint_twice_does_not_duplicate_or_error() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();
    let checkpoint_hash = dummy_checkpoint_hash(4);

    for _ in 0..2 {
        attach_authorization_evidence(
            &c,
            &checkpoint_hash,
            "g",
            "device-A",
            1,
            b"cp",
            b"sig",
            &AUTHOR_KEY,
            &[(hash, b"proof".to_vec())],
        )
        .unwrap();
    }

    assert!(is_published(&c, &hash).unwrap());
    let count: i64 =
        c.query_row("SELECT COUNT(*) FROM authorization_checkpoints", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1, "re-attaching the same checkpoint must not duplicate it");
}

#[test]
fn a_different_payload_under_an_already_used_checkpoint_hash_is_corrupt_state() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();
    let checkpoint_hash = dummy_checkpoint_hash(6);

    attach_authorization_evidence(
        &c,
        &checkpoint_hash,
        "g",
        "device-A",
        1,
        b"cp-original",
        b"sig",
        &AUTHOR_KEY,
        &[(hash, b"proof".to_vec())],
    )
    .unwrap();

    let result = attach_authorization_evidence(
        &c,
        &checkpoint_hash,
        "g",
        "device-A",
        1,
        b"cp-DIFFERENT", // same hash, different content -- must not be picked silently
        b"sig",
        &AUTHOR_KEY,
        &[(hash, b"proof".to_vec())],
    );
    assert!(
        matches!(result, Err(SyncSqliteError::CorruptState(_))),
        "expected CorruptState, got {result:?}"
    );
}

#[test]
fn re_attaching_a_change_under_a_different_checkpoint_is_corrupt_state() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(7),
        "g",
        "device-A",
        1,
        b"cp-a",
        b"sig-a",
        &AUTHOR_KEY,
        &[(hash, b"proof-a".to_vec())],
    )
    .unwrap();

    // A different checkpoint later claims to cover the SAME change --
    // an already-published Change must never silently switch which
    // checkpoint it's attributed to.
    let result = attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(8),
        "g",
        "device-A",
        2,
        b"cp-b",
        b"sig-b",
        &AUTHOR_KEY,
        &[(hash, b"proof-b".to_vec())],
    );
    assert!(
        matches!(result, Err(SyncSqliteError::CorruptState(_))),
        "expected CorruptState, got {result:?}"
    );
}

#[test]
fn a_change_authorization_row_cannot_reference_a_nonexistent_checkpoint() {
    // The trigger backstop: bypass attach_authorization_evidence
    // entirely and try to insert a dangling change_authorization row
    // directly, the way a bug in some OTHER writer might. No pragma
    // setup needed -- the trigger fires unconditionally, on any
    // connection, which is the whole point of using one instead of
    // `REFERENCES` + `PRAGMA foreign_keys` (a per-connection setting
    // that would not backstop a different connection anyway).
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();

    let result = c.execute(
        "INSERT INTO change_authorization (change_hash, checkpoint_hash, merkle_proof) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![&hash.0[..], &dummy_checkpoint_hash(9)[..], b"proof".as_slice()],
    );
    assert!(result.is_err(), "expected the trigger to abort this insert, got {result:?}");
}

#[test]
fn a_referenced_checkpoint_cannot_be_deleted() {
    let c = conn();
    let change = root_change("g");
    admit_change(&c, &change).unwrap();
    let hash = change.compute_hash();
    let checkpoint_hash = dummy_checkpoint_hash(15);

    attach_authorization_evidence(
        &c,
        &checkpoint_hash,
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(hash, b"proof".to_vec())],
    )
    .unwrap();

    let result = c.execute(
        "DELETE FROM authorization_checkpoints WHERE checkpoint_hash = ?1",
        [&checkpoint_hash[..]],
    );
    assert!(result.is_err(), "expected the trigger to abort this delete, got {result:?}");
    assert!(is_published(&c, &hash).unwrap(), "evidence must still be intact");
}

#[test]
fn published_status_survives_a_reopened_connection() {
    // Crash/restart requirement: publication status is an ordinary
    // committed row, not anything held only in memory, so a fresh
    // connection against the same file must see it identically.
    let dir = std::env::temp_dir()
        .join(format!("yadorilink-published-view-restart-test-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    let hash;
    {
        let c = Connection::open(&dir).unwrap();
        init_dag_schema(&c).unwrap();
        let change = root_change("g");
        admit_change(&c, &change).unwrap();
        hash = change.compute_hash();
        attach_authorization_evidence(
            &c,
            &dummy_checkpoint_hash(5),
            "g",
            "device-A",
            1,
            b"cp",
            b"sig",
            &AUTHOR_KEY,
            &[(hash, b"proof".to_vec())],
        )
        .unwrap();
        assert!(is_published(&c, &hash).unwrap());
    } // connection dropped -- simulates process exit

    let reopened = Connection::open(&dir).unwrap();
    assert!(
        is_published(&reopened, &hash).unwrap(),
        "publication status must survive a fresh connection against the same file"
    );
    assert_eq!(published_group_heads(&reopened, "g").unwrap(), vec![hash]);
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn published_file_at_path_returns_the_older_published_version_over_a_pending_current_one() {
    // The key scenario: v1 published, v2 pending
    // and files.state = 'current'. The published view must answer
    // v1, not None (that would under-serve a legitimate reader) and
    // not v2 (that would leak Pending content).
    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();

    insert_file_row(&c, "g", "doc.txt", 1, "superseded", Some(&v1_hash), false, 111);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), false, 222);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(10),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof".to_vec())],
    )
    .unwrap();
    // v2 intentionally left unpublished.

    let result = published_file_at_path(&c, "g", "doc.txt").unwrap();
    assert_eq!(
        result.map(|r| r.size),
        Some(111),
        "must answer v1 (the published version), not None and not v2's size"
    );
}

#[test]
fn published_file_at_path_returns_none_when_no_version_at_the_path_is_published() {
    let c = full_schema_conn();
    let author = root_change("g");
    admit_change(&c, &author).unwrap();
    let hash = author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "current", Some(&hash), false, 1);
    // no evidence attached at all

    assert_eq!(published_file_at_path(&c, "g", "doc.txt").unwrap(), None);
}

#[test]
fn published_file_at_path_ignores_a_row_with_no_authoring_change_hash() {
    // A NULL authoring_change_hash never joins to change_authorization
    // -- fail closed on missing provenance, same principle as every
    // other check in this design.
    let c = full_schema_conn();
    insert_file_row(&c, "g", "doc.txt", 1, "current", None, false, 1);

    assert_eq!(published_file_at_path(&c, "g", "doc.txt").unwrap(), None);
}

#[test]
fn published_file_at_path_reflects_the_latest_published_version_once_both_are_published() {
    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();

    insert_file_row(&c, "g", "doc.txt", 1, "superseded", Some(&v1_hash), false, 111);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), false, 222);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(11),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof-v1".to_vec()), (v2_hash, b"proof-v2".to_vec())],
    )
    .unwrap();

    // Both published now -- the view must advance to v2 (highest
    // version_seq among published rows), matching files.state='current'
    // in this fully-caught-up case.
    let result = published_file_at_path(&c, "g", "doc.txt").unwrap();
    assert_eq!(result.map(|r| r.size), Some(222));
}

#[test]
fn published_snapshot_files_excludes_a_row_whose_authoring_change_is_pending() {
    let c = full_schema_conn();
    let author = root_change("g");
    admit_change(&c, &author).unwrap();
    let hash = author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "current", Some(&hash), false, 1);
    // no evidence attached

    assert_eq!(published_snapshot_files(&c, "g").unwrap(), Vec::new());
}

#[test]
fn published_snapshot_files_includes_every_published_retained_version_not_just_current() {
    // read_snapshot_files enumerates the FULL retained history, not
    // just state='current' -- the published equivalent must do the
    // same, restricted to published rows.
    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "superseded", Some(&v1_hash), false, 111);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), false, 222);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(12),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof1".to_vec()), (v2_hash, b"proof2".to_vec())],
    )
    .unwrap();

    let rows = published_snapshot_files(&c, "g").unwrap();
    let mut sizes: Vec<u64> = rows.iter().map(|r| r.record.size).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![111, 222], "both published retained versions must appear");
}

#[test]
fn published_snapshot_files_promotes_the_latest_published_version_to_current() {
    // The key scenario: v1 published (raw state
    // 'superseded', because v2 came along and became raw-current),
    // v2 pending (raw state 'current'). The published PROJECTION must
    // show v1 as Current -- a straight filter that just drops v2 and
    // keeps v1's raw 'superseded' label is wrong: no observer in the
    // published world has ever seen a newer version, so v1 IS their
    // current state, not a superseded one.
    use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotVersionState;

    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "superseded", Some(&v1_hash), false, 111);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), false, 222);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(16),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof".to_vec())],
    )
    .unwrap();
    // v2 intentionally left unpublished.

    let rows = published_snapshot_files(&c, "g").unwrap();
    assert_eq!(rows.len(), 1, "only v1 is published, so only one row should appear");
    assert_eq!(
        rows[0].state,
        SnapshotVersionState::Current,
        "the only published version at this path must read as Current in the projection, \
         not as its raw 'superseded' label"
    );
    assert!(!rows[0].record.deleted);
}

#[test]
fn published_snapshot_files_promotes_the_latest_published_version_even_when_a_pending_delete_follows(
) {
    // Second scenario: v1 published and live, v2 a
    // pending DELETE. The published projection must show v1 as
    // Current and non-deleted -- a pending delete must not leak into
    // the published world's view of whether the file still exists.
    use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotVersionState;

    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "superseded", Some(&v1_hash), false, 111);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), true, 0); // pending delete

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(17),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof".to_vec())],
    )
    .unwrap();
    // the delete (v2) intentionally left unpublished.

    let rows = published_snapshot_files(&c, "g").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, SnapshotVersionState::Current);
    assert!(
        !rows[0].record.deleted,
        "the pending delete must not be visible in the published projection"
    );
}

#[test]
fn published_snapshot_files_keeps_trashed_below_the_promoted_current_version() {
    // A genuinely trashed OLDER version must not be relabeled
    // Current just because it's published and some newer, also-
    // published version exists -- only the greatest published
    // version_seq at a path is ever promoted to Current.
    use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotVersionState;

    let c = full_schema_conn();
    let v1_author = root_change("g");
    let v2_author = child_change("g", &v1_author);
    admit_change(&c, &v1_author).unwrap();
    admit_change(&c, &v2_author).unwrap();
    let v1_hash = v1_author.compute_hash();
    let v2_hash = v2_author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "trashed", Some(&v1_hash), true, 0);
    insert_file_row(&c, "g", "doc.txt", 2, "current", Some(&v2_hash), false, 222);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(18),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(v1_hash, b"proof1".to_vec()), (v2_hash, b"proof2".to_vec())],
    )
    .unwrap();

    let rows = published_snapshot_files(&c, "g").unwrap();
    assert_eq!(rows.len(), 2);
    let by_size: std::collections::HashMap<u64, SnapshotVersionState> =
        rows.iter().map(|r| (r.record.size, r.state)).collect();
    assert_eq!(by_size[&222], SnapshotVersionState::Current);
    assert_eq!(
        by_size[&0],
        SnapshotVersionState::Trashed,
        "an older trashed version stays trashed"
    );
}

#[test]
fn published_snapshot_files_does_not_promote_the_sole_published_version_when_it_is_itself_trashed()
{
    // The case the previous test's setup could not exercise: when
    // the ONLY published version at a path is itself raw-Trashed
    // (not merely superseded by something else), the projection
    // must leave it Trashed -- not promote it to Current just
    // because it happens to be the greatest published version_seq.
    // The prior implementation unconditionally set the last row in
    // each path's group to Current, which got exactly this case
    // wrong (it only ever exercised "older Trashed, newer Current").
    use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotVersionState;

    let c = full_schema_conn();
    let author = root_change("g");
    admit_change(&c, &author).unwrap();
    let hash = author.compute_hash();
    insert_file_row(&c, "g", "doc.txt", 1, "trashed", Some(&hash), true, 0);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(19),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(hash, b"proof".to_vec())],
    )
    .unwrap();

    let rows = published_snapshot_files(&c, "g").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].state,
        SnapshotVersionState::Trashed,
        "the sole published version must stay Trashed, not be promoted to Current"
    );
}

fn version_with_block(block_hash: &[u8]) -> yadorilink_replica_domain::file::FileVersion {
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
    use yadorilink_replica_domain::ids::BlockHash;
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.to_vec()), size: 7 }],
        7,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

#[test]
fn published_group_file_version_references_block_requires_a_published_authoring_change() {
    use yadorilink_replica_domain::change::{Op, PutOrigin};
    use yadorilink_replica_domain::ids::SyncPath;

    let c = conn();
    let block_hash = vec![0x99u8; 32];
    let version = version_with_block(&block_hash);
    crate::dag_store::serving_authorization_index::put_file_version(&c, "g", &version).unwrap();

    let root = root_change("g");
    admit_change(&c, &root).unwrap();
    let putter = create_signed_for_tests(
        vec![root.compute_hash()],
        root.lamport,
        DeviceId("device-A".into()),
        FolderGroupId("g".into()),
        vec![Op::Put {
            path: SyncPath("doc.txt".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key(),
    );
    admit_change(&c, &putter).unwrap();
    let putter_hash = putter.compute_hash();

    // Admitted, but not yet published: must not be servable.
    assert!(!published_group_file_version_references_block(&c, "g", &block_hash).unwrap());

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(13),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(putter_hash, b"proof".to_vec())],
    )
    .unwrap();

    assert!(published_group_file_version_references_block(&c, "g", &block_hash).unwrap());
}

/// The full compaction cycle for block serving: a
/// version's authorizing link survives its authoring Change being
/// compacted away, but ONLY via the witness table joined against the
/// SAME already-verified `change_authorization` evidence a live
/// Change's version would use -- not by merely existing in the link
/// table. This is what replaced the old, evidence-free `compacted_
/// file_version_authorization`.
#[test]
fn published_group_file_version_references_block_survives_compaction_via_a_verified_witness_link() {
    use yadorilink_replica_domain::change::{Op, PutOrigin};
    use yadorilink_replica_domain::ids::SyncPath;

    let c = conn();
    let block_hash = vec![0x77u8; 32];
    let version = version_with_block(&block_hash);
    crate::dag_store::serving_authorization_index::put_file_version(&c, "g", &version).unwrap();

    let root = root_change("g");
    admit_change(&c, &root).unwrap();
    let putter = create_signed_for_tests(
        vec![root.compute_hash()],
        root.lamport,
        DeviceId("device-A".into()),
        FolderGroupId("g".into()),
        vec![Op::Put {
            path: SyncPath("doc.txt".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key(),
    );
    admit_change(&c, &putter).unwrap();
    let putter_hash = putter.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(21),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(putter_hash, b"proof".to_vec())],
    )
    .unwrap();
    assert!(
        published_group_file_version_references_block(&c, "g", &block_hash).unwrap(),
        "sanity: servable via the live change_file_versions path before compaction"
    );

    // Simulate what `commit_prune` does to a compacted Change: its
    // `change_file_versions`/`changes` rows are deleted, but its
    // `change_authorization`/`authorization_checkpoints` evidence is
    // deliberately left untouched (`dag_store::mod`'s own schema doc
    // comment on `pruned_published_change_versions`).
    c.execute(
        "DELETE FROM change_file_versions WHERE change_hash = ?1",
        rusqlite::params![&putter_hash.0[..]],
    )
    .unwrap();
    c.execute("DELETE FROM changes WHERE change_hash = ?1", rusqlite::params![&putter_hash.0[..]])
        .unwrap();
    assert!(
        !published_group_file_version_references_block(&c, "g", &block_hash).unwrap(),
        "the version's authorizing link is genuinely lost once its authoring change is \
         pruned and no witness has been recorded yet"
    );

    // A real compaction/rebootstrap-install records exactly this link
    // before deleting the Change body.
    crate::dag_store::serving_authorization_index::record_pruned_published_change_version(
        &c,
        "g",
        &version.version_hash,
        &putter_hash,
    )
    .unwrap();
    assert!(
        published_group_file_version_references_block(&c, "g", &block_hash).unwrap(),
        "the witness link must restore block-serving authorization by reaching the SAME \
         surviving change_authorization evidence, not by trusting its own existence"
    );
}

#[test]
fn published_heads_among_filters_out_unpublished_hashes() {
    let c = conn();
    let published = root_change("g");
    let unpublished = root_change("g2");
    admit_change(&c, &published).unwrap();
    admit_change(&c, &unpublished).unwrap();
    let published_hash = published.compute_hash();
    let unpublished_hash = unpublished.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(14),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(published_hash, b"proof".to_vec())],
    )
    .unwrap();

    let result = published_heads_among(&c, &[published_hash, unpublished_hash]).unwrap();
    assert_eq!(result, vec![published_hash]);
}

#[test]
fn device_frontier_can_be_set_from_an_unpublished_hash() {
    // Pins set_device_frontier's publication-unaware contract: it
    // will record a Pending Change's hash as this device's
    // acknowledged frontier, so a compaction/prune check must not
    // treat the raw frontier as ack/dominance/retention justification
    // on its own. A caller that needs the published subset filters
    // through published_heads_among before calling
    // set_device_frontier; the raw contract itself stays unchanged.
    let c = conn();
    let unpublished = root_change("g");
    admit_change(&c, &unpublished).unwrap();
    let unpublished_hash = unpublished.compute_hash();
    assert!(!is_published(&c, &unpublished_hash).unwrap());

    frontier_index::set_device_frontier(&c, "g", "device-B", &[unpublished_hash]).unwrap();

    assert_eq!(
        frontier_index::get_device_frontier(&c, "g", "device-B").unwrap(),
        vec![unpublished_hash],
        "documents the current gap -- an unpublished hash IS accepted as a frontier today"
    );
}

#[test]
fn pending_local_changes_for_group_excludes_published_and_scopes_by_group() {
    let c = conn();
    let pending_a = root_change("g");
    let pending_b = child_change("g", &pending_a);
    let published = root_change("g2"); // different group entirely
    admit_change(&c, &pending_a).unwrap();
    admit_change(&c, &pending_b).unwrap();
    admit_change(&c, &published).unwrap();
    let published_hash = published.compute_hash();

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(20),
        "g2",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(published_hash, b"proof".to_vec())],
    )
    .unwrap();

    let mut pending_g = pending_local_changes_for_group(&c, "g", "device-A").unwrap();
    pending_g.sort();
    let mut expected = vec![pending_a.compute_hash(), pending_b.compute_hash()];
    expected.sort();
    assert_eq!(pending_g, expected);

    assert_eq!(
        pending_local_changes_for_group(&c, "g2", "device-A").unwrap(),
        Vec::new(),
        "the published change in g2 must not appear as pending"
    );
}

#[test]
fn pending_local_changes_for_group_shrinks_as_evidence_is_attached() {
    let c = conn();
    let a = root_change("g");
    let b = child_change("g", &a);
    admit_change(&c, &a).unwrap();
    admit_change(&c, &b).unwrap();
    assert_eq!(pending_local_changes_for_group(&c, "g", "device-A").unwrap().len(), 2);

    attach_authorization_evidence(
        &c,
        &dummy_checkpoint_hash(21),
        "g",
        "device-A",
        1,
        b"cp",
        b"sig",
        &AUTHOR_KEY,
        &[(a.compute_hash(), b"proof".to_vec())],
    )
    .unwrap();

    assert_eq!(
        pending_local_changes_for_group(&c, "g", "device-A").unwrap(),
        vec![b.compute_hash()]
    );
}

#[test]
fn pending_local_changes_for_group_excludes_another_devices_admitted_change() {
    // The exact bug this function was renamed and re-scoped to fix:
    // a Change admitted from a DIFFERENT device in the SAME group,
    // still unpublished, must never appear in "device-A"'s own
    // pending batch -- device-A has no standing to request a
    // checkpoint covering content it did not author.
    let c = conn();
    let own = root_change("g");
    let others = root_change_by("g", "device-B");
    admit_change(&c, &own).unwrap();
    admit_change(&c, &others).unwrap();

    assert_eq!(
        pending_local_changes_for_group(&c, "g", "device-A").unwrap(),
        vec![own.compute_hash()],
        "device-B's admitted-but-unpublished Change must not appear in device-A's batch"
    );
    assert_eq!(
        pending_local_changes_for_group(&c, "g", "device-B").unwrap(),
        vec![others.compute_hash()]
    );
}
