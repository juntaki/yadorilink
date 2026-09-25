#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_retention_roots_schema(&conn).unwrap();
    crate::dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
    crate::dag_store::init_dag_schema(&conn).unwrap();
    conn
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn make_version(byte: u8) -> FileVersion {
    let blocks = vec![VersionBlock { hash: BlockHash(vec![byte; 32]), size: 4 }];
    let meta = FileMeta {
        mtime_unix_nanos: 1,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    FileVersion::new(blocks, 4, meta)
}

#[test]
fn register_and_release_round_trip() {
    let conn = open();
    let hash = ChangeHash([9u8; 32]);
    register_retention_root(
        &conn,
        "materialized_generation",
        "gen-1",
        "g",
        &hash,
        RetentionClass::FullPayload,
    )
    .unwrap();
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
    release_retention_root(
        &conn,
        "materialized_generation",
        "gen-1",
        "g",
        &hash,
        RetentionClass::FullPayload,
    )
    .unwrap();
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn registering_the_same_root_twice_is_idempotent() {
    let conn = open();
    let hash = ChangeHash([9u8; 32]);
    for _ in 0..3 {
        register_retention_root(&conn, "k", "id", "g", &hash, RetentionClass::CausalStub).unwrap();
    }
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn full_payload_root_resolves_to_its_referenced_block_hashes() {
    let conn = open();
    let version = make_version(0xAB);
    crate::dag_store::put_file_version(&conn, "g", &version).unwrap();
    let change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("d1".into()),
        FolderGroupId("g".into()),
        vec![Op::Put {
            path: SyncPath("a.txt".into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &signing_key(),
    );
    crate::dag_store::admit_change(&conn, &change).unwrap();
    register_retention_root(
        &conn,
        "materialized_generation",
        "gen-1",
        "g",
        &change.compute_hash(),
        RetentionClass::FullPayload,
    )
    .unwrap();

    let live = full_payload_retained_block_hashes(&conn, "g").unwrap();
    assert_eq!(live, HashSet::from([hex::encode([0xABu8; 32])]));
}

#[test]
fn a_group_with_no_registered_roots_yields_no_extra_live_blocks() {
    let conn = open();
    assert!(full_payload_retained_block_hashes(&conn, "g").unwrap().is_empty());
}

fn emitter(seed: u8) -> crate::dag_store::ChangeEmitter {
    crate::dag_store::ChangeEmitter::new(
        format!("device-{seed}"),
        SigningKey::from_bytes(&[seed; 32]),
    )
}

fn is_pruned(conn: &Connection, group_id: &str, hash: &ChangeHash) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = ?1 AND change_hash = ?2)",
        rusqlite::params![group_id, &hash.0[..]],
        |r| r.get(0),
    )
    .unwrap()
}

/// A checkpoint whose plan would prune `a` (a real prune plan: `b` is
/// the surviving frontier, `a` is strictly below it) must leave `a`
/// fully intact -- present in `changes`, absent from `pruned_changes`
/// -- proving `commit_prune` honors the root rather than deleting
/// `a`'s body regardless. See [`commit_prune`]'s own doc for why this
/// is a per-hash skip, not a whole-checkpoint refusal: `b` (unrooted,
/// and not even in this checkpoint's `pruned` list to begin with) is
/// untouched either way, confirming the checkpoint still commits
/// normally around the held root.
#[test]
fn a_full_payload_rooted_change_survives_a_checkpoint_that_would_prune_it() {
    let conn = open();
    let em = emitter(1);
    let a = crate::dag_store::emit_local_change(
        &conn,
        "g",
        vec![Op::Put {
            path: SyncPath("a.txt".into()),
            version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &em,
    )
    .unwrap();
    let a_hash = a.compute_hash();
    let b = crate::dag_store::emit_local_change(
        &conn,
        "g",
        vec![Op::Put {
            path: SyncPath("b.txt".into()),
            version: yadorilink_replica_domain::ids::VersionHash([2u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &em,
    )
    .unwrap();
    let b_hash = b.compute_hash();

    register_retention_root(
        &conn,
        "captured_authoring",
        "retained-1",
        "g",
        &a_hash,
        RetentionClass::FullPayload,
    )
    .unwrap();

    // The real plan a compactor would compute: `b` is the maximal
    // (surviving) frontier, `a` sits strictly below it and would
    // ordinarily be pruned.
    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![b_hash],
        [0u8; 32],
    );
    crate::dag_store::commit_prune(&conn, &checkpoint, &[a_hash]).unwrap();

    assert!(crate::dag_store::has_change(&conn, &a_hash).unwrap(), "rooted change must survive");
    assert!(!is_pruned(&conn, "g", &a_hash), "rooted change must not gain a pruned-stub tombstone");
    assert!(
        crate::dag_store::has_change(&conn, &b_hash).unwrap(),
        "unrelated change is unaffected"
    );
}

/// The mirror case: once the same root is released, a later checkpoint
/// naming the same hash actually prunes it -- proving the skip in
/// `commit_prune` is scoped to a live root, not a permanent exemption.
#[test]
fn a_released_root_no_longer_blocks_pruning_the_same_change() {
    let conn = open();
    let em = emitter(2);
    let a = crate::dag_store::emit_local_change(
        &conn,
        "g",
        vec![Op::Put {
            path: SyncPath("a.txt".into()),
            version: yadorilink_replica_domain::ids::VersionHash([3u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &em,
    )
    .unwrap();
    let a_hash = a.compute_hash();
    let b = crate::dag_store::emit_local_change(
        &conn,
        "g",
        vec![Op::Put {
            path: SyncPath("b.txt".into()),
            version: yadorilink_replica_domain::ids::VersionHash([4u8; 32]),
            origin: PutOrigin::Direct,
        }],
        &em,
    )
    .unwrap();
    let b_hash = b.compute_hash();

    register_retention_root(
        &conn,
        "captured_authoring",
        "retained-2",
        "g",
        &a_hash,
        RetentionClass::FullPayload,
    )
    .unwrap();
    let checkpoint_1 = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![b_hash],
        [0u8; 32],
    );
    crate::dag_store::commit_prune(&conn, &checkpoint_1, &[a_hash]).unwrap();
    assert!(crate::dag_store::has_change(&conn, &a_hash).unwrap(), "still held by the live root");

    release_retention_root(
        &conn,
        "captured_authoring",
        "retained-2",
        "g",
        &a_hash,
        RetentionClass::FullPayload,
    )
    .unwrap();
    let checkpoint_2 = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId("g".into()),
        vec![b_hash],
        [1u8; 32],
    );
    crate::dag_store::commit_prune(&conn, &checkpoint_2, &[a_hash]).unwrap();

    assert!(!crate::dag_store::has_change(&conn, &a_hash).unwrap(), "must now prune");
    assert!(is_pruned(&conn, "g", &a_hash), "must now carry a pruned-stub tombstone");
}

/// [`full_payload_retained_block_hashes_all_groups`] unions roots across
/// every group in one pass -- the shape `yadorilink-daemon`'s
/// daemon-wide GC sweep needs (one block store shared by every group).
/// Two distinct groups each with their own rooted change and distinct
/// block content prove neither the union nor the per-group resolution
/// (`group_id` threaded correctly into `get_file_version`) is lost.
#[test]
fn all_groups_block_hashes_unions_roots_across_every_group() {
    let conn = open();
    crate::dag_store::init_dag_schema(&conn).unwrap(); // second group's schema is the same tables; idempotent
    let version_g1 = make_version(0x11);
    let version_g2 = make_version(0x22);
    crate::dag_store::put_file_version(&conn, "g1", &version_g1).unwrap();
    crate::dag_store::put_file_version(&conn, "g2", &version_g2).unwrap();

    let change_g1 = create_signed_for_tests(
        vec![],
        0,
        DeviceId("d1".into()),
        FolderGroupId("g1".into()),
        vec![Op::Put {
            path: SyncPath("a.txt".into()),
            version: version_g1.version_hash,
            origin: PutOrigin::Direct,
        }],
        &signing_key(),
    );
    let change_g2 = create_signed_for_tests(
        vec![],
        0,
        DeviceId("d2".into()),
        FolderGroupId("g2".into()),
        vec![Op::Put {
            path: SyncPath("b.txt".into()),
            version: version_g2.version_hash,
            origin: PutOrigin::Direct,
        }],
        &signing_key(),
    );
    crate::dag_store::admit_change(&conn, &change_g1).unwrap();
    crate::dag_store::admit_change(&conn, &change_g2).unwrap();
    register_retention_root(
        &conn,
        "captured_authoring",
        "retained-g1",
        "g1",
        &change_g1.compute_hash(),
        RetentionClass::FullPayload,
    )
    .unwrap();
    register_retention_root(
        &conn,
        "captured_authoring",
        "retained-g2",
        "g2",
        &change_g2.compute_hash(),
        RetentionClass::FullPayload,
    )
    .unwrap();

    let live = full_payload_retained_block_hashes_all_groups(&conn).unwrap();
    assert_eq!(
        live,
        HashSet::from([hex::encode([0x11u8; 32]), hex::encode([0x22u8; 32])]),
        "must include both groups' rooted blocks in one union"
    );
}
