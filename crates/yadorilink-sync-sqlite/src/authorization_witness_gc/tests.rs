//! What collecting authorization witnesses removes, and what it must keep.
//!
//! Each "keeps" test sets up one retained thing that is the only reason a
//! witness is still needed, so a collection that ignored that reason would
//! delete the witness and fail the test. A file row's author is the one
//! reason a seal never leaves alone -- the base's carried authors or the
//! version's link name it too -- so the seal-path row tests fail only for a
//! collection that ignores all three, and
//! `a_file_row_alone_keeps_its_authors_evidence` pins the row by itself.

use ed25519_dalek::SigningKey;
use rusqlite::{Connection, OptionalExtension};

use super::*;
use crate::rebootstrap_store::{install_base_for_tests, seal_group, VerifiedSeal};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof, merkle_root,
    sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, VersionBlock};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::ids::{BlockHash, ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::recursive_operation::{
    EffectSetHash, RecursiveOperation, RecursiveOperationId, RecursiveOperationKind,
};
use yadorilink_replica_domain::test_authoring::{
    create_recursive_part_for_tests, create_signed_for_tests, reset_author_sequences,
};
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};

const GROUP: &str = "group-witness-gc";

fn open() -> Connection {
    reset_author_sequences();
    let conn = Connection::open_in_memory().unwrap();
    crate::dag_store::init_dag_schema(&conn).unwrap();
    yadorilink_sqlite_runtime::init_schema(&conn).unwrap();
    crate::rebootstrap_store::init_rebootstrap_schema(&conn).unwrap();
    conn
}

/// One block per version, so a version's content can be asked for by
/// block the way a peer asks for it.
fn block(seed: u8) -> BlockHash {
    BlockHash(vec![seed; 32])
}

fn version(seed: u8) -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: block(seed), size: 1 }],
        1,
        FileMeta {
            mtime_unix_nanos: 1_000 + seed as i64,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn store_versions(conn: &Connection) {
    for seed in 1..=40 {
        crate::dag_store::put_file_version(conn, GROUP, &version(seed)).unwrap();
    }
}

fn key(device: &str) -> SigningKey {
    SigningKey::from_bytes(&[device.as_bytes()[device.len() - 1]; 32])
}

fn put(path: &str, seed: u8) -> Op {
    Op::Put {
        path: SyncPath(path.to_string()),
        version: version(seed).version_hash,
        origin: PutOrigin::Direct,
    }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.to_string()) }
}

/// Admits a change on the group's original history, parented on exactly
/// `parents`.
fn admit(conn: &Connection, device: &str, parents: &[&Change], ops: Vec<Op>) -> Change {
    let change = create_signed_for_tests(
        parents.iter().map(|parent| parent.compute_hash()).collect(),
        parents.iter().map(|parent| parent.lamport).max().unwrap_or(0),
        DeviceId(device.to_string()),
        FolderGroupId(GROUP.to_string()),
        ops,
        &key(device),
    );
    let outcome = crate::dag_store::admit_change(conn, &change).unwrap().outcome;
    assert!(matches!(outcome, crate::dag_store::AdmitOutcome::Applied), "got {outcome:?}");
    change
}

/// Authors a change the way this device's own emission does, on the
/// group's current frontier and epoch.
fn emit(conn: &Connection, device: &str, ops: Vec<Op>) -> Change {
    crate::dag_store::emit_local_change(conn, GROUP, ops, &ChangeEmitter::new(device, key(device)))
        .unwrap()
}

/// Publishes `hashes` under one genuine authorization checkpoint numbered
/// `seq`, each with its own inclusion proof, the way a checkpoint flush
/// attaches them.
fn publish_hashes(conn: &Connection, group: &str, seq: u64, hashes: &[ChangeHash]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = hashes.iter().map(|hash| hash.0).collect();
    let checkpoint = AuthorizationCheckpoint {
        group_id: group.to_string(),
        device_id: "device-a".to_string(),
        signing_key_fingerprint: [1; 32],
        merkle_root: merkle_root(&leaves),
        leaf_count: leaves.len() as u64,
        checkpoint_seq: seq,
        signer_key_id: [2; 32],
        policy_epoch: 1,
        policy_seq: 1,
        policy_head: [3; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, &SigningKey::from_bytes(&[42; 32]));
    let hash = checkpoint_hash(&encoded, &signature);
    let entries: Vec<(ChangeHash, Vec<u8>)> = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            (ChangeHash(*leaf), encode_merkle_proof(&build_merkle_proof(&leaves, index)))
        })
        .collect();
    crate::dag_store::published_view::attach_authorization_evidence(
        conn, &hash, group, "device-a", seq, &encoded, &signature, &[7; 32], &entries,
    )
    .unwrap();
    hash
}

/// Publishes every retained change of the group not published yet.
fn publish(conn: &Connection, seq: u64) -> [u8; 32] {
    let unpublished: Vec<ChangeHash> = {
        let mut stmt = conn
            .prepare(
                "SELECT c.change_hash FROM changes c WHERE c.group_id = ?1 AND NOT EXISTS \
                 (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash) \
                 ORDER BY c.change_hash",
            )
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0)).unwrap();
        rows.map(|row| ChangeHash(row.unwrap().try_into().unwrap())).collect()
    };
    publish_hashes(conn, GROUP, seq, &unpublished)
}

fn file_row(
    tx: &rusqlite::Transaction<'_>,
    path: &str,
    version: &FileVersion,
    author: &ChangeHash,
    deleted: bool,
) {
    let mut offset = 0;
    let blocks = version
        .blocks
        .iter()
        .map(|block| {
            let info = BlockInfo { hash: block.hash.0.clone(), offset, size: block.size };
            offset += block.size as u64;
            info
        })
        .collect();
    crate::file_index::upsert_file_in_tx(
        tx,
        GROUP,
        &FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks,
            deleted,
        },
        "device-a",
        Some(author),
    )
    .unwrap();
}

/// Brings the file rows up to what the live heads resolve to, conflict
/// copies included, and settles every projection obligation.
fn project(conn: &Connection) {
    let paths: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT DISTINCT path FROM path_live_heads WHERE group_id = ?1").unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    let tx = conn.unchecked_transaction().unwrap();
    for path in paths {
        let heads = crate::dag_store::live_path_heads(&tx, GROUP, &path).unwrap();
        let version_of = |index: usize| {
            let hash = heads[index].content.as_ref().unwrap().version_hash;
            crate::dag_store::get_file_version(&tx, GROUP, &VersionHash(hash)).unwrap().unwrap()
        };
        match resolve_path_heads(&path, &heads) {
            PathResolution::Present { winner, conflict_copies } => {
                file_row(
                    &tx,
                    &path,
                    &version_of(winner),
                    &ChangeHash(heads[winner].change_hash),
                    false,
                );
                for copy in conflict_copies {
                    let head = &heads[copy.head];
                    file_row(
                        &tx,
                        &copy.path,
                        &version_of(copy.head),
                        &ChangeHash(head.change_hash),
                        false,
                    );
                }
            }
            PathResolution::Absent => {
                let existing: Option<(i64, i64, String)> = tx
                    .query_row(
                        "SELECT size, mtime_unix_nanos, blocks_json FROM files \
                         WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                        [GROUP, path.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .unwrap();
                if let Some((size, mtime_unix_nanos, blocks_json)) = existing {
                    let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).unwrap();
                    let removed = FileVersion::from_index_row(
                        blocks,
                        size as u64,
                        mtime_unix_nanos,
                        RecordKind::File,
                        None,
                        None,
                        Vec::new(),
                    );
                    file_row(&tx, &path, &removed, &ChangeHash(heads[0].change_hash), true);
                }
            }
        }
    }
    tx.execute("DELETE FROM projection_obligations WHERE group_id = ?1", [GROUP]).unwrap();
    tx.commit().unwrap();
}

fn seal(conn: &Connection) -> VerifiedSeal {
    let tx = conn.unchecked_transaction().unwrap();
    let seal = seal_group(&tx, GROUP).unwrap();
    tx.commit().unwrap();
    seal
}

fn collect(conn: &Connection) -> WitnessCollection {
    collect_authorization_witnesses(conn, GROUP).unwrap()
}

fn has_evidence(conn: &Connection, change: &ChangeHash) -> bool {
    crate::dag_store::published_view::is_published(conn, change).unwrap()
}

fn has_checkpoint(conn: &Connection, checkpoint: &[u8; 32]) -> bool {
    crate::dag_store::published_view::checkpoint_envelope(conn, checkpoint).unwrap().is_some()
}

fn evidence_rows(conn: &Connection, group: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM change_authorization ca \
         JOIN authorization_checkpoints k ON k.checkpoint_hash = ca.checkpoint_hash \
         WHERE k.group_id = ?1",
        [group],
        |row| row.get(0),
    )
    .unwrap()
}

fn checkpoint_rows(conn: &Connection, group: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM authorization_checkpoints WHERE group_id = ?1",
        [group],
        |row| row.get(0),
    )
    .unwrap()
}

fn serves_block(conn: &Connection, seed: u8) -> bool {
    crate::dag_store::published_view::published_group_file_version_references_block(
        conn,
        GROUP,
        &block(seed).0,
    )
    .unwrap()
}

fn row_author(conn: &Connection, path: &str) -> ChangeHash {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT authoring_change_hash FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            [GROUP, path],
            |row| row.get(0),
        )
        .unwrap();
    ChangeHash(bytes.try_into().unwrap())
}

/// What retention expiry does to a row once it is past both bounds.
fn expire_rows(conn: &Connection, path: &str, state: &str) {
    conn.execute(
        "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND state = ?3",
        [GROUP, path, state],
    )
    .unwrap();
}

struct History {
    a1: Change,
    a2: Change,
    a3: Change,
    b1: Change,
    b2: Change,
    c1: Change,
    /// Covers `a1` and `a2` only.
    first_checkpoint: [u8; 32],
    /// Covers the rest.
    second_checkpoint: [u8; 32],
}

/// `a1` writes `p` and `a2` removes it, `b1` writes the same bytes to `p`
/// concurrently and survives; `a3` and `b2` conflict on `r`; `c1` descends
/// everything and writes `q`. `a1` and `a2` end up authoring nothing the
/// group retains, heading nothing, and tipping no author.
fn build_history(conn: &Connection) -> History {
    store_versions(conn);
    let a1 = admit(conn, "device-a", &[], vec![put("p", 1)]);
    let a2 = admit(conn, "device-a", &[&a1], vec![delete("p")]);
    let first_checkpoint = publish(conn, 1);
    let b1 = admit(conn, "device-b", &[], vec![put("p", 1)]);
    let a3 = admit(conn, "device-a", &[&a2], vec![put("r", 2)]);
    let b2 = admit(conn, "device-b", &[&b1], vec![put("r", 3)]);
    let c1 = admit(conn, "device-c", &[&a3, &b2], vec![put("q", 4)]);
    let second_checkpoint = publish(conn, 2);
    project(conn);
    History { a1, a2, a3, b1, b2, c1, first_checkpoint, second_checkpoint }
}

// ---------------------------------------------------------------------------
// What goes.
// ---------------------------------------------------------------------------

/// A seal drops the evidence of every change it absorbed that nothing the
/// group retains names, and the checkpoint that covered only those. The
/// checkpoint still covering a retained row's author stays.
#[test]
fn a_seal_collects_the_evidence_of_absorbed_changes_nothing_retained_names() {
    let conn = open();
    let h = build_history(&conn);

    seal(&conn);

    for gone in [&h.a1, &h.a2] {
        assert!(
            !has_evidence(&conn, &gone.compute_hash()),
            "evidence of an absorbed change stayed"
        );
    }
    assert!(!has_checkpoint(&conn, &h.first_checkpoint), "a checkpoint citing nothing stayed");
    for kept in [&h.a3, &h.b1, &h.b2, &h.c1] {
        assert!(has_evidence(&conn, &kept.compute_hash()));
    }
    assert!(has_checkpoint(&conn, &h.second_checkpoint));
}

/// Evidence is `O(retained versions)`, not `O(lifetime changes)`: rewriting
/// one path through seal after seal, with retention expiring what it
/// replaced, keeps the same number of witnesses however long it goes on.
#[test]
fn witnesses_stay_bounded_by_what_is_retained_across_repeated_seals() {
    let conn = open();
    build_history(&conn);
    seal(&conn);

    let mut counts = Vec::new();
    for round in 0..6u8 {
        store_versions(&conn);
        emit(&conn, "device-a", vec![put("q", 10 + round)]);
        publish(&conn, 10 + round as u64);
        project(&conn);
        expire_rows(&conn, "q", "superseded");
        seal(&conn);
        counts.push((evidence_rows(&conn, GROUP), checkpoint_rows(&conn, GROUP)));
    }

    assert!(
        counts.windows(2).all(|pair| pair[0] == pair[1]),
        "witnesses grew with the history instead of with what is retained: {counts:?}"
    );
}

/// A link to a version no row and no carried head holds any more only
/// authorizes serving content this replica no longer retains.
#[test]
fn a_link_to_a_version_nothing_retained_holds_is_collected() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    assert!(serves_block(&conn, 4));
    store_versions(&conn);
    emit(&conn, "device-c", vec![put("q", 20)]);
    publish(&conn, 3);
    project(&conn);
    expire_rows(&conn, "q", "superseded");

    seal(&conn);

    assert!(!serves_block(&conn, 4), "a version nothing retains is still served");
    assert!(serves_block(&conn, 20));
    // `c1`'s last claim was that link: its row expired, and `q`'s head and
    // `device-c`'s tip moved on.
    assert!(!has_evidence(&conn, &h.c1.compute_hash()));
}

/// Collecting one group never touches another group's witnesses, even
/// ones nothing in this replica names.
#[test]
fn collection_is_scoped_to_its_group() {
    let conn = open();
    build_history(&conn);
    let elsewhere = ChangeHash([9; 32]);
    let checkpoint = publish_hashes(&conn, "another-group", 1, &[elsewhere]);

    seal(&conn);
    collect(&conn);

    assert!(has_evidence(&conn, &elsewhere));
    assert!(has_checkpoint(&conn, &checkpoint));
}

// ---------------------------------------------------------------------------
// What stays, one reason at a time.
// ---------------------------------------------------------------------------

/// A second seal re-carries every row the first one carried, and must
/// witness each author it no longer holds as a change: evidence of a
/// current row's author survives a seal, an epoch reset onto a second base,
/// and a collection in between.
#[test]
fn every_current_row_stays_witnessed_across_two_seals() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    collect(&conn);
    store_versions(&conn);
    emit(&conn, "device-a", vec![put("u", 21)]);
    publish(&conn, 3);
    project(&conn);

    let second = seal(&conn);

    let carried: Vec<ChangeHash> =
        second.snapshot().files.iter().filter_map(|file| file.authoring_change_hash).collect();
    assert!(!carried.is_empty());
    for author in carried {
        assert!(has_evidence(&conn, &author));
    }
}

/// A superseded or trashed version is still a retained version: a snapshot
/// lists it, and lists only rows whose evidence it can carry.
#[test]
fn superseded_and_trashed_versions_keep_the_evidence_that_authored_them() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    // `q`'s content from `c1` becomes superseded, `p`'s from `b1` trashed.
    emit(&conn, "device-c", vec![put("q", 22)]);
    emit(&conn, "device-b", vec![delete("p")]);
    publish(&conn, 3);
    project(&conn);
    let before = crate::dag_store::published_view::published_snapshot_files(&conn, GROUP).unwrap();

    seal(&conn);

    for author in [&h.c1, &h.b1] {
        assert!(has_evidence(&conn, &author.compute_hash()), "a retained version lost its author");
    }
    let after = crate::dag_store::published_view::published_snapshot_files(&conn, GROUP).unwrap();
    assert_eq!(after.len(), before.len(), "a retained version dropped out of the snapshot");
    // Neither version is any head's now; only the rows hold them.
    assert!(serves_block(&conn, 4), "the superseded version is no longer servable");
    assert!(serves_block(&conn, 1), "the trashed version is no longer servable");
}

/// A row trashed by a recursive delete keeps the evidence of the part that
/// trashed it, after its tombstone has expired and its author moved on:
/// restoring it answers from that operation.
#[test]
fn a_trashed_row_keeps_the_evidence_of_the_operation_that_trashed_it() {
    let conn = open();
    store_versions(&conn);
    let x1 = admit(&conn, "device-a", &[], vec![put("t/x", 30)]);
    project(&conn);
    let effects = vec![delete("t/x")];
    let rm = create_recursive_part_for_tests(
        vec![x1.compute_hash()],
        x1.lamport,
        DeviceId("device-d".to_string()),
        FolderGroupId(GROUP.to_string()),
        RecursiveOperation {
            operation_id: RecursiveOperationId([5; 16]),
            kind: RecursiveOperationKind::RmTree { root: SyncPath("t".to_string()) },
            part_index: 0,
            part_count: 1,
            effect_set_hash: EffectSetHash::of_effects(&effects),
        },
        effects,
        &key("device-d"),
    );
    assert!(matches!(
        crate::dag_store::admit_change(&conn, &rm).unwrap().outcome,
        crate::dag_store::AdmitOutcome::Applied
    ));
    project(&conn);
    let stamped: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND state = 'trashed' \
             AND trashed_by_operation_author = 'device-d'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stamped, 1, "the trashed row names the operation that trashed it");
    // `device-d` moves on, and `t/x` is written again.
    let d2 = admit(&conn, "device-d", &[&rm], vec![put("u", 31)]);
    admit(&conn, "device-a", &[&d2], vec![put("t/x", 32)]);
    publish(&conn, 1);
    project(&conn);
    // The tombstone the operation wrote expires; the trashed row does not.
    expire_rows(&conn, "t/x", "superseded");

    seal(&conn);

    assert!(has_evidence(&conn, &rm.compute_hash()));
    assert!(has_evidence(&conn, &x1.compute_hash()));
}

/// A version keeps the first link it got. When a later change writes the
/// same bytes and the row naming the first author expires, serving the
/// version still goes through the first author's evidence.
#[test]
fn a_version_linked_to_an_earlier_author_stays_servable() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    assert!(serves_block(&conn, 4));
    store_versions(&conn);
    // `device-b` writes `q`'s exact bytes again.
    let b3 = emit(&conn, "device-b", vec![put("q", 4)]);
    publish(&conn, 3);
    project(&conn);
    assert_eq!(row_author(&conn, "q"), b3.compute_hash());
    expire_rows(&conn, "q", "superseded");
    // `device-c` moves on elsewhere.
    emit(&conn, "device-c", vec![put("v", 23)]);
    publish(&conn, 4);
    project(&conn);

    seal(&conn);

    assert!(has_evidence(&conn, &h.c1.compute_hash()));
    assert!(serves_block(&conn, 4), "the carried version is no longer servable");
}

/// Two devices writing identical bytes concurrently are two heads the base
/// carries, though only one of them writes the row. The other is content a
/// merge joins and a projection may still materialize from.
#[test]
fn a_head_the_base_carries_without_a_row_keeps_its_evidence() {
    let conn = open();
    store_versions(&conn);
    let s1 = admit(&conn, "device-a", &[], vec![put("s", 33)]);
    let s2 = admit(&conn, "device-b", &[], vec![put("s", 33)]);
    admit(&conn, "device-a", &[&s1, &s2], vec![put("w", 34)]);
    admit(&conn, "device-b", &[&s1, &s2], vec![put("y", 35)]);
    publish(&conn, 1);
    project(&conn);
    let row = row_author(&conn, "s");
    let rowless = if row == s1.compute_hash() { &s2 } else { &s1 };

    let sealed = seal(&conn);

    assert!(sealed.summary().path_heads.iter().any(|h| h.change_hash == rowless.compute_hash()));
    assert!(has_evidence(&conn, &rowless.compute_hash()));
}

/// A head the base carries keeps its version servable before any row holds
/// it: a conflict copy not materialized yet, with its projection still
/// owed, is content a peer materializing the same base asks for.
#[test]
fn a_carried_head_keeps_its_version_servable_while_its_copy_is_owed() {
    let conn = open();
    let h = build_history(&conn);
    seal(&conn);
    let copy: String = conn
        .query_row(
            "SELECT path FROM files WHERE group_id = ?1 AND path LIKE 'r %' AND state = 'current'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    let copied_seed = if row_author(&conn, &copy) == h.a3.compute_hash() { 2 } else { 3 };
    conn.execute("DELETE FROM files WHERE group_id = ?1 AND path = ?2", [GROUP, copy.as_str()])
        .unwrap();
    crate::projection_obligations::init_projection_obligations_schema(&conn).unwrap();
    conn.execute(
        "INSERT INTO projection_obligations \
         (group_id, path, invalidation_generation, state, created_at, updated_at) \
         VALUES (?1, 'r', 1, 'pending', 0, 0)",
        [GROUP],
    )
    .unwrap();

    collect(&conn);

    assert!(serves_block(&conn, copied_seed), "the owed copy's content is no longer servable");
}

/// An author whose every write was superseded still has a tip, and the tip
/// is what the summary names for it.
#[test]
fn an_author_whose_every_write_was_superseded_keeps_its_tip_evidence() {
    let conn = open();
    store_versions(&conn);
    let d1 = admit(&conn, "device-d", &[], vec![put("s", 36)]);
    admit(&conn, "device-a", &[&d1], vec![put("s", 37)]);
    publish(&conn, 1);
    project(&conn);

    seal(&conn);

    assert!(has_evidence(&conn, &d1.compute_hash()));
}

/// A row the base carries names its author in the base's summary, and the
/// evidence stays while that base is the group's, even once the row itself
/// expires.
#[test]
fn a_row_the_base_carries_keeps_its_authors_evidence_after_the_row_expires() {
    let conn = open();
    store_versions(&conn);
    // `x` and `y` hold the same version, written by two changes; the seal
    // links the version to `x`'s author alone.
    let x = admit(&conn, "device-a", &[], vec![put("x", 38)]);
    let y = admit(&conn, "device-b", &[&x], vec![put("y", 38)]);
    project(&conn);
    // `device-b` removes `y`, so `y`'s write heads nothing and tips
    // nothing, and survives only as the trashed row.
    admit(&conn, "device-b", &[&y], vec![delete("y")]);
    publish(&conn, 1);
    project(&conn);

    seal(&conn);
    expire_rows(&conn, "y", "trashed");
    collect(&conn);

    assert!(has_evidence(&conn, &y.compute_hash()));
}

/// A change above the base is history the group holds, published and
/// waiting for its seal, before any row names it.
#[test]
fn a_change_above_the_base_keeps_its_evidence_before_anything_projects_it() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    let e1 = emit(&conn, "device-a", vec![put("z", 24)]);
    emit(&conn, "device-a", vec![put("z2", 25)]);
    publish(&conn, 3);

    collect(&conn);
    project(&conn);

    assert!(has_evidence(&conn, &e1.compute_hash()));
    seal(&conn);
}

/// A file row is on its own a reason to keep its author's evidence: the
/// current-row readers (`unauthored_current_paths_in_tx`,
/// `group_history_paths`) take a row whose author is no longer retained as
/// authored only through that evidence. Here nothing but the row names the
/// author -- no change, link, base or tip -- while a change nothing names
/// under the same checkpoint goes.
#[test]
fn a_file_row_alone_keeps_its_authors_evidence() {
    let conn = open();
    store_versions(&conn);
    let author = ChangeHash([5; 32]);
    let unnamed = ChangeHash([6; 32]);
    let checkpoint = publish_hashes(&conn, GROUP, 1, &[author, unnamed]);
    {
        let tx = conn.unchecked_transaction().unwrap();
        file_row(&tx, "only", &version(30), &author, false);
        tx.commit().unwrap();
    }

    collect(&conn);

    assert!(has_evidence(&conn, &author), "a file row's author lost its evidence");
    assert!(!has_evidence(&conn, &unnamed));
    assert!(has_checkpoint(&conn, &checkpoint));
    assert!(crate::file_index::unauthored_current_paths_in_tx(&conn, GROUP).unwrap().is_empty());
}

/// An orphan arrives with its evidence and waits for its parent; the
/// evidence has to be there when it is admitted.
#[test]
fn an_orphan_keeps_the_evidence_it_arrived_with() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);
    store_versions(&conn);
    let orphan = Change::create_signed(
        vec![ChangeHash([8; 32])],
        100,
        DeviceId("device-e".to_string()),
        yadorilink_replica_domain::ids::AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        yadorilink_replica_domain::rebootstrap::HistoryEpoch::Base(sealed.history_base()),
        vec![put("o", 26)],
        &key("device-e"),
    );
    assert!(matches!(
        crate::dag_store::admit_change(&conn, &orphan).unwrap().outcome,
        crate::dag_store::AdmitOutcome::Orphaned
    ));
    publish_hashes(&conn, GROUP, 3, &[orphan.compute_hash()]);

    collect(&conn);

    assert!(has_evidence(&conn, &orphan.compute_hash()));
}

/// A pruned stub is history the replica still holds, and keeps its
/// evidence until a seal retires the stub itself.
#[test]
fn a_pruned_stub_keeps_its_evidence() {
    let conn = open();
    let h = build_history(&conn);
    let checkpoint = yadorilink_replica_engine::compaction::Checkpoint::new(
        FolderGroupId(GROUP.to_string()),
        vec![h.a3.compute_hash()],
        [0; 32],
    );
    {
        let tx = conn.unchecked_transaction().unwrap();
        crate::dag_store::commit_prune(&tx, &checkpoint, &[h.a1.compute_hash()]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!crate::dag_store::has_change(&conn, &h.a1.compute_hash()).unwrap());

    collect(&conn);

    assert!(has_evidence(&conn, &h.a1.compute_hash()));
}

/// An installed base carries its rows' witnesses in the snapshot, and the
/// installer keeps every one of them: each row stays authored, and each
/// version the witnesses authorize stays servable.
///
/// That includes the row the base's frontier change wrote: the install
/// keeps no change body, so that row too is served on the strength of the
/// witness the base carries for it, exactly as the sealer serves it.
#[test]
fn an_installed_base_keeps_every_witness_it_installed() {
    let sealer = open();
    let h = build_history(&sealer);
    let sealed = seal(&sealer);

    let mut installer = open();
    {
        let tx = installer.transaction().unwrap();
        install_base_for_tests(&tx, sealed.checkpoint(), sealed.snapshot()).unwrap();
        tx.commit().unwrap();
    }
    let published = |conn: &Connection| {
        crate::dag_store::published_view::published_snapshot_files(conn, GROUP).unwrap().len()
    };
    let installed = published(&installer);
    assert_eq!(installed, sealed.snapshot().published_change_witnesses.len());
    assert!(sealed.frontier().contains(&h.c1.compute_hash()));

    collect(&installer);

    assert_eq!(published(&installer), installed, "an installed row lost its witness");
    for witness in &sealed.snapshot().published_change_witnesses {
        assert!(has_evidence(&installer, &witness.change_hash));
    }
    assert!(crate::file_index::unauthored_current_paths_in_tx(&installer, GROUP)
        .unwrap()
        .is_empty());
    for seed in [1, 2, 3] {
        assert!(serves_block(&installer, seed), "carried version {seed} is no longer servable");
    }
    assert!(has_evidence(&installer, &h.c1.compute_hash()), "the frontier change's evidence");
    assert!(serves_block(&installer, 4), "the row the frontier change wrote is served");
}

/// A replica that only installs peers' bases and never seals must stay
/// bounded too. An installer that held the same history the sealer
/// absorbed keeps no evidence of `a1` and `a2` -- which the sealer itself
/// collected -- and no checkpoint that covered only them: an install
/// collects what the lineage it replaces alone named, as a seal does.
#[test]
fn an_install_leaves_no_evidence_only_the_replaced_lineage_named() {
    let sealer = open();
    build_history(&sealer);
    let sealed = seal(&sealer);

    let mut installer = open();
    let h = build_history(&installer);
    {
        let tx = installer.transaction().unwrap();
        install_base_for_tests(&tx, sealed.checkpoint(), sealed.snapshot()).unwrap();
        tx.commit().unwrap();
    }

    for gone in [&h.a1, &h.a2] {
        assert!(
            !has_evidence(&installer, &gone.compute_hash()),
            "an install kept evidence only the lineage it replaced named"
        );
    }
    assert!(!has_checkpoint(&installer, &h.first_checkpoint));
    assert_eq!(
        (evidence_rows(&installer, GROUP), checkpoint_rows(&installer, GROUP)),
        (evidence_rows(&sealer, GROUP), checkpoint_rows(&sealer, GROUP)),
        "an installer keeps more witnesses than the base it installed retains"
    );
}

/// Collection is idempotent: a second run finds nothing more.
#[test]
fn a_second_collection_removes_nothing() {
    let conn = open();
    build_history(&conn);
    seal(&conn);

    assert_eq!(collect(&conn), WitnessCollection::default());
}
