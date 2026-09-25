//! The derived path frontier, held against an independent re-derivation
//! of the same question.
//!
//! `path_live_heads` is maintained incrementally: each admission decides
//! which of a path's heads it supersedes and records the result. Nothing
//! recomputes that later, so an error made once is permanent and silent
//! -- a path simply resolves to the wrong content, or to no content at
//! all, from then on.
//!
//! So every scenario here computes the same answer twice. The oracle
//! ([`history_walk_live_heads`]) is the algorithm the index replaced: walk
//! the group's ancestry backwards from its current heads, decode every
//! visited change, keep the ones whose ops touch the path, and stop a
//! lineage at the first one that does. It is deliberately the slow,
//! obvious form, written out here rather than kept in the production read
//! path -- a fallback there would hide exactly the divergence this file
//! exists to catch.
//!
//! The scenarios are chosen for the shapes where incremental maintenance
//! and a full re-derivation can come apart: concurrency that must be
//! preserved, merges that do not touch the path and must therefore change
//! nothing, a later change that resolves an earlier fork, delivery in an
//! order that buffers changes as orphans and promotes them later,
//! duplicate admission, and a rebuild from canonical history.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::rebootstrap::Checkpoint;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_replica_engine::conflict::{change_touches_path, path_head_from_change, PathHead};
use yadorilink_sync_sqlite::dag_store::{
    admit_change, commit_prune, derive_required_conflict_copy_ops, group_heads,
    init_conflict_copy_provenance_schema, init_dag_schema, live_path_heads, path_heads_at_frontier,
    put_file_version, rebuild_group_path_frontier, register_retention_root, RetentionClass,
};

const GROUP: &str = "group-differential";

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    // Admitting a change whose parents include more than one head makes
    // admission derive the conflict copies that merge owes, which reads
    // this table. Provisioned here so a merge scenario exercises the real
    // admission path rather than a reduced one.
    init_conflict_copy_provenance_schema(&conn).unwrap();
    conn
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn version(byte: u8) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1_000 + byte as i64,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Puts every version any op in this file might reference, so admission's
/// referenced-version validation is never the thing under test.
fn seed_versions(conn: &Connection) {
    for byte in 0..=40u8 {
        put_file_version(conn, GROUP, &version(byte)).unwrap();
    }
}

fn version_hash(byte: u8) -> VersionHash {
    version(byte).version_hash
}

fn put(path: &str, byte: u8) -> Op {
    Op::Put {
        path: SyncPath(path.to_string()),
        version: version_hash(byte),
        origin: PutOrigin::Direct,
    }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.to_string()) }
}

fn mv(from: &str, to: &str, byte: u8) -> Op {
    Op::Move {
        from: SyncPath(from.to_string()),
        to: SyncPath(to.to_string()),
        version: version_hash(byte),
    }
}

/// Builds a change on the given parents, the way the real emitter builds
/// one.
///
/// Lamport is `max(parent lamports) + 1`, so the DAG's "lamport strictly
/// increases along every parent edge" invariant holds. The conflict-copy
/// puts the change owes are derived and appended, because admission
/// rejects a change that resolves a contested path without carrying them
/// -- a merge hand-written without them is not a change this system can
/// produce, and testing the frontier against one would be testing a shape
/// that never occurs.
fn change_on(
    conn: &Connection,
    parents: &[(&ChangeHash, u64)],
    device: &str,
    seed: u8,
    mut ops: Vec<Op>,
) -> (Change, u64) {
    let parent_hashes: Vec<ChangeHash> = parents.iter().map(|(h, _)| **h).collect();
    let max_parent_lamport = parents.iter().map(|(_, l)| *l).max().unwrap_or(0);
    ops.extend(
        derive_required_conflict_copy_ops(conn, GROUP, &parent_hashes, &ops)
            .expect("deriving the conflict copies a change owes must succeed"),
    );
    let change = create_signed_for_tests(
        parent_hashes,
        max_parent_lamport,
        DeviceId(device.to_string()),
        FolderGroupId(GROUP.to_string()),
        ops,
        &key(seed),
    );
    let lamport = change.lamport;
    (change, lamport)
}

fn admit(conn: &Connection, change: &Change) -> ChangeHash {
    admit_change(conn, change).unwrap();
    change.compute_hash()
}

// ---------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------

/// The algorithm `path_live_heads` replaced, kept here and only here.
///
/// Walks backwards from the group's current heads over retained parent
/// edges. Every visited change is decoded and its ops scanned; one that
/// touches `path` is a live head and its own ancestors are not explored
/// further along that lineage, because anything above it on that lineage
/// is superseded by it. One that does not touch `path` contributes
/// nothing and the walk continues through it.
///
/// This is O(the group's whole history) per path resolved, which is why
/// it is not what production runs. It is also obviously correct, which is
/// why it is what production is checked against.
fn history_walk_live_heads(conn: &Connection, group_id: &str, path: &str) -> Vec<PathHead> {
    let heads = group_heads(conn, group_id).unwrap();
    history_walk_at_frontier(conn, path, &heads)
}

/// [`history_walk_live_heads`] seeded at an arbitrary frontier rather
/// than the group's current heads.
///
/// This is the independent check on historical frontier resolution.
/// `path_heads_at_frontier` no longer walks -- it reads the same derived
/// effects the live-head read does -- so it can no longer stand as its
/// own oracle, and something that owes nothing to those tables has to
/// answer the same question. This does: it decodes canonical changes and
/// follows parent edges, and touches no derived table at all.
fn history_walk_at_frontier(conn: &Connection, path: &str, seed: &[ChangeHash]) -> Vec<PathHead> {
    let mut frontier: Vec<ChangeHash> = seed.to_vec();
    let mut visited: HashSet<ChangeHash> = HashSet::new();
    let mut found: Vec<PathHead> = Vec::new();

    while let Some(hash) = frontier.pop() {
        if !visited.insert(hash) {
            continue;
        }
        let Some(change) = read_change(conn, &hash) else {
            continue;
        };
        if change_touches_path(&change, path) {
            if let Some(head) = path_head_from_change(&change, path) {
                found.push(head);
            }
            // Stop this lineage: anything further back that touches
            // `path` is an ancestor of what was just found, hence
            // superseded by it.
            continue;
        }
        for parent in &change.parents {
            if !visited.contains(parent) {
                frontier.push(*parent);
            }
        }
    }

    // The walk stops each lineage at its first toucher, but two lineages
    // can reach the same toucher by different routes, and one lineage's
    // toucher can be an ancestor of another's. Drop anything another
    // finding descends from.
    let mut live: Vec<PathHead> = Vec::new();
    for candidate in &found {
        let superseded = found.iter().any(|other| {
            other.change_hash != candidate.change_hash
                && reaches(conn, &ChangeHash(other.change_hash), &ChangeHash(candidate.change_hash))
        });
        if !superseded && !live.iter().any(|h| h.change_hash == candidate.change_hash) {
            live.push(candidate.clone());
        }
    }
    live
}

/// Whether `from` reaches `to` by retained parent edges. Plain BFS, no
/// pruning of any kind -- the oracle must not borrow the production
/// implementation's shortcuts.
fn reaches(conn: &Connection, from: &ChangeHash, to: &ChangeHash) -> bool {
    let mut queue = vec![*from];
    let mut seen = HashSet::new();
    while let Some(node) = queue.pop() {
        if !seen.insert(node) {
            continue;
        }
        let Some(change) = read_change(conn, &node) else {
            continue;
        };
        for parent in &change.parents {
            if parent == to {
                return true;
            }
            queue.push(*parent);
        }
    }
    false
}

fn read_change(conn: &Connection, hash: &ChangeHash) -> Option<Change> {
    let encoded: Vec<u8> = conn
        .query_row(
            "SELECT encoded FROM changes WHERE change_hash = ?1",
            rusqlite::params![&hash.0[..]],
            |row| row.get(0),
        )
        .ok()?;
    Change::from_wire_bytes(&encoded).ok()
}

/// Every path any retained change in the group mentions, so a scenario
/// checks the whole path space rather than the paths its author
/// remembered to list.
fn all_paths(conn: &Connection, group_id: &str) -> Vec<String> {
    let mut stmt = conn.prepare("SELECT encoded FROM changes WHERE group_id = ?1").unwrap();
    let rows = stmt.query_map(rusqlite::params![group_id], |row| row.get::<_, Vec<u8>>(0)).unwrap();
    let mut paths: HashSet<String> = HashSet::new();
    for row in rows {
        let change = Change::from_wire_bytes(&row.unwrap()).unwrap();
        for op in &change.ops {
            match op {
                Op::Put { path, .. } | Op::Delete { path } => {
                    paths.insert(path.as_str().to_string());
                }
                Op::Move { from, to, .. } => {
                    paths.insert(from.as_str().to_string());
                    paths.insert(to.as_str().to_string());
                }
            }
        }
    }
    // A path nothing ever touched must resolve to nothing on both sides
    // too, so include one.
    paths.insert("never-touched.txt".to_string());
    let mut out: Vec<String> = paths.into_iter().collect();
    out.sort();
    out
}

fn normalize(mut heads: Vec<PathHead>) -> Vec<(String, u64, String, String, Option<[u8; 32]>)> {
    heads.sort_by_key(|h| h.change_hash);
    heads
        .into_iter()
        .map(|h| {
            (
                hex(&h.change_hash),
                h.lamport,
                h.device_id,
                h.naming_device_id,
                h.content.map(|c| c.version_hash),
            )
        })
        .collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The assertion every scenario ends with: for every path the group's
/// history mentions, the incrementally maintained index must agree
/// exactly with two independent re-derivations -- same heads, same
/// lamports, same carrier and naming devices, same content.
///
/// Two oracles, not one, because they fail differently. The local walk
/// is written out in this file and owes nothing to the implementation it
/// checks. `path_heads_at_frontier` is production code that resolves a
/// path against an arbitrary frontier, still used for historical
/// frontiers where no index exists; seeded with the group's current
/// heads it is answering exactly the question the index answers, so
/// agreement here is what licenses admission to read the index instead
/// of walking whenever it recognizes the frontier as the current one.
fn assert_index_matches_oracle(conn: &Connection, scenario: &str) {
    let heads = group_heads(conn, GROUP).unwrap();
    for path in all_paths(conn, GROUP) {
        let indexed = normalize(live_path_heads(conn, GROUP, &path).unwrap());
        let walked = normalize(history_walk_live_heads(conn, GROUP, &path));
        assert_eq!(
            indexed, walked,
            "{scenario}: the derived index and the history walk disagree about {path}"
        );
        let at_frontier = normalize(path_heads_at_frontier(conn, GROUP, &path, &heads).unwrap());
        assert_eq!(
            indexed, at_frontier,
            "{scenario}: the derived index and the frontier walk disagree about {path}"
        );
    }
}

/// The same check after discarding every derived row and rebuilding from
/// canonical history. A rebuild that produced a different frontier from
/// the one incremental maintenance produced would mean one of the two is
/// wrong, and nothing else would reveal which situations it happens in.
fn assert_rebuild_matches_incremental(conn: &Connection, scenario: &str) {
    let mut before: HashMap<String, Vec<_>> = HashMap::new();
    for path in all_paths(conn, GROUP) {
        before.insert(path.clone(), normalize(live_path_heads(conn, GROUP, &path).unwrap()));
    }
    rebuild_group_path_frontier(conn, GROUP).unwrap();
    for (path, expected) in before {
        let after = normalize(live_path_heads(conn, GROUP, &path).unwrap());
        assert_eq!(
            after, expected,
            "{scenario}: rebuilding from canonical history changed {path}'s live heads"
        );
    }
    assert_index_matches_oracle(conn, &format!("{scenario} (after rebuild)"));
}

fn check(conn: &Connection, scenario: &str) {
    assert_index_matches_oracle(conn, scenario);
    assert_rebuild_matches_incremental(conn, scenario);
}

// ---------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------

/// A(P) then B(P) on top of it. The later change supersedes the earlier:
/// `P -> {B}`.
#[test]
fn sequential_edits_leave_one_live_head() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);

    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "a sequential edit must leave exactly one live head");
    assert_eq!(heads[0].change_hash, hb.0, "the live head must be the later change");

    check(&conn, "sequential edits");
}

/// A(P) and B(P) both on the root, neither descending from the other.
/// Both stay live: `P -> {A, B}`.
#[test]
fn concurrent_edits_leave_both_live_heads() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);

    let (a, _) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);

    let mut got: Vec<[u8; 32]> = live_path_heads(&conn, GROUP, "p.txt")
        .unwrap()
        .into_iter()
        .map(|h| h.change_hash)
        .collect();
    got.sort();
    let mut want = vec![ha.0, hb.0];
    want.sort();
    assert_eq!(got, want, "two concurrent writers of a path must both stay live");

    check(&conn, "concurrent edits");
}

/// A(P) and B(P) concurrent, then a merge M that touches only Q. M must
/// leave P's frontier alone: `P -> {A, B}` still, and `Q -> {M}`.
///
/// This is the case a naive "the newest change supersedes everything"
/// rule gets wrong, and it gets it wrong silently: P would collapse to
/// one arbitrary head and the other writer's content would vanish.
#[test]
fn a_merge_through_an_unrelated_path_does_not_disturb_the_forked_one() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);
    let (a, la) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, lb) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);

    let (m, _) = change_on(&conn, &[(&ha, la), (&hb, lb)], "device-a", 1, vec![put("q.txt", 3)]);
    let hm = admit(&conn, &m);

    let mut got: Vec<[u8; 32]> = live_path_heads(&conn, GROUP, "p.txt")
        .unwrap()
        .into_iter()
        .map(|h| h.change_hash)
        .collect();
    got.sort();
    let mut want = vec![ha.0, hb.0];
    want.sort();
    assert_eq!(got, want, "a merge that does not touch p.txt must not change p.txt's heads");

    let q = live_path_heads(&conn, GROUP, "q.txt").unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].change_hash, hm.0);

    check(&conn, "merge through an unrelated path");
}

/// The same fork, then a merge M touching Q, then E on top of M touching
/// P. E descends from both A and B, so it resolves the fork: `P -> {E}`.
#[test]
fn a_later_change_over_a_merge_resolves_the_fork() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);
    let (a, la) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, lb) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);
    let (m, lm) = change_on(&conn, &[(&ha, la), (&hb, lb)], "device-a", 1, vec![put("q.txt", 3)]);
    let hm = admit(&conn, &m);
    let (e, _) = change_on(&conn, &[(&hm, lm)], "device-a", 1, vec![put("p.txt", 4)]);
    let he = admit(&conn, &e);

    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "a change descending from both forks must resolve the path");
    assert_eq!(heads[0].change_hash, he.0);

    check(&conn, "later change resolves the fork");
}

/// Three devices forking off one root and all writing the same path, then
/// a merge that resolves them. Concurrency wider than two must behave the
/// same way; nothing here may be special-cased to a pair.
#[test]
fn three_way_concurrency_keeps_every_branch_then_collapses_on_merge() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);

    let mut tips = Vec::new();
    for (i, device) in ["device-a", "device-b", "device-c"].iter().enumerate() {
        let (c, l) = change_on(
            &conn,
            &[(&hroot, lroot)],
            device,
            (i + 1) as u8,
            vec![put("p.txt", (i + 1) as u8)],
        );
        tips.push((admit(&conn, &c), l));
    }

    assert_eq!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().len(),
        3,
        "three concurrent writers must leave three live heads"
    );
    check(&conn, "three-way concurrency");

    let parents: Vec<(&ChangeHash, u64)> = tips.iter().map(|(h, l)| (h, *l)).collect();
    let (m, _) = change_on(&conn, &parents, "device-a", 1, vec![put("p.txt", 9)]);
    let hm = admit(&conn, &m);
    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "a merge touching the path must collapse all three");
    assert_eq!(heads[0].change_hash, hm.0);

    check(&conn, "three-way concurrency, merged");
}

/// Five devices, each forking off the root and writing both a shared path
/// and its own. Width must follow the path's real conflict width, not the
/// device count or the history length.
#[test]
fn n_way_concurrency_tracks_per_path_width() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);

    for i in 0..5u8 {
        let (c, _) = change_on(
            &conn,
            &[(&hroot, lroot)],
            &format!("device-{i}"),
            i + 1,
            vec![put("shared.txt", i + 1), put(&format!("own-{i}.txt"), i + 10)],
        );
        admit(&conn, &c);
    }

    assert_eq!(
        live_path_heads(&conn, GROUP, "shared.txt").unwrap().len(),
        5,
        "the contested path must carry every concurrent writer"
    );
    for i in 0..5u8 {
        assert_eq!(
            live_path_heads(&conn, GROUP, &format!("own-{i}.txt")).unwrap().len(),
            1,
            "an uncontested path must stay at width one however wide the group is"
        );
    }

    check(&conn, "n-way concurrency");
}

/// A delete is a head like any other: it supersedes what it deletes, and
/// concurrently with a content head it stays live alongside it rather
/// than removing it.
#[test]
fn delete_supersedes_sequentially_and_coexists_concurrently() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let hroot = admit(&conn, &root);

    let (d, _) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![delete("p.txt")]);
    let hd = admit(&conn, &d);
    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].change_hash, hd.0);
    assert!(heads[0].content.is_none(), "a delete must produce a removing head");
    check(&conn, "sequential delete");

    // Concurrently with that delete, another device writes the path.
    let (w, _) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 5)]);
    let hw = admit(&conn, &w);
    let mut got: Vec<[u8; 32]> = live_path_heads(&conn, GROUP, "p.txt")
        .unwrap()
        .into_iter()
        .map(|h| h.change_hash)
        .collect();
    got.sort();
    let mut want = vec![hd.0, hw.0];
    want.sort();
    assert_eq!(got, want, "a concurrent delete and write must both stay live");

    check(&conn, "concurrent delete and write");
}

/// A move removes its source and lands content at its target, so it is a
/// head on both paths at once.
#[test]
fn move_is_a_head_on_both_of_its_paths() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("from.txt", 1)]);
    let hroot = admit(&conn, &root);
    let (m, _) =
        change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![mv("from.txt", "to.txt", 2)]);
    let hm = admit(&conn, &m);

    let from = live_path_heads(&conn, GROUP, "from.txt").unwrap();
    assert_eq!(from.len(), 1);
    assert_eq!(from[0].change_hash, hm.0);
    assert!(from[0].content.is_none(), "the source side of a move must be a removing head");

    let to = live_path_heads(&conn, GROUP, "to.txt").unwrap();
    assert_eq!(to.len(), 1);
    assert_eq!(to[0].change_hash, hm.0);
    assert!(to[0].content.is_some(), "the target side of a move must land content");

    check(&conn, "move");
}

/// Two devices concurrently moving the same source to different targets:
/// three paths, each with its own width.
#[test]
fn concurrent_moves_from_one_source_keep_every_side_live() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("from.txt", 1)]);
    let hroot = admit(&conn, &root);
    let (a, _) =
        change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![mv("from.txt", "a.txt", 2)]);
    let ha = admit(&conn, &a);
    let (b, _) =
        change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![mv("from.txt", "b.txt", 3)]);
    let hb = admit(&conn, &b);

    assert_eq!(
        live_path_heads(&conn, GROUP, "from.txt").unwrap().len(),
        2,
        "both moves remove the source, concurrently"
    );
    assert_eq!(live_path_heads(&conn, GROUP, "a.txt").unwrap()[0].change_hash, ha.0);
    assert_eq!(live_path_heads(&conn, GROUP, "b.txt").unwrap()[0].change_hash, hb.0);

    check(&conn, "concurrent moves");
}

/// A conflict copy keeps the carrier's naming identity; a repair
/// re-assertion moves it to the original author. Both are ordinary heads
/// for causal purposes, and the index must carry the distinction the
/// per-path fold makes.
#[test]
fn conflict_copy_and_reassertion_origins_survive_the_round_trip() {
    let conn = open();
    seed_versions(&conn);

    // A genuine fork, so the merge below really does owe a conflict copy
    // and the derivation produces one rather than the test inventing it.
    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);
    let (a, la) = change_on(
        &conn,
        &[(&hroot, lroot)],
        "device-a",
        1,
        // Also lands the content the merge below re-asserts: a
        // re-assertion carries existing content forward, so the path has
        // to already hold some.
        vec![put("p.txt", 1), put("reasserted.txt", 3)],
    );
    let ha = admit(&conn, &a);
    let (b, lb) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);

    let reassert_op = Op::Put {
        path: SyncPath("reasserted.txt".to_string()),
        version: version_hash(3),
        origin: PutOrigin::Reasserted {
            // The change that actually wrote this path's current content.
            original_change: ha,
            // Must be the device that actually wrote the content being
            // carried forward -- admission checks this against the head
            // the re-assertion names.
            naming_device_id: DeviceId("device-a".to_string()),
        },
    };
    let (m, _) = change_on(
        &conn,
        &[(&ha, la), (&hb, lb)],
        "device-carrier",
        4,
        vec![put("p.txt", 4), reassert_op],
    );
    let hm = admit(&conn, &m);

    // The merge resolved p.txt, and carries a copy for the branch that
    // lost. Its path is derived from the losing change, so find it rather
    // than spelling it out.
    let copy_path = all_paths(&conn, GROUP)
        .into_iter()
        .find(|p| p.contains("conflicted copy"))
        .expect("the merge must have carried a conflict copy for the losing branch");
    let copy = live_path_heads(&conn, GROUP, &copy_path).unwrap();
    assert_eq!(copy.len(), 1);
    assert_eq!(
        copy[0].naming_device_id, "device-carrier",
        "a conflict-copy put must keep the carrier's naming identity"
    );

    let reasserted = live_path_heads(&conn, GROUP, "reasserted.txt").unwrap();
    assert_eq!(reasserted.len(), 1);
    assert_eq!(
        reasserted[0].naming_device_id, "device-a",
        "a re-assertion must name the device that actually wrote the content"
    );
    assert_eq!(
        reasserted[0].device_id, "device-carrier",
        "causal identity stays with the carrier even when naming identity does not"
    );

    let p = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(p.len(), 1, "the merge resolves the contested path");
    assert_eq!(p[0].change_hash, hm.0);

    check(&conn, "conflict-copy and re-assertion origins");
}

/// A chain delivered child-first. Each change is buffered as an orphan
/// until its parents arrive, then promoted. Promotion goes through the
/// same admission path, so the frontier must land exactly where in-order
/// delivery would have left it.
#[test]
fn out_of_order_delivery_and_orphan_promotion_converge() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = a.compute_hash();
    let (b, lb) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("p.txt", 2)]);
    let hb = b.compute_hash();
    let (c, _) = change_on(&conn, &[(&hb, lb)], "device-a", 1, vec![put("p.txt", 3)]);
    let hc = c.compute_hash();

    // Reverse order: c and b are orphans until a lands.
    admit_change(&conn, &c).unwrap();
    admit_change(&conn, &b).unwrap();
    assert!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().is_empty(),
        "an unadmitted orphan must not be a live head"
    );
    admit_change(&conn, &a).unwrap();

    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "once promoted, the chain must resolve to its tip");
    assert_eq!(heads[0].change_hash, hc.0);

    check(&conn, "out-of-order delivery");
}

/// Out-of-order delivery across a fork, so promotion happens with genuine
/// concurrency present rather than down a single chain.
#[test]
fn out_of_order_delivery_across_a_fork_converges() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = root.compute_hash();
    let (a, _) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 1)]);
    let (b, _) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    let ha = a.compute_hash();
    let hb = b.compute_hash();

    admit_change(&conn, &a).unwrap();
    admit_change(&conn, &b).unwrap();
    admit_change(&conn, &root).unwrap();

    let mut got: Vec<[u8; 32]> = live_path_heads(&conn, GROUP, "p.txt")
        .unwrap()
        .into_iter()
        .map(|h| h.change_hash)
        .collect();
    got.sort();
    let mut want = vec![ha.0, hb.0];
    want.sort();
    assert_eq!(got, want, "promotion must preserve concurrency, not collapse it");

    check(&conn, "out-of-order delivery across a fork");
}

/// Admitting the same change twice must change nothing. A second
/// admission that re-ran the frontier update against an already-updated
/// frontier could drop a concurrent head that the first admission
/// correctly kept.
#[test]
fn duplicate_admission_is_a_no_op() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);
    let (a, _) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 1)]);
    let (b, _) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 2)]);
    admit(&conn, &a);
    admit(&conn, &b);

    let before = normalize(live_path_heads(&conn, GROUP, "p.txt").unwrap());
    for _ in 0..3 {
        admit_change(&conn, &a).unwrap();
        admit_change(&conn, &b).unwrap();
        admit_change(&conn, &root).unwrap();
    }
    let after = normalize(live_path_heads(&conn, GROUP, "p.txt").unwrap());
    assert_eq!(after, before, "re-admitting an already-admitted change must change nothing");

    check(&conn, "duplicate admission");
}

/// A rebuild from canonical history over a DAG with every shape in it at
/// once, starting from derived tables that have been wiped -- the
/// migration path for a database that predates the index, and the repair
/// path for one that lost it.
#[test]
fn rebuilding_from_canonical_history_reproduces_the_frontier() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let hroot = admit(&conn, &root);
    let (a, la) = change_on(
        &conn,
        &[(&hroot, lroot)],
        "device-a",
        1,
        vec![put("p.txt", 1), mv("seed.txt", "moved.txt", 2)],
    );
    let ha = admit(&conn, &a);
    let (b, lb) =
        change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 3), delete("q.txt")]);
    let hb = admit(&conn, &b);
    let (m, lm) = change_on(&conn, &[(&ha, la), (&hb, lb)], "device-a", 1, vec![put("r.txt", 4)]);
    let hm = admit(&conn, &m);
    let (tail, _) = change_on(&conn, &[(&hm, lm)], "device-c", 3, vec![delete("p.txt")]);
    admit(&conn, &tail);

    let mut expected: HashMap<String, Vec<_>> = HashMap::new();
    for path in all_paths(&conn, GROUP) {
        expected.insert(path.clone(), normalize(live_path_heads(&conn, GROUP, &path).unwrap()));
    }

    // Wipe every derived row, the way a database predating these tables
    // would present itself.
    conn.execute("DELETE FROM path_live_heads", []).unwrap();
    conn.execute("DELETE FROM change_path_effects", []).unwrap();
    conn.execute("DELETE FROM change_causal_order", []).unwrap();
    conn.execute("DELETE FROM group_admission_ord", []).unwrap();
    for path in expected.keys() {
        assert!(
            live_path_heads(&conn, GROUP, path).unwrap().is_empty(),
            "sanity: the wipe must actually have emptied the index"
        );
    }

    rebuild_group_path_frontier(&conn, GROUP).unwrap();
    for (path, want) in &expected {
        assert_eq!(
            &normalize(live_path_heads(&conn, GROUP, path).unwrap()),
            want,
            "rebuilding from canonical history must reproduce {path}'s live heads exactly"
        );
    }
    assert_index_matches_oracle(&conn, "rebuild from canonical history");
}

/// Reopening the schema over a database whose derived rows are gone
/// rebuilds them, without the caller asking. This is what makes an
/// existing database upgrade rather than silently resolve every path to
/// nothing.
#[test]
fn reopening_the_schema_rebuilds_a_missing_index() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let hroot = admit(&conn, &root);
    let (a, _) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 2)]);
    let ha = admit(&conn, &a);

    conn.execute("DELETE FROM path_live_heads", []).unwrap();
    conn.execute("DELETE FROM change_path_effects", []).unwrap();
    conn.execute("DELETE FROM change_causal_order", []).unwrap();
    conn.execute("DELETE FROM group_admission_ord", []).unwrap();

    init_dag_schema(&conn).unwrap();

    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "schema init must rebuild an index it finds missing");
    assert_eq!(heads[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "schema init rebuild");
}

/// Partial damage is caught too, not just a wholly missing index.
///
/// Deleting one live-head row leaves the index non-empty, so an
/// emptiness check would pass it. What catches it is that a group head
/// is causally maximal and must therefore be listed live on every path
/// it touches -- a head that is not is proof the frontier has drifted
/// from the history it is derived from.
#[test]
fn reopening_the_schema_rebuilds_a_partially_damaged_index() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let hroot = admit(&conn, &root);
    let (a, _) =
        change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 2), put("q.txt", 3)]);
    let ha = admit(&conn, &a);

    // Remove one path's live head, leaving every other derived row in
    // place.
    conn.execute(
        "DELETE FROM path_live_heads WHERE group_id = ?1 AND path = 'p.txt'",
        rusqlite::params![GROUP],
    )
    .unwrap();
    assert!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().is_empty(),
        "sanity: the damage must actually be visible through the read path"
    );
    assert_eq!(
        live_path_heads(&conn, GROUP, "q.txt").unwrap().len(),
        1,
        "sanity: the rest of the index must still be intact, or this proves nothing"
    );

    init_dag_schema(&conn).unwrap();

    let heads = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(heads.len(), 1, "schema init must rebuild a group whose frontier drifted");
    assert_eq!(heads[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "schema init rebuild after partial damage");
}

/// Compaction can remove a change that sits causally between two that
/// survive, and supersession has to stay visible across the gap.
///
/// Pruning is not a clean cut at a prefix. A retention root keeps one
/// change alive for its payload while the changes below it go, so a
/// still-retained head can end up on the far side of a tombstone from
/// its own descendant. Deciding supersession from live ancestry edges
/// alone would then read the two as unrelated, and the superseded head
/// would come back to life beside the change that replaced it -- content
/// the user overwrote reappearing as a conflict, caused by a prune that
/// touched neither of them.
///
/// The scenario is the smallest one that has the shape: A writes the
/// path, B does not touch it, C writes it again, and B alone is pruned
/// while A is pinned by a retention root.
#[test]
fn a_prune_that_removes_a_causal_bridge_keeps_supersession_visible() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    // The bridge: causally between the two writers of p.txt, and touching
    // a different path so it is not itself a head for p.txt.
    let (b, lb) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("bridge.txt", 2)]);
    let hb = admit(&conn, &b);
    let (c, _) = change_on(&conn, &[(&hb, lb)], "device-a", 1, vec![put("p.txt", 3)]);
    let hc = admit(&conn, &c);

    let before = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(before.len(), 1, "sanity: C must have superseded A before the prune");
    assert_eq!(before[0].change_hash, hc.0);

    // Pin A so compaction keeps it, then prune both. Only B actually goes,
    // which is what leaves a tombstone between two live changes.
    register_retention_root(
        &conn,
        "test",
        "keeps-a-alive",
        GROUP,
        &ha,
        RetentionClass::FullPayload,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(FolderGroupId(GROUP.to_string()), vec![hc], [0u8; 32]);
    commit_prune(&conn, &checkpoint, &[ha, hb]).unwrap();

    assert!(
        conn.query_row(
            "SELECT COUNT(*) FROM changes WHERE change_hash = ?1",
            rusqlite::params![&ha.0[..]],
            |r| r.get::<_, i64>(0)
        )
        .unwrap()
            == 1,
        "sanity: the retention root must have kept A retained"
    );
    assert!(
        conn.query_row(
            "SELECT COUNT(*) FROM changes WHERE change_hash = ?1",
            rusqlite::params![&hb.0[..]],
            |r| r.get::<_, i64>(0)
        )
        .unwrap()
            == 0,
        "sanity: the bridge must actually have been pruned"
    );

    // The live frontier is unchanged by a prune of something that was
    // never a head.
    let after = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(
        normalize(after),
        normalize(before),
        "pruning a change between two writers of a path must not change what that path resolves to"
    );

    // And a rebuild from what is left has to reach the same answer. This
    // is the half that actually fails when the walk cannot cross a
    // tombstone: the replay re-decides supersession from scratch, and A
    // and C look unrelated once the change between them is gone.
    rebuild_group_path_frontier(&conn, GROUP).unwrap();
    let rebuilt = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(
        rebuilt.len(),
        1,
        "rebuilding across a pruned bridge must not resurrect the superseded head"
    );
    assert_eq!(rebuilt[0].change_hash, hc.0);
}

/// A live head for a path the group's *current* head does not touch must
/// still be repaired when its row goes missing.
///
/// This is the case a check anchored on `group_heads` cannot see. A
/// path's live head is normally NOT a current group head: the group moves
/// on, later changes touch other paths, and the change that last wrote
/// this path falls behind the frontier while remaining perfectly live for
/// it. Validating only what the current heads touch therefore inspects a
/// vanishing fraction of the index -- on a 10,000-file import, one change
/// out of ten thousand -- and a row lost anywhere else is never noticed.
///
/// The consequence is silent data loss, not a visible error: the path
/// resolves to "nothing ever touched this", which reads as absent, and
/// stays that way across every subsequent startup.
#[test]
fn a_lost_live_head_is_repaired_even_when_its_path_is_not_the_current_head_s() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    // B moves the frontier on without touching p.txt, so A stops being a
    // group head while staying p.txt's live head.
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("q.txt", 2)]);
    let hb = admit(&conn, &b);

    assert_eq!(
        group_heads(&conn, GROUP).unwrap(),
        vec![hb],
        "sanity: the group's only head must be B, not A"
    );
    assert_eq!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap()[0].change_hash,
        ha.0,
        "sanity: A must still be p.txt's live head"
    );

    // Lose exactly that row. The cause does not matter -- a partial write,
    // a bug elsewhere, disk corruption -- only that the index no longer
    // agrees with the history it is derived from.
    conn.execute(
        "DELETE FROM path_live_heads WHERE group_id = ?1 AND path = 'p.txt'",
        rusqlite::params![GROUP],
    )
    .unwrap();
    assert!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().is_empty(),
        "sanity: p.txt must now resolve to nothing, which is the silent loss"
    );

    init_dag_schema(&conn).unwrap();

    let repaired = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(
        repaired.len(),
        1,
        "startup must repair a live head lost for a path no current group head touches"
    );
    assert_eq!(repaired[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "lost live head off the current frontier");
}

/// A live-head row that should have been superseded, but was not removed,
/// must be caught too.
///
/// The mirror of a lost row: an extra one. Its effect is a path that
/// resolves to two heads where one is genuinely dead, which surfaces as a
/// conflict copy of content the user already replaced -- wrong in a way
/// that is visible but inexplicable, rather than wrong in a way that is
/// invisible.
///
/// Reachable cheaply because supersession among the recorded live heads
/// is checkable directly: if one live head descends from another, the
/// ancestor was never a live head. That needs an ancestry query only for
/// paths that record more than one head, which is the conflicted minority.
#[test]
fn a_stale_live_head_that_should_have_been_superseded_is_repaired() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("p.txt", 2)]);
    let hb = admit(&conn, &b);

    assert_eq!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().len(),
        1,
        "sanity: B must have superseded A"
    );

    // Put A back as though supersession had never removed it.
    conn.execute(
        "INSERT INTO path_live_heads (group_id, path, change_hash) VALUES (?1, 'p.txt', ?2)",
        rusqlite::params![GROUP, &ha.0[..]],
    )
    .unwrap();
    assert_eq!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().len(),
        2,
        "sanity: the path must now resolve to a dead head alongside the live one"
    );

    init_dag_schema(&conn).unwrap();

    let repaired = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(repaired.len(), 1, "startup must drop a live head its own descendant supersedes");
    assert_eq!(repaired[0].change_hash, hb.0);
    assert_index_matches_oracle(&conn, "stale extra live head");
}

/// A live head whose normalized effect row is gone must fail loudly, not
/// disappear from the answer.
///
/// Resolving a path joins the recorded live heads to their effects. A
/// live head with no effect row therefore contributes nothing to the
/// result -- the path quietly resolves as though that head were not
/// there, which for a single-head path means "absent". Silence is the
/// wrong response to a row that is missing from a table nothing but this
/// code writes.
///
/// So the read reports it, and startup repairs it.
#[test]
fn a_live_head_with_no_effect_row_is_reported_and_repaired() {
    let conn = open();
    seed_versions(&conn);

    let (a, _) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);

    conn.execute(
        "DELETE FROM change_path_effects WHERE group_id = ?1 AND path = 'p.txt'",
        rusqlite::params![GROUP],
    )
    .unwrap();

    let err = live_path_heads(&conn, GROUP, "p.txt")
        .expect_err("a live head with no effect row must not read as an empty path");
    let message = err.to_string();
    assert!(
        message.contains("p.txt"),
        "the error must name the path it could not resolve, got: {message}"
    );

    init_dag_schema(&conn).unwrap();

    let repaired = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(repaired.len(), 1, "startup must rebuild an effect row it finds missing");
    assert_eq!(repaired[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "live head with no effect row");
}

/// An admitted change with no admission ordinal must be repaired.
///
/// The ordinal is what makes supersession decidable without walking
/// history, and admission fails closed when a live head has none. A
/// change missing one is therefore not a dormant inconsistency: it is a
/// future admission that cannot complete. Startup has to find it before
/// that admission does.
#[test]
fn an_admitted_change_with_no_admission_ordinal_is_repaired() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("q.txt", 2)]);
    admit(&conn, &b);

    conn.execute(
        "DELETE FROM change_causal_order WHERE change_hash = ?1",
        rusqlite::params![&ha.0[..]],
    )
    .unwrap();

    init_dag_schema(&conn).unwrap();

    let restored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM change_causal_order WHERE change_hash = ?1",
            rusqlite::params![&ha.0[..]],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(restored, 1, "startup must restore an admission ordinal it finds missing");
    assert_index_matches_oracle(&conn, "missing admission ordinal");
}

/// Two changes in one group must never hold the same admission ordinal.
///
/// Every supersession shortcut rests on the ordinal being a real linear
/// extension of the DAG. A duplicate would silently break that ordering
/// rather than fail, so the database refuses to store one at all --
/// defense in depth behind the counter, not a substitute for it.
#[test]
fn a_duplicate_admission_ordinal_is_refused_by_the_database() {
    let conn = open();
    seed_versions(&conn);

    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("q.txt", 2)]);
    let hb = admit(&conn, &b);

    let a_ord: i64 = conn
        .query_row(
            "SELECT admission_ord FROM change_causal_order WHERE change_hash = ?1",
            rusqlite::params![&ha.0[..]],
            |r| r.get(0),
        )
        .unwrap();

    let clash = conn.execute(
        "UPDATE change_causal_order SET admission_ord = ?1 WHERE change_hash = ?2",
        rusqlite::params![a_ord, &hb.0[..]],
    );
    assert!(
        clash.is_err(),
        "the database must refuse to give two changes in one group the same ordinal"
    );
}

/// Resolving a path at a historical frontier must agree with a walk of
/// canonical history seeded at that same frontier.
///
/// This covers what the live-head oracle cannot. `path_heads_at_frontier`
/// answers "what did this path look like at some earlier point", which is
/// what admission asks when it derives the conflict copies a change owes
/// -- and it now answers from the derived effects rather than by walking.
/// So it is checked here against something that still walks: every
/// frontier in the DAG, every path in the group, compared against a
/// from-scratch traversal of canonical changes.
///
/// The frontiers exercised are each change's own parents, which is
/// exactly the set admission validates against, plus the current heads.
#[test]
fn resolving_a_path_at_every_historical_frontier_agrees_with_a_walk() {
    let conn = open();
    seed_versions(&conn);

    // A DAG with every shape that makes frontier resolution non-trivial:
    // sequential edits, a fork both sides write, a merge that resolves
    // it, a delete, and a move.
    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let hroot = admit(&conn, &root);
    let (a, la) = change_on(&conn, &[(&hroot, lroot)], "device-a", 1, vec![put("p.txt", 2)]);
    let ha = admit(&conn, &a);
    let (b, lb) = change_on(&conn, &[(&hroot, lroot)], "device-b", 2, vec![put("p.txt", 3)]);
    let hb = admit(&conn, &b);
    let (m, lm) = change_on(&conn, &[(&ha, la), (&hb, lb)], "device-a", 1, vec![put("q.txt", 4)]);
    let hm = admit(&conn, &m);
    let (d, ld) = change_on(&conn, &[(&hm, lm)], "device-a", 1, vec![delete("q.txt")]);
    let hd = admit(&conn, &d);
    let (mv1, lmv) = change_on(&conn, &[(&hd, ld)], "device-a", 1, vec![mv("p.txt", "r.txt", 5)]);
    let hmv = admit(&conn, &mv1);
    let (tail, _) = change_on(&conn, &[(&hmv, lmv)], "device-c", 3, vec![put("r.txt", 6)]);
    admit(&conn, &tail);

    // Every frontier a change was ever authored against, plus the
    // group's current heads.
    let mut frontiers: Vec<Vec<ChangeHash>> = vec![
        vec![],
        vec![hroot],
        vec![ha],
        vec![hb],
        vec![ha, hb],
        vec![hm],
        vec![hd],
        vec![hmv],
        group_heads(&conn, GROUP).unwrap(),
    ];
    frontiers.dedup();

    for path in all_paths(&conn, GROUP) {
        for frontier in &frontiers {
            let resolved =
                normalize(path_heads_at_frontier(&conn, GROUP, &path, frontier).unwrap());
            let walked = normalize(history_walk_at_frontier(&conn, &path, frontier));
            assert_eq!(
                resolved, walked,
                "resolving {path} at frontier {frontier:?} disagrees with a walk of canonical \
                 history seeded at the same frontier"
            );
        }
    }
}

/// Losing an effect row and its live head together leaves an index that
/// is perfectly self-consistent and simply missing a file.
///
/// Every structural check passes: the group still has effects, the path
/// is not in the effects table so nothing expects a live head for it,
/// there is no orphaned live row, the ordinals are intact, and no path
/// records two heads. Nothing about the shape of the remaining rows is
/// wrong. What is wrong is that they no longer say what the changes they
/// were derived from say -- and the only way to notice is to ask the
/// changes.
///
/// The file is simply gone, permanently, with no error anywhere.
#[test]
fn an_effect_and_its_live_head_lost_together_are_still_caught() {
    let conn = open();
    seed_versions(&conn);

    // A touches two paths, so removing one of them leaves the other
    // behind and the index still looks populated.
    let (a, la) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1), put("r.txt", 2)]);
    let ha = admit(&conn, &a);
    let (b, _) = change_on(&conn, &[(&ha, la)], "device-a", 1, vec![put("q.txt", 3)]);
    admit(&conn, &b);

    conn.execute(
        "DELETE FROM change_path_effects WHERE group_id = ?1 AND path = 'p.txt'",
        rusqlite::params![GROUP],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM path_live_heads WHERE group_id = ?1 AND path = 'p.txt'",
        rusqlite::params![GROUP],
    )
    .unwrap();

    // The damage is invisible to every check that reasons about row
    // shape: what is left is entirely self-consistent.
    assert!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap().is_empty(),
        "sanity: p.txt must currently resolve as though it never existed"
    );
    assert_eq!(
        live_path_heads(&conn, GROUP, "r.txt").unwrap().len(),
        1,
        "sanity: the rest of the same change's effects must be untouched"
    );
    assert_eq!(
        live_path_heads(&conn, GROUP, "q.txt").unwrap().len(),
        1,
        "sanity: the group must still look populated"
    );

    init_dag_schema(&conn).unwrap();

    let repaired = live_path_heads(&conn, GROUP, "p.txt").unwrap();
    assert_eq!(repaired.len(), 1, "startup must restore a path lost with its own effect row");
    assert_eq!(repaired[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "effect and live head lost together");
}

/// An effect row that disagrees with its change's ops must be corrected,
/// not trusted.
///
/// The same class as the test above, in its other form: the row is
/// present and structurally fine, but says the wrong thing. Left alone it
/// makes the path resolve to content the change never wrote.
#[test]
fn an_effect_row_that_contradicts_its_change_is_rebuilt() {
    let conn = open();
    seed_versions(&conn);

    let (a, _) = change_on(&conn, &[], "device-a", 1, vec![put("p.txt", 1)]);
    let ha = admit(&conn, &a);
    let genuine =
        live_path_heads(&conn, GROUP, "p.txt").unwrap()[0].content.as_ref().unwrap().version_hash;

    // Point the effect at a different version than the change's op does.
    conn.execute(
        "UPDATE change_path_effects SET version_hash = ?1 WHERE group_id = ?2 AND path = 'p.txt'",
        rusqlite::params![&version_hash(9).0[..], GROUP],
    )
    .unwrap();
    assert_ne!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap()[0].content.as_ref().unwrap().version_hash,
        genuine,
        "sanity: the path must currently resolve to content its change never wrote"
    );

    init_dag_schema(&conn).unwrap();

    assert_eq!(
        live_path_heads(&conn, GROUP, "p.txt").unwrap()[0].content.as_ref().unwrap().version_hash,
        genuine,
        "startup must restore the effect its change's ops actually describe"
    );
    assert_eq!(live_path_heads(&conn, GROUP, "p.txt").unwrap()[0].change_hash, ha.0);
    assert_index_matches_oracle(&conn, "effect row contradicting its change");
}

/// A long mostly-linear history with periodic forks and merges, plus
/// repeated edits to a small set of paths. This is the shape real use
/// produces, and the one where an incremental rule that is subtly wrong
/// has the most opportunity to drift away from the truth unnoticed.
#[test]
fn a_long_mixed_history_stays_in_agreement_throughout() {
    let conn = open();
    seed_versions(&conn);

    let (root, lroot) = change_on(&conn, &[], "device-a", 1, vec![put("seed.txt", 0)]);
    let mut tip = admit(&conn, &root);
    let mut tip_lamport = lroot;

    for round in 0..12u8 {
        let path = format!("p{}.txt", round % 4);
        if round % 3 == 2 {
            // Fork, both sides writing the same path, then merge through
            // a path neither side touched.
            let (a, la) = change_on(
                &conn,
                &[(&tip, tip_lamport)],
                "device-a",
                1,
                vec![put(&path, round + 1)],
            );
            let ha = admit(&conn, &a);
            let (b, lb) = change_on(
                &conn,
                &[(&tip, tip_lamport)],
                "device-b",
                2,
                vec![put(&path, round + 2)],
            );
            let hb = admit(&conn, &b);
            assert_index_matches_oracle(&conn, &format!("mixed history, round {round} forked"));

            let (m, lm) = change_on(
                &conn,
                &[(&ha, la), (&hb, lb)],
                "device-a",
                1,
                vec![put(&format!("merge{round}.txt"), round + 3)],
            );
            tip = admit(&conn, &m);
            tip_lamport = lm;
        } else {
            let ops = if round % 5 == 4 {
                vec![delete(&path)]
            } else if round % 7 == 6 {
                vec![mv(&path, &format!("{path}.moved"), round + 1)]
            } else {
                vec![put(&path, round + 1)]
            };
            let (c, l) = change_on(&conn, &[(&tip, tip_lamport)], "device-a", 1, ops);
            tip = admit(&conn, &c);
            tip_lamport = l;
        }
        assert_index_matches_oracle(&conn, &format!("mixed history, round {round}"));
    }

    check(&conn, "long mixed history");
}
