//! Correctness coverage for `is_ancestor`'s query shape (no eager `edges`
//! UNION materialization, for performance at scale). The existing basic positive/negative pair
//! (`dag_store::mod.rs`'s admission-path test) already covers the
//! ordinary single-parent case; this file covers the two shapes whose
//! querying that design affects: a genuine branch/merge
//! (multiple parents) and a walk that must cross the pruned/compacted
//! history boundary (`pruned_change_parents`, now queried as its own
//! `UNION ALL` arm instead of pre-unioned into `change_parents`).

use rusqlite::Connection;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sync_sqlite::dag_store::{init_dag_schema, is_ancestor};

fn hash(tag: u8, i: u64) -> ChangeHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_le_bytes());
    ChangeHash(h)
}

/// `author_seq` is passed separately from `lamport` because the two are
/// different things and the store now enforces it: a change's dot is
/// `(group_id, device_id, author_seq)` and no two changes of one author may
/// share it, while concurrent siblings routinely share a Lamport clock.
fn insert_change(conn: &Connection, group_id: &str, h: &ChangeHash, author_seq: i64, lamport: i64) {
    conn.execute(
        "INSERT INTO changes \
         (group_id, change_hash, device_id, author_seq, lamport, encoded) \
         VALUES (?1, ?2, 'test-device', ?3, ?4, x'')",
        rusqlite::params![group_id, &h.0[..], author_seq, lamport],
    )
    .unwrap();
}

fn insert_edge(conn: &Connection, child: &ChangeHash, parent: &ChangeHash) {
    conn.execute(
        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
        rusqlite::params![&child.0[..], &parent.0[..]],
    )
    .unwrap();
}

/// A genuine merge: `root -> a -> merge` and `root -> b -> merge`, i.e.
/// `merge` has two parents (`a` and `b`), each descending independently
/// from `root`. `is_ancestor(root, merge)` must be true via EITHER branch,
/// and neither branch's own supersession by a match on the other should
/// suppress exploring it (each branch is independent).
#[test]
fn is_ancestor_finds_a_common_ancestor_through_either_branch_of_a_merge() {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    let group = "merge-group";
    let root = hash(1, 0);
    let a = hash(1, 1);
    let b = hash(1, 2);
    let merge = hash(1, 3);
    let unrelated = hash(1, 4);

    insert_change(&conn, group, &root, 1, 1);
    insert_change(&conn, group, &a, 2, 2);
    insert_change(&conn, group, &b, 3, 2);
    insert_change(&conn, group, &merge, 4, 3);
    insert_change(&conn, group, &unrelated, 5, 1);
    insert_edge(&conn, &a, &root);
    insert_edge(&conn, &b, &root);
    insert_edge(&conn, &merge, &a);
    insert_edge(&conn, &merge, &b);

    assert!(
        is_ancestor(&conn, &root, &merge).unwrap(),
        "root must reach merge through either branch"
    );
    assert!(is_ancestor(&conn, &a, &merge).unwrap(), "a is merge's direct parent");
    assert!(is_ancestor(&conn, &b, &merge).unwrap(), "b is merge's direct parent");
    assert!(
        !is_ancestor(&conn, &a, &b).unwrap(),
        "a and b are siblings, neither descends from the other"
    );
    assert!(!is_ancestor(&conn, &b, &a).unwrap());
    assert!(
        !is_ancestor(&conn, &unrelated, &merge).unwrap(),
        "an unrelated root change is not an ancestor"
    );
    assert!(!is_ancestor(&conn, &merge, &root).unwrap(), "ancestry is strictly one-directional");
}

/// A chain whose oldest portion has been compacted: `root -> mid` lives
/// only in `pruned_change_parents` (as a real compaction would leave it),
/// while `mid -> newest` remains live in `change_parents`. `is_ancestor`
/// must cross that boundary to correctly answer both a query entirely
/// within live history and one that requires the pruned edge.
#[test]
fn is_ancestor_crosses_the_pruned_history_boundary() {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    let group = "prune-boundary-group";
    let root = hash(2, 0);
    let mid = hash(2, 1);
    let newest = hash(2, 2);

    // `root` itself is compacted away (no `changes` row for it -- the
    // whole point of a pruned tombstone), `mid`/`newest` remain live.
    insert_change(&conn, group, &mid, 2, 2);
    insert_change(&conn, group, &newest, 3, 3);
    insert_edge(&conn, &newest, &mid); // live edge
    conn.execute(
        "INSERT INTO pruned_change_parents (group_id, child_hash, parent_hash, checkpoint_hash) \
         VALUES (?1, ?2, ?3, x'0000000000000000000000000000000000000000000000000000000000000000')",
        rusqlite::params![group, &mid.0[..], &root.0[..]],
    )
    .unwrap();

    assert!(
        is_ancestor(&conn, &root, &newest).unwrap(),
        "a pruned ancestor reachable only through pruned_change_parents must still be found"
    );
    assert!(
        is_ancestor(&conn, &mid, &newest).unwrap(),
        "sanity: the live edge alone must also resolve"
    );
    assert!(
        !is_ancestor(&conn, &newest, &root).unwrap(),
        "ancestry is strictly one-directional across the boundary too"
    );
}
