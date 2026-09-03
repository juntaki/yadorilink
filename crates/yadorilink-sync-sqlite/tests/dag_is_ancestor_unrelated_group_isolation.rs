//! The decisive attribution test for the 2026-09-02 100k acceptance-run
//! failure: does `is_ancestor`'s cost for a FIXED-size target group's own
//! history grow as a completely UNRELATED group's history grows? If yes,
//! that directly proves the un-scoped edge-set query is the mechanism (a
//! correctly group-scoped query would be indifferent to unrelated-group
//! size entirely). `#[ignore]`d (prints, not a pass/fail gate) -- run
//! explicitly with `--ignored --nocapture --test-threads=1`.

use rusqlite::Connection;
use std::time::Instant;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sync_sqlite::dag_store::{init_dag_schema, is_ancestor};

fn seed_linear_chain(conn: &Connection, group_id: &str, seed: u64, n: u64) -> Vec<ChangeHash> {
    let mut hashes: Vec<ChangeHash> = Vec::with_capacity(n as usize);
    let tx = conn.unchecked_transaction().unwrap();
    for i in 0..n {
        let mut h = [0u8; 32];
        h[0..8].copy_from_slice(&seed.to_le_bytes());
        h[8..16].copy_from_slice(&i.to_le_bytes());
        let hash = ChangeHash(h);
        tx.execute(
            "INSERT INTO changes (group_id, change_hash, device_id, lamport, applied, encoded) \
             VALUES (?1, ?2, 'bench-device', ?3, 1, x'')",
            rusqlite::params![group_id, &hash.0[..], i as i64 + 1],
        )
        .unwrap();
        if i > 0 {
            tx.execute(
                "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                rusqlite::params![&hash.0[..], &hashes[(i - 1) as usize].0[..]],
            )
            .unwrap();
        }
        hashes.push(hash);
    }
    tx.commit().unwrap();
    hashes
}

/// The pre-fix query shape verbatim (the original `edges(child_hash,
/// parent_hash) AS (... UNION ...)` CTE, unioning the FULL `change_parents`
/// and `pruned_change_parents` tables up front regardless of group), kept
/// here only as the RED baseline for this measurement -- `is_ancestor`
/// itself no longer has this shape.
fn is_ancestor_old_shape(
    conn: &Connection,
    ancestor: &ChangeHash,
    descendant: &ChangeHash,
) -> bool {
    conn.query_row(
        "WITH RECURSIVE
           edges(child_hash, parent_hash) AS (
             SELECT child_hash, parent_hash FROM change_parents
             UNION
             SELECT child_hash, parent_hash FROM pruned_change_parents
           ),
           ancestry(hash) AS (
             SELECT parent_hash FROM edges WHERE child_hash = ?1
             UNION
             SELECT edges.parent_hash
             FROM edges JOIN ancestry ON edges.child_hash = ancestry.hash
           )
         SELECT EXISTS(SELECT 1 FROM ancestry WHERE hash = ?2)",
        rusqlite::params![&descendant.0[..], &ancestor.0[..]],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
#[ignore = "attribution measurement, not a correctness test -- run explicitly, see module doc comment"]
fn is_ancestor_old_shape_for_a_fixed_target_group_as_an_unrelated_group_grows_red_baseline() {
    const TARGET_SIZE: u64 = 1_000;
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    let target = seed_linear_chain(&conn, "target-group", 1, TARGET_SIZE);
    let target_newest = target[(TARGET_SIZE - 1) as usize];
    let target_immediate_parent = target[(TARGET_SIZE - 2) as usize];

    println!(
        "RED baseline (pre-fix query shape): target group fixed at {TARGET_SIZE} changes; \
         measuring is_ancestor(immediate_parent, newest) for the TARGET group as an UNRELATED \
         group grows"
    );
    let mut unrelated_total: u64 = 0;
    for unrelated_batch in [1_000u64, 4_000, 10_000, 15_000, 30_000] {
        seed_linear_chain(&conn, "unrelated-group", 2 + unrelated_total, unrelated_batch);
        unrelated_total += unrelated_batch;

        let t = Instant::now();
        let found = is_ancestor_old_shape(&conn, &target_immediate_parent, &target_newest);
        let elapsed = t.elapsed();
        assert!(found);
        println!(
            "unrelated_group_total={unrelated_total:>7}  \
             is_ancestor_OLD(target_immediate_parent, target_newest)={elapsed:>10.2?}"
        );
    }
}

#[test]
#[ignore = "attribution measurement, not a correctness test -- run explicitly, see module doc comment"]
fn is_ancestor_for_a_fixed_target_group_as_an_unrelated_group_grows() {
    const TARGET_SIZE: u64 = 1_000;
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();

    // Seed the target group ONCE, fixed at 1,000 changes -- never touched
    // again after this.
    let target = seed_linear_chain(&conn, "target-group", 1, TARGET_SIZE);
    let target_newest = target[(TARGET_SIZE - 1) as usize];
    let target_immediate_parent = target[(TARGET_SIZE - 2) as usize];

    println!(
        "target group fixed at {TARGET_SIZE} changes; measuring is_ancestor(immediate_parent, \
         newest) for the TARGET group as an UNRELATED group grows"
    );
    let mut unrelated_total: u64 = 0;
    for unrelated_batch in [1_000u64, 4_000, 10_000, 15_000, 30_000, 40_000] {
        seed_linear_chain(&conn, "unrelated-group", 2 + unrelated_total, unrelated_batch);
        unrelated_total += unrelated_batch;

        let t = Instant::now();
        let found = is_ancestor(&conn, &target_immediate_parent, &target_newest).unwrap();
        let elapsed = t.elapsed();
        assert!(found);
        println!(
            "unrelated_group_total={unrelated_total:>7}  \
             is_ancestor(target_immediate_parent, target_newest)={elapsed:>10.2?}"
        );
    }
}

/// Deterministic regression guard (not ignored): the same "unrelated
/// group's size must not affect the target group's `is_ancestor` cost"
/// property, but specifically for `pruned_change_parents` -- the table
/// `change_parents` has no supporting index for a bare `child_hash`
/// lookup would fall back to a full scan without
/// `pruned_change_parents_by_child`. Inserted directly (not via real
/// compaction machinery, which is irrelevant to what this measures).
#[test]
fn is_ancestor_is_not_slowed_by_an_unrelated_groups_pruned_history() {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();

    let target = seed_linear_chain(&conn, "target-group", 1, 100);
    let target_newest = target[98];
    let target_immediate_parent = target[97];

    // A large, entirely unrelated group's worth of pruned (compacted)
    // history -- 20,000 rows, none of which share a group_id or hash with
    // the target group at all.
    let tx = conn.unchecked_transaction().unwrap();
    for i in 0..20_000u64 {
        let mut child = [0u8; 32];
        child[16..24].copy_from_slice(&i.to_le_bytes());
        let mut parent = [0u8; 32];
        parent[16..24].copy_from_slice(&(i + 1).to_le_bytes());
        tx.execute(
            "INSERT INTO pruned_change_parents (group_id, child_hash, parent_hash, checkpoint_hash) \
             VALUES ('unrelated-pruned-group', ?1, ?2, x'0000000000000000000000000000000000000000000000000000000000000000')",
            rusqlite::params![&child[..], &parent[..]],
        )
        .unwrap();
    }
    tx.commit().unwrap();

    let t = Instant::now();
    let found = is_ancestor(&conn, &target_immediate_parent, &target_newest).unwrap();
    let elapsed = t.elapsed();

    assert!(found, "sanity: the immediate parent must be reported as an ancestor");
    assert!(
        elapsed.as_millis() < 5,
        "is_ancestor took {elapsed:?} with 20,000 unrelated pruned_change_parents rows present \
         -- expected sub-millisecond; a lookup for the TARGET group's own immediate parent must \
         not scale with an unrelated group's compacted history size. See \
         pruned_change_parents_by_child's own doc comment."
    );
}
