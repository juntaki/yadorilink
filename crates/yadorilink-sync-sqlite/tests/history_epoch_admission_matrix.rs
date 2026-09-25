//! The admission matrix, stated once in the same words the design
//! states it.
//!
//! `dag_author_chain_red.rs` already pins each of these outcomes across
//! many edge cases, from the angle of the author chain's own admission
//! surface. This file is deliberately smaller and reads the other way:
//! one test per row of the plan's four-way matrix, so the matrix itself
//! -- not its edge cases -- has a single place that fails if production
//! ever disagrees with it.
//!
//! ```text
//! missing DAG parent          -> DAG orphan
//! missing author_prev         -> author dependency hold
//! known contradictory prev    -> reject
//! exact next predecessor      -> admit
//! ```
//!
//! "DAG orphan" and "author dependency hold" are the same
//! [`AdmitOutcome::Orphaned`] at the outcome level -- there is one
//! buffer, not two -- but they are distinguishable rows even so: a DAG
//! orphan is missing a `change_parents` edge, an author hold is missing
//! nothing from `change_parents` and is instead keyed by
//! `orphan_changes.author_prev_hash`. Each test below checks its own row
//! by that distinction, not merely by the shared outcome.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;
use yadorilink_sync_sqlite::dag_store::{
    admit_change, init_dag_schema, AdmitOutcome, AuthorChainRefusal,
};

const GROUP: &str = "admission-matrix-group";

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn key(device: u8) -> SigningKey {
    SigningKey::from_bytes(&[device; 32])
}

/// A `Delete`-only change: admission of the author chain and the DAG is
/// the only thing under test in this file, so nothing here needs a file
/// version or a block store.
fn change(device: u8, seq: u64, prev: Option<&Change>, parents: &[&Change], path: &str) -> Change {
    let mut parent_hashes: Vec<ChangeHash> = parents.iter().map(|p| p.compute_hash()).collect();
    parent_hashes.sort();
    let max_parent_lamport = parents.iter().map(|p| p.lamport).max().unwrap_or(0);
    Change::create_signed(
        parent_hashes,
        max_parent_lamport,
        DeviceId(format!("device-{device}")),
        AuthorSeq(seq),
        prev.map(Change::compute_hash),
        FolderGroupId(GROUP.to_owned()),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath(path.to_owned()) }],
        &key(device),
    )
}

fn admit(conn: &Connection, change: &Change) -> AdmitOutcome {
    admit_change(conn, change).unwrap().outcome
}

fn is_missing_a_dag_parent_edge(conn: &Connection, orphan: &ChangeHash) -> bool {
    // A DAG orphan's own `change_parents` row names a hash the store does
    // not hold -- that IS the thing it is waiting on.
    let missing: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM change_parents cp \
             WHERE cp.child_hash = ?1 \
               AND NOT EXISTS (SELECT 1 FROM changes c WHERE c.change_hash = cp.parent_hash)",
            [&orphan.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    missing > 0
}

fn is_buffered_waiting_on_author_prev(conn: &Connection, orphan: &ChangeHash) -> bool {
    let waiting: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM orphan_changes o \
             WHERE o.change_hash = ?1 AND o.author_prev_hash IS NOT NULL",
            [&orphan.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    waiting > 0
}

/// Row 1: `missing DAG parent -> DAG orphan`.
///
/// Every DAG parent absent. The change is not early on its own author's
/// chain -- it is the group's first change from this device -- so
/// nothing but the missing causal parent explains the hold.
#[test]
fn missing_dag_parent_is_a_dag_orphan() {
    let conn = conn();
    let unseen_parent = change(1, 1, None, &[], "parent.bin");
    let child = change(2, 1, None, &[&unseen_parent], "child.bin");

    let outcome = admit(&conn, &child);
    assert!(matches!(outcome, AdmitOutcome::Orphaned), "expected a DAG orphan, got {outcome:?}");
    assert!(
        is_missing_a_dag_parent_edge(&conn, &child.compute_hash()),
        "the hold must be explained by a missing change_parents edge"
    );
}

/// Row 2: `missing author_prev -> author dependency hold`.
///
/// Every DAG parent present; only this author's own predecessor is
/// missing. The plan is explicit that this is NOT the same as a missing
/// DAG parent and must not be reported as one (`author_prev` is an
/// identity link, not causal ancestry) -- it reuses the same buffer
/// without being one.
#[test]
fn missing_author_prev_is_an_author_dependency_hold() {
    let conn = conn();
    let a1 = change(1, 1, None, &[], "doc.txt");
    assert!(matches!(admit(&conn, &a1), AdmitOutcome::Applied));

    // a2 is never delivered. a3 is parented on a1 (a DAG parent it has),
    // and names a2 as its author's predecessor (a name it does not).
    let a2 = change(1, 2, Some(&a1), &[&a1], "other.txt");
    let a3 = change(1, 3, Some(&a2), &[&a1], "doc.txt");

    let outcome = admit(&conn, &a3);
    assert!(matches!(outcome, AdmitOutcome::Orphaned), "expected a hold, got {outcome:?}");
    assert!(
        !is_missing_a_dag_parent_edge(&conn, &a3.compute_hash()),
        "every DAG parent is already present; nothing there is missing"
    );
    assert!(
        is_buffered_waiting_on_author_prev(&conn, &a3.compute_hash()),
        "the hold must be keyed by the missing author_prev, not a DAG parent"
    );
}

/// Row 3: `known contradictory prev -> reject`.
///
/// The gap is decided, not merely early: `a3` names `a1` as its
/// predecessor while this replica already holds `a2` as this author's
/// actual tip at `seq == W + 1`. No later delivery can make that
/// consistent, so it is refused rather than held.
#[test]
fn known_contradictory_author_prev_is_rejected() {
    let conn = conn();
    let a1 = change(1, 1, None, &[], "a.txt");
    assert!(matches!(admit(&conn, &a1), AdmitOutcome::Applied));
    let a2 = change(1, 2, Some(&a1), &[&a1], "b.txt");
    assert!(matches!(admit(&conn, &a2), AdmitOutcome::Applied));

    // Every DAG parent (a1) is present, and W + 1 == 3, but a3 names a1
    // rather than a2 as its predecessor -- a contradiction this replica
    // can already see, not an absence.
    let a3 = change(1, 3, Some(&a1), &[&a1], "c.txt");

    let outcome = admit(&conn, &a3);
    assert!(
        matches!(
            outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "expected a rejection, got {outcome:?}"
    );
}

/// Row 4: `exact next predecessor -> admit`.
///
/// `seq == W + 1` and `author_prev` names the stored tip exactly: the
/// ordinary case, admitted outright.
#[test]
fn exact_next_predecessor_is_admitted() {
    let conn = conn();
    let a1 = change(1, 1, None, &[], "a.txt");
    assert!(matches!(admit(&conn, &a1), AdmitOutcome::Applied));

    let a2 = change(1, 2, Some(&a1), &[&a1], "b.txt");
    let outcome = admit(&conn, &a2);
    assert!(matches!(outcome, AdmitOutcome::Applied), "expected admission, got {outcome:?}");
}
