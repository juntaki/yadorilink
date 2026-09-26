#![cfg(test)]
//! `history_base_named_heads` is derived state: which base heads the
//! current epoch has named is a fact of the retained changes' signed
//! `observed_base_heads` (and, for a change a checkpoint pruned, of the
//! record it left). A row lost or added behind the store's back must be
//! caught by the startup check and put right by the rebuild, as every
//! other derived path-frontier table is.

use super::base_install_tests::open;
use super::seal_tests::{build_history, key, put, seal, store_versions, version, History, GROUP};
use super::*;
use yadorilink_replica_domain::change::ChangePurpose;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};

struct Named {
    /// Writes `r` on the base, naming `A3` (seen) but not `B2`.
    x: Change,
    /// Writes `q` on the base, naming nothing: `C1` stays live beside it.
    y: Change,
    h: History,
}

fn on_base_observing(
    base: HistoryBase,
    device: &str,
    seq: u64,
    clocked_from: u64,
    observed: Vec<ChangeHash>,
    ops: Vec<Op>,
) -> Change {
    Change::create_signed_observing(
        Vec::new(),
        clocked_from,
        DeviceId(device.to_string()),
        AuthorSeq(seq),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Base(base),
        ChangePurpose::Ordinary,
        None,
        observed,
        ops,
        &key(device),
    )
}

/// After the seal the base carries `r -> {A3, B2}` and `q -> C1`.
fn named_history(conn: &Connection) -> Named {
    let h = build_history(conn);
    let base = seal(conn).history_base();
    store_versions(conn);
    let x = on_base_observing(
        base,
        "device-b",
        h.b2.author_seq.get() + 1,
        h.c1.lamport,
        vec![h.a3.compute_hash()],
        vec![put("r", &version(5))],
    );
    crate::dag_store::admit_change(conn, &x).unwrap();
    let y = on_base_observing(
        base,
        "device-c",
        h.c1.author_seq.get() + 1,
        h.c1.lamport,
        Vec::new(),
        vec![put("q", &version(6))],
    );
    crate::dag_store::admit_change(conn, &y).unwrap();
    let named = Named { x, y, h };
    assert_eq!(live(conn, "r"), sorted_hashes(vec![&named.x, &named.h.b2]));
    assert_eq!(live(conn, "q"), sorted_hashes(vec![&named.y, &named.h.c1]));
    named
}

fn live(conn: &Connection, path: &str) -> Vec<ChangeHash> {
    let mut heads: Vec<ChangeHash> = crate::dag_store::live_path_heads(conn, GROUP, path)
        .unwrap()
        .into_iter()
        .map(|head| ChangeHash(head.change_hash))
        .collect();
    heads.sort();
    heads
}

fn sorted_hashes(changes: Vec<&Change>) -> Vec<ChangeHash> {
    let mut hashes: Vec<ChangeHash> = changes.into_iter().map(Change::compute_hash).collect();
    hashes.sort();
    hashes
}

fn insert_named(conn: &Connection, path: &str, head: &ChangeHash, naming: &ChangeHash) {
    conn.execute(
        "INSERT INTO history_base_named_heads (group_id, path, change_hash, naming_change) \
         VALUES (?1, ?2, ?3, ?4)",
        params![GROUP, path, &head.0[..], &naming.0[..]],
    )
    .unwrap();
}

/// A lost row would make a base head the epoch superseded live again. The
/// startup check finds the change whose names are no longer all recorded,
/// and the rebuild records them again.
#[test]
fn a_lost_name_is_restored_at_startup() {
    let conn = open();
    let n = named_history(&conn);
    let a3 = n.h.a3.compute_hash();
    conn.execute(
        "DELETE FROM history_base_named_heads WHERE group_id = ?1 AND path = 'r' \
         AND change_hash = ?2",
        params![GROUP, &a3.0[..]],
    )
    .unwrap();
    assert!(live(&conn, "r").contains(&a3), "the lost row resurrects A3 at r");

    crate::dag_store::init_dag_schema(&conn).unwrap();

    assert_eq!(live(&conn, "r"), sorted_hashes(vec![&n.x, &n.h.b2]));
}

/// A spurious row, whatever change it claims named the head, would leave a
/// base head superseded forever. The startup check finds it and the
/// rebuild drops it: the head is live again.
#[test]
fn a_spurious_name_is_dropped_at_startup() {
    let bogus = ChangeHash([0x77; 32]);
    for attribute_to_retained in [true, false] {
        let conn = open();
        let n = named_history(&conn);
        let c1 = n.h.c1.compute_hash();
        let naming = if attribute_to_retained { n.y.compute_hash() } else { bogus };
        insert_named(&conn, "q", &c1, &naming);
        assert_eq!(live(&conn, "q"), vec![n.y.compute_hash()], "the spurious row buries C1");

        crate::dag_store::init_dag_schema(&conn).unwrap();

        assert_eq!(
            live(&conn, "q"),
            sorted_hashes(vec![&n.y, &n.h.c1]),
            "attributed to a retained change: {attribute_to_retained}"
        );
    }
}

/// The rebuild on its own clears the group's names and recomputes them,
/// rather than only adding to what is there.
#[test]
fn a_rebuild_recomputes_the_names_rather_than_adding_to_them() {
    let conn = open();
    let n = named_history(&conn);
    let c1 = n.h.c1.compute_hash();
    insert_named(&conn, "q", &c1, &n.y.compute_hash());
    conn.execute(
        "DELETE FROM history_base_named_heads WHERE group_id = ?1 AND path = 'r'",
        params![GROUP],
    )
    .unwrap();

    let tx = conn.unchecked_transaction().unwrap();
    crate::dag_store::path_frontier::rebuild_group(&tx, GROUP).unwrap();
    tx.commit().unwrap();

    assert_eq!(live(&conn, "q"), sorted_hashes(vec![&n.y, &n.h.c1]));
    assert_eq!(live(&conn, "r"), sorted_hashes(vec![&n.x, &n.h.b2]));
}

/// A name a pruned change recorded is kept by the rebuild: its signed
/// bytes are gone, and with them the only way to derive it again.
#[test]
fn a_name_a_pruned_change_recorded_survives_a_rebuild() {
    let conn = open();
    let n = named_history(&conn);
    let x = n.x.compute_hash();
    let a3 = n.h.a3.compute_hash();
    let y = n.y.compute_hash();
    let checkpoint = Checkpoint::new(FolderGroupId(GROUP.to_string()), vec![y], [0x42; 32]);
    let tx = conn.unchecked_transaction().unwrap();
    crate::dag_store::commit_prune(&tx, &checkpoint, &[x]).unwrap();
    tx.commit().unwrap();
    assert!(!crate::dag_store::has_change(&conn, &x).unwrap(), "X was pruned");

    crate::dag_store::init_dag_schema(&conn).unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    crate::dag_store::path_frontier::rebuild_group(&tx, GROUP).unwrap();
    tx.commit().unwrap();

    let named: bool = conn
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM history_base_named_heads \
             WHERE group_id = ?1 AND path = 'r' AND change_hash = ?2)",
            params![GROUP, &a3.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert!(named, "the pruned X's name of A3 at r is kept");
}
