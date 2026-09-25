#![cfg(test)]

use super::*;

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_causal_basis_schema(&conn).unwrap();
    conn
}

fn h(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

#[test]
fn same_frontier_interns_to_the_same_basis_id_regardless_of_input_order() {
    let conn = open();
    let a = intern_causal_basis(&conn, "g", &[h(1), h(2), h(3)]).unwrap();
    let b = intern_causal_basis(&conn, "g", &[h(3), h(1), h(2)]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn duplicate_members_in_the_input_do_not_change_the_basis_id() {
    let conn = open();
    let a = intern_causal_basis(&conn, "g", &[h(1), h(2)]).unwrap();
    let b = intern_causal_basis(&conn, "g", &[h(1), h(1), h(2), h(2)]).unwrap();
    assert_eq!(a, b);
}

#[test]
fn a_million_paths_sharing_one_frontier_create_one_basis_row() {
    let conn = open();
    let frontier = [h(1), h(2), h(3)];
    for _ in 0..1000 {
        intern_causal_basis(&conn, "g", &frontier).unwrap();
    }
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM causal_basis_sets", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1, "interning the same frontier repeatedly must dedup to one row");
}

#[test]
fn different_groups_with_the_same_member_hashes_intern_separately() {
    let conn = open();
    let a = intern_causal_basis(&conn, "g1", &[h(1)]).unwrap();
    let b = intern_causal_basis(&conn, "g2", &[h(1)]).unwrap();
    assert_ne!(a, b, "the same change hash under a different group must be a distinct basis");
}

#[test]
fn lookup_returns_the_exact_ascending_member_set() {
    let conn = open();
    let basis_id = intern_causal_basis(&conn, "g", &[h(3), h(1), h(2)]).unwrap();
    let members = lookup_causal_basis_members(&conn, &basis_id).unwrap().unwrap();
    assert_eq!(members, vec![h(1), h(2), h(3)]);
}

#[test]
fn lookup_of_an_unknown_basis_id_is_none() {
    let conn = open();
    assert!(lookup_causal_basis_members(&conn, "g:deadbeef").unwrap().is_none());
}

#[test]
fn an_empty_frontier_interns_to_a_stable_basis_with_no_members() {
    let conn = open();
    let basis_id = intern_causal_basis(&conn, "g", &[]).unwrap();
    let members = lookup_causal_basis_members(&conn, &basis_id).unwrap().unwrap();
    assert!(members.is_empty());
}
