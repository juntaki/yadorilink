#![cfg(test)]

use super::*;
use std::sync::Arc;

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn a_prepared_snapshot_is_collectable_by_its_group_and_hash() {
    let store = PreparedSnapshots::new();
    store.prepare("g", hash(1), Arc::new(vec![7u8; 16]));
    assert_eq!(store.take_for("g", &hash(1)).as_deref(), Some(&vec![7u8; 16]));
}

/// The hash is in a signed manifest the peer already holds, so it is not
/// a secret and must not act as one. A hello for another group reaches
/// nothing, even with the right hash.
#[test]
fn another_groups_hello_cannot_reach_it_even_with_the_right_hash() {
    let store = PreparedSnapshots::new();
    store.prepare("g", hash(1), Arc::new(vec![7u8; 16]));
    assert!(store.take_for("other", &hash(1)).is_none());
}

#[test]
fn preparing_the_same_snapshot_twice_costs_one_entry() {
    let store = PreparedSnapshots::new();
    store.prepare("g", hash(1), Arc::new(vec![0u8; 1024]));
    store.prepare("g", hash(1), Arc::new(vec![0u8; 1024]));
    assert_eq!(store.held_count(), 1);
    assert_eq!(store.held_bytes(), 1024);
}

/// Asking for manifests and never collecting must not accumulate. Both
/// budgets hold, and the oldest goes first.
#[test]
fn uncollected_work_is_bounded_by_count_and_by_bytes() {
    let store = PreparedSnapshots::with_bounds(Duration::from_secs(300), 4096, 2);
    for i in 0..8u8 {
        store.prepare("g", hash(i), Arc::new(vec![0u8; 1024]));
    }
    assert!(store.held_count() <= 2);
    assert!(store.held_bytes() <= 4096);
    assert!(store.take_for("g", &hash(0)).is_none(), "the oldest must have been evicted");

    let store = PreparedSnapshots::with_bounds(Duration::from_secs(300), 2048, 100);
    for i in 0..8u8 {
        store.prepare("g", hash(i), Arc::new(vec![0u8; 1024]));
    }
    assert!(store.held_bytes() <= 2048);
}

#[test]
fn a_prepared_snapshot_expires() {
    let store = PreparedSnapshots::with_bounds(Duration::from_millis(1), 1 << 20, 16);
    store.prepare("g", hash(1), Arc::new(vec![0u8; 16]));
    std::thread::sleep(Duration::from_millis(5));
    assert!(store.take_for("g", &hash(1)).is_none());
    assert_eq!(store.held_bytes(), 0);
}

/// A restart loses everything here, and that is the intended semantics:
/// a fresh store serves nothing, and the requester starts over.
#[test]
fn nothing_survives_a_restart() {
    let store = PreparedSnapshots::new();
    store.prepare("g", hash(1), Arc::new(vec![0u8; 16]));
    let restarted = PreparedSnapshots::new();
    assert!(restarted.take_for("g", &hash(1)).is_none());
}
