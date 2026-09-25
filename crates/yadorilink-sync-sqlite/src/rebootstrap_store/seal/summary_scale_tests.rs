//! Recomputing a seal's `Gamma` stays proportional to the history, however
//! the writes to one path are spread through it.
//!
//! The seal recomputes `Gamma` inside its write transaction, so its cost is
//! time the database writer is held. The shape here is the expensive one
//! for a per-pair ancestry check: many concurrent writes low in the
//! history and many high above a long chain that descends from none of
//! them, all to one path.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::*;
use crate::rebootstrap_store::seal_tests::{key, put, version, GROUP};
use yadorilink_replica_domain::ids::DeviceId;

fn hash(n: u32) -> ChangeHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    ChangeHash(bytes)
}

#[test]
fn gamma_of_a_hot_path_over_a_long_history_is_recomputed_in_linear_time() {
    const CONCURRENT: u32 = 100;
    const CHAIN: u32 = 2_000;

    // Only the parents, the clock and the ops matter here; the signature
    // is never checked, and each change is keyed by the hash given it.
    let template = Change::create_signed(
        Vec::new(),
        0,
        DeviceId("device-a".to_string()),
        AuthorSeq(1),
        None,
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Genesis,
        Vec::new(),
        &key("device-a"),
    );
    let change = |parents: Vec<ChangeHash>, lamport: u64, writes: bool| {
        let mut change = template.clone();
        change.parents = parents;
        change.lamport = lamport;
        change.ops = if writes { vec![put("hot", &version(1))] } else { Vec::new() };
        change
    };

    let mut changes = Vec::new();
    let mut next = 0u32;
    let mut add = |changes: &mut Vec<(ChangeHash, Change)>, c: Change| {
        next += 1;
        changes.push((hash(next), c));
        hash(next)
    };
    // The low writes: concurrent, each a root.
    for _ in 0..CONCURRENT {
        add(&mut changes, change(Vec::new(), 1, true));
    }
    // A long chain that descends from none of them.
    let mut tip = add(&mut changes, change(Vec::new(), 1, false));
    for lamport in 2..=u64::from(CHAIN) {
        tip = add(&mut changes, change(vec![tip], lamport, false));
    }
    // The high writes: concurrent children of the chain's tip.
    for _ in 0..CONCURRENT {
        add(&mut changes, change(vec![tip], u64::from(CHAIN) + 1, true));
    }

    let history = AbsorbedHistory {
        group_id: GROUP.to_string(),
        epoch: HistoryEpoch::Genesis,
        base: None,
        changes,
        positions: BTreeMap::new(),
    };
    let started = Instant::now();
    let summary = recompute_summary(&history).unwrap();
    let elapsed = started.elapsed();

    assert_eq!(
        summary.path_heads.len(),
        2 * CONCURRENT as usize,
        "no write to the path descends from another, so every one is a head"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "recomputing Gamma over {} changes took {elapsed:?}",
        CONCURRENT * 2 + CHAIN
    );
}
