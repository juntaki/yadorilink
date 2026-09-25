#![cfg(test)]

//! The history a staged Change was written on is decided before anything
//! about its ancestry.
//!
//! A Change's `history_epoch` is part of its signed bytes, and this replica's
//! own base is local state, so "written on another history" is decidable
//! from the Change alone. A missing parent is not: it is a property of what
//! has arrived so far. Asking the ancestry question first gets the foreign
//! case wrong in two ways that the staging area makes permanent rather than
//! slow:
//!
//! * a foreign Change whose parents never arrive is never selected for
//!   promotion, so it sits staged -- possessed, servable to every peer, never
//!   asked for again and never settled;
//! * a foreign Change behind a foreign parent that was refused first is
//!   refused as "behind a rejected parent", which names the wrong remedy: the
//!   parent is not what is wrong with it.

use super::*;
use crate::verified_change_store::{
    admissible_now, is_servable, stage_verified_bundles,
    test_support::{bundle, checkpoint, conn, GROUP},
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};

const LOCAL_BASE: HistoryBase = HistoryBase([0x22; 32]);
const FOREIGN: HistoryEpoch = HistoryEpoch::Base(HistoryBase([0x11; 32]));

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn install_base(c: &Connection, base: HistoryBase) {
    c.execute(
        "INSERT OR REPLACE INTO group_history_bases \
         (group_id, history_base, checkpoint_hash, previous_checkpoint_hash) \
         VALUES (?1, ?2, ?3, NULL)",
        rusqlite::params![GROUP, &base.0[..], &[0x7f_u8; 32][..]],
    )
    .unwrap();
}

/// One change of device 2's chain on `epoch`: `prev` is both its author
/// predecessor and its only DAG parent, as in a plain linear history.
fn chained(epoch: HistoryEpoch, seq: u64, prev: Option<&Change>, path: &str) -> Change {
    Change::create_signed(
        prev.map(|p| vec![p.compute_hash()]).unwrap_or_default(),
        prev.map(|p| p.lamport).unwrap_or(0),
        DeviceId("device-2".into()),
        AuthorSeq(seq),
        prev.map(Change::compute_hash),
        FolderGroupId(GROUP.into()),
        epoch,
        vec![Op::Delete { path: SyncPath(path.into()) }],
        &SigningKey::from_bytes(&[2u8; 32]),
    )
}

fn stage(c: &Connection, change: &Change) -> ChangeHash {
    let tx = c.unchecked_transaction().unwrap();
    stage_verified_bundles(&tx, &[bundle(change.clone(), checkpoint(1))], 1).unwrap();
    tx.commit().unwrap();
    change.compute_hash()
}

fn promote(c: &Connection, hash: &ChangeHash) -> AdmissionOutcome {
    let plan = plan_admission(c, hash).unwrap().expect("staged");
    let tx = c.unchecked_transaction().unwrap();
    let outcome = commit_admission(&tx, &plan).unwrap();
    tx.commit().unwrap();
    outcome
}

fn count(c: &Connection, table: &str) -> i64 {
    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap()
}

/// A foreign Change whose parents are not here is still foreign, and is
/// settled as foreign -- not left staged waiting on parents that belong to
/// another history.
#[test]
fn a_staged_foreign_change_with_absent_parents_is_refused_as_foreign() {
    let c = conn();
    install_base(&c, LOCAL_BASE);
    let f1 = chained(FOREIGN, 1, None, "f1.bin");
    let f2 = chained(FOREIGN, 2, Some(&f1), "f2.bin");
    let f3 = chained(FOREIGN, 3, Some(&f2), "f3.bin");

    let hash = stage(&c, &f3);
    assert_eq!(
        admissible_now(&c, &group(), 16).unwrap(),
        vec![hash],
        "a Change written on another history has nothing here to wait for, so it must be \
         selected for settling even though its parents are absent"
    );
    assert!(
        matches!(promote(&c, &hash), AdmissionOutcome::RefusedForeignHistoryBase { .. }),
        "and it must be refused for the history it was written on"
    );
    assert!(!is_servable(&c, &hash).unwrap(), "a refused foreign Change is no longer possessed");
    assert_eq!(count(&c, "changes"), 0);
    assert_eq!(count(&c, "orphan_changes"), 0);
}

/// Every member of a self-contained foreign history is refused for the same
/// reason, whatever order it is settled in.
#[test]
fn every_member_of_a_staged_foreign_history_is_refused_as_foreign() {
    let c = conn();
    install_base(&c, LOCAL_BASE);
    let f1 = chained(FOREIGN, 1, None, "f1.bin");
    let f2 = chained(FOREIGN, 2, Some(&f1), "f2.bin");
    let f3 = chained(FOREIGN, 3, Some(&f2), "f3.bin");
    for change in [&f1, &f2, &f3] {
        stage(&c, change);
    }

    let mut outcomes = Vec::new();
    loop {
        let ready = admissible_now(&c, &group(), 16).unwrap();
        if ready.is_empty() {
            break;
        }
        for hash in ready {
            outcomes.push((hash, promote(&c, &hash)));
        }
    }

    assert_eq!(outcomes.len(), 3, "every staged member is settled, got {outcomes:?}");
    for (hash, outcome) in &outcomes {
        assert!(
            matches!(outcome, AdmissionOutcome::RefusedForeignHistoryBase { .. }),
            "{hash:?} was written on another history, and that -- not a rejected parent -- is \
             why it is refused, got {outcome:?}"
        );
    }
    assert_eq!(count(&c, "verified_change_objects"), 0, "nothing foreign stays possessed");
    assert_eq!(count(&c, "changes"), 0);
}

/// "Foreign" is measured against the base this replica holds when the
/// Change is settled, not the one it held when the Change arrived: a base
/// switch turns what was staged on the old history into foreign history.
#[test]
fn a_change_staged_before_a_base_switch_is_refused_as_foreign_after_it() {
    let c = conn();
    let g1 = chained(HistoryEpoch::Genesis, 1, None, "g1.bin");
    let g2 = chained(HistoryEpoch::Genesis, 2, Some(&g1), "g2.bin");
    let hash = stage(&c, &g2);
    assert!(admissible_now(&c, &group(), 16).unwrap().is_empty(), "waiting on its parent");

    install_base(&c, LOCAL_BASE);

    assert_eq!(
        admissible_now(&c, &group(), 16).unwrap(),
        vec![hash],
        "after the switch it is foreign, and a foreign Change does not wait on parents"
    );
    assert!(matches!(promote(&c, &hash), AdmissionOutcome::RefusedForeignHistoryBase { .. }));
}

/// The canonical install decides the history before the parent shape too,
/// so no entry point reports a foreign Change as a stale plan.
#[test]
fn the_canonical_install_refuses_a_foreign_change_before_asking_for_its_parents() {
    let c = conn();
    install_base(&c, LOCAL_BASE);
    let f1 = chained(FOREIGN, 1, None, "f1.bin");
    let f2 = chained(FOREIGN, 2, Some(&f1), "f2.bin");

    let tx = c.unchecked_transaction().unwrap();
    let outcome = dag_store::install_canonical_change_only(&tx, &f2).unwrap();
    tx.commit().unwrap();
    assert!(
        matches!(outcome, dag_store::InstallCanonicalOutcome::RefusedForeignHistoryBase { .. }),
        "a foreign Change is not a Change with missing parents, got {outcome:?}"
    );
}

/// A Change this replica already holds as a pruned witness of the history
/// its base absorbed is not foreign history to refuse -- it is history held
/// here. A staged copy of it, as a peer still keeping the old history may
/// send, is settled once and gone, not selected and reported stale on
/// every pass.
#[test]
fn a_staged_copy_of_a_pruned_change_is_settled_once() {
    let c = conn();
    let g1 = chained(HistoryEpoch::Genesis, 1, None, "g1.bin");
    let g2 = chained(HistoryEpoch::Genesis, 2, Some(&g1), "g2.bin");
    install_base(&c, LOCAL_BASE);
    let hash = g2.compute_hash();
    c.execute(
        "INSERT INTO pruned_changes \
         (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
         VALUES (?1, ?2, ?3, ?4, 1)",
        rusqlite::params![GROUP, &hash.0[..], vec![0x7f_u8; 32], g2.lamport as i64],
    )
    .unwrap();
    stage(&c, &g2);

    let mut passes = 0;
    while let Some(next) = admissible_now(&c, &group(), 16).unwrap().first().copied() {
        passes += 1;
        assert!(passes <= 2, "a staged copy of a pruned Change is re-selected on every pass");
        let outcome = promote(&c, &next);
        assert!(
            !matches!(outcome, AdmissionOutcome::RefusedForeignHistoryBase { .. }),
            "a Change held here is not refused as foreign, got {outcome:?}"
        );
    }
    assert_eq!(count(&c, "verified_change_objects"), 0, "the staged copy is gone");
    assert_eq!(count(&c, "rejected_changes"), 0, "and nothing was refused");
}

/// A staged Change past the next sequence that names the author's recorded
/// tip, once a base has absorbed that tip, is decided like its admission
/// decides it: the named position is known here, so the gap is refused and
/// the staged copy goes -- it is not held waiting for a predecessor that
/// will never arrive again.
#[test]
fn a_staged_change_naming_an_absorbed_tip_past_the_next_sequence_is_settled() {
    let c = conn();
    let g1 = chained(HistoryEpoch::Genesis, 1, None, "g1.bin");
    let g2 = chained(HistoryEpoch::Genesis, 2, Some(&g1), "g2.bin");
    install_base(&c, LOCAL_BASE);
    c.execute(
        "INSERT INTO author_chain_state \
         (group_id, device_id, watermark, tip_change_hash, anchor_base) \
         VALUES (?1, 'device-2', 2, ?2, ?3)",
        rusqlite::params![GROUP, &g2.compute_hash().0[..], &LOCAL_BASE.0[..]],
    )
    .unwrap();
    c.execute(
        "INSERT INTO history_base_meta (group_id, base_hash, lamport_ceiling) VALUES (?1, ?2, ?3)",
        rusqlite::params![GROUP, &LOCAL_BASE.0[..], g2.lamport as i64],
    )
    .unwrap();
    let gap = Change::create_signed(
        Vec::new(),
        g2.lamport,
        DeviceId("device-2".into()),
        AuthorSeq(4),
        Some(g2.compute_hash()),
        FolderGroupId(GROUP.into()),
        HistoryEpoch::Base(LOCAL_BASE),
        vec![Op::Delete { path: SyncPath("gap.bin".into()) }],
        &SigningKey::from_bytes(&[2u8; 32]),
    );
    let hash = stage(&c, &gap);

    assert_eq!(
        admissible_now(&c, &group(), 16).unwrap(),
        vec![hash],
        "a Change naming the absorbed tip has nothing here to wait for"
    );
    let outcome = promote(&c, &hash);
    assert!(
        matches!(outcome, AdmissionOutcome::RefusedAuthorChain(_)),
        "the gap past the absorbed tip is refused, got {outcome:?}"
    );
    assert_eq!(count(&c, "verified_change_objects"), 0, "the staged copy is gone");
    assert_eq!(count(&c, "changes"), 0);
}
