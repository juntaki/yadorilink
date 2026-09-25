#![cfg(test)]

//! A staged Change waiting on its author's previous Change is held, not
//! selected.
//!
//! Author ordering is not DAG causality: an author's previous Change is
//! routinely not among a Change's parents, so a Change can have every parent
//! canonical and still name a predecessor this replica has not admitted yet.
//! Admission answers that with a hold. The staging area has to hold it too,
//! or the Change is selected on every pass, reported stale, and -- sorting
//! ahead of the predecessor it waits for -- fills the bounded candidate
//! window so that predecessor is never selected at all.
//!
//! The gap rule is otherwise unchanged: a Change whose position is already
//! decidable -- its predecessor held, its predecessor refused, or a sequence
//! that leaves no room for a predecessor still in flight -- is selected and
//! settled.

use super::*;
use crate::verified_change_store::{
    admissible_now, is_canonical, stage_verified_bundles,
    test_support::{bundle, checkpoint, conn, GROUP},
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::admission::AuthorChainRefusal;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

/// A parentless Change of device 2 at `seq`, naming `prev` as its author
/// predecessor: every DAG parent is trivially present, so the author link
/// is the only thing it can wait on.
fn authored(epoch: HistoryEpoch, seq: u64, prev: Option<ChangeHash>, path: &str) -> Change {
    Change::create_signed(
        vec![],
        0,
        DeviceId("device-2".into()),
        AuthorSeq(seq),
        prev,
        FolderGroupId(GROUP.into()),
        epoch,
        vec![Op::Delete { path: SyncPath(path.into()) }],
        &SigningKey::from_bytes(&[2u8; 32]),
    )
}

/// Device 2's chain `seq 1..=len`, linked by author predecessor only.
fn chain(len: u64) -> Vec<Change> {
    let mut out: Vec<Change> = Vec::new();
    for seq in 1..=len {
        let prev = out.last().map(Change::compute_hash);
        out.push(authored(HistoryEpoch::Genesis, seq, prev, &format!("a{seq}.bin")));
    }
    out
}

fn stage_at(c: &Connection, change: &Change, verified_at: i64) -> ChangeHash {
    let tx = c.unchecked_transaction().unwrap();
    stage_verified_bundles(&tx, &[bundle(change.clone(), checkpoint(1))], verified_at).unwrap();
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

/// The daemon's drain, in miniature: settle a bounded window of candidates
/// per pass, and stop at the first pass that settles nothing.
fn drain(c: &Connection, window: usize) {
    loop {
        let candidates = admissible_now(c, &group(), window).unwrap();
        let mut settled = false;
        for hash in candidates {
            if !matches!(promote(c, &hash), AdmissionOutcome::Stale(_)) {
                settled = true;
            }
        }
        if !settled {
            return;
        }
    }
}

/// Changes waiting on their author's predecessor must not occupy the
/// candidate window ahead of that predecessor.
#[test]
fn changes_waiting_on_their_author_predecessor_do_not_crowd_it_out() {
    let c = conn();
    let chain = chain(5);
    // Everything after the first arrives first, so all of it sorts ahead.
    for change in &chain[1..] {
        stage_at(&c, change, 1);
    }
    stage_at(&c, &chain[0], 2);

    drain(&c, 2);

    for (i, change) in chain.iter().enumerate() {
        assert!(
            is_canonical(&c, &change.compute_hash()).unwrap(),
            "seq {} must be admitted once the chain is complete; a Change held on its author \
             predecessor was selected ahead of that predecessor instead",
            i + 1
        );
    }
}

/// Held until the predecessor lands, then selected.
#[test]
fn a_change_whose_author_predecessor_is_absent_is_held_until_it_lands() {
    let c = conn();
    let chain = chain(2);
    let second = stage_at(&c, &chain[1], 1);
    assert!(
        admissible_now(&c, &group(), 16).unwrap().is_empty(),
        "its author's previous Change is not here and may still be in flight: held, not selected"
    );

    let first = stage_at(&c, &chain[0], 2);
    assert_eq!(admissible_now(&c, &group(), 16).unwrap(), vec![first]);
    assert!(matches!(promote(&c, &first), AdmissionOutcome::Promoted { .. }));
    assert_eq!(admissible_now(&c, &group(), 16).unwrap(), vec![second]);
    assert!(matches!(promote(&c, &second), AdmissionOutcome::Promoted { .. }));
}

/// At the exact next position the predecessor is the tip this replica
/// holds, so naming anything else is a contradiction already known: it is
/// selected and refused, not held.
#[test]
fn the_exact_next_position_naming_an_unknown_predecessor_is_refused_not_held() {
    let c = conn();
    let first = chain(1).remove(0);
    let first_hash = stage_at(&c, &first, 1);
    promote(&c, &first_hash);

    let stray = authored(HistoryEpoch::Genesis, 2, Some(ChangeHash([0x5a; 32])), "stray.bin");
    let hash = stage_at(&c, &stray, 2);
    assert_eq!(admissible_now(&c, &group(), 16).unwrap(), vec![hash]);
    assert!(matches!(
        promote(&c, &hash),
        AdmissionOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
    ));
}

/// A predecessor refused here can never be admitted, so a Change waiting on
/// it is selected and refused behind it rather than held for good.
#[test]
fn a_change_behind_a_refused_author_predecessor_is_selected_and_refused() {
    let c = conn();
    let refused = authored(HistoryEpoch::Base(HistoryBase([0x11; 32])), 1, None, "r.bin");
    let refused_hash = stage_at(&c, &refused, 1);
    assert!(matches!(
        promote(&c, &refused_hash),
        AdmissionOutcome::RefusedForeignHistoryBase { .. }
    ));

    let behind = authored(HistoryEpoch::Genesis, 2, Some(refused_hash), "b.bin");
    let hash = stage_at(&c, &behind, 2);
    assert_eq!(admissible_now(&c, &group(), 16).unwrap(), vec![hash]);
    assert!(matches!(
        promote(&c, &hash),
        AdmissionOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
    ));
}

/// A rejection row the current rules no longer stand behind does not make
/// its Change refused: the author chain answers a Change waiting on it with
/// a hold, exactly as if the row were absent. The staging area must hold it
/// too, or such successors are selected on every pass, reported stale, and
/// -- enough of them sorting first -- crowd out the predecessors that would
/// release them.
#[test]
fn a_stale_rejection_of_the_author_predecessor_does_not_release_its_successors() {
    let c = conn();
    let [_, (domain, version)] = dag_store::current_rules_stamps();
    let mut firsts = Vec::new();
    let mut seconds = Vec::new();
    for author in 3u8..6 {
        let key = SigningKey::from_bytes(&[author; 32]);
        let device = DeviceId(format!("device-{author}"));
        let first = Change::create_signed(
            vec![],
            0,
            device.clone(),
            AuthorSeq(1),
            None,
            FolderGroupId(GROUP.into()),
            HistoryEpoch::Genesis,
            vec![Op::Delete { path: SyncPath(format!("{author}-1.bin")) }],
            &key,
        );
        let second = Change::create_signed(
            vec![],
            0,
            device,
            AuthorSeq(2),
            Some(first.compute_hash()),
            FolderGroupId(GROUP.into()),
            HistoryEpoch::Genesis,
            vec![Op::Delete { path: SyncPath(format!("{author}-2.bin")) }],
            &key,
        );
        c.execute(
            "INSERT INTO rejected_changes \
             (change_hash, group_id, reason, rejected_at, rejection_domain, rules_version, \
              rests_on) \
             VALUES (?1, ?2, 'refused under superseded rules', 0, ?3, ?4, NULL)",
            rusqlite::params![&first.compute_hash().0[..], GROUP, domain, version - 1],
        )
        .unwrap();
        firsts.push(first);
        seconds.push(second);
    }
    // Every successor arrives first, so all of them sort ahead.
    for second in &seconds {
        stage_at(&c, second, 1);
    }
    for first in &firsts {
        stage_at(&c, first, 2);
    }

    drain(&c, 2);

    for change in firsts.iter().chain(&seconds) {
        assert!(
            is_canonical(&c, &change.compute_hash()).unwrap(),
            "{:?} must be admitted: a predecessor refused only under superseded rules is not \
             refused, so the Changes behind it wait for it rather than crowding it out",
            change.compute_hash()
        );
    }
}
