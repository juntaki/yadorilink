#![cfg(test)]
//! An installed history base is where every author it carries resumes.
//!
//! A base absorbs each author's history up to the watermark it carries.
//! The change that attained that watermark is part of what was absorbed:
//! it may be pruned, or kept only as a boundary change of the history the
//! base replaced. So the first change an author writes on the base does
//! not continue that change by name. It continues the base itself, and
//! the base link is the change's signed history epoch, not its
//! `author_prev` -- a change hash can only ever name a change, never a
//! base. The first change on a base therefore takes the next sequence and
//! names no predecessor, and every later one names its author's tip as
//! usual.

use super::base_install_tests::open;
use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::admission::AuthorChainRefusal;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

const GROUP: &str = "group-base-anchored-author";

fn unseen_key() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// A base carrying two authors: `device-a`, whose tip is the base's one
/// frontier change, and `device-unseen`, whose tip at sequence 6 was
/// pruned before it and survives only as that change's boundary parent.
/// Installed with the atomic epoch reset, so neither tip is retained: the
/// base absorbs both, and every change on it is an epoch root clocked from
/// the base's ceiling (the frontier's Lamport).
struct InstalledBase {
    epoch: HistoryEpoch,
    frontier: Change,
    pruned_tip: Change,
}

fn install_base(conn: &mut Connection) -> InstalledBase {
    let group = FolderGroupId(GROUP.to_string());
    let pruned_tip = Change::create_signed(
        Vec::new(),
        0,
        DeviceId("device-unseen".to_string()),
        AuthorSeq(6),
        Some(ChangeHash([77u8; 32])),
        group.clone(),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath("pruned.txt".to_string()) }],
        &unseen_key(),
    );
    let frontier = Change::create_signed(
        vec![pruned_tip.compute_hash()],
        pruned_tip.lamport,
        DeviceId("device-a".to_string()),
        AuthorSeq(1),
        None,
        group.clone(),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath("gone.txt".to_string()) }],
        &SigningKey::from_bytes(&[9u8; 32]),
    );
    let frontier_hash = frontier.compute_hash();
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        vec![frontier.to_wire_bytes()],
        Vec::new(),
        Vec::new(),
        vec![BoundaryParentAuth {
            child_hash: frontier_hash,
            parent_hash: pruned_tip.compute_hash(),
            parent_lamport: pruned_tip.lamport,
        }],
        vec![
            SnapshotAuthorState {
                device_id: "device-a".to_string(),
                watermark: frontier.author_seq,
                tip_change_hash: frontier_hash,
            },
            SnapshotAuthorState {
                device_id: "device-unseen".to_string(),
                watermark: pruned_tip.author_seq,
                tip_change_hash: pruned_tip.compute_hash(),
            },
        ],
        Vec::new(),
        // The frontier holds the greatest Lamport the replaced history
        // reached, so a change parented on it lands one above either way.
        frontier.lamport,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, vec![frontier_hash], snapshot.snapshot_hash());
    let tx = conn.transaction().unwrap();
    install_base_for_tests(&tx, &checkpoint, &snapshot).unwrap();
    tx.commit().unwrap();
    InstalledBase {
        epoch: HistoryEpoch::Base(HistoryBase::from_checkpoint(&checkpoint)),
        frontier,
        pruned_tip,
    }
}

/// A change by `device-unseen` on the installed base: an epoch root,
/// clocked from the base's ceiling.
fn unseen_change(
    base: &InstalledBase,
    seq: u64,
    author_prev: Option<ChangeHash>,
    path: &str,
) -> Change {
    Change::create_signed(
        Vec::new(),
        base.frontier.lamport,
        DeviceId("device-unseen".to_string()),
        AuthorSeq(seq),
        author_prev,
        FolderGroupId(GROUP.to_string()),
        base.epoch,
        vec![Op::Delete { path: SyncPath(path.to_string()) }],
        &unseen_key(),
    )
}

fn admit(conn: &Connection, change: &Change) -> crate::dag_store::AdmitOutcome {
    crate::dag_store::admit_change(conn, change).unwrap().outcome
}

#[test]
fn an_author_the_base_carries_opens_its_epoch_naming_no_predecessor() {
    let mut conn = open();
    let base = install_base(&mut conn);

    let opening = unseen_change(&base, 7, None, "next.txt");
    assert_eq!(
        admit(&conn, &opening),
        crate::dag_store::AdmitOutcome::Applied,
        "the next sequence on the installed base, naming nothing, continues the base"
    );
}

#[test]
fn naming_the_tip_the_base_absorbed_is_refused() {
    let mut conn = open();
    let base = install_base(&mut conn);

    let reaching_back = unseen_change(&base, 7, Some(base.pruned_tip.compute_hash()), "next.txt");
    assert!(
        matches!(
            admit(&conn, &reaching_back),
            crate::dag_store::AdmitOutcome::RefusedAuthorChain(
                AuthorChainRefusal::AuthorPrevMismatch { named: Some(_), .. }
            )
        ),
        "the absorbed tip is behind the base; the first change on it names no predecessor"
    );
}

#[test]
fn after_the_opening_change_the_author_continues_from_its_tip() {
    let mut conn = open();
    let base = install_base(&mut conn);

    let opening = unseen_change(&base, 7, None, "seven.txt");
    assert_eq!(admit(&conn, &opening), crate::dag_store::AdmitOutcome::Applied);

    let unlinked = unseen_change(&base, 8, None, "eight-unlinked.txt");
    assert!(
        matches!(
            admit(&conn, &unlinked),
            crate::dag_store::AdmitOutcome::RefusedAuthorChain(
                AuthorChainRefusal::AuthorPrevMismatch { named: None, .. }
            )
        ),
        "once the author has written on the base, its tip is a change again"
    );

    let continuing = unseen_change(&base, 8, Some(opening.compute_hash()), "eight.txt");
    assert_eq!(admit(&conn, &continuing), crate::dag_store::AdmitOutcome::Applied);
}

#[test]
fn this_devices_next_change_on_an_installed_base_names_no_predecessor() {
    let mut conn = open();
    let base = install_base(&mut conn);

    assert_eq!(
        crate::dag_store::author_chain::next_author_position(&conn, GROUP, "device-a").unwrap(),
        (AuthorSeq(2), None),
        "local emission opens the epoch at the carried watermark's next position, naming nothing"
    );

    // And once it has written there, the next one names that change.
    let opening = Change::create_signed(
        Vec::new(),
        base.frontier.lamport,
        DeviceId("device-a".to_string()),
        AuthorSeq(2),
        None,
        FolderGroupId(GROUP.to_string()),
        base.epoch,
        vec![Op::Delete { path: SyncPath("a-two.txt".to_string()) }],
        &SigningKey::from_bytes(&[9u8; 32]),
    );
    assert_eq!(admit(&conn, &opening), crate::dag_store::AdmitOutcome::Applied);
    assert_eq!(
        crate::dag_store::author_chain::next_author_position(&conn, GROUP, "device-a").unwrap(),
        (AuthorSeq(3), Some(opening.compute_hash()))
    );
}

/// What a base does not carry is not continued through it. An author whose
/// own replica got further than the base before it was installed keeps
/// naming the change that took it there, which was written on the history
/// the base replaced. A replica that installed the base fresh has that
/// author at the base's position: it refuses that tip as another history,
/// and every change that names it behind it. The base must carry every
/// position its authors continue from for them to converge.
#[test]
fn a_fresh_installer_refuses_a_tip_the_base_did_not_carry_and_what_names_it() {
    let mut conn = open();
    let base = install_base(&mut conn);
    let key = SigningKey::from_bytes(&[9u8; 32]);

    let uncarried_tip = Change::create_signed(
        vec![base.frontier.compute_hash()],
        base.frontier.lamport,
        DeviceId("device-a".to_string()),
        AuthorSeq(2),
        Some(base.frontier.compute_hash()),
        FolderGroupId(GROUP.to_string()),
        HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath("a-two.txt".to_string()) }],
        &key,
    );
    let continuing = Change::create_signed(
        Vec::new(),
        base.frontier.lamport,
        DeviceId("device-a".to_string()),
        AuthorSeq(3),
        Some(uncarried_tip.compute_hash()),
        FolderGroupId(GROUP.to_string()),
        base.epoch,
        vec![Op::Delete { path: SyncPath("a-three.txt".to_string()) }],
        &key,
    );

    let outcome = admit(&conn, &uncarried_tip);
    assert!(
        matches!(outcome, crate::dag_store::AdmitOutcome::RefusedForeignHistoryBase { .. }),
        "the tip was written on the replaced history, got {outcome:?}"
    );
    let outcome = admit(&conn, &continuing);
    assert!(
        matches!(outcome, crate::dag_store::AdmitOutcome::RefusedAuthorChain(_)),
        "a change naming a refused tip is refused behind it, got {outcome:?}"
    );
}
