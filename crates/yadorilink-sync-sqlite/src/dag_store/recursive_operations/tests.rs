use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::*;
use crate::dag_store::{
    admit_change, commit_prune, has_change, init_dag_schema, AdmitOutcome, AuthorChainRefusal,
};
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId, SyncPath};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_domain::recursive_operation::{RecursiveOperation, RecursiveOperationKind};
use yadorilink_replica_domain::test_authoring::{
    create_recursive_part_for_tests, create_signed_for_tests, reset_author_sequences,
};

const GROUP: &str = "g";

fn conn() -> Connection {
    reset_author_sequences();
    let c = Connection::open_in_memory().unwrap();
    init_dag_schema(&c).unwrap();
    c
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

fn rm_tree(id: u8, part_index: u32, part_count: u32, effects: &[Op]) -> RecursiveOperation {
    RecursiveOperation {
        operation_id: RecursiveOperationId([id; 16]),
        kind: RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
        part_index,
        part_count,
        effect_set_hash: EffectSetHash::of_effects(effects),
    }
}

fn part(
    device: &str,
    parent: Option<&Change>,
    operation: RecursiveOperation,
    ops: Vec<Op>,
) -> Change {
    create_recursive_part_for_tests(
        parent.map(Change::compute_hash).into_iter().collect(),
        parent.map_or(0, |p| p.lamport),
        DeviceId(device.into()),
        FolderGroupId(GROUP.into()),
        operation,
        ops,
        &key(device.as_bytes()[0]),
    )
}

fn admit(conn: &Connection, change: &Change) {
    let result = admit_change(conn, change).expect("admission must not error");
    assert_eq!(result.outcome, AdmitOutcome::Applied, "admission must succeed");
}

fn reference(device: &str, id: u8) -> RecursiveOperationRef {
    RecursiveOperationRef {
        author: DeviceId(device.into()),
        operation_id: RecursiveOperationId([id; 16]),
    }
}

/// The whole observed set of a three-entry `rm -rf a` split in two.
fn effects() -> Vec<Op> {
    vec![delete("a"), delete("a/x"), delete("a/y")]
}

#[test]
fn every_part_of_an_operation_is_found_by_its_id_and_the_operation_is_complete() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x"), delete("a/y")]);
    admit(&c, &p0);
    let p1 = part("dev", Some(&p0), rm_tree(1, 1, 2, &all), vec![delete("a")]);
    admit(&c, &p1);

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().expect("recorded");
    assert_eq!(recorded.descriptor, rm_tree(1, 0, 2, &all).descriptor());
    assert_eq!(
        recorded.parts.iter().map(|p| (p.part_index, p.change_hash)).collect::<Vec<_>>(),
        vec![(0, p0.compute_hash()), (1, p1.compute_hash())]
    );
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
    let mut set = recorded.effect_set();
    set.sort_by(|x, y| x.primary_path().cmp(y.primary_path()));
    assert_eq!(set, all);

    for change in [&p0, &p1] {
        assert_eq!(
            recursive_operation_of_change(&c, &change.compute_hash()).unwrap(),
            Some(reference("dev", 1))
        );
    }
    assert_eq!(recursive_operation(&c, GROUP, &reference("dev", 2)).unwrap(), None);
}

#[test]
fn an_operation_missing_parts_reports_which_ones() {
    let c = conn();
    let all = vec![delete("a"), delete("a/x"), delete("a/y")];
    let p1 = part("dev", None, rm_tree(1, 1, 3, &all), vec![delete("a/x")]);
    admit(&c, &p1);

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(
        recorded.completeness(),
        RecursiveOperationCompleteness::Partial { missing_part_indexes: vec![0, 2] }
    );
}

/// All parts present, but they do not add up to the set the author
/// declared: never reported as complete.
#[test]
fn parts_that_do_not_add_up_to_the_declared_effect_set_are_inconsistent() {
    let c = conn();
    let declared = effects();
    let only = part("dev", None, rm_tree(1, 0, 1, &declared), vec![delete("a/x")]);
    admit(&c, &only);

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Inconsistent);
}

fn is_buffered(conn: &Connection, change: &Change) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM orphan_changes WHERE change_hash = ?1",
        [&change.compute_hash().0[..]],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        > 0
}

/// Admits `change` and asserts it is refused finally: an outcome, not an
/// error, recorded so no peer is asked for it again.
fn assert_refused_as_contradiction(conn: &Connection, change: &Change) {
    let result =
        admit_change(conn, change).expect("a contradicting part is a verdict, not an error");
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(
                AuthorChainRefusal::RecursiveOperationContradicted { .. }
                    | AuthorChainRefusal::RecursiveOperationPartHeld { .. }
            )
        ),
        "unexpected outcome {:?}",
        result.outcome
    );
    assert!(!has_change(conn, &change.compute_hash()).unwrap(), "a refused part is not stored");
    assert!(
        crate::dag_store::is_change_rejected(conn, &change.compute_hash()).unwrap(),
        "the refusal is recorded, so the part is not re-requested"
    );
}

#[test]
fn a_part_that_disagrees_with_its_operation_is_refused_and_not_stored() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &p0);

    // Same operation, but cut from a different observed set.
    let other = vec![delete("a"), delete("a/y")];
    let p1 = part("dev", Some(&p0), rm_tree(1, 1, 2, &other), vec![delete("a")]);
    assert_refused_as_contradiction(&c, &p1);

    // Same operation, different part count, on a fresh replica (the
    // refused part above consumed this author's next sequence).
    let c = conn();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &p0);
    let p1 = part("dev", Some(&p0), rm_tree(1, 1, 3, &all), vec![delete("a")]);
    assert_refused_as_contradiction(&c, &p1);

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.parts.len(), 1);
}

#[test]
fn a_part_index_already_carried_by_another_change_is_refused() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &p0);
    let again = part("dev", Some(&p0), rm_tree(1, 0, 2, &all), vec![delete("a/y")]);
    assert_refused_as_contradiction(&c, &again);

    // A redelivery of the part that holds the index is not a conflict.
    admit_change(&c, &p0).expect("redelivery is idempotent");
}

/// The author's next change after a refused part names that part as its
/// predecessor. It is refused behind it, not held forever waiting for it.
#[test]
fn the_authors_next_change_after_a_refused_part_is_released() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &p0);
    let again = part("dev", Some(&p0), rm_tree(1, 0, 2, &all), vec![delete("a/y")]);
    let next = create_signed_for_tests(
        vec![p0.compute_hash()],
        p0.lamport,
        DeviceId("dev".into()),
        FolderGroupId(GROUP.into()),
        vec![delete("elsewhere")],
        &key(b'd'),
    );
    assert_eq!(next.author_prev, Some(again.compute_hash()));
    // Arrives first, so it waits on its author's previous change.
    assert_eq!(admit_change(&c, &next).unwrap().outcome, AdmitOutcome::Orphaned);

    assert_refused_as_contradiction(&c, &again);
    assert!(!is_buffered(&c, &next), "nothing is left waiting on a refused part");
}

/// A contradicting part buffered behind another device's change must not
/// take that change down with it when the change arrives and wakes it.
#[test]
fn a_contradicting_orphan_part_does_not_block_the_parent_that_wakes_it() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &p0);
    let honest = create_signed_for_tests(
        vec![p0.compute_hash()],
        p0.lamport,
        DeviceId("eve".into()),
        FolderGroupId(GROUP.into()),
        vec![delete("b")],
        &key(b'e'),
    );
    let again = part("dev", Some(&honest), rm_tree(1, 0, 2, &all), vec![delete("a/y")]);
    assert_eq!(admit_change(&c, &again).unwrap().outcome, AdmitOutcome::Orphaned);

    let woken = admit_change(&c, &honest).expect("the parent's admission must not fail");
    assert_eq!(woken.outcome, AdmitOutcome::Applied);
    assert_eq!(woken.newly_admitted, vec![honest.compute_hash()]);
    assert!(has_change(&c, &honest.compute_hash()).unwrap());
    assert!(!has_change(&c, &again.compute_hash()).unwrap());
    assert!(!is_buffered(&c, &again), "the contradicting part leaves the buffer");
    assert!(crate::dag_store::is_change_rejected(&c, &again.compute_hash()).unwrap());
}

/// An agreeing part that waited in the orphan buffer is recorded when it is
/// promoted, exactly as one admitted directly.
#[test]
fn a_part_promoted_from_the_orphan_buffer_is_recorded() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x"), delete("a/y")]);
    let p1 = part("dev", Some(&p0), rm_tree(1, 1, 2, &all), vec![delete("a")]);
    assert_eq!(admit_change(&c, &p1).unwrap().outcome, AdmitOutcome::Orphaned);
    admit(&c, &p0);

    assert_eq!(
        recursive_operation_of_change(&c, &p1.compute_hash()).unwrap(),
        Some(reference("dev", 1))
    );
    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
}

/// An operation is its author's: another device reusing the id names a
/// different operation, and can neither be refused by nor poison the
/// first one.
#[test]
fn the_same_id_from_another_author_is_another_operation() {
    let c = conn();
    let all = effects();
    let mine = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &mine);
    let other_set = vec![delete("a/z")];
    let theirs = part("eve", None, rm_tree(1, 0, 1, &other_set), other_set.clone());
    admit(&c, &theirs);

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.descriptor.part_count, 2);
    assert_eq!(recorded.parts.len(), 1);
    let recorded = recursive_operation(&c, GROUP, &reference("eve", 1)).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
}

/// Compaction drops the parts' changes; the operation and its effect set
/// must still be answerable from the record alone.
#[test]
fn the_operation_outlives_its_compacted_parts() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x"), delete("a/y")]);
    admit(&c, &p0);
    let p1 = part("dev", Some(&p0), rm_tree(1, 1, 2, &all), vec![delete("a")]);
    admit(&c, &p1);
    let later = create_signed_for_tests(
        vec![p1.compute_hash()],
        p1.lamport,
        DeviceId("dev".into()),
        FolderGroupId(GROUP.into()),
        vec![delete("elsewhere")],
        &key(b'd'),
    );
    admit(&c, &later);

    let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
        FolderGroupId(GROUP.into()),
        vec![later.compute_hash()],
        [0u8; 32],
    );
    {
        let tx = c.unchecked_transaction().unwrap();
        commit_prune(&tx, &checkpoint, &[p0.compute_hash(), p1.compute_hash()]).unwrap();
        tx.commit().unwrap();
    }
    assert!(!has_change(&c, &p0.compute_hash()).unwrap());
    assert!(!has_change(&c, &p1.compute_hash()).unwrap());

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
    assert_eq!(recorded.effect_set().len(), 3);
    assert_eq!(
        recursive_operation_of_change(&c, &p1.compute_hash()).unwrap(),
        Some(reference("dev", 1))
    );
}

fn part_on(
    epoch: HistoryEpoch,
    device: &str,
    seq: u64,
    operation: RecursiveOperation,
    ops: Vec<Op>,
) -> Change {
    Change::create_recursive_part_signed(
        vec![],
        0,
        DeviceId(device.into()),
        AuthorSeq(seq),
        None,
        FolderGroupId(GROUP.into()),
        epoch,
        operation,
        ops,
        &key(device.as_bytes()[0]),
    )
}

fn another_history() -> HistoryEpoch {
    HistoryEpoch::Base(HistoryBase([7; 32]))
}

/// A replica that joined a history from its base never saw the parts
/// written below that base, while a long-lived one recorded them. Refusing
/// against those records would split the two over one change, so a part is
/// measured only against parts written on its own history.
#[test]
fn a_part_recorded_on_another_history_never_refuses_one_on_this_history() {
    let c = conn();
    let all = effects();
    let old = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x")]);
    admit(&c, &old);

    let reused = vec![delete("a/z")];
    let new = part_on(another_history(), "dev", 1, rm_tree(1, 0, 1, &reused), reused.clone());
    assert_eq!(recursive_operation_part_refusal(&c, &new).unwrap(), None);
    record_recursive_operation_part(&c, &new).expect("recording must not refuse it either");

    // The two histories disagree about the operation, which a restore
    // must never take for a complete set.
    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Inconsistent);
}

/// A history sealed between two parts of one operation: the parts agree,
/// and together they are the whole operation.
#[test]
fn an_operation_whose_parts_straddle_two_histories_is_complete() {
    let c = conn();
    let all = effects();
    let p0 = part("dev", None, rm_tree(1, 0, 2, &all), vec![delete("a/x"), delete("a/y")]);
    admit(&c, &p0);
    let p1 = part_on(another_history(), "dev", 2, rm_tree(1, 1, 2, &all), vec![delete("a")]);
    record_recursive_operation_part(&c, &p1).unwrap();

    let recorded = recursive_operation(&c, GROUP, &reference("dev", 1)).unwrap().unwrap();
    assert_eq!(
        recorded.parts.iter().map(|p| p.change_hash).collect::<Vec<_>>(),
        vec![p0.compute_hash(), p1.compute_hash()]
    );
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
}

#[test]
fn an_ordinary_change_is_not_part_of_any_operation() {
    let c = conn();
    let plain = create_signed_for_tests(
        vec![],
        0,
        DeviceId("dev".into()),
        FolderGroupId(GROUP.into()),
        vec![delete("a/x")],
        &key(b'd'),
    );
    admit(&c, &plain);
    assert_eq!(recursive_operation_of_change(&c, &plain.compute_hash()).unwrap(), None);
}
