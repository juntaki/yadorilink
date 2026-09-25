//! Change construction for tests and fixtures, with the author sequence
//! allocated for you.
//!
//! Production never signs a change through here. A real emission reads the
//! author's own persisted state to learn its next position and signs with
//! that, in one place, so that the number on the change is the number the
//! store will hold. A test usually has no such state and does not want one:
//! it builds a handful of changes and cares about their shape, not about
//! bookkeeping that would be identical in every file.
//!
//! So this module keeps a counter per `(group_id, device_id)` and hands out
//! 1, 2, 3, … in construction order, remembering the hash it handed each
//! one to so the next change can name it as its author's predecessor. For
//! the overwhelmingly common fixture — an author whose changes are built in
//! the same order they are meant to be admitted — that is exactly the right
//! sequence and the right link, and it means a test's author chain stays
//! valid without the test spelling it out. A test that
//! deliberately wants a specific or an invalid sequence calls
//! [`Change::create_signed`] directly and says so.
//!
//! The counter is per THREAD, not per process, and that is the whole of what
//! makes it usable. An author chain is only meaningful relative to one
//! history, and a store enforces it that way: an author's first change in a
//! store must carry sequence 1. A counter shared across a whole test binary
//! would hand the fourth test to run a sequence of 4 for a store that has
//! never seen that author, and the store would rightly refuse it. Since the
//! test harness gives each test its own thread, a per-thread counter gives
//! each test its own fresh numbering, which is what each test's own fresh
//! store expects.
//!
//! Two limits are worth stating, and both are loud rather than silent — the
//! store refuses the result, it does not quietly accept a wrong number.
//!
//! * A test that authors for the SAME author from two threads gets 1 from
//!   each, and the second is refused as equivocation. Such a test should
//!   author on one thread, or choose its sequences explicitly.
//! * A test that builds a SECOND independent history on the same thread —
//!   two stores in one test — carries the first one's numbering into it, and
//!   the second store refuses the first change it is handed. Such a test
//!   calls [`reset_author_sequences`] when it starts the new history.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;

use crate::change::{Change, Op, RepairObligation};
use crate::ids::{AuthorSeq, ChangeHash, DeviceId, FolderGroupId};
use crate::rebootstrap::HistoryEpoch;
use crate::recursive_operation::RecursiveOperation;

/// One author's allocator state in one group: the sequence it last handed
/// out, and the change that took it.
#[derive(Default, Clone, Copy)]
struct AuthorCursor {
    last_seq: u64,
    last_hash: Option<ChangeHash>,
}

thread_local! {
    static AUTHOR_CURSORS: RefCell<BTreeMap<(String, String), AuthorCursor>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// Allocates and consumes this author's next sequence in this group, with
/// the change it must name as its author's predecessor.
///
/// The two are allocated together because they are two halves of one
/// answer: a sequence without the matching link is refused by admission
/// just as surely as a wrong number would be.
pub fn next_author_position(
    group_id: &FolderGroupId,
    device_id: &DeviceId,
) -> (AuthorSeq, Option<ChangeHash>) {
    AUTHOR_CURSORS.with(|table| {
        let mut table = table.borrow_mut();
        let cursor = table
            .entry((group_id.as_str().to_string(), device_id.as_str().to_string()))
            .or_default();
        cursor.last_seq += 1;
        (AuthorSeq(cursor.last_seq), cursor.last_hash)
    })
}

/// Allocates this author's next sequence in this group, discarding the
/// predecessor link. For a test that only wants the number.
pub fn next_author_seq(group_id: &FolderGroupId, device_id: &DeviceId) -> AuthorSeq {
    next_author_position(group_id, device_id).0
}

/// Records `hash` as the change that took this author's latest allocated
/// position, so the next allocation names it.
fn record_author_tip(group_id: &FolderGroupId, device_id: &DeviceId, hash: ChangeHash) {
    AUTHOR_CURSORS.with(|table| {
        let mut table = table.borrow_mut();
        let cursor = table
            .entry((group_id.as_str().to_string(), device_id.as_str().to_string()))
            .or_default();
        cursor.last_hash = Some(hash);
    })
}

/// Starts the numbering over, for a test that builds a second independent
/// history on one thread.
///
/// A sequence means "this author's nth change in this history", so a test
/// that opens a second store is starting a second history and must say so:
/// otherwise the fresh store is handed a change at whatever number the first
/// history had reached, and refuses it. Call this as the new history begins,
/// not at the end of the old one, so that it cannot be separated from the
/// store it belongs to.
pub fn reset_author_sequences() {
    AUTHOR_CURSORS.with(|table| table.borrow_mut().clear());
}

/// [`Change::create_signed`] with the author sequence allocated by
/// [`next_author_seq`], on a group's original history.
///
/// [`HistoryEpoch::Genesis`] rather than a parameter, because that is what
/// a store with no installed base is on, and that is what almost every
/// fixture builds against. A test that installs a base and then authors
/// onto it calls [`create_signed_on_base_for_tests`] and says so.
pub fn create_signed_for_tests(
    parents: Vec<ChangeHash>,
    max_parent_lamport: u64,
    device_id: DeviceId,
    group_id: FolderGroupId,
    ops: Vec<Op>,
    signing_key: &SigningKey,
) -> Change {
    create_signed_on_base_for_tests(
        parents,
        max_parent_lamport,
        device_id,
        group_id,
        HistoryEpoch::Genesis,
        ops,
        signing_key,
    )
}

/// [`create_signed_for_tests`] for a store that has a history base
/// installed: the epoch is the caller's to name, because admission on such
/// a store admits only changes written on the base it actually holds.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_on_base_for_tests(
    parents: Vec<ChangeHash>,
    max_parent_lamport: u64,
    device_id: DeviceId,
    group_id: FolderGroupId,
    history_epoch: HistoryEpoch,
    ops: Vec<Op>,
    signing_key: &SigningKey,
) -> Change {
    let (author_seq, author_prev) = next_author_position(&group_id, &device_id);
    let change = Change::create_signed(
        parents,
        max_parent_lamport,
        device_id.clone(),
        author_seq,
        author_prev,
        group_id.clone(),
        history_epoch,
        ops,
        signing_key,
    );
    record_author_tip(&group_id, &device_id, change.compute_hash());
    change
}

/// [`Change::create_repair_signed`] with the author sequence allocated by
/// [`next_author_seq`].
pub fn create_repair_signed_for_tests(
    parents: Vec<ChangeHash>,
    max_parent_lamport: u64,
    device_id: DeviceId,
    group_id: FolderGroupId,
    obligations: Vec<RepairObligation>,
    ops: Vec<Op>,
    signing_key: &SigningKey,
) -> Change {
    let (author_seq, author_prev) = next_author_position(&group_id, &device_id);
    let change = Change::create_repair_signed(
        parents,
        max_parent_lamport,
        device_id.clone(),
        author_seq,
        author_prev,
        group_id.clone(),
        HistoryEpoch::Genesis,
        obligations,
        ops,
        signing_key,
    );
    record_author_tip(&group_id, &device_id, change.compute_hash());
    change
}

/// [`Change::create_recursive_part_signed`] with the author sequence
/// allocated by [`next_author_seq`], on a group's original history.
pub fn create_recursive_part_for_tests(
    parents: Vec<ChangeHash>,
    max_parent_lamport: u64,
    device_id: DeviceId,
    group_id: FolderGroupId,
    recursive_operation: RecursiveOperation,
    ops: Vec<Op>,
    signing_key: &SigningKey,
) -> Change {
    let (author_seq, author_prev) = next_author_position(&group_id, &device_id);
    let change = Change::create_recursive_part_signed(
        parents,
        max_parent_lamport,
        device_id.clone(),
        author_seq,
        author_prev,
        group_id.clone(),
        HistoryEpoch::Genesis,
        recursive_operation,
        ops,
        signing_key,
    );
    record_author_tip(&group_id, &device_id, change.compute_hash());
    change
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_author_gets_its_own_consecutive_sequence() {
        let group = FolderGroupId("seq-allocator-group".into());
        let a = DeviceId("seq-allocator-a".into());
        let b = DeviceId("seq-allocator-b".into());

        assert_eq!(next_author_seq(&group, &a), AuthorSeq(1));
        assert_eq!(next_author_seq(&group, &b), AuthorSeq(1));
        assert_eq!(next_author_seq(&group, &a), AuthorSeq(2));
        assert_eq!(next_author_seq(&group, &b), AuthorSeq(2));
    }

    #[test]
    fn the_same_author_in_another_group_starts_over() {
        let a = DeviceId("seq-allocator-scoped".into());
        let one = FolderGroupId("seq-allocator-group-one".into());
        let two = FolderGroupId("seq-allocator-group-two".into());

        assert_eq!(next_author_seq(&one, &a), AuthorSeq(1));
        assert_eq!(next_author_seq(&two, &a), AuthorSeq(1));
        assert_eq!(next_author_seq(&one, &a), AuthorSeq(2));
    }

    #[test]
    fn each_change_names_the_one_this_author_built_before_it() {
        reset_author_sequences();
        let group = FolderGroupId("seq-allocator-prev".into());
        let device = DeviceId("seq-allocator-prev-device".into());
        let key = SigningKey::from_bytes(&[7u8; 32]);

        let first = create_signed_for_tests(vec![], 0, device.clone(), group.clone(), vec![], &key);
        let second = create_signed_for_tests(
            vec![first.compute_hash()],
            first.lamport,
            device.clone(),
            group.clone(),
            vec![],
            &key,
        );

        assert_eq!(first.author_seq, AuthorSeq(1));
        assert_eq!(first.author_prev, None, "an author's first change has no predecessor");
        assert_eq!(second.author_seq, AuthorSeq(2));
        assert_eq!(second.author_prev, Some(first.compute_hash()));
    }

    #[test]
    fn a_second_authors_link_is_its_own_and_not_the_first_authors() {
        reset_author_sequences();
        let group = FolderGroupId("seq-allocator-prev-two".into());
        let a = DeviceId("seq-allocator-prev-a".into());
        let b = DeviceId("seq-allocator-prev-b".into());
        let key = SigningKey::from_bytes(&[8u8; 32]);

        let a1 = create_signed_for_tests(vec![], 0, a.clone(), group.clone(), vec![], &key);
        let b1 = create_signed_for_tests(
            vec![a1.compute_hash()],
            a1.lamport,
            b.clone(),
            group.clone(),
            vec![],
            &key,
        );
        let b2 = create_signed_for_tests(
            vec![b1.compute_hash()],
            b1.lamport,
            b.clone(),
            group.clone(),
            vec![],
            &key,
        );

        // b's first change has a DAG parent but no author predecessor: the
        // two links answer different questions.
        assert_eq!(b1.author_prev, None);
        assert_eq!(b2.author_prev, Some(b1.compute_hash()));
    }
}
