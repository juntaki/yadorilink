//! Regression coverage for the signed causal dot and the per-author chain state.
//!
//! A change's causal dot is `(group_id, device_id, author_seq)`. The author
//! identity is the device id: the coordination plane issues a device id per
//! registration and binds that device's signing key to it set-once, so a key
//! change or a recovery is a new device, not a new name for the old one. A
//! locally generated author identity would carry no such binding — an author
//! holding the signing key could mint a fresh one at will, and a clone that
//! copied the device record would copy it too — so there is none.
//!
//! `author_seq` is NOT the Lamport clock and NEVER resets: not at a
//! `HistoryBase` switch, not at a re-bootstrap, not at a compaction. Resetting
//! it would make the per-author high-water mark unsound, which is exactly the
//! `same_dot_breaks_membership` counterexample: a watermark would then claim a
//! replica holds a change it has never seen.
//!
//! Per-author retained state is `(watermark, tip)` — the highest sequence the
//! author reached, and the change that attained it. The watermark alone buys
//! only arithmetic, and arithmetic alone is `bare_increment_breaks_membership`.
//! The tip is what makes the check causal.
//!
//! Admission order is fixed, and these tests pin it in this order:
//!
//! 1. an identical `ChangeHash` already present is an idempotent no-op,
//!    decided BEFORE any author-chain validation;
//! 2. missing DAG parents go to the existing ordinary orphan buffer;
//! 3. author state is consulted only once every parent is present;
//! 4. `seq == 1`, or `seq == W + 1` together with an `author_prev` that IS
//!    the author's current tip, admits;
//! 5. every parent present but `seq > W + 1` is HELD when the `author_prev`
//!    it names has not arrived, and refused when the gap is already decided
//!    — see below;
//! 6. `seq == W + 1` naming anything other than the tip is refused;
//! 7. the same `(group_id, device_id, author_seq)` carrying a different
//!    `ChangeHash` is equivocation and is refused.
//!
//! Item 5 is where author ordering stops resembling ancestry, and it has to
//! be read with that in mind. An earlier form of this rule refused every
//! sequence gap outright, on the argument that a genuinely-undelivered
//! predecessor would leave a hole in the DAG ancestry too, so the ordinary
//! orphan buffer would have stopped the change first. That argument depends
//! on `A:n` causally preceding `A:n+1`, and the author link does not give
//! that — it is exactly what the link replaced. `A:n+1` is parented on the
//! basis its author edited, which is routinely older than, and never
//! required to descend, `A:n`. So an author's changes really can arrive
//! with every DAG parent present and the predecessor still in flight, and
//! refusing that would refuse a valid change permanently for being early.
//!
//! What holds it is the orphan buffer that already exists, not a second
//! mechanism: a buffered change waits on the names it carries and has not
//! got, and `author_prev` is one of those names alongside the parents. The
//! gap refusal is kept for the gaps that are decided and cannot become
//! undecided — a change past the first that names no predecessor at all,
//! and one whose named predecessor is already here, whose own position is
//! therefore known and contradicts the claimed sequence.
//!
//! The author link is an IDENTITY, not an ancestry. A change carries a
//! signed `author_prev` naming the change its author wrote just before it,
//! and admission compares that name against the stored tip. It never asks
//! whether the change descends its author's tip in the DAG, because DAG
//! parents answer a different question: they are the basis the author
//! actually edited, and an ordinary local edit is routinely parented on an
//! earlier change of its own while its author has since written others
//! elsewhere. Requiring DAG descent would refuse that edit on every replica
//! but the one that wrote it. What the chain has to give is that an author's
//! admitted changes are prefix-closed under the author link; the link alone
//! gives that.
//!
//! Equivocation and forked author history are outside the merge domain. They
//! fail closed and are never reconciled: there is no rule that lets one
//! through and discovers the problem later.
//!
//! ## What each test pins
//!
//! Every test exercises the author-chain admission surface:
//!
//! * `yadorilink_replica_domain::ids::AuthorSeq`;
//! * `Change::author_seq`, signed and carried in the canonical encoding
//!   immediately after `device_id`, with `Change::create_signed` taking it in
//!   that same position;
//! * the `author_chain_state(group_id, device_id, watermark, tip_change_hash)`
//!   table, written in the SAME transaction that admits the change;
//! * `AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal)` with the variants
//!   `AuthorEquivocation`, `ForkedAuthorHistory`, `AuthorSequenceGap` and
//!   `AuthorPrevMismatch`.
//!
//! Each test's own doc comment states which store behaviour it rules out. A
//! store without a per-author sequence would, for example:
//!
//! * admit a second change from the same device at a dot the store already
//!   holds — nothing would compare dots (`same_dot_with_a_different_hash
//!   _is_refused_as_equivocation`);
//! * admit a change that names an earlier change of its own author instead of
//!   that author's latest as an ordinary concurrent branch — nothing would
//!   consult a tip
//!   (`seq_w_plus_one_that_names_an_earlier_change_of_its_own_is_refused`).
//!
//! `missing_parent_holds_a_later_seq_change_in_the_ordinary_orphan_buffer`
//! pins the buffer's existing behaviour for a missing DAG parent, which is
//! the mechanism the author chain reuses rather than duplicates. It is NOT
//! evidence that a missing parent covers a missing author predecessor: those
//! are different sets, and
//! `a_gap_whose_author_predecessor_has_not_arrived_is_held_and_later_promoted`
//! is the one that pins the case only the author link can produce.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::compaction::Checkpoint;
use yadorilink_sync_sqlite::dag_store::{
    admit_change, commit_prune, has_change, has_change_or_buffered_orphan, init_dag_schema,
    missing_ancestor_frontier, AdmitOutcome, AdmitResult, AuthorChainRefusal, PathRefusal,
};

const GROUP: &str = "author-chain-group";

fn conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    conn
}

fn key(device: u8) -> SigningKey {
    SigningKey::from_bytes(&[device; 32])
}

/// A `Delete`-only change, so admission needs no file versions and no block
/// store: the author chain is the only thing under test here.
///
/// `prev` and `parents` are separate arguments because they are separate
/// relations: `prev` is the change this author wrote just before this one
/// (author ordering), `parents` is the causal basis this change was written
/// on (what it means for a path). Real local edits routinely have a `prev`
/// that is not among their `parents`.
fn change(
    device: u8,
    seq: u64,
    group: &str,
    prev: Option<&Change>,
    parents: &[&Change],
    path: &str,
) -> Change {
    change_on(HistoryEpoch::Genesis, device, seq, group, prev, parents, path)
}

/// The same, on a named history. A store with a base installed admits only
/// changes written on that base, so a test that installs one authors
/// through here.
#[allow(clippy::too_many_arguments)]
fn change_on(
    epoch: HistoryEpoch,
    device: u8,
    seq: u64,
    group: &str,
    prev: Option<&Change>,
    parents: &[&Change],
    path: &str,
) -> Change {
    let mut parent_hashes: Vec<ChangeHash> = parents.iter().map(|p| p.compute_hash()).collect();
    parent_hashes.sort();
    let max_parent_lamport = parents.iter().map(|p| p.lamport).max().unwrap_or(0);
    Change::create_signed(
        parent_hashes,
        max_parent_lamport,
        DeviceId(format!("device-{device}")),
        AuthorSeq(seq),
        prev.map(|prev| prev.compute_hash()),
        FolderGroupId(group.to_owned()),
        epoch,
        vec![Op::Delete { path: SyncPath(path.to_owned()) }],
        &key(device),
    )
}

/// Installs `base` as `group`'s history base, the way a committed
/// compaction of everything this replica holds would leave it: the base
/// carries the greatest Lamport value the group reached, and every author's
/// current position, which the next change of each author continues from
/// the base rather than from the change that attained it.
///
/// Anchoring every author unconditionally is faithful only to that full
/// compaction. A real install anchors an author only when the base carries
/// exactly the position held here; a test that needs a base carrying less
/// than this replica holds must not use this helper.
fn install_base(conn: &Connection, group: &str, base: HistoryBase) {
    conn.execute(
        "INSERT OR REPLACE INTO group_history_bases \
         (group_id, history_base, checkpoint_hash, previous_checkpoint_hash) \
         VALUES (?1, ?2, ?3, NULL)",
        rusqlite::params![group, &base.0[..], &[0x7fu8; 32][..]],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO history_base_meta (group_id, base_hash, lamport_ceiling) \
         SELECT ?1, ?2, COALESCE(MAX(lamport), 0) FROM changes WHERE group_id = ?1",
        rusqlite::params![group, &base.0[..]],
    )
    .unwrap();
    conn.execute(
        "UPDATE author_chain_state SET anchor_base = ?2 WHERE group_id = ?1",
        rusqlite::params![group, &base.0[..]],
    )
    .unwrap();
}

fn admit(conn: &Connection, change: &Change) -> AdmitResult {
    admit_change(conn, change).unwrap()
}

fn admit_expecting_applied(conn: &Connection, change: &Change, what: &str) {
    let result = admit(conn, change);
    assert!(
        matches!(result.outcome, AdmitOutcome::Applied),
        "{what}: expected admission, got {:?}",
        result.outcome
    );
}

/// The author's `(watermark, tip)`, or `None` when the author has written
/// nothing in this group. Read straight from the table so these tests pin the
/// persisted state itself, not an accessor's view of it.
fn author_state(conn: &Connection, device: u8, group: &str) -> Option<(u64, ChangeHash)> {
    conn.query_row(
        "SELECT watermark, tip_change_hash FROM author_chain_state \
         WHERE group_id = ?1 AND device_id = ?2",
        rusqlite::params![group, format!("device-{device}")],
        |row| {
            let watermark: i64 = row.get(0)?;
            let tip: Vec<u8> = row.get(1)?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&tip);
            Ok((watermark as u64, ChangeHash(bytes)))
        },
    )
    .ok()
}

fn is_buffered_orphan(conn: &Connection, hash: &ChangeHash) -> bool {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM orphan_changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    count > 0
}

fn admitted_count(conn: &Connection, group: &str) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM changes WHERE group_id = ?1", [group], |row| row.get(0))
        .unwrap()
}

// --- 1. equivocation -------------------------------------------------------

/// Pins the `dot_inj` half of admission — two admitted changes of the same
/// scoped author at the same sequence must be the same change — and the
/// `same_dot_breaks_membership` counterexample that says what reusing a dot
/// costs: the watermark stops deciding membership, so a replica claims to hold
/// content it has never seen.
///
/// Without a dot comparison both changes would be admitted as two ordinary
/// parentless roots of the same group; with `author_seq` carried but no rule
/// enforced, the second admission would return `Applied` instead of refusing.
#[test]
fn same_dot_with_a_different_hash_is_refused_as_equivocation() {
    let conn = conn();
    let first = change(1, 1, GROUP, None, &[], "first.bin");
    admit_expecting_applied(&conn, &first, "the author's first change");

    let forged = change(1, 1, GROUP, None, &[], "forged.bin");
    assert_ne!(first.compute_hash(), forged.compute_hash(), "the two changes must differ");

    let result = admit(&conn, &forged);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorEquivocation { .. })
        ),
        "a second change at a dot the store already holds is equivocation, got {:?}",
        result.outcome
    );
    assert!(
        !is_buffered_orphan(&conn, &forged.compute_hash()),
        "equivocation fails closed; it is never held for later reconsideration"
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((1, first.compute_hash())),
        "a refused change must not move the author's watermark or tip"
    );
}

// --- 2. a sequence gap is refused, not held --------------------------------

/// Pins the `beyond` rule read strictly: admission requires `seq == W + 1`,
/// not `seq > W`. A change at `W + 2` is refused outright HERE, and the
/// reason is not the skip on its own — it is that this change's own signed
/// bytes already settle the question.
///
/// It names `first` as the change its author wrote just before it, and
/// `first` is admitted, standing at sequence 1. A change that followed
/// sequence 1 is sequence 2. Nothing that could still arrive changes what
/// `first`'s position is, so there is nothing to wait for and no later
/// delivery that could make this admissible.
///
/// Contrast the companion test below, where the named predecessor has NOT
/// arrived: there the same arithmetic gap is held instead, because then the
/// change may simply be early. The distinction is the whole content of the
/// rule; the skip alone is not.
///
/// Without a per-author sequence the change would be admitted as an ordinary
/// child of an admitted parent.
#[test]
fn all_parents_present_but_seq_is_w_plus_2_is_rejected_not_orphaned() {
    let conn = conn();
    let first = change(1, 1, GROUP, None, &[], "first.bin");
    admit_expecting_applied(&conn, &first, "the author's first change");

    // Every parent is present: this change descends the author's own tip.
    // Only its sequence skips one.
    let skipping = change(1, 3, GROUP, Some(&first), &[&first], "skipping.bin");
    let result = admit(&conn, &skipping);

    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "a complete-ancestry change past W+1 is refused, got {:?}",
        result.outcome
    );
    assert!(
        !is_buffered_orphan(&conn, &skipping.compute_hash()),
        "a gap whose named predecessor is already here is decided now: holding it would \
         wait for something that has already arrived"
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((1, first.compute_hash())),
        "a refused change must not move the author's watermark or tip"
    );
}

/// The buffer's existing behaviour for a missing DAG parent, pinned as the
/// mechanism the author link reuses.
///
/// Here the author's intervening change is also this change's parent, so
/// the ancestry is incomplete and admission stops before the author state
/// is consulted at all. That covers only the changes whose predecessor
/// happens to be an ancestor — a strictly smaller set than "the author's
/// predecessor is missing", which is why the test below exists as well.
///
/// This pins existing orphan-buffer behaviour rather than an author-chain
/// rule.
#[test]
fn missing_parent_holds_a_later_seq_change_in_the_ordinary_orphan_buffer() {
    let conn = conn();
    let first = change(1, 1, GROUP, None, &[], "first.bin");
    admit_expecting_applied(&conn, &first, "the author's first change");

    // `second` is never delivered. `third` descends it, so its ancestry is
    // incomplete and admission stops before it ever looks at the author state.
    let second = change(1, 2, GROUP, Some(&first), &[&first], "second.bin");
    let third = change(1, 3, GROUP, Some(&second), &[&second], "third.bin");

    let result = admit(&conn, &third);
    assert!(
        matches!(result.outcome, AdmitOutcome::Orphaned),
        "a change whose parent has not arrived is an ordinary orphan, got {:?}",
        result.outcome
    );
    assert!(
        is_buffered_orphan(&conn, &third.compute_hash()),
        "the ordinary orphan buffer must hold it until its ancestry completes"
    );

    // And it promotes normally once the gap is filled, still in sequence.
    admit_expecting_applied(&conn, &second, "the intervening change arriving late");
    assert!(
        !is_buffered_orphan(&conn, &third.compute_hash()),
        "the held change must be promoted when its parent arrives"
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((3, third.compute_hash())),
        "promotion advances the author chain through both changes, in order"
    );
}

/// The case the missing-parent test above does NOT cover, and the one that
/// only exists because author ordering is not ancestry.
///
/// One device, two paths. A:1 places `doc.txt`. A:2 writes the unrelated
/// `other.txt`. A:3 edits `doc.txt` again, and is parented on A:1 — the
/// basis its bytes actually came from — not on A:2, because claiming A:2 as
/// an ancestor would assert the user saw and overwrote that write. So A:3
/// names A:2 as its author's previous change while descending only A:1.
///
/// A peer that receives A:1 and A:3 but not yet A:2 therefore has every one
/// of A:3's DAG parents and none of the hole the old rule assumed would be
/// there. Refusing A:3 would refuse a perfectly ordinary edit permanently,
/// on every replica that happened to receive the two changes out of order,
/// and the refusal is recorded so the change would never be asked for
/// again. It is held instead, and admitted the moment A:2 lands.
#[test]
fn a_gap_whose_author_predecessor_has_not_arrived_is_held_and_later_promoted() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1 placing doc.txt");

    // A:2 is written but not delivered yet.
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "other.txt");
    // A:3 edits doc.txt on the basis of A:1 and names A:2 as its
    // predecessor. Every DAG parent it has is already admitted.
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(
        !a3.parents.contains(&a2.compute_hash()),
        "the edit must not claim its author's previous change as a causal parent"
    );

    let result = admit(&conn, &a3);
    assert!(
        matches!(result.outcome, AdmitOutcome::Orphaned),
        "a change whose author predecessor has not arrived is early, not broken, got {:?}",
        result.outcome
    );
    assert!(
        is_buffered_orphan(&conn, &a3.compute_hash()),
        "it must be held in the one orphan buffer, against the name it is waiting on"
    );
    assert!(
        !has_change_or_buffered_orphan(&conn, &a2.compute_hash()).unwrap(),
        "sanity: the predecessor really is one this replica does not have"
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((1, a1.compute_hash())),
        "a held change must not move the author's watermark or tip"
    );

    // Holding is only safe if the held change's own missing name is asked
    // for. Nothing else would ask: A:2 is reachable through no parent edge,
    // because it is not an ancestor of anything here.
    let wanted = missing_ancestor_frontier(&conn, [a3.compute_hash()]).unwrap();
    assert!(
        wanted.contains(&a2.compute_hash()),
        "the author predecessor a held change waits on must be re-requested, got {wanted:?}"
    );

    let result = admit(&conn, &a2);
    assert!(matches!(result.outcome, AdmitOutcome::Applied), "got {:?}", result.outcome);
    assert!(
        result.newly_admitted.contains(&a3.compute_hash()),
        "the held change is promoted in the same admission that supplies its predecessor"
    );
    assert!(!is_buffered_orphan(&conn, &a3.compute_hash()));
    assert!(has_change(&conn, &a3.compute_hash()).unwrap());
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((3, a3.compute_hash())),
        "the chain advances through both, in order, once the gap is filled"
    );
}

/// The gap that stays refused even with no author state at all: a change
/// claiming a position past the first while naming no predecessor.
///
/// Holding is for a change waiting on a name. This one declines to give a
/// name, so nothing could ever arrive to satisfy it, and buffering it would
/// occupy the bounded buffer until eviction and mark the hash as known so
/// it was never re-requested — refusing to decide, at a cost.
#[test]
fn a_position_past_the_first_that_names_no_predecessor_is_refused_not_held() {
    let conn = conn();
    let nameless = change(1, 4, GROUP, None, &[], "nameless.bin");
    let result = admit(&conn, &nameless);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "got {:?}",
        result.outcome
    );
    assert!(!is_buffered_orphan(&conn, &nameless.compute_hash()));
    assert_eq!(author_state(&conn, 1, GROUP), None);
}

/// An author this replica has never seen, arriving mid-chain: held, not
/// refused, and not taken on faith either.
///
/// The old rule refused this on the ground that an unknown author may only
/// take the first position — but "unknown here" and "has not written" are
/// the same statement only when delivery is ordered, and it is not. The
/// sequence it claims is still never believed: it buys nothing while held,
/// and when the named predecessor lands the position is measured against
/// the state that predecessor established.
#[test]
fn an_unknown_author_arriving_mid_chain_is_held_until_its_predecessor_lands() {
    let conn = conn();
    let b1 = change(2, 1, GROUP, None, &[], "b1.bin");

    // B:2 must have complete DAG ancestry while its predecessor is absent,
    // so it is parented on another device's change rather than on B:1.
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let b2_on_a1 = change(2, 2, GROUP, Some(&b1), &[&a1], "b2-on-a1.bin");

    let result = admit(&conn, &b2_on_a1);
    assert!(
        matches!(result.outcome, AdmitOutcome::Orphaned),
        "an unknown author's second change with complete ancestry is early, got {:?}",
        result.outcome
    );
    assert_eq!(author_state(&conn, 2, GROUP), None, "nothing about the claim is recorded yet");

    admit_expecting_applied(&conn, &b1, "B:1 arriving late");
    assert_eq!(
        author_state(&conn, 2, GROUP),
        Some((2, b2_on_a1.compute_hash())),
        "the held change is promoted once its predecessor establishes the position"
    );
}

// --- 3/4. the author link is an identity, not an ancestry ------------------

/// `seq == W + 1` on its own is not admissible. A change at the right
/// sequence that names an EARLIER change of its own author, abandoning that
/// author's tip, has no admission step at all — it is refused, not absorbed
/// as a concurrent branch.
///
/// Note what is and is not being asked. The question is whether the change
/// NAMES its author's tip, not whether it descends it in the DAG: those are
/// different relations, and only the first one is the author chain's
/// business. The companion test below builds a change that does not descend
/// its author's tip at all and must still admit.
#[test]
fn seq_w_plus_one_that_names_an_earlier_change_of_its_own_is_refused() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    let b1 = change(2, 1, GROUP, None, &[&a1], "b1.bin");
    admit_expecting_applied(&conn, &b1, "B:1 branching off A:1");

    // The right sequence, naming A:1 and so abandoning A:2.
    let a3 = change(1, 3, GROUP, Some(&a1), &[&b1], "a3.bin");
    let result = admit(&conn, &a3);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "the right sequence naming the wrong previous change of its own is refused, got {:?}",
        result.outcome
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((2, a2.compute_hash())),
        "a refused change must not move the author's watermark or tip"
    );
}

/// An author-chain refusal on the main remote admission path is durable.
///
/// "Final" has to mean something operationally, not only in a comment.
/// Nothing decides whether to keep asking a peer for a hash except whether
/// that hash is in retained history, in the orphan buffer, or in the
/// durable rejection record — so a refusal that wrote none of the three is
/// re-requested at every heads exchange and refused again each time, in a
/// loop with no exit.
///
/// This is the path a peer's change actually takes on a running daemon:
/// the coordinator's admission port lands in `admit_change`. The staged
/// bundle path and orphan promotion recorded their refusals; this one did
/// not, which is exactly the kind of difference a shared boundary exists
/// to prevent.
#[test]
fn an_author_chain_refusal_is_recorded_durably_and_never_re_requested() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    let forking = change(1, 3, GROUP, Some(&a1), &[&a1], "forking.bin");
    let hash = forking.compute_hash();
    assert!(
        !has_change_or_buffered_orphan(&conn, &hash).unwrap(),
        "sanity: before the refusal this hash is simply one we have not received"
    );

    let result = admit(&conn, &forking);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "got {:?}",
        result.outcome
    );

    assert!(!has_change(&conn, &hash).unwrap(), "the refused change is not retained");
    assert!(!is_buffered_orphan(&conn, &hash), "and it is not held for a retry");
    assert!(
        has_change_or_buffered_orphan(&conn, &hash).unwrap(),
        "yet it is settled: a peer must not be asked for it again"
    );
}

/// The same durability for the other final verdict, so the two cannot
/// drift apart: a change written on a history this replica is not on is
/// refused once and recorded, rather than re-requested forever.
#[test]
fn a_foreign_history_refusal_is_recorded_durably_too() {
    let conn = conn();
    install_base(&conn, GROUP, HistoryBase([0x11u8; 32]));

    let foreign =
        change_on(HistoryEpoch::Base(HistoryBase([0x22u8; 32])), 1, 1, GROUP, None, &[], "f.bin");
    let hash = foreign.compute_hash();
    let result = admit(&conn, &foreign);
    assert!(
        matches!(result.outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }),
        "got {:?}",
        result.outcome
    );
    assert!(!has_change(&conn, &hash).unwrap());
    assert!(!is_buffered_orphan(&conn, &hash));
    assert!(
        has_change_or_buffered_orphan(&conn, &hash).unwrap(),
        "a change from another history is settled, not merely not-yet-received"
    );
}

/// A foreign-history verdict is a verdict about the history this replica is
/// on, not about the change alone. A change that arrives from a history this
/// replica has not switched to yet is settled as foreign for as long as the
/// replica stays where it is; once it installs that history, the same
/// change is ordinary history and must be asked for again, or it and every
/// change behind it stay excluded on a verdict that no longer holds.
#[test]
fn a_foreign_history_refusal_lapses_once_this_replica_installs_that_history() {
    let conn = conn();
    let h1 = HistoryBase([0x11u8; 32]);
    let h2 = HistoryBase([0x22u8; 32]);
    install_base(&conn, GROUP, h1);

    let c = change_on(HistoryEpoch::Base(h2), 2, 1, GROUP, None, &[], "c.bin");
    let d = change_on(HistoryEpoch::Base(h2), 2, 2, GROUP, Some(&c), &[&c], "d.bin");
    for early in [&c, &d] {
        assert!(
            matches!(admit(&conn, early).outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }),
            "while this replica is on H1, a change written on H2 is foreign"
        );
    }
    assert!(has_change_or_buffered_orphan(&conn, &c.compute_hash()).unwrap());

    install_base(&conn, GROUP, h2);

    assert!(
        !has_change_or_buffered_orphan(&conn, &c.compute_hash()).unwrap(),
        "the refusal was measured against H1, which this replica is no longer on"
    );
    assert_eq!(
        missing_ancestor_frontier(&conn, [d.compute_hash()]).unwrap(),
        vec![d.compute_hash()],
        "so the H2 change is asked for again"
    );
    admit_expecting_applied(&conn, &c, "C on the now-installed history");
    admit_expecting_applied(&conn, &d, "D behind it");
}

/// The shape the separation exists for, and the exact shape an ancestry
/// rule refused: an ordinary local edit authored onto the basis its own
/// bytes came from.
///
/// One device, two paths, no concurrency and no peer. A1 places `doc.txt`
/// and is that path's materialized basis. The same device then writes
/// `other.txt`, producing A2 — now its tip. Then it edits `doc.txt`, whose
/// bytes still come from A1, so the edit is parented on A1 and is NOT a
/// descendant of A2. Parenting it on A2 instead would assert the user saw
/// and overwrote the `other.txt` write, which is a silent lost update — so
/// the parent choice is correct and is not up for negotiation.
///
/// The edit names A2 as its author's previous change, because it is, and a
/// peer holding A1 and A2 admits it. Under an ancestry rule this same
/// change was signed locally and refused permanently by every other
/// replica.
#[test]
fn a_local_edit_onto_its_own_earlier_basis_is_admitted_by_a_peer_holding_the_tip() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1 placing doc.txt");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "other.txt");
    admit_expecting_applied(&conn, &a2, "A:2 writing an unrelated path");

    let local_edit = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(
        !local_edit.parents.contains(&a2.compute_hash()),
        "the edit must not claim its author's tip as a causal parent"
    );
    admit_expecting_applied(&conn, &local_edit, "an edit onto the basis its bytes came from");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((3, local_edit.compute_hash())),
        "the ordinary edit advances its author's chain like any other change"
    );
}

/// The other side of the same rule: the author's next change names no
/// parent of its own authorship at all. Its only DAG parent is another
/// device's change, and it names its own tip as its predecessor.
///
/// This is the ordinary shape of a device continuing after merging a peer's
/// work, and it admits — which is what it means for the author link to be an
/// identity rather than an ancestry. Any check phrased over the direct
/// parent edge would refuse it.
#[test]
fn a_change_whose_only_parent_is_another_device_still_names_its_own_tip() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    let b1 = change(2, 1, GROUP, None, &[&a2], "b1.bin");
    admit_expecting_applied(&conn, &b1, "B:1 on top of A:2");
    let b2 = change(2, 2, GROUP, Some(&b1), &[&b1], "b2.bin");
    admit_expecting_applied(&conn, &b2, "B:2");

    // A:3's only parent is B:2. A:2 is nowhere among its parents.
    let a3 = change(1, 3, GROUP, Some(&a2), &[&b2], "a3.bin");
    assert!(!a3.parents.contains(&a2.compute_hash()), "A:2 must not be a direct parent here");

    admit_expecting_applied(&conn, &a3, "A:3 naming its tip while parented elsewhere");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((3, a3.compute_hash())),
        "admission advances the author's watermark and tip together with the change"
    );
}

// --- 5. no reset at a HistoryBase switch -----------------------------------

/// Pins the rule that the author sequence does not reset at a `HistoryBase`
/// switch. A `HistoryBase` appears nowhere in the admission rule, deliberately:
/// the sequence is independent of the Lamport clock, which may restart per
/// epoch. Resetting it is `same_dot_breaks_membership` — the watermark would
/// then name a dot the replica does not hold.
///
/// The reset change is checked only for being refused, not for which refusal: a replica that
/// still holds the colliding change sees equivocation, while one that has
/// compacted it away and kept only `(watermark, tip)` sees a forked author
/// history. Both fail closed, and which one is reached depends on retained
/// history rather than on this rule.
#[test]
fn author_seq_does_not_reset_at_a_history_base_switch() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    // The group crosses a history-base boundary, so everything after it is
    // written on the new base.
    let base = HistoryBase(a2.compute_hash().0);
    install_base(&conn, GROUP, base);
    let epoch = HistoryEpoch::Base(base);

    let restarted = change_on(epoch, 1, 1, GROUP, None, &[&a2], "restarted.bin");
    let result = admit(&conn, &restarted);
    assert!(
        matches!(result.outcome, AdmitOutcome::RefusedAuthorChain(_)),
        "the author sequence must not restart across a history-base switch, got {:?}",
        result.outcome
    );
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((2, a2.compute_hash())),
        "the refused restart must not move the author's watermark or tip"
    );

    // Continuing the sequence across the boundary is the admissible form.
    // The base absorbed A:2, so A:3 continues the base: it names no
    // predecessor, and its signed history epoch is the link.
    let reaching_back = change_on(epoch, 1, 3, GROUP, Some(&a2), &[&a2], "a3-back.bin");
    assert!(
        matches!(
            admit(&conn, &reaching_back).outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "the first change above the base does not name the change the base absorbed"
    );
    let a3 = change_on(epoch, 1, 3, GROUP, None, &[&a2], "a3.bin");
    admit_expecting_applied(&conn, &a3, "A:3 continuing across the boundary");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((3, a3.compute_hash())),
        "the sequence continues from the watermark the boundary preserved"
    );
}

/// An installed base does not make an unknown author's own claim about its
/// position true.
///
/// A device whose changes this replica has never held has no retained
/// position here. Taking the first change it happens to see as that position
/// means whichever change arrives first names the watermark — any sequence at
/// all, chosen by the author — and everything below it is then treated as
/// history this replica has already absorbed. That is not a weaker check; it
/// is no check, and it is the one thing the watermark may never be: a number
/// nobody attested.
///
/// The position of every author an installed base retains has to come from
/// the base itself, carried in the snapshot and restored before any change is
/// measured against it.
///
/// Here the claim is refused rather than held, and the difference from
/// `an_unknown_author_arriving_mid_chain_is_held_until_its_predecessor_lands`
/// is the name this change carries: it names a change this replica already
/// holds, standing at sequence 1, and then numbers itself 9. Nothing can
/// arrive to reconcile that. A change naming a predecessor this replica
/// does not have is a different situation and waits — but it waits without
/// its sequence being believed for anything, which is the part that matters
/// here: nothing about the claim is recorded while it waits.
#[test]
fn an_installed_base_does_not_trust_an_unknown_authors_first_observed_sequence() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");

    // The group carries an installed history base.
    let base = HistoryBase(a1.compute_hash().0);
    install_base(&conn, GROUP, base);

    // Device 2 has no retained position in this group, and the base carries
    // none for it. Its first observed change names a sequence far above any
    // history this replica can account for.
    let unattested =
        change_on(HistoryEpoch::Base(base), 2, 9, GROUP, Some(&a1), &[&a1], "unattested.bin");
    let result = admit(&conn, &unattested);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "an author with no position carried by the base names its own sequence; that claim is \
         refused, not adopted, got {:?}",
        result.outcome
    );
    assert_eq!(
        author_state(&conn, 2, GROUP),
        None,
        "a refused change must not establish a position for its author"
    );
    assert!(
        !is_buffered_orphan(&conn, &unattested.compute_hash()),
        "the refusal is final: nothing later could make an unattested sequence admissible"
    );
}

// --- 6. the dot is group-scoped --------------------------------------------

/// Pins the group component of the dot. Dropping it makes the admission model
/// unsatisfiable — that is `no_dotted_for_unscoped_author` — so the scoped
/// author is `(group_id, device_id)` and one device's sequence in one group
/// says nothing about its sequence in another.
///
/// Pins that the per-author sequence is scoped per group.
#[test]
fn author_seq_is_scoped_per_group() {
    let conn = conn();
    let other_group = "author-chain-group-other";

    let g1a1 = change(1, 1, GROUP, None, &[], "g1a1.bin");
    admit_expecting_applied(&conn, &g1a1, "device 1's first change in the first group");
    let g1a2 = change(1, 2, GROUP, Some(&g1a1), &[&g1a1], "g1a2.bin");
    admit_expecting_applied(&conn, &g1a2, "device 1's second change in the first group");

    // The same device starts again at 1 in a different group. The first
    // group's watermark of 2 must not make this a reused dot.
    let g2a1 = change(1, 1, other_group, None, &[], "g2a1.bin");
    admit_expecting_applied(&conn, &g2a1, "device 1's first change in the second group");

    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((2, g1a2.compute_hash())),
        "the first group's author state is untouched by the second group's admission"
    );
    assert_eq!(
        author_state(&conn, 1, other_group),
        Some((1, g2a1.compute_hash())),
        "each group keeps its own author state for the same device"
    );
}

// --- 7. a fresh author starts at 1 -----------------------------------------

/// Pins the left disjunct of `extends_tip`: `seq == 1` needs no tip, because
/// the author has none. A newly registered device — which is what a signing-key
/// change or a recovery produces, since the key is bound to the device id
/// set-once — begins its own chain at 1 in a group that already has history.
///
/// Pins that author state is created on a device's first change.
#[test]
fn a_newly_registered_device_starts_its_chain_at_seq_one() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "the existing author's change");

    assert_eq!(author_state(&conn, 2, GROUP), None, "a device that has written nothing has no tip");

    let b1 = change(2, 1, GROUP, None, &[&a1], "b1.bin");
    admit_expecting_applied(&conn, &b1, "a newly registered device's first change");
    assert_eq!(
        author_state(&conn, 2, GROUP),
        Some((1, b1.compute_hash())),
        "the new author's chain starts at 1 with its own tip"
    );

    // Its second change is then bound by the ordinary rule.
    let b3 = change(2, 3, GROUP, Some(&b1), &[&b1], "b3.bin");
    let result = admit(&conn, &b3);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "a new author gets no exemption from the successor rule, got {:?}",
        result.outcome
    );
}

// --- 8. a returning offline branch -----------------------------------------

/// Pins `valid_returning_branch`: a device that went offline before a seal
/// comes back with its own continuation of its author chain, and the WHOLE
/// branch is admissible from the retained `(watermark, tip)` alone — the
/// sealed prefix before it is never consulted.
///
/// To actually exercise that claim, A:1 is pruned out of `changes` before the
/// branch is admitted, the way real compaction retires a sealed prefix, so
/// this test cannot be passing merely because the prefix is still sitting in
/// the table. A:2's own row is deliberately left in place: A:2 is the
/// author's tip, and every change here that names a parent has that parent's
/// row walked to verify the edge, so it is the ancestry walk itself — not
/// `author_chain_state` — that still needs A:2 present. What this test shows
/// is narrower than "the whole prefix is unconsulted": only that the prefix
/// *before* the tip is unconsulted, because the tip's row is load-bearing for
/// a different reason than the chain check.
///
/// Pins that the watermark and tip are retained, so a returning branch has
/// something to attach to.
#[test]
fn a_valid_returning_branch_is_admitted_from_the_watermark_and_tip_alone() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    // The rest of the group moved on while device 1 was away.
    let b1 = change(2, 1, GROUP, None, &[&a2], "b1.bin");
    admit_expecting_applied(&conn, &b1, "B:1");

    // Retire A:1 from retained history the way real compaction does. The
    // checkpoint's frontier names A:2 as the retained cut, so a change that
    // still names A:2 as a parent is not a dangling edge into deleted
    // history.
    let checkpoint =
        Checkpoint::new(FolderGroupId(GROUP.into()), vec![a2.compute_hash()], [0x9au8; 32]);
    commit_prune(&conn, &checkpoint, &[a1.compute_hash()]).unwrap();
    assert!(
        !has_change(&conn, &a1.compute_hash()).unwrap(),
        "A:1 must actually be gone from retained history for this test to mean anything"
    );
    assert!(
        has_change(&conn, &a2.compute_hash()).unwrap(),
        "A:2, the author's tip, is left in place on purpose: the ancestry walk needs its row \
         to verify A:3's parent edge, which is a different requirement than what \
         author_chain_state alone supplies"
    );

    // Device 1 returns with a two-change branch of its own, built offline on
    // its own tip, with A:1 already gone from `changes`.
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a2], "a3.bin");
    let a4 = change(1, 4, GROUP, Some(&a3), &[&a3], "a4.bin");

    admit_expecting_applied(&conn, &a3, "the first change of the returning branch");
    admit_expecting_applied(&conn, &a4, "the second change of the returning branch");

    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((4, a4.compute_hash())),
        "the whole returning branch lands, and the author state follows it"
    );
}

// --- 9. exact duplicates are decided first ---------------------------------

/// Pins the ordering rule that an identical `ChangeHash` already present is an
/// idempotent no-op decided BEFORE any author-chain validation. This is not a
/// convenience: a change the replica already holds necessarily sits at or below
/// that author's watermark, so validating it as if it were new would refuse it
/// as a forked history and turn ordinary re-delivery into a fatal verdict.
///
/// The no-op must additionally leave the author state untouched. The
/// re-delivery of a change that is now
/// strictly below the watermark is the case that distinguishes a
/// duplicate-first ordering from a duplicate-later one.
#[test]
fn exact_duplicate_delivery_is_idempotent_and_does_not_advance_the_author_state() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");

    let repeat = admit(&conn, &a1);
    assert!(
        !matches!(repeat.outcome, AdmitOutcome::RefusedAuthorChain(_)),
        "re-delivering a change the replica already holds is a no-op, not a refusal, got {:?}",
        repeat.outcome
    );
    assert_eq!(admitted_count(&conn, GROUP), 1, "a duplicate must not be stored twice");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((1, a1.compute_hash())),
        "a duplicate must not advance the watermark"
    );

    // Now move the author on, and re-deliver the older change. It is strictly
    // below the watermark, so only a duplicate check that runs FIRST keeps
    // this a no-op instead of a forked-history refusal.
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");
    admit_expecting_applied(&conn, &a2, "A:2");

    let stale_repeat = admit(&conn, &a1);
    assert!(
        !matches!(stale_repeat.outcome, AdmitOutcome::RefusedAuthorChain(_)),
        "re-delivering a held change from below the watermark must stay a no-op, got {:?}",
        stale_repeat.outcome
    );
    assert_eq!(admitted_count(&conn, GROUP), 2, "the no-op must not store anything");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((2, a2.compute_hash())),
        "the no-op must not rewind the watermark or the tip"
    );
}

// --- structural: sequences start at 1 --------------------------------------

/// Pins `seq_pos`, the one part of the dot that is checkable on receipt with
/// no history at all: a sequence of 0 is not a sequence. It is refused as a
/// malformed change, well before any store lookup.
///
/// Pins the structural check on the signed field.
#[test]
fn author_seq_zero_is_structurally_invalid() {
    let conn = conn();
    let zeroed = change(1, 0, GROUP, None, &[], "zeroed.bin");
    let error =
        admit_change(&conn, &zeroed).expect_err("a change at sequence 0 must be refused outright");
    assert!(
        !is_buffered_orphan(&conn, &zeroed.compute_hash()),
        "a structurally invalid change is never buffered"
    );
    assert_eq!(author_state(&conn, 1, GROUP), None, "nothing about it reaches the author state");
    let _ = error;
}

// --- startup self-heal ordering --------------------------------------------

/// The startup self-heal rebuilds each author's position from retained
/// history, and it sweeps the orphan buffer for changes whose parents are
/// already durably admitted. The order between those two is not a detail.
///
/// Promotion is an admission, so it applies the author-chain rules, and a
/// refusal there is destructive: the orphan is recorded as permanently
/// rejected and its subtree is dropped. The rebuild exists precisely for the
/// case where `author_chain_state` is missing or behind — so running the
/// sweep first would measure every buffered orphan against a position its
/// author has in fact already passed, refuse each one as a sequence gap, and
/// destroy it moments before the rebuild that would have made it admissible.
///
/// This reproduces that state directly: an author's first change durably
/// admitted, its second buffered as an orphan, and the author's recorded
/// position gone.
#[test]
fn the_startup_sweep_rebuilds_author_state_before_it_judges_buffered_orphans() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "a2.bin");

    // A:2 arrives first and is held for its missing parent.
    assert!(
        matches!(admit(&conn, &a2).outcome, AdmitOutcome::Orphaned),
        "A:2 must be buffered while its parent is missing"
    );
    // A:1 lands without a promotion pass, which is the crash window the
    // startup sweep exists to close.
    yadorilink_sync_sqlite::dag_store::install_canonical_change_only(&conn, &a1).unwrap();
    assert!(is_buffered_orphan(&conn, &a2.compute_hash()), "A:2 is still buffered");

    // The author's recorded position is missing — the case the rebuild is
    // for, and the only case in which the order between the two passes can
    // be observed at all.
    conn.execute("DELETE FROM author_chain_state", []).unwrap();

    init_dag_schema(&conn).unwrap();

    assert!(
        !is_buffered_orphan(&conn, &a2.compute_hash()),
        "the sweep must promote A:2 once the author's position is rebuilt"
    );
    let rejected: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_changes WHERE change_hash = ?1",
            [&a2.compute_hash().0[..]],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        rejected, 0,
        "A:2 is a valid continuation of its author's chain and must never be recorded as \
         permanently rejected"
    );
    assert_eq!(admitted_count(&conn, GROUP), 2, "both changes must be durably admitted");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((2, a2.compute_hash())),
        "the author's position must end up where its retained history says it is"
    );
}

// --- 11. a foreign history base is its own refusal -------------------------

/// A complete, self-consistent history written on another base admits
/// nothing here.
///
/// This is the shape nothing structural objects to. A device that has been
/// away brings back its whole history: a chain whose every parent is
/// present within the bundle itself, whose Lamport values agree with those
/// parents, whose author sequences run 1, 2, 3 from a first change, and
/// whose signatures all verify. Judged by ancestry alone it is a second
/// independent root of this group, and admitting it would splice two
/// histories into one — the local base stands for a prefix these changes
/// never saw, so every path they touch would be resolved against writes
/// that were already superseded.
///
/// What tells them apart is the history each change names in its own
/// signed bytes. It cannot be restated by a relay: rewriting it changes
/// the change hash and breaks the signature. So the verdict is available
/// from the first change, it is the same for every change behind it, and
/// it is distinct from "a parent has not arrived yet" and from "your
/// author chain forked" — neither of which is true here, and both of which
/// would send the peer looking for something that would not help.
#[test]
fn a_self_contained_history_on_another_base_admits_nothing() {
    const GROUP: &str = "two-histories-group";
    let conn = conn();

    // This replica is on H2.
    let local_base = HistoryBase([0x22u8; 32]);
    install_base(&conn, GROUP, local_base);
    let local = change_on(HistoryEpoch::Base(local_base), 1, 1, GROUP, None, &[], "local.bin");
    admit_expecting_applied(&conn, &local, "a change on this replica's own base");

    // The returning device's history, written on H1, root first and
    // internally complete.
    let foreign_base = HistoryEpoch::Base(HistoryBase([0x11u8; 32]));
    let f1 = change_on(foreign_base, 2, 1, GROUP, None, &[], "f1.bin");
    let f2 = change_on(foreign_base, 2, 2, GROUP, Some(&f1), &[&f1], "f2.bin");
    let f3 = change_on(foreign_base, 2, 3, GROUP, Some(&f2), &[&f2], "f3.bin");

    for (change, what) in [(&f1, "the root"), (&f2, "its child"), (&f3, "its grandchild")] {
        let result = admit(&conn, change);
        assert!(
            matches!(result.outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }),
            "{what} of a history written on another base must be refused as foreign, not as a \
             missing parent and not as a forked author, got {:?}",
            result.outcome
        );
        assert!(!has_change(&conn, &change.compute_hash()).unwrap(), "{what} must not be retained");
    }

    // Zero admitted, and no position invented for its author: an author
    // this replica has never held must not acquire a watermark by having
    // its old history refused.
    assert_eq!(
        admitted_count(&conn, GROUP),
        1,
        "only this replica's own change may be in retained history"
    );
    assert_eq!(author_state(&conn, 2, GROUP), None);

    // Delivered the other way round — child first, with its parents still
    // in flight — the answer is the same rather than a bounded wait. The
    // epoch is decidable from the change's own bytes, so a foreign history
    // cannot occupy the orphan buffer that changes which are merely early
    // depend on.
    let result = admit(&conn, &f3);
    assert!(
        matches!(result.outcome, AdmitOutcome::RefusedForeignHistoryBase { .. }),
        "a foreign-base change with absent parents is still foreign, not orphaned, got {:?}",
        result.outcome
    );
    assert_eq!(orphan_count(&conn), 0, "nothing from another history may be buffered");
}

fn orphan_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM orphan_changes", [], |row| row.get(0)).unwrap()
}

// --- 12. a refusal releases what was waiting on it -------------------------

/// The counterpart to holding: what happens when the change a held change
/// was waiting for turns out to be one this replica will never accept.
///
/// A:1 is admitted. A:3 arrives early, descends A:1 alone, and names A:2 as
/// its author's previous change, so it is held against that name — correct,
/// and the reason holding exists. Then A:2 itself arrives and is refused
/// finally: it claims the position right after A:1 while naming something
/// other than A:1 as what it followed, which forks its author's own chain
/// and is a verdict no later delivery can change.
///
/// A:2 will therefore never enter retained history, so A:3 can never be
/// promoted either — its author's previous change is permanently absent.
/// But A:3 is not a DAG child of A:2 (that is the whole point of the author
/// link being a separate relation), so a dependent walk that follows only
/// `change_parents` edges never reaches it. Left in the buffer it is worse
/// than merely stale: `has_change_or_buffered_orphan` reports its hash as
/// already known, so no peer is ever asked for it again, and the missing
/// frontier it would contribute is empty because the one name it waits on
/// is recorded as permanently rejected and counted as resolved. Buffered,
/// waiting, asking for nothing, never promoted and never dropped.
///
/// So the refusal has to release it. And a later re-delivery of A:3 must
/// not simply re-enter the same state: naming a permanently-rejected
/// predecessor is itself a decided gap, not an early arrival.
#[test]
fn a_buffered_change_whose_author_prev_is_permanently_rejected_is_dropped() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1 placing doc.txt");

    // A change of this author that this replica never receives, used only
    // as the name A:2 wrongly claims to have followed.
    let unrelated = change(1, 9, GROUP, None, &[], "unrelated.bin");
    // A:2 stands at the position right after A:1 but names `unrelated`
    // instead of A:1: a fork of its author's chain, refused finally.
    let a2 = change(1, 2, GROUP, Some(&unrelated), &[&a1], "other.txt");
    // A:3 edits doc.txt on the basis of A:1 and names A:2 as its author's
    // previous change. Every DAG parent it has is already admitted.
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(
        !a3.parents.contains(&a2.compute_hash()),
        "A:3 must not claim its author's previous change as a causal parent"
    );

    assert!(
        matches!(admit(&conn, &a3).outcome, AdmitOutcome::Orphaned),
        "A:3 is early, not broken, while A:2 has not arrived"
    );
    assert!(is_buffered_orphan(&conn, &a3.compute_hash()), "sanity: A:3 really is held");

    let result = admit(&conn, &a2);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
        ),
        "A:2 forks its author's chain and must be refused finally, got {:?}",
        result.outcome
    );
    assert_eq!(
        rejected_count(&conn, &a2.compute_hash()),
        1,
        "sanity: the refusal is recorded durably, which is what makes A:2 permanently absent"
    );

    assert!(
        !is_buffered_orphan(&conn, &a3.compute_hash()),
        "the change waiting on a name this replica has permanently refused must be released \
         from the buffer, not left waiting for something that can never arrive"
    );
    assert!(!has_change(&conn, &a3.compute_hash()).unwrap(), "and it must not be admitted either");
    assert_eq!(
        author_state(&conn, 1, GROUP),
        Some((1, a1.compute_hash())),
        "neither the refusal nor the release may move the author's position"
    );

    // Re-delivered, it must reach a decided verdict rather than buffer
    // against the same dead name again.
    let result = admit(&conn, &a3);
    assert!(
        matches!(
            result.outcome,
            AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
        ),
        "a change naming a permanently-rejected predecessor names a gap nothing can fill, so \
         it is refused rather than held, got {:?}",
        result.outcome
    );
    assert!(!is_buffered_orphan(&conn, &a3.compute_hash()), "and it is not buffered again");
    assert_eq!(
        rejected_count(&conn, &a3.compute_hash()),
        1,
        "the refusal is recorded, so a peer stops being asked for it"
    );
}

/// The other direction, so the release above cannot be implemented as
/// "drop anything waiting on an author name". A refusal releases only what
/// was waiting on the hash it refused; a change waiting on a name that is
/// merely absent stays held and stays asked for, and one whose name later
/// arrives still promotes.
#[test]
fn a_refusal_releases_only_what_waited_on_the_hash_it_refused() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.bin");
    admit_expecting_applied(&conn, &a1, "A:1");
    let b1 = change(2, 1, GROUP, None, &[], "b1.bin");
    admit_expecting_applied(&conn, &b1, "B:1");

    // B:2 is written but not delivered; B:3 waits on it. Nothing about B:2
    // is decided.
    let b2 = change(2, 2, GROUP, Some(&b1), &[&b1], "b2.bin");
    let b3 = change(2, 3, GROUP, Some(&b2), &[&b1], "b3.bin");
    assert!(matches!(admit(&conn, &b3).outcome, AdmitOutcome::Orphaned));

    // An unrelated author's refusal lands in between.
    let stranger = change(1, 9, GROUP, None, &[], "stranger.bin");
    let a2_forked = change(1, 2, GROUP, Some(&stranger), &[&a1], "a2.bin");
    assert!(matches!(
        admit(&conn, &a2_forked).outcome,
        AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorPrevMismatch { .. })
    ));

    assert!(
        is_buffered_orphan(&conn, &b3.compute_hash()),
        "a change waiting on a name that is merely absent must still be held"
    );
    let wanted = missing_ancestor_frontier(&conn, [b3.compute_hash()]).unwrap();
    assert!(
        wanted.contains(&b2.compute_hash()),
        "and the name it waits on must still be re-requested, got {wanted:?}"
    );

    // And when that name does arrive, it promotes as before.
    let result = admit(&conn, &b2);
    assert!(
        result.newly_admitted.contains(&b3.compute_hash()),
        "the held change must still be promoted by the admission that supplies its predecessor"
    );
    assert!(has_change(&conn, &b3.compute_hash()).unwrap());
}

fn rejected_count(conn: &Connection, hash: &ChangeHash) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM rejected_changes WHERE change_hash = ?1",
        [&hash.0[..]],
        |row| row.get(0),
    )
    .unwrap()
}

// --- 13. a path refusal releases what was waiting on it too ----------------

/// The release above, when the refusal comes from the path rules instead of
/// the author chain.
///
/// Admission checks the paths a change names before anything else, and a
/// path nobody can store faithfully is a verdict on the change's own signed
/// bytes, exactly as final as an author-chain refusal. So the change held
/// against it -- here as its author's previous change -- is waiting on
/// something that can never arrive, and must be released the same way.
#[test]
fn a_path_refusal_releases_a_change_waiting_on_it_as_author_predecessor() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1");

    // A:2 continues A:1 correctly but names a path no Windows member can
    // create. A:3 follows A:2 in author order and edits on A:1's basis.
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "notes:draft.txt");
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(matches!(admit(&conn, &a3).outcome, AdmitOutcome::Orphaned));
    assert!(is_buffered_orphan(&conn, &a3.compute_hash()), "sanity: A:3 really is held");

    let refused = admit(&conn, &a2).outcome;
    assert!(
        matches!(refused, AdmitOutcome::RefusedPath(PathRefusal::NonPortablePath { .. })),
        "A:2 must be refused for its path, got {refused:?}"
    );
    assert_eq!(rejected_count(&conn, &a2.compute_hash()), 1, "sanity: the refusal is recorded");

    assert!(
        !is_buffered_orphan(&conn, &a3.compute_hash()),
        "the change waiting on a predecessor refused for its path must be released from the \
         buffer, not left waiting for something that can never arrive"
    );
    assert_eq!(author_state(&conn, 1, GROUP), Some((1, a1.compute_hash())));
}

/// The same for a DAG child: a change whose causal parent is refused for
/// its path can never have all its parents present.
#[test]
fn a_path_refusal_releases_a_change_waiting_on_it_as_dag_parent() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "notes:draft.txt");
    let b1 = change(2, 1, GROUP, None, &[&a1], "doc.txt");
    assert!(matches!(admit(&conn, &b1).outcome, AdmitOutcome::Orphaned));
    assert!(is_buffered_orphan(&conn, &b1.compute_hash()), "sanity: B:1 really is held");

    assert!(
        matches!(admit(&conn, &a1).outcome, AdmitOutcome::RefusedPath(_)),
        "A:1 must be refused for its path"
    );

    assert!(
        !is_buffered_orphan(&conn, &b1.compute_hash()),
        "the change whose DAG parent was refused for its path must be released from the buffer"
    );
}

/// A change whose DAG parent is already refused must itself be refused, not
/// held. Released from the buffer when its parent was refused, it is still
/// advertised by whichever peer holds it, so it arrives again; and a child
/// can also arrive for the first time after its parent was refused. Held,
/// it would wait on a name that is recorded as refused and so counted as
/// resolved: never promoted, never asked for again, and occupying a slot
/// of the bounded buffer. The refusal is recorded under the rules that
/// refused the parent, since it stands exactly as long as that one does.
#[test]
fn a_change_whose_dag_parent_was_refused_for_its_path_is_refused_on_redelivery() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "notes:draft.txt");
    let b1 = change(2, 1, GROUP, None, &[&a1], "doc.txt");
    assert!(matches!(admit(&conn, &b1).outcome, AdmitOutcome::Orphaned));
    assert!(matches!(admit(&conn, &a1).outcome, AdmitOutcome::RefusedPath(_)));
    assert!(!is_buffered_orphan(&conn, &b1.compute_hash()), "sanity: B:1 was released");

    let redelivered = admit(&conn, &b1).outcome;
    assert_eq!(
        redelivered,
        AdmitOutcome::RefusedBehindRejectedParent { parent: a1.compute_hash() },
        "B:1 can never have its parent, so it must be refused rather than held again: \
         got {redelivered:?}"
    );
    assert!(!is_buffered_orphan(&conn, &b1.compute_hash()));
    assert_eq!(
        rejection_domain(&conn, &b1.compute_hash()).as_deref(),
        Some("path"),
        "the verdict on B:1 rests on the path rules that refused A:1"
    );
}

/// The same for a first arrival behind a parent the author chain refused.
#[test]
fn a_first_arrival_behind_an_author_chain_refused_parent_is_refused_under_its_rules() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "a1.txt");
    admit_expecting_applied(&conn, &a1, "A:1");
    // Sequence 3 with nothing named before it: a gap nothing can close.
    let a3 = change(1, 3, GROUP, None, &[&a1], "a3.txt");
    assert!(matches!(admit(&conn, &a3).outcome, AdmitOutcome::RefusedAuthorChain(_)));

    let b1 = change(2, 1, GROUP, None, &[&a3], "b1.txt");
    let outcome = admit(&conn, &b1).outcome;
    assert_eq!(
        outcome,
        AdmitOutcome::RefusedBehindRejectedParent { parent: a3.compute_hash() },
        "a child of a refused change must be refused, not held: got {outcome:?}"
    );
    assert!(!is_buffered_orphan(&conn, &b1.compute_hash()));
    assert_eq!(rejection_domain(&conn, &b1.compute_hash()).as_deref(), Some("author-chain"));
}

/// A gap refused because the predecessor it names was refused is only as
/// settled as THAT refusal. When the predecessor was refused for its path,
/// the dependent verdict must be stamped with the path rules' version, so a
/// change to the path rules re-opens both together. Stamped as an
/// author-chain verdict instead, the dependent would stay settled while the
/// predecessor it rests on is re-evaluated and admitted.
#[test]
fn a_gap_behind_a_path_refused_predecessor_is_recorded_under_the_path_rules() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "notes:draft.txt");
    assert!(
        matches!(admit(&conn, &a2).outcome, AdmitOutcome::RefusedPath(_)),
        "A:2 must be refused for its path"
    );

    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(matches!(
        admit(&conn, &a3).outcome,
        AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
    ));
    assert_eq!(
        rejection_domain(&conn, &a3.compute_hash()).as_deref(),
        Some("path"),
        "the verdict on A:3 rests on the path rules that refused A:2"
    );

    // And the author chain's own gap verdicts keep their own domain.
    let b1 = change(2, 1, GROUP, None, &[], "b1.bin");
    admit_expecting_applied(&conn, &b1, "B:1");
    let b3 = change(2, 3, GROUP, None, &[&b1], "b3.bin");
    assert!(matches!(
        admit(&conn, &b3).outcome,
        AdmitOutcome::RefusedAuthorChain(AuthorChainRefusal::AuthorSequenceGap { .. })
    ));
    assert_eq!(rejection_domain(&conn, &b3.compute_hash()).as_deref(), Some("author-chain"));
}

fn rejection_domain(conn: &Connection, hash: &ChangeHash) -> Option<String> {
    conn.query_row(
        "SELECT rejection_domain FROM rejected_changes WHERE change_hash = ?1",
        [&hash.0[..]],
        |row| row.get(0),
    )
    .ok()
}

/// Re-opens `hash`'s own verdict and nothing else's, the way a verdict is
/// re-opened when the rules it was recorded under stop being current.
fn reopen_verdict_of(conn: &Connection, hash: &ChangeHash) {
    let reopened = conn
        .execute(
            "UPDATE rejected_changes SET rules_version = rules_version - 1 WHERE change_hash = ?1",
            [&hash.0[..]],
        )
        .unwrap();
    assert_eq!(reopened, 1, "sanity: {hash:?} had a verdict to re-open");
}

/// Makes `hash` held here the way a re-bootstrap boundary does, as a prune
/// tombstone, leaving its own rejection row and stamp exactly as they were.
fn hold_as_pruned(conn: &Connection, hash: &ChangeHash) {
    conn.execute(
        "INSERT INTO pruned_changes \
         (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
         VALUES (?1, ?2, ?3, 1, 1)",
        rusqlite::params![GROUP, &hash.0[..], vec![0x5Au8; 32]],
    )
    .unwrap();
    assert!(
        rejection_domain(conn, hash).is_some(),
        "sanity: {hash:?} keeps its own rejection row, stamped under current rules"
    );
}

/// The other way a dependent verdict lapses: the change it rests on becomes
/// held here while its own verdict stays stamped under current rules, as
/// after a re-bootstrap onto a base that includes it. B:1 was refused
/// because A:1 could never be held; now A:1 is held, so B:1 must be asked
/// for again and, admitted afresh, must not be refused behind A:1.
#[test]
fn a_refusal_behind_a_refused_dag_parent_lapses_once_the_parent_is_held() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "notes:draft.txt");
    assert!(matches!(admit(&conn, &a1).outcome, AdmitOutcome::RefusedPath(_)));
    let b1 = change(2, 1, GROUP, None, &[&a1], "doc.txt");
    assert_eq!(
        admit(&conn, &b1).outcome,
        AdmitOutcome::RefusedBehindRejectedParent { parent: a1.compute_hash() }
    );
    assert_eq!(rests_on(&conn, &b1.compute_hash()), Some(a1.compute_hash()));

    hold_as_pruned(&conn, &a1.compute_hash());

    assert!(
        !has_change_or_buffered_orphan(&conn, &b1.compute_hash()).unwrap(),
        "B:1's refusal rested on A:1 being unheld, and it is held now"
    );
    assert_eq!(
        missing_ancestor_frontier(&conn, [b1.compute_hash()]).unwrap(),
        vec![b1.compute_hash()],
        "so B:1 is asked for again"
    );
    let readmitted = admit(&conn, &b1).outcome;
    assert!(
        !matches!(readmitted, AdmitOutcome::RefusedBehindRejectedParent { .. }),
        "a held parent is not a refused one, whatever its old row says: got {readmitted:?}"
    );
}

/// The author-link counterpart: A:3 was refused because its predecessor A:2
/// could never be held; once A:2 is held, that verdict no longer stands.
#[test]
fn a_refusal_behind_a_refused_author_predecessor_lapses_once_it_is_held() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "notes:draft.txt");
    assert!(matches!(admit(&conn, &a2).outcome, AdmitOutcome::RefusedPath(_)));
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(matches!(admit(&conn, &a3).outcome, AdmitOutcome::RefusedAuthorChain(_)));
    assert_eq!(rests_on(&conn, &a3.compute_hash()), Some(a2.compute_hash()));

    hold_as_pruned(&conn, &a2.compute_hash());

    assert!(
        !has_change_or_buffered_orphan(&conn, &a3.compute_hash()).unwrap(),
        "A:3's refusal rested on A:2 being unheld, and it is held now"
    );
}

fn rests_on(conn: &Connection, hash: &ChangeHash) -> Option<ChangeHash> {
    conn.query_row(
        "SELECT rests_on FROM rejected_changes WHERE change_hash = ?1",
        [&hash.0[..]],
        |row| row.get::<_, Option<Vec<u8>>>(0),
    )
    .unwrap()
    .map(|bytes| ChangeHash(bytes.try_into().expect("a 32-byte hash")))
}

/// A refusal behind a refused DAG parent is not a verdict of its own: it is
/// the parent's, applied to a descendant. When the parent's verdict stops
/// standing, for whatever reason, the child's must stop with it and the
/// child must be asked for again, or it stays excluded on the strength of a
/// decision nobody holds any more.
#[test]
fn a_refusal_behind_a_refused_dag_parent_lapses_with_the_parents_verdict() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "notes:draft.txt");
    assert!(matches!(admit(&conn, &a1).outcome, AdmitOutcome::RefusedPath(_)));
    let b1 = change(2, 1, GROUP, None, &[&a1], "doc.txt");
    assert_eq!(
        admit(&conn, &b1).outcome,
        AdmitOutcome::RefusedBehindRejectedParent { parent: a1.compute_hash() }
    );
    assert!(has_change_or_buffered_orphan(&conn, &b1.compute_hash()).unwrap());

    reopen_verdict_of(&conn, &a1.compute_hash());

    assert!(
        !has_change_or_buffered_orphan(&conn, &b1.compute_hash()).unwrap(),
        "B:1's refusal rested on A:1's, which no longer stands"
    );
    assert_eq!(
        missing_ancestor_frontier(&conn, [b1.compute_hash()]).unwrap(),
        vec![b1.compute_hash()],
        "so B:1 is asked for again, to be decided afresh"
    );
}

/// The author-link counterpart: a gap refused because the predecessor it
/// names was refused stands exactly as long as that refusal does.
#[test]
fn a_refusal_behind_a_refused_author_predecessor_lapses_with_its_verdict() {
    let conn = conn();
    let a1 = change(1, 1, GROUP, None, &[], "doc.txt");
    admit_expecting_applied(&conn, &a1, "A:1");
    let a2 = change(1, 2, GROUP, Some(&a1), &[&a1], "notes:draft.txt");
    assert!(matches!(admit(&conn, &a2).outcome, AdmitOutcome::RefusedPath(_)));
    let a3 = change(1, 3, GROUP, Some(&a2), &[&a1], "doc.txt");
    assert!(matches!(admit(&conn, &a3).outcome, AdmitOutcome::RefusedAuthorChain(_)));
    assert!(has_change_or_buffered_orphan(&conn, &a3.compute_hash()).unwrap());

    reopen_verdict_of(&conn, &a2.compute_hash());

    assert!(
        !has_change_or_buffered_orphan(&conn, &a3.compute_hash()).unwrap(),
        "A:3's refusal rested on A:2's, which no longer stands"
    );
}
