#![cfg(test)]

use super::*;
use crate::materialized_generation::bump_mutation_fence;
use crate::verified_change_store::{
    is_servable, servable_change_hashes, stage_verified_bundles,
    test_support::{bundle, change_touching, checkpoint, conn, GROUP},
};
use rusqlite::Connection;

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn stage(c: &Connection, change: &Change, tag: u8) -> ChangeHash {
    let hash = change.compute_hash();
    let tx = c.unchecked_transaction().unwrap();
    stage_verified_bundles(&tx, &[bundle(change.clone(), checkpoint(tag))], 1).unwrap();
    tx.commit().unwrap();
    hash
}

/// Plan then commit, the way a caller does: planning with no writer
/// transaction, committing inside one. Every test here used to pass the
/// bare connection, so they all modelled a caller that had NO
/// transaction -- which is exactly the shape the real caller had, and
/// the reason nothing caught it.
fn promote(c: &Connection, hash: &ChangeHash) -> AdmissionOutcome {
    let plan = plan_admission(c, hash).unwrap().expect("staged");
    commit_in_transaction(c, &plan).unwrap()
}

/// Commit `plan` inside a transaction, as every caller must.
fn commit_in_transaction(
    c: &Connection,
    plan: &AdmissionPlan,
) -> Result<AdmissionOutcome, SyncSqliteError> {
    let tx = c.unchecked_transaction()?;
    let outcome = commit_admission(&tx, plan)?;
    tx.commit()?;
    Ok(outcome)
}

#[test]
fn a_promotion_outside_a_transaction_is_refused_rather_than_half_applied() {
    // `&Connection` and `&Transaction` are indistinguishable to the
    // compiler, so this contract cannot be expressed in the signature.
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);
    let plan = plan_admission(&c, &hash).unwrap().expect("staged");

    let err = commit_admission(&c, &plan).expect_err("autocommit must be refused");

    assert!(matches!(err, SyncSqliteError::CorruptState(_)), "{err:?}");
    assert!(!verified_change_store::is_canonical(&c, &hash).unwrap());
}

#[test]
fn a_staged_change_with_no_parents_promotes() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    assert_eq!(promote(&c, &hash), AdmissionOutcome::Promoted { newly_admitted: vec![hash] });
    assert!(crate::dag_store::published_view::is_published(&c, &hash).unwrap());
}

/// The central invariant: promotion moves a hash across the possession
/// union without ever removing it. There is no instant at which a peer
/// could observe the Change as un-possessed and send it again.
#[test]
fn promotion_never_withdraws_possession() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    assert!(is_servable(&c, &hash).unwrap(), "possessed while staged");
    assert_eq!(servable_change_hashes(&c, &group()).unwrap(), vec![hash]);

    promote(&c, &hash);

    assert!(is_servable(&c, &hash).unwrap(), "possessed once canonical");
    assert_eq!(
        servable_change_hashes(&c, &group()).unwrap(),
        vec![hash],
        "and named exactly once, not twice"
    );
}

/// A crash mid-promotion must leave the Change either still staged or
/// fully canonical, never neither. The transaction is what guarantees it:
/// rolling the promotion back restores possession by the staged route.
#[test]
fn an_abandoned_promotion_transaction_leaves_the_change_staged() {
    let mut c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    let plan = plan_admission(&c, &hash).unwrap().unwrap();
    {
        let tx = c.transaction().unwrap();
        commit_admission(&tx, &plan).unwrap();
        // The process dies here. Nothing commits.
    }

    assert!(is_servable(&c, &hash).unwrap(), "still possessed after a rollback");
    assert!(!crate::verified_change_store::is_canonical(&c, &hash).unwrap(), "and not canonical");
    assert_eq!(admissible_now_hashes(&c), vec![hash], "so it is promoted later");
}

fn admissible_now_hashes(c: &Connection) -> Vec<ChangeHash> {
    crate::verified_change_store::admissible_now(c, &group(), 16).unwrap()
}

/// Nothing schedules the child. Its promotability is recomputed from
/// current state, so the parent landing is enough on its own — no wake-up,
/// no invalidation, no stored blocking reason to clear.
#[test]
fn a_child_staged_before_its_parent_becomes_promotable_when_the_parent_lands() {
    let c = conn();
    let parent = change_touching(vec![], 0, &["a.txt"]);
    let child = change_touching(vec![parent.compute_hash()], parent.lamport, &["b.txt"]);

    let child_hash = stage(&c, &child, 1);
    assert!(admissible_now_hashes(&c).is_empty(), "blocked by its missing parent");

    let parent_hash = stage(&c, &parent, 1);
    assert_eq!(admissible_now_hashes(&c), vec![parent_hash], "only the parent is promotable yet");

    promote(&c, &parent_hash);

    assert_eq!(
        admissible_now_hashes(&c),
        vec![child_hash],
        "the child became promotable purely by the parent landing"
    );
    promote(&c, &child_hash);
    assert!(crate::dag_store::published_view::is_published(&c, &child_hash).unwrap());
}

/// A local mutation captured between planning and committing must stop the
/// promotion. Otherwise the remote Change is ordered causally after a
/// local edit it never saw.
#[test]
fn a_capture_fence_that_moves_between_plan_and_commit_blocks_the_promotion() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    let plan = plan_admission(&c, &hash).unwrap().unwrap();

    // A local mutation to the same path is captured after planning.
    bump_mutation_fence(&c, GROUP, "a.txt", "local-edit", 1000).unwrap();

    let outcome = commit_in_transaction(&c, &plan).unwrap();
    assert!(
        matches!(
            outcome,
            AdmissionOutcome::Stale(Stale::CaptureFenceMoved { ref path, planned: 0, current: 1 })
                if path == "a.txt"
        ),
        "expected a stale capture fence, got {outcome:?}"
    );
    assert!(
        !crate::verified_change_store::is_canonical(&c, &hash).unwrap(),
        "a refused promotion must write nothing"
    );
    assert!(is_servable(&c, &hash).unwrap(), "and must not lose possession");

    // Re-planning against current state succeeds: the refusal is a
    // re-drive, not a failure.
    assert_eq!(promote(&c, &hash), AdmissionOutcome::Promoted { newly_admitted: vec![hash] });
}

/// The fence is only revalidated for paths the Change actually touches: an
/// unrelated local edit must not stall unrelated remote work.
#[test]
fn a_capture_fence_moving_on_an_untouched_path_does_not_block_the_promotion() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    let plan = plan_admission(&c, &hash).unwrap().unwrap();
    bump_mutation_fence(&c, GROUP, "unrelated.txt", "local-edit", 1000).unwrap();

    assert_eq!(
        commit_in_transaction(&c, &plan).unwrap(),
        AdmissionOutcome::Promoted { newly_admitted: vec![hash] }
    );
}

fn mark_dirty(c: &Connection, path: &str) {
    c.execute(
        "INSERT INTO local_dirty_paths \
           (group_id, path, change_kind, first_seen_unix_nanos, observed_at_unix_nanos) \
         VALUES (?1, ?2, 'modified', 1, 1)",
        rusqlite::params![GROUP, path],
    )
    .unwrap();
}

/// An edit of a copy name the namespace placed `d/a.txt`'s leaf under is
/// journaled at the copy name and authored at `d/a.txt` (write-through), so
/// it holds a remote change to `d/a.txt` like a dirty `d/a.txt` would. A
/// dirty name that is not a copy of it holds nothing.
#[test]
fn a_dirty_copy_name_holds_a_remote_change_to_its_source() {
    let c = conn();
    let change = change_touching(vec![], 0, &["d/a.txt"]);
    let hash = stage(&c, &change, 1);
    mark_dirty(&c, "d/ab (conflicted copy, device-x 2026-09-25 abcd).txt");
    mark_dirty(&c, "a (conflicted copy, device-x 2026-09-25 abcd).txt");
    mark_dirty(&c, "d/a (conflicted copy, device-x 2026-09-25 abcd).md");

    let plan = plan_admission(&c, &hash).unwrap().unwrap();
    assert_eq!(
        commit_in_transaction(&c, &plan).unwrap(),
        AdmissionOutcome::Promoted { newly_admitted: vec![hash] },
        "no dirty copy name of d/a.txt"
    );

    let c = conn();
    let hash = stage(&c, &change, 1);
    mark_dirty(&c, "d/a (conflicted copy, device-x 2026-09-25 abcd).txt");
    let plan = plan_admission(&c, &hash).unwrap().unwrap();
    let outcome = commit_in_transaction(&c, &plan).unwrap();
    assert!(
        matches!(
            outcome,
            AdmissionOutcome::Stale(Stale::CaptureBarrierOpen { ref path }) if path == "d/a.txt"
        ),
        "expected the capture barrier, got {outcome:?}"
    );
}

#[test]
fn committing_a_plan_whose_change_someone_else_already_promoted_is_not_an_error() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = stage(&c, &change, 1);

    let plan = plan_admission(&c, &hash).unwrap().unwrap();
    promote(&c, &hash);

    assert_eq!(commit_in_transaction(&c, &plan).unwrap(), AdmissionOutcome::AlreadyCanonical);
    assert_eq!(
        servable_change_hashes(&c, &group()).unwrap(),
        vec![hash],
        "possession stays exactly one entry"
    );
}

#[test]
fn a_plan_whose_parent_never_became_canonical_is_refused_without_writing() {
    let c = conn();
    let parent = change_touching(vec![], 0, &["a.txt"]);
    let child = change_touching(vec![parent.compute_hash()], parent.lamport, &["b.txt"]);
    let child_hash = stage(&c, &child, 1);

    let plan = plan_admission(&c, &child_hash).unwrap().unwrap();
    assert_eq!(
        commit_in_transaction(&c, &plan).unwrap(),
        AdmissionOutcome::Stale(Stale::ParentNotCanonical(parent.compute_hash()))
    );
    assert!(!crate::verified_change_store::is_canonical(&c, &child_hash).unwrap());
}

/// A Change buffered on the legacy orphan path must not be swept into the
/// canonical DAG by someone else's promotion.
///
/// `dag_store::admit_change` finishes by recursively promoting every
/// buffered orphan the new Change completes. Reached from here, that would
/// install those children inside this transaction against local capture
/// fences nobody read and nobody revalidated — bypassing the entire
/// plan/revalidate sequence promotion exists to enforce. Every Change
/// earns its own promotion.
#[test]
fn promotion_does_not_sweep_in_a_legacy_orphan_child() {
    let c = conn();
    let parent = change_touching(vec![], 0, &["a.txt"]);
    let child = change_touching(vec![parent.compute_hash()], parent.lamport, &["b.txt"]);
    let child_hash = child.compute_hash();

    // The child arrives on the OLD path and buffers as an orphan, its
    // parent being absent.
    let buffered = crate::dag_store::admit_change(&c, &child).unwrap();
    assert_eq!(buffered.outcome, crate::dag_store::AdmitOutcome::Orphaned);

    // The parent arrives on the NEW path and is promoted.
    let parent_hash = stage(&c, &parent, 1);
    let outcome = promote(&c, &parent_hash);

    assert_eq!(
        outcome,
        AdmissionOutcome::Promoted { newly_admitted: vec![parent_hash] },
        "promotion must report exactly the Change it promoted"
    );
    assert!(
        !crate::verified_change_store::is_canonical(&c, &child_hash).unwrap(),
        "the buffered child must NOT have been swept into the canonical DAG; it never \
         passed a capture-token revalidation"
    );
}

#[test]
fn planning_writes_nothing() {
    let c = conn();
    let change = change_touching(vec![], 0, &["never-mutated.txt"]);
    let hash = stage(&c, &change, 1);

    let before: i64 =
        c.query_row("SELECT count(*) FROM path_actual_mutation_fences", [], |r| r.get(0)).unwrap();

    plan_admission(&c, &hash).unwrap().unwrap();

    let after: i64 =
        c.query_row("SELECT count(*) FROM path_actual_mutation_fences", [], |r| r.get(0)).unwrap();
    assert_eq!(before, after, "planning must be read-only so it can run with no writer gate held");
}

#[test]
fn planning_a_hash_that_is_not_staged_yields_nothing() {
    let c = conn();
    let unseen = change_touching(vec![], 0, &["a.txt"]).compute_hash();
    assert!(plan_admission(&c, &unseen).unwrap().is_none());
}

/// A Change with an explicit author position, for tests where the author
/// chain itself is what refuses something: `change_touching` numbers its
/// author positions for itself, so it cannot author a gap on purpose.
fn authored(
    device: u8,
    seq: u64,
    prev: Option<&Change>,
    parents: &[&Change],
    path: &str,
) -> Change {
    use yadorilink_replica_domain::change::Op;
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    let mut parent_hashes: Vec<ChangeHash> = parents.iter().map(|p| p.compute_hash()).collect();
    parent_hashes.sort();
    Change::create_signed(
        parent_hashes,
        parents.iter().map(|p| p.lamport).max().unwrap_or(0),
        DeviceId(format!("device-{device}")),
        AuthorSeq(seq),
        prev.map(Change::compute_hash),
        FolderGroupId(GROUP.into()),
        yadorilink_replica_domain::rebootstrap::HistoryEpoch::Genesis,
        vec![Op::Delete { path: SyncPath(path.into()) }],
        &ed25519_dalek::SigningKey::from_bytes(&[device; 32]),
    )
}

fn rejection_stamp(c: &Connection, hash: &ChangeHash) -> Option<(String, u32)> {
    c.query_row(
        "SELECT rejection_domain, rules_version FROM rejected_changes WHERE change_hash = ?1",
        [&hash.0[..]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .ok()
}

fn rests_on(c: &Connection, hash: &ChangeHash) -> Option<ChangeHash> {
    c.query_row(
        "SELECT rests_on FROM rejected_changes WHERE change_hash = ?1",
        [&hash.0[..]],
        |row| row.get::<_, Option<Vec<u8>>>(0),
    )
    .unwrap()
    .map(|bytes| ChangeHash(bytes.try_into().expect("a 32-byte hash")))
}

/// Stages `parent` and a child of it (and a grandchild of that child), then
/// promotes `parent`, which `parent`'s own content makes a permanent
/// refusal. What follows must dispose of both staged descendants: a staged
/// Change that can never become canonical must not stay possessed.
fn a_refused_parent_must_not_strand_its_staged_descendants(
    c: &Connection,
    parent: &Change,
    refused_as: fn(&AdmissionOutcome) -> bool,
    expected_domain: &str,
) {
    // Different authors, so each descendant waits on its DAG parent only
    // and its own author chain is clean.
    let child = authored(3, 1, None, &[parent], "child.txt");
    let grandchild = authored(4, 1, None, &[&child], "grandchild.txt");
    let parent_hash = stage(c, parent, 1);
    let child_hash = stage(c, &child, 2);
    let grandchild_hash = stage(c, &grandchild, 3);
    assert_eq!(admissible_now_hashes(c), vec![parent_hash], "only the parent is a candidate yet");

    let outcome = promote(c, &parent_hash);
    assert!(refused_as(&outcome), "the parent must be refused permanently, got {outcome:?}");
    assert!(!is_servable(c, &parent_hash).unwrap());

    assert_eq!(
        admissible_now_hashes(c),
        vec![child_hash],
        "a staged child of a permanently refused parent must be a candidate: it can only \
         be refused, and nothing else will ever select it"
    );
    assert_eq!(
        promote(c, &child_hash),
        AdmissionOutcome::RefusedBehindRejectedParent { parent: parent_hash }
    );
    assert!(!is_servable(c, &child_hash).unwrap(), "the refused child is no longer possessed");
    assert_eq!(
        rejection_stamp(c, &child_hash).map(|(domain, _)| domain).as_deref(),
        Some(expected_domain),
        "the child's refusal rests on the rules that refused its parent"
    );
    assert_eq!(
        rejection_stamp(c, &child_hash).map(|(_, version)| version),
        rejection_stamp(c, &parent_hash).map(|(_, version)| version),
    );
    assert_eq!(rests_on(c, &child_hash), Some(parent_hash), "and names the parent it rests on");

    assert_eq!(admissible_now_hashes(c), vec![grandchild_hash], "and so on down the line");
    assert_eq!(
        promote(c, &grandchild_hash),
        AdmissionOutcome::RefusedBehindRejectedParent { parent: child_hash }
    );
    assert_eq!(rests_on(c, &grandchild_hash), Some(child_hash));
    assert!(servable_change_hashes(c, &group())
        .unwrap()
        .iter()
        .all(|h| { ![parent_hash, child_hash, grandchild_hash].contains(h) }));
    assert!(admissible_now_hashes(c).is_empty(), "nothing is left to select");
}

#[test]
fn staged_child_of_permanently_rejected_parent_is_discarded_and_not_servable_path() {
    let c = conn();
    let parent = authored(2, 1, None, &[], "notes:draft.txt");
    a_refused_parent_must_not_strand_its_staged_descendants(
        &c,
        &parent,
        |outcome| matches!(outcome, AdmissionOutcome::RefusedPath(_)),
        "path",
    );
}

#[test]
fn staged_child_of_permanently_rejected_parent_is_discarded_and_not_servable_author_chain() {
    let c = conn();
    let first = authored(2, 1, None, &[], "first.txt");
    let first_hash = stage(&c, &first, 9);
    assert!(matches!(promote(&c, &first_hash), AdmissionOutcome::Promoted { .. }));
    // Position 3 naming nothing before it: a gap nothing can close.
    let parent = authored(2, 3, None, &[&first], "gap.txt");
    a_refused_parent_must_not_strand_its_staged_descendants(
        &c,
        &parent,
        |outcome| matches!(outcome, AdmissionOutcome::RefusedAuthorChain(_)),
        "author-chain",
    );
}

/// The refusal is checked before canonicity: a plan for a child whose
/// parent is refused commits as a refusal, not as a stale plan to re-drive.
/// Reported as stale, the child would be planned and refused as stale on
/// every pass for as long as it stayed staged.
#[test]
fn a_plan_behind_a_refused_parent_commits_as_a_refusal_not_as_stale() {
    let c = conn();
    let parent = authored(2, 1, None, &[], "notes:draft.txt");
    let child = authored(3, 1, None, &[&parent], "child.txt");
    let parent_hash = stage(&c, &parent, 1);
    let child_hash = stage(&c, &child, 2);
    let child_plan = plan_admission(&c, &child_hash).unwrap().unwrap();
    assert!(matches!(promote(&c, &parent_hash), AdmissionOutcome::RefusedPath(_)));

    assert_eq!(
        commit_in_transaction(&c, &child_plan).unwrap(),
        AdmissionOutcome::RefusedBehindRejectedParent { parent: parent_hash }
    );
    assert!(!is_servable(&c, &child_hash).unwrap());
}

/// A staged child of a refused parent must be selected however many staged
/// rows sort ahead of it that the rules stamp preselects but whose refusal
/// has lapsed further down its `rests_on` chain.
///
/// Such a row is never consumed: its parent is not canonical and no longer
/// refused, so the child just waits for the parent to be fetched again. It
/// keeps its place at the front of the order on every call, and counted
/// against the selection's limit before being confirmed, enough of them
/// would crowd out every real candidate for good.
#[test]
fn lapsed_refusals_ahead_in_order_do_not_crowd_out_a_real_candidate() {
    use crate::dag_store::{record_rejected_change_resting_on, RejectionDomain};

    fn stage_at(c: &Connection, change: &Change, tag: u8, verified_at: i64) -> ChangeHash {
        let tx = c.unchecked_transaction().unwrap();
        stage_verified_bundles(&tx, &[bundle(change.clone(), checkpoint(tag))], verified_at)
            .unwrap();
        tx.commit().unwrap();
        change.compute_hash()
    }

    const LIMIT: usize = 2;
    let c = conn();

    // A basis refused on its own content, and refusals resting on it for
    // parents this device never held, each with a staged child.
    let basis = authored(5, 1, None, &[], "notes:basis.txt");
    let basis_hash = stage_at(&c, &basis, 1, 1);
    assert!(matches!(promote(&c, &basis_hash), AdmissionOutcome::RefusedPath(_)));
    for n in 0..=LIMIT as u64 {
        let absent_parent = authored(6, n + 1, None, &[], &format!("absent-{n}.txt"));
        record_rejected_change_resting_on(
            &c,
            &absent_parent.compute_hash(),
            GROUP,
            RejectionDomain::Path,
            Some(&basis_hash),
            None,
            "behind a refused basis",
            1,
        )
        .unwrap();
        let child = authored(7, n + 1, None, &[&absent_parent], &format!("waiting-{n}.txt"));
        stage_at(&c, &child, 10 + n as u8, 10 + n as i64);
    }
    // The basis's verdict is re-opened, so every refusal resting on it
    // lapses, while their own stamps stay current.
    c.execute(
        "UPDATE rejected_changes SET rules_version = rules_version - 1 WHERE change_hash = ?1",
        [&basis_hash.0[..]],
    )
    .unwrap();

    // A parent refused on its own content, and its staged child, which is
    // newer than every lapsed row.
    let parent = authored(2, 1, None, &[], "notes:draft.txt");
    let parent_hash = stage_at(&c, &parent, 50, 100);
    assert!(matches!(promote(&c, &parent_hash), AdmissionOutcome::RefusedPath(_)));
    let child = authored(3, 1, None, &[&parent], "child.txt");
    let child_hash = stage_at(&c, &child, 51, 101);

    assert_eq!(
        crate::verified_change_store::admissible_now(&c, &group(), LIMIT).unwrap(),
        vec![child_hash],
        "the one real candidate must be selected, not crowded out by rows that only look like one"
    );
}

/// A parent that becomes held here -- a prune tombstone, as a re-bootstrap
/// boundary installs one -- is not a refused parent, whatever its own row
/// still says under current rules. Its staged child must neither be refused
/// behind it nor be selected as a Change behind a refused parent, which it
/// would then be on every call without ever settling.
#[test]
fn a_held_parent_with_a_stale_refusal_row_refuses_nothing_behind_it() {
    let c = conn();
    let parent = authored(2, 1, None, &[], "notes:draft.txt");
    let child = authored(3, 1, None, &[&parent], "child.txt");
    let parent_hash = stage(&c, &parent, 1);
    let child_hash = stage(&c, &child, 2);
    let child_plan = plan_admission(&c, &child_hash).unwrap().unwrap();
    assert!(matches!(promote(&c, &parent_hash), AdmissionOutcome::RefusedPath(_)));

    c.execute(
        "INSERT INTO pruned_changes \
         (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
         VALUES (?1, ?2, ?3, 1, 1)",
        rusqlite::params![GROUP, &parent_hash.0[..], vec![0x5Au8; 32]],
    )
    .unwrap();
    assert!(rejection_stamp(&c, &parent_hash).is_some(), "sanity: the parent's row is untouched");

    assert!(
        !admissible_now_hashes(&c).contains(&child_hash),
        "a child of a held parent is not a Change behind a refused parent"
    );
    let outcome = commit_in_transaction(&c, &child_plan).unwrap();
    assert!(
        !matches!(outcome, AdmissionOutcome::RefusedBehindRejectedParent { .. }),
        "a held parent is never a reason to refuse, got {outcome:?}"
    );
    assert!(rejection_stamp(&c, &child_hash).is_none());
}
