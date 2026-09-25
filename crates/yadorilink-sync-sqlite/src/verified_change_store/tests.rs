#![cfg(test)]

use super::test_support::{bundle, change_touching, checkpoint, conn, stage_in_tx, GROUP};
use super::*;

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

#[test]
fn a_staged_change_is_possessed_without_being_canonical() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = change.compute_hash();

    stage_in_tx(&c, &[bundle(change, checkpoint(1))], 1).unwrap();

    assert!(is_servable(&c, &hash).unwrap(), "delivery is complete");
    assert!(!is_canonical(&c, &hash).unwrap(), "but it is not canonical yet");
    assert_eq!(servable_change_hashes(&c, &group()).unwrap(), vec![hash]);
}

/// The property that stops the retransmission storm: a Change that is
/// received and verified but parked — waiting on a parent, or on a local
/// capture barrier — already counts as delivered, so a peer comparing
/// sets sees no difference and does not send it again.
#[test]
fn a_change_blocked_from_promotion_is_still_never_re_requested() {
    let c = conn();
    let parent = change_touching(vec![], 0, &["a.txt"]);
    let child = change_touching(vec![parent.compute_hash()], parent.lamport, &["a.txt"]);
    let child_hash = child.compute_hash();

    // Only the child is delivered. Its parent is nowhere.
    stage_in_tx(&c, &[bundle(child, checkpoint(1))], 1).unwrap();

    assert!(is_servable(&c, &child_hash).unwrap(), "an unpromotable Change is still possessed");
    assert!(
        admissible_now(&c, &group(), 16).unwrap().is_empty(),
        "and it is correctly not promotable"
    );
}

#[test]
fn redelivery_is_idempotent() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let staged = bundle(change, checkpoint(1));

    let first = stage_in_tx(&c, std::slice::from_ref(&staged), 1).unwrap();
    assert_eq!(first.len(), 1);

    for _ in 0..5 {
        let again = stage_in_tx(&c, std::slice::from_ref(&staged), 2).unwrap();
        assert!(again.is_empty(), "a redelivery must do no work");
    }

    assert_eq!(servable_change_hashes(&c, &group()).unwrap().len(), 1);
}

/// The same principle the reconciliation engine needed: a peer must not be
/// able to get the valid front of a batch applied by putting something
/// malformed behind it.
#[test]
fn a_batch_with_a_malformed_bundle_stages_none_of_it() {
    let c = conn();
    let good = change_touching(vec![], 0, &["a.txt"]);
    let good_hash = good.compute_hash();

    let mut bad = bundle(change_touching(vec![], 0, &["b.txt"]), checkpoint(1));
    // Bytes that do not decode to the Change presented with them.
    bad.encoded = b"not a change".to_vec();

    let result = stage_in_tx(&c, &[bundle(good, checkpoint(1)), bad], 1);

    assert!(result.is_err(), "the batch must be refused");
    assert!(
        !is_servable(&c, &good_hash).unwrap(),
        "the valid bundle ahead of the malformed one must not have been staged"
    );
    assert!(servable_change_hashes(&c, &group()).unwrap().is_empty());
}

#[test]
fn one_batch_cannot_stage_two_payloads_under_one_checkpoint_hash() {
    let c = conn();
    let mut forged = checkpoint(1);
    forged.encoded = vec![0xFF; 8];

    let result = stage_in_tx(
        &c,
        &[
            bundle(change_touching(vec![], 0, &["a.txt"]), checkpoint(1)),
            bundle(change_touching(vec![], 0, &["b.txt"]), forged),
        ],
        1,
    );

    assert!(result.is_err());
    assert!(servable_change_hashes(&c, &group()).unwrap().is_empty());
}

#[test]
fn a_staged_change_bound_to_another_group_than_its_checkpoint_is_refused() {
    let c = conn();
    let mut foreign = checkpoint(1);
    foreign.group_id = FolderGroupId("other-group".into());

    let result = stage_in_tx(&c, &[bundle(change_touching(vec![], 0, &["a.txt"]), foreign)], 1);

    assert!(result.is_err());
    assert!(servable_change_hashes(&c, &group()).unwrap().is_empty());
}

#[test]
fn a_staged_change_survives_a_reopen() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = change.compute_hash();

    {
        let c = rusqlite::Connection::open(file.path()).unwrap();
        crate::dag_store::init_dag_schema(&c).unwrap();
        init_verified_change_schema(&c).unwrap();
        stage_in_tx(&c, &[bundle(change, checkpoint(1))], 1).unwrap();
    }

    // A crash between verification and promotion loses nothing: the
    // process is gone, the staged object is not.
    let c = rusqlite::Connection::open(file.path()).unwrap();
    assert!(is_servable(&c, &hash).unwrap());
    assert!(load_staged(&c, &hash).unwrap().is_some());
}

#[test]
fn a_bundle_reads_back_identically_from_either_side_of_promotion() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = change.compute_hash();
    let staged_bundle = bundle(change, checkpoint(1));

    stage_in_tx(&c, std::slice::from_ref(&staged_bundle), 1).unwrap();
    let while_staged = load_servable(&c, &hash).unwrap().expect("servable while staged");

    let plan = crate::remote_admission::plan_admission(&c, &hash).unwrap().unwrap();
    let tx = c.unchecked_transaction().unwrap();
    crate::remote_admission::commit_admission(&tx, &plan).unwrap();
    tx.commit().unwrap();

    let once_canonical = load_servable(&c, &hash).unwrap().expect("still servable once canonical");

    // A peer asking for this hash cannot tell which side of promotion it
    // is on, which is what lets promotion be invisible to reconciliation.
    assert_eq!(while_staged.encoded, once_canonical.encoded);
    assert_eq!(while_staged.merkle_proof, once_canonical.merkle_proof);
    assert_eq!(while_staged.checkpoint, once_canonical.checkpoint);
}

/// A locally authored Change with no checkpoint yet is Pending. It is
/// possessed locally but not servable: with no evidence there is nothing
/// for a receiver to verify, and serving it would amount to asking a peer
/// to trust the carrier.
#[test]
fn a_canonical_change_without_evidence_is_not_servable() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = change.compute_hash();

    crate::dag_store::admit_change(&c, &change).unwrap();

    assert!(is_canonical(&c, &hash).unwrap());
    assert!(load_servable(&c, &hash).unwrap().is_none());
    assert!(servable_change_hashes(&c, &group()).unwrap().is_empty());
}

#[test]
fn a_change_cannot_be_staged_against_a_checkpoint_that_was_never_staged() {
    let c = conn();
    let change = change_touching(vec![], 0, &["a.txt"]);
    let hash = change.compute_hash();

    // Bypass `stage_verified_bundles`, which always writes the checkpoint
    // first, to prove the invariant is enforced by the schema rather than
    // only by that function's ordering.
    let result = c.execute(
        "INSERT INTO verified_change_objects \
         (change_hash, group_id, encoded, checkpoint_hash, merkle_proof, verified_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &hash.0[..],
            GROUP,
            change.to_wire_bytes(),
            &[9u8; 32][..],
            &[0u8; 4][..],
            1
        ],
    );

    assert!(result.is_err(), "the trigger must reject an unstaged checkpoint");
}
