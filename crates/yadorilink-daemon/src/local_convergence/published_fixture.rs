#![cfg(test)]

//! Publishing a change into a real `ReplicaCoordinator`, the way the
//! store actually requires it.
//!
//! Local emission alone produces a *Pending* change. Block-serving
//! authorization reads the published view, so a row indexed without a
//! published change behind it is correctly unservable: bytes present,
//! record present, no published evidence, serve refused. That state is
//! reachable and right, and a negative fixture may well want it.
//!
//! What `FakeReplicaState` got wrong was the other direction -- it
//! served with no published evidence at all. Fixtures written against
//! it therefore asserted over a peer that hands out bytes nothing
//! authorizes, which is why they had to be given a real publish here
//! rather than a looser store.
//!
//! So this publishes for real: one self-signed checkpoint covering the
//! change, its Merkle proof, and the evidence attached to the store.
//! Deliberately not a `FakeCoordination` stand-in -- the checkpoint is
//! cryptographically self-consistent, and it is run through
//! `verify_change_admission` before being attached, so a fixture cannot
//! publish evidence the admission contract would reject. A device
//! signing its own checkpoint is the minimal faithful stand-in for a
//! coordination plane these tests do not have; everything downstream of
//! that signature is the real check.
//!
//! The three things a servable block needs stay separate operations,
//! because they fail independently and a test may want only some of
//! them: the bytes in the store, the group's provenance for the block,
//! and a published change referencing the version.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
    fingerprint_signing_key, merkle_root, sign_checkpoint, verify_change_admission,
    AuthorizationCheckpoint,
};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_engine::ports::ChangeEvidence;

use crate::replica_coordinator::ReplicaCoordinator;

/// Self-signs a checkpoint covering `change` and returns its evidence,
/// verified against the admission contract first -- the shape the store
/// receives alongside an admitted change.
///
/// `checkpoint_seq` should increase per (group, device) because real
/// issuance is a strictly increasing per-group sequence and a fixture
/// that reuses one is modelling something issuance never emits. Storage
/// does not enforce it: `authorization_checkpoints` is keyed by
/// `checkpoint_hash`, with no unique constraint on the sequence.
pub(crate) fn verified_evidence(
    signing_key: &SigningKey,
    checkpoint_seq: u64,
    change: &Change,
) -> ChangeEvidence {
    let group_id = change.group_id.to_string();
    let device_id = change.device_id.to_string();
    let author_fingerprint = fingerprint_signing_key(&signing_key.verifying_key());
    let hashes = vec![change.compute_hash().0];

    let checkpoint = AuthorizationCheckpoint {
        group_id: group_id.clone(),
        device_id: device_id.clone(),
        signing_key_fingerprint: author_fingerprint,
        merkle_root: merkle_root(&hashes),
        leaf_count: hashes.len() as u64,
        checkpoint_seq,
        signer_key_id: author_fingerprint,
        policy_epoch: 0,
        policy_seq: 0,
        policy_head: [0u8; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, signing_key);
    let proof = build_merkle_proof(&hashes, 0);

    // The contract the published view is entitled to assume. Running it
    // here means a fixture cannot attach evidence that admission would
    // have refused -- which is the failure mode of publishing by hand.
    verify_change_admission(
        &group_id,
        &device_id,
        &signing_key.verifying_key(),
        hashes[0],
        &proof,
        &checkpoint,
        &signature,
        |signer_key_id, policy_head| {
            // Answers only for the checkpoint this helper just built. A
            // resolver that returned the key unconditionally would make
            // the verification below pass for a checkpoint naming some
            // other signer or policy head -- so a fixture that starts
            // building broken checkpoints would go on publishing them.
            (*signer_key_id == author_fingerprint && *policy_head == [0u8; 32])
                .then(|| signing_key.verifying_key())
        },
    )
    .expect("a self-signed checkpoint must satisfy the admission contract it is built from");

    ChangeEvidence {
        checkpoint_hash: checkpoint_hash(&encoded, &signature),
        checkpoint_seq,
        checkpoint_encoded: encoded,
        checkpoint_signature: signature.to_vec(),
        author_signing_public_key: signing_key.verifying_key().to_bytes(),
        merkle_proof_encoded: encode_merkle_proof(&proof),
    }
}

/// Publishes `change` into `state`: attaches [`verified_evidence`] for it
/// to the store's published view.
pub(crate) fn publish_change(
    state: &Arc<ReplicaCoordinator>,
    signing_key: &SigningKey,
    checkpoint_seq: u64,
    change: &Change,
) {
    let evidence = verified_evidence(signing_key, checkpoint_seq, change);
    let entries = vec![(change.compute_hash(), evidence.merkle_proof_encoded.clone())];
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::dag_store::published_view::attach_authorization_evidence(
                conn,
                &evidence.checkpoint_hash,
                &change.group_id.to_string(),
                &change.device_id.to_string(),
                checkpoint_seq,
                &evidence.checkpoint_encoded,
                &evidence.checkpoint_signature,
                &evidence.author_signing_public_key,
                &entries,
            )
        })
        .expect("attach self-signed checkpoint evidence");
}
