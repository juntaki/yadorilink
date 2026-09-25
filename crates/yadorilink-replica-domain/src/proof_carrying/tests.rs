#![cfg(test)]

use crate::test_authoring::create_signed_for_tests;
use ed25519_dalek::SigningKey;

use super::*;
use crate::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, fingerprint_signing_key, merkle_root,
    sign_checkpoint,
};
use crate::change::Op;
use crate::ids::{DeviceId, FolderGroupId, SyncPath};

const GROUP: &str = "g";
const DEVICE: &str = "device-A";

fn author() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn authority() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn signed_change(group: &str, device: &str) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId(device.into()),
        FolderGroupId(group.into()),
        vec![Op::Delete { path: SyncPath("a.txt".into()) }],
        &author(),
    )
}

/// Everything an honest sender would produce for `change`.
struct Carried {
    encoded_change: Vec<u8>,
    checkpoint_hash: [u8; 32],
    checkpoint_encoded: Vec<u8>,
    signature: [u8; 64],
    author_key: [u8; 32],
    proof: MerkleProof,
}

impl Carried {
    fn as_input(&self) -> ProofCarryingChange<'_> {
        ProofCarryingChange {
            encoded_change: &self.encoded_change,
            checkpoint_hash: &self.checkpoint_hash,
            checkpoint_encoded: &self.checkpoint_encoded,
            checkpoint_signature: &self.signature,
            author_signing_public_key: &self.author_key,
            proof: &self.proof,
        }
    }
}

fn carry(change: &Change, checkpoint_group: &str, checkpoint_device: &str) -> Carried {
    let leaves = vec![change.compute_hash().0];
    let checkpoint = AuthorizationCheckpoint {
        group_id: checkpoint_group.to_string(),
        device_id: checkpoint_device.to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author().verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority().verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let signature = sign_checkpoint(&checkpoint, &authority());
    let checkpoint_encoded = canonical_signing_bytes(&checkpoint);
    Carried {
        encoded_change: change.to_wire_bytes(),
        checkpoint_hash: crate::authorization_checkpoint::checkpoint_hash(
            &checkpoint_encoded,
            &signature,
        ),
        checkpoint_encoded,
        signature,
        author_key: author().verifying_key().to_bytes(),
        proof: build_merkle_proof(&leaves, 0),
    }
}

fn honest() -> Carried {
    carry(&signed_change(GROUP, DEVICE), GROUP, DEVICE)
}

fn resolve_real(key_id: &[u8; 32], _head: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    let authority = authority().verifying_key();
    (*key_id == fingerprint_signing_key(&authority)).then_some(authority)
}

fn verify(carried: &Carried) -> Result<VerifiedChange, ProofVerificationError> {
    verify_proof_carrying_change(&carried.as_input(), GROUP, resolve_real)
}

#[test]
fn an_honest_proof_carrying_change_verifies() {
    let carried = honest();
    let verified = verify(&carried).expect("honest input must verify");
    assert_eq!(verified.change_hash, verified.change.compute_hash());
    assert_eq!(verified.checkpoint.checkpoint_seq, 1);
}

/// No parameter here names who delivered the Change, so acceptance cannot
/// depend on it. Verifying the identical bytes twice — as two different
/// receive paths would — must give the identical answer.
#[test]
fn the_same_bytes_verify_identically_however_they_arrived() {
    let carried = honest();
    let first = verify(&carried).unwrap();
    let second = verify(&carried).unwrap();
    assert_eq!(first.change_hash, second.change_hash);
    assert_eq!(first.checkpoint, second.checkpoint);
}

#[test]
fn a_change_for_another_group_is_refused() {
    let carried = carry(&signed_change("other", DEVICE), "other", DEVICE);
    assert!(matches!(
        verify_proof_carrying_change(&carried.as_input(), GROUP, resolve_real),
        Err(ProofVerificationError::GroupMismatch { .. })
    ));
}

#[test]
fn a_checkpoint_naming_another_group_than_the_change_is_refused() {
    let change = signed_change(GROUP, DEVICE);
    let carried = carry(&change, "other", DEVICE);
    assert!(matches!(
        verify(&carried),
        Err(ProofVerificationError::CheckpointGroupMismatch { .. })
    ));
}

#[test]
fn a_checkpoint_naming_another_device_than_the_author_is_refused() {
    let change = signed_change(GROUP, DEVICE);
    let carried = carry(&change, GROUP, "device-Z");
    assert!(matches!(
        verify(&carried),
        Err(ProofVerificationError::CheckpointDeviceMismatch { .. })
    ));
}

/// The envelope is bound to its hash before it is decoded any further, so
/// no decode ever runs on bytes nothing has vouched for.
#[test]
fn an_envelope_that_does_not_match_its_claimed_hash_is_refused_before_decoding() {
    let mut carried = honest();
    carried.checkpoint_hash[0] ^= 0xFF;
    assert!(matches!(verify(&carried), Err(ProofVerificationError::CheckpointHashMismatch)));

    // Also when the envelope itself is the altered half: still refused at
    // the hash, not at the decode.
    let mut carried = honest();
    carried.checkpoint_encoded.push(0);
    assert!(matches!(verify(&carried), Err(ProofVerificationError::CheckpointHashMismatch)));
}

#[test]
fn a_change_signed_by_a_different_key_than_the_checkpoint_vouches_for_is_refused() {
    let mut carried = honest();
    carried.author_key = SigningKey::from_bytes(&[3u8; 32]).verifying_key().to_bytes();
    // The signature check runs before the policy chain is consulted, so a
    // Change that is not even self-consistent costs no key resolution.
    assert!(matches!(verify(&carried), Err(ProofVerificationError::BadChangeSignature(_))));
}

#[test]
fn a_checkpoint_signed_by_a_key_the_policy_chain_rejects_is_refused() {
    let carried = honest();
    assert!(matches!(
        verify_proof_carrying_change(&carried.as_input(), GROUP, |_, _| None),
        Err(ProofVerificationError::NotAdmissible(
            CheckpointAdmissionError::UnknownOrInvalidSignerKey
        ))
    ));
}

#[test]
fn a_proof_for_a_different_change_is_refused() {
    let mut carried = honest();
    let other = carry(&signed_change(GROUP, DEVICE), GROUP, DEVICE);
    // A proof built over a different leaf set cannot recompute this
    // checkpoint's root.
    carried.proof = build_merkle_proof(&[[0xAB; 32], other.checkpoint_hash], 0);
    assert!(matches!(verify(&carried), Err(ProofVerificationError::NotAdmissible(_))));
}

#[test]
fn undecodable_change_bytes_are_refused() {
    let mut carried = honest();
    carried.encoded_change.push(0);
    assert!(matches!(verify(&carried), Err(ProofVerificationError::UndecodableChange(_))));

    let mut carried = honest();
    carried.encoded_change.clear();
    assert!(matches!(verify(&carried), Err(ProofVerificationError::UndecodableChange(_))));
}

/// A carried author key that is not the one the checkpoint vouches for is
/// refused however it is malformed.
///
/// Which check catches it depends on the bytes: some patterns fail to
/// decompress to a curve point and are refused as a malformed key, while
/// others decompress to a valid point that simply is not the signer, and
/// are refused at the signature. Both are fail-closed, and the test asserts
/// the property rather than which of the two fired.
#[test]
fn an_author_key_that_is_not_the_vouched_for_one_is_refused() {
    for pattern in [[0xFF; 32], [0x00; 32], [0x01; 32]] {
        let mut carried = honest();
        carried.author_key = pattern;
        assert!(
            verify(&carried).is_err(),
            "author key {pattern:02x?} must not verify against this checkpoint"
        );
    }
}
