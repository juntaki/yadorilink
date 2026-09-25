//! Verifying a staged bundle, through the one verification primitive.
//!
//! Everything cryptographic lives in
//! [`yadorilink_replica_domain::proof_carrying`], which every receive path in
//! this codebase calls. This module only adapts a [`VerifiedChangeBundle`] to
//! that call and then checks the one thing the domain cannot: that the fields
//! carried beside the checkpoint envelope, which this device would index it
//! under, agree with what the authority actually signed.

use ed25519_dalek::VerifyingKey;
use yadorilink_replica_domain::authorization_checkpoint::decode_merkle_proof;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::proof_carrying::{
    verify_proof_carrying_change, ProofCarryingChange, ProofVerificationError,
};
use yadorilink_sync_sqlite::verified_change_store::VerifiedChangeBundle;

#[derive(Debug, thiserror::Error)]
pub enum BundleVerifyError {
    /// The bundle did not verify. Every cryptographic check lives behind this
    /// variant, in the shared primitive.
    #[error(transparent)]
    Proof(#[from] ProofVerificationError),

    #[error("checkpoint signature is not 64 bytes")]
    MalformedSignature,

    #[error("the merkle proof does not decode: {0:?}")]
    UndecodableProof(yadorilink_replica_domain::authorization_checkpoint::CheckpointDecodeError),

    /// The checkpoint's signed content disagrees with the fields carried
    /// beside it. Those fields are what this device indexes the envelope
    /// under, so if they could disagree the index would describe something the
    /// authority never vouched for.
    #[error("checkpoint envelope disagrees with the {field} carried alongside it")]
    EnvelopeDisagreement { field: &'static str },

    /// The carried file versions are not exactly the set the Change refers
    /// to. Checked here, before anything is staged, so a bundle that could
    /// never be admitted is refused at the point it arrives rather than
    /// becoming a possessed Change that waits forever.
    #[error(transparent)]
    CarriedVersions(#[from] yadorilink_replica_domain::proof_carrying::CarriedVersionError),
}

/// Verify a bundle in full, returning the Change's hash if it is admissible.
pub fn verify_bundle(
    bundle: &VerifiedChangeBundle,
    expected_group: &str,
    resolve_authority_key: &(dyn Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + Send + Sync),
) -> Result<ChangeHash, BundleVerifyError> {
    let signature: [u8; 64] = bundle
        .checkpoint
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| BundleVerifyError::MalformedSignature)?;

    let proof =
        decode_merkle_proof(&bundle.merkle_proof).map_err(BundleVerifyError::UndecodableProof)?;

    let verified = verify_proof_carrying_change(
        &ProofCarryingChange {
            encoded_change: &bundle.encoded,
            checkpoint_hash: &bundle.checkpoint.checkpoint_hash,
            checkpoint_encoded: &bundle.checkpoint.encoded,
            checkpoint_signature: &signature,
            author_signing_public_key: &bundle.checkpoint.author_signing_public_key,
            proof: &proof,
        },
        expected_group,
        |key_id, policy_head| resolve_authority_key(key_id, policy_head),
    )?;

    // The group and device carried beside the envelope are already covered:
    // the primitive requires the signed checkpoint to name the Change's own
    // group and device, and the bundle's own staging refuses a group
    // mismatch. The sequence number is not, and it is indexed.
    if verified.checkpoint.checkpoint_seq != bundle.checkpoint.checkpoint_seq {
        return Err(BundleVerifyError::EnvelopeDisagreement { field: "checkpoint sequence" });
    }
    if verified.checkpoint.device_id != bundle.checkpoint.device_id {
        return Err(BundleVerifyError::EnvelopeDisagreement { field: "device id" });
    }

    // Against the *verified* Change rather than the one carried beside it:
    // the set of versions a bundle owes is defined by the Change the
    // signature covers, so deriving it from anything else would let the
    // carried copy choose its own obligations.
    yadorilink_replica_domain::proof_carrying::verify_carried_versions(
        &verified.change,
        &bundle.versions,
    )?;

    Ok(verified.change_hash)
}
