//! The single verification of a proof-carrying Change.
//!
//! A proof-carrying Change is self-contained: everything needed to decide
//! whether it may be admitted travels with it. Nothing here is looked up from
//! the verifier's own state except the group's authority key, which is
//! resolved from the verifier's own already-verified policy chain — never from
//! anything the sender asserts.
//!
//! # No carrier appears in this signature
//!
//! There is no parameter here naming who delivered the Change, over what
//! transport, or through how many hops. That absence is the point: it makes
//!
//! ```text
//! Accept(change, direct) == Accept(change, relay) == Accept(change, TURN)
//! ```
//!
//! true by construction rather than by a separate rule each receive path has
//! to remember to apply the same way.
//!
//! # Why this is one function
//!
//! The sequence below has an order that matters — the checkpoint envelope is
//! bound to its hash *before* it is decoded any further, so a decode never
//! runs on bytes nothing has vouched for — and it has steps whose omission is
//! silent rather than loud. Assembled separately at each receive path, two
//! paths drift, and then an equivalence comparison between them measures
//! transport differences and verification differences at the same time
//! without being able to tell which is which. So every receive path calls
//! this.

use ed25519_dalek::VerifyingKey;

use crate::authorization_checkpoint::{
    checkpoint_hash as compute_checkpoint_hash, decode_checkpoint, verify_change_admission,
    AuthorizationCheckpoint, CheckpointAdmissionError, CheckpointDecodeError, MerkleProof,
};
use std::collections::BTreeSet;

use crate::change::{Change, Op};
use crate::codec::ChangeError;
use crate::file::FileVersion;
use crate::ids::{ChangeHash, VersionHash};

/// Everything that travels with a Change so a receiver can verify it offline.
///
/// The caller supplies the checkpoint envelope; how it was obtained differs by
/// receive path (carried in the same wire batch, held in a staged bundle) and
/// is not this function's concern.
#[derive(Clone, Copy, Debug)]
pub struct ProofCarryingChange<'a> {
    /// The Change's own signed bytes, exactly as received.
    pub encoded_change: &'a [u8],
    /// The hash the sender claims for the checkpoint envelope below.
    pub checkpoint_hash: &'a [u8; 32],
    /// The checkpoint's canonical signing bytes.
    pub checkpoint_encoded: &'a [u8],
    /// The authority's signature over those bytes.
    pub checkpoint_signature: &'a [u8; 64],
    /// The author's raw signing key, carried alongside rather than looked up,
    /// so a device that has never seen this author can still verify. It is
    /// not trusted on its own: the checkpoint's signed fingerprint is what
    /// vouches for it.
    pub author_signing_public_key: &'a [u8; 32],
    /// The Merkle inclusion proof binding this Change to that checkpoint.
    pub proof: &'a MerkleProof,
}

/// What verification established.
#[derive(Clone, Debug)]
pub struct VerifiedChange {
    pub change: Change,
    pub change_hash: ChangeHash,
    /// The decoded checkpoint. Returned so a caller that indexes the envelope
    /// can check its own index fields against what was actually signed,
    /// rather than against what was carried beside it.
    pub checkpoint: AuthorizationCheckpoint,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofVerificationError {
    /// The carried bytes do not decode to a Change.
    UndecodableChange(ChangeError),

    /// The Change belongs to a different group than the one being verified
    /// for.
    GroupMismatch { expected: String, actual: String },

    /// The carried bytes are not the Change's canonical encoding.
    ///
    /// The hash covers the canonical form, so a second encoding that decodes
    /// to the same Change hashes identically while carrying different bytes —
    /// bytes a receiver would then store and re-serve to other peers.
    NonCanonicalEncoding,

    /// The envelope does not hash to the checkpoint hash claimed for it.
    ///
    /// Checked before the envelope is decoded any further, so no decode ever
    /// runs on bytes nothing has vouched for.
    CheckpointHashMismatch,

    /// The checkpoint envelope does not decode.
    UndecodableCheckpoint(CheckpointDecodeError),

    /// The checkpoint is for a different group than the Change.
    CheckpointGroupMismatch { change: String, checkpoint: String },

    /// The checkpoint is for a different device than the Change's author.
    CheckpointDeviceMismatch { change: String, checkpoint: String },

    /// The carried author key is not a valid public key.
    MalformedAuthorKey,

    /// The Change's own signature does not verify under the carried key.
    BadChangeSignature(ChangeError),

    /// The Change is not admissible under its checkpoint.
    NotAdmissible(CheckpointAdmissionError),
}

impl std::fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndecodableChange(error) => write!(f, "change does not decode: {error}"),
            Self::GroupMismatch { expected, actual } => {
                write!(f, "change is bound to group {actual}, expected {expected}")
            }
            Self::NonCanonicalEncoding => {
                f.write_str("the carried bytes are not the change's canonical encoding")
            }
            Self::CheckpointHashMismatch => {
                f.write_str("checkpoint envelope does not match the claimed checkpoint hash")
            }
            Self::UndecodableCheckpoint(error) => {
                write!(f, "checkpoint does not decode: {error:?}")
            }
            Self::CheckpointGroupMismatch { change, checkpoint } => {
                write!(f, "checkpoint is bound to group {checkpoint} but the change to {change}")
            }
            Self::CheckpointDeviceMismatch { change, checkpoint } => write!(
                f,
                "checkpoint is for device {checkpoint} but the change was authored by {change}"
            ),
            Self::MalformedAuthorKey => f.write_str("author signing key is not a valid public key"),
            Self::BadChangeSignature(error) => {
                write!(f, "the change's own signature does not verify: {error}")
            }
            Self::NotAdmissible(error) => {
                write!(f, "the change is not admissible under its checkpoint: {error:?}")
            }
        }
    }
}

impl std::error::Error for ProofVerificationError {}

/// Verify a proof-carrying Change in full.
///
/// The order below is deliberate:
///
/// 1. decode the Change;
/// 2. require it to belong to `expected_group_id`;
/// 3. require the carried bytes to be its canonical encoding;
/// 4. bind the checkpoint envelope to its claimed hash, *before* decoding it;
/// 5. decode the checkpoint;
/// 6. require its group and device to match the Change's own;
/// 7. verify the Change's own signature under the carried author key;
/// 8. hash that carried key and match the checkpoint's signed fingerprint;
/// 9. resolve the authority key from the caller's verified policy chain;
/// 10. verify the checkpoint's signature under it;
/// 11. verify the Merkle proof for this exact Change hash.
///
/// Steps 8 through 11 are `verify_change_admission`'s, called here rather than
/// restated. The Change's own signature is checked before them, so a Change
/// that is not even self-consistent costs no key resolution.
///
/// `resolve_authority_key(signer_key_id, policy_head)` must be backed by the
/// caller's own verified policy chain for the group. A bare "trust this key"
/// is never accepted, for the same reason a `PolicyRecord` signed by a
/// rotated-out authority key is rejected elsewhere: which key is authoritative
/// is a question only the verified chain can answer.
pub fn verify_proof_carrying_change(
    input: &ProofCarryingChange<'_>,
    expected_group_id: &str,
    resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey>,
) -> Result<VerifiedChange, ProofVerificationError> {
    // 1.
    let change = Change::from_wire_bytes(input.encoded_change)
        .map_err(ProofVerificationError::UndecodableChange)?;

    // 2.
    if change.group_id.as_str() != expected_group_id {
        return Err(ProofVerificationError::GroupMismatch {
            expected: expected_group_id.to_owned(),
            actual: change.group_id.as_str().to_owned(),
        });
    }

    // 3.
    if change.to_wire_bytes() != input.encoded_change {
        return Err(ProofVerificationError::NonCanonicalEncoding);
    }

    // 4. Before any further decode: nothing below runs on bytes that have not
    // been bound to the hash they were delivered under.
    if compute_checkpoint_hash(input.checkpoint_encoded, input.checkpoint_signature)
        != *input.checkpoint_hash
    {
        return Err(ProofVerificationError::CheckpointHashMismatch);
    }

    // 5.
    let checkpoint = decode_checkpoint(input.checkpoint_encoded)
        .map_err(ProofVerificationError::UndecodableCheckpoint)?;

    // 6.
    if checkpoint.group_id != change.group_id.as_str() {
        return Err(ProofVerificationError::CheckpointGroupMismatch {
            change: change.group_id.as_str().to_owned(),
            checkpoint: checkpoint.group_id,
        });
    }
    if checkpoint.device_id != change.device_id.as_str() {
        return Err(ProofVerificationError::CheckpointDeviceMismatch {
            change: change.device_id.as_str().to_owned(),
            checkpoint: checkpoint.device_id,
        });
    }

    let author_key = VerifyingKey::from_bytes(input.author_signing_public_key)
        .map_err(|_| ProofVerificationError::MalformedAuthorKey)?;

    // 8. Before the checkpoint's own signature: a Change that is not even
    // self-consistent is refused without consulting the policy chain.
    change.verify_signature(&author_key).map_err(ProofVerificationError::BadChangeSignature)?;

    // 7, 9, 10, 11.
    let change_hash = change.compute_hash();
    verify_change_admission(
        expected_group_id,
        change.device_id.as_str(),
        &author_key,
        change_hash.0,
        input.proof,
        &checkpoint,
        input.checkpoint_signature,
        resolve_authority_key,
    )
    .map_err(ProofVerificationError::NotAdmissible)?;

    Ok(VerifiedChange { change, change_hash, checkpoint })
}

/// Every file version a Change refers to directly.
///
/// "Directly" is the whole boundary. A `FileVersion` names block hashes, and
/// those blocks are content, fetched over the block lane. What a Change
/// cannot be admitted without is the version *metadata* — without it the DAG
/// has no record of what the `Put` even refers to — so that is what travels
/// with the proof and this is what defines the set.
///
/// Ordered and deduplicated, because it is compared against what a bundle
/// carried and a comparison of multisets would let the same version be
/// counted twice.
pub fn directly_referenced_versions(change: &Change) -> BTreeSet<VersionHash> {
    change
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Put { version, .. } | Op::Move { version, .. } => Some(*version),
            Op::Delete { .. } => None,
        })
        .collect()
}

/// Why a bundle's carried versions do not match the Change it carries.
#[derive(Debug, PartialEq, Eq)]
pub enum CarriedVersionError {
    /// A version the Change refers to was not carried, so this Change could
    /// never be admitted from this bundle alone.
    Missing { version: VersionHash },

    /// A version was carried that this Change does not refer to.
    ///
    /// Refused rather than ignored. A Change is a legitimate, authorized
    /// object; if unrelated metadata could ride along with one, then any
    /// authorized author becomes a carrier for injecting rows into another
    /// device's storage that nothing in the DAG references and nothing will
    /// ever collect.
    Unrelated { version: VersionHash },

    /// The same version was carried more than once.
    ///
    /// Not merged silently: two copies under one hash are either identical,
    /// in which case one is waste, or different, in which case the sender is
    /// asking which one this device will keep. Neither is a question a
    /// receiver should be answering.
    Duplicate { version: VersionHash },

    /// A carried version's bytes do not hash to the identity claimed for it,
    /// or its structure is invalid.
    Invalid { version: VersionHash, reason: ChangeError },
}

impl std::fmt::Display for CarriedVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarriedVersionError::Missing { version } => {
                write!(f, "the change refers to file version {version:?}, which was not carried")
            }
            CarriedVersionError::Unrelated { version } => {
                write!(
                    f,
                    "file version {version:?} was carried but the change does not refer to it"
                )
            }
            CarriedVersionError::Duplicate { version } => {
                write!(f, "file version {version:?} was carried more than once")
            }
            CarriedVersionError::Invalid { version, reason } => {
                write!(f, "carried file version {version:?} is not valid: {reason}")
            }
        }
    }
}

impl std::error::Error for CarriedVersionError {}

/// Check that `carried` is exactly the set of versions `change` refers to,
/// and that each one is what it claims to be.
///
/// Equality, not containment, in both directions:
///
/// ```text
///   carried_version_hashes == unique(directly_referenced_versions(change))
/// ```
///
/// The forward direction is what makes a bundle self-contained: with every
/// referenced version present, admission needs nothing from the network,
/// which keeps "delivery complete" and "admissible" from acquiring a third
/// waiting condition that only more network traffic can clear. The reverse
/// direction is what stops a Change being used as a carrier for metadata
/// nothing refers to.
///
/// A sender does not omit a version because it thinks the receiver already
/// holds it. Self-containment is a property of the bundle, not of a guess
/// about the far end; deduplication is the receiver's business, and it can do
/// it safely because these are content-addressed.
pub fn verify_carried_versions(
    change: &Change,
    carried: &[FileVersion],
) -> Result<(), CarriedVersionError> {
    let required = directly_referenced_versions(change);

    let mut seen: BTreeSet<VersionHash> = BTreeSet::new();
    for version in carried {
        // Recomputes the hash from the bytes and applies the full structural
        // contract. A version's claimed identity is never taken on trust.
        version.verify_hash().map_err(|reason| CarriedVersionError::Invalid {
            version: version.version_hash,
            reason,
        })?;

        if !required.contains(&version.version_hash) {
            return Err(CarriedVersionError::Unrelated { version: version.version_hash });
        }
        if !seen.insert(version.version_hash) {
            return Err(CarriedVersionError::Duplicate { version: version.version_hash });
        }
    }

    if let Some(missing) = required.difference(&seen).next() {
        return Err(CarriedVersionError::Missing { version: *missing });
    }

    Ok(())
}

#[cfg(test)]
mod tests;
