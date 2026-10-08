//! What a native bootstrap carries beside the native state itself: the index
//! rows a snapshot installs, the witness that vouches for each row's native
//! head (the signed delta plus its publication evidence), and the projection
//! state a device recorded (kept copies and stable names). Placements are not
//! carried: a receiver derives them from the heads, and a reconciliation hold
//! describes one device's disk.
//! [`NativeSnapshotState::validate`] checks the shape a received snapshot must
//! have before anything in it is installed.

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::native_checkpoint::ProjectionDigest;

use crate::error::ReplicaEngineError;

const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOCKS_PER_FILE: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotVersionState {
    Current,
    Superseded,
    Trashed,
}

impl SnapshotVersionState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Superseded => "superseded",
            Self::Trashed => "trashed",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        match value {
            "current" => Some(Self::Current),
            "superseded" => Some(Self::Superseded),
            "trashed" => Some(Self::Trashed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotFile {
    pub record: FileRecord,
    pub version_seq: i64,
    pub state: SnapshotVersionState,
    pub origin_device_id: Option<String>,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    /// The canonical identity of the native head this row shows
    /// (`NativeRowIdentity::to_bytes`), when the row was produced under native
    /// authority. [`NativeSnapshotState::validate`] requires a
    /// [`NativeRowWitness`] of exactly the row's version for every identity.
    pub native_identity: Option<Vec<u8>>,
}

/// What vouches for a native row: the version its identity's head carried, the
/// signed delta that head came from, and that delta's publication evidence (its
/// checkpoint envelope and merkle proof). The proof's leaf is only the delta's
/// hash, so the delta itself is carried: it is what binds the identity's source
/// path, dot and the version the row shows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeRowWitness {
    pub identity: Vec<u8>,
    pub version: VersionHash,
    pub delta_wire: Vec<u8>,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_encoded: Vec<u8>,
    pub checkpoint_signature: Vec<u8>,
    pub author_signing_public_key: [u8; 32],
    pub merkle_proof_encoded: Vec<u8>,
}

/// A live head declared a kept conflict copy, by exact identity: its source
/// path, the dot that created it and the hash of the delta that did so.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeKeptHead {
    pub source_path: String,
    pub author: String,
    pub incarnation: [u8; 16],
    pub seq: u64,
    pub provenance: [u8; 32],
}

/// A stable name a head was bound to when it first lost a name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeBindingEntry {
    pub source_path: String,
    pub author: String,
    pub incarnation: [u8; 16],
    pub seq: u64,
    pub stable_path: String,
}

/// The native half of a snapshot. Empty for a group with no native rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeSnapshotState {
    pub row_witnesses: Vec<NativeRowWitness>,
    pub kept_heads: Vec<NativeKeptHead>,
    pub bindings: Vec<NativeBindingEntry>,
}

impl NativeRowWitness {
    /// Verifies the witness as a received delta is verified (its signature,
    /// checkpoint and merkle proof, under the authority key
    /// `resolve_authority_key` resolves) and that the delta binds the tuple
    /// the row cites: its hash is the identity's provenance, its author and
    /// sequence are the identity's dot, and it has an op at the identity's
    /// source path that puts exactly the witnessed version.
    pub fn verify(
        &self,
        expected_group_id: &str,
        resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey>,
    ) -> Result<(), String> {
        use yadorilink_replica_domain::authorization_checkpoint::decode_merkle_proof;
        use yadorilink_replica_domain::native_plan::NativeRowIdentity;
        use yadorilink_replica_domain::proof_carrying_delta::{
            verify_proof_carrying_delta, ProofCarryingDelta,
        };
        let identity = NativeRowIdentity::from_bytes(&self.identity).map_err(|e| e.to_string())?;
        let signature: [u8; 64] = self
            .checkpoint_signature
            .as_slice()
            .try_into()
            .map_err(|_| "the checkpoint signature is not 64 bytes".to_string())?;
        let proof = decode_merkle_proof(&self.merkle_proof_encoded)
            .map_err(|error| format!("the merkle proof does not decode: {error:?}"))?;
        let verified = verify_proof_carrying_delta(
            &ProofCarryingDelta {
                encoded_delta: &self.delta_wire,
                checkpoint_hash: &self.checkpoint_hash,
                checkpoint_encoded: &self.checkpoint_encoded,
                checkpoint_signature: &signature,
                author_signing_public_key: &self.author_signing_public_key,
                proof: &proof,
            },
            expected_group_id,
            resolve_authority_key,
        )
        .map_err(|error| format!("the delta's publication does not verify: {error:?}"))?;
        if verified.delta_hash != identity.provenance {
            return Err("the delta is not the head the row's identity names".into());
        }
        if verified.delta.dot() != identity.dot {
            return Err("the delta's author and sequence are not the identity's dot".into());
        }
        let binds = verified.delta.ops.iter().any(|op| {
            op.path == identity.source_path
                && op.put.as_ref().is_some_and(|put| put.version == self.version)
        });
        if !binds {
            return Err(
                "the delta does not put the witnessed version at the identity's path".into()
            );
        }
        Ok(())
    }
}

/// Domain tag of [`NativeSnapshotState::projection_digest`]'s preimage. The
/// last byte is the encoding generation.
const PROJECTION_DIGEST_TAG: &[u8; 8] = b"YLNKnpd\x02";

impl NativeSnapshotState {
    /// Refuses a snapshot state whose entries are malformed, out of bounds or
    /// ambiguous: a witness with a malformed identity or two witnesses for
    /// one identity, a binding that names one head twice or at sequence zero,
    /// and any string or blob past its bound.
    pub fn validate(&self) -> Result<(), ReplicaEngineError> {
        let corrupt = |detail: &str| ReplicaEngineError::CorruptState(detail.to_owned());
        let mut identities: Vec<&[u8]> = Vec::with_capacity(self.row_witnesses.len());
        for witness in &self.row_witnesses {
            if witness.delta_wire.len() > MAX_BLOB_BYTES
                || witness.checkpoint_encoded.len() > MAX_BLOB_BYTES
                || witness.checkpoint_signature.len() > MAX_BLOB_BYTES
                || witness.merkle_proof_encoded.len() > MAX_BLOB_BYTES
            {
                return Err(corrupt("a native witness exceeds a field bound"));
            }
            yadorilink_replica_domain::native_plan::NativeRowIdentity::from_bytes(
                &witness.identity,
            )
            .map_err(|error| {
                ReplicaEngineError::CorruptState(format!(
                    "a native witness has a malformed identity: {error}"
                ))
            })?;
            identities.push(&witness.identity);
        }
        identities.sort_unstable();
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(corrupt("one native identity has two witnesses"));
        }
        let mut bound: Vec<(&str, &str, [u8; 16], u64)> = self
            .bindings
            .iter()
            .map(|b| (b.source_path.as_str(), b.author.as_str(), b.incarnation, b.seq))
            .collect();
        bound.sort_unstable();
        if bound.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(corrupt("one native head is bound to two names"));
        }
        if self.bindings.iter().any(|b| {
            b.seq == 0
                || b.stable_path.len() > MAX_STRING_BYTES
                || b.source_path.len() > MAX_STRING_BYTES
                || b.author.len() > MAX_STRING_BYTES
        }) || self.kept_heads.iter().any(|k| {
            k.seq == 0
                || k.source_path.len() > MAX_STRING_BYTES
                || k.author.len() > MAX_STRING_BYTES
        }) {
            return Err(corrupt("a native entry is malformed"));
        }
        let mut kept: Vec<(&str, &str, [u8; 16], u64)> = self
            .kept_heads
            .iter()
            .map(|k| (k.source_path.as_str(), k.author.as_str(), k.incarnation, k.seq))
            .collect();
        kept.sort_unstable();
        if kept.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(corrupt("one native head is kept twice"));
        }
        Ok(())
    }
}

impl NativeSnapshotState {
    /// The digest a checkpoint commits to for the projection facts this state
    /// carries: kept heads and stable names (the witnesses prove
    /// themselves, each by its own signed delta). Domain-separated, over a
    /// canonical encoding that does not depend on the order the entries are
    /// held in. A state with none digests to [`ProjectionDigest::NONE`].
    pub fn projection_digest(&self) -> ProjectionDigest {
        if self.kept_heads.is_empty() && self.bindings.is_empty() {
            return ProjectionDigest::NONE;
        }
        fn put_bytes(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        fn put_count(hasher: &mut Sha256, count: usize) {
            hasher.update((count as u64).to_be_bytes());
        }
        let mut hasher = Sha256::new();
        hasher.update(PROJECTION_DIGEST_TAG);

        let mut kept: Vec<&NativeKeptHead> = self.kept_heads.iter().collect();
        kept.sort_unstable();
        put_count(&mut hasher, kept.len());
        for head in kept {
            put_bytes(&mut hasher, head.source_path.as_bytes());
            put_bytes(&mut hasher, head.author.as_bytes());
            hasher.update(head.incarnation);
            hasher.update(head.seq.to_be_bytes());
            hasher.update(head.provenance);
        }

        let mut bindings: Vec<&NativeBindingEntry> = self.bindings.iter().collect();
        bindings.sort_unstable();
        put_count(&mut hasher, bindings.len());
        for binding in bindings {
            put_bytes(&mut hasher, binding.source_path.as_bytes());
            put_bytes(&mut hasher, binding.author.as_bytes());
            hasher.update(binding.incarnation);
            hasher.update(binding.seq.to_be_bytes());
            put_bytes(&mut hasher, binding.stable_path.as_bytes());
        }
        ProjectionDigest(hasher.finalize().into())
    }
}

impl SnapshotFile {
    /// Whether the row's own fields are within their bounds.
    pub fn validate(&self) -> Result<(), ReplicaEngineError> {
        if self.version_seq < 0
            || self.record.path.len() > MAX_STRING_BYTES
            || self.origin_device_id.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
            || self.symlink_target.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
            || self.record.blocks.len() > MAX_BLOCKS_PER_FILE
        {
            return Err(ReplicaEngineError::CorruptState(
                "a snapshot file exceeds a field bound".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(stable: &str) -> NativeBindingEntry {
        NativeBindingEntry {
            source_path: "a".to_owned(),
            author: "device-a".to_owned(),
            incarnation: [1; 16],
            seq: 1,
            stable_path: stable.to_owned(),
        }
    }

    fn kept(path: &str, seq: u8) -> NativeKeptHead {
        NativeKeptHead {
            source_path: path.into(),
            author: "device-a".into(),
            incarnation: [1; 16],
            seq: u64::from(seq),
            provenance: [seq; 32],
        }
    }

    fn state_with(
        kept_heads: Vec<NativeKeptHead>,
        bindings: Vec<NativeBindingEntry>,
    ) -> NativeSnapshotState {
        NativeSnapshotState { row_witnesses: Vec::new(), kept_heads, bindings }
    }

    #[test]
    fn the_projection_digest_commits_to_every_fact_and_not_to_order() {
        let base = state_with(
            vec![kept("a", 1), kept("b", 2)],
            vec![binding("one"), NativeBindingEntry { seq: 2, ..binding("two") }],
        );
        let digest = base.projection_digest();
        assert_ne!(digest, ProjectionDigest::NONE);
        assert_eq!(state_with(Vec::new(), Vec::new()).projection_digest(), ProjectionDigest::NONE);

        let mut reordered = base.clone();
        reordered.kept_heads.reverse();
        reordered.bindings.reverse();
        assert_eq!(reordered.projection_digest(), digest, "order is not committed");

        let mut retargeted = base.clone();
        retargeted.kept_heads[0].provenance = [9; 32];
        assert_ne!(retargeted.projection_digest(), digest, "a kept head's provenance is committed");
        let mut moved = base.clone();
        moved.kept_heads[0].seq = 7;
        assert_ne!(moved.projection_digest(), digest, "a kept head's dot is committed");
        let mut renamed = base.clone();
        renamed.bindings[0].stable_path = "other".into();
        assert_ne!(renamed.projection_digest(), digest);
        let mut dropped = base.clone();
        dropped.kept_heads.pop();
        assert_ne!(dropped.projection_digest(), digest);
        let mut dropped = base.clone();
        dropped.bindings.pop();
        assert_ne!(dropped.projection_digest(), digest);
        let mut added = base.clone();
        added.kept_heads.push(kept("c", 3));
        assert_ne!(added.projection_digest(), digest);

        // A fact moved from one list to another is not the same fact.
        let in_kept = state_with(
            vec![NativeKeptHead {
                source_path: String::new(),
                author: String::new(),
                incarnation: [0; 16],
                seq: 0,
                provenance: [0; 32],
            }],
            Vec::new(),
        );
        let in_bindings = state_with(
            Vec::new(),
            vec![NativeBindingEntry {
                source_path: String::new(),
                author: String::new(),
                incarnation: [0; 16],
                seq: 0,
                stable_path: String::new(),
            }],
        );
        assert_ne!(in_kept.projection_digest(), in_bindings.projection_digest());
    }

    /// The digest of one fixed state, byte for byte, under the current generation
    /// tag. The kept-copy entry names an exact head (author, incarnation,
    /// sequence, provenance); a digest of the previous shape (a kept version)
    /// was taken under the previous tag and cannot equal one of this shape.
    #[test]
    fn the_projection_digest_of_a_fixed_state_is_pinned_to_its_generation() {
        let state = state_with(vec![kept("a", 1), kept("b", 2)], vec![binding("a (copy)")]);
        assert_eq!(&PROJECTION_DIGEST_TAG[..7], b"YLNKnpd");
        assert_ne!(PROJECTION_DIGEST_TAG[7], 1, "the generation of the version-keyed shape");
        assert_eq!(
            hex_of(&state.projection_digest().0),
            "6a56eb7717a7ff3c72e17c312eb6fc0f7525308d602dc6de57ef99b3cc3a4256"
        );
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_head_kept_twice_or_at_sequence_zero_is_refused() {
        assert!(state_with(vec![kept("a", 1)], Vec::new()).validate().is_ok());
        let twice = state_with(vec![kept("a", 1), kept("a", 1)], Vec::new());
        assert!(twice.validate().is_err(), "one head named twice is ambiguous");
        let mut zero = kept("a", 1);
        zero.seq = 0;
        assert!(state_with(vec![zero], Vec::new()).validate().is_err());
    }

    #[test]
    fn a_head_bound_to_two_names_is_refused() {
        let state = state_with(Vec::new(), vec![binding("one"), binding("two")]);
        assert!(state.validate().is_err());
    }

    #[test]
    fn a_witness_with_a_malformed_identity_is_refused() {
        let mut state = state_with(Vec::new(), Vec::new());
        state.row_witnesses = vec![NativeRowWitness {
            identity: b"junk".to_vec(),
            version: VersionHash([0; 32]),
            delta_wire: Vec::new(),
            checkpoint_hash: [0; 32],
            checkpoint_encoded: Vec::new(),
            checkpoint_signature: Vec::new(),
            author_signing_public_key: [0; 32],
            merkle_proof_encoded: Vec::new(),
        }];
        assert!(state.validate().is_err());
    }
}
