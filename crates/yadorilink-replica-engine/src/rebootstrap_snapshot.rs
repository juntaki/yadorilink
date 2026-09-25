//! Canonical materialized-state snapshot used by history re-bootstrap. A
//! checkpoint's `snapshot_hash` commits to the bytes produced here. The
//! snapshot carries more than the current file index: retained
//! version-history rows, the checkpoint-frontier `Change` bodies, every
//! `FileVersion` those rows/frontier changes need, and a
//! [`PublishedChangeWitness`] for every authoring Change compaction pruned
//! out of the frontier but whose content a retained [`SnapshotFile`] still
//! depends on. That last component lets a receiver independently re-verify
//! (`authorization_checkpoint:: verify_change_admission`) that every
//! retained version is backed by real authorization evidence, not
//! merely trust the outer manifest signer's word for it — see
//! `SnapshotFile::authoring_change_hash`'s own doc comment. Causality is
//! represented solely by retained signed changes, their frontier,
//! published-change witnesses, and content-addressed `FileVersion`s —
//! never by per-file counters. The domain tag below was advanced when
//! the retired version-vector section was removed, so a snapshot
//! written by any earlier build fails to decode rather than being
//! misinterpreted.
//! Advanced again (`\x02` -> `\x03`) when `SnapshotFile::
//! symlink_target`'s encoding changed from a UTF-8 string (`put_opt_str`/
//! `opt_string`, silently rejecting a real, non-UTF-8 symlink target) to a
//! raw length-prefixed byte string (`put_opt_bytes`/`opt_bytes`) — see
//! `change::FileMeta::symlink_target`'s doc for why a symlink target must
//! be captured byte-exactly.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::compaction::Checkpoint;
use crate::error::ReplicaEngineError;
use yadorilink_replica_domain::base_negotiation::{SummaryIdentity, SummaryIdentityBuilder};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, FolderGroupId, VersionHash};

// \x04: `unix_mode` widened from a single
// owner-exec bool byte to the full replicated-permission-bits encoding
// (a flag byte plus an optional u32) -- see `FileMeta::encode_into`'s
// identical shape for `unix_mode`. \x05 added `xattrs` (a count followed by sorted name/value
// pairs) -- see
// `FileMeta::encode_into`'s identical shape for `xattrs`. \x06 replaces `boundary_parent_auth`
// (dead since Changes stopped carrying auth_seq/auth_epoch pins) with
// `authoring_change_hash` per file and `published_change_witnesses`:
// the checkpoint evidence for an authoring Change that was pruned by
// compaction, so a version a compacted snapshot retains never loses its
// block-serving justification for lack of evidence -- see
// `SnapshotFile::authoring_change_hash`/`PublishedChangeWitness`'s own
// doc comments.
// \x07 carries the causal summary of the history the base replaces: each
// retained author's `(watermark, tip)`, the causally maximal present entry
// heads of every path, and the greatest Lamport the replaced history reached.
// Together they are what makes an installed base a description of a
// history rather than only of its files -- see [`SnapshotAuthorState`] and
// [`SnapshotPathHead`].
const SNAPSHOT_DOMAIN: &[u8; 8] = b"YLNKsnp\x07";
const MAX_SNAPSHOT_FILES: usize = 1_000_000;
const MAX_FRONTIER_CHANGES: usize = 4096;
const MAX_FILE_VERSIONS: usize = 1_000_000;
const MAX_WITNESSES: usize = 1_000_000;
const MAX_BOUNDARY_EDGES: usize = 1_000_000;
const MAX_AUTHOR_STATE: usize = 1_000_000;
const MAX_PATH_HEADS: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_BLOCKS_PER_FILE: usize = 1_000_000;
const MAX_XATTRS_PER_FILE: usize = 256;

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

    fn tag(self) -> u8 {
        match self {
            Self::Current => 0,
            Self::Superseded => 1,
            Self::Trashed => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ReplicaEngineError> {
        match tag {
            0 => Ok(Self::Current),
            1 => Ok(Self::Superseded),
            2 => Ok(Self::Trashed),
            _ => Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot has unknown version-history state".into(),
            )),
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
    /// The Change that authored this exact `(path, version_seq)` row --
    /// `None` only for a pre-authorization-model row (see
    /// `dag_store::published_view::published_file_at_path`'s doc comment
    /// on the same NULL case). [`RebootstrapSnapshot::new`] requires every
    /// row that names one to be justified: either that hash is itself
    /// among `frontier_changes`, or a matching entry exists in
    /// `published_change_witnesses` -- a row naming neither is exactly
    /// "content compaction retained with no surviving evidence," which
    /// this type must not be constructible with (design doc §3.7).
    pub authoring_change_hash: Option<ChangeHash>,
}

/// Checkpoint evidence for one Change that compaction pruned from
/// `frontier_changes` but whose content a retained [`SnapshotFile`] still
/// depends on -- see that field's own doc comment. Carries exactly what
/// [`crate::ports::ChangeEvidence`]/`dag_store::published_view::
/// attach_authorization_evidence` already carry for a live Change's
/// evidence (the checkpoint's own self-contained wire envelope plus this
/// Change's Merkle inclusion proof under it), so a receiver can verify it
/// with the SAME primitive (`authorization_checkpoint::
/// verify_change_admission`) ordinary Change admission uses -- a pruned
/// Change's evidence is not a weaker, second-class proof.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublishedChangeWitness {
    pub change_hash: ChangeHash,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_encoded: Vec<u8>,
    pub checkpoint_signature: Vec<u8>,
    pub author_signing_public_key: [u8; 32],
    pub merkle_proof_encoded: Vec<u8>,
}

/// Why a [`PublishedChangeWitness`] does not verify.
#[derive(Debug, thiserror::Error)]
pub enum WitnessVerifyError {
    #[error("the checkpoint signature is not 64 bytes")]
    MalformedSignature,
    #[error("the checkpoint envelope does not hash to the checkpoint hash it is carried under")]
    CheckpointHashMismatch,
    #[error("the checkpoint does not decode: {0:?}")]
    UndecodableCheckpoint(
        yadorilink_replica_domain::authorization_checkpoint::CheckpointDecodeError,
    ),
    #[error("the author signing key is not a valid key")]
    MalformedAuthorKey,
    #[error("the merkle proof does not decode: {0:?}")]
    UndecodableProof(yadorilink_replica_domain::authorization_checkpoint::CheckpointDecodeError),
    #[error("the checkpoint does not admit the change: {0:?}")]
    NotAdmissible(yadorilink_replica_domain::authorization_checkpoint::CheckpointAdmissionError),
}

impl PublishedChangeWitness {
    /// Verifies this witness as a received change's evidence is verified,
    /// less the change's own signature, whose body a witness does not
    /// carry: the envelope bound to its hash before it is decoded, then
    /// `authorization_checkpoint::verify_change_admission` -- a checkpoint
    /// for `expected_group_id` signed by the authority key
    /// `resolve_authority_key` resolves from the caller's own verified
    /// policy chain, bound to the carried author key, with a Merkle proof
    /// of exactly this change hash.
    ///
    /// Returns the verified checkpoint, which names the change's author.
    pub fn verify(
        &self,
        expected_group_id: &str,
        resolve_authority_key: impl FnOnce(&[u8; 32], &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey>,
    ) -> Result<
        yadorilink_replica_domain::authorization_checkpoint::AuthorizationCheckpoint,
        WitnessVerifyError,
    > {
        use yadorilink_replica_domain::authorization_checkpoint::{
            checkpoint_hash, decode_checkpoint, decode_merkle_proof, verify_change_admission,
        };
        let signature: [u8; 64] = self
            .checkpoint_signature
            .as_slice()
            .try_into()
            .map_err(|_| WitnessVerifyError::MalformedSignature)?;
        if checkpoint_hash(&self.checkpoint_encoded, &signature) != self.checkpoint_hash {
            return Err(WitnessVerifyError::CheckpointHashMismatch);
        }
        let checkpoint = decode_checkpoint(&self.checkpoint_encoded)
            .map_err(WitnessVerifyError::UndecodableCheckpoint)?;
        let author_key = ed25519_dalek::VerifyingKey::from_bytes(&self.author_signing_public_key)
            .map_err(|_| WitnessVerifyError::MalformedAuthorKey)?;
        let proof = decode_merkle_proof(&self.merkle_proof_encoded)
            .map_err(WitnessVerifyError::UndecodableProof)?;
        verify_change_admission(
            expected_group_id,
            &checkpoint.device_id,
            &author_key,
            self.change_hash.0,
            &proof,
            &checkpoint,
            &signature,
            resolve_authority_key,
        )
        .map_err(WitnessVerifyError::NotAdmissible)?;
        Ok(checkpoint)
    }
}

/// A direct parent edge crossing the checkpoint boundary -- `parent_hash`
/// is not itself among `frontier_changes` (compaction pruned its body),
/// but `child_hash` (a live frontier member) still declares it as a
/// parent. Purely a DAG-integrity record: it lets
/// `retained_history_integrity::retained_parent_edges_match` distinguish
/// an intentionally-pruned ancestor from a missing/corrupt one, and
/// `parent_lamport` preserves the pruned ancestor's causal-clock value so
/// lamport-ordering logic spanning the boundary does not need its full
/// body. This is NOT an authorization mechanism (an earlier revision's
/// now-removed `parent_auth_seq`/`parent_auth_epoch` fields were; proof-
/// carrying-change replaced them with [`PublishedChangeWitness`], which is
/// what a caller must consult to decide whether `parent_hash`'s content
/// may be served to a peer).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundaryParentAuth {
    pub child_hash: ChangeHash,
    pub parent_hash: ChangeHash,
    pub parent_lamport: u64,
}

/// One author's position in the history this snapshot replaces: the
/// highest sequence it reached, and the change that reached it.
///
/// Every author the replaced history retained appears here, whether or not
/// it still holds a live head anywhere. That is the difference between a
/// base that describes a history and one that only describes its files: an
/// author whose every write was later superseded is invisible in the
/// frontier and in the path heads, and a receiver that learned nothing
/// about it would have no position to measure its next change against.
/// Inventing one from that change — taking whatever sequence it happens to
/// name — would let the author choose its own watermark, and everything
/// below a watermark is treated as history already absorbed. The position
/// therefore travels with the base, or the base is not installable.
///
/// `tip_change_hash` travels with the watermark for the same reason it is
/// stored beside it locally: the number alone cannot tell a change that
/// continues this author's chain from one that forks away at the same
/// number. The tip settles it by name — a continuing change names the tip
/// as its author's previous change — which is the only form that survives
/// the install at all, since the change the tip refers to is routinely one
/// the base replaced and no walk could reach.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotAuthorState {
    pub device_id: String,
    pub watermark: AuthorSeq,
    pub tip_change_hash: ChangeHash,
}

/// One causally maximal present entry head of one path in the replaced
/// history: a write of a file, a symlink or a directory that nothing
/// later removed or rewrote. A structural directory, one that exists only
/// to hold something below it, is derived from the tree and has no head.
///
/// Heads that landed the same content are *not* one head. Two devices that
/// wrote identical bytes concurrently produced two writes, and a later
/// delete that descends from only one of them removes only that one; a
/// snapshot that had collapsed them into a single entry would have no way
/// to say that the other survives, and the content would be lost. The set
/// is therefore keyed by the change that wrote the head, never by
/// `version_hash`.
///
/// Per path there is at most one head per author, which is a consequence
/// of how a write to a path is formed rather than a policy. It is not the
/// author chain that gives it: the chain links an author's writes to each
/// other, and since an author's chain link is not a DAG parent, it orders
/// nothing in the path's own history. What gives it is path-local DAG
/// ordering. Every emission touching a path either refreshes that path's
/// materialized basis to a head set that contains the emitted change, or
/// invalidates that basis outright; and a local edit takes exactly the
/// basis it was made against as its parents. So an author's second write
/// to a path descends its first through the DAG itself, and the earlier
/// one cannot still be maximal.
///
/// Two heads here from one author is therefore corrupt state, and
/// [`RebootstrapSnapshot::new`] refuses to build such a snapshot. The
/// basis property it rests on is kept by the local emission seam, which
/// retires the basis of every path a change writes (derived conflict
/// copies and a restore's not-yet-written target included), and by prune
/// and base install, which drop every basis of the group. The refusal
/// stays regardless: it is what catches a writer that ever breaks that.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotPathHead {
    pub path: String,
    pub change_hash: ChangeHash,
    pub device_id: String,
    pub author_seq: AuthorSeq,
    pub lamport: u64,
    pub version_hash: VersionHash,
    /// The device whose name a conflict copy of this head's content would
    /// carry — equal to `device_id` for an ordinary write, and the original
    /// author for content carried forward on someone else's behalf. Same
    /// distinction, and same reason, as the live path frontier's own
    /// `naming_device_id`.
    pub naming_device_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RebootstrapSnapshot {
    pub group_id: FolderGroupId,
    pub files: Vec<SnapshotFile>,
    pub frontier_changes: Vec<Vec<u8>>,
    pub file_versions: Vec<Vec<u8>>,
    pub published_change_witnesses: Vec<PublishedChangeWitness>,
    pub boundary_parent_auth: Vec<BoundaryParentAuth>,
    /// `W`: every retained author's `(watermark, tip)`.
    pub author_state: Vec<SnapshotAuthorState>,
    /// `Gamma`: per path, the causally maximal present entry heads.
    pub path_heads: Vec<SnapshotPathHead>,
    /// The greatest Lamport any change in the replaced history reached,
    /// head or not.
    ///
    /// A third component of the summary rather than an optimisation. Heads
    /// are ranked by Lamport, so a base that forgot the ceiling would have
    /// to restart the clock at its own root, and a restarted clock makes
    /// the compaction observable in the order two replicas resolve a path
    /// into. The head sets cannot supply it either: a change that removed
    /// the path it wrote is nobody's content head and can still hold the
    /// greatest Lamport.
    pub lamport_ceiling: u64,
}

impl RebootstrapSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        group_id: FolderGroupId,
        mut files: Vec<SnapshotFile>,
        frontier_changes: Vec<Vec<u8>>,
        file_versions: Vec<Vec<u8>>,
        mut published_change_witnesses: Vec<PublishedChangeWitness>,
        mut boundary_parent_auth: Vec<BoundaryParentAuth>,
        mut author_state: Vec<SnapshotAuthorState>,
        mut path_heads: Vec<SnapshotPathHead>,
        lamport_ceiling: u64,
    ) -> Result<Self, ReplicaEngineError> {
        files.sort_by(|a, b| {
            a.record
                .path
                .cmp(&b.record.path)
                .then(a.version_seq.cmp(&b.version_seq))
                .then(a.state.cmp(&b.state))
        });
        if files.windows(2).any(|pair| {
            pair[0].record.path == pair[1].record.path && pair[0].version_seq == pair[1].version_seq
        }) {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains duplicate (path, version_seq) rows".into(),
            ));
        }
        let mut current_paths = BTreeSet::new();
        for file in &files {
            if file.state == SnapshotVersionState::Current
                && !current_paths.insert(file.record.path.clone())
            {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot contains more than one current row for a path".into(),
                ));
            }
        }

        let mut canonical_changes = Vec::with_capacity(frontier_changes.len());
        let mut frontier_dots: Vec<(String, AuthorSeq, u64)> =
            Vec::with_capacity(frontier_changes.len());
        for encoded in frontier_changes {
            let change = Change::from_wire_bytes(&encoded).map_err(|error| {
                ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            if change.group_id != group_id {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot frontier change belongs to another group".into(),
                ));
            }
            frontier_dots.push((
                change.device_id.as_str().to_owned(),
                change.author_seq,
                change.lamport,
            ));
            canonical_changes.push((change.compute_hash(), encoded));
        }
        canonical_changes.sort_by_key(|(hash, _)| *hash);
        if canonical_changes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains duplicate frontier changes".into(),
            ));
        }

        let mut canonical_versions = Vec::with_capacity(file_versions.len());
        for encoded in file_versions {
            let version = FileVersion::from_canonical_encoding(&encoded).map_err(|error| {
                ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid file version: {error}"
                ))
            })?;
            canonical_versions.push((version.version_hash, encoded));
        }
        canonical_versions.sort_by_key(|(hash, _)| *hash);
        if canonical_versions.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains duplicate file versions".into(),
            ));
        }

        published_change_witnesses.sort();
        published_change_witnesses.dedup();
        if published_change_witnesses
            .windows(2)
            .any(|pair| pair[0].change_hash == pair[1].change_hash)
        {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains two different witnesses for the same change".into(),
            ));
        }

        let frontier_hashes: std::collections::HashSet<ChangeHash> =
            canonical_changes.iter().map(|(hash, _)| *hash).collect();
        let witness_hashes: std::collections::HashSet<ChangeHash> =
            published_change_witnesses.iter().map(|w| w.change_hash).collect();
        for file in &files {
            let Some(authoring_change_hash) = file.authoring_change_hash else { continue };
            if !frontier_hashes.contains(&authoring_change_hash)
                && !witness_hashes.contains(&authoring_change_hash)
            {
                return Err(ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot retains {} (version_seq {}) authored by {} with no \
                     frontier change or witness justifying it -- refusing to construct a \
                     snapshot that could grant block-serving authorization with no evidence",
                    file.record.path,
                    file.version_seq,
                    authoring_change_hash.to_hex(),
                )));
            }
        }

        boundary_parent_auth.sort();
        boundary_parent_auth.dedup();

        refuse_unstorable_lamports(lamport_ceiling, &boundary_parent_auth)?;

        // The causal summary. Sorted so the canonical encoding is a
        // function of the content rather than of the order a builder
        // happened to produce it in, then checked for the things a
        // receiver cannot check for itself once the snapshot is installed.
        author_state.sort();
        author_state.dedup();
        if author_state.windows(2).any(|pair| pair[0].device_id == pair[1].device_id) {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot gives one author two different positions".into(),
            ));
        }
        for author in &author_state {
            if author.watermark.get() < 1 || author.watermark > AuthorSeq::MAX {
                return Err(ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot gives author {} a watermark of {}, which is not a \
                     position in any author chain",
                    author.device_id, author.watermark
                )));
            }
        }
        let watermark_of: std::collections::HashMap<&str, AuthorSeq> =
            author_state.iter().map(|a| (a.device_id.as_str(), a.watermark)).collect();

        // Every author the snapshot carries history for must have a
        // position in it. A frontier change whose author is missing here
        // is precisely the state this summary exists to prevent: the
        // receiver would install that change and still have no attested
        // position for the device that wrote it.
        for (device_id, author_seq, lamport) in &frontier_dots {
            match watermark_of.get(device_id.as_str()) {
                None => {
                    return Err(ReplicaEngineError::CorruptState(format!(
                        "re-bootstrap snapshot carries a frontier change by {device_id} but no \
                         position for that author"
                    )));
                }
                Some(watermark) if watermark < author_seq => {
                    return Err(ReplicaEngineError::CorruptState(format!(
                        "re-bootstrap snapshot puts author {device_id} at watermark {watermark} \
                         while carrying a frontier change of that author at sequence {author_seq}"
                    )));
                }
                Some(_) => {}
            }
            if *lamport > lamport_ceiling {
                return Err(ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot claims a Lamport ceiling of {lamport_ceiling} while \
                     carrying a frontier change at {lamport}"
                )));
            }
        }

        // Path heads. Deduplication is by `(path, change_hash)` and by
        // nothing else: two heads that landed the same `version_hash` are
        // two writes, and collapsing them would discard content the moment
        // a delete descends from only one of them.
        path_heads.sort();
        path_heads.dedup();
        if path_heads
            .windows(2)
            .any(|pair| pair[0].path == pair[1].path && pair[0].change_hash == pair[1].change_hash)
        {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot lists one change twice as a head of one path".into(),
            ));
        }
        let mut author_of_path_head: std::collections::HashSet<(&str, &str)> =
            std::collections::HashSet::new();
        for head in &path_heads {
            // At most one head per author per path -- see
            // `SnapshotPathHead`'s own doc comment for where that comes
            // from. An author's second write to a path descends its first
            // through the path's own basis, so the earlier one cannot be
            // maximal beside the later; two here means the history this
            // summary was built from was not a history.
            if !author_of_path_head.insert((head.path.as_str(), head.device_id.as_str())) {
                return Err(ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot lists two heads of {} by the same author {} -- one \
                     author's second write to a path descends its first, so this is not a \
                     summary of any history",
                    head.path, head.device_id
                )));
            }
            match watermark_of.get(head.device_id.as_str()) {
                None => {
                    return Err(ReplicaEngineError::CorruptState(format!(
                        "re-bootstrap snapshot lists a head of {} by {} but no position for that \
                         author",
                        head.path, head.device_id
                    )));
                }
                Some(watermark) if *watermark < head.author_seq => {
                    return Err(ReplicaEngineError::CorruptState(format!(
                        "re-bootstrap snapshot lists a head of {} at sequence {} by {}, above \
                         that author's own watermark {watermark}",
                        head.path, head.author_seq, head.device_id
                    )));
                }
                Some(_) => {}
            }
            if head.lamport > lamport_ceiling {
                return Err(ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot claims a Lamport ceiling of {lamport_ceiling} while \
                     listing a head of {} at {}",
                    head.path, head.lamport
                )));
            }
        }

        let snapshot = Self {
            group_id,
            files,
            frontier_changes: canonical_changes.into_iter().map(|(_, bytes)| bytes).collect(),
            file_versions: canonical_versions.into_iter().map(|(_, bytes)| bytes).collect(),
            published_change_witnesses,
            boundary_parent_auth,
            author_state,
            path_heads,
            lamport_ceiling,
        };
        snapshot.validate_bounds()?;
        Ok(snapshot)
    }

    fn validate_bounds(&self) -> Result<(), ReplicaEngineError> {
        if self.files.len() > MAX_SNAPSHOT_FILES
            || self.frontier_changes.len() > MAX_FRONTIER_CHANGES
            || self.file_versions.len() > MAX_FILE_VERSIONS
            || self.published_change_witnesses.len() > MAX_WITNESSES
            || self.boundary_parent_auth.len() > MAX_BOUNDARY_EDGES
            || self.author_state.len() > MAX_AUTHOR_STATE
            || self.path_heads.len() > MAX_PATH_HEADS
        {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot exceeds a collection bound".into(),
            ));
        }
        for witness in &self.published_change_witnesses {
            if witness.checkpoint_encoded.len() > MAX_BLOB_BYTES
                || witness.checkpoint_signature.len() > MAX_BLOB_BYTES
                || witness.merkle_proof_encoded.len() > MAX_BLOB_BYTES
            {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot witness exceeds a field bound".into(),
                ));
            }
        }
        for author in &self.author_state {
            if author.device_id.len() > MAX_STRING_BYTES {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot author state exceeds a field bound".into(),
                ));
            }
        }
        for head in &self.path_heads {
            if head.path.len() > MAX_STRING_BYTES
                || head.device_id.len() > MAX_STRING_BYTES
                || head.naming_device_id.len() > MAX_STRING_BYTES
            {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot path head exceeds a field bound".into(),
                ));
            }
        }
        for file in &self.files {
            if file.version_seq < 0
                || file.record.path.len() > MAX_STRING_BYTES
                || file.origin_device_id.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
                || file.symlink_target.as_ref().is_some_and(|v| v.len() > MAX_STRING_BYTES)
                || file.record.blocks.len() > MAX_BLOCKS_PER_FILE
            {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot file exceeds a field bound".into(),
                ));
            }
        }
        if self.frontier_changes.iter().any(|v| v.len() > MAX_BLOB_BYTES)
            || self.file_versions.iter().any(|v| v.len() > MAX_BLOB_BYTES)
        {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot blob exceeds the per-item bound".into(),
            ));
        }
        Ok(())
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_encoding()).into()
    }

    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_DOMAIN);
        put_str(&mut out, self.group_id.as_str());

        put_u32(&mut out, self.files.len() as u32);
        for file in &self.files {
            put_str(&mut out, &file.record.path);
            put_u64(&mut out, file.record.size);
            put_i64(&mut out, file.record.mtime_unix_nanos);
            out.push(file.record.deleted as u8);
            put_i64(&mut out, file.version_seq);
            out.push(file.state.tag());

            put_u32(&mut out, file.record.blocks.len() as u32);
            for block in &file.record.blocks {
                put_bytes(&mut out, &block.hash);
                put_u64(&mut out, block.offset);
                put_u32(&mut out, block.size);
            }

            put_opt_str(&mut out, file.origin_device_id.as_deref());
            out.push(match file.record_kind {
                RecordKind::File => 0,
                RecordKind::Directory => 1,
                RecordKind::Symlink => 2,
            });
            put_opt_bytes(&mut out, file.symlink_target.as_deref());
            out.push(file.symlink_out_of_root as u8);
            match file.unix_mode {
                None => out.push(0),
                Some(mode) => {
                    out.push(1);
                    put_u32(&mut out, mode);
                }
            }
            // Caller-guaranteed sorted by name (`FileMeta::xattrs`'s own
            // invariant) -- this snapshot format trusts it, same as it
            // already trusts every other field it re-encodes from this
            // device's own already-validated index rows.
            put_u32(&mut out, file.xattrs.len() as u32);
            for (name, value) in &file.xattrs {
                put_str(&mut out, name);
                put_bytes(&mut out, value);
            }
            match file.authoring_change_hash {
                None => out.push(0),
                Some(hash) => {
                    out.push(1);
                    out.extend_from_slice(&hash.0);
                }
            }
        }

        put_u32(&mut out, self.frontier_changes.len() as u32);
        for encoded in &self.frontier_changes {
            put_bytes(&mut out, encoded);
        }

        put_u32(&mut out, self.file_versions.len() as u32);
        for encoded in &self.file_versions {
            put_bytes(&mut out, encoded);
        }

        put_u32(&mut out, self.published_change_witnesses.len() as u32);
        for witness in &self.published_change_witnesses {
            out.extend_from_slice(&witness.change_hash.0);
            out.extend_from_slice(&witness.checkpoint_hash);
            put_bytes(&mut out, &witness.checkpoint_encoded);
            put_bytes(&mut out, &witness.checkpoint_signature);
            out.extend_from_slice(&witness.author_signing_public_key);
            put_bytes(&mut out, &witness.merkle_proof_encoded);
        }

        put_u32(&mut out, self.boundary_parent_auth.len() as u32);
        for edge in &self.boundary_parent_auth {
            out.extend_from_slice(&edge.child_hash.0);
            out.extend_from_slice(&edge.parent_hash.0);
            put_u64(&mut out, edge.parent_lamport);
        }

        put_u32(&mut out, self.author_state.len() as u32);
        for author in &self.author_state {
            put_str(&mut out, &author.device_id);
            put_u64(&mut out, author.watermark.get());
            out.extend_from_slice(&author.tip_change_hash.0);
        }

        put_u32(&mut out, self.path_heads.len() as u32);
        for head in &self.path_heads {
            put_str(&mut out, &head.path);
            out.extend_from_slice(&head.change_hash.0);
            put_str(&mut out, &head.device_id);
            put_u64(&mut out, head.author_seq.get());
            put_u64(&mut out, head.lamport);
            out.extend_from_slice(&head.version_hash.0);
            put_str(&mut out, &head.naming_device_id);
        }

        put_u64(&mut out, self.lamport_ceiling);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ReplicaEngineError> {
        let mut reader = Reader::new(bytes);
        reader.expect(SNAPSHOT_DOMAIN)?;
        let group_id = FolderGroupId(reader.string(MAX_STRING_BYTES)?);

        let file_count = reader.count(MAX_SNAPSHOT_FILES)?;
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            let path = reader.string(MAX_STRING_BYTES)?;
            let size = reader.u64()?;
            let mtime_unix_nanos = reader.i64()?;
            let deleted = reader.bool()?;
            let version_seq = reader.i64()?;
            let state = SnapshotVersionState::from_tag(reader.byte()?)?;

            let block_count = reader.count(MAX_BLOCKS_PER_FILE)?;
            let mut blocks = Vec::with_capacity(block_count);
            for _ in 0..block_count {
                blocks.push(BlockInfo {
                    hash: reader.bytes(MAX_BLOB_BYTES)?,
                    offset: reader.u64()?,
                    size: reader.u32()?,
                });
            }

            let origin_device_id = reader.opt_string(MAX_STRING_BYTES)?;
            let record_kind = match reader.byte()? {
                0 => RecordKind::File,
                1 => RecordKind::Directory,
                2 => RecordKind::Symlink,
                _ => {
                    return Err(ReplicaEngineError::CorruptState(
                        "re-bootstrap snapshot has unknown record kind".into(),
                    ));
                }
            };
            let symlink_target = reader.opt_bytes(MAX_STRING_BYTES)?;
            let symlink_out_of_root = reader.bool()?;
            let unix_mode = match reader.byte()? {
                0 => None,
                1 => Some(reader.u32()?),
                _ => {
                    return Err(ReplicaEngineError::CorruptState(
                        "re-bootstrap snapshot has unknown unix mode flag".into(),
                    ));
                }
            };
            let xattr_count = reader.count(MAX_XATTRS_PER_FILE)?;
            let mut xattrs = Vec::with_capacity(xattr_count);
            for _ in 0..xattr_count {
                let name = reader.string(MAX_STRING_BYTES)?;
                let value = reader.bytes(MAX_BLOB_BYTES)?;
                xattrs.push((name, value));
            }

            let authoring_change_hash = match reader.byte()? {
                0 => None,
                1 => Some(ChangeHash(reader.array32()?)),
                _ => {
                    return Err(ReplicaEngineError::CorruptState(
                        "re-bootstrap snapshot has unknown authoring-change-hash flag".into(),
                    ));
                }
            };

            files.push(SnapshotFile {
                record: FileRecord { path, size, mtime_unix_nanos, blocks, deleted },
                version_seq,
                state,
                origin_device_id,
                record_kind,
                symlink_target,
                symlink_out_of_root,
                unix_mode,
                xattrs,
                authoring_change_hash,
            });
        }

        let change_count = reader.count(MAX_FRONTIER_CHANGES)?;
        let mut frontier_changes = Vec::with_capacity(change_count);
        for _ in 0..change_count {
            frontier_changes.push(reader.bytes(MAX_BLOB_BYTES)?);
        }

        let version_count = reader.count(MAX_FILE_VERSIONS)?;
        let mut file_versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            file_versions.push(reader.bytes(MAX_BLOB_BYTES)?);
        }

        let witness_count = reader.count(MAX_WITNESSES)?;
        let mut published_change_witnesses = Vec::with_capacity(witness_count);
        for _ in 0..witness_count {
            published_change_witnesses.push(PublishedChangeWitness {
                change_hash: ChangeHash(reader.array32()?),
                checkpoint_hash: reader.array32()?,
                checkpoint_encoded: reader.bytes(MAX_BLOB_BYTES)?,
                checkpoint_signature: reader.bytes(MAX_BLOB_BYTES)?,
                author_signing_public_key: reader.array32()?,
                merkle_proof_encoded: reader.bytes(MAX_BLOB_BYTES)?,
            });
        }
        let boundary_count = reader.count(MAX_BOUNDARY_EDGES)?;
        let mut boundary_parent_auth = Vec::with_capacity(boundary_count);
        for _ in 0..boundary_count {
            boundary_parent_auth.push(BoundaryParentAuth {
                child_hash: ChangeHash(reader.array32()?),
                parent_hash: ChangeHash(reader.array32()?),
                parent_lamport: reader.u64()?,
            });
        }
        let author_count = reader.count(MAX_AUTHOR_STATE)?;
        let mut author_state = Vec::with_capacity(author_count);
        for _ in 0..author_count {
            author_state.push(SnapshotAuthorState {
                device_id: reader.string(MAX_STRING_BYTES)?,
                watermark: AuthorSeq(reader.u64()?),
                tip_change_hash: ChangeHash(reader.array32()?),
            });
        }
        let head_count = reader.count(MAX_PATH_HEADS)?;
        let mut path_heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            path_heads.push(SnapshotPathHead {
                path: reader.string(MAX_STRING_BYTES)?,
                change_hash: ChangeHash(reader.array32()?),
                device_id: reader.string(MAX_STRING_BYTES)?,
                author_seq: AuthorSeq(reader.u64()?),
                lamport: reader.u64()?,
                version_hash: VersionHash(reader.array32()?),
                naming_device_id: reader.string(MAX_STRING_BYTES)?,
            });
        }
        let lamport_ceiling = reader.u64()?;
        reader.finish()?;
        Self::new(
            group_id,
            files,
            frontier_changes,
            file_versions,
            published_change_witnesses,
            boundary_parent_auth,
            author_state,
            path_heads,
            lamport_ceiling,
        )
    }

    /// The identity of the causal summary this snapshot carries, as a base
    /// advertisement states it.
    pub fn summary_identity(&self) -> SummaryIdentity {
        summary_identity_of(&self.author_state, &self.path_heads, self.lamport_ceiling)
    }

    pub fn validate_against_checkpoint(
        &self,
        checkpoint: &Checkpoint,
    ) -> Result<(), ReplicaEngineError> {
        if self.group_id != checkpoint.group_id {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot group does not match checkpoint".into(),
            ));
        }
        if self.snapshot_hash() != checkpoint.snapshot_hash {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot hash does not match checkpoint".into(),
            ));
        }
        // A merged base is minted over the identity of the joined summary,
        // not over these bytes, so the snapshot hash alone does not tie the
        // summary it carries to the base: the identity has to match too.
        if let Some(merged_from) = &checkpoint.merged_from {
            if self.summary_identity() != merged_from.summary() {
                return Err(ReplicaEngineError::CorruptState(
                    "re-bootstrap snapshot does not carry the summary its merged checkpoint was \
                     minted over"
                        .into(),
                ));
            }
        }

        let snapshot_frontier: BTreeSet<ChangeHash> = self
            .frontier_changes
            .iter()
            .map(|encoded| {
                Change::from_wire_bytes(encoded).map(|change| change.compute_hash()).map_err(
                    |error| {
                        ReplicaEngineError::CorruptState(format!(
                            "re-bootstrap snapshot contains an invalid frontier change: {error}"
                        ))
                    },
                )
            })
            .collect::<Result<_, _>>()?;
        let checkpoint_frontier: BTreeSet<ChangeHash> =
            checkpoint.frontier.iter().copied().collect();
        if snapshot_frontier != checkpoint_frontier {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot frontier changes do not match checkpoint frontier".into(),
            ));
        }

        let version_hashes: BTreeSet<VersionHash> = self
            .file_versions
            .iter()
            .map(|encoded| {
                FileVersion::from_canonical_encoding(encoded)
                    .map(|version| version.version_hash)
                    .map_err(|error| {
                        ReplicaEngineError::CorruptState(format!(
                            "re-bootstrap snapshot contains an invalid file version: {error}"
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        for encoded in &self.frontier_changes {
            let change = Change::from_wire_bytes(encoded).map_err(|error| {
                ReplicaEngineError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            for op in &change.ops {
                let version = match op {
                    yadorilink_replica_domain::change::Op::Put { version, .. }
                    | yadorilink_replica_domain::change::Op::Move { version, .. } => Some(*version),
                    yadorilink_replica_domain::change::Op::Delete { .. } => None,
                };
                if version.is_some_and(|hash| !version_hashes.contains(&hash)) {
                    return Err(ReplicaEngineError::CorruptState(
                        "re-bootstrap snapshot is missing a frontier-referenced file version"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The identity of the summary `(W, Gamma, L)`, over its canonical order:
/// authors ascending by device id, heads ascending by path and then change
/// hash.
pub fn summary_identity_of(
    author_state: &[SnapshotAuthorState],
    path_heads: &[SnapshotPathHead],
    lamport_ceiling: u64,
) -> SummaryIdentity {
    let mut authors: Vec<_> = author_state.iter().collect();
    authors.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let mut heads: Vec<_> = path_heads.iter().collect();
    heads.sort_by(|a, b| (a.path.as_str(), a.change_hash).cmp(&(b.path.as_str(), b.change_hash)));

    let mut builder = SummaryIdentityBuilder::new(authors.len());
    for author in authors {
        builder.author(&author.device_id, author.watermark.0, &author.tip_change_hash);
    }
    builder.begin_heads(heads.len());
    for head in heads {
        builder.head(
            &head.path,
            &head.change_hash,
            &head.device_id,
            head.author_seq.0,
            head.lamport,
            &head.version_hash.0,
            &head.naming_device_id,
        );
    }
    builder.finish(lamport_ceiling)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
fn put_str(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}
fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            put_str(out, value);
        }
        None => out.push(0),
    }
}
/// Same shape as [`put_opt_str`], for a field with no UTF-8 requirement
/// (`SnapshotFile::symlink_target` — see its doc comment). Kept as a
/// distinct helper rather than folding `symlink_target` into `put_opt_str`
/// so the type system, not a convention, keeps a byte field from silently
/// being encoded as if it were text.
fn put_opt_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            out.push(1);
            put_bytes(out, value);
        }
        None => out.push(0),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ReplicaEngineError> {
        let end = self.pos.checked_add(len).ok_or_else(|| {
            ReplicaEngineError::CorruptState("re-bootstrap snapshot length overflow".into())
        })?;
        if end > self.bytes.len() {
            return Err(ReplicaEngineError::CorruptState("truncated re-bootstrap snapshot".into()));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), ReplicaEngineError> {
        if self.take(expected.len())? != expected {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot domain/version mismatch".into(),
            ));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, ReplicaEngineError> {
        Ok(self.take(1)?[0])
    }

    fn bool(&mut self) -> Result<bool, ReplicaEngineError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains non-canonical boolean".into(),
            )),
        }
    }

    fn u32(&mut self) -> Result<u32, ReplicaEngineError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ReplicaEngineError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, ReplicaEngineError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn count(&mut self, max: usize) -> Result<usize, ReplicaEngineError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot count exceeds bound".into(),
            ));
        }
        Ok(count)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, ReplicaEngineError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot item exceeds bound".into(),
            ));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self, max: usize) -> Result<String, ReplicaEngineError> {
        String::from_utf8(self.bytes(max)?).map_err(|_| {
            ReplicaEngineError::CorruptState("re-bootstrap snapshot contains invalid UTF-8".into())
        })
    }

    fn opt_string(&mut self, max: usize) -> Result<Option<String>, ReplicaEngineError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.string(max)?)),
            _ => Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains non-canonical option tag".into(),
            )),
        }
    }

    /// Byte-string counterpart of [`Self::opt_string`] — see `put_opt_bytes`'s
    /// doc comment for why `symlink_target` uses this instead.
    fn opt_bytes(&mut self, max: usize) -> Result<Option<Vec<u8>>, ReplicaEngineError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes(max)?)),
            _ => Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot contains non-canonical option tag".into(),
            )),
        }
    }

    fn array32(&mut self) -> Result<[u8; 32], ReplicaEngineError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn finish(self) -> Result<(), ReplicaEngineError> {
        if self.pos != self.bytes.len() {
            return Err(ReplicaEngineError::CorruptState(
                "re-bootstrap snapshot has trailing bytes".into(),
            ));
        }
        Ok(())
    }
}

/// Refuses Lamport values a replica cannot store. They are stored as SQLite
/// integers, and one past that range would be read back as damage by every
/// admission on the installed epoch. Heads and frontier changes are bounded
/// by the ceiling, so bounding the ceiling bounds them too.
fn refuse_unstorable_lamports(
    lamport_ceiling: u64,
    boundary_parent_auth: &[BoundaryParentAuth],
) -> Result<(), ReplicaEngineError> {
    const MAX_STORABLE_LAMPORT: u64 = i64::MAX as u64;
    if lamport_ceiling > MAX_STORABLE_LAMPORT {
        return Err(ReplicaEngineError::CorruptState(format!(
            "re-bootstrap snapshot claims a Lamport ceiling of {lamport_ceiling}, beyond the \
             storable range"
        )));
    }
    if let Some(edge) =
        boundary_parent_auth.iter().find(|edge| edge.parent_lamport > MAX_STORABLE_LAMPORT)
    {
        return Err(ReplicaEngineError::CorruptState(format!(
            "re-bootstrap snapshot carries a boundary parent at Lamport {}, beyond the storable \
             range",
            edge.parent_lamport
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
