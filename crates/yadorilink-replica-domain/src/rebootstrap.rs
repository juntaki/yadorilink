//! Pure signed-object surface of history bases: a deterministic
//! history-epoch identity ([`HistoryBase`]), a condensed pruned-prefix
//! checkpoint ([`Checkpoint`]/[`CheckpointHash`]), and a signed snapshot
//! manifest ([`SnapshotManifest`]).

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::change;
use crate::codec::ChangeError;
use crate::ids::{ChangeHash, DeviceId, FolderGroupId};

// \x03: the \x01 layout again. \x02 (retired) added a summary identity and
// frontier-position commitment to every checkpoint; that model was dropped,
// and a number once used is not reused.
const CHECKPOINT_DOMAIN_TAG: &[u8; 8] = b"YLNKckp\x03";
const MERGED_CHECKPOINT_DOMAIN_TAG: &[u8; 8] = b"YLNKckm\x03";
const HISTORY_BASE_DOMAIN: &[u8; 8] = b"YLNKhbs\x01";
const HISTORY_BASE_MERGE_DOMAIN: &[u8; 8] = b"YLNKhbm\x01";
const SNAPSHOT_MANIFEST_DOMAIN: &[u8; 8] = b"YLNKsmf\x01";
const MAX_REBOOTSTRAP_HEADS: usize = 1024;
const MAX_FRONTIER: usize = 1024;

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, value: &str) {
    put_len_bytes(out, value.as_bytes());
}

fn decode_err(message: &str) -> ChangeError {
    ChangeError::Encoding(format!("rebootstrap decode: {message}"))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ChangeError> {
        if self.remaining() < count {
            return Err(decode_err("unexpected end of input"));
        }
        let out = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, ChangeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], ChangeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn array64(&mut self) -> Result<[u8; 64], ChangeError> {
        Ok(self.take(64)?.try_into().unwrap())
    }

    fn bounded_count(&mut self, min_entry_size: usize, max: usize) -> Result<usize, ChangeError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(decode_err(&format!("count {count} exceeds bound {max}")));
        }
        if min_entry_size > 0 && count > self.remaining() / min_entry_size {
            return Err(decode_err(&format!(
                "count {count} exceeds the {} entries the remaining bytes can hold",
                self.remaining() / min_entry_size
            )));
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String, ChangeError> {
        let count = self.u32()? as usize;
        let bytes = self.take(count)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| ChangeError::Encoding(e.to_string()))
    }

    fn expect_end(&self) -> Result<(), ChangeError> {
        if self.remaining() != 0 {
            return Err(decode_err("trailing bytes after decode"));
        }
        Ok(())
    }
}

// --- Checkpoint --------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointHash(pub [u8; 32]);

impl CheckpointHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CheckpointHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CheckpointHash({})", hex::encode(self.0))
    }
}

/// A condensed pruned prefix. `frontier` is canonical ascending+deduped.
///
/// A checkpoint either seals one history, and the base above it is derived
/// from the checkpoint's own hash, or carries the join of two histories
/// ([`MergedFrom`]), and the base above it is the one minted over that
/// join ([`HistoryBase::mint_merged`]). Either way the base is a function
/// of the checkpoint alone, so everything that names a base by its
/// checkpoint -- a signed manifest, an advertisement, the installed row --
/// names a merged base the same way it names a sealed one.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    pub group_id: FolderGroupId,
    pub frontier: Vec<ChangeHash>,
    pub snapshot_hash: [u8; 32],
    /// The two bases a merged checkpoint joins and the identity of the
    /// joined summary; `None` for a checkpoint that seals one history.
    pub merged_from: Option<MergedFrom>,
}

/// What a merged checkpoint stands for: the two bases whose summaries were
/// joined, and the identity of the joined summary.
///
/// These are exactly the inputs of [`HistoryBase::mint_merged`], carried so
/// that anyone holding the checkpoint derives the same minted base, and so
/// that the snapshot the checkpoint commits to can be checked to carry the
/// summary the base was minted over. The snapshot bytes are not an input:
/// two replicas that merge the same two bases into the same summary found
/// one base, however each lays out the rows of its snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MergedFrom {
    low: HistoryBase,
    high: HistoryBase,
    summary: crate::base_negotiation::SummaryIdentity,
}

impl MergedFrom {
    /// The merge of `a` and `b` into the summary `summary` identifies.
    /// Symmetric in `a` and `b`. A base merged with itself is not a merge:
    /// nothing is minted for it, so it is refused here.
    pub fn new(
        a: HistoryBase,
        b: HistoryBase,
        summary: crate::base_negotiation::SummaryIdentity,
    ) -> Result<Self, ChangeError> {
        if a == b {
            return Err(ChangeError::Malformed(
                "a merged checkpoint joins two different bases".into(),
            ));
        }
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        Ok(Self { low, high, summary })
    }

    /// The two merged bases, ascending.
    pub fn bases(&self) -> (HistoryBase, HistoryBase) {
        (self.low, self.high)
    }

    /// The identity of the joined summary.
    pub fn summary(&self) -> crate::base_negotiation::SummaryIdentity {
        self.summary
    }
}

impl Checkpoint {
    pub fn new(
        group_id: FolderGroupId,
        mut frontier: Vec<ChangeHash>,
        snapshot_hash: [u8; 32],
    ) -> Self {
        frontier.sort();
        frontier.dedup();
        Self { group_id, frontier, snapshot_hash, merged_from: None }
    }

    /// A checkpoint over the join of two histories: the base above it is
    /// the one minted over `merged_from`.
    pub fn new_merged(
        group_id: FolderGroupId,
        frontier: Vec<ChangeHash>,
        snapshot_hash: [u8; 32],
        merged_from: MergedFrom,
    ) -> Self {
        Self { merged_from: Some(merged_from), ..Self::new(group_id, frontier, snapshot_hash) }
    }

    /// A sealing checkpoint encodes exactly as it always has; a merged one
    /// under its own domain tag, followed by what it merged.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(match self.merged_from {
            None => CHECKPOINT_DOMAIN_TAG,
            Some(_) => MERGED_CHECKPOINT_DOMAIN_TAG,
        });
        put_str(&mut buf, self.group_id.as_str());
        put_u32(&mut buf, self.frontier.len() as u32);
        for hash in &self.frontier {
            buf.extend_from_slice(&hash.0);
        }
        buf.extend_from_slice(&self.snapshot_hash);
        if let Some(merged_from) = &self.merged_from {
            buf.extend_from_slice(&merged_from.low.0);
            buf.extend_from_slice(&merged_from.high.0);
            buf.extend_from_slice(&merged_from.summary.0);
        }
        buf
    }

    pub fn checkpoint_hash(&self) -> CheckpointHash {
        CheckpointHash(Sha256::digest(self.canonical_encoding()).into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader::new(bytes);
        let merged = match reader.take(8)? {
            tag if tag == CHECKPOINT_DOMAIN_TAG => false,
            tag if tag == MERGED_CHECKPOINT_DOMAIN_TAG => true,
            _ => return Err(decode_err("bad checkpoint domain tag")),
        };
        let group_id = FolderGroupId(reader.string()?);
        let count = reader.bounded_count(32, MAX_FRONTIER)?;
        let mut frontier = Vec::with_capacity(count);
        for _ in 0..count {
            frontier.push(ChangeHash(reader.array32()?));
        }
        if !frontier.windows(2).all(|window| window[0] < window[1]) {
            return Err(decode_err("frontier is not strictly ascending"));
        }
        let snapshot_hash = reader.array32()?;
        let merged_from = if merged {
            let low = HistoryBase(reader.array32()?);
            let high = HistoryBase(reader.array32()?);
            let summary = crate::base_negotiation::SummaryIdentity(reader.array32()?);
            if low >= high {
                return Err(decode_err("merged bases are not strictly ascending"));
            }
            Some(MergedFrom { low, high, summary })
        } else {
            None
        };
        reader.expect_end()?;
        Ok(Self { group_id, frontier, snapshot_hash, merged_from })
    }
}

/// Stable identity for the history epoch above one committed checkpoint.
/// Devices may exchange ordinary DAG changes only when they share this base.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryBase(pub [u8; 32]);

impl HistoryBase {
    /// The base above `checkpoint`: derived from the checkpoint's hash for
    /// a checkpoint that seals one history, and the base minted over the
    /// join for a merged one.
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        if let Some(merged_from) = &checkpoint.merged_from {
            return Self::mint_merged(
                &checkpoint.group_id,
                merged_from.low,
                merged_from.high,
                &merged_from.summary,
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(HISTORY_BASE_DOMAIN);
        hasher.update(checkpoint.checkpoint_hash().as_bytes());
        Self(hasher.finalize().into())
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// The base founded on the join of two incomparable histories: `a` and
    /// `b` are the two bases being merged, and `joined` is the identity of
    /// the joined summary.
    ///
    /// Minted rather than chosen. The joined summary is a history neither
    /// input base names, and every change authored above a base signs it,
    /// so reusing either input for it would give one base id two meanings:
    /// a change signed against the reused id on one replica would be
    /// admitted against a different history on another.
    ///
    /// Deterministic and symmetric: the inputs are hashed in ascending
    /// order, so two replicas that merge the same two bases into the same
    /// summary found the same base, whichever side each merged from. Never
    /// equal to either input by construction rather than by hash luck: a
    /// result that collides with one is hashed again with the next attempt
    /// number.
    ///
    /// Only for merges whose join differs from both sides. A merge in which
    /// one side already holds the other's whole history adopts that side's
    /// base instead; minting there would move only the replica that merged
    /// first onto a base the other side has never seen.
    ///
    /// Unlike a sealed base, a merged base is not derived from a
    /// checkpoint's hash: its identity is fixed by what was merged before
    /// any snapshot of the joined summary exists, so replicas agree on it
    /// however each builds that snapshot. The checkpoint that commits to
    /// such a snapshot carries these inputs ([`MergedFrom`]), and
    /// [`HistoryBase::from_checkpoint`] mints from them.
    pub fn mint_merged(
        group_id: &FolderGroupId,
        a: HistoryBase,
        b: HistoryBase,
        joined: &crate::base_negotiation::SummaryIdentity,
    ) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        let mut attempt: u32 = 0;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(HISTORY_BASE_MERGE_DOMAIN);
            hasher.update((group_id.as_str().len() as u64).to_be_bytes());
            hasher.update(group_id.as_str().as_bytes());
            hasher.update(low.0);
            hasher.update(high.0);
            hasher.update(joined.0);
            hasher.update(attempt.to_be_bytes());
            let minted = Self(hasher.finalize().into());
            if minted != low && minted != high {
                return minted;
            }
            attempt += 1;
        }
    }
}

/// The history a change was written on: either a group's original history,
/// which no compaction has replaced, or the epoch standing above one
/// installed [`HistoryBase`].
///
/// This is part of every change's signed, hashed bytes, and that is what
/// makes it load-bearing rather than descriptive. A device that has
/// installed a base holds a history whose whole prefix the base stands
/// for; a device still on its original history holds that prefix itself.
/// The two are different histories, and a change written on one of them
/// says nothing admissible about the other — the sequence numbers, the
/// Lamport values and the parent hashes all mean something different
/// there.
///
/// Without a signed epoch, a device carrying a complete, internally
/// consistent old history could hand it over whole and have it taken for
/// a second independent root of the current one: every parent is present,
/// so nothing structural objects. With it, the mismatch is decidable from
/// the bytes alone, and it cannot be edited away — rewriting the epoch
/// changes both the change hash and the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HistoryEpoch {
    /// The group's own history, from its first change, with no base
    /// installed under it.
    Genesis,
    /// The epoch above the named base.
    Base(HistoryBase),
}

impl HistoryEpoch {
    /// The one-byte discriminant that opens this epoch's encoding.
    pub(crate) const GENESIS_TAG: u8 = 0;
    pub(crate) const BASE_TAG: u8 = 1;

    pub fn base(self) -> Option<HistoryBase> {
        match self {
            Self::Genesis => None,
            Self::Base(base) => Some(base),
        }
    }

    /// The epoch a group is on, given the base it currently has installed.
    pub fn from_installed_base(base: Option<HistoryBase>) -> Self {
        match base {
            None => Self::Genesis,
            Some(base) => Self::Base(base),
        }
    }
}

impl std::fmt::Display for HistoryEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Genesis => f.write_str("genesis"),
            Self::Base(base) => write!(f, "base {}", base.to_hex()),
        }
    }
}

/// Resolves the pinned Ed25519 key for the device identity a signed re-bootstrap
/// object names. Keeping identity resolution inside the verification API avoids
/// a caller accidentally verifying a manifest that claims `device-b` with some
/// unrelated but otherwise-valid `device-a` key.
pub trait RebootstrapTrust {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]>;
}

impl<F> RebootstrapTrust for F
where
    F: Fn(&str) -> Option<[u8; 32]>,
{
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self(device_id)
    }
}

fn manifest_verifying_key<T: RebootstrapTrust + ?Sized>(
    trust: &T,
    signer_device_id: &DeviceId,
) -> Result<VerifyingKey, ChangeError> {
    let key_bytes = trust.signing_key(signer_device_id.as_str()).ok_or_else(|| {
        ChangeError::Malformed(format!(
            "no pinned re-bootstrap signing key for manifest signer {}",
            signer_device_id.as_str()
        ))
    })?;
    change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
        ChangeError::Malformed(format!(
            "pinned re-bootstrap signing key for {} is invalid: {error}",
            signer_device_id.as_str()
        ))
    })
}

/// Signed description of the baseline a stale device must install before DAG
/// synchronization can continue. The snapshot bytes themselves travel over the
/// ordinary content path; `snapshot_hash` remains the checkpoint's opaque
/// materialized-state identity and is verified by the caller-supplied snapshot
/// verifier before the atomic install is allowed to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub group_id: FolderGroupId,
    pub history_base: HistoryBase,
    pub checkpoint: Checkpoint,
    pub current_heads: Vec<ChangeHash>,
    pub previous_checkpoint_hash: Option<[u8; 32]>,
    pub signer_device_id: DeviceId,
    pub signature: [u8; 64],
}

impl SnapshotManifest {
    pub fn new_signed(
        checkpoint: Checkpoint,
        mut current_heads: Vec<ChangeHash>,
        previous_checkpoint_hash: Option<[u8; 32]>,
        signer_device_id: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<Self, ChangeError> {
        current_heads.sort();
        current_heads.dedup();
        if current_heads.len() > MAX_REBOOTSTRAP_HEADS {
            return Err(ChangeError::Malformed(format!(
                "re-bootstrap current-head count {} exceeds {}",
                current_heads.len(),
                MAX_REBOOTSTRAP_HEADS
            )));
        }
        let mut manifest = Self {
            group_id: checkpoint.group_id.clone(),
            history_base: HistoryBase::from_checkpoint(&checkpoint),
            checkpoint,
            current_heads,
            previous_checkpoint_hash,
            signer_device_id,
            signature: [0u8; 64],
        };
        manifest.signature = signing_key.sign(&manifest.signing_bytes()).to_bytes();
        Ok(manifest)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MANIFEST_DOMAIN);
        put_str(&mut out, self.group_id.as_str());
        out.extend_from_slice(&self.history_base.0);
        let checkpoint = self.checkpoint.canonical_encoding();
        put_len_bytes(&mut out, &checkpoint);
        put_u32(&mut out, self.current_heads.len() as u32);
        for head in &self.current_heads {
            out.extend_from_slice(&head.0);
        }
        match self.previous_checkpoint_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(&hash);
            }
            None => out.push(0),
        }
        put_str(&mut out, self.signer_device_id.as_str());
        out
    }

    pub fn manifest_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    fn verify_with_key(&self, verifying_key: &VerifyingKey) -> Result<(), ChangeError> {
        if self.group_id != self.checkpoint.group_id {
            return Err(ChangeError::Malformed(
                "snapshot manifest group does not match checkpoint group".into(),
            ));
        }
        if self.history_base != HistoryBase::from_checkpoint(&self.checkpoint) {
            return Err(ChangeError::Malformed(
                "snapshot manifest history base does not derive from its checkpoint".into(),
            ));
        }
        if self.checkpoint.frontier.len() > MAX_REBOOTSTRAP_HEADS
            || !self.checkpoint.frontier.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ChangeError::Malformed(
                "snapshot manifest checkpoint frontier is not canonical".into(),
            ));
        }
        if self.current_heads.len() > MAX_REBOOTSTRAP_HEADS
            || !self.current_heads.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ChangeError::Malformed(
                "snapshot manifest current heads are not canonical".into(),
            ));
        }
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifying_key.verify(&self.signing_bytes(), &signature).map_err(|_| {
            ChangeError::Malformed("snapshot manifest signature verification failed".into())
        })
    }

    pub fn verify<T: RebootstrapTrust + ?Sized>(&self, trust: &T) -> Result<(), ChangeError> {
        let verifying_key = manifest_verifying_key(trust, &self.signer_device_id)?;
        self.verify_with_key(&verifying_key)
    }

    /// Full wire encoding: `signing_bytes()` (everything but the signature)
    /// followed by the signature itself. Round trips through `decode`.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != SNAPSHOT_MANIFEST_DOMAIN {
            return Err(decode_err("bad snapshot manifest domain tag"));
        }
        let group_id = FolderGroupId(reader.string()?);
        let history_base = HistoryBase(reader.array32()?);
        let checkpoint_len = reader.u32()? as usize;
        let checkpoint = Checkpoint::decode(reader.take(checkpoint_len)?)?;
        let head_count = reader.bounded_count(32, MAX_REBOOTSTRAP_HEADS)?;
        let mut current_heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            current_heads.push(ChangeHash(reader.array32()?));
        }
        if !current_heads.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(decode_err("snapshot manifest current heads are not canonical"));
        }
        let previous_checkpoint_hash = match reader.take(1)?[0] {
            0 => None,
            1 => Some(reader.array32()?),
            _ => return Err(decode_err("bad previous_checkpoint_hash presence tag")),
        };
        let signer_device_id = DeviceId(reader.string()?);
        let signature = reader.array64()?;
        reader.expect_end()?;
        Ok(Self {
            group_id,
            history_base,
            checkpoint,
            current_heads,
            previous_checkpoint_hash,
            signer_device_id,
            signature,
        })
    }
}

#[cfg(test)]
mod merge_mint_tests;

#[cfg(test)]
mod merged_checkpoint_tests;
