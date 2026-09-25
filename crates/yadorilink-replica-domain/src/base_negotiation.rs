//! What two peers tell each other about the history they stand on, and
//! what that is allowed to decide.
//!
//! Before two peers compare change sets they compare bases. A change is
//! meaningful only on the history it was written on -- its author
//! position, its Lamport value and its parents all describe that history
//! -- so two peers on different bases have no ordinary difference to
//! reconcile. What they have is two summaries to merge, which is a
//! different operation with its own verification.
//!
//! # Trust boundary
//!
//! An advertisement is the peer's own claim. Nothing in it is evidence
//! that the base it names was ever legitimately sealed, that the summary
//! identity it names is the summary that base carries, or that its heads
//! exist. So the only decisions it may drive are ones a peer could force
//! anyway, by refusing to talk:
//!
//! * **Same base** -- ordinary reconciliation proceeds. That is exactly
//!   what an entitled peer could already cause, and every change it then
//!   delivers is verified and measured against this device's own base on
//!   its own signed bytes, never against the advertisement.
//! * **Different base** -- this session exchanges no changes, and the
//!   peer's claim is reported as a merge that would be required. The
//!   report is a claim, carried as one. It never installs a base, never
//!   switches this device's base, and never starts a merge. Doing any of
//!   that takes the signed snapshot manifest, the snapshot bytes that
//!   hash to its identity, and a summary verified against them.
//! * **Contradiction** -- the same base with two different summaries, or
//!   an advertisement for another group: the session is refused and
//!   nothing is recorded.
//!
//! What the advertisement *can* be held to is its own internal
//! consistency. A named base is derived from the checkpoint the
//! advertisement carries, and that checkpoint names the snapshot, so a
//! peer cannot claim one base with another base's snapshot identity. That
//! is a hash relation, checked on decode; it makes the claim well formed,
//! not true.

use sha2::{Digest, Sha256};

use crate::codec::ChangeError;
use crate::ids::{ChangeHash, FolderGroupId};
use crate::rebootstrap::{Checkpoint, CheckpointHash, HistoryBase, HistoryEpoch};

// \x03: the \x01 layout (checkpoint and summary identity side by side);
// \x02 (retired) read the summary off the checkpoint.
const ADVERTISEMENT_DOMAIN: &[u8; 8] = b"YLNKbad\x03";
const SUMMARY_IDENTITY_DOMAIN: &[u8; 8] = b"YLNKsid\x01";

const GENESIS_TAG: u8 = 0;
const INSTALLED_TAG: u8 = 1;

/// How many active heads an advertisement lists. A group with more lists
/// the lowest this many by hash and states the true count, so a large
/// concurrent frontier degrades the advertisement rather than the session.
pub const MAX_ADVERTISED_HEADS: usize = 1024;

/// The largest group identifier an advertisement carries, in bytes.
pub const MAX_ADVERTISED_GROUP_BYTES: usize = 512;

/// The identity of the causal summary a history base carries.
///
/// A digest over a canonical encoding of the summary; see
/// [`SummaryIdentityBuilder`]. Two devices holding the same base hold the
/// same summary, so the identities must agree -- a disagreement is a
/// contradiction, not a difference to reconcile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SummaryIdentity(pub [u8; 32]);

impl SummaryIdentity {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for SummaryIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SummaryIdentity({})", hex::encode(self.0))
    }
}

/// Builds a [`SummaryIdentity`] from the parts of a summary, in the order
/// the caller feeds them.
///
/// The caller owns canonical order: authors ascending by device id, heads
/// ascending by `(path, change_hash)`. Every variable-length field is
/// length-prefixed and every section is counted, so no two different
/// summaries share an encoding.
pub struct SummaryIdentityBuilder {
    hasher: Sha256,
}

impl SummaryIdentityBuilder {
    pub fn new(author_count: usize) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SUMMARY_IDENTITY_DOMAIN);
        hasher.update((author_count as u64).to_be_bytes());
        Self { hasher }
    }

    fn string(&mut self, value: &str) {
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value.as_bytes());
    }

    pub fn author(&mut self, device_id: &str, watermark: u64, tip: &ChangeHash) {
        self.string(device_id);
        self.hasher.update(watermark.to_be_bytes());
        self.hasher.update(tip.0);
    }

    pub fn begin_heads(&mut self, head_count: usize) {
        self.hasher.update((head_count as u64).to_be_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    pub fn head(
        &mut self,
        path: &str,
        change_hash: &ChangeHash,
        device_id: &str,
        author_seq: u64,
        lamport: u64,
        version_hash: &[u8; 32],
        naming_device_id: &str,
    ) {
        self.string(path);
        self.hasher.update(change_hash.0);
        self.string(device_id);
        self.hasher.update(author_seq.to_be_bytes());
        self.hasher.update(lamport.to_be_bytes());
        self.hasher.update(version_hash);
        self.string(naming_device_id);
    }

    pub fn finish(mut self, lamport_ceiling: u64) -> SummaryIdentity {
        self.hasher.update(lamport_ceiling.to_be_bytes());
        SummaryIdentity(self.hasher.finalize().into())
    }
}

/// The base a peer says it stands on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AdvertisedBase {
    /// The group's original history; no base installed.
    Genesis,
    /// An installed base: the checkpoint it derives from, and the identity
    /// of the summary it carries.
    Installed { checkpoint: Box<Checkpoint>, summary: SummaryIdentity },
}

impl AdvertisedBase {
    pub fn epoch(&self) -> HistoryEpoch {
        match self {
            Self::Genesis => HistoryEpoch::Genesis,
            Self::Installed { checkpoint, .. } => {
                HistoryEpoch::Base(HistoryBase::from_checkpoint(checkpoint))
            }
        }
    }
}

/// The identity of the snapshot a base stands for: the checkpoint the
/// base derives from, and the snapshot hash that checkpoint names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotIdentity {
    pub checkpoint_hash: CheckpointHash,
    pub snapshot_hash: [u8; 32],
}

/// What a peer says about its history for one group, before any change
/// set is compared.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BaseAdvertisement {
    pub group_id: FolderGroupId,
    pub base: AdvertisedBase,
    /// Active heads, ascending, at most [`MAX_ADVERTISED_HEADS`].
    pub active_heads: Vec<ChangeHash>,
    /// How many active heads there are in total; more than
    /// `active_heads.len()` only when the list was cut at the bound.
    pub active_head_count: u64,
}

impl BaseAdvertisement {
    /// Canonicalizes `heads` (ascending, deduplicated, cut at the bound)
    /// and checks that an installed base belongs to `group_id`.
    pub fn new(
        group_id: FolderGroupId,
        base: AdvertisedBase,
        mut heads: Vec<ChangeHash>,
    ) -> Result<Self, ChangeError> {
        if group_id.as_str().len() > MAX_ADVERTISED_GROUP_BYTES {
            return Err(malformed("group identifier exceeds the advertised bound"));
        }
        if let AdvertisedBase::Installed { checkpoint, .. } = &base {
            if checkpoint.group_id != group_id {
                return Err(malformed("advertised checkpoint belongs to another group"));
            }
        }
        heads.sort();
        heads.dedup();
        let active_head_count = heads.len() as u64;
        heads.truncate(MAX_ADVERTISED_HEADS);
        Ok(Self { group_id, base, active_heads: heads, active_head_count })
    }

    pub fn epoch(&self) -> HistoryEpoch {
        self.base.epoch()
    }

    pub fn summary(&self) -> Option<SummaryIdentity> {
        match &self.base {
            AdvertisedBase::Genesis => None,
            AdvertisedBase::Installed { summary, .. } => Some(*summary),
        }
    }

    pub fn snapshot(&self) -> Option<SnapshotIdentity> {
        match &self.base {
            AdvertisedBase::Genesis => None,
            AdvertisedBase::Installed { checkpoint, .. } => Some(SnapshotIdentity {
                checkpoint_hash: checkpoint.checkpoint_hash(),
                snapshot_hash: checkpoint.snapshot_hash,
            }),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ADVERTISEMENT_DOMAIN);
        put_len_bytes(&mut out, self.group_id.as_str().as_bytes());
        match &self.base {
            AdvertisedBase::Genesis => out.push(GENESIS_TAG),
            AdvertisedBase::Installed { checkpoint, summary } => {
                out.push(INSTALLED_TAG);
                out.extend_from_slice(&HistoryBase::from_checkpoint(checkpoint).0);
                put_len_bytes(&mut out, &checkpoint.canonical_encoding());
                out.extend_from_slice(&summary.0);
            }
        }
        out.extend_from_slice(&self.active_head_count.to_be_bytes());
        out.extend_from_slice(&(self.active_heads.len() as u32).to_be_bytes());
        for head in &self.active_heads {
            out.extend_from_slice(&head.0);
        }
        out
    }

    /// Decodes a peer's advertisement, refusing anything not in canonical
    /// form or not internally consistent.
    ///
    /// Consistency here is a hash relation, not trust: a named base must
    /// be the one its carried checkpoint derives, and that checkpoint must
    /// belong to the advertised group. A peer can still fabricate a whole
    /// consistent advertisement; see the module documentation for what
    /// that is and is not allowed to cause.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader { buf: bytes, pos: 0 };
        if reader.take(8)? != ADVERTISEMENT_DOMAIN {
            return Err(malformed("bad advertisement domain tag"));
        }
        let group_len = reader.u32()? as usize;
        if group_len > MAX_ADVERTISED_GROUP_BYTES {
            return Err(malformed("group identifier exceeds the advertised bound"));
        }
        let group_id = FolderGroupId(
            String::from_utf8(reader.take(group_len)?.to_vec())
                .map_err(|_| malformed("group identifier is not UTF-8"))?,
        );
        let base = match reader.take(1)?[0] {
            GENESIS_TAG => AdvertisedBase::Genesis,
            INSTALLED_TAG => {
                let claimed = HistoryBase(reader.array32()?);
                let checkpoint_len = reader.u32()? as usize;
                let checkpoint = Checkpoint::decode(reader.take(checkpoint_len)?)?;
                if checkpoint.group_id != group_id {
                    return Err(malformed("advertised checkpoint belongs to another group"));
                }
                if HistoryBase::from_checkpoint(&checkpoint) != claimed {
                    return Err(malformed("advertised base does not derive from its checkpoint"));
                }
                AdvertisedBase::Installed {
                    checkpoint: Box::new(checkpoint),
                    summary: SummaryIdentity(reader.array32()?),
                }
            }
            _ => return Err(malformed("unknown advertised base tag")),
        };
        let active_head_count = u64::from_be_bytes(reader.take(8)?.try_into().unwrap());
        let listed = reader.u32()? as usize;
        if listed > MAX_ADVERTISED_HEADS {
            return Err(malformed("advertisement lists more heads than the bound"));
        }
        if listed > reader.remaining() / 32 {
            return Err(malformed("advertisement lists more heads than it carries"));
        }
        let mut active_heads = Vec::with_capacity(listed);
        for _ in 0..listed {
            active_heads.push(ChangeHash(reader.array32()?));
        }
        if !active_heads.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(malformed("advertised heads are not strictly ascending"));
        }
        // The count may exceed the list only where the list was cut.
        let cut = active_head_count != listed as u64;
        if active_head_count < listed as u64 || (cut && listed != MAX_ADVERTISED_HEADS) {
            return Err(malformed("advertised head count disagrees with the listed heads"));
        }
        if reader.remaining() != 0 {
            return Err(malformed("trailing bytes after advertisement"));
        }
        Ok(Self { group_id, base, active_heads, active_head_count })
    }
}

/// A peer that, by its own account, stands on a different base.
///
/// A claim, not evidence. It records what the peer said so a later merge
/// knows what to ask for and verify; nothing about it is authority to
/// install, switch or merge anything.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForeignBase {
    /// The base this device stood on when it heard the claim. A claim
    /// heard against a base this device has since left describes nothing.
    pub local_epoch: HistoryEpoch,
    /// The peer's advertisement, as the peer made it.
    pub claim: BaseAdvertisement,
}

/// Why a session was refused before any change set was compared.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BaseRefusal {
    /// The advertisement describes another group than the session's.
    GroupMismatch { local: FolderGroupId, peer: FolderGroupId },
    /// Both sides name the same base but different summaries for it. A
    /// base carries one summary, so one side is corrupt or lying; neither
    /// is something to reconcile or merge.
    SummaryConflict { base: HistoryBase, local: SummaryIdentity, peer: SummaryIdentity },
}

impl std::fmt::Display for BaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GroupMismatch { local, peer } => write!(
                f,
                "peer advertised group {} on a session for group {}",
                peer.as_str(),
                local.as_str()
            ),
            Self::SummaryConflict { base, local, peer } => write!(
                f,
                "both sides stand on base {} but carry different summaries ({} here, {} there)",
                base.to_hex(),
                local.to_hex(),
                peer.to_hex()
            ),
        }
    }
}

/// What a comparison of two advertisements decided.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BaseNegotiation {
    /// Same base: reconcile change sets as usual.
    SameBase,
    /// Different bases: exchange no changes. Merging is required, and is
    /// not started here.
    MergeRequired(ForeignBase),
    /// A contradiction: end the session and record nothing.
    Refused(BaseRefusal),
}

/// Compares this device's advertisement with a peer's.
///
/// Symmetric in its decision: two peers comparing each other's
/// advertisements reach the same kind of verdict, so neither side can end
/// up reconciling while the other has stopped.
pub fn negotiate(local: &BaseAdvertisement, peer: &BaseAdvertisement) -> BaseNegotiation {
    if local.group_id != peer.group_id {
        return BaseNegotiation::Refused(BaseRefusal::GroupMismatch {
            local: local.group_id.clone(),
            peer: peer.group_id.clone(),
        });
    }
    let local_epoch = local.epoch();
    if local_epoch != peer.epoch() {
        return BaseNegotiation::MergeRequired(ForeignBase { local_epoch, claim: peer.clone() });
    }
    // Same epoch. A base derives from its checkpoint, so the snapshot
    // identities already agree; the summary is the one part a base does
    // not itself commit to, and two summaries for one base is a
    // contradiction.
    match (local_epoch, local.summary(), peer.summary()) {
        (HistoryEpoch::Base(base), Some(ours), Some(theirs)) if ours != theirs => {
            BaseNegotiation::Refused(BaseRefusal::SummaryConflict {
                base,
                local: ours,
                peer: theirs,
            })
        }
        _ => BaseNegotiation::SameBase,
    }
}

fn malformed(message: &str) -> ChangeError {
    ChangeError::Encoding(format!("base advertisement: {message}"))
}

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ChangeError> {
        if self.remaining() < count {
            return Err(malformed("unexpected end of input"));
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
}

#[cfg(test)]
mod tests;
