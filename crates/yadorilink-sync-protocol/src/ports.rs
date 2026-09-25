//! What the protocol needs from the layer that owns Change semantics.
//!
//! The protocol moves bytes and compares sets. It does not decode a Change,
//! check a signature, resolve authorization or touch storage. Everything of
//! that kind is behind this seam, so that transport code can never become a
//! second place where admission is decided.

use std::fmt;
use std::future::Future;

use yadorilink_rbsr::ItemId;

use crate::wire::OpaqueBundle;

/// The folder group being reconciled.
///
/// A thin newtype rather than the domain's own group id: this crate is
/// deliberately unaware of the domain's types, and the adapter converts.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct GroupId(pub String);

impl GroupId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Anything the replica layer can fail at, flattened to a message.
///
/// The protocol never branches on why: a port failure ends the session, and
/// the next session re-derives everything from durable state.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PortError(pub String);

impl PortError {
    pub fn new(message: impl fmt::Display) -> Self {
        Self(message.to_string())
    }
}

/// What comparing the two sides' history bases decided, before any change
/// set is compared.
///
/// Both sides reach this independently from the same two advertisements,
/// and the comparison is symmetric, so they agree on whether to go on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseVerdict {
    /// Same base: reconcile change sets as usual.
    SameBase,
    /// The two sides stand on different bases. No change is exchanged: a
    /// change written on one base says nothing admissible about the other.
    /// Merging the two is required and is not this session's to start.
    MergeRequired,
    /// The advertisements contradict each other or are malformed. The
    /// session ends and nothing is recorded.
    Refused(String),
}

/// The replica's side of a sync session with one peer.
///
/// Every method is asynchronous, and deliberately so. The implementation
/// behind this trait reaches storage, and a synchronous storage call made from
/// a session task occupies a runtime worker for its whole duration — which,
/// with a writer gate held, has been measured in tens of seconds. A worker
/// blocked that way runs no other task at all, up to and including the QUIC
/// endpoint driver. The boundary that moves such work off the runtime, under
/// a bounded number of threads, can only exist if this trait is async.
pub trait ReplicaPort: Send + Sync {
    /// Whether this peer may be told anything at all about `group`.
    ///
    /// Checked before a single fingerprint is computed, sent or answered. A
    /// fingerprint reveals whether two sets agree, and a difference in
    /// fingerprints across a range reveals that the peer is missing something
    /// there — both are disclosures. Settling entitlement afterwards would
    /// leak first and ask later.
    fn may_disclose(
        &self,
        peer: PeerKey,
        group: GroupId,
    ) -> impl Future<Output = Result<bool, PortError>> + Send;

    /// This node's advertisement of the history it stands on for `group`,
    /// opaque at this layer.
    ///
    /// Asked only after [`may_disclose`](Self::may_disclose) has said yes:
    /// the advertisement names heads and a base, which is disclosure.
    fn base_advertisement(
        &self,
        peer: PeerKey,
        group: GroupId,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;

    /// Compare this node's advertisement, exactly as it was sent, with the
    /// peer's.
    ///
    /// The peer's advertisement is its own claim. Whatever the verdict,
    /// the claim must not change which base this node stands on.
    fn negotiate_base(
        &self,
        peer: PeerKey,
        group: GroupId,
        ours: Vec<u8>,
        theirs: Vec<u8>,
    ) -> impl Future<Output = Result<BaseVerdict, PortError>> + Send;

    /// The peer sent something in place of its advertisement that cannot be
    /// judged at all -- declared longer than any advertisement may be -- so
    /// this negotiation ends refused without a verdict from
    /// [`Self::negotiate_base`]. It is still the latest word on the peer:
    /// whatever an earlier negotiation recorded about the peer's base must
    /// not outlive it. A port that records nothing need do nothing.
    fn base_unjudgeable(
        &self,
        _peer: PeerKey,
        _group: GroupId,
        _reason: String,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        async { Ok(()) }
    }

    /// The identifiers this node can serve to this peer for this group.
    ///
    /// Servable verified possession: body, evidence, checkpoint envelope and
    /// inclusion proof all held and re-verifiable, and disclosable to this
    /// peer. Not canonical admission — a Change that is verified and staged
    /// but still waiting on a parent or a capture barrier belongs here, or the
    /// peer will send it again.
    fn servable(
        &self,
        peer: PeerKey,
        group: GroupId,
    ) -> impl Future<Output = Result<Vec<ItemId>, PortError>> + Send;

    /// The bundles for `hashes`, for a peer entitled to them.
    ///
    /// A hash this node does not hold, or may not disclose, is simply absent
    /// from the result. It is not an error: the peer's view of what we hold is
    /// a snapshot and may already be stale.
    fn load_bundles(
        &self,
        peer: PeerKey,
        group: GroupId,
        hashes: Vec<ItemId>,
    ) -> impl Future<Output = Result<Vec<OpaqueBundle>, PortError>> + Send;

    /// Verify and durably stage a delivery, all of it or none of it.
    ///
    /// Returns the hashes newly staged. Redelivery is expected and must be
    /// cheap: a bundle already possessed does no work.
    fn stage_bundles(
        &self,
        peer: PeerKey,
        group: GroupId,
        bundles: Vec<OpaqueBundle>,
    ) -> impl Future<Output = Result<Vec<ItemId>, PortError>> + Send;
}

/// The transport identity of the peer on the other end.
///
/// Carrier identity only. It selects which set is disclosable and nothing
/// else; it never contributes to whether a Change may be admitted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerKey(pub [u8; 32]);

impl PeerKey {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey(")?;
        for byte in &self.0[..6] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}
