//! Protocol and framing failures.

use thiserror::Error;

/// A frame the peer sent that cannot be decoded.
///
/// Every variant describes a claim the peer made that the bytes do not
/// support. None of them is recoverable by retrying the same frame; the
/// session is torn down and reconciliation restarts from durable state.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame claims {needed} more bytes but only {available} are present")]
    Truncated { needed: usize, available: usize },

    #[error("round declares {declared} statements or bytes, limit is {limit}")]
    RoundTooLarge { declared: usize, limit: usize },

    #[error("listing declares {declared} identifiers, limit is {limit}")]
    ListingTooLarge { declared: usize, limit: usize },

    #[error("bundle request declares {declared} hashes, limit is {limit}")]
    RequestTooLarge { declared: usize, limit: usize },

    #[error("bundle declares {declared} bytes, limit is {limit}")]
    BundleTooLarge { declared: usize, limit: usize },

    #[error("unknown message kind {0}")]
    UnknownMessageKind(u8),

    #[error("malformed range end discriminant {0}")]
    MalformedRangeEnd(u8),

    #[error("malformed boolean flag {0}")]
    MalformedFlag(u8),

    #[error("{0} unread bytes after the frame")]
    TrailingBytes(usize),

    #[error("group identifier declares {declared} bytes, limit is {limit}")]
    GroupTooLong { declared: usize, limit: usize },

    #[error("peer speaks protocol version {theirs}, this node speaks {ours}")]
    UnsupportedVersion { theirs: u32, ours: u32 },

    #[error("group identifier is not valid UTF-8")]
    MalformedGroupId,

    #[error("base advertisement declares {declared} bytes, limit is {limit}")]
    AdvertisementTooLarge { declared: usize, limit: usize },
}

/// Anything that ends a session.
///
/// None of these is retried in place. A session that fails is abandoned and
/// the next one starts from the two peers' durable sets, which is the whole
/// reason session state was made disposable.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("transport failed: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Wire(#[from] WireError),

    #[error(transparent)]
    Rbsr(#[from] yadorilink_rbsr::RbsrError),

    #[error(transparent)]
    Port(#[from] crate::ports::PortError),

    /// The peer may not be told about this group at all. Raised before any
    /// fingerprint is computed or exchanged.
    #[error("peer is not entitled to group {group}")]
    NotDisclosable { group: crate::ports::GroupId },

    /// A frame declared more bytes than are ever accepted for its kind.
    #[error("frame declares {declared} bytes, limit is {limit}")]
    FrameTooLarge { declared: usize, limit: usize },

    /// The peer kept the exchange going past the point where it must have
    /// terminated.
    #[error("reconciliation exceeded {limit} rounds")]
    TooManyRounds { limit: usize },

    /// The peer sent a bundle that was never requested.
    #[error("peer sent a bundle that was not requested")]
    UnrequestedBundle,

    /// The peer opened a lane and closed it without saying what it was for.
    #[error("peer opened a lane without a hello")]
    NoHello,

    /// The two sides' base advertisements contradict each other, or the
    /// peer's is malformed. Nothing was compared and nothing recorded.
    #[error("history base negotiation for group {group} refused: {reason}")]
    BaseRefused { group: crate::ports::GroupId, reason: String },
}
