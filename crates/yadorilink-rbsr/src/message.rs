//! What the two sides of a reconciliation say to each other.

use crate::fingerprint::Fingerprint;
use crate::id::ItemId;
use crate::range::Range;

/// One statement about one range.
///
/// A round is a set of these covering disjoint ranges. There is no session
/// identifier, sequence number or acknowledgement: a message is meaningful
/// only against the durable set the receiver holds right now, which is what
/// lets a session be abandoned at any point and restarted from nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RbsrMessage {
    /// "Across this range, my set fingerprints to this."
    Fingerprint { range: Range, fingerprint: Fingerprint },
    /// "Across this range, these are exactly the identifiers I hold."
    ///
    /// `reply_requested` asks the receiver to answer with its own listing for
    /// the same range, which is what lets the sender learn what it is missing.
    /// A listing sent in answer sets it to `false`, which terminates the
    /// exchange for that range.
    Items { range: Range, ids: Vec<ItemId>, reply_requested: bool },
}

impl RbsrMessage {
    pub fn range(&self) -> &Range {
        match self {
            RbsrMessage::Fingerprint { range, .. } => range,
            RbsrMessage::Items { range, .. } => range,
        }
    }
}
