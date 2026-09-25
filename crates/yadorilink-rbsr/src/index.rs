//! The set a peer reconciles against.

use std::collections::BTreeSet;

use crate::fingerprint::{fingerprint, Fingerprint};
use crate::id::ItemId;
use crate::range::Range;

/// The identifiers this node offers to one peer, for one group.
///
/// # What belongs in here
///
/// Membership is *servable verified possession*, not canonical admission. An
/// identifier belongs in the index when, for this peer and this group:
///
/// * the Change body is held, and
/// * its complete authorization evidence is held, and
/// * its checkpoint envelope is held, and
/// * its Merkle inclusion proof is held, and
/// * all of that can be re-verified, and
/// * it may be disclosed to this peer.
///
/// Whether it has been promoted into the canonical Published DAG is
/// deliberately *not* part of the condition. A Change that is verified and
/// durably staged in the inbox, but still waiting on a parent or on a local
/// capture barrier, is possessed: reconciliation must consider it delivered
/// and stop re-transferring it. Making canonical admission the membership
/// condition would recreate the storm — receive, verify, wait on the barrier,
/// stay missing from the peer's view, receive again — in a new shape.
///
/// Promotion therefore changes semantic visibility and nothing else. It does
/// not change index membership.
///
/// # Why per peer
///
/// Disclosure is part of membership, so the index is built for one peer. A
/// fingerprint reveals whether two sets agree, and a count difference reveals
/// how much a peer is missing; neither may be exchanged before it is settled
/// that this peer is entitled to the range at all.
pub trait ReconciliationIndex {
    /// The identifiers within `range`, ascending and without duplicates.
    fn items(&self, range: &Range) -> Vec<ItemId>;

    /// How many identifiers fall within `range`.
    fn count(&self, range: &Range) -> u64 {
        self.items(range).len() as u64
    }

    /// The fingerprint of `range`.
    fn fingerprint(&self, range: &Range) -> Fingerprint {
        fingerprint(range, self.items(range).iter())
    }
}

/// An in-memory index. Used by tests, and as the reference against which a
/// storage-backed implementation is checked.
#[derive(Clone, Debug, Default)]
pub struct MemoryIndex {
    ids: BTreeSet<ItemId>,
}

impl MemoryIndex {
    pub fn new(ids: impl IntoIterator<Item = ItemId>) -> Self {
        Self { ids: ids.into_iter().collect() }
    }

    pub fn insert(&mut self, id: ItemId) -> bool {
        self.ids.insert(id)
    }

    pub fn contains(&self, id: &ItemId) -> bool {
        self.ids.contains(id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ItemId> {
        self.ids.iter()
    }
}

impl ReconciliationIndex for MemoryIndex {
    fn items(&self, range: &Range) -> Vec<ItemId> {
        self.ids.iter().filter(|id| range.contains(id)).copied().collect()
    }
}
