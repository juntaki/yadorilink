//! The reconciliation state machine.
//!
//! A reconciler compares its own durable set against a peer's, round by
//! round, and reports the difference. It holds no state that matters: every
//! answer is computed from the index as it is at that moment. Abandoning a
//! session loses nothing that correctness depended on, which is the property
//! that makes a durable per-peer sync-debt table unnecessary.

use std::collections::BTreeSet;

use crate::error::RbsrError;
use crate::id::ItemId;
use crate::index::ReconciliationIndex;
use crate::message::RbsrMessage;
use crate::range::{Range, RangeEnd};

/// Tuning for one reconciliation.
#[derive(Clone, Copy, Debug)]
pub struct RbsrConfig {
    /// The largest number of identifiers carried in one `Items` message, and
    /// the threshold at or below which a differing range is resolved by
    /// listing its contents rather than by splitting it further.
    pub items_per_message: usize,
    /// How many sub-ranges a differing large range is split into.
    pub split_factor: usize,
    /// The largest number of statements accepted in one incoming round.
    /// A peer that exceeds it is trying to make us do unbounded work.
    pub max_messages_per_round: usize,
}

impl Default for RbsrConfig {
    fn default() -> Self {
        Self { items_per_message: 32, split_factor: 8, max_messages_per_round: 1024 }
    }
}

/// Compares a local set against a peer's.
#[derive(Debug)]
pub struct Reconciler<I> {
    index: I,
    config: RbsrConfig,
    want: BTreeSet<ItemId>,
    offer: BTreeSet<ItemId>,
}

impl<I: ReconciliationIndex> Reconciler<I> {
    pub fn new(index: I, config: RbsrConfig) -> Self {
        Self { index, config, want: BTreeSet::new(), offer: BTreeSet::new() }
    }

    /// The opening statement: one fingerprint over the whole identifier space.
    pub fn initiate(&self) -> Vec<RbsrMessage> {
        vec![RbsrMessage::Fingerprint {
            range: Range::FULL,
            fingerprint: self.index.fingerprint(&Range::FULL),
        }]
    }

    /// Identifiers the peer holds and this node does not.
    pub fn want(&self) -> &BTreeSet<ItemId> {
        &self.want
    }

    /// Identifiers this node holds and the peer does not.
    pub fn offer(&self) -> &BTreeSet<ItemId> {
        &self.offer
    }

    /// The index being reconciled.
    pub fn index(&self) -> &I {
        &self.index
    }

    /// Take one round from the peer and produce the answer.
    ///
    /// An empty answer means every range the peer spoke about is settled. It
    /// does not mean the two sets are equal — it means nothing further needs
    /// to be exchanged to know the difference, which is then in [`want`] and
    /// [`offer`].
    ///
    /// [`want`]: Self::want
    /// [`offer`]: Self::offer
    pub fn ingest(&mut self, incoming: &[RbsrMessage]) -> Result<Vec<RbsrMessage>, RbsrError> {
        if incoming.len() > self.config.max_messages_per_round {
            return Err(RbsrError::RoundTooLarge {
                received: incoming.len(),
                limit: self.config.max_messages_per_round,
            });
        }

        // Validate the whole round before applying any of it. A peer must not
        // be able to smuggle a difference into our state by placing a valid
        // statement in front of a malformed one and having the round rejected
        // only after the valid part was already applied.
        for message in incoming {
            self.validate(message)?;
        }

        let mut reply = Vec::new();
        for message in incoming {
            match message {
                RbsrMessage::Fingerprint { range, fingerprint } => {
                    if self.index.fingerprint(range) != *fingerprint {
                        self.resolve(range, &mut reply);
                    }
                }
                RbsrMessage::Items { range, ids, reply_requested } => {
                    let theirs: BTreeSet<ItemId> = ids.iter().copied().collect();
                    let mine: BTreeSet<ItemId> = self.index.items(range).into_iter().collect();

                    self.want.extend(theirs.difference(&mine).copied());
                    self.offer.extend(mine.difference(&theirs).copied());

                    if *reply_requested {
                        self.emit_items(range, false, &mut reply);
                    }
                }
            }
        }

        Ok(reply)
    }

    /// Answer a range whose fingerprints disagree.
    fn resolve(&self, range: &Range, out: &mut Vec<RbsrMessage>) {
        let mine = self.index.items(range);

        if mine.len() <= self.config.items_per_message {
            // Small enough to settle by listing. Asking for an answer is what
            // lets us learn what we are missing here.
            out.push(RbsrMessage::Items { range: *range, ids: mine, reply_requested: true });
            return;
        }

        // Too large to list: narrow it. Splitting by our own items keeps every
        // part non-empty on our side, so each part is strictly smaller than
        // the parent and the recursion terminates.
        for part in split_by_items(range, &mine, self.config.split_factor) {
            out.push(RbsrMessage::Fingerprint {
                range: part,
                fingerprint: self.index.fingerprint(&part),
            });
        }
    }

    /// List our contents of `range`, in as many messages as the per-message
    /// cap requires. The parts partition `range` exactly, so the receiver's
    /// difference over the parts is its difference over the whole.
    fn emit_items(&self, range: &Range, reply_requested: bool, out: &mut Vec<RbsrMessage>) {
        let mine = self.index.items(range);

        if mine.len() <= self.config.items_per_message {
            out.push(RbsrMessage::Items { range: *range, ids: mine, reply_requested });
            return;
        }

        let parts = mine.len().div_ceil(self.config.items_per_message);
        for part in split_by_items(range, &mine, parts) {
            out.push(RbsrMessage::Items {
                range: part,
                ids: self.index.items(&part),
                reply_requested,
            });
        }
    }

    /// Reject anything a peer could use to make us do unbounded or meaningless
    /// work, before it reaches the index.
    fn validate(&self, message: &RbsrMessage) -> Result<(), RbsrError> {
        let range = message.range();
        if range.is_empty() {
            return Err(RbsrError::EmptyRange);
        }

        if let RbsrMessage::Items { ids, .. } = message {
            if ids.len() > self.config.items_per_message {
                return Err(RbsrError::ListingTooLarge {
                    received: ids.len(),
                    limit: self.config.items_per_message,
                });
            }

            let mut previous: Option<&ItemId> = None;
            for id in ids {
                if !range.contains(id) {
                    return Err(RbsrError::ItemOutsideRange);
                }
                if let Some(previous) = previous {
                    if previous >= id {
                        return Err(RbsrError::ListingNotAscending);
                    }
                }
                previous = Some(id);
            }
        }

        Ok(())
    }
}

/// Split `range` into at most `parts` sub-ranges that partition it exactly,
/// cutting at the positions of `mine`.
///
/// `mine` must be the ascending, deduplicated contents of `range`.
fn split_by_items(range: &Range, mine: &[ItemId], parts: usize) -> Vec<Range> {
    let parts = parts.max(2);
    if mine.len() < 2 {
        return vec![*range];
    }

    let stride = mine.len().div_ceil(parts).max(1);
    let mut ranges = Vec::new();
    let mut start = range.start;

    let mut cut = stride;
    while cut < mine.len() {
        let boundary = mine[cut];
        ranges.push(Range::new(start, RangeEnd::Excluded(boundary)));
        start = boundary;
        cut += stride;
    }
    ranges.push(Range::new(start, range.end));

    ranges
}

#[cfg(test)]
mod tests;
