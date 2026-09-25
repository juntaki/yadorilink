//! Half-open ranges over the identifier space.

use std::fmt;

use crate::id::ItemId;

/// The upper bound of a range.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum RangeEnd {
    /// Extends to the end of the identifier space. Needed because the largest
    /// identifier has no successor, so `[start, ∞)` is not expressible as an
    /// exclusive bound.
    Open,
    /// Excludes this identifier and everything above it.
    Excluded(ItemId),
}

/// A half-open range `[start, end)` of identifiers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub start: ItemId,
    pub end: RangeEnd,
}

impl Range {
    /// The whole identifier space.
    pub const FULL: Range = Range { start: ItemId::MIN, end: RangeEnd::Open };

    pub const fn new(start: ItemId, end: RangeEnd) -> Self {
        Self { start, end }
    }

    /// Whether `id` falls inside this range.
    pub fn contains(&self, id: &ItemId) -> bool {
        if *id < self.start {
            return false;
        }
        match self.end {
            RangeEnd::Open => true,
            RangeEnd::Excluded(end) => *id < end,
        }
    }

    /// Whether the range can hold no identifier at all.
    pub fn is_empty(&self) -> bool {
        match self.end {
            RangeEnd::Open => false,
            RangeEnd::Excluded(end) => end <= self.start,
        }
    }
}

impl fmt::Debug for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end {
            RangeEnd::Open => write!(f, "[{}, ∞)", self.start),
            RangeEnd::Excluded(end) => write!(f, "[{}, {})", self.start, end),
        }
    }
}

#[cfg(test)]
mod tests;
