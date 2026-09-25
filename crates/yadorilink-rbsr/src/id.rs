//! Identifiers participating in reconciliation.

use std::fmt;

/// One member of the reconciled set.
///
/// Reconciliation is over a one-dimensional, totally ordered set of 32-byte
/// identifiers, compared lexicographically. In Yadori these are canonical
/// `ChangeHash` values, but this crate is deliberately ignorant of that: it
/// reconciles opaque identifiers and knows nothing about Changes, groups,
/// authorization or storage.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId([u8; 32]);

impl ItemId {
    /// The smallest identifier. The lower bound of the full space.
    pub const MIN: ItemId = ItemId([0x00; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The next identifier in lexicographic order, or `None` if this is the
    /// largest one. Used to turn an inclusive bound into an exclusive one.
    pub fn successor(&self) -> Option<Self> {
        let mut next = self.0;
        for byte in next.iter_mut().rev() {
            let (incremented, carried) = byte.overflowing_add(1);
            *byte = incremented;
            if !carried {
                return Some(Self(next));
            }
        }
        None
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemId({self})")
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..6] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

#[cfg(test)]
mod tests;
