//! Range fingerprints.
//!
//! # Why this construction
//!
//! Reconciliation is only as sound as its fingerprint. A peer that can find
//! two different sets with the same fingerprint can convince us a range is
//! settled while withholding Changes from it — silently, with no error to
//! observe, which is exactly the failure mode the whole redesign exists to
//! remove. Yadori includes adversarial peers in its security model, so the
//! fingerprint has to be collision resistant against a peer that chooses its
//! own set.
//!
//! That rules out the usual incremental constructions:
//!
//! * XOR-combined per-element hashes: trivially collidable, and any element
//!   present twice cancels.
//! * Per-element hashes summed modulo 2^256: composable and fast, but a
//!   generalised-birthday (Wagner) attack finds collisions well below the
//!   security level. Implementations offering it say so themselves.
//!
//! What is used instead is the plain thing: BLAKE3 over the domain
//! separator, the range bounds, the element count, and every identifier in
//! the range in ascending order. It is not incrementally composable, so
//! fingerprinting a range costs a scan of that range.
//!
//! That cost is accepted deliberately. RBSR does not require an incrementally
//! composable fingerprint — the Willow specification treats an efficient
//! composable construction as an optimisation, not a requirement — and
//! commutativity is only needed to avoid linearising multi-dimensional
//! ranges, which does not arise for a one-dimensional set. The semantics here
//! are unambiguous, which at this stage matters more than the constant
//! factor. If range hashing is ever measured to dominate, the replacement is
//! a *secure* tree-friendly fingerprint behind this same interface, not a
//! weaker combiner.

use crate::id::ItemId;
use crate::range::{Range, RangeEnd};

/// Domain separator. Bump the version if the encoding below ever changes, so
/// that a peer on an older encoding produces visibly different fingerprints
/// rather than silently comparable ones.
const DOMAIN: &[u8] = b"yadori-rbsr-fingerprint-v1";

const END_OPEN: u8 = 0;
const END_EXCLUDED: u8 = 1;

/// A collision-resistant summary of the identifiers within one range.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fingerprint the identifiers of `range`.
    ///
    /// `ids` must be exactly the identifiers the caller holds within `range`,
    /// in ascending order and without duplicates. [`fingerprint`] is the entry
    /// point that enforces that.
    fn from_sorted(range: &Range, ids: &[ItemId]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);

        // Bind the range. Two peers only ever compare fingerprints computed
        // for the same range; binding it makes a mismatch on that assumption
        // produce a difference rather than a silently meaningless comparison.
        hasher.update(range.start.as_bytes());
        match range.end {
            RangeEnd::Open => hasher.update(&[END_OPEN]),
            RangeEnd::Excluded(end) => {
                hasher.update(&[END_EXCLUDED]);
                hasher.update(end.as_bytes())
            }
        };

        // Bind the count, so that the identifier sequence cannot be
        // reinterpreted with a different split between length and content.
        hasher.update(&(ids.len() as u64).to_le_bytes());

        for id in ids {
            hasher.update(id.as_bytes());
        }

        Self(*hasher.finalize().as_bytes())
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint(")?;
        for byte in &self.0[..6] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}

/// Fingerprint an arbitrary collection of identifiers restricted to `range`.
///
/// Identifiers outside the range are ignored, duplicates are collapsed and
/// order is normalised, so a caller cannot change a fingerprint by presenting
/// the same set differently.
pub fn fingerprint<'a>(range: &Range, ids: impl IntoIterator<Item = &'a ItemId>) -> Fingerprint {
    let mut within: Vec<ItemId> =
        ids.into_iter().filter(|id| range.contains(id)).copied().collect();
    within.sort_unstable();
    within.dedup();
    Fingerprint::from_sorted(range, &within)
}

#[cfg(test)]
mod tests;
