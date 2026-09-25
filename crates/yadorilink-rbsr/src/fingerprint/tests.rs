#![cfg(test)]

use super::{fingerprint, Fingerprint};
use crate::id::ItemId;
use crate::range::{Range, RangeEnd};

fn id(first: u8) -> ItemId {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    ItemId::from_bytes(bytes)
}

#[test]
fn presentation_does_not_change_the_fingerprint() {
    let canonical = fingerprint(&Range::FULL, &[id(1), id(2), id(3)]);
    assert_eq!(fingerprint(&Range::FULL, &[id(3), id(1), id(2)]), canonical);
    assert_eq!(fingerprint(&Range::FULL, &[id(1), id(1), id(2), id(3), id(3)]), canonical);
}

#[test]
fn identifiers_outside_the_range_are_ignored() {
    let range = Range::new(id(1), RangeEnd::Excluded(id(3)));
    assert_eq!(
        fingerprint(&range, &[id(1), id(2)]),
        fingerprint(&range, &[id(0), id(1), id(2), id(3), id(9)])
    );
}

#[test]
fn different_sets_fingerprint_differently() {
    assert_ne!(
        fingerprint(&Range::FULL, &[id(1), id(2)]),
        fingerprint(&Range::FULL, &[id(1), id(3)])
    );
}

#[test]
fn the_same_set_in_a_different_range_fingerprints_differently() {
    let ids = [id(1), id(2)];
    assert_ne!(
        fingerprint(&Range::new(id(0), RangeEnd::Excluded(id(9))), &ids),
        fingerprint(&Range::new(id(1), RangeEnd::Excluded(id(9))), &ids)
    );
}

#[test]
fn the_empty_set_is_not_a_wildcard() {
    let empty = fingerprint(&Range::FULL, &[]);
    assert_ne!(empty, fingerprint(&Range::FULL, &[id(1)]));
    assert_ne!(empty, Fingerprint::from_bytes([0u8; 32]));
}

/// A count prefix is what stops `{ab}` and `{a, b}`-style regroupings of
/// the same byte sequence from colliding. Fixed-width identifiers make
/// that hard to demonstrate directly, so this pins the count's presence:
/// changing only the count changes the fingerprint.
#[test]
fn the_element_count_is_bound_into_the_fingerprint() {
    let range = Range::FULL;
    let ids = [id(1), id(2)];
    let honest = fingerprint(&range, &ids);
    let forged = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(super::DOMAIN);
        hasher.update(range.start.as_bytes());
        hasher.update(&[super::END_OPEN]);
        hasher.update(&99u64.to_le_bytes());
        for id in &ids {
            hasher.update(id.as_bytes());
        }
        Fingerprint::from_bytes(*hasher.finalize().as_bytes())
    };
    assert_ne!(honest, forged);
}
