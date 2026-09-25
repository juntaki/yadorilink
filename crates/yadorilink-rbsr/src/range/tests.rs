#![cfg(test)]

use super::{Range, RangeEnd};
use crate::id::ItemId;

fn id(first: u8) -> ItemId {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    ItemId::from_bytes(bytes)
}

#[test]
fn the_full_range_contains_every_identifier() {
    assert!(Range::FULL.contains(&ItemId::MIN));
    assert!(Range::FULL.contains(&ItemId::from_bytes([0xff; 32])));
    assert!(!Range::FULL.is_empty());
}

#[test]
fn a_half_open_range_excludes_its_upper_bound() {
    let range = Range::new(id(0x10), RangeEnd::Excluded(id(0x20)));
    assert!(!range.contains(&id(0x0f)));
    assert!(range.contains(&id(0x10)));
    assert!(range.contains(&id(0x1f)));
    assert!(!range.contains(&id(0x20)));
}

#[test]
fn an_inverted_or_degenerate_range_is_empty() {
    assert!(Range::new(id(0x20), RangeEnd::Excluded(id(0x10))).is_empty());
    assert!(Range::new(id(0x20), RangeEnd::Excluded(id(0x20))).is_empty());
}
