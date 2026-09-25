#![cfg(test)]

use super::split_by_items;
use crate::id::ItemId;
use crate::range::{Range, RangeEnd};

fn id(first: u8) -> ItemId {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    ItemId::from_bytes(bytes)
}

#[test]
fn splitting_partitions_the_range_exactly() {
    let range = Range::FULL;
    let mine: Vec<ItemId> = (1..=16).map(id).collect();
    let parts = split_by_items(&range, &mine, 4);

    assert!(parts.len() > 1, "a large range must actually be narrowed");
    assert_eq!(parts[0].start, range.start);
    assert_eq!(parts.last().unwrap().end, range.end);
    for pair in parts.windows(2) {
        assert_eq!(
            pair[0].end,
            RangeEnd::Excluded(pair[1].start),
            "parts must be contiguous with no gap and no overlap"
        );
    }

    // Every identifier lands in exactly one part.
    for id in &mine {
        assert_eq!(
            parts.iter().filter(|part| part.contains(id)).count(),
            1,
            "identifier {id} must fall in exactly one part"
        );
    }
}

#[test]
fn every_part_is_strictly_smaller_so_the_recursion_terminates() {
    let range = Range::FULL;
    let mine: Vec<ItemId> = (1..=64).map(id).collect();
    for part in split_by_items(&range, &mine, 8) {
        let held = mine.iter().filter(|id| part.contains(id)).count();
        assert!(held > 0, "a part must not be empty on the splitter's side");
        assert!(held < mine.len(), "a part must be strictly smaller");
    }
}

#[test]
fn a_range_that_cannot_be_narrowed_is_returned_unchanged() {
    let range = Range::new(id(1), RangeEnd::Excluded(id(9)));
    assert_eq!(split_by_items(&range, &[id(4)], 8), vec![range]);
    assert_eq!(split_by_items(&range, &[], 8), vec![range]);
}
