#![cfg(test)]

use super::*;

fn hash(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

/// Case 1: an unchanged frontier is the only shape
/// `retire_conflict_copies_only` may report its inner outcome as-is --
/// this is what lets a genuinely `Settled` pass complete its
/// generation.
#[test]
fn unchanged_frontier_is_not_reported_as_changed() {
    let before = vec![hash(1), hash(2)];
    let after = vec![hash(1), hash(2)];
    assert!(!frontier_changed_during_pass(&before, &after));
}

/// Case 2: any admission during the pass -- growing the frontier, not
/// just replacing a head -- must be caught, since a caller that
/// completed the generation anyway would never re-evaluate the newly
/// admitted change's effect on justification.
#[test]
fn a_frontier_that_gained_a_head_during_the_pass_is_reported_as_changed() {
    let before = vec![hash(1)];
    let after = vec![hash(1), hash(2)];
    assert!(frontier_changed_during_pass(&before, &after));
}

/// A head superseded mid-pass (frontier shrinks by one, gains a
/// different one) must equally be caught -- not just a pure growth.
#[test]
fn a_frontier_whose_heads_were_replaced_during_the_pass_is_reported_as_changed() {
    let before = vec![hash(1), hash(2)];
    let after = vec![hash(1), hash(3)];
    assert!(frontier_changed_during_pass(&before, &after));
}

/// Case 4: multiple intermediate admissions during one pass (e.g. two
/// separate peer changes landing back to back) still collapse to a
/// single before/after mismatch -- there is no per-admission tracking
/// to lose count of; only the endpoints of the pass are ever compared,
/// so no intermediate change can be coalesced away and missed.
#[test]
fn multiple_intermediate_admissions_still_trip_the_check() {
    let before = vec![hash(1)];
    let mid = vec![hash(1), hash(2)];
    let after = vec![hash(1), hash(2), hash(3)];
    assert!(frontier_changed_during_pass(&before, &mid));
    assert!(frontier_changed_during_pass(&before, &after));
    assert!(frontier_changed_during_pass(&mid, &after));
}
