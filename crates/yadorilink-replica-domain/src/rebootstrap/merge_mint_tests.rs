//! The identity of a base minted over the join of two histories.

use super::*;
use crate::base_negotiation::SummaryIdentity;

fn group(name: &str) -> FolderGroupId {
    FolderGroupId(name.to_string())
}

fn base(byte: u8) -> HistoryBase {
    HistoryBase([byte; 32])
}

fn joined(byte: u8) -> SummaryIdentity {
    SummaryIdentity([byte; 32])
}

/// Two replicas that merge the same two bases into the same summary found
/// the same base, whichever side each of them merged from.
#[test]
fn a_merged_base_is_the_same_whichever_side_merges() {
    let minted = HistoryBase::mint_merged(&group("g"), base(1), base(2), &joined(9));
    assert_eq!(minted, HistoryBase::mint_merged(&group("g"), base(2), base(1), &joined(9)));
    assert_eq!(
        minted,
        HistoryBase::mint_merged(&group("g"), base(1), base(2), &joined(9)),
        "minting is a function of its inputs"
    );
}

/// The joined summary is a history neither input names, so the base
/// founded on it is neither input.
#[test]
fn a_merged_base_is_neither_input() {
    for (a, b) in [(base(1), base(2)), (base(7), base(7))] {
        let minted = HistoryBase::mint_merged(&group("g"), a, b, &joined(9));
        assert_ne!(minted, a);
        assert_ne!(minted, b);
    }
}

/// Every input names what the base stands for: a different group, pair of
/// bases or joined summary is a different base.
#[test]
fn a_merged_base_depends_on_every_input() {
    let minted = HistoryBase::mint_merged(&group("g"), base(1), base(2), &joined(9));
    assert_ne!(minted, HistoryBase::mint_merged(&group("h"), base(1), base(2), &joined(9)));
    assert_ne!(minted, HistoryBase::mint_merged(&group("g"), base(1), base(3), &joined(9)));
    assert_ne!(minted, HistoryBase::mint_merged(&group("g"), base(3), base(2), &joined(9)));
    assert_ne!(minted, HistoryBase::mint_merged(&group("g"), base(1), base(2), &joined(8)));
}

/// Pinned bytes: the mint is part of every change's signed epoch once a
/// merged base is installed, so its encoding may not drift.
#[test]
fn a_merged_base_is_hashed_over_a_fixed_encoding() {
    let mut hasher = Sha256::new();
    hasher.update(b"YLNKhbm\x01");
    hasher.update(1u64.to_be_bytes());
    hasher.update(b"g");
    hasher.update([1u8; 32]);
    hasher.update([2u8; 32]);
    hasher.update([9u8; 32]);
    hasher.update(0u32.to_be_bytes());
    let expected = HistoryBase(hasher.finalize().into());
    assert_eq!(HistoryBase::mint_merged(&group("g"), base(2), base(1), &joined(9)), expected);
}
