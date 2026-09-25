//! Behaviour against a peer that is not following the protocol.
//!
//! Reconciliation runs against peers that may be adversarial, so every one of
//! these is a named, rejected condition rather than something the state
//! machine tries to interpret.

use yadorilink_rbsr::{
    Fingerprint, ItemId, MemoryIndex, Range, RangeEnd, RbsrConfig, RbsrError, RbsrMessage,
    Reconciler,
};

fn id(first: u8) -> ItemId {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    ItemId::from_bytes(bytes)
}

fn reconciler(ids: impl IntoIterator<Item = ItemId>) -> Reconciler<MemoryIndex> {
    Reconciler::new(MemoryIndex::new(ids), RbsrConfig::default())
}

#[test]
fn an_oversized_round_is_rejected_before_any_work_is_done() {
    let config = RbsrConfig::default();
    let mut peer = reconciler([id(1)]);

    let flood: Vec<RbsrMessage> = (0..config.max_messages_per_round + 1)
        .map(|_| RbsrMessage::Fingerprint {
            range: Range::FULL,
            fingerprint: Fingerprint::from_bytes([0u8; 32]),
        })
        .collect();

    assert_eq!(
        peer.ingest(&flood),
        Err(RbsrError::RoundTooLarge {
            received: flood.len(),
            limit: config.max_messages_per_round,
        })
    );
}

#[test]
fn an_oversized_listing_is_rejected() {
    let config = RbsrConfig::default();
    let mut peer = reconciler([id(1)]);

    let ids: Vec<ItemId> = (0..=config.items_per_message as u8).map(id).collect();
    let result = peer.ingest(&[RbsrMessage::Items {
        range: Range::FULL,
        ids: ids.clone(),
        reply_requested: true,
    }]);

    assert_eq!(
        result,
        Err(RbsrError::ListingTooLarge { received: ids.len(), limit: config.items_per_message })
    );
}

#[test]
fn a_statement_about_an_empty_range_is_rejected() {
    let mut peer = reconciler([id(1)]);
    let empty = Range::new(id(5), RangeEnd::Excluded(id(5)));

    assert_eq!(
        peer.ingest(&[RbsrMessage::Fingerprint {
            range: empty,
            fingerprint: Fingerprint::from_bytes([0u8; 32]),
        }]),
        Err(RbsrError::EmptyRange)
    );
}

#[test]
fn a_listing_that_escapes_its_own_range_is_rejected() {
    let mut peer = reconciler([id(1)]);

    assert_eq!(
        peer.ingest(&[RbsrMessage::Items {
            range: Range::new(id(1), RangeEnd::Excluded(id(3))),
            ids: vec![id(1), id(9)],
            reply_requested: false,
        }]),
        Err(RbsrError::ItemOutsideRange)
    );
}

#[test]
fn a_listing_that_is_not_strictly_ascending_is_rejected() {
    let mut peer = reconciler([id(1)]);

    assert_eq!(
        peer.ingest(&[RbsrMessage::Items {
            range: Range::FULL,
            ids: vec![id(3), id(1)],
            reply_requested: false,
        }]),
        Err(RbsrError::ListingNotAscending)
    );

    assert_eq!(
        peer.ingest(&[RbsrMessage::Items {
            range: Range::FULL,
            ids: vec![id(1), id(1)],
            reply_requested: false,
        }]),
        Err(RbsrError::ListingNotAscending)
    );
}

#[test]
fn a_rejected_round_leaves_the_reconciler_unchanged() {
    let mut peer = reconciler([id(1), id(2)]);

    // The malformed statement is not the first one. A round that is validated
    // message by message as it is applied would already have recorded the
    // difference from the valid statement before reaching the invalid one.
    assert!(peer
        .ingest(&[
            RbsrMessage::Items { range: Range::FULL, ids: vec![id(7)], reply_requested: false },
            RbsrMessage::Items {
                range: Range::new(id(1), RangeEnd::Excluded(id(3))),
                ids: vec![id(1), id(9)],
                reply_requested: true,
            },
        ])
        .is_err());

    assert!(
        peer.want().is_empty() && peer.offer().is_empty(),
        "a rejected round must not have been partially applied"
    );
}

/// A peer can always withhold: nothing stops it claiming a fingerprint that
/// matches ours for a range whose contents it is hiding. What it must not be
/// able to do is *forge* agreement — find a genuinely different set that
/// fingerprints identically — which is what the fingerprint's collision
/// resistance is for, and why no XOR- or modular-sum combiner is used.
///
/// This pins the honest half of that: a peer whose set genuinely differs
/// cannot make the fingerprints match by reordering, repeating or padding its
/// presentation of that set.
#[test]
fn agreement_cannot_be_manufactured_by_re_presenting_a_set() {
    let mine = [id(1), id(2), id(3)];
    let honest = yadorilink_rbsr::fingerprint(&Range::FULL, mine.iter());

    let reordered = [id(3), id(2), id(1)];
    let repeated = [id(1), id(1), id(2), id(3)];
    assert_eq!(yadorilink_rbsr::fingerprint(&Range::FULL, reordered.iter()), honest);
    assert_eq!(yadorilink_rbsr::fingerprint(&Range::FULL, repeated.iter()), honest);

    // But a set that actually differs cannot match, however it is presented.
    let different = [id(1), id(2), id(4)];
    assert_ne!(yadorilink_rbsr::fingerprint(&Range::FULL, different.iter()), honest);
}

/// A peer that lies about a fingerprint can hide a range from this exchange,
/// but it cannot make us believe we hold something we do not.
#[test]
fn a_lying_fingerprint_cannot_inject_identifiers() {
    let mut peer = reconciler([id(1), id(2)]);

    let reply = peer
        .ingest(&[RbsrMessage::Fingerprint {
            range: Range::FULL,
            fingerprint: Fingerprint::from_bytes([0xff; 32]),
        }])
        .expect("a wrong fingerprint is well-formed, just wrong");

    assert!(!reply.is_empty(), "a differing fingerprint must provoke an answer");
    assert!(peer.want().is_empty(), "nothing may be recorded as wanted from a fingerprint alone");
}
