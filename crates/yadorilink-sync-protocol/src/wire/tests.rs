#![cfg(test)]

use super::*;

fn id(first: u8) -> ItemId {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    ItemId::from_bytes(bytes)
}

fn body_of(frame: &[u8]) -> &[u8] {
    &frame[4..]
}

#[test]
fn a_round_round_trips() {
    let messages = vec![
        RbsrMessage::Fingerprint {
            range: Range::FULL,
            fingerprint: Fingerprint::from_bytes([3u8; 32]),
        },
        RbsrMessage::Items {
            range: Range::new(id(1), RangeEnd::Excluded(id(9))),
            ids: vec![id(2), id(3)],
            reply_requested: true,
        },
        RbsrMessage::Items {
            range: Range::new(id(9), RangeEnd::Open),
            ids: vec![],
            reply_requested: false,
        },
    ];

    let frame = encode_round(&messages).unwrap();
    let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(declared, frame.len() - 4, "the length prefix must describe the body");
    assert_eq!(decode_round(body_of(&frame)).unwrap(), messages);
}

#[test]
fn a_truncated_round_is_rejected_rather_than_partially_decoded() {
    let frame = encode_round(&[RbsrMessage::Items {
        range: Range::FULL,
        ids: vec![id(1), id(2)],
        reply_requested: true,
    }])
    .unwrap();

    for cut in 1..frame.len() - 4 {
        let truncated = &body_of(&frame)[..cut];
        assert!(decode_round(truncated).is_err(), "a body cut to {cut} bytes must not decode");
    }
}

/// A declared count is a claim by the peer. Believing it before the bytes
/// exist hands a remote peer an allocation primitive.
#[test]
fn a_listing_count_larger_than_the_bytes_present_allocates_nothing() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes()); // one message
    body.push(KIND_ITEMS);
    body.extend_from_slice(id(0).as_bytes());
    body.push(END_OPEN);
    body.push(0); // reply_requested
    body.extend_from_slice(&4096u16.to_be_bytes()); // claims 4096 ids
                                                    // ...and supplies none of them.

    assert!(matches!(decode_round(&body), Err(WireError::Truncated { needed: 131_072, .. })));
}

#[test]
fn an_oversized_listing_is_rejected_by_the_declared_count_alone() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(KIND_ITEMS);
    body.extend_from_slice(id(0).as_bytes());
    body.push(END_OPEN);
    body.push(0);
    body.extend_from_slice(&(u16::MAX).to_be_bytes());

    assert!(matches!(decode_round(&body), Err(WireError::ListingTooLarge { .. })));
}

#[test]
fn trailing_bytes_after_a_round_are_rejected() {
    let frame = encode_round(&[RbsrMessage::Fingerprint {
        range: Range::FULL,
        fingerprint: Fingerprint::from_bytes([1u8; 32]),
    }])
    .unwrap();

    let mut body = body_of(&frame).to_vec();
    body.push(0xFF);
    assert!(matches!(decode_round(&body), Err(WireError::TrailingBytes(1))));
}

#[test]
fn an_unknown_message_kind_is_rejected_not_skipped() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(0x7F);
    body.extend_from_slice(id(0).as_bytes());
    body.push(END_OPEN);

    assert!(matches!(decode_round(&body), Err(WireError::UnknownMessageKind(0x7F))));
}

#[test]
fn a_malformed_range_end_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(KIND_FINGERPRINT);
    body.extend_from_slice(id(0).as_bytes());
    body.push(0x7F);

    assert!(matches!(decode_round(&body), Err(WireError::MalformedRangeEnd(0x7F))));
}

#[test]
fn a_hello_round_trips() {
    let frame = encode_hello("shared-folder").unwrap();
    assert_eq!(decode_hello(body_of(&frame)).unwrap(), "shared-folder");
}

#[test]
fn a_hello_from_another_protocol_version_is_refused_not_parsed() {
    let mut body = Vec::new();
    body.extend_from_slice(&(PROTOCOL_VERSION + 1).to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.push(b'g');

    assert!(matches!(decode_hello(&body), Err(WireError::UnsupportedVersion { .. })));
}

#[test]
fn a_hello_declaring_more_group_bytes_than_it_carries_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&511u16.to_be_bytes());

    assert!(matches!(decode_hello(&body), Err(WireError::Truncated { .. })));
}

#[test]
fn an_oversized_group_id_is_rejected() {
    assert!(matches!(
        encode_hello(&"g".repeat(MAX_GROUP_BYTES + 1)),
        Err(WireError::GroupTooLong { .. })
    ));
}

#[test]
fn a_group_id_that_is_not_utf8_is_rejected() {
    let mut body = Vec::new();
    body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0xFF, 0xFE]);

    assert_eq!(decode_hello(&body), Err(WireError::MalformedGroupId));
}

#[test]
fn a_bundle_request_round_trips_and_is_bounded() {
    let hashes = vec![id(1), id(2), id(3)];
    let frame = encode_bundle_request(&hashes).unwrap();
    assert_eq!(decode_bundle_request(body_of(&frame)).unwrap(), hashes);

    let mut body = Vec::new();
    body.extend_from_slice(&(MAX_BUNDLE_REQUEST as u32 + 1).to_be_bytes());
    assert!(matches!(decode_bundle_request(&body), Err(WireError::RequestTooLarge { .. })));
}

#[test]
fn a_bundle_round_trips() {
    let bundle = OpaqueBundle { change_hash: id(5), payload: vec![9u8; 100] };
    let frame = encode_bundle(&bundle).unwrap();
    assert_eq!(decode_bundle(body_of(&frame)).unwrap(), bundle);
}

#[test]
fn a_bundle_frame_shorter_than_its_hash_is_rejected() {
    assert!(matches!(decode_bundle(&[0u8; 31]), Err(WireError::Truncated { .. })));
}
