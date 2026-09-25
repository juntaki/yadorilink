#![cfg(test)]

use super::*;

fn a_request() -> ServiceRequest {
    ServiceRequest::VersionPresent {
        group_id: "g".into(),
        file_path: "dir/report.pdf".into(),
        version_hash: VersionHash([9u8; 32]),
        blocks: vec![
            VersionBlock { hash: BlockHash(vec![1u8; 32]), size: 4096 },
            VersionBlock { hash: BlockHash(vec![2u8; 32]), size: 17 },
        ],
        for_handoff: true,
    }
}

#[test]
fn a_request_round_trips() {
    assert_eq!(decode_request(&encode_request(&a_request())).unwrap(), a_request());
}

#[test]
fn a_response_round_trips() {
    for present in [true, false] {
        let response = ServiceResponse::VersionPresent { present };
        assert_eq!(decode_response(&encode_response(&response)).unwrap(), response);
    }
}

#[test]
fn a_truncated_request_is_rejected_at_every_offset() {
    let encoded = encode_request(&a_request());
    for cut in 0..encoded.len() {
        assert!(
            decode_request(&encoded[..cut]).is_err(),
            "a request cut to {cut} bytes must not decode"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut encoded = encode_request(&a_request());
    encoded.push(0);
    assert!(matches!(decode_request(&encoded), Err(ServiceRpcError::TrailingBytes(1))));
}

/// A hostile block count is refused against the bytes actually present,
/// so it never becomes an allocation.
#[test]
fn an_impossible_block_count_is_refused_before_allocating() {
    let mut encoded = vec![RPC_VERSION, KIND_VERSION_PRESENT];
    put_str(&mut encoded, "g");
    put_str(&mut encoded, "f");
    encoded.extend_from_slice(&[0u8; 32]);
    encoded.push(0);
    encoded.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        decode_request(&encoded),
        Err(ServiceRpcError::FieldTooLarge { field: "block count", .. })
    ));

    let mut plausible = encoded[..encoded.len() - 4].to_vec();
    plausible.extend_from_slice(&(MAX_BLOCKS as u32 - 1).to_be_bytes());
    assert!(matches!(decode_request(&plausible), Err(ServiceRpcError::Truncated { .. })));
}

#[test]
fn an_unknown_kind_is_refused_not_guessed() {
    assert!(matches!(
        decode_request(&[RPC_VERSION, 0xEE]),
        Err(ServiceRpcError::UnknownKind(0xEE))
    ));
}

/// The legacy re-bootstrap request/response (kind 6) is gone: it installed a
/// peer's base on the strength of its frontier alone, without verifying the
/// witnesses the base carries. A peer that still sends it is refused like
/// any other unknown kind, in both directions, rather than answered.
#[test]
fn the_retired_rebootstrap_kind_is_refused_both_ways() {
    let mut request = vec![RPC_VERSION, 6];
    put_str(&mut request, "g");
    request.extend_from_slice(&[0u8; 32]);
    assert!(matches!(decode_request(&request), Err(ServiceRpcError::UnknownKind(6))));
    assert!(matches!(decode_response(&[RPC_VERSION, 6, 0]), Err(ServiceRpcError::UnknownKind(6))));
}
