pub mod framing;

pub mod sync {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.sync.v1.rs"));
}

pub mod shellipc {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.shellipc.v1.rs"));
}

pub mod local_discovery {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.local_discovery.v1.rs"));
}

pub mod daemonctl {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.daemonctl.v1.rs"));

    /// Exact daemon-control protocol generation for the current pre-release
    /// source tree. The CLI, desktop app, and daemon are shipped as one unit;
    /// development builds are not required to interoperate across protocol
    /// generations. A version mismatch should fail clearly rather than select a
    /// backward-compatibility path.
    pub const CONTROL_PROTOCOL_VERSION: u32 = 2;
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::daemonctl::daemon_control_request::Payload as ReqPayload;
    use crate::daemonctl::{DaemonControlRequest, StatusRequest};
    use crate::sync::{BlockResponse, Compression, SyncMessage};

    #[test]
    fn old_block_response_bytes_decode_as_uncompressed() {
        let old_format = BlockResponse {
            block_hash: vec![1; 32],
            data: b"plain block".to_vec(),
            not_found: false,
            compression: Compression::None as i32,
        }
        .encode_to_vec();

        let decoded = BlockResponse::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.compression, Compression::None as i32);
    }

    /// Hand-rolls a length-delimited (wire type 2) `SyncMessage` field
    /// carrying a submessage whose own field 1 is the string "group-a" —
    /// the shape both the removed `Index` and `IndexUpdate` had. Built by
    /// hand precisely because the Rust types no longer exist to build it
    /// with; these are the bytes an old peer still puts on the wire.
    fn legacy_index_shaped_field(field_number: u8) -> Vec<u8> {
        let mut submessage = vec![0x0A, 7];
        submessage.extend_from_slice(b"group-a");

        let mut framed = vec![(field_number << 3) | 2, submessage.len() as u8];
        framed.extend_from_slice(&submessage);
        framed
    }

    /// `SyncMessage` fields 2 and 3 were `full_index`/`index_update`,
    /// removed with the mtime index-convergence engine and `reserved` in
    /// `sync.proto`. An old peer that predates the change DAG still sends
    /// them, so what those bytes decode to here is a live wire-compat
    /// question, not a hypothetical.
    ///
    /// They must land as an *unset* `payload`: that is the case
    /// `peer_session.rs`'s `handle_message` routes to `None => Ok(())` and
    /// silently drops, which is why deleting its explicit legacy drop arm
    /// preserved the behaviour rather than turning these into errors.
    ///
    /// This also guards the hazard `reserved` exists for. Field numbers are
    /// wire identity: if a future message were assigned 2 or 3, an old
    /// peer's `Index` bytes would decode as whatever new meaning that
    /// number carries — silent misinterpretation of a message we no longer
    /// understand, strictly worse than dropping it. `reserved` makes protoc
    /// reject the reuse at build time; this asserts the resulting runtime
    /// behaviour, and would fail the moment either number came back.
    #[test]
    fn legacy_full_index_and_index_update_bytes_decode_as_an_unset_payload() {
        for field_number in [2u8, 3u8] {
            let old_peer_bytes = legacy_index_shaped_field(field_number);

            let decoded = SyncMessage::decode(old_peer_bytes.as_slice())
                .unwrap_or_else(|e| panic!("field {field_number} must decode, not error: {e}"));

            assert!(
                decoded.payload.is_none(),
                "reserved SyncMessage field {field_number} decoded as {:?}; an old peer's \
                 legacy index bytes must arrive as an unset payload and be dropped, never \
                 be reinterpreted as a live message",
                decoded.payload
            );
        }
    }

    /// A request built by a current CLI carries `protocol_version ==
    /// CONTROL_PROTOCOL_VERSION` alongside its payload, and both round-trip
    /// through encode/decode untouched by each other — the top-level
    /// version field and the `oneof payload` are independent.
    #[test]
    fn current_daemon_control_request_round_trips_protocol_version_and_payload() {
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::Status(StatusRequest {})),
            protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlRequest::decode(req.encode_to_vec().as_slice()).unwrap();

        assert_eq!(decoded.protocol_version, crate::daemonctl::CONTROL_PROTOCOL_VERSION);
        assert!(matches!(decoded.payload, Some(ReqPayload::Status(_))));
    }
}
