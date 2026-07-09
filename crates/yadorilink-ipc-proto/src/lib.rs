pub mod framing;

pub mod coordination {
    tonic::include_proto!("yadorilink.coordination.v1");
}

pub mod sync {
    tonic::include_proto!("yadorilink.sync.v1");
}

pub mod shellipc {
    tonic::include_proto!("yadorilink.shellipc.v1");
}

pub mod relay {
    tonic::include_proto!("yadorilink.relay.v1");
}

pub mod local_discovery {
    tonic::include_proto!("yadorilink.local_discovery.v1");
}

pub mod daemonctl {
    tonic::include_proto!("yadorilink.daemonctl.v1");

    /// add-update-migration-safety task 1.1: this crate's own control-
    /// protocol version marker — bump it whenever a change to this wire
    /// format needs the daemon/CLI to actively distinguish "I'm talking to
    /// an old peer" rather than relying on protobuf's ordinary
    /// unknown-field/zero-default forward compatibility alone (e.g. a
    /// request variant that isn't safe to silently ignore). Every
    /// `DaemonControlRequest`/`DaemonControlResponse` carries this via its
    /// own `protocol_version`/`daemon_protocol_version` field (see those
    /// fields' doc comments in `daemon_control.proto`) so either side can
    /// tell a genuinely pre-versioning peer (field absent, decodes as 0)
    /// apart from a peer that's simply one version behind.
    pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::coordination::PeerInfo;
    use crate::daemonctl::daemon_control_request::Payload as ReqPayload;
    use crate::daemonctl::{DaemonControlRequest, DaemonControlResponse, StatusRequest};
    use crate::sync::{
        BlockResponse, ClusterConfig, Compression, EncryptedFileEntry, Index, IndexUpdate,
    };

    #[test]
    fn old_block_response_bytes_decode_as_uncompressed() {
        let old_format = BlockResponse {
            block_hash: vec![1; 32],
            data: b"plain block".to_vec(),
            not_found: false,
            compression: Compression::None as i32,
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = BlockResponse::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.compression, Compression::None as i32);
    }

    /// add-untrusted-storage-peer task 5's wire-compat discipline (mirrors
    /// `old_block_response_bytes_decode_as_uncompressed` above): a
    /// `BlockResponse` encoded by a pre-encryption build never sets
    /// `is_ciphertext`/`ciphertext_nonce`, so it decodes as ordinary
    /// plaintext — a peer that adds this code never needs to worry about
    /// misinterpreting old traffic as ciphertext.
    #[test]
    fn old_block_response_bytes_decode_as_not_ciphertext() {
        let old_format = BlockResponse {
            block_hash: vec![2; 32],
            data: b"plain block".to_vec(),
            not_found: false,
            compression: Compression::None as i32,
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = BlockResponse::decode(old_format.as_slice()).unwrap();

        assert!(!decoded.is_ciphertext);
        assert!(decoded.ciphertext_nonce.is_empty());
    }

    /// An old `ClusterConfig` (predating this change) decodes with
    /// `supports_encrypted_storage_peer` at its proto3 zero-value (`false`)
    /// — `record_peer_encryption_support` (`peer_session.rs`) must never
    /// treat an old peer as encryption-capable just because the field is
    /// absent.
    #[test]
    fn old_cluster_config_bytes_decode_as_not_supporting_encrypted_storage_peer() {
        let old_format = ClusterConfig {
            folder_group_ids: vec!["group-a".into()],
            known_peer_device_ids: vec!["device-a".into()],
            supported_compression: vec![],
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = ClusterConfig::decode(old_format.as_slice()).unwrap();

        assert!(!decoded.supports_encrypted_storage_peer);
    }

    /// An old `PeerInfo` (predating this change) decodes with an empty
    /// `storage_only_group_ids` map — a group missing from the map is
    /// treated as trusted (`false`), matching `shared_group_roles`'s own
    /// missing-key default.
    #[test]
    fn old_peer_info_bytes_decode_with_no_storage_only_flags() {
        let old_format = PeerInfo {
            device_id: "device-a".into(),
            wireguard_public_key: vec![1; 32],
            endpoints: vec![],
            shared_group_ids: vec!["group-a".into()],
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = PeerInfo::decode(old_format.as_slice()).unwrap();

        assert!(decoded.storage_only_group_ids.is_empty());
    }

    /// task 3.1: an `EncryptedFileEntry`'s `encrypted_file_meta` round-trips
    /// as opaque bytes — this crate doesn't know or care about AEAD, only
    /// that the wire type carries arbitrary ciphertext bytes faithfully.
    #[test]
    fn encrypted_file_entry_round_trips_opaque_ciphertext_fields() {
        let entry = EncryptedFileEntry {
            encrypted_file_meta: b"not-real-ciphertext".to_vec(),
            file_meta_nonce: vec![9; 24],
            blocks: vec![crate::sync::CiphertextBlockInfo {
                ciphertext_hash: vec![7; 32],
                size: 4096,
            }],
            deleted: false,
        };
        let bytes = entry.encode_to_vec();
        let decoded = EncryptedFileEntry::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn old_index_bytes_decode_as_uncompressed() {
        let old_format = Index {
            folder_group_id: "group-a".into(),
            files: vec![],
            compression: 0,
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = Index::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.compression, Compression::None as i32);
    }

    #[test]
    fn old_index_update_bytes_decode_as_uncompressed() {
        let old_format = IndexUpdate {
            folder_group_id: "group-a".into(),
            changed_files: vec![],
            compression: 0,
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = IndexUpdate::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.compression, Compression::None as i32);
    }

    /// add-update-migration-safety task 1.1/2.3, spec "Old CLI talks to
    /// newer daemon": a `DaemonControlRequest` built the way every CLI
    /// build before this change built one — only `payload` set, no
    /// `protocol_version` field at all — decodes with `protocol_version ==
    /// 0`, not an error and not some other sentinel. A current daemon must
    /// treat that 0 as "pre-versioning client," never as a literal invalid
    /// version number.
    #[test]
    fn old_daemon_control_request_bytes_decode_with_zero_protocol_version() {
        let old_format = DaemonControlRequest {
            payload: Some(ReqPayload::Status(StatusRequest {})),
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = DaemonControlRequest::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.protocol_version, 0);
        assert!(matches!(decoded.payload, Some(ReqPayload::Status(_))));
    }

    /// Converse of the above, spec "New CLI talks to older supported
    /// daemon": a `DaemonControlResponse` from a daemon build that
    /// predates `daemon_protocol_version` decodes that field as 0 — the
    /// CLI-side signal that it's talking to a pre-versioning daemon,
    /// distinguishable from any real daemon protocol version (which starts
    /// at 1, see `CONTROL_PROTOCOL_VERSION`).
    #[test]
    fn old_daemon_control_response_bytes_decode_with_zero_daemon_protocol_version() {
        let old_format = DaemonControlResponse {
            payload: Some(crate::daemonctl::daemon_control_response::Payload::Error(
                "empty request".into(),
            )),
            ..Default::default()
        }
        .encode_to_vec();

        let decoded = DaemonControlResponse::decode(old_format.as_slice()).unwrap();

        assert_eq!(decoded.daemon_protocol_version, 0);
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
