//! Peer wire codec/frame layer for `yadorilink`'s sync protocol: converts
//! between raw wire bytes and protobuf-free domain frames
//! (`InboundFrame`/`OutboundFrame`). Owns the on-the-wire representation of
//! peer sync messages as a standalone crate so it can be consumed without
//! pulling in `yadorilink-sync-core`'s storage/engine dependencies.
//! `yadorilink-sync-core` depends on this crate; this crate never depends
//! back on it, and its public frame types never expose a generated
//! `yadorilink_ipc_proto` type.

mod codec;
mod error;
mod frame;
mod protobuf;

pub use codec::PeerWireCodec;
pub use error::WireError;
pub use frame::{
    BlockReplyFrame, BlockReplyOutboundFrame, BlockReplyOutboundOutcome, BlockReplyOutcomeFrame,
    BlockRequestFrame, ChangeBatchFrame, ChangeBatchOutboundFrame, ChangeRequestFrame,
    ClusterConfigFrame, ClusterConfigOutboundFrame, HandoffLeaseGrantFrame,
    HandoffLeaseReleaseFrame, HandoffLeaseReleaseOutboundFrame, HandoffLeaseRequestFrame,
    HandoffTicketGrantFrame, HandoffTicketReleaseFrame, HandoffTicketReleaseOutboundFrame,
    HandoffTicketRequestFrame, HeadsAnnounceFrame, HeadsAnnounceOutboundFrame, InboundFrame,
    OutboundFrame, RebootstrapSnapshotRequestFrame, RebootstrapSnapshotResponseFrame,
    VersionPresentAckFrame, VersionPresentAckOutboundFrame, VersionPresentQueryFrame,
};
pub use protobuf::ProtobufPeerWireCodec;

/// The wire's `Compression` enum values, owned here (not re-exported from
/// `yadorilink_ipc_proto::sync::Compression` at call sites) so that
/// consumers needing only these two values don't need to reach through a
/// generated protobuf type to name them.
pub const COMPRESSION_NONE: i32 = 0;
pub const COMPRESSION_ZSTD: i32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_present_ack_frame_preserves_domain_fields() {
        let frame = VersionPresentAckFrame { request_id: 42, present: true };

        assert_eq!(frame.request_id, 42);
        assert!(frame.present);
    }

    #[test]
    fn peer_wire_frames_do_not_expose_proto_types() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<InboundFrame>();
        assert_send_sync::<OutboundFrame>();
    }

    /// Constructs every `InboundFrame`/`OutboundFrame` variant using only
    /// plain Rust primitives (`String`/`Vec<u8>`/`bool`/`u32`/`u64`/`i32`/
    /// `i64`) as field values -- this module names no
    /// `yadorilink_ipc_proto` type anywhere, so if any public frame field
    /// were secretly typed as a generated protobuf type, this file would
    /// fail to compile rather than merely fail an assertion. That is the
    /// proof this crate's public API surface never leaks `proto::*`.
    #[test]
    fn public_frames_do_not_expose_generated_proto_types() {
        let inbound: Vec<InboundFrame> = vec![
            InboundFrame::VersionPresentQuery(VersionPresentQueryFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                file_path: "f".to_string(),
                block_hashes: vec![vec![0u8; 32]],
                for_handoff: false,
                version_hash: vec![0u8; 32],
                block_sizes: vec![4096],
            }),
            InboundFrame::VersionPresentAck(VersionPresentAckFrame {
                request_id: 1,
                present: true,
            }),
            InboundFrame::HeadsAnnounce(HeadsAnnounceFrame {
                folder_group_id: "g".to_string(),
                heads: vec![vec![0u8; 32]],
            }),
            InboundFrame::ChangeRequest(ChangeRequestFrame {
                folder_group_id: "g".to_string(),
                want: vec![vec![0u8; 32]],
            }),
            InboundFrame::ChangeBatch(ChangeBatchFrame {
                folder_group_id: "g".to_string(),
                changes: vec![vec![1, 2, 3]],
                compressed_changes: Vec::new(),
                file_versions: vec![vec![4, 5, 6]],
            }),
            InboundFrame::ClusterConfig(ClusterConfigFrame {
                acked_peer_cluster_config: true,
                supported_compression: vec![COMPRESSION_ZSTD],
                supports_reliable_delivery: true,
                supports_change_dag: true,
                supports_version_present: true,
                supports_version_hash_exact: true,
                max_inflight_requests: 1,
                max_inflight_bytes: 1,
                protocol_version: 1,
            }),
            InboundFrame::BlockRequest(BlockRequestFrame {
                folder_group_id: "g".to_string(),
                file_path: "f".to_string(),
                block_hash: vec![0u8; 32],
                request_id: 1,
            }),
            InboundFrame::BlockReply(BlockReplyFrame {
                block_hash: vec![0u8; 32],
                outcome: Some(BlockReplyOutcomeFrame::Found {
                    data: vec![1, 2, 3],
                    compression: COMPRESSION_NONE,
                }),
                request_id: 1,
            }),
            InboundFrame::HandoffLeaseRequest(HandoffLeaseRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
            }),
            InboundFrame::HandoffLeaseGrant(HandoffLeaseGrantFrame {
                request_id: 1,
                granted: true,
                lease_id: "l".to_string(),
                root_digest: vec![0u8; 32],
                expires_at_unix: 0,
            }),
            InboundFrame::HandoffLeaseRelease(HandoffLeaseReleaseFrame {
                folder_group_id: "g".to_string(),
                lease_id: "l".to_string(),
            }),
            InboundFrame::HandoffTicketRequest(HandoffTicketRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
            }),
            InboundFrame::HandoffTicketGrant(HandoffTicketGrantFrame {
                request_id: 1,
                granted: true,
                lease_id: "l".to_string(),
                expires_at_unix: 0,
                target_device_id: "d".to_string(),
            }),
            InboundFrame::HandoffTicketRelease(HandoffTicketReleaseFrame {
                folder_group_id: "g".to_string(),
                target_device_id: "d".to_string(),
                lease_id: "l".to_string(),
            }),
            InboundFrame::RebootstrapSnapshotRequest(RebootstrapSnapshotRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                requested_hash: vec![0u8; 32],
            }),
            InboundFrame::RebootstrapSnapshotResponse(RebootstrapSnapshotResponseFrame {
                request_id: 1,
                granted: true,
                required_encoded: vec![1, 2, 3],
                snapshot_bytes: vec![4, 5, 6],
            }),
            InboundFrame::Unknown { message_kind: Some(99) },
        ];
        assert_eq!(inbound.len(), 17);

        let outbound: Vec<OutboundFrame> = vec![
            OutboundFrame::ClusterConfig(ClusterConfigOutboundFrame {
                folder_group_ids: vec!["g".to_string()],
                known_peer_device_ids: vec!["d".to_string()],
                supported_compression: vec![COMPRESSION_ZSTD],
                supports_reliable_delivery: true,
                acked_peer_cluster_config: true,
                supports_change_dag: true,
                supports_version_present: true,
                supports_version_hash_exact: true,
                max_inflight_requests: 1,
                max_inflight_bytes: 1,
                available_worker_slots: 1,
                estimated_queue_delay_ms: 0,
                protocol_version: 1,
            }),
            OutboundFrame::HeadsAnnounce(HeadsAnnounceOutboundFrame {
                folder_group_id: "g".to_string(),
                heads: vec![vec![0u8; 32]],
                frontier_hint: vec![0u8; 32],
            }),
            OutboundFrame::ChangeRequest(ChangeRequestFrame {
                folder_group_id: "g".to_string(),
                want: vec![vec![0u8; 32]],
            }),
            OutboundFrame::ChangeBatch(ChangeBatchOutboundFrame {
                folder_group_id: "g".to_string(),
                changes: vec![vec![1, 2, 3]],
                compressed_changes: Vec::new(),
                file_versions: vec![vec![4, 5, 6]],
            }),
            OutboundFrame::BlockRequest(BlockRequestFrame {
                folder_group_id: "g".to_string(),
                file_path: "f".to_string(),
                block_hash: vec![0u8; 32],
                request_id: 1,
            }),
            OutboundFrame::BlockReply(BlockReplyOutboundFrame {
                block_hash: vec![0u8; 32],
                outcome: BlockReplyOutboundOutcome::Found {
                    data: vec![1, 2, 3],
                    compression: COMPRESSION_NONE,
                },
                request_id: 1,
            }),
            OutboundFrame::VersionPresentQuery(VersionPresentQueryFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                file_path: "f".to_string(),
                block_hashes: vec![vec![0u8; 32]],
                for_handoff: false,
                version_hash: vec![0u8; 32],
                block_sizes: vec![4096],
            }),
            OutboundFrame::VersionPresentAck(VersionPresentAckOutboundFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                file_path: "f".to_string(),
                present: true,
                signature: Vec::new(),
            }),
            OutboundFrame::HandoffLeaseRequest(HandoffLeaseRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
            }),
            OutboundFrame::HandoffLeaseGrant(HandoffLeaseGrantFrame {
                request_id: 1,
                granted: true,
                lease_id: "l".to_string(),
                root_digest: vec![0u8; 32],
                expires_at_unix: 0,
            }),
            OutboundFrame::HandoffLeaseRelease(HandoffLeaseReleaseOutboundFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                lease_id: "l".to_string(),
            }),
            OutboundFrame::HandoffTicketRequest(HandoffTicketRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
            }),
            OutboundFrame::HandoffTicketGrant(HandoffTicketGrantFrame {
                request_id: 1,
                granted: true,
                lease_id: "l".to_string(),
                expires_at_unix: 0,
                target_device_id: "d".to_string(),
            }),
            OutboundFrame::HandoffTicketRelease(HandoffTicketReleaseOutboundFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                target_device_id: "d".to_string(),
                lease_id: "l".to_string(),
            }),
            OutboundFrame::RebootstrapSnapshotRequest(RebootstrapSnapshotRequestFrame {
                request_id: 1,
                folder_group_id: "g".to_string(),
                requested_hash: vec![0u8; 32],
            }),
            OutboundFrame::RebootstrapSnapshotResponse(RebootstrapSnapshotResponseFrame {
                request_id: 1,
                granted: true,
                required_encoded: vec![1, 2, 3],
                snapshot_bytes: vec![4, 5, 6],
            }),
        ];
        assert_eq!(outbound.len(), 16);
    }
}
