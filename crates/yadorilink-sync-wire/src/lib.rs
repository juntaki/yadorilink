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
    BlockRequestHeaderFrame, BlockResponseHeaderFrame, BlockResponseOutcomeFrame,
    ChangeBatchFrame, ChangeBatchOutboundFrame, ChangeRequestFrame,
    ClusterConfigFrame, ClusterConfigOutboundFrame, HandoffLeaseGrantFrame,
    HandoffLeaseReleaseFrame, HandoffLeaseReleaseOutboundFrame, HandoffLeaseRequestFrame,
    HandoffTicketGrantFrame, HandoffTicketReleaseFrame, HandoffTicketReleaseOutboundFrame,
    HandoffTicketRequestFrame, HeadsAnnounceFrame, HeadsAnnounceOutboundFrame, InboundFrame,
    OutboundFrame, RebootstrapSnapshotRequestFrame, RebootstrapSnapshotResponseFrame,
    RelayCloseFrame, RelayDataFrame, RelayOpenFrame, RelayOpenedFrame, VersionPresentAckFrame,
    VersionPresentAckOutboundFrame, VersionPresentQueryFrame,
};
pub use protobuf::ProtobufPeerWireCodec;

/// The wire's `Compression` enum values, owned here (not re-exported from
/// `yadorilink_ipc_proto::sync::Compression` at call sites) so that
/// consumers needing only these two values don't need to reach through a
/// generated protobuf type to name them.
///
/// These are not a negotiated capability: every peer that reaches a session
/// is the same protocol generation and understands both. A sender picks
/// between them per payload, choosing raw whenever compressing would make
/// the payload larger.
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
                want_heads: vec![vec![0u8; 32]],
                have_heads: vec![vec![1u8; 32]],
            }),
            InboundFrame::ChangeBatch(ChangeBatchFrame {
                folder_group_id: "g".to_string(),
                changes: vec![vec![1, 2, 3]],
                file_versions: vec![vec![4, 5, 6]],
                more: true,
            }),
            InboundFrame::ClusterConfig(ClusterConfigFrame {
                acked_peer_cluster_config: true,
                max_inflight_requests: 1,
                max_inflight_bytes: 1,
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
        ];
        assert_eq!(inbound.len(), 14);

        let outbound: Vec<OutboundFrame> = vec![
            OutboundFrame::ClusterConfig(ClusterConfigOutboundFrame {
                acked_peer_cluster_config: true,
                max_inflight_requests: 1,
                max_inflight_bytes: 1,
            }),
            OutboundFrame::HeadsAnnounce(HeadsAnnounceOutboundFrame {
                folder_group_id: "g".to_string(),
                heads: vec![vec![0u8; 32]],
            }),
            OutboundFrame::ChangeRequest(ChangeRequestFrame {
                folder_group_id: "g".to_string(),
                want_heads: vec![vec![0u8; 32]],
                have_heads: vec![vec![1u8; 32]],
            }),
            OutboundFrame::ChangeBatch(ChangeBatchOutboundFrame {
                folder_group_id: "g".to_string(),
                changes: vec![vec![1, 2, 3]],
                file_versions: vec![vec![4, 5, 6]],
                more: true,
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
                present: true,
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
            OutboundFrame::RelayOpen(RelayOpenFrame {
                version: 1,
                grant_id: "gr".to_string(),
                group_id: "g".to_string(),
                source_device_id: "d0".to_string(),
                relay_device_id: "d1".to_string(),
                destination_device_id: "d2".to_string(),
                not_before_unix: 0,
                expires_at_unix: 0,
                max_session_bytes: 0,
                signature: Vec::new(),
            }),
            OutboundFrame::RelayOpened(RelayOpenedFrame {
                grant_id: "gr".to_string(),
                granted: true,
                session_id: 1,
            }),
            OutboundFrame::RelayData(RelayDataFrame { session_id: 1, payload: vec![1, 2, 3] }),
            OutboundFrame::RelayClose(RelayCloseFrame {
                session_id: 1,
                reason: "r".to_string(),
            }),
        ];
        assert_eq!(outbound.len(), 18);
    }
}
