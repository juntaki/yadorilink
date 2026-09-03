//! The one place in `peer_wire/` (and, once every message family has
//! migrated, in this whole crate) allowed to depend on
//! `yadorilink_ipc_proto`/`prost`. Every other module under `peer_wire/`
//! only knows the domain `InboundFrame`/`OutboundFrame`/`*Frame` types.

use prost::Message as _;
use yadorilink_ipc_proto::sync as proto;

use super::codec::PeerWireCodec;
use super::error::WireError;
// The `*OutboundFrame` types are only named directly by this module's own
// `#[cfg(test)] mod outbound_parity_tests` (via `use super::*`) -- encode()
// itself pattern-matches `OutboundFrame`'s variants without needing each
// inner type's name in scope.
#[allow(unused_imports)]
use super::frame::{
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

impl TryFrom<proto::VersionPresentQuery> for VersionPresentQueryFrame {
    type Error = WireError;

    fn try_from(value: proto::VersionPresentQuery) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: value.request_id,
            folder_group_id: value.folder_group_id,
            file_path: value.file_path,
            block_hashes: value.block_hashes,
            for_handoff: value.for_handoff,
            version_hash: value.version_hash,
            block_sizes: value.block_sizes,
        })
    }
}

impl TryFrom<proto::VersionPresentAck> for VersionPresentAckFrame {
    type Error = WireError;

    fn try_from(value: proto::VersionPresentAck) -> Result<Self, Self::Error> {
        Ok(Self { request_id: value.request_id, present: value.present })
    }
}

impl TryFrom<proto::HandoffLeaseGrant> for HandoffLeaseGrantFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffLeaseGrant) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: value.request_id,
            granted: value.granted,
            lease_id: value.lease_id,
            root_digest: value.root_digest,
            expires_at_unix: value.expires_at_unix,
        })
    }
}

impl From<HandoffLeaseGrantFrame> for proto::HandoffLeaseGrant {
    fn from(value: HandoffLeaseGrantFrame) -> Self {
        Self {
            request_id: value.request_id,
            granted: value.granted,
            lease_id: value.lease_id,
            root_digest: value.root_digest,
            expires_at_unix: value.expires_at_unix,
        }
    }
}

impl TryFrom<proto::HandoffTicketGrant> for HandoffTicketGrantFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffTicketGrant) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: value.request_id,
            granted: value.granted,
            lease_id: value.lease_id,
            expires_at_unix: value.expires_at_unix,
            target_device_id: value.target_device_id,
        })
    }
}

impl From<HandoffTicketGrantFrame> for proto::HandoffTicketGrant {
    fn from(value: HandoffTicketGrantFrame) -> Self {
        Self {
            request_id: value.request_id,
            granted: value.granted,
            lease_id: value.lease_id,
            expires_at_unix: value.expires_at_unix,
            target_device_id: value.target_device_id,
        }
    }
}

impl TryFrom<proto::RebootstrapSnapshotResponse> for RebootstrapSnapshotResponseFrame {
    type Error = WireError;

    fn try_from(value: proto::RebootstrapSnapshotResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: value.request_id,
            granted: value.granted,
            required_encoded: value.required_encoded,
            snapshot_bytes: value.snapshot_bytes,
        })
    }
}

impl From<RebootstrapSnapshotResponseFrame> for proto::RebootstrapSnapshotResponse {
    fn from(value: RebootstrapSnapshotResponseFrame) -> Self {
        Self {
            request_id: value.request_id,
            granted: value.granted,
            required_encoded: value.required_encoded,
            snapshot_bytes: value.snapshot_bytes,
        }
    }
}

impl TryFrom<proto::HeadsAnnounce> for HeadsAnnounceFrame {
    type Error = WireError;

    fn try_from(value: proto::HeadsAnnounce) -> Result<Self, Self::Error> {
        Ok(Self { folder_group_id: value.folder_group_id, heads: value.heads })
    }
}

impl TryFrom<proto::ChangeRequest> for ChangeRequestFrame {
    type Error = WireError;

    fn try_from(value: proto::ChangeRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            folder_group_id: value.folder_group_id,
            want_heads: value.want_heads,
            have_heads: value.have_heads,
        })
    }
}

impl TryFrom<proto::ChangeBatch> for ChangeBatchFrame {
    type Error = WireError;

    fn try_from(value: proto::ChangeBatch) -> Result<Self, Self::Error> {
        Ok(Self {
            folder_group_id: value.folder_group_id,
            changes: value.changes,
            file_versions: value.file_versions,
            more: value.more,
        })
    }
}

impl TryFrom<proto::ClusterConfig> for ClusterConfigFrame {
    type Error = WireError;

    fn try_from(value: proto::ClusterConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            acked_peer_cluster_config: value.acked_peer_cluster_config,
            max_inflight_requests: value.max_inflight_requests,
            max_inflight_bytes: value.max_inflight_bytes,
        })
    }
}

impl TryFrom<proto::BlockRequestHeader> for BlockRequestHeaderFrame {
    type Error = WireError;

    fn try_from(value: proto::BlockRequestHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            folder_group_id: value.folder_group_id,
            file_path: value.file_path,
            block_hash: value.block_hash,
        })
    }
}

impl TryFrom<proto::BlockResponseHeader> for BlockResponseHeaderFrame {
    type Error = WireError;

    fn try_from(value: proto::BlockResponseHeader) -> Result<Self, Self::Error> {
        use proto::block_response_header::Outcome;
        let Some(outcome) = value.outcome else {
            return Err(WireError::Decode(
                "BlockResponseHeader with no outcome is malformed for this generation"
                    .to_string(),
            ));
        };
        let outcome = match outcome {
            Outcome::Found(found) => BlockResponseOutcomeFrame::Found {
                size: found.size,
                hash: found.hash,
                compression: found.compression,
            },
            Outcome::DontHave(_) => BlockResponseOutcomeFrame::DontHave,
            Outcome::Busy(busy) => BlockResponseOutcomeFrame::Busy {
                retry_after_ms: busy.retry_after_ms,
                queue_depth: busy.queue_depth,
            },
            Outcome::Rejected(rejected) => {
                BlockResponseOutcomeFrame::Rejected { reason: rejected.reason }
            }
        };
        Ok(Self { outcome })
    }
}

impl From<BlockResponseHeaderFrame> for proto::BlockResponseHeader {
    fn from(value: BlockResponseHeaderFrame) -> Self {
        use proto::block_response_header::Outcome;
        let outcome = match value.outcome {
            BlockResponseOutcomeFrame::Found { size, hash, compression } => {
                Outcome::Found(proto::BlockFound { size, hash, compression })
            }
            BlockResponseOutcomeFrame::DontHave => Outcome::DontHave(true),
            BlockResponseOutcomeFrame::Busy { retry_after_ms, queue_depth } => {
                Outcome::Busy(proto::BlockBusy { retry_after_ms, queue_depth })
            }
            BlockResponseOutcomeFrame::Rejected { reason } => {
                Outcome::Rejected(proto::BlockRejected { reason })
            }
        };
        Self { outcome: Some(outcome) }
    }
}

impl TryFrom<proto::HandoffLeaseRequest> for HandoffLeaseRequestFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffLeaseRequest) -> Result<Self, Self::Error> {
        Ok(Self { request_id: value.request_id, folder_group_id: value.folder_group_id })
    }
}

impl TryFrom<proto::HandoffLeaseRelease> for HandoffLeaseReleaseFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffLeaseRelease) -> Result<Self, Self::Error> {
        Ok(Self { folder_group_id: value.folder_group_id, lease_id: value.lease_id })
    }
}

impl TryFrom<proto::HandoffTicketRequest> for HandoffTicketRequestFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffTicketRequest) -> Result<Self, Self::Error> {
        Ok(Self { request_id: value.request_id, folder_group_id: value.folder_group_id })
    }
}

impl TryFrom<proto::HandoffTicketRelease> for HandoffTicketReleaseFrame {
    type Error = WireError;

    fn try_from(value: proto::HandoffTicketRelease) -> Result<Self, Self::Error> {
        Ok(Self {
            folder_group_id: value.folder_group_id,
            target_device_id: value.target_device_id,
            lease_id: value.lease_id,
        })
    }
}

impl TryFrom<proto::RebootstrapSnapshotRequest> for RebootstrapSnapshotRequestFrame {
    type Error = WireError;

    fn try_from(value: proto::RebootstrapSnapshotRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: value.request_id,
            folder_group_id: value.folder_group_id,
            requested_hash: value.requested_hash,
        })
    }
}

impl TryFrom<proto::RelayOpen> for RelayOpenFrame {
    type Error = WireError;

    fn try_from(value: proto::RelayOpen) -> Result<Self, Self::Error> {
        Ok(Self {
            version: value.version,
            grant_id: value.grant_id,
            group_id: value.group_id,
            source_device_id: value.source_device_id,
            relay_device_id: value.relay_device_id,
            destination_device_id: value.destination_device_id,
            not_before_unix: value.not_before_unix,
            expires_at_unix: value.expires_at_unix,
            max_session_bytes: value.max_session_bytes,
            signature: value.signature,
        })
    }
}

impl TryFrom<proto::RelayOpened> for RelayOpenedFrame {
    type Error = WireError;

    fn try_from(value: proto::RelayOpened) -> Result<Self, Self::Error> {
        Ok(Self { grant_id: value.grant_id, granted: value.granted, session_id: value.session_id })
    }
}

impl TryFrom<proto::RelayData> for RelayDataFrame {
    type Error = WireError;

    fn try_from(value: proto::RelayData) -> Result<Self, Self::Error> {
        Ok(Self { session_id: value.session_id, payload: value.payload })
    }
}

impl TryFrom<proto::RelayClose> for RelayCloseFrame {
    type Error = WireError;

    fn try_from(value: proto::RelayClose) -> Result<Self, Self::Error> {
        Ok(Self { session_id: value.session_id, reason: value.reason })
    }
}

/// `PeerWireCodec` implementation backed by this crate's existing
/// protobuf schema. See `peer_wire/mod.rs`'s own doc comment for exactly
/// which message families are wired through so far -- every other message
/// type still decodes to `InboundFrame::Unknown` and cannot yet be encoded,
/// matching the fact that no other handler has moved off `proto::SyncMessage`
/// yet.
pub struct ProtobufPeerWireCodec;

impl PeerWireCodec for ProtobufPeerWireCodec {
    fn decode(&self, bytes: &[u8]) -> Result<InboundFrame, WireError> {
        let message =
            proto::SyncMessage::decode(bytes).map_err(|e| WireError::Decode(e.to_string()))?;
        match message.payload {
            Some(proto::sync_message::Payload::VersionPresentQuery(query)) => {
                Ok(InboundFrame::VersionPresentQuery(query.try_into()?))
            }
            Some(proto::sync_message::Payload::VersionPresentAck(ack)) => {
                Ok(InboundFrame::VersionPresentAck(ack.try_into()?))
            }
            Some(proto::sync_message::Payload::HeadsAnnounce(announce)) => {
                Ok(InboundFrame::HeadsAnnounce(announce.try_into()?))
            }
            Some(proto::sync_message::Payload::ChangeRequest(req)) => {
                Ok(InboundFrame::ChangeRequest(req.try_into()?))
            }
            Some(proto::sync_message::Payload::ChangeBatch(batch)) => {
                Ok(InboundFrame::ChangeBatch(batch.try_into()?))
            }
            Some(proto::sync_message::Payload::ClusterConfig(config)) => {
                Ok(InboundFrame::ClusterConfig(config.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffLeaseRequest(req)) => {
                Ok(InboundFrame::HandoffLeaseRequest(req.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffLeaseGrant(grant)) => {
                Ok(InboundFrame::HandoffLeaseGrant(grant.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffLeaseRelease(release)) => {
                Ok(InboundFrame::HandoffLeaseRelease(release.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffTicketRequest(req)) => {
                Ok(InboundFrame::HandoffTicketRequest(req.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffTicketGrant(grant)) => {
                Ok(InboundFrame::HandoffTicketGrant(grant.try_into()?))
            }
            Some(proto::sync_message::Payload::HandoffTicketRelease(release)) => {
                Ok(InboundFrame::HandoffTicketRelease(release.try_into()?))
            }
            Some(proto::sync_message::Payload::RebootstrapSnapshotRequest(req)) => {
                Ok(InboundFrame::RebootstrapSnapshotRequest(req.try_into()?))
            }
            Some(proto::sync_message::Payload::RebootstrapSnapshotResponse(resp)) => {
                Ok(InboundFrame::RebootstrapSnapshotResponse(resp.try_into()?))
            }
            Some(proto::sync_message::Payload::RelayOpen(open)) => {
                Ok(InboundFrame::RelayOpen(open.try_into()?))
            }
            Some(proto::sync_message::Payload::RelayOpened(opened)) => {
                Ok(InboundFrame::RelayOpened(opened.try_into()?))
            }
            Some(proto::sync_message::Payload::RelayData(data)) => {
                Ok(InboundFrame::RelayData(data.try_into()?))
            }
            Some(proto::sync_message::Payload::RelayClose(close)) => {
                Ok(InboundFrame::RelayClose(close.try_into()?))
            }
            // Every current `SyncMessage.payload` oneof variant has an
            // explicit arm above. Under exact-generation ALPN, a
            // same-generation peer always sets a recognized `payload`, so
            // reaching here means a genuinely empty oneof -- a protocol
            // violation for this generation, not a legitimate
            // forward-compatible case to silently ignore.
            None => Err(WireError::Decode(
                "SyncMessage with no payload is malformed for this generation".to_string(),
            )),
        }
    }

    fn encode(&self, frame: OutboundFrame) -> Result<Vec<u8>, WireError> {
        let payload = match frame {
            OutboundFrame::ClusterConfig(config) => {
                proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                    acked_peer_cluster_config: config.acked_peer_cluster_config,
                    max_inflight_requests: config.max_inflight_requests,
                    max_inflight_bytes: config.max_inflight_bytes,
                })
            }
            OutboundFrame::HeadsAnnounce(announce) => {
                proto::sync_message::Payload::HeadsAnnounce(proto::HeadsAnnounce {
                    folder_group_id: announce.folder_group_id,
                    heads: announce.heads,
                })
            }
            OutboundFrame::ChangeRequest(req) => {
                proto::sync_message::Payload::ChangeRequest(proto::ChangeRequest {
                    folder_group_id: req.folder_group_id,
                    want_heads: req.want_heads,
                    have_heads: req.have_heads,
                })
            }
            OutboundFrame::ChangeBatch(batch) => {
                proto::sync_message::Payload::ChangeBatch(proto::ChangeBatch {
                    folder_group_id: batch.folder_group_id,
                    changes: batch.changes,
                    file_versions: batch.file_versions,
                    more: batch.more,
                })
            }
            OutboundFrame::VersionPresentQuery(query) => {
                proto::sync_message::Payload::VersionPresentQuery(proto::VersionPresentQuery {
                    request_id: query.request_id,
                    folder_group_id: query.folder_group_id,
                    file_path: query.file_path,
                    block_hashes: query.block_hashes,
                    for_handoff: query.for_handoff,
                    version_hash: query.version_hash,
                    block_sizes: query.block_sizes,
                })
            }
            OutboundFrame::VersionPresentAck(ack) => {
                proto::sync_message::Payload::VersionPresentAck(proto::VersionPresentAck {
                    request_id: ack.request_id,
                    present: ack.present,
                })
            }
            OutboundFrame::HandoffLeaseRequest(req) => {
                proto::sync_message::Payload::HandoffLeaseRequest(proto::HandoffLeaseRequest {
                    request_id: req.request_id,
                    folder_group_id: req.folder_group_id,
                })
            }
            OutboundFrame::HandoffLeaseGrant(grant) => {
                proto::sync_message::Payload::HandoffLeaseGrant(grant.into())
            }
            OutboundFrame::HandoffLeaseRelease(release) => {
                proto::sync_message::Payload::HandoffLeaseRelease(proto::HandoffLeaseRelease {
                    folder_group_id: release.folder_group_id,
                    lease_id: release.lease_id,
                })
            }
            OutboundFrame::HandoffTicketRequest(req) => {
                proto::sync_message::Payload::HandoffTicketRequest(proto::HandoffTicketRequest {
                    request_id: req.request_id,
                    folder_group_id: req.folder_group_id,
                })
            }
            OutboundFrame::HandoffTicketGrant(grant) => {
                proto::sync_message::Payload::HandoffTicketGrant(grant.into())
            }
            OutboundFrame::HandoffTicketRelease(release) => {
                proto::sync_message::Payload::HandoffTicketRelease(proto::HandoffTicketRelease {
                    folder_group_id: release.folder_group_id,
                    target_device_id: release.target_device_id,
                    lease_id: release.lease_id,
                })
            }
            OutboundFrame::RebootstrapSnapshotRequest(req) => {
                proto::sync_message::Payload::RebootstrapSnapshotRequest(
                    proto::RebootstrapSnapshotRequest {
                        request_id: req.request_id,
                        folder_group_id: req.folder_group_id,
                        requested_hash: req.requested_hash,
                    },
                )
            }
            OutboundFrame::RebootstrapSnapshotResponse(resp) => {
                proto::sync_message::Payload::RebootstrapSnapshotResponse(resp.into())
            }
            OutboundFrame::RelayOpen(open) => {
                proto::sync_message::Payload::RelayOpen(proto::RelayOpen {
                    version: open.version,
                    grant_id: open.grant_id,
                    group_id: open.group_id,
                    source_device_id: open.source_device_id,
                    relay_device_id: open.relay_device_id,
                    destination_device_id: open.destination_device_id,
                    not_before_unix: open.not_before_unix,
                    expires_at_unix: open.expires_at_unix,
                    max_session_bytes: open.max_session_bytes,
                    signature: open.signature,
                })
            }
            OutboundFrame::RelayOpened(opened) => {
                proto::sync_message::Payload::RelayOpened(proto::RelayOpened {
                    grant_id: opened.grant_id,
                    granted: opened.granted,
                    session_id: opened.session_id,
                })
            }
            OutboundFrame::RelayData(data) => {
                proto::sync_message::Payload::RelayData(proto::RelayData {
                    session_id: data.session_id,
                    payload: data.payload,
                })
            }
            OutboundFrame::RelayClose(close) => {
                proto::sync_message::Payload::RelayClose(proto::RelayClose {
                    session_id: close.session_id,
                    reason: close.reason,
                })
            }
        };
        Ok(proto::SyncMessage { payload: Some(payload) }.encode_to_vec())
    }

    fn encode_block_request_header(
        &self,
        frame: BlockRequestHeaderFrame,
    ) -> Result<Vec<u8>, WireError> {
        Ok(proto::BlockRequestHeader {
            folder_group_id: frame.folder_group_id,
            file_path: frame.file_path,
            block_hash: frame.block_hash,
        }
        .encode_to_vec())
    }

    fn decode_block_request_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockRequestHeaderFrame, WireError> {
        proto::BlockRequestHeader::decode(bytes)
            .map_err(|e| WireError::Decode(e.to_string()))?
            .try_into()
    }

    fn encode_block_response_header(
        &self,
        frame: BlockResponseHeaderFrame,
    ) -> Result<Vec<u8>, WireError> {
        Ok(proto::BlockResponseHeader::from(frame).encode_to_vec())
    }

    fn decode_block_response_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockResponseHeaderFrame, WireError> {
        proto::BlockResponseHeader::decode(bytes)
            .map_err(|e| WireError::Decode(e.to_string()))?
            .try_into()
    }
}

/// Byte-parity tests: for every outbound message family, the new
/// `ProtobufPeerWireCodec::encode` path must produce EXACTLY the same
/// wire bytes as the legacy hand-built `proto::SyncMessage { .. }
/// .encode_to_vec()` construction still used at each real send call site
/// in `peer_session.rs` today. This is the safety net Phase 7C.5's
/// production-send-migration commit (4 of 8) depends on: a passing
/// round-trip test only proves the new codec is internally consistent
/// with itself, not that it reproduces what production has always sent.
/// Field values below are copied verbatim from each real call site
/// (`cluster_config_message`, `send_change_batch`, `handle_version_
/// present_query`, etc.) -- not arbitrary test data -- specifically so a
/// mismatch here means the migration would have changed real wire output.
#[cfg(test)]
mod outbound_parity_tests {
    use super::*;

    #[test]
    fn cluster_config_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                acked_peer_cluster_config: false,
                max_inflight_requests: 7,
                max_inflight_bytes: 1_000_000,
            })),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::ClusterConfig(ClusterConfigOutboundFrame {
                acked_peer_cluster_config: false,
                max_inflight_requests: 7,
                max_inflight_bytes: 1_000_000,
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn heads_announce_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HeadsAnnounce(proto::HeadsAnnounce {
                folder_group_id: "g1".to_string(),
                heads: vec![vec![1u8; 32], vec![2u8; 32]],
            })),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HeadsAnnounce(HeadsAnnounceOutboundFrame {
                folder_group_id: "g1".to_string(),
                heads: vec![vec![1u8; 32], vec![2u8; 32]],
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn change_batch_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ChangeBatch(proto::ChangeBatch {
                folder_group_id: "g1".to_string(),
                changes: vec![vec![1, 2, 3], vec![4, 5]],
                file_versions: vec![vec![9, 9]],
                more: true,
            })),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::ChangeBatch(ChangeBatchOutboundFrame {
                folder_group_id: "g1".to_string(),
                changes: vec![vec![1, 2, 3], vec![4, 5]],
                file_versions: vec![vec![9, 9]],
                more: true,
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn change_request_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ChangeRequest(proto::ChangeRequest {
                folder_group_id: "g1".to_string(),
                want_heads: vec![vec![1u8; 32], vec![2u8; 32]],
                have_heads: vec![vec![3u8; 32]],
            })),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::ChangeRequest(ChangeRequestFrame {
                folder_group_id: "g1".to_string(),
                want_heads: vec![vec![1u8; 32], vec![2u8; 32]],
                have_heads: vec![vec![3u8; 32]],
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    /// One block request, one bidirectional stream: the headers are their
    /// own encoding namespace rather than `SyncMessage` variants, so their
    /// round trip is what pins them rather than parity against a control
    /// message that no longer carries them.
    #[test]
    fn a_block_request_header_round_trips() {
        let frame = BlockRequestHeaderFrame {
            folder_group_id: "g1".to_string(),
            file_path: "a.bin".to_string(),
            block_hash: vec![7u8; 32],
        };
        let bytes = ProtobufPeerWireCodec.encode_block_request_header(frame.clone()).unwrap();
        assert_eq!(ProtobufPeerWireCodec.decode_block_request_header(&bytes).unwrap(), frame);
    }

    #[test]
    fn every_block_response_outcome_round_trips() {
        let outcomes = [
            BlockResponseOutcomeFrame::Found {
                size: 3,
                hash: vec![1u8; 32],
                compression: proto::Compression::Zstd as i32,
            },
            BlockResponseOutcomeFrame::DontHave,
            BlockResponseOutcomeFrame::Busy { retry_after_ms: 150, queue_depth: 4 },
            BlockResponseOutcomeFrame::Rejected { reason: "not authorized".to_string() },
        ];
        for outcome in outcomes {
            let frame = BlockResponseHeaderFrame { outcome };
            let bytes =
                ProtobufPeerWireCodec.encode_block_response_header(frame.clone()).unwrap();
            assert_eq!(
                ProtobufPeerWireCodec.decode_block_response_header(&bytes).unwrap(),
                frame
            );
        }
    }

    /// Under exact-generation ALPN a same-generation peer's
    /// `BlockResponseHeader` always sets exactly one `outcome`; an absent
    /// oneof is malformed for this generation and must be rejected at
    /// decode time, never treated as `DontHave`.
    #[test]
    fn an_absent_block_response_outcome_is_a_decode_error() {
        let bytes = proto::BlockResponseHeader { outcome: None }.encode_to_vec();
        assert!(matches!(
            ProtobufPeerWireCodec.decode_block_response_header(&bytes),
            Err(WireError::Decode(_))
        ));
    }

    #[test]
    fn version_present_query_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::VersionPresentQuery(
                proto::VersionPresentQuery {
                    request_id: 11,
                    folder_group_id: "g1".to_string(),
                    file_path: "a.bin".to_string(),
                    block_hashes: vec![vec![1u8; 32]],
                    for_handoff: true,
                    version_hash: vec![2u8; 32],
                    block_sizes: vec![4096],
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::VersionPresentQuery(VersionPresentQueryFrame {
                request_id: 11,
                folder_group_id: "g1".to_string(),
                file_path: "a.bin".to_string(),
                block_hashes: vec![vec![1u8; 32]],
                for_handoff: true,
                version_hash: vec![2u8; 32],
                block_sizes: vec![4096],
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn version_present_ack_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::VersionPresentAck(
                proto::VersionPresentAck { request_id: 11, present: true },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::VersionPresentAck(VersionPresentAckOutboundFrame {
                request_id: 11,
                present: true,
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_lease_request_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseRequest(
                proto::HandoffLeaseRequest { request_id: 21, folder_group_id: "g1".to_string() },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffLeaseRequest(HandoffLeaseRequestFrame {
                request_id: 21,
                folder_group_id: "g1".to_string(),
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_lease_grant_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseGrant(
                proto::HandoffLeaseGrant {
                    request_id: 3,
                    granted: true,
                    lease_id: "lease-abc".to_string(),
                    root_digest: vec![0xAB; 32],
                    expires_at_unix: 1_700_000_000,
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffLeaseGrant(HandoffLeaseGrantFrame {
                request_id: 3,
                granted: true,
                lease_id: "lease-abc".to_string(),
                root_digest: vec![0xAB; 32],
                expires_at_unix: 1_700_000_000,
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_lease_release_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseRelease(
                proto::HandoffLeaseRelease {
                    folder_group_id: "g1".to_string(),
                    lease_id: "lease-1".to_string(),
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffLeaseRelease(HandoffLeaseReleaseOutboundFrame {
                folder_group_id: "g1".to_string(),
                lease_id: "lease-1".to_string(),
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_ticket_request_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketRequest(
                proto::HandoffTicketRequest { request_id: 23, folder_group_id: "g2".to_string() },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffTicketRequest(HandoffTicketRequestFrame {
                request_id: 23,
                folder_group_id: "g2".to_string(),
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_ticket_grant_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketGrant(
                proto::HandoffTicketGrant {
                    request_id: 4,
                    granted: true,
                    lease_id: "lease-def".to_string(),
                    expires_at_unix: 1_700_000_001,
                    target_device_id: "device-x".to_string(),
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffTicketGrant(HandoffTicketGrantFrame {
                request_id: 4,
                granted: true,
                lease_id: "lease-def".to_string(),
                expires_at_unix: 1_700_000_001,
                target_device_id: "device-x".to_string(),
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn handoff_ticket_release_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketRelease(
                proto::HandoffTicketRelease {
                    folder_group_id: "g2".to_string(),
                    target_device_id: "device-y".to_string(),
                    lease_id: "lease-2".to_string(),
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::HandoffTicketRelease(HandoffTicketReleaseOutboundFrame {
                folder_group_id: "g2".to_string(),
                target_device_id: "device-y".to_string(),
                lease_id: "lease-2".to_string(),
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn rebootstrap_snapshot_request_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::RebootstrapSnapshotRequest(
                proto::RebootstrapSnapshotRequest {
                    request_id: 25,
                    folder_group_id: "g3".to_string(),
                    requested_hash: vec![9u8; 32],
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::RebootstrapSnapshotRequest(RebootstrapSnapshotRequestFrame {
                request_id: 25,
                folder_group_id: "g3".to_string(),
                requested_hash: vec![9u8; 32],
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }

    #[test]
    fn rebootstrap_snapshot_response_matches_the_legacy_wire_encoding() {
        let legacy = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::RebootstrapSnapshotResponse(
                proto::RebootstrapSnapshotResponse {
                    request_id: 5,
                    granted: true,
                    required_encoded: vec![1, 2, 3, 4],
                    snapshot_bytes: vec![5, 6, 7, 8, 9],
                },
            )),
        }
        .encode_to_vec();

        let migrated = ProtobufPeerWireCodec
            .encode(OutboundFrame::RebootstrapSnapshotResponse(RebootstrapSnapshotResponseFrame {
                request_id: 5,
                granted: true,
                required_encoded: vec![1, 2, 3, 4],
                snapshot_bytes: vec![5, 6, 7, 8, 9],
            }))
            .unwrap();

        assert_eq!(migrated, legacy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_present_query_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::VersionPresentQuery(
                proto::VersionPresentQuery {
                    request_id: 11,
                    folder_group_id: "g1".to_string(),
                    file_path: "a.bin".to_string(),
                    block_hashes: vec![vec![1u8; 32]],
                    for_handoff: true,
                    version_hash: vec![2u8; 32],
                    block_sizes: vec![4096],
                },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::VersionPresentQuery(query) => {
                assert_eq!(query.request_id, 11);
                assert_eq!(query.folder_group_id, "g1");
                assert_eq!(query.file_path, "a.bin");
                assert_eq!(query.block_hashes, vec![vec![1u8; 32]]);
                assert!(query.for_handoff);
                assert_eq!(query.version_hash, vec![2u8; 32]);
                assert_eq!(query.block_sizes, vec![4096]);
            }
            other => panic!("expected VersionPresentQuery, got {other:?}"),
        }
    }

    #[test]
    fn version_present_ack_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let outbound = VersionPresentAckOutboundFrame { request_id: 7, present: true };

        let bytes = codec.encode(OutboundFrame::VersionPresentAck(outbound)).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::VersionPresentAck(ack) => {
                assert_eq!(ack, VersionPresentAckFrame { request_id: 7, present: true })
            }
            other => panic!("expected VersionPresentAck, got {other:?}"),
        }
    }

    #[test]
    fn version_present_ack_round_trips_false_present() {
        let codec = ProtobufPeerWireCodec;
        let outbound = VersionPresentAckOutboundFrame { request_id: 99, present: false };

        let bytes = codec.encode(OutboundFrame::VersionPresentAck(outbound)).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::VersionPresentAck(ack) => {
                assert_eq!(ack, VersionPresentAckFrame { request_id: 99, present: false })
            }
            other => panic!("expected VersionPresentAck, got {other:?}"),
        }
    }

    #[test]
    fn handoff_lease_grant_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = HandoffLeaseGrantFrame {
            request_id: 3,
            granted: true,
            lease_id: "lease-abc".to_string(),
            root_digest: vec![0xAB; 32],
            expires_at_unix: 1_700_000_000,
        };

        let bytes = codec.encode(OutboundFrame::HandoffLeaseGrant(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::HandoffLeaseGrant(grant) => assert_eq!(grant, original),
            other => panic!("expected HandoffLeaseGrant, got {other:?}"),
        }
    }

    #[test]
    fn relay_open_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = RelayOpenFrame {
            version: 1,
            grant_id: "grant-1".to_string(),
            group_id: "group-1".to_string(),
            source_device_id: "device-a".to_string(),
            relay_device_id: "device-b".to_string(),
            destination_device_id: "device-c".to_string(),
            not_before_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_300,
            max_session_bytes: 0,
            signature: vec![0xCD; 64],
        };

        let bytes = codec.encode(OutboundFrame::RelayOpen(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::RelayOpen(open) => assert_eq!(open, original),
            other => panic!("expected RelayOpen, got {other:?}"),
        }
    }

    #[test]
    fn relay_opened_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original =
            RelayOpenedFrame { grant_id: "grant-1".to_string(), granted: true, session_id: 42 };

        let bytes = codec.encode(OutboundFrame::RelayOpened(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::RelayOpened(opened) => assert_eq!(opened, original),
            other => panic!("expected RelayOpened, got {other:?}"),
        }
    }

    #[test]
    fn relay_data_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = RelayDataFrame { session_id: 42, payload: vec![1, 2, 3, 4, 5] };

        let bytes = codec.encode(OutboundFrame::RelayData(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::RelayData(data) => assert_eq!(data, original),
            other => panic!("expected RelayData, got {other:?}"),
        }
    }

    #[test]
    fn relay_close_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = RelayCloseFrame { session_id: 42, reason: "idle_timeout".to_string() };

        let bytes = codec.encode(OutboundFrame::RelayClose(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::RelayClose(close) => assert_eq!(close, original),
            other => panic!("expected RelayClose, got {other:?}"),
        }
    }

    #[test]
    fn handoff_ticket_grant_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = HandoffTicketGrantFrame {
            request_id: 4,
            granted: true,
            lease_id: "lease-def".to_string(),
            expires_at_unix: 1_700_000_001,
            target_device_id: "device-x".to_string(),
        };

        let bytes = codec.encode(OutboundFrame::HandoffTicketGrant(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::HandoffTicketGrant(grant) => assert_eq!(grant, original),
            other => panic!("expected HandoffTicketGrant, got {other:?}"),
        }
    }

    #[test]
    fn rebootstrap_snapshot_response_round_trips_through_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let original = RebootstrapSnapshotResponseFrame {
            request_id: 5,
            granted: true,
            required_encoded: vec![1, 2, 3, 4],
            snapshot_bytes: vec![5, 6, 7, 8, 9],
        };

        let bytes =
            codec.encode(OutboundFrame::RebootstrapSnapshotResponse(original.clone())).unwrap();
        let decoded = codec.decode(&bytes).unwrap();

        match decoded {
            InboundFrame::RebootstrapSnapshotResponse(resp) => assert_eq!(resp, original),
            other => panic!("expected RebootstrapSnapshotResponse, got {other:?}"),
        }
    }

    #[test]
    fn heads_announce_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HeadsAnnounce(proto::HeadsAnnounce {
                folder_group_id: "g1".to_string(),
                heads: vec![vec![1u8; 32], vec![2u8; 32]],
            })),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::HeadsAnnounce(announce) => {
                assert_eq!(announce.folder_group_id, "g1");
                assert_eq!(announce.heads, vec![vec![1u8; 32], vec![2u8; 32]]);
            }
            other => panic!("expected HeadsAnnounce, got {other:?}"),
        }
    }

    #[test]
    fn change_request_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ChangeRequest(proto::ChangeRequest {
                folder_group_id: "g1".to_string(),
                want_heads: vec![vec![4u8; 32]],
                have_heads: vec![vec![5u8; 32]],
            })),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::ChangeRequest(req) => {
                assert_eq!(req.folder_group_id, "g1");
                assert_eq!(req.want_heads, vec![vec![4u8; 32]]);
                assert_eq!(req.have_heads, vec![vec![5u8; 32]]);
            }
            other => panic!("expected ChangeRequest, got {other:?}"),
        }
    }

    #[test]
    fn change_batch_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ChangeBatch(proto::ChangeBatch {
                folder_group_id: "g1".to_string(),
                changes: vec![vec![1, 2, 3]],
                file_versions: vec![vec![4, 5, 6]],
                more: true,
            })),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::ChangeBatch(batch) => {
                assert_eq!(batch.folder_group_id, "g1");
                assert_eq!(batch.changes, vec![vec![1, 2, 3]]);
                assert_eq!(batch.file_versions, vec![vec![4, 5, 6]]);
                assert!(batch.more);
            }
            other => panic!("expected ChangeBatch, got {other:?}"),
        }
    }

    #[test]
    fn cluster_config_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::ClusterConfig(proto::ClusterConfig {
                acked_peer_cluster_config: true,
                max_inflight_requests: 7,
                max_inflight_bytes: 8,
            })),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::ClusterConfig(config) => {
                assert!(config.acked_peer_cluster_config);
                assert_eq!(config.max_inflight_requests, 7);
                assert_eq!(config.max_inflight_bytes, 8);
            }
            other => panic!("expected ClusterConfig, got {other:?}"),
        }
    }

    #[test]
    fn handoff_lease_request_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseRequest(
                proto::HandoffLeaseRequest { request_id: 21, folder_group_id: "g1".to_string() },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::HandoffLeaseRequest(req) => {
                assert_eq!(req.request_id, 21);
                assert_eq!(req.folder_group_id, "g1");
            }
            other => panic!("expected HandoffLeaseRequest, got {other:?}"),
        }
    }

    #[test]
    fn handoff_lease_release_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffLeaseRelease(
                proto::HandoffLeaseRelease {
                    folder_group_id: "g1".to_string(),
                    lease_id: "lease-1".to_string(),
                },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::HandoffLeaseRelease(release) => {
                assert_eq!(release.folder_group_id, "g1");
                assert_eq!(release.lease_id, "lease-1");
            }
            other => panic!("expected HandoffLeaseRelease, got {other:?}"),
        }
    }

    #[test]
    fn handoff_ticket_request_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketRequest(
                proto::HandoffTicketRequest { request_id: 23, folder_group_id: "g2".to_string() },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::HandoffTicketRequest(req) => {
                assert_eq!(req.request_id, 23);
                assert_eq!(req.folder_group_id, "g2");
            }
            other => panic!("expected HandoffTicketRequest, got {other:?}"),
        }
    }

    #[test]
    fn handoff_ticket_release_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::HandoffTicketRelease(
                proto::HandoffTicketRelease {
                    folder_group_id: "g2".to_string(),
                    target_device_id: "device-y".to_string(),
                    lease_id: "lease-2".to_string(),
                },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::HandoffTicketRelease(release) => {
                assert_eq!(release.folder_group_id, "g2");
                assert_eq!(release.target_device_id, "device-y");
                assert_eq!(release.lease_id, "lease-2");
            }
            other => panic!("expected HandoffTicketRelease, got {other:?}"),
        }
    }

    #[test]
    fn rebootstrap_snapshot_request_decodes_from_the_wire() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage {
            payload: Some(proto::sync_message::Payload::RebootstrapSnapshotRequest(
                proto::RebootstrapSnapshotRequest {
                    request_id: 25,
                    folder_group_id: "g3".to_string(),
                    requested_hash: vec![9u8; 32],
                },
            )),
        };

        let decoded = codec.decode(&message.encode_to_vec()).unwrap();
        match decoded {
            InboundFrame::RebootstrapSnapshotRequest(req) => {
                assert_eq!(req.request_id, 25);
                assert_eq!(req.folder_group_id, "g3");
                assert_eq!(req.requested_hash, vec![9u8; 32]);
            }
            other => panic!("expected RebootstrapSnapshotRequest, got {other:?}"),
        }
    }

    // Every `SyncMessage.payload` oneof variant is wired into `decode`'s
    // match. Under exact-generation ALPN a same-generation peer always sets
    // a recognized `payload`, so a genuinely empty oneof is a protocol
    // violation for this generation -- `an_empty_payload_is_a_decode_error`
    // below covers it; the forward-incompatible-future-variant case cannot
    // be constructed against this build's own generated types.

    #[test]
    fn an_empty_payload_is_a_decode_error() {
        let codec = ProtobufPeerWireCodec;
        let message = proto::SyncMessage { payload: None };

        assert!(matches!(codec.decode(&message.encode_to_vec()), Err(WireError::Decode(_))));
    }

    #[test]
    fn garbage_bytes_fail_to_decode() {
        let codec = ProtobufPeerWireCodec;
        // Not a valid varint tag for the first field -- prost must reject
        // this, not panic or silently produce an empty message.
        let garbage = vec![0xFFu8; 4];

        assert!(matches!(codec.decode(&garbage), Err(WireError::Decode(_))));
    }
}
