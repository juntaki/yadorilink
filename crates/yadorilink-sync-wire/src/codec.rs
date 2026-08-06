use super::error::WireError;
use super::frame::{InboundFrame, OutboundFrame};

/// Converts between raw wire bytes and domain frames. The only
/// implementation today (`ProtobufPeerWireCodec`, added in a later commit)
/// wraps `prost`/`yadorilink_ipc_proto`; this trait exists so
/// `PeerSyncSession` depends on the abstraction, not the concrete wire
/// format -- a prerequisite for isolating protobuf behind a
/// `yadorilink-sync-wire` crate boundary (Phase 7D) without touching every
/// call site again.
pub trait PeerWireCodec: Send + Sync {
    fn decode(&self, bytes: &[u8]) -> Result<InboundFrame, WireError>;

    fn encode(&self, frame: OutboundFrame) -> Result<Vec<u8>, WireError>;
}
