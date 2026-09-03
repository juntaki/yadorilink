use super::error::WireError;
use super::frame::{
    BlockRequestHeaderFrame, BlockResponseHeaderFrame, InboundFrame, OutboundFrame,
};

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

    /// Block-stream headers are their own encoding namespace, not
    /// `SyncMessage` variants: they never travel on the control stream, and
    /// wrapping them in the control message envelope purely for uniformity
    /// would mean a block stream could carry any control message at all --
    /// a decode branch nothing sends and nothing should have to reason
    /// about.
    fn encode_block_request_header(
        &self,
        frame: BlockRequestHeaderFrame,
    ) -> Result<Vec<u8>, WireError>;

    fn decode_block_request_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockRequestHeaderFrame, WireError>;

    fn encode_block_response_header(
        &self,
        frame: BlockResponseHeaderFrame,
    ) -> Result<Vec<u8>, WireError>;

    fn decode_block_response_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockResponseHeaderFrame, WireError>;
}
