//! Peer-to-peer mesh transport.
//!
//! Layering, outer to inner:
//! - [`quic_peer_channel::QuicPeerChannel`]: the message channel a sync
//!   session talks to -- one long-lived bidirectional QUIC stream carrying
//!   the whole conversation with one peer, plus the block streams that
//!   conversation opens alongside it.
//! - [`block_stream::QuicBlockStream`]: one block request and its response,
//!   on a bidirectional stream of its own.
//! - [`quic_peer_endpoint::QuicPeerEndpoint`]: this device's single QUIC
//!   endpoint, which authenticates every peer by its Ed25519 device key
//!   ([`quic_identity`]) and separates peers by QUIC connection id.
//! - [`quic_socket::TransportHubQuicSocket`]: the bridge that lets that
//!   endpoint share the device's one UDP binding with STUN and the relay
//!   envelope, so a NAT candidate still names the exact socket data flows
//!   on.
//! - [`transport_hub::TransportHub`]: that binding, its demultiplexer, and
//!   the NAT-traversal machinery around it.
//! - [`relay_path`]: the synthetic addresses that let a relay-carried peer
//!   look, to that endpoint, like any other UDP path.
//!
//! Sync data travels over direct peer-to-peer paths this device establishes
//! itself, or -- when no direct path can be had -- over a relay
//! ([`relay_path`]), itself just another peer this device already shares a
//! group with. A relayed peer is presented to the QUIC endpoint as an
//! ordinary UDP path at a synthetic address, so nothing above the hub has to
//! know the difference. A peer no path ever reaches is reported
//! [`peer_channel::PeerReachability::Unreachable`] with a failure category,
//! never routed through an operator-run server.

pub mod block_stream;
mod error;
mod key_secret_store;
mod keys;
mod local_candidates;
mod local_discovery;
pub mod nat;
mod peer_channel;
pub mod quic_identity;
pub mod quic_peer_channel;
pub mod quic_peer_endpoint;
pub mod quic_socket;
pub mod relay_path;
mod supervise;
mod transport_hub;
mod udp_batching;

pub use block_stream::{
    QuicBlockStream, MAX_BLOCK_STREAM_BODY_BYTES, MAX_BLOCK_STREAM_HEADER_BYTES,
};
pub use error::TransportError;
pub use keys::{verifying_key_from_bytes, DeviceSigningKeyPair, KeyLoadError};
pub use local_candidates::{
    local_candidate_addresses, local_candidates_classified, routable_local_ipv4,
    LOCAL_CANDIDATE_PRIORITY,
};
pub use local_discovery::{start_local_discovery, PeerAnnouncement};
pub use nat::classify::{classify, NatClass};
pub use nat::portmap::{PortMapConfig, PortMapper};
pub use nat::punch::{run_burst, PunchConfig, PunchDecision, PunchLimiter, PunchTarget};
pub use nat::stun::{StunConfig, StunProber};
pub use nat::{
    Candidate, CandidateClass, CandidateSink, NatObservations, ObservationLog, PortMappingStatus,
};
pub use peer_channel::{
    classify_endpoint, diff_netmap, NetmapDiff, NetmapSnapshot, PeerReachability,
    UnreachableCategory,
};
pub use quic_identity::{
    device_certified_key, quic_client_config, quic_server_config, AuthorizedPeerKeys,
    PinnedPeerKeys, PEER_SERVER_NAME, YADORILINK_P2P_ALPN,
};
pub use quic_peer_channel::{QuicPeerChannel, MAX_CONTROL_FRAME_BYTES};
pub use quic_peer_endpoint::{
    connect_role, ConnectRole, QuicPeerEndpoint, PEER_IDLE_TIMEOUT, RACED_DIAL_WORST_CASE,
};
pub use quic_socket::{HubQuinnRuntime, TransportHubQuicSocket};
pub use relay_path::{is_synthetic_relay_addr, RelayControlEgress, RelayPathHandle};
pub use transport_hub::{wrap_relay_envelope, HubStunSocket, TransportHub};
