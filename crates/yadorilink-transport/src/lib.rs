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
//! - [`quic_socket::TransportHubQuicSocket`]: the bridge that drives that
//!   endpoint over the device's one UDP binding.
//! - [`transport_hub::TransportHub`]: that binding and its receive loop.
//!
//! This is not the production peer transport. Peer connectivity -- dialling,
//! NAT traversal, path selection, relay fallback and LAN discovery -- belongs
//! entirely to the iroh endpoint in `yadorilink-sync-substrate`. What this
//! crate still supplies to shipped code is the device signing key pair and
//! its OS keyring storage, the block-stream length framing both transports
//! share, the netmap diff, and `TransportError`. The QUIC endpoint and
//! channel below are kept only as an independent control plane for tests
//! that need a reachability probe which is not the sync path itself.

pub mod block_stream;
mod error;
mod key_secret_store;
mod keys;
mod peer_channel;
pub mod quic_identity;
pub mod quic_peer_channel;
pub mod quic_peer_endpoint;
pub mod quic_socket;
/// Which UDP socket this crate's networking is built on -- the one place
/// the native and turmoil builds differ.
pub mod sim_net;
/// The seeded jitter source a turmoil build draws from. Compiled away
/// entirely in every other build.
pub mod sim_rand;
mod transport_hub;
mod udp_batching;

pub use block_stream::{
    QuicBlockStream, MAX_BLOCK_STREAM_BODY_BYTES, MAX_BLOCK_STREAM_HEADER_BYTES,
};
pub use error::TransportError;
pub use keys::{verifying_key_from_bytes, DeviceSigningKeyPair, KeyLoadError};
pub use peer_channel::{diff_netmap, NetmapDiff, NetmapSnapshot};
pub use quic_identity::{
    device_certified_key, quic_client_config, quic_server_config, AuthorizedPeerKeys,
    PinnedPeerKeys, PEER_SERVER_NAME, YADORILINK_P2P_ALPN,
};
pub use quic_peer_channel::{QuicPeerChannel, MAX_CONTROL_FRAME_BYTES};
pub use quic_peer_endpoint::{connect_role, ConnectRole, QuicPeerEndpoint, PEER_IDLE_TIMEOUT};
pub use quic_socket::{HubQuinnRuntime, TransportHubQuicSocket};
pub use transport_hub::TransportHub;
