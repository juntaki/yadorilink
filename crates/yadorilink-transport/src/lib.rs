//! WireGuard mesh transport (see openspec `p2p-transport` spec, design.md D6).
//!
//! Layering, outer to inner:
//! - [`peer_channel::PeerChannel`]: the transport-path-agnostic interface
//!   `yadorilink-sync-core` talks to (task 4.7).
//! - [`relay_hub::RelayHub`]: one shared relay connection per device
//!   (multiple `PeerChannel`s multiplex over it — see that module for why
//!   a per-peer relay connection doesn't work), wrapping [`relay_client`]
//!   / [`relay_server`], the always-works fallback path, a content-blind
//!   forwarder keyed by WireGuard public key (tasks 4.2, 4.3).
//! - direct UDP send/recv, driven from within `peer_channel`'s actor
//!   (tasks 4.4, 4.5, 4.6).
//! - [`tunn_wrapper::WgTunnel`]: real WireGuard encryption/handshake via
//!   `boringtun`, adapted from an IP-tunnel API to a message channel via
//!   [`framing`] (task 4.1).

mod error;
mod framing;
mod keys;
mod local_candidates;
mod local_discovery;
mod peer_channel;
mod relay_auth;
mod relay_client;
mod relay_hub;
mod relay_io;
pub mod relay_server;
mod reliable;
mod supervise;
mod tunn_wrapper;
mod udp_batching;

pub use error::TransportError;
pub use keys::{public_key_from_bytes, DeviceKeyPair};
pub use local_candidates::{local_candidate_addresses, LOCAL_CANDIDATE_PRIORITY};
pub use local_discovery::{start_local_discovery, PeerAnnouncement};
pub use peer_channel::{
    diff_netmap, NetmapDiff, NetmapSnapshot, PathKind, PeerChannel, TransportMode,
};
pub use relay_hub::RelayHub;
