//! WireGuard mesh transport.
//!
//! Layering, outer to inner:
//! - [`peer_channel::PeerChannel`]: the interface `yadorilink-sync-core`
//!   talks to. Sync data travels only over direct peer-to-peer paths this
//!   device establishes itself; a peer with no workable candidate is
//!   reported [`peer_channel::PeerReachability::Unreachable`], never routed
//!   through any operator-run server.
//! - direct UDP send/recv and candidate racing, driven from within
//!   `peer_channel`'s actor.
//! - [`tunn_wrapper::WgTunnel`]: real WireGuard encryption/handshake via
//!   `boringtun`, adapted from an IP-tunnel API to a message channel via
//!   [`framing`].

mod error;
mod framing;
mod key_secret_store;
mod keys;
mod local_candidates;
mod local_discovery;
pub mod nat;
mod peer_channel;
mod reliable;
mod supervise;
// The handshake ingress worker intentionally shares a bounded mpsc receiver
// behind Arc<tokio::sync::Mutex<_>> so a fixed worker pool can drain one
// queue without duplicating ownership. Keep the concrete type visible at the
// implementation seam; only suppress Clippy's cosmetic complexity warning.
#[allow(clippy::type_complexity)]
mod transport_hub;
mod tunn_wrapper;
mod udp_batching;

pub use error::TransportError;
pub use keys::{
    public_key_from_bytes, verifying_key_from_bytes, DeviceKeyPair, DeviceSigningKeyPair,
    KeyLoadError,
};
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
    diff_netmap, NetmapDiff, NetmapSnapshot, PeerChannel, PeerReachability, RelayCarrier,
    UnreachableCategory,
};
pub use transport_hub::{
    wrap_relay_envelope, DatagramKind, HubStunSocket, InboundDatagram, TransportHub,
};
pub use tunn_wrapper::{IncomingResult, WireGuardEngine};
