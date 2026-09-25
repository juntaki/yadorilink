//! Networking substrate for `YadoriSyncProtocol`.
//!
//! This crate is the *only* place in the tree that names `iroh` or
//! `p2panda-net` types. Everything above it speaks in terms of [`PeerId`],
//! [`Lane`] and [`PeerLink`], so a pre-1.0 p2panda upgrade is absorbed in one
//! adapter rather than spreading through the domain.
//!
//! Transport identity is *carrier* identity. It determines who we exchanged
//! bytes with and nothing else; it never contributes to a decision about
//! whether a Change may be admitted.

mod address;
mod admission;
mod directory;
mod error;
mod lan;
mod lane;
mod link;
mod network;
mod node;
mod observe;
mod path_witness;
mod peer;
/// Deterministic relay infrastructure for tests. See the module's own doc.
#[cfg(feature = "test-support")]
pub mod testing;
mod track_send;

pub use address::PeerAddress;
#[cfg(feature = "test-support")]
pub use admission::AdmitAnyAuthenticated;
pub use admission::{AdmitNone, AdmitWhen, PeerAdmission};
pub use directory::AddressDirectory;
pub use error::SubstrateError;
pub use lane::{HistoryStreamKind, Lane, LaneLimits};
pub use link::{Carrier, CarrierChanges, LaneRecv, LaneSend, LaneStream, PathWatcher, PeerLink};
pub use network::YadoriNetwork;
pub use node::{is_relay_url, NetworkConfig, SubstrateNode, YADORI_SYNC_ALPN};
pub use observe::{DialFailure, LinkEvent, LinkObserver};
pub use path_witness::{verdict_for, PathBytes, PathKind, PathWitness, TransferVerdict};
pub use peer::PeerId;
pub use track_send::{
    TrackSendConnection, TrackSendConnections, TrackSendReader, TrackSendWriter, YADORI_SEND_ALPN,
};
