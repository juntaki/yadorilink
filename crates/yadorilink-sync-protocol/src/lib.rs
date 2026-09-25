//! `YadoriSyncProtocol`: reconciliation, bundle transfer, and the session
//! that drives them.

mod error;
pub mod ports;
pub mod session;
pub mod single_flight;
pub mod wire;

pub use error::{ProtocolError, WireError};
pub use ports::{BaseVerdict, GroupId, PeerKey, PortError, ReplicaPort};
pub use session::{
    reconcile, request_bundles, serve_bundles, ReconcileOutcome, Reconciled, Role, SessionConfig,
};
pub use single_flight::{Flight, SharedSingleFlight, SingleFlight};
pub use wire::{OpaqueBundle, PROTOCOL_VERSION};
