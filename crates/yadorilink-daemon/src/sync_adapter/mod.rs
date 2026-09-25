//! Binding `YadoriSyncProtocol` to this device's storage and policy.
//!
//! The protocol crate moves bytes and compares sets, and knows nothing about
//! Changes, signatures, checkpoints or SQLite. Everything it needs from the
//! replica arrives through this adapter, which is therefore the one place
//! where a sync session touches authorization at all.

pub mod address_directory;
mod admission;
pub mod async_store;
pub mod bundle_codec;
mod daemon_directory;
pub mod foreign_base;
pub mod metrics;

pub mod driver;
mod replica_port;
pub mod sync_stack;
pub mod verify;

#[cfg(test)]
mod accept_hook_tests;
#[cfg(test)]
mod async_store_tests;
#[cfg(test)]
mod base_negotiation_tests;
#[cfg(test)]
mod driver_tests;
#[cfg(test)]
mod planner_tests;
#[cfg(test)]
mod relay_block_transfer_tests;
#[cfg(test)]
mod relay_equivalence_tests;
#[cfg(test)]
mod relay_to_direct_path_evolution_tests;

/// The stack on a simulated carrier, under a partition. Only built for the
/// turmoil simulation cfg, which is the only build that has a carrier to cut.
#[cfg(test)]
mod local_capture_tests;
#[cfg(test)]
mod sync_stack_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod turmoil_partition_tests;

pub use admission::{AdmissionCoordinator, DrainOutcome};
pub use async_store::{AsyncReplicaStore, StoreError, StoreLimits, StoreMetrics};
pub use daemon_directory::DaemonPeerDirectory;
// The lane adapters live in `yadorilink-lane-ports` so that anything building
// a `PeerSyncSession` -- this crate or a fixture below it -- constructs the
// same real transports. Re-exported here because every existing caller in
// this crate names them through `sync_adapter`.
pub use driver::{ReconciliationDriver, Wake};
pub use replica_port::SqliteReplicaPort;
pub use sync_stack::{SyncStack, SyncStackError};
pub use yadorilink_lane_ports::{
    serve_snapshot_stream, LaneBlockStream, LaneServiceStream, LaneSnapshotFetch, PeerDirectory,
    PeerLinkSource, PeerTransports, PreparedSnapshots, StaticPeerDirectory,
    MAX_SERVICE_MESSAGE_BYTES,
};
/// Re-exported so a caller configuring a stack does not have to depend on the
/// substrate crate directly -- this module is the seam, and naming iroh above
/// it is what the substrate boundary exists to prevent.
pub use yadorilink_sync_substrate::NetworkConfig;
