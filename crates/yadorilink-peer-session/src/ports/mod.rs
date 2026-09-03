//! Capability-port traits `PeerSyncSession` needs from the runtime that
//! composes it: the SQL-backed replica state (`PeerReplicaStatePort`) and
//! the transport-layer channel to one peer (`PeerMessageChannel`), plus an
//! in-memory implementation of the latter for simulation and tests
//! (`InMemoryPeerChannel`).

#[cfg(any(test, feature = "test-support"))]
mod in_memory_channel;
mod peer_message_channel;
mod peer_replica_state;

#[cfg(any(test, feature = "test-support"))]
pub use in_memory_channel::{InMemoryBlockStream, InMemoryPeerChannel};
pub use peer_message_channel::{PeerBlockStream, PeerMessageChannel};
pub use peer_replica_state::{
    ExactActualState, FinishedProjectedUpsert, MaterializedFingerprint, OpenMaterializationIntent,
    PeerReplicaStatePort, PreparedProjectedDelete, PreparedProjectedUpsert,
};
/// Re-exported (not defined here) so `peer_session.rs`'s existing
/// `crate::ports::BlockContentStore` call sites keep working unchanged
/// after Phase 7D-6's physical move -- same re-export
/// `yadorilink-sync-core`'s own `ports` module makes.
pub use yadorilink_local_storage::BlockContentStore;
