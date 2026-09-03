//! Pure replica-engine policy: DAG-driven change admission, causal
//! authorization, custody/durability evidence checks, and deterministic
//! conflict-repair election -- extracted out of `yadorilink-sync-core`
//! (Phase 7D-3) into a standalone crate with zero I/O, SQL, wire, or async
//! runtime dependency.
//!
//! Depends only on `yadorilink-replica-domain`. Storage/filesystem-coupled
//! code (`SyncState`, `dag_store`, `materialization`) stays in
//! `yadorilink-sync-core`, which implements this crate's 4 ports
//! ([`ports::ReplicaHistoryPort`], [`ports::ChangeAdmissionPort`],
//! [`ports::FrontierStorePort`], [`ports::DurabilityEvidencePort`]) as thin
//! adapters over its own storage.

pub mod authenticated_history;
pub mod change_ops;
pub mod compaction;
pub mod conflict;
pub mod conflict_authoring;
pub mod custody;
mod engine;
pub mod error;
pub mod handoff_lease;
pub mod optimistic_placement;
pub mod outcomes;
pub mod ports;
pub mod rebootstrap;
pub mod rebootstrap_snapshot;
pub mod repair_election;
pub mod resolution_planning;
pub mod retained_obligation;

use std::sync::Arc;

pub use engine::{AntiEntropyPage, DurableVersionQuery, PeerReplicaEngine};
pub use ports::{
    ChangeAdmissionPort, DurabilityEvidencePort, FrontierStorePort, ReplicaHistoryPort,
};

/// `PeerReplicaEngine`'s 4 port dependencies, held as one bundle so its own
/// constructor takes a single argument rather than 4 positional `Arc`s.
pub struct ReplicaEngineDependencies {
    pub history: Arc<dyn ReplicaHistoryPort>,
    pub admission: Arc<dyn ChangeAdmissionPort>,
    pub frontier: Arc<dyn FrontierStorePort>,
    pub durability: Arc<dyn DurabilityEvidencePort>,
}
