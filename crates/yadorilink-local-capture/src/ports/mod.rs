//! `LocalMutationStore` — the capability surface `LocalChangeProcessor`
//! needs from a replica-state type, moved here from
//! `yadorilink-sync-core::ports::local_mutation` in Phase 7D-8.6.
//!
//! `BlockContentStore` (the other port `LocalChangeProcessor` consumes)
//! stays defined in `yadorilink-local-storage`, re-exported here for this
//! crate's own callers, mirroring `yadorilink-sync-core::ports::mod`'s own
//! identical re-export before this move.
//!
//! `LocalMutationStore`'s implementation lived here too, for `SyncState`,
//! until Phase 7D-10's final sync-core deletion pass: `yadorilink-daemon`'s
//! `ReplicaCoordinator` had grown its own equivalent impl
//! (`yadorilink-daemon/src/replica_coordinator/local_mutation.rs`) with real
//! production callers, while this crate's own `impl ... for SyncState` had
//! none (test-only, `#[cfg(any(test, feature = "test-support"))]`) -- so it
//! was deleted outright rather than repointed, and this crate now has no
//! dependency on `yadorilink-sync-core` at all, in either production code or
//! its own tests (which build a `ReplicaCoordinator` via a dev-only
//! back-edge onto `yadorilink-daemon` instead -- see this crate's Cargo.toml).

mod local_mutation;

pub use local_mutation::{LocalChangeEmission, LocalMutationStore};
pub use yadorilink_local_storage::BlockContentStore;
