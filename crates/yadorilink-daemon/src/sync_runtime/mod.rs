//! In-memory, never-persisted runtime-coordination state owned by
//! `ReplicaCoordinator`: none of these types touch SQLite.
//!
//! This is a verbatim, independent copy of
//! `yadorilink_sync_core::sync_runtime`'s equivalent module (Phase 7D-10.11
//! "temporary coexistence" pattern, matching how `SyncError`, `dag_import.rs`,
//! and `recovery.rs` were each relocated to `yadorilink-daemon` earlier in
//! this initiative). `yadorilink_sync_core::index::SyncState`'s own copy is
//! left untouched: `SyncState` has zero remaining production callers
//! workspace-wide (every live daemon call site now goes through
//! `ReplicaCoordinator`), so its copy is exercised only by that crate's own
//! test suite and other crates' `#[cfg(test)]`/`test-support` fixtures, and
//! will simply disappear when `yadorilink-sync-core` is deleted. Duplicating
//! here (rather than hoisting to a shared lower crate) matches this
//! initiative's established rule: these types are daemon-composition-root
//! owned, the same reasoning already applied to `ReplicaCoordinator` itself.
pub mod materialization_wake;
pub mod path_locks;
pub mod schema;
pub mod startup_readiness;
