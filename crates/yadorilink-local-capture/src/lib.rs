//! Bridges a raw local filesystem event into an indexed, chunked
//! `FileRecord` — `LocalChangeProcessor` and the disk-reconcile/debounce-
//! flush machinery around it.
//!
//! Moved out of `yadorilink-sync-core` in Phase 7D-8.6
//! (`docs/design/phase7d8-local-change-boundary-ledger.md`), the last
//! sub-phase of that ledger: every other piece of `local_change.rs`'s
//! dependency surface was already a port, already extracted, or (at the
//! time, for `yadorilink-sync-core::root_identity::VerifiedRoot`) confirmed
//! a permanent, minimal leaf dependency before this move — see the ledger's
//! "7D-8.4 finding (resolved)". Phase 7D-9B subsequently moved
//! `root_identity.rs` itself to `yadorilink-root-authority`
//! (`docs/design/phase7d9-dependency-plan.md`), which this crate already
//! depended on, so `VerifiedRoot` is reached from there now.
//!
//! Like `yadorilink-peer-session` (Phase 7D-6), this crate ended up with
//! zero dependency on `yadorilink-sync-core`: Phase 7D-10's final deletion
//! pass moved `debounce::DebounceFlush`/`watcher::{FsChangeEvent,
//! FsChangeKind}`/`chunker::write_placeholder`/`change::PolicyUnavailable`/
//! `dag_import`'s constant to their real homes in `yadorilink-filesystem-sync`/
//! `yadorilink-local-storage`/`yadorilink-replica-domain` across earlier
//! 7D-9/7D-10 sub-phases, and deleted this crate's own test-only
//! `impl LocalMutationStore for SyncState` (`ports::local_mutation`)
//! outright once `yadorilink-daemon`'s `ReplicaCoordinator` had grown the
//! real, production-backed equivalent. This crate's own `tests/` (external)
//! fixtures build a `ReplicaCoordinator` directly via a dev-only back-edge
//! onto `yadorilink-daemon`; this crate's own internal `#[cfg(test)]` code
//! (in `local_change.rs`/`ports/local_mutation.rs`) goes through
//! `test_support::TestReplica` instead -- see that module's own doc comment
//! for why a bare `ReplicaCoordinator` does not compile there.

pub mod error;
pub mod local_change;
pub mod ports;
#[cfg(test)]
pub(crate) mod test_support;

pub use error::LocalCaptureError;
pub use local_change::{FlushOutcome, LocalChangeOutcome, LocalChangeProcessor};
