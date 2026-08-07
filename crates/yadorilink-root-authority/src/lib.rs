//! The root-mutation capability every daemon-originated local
//! filesystem/index/DAG/materialization-state write must hold
//! ([`root_commit::RootLease`]/[`root_commit::RootCommitPermit`]), backed
//! by an OS-level advisory exclusive lock on the sync root
//! ([`sync_root_lock::SyncRootLock`]), the filesystem-identity comparisons
//! that detect a root being replaced out from under an active lock
//! ([`fs_identity`]), the OS filesystem-capability probes and reserved
//! on-disk artefact naming that back atomic-commit safety decisions
//! elsewhere in the sync engine ([`fs_capabilities`],
//! [`reserved_namespace`]).
//!
//! Split out of `yadorilink-sync-core` in Phase 7D-6: `PeerSyncSession`
//! (moving to `yadorilink-peer-session`) and `yadorilink-sync-core`'s own
//! local-authoring/materialization/recovery code both need
//! `RootCommitPermit` on their capability-port surfaces, and neither can
//! depend on the other -- see `docs/design/
//! phase7d6-peer-session-extraction-boundary.md`. Unlike Phase 7D-1's DAG
//! admission-outcome types, this is not a pure value type: `RootLease`
//! wraps a real, live `SyncRootLock`, so it could not simply move into
//! `yadorilink-replica-domain`.
//!
//! No SQLite, no daemon-specific coupling: a lease's *lifecycle* (when a
//! link starts/stops/restarts, i.e. when an `Arc<RootLease>` is actually
//! constructed and hands out permits) stays `yadorilink-daemon`'s
//! `link_manager` territory, unchanged by this move -- see
//! [`root_commit`]'s own module doc.

pub mod canonical_fold;
pub mod error;
pub mod fs_capabilities;
pub mod fs_identity;
pub mod ignore_patterns;
pub mod reserved_namespace;
pub mod root_commit;
/// Sync-root identity: proves the directory a scan is about to treat as
/// authoritative is really this link's folder, and not the bare mountpoint an
/// unmounted volume leaves behind. Moved from `yadorilink-sync-core` in
/// Phase 7D-9B -- see its own module doc for the `RootVerificationStatePort`
/// split this move required.
pub mod root_identity;
pub mod sync_root_lock;

pub use error::RootAuthorityError;
