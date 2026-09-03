//! Real filesystem execution: the platform-level commit adapter that
//! atomically swaps a prepared replacement into a live filesystem location.
//!
//! Split out of `yadorilink-sync-core` in Phase 7D-9B
//! (`docs/design/phase7d9-dependency-plan.md`'s 7D-9B routing rules): this
//! crate is the home for real file operations/probes/commit execution,
//! distinct from `yadorilink-root-authority` (authority tokens/leases/
//! permits/root identity, which this crate depends on for its filesystem-
//! capability and identity-comparison primitives) and
//! `yadorilink-local-storage` (content-addressed block store).
//!
//! No new error type: every fallible path here already used
//! `yadorilink_sync_core::SyncError` only via its `ReservedNamespaceCollision`
//! variant (everything else was `std::io::Error` or a module-local error
//! enum) -- `yadorilink_root_authority::RootAuthorityError`, which this
//! crate already depends on for `fs_capabilities`/`fs_identity`/
//! `reserved_namespace`, carries an identical variant, so call sites were
//! repointed at that instead of standing up a redundant wrapping type.

pub mod block_deletion;
pub mod block_liveness;
pub mod debounce;
pub mod materialization_eviction;
pub mod materialization_execution;
pub mod materialization_repair;
pub mod materialization_types;
pub mod placeholder_backend;
pub mod stale_temp_files;
pub mod watcher;
