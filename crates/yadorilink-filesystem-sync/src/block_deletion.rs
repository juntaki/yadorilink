//! Mark-and-sweep physical block-store GC, split out of
//! `yadorilink-sync-core`'s `block_deletion.rs` in Phase 7D-9C.
//!
//! `BlockDeletionCoordinator` originally held two methods: `sweep` (this
//! function) and `reclaim_cached_blocks` (stays in sync-core — it needs
//! `&dyn crate::ports::MaterializationStatePort`, a trait definition that
//! has not itself left sync-core yet). `sweep` has no such dependency: it
//! only ever calls through `&dyn BlockReclamationStore` (already owned by
//! `yadorilink-local-storage`, re-exported from `yadorilink-sync-core::ports`
//! only for convenience) and returns exactly what that trait's own `sweep`
//! method returns, so it moves independently, without waiting on the port
//! split.
//!
//! `sweep`'s original signature took a `BlockDeletionReason` enum and
//! refused any value but `GloballyUnreferenced` with a `SyncError::
//! InvalidInput` at runtime. A workspace-wide grep before this move found
//! `BlockDeletionReason::CorruptBlock` (the enum's only other variant) is
//! never constructed anywhere — not in production code, not in any test —
//! so the guard existed to gate a value nothing has ever passed. Moving
//! this function to a crate that must not depend on `yadorilink-sync-core`'s
//! `SyncError` for the sole purpose of preserving a guard against a dead
//! enum variant would mean either inventing a new error type just for this,
//! or leaving the function returning the wrong crate's error type. Neither
//! is warranted: the `reason` parameter and `BlockDeletionReason` are
//! dropped here rather than carried forward, and this function returns
//! `yadorilink_local_storage::StorageError` directly — the same type
//! `BlockReclamationStore::sweep` itself already returns, with no
//! conversion needed. The one real call site (`yadorilink-daemon`'s
//! `gc.rs::run_sweep_sync`) already immediately `.map_err(|e|
//! GcTriggerError::Failed(e.to_string()))`s the result, so this is not a
//! caller-visible behavior change.

use std::collections::HashSet;
use std::time::SystemTime;

use yadorilink_local_storage::{BlockReclamationStore, ContentHash, GcReport, StorageError};

use crate::block_liveness::BlockPhysicalDeletionGuard;

/// Deletes every block in `store` not present in `live` and older than
/// `grace_cutoff`, guarded by `guard` (proof no in-flight materialization
/// write can be reading a block concurrently — see
/// `BlockLivenessGate::begin_physical_deletion`'s own doc comment). A
/// `dry_run` sweep reports what it would delete without deleting anything.
pub fn sweep_globally_unreferenced_blocks(
    _guard: &BlockPhysicalDeletionGuard<'_>,
    store: &dyn BlockReclamationStore,
    live: &HashSet<ContentHash>,
    grace_cutoff: SystemTime,
    dry_run: bool,
) -> Result<GcReport, StorageError> {
    store.sweep(live, grace_cutoff, dry_run)
}
