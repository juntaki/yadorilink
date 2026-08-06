//! Physical content-addressed block *reclamation* (custody-scoped deletion
//! of blocks freed by an eviction). Global mark-and-sweep GC (`sweep`, the
//! `BlockDeletionReason` guard) is `yadorilink_filesystem_sync::block_deletion::
//! sweep_globally_unreferenced_blocks` (Phase 7D-9C) -- it had zero
//! dependency on anything in `yadorilink-sync-core` (only `&dyn
//! BlockReclamationStore`, owned by `yadorilink-local-storage`), unlike
//! `reclaim_cached_blocks` below, which needed `&dyn
//! MaterializationStatePort` -- a trait *definition* that stayed in
//! `yadorilink-sync-core` until this file's own move here (Phase 7D-10,
//! alongside the trait's own relocation -- see
//! `docs/design/phase7d10-exit-report.md`'s 2026-08-06 "item 1" addendum).
//! See `sweep_globally_unreferenced_blocks`'s own doc comment for why
//! `BlockDeletionReason` itself did not move forward with it (its only
//! non-default variant is never constructed anywhere in the workspace).

use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::session_state::MaterializationState;
use crate::SyncSqliteError;

pub struct BlockDeletionCoordinator<'a> {
    store: &'a dyn BlockReclamationStore,
}

impl<'a> BlockDeletionCoordinator<'a> {
    pub fn new(store: &'a dyn BlockReclamationStore) -> Self {
        Self { store }
    }

    /// `pub`: `yadorilink-sync-core`'s `impl MaterializationExecutionPort for
    /// SyncState` (`ports/materialization_execution_impl.rs`) and
    /// `yadorilink-daemon`'s `impl MaterializationExecutionPort for
    /// ReplicaCoordinator` (Phase 7D-10.5) both need to call this from
    /// outside this crate -- both `SyncState` and `ReplicaCoordinator` reach
    /// the same coordinator. Widening this one method's visibility does not
    /// weaken anything it protects: the safety-relevant state (custody
    /// revalidation, pin/materialization-state re-check) all happens inside
    /// the method body itself, unchanged.
    pub fn reclaim_cached_blocks(
        &self,
        _guard: &BlockPhysicalDeletionGuard<'_>,
        custody: yadorilink_replica_engine::custody::VerifiedCustody<'_>,
        state: &dyn crate::MaterializationStatePort,
    ) -> Result<GcReport, SyncSqliteError> {
        let Some(current) = state.get_current_version_record(custody.group_id(), custody.path())?
        else {
            return Ok(GcReport::default());
        };
        if current.deleted {
            return Ok(GcReport::default());
        }
        let current = current.to_file_version();
        if current.version_hash != *custody.version_hash() || current.blocks != custody.blocks() {
            return Ok(GcReport::default());
        }
        // Custody confirmation may have waited on the network. Revalidate
        // local retention requirements under the exclusive deletion guard so
        // a concurrent pin or re-hydration cannot be followed by reclaiming
        // the blocks its final state requires.
        if state.is_pinned(custody.group_id(), custody.path())?
            || state.get_materialization_state(custody.group_id(), custody.path())?
                != Some(MaterializationState::Placeholder)
        {
            return Ok(GcReport::default());
        }
        if !custody.confirmation_still_valid() {
            return Ok(GcReport::default());
        }

        let needed =
            state.blocks_referenced_outside_current_file(custody.group_id(), custody.path())?;
        let reclaimable: Vec<String> = current
            .blocks
            .iter()
            .map(|block| hex::encode(&block.hash.0))
            .filter(|hash| !needed.contains(hash))
            .collect();
        Ok(self.store.reclaim_cached_blocks(&reclaimable)?)
    }
}
