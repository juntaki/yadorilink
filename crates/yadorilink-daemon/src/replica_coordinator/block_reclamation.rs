//! Physical content-addressed block *reclamation*: custody-scoped deletion
//! of the blocks an eviction freed. Owned by `ReplicaCoordinator` because
//! the decision is a read across the file index, the materialization state
//! and the block-reference set, all of which this type already holds.

use yadorilink_filesystem_sync::block_liveness::BlockPhysicalDeletionGuard;
use yadorilink_local_storage::{BlockReclamationStore, GcReport};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::VerifiedCustody;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::ReplicaCoordinator;

impl ReplicaCoordinator {
    /// Reclaims the cached blocks of a path whose eviction custody has been
    /// verified. The caller must already hold the exclusive
    /// `BlockPhysicalDeletionGuard`; every safety-relevant re-check (the
    /// custody's exact version, pin and materialization state, the custody
    /// confirmation itself, and the cross-row reference set) runs here,
    /// under that guard, in this order.
    pub(crate) fn reclaim_cached_blocks(
        &self,
        _guard: &BlockPhysicalDeletionGuard<'_>,
        custody: VerifiedCustody<'_>,
        store: &dyn BlockReclamationStore,
    ) -> Result<GcReport, SyncSqliteError> {
        let Some(current) =
            self.sqlite().dag_get_current_version_record(custody.group_id(), custody.path())?
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
        if self.file_index_repository().is_pinned(custody.group_id(), custody.path())?
            || self
                .materialization_state_repository()
                .get_materialization_state(custody.group_id(), custody.path())?
                != Some(MaterializationState::Placeholder)
        {
            return Ok(GcReport::default());
        }
        if !custody.confirmation_still_valid() {
            return Ok(GcReport::default());
        }

        let needed = self
            .materialization_state_repository()
            .blocks_referenced_outside_current_file(custody.group_id(), custody.path())?;
        let reclaimable: Vec<String> = current
            .blocks
            .iter()
            .map(|block| hex::encode(&block.hash.0))
            .filter(|hash| !needed.contains(hash))
            .collect();
        Ok(store.reclaim_cached_blocks(&reclaimable)?)
    }
}
