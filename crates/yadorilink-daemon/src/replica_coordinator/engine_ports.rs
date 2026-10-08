//! The implementation of `yadorilink-replica-engine`'s durability evidence
//! port over `ReplicaCoordinator`, used to build a `PeerReplicaEngine` at
//! the daemon's own composition root (`peer_orchestrator.rs`).

use std::sync::Arc;

use yadorilink_local_storage::BlockContentStore;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_replica_engine::ports::{
    DurabilityEvidencePort, DurabilityRoot, ReplicaRetentionPolicy,
};
use yadorilink_replica_engine::{PeerReplicaEngine, ReplicaEngineDependencies};

use super::ReplicaCoordinator;

fn storage_err(error: PeerSessionError) -> ReplicaEngineError {
    ReplicaEngineError::Storage(error.to_string())
}

/// `DurabilityEvidencePort` needs both replica state and
/// `BlockContentStore` -- no single existing type owns both, so this is a
/// small adapter, the same shape as peer-session's own (now test-only)
/// `DurabilityEvidenceAdapter`, but built directly against
/// `ReplicaCoordinator` rather than `Arc<crate::replica_coordinator::ReplicaCoordinator>`.
pub struct DurabilityEvidenceAdapter {
    pub coordinator: Arc<ReplicaCoordinator>,
    pub store: Arc<dyn BlockContentStore>,
}

impl DurabilityEvidencePort for DurabilityEvidenceAdapter {
    fn retention_policy(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<ReplicaRetentionPolicy>, ReplicaEngineError> {
        Ok(self
            .coordinator
            .link_repository()
            .materialization_policy_for_group(group.as_str())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)?
            .map(|policy| match policy {
                MaterializationPolicy::Eager => ReplicaRetentionPolicy::Eager,
                MaterializationPolicy::OnDemand => ReplicaRetentionPolicy::OnDemand,
            }))
    }

    fn current_root(
        &self,
        group: &FolderGroupId,
        path: &yadorilink_replica_domain::ids::SyncPath,
    ) -> Result<Option<DurabilityRoot>, ReplicaEngineError> {
        Ok(self
            .coordinator
            .sqlite()
            .dag_get_current_version_record(group.as_str(), path.as_str())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)?
            .map(|record| DurabilityRoot {
                deleted: record.deleted,
                version: record.to_file_version(),
            }))
    }

    fn retained_roots(
        &self,
        group: &FolderGroupId,
        path: &yadorilink_replica_domain::ids::SyncPath,
    ) -> Result<Vec<DurabilityRoot>, ReplicaEngineError> {
        Ok(self
            .coordinator
            .sqlite()
            .dag_list_versions(group.as_str(), path.as_str())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)?
            .into_iter()
            .map(|record| DurabilityRoot {
                deleted: record.deleted,
                version: FileVersion::from_index_row(
                    record.blocks,
                    record.size,
                    record.mtime_unix_nanos,
                    record.record_kind,
                    record.unix_mode,
                    record.symlink_target,
                    record.xattrs,
                ),
            })
            .collect())
    }

    fn has_block_provenance(
        &self,
        group: &FolderGroupId,
        block: &BlockHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.coordinator
            .sqlite()
            .dag_group_has_block_provenance(group.as_str(), &block.0)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn root_set_summary(
        &self,
        group: &FolderGroupId,
    ) -> Result<yadorilink_replica_domain::session_state::RootSetSummary, ReplicaEngineError> {
        self.coordinator
            .file_index_repository()
            .group_root_set_summary(group.as_str())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn verify_block(&self, block: &BlockHash) -> Result<(), ReplicaEngineError> {
        // Full read and re-hash, not an existence check -- see
        // `PeerReplicaEngine::holds_version_durably`'s step 6. Attributed
        // so this cost shows up as custody evidence rather than as an
        // anonymous block read.
        let _reads = yadorilink_local_storage::io_diag::attribute_reads(
            yadorilink_local_storage::io_diag::ReadReason::CustodyEvidence,
        );
        self.store
            .get(&hex::encode(&block.0))
            .map(|_| ())
            .map_err(|error| ReplicaEngineError::Storage(error.to_string()))
    }
}

/// Builds the `PeerReplicaEngine` a `PeerSyncSession` needs, directly
/// against `ReplicaCoordinator` and `store` -- the one construction site
/// for it in real (non-fake) code, shared by the daemon's own composition
/// root (`peer_orchestrator.rs`) and every daemon test that constructs a
/// real `PeerSyncSession` over a real `ReplicaCoordinator`.
pub fn build_peer_replica_engine(
    coordinator: &Arc<ReplicaCoordinator>,
    store: Arc<dyn BlockContentStore>,
) -> PeerReplicaEngine {
    PeerReplicaEngine::new(ReplicaEngineDependencies {
        durability: Arc::new(DurabilityEvidenceAdapter { coordinator: coordinator.clone(), store }),
    })
}
