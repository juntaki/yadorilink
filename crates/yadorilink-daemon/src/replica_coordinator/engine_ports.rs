//! Direct implementations of `yadorilink-replica-engine`'s four narrow
//! ports for `ReplicaCoordinator`, used to build a `PeerReplicaEngine` at
//! the daemon's own composition root (`peer_orchestrator.rs`).
//! `ReplicaCoordinator` is a concrete daemon type, so it implements these
//! foreign traits directly, with no wrapper and no dynamic dispatch
//! through an intermediate `Arc<dyn ...>`.
//!
//! Each method here goes to `ReplicaCoordinator`'s own repositories.

use std::sync::Arc;

use yadorilink_local_storage::BlockContentStore;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::admission::{AdmitOutcome, PathRefusal};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{BlockHash, ChangeHash, DeviceId, FolderGroupId, VersionHash};
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_engine::error::{AdmissionStoreError, ReplicaEngineError};
use yadorilink_replica_engine::ports::{
    AdmissionStoreOutcome, AdmissionStoreResult, ChangeAdmissionPort, ChangeEvidence,
    DurabilityEvidencePort, DurabilityRoot, FrontierStorePort, ReplicaHistoryPort,
    ReplicaRetentionPolicy,
};
use yadorilink_replica_engine::{PeerReplicaEngine, ReplicaEngineDependencies};

use super::ReplicaCoordinator;

fn storage_err(error: PeerSessionError) -> ReplicaEngineError {
    ReplicaEngineError::Storage(error.to_string())
}

impl ReplicaHistoryPort for ReplicaCoordinator {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite()
            .dag_parents_of(hash)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        self.sqlite()
            .dag_published_change(hash)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite()
            .dag_published_group_heads(group.as_str())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.sqlite()
            .dag_missing_ancestor_frontier(roots.to_vec())
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.sqlite()
            .dag_has_file_version(group.as_str(), hash)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }

    fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError> {
        self.sqlite()
            .dag_get_file_version(group.as_str(), hash)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
            .map_err(storage_err)
    }
}

impl ChangeAdmissionPort for ReplicaCoordinator {
    fn admit_unprojected_change(
        &self,
        change: &Change,
        versions: &[FileVersion],
        evidence: &ChangeEvidence,
    ) -> Result<AdmissionStoreResult, AdmissionStoreError> {
        self.admit_unprojected_change_batch(&[(change, versions, evidence)]).remove(0)
    }

    fn admit_unprojected_change_batch(
        &self,
        items: &[(&Change, &[FileVersion], &ChangeEvidence)],
    ) -> Vec<Result<AdmissionStoreResult, AdmissionStoreError>> {
        let pending: Vec<yadorilink_sync_sqlite::PendingAdmission<'_>> = items
            .iter()
            .map(|(change, versions, evidence)| yadorilink_sync_sqlite::PendingAdmission {
                change,
                versions,
                evidence: Some(evidence),
            })
            .collect();
        self.change_history_repository()
            .dag_admit_change_batch_with_versions(&pending)
            .into_iter()
            .map(|r| r.map_err(crate::sync_error::SyncError::from).map_err(PeerSessionError::from))
            .map(|result| {
                match result {
                Ok(result) => Ok(AdmissionStoreResult {
                    outcome: match result.outcome {
                        AdmitOutcome::Applied => AdmissionStoreOutcome::Applied,
                        AdmitOutcome::Orphaned => AdmissionStoreOutcome::Orphaned,
                        AdmitOutcome::RefusedAuthorChain(refusal) => {
                            AdmissionStoreOutcome::RefusedAuthorChain {
                                reason: refusal.to_string(),
                            }
                        }
                        AdmitOutcome::RefusedForeignHistoryBase { local, incoming } => {
                            AdmissionStoreOutcome::RefusedForeignHistoryBase {
                                reason: yadorilink_replica_domain::admission::AdmissionRefusal::
                                    ForeignHistoryBase { local, incoming }
                                    .to_string(),
                            }
                        }
                        // Comes back from the store as an outcome so that
                        // the transaction carrying its durable record
                        // commits. The engine reports it as the permanent
                        // rejection it is.
                        AdmitOutcome::RefusedBehindRejectedParent { parent } => {
                            AdmissionStoreOutcome::RefusedBehindRejectedParent {
                                reason: yadorilink_replica_domain::admission::AdmissionRefusal::
                                    BehindRejectedParent { parent }
                                    .to_string(),
                            }
                        }
                        AdmitOutcome::RefusedPath(PathRefusal::ReservedNamespaceCollision {
                            path,
                        }) => return Err(AdmissionStoreError::ReservedNamespaceCollision { path }),
                        AdmitOutcome::RefusedPath(PathRefusal::NonPortablePath { path }) => {
                            return Err(AdmissionStoreError::NonPortablePath { path })
                        }
                    },
                    newly_admitted: result.newly_admitted,
                }),
                Err(PeerSessionError::ReservedNamespaceCollision(path)) => {
                    Err(AdmissionStoreError::ReservedNamespaceCollision { path })
                }
                Err(PeerSessionError::NonPortablePath(path)) => {
                    Err(AdmissionStoreError::NonPortablePath { path })
                }
                Err(error) => Err(AdmissionStoreError::Other(error.to_string())),
            }
            })
            .collect()
    }
}

impl FrontierStorePort for ReplicaCoordinator {
    fn record_acknowledged_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        yadorilink_replica_engine::compaction::record_acknowledged_frontier(
            self, group, device, frontier,
        )
    }
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
        history: coordinator.clone(),
        admission: coordinator.clone(),
        frontier: coordinator.clone(),
        durability: Arc::new(DurabilityEvidenceAdapter { coordinator: coordinator.clone(), store }),
    })
}
