//! Adapters implementing `yadorilink-replica-engine`'s 4 narrow ports
//! (`ReplicaHistoryPort`, `ChangeAdmissionPort`, `FrontierStorePort`,
//! `DurabilityEvidencePort`) over this crate's own `PeerReplicaStatePort`/
//! `BlockContentStore`. `PeerReplicaEngine` (in `yadorilink-replica-engine`)
//! depends only on these traits; this module is where its storage-coupled
//! implementation actually lives.
//!
//! `PeerReplicaStateAdapter` wraps `Arc<dyn PeerReplicaStatePort>` (what
//! `PeerSyncSession` actually holds, for testability -- tests substitute a
//! mock) rather than a blanket `impl<T: PeerReplicaStatePort> ... for T`:
//! Rust's orphan rule refuses `impl<T: LocalTrait> ForeignTrait for T`
//! (E0210, "only traits defined in the current crate can be implemented
//! for a type parameter") -- the same reasoning that forced
//! `authenticated_history_bridge.rs`'s `ChangeAuthenticatorTrust` newtype
//! in Phase 7D-3.2.

use std::sync::Arc;

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{BlockHash, ChangeHash, DeviceId, FolderGroupId, VersionHash};
use yadorilink_replica_engine::error::{AdmissionStoreError, ReplicaEngineError};
use yadorilink_replica_engine::ports::{
    AdmissionStoreOutcome, AdmissionStoreResult, ChangeAdmissionPort, DurabilityEvidencePort,
    DurabilityRoot, FrontierStorePort, ReplicaHistoryPort, ReplicaRetentionPolicy,
};

use crate::ports::PeerReplicaStatePort;
use crate::PeerSessionError;
use yadorilink_replica_domain::admission::AdmitOutcome;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

use yadorilink_local_storage::BlockContentStore;

fn storage_err(error: PeerSessionError) -> ReplicaEngineError {
    ReplicaEngineError::Storage(error.to_string())
}

/// Wraps `Arc<dyn PeerReplicaStatePort>` -- see this module's own doc
/// comment for why a blanket impl over the trait directly is illegal.
#[derive(Clone)]
pub struct PeerReplicaStateAdapter(pub Arc<dyn PeerReplicaStatePort>);

impl ReplicaHistoryPort for PeerReplicaStateAdapter {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.0.dag_parents_of(hash).map_err(storage_err)
    }

    fn encoded_change(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, ReplicaEngineError> {
        self.0.dag_get_encoded(hash).map_err(storage_err)
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        self.0.dag_get_change(hash).map_err(storage_err)
    }

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.0.dag_group_heads(group.as_str()).map_err(storage_err)
    }

    fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.0.dag_missing_ancestor_frontier(roots.to_vec()).map_err(storage_err)
    }

    fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.0.dag_has_file_version(group.as_str(), hash).map_err(storage_err)
    }

    fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError> {
        self.0.dag_get_file_version(group.as_str(), hash).map_err(storage_err)
    }
}

impl ChangeAdmissionPort for PeerReplicaStateAdapter {
    fn admit_unprojected_change(
        &self,
        change: &Change,
        versions: &[FileVersion],
    ) -> Result<AdmissionStoreResult, AdmissionStoreError> {
        match self.0.dag_admit_change_with_versions(change, versions, false) {
            Ok(result) => Ok(AdmissionStoreResult {
                outcome: match result.outcome {
                    AdmitOutcome::Applied => AdmissionStoreOutcome::Applied,
                    AdmitOutcome::Orphaned => AdmissionStoreOutcome::Orphaned,
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
    }

    fn admit_unprojected_change_batch(
        &self,
        items: &[(&Change, &[FileVersion])],
    ) -> Vec<Result<AdmissionStoreResult, AdmissionStoreError>> {
        let port_items: Vec<(&Change, &[FileVersion], bool)> =
            items.iter().map(|(change, versions)| (*change, *versions, false)).collect();
        self.0
            .dag_admit_change_batch_with_versions(&port_items)
            .into_iter()
            .map(|result| match result {
                Ok(result) => Ok(AdmissionStoreResult {
                    outcome: match result.outcome {
                        AdmitOutcome::Applied => AdmissionStoreOutcome::Applied,
                        AdmitOutcome::Orphaned => AdmissionStoreOutcome::Orphaned,
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
            })
            .collect()
    }
}

impl FrontierStorePort for PeerReplicaStateAdapter {
    fn record_acknowledged_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        self.0.record_acknowledged_frontier(group, device, frontier).map_err(storage_err)
    }
}

/// `DurabilityEvidencePort` needs both replica state (retention policy,
/// retained/current version rows, block provenance) and `BlockContentStore`
/// (full checksum verification) -- no single existing type owns both, so
/// this is a small adapter struct rather than a third blanket `impl`.
pub struct DurabilityEvidenceAdapter {
    pub state: Arc<dyn PeerReplicaStatePort>,
    pub store: Arc<dyn BlockContentStore>,
}

impl DurabilityEvidencePort for DurabilityEvidenceAdapter {
    fn retention_policy(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<ReplicaRetentionPolicy>, ReplicaEngineError> {
        Ok(self.state.materialization_policy_for_group(group.as_str()).map_err(storage_err)?.map(
            |policy| match policy {
                MaterializationPolicy::Eager => ReplicaRetentionPolicy::Eager,
                MaterializationPolicy::OnDemand => ReplicaRetentionPolicy::OnDemand,
            },
        ))
    }

    fn current_root(
        &self,
        group: &FolderGroupId,
        path: &yadorilink_replica_domain::ids::SyncPath,
    ) -> Result<Option<DurabilityRoot>, ReplicaEngineError> {
        Ok(self
            .state
            .get_current_version_record(group.as_str(), path.as_str())
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
            .state
            .list_versions(group.as_str(), path.as_str())
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
        self.state.group_has_block_provenance(group.as_str(), &block.0).map_err(storage_err)
    }

    fn verify_block(&self, block: &BlockHash) -> Result<(), ReplicaEngineError> {
        self.store
            .get(&hex::encode(&block.0))
            .map(|_| ())
            .map_err(|error| ReplicaEngineError::Storage(error.to_string()))
    }
}
