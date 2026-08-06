//! The 4 narrow ports `PeerReplicaEngine` depends on. Each port owns only
//! the operations its own use case needs -- not a wholesale trait-ification
//! of `yadorilink-sync-core`'s own storage API. `yadorilink-sync-core`
//! implements every one of these for its own `SyncState`/`dag_store`/
//! `index` machinery; this crate never depends back on any of that.

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{
    BlockHash, ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
};

use crate::error::{AdmissionStoreError, ReplicaEngineError};

/// Read-only access to the retained change-history DAG: parent edges,
/// encoded bytes, group heads, and the missing-ancestor-frontier
/// computation every hold/orphan path needs.
pub trait ReplicaHistoryPort: Send + Sync {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError>;

    fn encoded_change(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, ReplicaEngineError>;

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError>;

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError>;

    fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError>;

    fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError>;

    fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError>;
}

/// Admits an already-authenticated, causally-monotonic change into the DAG
/// as durable-but-not-yet-projected. `false` (never project inline) is not
/// a caller-chosen parameter here -- `PeerReplicaEngine`'s own use case
/// always admits unprojected, so the port API never exposes that choice.
pub trait ChangeAdmissionPort: Send + Sync {
    fn admit_unprojected_change(
        &self,
        change: &Change,
        versions: &[FileVersion],
    ) -> Result<AdmissionStoreResult, AdmissionStoreError>;
}

pub struct AdmissionStoreResult {
    pub outcome: AdmissionStoreOutcome,
    pub newly_admitted: Vec<ChangeHash>,
}

pub enum AdmissionStoreOutcome {
    Applied,
    Orphaned,
}

/// Records a peer's (or this device's own) acknowledged frontier for a
/// group. Recording failure is best-effort at every call site -- see
/// `PeerReplicaEngine::record_frontier_and_find_missing`'s own doc comment
/// for why a missed update only costs a delayed compaction opportunity,
/// never a correctness issue.
pub trait FrontierStorePort: Send + Sync {
    fn record_acknowledged_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError>;
}

/// This device's retention policy for a group -- the durability-evidence
/// equivalent of `yadorilink_replica_domain::session_state::MaterializationPolicy`,
/// deliberately a distinct type (not re-exported) so this crate never
/// depends on `yadorilink-sync-core`'s own storage-representation enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaRetentionPolicy {
    Eager,
    OnDemand,
}

/// One version this device durably holds at a path -- content identity and
/// tombstone status only, never a raw storage row (no `version_seq`, no DB
/// `state` string, no separately-carried metadata columns). `FileVersion`
/// alone already carries every field its own `compute_hash()` needs, so a
/// caller can always recompute the identity this snapshot claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurabilityRoot {
    pub version: FileVersion,
    pub deleted: bool,
}

/// Evidence this device can offer that it durably, verifiably holds
/// specific file content -- the read surface `PeerReplicaEngine::
/// holds_version_durably` needs, and nothing about how that evidence is
/// stored.
pub trait DurabilityEvidencePort: Send + Sync {
    fn retention_policy(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<ReplicaRetentionPolicy>, ReplicaEngineError>;

    fn current_root(
        &self,
        group: &FolderGroupId,
        path: &SyncPath,
    ) -> Result<Option<DurabilityRoot>, ReplicaEngineError>;

    fn retained_roots(
        &self,
        group: &FolderGroupId,
        path: &SyncPath,
    ) -> Result<Vec<DurabilityRoot>, ReplicaEngineError>;

    fn has_block_provenance(
        &self,
        group: &FolderGroupId,
        block: &BlockHash,
    ) -> Result<bool, ReplicaEngineError>;

    /// Full checksum verification of one block's content -- `Ok(())` only
    /// if the block is present and its bytes re-hash to `block`. Never
    /// merely an existence check (see `PeerReplicaEngine::
    /// holds_version_durably`'s own doc comment on why a corrupt/truncated
    /// block must answer "not held").
    fn verify_block(&self, block: &BlockHash) -> Result<(), ReplicaEngineError>;
}
