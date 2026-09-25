//! The 4 narrow ports `PeerReplicaEngine` depends on.

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{
    BlockHash, ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
};
use yadorilink_replica_domain::session_state::RootSetSummary;

use crate::error::{AdmissionStoreError, ReplicaEngineError};

/// Read-only access to the retained change-history DAG: parent edges,
/// encoded bytes, group heads, and the missing-ancestor-frontier
/// computation every hold/orphan path needs.
pub trait ReplicaHistoryPort: Send + Sync {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError>;

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
/// One remotely-received Change's already-verified `AuthorizationCheckpoint`
/// evidence, storage-agnostic (this crate never depends on
/// `yadorilink-sync-sqlite`) -- converted to
/// `yadorilink_sync_sqlite::dag_store::published_view::PublishedEvidence`
/// only at the daemon's own port-implementation layer. Admission must write the
/// Change and its evidence atomically, in ONE transaction, so a crash
/// never strands a remote Change as an accidental Pending row.
#[derive(Debug, Clone)]
pub struct ChangeEvidence {
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_seq: u64,
    pub checkpoint_encoded: Vec<u8>,
    pub checkpoint_signature: Vec<u8>,
    pub author_signing_public_key: [u8; 32],
    pub merkle_proof_encoded: Vec<u8>,
}

pub trait ChangeAdmissionPort: Send + Sync {
    fn admit_unprojected_change(
        &self,
        change: &Change,
        versions: &[FileVersion],
        evidence: &ChangeEvidence,
    ) -> Result<AdmissionStoreResult, AdmissionStoreError>;

    /// Bounded micro-batch sibling of [`Self::admit_unprojected_change`]:
    /// admits every item in `items`, in order, returning one result per
    /// item in the same order -- see `yadorilink_sync_sqlite::
    /// ChangeHistoryRepository::dag_admit_change_batch_with_versions`'s own
    /// doc comment for the exact per-item guarantees (atomicity, failure
    /// isolation, ordering) a real implementation must preserve. Default
    /// implementation just calls [`Self::admit_unprojected_change`] once
    /// per item -- byte-identical behavior to before this method existed,
    /// so any implementor that does not override it (today: the test fake
    /// in `engine::tests`) keeps working unchanged. Only a real storage-
    /// backed implementor needs to override this for the writer_gate
    /// benefit; the port's own contract does not require it.
    fn admit_unprojected_change_batch(
        &self,
        items: &[(&Change, &[FileVersion], &ChangeEvidence)],
    ) -> Vec<Result<AdmissionStoreResult, AdmissionStoreError>> {
        items
            .iter()
            .map(|(change, versions, evidence)| {
                self.admit_unprojected_change(change, versions, evidence)
            })
            .collect()
    }
}

pub struct AdmissionStoreResult {
    pub outcome: AdmissionStoreOutcome,
    pub newly_admitted: Vec<ChangeHash>,
}

pub enum AdmissionStoreOutcome {
    Applied,
    Orphaned,
    /// The store refused the Change because its own author's chain cannot
    /// accommodate it. Final: nothing was stored and nothing is held, so
    /// there is no ancestry to request and no retry to schedule.
    RefusedAuthorChain {
        reason: String,
    },
    /// The store refused the Change because it was written on a different
    /// history than this replica's. Final for the same reason, and
    /// distinct because the remedy is a re-bootstrap, not a resend.
    RefusedForeignHistoryBase {
        reason: String,
    },
    /// The store refused the Change because one of its DAG parents is
    /// itself permanently refused, so its ancestry can never be complete.
    /// Final: there is no ancestry worth requesting.
    RefusedBehindRejectedParent {
        reason: String,
    },
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

    /// This device's whole durability-root set for a group, reduced to two
    /// digests and two counts.
    ///
    /// Derived from the index alone. Implementations must not read or hash
    /// a single block to answer it -- that is the distinction between this
    /// and every other method on this port, and the reason a caller may
    /// treat the answer as a health signal and never as custody. A peer
    /// comparing digests learns that two indexes agree; only
    /// `verify_block` above learns that the bytes are there.
    fn root_set_summary(&self, group: &FolderGroupId)
        -> Result<RootSetSummary, ReplicaEngineError>;
}
