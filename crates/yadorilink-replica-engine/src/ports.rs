//! The narrow port `PeerReplicaEngine` depends on.

use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId, SyncPath};
use yadorilink_replica_domain::session_state::RootSetSummary;

use crate::error::ReplicaEngineError;

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
