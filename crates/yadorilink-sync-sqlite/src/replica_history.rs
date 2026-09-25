//! `ReplicaHistoryPort` implementation for [`crate::SqliteSyncStore`] --
//! pure delegation to the store's own read methods, converting this
//! crate's own error type to `yadorilink_replica_engine::error::ReplicaEngineError`
//! at the boundary.

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId, VersionHash};
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_replica_engine::ports::ReplicaHistoryPort;

use crate::error::SyncSqliteError;
use crate::SqliteSyncStore;

fn storage_err(error: SyncSqliteError) -> ReplicaEngineError {
    ReplicaEngineError::Storage(error.to_string())
}

/// `ExternallyObservable(x) => ValidAuthorizationEvidence(x)`
/// (the publication invariant): `encoded_change`/
/// `change`/`group_heads` are the exact three reads that feed outbound
/// heads-announce, have-boundary, and `ChangeBatch` construction, so they
/// delegate to the `published_*` (evidence-gated) reads, never the raw
/// admitted-DAG ones -- a Pending Change must never be reachable through
/// this port, regardless of which caller constructs it. The other methods
/// here (`parents_of`, `missing_ancestor_frontier`, `has_file_version`,
/// `file_version`) are graph-topology/content-addressed-storage reads with
/// no publication semantics of their own -- see `dag_store::published_view`'s
/// module doc for why gating them would be both unnecessary (they never by
/// themselves make Pending content or its existence externally observable;
/// every caller that turns their output into wire content already goes
/// through one of the three gated reads first) and actively harmful (an
/// ancestor/version lookup needed purely for local admission bookkeeping
/// must see the true DAG, not just its published subset).
impl ReplicaHistoryPort for SqliteSyncStore {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.parents_of(hash).map_err(storage_err)
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        self.published_change(hash).map_err(storage_err)
    }

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.published_group_heads(group).map_err(storage_err)
    }

    fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.missing_ancestor_frontier(roots).map_err(storage_err)
    }

    fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, ReplicaEngineError> {
        self.has_file_version(group, hash).map_err(storage_err)
    }

    fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, ReplicaEngineError> {
        self.file_version(group, hash).map_err(storage_err)
    }
}
