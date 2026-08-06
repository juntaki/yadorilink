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

impl ReplicaHistoryPort for SqliteSyncStore {
    fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.parents_of(hash).map_err(storage_err)
    }

    fn encoded_change(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, ReplicaEngineError> {
        self.get_encoded(hash).map_err(storage_err)
    }

    fn change(&self, hash: &ChangeHash) -> Result<Option<Change>, ReplicaEngineError> {
        self.get_change(hash).map_err(storage_err)
    }

    fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, ReplicaEngineError> {
        self.group_heads(group).map_err(storage_err)
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
