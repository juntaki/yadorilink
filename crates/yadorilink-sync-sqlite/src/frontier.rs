//! `FrontierStorePort` implementation for [`crate::SqliteSyncStore`].

use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_replica_engine::ports::FrontierStorePort;

use crate::SqliteSyncStore;

impl FrontierStorePort for SqliteSyncStore {
    fn record_acknowledged_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), ReplicaEngineError> {
        // Normalized here, not inside `set_device_frontier`, which stores
        // exactly what it's given -- matches
        // `yadorilink-sync-core::compaction::record_acknowledged_frontier`'s
        // existing normalize-then-store split.
        let mut normalized = frontier.to_vec();
        normalized.sort();
        normalized.dedup();
        self.set_device_frontier(group, device, &normalized)
            .map_err(|error| ReplicaEngineError::Storage(error.to_string()))
    }
}
