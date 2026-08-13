//! `DaemonState`-backed [`ReplicaRoleRepository`] -- wraps `DaemonState`
//! rather than raw `SyncState` for the same reason the membership repository
//! adapter does: `latch_group_durability_unknown` also updates
//! `DaemonState`'s own in-memory durability-status cache.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::FolderLink;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

use crate::application::ports::ReplicaRoleRepository;
use crate::daemon_state::DaemonState;

pub(crate) struct SyncStateReplicaRoleRepository {
    state: Arc<DaemonState>,
}

impl SyncStateReplicaRoleRepository {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl ReplicaRoleRepository for SyncStateReplicaRoleRepository {
    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        self.state.replica_coordinator.link_repository().list_links().map_err(SyncError::from)
    }

    fn live_link_local_path_for_group(&self, group_id: &str) -> Result<Option<String>, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .live_link_local_path_for_group(group_id)
            .map_err(SyncError::from)
    }

    fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .recheck_digest_then_set_materialization_policy(
                group_id,
                local_path,
                policy,
                expected_digest,
            )
            .map_err(SyncError::from)
    }

    fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        let removed = self
            .state
            .replica_coordinator
            .link_repository()
            .recheck_digest_then_remove_link(group_id, local_path, expected_digest)
            .map_err(SyncError::from)?;
        if removed {
            self.state.clear_custody_confirmation(group_id);
        }
        Ok(removed)
    }

    fn remove_link(&self, local_path: &str) -> Result<(), SyncError> {
        // Look up this link's group_id before it's gone, so a stale
        // custody confirmation cached for it can't be reused by a later
        // relink of the same group -- see `clear_custody_confirmation`'s
        // own doc comment. A `list_links` failure here just means the
        // cache entry (if any) is left uncleared -- it still self-heals
        // via the staleness bound and membership-generation check, but log
        // it loudly rather than swallowing it, since a stale window is a
        // real (if bounded) truthfulness gap.
        let group_id = match self.state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links.into_iter().find(|l| l.local_path == local_path).map(|l| l.group_id),
            Err(e) => {
                tracing::warn!(
                    local_path,
                    error = %e,
                    "remove_link: list_links failed, cannot clear this group's custody \
                     confirmation cache entry (will self-heal via staleness bound)"
                );
                None
            }
        };
        self.state
            .replica_coordinator
            .link_repository()
            .remove_link(local_path)
            .map_err(SyncError::from)?;
        if let Some(group_id) = group_id {
            self.state.clear_custody_confirmation(&group_id);
        }
        Ok(())
    }

    fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(local_path, policy)
            .map_err(SyncError::from)
    }

    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.state.latch_group_durability_unknown(group_id)
    }

    fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .arm_duplicate_recovery_paths(group_id)
            .map_err(SyncError::from)
    }

    fn set_suppress_tombstones(&self, local_path: &str, suppress: bool) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .set_suppress_tombstones(local_path, suppress)
            .map_err(SyncError::from)
    }
}
