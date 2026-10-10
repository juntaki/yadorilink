//! Freeing the local copy of a file in a provider folder on request (`yadorilink evict <path>`).
//!
//! The operating system owns what a provider folder holds locally; the daemon only asks the host
//! to drop its copy, through the same eviction request the publication machine uses. Before it
//! asks, it requires what an eviction on a linked folder requires: a full replica must confirm it
//! holds exactly the current version, so that the bytes the OS drops can be fetched again on the
//! next open. The version is checked again after the confirmation and before the request, so content that arrived
//! meanwhile is not dropped on the strength of an answer about an older version. The host refuses to dehydrate a
//! file the user has changed and not yet shared (the placeholder is no longer in sync), so a local edit is never
//! lost by this path, and what it drops is only the operating system's copy: the daemon keeps the blocks.

use std::sync::{Arc, OnceLock};

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use crate::application::ports::EvictOutcome;
use crate::daemon_state::DaemonState;
use crate::provider_host_link::ProviderHostLink;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::sync_error::SyncError;

pub(crate) struct ProviderEvictor {
    state: Arc<DaemonState>,
    host: Arc<ProviderHostLink>,
}

impl ProviderEvictor {
    pub(crate) fn new(state: Arc<DaemonState>, host: Arc<ProviderHostLink>) -> Self {
        Self { state, host }
    }

    pub(crate) async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictOutcome, SyncError> {
        let path = path.trim_end_matches('/');
        let coordinator = &self.state.replica_coordinator;
        let repository = coordinator.provider_repository();
        let ProviderDeclaration::Provider(root) = repository.declaration_for_group(group_id)?
        else {
            return Err(SyncError::EvictionRejected(format!("{path}: not in a provider folder")));
        };
        let Some(item) = repository.item_for_path(&root.root_id, path)? else {
            return Err(SyncError::EvictionRejected(format!("{path}: not an item of the folder")));
        };
        let record = coordinator
            .sqlite()
            .dag_get_current_version_record(group_id, path)?
            .filter(|record| !record.deleted)
            .ok_or_else(|| SyncError::EvictionRejected(format!("{path}: no current version")))?;
        if record.record_kind != RecordKind::File {
            return Err(SyncError::EvictionRejected(format!(
                "{path} is not a regular file and cannot be evicted"
            )));
        }
        let version = record.to_file_version();
        let confirmed = self
            .state
            .confirm_version_present_witness_via_peer(
                group_id,
                path,
                version.version_hash,
                &version.blocks,
            )
            .await;
        if confirmed.is_none() {
            tracing::info!(
                path,
                "provider eviction refused: no full replica confirmed the version"
            );
            return Ok(EvictOutcome::default());
        }
        // The custody answer is for `version`. If the item moved on while it was awaited, nothing confirms the
        // newer content yet: leave the file as it is.
        let still_current =
            coordinator.sqlite().dag_get_current_version_record(group_id, path)?.is_some_and(
                |now| !now.deleted && now.to_file_version().version_hash == version.version_hash,
            );
        if !still_current {
            tracing::info!(
                path,
                "provider eviction refused: the version changed while custody was confirmed"
            );
            return Ok(EvictOutcome::default());
        }
        match self.host.evict_shown_version(&root.root_id, item, version.version_hash.0).await {
            HostAnswer::Evicted => {
                Ok(EvictOutcome { dehydrated: true, blocks_reclaimed: 0, bytes_reclaimed: 0 })
            }
            // Already without its data, or open in an application: nothing was freed.
            HostAnswer::NotMaterialized | HostAnswer::Busy => Ok(EvictOutcome::default()),
            HostAnswer::NotConnected => {
                Err(SyncError::EvictionRejected("the Cloud Files host is not connected".into()))
            }
            HostAnswer::Error(reason) => Err(SyncError::EvictionRejected(reason)),
        }
    }
}

/// The evictor, installed by the shell side once it exists (the control socket is built first).
#[derive(Default)]
pub(crate) struct ProviderEvictSlot(OnceLock<Arc<ProviderEvictor>>);

impl ProviderEvictSlot {
    pub(crate) fn install(&self, evictor: Arc<ProviderEvictor>) {
        let _ = self.0.set(evictor);
    }

    pub(crate) async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<EvictOutcome, SyncError> {
        match self.0.get() {
            Some(evictor) => evictor.evict(group_id, path).await,
            None => Err(SyncError::EvictionRejected(
                "provider folders are not available in this daemon".into(),
            )),
        }
    }
}
