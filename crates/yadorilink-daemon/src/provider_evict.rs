//! Freeing the local copy of a file in a provider folder on request (`yadorilink evict <path>`).
//!
//! The operating system owns what a provider folder holds locally; the daemon asks the host to
//! drop its copy, and then frees its own cached blocks of the version, which is what returns real
//! disk space. The first is safe on its own (the daemon keeps the blocks, so the next open is a
//! local hand-over); the second needs a full replica's durable custody lease on exactly this
//! version, taken BEFORE the OS drops anything and checked again before any block is removed
//! (see [`crate::provider_reclaim`]). Without that lease the OS copy is still dropped and the
//! answer says why the blocks stayed.
//!
//! The host refuses to dehydrate a file the user has changed and not yet shared (the placeholder
//! is no longer in sync), so a local edit is never lost by this path.

use std::sync::{Arc, OnceLock};

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_sync_sqlite::provider::{ItemId, ProviderDeclaration};

use crate::application::ports::BoxFuture;
use crate::daemon_state::DaemonState;
use crate::provider_evidence::{os_holds_current_content, ProviderMembership};
use crate::provider_host_link::ProviderHostLink;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::provider_reclaim::{ProviderReclaim, Reclaimed, Retained};
use crate::sync_error::SyncError;

/// The host side an eviction needs: a fake in tests, the attached menu-bar app in production.
pub(crate) trait EvictHost: Send + Sync {
    fn connected(&self) -> bool;

    /// Drops the OS copy only while the host shows exactly `target`.
    fn evict_shown_version<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer>;
}

impl EvictHost for ProviderHostLink {
    fn connected(&self) -> bool {
        self.host_connected()
    }

    fn evict_shown_version<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer> {
        ProviderHostLink::evict_shown_version(self, root_id, item, target)
    }
}

/// What one eviction request did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderEvictOutcome {
    /// The OS dropped its copy.
    pub dehydrated: bool,
    /// The daemon's cached blocks that were physically freed.
    pub reclaimed: Reclaimed,
    /// Why the blocks stayed, when they did.
    pub retained: Option<Retained>,
}

pub(crate) struct ProviderEvictor {
    state: Arc<DaemonState>,
    host: Arc<dyn EvictHost>,
    reclaim: Arc<ProviderReclaim>,
    membership: Arc<ProviderMembership>,
}

impl ProviderEvictor {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        host: Arc<dyn EvictHost>,
        reclaim: Arc<ProviderReclaim>,
        membership: Arc<ProviderMembership>,
    ) -> Self {
        Self { state, host, reclaim, membership }
    }

    pub(crate) async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        let result = self.evict_inner(group_id, path).await;
        // The item has settled, whatever the outcome: a lease taken for an eviction that did not
        // complete is released by the reconciler now rather than at the next restart.
        self.state.nudge_custody_hold_reconciler();
        result
    }

    async fn evict_inner(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ProviderEvictOutcome, SyncError> {
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
        if !self.host.connected() {
            return Err(not_connected());
        }
        let version = record.to_file_version().version_hash;
        // The lease comes first, and its item lock stays held until the blocks are settled: the
        // OS copy is dropped only when this device knows whether the blocks can follow.
        let mut _local_copy = None;
        let prepared = match self.reclaim.prepare(group_id, path, Some(version)).await {
            Ok(prepared) => Ok(prepared),
            // Another operation holds the item, or it is not the version the request was about:
            // leave everything as it is.
            Err(why @ (Retained::Busy | Retained::VersionMoved)) => {
                return Ok(ProviderEvictOutcome { retained: Some(why), ..Default::default() });
            }
            // No lease: the OS copy may go only if the next open can be served from this
            // device's own blocks, proven by reading and hashing every one of them. The item
            // lock taken for the proof stays held until the host has answered.
            Err(why) => {
                match self.reclaim.hold_verified_local_copy(group_id, path, version).await {
                    Ok(copy) => {
                        _local_copy = Some(copy);
                        Err(why)
                    }
                    Err(refused @ (Retained::Busy | Retained::VersionMoved)) => {
                        return Ok(ProviderEvictOutcome {
                            retained: Some(refused),
                            ..Default::default()
                        });
                    }
                    Err(refused) => {
                        tracing::info!(
                            reason = why.code(),
                            "provider eviction refused: no lease, local blocks not verified"
                        );
                        return Ok(ProviderEvictOutcome {
                            retained: Some(refused),
                            ..Default::default()
                        });
                    }
                }
            }
        };
        let answer = self.drop_os_copy(&root.root_id, item, version.0).await?;
        let (dehydrated, host_retained) = match answer {
            HostAnswer::Evicted => (true, None),
            // Already without its data: the blocks may still be freed.
            HostAnswer::NotMaterialized => (false, None),
            HostAnswer::Busy => (false, Some(Retained::HostBusy)),
            HostAnswer::NotConnected => return Err(not_connected()),
            HostAnswer::Error(reason) => return Err(SyncError::EvictionRejected(reason)),
        };
        let prepared = match (prepared, host_retained) {
            (Ok(prepared), None) => prepared,
            (_, Some(why)) | (Err(why), None) => {
                return Ok(ProviderEvictOutcome {
                    dehydrated,
                    retained: Some(why),
                    ..Default::default()
                });
            }
        };
        let reclaimed = self.reclaim.reclaim(prepared).await?;
        let retained = (reclaimed.blocks == 0).then_some(Retained::NothingFreed);
        Ok(ProviderEvictOutcome { dehydrated, reclaimed, retained })
    }

    /// Asks the host to drop its copy, but only for an item the daemon's own evidence shows the OS
    /// holds with the CURRENT content (see [`os_holds_current_content`]): the host cannot check a
    /// shown version itself, so a request for anything else would drop whatever the OS has there
    /// now.
    async fn drop_os_copy(
        &self,
        root_id: &str,
        item: ItemId,
        version: [u8; 32],
    ) -> Result<HostAnswer, SyncError> {
        let holds = os_holds_current_content(
            &self.state.replica_coordinator,
            &self.membership,
            root_id,
            &item,
        );
        if !holds {
            return Ok(HostAnswer::NotMaterialized);
        }
        Ok(self.host.evict_shown_version(root_id, item, version).await)
    }
}

fn not_connected() -> SyncError {
    SyncError::EvictionRejected("the File Provider host is not connected".into())
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
    ) -> Result<ProviderEvictOutcome, SyncError> {
        match self.0.get() {
            Some(evictor) => evictor.evict(group_id, path).await,
            None => Err(SyncError::EvictionRejected(
                "provider folders are not available in this daemon".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
