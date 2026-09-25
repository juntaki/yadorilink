//! `hydration`-backed [`MaterializationPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{
    BoxFuture, EvictOutcome, MaterializationPort, MaterializationStateSummary,
    MaterializationStatusSummary,
};
use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::hydration::directory_pin;
use yadorilink_replica_domain::session_state::MaterializationState;

pub(crate) struct DaemonMaterializationAdapter {
    state: Arc<DaemonState>,
}

impl DaemonMaterializationAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

/// A folder is asked for as a whole: its pin is a policy over everything
/// below it (see `hydration::directory_pin`), and every other request acts
/// on the files below it. Anything else is one file.
impl MaterializationPort for DaemonMaterializationAdapter {
    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            if directory_pin::is_indexed_directory(&self.state, group_id, path)? {
                return directory_pin::hydrate_directory(&self.state, group_id, path).await;
            }
            hydration::hydrate(&self.state, group_id, path).await
        })
    }

    fn pin<'a>(&'a self, group_id: &'a str, path: &'a str) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            if directory_pin::is_indexed_directory(&self.state, group_id, path)? {
                return directory_pin::pin_directory(&self.state, group_id, path).await;
            }
            hydration::pin(&self.state, group_id, path).await
        })
    }

    fn unpin<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            if directory_pin::is_indexed_directory(&self.state, group_id, path)? {
                return directory_pin::unpin_directory(&self.state, group_id, path);
            }
            directory_pin::unpin_non_directory(&self.state, group_id, path).await
        })
    }

    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
        let path = path.trim_end_matches('/');
        if directory_pin::is_indexed_directory(&self.state, group_id, path)? {
            return directory_pin::evict_directory(&self.state, group_id, path).map(|outcome| {
                EvictOutcome {
                    dehydrated: outcome.evicted_files > 0,
                    blocks_reclaimed: outcome.blocks_reclaimed,
                    bytes_reclaimed: outcome.bytes_reclaimed,
                }
            });
        }
        hydration::evict(&self.state, group_id, path).map(|outcome| EvictOutcome {
            dehydrated: outcome.dehydrated,
            blocks_reclaimed: outcome.blocks_reclaimed,
            bytes_reclaimed: outcome.bytes_reclaimed,
        })
    }

    fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
        let path = path.trim_end_matches('/');
        let info = if directory_pin::is_indexed_directory(&self.state, group_id, path)? {
            Some(directory_pin::directory_status(&self.state, group_id, path)?)
        } else {
            hydration::materialization_status(&self.state, group_id, path)?
        };
        Ok(info.map(|info| MaterializationStatusSummary {
            state: match info.state {
                MaterializationState::Hydrated => MaterializationStateSummary::Hydrated,
                MaterializationState::Placeholder => MaterializationStateSummary::Placeholder,
                MaterializationState::Hydrating => MaterializationStateSummary::Hydrating,
                MaterializationState::Evicting => MaterializationStateSummary::Evicting,
            },
            pinned: info.pinned,
        }))
    }
}
