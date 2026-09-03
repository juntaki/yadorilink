//! `hydration`-backed [`MaterializationPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{
    BoxFuture, EvictOutcome, MaterializationPort, MaterializationStateSummary,
    MaterializationStatusSummary,
};
use crate::daemon_state::DaemonState;
use crate::hydration;
use yadorilink_replica_domain::session_state::MaterializationState;

pub(crate) struct DaemonMaterializationAdapter {
    state: Arc<DaemonState>,
}

impl DaemonMaterializationAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl MaterializationPort for DaemonMaterializationAdapter {
    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(hydration::hydrate(&self.state, group_id, path))
    }

    fn pin<'a>(&'a self, group_id: &'a str, path: &'a str) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(hydration::pin(&self.state, group_id, path))
    }

    fn unpin<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(hydration::unpin(&self.state, group_id, path))
    }

    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
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
        Ok(hydration::materialization_status(&self.state, group_id, path)?.map(|info| {
            MaterializationStatusSummary {
                state: match info.state {
                    MaterializationState::Hydrated => MaterializationStateSummary::Hydrated,
                    MaterializationState::Placeholder => MaterializationStateSummary::Placeholder,
                    MaterializationState::Hydrating => MaterializationStateSummary::Hydrating,
                    MaterializationState::Evicting => MaterializationStateSummary::Evicting,
                },
                pinned: info.pinned,
            }
        }))
    }
}
