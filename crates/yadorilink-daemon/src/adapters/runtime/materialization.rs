//! `hydration`-backed [`MaterializationPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{BoxFuture, EvictOutcome, MaterializationPort};
use crate::daemon_state::DaemonState;
use crate::hydration;

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
}
