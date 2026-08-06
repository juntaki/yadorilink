//! `DaemonState`-backed [`ReplicaReadinessPort`].

use std::sync::Arc;

use crate::application::ports::{BoxFuture, ReplicaReadinessPort};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonReplicaReadinessAdapter {
    state: Arc<DaemonState>,
}

impl DaemonReplicaReadinessAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl ReplicaReadinessPort for DaemonReplicaReadinessAdapter {
    fn another_full_replica_is_ready_excluding<'a>(
        &'a self,
        group_id: &'a str,
        excluded_device_id: &'a str,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            self.state.another_full_replica_is_ready_excluding(group_id, excluded_device_id).await
        })
    }
}
