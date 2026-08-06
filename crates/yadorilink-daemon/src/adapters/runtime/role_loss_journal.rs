//! `DaemonState`-backed [`RoleLossJournal`].

use std::sync::Arc;

use yadorilink_replica_domain::session_state::RoleLossAction;

use crate::application::ports::{BoxFuture, RoleLossJournal};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonRoleLossJournal {
    state: Arc<DaemonState>,
}

impl DaemonRoleLossJournal {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl RoleLossJournal for DaemonRoleLossJournal {
    fn open_operation(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
        action: RoleLossAction,
        local_path: &str,
    ) -> Result<String, String> {
        self.state.open_role_loss_operation(
            group_id,
            target_device_id,
            lease_id,
            action,
            local_path,
        )
    }

    fn mark_worker_committed(&self, operation_id: &str, membership_generation: i64) {
        self.state.mark_role_loss_worker_committed(operation_id, membership_generation);
    }

    fn discard_operation(&self, operation_id: &str) {
        self.state.discard_role_loss_operation(operation_id);
    }

    fn settle_success(&self, operation_id: &str) {
        self.state.settle_role_loss_operation_success(operation_id);
    }

    fn compensate<'a>(&'a self, operation_id: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { self.state.compensate_role_loss_operation(operation_id).await })
    }
}
