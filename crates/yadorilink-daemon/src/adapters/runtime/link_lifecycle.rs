//! `SyncState`/`LinkRuntimeController`-backed [`LinkRepositoryPort`]/
//! [`LinkWatcherPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{
    BoxFuture, LinkRepositoryPort, LinkWatcherPort, PendingEnrollmentLinkCommand,
};
use crate::application::EnrollmentKind;
use crate::daemon_state::DaemonState;
use crate::error::DaemonError;

pub(crate) struct DaemonLinkRepositoryAdapter {
    state: Arc<DaemonState>,
}

impl DaemonLinkRepositoryAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl LinkRepositoryPort for DaemonLinkRepositoryAdapter {
    fn live_link_paths_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group(group_id)
            .map_err(SyncError::from)
    }

    fn list_link_paths(&self) -> Result<Vec<String>, SyncError> {
        Ok(self
            .state
            .replica_coordinator
            .link_repository()
            .list_links()
            .map_err(SyncError::from)?
            .into_iter()
            .map(|l| l.local_path)
            .collect())
    }

    fn commit_plain_link(&self, local_path: &str, group_id: &str) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .add_link(local_path, group_id)
            .map_err(SyncError::from)
    }

    fn commit_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollmentLinkCommand,
    ) -> Result<(), SyncError> {
        let kind = match marker.kind {
            EnrollmentKind::Create => {
                yadorilink_replica_domain::session_state::EnrollmentKind::Create
            }
            EnrollmentKind::Join => yadorilink_replica_domain::session_state::EnrollmentKind::Join,
        };
        self.state
            .replica_coordinator
            .enrollment_repository()
            .add_link_with_pending_enrollment_and_begin_setup(
                local_path,
                group_id,
                &yadorilink_replica_domain::session_state::PendingEnrollment {
                    operation_id: marker.operation_id.clone(),
                    kind,
                    group_id: group_id.to_string(),
                    device_id: marker.device_id.clone(),
                    local_path: local_path.to_string(),
                },
                crate::daemon_state::now_unix(),
            )
            .map_err(SyncError::from)
    }

    fn remove_link(&self, local_path: &str) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .remove_link(local_path)
            .map_err(SyncError::from)
    }

    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        operation_id: &str,
        detail: &str,
    ) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .enrollment_repository()
            .rollback_local_setup_to_cancel_pending(
                local_path,
                operation_id,
                detail,
                crate::daemon_state::now_unix(),
            )
            .map_err(SyncError::from)
    }

    fn mark_enrollment_activation_pending(&self, operation_id: &str) -> Result<bool, SyncError> {
        self.state
            .replica_coordinator
            .enrollment_repository()
            .mark_enrollment_activation_pending(operation_id, crate::daemon_state::now_unix())
            .map_err(SyncError::from)
    }
}

pub(crate) struct DaemonLinkWatcherAdapter {
    state: Arc<DaemonState>,
    controller: Arc<LinkRuntimeController>,
}

impl DaemonLinkWatcherAdapter {
    pub(crate) fn new(state: Arc<DaemonState>, controller: Arc<LinkRuntimeController>) -> Self {
        Self { state, controller }
    }
}

impl LinkWatcherPort for DaemonLinkWatcherAdapter {
    fn is_ready(&self, local_path: &str) -> bool {
        self.controller.is_ready(local_path)
    }

    fn start<'a>(
        &'a self,
        local_path: &'a str,
        group_id: &'a str,
        on_demand: bool,
        max_local_size_bytes: Option<i64>,
    ) -> BoxFuture<'a, Result<(), DaemonError>> {
        Box::pin(async move {
            if on_demand {
                if !yadorilink_filesystem_sync::placeholder_backend::on_demand_pipeline_is_connected(
                ) {
                    return Err(DaemonError::Config(
                        "on-demand (placeholder) materialization is not available in this build \
                         yet -- link this folder in eager (full-copy) mode instead"
                            .to_string(),
                    ));
                }
                self.state
                    .replica_coordinator
                    .link_repository()
                    .set_materialization_policy(
                        local_path,
                        yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
                    )
                    .map_err(SyncError::from)?;
                if let Some(max_bytes) = max_local_size_bytes {
                    self.state
                        .replica_coordinator
                        .link_repository()
                        .set_max_local_size_bytes(local_path, Some(max_bytes))
                        .map_err(SyncError::from)?;
                }
            }
            // Retention is a fixed built-in policy (10 versions / 30 days)
            // applied to every link, so there is nothing per-link to
            // configure here.
            self.controller.start(local_path.to_string(), group_id.to_string())?;
            Ok(())
        })
    }

    fn stop<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.controller.stop(local_path))
    }
}
