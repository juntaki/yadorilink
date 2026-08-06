//! `DaemonState`-backed [`LinkPauseResumePort`]/[`GcPort`]/
//! [`DaemonLifecyclePort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{
    BoxFuture, DaemonLifecyclePort, GcCommandError, GcCommandOutcome, GcPort, LinkPauseResumePort,
};
use crate::daemon_state::DaemonState;
use crate::gc::{self, GcTriggerError};

pub(crate) struct DaemonPauseResumeAdapter {
    state: Arc<DaemonState>,
    controller: Arc<LinkRuntimeController>,
}

impl DaemonPauseResumeAdapter {
    pub(crate) fn new(state: Arc<DaemonState>, controller: Arc<LinkRuntimeController>) -> Self {
        Self { state, controller }
    }
}

impl LinkPauseResumePort for DaemonPauseResumeAdapter {
    fn pause(&self, local_path: &str) -> Result<(), SyncError> {
        self.state.replica_coordinator.link_repository().set_paused(local_path, true).map_err(SyncError::from)
    }

    fn resume<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(self.controller.resume(local_path))
    }
}

pub(crate) struct DaemonGcAdapter {
    state: Arc<DaemonState>,
}

impl DaemonGcAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl GcPort for DaemonGcAdapter {
    fn run_sweep(&self, dry_run: bool) -> BoxFuture<'_, Result<GcCommandOutcome, GcCommandError>> {
        let state = self.state.clone();
        Box::pin(async move {
            gc::run_sweep(state, dry_run).await.map(encode_outcome).map_err(encode_error)
        })
    }
}

fn encode_outcome(report: yadorilink_local_storage::GcReport) -> GcCommandOutcome {
    GcCommandOutcome {
        blocks_deleted: report.blocks_deleted,
        bytes_reclaimed: report.bytes_reclaimed,
    }
}

fn encode_error(error: GcTriggerError) -> GcCommandError {
    match error {
        GcTriggerError::AlreadyRunning => GcCommandError::AlreadyRunning,
        GcTriggerError::SyncBurstInProgress => GcCommandError::SyncBurstInProgress,
        GcTriggerError::Failed(e) => GcCommandError::Failed(e),
    }
}

pub(crate) struct DaemonLifecycleAdapter {
    state: Arc<DaemonState>,
}

impl DaemonLifecycleAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl DaemonLifecyclePort for DaemonLifecycleAdapter {
    fn request_shutdown(&self) {
        let _ = self.state.shutdown_tx.send(true);
    }
}
