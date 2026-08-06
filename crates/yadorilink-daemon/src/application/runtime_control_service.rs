use std::sync::Arc;

use crate::sync_error::SyncError;

use super::ports::{
    DaemonLifecyclePort, GcCommandError, GcCommandOutcome, GcPort, LinkPauseResumePort,
};

pub(crate) struct PauseResumeService {
    port: Arc<dyn LinkPauseResumePort>,
}

impl PauseResumeService {
    pub(crate) fn new(port: Arc<dyn LinkPauseResumePort>) -> Self {
        Self { port }
    }

    pub(crate) fn pause(&self, local_path: &str) -> Result<(), SyncError> {
        self.port.pause(local_path)
    }

    pub(crate) async fn resume(&self, local_path: &str) -> Result<(), SyncError> {
        self.port.resume(local_path).await
    }
}

pub(crate) struct GcCommandService {
    port: Arc<dyn GcPort>,
}

impl GcCommandService {
    pub(crate) fn new(port: Arc<dyn GcPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn run(&self, dry_run: bool) -> Result<GcCommandOutcome, GcCommandError> {
        self.port.run_sweep(dry_run).await
    }
}

pub(crate) struct DaemonLifecycleService {
    port: Arc<dyn DaemonLifecyclePort>,
}

impl DaemonLifecycleService {
    pub(crate) fn new(port: Arc<dyn DaemonLifecyclePort>) -> Self {
        Self { port }
    }

    pub(crate) fn request_shutdown(&self) {
        self.port.request_shutdown();
    }
}
