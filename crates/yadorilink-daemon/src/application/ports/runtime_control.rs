//! What `PauseResumeService`/`GcCommandService`/`DaemonLifecycleService`
//! need from the runtime -- daemon-wide operations that don't fit
//! `MaterializationPort`'s per-file shape (pause/resume act on a link as a
//! whole; GC and shutdown aren't scoped to a link at all).

use crate::sync_error::SyncError;

use super::common::BoxFuture;

pub(crate) trait LinkPauseResumePort: Send + Sync {
    fn pause(&self, local_path: &str) -> Result<(), SyncError>;

    fn resume<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, Result<(), SyncError>>;
}

/// Application-owned mirror of `yadorilink_local_storage::GcReport` --
/// kept as a distinct type (not a re-export) so `application` never names
/// a local-storage crate type in a port signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GcCommandOutcome {
    pub(crate) blocks_deleted: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Application-owned mirror of the daemon's own `GcTriggerError` -- kept
/// distinct so `application` never names that GC implementation type
/// directly in a port signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GcCommandError {
    AlreadyRunning,
    SyncBurstInProgress,
    Failed(String),
}

impl std::fmt::Display for GcCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcCommandError::AlreadyRunning => {
                write!(f, "a garbage-collection sweep is already in progress; try again shortly")
            }
            GcCommandError::SyncBurstInProgress => write!(
                f,
                "sync activity is in progress; garbage collection was skipped to avoid \
                 contention -- try again once idle, or wait for the next automatic sweep"
            ),
            GcCommandError::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GcCommandError {}

pub(crate) trait GcPort: Send + Sync {
    fn run_sweep(&self, dry_run: bool) -> BoxFuture<'_, Result<GcCommandOutcome, GcCommandError>>;
}

pub(crate) trait DaemonLifecyclePort: Send + Sync {
    /// Requests graceful shutdown -- fire-and-forget, matching
    /// `DaemonState.shutdown_tx`'s own "a send error just means every
    /// receiver is already gone" semantics.
    fn request_shutdown(&self);
}
