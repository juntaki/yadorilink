//! What `LinkLifecycleService` needs to atomically register a link. Split
//! into two ports matching the two concerns the daemon's original
//! `link` handler body bundled: `LinkRepositoryPort` for the durable `SyncState`
//! reads/writes (each method here is one atomic `SyncState` operation,
//! never decomposed further -- a transactional commit/rollback stays one
//! port call, never split across two so a caller could interleave other
//! work in between), and `LinkWatcherPort` for the in-memory watcher/
//! on-demand-materialization setup that runs after the commit.
//!
//! This is the single local-link commit path both the plain `yadorilink
//! link` command and `EnrollmentService::create_and_link`/`join_and_link`
//! (via `EnrollmentLinkPort`) converge on -- there is no second,
//! independent way to create a link row in this daemon.

use crate::sync_error::SyncError;

use super::common::BoxFuture;
use crate::application::EnrollmentKind;
use crate::error::DaemonError;

pub(crate) struct PendingEnrollmentLinkCommand {
    pub(crate) operation_id: String,
    pub(crate) kind: EnrollmentKind,
    pub(crate) device_id: String,
}

pub(crate) struct LinkCommand {
    pub(crate) local_path: String,
    pub(crate) group_id: String,
    pub(crate) on_demand: bool,
    pub(crate) max_local_size_bytes: Option<i64>,
    pub(crate) acknowledge_risks: bool,
    /// `None` for a plain `yadorilink link` -- no pending-enrollment
    /// marker is written, and any failure is a plain rollback-free `Err`
    /// (nothing was ever committed). `Some` for a `share create`/`share
    /// join` link, coupling the link row and the marker in one
    /// transaction.
    pub(crate) pending_enrollment: Option<PendingEnrollmentLinkCommand>,
}

pub(crate) trait LinkRepositoryPort: Send + Sync {
    /// Every currently-live local path linked to `group_id` on this
    /// device -- used for the duplicate-group refusal (a folder group can
    /// only be linked to one folder on a device).
    fn live_link_paths_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError>;

    /// Every currently-linked local path on this device -- used for the
    /// nested-path preflight (ancestor/descendant/exact-match conflicts).
    fn list_link_paths(&self) -> Result<Vec<String>, SyncError>;

    fn commit_plain_link(&self, local_path: &str, group_id: &str) -> Result<(), SyncError>;

    /// Atomically inserts the link row AND the pending-enrollment marker,
    /// advancing the matching `enrollment_operations` row from `Prepared`
    /// to `LocalSetupPending` in the same transaction.
    fn commit_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollmentLinkCommand,
    ) -> Result<(), SyncError>;

    fn remove_link(&self, local_path: &str) -> Result<(), SyncError>;

    /// Atomically removes the link row AND rolls the matching
    /// `enrollment_operations` row back from `LocalSetupPending` to
    /// `CancelPending`, recording `detail` as the failure reason.
    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        operation_id: &str,
        detail: &str,
    ) -> Result<(), SyncError>;

    /// Advances the `enrollment_operations` row from `LocalSetupPending`
    /// to `ActivationPending` -- `Ok(false)` means the row was no longer
    /// advanceable (e.g. a concurrent recovery sweep already rolled it
    /// back), distinct from a read/write failure.
    fn mark_enrollment_activation_pending(&self, operation_id: &str) -> Result<bool, SyncError>;
}

pub(crate) trait LinkWatcherPort: Send + Sync {
    /// The fallible steps that run after the link (and marker) row(s) are
    /// already committed: on-demand materialization policy/size-cap
    /// configuration, then starting the OS watcher. Bundled as one port
    /// call (mirroring the original `finish_link_setup`) since both must
    /// succeed or neither counts as done -- `LinkLifecycleService` rolls
    /// back the repository commit on any failure here.
    fn start<'a>(
        &'a self,
        local_path: &'a str,
        group_id: &'a str,
        on_demand: bool,
        max_local_size_bytes: Option<i64>,
    ) -> BoxFuture<'a, Result<(), DaemonError>>;

    fn stop<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()>;
}
