//! The live daemon's rebootstrap: a device that holds native state of a group but can no longer
//! catch up by deltas replaces that state with a sealed checkpoint a peer offers.
//!
//! The machine itself lives in `yadorilink_sync_sqlite::native_rebootstrap` and its siblings and
//! is driven from its journal, one step at a time: begin (freeze, one final capture pass of the
//! folder, preserve what the replacement would lose, durable barrier), install (quarantine the
//! originals that cannot be re-authored, replace the state, rotate the author incarnation),
//! bounded catch-up from the connected peers, replay of this device's own unpublished intent,
//! finish. This module supplies what the machine asks of its host: the final capture pass over
//! the linked folder, the content a preserved version needs, the authority that decides whether
//! own intent may be replayed, root-confined removal of quarantined originals, and one awaited
//! catch-up pass over the live peer connections. After a restart the same driver continues from
//! whatever the journal says.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::{BlockInfo, FileVersion};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_sync_sqlite::local_author::LocalAuthor;
use yadorilink_sync_sqlite::native_bootstrap::NativeBootstrap;
use yadorilink_sync_sqlite::native_rebootstrap::{
    begin_rebootstrap, finish_rebootstrap, rebootstrap_status, recover_after_restart, BeginError,
    BeginRequest, CaptureAuthority, CaptureBarrier, Crash, Failpoint, FinalCapture,
    LeaveIncremental, PreserveContext, ReassertAuthority, Reassertability, RebootstrapState,
    RecoveryContentSource, RestartOutcome,
};
use yadorilink_sync_sqlite::native_rebootstrap_install::{
    install_rebootstrap, InstallContext, InstallError, InstallPoint, Observed, QuarantineRoot,
};
use yadorilink_sync_sqlite::native_rebootstrap_replay::{
    catch_up, replay_own_intent, CatchUpLimits, CatchUpPass, CatchUpSource, MachinePoint,
    ReplayContext, ReplayError,
};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::{DaemonState, GroupPolicyResolution};
use crate::native_recovery::PolicyView;

/// The longest the final capture of versions to preserve may spend fetching missing blocks
/// from peers while the group is frozen. Not yet measured: set from the freeze measurement.
pub const RECOVERY_FETCH_FROZEN_CAP: Duration = Duration::from_secs(30);

/// The longest one pass that completes unavailable items may spend fetching their missing
/// blocks. Not yet measured: set from the freeze measurement.
pub const RECOVERY_FETCH_PASS_CAP: Duration = Duration::from_secs(120);

/// How many times a step that lost a race for the database's write lock is run again.
const BUSY_RETRIES: u32 = 20;

/// A point of the machine at which a test may stop the process to see what survives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    Begin(Failpoint),
    Install(InstallPoint),
    Machine(MachinePoint),
}

/// Called at each [`Point`]; an error stops the machine there as a crash would.
pub type Hook = Arc<dyn Fn(Point) -> Result<(), Crash> + Send + Sync>;

#[derive(Debug)]
pub enum RebootstrapError {
    /// The machine did not start: the bundle was refused, or the group has not given up
    /// the incremental path. Nothing was changed.
    Refused(String),
    /// Another call, or a rebootstrap already running, holds the group.
    Busy,
    /// The machine stopped on a condition that needs the user or time; the journal says why.
    Blocked(String),
    /// The machine waits for something that arrives on its own (the group's policy after a
    /// restart); it is left where it is and continued later.
    Waiting(String),
    /// A test stopped the machine at a point.
    Crashed,
    Failed(String),
}

impl std::fmt::Display for RebootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "the rebootstrap did not start: {why}"),
            Self::Busy => write!(f, "a rebootstrap of this group is already running"),
            Self::Blocked(why) => write!(f, "the rebootstrap is blocked: {why}"),
            Self::Waiting(why) => write!(f, "the rebootstrap is waiting: {why}"),
            Self::Crashed => write!(f, "the rebootstrap was stopped"),
            Self::Failed(why) => write!(f, "the rebootstrap failed: {why}"),
        }
    }
}

impl From<SyncSqliteError> for RebootstrapError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Failed(error.to_string())
    }
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Runs a rebootstrap of `group` to the verified-on-begin `bundle` a peer sealed, to the end:
/// freeze, preserve, install, catch up, replay, finish, and the work that follows (the folder
/// is scanned again, the replacement checkpoint is sealed). Blocks the calling thread for as
/// long as that takes; it must run where blocking is allowed.
pub(crate) fn run(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    bundle: NativeBootstrap,
) -> Result<(), RebootstrapError> {
    let result = {
        let _claim = state.native_replication.claim_machine(group).ok_or(RebootstrapError::Busy)?;
        let machine = Machine::new(state, group);
        let preserved = machine.begin(bundle)?;
        machine.drive(&preserved.recovery_id)
    };
    if matches!(result, Err(RebootstrapError::Waiting(_))) {
        // Nothing is lost by waiting: the journal holds the machine where it stopped.
        spawn_resume(state.clone(), group.0.clone());
    }
    result
}

/// Continues the rebootstrap of `group` the journal records, if any, from where a restart
/// found it. Nothing to do for a group with no rebootstrap (or one that had not reached its
/// barrier, which the restart discards). Blocks like [`run`].
pub fn resume(state: &Arc<DaemonState>, group: &FolderGroupId) -> Result<(), RebootstrapError> {
    let Some(_claim) = state.native_replication.claim_machine(group) else { return Ok(()) };
    let machine = Machine::new(state, group);
    let outcome = machine.read(|conn| {
        recover_after_restart(conn, &machine.recovery_root, group).map_err(RebootstrapError::from)
    })??;
    match outcome {
        RestartOutcome::Idle | RestartOutcome::Abandoned { .. } => {
            // No machine: only the replacement checkpoint of an earlier one may still be owed.
            machine.handle.block_on(seal_replacement_checkpoint(state, group));
            Ok(())
        }
        RestartOutcome::Blocked(reason) => Err(RebootstrapError::Blocked(format!("{reason:?}"))),
        RestartOutcome::Preserved(preserved)
        | RestartOutcome::Quarantining(preserved)
        | RestartOutcome::CatchingUp(preserved)
        | RestartOutcome::Replaying(preserved) => machine.drive(&preserved.recovery_id),
    }
}

/// How long a continued rebootstrap waits before it looks again at what it was waiting for.
const WAITING_RETRY: Duration = Duration::from_secs(5);

/// Continues a recorded rebootstrap of `group` in the background, once its folder is watched.
/// A machine that waits for the group's policy (it is loaded a moment after a restart) is
/// continued again until it ends.
pub(crate) fn spawn_resume(state: Arc<DaemonState>, group: String) {
    tokio::spawn(async move {
        let group = FolderGroupId(group);
        loop {
            let (state_for_run, group_for_run) = (state.clone(), group.clone());
            let outcome =
                tokio::task::spawn_blocking(move || resume(&state_for_run, &group_for_run)).await;
            match outcome {
                Ok(Ok(())) => return,
                Ok(Err(RebootstrapError::Waiting(why))) => {
                    tracing::debug!(group = %group.0, %why, "native rebootstrap: waiting");
                    tokio::time::sleep(WAITING_RETRY).await;
                }
                Ok(Err(error)) => {
                    tracing::warn!(group = %group.0, %error, "native rebootstrap: could not continue after the restart");
                    return;
                }
                Err(_) => return,
            }
        }
    });
}

struct Machine {
    state: Arc<DaemonState>,
    group: FolderGroupId,
    device: DeviceId,
    handle: tokio::runtime::Handle,
    hook: Option<Hook>,
    recovery_root: PathBuf,
    items_root: PathBuf,
}

impl Machine {
    fn new(state: &Arc<DaemonState>, group: &FolderGroupId) -> Self {
        Self {
            state: state.clone(),
            group: group.clone(),
            device: DeviceId(state.device_id.clone()),
            handle: tokio::runtime::Handle::current(),
            hook: state.native_replication.rebootstrap_hook(),
            recovery_root: crate::device_config::recovery_root(),
            items_root: crate::device_config::recovery_items_root(),
        }
    }

    fn fire(&self, point: Point) -> Result<(), Crash> {
        match &self.hook {
            Some(hook) => hook(point),
            None => Ok(()),
        }
    }

    /// `step` on a connection, without the writer gate: for steps that wait on other threads
    /// that write (the capture pass, the catch-up). A step that loses a race for SQLite's write
    /// lock is run again; every step of the machine is resumable.
    fn read<T>(&self, mut step: impl FnMut(&Connection) -> T) -> Result<T, RebootstrapError> {
        let mut out = None;
        self.state
            .replica_coordinator
            .database()
            .read::<_, SyncSqliteError>(|conn| {
                out = Some(step(conn));
                Ok(())
            })
            .map_err(RebootstrapError::from)?;
        Ok(out.expect("the step ran"))
    }

    /// `step` on a connection with the writer gate held: for steps that wait on nothing but
    /// the file system, so no other writer of this process interleaves with them.
    fn write<T>(&self, mut step: impl FnMut(&Connection) -> T) -> Result<T, RebootstrapError> {
        let mut out = None;
        self.state
            .replica_coordinator
            .database()
            .write::<_, SyncSqliteError>(|conn| {
                out = Some(step(conn));
                Ok(())
            })
            .map_err(RebootstrapError::from)?;
        Ok(out.expect("the step ran"))
    }

    fn sync_roots(&self) -> Vec<PathBuf> {
        self.state
            .replica_coordinator
            .link_repository()
            .list_links()
            .map(|links| {
                links.iter().filter_map(|link| link.folder_path().map(PathBuf::from)).collect()
            })
            .unwrap_or_default()
    }

    fn authority(&self) -> DaemonAuthority {
        DaemonAuthority { state: self.state.clone(), group: self.group.clone() }
    }

    fn preserve_context<'a>(
        &'a self,
        sync_roots: &'a [PathBuf],
        capture: &'a DaemonCapture,
        content: &'a DaemonContent,
        authority: &'a DaemonAuthority,
    ) -> PreserveContext<'a> {
        PreserveContext {
            recovery_root: &self.recovery_root,
            items_root: self.items_root.clone(),
            sync_roots,
            available_bytes: None,
            // Whether the folder was captured is what the pass reports while it runs; a
            // machine that is past that point has nothing partial to report.
            capture: CaptureBarrier::Completed,
            final_capture: capture,
            content,
            authority,
            now_unix: now_unix(),
        }
    }

    fn begin(
        &self,
        bundle: NativeBootstrap,
    ) -> Result<yadorilink_sync_sqlite::native_rebootstrap::Preserved, RebootstrapError> {
        let resolution = self.state.resolve_group_policy(self.group.as_str());
        let view = match &resolution {
            GroupPolicyResolution::Verified(policy) => PolicyView::Verified(policy),
            GroupPolicyResolution::Bootstrap => PolicyView::Genesis {
                service_key: self.state.authority.pinned_coordination_service_key(),
            },
            GroupPolicyResolution::Withhold => {
                return Err(RebootstrapError::Refused("the group's policy is withheld".into()))
            }
        };
        let truncations = self.state.native_replication.truncations_snapshot();
        let attached = self.state.native_replication.attached_devices();
        let connected: Vec<&str> = attached.iter().map(String::as_str).collect();
        let sync_roots = self.sync_roots();
        let capture = DaemonCapture::new(self);
        let content = DaemonContent::new(self, RECOVERY_FETCH_FROZEN_CAP);
        let authority = self.authority();
        let ctx = self.preserve_context(&sync_roots, &capture, &content, &authority);
        let result = self.retrying(|| {
            self.read(|conn| {
                begin_rebootstrap(
                    conn,
                    BeginRequest {
                        group: &self.group,
                        own_device: &self.device,
                        bundle: bundle.clone(),
                        policy: &view,
                        gate: LeaveIncremental { truncations: &truncations, connected: &connected },
                    },
                    &ctx,
                    &mut |point| self.fire(Point::Begin(point)),
                )
            })
        });
        match result? {
            Ok(preserved) => Ok(preserved),
            Err(BeginError::CandidateRefused(why)) => Err(RebootstrapError::Refused(why)),
            Err(BeginError::NotLeavingIncremental) => Err(RebootstrapError::Refused(
                "not every connected peer has truncated the history this device needs".into(),
            )),
            Err(BeginError::NotBetterThanCurrent) => Err(RebootstrapError::Refused(
                "the state already being rebootstrapped to covers this one".into(),
            )),
            Err(BeginError::TargetFixed(id)) => {
                Err(RebootstrapError::Refused(format!("rebootstrap {id} is already installing")))
            }
            Err(BeginError::Busy) => Err(RebootstrapError::Busy),
            Err(BeginError::Blocked(reason)) => {
                Err(RebootstrapError::Blocked(format!("{reason:?}")))
            }
            Err(BeginError::Crashed) => Err(RebootstrapError::Crashed),
            Err(BeginError::Store(error)) => Err(error.into()),
        }
    }

    /// Runs `step` again while it fails only because the database was busy.
    fn retrying<T>(
        &self,
        mut step: impl FnMut() -> Result<Result<T, BeginError>, RebootstrapError>,
    ) -> Result<Result<T, BeginError>, RebootstrapError> {
        use yadorilink_sqlite_runtime::SqlOperationError;
        let mut attempts = 0;
        loop {
            let outcome = step()?;
            match &outcome {
                Err(BeginError::Store(error)) if error.is_locked() && attempts < BUSY_RETRIES => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(200));
                }
                _ => return Ok(outcome),
            }
        }
    }

    /// Takes the machine from wherever the journal says it is to its end.
    fn drive(&self, recovery_id: &str) -> Result<(), RebootstrapError> {
        loop {
            let status = self.read(|conn| rebootstrap_status(conn, &self.group))??;
            let Some(status) = status.filter(|s| s.recovery_id == recovery_id) else {
                return self.finish_pending_work();
            };
            match status.state {
                RebootstrapState::Preserved | RebootstrapState::Quarantining => self.install()?,
                RebootstrapState::CatchingUp => {
                    self.adopt_rotated_author()?;
                    self.catch_up(recovery_id)?;
                }
                RebootstrapState::Replaying => {
                    self.adopt_rotated_author()?;
                    self.replay(recovery_id)?;
                    let finished =
                        self.write(|conn| finish_rebootstrap(conn, &self.group, recovery_id))??;
                    if !finished {
                        return Err(RebootstrapError::Failed(
                            "the replay ended with steps that have no outcome".into(),
                        ));
                    }
                }
                RebootstrapState::Blocked(reason) => {
                    return Err(RebootstrapError::Blocked(format!("{reason:?}")))
                }
                RebootstrapState::Planning
                | RebootstrapState::Capturing
                | RebootstrapState::Preserving => {
                    return Err(RebootstrapError::Failed(format!(
                        "the rebootstrap stopped before its barrier ({:?})",
                        status.state
                    )))
                }
            }
        }
    }

    fn install(&self) -> Result<(), RebootstrapError> {
        let Some(root) = DaemonQuarantineRoot::open(&self.state, &self.group) else {
            return Err(RebootstrapError::Blocked(
                "the folder is not being watched, so its originals cannot be set aside".into(),
            ));
        };
        let sync_roots = self.sync_roots();
        let capture = DaemonCapture::new(self);
        let content = DaemonContent::new(self, RECOVERY_FETCH_FROZEN_CAP);
        let authority = self.authority();
        let ctx = self.preserve_context(&sync_roots, &capture, &content, &authority);
        let closure_key =
            if authority.is_writer() { self.state.device_signing_key() } else { None };
        let install =
            InstallContext { preserve: &ctx, root: &root, closure_key: closure_key.as_ref() };
        let recovery_id = self
            .read(|conn| rebootstrap_status(conn, &self.group))??
            .map(|s| s.recovery_id)
            .ok_or_else(|| RebootstrapError::Failed("no rebootstrap to install".into()))?;
        let result = self.write(|conn| {
            install_rebootstrap(conn, &install, &self.group, &recovery_id, &mut |point| {
                self.fire(Point::Install(point))
            })
        })?;
        match result {
            Ok(_) => Ok(()),
            Err(InstallError::Busy) => Err(RebootstrapError::Busy),
            Err(InstallError::Crashed) => Err(RebootstrapError::Crashed),
            Err(InstallError::Blocked(reason)) => {
                Err(RebootstrapError::Blocked(format!("{reason:?}")))
            }
            Err(InstallError::Store(error)) => Err(error.into()),
            Err(other) => Err(RebootstrapError::Failed(format!("{other:?}"))),
        }
    }

    fn catch_up(&self, recovery_id: &str) -> Result<(), RebootstrapError> {
        let mut source = DaemonCatchUp {
            state: self.state.clone(),
            group: self.group.clone(),
            handle: self.handle.clone(),
        };
        let result = self.read(|conn| {
            catch_up(
                conn,
                &self.group,
                recovery_id,
                &mut source,
                CatchUpLimits::default(),
                now_unix(),
                &mut |point| self.fire(Point::Machine(point)),
            )
        })?;
        match result {
            Ok(report) => {
                tracing::info!(group = %self.group.0, passes = report.passes, end = ?report.end, "native rebootstrap: catch-up over");
                Ok(())
            }
            Err(error) => Err(replay_failure(error)),
        }
    }

    fn replay(&self, recovery_id: &str) -> Result<(), RebootstrapError> {
        // The policy that decides whether own intent may be replayed is loaded a moment after
        // a restart; a unit is never given up for want of it. Loaded is not the same as
        // complete: right after a restart the policy can be present with the chain of grants
        // not applied yet, naming no writer at all, and judging a unit against that set
        // would set the whole unit aside for good (the authority is asked once per unit and
        // an unreplayed unit stays unreplayed). No writer is not an answer to wait out
        // either, so it waits like the missing policy does, and is looked at again.
        match self.state.resolve_group_policy(self.group.as_str()) {
            GroupPolicyResolution::Withhold => {
                return Err(RebootstrapError::Waiting(
                    "the group's policy is not loaded yet".into(),
                ));
            }
            GroupPolicyResolution::Verified(policy) if policy.current_writers().is_empty() => {
                return Err(RebootstrapError::Waiting(
                    "the group's policy names no writer yet".into(),
                ));
            }
            _ => {}
        }
        let key = self
            .state
            .device_signing_key()
            .ok_or_else(|| RebootstrapError::Failed("this device has no signing key".into()))?;
        let author = self
            .state
            .replica_coordinator
            .open_local_author(&self.state.device_id, key)
            .map_err(|e| RebootstrapError::Failed(e.to_string()))?;
        let authority = self.authority();
        let result = self.write(|conn| {
            let local = LocalAuthor::of_key(&author);
            let ctx = ReplayContext {
                recovery_root: &self.recovery_root,
                authority: &authority,
                author: &local,
                now_unix: now_unix(),
            };
            replay_own_intent(conn, &ctx, &self.group, recovery_id, &mut |point| {
                self.fire(Point::Machine(point))
            })
        })?;
        match result {
            Ok(report) => {
                if !report.unreplayed_units.is_empty() {
                    tracing::warn!(
                        group = %self.group.0,
                        units = report.unreplayed_units.len(),
                        "native rebootstrap: some of this device's own changes were kept aside and not replayed; see `yadorilink preserved list`"
                    );
                }
                Ok(())
            }
            Err(error) => Err(replay_failure(error)),
        }
    }

    /// The install rotated this device's author incarnation in the database; the daemon's
    /// handle and its sidecar follow before anything signs.
    fn adopt_rotated_author(&self) -> Result<(), RebootstrapError> {
        self.state
            .replica_coordinator
            .adopt_current_author()
            .map_err(|e| RebootstrapError::Failed(e.to_string()))
    }

    /// What follows the end of a rebootstrap, and is safe to do again: the folder is scanned
    /// for what was edited during the freeze, the materializer wakes, items whose missing
    /// blocks have arrived are completed, and the replacement checkpoint is sealed so the
    /// closure of the incarnation this device left may travel with it.
    fn finish_pending_work(&self) -> Result<(), RebootstrapError> {
        self.state.replica_coordinator.notify_materialization_wake();
        let state = self.state.clone();
        let group = self.group.clone();
        self.handle.block_on(async move {
            if let Err(error) = rescan_group(&state, &group).await {
                tracing::warn!(group = %group.0, %error, "native rebootstrap: could not scan the folder after the rebootstrap");
            }
            // The deltas the replay authored are published like any local change, so peers
            // can be served the content they name.
            state.flush_pending_native_checkpoint_for_group(group.as_str()).await;
            crate::preserved_items::complete_unavailable_items(&state, &group).await;
            seal_replacement_checkpoint(&state, &group).await;
        });
        self.state.record_activity();
        Ok(())
    }
}

fn replay_failure(error: ReplayError) -> RebootstrapError {
    match error {
        ReplayError::Busy => RebootstrapError::Busy,
        ReplayError::Crashed => RebootstrapError::Crashed,
        ReplayError::Blocked(reason) => RebootstrapError::Blocked(format!("{reason:?}")),
        ReplayError::Store(error) => error.into(),
        ReplayError::NotRunnable(why) => RebootstrapError::Failed(why),
    }
}

/// Folds `group`'s folder into the index once, if its link is running.
async fn rescan_group(state: &Arc<DaemonState>, group: &FolderGroupId) -> Result<(), String> {
    let runtime = runtime_of(state, group.as_str()).ok_or("the folder is not being watched")?;
    runtime.capture_whole_group(group.as_str()).await
}

fn runtime_of(
    state: &Arc<DaemonState>,
    group: &str,
) -> Option<Arc<crate::link_runtime::LinkRuntime>> {
    let local_path = state
        .replica_coordinator
        .link_repository()
        .live_link_local_path_for_group(group)
        .ok()
        .flatten()?;
    state.links.runtime(&local_path)
}

/// Seals this device's state once every own unit of its rebootstraps has been replayed, and
/// marks the incarnations it left as covered by that checkpoint, which is what lets their
/// closure leave the device, only ever inside a bundle. A device that cannot reach the
/// group's authority, or that still holds an unreplayed unit, seals nothing and the closure
/// stays where it is.
pub(crate) async fn seal_replacement_checkpoint(state: &Arc<DaemonState>, group: &FolderGroupId) {
    let db = state.replica_coordinator.database();
    let (pending, held) = {
        let (db, group) = (db.clone(), group.clone());
        match tokio::task::spawn_blocking(move || {
            db.read::<_, SyncSqliteError>(|conn| {
                Ok((
                    yadorilink_sync_sqlite::native_closure::unexported_rotation_authors(
                        conn, &group,
                    )?,
                    yadorilink_sync_sqlite::native_rebootstrap_replay::unreplayed_units(
                        conn, &group,
                    )?,
                    rebootstrap_status(conn, &group)?.is_some(),
                ))
            })
        })
        .await
        {
            Ok(Ok((pending, units, running))) => (pending, !units.is_empty() || running),
            _ => return,
        }
    };
    if pending.is_empty() || held {
        return;
    }
    let sealed = match crate::native_recovery::seal_own_state(state, group).await {
        Ok(sealed) => sealed.checkpoint.checkpoint_hash().0,
        Err(reason) => {
            tracing::debug!(group = %group.0, ?reason, "native rebootstrap: the replacement checkpoint is not sealed yet");
            return;
        }
    };
    let group = group.clone();
    let marked = tokio::task::spawn_blocking(move || {
        db.write::<_, SyncSqliteError>(|conn| {
            for author in &pending {
                yadorilink_sync_sqlite::native_closure::mark_replacement_checkpoint(
                    conn, &group, author, sealed,
                )?;
            }
            Ok(())
        })
    })
    .await;
    if !matches!(marked, Ok(Ok(()))) {
        tracing::warn!("native rebootstrap: could not record the replacement checkpoint");
    }
}

// --- what the machine asks of its host ------------------------------------------------------------

/// Whether this device may author `path` of the group now: asked again before each unit of own
/// intent replays, and when the plan decides which originals are re-authored and which are set
/// aside.
pub(crate) struct DaemonAuthority {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) group: FolderGroupId,
}

/// Whether this device may author into `group` now: a writer of the group's verified policy,
/// or any member while the group has no policy yet. A group whose policy is withheld is none.
pub(crate) fn is_writer(state: &Arc<DaemonState>, group: &FolderGroupId) -> bool {
    match state.resolve_group_policy(group.as_str()) {
        GroupPolicyResolution::Verified(policy) => {
            policy.current_writers().iter().any(|writer| writer.device_id == state.device_id)
        }
        GroupPolicyResolution::Bootstrap => true,
        GroupPolicyResolution::Withhold => false,
    }
}

impl DaemonAuthority {
    fn is_writer(&self) -> bool {
        is_writer(&self.state, &self.group)
    }
}

impl ReassertAuthority for DaemonAuthority {
    fn classify(&self, _path: &SyncPath) -> Reassertability {
        match self.state.resolve_group_policy(self.group.as_str()) {
            GroupPolicyResolution::Withhold => Reassertability::PolicyWithheld,
            _ if self.is_writer() => Reassertability::Reassertable,
            _ => Reassertability::NotWriter,
        }
    }
}

/// The final capture pass: the normal local-capture seam over the whole folder, authoring under
/// the rebootstrap's capability while the group is otherwise frozen.
struct DaemonCapture {
    state: Arc<DaemonState>,
    group: FolderGroupId,
    handle: tokio::runtime::Handle,
}

impl DaemonCapture {
    fn new(machine: &Machine) -> Self {
        Self {
            state: machine.state.clone(),
            group: machine.group.clone(),
            handle: machine.handle.clone(),
        }
    }
}

impl FinalCapture for DaemonCapture {
    fn capture(&self, authority: &Arc<CaptureAuthority>) -> CaptureBarrier {
        let Some(runtime) = runtime_of(&self.state, self.group.as_str()) else {
            return CaptureBarrier::Partial { detail: "the folder is not being watched".into() };
        };
        let _pass = self
            .state
            .replica_coordinator
            .begin_capture_pass(self.group.as_str(), authority.clone());
        match self.handle.block_on(runtime.capture_whole_group(self.group.as_str())) {
            Ok(()) => CaptureBarrier::Completed,
            Err(detail) => CaptureBarrier::Partial { detail },
        }
    }
}

/// The bytes of versions the machine preserves: read from the block store, and fetched from the
/// connected peers when they are missing, within a total time cap.
pub(crate) struct DaemonContent {
    state: Arc<DaemonState>,
    group: String,
    handle: tokio::runtime::Handle,
    deadline: Instant,
}

impl DaemonContent {
    fn new(machine: &Machine, cap: Duration) -> Self {
        Self {
            state: machine.state.clone(),
            group: machine.group.0.clone(),
            handle: machine.handle.clone(),
            deadline: Instant::now() + cap,
        }
    }

    pub(crate) fn for_group(
        state: &Arc<DaemonState>,
        group: &FolderGroupId,
        cap: Duration,
    ) -> Self {
        Self {
            state: state.clone(),
            group: group.0.clone(),
            handle: tokio::runtime::Handle::current(),
            deadline: Instant::now() + cap,
        }
    }

    /// The whole of `version` when every block is held and intact.
    fn read_held(&self, version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        let mut bytes = Vec::with_capacity(version.size as usize);
        for block in &version.blocks {
            match self.state.block_store.get(&hex::encode(&block.hash.0)) {
                Ok(data) if data.len() == block.size as usize && sha256_is(&data, &block.hash) => {
                    bytes.extend_from_slice(&data);
                }
                Ok(_) | Err(_) => return Ok(None),
            }
        }
        Ok((bytes.len() as u64 == version.size).then_some(bytes))
    }

    /// Asks the connected peers for the blocks of `version` that are not held, until the cap.
    pub(crate) async fn fetch_missing(&self, version: &FileVersion) {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let mut offset = 0u64;
        let blocks: Vec<BlockInfo> = version
            .blocks
            .iter()
            .map(|block| {
                let info = BlockInfo { hash: block.hash.0.clone(), offset, size: block.size };
                offset += u64::from(block.size);
                info
            })
            .collect();
        let _ = tokio::time::timeout(
            remaining,
            crate::hydration::fetch_unindexed_blocks(&self.state, &self.group, &blocks),
        )
        .await;
    }

    pub(crate) fn read_after_fetch(&self, version: &FileVersion) -> Option<Vec<u8>> {
        self.read_held(version).ok().flatten()
    }
}

fn sha256_is(data: &[u8], hash: &BlockHash) -> bool {
    Sha256::digest(data)[..] == hash.0[..]
}

impl RecoveryContentSource for DaemonContent {
    fn read_version(&self, version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        if let Some(bytes) = self.read_held(version)? {
            return Ok(Some(bytes));
        }
        self.handle.block_on(self.fetch_missing(version));
        self.read_held(version)
    }

    fn held_blocks(
        &self,
        version: &FileVersion,
    ) -> Result<Vec<yadorilink_replica_domain::ids::BlockHash>, String> {
        let hashes: Vec<String> =
            version.blocks.iter().map(|block| hex::encode(&block.hash.0)).collect();
        let present =
            self.state.block_store.present_blocks(&hashes).map_err(|error| error.to_string())?;
        Ok(version
            .blocks
            .iter()
            .zip(present)
            .filter(|(_, held)| *held)
            .map(|(block, _)| block.hash.clone())
            .collect())
    }
}

/// The linked folder as the install reaches it: relative paths only, no link followed out of
/// the root, every operation admitted by the link's root lease.
struct DaemonQuarantineRoot {
    root: PathBuf,
    lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
}

impl DaemonQuarantineRoot {
    fn open(state: &Arc<DaemonState>, group: &FolderGroupId) -> Option<Self> {
        let local_path = state
            .replica_coordinator
            .link_repository()
            .live_link_local_path_for_group(group.as_str())
            .ok()
            .flatten()?;
        let runtime = state.links.runtime(&local_path)?;
        Some(Self { root: PathBuf::from(local_path), lease: runtime.root_lease().clone() })
    }

    /// The path of `relative` under the root, after checking that no component of its parent
    /// directory is a link: `Ok(None)` when a parent does not exist.
    fn confined(&self, relative: &str) -> Result<Option<PathBuf>, String> {
        yadorilink_sync_sqlite::native_rebootstrap_recovery::validate_manifest_path(relative)
            .map_err(|e| e.to_string())?;
        let mut current = self.root.clone();
        let mut components = relative.split('/').peekable();
        while let Some(component) = components.next() {
            current.push(component);
            if components.peek().is_none() {
                break;
            }
            match std::fs::symlink_metadata(&current) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(format!("{relative}: a parent is not a directory")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(Some(current))
    }

    fn observe_at(path: &Path) -> Result<Observed, String> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Observed::Absent),
            Err(e) => return Err(e.to_string()),
        };
        let kind = meta.file_type();
        if kind.is_symlink() {
            let target = std::fs::read_link(path).map_err(|e| e.to_string())?;
            return Ok(Observed::Symlink {
                target: target.to_string_lossy().into_owned().into_bytes(),
            });
        }
        if kind.is_dir() {
            return Ok(Observed::Directory);
        }
        if !kind.is_file() {
            return Ok(Observed::Other);
        }
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        Ok(Observed::File { size: bytes.len() as u64, sha256: Sha256::digest(&bytes).into() })
    }
}

impl QuarantineRoot for DaemonQuarantineRoot {
    fn observe(&self, path: &str) -> Result<Observed, String> {
        let _op = self.lease.begin_operation().map_err(|e| e.to_string())?;
        match self.confined(path)? {
            Some(full) => Self::observe_at(&full),
            None => Ok(Observed::Absent),
        }
    }

    fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let _op = self.lease.begin_operation().map_err(|e| e.to_string())?;
        let full = self.confined(path)?.ok_or_else(|| format!("{path} does not exist"))?;
        if !std::fs::symlink_metadata(&full).map_err(|e| e.to_string())?.is_file() {
            return Err(format!("{path} is not a regular file"));
        }
        std::fs::read(full).map_err(|e| e.to_string())
    }

    fn remove(&self, path: &str, expected: &Observed) -> Result<(), String> {
        use yadorilink_root_authority::reserved_namespace::{
            artefact_component_name, ArtefactKind,
        };
        let _op = self.lease.begin_operation().map_err(|e| e.to_string())?;
        let Some(full) = self.confined(path)? else { return Ok(()) };
        // Compare-then-unlink by name is not atomic: the user could save in between. The
        // object is renamed to a private name in its own directory first, so it cannot be
        // written under its old name, and is checked there.
        let private = full.with_file_name(
            artefact_component_name(
                ArtefactKind::Preimage,
                &hex::encode(rand::random::<[u8; 8]>()),
            )
            .map_err(|e| e.to_string())?,
        );
        match std::fs::rename(&full, &private) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.to_string()),
        }
        let renamed = Self::observe_at(&private)?;
        if renamed == *expected {
            return if matches!(renamed, Observed::Directory) {
                std::fs::rename(&private, &full).map_err(|e| e.to_string())
            } else {
                std::fs::remove_file(&private).map_err(|e| e.to_string())
            };
        }
        // Not what the plan saw any more: the name is given back so the next attempt sees
        // the new content and saves it first.
        if std::fs::symlink_metadata(&full).is_err() {
            std::fs::rename(&private, &full).map_err(|e| e.to_string())?;
        }
        Err(format!("{path} changed while it was being removed"))
    }
}

/// One awaited incremental pass over the live peer connections.
struct DaemonCatchUp {
    state: Arc<DaemonState>,
    group: FolderGroupId,
    handle: tokio::runtime::Handle,
}

impl CatchUpSource for DaemonCatchUp {
    fn pass(&mut self, cap: Duration) -> Result<CatchUpPass, String> {
        let obtained =
            self.handle.block_on(self.state.native_replication.catch_up_pass(&self.group, cap));
        Ok(CatchUpPass { obtained })
    }
}
