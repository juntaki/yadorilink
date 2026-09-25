//! The desktop account window --
//! view deletion status, request/confirm/cancel deletion, and export a copy
//! of your coordination-plane records, without a terminal; PLUS the
//! account-level, cross-device concerns this window has grown into the
//! natural home for: every device registered on this account (not just
//! ones sharing a currently-linked folder -- see `home_window.rs`'s own,
//! narrower Devices section), every ACL edge across every folder this
//! account can see, every request waiting for this account's approval
//! across every owned folder, and every not-yet-redeemed invite this
//! account has minted. "Who can see/manage what across this whole
//! account", distinct from Home's per-folder Share window, which shows the
//! same three listings narrowed to one already-open folder. Launched as its
//! own process (`--window account`) from the tray, mirroring the onboarding
//! window's separate-process model.
//!
//! Same "pure machine + thin renderer + off-thread executor" discipline as
//! `crate::onboarding`: `step` and the `*_to_event` mappers are unit-tested
//! here; the eframe screen is `cargo check`-gated only (there is no display
//! server in CI). Every coordination/daemon call goes through
//! `yadorilink_client_core::ops::{account,devices,shares}` -- the single
//! implementation the CLI uses too -- so the app and CLI can never diverge
//! on what any of this does. This module has no code path
//! that deletes a local folder or a local file: every mutation here is
//! either an export to a file under this device's own config dir, or a
//! coordination-plane/daemon call already exercised by an existing CLI
//! command.
//!
//! The mutating actions added for the cross-device sections are
//! deliberately less capable than their per-folder counterparts in
//! `share_window.rs`: revoking an ACL edge or denying a request here never
//! offers the durability-override retry `share_window.rs` offers (a
//! refusal is reported as a plain failure, pointing at the per-folder Share
//! window). That is a scope decision, not an oversight -- an account-wide
//! listing is the wrong place to introduce a second implementation of an
//! override flow that already has exactly one home.

use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use eframe::egui;
use yadorilink_client_core::ops::shares::{self as share, RevokeAttempt, RevokeEdgeOutcome};
use yadorilink_client_core::ops::{account, devices as device};
use yadorilink_client_core::wording::LOCAL_FIRST_NOTICE;

use crate::onboarding::executor::EventSink;
use crate::onboarding::machine::OpStatus;
use crate::share_access;

/// The app's view of where the account is in the deletion lifecycle -- the
/// UI-facing projection of coordination-worker's `DeletionStatus`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Active,
    Requested,
    Grace {
        remaining_secs: i64,
        grace_expires_at_unix: i64,
    },
    /// A state name this build does not model -- surfaced verbatim rather than
    /// guessed at.
    Unknown(String),
}

pub fn lifecycle_from_status(status: &account::DeletionStatus) -> Lifecycle {
    match status.state.as_str() {
        "active" => Lifecycle::Active,
        "requested" => Lifecycle::Requested,
        "grace" => Lifecycle::Grace {
            remaining_secs: status.remaining_secs.unwrap_or(0).max(0),
            grace_expires_at_unix: status.grace_expires_at_unix.unwrap_or(0),
        },
        other => Lifecycle::Unknown(other.to_string()),
    }
}

/// A cross-folder access snapshot: every ACL edge, every request waiting
/// for this account's approval, and every not-yet-redeemed invite this
/// account can see -- fetched together for the same reason `Access` in
/// `share_window.rs` is: so the panel never renders a half-loaded mixture
/// of one listing's answer and another's.
#[derive(Clone, Debug, PartialEq)]
pub struct AccessOverview {
    pub edges: Vec<share::ShareEdgeInfo>,
    pub pending: Vec<share::PendingApproval>,
    pub invites: Vec<share::PendingInviteInfo>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct State {
    pub status: OpStatus,
    /// None until the first status load completes.
    pub lifecycle: Option<Lifecycle>,
    /// The one-time confirmation token returned by a request, shown so the
    /// user can confirm; also pre-fills `confirm_input`.
    pub confirmation_token: Option<String>,
    /// The token the user will submit to confirm (editable in case they came
    /// back to a request made earlier / from the CLI).
    pub confirm_input: String,
    /// A transient success line (export written, deletion cancelled, a
    /// device removed, access revoked, a request approved/denied, an
    /// invite cancelled,...).
    pub notice: Option<String>,
    /// Every device registered on this account -- `None` until the first
    /// load completes.
    pub devices: Option<Vec<device::DeviceInfo>>,
    pub devices_status: OpStatus,
    /// The cross-folder ACL/pending/invites snapshot -- `None` until the
    /// first load completes.
    pub access: Option<AccessOverview>,
    pub access_status: OpStatus,
    /// A transient failure line for one of the per-row mutations below
    /// (device removal, edge revoke, approve/deny, invite cancel) --
    /// separate from `notice`, which this same set of actions also uses for
    /// success, so a failure never gets overwritten by an unrelated success
    /// line still on screen from a moment earlier.
    pub action_error: Option<String>,
    /// Keys for mutations currently in flight, so only the row that was
    /// clicked shows a spinner / has its own button disabled, rather than
    /// the whole window: `"device:<id>"`, `"edge:<id>"`,
    /// `"approve:<group_id>:<device_id>"`, `"deny:<group_id>:<device_id>"`,
    /// `"invite:<id>"`.
    pub busy: HashSet<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            status: OpStatus::Idle,
            lifecycle: None,
            confirmation_token: None,
            confirm_input: String::new(),
            notice: None,
            devices: None,
            devices_status: OpStatus::Idle,
            access: None,
            access_status: OpStatus::Idle,
            action_error: None,
            busy: HashSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    StatusRequested,
    StatusLoaded(Lifecycle),
    StatusFailed(String),
    RequestDeletion,
    DeletionRequested { confirmation_token: String },
    RequestFailed(String),
    ConfirmInputChanged(String),
    ConfirmDeletion,
    DeletionConfirmed(Lifecycle),
    ConfirmFailed(String),
    CancelDeletion,
    DeletionCancelled(Lifecycle),
    CancelFailed(String),
    ExportRequested,
    Exported(String),
    ExportFailed(String),

    DevicesRequested,
    DevicesLoaded(Vec<device::DeviceInfo>),
    DevicesFailed(String),
    RemoveDeviceRequested { device_id: String },
    DeviceRemoved { device_id: String },
    RemoveDeviceFailed { device_id: String, msg: String },

    AccessRequested,
    // Boxed for the same reason `share_window.rs`'s `AccessFetched` is:
    // this carries three whole listings at once.
    AccessLoaded(Box<AccessOverview>),
    AccessFailed(String),

    RevokeEdgeRequested { edge_id: String },
    EdgeRevoked { edge_id: String },
    RevokeEdgeFailed { edge_id: String, msg: String },

    ApproveRequested { group_id: String, device_id: String, group_name: String },
    ApproveDone { group_id: String, device_id: String, group_name: String, result: String },
    ApproveFailed { group_id: String, device_id: String, msg: String },

    DenyRequested { group_id: String, device_id: String, group_name: String },
    DenyDone { group_id: String, device_id: String },
    DenyFailed { group_id: String, device_id: String, msg: String },

    CancelInviteRequested { invite_id: String },
    InviteCancelled { invite_id: String },
    CancelInviteFailed { invite_id: String, msg: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    LoadStatus,
    Request,
    Confirm { confirmation_token: String },
    Cancel,
    Export,

    LoadDevices,
    RemoveDevice { device_id: String },
    LoadAccess,
    RevokeEdge { edge_id: String },
    Approve { group_id: String, device_id: String, group_name: String },
    Deny { group_id: String, device_id: String, group_name: String },
    CancelInvite { invite_id: String },
}

/// Pure transition. Mid-operation events (while `status == Working`) that would
/// start another operation are no-ops, so a double click can't fire two
/// requests; result events always land regardless of status.
pub fn step(mut state: State, event: Event) -> (State, Vec<Effect>) {
    match event {
        Event::StatusRequested if state.status != OpStatus::Working => {
            state.status = OpStatus::Working;
            state.notice = None;
            return (state, vec![Effect::LoadStatus]);
        }
        Event::StatusLoaded(lifecycle) => {
            state.lifecycle = Some(lifecycle);
            state.status = OpStatus::Idle;
        }
        Event::StatusFailed(msg) => state.status = OpStatus::Failed(msg),

        Event::RequestDeletion if state.status != OpStatus::Working => {
            state.status = OpStatus::Working;
            state.notice = None;
            return (state, vec![Effect::Request]);
        }
        Event::DeletionRequested { confirmation_token } => {
            state.confirmation_token = Some(confirmation_token.clone());
            state.confirm_input = confirmation_token;
            state.lifecycle = Some(Lifecycle::Requested);
            state.status = OpStatus::Idle;
        }
        Event::RequestFailed(msg) => state.status = OpStatus::Failed(msg),

        Event::ConfirmInputChanged(value) if state.status != OpStatus::Working => {
            state.confirm_input = value;
        }
        Event::ConfirmDeletion if state.status != OpStatus::Working => {
            let token = state.confirm_input.trim().to_string();
            if !token.is_empty() {
                state.status = OpStatus::Working;
                state.notice = None;
                return (state, vec![Effect::Confirm { confirmation_token: token }]);
            }
        }
        Event::DeletionConfirmed(lifecycle) => {
            state.lifecycle = Some(lifecycle);
            state.confirmation_token = None;
            state.status = OpStatus::Idle;
        }
        Event::ConfirmFailed(msg) => state.status = OpStatus::Failed(msg),

        Event::CancelDeletion if state.status != OpStatus::Working => {
            state.status = OpStatus::Working;
            state.notice = None;
            return (state, vec![Effect::Cancel]);
        }
        Event::DeletionCancelled(lifecycle) => {
            state.lifecycle = Some(lifecycle);
            state.confirmation_token = None;
            state.confirm_input = String::new();
            state.notice = Some("Account deletion cancelled. Your account is active.".to_string());
            state.status = OpStatus::Idle;
        }
        Event::CancelFailed(msg) => state.status = OpStatus::Failed(msg),

        Event::ExportRequested if state.status != OpStatus::Working => {
            state.status = OpStatus::Working;
            state.notice = None;
            return (state, vec![Effect::Export]);
        }
        Event::Exported(path) => {
            state.notice = Some(format!("Exported your account data to {path}."));
            state.status = OpStatus::Idle;
        }
        Event::ExportFailed(msg) => state.status = OpStatus::Failed(msg),

        Event::DevicesRequested if state.devices_status != OpStatus::Working => {
            state.devices_status = OpStatus::Working;
            return (state, vec![Effect::LoadDevices]);
        }
        Event::DevicesLoaded(devices) => {
            state.devices = Some(devices);
            state.devices_status = OpStatus::Idle;
        }
        Event::DevicesFailed(msg) => state.devices_status = OpStatus::Failed(msg),

        Event::RemoveDeviceRequested { device_id } => {
            let key = format!("device:{device_id}");
            if state.busy.insert(key) {
                state.action_error = None;
                return (state, vec![Effect::RemoveDevice { device_id }]);
            }
        }
        Event::DeviceRemoved { device_id } => {
            state.busy.remove(&format!("device:{device_id}"));
            if let Some(devices) = &mut state.devices {
                devices.retain(|d| d.device_id != device_id);
            }
            state.notice = Some(format!("Removed device {device_id}."));
        }
        Event::RemoveDeviceFailed { device_id, msg } => {
            state.busy.remove(&format!("device:{device_id}"));
            state.action_error = Some(msg);
        }

        Event::AccessRequested if state.access_status != OpStatus::Working => {
            state.access_status = OpStatus::Working;
            return (state, vec![Effect::LoadAccess]);
        }
        Event::AccessLoaded(access) => {
            state.access = Some(*access);
            state.access_status = OpStatus::Idle;
        }
        Event::AccessFailed(msg) => state.access_status = OpStatus::Failed(msg),

        Event::RevokeEdgeRequested { edge_id } => {
            let key = format!("edge:{edge_id}");
            if state.busy.insert(key) {
                state.action_error = None;
                return (state, vec![Effect::RevokeEdge { edge_id }]);
            }
        }
        Event::EdgeRevoked { edge_id } => {
            state.busy.remove(&format!("edge:{edge_id}"));
            if let Some(access) = &mut state.access {
                access.edges.retain(|e| e.edge_id != edge_id);
            }
            state.notice = Some("Access revoked.".to_string());
        }
        Event::RevokeEdgeFailed { edge_id, msg } => {
            state.busy.remove(&format!("edge:{edge_id}"));
            state.action_error = Some(msg);
        }

        Event::ApproveRequested { group_id, device_id, group_name } => {
            let key = format!("approve:{group_id}:{device_id}");
            if state.busy.insert(key) {
                state.action_error = None;
                return (state, vec![Effect::Approve { group_id, device_id, group_name }]);
            }
        }
        Event::ApproveDone { group_id, device_id, group_name, result } => {
            state.busy.remove(&format!("approve:{group_id}:{device_id}"));
            if let Some(access) = &mut state.access {
                access.pending.retain(|p| !(p.group_id == group_id && p.device_id == device_id));
            }
            state.notice = Some(yadorilink_client_core::wording::approve_result_line(
                &result,
                &device_id,
                &group_name,
            ));
        }
        Event::ApproveFailed { group_id, device_id, msg } => {
            state.busy.remove(&format!("approve:{group_id}:{device_id}"));
            state.action_error = Some(msg);
        }

        Event::DenyRequested { group_id, device_id, group_name } => {
            let key = format!("deny:{group_id}:{device_id}");
            if state.busy.insert(key) {
                state.action_error = None;
                return (state, vec![Effect::Deny { group_id, device_id, group_name }]);
            }
        }
        Event::DenyDone { group_id, device_id } => {
            state.busy.remove(&format!("deny:{group_id}:{device_id}"));
            if let Some(access) = &mut state.access {
                access.pending.retain(|p| !(p.group_id == group_id && p.device_id == device_id));
            }
            state.notice = Some(format!("Denied {device_id}'s request."));
        }
        Event::DenyFailed { group_id, device_id, msg } => {
            state.busy.remove(&format!("deny:{group_id}:{device_id}"));
            state.action_error = Some(msg);
        }

        Event::CancelInviteRequested { invite_id } => {
            let key = format!("invite:{invite_id}");
            if state.busy.insert(key) {
                state.action_error = None;
                return (state, vec![Effect::CancelInvite { invite_id }]);
            }
        }
        Event::InviteCancelled { invite_id } => {
            state.busy.remove(&format!("invite:{invite_id}"));
            if let Some(access) = &mut state.access {
                access.invites.retain(|i| i.invite_id != invite_id);
            }
            state.notice = Some("Invite cancelled.".to_string());
        }
        Event::CancelInviteFailed { invite_id, msg } => {
            state.busy.remove(&format!("invite:{invite_id}"));
            state.action_error = Some(msg);
        }

        // Out-of-status or otherwise inapplicable events: no-op.
        _ => {}
    }
    (state, Vec::new())
}

// ---- executor -------------------------------------------------------------

/// Run an account effect off the UI thread and post the result event back.
pub fn spawn(effect: Effect, sink: EventSink<Event>) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                sink.send(runtime_error_event(&effect, format!("runtime error: {e}")));
                return;
            }
        };
        let event = runtime.block_on(execute(effect));
        sink.send(event);
    });
}

/// Fetches the cross-folder access snapshot in one background task -- the
/// same "read everything the panel shows together" shape
/// `share_window.rs`'s own `spawn_access_fetch` uses, extended to a third
/// listing (invites). Unlike that per-folder fetch, `pending_approvals` here
/// is never conditioned on "does this account own the group being looked
/// at" -- there is no single group in view, so every request this account
/// has to decide on, across every group it owns, belongs on screen.
async fn load_access() -> Result<AccessOverview, String> {
    let edges = share::list_shares_resolved().await.map_err(|e| e.to_string())?;
    let pending = share::pending_approvals().await.map_err(|e| e.to_string())?;
    let invites = share::list_invites_resolved().await.map_err(|e| e.to_string())?;
    Ok(AccessOverview { edges, pending, invites })
}

async fn execute(effect: Effect) -> Event {
    match effect {
        Effect::LoadStatus => status_to_event(account::deletion_status().await),
        Effect::Request => request_to_event(account::request_deletion().await),
        Effect::Confirm { confirmation_token } => {
            confirm_to_event(account::confirm_deletion(confirmation_token).await)
        }
        Effect::Cancel => cancel_to_event(account::cancel_deletion().await),
        Effect::Export => export_to_event(account::export_account_json().await),

        Effect::LoadDevices => match device::list_devices().await {
            Ok(devices) => Event::DevicesLoaded(devices),
            Err(e) => Event::DevicesFailed(e.to_string()),
        },
        // `force: false` always -- the same data-loss override
        // `home_window.rs`'s Devices section also never offers itself
        // (see `actions::remove_device`'s own doc comment); a device that
        // genuinely needs the override is removed from there or the CLI.
        Effect::RemoveDevice { device_id } => {
            match crate::actions::remove_device(device_id.clone(), false).await {
                Ok(()) => Event::DeviceRemoved { device_id },
                Err(e) => Event::RemoveDeviceFailed { device_id, msg: e.to_string() },
            }
        }

        Effect::LoadAccess => match load_access().await {
            Ok(access) => Event::AccessLoaded(Box::new(access)),
            Err(msg) => Event::AccessFailed(msg),
        },
        // Plain revoke only -- see this module's top doc comment on why the
        // durability override stays exclusive to `share_window.rs`.
        Effect::RevokeEdge { edge_id } => match share::revoke_edge(&edge_id, false).await {
            // An edge that is already gone is the end state asked for.
            Ok(RevokeEdgeOutcome::Revoked(_) | RevokeEdgeOutcome::AlreadyRevoked) => {
                Event::EdgeRevoked { edge_id }
            }
            Err(e) => Event::RevokeEdgeFailed { edge_id, msg: e.to_string() },
        },
        Effect::Approve { group_id, device_id, group_name } => {
            match share::approve_resolved(&group_id, &device_id).await {
                Ok(result) => Event::ApproveDone { group_id, device_id, group_name, result },
                Err(e) => Event::ApproveFailed { group_id, device_id, msg: e.to_string() },
            }
        }
        // `try_revoke_resolved`, not the CLI's name-resolving `deny` --
        // this row already carries `group_id`, so there is no name to
        // resolve, exactly `share_window.rs`'s own `Action::Deny` handling.
        // A `NotDurable` refusal is reported as a plain failure, same
        // reasoning as `share_window.rs`'s: the daemon's readiness gate
        // does not apply to a not-yet-active edge, so hitting it here means
        // a concurrent admission raced this denial -- a real removal,
        // which belongs in the per-folder Share window that can offer its
        // override with the member's name in front of it.
        Effect::Deny { group_id, device_id, group_name: _ } => {
            match share::try_revoke_resolved(group_id.clone(), device_id.clone(), false).await {
                Ok(RevokeAttempt::Committed(_)) => Event::DenyDone { group_id, device_id },
                Ok(RevokeAttempt::NotDurable { message, .. }) => {
                    Event::DenyFailed { group_id, device_id, msg: message }
                }
                Err(e) => Event::DenyFailed { group_id, device_id, msg: e.to_string() },
            }
        }
        Effect::CancelInvite { invite_id } => match share::cancel_invite(&invite_id).await {
            Ok(()) => Event::InviteCancelled { invite_id },
            Err(e) => Event::CancelInviteFailed { invite_id, msg: e.to_string() },
        },
    }
}

fn runtime_error_event(effect: &Effect, msg: String) -> Event {
    match effect {
        Effect::LoadStatus => Event::StatusFailed(msg),
        Effect::Request => Event::RequestFailed(msg),
        Effect::Confirm { .. } => Event::ConfirmFailed(msg),
        Effect::Cancel => Event::CancelFailed(msg),
        Effect::Export => Event::ExportFailed(msg),
        Effect::LoadDevices => Event::DevicesFailed(msg),
        Effect::RemoveDevice { device_id } => {
            Event::RemoveDeviceFailed { device_id: device_id.clone(), msg }
        }
        Effect::LoadAccess => Event::AccessFailed(msg),
        Effect::RevokeEdge { edge_id } => Event::RevokeEdgeFailed { edge_id: edge_id.clone(), msg },
        Effect::Approve { group_id, device_id, .. } => {
            Event::ApproveFailed { group_id: group_id.clone(), device_id: device_id.clone(), msg }
        }
        Effect::Deny { group_id, device_id, .. } => {
            Event::DenyFailed { group_id: group_id.clone(), device_id: device_id.clone(), msg }
        }
        Effect::CancelInvite { invite_id } => {
            Event::CancelInviteFailed { invite_id: invite_id.clone(), msg }
        }
    }
}

fn status_to_event(
    result: Result<account::DeletionStatus, yadorilink_client_core::CoreError>,
) -> Event {
    match result {
        Ok(status) => Event::StatusLoaded(lifecycle_from_status(&status)),
        Err(e) => Event::StatusFailed(e.to_string()),
    }
}

fn request_to_event(
    result: Result<account::DeletionRequested, yadorilink_client_core::CoreError>,
) -> Event {
    match result {
        Ok(requested) => {
            Event::DeletionRequested { confirmation_token: requested.confirmation_token }
        }
        Err(e) => Event::RequestFailed(e.to_string()),
    }
}

fn confirm_to_event(
    result: Result<account::DeletionStatus, yadorilink_client_core::CoreError>,
) -> Event {
    match result {
        Ok(status) => Event::DeletionConfirmed(lifecycle_from_status(&status)),
        Err(e) => Event::ConfirmFailed(e.to_string()),
    }
}

fn cancel_to_event(
    result: Result<account::DeletionStatus, yadorilink_client_core::CoreError>,
) -> Event {
    match result {
        Ok(status) => Event::DeletionCancelled(lifecycle_from_status(&status)),
        Err(e) => Event::CancelFailed(e.to_string()),
    }
}

/// Maps a successful export to a written file under this device's config dir
/// (revealed in the file manager), mirroring `actions::export_diagnostics`.
/// Writing the export is a create/write of the user's own data -- no local
/// folder is ever deleted here.
fn export_to_event(result: Result<String, yadorilink_client_core::CoreError>) -> Event {
    let pretty = match result {
        Ok(json) => json,
        Err(e) => return Event::ExportFailed(e.to_string()),
    };
    let path = default_export_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Event::ExportFailed(e.to_string());
        }
    }
    if let Err(e) = std::fs::write(&path, pretty) {
        return Event::ExportFailed(e.to_string());
    }
    let _ = opener::reveal(&path);
    Event::Exported(path.to_string_lossy().to_string())
}

fn default_export_path() -> std::path::PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::ipc_client::config_dir_public().join(format!("account-export-{now}.json"))
}

// ---- window ---------------------------------------------------------------

const ACCENT: egui::Color32 = egui::Color32::from_rgb(0xE2, 0x4A, 0x33);

/// Entry point for `--window account`. Must run on the process main thread.
pub fn run_account() -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 760.0])
            .with_title("YadoriLink — Account"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Account",
        options,
        Box::new(move |cc| {
            crate::fonts::install(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(AccountApp::new(rx, sink)))
        }),
    )
}

struct AccountApp {
    state: State,
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    status_fetch_started: bool,
    /// Both cross-device listings are kicked off once, on the first frame,
    /// alongside `status_fetch_started` -- independent of deletion status,
    /// so a slow/failed deletion-status load never holds up the Devices/
    /// Access sections (see `render_body`'s own ordering).
    cross_device_fetch_started: bool,
}

impl AccountApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        AccountApp {
            state: State::default(),
            rx,
            sink,
            status_fetch_started: false,
            cross_device_fetch_started: false,
        }
    }

    fn apply(&mut self, event: Event) {
        let (next, effects) = step(self.state.clone(), event);
        self.state = next;
        for effect in effects {
            spawn(effect, self.sink.clone());
        }
    }
}

impl eframe::App for AccountApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.rx.try_recv() {
            self.apply(event);
        }
        if !self.status_fetch_started {
            self.status_fetch_started = true;
            self.apply(Event::StatusRequested);
        }
        if !self.cross_device_fetch_started {
            self.cross_device_fetch_started = true;
            self.apply(Event::DevicesRequested);
            self.apply(Event::AccessRequested);
        }

        let mut pending: Vec<Event> = Vec::new();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("Your account");
            ui.add_space(8.0);
            ui.label(LOCAL_FIRST_NOTICE);
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(10.0);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                self.render_body(ui, &mut pending);
            });
        });
        for event in pending {
            self.apply(event);
        }
    }
}

impl AccountApp {
    fn render_body(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        if let OpStatus::Failed(msg) = &self.state.status {
            ui.label(
                egui::RichText::new(format!("Something went wrong: {msg}"))
                    .color(egui::Color32::from_rgb(0xc0, 0x39, 0x2b)),
            );
            ui.add_space(6.0);
            if ui.button("Reload status").clicked() {
                pending.push(Event::StatusRequested);
            }
            ui.add_space(10.0);
        }

        if let Some(notice) = &self.state.notice {
            ui.label(egui::RichText::new(notice).color(ACCENT));
            ui.add_space(8.0);
        }
        if let Some(err) = &self.state.action_error {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!("That didn't go through: {err}"),
            );
            ui.add_space(8.0);
        }

        // The cross-device sections below never wait on deletion status --
        // that load can be slow or fail independently, and none of these
        // sections need it.
        self.render_devices(ui, pending);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_access(ui, pending);

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);

        let working = self.state.status == OpStatus::Working;
        if working && self.state.lifecycle.is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading account status…");
            });
            return;
        }

        // Export is available regardless of deletion state.
        ui.label(egui::RichText::new("Data export").strong());
        ui.label("Download a machine-readable copy of your coordination-plane records.");
        if ui.add_enabled(!working, egui::Button::new("Export my data")).clicked() {
            pending.push(Event::ExportRequested);
        }
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);

        ui.label(egui::RichText::new("Delete account").strong());
        match self.state.lifecycle.clone().unwrap_or(Lifecycle::Active) {
            Lifecycle::Active => self.render_active(ui, pending, working),
            Lifecycle::Requested => self.render_requested(ui, pending, working),
            Lifecycle::Grace { remaining_secs, .. } => {
                self.render_grace(ui, pending, working, remaining_secs)
            }
            Lifecycle::Unknown(state) => {
                ui.label(format!("Account deletion state: {state}."));
            }
        }
    }

    /// Every device registered on this account -- unscoped by folder
    /// sharing, unlike Home's own Devices section (which only ever shows a
    /// device that shares a currently-linked folder with this one). A
    /// device registered but not yet linked to anything shared appears
    /// here and nowhere else in this app.
    fn render_devices(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.label(egui::RichText::new("Your devices").strong());
        match (&self.state.devices, &self.state.devices_status) {
            (None, OpStatus::Failed(msg)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                    format!("Could not load your devices: {msg}"),
                );
                return;
            }
            (None, _) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading devices…");
                });
                return;
            }
            (Some(devices), _) if devices.is_empty() => {
                ui.label(egui::RichText::new("No devices registered yet.").weak());
                return;
            }
            (Some(_), _) => {}
        }
        let devices = self.state.devices.clone().unwrap_or_default();
        let mut remove_clicked: Option<(String, String)> = None;
        for d in &devices {
            let key = format!("device:{}", d.device_id);
            let busy = self.state.busy.contains(&key);
            ui.horizontal(|ui| {
                let dot = if d.online { "●" } else { "○" };
                let dot_color = if d.online {
                    egui::Color32::from_rgb(0x2e, 0x9e, 0x5b)
                } else {
                    ui.visuals().weak_text_color()
                };
                ui.colored_label(dot_color, dot);
                ui.label(&d.device_name);
                ui.label(egui::RichText::new(&d.device_id).weak().small().monospace());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!busy, egui::Button::new("Remove…")).clicked() {
                        remove_clicked = Some((d.device_id.clone(), d.device_name.clone()));
                    }
                    if busy {
                        ui.spinner();
                    }
                });
            });
        }
        // No rename capability exists on this coordination plane
        // (`yadorilink device` has `register`/`list`/`remove` only), same
        // confirmed gap `home_window.rs`'s own Devices section documents --
        // this section deliberately offers no rename control either.
        if let Some((device_id, device_name)) = remove_clicked {
            let confirmed = rfd::MessageDialog::new()
                .set_title("Remove this device?")
                .set_description(format!(
                    "{device_name}\n\nThis revokes its access to every folder group at once. \
                     A currently-connected session on that device is disconnected promptly."
                ))
                .set_buttons(rfd::MessageButtons::OkCancel)
                .show()
                == rfd::MessageDialogResult::Ok;
            if confirmed {
                pending.push(Event::RemoveDeviceRequested { device_id });
            }
        }
    }

    /// The cross-folder access snapshot: every ACL edge, every request
    /// waiting for this account's approval, and every invite this account
    /// has minted, none of it narrowed to one already-open folder.
    fn render_access(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.label(egui::RichText::new("Access across your folders").strong());
        match (&self.state.access, &self.state.access_status) {
            (None, OpStatus::Failed(msg)) => {
                ui.colored_label(
                    egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                    format!("Could not load your sharing settings: {msg}"),
                );
                return;
            }
            (None, _) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading access…");
                });
                return;
            }
            (Some(_), _) => {}
        }
        let access = self.state.access.clone().unwrap();

        if access.edges.is_empty() {
            ui.label(egui::RichText::new("No one has access to any of your folders yet.").weak());
        }
        let mut revoke_clicked: Option<(String, String)> = None;
        for edge in &access.edges {
            let key = format!("edge:{}", edge.edge_id);
            let busy = self.state.busy.contains(&key);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&edge.group_name).strong());
                ui.label(
                    egui::RichText::new(format!(
                        "{}  ·  {}",
                        edge.role.as_deref().unwrap_or("unknown"),
                        yadorilink_client_core::wording::state_label(&edge.state),
                    ))
                    .weak()
                    .small(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add_enabled(!busy, egui::Button::new("Revoke…")).clicked() {
                        revoke_clicked = Some((edge.edge_id.clone(), edge.group_name.clone()));
                    }
                    if busy {
                        ui.spinner();
                    }
                });
            });
            ui.label(egui::RichText::new(&edge.device_id).weak().small().monospace());
        }
        if let Some((edge_id, group_name)) = revoke_clicked {
            let confirmed = rfd::MessageDialog::new()
                .set_title("Revoke this access?")
                .set_description(format!(
                    "This removes access to \"{group_name}\". If the daemon refuses because \
                     this would leave the folder without another confirmed-ready full replica, \
                     use that folder's own Share window to review and, if you're sure, force it."
                ))
                .set_buttons(rfd::MessageButtons::OkCancel)
                .show()
                == rfd::MessageDialogResult::Ok;
            if confirmed {
                pending.push(Event::RevokeEdgeRequested { edge_id });
            }
        }

        ui.add_space(14.0);
        ui.label(egui::RichText::new(share_access::PENDING_REQUESTS_HEADING).strong());
        let rows = share_access::all_pending_rows(&access.pending);
        if rows.is_empty() {
            ui.label(egui::RichText::new(share_access::no_pending_requests_line()).weak().small());
        }
        let mut approve_clicked: Option<(String, String, String)> = None;
        let mut deny_clicked: Option<(String, String, String)> = None;
        for row in &rows {
            let approve_key = format!("approve:{}:{}", row.group_id, row.device_id);
            let deny_key = format!("deny:{}:{}", row.group_id, row.device_id);
            let row_busy =
                self.state.busy.contains(&approve_key) || self.state.busy.contains(&deny_key);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&row.group_name).strong());
                ui.label(
                    egui::RichText::new(format!(
                        "{} is asking for {} access",
                        row.short_device_id, row.requested_role_label
                    ))
                    .weak()
                    .small(),
                );
            });
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!row_busy, |ui| {
                    if ui.button("Approve").clicked() {
                        approve_clicked = Some((
                            row.group_id.clone(),
                            row.device_id.clone(),
                            row.group_name.clone(),
                        ));
                    }
                    if ui.button("Deny").clicked() {
                        deny_clicked = Some((
                            row.group_id.clone(),
                            row.device_id.clone(),
                            row.group_name.clone(),
                        ));
                    }
                });
                if row_busy {
                    ui.spinner();
                }
            });
        }
        if let Some((group_id, device_id, group_name)) = approve_clicked {
            pending.push(Event::ApproveRequested { group_id, device_id, group_name });
        }
        if let Some((group_id, device_id, group_name)) = deny_clicked {
            pending.push(Event::DenyRequested { group_id, device_id, group_name });
        }

        ui.add_space(14.0);
        ui.label(egui::RichText::new("Invites you've sent").strong());
        if access.invites.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No pending invites. Mint one from a folder's own Share window.",
                )
                .weak()
                .small(),
            );
        }
        let mut cancel_clicked: Option<String> = None;
        for invite in &access.invites {
            let key = format!("invite:{}", invite.invite_id);
            let busy = self.state.busy.contains(&key);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&invite.group_name).strong());
                ui.label(
                    egui::RichText::new(format!("{}  ·  {}", invite.role, invite.status))
                        .weak()
                        .small(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if invite.status == "pending"
                        && ui.add_enabled(!busy, egui::Button::new("Cancel…")).clicked()
                    {
                        cancel_clicked = Some(invite.invite_id.clone());
                    }
                    if busy {
                        ui.spinner();
                    }
                });
            });
        }
        if let Some(invite_id) = cancel_clicked {
            let confirmed = rfd::MessageDialog::new()
                .set_title("Cancel this invite?")
                .set_description(
                    "Anyone who has this invite link will no longer be able to redeem it.",
                )
                .set_buttons(rfd::MessageButtons::OkCancel)
                .show()
                == rfd::MessageDialogResult::Ok;
            if confirmed {
                pending.push(Event::CancelInviteRequested { invite_id });
            }
        }
    }

    fn render_active(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>, working: bool) {
        ui.label("Deleting your account is a two-step, cancellable process.");
        if ui.add_enabled(!working, egui::Button::new("Request account deletion")).clicked() {
            pending.push(Event::RequestDeletion);
        }
    }

    fn render_requested(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>, working: bool) {
        ui.label(
            "Deletion has been requested but not confirmed. Confirm to start the grace period.",
        );
        if let Some(token) = &self.state.confirmation_token {
            ui.add_space(4.0);
            ui.label("Your one-time confirmation token (shown once):");
            ui.label(egui::RichText::new(token).monospace().color(ACCENT));
        }
        ui.add_space(6.0);
        let mut input = self.state.confirm_input.clone();
        if ui
            .add_enabled(
                !working,
                egui::TextEdit::singleline(&mut input).hint_text("confirmation token"),
            )
            .changed()
        {
            pending.push(Event::ConfirmInputChanged(input));
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(!working, egui::Button::new("Confirm deletion")).clicked() {
                pending.push(Event::ConfirmDeletion);
            }
            if ui.add_enabled(!working, egui::Button::new("Cancel deletion")).clicked() {
                pending.push(Event::CancelDeletion);
            }
        });
    }

    fn render_grace(
        &self,
        ui: &mut egui::Ui,
        pending: &mut Vec<Event>,
        working: bool,
        remaining_secs: i64,
    ) {
        ui.label(
            egui::RichText::new(format!(
                "Account deletion is scheduled. Grace period ends in about {}. Finalization is irreversible.",
                format_remaining(remaining_secs)
            ))
            .color(egui::Color32::from_rgb(0xc0, 0x39, 0x2b)),
        );
        ui.add_space(6.0);
        if ui
            .add_enabled(!working, egui::Button::new("Cancel deletion (restore account)"))
            .clicked()
        {
            pending.push(Event::CancelDeletion);
        }
    }
}

/// Coarse, human-readable rendering of a remaining-grace duration (same
/// buckets as the CLI's `format_remaining`).
fn format_remaining(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests;
