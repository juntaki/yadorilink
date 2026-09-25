//! Entry point for `--window share --path <local_path>` -- the per-folder
//! sharing window: choose a permission and an expiry, mint a one-use
//! cross-account invite, hand it over as a link, a QR code or an email,
//! and manage who already has access -- their roles, the requests waiting
//! on a decision, and removal. A dedicated window rather than a section of
//! the folder-detail window: `folder_status_window.rs` does mutate, but
//! only this device's own local state (trash restore, version restore,
//! pin/unpin, hydrate/evict), never who else can reach the folder.
//! Granting and revoking access is a different blast radius and a
//! different decision, so it gets its own window; that window's "Share…"
//! button only launches this process.
//!
//! Same threading/state shape as `folder_status_window.rs` and
//! `account.rs`: an `mpsc` channel plus an `EventSink` (from
//! `onboarding::executor`), background threads do every IPC/network call,
//! and `update` only ever reads already-computed state.
//!
//! Every coordination-plane and daemon call this window makes goes through
//! `yadorilink_client_core::ops::shares`, the same functions `yadorilink
//! share` calls. Minting an invite, changing a role, admitting a device and
//! revoking access are not plain pass-through actions. They each carry an authorization decision, and
//! this crate's established rule for those is the opposite one: `account.rs`
//! and `onboarding/executor.rs` both call the CLI's typed library functions
//! ("the single implementation the CLI uses too -- so the app and CLI can
//! never diverge"). A second, GUI-only path is exactly the kind of
//! divergence that ends with two different answers to "what does this role
//! actually grant".
//!
//! Test coverage: the pure logic in `share_invite.rs`
//! and `share_access.rs`, the QR bitmap construction below, and
//! `apply_action_result`'s turn from a completed action into what the
//! window says next (which needs no `egui::Context`), are unit-tested; this
//! file's actual `eframe`/`egui` rendering -- including every click path
//! through the access panel and its two removal confirmations -- is
//! covered by compilation, not by automated UI tests.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_client_core::ops::shares::{GroupMemberInfo, PendingApproval, RevokeAttempt};
use yadorilink_ipc_proto::daemonctl::{
    MintedInviteInfo, ReplicaMembershipCommandOutcome, StatusResponse,
};

use crate::onboarding::executor::EventSink;
use crate::share_access::{
    access_unreadable_banner, approval_gated_invite_note, assignable_role,
    confirmation_device_label, deny_done_line, deny_not_carried_out_line, deny_precheck,
    member_rows, no_pending_requests_line, pending_rows, revoke_confirm_prompt, revoke_done_line,
    revoke_override_prompt, role_change_done_line, DenyPrecheck, DenyRefusal, MemberRow,
    PendingRow, MEMBERS_HEADING, NO_MEMBERS, ONLY_THE_OWNER_CAN_MANAGE_ACCESS,
    PENDING_REQUESTS_HEADING, REMOVE_ACCESS_BUTTON, REVOKE_OVERRIDE_BUTTON,
};
use crate::share_invite::{
    expires_in_label, group_id_for_path, mailto_url, qr_modules, role_display_label, ExpiryPreset,
    InviteRole, QrModules,
};

/// How often the window retries resolving the folder it was opened for,
/// while that has not succeeded yet.
const RESOLVE_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// How long the "Copied" acknowledgement stays on screen after the copy
/// button is pressed.
const COPIED_NOTICE: Duration = Duration::from_secs(3);

const DANGER: egui::Color32 = egui::Color32::from_rgb(0xc0, 0x39, 0x2b);
const SUCCESS: egui::Color32 = egui::Color32::from_rgb(0x2e, 0x9e, 0x5b);

enum Event {
    // Boxed for the same reason `folder_status_window.rs` boxes it:
    // `StatusResponse` is far larger than anything else that travels on
    // this channel, and leaving it unboxed sizes every event to match.
    StatusFetched(Result<Box<StatusResponse>, String>),
    InviteMinted(Result<MintedInviteInfo, String>),
    /// Boxed for the same reason: `Access` carries two whole listings.
    AccessFetched(Result<Box<Access>, String>),
    /// One mutating action's result, tagged with the action it belongs to
    /// so the outcome can be worded, and so a refused removal can be
    /// offered again with the durability override.
    ActionDone(Action, Result<ActionOutcome, String>),
}

/// Everything the access panel shows, fetched together so the panel never
/// renders a half-loaded mixture of one listing's answer and another's.
struct Access {
    members: Vec<GroupMemberInfo>,
    /// Every request this account has to decide on, across every folder
    /// group it owns; narrowed to this window's own folder for display (see
    /// `share_access::pending_rows`). Always empty for an account that does
    /// not own this group, which is never asked for the listing at all.
    pending: Vec<PendingApproval>,
    /// Whether the account this window is signed in as OWNS this folder
    /// group.
    ///
    /// The member listing is deliberately visible to any member account,
    /// but every mutation below it is owner-only on the coordination plane.
    /// Deciding this here, from the owner-scoped folder-group listing, is
    /// what keeps the window from showing a role picker and a Remove button
    /// whose every click would come back refused.
    owns_group: bool,
}

/// One mutating action the access panel can start.
///
/// Carries the device LABEL it was started for, not just the id: every
/// confirmation and every outcome message names the device, and deriving
/// that name again afterwards would read it out of a listing that may have
/// been refreshed since the button was pressed.
#[derive(Clone)]
enum Action {
    ChangeRole {
        device_id: String,
        device_label: String,
        role: InviteRole,
    },
    Approve {
        device_id: String,
        device_label: String,
        group_name: String,
    },
    Deny {
        device_id: String,
        device_label: String,
    },
    Revoke {
        device_id: String,
        device_label: String,
        /// Whether this attempt carries the durability override. Only ever
        /// `true` for an attempt started from the override confirmation.
        forced: bool,
    },
}

/// What a completed action reports back, before it is worded for display.
enum ActionOutcome {
    /// A role change: the coordination plane answers `204 No Content`, so
    /// the window words it from the action.
    Committed,
    /// An approval, with the coordination plane's own result value --
    /// `approved`, `already_active`, or something a newer plane knows about.
    Approved(String),
    /// A denial that was carried out, with the daemon's outcome record.
    /// Carried rather than discarded for exactly the reason `Revoked` below
    /// carries it: a denial runs the very same mutation a removal runs, and
    /// the warnings that mutation can produce are computed daemon-side.
    Denied(Box<ReplicaMembershipCommandOutcome>),
    /// A denial that was NOT sent, because the re-read this window does
    /// immediately beforehand found the request was no longer waiting.
    /// Nothing was changed on the coordination plane.
    DenyNotCarriedOut(DenyRefusal),
    /// A removal that committed, with the daemon's outcome record. Its
    /// warnings still have to be shown: a forced removal's data-loss
    /// warning is computed daemon-side, not inferred from the flag.
    Revoked(Box<ReplicaMembershipCommandOutcome>),
    /// A removal the daemon refused because it would leave this folder
    /// without another confirmed-ready complete copy, carrying that refusal
    /// verbatim. The one failure this window offers an override for.
    RevokeRefused(String),
}

/// A destructive action waiting on an explicit confirmation.
enum Confirm {
    /// "Remove this member?" -- the ordinary confirmation, which every
    /// removal passes through.
    Revoke { device_id: String, device_label: String },
    /// The durability override, reached ONLY after the daemon refused a
    /// removal for the one reason `force` can get past. Carries that
    /// refusal so the confirmation can quote it.
    RevokeOverride { device_id: String, device_label: String, refusal: String },
}

/// The result of the most recent mutating action, shown until the next one
/// starts.
struct Notice {
    ok: bool,
    lines: Vec<String>,
    /// Lines that must read as warnings even when the action succeeded --
    /// a forced removal's data-loss warning, in the daemon's own words
    /// rather than paraphrased.
    warnings: Vec<String>,
}

/// What this window knows about the folder it was opened for. The
/// coordination-plane group id is the only thing it needs from the daemon:
/// minting takes a group id, so there is no name to resolve and no
/// additional lookup to fail.
enum Folder {
    /// No status snapshot has come back yet.
    Resolving,
    Linked {
        group_id: String,
    },
    /// A snapshot arrived, and it has no link at this path -- the folder
    /// was unlinked (possibly while this window was open).
    NotLinked,
    /// The daemon could not be reached, so whether this folder is linked is
    /// currently unknown. Deliberately distinct from `NotLinked`: "we
    /// cannot ask right now" must never render as "you are not sharing
    /// this".
    Unreachable(String),
}

/// A minted invite, plus everything derived from it that the window shows.
struct MintedInvite {
    url: String,
    role: String,
    expires_at_unix: i64,
    requires_approval: bool,
    /// `None` when the payload could not be encoded as a QR code at all.
    /// Not fatal: the link itself is shown and copyable regardless.
    qr: Option<QrModules>,
    /// Uploaded lazily on the first frame that draws the QR, then reused
    /// -- a texture upload needs an `egui::Context`, which only exists
    /// inside `update`.
    qr_texture: Option<egui::TextureHandle>,
}

/// Entry point for `--window share`. Must run on the process main thread
/// (same `eframe`/winit constraint every other window in this crate
/// already follows).
pub fn run_share(local_path: String) -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Tall enough that a freshly minted invite shows its QR code
            // in full. At 620 the code was cut off by the window's bottom
            // edge: reachable by scrolling, but the whole point of the
            // flow is the thing that was off screen, and no scrollbar said
            // so. Kept under 800 so it still fits a 900-point-tall display.
            .with_inner_size([460.0, 780.0])
            .with_title("YadoriLink — Share Folder"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Share Folder",
        options,
        Box::new(move |cc| {
            crate::fonts::install(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(ShareApp::new(local_path, rx, sink)))
        }),
    )
}

async fn fetch_status() -> Result<StatusResponse, String> {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::StatusRequest;

    match crate::ipc_client::send(ReqPayload::Status(StatusRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::Status(status)) => Ok(status),
            _ => Err("unexpected daemon response".to_string()),
        },
        Err(e) => Err(e.to_string()),
    }
}

/// Runs `future` on a throwaway thread + runtime and posts its result to
/// `sink` -- the same shape `folder_status_window::spawn_task` uses, for
/// the same reason (a slow or unreachable daemon must never block the UI
/// thread), including reporting a runtime-construction failure through the
/// sink as a real error rather than swallowing it.
fn spawn_task<X, F>(
    sink: EventSink<Event>,
    future: F,
    to_event: impl FnOnce(Result<X, String>) -> Event + Send + 'static,
) where
    X: Send + 'static,
    F: std::future::Future<Output = Result<X, String>> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                sink.send(to_event(Err(format!("could not start a background task runtime: {e}"))));
                return;
            }
        };
        let result = rt.block_on(future);
        sink.send(to_event(result));
    });
}

fn spawn_status_fetch(sink: EventSink<Event>) {
    spawn_task(sink, fetch_status(), |result| Event::StatusFetched(result.map(Box::new)));
}

fn spawn_mint(
    sink: EventSink<Event>,
    group_id: String,
    role: InviteRole,
    expiry: ExpiryPreset,
    require_approval: bool,
) {
    spawn_task(
        sink,
        async move {
            yadorilink_client_core::ops::shares::mint_invite_resolved(
                group_id,
                Some(role.wire_value().to_string()),
                expiry.ttl_secs(),
                require_approval,
            )
            .await
            .map_err(|e| e.to_string())
        },
        Event::InviteMinted,
    );
}

/// Reads everything the access panel shows in one background task.
///
/// The owner-scoped folder-group listing is read first, and the waiting
/// requests are only asked for when this account actually owns the group --
/// the coordination plane scopes that listing to "groups you own OR groups
/// your devices are in", so an account that merely joined this folder would
/// otherwise be handed its OWN pending request to approve, which it has no
/// authority to act on.
fn spawn_access_fetch(sink: EventSink<Event>, group_id: String) {
    use yadorilink_client_core::ops::shares as share;
    spawn_task(
        sink,
        async move {
            let members =
                share::list_members_resolved(&group_id).await.map_err(|e| e.to_string())?;
            let owns_group = share::list_groups()
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .any(|group| group.group_id == group_id);
            let pending = if owns_group {
                share::pending_approvals().await.map_err(|e| e.to_string())?
            } else {
                Vec::new()
            };
            Ok(Access { members, pending, owns_group })
        },
        |result| Event::AccessFetched(result.map(Box::new)),
    );
}

/// Runs one mutating action against an already-resolved folder group.
///
/// A removal goes through `try_revoke_resolved` rather than
/// `revoke_resolved` so the durability refusal comes back as an outcome to
/// offer an override for, instead of an error indistinguishable from an
/// unreachable daemon.
async fn run_action(group_id: String, action: Action) -> Result<ActionOutcome, String> {
    use yadorilink_client_core::ops::shares as share;
    match action {
        Action::ChangeRole { device_id, role, .. } => {
            share::change_role_resolved(&group_id, &device_id, role.wire_value())
                .await
                .map(|()| ActionOutcome::Committed)
                .map_err(|e| e.to_string())
        }
        Action::Approve { device_id, .. } => share::approve_resolved(&group_id, &device_id)
            .await
            .map(ActionOutcome::Approved)
            .map_err(|e| e.to_string()),
        // Denying IS revoking, unforced -- the same call `yadorilink share
        // deny` makes, and deliberately not a bespoke delete: the revoke
        // path marks the originating invite revoked atomically with removing
        // the request, which is what stops the denied recipient replaying
        // their acceptance.
        //
        // Because it is the same mutation, it is destructive against the
        // wrong target. The requests panel is read when the window opens and
        // after this window's own actions, never on a timer (deliberately --
        // see `access_requested`), so a row can still read "waiting" after
        // that request was APPROVED somewhere else, and denying it then would
        // remove a member whose access is live and working while reporting
        // that a request had been turned down. So the current state is
        // re-read here, immediately before the mutation would be sent, and a
        // request that is no longer waiting is not denied at all -- see
        // `share_access::deny_precheck`. This closes the window down to the
        // round trip below rather than the age of the panel, and it fails
        // closed: an unreadable listing propagates as an error and sends
        // nothing, rather than dispatching a removal it could not verify.
        //
        // A durability refusal is reported as a plain failure rather than
        // offered as an override. The daemon's readiness gate does not apply
        // to a device whose edge is not active, which is exactly what a
        // device awaiting approval is; a denial that somehow hits the gate
        // means the device was admitted inside that remaining window and now
        // holds data, and that is a REMOVAL, which belongs in the members
        // list where the confirmation names it as one.
        Action::Deny { device_id, .. } => {
            let pending = share::pending_approvals().await.map_err(|e| e.to_string())?;
            let members =
                share::list_members_resolved(&group_id).await.map_err(|e| e.to_string())?;
            match deny_precheck(&pending, &members, &group_id, &device_id) {
                DenyPrecheck::NotWaiting(refusal) => Ok(ActionOutcome::DenyNotCarriedOut(refusal)),
                DenyPrecheck::StillWaiting => {
                    match share::try_revoke_resolved(group_id, device_id, false)
                        .await
                        .map_err(|e| e.to_string())?
                    {
                        RevokeAttempt::Committed(outcome) => {
                            Ok(ActionOutcome::Denied(Box::new(outcome)))
                        }
                        RevokeAttempt::NotDurable { message, .. } => Err(message),
                    }
                }
            }
        }
        Action::Revoke { device_id, forced, .. } => {
            match share::try_revoke_resolved(group_id, device_id, forced)
                .await
                .map_err(|e| e.to_string())?
            {
                RevokeAttempt::Committed(outcome) => Ok(ActionOutcome::Revoked(Box::new(outcome))),
                RevokeAttempt::NotDurable { message, .. } => {
                    Ok(ActionOutcome::RevokeRefused(message))
                }
            }
        }
    }
}

fn spawn_action(sink: EventSink<Event>, group_id: String, action: Action) {
    let reported = action.clone();
    spawn_task(sink, run_action(group_id, action), move |result| {
        Event::ActionDone(reported, result)
    });
}

struct ShareApp {
    local_path: String,
    folder: Folder,
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    resolve_in_flight: bool,
    last_resolve_started: Option<Instant>,
    role: InviteRole,
    expiry: ExpiryPreset,
    require_approval: bool,
    minting: bool,
    minted: Option<MintedInvite>,
    mint_error: Option<String>,
    copied_at: Option<Instant>,
    /// This device's own id, read once at startup purely so one member row
    /// can be labelled "you" and excluded from the management controls. A
    /// machine with no local device identity simply never matches, exactly
    /// as on the command line.
    own_device_id: Option<String>,
    access: Option<Access>,
    access_error: Option<String>,
    access_in_flight: bool,
    /// Whether an access fetch has ever been started. The listing is read
    /// once when the folder resolves and again after every mutation, never
    /// on a timer: it changes only when somebody acts, and a window polling
    /// a coordination-plane listing in the background would be a new,
    /// unasked-for network load.
    ///
    /// The consequence, which every control drawn from this listing has to
    /// account for: somebody else acting -- from another device, or another
    /// session -- leaves these rows out of date with nothing on screen to
    /// say so. Every action but one is harmless against a stale row (the
    /// coordination plane re-decides, and the refresh that follows corrects
    /// the panel). The exception is Deny, which is destructive against the
    /// wrong target, so it re-reads the current state before it dispatches
    /// anything -- see `run_action`'s `Action::Deny` branch.
    access_requested: bool,
    /// Set when a refresh was asked for while one was already in flight --
    /// see `refresh_access`. Consumed as soon as that read lands.
    access_refresh_queued: bool,
    /// Which role each member's picker is currently sitting on, keyed by
    /// device id. Absent means "whatever the member's current role maps to",
    /// so a refreshed listing does not silently move a picker the user has
    /// already touched.
    role_selection: HashMap<String, InviteRole>,
    action_in_flight: bool,
    notice: Option<Notice>,
    confirm: Option<Confirm>,
}

impl ShareApp {
    fn new(local_path: String, rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        ShareApp {
            local_path,
            folder: Folder::Resolving,
            rx,
            sink,
            resolve_in_flight: false,
            last_resolve_started: None,
            role: InviteRole::default(),
            expiry: ExpiryPreset::default(),
            require_approval: false,
            minting: false,
            minted: None,
            mint_error: None,
            copied_at: None,
            own_device_id: yadorilink_client_core::ops::shares::own_device_id(),
            access: None,
            access_error: None,
            access_in_flight: false,
            access_requested: false,
            access_refresh_queued: false,
            role_selection: HashMap::new(),
            action_in_flight: false,
            notice: None,
            confirm: None,
        }
    }

    fn group_id(&self) -> Option<&str> {
        match &self.folder {
            Folder::Linked { group_id } => Some(group_id.as_str()),
            _ => None,
        }
    }

    /// Re-reads the access listing. Called when the folder first resolves
    /// and after every mutation commits, so the panel never keeps showing
    /// the state that an action has just changed.
    ///
    /// A request that arrives while a read is already in flight is
    /// remembered rather than dropped: the in-flight read was started before
    /// the mutation landed, so its answer predates the change, and simply
    /// returning here would leave the panel showing the state the action
    /// just replaced with no further attempt to correct it.
    fn refresh_access(&mut self) {
        let Some(group_id) = self.group_id().map(str::to_string) else {
            return;
        };
        self.access_requested = true;
        if self.access_in_flight {
            self.access_refresh_queued = true;
            return;
        }
        self.access_in_flight = true;
        self.access_error = None;
        spawn_access_fetch(self.sink.clone(), group_id);
    }

    /// Starts the refresh that arrived while the last one was still in
    /// flight, if there was one.
    fn run_queued_access_refresh(&mut self) {
        if std::mem::take(&mut self.access_refresh_queued) {
            self.refresh_access();
        }
    }

    /// Starts one mutating action, clearing any previous outcome so a stale
    /// success line cannot sit next to a running action and read as its
    /// result.
    fn start_action(&mut self, action: Action) {
        let Some(group_id) = self.group_id().map(str::to_string) else {
            return;
        };
        self.action_in_flight = true;
        self.notice = None;
        self.confirm = None;
        spawn_action(self.sink.clone(), group_id, action);
    }
}

impl eframe::App for ShareApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::StatusFetched(Ok(status)) => {
                    self.resolve_in_flight = false;
                    self.folder = match group_id_for_path(&status, &self.local_path) {
                        Some(group_id) => Folder::Linked { group_id: group_id.to_string() },
                        None => Folder::NotLinked,
                    };
                }
                Event::StatusFetched(Err(e)) => {
                    self.resolve_in_flight = false;
                    self.folder = Folder::Unreachable(e);
                }
                Event::InviteMinted(Ok(invite)) => {
                    self.minting = false;
                    self.mint_error = None;
                    self.copied_at = None;
                    let url = yadorilink_client_core::wording::invite_url(&invite.code);
                    self.minted = Some(MintedInvite {
                        qr: qr_modules(&url),
                        url,
                        // Every displayed property comes from what the
                        // coordination plane actually recorded, never from
                        // the form's own inputs -- so a plane that resolved
                        // or clamped something differently is reported as
                        // it is, not as it was asked for.
                        role: invite.role,
                        expires_at_unix: invite.expires_at_unix,
                        requires_approval: invite.requires_approval,
                        qr_texture: None,
                    });
                }
                Event::InviteMinted(Err(e)) => {
                    self.minting = false;
                    self.mint_error = Some(e);
                }
                Event::AccessFetched(Ok(access)) => {
                    self.access_in_flight = false;
                    self.access_error = None;
                    self.access = Some(*access);
                    self.run_queued_access_refresh();
                }
                Event::AccessFetched(Err(e)) => {
                    self.access_in_flight = false;
                    self.access_error = Some(e);
                    self.run_queued_access_refresh();
                }
                Event::ActionDone(action, result) => {
                    self.action_in_flight = false;
                    self.apply_action_result(action, result);
                }
            }
        }

        // Retry resolving the folder only until it IS resolved: this window
        // needs the group id once, and re-reading status underneath a
        // displayed invite would buy nothing. An unreachable daemon keeps
        // retrying, so a window opened while the daemon was starting up
        // recovers on its own.
        let unresolved = !matches!(self.folder, Folder::Linked { .. });
        let due = self.last_resolve_started.is_none_or(|t| t.elapsed() >= RESOLVE_RETRY_INTERVAL);
        if unresolved && due && !self.resolve_in_flight {
            self.last_resolve_started = Some(Instant::now());
            self.resolve_in_flight = true;
            spawn_status_fetch(self.sink.clone());
        }

        // The access listing is read once, as soon as the folder resolves to
        // a group id -- not on a timer. It only changes when somebody acts,
        // and every action here refreshes it on completion.
        if !unresolved && !self.access_requested {
            self.refresh_access();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_body(ui);
            });
        });
        // Drawn after (and therefore over) the scrolling body, and anchored
        // to the middle of the viewport, so a confirmation cannot end up
        // scrolled out of sight below a long member list. Every control it
        // guards is disabled while it is up -- see `render_member_rows`.
        self.render_confirm(ctx);

        // Clear the "Copied" notice once its own window has elapsed --
        // otherwise `copied_at.is_some()` below never goes false again and
        // this window repaints forever after a single click.
        if self.copied_at.is_some_and(|t| t.elapsed() >= COPIED_NOTICE) {
            self.copied_at = None;
        }

        if unresolved
            || self.minting
            || self.copied_at.is_some()
            || self.access_in_flight
            || self.action_in_flight
        {
            ctx.request_repaint_after(RESOLVE_RETRY_INTERVAL);
        }
    }
}

impl ShareApp {
    /// Turns one completed action into what the window shows next, and
    /// re-reads the access listing when the action changed something.
    fn apply_action_result(&mut self, action: Action, result: Result<ActionOutcome, String>) {
        let label = action.device_label().to_string();
        match result {
            Ok(ActionOutcome::Committed) => {
                let line = match &action {
                    Action::ChangeRole { role, .. } => role_change_done_line(&label, *role),
                    // A removal always reports through `Revoked` below, an
                    // approval through `Approved`, and a denial through
                    // `Denied`/`DenyNotCarriedOut`; none of them reaches here.
                    Action::Approve { .. } | Action::Deny { .. } | Action::Revoke { .. } => {
                        format!("{label}: done.")
                    }
                };
                self.notice = Some(Notice { ok: true, lines: vec![line], warnings: Vec::new() });
                self.refresh_access();
            }
            Ok(ActionOutcome::Approved(result)) => {
                let group_name = match &action {
                    Action::Approve { group_name, .. } => group_name.clone(),
                    _ => String::new(),
                };
                let device_id = action.device_id().to_string();
                // Worded by the command line's own formatter, which
                // deliberately refuses to claim "Approved" for a result this
                // build does not recognize.
                let line = yadorilink_client_core::wording::approve_result_line(
                    &result,
                    &device_id,
                    &group_name,
                );
                self.notice = Some(Notice { ok: true, lines: vec![line], warnings: Vec::new() });
                self.refresh_access();
            }
            Ok(ActionOutcome::Denied(outcome)) => {
                self.notice = Some(Notice {
                    ok: true,
                    lines: vec![deny_done_line(&label)],
                    // The same warnings a removal shows, from the same
                    // daemon-computed outcome -- a denial IS a revoke, so it
                    // is worded to the shared renderer as one, exactly as
                    // `yadorilink share deny` renders its own outcome. They
                    // are empty for an ordinary denial and must stay silent
                    // then; discarding the outcome outright is what would
                    // hide one that is not.
                    warnings: yadorilink_client_core::wording::membership_outcome_warnings(
                        "revoke", &outcome,
                    ),
                });
                self.refresh_access();
            }
            Ok(ActionOutcome::DenyNotCarriedOut(refusal)) => {
                // Nothing was sent and nothing changed, so this is not a
                // success line -- it is the same "your action did not
                // happen, here is why" shape a cancelled override reports
                // with. The listing is re-read regardless: the panel is
                // demonstrably behind, and this is what corrects it.
                self.notice = Some(Notice {
                    ok: false,
                    lines: vec![deny_not_carried_out_line(&label, refusal)],
                    warnings: Vec::new(),
                });
                self.refresh_access();
            }
            Ok(ActionOutcome::Revoked(outcome)) => {
                self.notice = Some(Notice {
                    ok: true,
                    lines: vec![revoke_done_line(&label)],
                    // The daemon computes these, including a forced
                    // removal's data-loss warning; they are shown in its own
                    // words rather than inferred from the flag that was sent.
                    warnings: yadorilink_client_core::wording::membership_outcome_warnings(
                        "revoke", &outcome,
                    ),
                });
                self.refresh_access();
            }
            Ok(ActionOutcome::RevokeRefused(refusal)) => {
                // The one failure this window offers an override for. Note
                // that nothing has changed on the coordination plane: the
                // daemon refuses before it writes anything at all.
                self.confirm = Some(Confirm::RevokeOverride {
                    device_id: action.device_id().to_string(),
                    device_label: label,
                    refusal,
                });
            }
            Err(message) => {
                self.notice =
                    Some(Notice { ok: false, lines: vec![message], warnings: Vec::new() });
            }
        }
    }
}

impl Action {
    fn device_id(&self) -> &str {
        match self {
            Action::ChangeRole { device_id, .. }
            | Action::Approve { device_id, .. }
            | Action::Deny { device_id, .. }
            | Action::Revoke { device_id, .. } => device_id,
        }
    }

    fn device_label(&self) -> &str {
        match self {
            Action::ChangeRole { device_label, .. }
            | Action::Approve { device_label, .. }
            | Action::Deny { device_label, .. }
            | Action::Revoke { device_label, .. } => device_label,
        }
    }
}

impl ShareApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading(crate::status_model::folder_display_name(&self.local_path));
        ui.label(egui::RichText::new(&self.local_path).weak().small());
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        match &self.folder {
            Folder::Resolving => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
                return;
            }
            Folder::NotLinked => {
                ui.label("This folder is no longer linked, so it cannot be shared.");
                return;
            }
            Folder::Unreachable(e) => {
                ui.colored_label(
                    DANGER,
                    "Can't reach the daemon right now, so this folder can't be shared yet.",
                );
                ui.label(egui::RichText::new(e).weak().small());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Retrying…");
                });
                return;
            }
            Folder::Linked { .. } => {}
        }

        self.render_invite_form(ui);

        if let Some(error) = &self.mint_error {
            ui.add_space(10.0);
            ui.colored_label(DANGER, format!("Could not create an invite: {error}"));
        }

        if self.minted.is_some() {
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(10.0);
            self.render_minted_invite(ui);
        }

        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_access(ui);
    }

    /// Who already has access, what they can do, and who is waiting to be
    /// let in.
    fn render_access(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(MEMBERS_HEADING).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!self.access_in_flight, egui::Button::new("Refresh")).clicked() {
                    self.refresh_access();
                }
                if self.access_in_flight {
                    ui.spinner();
                }
            });
        });
        ui.add_space(6.0);

        if self.action_in_flight {
            // Every control below goes inert while an action runs, so
            // without this the window would just look unresponsive.
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Applying your change…");
            });
            ui.add_space(6.0);
        }

        if let Some(error) = &self.access_error {
            // A failed read is never rendered as an empty access list: "we
            // could not ask" and "nobody has access" are opposite answers,
            // and confusing them here would tell someone their folder is
            // unshared when it may not be. When a previous listing is still
            // on screen, the banner also has to say those rows are a
            // last-known snapshot rather than a fresh confirmation.
            ui.colored_label(DANGER, access_unreadable_banner(self.access.is_some()));
            ui.label(egui::RichText::new(error).weak().small());
            ui.add_space(6.0);
        }

        if let Some(notice) = &self.notice {
            let color = if notice.ok { SUCCESS } else { DANGER };
            for line in &notice.lines {
                ui.colored_label(color, line);
            }
            for warning in &notice.warnings {
                ui.colored_label(DANGER, warning);
            }
            ui.add_space(6.0);
        }

        let Some(access) = &self.access else {
            if self.access_error.is_none() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
            }
            return;
        };

        let owns_group = access.owns_group;
        let rows = member_rows(&access.members, self.own_device_id.as_deref());
        let pending = pending_rows(&access.pending, self.group_id().unwrap_or_default());

        if rows.is_empty() {
            ui.label(NO_MEMBERS);
        } else {
            self.render_member_rows(ui, &rows, owns_group);
        }

        if !owns_group {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(ONLY_THE_OWNER_CAN_MANAGE_ACCESS).weak().small());
            // A non-owner is never shown a requests panel: the coordination
            // plane refuses their approve/deny outright, and this account
            // was never asked for the listing in the first place.
            return;
        }

        ui.add_space(14.0);
        ui.label(egui::RichText::new(PENDING_REQUESTS_HEADING).strong());
        ui.add_space(6.0);
        self.render_pending_rows(ui, &pending);
    }

    #[allow(
        clippy::excessive_nesting,
        reason = "the role ComboBox and the Change role / Remove access buttons must be drawn inside the same `add_enabled_ui(controls_live, ..)` closure so one guard covers every control, and their clicks are collected into locals applied after the loop; extracting a level would break that single-guard property"
    )]
    fn render_member_rows(&mut self, ui: &mut egui::Ui, rows: &[MemberRow], owns_group: bool) {
        // Clicks are collected here and applied after the loop, matching
        // `folder_status_window.rs`'s own pattern: a button handler cannot
        // mutate the window state the row it lives in is being drawn from.
        let mut selected_role: Option<(String, InviteRole)> = None;
        let mut change_role: Option<(String, String, InviteRole)> = None;
        let mut remove: Option<(String, String)> = None;
        // Every control is inert while a confirmation is up or an action is
        // running -- a second action started underneath a pending
        // confirmation would resolve against a listing nobody is looking at.
        let controls_live = owns_group && self.confirm.is_none() && !self.action_in_flight;

        for row in rows {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&row.device_name).strong());
                ui.label(egui::RichText::new(format!("({})", row.short_device_id)).weak().small())
                    .on_hover_text(&row.device_id);
            });
            ui.label(egui::RichText::new(row.detail_line()).weak().small());

            if !owns_group || !row.is_manageable() {
                continue;
            }
            // Falls back to the member's CURRENT role, and to no selection
            // at all when that role is not one this app can assign -- see
            // `share_access::assignable_role`.
            let selection = self
                .role_selection
                .get(&row.device_id)
                .copied()
                .or_else(|| assignable_role(&row.role));
            ui.horizontal(|ui| {
                ui.add_enabled_ui(controls_live, |ui| {
                    egui::ComboBox::from_id_salt(format!("share-role-{}", row.device_id))
                        .selected_text(selection.map_or("Choose a role", InviteRole::label))
                        .show_ui(ui, |ui| {
                            // Viewer and Editor only. Owner is never offered
                            // here, whatever the member currently holds.
                            for role in InviteRole::ALL {
                                if ui
                                    .selectable_label(selection == Some(role), role.label())
                                    .clicked()
                                {
                                    selected_role = Some((row.device_id.clone(), role));
                                }
                            }
                        });
                    let applicable = selection.is_some_and(|role| row.would_change_role_to(role));
                    if ui
                        .add_enabled(applicable, egui::Button::new("Change role"))
                        .on_disabled_hover_text(
                            "Pick a different role than the one they already have.",
                        )
                        .clicked()
                    {
                        if let Some(role) = selection {
                            change_role =
                                Some((row.device_id.clone(), confirmation_device_label(row), role));
                        }
                    }
                    if ui.button(REMOVE_ACCESS_BUTTON).clicked() {
                        remove = Some((row.device_id.clone(), confirmation_device_label(row)));
                    }
                });
            });
        }

        if let Some((device_id, role)) = selected_role {
            self.role_selection.insert(device_id, role);
        }
        if let Some((device_id, device_label, role)) = change_role {
            self.start_action(Action::ChangeRole { device_id, device_label, role });
        }
        if let Some((device_id, device_label)) = remove {
            // Never straight to the daemon: every removal passes through the
            // plain confirmation first.
            self.notice = None;
            self.confirm = Some(Confirm::Revoke { device_id, device_label });
        }
    }

    fn render_pending_rows(&mut self, ui: &mut egui::Ui, rows: &[PendingRow]) {
        if rows.is_empty() {
            // Says the same two things the command line's empty line says,
            // pointing at this window's own checkbox -- "nothing to do"
            // alone leaves somebody who was told to expect a request with
            // nowhere to go.
            ui.label(egui::RichText::new(no_pending_requests_line()).weak().small());
            return;
        }

        let mut approve: Option<(String, String)> = None;
        let mut deny: Option<String> = None;
        let controls_live = self.confirm.is_none() && !self.action_in_flight;

        for row in rows {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                // A waiting request carries no device NAME: the
                // coordination plane's share-edge listing has only the
                // device id, and inventing a friendlier label for a device
                // nobody has admitted yet would be inventing an identity.
                ui.label(egui::RichText::new(&row.short_device_id).monospace())
                    .on_hover_text(&row.device_id);
                ui.label(
                    egui::RichText::new(format!(
                        "is asking for {} access",
                        row.requested_role_label
                    ))
                    .weak()
                    .small(),
                );
            });
            ui.label(egui::RichText::new(&row.device_id).weak().small());
            ui.horizontal(|ui| {
                ui.add_enabled_ui(controls_live, |ui| {
                    if ui.button("Approve").clicked() {
                        approve = Some((row.device_id.clone(), row.group_name.clone()));
                    }
                    if ui.button("Deny").clicked() {
                        deny = Some(row.device_id.clone());
                    }
                });
            });
        }

        // The device id IS the label for a request: it is the only identity
        // the coordination plane reports for a device nobody has admitted.
        if let Some((device_id, group_name)) = approve {
            self.start_action(Action::Approve {
                device_label: device_id.clone(),
                device_id,
                group_name,
            });
        }
        if let Some(device_id) = deny {
            self.start_action(Action::Deny { device_label: device_id.clone(), device_id });
        }
    }

    /// The confirmation a removal is waiting on, drawn over the window body
    /// with every control it guards disabled behind it.
    ///
    /// An in-window panel rather than a native modal dialog: `main.rs`'s
    /// tray-side folder removal can block on `rfd` because it is not inside
    /// a render loop, whereas blocking here would freeze the very window the
    /// dialog belongs to. The convention it follows from there is the one
    /// that matters -- name the risk, spell out what does and does not
    /// happen, and make the person press a button that says so.
    fn render_confirm(&mut self, ctx: &egui::Context) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let (title, prompt, confirm_label, is_override) = match confirm {
            Confirm::Revoke { device_label, .. } => {
                ("Remove access?", revoke_confirm_prompt(device_label), "Remove access", false)
            }
            Confirm::RevokeOverride { device_label, refusal, .. } => (
                "This folder may have no other complete copy",
                revoke_override_prompt(device_label, refusal),
                REVOKE_OVERRIDE_BUTTON,
                true,
            ),
        };

        let mut confirmed = false;
        let mut cancelled = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(380.0);
                ui.colored_label(DANGER, prompt);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    // Cancel first, and it is the button this window opens
                    // under the pointer's likely resting place -- the
                    // destructive one should never be the easy one to hit.
                    if ui.button("Cancel").clicked() {
                        cancelled = true;
                    }
                    if ui.button(confirm_label).clicked() {
                        confirmed = true;
                    }
                });
            });

        if cancelled {
            // Cancelling the ordinary confirmation is a genuine no-op -- the
            // member is still there, nothing happened. Cancelling the
            // OVERRIDE confirmation is different: the daemon already
            // refused the plain removal before this dialog ever opened, so
            // walking away here must not erase that refusal without a
            // trace -- otherwise the member stays exactly as unreachable as
            // before, with no on-screen record of why the earlier attempt
            // did nothing.
            if let Some(Confirm::RevokeOverride { refusal, .. }) = &self.confirm {
                self.notice =
                    Some(Notice { ok: false, lines: vec![refusal.clone()], warnings: Vec::new() });
            }
            self.confirm = None;
            return;
        }
        if !confirmed {
            return;
        }
        let Some(confirm) = self.confirm.take() else {
            return;
        };
        let (device_id, device_label) = match confirm {
            Confirm::Revoke { device_id, device_label }
            | Confirm::RevokeOverride { device_id, device_label, .. } => (device_id, device_label),
        };
        // `forced` is true ONLY for the override confirmation -- the plain
        // one always retries the same unforced call the daemon is free to
        // refuse again.
        self.start_action(Action::Revoke { device_id, device_label, forced: is_override });
    }

    fn render_invite_form(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Invite someone to this folder").strong());
        ui.label(
            egui::RichText::new(
                "Creates a link that works once, for one device. Send it to exactly one person.",
            )
            .weak(),
        );
        ui.add_space(12.0);

        ui.label(egui::RichText::new("Permission").strong());
        ui.horizontal(|ui| {
            for role in InviteRole::ALL {
                ui.radio_value(&mut self.role, role, role.label());
            }
        });
        ui.label(egui::RichText::new(self.role.description()).weak().small());
        ui.add_space(12.0);

        ui.label(egui::RichText::new("Link expires").strong());
        ui.horizontal(|ui| {
            for preset in ExpiryPreset::ALL {
                ui.radio_value(&mut self.expiry, preset, preset.label());
            }
        });
        ui.add_space(12.0);

        ui.checkbox(&mut self.require_approval, crate::share_invite::REQUIRE_APPROVAL_LABEL);
        if self.require_approval {
            ui.label(
                egui::RichText::new(
                    "They can redeem the link, but nothing syncs to them until you approve the \
                     request.",
                )
                .weak()
                .small(),
            );
        }
        ui.add_space(14.0);

        let button_label =
            if self.minted.is_some() { "Create another invite link" } else { "Create invite link" };
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.minting, egui::Button::new(button_label)).clicked() {
                if let Some(group_id) = self.group_id().map(str::to_string) {
                    self.minting = true;
                    self.mint_error = None;
                    spawn_mint(
                        self.sink.clone(),
                        group_id,
                        self.role,
                        self.expiry,
                        self.require_approval,
                    );
                }
            }
            if self.minting {
                ui.spinner();
                ui.label("Creating…");
            }
        });
    }

    fn render_minted_invite(&mut self, ui: &mut egui::Ui) {
        let Some(minted) = &mut self.minted else {
            return;
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        ui.label(egui::RichText::new("Invite link").strong());
        ui.label(egui::RichText::new(&minted.url).monospace());
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button("Copy link").clicked() {
                ui.ctx().copy_text(minted.url.clone());
                self.copied_at = Some(Instant::now());
            }
            if ui.button("Send by email").clicked() {
                let mailto = mailto_url(
                    &minted.url,
                    &crate::status_model::folder_display_name(&self.local_path),
                );
                // Same hand-off to the OS every other outbound link in this
                // crate uses (`actions::open_folder`, `google_login`'s
                // browser launch). A mail client that refuses to open is
                // logged, not surfaced as a failed share: the link above is
                // still there to copy.
                if let Err(e) = opener::open(&mailto) {
                    tracing::warn!(error = %e, "could not open a mail client");
                }
            }
            if self.copied_at.is_some_and(|t| t.elapsed() < COPIED_NOTICE) {
                ui.colored_label(SUCCESS, "Copied");
            }
        });
        ui.add_space(10.0);

        ui.label(format!(
            "Permission: {}  ·  Expires {}",
            role_display_label(&minted.role),
            expires_in_label(minted.expires_at_unix, now_unix),
        ));
        if minted.requires_approval {
            // Points at this window's own requests panel rather than at the
            // command line: the request appears there once the recipient
            // redeems the link, with Approve and Deny beside it.
            ui.label(approval_gated_invite_note());
        }
        ui.add_space(12.0);

        match &minted.qr {
            Some(modules) => {
                let texture = minted.qr_texture.get_or_insert_with(|| {
                    ui.ctx().load_texture(
                        "share-invite-qr",
                        qr_color_image(modules, QR_MODULE_PIXELS),
                        // Nearest-neighbour: a QR code's modules must stay
                        // hard-edged squares. Smoothing them is what makes
                        // a rendered code fail to scan.
                        egui::TextureOptions::NEAREST,
                    )
                });
                ui.add(egui::Image::from_texture(egui::load::SizedTexture::from_handle(texture)));
                ui.label(
                    egui::RichText::new("Scan this with the other device to open the same link.")
                        .weak()
                        .small(),
                );
            }
            None => {
                ui.label(
                    egui::RichText::new(
                        "This link could not be drawn as a QR code. Copy or email it instead.",
                    )
                    .weak()
                    .small(),
                );
            }
        }
    }
}

/// How many image pixels one QR module is drawn as. An integer scale, so
/// every module is exactly the same size -- a fractional scale leaves some
/// modules a pixel wider than their neighbours, which is what breaks
/// decoding.
const QR_MODULE_PIXELS: usize = 6;

/// The quiet zone, in modules, drawn around the symbol. Four is the QR
/// specification's own minimum, and it is what lets a scanner find the
/// symbol's edge regardless of what the window's background looks like.
const QR_QUIET_ZONE_MODULES: usize = 4;

/// Paints a QR module grid into an `egui::ColorImage`.
///
/// Black on white, deliberately not the egui theme's foreground/background
/// colors: this image is read by a camera, and a light-on-dark rendering is
/// not reliably decodable.
fn qr_color_image(modules: &QrModules, module_px: usize) -> egui::ColorImage {
    let side_px = (modules.width + 2 * QR_QUIET_ZONE_MODULES) * module_px;
    let mut image = egui::ColorImage::new([side_px, side_px], egui::Color32::WHITE);
    for y in 0..modules.width {
        for x in 0..modules.width {
            if !modules.is_dark(x, y) {
                continue;
            }
            let origin_x = (x + QR_QUIET_ZONE_MODULES) * module_px;
            let origin_y = (y + QR_QUIET_ZONE_MODULES) * module_px;
            for dy in 0..module_px {
                for dx in 0..module_px {
                    image[(origin_x + dx, origin_y + dy)] = egui::Color32::BLACK;
                }
            }
        }
    }
    image
}

#[cfg(test)]
mod tests;

/// Hand-built `ShareApp` states for looking at this window without an
/// account, a coordination plane, or a linked folder.
///
/// Every state below is the REAL `ShareApp` with its real `update`, real
/// pickers and real QR encoder -- only the fields a live daemon and
/// coordination plane would have filled in are supplied here. Nothing in
/// this module is reachable unless the crate is built with
/// `--features preview`, which no release build enables.
///
/// The states exist because the populated sharing window is otherwise
/// unreachable on a developer machine: drawing the invite form, the QR
/// code and the access listing all require a signed-in account plus a
/// folder group that exists on the coordination plane, so a plain
/// `--window share` on an unconfigured machine can only ever render the
/// "daemon unreachable" and "folder not linked" paths.
#[cfg(feature = "preview")]
pub mod preview {
    use super::*;

    const GROUP_ID: &str = "grp_7f3a91c4e05b48d2";

    /// Which hand-built state to open.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Scene {
        /// Before anything is minted: role picker, expiry picker and the
        /// require-approval toggle, all live.
        Form,
        /// After a mint: the invite URL, its QR code, Copy link and the
        /// email hand-off.
        Minted,
        /// The people-with-access listing, with no request waiting.
        Access,
        /// The listing plus requests waiting on an Approve/Deny decision.
        Pending,
        /// The ordinary "remove this member?" confirmation.
        ConfirmRevoke,
        /// The durability override confirmation, reached only after the
        /// daemon refuses a removal.
        ConfirmRevokeOverride,
    }

    impl Scene {
        pub const ALL: [Scene; 6] = [
            Scene::Form,
            Scene::Minted,
            Scene::Access,
            Scene::Pending,
            Scene::ConfirmRevoke,
            Scene::ConfirmRevokeOverride,
        ];

        pub fn name(self) -> &'static str {
            match self {
                Scene::Form => "form",
                Scene::Minted => "minted",
                Scene::Access => "access",
                Scene::Pending => "pending",
                Scene::ConfirmRevoke => "confirm-revoke",
                Scene::ConfirmRevokeOverride => "confirm-revoke-override",
            }
        }

        pub fn parse(raw: &str) -> Option<Scene> {
            Scene::ALL.into_iter().find(|scene| scene.name() == raw)
        }

        pub fn names() -> String {
            Scene::ALL.map(Scene::name).join(", ")
        }
    }

    /// Device names chosen to exercise layout rather than to look tidy: a
    /// very long one, one in Japanese, and one short enough to leave the
    /// row mostly empty.
    fn members() -> Vec<GroupMemberInfo> {
        vec![
            GroupMemberInfo {
                device_id: "dev_self_0001".to_string(),
                device_name: "Jumpei's MacBook Air (M4)".to_string(),
                role: "editor".to_string(),
                is_same_account: true,
                is_caller_account: true,
                storage_mode: "complete".to_string(),
                online: true,
                last_seen_unix: now() - 30,
            },
            GroupMemberInfo {
                device_id: "dev_long_0002".to_string(),
                device_name: "Design team shared workstation — studio floor 3, window seat"
                    .to_string(),
                role: "viewer".to_string(),
                is_same_account: false,
                is_caller_account: false,
                storage_mode: "on-demand".to_string(),
                online: false,
                last_seen_unix: now() - 86_400 * 3,
            },
            GroupMemberInfo {
                device_id: "dev_jp_0003".to_string(),
                device_name: "高橋さんのデスクトップ（開発用）".to_string(),
                role: "editor".to_string(),
                is_same_account: false,
                is_caller_account: false,
                storage_mode: "complete".to_string(),
                online: true,
                last_seen_unix: now() - 120,
            },
            GroupMemberInfo {
                device_id: "dev_short_0004".to_string(),
                device_name: "iPad".to_string(),
                role: "unknown".to_string(),
                is_same_account: false,
                is_caller_account: false,
                storage_mode: "on-demand".to_string(),
                online: false,
                last_seen_unix: now() - 86_400 * 40,
            },
        ]
    }

    fn pending() -> Vec<PendingApproval> {
        vec![
            PendingApproval {
                group_id: GROUP_ID.to_string(),
                group_name: "Quarterly design review".to_string(),
                device_id: "dev_pending_0005".to_string(),
                role: Some("viewer".to_string()),
            },
            PendingApproval {
                group_id: GROUP_ID.to_string(),
                group_name: "Quarterly design review".to_string(),
                device_id: "dev_pending_0006".to_string(),
                // The coordination plane reported no role -- rendered as
                // unknown rather than guessed at.
                role: None,
            },
        ]
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    fn minted_invite() -> MintedInvite {
        // A realistically-shaped invite code, so the QR encoder is handed
        // the same payload length a real one would produce.
        let url =
            yadorilink_client_core::wording::invite_url("PRV7-K2M9-XQ4T-8N6B-J3WD-5HYC-1FZA-0RSE");
        MintedInvite {
            qr: qr_modules(&url),
            url,
            role: "viewer".to_string(),
            expires_at_unix: now() + 86_400 * 7,
            requires_approval: true,
            qr_texture: None,
        }
    }

    fn app(scene: Scene) -> ShareApp {
        let (tx, rx) = mpsc::channel::<Event>();
        // No repaint hook is needed: nothing in a preview posts an event,
        // and the sink is kept alive only because `ShareApp` owns one.
        let sink = EventSink::new(tx, Arc::new(|| {}));
        let mut app =
            ShareApp::new("/Users/jumpei/Documents/Quarterly design review".to_string(), rx, sink);
        app.folder = Folder::Linked { group_id: GROUP_ID.to_string() };
        app.own_device_id = Some("dev_self_0001".to_string());
        // Every scene has already "loaded": leaving this false would make
        // `update` start a real access fetch against a daemon that is not
        // there and replace the hand-built listing with an error.
        app.access_requested = true;
        app.resolve_in_flight = false;

        match scene {
            Scene::Form => {}
            Scene::Minted => {
                app.minted = Some(minted_invite());
            }
            Scene::Access => {
                app.access =
                    Some(Access { members: members(), pending: Vec::new(), owns_group: true });
            }
            Scene::Pending => {
                app.access =
                    Some(Access { members: members(), pending: pending(), owns_group: true });
            }
            Scene::ConfirmRevoke => {
                app.access =
                    Some(Access { members: members(), pending: Vec::new(), owns_group: true });
                app.confirm = Some(Confirm::Revoke {
                    device_id: "dev_jp_0003".to_string(),
                    device_label: "高橋さんのデスクトップ（開発用）".to_string(),
                });
            }
            Scene::ConfirmRevokeOverride => {
                app.access =
                    Some(Access { members: members(), pending: Vec::new(), owns_group: true });
                app.confirm = Some(Confirm::RevokeOverride {
                    device_id: "dev_long_0002".to_string(),
                    device_label: "Design team shared workstation — studio floor 3, window seat"
                        .to_string(),
                    refusal: "removing this device would leave the folder without another \
                              confirmed-ready complete copy"
                        .to_string(),
                });
            }
        }
        app
    }

    /// Opens the sharing window in one hand-built state.
    pub fn run(scene: Scene) -> Result<(), eframe::Error> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([460.0, 780.0])
                .with_title(format!("YadoriLink — Share Folder [preview: {}]", scene.name())),
            ..Default::default()
        };
        eframe::run_native(
            "YadoriLink Share Folder Preview",
            options,
            Box::new(move |cc| {
                crate::fonts::install(&cc.egui_ctx);
                Ok(Box::new(app(scene)))
            }),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_scene_name_parses_back_to_itself() {
            for scene in Scene::ALL {
                assert_eq!(Scene::parse(scene.name()), Some(scene));
            }
        }

        #[test]
        fn the_minted_scene_actually_encodes_a_qr_code() {
            // The whole point of the minted scene is to draw a QR code; a
            // payload that silently failed to encode would render the
            // scene useless without saying so.
            let invite = minted_invite();
            let qr = invite.qr.expect("the preview invite URL must encode as a QR code");
            assert!(qr.width >= 21, "a QR grid is at least 21 modules wide");
            assert_eq!(qr.dark.len(), qr.width * qr.width);
        }

        #[test]
        fn the_preview_listing_covers_the_layout_cases_it_exists_for() {
            let rows = members();
            assert!(rows.iter().any(|m| m.device_name.chars().count() > 40), "a long name");
            assert!(
                rows.iter().any(|m| m.device_name.chars().any(|c| c > '\u{3000}')),
                "a non-ASCII name"
            );
            assert!(rows.iter().any(|m| !m.online), "an offline device");
            assert!(rows.iter().any(|m| m.is_caller_account), "this device's own row");
        }
    }
}
