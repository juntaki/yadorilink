//! The desktop account section --
//! view deletion status, request/confirm/cancel deletion, and export a copy
//! of your coordination-plane records, without a terminal. Launched as its
//! own process (`--window account`) from the tray, mirroring the onboarding
//! window's separate-process model.
//!
//! Same "pure machine + thin renderer + off-thread executor" discipline as
//! `crate::onboarding`: `step` and the `*_to_event` mappers are unit-tested
//! here; the eframe screen is `cargo check`-gated only (there is no display
//! server in CI). Every coordination call goes through `yadorilink_cli::commands::
//! account`'s typed library fns -- the single implementation the CLI uses too
//! -- so the app and CLI can never diverge on what deletion/export does. This
//! module has no code path that deletes a local folder: export
//! writes the user's own data to a file, and deletion is purely server-side.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use eframe::egui;
use yadorilink_cli::commands::account;
use yadorilink_cli::commands::account::LOCAL_FIRST_NOTICE;

use crate::onboarding::executor::EventSink;
use crate::onboarding::machine::OpStatus;

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

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// A transient success line (export written, deletion cancelled,...).
    pub notice: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        State {
            status: OpStatus::Idle,
            lifecycle: None,
            confirmation_token: None,
            confirm_input: String::new(),
            notice: None,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    LoadStatus,
    Request,
    Confirm { confirmation_token: String },
    Cancel,
    Export,
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

async fn execute(effect: Effect) -> Event {
    match effect {
        Effect::LoadStatus => status_to_event(account::deletion_status().await),
        Effect::Request => request_to_event(account::request_deletion().await),
        Effect::Confirm { confirmation_token } => {
            confirm_to_event(account::confirm_deletion(confirmation_token).await)
        }
        Effect::Cancel => cancel_to_event(account::cancel_deletion().await),
        Effect::Export => export_to_event(account::export_account_json().await),
    }
}

fn runtime_error_event(effect: &Effect, msg: String) -> Event {
    match effect {
        Effect::LoadStatus => Event::StatusFailed(msg),
        Effect::Request => Event::RequestFailed(msg),
        Effect::Confirm { .. } => Event::ConfirmFailed(msg),
        Effect::Cancel => Event::CancelFailed(msg),
        Effect::Export => Event::ExportFailed(msg),
    }
}

fn status_to_event(
    result: Result<account::DeletionStatus, yadorilink_cli::error::CliError>,
) -> Event {
    match result {
        Ok(status) => Event::StatusLoaded(lifecycle_from_status(&status)),
        Err(e) => Event::StatusFailed(e.to_string()),
    }
}

fn request_to_event(
    result: Result<account::DeletionRequested, yadorilink_cli::error::CliError>,
) -> Event {
    match result {
        Ok(requested) => {
            Event::DeletionRequested { confirmation_token: requested.confirmation_token }
        }
        Err(e) => Event::RequestFailed(e.to_string()),
    }
}

fn confirm_to_event(
    result: Result<account::DeletionStatus, yadorilink_cli::error::CliError>,
) -> Event {
    match result {
        Ok(status) => Event::DeletionConfirmed(lifecycle_from_status(&status)),
        Err(e) => Event::ConfirmFailed(e.to_string()),
    }
}

fn cancel_to_event(
    result: Result<account::DeletionStatus, yadorilink_cli::error::CliError>,
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
fn export_to_event(result: Result<String, yadorilink_cli::error::CliError>) -> Event {
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
            .with_inner_size([560.0, 520.0])
            .with_title("YadoriLink — Account"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Account",
        options,
        Box::new(move |cc| {
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
}

impl AccountApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        AccountApp { state: State::default(), rx, sink, status_fetch_started: false }
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

        let mut pending: Vec<Event> = Vec::new();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading("Your account");
            ui.add_space(8.0);
            ui.label(LOCAL_FIRST_NOTICE);
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(10.0);
            self.render_body(ui, &mut pending);
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
mod tests {
    use super::*;

    fn status(state: &str, remaining: Option<i64>) -> account::DeletionStatus {
        account::DeletionStatus {
            state: state.to_string(),
            grace_expires_at_unix: remaining.map(|_| 1_000),
            remaining_secs: remaining,
        }
    }

    #[test]
    fn lifecycle_projects_each_server_state() {
        assert_eq!(lifecycle_from_status(&status("active", None)), Lifecycle::Active);
        assert_eq!(lifecycle_from_status(&status("requested", None)), Lifecycle::Requested);
        assert_eq!(
            lifecycle_from_status(&status("grace", Some(120))),
            Lifecycle::Grace { remaining_secs: 120, grace_expires_at_unix: 1_000 }
        );
        assert_eq!(
            lifecycle_from_status(&status("weird", None)),
            Lifecycle::Unknown("weird".to_string())
        );
    }

    #[test]
    fn requesting_status_emits_load_effect_once() {
        let (state, fx) = step(State::default(), Event::StatusRequested);
        assert_eq!(fx, vec![Effect::LoadStatus]);
        assert_eq!(state.status, OpStatus::Working);
        // A second StatusRequested while working is a no-op (no double fetch).
        let (_state, fx2) = step(state, Event::StatusRequested);
        assert!(fx2.is_empty());
    }

    #[test]
    fn request_then_confirm_carries_the_token() {
        let mut s = State { status: OpStatus::Idle, ..State::default() };
        s = step(s, Event::RequestDeletion).0;
        assert_eq!(s.status, OpStatus::Working);
        s = step(s, Event::DeletionRequested { confirmation_token: "tok-123".into() }).0;
        assert_eq!(s.confirmation_token.as_deref(), Some("tok-123"));
        assert_eq!(s.confirm_input, "tok-123");
        assert_eq!(s.lifecycle, Some(Lifecycle::Requested));

        let (s2, fx) = step(s, Event::ConfirmDeletion);
        assert_eq!(fx, vec![Effect::Confirm { confirmation_token: "tok-123".into() }]);
        assert_eq!(s2.status, OpStatus::Working);
    }

    #[test]
    fn confirm_is_blocked_when_the_token_is_empty() {
        let s = State { status: OpStatus::Idle, confirm_input: "   ".into(), ..State::default() };
        let (s2, fx) = step(s, Event::ConfirmDeletion);
        assert!(fx.is_empty());
        assert_eq!(s2.status, OpStatus::Idle);
    }

    #[test]
    fn cancel_restores_active_and_clears_the_token() {
        let s = State {
            status: OpStatus::Working,
            confirmation_token: Some("tok".into()),
            confirm_input: "tok".into(),
            lifecycle: Some(Lifecycle::Grace { remaining_secs: 10, grace_expires_at_unix: 1 }),
            notice: None,
        };
        let s = step(s, Event::DeletionCancelled(Lifecycle::Active)).0;
        assert_eq!(s.lifecycle, Some(Lifecycle::Active));
        assert!(s.confirmation_token.is_none());
        assert!(s.confirm_input.is_empty());
        assert!(s.notice.is_some());
    }

    #[test]
    fn export_result_maps_to_a_written_path_notice() {
        let s = step(State::default(), Event::Exported("/tmp/export.json".into())).0;
        assert_eq!(s.notice.as_deref(), Some("Exported your account data to /tmp/export.json."));
        assert_eq!(s.status, OpStatus::Idle);
    }

    #[test]
    fn export_default_path_is_json_under_config_dir() {
        let path = default_export_path();
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("account-export-"));
    }

    #[test]
    fn status_mapper_surfaces_errors() {
        let ev = status_to_event(Err(yadorilink_cli::error::CliError::NotLoggedIn));
        match ev {
            Event::StatusFailed(msg) => assert!(msg.contains("not logged in")),
            other => panic!("expected StatusFailed, got {other:?}"),
        }
    }

    #[test]
    fn format_remaining_renders_coarse_buckets() {
        assert_eq!(format_remaining(-5), "0m");
        assert_eq!(format_remaining(90), "1m");
        assert_eq!(format_remaining(2 * 86_400 + 5 * 3600), "2d 5h");
    }
}
