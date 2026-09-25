//! Entry point for `--window settings` -- the Settings skeleton: bandwidth
//! limits, startup (launch-at-login), update status/check/install/config,
//! a diagnostics entry point, and a link into the existing Account window.
//! Every capability here already exists as a tray menu item or a daemon
//! request -- this window composes `actions::*`
//! calls that already exist (plus a handful of thin new ones in
//! `actions.rs` for exact-value limits/update-status/update-config, which
//! the tray never needed) into one place. No new DTO, no new daemon
//! request.
//!
//! Diagnostics stays an entry point only, matching the brief: "a button
//! that generates/opens the bundle, not the bundle's internal content" --
//! this window never renders the bundle's contents itself, exactly like
//! the tray's own "Export Diagnostics…" item.
//!
//! Same "own `mpsc` channel + `EventSink`, background thread does the
//! fetch/action" shape as every other window in this crate.
//!
//! Test coverage: the pure logic here is unit-tested; the `eframe`/`egui`
//! rendering is covered by compilation, not by automated UI tests.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_ipc_proto::daemonctl::{LimitsShowResponse, UpdateStatusResponse};

use crate::onboarding::executor::EventSink;

const POLL_INTERVAL: Duration = Duration::from_secs(10);

enum Event {
    LimitsFetched(Result<LimitsShowResponse, String>),
    LimitsSaved(Result<LimitsShowResponse, String>),
    UpdateStatusFetched(Result<Box<UpdateStatusResponse>, String>),
    UpdateCheckDone(Result<(), String>),
    UpdateInstallDone(Result<(), String>),
    UpdateConfigSaved(Result<(), String>),
    DiagnosticsExported(Result<String, String>),
}

/// Entry point for `--window settings`. Must run on the process main
/// thread (same `eframe`/winit constraint every other window in this crate
/// already follows).
pub fn run_settings() -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([520.0, 620.0])
            .with_min_inner_size([420.0, 400.0])
            .with_title("YadoriLink — Settings"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Settings",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(SettingsApp::new(rx, sink)))
        }),
    )
}

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

fn spawn_limits_fetch(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::show_limits().await.map_err(|e| e.to_string()) },
        Event::LimitsFetched,
    );
}

fn spawn_limits_save(sink: EventSink<Event>, up: u64, down: u64) {
    spawn_task(
        sink,
        async move { crate::actions::set_limits(up, down).await.map_err(|e| e.to_string()) },
        |result| {
            // `LimitsSetResponse` and `LimitsShowResponse` carry the exact
            // same two fields; re-shaping the applied values into the
            // `Show` type lets both events feed the same rendering path
            // without a third response struct.
            Event::LimitsSaved(result.map(
                |r: yadorilink_ipc_proto::daemonctl::LimitsSetResponse| LimitsShowResponse {
                    upload_bytes_per_sec: r.upload_bytes_per_sec,
                    download_bytes_per_sec: r.download_bytes_per_sec,
                },
            ))
        },
    );
}

fn spawn_update_status_fetch(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::update_status().await.map_err(|e| e.to_string()) },
        |result| Event::UpdateStatusFetched(result.map(Box::new)),
    );
}

fn spawn_update_check(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::check_for_updates().await.map_err(|e| e.to_string()) },
        Event::UpdateCheckDone,
    );
}

fn spawn_update_install(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::install_update().await.map_err(|e| e.to_string()) },
        Event::UpdateInstallDone,
    );
}

fn spawn_update_config_save(sink: EventSink<Event>, checks: Option<bool>, install: Option<String>) {
    spawn_task(
        sink,
        async move {
            crate::actions::set_update_config(checks, install)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        },
        Event::UpdateConfigSaved,
    );
}

fn spawn_diagnostics_export(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move {
            crate::actions::export_diagnostics()
                .await
                .map(|p| p.to_string_lossy().to_string())
                .map_err(|e| e.to_string())
        },
        Event::DiagnosticsExported,
    );
}

/// The bandwidth panel's own editable draft -- kept as plain strings so a
/// half-typed number never gets silently clamped mid-edit; parsed only
/// when "Save" is clicked.
#[derive(Default, Clone)]
struct LimitsDraft {
    up_mib: String,
    down_mib: String,
}

impl LimitsDraft {
    fn from_response(r: &LimitsShowResponse) -> Self {
        LimitsDraft {
            up_mib: format_mib(r.upload_bytes_per_sec),
            down_mib: format_mib(r.download_bytes_per_sec),
        }
    }
}

/// `0` (unlimited) renders as an empty field -- a blank box reads more
/// naturally as "no limit" than a literal `0.000`.
fn format_mib(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        String::new()
    } else {
        format!("{:.2}", bytes_per_sec as f64 / (1024.0 * 1024.0))
    }
}

/// Parses a MiB/s field back to bytes/sec -- an empty or unparseable field
/// is treated as unlimited (`0`), matching `format_mib`'s own convention,
/// never a silent error.
fn parse_mib(input: &str) -> u64 {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return 0;
    }
    trimmed.parse::<f64>().map(|mib| (mib * 1024.0 * 1024.0).round() as u64).unwrap_or(0)
}

struct SettingsApp {
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    last_poll: Option<Instant>,

    limits: Option<LimitsShowResponse>,
    limits_draft: LimitsDraft,
    limits_error: Option<String>,
    limits_fetch_in_flight: bool,
    limits_save_in_flight: bool,
    limits_message: Option<Result<String, String>>,

    update_status: Option<UpdateStatusResponse>,
    update_error: Option<String>,
    update_fetch_in_flight: bool,
    update_action_in_flight: bool,
    update_message: Option<Result<String, String>>,

    login_item_enabled: bool,
    login_item_message: Option<Result<String, String>>,

    diagnostics_in_flight: bool,
    diagnostics_message: Option<Result<String, String>>,
}

impl SettingsApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        SettingsApp {
            rx,
            sink,
            last_poll: None,
            limits: None,
            limits_draft: LimitsDraft::default(),
            limits_error: None,
            limits_fetch_in_flight: false,
            limits_save_in_flight: false,
            limits_message: None,
            update_status: None,
            update_error: None,
            update_fetch_in_flight: false,
            update_action_in_flight: false,
            update_message: None,
            login_item_enabled: crate::login_item::is_enabled(),
            login_item_message: None,
            diagnostics_in_flight: false,
            diagnostics_message: None,
        }
    }
}

impl eframe::App for SettingsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::LimitsFetched(Ok(limits)) => {
                    self.limits_draft = LimitsDraft::from_response(&limits);
                    self.limits = Some(limits);
                    self.limits_error = None;
                    self.limits_fetch_in_flight = false;
                }
                Event::LimitsFetched(Err(e)) => {
                    self.limits_error = Some(e);
                    self.limits_fetch_in_flight = false;
                }
                Event::LimitsSaved(result) => {
                    self.limits_save_in_flight = false;
                    match result {
                        Ok(limits) => {
                            self.limits_draft = LimitsDraft::from_response(&limits);
                            self.limits = Some(limits);
                            self.limits_message = Some(Ok("Limits updated.".to_string()));
                        }
                        Err(e) => self.limits_message = Some(Err(e)),
                    }
                }
                Event::UpdateStatusFetched(Ok(status)) => {
                    self.update_status = Some(*status);
                    self.update_error = None;
                    self.update_fetch_in_flight = false;
                }
                Event::UpdateStatusFetched(Err(e)) => {
                    self.update_error = Some(e);
                    self.update_fetch_in_flight = false;
                }
                Event::UpdateCheckDone(result) => {
                    self.update_action_in_flight = false;
                    self.update_message = Some(result.map(|()| "Checked for updates.".to_string()));
                    self.update_fetch_in_flight = true;
                    spawn_update_status_fetch(self.sink.clone());
                }
                Event::UpdateInstallDone(result) => {
                    self.update_action_in_flight = false;
                    self.update_message = Some(result.map(|()| "Install requested.".to_string()));
                    self.update_fetch_in_flight = true;
                    spawn_update_status_fetch(self.sink.clone());
                }
                Event::UpdateConfigSaved(result) => {
                    self.update_action_in_flight = false;
                    self.update_message = Some(result.map(|()| "Preferences saved.".to_string()));
                    self.update_fetch_in_flight = true;
                    spawn_update_status_fetch(self.sink.clone());
                }
                Event::DiagnosticsExported(result) => {
                    self.diagnostics_in_flight = false;
                    self.diagnostics_message =
                        Some(result.map(|path| format!("Diagnostics bundle saved to {path}.")));
                }
            }
        }

        let due = self.last_poll.is_none_or(|t| t.elapsed() >= POLL_INTERVAL);
        if due {
            self.last_poll = Some(Instant::now());
            if !self.limits_fetch_in_flight && !self.limits_save_in_flight {
                self.limits_fetch_in_flight = true;
                spawn_limits_fetch(self.sink.clone());
            }
            if !self.update_fetch_in_flight && !self.update_action_in_flight {
                self.update_fetch_in_flight = true;
                spawn_update_status_fetch(self.sink.clone());
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_body(ui);
            });
        });

        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

impl SettingsApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Settings");
        ui.add_space(10.0);

        self.render_bandwidth(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_startup(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_update(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_diagnostics(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_account(ui);
    }

    fn render_bandwidth(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Bandwidth limits").strong());
        ui.label(egui::RichText::new("MiB/s, blank = unlimited").weak().small());
        ui.add_space(4.0);

        if let Some(e) = &self.limits_error {
            ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
        }
        if self.limits.is_none() && self.limits_error.is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading…");
            });
            return;
        }

        ui.horizontal(|ui| {
            ui.label("Upload:");
            ui.add(
                egui::TextEdit::singleline(&mut self.limits_draft.up_mib)
                    .desired_width(70.0)
                    .hint_text("unlimited"),
            );
            ui.label("Download:");
            ui.add(
                egui::TextEdit::singleline(&mut self.limits_draft.down_mib)
                    .desired_width(70.0)
                    .hint_text("unlimited"),
            );
            if ui.add_enabled(!self.limits_save_in_flight, egui::Button::new("Save")).clicked() {
                let up = parse_mib(&self.limits_draft.up_mib);
                let down = parse_mib(&self.limits_draft.down_mib);
                self.limits_save_in_flight = true;
                self.limits_message = None;
                spawn_limits_save(self.sink.clone(), up, down);
            }
        });
        if self.limits_save_in_flight {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Saving…");
            });
        }
        if let Some(msg) = &self.limits_message {
            render_result_label(ui, msg);
        }
    }

    fn render_startup(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Startup").strong());
        ui.add_space(4.0);
        let mut enabled = self.login_item_enabled;
        if ui.checkbox(&mut enabled, "Start YadoriLink at login (this user)").changed() {
            let result =
                if enabled { crate::login_item::enable() } else { crate::login_item::disable() };
            match result {
                Ok(()) => {
                    self.login_item_enabled = enabled;
                    self.login_item_message = Some(Ok(if enabled {
                        "Will start at login.".to_string()
                    } else {
                        "Will not start at login.".to_string()
                    }));
                }
                Err(e) => self.login_item_message = Some(Err(e.to_string())),
            }
        }
        if let Some(msg) = &self.login_item_message {
            render_result_label(ui, msg);
        }
    }

    fn render_update(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Updates").strong());
        ui.add_space(4.0);

        if let Some(e) = &self.update_error {
            ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
        }
        let Some(status) = self.update_status.clone() else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading…");
            });
            return;
        };

        ui.label(format!(
            "Version {}  ·  {} channel  ·  {}",
            status.current_version, status.channel, status.install_source
        ));
        ui.label(if status.last_check_unix == 0 {
            "Last checked: never".to_string()
        } else {
            format!("Last checked: {} (unix seconds)", status.last_check_unix)
        });
        ui.label(format!("State: {}", status.state));
        if !status.available_version.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(0x2e, 0x9e, 0x5b),
                format!("Update available: {}", status.available_version),
            );
            if status.mandatory {
                ui.colored_label(
                    egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                    "Mandatory (security/compatibility) update.",
                );
            }
            if !status.holdback_reason.is_empty() {
                ui.label(format!("Held back: {}", status.holdback_reason));
            }
            if status.waiting_for_safe_point {
                ui.label("Waiting for a safe point to install.");
            }
        }
        if !status.last_error_category.is_empty() {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!(
                    "Last update error: {} ({})",
                    status.last_error_category,
                    if status.last_error_message.is_empty() {
                        "no further detail"
                    } else {
                        &status.last_error_message
                    }
                ),
            );
        }

        ui.add_space(6.0);
        let busy = self.update_action_in_flight;
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("Check for updates")).clicked() {
                self.update_action_in_flight = true;
                self.update_message = None;
                spawn_update_check(self.sink.clone());
            }
            if !status.available_version.is_empty()
                && ui.add_enabled(!busy, egui::Button::new("Install update")).clicked()
            {
                self.update_action_in_flight = true;
                self.update_message = None;
                spawn_update_install(self.sink.clone());
            }
            if busy {
                ui.spinner();
            }
        });

        ui.add_space(6.0);
        let mut checks_on = status.automatic_checks_enabled;
        if ui
            .add_enabled(
                !busy,
                egui::Checkbox::new(&mut checks_on, "Automatically check for updates"),
            )
            .changed()
        {
            self.update_action_in_flight = true;
            self.update_message = None;
            spawn_update_config_save(self.sink.clone(), Some(checks_on), None);
        }
        let mut auto_install = status.automatic_install_mode == "automatic";
        if ui
            .add_enabled(
                !busy,
                egui::Checkbox::new(&mut auto_install, "Install updates automatically"),
            )
            .changed()
        {
            let mode = if auto_install { "automatic" } else { "manual" }.to_string();
            self.update_action_in_flight = true;
            self.update_message = None;
            spawn_update_config_save(self.sink.clone(), None, Some(mode));
        }

        if let Some(msg) = &self.update_message {
            render_result_label(ui, msg);
        }
    }

    fn render_diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Diagnostics").strong());
        ui.label(
            egui::RichText::new(
                "Export a redacted diagnostics bundle to attach to a support request.",
            )
            .weak()
            .small(),
        );
        ui.add_space(4.0);
        if ui
            .add_enabled(!self.diagnostics_in_flight, egui::Button::new("Export diagnostics…"))
            .clicked()
        {
            self.diagnostics_in_flight = true;
            self.diagnostics_message = None;
            spawn_diagnostics_export(self.sink.clone());
        }
        if self.diagnostics_in_flight {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Exporting…");
            });
        }
        if let Some(msg) = &self.diagnostics_message {
            render_result_label(ui, msg);
        }
    }

    fn render_account(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Account").strong());
        ui.add_space(4.0);
        if ui.button("Account & Data…").clicked() {
            crate::actions::spawn_window("account");
        }
    }
}

fn render_result_label(ui: &mut egui::Ui, msg: &Result<String, String>) {
    match msg {
        Ok(text) => {
            ui.colored_label(egui::Color32::from_rgb(0x2e, 0x9e, 0x5b), text);
        }
        Err(text) => {
            ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), text);
        }
    }
}

#[cfg(test)]
mod tests;
