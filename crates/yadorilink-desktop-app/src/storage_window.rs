//! Entry point for `--window storage` -- the Storage view: per-folder hydrated/placeholder/
//! hydrating counts and local disk usage, plus the global block-store
//! usage/GC health `yadorilink status`/`yadorilink gc` compute, with a
//! manual GC trigger.
//!
//! Every field here comes straight from `StatusResponse`
//! (`LinkStatus.{hydrated,placeholder,hydrating}_count`,
//! `StatusResponse.{block_store_total_bytes,block_store_block_count,
//! last_gc_unix,gc_reclaimable_estimate_bytes}`) or `GcResponse` -- no
//! re-derivation, matching `folder_detail.rs`'s own established discipline.
//! Per-file pin/unpin/hydrate/evict stays exactly where it already lives
//! (`folder_status_window.rs`'s "Version history & selective sync"
//! panel) -- this window
//! links out to it rather than duplicating a second per-file picker.
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
use yadorilink_ipc_proto::daemonctl::{GcResponse, StatusResponse};
use yadorilink_product_view::FolderSummary;

use crate::onboarding::executor::EventSink;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Event {
    // Boxed for the same `clippy::large_enum_variant` reason every other
    // window's identical `StatusFetched` variant already is.
    StatusFetched(Result<Box<StatusResponse>, String>),
    /// `dry_run`, then the sweep's own report.
    GcDone(bool, Result<GcResponse, String>),
}

/// Entry point for `--window storage`. Must run on the process main thread
/// (same `eframe`/winit constraint every other window in this crate already
/// follows).
pub fn run_storage() -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 560.0])
            .with_min_inner_size([420.0, 360.0])
            .with_title("YadoriLink — Storage"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Storage",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(StorageApp::new(rx, sink)))
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

fn spawn_fetch(sink: EventSink<Event>) {
    spawn_task(sink, fetch_status(), |result| Event::StatusFetched(result.map(Box::new)));
}

fn spawn_gc(sink: EventSink<Event>, dry_run: bool) {
    spawn_task(
        sink,
        async move { crate::actions::run_gc(dry_run).await.map_err(|e| e.to_string()) },
        move |result| Event::GcDone(dry_run, result),
    );
}

struct StorageApp {
    status: Option<StatusResponse>,
    error: Option<String>,
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    fetch_in_flight: bool,
    last_fetch_started: Option<Instant>,
    gc_in_flight: bool,
    last_gc_message: Option<Result<String, String>>,
}

impl StorageApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        StorageApp {
            status: None,
            error: None,
            rx,
            sink,
            fetch_in_flight: false,
            last_fetch_started: None,
            gc_in_flight: false,
            last_gc_message: None,
        }
    }

    fn links(&self) -> &[yadorilink_ipc_proto::daemonctl::LinkStatus] {
        self.status.as_ref().map(|s| s.links.as_slice()).unwrap_or_default()
    }
}

impl eframe::App for StorageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::StatusFetched(Ok(status)) => {
                    self.status = Some(*status);
                    self.error = None;
                    self.fetch_in_flight = false;
                }
                Event::StatusFetched(Err(e)) => {
                    self.error = Some(e);
                    self.fetch_in_flight = false;
                }
                Event::GcDone(dry_run, result) => {
                    self.gc_in_flight = false;
                    self.last_gc_message =
                        Some(result.map(|report| gc_report_message(&report, dry_run)));
                    // A real (non-dry-run) sweep just changed
                    // `block_store_*`/`gc_reclaimable_estimate_bytes` --
                    // re-fetch so this window reflects the daemon's own new
                    // numbers rather than the pre-sweep snapshot.
                    if !self.fetch_in_flight {
                        self.fetch_in_flight = true;
                        spawn_fetch(self.sink.clone());
                    }
                }
            }
        }

        let due = self.last_fetch_started.is_none_or(|t| t.elapsed() >= POLL_INTERVAL);
        if due {
            self.last_fetch_started = Some(Instant::now());
            if !self.fetch_in_flight {
                self.fetch_in_flight = true;
                spawn_fetch(self.sink.clone());
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_body(ui);
            });
        });

        ctx.request_repaint_after(POLL_INTERVAL);
    }
}

impl StorageApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Storage");
        if let Some(e) = &self.error {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!("Can't reach the daemon right now: {e}"),
            );
        }
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        self.render_block_store(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_folders(ui);
    }

    fn render_block_store(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Block store").strong());
        match &self.status {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
                return;
            }
            Some(status) => {
                field_row(ui, "Total usage", &format_bytes(status.block_store_total_bytes));
                field_row(ui, "Blocks stored", &status.block_store_block_count.to_string());
                field_row(ui, "Last cleanup", &last_gc_summary(status.last_gc_unix));
                field_row(
                    ui,
                    "Reclaimable now (last estimate)",
                    &format_bytes(status.gc_reclaimable_estimate_bytes),
                );
            }
        }
        ui.label(
            egui::RichText::new(
                "Reclaimable space is blocks no current file version anywhere on this device \
                 still needs -- superseded/trashed content past its retention window. This \
                 never touches a version you could still restore.",
            )
            .weak()
            .small(),
        );

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let busy = self.gc_in_flight;
            if ui.add_enabled(!busy, egui::Button::new("Check reclaimable space")).clicked() {
                self.gc_in_flight = true;
                spawn_gc(self.sink.clone(), true);
            }
            if ui.add_enabled(!busy, egui::Button::new("Reclaim space now")).clicked() {
                self.gc_in_flight = true;
                spawn_gc(self.sink.clone(), false);
            }
            if busy {
                ui.spinner();
            }
        });
        if let Some(msg) = &self.last_gc_message {
            ui.add_space(4.0);
            match msg {
                Ok(text) => {
                    ui.colored_label(egui::Color32::from_rgb(0x2e, 0x9e, 0x5b), text);
                }
                Err(text) => {
                    ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), text);
                }
            }
        }
    }

    fn render_folders(&self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Per-folder storage").strong());
        if self.status.is_some() && self.links().is_empty() {
            ui.label(egui::RichText::new("No folders linked yet.").weak());
            return;
        }
        if self.status.is_none() {
            return;
        }

        let volumes = self.status.as_ref().map(|s| s.volumes.as_slice()).unwrap_or_default();
        for link in self.links() {
            let folder = FolderSummary::from(link);
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&folder.name).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        manage_files_button(ui, &link.local_path);
                    });
                });
                ui.label(
                    egui::RichText::new(crate::folder_detail::this_device_label(link))
                        .weak()
                        .small(),
                );
                ui.label(egui::RichText::new(hydration_summary(&folder)).weak().small());
                if let Some(volume) = crate::folder_detail::disk_usage_for(link, volumes) {
                    ui.label(
                        egui::RichText::new(crate::folder_detail::disk_usage_label(volume))
                            .weak()
                            .small(),
                    );
                }
            });
        }
    }
}

/// Opens the folder's own status window, where its files are managed.
fn manage_files_button(ui: &mut egui::Ui, local_path: &str) {
    if ui.button("Manage files…").clicked() {
        crate::actions::spawn_window_with_path("folder-status", local_path);
    }
}

/// "1,204 hydrated · 38 placeholder · 2 hydrating" -- an on-demand link's
/// steady state always has some placeholders (that's the point of
/// on-demand, not a warning sign -- see `folder_detail::this_device_label`'s
/// own doc comment on the identical distinction); this line is a plain
/// factual count, never colored/alarmist, matching that discipline. Any
/// zero bucket is still shown (not hidden), so the three numbers always
/// sum to the folder's true total file count in one glance (the reason
/// these three stay separate rather than collapsing into one
/// `files_total`).
fn hydration_summary(folder: &FolderSummary) -> String {
    format!(
        "{} hydrated · {} placeholder · {} hydrating",
        folder.files_hydrated, folder.files_placeholder, folder.files_hydrating
    )
}

/// Same wording `yadorilink gc [--dry-run]` prints (`commands::gc::
/// format_gc_report`) -- kept as its own copy here rather than shared,
/// matching this crate's established duplication precedent
/// (`ipc_client.rs`'s doc comment).
fn gc_report_message(report: &GcResponse, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Dry run: would delete {} block(s), reclaiming {}",
            report.blocks_deleted,
            format_bytes(report.bytes_reclaimed)
        )
    } else {
        format!(
            "Deleted {} block(s), reclaimed {}",
            report.blocks_deleted,
            format_bytes(report.bytes_reclaimed)
        )
    }
}

/// Same relative-bucket shape `yadorilink-cli`'s `commands::status::
/// last_gc_summary` and this crate's `home_window::last_seen_label` /
/// `folder_status_window::relative_time_from_unix_nanos` already use
/// (kept as its own copy, matching this crate's established duplication
/// precedent) -- this one takes plain Unix seconds, matching
/// `StatusResponse.last_gc_unix`'s own scale.
fn last_gc_summary(last_gc_unix: i64) -> String {
    if last_gc_unix <= 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let elapsed = (now - last_gc_unix).max(0);
    if elapsed < 60 {
        format!("{elapsed}s ago")
    } else if elapsed < 3600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86400 {
        format!("{}h ago", elapsed / 3600)
    } else {
        format!("{}d ago", elapsed / 86400)
    }
}

/// Same binary-unit byte formatter as `folder_detail::format_bytes`
/// (private to that module -- kept as its own copy, matching this crate's
/// established duplication precedent).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn field_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).strong());
        ui.label(value);
    });
}

#[cfg(test)]
mod tests;
