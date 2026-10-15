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
//! Per-file hydrate/evict stays exactly where it already lives
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
use yadorilink_ipc_proto::daemonctl::{
    GcResponse, RetainedOriginal, RetainedRelease, StatusResponse,
};
use yadorilink_product_view::FolderSummary;

use crate::onboarding::executor::EventSink;

/// Section and action names, kept apart so the three kinds of storage and the actions that
/// change them cannot be confused: local files, YadoriLink's own data, disk free space.
const FILES_SECTION: &str = "Files on this Mac";
const INTERNAL_SECTION: &str = "YadoriLink internal storage";
const INTERNAL_TOTAL_LABEL: &str = "YadoriLink data";
const CLEANABLE_LABEL: &str = "Internal space that can be cleaned up (last estimate)";
const CHECK_ACTION: &str = "Check internal space";
const CLEAN_UP_ACTION: &str = "Clean up YadoriLink data";
const CLEAN_UP_EXPLANATION: &str = "Old versions and other internal data YadoriLink no longer \
    needs. This does not change the files in your folders and does not make downloaded files \
    online only. It never removes a version you could still restore.";
const FILES_EXPLANATION: &str = "File counts only; sizes are not measured per file. Free disk \
    space is shown separately for each folder's own disk.";

const POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Event {
    // Boxed for the same `clippy::large_enum_variant` reason every other
    // window's identical `StatusFetched` variant already is.
    StatusFetched(Result<Box<StatusResponse>, String>),
    /// `dry_run`, then the sweep's own report.
    GcDone(bool, Result<GcResponse, String>),
    RetainedFetched(Result<Vec<RetainedOriginal>, String>),
    ReleaseDone(Result<String, String>),
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

fn spawn_retained_fetch(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::list_retained_originals().await.map_err(|e| e.to_string()) },
        Event::RetainedFetched,
    );
}

/// Tries to release the kept originals of each of `groups`, one after the other.
fn spawn_release(sink: EventSink<Event>, groups: Vec<String>) {
    spawn_task(
        sink,
        async move {
            // A group that cannot be released (its folder is not watched, a rebootstrap runs)
            // does not stop the others; its error is reported with the result.
            let mut releases = Vec::new();
            let mut errors = Vec::new();
            for group in groups {
                match crate::actions::release_retained_originals(&group).await {
                    Ok(done) => releases.extend(done),
                    Err(e) => errors.push(format!("{group}: {e}")),
                }
            }
            if errors.is_empty() {
                Ok(release_message(&releases))
            } else {
                Err(format!("{} -- {}", release_message(&releases), errors.join("; ")))
            }
        },
        Event::ReleaseDone,
    );
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
    retained: Vec<RetainedOriginal>,
    /// The status count the listing was last fetched for: the listing measures every kept file,
    /// so it is fetched again only when that count changes or after a release.
    retained_listed_for: Option<u32>,
    retained_in_flight: bool,
    release_in_flight: bool,
    last_release_message: Option<Result<String, String>>,
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
            retained: Vec::new(),
            retained_listed_for: None,
            retained_in_flight: false,
            release_in_flight: false,
            last_release_message: None,
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
                    // The status carries only the count; the listing, which measures each
                    // kept file, is fetched only while there is any.
                    let kept = status.preserved.as_ref().map_or(0, |p| p.retained_originals);
                    self.status = Some(*status);
                    self.error = None;
                    self.fetch_in_flight = false;
                    if kept == 0 {
                        self.retained.clear();
                        self.retained_listed_for = None;
                    } else if !self.retained_in_flight && self.retained_listed_for != Some(kept) {
                        self.retained_listed_for = Some(kept);
                        self.retained_in_flight = true;
                        spawn_retained_fetch(self.sink.clone());
                    }
                }
                Event::RetainedFetched(result) => {
                    self.retained_in_flight = false;
                    match result {
                        Ok(items) => self.retained = items,
                        // A failed listing is asked for again by the next status.
                        Err(_) => self.retained_listed_for = None,
                    }
                }
                Event::ReleaseDone(result) => {
                    self.release_in_flight = false;
                    self.last_release_message = Some(result);
                    // What was listed before the release may be stale, even if a fetch is
                    // running: the next status asks again.
                    self.retained_listed_for = None;
                    if !self.retained_in_flight {
                        self.retained_in_flight = true;
                        spawn_retained_fetch(self.sink.clone());
                    }
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
        if !self.retained.is_empty() {
            ui.add_space(14.0);
            ui.separator();
            ui.add_space(10.0);
            self.render_retained(ui);
        }
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_folders(ui);
    }

    fn render_block_store(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new(INTERNAL_SECTION).strong());
        match &self.status {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
                return;
            }
            Some(status) => {
                field_row(ui, INTERNAL_TOTAL_LABEL, &format_bytes(status.block_store_total_bytes));
                field_row(ui, "Blocks stored", &status.block_store_block_count.to_string());
                field_row(ui, "Last cleanup", &last_gc_summary(status.last_gc_unix));
                field_row(ui, CLEANABLE_LABEL, &format_bytes(status.gc_reclaimable_estimate_bytes));
            }
        }
        ui.label(egui::RichText::new(CLEAN_UP_EXPLANATION).weak().small());

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let busy = self.gc_in_flight;
            if ui.add_enabled(!busy, egui::Button::new(CHECK_ACTION)).clicked() {
                self.gc_in_flight = true;
                spawn_gc(self.sink.clone(), true);
            }
            if ui.add_enabled(!busy, egui::Button::new(CLEAN_UP_ACTION)).clicked() {
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

    fn render_retained(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Kept originals").strong());
        if let Some(summary) = retained_summary(&self.retained) {
            ui.label(summary);
        }
        ui.label(
            egui::RichText::new(
                "A reset kept these files in their folders because this system could not prove \
                 that no program still writes to them. Releasing removes one only when that can \
                 be proved and it is unchanged; a changed one is saved as a preserved item first.",
            )
            .weak()
            .small(),
        );
        for row in retained_rows(&self.retained) {
            ui.label(egui::RichText::new(row).small());
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let busy = self.release_in_flight;
            if ui.add_enabled(!busy, egui::Button::new("Release kept originals")).clicked() {
                self.release_in_flight = true;
                let mut groups: Vec<String> =
                    self.retained.iter().map(|item| item.group_id.clone()).collect();
                groups.sort();
                groups.dedup();
                spawn_release(self.sink.clone(), groups);
            }
            if busy {
                ui.spinner();
            }
        });
        if let Some(msg) = &self.last_release_message {
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
        ui.label(egui::RichText::new(FILES_SECTION).strong());
        ui.label(egui::RichText::new(FILES_EXPLANATION).weak().small());
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
                        manage_files_button(ui, link);
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
                        egui::RichText::new(format!(
                            "Free disk space: {}",
                            crate::folder_detail::disk_usage_label(volume)
                        ))
                        .weak()
                        .small(),
                    );
                }
            });
        }
    }
}

/// Opens the folder's own status window, where its files are managed.
fn manage_files_button(ui: &mut egui::Ui, link: &yadorilink_ipc_proto::daemonctl::LinkStatus) {
    // A provider folder has no directory to manage files in.
    if !link.provider_display_name.is_empty() {
        return;
    }
    let local_path = link.local_path.as_str();
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
            "Dry run: would delete {} internal block(s), cleaning up {}",
            report.blocks_deleted,
            format_bytes(report.bytes_reclaimed)
        )
    } else {
        format!(
            "Deleted {} internal block(s), cleaned up {}",
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

/// The one line above the kept originals: how many and the disk they take, saying so when the
/// size of some is unknown because their folder is not watched. `None` when none are kept.
fn retained_summary(items: &[RetainedOriginal]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let known: u64 = items.iter().filter(|item| item.reachable).map(|item| item.size).sum();
    let unknown = items.iter().filter(|item| !item.reachable).count();
    let mut line = format!("{} original(s), {}", items.len(), format_bytes(known));
    if unknown > 0 {
        line.push_str(&format!(" (size unknown for {unknown}: its folder is not watched)"));
    }
    Some(line)
}

/// One row per kept original: the folder group, the path and the size.
fn retained_rows(items: &[RetainedOriginal]) -> Vec<String> {
    items
        .iter()
        .map(|item| {
            let size =
                if item.reachable { format_bytes(item.size) } else { "size unknown".to_string() };
            format!("{} · {} · {size}", item.group_id, item.path)
        })
        .collect()
}

/// What a release did, in one sentence for the window.
fn release_message(releases: &[RetainedRelease]) -> String {
    if releases.is_empty() {
        return "There was nothing to release.".to_string();
    }
    let count = |outcomes: &[&str]| {
        releases.iter().filter(|r| outcomes.contains(&r.outcome.as_str())).count()
    };
    let released = count(&["removed", "gone", "saved_then_removed"]);
    let kept = releases.len() - released;
    let saved = count(&["saved_then_removed", "saved_still_retained"]);
    let mut message = format!("{released} released, {kept} kept");
    if saved > 0 {
        message.push_str(&format!(
            "; {saved} changed and saved as preserved items first (see `yadorilink preserved list`)"
        ));
    }
    message
}

fn field_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).strong());
        ui.label(value);
    });
}

#[cfg(test)]
mod tests;
