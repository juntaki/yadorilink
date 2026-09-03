//! Entry point for `--window folder-status --path <local_path>` -- the M4
//! Pass 3 per-folder detail window presenting "Data protection / This
//! device / Availability / Complete copies / Connection" for one linked
//! folder, per `folder_detail.rs`'s pure formatters. Same threading/state
//! shape as `account.rs`'s window (own `mpsc` channel + `EventSink` from
//! `onboarding::executor`, background thread does the IPC fetch, `update`
//! only ever reads already-computed state) -- simpler than the onboarding
//! wizard's `Effect`/`step` machine since this window has exactly one
//! operation (fetch status) and no user-driven transitions to model.
//!
//! IMPORTANT / honesty note for reviewers (matching `main.rs`'s own): the
//! pure logic in `folder_detail.rs` is unit-tested; this file's actual
//! `eframe`/`egui` rendering can only be verified by `cargo build`/`cargo
//! check` in this sandboxed environment -- there is no display server here
//! to click a real window against.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, FileVersionInfo, LinkStatus, MaterializationState,
    MaterializationStatusResponse, PeerStatus, StatusResponse, TrashedFileInfo,
};

use crate::onboarding::executor::EventSink;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Which mutating action an [`Event::ActionDone`] reports the outcome of --
/// decides which section re-fetches once the action completes, and how the
/// outcome message reads. One shared variant rather than one `*Done` event
/// per action: none of these six need their own distinct result shape,
/// only a human-readable outcome and which section to refresh.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    TrashRestore,
    VersionRestore,
    Pin,
    Unpin,
    Hydrate,
    Evict,
}

enum Event {
    // Boxed: `StatusResponse` is far larger than every other variant here,
    // and `clippy::large_enum_variant` is right that leaving it unboxed
    // would size every `Event` (including the small, frequent
    // `ActionDone`) to match the biggest one.
    StatusFetched(Result<Box<StatusResponse>, String>),
    ConflictsFetched(Result<Vec<ConflictedFileInfo>, String>),
    TrashFetched(Result<Vec<TrashedFileInfo>, String>),
    /// The file-tools panel's own fetch, tagged with the absolute path it
    /// was fetched FOR -- a slow fetch racing a user picking a different
    /// file before it returns must never overwrite that newer selection's
    /// own state with a stale result (checked in the event handler below).
    FileToolsFetched(String, Result<(Vec<FileVersionInfo>, MaterializationStatusResponse), String>),
    ActionDone(ActionKind, Result<String, String>),
}

/// Entry point for `--window folder-status`. Must run on the process main
/// thread (same `eframe`/winit constraint every other window in this crate
/// already follows).
pub fn run_folder_status(local_path: String) -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 460.0])
            .with_title("YadoriLink — Folder Details"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Folder Details",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(FolderStatusApp::new(local_path, rx, sink)))
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

/// Runs `future` on a throwaway thread + current-thread runtime and posts
/// its result to `sink` via `to_event` -- the one shared shape every
/// background fetch/action in this window follows (mirrors `spawn_fetch`'s
/// original single-purpose version, generalized once a second, third,
/// fourth... background operation needed the identical thread+runtime
/// scaffolding). Every caller's `future` already resolves to a
/// `Result<X, String>` (a fetch/action either succeeds or fails with a
/// message), which this relies on to report a runtime-construction
/// failure the same way as any other failure -- through the sink, as a
/// real `Err`, not silently -- rather than needing a way to synthesize an
/// arbitrary success value it doesn't have.
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
                sink.send(to_event(Err(format!(
                    "could not start a background task runtime: {e}"
                ))));
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

fn spawn_conflicts_fetch(sink: EventSink<Event>, local_path: String) {
    spawn_task(
        sink,
        async move { crate::actions::list_conflicts_for(&local_path).await.map_err(|e| e.to_string()) },
        Event::ConflictsFetched,
    );
}

fn spawn_trash_fetch(sink: EventSink<Event>, local_path: String) {
    spawn_task(
        sink,
        async move { crate::actions::list_trash_for(&local_path).await.map_err(|e| e.to_string()) },
        Event::TrashFetched,
    );
}

fn spawn_file_tools_fetch(sink: EventSink<Event>, absolute_path: String) {
    let for_path = absolute_path.clone();
    spawn_task(
        sink,
        async move {
            let versions = crate::actions::list_versions(absolute_path.clone())
                .await
                .map_err(|e| e.to_string())?;
            let materialization = crate::actions::materialization_status(absolute_path)
                .await
                .map_err(|e| e.to_string())?;
            Ok((versions, materialization))
        },
        move |result| Event::FileToolsFetched(for_path, result),
    );
}

fn spawn_action(
    sink: EventSink<Event>,
    kind: ActionKind,
    future: impl std::future::Future<Output = Result<String, String>> + Send + 'static,
) {
    spawn_task(sink, future, move |result| Event::ActionDone(kind, result));
}

/// The Version History / Selective Sync panel's own state, keyed on
/// whichever file the user last picked via `pick_file_in` -- both panels
/// operate on the same single chosen file, so they share one fetch/state
/// unit rather than duplicating it.
#[derive(Default)]
struct FileTools {
    absolute_path: Option<String>,
    versions: Option<Vec<FileVersionInfo>>,
    materialization: Option<MaterializationStatusResponse>,
    loading: bool,
    error: Option<String>,
}

struct FolderStatusApp {
    local_path: String,
    status: Option<StatusResponse>,
    error: Option<String>,
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    fetch_in_flight: bool,
    last_fetch_started: Option<Instant>,
    conflicts: Option<Vec<ConflictedFileInfo>>,
    conflicts_error: Option<String>,
    conflicts_fetch_in_flight: bool,
    /// One-shot: set when the first fetch to ever report a non-empty
    /// conflict list arrives, consumed by `render_conflicts` on the very
    /// next frame it draws. `CollapsingHeader::default_open` only seeds
    /// the OPEN/CLOSED state the first time its `Id` is ever shown --
    /// since that first show happens before any fetch has completed (the
    /// panel starts life not knowing whether there are conflicts at all),
    /// `default_open` can never see the real answer in time. `.open(Some(
    /// true))` for exactly one frame, driven by this flag, is what
    /// actually auto-expands the panel the moment conflicts are found,
    /// while leaving every later frame free for the user's own manual
    /// toggle to stick.
    conflicts_should_force_open_once: bool,
    trash: Option<Vec<TrashedFileInfo>>,
    trash_error: Option<String>,
    trash_fetch_in_flight: bool,
    file_tools: FileTools,
    /// The most recent mutating action's outcome, shown as a one-line
    /// banner until the next action replaces it -- `Ok` messages are
    /// informational (e.g. "Restored"), `Err` messages are the daemon's
    /// own error text, same "show it, don't swallow it" rule every other
    /// panel in this window already follows for a failed fetch.
    last_action_message: Option<Result<String, String>>,
    action_in_flight: bool,
}

impl FolderStatusApp {
    fn new(local_path: String, rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        FolderStatusApp {
            local_path,
            status: None,
            error: None,
            rx,
            sink,
            fetch_in_flight: false,
            last_fetch_started: None,
            conflicts: None,
            conflicts_error: None,
            conflicts_fetch_in_flight: false,
            conflicts_should_force_open_once: false,
            trash: None,
            trash_error: None,
            trash_fetch_in_flight: false,
            file_tools: FileTools::default(),
            last_action_message: None,
            action_in_flight: false,
        }
    }

    /// This window's own `LinkStatus`, if the daemon's latest snapshot
    /// still has a link at `local_path` -- `None` covers both "no status
    /// yet" and "this folder was unlinked while the window was open",
    /// deliberately rendered identically (see `render_body`) since
    /// neither case has anything truthful to show.
    fn link(&self) -> Option<&LinkStatus> {
        self.status.as_ref()?.links.iter().find(|l| l.local_path == self.local_path)
    }

    fn peers(&self) -> &[PeerStatus] {
        self.status.as_ref().map(|s| s.peers.as_slice()).unwrap_or_default()
    }
}

impl eframe::App for FolderStatusApp {
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
                Event::ConflictsFetched(Ok(files)) => {
                    // Only the transition into "has conflicts" (not every
                    // fetch that happens to still have some) triggers the
                    // one-shot open -- a poll that reconfirms an
                    // already-known, already-rendered conflict list must
                    // never re-force the panel open over a user's own
                    // manual collapse.
                    let was_known_non_empty = self.conflicts.as_ref().is_some_and(|c| !c.is_empty());
                    if !files.is_empty() && !was_known_non_empty {
                        self.conflicts_should_force_open_once = true;
                    }
                    self.conflicts = Some(files);
                    self.conflicts_error = None;
                    self.conflicts_fetch_in_flight = false;
                }
                Event::ConflictsFetched(Err(e)) => {
                    self.conflicts_error = Some(e);
                    self.conflicts_fetch_in_flight = false;
                }
                Event::TrashFetched(Ok(files)) => {
                    self.trash = Some(files);
                    self.trash_error = None;
                    self.trash_fetch_in_flight = false;
                }
                Event::TrashFetched(Err(e)) => {
                    self.trash_error = Some(e);
                    self.trash_fetch_in_flight = false;
                }
                Event::FileToolsFetched(for_path, result) => {
                    // A slower fetch for a file the user has since moved on
                    // from must never clobber the newer selection's own
                    // state -- see `FileToolsFetched`'s own doc comment.
                    if self.file_tools.absolute_path.as_deref() == Some(for_path.as_str()) {
                        self.file_tools.loading = false;
                        match result {
                            Ok((versions, materialization)) => {
                                self.file_tools.versions = Some(versions);
                                self.file_tools.materialization = Some(materialization);
                                self.file_tools.error = None;
                            }
                            Err(e) => self.file_tools.error = Some(e),
                        }
                    }
                }
                Event::ActionDone(kind, result) => {
                    self.action_in_flight = false;
                    let ok = result.is_ok();
                    self.last_action_message = Some(result);
                    // Re-fetch whatever this action just changed, so the
                    // panel reflects the daemon's own new state rather than
                    // a client-side guess -- the daemon is the sole
                    // authority on whether e.g. an evict actually happened
                    // (see `EvictResponse.dehydrated`'s own doc comment).
                    if ok {
                        match kind {
                            ActionKind::TrashRestore => {
                                self.trash_fetch_in_flight = true;
                                spawn_trash_fetch(self.sink.clone(), self.local_path.clone())
                            }
                            ActionKind::VersionRestore
                            | ActionKind::Pin
                            | ActionKind::Unpin
                            | ActionKind::Hydrate
                            | ActionKind::Evict => {
                                if let Some(path) = self.file_tools.absolute_path.clone() {
                                    self.file_tools.loading = true;
                                    spawn_file_tools_fetch(self.sink.clone(), path);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Each fetch is gated by its own in-flight flag, not just the shared
        // 2s cadence timer below -- a fetch that's still running when the
        // next tick arrives (plausible for conflicts/trash, which scan the
        // whole index) must be left alone rather than getting a duplicate
        // spawned alongside it. `due` paces how often a NEW attempt is even
        // considered; it intentionally advances regardless of which of the
        // three actually got spawned, so a slow fetch doesn't also stall the
        // other two's next attempt.
        let due = self.last_fetch_started.is_none_or(|t| t.elapsed() >= POLL_INTERVAL);
        if due {
            self.last_fetch_started = Some(Instant::now());
            if !self.fetch_in_flight {
                self.fetch_in_flight = true;
                spawn_fetch(self.sink.clone());
            }
            if !self.conflicts_fetch_in_flight {
                self.conflicts_fetch_in_flight = true;
                spawn_conflicts_fetch(self.sink.clone(), self.local_path.clone());
            }
            if !self.trash_fetch_in_flight {
                self.trash_fetch_in_flight = true;
                spawn_trash_fetch(self.sink.clone(), self.local_path.clone());
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

impl FolderStatusApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading(folder_display_name(&self.local_path));
        ui.label(egui::RichText::new(&self.local_path).weak().small());
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        if self.error.is_some() {
            // Deliberately does NOT just show an error banner ABOVE
            // otherwise-normal-looking field values below: a fetch
            // failure means everything from here down is a STALE
            // last-known snapshot, not a live confirmation, and must
            // never render identically to a fresh one -- the same
            // "never flash/retain a stale Protected state" principle M4's
            // durability model applies everywhere else (see
            // `crate::folder_detail`'s own doc comment on `Durability !=
            // Connectivity`/fail-closed defaults). Showing the last-known
            // fields at all (rather than blanking them entirely) is a
            // deliberate choice -- "we last saw X, but can't confirm it
            // right now" is more useful than nothing -- but the banner
            // must be impossible to miss and every field below it is
            // visually marked stale.
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                "Can't reach the daemon right now — the details below may be out of date.",
            );
            ui.add_space(8.0);
        }

        let Some(link) = self.link() else {
            if self.status.is_none() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
            } else {
                ui.label("This folder is no longer linked.");
            }
            return;
        };
        let peers = self.peers();
        // `stale` marks every field below as "last known", not confirmed
        // just now -- see the fetch-error branch above for why this must
        // never render identically to a fresh, live-confirmed status.
        let stale = self.error.is_some();

        field_row(ui, "Data protection", crate::folder_detail::data_protection_label(link), stale);
        if let Some(detail) = crate::folder_detail::data_protection_detail(link) {
            ui.label(dim(egui::RichText::new(detail).weak(), stale));
        }
        ui.add_space(6.0);
        field_row(ui, "This device", crate::folder_detail::this_device_label(link), stale);
        ui.add_space(6.0);
        field_row(ui, "Availability", crate::folder_detail::availability_label(link), stale);
        ui.add_space(10.0);

        let copies = crate::folder_detail::complete_copies(link, peers);
        if !copies.is_empty() {
            ui.label(dim(egui::RichText::new("Complete copies").strong(), stale));
            // "configured" is load-bearing, not decoration: this list is a
            // netmap-derived, content-blind STRUCTURAL declaration ("this
            // device is set up to keep everything"), not the peer-confirmed
            // content custody `Data protection` above actually verifies.
            // Dropping this qualifier (an earlier version of this row did)
            // would let "available" read as a verified-complete-copy claim
            // stronger than this daemon can back up (M4 Pass 3 Codex
            // review #3 follow-up) -- mirrors `yadorilink-cli`'s own
            // already-reviewed "configured full copy" wording exactly.
            ui.label(dim(
                egui::RichText::new("Devices configured to keep a full copy:").weak().small(),
                stale,
            ));
            for row in &copies {
                ui.label(dim(
                    format!("  {}  —  configured full copy ({})", row.device_id, row.state.label())
                        .into(),
                    stale,
                ));
            }
            ui.add_space(10.0);
        }

        let connections = crate::folder_detail::connections(link, peers);
        if !connections.is_empty() {
            ui.label(dim(egui::RichText::new("Connection").strong(), stale));
            for row in &connections {
                ui.label(dim(format!("  {}  —  {}", row.device_id, row.label).into(), stale));
            }
        }

        ui.add_space(14.0);
        ui.separator();
        self.render_conflicts(ui);
        ui.add_space(10.0);
        self.render_trash(ui);
        ui.add_space(10.0);
        ui.separator();
        self.render_file_tools(ui);
    }

    fn render_conflicts(&mut self, ui: &mut egui::Ui) {
        // A one-shot signal, not `default_open`: the label above changes
        // with the conflict count, so it's also `id_salt`-pinned to a
        // fixed identity -- without that, `default_open` re-evaluating
        // against a fresh `Id` every time the count changes would fight
        // any manual collapse the user just performed.
        let force_open_this_frame = self.conflicts_should_force_open_once;
        self.conflicts_should_force_open_once = false;
        egui::CollapsingHeader::new(format!(
            "Conflicts{}",
            self.conflicts.as_ref().map(|c| format!(" ({})", c.len())).unwrap_or_default()
        ))
        .id_salt("conflicts_panel")
        .open(force_open_this_frame.then_some(true))
        .show(ui, |ui| {
            if let Some(e) = &self.conflicts_error {
                ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
                return;
            }
            match &self.conflicts {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading…");
                    });
                }
                Some(files) if files.is_empty() => {
                    ui.label("No conflicted files.");
                }
                Some(files) => {
                    for file in files {
                        ui.horizontal(|ui| {
                            ui.label(&file.path);
                            if ui.button("Reveal").clicked() {
                                let full = std::path::Path::new(&self.local_path).join(&file.path);
                                let _ = opener::reveal(&full);
                            }
                        });
                    }
                }
            }
        });
    }

    fn render_trash(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(format!(
            "Trash{}",
            self.trash.as_ref().map(|t| format!(" ({})", t.len())).unwrap_or_default()
        ))
        .default_open(false)
        .show(ui, |ui| {
            if let Some(e) = &self.trash_error {
                ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
                return;
            }
            match &self.trash {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading…");
                    });
                }
                Some(files) if files.is_empty() => {
                    ui.label("Trash is empty.");
                }
                Some(files) => {
                    let mut restore_clicked: Option<String> = None;
                    for file in files {
                        ui.horizontal(|ui| {
                            ui.label(&file.path);
                            if ui
                                .add_enabled(!self.action_in_flight, egui::Button::new("Restore"))
                                .clicked()
                            {
                                restore_clicked = Some(file.path.clone());
                            }
                        });
                    }
                    if let Some(path) = restore_clicked {
                        let absolute_path = std::path::Path::new(&self.local_path)
                            .join(&path)
                            .to_string_lossy()
                            .to_string();
                        self.action_in_flight = true;
                        spawn_action(self.sink.clone(), ActionKind::TrashRestore, async move {
                            crate::actions::restore_trash(absolute_path)
                                .await
                                .map(|()| "Restored from trash.".to_string())
                                .map_err(|e| e.to_string())
                        });
                    }
                }
            }
        });
    }

    /// Version history + selective sync (on-demand pin/unpin/hydrate/
    /// evict) for one file the user explicitly picks -- there is no
    /// daemon request to list every indexed path in a folder (see
    /// `actions::pick_file_in`'s own doc comment), so this panel operates
    /// on exactly one chosen file rather than a full in-app file browser.
    fn render_file_tools(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Version history & selective sync").default_open(false).show(
            ui,
            |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Choose a file…").clicked() {
                        if let Some(path) = crate::actions::pick_file_in(&self.local_path) {
                            let absolute_path = path.to_string_lossy().to_string();
                            self.file_tools = FileTools {
                                absolute_path: Some(absolute_path.clone()),
                                loading: true,
                                ..FileTools::default()
                            };
                            spawn_file_tools_fetch(self.sink.clone(), absolute_path);
                        }
                    }
                    if let Some(path) = &self.file_tools.absolute_path {
                        ui.label(egui::RichText::new(path).weak().small());
                    }
                });

                if let Some(msg) = &self.last_action_message {
                    ui.add_space(6.0);
                    match msg {
                        Ok(text) => {
                            ui.colored_label(egui::Color32::from_rgb(0x2e, 0x9e, 0x5b), text);
                        }
                        Err(text) => {
                            ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), text);
                        }
                    }
                }

                let Some(absolute_path) = self.file_tools.absolute_path.clone() else {
                    return;
                };
                ui.add_space(8.0);

                if let Some(e) = &self.file_tools.error {
                    ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
                }
                if self.file_tools.loading {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading…");
                    });
                }

                if let Some(materialization) = self.file_tools.materialization {
                    ui.label(egui::RichText::new("Selective sync").strong());
                    if materialization.known {
                        let state_label = materialization_state_label(materialization.state());
                        let pinned = if materialization.pinned { ", pinned" } else { "" };
                        ui.label(format!("{state_label}{pinned}"));
                        ui.horizontal(|ui| {
                            let busy = self.action_in_flight;
                            if ui.add_enabled(!busy, egui::Button::new("Pin")).clicked() {
                                self.action_in_flight = true;
                                let path = absolute_path.clone();
                                spawn_action(self.sink.clone(), ActionKind::Pin, async move {
                                    crate::actions::pin_file(path)
                                        .await
                                        .map(|()| "Pinned.".to_string())
                                        .map_err(|e| e.to_string())
                                });
                            }
                            if ui.add_enabled(!busy, egui::Button::new("Unpin")).clicked() {
                                self.action_in_flight = true;
                                let path = absolute_path.clone();
                                spawn_action(self.sink.clone(), ActionKind::Unpin, async move {
                                    crate::actions::unpin_file(path)
                                        .await
                                        .map(|()| "Unpinned.".to_string())
                                        .map_err(|e| e.to_string())
                                });
                            }
                            if ui.add_enabled(!busy, egui::Button::new("Hydrate")).clicked() {
                                self.action_in_flight = true;
                                let path = absolute_path.clone();
                                spawn_action(self.sink.clone(), ActionKind::Hydrate, async move {
                                    crate::actions::hydrate_file(path)
                                        .await
                                        .map(|()| "Hydrated.".to_string())
                                        .map_err(|e| e.to_string())
                                });
                            }
                            if ui.add_enabled(!busy, egui::Button::new("Evict")).clicked() {
                                self.action_in_flight = true;
                                let path = absolute_path.clone();
                                spawn_action(self.sink.clone(), ActionKind::Evict, async move {
                                    crate::actions::evict_file(path)
                                        .await
                                        .map_err(|e| e.to_string())
                                        .map(|dehydrated| {
                                            if dehydrated {
                                                "Evicted (converted to a placeholder).".to_string()
                                            } else {
                                                "Not evicted -- it may be pinned, busy, or not \
                                                 fully synced."
                                                    .to_string()
                                            }
                                        })
                                });
                            }
                        });
                    } else {
                        ui.label(
                            "Not currently tracked (not indexed, or not under a linked folder).",
                        );
                    }
                    ui.add_space(10.0);
                }

                if let Some(versions) = self.file_tools.versions.clone() {
                    ui.label(egui::RichText::new("Version history").strong());
                    if versions.is_empty() {
                        ui.label("No retained versions.");
                    }
                    for version in &versions {
                        ui.horizontal(|ui| {
                            ui.label(version_line(version));
                            if version.state == "superseded"
                                && ui
                                    .add_enabled(
                                        !self.action_in_flight,
                                        egui::Button::new("Restore this version"),
                                    )
                                    .clicked()
                            {
                                self.action_in_flight = true;
                                let path = absolute_path.clone();
                                let version_seq = version.version_seq;
                                spawn_action(
                                    self.sink.clone(),
                                    ActionKind::VersionRestore,
                                    async move {
                                        crate::actions::restore_version(path, Some(version_seq))
                                            .await
                                            .map(|()| format!("Restored to version {version_seq}."))
                                            .map_err(|e| e.to_string())
                                    },
                                );
                            }
                        });
                    }
                }
            },
        );
    }
}

/// `MaterializationState` proto enum -> the same wording
/// `commands::materialization::status` already prints for each state,
/// kept consistent between CLI and desktop app.
fn materialization_state_label(state: MaterializationState) -> &'static str {
    match state {
        MaterializationState::Hydrated => "hydrated",
        MaterializationState::Placeholder => "placeholder",
        MaterializationState::Hydrating => "hydrating",
        MaterializationState::Evicting => "evicting",
        MaterializationState::Unspecified => "unknown",
    }
}

/// One version's summary line -- same fields/order as
/// `commands::version_history::version_line`, this window's own rendering
/// of the identical `FileVersionInfo`.
fn version_line(v: &FileVersionInfo) -> String {
    format!(
        "v{}  {}  size={}  origin={}  state={}  mode={}",
        v.version_seq,
        v.mtime_unix_nanos,
        v.size,
        if v.origin_device_id.is_empty() { "unknown" } else { &v.origin_device_id },
        v.state,
        // `-` for "no Unix permission info" (e.g. authored on Windows) --
        // never fabricated as a fake octal value.
        v.unix_mode.map(|mode| format!("{mode:#o}")).unwrap_or_else(|| "-".to_string()),
    )
}

/// The folder's last path segment, mirroring `status_model::
/// folder_menu_label`'s own "don't blow out the window with a long path"
/// choice.
fn folder_display_name(local_path: &str) -> String {
    std::path::Path::new(local_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| local_path.to_string())
}

fn field_row(ui: &mut egui::Ui, label: &str, value: &str, stale: bool) {
    ui.horizontal(|ui| {
        ui.label(dim(egui::RichText::new(label).strong(), stale));
        ui.label(dim(egui::RichText::new(value), stale));
    });
}

/// Visually marks `text` as a stale (not just-confirmed) value when
/// `stale` is true -- weakened color, matching this window's own
/// "never render a stale value identically to a fresh one" rule (see
/// `render_body`'s fetch-error branch).
fn dim(text: egui::RichText, stale: bool) -> egui::RichText {
    if stale {
        text.weak()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_display_name_uses_the_last_path_segment() {
        assert_eq!(folder_display_name("/Users/alice/Photos"), "Photos");
    }

    #[test]
    fn folder_display_name_falls_back_to_the_whole_path_when_it_has_no_segment() {
        assert_eq!(folder_display_name("/"), "/");
    }

    #[test]
    fn materialization_state_label_covers_every_state() {
        assert_eq!(materialization_state_label(MaterializationState::Hydrated), "hydrated");
        assert_eq!(materialization_state_label(MaterializationState::Placeholder), "placeholder");
        assert_eq!(materialization_state_label(MaterializationState::Hydrating), "hydrating");
        assert_eq!(materialization_state_label(MaterializationState::Evicting), "evicting");
        assert_eq!(materialization_state_label(MaterializationState::Unspecified), "unknown");
    }

    #[test]
    fn version_line_renders_every_field() {
        let v = FileVersionInfo {
            version_seq: 3,
            size: 42,
            mtime_unix_nanos: 12345,
            state: "superseded".into(),
            origin_device_id: "device-a".into(),
            unix_mode: Some(0o755),
        };
        assert_eq!(
            version_line(&v),
            "v3  12345  size=42  origin=device-a  state=superseded  mode=0o755"
        );
    }

    #[test]
    fn version_line_renders_unknown_origin() {
        let v = FileVersionInfo {
            version_seq: 1,
            size: 0,
            mtime_unix_nanos: 0,
            state: "current".into(),
            origin_device_id: String::new(),
            unix_mode: None,
        };
        assert!(version_line(&v).contains("origin=unknown"));
    }

    /// No Unix permission info (a version authored on Windows) renders as
    /// `-`, never a fabricated octal value -- same rule as the CLI's own
    /// `version_history::version_line`.
    #[test]
    fn version_line_renders_absent_unix_mode() {
        let v = FileVersionInfo {
            version_seq: 1,
            size: 0,
            mtime_unix_nanos: 0,
            state: "current".into(),
            origin_device_id: "device-a".into(),
            unix_mode: None,
        };
        assert!(version_line(&v).contains("mode=-"));
    }
}
