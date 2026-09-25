//! Entry point for `--window folder-status --path <local_path>` -- the
//! per-folder detail window presenting "Data protection / This
//! device / Availability / Complete copies / Connection" for one linked
//! folder, per `folder_detail.rs`'s pure formatters. Same threading/state
//! shape as `account.rs`'s window (own `mpsc` channel + `EventSink` from
//! `onboarding::executor`, background thread does the IPC fetch, `update`
//! only ever reads already-computed state) -- simpler than the onboarding
//! wizard's `Effect`/`step` machine since this window has exactly one
//! operation (fetch status) and no user-driven transitions to model.
//!
//! Test coverage: the pure logic in `folder_detail.rs` is unit-tested; this
//! file's `eframe`/`egui` rendering is covered by compilation, not by
//! automated UI tests.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, FileVersionInfo, LinkStatus, MaterializationState,
    MaterializationStatusResponse, PeerStatus, RestoreTrashOperationResponse, StatusResponse,
    TrashedFileInfo,
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
    /// Other devices with access to this folder's group --
    /// `crate::devices::peer_count`, a coordination-plane call
    /// separate from the daemon-control `StatusFetched` above (see that
    /// function's own doc comment for why it's split out).
    PeerCountFetched(Result<usize, String>),
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
            crate::fonts::install(&cc.egui_ctx);
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

fn spawn_peer_count_fetch(sink: EventSink<Event>, group_id: String) {
    spawn_task(
        sink,
        async move { crate::devices::peer_count(&group_id).await.map_err(|e| e.to_string()) },
        Event::PeerCountFetched,
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
    peer_count: Option<usize>,
    peer_count_error: Option<String>,
    peer_count_fetch_in_flight: bool,
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
            peer_count: None,
            peer_count_error: None,
            peer_count_fetch_in_flight: false,
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

    fn volumes(&self) -> &[yadorilink_ipc_proto::daemonctl::VolumeFreeSpace] {
        self.status.as_ref().map(|s| s.volumes.as_slice()).unwrap_or_default()
    }
}

impl eframe::App for FolderStatusApp {
    #[allow(
        clippy::excessive_nesting,
        reason = "the event-drain loop is one match over every `Event` variant, and the post-action re-fetch arm nests match-on-`ActionKind` inside it so the exhaustiveness check keeps each action wired to the fetch that reconfirms it against the daemon; lifting the arms out would split that correspondence across items"
    )]
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
                Event::PeerCountFetched(Ok(count)) => {
                    self.peer_count = Some(count);
                    self.peer_count_error = None;
                    self.peer_count_fetch_in_flight = false;
                }
                Event::PeerCountFetched(Err(e)) => {
                    self.peer_count_error = Some(e);
                    self.peer_count_fetch_in_flight = false;
                }
                Event::ConflictsFetched(Ok(files)) => {
                    // Only the transition into "has conflicts" (not every
                    // fetch that happens to still have some) triggers the
                    // one-shot open -- a poll that reconfirms an
                    // already-known, already-rendered conflict list must
                    // never re-force the panel open over a user's own
                    // manual collapse.
                    let was_known_non_empty =
                        self.conflicts.as_ref().is_some_and(|c| !c.is_empty());
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
                    // A folder restore that failed for some of its entries
                    // still restored the rest, so the trash is re-read
                    // whatever the outcome.
                    if ok || kind == ActionKind::TrashRestore {
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
            // The peer count needs this folder's `group_id`, which is only
            // known once the first status fetch has resolved -- gated on
            // `self.link()` rather than the shared `due` timer alone, and
            // re-fetched (not just fetched once) so a later readiness/access
            // change is eventually reflected without requiring the user to
            // reopen the window.
            if !self.peer_count_fetch_in_flight {
                if let Some(group_id) = self.link().map(|l| l.group_id.clone()) {
                    self.peer_count_fetch_in_flight = true;
                    spawn_peer_count_fetch(self.sink.clone(), group_id);
                }
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
        ui.horizontal(|ui| {
            ui.heading(crate::status_model::folder_display_name(&self.local_path));
            // This window's own mutating actions are per-file (trash
            // restore, version restore, pin/unpin, hydrate/evict); nothing
            // here touches sharing. The button opens the sharing window as
            // its own process (exactly what the tray's own "Share…" item
            // does) and never mints or changes anything itself.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Share…").clicked() {
                    crate::actions::spawn_window_with_path("share", &self.local_path);
                }
            });
        });
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
            // "never flash/retain a stale Protected state" principle the
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
        // What the claim above is standing on. Shown here rather than folded
        // into the label because "confirmed" and "verified" are genuinely
        // different assurances and this is the one screen where a user is
        // asking about assurance.
        if let Some(evidence) = crate::folder_detail::data_protection_evidence(link) {
            ui.label(dim(egui::RichText::new(evidence).weak().small(), stale));
        }
        ui.add_space(6.0);
        field_row(ui, "This device", crate::folder_detail::this_device_label(link), stale);
        ui.add_space(6.0);
        field_row(ui, "Availability", crate::folder_detail::availability_label(link), stale);
        ui.add_space(6.0);

        // Peers -- a coordination-plane count, not a `StatusResponse`
        // field, so it has its own loading/error state independent of the
        // `stale` flag above (see `PeerCountFetched`'s doc comment).
        match (&self.peer_count, &self.peer_count_error) {
            (Some(count), _) => field_row(ui, "Peers", &format!("{count}"), stale),
            (None, Some(e)) => field_row(ui, "Peers", &format!("unavailable ({e})"), true),
            (None, None) => field_row(ui, "Peers", "…", true),
        }

        // Disk usage -- this folder's own volume, matched by exact local
        // path (see `disk_usage_for`'s own doc comment on why exact, not
        // prefix, matching is correct here).
        if let Some(volume) = crate::folder_detail::disk_usage_for(link, self.volumes()) {
            field_row(ui, "Disk usage", &crate::folder_detail::disk_usage_label(volume), stale);
        }
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
            // stronger than this daemon can back up -- mirrors `yadorilink-cli`'s own
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

    #[allow(
        clippy::excessive_nesting,
        reason = "egui is immediate-mode: the conflict rows only exist inside the CollapsingHeader/match/for/horizontal closure chain that draws them, so the nesting is the widget tree itself and cannot be flattened without passing `ui` back out"
    )]
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
                        let detail = yadorilink_product_view::conflict_detail(file);
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(&file.path);
                            if ui.button("Reveal this copy").clicked() {
                                let full = std::path::Path::new(&self.local_path).join(&file.path);
                                let _ = opener::reveal(&full);
                            }
                        });
                        ui.label(egui::RichText::new(conflict_origin_line(&detail)).weak().small());
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "Current version kept at: {}",
                                    detail.current_path
                                ))
                                .weak()
                                .small(),
                            );
                            if ui.small_button("Reveal current").clicked() {
                                let full = std::path::Path::new(&self.local_path)
                                    .join(&detail.current_path);
                                let _ = opener::reveal(&full);
                            }
                        });
                        ui.label(
                            egui::RichText::new(format!("Why: {}", detail.reason.explanation()))
                                .weak()
                                .small(),
                        );
                        ui.add_space(4.0);
                    }
                }
            }
        });
    }

    #[allow(
        clippy::excessive_nesting,
        reason = "the deferred `restore_clicked` handoff has to sit in the same scope as the row loop that sets it -- egui forbids mutating window state from inside the row closure -- so the collect-then-apply pattern keeps the click and its action in one readable block"
    )]
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
                    let mut restore_clicked: Option<TrashRestoreClick> = None;
                    for group in trash_groups(files) {
                        ui.add_space(4.0);
                        let indent = if group.operation.is_some() {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(folder_group_title(&group)).strong());
                                if ui
                                    .add_enabled(
                                        !self.action_in_flight,
                                        egui::Button::new("Restore folder"),
                                    )
                                    .on_hover_text(
                                        "Restores everything this delete or rename removed, \
                                         together.",
                                    )
                                    .clicked()
                                {
                                    restore_clicked = Some(TrashRestoreClick::Folder(
                                        group.root_path().to_string(),
                                    ));
                                }
                            });
                            12.0
                        } else {
                            0.0
                        };
                        for file in &group.entries {
                            ui.horizontal(|ui| {
                                ui.add_space(indent);
                                ui.label(&file.path);
                                if ui
                                    .add_enabled(
                                        !self.action_in_flight,
                                        egui::Button::new("Restore"),
                                    )
                                    .clicked()
                                {
                                    restore_clicked =
                                        Some(TrashRestoreClick::Entry(file.path.clone()));
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.add_space(indent);
                                ui.label(
                                    egui::RichText::new(trashed_file_provenance_line(file))
                                        .weak()
                                        .small(),
                                );
                            });
                        }
                    }
                    if let Some(click) = restore_clicked {
                        self.action_in_flight = true;
                        let local_path = self.local_path.clone();
                        let absolute = move |path: &str| {
                            std::path::Path::new(&local_path)
                                .join(path)
                                .to_string_lossy()
                                .to_string()
                        };
                        match click {
                            TrashRestoreClick::Entry(path) => {
                                let absolute_path = absolute(&path);
                                spawn_action(
                                    self.sink.clone(),
                                    ActionKind::TrashRestore,
                                    async move {
                                        crate::actions::restore_trash(absolute_path)
                                            .await
                                            .map(|()| "Restored from trash.".to_string())
                                            .map_err(|e| e.to_string())
                                    },
                                );
                            }
                            TrashRestoreClick::Folder(path) => {
                                let absolute_path = absolute(&path);
                                spawn_action(
                                    self.sink.clone(),
                                    ActionKind::TrashRestore,
                                    async move {
                                        crate::actions::restore_trash_operation(absolute_path)
                                            .await
                                            .map_err(|e| e.to_string())
                                            .and_then(|outcome| folder_restore_message(&outcome))
                                    },
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    /// Version history + selective sync (on-demand pin/unpin/hydrate/
    /// evict) for one file or folder the user explicitly picks -- there is
    /// no daemon request to list every indexed path in a folder (see
    /// `actions::pick_file_in`'s own doc comment), so this panel operates
    /// on exactly one chosen entry rather than a full in-app file browser.
    /// A folder's selective sync acts on everything below it.
    #[allow(
        clippy::excessive_nesting,
        reason = "one panel whose pin/unpin/hydrate/evict buttons and version-restore rows all close over the same `absolute_path` and `action_in_flight` guard; the depth is egui's nested-closure widget tree, and splitting per button would duplicate that shared borrow state"
    )]
    fn render_file_tools(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Version history & selective sync").default_open(false).show(
            ui,
            |ui| {
                ui.horizontal(|ui| {
                    let picked = if ui.button("Choose a file…").clicked() {
                        crate::actions::pick_file_in(&self.local_path)
                    } else if ui
                        .button("Choose a folder…")
                        .on_hover_text(
                            "Pin, download or evict a folder as a whole. A pinned folder keeps \
                             what is added to it later on this device too.",
                        )
                        .clicked()
                    {
                        crate::actions::pick_folder_in(&self.local_path)
                    } else {
                        None
                    };
                    if let Some(path) = picked {
                        let absolute_path = path.to_string_lossy().to_string();
                        self.file_tools = FileTools {
                            absolute_path: Some(absolute_path.clone()),
                            loading: true,
                            ..FileTools::default()
                        };
                        spawn_file_tools_fetch(self.sink.clone(), absolute_path);
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

/// Which trash row's restore button was clicked this frame -- applied after
/// the row loop, since egui forbids mutating window state inside it.
enum TrashRestoreClick {
    /// One trashed entry, on its own.
    Entry(String),
    /// Every entry one recursive delete or directory rename removed, named
    /// by any of them; the daemon finds the rest by the operation.
    Folder(String),
}

/// Trashed entries as the Trash panel shows them: the entries one recursive
/// delete or directory rename removed together form one group (restorable
/// as a folder), and every entry deleted on its own is a group of one.
/// Groups keep the order their first entry has in the daemon's listing.
#[derive(Debug, PartialEq)]
struct TrashGroup<'a> {
    /// `TrashedFileInfo.deleted_by_operation`; `None` for an entry deleted
    /// on its own.
    operation: Option<String>,
    entries: Vec<&'a TrashedFileInfo>,
}

impl TrashGroup<'_> {
    /// The group's outermost entry: the one with the fewest path
    /// components, the first such in path order on a tie. A delete of a
    /// folder names the folder; a rename names its source.
    fn root_path(&self) -> &str {
        self.entries
            .iter()
            .map(|entry| entry.path.as_str())
            .min_by(|a, b| a.split('/').count().cmp(&b.split('/').count()).then(a.cmp(b)))
            .unwrap_or_default()
    }
}

fn trash_groups(files: &[TrashedFileInfo]) -> Vec<TrashGroup<'_>> {
    let mut groups: Vec<TrashGroup<'_>> = Vec::new();
    for file in files {
        if file.deleted_by_operation.is_empty() {
            groups.push(TrashGroup { operation: None, entries: vec![file] });
            continue;
        }
        match groups
            .iter_mut()
            .find(|group| group.operation.as_deref() == Some(file.deleted_by_operation.as_str()))
        {
            Some(group) => group.entries.push(file),
            None => groups.push(TrashGroup {
                operation: Some(file.deleted_by_operation.clone()),
                entries: vec![file],
            }),
        }
    }
    groups
}

/// "Removed together with Photos/2024 (3 items)". The trash does not say
/// whether the operation was a delete or a rename, so the title names only
/// what both do to these entries: remove them from where they were.
fn folder_group_title(group: &TrashGroup<'_>) -> String {
    let count = group.entries.len();
    format!(
        "Removed together with {} ({count} item{})",
        group.root_path(),
        if count == 1 { "" } else { "s" }
    )
}

/// A folder restore's outcome as one line. Any entry that could not be
/// restored makes it a failure naming each one, even though the rest were
/// restored; an operation only part of which has reached this device says
/// so, since entries it removed elsewhere in the folder are not back.
fn folder_restore_message(outcome: &RestoreTrashOperationResponse) -> Result<String, String> {
    let restored = outcome.restored_paths.len();
    let mut text =
        format!("Restored {restored} item{} of the folder.", if restored == 1 { "" } else { "s" });
    if outcome.partial {
        text.push_str(
            " Part of that delete has not reached this device yet, so what it removed elsewhere \
             in the folder is not restored.",
        );
    }
    if outcome.failed.is_empty() {
        return Ok(text);
    }
    let failures: Vec<String> = outcome
        .failed
        .iter()
        .map(|failure| format!("{}: {}", failure.path, failure.error))
        .collect();
    Err(format!("{text} Could not restore {}.", failures.join("; ")))
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

/// "Deleted 3h ago by device-a  ·  v4  ·  1.2 MiB" -- a trashed file's
/// causal provenance: which device's edit produced the version that got
/// deleted, when, and its last known size/version, straight from
/// `TrashedFileInfo`'s own fields (no re-derivation) -- this window
/// previously rendered only the bare path here, dropping all of this.
fn trashed_file_provenance_line(f: &TrashedFileInfo) -> String {
    format!(
        "Deleted {} by {}  ·  v{}  ·  {}",
        relative_time_from_unix_nanos(f.deleted_at_unix_nanos),
        if f.origin_device_id.is_empty() { "unknown device" } else { &f.origin_device_id },
        f.version_seq,
        // A directory has no size of its own.
        if f.kind() == yadorilink_ipc_proto::daemonctl::EntryKind::Directory {
            "folder".to_string()
        } else {
            format_bytes_short(f.last_known_size.max(0) as u64)
        },
    )
}

/// "3m ago"/"2h ago"/"5d ago"/"just now"/"unknown time" -- same relative-
/// bucket shape `home_window.rs`'s `last_seen_label` and `yadorilink-cli`'s
/// `commands::status::last_gc_summary` already use (kept as its own copy,
/// matching this crate's established duplication precedent -- see
/// `ipc_client.rs`'s doc comment); this one takes nanoseconds since
/// `TrashedFileInfo.deleted_at_unix_nanos`/`FileVersionInfo.mtime_unix_nanos`
/// are nanosecond-scaled, unlike `DeviceSummary.last_seen_unix`.
fn relative_time_from_unix_nanos(nanos: i64) -> String {
    if nanos <= 0 {
        return "unknown time".to_string();
    }
    let secs = nanos / 1_000_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let elapsed = (now - secs).max(0);
    if elapsed < 10 {
        "just now".to_string()
    } else if elapsed < 60 {
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
/// (private to that module -- kept as its own copy here rather than
/// exposing it, matching this crate's established duplication precedent).
fn format_bytes_short(bytes: u64) -> String {
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

/// "From <device>, saved <timestamp>" -- the losing side's origin, parsed
/// from the conflicted-copy filename itself (see `yadorilink_product_view::
/// conflict_detail`'s own doc comment for why that's where this data
/// actually lives on the wire today). Degrades to a plain statement when
/// either field didn't parse, rather than printing a raw `None`.
fn conflict_origin_line(detail: &yadorilink_product_view::ConflictDetail) -> String {
    match (&detail.loser_device_id, &detail.timestamp) {
        (Some(device), Some(ts)) => format!("From {device}, saved {ts}"),
        (Some(device), None) => format!("From {device}"),
        (None, _) => "Origin device unknown".to_string(),
    }
}

/// One version's summary line -- same fields/order as
/// `commands::version_history::version_line`, this window's own rendering
/// of the identical `FileVersionInfo`.
fn version_line(v: &FileVersionInfo) -> String {
    let content = if v.kind() == yadorilink_ipc_proto::daemonctl::EntryKind::Directory {
        "directory".to_string()
    } else {
        format!("{}  size={}", v.mtime_unix_nanos, v.size)
    };
    format!(
        "v{}  {content}  origin={}  state={}  mode={}",
        v.version_seq,
        if v.origin_device_id.is_empty() { "unknown" } else { &v.origin_device_id },
        v.state,
        // `-` for "no Unix permission info" (e.g. authored on Windows) --
        // never fabricated as a fake octal value.
        v.unix_mode.map(|mode| format!("{mode:#o}")).unwrap_or_else(|| "-".to_string()),
    )
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
mod tests;
