//! Entry point for `--window home` — the Home screen: an at-a-glance
//! aggregate view across every linked folder and every device with access
//! to any of them, plus the mode/pause/peer/disk-usage controls the tray's
//! own menu never had room for, built on the `yadorilink-product-view`
//! DTO layer.
//!
//! Same "own `mpsc` channel + `EventSink` from `onboarding::executor`,
//! background thread does the IPC/coordination-plane fetch, `update` only
//! ever reads already-computed state" shape as `folder_status_window.rs`
//! and `account.rs`. Two independent poll loops run at different cadences
//! for a reason: `StatusResponse` (the daemon control socket) is cheap and
//! polled every 2s like every other window; the device/peer-count listing
//! is a coordination-plane HTTP call per distinct folder group
//! (`crate::devices::device_summaries`/`peer_counts`), so it is
//! fetched once at startup and again only when the *set* of distinct
//! `group_id`s this device links actually changes (a folder linked/
//! unlinked) — never on every 2s status tick, which would hammer the
//! coordination plane for no reason (see the design doc's own "Open
//! dependencies" note on batching this).
//!
//! Mutating actions here (`actions::pause_link`/`resume_link`/
//! `set_folder_mode`/`remove_device`) are the same thin daemon/coordination-
//! plane calls every other window in this crate already uses — this file
//! invents no new sync behavior, mirroring `actions.rs`'s own top doc
//! comment.
//!
//! Test coverage: the pure logic this renders (`status_model`,
//! `folder_detail`, `yadorilink_product_view`) is unit-tested; this file's
//! `eframe`/`egui` rendering is covered by compilation, not by automated
//! UI tests.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_ipc_proto::daemonctl::StatusResponse;
use yadorilink_product_view::{DeviceSummary, FolderMode, FolderState, FolderSummary};

use crate::onboarding::executor::EventSink;

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Event {
    // Boxed for the same `clippy::large_enum_variant` reason
    // `folder_status_window.rs`'s identical variant is.
    StatusFetched(Result<Box<StatusResponse>, String>),
    DevicesFetched(Result<(Vec<DeviceSummary>, HashMap<String, usize>), String>),
    /// `local_path`, then the pause/resume outcome.
    PauseToggleDone(String, Result<(), String>),
    /// `group_id`, then the mode-switch outcome message (already worded --
    /// see `set_folder_mode`'s own `StorageModeOutcome`).
    ModeSwitchDone(String, Result<String, String>),
    /// `device_id`, then the removal outcome.
    RemoveDeviceDone(String, Result<(), String>),
}

/// Entry point for `--window home`. Must run on the process main thread
/// (same `eframe`/winit constraint every other window in this crate
/// already follows).
pub fn run_home() -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 620.0])
            .with_min_inner_size([560.0, 420.0])
            .with_title("YadoriLink"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(HomeApp::new(rx, sink)))
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

/// Same shared thread+runtime scaffolding as `folder_status_window.rs`'s
/// `spawn_task` -- kept as its own copy rather than a shared helper since
/// each window's `Event` type differs and this is a handful of lines, not
/// worth a new module just to share.
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

/// One combined coordination-plane fetch: `device_summaries` and
/// `peer_counts` each fire their own one-call-per-distinct-group_id fan-out
/// (`crate::devices::group_memberships` backs both), so
/// firing them concurrently rather than sequentially halves the wall-clock
/// cost of a Home window's startup fetch without doubling the number of
/// HTTP calls made.
fn spawn_devices_fetch(
    sink: EventSink<Event>,
    links: Vec<yadorilink_ipc_proto::daemonctl::LinkStatus>,
) {
    spawn_task(
        sink,
        async move {
            let (devices, counts) = tokio::join!(
                crate::devices::device_summaries(&links),
                crate::devices::peer_counts(&links),
            );
            let devices = devices.map_err(|e| e.to_string())?;
            let counts = counts.map_err(|e| e.to_string())?;
            Ok((devices, counts))
        },
        Event::DevicesFetched,
    );
}

fn spawn_pause_toggle(sink: EventSink<Event>, local_path: String, pause: bool) {
    let for_path = local_path.clone();
    spawn_task(
        sink,
        async move {
            if pause {
                crate::actions::pause_link(local_path).await.map_err(|e| e.to_string())
            } else {
                crate::actions::resume_link(local_path).await.map_err(|e| e.to_string())
            }
        },
        move |result| Event::PauseToggleDone(for_path, result),
    );
}

fn spawn_mode_switch(
    sink: EventSink<Event>,
    group_id: String,
    on_demand: bool,
    display_name: String,
) {
    let for_group = group_id.clone();
    spawn_task(
        sink,
        async move {
            crate::actions::set_folder_mode(group_id, on_demand, &display_name)
                .await
                .map(|outcome| mode_switch_message(&display_name, on_demand, &outcome))
                .map_err(|e| e.to_string())
        },
        move |result| Event::ModeSwitchDone(for_group, result),
    );
}

fn mode_switch_message(
    display_name: &str,
    on_demand: bool,
    outcome: &yadorilink_client_core::ops::shares::StorageModeOutcome,
) -> String {
    let mode = if on_demand { "Selective" } else { "Synced" };
    if outcome.changed {
        format!("{display_name} is now {mode}.")
    } else {
        format!("{display_name} was already {mode}.")
    }
}

fn spawn_remove_device(sink: EventSink<Event>, device_id: String, force: bool) {
    let for_device = device_id.clone();
    spawn_task(
        sink,
        async move { crate::actions::remove_device(device_id, force).await.map_err(|e| e.to_string()) },
        move |result| Event::RemoveDeviceDone(for_device, result),
    );
}

struct HomeApp {
    status: Option<StatusResponse>,
    error: Option<String>,
    rx: Receiver<Event>,
    sink: EventSink<Event>,
    fetch_in_flight: bool,
    last_fetch_started: Option<Instant>,

    devices: Option<Vec<DeviceSummary>>,
    peer_counts: HashMap<String, usize>,
    devices_error: Option<String>,
    devices_fetch_in_flight: bool,
    /// The distinct, sorted `group_id`s the last devices fetch was for --
    /// re-fetched only when this set actually changes (a folder linked or
    /// unlinked), never on every 2s status tick.
    devices_fetched_for_groups: Vec<String>,

    /// `local_path`s currently mid pause/resume, so a double click can't
    /// fire the request twice and the row can show a spinner instead of a
    /// clickable button while it's in flight.
    pause_in_flight: std::collections::HashSet<String>,
    /// `group_id`s currently mid mode-switch, same reason.
    mode_switch_in_flight: std::collections::HashSet<String>,
    /// `device_id`s currently mid removal, same reason.
    remove_in_flight: std::collections::HashSet<String>,

    /// The most recent action's outcome, shown as a one-line banner until
    /// the next action replaces it -- same "show it, don't swallow it" rule
    /// `folder_status_window.rs`'s `last_action_message` already follows.
    last_action_message: Option<Result<String, String>>,
}

impl HomeApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        HomeApp {
            status: None,
            error: None,
            rx,
            sink,
            fetch_in_flight: false,
            last_fetch_started: None,
            devices: None,
            peer_counts: HashMap::new(),
            devices_error: None,
            devices_fetch_in_flight: false,
            devices_fetched_for_groups: Vec::new(),
            pause_in_flight: Default::default(),
            mode_switch_in_flight: Default::default(),
            remove_in_flight: Default::default(),
            last_action_message: None,
        }
    }

    fn links(&self) -> &[yadorilink_ipc_proto::daemonctl::LinkStatus] {
        self.status.as_ref().map(|s| s.links.as_slice()).unwrap_or_default()
    }

    /// The distinct `group_id`s currently linked, sorted -- compared
    /// against `devices_fetched_for_groups` to decide whether the devices
    /// fetch is stale.
    fn distinct_group_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> =
            self.links().iter().map(|l| l.group_id.clone()).filter(|g| !g.is_empty()).collect();
        ids.sort();
        ids.dedup();
        ids
    }
}

impl eframe::App for HomeApp {
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
                Event::DevicesFetched(Ok((devices, counts))) => {
                    self.devices = Some(devices);
                    self.peer_counts = counts;
                    self.devices_error = None;
                    self.devices_fetch_in_flight = false;
                }
                Event::DevicesFetched(Err(e)) => {
                    self.devices_error = Some(e);
                    self.devices_fetch_in_flight = false;
                }
                Event::PauseToggleDone(local_path, result) => {
                    self.pause_in_flight.remove(&local_path);
                    if let Err(e) = result {
                        self.last_action_message = Some(Err(e));
                    }
                    // The next 2s status tick reflects the daemon's own new
                    // `paused` state; no client-side guess is stored here.
                }
                Event::ModeSwitchDone(group_id, result) => {
                    self.mode_switch_in_flight.remove(&group_id);
                    self.last_action_message = Some(result);
                }
                Event::RemoveDeviceDone(device_id, result) => {
                    self.remove_in_flight.remove(&device_id);
                    match result {
                        Ok(()) => {
                            self.last_action_message = Some(Ok("Device removed.".to_string()));
                            // Re-fetch: the removed device (and any group
                            // whose membership just changed) must not
                            // linger in a stale listing.
                            self.devices_fetched_for_groups.clear();
                        }
                        Err(e) => self.last_action_message = Some(Err(e)),
                    }
                }
            }
        }

        let due = self.last_fetch_started.is_none_or(|t| t.elapsed() >= STATUS_POLL_INTERVAL);
        if due {
            self.last_fetch_started = Some(Instant::now());
            if !self.fetch_in_flight {
                self.fetch_in_flight = true;
                spawn_status_fetch(self.sink.clone());
            }
        }

        let current_groups = self.distinct_group_ids();
        if !self.devices_fetch_in_flight
            && !current_groups.is_empty()
            && current_groups != self.devices_fetched_for_groups
        {
            self.devices_fetch_in_flight = true;
            self.devices_fetched_for_groups = current_groups;
            spawn_devices_fetch(self.sink.clone(), self.links().to_vec());
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_body(ui);
            });
        });

        ctx.request_repaint_after(STATUS_POLL_INTERVAL);
    }
}

impl HomeApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("YadoriLink");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Add Synced Folder…").clicked() {
                    crate::actions::spawn_window("onboarding");
                }
            });
        });

        match &self.status {
            Some(status) => {
                ui.label(egui::RichText::new(crate::status_model::headline(status)).strong());
                for reason in crate::status_model::reason_lines(status) {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                        format!("! {reason}"),
                    );
                }
            }
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
            }
        }
        if let Some(e) = &self.error {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!("Can't reach the daemon right now: {e}"),
            );
        }

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

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        self.render_transfers(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(8.0);
        self.render_folders(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(8.0);
        self.render_devices(ui);
    }

    fn render_transfers(&self, ui: &mut egui::Ui) {
        let transferring: Vec<FolderSummary> =
            self.links().iter().map(FolderSummary::from).filter(|f| f.transfer.is_some()).collect();

        ui.label(egui::RichText::new("Transfers").strong());
        if transferring.is_empty() {
            ui.label(egui::RichText::new("Nothing is currently transferring.").weak());
            return;
        }
        for folder in &transferring {
            let transfer = folder.transfer.as_ref().unwrap();
            ui.horizontal(|ui| {
                ui.label(&folder.name);
                ui.label(
                    egui::RichText::new(crate::folder_detail::transfer_progress_label(transfer))
                        .weak(),
                );
            });
        }
    }

    fn render_folders(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Folders").strong());
        if self.status.is_some() && self.links().is_empty() {
            ui.label(egui::RichText::new("No folders linked yet.").weak());
            return;
        }

        let volumes: Vec<yadorilink_ipc_proto::daemonctl::VolumeFreeSpace> =
            self.status.as_ref().map(|s| s.volumes.clone()).unwrap_or_default();
        let links = self.links().to_vec();

        let mut pause_clicked: Option<(String, bool)> = None;
        let mut mode_clicked: Option<(String, bool, String)> = None;

        for link in &links {
            let folder = FolderSummary::from(link);
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&folder.name).strong());
                    ui.label(state_badge(folder.state));
                    ui.label(mode_badge(folder.mode));
                    if let Some(count) = self.peer_counts.get(&folder.group_id) {
                        ui.label(egui::RichText::new(format!("{count} peer(s)")).weak());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Details…").clicked() {
                            crate::actions::spawn_window_with_path(
                                "folder-status",
                                &link.local_path,
                            );
                        }
                        if ui.button("Share…").clicked() {
                            crate::actions::spawn_window_with_path("share", &link.local_path);
                        }
                    });
                });
                ui.label(egui::RichText::new(&folder.local_path).weak().small());

                // Durability/health -- otherwise only visible by opening
                // this folder's own Details window per folder
                // (`folder_detail::data_protection_label`/`_detail`, the
                // same pure formatters that window already
                // renders; this is the identical fact, not a re-derivation,
                // just surfaced at Home's own at-a-glance level so a
                // last-full-replica warning doesn't require opening every
                // folder individually to notice).
                ui.horizontal(|ui| {
                    ui.label(data_protection_badge(link));
                });
                if let Some(detail) = crate::folder_detail::data_protection_detail(link) {
                    ui.label(egui::RichText::new(detail).weak().small());
                }

                if let Some(volume) = crate::folder_detail::disk_usage_for(link, &volumes) {
                    ui.label(
                        egui::RichText::new(crate::folder_detail::disk_usage_label(volume))
                            .weak()
                            .small(),
                    );
                }

                ui.horizontal(|ui| {
                    let pausing = self.pause_in_flight.contains(&link.local_path);
                    let pause_label = if folder.paused { "Resume" } else { "Pause" };
                    if ui.add_enabled(!pausing, egui::Button::new(pause_label)).clicked() {
                        pause_clicked = Some((link.local_path.clone(), !folder.paused));
                    }
                    if pausing {
                        ui.spinner();
                    }

                    ui.add_space(12.0);
                    ui.label("Mode:");
                    let switching = self.mode_switch_in_flight.contains(&folder.group_id);
                    ui.add_enabled_ui(!switching, |ui| {
                        let mut mode = folder.mode;
                        if ui.radio_value(&mut mode, FolderMode::Synced, "Synced").clicked()
                            && folder.mode != FolderMode::Synced
                        {
                            mode_clicked =
                                Some((folder.group_id.clone(), false, folder.name.clone()));
                        }
                        if ui.radio_value(&mut mode, FolderMode::Selective, "Selective").clicked()
                            && folder.mode != FolderMode::Selective
                        {
                            mode_clicked =
                                Some((folder.group_id.clone(), true, folder.name.clone()));
                        }
                    });
                    if switching {
                        ui.spinner();
                    }
                });

                if folder.mode == FolderMode::Selective {
                    ui.label(
                        egui::RichText::new(
                            "Selective sync applies to this whole folder on this device. \
                             Per-subpath selection isn't available yet.",
                        )
                        .weak()
                        .small(),
                    );
                }
            });
        }

        if let Some((local_path, pause)) = pause_clicked {
            self.pause_in_flight.insert(local_path.clone());
            spawn_pause_toggle(self.sink.clone(), local_path, pause);
        }
        if let Some((group_id, on_demand, display_name)) = mode_clicked {
            // A demotion (Synced -> Selective) can permanently give up this
            // device's full-replica status for the group; confirm before
            // asking the daemon, the same native-dialog pattern `main.rs`'s
            // unlink handler already uses for its own data-affecting action.
            let proceed = if on_demand {
                rfd::MessageDialog::new()
                    .set_title("Switch to Selective sync?")
                    .set_description(format!(
                        "{display_name}\n\nThis device will stop keeping a full copy of this \
                         folder. YadoriLink refuses this if no other device currently holds a \
                         confirmed-ready full copy."
                    ))
                    .set_buttons(rfd::MessageButtons::OkCancel)
                    .show()
                    == rfd::MessageDialogResult::Ok
            } else {
                true
            };
            if proceed {
                self.mode_switch_in_flight.insert(group_id.clone());
                spawn_mode_switch(self.sink.clone(), group_id, on_demand, display_name);
            }
        }
    }

    fn render_devices(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Devices").strong());
        match &self.devices {
            None if self.devices_fetch_in_flight => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading devices…");
                });
                return;
            }
            None => {
                ui.label(
                    egui::RichText::new("No linked folders yet, so no devices to list.").weak(),
                );
                return;
            }
            Some(devices) if devices.is_empty() => {
                ui.label(egui::RichText::new("No other devices have access yet.").weak());
            }
            Some(_) => {}
        }
        if let Some(e) = &self.devices_error {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!("Could not refresh the device list: {e}"),
            );
        }

        let devices = self.devices.clone().unwrap_or_default();
        let mut remove_clicked: Option<(String, String)> = None;
        for device in &devices {
            ui.horizontal(|ui| {
                let dot = if device.online { "●" } else { "○" };
                let dot_color = if device.online {
                    egui::Color32::from_rgb(0x2e, 0x9e, 0x5b)
                } else {
                    ui.visuals().weak_text_color()
                };
                ui.colored_label(dot_color, dot);
                ui.label(&device.display_name);
                if let Some(label) = device_status_label(device.online, device.last_seen_unix) {
                    ui.label(egui::RichText::new(label).weak().small());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let removing = self.remove_in_flight.contains(&device.device_id);
                    if ui.add_enabled(!removing, egui::Button::new("Remove…")).clicked() {
                        remove_clicked =
                            Some((device.device_id.clone(), device.display_name.clone()));
                    }
                    if removing {
                        ui.spinner();
                    }
                });
            });
        }
        // No rename capability exists on this daemon/coordination plane
        // (`yadorilink device` has `register`/`list`/`remove` only); this
        // screen deliberately offers no rename control rather than faking
        // one client-side.

        if let Some((device_id, display_name)) = remove_clicked {
            let confirmed = rfd::MessageDialog::new()
                .set_title("Remove this device?")
                .set_description(format!(
                    "{display_name}\n\nThis revokes its access to every folder group at once. \
                     A currently-connected session on that device is disconnected promptly."
                ))
                .set_buttons(rfd::MessageButtons::OkCancel)
                .show()
                == rfd::MessageDialogResult::Ok;
            if confirmed {
                self.remove_in_flight.insert(device_id.clone());
                spawn_remove_device(self.sink.clone(), device_id, false);
            }
        }
    }
}

fn state_badge(state: FolderState) -> egui::RichText {
    let (text, color) = match state {
        FolderState::UpToDate => ("Up to date", egui::Color32::from_rgb(0x2e, 0x9e, 0x5b)),
        FolderState::Syncing => ("Syncing…", egui::Color32::from_rgb(0x2b, 0x6c, 0xb0)),
        FolderState::Paused => ("Paused", egui::Color32::GRAY),
        FolderState::Blocked => ("Not syncing", egui::Color32::from_rgb(0xc0, 0x39, 0x2b)),
        FolderState::Attention => ("Needs attention", egui::Color32::from_rgb(0xe2, 0x4a, 0x33)),
    };
    egui::RichText::new(text).color(color).small()
}

/// "Data protection: Protected/Protecting/At risk/Status unavailable" --
/// colored by risk, reusing `folder_detail::data_protection_label`'s exact
/// wording verbatim (never reworded here) so this badge and the per-folder
/// Details window can never disagree about what the label says, only
/// where it's shown.
fn data_protection_badge(link: &yadorilink_ipc_proto::daemonctl::LinkStatus) -> egui::RichText {
    let label = crate::folder_detail::data_protection_label(link);
    let color = match label {
        "Protected" => egui::Color32::from_rgb(0x2e, 0x9e, 0x5b),
        "Protecting" => egui::Color32::from_rgb(0x2b, 0x6c, 0xb0),
        "At risk" => egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
        _ => egui::Color32::GRAY,
    };
    egui::RichText::new(format!("Data protection: {label}")).color(color).small()
}

fn mode_badge(mode: FolderMode) -> egui::RichText {
    let text = match mode {
        FolderMode::Synced => "Synced",
        FolderMode::Selective => "Selective",
    };
    egui::RichText::new(text).weak().small()
}

/// The weak text drawn after a device's name in the device list: "last
/// seen" only for an offline device. For an online device the server's
/// timestamp is when it came online (or `0` for this machine's own row,
/// which client-core keeps online before the server has marked it), so an
/// age there would read as "last seen 3 days ago" next to a green dot.
fn device_status_label(online: bool, last_seen_unix: i64) -> Option<String> {
    (!online).then(|| last_seen_label(last_seen_unix))
}

/// "3m ago" / "2h ago" / "5d ago" / "just now" / "never" -- same relative-
/// bucket shape as `yadorilink-cli`'s `commands::status::last_gc_summary`
/// (kept as its own copy rather than shared, matching this crate's
/// established duplication precedent -- `ipc_client.rs`'s doc comment).
/// `0` renders as "never" (this file's "0 = not yet known" convention,
/// e.g. a device that has never reported presence to this account).
fn last_seen_label(last_seen_unix: i64) -> String {
    if last_seen_unix <= 0 {
        return "never seen".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let elapsed = (now - last_seen_unix).max(0);
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

#[cfg(test)]
mod tests;
