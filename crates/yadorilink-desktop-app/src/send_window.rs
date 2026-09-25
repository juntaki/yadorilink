//! Entry point for `--window send` -- Track Send's desktop UI: send a file
//! or folder to another device on this account (one-shot, not linked/
//! synced -- see `yadorilink-cli`'s own `commands::send` doc comment), and
//! accept/receive whatever other devices have sent here.
//!
//! Same "own `mpsc` channel + `EventSink`, background thread does the
//! fetch/action" shape as every other window in this crate. Two
//! independent poll loops, same reasoning as `home_window.rs`: `StatusResponse`
//! (for the currently linked folders' `group_id`s) and Inbox are both cheap
//! daemon-control-socket calls polled every 2s; the device picker (who can
//! I send to) is a coordination-plane fetch, refetched only when the set of
//! linked groups changes, exactly like `home_window.rs`'s own device/peer-
//! count fetch -- reusing the identical `crate::devices::device_summaries`
//! this crate's Home/Devices section already uses, since
//! there is still no single "every device on my account" list (see that
//! function's own doc comment) -- this window inherits the same real
//! constraint, not a new one.
//!
//! Test coverage: the pure logic here (`format_bytes`/`sender_label`) is
//! unit-tested; the `eframe`/`egui` rendering is covered by compilation,
//! not by automated UI tests.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use yadorilink_ipc_proto::daemonctl::{
    InboxTransfer, ReceiveTransferResponse, SendFileResponse, StatusResponse,
};
use yadorilink_product_view::DeviceSummary;

use crate::onboarding::executor::EventSink;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Event {
    // Boxed for the same `clippy::large_enum_variant` reason every other
    // window's identical `StatusFetched` variant is.
    StatusFetched(Result<Box<StatusResponse>, String>),
    DevicesFetched(Result<Vec<DeviceSummary>, String>),
    InboxFetched(Result<Vec<InboxTransfer>, String>),
    SendDone(Result<SendFileResponse, String>),
    /// `transfer_id`, then the receive outcome.
    ReceiveDone(String, Result<ReceiveTransferResponse, String>),
}

/// Entry point for `--window send`. Must run on the process main thread
/// (same `eframe`/winit constraint every other window in this crate
/// already follows).
pub fn run_send() -> Result<(), eframe::Error> {
    let (tx, rx) = mpsc::channel::<Event>();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 560.0])
            .with_min_inner_size([420.0, 360.0])
            .with_title("YadoriLink — Send & Receive"),
        ..Default::default()
    };
    eframe::run_native(
        "YadoriLink Send & Receive",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(SendApp::new(rx, sink)))
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

/// Same shared thread+runtime scaffolding every other window's `spawn_task`
/// is -- kept as its own copy per this crate's established precedent (see
/// `home_window.rs`'s own copy's doc comment for why).
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

fn spawn_devices_fetch(
    sink: EventSink<Event>,
    links: Vec<yadorilink_ipc_proto::daemonctl::LinkStatus>,
) {
    spawn_task(
        sink,
        async move { crate::devices::device_summaries(&links).await.map_err(|e| e.to_string()) },
        Event::DevicesFetched,
    );
}

fn spawn_inbox_fetch(sink: EventSink<Event>) {
    spawn_task(
        sink,
        async move { crate::actions::list_inbox().await.map_err(|e| e.to_string()) },
        Event::InboxFetched,
    );
}

fn spawn_send(sink: EventSink<Event>, source_path: String, target_device: String) {
    spawn_task(
        sink,
        async move {
            crate::actions::send_file(source_path, target_device).await.map_err(|e| e.to_string())
        },
        Event::SendDone,
    );
}

fn spawn_receive(sink: EventSink<Event>, transfer_id: String, to: Option<String>) {
    let for_transfer = transfer_id.clone();
    spawn_task(
        sink,
        async move {
            crate::actions::receive_transfer(transfer_id, to).await.map_err(|e| e.to_string())
        },
        move |result| Event::ReceiveDone(for_transfer, result),
    );
}

struct SendApp {
    rx: Receiver<Event>,
    sink: EventSink<Event>,

    last_poll: Option<Instant>,
    status_fetch_in_flight: bool,
    inbox_fetch_in_flight: bool,
    devices_fetch_in_flight: bool,
    /// The distinct `group_id`s of the currently linked folders, last time
    /// `devices` was fetched -- a fresh fetch is only kicked off when this
    /// set actually changes (a folder linked/unlinked), same rationale as
    /// `home_window.rs`'s identical guard.
    known_group_ids: std::collections::BTreeSet<String>,

    devices: Vec<DeviceSummary>,
    devices_error: Option<String>,
    inbox: Option<Vec<InboxTransfer>>,
    inbox_error: Option<String>,

    // ---- Send form state ----
    source_path: String,
    target_device: Option<String>, // device_id
    send_in_flight: bool,
    last_send_message: Option<Result<String, String>>,

    // ---- Receive state ----
    receive_in_flight: std::collections::BTreeSet<String>,
    last_receive_message: Option<Result<String, String>>,
}

impl SendApp {
    fn new(rx: Receiver<Event>, sink: EventSink<Event>) -> Self {
        SendApp {
            rx,
            sink,
            last_poll: None,
            status_fetch_in_flight: false,
            inbox_fetch_in_flight: false,
            devices_fetch_in_flight: false,
            known_group_ids: std::collections::BTreeSet::new(),
            devices: Vec::new(),
            devices_error: None,
            inbox: None,
            inbox_error: None,
            source_path: String::new(),
            target_device: None,
            send_in_flight: false,
            last_send_message: None,
            receive_in_flight: std::collections::BTreeSet::new(),
            last_receive_message: None,
        }
    }

    /// Own device id (from local device identity, not the network) -- the
    /// device picker never lists the device the user is currently on,
    /// since sending to yourself is meaningless.
    fn own_device_id(&self) -> Option<String> {
        yadorilink_client_core::ops::shares::own_device_id()
    }

    fn other_devices(&self) -> Vec<&DeviceSummary> {
        let own = self.own_device_id();
        self.devices.iter().filter(|d| Some(d.device_id.as_str()) != own.as_deref()).collect()
    }

    fn device_label(&self, device_id: &str) -> String {
        self.devices
            .iter()
            .find(|d| d.device_id == device_id)
            .map(|d| {
                if d.display_name.is_empty() {
                    device_id.to_string()
                } else {
                    format!("{} ({device_id})", d.display_name)
                }
            })
            .unwrap_or_else(|| device_id.to_string())
    }
}

impl eframe::App for SendApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::StatusFetched(Ok(status)) => {
                    self.status_fetch_in_flight = false;
                    let group_ids: std::collections::BTreeSet<String> = status
                        .links
                        .iter()
                        .map(|l| l.group_id.clone())
                        .filter(|g| !g.is_empty())
                        .collect();
                    if group_ids != self.known_group_ids && !self.devices_fetch_in_flight {
                        self.known_group_ids = group_ids;
                        self.devices_fetch_in_flight = true;
                        spawn_devices_fetch(self.sink.clone(), status.links.clone());
                    }
                }
                Event::StatusFetched(Err(_)) => {
                    self.status_fetch_in_flight = false;
                }
                Event::DevicesFetched(Ok(devices)) => {
                    self.devices = devices;
                    self.devices_error = None;
                    self.devices_fetch_in_flight = false;
                    // Drop a picked target that no longer exists (e.g. a
                    // device removed while this window was open).
                    if let Some(target) = &self.target_device {
                        if !self.devices.iter().any(|d| &d.device_id == target) {
                            self.target_device = None;
                        }
                    }
                }
                Event::DevicesFetched(Err(e)) => {
                    self.devices_error = Some(e);
                    self.devices_fetch_in_flight = false;
                }
                Event::InboxFetched(Ok(transfers)) => {
                    self.inbox = Some(transfers);
                    self.inbox_error = None;
                    self.inbox_fetch_in_flight = false;
                }
                Event::InboxFetched(Err(e)) => {
                    self.inbox_error = Some(e);
                    self.inbox_fetch_in_flight = false;
                }
                Event::SendDone(result) => {
                    self.send_in_flight = false;
                    self.last_send_message = Some(result.map(|r| {
                        format!(
                            "Offered transfer {} — {} file(s), {}.",
                            r.transfer_id,
                            r.files_offered.len(),
                            format_bytes(r.total_size)
                        )
                    }));
                }
                Event::ReceiveDone(transfer_id, result) => {
                    self.receive_in_flight.remove(&transfer_id);
                    let ok = result.is_ok();
                    self.last_receive_message = Some(result.map(|r| {
                        format!(
                            "Received into {} — {}.",
                            r.destination_dir,
                            format_bytes(r.bytes_received)
                        )
                    }));
                    if ok {
                        self.inbox_fetch_in_flight = true;
                        spawn_inbox_fetch(self.sink.clone());
                    }
                }
            }
        }

        let due = self.last_poll.is_none_or(|t| t.elapsed() >= POLL_INTERVAL);
        if due {
            self.last_poll = Some(Instant::now());
            if !self.status_fetch_in_flight {
                self.status_fetch_in_flight = true;
                spawn_status_fetch(self.sink.clone());
            }
            if !self.inbox_fetch_in_flight {
                self.inbox_fetch_in_flight = true;
                spawn_inbox_fetch(self.sink.clone());
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

impl SendApp {
    fn render_body(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Send & Receive");
        ui.label(
            egui::RichText::new(
                "A one-shot transfer to another device on your account — separate from synced folders.",
            )
            .weak()
            .small(),
        );
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(10.0);

        self.render_send_panel(ui);
        ui.add_space(14.0);
        ui.separator();
        ui.add_space(10.0);
        self.render_inbox_panel(ui);
    }

    fn render_send_panel(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Send").strong());
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.source_path).hint_text("File or folder path"),
            );
        });
        ui.horizontal(|ui| {
            if ui.button("Choose file…").clicked() {
                if let Some(path) = crate::actions::pick_any_file() {
                    self.source_path = path.to_string_lossy().to_string();
                }
            }
            if ui.button("Choose folder…").clicked() {
                if let Some(path) = crate::actions::pick_folder_titled("Choose a folder to send") {
                    self.source_path = path.to_string_lossy().to_string();
                }
            }
        });
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label("To:");
            let others: Vec<DeviceSummary> = self.other_devices().into_iter().cloned().collect();
            let selected_label = self
                .target_device
                .as_deref()
                .map(|id| self.device_label(id))
                .unwrap_or_else(|| "Choose a device…".to_string());
            egui::ComboBox::from_id_salt("send_target_device")
                .selected_text(selected_label)
                .show_ui(ui, |ui| {
                    for device in &others {
                        let label = if device.display_name.is_empty() {
                            device.device_id.clone()
                        } else {
                            format!(
                                "{} ({}){}",
                                device.display_name,
                                device.device_id,
                                if device.online { "" } else { " — offline" }
                            )
                        };
                        ui.selectable_value(
                            &mut self.target_device,
                            Some(device.device_id.clone()),
                            label,
                        );
                    }
                });
            if self.devices.is_empty() && self.devices_error.is_none() {
                ui.label(egui::RichText::new("(loading devices…)").weak().small());
            }
        });
        if let Some(e) = &self.devices_error {
            ui.colored_label(
                egui::Color32::from_rgb(0xc0, 0x39, 0x2b),
                format!("Could not list devices: {e}"),
            );
        } else if self.devices.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No other devices found yet — devices become visible here once they share a linked folder with you.",
                )
                .weak()
                .small(),
            );
        }

        ui.add_space(6.0);
        let can_send = !self.send_in_flight
            && !self.source_path.trim().is_empty()
            && self.target_device.is_some();
        if ui.add_enabled(can_send, egui::Button::new("Send")).clicked() {
            if let Some(target) = self.target_device.clone() {
                self.send_in_flight = true;
                self.last_send_message = None;
                spawn_send(self.sink.clone(), self.source_path.trim().to_string(), target);
            }
        }
        if self.send_in_flight {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Sending…");
            });
        }
        if let Some(msg) = &self.last_send_message {
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

    fn render_inbox_panel(&mut self, ui: &mut egui::Ui) {
        ui.label(egui::RichText::new("Inbox").strong());
        ui.add_space(4.0);

        if let Some(msg) = &self.last_receive_message {
            match msg {
                Ok(text) => {
                    ui.colored_label(egui::Color32::from_rgb(0x2e, 0x9e, 0x5b), text);
                }
                Err(text) => {
                    ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), text);
                }
            }
            ui.add_space(6.0);
        }

        if let Some(e) = &self.inbox_error {
            ui.colored_label(egui::Color32::from_rgb(0xc0, 0x39, 0x2b), e);
            return;
        }
        match &self.inbox {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading…");
                });
            }
            Some(transfers) if transfers.is_empty() => {
                ui.label("Inbox is empty.");
            }
            Some(transfers) => {
                let transfers = transfers.clone();
                for transfer in &transfers {
                    ui.add_space(6.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(self.device_label(&transfer.sender_device_id))
                                    .strong(),
                            );
                            ui.label(egui::RichText::new(format!("[{}]", transfer.status)).weak());
                        });
                        ui.label(format!(
                            "{} file(s), {}",
                            transfer.files.len(),
                            format_bytes(transfer.total_size)
                        ));
                        for file in &transfer.files {
                            ui.label(
                                egui::RichText::new(format!(
                                    "  {}  ({})",
                                    file.relative_path,
                                    format_bytes(file.size)
                                ))
                                .weak()
                                .small(),
                            );
                        }
                        let busy = self.receive_in_flight.contains(&transfer.transfer_id);
                        ui.horizontal(|ui| {
                            if ui.add_enabled(!busy, egui::Button::new("Receive")).clicked() {
                                self.receive_in_flight.insert(transfer.transfer_id.clone());
                                self.last_receive_message = None;
                                spawn_receive(
                                    self.sink.clone(),
                                    transfer.transfer_id.clone(),
                                    None,
                                );
                            }
                            if ui.add_enabled(!busy, egui::Button::new("Receive to…")).clicked() {
                                if let Some(dir) = crate::actions::pick_folder_titled(
                                    "Choose where to save this transfer",
                                ) {
                                    self.receive_in_flight.insert(transfer.transfer_id.clone());
                                    self.last_receive_message = None;
                                    spawn_receive(
                                        self.sink.clone(),
                                        transfer.transfer_id.clone(),
                                        Some(dir.to_string_lossy().to_string()),
                                    );
                                }
                            }
                            if busy {
                                ui.spinner();
                            }
                        });
                    });
                }
            }
        }
    }
}

/// Byte-count formatter -- same binary-unit, one-decimal-place shape as
/// `folder_detail.rs`'s own private copy (this crate's established
/// duplication precedent rather than a shared helper -- see
/// `ipc_client.rs`'s doc comment).
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

#[cfg(test)]
mod tests;
