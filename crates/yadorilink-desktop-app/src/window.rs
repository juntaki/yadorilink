//! The eframe onboarding window, run as a
//! separate process (`yadorilink-status-app --window onboarding`) so its winit
//! event loop never has to coexist with the tao tray loop. The window is a
//! thin renderer over `onboarding::machine`: every button/checkbox turns into
//! a `machine::Event`, `machine::step` decides what happens, and the emitted
//! effects run off-thread via `onboarding::executor`, posting result events
//! back through a channel this window drains each frame. No flow-control logic
//! lives here (spec's "rendering SHALL contain no flow-control decisions").
//!
//! There is no display server in this environment, so this file is
//! `cargo check`/`clippy`-gated only — the same honesty discipline `main.rs`'s
//! tray wiring already documents. All testable behaviour is in the machine and
//! executor, which are headless-tested.

use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use eframe::egui;

use crate::login_item;
use crate::onboarding::executor::{self, EventSink};
use crate::onboarding::machine::{
    self, Event, LinkStage, Mode, OpStatus, Phase, State, StorageMode,
};
use crate::onboarding::probe;

/// Vermilion accent loosely matching the landing page's paper/ink/vermilion
/// language, applied over egui's platform light/dark base.
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0xE2, 0x4A, 0x33);

/// Result of trying to become the single onboarding-window instance.
enum Acquire {
    /// This process owns the guard; run the window and serve focus requests.
    Primary(SingleInstance),
    /// A live instance owned by this user is already running; focus it and exit.
    AlreadyRunning,
    /// Ownership could not be established or confirmed (e.g. a runtime-dir
    /// permission problem). Launch anyway rather than silently refuse to start,
    /// just without the single-instance guarantee.
    Unavailable,
}

/// Single-instance guard + focus channel for the onboarding window.
///
/// The endpoint is per-user: a second launch by the *same* user focuses the
/// running window, while another OS user — or an unrelated process — can never
/// take the endpoint out from under us and make every launch look like "already
/// running". On Unix it is a Unix domain socket under a private, verified,
/// user-owned directory (`$XDG_RUNTIME_DIR` if it checks out, else a per-user
/// cache directory this process creates itself — see `single_instance_dir`)
/// — never a shared world-writable temp directory another local user could
/// pre-occupy. A bind failure is classified — a live sibling (a connect
/// succeeds) vs. a stale socket (removed and retried, under an exclusive lock
/// so two racing launches can't both perform the recovery — see
/// `recover_stale_socket`) vs. an unrelated failure (launch anyway) — rather
/// than being treated uniformly as "already running".
struct SingleInstance {
    listener: SingleInstanceListener,
    #[cfg(unix)]
    path: std::path::PathBuf,
}

#[cfg(unix)]
type SingleInstanceListener = std::os::unix::net::UnixListener;
#[cfg(not(unix))]
type SingleInstanceListener = std::net::TcpListener;

/// The private, per-user directory the single-instance socket (and its
/// recovery lock file) live under. Never a shared world-writable location:
/// `std::env::temp_dir()` resolves to `/tmp` when `$TMPDIR` is unset, which
/// any other local user can pre-populate (pre-bind the socket path, or
/// pre-create a directory with permissions of their choosing) to hijack or
/// suppress this app's single-instance check. See `resolve_private_socket_dir`
/// for the actual candidate-selection-plus-verification logic, split out so
/// it is unit-testable without depending on the real process environment.
#[cfg(unix)]
fn single_instance_dir() -> Option<std::path::PathBuf> {
    resolve_private_socket_dir(
        std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from),
        std::env::var_os("XDG_CACHE_HOME").map(std::path::PathBuf::from),
        std::env::var_os("HOME").map(std::path::PathBuf::from),
    )
}

/// Picks and verifies the private directory to hold the single-instance
/// socket, given explicit candidate inputs (rather than reading the process
/// environment directly) so the selection logic is testable without
/// mutating global env vars, which would race with any other test in this
/// binary reading the same ones.
///
/// Prefers `xdg_runtime_dir` if it is absolute and verifies as a private,
/// user-owned directory (see `verify_private_dir`) — per the XDG base
/// directory spec it should already be `0700` and owned by the current
/// user, but this is verified rather than assumed, since a non-systemd
/// environment could set the var to something looser. Otherwise falls back
/// to a private per-user cache directory this process creates and locks
/// down itself: `~/Library/Caches/yadorilink/run` on macOS, or
/// `$XDG_CACHE_HOME/yadorilink/run` (default `~/.cache/yadorilink/run`) on
/// other Unixes — analogous in spirit to `$XDG_RUNTIME_DIR` (transient,
/// per-user, private) but usable even where no runtime dir is provided.
/// Returns `None` only if no per-user location can be resolved or verified
/// at all (e.g. `$HOME` unset), in which case the caller launches without
/// the single-instance guarantee rather than trusting a shared location.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(unused_variables))]
fn resolve_private_socket_dir(
    xdg_runtime_dir: Option<std::path::PathBuf>,
    xdg_cache_home: Option<std::path::PathBuf>,
    home: Option<std::path::PathBuf>,
) -> Option<std::path::PathBuf> {
    if let Some(dir) = xdg_runtime_dir.filter(|p| p.is_absolute()) {
        if verify_private_dir(&dir) {
            return Some(dir);
        }
    }
    #[cfg(target_os = "macos")]
    let base = home?.join("Library").join("Caches");
    #[cfg(not(target_os = "macos"))]
    let base = match xdg_cache_home.filter(|p| p.is_absolute()) {
        Some(dir) => dir,
        None => home?.join(".cache"),
    };
    let dir = base.join("yadorilink").join("run");
    create_private_dir(&dir).then_some(dir)
}

/// Creates `dir` (and its parents) if missing, sets its mode to `0700`, then
/// verifies ownership and mode before returning whether it is safe to trust
/// (see `verify_private_dir`). Re-verifies even a pre-existing directory:
/// if another local user managed to pre-create it, `set_permissions` will
/// simply fail (we don't own it) and the verification step below correctly
/// refuses it rather than silently using it.
#[cfg(unix)]
fn create_private_dir(dir: &std::path::Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    verify_private_dir(dir)
}

/// Whether `dir` is safe to trust as the private location for the
/// single-instance socket: it must be a real directory (not a symlink —
/// `symlink_metadata` deliberately does not follow one, so a symlink
/// planted by another local user pointing anywhere else is refused
/// outright, never silently followed), owned by the current effective
/// user, and mode exactly `0700` (no group/other permission bits at all).
#[cfg(unix)]
fn verify_private_dir(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(dir) else { return false };
    if !meta.is_dir() {
        return false;
    }
    let current_uid = unsafe { libc::getuid() };
    meta.uid() == current_uid && (meta.mode() & 0o777) == 0o700
}

#[cfg(unix)]
fn single_instance_endpoint() -> Option<std::path::PathBuf> {
    let dir = single_instance_dir()?;
    // The username is folded into the name as belt-and-suspenders in case
    // this directory is ever shared across users despite the checks above.
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "default".to_string());
    Some(dir.join(format!("yadorilink-onboarding-{user}.sock")))
}

impl SingleInstance {
    #[cfg(unix)]
    fn acquire() -> Acquire {
        use std::os::unix::net::UnixListener;
        let Some(path) = single_instance_endpoint() else { return Acquire::Unavailable };
        match UnixListener::bind(&path) {
            Ok(listener) => Acquire::Primary(SingleInstance { listener, path }),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                Self::recover_stale_socket(&path)
            }
            // A different failure (permissions, missing dir): do not block the
            // launch by pretending another instance is running.
            Err(_) => Acquire::Unavailable,
        }
    }

    /// Handles the `AddrInUse` case: someone already holds `path`, which is
    /// either a live sibling instance or a stale socket file left behind by
    /// one that exited without cleaning up (crash, kill -9, power loss).
    ///
    /// The naive version of this check — connect, and if that fails,
    /// unlink-then-rebind — has a TOCTOU race when two launches hit it at
    /// the same time: both can see the stale socket, both `remove_file` +
    /// `bind`, and the second bind silently unlinks the first's brand-new
    /// listener out from under it, leaving both processes believing they
    /// are `Primary`. To close that race, the whole
    /// probe-then-unlink-then-rebind sequence runs under an exclusive lock
    /// on a sibling `.lock` file, so only one process at a time can be
    /// performing recovery; a second racer blocks until the first finishes,
    /// then re-probes and correctly finds a live listener to connect to.
    ///
    /// The lock is an `flock` held via the lock file's open file
    /// description, not a plain "does this file exist" check, so it is
    /// automatically released by the kernel when the holding process exits
    /// for any reason, including a crash — recovery can never be
    /// permanently bricked by a process that died mid-recovery.
    #[cfg(unix)]
    fn recover_stale_socket(path: &std::path::Path) -> Acquire {
        use std::os::unix::net::{UnixListener, UnixStream};

        let lock_path = path.with_extension("lock");
        let lock_file = match std::fs::OpenOptions::new().create(true).write(true).open(&lock_path)
        {
            Ok(f) => f,
            Err(_) => return Acquire::Unavailable,
        };
        // Blocks until we hold the lock exclusively, serializing every
        // concurrent racer through the critical section below one at a time.
        if fs2::FileExt::lock_exclusive(&lock_file).is_err() {
            return Acquire::Unavailable;
        }

        // Now that we are the only process in the critical section: a
        // sibling that raced us to the lock and won may already have
        // finished recovery and be bound as the live listener.
        if UnixStream::connect(path).is_ok() {
            return Acquire::AlreadyRunning;
        }
        // Still genuinely stale (no live listener behind it): safe to
        // remove and rebind, since no other process can be doing the same
        // thing concurrently while we hold the lock.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(listener) => Acquire::Primary(SingleInstance { listener, path: path.to_path_buf() }),
            Err(_) => Acquire::Unavailable,
        }
        // `lock_file` is dropped here, releasing the flock: once bound (or
        // failed), the socket itself is what future launches probe against,
        // so nothing further needs the recovery lock held.
    }

    #[cfg(not(unix))]
    fn acquire() -> Acquire {
        // Non-Unix fallback: a loopback port is not user-scoped, so a real fix
        // needs a named pipe with a per-user security descriptor. Until then, at
        // least classify the bind failure instead of treating every error as
        // "already running": a live sibling (connect succeeds) focuses; any
        // other failure launches anyway.
        use std::net::{TcpListener, TcpStream};
        const SINGLE_INSTANCE_PORT: u16 = 47811;
        match TcpListener::bind(("127.0.0.1", SINGLE_INSTANCE_PORT)) {
            Ok(listener) => Acquire::Primary(SingleInstance { listener }),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if TcpStream::connect(("127.0.0.1", SINGLE_INSTANCE_PORT)).is_ok() {
                    Acquire::AlreadyRunning
                } else {
                    Acquire::Unavailable
                }
            }
            Err(_) => Acquire::Unavailable,
        }
    }

    /// Ask an already-running instance to bring its window to the front. Best
    /// effort: any failure (including not being able to resolve the private
    /// socket directory at all) just means no existing window to focus.
    fn signal_focus() {
        #[cfg(unix)]
        {
            if let Some(path) = single_instance_endpoint() {
                let _ = std::os::unix::net::UnixStream::connect(path);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = std::net::TcpStream::connect(("127.0.0.1", 47811u16));
        }
    }

    /// Spawn the accept loop: each incoming connection (a later launch) focuses
    /// this window via a viewport command.
    fn serve_focus(self, ctx: egui::Context) {
        std::thread::spawn(move || {
            for stream in self.listener.incoming() {
                if stream.is_err() {
                    continue;
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                ctx.request_repaint();
            }
        });
    }
}

#[cfg(unix)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        // Remove our own socket file so a later launch does not see a stale one.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Entry point for `--window onboarding`. Enforces single-instance, gathers the
/// probe, derives the start state, and runs the eframe window. Must be
/// called on the process main thread (macOS requires GUI + rfd dialogs there).
pub fn run_onboarding() -> Result<(), eframe::Error> {
    let guard = match SingleInstance::acquire() {
        Acquire::Primary(guard) => Some(guard),
        Acquire::AlreadyRunning => {
            SingleInstance::signal_focus();
            return Ok(());
        }
        // Could not confirm ownership: launch anyway, without the guard, rather
        // than refuse to start because some unrelated process holds the endpoint.
        Acquire::Unavailable => None,
    };

    let initial = gather_initial_state();

    let (tx, rx) = mpsc::channel::<Event>();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 560.0])
            .with_min_inner_size([640.0, 480.0])
            .with_title("YadoriLink Setup"),
        ..Default::default()
    };

    eframe::run_native(
        "YadoriLink Setup",
        options,
        Box::new(move |cc| {
            apply_theme(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            if let Some(guard) = guard {
                guard.serve_focus(ctx.clone());
            }
            let sink = EventSink::new(tx, Arc::new(move || ctx.request_repaint()));
            Ok(Box::new(OnboardingApp::new(initial, rx, sink)))
        }),
    )
}

/// Run the probe on a throwaway runtime (the daemon `ListLinks` call is async)
/// before the window opens, then derive the start phase.
fn gather_initial_state() -> State {
    let probe = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| rt.block_on(probe::gather()))
        .unwrap_or_default();
    machine::derive_initial(probe)
}

fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.selection.bg_fill = ACCENT;
    style.visuals.hyperlink_color = ACCENT;
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    ctx.set_style(style);
}

struct OnboardingApp {
    state: State,
    rx: Receiver<Event>,
    sink: EventSink,
    /// Reflects `login_item::is_enabled`; toggled on the Done step.
    login_at_startup: bool,
    /// Whether add-folder mode's one-shot group fetch has been kicked off.
    groups_fetch_started: bool,
}

impl OnboardingApp {
    fn new(state: State, rx: Receiver<Event>, sink: EventSink) -> Self {
        OnboardingApp {
            state,
            rx,
            sink,
            login_at_startup: login_item::is_enabled(),
            groups_fetch_started: false,
        }
    }

    /// Feed one event through the machine and run any effects it emits.
    fn apply(&mut self, event: Event) {
        let (next, effects) = machine::step(self.state.clone(), event);
        self.state = next;
        for effect in effects {
            executor::spawn(effect, self.sink.clone());
        }
    }
}

impl eframe::App for OnboardingApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain any results the executor posted since the last frame.
        while let Ok(event) = self.rx.try_recv() {
            self.apply(event);
        }

        // Add-folder mode needs the group list; fire the request once.
        if self.state.mode == Mode::AddFolder
            && self.state.phase == Phase::LinkFolder
            && self.state.link_stage == LinkStage::ChooseGroup
            && !self.groups_fetch_started
        {
            self.groups_fetch_started = true;
            self.apply(Event::GroupsRequested);
        }

        let mut pending: Vec<Event> = Vec::new();

        egui::SidePanel::left("wizard_steps")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| self.render_sidebar(ui));

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_content(ctx, ui, &mut pending);
        });

        for event in pending {
            self.apply(event);
        }
    }
}

impl OnboardingApp {
    fn render_sidebar(&self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        ui.heading("YadoriLink");
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Setup").color(ACCENT).strong());
        ui.add_space(20.0);

        let steps = [
            (Phase::SignIn, "Sign in"),
            (Phase::DeviceRegister, "Register device"),
            (Phase::ShareChoose, "Choose a share"),
            (Phase::LinkFolder, "Link a folder"),
        ];
        let current = self.state.phase.ordinal();
        for (phase, label) in steps {
            let ord = phase.ordinal();
            let (marker, color) = if self.state.phase == Phase::Done || ord < current {
                ("✓", egui::Color32::from_rgb(0x2e, 0x9e, 0x5b))
            } else if ord == current {
                ("●", ACCENT)
            } else {
                ("○", ui.visuals().weak_text_color())
            };
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(marker).color(color));
                let mut text = egui::RichText::new(label);
                if ord == current {
                    text = text.strong();
                }
                ui.label(text);
            });
            ui.add_space(6.0);
        }

        if self.state.mode == Mode::AddFolder {
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("Adding another folder")
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }
    }

    fn render_content(&mut self, ctx: &egui::Context, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.add_space(16.0);
        match self.state.phase {
            Phase::Welcome => self.render_welcome(ui, pending),
            Phase::SignIn => self.render_sign_in(ui, pending),
            Phase::DeviceRegister => self.render_device_register(ui, pending),
            Phase::ShareChoose => self.render_share_choose(ui, pending),
            Phase::LinkFolder => self.render_link_folder(ui, pending),
            Phase::Done => self.render_done(ctx, ui),
        }
    }

    fn render_welcome(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.heading("Welcome to YadoriLink");
        ui.add_space(8.0);
        ui.label(
            "Sync a folder end-to-end encrypted across your devices — no CLI required. \
             This wizard signs you in, registers this device, sets up a share, and links \
             your first folder.",
        );
        ui.add_space(20.0);
        if ui.button("Get started").clicked() {
            pending.push(Event::Start);
        }
    }

    fn render_sign_in(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.heading("Sign in with Google");
        ui.add_space(8.0);
        ui.label(
            "Your browser opens Google's consent screen. YadoriLink receives the result on a \
             local one-time callback and stores the session in your OS keychain — no password \
             is ever shown or stored here.",
        );
        ui.add_space(16.0);
        match &self.state.status {
            OpStatus::Working => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Waiting for you to finish signing in in the browser…");
                });
            }
            OpStatus::Failed(msg) => {
                self.error_card(ui, msg, pending, /* allow_back */ true);
            }
            OpStatus::Idle => {
                if ui.button("Sign in with Google").clicked() {
                    pending.push(Event::SignInRequested);
                }
            }
        }
    }

    fn render_device_register(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.heading("Register this device");
        ui.add_space(8.0);
        if let Some(account) = &self.state.account {
            ui.label(format!("Signed in as {account}."));
            ui.add_space(8.0);
        }
        ui.label("Give this device a name your other devices will recognize.");
        ui.add_space(12.0);

        let working = self.state.status == OpStatus::Working;
        let mut name = self.state.device_name.clone();
        ui.horizontal(|ui| {
            ui.label("Device name:");
            let response = ui.add_enabled(!working, egui::TextEdit::singleline(&mut name));
            if response.changed() {
                pending.push(Event::DeviceNameChanged(name.clone()));
            }
        });
        ui.add_space(16.0);

        match &self.state.status {
            OpStatus::Working => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Registering…");
                });
            }
            OpStatus::Failed(msg) => self.error_card(ui, msg, pending, true),
            OpStatus::Idle => {
                let enabled = !name.trim().is_empty();
                if ui.add_enabled(enabled, egui::Button::new("Register device")).clicked() {
                    pending.push(Event::DeviceRegisterRequested);
                }
                if ui.button("Back").clicked() {
                    pending.push(Event::Back);
                }
            }
        }
    }

    fn render_share_choose(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.heading("Set up a share");
        ui.add_space(8.0);
        ui.label("Create a folder group to sync across your devices.");
        ui.add_space(12.0);

        let working = self.state.status == OpStatus::Working;
        ui.add_enabled_ui(!working, |ui| {
            let mut share_name = self.state.share_name.clone();
            ui.horizontal(|ui| {
                ui.label("Group name:");
                if ui.text_edit_singleline(&mut share_name).changed() {
                    pending.push(Event::ShareNameChanged(share_name.clone()));
                }
            });
        });
        ui.add_space(16.0);

        match &self.state.status {
            OpStatus::Working => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Contacting the coordination service…");
                });
            }
            OpStatus::Failed(msg) => self.error_card(ui, msg, pending, true),
            OpStatus::Idle => {
                let ready = !self.state.share_name.trim().is_empty();
                if ui.add_enabled(ready, egui::Button::new("Create group")).clicked() {
                    pending.push(Event::ShareSubmitRequested);
                }
                if ui.button("Back").clicked() {
                    pending.push(Event::Back);
                }
            }
        }
    }

    fn render_link_folder(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.heading("Link a folder");
        ui.add_space(8.0);
        match self.state.link_stage {
            LinkStage::ChooseGroup => self.render_choose_group(ui, pending),
            LinkStage::ChooseFolder => self.render_choose_folder(ui, pending),
            LinkStage::Previewing => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Checking the folder…");
                });
            }
            LinkStage::Review => self.render_link_review(ui, pending),
        }
    }

    fn render_choose_group(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.label("Which folder group should this folder sync into?");
        ui.add_space(12.0);
        match &self.state.status {
            OpStatus::Working => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading your groups…");
                });
            }
            OpStatus::Failed(msg) => self.error_card(ui, msg, pending, false),
            OpStatus::Idle => {
                if self.state.available_groups.is_empty() {
                    ui.label("No folder groups found for this account.");
                } else {
                    for group in &self.state.available_groups {
                        if ui.button(&group.name).clicked() {
                            pending.push(Event::GroupSelected(group.group_id.clone()));
                        }
                    }
                }
            }
        }
    }

    fn render_choose_folder(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        ui.label("Pick the folder on this device you want to keep in sync.");
        ui.add_space(12.0);
        if ui.button("Choose folder…").clicked() {
            if let Some(path) = pick_folder() {
                pending.push(Event::FolderPicked(path));
            }
        }
        if self.state.mode == Mode::AddFolder && ui.button("Back").clicked() {
            pending.push(Event::Back);
        }
    }

    fn render_link_review(&self, ui: &mut egui::Ui, pending: &mut Vec<Event>) {
        if let Some(path) = &self.state.folder_path {
            ui.label(egui::RichText::new(path).monospace());
            ui.add_space(8.0);
        }
        let Some(preflight) = &self.state.preflight else {
            return;
        };

        // Dry-run preview: the preflight already ran without registering
        // anything, so its factual summary IS the dry-run result.
        ui.label(egui::RichText::new("Preview (nothing is linked yet):").strong());
        for line in &preflight.summary {
            ui.label(format!("• {line}"));
        }
        ui.add_space(8.0);

        if preflight.is_risky {
            ui.label(
                egui::RichText::new("Please review and acknowledge each warning before linking:")
                    .color(ACCENT)
                    .strong(),
            );
            ui.add_space(6.0);
            for (index, warning) in preflight.warnings.iter().enumerate() {
                let mut acked = self.state.acks.get(index).copied().unwrap_or(false);
                if ui.checkbox(&mut acked, warning).changed() {
                    pending.push(Event::WarningAckToggled(index));
                }
            }
            ui.add_space(12.0);
        }

        // Storage mode: how much of the folder this device keeps on disk.
        ui.label(egui::RichText::new("On this device:").strong());
        let mut mode = self.state.storage_mode;
        if ui.radio_value(&mut mode, StorageMode::Eager, "Store everything").clicked() {
            pending.push(Event::StorageModeChosen(StorageMode::Eager));
        }
        if ui.radio_value(&mut mode, StorageMode::OnDemand, "Store only needed files").clicked() {
            pending.push(Event::StorageModeChosen(StorageMode::OnDemand));
        }
        ui.add_space(12.0);

        match &self.state.status {
            OpStatus::Working => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Linking…");
                });
            }
            OpStatus::Failed(msg) => self.error_card(ui, msg, pending, false),
            OpStatus::Idle => {
                let can_confirm = self.state.can_confirm_link();
                if ui.add_enabled(can_confirm, egui::Button::new("Confirm and link")).clicked() {
                    pending.push(Event::LinkConfirmRequested);
                }
                if ui.button("Choose a different folder…").clicked() {
                    if let Some(path) = pick_folder() {
                        pending.push(Event::FolderPicked(path));
                    }
                }
            }
        }
    }

    fn render_done(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.heading("You're all set");
        ui.add_space(8.0);
        if let Some(path) = &self.state.linked_path {
            ui.label(format!("YadoriLink is now syncing {path}."));
        } else {
            ui.label("YadoriLink is now syncing your folder.");
        }
        ui.add_space(16.0);

        // Inline launch-at-login toggle (/ open question resolved to inline,
        // default off), wired to the same login_item mechanism the tray uses.
        let mut enabled = self.login_at_startup;
        if ui.checkbox(&mut enabled, "Start YadoriLink at login (this user)").changed() {
            let result = if enabled { login_item::enable() } else { login_item::disable() };
            match result {
                Ok(()) => self.login_at_startup = enabled,
                Err(e) => tracing::warn!(error = %e, "launch-at-login toggle failed"),
            }
        }
        ui.add_space(20.0);
        if ui.button("Done").clicked() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    /// A recoverable-failure card: the human-readable cause plus retry (and
    /// optionally back), matching the machine's in-place recovery (spec "Step
    /// failure is recoverable in place").
    fn error_card(
        &self,
        ui: &mut egui::Ui,
        message: &str,
        pending: &mut Vec<Event>,
        allow_back: bool,
    ) {
        ui.label(
            egui::RichText::new(format!("Something went wrong: {message}"))
                .color(egui::Color32::from_rgb(0xc0, 0x39, 0x2b)),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Try again").clicked() {
                pending.push(Event::Retry);
            }
            if allow_back && ui.button("Back").clicked() {
                pending.push(Event::Back);
            }
        });
    }
}

/// Cross-platform native folder picker (/ ), delegating to the
/// single `actions::pick_folder` rfd implementation. Runs on the eframe main
/// thread, which macOS requires for native dialogs.
fn pick_folder() -> Option<String> {
    crate::actions::pick_folder().map(|path| path.to_string_lossy().to_string())
}

#[cfg(all(test, unix))]
mod single_instance_tests {
    //! Covers the two Unix-only single-instance hardening fixes that are
    //! unit-testable without a real GUI: the private-directory
    //! selection/verification (`resolve_private_socket_dir`,
    //! `verify_private_dir`, `create_private_dir`) and the race-free
    //! stale-socket recovery (`SingleInstance::recover_stale_socket`), the
    //! latter exercised with real threads and real Unix sockets in a scratch
    //! directory rather than mocked.
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir_with_mode(mode: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn verify_private_dir_accepts_a_freshly_made_0700_dir_we_own() {
        let dir = dir_with_mode(0o700);
        assert!(verify_private_dir(dir.path()));
    }

    #[test]
    fn verify_private_dir_refuses_a_too_permissive_mode() {
        // Owned by us, but readable/writable/executable by group and other:
        // never trusted, even though we do own it.
        let dir = dir_with_mode(0o755);
        assert!(!verify_private_dir(dir.path()));
    }

    #[test]
    fn verify_private_dir_refuses_a_symlink_even_to_a_0700_target() {
        // A symlink at the candidate path, rather than a real directory --
        // `symlink_metadata` must not follow it, so planting a symlink to
        // somewhere else (e.g. by another local user, or pointing at a
        // shared location) can never be trusted just because the eventual
        // target happens to look private.
        let target = dir_with_mode(0o700);
        let link_parent = tempfile::tempdir().unwrap();
        let link_path = link_parent.path().join("runtime-link");
        std::os::unix::fs::symlink(target.path(), &link_path).unwrap();
        assert!(!verify_private_dir(&link_path));
    }

    #[test]
    fn verify_private_dir_refuses_a_missing_path() {
        let missing = tempfile::tempdir().unwrap().path().join("does-not-exist");
        assert!(!verify_private_dir(&missing));
    }

    #[test]
    fn create_private_dir_heals_a_too_permissive_mode_on_a_dir_we_own() {
        let dir = dir_with_mode(0o755);
        assert!(create_private_dir(dir.path()));
        let meta = std::fs::symlink_metadata(dir.path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn create_private_dir_creates_missing_parents() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b").join("run");
        assert!(create_private_dir(&nested));
        assert!(verify_private_dir(&nested));
    }

    #[test]
    fn resolve_prefers_a_verified_xdg_runtime_dir() {
        let runtime = dir_with_mode(0o700);
        let resolved = resolve_private_socket_dir(Some(runtime.path().to_path_buf()), None, None);
        assert_eq!(resolved.as_deref(), Some(runtime.path()));
    }

    #[test]
    fn resolve_refuses_a_world_writable_xdg_runtime_dir_and_falls_back_to_a_private_dir() {
        // A world-writable runtime dir is exactly the "another local user
        // pre-created it" scenario the gate must catch -- it must never be
        // trusted, even though `$XDG_RUNTIME_DIR` was set.
        let runtime = dir_with_mode(0o777);
        let home = tempfile::tempdir().unwrap();
        let resolved = resolve_private_socket_dir(
            Some(runtime.path().to_path_buf()),
            None,
            Some(home.path().to_path_buf()),
        )
        .expect("a private fallback under home must still be resolved");
        assert_ne!(resolved, runtime.path());
        assert!(resolved.starts_with(home.path()));
        assert!(verify_private_dir(&resolved));
    }

    #[test]
    fn resolve_returns_none_without_either_a_runtime_dir_or_home() {
        assert_eq!(resolve_private_socket_dir(None, None, None), None);
    }

    /// The actual regression test for the TOCTOU fix: two threads race to
    /// recover the same stale socket path (simulating two simultaneous
    /// launches after a crash left the socket file behind with no live
    /// listener). Without the exclusive lock, both could conclude the
    /// socket is stale, both unlink+rebind, and both end up `Primary`. With
    /// it, exactly one must win.
    #[test]
    fn concurrent_stale_socket_recovery_yields_exactly_one_primary() {
        let dir = dir_with_mode(0o700);
        let path = dir.path().join("race.sock");

        // Simulate a crashed prior instance: bind, then drop without
        // removing the file, leaving a stale socket with no live listener.
        {
            let _stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (path_a, path_b) = (path.clone(), path.clone());
        let (barrier_a, barrier_b) = (barrier.clone(), barrier.clone());

        let handle_a = std::thread::spawn(move || {
            barrier_a.wait();
            SingleInstance::recover_stale_socket(&path_a)
        });
        let handle_b = std::thread::spawn(move || {
            barrier_b.wait();
            SingleInstance::recover_stale_socket(&path_b)
        });

        let result_a = handle_a.join().unwrap();
        let result_b = handle_b.join().unwrap();

        let primary_count =
            [&result_a, &result_b].into_iter().filter(|r| matches!(r, Acquire::Primary(_))).count();
        let already_running_count = [&result_a, &result_b]
            .into_iter()
            .filter(|r| matches!(r, Acquire::AlreadyRunning))
            .count();
        assert_eq!(primary_count, 1, "exactly one racer must become Primary, never zero or both");
        assert_eq!(already_running_count, 1, "the loser must see the winner as already running");
    }
}
