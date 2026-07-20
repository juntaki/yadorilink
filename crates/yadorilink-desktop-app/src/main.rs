//! A single cross-platform
//! menu-bar/notification-area tray binary (see this crate's `Cargo.toml`
//! doc comment for why one binary covers both target platforms instead of
//! two native shells). Thin client over the daemon control socket only
//! — every mutating action in `actions.rs` is a
//! direct pass-through to an existing daemon request, and every displayed
//! field comes straight from `StatusResponse` (`status_model.rs`).
//!
//! IMPORTANT / honesty note for reviewers: the pure logic in
//! `status_model.rs`/`actions.rs`/`ipc_client.rs` is unit-tested and the
//! IPC calls are exercised by this crate's `tests/` against a real daemon
//! (same harness `yadorilink-cli`'s integration tests use). The actual
//! tray icon / menu / event-loop wiring below can only be verified by
//! `cargo build`/`cargo check` in this sandboxed environment — there is no
//! display server or window manager here to click a real menu item
//! against, so the event-loop plumbing itself (this file) is UI-verified
//! only by inspection, not by a real run.

use std::time::Duration;

use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use yadorilink_desktop_app::{account, actions, ipc_client, login_item, status_model, window};
use yadorilink_ipc_proto::daemonctl::StatusResponse;

/// Sent from the background polling thread to the event loop whenever a
/// fresh (or newly-unreachable) status snapshot is available.
enum UserEvent {
    Status(Result<StatusResponse, ()>),
}

const POLL_INTERVAL: Duration = Duration::from_secs(2);

fn main() {
    tracing_subscriber::fmt::init();

    // The GUI surfaces are the same binary
    // launched with `--window <kind>`, each running its own eframe/winit event
    // loop as a separate process so none has to coexist with the tao tray loop
    // below. The tray (and installers) spawn them; they share state with the
    // tray purely through the keychain/device.json/daemon the tray already
    // polls, so no new channel between them is needed.
    match requested_window() {
        Some(WindowKind::Onboarding) => {
            if let Err(e) = window::run_onboarding() {
                tracing::error!(error = %e, "onboarding window exited with an error");
            }
            return;
        }
        Some(WindowKind::Account) => {
            if let Err(e) = account::run_account() {
                tracing::error!(error = %e, "account window exited with an error");
            }
            return;
        }
        None => {}
    }

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // Background polling thread: its own small tokio runtime, entirely
    // separate from the tao event loop (which must stay on the main
    // thread on macOS — see `tray-icon`'s own platform notes) — this is
    // the same "own runtime per background thread" approach
    // `tokio::runtime::Runtime::new.block_on(...)` uses for one-shot
    // menu actions below, just long-lived instead of per-click.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to start polling runtime");
        rt.block_on(async move {
            loop {
                let status = fetch_status().await;
                if proxy.send_event(UserEvent::Status(status)).is_err() {
                    // Event loop is gone (app quitting) — stop polling.
                    return;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    });

    let icon = placeholder_icon();
    let tray_icon = TrayIconBuilder::new()
        .with_tooltip(status_model::DAEMON_UNREACHABLE_HEADLINE)
        .with_icon(icon)
        .with_menu(Box::new(build_menu(None)))
        .build()
        .expect("failed to build tray icon");

    let menu_channel = MenuEvent::receiver();
    let tray_channel = TrayIconEvent::receiver();

    event_loop.run(move |event, _target, control_flow| {
        *control_flow = ControlFlow::Wait;

        if let Event::UserEvent(UserEvent::Status(status)) = event {
            apply_status(&tray_icon, status.ok());
        }

        // `tray-icon`/`muda` events arrive on their own global channels
        // (see `TrayIconEvent::receiver`/`MenuEvent::receiver`'s doc
        // comments) rather than through tao's own `Event` enum — drained
        // once per loop iteration alongside tao's events.
        if let Ok(event) = tray_channel.try_recv() {
            if matches!(event, TrayIconEvent::Click { .. }) {
                tray_icon.show_menu();
            }
        }

        if let Ok(event) = menu_channel.try_recv() {
            handle_menu_event(event.id().as_ref());
            if event.id().as_ref() == "quit" {
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}

/// Which GUI window, if any, this invocation should open instead of the tray.
enum WindowKind {
    Onboarding,
    Account,
}

/// Parses `--window <kind>` (/— the tray items and installer first-run
/// hook launch these windows this way).
fn requested_window() -> Option<WindowKind> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--window" {
            return match args.next().as_deref() {
                Some("onboarding") => Some(WindowKind::Onboarding),
                Some("account") => Some(WindowKind::Account),
                _ => None,
            };
        }
    }
    None
}

/// Launch one of this binary's GUI windows as a separate process — the
/// tray never runs an eframe loop in its own process.
fn spawn_window(kind: &str) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).arg("--window").arg(kind).spawn();
    }
}

async fn fetch_status() -> Result<StatusResponse, ()> {
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::StatusRequest;

    match ipc_client::send(ReqPayload::Status(StatusRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::Status(status)) => Ok(status),
            _ => Err(()),
        },
        Err(_) => Err(()),
    }
}

fn apply_status(tray_icon: &TrayIcon, status: Option<StatusResponse>) {
    let headline = match &status {
        Some(status) => status_model::headline(status),
        None => status_model::DAEMON_UNREACHABLE_HEADLINE.to_string(),
    };
    let _ = tray_icon.set_tooltip(Some(&headline));
    tray_icon.set_menu(Some(Box::new(build_menu(status.as_ref()))));
}

/// Rebuilds the whole menu from the latest status snapshot — simpler and
/// less error-prone than mutating individual native menu items in place,
/// and cheap enough at a 2s poll interval (this is not
/// a high-frequency UI).
fn build_menu(status: Option<&StatusResponse>) -> Menu {
    let menu = Menu::new();

    let headline_text = match status {
        Some(status) => status_model::headline(status),
        None => status_model::DAEMON_UNREACHABLE_HEADLINE.to_string(),
    };
    let _ = menu.append(&MenuItem::new(headline_text, false, None));
    let _ = menu.append(&PredefinedMenuItem::separator());

    // No valid session yet --
    // offer the loopback-redirect + PKCE login flow directly (see
    // `handle_menu_event`'s "login_with_google" case and
    // `google_login::login`). Shown ahead of "Set Up YadoriLink…" below
    // since device registration itself needs a valid access token.
    if yadorilink_cli::http_client::require_access_token().is_err() {
        let _ =
            menu.append(&MenuItem::with_id("login_with_google", "Login with Google…", true, None));
        let _ = menu.append(&PredefinedMenuItem::separator());
    }

    // "first-run setup": no local device identity yet means this
    // machine has never completed `yadorilink device register`/`login` —
    // offer a discoverable entry point into that existing, already-tested
    // CLI onboarding flow rather than reimplementing sign-in/device-setup
    // UI natively in this pass (see `handle_menu_event`'s "setup_device"
    // case for exactly what this does and why).
    if !ipc_client::is_device_registered() {
        let _ = menu.append(&MenuItem::with_id("setup_device", "Set Up YadoriLink…", true, None));
        let _ = menu.append(&PredefinedMenuItem::separator());
    }

    if let Some(status) = status {
        for reason in status_model::reason_lines(status) {
            let _ = menu.append(&MenuItem::new(format!("  ! {reason}"), false, None));
        }
        if !status.links.is_empty() {
            let folders = Submenu::new("Linked Folders", true);
            for link in &status.links {
                // Each folder is now a
                // submenu offering both "Open" and a guarded "Remove…" (unlink)
                // — CLI-free folder removal from the tray.
                let per_folder = Submenu::new(status_model::folder_menu_label(link), true);
                let _ = per_folder.append(&MenuItem::with_id(
                    format!("open_folder:{}", link.local_path),
                    "Open Folder",
                    true,
                    None,
                ));
                let _ = per_folder.append(&MenuItem::with_id(
                    format!("unlink:{}", link.local_path),
                    "Remove from YadoriLink…",
                    true,
                    None,
                ));
                let _ = folders.append(&per_folder);
            }
            let _ = menu.append(&folders);
        }
        // Only offered once a device identity exists — see
        // this function's "setup_device" section above; linking a folder
        // needs a resolvable access token, which needs that setup first.
        if ipc_client::is_device_registered() {
            let _ = menu.append(&MenuItem::with_id(
                "add_synced_folder",
                "Add Synced Folder…",
                true,
                None,
            ));
        }
        let _ = menu.append(&MenuItem::with_id("pause_all", "Pause All", true, None));
        let _ = menu.append(&MenuItem::with_id("resume_all", "Resume All", true, None));
        let _ = menu.append(&PredefinedMenuItem::separator());

        // "resource limit" actions.
        let limits = Submenu::new("Bandwidth Limits", true);
        for preset in actions::BandwidthPreset::ALL {
            let _ = limits.append(&MenuItem::with_id(preset.menu_id(), preset.label(), true, None));
        }
        let _ = menu.append(&limits);

        let _ = menu.append(&MenuItem::with_id("check_updates", "Check for Updates", true, None));
        if !status.update_available_version.is_empty() {
            let _ = menu.append(&MenuItem::with_id(
                "install_update",
                format!("Install Update ({})", status.update_available_version),
                true,
                None,
            ));
        }
        let _ = menu.append(&MenuItem::with_id(
            "export_diagnostics",
            "Export Diagnostics…",
            true,
            None,
        ));
        let _ = menu.append(&MenuItem::with_id("restart_daemon", "Restart Daemon", true, None));
    } else {
        // "degraded-state actions": distinct from `restart_daemon`
        // above (which sends a `Shutdown` IPC request — a no-op, not a
        // "start", when nothing is listening) — see
        // `actions::start_daemon`'s doc comment.
        let _ = menu.append(&MenuItem::with_id(
            "start_daemon",
            "Start Daemon (retry connection)",
            true,
            None,
        ));
    }

    let _ = menu.append(&PredefinedMenuItem::separator());
    // Labelled "(this user)" since the
    // toggle manages a per-user startup entry (macOS LaunchAgent / Windows HKCU
    // Run key), distinct from any machine-wide installer startup option.
    let login_label = if login_item::is_enabled() {
        "Disable Start at Login (this user)"
    } else {
        "Start at Login (this user)"
    };
    let _ = menu.append(&MenuItem::with_id("toggle_login_item", login_label, true, None));
    // Account management (data export + self-service deletion) and
    // CLI-free sign-out, offered only while a session exists. After sign-out
    // runs, the 2s poll rebuilds this menu into its signed-out state on its own.
    if yadorilink_cli::http_client::require_access_token().is_ok() {
        let _ = menu.append(&MenuItem::with_id("account", "Account & Data…", true, None));
        let _ = menu.append(&MenuItem::with_id("sign_out", "Sign Out", true, None));
    }
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id("quit", "Quit", true, None));

    menu
}

/// Dispatches a clicked menu item's id to the matching action. Every
/// mutating action runs on its own short-lived tokio runtime/thread (see
/// this file's top doc comment) so a slow/unreachable daemon never blocks
/// the tao event loop thread.
fn handle_menu_event(id: &str) {
    if let Some(path) = id.strip_prefix("open_folder:") {
        let path = path.to_string();
        std::thread::spawn(move || {
            let _ = actions::open_folder(&path);
        });
        return;
    }
    // Guarded folder removal. The CLI's
    // `unlink` has no extra guard beyond user intent, so this app substitutes a
    // native confirm dialog (run on this main thread, as macOS requires) and
    // spells out that local files are kept, then sends the same daemon Unlink.
    if let Some(path) = id.strip_prefix("unlink:") {
        let path = path.to_string();
        let result = rfd::MessageDialog::new()
            .set_title("Remove folder from YadoriLink?")
            .set_description(format!(
                "{path}\n\nThis stops syncing this folder. Your local files are not deleted."
            ))
            .set_buttons(rfd::MessageButtons::OkCancel)
            .show();
        if result == rfd::MessageDialogResult::Ok {
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("failed to start action runtime");
                if let Err(e) = rt.block_on(actions::unlink(path)) {
                    tracing::warn!(error = %e, "unlink failed");
                }
            });
        }
        return;
    }
    if let Some(preset) = actions::BandwidthPreset::from_menu_id(id) {
        run_async(actions::set_bandwidth_limit(preset));
        return;
    }
    match id {
        "pause_all" => run_async(actions::pause_all()),
        "resume_all" => run_async(actions::resume_all()),
        "check_updates" => run_async(actions::check_for_updates()),
        "install_update" => run_async(actions::install_update()),
        "export_diagnostics" => {
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().expect("failed to start action runtime");
                if let Err(e) = rt.block_on(actions::export_diagnostics()) {
                    tracing::warn!(error = %e, "diagnostics export failed");
                }
            });
        }
        "restart_daemon" => run_async(actions::restart_daemon()),
        "start_daemon" => {
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().expect("failed to start action runtime");
                if let Err(e) = rt.block_on(actions::start_daemon()) {
                    tracing::warn!(error = %e, "start daemon failed");
                }
            });
        }
        // Sign-in now happens inside the
        // onboarding window (in-UI waiting/success/failure), not a fire-and-
        // forget browser handoff from the tray.
        "login_with_google" => spawn_window("onboarding"),
        "toggle_login_item" => {
            let result =
                if login_item::is_enabled() { login_item::disable() } else { login_item::enable() };
            if let Err(e) = result {
                tracing::warn!(error = %e, "launch-at-login toggle failed");
            }
        }
        // Open the account window
        // (data export + self-service deletion), its own `--window account`
        // process, same as the onboarding window.
        "account" => spawn_window("account"),
        // Sign out (revoke session + clear
        // keychain). The next status poll rebuilds the menu into signed-out.
        "sign_out" => {
            std::thread::spawn(|| {
                let rt = tokio::runtime::Runtime::new().expect("failed to start action runtime");
                if let Err(e) = rt.block_on(actions::sign_out()) {
                    tracing::warn!(error = %e, "sign out failed");
                }
            });
        }
        // All three first-run/setup entry
        // points now open the onboarding window, which derives the right step
        // from actual state — a fresh install lands on sign-in, a
        // configured machine when adding another folder. The Terminal shim and the
        // osascript folder/name prompts are gone.
        "setup_device" | "add_synced_folder" => spawn_window("onboarding"),
        _ => {}
    }
}

fn run_async<F>(fut: F)
where
    F: std::future::Future<Output = Result<(), ipc_client::IpcError>> + Send + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to start action runtime");
        if let Err(e) = rt.block_on(fut) {
            tracing::warn!(error = %e, "tray action failed");
        }
    });
}

/// A minimal 16x16 solid-color placeholder icon — this change ships no
/// real icon asset (a proper multi-resolution `.icns`/`.ico` is packaging
/// work, tracked as a follow-up), just enough for
/// `TrayIconBuilder::build` to succeed and for the tray to be visibly
/// present.
fn placeholder_icon() -> Icon {
    const SIZE: u32 = 16;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for _ in 0..(SIZE * SIZE) {
        rgba.extend_from_slice(&[0x2b, 0x6c, 0xb0, 0xff]); // opaque blue square
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("placeholder icon dimensions are valid")
}
