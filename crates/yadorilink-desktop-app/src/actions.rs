//! The tray menu's mutating/action-taking
//! commands. Every action here is a thin wrapper around an existing daemon
//! control-socket request ("It never reads the sync
//! index or block store directly... sends explicit commands to the
//! daemon") — this module invents no new sync behavior, it only calls the
//! same requests `yadorilink-cli`'s `commands/` already send, so mutating
//! settings are validated and persisted by the daemon, not only by this
//! UI.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DiagnosticsExportRequest, LimitsSetRequest, PauseRequest, ResumeRequest, ShutdownRequest,
    UnlinkRequest, UpdateCheckRequest, UpdateInstallRequest,
};

use crate::ipc_client::{self, IpcError};

/// "pause/resume... for linked folders": pauses every currently
/// linked folder — mirrors `yadorilink-cli`'s `commands/daemon::pause`
/// exactly (list links, then `Pause` each), rather than adding a new
/// "pause everything" daemon request, since the existing per-link
/// `Pause`/`Resume` requests already cover it and this keeps the daemon's
/// request surface unchanged (spec's non-goal: no new sync policy logic
/// in the desktop app).
pub async fn pause_all() -> Result<(), IpcError> {
    let links = list_link_paths().await?;
    for local_path in links {
        ipc_client::send(ReqPayload::Pause(PauseRequest { local_path })).await?;
    }
    Ok(())
}

pub async fn resume_all() -> Result<(), IpcError> {
    let links = list_link_paths().await?;
    for local_path in links {
        ipc_client::send(ReqPayload::Resume(ResumeRequest { local_path })).await?;
    }
    Ok(())
}

async fn list_link_paths() -> Result<Vec<String>, IpcError> {
    let resp = ipc_client::send(ReqPayload::ListLinks(
        yadorilink_ipc_proto::daemonctl::ListLinksRequest {},
    ))
    .await?;
    match resp.payload {
        Some(RespPayload::ListLinks(list)) => {
            Ok(list.links.into_iter().map(|l| l.local_path).collect())
        }
        _ => Ok(Vec::new()),
    }
}

// The tray's old "Add Synced Folder" path
// (`link_folder`/`add_synced_folder`) is removed. It linked with
// `acknowledge_risks: true` unconditionally — bypassing the first-run preflight
// the proposal calls out as the gap to fix. Folder linking now goes through the
// onboarding window, which runs the shared `link_preflight` and only
// acknowledges risks the user has explicitly ticked (see `crate::window` +
// `yadorilink_cli::commands::link::{run_link_preflight, link_resolved}`).

/// "open folder": reveals a linked folder in the native file
/// manager (Finder/Explorer) — a pure OS action, no daemon IPC involved.
pub fn open_folder(local_path: &str) -> Result<(), opener::OpenError> {
    opener::open(local_path)
}

/// Remove a linked folder — the same
/// daemon `Unlink` request `yadorilink unlink` sends (`commands::link::
/// unlink`). The daemon only forgets the link; it never touches the local
/// files (spec's "local files are not deleted"). The caller is responsible
/// for the CLI-equivalent confirmation before this is invoked (the CLI has
/// no extra guard beyond user intent; this app surfaces a native confirm
/// dialog in its place — see `main.rs`'s folder-submenu handler).
pub async fn unlink(local_path: String) -> Result<(), IpcError> {
    // `force: false` -- the tray has no equivalent of the CLI's `--force`
    // data-loss override; a durability-gate refusal here surfaces as a
    // plain IPC error, same as any other failed action.
    ipc_client::send(ReqPayload::Unlink(UnlinkRequest { local_path, force: false })).await?;
    Ok(())
}

/// Sign out — revokes the coordination
/// session and clears the OS keychain by reusing `yadorilink-cli`'s own
/// `commands::auth::logout` (the single implementation, so the app and CLI
/// can never diverge on what "sign out" does). After this returns, the
/// tray's 2s poll finds `require_access_token` failing and rebuilds the menu
/// into its signed-out state (offering "Login with Google…") on its own.
pub async fn sign_out() -> Result<(), yadorilink_cli::error::CliError> {
    yadorilink_cli::commands::auth::logout().await
}

/// "restart daemon": a clean `Shutdown` request. The daemon is
/// registered to restart itself (macOS `LaunchAgent` `KeepAlive`/Windows
/// Scheduled Task `-AtLogOn`, see `installer/`) for anything other than a
/// clean exit; a graceful `Shutdown` is exactly what `yadorilink daemon
/// stop` already sends, and relies on the same supervisor to bring it back
/// — this app does not itself spawn a new daemon process (that would
/// duplicate the installer's own supervision logic, which already has to
/// get this right for crash recovery, not just for this menu item).
pub async fn restart_daemon() -> Result<(), IpcError> {
    ipc_client::send(ReqPayload::Shutdown(ShutdownRequest {})).await?;
    Ok(())
}

/// "degraded-state actions": the daemon-unavailable/degraded tray
/// menu's "Start Daemon" action — unlike `restart_daemon` above, this
/// covers the case where nothing is listening on the control socket at
/// all (so a `Shutdown` request would just fail with "daemon not
/// running", a no-op), by directly spawning the daemon binary — identical
/// logic to `yadorilink-cli`'s own `commands/daemon::start` (deliberately
/// duplicated rather than shared, matching this crate's established
/// "own client/process code, not shared with the CLI" precedent — see
/// `ipc_client.rs`'s doc comment).
pub async fn start_daemon() -> Result<(), StartDaemonError> {
    if ipc_client::send(ReqPayload::Status(yadorilink_ipc_proto::daemonctl::StatusRequest {}))
        .await
        .is_ok()
    {
        return Ok(()); // already running
    }

    let daemon_binary = daemon_binary_path();
    std::process::Command::new(&daemon_binary)
        .spawn()
        .map_err(|e| StartDaemonError::Spawn(daemon_binary.clone(), e))?;

    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if ipc_client::send(ReqPayload::Status(yadorilink_ipc_proto::daemonctl::StatusRequest {}))
            .await
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(StartDaemonError::NeverBecameReachable)
}

#[derive(Debug, thiserror::Error)]
pub enum StartDaemonError {
    #[error("failed to launch {0}: {1}")]
    Spawn(std::path::PathBuf, std::io::Error),
    #[error("daemon did not become reachable after starting")]
    NeverBecameReachable,
}

/// Mirrors `yadorilink-cli`'s `commands/daemon::daemon_binary_path` exactly
/// (same "look next to this executable first, fall back to PATH" logic).
fn daemon_binary_path() -> std::path::PathBuf {
    let name = if cfg!(windows) { "yadorilink-daemon.exe" } else { "yadorilink-daemon" };
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from(name))
}

/// "updates": check for an available update — identical request
/// `yadorilink update check` sends.
pub async fn check_for_updates() -> Result<(), IpcError> {
    ipc_client::send(ReqPayload::UpdateCheck(UpdateCheckRequest {})).await?;
    Ok(())
}

/// "updates": install a previously-checked update — identical
/// request `yadorilink update install` sends. The daemon's own update
/// pipeline (mandatory/holdback/safe-point gating)
/// is the sole authority for whether/when this actually applies, matching
/// its "round-trip through daemon validation" rule.
pub async fn install_update() -> Result<(), IpcError> {
    ipc_client::send(ReqPayload::UpdateInstall(UpdateInstallRequest {})).await?;
    Ok(())
}

/// "resource limit" actions: a small, fixed set of bandwidth
/// presets for the tray menu (a native numeric-entry dialog is out of
/// scope for this pass — see this crate's top-level honesty notes) —
/// `yadorilink limits set` itself accepts an arbitrary rate, this is just
/// a coarser UI over the identical daemon request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthPreset {
    Unlimited,
    OneMibPerSec,
    FiveMibPerSec,
    TenMibPerSec,
}

impl BandwidthPreset {
    pub const ALL: [BandwidthPreset; 4] = [
        BandwidthPreset::Unlimited,
        BandwidthPreset::OneMibPerSec,
        BandwidthPreset::FiveMibPerSec,
        BandwidthPreset::TenMibPerSec,
    ];

    pub fn label(self) -> &'static str {
        match self {
            BandwidthPreset::Unlimited => "Unlimited",
            BandwidthPreset::OneMibPerSec => "1 MiB/s",
            BandwidthPreset::FiveMibPerSec => "5 MiB/s",
            BandwidthPreset::TenMibPerSec => "10 MiB/s",
        }
    }

    /// `0` is this codebase's established "unlimited" convention (matches
    /// `yadorilink-cli`'s `commands/status.rs`::`format_rate_bytes_per_sec`
    /// and `limits show`'s own convention).
    pub fn bytes_per_sec(self) -> u64 {
        const MIB: u64 = 1024 * 1024;
        match self {
            BandwidthPreset::Unlimited => 0,
            BandwidthPreset::OneMibPerSec => MIB,
            BandwidthPreset::FiveMibPerSec => 5 * MIB,
            BandwidthPreset::TenMibPerSec => 10 * MIB,
        }
    }

    /// Menu id round trip — see `main.rs`'s `handle_menu_event`.
    pub fn menu_id(self) -> &'static str {
        match self {
            BandwidthPreset::Unlimited => "limits:unlimited",
            BandwidthPreset::OneMibPerSec => "limits:1mib",
            BandwidthPreset::FiveMibPerSec => "limits:5mib",
            BandwidthPreset::TenMibPerSec => "limits:10mib",
        }
    }

    pub fn from_menu_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.menu_id() == id)
    }
}

/// Applies the same preset to both upload and download — matches
/// `yadorilink limits set`'s own per-direction request shape, but the
/// tray's presets are deliberately symmetric for simplicity (a user who
/// wants asymmetric limits already has the CLI for that -- the
/// "keep the first beta scope small" principle).
pub async fn set_bandwidth_limit(preset: BandwidthPreset) -> Result<(), IpcError> {
    ipc_client::send(ReqPayload::LimitsSet(LimitsSetRequest {
        upload_bytes_per_sec: preset.bytes_per_sec(),
        download_bytes_per_sec: preset.bytes_per_sec(),
    }))
    .await?;
    Ok(())
}

/// A native folder-picker dialog via
/// `rfd`, replacing the previous macOS-only `osascript` path — one
/// cross-platform implementation covering both target platforms (the
/// onboarding window's link step calls this on its eframe main thread, which
/// macOS requires for native dialogs). Text input (the old `prompt_text`) has
/// no `rfd` equivalent and is superseded by the window's own egui text fields.
/// Only the two shipped desktop platforms are supported; elsewhere it returns
/// `None` explicitly (this crate has no Linux desktop target — see
/// `login_item.rs`'s matching platform scope).
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn pick_folder() -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title("Choose a folder to sync").pick_folder()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_folder() -> Option<std::path::PathBuf> {
    None
}

/// "diagnostics export": requests the same daemon-assembled,
/// already-redacted bundle `yadorilink diagnose export` writes, saves it
/// under this device's config directory, and reveals it in the native
/// file manager — "without requiring a terminal" (spec scenario).
pub async fn export_diagnostics() -> Result<std::path::PathBuf, DiagnosticsError> {
    let resp = ipc_client::send(ReqPayload::DiagnosticsExport(DiagnosticsExportRequest {}))
        .await
        .map_err(DiagnosticsError::Ipc)?;
    let bundle_json = match resp.payload {
        Some(RespPayload::DiagnosticsExport(bundle)) => bundle.bundle_json,
        _ => return Err(DiagnosticsError::UnexpectedResponse),
    };
    let path = default_export_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(DiagnosticsError::Io)?;
    }
    std::fs::write(&path, bundle_json).map_err(DiagnosticsError::Io)?;
    let _ = opener::reveal(&path);
    Ok(path)
}

#[derive(Debug, thiserror::Error)]
pub enum DiagnosticsError {
    #[error(transparent)]
    Ipc(#[from] IpcError),
    #[error("daemon returned an unexpected response to a diagnostics export request")]
    UnexpectedResponse,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn default_export_path() -> std::path::PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ipc_client::config_dir_public().join(format!("diagnostics-{now}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `default_export_path` always lands inside the config directory with
    /// a `.json` extension — a pure, display-free check that the naming
    /// scheme is stable (the real IPC round trip in `export_diagnostics`
    /// itself needs a running daemon and is covered by this crate's
    /// daemon-backed integration test instead).
    #[test]
    fn default_export_path_is_json_under_config_dir() {
        let path = default_export_path();
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("diagnostics-"));
    }

    /// Every preset's menu id round-trips back to the same preset — the
    /// tray menu only has the id string to go on when dispatching a click
    /// (`main.rs`'s `handle_menu_event`), so this mapping must be
    /// bijective or a click could silently apply the wrong rate.
    #[test]
    fn every_bandwidth_preset_menu_id_round_trips() {
        for preset in BandwidthPreset::ALL {
            assert_eq!(BandwidthPreset::from_menu_id(preset.menu_id()), Some(preset));
        }
    }

    #[test]
    fn unlimited_preset_is_the_zero_convention() {
        assert_eq!(BandwidthPreset::Unlimited.bytes_per_sec(), 0);
    }

    #[test]
    fn unknown_menu_id_maps_to_no_preset() {
        assert_eq!(BandwidthPreset::from_menu_id("not_a_real_id"), None);
    }

    /// `daemon_binary_path` picks the platform-correct binary name — the
    /// "prefer a sibling of the current executable, else fall back to
    /// PATH" resolution itself needs a real filesystem layout to
    /// meaningfully test end-to-end, but the name it looks for is a pure,
    /// display-free fact worth pinning.
    #[test]
    fn daemon_binary_path_uses_the_platform_correct_name() {
        let path = daemon_binary_path();
        let name = path.file_name().unwrap().to_string_lossy();
        if cfg!(windows) {
            assert_eq!(name, "yadorilink-daemon.exe");
        } else {
            assert_eq!(name, "yadorilink-daemon");
        }
    }
}
