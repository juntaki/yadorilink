//! The tray menu's mutating/action-taking
//! commands. Every action here is a thin wrapper around an existing daemon
//! control-socket request ("It never reads the sync
//! index or block store directly... sends explicit commands to the
//! daemon") — this module invents no new sync behavior, it only calls the
//! same requests `yadorilink-cli`'s `commands/` already send, so mutating
//! settings are validated and persisted by the daemon, not only by this
//! UI.

use yadorilink_client_core::ops::{
    auth, daemon, devices, diagnostics, files, folders, links, shares, storage, transfers, updates,
};
use yadorilink_client_core::CoreError;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, FileVersionInfo, GcResponse, InboxTransfer, LimitsSetResponse,
    LimitsShowResponse, MaterializationStatusResponse, ReceiveTransferResponse,
    RestoreTrashOperationResponse, SendFileResponse, TrashedFileInfo, UpdateConfigResponse,
    UpdateStatusResponse,
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
    Ok(folders::pause_all().await?)
}

pub async fn resume_all() -> Result<(), IpcError> {
    Ok(folders::resume_all().await?)
}

/// Pauses sync for exactly one linked folder — the same daemon `Pause`
/// request `pause_all` sends per-link and `yadorilink daemon pause`'s own
/// per-link path already sends; a Home/Folder screen's per-folder
/// pause control (the tray so far only offers "Pause All").
pub async fn pause_link(local_path: String) -> Result<(), IpcError> {
    Ok(folders::pause_folder(local_path).await?)
}

/// Resumes sync for exactly one linked folder — the single-link
/// counterpart to `pause_link` above.
pub async fn resume_link(local_path: String) -> Result<(), IpcError> {
    Ok(folders::resume_folder(local_path).await?)
}

// The tray's old "Add Synced Folder" path
// (`link_folder`/`add_synced_folder`) is removed. It linked with
// `acknowledge_risks: true` unconditionally — bypassing the first-run preflight
// the proposal calls out as the gap to fix. Folder linking now goes through the
// onboarding window, which runs the shared `link_preflight` and only
// acknowledges risks the user has explicitly ticked (see `crate::window` +
// `yadorilink_client_core::ops::links::run_link_preflight`).

/// "open folder": reveals a linked folder in the native file
/// manager (Finder/Explorer) — a pure OS action, no daemon IPC involved.
pub fn open_folder(local_path: &str) -> Result<(), opener::OpenError> {
    opener::open(local_path)
}

/// Launch one of this binary's GUI windows as a separate process. Every
/// GUI surface is this same binary re-invoked as `--window <kind>`,
/// running its own eframe/winit event loop, so none of them has to coexist
/// with the tray's own tao loop (see `main.rs`'s doc comment for the full
/// reasoning).
///
/// Lives here rather than in `main.rs` because one window can also open
/// another (the folder-detail window's "Share…" button), and only this
/// crate's library half is reachable from a window module.
pub fn spawn_window(kind: &str) {
    spawn_window_process(kind, None);
}

/// Same as `spawn_window`, for a window kind that also needs a
/// `--path <local_path>` argument (the per-folder detail and share
/// windows, which have to know WHICH folder they are about).
pub fn spawn_window_with_path(kind: &str, local_path: &str) {
    spawn_window_process(kind, Some(local_path));
}

fn spawn_window_process(kind: &str, local_path: Option<&str>) {
    let Ok(exe) = std::env::current_exe() else {
        tracing::warn!(kind, "cannot locate this executable to open a window");
        return;
    };
    let mut command = std::process::Command::new(exe);
    command.arg("--window").arg(kind);
    if let Some(local_path) = local_path {
        command.arg("--path").arg(local_path);
    }
    if let Err(e) = command.spawn() {
        tracing::warn!(error = %e, kind, "could not open a window");
    }
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
    links::send_unlink(&local_path, false).await?;
    Ok(())
}

/// Switches this device's storage mode (Synced/eager <-> Selective/
/// on-demand) for an already-linked folder group — the Folder screen's
/// mode switch, reusing the client layer's `set_storage_mode_resolved`
/// (the same daemon-orchestrated coordination-plane write + local policy
/// flip `yadorilink share set-storage-mode` sends) rather than a second
/// implementation. Addressed by `group_id` (already on hand from a
/// `FolderSummary`/`LinkStatus` this window already fetched), not group
/// name, so this never needs its own extra name-resolution round trip.
///
/// A demotion (Synced -> Selective) can be refused by the daemon's
/// durability handoff gate (no other confirmed-ready full replica yet) --
/// that refusal surfaces as a plain `Err`, same as any other failed
/// action; the caller is responsible for warning the user before calling
/// this for a demotion, the same way `main.rs`'s unlink confirm dialog
/// warns before that data-affecting action.
pub async fn set_folder_mode(
    group_id: String,
    on_demand: bool,
    group_name_for_display: &str,
) -> Result<shares::StorageModeOutcome, CoreError> {
    shares::set_storage_mode_resolved(group_id, on_demand, group_name_for_display).await
}

/// De-registers a device from this account, revoking its access to every
/// folder group at once — identical request `yadorilink device remove`
/// sends (`commands::device::remove`), the Devices screen's "Remove
/// device" action. `force` bypasses the daemon's durability readiness
/// pre-check for a device that must be removed regardless (data-loss
/// risk, audit-logged by the daemon); the caller is responsible for the
/// same kind of confirm dialog `main.rs`'s unlink handler shows before
/// calling this with `force: true`.
pub async fn remove_device(device_id: String, force: bool) -> Result<(), CoreError> {
    devices::remove_device(&device_id, force).await?;
    Ok(())
}

/// Sign out — irreversibly revokes this installation's access on the server,
/// confirms the revocation, and only then clears the OS keychain, by reusing
/// `yadorilink_client_core::ops::auth::sign_out` (the single implementation
/// `yadorilink logout` runs too, so the app and CLI can never diverge on
/// what "sign out" does).
///
/// It makes a network call and it can FAIL. That is deliberate: if the
/// revocation cannot be confirmed, the credential is kept rather than deleted,
/// because deleting it would leave this computer signed in on the server with
/// nothing here able to sign it out. The error text says so; show it rather
/// than swallowing it, and do not offer a local-only clear as a "retry" —
/// that is a different operation (`yadorilink forget-local-credentials`) with
/// a different outcome.
///
/// After this returns Ok, the tray's 2s poll finds `is_signed_in` false and
/// rebuilds the menu into its signed-out state (offering "Login with Google…")
/// on its own.
pub async fn sign_out() -> Result<(), CoreError> {
    auth::sign_out().await?;
    Ok(())
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
    Ok(daemon::stop_daemon().await?)
}

/// "degraded-state actions": the daemon-unavailable/degraded tray
/// menu's "Start Daemon" action — unlike `restart_daemon` above, this
/// covers the case where nothing is listening on the control socket at
/// all (so a `Shutdown` request would just fail with "daemon not
/// running", a no-op), by directly spawning the daemon binary -- the one
/// implementation `yadorilink daemon start` also runs
/// (`yadorilink_client_core::ops::daemon::start_daemon`).
pub async fn start_daemon() -> Result<(), CoreError> {
    daemon::start_daemon().await?;
    Ok(())
}

/// "updates": check for an available update — identical request
/// `yadorilink update check` sends.
pub async fn check_for_updates() -> Result<(), IpcError> {
    updates::check_for_updates().await?;
    Ok(())
}

/// "updates": install a previously-checked update — identical
/// request `yadorilink update install` sends. The daemon's own update
/// pipeline (mandatory/holdback/safe-point gating)
/// is the sole authority for whether/when this actually applies, matching
/// its "round-trip through daemon validation" rule.
pub async fn install_update() -> Result<(), IpcError> {
    updates::install_update().await?;
    Ok(())
}

/// "resource limit" actions: a small, fixed set of bandwidth
/// presets for the tray menu (there is no native numeric-entry dialog) —
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
    storage::set_bandwidth_limits(preset.bytes_per_sec(), preset.bytes_per_sec()).await?;
    Ok(())
}

/// This folder's currently-live conflicted-copy files, filtered down from
/// `ListConflicts`' own all-links response (mirrors `list_link_paths`'
/// established "fetch the aggregate request, filter to what this caller
/// actually needs" shape) -- the folder-status window's Conflicts panel.
pub async fn list_conflicts_for(local_path: &str) -> Result<Vec<ConflictedFileInfo>, IpcError> {
    Ok(files::list_conflicts(Some(local_path)).await?)
}

/// This folder's currently-recoverable trashed files, same filtering
/// shape as `list_conflicts_for` -- the folder-status window's Trash
/// panel.
pub async fn list_trash_for(local_path: &str) -> Result<Vec<TrashedFileInfo>, IpcError> {
    Ok(files::list_trash(Some(local_path)).await?)
}

/// Recovers a deleted file's last version before deletion as a new
/// current version -- identical request `yadorilink trash restore` sends.
pub async fn restore_trash(absolute_path: String) -> Result<(), IpcError> {
    Ok(files::restore_from_trash(absolute_path).await?)
}

/// Recovers, together, every trashed entry removed by the same recursive
/// delete or directory rename that removed the entry at `absolute_path` --
/// identical request `yadorilink trash restore --folder` sends.
pub async fn restore_trash_operation(
    absolute_path: String,
) -> Result<RestoreTrashOperationResponse, IpcError> {
    Ok(files::restore_trash_operation(absolute_path).await?)
}

/// Every retained version of one file, newest first including the
/// current one -- identical request `yadorilink versions <path>` sends.
pub async fn list_versions(absolute_path: String) -> Result<Vec<FileVersionInfo>, IpcError> {
    Ok(files::list_versions(absolute_path).await?)
}

/// Restores one file to a specific prior version (or, when `version_seq`
/// is `None`, the most recently superseded one) -- identical request
/// `yadorilink restore <path> [--version <id>]` sends.
pub async fn restore_version(
    absolute_path: String,
    version_seq: Option<i64>,
) -> Result<(), IpcError> {
    Ok(files::restore_version(absolute_path, version_seq).await?)
}

/// One file's current materialization state and pin flag -- identical
/// request `yadorilink materialization-status <path>` sends, the
/// on-demand-sync selective-sync panel's read side.
pub async fn materialization_status(
    absolute_path: String,
) -> Result<MaterializationStatusResponse, IpcError> {
    Ok(files::materialization_status(absolute_path).await?)
}

/// Force-hydrates a placeholder file and keeps it hydrated -- identical
/// request `yadorilink pin <path>` sends.
pub async fn pin_file(absolute_path: String) -> Result<(), IpcError> {
    Ok(files::pin_file(absolute_path).await?)
}

/// Allows a pinned file to become a placeholder again -- identical
/// request `yadorilink unpin <path>` sends.
pub async fn unpin_file(absolute_path: String) -> Result<(), IpcError> {
    Ok(files::unpin_file(absolute_path).await?)
}

/// Fetches a placeholder file's real content -- identical request
/// `yadorilink hydrate <path>` sends.
pub async fn hydrate_file(absolute_path: String) -> Result<(), IpcError> {
    Ok(files::hydrate_file(absolute_path).await?)
}

/// Converts a hydrated file back into a placeholder to reclaim local disk
/// space -- identical request `yadorilink evict <path>` sends. Returns
/// whether the file was actually dehydrated (mirrors
/// `commands::materialization::evict`'s own `EvictResponse.dehydrated`
/// check -- a request that silently did nothing, e.g. the file is
/// pinned/busy/not fully synced, must never read as success).
pub async fn evict_file(absolute_path: String) -> Result<bool, IpcError> {
    Ok(files::evict_file(absolute_path).await?)
}

/// A native single-file picker scoped to start browsing inside `dir` --
/// same rationale/platform scope as `pick_folder` above (only the two
/// shipped desktop platforms; `rfd` has no Linux desktop target here).
/// Used by the folder-status window's history/restore and selective-sync
/// panels, which both operate on one file the user picks explicitly
/// rather than a full in-app file browser (no daemon request exists to
/// list every indexed path in a folder, and building one would be new
/// surface, not wiring existing capability).
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn pick_file_in(dir: &str) -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title("Choose a file").set_directory(dir).pick_file()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_file_in(_dir: &str) -> Option<std::path::PathBuf> {
    None
}

/// `pick_file_in`'s folder counterpart: the same panels act on a folder as
/// a whole (pinning it keeps everything below it, now and later).
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn pick_folder_in(dir: &str) -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title("Choose a folder").set_directory(dir).pick_folder()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_folder_in(_dir: &str) -> Option<std::path::PathBuf> {
    None
}

/// A native single-file picker with no starting-directory restriction --
/// the Send window's "Choose file…" button, distinct from `pick_file_in`
/// (which is scoped to browsing inside one already-linked folder for the
/// version-history/selective-sync panel). Same platform scope as every
/// other `rfd` picker in this module.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn pick_any_file() -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title("Choose a file to send").pick_file()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_any_file() -> Option<std::path::PathBuf> {
    None
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
    pick_folder_titled("Choose a folder to sync")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_folder() -> Option<std::path::PathBuf> {
    None
}

/// Same folder picker as `pick_folder`, with a caller-chosen dialog title
/// -- the Send window's "Choose folder…" (a send source) and "Receive
/// to…" (a receive destination) need distinct wording for the same
/// underlying `rfd` dialog.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn pick_folder_titled(title: &str) -> Option<std::path::PathBuf> {
    rfd::FileDialog::new().set_title(title).pick_folder()
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn pick_folder_titled(_title: &str) -> Option<std::path::PathBuf> {
    None
}

/// "diagnostics export": requests the same daemon-assembled,
/// already-redacted bundle `yadorilink diagnose export` writes, saves it
/// under this device's config directory, and reveals it in the native
/// file manager — "without requiring a terminal" (spec scenario).
pub async fn export_diagnostics() -> Result<std::path::PathBuf, DiagnosticsError> {
    let bundle_json = match diagnostics::export_bundle_json().await {
        Ok(bundle_json) => bundle_json,
        // The client layer reports a response of the wrong kind as `Other`;
        // everything the socket itself can fail with arrives as another
        // category.
        Err(CoreError::Other(_)) => return Err(DiagnosticsError::UnexpectedResponse),
        Err(e) => return Err(DiagnosticsError::Ipc(e.into())),
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

/// Offers a file or directory to another device on this account -- one-shot,
/// not linked/synced -- identical request `yadorilink send <path>
/// <target-device>` sends (`commands::send::send`). `target_device` is a
/// `device_id`, resolved against this account's already-known device list
/// (the Send window's own device picker, sourced from
/// `crate::devices::device_summaries` over the currently linked
/// folders' groups -- there is no single "every device on my account" list,
/// see that function's own doc comment).
pub async fn send_file(
    source_path: String,
    target_device: String,
) -> Result<SendFileResponse, IpcError> {
    Ok(transfers::send_file(source_path, target_device).await?)
}

/// Every transfer other devices have sent to this device, whether or not
/// `receive_transfer` has been run for it yet -- identical request
/// `yadorilink inbox` sends.
pub async fn list_inbox() -> Result<Vec<InboxTransfer>, IpcError> {
    Ok(transfers::list_inbox().await?)
}

/// Accepts an inbound transfer, materializing it into `to` (or the daemon's
/// default inbox directory when `None`) -- identical request `yadorilink
/// receive <transfer-id> [--to <dir>]` sends. Resumable, same as the CLI.
pub async fn receive_transfer(
    transfer_id: String,
    to: Option<String>,
) -> Result<ReceiveTransferResponse, IpcError> {
    Ok(transfers::receive_transfer(transfer_id, to).await?)
}

/// The currently configured (not measured) global transfer rate limits --
/// identical request `yadorilink limits show` sends. The Settings window's
/// bandwidth panel reads this to seed its editable fields, rather than
/// assuming the tray's own coarse presets (`BandwidthPreset`) are still in
/// effect.
pub async fn show_limits() -> Result<LimitsShowResponse, IpcError> {
    Ok(storage::bandwidth_limits().await?)
}

/// Sets exact global upload/download rate limits (bytes/sec, `0` =
/// unlimited) -- identical request `yadorilink limits set --up --down`
/// sends. Unlike `set_bandwidth_limit`'s fixed presets, this accepts any
/// value, for the Settings window's own numeric fields.
pub async fn set_limits(up: u64, down: u64) -> Result<LimitsSetResponse, IpcError> {
    Ok(storage::set_bandwidth_limits(up, down).await?)
}

/// Current version/channel/install-source/last-check/state/available-
/// version/rollout/error/automatic-checks-and-install-mode -- identical
/// request `yadorilink update status` sends. The Settings window's Update
/// panel renders this directly rather than re-deriving anything from it.
pub async fn update_status() -> Result<UpdateStatusResponse, IpcError> {
    Ok(updates::update_status().await?)
}

/// Configures automatic update checks and/or automatic install mode --
/// identical request `yadorilink update config --checks --install` sends.
/// `None` for either argument means "leave that setting unchanged" (same
/// discipline the wire request itself documents).
pub async fn set_update_config(
    automatic_checks_enabled: Option<bool>,
    automatic_install_mode: Option<String>,
) -> Result<UpdateConfigResponse, IpcError> {
    Ok(updates::set_update_config(automatic_checks_enabled, automatic_install_mode).await?)
}

/// Triggers an immediate block-store mark-and-sweep, or (when `dry_run`)
/// reports what a real sweep would reclaim without deleting anything --
/// identical request `yadorilink gc [--dry-run]` sends. The daemon refuses
/// a concurrent sweep or one during active sync (surfaced as an ordinary
/// `IpcError::DaemonError`, the same "show it, don't swallow it" path
/// every other daemon-reported failure in this module already takes) --
/// this wrapper never retries or masks that.
pub async fn run_gc(dry_run: bool) -> Result<GcResponse, IpcError> {
    Ok(storage::run_gc(dry_run).await?)
}

#[cfg(test)]
mod tests;
