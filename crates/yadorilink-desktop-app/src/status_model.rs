//! Pure, GUI-free transforms from a `StatusResponse` (the same message
//! `yadorilink status` renders — see `yadorilink-cli`'s
//! `commands/status.rs`) into the strings the tray icon shows. Kept
//! entirely free of `tray_icon`/`tao` so every rendering decision here
//! is unit-testable without a display or event loop, mirroring
//! `yadorilink-cli`'s own established "one pure formatter fn per field
//! group, tested against a default fixture" discipline (`status.rs`'s
//! `held_summary_suffix`/`degraded_suffix`/etc.).

use yadorilink_ipc_proto::daemonctl::{LinkStatus, StatusResponse};
use yadorilink_product_view::FolderState;

/// The tray icon's headline label (menu title / tooltip prefix). Mirrors
/// `yadorilink status`'s own `overall_state_line` semantics — same field,
/// same "empty state means an old/unreachable daemon" handling — so the
/// desktop app and the CLI can never disagree about what "healthy" means
/// (spec's "CLI Parity For App-Visible State" requirement).
pub fn headline(status: &StatusResponse) -> String {
    match status.overall_state.as_str() {
        "healthy" => match paused_count(status) {
            0 => "YadoriLink: synced".to_string(),
            n if n == status.links.len() => "YadoriLink: syncing is paused".to_string(),
            n => format!("YadoriLink: {n} folder{} paused", plural(n as u64)),
        },
        "attention" => format!("YadoriLink: needs attention ({})", status.links.len().max(1)),
        "degraded" => "YadoriLink: degraded".to_string(),
        _ => "YadoriLink: unknown".to_string(),
    }
}

/// The headline shown when the daemon can't be reached at all — a
/// degraded state where IPC itself is unavailable, never confused with
/// a real `StatusResponse`'s own states above.
pub const DAEMON_UNREACHABLE_HEADLINE: &str = "YadoriLink: daemon not running";

/// One line per attention/degraded reason, in the same coarse
/// `category:context` shape `overall_status` (daemon-side) produces —
/// rendered as-is, never reformatted into something that could drift from
/// what the CLI would print for the identical `StatusResponse`.
pub fn reason_lines(status: &StatusResponse) -> Vec<String> {
    status.attention_reasons.iter().map(|r| reason_sentence(r)).collect()
}

fn paused_count(status: &StatusResponse) -> usize {
    status.links.iter().filter(|l| FolderState::from_link(l) == FolderState::Paused).count()
}

// ---- User-facing wording -------------------------------------------------
// Every plain-language sentence the tray shows for a daemon reason code or an
// action outcome lives in this block, so the shared wording layer can replace
// it in one place.

/// Plain sentence for a coarse `category:context` attention reason. The
/// context (group id, path, device id) is never shown; an unrecognised
/// category becomes a generic sentence.
pub fn reason_sentence(reason: &str) -> String {
    let category = reason.split(':').next().unwrap_or("");
    match category {
        "conflict" => "A file conflict needs review",
        "low_disk" => "Disk space is low",
        "peer_disconnected" => "Another device is offline",
        "recent_error" => "A recent sync error occurred",
        "update_failed" => "The update check failed",
        _ => "Something needs attention",
    }
    .to_string()
}

/// A tray action whose outcome is reported back to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    PauseAll,
    ResumeAll,
    CheckUpdates,
    DownloadUpdate,
    Bandwidth,
    Unlink,
    SignOut,
    RestartDaemon,
}

/// Result of a tray action, as shown in the menu/tooltip. `details` is the
/// raw error text, only for the on-demand details dialog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub text: String,
    pub is_error: bool,
    pub details: Option<String>,
}

pub fn action_notice(action: TrayAction, result: Result<(), String>) -> Notice {
    match result {
        Ok(()) => Notice {
            text: match action {
                TrayAction::PauseAll => "Syncing paused",
                TrayAction::ResumeAll => "Syncing resumed",
                TrayAction::CheckUpdates => "Update check finished",
                TrayAction::DownloadUpdate => "Opened the download page",
                TrayAction::Bandwidth => "Bandwidth limit changed",
                TrayAction::Unlink => "Folder removed from YadoriLink",
                TrayAction::SignOut => "Signed out",
                TrayAction::RestartDaemon => "Restart requested",
            }
            .to_string(),
            is_error: false,
            details: None,
        },
        Err(raw) => {
            let what = match action {
                TrayAction::PauseAll => "Could not pause syncing",
                TrayAction::ResumeAll => "Could not resume syncing",
                TrayAction::CheckUpdates => "Could not check for updates",
                TrayAction::DownloadUpdate => "Could not open the download page",
                TrayAction::Bandwidth => "Could not change the bandwidth limit",
                TrayAction::Unlink => "Could not remove the folder",
                TrayAction::SignOut => "Could not sign out; you are still signed in",
                TrayAction::RestartDaemon => "Could not restart YadoriLink",
            };
            let why = if raw.contains("not running or not reachable") {
                " because YadoriLink is not running"
            } else {
                ""
            };
            Notice { text: format!("{what}{why}"), is_error: true, details: Some(raw) }
        }
    }
}

/// What "download the new version" did. Both are normal results: a
/// package-managed install is told its command rather than sent to a page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateDownload {
    OpenedPage,
    /// The daemon's instruction for an install a package manager owns.
    Guidance(String),
}

pub fn update_download_notice(result: Result<UpdateDownload, String>) -> Notice {
    match result {
        Ok(UpdateDownload::OpenedPage) => action_notice(TrayAction::DownloadUpdate, Ok(())),
        Ok(UpdateDownload::Guidance(text)) => Notice { text, is_error: false, details: None },
        Err(raw) => action_notice(TrayAction::DownloadUpdate, Err(raw)),
    }
}

/// The tray and Settings label for getting a new version: an install that a
/// package manager owns is told its steps, not sent to a page.
pub fn update_download_label(version: &str, install_source: &str) -> String {
    let verb = if yadorilink_client_core::ops::updates::is_package_managed(install_source) {
        "Show Update Steps"
    } else {
        "Download Update"
    };
    format!("{verb} ({version})")
}

/// What the tray icon shows; `None` status means the daemon is unreachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayState {
    Idle,
    Syncing,
    Paused,
    Attention,
}

pub fn tray_state(status: Option<&StatusResponse>) -> TrayState {
    let Some(status) = status else { return TrayState::Attention };
    if status.overall_state != "healthy" {
        return TrayState::Attention;
    }
    let paused = paused_count(status);
    if paused > 0 && paused == status.links.len() {
        TrayState::Paused
    } else if status.links.iter().any(|l| FolderState::from_link(l) == FolderState::Syncing) {
        TrayState::Syncing
    } else {
        TrayState::Idle
    }
}

/// Solid-colour tray icon pixels: the existing blue, tinted per state.
pub fn tray_icon_rgba(state: TrayState, size: u32) -> Vec<u8> {
    let [r, g, b] = match state {
        TrayState::Idle => [0x2b, 0x6c, 0xb0],
        TrayState::Syncing => [0x38, 0xa9, 0xd6],
        TrayState::Paused => [0x8a, 0x8f, 0x98],
        TrayState::Attention => [0xe0, 0x8a, 0x1e],
    };
    [r, g, b, 0xff].repeat((size * size) as usize)
}

/// A linked folder's short display name: its last path segment, so a long
/// path doesn't blow out a menu's width or a window's heading. Falls back
/// to the whole path when there is no final segment (a filesystem root).
/// Shared by every surface that titles a folder — the tray submenu below,
/// and the folder-detail and share windows.
///
/// Delegates to `yadorilink-product-view`'s `folder::display_name`, the
/// same derivation `FolderSummary.name` uses, so the tray and the product
/// DTO layer can never silently drift apart.
pub fn folder_display_name(local_path: &str) -> String {
    yadorilink_product_view::folder::display_name(local_path)
}

/// One label per linked folder for the tray's "Linked Folders" submenu —
/// the folder's last path segment (so long paths don't blow out the menu
/// width) plus a short state suffix, non-empty exactly when there's
/// something to say beyond "syncing" (same "empty unless applicable"
/// discipline `yadorilink-cli`'s `status.rs` already uses).
///
/// The suffix's *precedence* (which condition wins when several apply) is
/// `FolderState::from_link`'s precedence, not a second independent
/// ordering kept here — two copies of the same ordering would be a real
/// duplication risk. Only the exact wording (and the degraded-vs-conflict
/// split within a single `Attention` state, which `FolderState` doesn't
/// need to distinguish) stays local to this function.
pub fn folder_menu_label(link: &LinkStatus) -> String {
    let name = yadorilink_product_view::folder::link_name(link);
    let suffix = match FolderState::from_link(link) {
        FolderState::Blocked => "  (not syncing: this folder group is linked twice)".to_string(),
        FolderState::Paused if link.degraded => {
            let reason = link.degraded_reason.to_lowercase();
            if reason.contains("space") || reason.contains("disk") {
                "  (paused; low disk space)".to_string()
            } else {
                "  (paused; needs attention)".to_string()
            }
        }
        FolderState::Paused => "  (paused by you)".to_string(),
        FolderState::Attention if link.degraded => "  (degraded)".to_string(),
        FolderState::Attention => {
            format!("  ({} conflict{})", link.conflict_count, plural(link.conflict_count))
        }
        FolderState::Syncing => "  (syncing…)".to_string(),
        FolderState::UpToDate => String::new(),
    };
    format!("{name}{suffix}")
}

fn plural(n: u64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests;
