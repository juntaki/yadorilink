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
        "healthy" => "YadoriLink: synced".to_string(),
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
    status.attention_reasons.clone()
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
    let name = folder_display_name(&link.local_path);
    let suffix = match FolderState::from_link(link) {
        FolderState::Blocked => "  (not syncing: this folder group is linked twice)".to_string(),
        FolderState::Paused => "  (paused)".to_string(),
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
