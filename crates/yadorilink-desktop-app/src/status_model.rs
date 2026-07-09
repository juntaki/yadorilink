//! Pure, GUI-free transforms from a `StatusResponse` (the same message
//! `yadorilink status` renders — see `yadorilink-cli`'s
//! `commands/status.rs`) into the strings the tray icon shows. Kept
//! entirely free of `tray_icon`/`tao` so every rendering decision here
//! is unit-testable without a display or event loop, mirroring
//! `yadorilink-cli`'s own established "one pure formatter fn per field
//! group, tested against a default fixture" discipline (`status.rs`'s
//! `held_summary_suffix`/`degraded_suffix`/etc.).

use yadorilink_ipc_proto::daemonctl::{LinkStatus, StatusResponse};

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

/// One label per linked folder for the tray's "Linked Folders" submenu —
/// the folder's last path segment (so long paths don't blow out the menu
/// width) plus a short state suffix, non-empty exactly when there's
/// something to say beyond "syncing" (same "empty unless applicable"
/// discipline `yadorilink-cli`'s `status.rs` already uses).
pub fn folder_menu_label(link: &LinkStatus) -> String {
    let name = std::path::Path::new(&link.local_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| link.local_path.clone());
    let mut suffix = String::new();
    if link.paused {
        suffix.push_str("  (paused)");
    } else if link.degraded {
        suffix.push_str("  (degraded)");
    } else if link.conflict_count > 0 {
        suffix.push_str(&format!(
            "  ({} conflict{})",
            link.conflict_count,
            plural(link.conflict_count)
        ));
    } else if link.has_active_transfer {
        suffix.push_str("  (syncing…)");
    }
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
mod tests {
    use super::*;

    fn base_status() -> StatusResponse {
        StatusResponse::default()
    }

    fn base_link() -> LinkStatus {
        LinkStatus { local_path: "/Users/alice/Photos".into(), ..Default::default() }
    }

    #[test]
    fn healthy_state_renders_synced_headline() {
        let mut status = base_status();
        status.overall_state = "healthy".into();
        assert_eq!(headline(&status), "YadoriLink: synced");
    }

    #[test]
    fn attention_state_renders_needs_attention_headline() {
        let mut status = base_status();
        status.overall_state = "attention".into();
        status.links = vec![base_link()];
        assert!(headline(&status).contains("needs attention"));
    }

    #[test]
    fn degraded_state_renders_degraded_headline() {
        let mut status = base_status();
        status.overall_state = "degraded".into();
        assert_eq!(headline(&status), "YadoriLink: degraded");
    }

    /// An empty/unrecognized `overall_state` (an old daemon predating this
    /// field) renders as "unknown", never silently as healthy — a stale
    /// or misleading status is exactly the risk to avoid here.
    #[test]
    fn empty_state_renders_unknown_not_healthy() {
        assert_eq!(headline(&base_status()), "YadoriLink: unknown");
    }

    #[test]
    fn reason_lines_pass_through_attention_reasons_unmodified() {
        let mut status = base_status();
        status.attention_reasons = vec!["conflict:group-1".into(), "low_disk:/data".into()];
        assert_eq!(reason_lines(&status), vec!["conflict:group-1", "low_disk:/data"]);
    }

    #[test]
    fn folder_label_uses_the_last_path_segment() {
        assert_eq!(folder_menu_label(&base_link()), "Photos");
    }

    #[test]
    fn paused_folder_label_shows_paused_suffix() {
        let mut link = base_link();
        link.paused = true;
        assert_eq!(folder_menu_label(&link), "Photos  (paused)");
    }

    #[test]
    fn degraded_folder_label_shows_degraded_suffix() {
        let mut link = base_link();
        link.degraded = true;
        assert_eq!(folder_menu_label(&link), "Photos  (degraded)");
    }

    #[test]
    fn conflicted_folder_label_shows_conflict_count() {
        let mut link = base_link();
        link.conflict_count = 2;
        assert_eq!(folder_menu_label(&link), "Photos  (2 conflicts)");
    }

    #[test]
    fn single_conflict_uses_singular_noun() {
        let mut link = base_link();
        link.conflict_count = 1;
        assert_eq!(folder_menu_label(&link), "Photos  (1 conflict)");
    }

    #[test]
    fn syncing_folder_with_no_other_condition_shows_syncing_suffix() {
        let mut link = base_link();
        link.has_active_transfer = true;
        assert_eq!(folder_menu_label(&link), "Photos  (syncing…)");
    }

    #[test]
    fn healthy_idle_folder_shows_no_suffix() {
        assert_eq!(folder_menu_label(&base_link()), "Photos");
    }

    /// Precedence: paused takes priority over degraded/conflict/transfer
    /// suffixes — a paused link's other transient conditions aren't worth
    /// showing since the user already knows sync is off for it.
    #[test]
    fn paused_takes_precedence_over_other_conditions() {
        let mut link = base_link();
        link.paused = true;
        link.degraded = true;
        link.conflict_count = 3;
        assert_eq!(folder_menu_label(&link), "Photos  (paused)");
    }
}
