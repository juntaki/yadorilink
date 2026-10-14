#![cfg(test)]

use super::*;

fn base_status() -> StatusResponse {
    StatusResponse::default()
}

fn base_link() -> LinkStatus {
    LinkStatus { local_path: "/Users/alice/Photos".into(), ..Default::default() }
}

#[test]
fn folder_display_name_uses_the_last_path_segment() {
    assert_eq!(folder_display_name("/Users/alice/Photos"), "Photos");
}

#[test]
fn folder_display_name_falls_back_to_the_whole_path_when_it_has_no_segment() {
    assert_eq!(folder_display_name("/"), "/");
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

/// An empty/unrecognized `overall_state` an unset value
/// field) renders as "unknown", never silently as healthy — a stale
/// or misleading status is exactly the risk to avoid here.
#[test]
fn empty_state_renders_unknown_not_healthy() {
    assert_eq!(headline(&base_status()), "YadoriLink: unknown");
}

#[test]
fn reason_lines_hide_internal_codes() {
    let mut status = base_status();
    status.attention_reasons = vec!["conflict:group-1".into(), "low_disk:/data".into()];
    assert_eq!(reason_lines(&status), vec!["A file conflict needs review", "Disk space is low"]);
    assert_eq!(reason_sentence("durability_unknown:g1:x"), "Something needs attention");
}

#[test]
fn folder_label_uses_the_last_path_segment() {
    assert_eq!(folder_menu_label(&base_link()), "Photos");
}

#[test]
fn paused_folder_label_shows_paused_suffix() {
    let mut link = base_link();
    link.paused = true;
    assert_eq!(folder_menu_label(&link), "Photos  (paused by you)");
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
    link.conflict_count = 3;
    assert_eq!(folder_menu_label(&link), "Photos  (paused by you)");
}

/// A folder group linked at two folders syncs NOTHING until the user
/// unlinks one. The tray is where a desktop user would notice, so a label
/// that omitted it would leave the folder looking merely idle while it
/// silently stopped syncing.
#[test]
fn an_ambiguous_folder_is_labelled_as_not_syncing() {
    let link = LinkStatus { ambiguous: true, ..base_link() };

    let label = folder_menu_label(&link);

    assert!(label.contains("not syncing"), "got {label:?}");
}

/// Ambiguity outranks pause in the label chain. A paused-AND-ambiguous
/// folder that rendered as merely "(paused)" would hide the state the user
/// has to act on behind one they chose deliberately.
#[test]
fn ambiguity_outranks_pause_in_the_folder_label() {
    let link = LinkStatus { ambiguous: true, paused: true, ..base_link() };

    let label = folder_menu_label(&link);

    assert!(label.contains("not syncing"), "got {label:?}");
    assert!(!label.contains("(paused)"), "pause must not mask the refusal, got {label:?}");
}

#[test]
fn healthy_with_some_paused_folders_is_not_reported_as_synced() {
    let mut status = base_status();
    status.overall_state = "healthy".into();
    let mut paused = base_link();
    paused.paused = true;
    status.links = vec![paused.clone(), base_link(), paused.clone()];
    assert_eq!(headline(&status), "YadoriLink: 2 folders paused");
    status.links = vec![paused.clone()];
    assert_eq!(headline(&status), "YadoriLink: syncing is paused");
}

#[test]
fn paused_and_low_disk_label_gives_the_reason() {
    let mut link = base_link();
    link.paused = true;
    link.degraded = true;
    link.degraded_reason = "insufficient free space to write big.bin".into();
    assert_eq!(folder_menu_label(&link), "Photos  (paused; low disk space)");
    link.degraded_reason = "database error".into();
    assert_eq!(folder_menu_label(&link), "Photos  (paused; needs attention)");
}

#[test]
fn action_notice_success_and_failure_are_plain() {
    let ok = action_notice(TrayAction::PauseAll, Ok(()));
    assert_eq!((ok.text.as_str(), ok.is_error), ("Syncing paused", false));
    let err = action_notice(TrayAction::SignOut, Err("revoke failed: HTTP 500".into()));
    assert!(err.is_error);
    assert!(!err.text.contains("HTTP"));
    assert_eq!(err.details.as_deref(), Some("revoke failed: HTTP 500"));
    let down =
        action_notice(TrayAction::Unlink, Err("daemon is not running or not reachable".into()));
    assert_eq!(down.text, "Could not remove the folder because YadoriLink is not running");
}

#[test]
fn tray_state_maps_status_and_icons_differ() {
    assert_eq!(tray_state(None), TrayState::Attention);
    let mut s = base_status();
    s.overall_state = "healthy".into();
    s.links = vec![base_link()];
    assert_eq!(tray_state(Some(&s)), TrayState::Idle);
    s.links[0].has_active_transfer = true;
    assert_eq!(tray_state(Some(&s)), TrayState::Syncing);
    s.links[0].paused = true;
    assert_eq!(tray_state(Some(&s)), TrayState::Paused);
    s.overall_state = "attention".into();
    assert_eq!(tray_state(Some(&s)), TrayState::Attention);
    let all = [TrayState::Idle, TrayState::Syncing, TrayState::Paused, TrayState::Attention];
    for (i, a) in all.iter().enumerate() {
        assert_eq!(tray_icon_rgba(*a, 16).len(), 16 * 16 * 4);
        for b in &all[i + 1..] {
            assert_ne!(tray_icon_rgba(*a, 16), tray_icon_rgba(*b, 16));
        }
    }
}

#[test]
fn package_manager_update_guidance_is_a_message_not_an_error() {
    let page = update_download_notice(Ok(UpdateDownload::OpenedPage));
    assert_eq!((page.text.as_str(), page.is_error), ("Opened the download page", false));

    let guidance = "Update with your package manager: brew upgrade yadorilink";
    let shown = update_download_notice(Ok(UpdateDownload::Guidance(guidance.into())));
    assert_eq!((shown.text.as_str(), shown.is_error), (guidance, false));
    assert_eq!(shown.details, None);

    let failed = update_download_notice(Err("io error: no browser".into()));
    assert!(failed.is_error);
    assert_eq!(failed.text, "Could not open the download page");
}

#[test]
fn the_update_action_is_named_for_what_it_does() {
    assert_eq!(update_download_label("0.4.3", "standalone"), "Download Update (0.4.3)");
    assert_eq!(update_download_label("0.4.3", "homebrew"), "Show Update Steps (0.4.3)");
    assert_eq!(update_download_label("0.4.3", "winget"), "Show Update Steps (0.4.3)");
}
