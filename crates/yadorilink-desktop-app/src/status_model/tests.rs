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
