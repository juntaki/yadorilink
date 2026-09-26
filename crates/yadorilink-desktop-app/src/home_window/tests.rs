#![cfg(test)]

use super::*;

#[test]
fn last_seen_label_reports_never_for_a_zero_or_negative_timestamp() {
    assert_eq!(last_seen_label(0), "never seen");
    assert_eq!(last_seen_label(-1), "never seen");
}

#[test]
fn last_seen_label_reports_a_relative_bucket() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(last_seen_label(now - 30), "30s ago");
    assert_eq!(last_seen_label(now - 120), "2m ago");
    assert_eq!(last_seen_label(now - 7200), "2h ago");
    assert_eq!(last_seen_label(now - 2 * 86400), "2d ago");
}

#[test]
fn last_seen_label_reports_just_now_for_a_very_recent_timestamp() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(last_seen_label(now), "just now");
}

#[test]
fn device_status_label_is_empty_for_an_online_device() {
    // An online device's server timestamp is the time it came online (or
    // 0 for this machine's own row before the server has marked it), so
    // rendering it as "Nd ago" / "never seen" would contradict the dot.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(device_status_label(true, now - 3 * 86400), None);
    assert_eq!(device_status_label(true, 0), None);
}

#[test]
fn device_status_label_shows_last_seen_for_an_offline_device() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(device_status_label(false, now - 7200).as_deref(), Some("2h ago"));
    assert_eq!(device_status_label(false, 0).as_deref(), Some("never seen"));
}

#[test]
fn data_protection_badge_shows_the_risk_wording() {
    use yadorilink_ipc_proto::daemonctl::{GroupDurabilityStatus, LinkStatus};

    let mut link = LinkStatus {
        durability_status: GroupDurabilityStatus::AtRisk as i32,
        ..Default::default()
    };
    assert_eq!(data_protection_badge(&link).text(), "Data protection: At risk");

    link.durability_status = GroupDurabilityStatus::Protected as i32;
    assert_eq!(data_protection_badge(&link).text(), "Data protection: Protected");
}

#[test]
fn mode_switch_message_reports_change_vs_already_in_mode() {
    let changed = yadorilink_client_core::ops::shares::StorageModeOutcome {
        changed: true,
        handoff_result: None,
    };
    assert_eq!(mode_switch_message("Photos", true, &changed), "Photos is now Selective.");
    let unchanged = yadorilink_client_core::ops::shares::StorageModeOutcome {
        changed: false,
        handoff_result: None,
    };
    assert_eq!(mode_switch_message("Photos", false, &unchanged), "Photos was already Synced.");
}
