#![cfg(test)]

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

fn reply(outcome: &str, guidance: &str, url: &str) -> UpdateInstallResponse {
    UpdateInstallResponse {
        outcome: outcome.into(),
        guidance: guidance.into(),
        download_url: url.into(),
    }
}

/// The desktop app refuses a reply that claims anything but a manual
/// download, exactly like the client core does.
#[test]
fn a_download_reply_that_is_not_manual_is_refused() {
    for outcome in ["installing", "deferred", "store_managed", "whatever", ""] {
        assert!(plan_update_download(&reply(outcome, "x", "")).is_err(), "{outcome}");
    }
}

#[test]
fn only_the_structured_official_page_is_opened() {
    let page = "https://github.com/juntaki/yadorilink/releases";
    assert_eq!(
        plan_update_download(&reply("manual_download", "Download from the page", page)).unwrap(),
        UpdatePlan::Open(page.to_owned())
    );
    // A link inside the sentence is display text: the steps are shown, nothing is opened.
    assert_eq!(
        plan_update_download(&reply(
            "manual_download",
            "Run `brew upgrade`, see https://evil.test",
            ""
        ))
        .unwrap(),
        UpdatePlan::Show("Run `brew upgrade`, see https://evil.test".to_owned())
    );
    assert!(plan_update_download(&reply("manual_download", "g", "https://evil.test/x")).is_err());
}
