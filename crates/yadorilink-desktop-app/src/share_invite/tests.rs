#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::LinkStatus;

/// The role picker offers Viewer and Editor and nothing else -- Owner
/// is a management-plane role with no authority model behind it, and
/// the coordination plane refuses it on this route.
#[test]
fn the_role_picker_offers_only_viewer_and_editor() {
    assert_eq!(InviteRole::ALL, [InviteRole::Viewer, InviteRole::Editor]);
    let wire: Vec<&str> = InviteRole::ALL.iter().map(|r| r.wire_value()).collect();
    assert_eq!(wire, vec!["viewer", "editor"]);
    assert!(!wire.contains(&"owner"));
    let labels: Vec<&str> = InviteRole::ALL.iter().map(|r| r.label()).collect();
    assert_eq!(labels, vec!["Viewer", "Editor"]);
    assert!(!labels.iter().any(|l| l.eq_ignore_ascii_case("owner")));
}

#[test]
fn the_default_role_is_the_least_privileged_one() {
    assert_eq!(InviteRole::default(), InviteRole::Viewer);
}

#[test]
fn every_role_describes_what_it_permits() {
    for role in InviteRole::ALL {
        assert!(!role.description().is_empty(), "{role:?} has no description");
    }
    assert!(InviteRole::Viewer.description().contains("not accepted"));
}

#[test]
fn a_reported_role_is_labelled_the_way_the_picker_labels_it() {
    assert_eq!(role_display_label("viewer"), "Viewer");
    assert_eq!(role_display_label("editor"), "Editor");
}

/// A role this build does not know renders verbatim -- never blank,
/// never silently relabelled as one of the two it does know.
#[test]
fn an_unrecognized_reported_role_renders_verbatim() {
    assert_eq!(role_display_label("owner"), "owner");
    assert_eq!(role_display_label("unknown"), "unknown");
    assert_eq!(role_display_label(""), "");
}

#[test]
fn expiry_presets_map_to_their_labelled_durations() {
    assert_eq!(ExpiryPreset::OneHour.ttl_secs(), Some(3_600));
    assert_eq!(ExpiryPreset::OneDay.ttl_secs(), Some(86_400));
    assert_eq!(ExpiryPreset::SevenDays.ttl_secs(), Some(604_800));
    assert_eq!(ExpiryPreset::default(), ExpiryPreset::SevenDays);
}

/// Each preset's label has to describe the TTL it actually requests --
/// a mismatch here is a window that tells the user one expiry and mints
/// another.
#[test]
fn every_expiry_preset_label_matches_the_ttl_it_requests() {
    for preset in ExpiryPreset::ALL {
        let secs = preset.ttl_secs().expect("every preset requests an explicit ttl");
        let expected = match preset.label() {
            "1 hour" => 3_600,
            "1 day" => 86_400,
            "7 days" => 7 * 86_400,
            other => panic!("unlabelled preset {other:?}"),
        };
        assert_eq!(secs, expected, "{preset:?} label and ttl disagree");
    }
}

#[test]
fn expiry_label_reports_a_past_expiry_as_already_expired() {
    assert_eq!(expires_in_label(1_000, 1_000), "already expired");
    assert_eq!(expires_in_label(999, 1_000), "already expired");
}

#[test]
fn expiry_label_picks_the_coarsest_unit_that_still_reads_as_at_least_one() {
    let now = 1_000_000;
    assert_eq!(expires_in_label(now + 7 * 86_400, now), "in about 7 days");
    assert_eq!(expires_in_label(now + 86_400 + 60, now), "in about 1 day");
    assert_eq!(expires_in_label(now + 5 * 3_600, now), "in about 5 hours");
    assert_eq!(expires_in_label(now + 3_600, now), "in about 1 hour");
    assert_eq!(expires_in_label(now + 150, now), "in about 2 minutes");
}

/// A nearly-expired link still reads as having some time left rather
/// than as "0 minutes", which would look indistinguishable from dead.
#[test]
fn expiry_label_never_rounds_a_live_invite_down_to_zero() {
    assert_eq!(expires_in_label(1_030, 1_000), "in about 1 minute");
}

/// The mailto body must be percent-encoded per RFC 3986, NOT
/// form-encoded: a `+` where a space belongs arrives literally in
/// several mail clients.
#[test]
fn mailto_url_percent_encodes_spaces_rather_than_form_encoding_them() {
    let url = mailto_url("yadorilink://invite/abc123", "Photos");
    assert!(url.starts_with("mailto:?subject="), "got: {url}");
    assert!(url.contains("%20"), "got: {url}");
    assert!(!url.contains('+'), "a mailto value must not be form-encoded: {url}");
}

#[test]
fn mailto_url_carries_the_invite_url_and_folder_name() {
    let url = mailto_url("yadorilink://invite/abc123", "Photos");
    // The invite URL survives encoding: its scheme separators are
    // escaped, and the code itself is unreserved so it appears as-is.
    assert!(url.contains("yadorilink%3A%2F%2Finvite%2Fabc123"), "got: {url}");
    assert!(url.contains("Photos"), "got: {url}");
    assert!(url.contains("&body="), "got: {url}");
}

/// A `&` or `=` in a folder name must not be able to split the mailto
/// URL into extra headers.
#[test]
fn mailto_url_escapes_a_folder_name_that_looks_like_query_syntax() {
    let url = mailto_url("yadorilink://invite/abc123", "R&D=notes");
    assert!(url.contains("R%26D%3Dnotes"), "got: {url}");
    // Exactly one `&`: the separator this function itself wrote.
    assert_eq!(url.matches('&').count(), 1, "got: {url}");
}

/// `utf8_percent_encode` percent-encodes every byte >= 0x80, so a
/// non-ASCII folder name (multi-byte UTF-8) must never appear literally
/// in the URL -- only its escaped bytes.
#[test]
fn mailto_url_percent_encodes_a_non_ascii_folder_name() {
    let url = mailto_url("yadorilink://invite/abc123", "写真");
    assert!(!url.contains('写') && !url.contains('真'), "got: {url}");
    assert!(url.contains("%E5%86%99%E7%9C%9F"), "got: {url}");
}

#[test]
fn qr_modules_form_a_square_grid_with_dark_and_light_modules() {
    let qr = qr_modules("yadorilink://invite/abc123").expect("a short URL always encodes");
    assert!(qr.width >= 21, "a QR code is at least 21 modules wide, got {}", qr.width);
    assert_eq!(qr.dark.len(), qr.width * qr.width);
    assert!(qr.dark.iter().any(|d| *d), "expected some dark modules");
    assert!(qr.dark.iter().any(|d| !*d), "expected some light modules");
    // The top-left finder pattern's own corner module is always dark.
    assert!(qr.is_dark(0, 0));
}

/// An out-of-range lookup reads as light rather than panicking -- and,
/// in particular, an over-wide `x` must not wrap around into the next
/// row's first module, which a flat `y * width + x` index alone does.
#[test]
fn qr_module_lookups_outside_the_grid_read_as_light_rather_than_wrapping() {
    let qr = QrModules { width: 2, dark: vec![false, false, true, false] };
    assert!(qr.is_dark(0, 1), "the fixture's second row starts dark");
    assert!(!qr.is_dark(2, 0), "x past the row width must not wrap into the next row");
    assert!(!qr.is_dark(0, 2));

    let real = qr_modules("yadorilink://invite/abc123").unwrap();
    assert!(!real.is_dark(real.width, 0));
    assert!(!real.is_dark(0, real.width));
}

fn status_with_links(links: &[(&str, &str)]) -> StatusResponse {
    StatusResponse {
        links: links
            .iter()
            .map(|(path, group)| LinkStatus {
                local_path: (*path).to_string(),
                group_id: (*group).to_string(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn group_id_lookup_finds_the_link_at_the_requested_path() {
    let status = status_with_links(&[("/a/Photos", "g-1"), ("/a/Docs", "g-2")]);
    assert_eq!(group_id_for_path(&status, "/a/Docs"), Some("g-2"));
}

#[test]
fn group_id_lookup_reports_none_for_a_path_that_is_no_longer_linked() {
    let status = status_with_links(&[("/a/Photos", "g-1")]);
    assert_eq!(group_id_for_path(&status, "/a/Docs"), None);
    assert_eq!(group_id_for_path(&StatusResponse::default(), "/a/Photos"), None);
}
