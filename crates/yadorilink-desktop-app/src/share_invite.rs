//! Pure, GUI-free logic behind the share window: which roles and expiries
//! it may offer, what a minted invite's expiry reads as, the `mailto:` URL
//! its email button opens, and the QR module grid its bitmap is painted
//! from. Kept entirely free of `egui` for the same reason
//! `status_model.rs`/`folder_detail.rs` are free of `tray_icon`/`egui`:
//! every decision made here is then unit-testable without a display.
//!
//! The invite payload itself is deliberately NOT built here --
//! `yadorilink_cli::commands::share::invite_url` is the single
//! implementation of the `yadorilink://invite/<code>` shape that
//! `share accept` parses, and a second formatter in this crate is exactly
//! how the two halves would drift apart.

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use yadorilink_ipc_proto::daemonctl::StatusResponse;

/// The role a recipient gets when they accept an invite.
///
/// Viewer and Editor only. Owner is a management-plane role: re-inviting,
/// revoking other members and transferring ownership have no
/// management-authority model behind them yet, and the coordination plane
/// rejects `owner` on the invite route accordingly. This picker therefore
/// has no Owner option to choose at all, rather than offering one that
/// fails at mint time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InviteRole {
    /// The default: least privilege for a stranger-facing invite, the same
    /// role the coordination plane applies to an invite minted with no
    /// role at all.
    #[default]
    Viewer,
    Editor,
}

impl InviteRole {
    /// Every role this window offers, in the order it presents them --
    /// least privilege first, matching the coordination plane's own
    /// omitted-role default for a cross-account invite.
    pub const ALL: [InviteRole; 2] = [InviteRole::Viewer, InviteRole::Editor];

    pub fn label(self) -> &'static str {
        match self {
            InviteRole::Viewer => "Viewer",
            InviteRole::Editor => "Editor",
        }
    }

    /// One line describing what the role actually permits, in terms of what
    /// the daemon-side verifier enforces (whether the recipient's own
    /// changes are accepted), not in terms of UI affordances.
    pub fn description(self) -> &'static str {
        match self {
            InviteRole::Viewer => "Can see this folder's files. Their changes are not accepted.",
            InviteRole::Editor => "Can see this folder's files and make changes to them.",
        }
    }

    /// The wire value the coordination plane recognizes. Sent explicitly
    /// rather than omitted: this window always has a role selected, so
    /// there is never a reason to fall back to the plane's own default and
    /// end up with a grant the picker did not show.
    pub fn wire_value(self) -> &'static str {
        match self {
            InviteRole::Viewer => "viewer",
            InviteRole::Editor => "editor",
        }
    }
}

/// The invite form's approval checkbox, as a constant rather than a string
/// literal at its one call site: the requests panel's empty state points at
/// this exact control by name, and a checkbox whose label has drifted away
/// from the thing pointing at it sends someone looking for a control that
/// no longer reads that way.
pub const REQUIRE_APPROVAL_LABEL: &str = "Require my approval before they get access";

/// A role the coordination plane reported back, labelled the way this
/// window's own picker labels it, so what a minted invite says it granted
/// reads the same as what was asked for.
///
/// An unrecognized value -- a role a newer coordination plane knows about
/// and this build does not -- passes through verbatim rather than being
/// guessed at or dropped. Same positive-match discipline the CLI applies
/// to a role it does not recognize: render it, never reinterpret it.
pub fn role_display_label(wire_value: &str) -> String {
    InviteRole::ALL
        .into_iter()
        .find(|role| role.wire_value() == wire_value)
        .map(|role| role.label().to_string())
        .unwrap_or_else(|| wire_value.to_string())
}

/// How long a minted invite stays redeemable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExpiryPreset {
    OneHour,
    OneDay,
    /// The default, matching the coordination plane's own default for an
    /// invite minted with no TTL.
    #[default]
    SevenDays,
}

impl ExpiryPreset {
    pub const ALL: [ExpiryPreset; 3] =
        [ExpiryPreset::OneHour, ExpiryPreset::OneDay, ExpiryPreset::SevenDays];

    pub fn label(self) -> &'static str {
        match self {
            ExpiryPreset::OneHour => "1 hour",
            ExpiryPreset::OneDay => "1 day",
            ExpiryPreset::SevenDays => "7 days",
        }
    }

    /// The TTL to request, in seconds.
    ///
    /// Always an explicit value, including for the 7-day preset, which
    /// happens to match the coordination plane's own default for an
    /// omitted TTL: a label that says "7 days" should ask for 7 days
    /// rather than for whatever the plane's default currently is. The
    /// window then displays the expiry the plane actually recorded, so a
    /// plane that clamps the request is still reported truthfully.
    pub fn ttl_secs(self) -> Option<u64> {
        match self {
            ExpiryPreset::OneHour => Some(3_600),
            ExpiryPreset::OneDay => Some(86_400),
            ExpiryPreset::SevenDays => Some(7 * 86_400),
        }
    }
}

/// A relative expiry ("in about 7 days") for a minted invite, from the
/// coordination plane's own `expires_at_unix`. `now_unix` is a parameter
/// rather than a clock read so the bucketing is testable.
///
/// Coarse on purpose: this is a "roughly how long do I have to send this"
/// answer, and rounding down never overstates the remaining time.
pub fn expires_in_label(expires_at_unix: i64, now_unix: i64) -> String {
    let remaining = expires_at_unix - now_unix;
    if remaining <= 0 {
        return "already expired".to_string();
    }
    let remaining = remaining as u64;
    if remaining >= 86_400 {
        plural(remaining / 86_400, "day")
    } else if remaining >= 3_600 {
        plural(remaining / 3_600, "hour")
    } else {
        // Under a minute still reads as "in about 1 minute" rather than
        // "in about 0 minutes", which would look like an already-dead link.
        plural((remaining / 60).max(1), "minute")
    }
}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("in about 1 {unit}")
    } else {
        format!("in about {count} {unit}s")
    }
}

/// Everything except the RFC 3986 unreserved characters is percent-encoded
/// in a `mailto:` header value. Notably this encodes a space as `%20`
/// rather than `+`: a `mailto:` query is not an HTML form submission, and
/// mail clients that take `+` literally would otherwise put plus signs
/// through the whole message body.
const MAILTO_VALUE: &AsciiSet =
    &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// A `mailto:` URL with the invite pre-written into the subject and body,
/// for the window's "Send by email" button (opened with the same
/// `opener::open` this crate already uses for every other hand-off to the
/// OS). No recipient address is filled in -- the user picks that in their
/// own mail client, and this app never asks for or stores one.
pub fn mailto_url(invite_url: &str, folder_name: &str) -> String {
    let subject = format!("Shared folder: {folder_name}");
    let body = format!(
        "I'd like to share the folder \"{folder_name}\" with you.\n\nOpen this link to \
         accept:\n{invite_url}\n\nThe link works once, for one device."
    );
    format!(
        "mailto:?subject={}&body={}",
        utf8_percent_encode(&subject, MAILTO_VALUE),
        utf8_percent_encode(&body, MAILTO_VALUE),
    )
}

/// A QR code's modules as a square grid, row-major, `true` for a dark
/// module. Painting it is the window's job; deciding what the grid IS is
/// this module's, so the encoding step is exercised without a display.
pub struct QrModules {
    pub width: usize,
    pub dark: Vec<bool>,
}

impl QrModules {
    /// Whether the module at `(x, y)` is dark; anything outside the grid
    /// reads as light.
    ///
    /// `x` is bounds-checked against the row width explicitly, not just
    /// through the flat index: `y * width + x` with an over-wide `x` lands
    /// on a real element of the NEXT row, so an off-by-one caller would
    /// silently read a neighbouring module instead of falling off the end.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        if x >= self.width {
            return false;
        }
        self.dark.get(y * self.width + x).copied().unwrap_or(false)
    }
}

/// Encodes `payload` as a QR code's module grid, or `None` if it does not
/// fit in any QR version. A `None` is not fatal to sharing: the invite URL
/// itself is shown and copyable regardless, exactly as the CLI keeps
/// printing the code and URL when its own terminal QR render fails.
///
/// Uses `qrcode`'s core module matrix (`to_colors`/`width`) rather than its
/// `image`/`svg` renderers -- those are default features this workspace
/// deliberately turns off, and a GPU-bound `egui` texture wants a raw
/// bitmap anyway, not an encoded image file.
pub fn qr_modules(payload: &str) -> Option<QrModules> {
    let code = qrcode::QrCode::new(payload).ok()?;
    let width = code.width();
    let dark = code.to_colors().into_iter().map(|c| c == qrcode::Color::Dark).collect();
    Some(QrModules { width, dark })
}

/// The folder group id the daemon reports for the folder linked at
/// `local_path`, or `None` when this snapshot has no link there (the
/// folder was unlinked, or no status has arrived yet -- the caller
/// distinguishes those two, this lookup cannot).
///
/// The group ID, not a name: `LinkStatus` carries `group_id`, and that is
/// exactly what minting an invite takes, so there is no name to resolve
/// and nothing to look up over the network.
pub fn group_id_for_path<'a>(status: &'a StatusResponse, local_path: &str) -> Option<&'a str> {
    status
        .links
        .iter()
        .find(|link| link.local_path == local_path)
        .map(|link| link.group_id.as_str())
}

#[cfg(test)]
mod tests {
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
}
