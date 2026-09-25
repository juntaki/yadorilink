//! Pure, GUI-free logic behind the share window: which roles and expiries
//! it may offer, what a minted invite's expiry reads as, the `mailto:` URL
//! its email button opens, and the QR module grid its bitmap is painted
//! from. Kept entirely free of `egui` for the same reason
//! `status_model.rs`/`folder_detail.rs` are free of `tray_icon`/`egui`:
//! every decision made here is then unit-testable without a display.
//!
//! The invite payload itself is deliberately NOT built here --
//! `yadorilink_client_core::wording::invite_url` is the single
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
mod tests;
