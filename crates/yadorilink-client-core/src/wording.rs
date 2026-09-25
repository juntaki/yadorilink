//! English sentences more than one front end shows verbatim.
//!
//! These are the texts where a paraphrase is itself a defect: a data-loss
//! warning worded more mildly in one place, an invite URL built a second way,
//! an approval reported as done when this build cannot confirm it was. Every
//! front end that shows one of these takes it from here. Anything only one
//! front end says stays in that front end.

use yadorilink_ipc_proto::daemonctl::ReplicaMembershipCommandOutcome;

use crate::ops::shares::GroupMemberInfo;

/// The local-first boundary every account-deletion surface must state:
/// deletion removes server-side records and access; local folders remain the
/// user's own data on their machines.
pub const LOCAL_FIRST_NOTICE: &str = "Account deletion removes your server-side coordination records \
(account, devices, folder groups, shares) and revokes every device's coordination access. \
It does NOT delete the folders synced on your machines -- those remain your own local data on your own \
devices. Removing them, if you ever want to, is a separate manual step.";

/// The invite's plaintext code encoded as a `yadorilink://invite/<code>`
/// URI -- a structured payload for the QR/URL (rather than the bare code)
/// that a scan-to-accept flow can parse unambiguously, while a human can
/// still read/type just the code portion after the last `/`.
///
/// Every surface that shows an invite builds it here: accepting an invite
/// (`ops::shares::extract_invite_code`) is defined against exactly this
/// shape, so a second, independently written formatter is a way for the two
/// halves to drift apart.
#[must_use]
pub fn invite_url(code: &str) -> String {
    format!("yadorilink://invite/{code}")
}

/// What an approval reports for each result the coordination plane can
/// return, matched POSITIVELY on every recognized value.
///
/// An unrecognized value is a build talking to a newer coordination plane,
/// and defaulting it to "Approved" would claim an outcome this build cannot
/// actually confirm happened. The call did return 2xx, so something
/// succeeded; say exactly that, and name the value so it can be looked up.
#[must_use]
pub fn approve_result_line(result: &str, device_id: &str, group_name: &str) -> String {
    match result {
        "approved" => format!("Approved {device_id} for {group_name}"),
        "already_active" => {
            format!("{device_id} already had access to {group_name}; nothing to approve")
        }
        other => format!(
            "The approval request for {device_id} in {group_name} was accepted, with an \
             outcome this version does not recognize ({other:?}); check `yadorilink share \
             list` for the current state"
        ),
    }
}

/// The empty-state line for "nobody is waiting on you", naming how a request
/// gets here in the first place.
pub const NO_PENDING_APPROVALS: &str =
    "No one is waiting for your approval. Requests appear here after someone redeems an \
     invite you minted with `yadorilink share invite <group> --require-approval`.";

/// The coordination plane's raw share-edge `state` rendered for a person.
///
/// The one state that means "waiting on a human" has to say so in words
/// rather than as an internal enum spelling. Every other value passes through
/// verbatim -- including one this build does not recognize, which must still
/// render.
#[must_use]
pub fn state_label(state: &str) -> &str {
    match state {
        crate::ops::shares::STATE_PENDING_APPROVAL => "awaiting the owner's approval",
        other => other,
    }
}

/// How one member relates to whoever is looking at the listing.
/// `own_device_id` is this device's own id, when known -- used only to label
/// the caller's own EXACT device as "you".
///
/// Deliberately computed from TWO different booleans, not one:
/// `is_same_account` is owner-relative ("is this member on the group owner's
/// account") while `is_caller_account` is caller-relative ("is this member on
/// the account making the request"). For the group owner these coincide, but
/// for a non-owner caller they do not; branching on `is_caller_account` first
/// is what keeps an invited account's labels from being inverted.
#[must_use]
pub fn member_relationship_label(
    member: &GroupMemberInfo,
    own_device_id: Option<&str>,
) -> &'static str {
    if own_device_id == Some(member.device_id.as_str()) {
        "you"
    } else if member.is_caller_account {
        "your other device"
    } else if member.is_same_account {
        "owner's device"
    } else {
        "invited"
    }
}

/// Whether this member keeps a full local copy of the group or fetches files
/// on demand, worded for a person.
///
/// A positive match on the one mode that means "full copy": an unrecognized
/// future storage mode reads as on-demand, which understates rather than
/// overstates what is durably held.
#[must_use]
pub fn member_storage_label(member: &GroupMemberInfo) -> &'static str {
    if member.storage_mode == "eager" {
        "full copy"
    } else {
        "on-demand"
    }
}

/// The device id shown alongside a device's name -- the leading 8
/// characters, enough to tell two devices apart without filling a line with
/// an opaque identifier.
#[must_use]
pub fn short_device_id(device_id: &str) -> String {
    device_id.chars().take(8).collect()
}

/// The informational lines a membership outcome carries: one per completed
/// durability handoff. Not warnings -- these report work that succeeded.
#[must_use]
pub fn membership_outcome_notices(outcome: &ReplicaMembershipCommandOutcome) -> Vec<String> {
    outcome
        .handoffs
        .iter()
        .map(|handoff| {
            format!(
                "handoff completed: group={} target={} generation={} lease={}",
                handoff.group_id,
                handoff.target_device_id,
                handoff.membership_generation,
                handoff.lease_id,
            )
        })
        .collect()
}

/// The warnings a membership outcome carries: a forced operation's data-loss
/// warning, and the harder one for an operation forced before its affected
/// folder groups could even be determined. Empty for an ordinary, non-forced
/// outcome -- which is the common case, and must stay silent.
///
/// `action` names the operation in the text ("remove", "revoke"), since the
/// same outcome shape is produced by several operations.
#[must_use]
pub fn membership_outcome_warnings(
    action: &str,
    outcome: &ReplicaMembershipCommandOutcome,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !outcome.forced_group_ids.is_empty() {
        warnings.push(format!(
            "warning: forced {action} without confirmed durability for: {}. This may \
             permanently lose data.",
            outcome.forced_group_ids.join(", ")
        ));
    }
    if !outcome.unknown_scope_operation_id.is_empty() {
        warnings.push(format!(
            "warning: {action} was forced before the affected folder groups could be \
             determined. The possible data-loss scope is unknown.\n\
             Recovery operation: {}\n\
             Sync status will remain degraded until reconciliation completes.",
            outcome.unknown_scope_operation_id
        ));
    }
    warnings
}

/// The device-code sign-in instructions: the bare verification URI and the
/// code, separately. Never the URI with the code already in it, which would
/// put a live credential in a browser address bar and its history.
///
/// The same text `yadorilink_fapi_client::DeviceAuthorization::instructions`
/// produces for the same two values.
#[must_use]
pub fn device_code_instructions(verification_uri: &str, user_code: &str) -> String {
    format!(
        "To finish signing in, open {verification_uri} on any device and enter this code:\n\n    \
         {user_code}\n"
    )
}

/// What a front end writing to a terminal (or a log) prints for each
/// sign-in progress event, one `String` per printed line, in order. Events
/// that print nothing return no lines.
#[must_use]
pub fn login_event_lines(event: &crate::ops::auth::LoginEvent) -> Vec<String> {
    use crate::ops::auth::{BrowserPurpose, LoginEvent};
    match event {
        LoginEvent::Enrolling | LoginEvent::WaitingForAuthorization => Vec::new(),
        LoginEvent::OpenBrowser { url, purpose: BrowserPurpose::ApproveDevice } => vec![
            "To add this computer to your YadoriLink account, open:\n".to_owned(),
            format!("    {url}\n"),
        ],
        LoginEvent::WaitingForApproval { expires_in } => vec![format!(
            "Waiting for approval (this link is valid for {} minutes)...",
            expires_in.as_secs() / 60
        )],
        LoginEvent::OpenBrowser { url, purpose: BrowserPurpose::SignIn } => {
            vec!["\nNow sign in to finish:\n".to_owned(), format!("    {url}\n")]
        }
        LoginEvent::ShowDeviceCode { verification_uri, user_code } => {
            vec![format!("\n{}", device_code_instructions(verification_uri, user_code))]
        }
        LoginEvent::SignedIn { client_id } => {
            vec![format!("Logged in. This computer is enrolled as {client_id}.")]
        }
    }
}

/// What a completed sign-out reports.
#[must_use]
pub fn sign_out_line(kind: &crate::ops::auth::SignOutKind) -> String {
    use crate::ops::auth::SignOutKind;
    match kind {
        SignOutKind::Revoked { grants_revoked } => format!(
            "Signed out. This computer's access was revoked ({grants_revoked} grant(s)) and its \
             credentials were removed."
        ),
        SignOutKind::AlreadyRevoked => "Signed out. This computer's access had already been \
                                        revoked; its credentials were removed."
            .to_owned(),
        SignOutKind::ConfirmedRevokedAfterRejection => {
            "Signed out. This computer's access was no longer valid, and the Authorization \
             Server independently confirmed the registration is revoked; its credentials were \
             removed."
                .to_owned()
        }
    }
}

#[cfg(test)]
mod tests;
