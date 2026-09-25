//! Pure, GUI-free logic behind the share window's access panel: who the
//! "People with access" rows describe, which requests are waiting on a
//! decision for THIS folder, which role a picker may move a member to,
//! whether a Deny is still the thing its button claims it is, and the
//! wording of the two confirmations a removal has to pass through.
//! Sibling to `share_invite.rs`, kept free of `egui` for the same reason:
//! every decision made here is then unit-testable without a display.
//!
//! Three labels are deliberately NOT re-derived here. The caller-relative
//! relationship ("you" / "your other device" / "owner's device" /
//! "invited"), the storage-mode wording, and the shortened device id all
//! come from `yadorilink_client_core::wording`, which is the single
//! implementation `yadorilink share members` renders with too. The
//! relationship label in particular is where an owner/caller inversion once
//! shipped, from exactly this logic being re-derived on a second surface
//! rather than reused -- calling the shared function is what makes that
//! impossible here rather than merely unlikely.

use yadorilink_client_core::ops::shares::{GroupMemberInfo, PendingApproval};
use yadorilink_client_core::wording::{
    member_relationship_label, member_storage_label, short_device_id,
};

use crate::share_invite::{role_display_label, InviteRole};

/// Shown when the coordination plane reports nobody at all in the group --
/// which is a genuinely empty listing, never a failed or unfinished read
/// (the caller distinguishes those, this string does not). Says the same
/// thing `yadorilink share members` says for the same answer.
pub const NO_MEMBERS: &str = "No one has access to this folder.";

/// Shown in place of the management controls for an account that does not
/// own this folder group. The member listing itself is visible to any
/// member account, but every mutation below it is the owner's alone, so
/// showing the controls to someone whose every click would be refused is
/// worse than not showing them.
pub const ONLY_THE_OWNER_CAN_MANAGE_ACCESS: &str =
    "Only the account that owns this folder can change who has access to it.";

/// The requests panel's heading, as a constant rather than a literal at its
/// one call site: the minted-invite panel above it tells the person minting
/// an approval-gated link to look for the request under this exact heading,
/// and a heading that has drifted away from the thing pointing at it sends
/// someone looking for a section that no longer reads that way.
pub const PENDING_REQUESTS_HEADING: &str = "Waiting for your approval";

/// The member list's heading, a constant for the same reason
/// [`PENDING_REQUESTS_HEADING`] is: the line shown when a Deny is stopped
/// because the device is already a member names this section as where to
/// find the removal control instead, and a heading that has drifted away
/// from the sentence pointing at it sends someone looking for a section
/// that no longer reads that way.
pub const MEMBERS_HEADING: &str = "People with access";

/// What the minted-invite panel says about an approval-gated link, pointing
/// at the requests panel in this same window rather than at a command line.
pub fn approval_gated_invite_note() -> String {
    format!(
        "The recipient will not get access until you approve them. Their request appears under \
         \"{PENDING_REQUESTS_HEADING}\" below once they redeem this link."
    )
}

/// The banner shown when the access listing could not be read.
///
/// `showing_last_known` decides which of two genuinely different things is
/// said. With no listing at all there is nothing below the banner, so it
/// only reports the failure; with a previous listing still on screen it
/// must also say that every row below it is a last-known snapshot rather
/// than a live answer -- the same rule `folder_status_window.rs` applies to
/// its own stale fields, and for the same reason: a failed read must never
/// render identically to a fresh one.
pub fn access_unreadable_banner(showing_last_known: bool) -> &'static str {
    if showing_last_known {
        "Can't read who has access right now — the list below is what was last seen, not a \
         confirmation of who has access now."
    } else {
        "Can't read who has access right now."
    }
}

/// The requests panel's empty state.
///
/// Carries the same two facts as `yadorilink share pending`'s own empty
/// line -- nobody is waiting, and a request appears once somebody redeems
/// an approval-gated invite -- but points at the checkbox in THIS window
/// rather than at the command-line flag that sets the same bit. Somebody
/// reading this has that checkbox a few lines above them; sending them to a
/// terminal instead would be the less helpful half of "the same helpful
/// thing".
///
/// Built from the checkbox's own label rather than repeating its words, so
/// the two cannot drift apart.
pub fn no_pending_requests_line() -> String {
    format!(
        "No one is waiting for your approval. A request appears here after someone redeems an \
         invite link you created with \"{}\" turned on.",
        crate::share_invite::REQUIRE_APPROVAL_LABEL
    )
}

/// The role a member's current wire value maps to in the change-role
/// picker, or `None` when it is not a role this app can assign.
///
/// `None` covers two real cases: the `"unknown"` sentinel the coordination
/// plane reports for an ACL entry with no matching grant record, and a role
/// a newer coordination plane knows about that this build does not --
/// including `owner`, which a group may still carry from data written
/// before the invite/grant routes were narrowed. Every one of those is
/// DISPLAYED verbatim (see `MemberRow::role_label`) and none of them
/// preselects anything in the picker: a picker that silently landed on
/// Viewer for an unrecognized role would misreport what the member holds
/// today, and one that offered Owner as a value would offer a role this app
/// has no authority model for.
pub fn assignable_role(wire_value: &str) -> Option<InviteRole> {
    InviteRole::ALL.into_iter().find(|role| role.wire_value() == wire_value)
}

/// One row of the "People with access" list.
pub struct MemberRow {
    pub device_name: String,
    /// The full device id -- what a removal confirmation names, and what
    /// every mutating call is addressed to.
    pub device_id: String,
    /// The shortened id shown beside the device name, matching what
    /// `yadorilink share members` prints.
    pub short_device_id: String,
    /// The role the coordination plane reported, labelled the way this
    /// window's own picker labels it. An unrecognized value passes through
    /// verbatim rather than being guessed at or blanked.
    pub role_label: String,
    /// That role's raw wire value, kept so the picker can tell "already this
    /// role" from "a role this build does not know".
    pub role: String,
    pub relationship: &'static str,
    pub presence: &'static str,
    pub storage: &'static str,
    /// Whether this row IS the device the window is running on.
    pub is_own_device: bool,
}

impl MemberRow {
    /// The one-line summary shown under a member's name: everything
    /// `yadorilink share members` prints for the member except the name and
    /// id already shown above it.
    pub fn detail_line(&self) -> String {
        format!(
            "{}  ·  {}  ·  {}  ·  {}",
            self.role_label, self.relationship, self.presence, self.storage
        )
    }

    /// Whether this window offers role changes and removal for this row.
    ///
    /// Never for the device the window is running on. Removing this device's
    /// own access to the folder it is currently syncing is the unlink flow,
    /// which has its own guarded affordance in the tray, and a role change
    /// applied to yourself from the window you are managing the folder in is
    /// a way to lock yourself out of it by accident.
    pub fn is_manageable(&self) -> bool {
        !self.is_own_device
    }

    /// Whether moving this member to `role` would change anything. The
    /// coordination plane treats a request naming the member's current role
    /// as a no-op success, so this is a UI affordance rather than a safety
    /// check -- a button that claims it will do something should do it.
    pub fn would_change_role_to(&self, role: InviteRole) -> bool {
        self.role != role.wire_value()
    }
}

/// Builds the "People with access" rows from the coordination plane's own
/// listing, in the order it returned them.
///
/// `own_device_id` is this machine's device id when it has one; `None`
/// simply means no row is ever labelled "you", exactly as on the command
/// line.
pub fn member_rows(members: &[GroupMemberInfo], own_device_id: Option<&str>) -> Vec<MemberRow> {
    members
        .iter()
        .map(|member| MemberRow {
            device_name: member.device_name.clone(),
            device_id: member.device_id.clone(),
            short_device_id: short_device_id(&member.device_id),
            role_label: role_display_label(&member.role),
            role: member.role.clone(),
            relationship: member_relationship_label(member, own_device_id),
            presence: if member.online { "online" } else { "offline" },
            storage: member_storage_label(member),
            is_own_device: own_device_id == Some(member.device_id.as_str()),
        })
        .collect()
}

/// One request waiting for this folder's owner to decide.
pub struct PendingRow {
    pub device_id: String,
    pub short_device_id: String,
    /// The folder group this request belongs to -- needed to act on it
    /// (`approve_resolved`/`try_revoke_resolved` both take a group id), not
    /// just to display it. Carried on every row rather than only where a
    /// caller happens to already know it, so a cross-folder listing (the
    /// account window's own "waiting for your approval" section, unfiltered
    /// across every owned group) can act on a row without a second lookup.
    pub group_id: String,
    /// The folder group's own name, carried so the outcome of a decision is
    /// worded by the same function the command line words it with, which
    /// names the group.
    pub group_name: String,
    /// The role the invite this device redeemed asked for, labelled like the
    /// picker. `"unknown"` when the coordination plane reported none --
    /// deciding without knowing the role is deciding blind, so the absence
    /// is stated rather than hidden.
    pub requested_role_label: String,
}

fn to_pending_row(request: &PendingApproval) -> PendingRow {
    PendingRow {
        device_id: request.device_id.clone(),
        short_device_id: short_device_id(&request.device_id),
        group_id: request.group_id.clone(),
        group_name: request.group_name.clone(),
        requested_role_label: request
            .role
            .as_deref()
            .map(role_display_label)
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

/// The subset of this account's waiting requests that belong to the folder
/// group this window was opened for.
///
/// Narrowed by group id, not by name: the window resolves its folder to a
/// group id off the daemon's own link status, and two accounts may well
/// have folder groups with the same name. The account-wide listing this
/// filters is already limited to requests this account genuinely has to
/// decide on -- see `pending_approvals` on the command-line side.
pub fn pending_rows(requests: &[PendingApproval], group_id: &str) -> Vec<PendingRow> {
    requests.iter().filter(|request| request.group_id == group_id).map(to_pending_row).collect()
}

/// Every request this account has to decide on, across every folder group it
/// owns -- the same listing `pending_rows` narrows to one folder, left
/// unfiltered for a cross-folder view (the account window's own
/// "Waiting for your approval" section) that has no single folder to narrow
/// to. Built from the identical per-row mapping so the two views can never
/// describe the same request differently.
pub fn all_pending_rows(requests: &[PendingApproval]) -> Vec<PendingRow> {
    requests.iter().map(to_pending_row).collect()
}

/// What a FRESH read of this folder's access state says about the request a
/// Deny was just clicked for.
///
/// The requests panel is read when the window opens and after this window's
/// own actions, never on a timer, so a row can still name a request that was
/// decided somewhere else -- from another device, or another session --
/// minutes ago. For every other control in the panel that is harmless. For
/// this one it is not: denying IS revoking (see `share_window`'s
/// `Action::Deny`), so a Deny aimed at a request that has since been
/// APPROVED would not turn a request down, it would remove a member whose
/// access is live and working, and report it as a request being turned down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyPrecheck {
    /// Still waiting on a decision. Denying turns it down, which is exactly
    /// what the button says it does.
    StillWaiting,
    /// Not waiting any more, so the denial must not be sent at all.
    NotWaiting(DenyRefusal),
}

/// Why a Deny was not carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyRefusal {
    /// The request was approved already and this device now holds live
    /// access to the folder. Taking that away is a removal, and a removal
    /// belongs in the member list, behind the confirmation that names it as
    /// one.
    AlreadyAdmitted,
    /// Neither waiting nor a member. All this listing establishes is that
    /// the request is gone; it cannot say which of the several causes did
    /// it -- turned down or approved-then-removed elsewhere, withdrawn by
    /// the requester, or swept by the coordination plane when the invite it
    /// came from expired. Either way there is nothing left to decide, and
    /// the message this maps to names the possibilities rather than picking
    /// one it cannot actually observe.
    NoLongerListed,
}

/// Re-decides, from listings read immediately before the mutation would be
/// sent, whether a Deny is still the thing the button claims it is.
///
/// `members` is already scoped to this folder group (it is the group's own
/// member listing); `pending` is account-wide, so it is narrowed by group id
/// here for the same reason `pending_rows` narrows it.
///
/// Membership is checked FIRST and wins outright. The two listings come from
/// two separate reads, so a request approved in between them can appear in
/// both, and the safe reading of "this is a live member" is the one that
/// stops the removal rather than the one that sends it.
pub fn deny_precheck(
    pending: &[PendingApproval],
    members: &[GroupMemberInfo],
    group_id: &str,
    device_id: &str,
) -> DenyPrecheck {
    if members.iter().any(|member| member.device_id == device_id) {
        return DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted);
    }
    let still_waiting = pending
        .iter()
        .any(|request| request.group_id == group_id && request.device_id == device_id);
    if still_waiting {
        DenyPrecheck::StillWaiting
    } else {
        DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
    }
}

/// How a member is named in a confirmation and in an outcome message: the
/// device name plus its full id, never the shortened one. A confirmation is
/// where a mistake becomes irreversible, so it names the exact device
/// rather than a prefix two devices could share.
///
/// Derived once, when the button is pressed, and carried through the
/// confirmation and the background call with the action itself -- so the
/// device a confirmation names is the device that was clicked, even if the
/// listing behind it has been refreshed in the meantime.
pub fn confirmation_device_label(row: &MemberRow) -> String {
    format!("{} ({})", row.device_name, row.device_id)
}

/// The member row's removal button, as a constant rather than a literal at
/// its one call site: the line shown when a Deny is stopped because the
/// device is already a member points at this button by name, and a button
/// that has drifted away from the sentence pointing at it sends someone
/// looking for a control that no longer reads that way. Same reason
/// `PENDING_REQUESTS_HEADING` is a constant.
pub const REMOVE_ACCESS_BUTTON: &str = "Remove access…";

/// The first confirmation a removal passes through: what it does, and what
/// it does NOT do. Mirrors the tray's own folder-removal dialog, which
/// likewise names the destructive-sounding thing that does not actually
/// happen -- somebody who thinks "remove" might delete the other person's
/// files will hesitate over the right button for the wrong reason.
pub fn revoke_confirm_prompt(device_label: &str) -> String {
    format!(
        "Remove {device_label}'s access to this folder?\n\nThey stop syncing it. Files already \
         on their device are not deleted, and they receive no further updates."
    )
}

/// The second confirmation, reached only when the daemon refused the
/// removal because it would leave this folder without another
/// confirmed-ready complete copy.
///
/// Quotes the daemon's own refusal verbatim rather than summarizing it: the
/// refusal names which folder groups are not ready, and a summary would
/// drop exactly the detail that lets someone judge whether to override.
/// This is the only place in this window that offers the override, and it
/// is never reached for any other failure -- see `RevokeAttempt` on the
/// command-line side for why forcing past anything else would not help.
pub fn revoke_override_prompt(device_label: &str, refusal: &str) -> String {
    format!(
        "{device_label} could not be removed yet:\n\n{refusal}\n\nRemoving them anyway may \
         permanently lose the only complete copy of this folder's data. The override is recorded \
         in the daemon's audit log."
    )
}

/// The button that carries out the override. Worded so that reading only
/// the buttons still tells someone which one is the dangerous one.
pub const REVOKE_OVERRIDE_BUTTON: &str = "Remove anyway and accept the risk";

/// What the window reports once a role change has been accepted. Named from
/// the picker's own label rather than from anything the coordination plane
/// echoes back: that route answers `204 No Content`, so there is no
/// server-reported effective role to quote, exactly as on the command line.
pub fn role_change_done_line(device_label: &str, role: InviteRole) -> String {
    format!("{device_label} is now {}.", role.label())
}

/// What the window reports once a request has been turned down.
///
/// Says that the invite cannot be redeemed again, because that is the part
/// that is not obvious: denying is the same operation as removing access,
/// and it revokes the originating invite along with the request, which is
/// what stops the recipient simply replaying their acceptance.
pub fn deny_done_line(device_label: &str) -> String {
    format!("{device_label} was turned down. The invite they used cannot be redeemed again.")
}

/// What the window reports when a Deny was NOT carried out, because the
/// state it was clicked against had already changed (see `deny_precheck`).
///
/// Neither line may claim the request was turned down: nothing was. In the
/// `AlreadyAdmitted` case the thing the person actually wanted may still be
/// available to them, so the line names the control that does it -- and says
/// plainly that it is a different, destructive action, because that is the
/// whole reason this Deny was stopped rather than sent.
pub fn deny_not_carried_out_line(device_label: &str, refusal: DenyRefusal) -> String {
    match refusal {
        DenyRefusal::AlreadyAdmitted => format!(
            "{device_label} was already approved and now has access to this folder, so nothing \
             was changed. Removing someone who is already syncing is a different, destructive \
             action: use \"{REMOVE_ACCESS_BUTTON}\" beside them under \"{MEMBERS_HEADING}\"."
        ),
        // Says only what was observed: the request is absent from a fresh
        // listing. It can be gone because it was approved or turned down
        // elsewhere, because the requester withdrew it, or because the
        // coordination plane swept it when its originating invite expired --
        // this listing cannot tell those apart, so it does not pick one.
        DenyRefusal::NoLongerListed => format!(
            "{device_label} is no longer waiting for your approval — the request was resolved, \
             withdrawn, or expired elsewhere. Nothing was changed."
        ),
    }
}

/// What the window reports once a removal has committed.
pub fn revoke_done_line(device_label: &str) -> String {
    format!("{device_label} no longer has access to this folder.")
}

#[cfg(test)]
mod tests;
