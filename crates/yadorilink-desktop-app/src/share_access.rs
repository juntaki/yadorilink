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
//! come from `yadorilink_cli::commands::share`, which is the single
//! implementation `yadorilink share members` renders with too. The
//! relationship label in particular is where an owner/caller inversion once
//! shipped, from exactly this logic being re-derived on a second surface
//! rather than reused -- calling the CLI's function is what makes that
//! impossible here rather than merely unlikely.

use yadorilink_cli::commands::share::{
    member_relationship_label, member_storage_label, short_device_id, GroupMemberInfo,
    PendingApproval,
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

/// The subset of this account's waiting requests that belong to the folder
/// group this window was opened for.
///
/// Narrowed by group id, not by name: the window resolves its folder to a
/// group id off the daemon's own link status, and two accounts may well
/// have folder groups with the same name. The account-wide listing this
/// filters is already limited to requests this account genuinely has to
/// decide on -- see `pending_approvals` on the command-line side.
pub fn pending_rows(requests: &[PendingApproval], group_id: &str) -> Vec<PendingRow> {
    requests
        .iter()
        .filter(|request| request.group_id == group_id)
        .map(|request| PendingRow {
            device_id: request.device_id.clone(),
            short_device_id: short_device_id(&request.device_id),
            group_name: request.group_name.clone(),
            requested_role_label: request
                .role
                .as_deref()
                .map(role_display_label)
                .unwrap_or_else(|| "unknown".to_string()),
        })
        .collect()
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
mod tests {
    use super::*;

    fn member(device_id: &str) -> GroupMemberInfo {
        GroupMemberInfo {
            device_id: device_id.to_string(),
            device_name: "laptop".to_string(),
            role: "editor".to_string(),
            is_same_account: true,
            is_caller_account: true,
            storage_mode: "eager".to_string(),
            online: true,
            last_seen_unix: 1_700_000_000,
        }
    }

    fn row_for(member: &GroupMemberInfo, own_device_id: Option<&str>) -> MemberRow {
        member_rows(std::slice::from_ref(member), own_device_id).pop().unwrap()
    }

    /// Every field `yadorilink share members` prints has to survive into the
    /// window's own row -- role, the caller-relative relationship,
    /// online/offline and the storage mode. Dropping any one of them makes
    /// this panel a strictly worse answer to "who has access" than the
    /// command line's.
    #[test]
    fn a_member_row_carries_every_field_the_command_line_listing_shows() {
        let row = row_for(&member("0123456789abcdef"), Some("other-device"));
        assert_eq!(row.device_name, "laptop");
        assert_eq!(row.device_id, "0123456789abcdef");
        assert_eq!(row.short_device_id, "01234567");
        assert_eq!(row.role_label, "Editor");
        assert_eq!(row.relationship, "your other device");
        assert_eq!(row.presence, "online");
        assert_eq!(row.storage, "full copy");
        assert_eq!(row.detail_line(), "Editor  ·  your other device  ·  online  ·  full copy");
    }

    #[test]
    fn a_member_row_reports_an_offline_on_demand_device_as_such() {
        let mut m = member("dev-1");
        m.online = false;
        m.storage_mode = "on-demand".to_string();
        let row = row_for(&m, None);
        assert_eq!(row.presence, "offline");
        assert_eq!(row.storage, "on-demand");
    }

    /// The relationship label must be the CLI's answer, not a second
    /// opinion -- for all four cases, including the non-owner caller's view
    /// that an earlier version of this label got backwards.
    #[test]
    fn the_relationship_label_is_the_one_the_command_line_computes() {
        let caller = "caller-device";

        let mut own = member(caller);
        own.is_same_account = false;
        own.is_caller_account = true;
        assert_eq!(row_for(&own, Some(caller)).relationship, "you");

        let mut mine = member("other-device");
        mine.is_same_account = false;
        mine.is_caller_account = true;
        assert_eq!(row_for(&mine, Some(caller)).relationship, "your other device");

        let mut owners = member("owner-device");
        owners.is_same_account = true;
        owners.is_caller_account = false;
        assert_eq!(row_for(&owners, Some(caller)).relationship, "owner's device");

        let mut stranger = member("stranger-device");
        stranger.is_same_account = false;
        stranger.is_caller_account = false;
        assert_eq!(row_for(&stranger, Some(caller)).relationship, "invited");

        for m in [&own, &mine, &owners, &stranger] {
            assert_eq!(
                row_for(m, Some(caller)).relationship,
                member_relationship_label(m, Some(caller)),
                "the window must not re-derive this label"
            );
        }
    }

    /// A machine with no local device identity still renders every member,
    /// just without ever claiming one of them is "you".
    #[test]
    fn with_no_known_own_device_id_no_row_is_labelled_you() {
        let rows = member_rows(&[member("dev-1"), member("dev-2")], None);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.relationship != "you"));
        assert!(rows.iter().all(|row| !row.is_own_device));
    }

    /// This window never offers to change or remove its own device's access:
    /// removing it is the unlink flow, and changing its own role from the
    /// window that manages the folder is a way to lock yourself out.
    #[test]
    fn the_windows_own_device_is_never_offered_a_role_change_or_a_removal() {
        let rows = member_rows(&[member("dev-1"), member("dev-2")], Some("dev-1"));
        let own = rows.iter().find(|row| row.device_id == "dev-1").unwrap();
        assert!(own.is_own_device);
        assert!(!own.is_manageable());

        let other = rows.iter().find(|row| row.device_id == "dev-2").unwrap();
        assert!(!other.is_own_device);
        assert!(other.is_manageable());
    }

    /// The picker offers Viewer and Editor and nothing else, for every
    /// member -- including one whose CURRENT role is something this build
    /// does not assign. Owner must never appear as a value to choose.
    #[test]
    fn the_role_picker_offers_only_viewer_and_editor() {
        assert_eq!(InviteRole::ALL, [InviteRole::Viewer, InviteRole::Editor]);
        let offered: Vec<&str> = InviteRole::ALL.iter().map(|role| role.wire_value()).collect();
        assert_eq!(offered, vec!["viewer", "editor"]);
        assert!(!offered.contains(&"owner"));
    }

    #[test]
    fn a_recognized_current_role_preselects_itself_in_the_picker() {
        assert_eq!(assignable_role("viewer"), Some(InviteRole::Viewer));
        assert_eq!(assignable_role("editor"), Some(InviteRole::Editor));
    }

    /// A current role this app cannot assign -- `owner` from older data, the
    /// `"unknown"` integrity sentinel, or a role a newer coordination plane
    /// knows about -- preselects nothing. Silently landing on Viewer would
    /// misreport what the member holds right now.
    #[test]
    fn an_unassignable_current_role_preselects_nothing_and_still_displays_verbatim() {
        for role in ["owner", "unknown", "some_future_role", ""] {
            assert_eq!(assignable_role(role), None, "{role} must not preselect a picker value");
            let mut m = member("dev-1");
            m.role = role.to_string();
            assert_eq!(
                row_for(&m, None).role_label,
                role,
                "an unassignable role must still be displayed as reported"
            );
        }
    }

    /// A picker sitting on the member's current role has nothing to apply.
    #[test]
    fn changing_a_member_to_the_role_they_already_hold_is_recognized_as_no_change() {
        let mut m = member("dev-1");
        m.role = "viewer".to_string();
        let row = row_for(&m, None);
        assert!(!row.would_change_role_to(InviteRole::Viewer));
        assert!(row.would_change_role_to(InviteRole::Editor));
    }

    /// A member whose current role this build cannot assign can still be
    /// moved to either of the two it can -- that is exactly how an `owner`
    /// row left over from older data gets brought back into range.
    #[test]
    fn a_member_holding_an_unassignable_role_can_still_be_moved_to_viewer_or_editor() {
        let mut m = member("dev-1");
        m.role = "owner".to_string();
        let row = row_for(&m, None);
        assert!(row.would_change_role_to(InviteRole::Viewer));
        assert!(row.would_change_role_to(InviteRole::Editor));
    }

    fn approval(group_id: &str, device_id: &str, role: Option<&str>) -> PendingApproval {
        PendingApproval {
            group_id: group_id.to_string(),
            group_name: "photos".to_string(),
            device_id: device_id.to_string(),
            role: role.map(str::to_string),
        }
    }

    /// This window manages one folder. A request against a DIFFERENT group
    /// this account also owns must not appear here -- approving it from a
    /// panel headed by another folder's name would grant access to a folder
    /// the owner was not looking at.
    #[test]
    fn only_the_requests_for_this_windows_own_folder_are_listed() {
        let requests = [
            approval("group-1", "device-a", Some("viewer")),
            approval("group-2", "device-b", Some("editor")),
            approval("group-1", "device-c", Some("editor")),
        ];
        let rows = pending_rows(&requests, "group-1");
        let device_ids: Vec<&str> = rows.iter().map(|row| row.device_id.as_str()).collect();
        assert_eq!(device_ids, vec!["device-a", "device-c"]);
    }

    #[test]
    fn a_pending_row_names_the_device_and_the_role_approving_would_grant() {
        let rows =
            pending_rows(&[approval("group-1", "0123456789abcdef", Some("viewer"))], "group-1");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "0123456789abcdef");
        assert_eq!(rows[0].short_device_id, "01234567");
        assert_eq!(rows[0].requested_role_label, "Viewer");
    }

    /// A request whose role the coordination plane did not report says so
    /// rather than guessing -- and is still listed, because somebody is
    /// genuinely waiting.
    #[test]
    fn a_pending_row_with_no_reported_role_says_unknown_rather_than_guessing() {
        let rows = pending_rows(&[approval("group-1", "device-a", None)], "group-1");
        assert_eq!(rows[0].requested_role_label, "unknown");
    }

    /// A role a newer coordination plane asked for renders verbatim, the
    /// same way the minted-invite panel renders one.
    #[test]
    fn a_pending_row_renders_an_unrecognized_requested_role_verbatim() {
        let rows = pending_rows(&[approval("group-1", "device-a", Some("owner"))], "group-1");
        assert_eq!(rows[0].requested_role_label, "owner");
    }

    #[test]
    fn nothing_is_listed_when_no_request_belongs_to_this_folder() {
        assert!(pending_rows(&[approval("group-2", "device-b", None)], "group-1").is_empty());
        assert!(pending_rows(&[], "group-1").is_empty());
    }

    /// A confirmation names the exact device, not a shortened id two
    /// devices could share.
    #[test]
    fn a_removal_confirmation_names_the_full_device_id() {
        let row = row_for(&member("0123456789abcdef"), None);
        let label = confirmation_device_label(&row);
        assert_eq!(label, "laptop (0123456789abcdef)");
        let prompt = revoke_confirm_prompt(&label);
        assert!(prompt.contains("0123456789abcdef"), "{prompt}");
        assert!(prompt.contains("laptop"), "{prompt}");
        assert!(!prompt.contains("(01234567)"), "a confirmation must not use a shortened id");
    }

    /// The first confirmation has to say what removal does NOT do, or
    /// somebody who fears it deletes the other person's files hesitates over
    /// the right button for the wrong reason.
    #[test]
    fn the_first_removal_confirmation_says_local_files_are_kept() {
        let prompt = revoke_confirm_prompt("laptop (dev-1)");
        assert!(prompt.contains("stop syncing"), "{prompt}");
        assert!(prompt.contains("not deleted"), "{prompt}");
        assert!(!prompt.contains("permanently lose"), "the plain confirmation is not the override");
    }

    /// The override confirmation must quote the daemon's refusal verbatim --
    /// it names which folder groups are not ready, which is exactly the
    /// detail somebody needs to judge whether to override -- and must state
    /// the risk in the strongest terms this window uses anywhere.
    #[test]
    fn the_override_confirmation_quotes_the_refusal_and_names_the_data_loss_risk() {
        let refusal = "another full replica is not ready for: [\"group-1\"]";
        let prompt = revoke_override_prompt("laptop (dev-1)", refusal);
        assert!(prompt.contains(refusal), "{prompt}");
        assert!(prompt.contains("laptop (dev-1)"), "{prompt}");
        assert!(prompt.contains("permanently lose"), "{prompt}");
        assert!(prompt.contains("only complete copy"), "{prompt}");
        assert!(prompt.contains("audit log"), "{prompt}");
    }

    /// Reading only the buttons still has to tell someone which one is the
    /// dangerous one.
    #[test]
    fn the_override_button_says_what_it_overrides() {
        assert!(REVOKE_OVERRIDE_BUTTON.contains("anyway"), "{REVOKE_OVERRIDE_BUTTON}");
        assert!(REVOKE_OVERRIDE_BUTTON.contains("risk"), "{REVOKE_OVERRIDE_BUTTON}");
    }

    #[test]
    fn a_role_change_reports_the_role_the_member_now_holds() {
        assert_eq!(
            role_change_done_line("laptop (dev-1)", InviteRole::Viewer),
            "laptop (dev-1) is now Viewer."
        );
        assert_eq!(
            role_change_done_line("laptop (dev-1)", InviteRole::Editor),
            "laptop (dev-1) is now Editor."
        );
    }

    /// Denying revokes the originating invite as well as the request, which
    /// is the part that is not obvious from the word "deny" -- and it is the
    /// part that stops the recipient replaying their acceptance.
    #[test]
    fn turning_a_request_down_says_the_invite_cannot_be_reused() {
        let line = deny_done_line("laptop (dev-1)");
        assert!(line.contains("turned down"), "{line}");
        assert!(line.contains("cannot be redeemed again"), "{line}");
    }

    /// A request that is genuinely still waiting is denied, and the button
    /// does exactly what it says.
    #[test]
    fn a_request_that_is_still_waiting_is_denied() {
        let pending = [approval("group-1", "device-a", Some("viewer"))];
        assert_eq!(deny_precheck(&pending, &[], "group-1", "device-a"), DenyPrecheck::StillWaiting);
    }

    /// The bug this guard exists for: the requests panel is not refreshed on
    /// a timer, so a row can still say "waiting" long after the request was
    /// approved from somewhere else. Denying IS revoking, so sending that
    /// denial would remove a member whose access is live and working. A
    /// device that appears in the member listing is never denied.
    #[test]
    fn a_request_already_approved_elsewhere_is_never_denied() {
        // Exactly what the stale panel still shows -- and what the fresh
        // read says instead: nobody is waiting, and the device is a member.
        let members = [member("device-a")];
        assert_eq!(
            deny_precheck(&[], &members, "group-1", "device-a"),
            DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted)
        );
    }

    /// Membership wins over a waiting request outright: the two listings are
    /// two separate reads, so an approval landing between them shows up in
    /// both, and the reading that stops a removal is the safe one.
    #[test]
    fn being_listed_as_a_member_outweighs_a_request_still_in_the_other_listing() {
        let pending = [approval("group-1", "device-a", Some("viewer"))];
        let members = [member("device-a")];
        assert_eq!(
            deny_precheck(&pending, &members, "group-1", "device-a"),
            DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted)
        );
    }

    /// Decided or withdrawn somewhere else: nothing to deny, and nothing to
    /// remove either.
    #[test]
    fn a_request_that_is_gone_from_both_listings_is_not_denied() {
        assert_eq!(
            deny_precheck(&[], &[], "group-1", "device-a"),
            DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
        );
    }

    /// The waiting listing is account-wide, so it is narrowed by group id
    /// here exactly as `pending_rows` narrows it -- a request for ANOTHER
    /// folder must never make this window's Deny proceed.
    #[test]
    fn a_request_waiting_on_a_different_folder_does_not_make_this_deny_proceed() {
        let pending = [approval("group-2", "device-a", Some("viewer"))];
        assert_eq!(
            deny_precheck(&pending, &[], "group-1", "device-a"),
            DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
        );
    }

    /// A Deny that was stopped must never report itself the way a carried-out
    /// denial reports itself. "was turned down" is the exact claim
    /// `deny_done_line` makes, and it is the claim that made a real removal
    /// read as a harmless refusal.
    #[test]
    fn a_deny_that_was_stopped_never_claims_the_request_was_turned_down() {
        assert!(deny_done_line("laptop (dev-1)").contains("was turned down"));
        for refusal in [DenyRefusal::AlreadyAdmitted, DenyRefusal::NoLongerListed] {
            let line = deny_not_carried_out_line("laptop (dev-1)", refusal);
            assert!(!line.contains("was turned down"), "{line}");
            assert!(line.contains("laptop (dev-1)"), "{line}");
            assert!(line.contains("Nothing was changed") || line.contains("nothing was changed"));
        }
    }

    /// The already-approved line has to say the access is live, and point at
    /// the control that would actually take it away -- by that control's own
    /// label AND the section it sits under, both by their own constants, so
    /// none of the three can drift apart. It names the SECTION rather than a
    /// direction ("the list above") because this notice renders above both
    /// panels inside one scroll area, so any directional wording would send
    /// the reader the wrong way from where they are actually looking.
    #[test]
    fn the_already_approved_line_names_the_removal_button_it_points_at() {
        let line = deny_not_carried_out_line("laptop (dev-1)", DenyRefusal::AlreadyAdmitted);
        assert!(line.contains("already approved"), "{line}");
        assert!(line.contains("now has access to this folder"), "{line}");
        assert!(line.contains(REMOVE_ACCESS_BUTTON), "{line}");
        assert!(line.contains(MEMBERS_HEADING), "{line}");
        assert!(line.contains("destructive"), "{line}");
        assert!(!line.contains("above"), "a direction is wrong from where this renders: {line}");
    }

    /// Says only what a fresh listing actually showed -- the request is gone
    /// -- without picking one of the several causes (approved or turned down
    /// elsewhere, withdrawn by the requester, or swept when its originating
    /// invite expired) that this listing cannot tell apart.
    #[test]
    fn the_no_longer_waiting_line_does_not_guess_why_the_request_is_gone() {
        let line = deny_not_carried_out_line("laptop (dev-1)", DenyRefusal::NoLongerListed);
        assert!(line.contains("no longer waiting for your approval"), "{line}");
        assert!(line.contains("resolved, withdrawn, or expired"), "{line}");
        assert!(!line.contains(REMOVE_ACCESS_BUTTON), "there is nobody to remove");
    }

    #[test]
    fn a_completed_removal_says_the_device_no_longer_has_access() {
        let line = revoke_done_line("laptop (dev-1)");
        assert!(line.contains("laptop (dev-1)"), "{line}");
        assert!(line.contains("no longer has access"), "{line}");
    }

    /// The outcome of a decision is worded by the command line's own
    /// function, including its refusal to claim "Approved" for a result this
    /// build does not recognize.
    #[test]
    fn an_approval_outcome_is_worded_by_the_command_lines_own_formatter() {
        use yadorilink_cli::commands::share::approve_result_line;
        assert!(approve_result_line("approved", "dev-1", "photos").starts_with("Approved"));
        let unknown = approve_result_line("some_future_outcome", "dev-1", "photos");
        assert!(!unknown.contains("Approved"), "{unknown}");
        assert!(unknown.contains("does not recognize"), "{unknown}");
    }

    #[test]
    fn a_pending_row_carries_the_group_name_its_outcome_message_needs() {
        let rows = pending_rows(&[approval("group-1", "device-a", Some("viewer"))], "group-1");
        assert_eq!(rows[0].group_name, "photos");
    }

    /// The empty requests state must carry both facts the command line's
    /// own empty line carries -- nobody is waiting, and how a request gets
    /// here -- and must point at the control in THIS window by its exact
    /// label rather than at a command-line flag.
    #[test]
    fn the_empty_requests_state_points_at_this_windows_own_approval_checkbox() {
        let line = no_pending_requests_line();
        assert!(line.starts_with("No one is waiting for your approval."), "{line}");
        assert!(line.contains(crate::share_invite::REQUIRE_APPROVAL_LABEL), "{line}");
        assert!(!line.contains("--require-approval"), "a window must not send someone to a flag");
        assert!(!line.contains("yadorilink share"), "{line}");

        // The same two facts the command line states, in this window's own
        // terms -- so the two surfaces cannot answer this differently.
        let cli = yadorilink_cli::commands::share::NO_PENDING_APPROVALS;
        assert!(cli.starts_with("No one is waiting for your approval."));
        assert!(cli.contains("require-approval"));
    }

    /// An empty member listing says what the command line says for the same
    /// answer, and never anything that could be mistaken for a failed read.
    #[test]
    fn the_empty_member_state_reads_as_an_answer_not_as_a_failure() {
        assert_eq!(NO_MEMBERS, "No one has access to this folder.");
        assert!(!NO_MEMBERS.contains("Can't"), "{NO_MEMBERS}");
        assert!(!NO_MEMBERS.contains("error"), "{NO_MEMBERS}");
    }

    /// A failed read with a previous listing still on screen must say those
    /// rows are a last-known snapshot. Rendering them under a banner that
    /// only mentions the failure would leave them looking freshly
    /// confirmed -- and "who has access" is exactly the question where a
    /// stale answer reads as a security claim.
    #[test]
    fn a_failed_read_showing_previous_rows_marks_them_as_last_known() {
        let with_rows = access_unreadable_banner(true);
        assert!(with_rows.contains("last seen"), "{with_rows}");
        assert!(with_rows.contains("not a confirmation"), "{with_rows}");

        let without_rows = access_unreadable_banner(false);
        assert!(!without_rows.contains("list below"), "{without_rows}");
        assert!(without_rows.starts_with("Can't read who has access right now."));
    }

    /// An approval-gated invite tells the person minting it where the
    /// request will show up, and that has to be a place in THIS window,
    /// named exactly as the heading reads.
    #[test]
    fn an_approval_gated_invite_points_at_this_windows_own_requests_panel() {
        let note = approval_gated_invite_note();
        assert!(note.contains(PENDING_REQUESTS_HEADING), "{note}");
        assert!(note.contains("will not get access until you approve"), "{note}");
        assert!(!note.contains("yadorilink share"), "a window must not send someone to a terminal");
    }

    #[test]
    fn the_non_owner_notice_explains_why_the_controls_are_absent() {
        assert!(ONLY_THE_OWNER_CAN_MANAGE_ACCESS.contains("owns this folder"));
        assert!(ONLY_THE_OWNER_CAN_MANAGE_ACCESS.contains("who has access"));
    }
}
