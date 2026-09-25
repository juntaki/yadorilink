#![cfg(test)]

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
    let rows = pending_rows(&[approval("group-1", "0123456789abcdef", Some("viewer"))], "group-1");
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

/// The account-wide view lists every request regardless of which group
/// it belongs to -- the whole reason it exists is to show requests a
/// per-folder window (narrowed by `pending_rows`) would leave out unless
/// that exact folder happened to be open. Each row still carries its own
/// `group_id`, since a cross-folder view has no single folder's id to
/// assume for an action.
#[test]
fn the_account_wide_view_lists_every_group_and_keeps_each_rows_own_group_id() {
    let requests = [
        approval("group-1", "device-a", Some("viewer")),
        approval("group-2", "device-b", Some("editor")),
    ];
    let rows = all_pending_rows(&requests);
    let group_ids: Vec<&str> = rows.iter().map(|row| row.group_id.as_str()).collect();
    assert_eq!(group_ids, vec!["group-1", "group-2"]);
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
    use yadorilink_client_core::wording::approve_result_line;
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
    let cli = yadorilink_client_core::wording::NO_PENDING_APPROVALS;
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
