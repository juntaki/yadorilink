#![cfg(test)]

use super::*;

fn status(state: &str, remaining: Option<i64>) -> account::DeletionStatus {
    account::DeletionStatus {
        state: state.to_string(),
        grace_expires_at_unix: remaining.map(|_| 1_000),
        remaining_secs: remaining,
    }
}

#[test]
fn lifecycle_projects_each_server_state() {
    assert_eq!(lifecycle_from_status(&status("active", None)), Lifecycle::Active);
    assert_eq!(lifecycle_from_status(&status("requested", None)), Lifecycle::Requested);
    assert_eq!(
        lifecycle_from_status(&status("grace", Some(120))),
        Lifecycle::Grace { remaining_secs: 120, grace_expires_at_unix: 1_000 }
    );
    assert_eq!(
        lifecycle_from_status(&status("weird", None)),
        Lifecycle::Unknown("weird".to_string())
    );
}

#[test]
fn requesting_status_emits_load_effect_once() {
    let (state, fx) = step(State::default(), Event::StatusRequested);
    assert_eq!(fx, vec![Effect::LoadStatus]);
    assert_eq!(state.status, OpStatus::Working);
    // A second StatusRequested while working is a no-op (no double fetch).
    let (_state, fx2) = step(state, Event::StatusRequested);
    assert!(fx2.is_empty());
}

#[test]
fn request_then_confirm_carries_the_token() {
    let mut s = State { status: OpStatus::Idle, ..State::default() };
    s = step(s, Event::RequestDeletion).0;
    assert_eq!(s.status, OpStatus::Working);
    s = step(s, Event::DeletionRequested { confirmation_token: "tok-123".into() }).0;
    assert_eq!(s.confirmation_token.as_deref(), Some("tok-123"));
    assert_eq!(s.confirm_input, "tok-123");
    assert_eq!(s.lifecycle, Some(Lifecycle::Requested));

    let (s2, fx) = step(s, Event::ConfirmDeletion);
    assert_eq!(fx, vec![Effect::Confirm { confirmation_token: "tok-123".into() }]);
    assert_eq!(s2.status, OpStatus::Working);
}

#[test]
fn confirm_is_blocked_when_the_token_is_empty() {
    let s = State { status: OpStatus::Idle, confirm_input: "   ".into(), ..State::default() };
    let (s2, fx) = step(s, Event::ConfirmDeletion);
    assert!(fx.is_empty());
    assert_eq!(s2.status, OpStatus::Idle);
}

#[test]
fn cancel_restores_active_and_clears_the_token() {
    let s = State {
        status: OpStatus::Working,
        confirmation_token: Some("tok".into()),
        confirm_input: "tok".into(),
        lifecycle: Some(Lifecycle::Grace { remaining_secs: 10, grace_expires_at_unix: 1 }),
        notice: None,
        ..State::default()
    };
    let s = step(s, Event::DeletionCancelled(Lifecycle::Active)).0;
    assert_eq!(s.lifecycle, Some(Lifecycle::Active));
    assert!(s.confirmation_token.is_none());
    assert!(s.confirm_input.is_empty());
    assert!(s.notice.is_some());
}

#[test]
fn export_result_maps_to_a_written_path_notice() {
    let s = step(State::default(), Event::Exported("/tmp/export.json".into())).0;
    assert_eq!(s.notice.as_deref(), Some("Exported your account data to /tmp/export.json."));
    assert_eq!(s.status, OpStatus::Idle);
}

#[test]
fn export_default_path_is_json_under_config_dir() {
    let path = default_export_path();
    assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
    assert!(path.file_name().unwrap().to_string_lossy().starts_with("account-export-"));
}

#[test]
fn status_mapper_surfaces_errors() {
    let ev = status_to_event(Err(yadorilink_client_core::CoreError::NotLoggedIn));
    match ev {
        Event::StatusFailed(msg) => assert!(msg.contains("not logged in")),
        other => panic!("expected StatusFailed, got {other:?}"),
    }
}

#[test]
fn format_remaining_renders_coarse_buckets() {
    assert_eq!(format_remaining(-5), "0m");
    assert_eq!(format_remaining(90), "1m");
    assert_eq!(format_remaining(2 * 86_400 + 5 * 3600), "2d 5h");
}

// ---- cross-device sections --------------------------------------------

fn a_device(id: &str) -> device::DeviceInfo {
    device::DeviceInfo { device_id: id.to_string(), device_name: id.to_string(), online: true }
}

#[test]
fn requesting_devices_emits_load_effect_once() {
    let (state, fx) = step(State::default(), Event::DevicesRequested);
    assert_eq!(fx, vec![Effect::LoadDevices]);
    assert_eq!(state.devices_status, OpStatus::Working);
    let (_state, fx2) = step(state, Event::DevicesRequested);
    assert!(fx2.is_empty(), "a second load while working must not double-fetch");
}

#[test]
fn removing_a_device_marks_it_busy_then_drops_it_from_the_list_on_success() {
    let mut s = State::default();
    s.devices = Some(vec![a_device("dev-1"), a_device("dev-2")]);
    let (s, fx) = step(s, Event::RemoveDeviceRequested { device_id: "dev-1".to_string() });
    assert_eq!(fx, vec![Effect::RemoveDevice { device_id: "dev-1".to_string() }]);
    assert!(s.busy.contains("device:dev-1"));

    let s = step(s, Event::DeviceRemoved { device_id: "dev-1".to_string() }).0;
    assert!(!s.busy.contains("device:dev-1"));
    let ids: Vec<&str> = s.devices.as_ref().unwrap().iter().map(|d| d.device_id.as_str()).collect();
    assert_eq!(ids, vec!["dev-2"]);
    assert!(s.notice.is_some());
}

#[test]
fn a_failed_device_removal_reports_the_error_and_clears_busy_without_touching_the_list() {
    let mut s = State::default();
    s.devices = Some(vec![a_device("dev-1")]);
    let s = step(s, Event::RemoveDeviceRequested { device_id: "dev-1".to_string() }).0;
    let s = step(
        s,
        Event::RemoveDeviceFailed { device_id: "dev-1".to_string(), msg: "refused".into() },
    )
    .0;
    assert!(!s.busy.contains("device:dev-1"));
    assert_eq!(s.action_error.as_deref(), Some("refused"));
    assert_eq!(s.devices.unwrap().len(), 1, "a failed removal must not drop the row");
}

/// The same device key twice in a row (a double click before the first
/// removal's spinner even renders) must issue exactly one request, not
/// two -- the same double-submission guard `requesting_status_emits_
/// load_effect_once` checks for the deletion flow.
#[test]
fn requesting_the_same_devices_removal_twice_issues_only_one_effect() {
    let s = State::default();
    let (s, fx1) = step(s, Event::RemoveDeviceRequested { device_id: "dev-1".to_string() });
    assert_eq!(fx1.len(), 1);
    let (_s, fx2) = step(s, Event::RemoveDeviceRequested { device_id: "dev-1".to_string() });
    assert!(fx2.is_empty());
}

fn an_edge(edge_id: &str, group_name: &str) -> share::ShareEdgeInfo {
    share::ShareEdgeInfo {
        edge_id: edge_id.to_string(),
        group_id: format!("group-{edge_id}"),
        group_name: group_name.to_string(),
        device_id: "device-1".to_string(),
        state: "active".to_string(),
        role: Some("viewer".to_string()),
    }
}

fn an_access_overview(edges: Vec<share::ShareEdgeInfo>) -> AccessOverview {
    AccessOverview { edges, pending: Vec::new(), invites: Vec::new() }
}

#[test]
fn revoking_an_edge_marks_it_busy_then_drops_it_from_the_listing_on_success() {
    let mut s = State::default();
    s.access = Some(an_access_overview(vec![an_edge("e1", "photos"), an_edge("e2", "docs")]));
    let (s, fx) = step(s, Event::RevokeEdgeRequested { edge_id: "e1".to_string() });
    assert_eq!(fx, vec![Effect::RevokeEdge { edge_id: "e1".to_string() }]);
    assert!(s.busy.contains("edge:e1"));

    let s = step(s, Event::EdgeRevoked { edge_id: "e1".to_string() }).0;
    assert!(!s.busy.contains("edge:e1"));
    let ids: Vec<&str> =
        s.access.as_ref().unwrap().edges.iter().map(|e| e.edge_id.as_str()).collect();
    assert_eq!(ids, vec!["e2"]);
}

fn a_request(group_id: &str, device_id: &str) -> share::PendingApproval {
    share::PendingApproval {
        group_id: group_id.to_string(),
        group_name: "photos".to_string(),
        device_id: device_id.to_string(),
        role: Some("viewer".to_string()),
    }
}

#[test]
fn approving_a_request_removes_it_from_the_pending_listing_and_reports_the_outcome() {
    let mut s = State::default();
    s.access = Some(AccessOverview {
        edges: Vec::new(),
        pending: vec![a_request("group-1", "device-a")],
        invites: Vec::new(),
    });
    let (s, fx) = step(
        s,
        Event::ApproveRequested {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            group_name: "photos".to_string(),
        },
    );
    assert_eq!(
        fx,
        vec![Effect::Approve {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            group_name: "photos".to_string(),
        }]
    );
    assert!(s.busy.contains("approve:group-1:device-a"));

    let s = step(
        s,
        Event::ApproveDone {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            group_name: "photos".to_string(),
            result: "approved".to_string(),
        },
    )
    .0;
    assert!(s.access.unwrap().pending.is_empty());
    assert_eq!(s.notice.as_deref(), Some("Approved device-a for photos"));
}

#[test]
fn denying_a_request_removes_it_from_the_pending_listing() {
    let mut s = State::default();
    s.access = Some(AccessOverview {
        edges: Vec::new(),
        pending: vec![a_request("group-1", "device-a")],
        invites: Vec::new(),
    });
    let (s, fx) = step(
        s,
        Event::DenyRequested {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            group_name: "photos".to_string(),
        },
    );
    assert_eq!(
        fx,
        vec![Effect::Deny {
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            group_name: "photos".to_string(),
        }]
    );
    let s = step(
        s,
        Event::DenyDone { group_id: "group-1".to_string(), device_id: "device-a".to_string() },
    )
    .0;
    assert!(s.access.unwrap().pending.is_empty());
    assert!(!s.busy.contains("deny:group-1:device-a"));
}

fn an_invite(invite_id: &str, status: &str) -> share::PendingInviteInfo {
    share::PendingInviteInfo {
        invite_id: invite_id.to_string(),
        group_id: "group-1".to_string(),
        group_name: "photos".to_string(),
        role: "viewer".to_string(),
        expires_at_unix: 1_700_000_000,
        status: status.to_string(),
    }
}

#[test]
fn cancelling_an_invite_drops_it_from_the_listing_on_success() {
    let mut s = State::default();
    s.access = Some(AccessOverview {
        edges: Vec::new(),
        pending: Vec::new(),
        invites: vec![an_invite("inv-1", "pending")],
    });
    let (s, fx) = step(s, Event::CancelInviteRequested { invite_id: "inv-1".to_string() });
    assert_eq!(fx, vec![Effect::CancelInvite { invite_id: "inv-1".to_string() }]);
    let s = step(s, Event::InviteCancelled { invite_id: "inv-1".to_string() }).0;
    assert!(s.access.unwrap().invites.is_empty());
    assert!(!s.busy.contains("invite:inv-1"));
}

#[test]
fn a_failed_action_sets_action_error_without_disturbing_an_existing_success_notice() {
    let mut s = State::default();
    s.notice = Some("Removed device dev-0.".to_string());
    s.access = Some(an_access_overview(vec![an_edge("e1", "photos")]));
    let s = step(s, Event::RevokeEdgeRequested { edge_id: "e1".to_string() }).0;
    let s =
        step(s, Event::RevokeEdgeFailed { edge_id: "e1".to_string(), msg: "not durable".into() }).0;
    assert_eq!(s.action_error.as_deref(), Some("not durable"));
    assert_eq!(s.notice.as_deref(), Some("Removed device dev-0."));
    assert_eq!(s.access.unwrap().edges.len(), 1, "a failed revoke must not drop the row");
}
