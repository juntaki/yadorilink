#![cfg(test)]

use super::*;

/// A link with every status axis in its healthiest state (`Protected`,
/// `AvailableNow`) and nothing else wrong -- the baseline every test
/// below that isn't specifically exercising `durability_status`/
/// `fetch_availability` starts from, so those two axes' own new
/// `overall_status` contribution doesn't leak into an unrelated test's
/// expected reasons. A bare `LinkStatus::default()` would NOT do this:
/// its zero-value `durability_status`/`fetch_availability` are
/// `Unspecified` -- deliberately treated as attention-worthy (an older
/// daemon that predates the field must not read as fine), so it would
/// contribute its own reason to every test that used it.
fn protected_link(group_id: &str) -> LinkStatus {
    LinkStatus {
        group_id: group_id.to_string(),
        durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Protected as i32,
        fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::AvailableNow as i32,
        ..Default::default()
    }
}

/// spec "Sync is healthy": no links/volumes/peers/errors at all (the
/// zero-value default) is healthy with no reasons — matches this
/// file's/`status.rs`'s "additive, empty/zero unless applicable"
/// convention for a freshly-started daemon.
#[test]
fn empty_status_is_healthy() {
    let (state, reasons) = overall_status(&StatusResponse::default());
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty());
}

/// A merely-paused link with nothing else wrong stays healthy — pause
/// is a deliberate user action, not an error state.
#[test]
fn paused_link_alone_is_still_healthy() {
    let response = StatusResponse {
        links: vec![LinkStatus { paused: true, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty());
}

/// spec "Sync needs attention": a conflict on any link needs attention,
/// naming the affected group.
#[test]
fn conflict_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus { conflict_count: 1, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["conflict:group-1".to_string()]);
}

/// A link the daemon has positively confirmed has no durable copy
/// anywhere (`AtRisk`) is `Degraded`, not `Healthy` -- this is the
/// exact overstatement this guards against: the rollup used to
/// never read `durability_status` at all, so a folder with zero
/// durable copies could still read `Overall: healthy`.
#[test]
fn at_risk_durability_is_degraded() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::AtRisk
                as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["durability_at_risk:group-1".to_string()]);
}

/// A link whose durability cannot currently be confirmed (`Unknown`,
/// or `Unspecified` from an unset value is
/// `Attention`, never silently `Healthy` -- fail-safe, matching every
/// other "cannot currently confirm" surface in this daemon.
#[test]
fn unknown_durability_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown
                as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["durability_unknown:group-1".to_string()]);
}

/// A link that is durably `Protected` but cannot currently be fetched
/// is `Attention` -- "cannot fetch right now" is real and actionable,
/// but must never escalate to `Degraded`: the data itself is not at
/// risk, matching "Durability != Connectivity."
#[test]
fn unavailable_fetch_with_protected_durability_is_attention_not_degraded() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::UnavailableNow
                as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["fetch_unavailable:group-1".to_string()]);
}

/// A link that is durably `Protected` but whose `fetch_availability`
/// cannot currently be confirmed (`Unknown`, or `Unspecified` from an
/// unset-value) is `Attention`, never silently `Healthy` -- an
/// unconfirmed fetch availability must fail closed exactly like an
/// unconfirmed durability status does (an earlier version of this fold-in only
/// checked `UnavailableNow`, so `Unknown`/`Unspecified` fetch
/// availability paired with `Protected` durability silently read as
/// fully `Healthy`).
#[test]
fn unknown_fetch_availability_with_protected_durability_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::Unknown as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["fetch_availability_unknown:group-1".to_string()]);
}

/// spec "Sync needs attention": a `"low"` volume needs attention; a
/// `"critical"` one is degraded — the severity split
/// `VolumeFreeSpace.state` already draws.
#[test]
fn low_disk_is_attention_but_critical_disk_is_degraded() {
    let low = StatusResponse {
        volumes: vec![VolumeFreeSpace {
            path: "/data".into(),
            state: "low".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(overall_status(&low).0, OverallState::Attention);

    let critical = StatusResponse {
        volumes: vec![VolumeFreeSpace {
            path: "/data".into(),
            state: "critical".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&critical);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["low_disk_critical:/data".to_string()]);
}

/// spec "Sync needs attention": a peer that cannot be connected
/// (unreachable) needs attention.
#[test]
fn unreachable_peer_is_attention() {
    let response = StatusResponse {
        peers: vec![PeerStatus {
            device_id: "device-b".into(),
            reachability: yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable as i32,
            ..Default::default()
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["peer_disconnected:device-b".to_string()]);
}

/// A degraded link (disk-pressure elsewhere) takes
/// precedence over -- and is reported alongside -- an unrelated
/// attention-level issue.
#[test]
fn degraded_link_outranks_but_still_reports_attention_reasons() {
    let response = StatusResponse {
        links: vec![
            LinkStatus { degraded: true, ..protected_link("group-1") },
            LinkStatus { conflict_count: 1, ..protected_link("group-2") },
        ],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert!(reasons.contains(&"degraded:group-1".to_string()));
    assert!(reasons.contains(&"conflict:group-2".to_string()));
}

/// A recorded update failure alone needs attention, even with every
/// link/volume/peer otherwise healthy.
#[test]
fn update_failure_is_attention() {
    let response = StatusResponse {
        update_last_error_category: "update_manifest_fetch_failed".into(),
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["update_failed:update_manifest_fetch_failed".to_string()]);
}
