#![cfg(test)]

use super::*;

fn base_link() -> LinkStatus {
    LinkStatus {
        local_path: "/Users/alice/Photos".into(),
        group_id: "group-1".into(),
        durability_status: GroupDurabilityStatus::Protected as i32,
        durability_evidence: DurabilityEvidence::CorroboratedIndex as i32,
        local_storage_state: LocalStorageState::FullCopy as i32,
        fetch_availability: FetchAvailability::AvailableNow as i32,
        ..Default::default()
    }
}

fn base_peer(device_id: &str) -> PeerStatus {
    PeerStatus {
        device_id: device_id.into(),
        reachability: PeerReachability::Connected as i32,
        route_kind: RouteKind::Direct as i32,
        ..Default::default()
    }
}

#[test]
fn data_protection_maps_every_durability_state() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Protected as i32;
    assert_eq!(data_protection_label(&link), "Protected");
    link.durability_status = GroupDurabilityStatus::Protecting as i32;
    assert_eq!(data_protection_label(&link), "Protecting");
    link.durability_status = GroupDurabilityStatus::AtRisk as i32;
    assert_eq!(data_protection_label(&link), "At risk");
    link.durability_status = GroupDurabilityStatus::Unknown as i32;
    assert_eq!(data_protection_label(&link), "Status unavailable");
    link.durability_status = GroupDurabilityStatus::Unspecified as i32;
    assert_eq!(
        data_protection_label(&link),
        "Status unavailable",
        "an unset value must fail safe, never read as Protected"
    );
}

/// The key distinction: protected-but-unreachable is NOT
/// data loss.
#[test]
fn protected_but_unavailable_gets_the_non_alarmist_detail_line() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Protected as i32;
    link.fetch_availability = FetchAvailability::UnavailableNow as i32;
    assert_eq!(
        data_protection_detail(&link),
        Some("Your data is protected, but no device that holds it is reachable right now.")
    );
}

#[test]
fn protected_and_available_has_no_detail_line() {
    let link = base_link();
    assert_eq!(data_protection_detail(&link), None);
}

#[test]
fn this_device_maps_every_local_storage_state() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::FullCopy as i32;
    assert_eq!(this_device_label(&link), "Full copy on this device");
    link.local_storage_state = LocalStorageState::PartiallyMaterialized as i32;
    assert_eq!(this_device_label(&link), "Making a full copy on this device…");
    link.local_storage_state = LocalStorageState::OnDemand as i32;
    assert_eq!(this_device_label(&link), "Saving space on this device (On-Demand)");
    link.local_storage_state = LocalStorageState::Unspecified as i32;
    assert_eq!(
        this_device_label(&link),
        "Status unavailable",
        "an unset value must never read as a specific reassuring \
         configuration"
    );
}

#[test]
fn availability_maps_every_fetch_availability_state() {
    let mut link = base_link();
    link.fetch_availability = FetchAvailability::AvailableNow as i32;
    assert_eq!(availability_label(&link), "Available now");
    link.fetch_availability = FetchAvailability::UnavailableNow as i32;
    assert_eq!(availability_label(&link), "Cannot fetch right now");
    link.fetch_availability = FetchAvailability::Unknown as i32;
    assert_eq!(availability_label(&link), "Status unavailable");
}

#[test]
fn no_full_replica_devices_renders_no_rows() {
    let link = base_link();
    assert!(complete_copies(&link, &[]).is_empty());
    assert!(connections(&link, &[]).is_empty());
}

#[test]
fn complete_copies_reports_available_offline_unknown() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into(), "nas-2".into(), "unseen".into()];
    let mut offline_peer = base_peer("nas-2");
    offline_peer.reachability = PeerReachability::Unreachable as i32;
    let peers = vec![base_peer("nas-1"), offline_peer];

    let rows = complete_copies(&link, &peers);
    assert_eq!(
        rows,
        vec![
            CompleteCopyRow { device_id: "nas-1".into(), state: CompleteCopyState::Available },
            CompleteCopyRow { device_id: "nas-2".into(), state: CompleteCopyState::Offline },
            CompleteCopyRow { device_id: "unseen".into(), state: CompleteCopyState::Unknown },
        ]
    );
}

#[test]
fn connection_distinguishes_direct_and_unavailable() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["direct-nas".into(), "down-nas".into()];
    let mut down_peer = base_peer("down-nas");
    down_peer.reachability = PeerReachability::Unreachable as i32;
    let peers = vec![base_peer("direct-nas"), down_peer];

    let rows = connections(&link, &peers);
    assert_eq!(
        rows,
        vec![
            ConnectionRow { device_id: "direct-nas".into(), label: "Direct" },
            ConnectionRow { device_id: "down-nas".into(), label: "Currently unavailable" },
        ]
    );
}

/// A peer connected only through a relay server is shown as connected, and
/// says so -- not as unavailable, and not as direct.
#[test]
fn a_relayed_peer_reads_as_relayed() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer("nas-1");
    peer.route_kind = RouteKind::Relay as i32;
    let rows = connections(&link, &[peer]);
    assert_eq!(rows, vec![ConnectionRow { device_id: "nas-1".into(), label: "Relayed" }]);
}

/// an unset value
/// `Connected` peer -- must NOT be conflated with a genuine failure to
/// determine the route.
#[test]
fn connected_with_unspecified_route_kind_reads_as_plain_connected() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer("nas-1");
    peer.route_kind = RouteKind::Unspecified as i32;
    let rows = connections(&link, &[peer]);
    assert_eq!(rows, vec![ConnectionRow { device_id: "nas-1".into(), label: "Connected" }]);
}

/// Durability != Connectivity, pinned directly: a group with zero
/// reachable/connected full-replica peers (fetch_availability
/// UnavailableNow, every connection row "Currently unavailable")
/// still reports "Protected" when `durability_status` says so --
/// connectivity state never downgrades the durability label.
#[test]
fn durability_is_independent_of_connectivity() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Protected as i32;
    link.fetch_availability = FetchAvailability::UnavailableNow as i32;
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer("nas-1");
    peer.reachability = PeerReachability::Unreachable as i32;

    assert_eq!(data_protection_label(&link), "Protected");
    assert_eq!(availability_label(&link), "Cannot fetch right now");
    assert_eq!(
        connections(&link, &[peer]),
        vec![ConnectionRow { device_id: "nas-1".into(), label: "Currently unavailable" }]
    );
}

fn base_volume(path: &str) -> VolumeFreeSpace {
    VolumeFreeSpace { path: path.into(), state: "ok".into(), available_bytes: 0, headroom_bytes: 0 }
}

#[test]
fn disk_usage_matches_by_exact_local_path() {
    let link = base_link();
    let volumes = vec![base_volume("/somewhere/else"), base_volume(&link.local_path)];
    let found = disk_usage_for(&link, &volumes).expect("exact match must be found");
    assert_eq!(found.path, link.local_path);
}

#[test]
fn disk_usage_is_none_when_no_volume_matches_this_folders_path() {
    let link = base_link();
    let volumes = vec![base_volume("/somewhere/else")];
    assert!(disk_usage_for(&link, &volumes).is_none());
}

#[test]
fn disk_usage_label_renders_bytes_and_state_verbatim() {
    let volume = VolumeFreeSpace {
        path: "/x".into(),
        state: "low".into(),
        available_bytes: 500 * 1024 * 1024,
        headroom_bytes: 0,
    };
    assert_eq!(disk_usage_label(&volume), "500.0 MiB free (low)");
}

#[test]
fn format_bytes_scales_to_a_human_readable_unit() {
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1536), "1.5 KiB");
    assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
    assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
}

fn base_transfer() -> yadorilink_product_view::FolderTransfer {
    yadorilink_product_view::FolderTransfer {
        bytes_done: 0,
        bytes_total: 0,
        blocks_done: 0,
        blocks_total: 0,
        eta_seconds: 0,
    }
}

#[test]
fn transfer_progress_reports_percent_bytes_and_eta() {
    let transfer = yadorilink_product_view::FolderTransfer {
        bytes_done: 50 * 1024 * 1024,
        bytes_total: 100 * 1024 * 1024,
        eta_seconds: 90,
        ..base_transfer()
    };
    assert_eq!(transfer_progress_label(&transfer), "50% · 50.0 MiB / 100.0 MiB · ~1m remaining");
}

#[test]
fn transfer_progress_with_unknown_total_size_is_zero_percent_not_a_panic() {
    let transfer = yadorilink_product_view::FolderTransfer { bytes_done: 10, ..base_transfer() };
    assert_eq!(transfer_progress_label(&transfer), "0% · 10 B / 0 B");
}

#[test]
fn transfer_progress_omits_eta_when_not_yet_known() {
    let transfer = yadorilink_product_view::FolderTransfer {
        bytes_done: 1,
        bytes_total: 2,
        ..base_transfer()
    };
    assert!(!transfer_progress_label(&transfer).contains("remaining"));
}

#[test]
fn format_eta_picks_the_coarsest_unit() {
    assert_eq!(format_eta(0), "");
    assert_eq!(format_eta(30), " · ~30s remaining");
    assert_eq!(format_eta(150), " · ~2m remaining");
    assert_eq!(format_eta(7200), " · ~2h remaining");
}
