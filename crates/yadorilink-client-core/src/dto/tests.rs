use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, ConflictedFileInfo, FetchAvailability as WireFetch, FileVersionInfo,
    GroupDurabilityStatus, HandoffResult, HeldFile as WireHeldFile, InboxFileSummary,
    InboxTransfer, LinkStatus, LocalStorageState as WireLocal, MaterializationState as WireMat,
    MaterializationStatusResponse, MembershipHandoffResult, MintedInviteInfo,
    PeerReachability as WireReach, PeerStatus, RecentSyncError, ReplicaMembershipCommandOutcome,
    RouteKind as WireRoute, StatusResponse, TrashedFileInfo, UnreachableCategory as WireUnreach,
    UpdateConfigResponse, UpdateInstallResponse, UpdateStatusResponse, VolumeFreeSpace,
};
use yadorilink_local_storage::free_space::VolumeFreeSpace as Space;
use yadorilink_local_storage::link_preflight::{
    LinkPreflightReport, NestedLinkConflict, NestedLinkRelation as WireNested, RiskyLocation,
};

use super::*;
use crate::ops::account::DeletionStatus;
use crate::ops::shares::{GroupMemberInfo, PendingApproval, PendingInviteInfo, ShareEdgeInfo};

fn secs(n: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(n)
}

fn link(path: &str, group: &str) -> LinkStatus {
    LinkStatus {
        local_path: path.into(),
        group_id: group.into(),
        durability_status: GroupDurabilityStatus::Protected as i32,
        fetch_availability: WireFetch::AvailableNow as i32,
        local_storage_state: WireLocal::FullCopy as i32,
        ..Default::default()
    }
}

fn peer(id: &str, reach: WireReach, route: WireRoute) -> PeerStatus {
    PeerStatus {
        device_id: id.into(),
        reachability: reach as i32,
        route_kind: route as i32,
        ..Default::default()
    }
}

#[test]
fn attention_reason_is_split_into_category_and_subject() {
    let links = [link("/Users/a/Docs", "g1")];
    let reason = attention_reason("conflict:g1", &links);
    assert_eq!(
        reason,
        AttentionReason {
            category: AttentionCategory::Conflict,
            subject: "g1".into(),
            folder_local_path: Some("/Users/a/Docs".into()),
            raw: "conflict:g1".into(),
        }
    );
    // Only the first colon splits: a subject may itself contain one.
    let disk = attention_reason("low_disk:C:\\data", &links);
    assert_eq!(disk.category, AttentionCategory::LowDisk);
    assert_eq!(disk.subject, "C:\\data");
    assert_eq!(disk.folder_local_path, None);
    // A device-scoped reason never resolves to a folder, even when an id
    // happens to equal a group id.
    let peer = attention_reason("peer_disconnected:g1", &links);
    assert_eq!(peer.category, AttentionCategory::PeerDisconnected);
    assert_eq!(peer.folder_local_path, None);
}

#[test]
fn every_rollup_category_is_recognized_and_an_unknown_one_is_kept_raw() {
    let expected = [
        ("degraded", AttentionCategory::Degraded),
        ("durability_at_risk", AttentionCategory::DurabilityAtRisk),
        ("durability_unknown", AttentionCategory::DurabilityUnknown),
        ("fetch_unavailable", AttentionCategory::FetchUnavailable),
        ("fetch_availability_unknown", AttentionCategory::FetchAvailabilityUnknown),
        ("conflict", AttentionCategory::Conflict),
        ("held", AttentionCategory::Held),
        ("low_disk_critical", AttentionCategory::LowDiskCritical),
        ("low_disk", AttentionCategory::LowDisk),
        ("peer_disconnected", AttentionCategory::PeerDisconnected),
        ("recent_error", AttentionCategory::RecentError),
        ("update_failed", AttentionCategory::UpdateFailed),
    ];
    for (name, category) in expected {
        assert_eq!(attention_reason(&format!("{name}:x"), &[]).category, category, "{name}");
    }
    let odd = attention_reason("something_new", &[]);
    assert_eq!(odd.category, AttentionCategory::Unrecognized);
    assert_eq!(odd.subject, "");
    assert_eq!(odd.raw, "something_new");
}

#[test]
fn folder_summary_wraps_the_shared_derivation_and_turns_unset_values_into_none() {
    let mut on_demand = link("/f/Photos", "g2");
    on_demand.materialization_policy = "ondemand".into();
    on_demand.conflict_count = 2;
    on_demand.has_active_transfer = true;
    on_demand.transfer_bytes_done = 5;
    on_demand.transfer_bytes_total = 10;
    on_demand.transfer_eta_seconds = 0;
    on_demand.durability_status = GroupDurabilityStatus::Unspecified as i32;
    on_demand.local_storage_state = WireLocal::OnDemand as i32;
    on_demand.fetch_availability = WireFetch::Unspecified as i32;
    let volumes = [VolumeFreeSpace {
        path: "/f/Photos".into(),
        state: "low".into(),
        available_bytes: 7,
        headroom_bytes: 3,
    }];
    let summary = folder_summary(&on_demand, &volumes);
    assert_eq!(summary.name, "Photos");
    assert_eq!(summary.mode, FolderMode::OnDemand);
    assert_eq!(summary.state, FolderState::Attention);
    assert_eq!(summary.durability, DurabilityStatus::Unknown);
    assert_eq!(summary.durability_evidence, DurabilityEvidence::Unknown);
    assert_eq!(summary.local_storage, LocalStorageState::OnDemand);
    assert_eq!(summary.fetch_availability, FetchAvailability::Unknown);
    assert_eq!(summary.degraded_reason, None);
    assert_eq!(
        summary.transfer,
        Some(FolderTransferProgress {
            bytes_done: 5,
            bytes_total: 10,
            blocks_done: 0,
            blocks_total: 0,
            eta: None
        })
    );
    assert_eq!(
        summary.volume,
        Some(VolumeSummary {
            path: "/f/Photos".into(),
            state: FreeSpaceState::Low,
            available_bytes: 7,
            headroom_bytes: 3
        })
    );

    let mut eager = link("/f/Docs", "g1");
    eager.ambiguous = true;
    eager.paused = true;
    eager.degraded_reason = "disk full".into();
    let summary = folder_summary(&eager, &volumes);
    assert_eq!(summary.mode, FolderMode::KeepAll);
    assert_eq!(summary.state, FolderState::Blocked);
    assert_eq!(summary.durability, DurabilityStatus::Protected);
    assert_eq!(summary.degraded_reason.as_deref(), Some("disk full"));
    assert_eq!(summary.volume, None);
    assert_eq!(summary.transfer, None);
}

fn status_response() -> StatusResponse {
    let mut docs = link("/f/Docs", "g1");
    docs.full_replica_device_ids = vec!["dev-a".into(), "dev-b".into(), "dev-c".into()];
    docs.held_files = vec![WireHeldFile {
        path: "a.txt".into(),
        reason: "locked".into(),
        held_since_unix_nanos: 2_000_000_000,
    }];
    StatusResponse {
        links: vec![docs],
        peers: vec![
            peer("dev-a", WireReach::Connected, WireRoute::Relay),
            PeerStatus {
                unreachable_category: WireUnreach::UdpBlocked as i32,
                ..peer("dev-b", WireReach::Unreachable, WireRoute::Unspecified)
            },
        ],
        upload_limit_bytes_per_sec: 0,
        download_limit_bytes_per_sec: 500,
        current_upload_bytes_per_sec: 1,
        current_download_bytes_per_sec: 2,
        volumes: vec![VolumeFreeSpace {
            path: "/store".into(),
            state: "surprising".into(),
            available_bytes: 1,
            headroom_bytes: 1,
        }],
        update_state: "held_back".into(),
        update_channel: "beta".into(),
        update_install_source: "pkg".into(),
        block_store_total_bytes: 9,
        block_store_block_count: 3,
        last_gc_unix: 0,
        gc_reclaimable_estimate_bytes: 4,
        active_transfers: vec![ActiveTransferProgress {
            group_id: "g1".into(),
            path: "big.bin".into(),
            bytes_done: 1,
            bytes_total: 2,
            blocks_done: 3,
            blocks_total: 4,
            source_peer: "dev-a".into(),
            started_at_unix: 100,
        }],
        recent_errors: vec![RecentSyncError {
            category: "io".into(),
            timestamp_unix: 50,
            coarse_context: "write".into(),
        }],
        overall_state: "attention".into(),
        attention_reasons: vec!["conflict:g1".into()],
        ..Default::default()
    }
}

#[test]
fn status_snapshot_maps_every_section_of_the_daemon_status() {
    let snapshot = status_snapshot(&status_response(), Some("me".into()), secs(1_000));
    assert_eq!(snapshot.captured_at, secs(1_000));
    assert_eq!(snapshot.overall, OverallState::Attention);
    assert_eq!(snapshot.this_device_id.as_deref(), Some("me"));
    assert_eq!(snapshot.attention_reasons[0].folder_local_path.as_deref(), Some("/f/Docs"));
    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(
        snapshot.peers,
        vec![
            PeerSummary {
                device_id: "dev-a".into(),
                reachability: PeerReachability::Connected,
                unreachable_category: None,
                route: RouteKind::Relay,
            },
            PeerSummary {
                device_id: "dev-b".into(),
                reachability: PeerReachability::Unreachable,
                unreachable_category: Some(UnreachableCategory::UdpBlocked),
                route: RouteKind::Unknown,
            },
        ]
    );
    assert_eq!(
        snapshot.transfers,
        vec![TransferSummary {
            group_id: "g1".into(),
            folder_local_path: Some("/f/Docs".into()),
            path: "big.bin".into(),
            bytes_done: 1,
            bytes_total: 2,
            blocks_done: 3,
            blocks_total: 4,
            source_device_id: "dev-a".into(),
            started_at: Some(secs(100)),
        }]
    );
    assert_eq!(
        snapshot.bandwidth,
        BandwidthStatus {
            limits: BandwidthLimits {
                upload_bytes_per_sec: None,
                download_bytes_per_sec: Some(500)
            },
            current_upload_bytes_per_sec: 1,
            current_download_bytes_per_sec: 2,
        }
    );
    assert_eq!(snapshot.volumes[0].state, FreeSpaceState::Unknown);
    assert_eq!(
        snapshot.storage,
        StorageSummary {
            block_store_total_bytes: 9,
            block_count: 3,
            last_gc_at: None,
            reclaimable_estimate_bytes: 4
        }
    );
    assert_eq!(
        snapshot.update,
        UpdateBadge {
            state: UpdateState::HeldBack,
            available_version: None,
            mandatory: false,
            waiting_for_safe_point: false,
            last_error_category: None,
            channel: "beta".into(),
            install_source: "pkg".into(),
            holdback_reason: None,
        }
    );
    assert_eq!(
        snapshot.recent_errors,
        vec![RecentError { category: "io".into(), at: Some(secs(50)), context: "write".into() }]
    );
}

#[test]
fn an_empty_or_unknown_overall_state_reads_as_unknown_never_healthy() {
    for raw in ["", "fine", "HEALTHY"] {
        let response = StatusResponse { overall_state: raw.into(), ..Default::default() };
        assert_eq!(status_snapshot(&response, None, secs(0)).overall, OverallState::Unknown);
    }
    for (raw, state) in [
        ("healthy", OverallState::Healthy),
        ("attention", OverallState::Attention),
        ("degraded", OverallState::Degraded),
    ] {
        let response = StatusResponse { overall_state: raw.into(), ..Default::default() };
        assert_eq!(status_snapshot(&response, None, secs(0)).overall, state);
    }
}

#[test]
fn folder_detail_lists_every_complete_copy_with_this_devices_connection_to_it() {
    let detail = folder_detail(&status_response(), "/f/Docs").expect("linked folder");
    assert_eq!(detail.summary.local_path, "/f/Docs");
    assert_eq!(
        detail.held_files,
        vec![HeldFile { path: "a.txt".into(), reason: "locked".into(), held_since: Some(secs(2)) }]
    );
    assert_eq!(
        detail.complete_copies,
        vec![
            ReplicaCopy {
                device_id: "dev-a".into(),
                reachability: PeerReachability::Connected,
                route: RouteKind::Relay
            },
            ReplicaCopy {
                device_id: "dev-b".into(),
                reachability: PeerReachability::Unreachable,
                route: RouteKind::Unknown
            },
            ReplicaCopy {
                device_id: "dev-c".into(),
                reachability: PeerReachability::Unknown,
                route: RouteKind::Unknown
            },
        ]
    );
    assert_eq!(folder_detail(&status_response(), "/elsewhere"), None);
}

#[test]
fn conflict_summary_names_the_file_it_conflicts_with() {
    let summary = conflict_summary(&ConflictedFileInfo {
        local_path: "/f/Docs".into(),
        path: "notes.txt".into(),
        size: -1,
        mtime_unix_nanos: 0,
        kind: 0,
        reason: 0,
    });
    assert_eq!(summary.current_path, "notes.txt");
    assert_eq!(summary.reason, ConflictReason::ConcurrentEdit);
    assert_eq!(summary.size, 0);
    assert_eq!(summary.modified_at, None);
    assert_eq!(summary.loser_device_id, None);
}

#[test]
fn only_the_highest_version_is_current() {
    let versions = file_versions(&[
        FileVersionInfo { version_seq: 3, size: 1, ..Default::default() },
        FileVersionInfo {
            version_seq: 7,
            size: 2,
            mtime_unix_nanos: 3_000_000_000,
            origin_device_id: "dev-a".into(),
            unix_mode: Some(0o644),
            state: "live".into(),
            kind: 0,
        },
        FileVersionInfo { version_seq: 5, size: 3, ..Default::default() },
    ]);
    assert_eq!(versions.iter().map(|v| v.is_current).collect::<Vec<_>>(), [false, true, false]);
    assert_eq!(versions[1].modified_at, Some(secs(3)));
    assert_eq!(versions[1].origin_device_id.as_deref(), Some("dev-a"));
    assert_eq!(versions[1].unix_mode, Some(0o644));
    assert_eq!(versions[0].origin_device_id, None);
}

#[test]
fn trash_file_and_materialization_turn_unset_values_into_none() {
    let trashed = trashed_file(&TrashedFileInfo {
        local_path: "/f".into(),
        path: "x".into(),
        version_seq: 4,
        last_known_size: 10,
        origin_device_id: String::new(),
        deleted_at_unix_nanos: 1_000_000_000,
        kind: 0,
        deleted_by_operation: String::new(),
    });
    assert_eq!(trashed.origin_device_id, None);
    assert_eq!(trashed.deleted_at, Some(secs(1)));
    assert_eq!(trashed.deleted_by_operation, None);
    let in_folder = trashed_file(&TrashedFileInfo {
        deleted_by_operation: "device-a:0a0b".into(),
        ..Default::default()
    });
    assert_eq!(in_folder.deleted_by_operation.as_deref(), Some("device-a:0a0b"));

    let unknown = file_availability(&MaterializationStatusResponse {
        known: false,
        state: WireMat::Unspecified as i32,
        pinned: false,
    });
    assert_eq!(
        unknown,
        FileAvailability { tracked: false, state: MaterializationState::Unknown, pinned: false }
    );
    let pinned = file_availability(&MaterializationStatusResponse {
        known: true,
        state: WireMat::Hydrating as i32,
        pinned: true,
    });
    assert_eq!(
        pinned,
        FileAvailability { tracked: true, state: MaterializationState::Hydrating, pinned: true }
    );
}

#[test]
fn membership_outcome_keeps_forced_groups_and_the_unknown_scope_operation() {
    let outcome = membership_outcome(&ReplicaMembershipCommandOutcome {
        handoffs: vec![MembershipHandoffResult {
            group_id: "g".into(),
            target_device_id: "t".into(),
            lease_id: "l".into(),
            membership_generation: 9,
        }],
        forced_group_ids: vec!["g2".into()],
        unknown_scope_operation_id: String::new(),
    });
    assert_eq!(outcome.forced_group_ids, ["g2".to_string()]);
    assert_eq!(outcome.unknown_scope_operation_id, None);
    assert_eq!(outcome.handoffs[0].membership_generation, 9);

    let unknown = membership_outcome(&ReplicaMembershipCommandOutcome {
        unknown_scope_operation_id: "op".into(),
        ..Default::default()
    });
    assert_eq!(unknown.unknown_scope_operation_id.as_deref(), Some("op"));

    let handoff = handoff_summary(&HandoffResult {
        target_device_id: "t".into(),
        membership_generation: 3,
        lease_id: String::new(),
        ..Default::default()
    });
    assert_eq!(handoff.lease_id, None);
}

fn member(id: &str, caller: bool, same: bool) -> GroupMemberInfo {
    GroupMemberInfo {
        device_id: id.into(),
        device_name: "Laptop".into(),
        role: "editor".into(),
        is_same_account: same,
        is_caller_account: caller,
        storage_mode: "eager".into(),
        online: true,
        last_seen_unix: 0,
    }
}

#[test]
fn member_relationship_is_caller_relative() {
    assert_eq!(
        member_summary(&member("me", true, true), Some("me")).relationship,
        MemberRelationship::You
    );
    assert_eq!(
        member_summary(&member("other", true, false), Some("me")).relationship,
        MemberRelationship::YourOtherDevice
    );
    assert_eq!(
        member_summary(&member("other", false, true), Some("me")).relationship,
        MemberRelationship::OwnersDevice
    );
    assert_eq!(
        member_summary(&member("other", false, false), None).relationship,
        MemberRelationship::Invited
    );
    let summary = member_summary(&member("me", true, true), None);
    assert_eq!(summary.role, ShareRole::Editor);
    assert_eq!(summary.storage, MemberStorage::FullCopy);
    assert_eq!(summary.last_seen, None);
    let mut odd = member("x", false, false);
    odd.role = "unknown".into();
    odd.storage_mode = "future".into();
    odd.last_seen_unix = 60;
    let summary = member_summary(&odd, None);
    assert_eq!(summary.role, ShareRole::Other { raw: "unknown".into() });
    assert_eq!(summary.storage, MemberStorage::OnDemand);
    assert_eq!(summary.last_seen, Some(secs(60)));
}

#[test]
fn shares_invites_and_approvals_keep_unrecognized_values() {
    let edge = |state: &str, role: Option<&str>| ShareEdgeInfo {
        edge_id: "e".into(),
        group_id: "g".into(),
        group_name: "G".into(),
        device_id: "d".into(),
        state: state.into(),
        role: role.map(Into::into),
    };
    assert_eq!(share_summary(&edge("active", Some("owner"))).state, ShareEdgeState::Active);
    assert_eq!(share_summary(&edge("active", Some("owner"))).role, Some(ShareRole::Owner));
    assert_eq!(
        share_summary(&edge("pending_approval", None)).state,
        ShareEdgeState::PendingApproval
    );
    assert_eq!(
        share_summary(&edge("revoked", None)).state,
        ShareEdgeState::Other { raw: "revoked".into() }
    );

    let pending = pending_approval_summary(&PendingApproval {
        group_id: "g".into(),
        group_name: "G".into(),
        device_id: "d".into(),
        role: Some("viewer".into()),
    });
    assert_eq!(pending.requested_role, Some(ShareRole::Viewer));

    let invite = invite_summary(&MintedInviteInfo {
        code: "abc".into(),
        invite_id: "i".into(),
        group_id: "g".into(),
        role: "viewer".into(),
        expires_at_unix: 70,
        requires_approval: true,
    });
    assert_eq!(invite.url, "yadorilink://invite/abc");
    assert_eq!(invite.url, crate::wording::invite_url("abc"));
    assert_eq!(invite.expires_at, secs(70));
    assert_eq!(invite.role, ShareRole::Viewer);

    let listed = pending_invite_summary(&PendingInviteInfo {
        invite_id: "i".into(),
        group_id: "g".into(),
        group_name: "G".into(),
        role: "editor".into(),
        expires_at_unix: 80,
        status: "expired".into(),
    });
    assert_eq!(listed.status, InviteStatus::Other { raw: "expired".into() });
    assert_eq!(listed.expires_at, secs(80));
}

#[test]
fn preflight_issues_follow_the_reports_own_order() {
    let report = LinkPreflightReport {
        path_exists: true,
        is_directory: true,
        entry_count: 3,
        scan_truncated: true,
        free_space: Some(Space { available_bytes: 5, total_bytes: 100, headroom_bytes: 10 }),
        nested_conflicts: vec![NestedLinkConflict {
            other_path: "/a".into(),
            relation: WireNested::Ancestor,
        }],
        risky_location: Some(RiskyLocation::CloudProviderFolder("Dropbox")),
        ignore_rules_unreadable: true,
        reserved_namespace_blocked_paths: vec![".yadorilink-x".into()],
        ..Default::default()
    };
    let result = preflight_result(&PathBuf::from("/a/b"), &report);
    assert_eq!(result.resolved_path, "/a/b");
    assert!(result.requires_acknowledgement);
    assert_eq!(
        result.free_space,
        Some(FreeSpace {
            available_bytes: 5,
            total_bytes: 100,
            headroom_bytes: 10,
            state: FreeSpaceState::Critical
        })
    );
    assert_eq!(
        result.issues,
        vec![
            PreflightIssue::IgnoreRulesUnreadable,
            PreflightIssue::NotEmpty { entry_count: 3, scan_truncated: true },
            PreflightIssue::CriticalFreeSpace { available_bytes: 5, headroom_bytes: 10 },
            PreflightIssue::NestedLink {
                other_path: "/a".into(),
                relation: NestedLinkRelation::Ancestor
            },
            PreflightIssue::CloudProviderFolder { provider: "Dropbox".into() },
            PreflightIssue::ReservedName { path: ".yadorilink-x".into() },
        ]
    );
    assert_eq!(result.issues.len(), report.warnings().len());

    let missing = preflight_result(&PathBuf::from("/gone"), &LinkPreflightReport::default());
    assert_eq!(missing.issues, vec![PreflightIssue::PathMissing]);
    assert!(missing.requires_acknowledgement);

    let clean = LinkPreflightReport {
        path_exists: true,
        is_directory: true,
        free_space: Some(Space { available_bytes: 100, total_bytes: 100, headroom_bytes: 10 }),
        ..Default::default()
    };
    let clean = preflight_result(&PathBuf::from("/ok"), &clean);
    assert!(clean.issues.is_empty());
    assert!(!clean.requires_acknowledgement);
}

#[test]
fn updates_map_states_modes_and_outcomes() {
    let status = update_status(&UpdateStatusResponse {
        current_version: "1.0".into(),
        state: "kill_switched".into(),
        last_check_unix: 20,
        automatic_checks_enabled: true,
        automatic_install_mode: "manual".into(),
        ..Default::default()
    });
    assert_eq!(status.state, UpdateState::KillSwitched);
    assert_eq!(status.last_checked_at, Some(secs(20)));
    assert_eq!(status.available_version, None);
    assert_eq!(
        status.config,
        UpdateConfig { automatic_checks: true, install_mode: UpdateInstallMode::Manual }
    );
    assert_eq!(
        update_config(&UpdateConfigResponse {
            automatic_checks_enabled: false,
            automatic_install_mode: "sometimes".into()
        })
        .install_mode,
        UpdateInstallMode::Other { raw: "sometimes".into() }
    );
    let states = [
        ("idle", UpdateState::Idle),
        ("checking", UpdateState::Checking),
        ("available", UpdateState::Available),
        ("held_back", UpdateState::HeldBack),
        ("kill_switched", UpdateState::KillSwitched),
        ("downloading", UpdateState::Downloading),
        ("downloaded", UpdateState::Downloaded),
        ("verified", UpdateState::Verified),
        ("installing", UpdateState::Installing),
        ("failed", UpdateState::Failed),
        ("deferred", UpdateState::Deferred),
        ("up_to_date", UpdateState::UpToDate),
        ("", UpdateState::Unknown { raw: String::new() }),
    ];
    for (raw, state) in states {
        let status =
            update_status(&UpdateStatusResponse { state: raw.into(), ..Default::default() });
        assert_eq!(status.state, state, "{raw}");
    }
    let outcome = |o: &str, g: &str| {
        update_install_outcome(&UpdateInstallResponse { outcome: o.into(), guidance: g.into() })
    };
    assert_eq!(outcome("installing", ""), UpdateInstallOutcome::Installing);
    assert_eq!(outcome("deferred", ""), UpdateInstallOutcome::Deferred);
    assert_eq!(
        outcome("store_managed", "use the store"),
        UpdateInstallOutcome::StoreManaged { guidance: "use the store".into() }
    );
    assert_eq!(outcome("later", ""), UpdateInstallOutcome::Other { raw: "later".into() });
}

#[test]
fn account_deletion_and_transfers_parse_their_states() {
    let grace = account_deletion_status(&DeletionStatus {
        state: "grace".into(),
        grace_expires_at_unix: Some(90),
        remaining_secs: Some(30),
    });
    assert_eq!(
        grace,
        AccountDeletionStatus {
            state: AccountDeletionState::Grace,
            grace_expires_at: Some(secs(90)),
            remaining: Some(Duration::from_secs(30)),
        }
    );
    let odd = account_deletion_status(&DeletionStatus {
        state: "purged".into(),
        grace_expires_at_unix: None,
        remaining_secs: Some(-5),
    });
    assert_eq!(odd.state, AccountDeletionState::Other { raw: "purged".into() });
    assert_eq!(odd.remaining, None);

    let inbox = incoming_transfer(&InboxTransfer {
        transfer_id: "t".into(),
        sender_device_id: "s".into(),
        files: vec![InboxFileSummary { relative_path: "a".into(), size: 1 }],
        total_size: 1,
        offered_at_unix_nanos: 4_000_000_000,
        status: "in_progress".into(),
    });
    assert_eq!(inbox.status, IncomingTransferStatus::InProgress);
    assert_eq!(inbox.offered_at, Some(secs(4)));
    assert_eq!(inbox.files, vec![IncomingFile { relative_path: "a".into(), size: 1 }]);
    for (raw, status) in [
        ("pending", IncomingTransferStatus::Pending),
        ("completed", IncomingTransferStatus::Completed),
        ("paused", IncomingTransferStatus::Other { raw: "paused".into() }),
    ] {
        let t = incoming_transfer(&InboxTransfer { status: raw.into(), ..Default::default() });
        assert_eq!(t.status, status);
    }
}

/// Each record's kind reaches the product types. An unset wire kind is a
/// sender that never classified the record, which only ever meant a file.
#[test]
fn versions_trash_and_conflicts_carry_their_entry_kind() {
    use yadorilink_ipc_proto::daemonctl::EntryKind as Wire;
    for (wire, kind) in [
        (Wire::Unspecified, EntryKind::File),
        (Wire::File, EntryKind::File),
        (Wire::Directory, EntryKind::Directory),
        (Wire::Symlink, EntryKind::Symlink),
    ] {
        let version =
            file_version(&FileVersionInfo { kind: wire as i32, ..Default::default() }, true);
        assert_eq!(version.kind, kind, "{wire:?}");
        let trashed = trashed_file(&TrashedFileInfo { kind: wire as i32, ..Default::default() });
        assert_eq!(trashed.kind, kind, "{wire:?}");
        let conflict = conflict_summary(&ConflictedFileInfo {
            path: "a (conflicted copy, 2026-01-01-000000, dev-b)".into(),
            kind: wire as i32,
            ..Default::default()
        });
        assert_eq!(conflict.kind, kind, "{wire:?}");
    }
}

#[test]
fn folder_restore_outcome_carries_every_part() {
    use yadorilink_ipc_proto::daemonctl::{
        RestoreTrashOperationFailure, RestoreTrashOperationResponse,
    };
    let outcome = folder_restore_outcome(&RestoreTrashOperationResponse {
        restored_paths: vec!["album".into(), "album/a.jpg".into()],
        failed: vec![RestoreTrashOperationFailure {
            path: "album/b.jpg".into(),
            error: "content unavailable".into(),
        }],
        partial: true,
    });
    assert_eq!(
        outcome,
        FolderRestoreOutcome {
            restored_paths: vec!["album".into(), "album/a.jpg".into()],
            failed: vec![FolderRestoreFailure {
                path: "album/b.jpg".into(),
                error: "content unavailable".into(),
            }],
            partial: true,
        }
    );
}

#[test]
fn conflict_summary_says_when_a_folder_took_the_name() {
    let summary = conflict_summary(&ConflictedFileInfo {
        local_path: "/f/Docs".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        reason: yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath as i32,
        ..Default::default()
    });
    assert_eq!(summary.current_path, "album");
    assert_eq!(summary.reason, ConflictReason::FolderAtPath);
}
