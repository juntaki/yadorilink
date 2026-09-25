#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, DurabilityEvidence, HeldFile, RecentSyncError,
};

use super::*;

fn base_link() -> LinkStatus {
    LinkStatus {
        local_path: "/tmp/photos".into(),
        group_id: "group-1".into(),
        paused: false,
        conflict_count: 0,
        materialization_policy: "eager".into(),
        hydrated_count: 0,
        placeholder_count: 0,
        hydrating_count: 0,
        held_file_count: 0,
        held_files: vec![],
        skipped_symlink_count: 0,
        degraded: false,
        degraded_reason: String::new(),
        has_active_transfer: false,
        transfer_bytes_done: 0,
        transfer_bytes_total: 0,
        transfer_blocks_done: 0,
        transfer_blocks_total: 0,
        transfer_eta_seconds: 0,
        durability_status: GroupDurabilityStatus::Protected as i32,
        durability_evidence: DurabilityEvidence::CorroboratedIndex as i32,
        policy_stale: false,
        ambiguous: false,
        ambiguous_local_paths: Vec::new(),
        local_storage_state: LocalStorageState::FullCopy as i32,
        fetch_availability: FetchAvailability::AvailableNow as i32,
        full_replica_device_ids: Vec::new(),
    }
}

/// a link with no held files renders no held-related output
/// at all — no `held=0` suffix, no detail lines.
#[test]
fn no_held_files_renders_no_new_output() {
    let link = base_link();
    assert_eq!(held_summary_suffix(&link), "");
    assert!(held_file_detail_lines(&link).is_empty());
}

/// No full-replica peers configured renders no "Complete
/// copies" lines at all.
#[test]
fn no_full_replica_peers_renders_no_complete_copies_lines() {
    let link = base_link();
    assert!(complete_copies_detail_lines(&link, &[]).is_empty());
}

/// the label says "configured
/// full copy," never "complete copy" -- this list is a structural,
/// content-blind netmap declaration, not peer-confirmed content
/// custody (that's `durability_status`'s job). A `Connected` device
/// reads "available".
#[test]
fn complete_copies_lines_report_available_for_a_connected_device() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer();
    peer.device_id = "nas-1".into();
    peer.reachability = PeerReachability::Connected as i32;

    let lines = complete_copies_detail_lines(&link, &[peer]);
    assert_eq!(lines, vec!["    configured full copy: nas-1  (available)".to_string()]);
}

/// a device this daemon has
/// never even seen (absent from `peers` entirely) reads "unknown",
/// NOT "offline" -- "offline" is a positive claim this daemon has no
/// basis for here. Only an explicit `Unreachable` reachability earns
/// "offline".
#[test]
fn unseen_device_reads_unknown_not_offline() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["unseen-device".into()];

    let lines = complete_copies_detail_lines(&link, &[]);
    assert_eq!(lines, vec!["    configured full copy: unseen-device  (unknown)".to_string()]);
}

/// `Connecting`/`Unspecified` are ALSO not
/// positive "offline" evidence -- they read "unknown" too, the same
/// as a device absent from `peers` entirely.
#[test]
fn indeterminate_reachability_states_read_unknown() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    for state in [PeerReachability::Connecting, PeerReachability::Unspecified] {
        let mut peer = base_peer();
        peer.device_id = "nas-1".into();
        peer.reachability = state as i32;
        let lines = complete_copies_detail_lines(&link, &[peer]);
        assert_eq!(
            lines,
            vec!["    configured full copy: nas-1  (unknown)".to_string()],
            "reachability {state:?} must read unknown, not offline"
        );
    }
}

/// A full-replica device that IS known but currently `Unreachable`
/// (a positive, known-down fact) reads "offline" -- distinct from the
/// "unknown" cases above.
#[test]
fn complete_copies_line_reports_offline_for_a_known_unreachable_device() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer();
    peer.device_id = "nas-1".into();
    peer.reachability = PeerReachability::Unreachable as i32;

    let lines = complete_copies_detail_lines(&link, &[peer]);
    assert_eq!(lines, vec!["    configured full copy: nas-1  (offline)".to_string()]);
}

/// a link with held files shows the count and, for each
/// held file, its path and reason.
#[test]
fn held_files_render_count_and_per_file_reason() {
    let mut link = base_link();
    link.held_file_count = 2;
    link.held_files = vec![
        HeldFile {
            path: "photo.jpg".into(),
            reason: "case_collision: collides with existing 'Photo.jpg'".into(),
            held_since_unix_nanos: 1_000,
        },
        HeldFile {
            path: "CON.txt".into(),
            reason: "invalid_name: reserved device name".into(),
            held_since_unix_nanos: 2_000,
        },
    ];

    assert_eq!(held_summary_suffix(&link), "  held=2");
    let lines = held_file_detail_lines(&link);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("photo.jpg"));
    assert!(lines[0].contains("case_collision"));
    assert!(lines[1].contains("CON.txt"));
    assert!(lines[1].contains("invalid_name"));
}

/// A healthy (non-degraded) link renders no degraded-related output,
/// matching this file's "empty unless applicable" discipline.
#[test]
fn no_degraded_state_renders_no_new_output() {
    assert_eq!(degraded_suffix(&base_link()), "");
}

/// a degraded link shows its reason.
#[test]
fn degraded_link_shows_its_reason() {
    let mut link = base_link();
    link.degraded = true;
    link.degraded_reason = "insufficient free space to write big.bin".to_string();
    assert_eq!(degraded_suffix(&link), "  degraded (insufficient free space to write big.bin)");
}

/// `Protected` and `Protecting` are both fine to leave as plain "syncing"
/// text -- neither renders the extra durability suffix.
#[test]
fn protected_or_protecting_durability_renders_no_new_output() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Protected as i32;
    assert_eq!(durability_suffix(&link), "");
    link.durability_status = GroupDurabilityStatus::Protecting as i32;
    assert_eq!(durability_suffix(&link), "");
}

/// A group whose coverage cannot currently be confirmed -- e.g. right
/// after a `--force` unlink bypassed the durability handoff gate --
/// must show a distinct "durability unknown" suffix, never plain
/// "syncing" (which would read as fully caught up and safe).
#[test]
fn durability_unknown_renders_its_own_suffix() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Unknown as i32;
    assert_eq!(durability_suffix(&link), "  durability unknown");
}

/// A group with a confirmed missing durable holder renders its own,
/// more severe suffix, distinct from the merely-unconfirmed case above.
#[test]
fn at_risk_durability_renders_its_own_suffix() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::AtRisk as i32;
    assert_eq!(durability_suffix(&link), "  durability: at risk");
}

/// an unset value
/// `Unspecified` (proto3's zero default) -- this must fail safe and
/// render exactly like `Unknown`, never like `Protected`.
#[test]
fn unspecified_durability_fails_safe_like_unknown() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Unspecified as i32;
    assert_eq!(durability_suffix(&link), "  durability unknown");
}

/// A full copy renders no local-storage suffix at all --
/// the common healthy case, same "empty unless applicable" discipline
/// as every other suffix here.
#[test]
fn full_copy_renders_no_local_storage_suffix() {
    let link = base_link();
    assert_eq!(local_storage_suffix(&link), "");
}

/// `Unspecified` must not render identically to `FullCopy`: that would
/// present a link whose local storage the daemon could not determine as
/// a healthy full copy. It must not consult the raw policy string to
/// guess one either -- the CLI and daemon ship together and the control
/// protocol version is checked exactly, so an unset value is the daemon
/// saying it does not know, not an unset-value to accommodate.
#[test]
fn unspecified_local_storage_says_so_rather_than_guessing() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::Unspecified as i32;
    assert_eq!(local_storage_suffix(&link), "  local storage unknown");
    link.materialization_policy = "ondemand".to_string();
    assert_eq!(local_storage_suffix(&link), "  local storage unknown");
}

/// On-demand reads `local_storage_state` directly, not
/// `materialization_policy` string-matching plus raw counts.
#[test]
fn on_demand_renders_hydration_counts() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::OnDemand as i32;
    link.hydrated_count = 3;
    link.placeholder_count = 2;
    link.hydrating_count = 1;
    assert_eq!(local_storage_suffix(&link), "  on-demand (hydrated=3 placeholder=2 hydrating=1)");
}

/// An eager link still catching up must render its own
/// distinct label -- never silently as `FullCopy` (the earlier
/// materialization_policy-string-based reconstruction this replaces
/// would have shown nothing at all here, since it only special-cased
/// "ondemand").
#[test]
fn partially_materialized_renders_its_own_suffix() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::PartiallyMaterialized as i32;
    link.hydrated_count = 5;
    link.placeholder_count = 1;
    link.hydrating_count = 0;
    assert_eq!(
        local_storage_suffix(&link),
        "  making full copy (hydrated=5 placeholder=1 hydrating=0)"
    );
}

/// `AvailableNow` renders no suffix -- the common case.
#[test]
fn available_now_renders_no_fetch_availability_suffix() {
    let link = base_link();
    assert_eq!(fetch_availability_suffix(&link), "");
}

/// `UnavailableNow` must be visible and distinct from
/// `durability_status` -- protected-but-currently-unfetchable is not
/// the same claim as data loss.
#[test]
fn unavailable_now_renders_its_own_suffix() {
    let mut link = base_link();
    link.fetch_availability = FetchAvailability::UnavailableNow as i32;
    assert_eq!(fetch_availability_suffix(&link), "  cannot fetch now");
}

/// `Unknown`, and an unset value,
/// must never render as available.
#[test]
fn unknown_fetch_availability_never_reads_as_available() {
    let mut link = base_link();
    link.fetch_availability = FetchAvailability::Unknown as i32;
    assert_eq!(fetch_availability_suffix(&link), "  fetch availability unknown");
    link.fetch_availability = FetchAvailability::Unspecified as i32;
    assert_eq!(fetch_availability_suffix(&link), "  fetch availability unknown");
}

/// `0` reads as "unlimited" — the shared convention
/// between `status` and `limits show`.
#[test]
fn format_rate_zero_is_unlimited() {
    assert_eq!(format_rate_bytes_per_sec(0), "unlimited");
}

/// non-zero rates scale to a human-readable unit.
#[test]
fn format_rate_scales_to_a_human_readable_unit() {
    assert_eq!(format_rate_bytes_per_sec(500), "500 B/s");
    assert_eq!(format_rate_bytes_per_sec(2048), "2.0 KiB/s");
    assert_eq!(format_rate_bytes_per_sec(5 * 1024 * 1024), "5.0 MiB/s");
    assert_eq!(format_rate_bytes_per_sec(3 * 1024 * 1024 * 1024), "3.0 GiB/s");
}

fn base_status() -> StatusResponse {
    StatusResponse {
        links: vec![],
        peers: vec![],
        upload_limit_bytes_per_sec: 0,
        download_limit_bytes_per_sec: 0,
        current_upload_bytes_per_sec: 0,
        current_download_bytes_per_sec: 0,
        volumes: vec![],
        // `..Default::default` rather than listing every new field
        // explicitly, since this struct literal predates those
        // fields and most tests using this helper don't care about
        // them.
        ..Default::default()
    }
}

/// A healthy, up-to-date status (the default) renders no
/// update-related output at all — matches this file's own "empty
/// unless applicable" discipline.
#[test]
fn no_update_available_renders_no_new_output() {
    assert_eq!(update_summary_lines(&base_status()), Vec::<String>::new());
}

/// spec "Status surfaces available update": an available, non-mandatory
/// update not yet at a safe point/holdback renders as simply available.
#[test]
fn available_update_renders_its_version() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("0.2.0"));
    assert!(lines[0].contains("available"));
}

/// A mandatory update's line says so explicitly, distinct from a
/// merely-available one.
#[test]
fn mandatory_update_says_so() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_mandatory = true;
    let lines = update_summary_lines(&status);
    assert!(lines[0].contains("mandatory"));
}

/// A held-back update shows the holdback reason as a second line.
#[test]
fn held_back_update_shows_its_reason() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_holdback_reason = "staged rollout at 10%".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("held back"));
    assert!(lines[1].contains("staged rollout at 10%"));
}

/// Install waits for a safe point.
#[test]
fn update_waiting_for_safe_point_says_so() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_waiting_for_safe_point = true;
    let lines = update_summary_lines(&status);
    assert!(lines[0].contains("waiting for a safe point"));
}

/// spec "Status surfaces failed update": a recorded update failure is
/// surfaced with a pointer to `update status` for more detail, even
/// with no update currently available.
#[test]
fn update_failure_is_surfaced_with_a_pointer_to_update_status() {
    let mut status = base_status();
    status.update_last_error_category = "update_manifest_fetch_failed".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("update_manifest_fetch_failed"));
    assert!(lines[0].contains("yadorilink update status"));
}

// --- overall-state rendering ---

/// an unset value renders
/// no new output at all.
#[test]
fn empty_overall_state_renders_no_new_output() {
    assert_eq!(overall_state_line(&base_status()), None);
}

#[test]
fn healthy_overall_state_renders_with_no_reasons() {
    let mut status = base_status();
    status.overall_state = "healthy".into();
    assert_eq!(overall_state_line(&status), Some("Overall: healthy".to_string()));
}

#[test]
fn attention_overall_state_renders_its_reasons() {
    let mut status = base_status();
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["conflict:group-1".into(), "low_disk:/data".into()];
    assert_eq!(
        overall_state_line(&status),
        Some("Overall: attention  (conflict:group-1, low_disk:/data)".to_string())
    );
}

/// the limits summary line reports both configured and
/// current rates, `unlimited` when unconfigured.
#[test]
fn limits_summary_line_reports_configured_and_current_rates() {
    let mut status = base_status();
    assert_eq!(
        limits_summary_line(&status),
        "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)"
    );

    status.upload_limit_bytes_per_sec = 1024;
    status.current_download_bytes_per_sec = 2048;
    assert_eq!(
        limits_summary_line(&status),
        "Limits: up=1.0 KiB/s down=unlimited  (current: up=unlimited down=2.0 KiB/s)"
    );
}

fn base_peer() -> PeerStatus {
    PeerStatus {
        device_id: "device-1".into(),
        reachability: PeerReachability::Connected as i32,
        unreachable_category: UnreachableCategory::Unspecified as i32,
        route_kind: RouteKind::Direct as i32,
    }
}

/// A reachable peer shows "connected"; an unreachable one shows
/// "cannot connect" with its failure category.
#[test]
fn connectivity_label_reflects_reachability_and_category() {
    let mut peer = base_peer();
    assert_eq!(peer_connectivity_label(&peer), "connected");

    peer.reachability = PeerReachability::Unreachable as i32;
    peer.unreachable_category = UnreachableCategory::NoResponse as i32;
    assert_eq!(peer_connectivity_label(&peer), "cannot connect (no response)");

    peer.reachability = PeerReachability::Connecting as i32;
    assert_eq!(peer_connectivity_label(&peer), "connecting");
}

/// A peer reachable only through a relay server is connected, and says
/// which path carries it.
#[test]
fn a_relayed_peer_reads_as_connected_via_relay() {
    let mut peer = base_peer();
    peer.route_kind = RouteKind::Relay as i32;
    assert_eq!(peer_connectivity_label(&peer), "connected (via relay)");
}

/// an unset value
/// connected peer -- must still read as plain "connected".
#[test]
fn connected_with_unspecified_route_kind_reads_as_plain_connected() {
    let mut peer = base_peer();
    peer.route_kind = RouteKind::Unspecified as i32;
    assert_eq!(peer_connectivity_label(&peer), "connected");
}

/// a volume line reports path, state, and byte counts.
#[test]
fn volume_line_reports_path_state_and_bytes() {
    let volume = VolumeFreeSpace {
        path: "/tmp/photos".into(),
        state: "low".into(),
        available_bytes: 1500,
        headroom_bytes: 1000,
    };
    assert_eq!(volume_line(&volume), "  /tmp/photos  low  (available=1500 headroom=1000)");
}

/// Byte formatting scales the same way `format_rate_bytes_per_sec`
/// does, minus the `/s` suffix.
#[test]
fn format_bytes_scales_to_a_human_readable_unit() {
    assert_eq!(format_bytes(500), "500 B");
    assert_eq!(format_bytes(2048), "2.0 KiB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
}

/// `0`/negative means "never run" — never rendered as a
/// literal unix-epoch timestamp.
#[test]
fn last_gc_summary_reports_never_when_no_sweep_has_completed() {
    assert_eq!(last_gc_summary(0), "never");
}

/// a recent completion renders as a short relative bucket.
#[test]
fn last_gc_summary_reports_a_relative_bucket_for_a_recent_sweep() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(last_gc_summary(now - 30), "30s ago");
    assert_eq!(last_gc_summary(now - 120), "2m ago");
    assert_eq!(last_gc_summary(now - 7200), "2h ago");
    assert_eq!(last_gc_summary(now - 2 * 86400), "2d ago");
}

/// `status` shows non-zero usage after files are synced
/// (block/byte counts) and reports the last-GC time / reclaimable
/// estimate alongside it — this is the pure-formatting half; the
/// daemon-side wiring is exercised by `control_socket.rs`'s own tests
/// and `yadorilink-cli`'s `tests/` integration suite.
#[test]
fn block_store_summary_line_reports_usage_and_gc_health() {
    let mut status = base_status();
    status.block_store_block_count = 42;
    status.block_store_total_bytes = 5 * 1024 * 1024;
    status.last_gc_unix = 0;
    status.gc_reclaimable_estimate_bytes = 1024;

    let line = block_store_summary_line(&status);

    assert!(line.contains("42 block(s)"));
    assert!(line.contains("5.0 MiB used"));
    assert!(line.contains("last GC: never"));
    assert!(line.contains("~1.0 KiB reclaimable"));
}

// --- progress + recent-error rendering ---

/// "Empty unless applicable" discipline: a link with no
/// active transfer renders no transfer-related suffix at all.
#[test]
fn no_active_transfer_renders_no_new_output() {
    assert_eq!(transfer_progress_suffix(&base_link()), "");
}

/// An active transfer's headline reports a percent,
/// byte/block counts, and a best-effort, explicitly-labelled ETA.
#[test]
fn active_transfer_renders_percent_bytes_blocks_and_eta() {
    let mut link = base_link();
    link.has_active_transfer = true;
    link.transfer_bytes_done = 50;
    link.transfer_bytes_total = 200;
    link.transfer_blocks_done = 1;
    link.transfer_blocks_total = 4;
    link.transfer_eta_seconds = 30;

    let suffix = transfer_progress_suffix(&link);
    assert!(suffix.contains("25%"));
    assert!(suffix.contains("50/200 bytes"));
    assert!(suffix.contains("1/4 blocks"));
    assert!(suffix.contains("eta~30s"));
}

/// an active transfer with no ETA signal yet (best-effort)
/// omits the `eta~` fragment rather than claiming `0s`.
#[test]
fn active_transfer_with_no_eta_signal_omits_the_eta_fragment() {
    let mut link = base_link();
    link.has_active_transfer = true;
    link.transfer_bytes_total = 200;
    link.transfer_eta_seconds = 0;

    assert!(!transfer_progress_suffix(&link).contains("eta~"));
}

/// The per-file active-transfer detail list renders one
/// line per entry, including its source peer.
#[test]
fn active_transfer_detail_lines_render_one_line_per_transfer() {
    let mut status = base_status();
    status.active_transfers = vec![ActiveTransferProgress {
        group_id: "group-1".into(),
        path: "big.bin".into(),
        bytes_done: 100,
        bytes_total: 400,
        blocks_done: 1,
        blocks_total: 4,
        source_peer: "device-b".into(),
        started_at_unix: 0,
    }];

    let lines = active_transfer_detail_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("big.bin"));
    assert!(lines[0].contains("25%"));
    assert!(lines[0].contains("device-b"));
}

/// no active transfers renders no "Active transfers:" detail
/// at all.
#[test]
fn no_active_transfers_renders_no_detail_lines() {
    assert!(active_transfer_detail_lines(&base_status()).is_empty());
}

/// Recent errors render their category and coarse
/// context — never anything beyond what the daemon already redacted.
#[test]
fn recent_errors_render_category_and_coarse_context() {
    let mut status = base_status();
    status.recent_errors = vec![RecentSyncError {
        category: "disk_pressure".into(),
        timestamp_unix: 12345,
        coarse_context: "hydration".into(),
    }];

    let lines = recent_errors_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("disk_pressure"));
    assert!(lines[0].contains("hydration"));
}

#[test]
fn no_recent_errors_renders_no_new_output() {
    assert!(recent_errors_summary_lines(&base_status()).is_empty());
}

/// A folder group linked at two folders syncs NOTHING until the user
/// unlinks all but one. Without this the refusal exists only as a daemon
/// log line: loud in the code, invisible to the person who has to act on
/// it, who would see a folder that had silently stopped syncing.
#[test]
fn an_ambiguous_link_says_it_is_not_syncing_and_names_every_folder() {
    let link = LinkStatus {
        ambiguous: true,
        ambiguous_local_paths: vec!["/Users/alice/A".into(), "/Users/alice/B".into()],
        ..base_link()
    };

    let suffix = ambiguous_suffix(&link);

    assert!(suffix.contains("NOT SYNCING"), "got {suffix:?}");
    // The paths are the remedy, not decoration: unlinking is keyed by path.
    assert!(suffix.contains("/Users/alice/A"), "got {suffix:?}");
    assert!(suffix.contains("/Users/alice/B"), "got {suffix:?}");
}

/// Same "empty unless applicable" discipline as every other suffix here: a
/// healthy link's line must be unaffected by this state existing.
#[test]
fn a_healthy_link_renders_no_ambiguity_suffix() {
    assert_eq!(ambiguous_suffix(&base_link()), "");
}

/// One whole `yadorilink status` rendering of an empty daemon, pinned line by
/// line: no folders, the limits and block-store summaries after a blank line.
#[test]
fn status_lines_for_an_empty_daemon_are_pinned_verbatim() {
    assert_eq!(
        status_lines(&base_status()),
        vec![
            "No linked folders.",
            "",
            "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)",
            "Block store: 0 block(s), 0 B used  (last GC: never, ~0 B reclaimable)",
        ]
    );
}

/// One whole rendering with a folder, a peer, an available update and a
/// recent error, pinned line by line so the order of the sections is fixed.
#[test]
fn status_lines_for_a_busy_daemon_are_pinned_verbatim() {
    let mut status = base_status();
    status.links.push(base_link());
    status.peers.push(PeerStatus { device_id: "peer-1".into(), ..Default::default() });
    status.update_available_version = "0.2.0".into();
    status
        .recent_errors
        .push(RecentSyncError { category: "disk_full".into(), ..Default::default() });
    assert_eq!(
        status_lines(&status),
        vec![
            "/tmp/photos  group=group-1  syncing  conflicts=0",
            "",
            "Peers:",
            "  peer-1  unknown",
            "",
            "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)",
            "Block store: 0 block(s), 0 B used  (last GC: never, ~0 B reclaimable)",
            "",
            "Update: 0.2.0 (available)",
            "",
            "Recent errors:",
            "  disk_full  ()  0",
        ]
    );
}
