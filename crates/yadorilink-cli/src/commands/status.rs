use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    LinkStatus, PeerStatus, StatusRequest, StatusResponse, VolumeFreeSpace,
};

use crate::control_client;
use crate::error::CliError;

/// add-sync-fidelity task 6.1: the `  held=N` suffix appended to a link's
/// summary line — empty (rendering no suffix at all) when the link has no
/// held files, so an unaffected link's `status` output is byte-for-byte
/// unchanged from before this task (task 6.3's "no new fields rendered
/// when a link has none"). Factored out as a pure function (matching
/// `yadorilink_daemon`'s and `yadorilink_sync_core`'s established pattern
/// of pulling formatting/decision logic out of the `println!`-driven
/// command body — see `report.rs`'s `confirm_with_reader`) so it's
/// directly unit-testable without capturing real process stdout.
fn held_summary_suffix(link: &LinkStatus) -> String {
    if link.held_file_count == 0 {
        String::new()
    } else {
        format!("  held={}", link.held_file_count)
    }
}

/// add-sync-fidelity task 6.1: one indented detail line per held file
/// (path and reason), printed directly beneath a link's summary line.
/// Empty when the link has no held files (task 6.3).
fn held_file_detail_lines(link: &LinkStatus) -> Vec<String> {
    link.held_files.iter().map(|h| format!("    held: {}  ({})", h.path, h.reason)).collect()
}

/// add-resource-governance task 5.4: the `  degraded (<reason>)` suffix —
/// same "empty unless applicable" discipline as `held_summary_suffix`, so
/// a healthy link's output line is unaffected by this feature existing.
fn degraded_suffix(link: &LinkStatus) -> String {
    if link.degraded {
        format!("  degraded ({})", link.degraded_reason)
    } else {
        String::new()
    }
}

/// add-folder-direction-modes task 4.3: same rendering `link.rs`'s `list`
/// command uses (kept as separate free functions per-module rather than a
/// shared helper, matching this pair's own existing precedent —
/// `held_summary_suffix` here vs. `skipped_symlink_suffix` there are
/// likewise independent, module-local implementations of the same "empty
/// unless applicable" idea, not something this codebase currently
/// factors into a shared crate-level formatting module).
fn mode_suffix(link: &LinkStatus) -> String {
    if link.mode.is_empty() || link.mode == "send_receive" {
        String::new()
    } else {
        format!("  mode={}", link.mode.replace('_', "-"))
    }
}

fn divergence_suffix(link: &LinkStatus) -> String {
    let mut parts = Vec::new();
    if link.out_of_sync_count > 0 {
        parts.push(format!("out_of_sync={}", link.out_of_sync_count));
    }
    if link.receive_only_changed_count > 0 {
        parts.push(format!("receive_only_changed={}", link.receive_only_changed_count));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  {}", parts.join(" "))
    }
}

/// add-resource-governance task 5.4: `0` reads as "unlimited" (matching
/// `limits show`'s own convention — task 5.3); otherwise a human-scaled
/// `B/s`/`KiB/s`/`MiB/s`/`GiB/s` value.
pub(crate) fn format_rate_bytes_per_sec(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        return "unlimited".to_string();
    }
    const UNITS: [&str; 4] = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
    let mut value = bytes_per_sec as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes_per_sec} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// add-desktop-status-app task 1.3: renders `StatusResponse.overall_state`/
/// `attention_reasons` — the same daemon-computed rollup the desktop
/// status app's tray label reads (`yadorilink-desktop-app`'s
/// `status_model::headline` calls the identical fields) — as `status`'s
/// first line, giving the CLI parity the desktop-status-app spec's
/// "App status is testable without UI automation" scenario asks for: an
/// automated test (or a user) can read the same aggregate state from the
/// CLI without any UI. Empty `overall_state` (an old daemon predating this
/// field) renders nothing at all, matching this file's "absent = no new
/// output" convention for every other additive field.
fn overall_state_line(status: &StatusResponse) -> Option<String> {
    if status.overall_state.is_empty() {
        return None;
    }
    if status.attention_reasons.is_empty() {
        Some(format!("Overall: {}", status.overall_state))
    } else {
        Some(format!(
            "Overall: {}  ({})",
            status.overall_state,
            status.attention_reasons.join(", ")
        ))
    }
}

/// task 5.4: `yadorilink status`'s configured-limits/current-rate summary
/// line.
fn limits_summary_line(status: &StatusResponse) -> String {
    format!(
        "Limits: up={} down={}  (current: up={} down={})",
        format_rate_bytes_per_sec(status.upload_limit_bytes_per_sec),
        format_rate_bytes_per_sec(status.download_limit_bytes_per_sec),
        format_rate_bytes_per_sec(status.current_upload_bytes_per_sec),
        format_rate_bytes_per_sec(status.current_download_bytes_per_sec),
    )
}

/// add-untrusted-storage-peer task 4.3: the ` [storage-only]` suffix for a
/// peer flagged ciphertext-only (`PeerStatus.storage_only`) — same "empty
/// unless applicable" discipline as `held_summary_suffix`, so an unflagged
/// peer's line is unaffected by this feature existing. Forward-compatible
/// rendering only: the daemon does not populate `storage_only` yet (a
/// documented, out-of-scope-for-this-change follow-up — the coordination
/// plane and wire type already carry the flag, but nothing on the daemon
/// side threads a peer's flag into `PeerStatus` yet), so every existing
/// `status` output renders this as empty/false today; only a future
/// daemon-side change will actually cause the badge to appear, with no CLI
/// change needed at that point.
fn storage_only_suffix(peer: &PeerStatus) -> String {
    if peer.storage_only {
        "  [storage-only]".to_string()
    } else {
        String::new()
    }
}

/// task 5.4: one line per volume's free-space state.
fn volume_line(volume: &VolumeFreeSpace) -> String {
    format!(
        "  {}  {}  (available={} headroom={})",
        volume.path, volume.state, volume.available_bytes, volume.headroom_bytes
    )
}

/// add-block-store-gc task 5.2: byte-count formatter, shared in shape with
/// `format_rate_bytes_per_sec` above minus the `/s` suffix — block-store
/// usage and the reclaimable estimate are point-in-time totals, not rates.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// task 5.2: a relative "how long ago" for `StatusResponse.last_gc_unix` —
/// "never" if a real (non-dry-run) sweep has never completed since this
/// daemon's block store was created (`0`, matching `GcState`'s own "0 = no
/// completed sweep" convention).
fn last_gc_summary(last_gc_unix: i64) -> String {
    if last_gc_unix <= 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let elapsed = (now - last_gc_unix).max(0);
    if elapsed < 60 {
        format!("{elapsed}s ago")
    } else if elapsed < 3600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86400 {
        format!("{}h ago", elapsed / 3600)
    } else {
        format!("{}d ago", elapsed / 86400)
    }
}

/// task 5.2: `yadorilink status`'s block-store usage/GC-health summary
/// line — always rendered (unlike this file's "empty unless applicable"
/// suffixes), since usage/last-GC-time is always meaningful, matching
/// `limits_summary_line`'s own "always shown" precedent immediately above.
fn block_store_summary_line(status: &StatusResponse) -> String {
    format!(
        "Block store: {} block(s), {} used  (last GC: {}, ~{} reclaimable)",
        status.block_store_block_count,
        format_bytes(status.block_store_total_bytes),
        last_gc_summary(status.last_gc_unix),
        format_bytes(status.gc_reclaimable_estimate_bytes),
    )
}

/// add-observability-and-metrics task 1.2/4.1: this link's active-transfer
/// headline — empty unless `has_active_transfer` (this file's established
/// "empty unless applicable" discipline, matching `degraded_suffix`/
/// `held_summary_suffix`). The ETA is explicitly labelled `~` (best-effort,
/// design.md) rather than presented as precise.
fn transfer_progress_suffix(link: &LinkStatus) -> String {
    if !link.has_active_transfer {
        return String::new();
    }
    let pct = if link.transfer_bytes_total > 0 {
        (link.transfer_bytes_done as f64 / link.transfer_bytes_total as f64 * 100.0).round() as u64
    } else {
        0
    };
    let eta = if link.transfer_eta_seconds > 0 {
        format!(" eta~{}s", link.transfer_eta_seconds)
    } else {
        String::new()
    };
    format!(
        "  transferring {pct}% ({}/{} bytes, {}/{} blocks){eta}",
        link.transfer_bytes_done,
        link.transfer_bytes_total,
        link.transfer_blocks_done,
        link.transfer_blocks_total,
    )
}

/// task 1.3/4.1: one line per currently-active transfer — the per-file
/// detail underlying every link's headline `transfer_progress_suffix`.
fn active_transfer_detail_lines(status: &StatusResponse) -> Vec<String> {
    status
        .active_transfers
        .iter()
        .map(|t| {
            let pct = if t.bytes_total > 0 {
                (t.bytes_done as f64 / t.bytes_total as f64 * 100.0).round() as u64
            } else {
                0
            };
            format!(
                "  {}  {pct}%  ({}/{} bytes, {}/{} blocks)  from={}",
                t.path, t.bytes_done, t.bytes_total, t.blocks_done, t.blocks_total, t.source_peer
            )
        })
        .collect()
}

/// task 2.2/4.1: the bounded recent-error feed, newest first (matching the
/// daemon's own `RecentErrorLog::recent` ordering) — every field here is
/// already a coarse category/timestamp/context string (never a path/key/
/// token/IP, task 2.1's redaction requirement), so this renders it as-is.
fn recent_errors_summary_lines(status: &StatusResponse) -> Vec<String> {
    status
        .recent_errors
        .iter()
        .map(|e| format!("  {}  ({})  {}", e.category, e.coarse_context, e.timestamp_unix))
        .collect()
}

/// add-automatic-updates task 5.5: concise update-state lines for
/// `yadorilink status`, only rendered when there's something worth
/// surfacing (spec "Status surfaces available update"/"Status surfaces
/// failed update") — a healthy, up-to-date daemon's `status` output is
/// otherwise unaffected by this feature existing, matching this file's
/// own "empty unless applicable" convention (`held_summary_suffix`,
/// `degraded_suffix`, ...).
fn update_summary_lines(status: &StatusResponse) -> Vec<String> {
    let mut lines = Vec::new();
    if !status.update_available_version.is_empty() {
        let install_plan = if status.update_mandatory {
            "will install automatically (mandatory security/compatibility update)"
        } else if status.update_waiting_for_safe_point {
            "waiting for a safe point to install"
        } else if !status.update_holdback_reason.is_empty() {
            "held back"
        } else {
            "available"
        };
        lines.push(format!("Update: {} ({install_plan})", status.update_available_version));
        if !status.update_holdback_reason.is_empty() {
            lines.push(format!("  {}", status.update_holdback_reason));
        }
    }
    if !status.update_last_error_category.is_empty() {
        lines.push(format!(
            "Update error: {}  (see `yadorilink update status` for details)",
            status.update_last_error_category
        ));
    }
    lines
}

/// add-observability-and-metrics task 4.1: `yadorilink status`, optionally
/// re-polling and re-rendering on an interval (`--watch`) instead of
/// printing one snapshot and exiting — useful for watching a big sync's
/// per-transfer progress live rather than re-running the command by hand.
/// A plain `yadorilink status` (`watch = false`) is byte-for-byte the same
/// single-snapshot behavior as before this flag existed.
pub async fn status(watch: bool) -> Result<(), CliError> {
    if !watch {
        return render_status_once().await;
    }
    loop {
        render_status_once().await?;
        println!();
        println!("--- refreshing every 2s (Ctrl-C to stop) ---");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn render_status_once() -> Result<(), CliError> {
    let resp = control_client::send(ReqPayload::Status(StatusRequest {})).await?;
    let Some(RespPayload::Status(status)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };

    if let Some(line) = overall_state_line(&status) {
        println!("{line}");
        println!();
    }

    if status.links.is_empty() {
        println!("No linked folders.");
    }
    for link in &status.links {
        let state = if link.paused { "paused" } else { "syncing" };
        let materialization = if link.materialization_policy == "ondemand" {
            format!(
                "  on-demand (hydrated={} placeholder={} hydrating={})",
                link.hydrated_count, link.placeholder_count, link.hydrating_count
            )
        } else {
            String::new()
        };
        let held = held_summary_suffix(link);
        let degraded = degraded_suffix(link);
        let mode = mode_suffix(link);
        let divergence = divergence_suffix(link);
        let transfer = transfer_progress_suffix(link);
        println!(
            "{}  group={}  {state}  conflicts={}{materialization}{held}{degraded}{mode}{divergence}{transfer}",
            link.local_path, link.group_id, link.conflict_count
        );
        for line in held_file_detail_lines(link) {
            println!("{line}");
        }
    }

    if !status.peers.is_empty() {
        println!();
        println!("Peers:");
        for peer in &status.peers {
            let connectivity =
                if peer.connected { peer.path_kind.as_str() } else { "disconnected" };
            let storage_only = storage_only_suffix(peer);
            println!("  {}  {connectivity}{storage_only}", peer.device_id);
        }
    }

    let transfer_lines = active_transfer_detail_lines(&status);
    if !transfer_lines.is_empty() {
        println!();
        println!("Active transfers:");
        for line in transfer_lines {
            println!("{line}");
        }
    }

    println!();
    println!("{}", limits_summary_line(&status));
    println!("{}", block_store_summary_line(&status));

    if !status.volumes.is_empty() {
        println!("Volumes:");
        for volume in &status.volumes {
            println!("{}", volume_line(volume));
        }
    }

    let update_lines = update_summary_lines(&status);
    if !update_lines.is_empty() {
        println!();
        for line in update_lines {
            println!("{line}");
        }
    }

    let error_lines = recent_errors_summary_lines(&status);
    if !error_lines.is_empty() {
        println!();
        println!("Recent errors:");
        for line in error_lines {
            println!("{line}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use yadorilink_ipc_proto::daemonctl::{ActiveTransferProgress, HeldFile, RecentSyncError};

    use super::*;

    fn base_link() -> LinkStatus {
        LinkStatus {
            local_path: "/tmp/photos".into(),
            group_id: "group-1".into(),
            paused: false,
            pending_changes: 0,
            conflict_count: 0,
            materialization_policy: "eager".into(),
            hydrated_count: 0,
            placeholder_count: 0,
            hydrating_count: 0,
            open_elsewhere_count: 0,
            chunking_policy: "fixed".into(),
            held_file_count: 0,
            held_files: vec![],
            skipped_symlink_count: 0,
            degraded: false,
            degraded_reason: String::new(),
            mode: "send_receive".into(),
            out_of_sync_count: 0,
            receive_only_changed_count: 0,
            has_active_transfer: false,
            transfer_bytes_done: 0,
            transfer_bytes_total: 0,
            transfer_blocks_done: 0,
            transfer_blocks_total: 0,
            transfer_eta_seconds: 0,
        }
    }

    /// add-folder-direction-modes task 4.3: mode/divergence rendering
    /// mirrors `link.rs`'s own tests for the identical formatting logic.
    #[test]
    fn send_receive_mode_and_no_divergence_render_no_new_output() {
        let link = base_link();
        assert_eq!(mode_suffix(&link), "");
        assert_eq!(divergence_suffix(&link), "");
    }

    #[test]
    fn non_default_mode_and_divergence_counts_render() {
        let mut link = base_link();
        link.mode = "send_only".into();
        link.out_of_sync_count = 4;
        assert_eq!(mode_suffix(&link), "  mode=send-only");
        assert_eq!(divergence_suffix(&link), "  out_of_sync=4");
    }

    /// task 6.3: a link with no held files renders no held-related output
    /// at all — no `held=0` suffix, no detail lines.
    #[test]
    fn no_held_files_renders_no_new_output() {
        let link = base_link();
        assert_eq!(held_summary_suffix(&link), "");
        assert!(held_file_detail_lines(&link).is_empty());
    }

    /// task 6.1: a link with held files shows the count and, for each
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

    /// add-resource-governance task 5.4/task 6.3-style discipline: a
    /// healthy (non-degraded) link renders no degraded-related output.
    #[test]
    fn no_degraded_state_renders_no_new_output() {
        assert_eq!(degraded_suffix(&base_link()), "");
    }

    /// task 5.4: a degraded link shows its reason.
    #[test]
    fn degraded_link_shows_its_reason() {
        let mut link = base_link();
        link.degraded = true;
        link.degraded_reason = "insufficient free space to write big.bin".to_string();
        assert_eq!(degraded_suffix(&link), "  degraded (insufficient free space to write big.bin)");
    }

    /// task 5.3/5.4: `0` reads as "unlimited" — the shared convention
    /// between `status` and `limits show`.
    #[test]
    fn format_rate_zero_is_unlimited() {
        assert_eq!(format_rate_bytes_per_sec(0), "unlimited");
    }

    /// task 5.4: non-zero rates scale to a human-readable unit.
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
            // add-automatic-updates: `..Default::default()` rather than
            // listing every new field explicitly, since this struct
            // literal predates those fields and most tests using this
            // helper don't care about them.
            ..Default::default()
        }
    }

    /// add-automatic-updates task 5.5/5.6: a healthy, up-to-date status
    /// (the pre-this-change default) renders no update-related output at
    /// all — matches this file's own "empty unless applicable" discipline.
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

    /// design.md "Mandatory security update is surfaced": a mandatory
    /// update's line says so explicitly, distinct from a merely-available one.
    #[test]
    fn mandatory_update_says_so() {
        let mut status = base_status();
        status.update_available_version = "0.2.0".into();
        status.update_mandatory = true;
        let lines = update_summary_lines(&status);
        assert!(lines[0].contains("mandatory"));
    }

    /// design.md "Rollout holdback prevents install": a held-back update
    /// shows the holdback reason as a second line.
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

    /// design.md "Install waits for safe point".
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

    // --- add-desktop-status-app task 1.3: overall-state rendering ---

    /// An old daemon that predates `overall_state` (empty string) renders
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

    /// task 5.4: the limits summary line reports both configured and
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
            connected: true,
            path_kind: "direct".into(),
            storage_only: false,
        }
    }

    /// add-untrusted-storage-peer task 4.3: an unflagged peer (today's
    /// only real case, since the daemon doesn't populate the field yet)
    /// renders no new output.
    #[test]
    fn no_storage_only_flag_renders_no_new_output() {
        assert_eq!(storage_only_suffix(&base_peer()), "");
    }

    /// A peer flagged storage-only renders the `[storage-only]` badge —
    /// forward-compatible for once the daemon starts populating this
    /// field.
    #[test]
    fn storage_only_peer_renders_badge() {
        let mut peer = base_peer();
        peer.storage_only = true;
        assert_eq!(storage_only_suffix(&peer), "  [storage-only]");
    }

    /// task 5.4: a volume line reports path, state, and byte counts.
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

    /// add-block-store-gc task 5.2/5.3: byte formatting scales the same
    /// way `format_rate_bytes_per_sec` does, minus the `/s` suffix.
    #[test]
    fn format_bytes_scales_to_a_human_readable_unit() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    /// task 5.2: `0`/negative means "never run" — never rendered as a
    /// literal unix-epoch timestamp.
    #[test]
    fn last_gc_summary_reports_never_when_no_sweep_has_completed() {
        assert_eq!(last_gc_summary(0), "never");
    }

    /// task 5.2: a recent completion renders as a short relative bucket.
    #[test]
    fn last_gc_summary_reports_a_relative_bucket_for_a_recent_sweep() {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
                as i64;
        assert_eq!(last_gc_summary(now - 30), "30s ago");
        assert_eq!(last_gc_summary(now - 120), "2m ago");
        assert_eq!(last_gc_summary(now - 7200), "2h ago");
        assert_eq!(last_gc_summary(now - 2 * 86400), "2d ago");
    }

    /// task 5.2/5.3: `status` shows non-zero usage after files are synced
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

    // --- add-observability-and-metrics task 1.3/2.2/4.1: progress + recent-error rendering ---

    /// task 4.1's "empty unless applicable" discipline: a link with no
    /// active transfer renders no transfer-related suffix at all.
    #[test]
    fn no_active_transfer_renders_no_new_output() {
        assert_eq!(transfer_progress_suffix(&base_link()), "");
    }

    /// task 1.2/4.1: an active transfer's headline reports a percent,
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

    /// task 4.1: an active transfer with no ETA signal yet (design.md:
    /// "best-effort") omits the `eta~` fragment rather than claiming `0s`.
    #[test]
    fn active_transfer_with_no_eta_signal_omits_the_eta_fragment() {
        let mut link = base_link();
        link.has_active_transfer = true;
        link.transfer_bytes_total = 200;
        link.transfer_eta_seconds = 0;

        assert!(!transfer_progress_suffix(&link).contains("eta~"));
    }

    /// task 1.3/4.1: the per-file active-transfer detail list renders one
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

    /// task 4.1: no active transfers renders no "Active transfers:" detail
    /// at all.
    #[test]
    fn no_active_transfers_renders_no_detail_lines() {
        assert!(active_transfer_detail_lines(&base_status()).is_empty());
    }

    /// task 2.2/4.1: recent errors render their category and coarse
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
}
