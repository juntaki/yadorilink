use yadorilink_ipc_proto::daemonctl::{
    FetchAvailability, GroupDurabilityStatus, LinkStatus, LocalStorageState, PeerReachability,
    PeerStatus, RouteKind, StatusResponse, UnreachableCategory, VolumeFreeSpace,
};

use crate::error::CliError;

/// The ` held=N` suffix appended to a link's summary line — empty
/// (rendering no suffix at all) when the link has no held files, so an
/// unaffected link's `status` output is byte-for-byte unchanged from
/// before this functionality was added (to ensure "no new fields rendered
/// when a link has none").
fn held_summary_suffix(link: &LinkStatus) -> String {
    if link.held_file_count == 0 {
        String::new()
    } else {
        format!("  held={}", link.held_file_count)
    }
}

/// One indented detail line per held file (path and reason), printed
/// directly beneath a link's summary line. Empty when the link has no
/// held files.
fn held_file_detail_lines(link: &LinkStatus) -> Vec<String> {
    link.held_files.iter().map(|h| format!("    held: {}  ({})", h.path, h.reason)).collect()
}

/// One `    configured full copy: <device>  (available|offline|unknown)`
/// line per device in `link.full_replica_device_ids`.
///
/// Deliberately says "configured full copy," never "complete copy" --
/// `full_replica_device_ids` is a netmap-derived, CONTENT-BLIND
/// structural declaration (see `PeerAuthorityState::full_replica_devices_
/// for_group`'s own doc comment: "a device is DECLARED a full-replica
/// writer"), not the peer-confirmed content custody `durability_status`
/// (via `custody_confirmation_cache`) actually verifies. Labeling a
/// merely-declared, possibly-never-confirmed, still-catching-up peer
/// "complete copy (available)" would read as a stronger durability claim
/// than this daemon can back up -- exactly the kind of per-device
/// overclaim `durability_status` already exists to guard against at the
/// group level. This list is
/// connectivity-layer inventory ONLY; `durability_status` remains the
/// sole source of truth for whether the group is actually protected.
///
/// Per-device state: `available` requires the SAME device to appear in
/// `peers` with `Connected` reachability; `offline` requires it to
/// appear with an explicit `Unreachable` reachability (a POSITIVELY
/// known-down fact); anything else -- absent from `peers` entirely,
/// `Unspecified` or `Connecting` -- reads
/// `unknown`, since this daemon has no positive evidence either way for
/// those (an earlier version
/// conflated "never observed" with "known offline").
fn complete_copies_detail_lines(link: &LinkStatus, peers: &[PeerStatus]) -> Vec<String> {
    link.full_replica_device_ids
        .iter()
        .map(|device_id| {
            let reachability =
                peers.iter().find(|p| &p.device_id == device_id).map(|p| p.reachability());
            let state = match reachability {
                Some(PeerReachability::Connected) => "available",
                Some(PeerReachability::Unreachable) => "offline",
                _ => "unknown",
            };
            format!("    configured full copy: {device_id}  ({state})")
        })
        .collect()
}

/// The ` degraded (<reason>)` suffix — same "empty unless applicable"
/// discipline as `held_summary_suffix`, so a healthy link's output line
/// is unaffected by this feature existing.
fn degraded_suffix(link: &LinkStatus) -> String {
    if link.degraded {
        format!("  degraded ({})", link.degraded_reason)
    } else {
        String::new()
    }
}

/// The `NOT SYNCING (this folder group is linked at N folders)` suffix — same
/// "empty unless applicable" discipline as `degraded_suffix`.
///
/// This state is not a degradation, it is a full stop: the group syncs nothing
/// at all until the user unlinks all but one of the folders. Without this the
/// refusal is a `tracing` line — loud in the daemon's log, invisible to the
/// person who has to act on it, who would see only a folder that has silently
/// stopped syncing.
///
/// Names every folder involved because unlinking is keyed by path: the paths
/// are the remedy, not decoration.
fn ambiguous_suffix(link: &LinkStatus) -> String {
    if !link.ambiguous {
        return String::new();
    }
    format!(
        "  NOT SYNCING (this folder group is linked at {} folders: {}; \
         unlink all but one to resume)",
        link.ambiguous_local_paths.len(),
        link.ambiguous_local_paths.join(", ")
    )
}

/// The ` durability unknown`/` durability: at risk` suffix — same
/// "empty unless applicable" discipline as `degraded_suffix`, but
/// deliberately the other way around: it renders *nothing extra* only for
/// the two states that are safe to leave as plain "syncing" text
/// (`Protected`, `Protecting`). an unset value always sends
/// `Unspecified`, which is treated exactly like `Unknown` here —
/// never silently shown as fine — so a link can never read as more durable
/// than this daemon can actually back up right now (most notably right
/// after a `--force` override bypassed the durability handoff gate for this
/// group).
fn durability_suffix(link: &LinkStatus) -> String {
    match link.durability_status() {
        GroupDurabilityStatus::Protected | GroupDurabilityStatus::Protecting => String::new(),
        GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
            "  durability unknown".to_string()
        }
        GroupDurabilityStatus::AtRisk => "  durability: at risk".to_string(),
    }
}

/// The ` on-demand (...)` suffix -- reads `link.
/// local_storage_state()` directly, the daemon's own TRUTHFUL derivation
/// (materialization policy AND actual current hydration state), rather
/// than reconstructing an equivalent judgment here from
/// `materialization_policy` plus the raw hydration counts (the earlier
/// version of this function did exactly that, string-comparing
/// `materialization_policy == "ondemand"` -- the anti-pattern the storage-state
/// model exists to eliminate). `PartiallyMaterialized` gets its own distinct
/// label rather than silently reading as either `FullCopy` or `OnDemand`:
/// an eager link still catching up is neither.
///
/// `Unspecified` an unset value
/// falls back to the raw `materialization_policy` string check ONLY for
/// this one legacy case -- rendering it identically to `FullCopy` would
/// silently drop the on-demand indicator for such a daemon. This is a
/// narrow, explicitly-scoped
/// compatibility fallback, not a reversion to reconstructing state from
/// raw fields for the common (current-daemon) case above.
fn local_storage_suffix(link: &LinkStatus) -> String {
    match link.local_storage_state() {
        LocalStorageState::FullCopy => String::new(),
        LocalStorageState::OnDemand => format!(
            "  on-demand (hydrated={} placeholder={} hydrating={})",
            link.hydrated_count, link.placeholder_count, link.hydrating_count
        ),
        LocalStorageState::PartiallyMaterialized => format!(
            "  making full copy (hydrated={} placeholder={} hydrating={})",
            link.hydrated_count, link.placeholder_count, link.hydrating_count
        ),
        // The daemon always sets this; the CLI and daemon ship together and
        // the control protocol version is checked exactly. An unset value is
        // therefore state the daemon could not determine, which is worth
        // saying rather than rendering as a healthy full copy.
        LocalStorageState::Unspecified => "  local storage unknown".to_string(),
    }
}

/// The ` cannot fetch now`/` fetch availability unknown` suffix --
/// reads `link.fetch_availability()` directly, NEVER reconstructed from
/// peer reachability (that would make it a bare alias for connectivity,
/// exactly what this field exists to NOT be). Silent for `AvailableNow`,
/// the common case, same "empty unless applicable" discipline as
/// `degraded_suffix`. `Unspecified` an unset value reads
/// the same as `Unknown`, never as available.
fn fetch_availability_suffix(link: &LinkStatus) -> String {
    match link.fetch_availability() {
        FetchAvailability::AvailableNow => String::new(),
        FetchAvailability::UnavailableNow => "  cannot fetch now".to_string(),
        FetchAvailability::Unknown | FetchAvailability::Unspecified => {
            "  fetch availability unknown".to_string()
        }
    }
}

/// `0` reads as "unlimited" (matching `limits show`'s own convention);
/// otherwise a human-scaled `B/s`/`KiB/s`/`MiB/s`/`GiB/s`
/// value.
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

/// Renders `StatusResponse.overall_state`/`attention_reasons` — the same
/// daemon-computed rollup the desktop status app's tray label reads
/// (`yadorilink-desktop-app`'s `status_model::headline` calls the
/// identical fields) — as `status`'s first line, giving the CLI parity
/// the desktop-status-app spec's "App status is testable without UI
/// automation" scenario asks for: an automated test (or a user) can read
/// the same aggregate state from the CLI without any UI. Empty
/// `overall_state` an unset value renders nothing
/// at all, matching this file's "absent = no new output" convention for
/// every other additive field.
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

/// `yadorilink status`'s configured-limits/current-rate summary
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

/// How a peer's connectivity is shown. A peer is either being connected,
/// connected (directly, or through a relay server when no direct path is
/// up), or honestly cannot be connected — in which case the reason (its
/// failure category) is shown so the user understands why. A daemon that has
/// not yet determined a peer's reachability leaves it unspecified, shown as
/// "unknown".
fn peer_connectivity_label(peer: &PeerStatus) -> String {
    match peer.reachability() {
        PeerReachability::Connected if peer.route_kind() == RouteKind::Relay => {
            "connected (via relay)".to_string()
        }
        PeerReachability::Connected => "connected".to_string(),
        PeerReachability::Connecting => "connecting".to_string(),
        PeerReachability::Unreachable => {
            format!("cannot connect ({})", unreachable_category_label(peer.unreachable_category()))
        }
        PeerReachability::Unspecified => "unknown".to_string(),
    }
}

/// Human-readable form of a `PeerStatus.unreachable_category`.
fn unreachable_category_label(category: UnreachableCategory) -> &'static str {
    match category {
        UnreachableCategory::NoCandidates => "no known address",
        UnreachableCategory::NoResponse => "no response",
        UnreachableCategory::UdpBlocked => "UDP blocked",
        UnreachableCategory::HandshakeRefused => "handshake refused",
        UnreachableCategory::Unspecified => "unknown reason",
    }
}

/// one line per volume's free-space state.
fn volume_line(volume: &VolumeFreeSpace) -> String {
    format!(
        "  {}  {}  (available={} headroom={})",
        volume.path, volume.state, volume.available_bytes, volume.headroom_bytes
    )
}

/// Byte-count formatter, shared in shape with `format_rate_bytes_per_sec`
/// above minus the `/s` suffix — block-store usage and the reclaimable
/// estimate are point-in-time totals, not rates.
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

/// a relative "how long ago" for `StatusResponse.last_gc_unix` —
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

/// `yadorilink status`'s block-store usage/GC-health summary
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

/// This link's active-transfer headline — empty unless
/// `has_active_transfer` (this file's established "empty unless
/// applicable" discipline, matching `degraded_suffix`/
/// `held_summary_suffix`). The ETA is explicitly labelled `~`
/// (best-effort) rather than presented as precise.
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

/// One line per currently-active transfer — the per-file
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

/// The bounded recent-error feed, newest first (matching the
/// daemon's own `RecentErrorLog::recent` ordering) — every field here is
/// already a coarse category/timestamp/context string (never a path/key/
/// token/IP, satisfying redaction requirements), so this renders it as-is.
fn recent_errors_summary_lines(status: &StatusResponse) -> Vec<String> {
    status
        .recent_errors
        .iter()
        .map(|e| format!("  {}  ({})  {}", e.category, e.coarse_context, e.timestamp_unix))
        .collect()
}

/// Concise update-state lines for `yadorilink status`, only rendered
/// when there's something worth surfacing (spec "Status surfaces
/// available update"/"Status surfaces failed update") — a healthy,
/// up-to-date daemon's `status` output is otherwise unaffected by this
/// feature existing, matching this file's own "empty unless applicable"
/// convention (`held_summary_suffix`, `degraded_suffix`,...).
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

/// `yadorilink status`, optionally re-polling and re-rendering on an
/// interval (`--watch`) instead of printing one snapshot and exiting —
/// useful for watching a big sync's per-transfer progress live rather
/// than re-running the command by hand. A plain `yadorilink status`
/// (`watch = false`) is byte-for-byte the same single-snapshot behavior
/// as before this flag existed.
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
    let status = yadorilink_client_core::ops::folders::status().await?;
    for line in status_lines(&status) {
        println!("{line}");
    }
    Ok(())
}

/// Every line one `yadorilink status` rendering prints, in order.
fn status_lines(status: &StatusResponse) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(line) = overall_state_line(status) {
        lines.push(line);
        lines.push(String::new());
    }

    if status.links.is_empty() {
        lines.push("No linked folders.".to_string());
    }
    for link in &status.links {
        let state = if link.paused { "paused" } else { "syncing" };
        let materialization = local_storage_suffix(link);
        let held = held_summary_suffix(link);
        let degraded = degraded_suffix(link);
        let transfer = transfer_progress_suffix(link);
        let durability = durability_suffix(link);
        let fetch_availability = fetch_availability_suffix(link);
        let ambiguous = ambiguous_suffix(link);
        lines.push(format!(
            "{}  group={}  {state}  conflicts={}{materialization}{held}{degraded}{transfer}{durability}{fetch_availability}{ambiguous}",
            link.local_path, link.group_id, link.conflict_count
        ));
        lines.extend(held_file_detail_lines(link));
        lines.extend(complete_copies_detail_lines(link, &status.peers));
    }

    if !status.peers.is_empty() {
        lines.push(String::new());
        lines.push("Peers:".to_string());
        for peer in &status.peers {
            let connectivity = peer_connectivity_label(peer);
            lines.push(format!("  {}  {connectivity}", peer.device_id));
        }
    }

    let transfer_lines = active_transfer_detail_lines(status);
    if !transfer_lines.is_empty() {
        lines.push(String::new());
        lines.push("Active transfers:".to_string());
        lines.extend(transfer_lines);
    }

    lines.push(String::new());
    lines.push(limits_summary_line(status));
    lines.push(block_store_summary_line(status));

    if !status.volumes.is_empty() {
        lines.push("Volumes:".to_string());
        for volume in &status.volumes {
            lines.push(volume_line(volume));
        }
    }

    let update_lines = update_summary_lines(status);
    if !update_lines.is_empty() {
        lines.push(String::new());
        lines.extend(update_lines);
    }

    let error_lines = recent_errors_summary_lines(status);
    if !error_lines.is_empty() {
        lines.push(String::new());
        lines.push("Recent errors:".to_string());
        lines.extend(error_lines);
    }
    lines
}

#[cfg(test)]
mod tests;
