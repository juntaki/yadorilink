//! Pure conversions from the daemon's control-protocol messages and the
//! coordination plane's listings into the product types. Nothing here does
//! I/O; every rule is covered by the unit tests next to this module.
//!
//! Two rules hold throughout: an unset wire value (`0`, an empty string) is
//! `None`, never a real-looking value; and a derivation that already exists
//! (folder state and mode in `yadorilink-product-view`, the conflict-copy
//! name parse, the invite URL) is called, not repeated.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yadorilink_ipc_proto::daemonctl::EntryKind as WireEntryKind;
use yadorilink_ipc_proto::daemonctl::{
    self as wire, ConflictedFileInfo, FileVersionInfo, GcResponse, HandoffResult, InboxTransfer,
    LinkStatus, MaterializationStatusResponse, MintedInviteInfo, PeerStatus,
    ReceiveTransferResponse, ReplicaMembershipCommandOutcome, RestoreTrashOperationResponse,
    SendFileResponse, StatusResponse, TrashedFileInfo, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse, VolumeFreeSpace,
};
use yadorilink_local_storage::free_space::FreeSpaceState as LocalFreeSpace;
use yadorilink_local_storage::link_preflight::{self, LinkPreflightReport, RiskyLocation};
use yadorilink_product_view as view;

use super::*;
use crate::ops::account::DeletionStatus;
use crate::ops::shares::{GroupMemberInfo, PendingApproval, PendingInviteInfo, ShareEdgeInfo};

// ---- small rules ----------------------------------------------------------

fn text(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn unix_secs(secs: i64) -> Option<SystemTime> {
    u64::try_from(secs).ok().filter(|s| *s > 0).map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

fn unix_nanos(nanos: i64) -> Option<SystemTime> {
    u64::try_from(nanos).ok().filter(|n| *n > 0).map(|n| UNIX_EPOCH + Duration::from_nanos(n))
}

fn size(bytes: i64) -> u64 {
    u64::try_from(bytes).unwrap_or(0)
}

fn limit(bytes_per_sec: u64) -> Option<u64> {
    (bytes_per_sec > 0).then_some(bytes_per_sec)
}

fn share_role(raw: &str) -> ShareRole {
    match raw {
        "owner" => ShareRole::Owner,
        "editor" => ShareRole::Editor,
        "viewer" => ShareRole::Viewer,
        other => ShareRole::Other { raw: other.to_owned() },
    }
}

fn free_space_state(raw: &str) -> FreeSpaceState {
    match raw {
        "ok" => FreeSpaceState::Ok,
        "low" => FreeSpaceState::Low,
        "critical" => FreeSpaceState::Critical,
        _ => FreeSpaceState::Unknown,
    }
}

fn update_state(raw: &str) -> UpdateState {
    match raw {
        "idle" => UpdateState::Idle,
        "checking" => UpdateState::Checking,
        "available" => UpdateState::Available,
        "held_back" => UpdateState::HeldBack,
        "kill_switched" => UpdateState::KillSwitched,
        "downloading" => UpdateState::Downloading,
        "downloaded" => UpdateState::Downloaded,
        "verified" => UpdateState::Verified,
        "installing" => UpdateState::Installing,
        "failed" => UpdateState::Failed,
        "deferred" => UpdateState::Deferred,
        "up_to_date" => UpdateState::UpToDate,
        other => UpdateState::Unknown { raw: other.to_owned() },
    }
}

fn install_mode(raw: &str) -> UpdateInstallMode {
    match raw {
        "automatic" => UpdateInstallMode::Automatic,
        "manual" => UpdateInstallMode::Manual,
        other => UpdateInstallMode::Other { raw: other.to_owned() },
    }
}

fn reachability(peer: Option<&PeerStatus>) -> PeerReachability {
    match peer.map(PeerStatus::reachability) {
        Some(wire::PeerReachability::Connecting) => PeerReachability::Connecting,
        Some(wire::PeerReachability::Connected) => PeerReachability::Connected,
        Some(wire::PeerReachability::Unreachable) => PeerReachability::Unreachable,
        Some(wire::PeerReachability::Unspecified) | None => PeerReachability::Unknown,
    }
}

fn route(peer: Option<&PeerStatus>) -> RouteKind {
    match peer.map(PeerStatus::route_kind) {
        Some(wire::RouteKind::Direct) => RouteKind::Direct,
        Some(wire::RouteKind::Relay) => RouteKind::Relay,
        Some(wire::RouteKind::Unspecified) | None => RouteKind::Unknown,
    }
}

fn folder_path_of<'a>(links: &'a [LinkStatus], group_id: &str) -> Option<&'a str> {
    links.iter().find(|l| l.group_id == group_id).map(|l| l.local_path.as_str())
}

// ---- status ---------------------------------------------------------------

/// The daemon's whole status as the product snapshot, stamped with the time
/// it was captured.
pub fn status_snapshot(
    response: &StatusResponse,
    this_device_id: Option<String>,
    captured_at: SystemTime,
) -> StatusSnapshot {
    let links = &response.links;
    StatusSnapshot {
        captured_at,
        overall: match response.overall_state.as_str() {
            "healthy" => OverallState::Healthy,
            "attention" => OverallState::Attention,
            "degraded" => OverallState::Degraded,
            _ => OverallState::Unknown,
        },
        attention_reasons: response
            .attention_reasons
            .iter()
            .map(|raw| attention_reason(raw, links))
            .collect(),
        this_device_id,
        folders: links.iter().map(|l| folder_summary(l, &response.volumes)).collect(),
        peers: response.peers.iter().map(peer_summary).collect(),
        transfers: response
            .active_transfers
            .iter()
            .map(|t| TransferSummary {
                group_id: t.group_id.clone(),
                folder_local_path: folder_path_of(links, &t.group_id).map(str::to_owned),
                path: t.path.clone(),
                bytes_done: t.bytes_done,
                bytes_total: t.bytes_total,
                blocks_done: t.blocks_done,
                blocks_total: t.blocks_total,
                source_device_id: t.source_peer.clone(),
                started_at: unix_secs(t.started_at_unix),
            })
            .collect(),
        bandwidth: BandwidthStatus {
            limits: BandwidthLimits {
                upload_bytes_per_sec: limit(response.upload_limit_bytes_per_sec),
                download_bytes_per_sec: limit(response.download_limit_bytes_per_sec),
            },
            current_upload_bytes_per_sec: response.current_upload_bytes_per_sec,
            current_download_bytes_per_sec: response.current_download_bytes_per_sec,
        },
        volumes: response.volumes.iter().map(volume_summary).collect(),
        storage: StorageSummary {
            block_store_total_bytes: response.block_store_total_bytes,
            block_count: response.block_store_block_count,
            last_gc_at: unix_secs(response.last_gc_unix),
            reclaimable_estimate_bytes: response.gc_reclaimable_estimate_bytes,
        },
        update: update_badge(response),
        recent_errors: response
            .recent_errors
            .iter()
            .map(|e| RecentError {
                category: e.category.clone(),
                at: unix_secs(e.timestamp_unix),
                context: e.coarse_context.clone(),
            })
            .collect(),
    }
}

fn update_badge(response: &StatusResponse) -> UpdateBadge {
    UpdateBadge {
        state: update_state(&response.update_state),
        available_version: text(&response.update_available_version),
        mandatory: response.update_mandatory,
        waiting_for_safe_point: response.update_waiting_for_safe_point,
        last_error_category: text(&response.update_last_error_category),
        channel: response.update_channel.clone(),
        install_source: response.update_install_source.clone(),
        holdback_reason: text(&response.update_holdback_reason),
    }
}

fn volume_summary(volume: &VolumeFreeSpace) -> VolumeSummary {
    VolumeSummary {
        path: volume.path.clone(),
        state: free_space_state(&volume.state),
        available_bytes: volume.available_bytes,
        headroom_bytes: volume.headroom_bytes,
    }
}

fn peer_summary(peer: &PeerStatus) -> PeerSummary {
    PeerSummary {
        device_id: peer.device_id.clone(),
        reachability: reachability(Some(peer)),
        unreachable_category: match peer.unreachable_category() {
            wire::UnreachableCategory::NoCandidates => Some(UnreachableCategory::NoCandidates),
            wire::UnreachableCategory::NoResponse => Some(UnreachableCategory::NoResponse),
            wire::UnreachableCategory::UdpBlocked => Some(UnreachableCategory::UdpBlocked),
            wire::UnreachableCategory::HandshakeRefused => {
                Some(UnreachableCategory::HandshakeRefused)
            }
            wire::UnreachableCategory::Unspecified => None,
        },
        route: route(Some(peer)),
    }
}

/// One `category:subject` reason from the daemon's overall-status rollup.
/// Only the first colon splits, so a subject may contain one. A reason about
/// a folder group names the folder linked to it here.
pub fn attention_reason(raw: &str, links: &[LinkStatus]) -> AttentionReason {
    let (name, subject) = raw.split_once(':').unwrap_or((raw, ""));
    let (category, folder_scoped) = match name {
        "degraded" => (AttentionCategory::Degraded, true),
        "durability_at_risk" => (AttentionCategory::DurabilityAtRisk, true),
        "durability_unknown" => (AttentionCategory::DurabilityUnknown, true),
        "fetch_unavailable" => (AttentionCategory::FetchUnavailable, true),
        "fetch_availability_unknown" => (AttentionCategory::FetchAvailabilityUnknown, true),
        "conflict" => (AttentionCategory::Conflict, true),
        "held" => (AttentionCategory::Held, true),
        "low_disk_critical" => (AttentionCategory::LowDiskCritical, false),
        "low_disk" => (AttentionCategory::LowDisk, false),
        "peer_disconnected" => (AttentionCategory::PeerDisconnected, false),
        "recent_error" => (AttentionCategory::RecentError, false),
        "update_failed" => (AttentionCategory::UpdateFailed, false),
        _ => (AttentionCategory::Unrecognized, false),
    };
    AttentionReason {
        category,
        subject: subject.to_owned(),
        folder_local_path: if folder_scoped {
            folder_path_of(links, subject).map(str::to_owned)
        } else {
            None
        },
        raw: raw.to_owned(),
    }
}

/// One linked folder. State, mode and name come from the shared
/// `yadorilink-product-view` derivation; this only changes their shape.
pub fn folder_summary(link: &LinkStatus, volumes: &[VolumeFreeSpace]) -> FolderSummary {
    let derived = view::FolderSummary::from(link);
    FolderSummary {
        local_path: derived.local_path,
        group_id: derived.group_id,
        name: derived.name,
        mode: match derived.mode {
            view::FolderMode::Synced => FolderMode::KeepAll,
            view::FolderMode::Selective => FolderMode::OnDemand,
        },
        state: match derived.state {
            view::FolderState::UpToDate => FolderState::UpToDate,
            view::FolderState::Syncing => FolderState::Syncing,
            view::FolderState::Paused => FolderState::Paused,
            view::FolderState::Blocked => FolderState::Blocked,
            view::FolderState::Attention => FolderState::Attention,
        },
        paused: derived.paused,
        conflict_count: derived.conflict_count,
        hydrated_file_count: derived.files_hydrated,
        placeholder_file_count: derived.files_placeholder,
        hydrating_file_count: derived.files_hydrating,
        held_file_count: derived.held_file_count,
        skipped_symlink_count: derived.skipped_symlink_count,
        transfer: derived.transfer.map(|t| FolderTransferProgress {
            bytes_done: t.bytes_done,
            bytes_total: t.bytes_total,
            blocks_done: t.blocks_done,
            blocks_total: t.blocks_total,
            eta: (t.eta_seconds > 0).then(|| Duration::from_secs(t.eta_seconds)),
        }),
        durability: match derived.durability_status {
            view::folder::DurabilityStatus::Protected => DurabilityStatus::Protected,
            view::folder::DurabilityStatus::Protecting => DurabilityStatus::Protecting,
            view::folder::DurabilityStatus::AtRisk => DurabilityStatus::AtRisk,
            view::folder::DurabilityStatus::Unknown
            | view::folder::DurabilityStatus::Unspecified => DurabilityStatus::Unknown,
        },
        durability_evidence: match link.durability_evidence() {
            wire::DurabilityEvidence::None => DurabilityEvidence::None,
            wire::DurabilityEvidence::CorroboratedIndex => DurabilityEvidence::CorroboratedIndex,
            wire::DurabilityEvidence::VerifiedPayload => DurabilityEvidence::VerifiedPayload,
            wire::DurabilityEvidence::Unspecified => DurabilityEvidence::Unknown,
        },
        local_storage: match derived.local_storage_state {
            wire::LocalStorageState::FullCopy => LocalStorageState::FullCopy,
            wire::LocalStorageState::PartiallyMaterialized => {
                LocalStorageState::PartiallyMaterialized
            }
            wire::LocalStorageState::OnDemand => LocalStorageState::OnDemand,
            wire::LocalStorageState::Unspecified => LocalStorageState::Unknown,
        },
        fetch_availability: match derived.fetch_availability {
            wire::FetchAvailability::AvailableNow => FetchAvailability::AvailableNow,
            wire::FetchAvailability::UnavailableNow => FetchAvailability::UnavailableNow,
            wire::FetchAvailability::Unknown | wire::FetchAvailability::Unspecified => {
                FetchAvailability::Unknown
            }
        },
        full_replica_device_ids: derived.full_replica_device_ids,
        policy_stale: derived.policy_stale,
        ambiguous: derived.ambiguous,
        ambiguous_local_paths: derived.ambiguous_local_paths,
        degraded: derived.degraded,
        degraded_reason: text(&derived.degraded_reason),
        volume: volumes.iter().find(|v| v.path == link.local_path).map(volume_summary),
    }
}

/// The detail view of the folder linked at `local_path`, or `None` when no
/// folder is linked there. Every complete copy is listed with this device's
/// current connection to it; a device the daemon reports nothing about reads
/// as unknown, not offline.
pub fn folder_detail(response: &StatusResponse, local_path: &str) -> Option<FolderDetail> {
    let link = response.links.iter().find(|l| l.local_path == local_path)?;
    Some(FolderDetail {
        summary: folder_summary(link, &response.volumes),
        held_files: link
            .held_files
            .iter()
            .map(|h| HeldFile {
                path: h.path.clone(),
                reason: h.reason.clone(),
                held_since: unix_nanos(h.held_since_unix_nanos),
            })
            .collect(),
        complete_copies: link
            .full_replica_device_ids
            .iter()
            .map(|device_id| {
                let peer = response.peers.iter().find(|p| &p.device_id == device_id);
                ReplicaCopy {
                    device_id: device_id.clone(),
                    reachability: reachability(peer),
                    route: route(peer),
                }
            })
            .collect(),
    })
}

// ---- files ----------------------------------------------------------------

pub fn conflict_summary(file: &ConflictedFileInfo) -> ConflictSummary {
    let detail = view::conflict_detail(file);
    ConflictSummary {
        local_path: file.local_path.clone(),
        path: file.path.clone(),
        size: size(file.size),
        modified_at: unix_nanos(file.mtime_unix_nanos),
        current_path: detail.current_path,
        loser_device_id: detail.loser_device_id,
        conflict_timestamp: detail.timestamp,
        kind: entry_kind(file.kind()),
        reason: match detail.reason {
            view::ConflictReason::ConcurrentEdit => ConflictReason::ConcurrentEdit,
            view::ConflictReason::FolderAtPath => ConflictReason::FolderAtPath,
        },
        holds_compaction: file.holds_compaction,
    }
}

/// An unset kind is a sender that never classified the record, and every
/// such record is a file.
fn entry_kind(kind: WireEntryKind) -> EntryKind {
    match kind {
        WireEntryKind::Unspecified | WireEntryKind::File => EntryKind::File,
        WireEntryKind::Directory => EntryKind::Directory,
        WireEntryKind::Symlink => EntryKind::Symlink,
    }
}

pub fn trashed_file(file: &TrashedFileInfo) -> TrashedFile {
    TrashedFile {
        local_path: file.local_path.clone(),
        path: file.path.clone(),
        version_seq: file.version_seq,
        last_known_size: size(file.last_known_size),
        origin_device_id: text(&file.origin_device_id),
        deleted_at: unix_nanos(file.deleted_at_unix_nanos),
        kind: entry_kind(file.kind()),
        deleted_by_operation: text(&file.deleted_by_operation),
    }
}

pub fn folder_restore_outcome(outcome: &RestoreTrashOperationResponse) -> FolderRestoreOutcome {
    FolderRestoreOutcome {
        restored_paths: outcome.restored_paths.clone(),
        failed: outcome
            .failed
            .iter()
            .map(|failure| FolderRestoreFailure {
                path: failure.path.clone(),
                error: failure.error.clone(),
            })
            .collect(),
        partial: outcome.partial,
    }
}

pub fn file_version(version: &FileVersionInfo, is_current: bool) -> FileVersion {
    FileVersion {
        version_seq: version.version_seq,
        size: size(version.size),
        modified_at: unix_nanos(version.mtime_unix_nanos),
        state: version.state.clone(),
        origin_device_id: text(&version.origin_device_id),
        unix_mode: version.unix_mode,
        is_current,
        kind: entry_kind(version.kind()),
    }
}

/// Every retained version, in the daemon's order, with the highest
/// `version_seq` marked current.
pub fn file_versions(versions: &[FileVersionInfo]) -> Vec<FileVersion> {
    let current = versions.iter().map(|v| v.version_seq).max();
    versions.iter().map(|v| file_version(v, Some(v.version_seq) == current)).collect()
}

pub fn file_availability(status: &MaterializationStatusResponse) -> FileAvailability {
    FileAvailability {
        tracked: status.known,
        state: match status.state() {
            wire::MaterializationState::Hydrated => MaterializationState::Hydrated,
            wire::MaterializationState::Placeholder => MaterializationState::Placeholder,
            wire::MaterializationState::Hydrating => MaterializationState::Hydrating,
            wire::MaterializationState::Evicting => MaterializationState::Evicting,
            wire::MaterializationState::Unspecified => MaterializationState::Unknown,
        },
        pinned: status.pinned,
    }
}

// ---- membership and shares ---------------------------------------------------

pub fn handoff_summary(handoff: &HandoffResult) -> HandoffSummary {
    HandoffSummary {
        target_device_id: handoff.target_device_id.clone(),
        membership_generation: handoff.membership_generation,
        lease_id: text(&handoff.lease_id),
    }
}

pub fn membership_outcome(outcome: &ReplicaMembershipCommandOutcome) -> MembershipOutcome {
    MembershipOutcome {
        handoffs: outcome
            .handoffs
            .iter()
            .map(|h| MembershipHandoff {
                group_id: h.group_id.clone(),
                target_device_id: h.target_device_id.clone(),
                lease_id: h.lease_id.clone(),
                membership_generation: h.membership_generation,
            })
            .collect(),
        forced_group_ids: outcome.forced_group_ids.clone(),
        unknown_scope_operation_id: text(&outcome.unknown_scope_operation_id),
    }
}

/// One member of a folder group, relative to whoever is looking: the same
/// rules as the command line's member listing.
pub fn member_summary(member: &GroupMemberInfo, own_device_id: Option<&str>) -> MemberSummary {
    let relationship = if own_device_id == Some(member.device_id.as_str()) {
        MemberRelationship::You
    } else if member.is_caller_account {
        MemberRelationship::YourOtherDevice
    } else if member.is_same_account {
        MemberRelationship::OwnersDevice
    } else {
        MemberRelationship::Invited
    };
    MemberSummary {
        device_id: member.device_id.clone(),
        device_name: member.device_name.clone(),
        role: share_role(&member.role),
        relationship,
        // Only "eager" is a full copy; an unrecognized mode understates.
        storage: if member.storage_mode == "eager" {
            MemberStorage::FullCopy
        } else {
            MemberStorage::OnDemand
        },
        online: member.online,
        last_seen: unix_secs(member.last_seen_unix),
    }
}

pub fn pending_approval_summary(pending: &PendingApproval) -> PendingApprovalSummary {
    PendingApprovalSummary {
        group_id: pending.group_id.clone(),
        group_name: pending.group_name.clone(),
        device_id: pending.device_id.clone(),
        requested_role: pending.role.as_deref().map(share_role),
    }
}

pub fn share_summary(edge: &ShareEdgeInfo) -> ShareSummary {
    ShareSummary {
        edge_id: edge.edge_id.clone(),
        group_id: edge.group_id.clone(),
        group_name: edge.group_name.clone(),
        device_id: edge.device_id.clone(),
        state: match edge.state.as_str() {
            "active" => ShareEdgeState::Active,
            crate::ops::shares::STATE_PENDING_APPROVAL => ShareEdgeState::PendingApproval,
            other => ShareEdgeState::Other { raw: other.to_owned() },
        },
        role: edge.role.as_deref().map(share_role),
    }
}

pub fn invite_summary(invite: &MintedInviteInfo) -> InviteSummary {
    InviteSummary {
        invite_id: invite.invite_id.clone(),
        code: invite.code.clone(),
        url: crate::wording::invite_url(&invite.code),
        group_id: invite.group_id.clone(),
        role: share_role(&invite.role),
        expires_at: unix_secs(invite.expires_at_unix).unwrap_or(UNIX_EPOCH),
        requires_approval: invite.requires_approval,
    }
}

pub fn pending_invite_summary(invite: &PendingInviteInfo) -> PendingInviteSummary {
    PendingInviteSummary {
        invite_id: invite.invite_id.clone(),
        group_id: invite.group_id.clone(),
        group_name: invite.group_name.clone(),
        role: share_role(&invite.role),
        expires_at: unix_secs(invite.expires_at_unix).unwrap_or(UNIX_EPOCH),
        status: match invite.status.as_str() {
            "pending" => InviteStatus::Pending,
            other => InviteStatus::Other { raw: other.to_owned() },
        },
    }
}

// ---- linking ----------------------------------------------------------------

/// The preflight report as typed issues, in the same order as the report's
/// own warning lines, so a front end can show them one to one.
pub fn preflight_result(resolved_path: &Path, report: &LinkPreflightReport) -> PreflightResult {
    PreflightResult {
        resolved_path: resolved_path.to_string_lossy().into_owned(),
        path_exists: report.path_exists,
        is_directory: report.is_directory,
        entry_count: report.entry_count,
        ignored_entry_count: report.ignored_entry_count,
        total_size_bytes: report.total_size_bytes,
        scan_truncated: report.scan_truncated,
        free_space: report.free_space.map(|space| FreeSpace {
            available_bytes: space.available_bytes,
            total_bytes: space.total_bytes,
            headroom_bytes: space.headroom_bytes,
            state: match space.classify() {
                LocalFreeSpace::Ok => FreeSpaceState::Ok,
                LocalFreeSpace::Low => FreeSpaceState::Low,
                LocalFreeSpace::Critical => FreeSpaceState::Critical,
            },
        }),
        issues: preflight_issues(report),
        requires_acknowledgement: report.is_risky(),
    }
}

fn preflight_issues(report: &LinkPreflightReport) -> Vec<PreflightIssue> {
    if !report.path_exists {
        return vec![PreflightIssue::PathMissing];
    }
    let mut issues = Vec::new();
    if report.ignore_rules_unreadable {
        issues.push(PreflightIssue::IgnoreRulesUnreadable);
    }
    if !report.is_empty_folder() {
        issues.push(PreflightIssue::NotEmpty {
            entry_count: report.entry_count,
            scan_truncated: report.scan_truncated,
        });
    }
    if let Some(space) = report.free_space {
        let (available_bytes, headroom_bytes) = (space.available_bytes, space.headroom_bytes);
        match space.classify() {
            LocalFreeSpace::Critical => {
                issues.push(PreflightIssue::CriticalFreeSpace { available_bytes, headroom_bytes });
            }
            LocalFreeSpace::Low => {
                issues.push(PreflightIssue::LowFreeSpace { available_bytes, headroom_bytes });
            }
            LocalFreeSpace::Ok => {}
        }
    }
    for conflict in &report.nested_conflicts {
        issues.push(PreflightIssue::NestedLink {
            other_path: conflict.other_path.clone(),
            relation: match conflict.relation {
                link_preflight::NestedLinkRelation::Ancestor => NestedLinkRelation::Ancestor,
                link_preflight::NestedLinkRelation::Descendant => NestedLinkRelation::Descendant,
                link_preflight::NestedLinkRelation::Same => NestedLinkRelation::Same,
            },
        });
    }
    match &report.risky_location {
        Some(RiskyLocation::CloudProviderFolder(provider)) => {
            issues.push(PreflightIssue::CloudProviderFolder { provider: (*provider).to_owned() });
        }
        Some(RiskyLocation::FilesystemRoot) => issues.push(PreflightIssue::FilesystemRoot),
        Some(RiskyLocation::HomeDirectory) => issues.push(PreflightIssue::HomeDirectory),
        None => {}
    }
    for path in &report.reserved_namespace_blocked_paths {
        issues.push(PreflightIssue::ReservedName { path: path.clone() });
    }
    issues
}

// ---- transfers, storage, updates, account --------------------------------------

pub fn sent_transfer(sent: SendFileResponse) -> SentTransfer {
    SentTransfer {
        transfer_id: sent.transfer_id,
        files_offered: sent.files_offered,
        total_size: sent.total_size,
    }
}

pub fn incoming_transfer(transfer: &InboxTransfer) -> IncomingTransfer {
    IncomingTransfer {
        transfer_id: transfer.transfer_id.clone(),
        sender_device_id: transfer.sender_device_id.clone(),
        files: transfer
            .files
            .iter()
            .map(|f| IncomingFile { relative_path: f.relative_path.clone(), size: f.size })
            .collect(),
        total_size: transfer.total_size,
        offered_at: unix_nanos(transfer.offered_at_unix_nanos),
        status: match transfer.status.as_str() {
            "pending" => IncomingTransferStatus::Pending,
            "in_progress" => IncomingTransferStatus::InProgress,
            "completed" => IncomingTransferStatus::Completed,
            other => IncomingTransferStatus::Other { raw: other.to_owned() },
        },
    }
}

pub fn received_transfer(received: ReceiveTransferResponse) -> ReceivedTransfer {
    ReceivedTransfer {
        destination_dir: received.destination_dir,
        files_received: received.files_received,
        bytes_received: received.bytes_received,
    }
}

pub fn gc_report(dry_run: bool, report: &GcResponse) -> GcReport {
    GcReport {
        dry_run,
        blocks_deleted: report.blocks_deleted,
        bytes_reclaimed: report.bytes_reclaimed,
    }
}

pub fn update_status(status: &UpdateStatusResponse) -> UpdateStatus {
    UpdateStatus {
        current_version: status.current_version.clone(),
        channel: status.channel.clone(),
        install_source: status.install_source.clone(),
        last_checked_at: unix_secs(status.last_check_unix),
        state: update_state(&status.state),
        available_version: text(&status.available_version),
        release_notes_url: text(&status.release_notes_url),
        mandatory: status.mandatory,
        holdback_reason: text(&status.holdback_reason),
        waiting_for_safe_point: status.waiting_for_safe_point,
        last_error_category: text(&status.last_error_category),
        last_error_message: text(&status.last_error_message),
        config: UpdateConfig {
            automatic_checks: status.automatic_checks_enabled,
            install_mode: install_mode(&status.automatic_install_mode),
        },
    }
}

pub fn update_config(config: &UpdateConfigResponse) -> UpdateConfig {
    UpdateConfig {
        automatic_checks: config.automatic_checks_enabled,
        install_mode: install_mode(&config.automatic_install_mode),
    }
}

pub fn update_install_outcome(outcome: &UpdateInstallResponse) -> UpdateInstallOutcome {
    match outcome.outcome.as_str() {
        "installing" => UpdateInstallOutcome::Installing,
        "deferred" => UpdateInstallOutcome::Deferred,
        "store_managed" => {
            UpdateInstallOutcome::StoreManaged { guidance: outcome.guidance.clone() }
        }
        other => UpdateInstallOutcome::Other { raw: other.to_owned() },
    }
}

pub fn account_deletion_status(status: &DeletionStatus) -> AccountDeletionStatus {
    AccountDeletionStatus {
        state: match status.state.as_str() {
            "active" => AccountDeletionState::Active,
            "requested" => AccountDeletionState::Requested,
            "grace" => AccountDeletionState::Grace,
            other => AccountDeletionState::Other { raw: other.to_owned() },
        },
        grace_expires_at: status.grace_expires_at_unix.and_then(unix_secs),
        remaining: status
            .remaining_secs
            .and_then(|s| u64::try_from(s).ok())
            .map(Duration::from_secs),
    }
}
