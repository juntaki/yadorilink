//! The product types a desktop front end sees: records and enums with owned
//! fields only, no protocol types, no paths (paths are strings), times as
//! [`SystemTime`] and spans as [`Duration`].
//!
//! Every type here is what [`crate::ClientCore`] returns or takes. They carry
//! meaning (enums, numbers, ids), never user-facing sentences; the only text
//! fields are identifiers, raw values kept for tooltips, and diagnostic
//! `message`/`reason` strings. Enums that mirror a server or daemon string keep
//! an `Other`/`Unknown { raw }` case so a newer peer never breaks decoding.
//!
//! With the `ffi` feature every type also derives its foreign-language binding.

use std::time::{Duration, SystemTime};

use crate::error::DesktopError;

mod convert;

pub use convert::{
    account_deletion_status, attention_reason, conflict_summary, file_availability, file_version,
    file_versions, folder_detail, folder_restore_outcome, folder_summary, gc_report,
    handoff_summary, incoming_transfer, invite_summary, member_summary, membership_outcome,
    pending_approval_summary, pending_invite_summary, preflight_result, received_transfer,
    sent_transfer, share_summary, status_snapshot, trashed_file, update_config,
    update_install_outcome, update_status,
};

// ---- construction -------------------------------------------------------

/// How [`crate::ClientCore::start_daemon`] brings the daemon up when nothing
/// answers the control socket.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonLaunch {
    /// Spawn `yadorilink-daemon` from `path`, else from next to the current
    /// executable, else from PATH.
    SpawnBinary { path: Option<String> },
    /// Ask launchd to start the named LaunchAgent (`launchctl kickstart`); if
    /// that fails and `fallback_binary` is set, spawn it by absolute path.
    /// Never searches PATH.
    LaunchAgent { label: String, fallback_binary: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct CoreConfig {
    pub daemon_launch: DaemonLaunch,
}

// ---- account ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SignInState {
    SignedOut,
    SignedIn,
    /// A credential store exists and cannot be used. Signing in again would
    /// leave it in place, so this is a state of its own.
    CredentialStoreUnusable {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountStatus {
    pub sign_in: SignInState,
    pub client_id: Option<String>,
    pub this_device_id: Option<String>,
    pub device_registered: bool,
    pub default_device_name: String,
    /// `None` when the daemon is not reachable.
    pub has_linked_folders: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SignOutKind {
    Revoked { grants_revoked: u32 },
    AlreadyRevoked,
    ConfirmedRevokedAfterRejection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SignOutOutcome {
    pub kind: SignOutKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceRegistration {
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AccountDeletionState {
    Active,
    Requested,
    Grace,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionStatus {
    pub state: AccountDeletionState,
    pub grace_expires_at: Option<SystemTime>,
    pub remaining: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionRequest {
    /// Shown once; confirming the deletion requires it.
    pub confirmation_token: String,
}

// ---- sign-in ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LoginFlow {
    /// The browser comes back to a loopback listener on this machine.
    Loopback,
    /// The device-authorization grant: a code entered on another page.
    DeviceCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct LoginOptions {
    pub flow: LoginFlow,
    /// Ends the flow with a network failure when it has not finished in
    /// time. `None` waits as long as each step allows.
    pub overall_timeout: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum BrowserPurpose {
    ApproveDevice,
    SignIn,
}

/// One step of a sign-in, in order.
///
/// Loopback: `Enrolling`, `OpenBrowser{ApproveDevice}`, `WaitingForApproval`,
/// `OpenBrowser{SignIn}`, `WaitingForAuthorization`, `SignedIn`.
/// Device code: `Enrolling`, `OpenBrowser{ApproveDevice}`,
/// `WaitingForApproval`, `ShowDeviceCode`, `SignedIn`. Any step may instead
/// end the stream with `Failed` or `Cancelled`.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LoginEvent {
    Enrolling,
    OpenBrowser { url: String, purpose: BrowserPurpose },
    WaitingForApproval { expires_in: Duration },
    WaitingForAuthorization,
    ShowDeviceCode { verification_uri: String, user_code: String },
    SignedIn { account: AccountStatus },
    Failed { error: DesktopError },
    Cancelled,
}

impl LoginEvent {
    /// Whether this event ends the stream.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LoginEvent::SignedIn { .. } | LoginEvent::Failed { .. } | LoginEvent::Cancelled
        )
    }
}

// ---- status -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum OverallState {
    Healthy,
    Attention,
    Degraded,
    Unknown,
}

/// The categories the daemon's overall-status rollup reports, one per
/// `category:subject` reason prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AttentionCategory {
    Degraded,
    DurabilityAtRisk,
    DurabilityUnknown,
    FetchUnavailable,
    FetchAvailabilityUnknown,
    Conflict,
    Held,
    LowDiskCritical,
    LowDisk,
    PeerDisconnected,
    RecentError,
    UpdateFailed,
    Unrecognized,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AttentionReason {
    pub category: AttentionCategory,
    /// A group id, volume path, device id or error category, by category.
    pub subject: String,
    /// The linked folder a folder-scoped reason is about, when its group is
    /// linked here.
    pub folder_local_path: Option<String>,
    /// The daemon's own `category:subject` text.
    pub raw: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FolderMode {
    /// Every file is kept on this device.
    KeepAll,
    /// Files are fetched when opened.
    OnDemand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FolderState {
    UpToDate,
    Syncing,
    Paused,
    /// The folder group is linked at more than one local folder and syncs
    /// nothing.
    Blocked,
    Attention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DurabilityStatus {
    Protected,
    Protecting,
    AtRisk,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DurabilityEvidence {
    None,
    CorroboratedIndex,
    VerifiedPayload,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LocalStorageState {
    FullCopy,
    PartiallyMaterialized,
    OnDemand,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FetchAvailability {
    AvailableNow,
    UnavailableNow,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderTransferProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    /// `None` when the daemon has no estimate.
    pub eta: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FreeSpaceState {
    Ok,
    Low,
    Critical,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct VolumeSummary {
    pub path: String,
    pub state: FreeSpaceState,
    pub available_bytes: u64,
    pub headroom_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderSummary {
    /// The identity key: the daemon keys links by path.
    pub local_path: String,
    pub group_id: String,
    pub name: String,
    pub mode: FolderMode,
    pub state: FolderState,
    pub paused: bool,
    pub conflict_count: u64,
    pub hydrated_file_count: u64,
    pub placeholder_file_count: u64,
    pub hydrating_file_count: u64,
    pub held_file_count: u64,
    pub skipped_symlink_count: u64,
    pub transfer: Option<FolderTransferProgress>,
    pub durability: DurabilityStatus,
    pub durability_evidence: DurabilityEvidence,
    pub local_storage: LocalStorageState,
    pub fetch_availability: FetchAvailability,
    pub full_replica_device_ids: Vec<String>,
    pub policy_stale: bool,
    pub ambiguous: bool,
    pub ambiguous_local_paths: Vec<String>,
    pub degraded: bool,
    /// Diagnostic text for a tooltip.
    pub degraded_reason: Option<String>,
    pub volume: Option<VolumeSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PeerReachability {
    Connecting,
    Connected,
    Unreachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UnreachableCategory {
    NoCandidates,
    NoResponse,
    UdpBlocked,
    HandshakeRefused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RouteKind {
    Direct,
    Relay,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PeerSummary {
    pub device_id: String,
    pub reachability: PeerReachability,
    pub unreachable_category: Option<UnreachableCategory>,
    pub route: RouteKind,
}

/// One active sync transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferSummary {
    pub group_id: String,
    pub folder_local_path: Option<String>,
    pub path: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    pub source_device_id: String,
    pub started_at: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BandwidthLimits {
    /// `None` is unlimited.
    pub upload_bytes_per_sec: Option<u64>,
    pub download_bytes_per_sec: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BandwidthStatus {
    pub limits: BandwidthLimits,
    pub current_upload_bytes_per_sec: u64,
    pub current_download_bytes_per_sec: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StorageSummary {
    pub block_store_total_bytes: u64,
    pub block_count: u64,
    /// `None` when no collection has run.
    pub last_gc_at: Option<SystemTime>,
    pub reclaimable_estimate_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UpdateState {
    Idle,
    Checking,
    Available,
    HeldBack,
    KillSwitched,
    Downloading,
    Downloaded,
    Verified,
    Installing,
    Failed,
    Deferred,
    UpToDate,
    Unknown { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateBadge {
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub mandatory: bool,
    pub waiting_for_safe_point: bool,
    pub last_error_category: Option<String>,
    pub channel: String,
    pub install_source: String,
    pub holdback_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RecentError {
    pub category: String,
    pub at: Option<SystemTime>,
    pub context: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StatusSnapshot {
    pub captured_at: SystemTime,
    pub overall: OverallState,
    pub attention_reasons: Vec<AttentionReason>,
    pub this_device_id: Option<String>,
    pub folders: Vec<FolderSummary>,
    pub peers: Vec<PeerSummary>,
    pub transfers: Vec<TransferSummary>,
    pub bandwidth: BandwidthStatus,
    pub volumes: Vec<VolumeSummary>,
    pub storage: StorageSummary,
    pub update: UpdateBadge,
    pub recent_errors: Vec<RecentError>,
}

/// One result of the status poll loop.
// Kept inline rather than boxed: the foreign binding lowers the variant's
// fields directly and has no boxed form, and one value lives per watch.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum StatusUpdate {
    Snapshot {
        snapshot: StatusSnapshot,
    },
    /// The daemon could not be asked; replaces the snapshot.
    Unavailable {
        error: DesktopError,
    },
}

// ---- folder detail and files ------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct HeldFile {
    pub path: String,
    pub reason: String,
    pub held_since: Option<SystemTime>,
}

/// One device holding a complete copy of a folder, with this device's
/// current connection to it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ReplicaCopy {
    pub device_id: String,
    pub reachability: PeerReachability,
    pub route: RouteKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderDetail {
    pub summary: FolderSummary,
    pub held_files: Vec<HeldFile>,
    pub complete_copies: Vec<ReplicaCopy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ConflictSummary {
    /// The linked folder's root.
    pub local_path: String,
    /// The conflicted copy, relative to the root.
    pub path: String,
    pub size: u64,
    pub modified_at: Option<SystemTime>,
    /// The file the copy conflicts with, relative to the root.
    pub current_path: String,
    pub loser_device_id: Option<String>,
    pub conflict_timestamp: Option<String>,
    pub kind: EntryKind,
    pub reason: ConflictReason,
}

/// Why a conflict copy is kept under its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ConflictReason {
    /// Devices changed the same file at the same time; the copy holds the
    /// version that did not keep the name.
    ConcurrentEdit,
    /// The name the copy came from is a folder now, so the file was moved
    /// aside instead of replacing the folder.
    FolderAtPath,
}

/// What kind of filesystem entry a record is. A directory carries no size
/// or modification time of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TrashedFile {
    pub local_path: String,
    pub path: String,
    pub version_seq: i64,
    pub last_known_size: u64,
    pub origin_device_id: Option<String>,
    pub deleted_at: Option<SystemTime>,
    pub kind: EntryKind,
    /// The recursive delete or directory rename that removed this entry;
    /// every trashed entry sharing it is restored together by
    /// [`crate::ClientCore::restore_trash_operation`]. `None` for an entry
    /// deleted on its own.
    pub deleted_by_operation: Option<String>,
}

/// What restoring a folder from the trash brought back.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderRestoreOutcome {
    /// Relative to the folder root, in path order.
    pub restored_paths: Vec<String>,
    pub failed: Vec<FolderRestoreFailure>,
    /// Not every part of the operation has reached this device, so what it
    /// removed elsewhere in the folder could not be restored here.
    pub partial: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderRestoreFailure {
    pub path: String,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileVersion {
    pub version_seq: i64,
    pub size: u64,
    pub modified_at: Option<SystemTime>,
    /// The daemon's own state value, for a tooltip.
    pub state: String,
    pub origin_device_id: Option<String>,
    pub unix_mode: Option<u32>,
    /// The highest `version_seq` of the file.
    pub is_current: bool,
    pub kind: EntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MaterializationState {
    Hydrated,
    Placeholder,
    Hydrating,
    Evicting,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileAvailability {
    pub tracked: bool,
    pub state: MaterializationState,
    pub pinned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct EvictOutcome {
    pub evicted: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct HandoffSummary {
    pub target_device_id: String,
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UnlinkOutcome {
    pub handoff: Option<HandoffSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StorageModeOutcome {
    /// `false` when the folder was already in the requested mode.
    pub changed: bool,
    pub handoff: Option<HandoffSummary>,
}

// ---- devices and membership -------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub online: bool,
    /// `None` when the listing does not report it.
    pub last_seen: Option<SystemTime>,
    pub is_this_device: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MembershipHandoff {
    pub group_id: String,
    pub target_device_id: String,
    pub lease_id: String,
    pub membership_generation: u64,
}

/// What a membership removal did. A front end must show the data-loss
/// warning when `forced_group_ids` is non-empty, and the unknown-scope
/// warning when `unknown_scope_operation_id` is set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MembershipOutcome {
    pub handoffs: Vec<MembershipHandoff>,
    pub forced_group_ids: Vec<String>,
    pub unknown_scope_operation_id: Option<String>,
}

// ---- shares -------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ShareRole {
    Owner,
    Editor,
    Viewer,
    Other { raw: String },
}

/// The roles a member can be changed to or invited with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AssignableRole {
    Viewer,
    Editor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MemberRelationship {
    You,
    YourOtherDevice,
    OwnersDevice,
    Invited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MemberStorage {
    FullCopy,
    OnDemand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MemberSummary {
    pub device_id: String,
    pub device_name: String,
    pub role: ShareRole,
    pub relationship: MemberRelationship,
    pub storage: MemberStorage,
    pub online: bool,
    pub last_seen: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PendingApprovalSummary {
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    pub requested_role: Option<ShareRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ShareEdgeState {
    Active,
    PendingApproval,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ShareSummary {
    pub edge_id: String,
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    pub state: ShareEdgeState,
    pub role: Option<ShareRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ApproveOutcome {
    Approved,
    AlreadyActive,
    Unrecognized { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RevokeEdgeOutcome {
    Revoked { outcome: MembershipOutcome },
    AlreadyRevoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct InviteSummary {
    pub invite_id: String,
    pub code: String,
    /// `yadorilink://invite/<code>`, built here so no front end assembles it.
    pub url: String,
    pub group_id: String,
    pub role: ShareRole,
    pub expires_at: SystemTime,
    pub requires_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum InviteStatus {
    Pending,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PendingInviteSummary {
    pub invite_id: String,
    pub group_id: String,
    pub group_name: String,
    pub role: ShareRole,
    pub expires_at: SystemTime,
    pub status: InviteStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AcceptInviteOutcome {
    pub group_id: String,
    pub local_path: String,
    /// The folder is linked but syncs nothing until the owner approves.
    pub awaiting_approval: bool,
}

// ---- linking ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FreeSpace {
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
    pub state: FreeSpaceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum NestedLinkRelation {
    Ancestor,
    Descendant,
    Same,
}

/// One risky condition a link preflight found, in the order the preflight
/// reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PreflightIssue {
    PathMissing,
    IgnoreRulesUnreadable,
    NotEmpty { entry_count: u64, scan_truncated: bool },
    LowFreeSpace { available_bytes: u64, headroom_bytes: u64 },
    CriticalFreeSpace { available_bytes: u64, headroom_bytes: u64 },
    NestedLink { other_path: String, relation: NestedLinkRelation },
    CloudProviderFolder { provider: String },
    FilesystemRoot,
    HomeDirectory,
    ReservedName { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PreflightResult {
    pub resolved_path: String,
    pub path_exists: bool,
    pub is_directory: bool,
    pub entry_count: u64,
    pub ignored_entry_count: u64,
    pub total_size_bytes: u64,
    pub scan_truncated: bool,
    pub free_space: Option<FreeSpace>,
    pub issues: Vec<PreflightIssue>,
    /// The daemon refuses the link unless the risks are acknowledged.
    pub requires_acknowledgement: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct LinkOutcome {
    pub group_id: String,
    pub local_path: String,
    pub mode: FolderMode,
}

// ---- send and receive, storage, settings, updates ---------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SentTransfer {
    pub transfer_id: String,
    pub files_offered: Vec<String>,
    pub total_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct IncomingFile {
    pub relative_path: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum IncomingTransferStatus {
    Pending,
    InProgress,
    Completed,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct IncomingTransfer {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub files: Vec<IncomingFile>,
    pub total_size: u64,
    pub offered_at: Option<SystemTime>,
    pub status: IncomingTransferStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ReceivedTransfer {
    pub destination_dir: String,
    pub files_received: Vec<String>,
    pub bytes_received: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct GcReport {
    pub dry_run: bool,
    pub blocks_deleted: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DiagnosticsCollectionMode {
    /// Assembled by the daemon.
    Daemon,
    /// Assembled by the daemon, which ran out of its time budget.
    DaemonPartial,
    /// The daemon was not reachable; a limited bundle from this process.
    OfflineFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DiagnosticsExport {
    pub path: String,
    pub collection_mode: DiagnosticsCollectionMode,
    pub redaction_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonStartOutcome {
    AlreadyRunning,
    Started,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UpdateInstallMode {
    Automatic,
    Manual,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateConfig {
    pub automatic_checks: bool,
    pub install_mode: UpdateInstallMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateStatus {
    pub current_version: String,
    pub channel: String,
    pub install_source: String,
    pub last_checked_at: Option<SystemTime>,
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub release_notes_url: Option<String>,
    pub mandatory: bool,
    pub holdback_reason: Option<String>,
    pub waiting_for_safe_point: bool,
    pub last_error_category: Option<String>,
    pub last_error_message: Option<String>,
    pub config: UpdateConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UpdateInstallOutcome {
    Installing,
    Deferred,
    /// Updates come from a store; `guidance` says where.
    StoreManaged {
        guidance: String,
    },
    Other {
        raw: String,
    },
}

#[cfg(test)]
mod tests;
