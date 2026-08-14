//! `ListLinks`/`Status`'s shared per-link read model -- the first vertical
//! slice of the control-socket query boundary: a plain, non-protobuf view
//! (`LinkStatusView`) behind a narrow port (`LinkStatusReadPort`), backed
//! today by an adapter (`DaemonLinkStatusReader`) that still holds
//! `Arc<DaemonState>` -- seeing every field this view
//! aggregates already lives on `DaemonState`/its owned components, that's
//! a deliberate strangler step, not a shortcut: the port is the real
//! boundary, and the control socket handler now depends on it, not on
//! `DaemonState`.

use std::sync::Arc;

use crate::durability_service::GroupDurabilityStatus;

/// M4 Pass 2: this link's TRUTHFUL current local storage state -- distinct
/// from `materialization_policy` (the CONFIGURED target, "eager" |
/// "ondemand"), which only says what this device is trying to become, not
/// what it currently holds. Deliberately NOT derived from policy alone:
/// an eager link that hasn't finished catching up must report
/// `PartiallyMaterialized`, never `FullCopy`, until every current file is
/// recorded hydrated.
///
/// Known limitation (M4 Pass 2 Codex review #2 finding #3, not newly
/// introduced by this pass -- the OLD `hydrated_count`/`placeholder_count`
/// fields this replaces carried the identical trust boundary): `FullCopy`
/// reflects the `files.materialization_state` DB column's bookkeeping, not
/// a live disk verification (existence/size/block-content check) -- a row
/// left `Hydrated` after its on-disk file is externally deleted or
/// corrupted would still report `FullCopy` until the separate
/// materialization-repair backstop reconciles it. Actually verifying disk
/// state on every `status` call would make every invocation stat every
/// file, a cost out of proportion to this read-only query; the repair
/// backstop is the real fix for that drift, out of this pass's scope. The
/// variant name and doc wording are deliberately scoped to what this
/// derivation actually proves ("recorded hydrated"), not a stronger claim
/// disk verification alone would justify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalStorageState {
    /// Materialization policy is eager AND every current file is recorded
    /// hydrated (see this enum's own doc comment for the DB-bookkeeping
    /// vs. live-disk-verification distinction).
    FullCopy,
    /// Materialization policy is eager, but at least one current file is
    /// still a placeholder or hydrating -- this device intends to become a
    /// full copy but is not one yet.
    PartiallyMaterialized,
    /// Materialization policy is on-demand -- placeholders for
    /// not-yet-opened files are this link's normal steady state, not a
    /// transient "catching up" condition.
    OnDemand,
}

/// M4 Pass 2: whether this link's required current-version content can
/// actually be obtained right now, locally or through a valid serving
/// path. Deliberately NOT an alias for `PeerReachability` -- a reachable
/// peer that isn't a full-replica writer for this group proves nothing
/// about fetchability, and content already hydrated locally is available
/// regardless of any peer's reachability at all. See
/// `DaemonLinkStatusReader::fetch_availability`'s own doc comment for the
/// exact derivation and its link-level aggregation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchAvailability {
    /// Every current file's content is either already hydrated locally, or
    /// this device knows of a currently-reachable full-replica peer that
    /// can serve what isn't.
    AvailableNow,
    /// At least one current file is neither hydrated locally nor
    /// obtainable from any currently-reachable full-replica peer.
    UnavailableNow,
    /// This daemon cannot currently vouch for either answer (the same
    /// daemon-wide "cannot currently confirm" condition that gates
    /// `durability_status` to `DurabilityUnknown` -- see
    /// `DaemonState::daemon_wide_evidence_uncertain`).
    Unknown,
}

/// One held (pinned, undeletable-on-demand) file within a link, as
/// reported by `SyncState::get_held_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldFileView {
    pub(crate) path: String,
    pub(crate) reason: String,
    pub(crate) held_since_unix_nanos: i64,
}

/// A link's Degraded (disk-pressure) state, if any -- see
/// `DegradedLinkInfo`'s own doc comment for what
/// this tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DegradedLinkView {
    pub(crate) reason: String,
}

/// A link's active-transfer rollup, if any transfer is currently in
/// flight for it -- see `crate::transfer_progress::LinkProgressRollup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkTransferView {
    pub(crate) bytes_done: u64,
    pub(crate) bytes_total: u64,
    pub(crate) blocks_done: u64,
    pub(crate) blocks_total: u64,
    pub(crate) eta_seconds: Option<u64>,
}

/// One linked folder's full status, as `ListLinks`/`Status` report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkStatusView {
    pub(crate) local_path: String,
    pub(crate) group_id: String,
    pub(crate) paused: bool,
    pub(crate) conflict_count: u64,
    /// `MaterializationPolicy::as_db_str()`'s own stable string, not
    /// re-derived as a separate enum here -- see that method's own doc.
    pub(crate) materialization_policy: String,
    pub(crate) hydrated_count: u64,
    pub(crate) placeholder_count: u64,
    pub(crate) hydrating_count: u64,
    pub(crate) held_files: Vec<HeldFileView>,
    pub(crate) skipped_symlink_count: u64,
    pub(crate) degraded: Option<DegradedLinkView>,
    pub(crate) transfer: Option<LinkTransferView>,
    pub(crate) durability_status: GroupDurabilityStatus,
    pub(crate) policy_stale: bool,
    /// M4 Pass 2: see `LocalStorageState`'s own doc comment.
    pub(crate) local_storage_state: LocalStorageState,
    /// M4 Pass 2: see `FetchAvailability`'s own doc comment.
    pub(crate) fetch_availability: FetchAvailability,
    /// Every live folder registered for this link's group; more than one
    /// entry means the group is linked twice and refusing to sync -- the
    /// invariant this reports on.
    pub(crate) ambiguous_local_paths: Vec<String>,
    /// M4 Pass 3: device ids of every OTHER device currently recorded
    /// (netmap-derived, content-blind) as an authorized-writer full
    /// replica for this group -- feeds the user-facing "Complete copies"
    /// per-device list. Cross-reference against `StatusResponse.peers`'s
    /// own `reachability` for each device's current availability; this
    /// list alone says nothing about whether any of them are online.
    pub(crate) full_replica_device_ids: Vec<String>,
}

pub(crate) trait LinkStatusReadPort: Send + Sync {
    fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError>;
}

pub(crate) struct LinkStatusQueryService {
    reader: Arc<dyn LinkStatusReadPort>,
}

impl LinkStatusQueryService {
    pub(crate) fn new(reader: Arc<dyn LinkStatusReadPort>) -> Self {
        Self { reader }
    }

    pub(crate) fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError> {
        self.reader.list_links()
    }
}
