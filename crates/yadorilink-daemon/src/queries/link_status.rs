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
    /// Every live folder registered for this link's group; more than one
    /// entry means the group is linked twice and refusing to sync -- the
    /// invariant this reports on.
    pub(crate) ambiguous_local_paths: Vec<String>,
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
