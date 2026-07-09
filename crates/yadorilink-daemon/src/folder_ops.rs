//! Folder Operations: divergence summaries, dry-run resolution previews,
//! and confirmation-gated override/revert/mode-change actions for
//! directional (`send-only`/`receive-only`) links.
//!
//! This is layered entirely on top of the existing divergence-tracking
//! primitives (`SyncState::list_out_of_sync`/`list_receive_only_changed`)
//! and resolution actions (`link_manager::override_link`/`revert_link`/
//! `set_link_mode_and_reconcile`) — nothing here changes how divergence is
//! recorded or how a resolution action actually mutates state; it only
//! adds a preview/confirm workflow and audit trail in front of those
//! existing entry points (these operations stay daemon-authoritative).
//!
//! **Preview/confirm/staleness**: `preview_resolution` snapshots exactly
//! the paths the requested action would affect right now and hands back
//! an opaque `preview_id`. `confirm_resolution` looks that snapshot back
//! up, recomputes the *same* affected-path set fresh, and only proceeds
//! if the two sets still match — if anything else resolved/reconciled/
//! re-linked in between (another client, a peer reconnect, a concurrent
//! CLI invocation), the confirm is rejected as stale rather than silently
//! acting on out-of-date information, and the preview is discarded either
//! way (single-use, so a stale confirm can't be retried without a fresh
//! preview).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use yadorilink_sync_core::types::LinkMode;
use yadorilink_sync_core::SyncError;

use crate::daemon_state::DaemonState;
use crate::link_manager;

/// Bounded audit/trace state: this is a diagnostic trail, not a durable
/// record store — old entries are dropped once this many have
/// accumulated, oldest first.
pub const MAX_AUDIT_ENTRIES: usize = 200;

/// Preview snapshots are held in memory only, bounded the same way audit
/// entries are, so an abandoned preview (never confirmed) can't grow this
/// unbounded either.
pub const MAX_PENDING_PREVIEWS: usize = 200;

/// A bounded sample of affected paths returned to callers for display —
/// the full snapshot (used for the staleness comparison) is kept
/// internally regardless of this cap.
pub const AFFECTED_PATHS_SAMPLE_LIMIT: usize = 50;

fn now_unix_nanos() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

/// Which resolution action a preview/confirm pair is for. Mirrors the
/// three existing entry points in `link_manager` exactly — this never
/// introduces a fourth kind of mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionAction {
    /// `link_manager::override_link` — send-only only.
    Override,
    /// `link_manager::revert_link` — receive-only only.
    Revert,
    /// `link_manager::set_link_mode_and_reconcile` to the given target mode.
    ModeChange(LinkMode),
}

impl ResolutionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResolutionAction::Override => "override",
            ResolutionAction::Revert => "revert",
            ResolutionAction::ModeChange(_) => "mode_change",
        }
    }

    pub fn target_mode(&self) -> Option<LinkMode> {
        match self {
            ResolutionAction::ModeChange(mode) => Some(*mode),
            _ => None,
        }
    }
}

/// A link's current divergence state, computed straight from
/// index/reconcile state (`SyncState::count_out_of_sync`/
/// `list_out_of_sync` and the receive-only-changed counterparts) — never
/// a separately-persisted summary that could drift from what reconcile
/// actually recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceSummary {
    pub local_path: String,
    pub group_id: String,
    pub mode: LinkMode,
    pub paused: bool,
    pub out_of_sync_count: u64,
    pub out_of_sync_sample: Vec<String>,
    pub receive_only_changed_count: u64,
    pub receive_only_changed_sample: Vec<String>,
}

pub fn divergence_summary(
    state: &DaemonState,
    local_path: &str,
) -> Result<DivergenceSummary, SyncError> {
    let link = find_link(state, local_path)?;
    let out_of_sync = state.sync_state.list_out_of_sync(&link.group_id)?;
    let receive_only_changed = state.sync_state.list_receive_only_changed(&link.group_id)?;
    Ok(DivergenceSummary {
        local_path: link.local_path,
        group_id: link.group_id,
        mode: link.mode,
        paused: link.paused,
        out_of_sync_count: out_of_sync.len() as u64,
        out_of_sync_sample: out_of_sync.into_iter().take(AFFECTED_PATHS_SAMPLE_LIMIT).collect(),
        receive_only_changed_count: receive_only_changed.len() as u64,
        receive_only_changed_sample: receive_only_changed
            .into_iter()
            .take(AFFECTED_PATHS_SAMPLE_LIMIT)
            .collect(),
    })
}

/// A dry-run preview for a resolution action — computed, never
/// mutating anything. `revision` is an opaque token derived from the
/// snapshot content itself (not just a counter), so `confirm_resolution`
/// can detect staleness even across a daemon restart that happens to
/// reuse preview ids (it can't: ids are never reused, but the revision is
/// an extra independent check at effectively no cost).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionPreview {
    pub preview_id: String,
    pub local_path: String,
    pub action: ResolutionActionSummary,
    pub affected_count: u64,
    pub affected_paths_sample: Vec<String>,
    pub created_at_unix_nanos: i64,
}

/// A serialization-friendly (no `LinkMode` type) summary of `ResolutionAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionActionSummary {
    pub action: &'static str,
    pub target_mode: Option<LinkMode>,
}

struct StoredPreview {
    local_path: String,
    action: ResolutionAction,
    /// Full snapshot, used for the staleness comparison in
    /// `confirm_resolution` — deliberately not truncated the way the
    /// display sample is.
    affected_paths: Vec<String>,
}

#[derive(Default)]
struct PreviewStoreInner {
    previews: std::collections::HashMap<String, StoredPreview>,
    /// Insertion order, so the oldest can be evicted once
    /// `MAX_PENDING_PREVIEWS` is exceeded.
    order: VecDeque<String>,
}

pub struct FolderOpsState {
    previews: Mutex<PreviewStoreInner>,
    audit: Mutex<VecDeque<FolderOperationAuditEntry>>,
    next_id: AtomicU64,
}

impl Default for FolderOpsState {
    fn default() -> Self {
        FolderOpsState {
            previews: Mutex::new(PreviewStoreInner::default()),
            audit: Mutex::new(VecDeque::new()),
            next_id: AtomicU64::new(0),
        }
    }
}

impl FolderOpsState {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert_preview(
        &self,
        local_path: String,
        action: ResolutionAction,
        affected: Vec<String>,
    ) -> String {
        let id = format!(
            "resprev-{}-{}",
            now_unix_nanos(),
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let mut store = self.previews.lock().unwrap_or_else(|p| p.into_inner());
        store.order.push_back(id.clone());
        store
            .previews
            .insert(id.clone(), StoredPreview { local_path, action, affected_paths: affected });
        while store.order.len() > MAX_PENDING_PREVIEWS {
            if let Some(oldest) = store.order.pop_front() {
                store.previews.remove(&oldest);
            }
        }
        id
    }

    /// Removes and returns the preview, single-use regardless of outcome —
    /// a confirm that fails staleness must be preceded by a fresh preview,
    /// not retried against the same one.
    fn take_preview(&self, preview_id: &str) -> Option<StoredPreview> {
        let mut store = self.previews.lock().unwrap_or_else(|p| p.into_inner());
        let preview = store.previews.remove(preview_id);
        if preview.is_some() {
            store.order.retain(|id| id != preview_id);
        }
        preview
    }

    fn record_audit(&self, entry: FolderOperationAuditEntry) {
        let mut audit = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        audit.push_back(entry);
        while audit.len() > MAX_AUDIT_ENTRIES {
            audit.pop_front();
        }
    }

    /// Diagnostics integration: the most recent audit entries,
    /// newest first, optionally filtered to one link.
    pub fn audit_entries(&self, local_path: Option<&str>) -> Vec<FolderOperationAuditEntry> {
        let audit = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        audit
            .iter()
            .rev()
            .filter(|entry| local_path.is_none_or(|p| entry.local_path == p))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderOperationAuditEntry {
    pub local_path: String,
    pub action: &'static str,
    pub target_mode: Option<LinkMode>,
    pub affected_count: u64,
    pub resolved_at_unix_nanos: i64,
}

fn find_link(
    state: &DaemonState,
    local_path: &str,
) -> Result<yadorilink_sync_core::index::FolderLink, SyncError> {
    state
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.local_path == local_path)
        .ok_or_else(|| SyncError::NotFound(format!("link {local_path}")))
}

/// The same divergence lists as `divergence_summary`, but scoped to
/// exactly what `action` would affect right now — shared by both
/// `preview_resolution` (to snapshot) and `confirm_resolution` (to
/// re-derive fresh, for the staleness check).
fn affected_paths_for(
    state: &DaemonState,
    link: &yadorilink_sync_core::index::FolderLink,
    action: ResolutionAction,
) -> Result<Vec<String>, SyncError> {
    match action {
        ResolutionAction::Override => {
            if link.mode != LinkMode::SendOnly {
                return Err(SyncError::InvalidLinkMode(format!(
                    "override is only valid on a send-only link; {} is currently {}",
                    link.local_path,
                    link.mode.as_db_str()
                )));
            }
            state.sync_state.list_out_of_sync(&link.group_id)
        }
        ResolutionAction::Revert => {
            if link.mode != LinkMode::ReceiveOnly {
                return Err(SyncError::InvalidLinkMode(format!(
                    "revert is only valid on a receive-only link; {} is currently {}",
                    link.local_path,
                    link.mode.as_db_str()
                )));
            }
            state.sync_state.list_receive_only_changed(&link.group_id)
        }
        ResolutionAction::ModeChange(target_mode) => {
            // Mirrors `set_link_mode_and_reconcile`'s own clearing rule
            // exactly (`preview_resolution` must never predict something
            // different from what `confirm_resolution` will actually do):
            // moving to a mode still clears whichever divergence set that
            // mode can no longer produce.
            let mut affected = Vec::new();
            if target_mode != LinkMode::SendOnly {
                affected.extend(state.sync_state.list_out_of_sync(&link.group_id)?);
            }
            if target_mode != LinkMode::ReceiveOnly {
                affected.extend(state.sync_state.list_receive_only_changed(&link.group_id)?);
            }
            Ok(affected)
        }
    }
}

/// Computes and stores a dry-run preview. Rejects exactly the
/// same preconditions the real action would (wrong mode, paused link),
/// so a preview is never misleadingly "successful" for a request
/// `confirm_resolution` could never actually satisfy.
pub fn preview_resolution(
    state: &DaemonState,
    local_path: &str,
    action: ResolutionAction,
) -> Result<ResolutionPreview, SyncError> {
    let link = find_link(state, local_path)?;
    if matches!(action, ResolutionAction::Override | ResolutionAction::Revert) && link.paused {
        return Err(SyncError::InvalidLinkMode(format!(
            "cannot resolve {local_path}: link is paused (resume it first)"
        )));
    }
    let affected = affected_paths_for(state, &link, action)?;
    let preview_id =
        state.folder_ops.insert_preview(link.local_path.clone(), action, affected.clone());
    Ok(ResolutionPreview {
        preview_id,
        local_path: link.local_path,
        action: ResolutionActionSummary {
            action: action.as_str(),
            target_mode: action.target_mode(),
        },
        affected_count: affected.len() as u64,
        affected_paths_sample: affected.into_iter().take(AFFECTED_PATHS_SAMPLE_LIMIT).collect(),
        created_at_unix_nanos: now_unix_nanos(),
    })
}

/// Performs the resolution action named by `preview_id`, but only if the
/// affected-path set computed fresh right now still matches what was
/// snapshotted at preview time (order-independent — a concurrent
/// reconcile that only reorders `list_out_of_sync`'s result isn't a real
/// change). Any mismatch — including the preview having already
/// expired/been consumed — is `SyncError::InvalidLinkMode` (stale
/// preview rejection), and the preview is discarded either way.
pub async fn confirm_resolution(state: &DaemonState, preview_id: &str) -> Result<u64, SyncError> {
    let Some(stored) = state.folder_ops.take_preview(preview_id) else {
        return Err(SyncError::InvalidLinkMode(format!(
            "resolution preview {preview_id} not found or already used; request a new preview"
        )));
    };
    let link = find_link(state, &stored.local_path)?;
    let current = affected_paths_for(state, &link, stored.action)?;

    let mut expected: Vec<&String> = stored.affected_paths.iter().collect();
    let mut actual: Vec<&String> = current.iter().collect();
    expected.sort();
    actual.sort();
    if expected != actual {
        return Err(SyncError::InvalidLinkMode(format!(
            "resolution preview {preview_id} is stale: {} has changed since the preview was taken; request a new preview",
            stored.local_path
        )));
    }

    let affected_count = match stored.action {
        ResolutionAction::Override => {
            link_manager::override_link(state, &stored.local_path).await?
        }
        ResolutionAction::Revert => link_manager::revert_link(state, &stored.local_path).await?,
        ResolutionAction::ModeChange(mode) => {
            link_manager::set_link_mode_and_reconcile(state, &stored.local_path, mode).await?;
            stored.affected_paths.len() as u64
        }
    };

    state.folder_ops.record_audit(FolderOperationAuditEntry {
        local_path: stored.local_path,
        action: stored.action.as_str(),
        target_mode: stored.action.target_mode(),
        affected_count,
        resolved_at_unix_nanos: now_unix_nanos(),
    });
    Ok(affected_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_state::DaemonState;
    use std::sync::Arc;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;
    use yadorilink_sync_core::version_vector::VersionVector;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    fn record(path: &str) -> yadorilink_sync_core::types::FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        yadorilink_sync_core::types::FileRecord {
            path: path.to_string(),
            size: 3,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    #[tokio::test]
    async fn preview_and_confirm_override_clears_out_of_sync() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.upsert_file("group-1", &record("a.txt")).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.txt", 1).unwrap();

        let summary = divergence_summary(&state, "/tmp/photos").unwrap();
        assert_eq!(summary.out_of_sync_count, 1);

        let preview =
            preview_resolution(&state, "/tmp/photos", ResolutionAction::Override).unwrap();
        assert_eq!(preview.affected_count, 1);

        let resolved = confirm_resolution(&state, &preview.preview_id).await.unwrap();
        assert_eq!(resolved, 1);
        assert_eq!(state.sync_state.count_out_of_sync("group-1").unwrap(), 0);

        let audit = state.folder_ops.audit_entries(None);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "override");
        assert_eq!(audit[0].affected_count, 1);
    }

    #[tokio::test]
    async fn confirm_rejects_a_stale_preview() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.upsert_file("group-1", &record("a.txt")).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.txt", 1).unwrap();

        let preview =
            preview_resolution(&state, "/tmp/photos", ResolutionAction::Override).unwrap();

        // State changes after the preview was taken: a second divergent
        // path shows up before the confirm arrives.
        state.sync_state.upsert_file("group-1", &record("b.txt")).unwrap();
        state.sync_state.record_out_of_sync("group-1", "b.txt", 2).unwrap();

        let err = confirm_resolution(&state, &preview.preview_id).await.unwrap_err();
        assert!(matches!(err, SyncError::InvalidLinkMode(_)), "{err:?}");
        // Rejected as stale, not silently resolved against the new state.
        assert_eq!(state.sync_state.count_out_of_sync("group-1").unwrap(), 2);
    }

    #[tokio::test]
    async fn confirm_rejects_an_unknown_or_already_used_preview_id() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();

        let err = confirm_resolution(&state, "resprev-does-not-exist").await.unwrap_err();
        assert!(matches!(err, SyncError::InvalidLinkMode(_)), "{err:?}");
    }

    #[tokio::test]
    async fn preview_rejects_override_on_a_link_that_is_not_send_only() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();

        let err =
            preview_resolution(&state, "/tmp/photos", ResolutionAction::Override).unwrap_err();
        assert!(matches!(err, SyncError::InvalidLinkMode(_)), "{err:?}");
    }

    #[tokio::test]
    async fn mode_change_preview_reports_both_sets_when_returning_to_send_receive() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.upsert_file("group-1", &record("a.txt")).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.txt", 1).unwrap();

        let preview = preview_resolution(
            &state,
            "/tmp/photos",
            ResolutionAction::ModeChange(LinkMode::SendReceive),
        )
        .unwrap();
        assert_eq!(preview.affected_count, 1);

        confirm_resolution(&state, &preview.preview_id).await.unwrap();
        assert_eq!(state.sync_state.count_out_of_sync("group-1").unwrap(), 0);
    }
}
