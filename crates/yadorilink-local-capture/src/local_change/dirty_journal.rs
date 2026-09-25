//! The durable `local_dirty_paths` journal: re-driving journaled paths
//! and the on-disk encoding of their event kind.

use std::path::{Path, PathBuf};

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;

use super::{FlushOutcome, LocalChangeProcessor};

/// Serialized `FsChangeKind` as stored in the `local_dirty_paths` journal, so a
/// startup/backstop re-drive can reconstruct the exact `FsChangeEvent`.
pub(super) fn dirty_kind_str(kind: FsChangeKind) -> &'static str {
    match kind {
        FsChangeKind::CreatedOrModified => "created_or_modified",
        FsChangeKind::Removed => "removed",
    }
}

/// Inverse of [`dirty_kind_str`]. Any unrecognized value maps to
/// `CreatedOrModified` — the safe default, since re-reading a path that turns
/// out to be absent still self-corrects to a deletion inside `process_event`.
pub(super) fn dirty_kind_from_str(s: &str) -> FsChangeKind {
    match s {
        "removed" => FsChangeKind::Removed,
        _ => FsChangeKind::CreatedOrModified,
    }
}

/// Why a path whose content changed while it was being read stays dirty.
pub(super) const CHANGED_DURING_READ: &str =
    "content changed while it was being read; left for a later capture";

impl LocalChangeProcessor {
    /// The key a flush of `path` under `root` journals it dirty by, or
    /// `None` if the path cannot be journaled at all (outside `root`, or
    /// not representable as a wire path). A caller asking whether a flush
    /// left `path` uncaptured must ask about exactly this key.
    pub fn dirty_journal_key(root: &Path, path: &Path) -> Option<String> {
        super::path_policy::relative_key(root, path)
    }

    /// Leaves `rel_path` journaled dirty after a pass that could not capture
    /// it (`LocalChangeOutcome::RetryLater`): the row re-drives the edit on
    /// the next flush or backstop, and holds a remote change for this path
    /// back until the edit is captured.
    pub(super) fn journal_uncaptured_local_edit(
        &self,
        group_id: &str,
        rel_path: &str,
        observed_at_unix_nanos: i64,
    ) -> Result<(), LocalCaptureError> {
        self.state.record_dirty_path(
            group_id,
            rel_path,
            dirty_kind_str(FsChangeKind::CreatedOrModified),
            observed_at_unix_nanos,
            &self.begin_operation()?.permit(),
        )?;
        self.state.mark_dirty_path_attempt(
            group_id,
            rel_path,
            CHANGED_DURING_READ,
            &self.begin_operation()?.permit(),
        )?;
        Ok(())
    }

    /// Re-drives every path still journaled dirty for `group_id` through the
    /// normal flush executor — the daemon's startup rescan and the durability
    /// backstop against a crash, a restart, or a disk fault that outlived the
    /// in-flight retry. Each `local_dirty_paths` row is turned back into the
    /// exact `FsChangeEvent` the debounce executor would have processed and run
    /// through `process_flush`, which re-reads the path, re-derives its record,
    /// commits the index + change DAG, and (on success) clears the row. A path
    /// whose on-disk content already matches the index resolves to `None` and
    /// is simply cleared — idempotent, never a spurious re-edit; one that still
    /// can't be processed stays journaled for the next attempt. Returns the
    /// produced records so the caller can announce them exactly as a live
    /// flush would.
    pub async fn redrive_dirty_journal(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        let dirty = self.state.list_dirty_paths(group_id)?;
        if dirty.is_empty() {
            return Ok(FlushOutcome::default());
        }
        tracing::info!(
            group_id,
            count = dirty.len(),
            "re-driving journaled local dirty paths (startup/backstop rescan)"
        );
        // Reconstruct absolute event paths the same way the watcher produced
        // them — `process_event_with_ignore_at` re-relativizes against a
        // canonicalized `root`, so joining onto the canonical root here round-
        // trips to the stored relative key.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let paths: Vec<(PathBuf, FsChangeKind, i64)> = dirty
            .into_iter()
            .map(|d| {
                (
                    canonical_root.join(&d.path),
                    dirty_kind_from_str(&d.change_kind),
                    d.observed_at_unix_nanos,
                )
            })
            .collect();
        self.process_flush(group_id, root, DebounceFlush::Paths(paths)).await
    }
}
