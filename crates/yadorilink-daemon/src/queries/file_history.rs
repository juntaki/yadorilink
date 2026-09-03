//! Version history and trash reads for `ListVersions`/`ListTrash` --
//! resolves an absolute path via `LinkedPathResolver`, then reads
//! `SyncState`'s already domain-shaped `VersionRecord`/`TrashedFile` rows
//! directly rather than inventing a parallel view type for them (they are
//! already plain, not protobuf).

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{TrashedFile, VersionRecord};

use crate::queries::linked_path::LinkedPathResolver;
use crate::replica_coordinator::ReplicaCoordinator;

#[derive(Debug, Clone)]
pub(crate) struct TrashedFileView {
    pub(crate) local_path: String,
    pub(crate) trashed: TrashedFile,
}

/// A live (non-deleted) conflicted-copy file, tagged with its link's
/// `local_path` -- mirrors `TrashedFileView`'s own per-link tagging shape.
/// Same underlying set `LinkStatus.conflict_count` counts, by construction
/// (both read `list_live_conflict_copies`).
#[derive(Debug, Clone)]
pub(crate) struct ConflictedFileView {
    pub(crate) local_path: String,
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mtime_unix_nanos: i64,
}

pub(crate) struct FileHistoryQueryService {
    sync_state: Arc<ReplicaCoordinator>,
    paths: Arc<LinkedPathResolver>,
}

impl FileHistoryQueryService {
    pub(crate) fn new(sync_state: Arc<ReplicaCoordinator>, paths: Arc<LinkedPathResolver>) -> Self {
        Self { sync_state, paths }
    }

    /// `None` when `absolute_path` isn't under any linked folder --
    /// distinct from `Ok(Some(vec![]))`, which means "resolved, no
    /// versions retained".
    pub(crate) fn list_versions(
        &self,
        absolute_path: &str,
    ) -> Result<Option<Vec<VersionRecord>>, SyncError> {
        let Some((group_id, path)) = self.paths.resolve(absolute_path) else {
            return Ok(None);
        };
        self.sync_state
            .sqlite()
            .dag_list_versions(&group_id, &path)
            .map(Some)
            .map_err(SyncError::from)
    }

    /// Every trashed file across every linked folder, each tagged with its
    /// link's own `local_path` -- mirrors `RuntimeStatusQueryService`'s own
    /// per-link iteration pattern.
    pub(crate) fn list_trash(&self) -> Result<Vec<TrashedFileView>, SyncError> {
        let mut out = Vec::new();
        for link in self.sync_state.link_repository().list_links()? {
            for trashed in self.sync_state.file_index_repository().list_trashed(&link.group_id)? {
                out.push(TrashedFileView { local_path: link.local_path.clone(), trashed });
            }
        }
        Ok(out)
    }

    /// Every currently-live conflicted-copy file across every linked
    /// folder, each tagged with its link's own `local_path` -- same
    /// per-link iteration shape as `list_trash`. Reads
    /// `list_live_conflict_copies`, the same targeted query
    /// `LinkStatusReadPort::list_links`'s `conflict_count` reads from, so
    /// the two can never disagree about which paths count.
    pub(crate) fn list_conflicts(&self) -> Result<Vec<ConflictedFileView>, SyncError> {
        let mut out = Vec::new();
        for link in self.sync_state.link_repository().list_links()? {
            for file in
                self.sync_state.file_index_repository().list_live_conflict_copies(&link.group_id)?
            {
                out.push(ConflictedFileView {
                    local_path: link.local_path.clone(),
                    path: file.path,
                    size: file.size,
                    mtime_unix_nanos: file.mtime_unix_nanos,
                });
            }
        }
        Ok(out)
    }
}
