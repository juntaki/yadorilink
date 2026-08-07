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
}
