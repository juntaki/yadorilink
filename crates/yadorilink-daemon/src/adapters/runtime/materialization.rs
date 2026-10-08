//! `hydration`-backed [`MaterializationPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;

use crate::application::ports::{
    BoxFuture, EvictOutcome, MaterializationPort, MaterializationStatusSummary,
};
use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::hydration::directory;
use yadorilink_replica_domain::session_state::MaterializationState;

pub(crate) struct DaemonMaterializationAdapter {
    state: Arc<DaemonState>,
}

impl DaemonMaterializationAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

/// A folder is asked for as a whole: every request acts on the files below
/// it (see `hydration::directory`). Anything else is one file.
impl MaterializationPort for DaemonMaterializationAdapter {
    fn materialize_to_temp<'a>(
        &'a self,
        request: crate::application::ports::TempMaterialization<'a>,
    ) -> BoxFuture<'a, Result<crate::application::ports::TempOutcome, SyncError>> {
        Box::pin(async move {
            match hydration::materialize_path(
                &self.state,
                request.group_id,
                request.path,
                hydration::Sink::Temp(&request),
            )
            .await?
            {
                hydration::Materialized::Temp(outcome) => Ok(outcome),
                hydration::Materialized::InPlace => Err(SyncError::CorruptState(
                    "a temp materialization produced an in-place result".into(),
                )),
            }
        })
    }

    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>> {
        Box::pin(async move {
            let path = path.trim_end_matches('/');
            if directory::is_indexed_directory(&self.state, group_id, path)? {
                return directory::hydrate_directory(&self.state, group_id, path).await;
            }
            hydration::materialize_path(&self.state, group_id, path, hydration::Sink::InPlace)
                .await
                .map(|_| ())
        })
    }

    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
        let path = path.trim_end_matches('/');
        if directory::is_indexed_directory(&self.state, group_id, path)? {
            return directory::evict_directory(&self.state, group_id, path).map(|outcome| {
                EvictOutcome {
                    dehydrated: outcome.evicted_files > 0,
                    blocks_reclaimed: outcome.blocks_reclaimed,
                    bytes_reclaimed: outcome.bytes_reclaimed,
                }
            });
        }
        hydration::evict(&self.state, group_id, path).map(|outcome| EvictOutcome {
            dehydrated: outcome.dehydrated,
            blocks_reclaimed: outcome.blocks_reclaimed,
            bytes_reclaimed: outcome.bytes_reclaimed,
        })
    }

    fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
        let path = path.trim_end_matches('/');
        let is_directory = directory::is_indexed_directory(&self.state, group_id, path)?;
        let info = if is_directory {
            Some(directory::directory_status(&self.state, group_id, path)?)
        } else {
            hydration::materialization_status(&self.state, group_id, path)?
        };
        // `Present` over an object that is not the current version's content
        // (an older version's bytes under a newer row) is an object that
        // stands without current content: the two facts are reported apart.
        // Fail closed: a kind or proof that cannot be read is not evidence.
        let content_is_current = || {
            if is_directory {
                return true;
            }
            let kind = self
                .state
                .replica_coordinator
                .file_index_repository()
                .get_record_kind(group_id, path)
                .ok()
                .flatten();
            match kind {
                None => false,
                Some(kind) if kind != yadorilink_replica_domain::file::RecordKind::File => true,
                Some(_) => self
                    .state
                    .replica_coordinator
                    .local_copy_names_current_version(group_id, path)
                    .unwrap_or(false),
            }
        };
        Ok(info.and_then(|info| {
            let exact = info.state == MaterializationState::Present && content_is_current();
            crate::shell_status::local_presence(Some(info.state), exact)
                .map(|state| MaterializationStatusSummary { state })
        }))
    }
}
