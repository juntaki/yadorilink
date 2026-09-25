//! Folder control, files inside linked folders, and linking.

use super::{about, existing_directory, offering_force, ClientCore};
use crate::dto::{
    self, ConflictSummary, EvictOutcome, FileAvailability, FileVersion, FolderMode,
    FolderRestoreOutcome, LinkOutcome, PreflightResult, StorageModeOutcome, TrashedFile,
    UnlinkOutcome,
};
use crate::error::DesktopError;
use crate::ops;

fn on_demand(mode: FolderMode) -> bool {
    mode == FolderMode::OnDemand
}

impl ClientCore {
    // ---- folder control ----------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn pause_folder(&self, local_path: String) -> Result<(), DesktopError> {
        Ok(ops::folders::pause_folder(local_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn resume_folder(&self, local_path: String) -> Result<(), DesktopError> {
        Ok(ops::folders::resume_folder(local_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn pause_all(&self) -> Result<(), DesktopError> {
        Ok(ops::folders::pause_all().await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn resume_all(&self) -> Result<(), DesktopError> {
        Ok(ops::folders::resume_all().await?)
    }

    /// Stops syncing the folder at `local_path`.
    ///
    /// # Errors
    /// Without `force`, `DurabilityBlocked{can_force: true}` when this device
    /// holds the group's only confirmed complete copy.
    pub async fn unlink_folder(
        &self,
        local_path: String,
        force: bool,
    ) -> Result<UnlinkOutcome, DesktopError> {
        let handoff =
            ops::links::send_unlink(&local_path, force).await.map_err(offering_force(force))?;
        Ok(UnlinkOutcome { handoff: handoff.as_ref().map(dto::handoff_summary) })
    }

    /// Switches this device between keeping every file and fetching on
    /// demand for a group it links. The File Provider domain is the front
    /// end's to reconcile afterwards.
    ///
    /// # Errors
    /// `InvalidInput{field: "group_id"}` when the group is not linked here;
    /// `DurabilityBlocked{can_force: false}` when giving up the complete copy
    /// is not safe yet.
    pub async fn set_storage_mode(
        &self,
        group_id: String,
        mode: FolderMode,
    ) -> Result<StorageModeOutcome, DesktopError> {
        let display = group_id.clone();
        let outcome = ops::shares::set_storage_mode_resolved(group_id, on_demand(mode), &display)
            .await
            .map_err(about("group_id"))?;
        Ok(StorageModeOutcome {
            changed: outcome.changed,
            handoff: outcome.handoff_result.as_ref().map(dto::handoff_summary),
        })
    }

    // ---- files -------------------------------------------------------------------

    /// # Errors
    /// Daemon failures.
    pub async fn list_conflicts(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<ConflictSummary>, DesktopError> {
        let files = ops::files::list_conflicts(local_path.as_deref()).await?;
        Ok(files.iter().map(dto::conflict_summary).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_trash(
        &self,
        local_path: Option<String>,
    ) -> Result<Vec<TrashedFile>, DesktopError> {
        let files = ops::files::list_trash(local_path.as_deref()).await?;
        Ok(files.iter().map(dto::trashed_file).collect())
    }

    /// # Errors
    /// Daemon failures.
    pub async fn restore_from_trash(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::restore_from_trash(absolute_path).await?)
    }

    /// Restores, together, every trashed entry removed by the same
    /// recursive delete or directory rename that removed the entry at
    /// `absolute_path`.
    ///
    /// # Errors
    /// Daemon failures, including an entry that was deleted on its own.
    pub async fn restore_trash_operation(
        &self,
        absolute_path: String,
    ) -> Result<FolderRestoreOutcome, DesktopError> {
        let outcome = ops::files::restore_trash_operation(absolute_path).await?;
        Ok(dto::folder_restore_outcome(&outcome))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn list_versions(
        &self,
        absolute_path: String,
    ) -> Result<Vec<FileVersion>, DesktopError> {
        let versions = ops::files::list_versions(absolute_path).await?;
        Ok(dto::file_versions(&versions))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn restore_version(
        &self,
        absolute_path: String,
        version_seq: Option<i64>,
    ) -> Result<(), DesktopError> {
        Ok(ops::files::restore_version(absolute_path, version_seq).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn file_availability(
        &self,
        absolute_path: String,
    ) -> Result<FileAvailability, DesktopError> {
        let status = ops::files::materialization_status(absolute_path).await?;
        Ok(dto::file_availability(&status))
    }

    /// # Errors
    /// Daemon failures.
    pub async fn pin_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::pin_file(absolute_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn unpin_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::unpin_file(absolute_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn hydrate_file(&self, absolute_path: String) -> Result<(), DesktopError> {
        Ok(ops::files::hydrate_file(absolute_path).await?)
    }

    /// # Errors
    /// Daemon failures.
    pub async fn evict_file(&self, absolute_path: String) -> Result<EvictOutcome, DesktopError> {
        let evict = ops::files::evict(absolute_path).await?;
        Ok(EvictOutcome {
            evicted: evict.dehydrated,
            blocks_reclaimed: evict.blocks_reclaimed,
            bytes_reclaimed: evict.bytes_reclaimed,
        })
    }

    // ---- linking -------------------------------------------------------------------

    /// The checks a link runs first. Pure apart from a best-effort look at
    /// the folders already linked; an unreachable daemon counts as none.
    ///
    /// # Errors
    /// `InvalidInput{field: "local_path"}` when the path does not resolve.
    pub async fn run_preflight(&self, local_path: String) -> Result<PreflightResult, DesktopError> {
        let (resolved, report) =
            ops::links::run_link_preflight(&local_path).await.map_err(about("local_path"))?;
        Ok(dto::preflight_result(&resolved, &report))
    }

    /// Creates a folder group and links it at `local_path`, as one step the
    /// daemon completes or rolls back.
    ///
    /// # Errors
    /// `InvalidInput{field: "local_path"}` for a path that does not resolve;
    /// daemon and coordination failures.
    pub async fn create_group_and_link(
        &self,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        let group_id =
            ops::shares::create_and_link(group_name, absolute, on_demand(mode), acknowledge_risks)
                .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }

    /// Joins a group this account owns and links it at `local_path`.
    ///
    /// # Errors
    /// As [`ClientCore::create_group_and_link`].
    pub async fn join_group_and_link(
        &self,
        group_id: String,
        group_name: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        ops::shares::join_resolved(
            group_id.clone(),
            group_name,
            absolute,
            on_demand(mode),
            acknowledge_risks,
        )
        .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }

    /// Links `local_path` into an existing group.
    ///
    /// # Errors
    /// As [`ClientCore::create_group_and_link`].
    pub async fn link_folder(
        &self,
        local_path: String,
        group_id: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<LinkOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        ops::links::link_resolved_as(
            absolute,
            group_id.clone(),
            on_demand(mode),
            acknowledge_risks,
        )
        .await?;
        Ok(LinkOutcome { group_id, local_path, mode })
    }
}
