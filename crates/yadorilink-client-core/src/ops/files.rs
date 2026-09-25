//! Per-file operations inside linked folders: conflicts, trash, version
//! history, and on-demand materialization (pin, unpin, hydrate, evict).
//!
//! Paths are absolute paths under a linked folder; resolving what a person
//! typed into one is the caller's job.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, EvictRequest, EvictResponse, FileVersionInfo, HydrateRequest,
    ListConflictsRequest, ListTrashRequest, ListVersionsRequest, MaterializationStatusRequest,
    MaterializationStatusResponse, PinRequest, RestoreTrashOperationRequest,
    RestoreTrashOperationResponse, RestoreTrashRequest, RestoreVersionRequest, TrashedFileInfo,
    UnpinRequest,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Currently-live conflicted-copy files, across every link, or only the
/// link at `local_path`.
pub async fn list_conflicts(
    local_path: Option<&str>,
) -> Result<Vec<ConflictedFileInfo>, CoreError> {
    let resp = control::send(ReqPayload::ListConflicts(ListConflictsRequest {})).await?;
    let Some(RespPayload::ListConflicts(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.files.into_iter().filter(|f| local_path.is_none_or(|p| f.local_path == p)).collect())
}

/// Currently-recoverable trashed files, across every link, or only the link
/// at `local_path`.
pub async fn list_trash(local_path: Option<&str>) -> Result<Vec<TrashedFileInfo>, CoreError> {
    let resp = control::send(ReqPayload::ListTrash(ListTrashRequest {})).await?;
    let Some(RespPayload::ListTrash(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.files.into_iter().filter(|f| local_path.is_none_or(|p| f.local_path == p)).collect())
}

/// Recovers a deleted file's last version before deletion as a new current
/// version.
pub async fn restore_from_trash(absolute_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::RestoreTrash(RestoreTrashRequest { absolute_path })).await?;
    Ok(())
}

/// Recovers, together, every trashed entry removed by the same recursive
/// delete or directory rename that removed the trashed entry at
/// `absolute_path`.
pub async fn restore_trash_operation(
    absolute_path: String,
) -> Result<RestoreTrashOperationResponse, CoreError> {
    let resp = control::send(ReqPayload::RestoreTrashOperation(RestoreTrashOperationRequest {
        absolute_path,
    }))
    .await?;
    let Some(RespPayload::RestoreTrashOperation(outcome)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(outcome)
}

/// Every retained version of one file, newest first including the current
/// one.
pub async fn list_versions(absolute_path: String) -> Result<Vec<FileVersionInfo>, CoreError> {
    let resp =
        control::send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path })).await?;
    let Some(RespPayload::ListVersions(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.versions)
}

/// Restores one file to a specific prior version, or (when `version_seq` is
/// `None`) the most recently superseded one, as a new current version.
pub async fn restore_version(
    absolute_path: String,
    version_seq: Option<i64>,
) -> Result<(), CoreError> {
    control::send(ReqPayload::RestoreVersion(RestoreVersionRequest { absolute_path, version_seq }))
        .await?;
    Ok(())
}

/// One file's current materialization state and pin flag.
pub async fn materialization_status(
    absolute_path: String,
) -> Result<MaterializationStatusResponse, CoreError> {
    let resp = control::send(ReqPayload::MaterializationStatus(MaterializationStatusRequest {
        absolute_path,
    }))
    .await?;
    let Some(RespPayload::MaterializationStatus(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(status)
}

/// Force-hydrates a placeholder file and keeps it hydrated.
pub async fn pin_file(absolute_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::Pin(PinRequest { absolute_path })).await?;
    Ok(())
}

/// Allows a pinned file to become a placeholder again.
pub async fn unpin_file(absolute_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::Unpin(UnpinRequest { absolute_path })).await?;
    Ok(())
}

/// Fetches a placeholder file's real content.
pub async fn hydrate_file(absolute_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::Hydrate(HydrateRequest { absolute_path })).await?;
    Ok(())
}

/// Converts a hydrated file back into a placeholder to reclaim local disk
/// space. Returns whether the file was actually dehydrated: a request that
/// did nothing (the file is pinned, busy, not fully synced, or was just
/// modified) must never read as success.
pub async fn evict_file(absolute_path: String) -> Result<bool, CoreError> {
    Ok(evict(absolute_path).await?.dehydrated)
}

/// [`evict_file`] with the daemon's whole answer, including what the
/// eviction reclaimed.
pub async fn evict(absolute_path: String) -> Result<EvictResponse, CoreError> {
    let resp = control::send(ReqPayload::Evict(EvictRequest { absolute_path })).await?;
    let Some(RespPayload::Evict(evict)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(evict)
}
