//! Pin, unpin, evict and download for a directory as a whole.
//!
//! A directory has no bytes of its own, so what a user asks of it is a
//! policy over what is below it. Pinning a directory keeps everything at or
//! below it on this device -- the entries there now and the ones that arrive
//! later -- through a prefix policy the file-level readers already consult
//! (eviction candidates, the repair pass that fetches owed bytes, and each
//! file's `is_pinned`). Evicting a directory releases that policy and then
//! frees every file below it that nothing else keeps. Unpinning releases the
//! policy only. Downloading hydrates every file below it.
//!
//! All of this is local projection policy: nothing here authors a change or
//! alters what the folder's history says.

use std::sync::Arc;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;

use crate::daemon_state::DaemonState;
use crate::sync_error::SyncError;

use super::MaterializationStatusInfo;

/// Whether `path` names a directory of the link: the link root (`""`), a
/// live explicit directory entry, or a path with live entries below it.
pub(crate) fn is_indexed_directory(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncError> {
    if path.is_empty() {
        return Ok(true);
    }
    let index = state.replica_coordinator.file_index_repository();
    let live_row = index.get_file(group_id, path)?.is_some_and(|row| !row.deleted);
    if live_row {
        return Ok(index.get_record_kind(group_id, path)? == Some(RecordKind::Directory));
    }
    Ok(index.has_live_descendant_row(group_id, path)?)
}

/// Keeps everything at or below the directory `prefix` on this device,
/// now and later, then fetches what is below it that is not here yet. The
/// policy stands even when a file cannot be fetched right now: the repair
/// pass fetches it once a peer can serve it.
pub(crate) async fn pin_directory(
    state: &Arc<DaemonState>,
    group_id: &str,
    prefix: &str,
) -> Result<(), SyncError> {
    state
        .replica_coordinator
        .file_index_repository()
        .set_directory_pinned(group_id, prefix, true)?;
    for path in files_not_hydrated_under(state, group_id, prefix)? {
        if let Err(error) = super::hydrate(state, group_id, &path).await {
            tracing::debug!(
                %error,
                group_id,
                directory = prefix,
                path = %path,
                "a file below a pinned directory could not be fetched yet"
            );
        }
    }
    Ok(())
}

/// Releases the pin on the directory `prefix`. A file's own pin is
/// separate and stays. A directory a pinned directory above it keeps is
/// refused, since unpinning it would change nothing.
pub(crate) fn unpin_directory(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<(), SyncError> {
    refuse_if_kept_by_ancestor(state, group_id, prefix)?;
    state
        .replica_coordinator
        .file_index_repository()
        .set_directory_pinned(group_id, prefix, false)?;
    Ok(())
}

/// Unpins `path` where no directory is: a file, or nothing at all. A
/// pinned directory above it that keeps it refuses the unpin. A folder
/// policy left at `path` itself -- the folder was deleted or renamed away,
/// and a file may have taken its name since -- is released too, and is
/// enough to make the unpin succeed when nothing is at `path` any more;
/// otherwise the file's own pin is cleared as before.
pub(crate) async fn unpin_non_directory(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    refuse_if_kept_by_ancestor(state, group_id, path)?;
    let released_folder_policy = state
        .replica_coordinator
        .file_index_repository()
        .set_directory_pinned(group_id, path, false)?;
    match super::unpin(state, group_id, path).await {
        Err(SyncError::NotFound(_)) if released_folder_policy => Ok(()),
        other => other,
    }
}

fn refuse_if_kept_by_ancestor(
    state: &DaemonState,
    group_id: &str,
    path: &str,
) -> Result<(), SyncError> {
    match state
        .replica_coordinator
        .file_index_repository()
        .pinned_directory_above(group_id, path)?
    {
        Some(directory) => Err(SyncError::InvalidInput(format!(
            "{path} is kept on this device because the folder {} is pinned; unpin that folder \
             instead",
            if directory.is_empty() { "root" } else { directory.as_str() }
        ))),
        None => Ok(()),
    }
}

/// What evicting a directory freed.
#[derive(Debug)]
pub(crate) struct DirectoryEviction {
    pub(crate) evicted_files: u64,
    pub(crate) blocks_reclaimed: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Releases the directory `prefix`'s own pin and frees every hydrated file
/// below it that nothing else keeps: a file pinned on its own stays, and a
/// pinned directory above `prefix` refuses the whole eviction, since the
/// user asked to keep that folder.
pub(crate) fn evict_directory(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<DirectoryEviction, SyncError> {
    if !state.on_demand_pipeline_is_connected() {
        return Err(SyncError::EvictionRejected(format!(
            "{prefix}: eviction is unavailable in this build (on-demand placeholder pipeline is \
             not connected)"
        )));
    }
    refuse_if_kept_by_ancestor(state, group_id, prefix)?;
    let index = state.replica_coordinator.file_index_repository();
    index.set_directory_pinned(group_id, prefix, false)?;
    let materialization = state.replica_coordinator.materialization_state_repository();
    let mut attempts = Vec::new();
    for path in index.list_live_files_under(group_id, prefix)? {
        if materialization.get_materialization_state(group_id, &path)?
            != Some(MaterializationState::Hydrated)
            || index.is_pinned(group_id, &path)?
        {
            continue;
        }
        let attempt = super::evict(state, group_id, &path).map(|evicted| FileEviction {
            dehydrated: evicted.dehydrated,
            blocks_reclaimed: evicted.blocks_reclaimed,
            bytes_reclaimed: evicted.bytes_reclaimed,
        });
        if let Err(error) = &attempt {
            tracing::debug!(%error, group_id, path = %path, "a file below an evicted directory stayed");
        }
        attempts.push((path, attempt));
    }
    fold_directory_eviction(prefix, attempts)
}

/// One file's eviction, as [`fold_directory_eviction`] reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FileEviction {
    pub(crate) dehydrated: bool,
    pub(crate) blocks_reclaimed: u64,
    pub(crate) bytes_reclaimed: u64,
}

/// Sums the evictions of the files below `prefix`. When every file that
/// could have been freed was, or none was and none failed (each left as it
/// was, the way a single busy file's eviction reports), the sum is the
/// outcome. Otherwise the folder was only partly freed, and that is an
/// error naming how many files stayed and why the first did -- never a
/// plain success. A failure with nothing freed is that file's own error.
pub(crate) fn fold_directory_eviction(
    prefix: &str,
    attempts: Vec<(String, Result<FileEviction, SyncError>)>,
) -> Result<DirectoryEviction, SyncError> {
    let eligible = attempts.len();
    let mut outcome =
        DirectoryEviction { evicted_files: 0, blocks_reclaimed: 0, bytes_reclaimed: 0 };
    let mut stayed = Vec::new();
    let mut first_error = None;
    for (path, attempt) in attempts {
        match attempt {
            Ok(evicted) => {
                if evicted.dehydrated {
                    outcome.evicted_files += 1;
                } else {
                    stayed.push(path);
                }
                outcome.blocks_reclaimed += evicted.blocks_reclaimed;
                outcome.bytes_reclaimed += evicted.bytes_reclaimed;
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some((path.clone(), error));
                }
                stayed.push(path);
            }
        }
    }
    match first_error {
        None if outcome.evicted_files == 0 || stayed.is_empty() => Ok(outcome),
        Some((_, error)) if outcome.evicted_files == 0 => Err(error),
        first_error => {
            let folder = if prefix.is_empty() { "root" } else { prefix };
            let reason = match first_error {
                Some((path, error)) => format!("{path}: {error}"),
                None => format!("{} was busy or changed while being freed", stayed[0]),
            };
            Err(SyncError::EvictionRejected(format!(
                "{folder}: {} of {eligible} files stayed on this device ({} freed, {} bytes); \
                 first: {reason}",
                stayed.len(),
                outcome.evicted_files,
                outcome.bytes_reclaimed,
            )))
        }
    }
}

/// Fetches every file below the directory `prefix` that is not here yet.
/// Every file is attempted; the first failure is reported after.
pub(crate) async fn hydrate_directory(
    state: &Arc<DaemonState>,
    group_id: &str,
    prefix: &str,
) -> Result<(), SyncError> {
    let mut first_error = None;
    for path in files_not_hydrated_under(state, group_id, prefix)? {
        if let Err(error) = super::hydrate(state, group_id, &path).await {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// A directory's materialization state (from the files below it) and
/// whether it is pinned (by its own policy or one above it).
pub(crate) fn directory_status(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<MaterializationStatusInfo, SyncError> {
    Ok(MaterializationStatusInfo {
        state: state
            .replica_coordinator
            .materialization_state_repository()
            .directory_materialization_state(group_id, prefix)?,
        pinned: state
            .replica_coordinator
            .file_index_repository()
            .is_directory_pinned(group_id, prefix)?,
    })
}

fn files_not_hydrated_under(
    state: &DaemonState,
    group_id: &str,
    prefix: &str,
) -> Result<Vec<String>, SyncError> {
    let materialization = state.replica_coordinator.materialization_state_repository();
    let mut out = Vec::new();
    for path in
        state.replica_coordinator.file_index_repository().list_live_files_under(group_id, prefix)?
    {
        if materialization.get_materialization_state(group_id, &path)?
            != Some(MaterializationState::Hydrated)
        {
            out.push(path);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
