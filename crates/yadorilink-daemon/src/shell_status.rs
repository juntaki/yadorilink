//! Resolves an absolute filesystem path (as a shell extension would
//! report it) to a sync status, per the `shell-integration` spec's icon
//! overlay states.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::shellipc::SyncState as ShellSyncState;

use crate::replica_coordinator::ReplicaCoordinator;

/// Canonicalizes `path`, falling back to canonicalizing its parent
/// directory (and rejoining the file name) if `path` itself doesn't exist
/// — e.g. a file that's indexed as synced but not yet materialized to
/// disk, or a `Removed` event's path, which is already gone by the time
/// it's processed. Falls back to `path` unchanged if even the parent
/// doesn't resolve.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(resolved_parent) = parent.canonicalize() {
            return resolved_parent.join(name);
        }
    }
    path.to_path_buf()
}

/// Resolves an absolute filesystem path to the `(group_id, relative_path)`
/// pair the sync index actually keys files by, per whichever linked
/// folder it falls under — shared by `resolve_status` and the shell-IPC
/// hydration request (`shell_ipc`'s handling of `HydrateRequest`), both of
/// which only ever see an absolute path, never a group_id directly.
///
/// Matches `local_change.rs`'s `process_event`: canonicalizes both the
/// stored link root *and* the queried path before comparing. Shell
/// extensions (and OS-level watchers, per `local_change.rs`) tend to
/// report fully-resolved paths (e.g. macOS's `/private/var/...` for what
/// looks like `/var/...`), while a stored `local_path` may still be in
/// whatever form it was linked with.
pub fn resolve_group_and_rel_path(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<(String, String)> {
    let canonical_query = canonicalize_best_effort(Path::new(absolute_path));

    // Read-only overlay lookup: an unreadable link table degrades to "not a
    // synced path" (no overlay), which is the safe direction here. Surfaced
    // rather than silently collapsed -- the same shape on a write path would be
    // a data-loss bug, so it must never look routine.
    let links = sync_state.link_repository().list_links().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read link table; shell overlay will show no synced paths");
        Vec::new()
    });
    let mut matches: Vec<(&yadorilink_replica_domain::session_state::FolderLink, PathBuf)> = links
        .iter()
        .filter(|l| !l.orphaned)
        .map(|l| (l, canonicalize_best_effort(Path::new(&l.local_path))))
        .filter(|(_, root)| canonical_query.starts_with(root))
        .collect();
    matches.sort_by_key(|(_, root)| std::cmp::Reverse(root.components().count()));
    let (link, canonical_root) = matches.first()?;
    let best_depth = canonical_root.components().count();
    if matches.iter().skip(1).any(|(_, root)| root.components().count() == best_depth) {
        tracing::warn!(
            absolute_path,
            "path resolves equally well to multiple linked roots; refusing to choose a sync group"
        );
        return None;
    }

    let rel_path = canonical_query.strip_prefix(canonical_root).ok()?;
    let rel_path = rel_path.to_string_lossy().replace('\\', "/");
    Some((link.group_id.clone(), rel_path))
}

/// A path's sync status, with the reason the path is in that state when
/// the state alone does not say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellStatus {
    pub state: ShellSyncState,
    pub detail: Option<String>,
}

impl ShellStatus {
    fn of(state: ShellSyncState) -> Self {
        Self { state, detail: None }
    }
}

pub fn resolve_status(sync_state: &ReplicaCoordinator, absolute_path: &str) -> ShellSyncState {
    resolve_status_detail(sync_state, absolute_path).state
}

/// The status of a file or directory under a linked folder.
///
/// A directory is not always an entry of its own. The link root never is;
/// a directory that only holds synced files has no row; and an explicit
/// directory a peer deleted while a file below it still lives keeps a
/// deleted row. Each of those -- and a live explicit directory -- takes
/// the aggregate status of what is indexed live below it: an error when a
/// conflict copy is among it (the one per-file status worse than synced an
/// indexed row carries), synced otherwise, rather than pending or unknown.
/// A path's own live entry decides first, so a stale retained record never
/// masks it. A directory a delete left on disk because it holds local
/// content this device never synced is settled too: it takes the same
/// aggregate status, and the detail says why it is still there.
pub fn resolve_status_detail(sync_state: &ReplicaCoordinator, absolute_path: &str) -> ShellStatus {
    let Some((group_id, rel_path)) = resolve_group_and_rel_path(sync_state, absolute_path) else {
        return ShellStatus::of(ShellSyncState::Unspecified);
    };
    let rel_path = rel_path.trim_end_matches('/');
    if rel_path.is_empty() {
        return ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path));
    }
    let own_row = match sync_state.file_index_repository().get_file(&group_id, rel_path) {
        Ok(row) => row,
        Err(_) => return ShellStatus::of(ShellSyncState::Unspecified),
    };
    if let Some(record) = own_row.as_ref().filter(|record| !record.deleted) {
        if yadorilink_replica_domain::conflict::is_conflict_copy_path(&record.path) {
            return ShellStatus::of(ShellSyncState::Error);
        }
        return ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path));
    }
    match sync_state.sqlite().retained_directory_reason(&group_id, rel_path) {
        Ok(Some(reason)) => {
            return ShellStatus {
                state: aggregate_status(sync_state, &group_id, rel_path),
                detail: Some(reason),
            };
        }
        Ok(None) => {}
        Err(_) => return ShellStatus::of(ShellSyncState::Unspecified),
    }
    match sync_state.file_index_repository().has_live_descendant_row(&group_id, rel_path) {
        Ok(true) => ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path)),
        // A deleted entry with nothing live below it has no status.
        Ok(false) if own_row.is_some() => ShellStatus::of(ShellSyncState::Unspecified),
        // Under a linked folder but not indexed yet — either brand new
        // (about to be picked up by the watcher) or not yet reconciled
        // with peers.
        Ok(false) => ShellStatus::of(ShellSyncState::Pending),
        Err(_) => ShellStatus::of(ShellSyncState::Unspecified),
    }
}

/// The status a directory at `rel_path` (the link root when empty) takes
/// from what is indexed live below it.
fn aggregate_status(
    sync_state: &ReplicaCoordinator,
    group_id: &str,
    rel_path: &str,
) -> ShellSyncState {
    match sync_state.file_index_repository().has_live_conflict_copy_descendant(group_id, rel_path) {
        Ok(true) => ShellSyncState::Error,
        Ok(false) => ShellSyncState::Synced,
        Err(_) => ShellSyncState::Unspecified,
    }
}

/// Resolves `absolute_path`'s materialization state (`on-demand-sync`
/// ) for the shell extension's placeholder/hydrated/hydrating
/// badge — `None` if the path isn't under any linked folder or isn't
/// indexed at all (e.g. an `Eager` folder's files are always `Hydrated`
/// in practice, but report `None` rather than a state if never indexed).
pub fn resolve_materialization_state(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<yadorilink_replica_domain::session_state::MaterializationState> {
    let (group_id, rel_path) = resolve_group_and_rel_path(sync_state, absolute_path)?;
    sync_state
        .materialization_state_repository()
        .get_materialization_state(&group_id, &rel_path)
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests;
