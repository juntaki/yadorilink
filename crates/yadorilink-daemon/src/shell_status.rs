//! Resolves an absolute filesystem path (as a shell extension would
//! report it) to a sync status, per the `shell-integration` spec's icon
//! overlay states.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::shellipc::SyncState as ShellSyncState;

use crate::daemon_state::DaemonState;

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
    state: &DaemonState,
    absolute_path: &str,
) -> Option<(String, String)> {
    let canonical_query = canonicalize_best_effort(Path::new(absolute_path));

    let links = state.sync_state.list_links().unwrap_or_default();
    let link = links.iter().find(|l| {
        let root = canonicalize_best_effort(Path::new(&l.local_path));
        canonical_query.starts_with(&root)
    })?;
    let canonical_root = canonicalize_best_effort(Path::new(&link.local_path));

    let rel_path = canonical_query.strip_prefix(&canonical_root).ok()?;
    let rel_path = rel_path.to_string_lossy().replace('\\', "/");
    Some((link.group_id.clone(), rel_path))
}

pub fn resolve_status(state: &DaemonState, absolute_path: &str) -> ShellSyncState {
    let Some((group_id, rel_path)) = resolve_group_and_rel_path(state, absolute_path) else {
        return ShellSyncState::Unspecified;
    };

    match state.sync_state.get_file(&group_id, &rel_path) {
        Ok(Some(record)) if record.deleted => ShellSyncState::Unspecified,
        Ok(Some(record)) if record.path.contains("(conflicted copy") => ShellSyncState::Error,
        Ok(Some(_)) => ShellSyncState::Synced,
        // Under a linked folder but not indexed yet — either brand new
        // (about to be picked up by the watcher) or not yet reconciled
        // with peers.
        Ok(None) => ShellSyncState::Pending,
        Err(_) => ShellSyncState::Unspecified,
    }
}

/// Resolves `absolute_path`'s materialization state (`on-demand-sync`
/// design D2) for the shell extension's placeholder/hydrated/hydrating
/// badge — `None` if the path isn't under any linked folder or isn't
/// indexed at all (e.g. an `Eager` folder's files are always `Hydrated`
/// in practice, but report `None` rather than a state if never indexed).
pub fn resolve_materialization_state(
    state: &DaemonState,
    absolute_path: &str,
) -> Option<yadorilink_sync_core::types::MaterializationState> {
    let (group_id, rel_path) = resolve_group_and_rel_path(state, absolute_path)?;
    state.sync_state.get_materialization_state(&group_id, &rel_path).ok().flatten()
}

/// Resolves `absolute_path`'s edit-presence state (task 9.4): the device
/// id currently reported editing it, if any and not stale.
pub fn resolve_open_elsewhere(state: &DaemonState, absolute_path: &str) -> Option<String> {
    let (group_id, rel_path) = resolve_group_and_rel_path(state, absolute_path)?;
    state.open_elsewhere(&group_id, &rel_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::types::FileRecord;
    use yadorilink_sync_core::version_vector::VersionVector;

    fn state_with_link(local_path: &str, group_id: &str) -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state =
            Arc::new(yadorilink_sync_core::index::SyncState::open_in_memory().unwrap());
        sync_state.add_link(local_path, group_id).unwrap();
        DaemonState::new("device-a".into(), sync_state, store)
    }

    #[tokio::test]
    async fn path_outside_any_link_is_unspecified() {
        let state = state_with_link("/home/alice/Photos", "group-1");
        assert_eq!(
            resolve_status(&state, "/home/alice/Downloads/file.txt"),
            ShellSyncState::Unspecified
        );
    }

    #[tokio::test]
    async fn indexed_file_is_synced() {
        let state = state_with_link("/home/alice/Photos", "group-1");
        state
            .sync_state
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "vacation.jpg".into(),
                    size: 10,
                    mtime_unix_nanos: 0,
                    version: VersionVector::new(),
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();
        assert_eq!(
            resolve_status(&state, "/home/alice/Photos/vacation.jpg"),
            ShellSyncState::Synced
        );
    }

    #[tokio::test]
    async fn unindexed_file_under_link_is_pending() {
        let state = state_with_link("/home/alice/Photos", "group-1");
        assert_eq!(
            resolve_status(&state, "/home/alice/Photos/brand-new.jpg"),
            ShellSyncState::Pending
        );
    }

    #[tokio::test]
    async fn conflicted_copy_is_error() {
        let state = state_with_link("/home/alice/Photos", "group-1");
        state
            .sync_state
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "shared (conflicted copy, 2026-01-01-000000, device-b).txt".into(),
                    size: 10,
                    mtime_unix_nanos: 0,
                    version: VersionVector::new(),
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();
        assert_eq!(
            resolve_status(
                &state,
                "/home/alice/Photos/shared (conflicted copy, 2026-01-01-000000, device-b).txt"
            ),
            ShellSyncState::Error
        );
    }
}
