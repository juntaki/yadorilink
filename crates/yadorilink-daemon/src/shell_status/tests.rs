#![cfg(test)]

use super::*;
use std::sync::Arc;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::FileRecord;

use crate::daemon_state::DaemonState;

fn state_with_link(local_path: &str, group_id: &str) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    sync_state.link_repository().add_link(local_path, group_id).unwrap();
    DaemonState::new("device-a".into(), sync_state, store)
}

#[tokio::test]
async fn path_outside_any_link_is_unspecified() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Downloads/file.txt"),
        ShellSyncState::Unspecified
    );
}

#[tokio::test]
async fn indexed_file_is_synced() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "vacation.jpg".into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/vacation.jpg"),
        ShellSyncState::Synced
    );
}

#[tokio::test]
async fn unindexed_file_under_link_is_pending() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/brand-new.jpg"),
        ShellSyncState::Pending
    );
}

#[tokio::test]
async fn conflicted_copy_is_error() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "shared (conflicted copy, 2026-01-01-000000, device-b).txt".into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    assert_eq!(
        resolve_status(
            &state.replica_coordinator,
            "/home/alice/Photos/shared (conflicted copy, 2026-01-01-000000, device-b).txt"
        ),
        ShellSyncState::Error
    );
}

/// The conflict marker belongs to the filename. A file inside a directory
/// that is itself a conflict copy is an ordinary synced file, not an error.
#[tokio::test]
async fn file_inside_directory_conflict_copy_is_not_error() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "album (conflicted copy, 2026-01-01-000000, device-b)/cover.jpg".into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    assert_eq!(
        resolve_status(
            &state.replica_coordinator,
            "/home/alice/Photos/album (conflicted copy, 2026-01-01-000000, device-b)/cover.jpg"
        ),
        ShellSyncState::Synced
    );
}

/// An orphaned link is treated as though it doesn't exist here -- a
/// file under it must not resolve to a status (or a
/// `HydrateRequest`/`Pin`/`Unpin`/`Evict` target, since they share this
/// same resolver) even though the link row itself is still present.
#[tokio::test]
async fn nested_links_resolve_to_the_deepest_root() {
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("child");
    std::fs::create_dir_all(&child).unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    sync_state
        .link_repository()
        .add_link(&parent.path().to_string_lossy(), "parent-group")
        .unwrap();
    sync_state.link_repository().add_link(&child.to_string_lossy(), "child-group").unwrap();
    let state = DaemonState::new("device-a".into(), sync_state, store);

    let query = child.join("file.txt").to_string_lossy().to_string();
    let (group, rel) = resolve_group_and_rel_path(&state.replica_coordinator, &query)
        .expect("a path under the nested child link must resolve");
    assert_eq!(group, "child-group");
    assert_eq!(rel, "file.txt");
}

#[tokio::test]
async fn orphaned_link_resolves_to_no_status() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "vacation.jpg".into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state.replica_coordinator.link_repository().mark_link_orphaned("/home/alice/Photos").unwrap();

    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/vacation.jpg"),
        ShellSyncState::Unspecified,
        "an orphaned link's files must not report a live sync status"
    );
    assert!(
        resolve_group_and_rel_path(&state.replica_coordinator, "/home/alice/Photos/vacation.jpg")
            .is_none(),
        "an orphaned link must not resolve for the shell-IPC hydrate/pin/unpin/evict path \
         either"
    );
}

fn upsert(state: &DaemonState, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: path.into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
}

/// A directory kept only to hold synced files has no row of its own. What
/// is below it is synced, so it is too -- not "not indexed yet".
#[tokio::test]
async fn structural_directory_with_synced_descendant_is_synced_not_pending() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    upsert(&state, "trips/2026/beach.jpg");

    for dir in ["/home/alice/Photos/trips", "/home/alice/Photos/trips/2026"] {
        let status = resolve_status_detail(&state.replica_coordinator, dir);
        assert_eq!(status.state, ShellSyncState::Synced, "{dir}");
        assert_eq!(status.detail, None, "{dir}");
    }
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/trips"),
        ShellSyncState::Synced
    );
}

/// The linked folder itself is never an entry of its own group.
#[tokio::test]
async fn link_root_is_not_pending() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos"),
        ShellSyncState::Synced
    );
    upsert(&state, "vacation.jpg");
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/"),
        ShellSyncState::Synced
    );
}

/// A peer deleted the explicit directory while a file below it still
/// lives: the directory stays as the file's container, and is synced.
#[tokio::test]
async fn deleted_explicit_directory_with_live_descendant_shows_structural_status() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let index = state.replica_coordinator.file_index_repository();
    upsert(&state, "album");
    index
        .set_record_kind(
            "group-1",
            "album",
            yadorilink_replica_domain::file::RecordKind::Directory,
            &permit,
        )
        .unwrap();
    index.mark_deleted("group-1", "album", "device-b", &permit).unwrap();
    upsert(&state, "album/cover.jpg");

    let status = resolve_status_detail(&state.replica_coordinator, "/home/alice/Photos/album");
    assert_eq!(status.state, ShellSyncState::Synced);
    assert_eq!(status.detail, None);

    // With nothing live below it, a deleted directory has no status.
    index.mark_deleted("group-1", "album/cover.jpg", "device-b", &permit).unwrap();
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/album"),
        ShellSyncState::Unspecified
    );
}

/// A directory whose delete arrived while it still held files this device
/// never synced is kept. The replicated state is settled, so it is
/// synced, and the status says why the directory is still there.
#[tokio::test]
async fn retained_directory_with_untracked_content_shows_retained_status() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let index = state.replica_coordinator.file_index_repository();
    upsert(&state, "build");
    index
        .set_record_kind(
            "group-1",
            "build",
            yadorilink_replica_domain::file::RecordKind::Directory,
            &permit,
        )
        .unwrap();
    index.mark_deleted("group-1", "build", "device-b", &permit).unwrap();
    state
        .replica_coordinator
        .sqlite()
        .record_retained_directory(
            "group-1",
            "build",
            yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT,
            None,
            1,
        )
        .unwrap();

    let status = resolve_status_detail(&state.replica_coordinator, "/home/alice/Photos/build");
    assert_eq!(status.state, ShellSyncState::Synced);
    assert_eq!(
        status.detail.as_deref(),
        Some(yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT)
    );
}

/// A directory's status aggregates what lives below it: a conflict copy
/// anywhere inside shows as an error on the structural directory, on a
/// deleted explicit directory kept for its contents, on a live explicit
/// directory, and on the link root -- not synced.
#[tokio::test]
async fn directory_status_aggregates_a_conflict_copy_below_it() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let index = state.replica_coordinator.file_index_repository();
    upsert(&state, "trips/2026/beach.jpg");
    upsert(&state, "trips/2026/beach (conflicted copy, device-b 2026-09-25).jpg");
    upsert(&state, "album");
    index
        .set_record_kind(
            "group-1",
            "album",
            yadorilink_replica_domain::file::RecordKind::Directory,
            &permit,
        )
        .unwrap();
    upsert(&state, "album/cover (conflicted copy, device-b 2026-09-25).jpg");
    upsert(&state, "kept");
    index
        .set_record_kind(
            "group-1",
            "kept",
            yadorilink_replica_domain::file::RecordKind::Directory,
            &permit,
        )
        .unwrap();
    index.mark_deleted("group-1", "kept", "device-b", &permit).unwrap();
    upsert(&state, "kept/a (conflicted copy, device-b 2026-09-25).txt");
    upsert(&state, "clean/a.txt");
    // `clean0/...` sorts just past `clean/`'s range: a conflict copy there
    // is not below `clean`.
    upsert(&state, "clean0/x (conflicted copy, device-b 2026-09-25).txt");

    for dir in [
        "/home/alice/Photos/trips",
        "/home/alice/Photos/trips/2026",
        "/home/alice/Photos/album",
        "/home/alice/Photos/kept",
        "/home/alice/Photos",
    ] {
        assert_eq!(resolve_status(&state.replica_coordinator, dir), ShellSyncState::Error, "{dir}");
    }
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/clean"),
        ShellSyncState::Synced,
        "a sibling directory's conflict copy is not this one's"
    );
    assert_eq!(
        resolve_status(&state.replica_coordinator, "/home/alice/Photos/trips/2026/beach.jpg"),
        ShellSyncState::Synced,
        "a file's own status stays per-file"
    );
}

/// A retained record left on a path that is now a live entry again does
/// not mask the entry's own status.
#[tokio::test]
async fn a_stale_retained_record_does_not_mask_a_live_entry() {
    let state = state_with_link("/home/alice/Photos", "group-1");
    state
        .replica_coordinator
        .sqlite()
        .record_retained_directory(
            "group-1",
            "build",
            yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT,
            None,
            1,
        )
        .unwrap();
    upsert(&state, "build");

    let status = resolve_status_detail(&state.replica_coordinator, "/home/alice/Photos/build");
    assert_eq!(status.state, ShellSyncState::Synced);
    assert_eq!(status.detail, None, "the path is a live entry, not a retained directory");
}
