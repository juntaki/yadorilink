//! Tests `versions`/`restore`/`trash list`/`trash restore`/`link
//! retention` end-to-end against a real daemon over the actual control
//! socket — same fixture/`TEST_MUTEX` pattern as `materialization.rs`,
//! since these commands also need no coordination-plane/auth setup.
//!
//! `commands::link::link` itself is auth-gated (it resolves a group name
//! against the coordination plane via `require_access_token`/
//! `resolve_group_id`) and out of scope for this daemon-only fixture,
//! exactly like `materialization.rs` never calls it either — tests here
//! that need a link seed it directly over `control_client::send`
//! (`ReqPayload::Link`), the same wire message `commands::link::link`
//! itself ultimately sends, so `--keep-versions`/`--keep-days` persistence
//! is exercised through the identical control-socket path a real `link`
//! invocation would use.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_cli::control_client;
use yadorilink_cli::error::CliError;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ListTrashRequest, ListVersionsRequest};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::types::{BlockInfo, FileRecord};
use yadorilink_sync_core::version_vector::VersionVector;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_state)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (dir, state)
}

/// Tests in this file share `YADORILINK_CONTROL_SOCKET` (a process-global
/// env var) and so must not run concurrently with each other.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Writes `data`'s block into `state`'s block store and records it as
/// obtained through `group_id` (mirroring what `LocalChangeProcessor` does
/// for a real local edit — see `record_group_block_provenance`'s doc
/// comment), returning the raw hash bytes. Without this, restoring a
/// version whose block was poked directly into the store fails as
/// "content is unavailable", since physical presence alone does not prove
/// the block was obtained through the group.
fn put_and_record(state: &DaemonState, group_id: &str, data: &[u8]) -> Vec<u8> {
    let hash_hex = state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash_hex).unwrap();
    state
        .sync_state
        .record_group_block_provenance(group_id, std::slice::from_ref(&hash_bytes))
        .unwrap();
    hash_bytes
}

fn record(
    path: &str,
    device_id: &str,
    counter: u64,
    blocks: Vec<BlockInfo>,
    size: u64,
) -> FileRecord {
    let mut version = VersionVector::new();
    for _ in 0..counter {
        version.increment(device_id);
    }
    FileRecord {
        path: path.into(),
        size,
        mtime_unix_nanos: counter as i64,
        version,
        blocks,
        deleted: false,
    }
}

/// `yadorilink versions <path>` succeeds and the underlying
/// `ListVersions` response (the exact data the CLI's `version_line`
/// renders — unit-tested for exact text shape in
/// `commands::version_history::tests`) is ordered newest first, including
/// the current version.
#[tokio::test]
async fn versions_command_lists_all_retained_versions_newest_first_including_current() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"first");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 5 };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("notes.txt", "device-a", 1, vec![v1_block], 5),
            "device-a",
        )
        .unwrap();
    let v2_bytes = put_and_record(&state, "group-1", b"second!");
    let v2_block = BlockInfo { hash: v2_bytes, offset: 0, size: 7 };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("notes.txt", "device-a", 2, vec![v2_block], 7),
            "device-a",
        )
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::versions(path.clone()).await.unwrap();

    let resp =
        control_client::send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path: path }))
            .await
            .unwrap();
    let Some(RespPayload::ListVersions(list)) = resp.payload else { panic!("wrong response") };
    assert_eq!(list.versions.len(), 2);
    assert_eq!(list.versions[0].version_seq, 2, "newest first");
    assert_eq!(list.versions[0].state, "current");
    assert_eq!(list.versions[1].version_seq, 1);
    assert_eq!(list.versions[1].state, "superseded");
}

/// `yadorilink restore <path> --version <id>` succeeds and
/// writes the chosen version's content back to disk as a brand-new
/// current version.
#[tokio::test]
async fn restore_command_restores_a_specific_version_as_a_new_current_version() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"original");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 8 };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", "device-a", 1, vec![v1_block], 8),
            "device-a",
        )
        .unwrap();
    let v2_bytes = put_and_record(&state, "group-1", b"edited!!");
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record(
                "todo.txt",
                "device-a",
                2,
                vec![BlockInfo { hash: v2_bytes, offset: 0, size: 8 }],
                8,
            ),
            "device-a",
        )
        .unwrap();

    let path = folder.join("todo.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::restore(path.clone(), Some(1)).await.unwrap();

    assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"original");
    let versions = state.sync_state.list_versions("group-1", "todo.txt").unwrap();
    assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite history");
}

/// `yadorilink restore <path>` without `--version` defaults
/// to the most recent superseded version.
#[tokio::test]
async fn restore_command_without_version_defaults_to_most_recent_superseded() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"first");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 5 };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", "device-a", 1, vec![v1_block], 5),
            "device-a",
        )
        .unwrap();
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", "device-a", 2, vec![], 0),
            "device-a",
        )
        .unwrap();

    let path = folder.join("todo.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::restore(path, None).await.unwrap();

    assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"first");
}

/// The missing-blocks restore failure exits non-zero (via
/// `CliError::Other`'s existing `exit_code`, the same path every other
/// daemon-reported failure takes) with a message specifically identifying
/// unavailable version content, not a generic failure.
#[tokio::test]
async fn restore_command_fails_clearly_and_exits_non_zero_on_missing_blocks() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    // A version referencing a block never actually written to this
    // device's block store.
    let phantom_block = BlockInfo {
        hash: {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"never fetched").to_vec()
        },
        offset: 0,
        size: 13,
    };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("phantom.bin", "device-a", 1, vec![phantom_block], 13),
            "device-a",
        )
        .unwrap();

    let path = folder.join("phantom.bin").to_string_lossy().to_string();
    let err = yadorilink_cli::commands::version_history::restore(path, Some(1)).await.unwrap_err();
    assert_ne!(err.exit_code(), 0, "a failed restore must exit non-zero");
    let CliError::Other(msg) = &err else { panic!("expected CliError::Other, got {err:?}") };
    assert!(
        msg.contains("unavailable") && msg.to_lowercase().contains("version"),
        "expected a message identifying unavailable version content, got {msg:?}"
    );
    assert!(!folder.join("phantom.bin").exists(), "a failed restore must not create a file");
}

/// `yadorilink trash list` shows a deleted file still within
/// retention, and `yadorilink trash restore <path>` recovers it.
#[tokio::test]
async fn trash_list_then_trash_restore_recovers_a_deleted_file() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    let local_path = folder.to_string_lossy().to_string();
    state.sync_state.add_link(&local_path, "group-1").unwrap();

    let hash_bytes = put_and_record(&state, "group-1", b"soon deleted");
    let block = BlockInfo { hash: hash_bytes, offset: 0, size: 12 };
    state
        .sync_state
        .upsert_file_with_origin(
            "group-1",
            &record("gone.txt", "device-a", 1, vec![block], 12),
            "device-a",
        )
        .unwrap();
    state.sync_state.mark_deleted("group-1", "gone.txt", "device-a").unwrap();

    yadorilink_cli::commands::version_history::trash_list().await.unwrap();

    let resp = control_client::send(ReqPayload::ListTrash(ListTrashRequest {})).await.unwrap();
    let Some(RespPayload::ListTrash(list)) = resp.payload else { panic!("wrong response") };
    assert_eq!(list.files.len(), 1);
    assert_eq!(list.files[0].path, "gone.txt");
    assert_eq!(list.files[0].local_path, local_path);

    let path = folder.join("gone.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::trash_restore(path).await.unwrap();

    assert_eq!(std::fs::read(folder.join("gone.txt")).unwrap(), b"soon deleted");
    let current = state.sync_state.get_file("group-1", "gone.txt").unwrap().unwrap();
    assert!(!current.deleted, "the file must be live again after trash restore");
}
