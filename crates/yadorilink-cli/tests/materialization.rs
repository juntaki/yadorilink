//! `yadorilink pin/unpin/evict` end-to-end against a
//! real daemon over the actual control socket — unlike `link`/`status`,
//! these commands need no coordination-plane/auth setup at all, so they're
//! testable directly at the CLI-command layer (not just the daemon's
//! protocol layer, already covered by `yadorilink-daemon`'s own tests).
//!
//! Unix-only (Windows local IPC support): drives the daemon via
//! `unix_transport::serve` directly rather than testing the transport
//! itself (that's `yadorilink-daemon`'s own `control_socket.rs`/`shell_ipc.rs`
//! test files' job, which do cover the Windows named-pipe path) — was
//! already implicitly Unix-only before that change.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::types::{BlockInfo, FileRecord, MaterializationState};
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

/// Tests in this file share `YADORILINK_CONTROL_SOCKET` (a process-global env
/// var) and so must not run concurrently with each other.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// on-demand-sync spec "Evicting a hydrated file frees local disk space".
#[tokio::test]
async fn evict_command_turns_a_hydrated_file_into_a_placeholder() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    let mut version = VersionVector::new();
    version.increment("device-a");
    state
        .sync_state
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![BlockInfo { hash: vec![0x11u8; 32], offset: 0, size: 500 }],
                deleted: false,
            },
        )
        .unwrap();

    yadorilink_cli::commands::materialization::evict(
        folder.join("notes.txt").to_string_lossy().to_string(),
    )
    .await
    .unwrap();

    assert_eq!(
        state.sync_state.get_materialization_state("group-1", "notes.txt").unwrap(),
        Some(MaterializationState::Placeholder)
    );
    assert_ne!(std::fs::read(folder.join("notes.txt")).unwrap(), content);
}

/// on-demand-sync spec "Pinned files cannot be evicted".
#[tokio::test]
async fn evict_command_fails_for_a_pinned_file() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    let mut version = VersionVector::new();
    version.increment("device-a");
    state
        .sync_state
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![BlockInfo { hash: vec![0x11u8; 32], offset: 0, size: 500 }],
                deleted: false,
            },
        )
        .unwrap();
    state.sync_state.set_pinned("group-1", "notes.txt", true).unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    let err = yadorilink_cli::commands::materialization::evict(path).await.unwrap_err();
    assert!(matches!(err, yadorilink_cli::error::CliError::Other(_)));

    // Still hydrated, untouched.
    assert_eq!(
        state.sync_state.get_materialization_state("group-1", "notes.txt").unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(folder.join("notes.txt")).unwrap(), content);
}

/// on-demand-sync spec "Unpinning allows eviction".
#[tokio::test]
async fn unpin_then_evict_succeeds() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    let mut version = VersionVector::new();
    version.increment("device-a");
    state
        .sync_state
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![BlockInfo { hash: vec![0x11u8; 32], offset: 0, size: 500 }],
                deleted: false,
            },
        )
        .unwrap();
    state.sync_state.set_pinned("group-1", "notes.txt", true).unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::materialization::unpin(path.clone()).await.unwrap();
    assert!(!state.sync_state.is_pinned("group-1", "notes.txt").unwrap());

    yadorilink_cli::commands::materialization::evict(path).await.unwrap();
    assert_eq!(
        state.sync_state.get_materialization_state("group-1", "notes.txt").unwrap(),
        Some(MaterializationState::Placeholder)
    );
}

/// `yadorilink pin` on an already-hydrated file needs no peer at all — it
/// should succeed immediately, just setting the pin flag.
#[tokio::test]
async fn pin_command_succeeds_for_an_already_hydrated_file() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state.sync_state.add_link(&folder.to_string_lossy(), "group-1").unwrap();

    std::fs::write(folder.join("notes.txt"), b"hello").unwrap();
    let mut version = VersionVector::new();
    version.increment("device-a");
    state
        .sync_state
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 5,
                mtime_unix_nanos: 0,
                version,
                blocks: vec![],
                deleted: false,
            },
        )
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::materialization::pin(path).await.unwrap();
    assert!(state.sync_state.is_pinned("group-1", "notes.txt").unwrap());
}
