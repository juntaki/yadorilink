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
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_context = std::sync::Arc::new(
        yadorilink_daemon::control_context::ControlContext::from_state(state.clone()),
    );
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
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
    // `evict` refuses outright unless a placeholder provider is connected
    // -- see `hydration::evict`'s own doc comment; this test exercises the
    // actual eviction mechanics, so it forces that gate open for its own
    // thread, the same way `yadorilink-daemon`'s own eviction tests do.
    let _pipeline_connected =
        yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // A direct `add_link` (never a real `start_link_watch`) leaves no live
    // root lease behind for `evict`'s `root_lease_for` lookup to find --
    // `install_test_root_commit_authority` registers the same
    // always-valid, test-only lease `yadorilink-daemon`'s own equivalent
    // fixtures use for exactly this reason.
    state.install_test_root_commit_authority("group-1");
    // `evict_file` also verifies the root's adopted identity before
    // touching it -- without this, eviction fails closed with "no
    // previously-adopted root token", the same fixture step
    // `yadorilink-daemon`'s own `hydration.rs::seed_link` test helper takes
    // for the identical reason.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    // The indexed hash must be the file's real content hash, not a
    // placeholder: `evict_file` verifies on-disk bytes against it before
    // reclaiming anything, and silently no-ops (`Ok`, nothing evicted) on a
    // mismatch rather than erroring -- same fixture requirement
    // `yadorilink-daemon`'s own `tests/control_socket.rs` documents for the
    // identical scenario.
    let hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&content).to_vec()
    };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: 500 }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // `upsert_file` no longer implies `Hydrated` (schema v25 changed the
    // column default to `Placeholder` -- see `set_materialization_state_
    // in_tx`'s doc comment): this fixture writes real matching content
    // directly to disk to simulate an already-hydrated file, so it must
    // say so explicitly now, same as every other caller of this pattern.
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "notes.txt",
            MaterializationState::Hydrated,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    yadorilink_cli::commands::materialization::evict(
        folder.join("notes.txt").to_string_lossy().to_string(),
    )
    .await
    .unwrap();

    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state("group-1", "notes.txt")
            .unwrap(),
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
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash: vec![0x11u8; 32], offset: 0, size: 500 }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // See `evict_command_turns_a_hydrated_file_into_a_placeholder`'s
    // identical comment: `upsert_file` no longer implies `Hydrated`.
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "notes.txt",
            MaterializationState::Hydrated,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_pinned("group-1", "notes.txt", true)
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    let err = yadorilink_cli::commands::materialization::evict(path).await.unwrap_err();
    assert!(matches!(err, yadorilink_cli::error::CliError::Other(_)));

    // Still hydrated, untouched.
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state("group-1", "notes.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
    assert_eq!(std::fs::read(folder.join("notes.txt")).unwrap(), content);
}

/// on-demand-sync spec "Unpinning allows eviction".
#[tokio::test]
async fn unpin_then_evict_succeeds() {
    let _guard = TEST_MUTEX.lock().await;
    // See `evict_command_turns_a_hydrated_file_into_a_placeholder`'s
    // identical comment: `evict` refuses outright without this override.
    let _pipeline_connected =
        yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // A direct `add_link` (never a real `start_link_watch`) leaves no live
    // root lease behind for `evict`'s `root_lease_for` lookup to find --
    // `install_test_root_commit_authority` registers the same
    // always-valid, test-only lease `yadorilink-daemon`'s own equivalent
    // fixtures use for exactly this reason.
    state.install_test_root_commit_authority("group-1");
    // `evict_file` also verifies the root's adopted identity before
    // touching it -- without this, eviction fails closed with "no
    // previously-adopted root token", the same fixture step
    // `yadorilink-daemon`'s own `hydration.rs::seed_link` test helper takes
    // for the identical reason.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    // See `evict_command_turns_a_hydrated_file_into_a_placeholder`'s
    // identical comment: the indexed hash must be the file's real content
    // hash for eviction to actually happen instead of silently no-op'ing.
    let hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&content).to_vec()
    };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: 500 }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // See `evict_command_turns_a_hydrated_file_into_a_placeholder`'s
    // identical comment: `upsert_file` no longer implies `Hydrated`.
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "notes.txt",
            MaterializationState::Hydrated,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .set_pinned("group-1", "notes.txt", true)
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::materialization::unpin(path.clone()).await.unwrap();
    assert!(!state
        .replica_coordinator
        .file_index_repository()
        .is_pinned("group-1", "notes.txt")
        .unwrap());

    yadorilink_cli::commands::materialization::evict(path).await.unwrap();
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state("group-1", "notes.txt")
            .unwrap(),
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
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();

    std::fs::write(folder.join("notes.txt"), b"hello").unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 5,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // See `evict_command_turns_a_hydrated_file_into_a_placeholder`'s
    // identical comment: `upsert_file` no longer implies `Hydrated` --
    // without this, `pin`'s own already_hydrated check
    // (`hydration.rs::pin`) is false, so it falls through to a real
    // `hydrate()` call, which needs peer/root-commit-authority setup this
    // fixture never provides (it's testing the already-hydrated
    // short-circuit specifically, per its own name).
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "notes.txt",
            MaterializationState::Hydrated,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::materialization::pin(path).await.unwrap();
    assert!(state
        .replica_coordinator
        .file_index_repository()
        .is_pinned("group-1", "notes.txt")
        .unwrap());
}
