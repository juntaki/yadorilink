//! The `commands::link` library surface
//! the onboarding window drives (`run_link_preflight` + `link_resolved`),
//! exercised against a real daemon over the actual control socket — the same
//! harness pattern `materialization.rs`/`gc.rs` use. Like those, the link
//! path needs no coordination-plane/auth setup (the group_id is opaque to the
//! daemon), so it is testable directly at the CLI-command layer.
//!
//! The coordination-plane library fns
//! (`device::register_device`, `share::{create_and_link, join}`) are the sole
//! implementations behind their unchanged CLI subcommands — the existing CLI
//! behavior is pinned by those subcommands staying byte-identical — but they
//! hit the Cloudflare-hosted coordination plane over HTTP, for which no
//! in-repo test server exists, so they are not integration-tested here.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    // A registered (non-empty device_id) device with no change-signing key is
    // fail-closed (`link_manager::ensure_initial_change_history`): linking a
    // folder refuses index-only sync rather than leave emission silently
    // off. Wire one before any test here links.
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);

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

/// the window's preflight is the same shared computation the CLI uses —
/// an empty folder raises no non-empty-folder warning, and `link_resolved`
/// registers it with the daemon (which only gates on nested-link conflicts,
/// so a non-nested link registers regardless of free-space classification —
/// low disk being a CLI/UI-layer guardrail the user acknowledges up front).
#[tokio::test]
async fn empty_folder_previews_clean_and_links() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("empty-shared");
    std::fs::create_dir_all(&folder).unwrap();

    let (absolute, report) =
        yadorilink_cli::commands::link::run_link_preflight(&folder.to_string_lossy())
            .await
            .unwrap();
    // Free-space state is environment-dependent, so we assert on the folder
    // contents specifically rather than the aggregate `is_risky`.
    assert!(report.is_empty_folder(), "temp folder should scan as empty");
    assert!(
        !report.warnings().iter().any(|w| w.contains("not empty")),
        "an empty folder must not raise a non-empty warning, got {:?}",
        report.warnings()
    );

    yadorilink_cli::commands::link::link_resolved(absolute, "group-1".into(), false).await.unwrap();

    let linked: Vec<String> =
        state.sync_state.list_links().unwrap().into_iter().map(|l| l.local_path).collect();
    assert!(
        linked.iter().any(|p| p == &folder.canonicalize().unwrap().to_string_lossy()),
        "the linked folder should now be registered with the daemon, got {linked:?}"
    );
}

/// a non-empty folder surfaces the shared "folder is not empty" warning
/// that the window renders as an acknowledgement card — the machine gates the
/// confirm on this exact warning set.
#[tokio::test]
async fn non_empty_folder_surfaces_a_warning() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;
    let folder = dir.path().join("has-content");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("existing.txt"), b"hi").unwrap();

    let (_absolute, report) =
        yadorilink_cli::commands::link::run_link_preflight(&folder.to_string_lossy())
            .await
            .unwrap();
    assert!(report.is_risky());
    assert!(
        report.warnings().iter().any(|w| w.contains("not empty")),
        "expected a non-empty-folder warning, got {:?}",
        report.warnings()
    );
}

/// / daemon defense-in-depth: linking a folder that nests an existing link
/// is a genuine correctness hazard the daemon is the sole authority on. The
/// window's aggregate acknowledgement (`acknowledge_risks`) is what lets it
/// through — without it the daemon refuses, with it the link registers.
#[tokio::test]
async fn nested_link_is_refused_without_ack_and_allowed_with_ack() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let parent = dir.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).unwrap();

    // Register the child link first — it has no nested conflict, so the
    // daemon accepts it with ack=false regardless of free-space state.
    let (child_abs, child_report) =
        yadorilink_cli::commands::link::run_link_preflight(&child.to_string_lossy()).await.unwrap();
    assert!(child_report.nested_conflicts.is_empty());
    yadorilink_cli::commands::link::link_resolved(child_abs, "group-child".into(), false)
        .await
        .unwrap();

    // Now the parent nests an existing link — preflight detects it, and the
    // daemon rejects a link that does not acknowledge it.
    let (parent_abs, parent_report) =
        yadorilink_cli::commands::link::run_link_preflight(&parent.to_string_lossy())
            .await
            .unwrap();
    assert!(
        !parent_report.nested_conflicts.is_empty(),
        "preflight should detect the nested child link"
    );

    let refused = yadorilink_cli::commands::link::link_resolved(
        parent_abs.clone(),
        "group-parent".into(),
        false,
    )
    .await;
    assert!(refused.is_err(), "daemon must refuse a nested link without acknowledge_risks");

    yadorilink_cli::commands::link::link_resolved(parent_abs, "group-parent".into(), true)
        .await
        .unwrap();

    let linked: Vec<String> =
        state.sync_state.list_links().unwrap().into_iter().map(|l| l.local_path).collect();
    assert!(
        linked.iter().any(|p| p == &parent.canonicalize().unwrap().to_string_lossy()),
        "the acknowledged nested link should now be registered, got {linked:?}"
    );
}
