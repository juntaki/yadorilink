//! Tests `yadorilink update status|check|install|config` end-to-end
//! against a real daemon over the actual control socket — same pattern
//! as `tests/limits.rs` (a real `unix_transport::serve` daemon, no
//! coordination-plane/auth setup needed).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::update::policy::{AutoInstallMode, UpdateState};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::UpdateStatusRequest;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    // `DaemonState::new` spawns the periodic update-check scheduler
    // immediately, which would otherwise try a real DNS lookup against
    // the built-in placeholder manifest URL from every test in this
    // file. Pointing it at a local port nothing listens on fails fast
    // and deterministically (connection refused) instead of depending
    // on network/DNS behavior in a test.
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", "http://127.0.0.1:1/manifest.json");

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

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`/`YADORILINK_CONFIG_DIR`
/// (process-global env vars) — same coordination discipline as
/// `tests/limits.rs`'s own `TEST_MUTEX`.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// "Update commands handle daemon-not-running": pointing the control
/// socket at a path nothing is listening on must fail clearly as
/// `DaemonNotRunning`, not hang or panic.
#[tokio::test]
async fn update_status_reports_daemon_not_running_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let result = yadorilink_cli::commands::update::status().await;
    let err = result.expect_err("expected an error with no daemon listening");
    assert_eq!(err.exit_code(), yadorilink_cli::error::CliError::DaemonNotRunning.exit_code());
}

/// "No-update" case: a freshly-started daemon reports the documented
/// safe defaults (checks enabled, manual install, no available version)
/// via the real IPC round trip. Deliberately does *not* assert
/// `state == "idle"`: `DaemonState::new` spawns the periodic update-check
/// scheduler immediately (it checks at daemon startup), and this test's
/// daemon has no reachable manifest endpoint configured,
/// so by the time this reads status the real startup check has usually
/// already run and failed fast (a nonexistent-domain DNS lookup) --
/// `state` can legitimately be `"checking"` or `"failed"` depending on
/// exactly how far that race got, and either is correct behavior, not a
/// bug this test should pin down.
#[tokio::test]
async fn update_status_reflects_fresh_daemon_defaults() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let resp =
        yadorilink_cli::control_client::send(ReqPayload::UpdateStatus(UpdateStatusRequest {}))
            .await
            .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert!(status.automatic_checks_enabled);
    assert_eq!(status.automatic_install_mode, "manual");
    assert!(status.available_version.is_empty(), "no update should ever appear out of nowhere");
}

/// "update-available"/"held-back"/"failed" cases: `yadorilink
/// status`'s embedded update fields and `update status`'s own response
/// reflect whatever the daemon's update policy currently records --
/// directly manipulated here (mirrors `tests/limits.rs`'s own
/// `state.governance_config.set_headroom_override_bytes` technique) since
/// exercising a *real* signed manifest fetch/rollout end-to-end belongs to
/// `yadorilink-daemon`'s own manifest/manager unit tests, not this CLI
/// wiring test.
#[tokio::test]
async fn update_status_reflects_an_available_held_back_update() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    state
        .update_manager
        .policy
        .update(|p| {
            p.state = UpdateState::HeldBack;
            p.available_version = Some("0.2.0".into());
            p.holdback_reason = Some("staged rollout at 10%".into());
        })
        .unwrap();

    let resp =
        yadorilink_cli::control_client::send(ReqPayload::UpdateStatus(UpdateStatusRequest {}))
            .await
            .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert_eq!(status.state, "held_back");
    assert_eq!(status.available_version, "0.2.0");
    assert_eq!(status.holdback_reason, "staged rollout at 10%");

    // `yadorilink status`'s embedded fields reflect the exact same state.
    let status_resp = yadorilink_cli::control_client::send(ReqPayload::Status(
        yadorilink_ipc_proto::daemonctl::StatusRequest {},
    ))
    .await
    .unwrap();
    let Some(RespPayload::Status(status)) = status_resp.payload else {
        panic!("expected a Status response");
    };
    assert_eq!(status.update_state, "held_back");
    assert_eq!(status.update_available_version, "0.2.0");
    assert_eq!(status.update_holdback_reason, "staged rollout at 10%");
}

/// case.
#[tokio::test]
async fn update_status_reflects_a_failed_check() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    state
        .update_manager
        .policy
        .update(|p| {
            p.state = UpdateState::Failed;
            p.last_error_category = Some("update_manifest_fetch_failed".into());
            p.last_error_message = Some("connection refused".into());
        })
        .unwrap();

    let resp =
        yadorilink_cli::control_client::send(ReqPayload::UpdateStatus(UpdateStatusRequest {}))
            .await
            .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert_eq!(status.state, "failed");
    assert_eq!(status.last_error_category, "update_manifest_fetch_failed");
}

/// `update config` persists and is reflected by a
/// subsequent `update status` read, without a daemon restart.
#[tokio::test]
async fn update_config_persists_and_is_reflected_by_status() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::update::config(Some("off".into()), Some("automatic".into()))
        .await
        .unwrap();

    let policy = state.update_manager.policy.load().unwrap();
    assert!(!policy.automatic_checks_enabled);
    assert_eq!(policy.automatic_install_mode, AutoInstallMode::Automatic);

    let resp =
        yadorilink_cli::control_client::send(ReqPayload::UpdateStatus(UpdateStatusRequest {}))
            .await
            .unwrap();
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        panic!("expected an UpdateStatus response");
    };
    assert!(!status.automatic_checks_enabled);
    assert_eq!(status.automatic_install_mode, "automatic");
}

/// case with nothing verified yet: `update install`
/// against a fresh daemon (no verified artifact) surfaces a clear error
/// rather than hanging or silently no-op'ing.
#[tokio::test]
async fn update_install_without_a_verified_artifact_is_a_clear_error() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let result = yadorilink_cli::commands::update::install().await;
    assert!(result.is_err(), "expected update install to fail without a verified artifact");
}

// Deliberately no test here that drives a verified artifact through to a
// real `install_macos::install`/`install_windows::install` call: that
// would actually shell out to `open`/launch a real installer process
// (GUI side effects on a real macOS machine, or an elevation prompt on
// Windows) from an automated test run, which `update::verify::tests` and
// `update::install_macos::tests`/`update::install_windows::tests`
// deliberately avoid via `CommandRunner` mocking instead. The
// `install`-without-a-verified-artifact case above already exercises this
// CLI command's IPC round-trip and error surfacing end-to-end; the
// platform-dispatch logic itself is covered by those lower-level mocked
// unit tests.
