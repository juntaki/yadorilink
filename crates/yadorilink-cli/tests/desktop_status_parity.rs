//! add-desktop-status-app task 1.3/1.4: end-to-end coverage for
//! `StatusResponse.overall_state`/`attention_reasons` (the daemon-computed
//! rollup a UI client like `yadorilink-desktop-app` reads instead of
//! re-deriving "is anything wrong?" itself) through the *real* control
//! socket -- same harness pattern as `tests/update.rs` (a real
//! `unix_transport::serve` daemon, no coordination-plane/auth setup
//! needed). This is deliberately a parity test, not a duplicate of
//! `yadorilink_daemon::control_socket`'s own `overall_status_tests` module:
//! that module unit-tests the pure precedence function directly (including
//! the `degraded` state, which needs no live daemon plumbing to construct);
//! this file instead exercises the identical field values a CLI/desktop
//! client actually receives over the wire, for the states reachable
//! through this crate's existing real-daemon test harness (spec's "App
//! status is testable without UI automation" scenario).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_cli::control_client;
use yadorilink_daemon::daemon_state::{DaemonState, PeerStatusInfo};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{LinkRequest, StatusRequest};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", "http://127.0.0.1:1/manifest.json");

    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    // This test binary's real host disk can legitimately be near-full (this
    // change was implemented on a long-lived shared sandbox, not a fresh
    // machine) -- without an explicit override, `StatusResponse.volumes`'
    // real free-space classification would flip to "low"/"critical" based
    // on ambient host disk state having nothing to do with the behavior
    // under test here, making every "healthy"/"attention" assertion below
    // flaky. Same technique `tests/limits.rs` already uses (in the other
    // direction, to force `critical`) to pin volume state deterministically.
    // `apply_governance_config()` is required alongside
    // `set_headroom_override_bytes` to also push the override into the
    // block store's own live-reloadable cached copy (`DaemonState::new`
    // only seeds that cache once, from whatever was on disk *before* this
    // call) -- otherwise `StatusResponse.volumes`' `"<block store>"` entry
    // keeps reading the real (possibly near-full) disk regardless.
    state.governance_config.set_headroom_override_bytes(Some(1)).unwrap();
    state.apply_governance_config();

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
/// `tests/update.rs`'s own `TEST_MUTEX`.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `DaemonState::new` always spawns the periodic update-check scheduler
/// immediately and always attempts a check at startup regardless of
/// `automatic_checks_enabled` (`update_ipc.rs`'s own doc comment) — against
/// this file's deliberately-unreachable `YADORILINK_UPDATE_MANIFEST_URL`,
/// that startup check fails fast (connection refused) and records an
/// `update_last_error_category`, which `overall_status` (correctly) surfaces
/// as an `update_failed:...` attention reason. `tests/update.rs` already
/// documents this exact race ("state can legitimately be 'checking' or
/// 'failed' ... either is correct behavior, not a bug this test should pin
/// down"); this helper applies the identical discipline to
/// `attention_reasons` so this file's "healthy" assertions verify the
/// actual behavior under test (links/peers/volumes) without being flaky
/// over how far that unrelated startup race happened to get.
fn attention_reasons_excluding_startup_update_check_race(
    status: &yadorilink_ipc_proto::daemonctl::StatusResponse,
) -> Vec<String> {
    status.attention_reasons.iter().filter(|r| !r.starts_with("update_failed:")).cloned().collect()
}

async fn fetch_status() -> yadorilink_ipc_proto::daemonctl::StatusResponse {
    let resp = yadorilink_cli::control_client::send(ReqPayload::Status(StatusRequest {}))
        .await
        .expect("status request should succeed against a running daemon");
    match resp.payload {
        Some(RespPayload::Status(status)) => status,
        other => panic!("expected a Status response, got {other:?}"),
    }
}

/// task 1.4 "daemon-unavailable": pointing the control socket at a path
/// nothing is listening on fails clearly via the CLI's own `status`
/// command, mirroring `tests/update.rs`'s identical case for `update
/// status`.
#[tokio::test]
async fn status_reports_daemon_not_running_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let result = yadorilink_cli::commands::status::status(false).await;
    let err = result.expect_err("expected an error with no daemon listening");
    assert_eq!(err.exit_code(), yadorilink_cli::error::CliError::DaemonNotRunning.exit_code());
}

/// task 1.4 "healthy": a freshly-started daemon with no links, no peers,
/// and no recorded errors reports `overall_state == "healthy"` with no
/// reasons, over the real control socket — not just the pure-function unit
/// test in `yadorilink_daemon::control_socket`.
#[tokio::test]
async fn fresh_daemon_reports_healthy_over_the_real_socket() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let status = fetch_status().await;
    assert!(attention_reasons_excluding_startup_update_check_race(&status).is_empty());
    if status.attention_reasons.is_empty() {
        assert_eq!(status.overall_state, "healthy");
    }

    // The CLI's own `status` rendering must also succeed against the same
    // daemon (this is the parity surface a desktop app's tray label and
    // `yadorilink status` both read).
    yadorilink_cli::commands::status::status(false)
        .await
        .expect("status command should succeed against a healthy daemon");
}

/// task 1.4 "error"/"needs attention" (spec: "a ... disconnected
/// account/device state" needs attention): a peer recorded as
/// disconnected drives `overall_state` to `"attention"` with a
/// `peer_disconnected:<device_id>` reason, over the real socket.
#[tokio::test]
async fn disconnected_peer_reports_attention_over_the_real_socket() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    state.peer_statuses.lock().unwrap().insert(
        "device-b".to_string(),
        PeerStatusInfo { connected: false, path_kind: "disconnected".to_string() },
    );

    let status = fetch_status().await;
    assert_eq!(status.overall_state, "attention");
    assert_eq!(
        attention_reasons_excluding_startup_update_check_race(&status),
        vec!["peer_disconnected:device-b".to_string()]
    );
}

/// task 1.4 "degraded": a headroom override pinned above the block
/// store's actual free space drives `overall_state` to `"degraded"` with a
/// `low_disk_critical:<block store>` reason, over the real socket --
/// same headroom-override technique `tests/limits.rs` uses, in the
/// opposite direction from this file's `start_daemon` default.
#[tokio::test]
async fn low_disk_reports_degraded_over_the_real_socket() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;
    state.governance_config.set_headroom_override_bytes(Some(u64::MAX / 2)).unwrap();
    state.apply_governance_config();

    let status = fetch_status().await;
    assert_eq!(status.overall_state, "degraded");
    assert_eq!(
        attention_reasons_excluding_startup_update_check_race(&status),
        vec!["low_disk_critical:<block store>".to_string()]
    );
}

/// task 1.4 "paused": pausing a link does not, by itself, flip
/// `overall_state` away from `"healthy"` — pausing is a deliberate user
/// action, not an error condition (see `control_socket::overall_status`'s
/// doc comment). Exercised through the real `Link`/`Pause`/`Status` IPC
/// round trip end to end, not just a synthetic `StatusResponse`. Links
/// directly via `ReqPayload::Link` (same pattern as `tests/version_history
/// .rs`) rather than the CLI's own `link()` command, which additionally
/// requires a resolved coordination-plane access token/group id that this
/// crate's real-daemon test harness deliberately doesn't set up (see this
/// file's module doc comment).
#[tokio::test]
async fn paused_link_still_reports_healthy_over_the_real_socket() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;

    let folder = dir.path().join("synced");
    std::fs::create_dir_all(&folder).unwrap();
    control_client::send(ReqPayload::Link(LinkRequest {
        local_path: folder.to_string_lossy().to_string(),
        group_id: "group-1".into(),
        on_demand: false,
        max_local_size_bytes: None,
        content_defined_chunking: false,
        mode: String::new(),
        keep_versions: None,
        keep_days: None,
        acknowledge_risks: true,
    }))
    .await
    .expect("linking a fresh folder should succeed");
    yadorilink_cli::commands::daemon::pause().await.expect("pause should succeed");

    let status = fetch_status().await;
    assert_eq!(status.links.len(), 1);
    assert!(status.links[0].paused);
    assert!(attention_reasons_excluding_startup_update_check_race(&status).is_empty());
    if status.attention_reasons.is_empty() {
        assert_eq!(status.overall_state, "healthy");
    }
}
