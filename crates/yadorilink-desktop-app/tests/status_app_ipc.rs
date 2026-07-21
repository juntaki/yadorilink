//! Exercises this crate's own `ipc_client`/`actions` (the modules the
//! tray binary actually calls) against a real daemon over the real
//! control socket — same harness pattern `yadorilink-cli`'s
//! `tests/update.rs`/`tests/desktop_status_parity.rs` use. The
//! tray/menu/event-loop wiring in `main.rs` itself cannot be exercised
//! this way (no display/window manager in this environment — see
//! `main.rs`'s top doc comment); this file instead proves the non-UI
//! half of this crate — the part that actually talks to the daemon —
//! behaves correctly, independent of `yadorilink-cli`'s own (separately
//! duplicated, per this crate's `ipc_client.rs` doc comment) client
//! code.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_desktop_app::{actions, ipc_client};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{LinkRequest, PendingEnrollmentKind, StatusRequest};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", "http://127.0.0.1:1/manifest.json");

    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    // A registered (non-empty device_id) device with no signing key fails
    // closed (`link_manager::ensure_initial_change_history`) -- see
    // `yadorilink-cli`'s `tests/desktop_status_parity.rs`'s identical setup.
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
    // Pin volume classification to "ok" regardless of this sandbox's real
    // (possibly near-full) host disk — see `yadorilink-cli`'s
    // `tests/desktop_status_parity.rs`' identical comment for the full
    // explanation. `apply_governance_config` (not just
    // `set_headroom_override_bytes` on the config store alone) is required
    // to also push the override into the block store's own live-reloadable
    // cached copy (`DaemonState::new` only seeds that cache once, from
    // whatever was on disk *before* this call) — the same method
    // `control_socket`'s `limits set`/headroom-override handlers call
    // after persisting a change, for the identical reason.
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

static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn fetch_status() -> yadorilink_ipc_proto::daemonctl::StatusResponse {
    let resp = ipc_client::send(ReqPayload::Status(StatusRequest {})).await.unwrap();
    match resp.payload {
        Some(RespPayload::Status(status)) => status,
        other => panic!("expected a Status response, got {other:?}"),
    }
}

/// This crate's `ipc_client::send` (a deliberate duplicate of
/// `yadorilink-cli`'s own connection code, see that module's doc comment)
/// reaches a real daemon and round-trips a `Status` request correctly.
/// `overall_state` may legitimately read `"attention"` here instead of
/// `"healthy"` — `DaemonState::new` always attempts an update check at
/// startup against this file's deliberately-unreachable
/// `YADORILINK_UPDATE_MANIFEST_URL`, and that failing fast is itself a
/// real, correctly-surfaced attention reason, not a bug (same race
/// `yadorilink-cli`'s `tests/update.rs`/`tests/desktop_status_parity.rs`
/// already document and tolerate for the identical harness).
#[tokio::test]
async fn ipc_client_reaches_a_real_daemon() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let status = fetch_status().await;
    let other_reasons: Vec<&String> =
        status.attention_reasons.iter().filter(|r| !r.starts_with("update_failed:")).collect();
    assert!(other_reasons.is_empty(), "unexpected attention reasons: {other_reasons:?}");
}

/// `ipc_client::send` fails clearly (not by hanging or panicking) when no
/// daemon is listening — the tray app's "daemon not running" degraded
/// state (the "Status app shows daemon connectivity" scenario) depends
/// on this failing fast and distinguishably.
#[tokio::test]
async fn ipc_client_reports_a_clear_error_with_no_daemon_running() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let err = ipc_client::send(ReqPayload::Status(StatusRequest {}))
        .await
        .expect_err("expected an error with no daemon listening");
    assert!(matches!(err, ipc_client::IpcError::DaemonNotRunning));
}

/// `actions::pause_all`/
/// `resume_all` actually flip every link's `paused` flag through the real
/// daemon, not just locally in this app's own state.
#[tokio::test]
async fn pause_all_and_resume_all_affect_every_linked_folder() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;

    let folder = dir.path().join("synced");
    std::fs::create_dir_all(&folder).unwrap();
    ipc_client::send(ReqPayload::Link(LinkRequest {
        local_path: folder.to_string_lossy().to_string(),
        group_id: "group-1".into(),
        on_demand: false,
        max_local_size_bytes: None,
        acknowledge_risks: true,
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
        pending_enrollment_device_id: String::new(),
    }))
    .await
    .expect("linking a fresh folder should succeed");

    actions::pause_all().await.expect("pause_all should succeed");
    let status = fetch_status().await;
    assert!(status.links[0].paused, "pause_all should have paused the link");

    actions::resume_all().await.expect("resume_all should succeed");
    let status = fetch_status().await;
    assert!(!status.links[0].paused, "resume_all should have resumed the link");
}

/// `actions::export_diagnostics` writes a
/// real file with the daemon-assembled bundle contents under the config
/// directory.
#[tokio::test]
async fn export_diagnostics_writes_a_real_bundle_file() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let path = actions::export_diagnostics().await.expect("diagnostics export should succeed");
    assert!(path.is_file(), "expected a diagnostics bundle file at {}", path.display());
    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.is_empty());
}
