//! The product facade against a stand-in daemon on a real socket, and
//! against no daemon at all.
#![cfg(unix)]

use std::time::Duration;

use yadorilink_client_core::dto::{CoreConfig, DaemonLaunch, FolderMode, StatusUpdate};
use yadorilink_client_core::error::{DaemonUnavailableReason, DesktopError};
use yadorilink_client_core::ClientCore;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, LinkStatus, ListLinksResponse, StatusResponse,
    CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// The tests share `YADORILINK_CONTROL_SOCKET`, a process-global variable.
static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn core() -> std::sync::Arc<ClientCore> {
    ClientCore::new(CoreConfig { daemon_launch: DaemonLaunch::SpawnBinary { path: None } })
}

/// Serves every request with `respond` until the test ends.
fn serve(
    socket: &std::path::Path,
    respond: impl Fn(DaemonControlRequest) -> RespPayload + Send + Sync + 'static,
) {
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let respond = std::sync::Arc::new(respond);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let respond = respond.clone();
            tokio::spawn(async move {
                if let Ok(Some(request)) = read_message::<DaemonControlRequest>(&mut stream).await {
                    let response = DaemonControlResponse {
                        daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
                        payload: Some(respond(request)),
                    };
                    let _ = write_message(&mut stream, &response).await;
                }
            });
        }
    });
}

fn linked_docs() -> LinkStatus {
    LinkStatus { local_path: "/f/Docs".into(), group_id: "g1".into(), ..Default::default() }
}

#[tokio::test]
async fn status_snapshot_maps_unreachable_daemon_to_daemon_unavailable() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("nobody-home.sock"));

    let error = core().status_snapshot().await.unwrap_err();
    assert!(
        matches!(
            error,
            DesktopError::DaemonUnavailable { reason: DaemonUnavailableReason::NotRunning, .. }
        ),
        "{error:?}"
    );

    let watch = core().watch_status(Duration::from_millis(20));
    let update = tokio::time::timeout(Duration::from_secs(5), watch.next()).await.unwrap();
    assert!(
        matches!(update, Some(StatusUpdate::Unavailable { ref error }) if error.is_daemon_unavailable()),
        "{update:?}"
    );
    watch.cancel();

    let account = core().account_status().await;
    assert_eq!(account.has_linked_folders, None, "unknown while the daemon is down");
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn status_and_folder_detail_read_the_daemons_status() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| {
        RespPayload::Status(StatusResponse {
            links: vec![linked_docs()],
            overall_state: "healthy".into(),
            ..Default::default()
        })
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let snapshot = core().status_snapshot().await.unwrap();
    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(snapshot.folders[0].name, "Docs");

    let detail = core().folder_detail("/f/Docs".into()).await.unwrap();
    assert_eq!(detail.summary.group_id, "g1");
    let missing = core().folder_detail("/f/Other".into()).await.unwrap_err();
    assert!(
        matches!(missing, DesktopError::InvalidInput { field: Some(ref f), .. } if f == "local_path"),
        "{missing:?}"
    );
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn a_storage_mode_change_for_a_group_not_linked_here_is_about_the_group_id() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| RespPayload::ListLinks(ListLinksResponse { links: vec![linked_docs()] }));
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let error =
        core().set_storage_mode("g-elsewhere".into(), FolderMode::OnDemand).await.unwrap_err();
    assert!(
        matches!(error, DesktopError::InvalidInput { field: Some(ref f), .. } if f == "group_id"),
        "{error:?}"
    );
    let unchanged = core().set_storage_mode("g1".into(), FolderMode::KeepAll).await.unwrap();
    assert!(!unchanged.changed);
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn an_unforced_unlink_refused_for_durability_offers_the_override() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    serve(&socket, |_| {
        RespPayload::Error(
            "refusing to unlink /f/Docs: no other full replica is confirmed ready to durably \
             hold every file in this group yet. Re-run with --force to unlink anyway."
                .into(),
        )
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);

    let error = core().unlink_folder("/f/Docs".into(), false).await.unwrap_err();
    assert!(matches!(error, DesktopError::DurabilityBlocked { can_force: true, .. }), "{error:?}");
    let forced = core().unlink_folder("/f/Docs".into(), true).await.unwrap_err();
    assert!(
        matches!(forced, DesktopError::DurabilityBlocked { can_force: false, .. }),
        "{forced:?}"
    );
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

#[tokio::test]
async fn starting_a_daemon_that_cannot_be_launched_is_daemon_unavailable() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("nobody-home.sock"));
    let core = ClientCore::new(CoreConfig {
        daemon_launch: DaemonLaunch::SpawnBinary {
            path: Some(dir.path().join("no-such-daemon").to_string_lossy().into_owned()),
        },
    });
    let error = core.start_daemon().await.unwrap_err();
    match error {
        DesktopError::DaemonUnavailable {
            reason: DaemonUnavailableReason::NotRunning,
            message,
        } => {
            assert!(message.contains("no-such-daemon"), "{message}");
        }
        other => panic!("expected daemon unavailable, got {other:?}"),
    }
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
}

/// A daemon that is running but wedged accepts the connection and never
/// answers. Starting it must say so promptly: launching another copy cannot
/// help, and waiting on every poll's reply deadline in turn kept the app's
/// "starting" state up for minutes before a misleading "did not become
/// reachable".
#[tokio::test(start_paused = true)]
async fn starting_a_daemon_that_never_answers_reports_it_unresponsive_promptly() {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
    // A launch that "succeeds" without bringing anything up, as
    // `launchctl kickstart` does for a job that is already running.
    let core = ClientCore::new(CoreConfig {
        daemon_launch: DaemonLaunch::SpawnBinary { path: Some("/usr/bin/true".into()) },
    });

    let started = tokio::time::Instant::now();
    let error = core.start_daemon().await.unwrap_err();
    let waited = started.elapsed();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");

    assert!(waited <= Duration::from_secs(30), "start waited {waited:?} on a silent daemon");
    match error {
        DesktopError::DaemonUnavailable {
            reason: DaemonUnavailableReason::Unresponsive, ..
        } => {}
        other => panic!("expected an unresponsive daemon, got {other:?}"),
    }
}
