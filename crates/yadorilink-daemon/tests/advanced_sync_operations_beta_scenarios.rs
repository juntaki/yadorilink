//! `add-advanced-sync-operations` task 6.3: beta acceptance scenarios for
//! non-technical recovery from an out-of-sync folder and a failed peer
//! connection, exercised end-to-end over the real control socket (mirrors
//! `tests/control_socket.rs`/`tests/reporting_ipc.rs`'s own pattern). The
//! third listed scenario ("unexpected ignored path") is covered instead by
//! `yadorilink-sync-core`'s `ignore_patterns::tests::explain_path_*` suite
//! and `yadorilink-cli`'s `tests/ignore.rs` `ignore_explain_*` test —
//! ignore explanation is filesystem-only (no daemon involved, see
//! `commands::ignore::explain_path_output`), so a daemon-control-socket
//! test would exercise nothing this suite's own tests don't already cover.
#![cfg(unix)]

use std::sync::Arc;

use tokio::net::UnixStream;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConnectivityDoctorRequest, DaemonControlRequest, DaemonControlResponse,
    FolderDivergenceSummaryRequest, FolderResolutionConfirmRequest, FolderResolutionPreviewRequest,
    LinkRequest, ListFolderOperationAuditRequest, SetModeRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

async fn start_daemon_with_state() -> (std::path::PathBuf, tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let state_db = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), state_db, store);
    let socket_path = dir.path().join("daemon.sock");

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_state)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (socket_path, dir, state)
}

async fn send(socket_path: &std::path::Path, payload: ReqPayload) -> DaemonControlResponse {
    let mut stream = UnixStream::connect(socket_path).await.unwrap();
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap().unwrap()
}

/// Beta acceptance scenario: "my send-only folder says it's out of sync,
/// how do I fix it without losing anything?" — a non-technical user should
/// be able to see the divergence, preview what a fix would do, and confirm
/// it, ending with a bounded audit trail entry they (or support) can point
/// to afterward.
#[tokio::test]
async fn recovering_from_an_out_of_sync_send_only_folder() {
    let (socket_path, dir, state) = start_daemon_with_state().await;
    let folder = dir.path().join("photos");
    std::fs::create_dir_all(&folder).unwrap();
    let local_path = folder.to_string_lossy().to_string();

    send(
        &socket_path,
        ReqPayload::Link(LinkRequest {
            local_path: local_path.clone(),
            group_id: "group-beta".into(),
            on_demand: false,
            max_local_size_bytes: None,
            content_defined_chunking: false,
            mode: String::new(),
            keep_versions: None,
            keep_days: None,
            acknowledge_risks: true,
        }),
    )
    .await;
    send(
        &socket_path,
        ReqPayload::SetMode(SetModeRequest {
            local_path: local_path.clone(),
            mode: "send_only".into(),
        }),
    )
    .await;

    // A peer's differing change got gated instead of applied — exactly
    // the divergence a send-only folder is supposed to record.
    state.sync_state.record_out_of_sync("group-beta", "vacation.jpg", 100).unwrap();

    // Step 1: "why does this folder say out of sync?"
    let resp = send(
        &socket_path,
        ReqPayload::FolderDivergenceSummary(FolderDivergenceSummaryRequest {
            local_path: local_path.clone(),
        }),
    )
    .await;
    let Some(RespPayload::FolderDivergenceSummary(summary)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };
    assert_eq!(summary.mode, "send_only");
    assert_eq!(summary.out_of_sync_count, 1);
    assert_eq!(summary.out_of_sync_sample, vec!["vacation.jpg".to_string()]);

    // Step 2: "what would fixing this do?" — a dry run, no mutation yet.
    let resp = send(
        &socket_path,
        ReqPayload::FolderResolutionPreview(FolderResolutionPreviewRequest {
            local_path: local_path.clone(),
            action: "override".into(),
            target_mode: String::new(),
        }),
    )
    .await;
    let Some(RespPayload::FolderResolutionPreview(preview)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };
    assert_eq!(preview.affected_count, 1);
    assert_eq!(
        state.sync_state.count_out_of_sync("group-beta").unwrap(),
        1,
        "preview must not mutate"
    );

    // Step 3: "OK, fix it."
    let resp = send(
        &socket_path,
        ReqPayload::FolderResolutionConfirm(FolderResolutionConfirmRequest {
            preview_id: preview.preview_id,
        }),
    )
    .await;
    let Some(RespPayload::FolderResolutionConfirm(result)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };
    assert_eq!(result.affected_count, 1);
    assert_eq!(state.sync_state.count_out_of_sync("group-beta").unwrap(), 0);

    // Step 4: "what did the system just do, for my own records?"
    let resp = send(
        &socket_path,
        ReqPayload::ListFolderOperationAudit(ListFolderOperationAuditRequest {
            local_path: local_path.clone(),
        }),
    )
    .await;
    let Some(RespPayload::ListFolderOperationAudit(audit)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };
    assert_eq!(audit.entries.len(), 1);
    assert_eq!(audit.entries[0].action, "override");
    assert_eq!(audit.entries[0].affected_count, 1);
}

/// Beta acceptance scenario: "a peer isn't connecting, what's wrong?" —
/// the connectivity doctor should give bounded, user-actionable categories
/// even when nothing else about the daemon has been configured yet,
/// rather than a blank screen or a raw error.
#[tokio::test]
async fn diagnosing_a_failed_peer_connection_via_the_doctor() {
    let (socket_path, _dir, _state) = start_daemon_with_state().await;

    let resp =
        send(&socket_path, ReqPayload::ConnectivityDoctor(ConnectivityDoctorRequest {})).await;
    let Some(RespPayload::ConnectivityDoctor(result)) = resp.payload else {
        panic!("wrong response variant: {:?}", resp.payload)
    };

    let names: Vec<&str> = result.categories.iter().map(|c| c.name.as_str()).collect();
    for expected in [
        "daemon",
        "listener",
        "coordination_plane",
        "discovery",
        "relay",
        "authorization",
        "clock_config",
        "policy_disabled",
    ] {
        assert!(names.contains(&expected), "missing doctor category {expected}: {names:?}");
    }
    // Every category reports a bounded, known status — never blank.
    for category in &result.categories {
        assert!(
            matches!(category.status.as_str(), "ok" | "warn" | "error"),
            "unexpected status {} for {}",
            category.status,
            category.name
        );
        assert!(!category.detail.is_empty(), "{} has no user-actionable detail", category.name);
    }
    // This freshly-started daemon is, at minimum, actually running.
    let daemon_category = result.categories.iter().find(|c| c.name == "daemon").unwrap();
    assert_eq!(daemon_category.status, "ok");
}
