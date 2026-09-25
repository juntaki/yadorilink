//! The control-socket client against a stand-in daemon that answers one
//! request with a canned response, so the client's own checks are exercised
//! over a real socket rather than by building `CoreError` values directly.
#![cfg(unix)]

use yadorilink_client_core::error::CoreError;
use yadorilink_client_core::ops::folders::pause_folder;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, PauseResponse, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`, a process-global
/// environment variable, so they run one at a time.
static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Binds a socket, points the client at it, and answers the first request
/// with `response`. Returns the request the daemon received.
async fn with_canned_daemon<T>(
    response: DaemonControlResponse,
    client: impl std::future::Future<Output = T>,
) -> (T, DaemonControlRequest) {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_message::<DaemonControlRequest>(&mut stream).await.unwrap().unwrap();
        write_message(&mut stream, &response).await.unwrap();
        request
    });
    let result = client.await;
    let request = daemon.await.unwrap();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
    (result, request)
}

/// A daemon from another protocol generation is refused even when its answer
/// looks like success: a pause it may not have understood must not read as
/// done.
#[tokio::test]
async fn a_success_answer_from_a_daemon_of_another_protocol_generation_is_refused() {
    let daemon = CONTROL_PROTOCOL_VERSION + 1;
    let (result, request) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: daemon,
            payload: Some(RespPayload::Pause(PauseResponse {})),
        },
        pause_folder("/folder".into()),
    )
    .await;
    assert_eq!(request.protocol_version, CONTROL_PROTOCOL_VERSION);
    assert!(matches!(request.payload, Some(ReqPayload::Pause(ref r)) if r.local_path == "/folder"));
    match result {
        Err(CoreError::DaemonProtocolMismatch { client, daemon: got }) => {
            assert_eq!((client, got), (CONTROL_PROTOCOL_VERSION, daemon));
        }
        other => panic!("expected a protocol mismatch, got {other:?}"),
    }
}

/// A plain error answer is a rejection, not a pause that went through.
#[tokio::test]
async fn a_plain_error_answer_is_a_rejection_with_the_daemons_message() {
    let (result, _) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Error("no such link".into())),
        },
        pause_folder("/folder".into()),
    )
    .await;
    assert!(
        matches!(&result, Err(CoreError::DaemonRejected(m)) if m == "no such link"),
        "{result:?}"
    );
}

/// The matching generation with the expected payload succeeds, so the two
/// refusals above are the checks and not a socket that never works.
#[tokio::test]
async fn a_matching_success_answer_succeeds() {
    let (result, _) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Pause(PauseResponse {})),
        },
        pause_folder("/folder".into()),
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
}
