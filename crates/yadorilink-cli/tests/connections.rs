//! `yadorilink connections`'s partial-output contract, over the real
//! control-socket framing.
//!
//! The command makes TWO requests on TWO connections: the
//! connection-attempt history, then the LAN-discovered candidates held for
//! each peer. Only the first is load-bearing. If the second fails -- a
//! daemon stopping between them, or answering with an error -- the command
//! must still report what it already has, name the missing section, and
//! succeed; a partway-down daemon is exactly when someone runs this, and
//! failing at that point discards output the operator had already been
//! given.
//!
//! That contract lives entirely in `connection_ops::print_lan_discovered_
//! candidates` being infallible, which is an easy thing for a later cleanup
//! to "tidy" back into a `?`-propagating `Result`. These tests exist to
//! make that tidy-up fail.
//!
//! A scripted fake daemon rather than a real one (the pattern
//! `tests/diagnose.rs` uses), because the behaviour under test is what
//! happens when the daemon stops answering PARTWAY THROUGH one command --
//! which a real, healthy `unix_transport::serve` cannot be asked to do.
#![cfg(unix)]

use std::path::PathBuf;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConnectionAttemptTrace, DaemonControlRequest, DaemonControlResponse,
    ListConnectionTracesResponse, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// These tests share `YADORILINK_CONTROL_SOCKET`, a process-global env var
/// -- same coordination discipline as `tests/diagnose.rs`'s own mutex.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn response(payload: RespPayload) -> DaemonControlResponse {
    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
    }
}

fn one_trace() -> RespPayload {
    RespPayload::ListConnectionTraces(ListConnectionTracesResponse {
        traces: vec![ConnectionAttemptTrace {
            peer_device_id: "device-b".into(),
            candidate_source: "local_discovery".into(),
            address_class: "lan".into(),
            outcome: "failed".into(),
            latency_ms: 12,
            failure_category: "no_response".into(),
            selected: false,
            authorization_decision: "n/a".into(),
            recorded_at_unix_nanos: 1,
        }],
    })
}

/// Serves `scripted` in order on one control socket, then stops listening.
///
/// The listener is closed and the socket unlinked BEFORE the last scripted
/// response is written, not after, so by the time the CLI holds that
/// response a further connect provably cannot succeed. Doing it afterwards
/// would leave a race in which the kernel accepts the CLI's second
/// connection into the backlog of a listener nobody is accepting from any
/// more, and the test would hang rather than exercise anything.
///
/// Returns the payload kind of every request actually received, so a test
/// can assert the CLI really did try the second one.
fn scripted_daemon(
    socket_path: PathBuf,
    scripted: Vec<RespPayload>,
) -> tokio::task::JoinHandle<Vec<&'static str>> {
    let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    tokio::spawn(async move {
        let mut listener = Some(listener);
        let mut seen = Vec::new();
        let total = scripted.len();
        for (index, payload) in scripted.into_iter().enumerate() {
            let (mut stream, _) = listener
                .as_ref()
                .expect("the listener is live until the last response")
                .accept()
                .await
                .unwrap();
            let request: DaemonControlRequest =
                read_message(&mut stream).await.unwrap().expect("the CLI must send a request");
            seen.push(match request.payload {
                Some(ReqPayload::ListConnectionTraces(_)) => "list_connection_traces",
                Some(ReqPayload::ListLanDiscoveredCandidates(_)) => {
                    "list_lan_discovered_candidates"
                }
                _ => "unexpected",
            });
            if index + 1 == total {
                listener = None;
                let _ = std::fs::remove_file(&socket_path);
            }
            write_message(&mut stream, &response(payload)).await.unwrap();
        }
        seen
    })
}

/// The contract itself: the daemon answers the trace request and is gone by
/// the time the LAN request goes out. The command must SUCCEED -- it has
/// already printed a complete, correct trace section, and turning that into
/// a non-zero exit because of a second connection it opened afterwards is
/// the regression this pins.
///
/// A `?`-propagating `print_lan_discovered_candidates` fails here.
#[tokio::test]
async fn a_failing_lan_request_does_not_fail_a_command_that_already_has_its_answer() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let daemon = scripted_daemon(socket_path.clone(), vec![one_trace()]);

    yadorilink_cli::commands::connection_ops::traces(None)
        .await
        .expect("a LAN section that cannot be fetched must not discard the trace section");

    assert_eq!(
        daemon.await.unwrap(),
        vec!["list_connection_traces"],
        "the daemon must have answered exactly the first request before going away"
    );
    assert!(
        tokio::net::UnixStream::connect(&socket_path).await.is_err(),
        "the socket must really be gone, or this test proved nothing about the second request"
    );
}

/// Same contract, the other way a second request fails: the daemon is still
/// there and answers, but with an application-level error. The command must
/// still succeed, and the reason it reports is the daemon's own.
#[tokio::test]
async fn a_lan_request_the_daemon_refuses_also_leaves_the_command_successful() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let daemon = scripted_daemon(
        socket_path,
        vec![one_trace(), RespPayload::Error("candidate view unavailable".into())],
    );

    yadorilink_cli::commands::connection_ops::traces(None)
        .await
        .expect("a refused LAN section must not discard the trace section either");

    assert_eq!(
        daemon.await.unwrap(),
        vec!["list_connection_traces", "list_lan_discovered_candidates"],
        "the CLI must have actually issued the second request"
    );
}

/// The other polarity, and the boundary of the rule above: when the FIRST
/// request fails there is nothing to report at all, so the command must
/// still fail. Tolerating a failure of the LAN section must not have
/// quietly turned `connections` into a command that always succeeds.
///
/// Pointing the control socket at a path nothing is listening on is this
/// crate's established stand-in for "daemon not running" (see
/// `tests/diagnose.rs`). Nothing is printed before that failure, because
/// the first `?` returns ahead of every `println!` in `traces` -- not
/// separately asserted here, since an in-process test cannot read back the
/// harness's captured stdout.
#[tokio::test]
async fn a_failing_first_request_still_fails_the_command() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let err = yadorilink_cli::commands::connection_ops::traces(None)
        .await
        .expect_err("with no daemon at all there is nothing to report, so this must fail");
    assert!(
        matches!(err, yadorilink_cli::error::CliError::DaemonNotRunning),
        "the failure must be the unreachable daemon itself, got {err:?}"
    );
}
