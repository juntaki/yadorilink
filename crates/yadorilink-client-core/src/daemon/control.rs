//! The one client for the daemon's local control socket: a Unix domain
//! socket on macOS/Linux, a named pipe on Windows. Every front end sends its
//! daemon requests through [`send`].

use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, DaemonControlResponse};
use yadorilink_ipc_proto::framing::{read_message, write_message};

use crate::error::CoreError;

/// Sends one request and returns the daemon's response. A plain
/// `RespPayload::Error` answer is returned as [`CoreError::DaemonRejected`]
/// and a different protocol generation as
/// [`CoreError::DaemonProtocolMismatch`], so an `Ok` response never carries
/// either and callers match only the payload they expect.
///
/// A daemon that does not accept within [`CONNECT_BUDGET`], or does not
/// answer a quick request within [`QUICK_REPLY_BUDGET`], is returned as
/// [`CoreError::DaemonUnresponsive`]; see [`reply_budget`] for which
/// requests have no reply deadline.
pub async fn send(payload: ReqPayload) -> Result<DaemonControlResponse, CoreError> {
    let stream = tokio::time::timeout(CONNECT_BUDGET, connect())
        .await
        .map_err(|_| CoreError::DaemonUnresponsive)?
        .map_err(|_| CoreError::DaemonNotRunning)?;
    exchange(stream, payload).await
}

/// How long connecting to the control socket may take. A daemon that is
/// running accepts at once; one that is not has no socket to refuse from.
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

/// How long a quick request may wait for its answer. These are the requests
/// the daemon answers from its own state without waiting on the network or a
/// bulk transfer, so a daemon that takes longer is wedged rather than busy.
pub const QUICK_REPLY_BUDGET: Duration = Duration::from_secs(15);

/// The reply deadline for `payload`: [`QUICK_REPLY_BUDGET`] for a quick
/// request (a shutdown among them: the daemon answers it before it drains),
/// `None` for one whose duration depends on the network, on peers
/// or on how much data it moves (linking, transfers, hydration, restores,
/// garbage collection, updates, group commands), which the client cannot
/// bound without failing work that is still progressing.
fn reply_budget(payload: &ReqPayload) -> Option<Duration> {
    match payload {
        ReqPayload::Status(_)
        | ReqPayload::Health(_)
        | ReqPayload::ListLinks(_)
        | ReqPayload::Pause(_)
        | ReqPayload::Resume(_)
        | ReqPayload::ListConflicts(_)
        | ReqPayload::ListInbox(_)
        | ReqPayload::ListTrash(_)
        | ReqPayload::ListVersions(_)
        | ReqPayload::MaterializationStatus(_)
        | ReqPayload::LimitsShow(_)
        | ReqPayload::UpdateStatus(_)
        | ReqPayload::ReportingStatus(_)
        | ReqPayload::ListQueueItems(_)
        | ReqPayload::ShowQueueItem(_)
        | ReqPayload::ListConnectionTraces(_)
        | ReqPayload::ListRecoveryOperations(_)
        | ReqPayload::ShowRecoveryOperation(_)
        | ReqPayload::Shutdown(_) => Some(QUICK_REPLY_BUDGET),
        _ => None,
    }
}

/// One request and its response over an already connected control stream.
/// A quick request that is not answered within its budget is
/// [`CoreError::DaemonUnresponsive`].
async fn exchange(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    payload: ReqPayload,
) -> Result<DaemonControlResponse, CoreError> {
    match reply_budget(&payload) {
        Some(budget) => tokio::time::timeout(budget, round_trip(stream, payload))
            .await
            .map_err(|_| CoreError::DaemonUnresponsive)?,
        None => round_trip(stream, payload).await,
    }
}

async fn round_trip(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    payload: ReqPayload,
) -> Result<DaemonControlResponse, CoreError> {
    let protocol_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION;
    write_message(&mut stream, &DaemonControlRequest { payload: Some(payload), protocol_version })
        .await?;
    let resp = read_message::<DaemonControlResponse>(&mut stream)
        .await?
        .ok_or(CoreError::DaemonNotRunning)?;

    // Pre-release binaries are one release unit. Do not interpret a response
    // from an older/newer development daemon using protobuf zero/default
    // behavior; fail fast and require matching binaries instead.
    if resp.daemon_protocol_version != protocol_version {
        return Err(CoreError::DaemonProtocolMismatch {
            client: protocol_version,
            daemon: resp.daemon_protocol_version,
        });
    }
    if let Some(RespPayload::Error(msg)) = &resp.payload {
        return Err(CoreError::DaemonRejected(msg.clone()));
    }
    Ok(resp)
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(crate::coordination::device_config::control_socket_path()).await
}

/// On Windows, the daemon's `windows_transport`
/// pre-creates the next pipe instance before handing off each connection,
/// so a fresh instance should almost always be waiting — but a burst of
/// concurrent client invocations can still race it, so a busy pipe
/// (`ERROR_PIPE_BUSY`, raw OS error 231) gets a few short retries rather
/// than failing immediately.
#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    let pipe_name = crate::coordination::device_config::control_pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION).open(&pipe_name) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::{ShutdownRequest, StatusRequest};

    use super::exchange;
    use crate::error::{CoreError, DaemonUnavailableReason, DesktopError};

    /// A daemon that accepts the connection and then never answers (wedged,
    /// stopped, stuck on a lock) must come back as unavailable instead of
    /// keeping the caller, and every status poll behind it, waiting forever.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_accepts_but_never_answers_reads_as_unavailable() {
        let (client, _daemon_that_never_answers) =
            tokio::net::UnixStream::pair().expect("socket pair");

        let answer = tokio::time::timeout(
            Duration::from_secs(600),
            exchange(client, ReqPayload::Status(StatusRequest {})),
        )
        .await
        .expect("a request to a silent daemon must give up on its own");

        let error = answer.expect_err("a silent daemon cannot have answered");
        assert!(
            matches!(
                DesktopError::from_core(error, false),
                DesktopError::DaemonUnavailable {
                    reason: DaemonUnavailableReason::Unresponsive,
                    ..
                }
            ),
            "a silent daemon must read as unresponsive, not as not running"
        );
    }

    /// Stopping is what a user reaches for when the daemon is wedged. The
    /// daemon answers a shutdown before it drains, so a silent one is
    /// unresponsive, not a request still in progress.
    #[tokio::test(start_paused = true)]
    async fn a_shutdown_the_daemon_never_answers_gives_up() {
        let (client, _daemon_that_never_answers) =
            tokio::net::UnixStream::pair().expect("socket pair");

        let answer = tokio::time::timeout(
            Duration::from_secs(600),
            exchange(client, ReqPayload::Shutdown(ShutdownRequest {})),
        )
        .await
        .expect("a shutdown sent to a silent daemon must give up on its own");

        assert!(matches!(answer, Err(CoreError::DaemonUnresponsive)), "{answer:?}");
    }
}
