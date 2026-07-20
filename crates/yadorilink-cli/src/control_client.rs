//! CLI-side client for the daemon's local control socket,
//! a Unix domain socket on macOS/Linux, a named pipe on Windows
//! (Windows local IPC support).

use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, DaemonControlResponse};
use yadorilink_ipc_proto::framing::{read_message, write_message};

use crate::error::CliError;

pub async fn send(
    payload: yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload,
) -> Result<DaemonControlResponse, CliError> {
    let mut stream = connect().await.map_err(|_| CliError::DaemonNotRunning)?;
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await?;
    let resp = read_message::<DaemonControlResponse>(&mut stream)
        .await?
        .ok_or(CliError::DaemonNotRunning)?;
    if let Some(RespPayload::Error(msg)) = &resp.payload {
        return Err(CliError::Other(msg.clone()));
    }
    Ok(resp)
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(crate::device_config::control_socket_path()).await
}

/// On Windows, the daemon's `windows_transport`
/// pre-creates the next pipe instance before handing off each connection,
/// so a fresh instance should almost always be waiting — but a burst of
/// concurrent CLI invocations can still race it, so a busy pipe
/// (`ERROR_PIPE_BUSY`, raw OS error 231) gets a few short retries rather
/// than failing immediately.
#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    let pipe_name = crate::device_config::control_pipe_name();
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
