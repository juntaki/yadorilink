//! This crate's own control-socket client. Deliberately duplicated from
//! `yadorilink-cli`'s `control_client.rs`/`device_config.rs` rather than
//! shared — that's this codebase's own established precedent (see
//! `yadorilink-cli`'s `device_config.rs` doc comment: "duplicated rather
//! than shared... the same reason `config_dir` is already duplicated
//! between the two crates"), and a research pass over this workspace
//! found no existing client library crate a new binary could depend on
//! instead. Only `yadorilink-ipc-proto` (wire messages + framing) is a
//! project-internal dependency here.

use std::path::PathBuf;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, DaemonControlResponse};
use yadorilink_ipc_proto::framing::{read_message, write_message};

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("daemon is not running or not reachable")]
    DaemonNotRunning,
    #[error("daemon returned an error: {0}")]
    DaemonError(String),
    #[error(
        "desktop app/daemon protocol version mismatch (app {client_version}, daemon {daemon_version}); run matching YadoriLink app and daemon binaries"
    )]
    ProtocolMismatch { client_version: u32, daemon_version: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn config_dir_public() -> PathBuf {
    config_dir()
}

fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    yadorilink_local_storage_default_root()
}

/// Mirrors `yadorilink-cli`'s `device_config::config_dir`'s fallback
/// exactly (same default root a fresh install's daemon/CLI already use),
/// without adding a dependency on `yadorilink-local-storage` just for this
/// one path helper.
fn yadorilink_local_storage_default_root() -> PathBuf {
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .map(|home| PathBuf::from(home).join(".yadorilink"))
            .unwrap_or_else(|_| PathBuf::from("."))
    }
    #[cfg(windows)]
    {
        std::env::var("APPDATA")
            .map(|appdata| PathBuf::from(appdata).join("yadorilink"))
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("YADORILINK_CONTROL_SOCKET") {
        return PathBuf::from(p);
    }
    config_dir().join("daemon.sock")
}

#[cfg(windows)]
pub fn control_pipe_name() -> String {
    if let Ok(name) = std::env::var("YADORILINK_CONTROL_PIPE") {
        return name;
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-ctl-{user}")
}

pub async fn send(payload: ReqPayload) -> Result<DaemonControlResponse, IpcError> {
    let mut stream = connect().await.map_err(|_| IpcError::DaemonNotRunning)?;
    let protocol_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION;
    write_message(&mut stream, &DaemonControlRequest { payload: Some(payload), protocol_version })
        .await?;
    let resp = read_message::<DaemonControlResponse>(&mut stream)
        .await?
        .ok_or(IpcError::DaemonNotRunning)?;

    // The pre-release desktop app and daemon are one release unit. Reject
    // different development protocol generations instead of relying on
    // protobuf's missing-field defaults as an implicit compatibility layer.
    if resp.daemon_protocol_version != protocol_version {
        return Err(IpcError::ProtocolMismatch {
            client_version: protocol_version,
            daemon_version: resp.daemon_protocol_version,
        });
    }
    if let Some(RespPayload::Error(msg)) = &resp.payload {
        return Err(IpcError::DaemonError(msg.clone()));
    }
    Ok(resp)
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(control_socket_path()).await
}

/// Windows local IPC support: same busy-pipe retry `yadorilink-cli`'s own
/// `connect` uses (see that module's doc comment for why) -- unverified
/// in this environment (no Windows toolchain/machine available here), kept
/// identical to the already-Windows-VM-verified CLI implementation rather
/// than inventing a new approach.
#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    let pipe_name = control_pipe_name();
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

/// Whether a device has already been registered locally (`device.json`
/// written by a prior `yadorilink device register`) -- read directly
/// from the local config file rather than over IPC, matching the
/// codebase's established pattern for this exact question
/// (`yadorilink-cli`'s `commands/link.rs`::`share accept` reads
/// `device_config` directly for the same reason: this is local client
/// identity, not daemon-owned sync state, so there's no aggregate-status
/// API for it). This app stays a thin status-app: it queries daemon
/// state and reads its own local config, it does not invent new daemon
/// surface for information that's already a local file.
pub fn is_device_registered() -> bool {
    config_dir().join("device.json").is_file()
}
