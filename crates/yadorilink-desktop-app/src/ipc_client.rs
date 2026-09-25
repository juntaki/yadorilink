//! This app's view of the daemon's control socket.
//!
//! The socket client itself is `yadorilink_client_core::daemon::control`, the
//! one implementation every front end shares (framing, connect, protocol
//! version check). This module only maps its errors onto the messages this
//! app shows, and names the config directory the app reads its own files
//! from -- the same directory the daemon and the command line use.

use std::path::PathBuf;

use yadorilink_client_core::coordination::device_config;
use yadorilink_client_core::CoreError;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::DaemonControlResponse;

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
    Io(String),
}

/// The client layer's errors, in this app's words. A daemon that refused or
/// answered unexpectedly reads as "daemon returned an error", whatever the
/// client layer's category for it.
impl From<CoreError> for IpcError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::DaemonNotRunning => IpcError::DaemonNotRunning,
            CoreError::DaemonProtocolMismatch { client, daemon } => {
                IpcError::ProtocolMismatch { client_version: client, daemon_version: daemon }
            }
            CoreError::Io(message) => IpcError::Io(message),
            CoreError::DaemonRejected(message) | CoreError::Other(message) => {
                IpcError::DaemonError(message)
            }
            other => IpcError::DaemonError(other.to_string()),
        }
    }
}

/// The config directory this installation's daemon, command line and app
/// share: `YADORILINK_CONFIG_DIR`, else the platform's application-data
/// directory.
pub fn config_dir_public() -> PathBuf {
    device_config::config_dir()
}

/// Sends one request over the daemon's control socket.
pub async fn send(payload: ReqPayload) -> Result<DaemonControlResponse, IpcError> {
    Ok(yadorilink_client_core::daemon::control::send(payload).await?)
}

/// Whether a device has already been registered locally (`device.json`
/// written by a prior registration) -- read directly from the local config
/// file rather than over IPC: this is local client identity, not
/// daemon-owned sync state.
pub fn is_device_registered() -> bool {
    device_config::config_path().is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every client-layer error this app can meet on the control socket
    /// reads exactly as this app worded it before the socket client moved.
    #[test]
    fn client_errors_keep_this_apps_wording() {
        assert_eq!(
            IpcError::from(CoreError::DaemonNotRunning).to_string(),
            "daemon is not running or not reachable"
        );
        assert_eq!(
            IpcError::from(CoreError::DaemonProtocolMismatch { client: 11, daemon: 10 })
                .to_string(),
            "desktop app/daemon protocol version mismatch (app 11, daemon 10); run matching \
             YadoriLink app and daemon binaries"
        );
        assert_eq!(
            IpcError::from(CoreError::DaemonRejected("no such link".into())).to_string(),
            "daemon returned an error: no such link"
        );
        assert_eq!(
            IpcError::from(CoreError::Other("unexpected daemon response".into())).to_string(),
            "daemon returned an error: unexpected daemon response"
        );
        assert_eq!(IpcError::from(CoreError::Io("pipe".into())).to_string(), "io error: pipe");
    }
}
