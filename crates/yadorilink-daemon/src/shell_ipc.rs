//! Local IPC between the daemon and OS shell extensions (Windows Explorer
//! icon overlay/context-menu handler, macOS Finder Sync extension).
//! Framed as length-prefixed protobuf
//! (`yadorilink_ipc_proto::framing`), not gRPC, since Explorer/Finder call
//! synchronously and frequently — full HTTP/2 setup overhead risks
//! visible UI lag.
//!
//! Unlike the daemon control socket (one request/response per connection),
//! this is a persistent duplex connection: the daemon proactively pushes
//! `StatusPush` updates (task 8.5) while continuing to answer the client's
//! `StatusQuery`/`ContextActionRequest` messages on the same connection.
//!
//! Transport: Unix domain socket on macOS/Linux (task 8.4 — the "over
//! XPC" sandbox bridging for a real macOS Finder Sync extension is
//! properly section 10's job, specifically task 10.4; what's implemented
//! here is the daemon-side socket those XPC-relayed bytes would ultimately
//! reach). Windows named pipe (task 8.3) is implemented behind
//! `#[cfg(windows)]` and has not been compiled or run on this
//! (non-Windows) development machine; verify on real Windows hardware
//! before relying on it.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionResponse, FolderFileEntry, HydrateResponse,
    ListFolderFilesResponse, ListOnDemandFoldersResponse,
    MaterializationState as ShellMaterializationState, OnDemandFolder, ShellIpcMessage,
    StatusResponse,
};

use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::shell_status::{
    resolve_group_and_rel_path, resolve_materialization_state, resolve_open_elsewhere,
    resolve_status,
};

const MAX_SHELL_IPC_CONNECTIONS: usize = 64;

fn to_shell_materialization_state(
    state: Option<yadorilink_sync_core::types::MaterializationState>,
) -> ShellMaterializationState {
    match state {
        Some(yadorilink_sync_core::types::MaterializationState::Hydrated) => {
            ShellMaterializationState::Hydrated
        }
        Some(yadorilink_sync_core::types::MaterializationState::Placeholder) => {
            ShellMaterializationState::Placeholder
        }
        Some(yadorilink_sync_core::types::MaterializationState::Hydrating) => {
            ShellMaterializationState::Hydrating
        }
        None => ShellMaterializationState::Unspecified,
    }
}

pub async fn handle_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    state: Arc<DaemonState>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut push_rx = state.status_push_tx.subscribe();
    loop {
        tokio::select! {
            biased;

            incoming = read_message::<ShellIpcMessage>(&mut read_half) => {
                match incoming? {
                    None => return Ok(()), // client disconnected
                    Some(msg) => {
                        if let Some(response) = handle_message(&state, msg).await {
                            write_message(&mut write_half, &response).await?;
                        }
                    }
                }
            }

            push = push_rx.recv() => {
                if let Ok(push) = push {
                    write_message(&mut write_half, &ShellIpcMessage { payload: Some(Payload::StatusPush(push)) }).await?;
                }
            }
        }
    }
}

async fn handle_message(state: &Arc<DaemonState>, msg: ShellIpcMessage) -> Option<ShellIpcMessage> {
    match msg.payload {
        Some(Payload::StatusQuery(q)) => {
            let sync_state = resolve_status(state, &q.path);
            let materialization_state = resolve_materialization_state(state, &q.path);
            let open_elsewhere_device_id =
                resolve_open_elsewhere(state, &q.path).unwrap_or_default();
            Some(ShellIpcMessage {
                payload: Some(Payload::StatusResponse(StatusResponse {
                    path: q.path,
                    state: sync_state as i32,
                    materialization_state: to_shell_materialization_state(materialization_state)
                        as i32,
                    open_elsewhere_device_id,
                })),
            })
        }
        Some(Payload::HydrateRequest(req)) => {
            let response = match resolve_group_and_rel_path(state, &req.path) {
                Some((group_id, rel_path)) => {
                    match hydration::hydrate(state, &group_id, &rel_path).await {
                        Ok(()) => HydrateResponse { ok: true, error: String::new() },
                        Err(e) => HydrateResponse { ok: false, error: e.to_string() },
                    }
                }
                None => HydrateResponse {
                    ok: false,
                    error: "path is not under any linked folder".into(),
                },
            };
            Some(ShellIpcMessage { payload: Some(Payload::HydrateResponse(response)) })
        }
        Some(Payload::ContextActionRequest(req)) => {
            let response = match ContextAction::try_from(req.action) {
                Ok(ContextAction::ViewStatus) => {
                    ContextActionResponse { ok: true, error: String::new() }
                }
                Ok(ContextAction::PauseItem) => {
                    state
                        .paused_paths
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(req.path);
                    ContextActionResponse { ok: true, error: String::new() }
                }
                Ok(ContextAction::ResumeItem) => {
                    state
                        .paused_paths
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&req.path);
                    ContextActionResponse { ok: true, error: String::new() }
                }
                // on-demand-sync spec "Context Menu Actions Include Pin and
                // Evict": the same daemon operations `yadorilink pin`/`yadorilink
                // evict` (control_socket) drive, exposed via the shell
                // extension's context menu instead of the CLI.
                Ok(ContextAction::PinItem) => match resolve_group_and_rel_path(state, &req.path) {
                    Some((group_id, rel_path)) => {
                        match hydration::pin(state, &group_id, &rel_path).await {
                            Ok(()) => ContextActionResponse { ok: true, error: String::new() },
                            Err(e) => ContextActionResponse { ok: false, error: e.to_string() },
                        }
                    }
                    None => ContextActionResponse {
                        ok: false,
                        error: "path is not under any linked folder".into(),
                    },
                },
                Ok(ContextAction::EvictItem) => {
                    match resolve_group_and_rel_path(state, &req.path) {
                        Some((group_id, rel_path)) => {
                            match hydration::evict(state, &group_id, &rel_path) {
                                Ok(()) => ContextActionResponse { ok: true, error: String::new() },
                                Err(e) => ContextActionResponse { ok: false, error: e.to_string() },
                            }
                        }
                        None => ContextActionResponse {
                            ok: false,
                            error: "path is not under any linked folder".into(),
                        },
                    }
                }
                _ => ContextActionResponse { ok: false, error: "unknown context action".into() },
            };
            Some(ShellIpcMessage { payload: Some(Payload::ContextActionResponse(response)) })
        }
        // on-demand-sync task 6.1/6.2 gap (see shellipc.proto's doc comment
        // on these two messages): lets a platform virtual-filesystem
        // provider (Windows cfapi) discover which linked folders are
        // OnDemand and enumerate their files to register sync roots and
        // create placeholders.
        Some(Payload::ListOnDemandFoldersRequest(_)) => {
            let folders = state
                .sync_state
                .list_links()
                .unwrap_or_default()
                .into_iter()
                .filter(|l| {
                    l.materialization_policy
                        == yadorilink_sync_core::types::MaterializationPolicy::OnDemand
                })
                .map(|l| OnDemandFolder { local_path: l.local_path, group_id: l.group_id })
                .collect();
            Some(ShellIpcMessage {
                payload: Some(Payload::ListOnDemandFoldersResponse(ListOnDemandFoldersResponse {
                    folders,
                })),
            })
        }
        Some(Payload::ListFolderFilesRequest(req)) => {
            let entries = state
                .sync_state
                .list_links()
                .unwrap_or_default()
                .into_iter()
                .find(|l| l.local_path == req.local_path)
                .map(|l| {
                    state
                        .sync_state
                        .list_files(&l.group_id)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|f| !f.deleted)
                        .map(|f| {
                            let materialization_state = to_shell_materialization_state(
                                state
                                    .sync_state
                                    .get_materialization_state(&l.group_id, &f.path)
                                    .ok()
                                    .flatten(),
                            );
                            FolderFileEntry {
                                relative_path: f.path,
                                size: f.size,
                                mtime_unix_nanos: f.mtime_unix_nanos,
                                materialization_state: materialization_state as i32,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(ShellIpcMessage {
                payload: Some(Payload::ListFolderFilesResponse(ListFolderFilesResponse {
                    entries,
                })),
            })
        }
        _ => None, // StatusResponse/StatusPush/ContextActionResponse/... are server->client only
    }
}

/// Reference client implementation (task 8.6): the shell extension's
/// native shim (Rust via `windows-rs` on Windows per or an FFI
/// core called from the Swift `FinderSync` extension on macOS) follows
/// this exact pattern — bounded timeout, `Unspecified` (no overlay) on
/// any failure, never blocking the file manager UI waiting on a daemon
/// that might not be running.
pub mod client {
    #[cfg(unix)]
    use std::path::Path;
    use std::time::Duration;

    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
    use yadorilink_ipc_proto::shellipc::{
        ShellIpcMessage, StatusQuery, SyncState as ShellSyncState,
    };

    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);

    #[cfg(unix)]
    pub async fn query_status(socket_path: &Path, path: &str) -> ShellSyncState {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_inner(socket_path, path))
            .await
            .unwrap_or(Ok(ShellSyncState::Unspecified))
            .unwrap_or(ShellSyncState::Unspecified)
    }

    #[cfg(unix)]
    async fn query_inner(socket_path: &Path, path: &str) -> std::io::Result<ShellSyncState> {
        let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
        query_over(&mut stream, path).await
    }

    /// windows-local-ipc-support: the Windows counterpart to the `#[cfg(unix)]`
    /// `query_status` above — same bounded-timeout, fail-soft-to-`Unspecified`
    /// contract, but connects to a named pipe (`pipe_name`, e.g.
    /// `\\.\pipe\yadorilink-<user>`) instead of a Unix socket path. A busy pipe
    /// gets a few short retries, matching `control_client`'s connect logic.
    #[cfg(windows)]
    pub async fn query_status(pipe_name: &str, path: &str) -> ShellSyncState {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_inner(pipe_name, path))
            .await
            .unwrap_or(Ok(ShellSyncState::Unspecified))
            .unwrap_or(ShellSyncState::Unspecified)
    }

    #[cfg(windows)]
    async fn query_inner(pipe_name: &str, path: &str) -> std::io::Result<ShellSyncState> {
        use tokio::net::windows::named_pipe::ClientOptions;

        const ERROR_PIPE_BUSY: i32 = 231;
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: Duration = Duration::from_millis(50);

        let mut attempt = 0;
        let mut stream = loop {
            match ClientOptions::new().open(pipe_name) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(e) => return Err(e),
            }
        };
        query_over(&mut stream, path).await
    }

    async fn query_over<S>(stream: &mut S, path: &str) -> std::io::Result<ShellSyncState>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        write_message(
            stream,
            &ShellIpcMessage {
                payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
            },
        )
        .await?;
        let resp = read_message::<ShellIpcMessage>(stream).await?;
        Ok(match resp.and_then(|m| m.payload) {
            Some(Payload::StatusResponse(r)) => {
                ShellSyncState::try_from(r.state).unwrap_or(ShellSyncState::Unspecified)
            }
            _ => ShellSyncState::Unspecified,
        })
    }
}

#[cfg(unix)]
pub mod unix_transport {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixListener;
    use tokio::sync::Semaphore;

    use crate::daemon_state::DaemonState;

    pub async fn serve(socket_path: &Path, state: Arc<DaemonState>) -> std::io::Result<()> {
        let _ = std::fs::remove_file(socket_path);
        prepare_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path)?;
        // Status queries can reveal which folders are linked and their
        // sync state — restrict to the owning user, same reasoning as
        // `control_socket::serve`.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %socket_path.display(), "shell-integration IPC listening (unix socket)");

        let connection_slots = Arc::new(Semaphore::new(super::MAX_SHELL_IPC_CONNECTIONS));
        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("shell IPC semaphore closed"))?;
            let (stream, _) = listener.accept().await?;
            let state = state.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, write_half) = stream.into_split();
                if let Err(e) = super::handle_connection(read_half, write_half, state).await {
                    tracing::debug!(error = %e, "shell IPC connection ended");
                }
            });
        }
    }

    fn prepare_private_socket_parent(socket_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// Windows named-pipe transport (windows-local-ipc-support: verified
/// against a real Windows 11 VM — see `control_socket::windows_transport`'s
/// doc comment for the concurrent-connection pipe-instance race this
/// structure specifically avoids).
#[cfg(windows)]
pub mod windows_transport {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Semaphore;

    use crate::daemon_state::DaemonState;
    use crate::windows_pipe_security::PipeSecurityAttributes;

    // See the identical helpers in `control_socket::windows_transport`:
    // `PipeSecurityAttributes` is `!Send` (raw `*mut c_void`), so it's built
    // and consumed inside a plain, non-async helper rather than as a local in
    // `serve`'s async fn body — that keeps it out of `serve`'s generator
    // state entirely, so the future `essential.spawn` (`main.rs`) wraps it in
    // stays `Send` regardless of how the loop below evolves.
    fn create_first_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    fn create_next_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new().create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    /// `pipe_name` should look like `\\.\pipe\yadorilink-<user>`.
    pub async fn serve(pipe_name: &str, state: Arc<DaemonState>) -> std::io::Result<()> {
        tracing::info!(pipe_name, "shell-integration IPC listening (named pipe)");
        let mut server = create_first_pipe_server(pipe_name)?;
        let connection_slots = Arc::new(Semaphore::new(super::MAX_SHELL_IPC_CONNECTIONS));

        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("shell IPC semaphore closed"))?;
            let next_server = create_next_pipe_server(pipe_name)?;
            server.connect().await?;
            let connected = server;
            server = next_server;

            let state = state.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, mut write_half) = tokio::io::split(connected);
                if let Err(e) = super::handle_connection(read_half, &mut write_half, state).await {
                    tracing::debug!(error = %e, "shell IPC connection ended");
                }
                let _ = write_half.shutdown().await;
            });
        }
    }
}
