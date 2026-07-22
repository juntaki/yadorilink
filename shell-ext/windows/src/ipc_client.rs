//! Thin, blocking-from-the-caller's-perspective IPC client for the
//! shell-integration protocol, following
//! the exact pattern `yadorilink_daemon::shell_ipc::client` documents as the
//! reference implementation for native shell-extension shims — but
//! implemented directly against `yadorilink-ipc-proto` rather than
//! depending on the (much larger) `yadorilink-daemon` crate, since this
//! code loads into every Explorer.exe process via a shell extension DLL.
//!
//! COM shell-extension callbacks (`IsMemberOf`, `GetOverlayInfo`, etc.)
//! are inherently synchronous, so this module owns one lazily-started,
//! single-threaded Tokio runtime and blocks on it per call — the same
//! bounded-timeout, fail-soft-to-`Unspecified` contract as the reference
//! client, just without requiring Explorer's calling thread to itself be
//! async.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::runtime::Runtime;
use windows::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionRequest, FolderFileEntry, HydrateRequest, ListFolderFilesRequest,
    ListOnDemandFoldersRequest, MaterializationState, OnDemandFolder, ShellIpcMessage, StatusQuery,
    SyncState,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
const ERROR_PIPE_BUSY: i32 = 231;
const MAX_ATTEMPTS: u32 = 5;
const RETRY_DELAY: Duration = Duration::from_millis(50);

/// On-demand sync's bounded hydration timeout is 30s
/// daemon-side (the time budget for the actual peer block fetch); this
/// client-side bound is set a little above that so the daemon's own
/// timeout has a chance to fire first and report a clean
/// `HydrateResponse { ok: false,.. }` rather than this client abandoning
/// the pipe read first and reporting a generic failure with no reason.
/// Substantially longer than `DEFAULT_TIMEOUT` (200ms, for cheap,
/// frequent status polls) and `DEFAULT_TIMEOUT * 10` (2s, for
/// context-menu actions that are usually local-only) because hydration is
/// the one shell-IPC call expected to involve real peer network I/O.
const HYDRATE_TIMEOUT: Duration = Duration::from_secs(31);

/// Folder/file enumeration (`ListOnDemandFolders`/
/// `ListFolderFiles`) runs at cfapi host startup, not on Explorer's UI
/// thread, so it can afford a more generous bound than the interactive
/// calls above without risking a visible hang anywhere.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the shell extension's background IPC runtime")
    })
}

fn pipe_name() -> String {
    #[cfg(debug_assertions)]
    {
        if let Ok(name) = std::env::var("YADORILINK_SHELL_IPC_PIPE") {
            return name;
        }
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\yadorilink-{user}")
}

async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let name = pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION.0).open(&name) {
            Ok(client) => {
                verify_server_identity(&client)?;
                return Ok(client);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(windows)]
fn verify_server_identity(client: &NamedPipeClient) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, TokenOwner, TOKEN_OWNER, TOKEN_QUERY,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe fn owner_sid_for_process(process: HANDLE) -> std::io::Result<Vec<u8>> {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token).map_err(win32_error)?;

        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenOwner, None, 0, &mut len);
        let mut buffer = vec![0u8; len as usize];
        let result = GetTokenInformation(
            token,
            TokenOwner,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            len,
            &mut len,
        );
        CloseHandle(token).ok();
        result.map_err(win32_error)?;
        Ok(buffer)
    }

    unsafe fn token_owner_sid(buffer: &[u8]) -> windows::Win32::Security::PSID {
        buffer.as_ptr().cast::<TOKEN_OWNER>().read_unaligned().Owner
    }

    unsafe {
        let pipe_handle = HANDLE(client.as_raw_handle());
        let mut server_pid = 0u32;
        GetNamedPipeServerProcessId(pipe_handle, &mut server_pid).map_err(win32_error)?;

        let server_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, server_pid)
            .map_err(win32_error)?;
        let server_owner = owner_sid_for_process(server_process)?;
        CloseHandle(server_process).ok();

        let current_process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::process::id())
                .map_err(win32_error)?;
        let current_owner = owner_sid_for_process(current_process)?;
        CloseHandle(current_process).ok();

        let server_sid = token_owner_sid(&server_owner);
        let current_sid = token_owner_sid(&current_owner);
        EqualSid(server_sid, current_sid).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "named-pipe server is not owned by the current user",
            )
        })
    }
}

#[cfg(windows)]
fn win32_error(err: windows::core::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

/// Queries the daemon for `path`'s sync state. Never blocks Explorer for
/// longer than `DEFAULT_TIMEOUT`, and fails soft to `Unspecified` (no
/// overlay) on any error — including "the daemon isn't running at all".
pub fn query_status(path: &str) -> SyncState {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_status_inner(path))
            .await
            .unwrap_or(SyncState::Unspecified)
    })
}

async fn query_status_inner(path: &str) -> SyncState {
    let Ok(mut stream) = connect().await else { return SyncState::Unspecified };
    let msg = ShellIpcMessage {
        payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return SyncState::Unspecified;
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusResponse(r)) })) => {
            SyncState::try_from(r.state).unwrap_or(SyncState::Unspecified)
        }
        _ => SyncState::Unspecified,
    }
}

/// on-demand-sync's "online-only" overlay: `MaterializationState`, not
/// `SyncState`, is the authoritative signal for whether a file is an
/// unhydrated placeholder — independent of sync convergence.
pub fn is_placeholder(path: &str) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT, is_placeholder_inner(path)).await.unwrap_or(false)
    })
}

async fn is_placeholder_inner(path: &str) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let msg = ShellIpcMessage {
        payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusResponse(r)) })) => {
            MaterializationState::try_from(r.materialization_state)
                == Ok(MaterializationState::Placeholder)
        }
        _ => false,
    }
}

/// Sends a context-menu action ("view status", "pause", "resume", "pin",
/// "evict") for `path`. Returns `true` on a confirmed success response
/// from the daemon; `false` for any failure, timeout, or unreachable
/// daemon — the caller (the context menu handler) is expected to just
/// silently no-op the menu item in that case rather than show an error
/// dialog, matching the overlay's own fail-soft contract.
pub fn send_context_action(path: &str, action: ContextAction) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT * 10, send_context_action_inner(path, action))
            .await
            .unwrap_or(false)
    })
}

/// Requests synchronous hydration of `path`:
/// the Cloud Filter API `CF_CALLBACK_TYPE_FETCH_DATA` handler calls this
/// and blocks on the result before completing the OS callback via
/// `CfExecute`. Returns `false` on any failure, timeout, or unreachable
/// daemon — the caller is expected to complete the pending cfapi callback
/// with an I/O error in that case, never hang the calling
/// application's read.
pub fn hydrate(path: &str) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(HYDRATE_TIMEOUT, hydrate_inner(path)).await.unwrap_or(false)
    })
}

async fn hydrate_inner(path: &str) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let msg = ShellIpcMessage {
        payload: Some(Payload::HydrateRequest(HydrateRequest { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    matches!(
        read_message::<ShellIpcMessage>(&mut stream).await,
        Ok(Some(ShellIpcMessage { payload: Some(Payload::HydrateResponse(r)) })) if r.ok
    )
}

/// Lists every OnDemand-policy linked folder the daemon currently knows
/// about (addressing a gap where `daemon_control.proto`'s
/// `ListLinks` reports per-group aggregates, not enough for a cfapi host
/// to know which local paths to register as sync roots). Empty on any
/// failure or if the daemon isn't reachable — the cfapi host's caller is
/// expected to just register nothing and retry on its own poll interval,
/// matching this client's fail-soft-never-hang contract elsewhere.
pub fn list_on_demand_folders() -> Vec<OnDemandFolder> {
    runtime().block_on(async {
        tokio::time::timeout(LIST_TIMEOUT, list_on_demand_folders_inner()).await.unwrap_or_default()
    })
}

async fn list_on_demand_folders_inner() -> Vec<OnDemandFolder> {
    let Ok(mut stream) = connect().await else { return Vec::new() };
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListOnDemandFoldersRequest(ListOnDemandFoldersRequest {})),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return Vec::new();
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListOnDemandFoldersResponse(r)) })) => {
            r.folders
        }
        _ => Vec::new(),
    }
}

/// Lists every non-deleted file the daemon has indexed under the OnDemand
/// folder rooted at `local_path` (same reasoning as
/// `list_on_demand_folders`), with enough metadata (`size`,
/// `mtime_unix_nanos`, `materialization_state`) to create or update a
/// cfapi placeholder per file. `local_path` must match a `local_path`
/// this client already got back from `list_on_demand_folders`.
pub fn list_folder_files(local_path: &str) -> Vec<FolderFileEntry> {
    runtime().block_on(async {
        tokio::time::timeout(LIST_TIMEOUT, list_folder_files_inner(local_path))
            .await
            .unwrap_or_default()
    })
}

async fn list_folder_files_inner(local_path: &str) -> Vec<FolderFileEntry> {
    let Ok(mut stream) = connect().await else { return Vec::new() };
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListFolderFilesRequest(ListFolderFilesRequest {
            local_path: local_path.to_string(),
        })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return Vec::new();
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListFolderFilesResponse(r)) })) => {
            r.entries
        }
        _ => Vec::new(),
    }
}

async fn send_context_action_inner(path: &str, action: ContextAction) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let msg = ShellIpcMessage {
        payload: Some(Payload::ContextActionRequest(ContextActionRequest {
            path: path.to_string(),
            action: action as i32,
        })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    matches!(
        read_message::<ShellIpcMessage>(&mut stream).await,
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ContextActionResponse(r)) })) if r.ok
    )
}
