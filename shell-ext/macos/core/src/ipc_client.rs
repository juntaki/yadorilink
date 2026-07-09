//! Thin, blocking-from-the-caller's-perspective IPC client for the
//! shell-integration protocol (build-yadorilink-mvp task 10.1/10.2/10.3),
//! following the exact pattern `yadorilink_daemon::shell_ipc::client`
//! documents as the reference implementation for native shell-extension
//! shims (bounded timeout, fail-soft to `Unspecified`/`false` on any
//! error) — the direct macOS counterpart of
//! `shell-ext/windows/src/ipc_client.rs`, swapping the named pipe for a
//! Unix domain socket and skipping the `ERROR_PIPE_BUSY` retry loop
//! (Unix listen backlogs don't have that failure mode).
//!
//! `FIFinderSync`'s `requestBadgeIdentifier(for:)` and `menu(for:)`
//! callbacks are synchronous from Finder's point of view, so — same as
//! the Windows DLL — this module owns one lazily-started, single-threaded
//! Tokio runtime and blocks on it per call.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionRequest, MaterializationState, ShellIpcMessage, StatusQuery,
    SyncState,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
// Context actions (pause/resume/pin/evict) can involve the daemon doing
// real work (e.g. hydrating a file for pin) before it replies, unlike a
// pure status read — same 10x allowance `shell-ext/windows` grants.
const ACTION_TIMEOUT: Duration = Duration::from_millis(2000);

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the shell extension's background IPC runtime")
    })
}

/// The real user home directory via `getpwuid(3)`, bypassing both the
/// `HOME` environment variable and Foundation's `NSHomeDirectory()` /
/// `FileManager.homeDirectoryForCurrentUser` — under App Sandbox, both of
/// those are silently redirected to the sandbox container's own home
/// (`~/Library/Containers/<bundle-id>/Data`), not the real one.
/// Confirmed on a real sandboxed build (macOS 15.7.7): `env::var("HOME")`
/// returned the container path, so `socket_path()` computed a path that
/// never matched the daemon's actual socket — `query_status` always fell
/// back to Unspecified/no-badge even with a correct
/// `temporary-exception.files.absolute-path.read-write` entitlement for
/// the real path, because the connection target itself was wrong.
/// `getpwuid` reads from Directory Services directly, which isn't
/// affected by that redirection.
fn real_home_dir() -> PathBuf {
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
        }
        let dir = std::ffi::CStr::from_ptr((*pw).pw_dir);
        PathBuf::from(dir.to_string_lossy().into_owned())
    }
}

/// build-yadorilink-mvp task 10.4/10.6: the App Group shared container this
/// sandboxed extension and the (unsandboxed) daemon both use to exchange
/// the Unix socket — see `Extension.entitlements`'s doc comment for why
/// App Groups was used instead of a `temporary-exception.files.*`
/// entitlement (that consistently failed with EPERM despite a correct
/// path and a real signature). The daemon isn't sandboxed itself, so it
/// needs no entitlement to write here — it's just told to via
/// `YADORILINK_SHELL_IPC_SOCKET`, an ordinary filesystem path from its
/// point of view.
///
/// No Team ID prefix in this path, despite matching the
/// `~/Library/Containers/<TeamID>.<bundle-id>/` convention App Sandbox
/// itself uses for its per-app container — confirmed by having the
/// extension call `FileManager.default.
/// containerURL(forSecurityApplicationGroupIdentifier:)` directly and
/// write the result to a file; the Team-ID-prefixed guess resolved to a
/// path that was never created, so `connect()` silently failed. Group ID
/// is specific to this build's provisioning (`Extension.entitlements`)
/// — a real product would want this resolved from the bundle's own
/// entitlements at runtime rather than hardcoded, but that's follow-up
/// work belonging with a real (non-verification-only) App Group rollout.
const APP_GROUP_CONTAINER: &str = "group.com.juntaki.yadorilink.shared";

/// Mirrors `yadorilink_daemon::device_config::config_dir()` /
/// `main.rs`'s socket-path derivation, but reimplemented
/// locally rather than depending on `yadorilink-daemon` (or
/// `yadorilink-local-storage`, whose `FsBlockStore::default_root()` backs
/// the daemon-side version) — this crate intentionally keeps a minimal
/// dependency tree since it loads into every Finder process via the
/// extension bundle. On macOS `FsBlockStore::default_root()` resolves to
/// `~/Library/Application Support/yadorilink/blocks`, so its parent
/// (`config_dir`) is `~/Library/Application Support/yadorilink`, matching
/// the fallback path constructed here.
fn socket_path() -> PathBuf {
    #[cfg(debug_assertions)]
    {
        if let Ok(path) = std::env::var("YADORILINK_SHELL_IPC_SOCKET") {
            return PathBuf::from(path);
        }
        if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
            return PathBuf::from(dir).join("shell.sock");
        }
    }
    let group_container =
        real_home_dir().join("Library").join("Group Containers").join(APP_GROUP_CONTAINER);
    if group_container.is_dir() {
        return group_container.join("shell.sock");
    }
    real_home_dir()
        .join("Library")
        .join("Application Support")
        .join("yadorilink")
        .join("shell.sock")
}

async fn connect() -> std::io::Result<UnixStream> {
    UnixStream::connect(socket_path()).await
}

/// Both signals a badge needs — `SyncState` (convergence with peers) and
/// `MaterializationState` (on-demand-sync's placeholder/hydrated/hydrating,
/// independent of sync convergence per shellipc.proto's comment on
/// `MaterializationState`). Fetched together over one connection rather
/// than two round trips, since `menu(for:)`/badge rendering needs both.
pub struct StatusInfo {
    pub sync_state: SyncState,
    pub materialization_state: MaterializationState,
    /// The advisory "open elsewhere" signal: the device id currently
    /// reported editing this file (Office `~$*` lock-file convention),
    /// empty if not open elsewhere or the signal has expired. Threaded
    /// through here so `combine_status` in lib.rs can render the sixth
    /// badge state without a second round trip.
    pub open_elsewhere_device_id: String,
}

impl StatusInfo {
    const UNSPECIFIED: StatusInfo = StatusInfo {
        sync_state: SyncState::Unspecified,
        materialization_state: MaterializationState::Unspecified,
        open_elsewhere_device_id: String::new(),
    };
}

/// Queries the daemon for `path`'s combined status. Never blocks Finder
/// for longer than `DEFAULT_TIMEOUT`, and fails soft to
/// `StatusInfo::UNSPECIFIED` (no badge) on any error — including "the
/// daemon isn't running at all" (spec "Graceful Degradation When Daemon
/// Is Not Running").
pub fn query_status(path: &str) -> StatusInfo {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_status_inner(path))
            .await
            .unwrap_or(StatusInfo::UNSPECIFIED)
    })
}

async fn query_status_inner(path: &str) -> StatusInfo {
    let Ok(mut stream) = connect().await else { return StatusInfo::UNSPECIFIED };
    let msg = ShellIpcMessage {
        payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return StatusInfo::UNSPECIFIED;
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusResponse(r)) })) => StatusInfo {
            sync_state: SyncState::try_from(r.state).unwrap_or(SyncState::Unspecified),
            materialization_state: MaterializationState::try_from(r.materialization_state)
                .unwrap_or(MaterializationState::Unspecified),
            open_elsewhere_device_id: r.open_elsewhere_device_id,
        },
        _ => StatusInfo::UNSPECIFIED,
    }
}

/// Sends a context-menu action ("view status", "pause", "resume", "pin",
/// "evict") for `path`. Returns `true` on a confirmed success response
/// from the daemon; `false` for any failure, timeout, or unreachable
/// daemon — the caller (the `menu(for:)` handler) is expected to just
/// silently no-op rather than show an error dialog, matching the badge's
/// own fail-soft contract.
pub fn send_context_action(path: &str, action: ContextAction) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(ACTION_TIMEOUT, send_context_action_inner(path, action))
            .await
            .unwrap_or(false)
    })
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
