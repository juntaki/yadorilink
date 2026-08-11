//! Shell-integration IPC client for the File Provider extension point
//! (7.3). A close copy of
//! `shell-ext/macos/core/src/ipc_client.rs`'s connect/timeout/fail-soft
//! pattern (see this crate's Cargo.toml doc comment for why it's a copy
//! rather than a shared dependency), extended with the three calls
//! `NSFileProviderReplicatedExtension` needs that FinderSync's badge/menu
//! callbacks never did: folder discovery (for domain registration),
//! per-folder file enumeration (for `NSFileProviderEnumerator`), and
//! hydration (for `fetchContents(for:version:request:completionHandler:)`).

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    HydrateRequest, ListFolderFilesRequest, ListOnDemandFoldersRequest,
    LocalWriteKind as ProtoLocalWriteKind, LocalWriteRequest, MaterializationState,
    ShellIpcMessage, StatusQuery, SyncState,
};

/// Status queries (used to build a single `NSFileProviderItem`) get the
/// same short budget `core::ipc_client` uses — a badge/status read must
/// never block a synchronous OS callback noticeably.
const STATUS_TIMEOUT: Duration = Duration::from_millis(200);
/// Folder/file-list enumeration is a bigger read (a whole group's file
/// list — see shellipc.proto's `ListFolderFilesResponse` doc comment)
/// but is still a local, in-memory index lookup on the daemon side, not
/// network I/O — a generous-but-still-bounded budget one order of
/// magnitude above a status read, matching the "context actions can do
/// real work" 2s figure `core::ipc_client::ACTION_TIMEOUT` uses as its
/// own reference point.
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Hydration is real network I/O against a remote peer — a bounded-timeout
/// decision gives the *daemon-side* dispatch a 30s budget
/// (`yadorilink_daemon::hydration::HYDRATION_TIMEOUT`). The client-side wait
/// here must be at least that long (otherwise we'd time out the IPC
/// round trip before the daemon's own deadline fires and gets a chance to
/// return a clean "no peer had this block" error), plus a small margin
/// for the extra hop's own overhead. `fetchContents(for:...)` is
/// synchronous from the *opening application's* point of view, so this
/// is still a bounded wait, just a much longer tier than status/action —
/// a multi-second timeout vs. ~200ms for status.
const HYDRATION_TIMEOUT: Duration = Duration::from_secs(35);
/// M1-3: a local-write notification (`createItem`/`modifyItem`/
/// `deleteItem`) makes the daemon read the live file from disk, chunk/hash
/// it, and commit an index+DAG write -- real local I/O, no network round
/// trip (peer broadcast afterward is fire-and-forget from this call's
/// point of view), so a longer budget than `ENUMERATION_TIMEOUT`'s cheap
/// in-memory lookup, but well short of `HYDRATION_TIMEOUT`'s network wait.
const WRITE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the File Provider extension's background IPC runtime")
    })
}

/// See `core::ipc_client::real_home_dir`'s doc comment: under App
/// Sandbox, `$HOME`/`NSHomeDirectory`/`homeDirectoryForCurrentUser` are
/// all redirected to the extension's own container home, not the real
/// user home. `getpwuid(3)` reads Directory Services directly and is not
/// affected.
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

/// Same App Group ID as `core::ipc_client::APP_GROUP_CONTAINER` — see
/// `YadoriLinkFileProvider/Extension/Extension.entitlements`'s doc comment
/// (copied from `YadoriLinkFinderSync/Extension/Extension.entitlements`,
/// which documents the App-Groups-not-temporary-exception root cause
/// this crate also depends on). Both extensions and the host app must
/// agree on this constant for the daemon's socket to be reachable.
const APP_GROUP_CONTAINER: &str = "group.com.juntaki.yadorilink.shared";

fn socket_path() -> PathBuf {
    if let Ok(path) = std::env::var("YADORILINK_SHELL_IPC_SOCKET") {
        return PathBuf::from(path);
    }
    if let Ok(dir) = std::env::var("YADORILINK_CONFIG_DIR") {
        return PathBuf::from(dir).join("shell.sock");
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

/// The real, real-user-visible home directory, exposed to Swift so the
/// host app can compute `~/Library/CloudStorage/yadorilink` (the
/// managed location) without hitting the same sandbox-redirection trap
/// `real_home_dir`'s doc comment describes — the host app itself is
/// currently unsandboxed (see `YadoriLinkFinderSyncHost`'s lack of an
/// entitlements file), so `FileManager.default.homeDirectoryForCurrentUser`
/// would actually be accurate there today, but routing this through the
/// same `getpwuid`-based helper keeps the host app and both extensions
/// agreeing on one implementation rather than three independent (and
/// potentially divergent) ones.
pub fn real_home_dir_string() -> String {
    real_home_dir().to_string_lossy().into_owned()
}

#[derive(serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct OnDemandFolderInfo {
    pub local_path: String,
    pub group_id: String,
}

/// Discovers every OnDemand-linked folder group ("how does the
/// extension learn which OnDemand folder groups exist" question) via the
/// `ListOnDemandFoldersRequest`/`Response` pair already added to
/// shellipc.proto (see this crate's module doc — added by the parallel
/// Windows cfapi work for the identical need, reused here rather than
/// inventing a second protocol surface). The daemon's own handler
/// (`shell_ipc.rs`'s `ListOnDemandFoldersRequest` arm) answers straight
/// from the persisted link table (`link_repository().list_links()`,
/// filtered to `OnDemand` and not orphaned) — this response IS the
/// authoritative desired-registration-state snapshot, not a cache of it.
///
/// `None` on any failure (unreachable daemon, timeout, malformed
/// response, or an explicit `snapshot_available: false` from the daemon
/// itself — see `shellipc.proto`'s own doc comment on that field) —
/// deliberately distinct from `Some(vec![])`, a *confirmed* "no OnDemand
/// folders exist right now" snapshot. The caller
/// (`DomainRegistration.registerOnDemandDomains`, which reconciles by
/// both registering missing domains AND removing stale ones) must treat
/// `None` as "cannot currently reconcile, leave existing registrations
/// untouched" — collapsing this into an empty `Vec` the way earlier code
/// did would make a transient daemon-unreachable moment look identical to
/// "every domain should be removed," which is exactly the fail-open
/// mistake a snapshot-based reconciliation must not make.
pub fn list_on_demand_folders() -> Option<Vec<OnDemandFolderInfo>> {
    runtime().block_on(async {
        tokio::time::timeout(ENUMERATION_TIMEOUT, list_on_demand_folders_inner()).await.ok()?
    })
}

async fn list_on_demand_folders_inner() -> Option<Vec<OnDemandFolderInfo>> {
    let mut stream = connect().await.ok()?;
    list_on_demand_folders_over(&mut stream).await
}

/// The stream-generic core of `list_on_demand_folders_inner`, split out
/// so this load-bearing None-vs-Some distinction is testable against an
/// in-memory duplex stream instead of a real Unix socket + daemon —
/// mirrors `yadorilink-daemon`'s own `shell_ipc.rs::query_over<S>` split.
async fn list_on_demand_folders_over<S>(stream: &mut S) -> Option<Vec<OnDemandFolderInfo>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListOnDemandFoldersRequest(ListOnDemandFoldersRequest {})),
    };
    write_message(stream, &msg).await.ok()?;
    match read_message::<ShellIpcMessage>(stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListOnDemandFoldersResponse(r)) }))
            if r.snapshot_available =>
        {
            Some(
                r.folders
                    .into_iter()
                    .map(|f| OnDemandFolderInfo { local_path: f.local_path, group_id: f.group_id })
                    .collect(),
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A duplex "server" half that writes `response` (if any) back after
    /// reading whatever request arrives, then closes -- enough to drive
    /// `list_on_demand_folders_over` through each branch without a real
    /// daemon.
    async fn respond_with(response: Option<ShellIpcMessage>) -> Option<Vec<OnDemandFolderInfo>> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
            if let Some(response) = response {
                let _ = write_message(&mut server, &response).await;
            }
            // Dropping `server` here closes the duplex from this end,
            // so a caller expecting a response after a `None` (simulating
            // "server closed the connection without answering") sees EOF
            // rather than hanging.
        });
        let result = list_on_demand_folders_over(&mut client).await;
        server_task.await.unwrap();
        result
    }

    fn response(folders: Vec<OnDemandFolderInfo>, snapshot_available: bool) -> ShellIpcMessage {
        ShellIpcMessage {
            payload: Some(Payload::ListOnDemandFoldersResponse(
                yadorilink_ipc_proto::shellipc::ListOnDemandFoldersResponse {
                    folders: folders
                        .into_iter()
                        .map(|f| yadorilink_ipc_proto::shellipc::OnDemandFolder {
                            local_path: f.local_path,
                            group_id: f.group_id,
                        })
                        .collect(),
                    snapshot_available,
                },
            )),
        }
    }

    #[tokio::test]
    async fn confirmed_nonempty_snapshot_is_some() {
        let folders = vec![OnDemandFolderInfo {
            local_path: "/Users/x/A".to_string(),
            group_id: "group-a".to_string(),
        }];
        let result = respond_with(Some(response(folders.clone(), true))).await;
        assert_eq!(result, Some(folders));
    }

    #[tokio::test]
    async fn confirmed_empty_snapshot_is_some_empty() {
        let result = respond_with(Some(response(vec![], true))).await;
        assert_eq!(result, Some(vec![]));
    }

    /// The exact daemon-side bug this whole change closes: a response
    /// whose `snapshot_available` is `false` (the daemon could not
    /// confirm the desired state, e.g. a DB read error) must be treated
    /// identically to a transport failure, never as "confirmed empty."
    #[tokio::test]
    async fn unconfirmed_snapshot_with_folders_flag_false_is_none() {
        let result = respond_with(Some(response(vec![], false))).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn connection_closed_without_a_response_is_none() {
        let result = respond_with(None).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn wrong_payload_type_is_none() {
        let wrong = ShellIpcMessage {
            payload: Some(Payload::HydrateResponse(
                yadorilink_ipc_proto::shellipc::HydrateResponse { ok: false, error: String::new() },
            )),
        };
        let result = respond_with(Some(wrong)).await;
        assert_eq!(result, None);
    }
}

#[derive(serde::Serialize)]
pub struct FileEntryInfo {
    pub relative_path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    /// Mirrors `shellipc.proto`'s `MaterializationState` names
    /// (`"hydrated" | "placeholder" | "hydrating" | "unspecified"`) as a
    /// plain lowercase string, so the Swift side has no build-time
    /// dependency on the proto's generated numbering (matching
    /// `core::lib::YadoriLinkBadgeStatus`'s stated rationale for keeping the
    /// FFI/JSON contract independent of `prost`'s numbering).
    pub materialization_state: String,
}

fn materialization_state_str(s: MaterializationState) -> &'static str {
    match s {
        MaterializationState::Hydrated => "hydrated",
        MaterializationState::Placeholder => "placeholder",
        MaterializationState::Hydrating => "hydrating",
        MaterializationState::Unspecified => "unspecified",
    }
}

/// Enumerates every (non-deleted) file in the folder group rooted at
/// `local_path` (must match a `local_path` from `list_on_demand_folders`)
/// — backs `NSFileProviderEnumerator.enumerateItems(for:startingAt:)`.
/// `ListFolderFilesResponse` is a flat list (shellipc.proto: "not
/// paginated, not directory-scoped"), so the Swift enumerator buckets
/// these into directory levels itself; this function just relays the
/// daemon's answer, empty on any failure.
pub fn list_folder_files(local_path: &str) -> Vec<FileEntryInfo> {
    runtime().block_on(async {
        tokio::time::timeout(ENUMERATION_TIMEOUT, list_folder_files_inner(local_path))
            .await
            .unwrap_or_default()
    })
}

async fn list_folder_files_inner(local_path: &str) -> Vec<FileEntryInfo> {
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
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListFolderFilesResponse(r)) })) => r
            .entries
            .into_iter()
            .map(|e| FileEntryInfo {
                relative_path: e.relative_path,
                size: e.size,
                mtime_unix_nanos: e.mtime_unix_nanos,
                materialization_state: materialization_state_str(
                    MaterializationState::try_from(e.materialization_state)
                        .unwrap_or(MaterializationState::Unspecified),
                )
                .to_string(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[derive(serde::Serialize)]
pub struct StatusInfo {
    pub sync_state: String,
    pub materialization_state: String,
}

/// Same query `core::ipc_client::query_status` makes, reimplemented here
/// (rather than shared — see this crate's Cargo.toml doc comment) so
/// `item(for:request:completionHandler:)` can build one
/// `NSFileProviderItem` per file without a second, FinderSync-specific
/// dependency. Bounded to `STATUS_TIMEOUT`; fails soft to all-empty/
/// unspecified fields on any error.
pub fn query_status(path: &str) -> StatusInfo {
    runtime().block_on(async {
        tokio::time::timeout(STATUS_TIMEOUT, query_status_inner(path)).await.unwrap_or(StatusInfo {
            sync_state: "unspecified".to_string(),
            materialization_state: "unspecified".to_string(),
        })
    })
}

async fn query_status_inner(path: &str) -> StatusInfo {
    let unspecified = || StatusInfo {
        sync_state: "unspecified".to_string(),
        materialization_state: "unspecified".to_string(),
    };
    let Ok(mut stream) = connect().await else { return unspecified() };
    let msg = ShellIpcMessage {
        payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return unspecified();
    }
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusResponse(r)) })) => StatusInfo {
            sync_state: sync_state_str(
                SyncState::try_from(r.state).unwrap_or(SyncState::Unspecified),
            )
            .to_string(),
            materialization_state: materialization_state_str(
                MaterializationState::try_from(r.materialization_state)
                    .unwrap_or(MaterializationState::Unspecified),
            )
            .to_string(),
        },
        _ => unspecified(),
    }
}

fn sync_state_str(s: SyncState) -> &'static str {
    match s {
        SyncState::Synced => "synced",
        SyncState::Syncing => "syncing",
        SyncState::Pending => "pending",
        SyncState::Error => "error",
        SyncState::Unspecified => "unspecified",
    }
}

/// Requests hydration of `path` (backs `fetchContents(for:version:
/// request:completionHandler:)`). Bounded to `HYDRATION_TIMEOUT`;
/// returns `false` on timeout, an unreachable daemon, or a
/// `HydrateResponse{ok: false,..}` — the caller is expected to complete
/// the OS callback with a clear I/O error in that case, never hang.
pub fn hydrate(path: &str) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(HYDRATION_TIMEOUT, hydrate_inner(path)).await.unwrap_or(false)
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

/// Which File Provider callback produced this notification --
/// `createItem`/`modifyItem` both collapse to the same
/// `CreatedOrModified` signal (the daemon re-observes the live file from
/// disk either way, never trusting the callback's own `contents`/
/// `changedFields`), and `deleteItem` to `Deleted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalWriteKind {
    CreatedOrModified,
    Deleted,
}

/// Notifies the daemon that a local write already landed on disk under
/// `local_path`/`relative_path` (backs `createItem`/`modifyItem`/
/// `deleteItem`). Carries no content or metadata -- only the signal that
/// something changed and what kind; the daemon re-observes the live file
/// itself. Returns `false` on timeout, an unreachable daemon, or a
/// `LocalWriteResponse{ok: false, ..}` -- the caller is expected to
/// complete the OS callback with a clear error in that case, never hang
/// or silently report success for a write the daemon never actually
/// admitted.
pub fn notify_local_write(local_path: &str, relative_path: &str, kind: LocalWriteKind) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(
            WRITE_NOTIFY_TIMEOUT,
            notify_local_write_inner(local_path, relative_path, kind),
        )
        .await
        .unwrap_or(false)
    })
}

async fn notify_local_write_inner(
    local_path: &str,
    relative_path: &str,
    kind: LocalWriteKind,
) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let proto_kind = match kind {
        LocalWriteKind::CreatedOrModified => ProtoLocalWriteKind::CreatedOrModified,
        LocalWriteKind::Deleted => ProtoLocalWriteKind::Deleted,
    };
    let msg = ShellIpcMessage {
        payload: Some(Payload::LocalWriteRequest(LocalWriteRequest {
            local_path: local_path.to_string(),
            relative_path: relative_path.to_string(),
            kind: proto_kind as i32,
        })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    matches!(
        read_message::<ShellIpcMessage>(&mut stream).await,
        Ok(Some(ShellIpcMessage { payload: Some(Payload::LocalWriteResponse(r)) })) if r.ok
    )
}
