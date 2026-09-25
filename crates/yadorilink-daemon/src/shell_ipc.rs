//! Local IPC between the daemon and OS shell extensions (Windows Explorer
//! icon overlay/context-menu handler, macOS Finder Sync extension).
//! Framed as length-prefixed protobuf
//! (`yadorilink_ipc_proto::framing`), not gRPC, since Explorer/Finder call
//! synchronously and frequently — full HTTP/2 setup overhead risks
//! visible UI lag.
//!
//! Unlike the daemon control socket (one request/response per connection),
//! this is a persistent duplex connection: the daemon proactively pushes
//! `StatusPush` updates while continuing to answer the client's
//! `StatusQuery`/`ContextActionRequest` messages on the same connection.
//!
//! Transport: Unix domain socket on macOS/Linux (the "over
//! XPC" sandbox bridging for a real macOS Finder Sync extension is
//! properly section 10's job; what's implemented
//! here is the daemon-side socket those XPC-relayed bytes would ultimately
//! reach). Windows named pipe is implemented behind
//! `#[cfg(windows)]` and has not been compiled or run on this
//! (non-Windows) development machine; verify on real Windows hardware
//! before relying on it.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionResponse, FolderFileEntry, HydrateResponse,
    ListFolderFilesResponse, ListOnDemandFoldersResponse, LocalWriteKind, LocalWriteResponse,
    MaterializationState as ShellMaterializationState, OnDemandFolder, ShellIpcMessage,
    StatusResponse,
};

use crate::shell_context::ShellContext;
use crate::shell_status::{resolve_materialization_state, resolve_status_detail};

const MAX_SHELL_IPC_CONNECTIONS: usize = 64;

fn shell_entry_kind(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_ipc_proto::shellipc::EntryKind {
    use yadorilink_ipc_proto::shellipc::EntryKind;
    use yadorilink_replica_domain::file::RecordKind;
    match kind {
        RecordKind::File => EntryKind::File,
        RecordKind::Directory => EntryKind::Directory,
        RecordKind::Symlink => EntryKind::Symlink,
    }
}

fn to_shell_materialization_state(
    state: Option<yadorilink_replica_domain::session_state::MaterializationState>,
) -> ShellMaterializationState {
    match state {
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated) => {
            ShellMaterializationState::Hydrated
        }
        Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder) => {
            ShellMaterializationState::Placeholder
        }
        Some(
            yadorilink_replica_domain::session_state::MaterializationState::Hydrating
            | yadorilink_replica_domain::session_state::MaterializationState::Evicting,
        ) => ShellMaterializationState::Hydrating,
        None => ShellMaterializationState::Unspecified,
    }
}

pub async fn handle_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    context: Arc<ShellContext>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut push_rx = context.telemetry.subscribe_status();
    loop {
        tokio::select! {
            biased;

            incoming = read_message::<ShellIpcMessage>(&mut read_half) => {
                match incoming? {
                    None => return Ok(()), // client disconnected
                    Some(msg) => {
                        if let Some(response) = handle_message(&context, msg).await {
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

#[allow(
    clippy::too_many_lines,
    clippy::excessive_nesting,
    reason = "exhaustive dispatch over every shell IPC `Payload` variant; keeping \
              the single `match` in one place is what makes the request/response \
              pairing for each variant reviewable and keeps the compiler's \
              exhaustiveness check on the protocol enum. The deep arm is the \
              per-file placeholder-generation fold, whose nesting is the \
              option/result chain (link -> materialization state -> Windows \
              placeholder generation) evaluated inline per listing entry."
)]
async fn handle_message(context: &ShellContext, msg: ShellIpcMessage) -> Option<ShellIpcMessage> {
    match msg.payload {
        Some(Payload::StatusQuery(q)) => {
            let status = resolve_status_detail(&context.replica_coordinator, &q.path);
            let materialization_state =
                resolve_materialization_state(&context.replica_coordinator, &q.path);
            Some(ShellIpcMessage {
                payload: Some(Payload::StatusResponse(StatusResponse {
                    path: q.path,
                    state: status.state as i32,
                    materialization_state: to_shell_materialization_state(materialization_state)
                        as i32,
                    status_detail: status.detail.unwrap_or_default(),
                })),
            })
        }
        Some(Payload::HydrateRequest(req)) => {
            let response = match context.queries.linked_path.resolve(&req.path) {
                Some((group_id, rel_path)) => {
                    match context.application.materialization.hydrate(&group_id, &rel_path).await {
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
                // shell-integration spec "Pause sync for a single item":
                // the same application pause/resume service the control
                // socket's link-level pause goes through, scoped to one
                // file or folder of the link.
                Ok(ContextAction::PauseItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context.application.pause_resume.pause_item(&group_id, &rel_path)
                            {
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
                Ok(ContextAction::ResumeItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context
                                .application
                                .pause_resume
                                .resume_item(&group_id, &rel_path)
                                .await
                            {
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
                // on-demand-sync spec "Context Menu Actions Include Pin and
                // Evict": the same daemon operations `yadorilink pin`/`yadorilink
                // evict` (control_socket) drive, exposed via the shell
                // extension's context menu instead of the CLI.
                Ok(ContextAction::PinItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context
                                .application
                                .materialization
                                .pin(&group_id, &rel_path)
                                .await
                            {
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
                Ok(ContextAction::EvictItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context.application.materialization.evict(&group_id, &rel_path) {
                                // `Ok` alone does not mean the
                                // file was actually freed -- `evict_file`
                                // can return `Ok` while leaving it fully
                                // materialized (pinned, busy, not yet
                                // `Hydrated`, or changed on disk right
                                // before the commit). `ok: true` here must
                                // mean "the action was performed," not
                                // merely "the request didn't error" -- see
                                // `EvictOutcome::dehydrated`'s own doc
                                // comment for the exact prior gap this
                                // closes (the shell extension used to
                                // report every non-erroring request as a
                                // successful eviction).
                                Ok(outcome) if outcome.dehydrated => {
                                    ContextActionResponse { ok: true, error: String::new() }
                                }
                                Ok(_) => ContextActionResponse {
                                    ok: false,
                                    error: "not evicted: the file may be pinned, busy, not fully \
                                            synced, or was just modified"
                                        .into(),
                                },
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
        // A gap (see shellipc.proto's doc comment
        // on these two messages): lets a platform virtual-filesystem
        // provider (Windows cfapi) discover which linked folders are
        // OnDemand and enumerate their files to register sync roots and
        // create placeholders.
        //
        // `list_links()`'s `Err` must NOT collapse into an empty `Vec` here
        // (a prior `unwrap_or_default()` did exactly that) -- a DB/read
        // error is "cannot currently confirm the desired state," not "the
        // desired state is confirmed empty." A macOS caller
        // (`DomainRegistration.swift`) reconciles OS-level domain
        // registrations against this response, including REMOVING
        // registrations absent from it; silently reporting an empty
        // snapshot on a transient read error would tell that caller to
        // remove every registered domain. `snapshot_available` makes the
        // distinction explicit on the wire instead of relying on the
        // client inferring it from a transport-level failure.
        Some(Payload::ListOnDemandFoldersRequest(_)) => {
            let response = match context.replica_coordinator.link_repository().list_links() {
                Ok(links) => {
                    let folders = links
                        .into_iter()
                        .filter(|l| {
                            l.materialization_policy
                                == yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand
                                // An orphaned link's coordination-side
                                // authorization is gone -- it must never be
                                // handed to the platform virtual-filesystem
                                // provider as a sync root to enumerate and
                                // register placeholders for.
                                && !l.orphaned
                        })
                        .map(|l| OnDemandFolder { local_path: l.local_path, group_id: l.group_id })
                        .collect();
                    ListOnDemandFoldersResponse { folders, snapshot_available: true }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "failed to list links for ListOnDemandFoldersRequest; reporting \
                         snapshot_available=false rather than an empty snapshot"
                    );
                    ListOnDemandFoldersResponse { folders: Vec::new(), snapshot_available: false }
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::ListOnDemandFoldersResponse(response)) })
        }
        // Every read below fails the whole listing closed
        // (`snapshot_available: false`, no entries) rather than collapsing
        // into `[]` -- the macOS File Provider treats a successful
        // enumeration as authoritative, so an empty listing that merely
        // could not be read would tell it the folder has zero files. Same
        // contract as `ListOnDemandFoldersRequest` above.
        Some(Payload::ListFolderFilesRequest(req)) => {
            let listing: Result<Vec<FolderFileEntry>, String> = 'listing: {
                let links = match context.replica_coordinator.link_repository().list_links() {
                    Ok(links) => links,
                    Err(e) => break 'listing Err(format!("failed to list links: {e}")),
                };
                // An orphaned link is no longer a live sync target -- treat
                // it the same as "no such link" here, so its folder is
                // never enumerated for placeholder registration either.
                // Neither has a listing to confirm.
                let Some(l) =
                    links.into_iter().find(|l| l.local_path == req.local_path && !l.orphaned)
                else {
                    break 'listing Err("local_path is not a currently linked, live folder".into());
                };
                let files = match context
                    .replica_coordinator
                    .file_index_repository()
                    .list_files_with_kind(&l.group_id)
                {
                    Ok(files) => files,
                    Err(e) => break 'listing Err(format!("failed to list files: {e}")),
                };
                // Only needed to mint/persist a Windows CfAPI
                // generation for entries reported as `Placeholder`
                // below -- looked up once per link, not once per
                // file. `None` (link not currently running) means
                // every such entry's `placeholder_generation` stays
                // unset this poll; `cfapi_host.rs`'s `sync_placeholders`
                // already treats an unset generation as "not yet
                // ready to create, retry next poll", so this degrades
                // to a delayed placeholder creation, never a wrong one.
                let runtime = context.links.runtime(&req.local_path);
                let mut entries = Vec::new();
                for (f, record_kind) in files.into_iter().filter(|(f, _)| !f.deleted) {
                    let materialization_state = match context
                        .replica_coordinator
                        .materialization_state_repository()
                        .get_materialization_state(&l.group_id, &f.path)
                    {
                        Ok(s) => to_shell_materialization_state(s),
                        Err(e) => {
                            break 'listing Err(format!(
                                "failed to read the materialization state of {}: {e}",
                                f.path
                            ));
                        }
                    };
                    let placeholder_generation =
                        if materialization_state == ShellMaterializationState::Placeholder {
                            runtime.as_ref().and_then(|runtime| {
                                match runtime
                                    .ensure_windows_placeholder_generation(&l.group_id, &f.path)
                                {
                                    Ok(generation) => Some(generation),
                                    Err(error) => {
                                        tracing::warn!(
                                            group_id = %l.group_id,
                                            path = %f.path,
                                            error = %error,
                                            "failed to mint/persist a Windows CfAPI \
                                             placeholder generation; cfapi-host will retry \
                                             creating this placeholder next poll"
                                        );
                                        None
                                    }
                                }
                            })
                        } else {
                            None
                        };
                    entries.push(FolderFileEntry {
                        relative_path: f.path,
                        size: f.size,
                        mtime_unix_nanos: f.mtime_unix_nanos,
                        materialization_state: materialization_state as i32,
                        placeholder_generation,
                        kind: shell_entry_kind(record_kind) as i32,
                    });
                }
                Ok(entries)
            };
            let response = match listing {
                Ok(entries) => ListFolderFilesResponse { entries, snapshot_available: true },
                Err(error) => {
                    tracing::warn!(
                        local_path = %req.local_path,
                        %error,
                        "ListFolderFilesRequest could not confirm the folder's listing; \
                         reporting snapshot_available=false rather than an empty listing"
                    );
                    ListFolderFilesResponse { entries: Vec::new(), snapshot_available: false }
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::ListFolderFilesResponse(response)) })
        }
        // The OS virtual-filesystem's own create/modify/delete
        // callback (macOS `NSFileProviderReplicatedExtension`'s
        // `createItem`/`modifyItem`/`deleteItem`) notifies the daemon that a
        // local write already landed on disk. Routes through the same
        // `LocalChangeProcessor::process_event` path a live filesystem
        // watcher's own event would take -- see `shellipc.proto`'s own doc
        // comment on `LocalWriteRequest` and
        // `LinkFlushHandle::capture_local_write`'s own doc for why no
        // File-Provider-specific sync logic exists here.
        Some(Payload::LocalWriteRequest(req)) => {
            let response = 'resolve: {
                let kind = match LocalWriteKind::try_from(req.kind) {
                    Ok(LocalWriteKind::CreatedOrModified) => {
                        yadorilink_filesystem_sync::watcher::FsChangeKind::CreatedOrModified
                    }
                    Ok(LocalWriteKind::Deleted) => {
                        yadorilink_filesystem_sync::watcher::FsChangeKind::Removed
                    }
                    Ok(LocalWriteKind::Unspecified) | Err(_) => {
                        break 'resolve LocalWriteResponse {
                            ok: false,
                            error: "unknown or unspecified write kind".into(),
                        };
                    }
                };
                // An orphaned link's coordination-side authorization is
                // permanently gone -- same exclusion `ListFolderFilesRequest`
                // and `ListOnDemandFoldersRequest` above already apply, for
                // the same reason: this must never accept a File-Provider
                // write for a link that's no longer a live sync target.
                // A read failure is not evidence that the folder is
                // unlinked, so it is reported as what it is.
                let links = match context.replica_coordinator.link_repository().list_links() {
                    Ok(links) => links,
                    Err(e) => {
                        break 'resolve LocalWriteResponse {
                            ok: false,
                            error: format!("could not read the linked folders: {e}"),
                        };
                    }
                };
                let Some(group_id) = links
                    .into_iter()
                    .find(|l| l.local_path == req.local_path && !l.orphaned)
                    .map(|l| l.group_id)
                else {
                    break 'resolve LocalWriteResponse {
                        ok: false,
                        error: "local_path is not a currently linked, live folder".into(),
                    };
                };
                let Some(runtime) = context.links.runtime(&req.local_path) else {
                    break 'resolve LocalWriteResponse {
                        ok: false,
                        error: "link is not currently running".into(),
                    };
                };
                match runtime.capture_local_write(&group_id, &req.relative_path, kind).await {
                    Ok(_) => LocalWriteResponse { ok: true, error: String::new() },
                    Err(e) => LocalWriteResponse { ok: false, error: e },
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::LocalWriteResponse(response)) })
        }
        _ => None, // StatusResponse/StatusPush/ContextActionResponse/... are server->client only
    }
}

#[cfg(test)]
mod item_pause_tests;
#[cfg(test)]
mod list_folder_files_tests;
#[cfg(test)]
mod local_write_tests;

/// Reference client implementation: the shell extension's
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

    /// Windows local IPC support: the Windows counterpart to the `#[cfg(unix)]`
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

    use crate::shell_context::ShellContext;

    pub async fn serve(socket_path: &Path, context: Arc<ShellContext>) -> std::io::Result<()> {
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
            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, write_half) = stream.into_split();
                if let Err(e) = super::handle_connection(read_half, write_half, context).await {
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

/// Windows named-pipe transport (Windows local IPC support: verified
/// against a real Windows 11 VM — see `control_socket::windows_transport`'s
/// doc comment for the concurrent-connection pipe-instance race this
/// structure specifically avoids).
#[cfg(windows)]
pub mod windows_transport {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Semaphore;

    use crate::shell_context::ShellContext;
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
    pub async fn serve(pipe_name: &str, context: Arc<ShellContext>) -> std::io::Result<()> {
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

            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, mut write_half) = tokio::io::split(connected);
                if let Err(e) = super::handle_connection(read_half, &mut write_half, context).await
                {
                    tracing::debug!(error = %e, "shell IPC connection ended");
                }
                let _ = write_half.shutdown().await;
            });
        }
    }
}
