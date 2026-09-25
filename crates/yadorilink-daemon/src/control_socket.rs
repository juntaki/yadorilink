//! CLI ↔ daemon control protocol: one
//! request/response exchange per connection, framed as length-prefixed
//! protobuf (`yadorilink_ipc_proto::framing`) over a Unix domain socket on
//! macOS/Linux, a named pipe on Windows (Windows local IPC support).
//!
//! `handle_connection` is transport-agnostic (any `AsyncRead + AsyncWrite`
//! stream) — unlike `shell_ipc`'s persistent duplex connection, control
//! socket exchanges are a single request then a single response, so no
//! split read/write halves are needed here even on Windows, where a
//! connected named pipe already implements both traits on one handle.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    delete_group_command_response, join_and_link_command_response, mint_invite_command_response,
    remove_device_command_response, revoke_device_command_response, revoke_edge_command_response,
    AcceptInviteCommandResponse, ActiveTransferProgress, ApplicationCommandError,
    ApplicationErrorCode, CheckFullReplicaHandoffReadyExcludingResponse,
    CheckFullReplicaHandoffReadyResponse, ConflictedFileInfo, ConnectionAttemptTrace,
    ConnectivityDoctorCategory, ConnectivityDoctorResponse, CreateAndLinkCommandResponse,
    DaemonControlRequest, DaemonControlResponse, DeleteGroupCommandResponse,
    EnrollmentCommandOutcome, EvictResponse, FetchAvailability, FileVersionInfo, GcResponse,
    GroupDurabilityStatus, HandoffResult, HealthResponse, HeldFile, HydrateResponse,
    InboxFileSummary, InboxTransfer, JoinAndLinkCommandResponse,
    LatchGroupDurabilityUnknownResponse, LimitsSetResponse, LimitsShowResponse, LinkRequest,
    LinkResponse, LinkStatus, ListConflictsResponse, ListConnectionTracesResponse,
    ListInboxResponse, ListLinksResponse, ListQueueItemsResponse, ListRecoveryOperationsResponse,
    ListTrashResponse, ListVersionsResponse, LocalStorageState,
    MaterializationState as WireMaterializationState, MaterializationStatusResponse,
    MembershipHandoffResult, MintInviteCommandResponse, MintedInviteInfo,
    ObtainHandoffTicketResponse, PauseResponse, PeerStatus, PendingEnrollmentKind, PinResponse,
    QueueItem, ReceiveTransferResponse, RecentSyncError, ReleaseHandoffTicketResponse,
    RemoveDeviceCommandResponse, RemovePendingEnrollmentResponse, ReplicaMembershipCommandOutcome,
    ReportingConsentState, ReportingStatusResponse, RequestHandoffLeaseResponse,
    RestoreTrashOperationFailure, RestoreTrashOperationResponse, RestoreTrashResponse,
    RestoreVersionResponse, ResumeResponse, RevokeDeviceCommandResponse, RevokeEdgeCommandResponse,
    RewindActionCounts as WireRewindActionCounts, RewindPathEntry as WireRewindPathEntry,
    RewindPreviewResponse, RewindRenameCandidate as WireRewindRenameCandidate, SendFileResponse,
    SetStorageModeResponse, ShowQueueItemResponse, ShutdownResponse, StatusResponse, TaskLiveness,
    TrashedFileInfo, UnlinkResponse, UnpinResponse, VolumeFreeSpace,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
#[cfg(windows)]
use yadorilink_replica_domain::file::RecordKind;

use crate::reporting_ipc;

const MAX_CONTROL_CONNECTIONS: usize = 64;

async fn handle_connection<S>(
    mut stream: S,
    context: Arc<crate::control_context::ControlContext>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(req) = read_message::<DaemonControlRequest>(&mut stream).await? else { return Ok(()) };
    let resp = handle_request(&context, req).await;
    match write_message(&mut stream, &resp).await {
        // A response too large to frame is refused by `write_message`
        // before any byte reaches the stream, so the connection is still
        // clean and the client can be told what happened instead of seeing
        // the socket close on it. Every response that can grow with the
        // size of a folder is expected to bound itself (see
        // `crate::rewind::trim_for_wire` for the worked case); this is the
        // backstop for one that does not.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            let fallback = DaemonControlResponse {
                daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                payload: Some(RespPayload::Error(format!(
                    "this daemon's answer is too large to send over the control socket \
                     ({error}); narrow the request and try again"
                ))),
            };
            write_message(&mut stream, &fallback).await
        }
        other => other,
    }
}

#[cfg(unix)]
pub mod unix_transport {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixListener;
    use tokio::sync::Semaphore;

    use crate::control_context::ControlContext;

    /// `context` is built exactly once by the caller (in production,
    /// `app.rs` -- the sole composition root; see `ControlContext`'s own
    /// doc comment) and handed down through every connection, never
    /// rebuilt here.
    pub async fn serve(socket_path: &Path, context: Arc<ControlContext>) -> std::io::Result<()> {
        let _ = std::fs::remove_file(socket_path); // clean up a stale socket from a crashed prior run
        prepare_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path)?;
        // This socket accepts unauthenticated Link/Unlink/Pause/Resume/Shutdown
        // requests from anything that can connect to it — restrict to the
        // owning user so another local account can't issue them (defense in
        // depth; the config directory itself should already be private).
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %socket_path.display(), "control socket listening (unix socket)");

        let connection_slots = Arc::new(Semaphore::new(super::MAX_CONTROL_CONNECTIONS));
        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("control socket semaphore closed"))?;
            let (stream, _) = listener.accept().await?;
            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(stream, context).await {
                    tracing::debug!(error = %e, "control connection ended");
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

/// Windows named-pipe transport (Windows local IPC support): verified
/// against a real Windows 11 VM, unlike `shell_ipc`'s windows_transport
/// (written earlier with no Windows machine available to test it).
#[cfg(windows)]
pub mod windows_transport {
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Semaphore;

    use crate::control_context::ControlContext;
    use crate::windows_pipe_security::PipeSecurityAttributes;

    // `PipeSecurityAttributes` holds a raw `*mut c_void` and is therefore
    // `!Send`. Constructing it (and calling `as_mut_ptr` into it) inside a
    // plain, non-async helper function — rather than as a local in `serve`'s
    // async fn body — keeps it entirely out of that fn's generator state, so
    // it can never be "live across an `.await`" no matter how the loop below
    // is restructured. `serve`'s future gets wrapped in an `async move` block
    // and passed to `essential.spawn` (`main.rs`), which requires `Send`;
    // relying on precise drop-tracking to exclude a same-named local from an
    // async fn's generator state proved fragile in practice, this sidesteps
    // the question by never giving the value an async-fn-local home at all.
    // The security descriptor only needs to be valid for the duration of the
    // CreateNamedPipe call itself — the OS copies what it needs into the pipe
    // object — so it's safe to drop at the end of this synchronous helper.
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

    /// `pipe_name` should look like `\\.\pipe\yadorilink-ctl-<user>`.
    ///
    /// Verified against a real Windows 11 VM: an earlier version of this
    /// function created the next pipe instance *after* `connect.await`
    /// returned, leaving a window with zero listening instances between a
    /// client connecting and the replacement instance existing — a second
    /// client connecting concurrently in that window got `ERROR_PIPE_BUSY`
    /// ("All pipe instances are busy"), caught by
    /// `windows_pipe_tests::two_concurrent_clients_are_both_served`.
    /// Creating the next instance *before* awaiting the current one's
    /// `connect` closes that window — there are always at least two
    /// listening instances in existence except right at startup.
    pub async fn serve(pipe_name: &str, context: Arc<ControlContext>) -> std::io::Result<()> {
        tracing::info!(pipe_name, "control socket listening (named pipe)");
        let mut server = create_first_pipe_server(pipe_name)?;
        let connection_slots = Arc::new(Semaphore::new(super::MAX_CONTROL_CONNECTIONS));

        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("control socket semaphore closed"))?;
            let next_server = create_next_pipe_server(pipe_name)?;
            server.connect().await?;
            let connected = server;
            server = next_server;

            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(connected, context).await {
                    tracing::debug!(error = %e, "control connection ended");
                }
            });
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "single exhaustive `match req.payload` dispatch table over every \
              `DaemonControlRequest` payload variant; each arm is one IPC verb's \
              call into an application service plus its response mapping. Kept in \
              one match so the compiler's exhaustiveness check is what proves every \
              wire verb is handled -- splitting it into per-group helpers would \
              require catch-all arms and let a newly added verb compile unhandled."
)]
async fn handle_request(
    context: &crate::control_context::ControlContext,
    req: DaemonControlRequest,
) -> DaemonControlResponse {
    // This repository has not shipped a public release yet, so the CLI,
    // desktop app, and daemon are always built and deployed as one unit —
    // a genuine version skew has no supported recovery path and must fail
    // clearly before touching any daemon state, not be executed anyway and
    // only surface as a mismatch once the CLI inspects the response. Absent
    // on a request that leaves it unset, `protocol_version`
    // decodes as 0, which is `!= CONTROL_PROTOCOL_VERSION` and thus rejected
    // the same as any other mismatch.
    if req.protocol_version != yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION {
        let message =
            if req.protocol_version > yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION {
                format!(
                    "this daemon (protocol version {}) does not support this request (client is \
                 protocol version {}); upgrade the daemon and try again",
                    yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                    req.protocol_version,
                )
            } else {
                format!(
                    "this daemon requires exactly protocol version {} (client is protocol version \
                 {}); this is a pre-release build with no client/daemon compatibility path — run \
                 matching CLI and daemon binaries",
                    yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                    req.protocol_version,
                )
            };
        return DaemonControlResponse {
            payload: Some(RespPayload::Error(message)),
            daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
    }
    let payload = match req.payload {
        Some(ReqPayload::Link(r)) => match decode_link_command(r) {
            Err(message) => RespPayload::Error(message),
            Ok(command) => match context.application.link_lifecycle.link(command).await {
                Ok(_) => RespPayload::Link(LinkResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            },
        },

        Some(ReqPayload::Unlink(r)) => {
            let application = context.application.clone();
            match application.replica_role.unlink(&r.local_path, r.force).await {
                Ok(outcome) => RespPayload::Unlink(UnlinkResponse {
                    handoff_result: outcome.handoff.map(|h| HandoffResult {
                        target_device_id: h.target_device_id,
                        root_digest: h.root_digest.to_vec(),
                        membership_generation: h.membership_generation,
                        lease_id: h.lease_id.unwrap_or_default(),
                    }),
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        Some(ReqPayload::ListLinks(_)) => match context.queries.link_status.list_links() {
            Ok(links) => RespPayload::ListLinks(ListLinksResponse {
                links: links.into_iter().map(encode_link_status).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Pause(r)) => match context.application.pause_resume.pause(&r.local_path) {
            Ok(()) => RespPayload::Pause(PauseResponse {}),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Resume(r)) => {
            match context.application.pause_resume.resume(&r.local_path).await {
                Ok(()) => RespPayload::Resume(ResumeResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // Drops a pending-enrollment marker once `share create`/`share
        // join` has confirmed its own activate call directly -- an
        // optimization over waiting for the next `pending_enrollment::
        // reconcile` sweep to notice the same thing. Always succeeds: a
        // marker that's already gone (this device's own sweep beat the
        // caller to it) is a no-op, matching `remove_pending_enrollment`'s
        // own idempotent delete.
        Some(ReqPayload::RemovePendingEnrollment(r)) => {
            match context.application.enrollment_recovery.acknowledge_activation(&r.operation_id) {
                Ok(()) => RespPayload::RemovePendingEnrollment(RemovePendingEnrollmentResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink versions <path>`.
        Some(ReqPayload::ListVersions(r)) => {
            match context.queries.file_history.list_versions(&r.absolute_path) {
                Ok(Some(versions)) => RespPayload::ListVersions(ListVersionsResponse {
                    versions: versions.into_iter().map(version_to_proto).collect(),
                }),
                Ok(None) => RespPayload::Error("path is not under any linked folder".into()),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink restore <path> [--version <id>]`. An
        // absent `version_seq` resolves to the most recent superseded
        // version (spec "Restore without a version defaults to the most
        // recent superseded version") via `VersionRestoreService`; there
        // being none to restore to is reported as a clear error rather
        // than silently no-op'ing.
        Some(ReqPayload::RestoreVersion(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_version(&group_id, &path, r.version_seq)
                        .await
                    {
                        Ok(true) => RespPayload::RestoreVersion(RestoreVersionResponse {}),
                        Ok(false) => {
                            RespPayload::Error("no superseded version to restore to".into())
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // `yadorilink trash list`. Unlike the per-file requests
        // above, this spans every linked folder at once (no `absolute_path`
        // to resolve) — mirrors `list_link_statuses`'s own per-link
        // iteration below.
        Some(ReqPayload::ListTrash(_)) => match context.queries.file_history.list_trash() {
            Ok(files) => RespPayload::ListTrash(ListTrashResponse {
                files: files.into_iter().map(trashed_file_view_to_proto).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink conflicts list`. Same "spans every linked folder at
        // once" shape as `ListTrash` above.
        Some(ReqPayload::ListConflicts(_)) => match context.queries.file_history.list_conflicts() {
            Ok(files) => RespPayload::ListConflicts(ListConflictsResponse {
                files: files.into_iter().map(conflicted_file_view_to_proto).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // Track Send: `yadorilink send <source_path> <target_device>`.
        Some(ReqPayload::SendFile(r)) => {
            match context.application.send_transfer.send(&r.source_path, &r.target_device).await {
                Ok(outcome) => RespPayload::SendFile(SendFileResponse {
                    transfer_id: outcome.transfer_id,
                    files_offered: outcome.files_offered,
                    total_size: outcome.total_size,
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Track Send: `yadorilink inbox`.
        Some(ReqPayload::ListInbox(_)) => match context.queries.inbox.list() {
            Ok(transfers) => RespPayload::ListInbox(ListInboxResponse {
                transfers: transfers
                    .into_iter()
                    .map(|t| InboxTransfer {
                        transfer_id: t.transfer_id,
                        sender_device_id: t.sender_device_id,
                        files: t
                            .files
                            .into_iter()
                            .map(|(relative_path, size)| InboxFileSummary { relative_path, size })
                            .collect(),
                        total_size: t.total_size,
                        offered_at_unix_nanos: t.offered_at_unix_nanos,
                        status: t.status.to_string(),
                    })
                    .collect(),
            }),
            Err(e) => RespPayload::Error(e),
        },

        // Track Send: `yadorilink receive <transfer_id> [--to <dir>]`.
        Some(ReqPayload::ReceiveTransfer(r)) => {
            let destination_dir =
                if r.destination_dir.is_empty() { None } else { Some(r.destination_dir.as_str()) };
            match context.application.send_transfer.receive(&r.transfer_id, destination_dir).await {
                Ok(outcome) => RespPayload::ReceiveTransfer(ReceiveTransferResponse {
                    destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
                    files_received: outcome.files_received,
                    bytes_received: outcome.bytes_received,
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // `yadorilink trash restore <path>`.
        Some(ReqPayload::RestoreTrash(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_trashed(&group_id, &path)
                        .await
                    {
                        Ok(()) => RespPayload::RestoreTrash(RestoreTrashResponse {}),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // `yadorilink trash restore --folder <path>`.
        Some(ReqPayload::RestoreTrashOperation(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_trashed_operation(&group_id, &path)
                        .await
                    {
                        Ok(outcome) => {
                            RespPayload::RestoreTrashOperation(RestoreTrashOperationResponse {
                                restored_paths: outcome.restored,
                                failed: outcome
                                    .failed
                                    .into_iter()
                                    .map(|(path, error)| RestoreTrashOperationFailure {
                                        path,
                                        error,
                                    })
                                    .collect(),
                                partial: outcome.partial,
                            })
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        Some(ReqPayload::Status(_)) => match context.queries.runtime_status.snapshot() {
            Ok(view) => {
                let mut response = encode_runtime_status(view);
                let (overall_state, attention_reasons) = overall_status(&response);
                response.overall_state = overall_state.as_str().to_string();
                response.attention_reasons = attention_reasons;
                RespPayload::Status(response)
            }
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::LimitsSet(r)) => {
            match context
                .application
                .governance
                .set_limits(r.upload_bytes_per_sec, r.download_bytes_per_sec)
            {
                Ok(limits) => RespPayload::LimitsSet(LimitsSetResponse {
                    upload_bytes_per_sec: limits.upload_bytes_per_sec,
                    download_bytes_per_sec: limits.download_bytes_per_sec,
                }),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::LimitsShow(_)) => {
            let config = context.queries.governance.limits();
            RespPayload::LimitsShow(LimitsShowResponse {
                upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
                download_bytes_per_sec: config.download_limit_bytes_per_sec,
            })
        }

        Some(ReqPayload::Hydrate(r)) => match context.queries.linked_path.resolve(&r.absolute_path)
        {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.hydrate(&group_id, &path).await {
                    Ok(()) => RespPayload::Hydrate(HydrateResponse {}),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Pin(r)) => match context.queries.linked_path.resolve(&r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.pin(&group_id, &path).await {
                    Ok(()) => RespPayload::Pin(PinResponse {}),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Unpin(r)) => match context.queries.linked_path.resolve(&r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.unpin(&group_id, &path).await {
                    Ok(()) => RespPayload::Unpin(UnpinResponse {}),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Evict(r)) => match context.queries.linked_path.resolve(&r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.evict(&group_id, &path) {
                    Ok(outcome) => RespPayload::Evict(EvictResponse {
                        dehydrated: outcome.dehydrated,
                        blocks_reclaimed: outcome.blocks_reclaimed,
                        bytes_reclaimed: outcome.bytes_reclaimed,
                    }),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::MaterializationStatus(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    let application = context.application.clone();
                    match application.materialization.status(&group_id, &path) {
                        Ok(Some(status)) => {
                            RespPayload::MaterializationStatus(MaterializationStatusResponse {
                                known: true,
                                state: materialization_state_to_proto(status.state) as i32,
                                pinned: status.pinned,
                            })
                        }
                        Ok(None) => {
                            RespPayload::MaterializationStatus(MaterializationStatusResponse {
                                known: false,
                                state: WireMaterializationState::Unspecified as i32,
                                pinned: false,
                            })
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        Some(ReqPayload::Shutdown(_)) => {
            tracing::info!("shutdown requested via control socket");
            // route through the same graceful-shutdown path
            // `main.rs` uses for SIGTERM/SIGINT instead of calling
            // `std::process::exit` directly here — that used to skip
            // aborting watcher tasks, draining in-flight broadcasts, and
            // removing socket files. `main.rs`'s top-level `select!` holds
            // the matching receiver and does the actual teardown/exit
            // once it observes this; a `send` error just means every
            // receiver (i.e. `main.rs` itself) is already gone, which
            // only happens if the process is already on its way out.
            context.application.lifecycle.request_shutdown();
            RespPayload::Shutdown(ShutdownResponse {})
        }

        Some(ReqPayload::Health(_)) => {
            RespPayload::Health(encode_health(context.queries.health.snapshot()))
        }

        // Dispatch into `reporting_ipc`, which owns the actual
        // translation to/from `yadorilink_reporting`/`crate::reporting`
        // types.
        Some(ReqPayload::ReportingStatus(_)) => RespPayload::ReportingStatus(
            encode_reporting_status(context.queries.reporting.status()),
        ),
        Some(ReqPayload::GenerateUsageReport(_)) => RespPayload::GenerateUsageReport(
            reporting_ipc::generate_usage_report(&*context.application.reporting),
        ),
        Some(ReqPayload::GenerateLastErrorReport(r)) => {
            match reporting_ipc::generate_last_error_report(
                &*context.application.reporting,
                r.report_id,
            ) {
                Ok(resp) => RespPayload::GenerateLastErrorReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::ListQueueItems(_)) => match context.queries.reporting.list_queue_items() {
            Ok(items) => RespPayload::ListQueueItems(ListQueueItemsResponse {
                items: items.into_iter().map(encode_queue_item).collect(),
            }),
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::ShowQueueItem(r)) => {
            match context.queries.reporting.show_queue_item(&r.report_id) {
                Ok(Some(report_json)) => {
                    RespPayload::ShowQueueItem(ShowQueueItemResponse { report_json })
                }
                Ok(None) => {
                    RespPayload::Error(format!("no queued report found with id `{}`", r.report_id))
                }
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::DeleteQueueItem(r)) => {
            match reporting_ipc::delete_queue_item(&*context.application.reporting, &r.report_id) {
                Ok(resp) => RespPayload::DeleteQueueItem(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::FlushQueue(_)) => {
            match reporting_ipc::flush_queue(&*context.application.reporting) {
                Ok(resp) => RespPayload::FlushQueue(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::SubmitReport(r)) => {
            match reporting_ipc::submit_report(&*context.application.reporting, &r.report_json)
                .await
            {
                Ok(resp) => RespPayload::SubmitReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::UpdateConsent(r)) => {
            match reporting_ipc::update_consent(&*context.application.reporting, r) {
                Ok(resp) => RespPayload::UpdateConsent(resp),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Dispatch into `context.application.update`/`context.queries.
        // update_status`; `update_ipc` only translates to/from the wire
        // types — mirrors `reporting_ipc`'s own dispatch pattern above.
        Some(ReqPayload::UpdateStatus(_)) => RespPayload::UpdateStatus(
            crate::update_ipc::encode_update_status(context.queries.update_status.snapshot()),
        ),
        Some(ReqPayload::UpdateCheck(_)) => {
            context.application.update.check().await;
            RespPayload::UpdateCheck(crate::update_ipc::encode_check_response(
                context.queries.update_status.snapshot(),
            ))
        }
        Some(ReqPayload::UpdateInstall(_)) => match context.application.update.install().await {
            Ok(outcome) => {
                RespPayload::UpdateInstall(crate::update_ipc::encode_install_response(outcome))
            }
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::UpdateConfig(r)) => {
            match context.application.update.config(crate::update_ipc::decode_config_request(r)) {
                Ok(policy) => {
                    RespPayload::UpdateConfig(crate::update_ipc::encode_config_response(policy))
                }
                Err(e) => RespPayload::Error(e),
            }
        }

        // Dispatch into `connection_trace`.
        Some(ReqPayload::ListConnectionTraces(r)) => {
            let peer_device_id =
                (!r.peer_device_id.is_empty()).then_some(r.peer_device_id.as_str());
            let traces = context
                .queries
                .diagnostics
                .recent_connection_traces(peer_device_id)
                .into_iter()
                .map(|trace| ConnectionAttemptTrace {
                    peer_device_id: trace.peer_device_id,
                    candidate_source: trace.candidate_source.to_string(),
                    address_class: trace.address_class.to_string(),
                    outcome: trace.outcome.to_string(),
                    latency_ms: trace.latency_ms,
                    failure_category: trace.failure_category,
                    selected: trace.selected,
                    authorization_decision: trace.authorization_decision.to_string(),
                    recorded_at_unix_nanos: trace.recorded_at_unix_nanos,
                })
                .collect();
            RespPayload::ListConnectionTraces(ListConnectionTracesResponse { traces })
        }

        Some(ReqPayload::ConnectivityDoctor(_)) => {
            let categories = context
                .queries
                .diagnostics
                .connectivity_doctor()
                .into_iter()
                .map(|c| ConnectivityDoctorCategory {
                    name: c.name.to_string(),
                    status: c.status.to_string(),
                    detail: c.detail,
                })
                .collect();
            RespPayload::ConnectivityDoctor(ConnectivityDoctorResponse { categories })
        }

        // Dispatch into `diagnostics_ipc`, which owns the actual bundle
        // assembly (from existing status/config/update/recent-error
        // sources) and the bounded-time-budget handling -- mirrors
        // `reporting_ipc`/`update_ipc`'s own dispatch pattern above.
        // Preview and Export both request the exact same daemon-side
        // bundle; only the CLI-side disposition of the result differs.
        Some(ReqPayload::DiagnosticsPreview(_)) => RespPayload::DiagnosticsPreview(
            crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
        ),
        Some(ReqPayload::DiagnosticsExport(_)) => RespPayload::DiagnosticsExport(
            crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
        ),

        // Dispatch into `gc::run_sweep`, which owns the actual
        // mark-and-sweep, daemon-wide mutual-exclusion, and
        // never-mid-burst logic -- this arm only translates to/from the
        // wire types, mirroring
        // `reporting_ipc`/`update_ipc`/`diagnostics_ipc`'s own dispatch
        // pattern above. `GcTriggerError`'s `Display` (already a clear,
        // actionable message for `AlreadyRunning`/`SyncBurstInProgress`)
        // is surfaced directly as `DaemonControlResponse.error`, same as
        // every other fallible request in this match.
        Some(ReqPayload::Gc(r)) => match context.application.gc.run_sweep(r.dry_run).await {
            Ok(report) => RespPayload::Gc(GcResponse {
                blocks_deleted: report.blocks_deleted,
                bytes_reclaimed: report.bytes_reclaimed,
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink rewind <group> --at <timestamp>`: Folder Rewind's
        // read-only preview. Nothing here mutates anything -- no signed
        // change, no filesystem write, no obligation -- so it goes through
        // `queries`, not `application`, like every other read-only handler.
        Some(ReqPayload::RewindPreview(r)) => {
            match context
                .queries
                .rewind
                .preview(&r.group_id, r.at_unix_nanos, r.include_unchanged)
                .await
            {
                Ok(preview) => RespPayload::RewindPreview(rewind_preview_to_proto(preview)),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // Read-only pre-check for `yadorilink share set-storage-mode`: never
        // mutates anything, local or remote (see
        // `DaemonState::another_full_replica_is_ready`'s doc comment). The
        // authoritative, fail-closed re-check happens again in
        // `SetStorageMode` below, right before the local flip commits.
        Some(ReqPayload::CheckFullReplicaHandoffReady(r)) => {
            RespPayload::CheckFullReplicaHandoffReady(CheckFullReplicaHandoffReadyResponse {
                ready: context.queries.handoff_readiness.ready(&r.group_id).await,
            })
        }

        Some(ReqPayload::SetStorageMode(r)) => {
            let application = context.application.clone();
            match application.replica_role.set_storage_mode(&r.group_id, r.on_demand).await {
                // `root_digest` is this device's own locally-computed
                // durability-root digest at commit time -- never sent to or
                // read back from coordination-worker (see
                // `HandoffCommitResult`'s doc comment), same as
                // `UnlinkResponse`'s construction above.
                Ok(handoff_result) => RespPayload::SetStorageMode(SetStorageModeResponse {
                    handoff_result: handoff_result.map(|(hr, root_digest)| HandoffResult {
                        target_device_id: hr.target_device_id,
                        root_digest: root_digest.to_vec(),
                        membership_generation: hr.membership_generation,
                        lease_id: hr.lease_id.unwrap_or_default(),
                    }),
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Read-only durability pre-check for `yadorilink share revoke`/
        // `yadorilink device remove`, run by the acting device's own daemon
        // BEFORE the CLI ever calls the coordination plane. See
        // `full_replica_handoff_not_ready_excluding`'s doc comment for the
        // empty-`group_id` "every affected group this daemon can see"
        // semantics and the "partial view, not a distributed proof" caveat.
        Some(ReqPayload::CheckFullReplicaHandoffReadyExcluding(r)) => {
            match context
                .queries
                .handoff_readiness
                .not_ready_excluding(&r.group_id, &r.excluded_device_id)
                .await
            {
                Ok(not_ready_group_ids) => RespPayload::CheckFullReplicaHandoffReadyExcluding(
                    CheckFullReplicaHandoffReadyExcludingResponse {
                        ready: not_ready_group_ids.is_empty(),
                        not_ready_group_ids,
                    },
                ),
                Err(e) => RespPayload::Error(format!(
                    "cannot verify full-replica durability because the local link table could not be read: {e}"
                )),
            }
        }

        // Durable post-force durability-status latch for the
        // CLI-orchestrated force paths (`durability_force.rs`'s revoke/
        // device-remove) -- see the request's proto doc comment. Persistence
        // failure is returned rather than acknowledging a latch that would
        // disappear on restart.
        Some(ReqPayload::LatchGroupDurabilityUnknown(r)) => {
            match context.application.durability.latch_group_durability_unknown(&r.group_id) {
                Ok(()) => {
                    RespPayload::LatchGroupDurabilityUnknown(LatchGroupDurabilityUnknownResponse {})
                }
                Err(error) => RespPayload::Error(error.to_string()),
            }
        }

        // Full-replica-handoff lease request (target-side) -- see the
        // request's proto doc comment and `DaemonState::request_handoff_
        // lease` for the local-check-then-coordination-plane-request-then-
        // local-record round trip this drives.
        Some(ReqPayload::RequestHandoffLease(r)) => {
            match context.application.handoff.request_lease(&r.group_id).await {
                Some(grant) => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
                    requested: true,
                    lease_id: grant.lease_id,
                    expires_at_unix: grant.expires_at_unix,
                }),
                None => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
                    requested: false,
                    lease_id: String::new(),
                    expires_at_unix: 0,
                }),
            }
        }

        // Removed-device handoff-ticket request (operating-device-side) --
        // see the request's proto doc comment and `DaemonState::obtain_
        // handoff_ticket_from_device` for the peer round trip (offline/
        // unreachable, timeout, and "the device could not attest its own
        // roots" all collapse to `granted = false` here, matching that
        // method's own doc comment).
        Some(ReqPayload::ObtainHandoffTicket(r)) => {
            match context.application.handoff.obtain_ticket(&r.group_id, &r.device_id).await {
                Some(grant) => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
                    granted: true,
                    lease_id: grant.lease_id,
                    expires_at_unix: grant.expires_at_unix,
                    target_device_id: grant.target_device_id,
                }),
                None => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
                    granted: false,
                    lease_id: String::new(),
                    expires_at_unix: 0,
                    target_device_id: String::new(),
                }),
            }
        }

        Some(ReqPayload::ReleaseHandoffTicket(r)) => {
            context
                .application
                .handoff
                .release_ticket(&r.group_id, &r.device_id, &r.target_device_id, &r.lease_id)
                .await;
            RespPayload::ReleaseHandoffTicket(ReleaseHandoffTicketResponse {})
        }

        Some(ReqPayload::RemoveDeviceCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .membership
                .remove_device(crate::application::RemoveDeviceCommand {
                    device_id: r.device_id,
                    force: r.force,
                })
                .await;
            RespPayload::RemoveDeviceCommand(RemoveDeviceCommandResponse {
                result: Some(match result {
                    Ok(outcome) => remove_device_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => remove_device_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::RevokeDeviceCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .membership
                .revoke_device(crate::application::RevokeDeviceCommand {
                    group_id: r.group_id,
                    device_id: r.device_id,
                    force: r.force,
                })
                .await;
            RespPayload::RevokeDeviceCommand(RevokeDeviceCommandResponse {
                result: Some(match result {
                    Ok(outcome) => revoke_device_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => revoke_device_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::RevokeEdgeCommand(r)) => {
            let application = context.application.clone();
            let result = application.membership.revoke_edge(r.edge_id, r.force).await;
            RespPayload::RevokeEdgeCommand(RevokeEdgeCommandResponse {
                result: Some(match result {
                    Ok(outcome) => revoke_edge_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => revoke_edge_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::DeleteGroupCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .group_admin
                .delete_folder_group(&r.group_id, r.acknowledge_cross_account_members)
                .await;
            RespPayload::DeleteGroupCommand(DeleteGroupCommandResponse {
                result: Some(match result {
                    Ok(()) => delete_group_command_response::Result::Ok(true),
                    Err(error) => delete_group_command_response::Result::Error(error),
                }),
            })
        }

        Some(ReqPayload::CreateAndLinkCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .enrollment
                .create_and_link(crate::application::CreateAndLinkCommand {
                    group_name: r.group_name,
                    absolute_path: r.local_path.into(),
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                })
                .await;
            RespPayload::CreateAndLinkCommand(CreateAndLinkCommandResponse {
                result: Some(match result {
                    Ok(outcome) => create_and_link_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(outcome),
                    ),
                    Err(error) => create_and_link_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::JoinAndLinkCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .enrollment
                .join_and_link(crate::application::JoinAndLinkCommand {
                    group_id: r.group_id,
                    group_name: r.group_name,
                    absolute_path: r.local_path.into(),
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                })
                .await;
            RespPayload::JoinAndLinkCommand(JoinAndLinkCommandResponse {
                result: Some(match result {
                    Ok(outcome) => join_and_link_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(outcome),
                    ),
                    Err(error) => join_and_link_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::AcceptInviteCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .enrollment
                .accept_invite_and_link(crate::application::AcceptInviteCommand {
                    code: r.code,
                    absolute_path: r.local_path.into(),
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                })
                .await;
            RespPayload::AcceptInviteCommand(AcceptInviteCommandResponse {
                result: Some(match result {
                    Ok(outcome) => accept_invite_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(outcome),
                    ),
                    Err(error) => accept_invite_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::MintInviteCommand(r)) => {
            let application = context.application.clone();
            let role = if r.role.is_empty() { None } else { Some(r.role.as_str()) };
            let ttl_secs = if r.ttl_secs == 0 { None } else { Some(r.ttl_secs) };
            let result = application
                .enrollment
                .mint_invite(&r.group_id, role, ttl_secs, r.requires_approval)
                .await;
            RespPayload::MintInviteCommand(MintInviteCommandResponse {
                result: Some(match result {
                    Ok(invite) => mint_invite_command_response::Result::Outcome(MintedInviteInfo {
                        code: invite.code,
                        invite_id: invite.invite_id,
                        group_id: invite.group_id,
                        role: invite.role,
                        expires_at_unix: invite.expires_at_unix,
                        // Echoed from the coordination plane's own response,
                        // never from the request: what the caller renders must
                        // describe the invite that exists.
                        requires_approval: invite.requires_approval,
                    }),
                    Err(detail) => {
                        mint_invite_command_response::Result::Error(ApplicationCommandError {
                            code: ApplicationErrorCode::CoordinationRejected as i32,
                            message: detail,
                            group_ids: Vec::new(),
                            operation_id: String::new(),
                        })
                    }
                }),
            })
        }

        // `yadorilink recovery list`/`show`.
        Some(ReqPayload::ListRecoveryOperations(_)) => match context.queries.recovery.list() {
            Ok(inv) => RespPayload::ListRecoveryOperations(ListRecoveryOperationsResponse {
                operations: inv
                    .valid
                    .iter()
                    .map(crate::recovery_diagnosis::ipc::recovery_summary_to_proto)
                    .collect(),
                invalid: inv
                    .invalid
                    .iter()
                    .map(crate::recovery_diagnosis::ipc::invalid_recovery_operation_to_proto)
                    .collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `show` returns a stable diagnosis (local
        // evidence + exactly one remote lookup + a pure recommendation),
        // not just the local journal row. `domain` is required and
        // unambiguous -- see `ShowRecoveryOperationRequest`'s own doc
        // comment in the proto file.
        Some(ReqPayload::ShowRecoveryOperation(r)) => {
            let Some(domain) =
                yadorilink_replica_domain::recovery::RecoveryDomain::try_from_str(&r.domain)
            else {
                return DaemonControlResponse {
                    payload: Some(RespPayload::Error(format!(
                        "unknown recovery domain {:?}; expected one of \"enrollment\", \
                         \"membership\", \"role-loss\"",
                        r.domain
                    ))),
                    daemon_protocol_version:
                        yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                };
            };
            let key = crate::recovery::RecoveryOperationKey {
                domain,
                operation_id: r.operation_id.clone(),
            };
            match context.queries.recovery.diagnose(&key).await {
                Ok(crate::queries::recovery::DiagnoseOutcome::Diagnosis(outcome)) => {
                    RespPayload::ShowRecoveryOperation(
                        crate::recovery_diagnosis::ipc::stable_diagnosis_outcome_to_proto(&outcome),
                    )
                }
                Ok(crate::queries::recovery::DiagnoseOutcome::CoordinationNotConfigured) => {
                    RespPayload::Error(
                        "coordination-plane address/access token not configured on this device"
                            .to_string(),
                    )
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        None => RespPayload::Error("empty request".to_string()),
    };

    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    }
}

// `classify_link_failure`/`enrollment_link_to_request` live in
// `crate::adapters::runtime::enrollment_link::DaemonEnrollmentLinkAdapter`
// -- `application::EnrollmentService` calls `link()` through that port
// instead of a callback into this module.

fn membership_outcome_to_proto(
    outcome: crate::application::ReplicaMembershipOutcome,
) -> ReplicaMembershipCommandOutcome {
    ReplicaMembershipCommandOutcome {
        handoffs: outcome
            .handoffs
            .into_iter()
            .map(|handoff| MembershipHandoffResult {
                group_id: handoff.group_id,
                target_device_id: handoff.target_device_id,
                lease_id: handoff.lease_id,
                membership_generation: handoff.membership_generation,
            })
            .collect(),
        forced_group_ids: outcome.forced_group_ids,
        unknown_scope_operation_id: outcome.unknown_scope_operation_id.unwrap_or_default(),
    }
}

fn membership_error_to_proto(
    error: crate::application::ReplicaMembershipError,
) -> ApplicationCommandError {
    use crate::application::ReplicaMembershipError as Error;
    let (code, group_ids, operation_id) = match &error {
        Error::LocalIdentityUnavailable => {
            (ApplicationErrorCode::LocalIdentityUnavailable, Vec::new(), String::new())
        }
        Error::TargetNotFound => (ApplicationErrorCode::TargetNotFound, Vec::new(), String::new()),
        Error::ReplicaNotReady { group_ids } => {
            (ApplicationErrorCode::ReplicaNotReady, group_ids.clone(), String::new())
        }
        Error::TicketUnavailable { group_id } => {
            (ApplicationErrorCode::TicketUnavailable, vec![group_id.clone()], String::new())
        }
        Error::CoordinationRejected { .. } => {
            (ApplicationErrorCode::CoordinationRejected, Vec::new(), String::new())
        }
        Error::CoordinationAmbiguous { .. } => {
            (ApplicationErrorCode::CoordinationAmbiguous, Vec::new(), String::new())
        }
        Error::DurabilityLatchFailed { group_ids, .. } => {
            (ApplicationErrorCode::DurabilityLatchFailed, group_ids.clone(), String::new())
        }
        Error::RecoveryPending { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryPending, Vec::new(), operation_id.clone())
        }
        Error::CoordinationTransport { .. } => {
            (ApplicationErrorCode::CoordinationTransport, Vec::new(), String::new())
        }
        Error::Persistence(_) => (ApplicationErrorCode::Persistence, Vec::new(), String::new()),
        Error::OperationConflict { operation_id, .. } => {
            (ApplicationErrorCode::OperationConflict, Vec::new(), operation_id.clone())
        }
        Error::RecoveryJournalUnavailable { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryJournalUnavailable, Vec::new(), operation_id.clone())
        }
    };
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids,
        operation_id,
    }
}

fn enrollment_outcome_to_proto(
    outcome: crate::application::EnrollmentOutcome,
) -> EnrollmentCommandOutcome {
    EnrollmentCommandOutcome {
        operation_id: outcome.operation_id,
        group_id: outcome.group_id,
        local_path: outcome.local_path.to_string_lossy().to_string(),
        awaiting_approval: outcome.awaiting_approval,
        already_linked: outcome.already_linked,
    }
}

fn enrollment_error_to_proto(
    error: crate::application::EnrollmentError,
) -> ApplicationCommandError {
    use crate::application::EnrollmentError as Error;
    let (code, operation_id) = match &error {
        Error::LocalIdentityUnavailable => {
            (ApplicationErrorCode::LocalIdentityUnavailable, String::new())
        }
        Error::RecoveryJournalUnavailable { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryJournalUnavailable, operation_id.clone())
        }
        Error::PreparationRejected { .. } => {
            (ApplicationErrorCode::PreparationRejected, String::new())
        }
        Error::PreparationAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::CoordinationAmbiguous, operation_id.clone())
        }
        Error::LocalLinkFailed { .. } => (ApplicationErrorCode::LocalLinkFailed, String::new()),
        Error::LocalLinkAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryPending, operation_id.clone())
        }
        Error::ActivationRejected { .. } => {
            (ApplicationErrorCode::ActivationRejected, String::new())
        }
        Error::ActivationAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::ActivationAmbiguous, operation_id.clone())
        }
        Error::CompensationPending { operation_id, .. } => {
            (ApplicationErrorCode::CompensationPending, operation_id.clone())
        }
        Error::OperationConflict { operation_id, .. } => {
            (ApplicationErrorCode::OperationConflict, operation_id.clone())
        }
        Error::CoordinationTransport { .. } => {
            (ApplicationErrorCode::CoordinationTransport, String::new())
        }
        Error::Persistence(_) => (ApplicationErrorCode::Persistence, String::new()),
    };
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids: Vec::new(),
        operation_id,
    }
}

/// `LinkRequest` (proto) -> `LinkCommand` (application-owned). All the
/// real orchestration -- duplicate-group prevention, nested-path
/// preflight, the pending-enrollment marker's same-transaction coupling,
/// watcher setup, and rollback-on-setup-failure -- lives in
/// `LinkLifecycleService::link`; this is decode only.
fn decode_link_command(r: LinkRequest) -> Result<crate::application::LinkCommand, String> {
    let pending_enrollment = if r.pending_enrollment_operation_id.is_empty() {
        None
    } else {
        // A request naming a pending enrollment must say which kind. The CLI
        // and the daemon ship as one unit and the protocol version is checked
        // exactly, so an unset or unknown value here is a malformed request,
        // not an older client to accommodate -- and guessing `Create` for a
        // join would attach the link to the wrong enrollment.
        let kind = match PendingEnrollmentKind::try_from(r.pending_enrollment_kind) {
            Ok(PendingEnrollmentKind::Join) => crate::application::EnrollmentKind::Join,
            Ok(PendingEnrollmentKind::Create) => crate::application::EnrollmentKind::Create,
            Ok(PendingEnrollmentKind::Unspecified) | Err(_) => {
                return Err(format!(
                    "link request names pending enrollment {} but no enrollment kind",
                    r.pending_enrollment_operation_id
                ));
            }
        };
        Some(crate::application::PendingEnrollmentLinkCommand {
            operation_id: r.pending_enrollment_operation_id,
            kind,
            device_id: r.pending_enrollment_device_id,
        })
    };
    Ok(crate::application::LinkCommand {
        local_path: r.local_path,
        group_id: r.group_id,
        on_demand: r.on_demand,
        max_local_size_bytes: r.max_local_size_bytes,
        acknowledge_risks: r.acknowledge_risks,
        pending_enrollment,
    })
}

/// `RewindPreview` (daemon) -> `RewindPreviewResponse` (proto).
///
/// A by-field mapping only: the decisions about what the listing carries --
/// the `unchanged` filter and the byte budgets that keep a response inside
/// one frame -- are made in `crate::rewind::trim_for_wire`, which this is
/// handed the result of.
///
/// `RewindPathAction::Unavailable` maps to a distinct `action` string with
/// its own `unavailable_reason`, never to `"unchanged"`: the whole point of
/// that variant is that "this device cannot answer" reaches the person
/// reading the preview as itself.
fn rewind_preview_to_proto(preview: crate::rewind::RewindPreview) -> RewindPreviewResponse {
    use yadorilink_replica_domain::rewind::RewindPathAction;
    RewindPreviewResponse {
        group_id: preview.group_id,
        target_unix_nanos: preview.target_unix_nanos,
        counts: Some(WireRewindActionCounts {
            create: preview.counts.create,
            delete: preview.counts.delete,
            replace: preview.counts.replace,
            unchanged: preview.counts.unchanged,
            unavailable: preview.counts.unavailable,
        }),
        total_entry_count: preview.total_entry_count,
        total_rename_candidate_count: preview.total_rename_candidate_count,
        listing_truncated: preview.listing_truncated,
        entries: preview
            .entries
            .into_iter()
            .map(|entry| {
                let (action, to_version_seq, from_version_seq, unavailable_reason) =
                    match entry.action {
                        RewindPathAction::Create { version_seq, .. } => {
                            ("create", Some(version_seq), None, None)
                        }
                        RewindPathAction::Delete => ("delete", None, None, None),
                        RewindPathAction::Replace { from_version_seq, to_version_seq, .. } => {
                            ("replace", Some(to_version_seq), Some(from_version_seq), None)
                        }
                        RewindPathAction::Unchanged => ("unchanged", None, None, None),
                        RewindPathAction::Unavailable { reason } => {
                            ("unavailable", None, None, Some(reason))
                        }
                    };
                WireRewindPathEntry {
                    path: entry.path,
                    action: action.to_string(),
                    to_version_seq,
                    from_version_seq,
                    unavailable_reason,
                }
            })
            .collect(),
        rename_candidates: preview
            .rename_candidates
            .into_iter()
            .map(|candidate| WireRewindRenameCandidate {
                from_path: candidate.from_path,
                to_path: candidate.to_path,
            })
            .collect(),
    }
}

fn version_to_proto(v: yadorilink_replica_domain::session_state::VersionRecord) -> FileVersionInfo {
    FileVersionInfo {
        version_seq: v.version_seq,
        size: v.size as i64,
        mtime_unix_nanos: v.mtime_unix_nanos,
        state: v.state.as_db_str().to_string(),
        origin_device_id: v.origin_device_id.unwrap_or_default(),
        unix_mode: v.unix_mode,
        kind: entry_kind_to_proto(v.record_kind) as i32,
    }
}

fn entry_kind_to_proto(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_ipc_proto::daemonctl::EntryKind {
    use yadorilink_ipc_proto::daemonctl::EntryKind;
    use yadorilink_replica_domain::file::RecordKind;
    match kind {
        RecordKind::File => EntryKind::File,
        RecordKind::Directory => EntryKind::Directory,
        RecordKind::Symlink => EntryKind::Symlink,
    }
}

/// `queries::reporting::ReportingStatusView` -> `ReportingStatusResponse`
/// (proto).
fn encode_reporting_status(
    view: crate::queries::reporting::ReportingStatusView,
) -> ReportingStatusResponse {
    ReportingStatusResponse {
        consent: Some(ReportingConsentState {
            usage_submission_enabled: view.consent.usage_submission_enabled,
            error_submission_enabled: view.consent.error_submission_enabled,
            prompt_to_report_enabled: view.consent.prompt_to_report_enabled,
            queue_retry_enabled: view.consent.queue_retry_enabled,
            anonymous_reporter_id: view.consent.anonymous_reporter_id,
            endpoint_override: view.consent.endpoint_override,
        }),
        queue_count: view.queue_count,
        error_candidate_count: view.error_candidate_count,
    }
}

/// `queries::reporting::QueueItemView` -> `QueueItem` (proto).
fn encode_queue_item(view: crate::queries::reporting::QueueItemView) -> QueueItem {
    QueueItem {
        report_id: view.report_id,
        report_type: match view.report_type {
            yadorilink_reporting::schema::ReportType::Usage => "usage".to_string(),
            yadorilink_reporting::schema::ReportType::Error => "error".to_string(),
        },
        queued_at: view.queued_at,
        size_bytes: view.size_bytes,
        submit_attempts: view.submit_attempts,
    }
}

/// `queries::file_history::TrashedFileView` -> `TrashedFileInfo` (proto).
fn trashed_file_view_to_proto(
    view: crate::queries::file_history::TrashedFileView,
) -> TrashedFileInfo {
    TrashedFileInfo {
        local_path: view.local_path,
        path: view.trashed.path,
        version_seq: view.trashed.version_seq,
        last_known_size: view.trashed.last_known_size as i64,
        origin_device_id: view.trashed.origin_device_id.unwrap_or_default(),
        deleted_at_unix_nanos: view.trashed.deleted_at_unix_nanos,
        kind: entry_kind_to_proto(view.trashed.record_kind) as i32,
        deleted_by_operation: view
            .trashed
            .deleted_by_operation
            .map(|operation| {
                format!("{}:{}", operation.author.as_str(), operation.operation_id.to_hex())
            })
            .unwrap_or_default(),
    }
}

/// `queries::file_history::ConflictedFileView` -> `ConflictedFileInfo` (proto).
fn conflicted_file_view_to_proto(
    view: crate::queries::file_history::ConflictedFileView,
) -> ConflictedFileInfo {
    ConflictedFileInfo {
        local_path: view.local_path,
        path: view.path,
        size: view.size as i64,
        mtime_unix_nanos: view.mtime_unix_nanos,
        kind: entry_kind_to_proto(view.record_kind) as i32,
        reason: match view.reason {
            crate::queries::file_history::ConflictCopyReason::ConcurrentEdit => {
                yadorilink_ipc_proto::daemonctl::ConflictReason::ConcurrentEdit
            }
            crate::queries::file_history::ConflictCopyReason::FolderAtPath => {
                yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath
            }
        } as i32,
    }
}

/// Maps the daemon's internal reachability into the control-socket wire
/// enums (`PeerStatus.reachability` / `unreachable_category`). The category
/// is `Unspecified` whenever the peer is not unreachable.
///
/// The third element is this connection's `RouteKind` (only meaningful,
/// i.e. non-`Unspecified`, when the reachability itself is `Connected`).
fn reachability_to_proto(
    reachability: crate::peer_registry::PeerReachability,
) -> (
    yadorilink_ipc_proto::daemonctl::PeerReachability,
    yadorilink_ipc_proto::daemonctl::UnreachableCategory,
    yadorilink_ipc_proto::daemonctl::RouteKind,
) {
    use crate::peer_registry::{PeerReachability as Daemon, UnreachableCategory as DaemonCat};
    use yadorilink_ipc_proto::daemonctl::{
        PeerReachability as Wire, RouteKind as WireRoute, UnreachableCategory as WireCat,
    };
    match reachability {
        Daemon::Connecting => (Wire::Connecting, WireCat::Unspecified, WireRoute::Unspecified),
        Daemon::Connected(route) => {
            let wire_route = match route {
                crate::route::RouteKind::Direct => WireRoute::Direct,
                crate::route::RouteKind::Relay => WireRoute::Relay,
            };
            (Wire::Connected, WireCat::Unspecified, wire_route)
        }
        Daemon::Unreachable(category) => {
            let wire_category = match category {
                DaemonCat::NoCandidates => WireCat::NoCandidates,
                DaemonCat::NoResponse => WireCat::NoResponse,
                DaemonCat::UdpBlocked => WireCat::UdpBlocked,
                DaemonCat::HandshakeRefused => WireCat::HandshakeRefused,
            };
            (Wire::Unreachable, wire_category, WireRoute::Unspecified)
        }
    }
}

fn materialization_state_to_proto(
    state: crate::application::ports::MaterializationStateSummary,
) -> WireMaterializationState {
    use crate::application::ports::MaterializationStateSummary as Daemon;
    match state {
        Daemon::Hydrated => WireMaterializationState::Hydrated,
        Daemon::Placeholder => WireMaterializationState::Placeholder,
        Daemon::Hydrating => WireMaterializationState::Hydrating,
        Daemon::Evicting => WireMaterializationState::Evicting,
    }
}

/// Maps the daemon's internal per-group durability status into the
/// control-socket wire enum (`LinkStatus.durability_status`).
fn durability_status_to_proto(
    status: crate::durability_service::GroupDurabilityStatus,
) -> GroupDurabilityStatus {
    use crate::durability_service::GroupDurabilityStatus as Daemon;
    match status {
        Daemon::Protected => GroupDurabilityStatus::Protected,
        Daemon::Protecting => GroupDurabilityStatus::Protecting,
        Daemon::Unknown => GroupDurabilityStatus::Unknown,
        Daemon::AtRisk => GroupDurabilityStatus::AtRisk,
    }
}

/// Projects the evidence axis onto the wire enum. See
/// `DurabilityEvidence`'s own doc comment for why it is an axis rather than
/// more values of the status it accompanies.
fn durability_evidence_to_proto(
    evidence: crate::durability_service::DurabilityEvidence,
) -> yadorilink_ipc_proto::daemonctl::DurabilityEvidence {
    use crate::durability_service::DurabilityEvidence as Domain;
    use yadorilink_ipc_proto::daemonctl::DurabilityEvidence as Wire;
    match evidence {
        Domain::None => Wire::None,
        Domain::CorroboratedIndex => Wire::CorroboratedIndex,
        Domain::VerifiedPayload => Wire::VerifiedPayload,
    }
}

fn local_storage_state_to_proto(
    state: crate::queries::link_status::LocalStorageState,
) -> LocalStorageState {
    use crate::queries::link_status::LocalStorageState as Domain;
    match state {
        Domain::FullCopy => LocalStorageState::FullCopy,
        Domain::PartiallyMaterialized => LocalStorageState::PartiallyMaterialized,
        Domain::OnDemand => LocalStorageState::OnDemand,
    }
}

fn fetch_availability_to_proto(
    availability: crate::queries::link_status::FetchAvailability,
) -> FetchAvailability {
    use crate::queries::link_status::FetchAvailability as Domain;
    match availability {
        Domain::AvailableNow => FetchAvailability::AvailableNow,
        Domain::UnavailableNow => FetchAvailability::UnavailableNow,
        Domain::Unknown => FetchAvailability::Unknown,
    }
}

/// `HealthView` (`crate::queries::health`, DaemonState-independent) -> the
/// IPC wire type.
pub(crate) fn encode_health(view: crate::queries::health::HealthView) -> HealthResponse {
    let tasks = view
        .tasks
        .into_iter()
        .map(|entry| TaskLiveness { name: entry.name, alive: entry.alive })
        .collect();
    HealthResponse { tasks, connected_peer_count: view.connected_peer_count }
}

// Wire conversions for recovery-journal rows/diagnoses now live in
// crate::recovery_diagnosis::ipc, not here -- see that module's own doc
// comment.

/// `RuntimeStatusView` (`crate::queries::runtime_status`, DaemonState-
/// independent) -> the IPC wire type. `overall_state`/`attention_reasons`
/// are left at their zero values -- `overall_status` fills them in from
/// this same response immediately after, so they can never disagree with
/// the rest of the message they summarize.
fn encode_runtime_status(
    view: crate::queries::runtime_status::RuntimeStatusView,
) -> StatusResponse {
    let links = view.links.into_iter().map(encode_link_status).collect();
    let peers = view
        .peers
        .into_iter()
        .map(|peer| {
            let (reachability, category, route_kind) = reachability_to_proto(peer.reachability);
            PeerStatus {
                device_id: peer.device_id,
                reachability: reachability as i32,
                unreachable_category: category as i32,
                route_kind: route_kind as i32,
            }
        })
        .collect();
    let volumes = view
        .volumes
        .into_iter()
        .map(|v| VolumeFreeSpace {
            path: v.path,
            state: v.state,
            available_bytes: v.available_bytes,
            headroom_bytes: v.headroom_bytes,
        })
        .collect();
    let update = crate::update_ipc::encode_update_status(view.update);
    let active_transfers = view
        .active_transfers
        .into_iter()
        .map(|t| ActiveTransferProgress {
            group_id: t.group_id,
            path: t.path,
            bytes_done: t.bytes_done,
            bytes_total: t.bytes_total,
            blocks_done: t.blocks_done,
            blocks_total: t.blocks_total,
            source_peer: t.source_peer,
            started_at_unix: t.started_at_unix,
        })
        .collect();
    let recent_errors = view
        .recent_errors
        .into_iter()
        .map(|e| RecentSyncError {
            category: e.category,
            timestamp_unix: e.timestamp_unix,
            coarse_context: e.coarse_context,
        })
        .collect();
    StatusResponse {
        links,
        peers,
        upload_limit_bytes_per_sec: view.upload_limit_bytes_per_sec,
        download_limit_bytes_per_sec: view.download_limit_bytes_per_sec,
        update_state: update.state,
        update_available_version: update.available_version,
        update_mandatory: update.mandatory,
        update_waiting_for_safe_point: update.waiting_for_safe_point,
        update_last_error_category: update.last_error_category,
        update_channel: update.channel,
        update_install_source: update.install_source,
        update_holdback_reason: update.holdback_reason,
        current_upload_bytes_per_sec: view.current_upload_bytes_per_sec,
        current_download_bytes_per_sec: view.current_download_bytes_per_sec,
        volumes,
        block_store_total_bytes: view.block_store.total_bytes,
        block_store_block_count: view.block_store.block_count,
        last_gc_unix: view.last_gc_unix,
        gc_reclaimable_estimate_bytes: view.gc_reclaimable_estimate_bytes,
        active_transfers,
        recent_errors,
        overall_state: String::new(),
        attention_reasons: Vec::new(),
    }
}

/// `LinkStatusView` (`crate::queries::link_status`, DaemonState-independent)
/// -> the IPC wire type -- the one place this crate is allowed to know
/// both sides.
pub(crate) fn encode_link_status(view: crate::queries::link_status::LinkStatusView) -> LinkStatus {
    let held_files: Vec<HeldFile> = view
        .held_files
        .into_iter()
        .map(|held| HeldFile {
            path: held.path,
            reason: held.reason,
            held_since_unix_nanos: held.held_since_unix_nanos,
        })
        .collect();
    let held_file_count = held_files.len() as u64;
    let durability_status = durability_status_to_proto(view.durability_status);
    let durability_evidence = durability_evidence_to_proto(view.durability_evidence);
    LinkStatus {
        local_path: view.local_path,
        group_id: view.group_id,
        paused: view.paused,
        conflict_count: view.conflict_count,
        materialization_policy: view.materialization_policy,
        hydrated_count: view.hydrated_count,
        placeholder_count: view.placeholder_count,
        hydrating_count: view.hydrating_count,
        held_file_count,
        held_files,
        skipped_symlink_count: view.skipped_symlink_count,
        degraded: view.degraded.is_some(),
        degraded_reason: view.degraded.map(|d| d.reason).unwrap_or_default(),
        // This link's active-transfer rollup -- absent (all zero,
        // `has_active_transfer = false`) when nothing is currently
        // in flight for this link.
        has_active_transfer: view.transfer.is_some(),
        transfer_bytes_done: view.transfer.as_ref().map(|t| t.bytes_done).unwrap_or(0),
        transfer_bytes_total: view.transfer.as_ref().map(|t| t.bytes_total).unwrap_or(0),
        transfer_blocks_done: view.transfer.as_ref().map(|t| t.blocks_done).unwrap_or(0),
        transfer_blocks_total: view.transfer.as_ref().map(|t| t.blocks_total).unwrap_or(0),
        transfer_eta_seconds: view.transfer.and_then(|t| t.eta_seconds).unwrap_or(0),
        durability_status: durability_status as i32,
        durability_evidence: durability_evidence as i32,
        policy_stale: view.policy_stale,
        // A folder group linked at more than one folder refuses to sync
        // entirely (each folder's scan would delete the other's files on
        // every device). The refusal is otherwise only a log line, which is
        // loud in the code and silent in the UI -- this is what makes it
        // visible where the user actually looks, and names every folder
        // involved so the remedy (unlink all but one) is actionable.
        ambiguous: view.ambiguous_local_paths.len() > 1,
        ambiguous_local_paths: view.ambiguous_local_paths,
        local_storage_state: local_storage_state_to_proto(view.local_storage_state) as i32,
        fetch_availability: fetch_availability_to_proto(view.fetch_availability) as i32,
        full_replica_device_ids: view.full_replica_device_ids,
    }
}

/// `StatusResponse.overall_state`'s three values, kept as a small internal
/// enum (rather than juggling raw strings below) purely so the precedence
/// rules below read clearly; the wire format is still the plain lowercase
/// string this converts to via `as_str`, matching every other
/// string-typed status enum in this message
/// (`LinkStatus.materialization_policy`, `VolumeFreeSpace.state`,...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverallState {
    Healthy,
    Attention,
    Degraded,
}

impl OverallState {
    fn as_str(self) -> &'static str {
        match self {
            OverallState::Healthy => "healthy",
            OverallState::Attention => "attention",
            OverallState::Degraded => "degraded",
        }
    }
}

/// Rolls up every already-populated field on `response` into one
/// glanceable `(state, reasons)` pair (spec's "Aggregate Sync Status"/
/// "Sync needs attention" scenarios), computed daemon-side so a UI client
/// (or the CLI) never has to re-derive "is anything wrong?" itself and
/// risk drifting from this definition. Deliberately takes the
/// already-built `StatusResponse` rather than the raw `DaemonState` — this
/// keeps it a pure function over data the caller already has, directly
/// unit-testable with plain struct literals (this file's/`status.rs`'s
/// established discipline), and guarantees the rollup can never disagree
/// with the detail fields sitting right next to it in the same message.
///
/// Precedence (highest first): any link `degraded`, any link whose
/// `durability_status` is `AT_RISK` (a positively-known "no durable copy
/// exists anywhere" fact -- the durability axis's own most severe
/// state), or any volume `state == "critical"` -> `Degraded` (spec: a
/// low-disk condition on a linked folder needs attention; a *critical*
/// one is actively blocking sync, same severity split
/// `VolumeFreeSpace.state`'s own `"low"` vs `"critical"` already draws).
/// Otherwise any conflict, held file, a `"low"` volume, a disconnected
/// peer, a link whose `durability_status` cannot currently be confirmed
/// (`UNKNOWN`/`UNSPECIFIED`) or whose `fetch_availability` is
/// `UNAVAILABLE_NOW`/`UNKNOWN`/`UNSPECIFIED` (an unconfirmed fetch
/// availability must never silently read as `AVAILABLE_NOW` any more than
/// an unconfirmed durability status may silently read as `PROTECTED` --
/// same fail-safe discipline, applied to both axes uniformly), a
/// non-empty recent-error feed, or a recorded update failure ->
/// `Attention`. A merely-`paused` link is *not* by itself
/// attention-worthy (spec's "Sync is healthy" scenario: "caught up or idle
/// *without errors*" says nothing about pause being an error state --
/// pausing is a deliberate user action, matching `status.rs`'s own
/// `held_summary_suffix`-style "only surface what's actionable"
/// discipline). Otherwise `Healthy`, with no reasons.
///
/// Folding in `durability_status`/`fetch_availability` here is required by
/// this function's own doc comment above: it claims the rollup "can never
/// disagree with the detail fields sitting right next to it in the same
/// message," and an earlier version of this function never read those
/// two fields at all -- a group with zero durable copies anywhere
/// (`AtRisk`) could read `Overall: healthy`.
fn overall_status(response: &StatusResponse) -> (OverallState, Vec<String>) {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, GroupDurabilityStatus};

    let mut degraded_reasons = Vec::new();
    let mut attention_reasons = Vec::new();

    for link in &response.links {
        if link.degraded {
            degraded_reasons.push(format!("degraded:{}", link.group_id));
        }
        match link.durability_status() {
            GroupDurabilityStatus::AtRisk => {
                degraded_reasons.push(format!("durability_at_risk:{}", link.group_id));
            }
            GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
                attention_reasons.push(format!("durability_unknown:{}", link.group_id));
            }
            GroupDurabilityStatus::Protected | GroupDurabilityStatus::Protecting => {}
        }
        match link.fetch_availability() {
            FetchAvailability::UnavailableNow => {
                attention_reasons.push(format!("fetch_unavailable:{}", link.group_id));
            }
            FetchAvailability::Unknown | FetchAvailability::Unspecified => {
                attention_reasons.push(format!("fetch_availability_unknown:{}", link.group_id));
            }
            FetchAvailability::AvailableNow => {}
        }
        if link.conflict_count > 0 {
            attention_reasons.push(format!("conflict:{}", link.group_id));
        }
        if link.held_file_count > 0 {
            attention_reasons.push(format!("held:{}", link.group_id));
        }
    }
    for volume in &response.volumes {
        match volume.state.as_str() {
            "critical" => degraded_reasons.push(format!("low_disk_critical:{}", volume.path)),
            "low" => attention_reasons.push(format!("low_disk:{}", volume.path)),
            _ => {}
        }
    }
    for peer in &response.peers {
        // A peer still racing candidates ("connecting") is transient and
        // not yet attention; only one that genuinely cannot be connected is.
        if peer.reachability() == yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable {
            attention_reasons.push(format!("peer_disconnected:{}", peer.device_id));
        }
    }
    for error in &response.recent_errors {
        attention_reasons.push(format!("recent_error:{}", error.category));
    }
    if !response.update_last_error_category.is_empty() {
        attention_reasons.push(format!("update_failed:{}", response.update_last_error_category));
    }

    if !degraded_reasons.is_empty() {
        degraded_reasons.extend(attention_reasons);
        return (OverallState::Degraded, degraded_reasons);
    }
    if !attention_reasons.is_empty() {
        return (OverallState::Attention, attention_reasons);
    }
    (OverallState::Healthy, Vec::new())
}

#[cfg(test)]
mod rewind_preview_wire_tests;

#[cfg(test)]
mod overall_status_tests;

#[cfg(test)]
mod entry_kind_wire_tests;

#[cfg(test)]
mod peer_status_contract_tests;

// --- Control-protocol exact-version enforcement, exercised directly
// against `handle_request` (the actual dispatch a real control-socket
// connection runs through).

#[cfg(test)]
mod migration_safety_tests;
