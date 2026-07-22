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
    ActiveTransferProgress, CheckFullReplicaHandoffReadyExcludingResponse,
    CheckFullReplicaHandoffReadyResponse, ConnectionAttemptTrace, ConnectivityDoctorCategory,
    ConnectivityDoctorResponse, DaemonControlRequest, DaemonControlResponse, EvictResponse,
    FileVersionInfo, GcResponse, GroupDurabilityStatus, HandoffResult, HealthResponse, HeldFile,
    HydrateResponse, LatchGroupDurabilityUnknownResponse, LimitsSetResponse, LimitsShowResponse,
    LinkRequest, LinkResponse, LinkStatus, ListConnectionTracesResponse, ListLinksResponse,
    ListTrashResponse, ListVersionsResponse, ObtainHandoffTicketResponse, PauseResponse,
    PeerStatus, PendingEnrollmentKind, PinResponse, RecentSyncError, ReleaseHandoffTicketResponse,
    RemovePendingEnrollmentResponse, RequestHandoffLeaseResponse, RestoreTrashResponse,
    RestoreVersionResponse, ResumeResponse, SetStorageModeResponse, ShutdownResponse,
    StatusResponse, TaskLiveness, TrashedFileInfo, UnlinkResponse, UnpinResponse, VolumeFreeSpace,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_sync_core::index::SyncState;
#[cfg(windows)]
use yadorilink_sync_core::types::RecordKind;
use yadorilink_sync_core::types::{EnrollmentKind, MaterializationPolicy};

use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::link_manager::{resume_link, start_link_watch, stop_link_watch};
use crate::reporting_ipc;
use crate::shell_status::resolve_group_and_rel_path;

const MAX_CONTROL_CONNECTIONS: usize = 64;

fn demotion_handoff_lease_failure_message() -> String {
    "refusing to drop full-replica status: confirmed a ready replica but could not obtain the \
     required handoff lease (peer unreachable, not caught up, or coordination unavailable); \
     re-run set-storage-mode to retry"
        .to_string()
}

fn unlink_handoff_lease_failure_message(local_path: &str) -> String {
    format!(
        "refusing to unlink {local_path}: confirmed a ready replica but could not obtain the \
         required handoff lease (peer unreachable, not caught up, or coordination unavailable). \
         Re-run unlink to retry, or use --force to unlink anyway (data-loss risk)."
    )
}

async fn handle_connection<S>(mut stream: S, state: Arc<DaemonState>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(req) = read_message::<DaemonControlRequest>(&mut stream).await? else { return Ok(()) };
    let resp = handle_request(&state, req).await;
    write_message(&mut stream, &resp).await
}

#[cfg(unix)]
pub mod unix_transport {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixListener;
    use tokio::sync::Semaphore;

    use crate::daemon_state::DaemonState;

    pub async fn serve(socket_path: &Path, state: Arc<DaemonState>) -> std::io::Result<()> {
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
            let state = state.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(stream, state).await {
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

    use crate::daemon_state::DaemonState;
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
    pub async fn serve(pipe_name: &str, state: Arc<DaemonState>) -> std::io::Result<()> {
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

            let state = state.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(connected, state).await {
                    tracing::debug!(error = %e, "control connection ended");
                }
            });
        }
    }
}

async fn handle_request(
    state: &Arc<DaemonState>,
    req: DaemonControlRequest,
) -> DaemonControlResponse {
    // This repository has not shipped a public release yet, so the CLI,
    // desktop app, and daemon are always built and deployed as one unit —
    // a genuine version skew has no supported recovery path and must fail
    // clearly before touching any daemon state, not be executed anyway and
    // only surface as a mismatch once the CLI inspects the response. Absent
    // on a request from a build that predates this field, `protocol_version`
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
        Some(ReqPayload::Link(r)) => match link(state, r) {
            Ok(()) => RespPayload::Link(LinkResponse {}),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Unlink(r)) => {
            // If this is recovery from a legacy two-live-roots state, persist the
            // survivor's additive-scan protection BEFORE anything can remove the
            // departing link. A crash after the unlink commit must therefore
            // never leave a seemingly healthy one-link group whose first scan
            // tombstones files that only existed under the departed root.
            let ambiguity_recovery = match prepare_ambiguity_recovery(state, &r.local_path) {
                Ok(recovery) => recovery,
                Err(e) => return DaemonControlResponse {
                    payload: Some(RespPayload::Error(e.to_string())),
                    daemon_protocol_version:
                        yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                },
            };
            match ensure_unlink_keeps_a_full_replica(state, &r.local_path, r.force).await {
                Ok(commit) => {
                    stop_link_watch(state, &r.local_path);
                    let (removed, handoff_result) = match commit {
                        UnlinkCommit::AlreadyRemoved(handoff_result) => (Ok(()), handoff_result),
                        UnlinkCommit::RemoveNormally => {
                            (state.sync_state.remove_link(&r.local_path), None)
                        }
                    };
                    if removed.is_ok() {
                        if let Some(recovery) = ambiguity_recovery {
                            if recovery.survivors.len() == 1 {
                                let survivor = recovery.survivors[0].clone();
                                stop_link_watch(state, &survivor);
                                if let Err(e) = start_link_watch(
                                    state.clone(),
                                    survivor.clone(),
                                    recovery.group_id.clone(),
                                ) {
                                    tracing::error!(
                                        group_id = %recovery.group_id,
                                        local_path = %survivor,
                                        error = %e,
                                        "duplicate-root recovery removed the extra link but could not restart the survivor; the group remains fail-closed until a relink or daemon restart"
                                    );
                                }
                            }
                        }
                    }
                    match removed {
                        Ok(()) => RespPayload::Unlink(UnlinkResponse {
                            handoff_result: handoff_result.map(|(hr, root_digest)| HandoffResult {
                                target_device_id: hr.target_device_id,
                                root_digest: root_digest.to_vec(),
                                membership_generation: hr.membership_generation,
                                lease_id: hr.lease_id.unwrap_or_default(),
                            }),
                        }),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                Err(e) => RespPayload::Error(e),
            }
        }

        Some(ReqPayload::ListLinks(_)) => match list_link_statuses(state) {
            Ok(links) => RespPayload::ListLinks(ListLinksResponse { links }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Pause(r)) => match state.sync_state.set_paused(&r.local_path, true) {
            Ok(()) => RespPayload::Pause(PauseResponse {}),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Resume(r)) => match resume_link(state, &r.local_path).await {
            Ok(()) => RespPayload::Resume(ResumeResponse {}),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // Drops a pending-enrollment marker once `share create`/`share
        // join` has confirmed its own activate call directly -- an
        // optimization over waiting for the next `pending_enrollment::
        // reconcile` sweep to notice the same thing. Always succeeds: a
        // marker that's already gone (this device's own sweep beat the
        // caller to it) is a no-op, matching `remove_pending_enrollment`'s
        // own idempotent delete.
        Some(ReqPayload::RemovePendingEnrollment(r)) => {
            match state.sync_state.remove_pending_enrollment(&r.operation_id) {
                Ok(()) => RespPayload::RemovePendingEnrollment(RemovePendingEnrollmentResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink versions <path>`. Resolves the absolute path to
        // `(group_id, relative path)` via the same
        // `resolve_group_and_rel_path` helper `Hydrate`/`Pin`/`Unpin`/
        // `Evict` above already use.
        Some(ReqPayload::ListVersions(r)) => {
            match resolve_group_and_rel_path(state, &r.absolute_path) {
                Some((group_id, path)) => match state.sync_state.list_versions(&group_id, &path) {
                    Ok(versions) => RespPayload::ListVersions(ListVersionsResponse {
                        versions: versions.into_iter().map(version_to_proto).collect(),
                    }),
                    Err(e) => RespPayload::Error(e.to_string()),
                },
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // `yadorilink restore <path> [--version <id>]`. An
        // absent `version_seq` resolves to the most recent superseded
        // version (spec "Restore without a version defaults to the most
        // recent superseded version") via `hydration::most_recent_superseded_
        // version_seq`; there being none to restore to is reported as a
        // clear error rather than silently no-op'ing.
        Some(ReqPayload::RestoreVersion(r)) => {
            match resolve_group_and_rel_path(state, &r.absolute_path) {
                Some((group_id, path)) => {
                    let version_seq = match r.version_seq {
                        Some(v) => Ok(Some(v)),
                        None => {
                            hydration::most_recent_superseded_version_seq(state, &group_id, &path)
                        }
                    };
                    match version_seq {
                        Ok(Some(version_seq)) => {
                            match hydration::restore_to_version(
                                state,
                                &group_id,
                                &path,
                                version_seq,
                            )
                            .await
                            {
                                Ok(()) => RespPayload::RestoreVersion(RestoreVersionResponse {}),
                                Err(e) => RespPayload::Error(e.to_string()),
                            }
                        }
                        Ok(None) => {
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
        Some(ReqPayload::ListTrash(_)) => match list_trashed_files(state) {
            Ok(files) => RespPayload::ListTrash(ListTrashResponse { files }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink trash restore <path>`.
        Some(ReqPayload::RestoreTrash(r)) => {
            match resolve_group_and_rel_path(state, &r.absolute_path) {
                Some((group_id, path)) => {
                    match hydration::restore_trashed(state, &group_id, &path).await {
                        Ok(()) => RespPayload::RestoreTrash(RestoreTrashResponse {}),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        Some(ReqPayload::Status(_)) => match list_link_statuses(state) {
            Ok(links) => {
                let peer_snapshots: Vec<_> = state
                    .peer_statuses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .map(|(device_id, info)| (device_id.clone(), info.reachability))
                    .collect();
                let sessions =
                    state.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let peers = peer_snapshots
                    .into_iter()
                    .map(|(device_id, mut reachability)| {
                        if reachability == crate::daemon_state::PeerReachability::Connected
                            && sessions.get(&device_id).is_some_and(|session| {
                                session.peer_handshake_received()
                                    && !session.change_dag_negotiated()
                            })
                        {
                            reachability =
                                crate::daemon_state::PeerReachability::ProtocolIncompatible;
                        }
                        // A peer is reachable or honestly cannot be connected
                        // (with the reason), reported solely via `reachability`.
                        let (reachability, category) = reachability_to_proto(reachability);
                        PeerStatus {
                            device_id,
                            reachability: reachability as i32,
                            unreachable_category: category as i32,
                        }
                    })
                    .collect();
                // Configured limits + current measured rates (from the
                // shared `rate_limiters` every session/hydration fetch
                // draws down) and per-volume free-space state, alongside
                // the existing per-folder/per-peer status above.
                let governance = state.governance_config.load_or_default();
                let volumes = volumes_free_space(state, &links);
                // Concise update state embedded directly in
                // `StatusResponse` — reuses `update_ipc::status_response`'s
                // exact field values rather than re-deriving them a
                // second way.
                let update_status = crate::update_ipc::status_response(state);
                // O(1) usage counters — never a directory walk on a
                // `status` call.
                let block_store_usage = state.block_store.usage().unwrap_or_default();
                let mut response = StatusResponse {
                    links,
                    peers,
                    upload_limit_bytes_per_sec: governance.upload_limit_bytes_per_sec,
                    download_limit_bytes_per_sec: governance.download_limit_bytes_per_sec,
                    update_state: update_status.state,
                    update_available_version: update_status.available_version,
                    update_mandatory: update_status.mandatory,
                    update_waiting_for_safe_point: update_status.waiting_for_safe_point,
                    update_last_error_category: update_status.last_error_category,
                    update_channel: update_status.channel,
                    update_install_source: update_status.install_source,
                    update_holdback_reason: update_status.holdback_reason,
                    current_upload_bytes_per_sec: state
                        .rate_limiters
                        .upload
                        .current_rate_bytes_per_sec(),
                    current_download_bytes_per_sec: state
                        .rate_limiters
                        .download
                        .current_rate_bytes_per_sec(),
                    volumes,
                    // Block-store usage (O(1) counters) and GC health,
                    // alongside every other status surface above.
                    block_store_total_bytes: block_store_usage.total_bytes,
                    block_store_block_count: block_store_usage.block_count,
                    last_gc_unix: state.gc.last_run_unix(),
                    gc_reclaimable_estimate_bytes: state.gc.reclaimable_estimate_bytes(),
                    // Every currently-active transfer and the bounded
                    // recent-error feed, alongside every other status
                    // surface above.
                    active_transfers: state
                        .transfer_progress
                        .snapshot()
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
                        .collect(),
                    recent_errors: state
                        .recent_errors
                        .recent()
                        .into_iter()
                        .map(|e| RecentSyncError {
                            category: e.category.to_string(),
                            timestamp_unix: e.timestamp_unix,
                            coarse_context: e.coarse_context,
                        })
                        .collect(),
                    // Filled in below, from `response`'s own
                    // already-populated fields, so this rollup can never
                    // disagree with the rest of the message it's
                    // summarizing.
                    overall_state: String::new(),
                    attention_reasons: Vec::new(),
                };
                let (overall_state, attention_reasons) = overall_status(&response);
                response.overall_state = overall_state.as_str().to_string();
                response.attention_reasons = attention_reasons;
                RespPayload::Status(response)
            }
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::LimitsSet(r)) => {
            match state
                .governance_config
                .set_limits(r.upload_bytes_per_sec, r.download_bytes_per_sec)
            {
                Ok(config) => {
                    // apply immediately to the running daemon's
                    // shared buckets, not just persist to disk — a
                    // `limits set` takes effect without a restart.
                    state.apply_governance_config();
                    RespPayload::LimitsSet(LimitsSetResponse {
                        upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
                        download_bytes_per_sec: config.download_limit_bytes_per_sec,
                    })
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::LimitsShow(_)) => {
            let config = state.governance_config.load_or_default();
            RespPayload::LimitsShow(LimitsShowResponse {
                upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
                download_bytes_per_sec: config.download_limit_bytes_per_sec,
            })
        }

        Some(ReqPayload::Hydrate(r)) => match resolve_group_and_rel_path(state, &r.absolute_path) {
            Some((group_id, path)) => match hydration::hydrate(state, &group_id, &path).await {
                Ok(()) => RespPayload::Hydrate(HydrateResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            },
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Pin(r)) => match resolve_group_and_rel_path(state, &r.absolute_path) {
            Some((group_id, path)) => match hydration::pin(state, &group_id, &path).await {
                Ok(()) => RespPayload::Pin(PinResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            },
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Unpin(r)) => match resolve_group_and_rel_path(state, &r.absolute_path) {
            Some((group_id, path)) => match hydration::unpin(state, &group_id, &path).await {
                Ok(()) => RespPayload::Unpin(UnpinResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            },
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Evict(r)) => match resolve_group_and_rel_path(state, &r.absolute_path) {
            Some((group_id, path)) => match hydration::evict(state, &group_id, &path) {
                Ok(()) => RespPayload::Evict(EvictResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            },
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

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
            let _ = state.shutdown_tx.send(true);
            RespPayload::Shutdown(ShutdownResponse {})
        }

        Some(ReqPayload::Health(_)) => RespPayload::Health(health_snapshot(state)),

        // Dispatch into `reporting_ipc`, which owns the actual
        // translation to/from `yadorilink_reporting`/`crate::reporting`
        // types.
        Some(ReqPayload::ReportingStatus(_)) => {
            RespPayload::ReportingStatus(reporting_ipc::reporting_status(state))
        }
        Some(ReqPayload::GenerateUsageReport(_)) => {
            RespPayload::GenerateUsageReport(reporting_ipc::generate_usage_report(state))
        }
        Some(ReqPayload::GenerateLastErrorReport(r)) => {
            match reporting_ipc::generate_last_error_report(state, r.report_id) {
                Ok(resp) => RespPayload::GenerateLastErrorReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::ListQueueItems(_)) => match reporting_ipc::list_queue_items(state) {
            Ok(resp) => RespPayload::ListQueueItems(resp),
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::ShowQueueItem(r)) => {
            match reporting_ipc::show_queue_item(state, &r.report_id) {
                Ok(resp) => RespPayload::ShowQueueItem(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::DeleteQueueItem(r)) => {
            match reporting_ipc::delete_queue_item(state, &r.report_id) {
                Ok(resp) => RespPayload::DeleteQueueItem(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::FlushQueue(_)) => match reporting_ipc::flush_queue(state) {
            Ok(resp) => RespPayload::FlushQueue(resp),
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::SubmitReport(r)) => {
            match reporting_ipc::submit_report(state, &r.report_json).await {
                Ok(resp) => RespPayload::SubmitReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::UpdateConsent(r)) => match reporting_ipc::update_consent(state, r) {
            Ok(resp) => RespPayload::UpdateConsent(resp),
            Err(e) => RespPayload::Error(e),
        },

        // Dispatch into `update_ipc`, which owns the actual translation
        // to/from `crate::update::{manager, policy}` types — mirrors
        // `reporting_ipc`'s own dispatch pattern immediately above.
        Some(ReqPayload::UpdateStatus(_)) => {
            RespPayload::UpdateStatus(crate::update_ipc::status_response(state))
        }
        Some(ReqPayload::UpdateCheck(_)) => {
            RespPayload::UpdateCheck(crate::update_ipc::check(state).await)
        }
        Some(ReqPayload::UpdateInstall(_)) => match crate::update_ipc::install(state).await {
            Ok(resp) => RespPayload::UpdateInstall(resp),
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::UpdateConfig(r)) => match crate::update_ipc::config(state, r) {
            Ok(resp) => RespPayload::UpdateConfig(resp),
            Err(e) => RespPayload::Error(e),
        },

        // Dispatch into `connection_trace`.
        Some(ReqPayload::ListConnectionTraces(r)) => {
            let peer_device_id =
                (!r.peer_device_id.is_empty()).then_some(r.peer_device_id.as_str());
            let traces = state
                .connection_traces
                .recent(peer_device_id)
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
            let categories = crate::connection_trace::run_connectivity_doctor(state)
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
        Some(ReqPayload::DiagnosticsPreview(_)) => {
            RespPayload::DiagnosticsPreview(crate::diagnostics_ipc::build_bundle(state).await)
        }
        Some(ReqPayload::DiagnosticsExport(_)) => {
            RespPayload::DiagnosticsExport(crate::diagnostics_ipc::build_bundle(state).await)
        }

        // Dispatch into `gc::run_sweep`, which owns the actual
        // mark-and-sweep, daemon-wide mutual-exclusion, and
        // never-mid-burst logic -- this arm only translates to/from the
        // wire types, mirroring
        // `reporting_ipc`/`update_ipc`/`diagnostics_ipc`'s own dispatch
        // pattern above. `GcTriggerError`'s `Display` (already a clear,
        // actionable message for `AlreadyRunning`/`SyncBurstInProgress`)
        // is surfaced directly as `DaemonControlResponse.error`, same as
        // every other fallible request in this match.
        Some(ReqPayload::Gc(r)) => match crate::gc::run_sweep(state.clone(), r.dry_run).await {
            Ok(report) => RespPayload::Gc(GcResponse {
                blocks_deleted: report.blocks_deleted,
                bytes_reclaimed: report.bytes_reclaimed,
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // Read-only pre-check for `yadorilink share set-storage-mode`: never
        // mutates anything, local or remote (see
        // `DaemonState::another_full_replica_is_ready`'s doc comment). The
        // authoritative, fail-closed re-check happens again in
        // `SetStorageMode` below, right before the local flip commits.
        Some(ReqPayload::CheckFullReplicaHandoffReady(r)) => {
            RespPayload::CheckFullReplicaHandoffReady(CheckFullReplicaHandoffReadyResponse {
                ready: state.another_full_replica_is_ready(&r.group_id).await,
            })
        }

        Some(ReqPayload::SetStorageMode(r)) => {
            match set_storage_mode(state, &r.group_id, r.on_demand).await {
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
            match full_replica_handoff_not_ready_excluding(
                state,
                &r.group_id,
                &r.excluded_device_id,
            )
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
            match state.latch_group_durability_unknown(&r.group_id) {
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
            match state.request_handoff_lease(&r.group_id).await {
                Some((grant, _root_digest)) => {
                    RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
                        requested: true,
                        lease_id: grant.lease_id,
                        expires_at_unix: grant.expires_at_unix,
                    })
                }
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
            match state.obtain_handoff_ticket_from_device(&r.group_id, &r.device_id).await {
                Some(grant) => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
                    granted: true,
                    lease_id: grant.lease_id.unwrap_or_default(),
                    expires_at_unix: grant.expires_at_unix,
                    target_device_id: grant.target_device_id.unwrap_or_default(),
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
            state
                .release_handoff_ticket_from_device(
                    &r.group_id,
                    &r.device_id,
                    &r.target_device_id,
                    &r.lease_id,
                )
                .await;
            RespPayload::ReleaseHandoffTicket(ReleaseHandoffTicketResponse {})
        }

        None => RespPayload::Error("empty request".to_string()),
    };

    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    }
}

/// Registers a new link, plus on-demand-sync's materialization
/// policy/cap — set *after* `add_link` so the row those setters
/// update-by-`local_path` already exists; `start_link_watch` itself
/// doesn't depend on the ordering (it never queries the links table for
/// the path it's given directly).
///
/// Defense-in-depth re-check, independent of whatever the CLI already
/// showed/gated. Scoped to
/// nested-link conflicts specifically (an already-linked folder that is an
/// ancestor, descendant, or exact match of `r.local_path`) rather than the
/// full preflight (non-empty folder, low disk space, risky location) --
/// those are deliberately CLI-layer UX guardrails the user already sees
/// and confirms/`--yes`es *before* a `LinkRequest` is ever sent (see
/// `commands::link::link`), whereas an overlapping link is a genuine
/// correctness hazard (two watchers racing over the same files) that this
/// daemon is the sole authority on, since it alone knows every existing
/// link's `local_path` -- worth rejecting here even if some future/'raw'
/// caller bypassed the CLI's own gate entirely.
///
/// That authority is over PATHS. It is not the authority on which GROUP a
/// folder belongs to: the one-live-link-per-group invariant is enforced in
/// `SyncState::insert_link_row`, atomically with the insert, because a check
/// out here cannot share the insert's transaction and so is a TOCTOU window
/// between two concurrent `link` calls. The check below is an early, clearer
/// refusal, not the guarantee.
fn link(state: &Arc<DaemonState>, r: LinkRequest) -> Result<(), crate::error::DaemonError> {
    // Deliberately NOT routed through `run_preflight`/`nested_conflicts`: that
    // branch is gated on `!r.acknowledge_risks`, i.e. `--yes` waves it through.
    // Path overlaps are warnings a user may knowingly accept; a second live root
    // on one group is not acceptable at any confirmation level, because each
    // root's scan tombstones the other's files on every device.
    //
    // `any(|p| p != &r.local_path)` rather than `!is_empty()`: re-linking the
    // SAME folder to the same group is idempotent and must stay allowed -- it is
    // exactly what a `share join` retry does after a failed link's rollback.
    let live_for_group = state.sync_state.live_link_paths_for_group(&r.group_id)?;
    if live_for_group.iter().any(|p| p != &r.local_path) {
        return Err(crate::error::DaemonError::Config(format!(
            "folder group {} is already linked at {}; a folder group can only be linked to one \
             folder on a device -- two would make each folder's scan delete the other's files on \
             every device. Unlink the other folder first, or link this folder to a different group",
            r.group_id,
            live_for_group.join(", ")
        )));
    }
    let existing_paths: Vec<String> =
        state.sync_state.list_links()?.into_iter().map(|l| l.local_path).collect();
    let preflight = yadorilink_sync_core::link_preflight::run_preflight(
        std::path::Path::new(&r.local_path),
        &existing_paths,
        None,
    );
    if !preflight.nested_conflicts.is_empty() && !r.acknowledge_risks {
        let conflict_summary = preflight
            .nested_conflicts
            .iter()
            .map(|c| match c.relation {
                yadorilink_sync_core::link_preflight::NestedLinkRelation::Ancestor => {
                    format!("{} is already linked and is an ancestor of this folder", c.other_path)
                }
                yadorilink_sync_core::link_preflight::NestedLinkRelation::Descendant => {
                    format!("{} is already linked and is nested inside this folder", c.other_path)
                }
                yadorilink_sync_core::link_preflight::NestedLinkRelation::Same => {
                    format!("{} is already linked", c.other_path)
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(crate::error::DaemonError::Config(format!(
            "link preflight rejected (nested-link conflict): {conflict_summary} -- re-run with acknowledge_risks/--yes to proceed"
        )));
    }
    // An empty operation id means "plain `link`, nothing to track" -- the
    // common case and the only one a pre-existing caller (a CLI build that
    // predates this field) ever sends. `share create`/`share join` set it,
    // so the daemon can write the pending-enrollment marker in the same
    // SQLite transaction as the link itself: if that write fails, the link
    // is never created either, and the caller's own enroll operation can
    // abort cleanly with no local trace at all (see
    // `SyncState::add_link_with_pending_enrollment`'s doc comment for why
    // the ordering matters).
    if r.pending_enrollment_operation_id.is_empty() {
        state.sync_state.add_link(&r.local_path, &r.group_id)?;
    } else {
        let kind = match PendingEnrollmentKind::try_from(r.pending_enrollment_kind)
            .unwrap_or(PendingEnrollmentKind::Unspecified)
        {
            PendingEnrollmentKind::Join => EnrollmentKind::Join,
            // `Create` and the (never expected, given a non-empty operation
            // id) `Unspecified` case both default to `Create` -- matching
            // `EnrollmentKind::from_db_str`'s own lenient fallback.
            PendingEnrollmentKind::Create | PendingEnrollmentKind::Unspecified => {
                EnrollmentKind::Create
            }
        };
        state.sync_state.add_link_with_pending_enrollment(
            &r.local_path,
            &r.group_id,
            &yadorilink_sync_core::index::PendingEnrollment {
                operation_id: r.pending_enrollment_operation_id.clone(),
                kind,
                group_id: r.group_id.clone(),
                device_id: r.pending_enrollment_device_id.clone(),
                local_path: r.local_path.clone(),
            },
        )?;
    }
    // From here on the link (and, if `pending_enrollment_operation_id` was
    // set, its pending-enrollment marker) is durably committed. Every
    // caller of this whole function treats any `Err` it returns as "nothing
    // was created" (the CLI's `share create`/`share join` compensate only
    // the coordination-plane side on failure -- see
    // `commands::share::create_and_link`'s doc comment), so a failure past
    // this point must roll the just-committed row(s) back rather than
    // return `Err` with local state left behind. `start_link_watch`'s own
    // fallible steps (loading the ignore set, binding the OS watcher) run
    // before it registers anything in `DaemonState`'s in-memory maps, so
    // there is no in-memory watcher state to unwind here, only the two
    // SQLite rows above.
    if let Err(e) = finish_link_setup(state, &r) {
        // The rollback itself is best-effort against the same SQLite
        // database the commit above just used, so it is expected to
        // succeed in practice -- but it is not guaranteed to (e.g. a
        // concurrent `SQLITE_BUSY`/`SQLITE_LOCKED` that outlasts the pool's
        // own retry budget). A rollback failure must never be silently
        // swallowed: the caller is about to be told the whole link setup
        // failed and to treat nothing as created, so a link/marker that is
        // actually still committed underneath that would be a live,
        // reconcile-eligible link this device's own logs are the only
        // record of.
        // The link and (if set) its marker were committed together; roll them
        // back together in one transaction so a mid-rollback failure can never
        // leave the DB with a marker naming a path whose link is already gone
        // (a half-state a later reconciliation would have to untangle). When
        // there is no marker, the plain single-row `remove_link` is enough.
        let mut rollback_ok = true;
        let rollback_result = if r.pending_enrollment_operation_id.is_empty() {
            state.sync_state.remove_link(&r.local_path)
        } else {
            state
                .sync_state
                .remove_link_and_pending_marker(&r.local_path, &r.pending_enrollment_operation_id)
        };
        if let Err(rollback_err) = rollback_result {
            rollback_ok = false;
            tracing::error!(
                error = %rollback_err,
                local_path = %r.local_path,
                operation_id = %r.pending_enrollment_operation_id,
                "failed to roll back a link (and its pending-enrollment marker, if any) after \
                 its post-commit setup failed -- this local link may still be committed even \
                 though link setup is being reported as failed"
            );
        }
        return Err(if rollback_ok {
            e
        } else {
            crate::error::DaemonError::Config(format!(
                "link setup failed ({e}), and rolling back the partially-committed local state \
                 also failed -- this device's local link state may now be inconsistent with \
                 what was reported; check the daemon log and run `yadorilink link list` to \
                 verify before retrying"
            ))
        });
    }
    Ok(())
}

/// The fallible steps of registering a link that run after the link (and
/// pending-enrollment marker) row(s) are already committed -- split out so
/// `link` above can roll both back together on any failure here, instead of
/// leaving a phantom local link (and, worse, an orphaned-looking
/// pending-enrollment row nothing will ever resolve) behind.
fn finish_link_setup(
    state: &Arc<DaemonState>,
    r: &LinkRequest,
) -> Result<(), crate::error::DaemonError> {
    if r.on_demand {
        state
            .sync_state
            .set_materialization_policy(&r.local_path, MaterializationPolicy::OnDemand)?;
        if let Some(max_bytes) = r.max_local_size_bytes {
            state.sync_state.set_max_local_size_bytes(&r.local_path, Some(max_bytes))?;
        }
    }
    // Retention is a fixed built-in policy (10 versions / 30 days) applied to
    // every link, so there is nothing per-link to configure here.
    start_link_watch(state.clone(), r.local_path.clone(), r.group_id.clone())?;
    Ok(())
}

/// `VersionRecord` (sync-core) -> `FileVersionInfo` (proto) — mirrors
/// `LinkStatus`'s own by-field mapping pattern from `yadorilink_sync_core`
/// types elsewhere in this file.
fn version_to_proto(v: yadorilink_sync_core::index::VersionRecord) -> FileVersionInfo {
    FileVersionInfo {
        version_seq: v.version_seq,
        size: v.size as i64,
        mtime_unix_nanos: v.mtime_unix_nanos,
        state: v.state.as_db_str().to_string(),
        origin_device_id: v.origin_device_id.unwrap_or_default(),
    }
}

#[derive(Debug)]
struct AmbiguityRecovery {
    group_id: String,
    survivors: Vec<String>,
}

fn prepare_ambiguity_recovery(
    state: &DaemonState,
    local_path: &str,
) -> Result<Option<AmbiguityRecovery>, yadorilink_sync_core::SyncError> {
    let links = state.sync_state.list_links()?;
    let Some(target) = links.iter().find(|l| l.local_path == local_path) else {
        return Ok(None);
    };
    let group_id = target.group_id.clone();
    let live_paths: Vec<String> = links
        .iter()
        .filter(|l| l.group_id == group_id && !l.orphaned)
        .map(|l| l.local_path.clone())
        .collect();
    if live_paths.len() < 2 {
        return Ok(None);
    }

    let survivors: Vec<String> = live_paths.into_iter().filter(|path| path != local_path).collect();

    state.sync_state.arm_duplicate_recovery_paths(&group_id)?;
    for survivor in &survivors {
        state.sync_state.set_suppress_tombstones(survivor, true)?;
    }

    Ok(Some(AmbiguityRecovery { group_id, survivors }))
}

/// The local link's path for `group_id`, if this device has one — the
/// reverse of every other lookup in this file (which resolve a `local_path`
/// forward to a `group_id`), needed here because [`SetStorageModeRequest`]
/// carries only the group id (like the Worker's own storage-mode route),
/// while `SyncState::set_materialization_policy` is keyed by `local_path`.
///
/// Returns `Result` rather than `Option`: the old `.ok()?` collapsed a failed
/// link-table read into "this device has no link for that group", so a database
/// error read as a routine absence. A group with two live links is likewise an
/// error here, not a coin flip between two folders.
fn local_path_for_group(
    state: &DaemonState,
    group_id: &str,
) -> Result<Option<String>, yadorilink_sync_core::SyncError> {
    state.sync_state.live_link_local_path_for_group(group_id)
}

/// Orchestrates `yadorilink share set-storage-mode`: the SOLE place that
/// commits BOTH the coordination-plane record of this device's storage mode
/// for `group_id` AND the local materialization-policy flip between eager
/// (full replica) and on-demand (cache) — the CLI (`commands::share::
/// set_storage_mode`) only asks for the change and prints this function's
/// result; it makes no coordination-plane call of its own and has nothing to
/// compensate.
///
/// Demoting FROM eager (`on_demand = true`) is refused, fail-closed, unless
/// [`DaemonState::another_full_replica_is_ready`] confirms some other full
/// replica durably holds the current version of every file in the group —
/// without central storage, a full replica is the only durable copy, so
/// giving one up before a confirmed handoff risks permanent data loss. This
/// re-checks readiness itself rather than trusting any earlier check the
/// caller may have already done (e.g. `CheckFullReplicaHandoffReady`), since
/// that is the only check in this whole path that is actually authoritative
/// at the moment local policy commits.
///
/// Promoting TO eager (`on_demand = false`) has no such hazard — gaining a
/// durable copy is always safe — and is applied unconditionally; this
/// direction is intentionally minimal (no readiness preflight, no backfill
/// orchestration) since the corrected custody/hydration paths already bring
/// an eager link's placeholders down over time.
///
/// Ordering, and why it is crash-safe either way. For a DEMOTION, when a real
/// confirming peer is named and this device has coordination-plane config
/// recorded (production, a logged-in registered device — see
/// [`DaemonState::coordination_client_config`]), a live lease is now
/// MANDATORY: this device asks the confirmed peer directly, over the
/// authenticated peer channel, to verify and pin its own durability-root set
/// and hand back a lease naming it
/// ([`DaemonState::obtain_handoff_lease_from_peer`]), refusing outright if no
/// live lease can be obtained (peer unreachable, refused, or its attested
/// root digest doesn't match this device's own). Only once a lease is in
/// hand does the coordination-plane role-loss commit happen, BEFORE the
/// local policy flip, mirroring `ensure_unlink_keeps_a_full_replica`'s
/// identical wiring. Unlike unlink, there is no `--force` here, so a refused
/// or unreachable coordination-plane commit -- or a lease that could not be
/// obtained at all -- fails the demotion closed with no local-only fallback
/// and this device stays locally eager -- a crash between the two commits
/// still leaves both sides agreeing this device is eager, which a re-run of
/// the
/// command reconciles. Committing local-only first would be the unsafe
/// order: it would let this device release its only durable copy (and, on a
/// crash before the coordination-plane commit, start reclaiming blocks)
/// before the handoff is ever recorded coordination-side. For a PROMOTION,
/// the coordination-plane storage-mode write
/// (`coordination_client::set_storage_mode`) also happens BEFORE the local
/// flip, and its failure aborts before the flip runs — but a promotion only
/// ever ADDS a durable copy, so the reverse failure direction (Worker
/// updated, local flip not yet run) is always safe and self-heals on a
/// re-run; there is no data-loss hazard symmetric to the demotion case.
///
/// Behavior when no coordination-plane config is recorded differs by
/// direction. A DEMOTION with no config falls through to a local-only flip
/// (it can only get there when there was no confirming peer to name, i.e. a
/// plane-disconnected daemon, which the readiness gate above already handles
/// fail-closed for a real full replica). A PROMOTION in production instead
/// FAILS CLOSED: it has no peer gate, so a silently-skipped Worker write
/// would leave the plane on-demand while local goes eager, and — because a
/// re-run no-ops once local already matches the target
/// (`commands::share::set_storage_mode`) — that split would not self-heal.
/// Under the deterministic simulator, where config is always absent by design
/// (`set_coordination_client_config` is `#[cfg(not(madsim))]`), a promotion
/// still proceeds local-only, just like a madsim demotion.
///
/// The readiness confirmation above is itself a network round trip, so there
/// is a real window between it returning and the local policy flip below
/// actually committing during which this device's own durability-root set
/// (`SyncState::enumerate_group_durability_roots`) could change (a local
/// edit lands). To close that TOCTOU, the digest the peer was confirmed
/// against ([`DaemonState::full_replica_handoff_ready_digest`]) is re-checked
/// and the policy flip is committed together, in one write transaction
/// ([`SyncState::recheck_digest_then_set_materialization_policy`]), so a
/// concurrent watcher index write cannot interleave between the re-check and
/// the commit; a mismatch fails closed exactly like an unconfirmed peer would
/// — there is no `--force` for demote (see this function's own doc comment on
/// that), so the caller simply has to retry.
///
/// Note this atomic re-check guards the coordination-plane ROLE flip (eager
/// -> on-demand), not block deletion. Actually reclaiming any specific
/// version's blocks stays separately gated, per file, by the on-demand
/// eviction custody check (`confirm_version_present_via_peer`), which is the
/// real backstop against dropping the last copy of a version.
async fn set_storage_mode(
    state: &Arc<DaemonState>,
    group_id: &str,
    on_demand: bool,
) -> Result<Option<(crate::coordination_client::HandoffCommitResult, [u8; 32])>, String> {
    let Some(local_path) = local_path_for_group(state, group_id).map_err(|e| e.to_string())? else {
        return Err(format!("no link registered for folder group {group_id}"));
    };
    if on_demand && state.is_local_full_replica(group_id) {
        let Some((digest_at_check, ready_peer_device_id)) =
            state.full_replica_handoff_ready_digest_and_peer(group_id).await
        else {
            return Err(
                "refusing to drop full-replica status: no other full replica is confirmed to \
                 hold every file in this group yet"
                    .to_string(),
            );
        };
        // Same role-loss shape as `ensure_unlink_keeps_a_full_replica`'s
        // unlink path (this device giving up its own eager status) — reuse
        // its exact wiring: a real confirmed peer means a non-empty root
        // set, so a live, peer-attested lease is now MANDATORY (asked of the
        // confirmed target directly, not merely looked up best-effort), and
        // its absence refuses the whole commit -- see that function's own
        // doc comment for the full rationale; only duplicated here because
        // the two call sites commit two different local side effects (link
        // removal vs. materialization-policy flip) on top of the same
        // coordination-plane commit.
        // Fix-saga: filled in inside the `Some(lease_id)` arm below, right
        // before the coordination-worker commit, and consulted after the
        // local recheck below to close out (success) or compensate
        // (failure) the journal row it names -- see
        // `DaemonState::open_role_loss_operation`'s doc comment.
        let mut role_loss_operation_id: Option<String> = None;
        let mut lease_acquisition_failed = false;
        let coordination_result = match (&ready_peer_device_id, state.coordination_client_config())
        {
            (Some(target_device_id), Some(config)) => {
                match state
                    .obtain_handoff_lease_from_peer(group_id, target_device_id, digest_at_check)
                    .await
                {
                    Some(lease_id) => {
                        // Fix-saga: persist the durable Prepared journal row
                        // FIRST, and fail closed if that write itself fails --
                        // committing the role loss on the Worker without a
                        // durable recovery record would reopen the exact
                        // split-state hole the journal exists to close.
                        // Nothing has been committed on either side yet, so
                        // aborting here leaves no split (routed through the
                        // same `Err(())` fail-closed tail as an unconfirmed
                        // peer -- for demote there is no `--force`, so it just
                        // refuses).
                        match state.open_role_loss_operation(
                            group_id,
                            target_device_id,
                            &lease_id,
                            yadorilink_sync_core::index::RoleLossAction::Demote,
                            &local_path,
                        ) {
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    group_id,
                                    target_device_id = %target_device_id,
                                    "refusing the demotion: could not persist the durable \
                                     role-loss rollback journal, so the role loss must not be \
                                     committed on the coordination plane"
                                );
                                Err(())
                            }
                            Ok(operation_id) => {
                                match crate::coordination_client::commit_handoff_role_loss(
                                    &config.addr,
                                    &config.access_token,
                                    group_id,
                                    &state.device_id,
                                    target_device_id,
                                    Some(lease_id.as_str()),
                                    "demote",
                                )
                                .await
                                {
                                    crate::coordination_client::RoleLossCommitOutcome::Committed(result) => {
                                        state.mark_role_loss_worker_committed(
                                            &operation_id,
                                            result.membership_generation,
                                        );
                                        role_loss_operation_id = Some(operation_id);
                                        Ok(Some((result, digest_at_check)))
                                    }
                                    crate::coordination_client::RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                        state.discard_role_loss_operation(&operation_id);
                                        tracing::warn!(
                                            error = %e,
                                            group_id,
                                            target_device_id = %target_device_id,
                                            "coordination-plane handoff role-loss commit failed; \
                                             set-storage-mode readiness gate treats this the same \
                                             as an unconfirmed peer"
                                        );
                                        Err(())
                                    }
                                    crate::coordination_client::RoleLossCommitOutcome::Ambiguous(e) => {
                                        tracing::error!(
                                            error = %e,
                                            group_id,
                                            target_device_id = %target_device_id,
                                            operation_id,
                                            "handoff role-loss commit outcome is ambiguous; retaining the \
                                             Prepared journal and compensating Worker state back to eager"
                                        );
                                        if let Err(compensation_error) =
                                            state.compensate_role_loss_operation(&operation_id).await
                                        {
                                            tracing::error!(
                                                error = %compensation_error,
                                                operation_id,
                                                "immediate ambiguous role-loss compensation failed; the \
                                                 periodic reconciler will retry"
                                            );
                                        }
                                        Err(())
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        lease_acquisition_failed = true;
                        tracing::warn!(
                            group_id,
                            target_device_id = %target_device_id,
                            "could not obtain a live handoff lease from the confirmed target \
                             peer (unreachable, refused, or its attested durability-root digest \
                             did not match this device's own); a lease is mandatory for a \
                             non-empty root set, so refusing to relinquish full-replica status"
                        );
                        Err(())
                    }
                }
            }
            // A confirmed handoff target with no coordination-plane config
            // recorded. A named target means a NON-EMPTY root set, which now
            // mandates a live lease -- and with no config there is no way to
            // obtain or commit one. Fail closed rather than relinquish the
            // role lease-less: the mandatory-lease guarantee is encoded here,
            // not left resting on the (implicit, unencoded) assumption that a
            // confirmed peer cannot exist without config. Under the
            // deterministic simulator config is always absent by design
            // (`set_coordination_client_config` is `#[cfg(not(madsim))]`) and
            // there is no real coordination plane, so a demotion there keeps
            // its pre-existing local-only fallthrough (see the `_` arm).
            #[cfg(not(madsim))]
            (Some(target_device_id), None) => {
                lease_acquisition_failed = true;
                tracing::warn!(
                    group_id,
                    target_device_id = %target_device_id,
                    "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                     coordination-plane configuration is unavailable"
                );
                Err(())
            }
            // Empty root set (vacuously ready -- no confirmed peer to name, no
            // lease required), and, under the simulator, the (Some, None) case
            // above (which is not compiled there) as its local-only path.
            _ => Ok(None),
        };
        let Ok(handoff_result) = coordination_result else {
            if lease_acquisition_failed {
                return Err(demotion_handoff_lease_failure_message());
            }
            return Err("refusing to drop full-replica status: the coordination plane could not \
                 confirm the target device is still an active eager full replica for this \
                 group; re-run set-storage-mode to re-confirm"
                .to_string());
        };
        // Atomic: re-enumerate the root set and, only if its digest still
        // equals the one the peer confirmed against, flip the policy — both
        // in one transaction, so no watcher write can slip in between.
        //
        // Fix-saga: when `role_loss_operation_id` is `Some`, the
        // coordination-worker role-loss commit above already succeeded, so a
        // failure here (digest mismatch OR a storage error -- both handled
        // identically, per `RoleLossOperation`'s state machine) must not
        // just return an error and leave the Worker and this device
        // disagreeing about full-replica status. Compensate by reverting
        // the Worker back to `eager` instead of erroring bare -- see
        // `DaemonState::compensate_role_loss_operation`'s doc comment for
        // why reverting, not force-completing the demotion, is the safe
        // direction. When `role_loss_operation_id` is `None`, no Worker
        // commit happened (an empty root set, or no coordination-plane
        // config), so this is exactly the pre-existing local-only failure
        // path, unchanged.
        let recheck_result = state.sync_state.recheck_digest_then_set_materialization_policy(
            group_id,
            &local_path,
            MaterializationPolicy::OnDemand,
            digest_at_check,
        );
        let local_failure_reason = match &recheck_result {
            Ok(true) => None,
            Ok(false) => Some(
                "this group's durable file/version set changed between the readiness check and \
                 the commit, so the earlier confirmation no longer covers it"
                    .to_string(),
            ),
            Err(e) => Some(e.to_string()),
        };
        let Some(local_failure_reason) = local_failure_reason else {
            if let Some(operation_id) = &role_loss_operation_id {
                state.settle_role_loss_operation_success(operation_id);
            }
            return Ok(handoff_result);
        };
        let Some(operation_id) = role_loss_operation_id else {
            return Err(format!(
                "refusing to drop full-replica status: {local_failure_reason}; re-run \
                 set-storage-mode to re-confirm"
            ));
        };
        return Err(match state.compensate_role_loss_operation(&operation_id).await {
            Ok(()) => format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the operation was SAFELY ROLLED BACK -- this \
                 device's full-replica status was restored on the coordination plane. Re-run \
                 set-storage-mode to try again."
            ),
            Err(compensation_err) => format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the automatic rollback could not complete \
                 ({compensation_err}) and will be retried automatically until it succeeds -- \
                 this device may briefly appear demoted on the coordination plane even though \
                 it is still storing this group eagerly locally."
            ),
        });
    }
    // Reached for a PROMOTION (`on_demand = false`), and for a redundant
    // on-demand request from a device that is not currently an eager full
    // replica (nothing to hand off, so the demotion branch above never
    // applies). Only the promotion direction needs a coordination-plane
    // write here: a demotion's write is the role-loss commit above, already
    // done by the time execution reaches this point. Written BEFORE the
    // local flip below, and its failure aborts before the flip runs (via
    // `?`), mirroring the demotion branch's own ordering -- see this
    // function's doc comment for why that direction is always the safe one
    // for a promotion.
    //
    // Unlike a demotion, a promotion has no ready-peer gate that would
    // independently fail closed when this daemon is disconnected from the
    // coordination plane. So if the mode write is silently skipped when no
    // config is recorded, a promotion would flip local policy to eager while
    // the coordination plane stays on-demand -- and it would NOT self-heal,
    // since re-running the command sees the local mode already at the target
    // and no-ops (`commands::share::set_storage_mode`). Fail closed instead:
    // in production a missing config means the daemon is not connected to the
    // coordination plane (started before login, or a token was lost and it
    // was not restarted), so refuse rather than diverge. The local flip below
    // is never reached in that case.
    #[cfg(not(madsim))]
    if !on_demand {
        let Some(config) = state.coordination_client_config() else {
            return Err(
                "not connected to the coordination plane; cannot change storage mode (ensure the \
                 daemon is logged in; restart it if you logged in after it started)"
                    .to_string(),
            );
        };
        crate::coordination_client::set_storage_mode(
            &config.addr,
            &config.access_token,
            group_id,
            &state.device_id,
            "eager",
        )
        .await?;
    }
    // Under the deterministic simulator `set_coordination_client_config` is
    // never called (it is `#[cfg(not(madsim))]`), so config is ALWAYS None by
    // design and there is no real coordination plane to write to -- a
    // promotion proceeds local-only here, exactly as a madsim demotion's
    // local-only fallthrough above does.
    let policy =
        if on_demand { MaterializationPolicy::OnDemand } else { MaterializationPolicy::Eager };
    state.sync_state.set_materialization_policy(&local_path, policy).map_err(|e| e.to_string())?;
    Ok(None)
}

/// `yadorilink trash list`: flattens every linked folder's
/// Refuses to unlink an eager (full-replica) folder on this device unless
/// [`DaemonState::another_full_replica_is_ready`] confirms some OTHER full
/// replica is, right now, durably holding the current version of every file
/// in the group. Because there is no central storage, a full replica is a
/// group's only durable copy, so unlinking the last one before a confirmed
/// handoff risks permanent data loss — merely having another device's row
/// recorded as "also a full replica" is not enough, since that device could
/// be offline, behind, or missing blocks (this is the same gap
/// `set_storage_mode`'s demotion gate closes; unlink is the same hazard by a
/// different name). Unlinking an on-demand link (this device is a cache, not
/// a durable holder) is always allowed regardless. A missing or unreadable
/// link list defers to `remove_link` for the real outcome rather than
/// blocking.
///
/// `force` bypasses the gate for a genuinely dead sole replica that would
/// otherwise have no way to ever unlink — every forced override is logged
/// here as an audit trail (`tracing::warn!`), since bypassing this gate can
/// permanently lose the only copy of the group's data.
///
/// The readiness confirmation is itself a peer round trip, so there is a
/// real window between it succeeding and the unlink actually committing
/// during which this device's own durability-root set
/// (`SyncState::enumerate_group_durability_roots`) could change (a local
/// edit lands). To close that TOCTOU, the digest the peer was confirmed
/// against ([`DaemonState::full_replica_handoff_ready_digest`]) is re-checked
/// and the link row removed together, in one write transaction
/// ([`SyncState::recheck_digest_then_remove_link`]), so a concurrent watcher
/// index write cannot interleave between the re-check and the removal; a
/// digest that no longer matches is treated exactly like an unconfirmed peer
/// — refused unless `--force`. See `set_storage_mode`'s matching comment for
/// the demote side of the same pattern.
///
/// Note this atomic re-check guards only the coordination-plane ROLE flip
/// (removing this device's eager link), not block deletion. Actually
/// reclaiming any version's blocks stays separately gated, per file, by the
/// on-demand eviction custody check (`confirm_version_present_via_peer`),
/// which is the real backstop against dropping the last copy of a version.
///
/// Returns which removal step the caller ([`handle_request`]) still owes: the
/// eager ready path removes the link atomically here (`AlreadyRemoved`); every
/// other path leaves the plain removal to the caller (`RemoveNormally`).
async fn ensure_unlink_keeps_a_full_replica(
    state: &DaemonState,
    local_path: &str,
    force: bool,
) -> Result<UnlinkCommit, String> {
    let Some(link) = state
        .sync_state
        .list_links()
        .map_err(|e| {
            format!("refusing to unlink because the local link table could not be read: {e}")
        })?
        .into_iter()
        .find(|l| l.local_path == local_path)
    else {
        return Ok(UnlinkCommit::RemoveNormally);
    };
    if link.materialization_policy != MaterializationPolicy::Eager {
        return Ok(UnlinkCommit::RemoveNormally);
    }
    // A confirmed whole-group handoff yields the exact root-set digest it was
    // made against (and, when a real peer confirmed it, that peer's device
    // id); the atomic method below re-enumerates and removes the link
    // in one transaction only if that digest still holds.
    let mut lease_acquisition_failed = false;
    if let Some((digest_at_check, ready_peer_device_id)) =
        state.full_replica_handoff_ready_digest_and_peer(&link.group_id).await
    {
        // This device giving up its own eager status is exactly the
        // role-loss shape coordination-worker's handoff-commit endpoint
        // guards (see `HandoffResult`'s proto doc comment): confirm the
        // named target is currently Active+eager and commit the role loss
        // (`storage_mode` narrows to on-demand) atomically, coordination-
        // side, before this device also removes its own local link. Only
        // attempted when both a real confirming peer was named (not the
        // vacuously-ready empty-group case, which has no peer to target)
        // and this device actually has coordination-plane config recorded
        // (`DaemonState::coordination_client_config`'s doc comment: absent
        // under the deterministic simulator, on a device that never
        // registered/logged in, and in most of this crate's own unit
        // tests) — otherwise this falls back to exactly the pre-existing
        // purely-local gate, unchanged.
        // `Ok(None)`: no coordination-plane commit was attempted (falls back
        // to the pre-existing purely-local gate) or attempted and refused
        // (fail closed, same as an unconfirmed peer). `Ok(Some(result))`: a
        // commit was attempted and succeeded, to be threaded into the
        // eventual `UnlinkResponse`.
        //
        // Fix-saga: filled in inside the `Some(lease_id)` arm below, right
        // before the coordination-worker commit, and consulted after the
        // local recheck further down to close out (success) or compensate
        // (failure) the journal row it names -- see
        // `DaemonState::open_role_loss_operation`'s doc comment.
        let mut role_loss_operation_id: Option<String> = None;
        let coordination_result = match (&ready_peer_device_id, state.coordination_client_config())
        {
            (Some(target_device_id), Some(config)) => {
                // A real confirming peer was named, i.e. a non-empty root
                // set -- a live, peer-attested lease is now MANDATORY, not
                // merely looked up best-effort: ask the confirmed target
                // directly, over the authenticated peer channel, to verify
                // and pin its own durability-root set and hand back a lease
                // naming it (`DaemonState::obtain_handoff_lease_from_peer`),
                // and refuse the whole commit if none can be obtained
                // (unreachable, refused, or a digest mismatch -- the target
                // isn't actually caught up to this device's exact set). The
                // `--force` override below still lets a forced unlink
                // proceed with no lease at all; this gate only governs the
                // non-forced path.
                match state
                    .obtain_handoff_lease_from_peer(
                        &link.group_id,
                        target_device_id,
                        digest_at_check,
                    )
                    .await
                {
                    None => {
                        lease_acquisition_failed = true;
                        tracing::warn!(
                            group_id = %link.group_id,
                            local_path,
                            target_device_id = %target_device_id,
                            "could not obtain a live handoff lease from the confirmed target \
                             peer; a lease is mandatory for a non-empty root set -- unlink \
                             readiness gate treats this the same as an unconfirmed peer (use \
                             --force to override)"
                        );
                        Err(())
                    }
                    Some(lease_id) => {
                        // Fix-saga: persist the durable Prepared journal row
                        // FIRST and fail closed if it can't be written -- see
                        // `set_storage_mode`'s matching Fix-saga comment. A
                        // failed Prepared write routes to the same `Err(())`
                        // the no-lease case uses, so the force-or-refuse tail
                        // below still governs (a `--force` unlink can still
                        // proceed, latching `DurabilityUnknown`; a non-forced
                        // one is refused) -- but the Worker role-loss commit is
                        // never reached without a durable rollback record.
                        match state.open_role_loss_operation(
                            &link.group_id,
                            target_device_id,
                            &lease_id,
                            yadorilink_sync_core::index::RoleLossAction::Unlink,
                            local_path,
                        ) {
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    group_id = %link.group_id,
                                    local_path,
                                    target_device_id = %target_device_id,
                                    "refusing the online unlink handoff: could not persist the \
                                     durable role-loss rollback journal, so the role loss must \
                                     not be committed on the coordination plane"
                                );
                                Err(())
                            }
                            Ok(operation_id) => {
                                match crate::coordination_client::commit_handoff_role_loss(
                                    &config.addr,
                                    &config.access_token,
                                    &link.group_id,
                                    &state.device_id,
                                    target_device_id,
                                    Some(lease_id.as_str()),
                                    "demote",
                                )
                                .await
                                {
                                    // `digest_at_check` is this device's own
                                    // local durability-root digest, paired here
                                    // purely for the caller's
                                    // `HandoffResult.root_digest` output --
                                    // never itself sent to coordination-worker
                                    // (see `commit_handoff_role_loss`'s doc
                                    // comment).
                                    crate::coordination_client::RoleLossCommitOutcome::Committed(result) => {
                                        state.mark_role_loss_worker_committed(
                                            &operation_id,
                                            result.membership_generation,
                                        );
                                        role_loss_operation_id = Some(operation_id);
                                        Ok(Some((result, digest_at_check)))
                                    }
                                    crate::coordination_client::RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                        state.discard_role_loss_operation(&operation_id);
                                        tracing::warn!(
                                            error = %e,
                                            group_id = %link.group_id,
                                            local_path,
                                            target_device_id = %target_device_id,
                                            "coordination-plane handoff role-loss commit failed; \
                                             unlink readiness gate treats this the same as an \
                                             unconfirmed peer"
                                        );
                                        Err(())
                                    }
                                    crate::coordination_client::RoleLossCommitOutcome::Ambiguous(e) => {
                                        tracing::error!(
                                            error = %e,
                                            group_id = %link.group_id,
                                            local_path,
                                            target_device_id = %target_device_id,
                                            operation_id,
                                            "unlink role-loss commit outcome is ambiguous; retaining the \
                                             Prepared journal and compensating Worker state back to eager"
                                        );
                                        if let Err(compensation_error) =
                                            state.compensate_role_loss_operation(&operation_id).await
                                        {
                                            tracing::error!(
                                                error = %compensation_error,
                                                operation_id,
                                                "immediate ambiguous unlink compensation failed; the periodic \
                                                 reconciler will retry"
                                            );
                                        }
                                        Err(())
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // A confirmed handoff target with no coordination-plane config
            // recorded -- a NON-EMPTY root set that now mandates a live
            // lease, with no way to obtain one. Fail closed exactly like the
            // no-lease-obtainable case above (`Err(())`), which the tail
            // below routes to the existing force-or-refuse handling -- so
            // `--force` still proceeds (latching `DurabilityUnknown`), a
            // non-forced unlink is refused, and the mandatory-lease guarantee
            // is encoded rather than resting on the implicit assumption that
            // a confirmed peer cannot exist without config. Under the
            // deterministic simulator config is always absent by design
            // (`set_coordination_client_config` is `#[cfg(not(madsim))]`), so
            // this case is not compiled there and the `_` arm's pre-existing
            // local-only fallthrough stands.
            #[cfg(not(madsim))]
            (Some(target_device_id), None) => {
                lease_acquisition_failed = true;
                tracing::warn!(
                    group_id = %link.group_id,
                    local_path,
                    target_device_id = %target_device_id,
                    "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                     coordination-plane configuration is unavailable"
                );
                Err(())
            }
            // Empty root set (vacuously ready -- no confirmed peer to name, no
            // lease required), and, under the simulator, the (Some, None) case
            // above (not compiled there) as its local-only path.
            _ => Ok(None),
        };
        if let Ok(handoff_result) = coordination_result {
            let recheck_result = state.sync_state.recheck_digest_then_remove_link(
                &link.group_id,
                local_path,
                digest_at_check,
            );
            match recheck_result {
                Ok(true) => {
                    if let Some(operation_id) = &role_loss_operation_id {
                        state.settle_role_loss_operation_success(operation_id);
                    }
                    return Ok(UnlinkCommit::AlreadyRemoved(handoff_result));
                }
                Ok(false) | Err(_) if role_loss_operation_id.is_some() => {
                    // Fix-saga: the Worker commit above already succeeded, so a
                    // local failure here (digest mismatch OR a storage error --
                    // both handled identically, per `RoleLossOperation`'s state
                    // machine) must not silently fall through to `--force`
                    // completing an unlink whose digest was never re-verified
                    // against the peer confirmation, nor leave a bare split
                    // state on the non-forced path. Compensate by reverting the
                    // Worker back to `eager` instead -- see `set_storage_mode`'s
                    // matching Fix-saga comment for the full rationale (revert,
                    // never force-complete, once the Worker has already
                    // committed).
                    let operation_id = role_loss_operation_id
                        .clone()
                        .expect("guarded by role_loss_operation_id.is_some() above");
                    let local_failure_reason = match &recheck_result {
                        Ok(false) => "this group's durable file/version set changed between the \
                                      readiness check and the commit, so the earlier \
                                      confirmation no longer covers it"
                            .to_string(),
                        Err(e) => e.to_string(),
                        Ok(true) => unreachable!("Ok(true) handled by the arm above"),
                    };
                    return Err(match state.compensate_role_loss_operation(&operation_id).await {
                        Ok(()) => format!(
                            "unlink was committed on the coordination plane but the matching \
                             local removal failed ({local_failure_reason}); the operation was \
                             SAFELY ROLLED BACK -- this device's full-replica status was \
                             restored on the coordination plane. Re-run unlink to try again."
                        ),
                        Err(compensation_err) => format!(
                            "unlink was committed on the coordination plane but the matching \
                             local removal failed ({local_failure_reason}); the automatic \
                             rollback could not complete ({compensation_err}) and will be \
                             retried automatically until it succeeds -- this device may briefly \
                             appear demoted on the coordination plane even though it is still \
                             storing this group eagerly locally."
                        ),
                    });
                }
                // No coordination-worker commit happened (empty root set, or no
                // coordination-plane config) -- exactly the pre-existing
                // behavior: the root set moved between the peer confirmation
                // and the atomic re-check, so fall through to the same
                // force-or-refuse handling as an unconfirmed peer.
                Ok(false) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
    }
    if force {
        tracing::warn!(
            group_id = %link.group_id,
            local_path,
            "forced unlink of an eager full replica with no other full replica confirmed \
             ready -- proceeding anyway; this may have permanently lost the only complete \
             copy of this folder's data"
        );
        // This override is exactly the case the local durability-status
        // latch exists for: the group's remaining local replica (if any)
        // must not be able to report `Healthy`/"synced" again until a real
        // whole-group handoff re-check says so, even though nothing else
        // about its own files just changed.
        state.latch_group_durability_unknown(&link.group_id).map_err(|e| e.to_string())?;
        return Ok(UnlinkCommit::RemoveNormally);
    }
    if lease_acquisition_failed {
        return Err(unlink_handoff_lease_failure_message(local_path));
    }
    Err(format!(
        "refusing to unlink {local_path}: no other full replica is confirmed ready to durably \
         hold every file in this group yet, so unlinking it may permanently lose the only \
         complete copy of this folder's data. Wait for another full replica to finish syncing, \
         or re-run with --force to unlink anyway (data-loss risk)."
    ))
}

/// Which link-row removal step the unlink dispatcher still owes after the
/// durability gate ([`ensure_unlink_keeps_a_full_replica`]) returns.
#[derive(Debug, PartialEq, Eq)]
enum UnlinkCommit {
    /// The eager ready path already removed the link row atomically with its
    /// digest re-check; the caller must not remove it again. Carries the
    /// coordination-plane handoff-commit result, paired with this device's
    /// own locally-computed root digest (never sent to or read back from
    /// coordination-worker — see `HandoffCommitResult`'s doc comment), when
    /// that path actually ran one (`Some`) — see
    /// `ensure_unlink_keeps_a_full_replica`'s doc comment for when it does
    /// and doesn't.
    AlreadyRemoved(Option<(crate::coordination_client::HandoffCommitResult, [u8; 32])>),
    /// No atomic removal happened (on-demand cache, no link row, or a forced
    /// bypass); the caller performs the plain `remove_link`.
    RemoveNormally,
}

/// The not-ready group id list behind `CheckFullReplicaHandoffReadyExcluding`
/// -- see that request's proto doc comment for the full contract. For each
/// candidate group (either the single `group_id` given, or, when empty,
/// every group this daemon has a local link for), a group only needs
/// checking at all if `excluded_device_id` is actually recorded here as an
/// eager full replica for it: revoking/removing an on-demand (cache) device,
/// or one this daemon has no record of at all, never gives up a durable
/// copy. This is necessarily a partial view -- this daemon only knows about
/// groups/peers it itself participates in -- which is why the coordination
/// Worker's own access-count guard still runs regardless of this answer.
async fn full_replica_handoff_not_ready_excluding(
    state: &Arc<DaemonState>,
    group_id: &str,
    excluded_device_id: &str,
) -> Result<Vec<String>, yadorilink_sync_core::SyncError> {
    let candidate_groups: Vec<String> = if group_id.is_empty() {
        state.sync_state.list_links()?.into_iter().map(|l| l.group_id).collect()
    } else {
        vec![group_id.to_string()]
    };
    let mut not_ready = Vec::new();
    for candidate in candidate_groups {
        if !state.peer_group_is_full_replica(excluded_device_id, &candidate) {
            continue;
        }
        if !state.another_full_replica_is_ready_excluding(&candidate, excluded_device_id).await {
            not_ready.push(candidate);
        }
    }
    Ok(not_ready)
}

/// trashed files into one list, each tagged with the link's own
/// `local_path` since `ListTrashRequest` spans every link at once — mirrors
/// `list_link_statuses`'s own per-link iteration.
fn list_trashed_files(
    state: &DaemonState,
) -> Result<Vec<TrashedFileInfo>, yadorilink_sync_core::SyncError> {
    let mut out = Vec::new();
    for link in state.sync_state.list_links()? {
        for trashed in state.sync_state.list_trashed(&link.group_id)? {
            out.push(TrashedFileInfo {
                local_path: link.local_path.clone(),
                path: trashed.path,
                version_seq: trashed.version_seq,
                last_known_size: trashed.last_known_size as i64,
                origin_device_id: trashed.origin_device_id.unwrap_or_default(),
                deleted_at_unix_nanos: trashed.deleted_at_unix_nanos,
            });
        }
    }
    Ok(out)
}

/// Maps the daemon's internal reachability into the control-socket wire
/// enums (`PeerStatus.reachability` / `unreachable_category`). The category
/// is `Unspecified` whenever the peer is not unreachable.
fn reachability_to_proto(
    reachability: crate::daemon_state::PeerReachability,
) -> (
    yadorilink_ipc_proto::daemonctl::PeerReachability,
    yadorilink_ipc_proto::daemonctl::UnreachableCategory,
) {
    use crate::daemon_state::{PeerReachability as Daemon, UnreachableCategory as DaemonCat};
    use yadorilink_ipc_proto::daemonctl::{
        PeerReachability as Wire, UnreachableCategory as WireCat,
    };
    match reachability {
        Daemon::Connecting => (Wire::Connecting, WireCat::Unspecified),
        Daemon::Connected => (Wire::Connected, WireCat::Unspecified),
        Daemon::ProtocolIncompatible => (Wire::ProtocolIncompatible, WireCat::Unspecified),
        Daemon::Unreachable(category) => {
            let wire_category = match category {
                DaemonCat::NoCandidates => WireCat::NoCandidates,
                DaemonCat::NoResponse => WireCat::NoResponse,
                DaemonCat::UdpBlocked => WireCat::UdpBlocked,
                DaemonCat::HandshakeRefused => WireCat::HandshakeRefused,
            };
            (Wire::Unreachable, wire_category)
        }
    }
}

/// Maps the daemon's internal per-group durability status into the
/// control-socket wire enum (`LinkStatus.durability_status`).
fn durability_status_to_proto(
    status: crate::daemon_state::GroupDurabilityStatus,
) -> GroupDurabilityStatus {
    use crate::daemon_state::GroupDurabilityStatus as Daemon;
    match status {
        Daemon::Healthy => GroupDurabilityStatus::Healthy,
        Daemon::Syncing => GroupDurabilityStatus::Syncing,
        Daemon::DurabilityUnknown => GroupDurabilityStatus::DurabilityUnknown,
        Daemon::KnownMissing => GroupDurabilityStatus::KnownMissing,
    }
}

/// a lightweight health surface distinct from `StatusResponse`
/// (see `daemon_control.proto`'s `HealthResponse` doc comment) — task
/// liveness, connected-peer count, and a process-wide pending-changes
/// total, all cheap to compute from state already held in memory (no SQLite
/// queries, unlike `list_link_statuses`).
pub(crate) fn health_snapshot(state: &DaemonState) -> HealthResponse {
    let tasks = state
        .task_liveness
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(name, alive)| TaskLiveness { name: name.clone(), alive: *alive })
        .collect();

    let peer_statuses = state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let connected_peer_count =
        peer_statuses.values().filter(|info| info.reachability.is_connected()).count() as u32;

    HealthResponse { tasks, connected_peer_count }
}

pub(crate) fn list_link_statuses(
    state: &DaemonState,
) -> Result<Vec<LinkStatus>, yadorilink_sync_core::SyncError> {
    let links = state.sync_state.list_links()?;
    let mut out = Vec::with_capacity(links.len());
    for link in links {
        let files = state.sync_state.list_files(&link.group_id)?;
        let conflict_count =
            files.iter().filter(|f| f.path.contains("(conflicted copy")).count() as u64;
        let materialization = state.sync_state.materialization_counts(&link.group_id)?;
        // Held-file and skipped-symlink status, populated from section
        // 1's per-file `SyncState` getters. Deliberately `get_held_state`/
        // `get_record_kind` per non-deleted file rather than a new
        // aggregate SQL query on `index.rs` — this section's scope is the
        // daemon/IPC surface only, and `index.rs` already exposes exactly
        // the by-`(group_id, path)` accessors this needs (mirrors this
        // same function's pre-existing `conflict_count`, an in-process
        // filter over `files` rather than its own query). Two extra
        // point-queries per non-deleted file is a real O(n) cost on a
        // large link — acceptable for now (a `status`/`link list` call is
        // infrequent, not a sync hot path), flagged here rather than
        // silently accepted.
        // NOT `?`: this resolver refuses an ambiguous group, and propagating
        // that would fail the ENTIRE status listing -- for every group on the
        // device, not just the offending one. Status is the surface that MAKES
        // the ambiguity visible (see `ambiguous_local_paths` below), so letting
        // it be the thing an ambiguous group breaks would hide the refusal
        // behind a bare error string and leave the user with no way to see which
        // folders collided. It would also turn a per-GROUP refusal into a
        // per-DEVICE one, which is exactly what this invariant must never do.
        //
        // `false` is the safe default and costs nothing here: it only classifies
        // symlinks as "skipped" for a cosmetic count, and an ambiguous group is
        // refusing to sync anyway, so there is no materialization for it to be
        // wrong about.
        let windows_symlink_opt_in =
            state.sync_state.windows_symlink_opt_in_for_group(&link.group_id).unwrap_or_else(|e| {
                tracing::warn!(
                    group_id = %link.group_id,
                    error = %e,
                    "cannot read this group's symlink policy for status; reporting the default"
                );
                false
            });
        let mut held_files = Vec::new();
        let mut skipped_symlink_count = 0u64;
        for file in files.iter().filter(|f| !f.deleted) {
            if let Some(held) = state.sync_state.get_held_state(&link.group_id, &file.path)? {
                held_files.push(HeldFile {
                    path: file.path.clone(),
                    reason: held.reason,
                    held_since_unix_nanos: held.since_unix_nanos,
                });
            }
            if is_skipped_windows_symlink(
                &state.sync_state,
                &link.group_id,
                &file.path,
                windows_symlink_opt_in,
            )? {
                skipped_symlink_count += 1;
            }
        }
        let held_file_count = held_files.len() as u64;
        // Independent of `paused` (a link can be paused and/or degraded
        // at once — see `DegradedLinkInfo`'s doc comment).
        let degraded_info = state.degraded_link_info(&link.local_path);
        // This link's active-transfer rollup, if any is currently in
        // flight.
        let rollup = state.transfer_progress.link_rollup(&link.group_id);
        let durability_status =
            durability_status_to_proto(state.group_durability_status(&link.group_id));
        // Every live folder registered for this group. More than one is the
        // refusing state; the paths ARE the remedy, since unlinking is keyed by
        // path. An unreadable link table surfaces as "not ambiguous" rather than
        // failing the whole status listing: status must keep rendering, and the
        // group is already refusing to sync on the paths that matter.
        let ambiguous_local_paths =
            state.sync_state.live_link_paths_for_group(&link.group_id).unwrap_or_else(|e| {
                tracing::warn!(
                    group_id = %link.group_id,
                    error = %e,
                    "cannot read this group's links to report whether it is linked twice"
                );
                Vec::new()
            });
        out.push(LinkStatus {
            local_path: link.local_path.clone(),
            group_id: link.group_id.clone(),
            paused: link.paused,
            conflict_count,
            materialization_policy: link.materialization_policy.as_db_str().to_string(),
            hydrated_count: materialization.hydrated,
            placeholder_count: materialization.placeholder,
            hydrating_count: materialization.hydrating,
            held_file_count,
            held_files,
            skipped_symlink_count,
            degraded: degraded_info.is_some(),
            degraded_reason: degraded_info.map(|info| info.reason).unwrap_or_default(),
            // This link's active-transfer rollup — absent (all zero,
            // `has_active_transfer = false`) when nothing is currently
            // in flight for this link.
            has_active_transfer: rollup.is_some(),
            transfer_bytes_done: rollup.map(|r| r.bytes_done).unwrap_or(0),
            transfer_bytes_total: rollup.map(|r| r.bytes_total).unwrap_or(0),
            transfer_blocks_done: rollup.map(|r| r.blocks_done).unwrap_or(0),
            transfer_blocks_total: rollup.map(|r| r.blocks_total).unwrap_or(0),
            transfer_eta_seconds: rollup.and_then(|r| r.eta_seconds).unwrap_or(0),
            durability_status: durability_status as i32,
            // Surfaces the same staleness gate admission and local emission
            // fail closed on, so a group whose policy this daemon distrusts
            // (own verification failure or coordinator-flagged invalid) is
            // distinguishable in status from a healthy one.
            policy_stale: state.is_group_policy_stale(&link.group_id),
            // A folder group linked at more than one folder refuses to sync
            // entirely (each folder's scan would delete the other's files on
            // every device). The refusal is otherwise only a log line, which is
            // loud in the code and silent in the UI — this is what makes it
            // visible where the user actually looks, and names every folder
            // involved so the remedy (unlink all but one) is actionable.
            //
            // Derived from the same live-link enumeration the invariant itself
            // uses, so status cannot drift from behaviour. `list_links` above
            // stays non-erroring on purpose: it is what keeps BOTH rows visible
            // for recovery.
            ambiguous: ambiguous_local_paths.len() > 1,
            ambiguous_local_paths,
        });
    }
    Ok(out)
}

/// Free-space state for every volume hosting the block store or a linked
/// folder — the block-store root (via `BlockStore::free_space`, `None`
/// for a backend with no real volume concept) plus one entry per distinct
/// link `local_path` (paths can collide if a device somehow links the
/// same directory twice, so this dedups by path rather than by link
/// count). Best-effort: a link whose volume can't currently be queried
/// (e.g. the folder was removed from disk without being unlinked) is
/// silently skipped rather than failing the whole `status` response.
pub(crate) fn volumes_free_space(
    state: &DaemonState,
    links: &[LinkStatus],
) -> Vec<VolumeFreeSpace> {
    let headroom_override = state.governance_config.load_or_default().headroom_override_bytes;
    let mut seen_paths = std::collections::HashSet::new();
    let mut volumes = Vec::new();

    if let Ok(Some(space)) = state.block_store.free_space() {
        // The block-store root path itself isn't tracked on `DaemonState`
        // directly (only the trait object is) — `VolumeFreeSpace.path`
        // reports a stable, recognizable label instead of guessing at a
        // filesystem path the caller has no other way to confirm.
        volumes.push(VolumeFreeSpace {
            path: "<block store>".to_string(),
            state: space.classify().as_str().to_string(),
            available_bytes: space.available_bytes,
            headroom_bytes: space.headroom_bytes,
        });
    }

    for link in links {
        if !seen_paths.insert(link.local_path.clone()) {
            continue;
        }
        if let Ok(space) = yadorilink_local_storage::free_space::classify_volume(
            std::path::Path::new(&link.local_path),
            headroom_override,
        ) {
            volumes.push(VolumeFreeSpace {
                path: link.local_path.clone(),
                state: space.classify().as_str().to_string(),
                available_bytes: space.available_bytes,
                headroom_bytes: space.headroom_bytes,
            });
        }
    }
    volumes
}

/// Whether `path` is a symlink record this device's index tracks (and
/// still syncs normally) but never materialized to disk under the
/// Windows default-skip-with-visible-status policy — i.e. the local
/// daemon is running on Windows, the record is `RecordKind::Symlink`, and
/// this link never opted in to real Windows symlink materialization. On a
/// non-Windows daemon this is always `false`: only the Windows
/// default-skip policy ever leaves a symlink record unmaterialized —
/// every POSIX symlink materializes via the ordinary atomic
/// temp-path-then-rename path (`chunker::materialize_symlink`).
#[cfg(windows)]
fn is_skipped_windows_symlink(
    state: &SyncState,
    group_id: &str,
    path: &str,
    windows_symlink_opt_in: bool,
) -> Result<bool, yadorilink_sync_core::SyncError> {
    if windows_symlink_opt_in {
        return Ok(false);
    }
    Ok(state.get_record_kind(group_id, path)?.is_some_and(|kind| kind == RecordKind::Symlink))
}

#[cfg(not(windows))]
fn is_skipped_windows_symlink(
    _state: &SyncState,
    _group_id: &str,
    _path: &str,
    _windows_symlink_opt_in: bool,
) -> Result<bool, yadorilink_sync_core::SyncError> {
    Ok(false)
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
/// Precedence (highest first): any link `degraded` or any volume
/// `state == "critical"` -> `Degraded` (spec: a low-disk condition on a
/// linked folder needs attention; a *critical* one is actively blocking
/// sync, same severity split `VolumeFreeSpace.state`'s own `"low"` vs
/// `"critical"` already draws). Otherwise any conflict, held file, a
/// `"low"` volume, a disconnected peer, a non-empty recent-error feed, or a
/// recorded update failure -> `Attention`. A merely-`paused` link is
/// *not* by itself attention-worthy (spec's "Sync is healthy" scenario:
/// "caught up or idle *without errors*" says nothing about pause being an
/// error state — pausing is a deliberate user action, matching
/// `status.rs`'s own `held_summary_suffix`-style "only surface what's
/// actionable" discipline). Otherwise `Healthy`, with no reasons.
fn overall_status(response: &StatusResponse) -> (OverallState, Vec<String>) {
    let mut degraded_reasons = Vec::new();
    let mut attention_reasons = Vec::new();

    for link in &response.links {
        if link.degraded {
            degraded_reasons.push(format!("degraded:{}", link.group_id));
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
mod overall_status_tests {
    use super::*;

    /// spec "Sync is healthy": no links/volumes/peers/errors at all (the
    /// zero-value default) is healthy with no reasons — matches this
    /// file's/`status.rs`'s "additive, empty/zero unless applicable"
    /// convention for a freshly-started daemon.
    #[test]
    fn empty_status_is_healthy() {
        let (state, reasons) = overall_status(&StatusResponse::default());
        assert_eq!(state, OverallState::Healthy);
        assert!(reasons.is_empty());
    }

    /// A merely-paused link with nothing else wrong stays healthy — pause
    /// is a deliberate user action, not an error state.
    #[test]
    fn paused_link_alone_is_still_healthy() {
        let response = StatusResponse {
            links: vec![LinkStatus { paused: true, ..Default::default() }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Healthy);
        assert!(reasons.is_empty());
    }

    /// spec "Sync needs attention": a conflict on any link needs attention,
    /// naming the affected group.
    #[test]
    fn conflict_is_attention() {
        let response = StatusResponse {
            links: vec![LinkStatus {
                group_id: "group-1".into(),
                conflict_count: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Attention);
        assert_eq!(reasons, vec!["conflict:group-1".to_string()]);
    }

    /// spec "Sync needs attention": a `"low"` volume needs attention; a
    /// `"critical"` one is degraded — the severity split
    /// `VolumeFreeSpace.state` already draws.
    #[test]
    fn low_disk_is_attention_but_critical_disk_is_degraded() {
        let low = StatusResponse {
            volumes: vec![VolumeFreeSpace {
                path: "/data".into(),
                state: "low".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(overall_status(&low).0, OverallState::Attention);

        let critical = StatusResponse {
            volumes: vec![VolumeFreeSpace {
                path: "/data".into(),
                state: "critical".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&critical);
        assert_eq!(state, OverallState::Degraded);
        assert_eq!(reasons, vec!["low_disk_critical:/data".to_string()]);
    }

    /// spec "Sync needs attention": a peer that cannot be connected
    /// (unreachable) needs attention.
    #[test]
    fn unreachable_peer_is_attention() {
        let response = StatusResponse {
            peers: vec![PeerStatus {
                device_id: "device-b".into(),
                reachability: yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Attention);
        assert_eq!(reasons, vec!["peer_disconnected:device-b".to_string()]);
    }

    /// A degraded link (disk-pressure elsewhere) takes
    /// precedence over -- and is reported alongside -- an unrelated
    /// attention-level issue.
    #[test]
    fn degraded_link_outranks_but_still_reports_attention_reasons() {
        let response = StatusResponse {
            links: vec![
                LinkStatus { group_id: "group-1".into(), degraded: true, ..Default::default() },
                LinkStatus { group_id: "group-2".into(), conflict_count: 1, ..Default::default() },
            ],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Degraded);
        assert!(reasons.contains(&"degraded:group-1".to_string()));
        assert!(reasons.contains(&"conflict:group-2".to_string()));
    }

    /// A recorded update failure alone needs attention, even with every
    /// link/volume/peer otherwise healthy.
    #[test]
    fn update_failure_is_attention() {
        let response = StatusResponse {
            update_last_error_category: "update_manifest_fetch_failed".into(),
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Attention);
        assert_eq!(reasons, vec!["update_failed:update_manifest_fetch_failed".to_string()]);
    }
}

// --- Control-protocol exact-version enforcement, exercised directly
// against `handle_request` (the actual dispatch a real control-socket
// connection runs through).

#[cfg(test)]
mod migration_safety_tests {
    use std::sync::Arc;

    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, LinkRequest, PendingEnrollmentKind, StatusRequest,
    };
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    use crate::daemon_state::DaemonState;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        // A registered device with no signing key fails closed (see
        // `link_manager::ensure_initial_change_history`'s doc comment) --
        // any test driving `start_link_watch` needs one wired.
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        state
    }

    /// A `LinkRequest` whose `pending_enrollment_operation_id` is set commits
    /// the link and the marker atomically (see
    /// `SyncState::add_link_with_pending_enrollment`), but `start_link_watch`
    /// runs *after* that commit and can still fail. Forced here by making
    /// `.yadorilinkignore` itself a directory rather than a file, so
    /// `EffectiveIgnoreSet::load_for_link_root` -- the first fallible step
    /// inside `start_link_watch`, run before anything is registered in
    /// `DaemonState`'s in-memory maps -- hits a real (non-`NotFound`) I/O
    /// error reading it. `link` must roll the already-committed link and
    /// marker back on that failure -- every caller (the CLI's `share
    /// create`/`share join`) treats any `Err` from this whole call as
    /// "nothing was created" and only compensates the coordination-plane
    /// side, so leaving local rows behind here would strand them forever
    /// with no coordination-side marker retry to find them.
    #[tokio::test]
    async fn link_rolls_back_the_link_and_marker_when_a_post_commit_step_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".yadorilinkignore")).unwrap();
        let state = test_state();
        let request = LinkRequest {
            local_path: dir.path().to_string_lossy().to_string(),
            group_id: "group-1".to_string(),
            on_demand: false,
            max_local_size_bytes: None,
            acknowledge_risks: true,
            pending_enrollment_operation_id: "op-1".to_string(),
            pending_enrollment_kind: PendingEnrollmentKind::Create as i32,
            pending_enrollment_device_id: "device-a".to_string(),
        };

        let result = super::link(&state, request);

        assert!(
            result.is_err(),
            "a directory named .yadorilinkignore must fail to load as the ignore file"
        );
        assert!(
            state.sync_state.list_links().unwrap().is_empty(),
            "the link must be rolled back, not left behind"
        );
        assert!(
            state.sync_state.list_pending_enrollments().unwrap().is_empty(),
            "the pending-enrollment marker must be rolled back too -- otherwise nothing ever \
             resolves it, since the link it names doesn't exist"
        );
    }

    /// Indexes one current file record in `group_id` -- just enough for the
    /// readiness gate below to have something to hand off (an empty group is
    /// vacuously ready regardless of any peer, which these tests are
    /// deliberately not exercising).
    fn upsert_solo_file(state: &DaemonState, group_id: &str) {
        use yadorilink_sync_core::types::{BlockInfo, FileRecord};
        use yadorilink_sync_core::version_vector::VersionVector;
        let mut version = VersionVector::new();
        version.increment("device-a");
        state
            .sync_state
            .upsert_file(
                group_id,
                &FileRecord {
                    path: "solo.bin".into(),
                    size: 4,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![BlockInfo { hash: vec![1u8; 32], offset: 0, size: 4 }],
                    deleted: false,
                },
            )
            .unwrap();
    }

    #[test]
    fn lease_acquisition_errors_are_not_reported_as_readiness_failures() {
        let demotion = super::demotion_handoff_lease_failure_message();
        let unlink = super::unlink_handoff_lease_failure_message("/tmp/group");

        for message in [&demotion, &unlink] {
            assert!(message.contains("confirmed a ready replica"));
            assert!(message.contains("could not obtain the required handoff lease"));
            assert!(
                !message.contains("no other full replica"),
                "lease failure must not be mislabeled as readiness failure: {message}"
            );
        }
    }

    /// The last full-replica device for a group cannot unlink it: with no
    /// other device known to store everything, unlinking would leave the group
    /// with no complete copy, so the guard refuses fail-closed.
    #[tokio::test]
    async fn last_full_replica_cannot_unlink() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        // A real file to hand off -- an empty group would be vacuously ready
        // regardless of any peer.
        upsert_solo_file(&state, "group-1");
        // Eager link (the default) => this device is a full replica. No peer
        // full-replica is recorded, so it is the last one.
        let err = super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", false)
            .await
            .expect_err("unlinking the only full replica must be refused");
        assert!(
            err.contains("no other full replica"),
            "error should explain the readiness refusal: {err}"
        );
    }

    /// Merely recording a peer as "also a full replica" is not enough on its
    /// own -- this is exactly the count-vs-readiness gap this guard closes.
    /// With no connected session to that peer, its confirmation can never be
    /// obtained, so unlinking must still be refused fail-closed.
    #[tokio::test]
    async fn recorded_peer_without_a_confirmed_ready_session_still_refused() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        upsert_solo_file(&state, "group-1");
        state.set_peer_group_full_replica("device-b", "group-1", true);

        let err = super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", false)
            .await
            .expect_err(
                "a recorded-but-unconfirmed peer must not be treated as a ready handoff target",
            );
        assert!(
            err.contains("no other full replica"),
            "error should explain the readiness refusal: {err}"
        );
    }

    /// A group with no current files at all has nothing to hand off, so
    /// unlinking it is vacuously allowed even with zero peers recorded.
    #[tokio::test]
    async fn full_replica_can_unlink_when_group_has_no_files() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();

        super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", false)
            .await
            .expect("nothing to hand off, so unlink is vacuously allowed");
    }

    /// `--force` bypasses the readiness gate for a genuinely dead sole
    /// replica -- the escape hatch, at the unit level (the surrounding CLI
    /// plumbing is exercised in `yadorilink-cli`'s own tests).
    #[tokio::test]
    async fn forced_unlink_bypasses_the_readiness_gate() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        upsert_solo_file(&state, "group-1");

        super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", true)
            .await
            .expect("--force must bypass the readiness gate even with no ready replica");
    }

    /// `--force` bypassing the readiness gate latches the group's local
    /// durability status to `DurabilityUnknown`: the UI must not be able to
    /// keep reporting the group Healthy/"synced" after an override that may
    /// have just discarded its only complete copy.
    #[tokio::test]
    async fn forced_unlink_latches_group_durability_unknown() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        upsert_solo_file(&state, "group-1");

        super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", true)
            .await
            .expect("--force must bypass the readiness gate even with no ready replica");

        assert_eq!(
            state.group_durability_status("group-1"),
            crate::daemon_state::GroupDurabilityStatus::DurabilityUnknown,
            "a force override must latch the group to DurabilityUnknown, never leave it \
             reporting Healthy"
        );
    }

    /// A normal (non-forced) unlink that succeeds without ever needing to
    /// bypass the gate must NOT latch the group -- the latch is specifically
    /// for when the gate was actually overridden, not every successful
    /// unlink.
    #[tokio::test]
    async fn non_forced_unlink_does_not_latch_durability_unknown() {
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        // Nothing to hand off, so this succeeds vacuously without needing
        // --force at all.

        super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", false)
            .await
            .expect("nothing to hand off, so unlink is vacuously allowed");

        assert_ne!(
            state.group_durability_status("group-1"),
            crate::daemon_state::GroupDurabilityStatus::DurabilityUnknown,
            "an unforced unlink must never latch the group's durability status"
        );
    }

    /// An on-demand device is a cache, not the group's durable holder, so it
    /// may always unlink regardless of any other full replica.
    #[tokio::test]
    async fn on_demand_device_can_always_unlink() {
        use yadorilink_sync_core::types::MaterializationPolicy;
        let state = test_state();
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        state
            .sync_state
            .set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand)
            .unwrap();

        super::ensure_unlink_keeps_a_full_replica(&state, "/home/alice/Photos", false)
            .await
            .expect("an on-demand device may always unlink");
    }

    /// The coordination plane's netmap push carries a `policyInvalidGroupIds`
    /// list naming groups whose stored policy state is malformed or corrupt
    /// on the coordination plane's side, so this device cannot trust
    /// anything it currently believes about that group's membership/auth.
    /// The daemon's netmap client never parses that list into anything (see
    /// `change_auth`'s and `peer_orchestrator`'s netmap-handling tests), so
    /// `mark_group_policy_stale` -- the one existing mechanism that would
    /// make a group's trouble visible here -- is never called for it either.
    ///
    /// `list_link_statuses` has no field at all carrying policy state, so a
    /// group whose policy this daemon knows to be stale is reported
    /// byte-for-byte identically to a perfectly healthy group: nothing
    /// distinguishes "policy corrupt, do not trust this group's state" from
    /// "everything is fine."
    #[tokio::test]
    async fn policy_invalid_group_id_surfaces_in_status() {
        let healthy_state = test_state();
        healthy_state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();

        let policy_invalid_state = test_state();
        policy_invalid_state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        // The closest real "policy invalid" signal the daemon can produce
        // today -- a real `policyInvalidGroupIds` entry never reaches this
        // call (that is exactly the gap), but this is the one state
        // transition `status` output would need to reflect once it does.
        policy_invalid_state.mark_group_policy_stale("group-1");

        let healthy_status = super::list_link_statuses(&healthy_state).unwrap();
        let policy_invalid_status = super::list_link_statuses(&policy_invalid_state).unwrap();

        assert_ne!(
            healthy_status, policy_invalid_status,
            "a policy-invalid group's status must be distinguishable from a healthy group's \
             (surfaced as something other than merely \"no peers\"), but list_link_statuses \
             carries no field for policy state at all, so the two are identical"
        );
    }

    /// `LatchGroupDurabilityUnknownRequest` -- the control request the
    /// CLI-orchestrated force paths (`durability_force.rs`) send for each
    /// group actually forced past the readiness gate, so `status` reports
    /// `DurabilityUnknown` for it exactly like the daemon-side forced-unlink
    /// path's own latch already does. Exercised through `handle_request`
    /// (the real dispatch a control-socket connection runs through), not the
    /// pub `latch_group_durability_unknown` method directly.
    #[tokio::test]
    async fn latch_group_durability_unknown_request_latches_the_group() {
        let state = test_state();
        assert_eq!(
            state.group_durability_status("group-1"),
            crate::daemon_state::GroupDurabilityStatus::Healthy,
            "sanity check: an untouched group with no files derives Healthy"
        );

        let req = DaemonControlRequest {
            payload: Some(ReqPayload::LatchGroupDurabilityUnknown(
                yadorilink_ipc_proto::daemonctl::LatchGroupDurabilityUnknownRequest {
                    group_id: "group-1".to_string(),
                },
            )),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let resp = super::handle_request(&state, req).await;
        assert!(
            matches!(resp.payload, Some(RespPayload::LatchGroupDurabilityUnknown(_))),
            "expected a LatchGroupDurabilityUnknown response, got {:?}",
            resp.payload
        );

        assert_eq!(
            state.group_durability_status("group-1"),
            crate::daemon_state::GroupDurabilityStatus::DurabilityUnknown,
            "the latch must take effect through the real request-dispatch path"
        );
    }

    /// A request shaped exactly the way older CLI builds built one — a
    /// real payload set, `protocol_version` left at its default (0)
    /// rather than the current daemon's own `CONTROL_PROTOCOL_VERSION` —
    /// is rejected before the payload is ever dispatched, not answered
    /// using backward-compatible defaults: this repository has not
    /// shipped a public release, so there is no supported skew to be
    /// lenient about.
    #[tokio::test]
    async fn old_cli_request_with_zero_protocol_version_is_rejected() {
        let state = test_state();
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::Status(StatusRequest {})),
            protocol_version: 0,
        };

        let resp = super::handle_request(&state, req).await;

        match resp.payload {
            Some(RespPayload::Error(msg)) => {
                assert!(
                    msg.contains("requires exactly protocol version"),
                    "expected a version-mismatch message, got {msg:?}"
                );
            }
            other => panic!("expected RespPayload::Error, got {other:?}"),
        }
        assert_eq!(
            resp.daemon_protocol_version,
            yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            "the daemon still stamps its own current version on the response even when \
             rejecting an old-shaped request"
        );
    }

    /// Stands in for a newer CLI build sending a request variant *this*
    /// daemon build has never heard of — protobuf drops an unrecognized
    /// oneof field number entirely, so from the daemon's point of view
    /// that decodes as `payload: None`, exactly as constructed here,
    /// alongside a `protocol_version` newer than what this daemon
    /// reports. The CLI must be told to upgrade the daemon, not given the
    /// same generic "empty request" a truly malformed/empty request gets
    /// — and the request must never reach payload dispatch to produce
    /// that message, since it's rejected by the upfront version check.
    #[tokio::test]
    async fn newer_client_unset_payload_reports_upgrade_the_daemon() {
        let state = test_state();
        let newer_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION + 1;
        let req = DaemonControlRequest { payload: None, protocol_version: newer_version };

        let resp = super::handle_request(&state, req).await;

        match resp.payload {
            Some(RespPayload::Error(msg)) => {
                assert!(
                    msg.contains("upgrade the daemon"),
                    "expected an upgrade-the-daemon message, got {msg:?}"
                );
            }
            other => panic!("expected RespPayload::Error, got {other:?}"),
        }
    }

    /// Control case for the test above: a genuinely empty/malformed
    /// request from a *version-matched* client (no payload, but the
    /// correct current `protocol_version`) gets the plain "empty
    /// request" message, not a version-mismatch one — the two failure
    /// modes stay distinguishable once the exact-version check passes.
    #[tokio::test]
    async fn truly_empty_request_still_reports_generic_empty_request() {
        let state = test_state();
        let req = DaemonControlRequest {
            payload: None,
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };

        let resp = super::handle_request(&state, req).await;

        assert_eq!(resp.payload, Some(RespPayload::Error("empty request".to_string())));
    }

    // --- One live link per group, at the daemon's own `link` seam -----------

    fn link_request(local_path: &str, group_id: &str, acknowledge_risks: bool) -> LinkRequest {
        LinkRequest {
            local_path: local_path.to_string(),
            group_id: group_id.to_string(),
            on_demand: false,
            max_local_size_bytes: None,
            acknowledge_risks,
            pending_enrollment_operation_id: String::new(),
            pending_enrollment_kind: 0,
            pending_enrollment_device_id: String::new(),
        }
    }

    /// `--yes` must NOT buy past this. The path-overlap checks in `link` are a
    /// warning gate deliberately gated on `!acknowledge_risks` -- a user may
    /// knowingly accept a nested link. A second live root on one folder group
    /// is not in that category at any confirmation level: each folder's scan
    /// would delete the other's files on every device. Routing this rule
    /// through `nested_conflicts` would silently inherit that bypass.
    #[tokio::test]
    async fn a_second_link_is_refused_even_with_acknowledge_risks() {
        let state = test_state();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        super::link(&state, link_request(&a.path().to_string_lossy(), "group-1", true)).unwrap();

        let err = super::link(&state, link_request(&b.path().to_string_lossy(), "group-1", true))
            .expect_err("--yes must not buy past the one-live-link-per-group rule");

        assert!(
            err.to_string().contains("already linked"),
            "the error must name the real problem, got {err}"
        );
        let links = state.sync_state.list_links().unwrap();
        assert_eq!(links.len(), 1, "the refusal must not add or delete a link");
        assert_eq!(links[0].local_path, a.path().to_string_lossy());
    }

    /// Re-linking the SAME folder to the same group is idempotent and must stay
    /// allowed: it is exactly what a `share join` retry does after a failed
    /// link's own rollback. A `!existing.is_empty()` check instead of
    /// `any(|p| p != &r.local_path)` would break that retry.
    #[tokio::test]
    async fn an_idempotent_same_path_relink_is_not_refused() {
        let state = test_state();
        let a = tempfile::tempdir().unwrap();
        let path = a.path().to_string_lossy().to_string();
        super::link(&state, link_request(&path, "group-1", true)).unwrap();

        super::link(&state, link_request(&path, "group-1", true))
            .expect("re-linking the same folder to the same group must stay idempotent");

        assert_eq!(state.sync_state.list_links().unwrap().len(), 1);
    }
}
