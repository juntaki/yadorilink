//! CLI ↔ daemon control protocol (tasks 7.1, 7.5, 7.6, 7.7): one
//! request/response exchange per connection, framed as length-prefixed
//! protobuf (`yadorilink_ipc_proto::framing`) over a Unix domain socket on
//! macOS/Linux, a named pipe on Windows (windows-local-ipc-support).
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
    ActiveTransferProgress, ConnectionAttemptTrace, ConnectivityDoctorCategory,
    ConnectivityDoctorResponse, DaemonControlRequest, DaemonControlResponse, EvictResponse,
    FileVersionInfo, FolderDivergenceSummaryResponse, FolderOperationAuditEntry,
    FolderResolutionConfirmResponse, FolderResolutionPreviewResponse, GcResponse, HealthResponse,
    HeldFile, HydrateResponse, LimitsSetResponse, LimitsShowResponse, LinkRequest, LinkResponse,
    LinkStatus, ListConnectionTracesResponse, ListFolderOperationAuditResponse, ListLinksResponse,
    ListTrashResponse, ListVersionsResponse, OverrideResponse, PauseResponse, PeerStatus,
    PinResponse, RecentSyncError, RestoreTrashResponse, RestoreVersionResponse, ResumeResponse,
    RevertResponse, SetModeResponse, SetRetentionPolicyResponse, ShutdownResponse, StatusResponse,
    TaskLiveness, TrashedFileInfo, UnlinkResponse, UnpinResponse, VolumeFreeSpace,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_sync_core::index::{RetentionPolicy, SyncState};
#[cfg(windows)]
use yadorilink_sync_core::types::RecordKind;
use yadorilink_sync_core::types::{ChunkingPolicy, LinkMode, MaterializationPolicy};

use crate::daemon_state::DaemonState;
use crate::hydration;
use crate::link_manager::{
    override_link, resume_link, revert_link, set_link_mode_and_reconcile, start_link_watch,
    stop_link_watch,
};
use crate::reporting_ipc;
use crate::shell_status::resolve_group_and_rel_path;

const MAX_CONTROL_CONNECTIONS: usize = 64;

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

/// Windows named-pipe transport (windows-local-ipc-support): verified
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
    // `!Send`. Constructing it (and calling `as_mut_ptr()` into it) inside a
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
    /// function created the next pipe instance *after* `connect().await`
    /// returned, leaving a window with zero listening instances between a
    /// client connecting and the replacement instance existing — a second
    /// client connecting concurrently in that window got `ERROR_PIPE_BUSY`
    /// ("All pipe instances are busy"), caught by
    /// `windows_pipe_tests::two_concurrent_clients_are_both_served`.
    /// Creating the next instance *before* awaiting the current one's
    /// `connect()` closes that window — there are always at least two
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
    // add-update-migration-safety task 1.1/2.3: read before `req.payload`
    // is matched (and partially moved) below — a `u32` copy, not a borrow,
    // so this doesn't fight the match on `req.payload` for ownership.
    // Absent on a request from a CLI build that predates this field,
    // decodes as 0, which is `< CONTROL_PROTOCOL_VERSION` and thus handled
    // by the same "older/unversioned client" branch below as a real old
    // version would be.
    let client_protocol_version = req.protocol_version;
    let payload = match req.payload {
        Some(ReqPayload::Link(r)) => match link(state, r) {
            Ok(()) => RespPayload::Link(LinkResponse {}),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Unlink(r)) => {
            stop_link_watch(state, &r.local_path);
            match state.sync_state.remove_link(&r.local_path) {
                Ok(()) => RespPayload::Unlink(UnlinkResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
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

        // add-folder-direction-modes task 4.2.
        Some(ReqPayload::SetMode(r)) => {
            match set_link_mode_and_reconcile(state, &r.local_path, LinkMode::from_db_str(&r.mode))
                .await
            {
                Ok(()) => RespPayload::SetMode(SetModeResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::Override(r)) => match override_link(state, &r.local_path).await {
            Ok(reconciled_count) => RespPayload::Override(OverrideResponse { reconciled_count }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Revert(r)) => match revert_link(state, &r.local_path).await {
            Ok(reverted_count) => RespPayload::Revert(RevertResponse { reverted_count }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // add-file-version-history task 5.2: `yadorilink versions <path>`.
        // Resolves the absolute path to `(group_id, relative path)` via the
        // same `resolve_group_and_rel_path` helper `Hydrate`/`Pin`/`Unpin`/
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

        // `yadorilink restore <path> [--version <id>]` (task 6.2). An
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

        // `yadorilink trash list` (task 6.3). Unlike the per-file requests
        // above, this spans every linked folder at once (no `absolute_path`
        // to resolve) — mirrors `list_link_statuses`'s own per-link
        // iteration below.
        Some(ReqPayload::ListTrash(_)) => match list_trashed_files(state) {
            Ok(files) => RespPayload::ListTrash(ListTrashResponse { files }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink trash restore <path>` (task 6.3).
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

        // `yadorilink link retention <path> --keep-versions <n> --keep-days
        // <t>` (task 6.4) — adjusts an already-linked folder's retention
        // policy in place; takes effect on the next retention-expiry sweep
        // (design D2), no restart needed since `link_manager::run_
        // retention_expiry_sweep` re-reads the policy from `SyncState` on
        // every sweep rather than caching it.
        Some(ReqPayload::SetRetentionPolicy(r)) => {
            match state.sync_state.set_retention_policy(
                &r.local_path,
                RetentionPolicy { max_versions: r.keep_versions, max_age_days: r.keep_days },
            ) {
                Ok(()) => RespPayload::SetRetentionPolicy(SetRetentionPolicyResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::Status(_)) => match list_link_statuses(state) {
            Ok(links) => {
                let peers = state
                    .peer_statuses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .map(|(device_id, info)| PeerStatus {
                        device_id: device_id.clone(),
                        connected: info.connected,
                        path_kind: info.path_kind.clone(),
                        // add-untrusted-storage-peer task 4.3: not yet
                        // populated here -- wiring this from the
                        // coordination-plane's storage-only ACL flag
                        // (`PeerInfo.storage_only_group_ids`) is a
                        // documented daemon-level follow-up (see
                        // tasks.md's notes); `yadorilink-daemon` is not one
                        // of this change's listed affected crates. Always
                        // `false` for now, which is exactly today's
                        // pre-existing behavior (no peer ever showed a
                        // storage-only badge before this field existed).
                        storage_only: false,
                    })
                    .collect();
                // add-resource-governance task 5.4: configured limits +
                // current measured rates (from the shared `rate_limiters`
                // every session/hydration fetch draws down, task 2.3) and
                // per-volume free-space state, alongside the existing
                // per-folder/per-peer status above.
                let governance = state.governance_config.load_or_default();
                let volumes = volumes_free_space(state, &links);
                // add-automatic-updates task 3.2: concise update state
                // embedded directly in `StatusResponse` — reuses
                // `update_ipc::status_response`'s exact field values
                // rather than re-deriving them a second way.
                let update_status = crate::update_ipc::status_response(state);
                // add-block-store-gc task 4.1: O(1) usage counters
                // (design D5) — never a directory walk on a `status` call.
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
                    // add-block-store-gc task 4.1: block-store usage
                    // (O(1) counters, design D5) and GC health, alongside
                    // every other status surface above.
                    block_store_total_bytes: block_store_usage.total_bytes,
                    block_store_block_count: block_store_usage.block_count,
                    last_gc_unix: state.gc.last_run_unix(),
                    gc_reclaimable_estimate_bytes: state.gc.reclaimable_estimate_bytes(),
                    // add-observability-and-metrics task 1.3/2.2: every
                    // currently-active transfer and the bounded recent-error
                    // feed, alongside every other status surface above.
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
                    // add-desktop-status-app task 1.1/1.2: filled in below,
                    // from `response`'s own already-populated fields, so
                    // this rollup can never disagree with the rest of the
                    // message it's summarizing.
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
                    // task 2.5: apply immediately to the running daemon's
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
            Some((group_id, path)) => match hydration::unpin(state, &group_id, &path) {
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
            // REL-4: route through the same graceful-shutdown path
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

        // add-oss-usage-error-reporting task 3.2: dispatch into
        // `reporting_ipc`, which owns the actual translation to/from
        // `yadorilink_reporting`/`crate::reporting` types.
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

        // add-automatic-updates task 3.3: dispatch into `update_ipc`,
        // which owns the actual translation to/from
        // `crate::update::{manager, policy}` types — mirrors
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

        // add-advanced-sync-operations section 2: dispatch into
        // `folder_ops`, which owns the actual divergence-summary/preview/
        // confirm/audit logic this just translates to/from the wire
        // types — mirrors `reporting_ipc`/`update_ipc`'s own dispatch
        // pattern above.
        Some(ReqPayload::FolderDivergenceSummary(r)) => {
            match crate::folder_ops::divergence_summary(state, &r.local_path) {
                Ok(summary) => {
                    RespPayload::FolderDivergenceSummary(FolderDivergenceSummaryResponse {
                        local_path: summary.local_path,
                        group_id: summary.group_id,
                        mode: summary.mode.as_db_str().to_string(),
                        paused: summary.paused,
                        out_of_sync_count: summary.out_of_sync_count,
                        out_of_sync_sample: summary.out_of_sync_sample,
                        receive_only_changed_count: summary.receive_only_changed_count,
                        receive_only_changed_sample: summary.receive_only_changed_sample,
                    })
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::FolderResolutionPreview(r)) => {
            match resolution_action_from_wire(&r.action, &r.target_mode) {
                Ok(action) => {
                    match crate::folder_ops::preview_resolution(state, &r.local_path, action) {
                        Ok(preview) => {
                            RespPayload::FolderResolutionPreview(FolderResolutionPreviewResponse {
                                preview_id: preview.preview_id,
                                local_path: preview.local_path,
                                action: preview.action.action.to_string(),
                                target_mode: preview
                                    .action
                                    .target_mode
                                    .map(|m| m.as_db_str().to_string())
                                    .unwrap_or_default(),
                                affected_count: preview.affected_count,
                                affected_paths_sample: preview.affected_paths_sample,
                                created_at_unix_nanos: preview.created_at_unix_nanos,
                            })
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                Err(e) => RespPayload::Error(e),
            }
        }

        Some(ReqPayload::FolderResolutionConfirm(r)) => {
            match crate::folder_ops::confirm_resolution(state, &r.preview_id).await {
                Ok(affected_count) => {
                    RespPayload::FolderResolutionConfirm(FolderResolutionConfirmResponse {
                        affected_count,
                    })
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::ListFolderOperationAudit(r)) => {
            let local_path = (!r.local_path.is_empty()).then_some(r.local_path.as_str());
            let entries = state
                .folder_ops
                .audit_entries(local_path)
                .into_iter()
                .map(|entry| FolderOperationAuditEntry {
                    local_path: entry.local_path,
                    action: entry.action.to_string(),
                    target_mode: entry
                        .target_mode
                        .map(|m| m.as_db_str().to_string())
                        .unwrap_or_default(),
                    affected_count: entry.affected_count,
                    resolved_at_unix_nanos: entry.resolved_at_unix_nanos,
                })
                .collect();
            RespPayload::ListFolderOperationAudit(ListFolderOperationAuditResponse { entries })
        }

        // add-advanced-sync-operations section 4: dispatch into
        // `connection_trace`.
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
                    relay_identity: trace.relay_identity,
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

        // add-diagnostics-support-bundle task 2.1/2.2: dispatch into
        // `diagnostics_ipc`, which owns the actual bundle assembly (from
        // existing status/config/update/recent-error sources) and the
        // bounded-time-budget handling (task 2.3) -- mirrors
        // `reporting_ipc`/`update_ipc`'s own dispatch pattern above.
        // Preview and Export both request the exact same daemon-side
        // bundle; only the CLI-side disposition of the result differs.
        Some(ReqPayload::DiagnosticsPreview(_)) => {
            RespPayload::DiagnosticsPreview(crate::diagnostics_ipc::build_bundle(state).await)
        }
        Some(ReqPayload::DiagnosticsExport(_)) => {
            RespPayload::DiagnosticsExport(crate::diagnostics_ipc::build_bundle(state).await)
        }

        // add-block-store-gc task 4.2: dispatch into `gc::run_sweep`,
        // which owns the actual mark-and-sweep, daemon-wide
        // mutual-exclusion, and never-mid-burst logic (tasks 3.2/3.5) --
        // this arm only translates to/from the wire types, mirroring
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

        // add-update-migration-safety task 2.3, spec "New CLI talks to
        // older supported daemon": an unset `oneof payload` is what a
        // *this* daemon build's proto decodes an unrecognized request
        // variant number as — the shape a newer CLI's request takes once
        // it reaches an older daemon that predates that variant entirely
        // (protobuf drops fields it has no definition for). Distinguish
        // that case, using the version each side already stamped on every
        // request/response, from a genuinely malformed/empty request, so
        // the CLI gets "upgrade the daemon" rather than an ambiguous
        // "empty request" for what's really a version mismatch.
        None if client_protocol_version
            > yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION =>
        {
            RespPayload::Error(format!(
                "this daemon (protocol version {}) does not support this request (client is \
                 protocol version {client_protocol_version}); upgrade the daemon and try again",
                yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            ))
        }
        None => RespPayload::Error("empty request".to_string()),
    };

    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    }
}

/// Registers a new link (task 7.5), plus on-demand-sync's materialization
/// policy/cap (task 5.1) — set *after* `add_link` so the row those setters
/// update-by-`local_path` already exists; `start_link_watch` itself
/// doesn't depend on the ordering (it never queries the links table for
/// the path it's given directly).
///
/// add-first-run-safety-onboarding task 2.3: defense-in-depth re-check,
/// independent of whatever the CLI already showed/gated. Scoped to
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
fn link(state: &Arc<DaemonState>, r: LinkRequest) -> Result<(), crate::error::DaemonError> {
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
    state.sync_state.add_link(&r.local_path, &r.group_id)?;
    // add-folder-direction-modes task 4.2/4.3: `--mode <mode>` at link
    // time. An empty `r.mode` (the CLI's unset default) decodes to
    // `LinkMode::SendReceive` via `from_db_str`'s own fallback — exactly
    // `add_link`'s own freshly-created-row default, so this is always
    // safe to call unconditionally rather than needing an `if let Some`
    // guard the way `on_demand`'s cap below does.
    state.sync_state.set_link_mode(&r.local_path, LinkMode::from_db_str(&r.mode))?;
    if r.on_demand {
        state
            .sync_state
            .set_materialization_policy(&r.local_path, MaterializationPolicy::OnDemand)?;
        if let Some(max_bytes) = r.max_local_size_bytes {
            state.sync_state.set_max_local_size_bytes(&r.local_path, Some(max_bytes))?;
        }
    }
    if r.content_defined_chunking {
        state.sync_state.set_chunking_policy(&r.local_path, ChunkingPolicy::ContentDefined)?;
    }
    // add-file-version-history task 5.2/6.4: `--keep-versions`/`--keep-days`
    // at link time. Only touch the retention-policy row if the caller
    // actually asked for a non-default value — matching `on_demand`'s/
    // `content_defined_chunking`'s "only touch it if the caller asked"
    // pattern above; the columns already default to 10/30 (design D2) via
    // the `links` table's own `DEFAULT`s, so calling `set_retention_policy`
    // unconditionally on every link would be harmless but sloppy.
    if r.keep_versions.is_some() || r.keep_days.is_some() {
        state.sync_state.set_retention_policy(
            &r.local_path,
            RetentionPolicy {
                max_versions: r.keep_versions.unwrap_or(10),
                max_age_days: r.keep_days.unwrap_or(30),
            },
        )?;
    }
    start_link_watch(state.clone(), r.local_path, r.group_id)?;
    Ok(())
}

/// add-file-version-history task 5.2: `VersionRecord` (sync-core) ->
/// `FileVersionInfo` (proto) — mirrors `LinkStatus`'s own by-field mapping
/// pattern from `yadorilink_sync_core` types elsewhere in this file.
/// Translates `FolderResolutionPreviewRequest`'s wire strings
/// ("override" | "revert" | "mode_change" + a `target_mode` only
/// meaningful for the last one) into `folder_ops::ResolutionAction`, or a
/// human-readable error for the CLI to surface directly (this validation
/// failure is a request-shape problem, not a `SyncError`, so it's built
/// as a `String` for `RespPayload::Error` here rather than routed through
/// `folder_ops` itself).
fn resolution_action_from_wire(
    action: &str,
    target_mode: &str,
) -> Result<crate::folder_ops::ResolutionAction, String> {
    match action {
        "override" => Ok(crate::folder_ops::ResolutionAction::Override),
        "revert" => Ok(crate::folder_ops::ResolutionAction::Revert),
        "mode_change" => {
            Ok(crate::folder_ops::ResolutionAction::ModeChange(LinkMode::from_db_str(target_mode)))
        }
        other => Err(format!(
            "unknown resolution action `{other}`; expected `override`, `revert`, or `mode_change`"
        )),
    }
}

fn version_to_proto(v: yadorilink_sync_core::index::VersionRecord) -> FileVersionInfo {
    FileVersionInfo {
        version_seq: v.version_seq,
        size: v.size as i64,
        mtime_unix_nanos: v.mtime_unix_nanos,
        state: v.state.as_db_str().to_string(),
        origin_device_id: v.origin_device_id.unwrap_or_default(),
    }
}

/// `yadorilink trash list` (task 6.3): flattens every linked folder's
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

/// REL-13: a lightweight health surface distinct from `StatusResponse`
/// (see `daemon_control.proto`'s `HealthResponse` doc comment) — task
/// liveness, relay connectivity, connected-peer count, and a process-wide
/// pending-changes total, all cheap to compute from state already held in
/// memory (no SQLite queries, unlike `list_link_statuses`).
pub(crate) fn health_snapshot(state: &DaemonState) -> HealthResponse {
    let tasks = state
        .task_liveness
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .map(|(name, alive)| TaskLiveness { name: name.clone(), alive: *alive })
        .collect();

    let peer_statuses = state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let connected_peer_count = peer_statuses.values().filter(|info| info.connected).count() as u32;
    // Approximation: `RelayHub`'s own connection state isn't currently
    // threaded through `peer_orchestrator` into `DaemonState` (that
    // would be a `peer_orchestrator.rs` change, out of this module's
    // scope), so "at least one peer is connected" stands in for "the
    // relay hub this device shares across all peer sessions is up" —
    // true whenever any peer session exists (this design is relay-first,
    // per `peer_orchestrator`'s module docs), but it can't distinguish
    // "relay is down" from "no peers are online right now" when the
    // connected-peer count is zero. Flagged as a follow-up.
    let relay_connected = connected_peer_count > 0;

    HealthResponse {
        tasks,
        relay_connected,
        connected_peer_count,
        pending_changes: state.total_pending_changes(),
    }
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
        let open_elsewhere_count = state.open_elsewhere_count(&link.group_id);
        // add-sync-fidelity task 5.3: held-file and skipped-symlink status
        // (design.md D1/D3), populated from section 1's per-file
        // `SyncState` getters. Deliberately `get_held_state`/
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
        let windows_symlink_opt_in =
            state.sync_state.windows_symlink_opt_in_for_group(&link.group_id)?;
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
        // add-resource-governance task 3.4/5.4: independent of `paused`
        // (a link can be paused and/or degraded at once — see
        // `DegradedLinkInfo`'s doc comment).
        let degraded_info = state.degraded_link_info(&link.local_path);
        // add-folder-direction-modes task 4.2/4.3: divergence counts are
        // meaningless (always 0) for a link not in the corresponding mode
        // — `count_out_of_sync`/`count_receive_only_changed` themselves
        // stay accurate regardless (nothing produces a stray entry for the
        // "wrong" mode), so this is just the by-group_id lookup, not a
        // mode-conditional query.
        let out_of_sync_count = state.sync_state.count_out_of_sync(&link.group_id)?;
        let receive_only_changed_count =
            state.sync_state.count_receive_only_changed(&link.group_id)?;
        // add-observability-and-metrics task 1.2: this link's active-
        // transfer rollup, if any is currently in flight.
        let rollup = state.transfer_progress.link_rollup(&link.group_id);
        out.push(LinkStatus {
            local_path: link.local_path.clone(),
            group_id: link.group_id.clone(),
            paused: link.paused,
            // REL-10: records still queued for retry (see
            // `DaemonState::pending_changes_count`'s doc comment) after a
            // failed per-peer broadcast — previously always hardcoded 0.
            pending_changes: state.pending_changes_count(&link.group_id),
            conflict_count,
            materialization_policy: link.materialization_policy.as_db_str().to_string(),
            hydrated_count: materialization.hydrated,
            placeholder_count: materialization.placeholder,
            hydrating_count: materialization.hydrating,
            open_elsewhere_count,
            chunking_policy: link.chunking_policy.as_db_str().to_string(),
            held_file_count,
            held_files,
            skipped_symlink_count,
            degraded: degraded_info.is_some(),
            degraded_reason: degraded_info.map(|info| info.reason).unwrap_or_default(),
            mode: link.mode.as_db_str().to_string(),
            out_of_sync_count,
            receive_only_changed_count,
            // add-observability-and-metrics task 1.2/1.3: this link's
            // active-transfer rollup — absent (all zero,
            // `has_active_transfer = false`) when nothing is currently
            // in flight for this link.
            has_active_transfer: rollup.is_some(),
            transfer_bytes_done: rollup.map(|r| r.bytes_done).unwrap_or(0),
            transfer_bytes_total: rollup.map(|r| r.bytes_total).unwrap_or(0),
            transfer_blocks_done: rollup.map(|r| r.blocks_done).unwrap_or(0),
            transfer_blocks_total: rollup.map(|r| r.blocks_total).unwrap_or(0),
            transfer_eta_seconds: rollup.and_then(|r| r.eta_seconds).unwrap_or(0),
        });
    }
    Ok(out)
}

/// add-resource-governance task 1.3/5.4: free-space state for every volume
/// hosting the block store or a linked folder — the block-store root (via
/// `BlockStore::free_space`, `None` for a backend with no real volume
/// concept) plus one entry per distinct link `local_path` (paths can
/// collide if a device somehow links the same directory twice, so this
/// dedups by path rather than by link count). Best-effort: a link whose
/// volume can't currently be queried (e.g. the folder was removed from
/// disk without being unlinked) is silently skipped rather than failing
/// the whole `status` response.
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

/// add-sync-fidelity task 5.3: whether `path` is a symlink record this
/// device's index tracks (and still syncs normally, per design.md D1/
/// task 4.4) but never materialized to disk under the Windows
/// default-skip-with-visible-status policy (task 3.2) — i.e. the local
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

/// add-desktop-status-app task 1.1/1.2: `StatusResponse.overall_state`'s
/// three values, kept as a small internal enum (rather than juggling raw
/// strings below) purely so the precedence rules below read clearly; the
/// wire format is still the plain lowercase string this converts to via
/// `as_str()`, matching every other string-typed status enum in this
/// message (`LinkStatus.mode`, `VolumeFreeSpace.state`, ...).
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

/// add-desktop-status-app task 1.1/1.2 (design.md decision 3, spec's
/// "Aggregate Sync Status"/"Sync needs attention" scenarios): rolls up
/// every already-populated field on `response` into one glanceable
/// `(state, reasons)` pair, computed daemon-side so a UI client (or the
/// CLI, task 1.3) never has to re-derive "is anything wrong?" itself and
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
        if !peer.connected {
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

    /// spec "Sync needs attention": a disconnected account/device (peer)
    /// needs attention.
    #[test]
    fn disconnected_peer_is_attention() {
        let response = StatusResponse {
            peers: vec![PeerStatus {
                device_id: "device-b".into(),
                connected: false,
                ..Default::default()
            }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Attention);
        assert_eq!(reasons, vec!["peer_disconnected:device-b".to_string()]);
    }

    /// A degraded link (disk-pressure, task 5.4 elsewhere) takes
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

// --- add-update-migration-safety task 2.3: old-CLI/new-daemon and
// new-CLI/old-daemon compatibility, exercised directly against
// `handle_request` (the actual dispatch a real control-socket connection
// runs through) rather than only at the wire-decode level (see
// `yadorilink_ipc_proto`'s own `old_daemon_control_request_bytes_decode_
// with_zero_protocol_version`/`..._response_...` tests for that layer).

#[cfg(test)]
mod migration_safety_tests {
    use std::sync::Arc;

    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, StatusRequest};
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    use crate::daemon_state::DaemonState;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// Spec "Old CLI talks to newer daemon": a request shaped exactly the
    /// way every CLI build before this task built one — a real payload
    /// set, `protocol_version` left at its default (0) rather than the
    /// current daemon's own `CONTROL_PROTOCOL_VERSION` — is handled
    /// normally using backward-compatible defaults, not rejected just
    /// because the version field is unset.
    #[tokio::test]
    async fn old_cli_request_with_zero_protocol_version_still_succeeds() {
        let state = test_state();
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::Status(StatusRequest {})),
            protocol_version: 0,
        };

        let resp = super::handle_request(&state, req).await;

        assert!(
            matches!(resp.payload, Some(RespPayload::Status(_))),
            "an old-shaped (unversioned) request must still get a normal response, not an \
             error: {:?}",
            resp.payload
        );
        assert_eq!(
            resp.daemon_protocol_version,
            yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            "the daemon still stamps its own current version on the response even when \
             answering an old-shaped request"
        );
    }

    /// Spec "New CLI talks to older supported daemon": stands in for a
    /// newer CLI sending a request variant *this* daemon build has never
    /// heard of — protobuf drops an unrecognized oneof field number
    /// entirely, so from the daemon's point of view that decodes as
    /// `payload: None`, exactly as constructed here, alongside a
    /// `protocol_version` newer than what this daemon reports. The CLI
    /// must be told to upgrade the daemon, not given the same generic
    /// "empty request" a truly malformed/empty request gets.
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
    /// request (no payload, and no newer-than-this-daemon version either)
    /// still gets the plain "empty request" message, not the
    /// version-mismatch one — the two failure modes stay distinguishable.
    #[tokio::test]
    async fn truly_empty_request_still_reports_generic_empty_request() {
        let state = test_state();
        let req = DaemonControlRequest { payload: None, protocol_version: 0 };

        let resp = super::handle_request(&state, req).await;

        assert_eq!(resp.payload, Some(RespPayload::Error("empty request".to_string())));
    }
}
