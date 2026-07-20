mod http {
    //! HTTP client for the coordination service's `/shares/*` routes.
    //! Sharing is roleless: every authorized device is a full bidirectional
    //! peer, so grants carry no read/write distinction.

    use serde::{Deserialize, Serialize};
    use uuid::Uuid;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        CheckFullReplicaHandoffReadyRequest, ListLinksRequest, PendingEnrollmentKind,
        RemovePendingEnrollmentRequest, SetStorageModeRequest,
    };

    use crate::control_client;
    use crate::error::CliError;
    use crate::http_client::{
        coordination_http_addr, get_json, post_json, post_json_no_content, require_access_token,
    };
    // Reuses the daemon crate's own activate/`ActivateOutcome` classification
    // rather than re-deriving it here: `coordination_client::post_activate`
    // already distinguishes a confirmed 404 (`Deleted`) from every other
    // failure (`TransientFailure` -- network error, timeout, or any other
    // non-2xx status), which is exactly the ambiguous-vs-confirmed
    // distinction `activate_disposition` below needs. `pending_enrollment
    // ::reconcile` (this same daemon crate) already relies on this exact
    // classification for its own retry logic, so this keeps the CLI and the
    // daemon's reconciliation sweep reading the SAME signal from the
    // coordination plane instead of two independently-maintained ones.
    use yadorilink_daemon::coordination_client::{activate_create, activate_join, ActivateOutcome};

    /// Maps the `--storage-mode` value to the daemon's `on_demand` flag:
    /// `eager` (store everything) links a fully-hydrated folder; `on-demand`
    /// (store only needed files) creates placeholders fetched on first access.
    fn parse_storage_mode(mode: &str) -> Result<bool, CliError> {
        match mode.to_ascii_lowercase().as_str() {
            "eager" | "everything" => Ok(false),
            "on-demand" | "ondemand" | "needed" => Ok(true),
            other => Err(CliError::Other(format!(
                "invalid --storage-mode {other:?} (expected eager or on-demand)"
            ))),
        }
    }

    /// The device id registered on this machine, or a friendly error pointing
    /// the user at `device register`.
    fn local_device_id() -> Result<String, CliError> {
        crate::device_config::load()
            .map_err(|_| {
                CliError::Other(
                    "no local device registered — run `yadorilink device register` first"
                        .to_string(),
                )
            })
            .map(|cfg| cfg.device_id)
    }

    #[derive(Deserialize)]
    struct FolderGroupInfo {
        group_id: String,
        name: String,
    }
    #[derive(Deserialize)]
    struct ListGroupsResponse {
        groups: Vec<FolderGroupInfo>,
    }

    /// A folder group the account owns. Typed result for library callers: the
    /// add-folder picker (CLI and desktop onboarding alike) offers one of
    /// these per group.
    pub struct GroupSummary {
        pub group_id: String,
        pub name: String,
    }

    /// List the account's folder groups
    /// so a caller can offer one to link a new folder into. Reuses the same
    /// `/shares/groups` route `resolve_group_id` uses.
    pub async fn list_groups() -> Result<Vec<GroupSummary>, CliError> {
        let access_token = require_access_token()?;
        let resp: ListGroupsResponse = get_json("/shares/groups", Some(&access_token)).await?;
        Ok(resp
            .groups
            .into_iter()
            .map(|g| GroupSummary { group_id: g.group_id, name: g.name })
            .collect())
    }

    /// Folder groups are addressed by human-readable name on the CLI, but
    /// the coordination plane's ACL routes take a `group_id` (assigned at
    /// creation) — resolve the name here rather than exposing the internal
    /// id to users. Shared with `commands::link`, which links a local
    /// directory to a group by name.
    pub async fn resolve_group_id(
        access_token: &str,
        group_name: &str,
    ) -> Result<String, CliError> {
        let resp: ListGroupsResponse = get_json("/shares/groups", Some(access_token)).await?;
        resp.groups.into_iter().find(|g| g.name == group_name).map(|g| g.group_id).ok_or_else(
            || {
                CliError::Other(format!(
                    "no folder group named {group_name:?} (run `yadorilink share create` first)"
                ))
            },
        )
    }

    // The coordination plane reads camelCase JSON keys (`creatingDeviceId`,
    // `deviceId`, `storageMode`); these request bodies must serialize to match,
    // or the field arrives undefined server-side. `CreateGroupRequest` has no
    // production caller anymore (the direct create route it once addressed is
    // gone -- `create_and_link` uses `PrepareCreateRequest` instead), but its
    // camelCase-serialization contract is still pinned by the unit test below,
    // so it stays test-only rather than being deleted outright.
    #[cfg(test)]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CreateGroupRequest<'a> {
        name: &'a str,
        creating_device_id: &'a str,
    }
    #[derive(Deserialize)]
    struct CreateGroupResponse {
        group_id: String,
    }

    // --- crash-safe Pending -> Active enrollment ----------------------------
    //
    // `create_and_link` and `join` (further down) authorize a device on the
    // coordination plane and only then commit a matching local link. The
    // coordination plane's explicit Pending -> Active protocol (its 0016
    // migration and shares service) is what keeps that crash-safe: prepare
    // authorizes a Pending row that is excluded from every netmap/replica-count
    // read there, activate confirms it once the local link is real, and cancel
    // is the compensating delete for a still-Pending row when a step fails.
    // Every one is idempotent by `operationId`, generated fresh per attempt.

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdBody<'a> {
        operation_id: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PrepareCreateRequest<'a> {
        operation_id: &'a str,
        name: &'a str,
        creating_device_id: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PrepareJoinRequest<'a> {
        operation_id: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JoinOperationBody<'a> {
        operation_id: &'a str,
        device_id: &'a str,
    }

    /// Confirms to the daemon that a pending-enrollment marker's
    /// coordination-plane activation succeeded (or was compensated), so it
    /// can drop the marker now instead of waiting for its own
    /// `PENDING_ENROLLMENT_RECONCILE_SWEEP_INTERVAL`-paced sweep to notice
    /// the same thing. Best-effort: if the daemon is unreachable, the
    /// marker simply survives until that sweep runs, exactly as if this
    /// call had never been made -- correctness never depends on it landing.
    async fn remove_pending_enrollment_marker(operation_id: &str) {
        if let Err(e) = control_client::send(ReqPayload::RemovePendingEnrollment(
            RemovePendingEnrollmentRequest { operation_id: operation_id.to_string() },
        ))
        .await
        {
            tracing::debug!(
                operation_id,
                error = %e,
                "failed to confirm pending-enrollment marker removal with the daemon; its own \
                 reconciliation sweep will clean it up"
            );
        }
    }

    /// Bounded, backed-off, logged retries for a compensating cancel call
    /// (CREATE's `/cancel` or JOIN's `/join/cancel`) — the immediate
    /// compensation for a create/join whose local link or activate step
    /// failed. Every failed attempt is logged with `operation_id` so one
    /// enrollment's whole retry history is findable after the fact. A cancel
    /// that outlasts every attempt is NOT escalated to the user as a second
    /// error — the coordination plane's TTL sweep terminally removes a
    /// still-Pending row that was never canceled, so the original failure is
    /// what gets reported.
    async fn cancel_with_retries<B: Serialize>(
        path: &str,
        body: &B,
        access_token: &str,
        operation_id: Uuid,
    ) {
        const MAX_ATTEMPTS: u32 = 3;
        const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);
        for attempt in 1..=MAX_ATTEMPTS {
            if post_json_no_content(path, body, Some(access_token)).await.is_ok() {
                return;
            }
            tracing::warn!(
                %operation_id,
                path,
                attempt,
                max_attempts = MAX_ATTEMPTS,
                "create/join enrollment compensation (cancel) failed; retrying"
            );
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
        }
        tracing::warn!(
            %operation_id,
            path,
            "enrollment compensation exhausted its retries; leaving the still-Pending row for the coordination plane's TTL sweep"
        );
    }

    /// What to do locally once a create/join's activate call has resolved,
    /// given as an [`ActivateOutcome`] rather than a raw HTTP success/failure
    /// so a lost RESPONSE (a transport error, timeout, or 5xx -- all folded
    /// into `TransientFailure` by `coordination_client::post_activate`) is
    /// distinguishable from an explicit, confirmed "this operation was never
    /// activated" (`Deleted`, a 404). Every prior version of `create_and_link`
    /// / `join` rolled back (unlinked + canceled + dropped the marker) on ANY
    /// activate failure -- including `TransientFailure`, where the
    /// coordination plane may already have committed the activation and only
    /// the response never arrived. That wrongly deleted a real local link
    /// (and its marker) out from under a coordination-plane row the plane
    /// itself still considers Active, reintroducing exactly the
    /// phantom-full-replica-without-a-local-copy hazard this whole
    /// enrollment protocol exists to prevent (just with the phantom now on
    /// the *coordination* side instead of the local one).
    enum ActivateDisposition {
        /// Activated, or already active (a retry of an idempotent call) --
        /// drop the marker and report success.
        Finalize,
        /// Confirmed permanently gone -- the ONLY outcome that rolls back
        /// (unlink + cancel + drop the marker), because this is the one case
        /// where the coordination plane has definitively said it never
        /// committed.
        RollBack,
        /// Unconfirmed: a transport error, timeout, 5xx, or any other
        /// unclassifiable failure. The coordination plane MAY have already
        /// committed this activation -- fail safe by doing nothing
        /// destructive. The local link and its pending-enrollment marker are
        /// left exactly as they are; the daemon's own reconciliation sweep
        /// (`pending_enrollment::reconcile`) is what resolves it from here,
        /// by retrying activate once the plane is reachable again and either
        /// finalizing (already committed) or rolling back (confirmed never
        /// committed).
        LeaveForReconcile,
    }

    fn activate_disposition(outcome: ActivateOutcome) -> ActivateDisposition {
        match outcome {
            ActivateOutcome::Success | ActivateOutcome::AlreadyActive => {
                ActivateDisposition::Finalize
            }
            ActivateOutcome::Deleted => ActivateDisposition::RollBack,
            // Fail-safe default: anything that isn't a clear, confirmed
            // "never activated" answer is treated as ambiguous, never as a
            // rollback trigger.
            ActivateOutcome::TransientFailure => ActivateDisposition::LeaveForReconcile,
        }
    }

    /// Create a group and link an already-resolved, already-preflighted local
    /// path to it, using the coordination plane's crash-safe Pending -> Active
    /// enrollment: prepare a Pending group (plus the creating device's Pending
    /// eager membership), commit the local link, then activate. If the LINK
    /// step fails, or activate comes back with a CONFIRMED "never activated"
    /// answer, the still-Pending group is canceled (retried) and the local
    /// link is rolled back, so no phantom full replica (an eager server edge
    /// with no local copy) is ever left counted. If activate instead comes
    /// back AMBIGUOUS (the response was lost, but the coordination plane may
    /// already have committed it), nothing is rolled back -- see
    /// `activate_disposition`'s doc comment for why guessing wrong there is
    /// exactly as dangerous as the phantom this whole protocol prevents, just
    /// on the opposite side. Returns the new group id. Shared by the CLI
    /// `create` command (which preflights first) and the desktop onboarding
    /// wizard (which preflighted in its preview step).
    ///
    /// Crash safety has three layers: (1) the immediate compensation here
    /// (only for a confirmed failure); (2) a pending-enrollment marker the
    /// daemon writes atomically with the link commit itself, reconciled by
    /// its own startup and periodic sweeps -- this is what resolves an
    /// ambiguous activate outcome, by retrying it once the coordination plane
    /// is reachable again, as well as covering THIS process being killed
    /// before activate/cancel finishes; and (3) the coordination plane's own
    /// TTL sweep of any Pending row that is never activated. `operation_id`
    /// (logged throughout) ties one enrollment's records together across the
    /// CLI and daemon logs.
    pub async fn create_and_link(
        group_name: String,
        absolute_path: std::path::PathBuf,
        on_demand: bool,
        acknowledge_risks: bool,
    ) -> Result<String, CliError> {
        let access_token = require_access_token()?;
        let device_id = local_device_id()?;
        let operation_id = Uuid::new_v4();
        let operation_id_str = operation_id.to_string();

        // PREPARE: authorize a Pending group + the creating device's Pending
        // eager membership. Neither counts anywhere the plane treats a row as
        // real until activate, so a crash before then leaves nothing phantom.
        let prepared: CreateGroupResponse = post_json(
            "/shares/groups/prepare",
            &PrepareCreateRequest {
                operation_id: &operation_id_str,
                name: &group_name,
                creating_device_id: &device_id,
            },
            Some(&access_token),
        )
        .await?;
        let group_id = prepared.group_id;
        tracing::debug!(
            %operation_id,
            %group_id,
            "create_and_link: pending group prepared; committing local link"
        );

        // Commit the local link and its pending-enrollment marker together:
        // the daemon writes both in one SQLite transaction
        // (`SyncState::add_link_with_pending_enrollment`), so a failure here
        // means neither exists -- there is no window where a real link
        // exists with no marker (or vice versa). On failure, compensate by
        // canceling the still-Pending group; nothing local needs cleaning up.
        let local_path = absolute_path.to_string_lossy().to_string();
        if let Err(link_err) = crate::commands::link::link_resolved_with_mode(
            absolute_path,
            group_id.clone(),
            on_demand,
            acknowledge_risks,
            Some(crate::commands::link::PendingEnrollmentFields {
                operation_id: operation_id_str.clone(),
                kind: PendingEnrollmentKind::Create,
                device_id,
            }),
        )
        .await
        {
            cancel_with_retries(
                &format!("/shares/groups/{group_id}/cancel"),
                &OperationIdBody { operation_id: &operation_id_str },
                &access_token,
                operation_id,
            )
            .await;
            return Err(link_err);
        }

        // ACTIVATE: flip the Pending group + creator edge to real. Only a
        // CONFIRMED "never activated" outcome rolls the local link back and
        // cancels the still-Pending group -- an ambiguous outcome (the
        // response was lost, but the plane may have already committed)
        // leaves the local link AND its pending-enrollment marker exactly as
        // they are, so the daemon's own reconciliation sweep can resolve it
        // instead of this process guessing wrong. See `activate_disposition`'s
        // doc comment.
        let outcome =
            activate_create(&coordination_http_addr(), &access_token, &group_id, &operation_id_str)
                .await;
        match activate_disposition(outcome) {
            ActivateDisposition::Finalize => {
                remove_pending_enrollment_marker(&operation_id_str).await;
                Ok(group_id)
            }
            ActivateDisposition::RollBack => {
                let _ = crate::commands::link::send_unlink(&local_path, false).await;
                cancel_with_retries(
                    &format!("/shares/groups/{group_id}/cancel"),
                    &OperationIdBody { operation_id: &operation_id_str },
                    &access_token,
                    operation_id,
                )
                .await;
                remove_pending_enrollment_marker(&operation_id_str).await;
                Err(CliError::Other(format!(
                    "folder group {group_id} activation (operation {operation_id_str}) was not \
                     confirmed by the coordination plane; rolled back the local link"
                )))
            }
            ActivateDisposition::LeaveForReconcile => {
                Err(CliError::EnrollmentPendingReconciliation(format!(
                    "could not confirm activation of folder group {group_id} with the \
                     coordination plane (operation {operation_id_str}); the local link and the \
                     daemon's pending-enrollment marker were kept so the daemon can retry and \
                     finish this automatically once the coordination plane is reachable again"
                )))
            }
        }
    }

    /// Create a new folder group and link it locally in one step. The creating
    /// device becomes the group's first full replica ('eager'), so a local copy
    /// must exist before the group is advertised. The local path is preflighted
    /// BEFORE the group is created, and if the local link cannot be established
    /// the just-created group is deleted — so a failed create never leaves a
    /// phantom full replica (an eager server edge with no local copy).
    pub async fn create(group_name: String, path: String, yes: bool) -> Result<(), CliError> {
        // Preflight the local path first, before any coordination-plane state
        // exists, so the common failure (a bad or risky folder) never creates a
        // group at all.
        let (absolute, acknowledged) =
            crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
        // The creating device is the group's first full replica: link eagerly.
        let group_id = create_and_link(group_name, absolute, false, acknowledged).await?;
        println!("Created folder group {group_id} and linked it at {path}");
        Ok(())
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DeviceIdBody<'a> {
        device_id: &'a str,
    }

    pub async fn grant(group_name: String, device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        post_json_no_content(
            &format!("/shares/groups/{group_id}/grant"),
            &DeviceIdBody { device_id: &device_id },
            Some(&access_token),
        )
        .await?;
        println!("Granted {device_id} access to {group_name}");
        Ok(())
    }

    /// `yadorilink share revoke <group> <device> [--force]`. Before touching
    /// the coordination plane, asks the local daemon whether `device_id`
    /// giving up this group would leave it without a confirmed-ready full
    /// replica (see `commands::durability_force`'s doc comment for why this
    /// is advisory and layered on top of the Worker's own count guard, not a
    /// replacement for it). `--force` bypasses a refusal with a data-loss
    /// warning and an audit log line; without it, an unready revoke is
    /// refused before any coordination-plane write happens at all.
    pub async fn revoke(
        group_name: String,
        device_id: String,
        force: bool,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let outcome = crate::commands::durability_force::guard_against_forced_replica_loss(
            "revoke this device's access",
            Some(group_id.clone()),
            &device_id,
            force,
        )
        .await?;
        // A cross-device removal that went through the removed-device-ticket
        // path already performed the revoke itself, atomically bound to the
        // lease it presented -- see `RemovalOutcome`'s doc comment. Issuing
        // the plain revoke below too would be the exact time-of-check/
        // time-of-use gap this fix closes, so it only runs when the guard
        // reports there is still a plain call left to make.
        if outcome == crate::commands::durability_force::RemovalOutcome::ProceedWithPlainCall {
            post_json_no_content(
                &format!("/shares/groups/{group_id}/revoke"),
                &DeviceIdBody { device_id: &device_id },
                Some(&access_token),
            )
            .await?;
        }
        println!("Revoked {device_id} access to {group_name}");
        Ok(())
    }

    /// `yadorilink share revoke <edge-id> [--force]`. Resolves the edge's
    /// `group_id`/`device_id` from the account's own edge listing first so
    /// the same durability readiness gate `revoke` runs can be applied here
    /// too; an edge that can't be found in that listing (already revoked, or
    /// belongs to a different account view) skips the gate and lets the
    /// delete call report the real outcome.
    pub async fn revoke_edge(edge_id: String, force: bool) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let resp: ListSharesResponse = get_json("/shares", Some(&access_token)).await?;
        // As with `revoke` above: a cross-device removal that already went
        // through the removed-device-ticket path has performed the revoke
        // itself, atomically bound to the presented lease -- the plain
        // per-edge delete below must be skipped in that case, never issued
        // as a redundant unconditional follow-up.
        let mut already_completed = false;
        if let Some(edge) = resp.edges.iter().find(|e| e.edge_id == edge_id) {
            let outcome = crate::commands::durability_force::guard_against_forced_replica_loss(
                "revoke this share edge",
                Some(edge.group_id.clone()),
                &edge.device_id,
                force,
            )
            .await?;
            already_completed =
                outcome == crate::commands::durability_force::RemovalOutcome::AlreadyCompleted;
        }
        if !already_completed {
            post_json_no_content::<()>(&format!("/shares/{edge_id}"), &(), Some(&access_token))
                .await?;
        }
        println!("Revoked share edge: {edge_id}");
        Ok(())
    }

    #[derive(Deserialize)]
    struct ShareEdgeInfo {
        edge_id: String,
        group_id: String,
        group_name: String,
        device_id: String,
    }
    #[derive(Deserialize)]
    struct ListSharesResponse {
        edges: Vec<ShareEdgeInfo>,
    }

    fn share_edge_line(edge: &ShareEdgeInfo) -> String {
        format!(
            "{}  group={} ({})  device={}",
            edge.edge_id, edge.group_name, edge.group_id, edge.device_id
        )
    }

    pub async fn list_shares() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let resp: ListSharesResponse = get_json("/shares", Some(&access_token)).await?;
        for edge in resp.edges {
            println!("{}", share_edge_line(&edge));
        }
        Ok(())
    }

    #[derive(Deserialize)]
    struct JoinableGroupInfo {
        group_id: String,
        name: String,
    }
    #[derive(Deserialize)]
    struct ListJoinableResponse {
        groups: Vec<JoinableGroupInfo>,
    }

    /// The folder groups this account owns and may join on this device.
    /// Typed result for library callers (the desktop onboarding folder-picker
    /// offers this list). Identity only: name/id, never file names or content.
    pub async fn list_joinable_groups() -> Result<Vec<GroupSummary>, CliError> {
        let access_token = require_access_token()?;
        let resp: ListJoinableResponse = get_json("/shares/joinable", Some(&access_token)).await?;
        Ok(resp
            .groups
            .into_iter()
            .map(|g| GroupSummary { group_id: g.group_id, name: g.name })
            .collect())
    }

    /// `yadorilink share joinable`: print the folder groups this account owns
    /// and can join on this device.
    pub async fn list_joinable() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let resp: ListJoinableResponse = get_json("/shares/joinable", Some(&access_token)).await?;
        if resp.groups.is_empty() {
            println!("No joinable folder groups. Create one with `yadorilink share create`.");
        }
        for group in resp.groups {
            println!("{}  ({})", group.name, group.group_id);
        }
        Ok(())
    }

    /// Resolve a joinable folder group by its human-readable name to its
    /// `group_id`, searching the account's owned joinable set.
    async fn resolve_joinable_group_id(
        access_token: &str,
        group_name: &str,
    ) -> Result<String, CliError> {
        let resp: ListJoinableResponse = get_json("/shares/joinable", Some(access_token)).await?;
        resp.groups.into_iter().find(|g| g.name == group_name).map(|g| g.group_id).ok_or_else(
            || {
                CliError::Other(format!(
                    "no joinable folder group named {group_name:?} (run `yadorilink share joinable` \
                     to see what this account can join)"
                ))
            },
        )
    }

    /// The coordination plane's storage-mode string for a link's `on_demand`
    /// flag: an eager (store-everything) full replica, or an on-demand cache.
    fn storage_mode_str(on_demand: bool) -> &'static str {
        if on_demand {
            "on-demand"
        } else {
            "eager"
        }
    }

    /// `yadorilink share join <group> --path <dir> --storage-mode <mode>`:
    /// same-account onboarding. Authorizes this device for the selected folder
    /// group and links it locally at `--path`, via the same crash-safe
    /// Pending -> Active enrollment as `create_and_link` (JOIN's
    /// prepare/activate/cancel routes rather than the direct `/join` route):
    /// prepare a Pending membership (excluded from every netmap/replica read
    /// until activated), commit the local link, then activate. A failure at
    /// the link step, or a CONFIRMED "never activated" activate outcome,
    /// cancels only the Pending membership (never the group) and rolls the
    /// local link back; an AMBIGUOUS activate outcome instead leaves the
    /// local link and its marker in place for the daemon's reconciliation
    /// sweep -- see `create_and_link`'s doc comment (identical reasoning) and
    /// `activate_disposition`'s.
    pub async fn join(
        group_name: String,
        path: String,
        storage_mode: String,
        yes: bool,
    ) -> Result<(), CliError> {
        let on_demand = parse_storage_mode(&storage_mode)?;
        let access_token = require_access_token()?;
        let group_id = resolve_joinable_group_id(&access_token, &group_name).await?;

        // Preflight/resolve the local path first, before any coordination-plane
        // state, so the common failure (a bad or risky folder) never prepares
        // an enrollment.
        let (absolute, acknowledged) =
            crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
        join_resolved(group_id, group_name, absolute, on_demand, acknowledged).await
    }

    /// Crash-safe join for callers that already selected a group by id and
    /// completed link preflight. The desktop onboarding wizard uses this so
    /// its group picker cannot bypass Pending -> Active enrollment with a
    /// bare daemon `Link` request.
    pub async fn join_resolved(
        group_id: String,
        group_name: String,
        absolute: std::path::PathBuf,
        on_demand: bool,
        acknowledged: bool,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let device_id = local_device_id()?;
        let operation_id = Uuid::new_v4();
        let operation_id_str = operation_id.to_string();
        let local_path = absolute.to_string_lossy().to_string();

        // PREPARE: authorize a Pending membership. It counts nowhere the plane
        // treats a row as real until activate, so a crash before then strands
        // nothing.
        post_json_no_content(
            &format!("/shares/groups/{group_id}/join/prepare"),
            &PrepareJoinRequest {
                operation_id: &operation_id_str,
                device_id: &device_id,
                storage_mode: storage_mode_str(on_demand),
            },
            Some(&access_token),
        )
        .await?;

        // Commit the local link and its pending-enrollment marker together:
        // the daemon writes both in one SQLite transaction
        // (`SyncState::add_link_with_pending_enrollment`), so a failure here
        // means neither exists. On failure, compensate by canceling the
        // still-Pending membership; nothing local needs cleaning up.
        if let Err(link_err) = crate::commands::link::link_resolved_with_mode(
            absolute,
            group_id.clone(),
            on_demand,
            acknowledged,
            Some(crate::commands::link::PendingEnrollmentFields {
                operation_id: operation_id_str.clone(),
                kind: PendingEnrollmentKind::Join,
                device_id: device_id.clone(),
            }),
        )
        .await
        {
            cancel_with_retries(
                &format!("/shares/groups/{group_id}/join/cancel"),
                &JoinOperationBody { operation_id: &operation_id_str, device_id: &device_id },
                &access_token,
                operation_id,
            )
            .await;
            return Err(link_err);
        }

        // ACTIVATE. Only a CONFIRMED "never activated" outcome unlinks and
        // cancels the Pending membership; an AMBIGUOUS outcome (response
        // lost, plane may have already committed) leaves the local link and
        // its marker untouched -- see `activate_disposition`'s doc comment.
        let outcome = activate_join(
            &coordination_http_addr(),
            &access_token,
            &group_id,
            &operation_id_str,
            &device_id,
        )
        .await;
        match activate_disposition(outcome) {
            ActivateDisposition::Finalize => {
                remove_pending_enrollment_marker(&operation_id_str).await;
                println!(
                    "Joined {group_name} and linked it at {local_path}{}",
                    if on_demand { " (on-demand)" } else { "" },
                );
                Ok(())
            }
            ActivateDisposition::RollBack => {
                let _ = crate::commands::link::send_unlink(&local_path, false).await;
                cancel_with_retries(
                    &format!("/shares/groups/{group_id}/join/cancel"),
                    &JoinOperationBody { operation_id: &operation_id_str, device_id: &device_id },
                    &access_token,
                    operation_id,
                )
                .await;
                remove_pending_enrollment_marker(&operation_id_str).await;
                Err(CliError::Other(format!(
                    "joining folder group {group_name} (operation {operation_id_str}) was not \
                     confirmed by the coordination plane; rolled back the local link"
                )))
            }
            ActivateDisposition::LeaveForReconcile => {
                Err(CliError::EnrollmentPendingReconciliation(format!(
                    "could not confirm this device joining folder group {group_name} with the \
                     coordination plane (operation {operation_id_str}); the local link and the \
                     daemon's pending-enrollment marker were kept so the daemon can retry and \
                     finish this automatically once the coordination plane is reachable again"
                )))
            }
        }
    }

    /// `yadorilink share set-storage-mode <group> --mode <eager|on-demand>`:
    /// changes this device's storage mode for a folder group it already
    /// links. The `on-demand` (demotion) direction is gated by a durability
    /// handoff: without central storage, an eager full replica is the
    /// group's only durable copy, so this device may only give that status
    /// up once some other full replica is confirmed to durably hold every
    /// file in the group. The `eager` direction has no such hazard (gaining
    /// a durable copy is always safe) and is applied unconditionally.
    ///
    /// The daemon is the SOLE orchestrator of both the coordination-plane
    /// write and the local materialization-policy flip -- this command only
    /// asks it to make the change and prints the result. A demotion's one
    /// coordination-plane write is the role-loss commit
    /// (`coordination_client::commit_handoff_role_loss`, action `"demote"`);
    /// a promotion's is a direct storage-mode write
    /// (`coordination_client::set_storage_mode`). Both happen inside the
    /// daemon's own `control_socket::set_storage_mode`, strictly before the
    /// matching local policy flip -- see that function's doc comment for the
    /// full ordering rationale -- so this command never touches the
    /// coordination plane itself and needs no compensation: any error the
    /// daemon reports means neither its coordination-plane write nor its
    /// local flip committed. The readiness pre-check below is a fail-fast
    /// local read (a peer-confirmation query, not a coordination-plane call)
    /// -- the daemon re-verifies readiness itself, fail-closed, right before
    /// it commits, so this is a gate, not a substitute for the authoritative
    /// check. A command that requests the mode the device is already in is a
    /// no-op, decided from this device's own last-known link state without
    /// asking the daemon to do anything.
    pub async fn set_storage_mode(group_name: String, mode: String) -> Result<(), CliError> {
        let on_demand = parse_storage_mode(&mode)?;
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;

        // Read the device's CURRENT local mode for this group up front, so
        // the command is a no-op (no daemon request at all) when already in
        // the target mode.
        let resp = control_client::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
        let Some(RespPayload::ListLinks(links)) = resp.payload else {
            return Err(CliError::Other("daemon did not return link status".to_string()));
        };
        let Some(link) = links.links.into_iter().find(|l| l.group_id == group_id) else {
            return Err(CliError::Other(format!(
                "{group_name} is not linked on this device; nothing to change"
            )));
        };
        let currently_on_demand = link.materialization_policy == "ondemand";
        if currently_on_demand == on_demand {
            println!("{group_name} is already {}", storage_mode_str(on_demand));
            return Ok(());
        }

        // Authoritative readiness gate for a demotion, evaluated before any
        // coordination-plane write. A promotion to eager has no durability
        // hazard and skips the gate entirely.
        if on_demand {
            let resp = control_client::send(ReqPayload::CheckFullReplicaHandoffReady(
                CheckFullReplicaHandoffReadyRequest { group_id: group_id.clone() },
            ))
            .await?;
            let ready = matches!(
                resp.payload,
                Some(RespPayload::CheckFullReplicaHandoffReady(r)) if r.ready
            );
            if !ready {
                return Err(CliError::Other(format!(
                    "refusing to drop full-replica status for {group_name}: no other full \
                     replica is confirmed to hold every file in this group yet"
                )));
            }
        }

        let new_mode = storage_mode_str(on_demand);

        // Ask the daemon to make the change: it owns both the
        // coordination-plane write (the role-loss commit for a demotion, or
        // a direct storage-mode write for a promotion) and the local
        // materialization-policy flip, strictly in that order, so there is
        // no coordination-plane write here for this command to compensate.
        let flip_resp = control_client::send(ReqPayload::SetStorageMode(SetStorageModeRequest {
            group_id: group_id.clone(),
            on_demand,
        }))
        .await?;

        println!("Set {group_name} storage mode to {new_mode}");
        // Set only when this demotion actually went through the
        // coordination-plane handoff role-loss commit (device registered/
        // logged in and a confirming peer was named) -- see
        // `SetStorageModeResponse.handoff_result`'s own proto doc comment.
        if let Some(RespPayload::SetStorageMode(r)) = flip_resp.payload {
            if let Some(result) = r.handoff_result {
                crate::commands::durability_force::print_handoff_result(&result);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn base_edge() -> ShareEdgeInfo {
            ShareEdgeInfo {
                edge_id: "edge-1".into(),
                group_id: "group-1".into(),
                group_name: "photos".into(),
                device_id: "device-1".into(),
            }
        }

        #[test]
        fn share_edge_line_renders_edge_fields() {
            let line = share_edge_line(&base_edge());
            assert!(line.contains("edge-1"));
            assert!(line.contains("device-1"));
        }

        /// Contract with the coordination plane: its route handlers read
        /// camelCase JSON keys, so these request bodies must serialize to
        /// exactly those keys (a snake_case key arrives undefined server-side).
        #[test]
        fn request_bodies_serialize_camelcase_for_the_coordination_plane() {
            let create =
                serde_json::to_value(CreateGroupRequest { name: "g", creating_device_id: "d" })
                    .unwrap();
            assert_eq!(create["creatingDeviceId"], "d");
            assert!(create.get("creating_device_id").is_none());

            let device = serde_json::to_value(DeviceIdBody { device_id: "d" }).unwrap();
            assert_eq!(device["deviceId"], "d");
            assert!(device.get("device_id").is_none());

            // Pending -> Active enrollment request bodies (0016 migration).
            let prepare_create = serde_json::to_value(PrepareCreateRequest {
                operation_id: "op",
                name: "g",
                creating_device_id: "d",
            })
            .unwrap();
            assert_eq!(prepare_create["operationId"], "op");
            assert_eq!(prepare_create["creatingDeviceId"], "d");

            let prepare_join = serde_json::to_value(PrepareJoinRequest {
                operation_id: "op",
                device_id: "d",
                storage_mode: "eager",
            })
            .unwrap();
            assert_eq!(prepare_join["operationId"], "op");
            assert_eq!(prepare_join["deviceId"], "d");
            assert_eq!(prepare_join["storageMode"], "eager");

            let join_operation =
                serde_json::to_value(JoinOperationBody { operation_id: "op", device_id: "d" })
                    .unwrap();
            assert_eq!(join_operation["operationId"], "op");
            assert_eq!(join_operation["deviceId"], "d");

            let operation_only =
                serde_json::to_value(OperationIdBody { operation_id: "op" }).unwrap();
            assert_eq!(operation_only["operationId"], "op");
        }

        #[test]
        fn storage_mode_str_maps_the_on_demand_flag() {
            assert_eq!(storage_mode_str(false), "eager");
            assert_eq!(storage_mode_str(true), "on-demand");
        }
    }

    // --- activate-response-loss fault injection (fix/activate-response-loss) --
    //
    // `activate_disposition` is the exact fix for the bug: every activate
    // failure used to roll back (unlink + cancel + drop the marker)
    // regardless of WHY it failed, so a lost response after the coordination
    // plane had already committed the activation wrongly deleted a real
    // local link out from under a row the plane still considers Active. Kept
    // in its own module, separate from the request-body/formatting coverage
    // in `mod tests` above.
    #[cfg(test)]
    mod activate_response_loss_tests {
        use super::*;

        #[test]
        fn success_and_already_active_finalize() {
            assert!(matches!(
                activate_disposition(ActivateOutcome::Success),
                ActivateDisposition::Finalize
            ));
            assert!(matches!(
                activate_disposition(ActivateOutcome::AlreadyActive),
                ActivateDisposition::Finalize
            ));
        }

        /// The ONLY outcome that rolls back is a coordination-plane response
        /// that explicitly and confirmedly says this operation was never
        /// activated (a 404 -- `Deleted`).
        #[test]
        fn explicit_deleted_rolls_back() {
            assert!(matches!(
                activate_disposition(ActivateOutcome::Deleted),
                ActivateDisposition::RollBack
            ));
        }

        /// `coordination_client::post_activate` (this daemon-crate function
        /// is reused verbatim by both `create_and_link` and `join`, not
        /// re-implemented here) already folds a transport error, a timeout,
        /// and any 5xx response into this same `TransientFailure` outcome --
        /// none of them say anything final about whether the coordination
        /// plane actually committed the activation. This is the crux of the
        /// fix: every one of those must be handed to the daemon's
        /// reconciliation loop, never treated as a rollback trigger.
        #[test]
        fn transient_failure_covering_transport_error_timeout_and_5xx_is_ambiguous_and_never_rolls_back(
        ) {
            assert!(matches!(
                activate_disposition(ActivateOutcome::TransientFailure),
                ActivateDisposition::LeaveForReconcile
            ));
        }

        /// The scenario this whole fix targets: the coordination plane
        /// actually committed the activation, but this process only ever
        /// observes the ambiguous (lost-response) outcome -- there is no
        /// separate "confirmed committed" signal the CLI can see at this
        /// layer (that confirmation only ever arrives via a LATER, separate
        /// call -- either this same operation retried, or the daemon's own
        /// reconciliation sweep). `activate_disposition` must still resolve
        /// to `LeaveForReconcile` here, exactly as it does for a genuine
        /// outage: the CLI can never tell the two apart from a single failed
        /// call, which is exactly why rolling back on ANY failure was wrong.
        #[test]
        fn activate_commits_but_response_is_lost_is_still_left_for_reconcile() {
            assert!(matches!(
                activate_disposition(ActivateOutcome::TransientFailure),
                ActivateDisposition::LeaveForReconcile
            ));
        }
    }
}

pub use http::{
    create, create_and_link, grant, join, join_resolved, list_groups, list_joinable,
    list_joinable_groups, list_shares, resolve_group_id, revoke, revoke_edge, set_storage_mode,
    GroupSummary,
};
