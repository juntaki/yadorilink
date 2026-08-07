mod http {
    //! HTTP client for the coordination service's `/shares/*` routes.
    //! Sharing is roleless: every authorized device is a full bidirectional
    //! peer, so grants carry no read/write distinction.

    use serde::{Deserialize, Serialize};
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        create_and_link_command_response, join_and_link_command_response,
        revoke_device_command_response, revoke_edge_command_response, ApplicationErrorCode,
        CheckFullReplicaHandoffReadyRequest, CreateAndLinkCommandRequest,
        JoinAndLinkCommandRequest, ListLinksRequest, RevokeDeviceCommandRequest,
        RevokeEdgeCommandRequest, SetStorageModeRequest,
    };

    use crate::control_client;
    use crate::error::CliError;
    use crate::http_client::{get_json, post_json_no_content, require_access_token};
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

    #[cfg(test)]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdBody<'a> {
        operation_id: &'a str,
    }

    #[cfg(test)]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PrepareCreateRequest<'a> {
        operation_id: &'a str,
        name: &'a str,
        creating_device_id: &'a str,
    }

    #[cfg(test)]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PrepareJoinRequest<'a> {
        operation_id: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    }

    #[cfg(test)]
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JoinOperationBody<'a> {
        operation_id: &'a str,
        device_id: &'a str,
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
    /// already have committed it), the daemon leaves the link and marker for
    /// reconciliation. Returns the new group id. Shared by the CLI
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
        let response =
            control_client::send(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
                group_name,
                local_path: absolute_path.to_string_lossy().to_string(),
                on_demand,
                acknowledge_risks,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::CreateAndLinkCommand(response)) => match response.result {
                Some(create_and_link_command_response::Result::Outcome(outcome)) => {
                    Ok(outcome.group_id)
                }
                Some(create_and_link_command_response::Result::Error(error)) => {
                    Err(application_error(error))
                }
                None => Err(CliError::Other("daemon returned an empty create result".into())),
            },
            Some(RespPayload::Error(error)) => Err(CliError::Other(error)),
            _ => Err(CliError::Other("unexpected daemon response to create-and-link".into())),
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
    /// replica. The daemon owns this fail-closed decision and the Worker's
    /// count guard remains an independent final check. `--force` bypasses a refusal with a data-loss
    /// warning and an audit log line; without it, an unready revoke is
    /// refused before any coordination-plane write happens at all.
    pub async fn revoke(
        group_name: String,
        device_id: String,
        force: bool,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let response =
            control_client::send(ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
                group_id,
                device_id: device_id.clone(),
                force,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::RevokeDeviceCommand(response)) => match response.result {
                Some(revoke_device_command_response::Result::Outcome(outcome)) => {
                    crate::commands::membership_render::render_membership_outcome(
                        "revoke", &outcome,
                    );
                }
                Some(revoke_device_command_response::Result::Error(error)) => {
                    return Err(application_error(error));
                }
                None => {
                    return Err(CliError::Other("daemon returned an empty revoke result".into()))
                }
            },
            Some(RespPayload::Error(error)) => return Err(CliError::Other(error)),
            _ => return Err(CliError::Other("unexpected daemon response to revoke".into())),
        }
        println!("Revoked {device_id} access to {group_name}");
        Ok(())
    }

    /// `yadorilink share revoke <edge-id> [--force]`. The daemon resolves
    /// `edge_id` to its `group_id`/`device_id` on the coordination plane and
    /// runs the same durability readiness gate `revoke` runs; the CLI never
    /// lists edges or deletes one directly over HTTP itself, so there is no
    /// window between a listing and a delete where the gate could be
    /// skipped. An edge that no longer exists is treated as already revoked.
    pub async fn revoke_edge(edge_id: String, force: bool) -> Result<(), CliError> {
        let response =
            control_client::send(ReqPayload::RevokeEdgeCommand(RevokeEdgeCommandRequest {
                edge_id: edge_id.clone(),
                force,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::RevokeEdgeCommand(response)) => match response.result {
                Some(revoke_edge_command_response::Result::Outcome(outcome)) => {
                    crate::commands::membership_render::render_membership_outcome(
                        "revoke", &outcome,
                    );
                }
                Some(revoke_edge_command_response::Result::Error(error)) => {
                    if ApplicationErrorCode::try_from(error.code)
                        .is_ok_and(|code| code == ApplicationErrorCode::TargetNotFound)
                    {
                        println!("Share edge already revoked: {edge_id}");
                        return Ok(());
                    }
                    return Err(application_error(error));
                }
                None => {
                    return Err(CliError::Other("daemon returned an empty revoke result".into()));
                }
            },
            Some(RespPayload::Error(error)) => return Err(CliError::Other(error)),
            _ => return Err(CliError::Other("unexpected daemon response to revoke".into())),
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
    /// sweep -- see `create_and_link`'s doc comment for the identical reasoning.
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
        let local_path = absolute.to_string_lossy().to_string();
        let response =
            control_client::send(ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
                group_id,
                group_name: group_name.clone(),
                local_path: local_path.clone(),
                on_demand,
                acknowledge_risks: acknowledged,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::JoinAndLinkCommand(response)) => match response.result {
                Some(join_and_link_command_response::Result::Outcome(_)) => {
                    println!(
                        "Joined {group_name} and linked it at {local_path}{}",
                        if on_demand { " (on-demand)" } else { "" },
                    );
                    Ok(())
                }
                Some(join_and_link_command_response::Result::Error(error)) => {
                    Err(application_error(error))
                }
                None => Err(CliError::Other("daemon returned an empty join result".into())),
            },
            Some(RespPayload::Error(error)) => Err(CliError::Other(error)),
            _ => Err(CliError::Other("unexpected daemon response to join-and-link".into())),
        }
    }

    fn application_error(
        error: yadorilink_ipc_proto::daemonctl::ApplicationCommandError,
    ) -> CliError {
        if ApplicationErrorCode::try_from(error.code)
            .is_ok_and(|code| code == ApplicationErrorCode::ActivationAmbiguous)
        {
            CliError::EnrollmentPendingReconciliation(error.message)
        } else {
            CliError::Other(error.message)
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
                println!(
                    "  handoff completed: target={} membership_generation={}{}",
                    result.target_device_id,
                    result.membership_generation,
                    if result.lease_id.is_empty() {
                        String::new()
                    } else {
                        format!(" lease={}", result.lease_id)
                    }
                );
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
}

pub use http::{
    create, create_and_link, grant, join, join_resolved, list_groups, list_joinable,
    list_joinable_groups, list_shares, resolve_group_id, revoke, revoke_edge, set_storage_mode,
    GroupSummary,
};
