mod http {
    //! HTTP client for the coordination service's `/shares/*` routes.
    //! Same-account `revoke`/`join` are roleless: every authorized device
    //! is a full bidirectional peer there, so those grants carry no
    //! read/write distinction. `grant` (also same-account) IS role-aware:
    //! `--role` accepts `viewer` or `editor` and defaults to `editor` when
    //! omitted -- preserving this command's pre-existing, always-full-writer
    //! behavior for every caller that never adopts the flag. `owner` is not
    //! yet available via `grant`: there is no management-authority model yet
    //! to back it (see `crate::commands::share::grant`'s own doc comment).
    //! Cross-account sharing (`invite`/`accept`) is role-aware too, with a
    //! DIFFERENT omitted-role default (`viewer`, least-privilege for a
    //! stranger-facing invite) -- the accepting device's Viewer/Editor role
    //! is chosen at invite-mint time and carried in the resulting grant.
    //! `owner` is not yet available via `invite` either, for the same
    //! reason as `grant`: there is no management-authority model yet to
    //! back it.

    use serde::{Deserialize, Serialize};
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        create_and_link_command_response, join_and_link_command_response,
        revoke_device_command_response, revoke_edge_command_response, ApplicationErrorCode,
        CheckFullReplicaHandoffReadyRequest, CreateAndLinkCommandRequest,
        JoinAndLinkCommandRequest, ListLinksRequest, ReplicaMembershipCommandOutcome,
        RevokeDeviceCommandRequest, RevokeEdgeCommandRequest, SetStorageModeRequest,
    };

    use yadorilink_ipc_proto::daemonctl::{
        accept_invite_command_response, mint_invite_command_response, AcceptInviteCommandRequest,
        MintInviteCommandRequest, MintedInviteInfo,
    };

    use crate::control_client;
    use crate::error::CliError;
    use crate::http_client::{
        delete_no_content, get_json, post_json, post_json_no_content, require_access_token,
    };
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

    // The coordination plane's `/shares/groups` route emits camelCase JSON
    // keys (`groupId`, `name`) -- `#[serde(rename_all = "camelCase")]` is
    // load-bearing here: without it, `group_id` matches nothing in the
    // response body at all (serde's default field matching is exact-name,
    // case-sensitive), and every caller of `resolve_group_id`/`list_groups`
    // below fails deserialization outright against a real coordination
    // worker. See `folder_group_info_deserializes_the_coordination_planes_
    // camelcase_shape` (the element type) and
    // `list_groups_response_envelope_deserializes_the_coordination_planes_
    // camelcase_body` (the envelope) for the regression tests.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
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
    /// `/shares/groups` route `resolve_group_id` tries first (before its own
    /// `/shares` fallback for a name owned by a different account).
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
    ///
    /// Resolves against TWO listings, in this order:
    ///
    /// 1. `GET /shares/groups`, which the coordination plane scopes to the
    ///    groups this account OWNS (`WHERE user_id = ?`).
    /// 2. `GET /shares`, which returns every ACL edge visible to this
    ///    account — its own groups' edges AND the edges binding its own
    ///    devices into groups owned by SOMEONE ELSE — each carrying that
    ///    group's `groupName` and `groupId`.
    ///
    /// The second lookup is what makes a name resolvable at all for an
    /// account that only ever joined a group by accepting a cross-account
    /// invite: it owns no groups, so the owner-scoped first listing is empty
    /// for it and every name lookup used to fail with "no folder group
    /// named ...". That is not merely a worse error message — it made a
    /// command like `share members`, which the coordination plane
    /// deliberately authorizes for a member account too (`userCanSeeGroup`,
    /// not `assertOwnsGroup`), impossible for that account to reach at all,
    /// because the CLI could never turn the name it was given into an id.
    ///
    /// Owned groups are consulted first so a name that exists in both
    /// listings resolves to the account's OWN group, deterministically and
    /// exactly as before this fallback existed. The fallback grants nothing:
    /// authorization stays entirely server-side and per-route, so resolving
    /// a name here only means the account now reaches its route's real
    /// answer (a listing it may see, or an ordinary permission-denied from
    /// an owner-only mutation) instead of a misleading local "no such
    /// group".
    pub async fn resolve_group_id(
        access_token: &str,
        group_name: &str,
    ) -> Result<String, CliError> {
        let owned: ListGroupsResponse = get_json("/shares/groups", Some(access_token)).await?;
        if let Some(group) = owned.groups.into_iter().find(|g| g.name == group_name) {
            return Ok(group.group_id);
        }
        let shared: ListSharesResponse = get_json("/shares", Some(access_token)).await?;
        shared
            .edges
            .into_iter()
            .find(|e| e.group_name == group_name)
            .map(|e| e.group_id)
            .ok_or_else(|| {
                CliError::Other(format!(
                    "no folder group named {group_name:?} is visible to this account (run \
                     `yadorilink share create` to make one, or `yadorilink share accept` to join \
                     one you were invited to)"
                ))
            })
    }

    /// The invite's plaintext code encoded as a `yadorilink://invite/<code>`
    /// URI -- a structured, future-proof payload for the QR/URL (rather
    /// than the bare code) that a scan-to-accept flow (desktop GUI, or a
    /// phone camera) can parse unambiguously, while a human can still
    /// read/type just the code portion after the last `/`.
    ///
    /// Public so every surface that shows an invite builds the SAME
    /// payload: `extract_invite_code` (what `share accept` parses) is
    /// defined against exactly this shape, so a second, independently
    /// written formatter elsewhere in the workspace is a way for the two
    /// halves to drift apart.
    pub fn invite_url(code: &str) -> String {
        format!("yadorilink://invite/{code}")
    }

    /// Renders `url` as a terminal-friendly QR code (Unicode block
    /// characters, roughly square modules via `module_dimensions(2, 1)` to
    /// compensate for terminal character cells being taller than they are
    /// wide). Returns `None` on a genuine encoding failure (the payload is
    /// too long for any QR version) rather than erroring the whole `invite`
    /// command -- the code and URL are still printed either way, so a QR
    /// rendering failure never blocks sharing the invite by other means.
    fn render_invite_qr(url: &str) -> Option<String> {
        let code = qrcode::QrCode::new(url).ok()?;
        Some(code.render::<char>().module_dimensions(2, 1).dark_color('█').light_color(' ').build())
    }

    /// Mints a one-use, expiring, device-scoped cross-account invite for an
    /// ALREADY-RESOLVED group id and returns the coordination plane's own
    /// record of it, printing nothing.
    ///
    /// Split out of `invite` below (mirroring `join`/`join_resolved`'s own
    /// split in this file, for the same reason) so a caller that already
    /// holds a group id can mint through this one implementation instead of
    /// re-deriving a name to resolve straight back into the id it started
    /// with. The desktop app's share window is exactly that caller: it
    /// reads the folder's group id off the daemon's own `LinkStatus`.
    ///
    /// Minting is not a local-link operation, but still goes through the
    /// daemon (`MintInviteCommand`) rather than a direct HTTP call: the
    /// coordination plane requires a minting device id, and the daemon is
    /// the only thing on this machine that knows this device's own id --
    /// no caller ever supplies it, unlike `grant`, which names some OTHER
    /// device explicitly.
    ///
    /// An omitted `role`/`ttl_secs` is forwarded as the proto's own
    /// "unset" value (empty string / `0`), which the coordination plane
    /// resolves to its defaults (`viewer`, 7 days) -- the caller never
    /// guesses those locally.
    pub async fn mint_invite_resolved(
        group_id: String,
        role: Option<String>,
        ttl_secs: Option<u64>,
        require_approval: bool,
    ) -> Result<MintedInviteInfo, CliError> {
        let response =
            control_client::send(ReqPayload::MintInviteCommand(MintInviteCommandRequest {
                group_id,
                role: role.unwrap_or_default(),
                ttl_secs: ttl_secs.unwrap_or(0),
                requires_approval: require_approval,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::MintInviteCommand(response)) => match response.result {
                Some(mint_invite_command_response::Result::Outcome(invite)) => Ok(invite),
                Some(mint_invite_command_response::Result::Error(error)) => {
                    Err(application_error(error))
                }
                None => Err(CliError::Other("daemon returned an empty invite result".into())),
            },
            Some(RespPayload::Error(error)) => Err(CliError::Other(error)),
            _ => Err(CliError::Other("unexpected daemon response to mint-invite".into())),
        }
    }

    /// Same as `mint_invite_resolved`, for a caller holding the folder
    /// group's human-readable name instead of its id.
    pub async fn mint_invite(
        group_name: &str,
        role: Option<String>,
        ttl_secs: Option<u64>,
        require_approval: bool,
    ) -> Result<MintedInviteInfo, CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, group_name).await?;
        mint_invite_resolved(group_id, role, ttl_secs, require_approval).await
    }

    /// Every line `share invite` prints for a freshly minted invite, in
    /// order. A pure function of the coordination plane's own record of the
    /// invite, so the wording is testable without a daemon -- the same
    /// split `accept_invite_lines` already uses for the other half of this
    /// flow.
    ///
    /// `qr` is the whole pre-rendered multi-line QR block, or `None` when
    /// rendering it failed; a failure simply omits the block (and its
    /// leading blank line), since the code and URL are printed either way
    /// and a QR rendering failure must never block sharing an invite by
    /// other means.
    fn invite_lines(
        group_name: &str,
        invite: &MintedInviteInfo,
        url: &str,
        qr: Option<&str>,
    ) -> Vec<String> {
        let mut lines = vec![
            format!("Invite for {group_name} (role: {}):", invite.role),
            format!("  code: {}", invite.code),
            format!("  url:  {url}"),
            format!("  expires in: {}", format_expiry(invite.expires_at_unix)),
        ];
        // Reported from what the coordination plane actually recorded, not
        // from the flag this command was given, so the recipient-facing
        // wording below always describes the invite that exists.
        if invite.requires_approval {
            lines.push(
                "  approval: required (you must approve the recipient before they get access)"
                    .to_string(),
            );
        }
        if let Some(qr) = qr {
            lines.push(String::new());
            lines.push(qr.to_string());
        }
        lines.push(String::new());
        lines.push("This code is one-time use -- share it with exactly one recipient.".to_string());
        lines.push(format!(
            "The recipient accepts it with: yadorilink share accept {url} --path <dir>"
        ));
        if invite.requires_approval {
            lines.push(format!(
                "They will not see anything until you admit them: run `yadorilink share pending` \
                 to see the request, then `yadorilink share approve {group_name} <device-id>`."
            ));
        }
        lines
    }

    /// `yadorilink share invite <group>`: mints a one-use, expiring,
    /// device-scoped cross-account invite for `group_name` and prints its
    /// code, a `yadorilink://` URL, and a terminal QR code encoding that
    /// URL. The minting itself is `mint_invite` above; this command is that
    /// call plus `invite_lines`' rendering of its result.
    pub async fn invite(
        group_name: String,
        role: Option<String>,
        ttl_secs: Option<u64>,
        require_approval: bool,
    ) -> Result<(), CliError> {
        let invite = mint_invite(&group_name, role, ttl_secs, require_approval).await?;
        let url = invite_url(&invite.code);
        let qr = render_invite_qr(&url);
        for line in invite_lines(&group_name, &invite, &url, qr.as_deref()) {
            println!("{line}");
        }
        Ok(())
    }

    /// A relative expiry ("7 days", "45 minutes") from the current time --
    /// simpler and more directly actionable for a share-once code than an
    /// absolute calendar timestamp, and needs no date/time dependency this
    /// CLI does not otherwise carry.
    fn format_expiry(expires_at_unix: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let remaining = expires_at_unix - now;
        if remaining <= 0 {
            return "already expired".to_string();
        }
        let remaining = remaining as u64;
        if remaining >= 86_400 {
            format!("{} day(s)", remaining / 86_400)
        } else if remaining >= 3600 {
            format!("{} hour(s)", remaining / 3600)
        } else {
            format!("{} minute(s)", remaining.max(60) / 60)
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PendingInviteInfo {
        invite_id: String,
        group_id: String,
        group_name: String,
        role: String,
        expires_at_unix: i64,
        status: String,
    }
    #[derive(Deserialize)]
    struct ListPendingInvitesResponse {
        invites: Vec<PendingInviteInfo>,
    }

    fn pending_invite_line(invite: &PendingInviteInfo) -> String {
        let expiry = match invite.status.as_str() {
            "pending" => format!("expires in {}", format_expiry(invite.expires_at_unix)),
            other => other.to_string(),
        };
        format!(
            "{}  group={} ({})  role={}  {expiry}",
            invite.invite_id, invite.group_name, invite.group_id, invite.role
        )
    }

    /// `yadorilink share invites`: lists every invite this account has
    /// minted (via a group it owns) that nobody has redeemed yet --
    /// `pending` (still usable, with its remaining TTL), `expired` (timed
    /// out with nobody ever using it), or `cancelled` (withdrawn early via
    /// `share cancel-invite`). An invite someone HAS already redeemed does
    /// not appear here -- see it as an ordinary grant via `share list`
    /// instead, and revoke it with `share revoke`.
    pub async fn list_invites() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let resp: ListPendingInvitesResponse =
            get_json("/shares/invites", Some(&access_token)).await?;
        if resp.invites.is_empty() {
            println!("No pending invites. Mint one with `yadorilink share invite <group>`.");
            return Ok(());
        }
        for invite in resp.invites {
            println!("{}", pending_invite_line(&invite));
        }
        Ok(())
    }

    /// `yadorilink share cancel-invite <invite-id>`: withdraws a
    /// not-yet-redeemed invite (from `share invites`) before it is ever
    /// used or expires. HTTP-only, like `share list`/`share revoke
    /// <edge-id>` -- there is no local device state involved, so this never
    /// goes through the daemon. A no-op (still succeeds) if the invite was
    /// already cancelled; the coordination plane refuses with a clear,
    /// specific error if it names an invite that was already accepted
    /// (pointing at `share revoke` instead) or one that never existed.
    pub async fn cancel_invite(invite_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        delete_no_content(&format!("/shares/invites/{invite_id}"), Some(&access_token)).await?;
        println!("Cancelled invite: {invite_id}");
        Ok(())
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

    /// `role` is `#[serde(skip_serializing_if = "Option::is_none")]` so
    /// omitting `--role` produces a request body with NO `role` key at all
    /// (not a JSON `"role": null`) -- reqwest's `.json(...)` otherwise
    /// serializes `Option::None` as an explicit `null`, and the coordination
    /// plane's role parsing treats an absent key (defaults to Editor for
    /// this route) very differently from a present-but-null one (rejected).
    /// See `grant_request_omits_the_role_key_entirely_when_none_but_serializes_it_when_some`
    /// below, and `share invite`'s own `MintInviteCommandRequest` for the
    /// same contract on the cross-account path.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GrantRequest<'a> {
        device_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<&'a str>,
    }

    /// `role` is the device's actual EFFECTIVE role after this call, and
    /// `created` says whether this call was the one that granted it: `true`
    /// for a fresh grant (`role` is the newly-granted role), `false` when
    /// the device was already authorized (`role` is its pre-existing role,
    /// UNCHANGED by this call even if a different `--role` was requested --
    /// this route never updates an already-granted device's role in
    /// place).
    #[derive(Deserialize)]
    struct GrantResponse {
        role: String,
        created: bool,
    }

    /// `yadorilink share grant <group> <device> [--role viewer|editor]`:
    /// authorizes another of your own already-registered devices for a
    /// folder group. Same-account only -- for a different account's device,
    /// use `share invite`/`share accept` instead.
    ///
    /// `--role` defaults to `editor` when omitted, NOT the same default
    /// `share invite` uses (`viewer`): this preserves `grant`'s
    /// pre-existing, always-full-writer behavior for every caller that
    /// never adopts the flag, avoiding a silent privilege regression.
    /// `owner` is not accepted here -- the coordination plane rejects it for
    /// this route with a clear error, since there is no real
    /// management-authority model yet to back an Owner grant (this route's
    /// own calling-device authorization deliberately stays account-level,
    /// unchanged from before roles existed).
    ///
    /// The coordination plane resolves the omitted-role default (rather
    /// than the CLI guessing it locally) and reports back the device's
    /// actual effective role plus whether this call is what granted it
    /// (`GrantResponse`'s own doc comment) -- printed here so the CLI never
    /// claims a role change took effect when the device was, in fact,
    /// already authorized under a different role. Re-granting an
    /// already-authorized device with a different `--role` does NOT change
    /// its role; `share change-role` is the command that does.
    ///
    /// `post_json` parses this route's success response as JSON
    /// unconditionally, so this command requires a coordination worker new
    /// enough to return a body (rather than `204 No Content`) on success --
    /// deploy the worker before shipping a CLI built against this.
    pub async fn grant(
        group_name: String,
        device_id: String,
        role: Option<String>,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let response: GrantResponse = post_json(
            &format!("/shares/groups/{group_id}/grant"),
            &GrantRequest { device_id: &device_id, role: role.as_deref() },
            Some(&access_token),
        )
        .await?;
        if response.created {
            println!("Granted {device_id} access to {group_name} (role: {})", response.role);
        } else {
            println!(
                "{device_id} was already authorized for {group_name}; role remains {} (change an \
                 existing grant's role with `yadorilink share change-role {group_name} \
                 {device_id} --role <viewer|editor>`)",
                response.role
            );
        }
        Ok(())
    }

    /// One device in a folder group's "people with access" listing. Mirrors
    /// the coordination plane's `GroupMemberInfo` response shape
    /// (`coordination-worker/src/shares/service.ts`) exactly -- group-scoped
    /// minimal identity only (device name and id), no email address anywhere.
    ///
    /// Public, with public fields, because this is the typed result
    /// `list_members` hands library callers: the desktop app's share window
    /// renders the same listing natively rather than parsing this command's
    /// printed text back apart.
    #[derive(Clone, Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupMemberInfo {
        pub device_id: String,
        pub device_name: String,
        /// `"viewer"` / `"editor"` in ordinary use; `"unknown"` for a
        /// genuine data-integrity anomaly (an ACL entry with no matching
        /// policy-log grant record -- see the coordination plane's own doc
        /// comment). Kept as a plain string and printed verbatim rather than
        /// parsed into an enum: this command never branches on the value,
        /// so an unrecognized future role (or the `"unknown"` sentinel)
        /// still renders instead of failing the whole listing.
        pub role: String,
        /// Whether this device is on the SAME account that OWNS the group --
        /// relative to the group owner, not to whoever is running this CLI
        /// command. Use `is_caller_account` (below) for a label relative to
        /// the actual caller; do not use this field alone to decide what to
        /// print for a non-owner caller, see `member_relationship_label`'s
        /// own doc comment.
        pub is_same_account: bool,
        /// Whether this device is on the SAME account as the account making
        /// THIS request (this CLI invocation's own access token), regardless
        /// of who owns the group. For the group owner running this command
        /// this agrees with `is_same_account`; for a non-owner caller (an
        /// invited account's own user) it does not -- that caller's own
        /// other device is `is_caller_account: true` / `is_same_account:
        /// false`, and the owner's devices are the other way around.
        pub is_caller_account: bool,
        pub storage_mode: String,
        pub online: bool,
        pub last_seen_unix: i64,
    }
    #[derive(Deserialize)]
    struct ListMembersResponse {
        members: Vec<GroupMemberInfo>,
    }

    /// How one member relates to whoever is looking at the listing.
    /// `own_device_id` is this device's own id (from local `device_config`,
    /// when known) -- used only to label the caller's own EXACT device as
    /// "you", never to change which members are shown (the coordination
    /// plane already decided the full membership list; this is purely a
    /// display label).
    ///
    /// Deliberately computed from TWO different booleans, not one:
    /// `is_same_account` is owner-relative ("is this member on the group
    /// owner's account") while `is_caller_account` is caller-relative ("is
    /// this member on the account making the request"). For the group owner
    /// these coincide, so it is tempting to collapse them into one check --
    /// but for a non-owner caller (an invited account's own user listing the
    /// members themselves) they do NOT coincide: that caller's own other
    /// device has `is_same_account: false` (it isn't the group owner) but
    /// `is_caller_account: true` (it IS their own account), and the group
    /// owner's devices are the other way around. Echoing `is_same_account`
    /// alone as if it meant "shares an account with me" silently assumed
    /// caller == owner and produced an inverted label for every other
    /// caller; branching on `is_caller_account` first avoids that.
    ///
    /// Public, and the single implementation of this label, so a second
    /// surface rendering the same listing (the desktop app's share window)
    /// cannot re-derive it slightly differently and reintroduce that
    /// inversion.
    pub fn member_relationship_label(
        member: &GroupMemberInfo,
        own_device_id: Option<&str>,
    ) -> &'static str {
        if own_device_id == Some(member.device_id.as_str()) {
            "you"
        } else if member.is_caller_account {
            "your other device"
        } else if member.is_same_account {
            "owner's device"
        } else {
            "invited"
        }
    }

    /// Whether this member keeps a full local copy of the group or fetches
    /// files on demand, worded for a person. Public for the same
    /// one-implementation reason as `member_relationship_label`.
    ///
    /// A positive match on the one mode that means "full copy": an
    /// unrecognized future storage mode reads as on-demand, which understates
    /// rather than overstates what is durably held.
    pub fn member_storage_label(member: &GroupMemberInfo) -> &'static str {
        if member.storage_mode == "eager" {
            "full copy"
        } else {
            "on-demand"
        }
    }

    /// The device id shown alongside a device's name -- the leading 8
    /// characters, enough to tell two devices apart without filling a line
    /// with an opaque identifier.
    pub fn short_device_id(device_id: &str) -> String {
        device_id.chars().take(8).collect()
    }

    /// Formats one member's line for `share members`' output.
    fn member_line(member: &GroupMemberInfo, own_device_id: Option<&str>) -> String {
        let short_id = short_device_id(&member.device_id);
        format!(
            "device={} ({short_id})  role={}  {}  {}  {}",
            member.device_name,
            member.role,
            member_relationship_label(member, own_device_id),
            if member.online { "online" } else { "offline" },
            member_storage_label(member),
        )
    }

    /// This device's own id, when this machine has a local device identity
    /// at all. Best-effort by design: a device that has never registered
    /// locally (e.g. a command run against a fresh config directory) simply
    /// never matches "you" in a member listing, and every member still
    /// renders correctly without it.
    pub fn own_device_id() -> Option<String> {
        crate::device_config::load().ok().map(|c| c.device_id)
    }

    /// Who has access to an ALREADY-RESOLVED folder group id, returning the
    /// coordination plane's own listing and printing nothing.
    ///
    /// Split out of `members` below (mirroring `mint_invite_resolved`'s own
    /// split in this file, for the same reason) so a caller that already
    /// holds a group id -- the desktop app's share window reads one off the
    /// daemon's `LinkStatus` -- does not have to invent a name to resolve
    /// straight back into the id it started with.
    pub async fn list_members_resolved(group_id: &str) -> Result<Vec<GroupMemberInfo>, CliError> {
        let access_token = require_access_token()?;
        let response: ListMembersResponse =
            get_json(&format!("/shares/groups/{group_id}/members"), Some(&access_token)).await?;
        Ok(response.members)
    }

    /// Same as `list_members_resolved`, for a caller holding the folder
    /// group's human-readable name instead of its id.
    pub async fn list_members(group_name: &str) -> Result<Vec<GroupMemberInfo>, CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, group_name).await?;
        list_members_resolved(&group_id).await
    }

    /// `yadorilink share members <group>`: lists who has access to a folder
    /// group and their role. Read-only -- no management capability is gated
    /// on this -- and group-scoped minimal identity only, matching the
    /// coordination plane's own identity-minimization rule: device display
    /// name and id, never another account's email address.
    pub async fn members(group_name: String) -> Result<(), CliError> {
        let members = list_members(&group_name).await?;
        let own_device_id = own_device_id();
        if members.is_empty() {
            println!("No one has access to {group_name}.");
            return Ok(());
        }
        for member in &members {
            println!("{}", member_line(member, own_device_id.as_deref()));
        }
        Ok(())
    }

    /// The request body for a live role change. The coordination plane reads
    /// camelCase JSON keys (`deviceId`), so this must serialize to match or
    /// the field arrives `undefined` server-side and the route rejects the
    /// call as a missing device id. `role` is always present -- unlike
    /// `GrantRequest`'s optional one, this route REQUIRES it (an omitted role
    /// on an existing collaborator must never silently default) -- so there
    /// is no `skip_serializing_if` here.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ChangeRoleRequest<'a> {
        device_id: &'a str,
        role: &'a str,
    }

    /// The roles `change-role` may move an existing member to.
    ///
    /// `owner` is deliberately absent, the same restriction `grant` and
    /// `invite` carry: there is no management-authority model yet to back an
    /// Owner grant, and the coordination plane rejects `owner` on this route
    /// for that reason. Checked here as well as server-side so a mistyped
    /// role fails immediately, with a message naming what IS accepted,
    /// instead of costing a network round trip to find out.
    pub const CHANGEABLE_ROLES: [&str; 2] = ["viewer", "editor"];

    /// Validates a requested role for `change-role`.
    ///
    /// Exact, case-sensitive matching against `CHANGEABLE_ROLES`, mirroring
    /// the coordination plane's own exact-match role set: accepting a
    /// spelling here that the plane would refuse would just move the failure
    /// one round trip later, and silently rewriting the caller's spelling
    /// would mean the CLI sent a role the caller did not type.
    pub fn validate_changeable_role(role: &str) -> Result<(), CliError> {
        if CHANGEABLE_ROLES.contains(&role) {
            return Ok(());
        }
        Err(CliError::Other(format!(
            "invalid --role {role:?} (expected {}); owner is not available via this command yet",
            CHANGEABLE_ROLES.join(" or ")
        )))
    }

    /// Moves an already-granted device to a different role in an
    /// ALREADY-RESOLVED folder group, printing nothing.
    ///
    /// HTTP-only, exactly like `grant`: a role change never touches this
    /// machine's local link state, so there is no daemon involvement and
    /// nothing local to keep in step. The coordination plane answers `204 No
    /// Content`, so there is no response body to report -- a request naming
    /// the device's CURRENT role is a no-op success there, which is why this
    /// is safe to retry.
    pub async fn change_role_resolved(
        group_id: &str,
        device_id: &str,
        role: &str,
    ) -> Result<(), CliError> {
        validate_changeable_role(role)?;
        let access_token = require_access_token()?;
        post_json_no_content(
            &format!("/shares/groups/{group_id}/role"),
            &ChangeRoleRequest { device_id, role },
            Some(&access_token),
        )
        .await
    }

    /// `yadorilink share change-role <group> <device> --role viewer|editor`:
    /// moves a device that ALREADY has access to a folder group to a
    /// different role, without a revoke-and-re-invite round trip.
    ///
    /// Unlike `grant`'s `--role`, this one is required and has no default: a
    /// role change that did not name a role would either no-op or silently
    /// pick something for an existing collaborator. Unlike `grant`, the
    /// target device may belong to a DIFFERENT account (someone who accepted
    /// a cross-account invite) -- authorization is the group owner's, exactly
    /// as it is for `revoke`.
    ///
    /// `owner` is not accepted, matching `grant`/`invite`; see
    /// `CHANGEABLE_ROLES`.
    ///
    /// A downgrade takes effect promptly rather than at the next poll: the
    /// coordination plane records it as a revoke-then-grant pair that bumps
    /// the group's authorization epoch, which every peer's admission gate
    /// re-derives from on its next check.
    pub async fn change_role(
        group_name: String,
        device_id: String,
        role: String,
    ) -> Result<(), CliError> {
        validate_changeable_role(&role)?;
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        change_role_resolved(&group_id, &device_id, &role).await?;
        println!("{}", change_role_line(&device_id, &group_name, &role));
        Ok(())
    }

    /// What `share change-role` prints once the coordination plane has
    /// accepted the change. A pure function of the request, because that is
    /// all there is: the route answers `204 No Content`, so this command has
    /// no server-reported effective role to echo the way `grant` does.
    fn change_role_line(device_id: &str, group_name: &str, role: &str) -> String {
        format!("{device_id} is now {role} for {group_name}")
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
        revoke_announcing(group_name, device_id, force, RevokeAnnouncement::Revoked).await
    }

    /// Which command's wording to close with once the revoke has committed.
    /// `share deny` runs the same mutation for a different reason (see
    /// `deny`'s own doc comment) and must not report it as having taken away
    /// access the device never had.
    #[derive(Clone, Copy)]
    enum RevokeAnnouncement {
        Revoked,
        Denied,
    }

    /// Takes a device's access to an ALREADY-RESOLVED folder group away and
    /// returns the daemon's own outcome record, printing nothing.
    ///
    /// The single mutation behind `share revoke`, `share deny` and the
    /// desktop app's share window alike (mirroring `mint_invite_resolved`'s
    /// own split in this file). Going through the daemon rather than
    /// straight to the coordination plane is what applies the durability
    /// readiness gate: without `force`, a revoke that would leave the group
    /// without another confirmed-ready full replica is refused BEFORE any
    /// coordination-plane write happens.
    ///
    /// `force` is a data-loss override, never a retry convenience -- see
    /// `revoke`'s own doc comment. A caller that sets it is asserting the
    /// user was shown the refusal and explicitly accepted the risk.
    ///
    /// The returned outcome carries the warnings a caller must still show
    /// (`membership_render::membership_outcome_warnings`): a forced revoke's
    /// data-loss warning, and the unknown-scope warning for a revoke forced
    /// before the affected groups could be determined.
    pub async fn revoke_resolved(
        group_id: String,
        device_id: String,
        force: bool,
    ) -> Result<ReplicaMembershipCommandOutcome, CliError> {
        match try_revoke_resolved(group_id, device_id, force).await? {
            RevokeAttempt::Committed(outcome) => Ok(outcome),
            // The same `CliError::Other` this whole path produced before the
            // refusal was given its own variant, so `share revoke`'s message
            // and exit code are unchanged.
            RevokeAttempt::NotDurable { message, .. } => Err(CliError::Other(message)),
        }
    }

    /// How a revoke attempt ended.
    ///
    /// The durability refusal is a distinct variant rather than just another
    /// error because it is the ONLY revoke failure that `force` can get past,
    /// and it is the only one where offering an override is honest. Every
    /// other failure -- an unreachable daemon, a coordination-plane refusal,
    /// a device that is not a member -- stays an ordinary `CliError`: forcing
    /// those would not help, and presenting a data-loss confirmation for a
    /// failure that has nothing to do with data loss would train people to
    /// click through the one confirmation that matters.
    pub enum RevokeAttempt {
        Committed(ReplicaMembershipCommandOutcome),
        /// The daemon refused before touching the coordination plane:
        /// revoking would leave the folder group without another
        /// confirmed-ready full replica. `message` is the daemon's own
        /// wording, and `group_ids` are the groups it named as not ready.
        NotDurable {
            message: String,
            group_ids: Vec<String>,
        },
    }

    /// `revoke_resolved`, with the durability refusal reported as an outcome
    /// rather than an error -- for a caller that can offer the override to a
    /// person (the desktop app's share window) instead of just failing.
    pub async fn try_revoke_resolved(
        group_id: String,
        device_id: String,
        force: bool,
    ) -> Result<RevokeAttempt, CliError> {
        let response =
            control_client::send(ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
                group_id,
                device_id,
                force,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::RevokeDeviceCommand(response)) => {
                classify_revoke_result(response.result)
            }
            Some(RespPayload::Error(error)) => Err(CliError::Other(error)),
            _ => Err(CliError::Other("unexpected daemon response to revoke".into())),
        }
    }

    /// Sorts the daemon's revoke result into "committed", "refused for
    /// durability" and "failed", positively matching the one error code
    /// `force` can get past. Split out from the transport call above purely
    /// so this classification is unit-testable without a running daemon --
    /// getting it wrong in either direction is a real hazard: a
    /// misclassified other-failure offers a data-loss override that would
    /// not have helped, and a misclassified refusal leaves a legitimate
    /// override unreachable from the desktop app entirely.
    fn classify_revoke_result(
        result: Option<revoke_device_command_response::Result>,
    ) -> Result<RevokeAttempt, CliError> {
        match result {
            Some(revoke_device_command_response::Result::Outcome(outcome)) => {
                Ok(RevokeAttempt::Committed(outcome))
            }
            Some(revoke_device_command_response::Result::Error(error)) => {
                if ApplicationErrorCode::try_from(error.code)
                    .is_ok_and(|code| code == ApplicationErrorCode::ReplicaNotReady)
                {
                    return Ok(RevokeAttempt::NotDurable {
                        message: error.message,
                        group_ids: error.group_ids,
                    });
                }
                Err(application_error(error))
            }
            None => Err(CliError::Other("daemon returned an empty revoke result".into())),
        }
    }

    async fn revoke_announcing(
        group_name: String,
        device_id: String,
        force: bool,
        announcement: RevokeAnnouncement,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let outcome = revoke_resolved(group_id, device_id.clone(), force).await?;
        crate::commands::membership_render::render_membership_outcome("revoke", &outcome);
        match announcement {
            RevokeAnnouncement::Revoked => println!("Revoked {device_id} access to {group_name}"),
            RevokeAnnouncement::Denied => {
                println!("Denied {device_id} access to {group_name}");
            }
        }
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

    /// The coordination plane's `state` value for an edge that has been
    /// accepted by its invited device but is waiting for the group owner to
    /// admit it. Matched as a plain string rather than parsed into an enum
    /// for the same reason `GroupMemberInfo::role` is: an unrecognized
    /// future state must still render in `share list`, not fail the whole
    /// listing.
    const STATE_PENDING_APPROVAL: &str = "pending_approval";

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ShareEdgeInfo {
        edge_id: String,
        group_id: String,
        group_name: String,
        device_id: String,
        /// `"active"` for an ordinary member, `"pending"` for one whose own
        /// device has not confirmed its side yet, or
        /// `STATE_PENDING_APPROVAL` for one waiting on the group owner's
        /// decision.
        ///
        /// Optional-with-default rather than required, deliberately: this
        /// listing also backs `resolve_group_id`, i.e. nearly every command
        /// in this file, so a coordination plane deployed before it reported
        /// edge state must degrade to "state unknown" rather than fail the
        /// whole deserialization and take every folder-group name lookup
        /// down with it. (`share grant`'s own response shape accepted a hard
        /// deploy-ordering dependency instead -- see `GrantResponse` -- but
        /// that one only ever breaks `grant` itself.)
        #[serde(default)]
        state: Option<String>,
        /// The edge's role: the current effective role for a live member,
        /// or the role the originating invite asked for when no grant has
        /// been emitted yet (which is exactly the case for an edge awaiting
        /// approval). `None` when the coordination plane has neither, and
        /// (same reasoning as `state`) when it does not report the field at
        /// all.
        #[serde(default)]
        role: Option<String>,
    }
    #[derive(Deserialize)]
    struct ListSharesResponse {
        edges: Vec<ShareEdgeInfo>,
    }

    /// The coordination plane's raw `state` value rendered for a person.
    ///
    /// `share list` is where someone who was told their folder is waiting
    /// on an owner goes to check, so the one state that means "waiting on a
    /// human" has to say so in words rather than as an internal enum
    /// spelling. Every other value passes through verbatim -- including one
    /// this build does not recognize, which must still render (see
    /// `ShareEdgeInfo::state`'s own comment on why the field degrades
    /// rather than fails).
    fn state_label(state: Option<&str>) -> &str {
        match state {
            Some(STATE_PENDING_APPROVAL) => "awaiting the owner's approval",
            Some(other) => other,
            None => "unknown",
        }
    }

    fn share_edge_line(edge: &ShareEdgeInfo) -> String {
        format!(
            "{}  group={} ({})  device={}  role={}  {}",
            edge.edge_id,
            edge.group_name,
            edge.group_id,
            edge.device_id,
            edge.role.as_deref().unwrap_or("unknown"),
            state_label(edge.state.as_deref()),
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

    /// Whether this edge is one SOMEONE is being asked to decide on.
    /// A positive match on the exact state, never "not active": a
    /// `pending` edge belongs to its own device's unfinished handshake, and
    /// an unrecognized future state is not something this build knows how
    /// to approve.
    ///
    /// Says nothing about WHO must decide -- see
    /// `approval_requests_awaiting_owner`, which is what `share pending`
    /// actually filters on.
    fn is_awaiting_approval(edge: &ShareEdgeInfo) -> bool {
        edge.state.as_deref() == Some(STATE_PENDING_APPROVAL)
    }

    /// The subset of `edges` that this account is genuinely being asked to
    /// decide on: awaiting approval AND belonging to a folder group this
    /// account OWNS.
    ///
    /// Both halves are load-bearing. `GET /shares` is deliberately scoped
    /// to "the groups you own OR the groups your own devices are in" (that
    /// second half is what lets an invited account resolve a shared group
    /// by name at all -- see `resolve_group_id`), so an INVITED account's
    /// own awaiting-approval edge is in its own listing too. Filtering on
    /// state alone therefore showed an invitee their own request under
    /// "waiting for your approval" and told them to run `share approve`,
    /// which the coordination plane then refuses as not-the-owner. Only the
    /// group owner can act, so only the group owner is shown anything.
    ///
    /// `owned_group_ids` comes from the owner-scoped `/shares/groups`
    /// listing (`list_groups`), not from this listing -- the ownership
    /// answer has to come from somewhere that knows about ownership, and
    /// `ShareEdgeInfo` deliberately carries no owner field.
    fn approval_requests_awaiting_owner(
        edges: Vec<ShareEdgeInfo>,
        owned_group_ids: &std::collections::HashSet<String>,
    ) -> Vec<ShareEdgeInfo> {
        edges
            .into_iter()
            .filter(|edge| is_awaiting_approval(edge) && owned_group_ids.contains(&edge.group_id))
            .collect()
    }

    /// One device waiting for this account's approval to join a folder group
    /// it owns -- the typed result `pending_approvals` hands library callers,
    /// carrying exactly the fields `pending_approval_line` renders.
    ///
    /// A distinct type from `ShareEdgeInfo` rather than that type made
    /// public: `ShareEdgeInfo` is the wire shape of the whole `/shares`
    /// listing (`state`, `edge_id` and all), and a caller acting on an
    /// approval request has no business seeing an edge whose state it would
    /// then have to re-filter. What reaches here has already been filtered
    /// to "this account genuinely has to decide on it".
    #[derive(Clone, Debug)]
    pub struct PendingApproval {
        pub group_id: String,
        pub group_name: String,
        pub device_id: String,
        /// The role the originating invite asked for. `None` when the
        /// coordination plane reported none, or reported no role field at
        /// all (an older deployment) -- rendered as `unknown` rather than
        /// guessed at.
        pub role: Option<String>,
    }

    impl PendingApproval {
        /// Narrows an already-filtered `/shares` edge to the fields a
        /// decision actually needs.
        fn from_edge(edge: ShareEdgeInfo) -> Self {
            PendingApproval {
                group_id: edge.group_id,
                group_name: edge.group_name,
                device_id: edge.device_id,
                role: edge.role,
            }
        }
    }

    /// The empty-state line for "nobody is waiting on you", naming how a
    /// request gets here in the first place. Public so the desktop app's
    /// share window says the same thing rather than inventing its own,
    /// weaker, wording for the same state.
    pub const NO_PENDING_APPROVALS: &str =
        "No one is waiting for your approval. Requests appear here after someone redeems an \
         invite you minted with `yadorilink share invite <group> --require-approval`.";

    fn pending_approval_line(request: &PendingApproval) -> String {
        let short_id = short_device_id(&request.device_id);
        format!(
            "group={} ({})  device={} ({short_id})  requested role={}",
            request.group_name,
            request.group_id,
            request.device_id,
            request.role.as_deref().unwrap_or("unknown"),
        )
    }

    /// `yadorilink share pending`: the devices waiting for this account's
    /// approval to join a folder group it owns.
    ///
    /// Reads the same `GET /shares` listing `share list` does and filters
    /// client-side, rather than asking for a dedicated route: that listing
    /// already returns every edge visible to this account with no state
    /// filter, so a waiting request is in it from the moment it exists.
    /// This is deliberately a pull, not a notification -- there is no
    /// background watcher anywhere in this path.
    ///
    /// That listing is broader than "requests I can act on", though, so it
    /// is intersected against the owner-scoped `/shares/groups` listing
    /// before anything is displayed -- see
    /// `approval_requests_awaiting_owner`. Two reads rather than one,
    /// deliberately: showing an invitee their own pending request and
    /// telling them to approve it is worse than an extra round trip on a
    /// command run by hand.
    /// Every request this account is being asked to decide on, across all
    /// the folder groups it owns, printing nothing.
    ///
    /// Split out of `list_pending_approvals` below so a caller that renders
    /// these itself -- the desktop app's share window, which narrows them to
    /// the one folder it was opened for -- shares this filtering rather than
    /// re-deriving "which requests are actually mine to act on", the exact
    /// question `approval_requests_awaiting_owner` exists to answer.
    pub async fn pending_approvals() -> Result<Vec<PendingApproval>, CliError> {
        let access_token = require_access_token()?;
        let owned_group_ids: std::collections::HashSet<String> =
            list_groups().await?.into_iter().map(|group| group.group_id).collect();
        let resp: ListSharesResponse = get_json("/shares", Some(&access_token)).await?;
        Ok(approval_requests_awaiting_owner(resp.edges, &owned_group_ids)
            .into_iter()
            .map(PendingApproval::from_edge)
            .collect())
    }

    pub async fn list_pending_approvals() -> Result<(), CliError> {
        let waiting = pending_approvals().await?;
        if waiting.is_empty() {
            println!("{NO_PENDING_APPROVALS}");
            return Ok(());
        }
        for request in &waiting {
            println!("{}", pending_approval_line(request));
        }
        println!();
        println!("Admit one with:   yadorilink share approve <group> <device-id>");
        println!("Turn one down with: yadorilink share deny <group> <device-id>");
        Ok(())
    }

    /// `result` is `approved` when this call is what admitted the device,
    /// or `already_active` when it was already a member -- a retry, a
    /// concurrent approve, or a device admitted some other way. Both are
    /// successes; they are distinguished only so this command can avoid
    /// claiming it did something it did not.
    #[derive(Deserialize)]
    struct ApproveResponse {
        result: String,
    }

    /// The approve route names its whole request in the URL (group id and
    /// device id) and reads no body at all -- deliberately, so there is no
    /// field an approving caller could use to widen the granted role. This
    /// empty struct exists only because the shared `post_json` helper
    /// always sends a JSON body.
    #[derive(Serialize)]
    struct ApproveRequest {}

    /// `yadorilink share approve <group> <device>`: admits a device waiting
    /// for this account's approval (from `share pending`).
    ///
    /// Deliberately takes no `--role`: the granted role is the one the
    /// invite the recipient redeemed already named, re-derived by the
    /// coordination plane from that invite. There is no way to widen it
    /// here, which is what keeps "what the recipient was offered" and "what
    /// they end up with" the same thing.
    ///
    /// HTTP-only, like `share list`/`share members` -- admitting someone
    /// else's device changes nothing about this machine's local state, so
    /// there is no daemon involvement and no local link to keep in step.
    pub async fn approve(group_name: String, device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let result = approve_resolved(&group_id, &device_id).await?;
        println!("{}", approve_result_line(&result, &device_id, &group_name));
        Ok(())
    }

    /// Admits a waiting device into an ALREADY-RESOLVED folder group and
    /// returns the coordination plane's own `result` value, printing
    /// nothing. Split out for the same reason as `mint_invite_resolved`; the
    /// raw value (rather than a rendered line) is returned so the caller
    /// decides how to word it -- see `approve_result_line`, which is what
    /// both this command and the desktop app's share window word it with.
    pub async fn approve_resolved(group_id: &str, device_id: &str) -> Result<String, CliError> {
        let access_token = require_access_token()?;
        let response: ApproveResponse = post_json(
            &format!("/shares/groups/{group_id}/members/{device_id}/approve"),
            &ApproveRequest {},
            Some(&access_token),
        )
        .await?;
        Ok(response.result)
    }

    /// What `share approve` reports for each result the coordination plane
    /// can return, matched POSITIVELY on every recognized value.
    ///
    /// An unrecognized value is a build talking to a newer coordination
    /// plane, and defaulting it to "Approved" would claim an outcome this
    /// build cannot actually confirm happened -- the same positive-match
    /// discipline `is_awaiting_approval` applies for the same reason. The
    /// call did return 2xx, so something succeeded; say exactly that, and
    /// name the value so it can be looked up.
    pub fn approve_result_line(result: &str, device_id: &str, group_name: &str) -> String {
        match result {
            "approved" => format!("Approved {device_id} for {group_name}"),
            "already_active" => {
                format!("{device_id} already had access to {group_name}; nothing to approve")
            }
            other => format!(
                "The approval request for {device_id} in {group_name} was accepted, with an \
                 outcome this version does not recognize ({other:?}); check `yadorilink share \
                 list` for the current state"
            ),
        }
    }

    /// `yadorilink share deny <group> <device>`: turns down a device
    /// waiting for this account's approval (from `share pending`).
    ///
    /// This IS `revoke`, called unchanged rather than reimplemented, and
    /// that is load-bearing rather than mere convenience: the revoke path
    /// marks the originating invite revoked atomically with removing the
    /// edge, which is what stops the denied recipient from simply replaying
    /// their accept. A bespoke delete that only removed the row would leave
    /// the invite replayable.
    ///
    /// The consequence worth knowing about: because deny and revoke are the
    /// same operation, denying a request that a concurrent `share approve`
    /// has ALREADY admitted revokes that just-granted membership rather
    /// than doing nothing. That is correct -- an owner may always revoke a
    /// live member, and the end state is the one the denier asked for.
    ///
    /// Never passes `--force`, and must never need to: the daemon's
    /// full-replica readiness gate does not apply to a device whose edge is
    /// not `active` (see `ReplicaMembershipService::
    /// target_edge_is_provably_not_active`), which is exactly what a device
    /// awaiting approval is. `--force`'s data-loss warning describes data
    /// at risk; a device that was never admitted holds none, so offering it
    /// here would be asking an owner to accept a risk that does not exist.
    pub async fn deny(group_name: String, device_id: String) -> Result<(), CliError> {
        revoke_announcing(group_name, device_id, false, RevokeAnnouncement::Denied).await
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
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

    /// Accepts either the bare invite code `share invite` prints, or the
    /// full `yadorilink://invite/<code>` URL -- so a recipient can paste
    /// whichever one they were actually given (a scanned QR always decodes
    /// to the URL; a code read/typed by hand is the bare form).
    fn extract_invite_code(input: &str) -> &str {
        input.strip_prefix("yadorilink://invite/").unwrap_or(input)
    }

    /// `yadorilink share accept <code-or-url> --path <dir> --storage-mode
    /// <mode>`: cross-account onboarding. Redeems a one-use invite minted
    /// by another account's `share invite` and links the resulting
    /// membership locally at `--path`, via the coordination plane's
    /// invite-accept prepare/activate protocol (routed through the daemon's
    /// `AcceptInviteCommand` -- see `EnrollmentService::accept_invite_and_link`'s
    /// own doc comment for the crash-safety/retry story, and in particular
    /// why re-running this exact command with the SAME code after a
    /// failure or crash is always safe). Unlike `join`, there is no
    /// coordination-plane group listing to resolve a name against
    /// beforehand -- the invite code alone names the group, which the
    /// daemon's response then reveals.
    pub async fn accept(
        code_or_url: String,
        path: String,
        storage_mode: String,
        yes: bool,
    ) -> Result<(), CliError> {
        let on_demand = parse_storage_mode(&storage_mode)?;
        let code = extract_invite_code(&code_or_url).to_string();

        // Preflight the local path first, before any coordination-plane
        // state, so the common failure (a bad or risky folder) never
        // redeems the one-use invite at all.
        let (absolute, acknowledged) =
            crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
        let local_path = absolute.to_string_lossy().to_string();

        let response =
            control_client::send(ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
                code,
                local_path: local_path.clone(),
                on_demand,
                acknowledge_risks: acknowledged,
            }))
            .await?;
        match response.payload {
            Some(RespPayload::AcceptInviteCommand(response)) => match response.result {
                Some(accept_invite_command_response::Result::Outcome(outcome)) => {
                    for line in accept_invite_lines(
                        &outcome.group_id,
                        &local_path,
                        on_demand,
                        outcome.awaiting_approval,
                    ) {
                        println!("{line}");
                    }
                    Ok(())
                }
                Some(accept_invite_command_response::Result::Error(error)) => {
                    Err(application_error(error))
                }
                None => Err(CliError::Other("daemon returned an empty accept result".into())),
            },
            Some(RespPayload::Error(error)) => Err(CliError::Other(error)),
            _ => Err(CliError::Other("unexpected daemon response to accept-invite".into())),
        }
    }

    /// What `share accept` prints once the daemon reports success.
    ///
    /// The redemption itself succeeding does NOT mean the folder is
    /// syncing. An invite minted with `--require-approval` lands the
    /// membership in the group owner's queue instead of granting it, and
    /// until they decide, this device holds a linked folder that
    /// deliberately syncs nothing. Reporting that as "Joined folder group
    /// ... and linked it at ..." is not merely imprecise -- it is the one
    /// message that would stop someone from ever finding out why their
    /// files are not moving, since nothing else in this flow will tell
    /// them and no notification arrives when approval comes through.
    ///
    /// So the two outcomes get genuinely different wording, and the waiting
    /// one names the command that shows the current answer. Local edits
    /// made while waiting are not lost either way -- with no policy-log
    /// grant they are withheld rather than sent -- but nobody should have
    /// to take that on faith from a message that claimed they had joined.
    fn accept_invite_lines(
        group_id: &str,
        local_path: &str,
        on_demand: bool,
        awaiting_approval: bool,
    ) -> Vec<String> {
        let storage = if on_demand { " (on-demand)" } else { "" };
        if !awaiting_approval {
            return vec![format!(
                "Joined folder group {group_id} and linked it at {local_path}{storage}"
            )];
        }
        vec![
            format!(
                "Invite redeemed for folder group {group_id}, and the folder is linked at \
                 {local_path}{storage} -- but it is NOT syncing yet."
            ),
            "This invite requires the group owner's approval. Nothing will sync until they \
             approve it, and there is no notification when they do."
                .to_string(),
            "Check the current answer with:   yadorilink share list".to_string(),
        ]
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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        fn base_edge() -> ShareEdgeInfo {
            ShareEdgeInfo {
                edge_id: "edge-1".into(),
                group_id: "group-1".into(),
                group_name: "photos".into(),
                device_id: "device-1".into(),
                state: Some("active".into()),
                role: Some("editor".into()),
            }
        }

        fn waiting_edge(device_id: &str, role: Option<&str>) -> ShareEdgeInfo {
            ShareEdgeInfo {
                state: Some(STATE_PENDING_APPROVAL.into()),
                device_id: device_id.into(),
                role: role.map(str::to_string),
                ..base_edge()
            }
        }

        #[test]
        fn share_edge_line_renders_edge_fields() {
            let line = share_edge_line(&base_edge());
            assert!(line.contains("edge-1"));
            assert!(line.contains("device-1"));
            assert!(line.contains("role=editor"));
            assert!(line.contains("active"));
        }

        /// An edge awaiting approval must be visibly different in `share
        /// list` from an ordinary member -- that listing is the only place
        /// the state surfaces at all, and an owner who cannot see the
        /// difference has no reason to go looking for `share pending`.
        ///
        /// It must also read as something a person can act on. `share list`
        /// is exactly where an invitee who was told their folder is waiting
        /// on an owner goes to check, so this one state is rendered in
        /// words rather than as the coordination plane's own enum spelling.
        #[test]
        fn share_edge_line_distinguishes_an_edge_awaiting_approval() {
            let line = share_edge_line(&waiting_edge("device-2", Some("viewer")));
            assert!(line.contains("awaiting the owner's approval"), "{line}");
            assert!(!line.contains(STATE_PENDING_APPROVAL), "{line}");
            let ordinary = share_edge_line(&base_edge());
            assert!(!ordinary.contains("awaiting"), "{ordinary}");
            assert!(ordinary.contains("active"), "{ordinary}");
        }

        /// A state this build does not recognize still renders -- verbatim,
        /// and never as one of the states it does know.
        #[test]
        fn share_edge_line_renders_an_unrecognized_state_verbatim() {
            let edge = ShareEdgeInfo { state: Some("some_future_state".into()), ..base_edge() };
            let line = share_edge_line(&edge);
            assert!(line.contains("some_future_state"), "{line}");
            assert!(!line.contains("awaiting"), "{line}");
        }

        /// A role the coordination plane could not determine renders as a
        /// visible placeholder rather than an empty gap, and never as a
        /// plausible-looking real role.
        #[test]
        fn share_edge_line_renders_a_missing_role_as_unknown() {
            let line = share_edge_line(&waiting_edge("device-2", None));
            assert!(line.contains("role=unknown"), "{line}");
        }

        /// The compatibility property `state`/`role` are optional FOR: a
        /// coordination plane that predates them still parses, so
        /// `resolve_group_id` -- and with it nearly every command in this
        /// file -- keeps working instead of failing on a missing field.
        #[test]
        fn share_edge_info_parses_a_response_that_predates_state_and_role() {
            let parsed: ShareEdgeInfo = serde_json::from_str(
                r#"{"edgeId":"e-1","groupId":"g-1","groupName":"photos","deviceId":"d-1"}"#,
            )
            .unwrap();
            assert_eq!(parsed.group_id, "g-1");
            assert_eq!(parsed.state, None);
            assert_eq!(parsed.role, None);
            // Such an edge is never mistaken for one awaiting approval.
            assert!(!is_awaiting_approval(&parsed));
        }

        /// Regression test, same bug class as
        /// `folder_group_info_deserializes_the_coordination_planes_camelcase_shape`
        /// above: `GET /shares` sends camelCase keys too. The literal here is
        /// the coordination plane's real `ShareEdgeInfo` response shape,
        /// including the fields added for approval requests -- a mismatch in
        /// any one of them silently drops it, which is the exact bug class
        /// this whole family of tests exists for.
        #[test]
        fn share_edge_info_deserializes_the_coordination_planes_camelcase_shape() {
            let parsed: ShareEdgeInfo = serde_json::from_str(
                r#"{"edgeId":"e-1","groupId":"g-1","groupName":"photos","deviceId":"d-1",
                    "state":"pending_approval","role":"viewer"}"#,
            )
            .unwrap();
            assert_eq!(parsed.edge_id, "e-1");
            assert_eq!(parsed.group_id, "g-1");
            assert_eq!(parsed.group_name, "photos");
            assert_eq!(parsed.device_id, "d-1");
            assert_eq!(parsed.state.as_deref(), Some(STATE_PENDING_APPROVAL));
            assert_eq!(parsed.role.as_deref(), Some("viewer"));
        }

        /// `role` is genuinely nullable on the wire (an edge with neither a
        /// grant record nor an originating invite), so an explicit JSON
        /// `null` must parse rather than fail the whole listing.
        #[test]
        fn share_edge_info_accepts_a_null_role() {
            let parsed: ShareEdgeInfo = serde_json::from_str(
                r#"{"edgeId":"e-1","groupId":"g-1","groupName":"photos","deviceId":"d-1",
                    "state":"pending","role":null}"#,
            )
            .unwrap();
            assert_eq!(parsed.role, None);
        }

        /// The line an owner actually reads before deciding. It must name
        /// the device to pass to `share approve`/`share deny`, and the role
        /// approving would grant -- deciding without the role is deciding
        /// blind.
        #[test]
        fn pending_approval_line_names_the_device_and_the_requested_role() {
            let line = pending_approval_line(&PendingApproval::from_edge(waiting_edge(
                "device-abcdef123",
                Some("editor"),
            )));
            assert!(line.contains("device-abcdef123"), "{line}");
            assert!(line.contains("requested role=editor"), "{line}");
            assert!(line.contains("photos"), "{line}");
        }

        /// The exact line `share pending` printed before the listing was
        /// split into a data-returning `pending_approvals` plus this
        /// formatter -- pinned in full so the split stayed
        /// behaviour-preserving.
        #[test]
        fn pending_approval_line_renders_the_same_text_as_before_the_listing_was_split() {
            let line = pending_approval_line(&PendingApproval::from_edge(waiting_edge(
                "device-abcdef123",
                Some("editor"),
            )));
            assert_eq!(
                line,
                "group=photos (group-1)  device=device-abcdef123 (device-a)  requested role=editor"
            );
        }

        /// A request with no reported role reads as `unknown` rather than
        /// being dropped or guessed at -- the owner still needs to see that
        /// somebody is waiting.
        #[test]
        fn pending_approval_line_reports_an_absent_role_as_unknown() {
            let line =
                pending_approval_line(&PendingApproval::from_edge(waiting_edge("device-1", None)));
            assert!(line.contains("requested role=unknown"), "{line}");
        }

        /// The narrowing from a `/shares` edge to a decision must not lose a
        /// field the owner (or the desktop window that renders these) needs.
        #[test]
        fn a_pending_approval_keeps_every_field_a_decision_needs() {
            let request = PendingApproval::from_edge(waiting_edge("device-2", Some("viewer")));
            assert_eq!(request.group_id, "group-1");
            assert_eq!(request.group_name, "photos");
            assert_eq!(request.device_id, "device-2");
            assert_eq!(request.role.as_deref(), Some("viewer"));
        }

        /// The empty state has to say how a request gets here at all --
        /// "nothing to do" alone leaves someone who was told to expect a
        /// request with nowhere to go. Shared with the desktop share
        /// window, so it is pinned as a constant rather than typed twice.
        #[test]
        fn the_no_pending_approvals_line_names_how_a_request_appears() {
            assert!(NO_PENDING_APPROVALS.starts_with("No one is waiting for your approval."));
            assert!(NO_PENDING_APPROVALS.contains("--require-approval"), "{NO_PENDING_APPROVALS}");
        }

        fn owned(group_ids: &[&str]) -> std::collections::HashSet<String> {
            group_ids.iter().map(|id| (*id).to_string()).collect()
        }

        /// The state half of the filter `share pending` applies. An `active`
        /// member is not a request, and neither is a `pending` edge whose own
        /// device has not finished its side -- listing either would invite an
        /// owner to "approve" something that is not theirs to decide.
        #[test]
        fn pending_approval_filter_selects_only_edges_in_the_awaiting_state() {
            let edges = vec![
                base_edge(),
                waiting_edge("device-waiting", Some("viewer")),
                ShareEdgeInfo { state: Some("pending".into()), ..base_edge() },
                ShareEdgeInfo { state: None, ..base_edge() },
            ];
            let selected = approval_requests_awaiting_owner(edges, &owned(&["group-1"]));
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].device_id, "device-waiting");
        }

        /// The ownership half, which is the one that actually needs a
        /// foreign-group edge to exercise at all.
        ///
        /// `GET /shares` returns the edges of groups this account owns AND
        /// the edges binding this account's own devices into SOMEONE ELSE's
        /// group. An invited account's own awaiting-approval edge is
        /// therefore in its own listing, indistinguishable by `state` from a
        /// request its owner is being asked to decide. Filtering on state
        /// alone showed an invitee their own request under "waiting for your
        /// approval" with instructions to approve it -- which the
        /// coordination plane then refuses, since they do not own the group.
        #[test]
        fn pending_approval_filter_excludes_a_request_on_a_group_this_account_does_not_own() {
            fn on_my_group() -> ShareEdgeInfo {
                ShareEdgeInfo {
                    group_id: "group-mine".into(),
                    ..waiting_edge("device-b", Some("viewer"))
                }
            }
            fn on_someone_elses_group() -> ShareEdgeInfo {
                ShareEdgeInfo {
                    group_id: "group-theirs".into(),
                    group_name: "someone-elses-photos".into(),
                    ..waiting_edge("device-of-this-account", Some("editor"))
                }
            }

            // The owner's own view: only their group is in the owned set.
            let as_owner = approval_requests_awaiting_owner(
                vec![on_my_group(), on_someone_elses_group()],
                &owned(&["group-mine"]),
            );
            assert_eq!(as_owner.len(), 1);
            assert_eq!(as_owner[0].group_id, "group-mine");

            // The invited account's own view: it owns no groups at all, so
            // it has nothing to decide -- not even about its own request.
            let as_invitee =
                approval_requests_awaiting_owner(vec![on_someone_elses_group()], &owned(&[]));
            assert!(
                as_invitee.is_empty(),
                "an account that owns no groups must never be shown an approval request"
            );
        }

        /// The approve route carries its whole request in the URL and reads
        /// no body, so this must serialize to an empty JSON object -- in
        /// particular it must never grow a `role` key, which is the one
        /// thing an approving caller must not be able to influence.
        #[test]
        fn approve_request_body_is_empty_and_carries_no_role() {
            let body = serde_json::to_value(ApproveRequest {}).unwrap();
            assert_eq!(body, serde_json::json!({}));
        }

        /// Both outcomes of the approve route are successes and must parse;
        /// they differ only in what this command claims it did.
        #[test]
        fn approve_response_deserializes_both_outcomes() {
            let approved: ApproveResponse =
                serde_json::from_str(r#"{"result":"approved"}"#).unwrap();
            assert_eq!(approved.result, "approved");
            let already: ApproveResponse =
                serde_json::from_str(r#"{"result":"already_active"}"#).unwrap();
            assert_eq!(already.result, "already_active");
        }

        /// Each recognized approve result gets its own wording, matched
        /// positively -- and an unrecognized one must NOT fall through to
        /// "Approved", which would claim an outcome this build cannot
        /// confirm happened.
        #[test]
        fn approve_result_line_never_claims_approval_for_an_unrecognized_result() {
            assert!(approve_result_line("approved", "device-1", "photos").starts_with("Approved"));
            assert!(approve_result_line("already_active", "device-1", "photos")
                .contains("nothing to approve"));

            let unknown = approve_result_line("some_future_outcome", "device-1", "photos");
            assert!(!unknown.contains("Approved"), "{unknown}");
            assert!(unknown.contains("does not recognize"), "{unknown}");
            assert!(unknown.contains("some_future_outcome"), "{unknown}");
        }

        /// An ordinary acceptance genuinely joined the group, and says so.
        #[test]
        fn accept_invite_reports_a_completed_join_when_no_approval_is_pending() {
            let lines = accept_invite_lines("group-1", "/home/bob/Shared", false, false);
            assert_eq!(lines.len(), 1);
            assert!(lines[0].starts_with("Joined folder group group-1"), "{:?}", lines[0]);
            assert!(lines[0].contains("/home/bob/Shared"), "{:?}", lines[0]);
        }

        /// The message this whole outcome variant exists for: an acceptance
        /// awaiting the owner's approval must NOT be reported as a join.
        /// Someone reading it has to learn three things -- that the folder
        /// is not syncing, that a person has to act before it does, and
        /// where to check -- because nothing else in this flow will tell
        /// them and no notification arrives when approval lands.
        #[test]
        fn accept_invite_never_claims_a_join_while_awaiting_approval() {
            let lines = accept_invite_lines("group-1", "/home/bob/Shared", false, true);
            let printed = lines.join("\n");
            assert!(!printed.contains("Joined"), "{printed}");
            assert!(printed.contains("NOT syncing"), "{printed}");
            assert!(printed.contains("owner's approval"), "{printed}");
            assert!(printed.contains("yadorilink share list"), "{printed}");
            // Still says where the folder actually is -- the link DID
            // commit, and the user needs to know where.
            assert!(printed.contains("/home/bob/Shared"), "{printed}");
        }

        /// The storage mode is still reported in either case; it describes
        /// the local link, which committed either way.
        #[test]
        fn accept_invite_reports_the_storage_mode_in_both_outcomes() {
            assert!(accept_invite_lines("g", "/p", true, false)[0].contains("(on-demand)"));
            assert!(accept_invite_lines("g", "/p", true, true)[0].contains("(on-demand)"));
        }

        /// Same bug class again: `GET /shares/joinable` also sends
        /// camelCase keys.
        #[test]
        fn joinable_group_info_deserializes_the_coordination_planes_camelcase_shape() {
            let parsed: JoinableGroupInfo =
                serde_json::from_str(r#"{"groupId":"g-1","name":"photos"}"#).unwrap();
            assert_eq!(parsed.group_id, "g-1");
            assert_eq!(parsed.name, "photos");
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

            let device =
                serde_json::to_value(GrantRequest { device_id: "d", role: Some("editor") })
                    .unwrap();
            assert_eq!(device["deviceId"], "d");
            assert!(device.get("device_id").is_none());
            assert_eq!(device["role"], "editor");

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

        /// Serialization gotcha: `reqwest`'s `.json(body)` serializes
        /// `Option::None` as an explicit JSON `null` by default, but the
        /// coordination plane's grant-role parsing treats a genuinely ABSENT
        /// key as "use the default" (editor) and a present-but-null key as
        /// invalid input. `#[serde(skip_serializing_if = "Option::is_none")]`
        /// on `GrantRequest::role` is what closes that gap -- this test would
        /// fail if that attribute were ever removed.
        #[test]
        fn grant_request_omits_the_role_key_entirely_when_none_but_serializes_it_when_some() {
            let omitted =
                serde_json::to_value(GrantRequest { device_id: "d", role: None }).unwrap();
            assert!(
                omitted.get("role").is_none(),
                "omitting --role must produce a body with no `role` key at all (not a JSON null), got: {omitted}"
            );
            assert_eq!(omitted["deviceId"], "d");

            let present =
                serde_json::to_value(GrantRequest { device_id: "d", role: Some("viewer") })
                    .unwrap();
            assert_eq!(present["role"], "viewer");

            // Also checked on the raw serialized string, not just the parsed
            // `Value` -- so this fails loudly if a future refactor drops
            // `skip_serializing_if` and the field starts round-tripping as a
            // literal `"role":null`.
            let omitted_json =
                serde_json::to_string(&GrantRequest { device_id: "d", role: None }).unwrap();
            assert!(!omitted_json.contains("role"), "expected no `role` key in {omitted_json}");
        }

        /// `GrantResponse` must deserialize both response shapes the
        /// coordination plane can send: a fresh grant (`created: true`) and
        /// a no-op re-grant of an already-authorized device (`created:
        /// false`, `role` is that device's pre-existing role). Both fields
        /// are required, not optional -- an older coordination worker that
        /// still returns `204 No Content` (no body at all) fails this
        /// deserialization entirely, which is the deploy-ordering
        /// constraint documented on this command's own doc comment.
        #[test]
        fn grant_response_deserializes_both_created_and_unchanged_shapes() {
            let created: GrantResponse =
                serde_json::from_str(r#"{"role":"editor","created":true}"#).unwrap();
            assert_eq!(created.role, "editor");
            assert!(created.created);

            let unchanged: GrantResponse =
                serde_json::from_str(r#"{"role":"editor","created":false}"#).unwrap();
            assert_eq!(unchanged.role, "editor");
            assert!(!unchanged.created);
        }

        fn sample_member(device_id: &str) -> GroupMemberInfo {
            GroupMemberInfo {
                device_id: device_id.to_string(),
                device_name: "laptop".to_string(),
                role: "editor".to_string(),
                is_same_account: true,
                is_caller_account: true,
                storage_mode: "eager".to_string(),
                online: true,
                last_seen_unix: 1_700_000_000,
            }
        }

        /// `GroupMemberInfo` must deserialize the coordination plane's exact
        /// camelCase `GroupMemberInfo` response shape
        /// (`coordination-worker/src/shares/service.ts`) -- including the
        /// `"unknown"` role sentinel, which this command renders verbatim
        /// rather than rejecting.
        #[test]
        fn group_member_info_deserializes_the_coordination_planes_camelcase_response() {
            let json = r#"{
                "deviceId": "dev-1",
                "deviceName": "laptop",
                "role": "unknown",
                "isSameAccount": false,
                "isCallerAccount": false,
                "storageMode": "on-demand",
                "online": false,
                "lastSeenUnix": 0
            }"#;
            let member: GroupMemberInfo = serde_json::from_str(json).unwrap();
            assert_eq!(member.device_id, "dev-1");
            assert_eq!(member.device_name, "laptop");
            assert_eq!(member.role, "unknown");
            assert!(!member.is_same_account);
            assert!(!member.is_caller_account);
            assert_eq!(member.storage_mode, "on-demand");
            assert!(!member.online);
        }

        #[test]
        fn member_line_labels_the_callers_own_device_as_you() {
            let member = sample_member("dev-1");
            let line = member_line(&member, Some("dev-1"));
            assert!(line.contains("you"), "expected a 'you' label, got: {line}");
            assert!(!line.contains("your other device"));
        }

        #[test]
        fn member_line_labels_the_callers_own_other_device_as_your_other_device() {
            // Same account as the caller (is_caller_account), not the exact
            // device running this command.
            let member = sample_member("dev-2");
            let line = member_line(&member, Some("dev-1"));
            assert!(line.contains("your other device"), "got: {line}");
        }

        #[test]
        fn member_line_labels_a_cross_account_device_as_invited() {
            let mut member = sample_member("dev-3");
            member.is_same_account = false;
            member.is_caller_account = false;
            let line = member_line(&member, Some("dev-1"));
            assert!(line.contains("invited"), "got: {line}");
            assert!(!line.contains("your other device"));
            assert!(!line.contains("owner's device"));
        }

        /// A caller device this local machine has never registered (no
        /// `device_config` on disk) must still render every member
        /// correctly -- just without ever matching "you".
        #[test]
        fn member_line_with_no_known_own_device_id_never_says_you() {
            let member = sample_member("dev-1");
            let line = member_line(&member, None);
            // "you" as its own word, not merely the substring inside "your
            // other device" below -- the relationship field is always
            // padded with double spaces in `member_line`'s format string.
            assert!(!line.contains("  you  "), "got: {line}");
            assert!(line.contains("your other device"));
        }

        /// Regression test for the owner/caller relationship inversion: a
        /// NON-OWNER caller (an invited account's own user) running `share
        /// members` themselves must see their OWN other device labeled as
        /// their own, and the group OWNER's device labeled as the owner's --
        /// not the other way around. Before `is_caller_account` existed,
        /// this command echoed the server's owner-relative `is_same_account`
        /// flag directly as if it meant "shares an account with the
        /// caller", which is only true when the caller happens to BE the
        /// owner: for any other caller it produced exactly the inverted
        /// labels this test asserts do NOT happen.
        #[test]
        fn member_line_from_a_non_owner_callers_perspective_labels_relationships_correctly() {
            let caller_device = "invitee-device-1";

            // The caller's own OTHER device: not on the group owner's
            // account (is_same_account: false) but IS on the account
            // running this command (is_caller_account: true).
            let mut my_other_device = sample_member("invitee-device-2");
            my_other_device.is_same_account = false;
            my_other_device.is_caller_account = true;
            let line = member_line(&my_other_device, Some(caller_device));
            assert!(line.contains("your other device"), "got: {line}");
            assert!(!line.contains("owner's device"));
            assert!(!line.contains("invited"));

            // The group OWNER's device: on the group owner's account
            // (is_same_account: true) but NOT on the account running this
            // command (is_caller_account: false) -- inverted from above.
            let mut owner_device = sample_member("owner-device-1");
            owner_device.is_same_account = true;
            owner_device.is_caller_account = false;
            let line = member_line(&owner_device, Some(caller_device));
            assert!(line.contains("owner's device"), "got: {line}");
            assert!(!line.contains("your other device"));
            assert!(!line.contains("invited"));

            // A genuine third party (neither the caller's own account nor
            // the group owner's) renders as plain "invited".
            let mut stranger_device = sample_member("stranger-device-1");
            stranger_device.is_same_account = false;
            stranger_device.is_caller_account = false;
            let line = member_line(&stranger_device, Some(caller_device));
            assert!(line.contains("invited"), "got: {line}");
            assert!(!line.contains("your other device"));
            assert!(!line.contains("owner's device"));
        }

        #[test]
        fn member_line_renders_role_online_and_storage_mode() {
            let mut member = sample_member("dev-1");
            member.role = "viewer".to_string();
            member.online = false;
            member.storage_mode = "on-demand".to_string();
            let line = member_line(&member, None);
            assert!(line.contains("role=viewer"), "got: {line}");
            assert!(line.contains("offline"), "got: {line}");
            assert!(line.contains("on-demand"), "got: {line}");
            assert!(
                !line.contains("online"),
                "expected offline, not a substring match on online, got: {line}"
            );
        }

        #[test]
        fn member_line_truncates_the_device_id_for_display() {
            let member = sample_member("0123456789abcdef");
            let line = member_line(&member, None);
            assert!(line.contains("(01234567)"), "got: {line}");
            assert!(
                !line.contains("0123456789abcdef"),
                "expected only the truncated id, got: {line}"
            );
        }

        /// `share members`' printed line, pinned in full, so pulling the
        /// relationship/storage labels and the id truncation out into their
        /// own reusable functions did not alter a single character of what
        /// this command prints.
        #[test]
        fn member_line_renders_exactly_the_same_text_as_before_its_labels_were_extracted() {
            let member = sample_member("0123456789abcdef");
            assert_eq!(
                member_line(&member, Some("0123456789abcdef")),
                "device=laptop (01234567)  role=editor  you  online  full copy"
            );

            let mut stranger = sample_member("fedcba9876543210");
            stranger.device_name = "desktop".to_string();
            stranger.role = "viewer".to_string();
            stranger.is_same_account = false;
            stranger.is_caller_account = false;
            stranger.online = false;
            stranger.storage_mode = "on-demand".to_string();
            assert_eq!(
                member_line(&stranger, Some("0123456789abcdef")),
                "device=desktop (fedcba98)  role=viewer  invited  offline  on-demand"
            );
        }

        /// The relationship label is now a shared function rather than an
        /// expression inlined into `member_line`, because a second surface
        /// renders the same listing. It must answer identically to what
        /// `member_line` prints, for every one of the four cases -- the
        /// inversion this label once shipped came from exactly this logic
        /// being re-derived rather than reused.
        #[test]
        fn the_shared_relationship_label_agrees_with_what_the_member_line_prints() {
            let caller = "caller-device";

            let mut own = sample_member(caller);
            own.is_same_account = false;
            own.is_caller_account = true;
            assert_eq!(member_relationship_label(&own, Some(caller)), "you");

            let mut my_other = sample_member("other-device");
            my_other.is_same_account = false;
            my_other.is_caller_account = true;
            assert_eq!(member_relationship_label(&my_other, Some(caller)), "your other device");

            let mut owners = sample_member("owner-device");
            owners.is_same_account = true;
            owners.is_caller_account = false;
            assert_eq!(member_relationship_label(&owners, Some(caller)), "owner's device");

            let mut stranger = sample_member("stranger-device");
            stranger.is_same_account = false;
            stranger.is_caller_account = false;
            assert_eq!(member_relationship_label(&stranger, Some(caller)), "invited");

            for member in [&own, &my_other, &owners, &stranger] {
                let line = member_line(member, Some(caller));
                let label = member_relationship_label(member, Some(caller));
                assert!(
                    line.contains(&format!("  {label}  ")),
                    "{line} should carry the shared label {label:?}"
                );
            }
        }

        /// A storage mode this build does not recognize must understate what
        /// is held ("on-demand"), never claim a full copy.
        #[test]
        fn the_storage_label_claims_a_full_copy_only_for_the_eager_mode() {
            let mut member = sample_member("dev-1");
            assert_eq!(member_storage_label(&member), "full copy");
            member.storage_mode = "on-demand".to_string();
            assert_eq!(member_storage_label(&member), "on-demand");
            member.storage_mode = "some-future-mode".to_string();
            assert_eq!(member_storage_label(&member), "on-demand");
        }

        #[test]
        fn a_short_device_id_is_the_leading_eight_characters_and_never_panics_on_a_shorter_one() {
            assert_eq!(short_device_id("0123456789abcdef"), "01234567");
            assert_eq!(short_device_id("abc"), "abc");
            assert_eq!(short_device_id(""), "");
        }

        /// The role a live role CHANGE may request: viewer or editor, never
        /// owner. Checked locally as well as server-side, so a mistyped role
        /// fails before a network round trip -- and so `owner` is refused by
        /// this build even against a coordination plane that one day accepts
        /// it on some other route.
        #[test]
        fn a_role_change_accepts_viewer_and_editor_and_refuses_owner() {
            assert!(validate_changeable_role("viewer").is_ok());
            assert!(validate_changeable_role("editor").is_ok());

            let refused = validate_changeable_role("owner").unwrap_err().to_string();
            assert!(refused.contains("owner"), "{refused}");
            assert!(refused.contains("viewer or editor"), "{refused}");

            assert_eq!(CHANGEABLE_ROLES, ["viewer", "editor"]);
            assert!(!CHANGEABLE_ROLES.contains(&"owner"));
        }

        /// Matched exactly, the way the coordination plane matches it:
        /// accepting a spelling the plane refuses would only move the
        /// failure one round trip later, and silently rewriting it would
        /// send a role the caller never typed.
        #[test]
        fn a_role_change_refuses_a_role_the_coordination_plane_would_refuse() {
            for role in ["", "Viewer", "EDITOR", "owner ", "admin", "read-only"] {
                assert!(
                    validate_changeable_role(role).is_err(),
                    "{role:?} must be refused locally, exactly as the coordination plane \
                     refuses it"
                );
            }
        }

        /// The guarantee the two tests above check locally, checked again at
        /// the network boundary: a rejected role must never reach the
        /// coordination plane at all, not just fail once it gets there. No
        /// route is mounted on this server, so `received_requests()` is
        /// direct proof of whether a call was made -- not an inference from
        /// reading `validate_changeable_role`'s call order.
        #[tokio::test]
        async fn change_role_resolved_issues_no_request_at_all_for_a_refused_role() {
            let server = MockServer::start().await;
            let _guard = crate::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
            std::env::set_var("YADORILINK_COORDINATION_HTTP_ADDR", server.uri());
            let result = change_role_resolved("group-1", "device-1", "owner").await;
            std::env::remove_var("YADORILINK_COORDINATION_HTTP_ADDR");

            assert!(result.is_err(), "an unchangeable role must be refused, not sent");
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                0,
                "a refused role must never reach the coordination plane"
            );
        }

        /// Contract with `POST /shares/groups/:groupId/role`, which reads
        /// `deviceId`/`role` as camelCase keys: a snake_case `device_id`
        /// arrives `undefined` server-side and the route rejects the call as
        /// a missing device id.
        #[test]
        fn change_role_request_serializes_the_coordination_planes_camelcase_shape() {
            let body =
                serde_json::to_value(ChangeRoleRequest { device_id: "dev-1", role: "viewer" })
                    .unwrap();
            assert_eq!(body, serde_json::json!({"deviceId": "dev-1", "role": "viewer"}));
        }

        /// `role` is REQUIRED on this route (unlike `grant`'s, which
        /// defaults), so it must always be present in the body -- never
        /// omitted, and never a JSON `null`, both of which that route
        /// rejects.
        #[test]
        fn a_change_role_request_always_carries_an_explicit_role() {
            let body =
                serde_json::to_value(ChangeRoleRequest { device_id: "dev-1", role: "editor" })
                    .unwrap();
            assert_eq!(body["role"], "editor");
            assert!(!body["role"].is_null());
            assert_eq!(body.as_object().unwrap().len(), 2, "no other key belongs in this body");
        }

        fn revoke_error(
            code: ApplicationErrorCode,
            message: &str,
        ) -> Option<revoke_device_command_response::Result> {
            Some(revoke_device_command_response::Result::Error(
                yadorilink_ipc_proto::daemonctl::ApplicationCommandError {
                    code: code as i32,
                    message: message.to_string(),
                    group_ids: vec!["group-1".to_string()],
                    operation_id: String::new(),
                },
            ))
        }

        /// The durability refusal is the ONE revoke failure a `--force`
        /// override can get past, so it is the one failure that may be
        /// offered as an override -- and it must be recognized by its error
        /// code, not by its wording.
        #[test]
        fn a_durability_refusal_is_reported_as_an_outcome_that_can_be_overridden() {
            let attempt = classify_revoke_result(revoke_error(
                ApplicationErrorCode::ReplicaNotReady,
                "another full replica is not ready for: [\"group-1\"]",
            ))
            .expect("a durability refusal is an outcome, not an error");
            match attempt {
                RevokeAttempt::NotDurable { message, group_ids } => {
                    assert!(message.contains("not ready"), "{message}");
                    assert_eq!(group_ids, vec!["group-1".to_string()]);
                }
                RevokeAttempt::Committed(_) => {
                    panic!("a refused revoke must not read as committed")
                }
            }
        }

        /// Every other failure stays an error. Forcing would not get past any
        /// of them, and offering a data-loss confirmation for a failure that
        /// has nothing to do with data loss is how people learn to click
        /// through the one confirmation that matters.
        #[test]
        fn a_revoke_failure_that_forcing_cannot_help_is_never_offered_as_an_override() {
            for code in [
                ApplicationErrorCode::TargetNotFound,
                ApplicationErrorCode::CoordinationRejected,
                ApplicationErrorCode::CoordinationTransport,
                ApplicationErrorCode::LocalIdentityUnavailable,
                ApplicationErrorCode::Persistence,
                ApplicationErrorCode::Unspecified,
            ] {
                let classified = classify_revoke_result(revoke_error(code, "something went wrong"));
                assert!(
                    classified.is_err(),
                    "{code:?} must stay an error, not an overridable refusal"
                );
            }
            assert!(classify_revoke_result(None).is_err());
        }

        /// A refusal that this build's `try_revoke_resolved` reports as an
        /// outcome must still reach `share revoke`'s own caller as exactly
        /// the error it always did -- same message, same `Other` category
        /// (exit code 1).
        #[test]
        fn a_durability_refusal_still_reaches_the_command_line_as_the_same_error() {
            let attempt = classify_revoke_result(revoke_error(
                ApplicationErrorCode::ReplicaNotReady,
                "another full replica is not ready for: [\"group-1\"]",
            ))
            .unwrap();
            let RevokeAttempt::NotDurable { message, .. } = attempt else {
                panic!("expected a durability refusal");
            };
            let as_cli_error = CliError::Other(message);
            assert_eq!(
                as_cli_error.to_string(),
                "another full replica is not ready for: [\"group-1\"]"
            );
            assert_eq!(as_cli_error.exit_code(), 1);
        }

        #[test]
        fn change_role_reports_the_role_the_device_now_holds() {
            assert_eq!(
                change_role_line("dev-1", "photos", "viewer"),
                "dev-1 is now viewer for photos"
            );
        }

        /// Companion to
        /// `folder_group_info_deserializes_the_coordination_planes_camelcase_shape`
        /// below, which parses a bare `FolderGroupInfo`: this one parses the
        /// whole `{"groups":[...]}` ENVELOPE the route actually returns, so
        /// the wrapper `resolve_group_id`/`list_groups` really deserialize
        /// is pinned too and not just the element type inside it.
        ///
        /// What the `#[serde(rename_all = "camelCase")]` on `FolderGroupInfo`
        /// restores is precisely the `resolve_group_id`/`list_groups` pair
        /// and their own callers -- `yadorilink link`, and `share grant`,
        /// `share revoke <group> <device>`, `share invite`,
        /// `share set-storage-mode` and `share members`. Deliberately NOT
        /// `share join`, which resolves names through
        /// `resolve_joinable_group_id` against `GET /shares/joinable` and so
        /// depends on `JoinableGroupInfo`'s own separate attribute (see
        /// `joinable_group_info_deserializes_the_coordination_planes_camelcase_shape`),
        /// nor `share create`, which names a NEW group rather than resolving
        /// an existing one.
        #[test]
        fn list_groups_response_envelope_deserializes_the_coordination_planes_camelcase_body() {
            let resp: ListGroupsResponse =
                serde_json::from_str(r#"{"groups":[{"groupId":"g-1","name":"docs"}]}"#).unwrap();
            assert_eq!(resp.groups.len(), 1);
            assert_eq!(resp.groups[0].group_id, "g-1");
            assert_eq!(resp.groups[0].name, "docs");
        }

        /// Mounts the two listings `resolve_group_id` consults, points the
        /// coordination HTTP client at the mock, and resolves `group_name`
        /// over a real HTTP round trip. Returns the mock server alongside
        /// the result so a caller can assert which routes were actually
        /// requested. Holds `COORDINATION_ADDR_ENV_LOCK` for the whole call
        /// -- see that static's own doc comment for why every test touching
        /// this process-global env var must serialize on one crate-wide
        /// lock.
        async fn resolve_against_mocked_listings(
            group_name: &str,
            owned: serde_json::Value,
            shares: serde_json::Value,
        ) -> (MockServer, Result<String, CliError>) {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/shares/groups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(owned))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/shares"))
                .respond_with(ResponseTemplate::new(200).set_body_json(shares))
                .mount(&server)
                .await;

            let _guard = crate::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
            std::env::set_var("YADORILINK_COORDINATION_HTTP_ADDR", server.uri());
            let result = resolve_group_id("the-access-token", group_name).await;
            std::env::remove_var("YADORILINK_COORDINATION_HTTP_ADDR");
            (server, result)
        }

        fn requested_paths(requests: &[wiremock::Request]) -> Vec<String> {
            requests.iter().map(|r| r.url.path().to_string()).collect()
        }

        /// The account-visible edge listing a member account gets back from
        /// `GET /shares`: its OWN device bound into a group owned by another
        /// account, carrying that group's name and id (the coordination
        /// plane's `listShareEdgesForUser` matches on
        /// `folder_groups.user_id = ? OR devices.user_id = ?`, so the second
        /// disjunct is what puts this row in a non-owner's response).
        fn cross_account_edge_listing() -> serde_json::Value {
            serde_json::json!({
                "edges": [{
                    "edgeId": "7",
                    "groupId": "group-owned-by-another-account",
                    "groupName": "docs",
                    "deviceId": "this-accounts-own-device",
                }]
            })
        }

        /// The defect this fallback fixes: an account that reached a group
        /// only by ACCEPTING a cross-account invite owns no folder groups at
        /// all, so the owner-scoped `GET /shares/groups` listing is empty for
        /// it and name resolution used to fail outright with "no folder group
        /// named ...". The coordination plane authorizes such an account for
        /// `GET /shares/groups/:groupId/members` (`userCanSeeGroup`, not
        /// `assertOwnsGroup`), so before this fallback `yadorilink share
        /// members docs` was unreachable for exactly the member accounts the
        /// command documents itself as serving -- not because the request was
        /// refused, but because the CLI could never turn the name into an id
        /// to make the request with.
        #[tokio::test]
        async fn resolve_group_id_falls_back_to_the_shares_listing_for_a_member_account() {
            let (server, result) = resolve_against_mocked_listings(
                "docs",
                serde_json::json!({ "groups": [] }),
                cross_account_edge_listing(),
            )
            .await;

            assert_eq!(
                result.expect("a member account must be able to resolve a shared group by name"),
                "group-owned-by-another-account"
            );
            let paths = requested_paths(&server.received_requests().await.unwrap());
            assert_eq!(
                paths,
                vec!["/shares/groups".to_string(), "/shares".to_string()],
                "the owner-scoped listing is tried first, then the account-visible edge listing"
            );
        }

        /// The fallback must not change how an OWNED group resolves. A name
        /// present in both listings resolves to this account's own group, and
        /// the second request is never issued at all -- so the added lookup
        /// costs an owner nothing and cannot reorder an existing result.
        #[tokio::test]
        async fn resolve_group_id_prefers_an_owned_group_and_skips_the_fallback_entirely() {
            let (server, result) = resolve_against_mocked_listings(
                "docs",
                serde_json::json!({ "groups": [{ "groupId": "my-own-group", "name": "docs" }] }),
                cross_account_edge_listing(),
            )
            .await;

            assert_eq!(result.unwrap(), "my-own-group");
            assert_eq!(
                requested_paths(&server.received_requests().await.unwrap()),
                vec!["/shares/groups".to_string()],
                "an owned match must short-circuit before the fallback request"
            );
        }

        /// A name in neither listing still fails, and the message names both
        /// ways to get access rather than only `share create` -- which was
        /// actively misleading advice for an invitee, whose route in is
        /// `share accept`.
        #[tokio::test]
        async fn resolve_group_id_fails_for_a_name_in_neither_listing() {
            let (_server, result) = resolve_against_mocked_listings(
                "nonexistent",
                serde_json::json!({ "groups": [] }),
                serde_json::json!({ "edges": [] }),
            )
            .await;

            let message = match result {
                Err(CliError::Other(message)) => message,
                other => panic!("expected a not-found message, got {other:?}"),
            };
            assert!(message.contains("nonexistent"), "got: {message}");
            assert!(message.contains("share create"), "got: {message}");
            assert!(message.contains("share accept"), "got: {message}");
        }

        #[test]
        fn storage_mode_str_maps_the_on_demand_flag() {
            assert_eq!(storage_mode_str(false), "eager");
            assert_eq!(storage_mode_str(true), "on-demand");
        }

        #[test]
        fn invite_url_wraps_the_code_in_the_yadorilink_scheme() {
            assert_eq!(invite_url("abc123"), "yadorilink://invite/abc123");
        }

        /// Regression test: the coordination plane's `GET /shares/groups`
        /// route sends camelCase keys (`groupId`) -- `FolderGroupInfo` was
        /// missing `#[serde(rename_all = "camelCase")]` and so failed to
        /// deserialize a real response at all (every field but `name`
        /// mismatched), silently breaking `resolve_group_id`/`list_groups`
        /// and therefore each of their callers: `yadorilink link`, and
        /// `share grant`, `share revoke <group> <device>`, `share invite`,
        /// `share set-storage-mode` and `share members`. `share join` and
        /// `share create` are NOT in that set -- `join` resolves through
        /// `resolve_joinable_group_id`/`JoinableGroupInfo` (its own
        /// attribute, its own regression test above) and `create` names a
        /// new group instead of resolving one. Never caught before because
        /// the only prior coverage (`share_edge_line_renders_edge_fields`-
        /// style tests, for the sibling structs above) built the Rust struct
        /// directly rather than deserializing a realistic JSON body.
        #[test]
        fn folder_group_info_deserializes_the_coordination_planes_camelcase_shape() {
            let parsed: FolderGroupInfo =
                serde_json::from_str(r#"{"groupId":"g-1","name":"photos"}"#).unwrap();
            assert_eq!(parsed.group_id, "g-1");
            assert_eq!(parsed.name, "photos");
        }

        #[test]
        fn extract_invite_code_accepts_either_the_bare_code_or_the_full_url() {
            assert_eq!(extract_invite_code("yadorilink://invite/abc123"), "abc123");
            assert_eq!(extract_invite_code("abc123"), "abc123");
        }

        #[test]
        fn extract_invite_code_round_trips_through_invite_url() {
            let code = "0123456789abcdef";
            assert_eq!(extract_invite_code(&invite_url(code)), code);
        }

        #[test]
        fn format_expiry_reports_already_expired_for_a_past_timestamp() {
            assert_eq!(format_expiry(0), "already expired");
        }

        #[test]
        fn format_expiry_picks_the_coarsest_unit_that_still_reads_as_at_least_one() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            assert_eq!(format_expiry(now + 2 * 86_400 + 10), "2 day(s)");
            assert_eq!(format_expiry(now + 5 * 3600), "5 hour(s)");
            assert_eq!(format_expiry(now + 90), "1 minute(s)");
        }

        #[test]
        fn render_invite_qr_produces_a_nonempty_multiline_block() {
            let qr = render_invite_qr("yadorilink://invite/abc123").expect("qr should encode");
            assert!(qr.lines().count() > 5, "expected a multi-row QR render, got:\n{qr}");
            assert!(qr.contains('█'), "expected at least one dark module");
        }

        /// A minted invite as the coordination plane reports it back. The
        /// expiry is far enough out that `format_expiry`'s day bucket is
        /// stable regardless of when the suite runs.
        fn minted_invite(requires_approval: bool) -> MintedInviteInfo {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            MintedInviteInfo {
                code: "abc123".into(),
                invite_id: "invite-1".into(),
                group_id: "group-1".into(),
                role: "viewer".into(),
                expires_at_unix: now + 7 * 86_400 + 10,
                requires_approval,
            }
        }

        /// `share invite`'s printed output, pinned line by line: the code,
        /// URL and expiry, then the one-use warning and the exact command
        /// the recipient runs.
        #[test]
        fn invite_lines_render_the_code_url_and_expiry_then_the_recipients_command() {
            let invite = minted_invite(false);
            let url = invite_url(&invite.code);
            assert_eq!(
                invite_lines("photos", &invite, &url, None),
                vec![
                    "Invite for photos (role: viewer):".to_string(),
                    "  code: abc123".to_string(),
                    "  url:  yadorilink://invite/abc123".to_string(),
                    "  expires in: 7 day(s)".to_string(),
                    String::new(),
                    "This code is one-time use -- share it with exactly one recipient.".to_string(),
                    "The recipient accepts it with: yadorilink share accept \
                     yadorilink://invite/abc123 --path <dir>"
                        .to_string(),
                ]
            );
        }

        /// The approval wording is driven by what the coordination plane
        /// recorded (`requires_approval`), and appears in BOTH places: the
        /// invite's own details and the closing instructions naming the
        /// command that admits the recipient.
        #[test]
        fn invite_lines_report_an_approval_gated_invite_in_both_places() {
            let invite = minted_invite(true);
            let url = invite_url(&invite.code);
            assert_eq!(
                invite_lines("photos", &invite, &url, None),
                vec![
                    "Invite for photos (role: viewer):".to_string(),
                    "  code: abc123".to_string(),
                    "  url:  yadorilink://invite/abc123".to_string(),
                    "  expires in: 7 day(s)".to_string(),
                    "  approval: required (you must approve the recipient before they get \
                     access)"
                        .to_string(),
                    String::new(),
                    "This code is one-time use -- share it with exactly one recipient.".to_string(),
                    "The recipient accepts it with: yadorilink share accept \
                     yadorilink://invite/abc123 --path <dir>"
                        .to_string(),
                    "They will not see anything until you admit them: run `yadorilink share \
                     pending` to see the request, then `yadorilink share approve photos \
                     <device-id>`."
                        .to_string(),
                ]
            );
        }

        #[test]
        fn invite_lines_omit_every_approval_line_when_approval_is_not_required() {
            let invite = minted_invite(false);
            let url = invite_url(&invite.code);
            let lines = invite_lines("photos", &invite, &url, None);
            assert!(!lines.iter().any(|l| l.contains("approval")), "got: {lines:#?}");
            assert!(!lines.iter().any(|l| l.contains("share approve")), "got: {lines:#?}");
        }

        /// The QR block sits between the invite's details and the closing
        /// instructions, preceded by a blank line -- and a QR that could not
        /// be rendered at all simply drops that block, leaving every other
        /// line (the code and URL above all) intact.
        #[test]
        fn invite_lines_place_the_qr_block_after_the_details_and_survive_its_absence() {
            let invite = minted_invite(false);
            let url = invite_url(&invite.code);
            let with_qr = invite_lines("photos", &invite, &url, Some("##\n##"));
            let without_qr = invite_lines("photos", &invite, &url, None);

            let qr_at = with_qr.iter().position(|l| l == "##\n##").expect("qr block is rendered");
            let expiry_at =
                with_qr.iter().position(|l| l.starts_with("  expires in:")).expect("expiry line");
            let warning_at = with_qr
                .iter()
                .position(|l| l.starts_with("This code is one-time use"))
                .expect("one-use warning");
            assert!(expiry_at < qr_at && qr_at < warning_at, "got: {with_qr:#?}");
            assert_eq!(with_qr[qr_at - 1], "", "the QR block is preceded by a blank line");

            assert_eq!(with_qr.len(), without_qr.len() + 2);
            assert!(without_qr.iter().any(|l| l.contains("yadorilink://invite/abc123")));
        }

        fn base_pending_invite() -> PendingInviteInfo {
            PendingInviteInfo {
                invite_id: "invite-1".into(),
                group_id: "group-1".into(),
                group_name: "photos".into(),
                role: "viewer".into(),
                expires_at_unix: 0,
                status: "pending".into(),
            }
        }

        #[test]
        fn pending_invite_line_shows_a_relative_expiry_for_a_still_pending_invite() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let invite = PendingInviteInfo { expires_at_unix: now + 3600, ..base_pending_invite() };
            let line = pending_invite_line(&invite);
            assert!(line.contains("invite-1"));
            assert!(line.contains("group=photos (group-1)"));
            assert!(line.contains("role=viewer"));
            assert!(line.contains("expires in 1 hour(s)"), "got: {line}");
        }

        #[test]
        fn pending_invite_line_shows_the_status_word_for_expired_or_cancelled_invites_without_a_relative_time(
        ) {
            let expired = PendingInviteInfo { status: "expired".into(), ..base_pending_invite() };
            let line = pending_invite_line(&expired);
            assert!(line.ends_with("expired"), "got: {line}");
            assert!(!line.contains("expires in"), "got: {line}");

            let cancelled =
                PendingInviteInfo { status: "cancelled".into(), ..base_pending_invite() };
            let line = pending_invite_line(&cancelled);
            assert!(line.ends_with("cancelled"), "got: {line}");
        }

        /// Contract with the coordination plane's `GET /shares/invites`
        /// response shape (camelCase keys) -- deserialization would fail
        /// silently mismatched, so this pins the exact field names.
        #[test]
        fn list_pending_invites_response_deserializes_the_coordination_planes_camelcase_shape() {
            let body = serde_json::json!({
                "invites": [{
                    "inviteId": "invite-1",
                    "groupId": "group-1",
                    "groupName": "photos",
                    "role": "viewer",
                    "expiresAtUnix": 1_700_000_000i64,
                    "status": "pending",
                }]
            });
            let resp: ListPendingInvitesResponse = serde_json::from_value(body).unwrap();
            assert_eq!(resp.invites.len(), 1);
            let invite = &resp.invites[0];
            assert_eq!(invite.invite_id, "invite-1");
            assert_eq!(invite.group_id, "group-1");
            assert_eq!(invite.group_name, "photos");
            assert_eq!(invite.role, "viewer");
            assert_eq!(invite.expires_at_unix, 1_700_000_000);
            assert_eq!(invite.status, "pending");
        }
    }
}

pub use http::{
    accept, approve, approve_resolved, approve_result_line, cancel_invite, change_role,
    change_role_resolved, create, create_and_link, deny, grant, invite, invite_url, join,
    join_resolved, list_groups, list_invites, list_joinable, list_joinable_groups, list_members,
    list_members_resolved, list_pending_approvals, list_shares, member_relationship_label,
    member_storage_label, members, mint_invite, mint_invite_resolved, own_device_id,
    pending_approvals, resolve_group_id, revoke, revoke_edge, revoke_resolved, set_storage_mode,
    short_device_id, try_revoke_resolved, validate_changeable_role, GroupMemberInfo, GroupSummary,
    PendingApproval, RevokeAttempt, CHANGEABLE_ROLES, NO_PENDING_APPROVALS,
};
