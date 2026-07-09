/// Default invite lifetime when `--expires` is omitted — short enough to
/// bound a leaked-but-unredeemed code's exposure window (see the "Bearer
/// invite codes" risk note).
const DEFAULT_INVITE_TTL_SECS: i64 = 24 * 60 * 60;

/// Parses a plain-integer-seconds or single-unit-suffixed duration ("30m",
/// "24h", "7d"; s/m/h/d only, no fractional or compound values like
/// "1h30m"). Hand-rolled rather than pulling in a duration-parsing
/// dependency for this one CLI flag. Feature-independent: shared by both
/// the gRPC and HTTP command implementations below.
fn parse_duration_secs(input: &str) -> Result<i64, crate::error::CliError> {
    use crate::error::CliError;
    let input = input.trim();
    let bad =
        || CliError::Other(format!("invalid --expires {input:?} (expected e.g. 30m, 24h, 7d)"));
    if input.is_empty() {
        return Err(bad());
    }
    let (digits, unit_secs) = match input.chars().last() {
        Some('s') => (&input[..input.len() - 1], 1),
        Some('m') => (&input[..input.len() - 1], 60),
        Some('h') => (&input[..input.len() - 1], 60 * 60),
        Some('d') => (&input[..input.len() - 1], 24 * 60 * 60),
        _ => (input, 1),
    };
    let value: i64 = digits.parse().map_err(|_| bad())?;
    value.checked_mul(unit_secs).ok_or_else(bad)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

/// The `share mark-storage-only` confirmation message. On the mark path
/// this explicitly says the peer "will only ever receive ciphertext" — the
/// `cli` spec's required scenario wording for "Designate an untrusted
/// storage peer". Feature-independent.
fn storage_only_confirmation(device_id: &str, group_name: &str, storage_only: bool) -> String {
    if storage_only {
        format!(
            "Device {device_id} is now storage-only (ciphertext-only) for group {group_name} — \
             it will only ever receive ciphertext, never the group content key or plaintext."
        )
    } else {
        format!("Device {device_id} is no longer storage-only for group {group_name}.")
    }
}

#[cfg(feature = "http-coordination")]
mod http {
    //! HTTP client for the coordination service's `/shares/*` routes.
    //! `ShareRole` here is a
    //! plain `"read"`/`"write"` string (the JSON API's wire shape),
    //! unlike the gRPC path's generated proto enum.

    use serde::{Deserialize, Serialize};

    use crate::error::CliError;
    use crate::grpc::require_access_token;
    use crate::http_client::{get_json, post_json, post_json_no_content};

    use super::{
        now_unix, parse_duration_secs, storage_only_confirmation, DEFAULT_INVITE_TTL_SECS,
    };

    fn parse_role(role: &str) -> Result<&'static str, CliError> {
        match role.to_ascii_lowercase().as_str() {
            "read" => Ok("read"),
            "write" => Ok("write"),
            other => {
                Err(CliError::Other(format!("invalid --role {other:?} (expected read or write)")))
            }
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

    async fn resolve_group_id(access_token: &str, group_name: &str) -> Result<String, CliError> {
        let resp: ListGroupsResponse = get_json("/shares/groups", Some(access_token)).await?;
        resp.groups.into_iter().find(|g| g.name == group_name).map(|g| g.group_id).ok_or_else(
            || {
                CliError::Other(format!(
                    "no folder group named {group_name:?} (run `yadorilink share create` first)"
                ))
            },
        )
    }

    #[derive(Serialize)]
    struct CreateGroupRequest<'a> {
        name: &'a str,
        creating_device_id: &'a str,
    }
    #[derive(Deserialize)]
    struct CreateGroupResponse {
        group_id: String,
    }

    pub async fn create(group_name: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let device_id = crate::device_config::load()
            .map_err(|_| {
                CliError::Other(
                    "no local device registered — run `yadorilink device register` first"
                        .to_string(),
                )
            })?
            .device_id;
        let resp: CreateGroupResponse = post_json(
            "/shares/groups",
            &CreateGroupRequest { name: &group_name, creating_device_id: &device_id },
            Some(&access_token),
        )
        .await?;
        println!("Created folder group: {}", resp.group_id);
        Ok(())
    }

    #[derive(Serialize)]
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

    pub async fn revoke(group_name: String, device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        post_json_no_content(
            &format!("/shares/groups/{group_id}/revoke"),
            &DeviceIdBody { device_id: &device_id },
            Some(&access_token),
        )
        .await?;
        println!("Revoked {device_id} access to {group_name}");
        Ok(())
    }

    pub async fn revoke_edge(edge_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        post_json_no_content::<()>(&format!("/shares/{edge_id}"), &(), Some(&access_token)).await?;
        println!("Revoked share edge: {edge_id}");
        Ok(())
    }

    #[derive(Serialize)]
    struct CreateInviteRequest<'a> {
        role: &'a str,
        expires_at_unix: i64,
    }
    #[derive(Deserialize)]
    struct CreateInviteResponse {
        code: String,
        expires_at_unix: i64,
    }

    pub async fn invite(
        group_name: String,
        role: String,
        expires: Option<String>,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let role = parse_role(&role)?;
        let ttl_secs = match expires {
            Some(s) => parse_duration_secs(&s)?,
            None => DEFAULT_INVITE_TTL_SECS,
        };
        let expires_at_unix = now_unix() + ttl_secs;

        let resp: CreateInviteResponse = post_json(
            &format!("/shares/groups/{group_id}/invites"),
            &CreateInviteRequest { role, expires_at_unix },
            Some(&access_token),
        )
        .await?;

        let role_label = if role == "read" { "read-only" } else { "read-write" };
        println!("Invite code: {}", resp.code);
        println!("Expires at (unix): {}", resp.expires_at_unix);
        println!(
            "Share this code out-of-band with the invitee; whoever redeems it first (`yadorilink \
             share accept <code>`) before it expires gains {role_label} access to {group_name} — \
             this creates a direct, authorized peer connection between accounts, so only share it \
             with someone you intend to collaborate with."
        );
        Ok(())
    }

    #[derive(Serialize)]
    struct AcceptInviteRequest<'a> {
        code: &'a str,
        device_id: &'a str,
    }
    #[derive(Deserialize)]
    struct AcceptInviteResponse {
        group_id: String,
        role: String,
    }

    pub async fn accept(code: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let device_id = crate::device_config::load()
            .map_err(|_| {
                CliError::Other(
                    "no local device registered — run `yadorilink device register` first"
                        .to_string(),
                )
            })?
            .device_id;

        let resp: AcceptInviteResponse = post_json(
            "/shares/invites/accept",
            &AcceptInviteRequest { code: &code, device_id: &device_id },
            Some(&access_token),
        )
        .await?;

        let role_label = if resp.role == "read" { "read-only" } else { "read-write" };
        println!("Accepted share invite: group {} ({role_label})", resp.group_id);
        Ok(())
    }

    #[derive(Deserialize)]
    struct ShareEdgeInfo {
        edge_id: String,
        group_id: String,
        group_name: String,
        device_id: String,
        role: String,
        cross_account: bool,
        storage_only: bool,
    }
    #[derive(Deserialize)]
    struct ListSharesResponse {
        edges: Vec<ShareEdgeInfo>,
    }

    fn share_edge_line(edge: &ShareEdgeInfo) -> String {
        let scope = if edge.cross_account { "cross-account" } else { "same-account" };
        let storage_only = if edge.storage_only { "  [storage-only]" } else { "" };
        format!(
            "{}  group={} ({})  device={}  role={}  {scope}{storage_only}",
            edge.edge_id, edge.group_name, edge.group_id, edge.device_id, edge.role
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

    #[derive(Serialize)]
    struct StorageOnlyRequest<'a> {
        device_id: &'a str,
        storage_only: bool,
    }

    pub async fn mark_storage_only(
        group_name: String,
        device_id: String,
        unset: bool,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let storage_only = !unset;
        post_json_no_content(
            &format!("/shares/groups/{group_id}/storage-only"),
            &StorageOnlyRequest { device_id: &device_id, storage_only },
            Some(&access_token),
        )
        .await?;
        println!("{}", storage_only_confirmation(&device_id, &group_name, storage_only));
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_role_accepts_read_write_case_insensitively_and_rejects_other_values() {
            assert_eq!(parse_role("read").unwrap(), "read");
            assert_eq!(parse_role("WRITE").unwrap(), "write");
            assert!(parse_role("admin").is_err());
        }

        fn base_edge() -> ShareEdgeInfo {
            ShareEdgeInfo {
                edge_id: "edge-1".into(),
                group_id: "group-1".into(),
                group_name: "photos".into(),
                device_id: "device-1".into(),
                role: "write".into(),
                cross_account: false,
                storage_only: false,
            }
        }

        #[test]
        fn share_edge_line_shows_storage_only_badge_when_flagged() {
            let mut edge = base_edge();
            edge.storage_only = true;
            assert!(share_edge_line(&edge).contains("[storage-only]"));
        }

        #[test]
        fn share_edge_line_omits_badge_when_not_flagged() {
            let line = share_edge_line(&base_edge());
            assert!(!line.contains("storage-only"));
        }
    }
}

#[cfg(feature = "http-coordination")]
pub use http::{
    accept, create, grant, invite, list_shares, mark_storage_only, revoke, revoke_edge,
};

#[cfg(not(feature = "http-coordination"))]
mod grpc_impl {
    use yadorilink_ipc_proto::coordination::share_invite_service_client::ShareInviteServiceClient;
    use yadorilink_ipc_proto::coordination::share_service_client::ShareServiceClient;
    use yadorilink_ipc_proto::coordination::{
        AcceptShareInviteRequest, CreateFolderGroupRequest, CreateShareInviteRequest,
        GrantAccessRequest, ListSharesRequest, RevokeAccessRequest, RevokeShareEdgeRequest,
        SetStorageOnlyRequest, ShareEdgeInfo, ShareRole,
    };

    use crate::error::CliError;
    use crate::grpc::{
        authed_request, coordination_channel, require_access_token, resolve_group_id,
    };

    use super::{
        now_unix, parse_duration_secs, storage_only_confirmation, DEFAULT_INVITE_TTL_SECS,
    };

    pub async fn create(group_name: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = ShareServiceClient::new(coordination_channel().await?);
        let resp = client
            .create_folder_group(authed_request(
                CreateFolderGroupRequest { name: group_name },
                &access_token,
            ))
            .await?
            .into_inner();
        println!("Created folder group: {}", resp.group_id);
        Ok(())
    }

    pub async fn grant(group_name: String, device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let mut client = ShareServiceClient::new(coordination_channel().await?);
        client
            .grant_access(authed_request(
                GrantAccessRequest { group_id, device_id: device_id.clone() },
                &access_token,
            ))
            .await?;
        println!("Granted {device_id} access to {group_name}");
        Ok(())
    }

    pub async fn revoke(group_name: String, device_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let mut client = ShareServiceClient::new(coordination_channel().await?);
        client
            .revoke_access(authed_request(
                RevokeAccessRequest { group_id, device_id: device_id.clone() },
                &access_token,
            ))
            .await?;
        println!("Revoked {device_id} access to {group_name}");
        Ok(())
    }

    /// Removes one ACL edge by the `edge_id` shown by `share list`. Unlike
    /// [`revoke`] above (owner-only, same-account), the underlying
    /// `RevokeShareEdge` RPC also allows the invitee side of a
    /// cross-account share to remove their own access.
    pub async fn revoke_edge(edge_id: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = ShareInviteServiceClient::new(coordination_channel().await?);
        client
            .revoke_share_edge(authed_request(
                RevokeShareEdgeRequest { edge_id: edge_id.clone() },
                &access_token,
            ))
            .await?;
        println!("Revoked share edge: {edge_id}");
        Ok(())
    }

    /// Mints a one-time, expiring invite for `group_name`, scoped to
    /// `role`, and prints the plaintext code — the only time it is ever
    /// shown, since the coordination plane persists only a hash of it.
    pub async fn invite(
        group_name: String,
        role: String,
        expires: Option<String>,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let role = parse_role(&role)?;
        let ttl_secs = match expires {
            Some(s) => parse_duration_secs(&s)?,
            None => DEFAULT_INVITE_TTL_SECS,
        };
        let expires_at_unix = now_unix() + ttl_secs;

        let mut client = ShareInviteServiceClient::new(coordination_channel().await?);
        let resp = client
            .create_share_invite(authed_request(
                CreateShareInviteRequest { group_id, role: role as i32, expires_at_unix },
                &access_token,
            ))
            .await?
            .into_inner();

        let role_label = if role == ShareRole::Read { "read-only" } else { "read-write" };
        println!("Invite code: {}", resp.code);
        println!("Expires at (unix): {}", resp.expires_at_unix);
        println!(
            "Share this code out-of-band with the invitee; whoever redeems it first (`yadorilink \
             share accept <code>`) before it expires gains {role_label} access to {group_name} — \
             this creates a direct, authorized peer connection between accounts, so only share it \
             with someone you intend to collaborate with."
        );
        Ok(())
    }

    /// Redeems `code` under this device's own account (loaded from the
    /// local device config — see `device_config::load`), creating a
    /// cross-account ACL edge.
    pub async fn accept(code: String) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let device_id = crate::device_config::load()
            .map_err(|_| {
                CliError::Other(
                    "no local device registered — run `yadorilink device register` first"
                        .to_string(),
                )
            })?
            .device_id;

        let mut client = ShareInviteServiceClient::new(coordination_channel().await?);
        let resp = client
            .accept_share_invite(authed_request(
                AcceptShareInviteRequest { code, device_id },
                &access_token,
            ))
            .await?
            .into_inner();

        let role_label =
            if resp.role == ShareRole::Read as i32 { "read-only" } else { "read-write" };
        println!("Accepted share invite: group {} ({role_label})", resp.group_id);
        Ok(())
    }

    /// Lists every ACL edge visible to this account (`ListShares`) —
    /// groups it owns, and its own devices' shares, marking which edges
    /// are cross-account.
    pub async fn list_shares() -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let mut client = ShareInviteServiceClient::new(coordination_channel().await?);
        let resp = client
            .list_shares(authed_request(ListSharesRequest {}, &access_token))
            .await?
            .into_inner();
        for edge in resp.edges {
            println!("{}", share_edge_line(&edge));
        }
        Ok(())
    }

    /// One `share list` line per ACL edge, including a `[storage-only]`
    /// badge for any edge flagged ciphertext-only
    /// (`ShareEdgeInfo.storage_only`, wired by the coordination plane's
    /// `SetStorageOnly` RPC).
    fn share_edge_line(edge: &ShareEdgeInfo) -> String {
        let role = if edge.role == ShareRole::Read as i32 { "read" } else { "write" };
        let scope = if edge.cross_account { "cross-account" } else { "same-account" };
        let storage_only = if edge.storage_only { "  [storage-only]" } else { "" };
        format!(
            "{}  group={} ({})  device={}  role={role}  {scope}{storage_only}",
            edge.edge_id, edge.group_name, edge.group_id, edge.device_id
        )
    }

    /// Flags (or unflags, when `unset`) `device_id` as storage-only/untrusted
    /// for `group_name`, via the coordination plane's `SetStorageOnly` RPC.
    pub async fn mark_storage_only(
        group_name: String,
        device_id: String,
        unset: bool,
    ) -> Result<(), CliError> {
        let access_token = require_access_token()?;
        let group_id = resolve_group_id(&access_token, &group_name).await?;
        let storage_only = !unset;
        let mut client = ShareServiceClient::new(coordination_channel().await?);
        client
            .set_storage_only(authed_request(
                SetStorageOnlyRequest { group_id, device_id: device_id.clone(), storage_only },
                &access_token,
            ))
            .await?;
        println!("{}", storage_only_confirmation(&device_id, &group_name, storage_only));
        Ok(())
    }

    fn parse_role(role: &str) -> Result<ShareRole, CliError> {
        match role.to_ascii_lowercase().as_str() {
            "read" => Ok(ShareRole::Read),
            "write" => Ok(ShareRole::Write),
            other => {
                Err(CliError::Other(format!("invalid --role {other:?} (expected read or write)")))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_role_accepts_read_write_case_insensitively_and_rejects_other_values() {
            assert_eq!(parse_role("read").unwrap(), ShareRole::Read);
            assert_eq!(parse_role("WRITE").unwrap(), ShareRole::Write);
            assert!(parse_role("admin").is_err());
        }

        fn base_edge() -> ShareEdgeInfo {
            ShareEdgeInfo {
                edge_id: "edge-1".into(),
                group_id: "group-1".into(),
                group_name: "photos".into(),
                device_id: "device-1".into(),
                role: ShareRole::Write as i32,
                cross_account: false,
                storage_only: false,
            }
        }

        /// `share list` shows a `[storage-only]` badge for an edge flagged
        /// ciphertext-only.
        #[test]
        fn share_edge_line_shows_storage_only_badge_when_flagged() {
            let mut edge = base_edge();
            edge.storage_only = true;
            assert!(share_edge_line(&edge).contains("[storage-only]"));
        }

        /// An edge that was never flagged (or predates this change) renders no
        /// new output — same "empty unless applicable" discipline used
        /// elsewhere in this codebase's status/link rendering.
        #[test]
        fn share_edge_line_omits_badge_when_not_flagged() {
            let line = share_edge_line(&base_edge());
            assert!(!line.contains("storage-only"));
        }
    }
}

#[cfg(not(feature = "http-coordination"))]
pub use grpc_impl::{
    accept, create, grant, invite, list_shares, mark_storage_only, revoke, revoke_edge,
};

#[cfg(test)]
mod shared_tests {
    use super::*;

    #[test]
    fn parse_duration_secs_accepts_plain_seconds_and_suffixed_units() {
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_secs("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration_secs("24h").unwrap(), 24 * 60 * 60);
        assert_eq!(parse_duration_secs("7d").unwrap(), 7 * 24 * 60 * 60);
    }

    #[test]
    fn parse_duration_secs_rejects_garbage() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("soon").is_err());
        assert!(parse_duration_secs("h").is_err());
    }

    #[test]
    fn storage_only_confirmation_mentions_ciphertext_only_when_marking() {
        let msg = storage_only_confirmation("device-1", "photos", true);
        assert!(msg.contains("device-1"));
        assert!(msg.contains("photos"));
        assert!(msg.contains("will only ever receive ciphertext"));
    }

    #[test]
    fn storage_only_confirmation_reports_unmarking() {
        let msg = storage_only_confirmation("device-1", "photos", false);
        assert!(msg.contains("no longer storage-only"));
    }
}
