//! `add-advanced-sync-operations` section 3 (Device Introduction): CLI
//! surface for introducer trust flags, scoped auto-accept policies, and
//! introduction proposal/accept/reject flows — talks directly to the
//! coordination plane's `IntroductionService` (mirrors `share.rs`'s own
//! direct-to-coordination pattern, since this is account/ACL-scoped state
//! the daemon doesn't own).

use yadorilink_ipc_proto::coordination::introduction_service_client::IntroductionServiceClient;
use yadorilink_ipc_proto::coordination::{
    AcceptIntroductionRequest, IntroductionInfo, ListAutoAcceptPoliciesRequest,
    ListPendingIntroductionsRequest, ProposeIntroductionRequest, RejectIntroductionRequest,
    RevokeAutoAcceptPolicyRequest, SetAutoAcceptPolicyRequest, SetIntroducerRequest,
};

use crate::error::CliError;
use crate::grpc::{authed_request, coordination_channel, require_access_token};

pub async fn set_introducer(device_id: String, enabled: bool) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    client
        .set_introducer(authed_request(
            SetIntroducerRequest { device_id: device_id.clone(), is_introducer: enabled },
            &access_token,
        ))
        .await?;
    let verb = if enabled { "marked" } else { "unmarked" };
    println!("{device_id} {verb} as an introducer");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn set_auto_accept_policy(
    introducer_device_id: Option<String>,
    group_id: Option<String>,
    destination_root_prefix: Option<String>,
    require_storage_only: bool,
    allowed_mode: Option<String>,
) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .set_auto_accept_policy(authed_request(
            SetAutoAcceptPolicyRequest {
                introducer_device_id: introducer_device_id.unwrap_or_default(),
                group_id: group_id.unwrap_or_default(),
                destination_root_prefix: destination_root_prefix.unwrap_or_default(),
                require_storage_only,
                allowed_mode: allowed_mode.unwrap_or_else(|| "send_receive".to_string()),
            },
            &access_token,
        ))
        .await?
        .into_inner();
    println!("Created auto-accept policy {}", resp.id);
    Ok(())
}

pub async fn list_auto_accept_policies() -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .list_auto_accept_policies(authed_request(ListAutoAcceptPoliciesRequest {}, &access_token))
        .await?
        .into_inner();
    if resp.policies.is_empty() {
        println!("No auto-accept policies configured.");
    }
    for policy in resp.policies {
        let introducer = if policy.introducer_device_id.is_empty() {
            "any"
        } else {
            &policy.introducer_device_id
        };
        let group = if policy.group_id.is_empty() { "any" } else { &policy.group_id };
        println!(
            "{}  introducer={introducer}  group={group}  mode={}  storage_only={}  enabled={}",
            policy.id, policy.allowed_mode, policy.require_storage_only, policy.enabled
        );
    }
    Ok(())
}

pub async fn revoke_auto_accept_policy(policy_id: String) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    client
        .revoke_auto_accept_policy(authed_request(
            RevokeAutoAcceptPolicyRequest { policy_id: policy_id.clone() },
            &access_token,
        ))
        .await?;
    println!("Revoked auto-accept policy {policy_id}");
    Ok(())
}

pub async fn propose(
    introducer_device_id: String,
    target_device_id: String,
    group_id: String,
) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .propose_introduction(authed_request(
            ProposeIntroductionRequest { introducer_device_id, target_device_id, group_id },
            &access_token,
        ))
        .await?
        .into_inner();
    print_introduction(&resp);
    Ok(())
}

pub async fn list_pending(target_device_id: Option<String>) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .list_pending_introductions(authed_request(
            ListPendingIntroductionsRequest {
                target_device_id: target_device_id.unwrap_or_default(),
            },
            &access_token,
        ))
        .await?
        .into_inner();
    if resp.introductions.is_empty() {
        println!("No pending introductions.");
    }
    for introduction in &resp.introductions {
        print_introduction(introduction);
    }
    Ok(())
}

pub async fn accept(introduction_id: String) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .accept_introduction(authed_request(
            AcceptIntroductionRequest { introduction_id },
            &access_token,
        ))
        .await?
        .into_inner();
    print_introduction(&resp);
    Ok(())
}

pub async fn reject(introduction_id: String) -> Result<(), CliError> {
    let access_token = require_access_token()?;
    let mut client = IntroductionServiceClient::new(coordination_channel().await?);
    let resp = client
        .reject_introduction(authed_request(
            RejectIntroductionRequest { introduction_id },
            &access_token,
        ))
        .await?
        .into_inner();
    print_introduction(&resp);
    Ok(())
}

fn print_introduction(info: &IntroductionInfo) {
    println!(
        "{}  introducer={}  target={}  group={}  status={}  decided_by={}",
        info.id,
        info.introducer_device_id,
        info.target_device_id,
        info.group_id,
        info.status,
        if info.decided_by.is_empty() { "-" } else { &info.decided_by }
    );
}
