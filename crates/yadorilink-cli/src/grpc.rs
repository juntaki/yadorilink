//! Shared helpers for talking to the coordination plane over gRPC.

use tonic::transport::{Channel, ClientTlsConfig};
use yadorilink_ipc_proto::coordination::share_service_client::ShareServiceClient;
use yadorilink_ipc_proto::coordination::ListFolderGroupsRequest;

use crate::error::CliError;

pub fn coordination_addr() -> String {
    std::env::var("YADORILINK_COORDINATION_ADDR").unwrap_or_else(|_| "http://127.0.0.1:7443".into())
}

pub fn relay_addr() -> String {
    std::env::var("YADORILINK_RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:7444".into())
}

pub async fn coordination_channel() -> Result<Channel, CliError> {
    let mut endpoint = Channel::from_shared(coordination_addr())
        .map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
    let uri = endpoint.uri();
    match uri.scheme_str() {
        Some("https") => {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
        }
        Some("http") if is_loopback_host(uri.host()) => {}
        Some("http") => {
            return Err(CliError::CoordinationPlaneUnreachable(
                "remote coordination addresses must use https://".to_string(),
            ));
        }
        _ => {
            return Err(CliError::CoordinationPlaneUnreachable(
                "coordination address must use http:// or https://".to_string(),
            ));
        }
    }
    endpoint.connect().await.map_err(Into::into)
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

pub fn authed_request<T>(msg: T, access_token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    if let Ok(value) = format!("Bearer {access_token}").parse() {
        req.metadata_mut().insert("authorization", value);
    }
    req
}

pub fn require_access_token() -> Result<String, CliError> {
    crate::token_store::load_access_token().ok_or(CliError::NotLoggedIn)
}

/// Folder groups are addressed by human-readable name on the CLI (per the
/// `cli` spec), but the coordination plane's ACL calls take a `group_id`
/// (assigned at creation) — resolve the name here rather than exposing
/// the internal id to users.
pub async fn resolve_group_id(access_token: &str, group_name: &str) -> Result<String, CliError> {
    let mut client = ShareServiceClient::new(coordination_channel().await?);
    let resp = client
        .list_folder_groups(authed_request(ListFolderGroupsRequest {}, access_token))
        .await?
        .into_inner();
    resp.groups.into_iter().find(|g| g.name == group_name).map(|g| g.group_id).ok_or_else(|| {
        CliError::Other(format!(
            "no folder group named {group_name:?} (run `yadorilink share create` first)"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_host_detection_accepts_only_local_hosts() {
        assert!(is_loopback_host(Some("localhost")));
        assert!(is_loopback_host(Some("127.0.0.1")));
        assert!(is_loopback_host(Some("[::1]")));
        assert!(!is_loopback_host(Some("192.0.2.10")));
        assert!(!is_loopback_host(Some("example.com")));
        assert!(!is_loopback_host(None));
    }
}
