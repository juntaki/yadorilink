//! HTTP+WebSocket client for the Cloudflare-hosted coordination plane —
//! the CLI's sole path to the coordination service. Talks to the
//! service's plain JSON routes; every coordination command goes through
//! the request helpers in this module.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::CliError;

pub fn coordination_http_addr() -> String {
    std::env::var("YADORILINK_COORDINATION_HTTP_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".into())
}

/// The coordination endpoint recorded in this device's `device.json` at
/// registration time, read from
/// `YADORILINK_COORDINATION_ADDR`. Kept distinct from
/// [`coordination_http_addr`] so the persisted device record and the
/// request base URL can be configured independently.
pub fn coordination_addr() -> String {
    std::env::var("YADORILINK_COORDINATION_ADDR").unwrap_or_else(|_| "http://127.0.0.1:7443".into())
}

/// Loads the stored access token, or [`CliError::NotLoggedIn`] if there is
/// none — the standard precondition for any authenticated coordination call.
pub fn require_access_token() -> Result<String, CliError> {
    crate::token_store::load_access_token().ok_or(CliError::NotLoggedIn)
}

/// Coordination-address validation: a remote address must use `https://`;
/// only a loopback host may use plain `http://` (local `wrangler dev`).
/// Uses the `url` crate to parse the address rather than hand-rolled string
/// splitting -- an earlier hand-rolled version of this function split on
/// `:` to find the host, which silently mangled IPv6 literal addresses
/// like `http://[::1]:8787` (the same bug class this crate's own
/// `google_login.rs`/`peer_orchestrator.rs` avoided by switching to `url`
/// too).
fn validate_addr(addr: &str) -> Result<(), CliError> {
    let url = url::Url::parse(addr).map_err(|e| {
        CliError::CoordinationPlaneUnreachable(format!("invalid coordination address: {e}"))
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&url) => Ok(()),
        "http" => Err(CliError::CoordinationPlaneUnreachable(
            "remote coordination addresses must use https://".to_string(),
        )),
        _ => Err(CliError::CoordinationPlaneUnreachable(
            "coordination address must use http:// or https://".to_string(),
        )),
    }
}

/// Matches on `url`'s typed `Host` enum rather than `host_str` -- for an
/// IPv6 literal, `host_str` returns the bracketed authority form
/// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a first
/// attempt at this fix used `host_str` this way and shipped with exactly
/// that bug (caught by `validate_addr_handles_an_ipv6_loopback_literal`
/// below). `Host::Ipv6` carries an already-parsed `Ipv6Addr` directly, so
/// there is no string/bracket handling left to get wrong.
fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .build()
        .map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))
}

async fn handle_response<Resp: DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<Resp, CliError> {
    let status = resp.status();
    if status.is_success() {
        return resp.json::<Resp>().await.map_err(|e| CliError::Other(e.to_string()));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    Err(error_from_body(status.as_u16(), &body))
}

/// Maps a failed coordination response body to a `CliError`. Split out from
/// `handle_response` so the classification is unit-testable without
/// constructing a `reqwest::Response`.
///
/// The typed `quota_exceeded` and
/// `rate_limited` bodies (shared by the CLI and, via this same client, the
/// desktop app) are rendered as specific, actionable messages rather than the
/// opaque code, and classified as `LimitExceeded` (user-actionable) rather than
/// as a coordination-plane outage.
fn error_from_body(status: u16, body: &serde_json::Value) -> CliError {
    let code = body.get("error").and_then(|v| v.as_str()).unwrap_or("");

    if code == "quota_exceeded" {
        let resource = body.get("resource").and_then(|v| v.as_str()).unwrap_or("resource");
        let limit = body.get("limit").and_then(|v| v.as_u64());
        let current = body.get("current").and_then(|v| v.as_u64());
        let human = match resource {
            "devices" => "registered devices",
            "folder_groups" => "folder groups",
            "share_edges" => "shared devices",
            "netmap_entries" => "network map entries",
            other => other,
        };
        let counts = match (current, limit) {
            (Some(c), Some(l)) => format!(" ({c} of {l})"),
            (_, Some(l)) => format!(" (limit {l})"),
            _ => String::new(),
        };
        let advice = "remove some before adding more, or ask an operator to raise the limit";
        return CliError::LimitExceeded(format!(
            "you've reached the {human} limit{counts}; {advice}"
        ));
    }

    if code == "rate_limited" {
        let retry = body.get("retryAfterSeconds").and_then(|v| v.as_u64());
        let msg = match retry {
            Some(secs) => format!("too many requests; retry in about {secs}s"),
            None => "too many requests; slow down and retry shortly".to_string(),
        };
        return CliError::LimitExceeded(msg);
    }

    let message = if code.is_empty() { "request failed".to_string() } else { code.to_string() };
    match status {
        401 => CliError::AuthFailed(message),
        429 | 503 => CliError::CoordinationPlaneUnreachable(message),
        _ => CliError::Other(message),
    }
}

pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
    path: &str,
    body: &Req,
    access_token: Option<&str>,
) -> Result<Resp, CliError> {
    let addr = coordination_http_addr();
    validate_addr(&addr)?;
    let mut req = client()?.post(format!("{addr}{path}")).json(body);
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }
    let resp =
        req.send().await.map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
    handle_response(resp).await
}

/// Like `post_json`, but for endpoints that return `204 No Content` on success (logout, revoke, etc.).
pub async fn post_json_no_content<Req: Serialize>(
    path: &str,
    body: &Req,
    access_token: Option<&str>,
) -> Result<(), CliError> {
    let addr = coordination_http_addr();
    validate_addr(&addr)?;
    let mut req = client()?.post(format!("{addr}{path}")).json(body);
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }
    let resp =
        req.send().await.map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    handle_response::<serde_json::Value>(resp).await.map(|_| ())
}

pub async fn get_json<Resp: DeserializeOwned>(
    path: &str,
    access_token: Option<&str>,
) -> Result<Resp, CliError> {
    let addr = coordination_http_addr();
    validate_addr(&addr)?;
    let mut req = client()?.get(format!("{addr}{path}"));
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }
    let resp =
        req.send().await.map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
    handle_response(resp).await
}

/// Issues a `DELETE` with no request body for endpoints that return
/// `204 No Content` on success (e.g. terminal single-group delete).
pub async fn delete_no_content(path: &str, access_token: Option<&str>) -> Result<(), CliError> {
    let addr = coordination_http_addr();
    validate_addr(&addr)?;
    let mut req = client()?.delete(format!("{addr}{path}"));
    if let Some(token) = access_token {
        req = req.bearer_auth(token);
    }
    let resp =
        req.send().await.map_err(|e| CliError::CoordinationPlaneUnreachable(e.to_string()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    handle_response::<serde_json::Value>(resp).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_addr_accepts_https_and_loopback_http_only() {
        assert!(validate_addr("https://coordination.example").is_ok());
        assert!(validate_addr("http://127.0.0.1:8787").is_ok());
        assert!(validate_addr("http://coordination.example").is_err());
        assert!(validate_addr("ftp://127.0.0.1").is_err());
    }

    /// Regression test: an earlier version of this function hand-rolled
    /// the host extraction by splitting on `:`, which silently mangled an
    /// IPv6 loopback literal (`[::1]`) since the address itself contains
    /// colons. Parsing with the `url` crate handles this correctly.
    #[test]
    fn validate_addr_handles_an_ipv6_loopback_literal() {
        assert!(validate_addr("http://[::1]:8787").is_ok());
        assert!(validate_addr("http://[2001:db8::1]:8787").is_err());
    }

    #[test]
    fn quota_exceeded_renders_a_specific_actionable_limit_error() {
        let body = serde_json::json!({
            "error": "quota_exceeded",
            "resource": "devices",
            "limit": 20,
            "current": 20
        });
        let err = error_from_body(429, &body);
        match err {
            CliError::LimitExceeded(msg) => {
                assert!(msg.contains("registered devices"), "got: {msg}");
                assert!(msg.contains("20 of 20"), "got: {msg}");
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn rate_limited_renders_a_retry_hint() {
        let body = serde_json::json!({
            "error": "rate_limited",
            "scope": "source",
            "retryAfterSeconds": 30
        });
        match error_from_body(429, &body) {
            CliError::LimitExceeded(msg) => assert!(msg.contains("30s"), "got: {msg}"),
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn plain_401_and_untyped_bodies_keep_their_prior_classification() {
        let auth = error_from_body(401, &serde_json::json!({ "error": "invalid credentials" }));
        assert!(matches!(auth, CliError::AuthFailed(_)));
        let other = error_from_body(500, &serde_json::json!({ "error": "internal error" }));
        assert!(matches!(other, CliError::Other(_)));
    }
}
