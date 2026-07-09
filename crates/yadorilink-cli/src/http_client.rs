//! HTTP+WebSocket client for the Cloudflare-hosted coordination plane.
//! Mirrors `grpc.rs`'s role for the gRPC transport, but talks to the HTTP
//! coordination service's plain JSON routes instead of the tonic-generated
//! service clients. Only compiled under the `http-coordination` feature
//! (see Cargo.toml) so the existing gRPC path is unaffected when this
//! feature is off.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::CliError;

pub fn coordination_http_addr() -> String {
    std::env::var("YADORILINK_COORDINATION_HTTP_ADDR")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".into())
}

/// Same http(s)/loopback validation as `grpc::coordination_channel`: a
/// remote address must use `https://`; only a loopback host may use plain
/// `http://` (local `wrangler dev`). Uses the
/// `url` crate to parse the address rather than hand-rolled string
/// splitting -- an earlier hand-rolled version of this function split on
/// `:` to find the host, which silently mangled IPv6 literal addresses
/// like `http://[::1]:8787` (the same bug class this crate's own
/// `google_login.rs`/`peer_orchestrator.rs` avoided by switching to `url`
/// too). `grpc.rs`'s equivalent check gets this for free from `tonic`'s
/// own `http::Uri` parsing; this module talks plain HTTP instead, so it
/// needs its own parser.
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

/// Matches on `url`'s typed `Host` enum rather than `host_str()` -- for an
/// IPv6 literal, `host_str()` returns the bracketed authority form
/// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a first
/// attempt at this fix used `host_str()` this way and shipped with exactly
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
    let message =
        body.get("error").and_then(|v| v.as_str()).unwrap_or("request failed").to_string();
    Err(match status.as_u16() {
        401 => CliError::AuthFailed(message),
        429 | 503 => CliError::CoordinationPlaneUnreachable(message),
        _ => CliError::Other(message),
    })
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
}
