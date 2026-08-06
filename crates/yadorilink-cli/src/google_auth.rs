//! Google OIDC login for the coordination plane.
//!
//! Native CLI/desktop clients are public OAuth clients (RFC 8252): this
//! crate never holds a Google client secret. Built on the `oauth2` crate
//! rather than hand-rolled request/response parsing for the one piece it
//! still owns -- building the desktop loopback-redirect authorization URL
//! with a PKCE challenge (RFC 7636). The actual Google token exchange for
//! both native flows happens in `coordination-worker` instead, which is the
//! only deployed component that can hold a confidential Google client
//! secret if the selected client type requires one:
//!
//! - Desktop: this crate still opens the browser to Google's consent screen
//!   and receives the authorization code on a loopback listener (unchanged
//!   from the prior design), but hands that code + PKCE verifier to
//!   coordination-worker's `POST /auth/google/desktop/exchange`, which
//!   returns a YadoriLink session directly. This crate never performs the
//!   code-for-token exchange itself and never sees a Google ID token for
//!   this flow.
//! - CLI: this crate never talks to Google at all. `login_via_device_grant`
//!   only calls coordination-worker's `POST /auth/google/device/start` and
//!   `POST /auth/google/device/poll`, which proxy Google's Device
//!   Authorization Grant server-side
//!   (coordination-worker/src/auth/google-broker.ts), including the RFC
//!   8628 `authorization_pending`/`slow_down` polling/backoff handling.

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::error::CliError;
use crate::http_client::post_json;
use crate::token_store;

/// Google requires a distinct OAuth client
/// *type* for the Device Authorization Grant ("TVs and Limited Input
/// devices") than for the loopback-redirect flow ("Desktop app") -- no
/// single client covers both. Only the desktop client id lives here: the
/// device client id is needed only by coordination-worker (which performs
/// that entire flow server-side), never by this crate. Neither id is paired
/// with a secret -- native clients are public OAuth clients; any
/// confidential exchange happens in coordination-worker using a
/// Worker-only secret (`wrangler secret put`), never one shipped in this
/// binary. This id must also be listed in `coordination-worker`'s
/// `GOOGLE_OAUTH_CLIENT_IDS` env var so the server accepts it as a valid
/// token audience.
const GOOGLE_OAUTH_DESKTOP_CLIENT_ID: &str =
    "877395650111-eldole4p3h5oaut7glkkacku49slblpe.apps.googleusercontent.com";

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Overridable for tests only, mirroring `http_client.rs`'s
/// `coordination_http_addr` pattern -- lets a test point this crate at a
/// local mock server instead of Google's real authorization endpoint,
/// without adding a non-test code path for it.
fn google_auth_url() -> String {
    std::env::var("YADORILINK_GOOGLE_AUTH_URL").unwrap_or_else(|_| GOOGLE_AUTH_URL.to_string())
}

/// A PKCE (RFC 7636) verifier/challenge pair for the loopback-redirect
/// Authorization Code flow: `verifier` is kept secret on this machine and
/// presented only at the final token exchange (now performed by
/// coordination-worker, not this crate); `challenge` (its SHA-256,
/// base64url-encoded) is sent up front in the authorization URL. This is
/// what lets a native app safely use an OAuth flow with no confidential
/// client secret (RFC 8252) -- an attacker who intercepts the redirect's
/// authorization code still cannot redeem it without also having `verifier`.
pub struct PkcePair {
    pub verifier: PkceCodeVerifier,
    pub challenge: PkceCodeChallenge,
}

pub fn generate_pkce_pair() -> PkcePair {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    PkcePair { verifier, challenge }
}

/// Builds the Google authorization URL for the loopback-redirect + PKCE
/// flow (RFC 8252) and the CSRF state token to check the callback
/// against. `redirect_uri` must be the exact `http://127.0.0.1:<port>/callback`
/// the local listener is bound to -- Google's "Desktop app" OAuth client
/// type accepts any loopback port without pre-registering an exact one.
/// Building this URL needs only the client id (no secret, no token
/// endpoint) -- `oauth2`'s type-state builder enforces exactly that: this
/// function never sets a client secret or token URL at all.
pub fn google_authorization_url(
    redirect_uri: &str,
    code_challenge: PkceCodeChallenge,
) -> Result<(String, CsrfToken), CliError> {
    let redirect_url = RedirectUrl::new(redirect_uri.to_string())
        .map_err(|e| CliError::Other(format!("invalid redirect URL: {e}")))?;
    let client = BasicClient::new(ClientId::new(GOOGLE_OAUTH_DESKTOP_CLIENT_ID.to_string()))
        .set_auth_uri(
            AuthUrl::new(google_auth_url())
                .map_err(|e| CliError::Other(format!("invalid Google auth URL: {e}")))?,
        )
        .set_redirect_uri(redirect_url);

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(code_challenge)
        .url();
    Ok((auth_url.to_string(), csrf_token))
}

#[derive(Serialize)]
struct DesktopExchangeRequest<'a> {
    code: &'a str,
    #[serde(rename = "redirectUri")]
    redirect_uri: &'a str,
    #[serde(rename = "codeVerifier")]
    code_verifier: &'a str,
}

#[derive(Deserialize)]
struct SessionResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

/// Sends the loopback-redirect flow's authorization code (+ PKCE verifier)
/// to coordination-worker's `POST /auth/google/desktop/exchange`, which
/// performs the actual Google token exchange server-side (using a
/// Worker-only secret if Google's client type requires one), validates the
/// resulting ID token, and returns a YadoriLink session directly -- this
/// crate never receives or holds a Google ID token for this flow. Persists
/// the session via the existing `token_store`.
pub async fn exchange_authorization_code_for_session(
    code: String,
    code_verifier: PkceCodeVerifier,
    redirect_uri: &str,
) -> Result<(), CliError> {
    let resp: SessionResponse = post_json(
        "/auth/google/desktop/exchange",
        &DesktopExchangeRequest {
            code: &code,
            redirect_uri,
            code_verifier: code_verifier.secret(),
        },
        None,
    )
    .await?;
    token_store::save_tokens(&resp.access_token, &resp.refresh_token)
        .map_err(|e| CliError::Other(e.to_string()))
}

#[derive(Serialize)]
struct DeviceStartRequest {}

#[derive(Deserialize)]
struct DeviceStartResponse {
    #[serde(rename = "loginHandle")]
    login_handle: String,
    #[serde(rename = "verificationUri")]
    verification_uri: String,
    #[serde(rename = "userCode")]
    user_code: String,
    #[serde(rename = "expiresIn")]
    expires_in: u64,
    interval: u64,
}

#[derive(Serialize)]
struct DevicePollRequest<'a> {
    #[serde(rename = "loginHandle")]
    login_handle: &'a str,
}

#[derive(Deserialize)]
struct DevicePollResponse {
    status: String,
    interval: Option<u64>,
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
}

/// The YadoriLink session tokens a completed device login produces --
/// returned rather than saved directly so tests can exercise the
/// polling/backoff loop without touching this crate's own OS keyring (see
/// `poll_device_login_to_completion`'s doc comment).
pub(crate) struct DeviceLoginSession {
    pub access_token: String,
    pub refresh_token: String,
}

/// Requests a device login from coordination-worker's brokered Device
/// Authorization Grant and polls until the user completes sign-in on any
/// device with a browser. This crate never talks to Google directly for
/// this flow -- the worker proxies Google's device-authorization/token
/// endpoints server-side, including the RFC 8628
/// `authorization_pending`/`slow_down` handling, so no Google client id or
/// secret is needed here at all. Split out from `login_via_device_grant` so
/// tests can exercise the polling/backoff logic against a mocked
/// coordination server directly, without touching this crate's own OS
/// keyring (`token_store::save_tokens`).
pub(crate) async fn poll_device_login_to_completion() -> Result<DeviceLoginSession, CliError> {
    let start: DeviceStartResponse =
        post_json("/auth/google/device/start", &DeviceStartRequest {}, None).await?;

    println!("To log in, open {} and enter this code:", start.verification_uri);
    println!();
    println!("    {}", start.user_code);
    println!();
    println!("Waiting for you to complete sign-in...");

    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    let mut interval = Duration::from_secs(start.interval.max(1));

    loop {
        tokio::time::sleep(interval).await;
        if Instant::now() >= deadline {
            return Err(CliError::AuthFailed("device sign-in expired".into()));
        }

        let poll: DevicePollResponse = post_json(
            "/auth/google/device/poll",
            &DevicePollRequest { login_handle: &start.login_handle },
            None,
        )
        .await?;

        match poll.status.as_str() {
            // The worker already tracks the authoritative current interval
            // (bumping it on Google's own `slow_down`) -- this loop just
            // adopts whatever it returns rather than guessing.
            "pending" | "slow_down" => {
                if let Some(secs) = poll.interval {
                    interval = Duration::from_secs(secs.max(1));
                }
            }
            "denied" => return Err(CliError::AuthFailed("sign-in was denied".into())),
            "expired" => return Err(CliError::AuthFailed("device sign-in expired".into())),
            "completed" => {
                let access_token = poll.access_token.ok_or_else(|| {
                    CliError::Other("worker reported a completed login with no access token".into())
                })?;
                let refresh_token = poll.refresh_token.ok_or_else(|| {
                    CliError::Other(
                        "worker reported a completed login with no refresh token".into(),
                    )
                })?;
                return Ok(DeviceLoginSession { access_token, refresh_token });
            }
            other => {
                return Err(CliError::Other(format!("unexpected device login status: {other}")));
            }
        }
    }
}

pub async fn login_via_device_grant() -> Result<(), CliError> {
    let session = poll_device_login_to_completion().await?;
    token_store::save_tokens(&session.access_token, &session.refresh_token)
        .map_err(|e| CliError::Other(e.to_string()))?;
    println!("Logged in.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::poll_device_login_to_completion;

    /// Returns coordination-worker's `pending` poll response on its first
    /// call, `slow_down` (with a bumped `interval`) on its second, and a
    /// `completed` response from the third call onward -- exercises this
    /// crate's own polling/backoff loop deterministically, by call count
    /// rather than by real elapsed time. Mirrors the shape
    /// coordination-worker/src/auth/google-broker.ts actually returns, not
    /// Google's own device-token response (this crate never sees that).
    struct SequencedPollResponder {
        call_count: AtomicUsize,
    }

    impl Respond for SequencedPollResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            match self.call_count.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(200)
                    .set_body_json(json!({ "status": "pending", "interval": 1 })),
                1 => ResponseTemplate::new(200)
                    .set_body_json(json!({ "status": "slow_down", "interval": 6 })),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "status": "completed",
                    "accessToken": "test-access-token",
                    "refreshToken": "test-refresh-token",
                })),
            }
        }
    }

    /// Serializes access to the `YADORILINK_COORDINATION_HTTP_ADDR` env var
    /// this test mutates -- process-global state that would otherwise race
    /// against any other test in this same binary that touches it. A
    /// `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held
    /// across this test's own multi-second `.await` (the whole point is to
    /// keep the env var stable for that entire span), and
    /// `std::sync::MutexGuard` held across an await point is exactly what
    /// `clippy::await_holding_lock` flags as a real hazard (a blocked std
    /// mutex can starve the async runtime); the tokio version is designed
    /// to be held this way.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn poll_device_login_honors_pending_and_slow_down_backoff_from_the_worker() {
        let _guard = ENV_LOCK.lock().await;
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/google/device/start"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "loginHandle": "test-login-handle",
                "verificationUri": "https://verify.example/here",
                "userCode": "ABCD-EFGH",
                "expiresIn": 60,
                "interval": 1,
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/auth/google/device/poll"))
            .respond_with(SequencedPollResponder { call_count: AtomicUsize::new(0) })
            .mount(&server)
            .await;

        std::env::set_var("YADORILINK_COORDINATION_HTTP_ADDR", server.uri());

        let start = Instant::now();
        let result = poll_device_login_to_completion().await;
        let elapsed = start.elapsed();

        std::env::remove_var("YADORILINK_COORDINATION_HTTP_ADDR");

        let session = result.expect("device grant should succeed after pending/slow_down");
        assert_eq!(session.access_token, "test-access-token");
        assert_eq!(session.refresh_token, "test-refresh-token");
        // The worker's own interval (1s pending, then 6s after slow_down)
        // drives this loop's sleeps -- a call-count-only stub with no real
        // backoff would return in well under a second.
        assert!(
            elapsed >= Duration::from_secs(1 + 6),
            "elapsed={elapsed:?} -- backoff was not actually honored"
        );
    }
}
