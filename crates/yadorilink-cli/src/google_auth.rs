//! switch-coordination-auth-to-google-oidc: Google OIDC login for the
//! HTTP-coordination transport, replacing email+password auth entirely.
//! Only compiled under the `http-coordination` feature.
//!
//! Built on the `oauth2` crate rather than hand-rolled request/response
//! parsing: OAuth request-building, PKCE generation, and device-flow
//! polling (including `authorization_pending`/`slow_down` handling per
//! RFC 8628) are exactly the kind of auth-adjacent code better left to a
//! maintained, widely-used library than reimplemented here -- unlike the
//! Argon2id/`hash-wasm` situation elsewhere in this codebase's history,
//! where the established dependency turned out to be actively
//! incompatible with the target runtime and hand-rolling was the only
//! option, nothing here rules out a real OAuth library.
//!
//! `exchange_id_token_for_session` is the one place any client trusts a
//! Google-issued ID token -- both `yadorilink-cli`'s Device Authorization
//! Grant flow (this module) and `yadorilink-desktop-app`'s loopback-redirect
//! plus PKCE flow call this same function (the latter depends on this
//! crate directly, matching this crate's existing "one implementation of
//! a security-sensitive path" preference -- see Cargo.toml's comment on
//! why `yadorilink-desktop-app` reuses `grpc::require_access_token`/
//! `resolve_group_id` rather than reimplementing them).

use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::{
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, DeviceAuthorizationUrl,
    EndpointNotSet, ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardDeviceAuthorizationResponse, StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::http_client::post_json;
use crate::token_store;

/// **Confirmed** (tasks.md 2.4): Google requires a distinct OAuth client
/// *type* for the Device Authorization Grant ("TVs and Limited Input
/// devices") than for the loopback-redirect flow ("Desktop app") -- no
/// single client covers both, so this crate hardcodes two separate
/// id/secret pairs (design.md: the coordination plane is not open source
/// and not self-hosted, so one hardcoded value per flow covers every
/// install of this CLI). Google issues a client secret even for
/// installed-app OAuth clients (it is not treated as confidential the way
/// a server-side web app's would be -- PKCE is the actual security
/// mechanism for the loopback flow, per RFC 8252). Both client ids must
/// also be listed in the HTTP coordination service's `GOOGLE_OAUTH_CLIENT_IDS` env
/// var so the server accepts either as a valid token audience.
const GOOGLE_OAUTH_DESKTOP_CLIENT_ID: &str = "REPLACE_WITH_GOOGLE_OAUTH_DESKTOP_CLIENT_ID";
const GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET: &str = "REPLACE_WITH_GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET";
const GOOGLE_OAUTH_DEVICE_CLIENT_ID: &str = "REPLACE_WITH_GOOGLE_OAUTH_DEVICE_CLIENT_ID";
const GOOGLE_OAUTH_DEVICE_CLIENT_SECRET: &str = "REPLACE_WITH_GOOGLE_OAUTH_DEVICE_CLIENT_SECRET";

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_DEVICE_AUTH_URL: &str = "https://oauth2.googleapis.com/device/code";

/// Overridable for tests only, mirroring `http_client.rs`'s
/// `coordination_http_addr()` pattern -- lets a test point this crate at a
/// local mock server instead of Google's real endpoints, without adding a
/// non-test code path for it.
fn google_token_url() -> String {
    std::env::var("YADORILINK_GOOGLE_TOKEN_URL").unwrap_or_else(|_| GOOGLE_TOKEN_URL.to_string())
}
fn google_device_auth_url() -> String {
    std::env::var("YADORILINK_GOOGLE_DEVICE_AUTH_URL")
        .unwrap_or_else(|_| GOOGLE_DEVICE_AUTH_URL.to_string())
}
fn google_auth_url() -> String {
    std::env::var("YADORILINK_GOOGLE_AUTH_URL").unwrap_or_else(|_| GOOGLE_AUTH_URL.to_string())
}

/// Google's OIDC `id_token` is not part of the OAuth2 core token response
/// (RFC 6749) -- it is an OIDC extension, so `oauth2`'s `ExtraTokenFields`
/// mechanism is how this crate captures it alongside the standard
/// access/refresh token fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleExtraTokenFields {
    id_token: Option<String>,
}
impl ExtraTokenFields for GoogleExtraTokenFields {}
type GoogleTokenResponse = StandardTokenResponse<GoogleExtraTokenFields, BasicTokenType>;

type GoogleClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    GoogleTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

/// `client_id`/`client_secret` select which of the two hardcoded OAuth
/// clients (Desktop app vs. TV/Limited-Input) this call builds for --
/// only the token URL is required unconditionally (both flows exchange a
/// code for a token there); auth_url/device_auth_url are added by each
/// flow's own entry point below, since the two flows need different ones
/// and `oauth2`'s type-state builder only allows a given endpoint-
/// dependent method once its endpoint is actually set.
fn google_client(
    client_id: &str,
    client_secret: &str,
) -> Result<
    GoogleClient<
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        oauth2::EndpointSet,
    >,
    CliError,
> {
    Ok(GoogleClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_token_uri(
            TokenUrl::new(google_token_url())
                .map_err(|e| CliError::Other(format!("invalid Google token URL: {e}")))?,
        ))
}

fn http_client() -> reqwest::Client {
    // Following redirects on an OAuth token/authorization response opens
    // the client up to SSRF-style vulnerabilities (per `oauth2`'s own
    // examples) -- this crate never expects a redirect from Google's
    // token endpoint.
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client should build")
}

/// A PKCE (RFC 7636) verifier/challenge pair for the loopback-redirect
/// Authorization Code flow: `verifier` is kept secret on this machine and
/// presented only at the final token exchange; `challenge` (its SHA-256,
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
pub fn google_authorization_url(
    redirect_uri: &str,
    code_challenge: PkceCodeChallenge,
) -> Result<(String, CsrfToken), CliError> {
    let redirect_url = RedirectUrl::new(redirect_uri.to_string())
        .map_err(|e| CliError::Other(format!("invalid redirect URL: {e}")))?;
    let client = google_client(GOOGLE_OAUTH_DESKTOP_CLIENT_ID, GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET)?
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

/// Exchanges an authorization code (+ PKCE verifier) from the
/// loopback-redirect flow for a Google ID token.
pub async fn exchange_authorization_code_for_id_token(
    code: String,
    code_verifier: PkceCodeVerifier,
    redirect_uri: &str,
) -> Result<String, CliError> {
    let redirect_url = RedirectUrl::new(redirect_uri.to_string())
        .map_err(|e| CliError::Other(format!("invalid redirect URL: {e}")))?;
    let client = google_client(GOOGLE_OAUTH_DESKTOP_CLIENT_ID, GOOGLE_OAUTH_DESKTOP_CLIENT_SECRET)?
        .set_auth_uri(
            AuthUrl::new(google_auth_url())
                .map_err(|e| CliError::Other(format!("invalid Google auth URL: {e}")))?,
        )
        .set_redirect_uri(redirect_url);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(code_verifier)
        .request_async(&http_client())
        .await
        .map_err(|e| CliError::AuthFailed(format!("Google token exchange failed: {e}")))?;

    token_response.extra_fields().id_token.clone().ok_or_else(|| {
        CliError::Other(
            "Google token response had no id_token -- was the openid scope requested?".into(),
        )
    })
}

/// Requests a device code from Google and polls until the user completes
/// sign-in on any device with a browser (RFC 8628, handled internally by
/// `oauth2`'s `exchange_device_access_token`, including
/// `authorization_pending`/`slow_down` responses), returning the resulting
/// Google ID token. Split out from `login_via_device_grant` so tests can
/// exercise the device-grant polling/backoff logic against a mocked
/// Google directly, without touching this crate's own coordination-plane
/// session exchange or OS keyring (`exchange_id_token_for_session`).
pub(crate) async fn fetch_id_token_via_device_grant() -> Result<String, CliError> {
    let client = google_client(GOOGLE_OAUTH_DEVICE_CLIENT_ID, GOOGLE_OAUTH_DEVICE_CLIENT_SECRET)?
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new(google_device_auth_url()).map_err(|e| {
                CliError::Other(format!("invalid Google device authorization URL: {e}"))
            })?,
        );
    let http_client = http_client();

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .request_async(&http_client)
        .await
        .map_err(|e| {
            CliError::CoordinationPlaneUnreachable(format!(
                "Google device-authorization request failed: {e}"
            ))
        })?;

    println!("To log in, open {} and enter this code:", details.verification_uri());
    println!();
    println!("    {}", details.user_code().secret());
    println!();
    println!("Waiting for you to complete sign-in...");

    let token_response: GoogleTokenResponse = client
        .exchange_device_access_token(&details)
        .request_async(&http_client, tokio::time::sleep, None)
        .await
        .map_err(|e| CliError::AuthFailed(format!("Google sign-in failed: {e}")))?;

    token_response.extra_fields().id_token.clone().ok_or_else(|| {
        CliError::Other(
            "Google token response had no id_token -- was the openid scope requested?".into(),
        )
    })
}

/// On success, exchanges the resulting Google ID token for this system's
/// own session via `exchange_id_token_for_session`.
pub async fn login_via_device_grant() -> Result<(), CliError> {
    let id_token = fetch_id_token_via_device_grant().await?;
    exchange_id_token_for_session(&id_token).await?;
    println!("Logged in.");
    Ok(())
}

#[derive(Serialize)]
struct GoogleLoginRequest<'a> {
    #[serde(rename = "idToken")]
    id_token: &'a str,
}

#[derive(Deserialize)]
struct GoogleLoginResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

/// The one place any client trusts a Google-issued ID token: exchanges it
/// with the HTTP coordination service's `/auth/google` (which verifies the token's
/// signature/issuer/audience/expiry server-side) for this system's own
/// session tokens, and persists them via the existing `token_store`.
pub async fn exchange_id_token_for_session(id_token: &str) -> Result<(), CliError> {
    let resp: GoogleLoginResponse =
        post_json("/auth/google", &GoogleLoginRequest { id_token }, None).await?;
    token_store::save_tokens(&resp.access_token, &resp.refresh_token)
        .map_err(|e| CliError::Other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::fetch_id_token_via_device_grant;

    /// Returns Google's token-endpoint `authorization_pending` response on
    /// its first call, `slow_down` on its second, and a successful token
    /// response (carrying a distinguishable `id_token`) from the third call
    /// onward -- exercises `oauth2`'s RFC 8628 polling/backoff handling
    /// (switch-coordination-auth-to-google-oidc task 5.3) deterministically,
    /// by call count rather than by real elapsed time.
    struct SequencedTokenResponder {
        call_count: AtomicUsize,
    }

    impl Respond for SequencedTokenResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            match self.call_count.fetch_add(1, Ordering::SeqCst) {
                0 => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "authorization_pending" })),
                1 => ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "slow_down" })),
                _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "test-access-token",
                    "token_type": "bearer",
                    "id_token": "test-id-token",
                })),
            }
        }
    }

    /// Serializes access to the `YADORILINK_GOOGLE_*` env vars this test
    /// mutates -- process-global state that would otherwise race against
    /// any other test in this same binary that touches them (none do today,
    /// but this guards against that changing silently). A `tokio::sync::Mutex`,
    /// not `std::sync::Mutex`: the guard is held across this test's own
    /// multi-second `.await` (the whole point is to keep the env vars
    /// stable for that entire span), and `std::sync::MutexGuard` held
    /// across an await point is exactly what `clippy::await_holding_lock`
    /// flags as a real hazard (a blocked std mutex can starve the async
    /// runtime); the tokio version is designed to be held this way.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn fetch_id_token_via_device_grant_honors_authorization_pending_and_slow_down_backoff() {
        let _guard = ENV_LOCK.lock().await;
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "test-device-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://verify.example/here",
                "expires_in": 60,
                "interval": 1,
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(SequencedTokenResponder { call_count: AtomicUsize::new(0) })
            .mount(&server)
            .await;

        std::env::set_var(
            "YADORILINK_GOOGLE_DEVICE_AUTH_URL",
            format!("{}/device/code", server.uri()),
        );
        std::env::set_var("YADORILINK_GOOGLE_TOKEN_URL", format!("{}/token", server.uri()));

        let start = Instant::now();
        let result = fetch_id_token_via_device_grant().await;
        let elapsed = start.elapsed();

        std::env::remove_var("YADORILINK_GOOGLE_DEVICE_AUTH_URL");
        std::env::remove_var("YADORILINK_GOOGLE_TOKEN_URL");

        assert_eq!(
            result.expect("device grant should succeed after pending/slow_down"),
            "test-id-token"
        );
        // `oauth2` keeps the 1s interval unchanged on `authorization_pending`
        // and adds a flat 5s on `slow_down` (RFC 8628 default backoff),
        // so the real polling loop sleeps ~1s then ~6s before the third
        // (successful) poll -- a call-count-only stub with no real backoff
        // would return in well under a second.
        assert!(
            elapsed >= Duration::from_secs(6),
            "elapsed={elapsed:?} -- backoff was not actually honored"
        );
    }
}
