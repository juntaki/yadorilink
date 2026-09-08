mod http {
    //! Google OIDC login. There is no separate `register` -- the
    //! coordination service's `/auth/google` finds or creates the account
    //! on first login.

    use serde::Serialize;

    use crate::error::CliError;
    use crate::google_auth::login_via_device_grant;
    use crate::http_client::post_json_no_content;
    use crate::token_store;

    // The coordination plane's `POST /auth/logout` route reads
    // `body.refreshToken` (camelCase) -- a snake_case `refresh_token` key
    // arrives as `undefined` server-side, `logout()` hashes that `undefined`
    // (coerced to the empty string), matches no session row, and the route
    // still returns 204 either way. That silent no-op is worse than an
    // ordinary parse failure: the CLI prints "Logged out." and clears its
    // OWN local tokens, but the coordination plane never actually revokes
    // the refresh-token session family, so a user who believes they logged
    // out (e.g. on a shared machine) has not invalidated their session at
    // all. See `logout_request_serializes_the_camelcase_field_the_coordination_plane_reads`
    // below, and the coordination-worker's own
    // `"a logout request with the wrong-cased field name does not revoke
    // the session"` regression test for the server-side half of this.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct LogoutRequest<'a> {
        refresh_token: &'a str,
    }

    pub async fn login() -> Result<(), CliError> {
        login_via_device_grant().await
    }

    /// Sends the actual `POST /auth/logout` call -- split out from `logout`
    /// so a test can exercise the exact request this crate sends against a
    /// mocked coordination server, without touching this crate's own OS
    /// keyring (`token_store`), mirroring `google_auth::poll_device_login_to_completion`'s
    /// identical split for the identical reason.
    async fn send_logout_request(refresh_token: &str) -> Result<(), CliError> {
        post_json_no_content("/auth/logout", &LogoutRequest { refresh_token }, None).await
    }

    pub async fn logout() -> Result<(), CliError> {
        let refresh_token = token_store::load_refresh_token().ok_or(CliError::NotLoggedIn)?;
        // Best-effort: still clear local tokens even if the server call
        // fails (e.g. the coordination plane is unreachable) — logout
        // should never leave the user stuck locally "logged in" to nothing.
        let _ = send_logout_request(&refresh_token).await;
        token_store::clear_tokens();
        println!("Logged out.");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// `LogoutRequest` must serialize to exactly `{"refreshToken": ...}`
        /// -- the coordination plane's logout route reads `body.refreshToken`
        /// (camelCase); a `refresh_token` key (this struct's field name,
        /// unrenamed) arrives `undefined` server-side.
        #[test]
        fn logout_request_serializes_the_camelcase_field_the_coordination_plane_reads() {
            let body = serde_json::to_value(LogoutRequest { refresh_token: "tok" }).unwrap();
            assert_eq!(body["refreshToken"], "tok");
            assert!(body.get("refresh_token").is_none());
        }

        /// End-to-end regression test: `LogoutRequest` was missing
        /// `#[serde(rename_all = "camelCase")]`, so this crate sent
        /// `{"refresh_token": ...}` to a route that reads
        /// `body.refreshToken` -- the coordination plane's `logout()` then
        /// hashed `undefined` (coerced to the empty string), matched no
        /// session row, and the route still returned 204. The CLI printed
        /// "Logged out." either way, but the refresh-token session family
        /// was never actually revoked server-side -- a user who believed
        /// they had logged out (e.g. on a shared machine) had not. This
        /// asserts the REAL wire body `send_logout_request` produces over
        /// an actual HTTP round trip, not merely the struct's serialization
        /// in isolation -- see the coordination-worker's own
        /// `"a logout request with the wrong-cased field name does not
        /// revoke the session"` test for proof, at the server layer, of
        /// exactly what a regression back to the old body shape would cost.
        #[tokio::test]
        async fn logout_sends_the_camelcase_refresh_token_field_the_coordination_plane_reads() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/auth/logout"))
                .respond_with(ResponseTemplate::new(204))
                .mount(&server)
                .await;

            // Shared with `google_auth`'s own tests -- see that static's
            // doc comment for why this must be a single crate-wide lock
            // around this process-global env var.
            let _guard = crate::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
            std::env::set_var("YADORILINK_COORDINATION_HTTP_ADDR", server.uri());
            let result = send_logout_request("the-refresh-token").await;
            std::env::remove_var("YADORILINK_COORDINATION_HTTP_ADDR");

            assert!(result.is_ok(), "expected the logout call to succeed: {result:?}");

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1, "expected exactly one logout request");
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(
                body,
                serde_json::json!({ "refreshToken": "the-refresh-token" }),
                "the coordination plane's logout route reads body.refreshToken -- a body shaped \
                 any other way (e.g. the old snake_case refresh_token key) silently fails to \
                 revoke the session while still returning success"
            );
        }
    }
}

pub use http::{login, logout};
