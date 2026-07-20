mod http {
    //! Google OIDC login. There is no separate `register` -- the
    //! coordination service's `/auth/google` finds or creates the account
    //! on first login.

    use serde::Serialize;

    use crate::error::CliError;
    use crate::google_auth::login_via_device_grant;
    use crate::http_client::post_json_no_content;
    use crate::token_store;

    #[derive(Serialize)]
    struct LogoutRequest<'a> {
        refresh_token: &'a str,
    }

    pub async fn login() -> Result<(), CliError> {
        login_via_device_grant().await
    }

    pub async fn logout() -> Result<(), CliError> {
        let refresh_token = token_store::load_refresh_token().ok_or(CliError::NotLoggedIn)?;
        // Best-effort: still clear local tokens even if the server call
        // fails (e.g. the coordination plane is unreachable) — logout
        // should never leave the user stuck locally "logged in" to nothing.
        let _ = post_json_no_content(
            "/auth/logout",
            &LogoutRequest { refresh_token: &refresh_token },
            None,
        )
        .await;
        token_store::clear_tokens();
        println!("Logged out.");
        Ok(())
    }
}

pub use http::{login, logout};
