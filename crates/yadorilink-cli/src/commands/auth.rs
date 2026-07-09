#[cfg(feature = "http-coordination")]
mod http {
    //! Google OIDC login, replacing email+password register/login entirely
    //! for this transport. There is no separate `register` -- the HTTP
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

#[cfg(feature = "http-coordination")]
pub use http::{login, logout};

#[cfg(not(feature = "http-coordination"))]
mod grpc_impl {
    use yadorilink_ipc_proto::coordination::auth_service_client::AuthServiceClient;
    use yadorilink_ipc_proto::coordination::{LoginRequest, LogoutRequest, RegisterRequest};

    use crate::error::CliError;
    use crate::grpc::coordination_channel;
    use crate::token_store;

    pub async fn register(email: String, password: String) -> Result<(), CliError> {
        let mut client = AuthServiceClient::new(coordination_channel().await?);
        client.register(RegisterRequest { email, password }).await?;
        println!("Account registered. Run `yadorilink login` next.");
        Ok(())
    }

    pub async fn login(email: String, password: String) -> Result<(), CliError> {
        let mut client = AuthServiceClient::new(coordination_channel().await?);
        let resp = client.login(LoginRequest { email, password }).await?.into_inner();
        token_store::save_tokens(&resp.access_token, &resp.refresh_token)
            .map_err(|e| CliError::Other(e.to_string()))?;
        println!("Logged in.");
        Ok(())
    }

    pub async fn logout() -> Result<(), CliError> {
        let refresh_token = token_store::load_refresh_token().ok_or(CliError::NotLoggedIn)?;
        let mut client = AuthServiceClient::new(coordination_channel().await?);
        // Best-effort: still clear local tokens even if the server call fails
        // (e.g. the coordination plane is unreachable) — logout should never
        // leave the user stuck locally "logged in" to nothing.
        let _ = client.logout(LogoutRequest { refresh_token }).await;
        token_store::clear_tokens();
        println!("Logged out.");
        Ok(())
    }
}

#[cfg(not(feature = "http-coordination"))]
pub use grpc_impl::{login, logout, register};
