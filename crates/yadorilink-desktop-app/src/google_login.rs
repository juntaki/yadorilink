//! Google OIDC authentication and native OAuth client-secret handling:
//! the desktop app's own "Login" action -- an OAuth 2.0 Authorization Code +
//! PKCE flow with a loopback (`127.0.0.1`) redirect (RFC 8252's native-app
//! pattern). Opens the system browser to Google's consent screen and
//! receives the callback on a temporary local HTTP listener this module
//! starts for that purpose, entirely self-contained with no external relay
//! service. PKCE generation and the authorization URL live in
//! `yadorilink_cli::google_auth` (shared with the CLI) -- this module only
//! owns what's specific to the loopback-redirect variant: the local
//! listener and opening the browser. The actual Google token exchange is
//! brokered by coordination-worker (`exchange_authorization_code_for_session`),
//! not performed by this binary -- see google_auth.rs's module doc.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("could not start the local OAuth callback listener: {0}")]
    Listener(std::io::Error),
    #[error("could not open the system browser: {0}")]
    Browser(opener::OpenError),
    #[error("OAuth callback was malformed or missing an authorization code: {0}")]
    MalformedCallback(String),
    #[error("the browser reported it could not complete sign-in: {0}")]
    Denied(String),
    #[error("OAuth callback state did not match -- possible CSRF, aborting login")]
    StateMismatch,
    #[error(transparent)]
    Auth(#[from] yadorilink_cli::error::CliError),
}

/// Runs the full loopback-redirect + PKCE login flow to completion: opens
/// the browser, waits for the single callback request, exchanges the
/// resulting code for a Google ID token, and exchanges that for this
/// system's own session (persisted via the existing `token_store`, shared
/// with the CLI).
pub async fn login() -> Result<(), LoginError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(LoginError::Listener)?;
    let port = listener.local_addr().map_err(LoginError::Listener)?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let pkce = yadorilink_cli::google_auth::generate_pkce_pair();
    let (auth_url, csrf_token) =
        yadorilink_cli::google_auth::google_authorization_url(&redirect_uri, pkce.challenge)?;

    opener::open(&auth_url).map_err(LoginError::Browser)?;

    let code = accept_callback(listener, csrf_token.secret()).await?;

    yadorilink_cli::google_auth::exchange_authorization_code_for_session(
        code,
        pkce.verifier,
        &redirect_uri,
    )
    .await?;
    Ok(())
}

/// Accepts exactly one connection on `listener` (the OAuth redirect),
/// reads its request line, and parses `code`/`state`/`error` from the
/// query string via the `url` crate (not hand-rolled percent-decoding --
/// same crate `oauth2`'s own loopback-redirect example uses for this
/// exact purpose), then responds with a static confirmation page. No need
/// for a full HTTP server crate just to read one request line.
async fn accept_callback(
    listener: TcpListener,
    expected_state: &str,
) -> Result<String, LoginError> {
    let (mut stream, _) = listener.accept().await.map_err(LoginError::Listener)?;

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.map_err(LoginError::Listener)?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| LoginError::MalformedCallback("empty request".into()))?;
    let path_and_query = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| LoginError::MalformedCallback(request_line.to_string()))?;
    let url = Url::parse(&format!("http://127.0.0.1{path_and_query}"))
        .map_err(|e| LoginError::MalformedCallback(e.to_string()))?;
    let param = |key: &str| url.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v.into_owned());

    // The callback query is attacker-influenceable: any local process or web
    // page that reaches this loopback port can supply arbitrary `error`,
    // `state`, and `code` values. So (1) never reflect a callback value into
    // the HTML response without escaping, and (2) validate `state` before
    // returning any "signed in" result. The response also carries a locked-down
    // CSP and nosniff so even a reflected value cannot execute.
    let error = param("error");
    let state_matches = param("state").as_deref() == Some(expected_state);
    let (status_line, body) = if let Some(error) = &error {
        (
            "HTTP/1.1 200 OK",
            format!(
                "<!doctype html><html><body><h1>Sign-in was not completed</h1><p>{}</p><p>You can close this tab.</p></body></html>",
                html_escape(error)
            ),
        )
    } else if !state_matches {
        (
            "HTTP/1.1 400 Bad Request",
            "<!doctype html><html><body><h1>Sign-in could not be verified</h1><p>You can close this tab and try again.</p></body></html>"
                .to_string(),
        )
    } else {
        (
            "HTTP/1.1 200 OK",
            "<!doctype html><html><body><h1>Signed in</h1><p>You can close this tab and return to yadorilink.</p></body></html>"
                .to_string(),
        )
    };
    let response = format!(
        "{status_line}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;

    if let Some(error) = error {
        return Err(LoginError::Denied(error));
    }
    if !state_matches {
        return Err(LoginError::StateMismatch);
    }
    param("code")
        .ok_or_else(|| LoginError::MalformedCallback("callback had no authorization code".into()))
}

/// Minimal HTML-entity escape for the small confirmation pages served on the
/// loopback callback. Callback query values are attacker-influenceable, so any
/// value echoed into the response is escaped to inert text.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    /// A real local `TcpListener` + a real TCP connection sending
    /// a hand-written HTTP GET request line, simulating exactly what the
    /// browser's redirect produces -- not a mocked stream.
    #[tokio::test]
    async fn accept_callback_extracts_the_code_from_a_real_redirect_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?code=abc123&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        });

        let code = accept_callback(listener, "expected-state").await.unwrap();
        client.await.unwrap();

        assert_eq!(code, "abc123");
    }

    #[tokio::test]
    async fn accept_callback_rejects_a_state_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?code=abc123&state=wrong-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        });

        let err = accept_callback(listener, "expected-state").await.unwrap_err();
        client.await.unwrap();

        assert!(matches!(err, LoginError::StateMismatch));
    }

    #[tokio::test]
    async fn accept_callback_surfaces_an_access_denied_redirect_as_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?error=access_denied&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        });

        let err = accept_callback(listener, "expected-state").await.unwrap_err();
        client.await.unwrap();

        assert!(matches!(err, LoginError::Denied(reason) if reason == "access_denied"));
    }

    /// Percent-decoding is now `url`'s responsibility (not hand-rolled) --
    /// this exercises it through the real `accept_callback` path with a
    /// percent-encoded code, rather than testing a private helper.
    #[tokio::test]
    async fn accept_callback_percent_decodes_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?code=a%2Fb&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        });

        let code = accept_callback(listener, "expected-state").await.unwrap();
        client.await.unwrap();

        assert_eq!(code, "a/b");
    }

    /// A callback `error` value is attacker-influenceable, so it must be
    /// reflected into the response as inert, escaped text -- never raw HTML --
    /// and the response must carry a locked-down CSP + nosniff.
    #[tokio::test]
    async fn accept_callback_escapes_reflected_error_and_locks_down_the_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?error=%3Cscript%3Ealert(1)%3C/script%3E&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp).into_owned()
        });

        let err = accept_callback(listener, "expected-state").await.unwrap_err();
        let response = client.await.unwrap();

        assert!(matches!(err, LoginError::Denied(_)));
        // The raw script tag must not appear; its escaped form must.
        assert!(!response.contains("<script>"), "unescaped script tag was reflected: {response}");
        assert!(response.contains("&lt;script&gt;"), "escaped form missing: {response}");
        // Defense-in-depth headers are present.
        assert!(
            response.contains("Content-Security-Policy: default-src 'none'"),
            "CSP missing: {response}"
        );
        assert!(
            response.contains("X-Content-Type-Options: nosniff"),
            "nosniff missing: {response}"
        );
    }

    /// A wrong `state` must not yield a "Signed in" success page; it is
    /// rejected before any success result.
    #[tokio::test]
    async fn accept_callback_does_not_show_success_on_state_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            stream
                .write_all(b"GET /callback?code=abc123&state=wrong-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            String::from_utf8_lossy(&resp).into_owned()
        });

        let err = accept_callback(listener, "expected-state").await.unwrap_err();
        let response = client.await.unwrap();

        assert!(matches!(err, LoginError::StateMismatch));
        assert!(
            !response.contains("Signed in"),
            "success page shown despite bad state: {response}"
        );
    }
}
