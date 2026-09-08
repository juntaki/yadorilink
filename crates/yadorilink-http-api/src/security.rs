//! Request-level security gates. Three independent layers, all mandatory:
//!
//! 1. [`require_known_host`] -- applied to *every* route (including the
//!    static Web UI): the `Host` header must exactly name one of this
//!    adapter's own bound loopback addresses. This is the primary defense
//!    against DNS rebinding. An attacker's page at `http://evil.example`
//!    can make `evil.example`'s DNS record resolve to `127.0.0.1`, but it
//!    cannot make the browser send a `Host` header naming anything other
//!    than `evil.example` -- `Host` is set by the browser from the request
//!    URL and is on the Fetch standard's forbidden-header list, so
//!    client-side JS cannot override it. A rebound request's `Host` header
//!    therefore never matches this allowlist, regardless of which IP it
//!    actually connects to.
//! 2. [`require_allowed_origin`] -- applied to every route: when a request
//!    carries an `Origin` header (every browser `fetch`/`XHR` sends one,
//!    same-origin or not; plain navigations and non-browser clients such as
//!    `curl` typically do not) it must exactly match this adapter's own
//!    origin or an explicitly configured dev-server origin. Requests
//!    without an `Origin` header fall through to bearer-token
//!    authentication instead.
//! 3. [`require_bearer_token`] -- applied only to `/api/*`: every request
//!    must carry `Authorization: Bearer <token>` matching this run's
//!    freshly generated token (`token.rs`). The token is never accepted
//!    from a cookie or query string -- see the crate root doc comment for
//!    why a cookie specifically would reopen a CSRF hole despite the Origin
//!    check above (a cookie is auto-attached by the browser to *any*
//!    request to this origin, cross-origin page or not; a header is not).
//!
//! [`add_security_headers`] is a fourth, response-side layer (not a gate):
//! every response, including one an earlier layer already rejected, gets
//! `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` -- this
//! adapter's responses (status/link/token data, and the shell page that
//! reads a bearer token out of `localStorage`) are never something a shared
//! cache or a MIME-sniffing browser should treat as reusable or
//! reinterpretable.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::AppState;

pub async fn require_known_host(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !state.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        tracing::warn!(host, "rejected request: Host header not in this adapter's allowlist");
        return Err(ApiError::Forbidden("Host header not recognized by this adapter"));
    }
    Ok(next.run(req).await)
}

pub async fn require_allowed_origin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(origin_header) = req.headers().get(header::ORIGIN) {
        // A real browser-issued `Origin` header is always ASCII (it's
        // built from a URI's scheme/host/port); a value that fails to
        // parse as one is never going to equal-match this adapter's own
        // allowlist entries either, so treat it as a rejection -- not as
        // "no Origin header was sent" -- fail closed rather than falling
        // through to bearer-token auth alone.
        let Ok(origin) = origin_header.to_str() else {
            tracing::warn!("rejected request: Origin header is not valid ASCII/UTF-8");
            return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
        };
        if !state.allowed_origins.iter().any(|o| o == origin) {
            tracing::warn!(origin, "rejected request: Origin not in this adapter's allowlist");
            return Err(ApiError::Forbidden("Origin not allowed by this adapter"));
        }
    }
    Ok(next.run(req).await)
}

pub async fn require_bearer_token(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // RFC 7235 says the auth-scheme token ("Bearer") is compared
    // case-insensitively; `str::strip_prefix` alone is not, so this splits
    // the scheme off explicitly instead.
    let presented =
        req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(rest)
        });
    let ok = match presented {
        Some(presented) => constant_time_eq(presented.as_bytes(), state.token.as_bytes()),
        None => false,
    };
    if !ok {
        return Err(ApiError::Unauthorized);
    }
    Ok(next.run(req).await)
}

/// Response-side, not a gate: always runs, on every response including one
/// an earlier layer already rejected -- see this module's own doc comment.
pub async fn add_security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Not built for speed -- built so a mismatching guess doesn't run in
/// visibly-varying time depending on where the first differing byte falls.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
