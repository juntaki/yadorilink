//! The peer-to-peer sync protocol driver: session lifecycle, handshake,
//! message ordering, timeout/retry/backpressure, compression negotiation,
//! bounded reconcile concurrency, and block serve/request orchestration
//! over one `yadorilink_transport::PeerChannel` per peer. Extracted out of
//! `yadorilink-sync-core` in Phase 7D-6 -- see
//! `docs/design/phase7d6-peer-session-extraction-boundary.md`.

pub mod adaptive_window;
pub mod block_serve;
pub mod error;
pub mod hazard;
pub mod ports;
pub mod rate_limiter;
pub(crate) mod replica_engine_ports;
#[cfg(test)]
pub(crate) mod test_support;

#[path = "peer_session_public.rs"]
pub mod peer_session;
/// The session implementation. Kept `#[doc(hidden)]` and re-exported through
/// [`peer_session`] (`peer_session_public.rs`), which prevents a partially
/// wired session from escaping its constructor -- same split as this file
/// had inside `yadorilink-sync-core` before Phase 7D-6's physical move.
#[doc(hidden)]
#[path = "peer_session.rs"]
pub mod peer_session_impl;

pub use error::PeerSessionError;

/// DST-only targeted trace: set `DST_TRACE_PATH=<exact sync path>` to get
/// stderr tracing of every write-side decision touching exactly that path.
/// Duplicated from `yadorilink-sync-core`'s identical helper (Phase 7D-6
/// crate split -- `peer_session.rs`'s own write-side decisions are exactly
/// the ones this traces) rather than shared, since neither crate may
/// depend on the other. Zero-cost when the variable is unset (one
/// `OnceLock` read and a pointer compare per call site).
pub(crate) fn dst_trace(path: &str, msg: impl FnOnce() -> String) {
    if dst_trace_enabled(path) {
        eprintln!("[DSTTRACE {path}] {}", msg());
    }
}

/// Whether `DST_TRACE_PATH` selects `path`. See `dst_trace`'s doc comment.
pub(crate) fn dst_trace_enabled(path: &str) -> bool {
    static TRACED: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let traced = TRACED.get_or_init(|| std::env::var("DST_TRACE_PATH").ok());
    match traced.as_deref() {
        None => false,
        Some("*") => true,
        Some(spec) => spec.split(',').any(|candidate| candidate.trim() == path),
    }
}
