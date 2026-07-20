#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sync-core error: {0}")]
    Sync(#[from] yadorilink_sync_core::SyncError),

    /// `peer_orchestrator`'s transport-level failures (e.g. a `PeerChannel`
    /// that could not be constructed for a peer).
    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("device identity load error: {0}")]
    KeyLoad(#[from] yadorilink_transport::KeyLoadError),

    /// Peer WireGuard-key-pin persistence (`peer_key_pins.json`) failed to
    /// parse/serialize.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Catch-all for local validation failures that aren't naturally an
    /// `Err` from another crate (invalid coordination address scheme,
    /// malformed access token header,...).
    #[error("{0}")]
    Config(String),

    /// The netmap subscription's WebSocket connection/protocol errors.
    /// Boxed because `tungstenite::Error` is large, so an unboxed variant
    /// would make every `Result<_, DaemonError>` return type oversized
    /// (`clippy::result_large_err`). The manual `From` impl below keeps `?`
    /// working directly on a `Result<_, tungstenite::Error>`.
    #[error("websocket error: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
}

impl From<tokio_tungstenite::tungstenite::Error> for DaemonError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        DaemonError::WebSocket(Box::new(err))
    }
}
