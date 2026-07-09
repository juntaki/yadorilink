#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sync-core error: {0}")]
    Sync(#[from] yadorilink_sync_core::SyncError),

    /// daemon-reliability TD (5.2): `peer_orchestrator`'s transport-level
    /// failures (relay connect, `PeerChannel` connect attempted eagerly
    /// while establishing the shared per-device relay hub).
    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    /// gRPC channel/endpoint setup failures (coordination plane connect) —
    /// distinct from `Grpc` below, which is a failure of an established
    /// call/stream.
    #[error("grpc transport error: {0}")]
    GrpcTransport(#[from] tonic::transport::Error),

    /// A coordination-plane RPC (or its stream) returned an error status.
    /// Boxed rather than `#[from]`'d directly: `tonic::Status` is ~176
    /// bytes, which would otherwise make every `Result<_, DaemonError>`
    /// return type unnecessarily large (`clippy::result_large_err`) even
    /// on call sites that can never hit this variant. The manual `From`
    /// impl below (rather than `#[from]` on a `Box<tonic::Status>` field,
    /// which would only convert from an already-boxed `Status`) keeps
    /// `?` working directly on a `Result<_, tonic::Status>`.
    #[error("grpc error: {0}")]
    Grpc(Box<tonic::Status>),

    /// Peer WireGuard-key-pin persistence (`peer_key_pins.json`) failed to
    /// parse/serialize.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Catch-all for local validation failures that aren't naturally an
    /// `Err` from another crate (invalid coordination address scheme,
    /// malformed access token header, ...).
    #[error("{0}")]
    Config(String),

    /// migrate-coordination-plane-to-cloudflare task 7.2: the
    /// WebSocket-based netmap subscription's connection/protocol errors —
    /// the `http-coordination` feature's counterpart to `GrpcTransport`/`Grpc` above.
    #[cfg(feature = "http-coordination")]
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}

impl From<tonic::Status> for DaemonError {
    fn from(status: tonic::Status) -> Self {
        DaemonError::Grpc(Box::new(status))
    }
}
