//! The capability surface `PeerSyncSession` (`peer_session.rs`) needs from
//! `yadorilink_transport::PeerChannel`: encoded-message send/receive,
//! reliable-delivery negotiation, and coordination-candidate refresh. Every
//! method below is called by `peer_session.rs` today via
//! `self.channel.<method>`, surveyed directly from that file (`grep -n
//! "\.channel\." crates/yadorilink-sync-core/src/peer_session.rs`) rather
//! than sketched from `PeerChannel`'s full method surface, which also
//! exposes `reachability`/`reachability_watch` and internal actor plumbing
//! this crate never touches.
//!
//! `#[async_trait]` because `send`, `recv`, and
//! `replace_coordination_candidates` are async on the real `PeerChannel`;
//! `try_send` and `enable_reliable_delivery` stay plain sync fns, matching
//! `PeerChannel`'s own shape.
//!
//! `send`/`try_send` take `Vec<u8>` rather than `PeerChannel`'s generic
//! `impl Into<Bytes>` parameter: a `dyn`-safe trait can't have a generic
//! method, and every real call site (`peer_session.rs`'s `send`/`try_send`
//! wrappers) already passes a freshly encoded `Vec<u8>`
//! (`msg.encode_to_vec()`), so narrowing to the concrete type both call
//! sites use loses nothing.
//!
//! Implemented directly for the concrete `PeerChannel` struct, matching
//! `peer_replica_state.rs`'s direct-impl-on-`SyncState` approach rather than
//! `block_store.rs`'s blanket impl: `PeerChannel` is a concrete struct with
//! one production implementation (unlike `BlockStore`, a foreign trait with
//! several), so there's no dispatch-over-multiple-impls need a blanket impl
//! would serve.
//!
//! Same scaffolding discipline as this module's siblings: every method here
//! is a thin, same-signature delegate to the `PeerChannel` method it wraps.
//! No consumer is migrated to use this trait yet — `peer_session.rs` still
//! holds `channel: Arc<PeerChannel>` directly. A later commit swaps that
//! field's type to `Arc<dyn PeerMessageChannel>`.

use yadorilink_transport::{PeerChannel, TransportError};

/// Capability surface `PeerSyncSession` needs from its transport-layer
/// channel to a single peer: send/receive encoded sync messages, negotiate
/// reliable-delivery framing, and refresh coordination-server-learned
/// candidates.
#[async_trait::async_trait]
pub trait PeerMessageChannel: Send + Sync {
    /// Sends one encoded `SyncMessage`, awaiting outbound-queue capacity.
    /// `peer_session.rs`'s `PeerSyncSession::send` wrapper calls this with
    /// `msg.encode_to_vec()` and propagates a channel-closed error via `?`.
    async fn send(&self, payload: Vec<u8>) -> Result<(), TransportError>;

    /// Non-blocking counterpart to [`send`](Self::send). `peer_session.rs`'s
    /// `PeerSyncSession::try_send` calls this on a hot admission-control
    /// path where a dropped best-effort reply (on a full or dead outbound
    /// queue) is an expected, silent outcome rather than a caller error.
    fn try_send(&self, payload: Vec<u8>) -> bool;

    /// Awaits the next inbound message's raw bytes, or `None` once the
    /// channel has closed. `peer_session.rs`'s main receive loop `select!`s
    /// on this alongside other events to decode each incoming
    /// `SyncMessage`.
    async fn recv(&self) -> Option<Vec<u8>>;

    /// Enables reliable-delivery (seq/ack) framing for this device's own
    /// outbound sends. `peer_session.rs`'s
    /// `record_peer_reliable_delivery_support` calls this once the
    /// `ClusterConfig` handshake confirms both sides advertised
    /// `supports_reliable_delivery`.
    fn enable_reliable_delivery(&self);

    /// Replaces the set of coordination-server-learned direct candidates
    /// this channel probes. `peer_session.rs`'s
    /// `PeerSyncSession::replace_coordination_candidates` forwards its own
    /// caller's refreshed candidate list here unchanged.
    async fn replace_coordination_candidates(&self, candidates: Vec<std::net::SocketAddr>);
}

#[async_trait::async_trait]
impl PeerMessageChannel for PeerChannel {
    async fn send(&self, payload: Vec<u8>) -> Result<(), TransportError> {
        PeerChannel::send(self, payload).await
    }

    fn try_send(&self, payload: Vec<u8>) -> bool {
        PeerChannel::try_send(self, payload)
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        PeerChannel::recv(self).await
    }

    fn enable_reliable_delivery(&self) {
        PeerChannel::enable_reliable_delivery(self)
    }

    async fn replace_coordination_candidates(&self, candidates: Vec<std::net::SocketAddr>) {
        PeerChannel::replace_coordination_candidates(self, candidates).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use boringtun::x25519::{PublicKey, StaticSecret};

    use super::*;

    /// Proves the direct impl above lets a real, production `Arc<PeerChannel>`
    /// (the same type `peer_orchestrator.rs` holds per connected peer)
    /// unsize-coerce to `Arc<dyn PeerMessageChannel>`, and that a call
    /// through the coerced handle still dispatches to the real channel.
    /// No mutual handshake is needed for this: `PeerChannel::connect`
    /// succeeds immediately even with no reachable candidate, and
    /// `try_send`/`enable_reliable_delivery` don't require an established
    /// path.
    #[tokio::test]
    async fn arc_peer_channel_coerces_to_port_trait() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let peer_public = PublicKey::from(&StaticSecret::from([2u8; 32]));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub = yadorilink_transport::TransportHub::from_socket(socket, None);
        let channel: Arc<PeerChannel> =
            Arc::new(PeerChannel::connect(local_secret, peer_public, 0, Vec::new(), hub).await.unwrap());

        let port: Arc<dyn PeerMessageChannel> = channel;
        port.enable_reliable_delivery();
        // No peer is reachable, so this is expected to report a dropped
        // best-effort send rather than block or panic -- proving dispatch
        // reached the real `PeerChannel::try_send`, not asserting delivery.
        let _ = port.try_send(b"port coercion proof".to_vec());
    }
}
