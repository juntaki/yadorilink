//! The capability surface `PeerSyncSession` (`peer_session.rs`) needs from
//! its transport: encoded-message send/receive to one peer, and block
//! streams to and from that same peer.
//!
//! `peer_session.rs` holds `Arc<dyn PeerMessageChannel>` and names no
//! concrete transport type. `QuicPeerChannel` implements this trait, and so
//! do `InMemoryPeerChannel` (this module's sibling, for simulation and
//! tests) and the daemon's inert loopback channel.
//!
//! `#[async_trait]` because `send` and `recv` are async; `try_send` is a
//! plain sync fn because it is a best-effort admission-control call that
//! must never wait.
//!
//! `send`/`try_send` take `Vec<u8>` rather than a generic `impl Into<Bytes>`:
//! a `dyn`-safe trait cannot have a generic method, and every real call site
//! already passes a freshly encoded `Vec<u8>` (`msg.encode_to_vec()`).
//!
//! ## The boundary
//!
//! - the orchestrator owns candidates, reconnection, reachability and
//!   revocation -- everything about establishing and re-establishing a path
//!   to a peer;
//! - this port owns data exchange with a peer that is already connected and
//!   authenticated, and nothing else.
//!
//! It used to carry two more methods, `enable_reliable_delivery` and
//! `replace_coordination_candidates`, because it was written by surveying
//! what the previous transport happened to expose. Both described connection
//! lifecycle rather than communication, and both went away with that
//! transport: reliability is not optional under QUIC and is not negotiated
//! mid-session, and which candidate reached a peer is settled before a
//! channel exists. Read that as a constraint on new capabilities: one that
//! belongs to connection lifecycle does not belong here.

use yadorilink_transport::{QuicBlockStream, QuicPeerChannel, TransportError};

/// Capability surface `PeerSyncSession` needs from its transport-layer
/// channel to a single peer.
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

    /// Opens a stream for one block request.
    ///
    /// This is data exchange with a connected peer, not connection
    /// lifecycle, which is why it belongs here alongside `send`/`recv`
    /// rather than with the orchestrator: nothing about it decides *which*
    /// path reached the peer, only what is said over the one that did.
    ///
    /// A transport that cannot carry block content answers
    /// `TransportError::ChannelClosed` rather than pretending to open a
    /// stream. That is a real state -- the daemon's inert loopback session
    /// is bound to no peer at all -- and a requester treats it exactly like
    /// any other failed fetch.
    async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError>;

    /// Awaits the next block stream the peer opened, or `None` once the
    /// channel has closed -- the block-serving counterpart to `recv`, and
    /// the same end-of-stream meaning.
    async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>>;
}

/// One block request's stream, from whichever side is driving it.
///
/// Deliberately narrow: two length-prefixed header messages and one raw
/// body, which is the entire block exchange. It is not a general byte-pipe
/// abstraction, because a general byte pipe would invite protocols that the
/// framing bound and the declared-length check below could not police.
#[async_trait::async_trait]
pub trait PeerBlockStream: Send {
    /// Writes one length-prefixed header message.
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError>;

    /// Reads one length-prefixed header message, refusing a declared length
    /// above `max_len` before allocating for it.
    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError>;

    /// Writes the raw body bytes and ends this direction of the stream. An
    /// empty body just ends it, which is how every non-`Found` response
    /// finishes.
    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError>;

    /// Reads exactly `len` raw body bytes, where `len` is the size the
    /// response header declared and the caller has already bounded against
    /// its own maximum block size.
    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError>;

    /// Ends this side's sending direction with nothing further to send --
    /// what the requester does immediately after its header.
    fn finish_send(&mut self);
}

#[async_trait::async_trait]
impl PeerBlockStream for QuicBlockStream {
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        QuicBlockStream::send_message(self, payload).await
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        QuicBlockStream::recv_message(self, max_len).await
    }

    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError> {
        QuicBlockStream::send_body(self, body).await
    }

    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError> {
        QuicBlockStream::recv_body(self, len).await
    }

    fn finish_send(&mut self) {
        QuicBlockStream::finish_send(self)
    }
}

/// The QUIC control stream as a session channel.
#[async_trait::async_trait]
impl PeerMessageChannel for QuicPeerChannel {
    async fn send(&self, payload: Vec<u8>) -> Result<(), TransportError> {
        QuicPeerChannel::send(self, payload).await
    }

    fn try_send(&self, payload: Vec<u8>) -> bool {
        QuicPeerChannel::try_send(self, payload)
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        QuicPeerChannel::recv(self).await
    }

    async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError> {
        Ok(Box::new(QuicPeerChannel::open_block_stream(self).await?))
    }

    async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
        let stream = QuicPeerChannel::accept_block_stream(self).await?;
        Some(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use yadorilink_transport::{
        ConnectRole, DeviceSigningKeyPair, QuicPeerEndpoint, TransportHub,
    };

    use super::*;

    /// Proves the impl above lets a real, production `Arc<QuicPeerChannel>`
    /// -- the same type the orchestrator holds per connected peer --
    /// unsize-coerce to `Arc<dyn PeerMessageChannel>`, the coercion
    /// `peer_session.rs`'s own field depends on, and that a call through the
    /// coerced handle still dispatches to the real channel.
    ///
    /// A live peer is deliberately not part of it: `try_send` is the
    /// best-effort admission-control path, so a channel with nobody at the
    /// other end reports a dropped send rather than blocking. What is being
    /// proven is dispatch, not delivery.
    #[tokio::test]
    async fn arc_quic_peer_channel_coerces_to_port_trait() {
        let dialer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let acceptor_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let acceptor_addr = acceptor_socket.local_addr().unwrap();

        let dialer_key = DeviceSigningKeyPair::generate();
        let acceptor_key = DeviceSigningKeyPair::generate();
        let dialer_public = dialer_key.public_bytes();
        let acceptor_public = acceptor_key.public_bytes();

        let dialer = QuicPeerEndpoint::new(TransportHub::from_socket(dialer_socket), dialer_key)
            .unwrap();
        let acceptor =
            QuicPeerEndpoint::new(TransportHub::from_socket(acceptor_socket), acceptor_key)
                .unwrap();
        dialer.authorize(acceptor_public);
        acceptor.authorize(dialer_public);

        let connection = dialer.connect(acceptor_addr, acceptor_public).await.unwrap();
        let channel = QuicPeerChannel::new(connection, ConnectRole::Dial);

        let port: Arc<dyn PeerMessageChannel> = channel;
        assert!(port.try_send(b"port coercion proof".to_vec()));
    }
}
