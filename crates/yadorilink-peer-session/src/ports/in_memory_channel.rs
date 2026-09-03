//! A [`PeerMessageChannel`] pair that carries messages in memory, for
//! deterministic simulation and for tests that want two real
//! `PeerSyncSession`s talking to each other with no socket in between.
//!
//! This exists because the port is about to become the only thing the
//! session knows about its transport. A second, genuinely independent
//! implementation is what proves that: as long as `PeerChannel` is the only
//! implementor, "the session depends on the port, not the transport" is a
//! claim about naming rather than about the dependency graph. Simulation
//! builds need it for a concrete reason too -- deterministic runs cannot use
//! the real transport, and whatever replaces the real transport will not be
//! usable under simulation either, so the protocol and convergence logic
//! need a transport they can be tested against on their own.
//!
//! Deliberately free of timers, wall-clock reads and randomness: everything
//! here is a bounded queue and a message copy, so a simulated run that uses
//! it is reproducible from its seed alone.

use std::sync::Arc;

use tokio::io::DuplexStream;
use tokio::sync::{mpsc, Mutex};
use yadorilink_transport::block_stream::{read_length_prefixed, write_length_prefixed};
use yadorilink_transport::TransportError;

use super::{PeerBlockStream, PeerMessageChannel};

/// Matches the real `PeerChannel`'s own outbound queue capacity, so a test
/// that fills this queue is exercising the same "how many messages can be
/// in flight before a best-effort send is dropped" boundary the production
/// channel imposes, rather than a boundary invented here.
const QUEUE_DEPTH: usize = 64;

/// Buffer capacity of one in-memory block stream's byte pipe.
///
/// A real QUIC stream has flow control, so a writer that gets ahead of its
/// reader eventually blocks; a pipe with a bound reproduces that, and one
/// without would let a test pass that a real stream would deadlock on. The
/// value only has to be small relative to a block and large relative to a
/// header, so the two directions of the exchange each exercise the blocking
/// path at least once for any block worth transferring.
const BLOCK_STREAM_PIPE_BYTES: usize = 64 * 1024;

/// One end of an in-memory link. Obtain a connected pair from
/// [`InMemoryPeerChannel::connected_pair`].
pub struct InMemoryPeerChannel {
    /// The *peer's* inbox. Dropping the far end closes this, which is what
    /// makes a disconnect observable without any timeout.
    outbound: mpsc::Sender<Vec<u8>>,
    /// This end's own inbox. `Mutex` because the port takes `&self` while
    /// `mpsc::Receiver::recv` needs `&mut` -- the session drives a single
    /// receive loop, so this is never contended in practice.
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// The *peer's* queue of block streams this end has opened, and this
    /// end's own queue of streams the peer opened. Same shape and same
    /// reasoning as the message queues above; opening a stream is a
    /// handoff, and the pipe underneath it is what carries the bytes.
    outbound_block_streams: mpsc::Sender<InMemoryBlockStream>,
    inbound_block_streams: Mutex<mpsc::Receiver<InMemoryBlockStream>>,
}

impl InMemoryPeerChannel {
    /// Two ends of one link: what `a` sends, `b` receives, and vice versa.
    pub fn connected_pair() -> (Arc<Self>, Arc<Self>) {
        let (a_tx, a_rx) = mpsc::channel(QUEUE_DEPTH);
        let (b_tx, b_rx) = mpsc::channel(QUEUE_DEPTH);
        let (a_streams_tx, a_streams_rx) = mpsc::channel(QUEUE_DEPTH);
        let (b_streams_tx, b_streams_rx) = mpsc::channel(QUEUE_DEPTH);
        (
            Arc::new(Self {
                outbound: b_tx,
                inbound: Mutex::new(a_rx),
                outbound_block_streams: b_streams_tx,
                inbound_block_streams: Mutex::new(a_streams_rx),
            }),
            Arc::new(Self {
                outbound: a_tx,
                inbound: Mutex::new(b_rx),
                outbound_block_streams: a_streams_tx,
                inbound_block_streams: Mutex::new(b_streams_rx),
            }),
        )
    }
}

/// One in-memory block stream: a byte pipe, framed exactly the way the QUIC
/// one is.
///
/// It reuses the transport's own framing functions rather than
/// reimplementing them, which is the point of having them shared: a test
/// double whose framing has drifted from the wire's proves nothing about
/// the protocol it is standing in for. What it does not reproduce is QUIC's
/// reset-on-drop, so an abandoned stream here reads as a clean end rather
/// than an error -- the exchange treats both as a failed fetch.
pub struct InMemoryBlockStream {
    pipe: DuplexStream,
}

#[async_trait::async_trait]
impl PeerBlockStream for InMemoryBlockStream {
    async fn send_message(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        write_length_prefixed(&mut self.pipe, payload).await
    }

    async fn recv_message(&mut self, max_len: usize) -> Result<Vec<u8>, TransportError> {
        read_length_prefixed(&mut self.pipe, max_len).await
    }

    async fn send_body(&mut self, body: &[u8]) -> Result<(), TransportError> {
        use tokio::io::AsyncWriteExt as _;
        if !body.is_empty() {
            self.pipe.write_all(body).await.map_err(TransportError::Io)?;
        }
        self.pipe.shutdown().await.map_err(TransportError::Io)
    }

    async fn recv_body(&mut self, len: usize) -> Result<Vec<u8>, TransportError> {
        use tokio::io::AsyncReadExt as _;
        let mut body = vec![0u8; len];
        if len > 0 {
            self.pipe.read_exact(&mut body).await.map_err(TransportError::Io)?;
        }
        // Same end-of-stream check the real stream makes, for the same
        // reason: the declared size has to be binding, not advisory.
        let mut extra = [0u8; 1];
        match self.pipe.read(&mut extra).await {
            Ok(0) => Ok(body),
            Ok(_) => Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer sent more body bytes than its response header declared",
            ))),
            Err(error) => Err(TransportError::Io(error)),
        }
    }

    fn finish_send(&mut self) {
        // A `DuplexStream` is one object for both directions, so shutting
        // the write half here would close the read half the requester still
        // needs. The FIN this stands in for is an optimization on the wire,
        // not something either side's correctness depends on, so the double
        // does nothing rather than doing something destructive.
    }
}

#[async_trait::async_trait]
impl PeerMessageChannel for InMemoryPeerChannel {
    async fn send(&self, payload: Vec<u8>) -> Result<(), TransportError> {
        self.outbound.send(payload).await.map_err(|_| TransportError::ChannelClosed)
    }

    fn try_send(&self, payload: Vec<u8>) -> bool {
        // Both "queue full" and "peer gone" report the same dropped-send
        // outcome the real channel reports, rather than distinguishing
        // them: the caller is on a best-effort admission-control path that
        // has no different response to make.
        self.outbound.try_send(payload).is_ok()
    }

    async fn recv(&self) -> Option<Vec<u8>> {
        self.inbound.lock().await.recv().await
    }

    async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError> {
        let (near, far) = tokio::io::duplex(BLOCK_STREAM_PIPE_BYTES);
        self.outbound_block_streams
            .send(InMemoryBlockStream { pipe: far })
            .await
            .map_err(|_| TransportError::ChannelClosed)?;
        Ok(Box::new(InMemoryBlockStream { pipe: near }))
    }

    async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
        let stream = self.inbound_block_streams.lock().await.recv().await?;
        Some(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_message_sent_from_either_end_arrives_at_the_other() {
        let (a, b) = InMemoryPeerChannel::connected_pair();

        a.send(b"from a".to_vec()).await.unwrap();
        b.send(b"from b".to_vec()).await.unwrap();

        assert_eq!(b.recv().await.as_deref(), Some(&b"from a"[..]));
        assert_eq!(a.recv().await.as_deref(), Some(&b"from b"[..]));
    }

    /// Ordering matters to the session: it decodes a stream of frames whose
    /// meaning depends on the order they arrived in.
    #[tokio::test]
    async fn messages_arrive_in_send_order() {
        let (a, b) = InMemoryPeerChannel::connected_pair();
        for i in 0..8u8 {
            a.send(vec![i]).await.unwrap();
        }
        for i in 0..8u8 {
            assert_eq!(b.recv().await, Some(vec![i]));
        }
    }

    /// A closed link has to be observable as an end-of-stream rather than
    /// as a hang, since the session's receive loop treats `None` as "this
    /// session is over" and has no timeout of its own to fall back on.
    #[tokio::test]
    async fn recv_reports_end_of_stream_once_the_far_end_is_gone() {
        let (a, b) = InMemoryPeerChannel::connected_pair();
        a.send(b"last".to_vec()).await.unwrap();
        drop(a);

        // Anything already queued is still delivered first -- a disconnect
        // must not lose messages the peer had already accepted.
        assert_eq!(b.recv().await.as_deref(), Some(&b"last"[..]));
        assert_eq!(b.recv().await, None);
    }

    #[tokio::test]
    async fn send_reports_channel_closed_once_the_far_end_is_gone() {
        let (a, b) = InMemoryPeerChannel::connected_pair();
        drop(b);
        assert!(matches!(
            a.send(b"nobody home".to_vec()).await,
            Err(TransportError::ChannelClosed)
        ));
    }

    /// `try_send` is the session's best-effort admission-control path, and
    /// its whole contract is that it drops rather than blocks. Filling the
    /// queue exactly is deterministic -- no timing assumption.
    #[tokio::test]
    async fn try_send_drops_once_the_queue_is_full() {
        let (a, _b) = InMemoryPeerChannel::connected_pair();
        for i in 0..QUEUE_DEPTH {
            assert!(a.try_send(vec![i as u8]), "queue should accept message {i}");
        }
        assert!(!a.try_send(b"one too many".to_vec()));
    }

    #[tokio::test]
    async fn try_send_drops_once_the_far_end_is_gone() {
        let (a, b) = InMemoryPeerChannel::connected_pair();
        drop(b);
        assert!(!a.try_send(b"nobody home".to_vec()));
    }

    /// The point of the type: a session holding `Arc<dyn PeerMessageChannel>`
    /// can be handed one of these instead of a real transport.
    #[tokio::test]
    async fn coerces_to_the_port_trait_and_dispatches_through_it() {
        let (a, b) = InMemoryPeerChannel::connected_pair();
        let a: Arc<dyn PeerMessageChannel> = a;
        let b: Arc<dyn PeerMessageChannel> = b;

        a.send(b"through the port".to_vec()).await.unwrap();
        assert_eq!(b.recv().await.as_deref(), Some(&b"through the port"[..]));
    }
}
