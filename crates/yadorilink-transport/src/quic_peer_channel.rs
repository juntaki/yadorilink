//! The control stream of one peer connection, as a message channel, and the
//! block streams that run alongside it.
//!
//! ## One long-lived bidirectional stream
//!
//! Everything the sync protocol *says* to a peer -- `ClusterConfig`,
//! `HeadsAnnounce`, `ChangeRequest`, `ChangeBatch`, custody, relay
//! open/data -- travels on a single bidirectional QUIC stream that lives as
//! long as the connection does. It is long-lived rather than per-exchange
//! because the protocol above is a conversation with ordering that matters
//! within it, and because a stream opened per message would pay a
//! stream-creation round of flow control for every frame while gaining
//! nothing: QUIC's independence between streams is worth having between
//! *control and bulk*, not between one control message and the next.
//!
//! ## Block streams
//!
//! Block content does not travel there. One block request is one
//! bidirectional stream of its own ([`crate::block_stream`]), so a large
//! transfer cannot head-of-line-block the conversation, needs no
//! application-level correlation id, and needs no chunking to fit inside a
//! control frame.
//!
//! That makes the stream accounting on this connection asymmetric in a way
//! worth stating plainly, because it is what the accept loop below depends
//! on. `accept_bi` only ever yields streams the *peer* opened, and the
//! dialling side is the one that opens the control stream. So on the
//! accepting side the first bidirectional stream to arrive is the control
//! stream and every one after it is a block stream; on the dialling side
//! every bidirectional stream that arrives is a block stream, because the
//! accepting side never opens a control stream at all. Both directions may
//! request blocks, so both sides run the accept loop.
//!
//! That in turn means the dialling side must open the control stream
//! *before* it opens any block stream: QUIC hands streams to the peer's
//! `accept_bi` in the order they were opened, so a block stream that got
//! ahead of the control stream would be accepted as the control stream and
//! the connection would be desynchronised from its first frame.
//! [`QuicPeerChannel::open_block_stream`] therefore waits for the control
//! stream to be settled rather than assuming the driver task below has
//! already been scheduled -- construction returns before that task has
//! necessarily run at all, and "in practice the session sends its handshake
//! first" is a property of a caller, not an invariant of this type.
//!
//! ## Framing
//!
//! A QUIC stream is a byte stream and this port is message-oriented, so the
//! boundaries have to come back: a `u32` big-endian length prefix, then that
//! many bytes of encoded protobuf. The length is checked against
//! [`MAX_CONTROL_FRAME_BYTES`] *before* any buffer is allocated, so a peer
//! cannot turn four bytes into a four-gigabyte allocation.
//!
//! There is deliberately no per-frame generation marker, unlike the local
//! IPC framing. That marker exists so a build of the wrong generation is
//! rejected before protobuf decoding, on a channel that has no handshake of
//! its own to carry the question. This one does: the protocol generation
//! rides the ALPN, so a peer of the wrong generation is refused during the
//! TLS handshake and never reaches the point of sending a frame at all.
//! Carrying the marker per message would re-answer, on every message,
//! something the connection settled once.

use std::fmt;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::block_stream::QuicBlockStream;
use crate::error::TransportError;
use crate::quic_peer_endpoint::ConnectRole;

/// The largest control frame this channel will send or accept.
///
/// No block content passes through here any more, so this no longer has to
/// clear a block-sized message; what it has to clear is the largest
/// *metadata* message the sync protocol produces, which is a bounded change
/// batch or a re-bootstrap snapshot. It is kept at 2 MiB rather than
/// tightened along with the block protocol because that is a separate
/// question with its own evidence -- the batch and snapshot bounds live in
/// the crates that produce them -- and lowering it here on the strength of
/// the block change alone would be guessing at a limit for messages this
/// change does not touch.
///
/// The number that matters is the one on the receive side: it is the bound
/// on how much memory a peer can make this device allocate by claiming a
/// length, and it is enforced before the allocation happens rather than
/// after.
pub const MAX_CONTROL_FRAME_BYTES: usize = 2 * 1024 * 1024;

/// The length prefix is a `u32`, so a ceiling above its range would be a
/// ceiling that can never be reached. Checked when the crate is built rather
/// than when the suite runs, because it is a relation between constants.
const _: () = {
    assert!(MAX_CONTROL_FRAME_BYTES <= u32::MAX as usize);
};

/// Bytes of length prefix in front of each frame.
const LENGTH_PREFIX_BYTES: usize = 4;

/// Outbound queue depth, matching the real `PeerChannel`'s own, so a caller
/// that fills this queue meets the same "how many messages may be in flight
/// before a best-effort send is dropped" boundary the transport it replaces
/// imposed, rather than one invented here.
const OUTBOUND_QUEUE_DEPTH: usize = 64;

/// Inbound queue depth. Same reasoning as the outbound side; it is what
/// stops a fast peer from turning stream flow control into unbounded local
/// buffering, by making the reader stop reading instead.
const INBOUND_QUEUE_DEPTH: usize = 64;

/// How many accepted-but-not-yet-claimed block streams this channel holds.
///
/// Small on purpose. It is a handoff, not a buffer: the real bound on how
/// many block requests a peer can have in flight against this device is
/// QUIC's own concurrent-stream limit (see the endpoint's transport config),
/// negotiated in the handshake and enforced by the peer's own stack before a
/// stream is ever opened. Queueing deeply here would only let this device
/// accept streams it is not yet serving, hiding that limit from the peer
/// rather than applying it.
const INBOUND_BLOCK_STREAM_QUEUE_DEPTH: usize = 8;

/// QUIC application error code for a peer that violated the framing above --
/// currently only by announcing a frame longer than the ceiling.
const FRAMING_VIOLATION: u32 = 2;

/// QUIC application error code for an ordinary local teardown.
const CHANNEL_CLOSED: u32 = 0;

/// QUIC application error code for a peer whose authorization this device
/// has withdrawn. Distinct from an ordinary close so the peer can tell
/// "this device is going away" from "this device will not talk to you any
/// more", and so a packet capture or a log can too.
const PEER_REVOKED: u32 = 3;

/// QUIC application error code closing a connection that a newer generation
/// to the same peer has replaced -- see
/// [`QuicPeerChannel::close_superseded`]. Distinct from [`PEER_REVOKED`] so
/// the peer can tell "you are no longer authorized" from "we are talking on
/// a different path now", which are opposite instructions about whether to
/// reconnect.
const PEER_SUPERSEDED: u32 = 4;

/// One peer's control stream, in the shape the sync session speaks.
pub struct QuicPeerChannel {
    connection: quinn::Connection,
    outbound: mpsc::Sender<Vec<u8>>,
    /// `AsyncMutex` because the port takes `&self` while
    /// `mpsc::Receiver::recv` needs `&mut`. The session drives a single
    /// receive loop, so this is never contended in practice.
    inbound: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    /// Block streams the peer has opened, waiting to be claimed by whoever
    /// serves block requests. Same `AsyncMutex` reasoning as `inbound`: one
    /// accept loop above, taking `&self`.
    inbound_block_streams: AsyncMutex<mpsc::Receiver<QuicBlockStream>>,
    /// Flips to `true` once the control stream has been settled -- opened by
    /// the dialling side, accepted by the other. `open_block_stream` waits on
    /// it so no block stream can be opened ahead of the control stream; see
    /// this module's own doc comment for what that would do to the peer's
    /// accept loop. `watch` rather than a flag plus a `Notify` because the
    /// state is what matters, not the edge: a waiter that arrives after the
    /// transition must proceed immediately rather than wait for a
    /// notification that has already happened.
    control_stream_ready: tokio::sync::watch::Receiver<bool>,
    driver: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for QuicPeerChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicPeerChannel")
            .field("remote", &self.connection.remote_address())
            .finish()
    }
}

impl Drop for QuicPeerChannel {
    fn drop(&mut self) {
        // Both halves, because either alone leaves something running. The
        // driver task holds the stream and would otherwise keep polling a
        // connection nobody reads from; the connection would otherwise stay
        // open until its idle timeout, leaving the peer to wait out a
        // session that has already ended here rather than learning about it
        // now.
        self.driver.abort();
        self.connection.close(CHANNEL_CLOSED.into(), b"peer channel closed");
    }
}

impl QuicPeerChannel {
    /// Wraps `connection`'s control stream.
    ///
    /// `role` decides which side opens that stream, and it is the same role
    /// that decided which side dialled -- see
    /// [`connect_role`](crate::quic_peer_endpoint::connect_role). Reusing it
    /// rather than deciding again means there is one rule in the system for
    /// who initiates, not two that could disagree.
    ///
    /// Returns without waiting for the stream. It has to: a QUIC stream does
    /// not exist for the peer until bytes are written to it, so the
    /// accepting side cannot observe one until the opening side sends its
    /// first message -- and if construction blocked on that, the accepting
    /// side could not construct the session that would produce its own first
    /// message. Queueing instead lets both sides be built immediately and
    /// lets the first frames cross in either order.
    pub fn new(connection: quinn::Connection, role: ConnectRole) -> Arc<Self> {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let (block_tx, block_rx) = mpsc::channel(INBOUND_BLOCK_STREAM_QUEUE_DEPTH);
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let driver = tokio::spawn(drive_connection(
            connection.clone(),
            role,
            outbound_rx,
            inbound_tx,
            block_tx,
            ready_tx,
        ));
        Arc::new(Self {
            connection,
            outbound: outbound_tx,
            inbound: AsyncMutex::new(inbound_rx),
            inbound_block_streams: AsyncMutex::new(block_rx),
            control_stream_ready: ready_rx,
            driver,
        })
    }

    /// Sends one encoded message, awaiting outbound-queue capacity.
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), TransportError> {
        if payload.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(TransportError::MessageTooLarge(payload.len(), MAX_CONTROL_FRAME_BYTES));
        }
        self.outbound.send(payload).await.map_err(|_| TransportError::ChannelClosed)
    }

    /// Best-effort counterpart to [`send`](Self::send): never blocks, and
    /// reports a dropped message rather than waiting for room.
    pub fn try_send(&self, payload: Vec<u8>) -> bool {
        if payload.len() > MAX_CONTROL_FRAME_BYTES {
            return false;
        }
        // A full queue and a dead channel report the same dropped-send
        // outcome, matching the transport this replaces: the caller is on an
        // admission-control path with no different response to make.
        self.outbound.try_send(payload).is_ok()
    }

    /// The next inbound message, or `None` once the connection has closed.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.inbound.lock().await.recv().await
    }

    /// Opens a bidirectional stream for one block request.
    ///
    /// Awaits twice, for two different reasons. First until the control
    /// stream is settled, so this stream cannot overtake it in the order the
    /// peer accepts them (see this module's doc comment). Then, inside
    /// `open_bi`, whenever the peer's concurrent-stream limit is already
    /// reached -- which is the backpressure that used to be an
    /// application-level in-flight window: a requester cannot get ahead of
    /// what the responder has agreed to work on at once.
    pub async fn open_block_stream(&self) -> Result<QuicBlockStream, TransportError> {
        let mut ready = self.control_stream_ready.clone();
        while !*ready.borrow_and_update() {
            // The sender is dropped when the driver task returns, which is
            // how a connection that ended before its control stream was ever
            // established reports itself: there will be no block streams on
            // it either.
            if ready.changed().await.is_err() {
                return Err(TransportError::ChannelClosed);
            }
        }
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        Ok(QuicBlockStream::new(send, recv))
    }

    /// The next block stream the peer has opened, or `None` once the
    /// connection has closed.
    ///
    /// `None` here means the same thing it means for [`recv`](Self::recv):
    /// this session is over. A caller looping on it ends when the loop ends,
    /// rather than needing a separate liveness check.
    pub async fn accept_block_stream(&self) -> Option<QuicBlockStream> {
        self.inbound_block_streams.lock().await.recv().await
    }

    /// The peer's current address, for diagnostics. QUIC may migrate a
    /// connection to a new path, so this is a snapshot rather than an
    /// identity -- identity is the key that authenticated the handshake.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    /// Whether the underlying connection is still usable.
    ///
    /// This is the QUIC replacement for a reachability state machine, and
    /// it is deliberately binary. A connection either exists -- having
    /// completed a mutually authenticated handshake -- or it has closed;
    /// there is no "authenticated but not yet confirmed" middle state to
    /// represent, because under QUIC the handshake *is* the confirmation.
    /// Read live from the connection rather than from a mirror kept
    /// elsewhere, so a caller that has to decide something safety-relevant
    /// (the relay layer refusing to chain through a route that has just
    /// gone) never reads a value that lags the truth.
    pub fn is_open(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Ends this connection because the peer's authorization has been
    /// withdrawn.
    ///
    /// Withdrawing a key from the endpoint's authorized set only refuses
    /// *future* handshakes; it says nothing to a connection that is already
    /// established, which would otherwise go on carrying a revoked device's
    /// traffic until it idled out. Revocation is therefore two actions, and
    /// this is the second: the first refuses the peer's next handshake,
    /// this one ends the session it already has.
    ///
    /// Ordering matters. Withdraw first, then close -- the other way round
    /// leaves a window in which the peer, seeing its connection drop,
    /// reconnects and is accepted, which is precisely the state revocation
    /// exists to prevent.
    ///
    /// Idempotent, and safe to call on a connection that has already gone:
    /// quinn ignores a close on a connection that is no longer live.
    pub fn close_revoked(&self) {
        self.driver.abort();
        self.connection.close(PEER_REVOKED.into(), b"peer authorization withdrawn");
    }

    /// Ends this connection because a newer generation to the same peer has
    /// taken over -- a direct path replacing a relayed one, or the reverse.
    ///
    /// Closing explicitly, rather than letting the last `Arc` drop do it, is
    /// what makes a generation replacement a replacement rather than a
    /// second connection: the superseded connection can still be reachable
    /// from the peer registry for a moment after the new one is published,
    /// and two live connections to one peer is precisely the state the
    /// connect-role rule exists to prevent. It also tells the peer at once,
    /// so it re-accepts on the new path instead of waiting out an idle
    /// timeout on a connection this device will never read again.
    ///
    /// Idempotent, and safe on a connection that has already gone.
    pub fn close_superseded(&self) {
        self.driver.abort();
        self.connection.close(PEER_SUPERSEDED.into(), b"superseded by a newer path");
    }
}

/// Establishes the control stream, starts accepting block streams, then
/// runs both directions of the control stream until either ends.
async fn drive_connection(
    connection: quinn::Connection,
    role: ConnectRole,
    outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    block_streams: mpsc::Sender<QuicBlockStream>,
    control_stream_ready: tokio::sync::watch::Sender<bool>,
) {
    let stream = match role {
        ConnectRole::Dial => connection.open_bi().await,
        ConnectRole::Accept => connection.accept_bi().await,
    };
    let (send, recv) = match stream {
        Ok(stream) => stream,
        Err(error) => {
            // Dropping `inbound` on the way out is what reports this: the
            // session's `recv` returns `None`, it ends, and its supervisor
            // reconnects. There is no half-open state to represent.
            tracing::debug!(%error, ?role, "peer control stream could not be established");
            return;
        }
    };
    // Both halves of the ordering rule are released here, and only here.
    // Block streams may now be opened (this side's control stream has a
    // stream id, so nothing can precede it), and may now be accepted (on the
    // accepting side the control stream was itself the first one to arrive,
    // and an accept loop running earlier would have claimed it).
    let _ = control_stream_ready.send(true);
    // Only now, with the control stream settled, can the accept loop start:
    // on the accepting side the control stream is itself the first
    // bidirectional stream to arrive, and an accept loop running before this
    // point would claim it and hand it out as a block stream. Starting it
    // here rather than at construction is what makes "every bidirectional
    // stream from here on is a block stream" true for both roles.
    let acceptor = tokio::spawn(accept_block_streams(connection.clone(), block_streams));
    // Whichever direction ends first ends the connection. There is exactly
    // one control stream, so a connection that has lost a direction has no
    // useful state left: the peer either cannot hear this device or cannot be
    // heard by it, and either way the conversation above is desynchronised.
    // Waiting for both to end instead would leave a half-broken connection
    // that still reads -- alive enough to hold the peer's session open, and
    // unable to answer anything on it.
    //
    // Closing here is what surfaces it: the session's `recv` returns `None`,
    // it ends, and its supervisor reconnects.
    tokio::select! {
        _ = write_frames(send, outbound) => {}
        _ = read_frames(recv, inbound, connection.clone()) => {}
    }
    // Explicit rather than relying on the handle's drop, which detaches
    // rather than cancels. The other way this task ends is the connection
    // closing under it -- `Drop` and `close_revoked` both do that, and
    // `accept_bi` on a closed connection returns immediately -- so it has no
    // path that outlives the channel either way.
    acceptor.abort();
    connection.close(CHANNEL_CLOSED.into(), b"peer control stream ended");
}

/// Hands every bidirectional stream the peer opens to whoever is serving
/// block requests, until the connection ends.
async fn accept_block_streams(
    connection: quinn::Connection,
    block_streams: mpsc::Sender<QuicBlockStream>,
) {
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(error) => {
                // Includes the ordinary end of the connection, so this is
                // `debug`: a closed connection is how a session normally
                // ends.
                tracing::debug!(%error, "peer stopped opening block streams");
                return;
            }
        };
        // Awaiting capacity rather than dropping. Accepting a stream this
        // device is not ready to serve and then dropping it would report a
        // reset to a peer that did nothing wrong; leaving it unaccepted
        // instead holds the peer at QUIC's own concurrent-stream limit,
        // which is the bound it already agreed to.
        if block_streams.send(QuicBlockStream::new(send, recv)).await.is_err() {
            // Nobody is serving block requests on this connection any more.
            return;
        }
    }
}

/// Length-prefixes each queued message onto the stream.
async fn write_frames(mut send: quinn::SendStream, mut outbound: mpsc::Receiver<Vec<u8>>) {
    while let Some(payload) = outbound.recv().await {
        // `send`/`try_send` already refused anything over the ceiling, so
        // this cannot truncate; the conversion is written fallibly anyway
        // rather than as a cast, because a cast is what would make a future
        // second producer's mistake silent.
        let Ok(length) = u32::try_from(payload.len()) else {
            tracing::error!(len = payload.len(), "refusing to frame an oversized control message");
            continue;
        };
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        // One write for prefix and body together: two writes could
        // interleave with nothing, but they would let a frame's header
        // reach the peer arbitrarily long before its body, which is exactly
        // the state a reader has to hold an allocation open across.
        if let Err(error) = send.write_all(&frame).await {
            tracing::debug!(%error, "peer control stream write failed");
            break;
        }
    }
    // `finish` only announces the end of this direction; it does not wait,
    // and a failure means the stream was already gone, which is what the
    // loop above just concluded.
    let _ = send.finish();
}

/// Reads length-prefixed frames off the stream until it ends or the peer
/// breaks the framing.
async fn read_frames(
    mut recv: quinn::RecvStream,
    inbound: mpsc::Sender<Vec<u8>>,
    connection: quinn::Connection,
) {
    loop {
        let mut length = [0u8; LENGTH_PREFIX_BYTES];
        if let Err(error) = recv.read_exact(&mut length).await {
            // Includes the ordinary end of the stream, so this is `debug`
            // rather than a warning: a closed connection is how a session
            // normally ends.
            tracing::debug!(%error, "peer control stream ended");
            break;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_CONTROL_FRAME_BYTES {
            // Refused before allocating, which is the whole point of
            // checking here rather than after a read: the peer has so far
            // sent four bytes, and must not be able to turn them into an
            // arbitrary allocation. Closing the connection rather than
            // skipping the frame is right because a stream is a byte
            // stream -- there is no resynchronisation point to skip to, so
            // everything after this length is unparseable anyway.
            tracing::warn!(
                declared = length,
                max = MAX_CONTROL_FRAME_BYTES,
                "peer announced an oversized control frame; closing the connection"
            );
            connection.close(FRAMING_VIOLATION.into(), b"control frame exceeds the maximum length");
            break;
        }
        let mut payload = vec![0u8; length];
        if let Err(error) = recv.read_exact(&mut payload).await {
            tracing::debug!(%error, "peer control stream ended mid-frame");
            break;
        }
        // Awaiting capacity rather than dropping: this is the reliable
        // direction of a reliable transport, and a dropped control message
        // is a desynchronised session. Back-pressure propagates into QUIC's
        // own stream flow control, which is where the peer should feel it.
        if inbound.send(payload).await.is_err() {
            // The channel was dropped, so nothing will read this stream
            // again.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing is a pure function of the payload, and the two halves
    /// have to be exact inverses -- one runs on what this device emits, the
    /// other on what it accepts from a peer.
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }

    #[test]
    fn a_length_prefix_is_big_endian_and_four_bytes() {
        assert_eq!(frame(b"abc")[..LENGTH_PREFIX_BYTES], [0, 0, 0, 3]);
        assert_eq!(frame(&[0u8; 300])[..LENGTH_PREFIX_BYTES], [0, 0, 1, 44]);
    }
}
