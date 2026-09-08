//! This device's one QUIC endpoint, and the rule deciding which side of a
//! peer pair dials it.
//!
//! ## One endpoint per device, one connection per peer
//!
//! A `quinn::Endpoint` is not a connection: it is the demultiplexer that
//! owns a UDP binding and routes datagrams to connections by their QUIC
//! connection ID. There is exactly one UDP binding on a device -- the
//! transport hub's, shared with STUN and the relay envelope, because a
//! STUN-reflexive or port-mapped candidate is only meaningful when it names
//! the exact socket data flows on. So there is exactly one endpoint, and
//! quinn's own connection-ID routing separates peers inside it.
//!
//! Below that, one `Connection` per peer, carrying every stream to that
//! peer. Splitting control and bulk over two connections would duplicate the
//! TLS handshake, the NAT path state, the keepalive and the congestion
//! controller for one device pair -- exactly the doubling this transport
//! consolidation exists to remove -- while QUIC already gives streams
//! head-of-line independence from each other within a single connection.
//!
//! ## Why the endpoint has to hold the authorized set, not a copy of it
//!
//! The server half of a QUIC configuration is fixed when the endpoint is
//! built; netmap authorization is not. [`AuthorizedPeerKeys`] is the shared,
//! updatable set that resolves that mismatch, and this type owns the one
//! belonging to this device -- so `authorize`/`revoke` here take effect on
//! the next handshake without the endpoint, or anyone else's live connection
//! through it, being disturbed.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::error::TransportError;
use crate::keys::DeviceSigningKeyPair;
use crate::quic_identity::{
    ed25519_key_from_spki, quic_client_config, quic_dual_server_config, quic_send_client_config,
    AuthorizedPeerKeys, PEER_SERVER_NAME, YADORILINK_SEND_ALPN,
};
use crate::quic_socket::{HubQuinnRuntime, TransportHubQuicSocket};
use crate::transport_hub::TransportHub;

/// How long a connection may sit with no traffic before QUIC declares the
/// peer gone, in milliseconds. quinn's own default (RFC 9308 s 3.2),
/// restated here because the keepalive below only makes sense next to it.
const PEER_IDLE_TIMEOUT_MS: u32 = 30_000;

/// [`PEER_IDLE_TIMEOUT_MS`] as a `Duration`, for callers above the transport
/// that need to size their own budgets against it.
///
/// It is the transport's real worst case for "the peer stopped answering and
/// nobody has noticed yet", so an application-level per-request timeout
/// shorter than this gives up on a request the transport is still recovering.
/// Exported as a derived relation rather than restated as a number, so the
/// two cannot drift apart.
pub const PEER_IDLE_TIMEOUT: Duration = Duration::from_millis(PEER_IDLE_TIMEOUT_MS as u64);

/// How often an otherwise-silent connection sends a keepalive.
///
/// Without one, a control connection with nothing to say -- two devices
/// already converged -- would be torn down by the idle timeout and have to
/// re-handshake on the next change, and any NAT mapping holding the path
/// open would expire with it. Comfortably below [`PEER_IDLE_TIMEOUT_MS`] so
/// several keepalives can be lost before the timeout is reached, which is
/// what distinguishes "quiet" from "gone".
const PEER_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// How many not-yet-claimed inbound connections are held per peer.
///
/// A peer that reconnects while its previous connection is still being torn
/// down is ordinary, so this cannot be one. It must be small and bounded,
/// though: every queued connection is an authenticated peer's live QUIC
/// state, and an authorized-but-misbehaving peer that reconnects in a loop
/// must not be able to make this device hold an unbounded number of them.
const INBOUND_CONNECTION_QUEUE_DEPTH: usize = 4;

/// How many not-yet-claimed Track Send connections this device holds at
/// once, across every peer -- unlike `INBOUND_CONNECTION_QUEUE_DEPTH`
/// above, this is one shared queue rather than one per peer (see
/// `QuicPeerEndpoint::inbound_send`'s own doc comment for why), so it is
/// sized for "several sends arrived before the daemon's dispatcher task
/// got to them", not for one misbehaving peer alone. Still small and
/// bounded for the identical reason: an authenticated connection sitting
/// in this queue is live QUIC state, and an authorized peer that opens
/// send connections in a loop must not be able to make this device hold
/// an unbounded number of them.
const INBOUND_SEND_QUEUE_DEPTH: usize = 8;

/// QUIC application error code closing a connection this device has no
/// intention of using. Named rather than a bare literal so every place that
/// closes one agrees.
const CONNECTION_NOT_WANTED: u32 = 1;

/// A completed inbound handshake queued for Track Send: the live connection,
/// paired with the peer's authenticated Ed25519 public key (see
/// `QuicPeerEndpoint::inbound_send`'s own doc comment for the queue this
/// feeds).
type PendingInboundConnection = (quinn::Connection, [u8; 32]);

/// The receiving half of Track Send's inbound-connection queue.
type InboundConnectionReceiver = mpsc::Receiver<PendingInboundConnection>;

/// The sending half of Track Send's inbound-connection queue, held by the
/// accept loop that feeds [`InboundConnectionReceiver`].
type InboundConnectionSender = mpsc::Sender<PendingInboundConnection>;

/// Written by the dialler on the one connection it has selected, and
/// required by the acceptor before it will hand a connection to a session.
///
/// ## Why a connection needs to say it was chosen
///
/// Racing candidates means several connections to one peer can complete.
/// The dialler picks the one whose handshake finished first **on its side**;
/// the acceptor would otherwise take whichever finished first **on its
/// side**, and nothing makes those two orders agree. Client-to-server and
/// server-to-client latency are independent, so a candidate that completes
/// first for the dialler can complete second for the acceptor -- and then
/// each end runs its session on a different connection, which is precisely
/// the split the connect-role rule exists to prevent, reintroduced
/// underneath it.
///
/// Closing the losers does not settle it either. That is a race, not an
/// invariant: the acceptor can claim a loser in the window before the close
/// arrives. So selection is stated rather than inferred -- exactly one
/// connection carries this, the dialler decides which, and the acceptor
/// obeys.
///
/// It rides a *unidirectional* stream deliberately. Bidirectional streams
/// already mean something on this connection (the control stream, then
/// block streams), and the accepting side's own stream bookkeeping depends
/// on the control stream being the first bidirectional one to arrive.
const SELECTION_PREFACE: [u8; 8] = *b"YL-SEL-1";

/// How long the acceptor waits for a queued connection to declare itself
/// selected before discarding it.
///
/// A connection that has just completed a handshake is one round trip away
/// from its dialler, so this is generous rather than tight. It is bounded
/// because it is otherwise a way to make this device wait: a peer that
/// opens connections and never selects any of them would hold the per-peer
/// accept for as long as this allows. In the ordinary case nothing waits at
/// all -- a losing connection is closed by its own dialler, and a closed
/// connection fails this immediately rather than timing out.
const SELECTION_TIMEOUT: Duration = Duration::from_secs(3);

/// How long [`QuicPeerEndpoint::connect_racing`] waits before starting the
/// next candidate.
///
/// Long enough that a candidate which is going to work has normally already
/// answered -- a handshake over a LAN or loopback path completes in
/// single-digit milliseconds -- so the common case creates exactly one
/// connection and the race costs nothing. Short enough that a dead first
/// candidate does not meaningfully delay a working second one, which is the
/// entire point: the alternative is waiting a full handshake timeout to
/// find that out.
const CANDIDATE_STAGGER: Duration = Duration::from_millis(250);

/// The most candidate addresses one dial will race.
///
/// The netmap decides how many endpoints a peer advertises, and this device
/// does not get to assume that number is small. Each raced candidate is a
/// concurrent handshake holding its own crypto state, so the count has to
/// be bounded here rather than trusted from the wire. Comfortably above what
/// a real device advertises (its LAN interfaces, a reflexive address, a
/// port-mapped one).
const MAX_RACED_CANDIDATES: usize = 8;

/// The longest [`QuicPeerEndpoint::connect_racing`] can take to conclude
/// that no candidate answered.
///
/// The last candidate starts one stagger interval per predecessor after the
/// first, and a candidate nothing answers on costs a full handshake timeout
/// from its own start. Exported as a derived relation rather than left for a
/// caller to re-derive: a supervisor that bounds a connection attempt has to
/// allow at least this, or its own clock ends every attempt before the
/// transport has finished trying -- and the parts of the attempt that come
/// after the race are then unreachable rather than merely late. Raising
/// `MAX_RACED_CANDIDATES` or the stagger moves this automatically, which a
/// literal on the caller's side would not.
pub const RACED_DIAL_WORST_CASE: Duration = Duration::from_millis(
    PEER_IDLE_TIMEOUT.as_millis() as u64
        + CANDIDATE_STAGGER.as_millis() as u64 * (MAX_RACED_CANDIDATES as u64 - 1),
);

/// Cancels the dials still running when a race ends, however it ends.
///
/// `JoinHandle`'s own `Drop` detaches rather than cancels, so a race whose
/// future is dropped -- a caller that stopped waiting because a connection
/// arrived from the other direction, or a supervisor being torn down --
/// would otherwise leave dials running with nobody to receive, close, or
/// even observe what they produced.
struct AbortRemainingDials(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortRemainingDials {
    fn drop(&mut self) {
        for dial in &self.0 {
            dial.abort();
        }
    }
}

/// Which side of a peer pair opens the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectRole {
    /// This device dials the peer.
    Dial,
    /// This device waits for the peer to dial it.
    Accept,
}

/// Decides, from the two device ids alone, which side dials.
///
/// Both devices in a pair know the other's key and address, so both *could*
/// dial, and if both do the result is two connections where the protocol
/// wants one -- each side ending up with a session on a different one,
/// neither able to see the other's messages. QUIC has no simultaneous-open
/// resolution to fall back on: unlike TCP, two dials are simply two
/// connections.
///
/// So the pair needs a rule, and the rule has to be decidable by each side
/// on its own, from information both already have, with no negotiation
/// round-trip that could itself race. Lexicographic order on the device id
/// is exactly that: total, agreed on by both sides without asking, and --
/// because it depends on nothing timing-related -- identical on every replay
/// of a simulated run at a given seed.
///
/// Equal ids mean a device has been told to connect to itself, which is a
/// misconfiguration rather than a topology. It resolves to [`Accept`], so
/// the mistake shows up as a connection that never arrives rather than as a
/// device dialling its own socket.
///
/// [`Accept`]: ConnectRole::Accept
pub fn connect_role(local_device_id: &str, peer_device_id: &str) -> ConnectRole {
    if local_device_id < peer_device_id {
        ConnectRole::Dial
    } else {
        ConnectRole::Accept
    }
}

/// Inbound connections that have completed the handshake, waiting to be
/// claimed by whichever session is responsible for that peer.
///
/// Kept separate from [`QuicPeerEndpoint`] so the accept loop can hold it
/// without holding the endpoint itself alive.
#[derive(Default)]
struct InboundConnections {
    /// Peer public key -> that peer's queue. Created lazily by whichever of
    /// the accept loop and [`QuicPeerEndpoint::accept`] gets there first.
    by_peer: StdMutex<HashMap<[u8; 32], PeerInbox>>,
}

struct PeerInbox {
    tx: mpsc::Sender<quinn::Connection>,
    /// `AsyncMutex` because the receiver needs `&mut` while `accept` takes
    /// `&self`. One session task per peer means it is uncontended; the mutex
    /// is what makes a second caller wait rather than steal.
    rx: Arc<AsyncMutex<mpsc::Receiver<quinn::Connection>>>,
}

impl InboundConnections {
    fn inbox(
        &self,
        peer: [u8; 32],
    ) -> (mpsc::Sender<quinn::Connection>, Arc<AsyncMutex<mpsc::Receiver<quinn::Connection>>>) {
        let mut by_peer = self.by_peer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let inbox = by_peer.entry(peer).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(INBOUND_CONNECTION_QUEUE_DEPTH);
            PeerInbox { tx, rx: Arc::new(AsyncMutex::new(rx)) }
        });
        (inbox.tx.clone(), inbox.rx.clone())
    }

    /// Drops `peer`'s queue entirely, closing every connection still
    /// waiting in it.
    ///
    /// Called when a peer is revoked. A queued connection is one this
    /// device already authenticated and accepted but no session has claimed
    /// yet; leaving it there would let a session started moments later pick
    /// up a connection from a device that is no longer authorized. Closing
    /// tells the peer immediately instead of letting it wait out an idle
    /// timeout on a connection nobody will ever read.
    ///
    /// A caller currently parked in `accept` for this peer holds its own
    /// `Arc` on the receiver, so its queue survives until it lets go; it
    /// then sees the sender closed and returns `None`, which its supervisor
    /// treats as the connection attempt ending. Either way no revoked
    /// connection is handed to a session.
    fn discard(&self, peer: &[u8; 32]) {
        let mut by_peer = self.by_peer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(inbox) = by_peer.remove(peer) {
            drop(inbox.tx);
            if let Ok(mut rx) = inbox.rx.try_lock() {
                rx.close();
                while let Ok(connection) = rx.try_recv() {
                    connection.close(CONNECTION_NOT_WANTED.into(), b"peer authorization withdrawn");
                }
            }
        }
    }

    fn deliver(&self, peer: [u8; 32], connection: quinn::Connection) {
        let (tx, _rx) = self.inbox(peer);
        if let Err(rejected) = tx.try_send(connection) {
            // The queue is full: this peer is opening connections faster
            // than its session is claiming them. Close the newest rather
            // than evicting a queued one -- the queued ones are older, so
            // the peer has been waiting on them longer, and closing tells
            // the peer immediately instead of letting it wait on a
            // connection this device will never read.
            let connection = rejected.into_inner();
            connection.close(CONNECTION_NOT_WANTED.into(), b"inbound connection queue full");
            tracing::debug!("dropping an inbound QUIC connection: the peer's queue is full");
        }
    }
}

/// This device's QUIC endpoint: one per device, over the transport hub's
/// shared UDP socket, authenticated by the device's Ed25519 signing key.
pub struct QuicPeerEndpoint {
    endpoint: quinn::Endpoint,
    /// This device's identity. Held because a client configuration is built
    /// per dial -- it pins the single key that dial expects to answer, which
    /// is what stops any other authorized peer from taking the call.
    device: DeviceSigningKeyPair,
    authorized: AuthorizedPeerKeys,
    /// A second, independent live set: keys admitted to a raw TLS handshake
    /// for a reason OTHER than ordinary netmap membership -- today, Track
    /// Send's own short-lived, sender+receiver-bound rendezvous grants (see
    /// `crates/yadorilink-daemon`'s `send_transfer` module). Deliberately
    /// never merged into `authorized`: `accept_loop` treats a completed
    /// SYNC-ALPN handshake as a real peer connection only when the peer key
    /// is ALSO in `authorized` specifically, so a key admitted only through
    /// this set can complete a handshake (Track Send needs that) without
    /// ever being able to reach a real sync session, a folder, or the
    /// change DAG through it.
    send_authorized: AuthorizedPeerKeys,
    /// Shared with the accept loop, which is why it is behind its own `Arc`
    /// rather than living in this struct directly.
    inbound: Arc<InboundConnections>,
    /// Completed inbound handshakes that negotiated [`YADORILINK_SEND_ALPN`]
    /// instead of the sync protocol's ALPN -- Track Send's own inbox,
    /// entirely separate from `inbound` above.
    ///
    /// Not peer-keyed like `inbound`: the sync protocol has one long-lived
    /// session per peer that is always the one waiting to claim a
    /// connection, but Track Send has no standing per-peer session --
    /// sends are sporadic and one-shot, from any authorized peer, at any
    /// time. So this is a single queue of `(connection, peer_public_key)`
    /// pairs, drained by one daemon-side task that dispatches each
    /// connection by the peer key it carries. `Some` until whichever task
    /// owns Track Send's inbound handling takes it (see
    /// [`take_inbound_send`](Self::take_inbound_send)); `None` afterwards,
    /// since a channel receiver has exactly one owner.
    inbound_send: StdMutex<Option<InboundConnectionReceiver>>,
    transport: Arc<quinn::TransportConfig>,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for QuicPeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicPeerEndpoint")
            .field("local_addr", &self.endpoint.local_addr().ok())
            .field("authorized", &self.authorized)
            .finish()
    }
}

impl Drop for QuicPeerEndpoint {
    fn drop(&mut self) {
        // The accept loop holds a clone of the `quinn::Endpoint`, so it
        // would keep polling for connections nobody can claim once this
        // handle is gone. Deliberately not closing the endpoint itself: a
        // `quinn::Connection` keeps the endpoint's driver alive on its own,
        // so channels handed out earlier go on working until their own
        // owners drop them.
        self.accept_loop.abort();
    }
}

impl QuicPeerEndpoint {
    /// Builds this device's endpoint on `hub`'s socket, authenticating as
    /// `device` and initially authorizing nobody.
    ///
    /// Starting closed is the point: between this call and the first netmap
    /// being applied there is no peer this device should accept, and an
    /// endpoint that accepted anyone during that window would be
    /// indistinguishable on the wire from a correctly configured one.
    pub fn new(
        hub: Arc<TransportHub>,
        device: DeviceSigningKeyPair,
    ) -> Result<Arc<Self>, TransportError> {
        let authorized = AuthorizedPeerKeys::new();
        let send_authorized = AuthorizedPeerKeys::new();
        let transport = Arc::new(peer_transport_config());

        // `quic_dual_server_config`, not `quic_server_config`: this is the
        // one server configuration the device's one endpoint actually runs
        // with, so it has to accept both the sync protocol's ALPN and
        // Track Send's -- see that function's own doc comment for why this
        // is a separate function rather than a change to
        // `quic_server_config` itself.
        let mut server_config = quic_dual_server_config(&device, &authorized, &send_authorized)?;
        server_config.transport_config(transport.clone());

        let socket = TransportHubQuicSocket::new(hub)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(HubQuinnRuntime),
        )?;

        let inbound = Arc::new(InboundConnections::default());
        let (inbound_send_tx, inbound_send_rx) = mpsc::channel(INBOUND_SEND_QUEUE_DEPTH);
        let accept_loop = tokio::spawn(accept_loop(
            endpoint.clone(),
            authorized.clone(),
            inbound.clone(),
            inbound_send_tx,
        ));

        Ok(Arc::new(Self {
            endpoint,
            device,
            authorized,
            send_authorized,
            inbound,
            inbound_send: StdMutex::new(Some(inbound_send_rx)),
            transport,
            accept_loop,
        }))
    }

    /// Takes ownership of Track Send's inbound-connection stream: every
    /// completed handshake that negotiated [`YADORILINK_SEND_ALPN`], paired
    /// with the peer's authenticated public key, in arrival order.
    ///
    /// Returns `None` on every call after the first -- a channel receiver
    /// has exactly one owner, and this endpoint has exactly one Track Send
    /// inbound-handling task to hand it to. That task is expected to drain
    /// this for the life of the endpoint; a connection queued here before
    /// anyone takes the receiver simply waits (bounded by
    /// [`INBOUND_SEND_QUEUE_DEPTH`], same backpressure shape as the sync
    /// protocol's own per-peer inbox).
    pub fn take_inbound_send(&self) -> Option<InboundConnectionReceiver> {
        self.inbound_send.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Dials `addr` for a Track Send connection, accepting an answer only
    /// from `peer_public_key` -- the send-ALPN counterpart of
    /// [`connect`](Self::connect)/[`dial`](Self::dial).
    ///
    /// Deliberately does not run the sync protocol's candidate-race/
    /// selection-preface dance ([`connect_racing`](Self::connect_racing)):
    /// Track Send is a one-shot request against a device this daemon
    /// already has (or can already establish) ordinary connectivity to,
    /// not a long-lived session worth racing multiple candidates for. A
    /// caller with more than one candidate address tries them in whatever
    /// order/bound fits its own retry policy; each attempt here is a plain
    /// single dial.
    pub async fn connect_send(
        &self,
        addr: SocketAddr,
        peer_public_key: [u8; 32],
    ) -> Result<quinn::Connection, TransportError> {
        let mut client_config = quic_send_client_config(&self.device, peer_public_key)?;
        client_config.transport_config(self.transport.clone());
        self.endpoint
            .connect_with(client_config, addr, PEER_SERVER_NAME)
            .map_err(|err| TransportError::NoRoute(err.to_string()))?
            .await
            .map_err(|err| TransportError::NoRoute(err.to_string()))
    }

    /// The address peers should be told to dial. Identical to the hub's, by
    /// construction -- there is only one binding.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Adds `peer_public_key` to the set this device accepts connections
    /// from, effective on the next handshake.
    pub fn authorize(&self, peer_public_key: [u8; 32]) -> bool {
        self.authorized.authorize(peer_public_key)
    }

    /// Revokes `peer_public_key`: everything about that peer this endpoint
    /// owns, in one call.
    ///
    /// A revoked peer can survive in three places, and this closes the two
    /// of them that are endpoint state:
    ///
    /// 1. **A future handshake.** The key leaves the accepted set, so the
    ///    peer's next handshake is refused.
    /// 2. **A queued connection.** `accept` is keyed per peer and buffers
    ///    authenticated connections, so a peer can complete a handshake
    ///    moments before the revoke and still be sitting in that queue,
    ///    already authenticated, waiting to be claimed. Those are closed and
    ///    the queue itself removed. This also closes the re-authorize hole:
    ///    if the same key is authorized again later, a connection queued
    ///    before the revoke must not be picked up as if it were new.
    ///
    /// The third place is a connection a session is *already running on*.
    /// That one is not reachable from here -- the session owns it -- so
    /// ending it is the caller's own second action, via
    /// [`QuicPeerChannel::close_revoked`](crate::QuicPeerChannel::close_revoked),
    /// together with cancelling the session task.
    ///
    /// The two halves this method does are deliberately not separately
    /// callable. They are one decision, and a caller that could do half of
    /// it would leave an already-authenticated connection for a revoked
    /// device sitting in a queue with nothing left to remove it.
    ///
    /// Returns whether the key had been authorized.
    pub fn revoke_peer(&self, peer_public_key: &[u8; 32]) -> bool {
        // Withdrawal first: a connection discarded before the key is gone
        // could be replaced by a fresh, accepted handshake in the gap.
        let was_authorized = self.authorized.revoke(peer_public_key);
        self.inbound.discard(peer_public_key);
        was_authorized
    }

    /// Whether `peer_public_key` is currently in the accepted set.
    ///
    /// A read of the live set, so it answers "would a handshake from this
    /// device be accepted right now" rather than "was it once".
    pub fn is_authorized(&self, peer_public_key: &[u8; 32]) -> bool {
        self.authorized.contains(peer_public_key)
    }

    /// Replaces the authorized set wholesale, which is the shape a netmap
    /// push arrives in, revoking every peer the replacement drops.
    ///
    /// Revoking the dropped peers is not an extra courtesy -- it is what
    /// makes this method mean the same thing as calling
    /// [`revoke_peer`](Self::revoke_peer) for each of them. Shrinking the set
    /// alone would leave an already-authenticated connection from a dropped
    /// peer sitting in its inbox, ready to be handed to a session if that
    /// peer were ever authorized again. An API that did half of it would
    /// re-open exactly the hole `revoke_peer` exists to close.
    ///
    /// Live connections are untouched: ending those needs the session that
    /// owns each one, which is the caller's.
    pub fn replace_authorized(&self, peer_public_keys: impl IntoIterator<Item = [u8; 32]>) {
        for removed in self.authorized.replace(peer_public_keys) {
            self.inbound.discard(&removed);
        }
    }

    /// Admits `peer_public_key` to a raw TLS handshake for Track Send
    /// purposes only -- see `send_authorized`'s own field doc comment for
    /// why this is a completely separate set from ordinary netmap
    /// authorization, never a way to reach a real sync session. Additive,
    /// unlike [`replace_authorized`](Self::replace_authorized): Track
    /// Send's own caller adds and removes exactly one key per grant, on its
    /// own schedule, entirely independent of netmap pushes.
    pub fn authorize_send_peer(&self, peer_public_key: [u8; 32]) -> bool {
        self.send_authorized.authorize(peer_public_key)
    }

    /// Withdraws a key added by [`authorize_send_peer`](Self::authorize_send_peer)
    /// -- called once its grant is consumed, expired, or the transfer it
    /// was for is done. Does not touch any already-completed handshake or
    /// live connection; same scope as [`replace_authorized`](Self::replace_authorized)'s
    /// own "decides who may connect next" guarantee.
    pub fn revoke_send_peer(&self, peer_public_key: &[u8; 32]) -> bool {
        self.send_authorized.revoke(peer_public_key)
    }

    /// Schedules [`revoke_send_peer`](Self::revoke_send_peer) at
    /// `expires_at_unix` (unix seconds) -- the one pattern both directions
    /// of a Track Send grant need: an [`authorize_send_peer`](Self::authorize_send_peer)
    /// admission that must not outlive the grant's own short TTL, since
    /// `AuthorizedPeerKeys` itself has no TTL notion of its own. An
    /// `expires_at_unix` already in the past schedules an effectively-
    /// immediate revoke rather than erroring -- a grant this device only
    /// just learned about but that is already stale needs to be revoked,
    /// not rejected outright, since it may have been briefly authorized a
    /// moment earlier by the very call this schedules after.
    pub fn schedule_send_peer_revoke(
        self: &Arc<Self>,
        peer_public_key: [u8; 32],
        expires_at_unix: i64,
    ) {
        let endpoint = self.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ttl = Duration::from_secs(expires_at_unix.saturating_sub(now).max(0) as u64);
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            endpoint.revoke_send_peer(&peer_public_key);
        });
    }

    /// Dials `addr`, accepting an answer only from `peer_public_key`.
    ///
    /// The expected key is one key rather than the authorized set: a dial is
    /// aimed at one device, and accepting the set here would mean any
    /// authorized peer that managed to answer this dial would be taken for
    /// the intended one with every check still passing.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        peer_public_key: [u8; 32],
    ) -> Result<quinn::Connection, TransportError> {
        let connection = self.dial(addr, peer_public_key).await?;
        // A single dial has nothing to race against, so the connection it
        // produced is the selection -- but it still has to say so, because
        // the acceptor cannot tell a lone dial from one candidate of a race
        // and must not have to.
        self.announce_selection(&connection).await?;
        Ok(connection)
    }

    /// One dial, with no claim about whether its connection will be used.
    ///
    /// Separate from [`connect`](Self::connect) because a race needs to
    /// produce several connections and then choose: announcing selection
    /// from inside the dial would announce it for every candidate, which is
    /// the ambiguity the preface exists to remove.
    async fn dial(
        &self,
        addr: SocketAddr,
        peer_public_key: [u8; 32],
    ) -> Result<quinn::Connection, TransportError> {
        let mut client_config = quic_client_config(&self.device, peer_public_key)?;
        client_config.transport_config(self.transport.clone());
        self.endpoint
            .connect_with(client_config, addr, PEER_SERVER_NAME)
            .map_err(|err| TransportError::NoRoute(err.to_string()))?
            .await
            .map_err(|err| TransportError::NoRoute(err.to_string()))
    }

    /// Tells the peer that this is the connection this device will use.
    ///
    /// Written immediately rather than left implicit in the first control
    /// frame: opening a stream puts nothing on the wire until something is
    /// written to it, so a selection that waited for the session's first
    /// message would leave the acceptor unable to tell which connection was
    /// chosen for as long as the session stayed quiet. See
    /// [`SELECTION_PREFACE`].
    async fn announce_selection(
        &self,
        connection: &quinn::Connection,
    ) -> Result<(), TransportError> {
        let mut stream =
            connection.open_uni().await.map_err(|err| TransportError::NoRoute(err.to_string()))?;
        stream
            .write_all(&SELECTION_PREFACE)
            .await
            .map_err(|err| TransportError::NoRoute(err.to_string()))?;
        // `finish` only announces the end of the stream; the bytes are
        // already the connection's to deliver, so dropping the handle after
        // this does not lose them.
        let _ = stream.finish();
        Ok(())
    }

    /// Waits for `connection` to declare itself the dialler's selection.
    ///
    /// Anything else -- no stream, the wrong bytes, a closed connection, or
    /// silence past [`SELECTION_TIMEOUT`] -- means this is not the
    /// connection the peer intends to talk on, and the caller discards it.
    async fn await_selection(connection: &quinn::Connection) -> bool {
        let accepted = tokio::time::timeout(SELECTION_TIMEOUT, connection.accept_uni()).await;
        let Ok(Ok(mut stream)) = accepted else {
            return false;
        };
        let mut preface = [0u8; SELECTION_PREFACE.len()];
        // `read_exact` on a peer-controlled stream, into a fixed buffer
        // sized by this device: the peer cannot make this allocate, and a
        // short or oversized stream simply fails the comparison.
        if stream.read_exact(&mut preface).await.is_err() {
            return false;
        }
        preface == SELECTION_PREFACE
    }

    /// Dials `candidates` and returns the first that answers with an
    /// authenticated connection, together with the address that answered.
    ///
    /// ## Why this races rather than walking the list
    ///
    /// A dial to an address nothing answers on does not fail fast. It costs
    /// the full handshake timeout -- [`PEER_IDLE_TIMEOUT`], measured at
    /// exactly 30s -- because there is nothing to fail against: the packets
    /// leave, and silence is indistinguishable from a slow path until the
    /// timer runs out.
    ///
    /// Trying candidates one after another therefore does not merely make a
    /// connection slower; it makes later candidates unreachable in
    /// practice. A supervisor bounds its whole attempt at roughly one
    /// handshake timeout, so the *first* dead address consumes the entire
    /// attempt and every candidate behind it is never reached -- on that
    /// attempt or on any subsequent one, since each retry starts from the
    /// same list in the same order. A peer whose first advertised endpoint
    /// happens not to work is then permanently unreachable, even with a
    /// perfectly good address second in the list. That is not a rare shape:
    /// a device advertises every address it might be reachable at -- each
    /// LAN interface, its reflexive address, a port-mapped one -- precisely
    /// because it cannot know which of them a given peer can use.
    ///
    /// So the candidates are raced, and the first authenticated answer
    /// wins. The peer's identity is pinned per dial exactly as in
    /// [`connect`](Self::connect), so racing widens which *address* may
    /// answer and never which *device* may.
    ///
    /// ## Staggered, and the losers are closed
    ///
    /// Racing introduces its own hazard: two candidates that both answer
    /// are two connections to one peer, which is the state the connect-role
    /// rule exists to prevent. Two things keep that from mattering. The
    /// starts are staggered by [`CANDIDATE_STAGGER`], so a reachable first
    /// candidate normally wins outright and no second connection is ever
    /// created; and any connection that completes after a winner has been
    /// chosen is closed explicitly rather than dropped, so the peer -- which
    /// skips a queued connection that is already closed -- never hands one
    /// of them to a session.
    ///
    /// At most [`MAX_RACED_CANDIDATES`] addresses are tried, so a netmap
    /// naming an unreasonable number of endpoints costs a bounded number of
    /// concurrent handshakes rather than one per entry.
    pub async fn connect_racing(
        self: &Arc<Self>,
        candidates: &[SocketAddr],
        peer_public_key: [u8; 32],
    ) -> Result<(quinn::Connection, SocketAddr), TransportError> {
        let Some((first, rest)) = candidates.split_first() else {
            return Err(TransportError::NoRoute(
                "no candidate addresses for this peer".to_string(),
            ));
        };
        // One candidate is the overwhelmingly common case and needs none of
        // the machinery below -- no task, no stagger, no losers to close.
        if rest.is_empty() {
            return self.connect(*first, peer_public_key).await.map(|c| (c, *first));
        }

        let raced: Vec<SocketAddr> =
            candidates.iter().copied().take(MAX_RACED_CANDIDATES).collect();
        // One slot per attempt, so reporting a result never blocks a task
        // and every result is either read below or drained afterwards --
        // there is no state in which a connection was made and nobody hears
        // about it. Deliberately a channel and plain tasks rather than a
        // `JoinSet`: the simulator's runtime shim does not provide one, and
        // this crate must build the same way under both.
        let (results_tx, mut results) = mpsc::channel(raced.len());
        let mut attempts = AbortRemainingDials(Vec::with_capacity(raced.len()));
        for (index, candidate) in raced.into_iter().enumerate() {
            let endpoint = self.clone();
            let results_tx = results_tx.clone();
            attempts.0.push(tokio::spawn(async move {
                tokio::time::sleep(CANDIDATE_STAGGER * index as u32).await;
                // `dial`, not `connect`: a candidate that answers has not
                // been chosen yet, and announcing selection here would
                // announce it for every candidate that answered.
                let outcome = endpoint.dial(candidate, peer_public_key).await;
                let _ = results_tx.send((candidate, outcome)).await;
            }));
        }
        // The racer's own sender, dropped so the receive loop below ends
        // once every attempt has reported rather than waiting forever.
        drop(results_tx);

        let mut last_failure = None;
        let mut winner = None;
        while let Some((candidate, outcome)) = results.recv().await {
            match outcome {
                Ok(connection) => {
                    winner = Some((connection, candidate));
                    break;
                }
                Err(error) => last_failure = Some(error),
            }
        }

        // Everything still dialling is cancelled, and anything that answered
        // in the meantime is closed rather than dropped: a dropped
        // connection still reached the peer as one it accepted, and the peer
        // has no way to tell it is unwanted unless it is told.
        for attempt in &attempts.0 {
            attempt.abort();
        }
        while let Ok((_, outcome)) = results.try_recv() {
            if let Ok(connection) = outcome {
                connection.close(CONNECTION_NOT_WANTED.into(), b"another candidate answered first");
            }
        }

        match winner {
            Some((connection, candidate)) => {
                // Announced only now, on the one connection that won, and
                // before it is handed back: until this lands the acceptor
                // will not claim any of them, which is what keeps the two
                // ends from choosing differently.
                self.announce_selection(&connection).await?;
                Ok((connection, candidate))
            }
            None => Err(last_failure
                .unwrap_or_else(|| TransportError::NoRoute("no candidate answered".to_string()))),
        }
    }

    /// Awaits the next inbound connection from `peer_public_key`, or `None`
    /// once the endpoint is gone.
    ///
    /// Keyed by peer rather than returning whatever arrived next, because
    /// the caller is one peer's session task: an unkeyed `accept` would let
    /// two such tasks steal each other's connections, and which one won
    /// would depend on scheduling. Connections that were closed while
    /// queued are skipped rather than handed over, so a session does not
    /// start on a path the peer has already abandoned.
    pub async fn accept(&self, peer_public_key: [u8; 32]) -> Option<quinn::Connection> {
        let (_tx, rx) = self.inbound.inbox(peer_public_key);
        let mut rx = rx.lock().await;
        loop {
            let connection = rx.recv().await?;
            if connection.close_reason().is_some() {
                continue;
            }
            // Authorization is re-checked here, against the live set, and
            // not only at handshake time. A caller parked in this method
            // holds its own reference to the queue, so `revoke_peer`
            // removing the queue from the endpoint does not empty the copy
            // this caller is reading from -- without this check, a
            // connection authenticated moments before a revoke could still
            // be handed to a session afterwards. Checking at the moment of
            // claiming is what makes that impossible regardless of who holds
            // the queue.
            if !self.authorized.contains(&peer_public_key) {
                connection.close(CONNECTION_NOT_WANTED.into(), b"peer authorization withdrawn");
                tracing::debug!(
                    "discarding a queued connection from a peer revoked since it \
                                 was accepted"
                );
                continue;
            }
            // The peer may have raced several candidates, so completing a
            // handshake is not the same as being the connection it will
            // use. Only the one it selected is handed to a session -- see
            // [`SELECTION_PREFACE`] for why arrival order cannot decide
            // this.
            if !Self::await_selection(&connection).await {
                connection.close(CONNECTION_NOT_WANTED.into(), b"not the peer's selected path");
                tracing::debug!("discarding a queued connection the peer never selected");
                continue;
            }
            return Some(connection);
        }
    }
}

/// The most bidirectional streams one peer may have open against this
/// device at once: its block requests, plus the single control stream.
const MAX_CONCURRENT_BIDI_STREAMS_PER_PEER: u32 = 128;

/// Shared by the accepting and dialing directions so both ends of a
/// connection agree on the timings that matter.
fn peer_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // Built from a `VarInt` rather than converted from a `Duration` so there
    // is no fallible step at all: an idle timeout is a QUIC transport
    // parameter, varint-encoded on the wire to begin with.
    transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        PEER_IDLE_TIMEOUT_MS,
    ))));
    transport.keep_alive_interval(Some(PEER_KEEP_ALIVE_INTERVAL));
    // Stated rather than left to quinn's default, because it is now a
    // protocol-visible bound rather than an internal one: one block request
    // is one bidirectional stream, so this is exactly how many block
    // requests a peer may have in flight against this device at once, plus
    // the one control stream. QUIC enforces it in the peer's own stack --
    // a requester past the limit waits in `open_bi` instead of putting
    // anything on the wire -- so it is admission control that costs this
    // device nothing to apply.
    //
    // Sized above the per-peer concurrency the session layer will actually
    // reach (its own in-flight fetch window is capped well below this), so
    // this bounds a misbehaving or misconfigured peer without ever being
    // the thing that limits a healthy transfer.
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS_PER_PEER.into());
    transport
}

/// Routes each completed inbound handshake to the peer it authenticated as,
/// and -- since `QuicPeerEndpoint::new` now builds its server configuration
/// from `quic_dual_server_config` -- to the right one of the two
/// completely separate protocols this endpoint accepts.
///
/// Every connection reaching here has already been through mutual raw-
/// public-key verification against the live authorized set -- the handshake
/// is what admitted it -- so the identity read back off it is the verified
/// one, not a claim. That set, however, is `authorized` UNION
/// `send_authorized` (`quic_dual_server_config`'s two live sets) -- a
/// completed handshake alone does not say which of the two admitted this
/// key. For a SYNC-ALPN connection that distinction matters: `authorized`
/// (passed in here, read fresh) is re-checked before `inbound.deliver()`,
/// so a key admitted only through `send_authorized` gets its handshake
/// (Track Send needs that to succeed) but never reaches a real sync
/// session. A SEND-ALPN connection needs no such re-check here -- its own
/// authorization is the application-layer grant check inside
/// `yadorilink-send`'s `handle_offer`, not anything this transport layer
/// decides.
async fn accept_loop(
    endpoint: quinn::Endpoint,
    authorized: AuthorizedPeerKeys,
    inbound: Arc<InboundConnections>,
    inbound_send_tx: InboundConnectionSender,
) {
    while let Some(incoming) = endpoint.accept().await {
        let authorized = authorized.clone();
        let inbound = inbound.clone();
        let inbound_send_tx = inbound_send_tx.clone();
        // One task per handshake: a peer that starts a handshake and then
        // goes quiet must not hold up every other peer's.
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(error) => {
                    // Includes every authorization refusal, which is a
                    // routine outcome rather than a fault: an unauthorized
                    // or revoked peer failing here is this endpoint working.
                    tracing::debug!(%error, "inbound QUIC handshake did not complete");
                    return;
                }
            };
            let Some(peer) = connection_peer_key(&connection) else {
                // Not reachable through a completed handshake -- the
                // verifier accepted an Ed25519 raw public key, so there is
                // one to read back. Closing rather than assuming keeps that
                // an assertion about the code instead of a guess about the
                // peer.
                connection.close(CONNECTION_NOT_WANTED.into(), b"no peer identity");
                tracing::warn!("an accepted QUIC connection carried no Ed25519 peer identity");
                return;
            };
            if negotiated_send_alpn(&connection) {
                // Track Send's own inbox, never the sync protocol's --
                // `try_send` rather than an unbounded await, so a dispatcher
                // task that is momentarily behind cannot stall this
                // connection's own handshake-acceptor task indefinitely; a
                // full queue closes the connection exactly as the sync
                // path's `InboundConnections::deliver` does.
                if let Err(err) = inbound_send_tx.try_send((connection, peer)) {
                    let connection = match err {
                        mpsc::error::TrySendError::Full(pair) => pair.0,
                        mpsc::error::TrySendError::Closed(pair) => pair.0,
                    };
                    connection
                        .close(CONNECTION_NOT_WANTED.into(), b"send inbox queue full or closed");
                    tracing::debug!(
                        "dropping an inbound Track Send QUIC connection: the queue is full or \
                         nobody has taken it yet"
                    );
                }
                return;
            }
            if !authorized.contains(&peer) {
                // Reachable only for a key admitted solely through
                // `send_authorized` -- every key genuinely in `authorized`
                // was already checked by the exact same read a moment
                // earlier at the crypto layer, so this is never a false
                // refusal of an ordinary netmap peer, only the closing half
                // of the split this function's own doc comment describes:
                // a Track Send grant's handshake succeeds, but it must
                // never be mistaken for a sync-protocol connection.
                connection.close(CONNECTION_NOT_WANTED.into(), b"not a sync-authorized peer");
                tracing::debug!(
                    "refusing a sync-ALPN connection from a key not in this device's netmap-\
                     derived authorized set (admitted only for Track Send, if at all)"
                );
                return;
            }
            inbound.deliver(peer, connection);
        });
    }
}

/// Whether `connection` negotiated [`YADORILINK_SEND_ALPN`] rather than the
/// sync protocol's ALPN. `false` for anything else, including a connection
/// whose handshake data quinn cannot report or downcast -- the sync
/// protocol is this endpoint's original, still-default behavior, so an
/// unrecognized case falls back to exactly what every connection did before
/// Track Send's ALPN existed, rather than to a queue built for a protocol
/// that connection never actually claimed to speak.
fn negotiated_send_alpn(connection: &quinn::Connection) -> bool {
    let Some(handshake_data) = connection.handshake_data() else {
        return false;
    };
    let Ok(handshake_data) = handshake_data.downcast::<quinn::crypto::rustls::HandshakeData>()
    else {
        return false;
    };
    handshake_data.protocol.as_deref() == Some(YADORILINK_SEND_ALPN)
}

/// The Ed25519 public key the peer authenticated with.
///
/// quinn hands back the verified TLS identity as the raw-public-key
/// "certificate chain" rustls received, which under RFC 7250 is a single
/// `SubjectPublicKeyInfo`. Every step is fallible and none of it is indexed
/// blindly: this runs on a peer-supplied encoding, even though that peer has
/// already been authenticated.
fn connection_peer_key(connection: &quinn::Connection) -> Option<[u8; 32]> {
    let identity = connection.peer_identity()?;
    let chain = identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()?;
    let end_entity = chain.first()?;
    ed25519_key_from_spki(end_entity.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::transport_hub::TransportHub;

    async fn endpoint() -> (Arc<QuicPeerEndpoint>, SocketAddr, [u8; 32]) {
        let hub =
            TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into()).await.expect("bind hub");
        let addr = hub.local_addr();
        let device = DeviceSigningKeyPair::generate();
        let public = device.public_bytes();
        (QuicPeerEndpoint::new(hub, device).expect("device endpoint"), addr, public)
    }

    /// Two connections from one dialler complete; the one that reached the
    /// acceptor FIRST is not the one the dialler selects. The acceptor must
    /// still hand the session the selected one.
    ///
    /// This is the invariant candidate racing put at risk. The dialler picks
    /// by client-side handshake completion and the acceptor sees server-side
    /// completion; those orders are independent, so "first to arrive" and
    /// "the one that was chosen" are different connections whenever the two
    /// directions have different latency. Asserting on identity rather than
    /// on timing is the point -- a test that merely raced two candidates
    /// would pass on a LAN and prove nothing.
    ///
    /// Identity is established by traffic, which is the only thing the two
    /// ends genuinely share: bytes written on the dialler's selected
    /// connection have to arrive on the connection the acceptor claimed.
    #[tokio::test]
    async fn the_acceptor_claims_the_selected_connection_not_the_first_to_arrive() {
        let (dialler, _dialler_addr, dialler_key) = endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = endpoint().await;
        dialler.authorize(acceptor_key);
        acceptor.authorize(dialler_key);

        // Two live connections to the same peer, established in order, so
        // the acceptor's inbox holds `first` ahead of `second`.
        let first = dialler.dial(acceptor_addr, acceptor_key).await.expect("first dial");
        let second = dialler.dial(acceptor_addr, acceptor_key).await.expect("second dial");

        // The dialler chooses the one that arrived SECOND, which is what a
        // race resolving the other way round produces.
        dialler.announce_selection(&second).await.expect("announce the selection");

        let claimed = tokio::time::timeout(Duration::from_secs(20), acceptor.accept(dialler_key))
            .await
            .expect("accept must resolve")
            .expect("a selected connection must be handed over");

        // Prove it is `second` and not `first`: a stream opened on `second`
        // has to surface on the claimed connection.
        let (mut send, _recv) = second.open_bi().await.expect("open a stream on the selection");
        send.write_all(b"selected").await.expect("write on the selection");
        let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(10), claimed.accept_bi())
            .await
            .expect("the claimed connection must carry the selection's traffic")
            .expect("stream");
        let mut carried = [0u8; 8];
        recv.read_exact(&mut carried).await.expect("read the marker");
        assert_eq!(
            &carried, b"selected",
            "the acceptor must claim the connection the dialler selected, not whichever \
             handshake happened to reach it first"
        );

        // And the unselected one is refused rather than left claimable.
        assert!(first.close_reason().is_some(), "an unselected connection must be closed");
    }

    /// The rule is a total order on ids, so exactly one side of any pair
    /// dials -- which is the property the whole thing exists for, and the
    /// one a hand-written comparison at each call site could silently get
    /// backwards on one side only.
    #[test]
    fn exactly_one_side_of_a_pair_dials() {
        for (a, b) in [
            ("device-a", "device-b"),
            ("device-b", "device-z"),
            ("0", "device-a"),
            ("device-a", "device-a-2"),
        ] {
            assert_eq!(connect_role(a, b), ConnectRole::Dial, "{a} should dial {b}");
            assert_eq!(connect_role(b, a), ConnectRole::Accept, "{b} should accept {a}");
        }
    }

    /// A device pointed at itself must not dial itself; it simply waits.
    #[test]
    fn a_device_paired_with_itself_does_not_dial() {
        assert_eq!(connect_role("device-a", "device-a"), ConnectRole::Accept);
    }

    /// Track Send's own inbox is genuinely separate from the sync
    /// protocol's: a `connect_send` dial must be delivered through
    /// `take_inbound_send`, and must NOT be claimable through the ordinary
    /// peer-keyed `accept` -- proving the two protocols cannot be confused
    /// for each other even though they share one endpoint, one socket, and
    /// one authorized-peer set.
    #[tokio::test]
    async fn a_send_alpn_connection_is_delivered_to_the_send_inbox_not_the_sync_one() {
        let (dialer, _dialer_addr, dialer_key) = endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = endpoint().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);

        let mut inbound_send =
            acceptor.take_inbound_send().expect("first take of the send inbox succeeds");

        let dialed = dialer
            .connect_send(acceptor_addr, acceptor_key)
            .await
            .expect("a send-ALPN dial completes");

        let (accepted, peer) = tokio::time::timeout(Duration::from_secs(10), inbound_send.recv())
            .await
            .expect("the send inbox receives the connection")
            .expect("the channel is still open");
        assert_eq!(peer, dialer_key, "the send inbox reports the dialer's authenticated key");

        // Prove it is genuinely the same connection, not a coincidence:
        // traffic written on one side must arrive on the other.
        let (mut send, _recv) = dialed.open_bi().await.expect("open a stream on the send dial");
        send.write_all(b"track send").await.expect("write on the send dial");
        let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(10), accepted.accept_bi())
            .await
            .expect("the send inbox connection carries the dial's stream")
            .expect("stream");
        let mut carried = [0u8; 10];
        recv.read_exact(&mut carried).await.expect("read the marker");
        assert_eq!(&carried, b"track send");

        // The ordinary sync-protocol `accept` must see nothing: a second
        // take of the send inbox reports it already taken (proving the
        // dispatch really used the send-specific path, not the sync one),
        // and a bounded wait on the sync `accept` for the same peer key
        // times out rather than handing back this connection.
        assert!(acceptor.take_inbound_send().is_none(), "the send inbox has exactly one owner");
        let sync_accept =
            tokio::time::timeout(Duration::from_millis(200), acceptor.accept(dialer_key));
        assert!(
            sync_accept.await.is_err(),
            "a send-ALPN connection must never reach sync `accept`"
        );
    }

    /// The reverse direction of the test above: an ordinary sync-protocol
    /// dial must still reach `accept` exactly as it always has, and must
    /// never be delivered through Track Send's inbox -- proving the new
    /// ALPN dispatch changed nothing about the connection every peer
    /// session already depends on.
    #[tokio::test]
    async fn a_sync_alpn_connection_still_reaches_the_ordinary_accept() {
        let (dialer, _dialer_addr, dialer_key) = endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = endpoint().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);

        let mut inbound_send =
            acceptor.take_inbound_send().expect("first take of the send inbox succeeds");

        let _dialed =
            dialer.connect(acceptor_addr, acceptor_key).await.expect("a sync-ALPN dial completes");

        let claimed = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(dialer_key))
            .await
            .expect("accept must resolve")
            .expect("a sync connection must be handed to the ordinary accept path");
        assert!(claimed.close_reason().is_none());

        let send_side = tokio::time::timeout(Duration::from_millis(200), inbound_send.recv());
        assert!(send_side.await.is_err(), "a sync-ALPN connection must never reach the send inbox");
    }

    /// The adversarial counterpart to the two tests above, and the one
    /// Track Send's own grant primitive depends on: a key admitted ONLY
    /// through `authorize_send_peer` -- never through the ordinary
    /// `authorize`, i.e. never a genuine netmap-derived peer -- can still
    /// complete a send-ALPN dial (Track Send needs exactly that for a
    /// same-account sender with no shared folder group), but if the SAME
    /// key is instead used to attempt the ordinary SYNC-protocol ALPN, the
    /// resulting connection must never reach `accept`. A coordination-plane
    /// rendezvous grant must never be usable to reach a real sync session,
    /// a folder, or the change DAG -- see `send_authorized`'s own field
    /// doc comment and `accept_loop`'s own post-handshake gate, which is
    /// what this test is exercising end to end rather than merely reading
    /// the source.
    #[tokio::test]
    async fn a_key_authorized_only_for_send_cannot_reach_the_ordinary_sync_accept() {
        let (dialer, _dialer_addr, dialer_key) = endpoint().await;
        let (acceptor, acceptor_addr, acceptor_key) = endpoint().await;
        // Deliberately NOT `acceptor.authorize(dialer_key)` -- the dialer
        // is never a genuine netmap peer of the acceptor's in this test,
        // exactly Track Send's own groupless-sender scenario.
        acceptor.authorize_send_peer(dialer_key);

        // The send-ALPN path this admission exists for still works.
        let mut inbound_send =
            acceptor.take_inbound_send().expect("first take of the send inbox succeeds");
        let dialed = dialer
            .connect_send(acceptor_addr, acceptor_key)
            .await
            .expect("a send-ALPN dial completes for a send-authorized-only key");
        let (accepted, peer) = tokio::time::timeout(Duration::from_secs(10), inbound_send.recv())
            .await
            .expect("the send inbox receives the connection")
            .expect("the channel is still open");
        assert_eq!(peer, dialer_key);
        drop(dialed);
        drop(accepted);

        // The SAME key attempting the ordinary sync ALPN instead: the raw
        // TLS handshake completes (`send_authorized` is unioned into the
        // crypto layer's accept set -- see `PinnedPeerKeys::additional`'s
        // own doc comment), but the connection must never be claimable
        // through `accept` -- proving a Track Send grant can never be
        // used to reach a real sync session.
        let sync_dial = dialer.dial(acceptor_addr, acceptor_key).await;
        match sync_dial {
            Ok(_connection) => {
                // The handshake succeeded, as expected -- now prove the
                // acceptor never promotes it to a real sync connection.
                let claimed =
                    tokio::time::timeout(Duration::from_millis(300), acceptor.accept(dialer_key))
                        .await;
                assert!(
                    claimed.is_err(),
                    "a key authorized only for Track Send must never reach the sync-protocol \
                     accept()"
                );
            }
            Err(_) => {
                // Also an acceptable outcome: if the transport-layer union
                // were ever tightened further to refuse the handshake
                // outright, that is a strictly stronger form of the same
                // guarantee this test exists to prove.
            }
        }
    }
}
