//! M3 Pass 5e: the actual B-side datagram-forwarding actor -- the ONLY
//! place bytes admitted by `relay_session::admit_relay_open` actually move.
//! Everything in this module is deliberately dumb: it never parses,
//! inspects, or modifies a payload, never chooses a destination other than
//! the one address it was opened against, and never itself relays through
//! a third party.
//!
//! **One dedicated ephemeral UDP socket per relay session**, bound fresh
//! and `connect()`-ed to the destination for THIS session only -- never
//! this device's own shared, multiplexed `TransportHub` socket. This is a
//! deliberate simplicity/safety choice: reusing the shared socket would
//! require teaching its demux ("which of my own direct channels does this
//! inbound datagram belong to") about relay sessions too, since a reply
//! from the destination arrives with no receiver-index this device's own
//! demux tables know about (that index was negotiated between A and C, two
//! parties this device's own transport stack has no session state for).
//! A dedicated per-session socket sidesteps that entirely -- the OS's own
//! per-socket UDP demultiplexing (by source address, since the socket is
//! `connect()`-ed) does the routing, with ZERO changes to this device's
//! own `TransportHub`/`PeerChannel` demux, and zero risk of a relay
//! session colliding with or confusing this device's own direct
//! connectivity state.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use yadorilink_peer_session::rate_limiter::TokenBucket;

/// Generous for a WireGuard datagram (typical MTU well under this); rejects
/// anything larger outright rather than silently truncating.
const MAX_RELAY_PACKET_SIZE: usize = 2048;
/// No traffic in EITHER direction for this long closes the session --
/// independent of the grant's own `expires_at_unix`, which bounds the
/// session's maximum lifetime regardless of activity.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const RELAY_IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Matches `relay_session::RelayAdmissionContext::max_concurrent_relay_
/// sessions`'s own default use in the daemon-side admission wiring -- kept
/// here too since `RelayForwarder` itself refuses to open a session past
/// this count even if a caller's own admission context somehow disagreed
/// (defense in depth, not the primary enforcement point).
pub const RELAY_MAX_CONCURRENT_SESSIONS: usize = 8;
const RELAY_MAX_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;
const RELAY_MAX_PACKETS_PER_SEC: u64 = 500;

// Where the forwarder sends bytes it receives FROM the destination (C),
// and how it reports a session closing -- implemented by whatever sent
// the original `RelayOpen` (a live `PeerSyncSession`, in production),
// which pushes these back out as `RelayData`/`RelayClose` on that same
// A<->B channel. Reuses `yadorilink_peer_session::peer_session::
// RelayReplySink` directly (not a separate duplicate trait) -- the same
// object a `PeerSyncSession` already implements gets handed straight
// through from `relay_session_handler.rs`, with no adapter shim needed.
pub use yadorilink_peer_session::peer_session::RelayReplySink;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayForwarderError {
    #[error("relay slot limit reached ({active}/{max})")]
    SlotLimitReached { active: usize, max: usize },
    #[error("failed to open the relay's own forwarding socket: {0}")]
    SocketSetup(String),
    #[error("no active relay session with id {0}")]
    UnknownSession(u64),
    #[error("relay session {session_id} byte cap reached ({sent}/{cap})")]
    ByteCapReached { session_id: u64, sent: u64, cap: u64 },
}

struct RelaySessionHandle {
    socket: Arc<UdpSocket>,
    close_tx: watch::Sender<Option<String>>,
    bytes_forwarded: Arc<AtomicU64>,
    max_session_bytes: Option<u64>,
    byte_bucket: Arc<TokenBucket>,
    packet_bucket: Arc<TokenBucket>,
    last_activity_unix_ms: Arc<AtomicI64>,
}

/// Owns every currently-open relay session on this device (as a relay,
/// "B"). One instance per daemon, shared with the `PeerSyncSessionDeps`
/// adapter that dispatches `RelayOpen`/`RelayData`/`RelayClose`.
pub struct RelayForwarder {
    sessions: StdMutex<HashMap<u64, RelaySessionHandle>>,
    next_session_id: AtomicU64,
}

impl RelayForwarder {
    pub fn new() -> Self {
        Self { sessions: StdMutex::new(HashMap::new()), next_session_id: AtomicU64::new(0) }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Opens a new relay session toward `destination_addr`, valid until
    /// `expires_at_unix` (mirroring the admitting grant's own expiry --
    /// this forwarder enforces it independently, never trusting the
    /// caller to close on time). `now_unix` is passed in, not read from
    /// the system clock, so this stays testable under a fake clock.
    pub fn open_session(
        self: &Arc<Self>,
        destination_addr: SocketAddr,
        max_session_bytes: Option<u64>,
        expires_at_unix: i64,
        now_unix_ms: i64,
        reply_sink: Arc<dyn RelayReplySink>,
    ) -> Result<u64, RelayForwarderError> {
        let active = self.active_session_count();
        if active >= RELAY_MAX_CONCURRENT_SESSIONS {
            return Err(RelayForwarderError::SlotLimitReached {
                active,
                max: RELAY_MAX_CONCURRENT_SESSIONS,
            });
        }

        let std_socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|e| RelayForwarderError::SocketSetup(e.to_string()))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| RelayForwarderError::SocketSetup(e.to_string()))?;
        // `connect()` on a UDP socket is a purely local operation (no
        // handshake) that fixes the peer address for `send`/`recv` -- the
        // OS then does the "which of my open sockets does this reply
        // belong to" demultiplexing by source address for us, which is
        // exactly this module's own doc comment's reasoning for a
        // dedicated socket in the first place.
        std_socket
            .connect(destination_addr)
            .map_err(|e| RelayForwarderError::SocketSetup(e.to_string()))?;
        let socket = Arc::new(
            UdpSocket::from_std(std_socket)
                .map_err(|e| RelayForwarderError::SocketSetup(e.to_string()))?,
        );

        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (close_tx, close_rx) = watch::channel(None);
        let bytes_forwarded = Arc::new(AtomicU64::new(0));
        let byte_bucket = Arc::new(TokenBucket::new(RELAY_MAX_BYTES_PER_SEC));
        let packet_bucket = Arc::new(TokenBucket::new(RELAY_MAX_PACKETS_PER_SEC));
        let last_activity_unix_ms = Arc::new(AtomicI64::new(now_unix_ms));

        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).insert(
            session_id,
            RelaySessionHandle {
                socket: socket.clone(),
                close_tx,
                bytes_forwarded: bytes_forwarded.clone(),
                max_session_bytes,
                byte_bucket: byte_bucket.clone(),
                packet_bucket: packet_bucket.clone(),
                last_activity_unix_ms: last_activity_unix_ms.clone(),
            },
        );

        let registry = self.clone();
        tokio::spawn(run_relay_forwarder_actor(
            session_id,
            socket,
            close_rx,
            bytes_forwarded,
            max_session_bytes,
            expires_at_unix,
            byte_bucket,
            packet_bucket,
            last_activity_unix_ms,
            reply_sink,
            registry,
        ));

        Ok(session_id)
    }

    /// Forwards `payload` toward the destination over `session_id`'s
    /// dedicated socket -- the A(source)-to-C(destination) direction.
    /// Silently succeeds-as-a-no-op-that-still-returns-Ok is deliberately
    /// NOT this method's behavior for an unknown session (unlike a raw
    /// datagram arriving with an unrecognized id on the wire, which the
    /// caller drops silently per `RelayData`'s own doc comment) -- this is
    /// the internal admission-checked path, so an unknown id here is
    /// always this device's own bookkeeping bug, worth surfacing.
    pub async fn forward_from_source(
        &self,
        session_id: u64,
        payload: &[u8],
        now_unix_ms: i64,
    ) -> Result<(), RelayForwarderError> {
        let handle = {
            let sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
            match sessions.get(&session_id) {
                Some(h) => (
                    h.socket.clone(),
                    h.bytes_forwarded.clone(),
                    h.max_session_bytes,
                    h.byte_bucket.clone(),
                    h.packet_bucket.clone(),
                    h.last_activity_unix_ms.clone(),
                ),
                None => return Err(RelayForwarderError::UnknownSession(session_id)),
            }
        };
        let (socket, bytes_forwarded, max_session_bytes, byte_bucket, packet_bucket, last_activity) =
            handle;

        if payload.len() > MAX_RELAY_PACKET_SIZE {
            return Ok(()); // oversized: silently dropped, matches datagram-loss semantics.
        }
        let prospective_total = bytes_forwarded.load(Ordering::Relaxed) + payload.len() as u64;
        if let Some(cap) = max_session_bytes {
            if prospective_total > cap {
                self.close_session(session_id, "byte_limit_reached");
                return Err(RelayForwarderError::ByteCapReached {
                    session_id,
                    sent: prospective_total,
                    cap,
                });
            }
        }

        byte_bucket.acquire(payload.len() as u64).await;
        packet_bucket.acquire(1).await;
        let _ = socket.send(payload).await;
        bytes_forwarded.fetch_add(payload.len() as u64, Ordering::Relaxed);
        last_activity.store(now_unix_ms, Ordering::Relaxed);
        Ok(())
    }

    /// Ends a session immediately, regardless of idle/expiry state --
    /// used both for an explicit `RelayClose` from the requester and
    /// internally (byte-cap exceeded). The actor task notices via `close`
    /// and removes its own registry entry; this method does not remove it
    /// directly, so there is exactly one removal path (the actor's own
    /// exit), not two that could race.
    pub fn close_session(&self, session_id: u64, reason: &str) {
        if let Some(handle) = self.sessions.lock().unwrap_or_else(|p| p.into_inner()).get(&session_id)
        {
            let _ = handle.close_tx.send(Some(reason.to_string()));
        }
    }

    fn remove_session(&self, session_id: u64) {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).remove(&session_id);
    }
}

impl Default for RelayForwarder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_relay_forwarder_actor(
    session_id: u64,
    socket: Arc<UdpSocket>,
    mut close_rx: watch::Receiver<Option<String>>,
    bytes_forwarded: Arc<AtomicU64>,
    max_session_bytes: Option<u64>,
    expires_at_unix: i64,
    byte_bucket: Arc<TokenBucket>,
    packet_bucket: Arc<TokenBucket>,
    last_activity_unix_ms: Arc<AtomicI64>,
    reply_sink: Arc<dyn RelayReplySink>,
    registry: Arc<RelayForwarder>,
) {
    let reason = loop {
        let now_unix = now_unix_seconds();
        if now_unix > expires_at_unix {
            break "grant_expired".to_string();
        }
        let mut buf = [0u8; MAX_RELAY_PACKET_SIZE];
        tokio::select! {
            biased;
            _ = close_rx.changed() => {
                break close_rx.borrow().clone().unwrap_or_else(|| "closed".to_string());
            }
            _ = tokio::time::sleep(RELAY_IDLE_CHECK_INTERVAL) => {
                let idle_for = now_unix_millis() - last_activity_unix_ms.load(Ordering::Relaxed);
                if idle_for >= RELAY_IDLE_TIMEOUT.as_millis() as i64 {
                    break "idle_timeout".to_string();
                }
                continue;
            }
            recv = socket.recv(&mut buf) => {
                let Ok(n) = recv else { break "socket_error".to_string() };
                if n == 0 {
                    continue;
                }
                let prospective_total = bytes_forwarded.load(Ordering::Relaxed) + n as u64;
                if let Some(cap) = max_session_bytes {
                    if prospective_total > cap {
                        break "byte_limit_reached".to_string();
                    }
                }
                byte_bucket.acquire(n as u64).await;
                packet_bucket.acquire(1).await;
                bytes_forwarded.fetch_add(n as u64, Ordering::Relaxed);
                last_activity_unix_ms.store(now_unix_millis(), Ordering::Relaxed);
                reply_sink.send_relay_data(session_id, buf[..n].to_vec());
            }
        }
    };
    registry.remove_session(session_id);
    reply_sink.send_relay_close(session_id, &reason);
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdSyncMutex;

    use tokio::net::UdpSocket as TokioUdpSocket;

    use super::*;

    struct RecordingSink {
        data: StdSyncMutex<Vec<(u64, Vec<u8>)>>,
        closed: StdSyncMutex<Vec<(u64, String)>>,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self { data: StdSyncMutex::new(Vec::new()), closed: StdSyncMutex::new(Vec::new()) })
        }
    }

    impl RelayReplySink for RecordingSink {
        fn send_relay_data(&self, session_id: u64, payload: Vec<u8>) {
            self.data.lock().unwrap().push((session_id, payload));
        }
        fn send_relay_close(&self, session_id: u64, reason: &str) {
            self.closed.lock().unwrap().push((session_id, reason.to_string()));
        }
    }

    async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else { return };
                let _ = socket.send_to(&buf[..n], from).await;
            }
        });
        (addr, handle)
    }

    /// Opaque bytes sent from the "source" direction reach the destination
    /// and the reply comes back through the sink -- the core round trip
    /// this whole module exists for.
    #[tokio::test]
    async fn opaque_bytes_round_trip_through_a_relay_session() {
        let (dest_addr, _server) = echo_server().await;
        let forwarder = Arc::new(RelayForwarder::new());
        let sink = RecordingSink::new();
        let now = now_unix_seconds();

        let session_id = forwarder
            .open_session(dest_addr, None, now + 60, now_unix_millis(), sink.clone())
            .unwrap();

        forwarder
            .forward_from_source(session_id, b"hello from A", now_unix_millis())
            .await
            .unwrap();

        // Give the echo server + the forwarder's own recv loop a moment.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let data = sink.data.lock().unwrap().clone();
        assert_eq!(data, vec![(session_id, b"hello from A".to_vec())]);
    }

    #[tokio::test]
    async fn session_closes_and_reports_reason_when_explicitly_closed() {
        let (dest_addr, _server) = echo_server().await;
        let forwarder = Arc::new(RelayForwarder::new());
        let sink = RecordingSink::new();
        let now = now_unix_seconds();

        let session_id =
            forwarder.open_session(dest_addr, None, now + 60, now_unix_millis(), sink.clone()).unwrap();
        forwarder.close_session(session_id, "requester_closed");
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(forwarder.active_session_count(), 0);
        let closed = sink.closed.lock().unwrap().clone();
        assert_eq!(closed, vec![(session_id, "requester_closed".to_string())]);
    }

    #[tokio::test]
    async fn byte_cap_closes_the_session_on_the_source_to_destination_side() {
        let (dest_addr, _server) = echo_server().await;
        let forwarder = Arc::new(RelayForwarder::new());
        let sink = RecordingSink::new();
        let now = now_unix_seconds();

        let session_id = forwarder
            .open_session(dest_addr, Some(4), now + 60, now_unix_millis(), sink.clone())
            .unwrap();

        let result = forwarder.forward_from_source(session_id, b"way too many bytes", now_unix_millis()).await;
        assert!(matches!(result, Err(RelayForwarderError::ByteCapReached { .. })));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(forwarder.active_session_count(), 0);
    }

    #[tokio::test]
    async fn slot_limit_is_enforced() {
        let (dest_addr, _server) = echo_server().await;
        let forwarder = Arc::new(RelayForwarder::new());
        let now = now_unix_seconds();
        for _ in 0..RELAY_MAX_CONCURRENT_SESSIONS {
            forwarder
                .open_session(dest_addr, None, now + 60, now_unix_millis(), RecordingSink::new())
                .unwrap();
        }
        let result =
            forwarder.open_session(dest_addr, None, now + 60, now_unix_millis(), RecordingSink::new());
        assert!(matches!(result, Err(RelayForwarderError::SlotLimitReached { .. })));
    }

    #[tokio::test]
    async fn forwarding_on_an_unknown_session_id_is_an_error() {
        let forwarder = Arc::new(RelayForwarder::new());
        let result = forwarder.forward_from_source(999, b"data", now_unix_millis()).await;
        assert_eq!(result, Err(RelayForwarderError::UnknownSession(999)));
    }
}
