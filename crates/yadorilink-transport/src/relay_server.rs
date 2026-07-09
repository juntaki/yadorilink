//! Minimal content-blind relay server: forwards opaque,
//! already-WireGuard-encrypted bytes between two registered public
//! keys. The relay never decrypts anything — it only reads the `Forward`
//! envelope's destination key, never the WireGuard payload inside it.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use yadorilink_ipc_proto::relay::relay_message::Payload;
use yadorilink_ipc_proto::relay::{Forwarded, HelloAck, HelloChallenge, RelayMessage};
use zeroize::Zeroizing;

pub type PublicKeyBytes = [u8; 32];
type Registry = Arc<Mutex<HashMap<PublicKeyBytes, OutboundRoute>>>;
type SourceConnectionCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounded lifetime of a peer-key registration: a registration must be
/// renewed via a fresh proof-of-key-ownership exchange (the same
/// Hello/HelloChallenge/HelloProof messages used at initial registration,
/// re-run over the already-open connection) before this elapses, or the
/// relay drops the registration and treats the key as unregistered —
/// independent of any revocation signal (the relay has none).
///
/// Chosen well above `IDLE_READ_TIMEOUT` (2 minutes) so it only bounds a
/// connection that is *actively* exchanging traffic and would otherwise
/// never hit the idle-read timeout; an idle connection is already bounded
/// by `IDLE_READ_TIMEOUT`. 15 minutes gives `RelayHub`'s renewal ticker
/// (`relay_hub.rs`, fires every `REGISTRATION_TTL / 3` = 5 minutes) two
/// full renewal attempts of margin before expiry, so one missed or slow
/// renewal round trip does not cost the registration.
pub(crate) const REGISTRATION_TTL: Duration = Duration::from_secs(15 * 60);
const OUTBOUND_QUEUE_CAPACITY: usize = 64;
const MAX_OUTBOUND_BYTES_PER_CONNECTION: usize = 256 * 1024;
const MAX_TOTAL_OUTBOUND_BYTES: usize = 4 * 1024 * 1024;
const MAX_RELAY_CONNECTIONS: usize = 1024;
const MAX_CONNECTIONS_PER_SOURCE: usize = 64;
const MAX_REGISTERED_KEYS: usize = 4096;
const RELAY_CHALLENGE_NONCE_LEN: usize = 32;

#[derive(Clone)]
pub struct RelayRuntime {
    registry: Registry,
    global_outbound_bytes: Arc<AtomicUsize>,
    connection_slots: Arc<Semaphore>,
    source_counts: SourceConnectionCounts,
}

impl RelayRuntime {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_bytes: Arc::new(AtomicUsize::new(0)),
            connection_slots: Arc::new(Semaphore::new(MAX_RELAY_CONNECTIONS)),
            source_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn metrics(&self) -> RelayMetrics {
        RelayMetrics {
            registry: self.registry.clone(),
            global_outbound_bytes: self.global_outbound_bytes.clone(),
            source_counts: self.source_counts.clone(),
        }
    }

    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let connection_slot = self
                .connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| io::Error::other("relay connection semaphore closed"))?;
            let (stream, peer_addr) = listener.accept().await?;
            let Some(source_guard) =
                SourceConnectionGuard::try_acquire(peer_addr.ip(), self.source_counts.clone())
            else {
                tracing::warn!(%peer_addr, "relay per-source connection cap reached; dropping connection");
                drop(connection_slot);
                drop(stream);
                continue;
            };
            let registry = self.registry.clone();
            let global_outbound_bytes = self.global_outbound_bytes.clone();
            // daemon-reliability reliability hardening/reliability hardening: previously a bare `tokio::spawn`
            // whose `JoinHandle` was dropped — a panic inside
            // `handle_connection` (e.g. in an untested edge case of the wire
            // parsing) would vanish silently instead of being logged.
            // `spawn_logged` doesn't restart this task (a single finished
            // connection handler restarting wouldn't make sense — new
            // connections are handled by the next loop iteration), it just
            // makes a panic visible instead of a silent zombie.
            crate::supervise::spawn_logged("relay-connection-handler", async move {
                let _connection_slot = connection_slot;
                let _source_guard = source_guard;
                if let Err(e) =
                    handle_connection(stream, peer_addr, registry, global_outbound_bytes).await
                {
                    tracing::warn!(error = %e, %peer_addr, "relay connection ended with an error");
                }
            });
        }
    }
}

impl Default for RelayRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct RelayMetrics {
    registry: Registry,
    global_outbound_bytes: Arc<AtomicUsize>,
    source_counts: SourceConnectionCounts,
}

impl RelayMetrics {
    pub fn render_openmetrics(&self) -> String {
        let active_sessions =
            self.registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len();
        let active_sources =
            self.source_counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len();
        let queued_outbound_bytes = self.global_outbound_bytes.load(Ordering::Relaxed);

        format!(
            "# TYPE yadorilink_relay_active_sessions gauge\n\
             yadorilink_relay_active_sessions {active_sessions}\n\
             # TYPE yadorilink_relay_active_sources gauge\n\
             yadorilink_relay_active_sources {active_sources}\n\
             # TYPE yadorilink_relay_queued_outbound_bytes gauge\n\
             yadorilink_relay_queued_outbound_bytes {queued_outbound_bytes}\n"
        )
    }
}

#[derive(Clone)]
struct OutboundRoute {
    tx: mpsc::Sender<QueuedRelayMessage>,
    connection_bytes: Arc<AtomicUsize>,
    global_bytes: Arc<AtomicUsize>,
}

struct QueuedRelayMessage {
    msg: RelayMessage,
    bytes: usize,
    connection_bytes: Arc<AtomicUsize>,
    global_bytes: Arc<AtomicUsize>,
}

impl Drop for QueuedRelayMessage {
    fn drop(&mut self) {
        self.connection_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
        self.global_bytes.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct SourceConnectionGuard {
    source: IpAddr,
    counts: SourceConnectionCounts,
}

impl SourceConnectionGuard {
    fn try_acquire(source: IpAddr, counts: SourceConnectionCounts) -> Option<Self> {
        {
            let mut counts_guard = counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let current = counts_guard.get(&source).copied().unwrap_or(0);
            if current >= MAX_CONNECTIONS_PER_SOURCE {
                return None;
            }
            counts_guard.insert(source, current + 1);
        }
        Some(Self { source, counts })
    }
}

impl Drop for SourceConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match counts.get_mut(&self.source) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                counts.remove(&self.source);
            }
            None => {}
        }
    }
}

pub async fn serve(listener: TcpListener) -> std::io::Result<()> {
    RelayRuntime::new().serve(listener).await
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    registry: Registry,
    global_outbound_bytes: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    handle_connection_with_timeouts(
        stream,
        peer_addr,
        registry,
        global_outbound_bytes,
        HANDSHAKE_TIMEOUT,
        IDLE_READ_TIMEOUT,
        REGISTRATION_TTL,
    )
    .await
}

async fn handle_connection_with_timeouts(
    stream: TcpStream,
    peer_addr: SocketAddr,
    registry: Registry,
    global_outbound_bytes: Arc<AtomicUsize>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
    registration_ttl: Duration,
) -> std::io::Result<()> {
    // See relay_client.rs's `connect` doc comment for why this is the
    // generic `tokio::io::split`, not `TcpStream::into_split`.
    let (mut read_half, write_half) = tokio::io::split(stream);

    let connection_outbound_bytes = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = mpsc::channel::<QueuedRelayMessage>(OUTBOUND_QUEUE_CAPACITY);
    let writer_task = tokio::spawn(async move {
        let mut write_half = write_half;
        while let Some(queued) = rx.recv().await {
            if crate::relay_io::write_relay_message(&mut write_half, &queued.msg).await.is_err() {
                break;
            }
        }
    });

    // First frame must be Hello, registering this connection's public key.
    let first = read_relay_message_with_timeout(&mut read_half, handshake_timeout).await?;
    let Some(RelayMessage { payload: Some(Payload::Hello(hello)) }) = first else {
        writer_task.abort();
        return Ok(());
    };
    let Ok(my_key): Result<PublicKeyBytes, _> = hello.public_key.as_slice().try_into() else {
        writer_task.abort();
        return Ok(());
    };
    let my_route = OutboundRoute {
        tx,
        connection_bytes: connection_outbound_bytes,
        global_bytes: global_outbound_bytes,
    };

    let (challenge_secret, challenge_public, challenge_nonce) = new_relay_challenge();
    if !queue_relay_message(
        &my_route,
        RelayMessage {
            payload: Some(Payload::HelloChallenge(HelloChallenge {
                server_public_key: challenge_public.to_bytes().to_vec(),
                nonce: challenge_nonce.to_vec(),
            })),
        },
    ) {
        writer_task.abort();
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "relay outbound queue full"));
    }

    let proof = read_relay_message_with_timeout(&mut read_half, handshake_timeout).await?;
    let Some(RelayMessage { payload: Some(Payload::HelloProof(proof)) }) = proof else {
        writer_task.abort();
        return Ok(());
    };
    let client_public = PublicKey::from(my_key);
    if !crate::relay_auth::verify_proof(
        &client_public,
        &challenge_secret,
        &challenge_nonce,
        &proof.mac,
    ) {
        writer_task.abort();
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay public-key proof failed",
        ));
    }

    if !register_route(&registry, my_key, my_route.clone(), MAX_REGISTERED_KEYS) {
        writer_task.abort();
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "relay key already registered or registered-key cap reached",
        ));
    }
    tracing::info!(key = %hex::encode(my_key), %peer_addr, "relay: device connected");

    if !queue_relay_message(
        &my_route,
        RelayMessage {
            payload: Some(Payload::HelloAck(HelloAck { observed_address: peer_addr.to_string() })),
        },
    ) {
        remove_route(&registry, &my_key, &my_route);
        writer_task.abort();
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "relay outbound queue full"));
    }

    // Registration TTL bookkeeping: the deadline starts at
    // successful registration and is pushed out by `registration_ttl` on
    // every successfully re-proved renewal below. `pending_renewal` holds
    // the challenge secret/nonce between a renewal `Hello` and the
    // `HelloProof` that must follow it — a fresh `Hello` replaces any
    // still-pending one, matching the initial handshake's
    // one-challenge-at-a-time shape.
    let mut registration_deadline = tokio::time::Instant::now() + registration_ttl;
    let mut pending_renewal: Option<(StaticSecret, [u8; RELAY_CHALLENGE_NONCE_LEN])> = None;

    let result = loop {
        tokio::select! {
            // this fires purely from elapsed time since
            // registration/last renewal — the relay never consults ACL or
            // revocation state to decide this.
            _ = tokio::time::sleep_until(registration_deadline) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay peer-key registration TTL expired without renewal",
                ));
            }
            read_result = read_relay_message_with_timeout(&mut read_half, idle_timeout) => {
                match read_result {
                    Err(e) => break Err(e),
                    Ok(None) => break Ok(()),
                    Ok(Some(RelayMessage { payload: Some(Payload::Forward(fwd)) })) => {
                        let Ok(dest_key): Result<PublicKeyBytes, _> =
                            fwd.dest_public_key.as_slice().try_into()
                        else {
                            continue;
                        };
                        let dest_route = registry
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get(&dest_key)
                            .cloned();
                        if let Some(dest_route) = dest_route {
                            let queued = queue_relay_message(
                                &dest_route,
                                RelayMessage {
                                    payload: Some(Payload::Forwarded(Forwarded {
                                        from_public_key: my_key.to_vec(),
                                        payload: fwd.payload,
                                    })),
                                },
                            );
                            if !queued {
                                tracing::warn!(
                                    dest_key = %hex::encode(dest_key),
                                    "relay outbound queue full; dropping forwarded frame"
                                );
                            }
                        }
                    }
                    Ok(Some(RelayMessage { payload: Some(Payload::Hello(hello)) })) => {
                        // Registration renewal request: re-run
                        // the exact same proof-of-key-ownership challenge
                        // as initial registration, reusing `relay_auth`'s
                        // hardened `verify_proof` rather than a separate,
                        // less-scrutinized renewal path. A `Hello` for a
                        // key other than this connection's registered one
                        // is nonsensical (the relay already identifies
                        // this connection by `my_key`) and is ignored.
                        if hello.public_key == my_key.to_vec() {
                            let (secret, public, nonce) = new_relay_challenge();
                            if !queue_relay_message(
                                &my_route,
                                RelayMessage {
                                    payload: Some(Payload::HelloChallenge(HelloChallenge {
                                        server_public_key: public.to_bytes().to_vec(),
                                        nonce: nonce.to_vec(),
                                    })),
                                },
                            ) {
                                break Err(io::Error::new(
                                    io::ErrorKind::WouldBlock,
                                    "relay outbound queue full",
                                ));
                            }
                            pending_renewal = Some((secret, nonce));
                        }
                    }
                    Ok(Some(RelayMessage { payload: Some(Payload::HelloProof(proof)) })) => {
                        if let Some((secret, nonce)) = pending_renewal.take() {
                            if crate::relay_auth::verify_proof(
                                &client_public,
                                &secret,
                                &nonce,
                                &proof.mac,
                            ) {
                                registration_deadline =
                                    tokio::time::Instant::now() + registration_ttl;
                            } else {
                                break Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "relay registration renewal proof failed",
                                ));
                            }
                        }
                        // A `HelloProof` with no pending renewal challenge
                        // (e.g. a stray retransmit) is ignored, matching
                        // "ignore anything else a client shouldn't send"
                        // below.
                    }
                    Ok(Some(_)) => {} // ignore anything else a client shouldn't send
                }
            }
        }
    };

    remove_route(&registry, &my_key, &my_route);
    writer_task.abort();
    tracing::info!(key = %hex::encode(my_key), "relay: device disconnected");
    result
}

fn queue_relay_message(route: &OutboundRoute, msg: RelayMessage) -> bool {
    let bytes = msg.encoded_len() + std::mem::size_of::<u32>();
    if bytes > MAX_OUTBOUND_BYTES_PER_CONNECTION || bytes > MAX_TOTAL_OUTBOUND_BYTES {
        return false;
    }
    if !try_reserve_bytes(&route.connection_bytes, MAX_OUTBOUND_BYTES_PER_CONNECTION, bytes) {
        return false;
    }
    if !try_reserve_bytes(&route.global_bytes, MAX_TOTAL_OUTBOUND_BYTES, bytes) {
        route.connection_bytes.fetch_sub(bytes, Ordering::Relaxed);
        return false;
    }

    let queued = QueuedRelayMessage {
        msg,
        bytes,
        connection_bytes: route.connection_bytes.clone(),
        global_bytes: route.global_bytes.clone(),
    };
    route.tx.try_send(queued).is_ok()
}

fn register_route(
    registry: &Registry,
    key: PublicKeyBytes,
    route: OutboundRoute,
    max_registered_keys: usize,
) -> bool {
    let mut registry = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if registry.contains_key(&key) || registry.len() >= max_registered_keys {
        return false;
    }
    registry.insert(key, route);
    true
}

fn remove_route(registry: &Registry, key: &PublicKeyBytes, route: &OutboundRoute) {
    let mut registry = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if registry.get(key).is_some_and(|registered| registered.tx.same_channel(&route.tx)) {
        registry.remove(key);
    }
}

fn new_relay_challenge() -> (StaticSecret, PublicKey, [u8; RELAY_CHALLENGE_NONCE_LEN]) {
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut secret_bytes[..]);
    let secret = StaticSecret::from(*secret_bytes);
    let public = PublicKey::from(&secret);
    let mut nonce = [0u8; RELAY_CHALLENGE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    (secret, public, nonce)
}

fn try_reserve_bytes(counter: &AtomicUsize, limit: usize, bytes: usize) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(bytes) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

async fn read_relay_message_with_timeout(
    stream: &mut (impl AsyncRead + Unpin),
    read_timeout: Duration,
) -> std::io::Result<Option<RelayMessage>> {
    match tokio::time::timeout(read_timeout, crate::relay_io::read_relay_message(stream)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "relay connection read timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use yadorilink_ipc_proto::relay::{Forward, Hello, HelloProof};

    async fn accept_one(
        listener: TcpListener,
        registry: Registry,
        timeout: Duration,
    ) -> io::Result<()> {
        accept_one_with_ttl(listener, registry, timeout, REGISTRATION_TTL).await
    }

    async fn accept_one_with_ttl(
        listener: TcpListener,
        registry: Registry,
        timeout: Duration,
        registration_ttl: Duration,
    ) -> io::Result<()> {
        let (stream, peer_addr) = listener.accept().await?;
        handle_connection_with_timeouts(
            stream,
            peer_addr,
            registry,
            Arc::new(AtomicUsize::new(0)),
            timeout,
            timeout,
            registration_ttl,
        )
        .await
    }

    fn route_with_capacity(capacity: usize) -> (OutboundRoute, mpsc::Receiver<QueuedRelayMessage>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            OutboundRoute {
                tx,
                connection_bytes: Arc::new(AtomicUsize::new(0)),
                global_bytes: Arc::new(AtomicUsize::new(0)),
            },
            rx,
        )
    }

    #[test]
    fn relay_metrics_render_coarse_privacy_safe_values() {
        let runtime = RelayRuntime::new();
        let rendered = runtime.metrics().render_openmetrics();

        assert!(rendered.contains("yadorilink_relay_active_sessions"));
        assert!(rendered.contains("yadorilink_relay_active_sources"));
        assert!(rendered.contains("yadorilink_relay_queued_outbound_bytes"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("device"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("path"));
    }

    async fn complete_relay_handshake(client: &mut TcpStream, secret: &StaticSecret) {
        let public = PublicKey::from(secret);
        crate::relay_io::write_relay_message(
            client,
            &RelayMessage {
                payload: Some(Payload::Hello(Hello { public_key: public.to_bytes().to_vec() })),
            },
        )
        .await
        .unwrap();
        let challenge = crate::relay_io::read_relay_message(client).await.unwrap();
        let Some(RelayMessage { payload: Some(Payload::HelloChallenge(challenge)) }) = challenge
        else {
            panic!("expected relay hello challenge");
        };
        let server_public_key: [u8; 32] =
            challenge.server_public_key.as_slice().try_into().unwrap();
        let server_public_key = PublicKey::from(server_public_key);
        let proof = crate::relay_auth::proof_mac(secret, &server_public_key, &challenge.nonce)
            .expect("test relay server's challenge key is a valid contributory X25519 point");
        crate::relay_io::write_relay_message(
            client,
            &RelayMessage { payload: Some(Payload::HelloProof(HelloProof { mac: proof })) },
        )
        .await
        .unwrap();
    }

    #[test]
    fn source_connection_guard_enforces_per_source_limit_and_releases_on_drop() {
        let counts: SourceConnectionCounts = Arc::new(Mutex::new(HashMap::new()));
        let source: IpAddr = "127.0.0.1".parse().unwrap();
        let mut guards = Vec::new();

        for _ in 0..MAX_CONNECTIONS_PER_SOURCE {
            guards.push(SourceConnectionGuard::try_acquire(source, counts.clone()).unwrap());
        }
        assert!(SourceConnectionGuard::try_acquire(source, counts.clone()).is_none());

        guards.pop();
        assert!(SourceConnectionGuard::try_acquire(source, counts).is_some());
    }

    #[test]
    fn register_route_enforces_registered_key_limit() {
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let (route_a, _rx_a) = route_with_capacity(1);
        let (route_b, _rx_b) = route_with_capacity(1);

        assert!(register_route(&registry, [1u8; 32], route_a, 1));
        assert!(!register_route(&registry, [2u8; 32], route_b, 1));
        assert_eq!(registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len(), 1);
    }

    #[test]
    fn register_route_rejects_live_key_reregistration() {
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let (route_a, _rx_a) = route_with_capacity(1);
        let (route_b, _rx_b) = route_with_capacity(1);

        assert!(register_route(&registry, [1u8; 32], route_a, 2));
        assert!(!register_route(&registry, [1u8; 32], route_b, 2));
        assert_eq!(registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len(), 1);
    }

    #[test]
    fn queue_relay_message_drops_when_channel_is_full() {
        let (route, _rx) = route_with_capacity(1);
        let message = RelayMessage {
            payload: Some(Payload::Forwarded(Forwarded {
                from_public_key: [1u8; 32].to_vec(),
                payload: vec![2u8; 64],
            })),
        };

        assert!(queue_relay_message(&route, message.clone()));
        assert!(!queue_relay_message(&route, message));
        assert!(route.connection_bytes.load(Ordering::Relaxed) > 0);
        assert_eq!(
            route.connection_bytes.load(Ordering::Relaxed),
            route.global_bytes.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn queue_relay_message_enforces_connection_byte_limit() {
        let (route, _rx) = route_with_capacity(OUTBOUND_QUEUE_CAPACITY);
        let message = RelayMessage {
            payload: Some(Payload::Forwarded(Forwarded {
                from_public_key: [1u8; 32].to_vec(),
                payload: vec![2u8; MAX_OUTBOUND_BYTES_PER_CONNECTION],
            })),
        };

        assert!(!queue_relay_message(&route, message));
        assert_eq!(route.connection_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(route.global_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn connection_without_hello_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let server = tokio::spawn(accept_one(listener, registry, Duration::from_millis(50)));

        let _client = TcpStream::connect(addr).await.unwrap();

        let err = server.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn idle_registered_connection_times_out_and_unregisters() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let server_registry = registry.clone();
        let server = tokio::spawn(accept_one(listener, server_registry, Duration::from_millis(50)));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let secret = StaticSecret::from([7u8; 32]);
        complete_relay_handshake(&mut client, &secret).await;
        let ack = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(matches!(ack, Some(RelayMessage { payload: Some(Payload::HelloAck(_)) })));

        let err = server.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    #[tokio::test]
    async fn registration_requires_valid_public_key_proof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let server = tokio::spawn(accept_one(listener, registry.clone(), Duration::from_secs(1)));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let secret = StaticSecret::from([9u8; 32]);
        let public = PublicKey::from(&secret);
        crate::relay_io::write_relay_message(
            &mut client,
            &RelayMessage {
                payload: Some(Payload::Hello(Hello { public_key: public.to_bytes().to_vec() })),
            },
        )
        .await
        .unwrap();
        let challenge = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(matches!(
            challenge,
            Some(RelayMessage { payload: Some(Payload::HelloChallenge(_)) })
        ));
        crate::relay_io::write_relay_message(
            &mut client,
            &RelayMessage { payload: Some(Payload::HelloProof(HelloProof { mac: vec![0u8; 32] })) },
        )
        .await
        .unwrap();

        let err = server.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }

    /// a `Forward` sent by a registered device to another
    /// registered device's public key must be delivered as a `Forwarded`
    /// frame with the sender's key attached.
    #[tokio::test]
    async fn dispatch_delivers_forward_to_registered_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(listener).await;
        });

        let secret_a = StaticSecret::from([61u8; 32]);
        let secret_b = StaticSecret::from([62u8; 32]);
        let key_a = PublicKey::from(&secret_a).to_bytes();
        let key_b = PublicKey::from(&secret_b).to_bytes();

        let mut client_a = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_a, &secret_a).await;
        let ack_a = crate::relay_io::read_relay_message(&mut client_a).await.unwrap();
        assert!(matches!(ack_a, Some(RelayMessage { payload: Some(Payload::HelloAck(_)) })));

        let mut client_b = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_b, &secret_b).await;
        let ack_b = crate::relay_io::read_relay_message(&mut client_b).await.unwrap();
        assert!(matches!(ack_b, Some(RelayMessage { payload: Some(Payload::HelloAck(_)) })));

        crate::relay_io::write_relay_message(
            &mut client_a,
            &RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: key_b.to_vec(),
                    payload: b"hello b".to_vec(),
                })),
            },
        )
        .await
        .unwrap();

        let received = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay_io::read_relay_message(&mut client_b),
        )
        .await
        .unwrap()
        .unwrap();
        match received {
            Some(RelayMessage { payload: Some(Payload::Forwarded(f)) }) => {
                assert_eq!(f.from_public_key, key_a.to_vec());
                assert_eq!(f.payload, b"hello b");
            }
            other => panic!("expected a Forwarded frame, got {other:?}"),
        }
    }

    /// Absent-dest behavior: a `Forward` addressed to a
    /// public key nobody has registered must be silently dropped —
    /// neither erroring nor killing the sender's connection — matching
    /// the documented behavior at the point the destination lookup
    /// happens (see the `None` branch in `handle_connection_with_timeouts`).
    #[tokio::test]
    async fn forward_to_unregistered_destination_is_dropped_without_disrupting_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve(listener).await;
        });

        let secret_a = StaticSecret::from([63u8; 32]);
        let secret_c = StaticSecret::from([65u8; 32]);
        let key_c = PublicKey::from(&secret_c).to_bytes();
        // Never connected/registered — a plausible-looking but absent
        // destination key.
        let unregistered_key = PublicKey::from(&StaticSecret::from([64u8; 32])).to_bytes();

        let mut client_a = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_a, &secret_a).await;
        let _ack_a = crate::relay_io::read_relay_message(&mut client_a).await.unwrap();

        crate::relay_io::write_relay_message(
            &mut client_a,
            &RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: unregistered_key.to_vec(),
                    payload: b"nobody home".to_vec(),
                })),
            },
        )
        .await
        .unwrap();

        // Prove the connection survived the absent-dest send by using it
        // for a real, deliverable Forward right afterwards.
        let mut client_c = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_c, &secret_c).await;
        let _ack_c = crate::relay_io::read_relay_message(&mut client_c).await.unwrap();

        crate::relay_io::write_relay_message(
            &mut client_a,
            &RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: key_c.to_vec(),
                    payload: b"still alive".to_vec(),
                })),
            },
        )
        .await
        .unwrap();

        let received = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay_io::read_relay_message(&mut client_c),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(received, Some(RelayMessage { payload: Some(Payload::Forwarded(_)) })));
    }

    /// Removal-on-disconnect: once a registered connection
    /// disconnects cleanly (not just via the idle timeout already covered
    /// by `idle_registered_connection_times_out_and_unregisters`), its
    /// route must be removed from the registry so a stale entry doesn't
    /// keep pointing at a dead connection (the exact leak this whole
    /// change targets — reliability hardening/reliability hardening's theme applied to the relay).
    #[tokio::test]
    async fn route_is_removed_when_connection_disconnects_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let server_registry = registry.clone();
        let server = tokio::spawn(accept_one(listener, server_registry, Duration::from_secs(5)));

        let secret = StaticSecret::from([66u8; 32]);
        let key = PublicKey::from(&secret).to_bytes();
        let mut client = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client, &secret).await;
        let _ack = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key));

        drop(client); // clean disconnect, not a timeout

        let result = server.await.unwrap();
        assert!(result.is_ok(), "a graceful client disconnect must resolve Ok, not an error");
        assert!(
            registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty(),
            "the route must be removed once its owning connection disconnects"
        );
    }

    /// Spawns a background accept loop on `listener`, registering each
    /// accepted connection into the shared `registry` with the next TTL
    /// popped from `ttls` (falling back to the production `REGISTRATION_TTL`
    /// once exhausted). Lets a test give one connection a short registration
    /// TTL while its counterpart(s) keep a normal one, so only the intended
    /// connection's registration actually lapses.
    fn spawn_registry_server(listener: TcpListener, registry: Registry, ttls: Vec<Duration>) {
        let ttls = Arc::new(Mutex::new(std::collections::VecDeque::from(ttls)));
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer_addr)) = listener.accept().await else { break };
                let registry = registry.clone();
                let ttl = ttls
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .pop_front()
                    .unwrap_or(REGISTRATION_TTL);
                tokio::spawn(async move {
                    let _ = handle_connection_with_timeouts(
                        stream,
                        peer_addr,
                        registry,
                        Arc::new(AtomicUsize::new(0)),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                        ttl,
                    )
                    .await;
                });
            }
        });
    }

    /// a registration that isn't renewed within its TTL is
    /// dropped — the connection is closed (distinct error from the
    /// pre-existing idle-read timeout, proven here by using a TTL far
    /// shorter than the generous idle timeout) and the registry entry is
    /// removed, exactly like the existing timeout/disconnect paths.
    #[tokio::test]
    async fn unrenewed_registration_is_dropped_once_its_ttl_elapses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let server_registry = registry.clone();
        // idle_timeout is generous (5s) so the TTL, not the idle-read
        // timeout, is what ends this connection.
        let server = tokio::spawn(accept_one_with_ttl(
            listener,
            server_registry,
            Duration::from_secs(5),
            Duration::from_millis(50),
        ));

        let secret = StaticSecret::from([91u8; 32]);
        let key = PublicKey::from(&secret).to_bytes();
        let mut client = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client, &secret).await;
        let _ack = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key));

        let err = server.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty(),
            "an unrenewed registration must be dropped once its TTL elapses"
        );
    }

    /// a client that re-proves key ownership (renews) before its
    /// registration's TTL elapses stays registered — proven by waiting past
    /// what the *original* (pre-renewal) deadline would have been and
    /// confirming traffic is still routed to it.
    #[tokio::test]
    async fn renewing_before_ttl_expiry_keeps_registration_live() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let short_ttl = Duration::from_millis(500);
        // First accepted connection (the one under test) gets the short
        // TTL; its partner keeps the production default so only the
        // renewal behavior under test is exercised.
        spawn_registry_server(listener, registry.clone(), vec![short_ttl]);

        let secret_under_test = StaticSecret::from([92u8; 32]);
        let key_under_test = PublicKey::from(&secret_under_test).to_bytes();
        let secret_partner = StaticSecret::from([93u8; 32]);

        let mut client_under_test = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_under_test, &secret_under_test).await;
        let _ack = crate::relay_io::read_relay_message(&mut client_under_test).await.unwrap();

        let mut client_partner = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_partner, &secret_partner).await;
        let _ack = crate::relay_io::read_relay_message(&mut client_partner).await.unwrap();

        // Renew partway through the original TTL window.
        tokio::time::sleep(Duration::from_millis(200)).await;
        crate::relay_io::write_relay_message(
            &mut client_under_test,
            &RelayMessage {
                payload: Some(Payload::Hello(Hello { public_key: key_under_test.to_vec() })),
            },
        )
        .await
        .unwrap();
        let challenge = crate::relay_io::read_relay_message(&mut client_under_test).await.unwrap();
        let Some(RelayMessage { payload: Some(Payload::HelloChallenge(challenge)) }) = challenge
        else {
            panic!("expected a renewal HelloChallenge, got {challenge:?}");
        };
        let server_public_key: [u8; 32] =
            challenge.server_public_key.as_slice().try_into().unwrap();
        let server_public_key = PublicKey::from(server_public_key);
        let proof =
            crate::relay_auth::proof_mac(&secret_under_test, &server_public_key, &challenge.nonce)
                .expect("test relay's renewal challenge key is a valid contributory X25519 point");
        crate::relay_io::write_relay_message(
            &mut client_under_test,
            &RelayMessage { payload: Some(Payload::HelloProof(HelloProof { mac: proof })) },
        )
        .await
        .unwrap();

        // Wait past what the *original* (pre-renewal) deadline would have
        // been (500ms from registration), but well inside the renewed one
        // (200ms + 500ms = 700ms from registration).
        tokio::time::sleep(Duration::from_millis(400)).await;

        crate::relay_io::write_relay_message(
            &mut client_partner,
            &RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: key_under_test.to_vec(),
                    payload: b"still registered".to_vec(),
                })),
            },
        )
        .await
        .unwrap();

        let received = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay_io::read_relay_message(&mut client_under_test),
        )
        .await
        .unwrap()
        .unwrap();
        match received {
            Some(RelayMessage { payload: Some(Payload::Forwarded(f)) }) => {
                assert_eq!(f.payload, b"still registered");
            }
            other => {
                panic!("expected the renewed registration to still receive forwards, got {other:?}")
            }
        }
    }

    /// once a registration's TTL has lapsed without renewal, the
    /// relay's dispatch behavior for that (now-expired) key must be
    /// identical to its behavior for a key that was never registered at
    /// all — both silently dropped, neither disrupting the sender's
    /// connection.
    #[tokio::test]
    async fn expired_registration_dispatch_behavior_matches_never_registered_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let short_ttl = Duration::from_millis(150);
        // First accepted connection (the one that will expire) gets the
        // short TTL; the sender and control connections, accepted later,
        // fall back to the production default.
        spawn_registry_server(listener, registry.clone(), vec![short_ttl]);

        let secret_expiring = StaticSecret::from([94u8; 32]);
        let key_expiring = PublicKey::from(&secret_expiring).to_bytes();
        let secret_sender = StaticSecret::from([95u8; 32]);
        let secret_control = StaticSecret::from([96u8; 32]);
        let key_control = PublicKey::from(&secret_control).to_bytes();
        let never_registered_key = PublicKey::from(&StaticSecret::from([97u8; 32])).to_bytes();

        let mut client_expiring = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_expiring, &secret_expiring).await;
        let _ack = crate::relay_io::read_relay_message(&mut client_expiring).await.unwrap();
        assert!(registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key_expiring));

        // Let the TTL lapse without ever renewing.
        tokio::time::sleep(short_ttl * 3).await;
        assert!(
            !registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&key_expiring),
            "the registration must have been dropped once its TTL elapsed"
        );

        let mut client_sender = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_sender, &secret_sender).await;
        let _ack = crate::relay_io::read_relay_message(&mut client_sender).await.unwrap();

        // A Forward to the now-expired key and one to a key that was never
        // registered at all must both be silently dropped, identically —
        // neither errors, neither disrupts the sender's connection.
        for dest in [key_expiring, never_registered_key] {
            crate::relay_io::write_relay_message(
                &mut client_sender,
                &RelayMessage {
                    payload: Some(Payload::Forward(Forward {
                        dest_public_key: dest.to_vec(),
                        payload: b"nobody home".to_vec(),
                    })),
                },
            )
            .await
            .unwrap();
        }

        // Prove the sender's connection survived both absent-dest sends by
        // using it for a real, deliverable Forward right afterwards.
        let mut client_control = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client_control, &secret_control).await;
        let _ack = crate::relay_io::read_relay_message(&mut client_control).await.unwrap();

        crate::relay_io::write_relay_message(
            &mut client_sender,
            &RelayMessage {
                payload: Some(Payload::Forward(Forward {
                    dest_public_key: key_control.to_vec(),
                    payload: b"still alive".to_vec(),
                })),
            },
        )
        .await
        .unwrap();

        let received = tokio::time::timeout(
            Duration::from_secs(2),
            crate::relay_io::read_relay_message(&mut client_control),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(received, Some(RelayMessage { payload: Some(Payload::Forwarded(_)) })));
    }

    /// A renewal proof that doesn't verify (wrong key/secret) must fail
    /// closed — the connection is dropped and the registration removed —
    /// reusing `relay_auth::verify_proof`'s hardened checks rather than a
    /// separate, less-scrutinized renewal path (the rationale for
    /// reusing the existing proof mechanism).
    #[tokio::test]
    async fn renewal_with_invalid_proof_drops_the_connection_and_registration() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
        let server_registry = registry.clone();
        let server = tokio::spawn(accept_one_with_ttl(
            listener,
            server_registry,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));

        let secret = StaticSecret::from([98u8; 32]);
        let key = PublicKey::from(&secret).to_bytes();
        let mut client = TcpStream::connect(addr).await.unwrap();
        complete_relay_handshake(&mut client, &secret).await;
        let _ack = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key));

        crate::relay_io::write_relay_message(
            &mut client,
            &RelayMessage { payload: Some(Payload::Hello(Hello { public_key: key.to_vec() })) },
        )
        .await
        .unwrap();
        let challenge = crate::relay_io::read_relay_message(&mut client).await.unwrap();
        assert!(matches!(
            challenge,
            Some(RelayMessage { payload: Some(Payload::HelloChallenge(_)) })
        ));
        crate::relay_io::write_relay_message(
            &mut client,
            &RelayMessage { payload: Some(Payload::HelloProof(HelloProof { mac: vec![0u8; 32] })) },
        )
        .await
        .unwrap();

        let err = server.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
    }
}
