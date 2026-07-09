use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::TcpListener;
use tokio::time::timeout;
use yadorilink_transport::{PathKind, PeerChannel, RelayHub, TransportMode};

async fn start_relay() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = yadorilink_transport::relay_server::serve(listener).await;
    });
    addr
}

async fn relay_hub(relay_addr: SocketAddr, secret: StaticSecret) -> Arc<RelayHub> {
    RelayHub::connect(relay_addr, secret).await.unwrap()
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn recv_within(channel: &PeerChannel, d: Duration) -> Vec<u8> {
    timeout(d, channel.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed unexpectedly")
}

/// p2p-transport spec: "Tunnel established between authorized peers" and
/// "Relay used when direct connection fails" — exercised here with the
/// relay as the only available path.
#[tokio::test]
async fn forced_relay_path_delivers_messages_both_ways() {
    let relay_addr = start_relay().await;
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let hub_a = relay_hub(relay_addr, secret_a.clone()).await;
    let hub_b = relay_hub(relay_addr, secret_b.clone()).await;

    let a = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_a,
        public_b,
        0,
        Some(hub_a),
        vec![],
        None,
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_b,
        public_a,
        1,
        Some(hub_b),
        vec![],
        None,
    )
    .await
    .unwrap();

    a.send(b"hello from a".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"hello from a");

    b.send(b"hello from b".to_vec()).await.unwrap();
    let received = recv_within(&a, Duration::from_secs(5)).await;
    assert_eq!(received, b"hello from b");

    assert_eq!(a.current_path(), PathKind::Relay);
    assert_eq!(b.current_path(), PathKind::Relay);
}

/// p2p-transport spec: "Direct connection succeeds" — exercised with a
/// known loopback candidate and no relay at all.
#[tokio::test]
async fn forced_direct_path_delivers_messages_both_ways() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    // Bind both sockets first, and hand each one into its own PeerChannel,
    // so each side's advertised candidate address exactly matches the
    // socket the channel actually uses (see `PeerChannel::connect`'s
    // `direct_socket` parameter).
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_a,
        public_b,
        0,
        None,
        vec![addr_b],
        Some(socket_a),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_b,
        public_a,
        1,
        None,
        vec![addr_a],
        Some(socket_b),
    )
    .await
    .unwrap();

    a.send(b"direct hello".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"direct hello");

    assert_eq!(a.current_path(), PathKind::Direct);
    assert_eq!(b.current_path(), PathKind::Direct);
}

/// p2p-transport spec: "Session upgrades from relay to direct" — starts
/// relay-only (always works) and confirms the channel transparently
/// switches once the direct loopback path becomes reachable.
#[tokio::test]
async fn auto_mode_upgrades_from_relay_to_direct() {
    let relay_addr = start_relay().await;
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let hub_a = relay_hub(relay_addr, secret_a.clone()).await;
    let hub_b = relay_hub(relay_addr, secret_b.clone()).await;

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        TransportMode::Auto,
        secret_a,
        public_b,
        0,
        Some(hub_a),
        vec![addr_b],
        Some(socket_a),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::Auto,
        secret_b,
        public_a,
        1,
        Some(hub_b),
        vec![addr_a],
        Some(socket_b),
    )
    .await
    .unwrap();

    assert_eq!(a.current_path(), PathKind::Relay);

    a.send(b"upgrade me".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"upgrade me");

    // The direct-probe/keepalive cycle should establish the direct path
    // shortly after connecting on loopback.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if a.current_path() == PathKind::Direct && b.current_path() == PathKind::Direct {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("channels never upgraded to direct path");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Application messages larger than one WireGuard datagram must be
/// transparently fragmented and reassembled.
#[tokio::test]
async fn large_message_is_fragmented_and_reassembled() {
    let relay_addr = start_relay().await;
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let hub_a = relay_hub(relay_addr, secret_a.clone()).await;
    let hub_b = relay_hub(relay_addr, secret_b.clone()).await;

    let a = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_a,
        public_b,
        0,
        Some(hub_a),
        vec![],
        None,
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_b,
        public_a,
        1,
        Some(hub_b),
        vec![],
        None,
    )
    .await
    .unwrap();

    let big_payload = vec![0x42u8; 128 * 1024]; // matches the sync-engine's default block size
    a.send(big_payload.clone()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, big_payload);
}

/// p2p-transport spec: "Unreachable local candidate does not block other
/// candidates" — a bogus first candidate (part of the concurrent
/// candidate-racing scheme) must not prevent connecting via a working
/// one listed alongside it.
#[tokio::test]
async fn unreachable_candidate_does_not_block_a_working_one() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // TEST-NET-3 (RFC 5737): reserved for documentation, guaranteed
    // unreachable/non-routable, so this simulates a candidate address that
    // never answers without depending on real network failure behavior.
    let bogus_candidate: SocketAddr = "203.0.113.1:41641".parse().unwrap();

    let a = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_a,
        public_b,
        0,
        None,
        vec![bogus_candidate, addr_b],
        Some(socket_a),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_b,
        public_a,
        1,
        None,
        vec![addr_a],
        Some(socket_b),
    )
    .await
    .unwrap();

    a.send(b"reach me anyway".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"reach me anyway");
}

/// Regression test for a real bug found via `yadorilink-daemon`'s 3-device
/// end-to-end test: a device with more than one peer must multiplex all
/// of its `PeerChannel`s over a single shared `RelayHub` connection.
/// Before the fix, each `PeerChannel` opened its own relay connection
/// under the same public key, and the relay server's one-connection-per-key
/// registry silently dropped the earlier connection's traffic.
#[tokio::test]
async fn one_device_can_relay_to_two_peers_simultaneously() {
    let relay_addr = start_relay().await;
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    let (secret_c, public_c) = gen_keypair();

    // Device A has exactly one relay hub, shared across both its peers.
    let hub_a = relay_hub(relay_addr, secret_a.clone()).await;
    let hub_b = relay_hub(relay_addr, secret_b.clone()).await;
    let hub_c = relay_hub(relay_addr, secret_c.clone()).await;

    let a_to_b = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_a.clone(),
        public_b,
        0,
        Some(hub_a.clone()),
        vec![],
        None,
    )
    .await
    .unwrap();
    let a_to_c = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_a,
        public_c,
        1,
        Some(hub_a),
        vec![],
        None,
    )
    .await
    .unwrap();
    let b_to_a = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_b,
        public_a,
        2,
        Some(hub_b),
        vec![],
        None,
    )
    .await
    .unwrap();
    let c_to_a = PeerChannel::connect(
        TransportMode::RelayOnly,
        secret_c,
        public_a,
        3,
        Some(hub_c),
        vec![],
        None,
    )
    .await
    .unwrap();

    a_to_b.send(b"to B".to_vec()).await.unwrap();
    a_to_c.send(b"to C".to_vec()).await.unwrap();

    assert_eq!(recv_within(&b_to_a, Duration::from_secs(5)).await, b"to B");
    assert_eq!(recv_within(&c_to_a, Duration::from_secs(5)).await, b"to C");

    b_to_a.send(b"from B".to_vec()).await.unwrap();
    c_to_a.send(b"from C".to_vec()).await.unwrap();

    // Both replies must reach the correct one of A's two channels — proof
    // the shared hub demultiplexes by sender rather than only the most
    // recently registered connection winning.
    assert_eq!(recv_within(&a_to_b, Duration::from_secs(5)).await, b"from B");
    assert_eq!(recv_within(&a_to_c, Duration::from_secs(5)).await, b"from C");
}

/// Two upgraded peers (both call `enable_reliable_delivery`) still
/// exchange ordinary application messages correctly — the marker-byte
/// framing is transparent to the caller on
/// both sides (`PeerChannel::send`/`recv`'s signatures are unchanged).
#[tokio::test]
async fn two_reliable_delivery_enabled_peers_exchange_messages_normally() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_a,
        public_b,
        0,
        None,
        vec![addr_b],
        Some(socket_a),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_b,
        public_a,
        1,
        None,
        vec![addr_a],
        Some(socket_b),
    )
    .await
    .unwrap();

    a.enable_reliable_delivery();
    b.enable_reliable_delivery();

    a.send(b"reliable hello".to_vec()).await.unwrap();
    assert_eq!(recv_within(&b, Duration::from_secs(5)).await, b"reliable hello");

    b.send(b"reliable reply".to_vec()).await.unwrap();
    assert_eq!(recv_within(&a, Duration::from_secs(5)).await, b"reliable reply");

    // A second round trip in each direction — exercises seq advancing past
    // 1 and the ack piggybacked on the very next send, not just the first
    // message on a fresh connection.
    a.send(b"reliable hello 2".to_vec()).await.unwrap();
    assert_eq!(recv_within(&b, Duration::from_secs(5)).await, b"reliable hello 2");
    b.send(b"reliable reply 2".to_vec()).await.unwrap();
    assert_eq!(recv_within(&a, Duration::from_secs(5)).await, b"reliable reply 2");
}

/// The asymmetric negotiation window: device A has confirmed B's
/// capability and enabled reliable delivery (so its sends are now
/// marker-framed), while device B has NOT yet enabled its own
/// (simulating B's `ClusterConfig` round-trip not having
/// completed, or a genuinely un-upgraded peer that never will). B must
/// still correctly receive A's framed messages (decoding is always
/// format-agnostic — see `reliable.rs`'s module doc comment) and B's own
/// legacy (unwrapped) sends must still reach A normally.
#[tokio::test]
async fn asymmetric_reliable_delivery_window_does_not_break_delivery() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_a,
        public_b,
        0,
        None,
        vec![addr_b],
        Some(socket_a),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        TransportMode::DirectOnly,
        secret_b,
        public_a,
        1,
        None,
        vec![addr_a],
        Some(socket_b),
    )
    .await
    .unwrap();

    // Only A enables reliable delivery — B never does, for this whole test.
    a.enable_reliable_delivery();

    // A's marker-framed send must still be understood by B, which never
    // enabled the layer itself.
    a.send(b"framed from A".to_vec()).await.unwrap();
    assert_eq!(recv_within(&b, Duration::from_secs(5)).await, b"framed from A");

    // B's plain legacy send must still reach A normally alongside A's own
    // framed traffic on the same connection.
    b.send(b"legacy from B".to_vec()).await.unwrap();
    assert_eq!(recv_within(&a, Duration::from_secs(5)).await, b"legacy from B");

    // A second framed message from A (now past seq 1, with B's prior
    // legacy send having nothing to do with A's own ack bookkeeping) still
    // gets through — proof the asymmetric window doesn't wedge after the
    // first exchange.
    a.send(b"framed from A again".to_vec()).await.unwrap();
    assert_eq!(recv_within(&b, Duration::from_secs(5)).await, b"framed from A again");
}
