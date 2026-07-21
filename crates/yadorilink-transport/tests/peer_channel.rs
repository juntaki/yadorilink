use std::net::SocketAddr;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::time::timeout;
use yadorilink_transport::{PeerChannel, PeerReachability};

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn recv_within(channel: &PeerChannel, d: Duration) -> Vec<u8> {
    timeout(d, channel.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed unexpectedly")
}

/// p2p-transport spec: "Direct connection succeeds" — exercised with a
/// known loopback candidate on each side.
#[tokio::test]
async fn direct_path_delivers_messages_both_ways() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    // Bind each device's shared socket first, and hand each one into its own
    // PeerChannel, so each side's advertised candidate address exactly matches
    // the socket the channel actually uses (see `PeerChannel::connect`'s
    // `shared` parameter).
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();

    a.send(b"direct hello".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"direct hello");

    b.send(b"direct reply".to_vec()).await.unwrap();
    let received = recv_within(&a, Duration::from_secs(5)).await;
    assert_eq!(received, b"direct reply");

    // Both sides confirm an authenticated direct path over the loopback
    // candidate shortly after the first exchange.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if matches!(a.reachability(), PeerReachability::Connected { .. })
            && matches!(b.reachability(), PeerReachability::Connected { .. })
        {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("channels never reached the connected state");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Application messages larger than one WireGuard datagram must be
/// transparently fragmented and reassembled over the direct path.
#[tokio::test]
async fn large_message_is_fragmented_and_reassembled() {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();

    // Warm up with small messages first, then upgrade to reliable delivery,
    // before sending the large payload. A 128 KiB message fragments into
    // ~110 UDP datagrams (1200 bytes/fragment); the reassembler only
    // completes a message once every one of its fragments has arrived, so
    // sending it immediately over plain (non-reliable) UDP -- while the
    // WireGuard handshake itself is still in flight -- makes this
    // integration test hostage to a single dropped datagram out of ~110,
    // with nothing to retransmit it. Pure fragmentation/reassembly logic
    // (including out-of-order arrival) is already covered directly by
    // `framing::tests::fragment_and_reassemble_roundtrip`; this test only
    // needs to prove it also works end-to-end over a real channel, which
    // doesn't require exercising loss-sensitive plain UDP delivery too.
    a.send(b"warmup".to_vec()).await.unwrap();
    assert_eq!(recv_within(&b, Duration::from_secs(5)).await, b"warmup");
    b.send(b"warmup-ack".to_vec()).await.unwrap();
    assert_eq!(recv_within(&a, Duration::from_secs(5)).await, b"warmup-ack");

    a.enable_reliable_delivery();
    b.enable_reliable_delivery();

    let big_payload = vec![0x42u8; 128 * 1024]; // matches the sync-engine's default block size
    a.send(big_payload.clone()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(10)).await;
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
        secret_a,
        public_b,
        0,
        vec![bogus_candidate, addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();

    a.send(b"reach me anyway".to_vec()).await.unwrap();
    let received = recv_within(&b, Duration::from_secs(5)).await;
    assert_eq!(received, b"reach me anyway");
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
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
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
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
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
