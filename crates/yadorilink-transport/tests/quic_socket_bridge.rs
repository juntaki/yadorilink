//! Proves a real `quinn` stack runs over `TransportHubQuicSocket` -- the
//! same code, the same handshake and the same streams, natively and under
//! deterministic simulation.
//!
//! This is the load-bearing check for sharing one UDP socket between QUIC,
//! STUN and the relay envelope. A prior bulk-transport module (since
//! removed) avoided the question by binding a second port, which the real
//! mesh cannot do without asking every NAT in the path for a second
//! mapping.
//!
//! Deliberately one test body with two entry points rather than two tests.
//! A simulation-only substitute for QUIC would make the deterministic build
//! green while proving nothing about the transport it is supposed to be
//! exercising, so the simulator gets the genuine stack or nothing.
//!
//! Peer authentication here is ordinary TLS server-certificate verification
//! against a root store holding exactly the certificate the server presents
//! -- not a bypassed verifier. This bridge is not the layer that decides
//! *which* peer may connect; that is the raw-public-key identity work, and
//! it replaces this configuration wholesale.

use std::net::SocketAddr;
use std::sync::Arc;

use yadorilink_transport::{HubQuinnRuntime, TransportHub, TransportHubQuicSocket};

const TEST_SERVER_NAME: &str = "yadorilink-quic-bridge-test";
const ALPN: &[u8] = b"yadorilink-bridge-test/1";
/// Large enough to span many packets and exercise flow control and
/// acknowledgement, rather than fitting in a single datagram and proving
/// only that the handshake worked.
const PAYLOAD_LEN: usize = 64 * 1024;

/// A hub bound on loopback, plus the QUIC socket sharing it.
async fn hub_socket() -> (Arc<TransportHub>, Arc<TransportHubQuicSocket>, SocketAddr) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback");
    let hub = TransportHub::from_socket(socket);
    let addr = hub.local_addr();
    let quic = TransportHubQuicSocket::new(hub.clone()).expect("one QUIC endpoint per hub");
    (hub, quic, addr)
}

fn tls_material(
) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec![TEST_SERVER_NAME.to_string()])
        .expect("generate self-signed certificate");
    let cert = certified.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    (cert, key)
}

fn server_config(
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> quinn::ServerConfig {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config");
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("server QUIC/TLS config"),
    ))
}

fn client_config(cert: rustls::pki_types::CertificateDer<'static>) -> quinn::ClientConfig {
    // Real verification against a root store containing exactly this
    // certificate -- the handshake genuinely checks the signature and the
    // name, it is just anchored at the certificate under test.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("trust the test certificate");
    let mut crypto =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("client QUIC/TLS config"),
    ))
}

async fn stream_transfer_over_the_hub() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (_server_hub, server_quic, server_addr) = hub_socket().await;
    let (_client_hub, client_quic, _client_addr) = hub_socket().await;
    let (cert, key) = tls_material();

    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config(cert.clone(), key)),
        server_quic,
        Arc::new(HubQuinnRuntime),
    )
    .expect("server endpoint over the hub");

    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        client_quic,
        Arc::new(HubQuinnRuntime),
    )
    .expect("client endpoint over the hub");
    client.set_default_client_config(client_config(cert));

    // Echo the request back so the test observes bytes travelling in both
    // directions over the same connection, not just client to server.
    let responder = tokio::spawn(async move {
        let connection = server.accept().await.expect("incoming connection").await.expect("accept");
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept_bi");
        let received = recv.read_to_end(PAYLOAD_LEN).await.expect("read request");
        send.write_all(&received).await.expect("write response");
        send.finish().expect("finish response");
        // Hold the connection open until the client has read the response;
        // dropping it here would close the connection underneath the
        // in-flight stream and race the client's read.
        connection.closed().await;
        received.len()
    });

    let connection =
        client.connect(server_addr, TEST_SERVER_NAME).expect("dial").await.expect("handshake");
    let (mut send, mut recv) = connection.open_bi().await.expect("open_bi");
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    send.write_all(&payload).await.expect("write request");
    send.finish().expect("finish request");

    let echoed = recv.read_to_end(PAYLOAD_LEN).await.expect("read response");
    assert_eq!(echoed.len(), PAYLOAD_LEN, "response length");
    assert_eq!(echoed, payload, "response bytes round-tripped unchanged");

    connection.close(0u32.into(), b"done");
    let served = responder.await.expect("responder task");
    assert_eq!(served, PAYLOAD_LEN);
}

#[cfg(not(madsim))]
#[tokio::test]
async fn quic_completes_a_bidirectional_stream_transfer_over_the_transport_hub() {
    stream_transfer_over_the_hub().await;
}

#[cfg(madsim)]
#[test]
fn quic_completes_a_bidirectional_stream_transfer_over_the_transport_hub() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(stream_transfer_over_the_hub());
}

/// The QUIC arm is last in the demux for a reason: it must take only the
/// genuine remainder. If it could claim a STUN response or a relay
/// envelope, NAT discovery and relayed traffic would break in a way that
/// looks like packet loss rather than misrouting -- and, in the other
/// direction, if STUN could claim a datagram on shape alone it would
/// swallow the occasional QUIC packet that happens to carry STUN's magic
/// cookie in the same position.
async fn demux_classification() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind hub");
    let hub = TransportHub::from_socket(socket);
    let hub_addr = hub.local_addr();
    let _stun_inbound = hub.register_stun();
    let mut quic_inbound = hub.register_quic().expect("the first registration on a fresh hub");

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
    let sender_addr = sender.local_addr().expect("sender addr");
    let send = |bytes: Vec<u8>| {
        let sender = &sender;
        async move {
            #[cfg(not(madsim))]
            sender.send_to(&bytes, hub_addr).await.expect("send");
            #[cfg(madsim)]
            sender.send_to(hub_addr, &bytes).await.expect("send");
        }
    };
    let stun_response = |txn: [u8; 12]| {
        let mut message = vec![0u8; 20];
        message[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        message[2..4].copy_from_slice(&0u16.to_be_bytes());
        message[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        message[8..20].copy_from_slice(&txn);
        message
    };

    // A STUN response to a binding request this hub actually sent: claimed
    // by the STUN arm, never offered to QUIC.
    let pending_txn = [3u8; 12];
    hub.register_stun_txn(pending_txn);
    send(stun_response(pending_txn)).await;

    // A relay envelope wrapping a QUIC packet. Its payload does reach the
    // QUIC arm -- that is what relaying is for -- but under the synthetic
    // address minted for that relay session, never under the address it
    // physically arrived from, which belongs to the relaying device rather
    // than to the peer.
    let relayed_payload = [0xC0u8, 0x00, 0x00, 0x00, 0x01];
    let mut relayed = vec![0x00, 0xFF, 0xFF, 0xFF];
    relayed.extend_from_slice(&42u64.to_le_bytes());
    relayed.extend_from_slice(&relayed_payload);
    send(relayed).await;

    let (received, from) =
        tokio::time::timeout(std::time::Duration::from_secs(5), quic_inbound.recv())
            .await
            .expect("a relayed payload should reach the QUIC arm")
            .expect("demux queue open");
    assert_eq!(received, relayed_payload, "the envelope is stripped, the payload is not");
    assert_ne!(
        from, sender_addr,
        "the relaying device's own address must never be presented as the peer's"
    );
    assert!(
        yadorilink_transport::is_synthetic_relay_addr(from),
        "a relayed payload must arrive under a synthetic relay address, got {from}"
    );

    // A QUIC long-header packet: the fixed bit 0x40 in byte 0 keeps it
    // outside the relay envelope's marker (byte 0 `0x00`) and outside
    // STUN's `byte0 & 0xC0 == 0`, so it belongs to the QUIC arm.
    let quic_shaped = vec![0xC3, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC];
    send(quic_shaped.clone()).await;

    let (received, from) =
        tokio::time::timeout(std::time::Duration::from_secs(5), quic_inbound.recv())
            .await
            .expect("a QUIC-shaped datagram should reach the QUIC arm")
            .expect("demux queue open");
    assert_eq!(received, quic_shaped, "the QUIC arm received exactly the QUIC-shaped datagram");
    assert_eq!(from, sender_addr, "source address preserved");
    assert!(
        quic_inbound.try_recv().is_err(),
        "the answered STUN response must not reach the QUIC arm"
    );

    // The other direction: STUN's shape check is only two leading zero bits
    // plus the magic cookie, which a genuine QUIC packet matches roughly
    // once in 2^32. Such a datagram carries a transaction id this device
    // never sent, so STUN must decline it and let it continue to QUIC --
    // otherwise those packets would vanish as unexplained loss.
    let unclaimed = stun_response([9u8; 12]);
    send(unclaimed.clone()).await;
    let (received, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), quic_inbound.recv())
            .await
            .expect("a STUN-shaped datagram with an unknown transaction must not be swallowed")
            .expect("demux queue open");
    assert_eq!(received, unclaimed, "STUN declined it, so QUIC got it intact");
}
#[cfg(not(madsim))]
#[tokio::test]
async fn each_protocol_sharing_the_socket_claims_only_its_own_datagrams() {
    demux_classification().await;
}

#[cfg(madsim)]
#[test]
fn each_protocol_sharing_the_socket_claims_only_its_own_datagrams() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(demux_classification());
}

/// One endpoint per device is an architecture invariant, so a second
/// registration on the same hub is refused rather than silently replacing
/// the first.
///
/// Replacement is the dangerous outcome, which is why this is checked rather
/// than documented: the stranded endpoint keeps every connection it holds
/// and simply stops receiving on all of them. Nothing errors, nothing
/// closes, traffic just stops in one direction -- about the hardest failure
/// shape there is to diagnose from the outside.
///
/// A registration whose receiver has been dropped is not a conflict: the
/// endpoint it belonged to is gone, so the hub can serve a new one.
async fn a_hub_serves_exactly_one_quic_endpoint() {
    let (hub, first, _addr) = hub_socket().await;

    assert!(
        TransportHubQuicSocket::new(hub.clone()).is_err(),
        "a second QUIC endpoint on one hub must be refused, not allowed to strand the first"
    );

    drop(first);
    assert!(
        TransportHubQuicSocket::new(hub).is_ok(),
        "once the previous endpoint is gone, the hub can serve a new one"
    );
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_second_quic_endpoint_on_one_hub_is_refused() {
    a_hub_serves_exactly_one_quic_endpoint().await;
}

#[cfg(madsim)]
#[test]
fn a_second_quic_endpoint_on_one_hub_is_refused() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_hub_serves_exactly_one_quic_endpoint());
}

/// Two blocked pollers both get woken when capacity returns.
///
/// quinn creates a poller per caller that needs write readiness -- that is
/// what `create_io_poller` is for -- so several can be waiting on one
/// device's send path at once. Keeping a single waker would mean the second
/// one to block overwrites the first, and when capacity freed only the last
/// registered would be woken; the other would stay parked until something
/// unrelated happened to poll it. That is a stall, not a slowdown, and it
/// gets likelier the more connections a device has, which is the direction
/// the connectivity work goes.
///
/// Both pollers are registered with no `.await` between them, so the writer
/// task cannot drain in the middle and make the test pass by accident.
///
/// Simulation-only, because this backpressure is: natively, write readiness
/// comes from the kernel socket, which registers each poller's waker itself.
#[cfg(madsim)]
async fn every_blocked_poller_is_woken_when_capacity_returns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;
    use std::task::{Context, Poll, Wake, Waker};

    use quinn::AsyncUdpSocket;

    /// A waker that only records that it fired.
    struct RecordingWaker(AtomicBool);
    impl Wake for RecordingWaker {
        fn wake(self: StdArc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &StdArc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let (hub, socket, _addr) = hub_socket().await;
    // A destination nothing reads, so nothing outside this test relieves the
    // pressure it builds.
    let destination: SocketAddr = "127.0.0.1:9".parse().unwrap();

    let mut poller_a = socket.clone().create_io_poller();
    let mut poller_b = socket.clone().create_io_poller();
    let record_a = StdArc::new(RecordingWaker(AtomicBool::new(false)));
    let record_b = StdArc::new(RecordingWaker(AtomicBool::new(false)));
    let waker_a = Waker::from(record_a.clone());
    let waker_b = Waker::from(record_b.clone());

    // From here to the two `poll_writable` calls there is no `.await`, so
    // the writer task cannot run and free capacity in between.
    let datagram = vec![0xC0u8; 1200];
    let mut filled = 0;
    loop {
        let transmit = quinn::udp::Transmit {
            destination,
            ecn: None,
            contents: &datagram,
            segment_size: None,
            src_ip: None,
        };
        match socket.try_send(&transmit) {
            Ok(()) => filled += 1,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("unexpected send error: {error}"),
        }
        assert!(filled < 100_000, "the simulated send queue must be bounded");
    }
    assert!(filled > 0, "the queue must accept something before it refuses");

    assert!(
        matches!(
            poller_a.as_mut().poll_writable(&mut Context::from_waker(&waker_a)),
            Poll::Pending
        ),
        "a full queue must report not-writable"
    );
    assert!(
        matches!(
            poller_b.as_mut().poll_writable(&mut Context::from_waker(&waker_b)),
            Poll::Pending
        ),
        "a full queue must report not-writable to a SECOND poller too"
    );
    assert!(!record_a.0.load(Ordering::SeqCst));
    assert!(!record_b.0.load(Ordering::SeqCst));

    // Now let the writer task run and take datagrams off the queue.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !(record_a.0.load(Ordering::SeqCst) && record_b.0.load(Ordering::SeqCst)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "both pollers must be woken once capacity returns -- a={}, b={}",
            record_a.0.load(Ordering::SeqCst),
            record_b.0.load(Ordering::SeqCst)
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    drop(hub);
}

#[cfg(madsim)]
#[test]
fn a_freed_send_slot_wakes_every_blocked_poller() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(every_blocked_poller_is_woken_when_capacity_returns());
}
