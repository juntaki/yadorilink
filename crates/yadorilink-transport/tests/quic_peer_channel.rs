//! Two devices, each with one `QuicPeerEndpoint` over its own transport hub,
//! exchanging framed control messages on a single connection -- natively and
//! under deterministic simulation.
//!
//! This is the layer between the authenticated handshake
//! (`quic_peer_identity.rs`) and a real sync session: it proves that the
//! device whose id sorts smaller dials, that the other side's `accept` hands
//! back that same connection, and that message boundaries survive a byte
//! stream in both directions.
//!
//! Two entry points per test body, as in the sibling QUIC tests: the
//! simulator runs the same real quinn/rustls stack as the native build,
//! never a substitute.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::{
    connect_role, ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint,
    TransportHub,
};

/// Generous, and only ever a backstop: every step below resolves within one
/// handshake and one round trip. It exists so a direction that stalls fails
/// the test instead of hanging it.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// One simulated device: its endpoint, its signing identity, and the address
/// peers dial.
struct Device {
    id: &'static str,
    endpoint: Arc<QuicPeerEndpoint>,
    public_key: [u8; 32],
    addr: SocketAddr,
}

async fn device(id: &'static str) -> Device {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback");
    let hub = TransportHub::from_socket(socket);
    let addr = hub.local_addr();
    let signing = DeviceSigningKeyPair::generate();
    let public_key = signing.public_bytes();
    let endpoint = QuicPeerEndpoint::new(hub, signing).expect("device endpoint");
    Device { id, endpoint, public_key, addr }
}

/// Opens the pair's one connection from whichever side the id ordering says
/// should dial, and returns a channel on each side.
async fn paired_channels(a: &Device, b: &Device) -> (Arc<QuicPeerChannel>, Arc<QuicPeerChannel>) {
    a.endpoint.authorize(b.public_key);
    b.endpoint.authorize(a.public_key);

    let a_role = connect_role(a.id, b.id);
    let b_role = connect_role(b.id, a.id);
    assert_ne!(a_role, b_role, "exactly one side of a pair dials");

    let (dialer, acceptor) = match a_role {
        ConnectRole::Dial => (a, b),
        ConnectRole::Accept => (b, a),
    };

    let accepting = {
        let endpoint = acceptor.endpoint.clone();
        let peer = dialer.public_key;
        tokio::spawn(async move { endpoint.accept(peer).await })
    };

    let dialed = tokio::time::timeout(
        STEP_TIMEOUT,
        dialer.endpoint.connect(acceptor.addr, acceptor.public_key),
    )
    .await
    .expect("the dial must resolve")
    .expect("the dial must succeed");
    let accepted = tokio::time::timeout(STEP_TIMEOUT, accepting)
        .await
        .expect("the accept must resolve")
        .expect("accept task")
        .expect("an inbound connection must arrive");

    let dialer_channel = QuicPeerChannel::new(dialed, ConnectRole::Dial);
    let acceptor_channel = QuicPeerChannel::new(accepted, ConnectRole::Accept);
    match a_role {
        ConnectRole::Dial => (dialer_channel, acceptor_channel),
        ConnectRole::Accept => (acceptor_channel, dialer_channel),
    }
}

async fn expect_recv(channel: &QuicPeerChannel, what: &str) -> Vec<u8> {
    tokio::time::timeout(STEP_TIMEOUT, channel.recv())
        .await
        .unwrap_or_else(|_| panic!("{what} never arrived"))
        .unwrap_or_else(|| panic!("the channel closed before {what} arrived"))
}

/// Messages keep their boundaries in both directions, including ones far
/// larger than a datagram (so the framing is genuinely reassembling a byte
/// stream rather than riding one packet per message) and ones of zero
/// length.
async fn messages_round_trip_with_their_boundaries_intact() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    let (channel_a, channel_b) = paired_channels(&a, &b).await;

    // Deliberately sent back to back, so a framing bug that read the stream
    // greedily would deliver them merged rather than as three messages.
    let small = b"cluster config stand-in".to_vec();
    let large: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
    let empty: Vec<u8> = Vec::new();
    for payload in [&small, &large, &empty] {
        channel_a.send(payload.clone()).await.expect("send from A");
    }

    assert_eq!(expect_recv(&channel_b, "the small message").await, small);
    assert_eq!(expect_recv(&channel_b, "the large message").await, large);
    assert_eq!(expect_recv(&channel_b, "the empty message").await, empty);

    // The reverse direction on the same connection and the same stream.
    let reply = b"and back the other way".to_vec();
    channel_b.send(reply.clone()).await.expect("send from B");
    assert_eq!(expect_recv(&channel_a, "the reply").await, reply);
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_quic_peer_channel_carries_messages_in_both_directions() {
    messages_round_trip_with_their_boundaries_intact().await;
}

#[cfg(madsim)]
#[test]
fn a_quic_peer_channel_carries_messages_in_both_directions() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(messages_round_trip_with_their_boundaries_intact());
}

/// `recv` reports the end of the connection as `None` rather than hanging,
/// which is what lets a session end and its supervisor reconnect instead of
/// parking forever on a peer that has gone away.
async fn a_closed_connection_ends_the_receive_side() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    let (channel_a, channel_b) = paired_channels(&a, &b).await;

    // One message first, so the control stream is genuinely established on
    // both sides before it is torn down -- otherwise this would only prove
    // that a stream that never existed reports nothing.
    channel_a.send(b"hello".to_vec()).await.expect("send from A");
    assert_eq!(expect_recv(&channel_b, "the first message").await, b"hello".to_vec());

    drop(channel_a);

    assert_eq!(
        tokio::time::timeout(STEP_TIMEOUT, channel_b.recv())
            .await
            .expect("recv must resolve rather than hang"),
        None,
        "a dropped peer channel must close the other side's receive half"
    );
}

#[cfg(not(madsim))]
#[tokio::test]
async fn dropping_one_end_closes_the_others_receive_half() {
    a_closed_connection_ends_the_receive_side().await;
}

#[cfg(madsim)]
#[test]
fn dropping_one_end_closes_the_others_receive_half() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_closed_connection_ends_the_receive_side());
}

/// A peer whose key was never authorized cannot open a channel at all: the
/// dial is refused during the handshake, so nothing reaches `accept`.
///
/// The assertion that matters is the *second* one. A refused dial alone
/// would also be produced by a client that simply failed; that no connection
/// is queued for the peer is what says the accepting endpoint refused it.
async fn an_unauthorized_peer_gets_no_channel() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    // Only one direction is authorized: A will talk to B, B will not talk to
    // A. A's dial therefore presents a client key B does not accept.
    a.endpoint.authorize(b.public_key);

    let accepting = {
        let endpoint = b.endpoint.clone();
        let peer = a.public_key;
        tokio::spawn(async move { endpoint.accept(peer).await })
    };

    let dialed = tokio::time::timeout(STEP_TIMEOUT, a.endpoint.connect(b.addr, b.public_key)).await;
    if let Ok(Ok(connection)) = dialed {
        // TLS 1.3 lets the client finish before the server has processed its
        // certificate, so a resolved dial is not yet acceptance. Using the
        // connection is where the refusal surfaces.
        let opened = tokio::time::timeout(STEP_TIMEOUT, connection.open_bi()).await;
        if let Ok(Ok((mut send, _recv))) = opened {
            assert!(
                send.write_all(b"should not be delivered").await.is_err()
                    || send.finish().is_err()
                    || tokio::time::timeout(STEP_TIMEOUT, connection.closed()).await.is_ok(),
                "an unauthorized dial must not end up with a usable stream"
            );
        }
    }

    // Nothing was queued for A on B's endpoint. Checked with a bounded wait
    // rather than instantly, so a connection that was merely slow to be
    // routed would still be caught.
    let queued = tokio::time::timeout(Duration::from_secs(2), accepting).await;
    assert!(
        queued.is_err(),
        "an unauthorized peer's connection must never reach the accepting side"
    );
}

#[cfg(not(madsim))]
#[tokio::test]
async fn an_unauthorized_dial_never_produces_an_accepted_connection() {
    an_unauthorized_peer_gets_no_channel().await;
}

#[cfg(madsim)]
#[test]
fn an_unauthorized_dial_never_produces_an_accepted_connection() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(an_unauthorized_peer_gets_no_channel());
}

/// Revoking a peer must stop the traffic on the connection it ALREADY has,
/// not merely refuse its next handshake.
///
/// Proven by exchanging application bytes, never by a handshake result.
/// Under TLS 1.3 the client reaches "handshake complete" before the server
/// has processed its certificate, so a dial resolving `Ok` says nothing
/// about acceptance -- a revocation test that asserted on the handshake
/// would pass for a revoked key while never exercising the control at all,
/// reporting a security mechanism as working precisely when it is not.
async fn revocation_stops_traffic_on_a_live_connection() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    let (channel_a, channel_b) = paired_channels(&a, &b).await;

    // Bytes cross first, so what follows is genuinely a revocation of a
    // working session rather than of one that never started.
    channel_a.send(b"before revocation".to_vec()).await.expect("send from A");
    assert_eq!(expect_recv(&channel_b, "the pre-revocation message").await, b"before revocation");

    // Stage one: B's key is withdrawn, so no future handshake from it is
    // accepted. Stage two: the connection it already has is ended. Neither
    // alone is revocation -- the first leaves the live session running, the
    // second just prompts a reconnect.
    a.endpoint.revoke_peer(&b.public_key);
    assert!(!a.endpoint.is_authorized(&b.public_key));
    channel_a.close_revoked();

    // The revoked side observes the session end rather than hanging.
    assert_eq!(
        tokio::time::timeout(STEP_TIMEOUT, channel_b.recv())
            .await
            .expect("recv must resolve rather than hang"),
        None,
        "a revoked peer's receive half must end"
    );

    // And nothing it sends afterwards reaches the other side. Sent through
    // the ordinary channel API, so this is the same path a session would
    // use, not a synthetic one.
    let _ = channel_b.send(b"after revocation".to_vec()).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), channel_a.recv()).await,
        Ok(None),
        "no application bytes may cross a revoked connection in either direction"
    );
}

#[cfg(not(madsim))]
#[tokio::test]
async fn revoking_a_peer_ends_its_live_session() {
    revocation_stops_traffic_on_a_live_connection().await;
}

#[cfg(madsim)]
#[test]
fn revoking_a_peer_ends_its_live_session() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(revocation_stops_traffic_on_a_live_connection());
}

/// A revoked peer that comes straight back cannot get application bytes
/// through either -- the other half of the same rule, and the reason the
/// withdrawal has to happen before the connection is closed rather than
/// after.
async fn a_revoked_peer_cannot_reconnect_into_a_working_session() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    let (channel_a, channel_b) = paired_channels(&a, &b).await;
    channel_a.send(b"before revocation".to_vec()).await.expect("send from A");
    assert_eq!(expect_recv(&channel_b, "the pre-revocation message").await, b"before revocation");

    a.endpoint.revoke_peer(&b.public_key);
    channel_a.close_revoked();
    drop(channel_b);

    // B redials. The dial itself may well resolve -- see this test module's
    // sibling above for why that proves nothing -- so the assertion is on
    // whether bytes arrive.
    let accepting = {
        let endpoint = a.endpoint.clone();
        let peer = b.public_key;
        tokio::spawn(async move { endpoint.accept(peer).await })
    };
    if let Ok(Ok(connection)) =
        tokio::time::timeout(STEP_TIMEOUT, b.endpoint.connect(a.addr, a.public_key)).await
    {
        let redialed = QuicPeerChannel::new(connection, ConnectRole::Dial);
        let _ = redialed.send(b"let me back in".to_vec()).await;
    }

    let queued = tokio::time::timeout(Duration::from_secs(2), accepting).await;
    assert!(queued.is_err(), "a revoked peer's reconnection must never reach the accepting side");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_revoked_peer_gets_no_working_reconnection() {
    a_revoked_peer_cannot_reconnect_into_a_working_session().await;
}

#[cfg(madsim)]
#[test]
fn a_revoked_peer_gets_no_working_reconnection() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_revoked_peer_cannot_reconnect_into_a_working_session());
}

/// One block request, one bidirectional stream, in both directions at once.
///
/// The exchange is deliberately run from BOTH sides of the same connection
/// simultaneously, because that is the case the stream accounting has to get
/// right: `accept_bi` yields only the streams the peer opened, so the
/// accepting side's first accepted stream is the control stream while the
/// dialling side's first accepted stream is already a block stream. A
/// version that assumed one rule for both roles would pass a one-directional
/// test and deadlock here.
///
/// The body is larger than a single QUIC packet and larger than the initial
/// stream flow-control window, so it exercises the writer actually waiting
/// on the reader rather than a payload that fits in one send.
async fn block_streams_carry_a_request_and_its_body_both_ways() {
    let a = device("device-a").await;
    let b = device("device-b").await;
    let (channel_a, channel_b) = paired_channels(&a, &b).await;

    /// Answers exactly one block request on `channel`, echoing the request
    /// header back as the response body so the test can assert the two ends
    /// of the exchange are the same stream.
    async fn serve_one(channel: Arc<QuicPeerChannel>, body: Vec<u8>) -> Vec<u8> {
        let mut stream = channel.accept_block_stream().await.expect("a block stream to serve");
        let request = stream
            .recv_message(yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES)
            .await
            .expect("the request header");
        stream.send_message(&(body.len() as u64).to_be_bytes()).await.expect("response header");
        stream.send_body(&body).await.expect("response body");
        request
    }

    async fn fetch(channel: Arc<QuicPeerChannel>, request: Vec<u8>) -> Vec<u8> {
        let mut stream = channel.open_block_stream().await.expect("open a block stream");
        stream.send_message(&request).await.expect("request header");
        stream.finish_send();
        let header = stream
            .recv_message(yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES)
            .await
            .expect("the response header");
        let declared = u64::from_be_bytes(header.try_into().expect("an eight-byte length"));
        stream.recv_body(declared as usize).await.expect("the response body")
    }

    let a_body: Vec<u8> = (0..600_000u32).map(|i| (i % 251) as u8).collect();
    let b_body: Vec<u8> = (0..600_000u32).map(|i| (i % 241) as u8).collect();

    let a_serving = tokio::spawn(serve_one(channel_a.clone(), a_body.clone()));
    let b_serving = tokio::spawn(serve_one(channel_b.clone(), b_body.clone()));
    let a_fetching = tokio::spawn(fetch(channel_a.clone(), b"request from A".to_vec()));
    let b_fetching = tokio::spawn(fetch(channel_b.clone(), b"request from B".to_vec()));

    let served_by_a = tokio::time::timeout(STEP_TIMEOUT, a_serving)
        .await
        .expect("A served its request in time")
        .expect("A's serving task");
    let served_by_b = tokio::time::timeout(STEP_TIMEOUT, b_serving)
        .await
        .expect("B served its request in time")
        .expect("B's serving task");
    let got_by_a = tokio::time::timeout(STEP_TIMEOUT, a_fetching)
        .await
        .expect("A's fetch completed in time")
        .expect("A's fetching task");
    let got_by_b = tokio::time::timeout(STEP_TIMEOUT, b_fetching)
        .await
        .expect("B's fetch completed in time")
        .expect("B's fetching task");

    assert_eq!(served_by_a, b"request from B", "A must see B's request header verbatim");
    assert_eq!(served_by_b, b"request from A", "B must see A's request header verbatim");
    assert_eq!(got_by_a, b_body, "A must read back exactly the body B wrote");
    assert_eq!(got_by_b, a_body, "B must read back exactly the body A wrote");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_block_stream_carries_one_request_and_its_body() {
    block_streams_carry_a_request_and_its_body_both_ways().await;
}

#[cfg(madsim)]
#[test]
fn a_block_stream_carries_one_request_and_its_body() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(block_streams_carry_a_request_and_its_body_both_ways());
}
