//! The gate that decides whether turmoil can host this project's real peer
//! transport, rather than a substitute for it.
//!
//! Two devices, each with its own `TransportHub` and `QuicPeerEndpoint`,
//! complete a genuine quinn/rustls handshake and exchange framed messages.
//! Nothing here is a fake: the same `QuicPeerEndpoint::connect`/`accept` and
//! the same `QuicPeerChannel` framing production uses, over the same
//! `AsyncUdpSocket` bridge. The only thing that differs from the native
//! build is which `UdpSocket` type the hub was compiled against, which is
//! `yadorilink_transport::sim_net`'s entire job.
//!
//! # Why each device gets its own host
//!
//! turmoil delivers a datagram directly, with no latency and no exposure to
//! partitions or drops, whenever the destination is loopback or the source
//! and destination share an IP (`turmoil::host::is_same`). Two devices bound
//! on `127.0.0.1`, the way the native test binds them, would therefore
//! produce a test that passes without a single byte crossing the simulated
//! network -- a green result that establishes nothing about the substrate.
//! One host per device is what puts the link in between.
//!
//! Only built under `RUSTFLAGS="--cfg turmoil"`.

#![cfg(turmoil)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::sim_net::UdpSocket;
use yadorilink_transport::{
    connect_role, ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint,
    TransportHub,
};

/// Both hosts bind this, since the peer's address has to be agreed before
/// either side runs and an ephemeral port could not be.
const PEER_PORT: u16 = 9000;

/// Generous, and only ever a backstop: every step below resolves within one
/// handshake and one round trip of simulated time. It exists so a direction
/// that stalls fails the test instead of hanging it.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Chosen so `connect_role` makes the client the dialer: it sorts before
/// `server`, and the smaller id dials.
const CLIENT_ID: &str = "device-a-client";
const SERVER_ID: &str = "device-b-server";

async fn endpoint_on_this_host(signing: DeviceSigningKeyPair) -> Arc<QuicPeerEndpoint> {
    // Unspecified rather than a literal host IP: turmoil fills in the
    // current host's address, and an explicit loopback would opt this test
    // straight out of the simulated network it exists to exercise.
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PEER_PORT);
    let socket = UdpSocket::bind(bind).await.expect("bind this host's peer port");
    let hub = TransportHub::from_socket(socket);
    QuicPeerEndpoint::new(hub, signing).expect("device endpoint")
}

/// One dial, one accept, one message each way, with the payload large
/// enough that it cannot ride a single datagram -- so the framing is
/// genuinely reassembling a byte stream that crossed the simulated link,
/// not passing through one packet.
#[test]
fn two_hosts_exchange_framed_messages_over_a_real_quic_connection() {
    let mut sim = turmoil::Builder::new()
        .rng_seed(0x9C_10_5E)
        .simulation_duration(Duration::from_secs(60))
        .build();

    // Identities are generated outside the simulation so each side can
    // authorize the other before either host starts running.
    let client_signing = DeviceSigningKeyPair::generate();
    let server_signing = DeviceSigningKeyPair::generate();
    let client_public = client_signing.public_bytes();
    let server_public = server_signing.public_bytes();

    assert_eq!(
        connect_role(CLIENT_ID, SERVER_ID),
        ConnectRole::Dial,
        "this test's host names decide which side dials, so the ordering has to be pinned"
    );

    let server_signing = std::sync::Mutex::new(Some(server_signing));
    sim.host("server", move || {
        // `host` takes an `Fn`, because turmoil may restart a host. This
        // one is never restarted, and a second start would need a second
        // identity anyway, so taking the key is the honest encoding of
        // "starts once" -- a restart panics here rather than silently
        // running with a different identity than the client authorized.
        let signing = server_signing.lock().expect("server identity lock").take();
        async move {
            let signing = signing.expect("the server host is started exactly once");
            let endpoint = endpoint_on_this_host(signing).await;
            endpoint.authorize(client_public);

            let connection = endpoint.accept(client_public).await.expect("an inbound connection");
            let channel = QuicPeerChannel::new(connection, ConnectRole::Accept);

            let received = channel.recv().await.expect("the client's message");
            // Echoed back with a marker, so the client's assertion proves
            // the round trip rather than just its own send.
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&received);
            channel.send(reply).await.expect("the reply must send");

            // Held open: dropping the channel here would close the
            // connection before the reply had crossed the link.
            std::future::pending::<()>().await;
            Ok(())
        }
    });

    sim.client("device-a-client", async move {
        let endpoint = endpoint_on_this_host(client_signing).await;
        endpoint.authorize(server_public);

        let server_addr = SocketAddr::new(turmoil::lookup("server"), PEER_PORT);
        let connection =
            tokio::time::timeout(STEP_TIMEOUT, endpoint.connect(server_addr, server_public))
                .await
                .expect("the dial must resolve")
                .expect("the dial must succeed");
        let channel = QuicPeerChannel::new(connection, ConnectRole::Dial);

        // Two MTUs' worth and then some: this cannot arrive as one datagram.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        channel.send(payload.clone()).await.expect("the message must send");

        let reply = tokio::time::timeout(STEP_TIMEOUT, channel.recv())
            .await
            .expect("the reply must arrive")
            .expect("the channel must not close before the reply");

        let mut expected = b"echo:".to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(
            reply.len(),
            expected.len(),
            "the reply lost its message boundary crossing the simulated link"
        );
        assert_eq!(reply, expected, "the reply's bytes did not survive the round trip");
        Ok(())
    });

    sim.run().expect("the simulation must complete");
}

/// The negative control the test above needs to mean anything.
///
/// A green round trip does not by itself prove the bytes crossed the
/// simulated link -- turmoil short-circuits delivery for loopback and
/// same-IP traffic, so a misconfigured test would pass exactly as happily
/// while bypassing the network model entirely. Here the two hosts are
/// partitioned before the dial, and the dial must fail. If it succeeds,
/// turmoil is not carrying this transport's datagrams and neither is any
/// fault this harness might later inject.
#[test]
fn a_partition_stops_the_handshake_which_is_what_proves_the_link_is_real() {
    let mut sim = turmoil::Builder::new()
        .rng_seed(0x9C_10_5E)
        .simulation_duration(Duration::from_secs(30))
        .build();

    let client_signing = DeviceSigningKeyPair::generate();
    let server_signing = DeviceSigningKeyPair::generate();
    let client_public = client_signing.public_bytes();
    let server_public = server_signing.public_bytes();

    let server_signing = std::sync::Mutex::new(Some(server_signing));
    sim.host("server", move || {
        let signing = server_signing.lock().expect("server identity lock").take();
        async move {
            let endpoint = endpoint_on_this_host(signing.expect("started exactly once")).await;
            endpoint.authorize(client_public);
            // Parked on the accept that must never complete.
            let _ = endpoint.accept(client_public).await;
            std::future::pending::<()>().await;
            Ok(())
        }
    });

    sim.client("device-a-client", async move {
        let endpoint = endpoint_on_this_host(client_signing).await;
        endpoint.authorize(server_public);

        turmoil::partition("device-a-client", "server");

        let server_addr = SocketAddr::new(turmoil::lookup("server"), PEER_PORT);
        let outcome =
            tokio::time::timeout(STEP_TIMEOUT, endpoint.connect(server_addr, server_public)).await;

        match outcome {
            // Either shape is a correct refusal: quinn may give up on its
            // own before this test's backstop fires, or not. What must not
            // happen is a connection.
            Err(_elapsed) => {}
            Ok(Err(_refused)) => {}
            Ok(Ok(_connected)) => panic!(
                "the handshake completed across a partition, so these datagrams are not \
                 travelling over turmoil's simulated network -- every fault this harness \
                 injects would be silently ignored"
            ),
        }
        Ok(())
    });

    sim.run().expect("the simulation must complete");
}
