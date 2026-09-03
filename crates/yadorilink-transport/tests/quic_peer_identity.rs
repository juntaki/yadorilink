//! Proves that a QUIC connection between two hubs is authenticated in both
//! directions by the devices' Ed25519 signing keys, and refused when either
//! direction's expectation is not met.
//!
//! The four refusal cases matter more than the success case. A handshake that
//! succeeds proves the wiring exists; only the refusals prove it is load
//! bearing. In particular the *client*-authentication case is checked
//! explicitly: TLS authenticates the server by default, so a configuration
//! that has quietly stopped requiring a client key still completes every
//! handshake and still moves data, and nothing but a test that presents an
//! unauthorized client would notice. Since nothing above this transport
//! re-encrypts, that omission would be handing plaintext file content to an
//! unauthenticated caller.
//!
//! Two entry points per test body, as in `quic_socket_bridge.rs`: the
//! deterministic simulator runs the same real quinn/rustls stack as the
//! native build, never a substitute.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_transport::{
    device_certified_key, quic_client_config, quic_server_config, AuthorizedPeerKeys,
    DeviceSigningKeyPair, HubQuinnRuntime, PinnedPeerKeys, TransportHub, TransportHubQuicSocket,
    PEER_SERVER_NAME, YADORILINK_P2P_ALPN,
};

/// Large enough to span several packets, so the success case exercises a
/// stream rather than only the handshake that opened it.
const PAYLOAD_LEN: usize = 32 * 1024;

/// Generous, and only ever a backstop. Every case here is expected to reach a
/// decision within one handshake; the timeout exists so that a direction that
/// silently stalls fails the test instead of hanging it, and the outcome
/// records which it was so a stall cannot be mistaken for a refusal.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// A hub bound on loopback, plus the QUIC socket sharing it.
async fn hub_socket() -> (Arc<TransportHub>, Arc<TransportHubQuicSocket>, SocketAddr) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback");
    let hub = TransportHub::from_socket(socket);
    let addr = hub.local_addr();
    let quic = TransportHubQuicSocket::new(hub.clone()).expect("one QUIC endpoint per hub");
    (hub, quic, addr)
}

/// What one side of an attempt ended up doing.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The full exchange completed: handshake, stream, bytes back.
    Exchanged,
    /// The connection was refused or torn down.
    Refused,
    /// Neither happened inside [`ATTEMPT_TIMEOUT`].
    Stalled,
}

impl Outcome {
    fn refused(&self, direction: &str) {
        assert_eq!(*self, Outcome::Refused, "{direction} must refuse the connection");
    }
}

/// Runs one connection attempt end to end and reports what each side saw.
///
/// Both sides are reported because a rejection is only convincing when the
/// side doing the rejecting is the side that was supposed to. A client whose
/// stream read fails could be failing for its own reasons; paired with a
/// server that refused, it is the same event seen twice.
async fn attempt(
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
) -> (Outcome, Outcome) {
    let (_server_hub, server_quic, server_addr) = hub_socket().await;
    let (_client_hub, client_quic, _client_addr) = hub_socket().await;

    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
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
    client.set_default_client_config(client_config);

    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();

    let serving = tokio::spawn(async move {
        let Some(incoming) = server.accept().await else {
            return Outcome::Refused;
        };
        let Ok(connection) = incoming.await else {
            return Outcome::Refused;
        };
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            return Outcome::Refused;
        };
        let Ok(received) = recv.read_to_end(PAYLOAD_LEN).await else {
            return Outcome::Refused;
        };
        if send.write_all(&received).await.is_err() || send.finish().is_err() {
            return Outcome::Refused;
        }
        // Hold the connection open until the client is done reading;
        // dropping it here would close it underneath the in-flight stream.
        connection.closed().await;
        Outcome::Exchanged
    });

    let expected = payload.clone();
    let dialing = async move {
        let Ok(dial) = client.connect(server_addr, PEER_SERVER_NAME) else {
            return Outcome::Refused;
        };
        let Ok(connection) = dial.await else {
            return Outcome::Refused;
        };
        let Ok((mut send, mut recv)) = connection.open_bi().await else {
            return Outcome::Refused;
        };
        if send.write_all(&payload).await.is_err() || send.finish().is_err() {
            return Outcome::Refused;
        }
        let Ok(echoed) = recv.read_to_end(PAYLOAD_LEN).await else {
            return Outcome::Refused;
        };
        connection.close(0u32.into(), b"done");
        assert_eq!(echoed, expected, "the echoed bytes must round-trip unchanged");
        Outcome::Exchanged
    };

    let client_outcome = match tokio::time::timeout(ATTEMPT_TIMEOUT, dialing).await {
        Ok(outcome) => outcome,
        Err(_) => Outcome::Stalled,
    };
    let server_outcome = match tokio::time::timeout(ATTEMPT_TIMEOUT, serving).await {
        Ok(joined) => joined.expect("server task"),
        Err(_) => Outcome::Stalled,
    };
    (client_outcome, server_outcome)
}

/// The success case: two devices that each hold the other's real signing key
/// complete the handshake and move bytes over a bidirectional stream.
///
/// Nothing here is pre-shared beyond the public keys the netmap already
/// distributes -- no certificate, no issuance step, no name.
async fn mutual_raw_public_keys_authenticate_both_directions() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();

    let (client, server) = attempt(
        quic_server_config(
            &server_device,
            &AuthorizedPeerKeys::with([client_device.public_bytes()]),
        )
        .expect("server config"),
        quic_client_config(&client_device, server_device.public_bytes()).expect("client config"),
    )
    .await;

    assert_eq!(client, Outcome::Exchanged, "client side of the exchange");
    assert_eq!(server, Outcome::Exchanged, "server side of the exchange");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_mutual_raw_public_key_handshake_carries_a_bidirectional_stream() {
    mutual_raw_public_keys_authenticate_both_directions().await;
}

#[cfg(madsim)]
#[test]
fn a_mutual_raw_public_key_handshake_carries_a_bidirectional_stream() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(mutual_raw_public_keys_authenticate_both_directions());
}

/// The dialer's half: a device that answers with a key other than the one
/// this dial was aimed at is refused, even though it holds a perfectly valid
/// signing key and completes the signature check over its own key.
///
/// This is the case that separates "the peer proved it owns a key" from "the
/// peer proved it owns *the* key", which is the only one of the two that
/// means anything.
async fn a_server_presenting_another_devices_key_is_refused() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();
    let someone_else = DeviceSigningKeyPair::generate();

    let (client, _server) = attempt(
        quic_server_config(
            &server_device,
            &AuthorizedPeerKeys::with([client_device.public_bytes()]),
        )
        .expect("server config"),
        quic_client_config(&client_device, someone_else.public_bytes()).expect("client config"),
    )
    .await;

    client.refused("the dialing client");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_server_key_the_client_did_not_expect_fails_the_handshake() {
    a_server_presenting_another_devices_key_is_refused().await;
}

#[cfg(madsim)]
#[test]
fn a_server_key_the_client_did_not_expect_fails_the_handshake() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_server_presenting_another_devices_key_is_refused());
}

/// The accepting half, and the one that is easy to leave unwired: a client
/// whose key is not in the server's authorized set is refused, and gets
/// nothing.
///
/// If the server had been built with client authentication off, this
/// connection would succeed and echo the payload back. The assertion on the
/// *client* outcome is therefore the substance of the test: it is what would
/// change if mutual authentication silently degraded to one-sided.
async fn a_client_outside_the_authorized_set_is_refused() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();
    let authorized_but_absent = DeviceSigningKeyPair::generate();

    let (client, server) = attempt(
        quic_server_config(
            &server_device,
            &AuthorizedPeerKeys::with([authorized_but_absent.public_bytes()]),
        )
        .expect("server config"),
        quic_client_config(&client_device, server_device.public_bytes()).expect("client config"),
    )
    .await;

    server.refused("the accepting server");
    client.refused("the client whose key was not authorized");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_client_key_the_server_did_not_expect_fails_the_handshake() {
    a_client_outside_the_authorized_set_is_refused().await;
}

#[cfg(madsim)]
#[test]
fn a_client_key_the_server_did_not_expect_fails_the_handshake() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_client_outside_the_authorized_set_is_refused());
}

/// A server that authorizes nobody accepts nobody -- including a client
/// holding a genuine, correctly signed device key.
///
/// The direction of this failure is the point. An endpoint whose expected set
/// has not been populated yet must be unreachable, not open: "we do not know
/// who is allowed" and "everyone is allowed" have to be different states, and
/// on the wire the only way to tell them apart is that the first one refuses.
async fn an_empty_authorized_set_accepts_nobody() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();

    let (client, server) = attempt(
        quic_server_config(&server_device, &AuthorizedPeerKeys::new()).expect("server config"),
        quic_client_config(&client_device, server_device.public_bytes()).expect("client config"),
    )
    .await;

    server.refused("a server authorizing nobody");
    client.refused("a client dialing a server that authorizes nobody");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_server_with_no_authorized_peers_fails_closed() {
    an_empty_authorized_set_accepts_nobody().await;
}

#[cfg(madsim)]
#[test]
fn a_server_with_no_authorized_peers_fails_closed() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(an_empty_authorized_set_accepts_nobody());
}

/// A peer of another protocol generation is refused during the handshake,
/// before any application frame exists -- even though both devices hold each
/// other's keys and both would pass every identity check.
///
/// The stand-in for "another generation" is assembled from the same public
/// pieces the shipped configuration uses, with only the ALPN differing,
/// because that is exactly what a future generation's build would be.
fn client_config_of_another_generation(
    device: &DeviceSigningKeyPair,
    expected_peer: [u8; 32],
    alpn: &[u8],
) -> quinn::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedPeerKeys::new([expected_peer], &provider));
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(device_certified_key(device)),
        ));
    crypto.alpn_protocols = vec![alpn.to_vec()];
    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("client QUIC/TLS config"),
    ))
}

async fn a_peer_of_another_generation_is_refused() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();

    let mut next_generation = YADORILINK_P2P_ALPN.to_vec();
    let last = next_generation.len() - 1;
    next_generation[last] += 1;
    assert_ne!(next_generation, YADORILINK_P2P_ALPN);

    let (client, server) = attempt(
        quic_server_config(
            &server_device,
            &AuthorizedPeerKeys::with([client_device.public_bytes()]),
        )
        .expect("server config"),
        client_config_of_another_generation(
            &client_device,
            server_device.public_bytes(),
            &next_generation,
        ),
    )
    .await;

    client.refused("a client speaking another generation");
    server.refused("a server offered another generation");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn a_mismatched_alpn_fails_the_handshake() {
    a_peer_of_another_generation_is_refused().await;
}

#[cfg(madsim)]
#[test]
fn a_mismatched_alpn_fails_the_handshake() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_peer_of_another_generation_is_refused());
}

/// Revocation, on an endpoint that is never rebuilt.
///
/// This is the case a construction-time snapshot of the authorized set gets
/// wrong, and gets wrong silently: every one of the tests above would still
/// pass, because each of them builds its server configuration immediately
/// before the single connection it makes. Here one server endpoint serves two
/// connections with a `revoke` in between, which is the real shape -- a
/// device's endpoint is built once at startup and outlives every netmap push
/// that follows.
///
/// Rebuilding the endpoint to apply a revocation is not an alternative that
/// merely costs more: it would tear down every *other* peer's live connection
/// through the same endpoint in order to withdraw one key.
///
/// Each attempt exchanges bytes rather than stopping at the handshake, for
/// the same reason `a_client_outside_the_authorized_set_is_refused` does:
/// under TLS 1.3 the client reaches its own "handshake complete" before the
/// server has processed the client certificate, so a dial that resolves is
/// not yet evidence the server accepted it. What the server did shows up on
/// the first stream.
async fn a_key_revoked_from_the_live_set_is_refused_next_time() {
    let server_device = DeviceSigningKeyPair::generate();
    let client_device = DeviceSigningKeyPair::generate();

    // The live set, held by the harness exactly as a device's orchestrator
    // holds its own.
    let authorized = AuthorizedPeerKeys::with([client_device.public_bytes()]);

    let (_server_hub, server_quic, server_addr) = hub_socket().await;
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(quic_server_config(&server_device, &authorized).expect("server config")),
        server_quic,
        Arc::new(HubQuinnRuntime),
    )
    .expect("server endpoint over the hub");

    // Echoes whatever arrives, for as long as anything does, and reports how
    // many connections got as far as moving bytes. Nothing about the server
    // side changes between the two dials except the set.
    let accepting = server.clone();
    let serving = tokio::spawn(async move {
        let mut served = 0usize;
        while let Some(incoming) = accepting.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                continue;
            };
            let Ok(received) = recv.read_to_end(PAYLOAD_LEN).await else {
                continue;
            };
            if send.write_all(&received).await.is_err() || send.finish().is_err() {
                continue;
            }
            served += 1;
            connection.closed().await;
        }
        served
    });

    let exchange = |client_config: quinn::ClientConfig| async move {
        let (_client_hub, client_quic, _addr) = hub_socket().await;
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            client_quic,
            Arc::new(HubQuinnRuntime),
        )
        .expect("client endpoint over the hub");
        client.set_default_client_config(client_config);

        let attempt = async {
            let Ok(dialing) = client.connect(server_addr, PEER_SERVER_NAME) else {
                return Outcome::Refused;
            };
            let Ok(connection) = dialing.await else {
                return Outcome::Refused;
            };
            let Ok((mut send, mut recv)) = connection.open_bi().await else {
                return Outcome::Refused;
            };
            let payload = vec![0x5Au8; PAYLOAD_LEN];
            if send.write_all(&payload).await.is_err() || send.finish().is_err() {
                return Outcome::Refused;
            }
            let Ok(echoed) = recv.read_to_end(PAYLOAD_LEN).await else {
                return Outcome::Refused;
            };
            connection.close(0u32.into(), b"done");
            assert_eq!(echoed, payload, "the echoed bytes must round-trip unchanged");
            Outcome::Exchanged
        };
        match tokio::time::timeout(ATTEMPT_TIMEOUT, attempt).await {
            Ok(outcome) => outcome,
            Err(_) => Outcome::Stalled,
        }
    };

    let first =
        exchange(quic_client_config(&client_device, server_device.public_bytes()).expect("config"))
            .await;
    assert_eq!(first, Outcome::Exchanged, "an authorized client connects and is served");

    // The netmap no longer lists this device. No endpoint is rebuilt, no
    // configuration is replaced, and the server task above is still the same
    // one.
    assert!(authorized.revoke(&client_device.public_bytes()), "was authorized");

    let second =
        exchange(quic_client_config(&client_device, server_device.public_bytes()).expect("config"))
            .await;
    second.refused("a client whose key was revoked from the live set");

    server.close(0u32.into(), b"test over");
    let served = tokio::time::timeout(ATTEMPT_TIMEOUT, serving)
        .await
        .expect("the server task ends once the endpoint closes")
        .expect("server task");
    assert_eq!(served, 1, "only the pre-revocation client was served");
}

#[cfg(not(madsim))]
#[tokio::test]
async fn revoking_a_key_refuses_the_next_connection_without_rebuilding_the_endpoint() {
    a_key_revoked_from_the_live_set_is_refused_next_time().await;
}

#[cfg(madsim)]
#[test]
fn revoking_a_key_refuses_the_next_connection_without_rebuilding_the_endpoint() {
    let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
    rt.block_on(a_key_revoked_from_the_live_set_is_refused_next_time());
}
