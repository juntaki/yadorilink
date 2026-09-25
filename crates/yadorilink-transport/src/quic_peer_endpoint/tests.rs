#![cfg(test)]

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

/// A real end-to-end dial/accept/traffic round trip over one connection,
/// shared by the IPv4 and IPv6 variants below -- proves more than "a
/// handshake happened": an established-then-immediately-closed
/// connection fails this.
async fn assert_connects_and_carries_traffic(
    dialler: &QuicPeerEndpoint,
    acceptor: &QuicPeerEndpoint,
    acceptor_addr: SocketAddr,
    acceptor_key: [u8; 32],
    dialler_key: [u8; 32],
    marker: &[u8; 8],
) {
    let connection =
        tokio::time::timeout(Duration::from_secs(10), dialler.connect(acceptor_addr, acceptor_key))
            .await
            .unwrap_or_else(|_| panic!("dial to {acceptor_addr} must not hang"))
            .unwrap_or_else(|e| panic!("dial to {acceptor_addr} must succeed: {e}"));

    let claimed = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(dialler_key))
        .await
        .expect("accept must resolve")
        .expect("the accepted connection must be handed to the session");

    let (mut send, _recv) = connection.open_bi().await.expect("open a stream");
    send.write_all(marker).await.expect("write the marker");
    let (_send, mut recv) = tokio::time::timeout(Duration::from_secs(5), claimed.accept_bi())
        .await
        .expect("the accepted connection must carry traffic")
        .expect("stream");
    let mut carried = [0u8; 8];
    recv.read_exact(&mut carried).await.expect("read the marker");
    assert_eq!(&carried, marker);
}

/// Dedicated regression test for the dual-stack bridge: `quinn` refuses
/// every IPv6 dial outright, before ever reaching the transport hub's own
/// send path, if `TransportHubQuicSocket::local_addr` reports an IPv4
/// address on a hub with a real bound IPv6 half. `endpoint()`'s hub is bound via
/// `TransportHub::bind` on an IPv4 primary address, which -- per that
/// function's own doc comment -- ALSO binds a v6-only half whenever the
/// host has usable IPv6, making it a real dual-stack hub on any normal
/// dev/CI machine. `hub.local_addr()` only ever reports the IPv4 half,
/// so the peer's IPv6-reachable address is constructed directly here.
// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn a_dual_stack_endpoint_still_dials_a_peer_over_ipv6() {
    let (dialler, _dialler_addr, dialler_key) = endpoint().await;
    let (acceptor, acceptor_v4_addr, acceptor_key) = endpoint().await;
    dialler.authorize(acceptor_key);
    acceptor.authorize(dialler_key);

    let acceptor_v6_addr = SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        acceptor_v4_addr.port(),
    );

    assert_connects_and_carries_traffic(
        &dialler,
        &acceptor,
        acceptor_v6_addr,
        acceptor_key,
        dialler_key,
        b"via-ipv6",
    )
    .await;
}

/// The regression guard the IPv6 fix above specifically needs: a
/// dual-stack-reporting endpoint (the one `quinn` now believes may dial
/// IPv6) must not silently lose the ability to reach an ordinary IPv4
/// peer -- exactly the failure mode a naive `local_addr() -> [::]:port`
/// fix would introduce, since `quinn` then normalizes every IPv4
/// destination into IPv4-mapped-IPv6 form, and the transport hub's own
/// v4-vs-v6 socket selection (`SocketAddr::is_ipv4()`) answers `false`
/// for that mapped form unless it is unmapped again first. Also proves
/// requirement 3 (dial through accept through the selection preface) as
/// a side effect: `connect`/`accept` run the full announce/await
/// selection handshake internally, not a raw handshake shortcut.
// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn the_same_dual_stack_endpoint_still_dials_a_peer_over_ipv4() {
    let (dialler, _dialler_addr, dialler_key) = endpoint().await;
    let (acceptor, acceptor_addr, acceptor_key) = endpoint().await;
    dialler.authorize(acceptor_key);
    acceptor.authorize(dialler_key);

    assert_connects_and_carries_traffic(
        &dialler,
        &acceptor,
        acceptor_addr,
        acceptor_key,
        dialler_key,
        b"via-ipv4",
    )
    .await;
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
// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
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
