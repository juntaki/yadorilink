#![cfg(test)]

use super::*;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A registry with the QUIC arm registered, so a test can assert what
/// reached it -- which is now the demux's whole "everything else" case.
fn registry_with_quic() -> (DemuxRegistry, mpsc::Receiver<(Vec<u8>, SocketAddr)>) {
    let registry = DemuxRegistry::new(addr("127.0.0.1:41641"));
    let (tx, rx) = mpsc::channel(8);
    *registry.quic_tx.lock().unwrap() = Some(tx);
    (registry, rx)
}

/// Every received datagram reaches the QUIC endpoint registered on the
/// socket, with its source address intact.
#[tokio::test]
async fn every_datagram_reaches_the_quic_endpoint() {
    let (registry, mut quic_rx) = registry_with_quic();
    registry.route(&[0xC0u8; 64], addr("203.0.113.9:1234"));
    let (datagram, from) = quic_rx.try_recv().expect("the datagram goes to QUIC");
    assert_eq!(datagram, vec![0xC0u8; 64]);
    assert_eq!(from, addr("203.0.113.9:1234"));
}

// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn endpoint_selects_socket_by_destination_family() {
    let v4 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let endpoint = UdpEndpoint { v4: Some(v4), v6: None, batching: UdpBatchingSupport::detect() };
    // A v4 destination resolves to the v4 socket.
    assert!(endpoint.socket_for(addr("127.0.0.1:9")).is_ok());
    // A v6 destination with no v6 half is a clean "no socket for family".
    let err = endpoint.socket_for("[::1]:9".parse().unwrap()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
}

// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn bind_yields_a_stable_port_and_a_v4_half() {
    let hub =
        TransportHub::bind((std::net::Ipv4Addr::UNSPECIFIED, 0).into()).await.expect("bind hub");
    assert_ne!(hub.local_port(), 0);
    // The v4 half is always present, so a v4 send never hits the
    // "no socket for family" path (it may still fail to route, but not for
    // lack of a socket).
    assert!(hub.endpoint.v4.is_some());
    // The v6 half is present whenever the host could bind it on the same
    // port; when it is, it shares the v4 half's port.
    if let Some(v6) = hub.endpoint.v6.as_ref() {
        assert_eq!(v6.local_addr().unwrap().port(), hub.local_port());
    }
}
