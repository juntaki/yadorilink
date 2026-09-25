#![cfg(test)]

use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;
use crate::transport_hub::TransportHub;

#[test]
fn to_hub_addr_unmaps_an_ipv4_mapped_ipv6_destination() {
    let mapped: SocketAddr = "[::ffff:192.168.0.200]:41641".parse().unwrap();
    let unmapped = to_hub_addr(mapped);
    assert_eq!(unmapped, "192.168.0.200:41641".parse::<SocketAddr>().unwrap());
    assert!(unmapped.is_ipv4());
}

#[test]
fn to_hub_addr_leaves_a_genuine_ipv6_destination_alone() {
    let addr: SocketAddr = "[2001:db8::1]:41641".parse().unwrap();
    assert_eq!(to_hub_addr(addr), addr);
}

#[test]
fn to_hub_addr_leaves_a_plain_ipv4_destination_alone() {
    let addr: SocketAddr = "192.168.0.200:41641".parse().unwrap();
    assert_eq!(to_hub_addr(addr), addr);
}

#[test]
fn to_quinn_addr_maps_ipv4_when_reporting_dual_stack() {
    let addr: SocketAddr = "192.168.0.200:41641".parse().unwrap();
    let mapped = to_quinn_addr(addr, true);
    assert_eq!(mapped, "[::ffff:192.168.0.200]:41641".parse::<SocketAddr>().unwrap());
    assert!(mapped.is_ipv6());
}

#[test]
fn to_quinn_addr_is_a_no_op_when_not_reporting_dual_stack() {
    let addr: SocketAddr = "192.168.0.200:41641".parse().unwrap();
    assert_eq!(to_quinn_addr(addr, false), addr);
}

#[test]
fn to_quinn_addr_leaves_a_genuine_ipv6_source_alone_either_way() {
    let addr: SocketAddr = "[2001:db8::1]:41641".parse().unwrap();
    assert_eq!(to_quinn_addr(addr, true), addr);
    assert_eq!(to_quinn_addr(addr, false), addr);
}

/// The regression this whole boundary exists to prevent, at the exact
/// seam where it would surface: a hub with NO IPv6 half
/// (`from_socket`'s single-socket adoption, matching a host with no
/// usable IPv6, or most integration test fixtures) must keep reporting
/// a plain IPv4 `local_addr` to quinn -- claiming dual-stack here would
/// tell quinn to normalize every address into IPv4-mapped-IPv6 form for
/// an endpoint that has no IPv6 socket to send that form out on.
// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn an_ipv4_only_hub_does_not_claim_ipv6_capability() {
    let socket = crate::sim_net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let hub = TransportHub::from_socket(socket);
    assert!(!hub.has_ipv6(), "test setup: from_socket must not fabricate a v6 half");

    let quic_socket = TransportHubQuicSocket::new(hub).expect("build the quic socket");
    let reported = AsyncUdpSocket::local_addr(quic_socket.as_ref()).expect("local_addr");
    assert!(
        reported.is_ipv4(),
        "an IPv4-only hub must report an IPv4 local_addr to quinn, got {reported}"
    );
}

/// The other half of the same invariant: a hub that DOES have a bound
/// IPv6 socket reports the dual-stack logical address, `[::]:port` --
/// this is what makes `quinn::Endpoint::new_with_abstract_socket` set
/// its internal `endpoint.ipv6 = true` and stop refusing IPv6 dials.
// Binds a real socket, so it is a native-only test: under either
// simulator the socket type belongs to a simulated world this test
// never enters. What it asserts -- dual-stack selection, port
// stability, ALPN routing on a real endpoint -- is about the
// operating system's sockets, which is exactly what a simulator
// does not model and does not need to.
#[cfg(not(turmoil))]
#[tokio::test]
async fn a_dual_stack_hub_reports_the_ipv6_logical_address() {
    let hub = TransportHub::bind((Ipv4Addr::LOCALHOST, 0).into()).await.expect("bind hub");
    assert!(
        hub.has_ipv6(),
        "this test requires a real dual-stack hub; if this fails in this environment, \
         IPv6 genuinely is not available here and this test's own premise does not hold"
    );
    let port = hub.local_addr().port();

    let quic_socket = TransportHubQuicSocket::new(hub).expect("build the quic socket");
    let reported = AsyncUdpSocket::local_addr(quic_socket.as_ref()).expect("local_addr");
    assert_eq!(
        reported,
        SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        "a dual-stack hub must report [::]:port to quinn"
    );
}
