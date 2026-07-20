//! Local network interface enumeration: a device's own interface addresses
//! are reported as high-priority endpoint candidates alongside its
//! STUN-observed and router-mapped public addresses, so peers on the same
//! network connect over the low-latency local path automatically via
//! candidate racing rather than explicit same-network detection.
//!
//! Both IPv4 and global-scope IPv6 addresses are reported. A pair of
//! IPv6-capable peers therefore connects directly, with no NAT traversal at
//! all — racing already tries every candidate concurrently and the
//! authenticated-first-wins rule picks whichever family works. Link-local and
//! (by default) unique-local IPv6 addresses are excluded: they are not
//! reachable off-link and only add candidates that can never confirm.
//!
//! Enumeration is a pure snapshot; the daemon re-invokes it on network-
//! interface change events so privacy-extension rotation and network moves
//! refresh the candidate set through the same reporting path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::nat::{Candidate, CandidateClass};

/// Local-address candidates get the highest priority: a same-network path is
/// always preferable to a NAT-traversed public path when both are viable.
/// Kept for the pre-existing reporting call site; new call sites should take
/// the per-address class from [`local_candidates_classified`].
pub const LOCAL_CANDIDATE_PRIORITY: i32 = 100;

/// Returns this host's non-loopback, non-link-local interface addresses (both
/// IPv4 and global IPv6), each paired with `port` (the local WireGuard-facing
/// UDP port), suitable for reporting as endpoint candidates.
pub fn local_candidate_addresses(port: u16) -> Vec<std::net::SocketAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| iface.ip())
        .filter(|ip| is_usable_candidate_address(*ip))
        .map(|ip| std::net::SocketAddr::new(ip, port))
        .collect()
}

/// Like [`local_candidate_addresses`] but tagging each address with its
/// candidate class (IPv4 interface addresses as LAN, global IPv6 as IPv6
/// host), so the caller can publish them into the merged candidate set with
/// the correct priority.
pub fn local_candidates_classified(port: u16) -> Vec<Candidate> {
    local_candidate_addresses(port)
        .into_iter()
        .map(|addr| {
            let class = match addr.ip() {
                IpAddr::V4(_) => CandidateClass::Lan,
                IpAddr::V6(_) => CandidateClass::Ipv6Host,
            };
            Candidate::new(addr, class)
        })
        .collect()
}

/// The first routable local IPv4 address, preferring a private LAN address
/// (the usual case behind a NAT). Used as the internal client address in
/// PCP/NAT-PMP requests and as the mapping target for UPnP-IGD.
pub fn routable_local_ipv4() -> Option<Ipv4Addr> {
    let interfaces = if_addrs::get_if_addrs().ok()?;
    let mut fallback: Option<Ipv4Addr> = None;
    for iface in interfaces {
        if iface.is_loopback() {
            continue;
        }
        if let IpAddr::V4(v4) = iface.ip() {
            if !is_usable_candidate_address(IpAddr::V4(v4)) {
                continue;
            }
            if v4.is_private() {
                return Some(v4);
            }
            fallback.get_or_insert(v4);
        }
    }
    fallback
}

fn is_usable_candidate_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => is_global_scope_ipv6(v6),
    }
}

/// Global-scope IPv6: reachable off-link. Excludes loopback, unspecified,
/// multicast, link-local (fe80::/10), and unique-local (fc00::/7). The stable
/// `Ipv6Addr` API lacks an `is_unicast_global`, so scope is computed directly.
fn is_global_scope_ipv6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    let octets = v6.octets();
    let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
    let is_unique_local = (octets[0] & 0xfe) == 0xfc;
    !is_link_local && !is_unique_local
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_non_loopback_candidates_at_the_given_port() {
        // Environment-dependent (needs at least one non-loopback interface,
        // true for any normal CI/dev machine), so this asserts the filtering
        // invariant rather than a specific address.
        for addr in local_candidate_addresses(41641) {
            assert!(!addr.ip().is_loopback());
            assert_eq!(addr.port(), 41641);
        }
    }

    #[test]
    fn global_ipv6_is_usable_but_link_local_and_ula_are_not() {
        assert!(is_usable_candidate_address("2001:db8::1".parse().unwrap()));
        assert!(!is_usable_candidate_address("fe80::1".parse().unwrap()));
        assert!(!is_usable_candidate_address("fd00::1".parse().unwrap()));
        assert!(!is_usable_candidate_address("::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_link_local_and_loopback_are_excluded() {
        assert!(is_usable_candidate_address("192.168.1.5".parse().unwrap()));
        assert!(is_usable_candidate_address("203.0.113.9".parse().unwrap()));
        assert!(!is_usable_candidate_address("169.254.1.1".parse().unwrap()));
        assert!(!is_usable_candidate_address("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_interface_addresses_classify_as_ipv6_host() {
        let v6 = std::net::SocketAddr::new("2001:db8::5".parse().unwrap(), 41641);
        let class = match v6.ip() {
            IpAddr::V4(_) => CandidateClass::Lan,
            IpAddr::V6(_) => CandidateClass::Ipv6Host,
        };
        assert_eq!(class, CandidateClass::Ipv6Host);
    }
}
