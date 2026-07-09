//! Local network interface enumeration (task 4.9 / design.md D10): a
//! device's own LAN addresses are reported as high-priority endpoint
//! candidates alongside its relay-observed public address, so peers on
//! the same network connect over the low-latency local path automatically
//! via candidate racing rather than explicit same-network detection.

use std::net::IpAddr;

/// Local-address candidates get the highest priority: a same-LAN path is
/// always preferable to a NAT-traversed public path when both are viable.
pub const LOCAL_CANDIDATE_PRIORITY: i32 = 100;

/// Returns this host's non-loopback, non-link-local interface addresses,
/// each paired with `port` (the local WireGuard-facing UDP port), suitable
/// for reporting as endpoint candidates.
pub fn local_candidate_addresses(port: u16) -> Vec<std::net::SocketAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| iface.ip())
        .filter(|ip| is_usable_lan_address(*ip))
        .map(|ip| std::net::SocketAddr::new(ip, port))
        .collect()
}

fn is_usable_lan_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        // IPv6 link-local/ULA addressing is more failure-prone across
        // consumer network gear; keep the MVP candidate set to IPv4.
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_only_ipv4_non_loopback_candidates() {
        // Environment-dependent (needs at least one non-loopback IPv4
        // interface, true for any normal CI/dev machine), so this asserts
        // the filtering invariant rather than a specific address.
        for addr in local_candidate_addresses(41641) {
            assert!(!addr.ip().is_loopback());
            assert_eq!(addr.port(), 41641);
            assert!(addr.is_ipv4());
        }
    }
}
