//! NAT/firewall classification: turn the passive observations the transport
//! already gathers (STUN mapped addresses, port-mapping outcome, punch
//! results) into a single verdict. Diagnostics render it, and the
//! unreachable-peer messaging uses it to explain *why* a pair cannot connect
//! ("both devices are behind NATs that prevent a direct connection") rather
//! than a bare failure.
//!
//! The classifier is a pure function of a [`NatObservations`] snapshot, so it
//! is deterministic and unit-testable as a truth table. It never sends any
//! probe of its own — everything it needs comes from traffic the system was
//! already sending.

use std::net::IpAddr;

use super::NatObservations;

/// The classified behavior of this device's NAT/firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    /// Not enough has been observed yet to classify (no STUN configured or
    /// no probe outcomes).
    Unknown,
    /// A public address directly on the host, or a full-cone NAT: mapped
    /// address equals a local address. Directly reachable.
    OpenOrFullCone,
    /// Endpoint-independent mapping: one stable mapping across servers.
    /// Hole punching works between two such NATs.
    EndpointIndependent,
    /// Endpoint-dependent (symmetric) mapping: different mapped ports to
    /// different servers. Punching is unlikely; out of scope here.
    EndpointDependent,
    /// No STUN, punch, or probe response ever seen despite the control plane
    /// being reachable: UDP is blocked on this network.
    UdpBlocked,
    /// Behind carrier-grade NAT (an RFC 6598 external address, or a mapped
    /// address that is itself private) — no inbound reachability without a
    /// relay, which is out of scope.
    CgnatLikely,
}

impl NatClass {
    /// A one-line, user-facing implication for the connectivity doctor.
    pub fn implication(self) -> &'static str {
        match self {
            NatClass::Unknown => "NAT type not yet determined.",
            NatClass::OpenOrFullCone => {
                "This device is directly reachable; peers can connect without traversal."
            }
            NatClass::EndpointIndependent => {
                "Direct connections should succeed with most peers via hole punching."
            }
            NatClass::EndpointDependent => {
                "This network's NAT assigns a new port per destination, so direct \
                 connections to other NATed peers usually fail."
            }
            NatClass::UdpBlocked => {
                "UDP appears to be blocked on this network; direct sync is not possible here."
            }
            NatClass::CgnatLikely => {
                "This device is behind carrier-grade NAT and cannot accept direct \
                 inbound connections on this network."
            }
        }
    }

    /// Whether hole punching is worth attempting for this class.
    pub fn is_punchable(self) -> bool {
        matches!(self, NatClass::OpenOrFullCone | NatClass::EndpointIndependent)
    }
}

/// True for RFC 6598 (100.64.0.0/10) carrier-grade-NAT shared address space.
fn is_cgnat_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(_) => false,
    }
}

/// True for addresses that must not appear as a *public* reflexive mapping —
/// if the mapped address is itself private/loopback/link-local/CGNAT, there
/// is another NAT in the path and the device is not directly reachable.
fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || is_cgnat_range(ip)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || is_unique_local_v6(v6),
    }
}

/// True for IPv6 unique-local addresses (fc00::/7).
fn is_unique_local_v6(v6: std::net::Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

/// Derives a [`NatClass`] from a snapshot of observations, following the
/// documented decision order.
pub fn classify(obs: &NatObservations) -> NatClass {
    // No STUN evidence at all.
    if obs.stun_mappings.is_empty() {
        // Attempted STUN and coordinated punching, nothing ever answered:
        // the network blocks UDP. (The caller only records punch attempts
        // when the control plane is reachable, so this is not a full
        // offline state.)
        if obs.stun_attempted && obs.punch_attempted && !obs.punch_any_success {
            return NatClass::UdpBlocked;
        }
        return NatClass::Unknown;
    }

    // Distinct mapped ports across servers ⇒ endpoint-dependent (symmetric).
    let distinct_ports: std::collections::HashSet<u16> =
        obs.stun_mappings.values().map(|m| m.port()).collect();
    if distinct_ports.len() > 1 {
        return NatClass::EndpointDependent;
    }

    // Single, consistent mapping. Inspect the mapped address itself.
    let mapped = obs.stun_mappings.values().next().expect("non-empty checked above");
    let mapped_ip = mapped.ip();

    if is_cgnat_range(mapped_ip) || is_non_public(mapped_ip) {
        return NatClass::CgnatLikely;
    }

    // Mapped address equals one of our own local addresses ⇒ no NAT in the
    // path (public host) or a full-cone mapping onto the same address.
    if obs.local_addrs.contains(&mapped_ip) {
        return NatClass::OpenOrFullCone;
    }

    NatClass::EndpointIndependent
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn obs_with(mappings: &[(&str, &str)]) -> NatObservations {
        let mut stun_mappings = BTreeMap::new();
        for (server, mapped) in mappings {
            stun_mappings.insert(sock(server), sock(mapped));
        }
        NatObservations {
            stun_mappings,
            stun_any_response: !mappings.is_empty(),
            stun_attempted: true,
            ..Default::default()
        }
    }

    #[test]
    fn no_observations_is_unknown() {
        assert_eq!(classify(&NatObservations::default()), NatClass::Unknown);
    }

    #[test]
    fn silent_network_is_udp_blocked() {
        let obs = NatObservations {
            stun_attempted: true,
            punch_attempted: true,
            punch_any_success: false,
            ..Default::default()
        };
        assert_eq!(classify(&obs), NatClass::UdpBlocked);
    }

    #[test]
    fn disagreeing_ports_are_endpoint_dependent() {
        let obs =
            obs_with(&[("1.1.1.1:3478", "203.0.113.7:5000"), ("8.8.8.8:3478", "203.0.113.7:6000")]);
        assert_eq!(classify(&obs), NatClass::EndpointDependent);
    }

    #[test]
    fn consistent_public_mapping_is_endpoint_independent() {
        let obs =
            obs_with(&[("1.1.1.1:3478", "203.0.113.7:5000"), ("8.8.8.8:3478", "203.0.113.7:5000")]);
        assert_eq!(classify(&obs), NatClass::EndpointIndependent);
        assert!(classify(&obs).is_punchable());
    }

    #[test]
    fn mapped_equals_local_is_open() {
        let mut obs = obs_with(&[("1.1.1.1:3478", "203.0.113.7:5000")]);
        obs.local_addrs = vec![ip("203.0.113.7")];
        assert_eq!(classify(&obs), NatClass::OpenOrFullCone);
    }

    #[test]
    fn cgnat_external_address_is_cgnat_likely() {
        let obs = obs_with(&[("1.1.1.1:3478", "100.72.5.9:5000")]);
        assert_eq!(classify(&obs), NatClass::CgnatLikely);
    }

    #[test]
    fn private_mapped_address_is_cgnat_likely() {
        // A mapped address that is itself RFC1918 means another NAT sits in
        // front — not directly reachable.
        let obs = obs_with(&[("1.1.1.1:3478", "10.0.0.5:5000")]);
        assert_eq!(classify(&obs), NatClass::CgnatLikely);
    }
}
