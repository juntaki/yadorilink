//! Netmap diffing, endpoint classification, and the vocabulary the daemon
//! uses to describe reaching a peer.
//!
//! This module used to hold `PeerChannel`, the WireGuard-plus-ARQ transport.
//! That transport is gone: peers are reached over one authenticated QUIC
//! connection each ([`crate::QuicPeerEndpoint`], [`crate::QuicPeerChannel`]),
//! and QUIC provides the reliability, packetization, reassembly, congestion
//! control and per-peer demultiplexing that layer reimplemented on top of
//! UDP.
//!
//! What survives here is what was never about the transport: how a device
//! works out what a netmap update revoked, how an address is classified, and
//! how a peer's reachability and its failure modes are named.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::nat::CandidateClass;
//
// The coordination plane's netmap subscription always pushes a *full*
// netmap snapshot, never a delta. So the client side
// (`yadorilink-daemon`'s `peer_orchestrator`) is the one that must
// diff each new snapshot against whatever it held before, to find what
// was revoked. This module owns that pure diff logic; `peer_orchestrator`
// owns holding the "previous" snapshot across updates and acting on the
// result (tearing down `PeerChannel`s via [`PeerChannel::revoke`]).

/// One netmap snapshot, keyed by `device_id` (stable across calls per
/// device — the coordination plane's device registration only ever
/// inserts a fresh device or marks one removed, never rotates a key under an
/// existing `device_id`) mapping to the set of folder groups this device
/// and the peer currently share.
///
/// A `HashSet`, not a `Vec`, deliberately: the coordination plane does not
/// guarantee a stable order for a peer's `shared_group_ids`, so the same
/// peer's group list can
/// legitimately come back in a different order across two consecutive
/// calls with no group actually added or removed. Diffing by position
/// would misclassify a reorder as a group being both removed and added.
pub type NetmapSnapshot = HashMap<String, HashSet<String>>;

/// The result of [`diff_netmap`]: what disappeared between two netmap
/// snapshots, split by blast-radius: a whole device losing all shared
/// groups versus one shared group among several being revoked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetmapDiff {
    /// Device ids present in `previous` but entirely absent from
    /// `current` — no authorized group remains between the local device
    /// and this peer (whole-device revocation, e.g. `device remove`, or a
    /// `share revoke` that was this pair's only shared group). Since
    /// `compute_netmap` only ever lists a peer it shares at least one
    /// group with (a peer with zero shared groups is omitted entirely,
    /// never present with an empty group set), a device's disappearance
    /// from the snapshot *is* the signal — this tears its
    /// `PeerChannel` down entirely for each of these.
    pub removed_devices: Vec<String>,
    /// `(device_id, group_id)` pairs present in `previous` whose device is
    /// *still* present in `current` (so at least one other shared group
    /// remains) but that specific group is no longer shared (`share
    /// revoke` of one group among several) — a narrower case:
    /// the tunnel/`PeerChannel` stays up, only that group's sync activity
    /// stops (enforced by `yadorilink-sync-core`'s per-request
    /// authorization checks).
    pub removed_group_edges: Vec<(String, String)>,
}

/// Diffs `current` against `previous`, classifying every
/// device that lost at least one shared group as either a whole-device
/// removal ([`NetmapDiff::removed_devices`]) or a narrower group-edge
/// removal ([`NetmapDiff::removed_group_edges`]). Devices present in
/// `current` but not `previous` (newly authorized) and groups unchanged
/// between the two snapshots produce no diff entries — this function
/// only ever reports *removals*. Output order is sorted for
/// deterministic logging/testing (`HashMap`/`HashSet` iteration order is
/// not stable).
pub fn diff_netmap(previous: &NetmapSnapshot, current: &NetmapSnapshot) -> NetmapDiff {
    let mut removed_devices = Vec::new();
    let mut removed_group_edges = Vec::new();

    for (device_id, previous_groups) in previous {
        match current.get(device_id) {
            None => removed_devices.push(device_id.clone()),
            Some(current_groups) => {
                for group_id in previous_groups {
                    if !current_groups.contains(group_id) {
                        removed_group_edges.push((device_id.clone(), group_id.clone()));
                    }
                }
            }
        }
    }

    removed_devices.sort();
    removed_group_edges.sort();
    NetmapDiff { removed_devices, removed_group_edges }
}

/// Classifies a confirmed endpoint address into the coarsest
/// [`CandidateClass`] derivable from the address alone. Provenance that
/// would distinguish a port-mapped address from a server-reflexive one
/// isn't tracked per confirmed address, so any global-scope IPv4 endpoint
/// is reported as server-reflexive; global IPv6 as an IPv6 host; and any
/// private/loopback/link-local address as LAN.
pub fn classify_endpoint(addr: SocketAddr) -> CandidateClass {
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_loopback() || v4.is_link_local() {
                CandidateClass::Lan
            } else {
                CandidateClass::ServerReflexive
            }
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // fc00::/7 unique-local and fe80::/10 link-local are LAN-scoped,
            // as is loopback; any other global v6 address is a v6 host path.
            if v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                CandidateClass::Lan
            } else {
                CandidateClass::Ipv6Host
            }
        }
    }
}
/// Why a peer could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCategory {
    /// No endpoint candidate is known at all (none from the netmap, none
    /// from local discovery).
    NoCandidates,
    /// Candidates were tried but stayed silent -- no authenticated reply on
    /// any of them (typically endpoint-dependent-mapping NAT or CGNAT on
    /// both sides).
    NoResponse,
    /// Even LAN/STUN probes fail to leave the host -- UDP is blocked
    /// outright.
    UdpBlocked,
    /// The peer is reachable on the network but refused the handshake: its
    /// key is not one this device accepts, or this device's key is not one
    /// it accepts. A distinct failure from network unreachability, and the
    /// one that means "reaching it is not the problem".
    HandshakeRefused,
}

/// Per-peer reachability, mapped onto IPC/status so a user sees a plain
/// "cannot connect" plus the failure category rather than a silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// A connection is being established; `attempt` counts how many
    /// attempts have already been exhausted for this peer.
    Connecting { attempt: u32 },
    /// An authenticated direct path is confirmed, over an endpoint of the
    /// given class.
    Connected { path: CandidateClass },
    /// Authenticated traffic is flowing by way of a relaying peer rather
    /// than over a direct path. Reported distinctly from `Connected` so a
    /// caller never mistakes a relay hop for a confirmed direct one --
    /// which matters because the rule that a relay must not chain through
    /// another relay is enforced by asking exactly that question.
    ConnectedRelay,
    /// Every known candidate was exhausted without an authenticated path.
    /// `next_retry` is when the next attempt is due.
    Unreachable { category: UnreachableCategory, next_retry: Instant },
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Candidate class ---------------------------------------------


    #[test]
    fn classify_endpoint_maps_address_scopes() {
        assert_eq!(classify_endpoint("192.168.1.5:41641".parse().unwrap()), CandidateClass::Lan);
        assert_eq!(classify_endpoint("10.0.0.9:41641".parse().unwrap()), CandidateClass::Lan);
        assert_eq!(
            classify_endpoint("198.51.100.7:41641".parse().unwrap()),
            CandidateClass::ServerReflexive
        );
    }
    // --- Netmap diff tests -------------------------------------------

    fn snapshot(entries: &[(&str, &[&str])]) -> NetmapSnapshot {
        entries
            .iter()
            .map(|(device_id, groups)| {
                (device_id.to_string(), groups.iter().map(|g| g.to_string()).collect())
            })
            .collect()
    }

    /// A device that disappears from the netmap entirely
    /// (whole-device revocation) is classified as a removed device, not a
    /// removed group edge — the diff must key off device presence in
    /// `current`, not just group-set difference.
    #[test]
    fn device_absent_from_current_netmap_is_classified_as_removed_device() {
        let previous =
            snapshot(&[("device-a", &["group-1", "group-2"]), ("device-b", &["group-1"])]);
        let current = snapshot(&[("device-b", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
        assert!(
            diff.removed_group_edges.is_empty(),
            "a wholly-removed device must not also be reported as a group-edge removal: {:?}",
            diff.removed_group_edges
        );
    }

    /// A device still present but with fewer shared groups is a group-edge
    /// removal (the tunnel is meant to stay up), not a device removal.
    #[test]
    fn device_present_with_fewer_groups_is_classified_as_removed_group_edge() {
        let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
        let current = snapshot(&[("device-a", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(
            diff.removed_devices.is_empty(),
            "a device that still shares another group must not be torn down: {:?}",
            diff.removed_devices
        );
        assert_eq!(diff.removed_group_edges, vec![("device-a".to_string(), "group-2".to_string())]);
    }

    /// A snapshot with no changes at all (including a peer's group list
    /// merely coming back in a different order, since `NetmapSnapshot`
    /// values are `HashSet`s) produces an empty diff.
    #[test]
    fn unchanged_netmap_produces_no_diff() {
        let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
        let current = snapshot(&[("device-a", &["group-2", "group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(diff.removed_devices.is_empty());
        assert!(diff.removed_group_edges.is_empty());
    }

    /// A brand-new peer (present in `current`, absent from `previous`) is
    /// an addition, not a removal — `diff_netmap` only ever reports what
    /// disappeared.
    #[test]
    fn newly_added_peer_produces_no_diff_entries() {
        let previous = snapshot(&[]);
        let current = snapshot(&[("device-a", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(diff.removed_devices.is_empty());
        assert!(diff.removed_group_edges.is_empty());
    }

    /// A single netmap update can carry both kinds of removal at once —
    /// both must be classified correctly in the same diff.
    #[test]
    fn mixed_update_classifies_each_device_independently() {
        let previous = snapshot(&[
            ("device-a", &["group-1"]),            // fully removed below
            ("device-b", &["group-1", "group-2"]), // loses group-2 only
            ("device-c", &["group-1"]),            // unchanged
        ]);
        let current = snapshot(&[("device-b", &["group-1"]), ("device-c", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
        assert_eq!(diff.removed_group_edges, vec![("device-b".to_string(), "group-2".to_string())]);
    }
}
