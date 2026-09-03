//! M3 Pass 4: the connectivity-route vocabulary Pass 5 (Peer Relay) and
//! Pass 6 (direct<->relay failover) build on. This pass introduces the
//! types and threads `RelayCapability` through the netmap; it does not
//! implement relay forwarding or failover itself -- today, every
//! `RouteKind::Direct` is the only kind ever actually produced; M3 Pass 6
//! is what starts producing `RouteKind::Relay` (see `peer_orchestrator::
//! map_transport_reachability`).
//!
//! **Standing invariant, unchanged from the decision that scoped this
//! work: `Durability != Connectivity`.** `RelayCapability`, `RouteKind`,
//! and full-replica status (`DaemonState::peer_group_is_full_replica`) are
//! three INDEPENDENT axes, never inferred from one another:
//! - A peer relaying datagrams for others is not thereby a safe place to
//!   store data (`RelayCapability::Capable` implies nothing about
//!   `full_replica_group_ids`).
//! - A full-replica peer is not thereby available as a relay
//!   (`peer_group_is_full_replica` implies nothing about
//!   `RelayCapability`).
//! - A session reachable via `RouteKind::Relay` is not evidence the data
//!   moving over it landed durably anywhere -- that is exactly what the
//!   change-DAG/materialization layer, not connectivity, is responsible
//!   for proving.
//!
//! What IS true, and the whole reason this is worth building: a device a
//! user already owns and trusts (a home NAS, an always-on desktop) can
//! naturally hold BOTH roles -- `StorageRole` (full-replica) is already
//! modeled per-group via `full_replica_group_ids`; `RelayCapability` is
//! this pass's new, separately-declared per-device role. Nothing in this
//! module ever couples the two.

/// A peer's own declared willingness to forward opaque QUIC datagrams
/// for OTHER peers in a shared group -- see this module's own doc comment
/// for why this is never inferred from full-replica status. Sourced from
/// the coordination-plane netmap (`WsNetmapPeer::relay_capable` in
/// `peer_orchestrator.rs`), defaulting to `Disabled` when absent (an older
/// coordination plane, or a device that has never opted in) -- the
/// fail-safe default, matching `full_replica_group_ids`'s own "absence
/// means not treated as available" convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCapability {
    /// This peer has declared it will act as a relay for other peers in a
    /// shared group, subject to the authorization/rate-limit rules Pass 5
    /// defines (same account/group only, short-lived authorization,
    /// fixed source/destination, opaque datagram forwarding only, idle
    /// timeout, connection/bandwidth/packet-rate limits, no relay
    /// recursion).
    Capable,
    /// This peer has not declared relay willingness (the default). Never
    /// treated as available for relay regardless of its storage role.
    Disabled,
}

impl RelayCapability {
    pub fn is_capable(self) -> bool {
        matches!(self, RelayCapability::Capable)
    }

    /// Stable wire/status slug: "capable" | "disabled".
    pub fn as_str(self) -> &'static str {
        match self {
            RelayCapability::Capable => "capable",
            RelayCapability::Disabled => "disabled",
        }
    }
}

/// Which path a peer connection is actually using. Carried by
/// `PeerReachability::Connected` so a caller can distinguish "connected
/// directly" from "connected via a relaying peer" without that
/// distinction implying anything about durability (see this module's own
/// doc comment). `Relay` is produced once `PeerChannel`'s own reachability
/// reports `ConnectedRelay` -- see `peer_orchestrator::map_transport_
/// reachability`.
///
/// Deliberately fieldless (unlike a natural `Relay { via: DeviceId }`
/// shape) so this stays `Copy`, matching `PeerReachability`'s own existing
/// by-value-`self` API used throughout the daemon and CLI -- adding a
/// `String` payload here would ripple `Copy` loss through every caller of
/// `PeerReachability`. M3 Pass 6 starts producing this variant (via
/// `peer_orchestrator::map_transport_reachability`) without adding that
/// payload; a caller that needs to know WHO is relaying reads it from the
/// daemon's own relay-session bookkeeping instead, not from this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// A direct, authenticated QUIC path to the peer.
    Direct,
    /// Connected by forwarding opaque QUIC datagrams through another
    /// peer rather than a direct path.
    Relay,
}

impl RouteKind {
    /// Stable wire/status slug: "direct" | "relay".
    pub fn as_str(self) -> &'static str {
        match self {
            RouteKind::Direct => "direct",
            RouteKind::Relay => "relay",
        }
    }
}
