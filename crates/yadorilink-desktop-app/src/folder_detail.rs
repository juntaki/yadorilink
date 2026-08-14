//! Pure, GUI-free transforms from a `LinkStatus`/`&[PeerStatus]` pair into
//! the "Data protection / This device / Availability / Complete copies /
//! Connection" presentation M4 Pass 3 requires — mirrors `status_model.rs`'s
//! and `yadorilink-cli`'s `commands/status.rs`'s own established discipline
//! (one pure formatter fn per field, unit-tested against a default fixture,
//! kept entirely free of `egui` so every rendering DECISION here is
//! testable without a display).
//!
//! Every field read here is the canonical semantic wire type M4 Passes 1-3
//! already built (`durability_status`, `local_storage_state`,
//! `fetch_availability`, `full_replica_device_ids`, `PeerStatus.
//! reachability`/`route_kind`) — nothing here reconstructs a safety
//! judgment from lower-level booleans or policy strings; that reconstruction
//! is exactly the anti-pattern M4 exists to eliminate (see M4 Pass 2's
//! `LocalStorageState`/`FetchAvailability` doc comments for the concrete
//! bug this replaced in `yadorilink-cli`).
//!
//! "Durability != Connectivity" holds here exactly as it does in the wire
//! model this reads from: `data_protection_label` never reads
//! `fetch_availability`/`peers`, and `availability_label`/`connection_label`
//! never read `durability_status`.

use yadorilink_ipc_proto::daemonctl::{
    FetchAvailability, GroupDurabilityStatus, LinkStatus, LocalStorageState, PeerReachability,
    PeerStatus, RouteKind,
};

/// "Data protection" -- Protected / Protecting / At risk / Status
/// unavailable, per the M4 directive's exact target vocabulary. A direct
/// projection of `durability_status`; never upgraded or softened by
/// connectivity, storage mode, or anything else.
pub fn data_protection_label(link: &LinkStatus) -> &'static str {
    match link.durability_status() {
        GroupDurabilityStatus::Protected => "Protected",
        GroupDurabilityStatus::Protecting => "Protecting",
        GroupDurabilityStatus::AtRisk => "At risk",
        GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
            "Status unavailable"
        }
    }
}

/// A short, non-alarmist explanation line under `data_protection_label` --
/// the M4 directive's own explicit distinction: "'Cannot fetch right now'
/// is NOT 'Your data is lost'." Combines `durability_status` with
/// `fetch_availability` ONLY for wording, never for the label itself above
/// (durability and fetch availability remain independently derived
/// upstream; this function just picks which sentence to show).
pub fn data_protection_detail(link: &LinkStatus) -> Option<&'static str> {
    match (link.durability_status(), link.fetch_availability()) {
        (GroupDurabilityStatus::Protected, FetchAvailability::UnavailableNow) => {
            Some("Your data is protected, but no device that holds it is reachable right now.")
        }
        (GroupDurabilityStatus::AtRisk, _) => {
            Some("No other device is configured to keep a full copy of this folder.")
        }
        (GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified, _) => {
            Some("This device cannot currently confirm whether this folder is protected.")
        }
        _ => None,
    }
}

/// "This device" -- Full copy / Saving space (On-Demand), per the M4
/// directive's exact target vocabulary. A direct projection of
/// `local_storage_state`; `PartiallyMaterialized` (an eager link still
/// catching up) reads as its own honest label, never silently as either
/// endpoint.
pub fn this_device_label(link: &LinkStatus) -> &'static str {
    match link.local_storage_state() {
        LocalStorageState::FullCopy => "Full copy on this device",
        LocalStorageState::PartiallyMaterialized => "Making a full copy on this device…",
        LocalStorageState::OnDemand => "Saving space on this device (On-Demand)",
        // An older daemon predating `local_storage_state` provides no
        // evidence of either its storage policy or hydration state --
        // folding this into `OnDemand` would turn genuine uncertainty
        // into a specific, reassuring configuration claim this daemon
        // never actually made (M4 Pass 3 Codex review #3 follow-up).
        LocalStorageState::Unspecified => "Status unavailable",
    }
}

/// "Availability" -- Available now / Cannot fetch right now / Status
/// unavailable. A direct projection of `fetch_availability`, independent
/// of `durability_status` (see this module's own doc comment).
pub fn availability_label(link: &LinkStatus) -> &'static str {
    match link.fetch_availability() {
        FetchAvailability::AvailableNow => "Available now",
        FetchAvailability::UnavailableNow => "Cannot fetch right now",
        FetchAvailability::Unknown | FetchAvailability::Unspecified => "Status unavailable",
    }
}

/// One "Complete copies" row: `device_id` plus its per-device state.
/// Deliberately named/typed to avoid the exact overclaim M4 Pass 3 Codex
/// review #3 found in `yadorilink-cli`'s own equivalent list: `state`
/// says "configured" (a structural, content-blind netmap declaration),
/// never "verified" or "complete" as a standalone claim -- the group's
/// actual verified protection is `data_protection_label` above, not this
/// per-device connectivity inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCopyRow {
    pub device_id: String,
    pub state: CompleteCopyState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteCopyState {
    /// The device is currently `Connected`.
    Available,
    /// The device is positively known `Unreachable`.
    Offline,
    /// No positive evidence either way (absent from `peers`, or
    /// `Connecting`/`ProtocolIncompatible`/`Unspecified`).
    Unknown,
}

impl CompleteCopyState {
    pub fn label(self) -> &'static str {
        match self {
            CompleteCopyState::Available => "available",
            CompleteCopyState::Offline => "offline",
            CompleteCopyState::Unknown => "unknown",
        }
    }
}

/// "Complete copies" -- one row per device in `link.full_replica_device_ids`,
/// cross-referenced against `peers`' own `reachability`. Mirrors
/// `yadorilink-cli`'s `complete_copies_detail_lines` exactly (same
/// 3-way Available/Offline/Unknown derivation, same never-observed ->
/// Unknown fail-closed rule) -- this is user-facing presentation of the
/// SAME structural, content-blind fact, not a re-derivation with different
/// semantics.
pub fn complete_copies(link: &LinkStatus, peers: &[PeerStatus]) -> Vec<CompleteCopyRow> {
    link.full_replica_device_ids
        .iter()
        .map(|device_id| {
            let reachability = peers.iter().find(|p| &p.device_id == device_id).map(|p| p.reachability());
            let state = match reachability {
                Some(PeerReachability::Connected) => CompleteCopyState::Available,
                Some(PeerReachability::Unreachable) => CompleteCopyState::Offline,
                _ => CompleteCopyState::Unknown,
            };
            CompleteCopyRow { device_id: device_id.clone(), state }
        })
        .collect()
}

/// "Connection" -- one row per device in `link.full_replica_device_ids`,
/// describing THIS device's own current connection to it: "Direct",
/// "Via a relay device", "Connected" (a connection exists but this
/// daemon predates `route_kind` and cannot say which kind), or "Currently
/// unavailable". Deliberately never names a specific relay device (that
/// identity isn't exposed on the wire yet -- see M4 Pass 3's own scoping
/// note) and deliberately never upgrades/downgrades
/// `data_protection_label`: relay connectivity says nothing about
/// durability (`Durability != Connectivity`).
///
/// `route_kind == Unspecified` while `Connected` (an older daemon
/// predating that field) must NOT default to "Direct" -- that would
/// assert a route this daemon never actually confirmed, potentially
/// hiding a real relay hop (M4 Pass 3 Codex review #3 follow-up; mirrors
/// `yadorilink-cli`'s own already-reviewed fallback to plain "connected"
/// for the identical case).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRow {
    pub device_id: String,
    pub label: &'static str,
}

pub fn connections(link: &LinkStatus, peers: &[PeerStatus]) -> Vec<ConnectionRow> {
    link.full_replica_device_ids
        .iter()
        .map(|device_id| {
            let peer = peers.iter().find(|p| &p.device_id == device_id);
            let label = match peer.map(|p| p.reachability()) {
                Some(PeerReachability::Connected) => match peer.unwrap().route_kind() {
                    RouteKind::Relay => "Via a relay device",
                    RouteKind::Direct => "Direct",
                    RouteKind::Unspecified => "Connected",
                },
                _ => "Currently unavailable",
            };
            ConnectionRow { device_id: device_id.clone(), label }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_link() -> LinkStatus {
        LinkStatus {
            local_path: "/Users/alice/Photos".into(),
            group_id: "group-1".into(),
            durability_status: GroupDurabilityStatus::Protected as i32,
            local_storage_state: LocalStorageState::FullCopy as i32,
            fetch_availability: FetchAvailability::AvailableNow as i32,
            ..Default::default()
        }
    }

    fn base_peer(device_id: &str) -> PeerStatus {
        PeerStatus {
            device_id: device_id.into(),
            reachability: PeerReachability::Connected as i32,
            route_kind: RouteKind::Direct as i32,
            ..Default::default()
        }
    }

    #[test]
    fn data_protection_maps_every_durability_state() {
        let mut link = base_link();
        link.durability_status = GroupDurabilityStatus::Protected as i32;
        assert_eq!(data_protection_label(&link), "Protected");
        link.durability_status = GroupDurabilityStatus::Protecting as i32;
        assert_eq!(data_protection_label(&link), "Protecting");
        link.durability_status = GroupDurabilityStatus::AtRisk as i32;
        assert_eq!(data_protection_label(&link), "At risk");
        link.durability_status = GroupDurabilityStatus::Unknown as i32;
        assert_eq!(data_protection_label(&link), "Status unavailable");
        link.durability_status = GroupDurabilityStatus::Unspecified as i32;
        assert_eq!(
            data_protection_label(&link),
            "Status unavailable",
            "an older daemon's Unspecified must fail safe, never read as Protected"
        );
    }

    /// The exact M4 target distinction: protected-but-unreachable is NOT
    /// data loss.
    #[test]
    fn protected_but_unavailable_gets_the_non_alarmist_detail_line() {
        let mut link = base_link();
        link.durability_status = GroupDurabilityStatus::Protected as i32;
        link.fetch_availability = FetchAvailability::UnavailableNow as i32;
        assert_eq!(
            data_protection_detail(&link),
            Some("Your data is protected, but no device that holds it is reachable right now.")
        );
    }

    #[test]
    fn protected_and_available_has_no_detail_line() {
        let link = base_link();
        assert_eq!(data_protection_detail(&link), None);
    }

    #[test]
    fn this_device_maps_every_local_storage_state() {
        let mut link = base_link();
        link.local_storage_state = LocalStorageState::FullCopy as i32;
        assert_eq!(this_device_label(&link), "Full copy on this device");
        link.local_storage_state = LocalStorageState::PartiallyMaterialized as i32;
        assert_eq!(this_device_label(&link), "Making a full copy on this device…");
        link.local_storage_state = LocalStorageState::OnDemand as i32;
        assert_eq!(this_device_label(&link), "Saving space on this device (On-Demand)");
        link.local_storage_state = LocalStorageState::Unspecified as i32;
        assert_eq!(
            this_device_label(&link),
            "Status unavailable",
            "an older daemon's Unspecified must never read as a specific reassuring \
             configuration"
        );
    }

    #[test]
    fn availability_maps_every_fetch_availability_state() {
        let mut link = base_link();
        link.fetch_availability = FetchAvailability::AvailableNow as i32;
        assert_eq!(availability_label(&link), "Available now");
        link.fetch_availability = FetchAvailability::UnavailableNow as i32;
        assert_eq!(availability_label(&link), "Cannot fetch right now");
        link.fetch_availability = FetchAvailability::Unknown as i32;
        assert_eq!(availability_label(&link), "Status unavailable");
    }

    #[test]
    fn no_full_replica_devices_renders_no_rows() {
        let link = base_link();
        assert!(complete_copies(&link, &[]).is_empty());
        assert!(connections(&link, &[]).is_empty());
    }

    #[test]
    fn complete_copies_reports_available_offline_unknown() {
        let mut link = base_link();
        link.full_replica_device_ids =
            vec!["nas-1".into(), "nas-2".into(), "unseen".into()];
        let mut offline_peer = base_peer("nas-2");
        offline_peer.reachability = PeerReachability::Unreachable as i32;
        let peers = vec![base_peer("nas-1"), offline_peer];

        let rows = complete_copies(&link, &peers);
        assert_eq!(
            rows,
            vec![
                CompleteCopyRow { device_id: "nas-1".into(), state: CompleteCopyState::Available },
                CompleteCopyRow { device_id: "nas-2".into(), state: CompleteCopyState::Offline },
                CompleteCopyRow { device_id: "unseen".into(), state: CompleteCopyState::Unknown },
            ]
        );
    }

    #[test]
    fn connection_distinguishes_direct_relay_and_unavailable() {
        let mut link = base_link();
        link.full_replica_device_ids = vec!["direct-nas".into(), "relay-nas".into(), "down-nas".into()];
        let mut relay_peer = base_peer("relay-nas");
        relay_peer.route_kind = RouteKind::Relay as i32;
        let mut down_peer = base_peer("down-nas");
        down_peer.reachability = PeerReachability::Unreachable as i32;
        let peers = vec![base_peer("direct-nas"), relay_peer, down_peer];

        let rows = connections(&link, &peers);
        assert_eq!(
            rows,
            vec![
                ConnectionRow { device_id: "direct-nas".into(), label: "Direct" },
                ConnectionRow { device_id: "relay-nas".into(), label: "Via a relay device" },
                ConnectionRow { device_id: "down-nas".into(), label: "Currently unavailable" },
            ]
        );
    }

    /// An older daemon predating `route_kind` sends `Unspecified` for a
    /// `Connected` peer -- must NOT default to "Direct" (a route claim
    /// this daemon never confirmed, which could hide a real relay hop).
    #[test]
    fn connected_with_unspecified_route_kind_reads_as_plain_connected() {
        let mut link = base_link();
        link.full_replica_device_ids = vec!["nas-1".into()];
        let mut peer = base_peer("nas-1");
        peer.route_kind = RouteKind::Unspecified as i32;
        let rows = connections(&link, &[peer]);
        assert_eq!(rows, vec![ConnectionRow { device_id: "nas-1".into(), label: "Connected" }]);
    }

    /// Durability != Connectivity, pinned directly: a group with zero
    /// reachable/connected full-replica peers (fetch_availability
    /// UnavailableNow, every connection row "Currently unavailable")
    /// still reports "Protected" when `durability_status` says so --
    /// connectivity state never downgrades the durability label.
    #[test]
    fn durability_is_independent_of_connectivity() {
        let mut link = base_link();
        link.durability_status = GroupDurabilityStatus::Protected as i32;
        link.fetch_availability = FetchAvailability::UnavailableNow as i32;
        link.full_replica_device_ids = vec!["nas-1".into()];
        let mut peer = base_peer("nas-1");
        peer.reachability = PeerReachability::Unreachable as i32;

        assert_eq!(data_protection_label(&link), "Protected");
        assert_eq!(availability_label(&link), "Cannot fetch right now");
        assert_eq!(
            connections(&link, &[peer]),
            vec![ConnectionRow { device_id: "nas-1".into(), label: "Currently unavailable" }]
        );
    }
}
