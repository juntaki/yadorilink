//! Availability: can the exact content a folder needs be fetched right now.
//!
//! One of two independent product dimensions (the other is [`crate::protection`]). It says
//! nothing about whether the data would survive losing this device, and "unavailable" is a
//! property of this dimension only.
//!
//! Aggregation (a folder set is as available as its least available part, the first match wins):
//!
//! 1. `WaitingForExactContent`: devices are reachable but none is known to hold the exact version
//! 2. `WaitingForPeer`: a device holding the content is offline; it resolves when it returns
//! 3. `Unknown`: not enough evidence either way
//! 4. `Available`
//!
//! `Available` is therefore reported only when every part is provably available. An empty set of
//! folders needs nothing, so it is `Available`.
//!
//! Serialization contract: [`Availability::as_str`] names are stable snake_case and are what
//! `status --json` prints; the wire enum is `ProductAvailability`, where an unset value is
//! `Unknown`.

use std::collections::BTreeSet;

use yadorilink_ipc_proto::daemonctl::{LinkStatus, ProductAvailability};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Available,
    WaitingForPeer,
    WaitingForExactContent,
    Unknown,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::WaitingForPeer => "waiting_for_peer",
            Availability::WaitingForExactContent => "waiting_for_exact_content",
            Availability::Unknown => "unknown",
        }
    }

    pub fn from_wire(wire: ProductAvailability) -> Self {
        match wire {
            ProductAvailability::Available => Availability::Available,
            ProductAvailability::WaitingForPeer => Availability::WaitingForPeer,
            ProductAvailability::WaitingForExactContent => Availability::WaitingForExactContent,
            ProductAvailability::Unknown | ProductAvailability::Unspecified => {
                Availability::Unknown
            }
        }
    }

    pub fn to_wire(self) -> ProductAvailability {
        match self {
            Availability::Available => ProductAvailability::Available,
            Availability::WaitingForPeer => ProductAvailability::WaitingForPeer,
            Availability::WaitingForExactContent => ProductAvailability::WaitingForExactContent,
            Availability::Unknown => ProductAvailability::Unknown,
        }
    }

    /// Higher rank wins an aggregation (see the module doc).
    fn rank(self) -> u8 {
        match self {
            Availability::WaitingForExactContent => 3,
            Availability::WaitingForPeer => 2,
            Availability::Unknown => 1,
            Availability::Available => 0,
        }
    }
}

/// The availability state with the devices it concerns. Device ids are the other devices
/// recorded as full copies of the folder, sorted without duplicates; a shell resolves them to
/// display names and never shows the ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilitySummary {
    pub availability: Availability,
    pub reachable_device_ids: Vec<String>,
    pub offline_device_ids: Vec<String>,
}

impl AvailabilitySummary {
    /// Read from the daemon's per-link fields; an older daemon's unset fields read `Unknown`.
    pub fn from_link(link: &LinkStatus) -> Self {
        AvailabilitySummary {
            availability: Availability::from_wire(link.availability()),
            reachable_device_ids: link.availability_reachable_device_ids.clone(),
            offline_device_ids: link.availability_offline_device_ids.clone(),
        }
    }

    /// The least available of `parts`, with the union of their devices (see the module doc). A
    /// device offline for one folder is not counted reachable for another.
    pub fn aggregate(parts: &[AvailabilitySummary]) -> Self {
        let availability = parts
            .iter()
            .map(|p| p.availability)
            .fold(Availability::Available, |a, b| if b.rank() > a.rank() { b } else { a });
        let offline: BTreeSet<&String> = parts.iter().flat_map(|p| &p.offline_device_ids).collect();
        let reachable: BTreeSet<&String> = parts
            .iter()
            .flat_map(|p| &p.reachable_device_ids)
            .filter(|id| !offline.contains(id))
            .collect();
        AvailabilitySummary {
            availability,
            reachable_device_ids: reachable.into_iter().cloned().collect(),
            offline_device_ids: offline.into_iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests;
