//! Pure, GUI-free transforms from a `LinkStatus`/`&[PeerStatus]` pair into
//! the "Data protection / This device / Availability / Complete copies /
//! Connection" presentation the folder detail view requires — mirrors `status_model.rs`'s
//! and `yadorilink-cli`'s `commands/status.rs`'s own established discipline
//! (one pure formatter fn per field, unit-tested against a default fixture,
//! kept entirely free of `egui` so every rendering DECISION here is
//! testable without a display).
//!
//! Every field read here is a canonical semantic wire type (`durability_status`,
//! `local_storage_state`,
//! `fetch_availability`, `full_replica_device_ids`, `PeerStatus.
//! reachability`/`route_kind`) — nothing here reconstructs a safety
//! judgment from lower-level booleans or policy strings; that reconstruction
//! is exactly the anti-pattern the durability model exists to eliminate
//! (see the daemon's `LocalStorageState`/`FetchAvailability` doc comments for the concrete
//! bug this replaced in `yadorilink-cli`).
//!
//! "Durability != Connectivity" holds here exactly as it does in the wire
//! model this reads from: `data_protection_label` never reads
//! `fetch_availability`/`peers`, and `availability_label`/`connection_label`
//! never read `durability_status`.

use yadorilink_ipc_proto::daemonctl::{
    DurabilityEvidence, FetchAvailability, GroupDurabilityStatus, LinkStatus, LocalStorageState,
    PeerReachability, PeerStatus, RouteKind, VolumeFreeSpace,
};

/// "Data protection" -- Protected / Protecting / At risk / Status
/// unavailable -- the product's fixed target vocabulary. A direct
/// projection of `durability_status`; never upgraded or softened by
/// connectivity, storage mode, or anything else.
pub fn data_protection_label(link: &LinkStatus) -> &'static str {
    match link.durability_status() {
        GroupDurabilityStatus::Protected => "Protected",
        GroupDurabilityStatus::Protecting => "Protecting",
        GroupDurabilityStatus::AtRisk => "At risk",
        GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => "Status unavailable",
    }
}

/// A short, non-alarmist explanation line under `data_protection_label` --
/// the product's explicit distinction: "'Cannot fetch right now'
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

/// How this device knows what `data_protection_label` claims — shown under
/// the detail line, not instead of it.
///
/// `Protected` is not the single fact it once was. Establishing the strong
/// version — a peer reading back and re-checksumming every byte of every
/// retained version — costs one round-trip and one whole-file re-read per
/// version, and the routine check runs every ninety seconds, so the routine
/// answer is now a comparison of what the two devices' indexes say. That is
/// a real distinction and a user looking at a protection label is entitled
/// to it, so it is shown rather than folded away.
///
/// Deliberately plain and unalarming for the ordinary case: index
/// corroboration is the normal, expected state, not a warning.
pub fn data_protection_evidence(link: &LinkStatus) -> Option<&'static str> {
    match link.durability_status() {
        // Only meaningful next to a positive claim. Attaching "how do you
        // know" to "at risk" or "cannot confirm" answers a question nobody
        // asked.
        GroupDurabilityStatus::Protected => match link.durability_evidence() {
            DurabilityEvidence::VerifiedPayload => {
                Some("Verified: another device read back and re-checked every file.")
            }
            DurabilityEvidence::CorroboratedIndex => {
                Some("Confirmed: another device reports holding this folder's current contents.")
            }
            DurabilityEvidence::None | DurabilityEvidence::Unspecified => None,
        },
        _ => None,
    }
}

/// "This device" -- Full copy / Saving space (On-Demand) -- the product's
/// fixed target vocabulary. A direct projection of
/// `local_storage_state`; `PartiallyMaterialized` (an eager link still
/// catching up) reads as its own honest label, never silently as either
/// endpoint.
pub fn this_device_label(link: &LinkStatus) -> &'static str {
    match link.local_storage_state() {
        LocalStorageState::FullCopy => "Full copy on this device",
        LocalStorageState::PartiallyMaterialized => "Making a full copy on this device…",
        LocalStorageState::OnDemand => "Saving space on this device (On-Demand)",
        // an unset value
        // evidence of either its storage policy or hydration state --
        // folding this into `OnDemand` would turn genuine uncertainty
        // into a specific, reassuring configuration claim this daemon
        // never actually made.
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
/// Deliberately named/typed to avoid an overclaim `yadorilink-cli`'s own
/// equivalent list once made: `state`
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
    /// `Connecting`/`Unspecified`).
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
            let reachability =
                peers.iter().find(|p| &p.device_id == device_id).map(|p| p.reachability());
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
/// "Relayed" (connected, through a relay server), "Connected" (a connection
/// exists but this daemon predates `route_kind` and cannot say which kind),
/// or "Currently unavailable". A relayed peer is as available as a direct
/// one; the label only says which path is carrying it. Deliberately
/// never upgrades/downgrades `data_protection_label`: connectivity says
/// nothing about durability (`Durability != Connectivity`).
///
/// `route_kind == Unspecified` while `Connected` (an unset-value
/// unset) must NOT be conflated with a genuine failure to
/// determine the route -- it reads as plain "Connected", mirroring
/// `yadorilink-cli`'s own already-reviewed fallback for the identical
/// case.
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
                    RouteKind::Direct => "Direct",
                    RouteKind::Relay => "Relayed",
                    RouteKind::Unspecified => "Connected",
                },
                _ => "Currently unavailable",
            };
            ConnectionRow { device_id: device_id.clone(), label }
        })
        .collect()
}

/// This folder's own disk-usage volume — `StatusResponse.volumes` carries
/// one entry per distinct volume path ("the block store root, plus each
/// link's own local root", per that message's own proto doc comment), so
/// an exact match on `link.local_path` is the correct lookup, not a prefix
/// search. `None` for an unset value, or if
/// this folder's root genuinely has no distinct volume entry yet.
pub fn disk_usage_for<'a>(
    link: &LinkStatus,
    volumes: &'a [VolumeFreeSpace],
) -> Option<&'a VolumeFreeSpace> {
    volumes.iter().find(|v| v.path == link.local_path)
}

/// "12.3 GiB free (ok)" — `state` is `free_space::FreeSpaceState`'s own
/// `as_str` text ("ok"/"low"/"critical"), rendered verbatim per this
/// file's own "never reword the daemon's own classification" discipline
/// (see e.g. `data_protection_label`'s doc comment).
pub fn disk_usage_label(volume: &VolumeFreeSpace) -> String {
    format!("{} free ({})", format_bytes(volume.available_bytes), volume.state)
}

/// Byte-count formatter — same binary-unit, one-decimal-place shape as
/// `yadorilink-cli`'s own `commands::status::format_bytes` (kept as its
/// own copy rather than shared, matching this crate's established
/// duplication precedent — see `ipc_client.rs`'s doc comment).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// "42% · 1.2 MiB / 3.0 MiB · ~30s remaining" — the live-transfer progress
/// line for one folder's `FolderTransfer`, straight from the daemon's own
/// already-computed byte totals and ETA (never re-derived from anything
/// lower-level — this module's own top doc comment). `bytes_total == 0`
/// (a transfer just starting, sizes not yet known) reads as `0%`, never a
/// divide-by-zero.
pub fn transfer_progress_label(transfer: &yadorilink_product_view::FolderTransfer) -> String {
    let percent = if transfer.bytes_total == 0 {
        0
    } else {
        ((transfer.bytes_done as f64 / transfer.bytes_total as f64) * 100.0).round() as u64
    };
    format!(
        "{percent}% · {} / {}{}",
        format_bytes(transfer.bytes_done),
        format_bytes(transfer.bytes_total),
        format_eta(transfer.eta_seconds),
    )
}

/// " · ~Ns/Nm/Nh remaining", or empty when the daemon hasn't reported an
/// ETA yet (`0` — this file's existing "0 = not yet known/applicable"
/// convention, matching `last_gc_summary`'s identical treatment of `0` in
/// `yadorilink-cli`'s `status.rs`).
fn format_eta(seconds: u64) -> String {
    if seconds == 0 {
        String::new()
    } else if seconds < 60 {
        format!(" · ~{seconds}s remaining")
    } else if seconds < 3600 {
        format!(" · ~{}m remaining", seconds / 60)
    } else {
        format!(" · ~{}h remaining", seconds / 3600)
    }
}

#[cfg(test)]
mod tests;
