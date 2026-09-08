//! HTTP handlers and the JSON shapes they produce. Every handler is a thin
//! translation: build a `DaemonControlRequest` payload from the HTTP
//! request, send it over `ControlClient`, translate the
//! `DaemonControlResponse` payload into JSON. No handler here computes
//! anything the daemon didn't already compute.
//!
//! Enum fields (`PeerStatus.reachability`, `LinkStatus.durability_status`,
//! ...) are serialized using prost's generated `as_str_name()` -- the exact
//! `SCREAMING_SNAKE_CASE` identifier from `daemon_control.proto` (e.g.
//! `"PEER_REACHABILITY_CONNECTED"`) -- rather than a hand-picked friendlier
//! vocabulary, so the JSON never drifts from the wire protocol it mirrors.
//! `MaterializationState` is the one exception: it reuses the lowercase
//! words `yadorilink-cli`'s own `commands/materialization.rs` already
//! established for this exact enum (`"hydrated"`, `"placeholder"`,
//! `"hydrating"`, `"evicting"`, `"unknown"`), since that vocabulary is
//! already user-facing prior art this adapter should match rather than
//! duplicate differently.

pub mod events;
pub mod reads;
pub mod writes;

use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::{LinkStatus, MaterializationState, PeerStatus};

pub fn link_status_json(l: &LinkStatus) -> Value {
    json!({
        "local_path": l.local_path,
        "group_id": l.group_id,
        "paused": l.paused,
        "conflict_count": l.conflict_count,
        "materialization_policy": l.materialization_policy,
        "hydrated_count": l.hydrated_count,
        "placeholder_count": l.placeholder_count,
        "hydrating_count": l.hydrating_count,
        "held_file_count": l.held_file_count,
        "held_files": l.held_files.iter().map(|h| json!({
            "path": h.path,
            "reason": h.reason,
            "held_since_unix_nanos": h.held_since_unix_nanos,
        })).collect::<Vec<_>>(),
        "skipped_symlink_count": l.skipped_symlink_count,
        "degraded": l.degraded,
        "degraded_reason": l.degraded_reason,
        "has_active_transfer": l.has_active_transfer,
        "transfer_bytes_done": l.transfer_bytes_done,
        "transfer_bytes_total": l.transfer_bytes_total,
        "transfer_blocks_done": l.transfer_blocks_done,
        "transfer_blocks_total": l.transfer_blocks_total,
        "transfer_eta_seconds": l.transfer_eta_seconds,
        "durability_status": l.durability_status().as_str_name(),
        "policy_stale": l.policy_stale,
        "ambiguous": l.ambiguous,
        "ambiguous_local_paths": l.ambiguous_local_paths,
        "local_storage_state": l.local_storage_state().as_str_name(),
        "fetch_availability": l.fetch_availability().as_str_name(),
        "full_replica_device_ids": l.full_replica_device_ids,
    })
}

pub fn peer_status_json(p: &PeerStatus) -> Value {
    json!({
        "device_id": p.device_id,
        "reachability": p.reachability().as_str_name(),
        "unreachable_category": p.unreachable_category().as_str_name(),
        "route_kind": p.route_kind().as_str_name(),
        "relay_capability": p.relay_capability().as_str_name(),
    })
}

pub fn materialization_state_word(s: MaterializationState) -> &'static str {
    match s {
        MaterializationState::Hydrated => "hydrated",
        MaterializationState::Placeholder => "placeholder",
        MaterializationState::Hydrating => "hydrating",
        MaterializationState::Evicting => "evicting",
        MaterializationState::Unspecified => "unknown",
    }
}
