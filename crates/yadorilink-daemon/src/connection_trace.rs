//! Connection Operations: a bounded, in-memory history of recent
//! connection attempts, plus a connectivity-doctor summary derived from
//! it and other already-tracked daemon state.
//!
//! Bounded diagnostic traces, not verbose raw logs: every field here is
//! a structured category or a project-internal identifier (device id,
//! relay id) — never a raw socket address, hostname, or any file
//! content/path, matching this project's content-blindness discipline
//! and mirroring `crate::reporting::error_candidates`'s bounded
//! error-candidate ring buffer and `folder_ops`'s bounded audit trail:
//! oldest entries are dropped once the cap is reached, this is never
//! durably persisted, and a restart starts the history empty.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::daemon_state::DaemonState;

/// Bounded, matching this module's own doc comment and every sibling
/// bounded store in this crate (`folder_ops::MAX_AUDIT_ENTRIES`,
/// `reporting::error_candidates`'s cap).
pub const MAX_TRACE_ENTRIES: usize = 500;

fn now_unix_nanos() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

/// Where a connection candidate/attempt came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    /// A peer address supplied by the coordination plane's netmap
    /// (`yadorilink-transport`'s own `CandidateSource::Coordination`).
    CoordinationPlane,
    /// A peer address learned from unauthenticated local network
    /// discovery/mDNS (`yadorilink-transport`'s own
    /// `CandidateSource::Discovery`).
    LocalDiscovery,
    /// The already-established direct (NAT-traversed) path being
    /// confirmed/used, as opposed to a *new* candidate being tried.
    DirectPath,
    /// The shared relay connection.
    Relay,
}

impl CandidateSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateSource::CoordinationPlane => "coordination_plane",
            CandidateSource::LocalDiscovery => "local_discovery",
            CandidateSource::DirectPath => "direct",
            CandidateSource::Relay => "relay",
        }
    }
}

/// Coarse address class — never a raw IP/hostname/port, per this
/// module's redaction requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Lan,
    Wan,
    RelayHop,
    Unknown,
}

impl AddressClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Lan => "lan",
            AddressClass::Wan => "wan",
            AddressClass::RelayHop => "relay",
            AddressClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    Connected,
    Failed,
    Rejected,
}

impl AttemptOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptOutcome::Connected => "connected",
            AttemptOutcome::Failed => "failed",
            AttemptOutcome::Rejected => "rejected",
        }
    }
}

/// One structured connection-attempt record — candidate source, coarse
/// address class, outcome, latency, failure category,
/// whether this attempt became the selected path, relay identity (if
/// any), and the authorization decision. `peer_device_id` is empty for
/// an attempt that isn't peer-specific (e.g. the coordination-plane
/// netmap subscription itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAttemptTrace {
    pub peer_device_id: String,
    pub candidate_source: &'static str,
    pub address_class: &'static str,
    pub outcome: &'static str,
    pub latency_ms: u64,
    /// A stable, short category (e.g. `TransportError::category`) —
    /// never the raw error text, which can embed address/protocol detail.
    /// Empty for a successful attempt.
    pub failure_category: String,
    /// Whether this attempt is (or became) the path currently in use.
    pub selected: bool,
    /// Pseudonymous relay identifier, empty when this attempt didn't
    /// involve a relay.
    pub relay_identity: String,
    /// "authorized" | "denied" | "n/a".
    pub authorization_decision: &'static str,
    pub recorded_at_unix_nanos: i64,
}

#[derive(Default)]
pub struct ConnectionTraceLog {
    entries: Mutex<VecDeque<ConnectionAttemptTrace>>,
}

impl ConnectionTraceLog {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        peer_device_id: impl Into<String>,
        candidate_source: CandidateSource,
        address_class: AddressClass,
        outcome: AttemptOutcome,
        latency_ms: u64,
        failure_category: impl Into<String>,
        selected: bool,
        relay_identity: impl Into<String>,
        authorized: Option<bool>,
    ) {
        let entry = ConnectionAttemptTrace {
            peer_device_id: peer_device_id.into(),
            candidate_source: candidate_source.as_str(),
            address_class: address_class.as_str(),
            outcome: outcome.as_str(),
            latency_ms,
            failure_category: failure_category.into(),
            selected,
            relay_identity: relay_identity.into(),
            authorization_decision: match authorized {
                Some(true) => "authorized",
                Some(false) => "denied",
                None => "n/a",
            },
            recorded_at_unix_nanos: now_unix_nanos(),
        };
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.push_back(entry);
        while entries.len() > MAX_TRACE_ENTRIES {
            entries.pop_front();
        }
    }

    /// Most recent entries first, optionally filtered to one peer.
    pub fn recent(&self, peer_device_id: Option<&str>) -> Vec<ConnectionAttemptTrace> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .rev()
            .filter(|e| peer_device_id.is_none_or(|p| e.peer_device_id == p))
            .cloned()
            .collect()
    }
}

/// Connectivity-doctor categories. Each category's status is
/// derived from state this daemon already tracks cheaply (task liveness,
/// live peer statuses, this trace log, and folder-link pause state) —
/// deliberately not a full active network probe. Where the underlying
/// signal can't distinguish "this specific subsystem is down" from a
/// related-but-coarser condition, that's documented on the category
/// itself rather than left implicit, matching this crate's own precedent
/// (`control_socket::health_snapshot`'s `relay_connected` approximation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCategory {
    pub name: &'static str,
    /// "ok" | "warn" | "error".
    pub status: &'static str,
    pub detail: String,
}

fn category(
    name: &'static str,
    ok: bool,
    warn_detail: impl Into<String>,
    ok_detail: &'static str,
) -> DoctorCategory {
    if ok {
        DoctorCategory { name, status: "ok", detail: ok_detail.to_string() }
    } else {
        DoctorCategory { name, status: "warn", detail: warn_detail.into() }
    }
}

pub fn run_connectivity_doctor(state: &DaemonState) -> Vec<DoctorCategory> {
    let mut out = Vec::new();

    // "daemon": trivially true — this function is running inside it.
    out.push(DoctorCategory {
        name: "daemon",
        status: "ok",
        detail: "daemon process is running".to_string(),
    });

    let tasks = state.task_liveness.lock().unwrap_or_else(|p| p.into_inner());
    let control_socket_alive = tasks.get("control-socket").copied().unwrap_or(true);
    let peer_orchestrator_alive = tasks.get("peer-orchestrator").copied().unwrap_or(true);
    drop(tasks);

    out.push(category(
        "listener",
        control_socket_alive,
        "local control-socket listener task is not running",
        "local control-socket listener is running",
    ));

    // "coordination_plane"/"discovery"/"relay" all currently share one
    // underlying task (`peer_orchestrator::run` owns the netmap stream,
    // relay hub, and direct-candidate handling together) — see this
    // function's doc comment. A dead `peer_orchestrator` task means all
    // three are certainly down; a live one means only that none of them
    // have crashed the whole task, not that each is individually healthy
    // right now (recent trace evidence below narrows that further).
    let recent = state.connection_traces.recent(None);
    let recent_window = recent.iter().take(50);
    let mut discovery_seen_ok = false;
    let mut relay_seen_ok = false;
    let mut coordination_seen_ok = false;
    let mut denied_count = 0u32;
    for trace in recent_window {
        let ok = trace.outcome == "connected";
        match trace.candidate_source {
            "local_discovery" => discovery_seen_ok |= ok,
            "relay" => relay_seen_ok |= ok,
            "coordination_plane" => coordination_seen_ok |= ok,
            _ => {}
        }
        if trace.authorization_decision == "denied" {
            denied_count += 1;
        }
    }

    out.push(category(
        "coordination_plane",
        peer_orchestrator_alive && (coordination_seen_ok || recent.is_empty()),
        "no recent successful coordination-plane connection observed",
        "peer-orchestrator task is running",
    ));
    out.push(category(
        "discovery",
        peer_orchestrator_alive,
        "peer-orchestrator task (which owns local discovery) is not running",
        "peer-orchestrator task is running (local discovery has no dedicated failure signal yet)",
    ));
    let _ = discovery_seen_ok; // recorded for future finer-grained discovery status
    out.push(category(
        "relay",
        peer_orchestrator_alive && (relay_seen_ok || recent.is_empty()),
        "no recent successful relay connection observed",
        "peer-orchestrator task is running",
    ));

    out.push(if denied_count > 0 {
        DoctorCategory {
            name: "authorization",
            status: "warn",
            detail: format!(
                "{denied_count} recent connection attempt(s) were denied authorization"
            ),
        }
    } else {
        DoctorCategory {
            name: "authorization",
            status: "ok",
            detail: "no recent authorization denials".to_string(),
        }
    });

    let clock_ok = SystemTime::now().duration_since(UNIX_EPOCH).is_ok();
    out.push(category(
        "clock_config",
        clock_ok,
        "system clock reads before the Unix epoch",
        "system clock is readable and sane",
    ));

    let links = state.sync_state.list_links().unwrap_or_default();
    let all_paused = !links.is_empty() && links.iter().all(|l| l.paused);
    out.push(if all_paused {
        DoctorCategory {
            name: "policy_disabled",
            status: "warn",
            detail: "every linked folder is currently paused".to_string(),
        }
    } else {
        DoctorCategory {
            name: "policy_disabled",
            status: "ok",
            detail: "at least one linked folder is active".to_string(),
        }
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_bounded_and_return_newest_first() {
        let log = ConnectionTraceLog::new();
        for i in 0..(MAX_TRACE_ENTRIES + 10) {
            log.record(
                format!("device-{i}"),
                CandidateSource::Relay,
                AddressClass::RelayHop,
                AttemptOutcome::Connected,
                10,
                "",
                true,
                "relay-1",
                Some(true),
            );
        }
        let recent = log.recent(None);
        assert_eq!(recent.len(), MAX_TRACE_ENTRIES);
        // Newest first: the very last one recorded is device-(N+9).
        assert_eq!(recent[0].peer_device_id, format!("device-{}", MAX_TRACE_ENTRIES + 9));
    }

    #[test]
    fn filters_by_peer_device_id() {
        let log = ConnectionTraceLog::new();
        log.record(
            "device-a",
            CandidateSource::LocalDiscovery,
            AddressClass::Lan,
            AttemptOutcome::Connected,
            5,
            "",
            true,
            "",
            Some(true),
        );
        log.record(
            "device-b",
            CandidateSource::Relay,
            AddressClass::RelayHop,
            AttemptOutcome::Failed,
            0,
            "relay_closed",
            false,
            "relay-1",
            None,
        );
        let filtered = log.recent(Some("device-a"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].peer_device_id, "device-a");
    }

    #[test]
    fn never_carries_a_raw_address_field() {
        // Structural guarantee, not a runtime one: `ConnectionAttemptTrace`
        // has no field that could hold a raw socket address at all — this
        // test exists to force a compile error (via an exhaustive match
        // with named bindings) if a future edit ever adds one without
        // updating this note.
        let trace = ConnectionAttemptTrace {
            peer_device_id: "device-a".into(),
            candidate_source: "relay",
            address_class: "relay",
            outcome: "connected",
            latency_ms: 1,
            failure_category: String::new(),
            selected: true,
            relay_identity: "relay-1".into(),
            authorization_decision: "authorized",
            recorded_at_unix_nanos: 0,
        };
        let ConnectionAttemptTrace {
            peer_device_id: _,
            candidate_source: _,
            address_class: _,
            outcome: _,
            latency_ms: _,
            failure_category: _,
            selected: _,
            relay_identity: _,
            authorization_decision: _,
            recorded_at_unix_nanos: _,
        } = trace;
    }
}
