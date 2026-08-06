//! Owns this device's live peer state: the running sync sessions
//! (`device_id -> Arc<PeerSyncSession>`) and each peer's last-known
//! reachability. Both maps are private -- every caller reaches them
//! through this type's own methods, never a raw `MutexGuard`/`HashMap`
//! crossing the module boundary. `peer_orchestrator.rs`'s own doc comments
//! encode exact ordering guarantees around session teardown/revocation
//! against this same data; the methods here preserve those guarantees
//! exactly (same lock scopes, same removal semantics) rather than
//! reshaping them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use yadorilink_peer_session::peer_session::PeerSyncSession;

/// Why a peer could not be connected. Rendered by the CLI and desktop app
/// as the reason a peer "cannot connect", and mapped verbatim onto the
/// control socket's peer-status wire fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCategory {
    /// No candidate address to try at all (no endpoints learned).
    NoCandidates,
    /// Candidates were probed but stayed silent — most often a symmetric
    /// NAT or CGNAT pair that cannot be traversed.
    NoResponse,
    /// No datagram could get out at all (even local/STUN probes failed).
    UdpBlocked,
    /// The peer answered but refused the handshake — a key or
    /// authorization mismatch, distinct from being unreachable on the
    /// network.
    HandshakeRefused,
}

impl UnreachableCategory {
    /// Stable wire/status slug.
    pub fn as_str(self) -> &'static str {
        match self {
            UnreachableCategory::NoCandidates => "no_candidates",
            UnreachableCategory::NoResponse => "no_response",
            UnreachableCategory::UdpBlocked => "udp_blocked",
            UnreachableCategory::HandshakeRefused => "handshake_refused",
        }
    }
}

/// A peer's live connectivity as tracked by the daemon and reported to the
/// CLI and desktop app. There is no operator-run relay: a peer is either
/// being connected, connected over a confirmed direct path, or cannot be
/// connected at all (with the reason it can't).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// Candidate paths are still being raced; not yet connected, but not
    /// yet given up on either.
    Connecting,
    /// A direct path to the peer is confirmed and in use.
    Connected,
    /// Transport is up, but sync protocol negotiation completed without the
    /// mandatory change-DAG capability.
    ProtocolIncompatible,
    /// The peer cannot currently be reached; carries why.
    Unreachable(UnreachableCategory),
}

impl PeerReachability {
    pub fn is_connected(self) -> bool {
        matches!(self, PeerReachability::Connected)
    }

    /// Stable wire/status slug: "connecting" | "connected" | "unreachable".
    pub fn as_str(self) -> &'static str {
        match self {
            PeerReachability::Connecting => "connecting",
            PeerReachability::Connected => "connected",
            PeerReachability::ProtocolIncompatible => "protocol_incompatible",
            PeerReachability::Unreachable(_) => "unreachable",
        }
    }

    /// The failure-category slug when unreachable, otherwise empty.
    pub fn unreachable_category_str(self) -> &'static str {
        match self {
            PeerReachability::Unreachable(category) => category.as_str(),
            PeerReachability::ProtocolIncompatible => "",
            _ => "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerStatusInfo {
    pub reachability: PeerReachability,
}

/// One peer's session presence plus its last-known reachability, as
/// returned by [`PeerRegistry::snapshot`] for status/health rendering.
pub struct PeerSnapshot {
    pub device_id: String,
    pub reachability: PeerReachability,
    /// Whether a session is currently registered for this device (distinct
    /// from `reachability`, since a status entry can outlive/precede an
    /// actual session -- e.g. `Connecting` before the session is inserted).
    pub has_session: bool,
    /// Whether the live session (if any) has completed peer handshake but
    /// not negotiated the change-DAG capability -- callers combine this
    /// with `reachability == Connected` to report `ProtocolIncompatible`,
    /// matching `control_socket.rs`'s existing status-handler override.
    pub protocol_incompatible: bool,
}

pub struct PeerRegistry {
    /// device_id -> the running sync session, so local changes can be
    /// broadcast and sessions torn down on ACL revocation.
    sessions: Mutex<HashMap<String, Arc<PeerSyncSession>>>,
    statuses: Mutex<HashMap<String, PeerStatusInfo>>,
}

impl PeerRegistry {
    pub(crate) fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()), statuses: Mutex::new(HashMap::new()) }
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<PeerSyncSession>>> {
        self.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_statuses(&self) -> std::sync::MutexGuard<'_, HashMap<String, PeerStatusInfo>> {
        self.statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The live session for `device_id`, if any.
    pub fn session(&self, device_id: &str) -> Option<Arc<PeerSyncSession>> {
        self.lock_sessions().get(device_id).cloned()
    }

    /// Whether a session is currently registered for `device_id`.
    pub fn has_session(&self, device_id: &str) -> bool {
        self.lock_sessions().contains_key(device_id)
    }

    /// Every live session that shares `group_id`, sorted by device id (the
    /// deterministic order the materialization-repair candidate loop
    /// requires).
    pub fn sessions_for_group(&self, group_id: &str) -> Vec<(String, Arc<PeerSyncSession>)> {
        let sessions = self.lock_sessions();
        let mut candidates: Vec<_> = sessions
            .iter()
            .filter(|(_, session)| session.shares_group(group_id))
            .map(|(peer_id, session)| (peer_id.clone(), session.clone()))
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates
    }

    /// Every live session, device id paired with its `Arc`.
    pub fn all_sessions(&self) -> Vec<(String, Arc<PeerSyncSession>)> {
        self.lock_sessions().iter().map(|(id, session)| (id.clone(), session.clone())).collect()
    }

    /// Count of currently live sessions.
    pub fn session_count(&self) -> usize {
        self.lock_sessions().len()
    }

    /// Installs `session` as the current session for `device_id`,
    /// returning whatever session (if any) it replaced.
    pub fn register_session(
        &self,
        device_id: String,
        session: Arc<PeerSyncSession>,
    ) -> Option<Arc<PeerSyncSession>> {
        self.lock_sessions().insert(device_id, session)
    }

    /// Removes `device_id`'s session unconditionally, whatever it is --
    /// used for forced teardown/revocation paths that must clear the slot
    /// regardless of which session (if any) currently occupies it.
    pub fn remove(&self, device_id: &str) -> Option<Arc<PeerSyncSession>> {
        self.lock_sessions().remove(device_id)
    }

    /// Removes `device_id`'s session only if it is still exactly `expected`
    /// (identity via `Arc::ptr_eq`), so a task ending an old session can
    /// never delete a newer session a fresher connection has since
    /// installed. Returns whether a removal happened.
    pub fn remove_if_current(&self, device_id: &str, expected: &Arc<PeerSyncSession>) -> bool {
        let mut sessions = self.lock_sessions();
        let matches = sessions.get(device_id).is_some_and(|current| Arc::ptr_eq(current, expected));
        if matches {
            sessions.remove(device_id);
        }
        matches
    }

    /// Records `device_id`'s current reachability, overwriting any
    /// previous value.
    pub fn set_reachability(&self, device_id: String, reachability: PeerReachability) {
        self.lock_statuses().insert(device_id, PeerStatusInfo { reachability });
    }

    /// `device_id`'s last-recorded reachability, if any status has ever
    /// been set for it.
    pub fn reachability(&self, device_id: &str) -> Option<PeerReachability> {
        self.lock_statuses().get(device_id).map(|info| info.reachability)
    }

    /// Updates `device_id`'s reachability only if a status entry already
    /// exists for it (as opposed to [`set_reachability`], which creates
    /// one). Returns whether an entry was found and updated -- callers use
    /// this to detect "the status entry is already gone" (the session
    /// ended) and stop polling, rather than resurrecting a removed entry.
    ///
    /// [`set_reachability`]: PeerRegistry::set_reachability
    pub fn update_reachability_if_present(
        &self,
        device_id: &str,
        reachability: PeerReachability,
    ) -> bool {
        let mut statuses = self.lock_statuses();
        match statuses.get_mut(device_id) {
            Some(info) => {
                info.reachability = reachability;
                true
            }
            None => false,
        }
    }

    /// Removes `device_id`'s status entry -- used alongside `remove`/
    /// `remove_if_current` when a session ends, so a stale status can never
    /// linger and be reported after the session it described is gone.
    pub fn clear_status(&self, device_id: &str) {
        self.lock_statuses().remove(device_id);
    }

    /// Count of peers whose last-recorded reachability is `Connected`.
    pub fn connected_peer_count(&self) -> u32 {
        self.lock_statuses().values().filter(|info| info.reachability.is_connected()).count() as u32
    }

    /// A snapshot of every peer with a recorded status, each combined with
    /// whether a session currently exists for it and whether that session
    /// has negotiated a change-DAG (used by callers to detect the
    /// `Connected`-but-`ProtocolIncompatible` case). Order is unspecified.
    pub fn snapshot(&self) -> Vec<PeerSnapshot> {
        let statuses = self.lock_statuses();
        let sessions = self.lock_sessions();
        statuses
            .iter()
            .map(|(device_id, info)| {
                let session = sessions.get(device_id);
                PeerSnapshot {
                    device_id: device_id.clone(),
                    reachability: info.reachability,
                    has_session: session.is_some(),
                    protocol_incompatible: session.is_some_and(|session| {
                        session.peer_handshake_received() && !session.change_dag_negotiated()
                    }),
                }
            })
            .collect()
    }
}
