//! Connects the daemon to the coordination plane's netmap stream and, for
//! each authorized peer that appears, establishes a `PeerChannel` by racing
//! its direct candidate addresses and runs a `PeerSyncSession` over it. A
//! peer that no candidate can reach is reported unreachable (with a
//! category) rather than silently routed anywhere else.
//!
//! Deliberately simple for this MVP: once a peer session is established
//! it is never torn down here even if later removed from the netmap
//! (ACL-revocation teardown is a documented follow-up); this only ever
//! *adds* sessions as new peers appear.
//!
//! The coordination netmap subscription
//! (channel connect, RPC, stream) used to be one-shot: any failure,
//! including one on the very first attempt before the network was up,
//! permanently ended `run` and left the daemon with no P2P sync until a
//! human restarted it.
//! `run` now retries that whole setup forever with backoff (every failure
//! — initial or later — is just another attempt); `run` itself stays up
//! for the daemon's whole lifetime (see its doc comment).
//!
//! That retry loop deliberately runs *inline* in `run`'s own task rather
//! than via `supervise::spawn_restarting`: `spawn_restarting` retries
//! inside a second, independently `tokio::spawn`ed task, so externally
//! aborting the task *running* `run` (as `main.rs`'s graceful
//! shutdown does, via `JoinSet::shutdown`) would only cancel `run`'s
//! `.await` on that task's `JoinHandle` — the detached retry loop
//! underneath would keep running past the abort (confirmed against
//! `supervise::tests::spawn_restarting_stops_when_aborted_from_outside`,
//! which only asserts no *new* attempt starts after abort, not that an
//! *in-flight* one stops). Keeping the loop inline means an external
//! abort of `run`'s task cancels it mid-connect or mid-sleep with nothing
//! left running behind it — see `reconnect_delay`'s doc comment for the
//! resulting small duplication of `BackoffConfig`'s jitter math.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_transport::{
    classify_endpoint, connect_role, diff_netmap, start_local_discovery, CandidateClass,
    ConnectRole, DeviceSigningKeyPair, NatClass, NetmapDiff, NetmapSnapshot, PunchConfig,
    PunchDecision, PunchLimiter, QuicPeerChannel, QuicPeerEndpoint,
};

use crate::connection_trace::{AddressClass, AttemptOutcome, CandidateSource};
use crate::coordination_client::EndpointCandidate;
use crate::daemon_state::DaemonState;
use crate::device_config;
use crate::error::DaemonError;
use crate::peer_registry::{PeerReachability, UnreachableCategory};
use crate::route::RouteKind;
use crate::supervise::BackoffConfig;

pub struct OrchestratorConfig {
    pub coordination_addr: String,
    pub access_token: String,
    pub device_id: String,
}

/// Auxiliary, netmap-diff-only bookkeeping that doesn't belong on
/// `DaemonState` (which tracks *connected* sessions, not "the netmap"
/// as such) — the previously-held netmap snapshot to diff each new
/// push against (`yadorilink_transport::diff_netmap`), plus enough of
/// a handle on each peer's live transport channel and session task to
/// actually tear a revoked one down immediately rather than waiting
/// for it to notice on its own.
///
/// Constructed once in `run` and threaded through every
/// `run_netmap_attempt` call (cheap to `Clone` — every field is an
/// `Arc`) so it survives a coordination-stream reconnect: a
/// revocation observed before a stream drop must still apply after the
/// stream reconnects, and — just as importantly — a fresh reconnect's
/// first snapshot must be diffed against the *last real* netmap, not an
/// empty one (an empty "previous" would report zero removals no matter
/// what changed, silently forgetting any revocation the diff hasn't
/// already acted on).
#[derive(Clone)]
struct NetmapDiffState {
    previous: Arc<StdMutex<NetmapSnapshot>>,
    /// Last authoritative Worker snapshot admitted by this daemon. It lives
    /// across WebSocket reconnects so a delayed/replayed snapshot cannot
    /// restore authorization or full-replica metadata that a newer snapshot
    /// already revoked.
    last_snapshot_generation: Arc<StdMutex<Option<u64>>>,
    /// This device's one QUIC endpoint, built on first use.
    ///
    /// One per device, not one per peer: a `quinn::Endpoint` is the
    /// demultiplexer that owns a UDP binding, and this device has exactly
    /// one binding -- the transport hub's, shared with STUN and the relay
    /// envelope, because a STUN-reflexive or port-mapped candidate is only
    /// meaningful when it names the exact socket data flows on. Peers are
    /// separated inside the endpoint by QUIC connection id.
    ///
    /// It lives here rather than in `run`'s locals because two very
    /// different call sites need the same one: the netmap update loop,
    /// which is the only thing that knows which peers are authorized, and
    /// every peer supervisor, which is the only thing that dials. Built
    /// lazily because it needs the shared socket, whose bind is fallible
    /// and asynchronous, and a bind failure must be a retryable per-attempt
    /// outcome rather than something that kills the coordination loop.
    quic_endpoint: Arc<tokio::sync::OnceCell<Arc<QuicPeerEndpoint>>>,
    /// device_id -> the `JoinHandle` for its `spawn_peer_session` task, so
    /// a whole-device revocation can abort the in-flight
    /// `PeerSyncSession::run` (and whatever it's mid-request on)
    /// immediately rather than relying on it to notice its `PeerChannel`
    /// died on its own. A session that ends on its own (not via
    /// revocation) leaves its now-finished handle here for
    /// `prune_finished_session_tasks` to sweep — only the task that
    /// inserted a handle (this module's own update loop) can remove it,
    /// a spawned task cannot reach into this map to remove its own entry.
    session_tasks: Arc<StdMutex<HashMap<String, JoinHandle<()>>>>,
    /// Per-peer hole-punch bounds/backoff (`device_id` keyed), so a rendezvous
    /// is offered to any one peer only a bounded number of times before it is
    /// judged unreachable. Threaded through every `run_netmap_attempt` like
    /// the maps above so the bound survives a coordination-stream reconnect.
    punch_limiter: Arc<StdMutex<PunchLimiter<String>>>,
    /// device_id -> the latest connect parameters this daemon knows for that
    /// peer (public key, candidate addresses, authorized groups) — the
    /// source of truth `spawn_peer_session`'s reconnect loop re-reads at the
    /// START of every attempt, not just its first. Without this, a
    /// supervisor asleep in its reconnect backoff would keep retrying
    /// against a candidate list captured once at first-spawn time, forever,
    /// even after a later netmap push moved the peer to a new endpoint.
    /// Every netmap update upserts this unconditionally for every peer it
    /// carries, whether or not a session is currently live for that peer
    /// (mirrors `replace_coordination_candidates`'s live-session path, one
    /// layer earlier so a backoff-sleeping supervisor sees it too).
    desired_peers: Arc<StdMutex<HashMap<String, PeerConnectSpec>>>,
    /// M3 Pass 3: `ReconnectCoordinator` -- a single global bound on how many
    /// peer supervisors may be mid-handshake-attempt at once, across every
    /// peer this device is reconnecting to. Without this, a steady-state
    /// event that drops many sessions at once (a network flap, a Wi-Fi
    /// roam, this process itself waking from sleep) makes every affected
    /// supervisor race its handshake attempt simultaneously -- a thundering
    /// herd of concurrent crypto/candidate-race work, independent of and in
    /// addition to the already-fixed O(N^2) fan-in cost (Pass 2) and the
    /// existing PER-PEER backoff+jitter (which only staggers ONE peer's OWN
    /// repeated attempts against itself, not concurrent attempts across
    /// DIFFERENT peers). The permit is acquired only immediately before the
    /// actual handshake attempt -- never held across backoff sleep, which
    /// happens entirely in `spawn_peer_session`'s loop, outside the scope
    /// that touches this semaphore -- and released once that attempt
    /// resolves one way or the other (session established, or the attempt
    /// failed).
    ///
    /// The permit covers one peer's whole attempt, which since candidate
    /// racing means one peer's whole *race* -- see
    /// `RECONNECT_HANDSHAKE_CONCURRENCY` for what that multiplies out to in
    /// handshakes, and for the measurement that says the product is fine.
    reconnect_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bumped once per applied netmap snapshot, so a live peer session can
    /// be told that what this device knows about how to reach its peer has
    /// changed.
    ///
    /// A live session needs nothing from an ordinary push -- it is already
    /// connected, and refreshed candidates describe how to *reach* a peer.
    /// It does need to know when the address it is connected on has stopped
    /// being advertised, because that is the coordination plane saying the
    /// path it is using is no longer one the peer expects to be reached at.
    /// A counter rather than a notification, so a supervisor that was busy
    /// when a push landed still sees it rather than missing the wakeup.
    netmap_epoch: Arc<tokio::sync::watch::Sender<u64>>,
    /// device_id -> (candidate address, last-announced-at) learned from
    /// unauthenticated local network discovery
    /// (`yadorilink_transport::start_local_discovery`), kept separate from
    /// `desired_peers`'s own coordination/rendezvous-sourced candidates
    /// rather than folded in, so `run_one_peer_session_attempt` can record
    /// which source an attempt actually drew from.
    ///
    /// LAN discovery only ever surfaces a public key already present in
    /// `DaemonState`'s pinned peer set (see `local_discovery`'s own module
    /// doc comment), so an entry here can only ever name a device this
    /// daemon already trusts -- it adds an address to dial, never a peer to
    /// trust. The QUIC handshake still authenticates every candidate
    /// against that same pinned key regardless of which map it came from.
    ///
    /// The timestamp is load-bearing, not informational: an unauthenticated
    /// LAN attacker who has merely observed a real peer's public key
    /// (broadcast in cleartext, by design -- see `local_discovery`'s own
    /// module doc comment) can forge announcements carrying it, since the
    /// broadcast layer itself does not authenticate. Without TTL-based
    /// expiry a first-come cap would let such an attacker permanently
    /// occupy every slot for a peer (denying real LAN discovery for the
    /// rest of the process's life) and would never let a legitimate peer's
    /// changed address (DHCP renewal, network switch, restart) replace a
    /// stale one. `handle_lan_announcement` prunes expired entries and, if
    /// still full, evicts the least-recently-seen one to make room --
    /// bounding how long any one entry (forged or real) can occupy a slot
    /// without being re-announced. This is a bound, not a full defense:
    /// nothing here rate-limits a determined attacker who keeps
    /// re-announcing faster than the TTL (the transport layer's own
    /// per-source-IP rate limit, `local_discovery::MAX_ANNOUNCEMENTS_
    /// PER_SOURCE_WINDOW`, is the only mitigation for that, and it is
    /// deliberately coarse). The trust boundary this cache feeds is
    /// unaffected either way: whatever address ends up here is still just
    /// a dial target, never authorization, so the worst a successful
    /// poisoning achieves is denying a LAN-discovery *convenience* for the
    /// process lifetime, not a security bypass.
    lan_discovered: Arc<StdMutex<HashMap<String, Vec<(SocketAddr, Instant)>>>>,
}

/// How many peers this device may be mid-connection-attempt with at once
/// (see `NetmapDiffState::reconnect_semaphore`).
///
/// It counts *peers*, not handshakes, and the difference is worth stating
/// because it did not used to exist. An attempt is now a candidate race, and
/// a race opens one handshake per candidate -- so this admits up to
/// `RECONNECT_HANDSHAKE_CONCURRENCY * MAX_RACED_CANDIDATES` outgoing
/// handshakes, thirty-two rather than four. The name predates that and the
/// old comment described a per-handshake worker pool in a transport that no
/// longer exists.
///
/// Thirty-two is measured rather than assumed to be acceptable:
/// `candidate_race_fan_in.rs` drives sixteen concurrent races of eight
/// candidates each -- a hundred and twenty-eight concurrent handshakes, four
/// times this ceiling -- and they complete in about 1.8s for roughly 8 MiB
/// of resident memory. The cost that matters is per in-flight handshake and
/// it is small; what this bound is really for is stopping every peer from
/// re-attempting at once after an event that drops many sessions together (a
/// network flap, a Wi-Fi roam, waking from sleep), which is a scheduling
/// concern rather than a memory one.
const RECONNECT_HANDSHAKE_CONCURRENCY: usize = 4;

/// One peer's current connect parameters, re-read by
/// `spawn_peer_session`'s reconnect loop at the start of every attempt —
/// see `NetmapDiffState::desired_peers`'s own doc comment.
#[derive(Clone)]
struct PeerConnectSpec {
    candidates: Vec<SocketAddr>,
    effective_group_ids: Vec<String>,
}

impl NetmapDiffState {
    fn new() -> Self {
        Self {
            previous: Arc::new(StdMutex::new(HashMap::new())),
            last_snapshot_generation: Arc::new(StdMutex::new(None)),
            quic_endpoint: Arc::new(tokio::sync::OnceCell::new()),
            session_tasks: Arc::new(StdMutex::new(HashMap::new())),
            punch_limiter: Arc::new(StdMutex::new(PunchLimiter::new(PunchConfig::default()))),
            desired_peers: Arc::new(StdMutex::new(HashMap::new())),
            reconnect_semaphore: Arc::new(tokio::sync::Semaphore::new(
                RECONNECT_HANDSHAKE_CONCURRENCY,
            )),
            netmap_epoch: Arc::new(tokio::sync::watch::channel(0).0),
            lan_discovered: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

/// How many LAN-discovered addresses this device will keep for one peer.
/// Matches `MAX_PEER_CANDIDATES`'s reasoning: bounded so a noisy/misbehaving
/// broadcaster cannot make one peer's candidate set grow without bound (on
/// top of `local_discovery`'s own per-source rate limiting).
const MAX_LAN_DISCOVERED_CANDIDATES: usize = 4;

/// How long a LAN-learned candidate stays usable without being
/// re-announced -- see `NetmapDiffState::lan_discovered`'s own doc comment
/// for why this bound exists. Generous relative to
/// `local_discovery`'s own 30s announce interval (ordinary jitter or a
/// missed announcement or two must not evict a still-live peer), but short
/// enough that a changed address or a stale/forged entry does not survive
/// indefinitely.
const LAN_DISCOVERED_CANDIDATE_TTL: Duration = Duration::from_secs(180);

/// The LAN-discovered candidates for `peer_device_id` that are still within
/// `LAN_DISCOVERED_CANDIDATE_TTL` of `now`, from an already-locked
/// `lan_discovered` map. A pure, independently-testable read-time
/// complement to `handle_lan_announcement`'s own write-time TTL pruning --
/// see `NetmapDiffState::lan_discovered`'s own doc comment for why BOTH
/// sides need the TTL applied, not just the write side.
fn ttl_filtered_lan_candidates(
    lan_discovered: &HashMap<String, Vec<(SocketAddr, Instant)>>,
    peer_device_id: &str,
    now: Instant,
) -> Vec<SocketAddr> {
    lan_discovered
        .get(peer_device_id)
        .map(|entries| {
            entries
                .iter()
                .filter(|(_, seen_at)| now.duration_since(*seen_at) <= LAN_DISCOVERED_CANDIDATE_TTL)
                .map(|(addr, _seen_at)| *addr)
                .collect()
        })
        .unwrap_or_default()
}

/// Folds one LAN discovery announcement into `diff_state.lan_discovered`.
/// Resolves the announcement's public key back to a device id via
/// `DaemonState`'s own pinned peer set -- an announcement naming a key this
/// device does not already have pinned (an unauthorized device, or a
/// stale/spoofed key) resolves to `None` and is dropped here, same as
/// `handle_incoming_rendezvous` drops a rendezvous signal for a peer with
/// no connect spec yet.
///
/// TTL-pruned and least-recently-seen-evicted on every call, not just
/// appended -- see `NetmapDiffState::lan_discovered`'s own doc comment for
/// why an unbounded first-come cap is unsafe here.
fn handle_lan_announcement(
    announcement: yadorilink_transport::PeerAnnouncement,
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) {
    let Some(device_id) = state.device_id_for_signing_key(&announcement.public_key) else {
        tracing::debug!("LAN discovery announcement from an unpinned key; ignoring");
        return;
    };
    // Only worth keeping if this device actually wants to reach that peer --
    // mirrors `handle_incoming_rendezvous`'s identical "no connect spec yet"
    // drop.
    if !diff_state.desired_peers.lock().unwrap_or_else(|p| p.into_inner()).contains_key(&device_id)
    {
        return;
    }
    let now = Instant::now();
    let mut lan_discovered = diff_state.lan_discovered.lock().unwrap_or_else(|p| p.into_inner());
    let entry = lan_discovered.entry(device_id).or_default();
    entry.retain(|(_, seen_at)| now.duration_since(*seen_at) <= LAN_DISCOVERED_CANDIDATE_TTL);

    if let Some(existing) = entry.iter_mut().find(|(addr, _)| *addr == announcement.addr) {
        existing.1 = now;
        return;
    }
    if entry.len() >= MAX_LAN_DISCOVERED_CANDIDATES {
        // Full even after pruning expired entries -- evict the
        // least-recently-seen one to make room for this one, rather than
        // refusing it outright. Bounds how long any single entry (forged
        // or real) can occupy a slot without being the most recently
        // re-announced; see this function's own doc comment.
        if let Some((oldest_index, _)) =
            entry.iter().enumerate().min_by_key(|(_, (_, seen_at))| *seen_at)
        {
            entry.remove(oldest_index);
        }
    }
    entry.push((announcement.addr, now));
}

/// Reacts to inbound rendezvous signals by folding the candidates the peer
/// offered into the connect parameters its supervisor re-reads at the start
/// of every attempt, so the next attempt tries an address this device may
/// never have been told about by the coordination plane.
///
/// It deliberately does not fire a synchronized probe burst back at those
/// addresses. Under QUIC a probe is a dial, and a dial is not a free packet:
/// which side of a pair dials is fixed by device-id ordering precisely so
/// that a pair ends up with one connection rather than two, and firing dials
/// outside that rule would produce connections no session ever claims. Making
/// simultaneous-open work under QUIC belongs with the candidate-racing work
/// as a whole, not here.
///
/// A signal naming a peer this device has no connect spec for is dropped --
/// there is nothing yet to attach the candidates to, and the next netmap
/// push creates that spec along with the peer's supervisor.
fn handle_incoming_rendezvous(
    signals: Vec<(String, Vec<SocketAddr>)>,
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) {
    for (from_device_id, candidates) in signals {
        if candidates.is_empty() {
            continue;
        }
        let mut desired =
            diff_state.desired_peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(spec) = desired.get_mut(&from_device_id) else {
            tracing::debug!(
                peer = %from_device_id,
                "rendezvous signal for a peer this device has no connect spec for; ignoring"
            );
            continue;
        };
        // Appended, not replaced: the coordination plane's own endpoints for
        // this peer are still valid, and a rendezvous offer is additional
        // information about the same peer rather than a correction to it.
        // Capped so a peer that signals repeatedly cannot grow one entry
        // without bound.
        for candidate in candidates {
            if spec.candidates.len() >= MAX_PEER_CANDIDATES {
                break;
            }
            if !spec.candidates.contains(&candidate) {
                spec.candidates.push(candidate);
            }
        }
        drop(desired);
        // Record that a punch was attempted so classification can reach
        // `UdpBlocked` if no attempt ever confirms a direct path.
        state.nat_observations.record_punch_attempt(false);
    }
}

/// How many addresses this device will keep for one peer. Matches the cap
/// the transport applied to its own candidate set, so a rendezvous flood
/// cannot make any one peer's connect spec grow without bound, and a dial
/// sweep stays bounded in time.
const MAX_PEER_CANDIDATES: usize = 8;

/// Offers this device's current server-reflexive candidates to a wanted but
/// unconnected peer via the coordination plane, so both sides can begin
/// simultaneous probing. Rate-limited per peer; once the per-peer attempt
/// bound is spent the peer is marked unreachable with a category derived from
/// this device's own NAT classification. A no-op when this device has no
/// server-reflexive candidate to offer (nothing punchable to propose).
fn maybe_initiate_rendezvous(
    peer_device_id: &str,
    config: &OrchestratorConfig,
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) {
    let reflexive: Vec<EndpointCandidate> = state
        .nat_candidates
        .borrow()
        .iter()
        .filter(|c| c.class == CandidateClass::ServerReflexive)
        .map(|c| EndpointCandidate { address: c.addr.to_string(), priority: c.priority() })
        .collect();
    if reflexive.is_empty() {
        return;
    }

    let decision = {
        let mut limiter =
            diff_state.punch_limiter.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        limiter.on_request(peer_device_id.to_string(), tokio::time::Instant::now())
    };
    match decision {
        PunchDecision::Proceed => {
            let addr = config.coordination_addr.clone();
            let token = config.access_token.clone();
            let device_id = config.device_id.clone();
            let target = peer_device_id.to_string();
            tokio::spawn(async move {
                crate::coordination_client::send_rendezvous(
                    &addr, &token, device_id, target, &reflexive,
                )
                .await;
            });
        }
        PunchDecision::BackOff { .. } => {}
        PunchDecision::Exhausted => {
            let category = nat_class_to_unreachable(yadorilink_transport::classify(
                &state.nat_observations.snapshot(),
            ));
            set_reachability(state, peer_device_id, PeerReachability::Unreachable(category));
        }
    }
}

/// Maps this device's NAT classification onto the reason a peer that could
/// not be punched is reported unreachable.
fn nat_class_to_unreachable(class: NatClass) -> UnreachableCategory {
    match class {
        NatClass::UdpBlocked => UnreachableCategory::UdpBlocked,
        _ => UnreachableCategory::NoResponse,
    }
}

/// Applies one peer entry from a full netmap snapshot to every live
/// authorization consumer. This runs for existing sessions too; connection
/// deduplication is deliberately a later concern.
fn apply_authoritative_peer_metadata(
    state: &Arc<DaemonState>,
    device_id: &str,
    signing_key: Option<[u8; 32]>,
    authorized_groups: &HashSet<String>,
    full_replica_groups: &HashSet<String>,
    relay_capable: bool,
    validation_cache: &std::sync::Mutex<HashMap<String, bool>>,
) -> HashSet<String> {
    // Seed identity only. Group authorization is withheld until the local
    // policy + retained-history validator positively admits it. Relay
    // capability is NOT gated on that validation the way group
    // authorization is -- see `crate::route::RelayCapability`'s own doc
    // comment -- so it is recorded here already, on both calls, rather
    // than only once authorization clears.
    state.replace_peer_netmap_metadata(
        device_id,
        signing_key,
        &HashSet::new(),
        &HashSet::new(),
        relay_capable,
    );

    let effective_groups = crate::change_auth::NetmapChangeAuthenticator::effective_servable_groups(
        state.clone(),
        authorized_groups,
        validation_cache,
    );
    let effective_full_replica_groups: HashSet<String> =
        full_replica_groups.intersection(&effective_groups).cloned().collect();

    state.replace_peer_netmap_metadata(
        device_id,
        signing_key,
        &effective_groups,
        &effective_full_replica_groups,
        relay_capable,
    );
    if let Some(session) = state.peers.session(device_id) {
        session.set_authorized_groups(effective_groups.iter().cloned());
    }
    effective_groups
}

fn has_duplicate_peer_ids<'a>(peer_ids: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    peer_ids.into_iter().any(|device_id| !seen.insert(device_id))
}

fn record_group_policy_states(
    state: &Arc<DaemonState>,
    coordination_endpoint: &str,
    service_key_pins: &mut HashMap<String, String>,
    service_public_key: &[u8],
    logs: &[crate::change_policy::GroupPolicyLog],
) -> Result<(), DaemonError> {
    let presented_key = <[u8; 32]>::try_from(service_public_key)
        .map_err(|_| DaemonError::Config("policy service public key is not 32 bytes".into()))?;
    let presented_hex = hex::encode(presented_key);
    let (verification_key, pin_decision) =
        policy_service_key_pin_decision(service_key_pins, coordination_endpoint, presented_key)?;
    // M3 Pass 5: mirrored onto `DaemonState` (not just this attempt-scoped
    // `service_key_pins` map) so relay-grant verification -- which can
    // happen at any later point, independent of any specific netmap
    // subscription attempt -- has the SAME trust anchor
    // `change_policy::verify_group_policy_log` already uses, without
    // needing its own separate pinning flow.
    state.set_pinned_coordination_service_key(verification_key);

    let mut states = HashMap::new();
    let mut stale_groups: Vec<String> = Vec::new();
    for log in logs {
        let base = state.group_policy_state(&log.group_id);
        match crate::change_policy::verify_group_policy_log_with_base(
            &verification_key,
            base.as_ref(),
            log,
        ) {
            Ok(policy) => {
                // A signature-valid chain is not enough: a PAST valid chain is
                // equally signature-valid, so a peer/coordination could replay
                // an old chain (especially right after a restart, when the
                // in-memory verified state is gone) to hide a later revoke.
                // The persisted per-group watermark is the highest chain this
                // device has ever verified and never moves backward; reject any
                // snapshot that would roll it back or fork it.
                let stored = state
                    .replica_coordinator
                    .policy_watermark_repository()
                    .policy_watermark(&log.group_id)
                    .map_err(crate::sync_error::SyncError::from)?;
                match policy.watermark_verdict(stored.as_ref()) {
                    crate::change_policy::WatermarkVerdict::Accept(watermark) => {
                        // Persist the (never-lowered) watermark BEFORE adopting
                        // the snapshot, so the anti-rollback guarantee is
                        // durable even if the daemon dies immediately after —
                        // a restart then still sees the higher watermark and
                        // refuses the old chain.
                        state
                            .replica_coordinator
                            .policy_watermark_repository()
                            .upsert_policy_watermark(&log.group_id, &watermark)
                            .map_err(crate::sync_error::SyncError::from)?;
                        states.insert(log.group_id.clone(), policy);
                    }
                    crate::change_policy::WatermarkVerdict::Reject(reason) => {
                        tracing::warn!(
                            group_id = %log.group_id,
                            reason = %reason,
                            "policy snapshot rejected by rollback watermark; marking group \
                             policy stale (change admission fails closed until a valid forward \
                             snapshot arrives)"
                        );
                        stale_groups.push(log.group_id.clone());
                    }
                }
            }
            Err(e) => {
                // One group's snapshot failing verification must not keep its
                // previously-trusted state — that would let a revoke carried
                // in this snapshot be silently ignored, leaving a revoked
                // writer trusted. Nor should it discard the other groups' valid
                // updates in the same snapshot or tear down existing sessions.
                // Drop this group from the trusted set and mark it stale so
                // change admission for it fails closed until a valid snapshot
                // arrives.
                tracing::warn!(
                    group_id = %log.group_id,
                    error = %e,
                    "policy log snapshot failed verification; marking group policy stale \
                     (change admission fails closed until a valid snapshot arrives)"
                );
                stale_groups.push(log.group_id.clone());
            }
        }
    }
    if pin_decision == PolicyServiceKeyPinDecision::RotationRequired {
        if states.is_empty()
            || states.values().any(|policy| policy.final_authority_key != presented_key)
        {
            return Err(DaemonError::Config(
                "policy service key changed without a verified rotation record".into(),
            ));
        }
        service_key_pins.insert(coordination_endpoint.to_string(), presented_hex);
        save_service_key_pins(service_key_pins)?;
    } else if pin_decision == PolicyServiceKeyPinDecision::NewPin {
        service_key_pins.insert(coordination_endpoint.to_string(), presented_hex);
        save_service_key_pins(service_key_pins)?;
    }
    // Mark the failed groups stale BEFORE swapping the trusted set, so
    // admission never sees a gap where a failed group is neither trusted under
    // its old state nor marked stale. The failed and verified group sets are
    // disjoint, so clearing the verified ones next can't un-mark a failed one.
    for group_id in &stale_groups {
        state.mark_group_policy_stale(group_id);
    }
    for group_id in states.keys() {
        state.clear_group_policy_stale(group_id);
    }
    state.replace_group_policy_states(states);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyServiceKeyPinDecision {
    NewPin,
    AlreadyPinned,
    RotationRequired,
}

fn policy_service_key_pin_decision(
    service_key_pins: &HashMap<String, String>,
    coordination_endpoint: &str,
    presented_key: [u8; 32],
) -> Result<([u8; 32], PolicyServiceKeyPinDecision), DaemonError> {
    let presented_hex = hex::encode(presented_key);
    match service_key_pins.get(coordination_endpoint) {
        None => Ok((presented_key, PolicyServiceKeyPinDecision::NewPin)),
        Some(pinned) if pinned == &presented_hex => {
            Ok((presented_key, PolicyServiceKeyPinDecision::AlreadyPinned))
        }
        Some(pinned) => {
            let pinned_bytes = hex::decode(pinned).map_err(|_| {
                DaemonError::Config("stored policy service key pin is malformed".into())
            })?;
            let pinned_key = <[u8; 32]>::try_from(pinned_bytes.as_slice()).map_err(|_| {
                DaemonError::Config("stored policy service key pin is not 32 bytes".into())
            })?;
            Ok((pinned_key, PolicyServiceKeyPinDecision::RotationRequired))
        }
    }
}

/// The UDP port this device's own LAN-discovery announcer/listener binds
/// and broadcasts to. Fixed rather than configurable: discovery only works
/// at all if every device on the LAN agrees on where to listen, same as
/// mDNS's own fixed port.
///
/// Deliberately NOT Syncthing's own registered local-discovery port
/// (21027): a host running both would otherwise fail this bind outright
/// (no `SO_REUSEADDR`/`SO_REUSEPORT` -- two unrelated protocols sharing a
/// socket would each misinterpret the other's packets, so allowing the
/// bind to "succeed" that way would be worse than failing it) with only a
/// `tracing::warn!` to show for it.
///
/// Also deliberately BELOW Linux's default ephemeral port range
/// (`/proc/sys/net/ipv4/ip_local_port_range`, typically 32768-60999): a
/// value inside that range risks a silent, nondeterministic bind failure
/// if any OTHER socket on the host -- including this same daemon's own
/// QUIC endpoint, which grabs an OS-assigned ephemeral port immediately
/// before this code runs -- happens to claim it first. Unlike the
/// Syncthing collision above, that failure mode is invisible and
/// unrepeatable (same one-shot `tracing::warn!`, no retry), which is worse
/// than a deterministic conflict. Picked with no known conflicting
/// well-known/registered use as of this writing.
const LAN_DISCOVERY_BROADCAST_PORT: u16 = 31027;

/// Starts this device's LAN discovery announcer/listener and the task that
/// folds its announcements into `diff_state.lan_discovered`, if this
/// device's own signing key and QUIC endpoint are both available. Returns
/// the discovery socket's own bound address on success -- otherwise unused
/// in production, but it gives a test a real address to send a raw
/// announcement packet to, so this exact function (not a substitute) can
/// be exercised end to end. `broadcast_port` is a parameter rather than
/// reading the module constant directly for the same reason: production
/// always passes `LAN_DISCOVERY_BROADCAST_PORT`, a test can pass `0` for
/// an OS-assigned ephemeral port and avoid colliding with any other test
/// or process using the real one.
///
/// The authorization check passed to `start_local_discovery` is LIVE --
/// `DaemonState::device_id_for_signing_key` reads `peer_netmap_metadata`
/// fresh on every announcement, never a set snapshotted here -- so this is
/// safe to call before the netmap loop has ever run (the netmap is the
/// ONLY writer of that metadata; a snapshot taken here at startup would be
/// permanently empty, silently discarding every announcement forever, not
/// just until the first netmap push -- this is the exact bug an earlier
/// version of this function had, and
/// `lan_discovery_started_before_any_peer_is_pinned_still_authorizes_one_
/// pinned_later` below exists specifically to catch a regression back to
/// it). Discovery starts working the moment any peer key is later pinned,
/// and correctly stops accepting a peer's announcements the moment it's
/// revoked, with nothing here needing to notice either transition.
async fn start_lan_discovery(
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
    broadcast_port: u16,
) -> Option<SocketAddr> {
    // Eagerly built (rather than left to its usual on-first-attempt lazy
    // init) so this device's real listening port is known before LAN
    // discovery starts announcing one -- discovery would otherwise have
    // nothing meaningful to broadcast until some peer's first connection
    // attempt happened to trigger the bind. A bind failure here is not
    // fatal to the whole daemon: it is exactly the same fallible path
    // `run_one_peer_session_attempt` already tolerates per-attempt, just
    // surfaced slightly earlier, so LAN discovery is simply skipped for
    // this run rather than the netmap loop below being blocked on it.
    let endpoint = match ensure_quic_endpoint(state, diff_state).await {
        Ok(endpoint) => endpoint,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to build this device's QUIC endpoint early for local discovery; will \
                 retry lazily on the first peer connection attempt, without LAN discovery for \
                 this run"
            );
            return None;
        }
    };
    let (Some(signing), Ok(local_addr)) = (state.device_signing_key(), endpoint.local_addr())
    else {
        return None;
    };
    let my_public_key = signing.verifying_key().to_bytes();
    let my_port = local_addr.port();
    let authorization_state = state.clone();
    let is_authorized =
        move |key: &[u8; 32]| authorization_state.device_id_for_signing_key(key).is_some();
    match start_local_discovery(my_public_key, my_port, broadcast_port, is_authorized).await {
        Ok((bound_addr, mut announcements)) => {
            let state = state.clone();
            let diff_state = diff_state.clone();
            tokio::spawn(async move {
                while let Some(announcement) = announcements.recv().await {
                    handle_lan_announcement(announcement, &state, &diff_state);
                }
            });
            Some(bound_addr)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                port = broadcast_port,
                "failed to start local network discovery (possibly a port conflict with \
                 another process bound to it); peers on this LAN will only be reachable via \
                 coordination-plane/rendezvous candidates"
            );
            None
        }
    }
}

/// Establishes this device's coordination-netmap subscription and, as
/// peers appear on it, their `PeerChannel`/`PeerSyncSession`s — and keeps
/// doing so for as long as the daemon runs.
///
/// Behavior contract callers (namely `main.rs`) can rely on: this is an
/// `async fn` meant to be spawned exactly once as an essential daemon
/// task. Under normal operation — including every kind of transient
/// failure this module retries (coordination connect, the
/// stream RPC itself) — it does
/// **not** return; the reconnect-with-backoff loop lives inside this
/// function's own task (see the module doc comment for why it's inline
/// rather than a nested spawned task), not in the caller. The only way it
/// stops is the task running it being cancelled from outside (e.g.
/// `main.rs`'s graceful shutdown aborting it) — cleanly, since there is
/// no detached child task left behind to leak.
pub async fn run(config: OrchestratorConfig, state: Arc<DaemonState>) -> Result<(), DaemonError> {
    let session_index = Arc::new(AtomicU32::new(0));
    // Created once here (not per-attempt) so it survives a
    // coordination-stream reconnect — see `NetmapDiffState`'s doc
    // comment.
    let diff_state = NetmapDiffState::new();

    let _ = start_lan_discovery(&state, &diff_state, LAN_DISCOVERY_BROADCAST_PORT).await;

    let mut attempt: u32 = 0;
    loop {
        match run_netmap_attempt(&config, &state, &session_index, &diff_state).await {
            Ok(()) => {
                tracing::warn!(attempt, "coordination netmap stream ended; reconnecting");
                // A clean stream end still means the coordination-plane
                // connection is no longer up (`run` is about to redial),
                // not a per-peer attempt so `peer_device_id` is empty.
                state.telemetry.record_connection_attempt(
                    "",
                    CandidateSource::CoordinationPlane,
                    AddressClass::Wan,
                    AttemptOutcome::Failed,
                    0,
                    "stream_ended",
                    false,
                    None,
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    attempt,
                    "coordination netmap subscription attempt failed; reconnecting"
                );
                state.telemetry.record_connection_attempt(
                    "",
                    CandidateSource::CoordinationPlane,
                    AddressClass::Wan,
                    AttemptOutcome::Failed,
                    0,
                    "connect_error",
                    false,
                    None,
                );
            }
        }
        let delay = reconnect_delay(attempt);
        tracing::info!(attempt, ?delay, "waiting before next coordination reconnect attempt");
        tokio::time::sleep(delay).await;
        attempt = attempt.saturating_add(1);
    }
}

/// Mirrors `supervise::BackoffConfig::RECONNECT`'s schedule (exponential
/// doubling from `initial`, capped at `max`, ±25% jitter) for `run`'s own
/// inline loop — `BackoffConfig::next` and its jitter RNG are private to
/// `supervise` (and deliberately not made `pub` for this one caller; see
/// the module doc comment for why this loop can't just reuse
/// `spawn_restarting` instead).
fn reconnect_delay(attempt: u32) -> Duration {
    let backoff = BackoffConfig::RECONNECT;
    let scale = 1u64 << attempt.min(20); // avoid overflow on a long-lived task
    let backed_off = backoff.initial.saturating_mul(scale as u32).min(backoff.max);
    let jitter_frac = jitter_unit_interval(); // [0, 1)
    let jitter_magnitude = backed_off.mul_f64(0.25 * jitter_frac);
    let jittered = if jitter_frac < 0.5 {
        backed_off.saturating_sub(jitter_magnitude)
    } else {
        backed_off.saturating_add(jitter_magnitude)
    };
    jittered.min(backoff.max)
}

/// A small, dependency-free `[0, 1)` PRNG (splitmix64 seeded from the
/// current time) — jitter doesn't need to be cryptographically random,
/// just different across processes/restarts.
fn jitter_unit_interval() -> f64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    let prev = STATE.fetch_add(seed | 1, Ordering::Relaxed);
    let mut z = prev.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

/// The coordination netmap subscription client: it connects the
/// coordination plane's `/netmap/subscribe` WebSocket route and processes
/// netmap updates. `run`'s inline backoff loop calls `run_netmap_attempt`
/// repeatedly; the downstream diff/spawn-session logic lives below this
/// module.
mod ws_netmap {
    use base64::Engine;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message;

    use super::*;

    #[derive(serde::Deserialize)]
    pub(super) struct WsNetmapMessage {
        #[serde(rename = "type")]
        #[allow(dead_code)]
        kind: String,
        #[serde(rename = "snapshotGeneration")]
        snapshot_generation: String,
        #[serde(default, rename = "serviceSigningPublicKeyBase64")]
        service_signing_public_key_base64: Option<String>,
        #[serde(default, rename = "groupPolicyLogs")]
        group_policy_logs: Vec<WsGroupPolicyLog>,
        // Groups the coordination plane isolated out of `group_policy_logs`
        // because their stored policy state (ACL and/or policy log) is
        // malformed or corrupt on its side. Without a field here serde
        // silently drops the list, and nothing ever fails these groups
        // closed; consuming it funnels each named group through the same
        // `mark_group_policy_stale` staleness gate the daemon's own
        // verification failures use.
        #[serde(default, rename = "policyInvalidGroupIds")]
        policy_invalid_group_ids: Vec<String>,
        peers: Vec<WsNetmapPeer>,
    }

    /// Type-state boundary for authoritative netmap application. Callers may
    /// not inspect or apply a snapshot until its whole peer identity set has
    /// been admitted, so a future reordering cannot accidentally mutate
    /// policy, diff, pin, or session state before duplicate IDs are rejected.
    pub(super) struct AdmittedNetmapMessage(WsNetmapMessage);

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum NetmapAdmissionError {
        DuplicateDeviceId,
        InvalidGeneration,
        StaleGeneration,
    }

    impl AdmittedNetmapMessage {
        pub(super) fn admit(
            message: WsNetmapMessage,
            last_generation: &StdMutex<Option<u64>>,
        ) -> Result<Self, NetmapAdmissionError> {
            if has_duplicate_peer_ids(message.peers.iter().map(|peer| peer.device_id.as_str())) {
                return Err(NetmapAdmissionError::DuplicateDeviceId);
            }
            let generation = message
                .snapshot_generation
                .parse::<u64>()
                .map_err(|_| NetmapAdmissionError::InvalidGeneration)?;
            let mut last = last_generation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if last.is_some_and(|last| generation <= last) {
                return Err(NetmapAdmissionError::StaleGeneration);
            }
            *last = Some(generation);
            Ok(Self(message))
        }

        fn into_inner(self) -> WsNetmapMessage {
            self.0
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsGroupPolicyLog {
        group_id: String,
        current_seq: u64,
        current_epoch: u64,
        policy_head_base64: String,
        #[serde(default)]
        records: Vec<WsPolicyRecord>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsPolicyRecord {
        group_id: String,
        seq: u64,
        prev_record_hash_base64: String,
        record_hash_base64: String,
        epoch: u64,
        action_type: u32,
        device_id: String,
        signing_key_fingerprint_base64: String,
        /// Grant only. `#[serde(default)]` so a coordination plane that has
        /// not yet been updated to emit roles (every existing deployment,
        /// today) omits the field entirely rather than failing to parse --
        /// `None` is mapped to `WriterRole::Editor` below, preserving
        /// today's actual behavior (every grant is a full writer) until the
        /// coordination plane starts minting Viewer/Owner grants for real.
        #[serde(default)]
        role: Option<u32>,
        new_authority_key_base64: String,
        signer_key_id_base64: String,
        signature_base64: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsNetmapPeer {
        device_id: String,
        /// The peer's Ed25519 device key: the one public key a device has,
        /// authenticating both its change history and its transport.
        ///
        /// Modelled as `Option` because the coordination plane's schema
        /// still permits it to be absent, not because absence is
        /// acceptable -- a peer without one can never authenticate, so the
        /// admission path rejects it and tears down anything it had. The
        /// field name is the coordination plane's; the column it comes
        /// from still carries the retired transport key's name there.
        #[serde(default)]
        signing_public_key_base64: Option<String>,
        endpoints: Vec<WsEndpoint>,
        shared_group_ids: Vec<String>,
        /// The subset of `shared_group_ids` this peer syncs as a full replica
        /// ("store everything"). Content-blind (group ids only). Absent on an
        /// older coordination plane, which reads as "no full-replica info" —
        /// the fail-safe default of not treating this peer as a durable holder.
        #[serde(default)]
        full_replica_group_ids: Vec<String>,
        /// M3 Pass 4: this peer's own declared willingness to relay opaque
        /// QUIC datagrams for other peers sharing a group with it --
        /// see `crate::route::RelayCapability`'s own doc comment. Absent on
        /// an older coordination plane, or a peer that has never opted in,
        /// reads as `false` -- the fail-safe default, matching
        /// `full_replica_group_ids`'s own "absence means not available"
        /// convention.
        #[serde(default)]
        relay_capable: bool,
    }

    #[derive(serde::Deserialize)]
    struct WsEndpoint {
        address: String,
    }

    /// A rendezvous signal delivered on the netmap subscription as a distinct
    /// message (`{ type: "rendezvous", from, candidates }`), separate from a
    /// netmap update. Carries only the originating device id and its offered
    /// candidate addresses — never file content or names.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsRendezvous {
        from: String,
        #[serde(default)]
        candidates: Vec<WsEndpoint>,
    }

    /// `config.coordination_addr` is the same http(s) base URL used for
    /// HTTP coordination service's unary routes; the netmap subscription is
    /// just a `wss://`/`ws://` upgrade of the same host at a fixed path,
    /// since the client-facing endpoint is a plain WebSocket. Uses the
    /// `url` crate to parse/rewrite the address rather than hand-rolled
    /// string splitting -- an earlier hand-rolled version
    /// of this function split on `:` to find the host, which silently
    /// mangled IPv6 literal addresses like `http://[::1]:8787` (the same
    /// bug class `yadorilink-cli`'s `http_client.rs`/`yadorilink-desktop-app`'s
    /// `google_login.rs` avoided the same way).
    pub(super) fn netmap_ws_url(
        coordination_addr: &str,
        device_id: &str,
    ) -> Result<String, DaemonError> {
        let mut url = url::Url::parse(coordination_addr)
            .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;
        let new_scheme = match url.scheme() {
            "https" => "wss",
            "http" if is_loopback_host(&url) => "ws",
            "http" => {
                return Err(DaemonError::Config(
                    "remote coordination addresses must use https://".into(),
                ))
            }
            _ => {
                return Err(DaemonError::Config(
                    "coordination address must use http:// or https://".into(),
                ))
            }
        };
        // http(s) <-> ws(s) is a "special-to-special" scheme change (per the
        // WHATWG URL spec's special-scheme list), which `url` supports.
        url.set_scheme(new_scheme)
            .map_err(|()| DaemonError::Config("failed to build the netmap websocket URL".into()))?;
        url.set_path("/netmap/subscribe");
        url.query_pairs_mut().clear().append_pair("deviceId", device_id);
        Ok(url.to_string())
    }

    /// Matches on `url`'s typed `Host` enum rather than `host_str` -- for
    /// an IPv6 literal, `host_str` returns the bracketed authority form
    /// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a
    /// first attempt at this fix used `host_str` this way and shipped
    /// with exactly that bug (caught by
    /// `ws_netmap_url_handles_an_ipv6_loopback_literal` below). `Host::Ipv6`
    /// carries an already-parsed `Ipv6Addr` directly, so there is no
    /// string/bracket handling left to get wrong.
    fn is_loopback_host(url: &url::Url) -> bool {
        match url.host() {
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        }
    }

    pub(super) async fn run_netmap_attempt(
        config: &OrchestratorConfig,
        state: &Arc<DaemonState>,
        session_index: &Arc<AtomicU32>,
        diff_state: &NetmapDiffState,
    ) -> Result<(), DaemonError> {
        let url = netmap_ws_url(&config.coordination_addr, &config.device_id)?;
        let auth_value = HeaderValue::from_str(&format!("Bearer {}", config.access_token))
            .map_err(|_| DaemonError::Config("access token is not a valid header value".into()))?;
        // Build through tungstenite so the mandatory WebSocket handshake
        // headers (`Sec-WebSocket-Key`, version, upgrade/connection) are
        // present. A bare `http::Request::builder` is accepted by
        // `connect_async` as-is; tungstenite does not retrofit those headers,
        // and every standards-compliant server rejects the handshake.
        let mut request = url
            .into_client_request()
            .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;
        request.headers_mut().insert("Authorization", auth_value);

        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
        // Record a successful coordination-plane connect so a doctor read
        // mid-outage can see the coordination plane itself is reachable,
        // separately from any peer's direct-path state.
        state.telemetry.record_connection_attempt(
            "",
            CandidateSource::CoordinationPlane,
            AddressClass::Wan,
            AttemptOutcome::Connected,
            0,
            "",
            true,
            Some(true),
        );

        let mut signing_key_pins = load_signing_key_pins()?;
        let mut service_key_pins = load_service_key_pins()?;

        fn ws_policy_log_to_record(
            log: &WsGroupPolicyLog,
        ) -> Result<crate::change_policy::GroupPolicyLog, String> {
            Ok(crate::change_policy::GroupPolicyLog {
                group_id: log.group_id.clone(),
                current_seq: log.current_seq,
                current_epoch: log.current_epoch,
                policy_head: decode_policy_b64(&log.policy_head_base64, "policyHeadBase64")?,
                records: log
                    .records
                    .iter()
                    .map(ws_policy_record_to_record)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        }

        fn ws_policy_record_to_record(
            record: &WsPolicyRecord,
        ) -> Result<crate::change_policy::PolicyRecord, String> {
            Ok(crate::change_policy::PolicyRecord {
                group_id: record.group_id.clone(),
                seq: record.seq,
                prev_record_hash: decode_policy_b64(
                    &record.prev_record_hash_base64,
                    "prevRecordHashBase64",
                )?,
                record_hash: decode_policy_b64(&record.record_hash_base64, "recordHashBase64")?,
                epoch: record.epoch,
                action_type: record.action_type,
                device_id: record.device_id.clone(),
                signing_key_fingerprint: decode_policy_b64(
                    &record.signing_key_fingerprint_base64,
                    "signingKeyFingerprintBase64",
                )?,
                // See `WsPolicyRecord::role`'s own doc comment: an absent
                // role (today, always) defaults to Editor, matching current
                // behavior exactly.
                role: record
                    .role
                    .unwrap_or_else(|| crate::change_policy::WriterRole::Editor.to_wire()),
                new_authority_key: decode_policy_b64(
                    &record.new_authority_key_base64,
                    "newAuthorityKeyBase64",
                )?,
                signer_key_id: decode_policy_b64(
                    &record.signer_key_id_base64,
                    "signerKeyIdBase64",
                )?,
                signature: decode_policy_b64(&record.signature_base64, "signatureBase64")?,
            })
        }

        fn decode_policy_b64(value: &str, field: &str) -> Result<Vec<u8>, String> {
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|e| format!("{field}: invalid base64: {e}"))
        }

        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            let text = match msg {
                Message::Text(text) => text,
                Message::Close(_) => break,
                // Ping/Pong/Binary/Frame: not a netmap update, nothing to do.
                _ => continue,
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                tracing::warn!("received malformed netmap message; ignoring");
                continue;
            };
            // A rendezvous signal arrives as a distinct message on this same
            // subscription; handle it and move on rather than parsing it as a
            // netmap update.
            if value.get("type").and_then(|t| t.as_str()) == Some("rendezvous") {
                if let Ok(rzv) = serde_json::from_value::<WsRendezvous>(value) {
                    let candidates =
                        rzv.candidates.iter().filter_map(|c| c.address.parse().ok()).collect();
                    handle_incoming_rendezvous(vec![(rzv.from, candidates)], state, diff_state);
                }
                continue;
            }
            let Ok(update) = serde_json::from_value::<WsNetmapMessage>(value) else {
                tracing::warn!("received malformed netmap message; ignoring");
                continue;
            };
            let update = match AdmittedNetmapMessage::admit(
                update,
                &diff_state.last_snapshot_generation,
            ) {
                Ok(update) => update,
                Err(NetmapAdmissionError::DuplicateDeviceId) => {
                    tracing::error!(
                        "received netmap snapshot with duplicate device ids; rejecting the entire snapshot"
                    );
                    continue;
                }
                Err(NetmapAdmissionError::InvalidGeneration) => {
                    tracing::error!(
                        "received netmap snapshot with an invalid generation; rejecting the entire snapshot"
                    );
                    continue;
                }
                Err(NetmapAdmissionError::StaleGeneration) => {
                    tracing::warn!(
                        "received stale or replayed netmap snapshot; rejecting the entire snapshot"
                    );
                    continue;
                }
            };
            let update = update.into_inner();
            if let Some(service_key_b64) = update.service_signing_public_key_base64.as_deref() {
                let policy_result = (|| -> Result<(), DaemonError> {
                    let service_key = base64::engine::general_purpose::STANDARD
                        .decode(service_key_b64)
                        .map_err(|error| {
                            DaemonError::Config(format!(
                                "received malformed policy service public key: {error}"
                            ))
                        })?;
                    let policy_logs = update
                        .group_policy_logs
                        .iter()
                        .map(ws_policy_log_to_record)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| {
                            DaemonError::Config(format!("received malformed policy log: {error}"))
                        })?;
                    record_group_policy_states(
                        state,
                        &config.coordination_addr,
                        &mut service_key_pins,
                        &service_key,
                        &policy_logs,
                    )
                })();
                if let Err(error) = policy_result {
                    tracing::warn!(
                        error = %error,
                        "policy portion of netmap snapshot is invalid; marking its groups stale while still applying peer revocations"
                    );
                    for group_id in
                        update.peers.iter().flat_map(|peer| peer.shared_group_ids.iter())
                    {
                        state.mark_group_policy_stale(group_id);
                    }
                } else {
                    // The startup scan may have advanced the index while its
                    // initial DAG import was withheld waiting for this policy.
                    // Retry immediately on the admission edge; the periodic
                    // audit remains the crash/loss backstop, not the primary
                    // path (its 90s cadence exceeds convergence timeouts).
                    for policy_log in &update.group_policy_logs {
                        let repair_state = state.clone();
                        let group_id = policy_log.group_id.clone();
                        crate::supervise::spawn_logged(
                            "policy-admission-history-backfill",
                            async move {
                                repair_state.backfill_missing_change_history(&group_id).await;
                                Ok(())
                            },
                        );
                    }
                }
            }

            // Fail closed for every group the coordination plane flagged as
            // policy-invalid. Applied AFTER the policy block above so a group
            // the plane isolated out of `group_policy_logs` (and thus never
            // cleared or re-verified) stays stale: admission, local emission,
            // and status all consult the same `mark_group_policy_stale` gate.
            // Applied regardless of whether this snapshot carried a service
            // key, since the invalid list is independent of the policy logs.
            for group_id in &update.policy_invalid_group_ids {
                state.mark_group_policy_stale(group_id);
            }

            // Diff this snapshot against the previously-held one *before*
            // acting on the new peer list below — identical to the gRPC
            // path.
            let current_netmap: NetmapSnapshot = update
                .peers
                .iter()
                .map(|peer| {
                    let groups: HashSet<String> = peer.shared_group_ids.iter().cloned().collect();
                    (peer.device_id.clone(), groups)
                })
                .collect();
            let diff = {
                let mut previous =
                    diff_state.previous.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let diff = diff_netmap(&previous, &current_netmap);
                *previous = current_netmap;
                diff
            };
            apply_netmap_diff(&diff, state, diff_state);
            prune_finished_session_tasks(diff_state);

            // Scoped to this one netmap-update pass: a group shared by many
            // peers in `update.peers` below is validated once, not once per
            // peer sharing it. See `effective_servable_groups`'s doc comment.
            let retained_group_validation_cache: std::sync::Mutex<HashMap<String, bool>> =
                std::sync::Mutex::new(HashMap::new());

            // M5-A Pass 5 (restart-convergence), round 2: peer processing is
            // genuinely two-phase now. Phase 1 (admission) below runs EVERY
            // peer's existing Ed25519 signing-key pin check --
            // exactly as before, teardown-and-skip on any failure -- but
            // does not publish anything into `peer_netmap_metadata` or run
            // any authorization validation yet. Only once every peer in
            // this pass has been fully admitted (or rejected) does Phase 2
            // seed the admitted peers' signing keys and then run
            // authorization validation / session management.
            //
            // A single combined pass (an earlier version of this fix) could
            // not do this safely: peer A's `validate_retained_group` for a
            // shared group can need peer B's signing key (a retained change
            // in that group authored by B), and that check's `true`/`false`
            // result is cached for the rest of the pass
            // (`retained_group_validation_cache`) to avoid re-walking a
            // group shared by many peers. Publishing each peer's raw,
            // not-yet-pin-checked key as soon as it was decoded (rather
            // than after admission) opened a real trust-boundary race: if
            // B's key had actually CHANGED from its pinned value (a
            // `PeerKeyDecision::Mismatch`, which is correctly rejected a
            // few lines later), an earlier single-pass version could still
            // let A's validation run against that about-to-be-rejected key
            // in the gap before B's own rejection ran, cache `true` for the
            // shared group, and publish A's authorization on that basis --
            // B's later rejection only clears B's own metadata, not the
            // already-cached group result or A's already-published
            // authorization. Doing admission for every peer FIRST, and only
            // publishing/validating with the admitted, pin-checked key
            // set, removes that window entirely.
            struct AdmittedPeer {
                device_id: String,
                signing_key: [u8; 32],
                candidate_endpoints: Vec<WsEndpoint>,
                authorized_groups: HashSet<String>,
                full_replica_groups: HashSet<String>,
                relay_capable: bool,
            }
            let mut admitted: Vec<AdmittedPeer> = Vec::new();
            for peer in update.peers {
                // The Ed25519 device key is mandatory, and its absence is
                // not a lesser form of presence. It is what authenticates
                // this device's connection to the peer in both directions,
                // so a netmap entry without one does not describe a peer
                // that can do less -- it describes a peer that can never
                // connect at all. Admitting it would mean carrying an entry
                // that every connect attempt has to reject again, and the
                // only shape of peer it could ever match is one this
                // generation of the protocol does not have.
                let Some(signing_key) =
                    decode_peer_signing_key(peer.signing_public_key_base64.as_deref())
                else {
                    tracing::warn!(
                        device_id = %peer.device_id,
                        "netmap peer has no usable Ed25519 device key; revoking any existing session"
                    );
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                };
                if pin_peer_signing_key(&mut signing_key_pins, &peer.device_id, &signing_key)? {
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                }
                let authorized_groups: HashSet<String> =
                    peer.shared_group_ids.iter().cloned().collect();
                let full_replica_groups: HashSet<String> =
                    peer.full_replica_group_ids.iter().cloned().collect();
                if !full_replica_groups.is_subset(&authorized_groups) {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer advertises full-replica groups it is not authorized for; revoking any existing session");
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                }
                admitted.push(AdmittedPeer {
                    device_id: peer.device_id,
                    signing_key,
                    candidate_endpoints: peer.endpoints,
                    authorized_groups,
                    full_replica_groups,
                    relay_capable: peer.relay_capable,
                });
            }

            // Phase 2: every peer admitted this pass has already passed its
            // Ed25519 signing-key pin check, so it is now safe to
            // settle ALL of their keys before validating ANY of their shared
            // groups -- no admitted peer's retained-history check can ever
            // race an admitted peer's own not-yet-settled key, and no
            // rejected peer's key is ever published at all.
            //
            // There is no "settle an absence" case to handle any more: a
            // peer with no usable device key never reaches this list, and a
            // peer that stops advertising one is torn down in phase 1, which
            // clears its metadata outright.
            for peer in &admitted {
                state.record_peer_signing_key(&peer.device_id, peer.signing_key);
            }

            // The set of Ed25519 keys this device will accept a QUIC
            // connection from is exactly the set of admitted peers this
            // netmap names, replaced wholesale on every push. Wholesale
            // rather than incrementally because that is the shape the
            // authority actually speaks in: a netmap is a complete statement
            // of who is authorized, and reconciling it by additions alone
            // would leave a removed device authorized until something else
            // happened to notice.
            //
            // This is the QUIC counterpart of the netmap gate the transport
            // it replaces applied at channel registration, and it is the
            // enforcement point for revocation: a key that leaves this set
            // is refused at its next handshake, with no CA, CRL or OCSP
            // involved. `apply_netmap_diff` above has already torn down the
            // live connections of devices this push removed.
            //
            // A failure to build the endpoint is not fatal to this pass: the
            // per-peer supervisors below retry it themselves, and until one
            // succeeds there is no endpoint for anyone to connect to anyway.
            match ensure_quic_endpoint(state, diff_state).await {
                Ok(endpoint) => {
                    endpoint.replace_authorized(admitted.iter().map(|peer| peer.signing_key))
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "could not apply this netmap's peer authorization to the QUIC endpoint yet"
                ),
            }

            for peer in admitted {
                let candidates: Vec<SocketAddr> = peer
                    .candidate_endpoints
                    .iter()
                    .filter_map(|e| e.address.parse().ok())
                    .collect();
                let effective_authorized_groups = apply_authoritative_peer_metadata(
                    state,
                    &peer.device_id,
                    Some(peer.signing_key),
                    &peer.authorized_groups,
                    &peer.full_replica_groups,
                    peer.relay_capable,
                    &retained_group_validation_cache,
                );
                let mut effective_group_ids: Vec<String> =
                    effective_authorized_groups.into_iter().collect();
                effective_group_ids.sort();
                // Unconditionally upserted, whether or not a session is
                // currently live for this peer -- see
                // `NetmapDiffState::desired_peers`'s own doc comment for why
                // a backoff-sleeping reconnect supervisor needs this too,
                // not just a currently-connected session.
                diff_state
                    .desired_peers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        peer.device_id.clone(),
                        PeerConnectSpec {
                            candidates: candidates.clone(),
                            effective_group_ids: effective_group_ids.clone(),
                        },
                    );
                // A live session needs nothing from this push beyond the
                // `desired_peers` upsert just above. Refreshed candidates
                // describe how to *reach* this peer, and this device is
                // already connected to it; the supervisor re-reads them at
                // the start of its next attempt if this connection ends.
                // The transport this replaces had to be told mid-session,
                // because its candidate race ran inside the live channel --
                // which is also why a single netmap push after a network
                // flap could kick every unreachable peer into a
                // simultaneous re-race. There is no such fan-out here.
                if state.peers.session(&peer.device_id).is_some() {
                    continue;
                }
                // A supervisor for this device may already be running --
                // e.g. asleep in its reconnect backoff after a prior
                // attempt ended -- even though no session is currently
                // live. Checking `state.peers.session()` alone (as above)
                // is not enough to decide whether to spawn: that map only
                // reflects a *currently connected* session, and is exactly
                // empty during a backoff sleep. Checking `session_tasks`
                // liveness instead is what actually answers "is someone
                // already responsible for reconnecting this peer" and
                // avoids spawning a second, duplicate supervisor that
                // would race the existing one.
                if peer_has_live_supervisor(diff_state, &peer.device_id) {
                    continue;
                }

                // Offer this device's server-reflexive candidates so a peer we
                // can't reach directly can still be hole-punched (rate-limited
                // per peer; a no-op when we have no reflexive candidate).
                maybe_initiate_rendezvous(&peer.device_id, config, state, diff_state);

                let device_id = peer.device_id.clone();
                let handle = spawn_peer_session(
                    state.clone(),
                    config.device_id.clone(),
                    device_id.clone(),
                    diff_state.clone(),
                    session_index.clone(),
                );
                diff_state
                    .session_tasks
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(device_id, handle);
            }

            // Every peer in this snapshot has had its connect spec upserted
            // by now, so a supervisor woken here reads the whole update
            // rather than half of it. A live session uses this to notice
            // that the address it is connected on has stopped being
            // advertised -- see `NetmapDiffState::netmap_epoch`.
            diff_state.netmap_epoch.send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        }
        // The server closed the stream without an error — still worth
        // retrying rather than treating as permanent.
        Ok(())
    }
}

use ws_netmap::run_netmap_attempt;

enum PeerKeyDecision {
    AlreadyPinned,
    NewlyPinned,
    Mismatch,
}

fn verify_or_pin_peer_key(
    pins: &mut HashMap<String, String>,
    device_id: &str,
    public_key: &[u8],
) -> PeerKeyDecision {
    let public_key_hex = hex::encode(public_key);
    match pins.get(device_id) {
        Some(pinned) if pinned == &public_key_hex => PeerKeyDecision::AlreadyPinned,
        Some(_) => PeerKeyDecision::Mismatch,
        None => {
            pins.insert(device_id.to_string(), public_key_hex);
            PeerKeyDecision::NewlyPinned
        }
    }
}

/// This device's record of every peer's Ed25519 device key, pinned on first
/// sight and refused on change.
fn load_signing_key_pins() -> Result<HashMap<String, String>, DaemonError> {
    load_key_pins(signing_key_pins_path())
}

fn load_service_key_pins() -> Result<HashMap<String, String>, DaemonError> {
    load_key_pins(service_key_pins_path())
}

fn load_key_pins(path: PathBuf) -> Result<HashMap<String, String>, DaemonError> {
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err.into()),
    }
}

/// Decodes a netmap peer's Ed25519 device key, or `None` if it carried
/// nothing usable.
///
/// Absent, empty, not base64, or not 32 bytes are one outcome, not four:
/// this key is what authenticates the peer's transport, so anything that is
/// not a key is a netmap entry describing a peer that cannot connect. The
/// caller rejects the peer and tears down anything it already had.
fn decode_peer_signing_key(encoded: Option<&str>) -> Option<[u8; 32]> {
    use base64::Engine;
    let encoded = encoded.filter(|value| !value.is_empty())?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Pins `device_id`'s Ed25519 device key via `verify_or_pin_peer_key`,
/// returning `true` when the key changed from a previously-pinned value so
/// the caller refuses the peer.
fn pin_peer_signing_key(
    pins: &mut HashMap<String, String>,
    device_id: &str,
    signing_key: &[u8; 32],
) -> Result<bool, DaemonError> {
    match verify_or_pin_peer_key(pins, device_id, signing_key) {
        PeerKeyDecision::AlreadyPinned => Ok(false),
        PeerKeyDecision::NewlyPinned => {
            save_signing_key_pins(pins)?;
            Ok(false)
        }
        PeerKeyDecision::Mismatch => {
            tracing::error!(
                device_id = %device_id,
                "netmap peer device key changed from pinned value; refusing connection"
            );
            Ok(true)
        }
    }
}

/// Writes via a temp file + atomic rename into `path` (rather than
/// truncating and writing `path` in place), so two writers racing this
/// function (multiple devices' orchestrator tasks in the same process
/// sharing one config dir, or — the scenario that actually corrupted this
/// exact file in production use — two entirely separate daemon/test
/// processes pointed at the same `YADORILINK_CONFIG_DIR`) can never
/// observe or produce a file that's half one writer's JSON and half the
/// other's. `truncate(true)` + `Write` alone gives no such guarantee:
/// each writer's own `open` independently truncates to empty, so two
/// interleaved writes can leave the file containing the tail of one
/// writer's bytes appended after the other's, valid JSON followed by
/// "trailing characters" that fails every future parse of the file for
/// every reader, permanently, until something notices and repairs it by
/// hand. `rename` on both Unix and Windows replaces `path` atomically as
/// a single filesystem operation — a concurrent reader either sees the
/// old complete file or the new complete file, never a mix of both.
fn save_signing_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    save_key_pins(signing_key_pins_path(), pins)
}

fn save_service_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    save_key_pins(service_key_pins_path(), pins)
}

fn save_key_pins(path: PathBuf, pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    let Some(parent) = path.parent() else {
        return Err(DaemonError::Config("key pins path has no parent directory".into()));
    };
    std::fs::create_dir_all(parent)?;
    // Unique even for two rapid, same-process calls (e.g. two devices in
    // one test binary saving within the same nanosecond): process id alone
    // isn't enough, so a monotonic per-process counter is folded in too.
    static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path =
        parent.join(format!("peer_keys.json.tmp.{}.{nanos}.{counter}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let mut file = options.open(&tmp_path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        serde_json::to_writer_pretty(&mut file, pins)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(&tmp_path)?;
        serde_json::to_writer_pretty(&mut file, pins)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

fn signing_key_pins_path() -> PathBuf {
    device_config::config_dir().join("signing_keys.json")
}

fn service_key_pins_path() -> PathBuf {
    device_config::config_dir().join("coordination_service_keys.json")
}

/// Whether `peer_device_id` already has a running session — the dedup
/// check `run_netmap_attempt`'s update loop uses to avoid opening a
/// second `PeerChannel`/`PeerSyncSession` for a peer that's already
/// connected (module docs on the deliberately-simple session lifecycle).
/// Its only non-test caller is `run_sim`, `#[cfg(madsim)]`-only -- gated
/// the same way here so a plain non-test, non-madsim build (which has no
/// caller at all) doesn't trip `-D dead-code`.
#[cfg(any(test, madsim))]
fn peer_already_connected(state: &DaemonState, peer_device_id: &str) -> bool {
    state.peers.has_session(peer_device_id)
}

/// Whether a reconnect supervisor is already responsible for `peer_device_id`
/// -- distinct from [`peer_already_connected`], which only reflects a
/// *currently connected* session and is exactly empty while a supervisor
/// sleeps in its reconnect backoff between attempts. The netmap-update loop
/// must check THIS before spawning a new supervisor: `state.peers.session()`
/// alone would spawn a duplicate, racing supervisor for a peer whose
/// existing one just hasn't reconnected yet.
fn peer_has_live_supervisor(diff_state: &NetmapDiffState, peer_device_id: &str) -> bool {
    diff_state
        .session_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(peer_device_id)
        .is_some_and(|handle| !handle.is_finished())
}

/// Records `peer_device_id`'s current reachability for the control socket,
/// overwriting any previous value.
fn set_reachability(state: &DaemonState, peer_device_id: &str, reachability: PeerReachability) {
    state.peers.set_reachability(peer_device_id.to_string(), reachability);
}

/// A session about to race candidates is reported `Connecting` — not yet
/// connected, but not yet given up on either.
fn mark_connecting(state: &DaemonState, peer_device_id: &str) {
    set_reachability(state, peer_device_id, PeerReachability::Connecting);
}

/// Called when a peer session ends — whether it never got past
/// connecting, or ran and later errored/returned — removing *both* the
/// `sessions` and `peer_statuses` entries, instead of the prior behavior
/// of merely re-marking the status "disconnected" forever. Removing the
/// `peer_statuses` entry is what makes `poll_reachability`'s
/// `else { break }` fire on its next tick, ending that task and dropping
/// its `Arc<PeerChannel>` clone — the other leak this closes is the
/// `sessions` entry keeping `PeerSyncSession` (and the channel `Arc` it
/// also holds) alive past the session's end.
fn end_session(state: &DaemonState, peer_device_id: &str) {
    state.peers.remove(peer_device_id);
    state.peers.clear_status(peer_device_id);
}

/// Same as [`end_session`], but only removes the session (and its status)
/// if it is still exactly `session` — so a task ending a session it once
/// owned never deletes a newer session a fresher connection has since
/// installed for the same device. Used at the natural end of a session's
/// own `run().await`, where the session's identity is already in hand.
fn end_session_if_current(
    state: &DaemonState,
    peer_device_id: &str,
    session: &Arc<PeerSyncSession>,
) {
    if state.peers.remove_if_current(peer_device_id, session) {
        state.peers.clear_status(peer_device_id);
    }
}

/// Acts on one netmap update's diff (`diff_netmap`'s output). Whole-device
/// removals get torn down entirely; group-edge removals leave the
/// transport layer alone (the tunnel stays up — that's simply the
/// *absence* of a teardown call here) but now call
/// [`PeerSyncSession::revoke_group`] on that peer's still-live session
/// (found via `state.peers.sessions`, the same map `teardown_peer` reads for
/// the whole-device case) so `yadorilink-sync-core`'s per-request
/// re-validation actually learns about the narrower revocation instead
/// of continuing to check the construction-time `shared_group_ids`
/// snapshot forever. `PeerSyncSession` has no reference to any
/// daemon-level "current netmap" of its own, and a `PeerChannel` has no
/// concept of a session or a group at all — `state.peers.sessions` is the one
/// place both a `device_id` and its live `Arc<PeerSyncSession>` are
/// available together.
fn apply_netmap_diff(diff: &NetmapDiff, state: &Arc<DaemonState>, diff_state: &NetmapDiffState) {
    for device_id in &diff.removed_devices {
        tracing::warn!(
            peer = %device_id,
            "device no longer present in netmap (device remove, or its last shared group was revoked); tearing down its peer channel and sync session"
        );
        teardown_peer(state, diff_state, device_id);
    }
    for (device_id, group_id) in &diff.removed_group_edges {
        tracing::info!(
            peer = %device_id,
            group = %group_id,
            "group-share edge revoked but another shared group remains; tunnel stays up, re-validating that group's session-level authorization"
        );
        if let Some(session) = state.peers.session(device_id) {
            // this is the actual enforcement step for the
            // group-edge case — from this call onward, `session`'s
            // `shares_group(group_id)` (consulted fresh by every
            // in-flight/queued block request and index update, per task
            // 4.1/4.2) returns `false`, so requests for this one group
            // over the still-live tunnel start being refused
            // (`not_found`) immediately, without needing to wait for the
            // tunnel itself to be touched.
            session.revoke_group(group_id);
        }
        // No live session found is not a bug: the device may not have
        // finished `PeerChannel::connect` yet (synchronous
        // `session_tasks` insert races ahead of the session existing in
        // `state.peers.sessions`), or its session may have just ended on its
        // own between this diff being computed and this loop running. In
        // either case there is nothing currently live to re-validate,
        // and any future session for this device is constructed fresh
        // from a subsequent (already-diffed-against) netmap snapshot, so
        // it will never pick group_id back up incorrectly.
    }
}

/// tears `device_id` down entirely — revokes its QUIC connection
/// (see `QuicPeerEndpoint::revoke_peer`'s doc comment: this is what
/// actually withdraws the key and refuses any further handshake attempt
/// from it), aborts its `PeerSyncSession` task (so any
/// in-flight request it's awaiting on is cancelled immediately rather
/// than left to notice its channel died), and removes it from
/// `DaemonState`.
///
/// That last step is hydration-candidate-pruning wiring:
/// `hydration::hydrate_inner` looks up authorized candidate peers live from
/// `state.peers.sessions` on every hydration attempt (not a cached/snapshotted
/// candidate list), so removing this entry here — synchronously, in the
/// same update that detected the revocation — is what makes a removed
/// device immediately stop being offered as a multi-peer hydration
/// candidate, rather than only once its session notices the torn-down
/// channel and exits on its own (`end_session` would have run anyway at
/// that point, just later).
fn teardown_peer(state: &Arc<DaemonState>, diff_state: &NetmapDiffState, device_id: &str) {
    // Revocation is administrative exclusion, and raw public keys have no
    // CA, CRL or OCSP to express it. It is therefore two distinct actions,
    // and BOTH are required: withdrawing the key stops the peer's next
    // handshake but says nothing to the connection it already has, while
    // closing that connection alone would just prompt it to reconnect.
    //
    // The order is load-bearing. Withdraw first, then close: closing first
    // would leave a window in which the peer, seeing its connection drop,
    // reconnects and is accepted -- exactly the state this is preventing.
    //
    // The key is read before `clear_peer_netmap_metadata` below, which is
    // where it is stored.
    if let Some(endpoint) = diff_state.quic_endpoint.get() {
        if let Some(peer_public_key) = state.peer_signing_key(device_id) {
            // Stage one: no future handshake from this key is accepted, and
            // any connection from it that arrived but was never claimed by a
            // session is discarded.
            endpoint.revoke_peer(&peer_public_key);
        }
    }
    // Stage two: end the connection this device is already running a session
    // on. Taken out of the route registry first so nothing else can pick it
    // up between the two, and closed explicitly rather than left to the last
    // `Arc` being dropped -- which `Arc` that is depends on task scheduling,
    // and revocation must not.
    let live_channel = state.direct_channel(device_id);
    state.remove_direct_channel(device_id);
    if let Some(channel) = live_channel {
        channel.close_revoked();
    }
    // Must happen before aborting the supervisor task below: once removed,
    // even an in-flight reconnect attempt that started just before the
    // abort lands finds no spec at its next check and stops trying, rather
    // than possibly reconnecting with stale parameters in the narrow window
    // before the abort is actually observed.
    diff_state
        .desired_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(device_id);
    // Same reasoning as `desired_peers` above: a revoked peer's LAN-learned
    // addresses must not survive to be offered as candidates on some later
    // re-admission under stale assumptions, and there is no other prune
    // point for this map otherwise.
    diff_state
        .lan_discovered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(device_id);
    if let Some(handle) = diff_state
        .session_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(device_id)
    {
        // Aborts the supervisor task itself, not a detached per-attempt
        // task -- `spawn_peer_session`'s reconnect loop runs inline in this
        // one task (deliberately not `supervise::spawn_restarting`, whose
        // own per-attempt `tokio::spawn` would leave an in-flight attempt
        // running detached past this abort; see this module's own doc
        // comment on `run`'s coordination loop for the identical reasoning).
        // This cancels whatever the supervisor is currently doing --
        // mid-connect, mid-`session.run()`, or mid-backoff-sleep -- with
        // nothing left running behind it.
        handle.abort();
    }
    end_session(state, device_id);
    state.clear_peer_netmap_metadata(device_id);
}

/// Hygiene, not correctness: a session that ends on its own (channel
/// error, peer-initiated close, etc. — not a netmap-diff-driven
/// `teardown_peer`) leaves its now-finished `JoinHandle` sitting in
/// `session_tasks` forever, since only the loop that inserted a handle
/// (this module's own update loop, not the spawned task itself) can
/// remove it. Swept once per netmap update so a long-lived daemon with
/// many peer connect/disconnect cycles doesn't accumulate finished
/// handles indefinitely; `.abort`ing an already-finished handle is a
/// harmless no-op, so leaving a stale entry here briefly is never a
/// correctness problem, only a (bounded, small) memory one.
fn prune_finished_session_tasks(diff_state: &NetmapDiffState) {
    diff_state
        .session_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|_, handle| !handle.is_finished());
}

/// Persistent per-peer supervisor: connects, runs the session to
/// completion, then reconnects with backoff -- forever, until this exact
/// task's `JoinHandle` (held in `diff_state.session_tasks`) is aborted by
/// `teardown_peer`. A `QuicPeerChannel`'s `recv` can end cleanly as part of
/// its own normal operation now (e.g. the QUIC connection idling out
/// (`yadorilink_transport::quic_peer_endpoint::PEER_IDLE_TIMEOUT`) against
/// a genuinely lost peer, rather than continuing to hold a connection
/// quinn itself has already given up on) -- before
/// this loop existed, that clean end was indistinguishable from
/// `teardown_peer`'s own bookkeeping cleanup to this function's caller, so
/// nothing ever reconnected: the peer stayed silently absent until some
/// *unrelated* netmap push happened to re-observe it (which, for an
/// unchanged authorized peer, might never happen again). The loop runs
/// inline in this one task -- deliberately NOT `supervise::spawn_restarting`,
/// whose own per-attempt `tokio::spawn` would leave an in-flight attempt
/// running detached past an abort of the *outer* handle (see this module's
/// own doc comment on `run`'s coordination loop, which hit the identical
/// footgun first).
fn spawn_peer_session(
    state: Arc<DaemonState>,
    local_device_id: String,
    peer_device_id: String,
    diff_state: NetmapDiffState,
    session_index: Arc<AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let generation_started = tokio::time::Instant::now();
            let this_generation = session_index.fetch_add(1, Ordering::Relaxed);
            run_one_peer_session_attempt(
                &state,
                &local_device_id,
                &peer_device_id,
                &diff_state,
                this_generation,
                &session_index,
            )
            .await;
            // A generation that stayed up for a while was a genuine
            // success -- reset the backoff instead of letting it ratchet
            // toward its 45s cap and stay there for the rest of this
            // device's lifetime. Without this, a peer that reconnects
            // occasionally but healthily over a long-running daemon (a
            // laptop sleeping overnight, a brief network blip) would
            // eventually always wait the full 45s after ANY disconnect,
            // indistinguishable from a peer that is genuinely struggling
            // to reconnect. Only a generation that dies almost immediately
            // (repeated handshake failures, a genuinely unreachable peer)
            // should escalate.
            if generation_started.elapsed() > Duration::from_secs(3) {
                attempt = 0;
            }
            let delay = BackoffConfig::RECONNECT.next(attempt);
            tracing::info!(
                peer = %peer_device_id,
                generation = this_generation,
                attempt,
                ?delay,
                generation_elapsed_ms = generation_started.elapsed().as_millis(),
                "peer session ended; reconnecting after backoff"
            );
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

/// This device's one QUIC endpoint, built on first use and shared by every
/// peer supervisor and by the netmap loop that authorizes peers on it.
///
/// Fallible and retried rather than fatal: it needs the shared UDP socket,
/// whose bind can fail transiently, and it needs this device's Ed25519
/// signing key, which a device that is not yet fully registered does not
/// have. Both are conditions a later attempt can find resolved.
async fn ensure_quic_endpoint(
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) -> Result<Arc<QuicPeerEndpoint>, DaemonError> {
    diff_state
        .quic_endpoint
        .get_or_try_init(|| async {
            // All peer connections share this device's one long-lived UDP
            // socket, so the NAT candidates it advertises describe the exact
            // binding data flows on.
            let hub = state.ensure_shared_socket().await?;
            let signing = state.device_signing_key().ok_or_else(|| {
                DaemonError::Config(
                    "this device has no Ed25519 signing key, so it cannot authenticate a peer \
                     connection"
                        .to_string(),
                )
            })?;
            // The same key that signs this device's change history also
            // authenticates its transport. That reuse is deliberate: it is
            // the only signature-capable key a device already holds and
            // already distributes to peers through the netmap, and TLS 1.3
            // domain-separates its own signatures by construction, so a
            // transcript signature can never be replayed as authorship.
            let device = DeviceSigningKeyPair { verifying: signing.verifying_key(), signing };
            // Starts authorizing nobody. The netmap loop opens it to exactly
            // the peers the current netmap names; until then there is no
            // device this daemon should accept a connection from.
            Ok(QuicPeerEndpoint::new(hub, device)?)
        })
        .await
        .cloned()
}

/// Opens this attempt's one connection to `peer_device_id`, or reports why
/// it could not.
///
/// Which side dials is decided by device-id ordering rather than by racing.
/// Both devices know the other's key and address, so both *could* dial, and
/// if both do the result is two connections where the protocol wants one --
/// each side's session on a different connection, neither seeing the
/// other's messages. QUIC has no simultaneous-open resolution to fall back
/// on: unlike TCP, two dials are simply two connections. Lexicographic order
/// on the device id settles it with no negotiation round trip that could
/// itself race.
///
/// The dialing side races the peer's known addresses and takes the first
/// that answers -- see [`QuicPeerEndpoint::connect_racing`] for why it must
/// race rather than walk the list, and what it costs not to.
async fn connect_to_peer(
    endpoint: &Arc<QuicPeerEndpoint>,
    role: ConnectRole,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    candidates: &[SocketAddr],
) -> Result<(Arc<QuicPeerChannel>, Option<SocketAddr>), UnreachableCategory> {
    match role {
        ConnectRole::Dial => {
            if candidates.is_empty() {
                return Err(UnreachableCategory::NoCandidates);
            }
            // The dials and this device's own inbox are watched together,
            // not one after the other.
            //
            // A peer that cannot be reached at any address it advertises
            // takes the dialling role toward its relay-capable peers (see
            // `connect_to_relay_anchor`), and the connection it makes that
            // way lands in this endpoint's inbox with nobody reading it:
            // this side is the designated dialler, so it never calls
            // `accept` in its own right. Looking only after the dials have
            // all failed makes that fallback cost a full race first -- and
            // the race's worst case is long enough that the supervisor's own
            // budget can end the attempt before the inbox is ever consulted,
            // which makes the fallback unreachable rather than slow.
            //
            // Biased toward the inbound, and that is a decision rather than
            // a default: a connection in the inbox has already been
            // *selected* by the peer, which is a commitment this device's
            // own in-flight dial has not yet made. Preferring the committed
            // one is what keeps the two ends on the same connection.
            let inbound = endpoint.accept(peer_public_key);
            tokio::pin!(inbound);
            let raced = {
                let racing = endpoint.connect_racing(candidates, peer_public_key);
                tokio::pin!(racing);
                tokio::select! {
                    biased;
                    claimed = &mut inbound => {
                        return match claimed {
                            Some(connection) => {
                                tracing::info!(
                                    peer = %peer_device_id,
                                    "the peer dialled this device while it was dialling the peer"
                                );
                                // Accepted, not dialled: which side opened
                                // the connection decides which side opens
                                // the control stream, and getting that
                                // backwards leaves both ends waiting for
                                // the other.
                                Ok((QuicPeerChannel::new(connection, ConnectRole::Accept), None))
                            }
                            None => Err(UnreachableCategory::NoResponse),
                        };
                    }
                    raced = &mut racing => raced,
                }
            };

            match raced {
                Ok((connection, candidate)) => {
                    Ok((QuicPeerChannel::new(connection, role), Some(candidate)))
                }
                // The category, never the raw error text: a
                // connection-attempt diagnostic must not carry a peer's
                // address into a log line.
                Err(error) => {
                    tracing::warn!(
                        peer = %peer_device_id,
                        candidate_count = candidates.len(),
                        failure = error.category(),
                        "no candidate accepted a QUIC connection"
                    );
                    // One last look at the inbox before giving up, for a
                    // connection that arrived while the last dial was still
                    // timing out. Short, because it is a check rather than a
                    // wait: waiting longer here would delay the relay
                    // fallback that comes after this for every genuinely
                    // unreachable peer.
                    match tokio::time::timeout(QUEUED_INBOUND_GRACE, &mut inbound).await {
                        Ok(Some(connection)) => {
                            tracing::info!(
                                peer = %peer_device_id,
                                "no advertised address answered, but the peer had dialled this \
                                 device"
                            );
                            Ok((QuicPeerChannel::new(connection, ConnectRole::Accept), None))
                        }
                        _ => Err(UnreachableCategory::NoResponse),
                    }
                }
            }
        }
        // The accepting side has nothing to retry: it waits for the dialer,
        // whose own supervisor applies the backoff. `None` means this
        // device's endpoint is gone, which only happens at shutdown.
        ConnectRole::Accept => match endpoint.accept(peer_public_key).await {
            Some(connection) => Ok((QuicPeerChannel::new(connection, role), None)),
            None => {
                tracing::debug!(
                    peer = %peer_device_id,
                    "device QUIC endpoint closed while waiting for this peer to dial"
                );
                Err(UnreachableCategory::NoResponse)
            }
        },
    }
}

/// A live connection to a peer, together with what kind of path it is on
/// and -- when that path is a relay -- the relay session carrying it.
///
/// The route is derived from the connection's own remote address rather
/// than from how the connection came to exist. That matters on the
/// accepting side, which does not open the relay session and would
/// otherwise have no way to tell a relayed peer from a direct one: below
/// the hub, quinn cannot tell the difference either, so the distinction has
/// to be drawn from the synthetic address the hub minted.
struct Established {
    channel: Arc<QuicPeerChannel>,
    route: RouteKind,
    /// `Some` only on the side that *opened* the relay session. The
    /// destination side of a relay path holds nothing: it never asked for
    /// the session and has nothing to close.
    relay: Option<crate::relay_carrier::OpenedRelayPath>,
    /// The candidate this device dialed, when it dialed one. Used only for
    /// the connection-class diagnostic; a relayed or accepted connection has
    /// no dialed candidate to report.
    dialed_candidate: Option<SocketAddr>,
}

impl Established {
    fn from_connection(
        channel: Arc<QuicPeerChannel>,
        dialed_candidate: Option<SocketAddr>,
        relay: Option<crate::relay_carrier::OpenedRelayPath>,
    ) -> Self {
        // Relay-carried traffic must never promote a peer to a confirmed
        // *direct* route: the relay layer decides whether it may forward by
        // asking exactly that question, so a relayed path answering "direct"
        // is what would let one relay chain through another.
        let route = if yadorilink_transport::is_synthetic_relay_addr(channel.remote_address()) {
            RouteKind::Relay
        } else {
            RouteKind::Direct
        };
        Self { channel, route, relay, dialed_candidate }
    }
}

/// How long a dial attempted *while an existing generation is still
/// carrying traffic* may take before it is abandoned.
///
/// Much shorter than [`CONNECT_ATTEMPT_TIMEOUT`], and deliberately so: that
/// one bounds a device with no connection at all, where waiting is the only
/// option. This one bounds a speculative probe for a better path, where the
/// current path is still working and a slow probe costs nothing but delay in
/// noticing it failed.
const PATH_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a relay-carried generation re-checks whether a direct path has
/// become available again.
///
/// A relay hop costs a peer's bandwidth and one of its bounded session
/// slots, so a device on one should not sit there once it could reach the
/// peer itself. A netmap push naming new candidates triggers this check
/// immediately; the interval is the backstop for a direct path that becomes
/// reachable again without the coordination plane saying anything -- a NAT
/// mapping reopening, a link coming back.
const RELAY_DIRECT_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// How often a relay-carried generation checks that the relay session under
/// it still exists. Short, because the whole point is to notice before the
/// QUIC idle timeout would.
const RELAY_SESSION_LIVENESS_INTERVAL: Duration = Duration::from_millis(500);

/// What ended one generation of a peer connection.
enum GenerationOutcome {
    /// The session returned on its own -- the connection closed, the peer
    /// went away, or it errored.
    Ended,
    /// A better path was established and this generation is superseded by
    /// it. The caller closes this one and continues on the replacement.
    Replaced(Established),
    /// The relay session carrying this generation is gone (its grant
    /// expired, the relay closed it, or the relay itself disconnected), so
    /// the path underneath the connection no longer exists.
    RelayLost,
}

/// One connect-then-run cycle of [`spawn_peer_session`]'s reconnect loop.
/// Reads `diff_state.desired_peers` fresh at the start -- not once at
/// `spawn_peer_session`'s own call time -- so a supervisor woken from a
/// long backoff sleep reconnects using the peer's LATEST known endpoint/
/// authorized-groups, not a stale snapshot from whenever this device's
/// session for that peer first started (see `PeerConnectSpec`'s own doc
/// comment).
///
/// One *attempt* can span several *generations*. Moving between a direct
/// path and a relayed one is not a migration -- quinn exposes no way to
/// change a peer's remote address, and reaching into its path state would be
/// the wrong lever even if it did. It is a generation replacement: a new
/// authenticated connection is established first, published as the next
/// generation, and only then is the superseded one closed. That is the same
/// machinery a reconnect already uses, so there is nothing new to invent
/// and, crucially, no window in which this device has no working path to the
/// peer at all.
async fn run_one_peer_session_attempt(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    diff_state: &NetmapDiffState,
    session_index: u32,
    generations: &Arc<AtomicU32>,
) {
    let attempt_started = tokio::time::Instant::now();
    let Some(spec) = diff_state
        .desired_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(peer_device_id)
        .cloned()
    else {
        // The peer was removed (and this supervisor's abort is presumably
        // already in flight) between this attempt starting and this check
        // -- nothing to connect to. The next loop iteration's backoff sleep
        // gives the pending abort time to land; if it hasn't landed, this
        // is a harmless no-op retry.
        tracing::debug!(
            peer = %peer_device_id,
            generation = session_index,
            "no desired connect spec for this peer; skipping this reconnect attempt"
        );
        return;
    };

    mark_connecting(state, peer_device_id);

    // Fresh-read like `desired_peers` above (see `NetmapDiffState::
    // lan_discovered`'s own doc comment) and merged into a LOCAL candidate
    // list for just this attempt -- never written back into `spec`/
    // `desired_peers` itself, so the two sources stay distinguishable for
    // the trace below rather than becoming one undifferentiated list.
    // Capped at the same total `MAX_PEER_CANDIDATES` the coordination/
    // rendezvous-sourced list already respects.
    //
    // The TTL is re-applied HERE, not just on the write path
    // (`handle_lan_announcement`'s own prune-on-insert) -- a peer that was
    // announced once and then never again (attacker gone quiet, or a real
    // peer that left the network) must not keep handing out that address
    // forever just because nothing has come along since to trigger a
    // write-side prune. Read-time filtering is what actually makes the
    // TTL bound true for every caller, not just the next writer.
    let lan_candidates: Vec<SocketAddr> = ttl_filtered_lan_candidates(
        &diff_state.lan_discovered.lock().unwrap_or_else(|p| p.into_inner()),
        peer_device_id,
        Instant::now(),
    );
    let mut attempt_candidates = spec.candidates.clone();
    for candidate in &lan_candidates {
        if attempt_candidates.len() >= MAX_PEER_CANDIDATES {
            break;
        }
        if !attempt_candidates.contains(candidate) {
            attempt_candidates.push(*candidate);
        }
    }

    // The peer's Ed25519 device key is what a QUIC handshake with it
    // authenticates against, in both directions: this device pins it as the
    // one key allowed to answer a dial, and refuses an inbound connection
    // presenting anything else. A peer the netmap carries no signing key for
    // therefore cannot be connected to at all -- there is nothing to verify
    // against, and connecting anyway would be an unauthenticated session
    // carrying plaintext file content.
    let Some(peer_public_key) = state.peer_signing_key(peer_device_id) else {
        tracing::warn!(
            peer = %peer_device_id,
            "netmap peer has no signing key to authenticate a connection against"
        );
        report_unreachable(state, peer_device_id, UnreachableCategory::HandshakeRefused);
        return;
    };

    let endpoint = match ensure_quic_endpoint(state, diff_state).await {
        Ok(endpoint) => endpoint,
        Err(e) => {
            tracing::warn!(peer = %peer_device_id, generation = session_index, error = %e, "failed to build this device's QUIC endpoint");
            report_unreachable(state, peer_device_id, UnreachableCategory::NoResponse);
            return;
        }
    };

    let role = connect_role(local_device_id, peer_device_id);
    let candidate_count = attempt_candidates.len();
    // Acquired immediately before the actual connection attempt -- this
    // supervisor's own backoff sleep already happened, entirely in
    // `spawn_peer_session`'s loop -- and released as soon as the attempt
    // resolves. It bounds how many peers this device may be mid-handshake
    // with at once, so an event that drops many sessions together (a network
    // flap, a Wi-Fi roam, this process waking from sleep) does not make every
    // affected supervisor handshake simultaneously.
    let reconnect_permit = diff_state
        .reconnect_semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("reconnect semaphore is never closed");
    let connect_started = tokio::time::Instant::now();
    let connect_result = tokio::time::timeout(
        CONNECT_ATTEMPT_TIMEOUT,
        connect_to_peer(&endpoint, role, peer_device_id, peer_public_key, &attempt_candidates),
    )
    .await;
    drop(reconnect_permit);
    // Attributable only in the success case: the winning candidate is known
    // precisely (`dialed_candidate`), so this fires exactly when a LAN-
    // discovered address is what actually got connected on -- not merely
    // "was offered this attempt". A failed attempt does not get a
    // LocalDiscovery trace entry: with several sources merged into one
    // candidate list, a failure is not attributable to any one source
    // (the same reasoning `record_reachability_transition`'s existing
    // `DirectPath` entry already follows -- it records the CONFIRMED path,
    // not every source that contributed a candidate).
    if let Ok(Ok((_, Some(dialed)))) = &connect_result {
        if lan_candidates.contains(dialed) {
            state.telemetry.record_connection_attempt(
                peer_device_id.to_string(),
                CandidateSource::LocalDiscovery,
                // Derived from the actual winning address, not hardcoded --
                // a LAN-discovered candidate is USUALLY on-LAN by
                // construction (that's what the broadcast/mDNS scope means),
                // but a spoofed or misconfigured announcement could carry an
                // off-LAN address, and hardcoding here would mis-record
                // exactly that case in telemetry.
                candidate_class_to_address(classify_endpoint(*dialed)),
                AttemptOutcome::Connected,
                connect_started.elapsed().as_millis() as u64,
                "",
                true,
                Some(true),
            );
        }
    }
    tracing::debug!(
        peer = %peer_device_id,
        generation = session_index,
        candidate_count,
        connect_ok = matches!(connect_result, Ok(Ok(_))),
        connect_elapsed_ms = connect_started.elapsed().as_millis(),
        desired_spec_wait_ms = attempt_started.elapsed().as_millis(),
        "peer connection attempt finished"
    );

    let direct = match connect_result {
        Ok(Ok((channel, dialed_candidate))) => Ok((channel, dialed_candidate)),
        Ok(Err(category)) => Err(category),
        Err(_elapsed) => {
            tracing::warn!(
                peer = %peer_device_id,
                generation = session_index,
                "peer connection attempt timed out"
            );
            Err(UnreachableCategory::NoResponse)
        }
    };

    let mut established = match direct {
        Ok((channel, dialed_candidate)) => {
            Established::from_connection(channel, dialed_candidate, None)
        }
        // No direct path. A relay is worth trying, but only on the dialing
        // side: opening one is an act of dialing, and which side dials is
        // fixed by device-id ordering precisely so a pair ends up with one
        // connection rather than two. The accepting side simply keeps
        // waiting -- if the peer needs a relay to reach this device, it is
        // the peer that opens it.
        Err(category) => {
            match connect_via_relay(state, &endpoint, peer_device_id, peer_public_key, role).await {
                Some(established) => established,
                None => {
                    match connect_to_relay_anchor(
                        state,
                        &endpoint,
                        &spec,
                        peer_device_id,
                        peer_public_key,
                        role,
                    )
                    .await
                    {
                        Some(established) => established,
                        None => {
                            report_unreachable(state, peer_device_id, category);
                            return;
                        }
                    }
                }
            }
        }
    };

    // Re-check the peer is still desired before registering anything.
    // `teardown_peer` removes `desired_peers` BEFORE calling `handle.abort()`
    // on this supervisor, specifically so an in-flight attempt can notice and
    // stop cleanly -- but `abort()` only takes effect at this task's NEXT
    // `.await` point, and there is none between here and the registration
    // below for it to land on. Without this second check a teardown that
    // raced the connection would go unnoticed: this attempt would register a
    // live channel and a session, then be aborted before reaching its own
    // cleanup, leaving a connection to a revoked device with no supervisor
    // left alive to end it.
    if !diff_state
        .desired_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(peer_device_id)
    {
        // Closed rather than dropped, and its relay session -- if it had
        // one -- torn down with it, so the peer learns immediately and the
        // relaying device gets its slot back rather than waiting out an
        // idle timeout.
        discard_generation(state, peer_device_id, established);
        return;
    }

    let mut generation = session_index;
    loop {
        let outcome = run_one_generation(
            state,
            local_device_id,
            peer_device_id,
            diff_state,
            &endpoint,
            &spec,
            peer_public_key,
            role,
            &established,
            generation,
        )
        .await;

        match outcome {
            GenerationOutcome::Replaced(replacement) => {
                tracing::info!(
                    peer = %peer_device_id,
                    generation,
                    from = established.route.as_str(),
                    to = replacement.route.as_str(),
                    "replacing a peer connection with one on a better path"
                );
                // The replacement is already authenticated and published
                // before this closes anything, so the superseded connection
                // is torn down against a working path rather than a hoped-for
                // one -- and its relay session, if it had one, stops
                // occupying a slot on the relaying device immediately rather
                // than waiting out an idle timeout there.
                discard_generation(state, peer_device_id, established);
                established = replacement;
                generation = generations.fetch_add(1, Ordering::Relaxed);
            }
            GenerationOutcome::RelayLost => {
                tracing::info!(
                    peer = %peer_device_id,
                    generation,
                    "the relay session carrying this connection is gone; reconnecting"
                );
                discard_generation(state, peer_device_id, established);
                return;
            }
            GenerationOutcome::Ended => {
                discard_generation(state, peer_device_id, established);
                return;
            }
        }
    }
}

/// Runs one generation's `PeerSyncSession` to completion, watching for a
/// better path underneath it.
#[allow(clippy::too_many_arguments)]
async fn run_one_generation(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    diff_state: &NetmapDiffState,
    endpoint: &Arc<QuicPeerEndpoint>,
    spec: &PeerConnectSpec,
    peer_public_key: [u8; 32],
    role: ConnectRole,
    established: &Established,
    generation: u32,
) -> GenerationOutcome {
    // A QUIC connection either exists or it does not, so there is no
    // candidate race left to reflect and no reachability watch to poll:
    // reaching this point IS the confirmed path, because the only way to
    // reach it is through a mutually authenticated handshake. Whether that
    // path is direct or relayed is the connection's remote address, read
    // once when the generation was established.
    let reachability = PeerReachability::Connected(established.route);
    set_reachability(state, peer_device_id, reachability);
    record_reachability_transition(
        state,
        peer_device_id,
        reachability,
        established
            .dialed_candidate
            .map(|addr| candidate_class_to_address(classify_endpoint(addr))),
    );

    // Registered so the relay layer can find this device's own direct route
    // to a peer -- both to address a forwarding socket and to refuse to
    // chain a relay through a route that is not itself direct. A relayed
    // connection is deliberately NOT registered: it is not a direct route,
    // and recording it as one is exactly how a relay would come to chain
    // through another relay.
    if established.route == RouteKind::Direct {
        state.set_direct_channel(
            peer_device_id.to_string(),
            established.channel.clone(),
            generation,
        );
    }

    let sync_roots = sync_roots_for_groups(state, &spec.effective_group_ids);
    let dependencies = peer_sync_session_deps(state);
    let session = PeerSyncSession::new_with_dependencies(
        established.channel.clone(),
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            state.block_store.clone(),
        )),
        spec.effective_group_ids.clone(),
        sync_roots,
        Some(state.forward_tx.clone()),
        dependencies,
    );
    state.peers.register_session(peer_device_id.to_string(), session.clone());

    let outcome = {
        let running = session.clone().run();
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => {
                if let Err(e) = result {
                    tracing::warn!(peer = %peer_device_id, generation, error = %e, "peer sync session ended with an error");
                }
                GenerationOutcome::Ended
            }
            replacement = await_better_path(
                state,
                endpoint,
                diff_state,
                peer_device_id,
                peer_public_key,
                role,
                established,
            ) => GenerationOutcome::Replaced(replacement),
            replacement = await_inbound_replacement(endpoint, peer_public_key, role) =>
                GenerationOutcome::Replaced(replacement),
            () = await_relay_session_loss(state, established) => GenerationOutcome::RelayLost,
        }
    };

    end_session_if_current(state, peer_device_id, &session);
    outcome
}

/// Ends one generation: closes its connection and, if it was carried by a
/// relay session this device opened, tears that session down too.
///
/// Closing is explicit rather than left to `Drop`. A superseded generation's
/// `PeerSyncSession` may still be reachable from the peer registry for a
/// moment, so dropping this scope's handle is not necessarily dropping the
/// last one, and two live connections to one peer is the state the
/// connect-role rule exists to prevent.
fn discard_generation(state: &Arc<DaemonState>, peer_device_id: &str, established: Established) {
    // Guarded by identity: a newer generation may already have registered
    // its own route under this key, and a key-only removal would delete the
    // live one -- leaving the relay layer believing this device has no
    // direct path to a peer it is actively talking to.
    state.remove_direct_channel_if_current(peer_device_id, &established.channel);
    established.channel.close_superseded();
    if let Some(relay) = &established.relay {
        crate::relay_carrier::close_relay_path(state, relay);
    }
}

/// Resolves once a strictly better path than `established` has been
/// established, and never otherwise -- so it can be raced against a running
/// session without ever being the thing that ends it.
///
/// "Better" is only ever one of two things, and both are triggered by
/// evidence rather than by a timer alone:
///
/// - a relayed generation becomes a direct one, because a direct path is
///   always preferable: it costs no other device's bandwidth and occupies
///   none of its bounded relay slots;
/// - a direct generation whose address the coordination plane has stopped
///   advertising is re-established against the addresses it now advertises,
///   falling back to a relay only if none of them answer.
///
/// A direct generation still sitting on an advertised address is left
/// completely alone. That restraint is deliberate: an address a peer is
/// demonstrably answering on is better evidence than any snapshot, and a
/// working connection is never torn down for a path that has not been
/// proven to exist. If nothing better can be established, this simply keeps
/// waiting, and the current generation goes on carrying traffic.
async fn await_better_path(
    state: &Arc<DaemonState>,
    endpoint: &Arc<QuicPeerEndpoint>,
    diff_state: &NetmapDiffState,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    role: ConnectRole,
    established: &Established,
) -> Established {
    // The accepting side has no dial to make. Which side dials is fixed by
    // device-id ordering so a pair ends up with one connection rather than
    // two, and a probe is a dial like any other -- an accepting device that
    // probed would produce connections no session ever claims.
    if role != ConnectRole::Dial {
        return std::future::pending().await;
    }

    let mut netmap_epoch = diff_state.netmap_epoch.subscribe();
    let mut probe = tokio::time::interval(RELAY_DIRECT_PROBE_INTERVAL);
    // The immediate first tick is consumed here rather than acted on: this
    // generation was established moments ago, and on a relayed one that
    // means a direct dial was *just* tried and failed.
    probe.tick().await;

    loop {
        if established.route == RouteKind::Relay {
            tokio::select! {
                _ = netmap_epoch.changed() => {}
                _ = probe.tick() => {}
            }
        } else {
            // A direct generation is only ever reconsidered when the
            // coordination plane says something new. Polling would be
            // pointless -- the answer cannot change without a netmap push.
            if netmap_epoch.changed().await.is_err() {
                return std::future::pending().await;
            }
        }

        if let Some(better) = try_better_path(
            state,
            endpoint,
            diff_state,
            peer_device_id,
            peer_public_key,
            role,
            established,
        )
        .await
        {
            return better;
        }
    }
}

/// One evaluation of whether a better path than `established` can be had
/// right now. See [`await_better_path`] for what counts as better.
async fn try_better_path(
    state: &Arc<DaemonState>,
    endpoint: &Arc<QuicPeerEndpoint>,
    diff_state: &NetmapDiffState,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    role: ConnectRole,
    established: &Established,
) -> Option<Established> {
    let candidates: Vec<SocketAddr> = diff_state
        .desired_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(peer_device_id)
        .map(|spec| spec.candidates.clone())
        .unwrap_or_default();

    if established.route == RouteKind::Direct {
        // Still connected on an address the plane advertises: there is
        // nothing here that a new connection could improve on.
        let current = established.channel.remote_address();
        if candidates.iter().any(|candidate| *candidate == current) {
            return None;
        }
    }

    if let Some((channel, dialed)) =
        probe_direct(endpoint, peer_device_id, peer_public_key, &candidates).await
    {
        return Some(Established::from_connection(channel, dialed, None));
    }

    // Already relayed and still no direct path: a second relay session would
    // be no better than the one already carrying traffic, and opening one
    // would cost the relaying device another slot for nothing.
    if established.route == RouteKind::Relay {
        return None;
    }

    connect_via_relay(state, endpoint, peer_device_id, peer_public_key, role).await
}

/// Dials `candidates` in order, bounded by [`PATH_PROBE_TIMEOUT`], and stops
/// at the first that answers with an authenticated connection.
async fn probe_direct(
    endpoint: &Arc<QuicPeerEndpoint>,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    candidates: &[SocketAddr],
) -> Option<(Arc<QuicPeerChannel>, Option<SocketAddr>)> {
    if candidates.is_empty() {
        return None;
    }
    // Raced, for exactly the reason a first connection is raced: a silent
    // address costs a full handshake timeout, which is longer than this
    // probe's whole budget, so walking the list would mean only ever trying
    // the first candidate. That is worse here than on a first connection,
    // not better -- this is the path that promotes a relayed connection back
    // to direct, so a peer whose first advertised address does not work
    // would stay on a relay for as long as it kept advertising it.
    //
    // The budget is deliberately shorter than the race's own worst case: a
    // probe runs while a working generation is still carrying traffic, so
    // giving up early costs a retry rather than a connection, and a live
    // candidate behind dead ones is found in stagger time regardless.
    match tokio::time::timeout(
        PATH_PROBE_TIMEOUT,
        endpoint.connect_racing(candidates, peer_public_key),
    )
    .await
    {
        Ok(Ok((connection, candidate))) => {
            Some((QuicPeerChannel::new(connection, ConnectRole::Dial), Some(candidate)))
        }
        Ok(Err(error)) => {
            tracing::debug!(
                peer = %peer_device_id,
                failure = error.category(),
                "no candidate answered a direct path probe"
            );
            None
        }
        Err(_elapsed) => {
            tracing::debug!(peer = %peer_device_id, "direct path probe timed out");
            None
        }
    }
}

/// Opens a relay path to `peer_device_id` and dials the peer over it.
///
/// The synthetic address the transport hands back is dialed exactly like any
/// other endpoint: the handshake, the peer-key pinning and the authorization
/// checks are the same ones a direct dial runs, because to everything above
/// the transport hub this *is* a direct dial. What differs is only where the
/// packets physically go.
///
/// `None` covers every ordinary reason a relay is unavailable -- no
/// relay-capable peer, no grant, the relay refusing admission, or the peer
/// not answering over the path once it exists. A relay session opened for a
/// dial that then fails is closed again here rather than left occupying a
/// slot on the relaying device.
async fn connect_via_relay(
    state: &Arc<DaemonState>,
    endpoint: &Arc<QuicPeerEndpoint>,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    role: ConnectRole,
) -> Option<Established> {
    if role != ConnectRole::Dial {
        return None;
    }
    let opened =
        crate::relay_carrier::open_relay_path(state, peer_device_id, &peer_public_key).await?;
    let synthetic = opened.path.synthetic_addr();
    match tokio::time::timeout(PATH_PROBE_TIMEOUT, endpoint.connect(synthetic, peer_public_key))
        .await
    {
        Ok(Ok(connection)) => Some(Established::from_connection(
            QuicPeerChannel::new(connection, ConnectRole::Dial),
            None,
            Some(opened),
        )),
        Ok(Err(error)) => {
            tracing::debug!(
                peer = %peer_device_id,
                failure = error.category(),
                "the peer did not answer a dial over a relay path"
            );
            crate::relay_carrier::close_relay_path(state, &opened);
            None
        }
        Err(_elapsed) => {
            tracing::debug!(peer = %peer_device_id, "a dial over a relay path timed out");
            crate::relay_carrier::close_relay_path(state, &opened);
            None
        }
    }
}

/// Dials a relay-capable peer that this device is supposed to be *accepting*
/// from, because nobody is managing to reach this device.
///
/// Which side dials is fixed by device-id ordering so a pair ends up with
/// one connection rather than two. That rule assumes both sides can be
/// reached, and says nothing useful when one cannot: a device whose
/// advertised address does not work -- a stale endpoint, a NAT that has
/// stopped forwarding, an address the coordination plane observed on a
/// network it is no longer on -- will never be dialled successfully by
/// anyone, and if it only ever waits, it drops out of the mesh entirely.
///
/// The way back in is a relay, and a relay can only forward to a
/// destination it has a live direct route to. So a device in that position
/// has to establish that route itself. It dials **only** its relay-capable
/// peers, and that restriction is the whole design rather than a
/// convenience:
///
/// - it is sufficient. Once a relay can reach this device, every other peer
///   can reach it through that relay, which is what relays are for.
/// - it is necessary to stop there. Dialling every peer would mean dialling
///   the very peers that are supposed to be dialling this device, which is
///   how a pair ends up with two connections and each side's session on a
///   different one.
///
/// Only reached after this device's own accept has already timed out for
/// this peer and no relay path was available, so it is a last resort rather
/// than a second opinion. The peer, for its part, claims the resulting
/// connection from its inbox once its own dial has failed -- see
/// `connect_to_peer`'s dialling arm.
async fn connect_to_relay_anchor(
    state: &Arc<DaemonState>,
    endpoint: &Arc<QuicPeerEndpoint>,
    spec: &PeerConnectSpec,
    peer_device_id: &str,
    peer_public_key: [u8; 32],
    role: ConnectRole,
) -> Option<Established> {
    if role != ConnectRole::Accept {
        return None;
    }
    if !state.peer_relay_capability(peer_device_id).is_capable() {
        return None;
    }
    if spec.candidates.is_empty() {
        return None;
    }
    let (channel, dialed) =
        probe_direct(endpoint, peer_device_id, peer_public_key, &spec.candidates).await?;
    tracing::info!(
        peer = %peer_device_id,
        "dialled a relay-capable peer because nothing is reaching this device"
    );
    Some(Established::from_connection(channel, dialed, None))
}

/// Resolves once the peer itself has established a NEW, already-selected
/// inbound connection to this device, and never at all on the dialing
/// side.
///
/// The accepting side of a generation has neither of `run_one_generation`'s
/// other two watch arms available to it: `await_better_path` returns
/// `pending` for a non-`Dial` role (probing is a dial like any other, and
/// which side dials is fixed), and `await_relay_session_loss` also returns
/// `pending` for it, because `Established::relay` is only ever `Some` on
/// the side that opened the relay session -- the destination holds
/// nothing to watch (see that field's own doc comment). Without this arm,
/// an accepting generation has nothing to select on but its own still-
/// running `PeerSyncSession`, so when the peer's OWN generation ends
/// (its relay session lost, most commonly) and it reconnects, the fresh
/// connection it dials sits claimed-but-unclaimed in `QuicPeerEndpoint`'s
/// own per-peer inbound queue (see that struct's `accept`'s own doc
/// comment) with nothing on this side ever calling `accept` again to take
/// it -- until the stale generation's QUIC connection eventually hits its
/// own idle timeout the slow way, tens of seconds later.
///
/// This is a generation *replacement*, not a *better path*: the new
/// connection is not a direct/relay upgrade this device sought out, it is
/// the peer's own selection-preface-confirmed reconnection, so it flows
/// through the same `GenerationOutcome::Replaced` machinery
/// `await_better_path` already uses rather than becoming a new outcome
/// variant. `Established::from_connection` derives `RouteKind` from the
/// connection's own remote address exactly as it does for any other
/// accepted connection, so this covers a relayed reconnect or a direct
/// one identically.
async fn await_inbound_replacement(
    endpoint: &Arc<QuicPeerEndpoint>,
    peer_public_key: [u8; 32],
    role: ConnectRole,
) -> Established {
    if role != ConnectRole::Accept {
        return std::future::pending().await;
    }
    match endpoint.accept(peer_public_key).await {
        Some(connection) => Established::from_connection(
            QuicPeerChannel::new(connection, ConnectRole::Accept),
            None,
            None,
        ),
        // `None` only means this device's own endpoint is gone (shutdown).
        // Nothing for this arm to report -- `running`'s own end (the
        // session it drives shares the same dead endpoint) is what should
        // decide the outcome, not a spurious `Replaced` racing it.
        None => std::future::pending().await,
    }
}

/// Resolves once the relay session carrying `established` has gone, and
/// never at all for a direct generation.
///
/// A relay session ends on its own schedule -- its grant expires, the relay
/// closes it, or the relay itself disconnects -- and when it does, the QUIC
/// connection riding it has no path underneath it any more. Noticing by
/// polling this device's own bookkeeping is what makes that prompt; waiting
/// for the connection's idle timeout to notice instead would leave a peer
/// looking connected for tens of seconds after it demonstrably is not.
async fn await_relay_session_loss(state: &Arc<DaemonState>, established: &Established) {
    let Some(relay) = &established.relay else {
        return std::future::pending().await;
    };
    let mut tick = tokio::time::interval(RELAY_SESSION_LIVENESS_INTERVAL);
    loop {
        tick.tick().await;
        if state.requester_relay_path(&relay.relay_device_id, relay.session_id).is_none() {
            return;
        }
    }
}

/// Reports a failed connection attempt: the status entry stays so
/// `yadorilink status` shows why, and this peer's supervisor retries after
/// its own backoff.
fn report_unreachable(
    state: &Arc<DaemonState>,
    peer_device_id: &str,
    category: UnreachableCategory,
) {
    set_reachability(state, peer_device_id, PeerReachability::Unreachable(category));
    record_reachability_transition(
        state,
        peer_device_id,
        PeerReachability::Unreachable(category),
        None,
    );
}

/// How long the dialling side looks for a connection the peer made in the
/// other direction, once none of the peer's own advertised addresses have
/// answered.
///
/// A check rather than a wait: such a connection has either already been
/// accepted and queued, in which case this returns immediately, or it has
/// not, in which case there is nothing to wait for and the next attempt will
/// find it. Waiting longer would only add latency to the ordinary case where
/// the peer is simply gone.
const QUEUED_INBOUND_GRACE: Duration = Duration::from_millis(100);

/// How long one connection attempt may take before this supervisor gives up
/// and backs off.
///
/// Derived from the transport's own worst case rather than restated as a
/// number, because the relation between the two is what matters and a
/// literal would let them drift apart -- silently, and in the direction that
/// removes behaviour. A race of candidates that all stay silent takes
/// [`RACED_DIAL_WORST_CASE`](yadorilink_transport::RACED_DIAL_WORST_CASE):
/// the last candidate starts one stagger interval per predecessor after the
/// first, and then costs a whole handshake timeout of its own. Anything
/// shorter and this supervisor's clock -- not the transport -- ends every
/// failing attempt, which does two bad things: it throws away the
/// transport's reason for the failure, and it makes everything the attempt
/// does *after* the race unreachable rather than merely late.
///
/// The accepting side needs a bound for a different reason: it is waiting on
/// a peer that may never dial, and without one it would wait forever, never
/// re-reading a netmap update that changed the peer's parameters.
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(
    yadorilink_transport::RACED_DIAL_WORST_CASE.as_millis() as u64
        + QUEUED_INBOUND_GRACE.as_millis() as u64
        + 5_000,
);

/// The relation the constant above exists to hold, checked at compile time
/// rather than left to the arithmetic staying right. The previous value was
/// a literal that happened to equal the handshake timeout, and nothing said
/// so; this fails the build instead.
const _: () = assert!(
    CONNECT_ATTEMPT_TIMEOUT.as_millis() > yadorilink_transport::RACED_DIAL_WORST_CASE.as_millis(),
    "a connection attempt must outlast the candidate race it contains, or the race's own \
     failure -- and everything the attempt does after it -- is unreachable"
);

/// Records the connection trace for a reachability transition. Only the
/// terminal states are worth a trace; `Connecting` is a transient racing
/// state with nothing to report yet. `connected_class` carries the direct
/// candidate class of a confirmed path so diagnostics can report which
/// class won.
fn record_reachability_transition(
    state: &DaemonState,
    peer_device_id: &str,
    current: PeerReachability,
    connected_class: Option<AddressClass>,
) {
    match current {
        // M3 Pass 4 (independent-review finding): explicit on `Direct`
        // rather than a `Connected(_)` wildcard -- a confirmed DIRECT path
        // means UDP got through, so a punch success and `DirectPath`
        // telemetry are warranted; neither is true of a relay-routed
        // connection (Pass 5+), which never touched this device's own NAT
        // traversal at all. Matched explicitly now so a future `Relay`
        // route doesn't silently fall into this arm and misreport a
        // successful direct punch that never happened.
        PeerReachability::Connected(crate::route::RouteKind::Direct) => {
            // A confirmed direct path means UDP got through, so record a punch
            // success — this keeps NAT classification from misjudging the
            // network as UDP-blocked once any peer connects.
            state.nat_observations.record_punch_attempt(true);
            state.telemetry.record_connection_attempt(
                peer_device_id.to_string(),
                CandidateSource::DirectPath,
                connected_class.unwrap_or(AddressClass::Unknown),
                AttemptOutcome::Connected,
                0,
                "",
                true,
                Some(true),
            );
        }
        // M3 Pass 6: reachable now (`map_transport_reachability` produces
        // it). Deliberately still a no-op -- a relay hop never touched
        // this device's own NAT traversal, so recording a direct-path
        // punch success or `DirectPath` telemetry here would misreport
        // what actually happened. No relay-specific telemetry exists yet;
        // add it here if/when it's needed, not speculatively.
        PeerReachability::Connected(crate::route::RouteKind::Relay) => {}
        PeerReachability::Unreachable(category) => state.telemetry.record_connection_attempt(
            peer_device_id.to_string(),
            CandidateSource::DirectPath,
            AddressClass::Unknown,
            AttemptOutcome::Failed,
            0,
            category.as_str(),
            false,
            None,
        ),
        PeerReachability::Connecting | PeerReachability::ProtocolIncompatible => {}
    }
}

fn candidate_class_to_address(class: yadorilink_transport::CandidateClass) -> AddressClass {
    use yadorilink_transport::CandidateClass as Transport;
    match class {
        Transport::Lan => AddressClass::Lan,
        Transport::PortMapped => AddressClass::PortMapped,
        Transport::Ipv6Host => AddressClass::Ipv6,
        Transport::ServerReflexive => AddressClass::ServerReflexive,
    }
}

/// Resolves each group to its one live sync root. A group that cannot be
/// resolved unambiguously is OMITTED from the map — the peer-apply path then
/// has no write target for it and defers, rather than writing into a folder
/// picked by chance.
///
/// This used to be a `HashMap::insert` loop over `list_links()`, which meant a
/// group with two live links resolved to the LAST row while
/// `link_gate_for_group` — consulted by the very same apply path — resolved it
/// to the FIRST. Two components in one process disagreeing about which folder
/// is "the" root for one group, at the same moment. An orphaned link's
/// coordination-side authorization is gone and must never be handed back as a
/// valid write target; the primitive filters those out.
/// Every `PeerSyncSessionDeps` field this device's own daemon state can
/// Always-deny relay handler used in place of `DaemonState`'s own
/// `RelaySessionHandler` impl under the deterministic simulator, where
/// `relay_forwarder`/`relay_session_handler` are not built at all (they bind
/// a real UDP socket, which the simulator has no model for -- see
/// `relay_forwarder`'s module-gating comment in `lib.rs`). Behaviorally
/// identical to `yadorilink_peer_session::peer_session`'s own internal
/// default relay handler: every open is refused, data/close are silent
/// no-ops -- exactly what a device with no relay support at all already
/// looks like to a peer.
#[cfg(madsim)]
struct SimNoRelaySessionHandler;

#[cfg(madsim)]
impl yadorilink_peer_session::peer_session::RelaySessionHandler for SimNoRelaySessionHandler {
    fn handle_relay_open<'a>(
        &'a self,
        open: yadorilink_sync_wire::RelayOpenFrame,
        _authenticated_peer_device_id: &'a str,
        _reply_sink: Arc<dyn yadorilink_peer_session::peer_session::RelayReplySink>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = yadorilink_sync_wire::RelayOpenedFrame> + Send + 'a>,
    > {
        Box::pin(async move {
            yadorilink_sync_wire::RelayOpenedFrame {
                grant_id: open.grant_id,
                granted: false,
                session_id: 0,
            }
        })
    }

    fn handle_relay_data<'a>(
        &'a self,
        _data: yadorilink_sync_wire::RelayDataFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn handle_relay_close<'a>(
        &'a self,
        _close: yadorilink_sync_wire::RelayCloseFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn handle_relay_opened<'a>(
        &'a self,
        _opened: yadorilink_sync_wire::RelayOpenedFrame,
        _authenticated_peer_device_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

/// supply, identical for every `PeerSyncSession` this device constructs --
/// factored out of what used to be two independently-maintained inline
/// literals (the outbound-connect and inbound-accept paths below) that had
/// already drifted (one carried every field's doc comment, the other only
/// some), and reused as-is by `DaemonState::local_retirement_session` for a
/// session bound to no live peer at all (`LoopbackPeerMessageChannel`) --
/// see that method's own doc comment for why retirement needs one.
pub(crate) fn peer_sync_session_deps(state: &Arc<DaemonState>) -> PeerSyncSessionDeps {
    PeerSyncSessionDeps {
        // Every session shares this daemon's one global upload/download
        // token-bucket pair (never an independent per-session copy).
        rate_limiters: state.rate_limiters.clone(),
        block_serve_engine: state.block_serve_engine.clone(),
        // This session's own disk-headroom preflight is turned on only
        // once `main.rs` has opted the whole daemon into enforcement
        // (see `DaemonState::disk_headroom_enforcement_enabled`'s doc
        // comment for why that's not just always-on here).
        headroom_enforced: state.disk_headroom_enforcement_enabled(),
        // Lets this session's `reconcile_one_file` force a racing local
        // change out of this device's per-link debounce accumulators
        // before comparing/applying a peer update — see
        // `PendingLocalChangeFlush for DaemonState`'s doc comment
        // (the daemon's own `LinkRuntimeController`).
        pending_local_change_flush: state.clone(),
        root_commit_authority_provider: state.clone(),
        // M3 Pass 5: `impl RelaySessionHandler for DaemonState` --
        // `relay_session_handler.rs`. Not built under the deterministic
        // simulator (see that module's own gating comment in `lib.rs`);
        // `SimNoRelaySessionHandler` above stands in for it there.
        #[cfg(not(madsim))]
        relay_session_handler: state.clone(),
        #[cfg(madsim)]
        relay_session_handler: Arc::new(SimNoRelaySessionHandler),
        // Admit incoming change-history changes only when this device
        // has pinned the author's signing key and the author is an
        // authorized writer for the change's group — both mirrored from
        // the netmap onto `DaemonState`. Without an authenticator a
        // session announces heads and serves stored changes but never
        // admits an incoming one.
        change_authenticator: crate::change_auth::NetmapChangeAuthenticator::new(state.clone()),
        // Lets this session author a captured change for content its
        // own materialize path displaces during custody transfer (see
        // `PeerSyncSession::set_change_emitter`'s doc comment). A device
        // that has not yet been provisioned a signing key is left with
        // no emitter -- the same fail-closed default the field itself
        // documents -- so a future caller must retain rather than
        // author in that case; it never falls back to an unsigned or
        // wrong-identity write.
        change_emitter: state.device_signing_key().map(|signing_key| {
            Arc::new(yadorilink_sync_sqlite::dag_store::ChangeEmitter::new(
                state.device_id.clone(),
                signing_key,
            ))
        }),
        // Lets this session answer an incoming peer `HandoffLeaseRequest`
        // by running this device's own target-side lease flow — see
        // `HandoffLeaseResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        handoff_lease_responder: state.clone(),
        block_write_activity_provider: state.clone(),
        // Lets this session answer an incoming peer `HandoffTicketRequest`
        // (from a different device removing/revoking this one) by running
        // this device's own removed-device-ticket flow — see
        // `HandoffTicketResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        handoff_ticket_responder: state.clone(),
        // Lets this session answer an incoming peer `RebootstrapSnapshotRequest`
        // and process an incoming `RebootstrapSnapshotResponse` by running this
        // device's own signing identity and pinned-key trust resolver — see
        // `DaemonRebootstrapHandler`'s doc comment (`rebootstrap_handler.rs`).
        rebootstrap_handler: crate::rebootstrap_handler::DaemonRebootstrapHandler::new(
            state.clone(),
        ),
        ..PeerSyncSessionDeps::standalone()
    }
}

pub(crate) fn sync_roots_for_groups(
    state: &DaemonState,
    group_ids: &[String],
) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    for group_id in group_ids {
        match state.replica_coordinator.link_repository().live_link_local_path_for_group(group_id) {
            Ok(Some(local_path)) => {
                roots.insert(group_id.clone(), PathBuf::from(local_path));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(
                    group_id = %group_id,
                    error = %e,
                    "cannot resolve a sync root for this group; its peer changes will not be \
                     applied until this is resolved"
                );
            }
        }
    }
    roots
}

// ---------------------------------------------------------------------------
// Deterministic-simulation discovery seam
// ---------------------------------------------------------------------------
//
// Under the deterministic simulator there is no coordination plane: the
// coordination plane is a separate service that is not compiled into the
// simulation, and the netmap WebSocket subscription above rides a live
// connection to it. So instead of discovering peers over that stream, an
// in-sim harness injects a *static* netmap
// directly (each peer's device id, keys, and pre-bound direct
// endpoint), and this seam opens a real, mutually authenticated peer
// connection and the exact same `PeerSyncSession` those discovered peers
// would have gotten -- every stage below `run_netmap_attempt` (session
// construction, forwarding, rate limiting, materialization) is the
// identical production code path.
//
// The pre-bound-socket pairing mirrors the way the sync-core two-device DST
// harness pairs devices in-sim: two UDP sockets bound on the loopback of a
// single simulation node, each device's QUIC endpoint sharing its own
// socket, and the pair's one connection opened from whichever side
// `connect_role` names. All of this is compiled only under `--cfg madsim`;
// production has no such seam and its behavior is byte-for-byte unchanged.

/// One already-authorized peer in a harness-supplied static netmap, plus
/// the pre-bound local UDP socket this device uses to reach it. Compiled
/// only under the deterministic simulator.
#[cfg(madsim)]
pub struct SimPeer {
    pub device_id: String,
    pub shared_group_ids: Vec<String>,
    /// This peer's pinned Ed25519 device key. The real netmap carries one
    /// per device: it authenticates the connection to that peer, and the
    /// change authenticator refuses to admit a `Change` it cannot verify
    /// against the claimed
    /// author's pinned key, so a harness that omits it cannot reach
    /// convergence at all. Supplied by the harness here because the
    /// simulator has no coordination plane to learn it from.
    pub signing_public_key: [u8; 32],
    /// The peer's direct endpoint address(es). The harness gives each side
    /// the other's single shared-socket address (see
    /// [`SimDiscovery::local_socket`]), so whichever side `connect_role`
    /// names as the dialer has somewhere to dial. Supplied to both sides
    /// rather than only to the dialer because which side that is depends on
    /// the device ids, which the harness does not need to reason about.
    pub peer_candidates: Vec<SocketAddr>,
}

/// The static-netmap discovery input the harness injects in place of the
/// coordination netmap stream. Passed to [`run_sim`], which is spawned as
/// the peer-orchestrator essential task under `--cfg madsim` instead of the
/// real [`run`].
#[cfg(madsim)]
pub struct SimDiscovery {
    /// This device's own Ed25519 change-history signing key. Production
    /// loads this from disk next to the transport keypair and wires it in
    /// `app::run`; the simulator's daemons have no on-disk device config, so
    /// the harness supplies it here instead. Without it a linked folder
    /// fails closed -- `ensure_initial_change_history` treats a registered
    /// device with no signing key as corrupt state rather than quietly
    /// indexing local edits that would never become `Change`s.
    pub signing_key: ed25519_dalek::SigningKey,
    pub local_device_id: String,
    pub peers: Vec<SimPeer>,
    /// The Ed25519 public key of the policy signing authority that produced
    /// [`group_policy_logs`](Self::group_policy_logs). This is the trust root
    /// `record_group_policy_states` pins and verifies every policy record
    /// against, exactly as it does with the service key a real netmap update
    /// carries. The harness holds the matching private key; the simulated
    /// daemon never sees it, just as a production daemon never sees the
    /// coordination plane's.
    pub policy_service_public_key: [u8; 32],
    /// The signed group policy logs the coordination plane would have
    /// delivered alongside the netmap: for each group this device takes part
    /// in, the hash-chained Grant/Revoke chain naming its authorized writers.
    ///
    /// Without these a simulated group is *introduced* (a peer is named as a
    /// writer for it, and it is linked locally) but has no verified
    /// `GroupPolicyState`, which is precisely the combination
    /// `DaemonState::resolve_group_policy` answers with `Withhold` -- a
    /// deliberate fail-closed state meaning "this group's real policy has not
    /// been resolved yet this run". The daemon then revokes the group from
    /// every session and drops every heads announcement for it, so nothing
    /// ever converges. Supplying the signed logs here lets the simulator reach
    /// the same `Verified` resolution a shipped daemon reaches, through the
    /// same verification and anti-rollback code.
    pub group_policy_logs: Vec<crate::change_policy::GroupPolicyLog>,
    /// This device's single pre-bound shared UDP socket (one per device, not
    /// one per peer). Every peer channel demultiplexes off it, and each peer's
    /// candidate list points at its address.
    pub local_socket: tokio::net::UdpSocket,
}

/// The coordination endpoint the simulated daemon pins its policy authority
/// key under. Production uses `DaemonConfig::coordination_addr`; the simulator
/// has no coordination plane to address, but the pinning code is keyed by
/// endpoint, so it needs a stable, non-colliding name to key by.
#[cfg(madsim)]
const SIM_COORDINATION_ENDPOINT: &str = "sim://deterministic-simulation";

/// The `--cfg madsim` counterpart to [`run`]: opens a `PeerChannel` /
/// `PeerSyncSession` for each peer in the harness-supplied static netmap,
/// then parks. Like [`run`], it must not return under normal operation --
/// the essential-task supervisor treats any return as a fatal task death --
/// so once the (static, never-changing) netmap has been acted on there is
/// nothing to re-subscribe to and it simply waits until aborted at
/// shutdown.
#[cfg(madsim)]
pub async fn run_sim(discovery: SimDiscovery, state: Arc<DaemonState>) -> Result<(), DaemonError> {
    let session_index = Arc::new(AtomicU32::new(0));
    let diff_state = NetmapDiffState::new();
    let SimDiscovery {
        signing_key,
        local_device_id,
        peers,
        policy_service_public_key,
        group_policy_logs,
        local_socket,
    } = discovery;

    // Same wiring `app::run` does for a registered production device, from
    // the harness instead of from disk -- see `SimDiscovery::signing_key`.
    // Cloned first because the same Ed25519 key does double duty: it signs
    // change history, and it is the identity that authenticates this
    // device's QUIC connections. That reuse is deliberate -- it is the only
    // signature-capable key a device already holds and already distributes
    // through the netmap, and TLS 1.3 domain-separates its own signatures by
    // construction, so a transcript signature cannot be replayed as
    // authorship.
    let quic_device_key = yadorilink_transport::DeviceSigningKeyPair {
        verifying: signing_key.verifying_key(),
        signing: signing_key.clone(),
    };
    state.set_device_signing_key(signing_key);

    // Install the harness-supplied group policy through the SAME function the
    // netmap subscription calls -- signature verification against the pinned
    // authority key, the persisted anti-rollback watermark, and the stale/
    // trusted bookkeeping all included. Nothing here reaches around those
    // checks: the harness plays the coordination plane by signing a real
    // policy log, and this daemon verifies it like any other.
    //
    // This has to happen before any peer metadata is applied below, because
    // `apply_authoritative_peer_metadata` -> `effective_servable_groups`
    // withholds any group whose policy resolves to `Withhold`, and a group
    // with no verified policy state that some peer is already a writer for
    // resolves to exactly that.
    let mut service_key_pins = load_service_key_pins()?;
    record_group_policy_states(
        &state,
        SIM_COORDINATION_ENDPOINT,
        &mut service_key_pins,
        &policy_service_public_key,
        &group_policy_logs,
    )?;

    // This device's single shared socket, installed before any connection is
    // opened so every peer rides the one binding.
    let hub = yadorilink_transport::TransportHub::from_socket(local_socket);
    state.set_shared_socket(hub.clone());

    // One QUIC endpoint for the whole device, over that same one socket --
    // not one per peer. A `quinn::Endpoint` is the demultiplexer that owns a
    // UDP binding; peers are separated inside it by QUIC connection id, so
    // there is no need for a second endpoint or a second binding, and a
    // NAT candidate is only meaningful because it names the exact socket data
    // flows on.
    let quic_endpoint = QuicPeerEndpoint::new(hub, quic_device_key)?;
    // The static sim netmap is this harness's whole coordination plane, so
    // this is its one and only netmap push: every peer it names becomes
    // authorized before any connection can arrive, and nobody else ever is.
    // The endpoint is built before this, authorizing nobody, so there is no
    // window in which it would accept an unknown device.
    quic_endpoint.replace_authorized(peers.iter().map(|peer| peer.signing_public_key));

    // Shared across peers exactly as the real netmap pass shares it, so one
    // group's retained-history validation is not repeated per peer.
    let validation_cache = std::sync::Mutex::new(HashMap::new());
    for peer in peers {
        // The static sim netmap is this harness's whole coordination plane, so
        // it has to produce what a real netmap pass produces: the peer's
        // pinned signing key, and its authorized groups run through the same
        // policy + retained-history validator. Calling the production function
        // rather than setting the fields directly is deliberate -- a harness
        // that authorized groups by a shortcut would be testing a path no
        // shipped daemon takes, and `effective_servable_groups` is exactly
        // where a group gets withheld for a reason worth catching in
        // simulation.
        let authorized_groups: HashSet<String> = peer.shared_group_ids.iter().cloned().collect();
        let effective_group_ids = apply_authoritative_peer_metadata(
            &state,
            &peer.device_id,
            Some(peer.signing_public_key),
            &authorized_groups,
            &HashSet::new(),
            false,
            &validation_cache,
        );
        diff_state.desired_peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            peer.device_id.clone(),
            PeerConnectSpec {
                candidates: peer.peer_candidates,
                effective_group_ids: effective_group_ids.into_iter().collect(),
            },
        );
        if peer_already_connected(&state, &peer.device_id)
            || peer_has_live_supervisor(&diff_state, &peer.device_id)
        {
            continue;
        }
        let handle = spawn_direct_peer_session(
            state.clone(),
            local_device_id.clone(),
            peer.device_id.clone(),
            peer.signing_public_key,
            quic_endpoint.clone(),
            diff_state.clone(),
            session_index.clone(),
        );
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer.device_id, handle);
    }

    // Static netmap: nothing to re-subscribe to. Park forever (until the
    // supervisor aborts this task at graceful shutdown), matching `run`'s
    // "never returns on its own" contract.
    std::future::pending().await
}

/// [`spawn_peer_session`]'s counterpart for the deterministic simulator:
/// connects over a pre-bound UDP socket (supplied by the harness) rather
/// than binding one, then runs the *same* `PeerSyncSession` with the same
/// forwarding/rate-limit/materialization wiring as production. Same
/// persistent-supervisor shape as `spawn_peer_session` -- see that
/// function's own doc comment for why the reconnect loop runs inline in
/// this one task rather than via `supervise::spawn_restarting`.
#[cfg(madsim)]
#[allow(clippy::too_many_arguments)]
fn spawn_direct_peer_session(
    state: Arc<DaemonState>,
    local_device_id: String,
    peer_device_id: String,
    peer_signing_public_key: [u8; 32],
    quic_endpoint: Arc<QuicPeerEndpoint>,
    diff_state: NetmapDiffState,
    session_index: Arc<AtomicU32>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let generation_started = tokio::time::Instant::now();
            let this_generation = session_index.fetch_add(1, Ordering::Relaxed);
            run_one_direct_peer_session_attempt(
                &state,
                &local_device_id,
                &peer_device_id,
                peer_signing_public_key,
                &quic_endpoint,
                &diff_state,
                this_generation,
            )
            .await;
            // See `spawn_peer_session`'s identical reset -- a generation
            // that stayed up for a while was a genuine success.
            if generation_started.elapsed() > Duration::from_secs(3) {
                attempt = 0;
            }
            let delay = BackoffConfig::RECONNECT.next(attempt);
            tracing::info!(
                peer = %peer_device_id,
                generation = this_generation,
                attempt,
                ?delay,
                "direct peer session ended; reconnecting after backoff"
            );
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

/// One connect-then-run cycle of [`spawn_direct_peer_session`]'s reconnect
/// loop -- mirrors `run_one_peer_session_attempt`'s own doc comment.
#[cfg(madsim)]
#[allow(clippy::too_many_arguments)]
async fn run_one_direct_peer_session_attempt(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    peer_signing_public_key: [u8; 32],
    quic_endpoint: &Arc<QuicPeerEndpoint>,
    diff_state: &NetmapDiffState,
    session_index: u32,
) {
    let Some(spec) = diff_state
        .desired_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(peer_device_id)
        .cloned()
    else {
        tracing::debug!(
            peer = %peer_device_id,
            "no desired connect spec for this peer; skipping this reconnect attempt"
        );
        return;
    };

    mark_connecting(state, peer_device_id);

    // The SAME connect path production takes, deliberately: the dial rule
    // and the candidate walk are one implementation, so a simulated run
    // exercises the shipped one rather than a parallel copy that could drift
    // from it.
    let role = connect_role(local_device_id, peer_device_id);
    let channel = match connect_to_peer(
        quic_endpoint,
        role,
        peer_device_id,
        peer_signing_public_key,
        &spec.candidates,
    )
    .await
    {
        Ok((channel, _dialed_candidate)) => channel,
        Err(_category) => {
            end_session(state, peer_device_id);
            return;
        }
    };

    // A QUIC connection either exists or it does not, so there is no
    // candidate race to reflect and no separate reachability watch to poll:
    // reaching this point *is* the confirmed direct path. When the
    // connection dies, the session's `recv` ends, the session returns, and
    // `end_session_if_current` below clears the status.
    set_reachability(state, peer_device_id, PeerReachability::Connected(RouteKind::Direct));

    // The static netmap can race the harness linking the shared folder
    // (in production a device knows its links before a netmap peer
    // appears; in-sim the daemon boots and this seam runs before the
    // harness has called `add_link`). Received files materialize into
    // `sync_roots`, so wait briefly for the shared group's local root
    // to appear before starting the session rather than constructing it
    // with an empty root map. The channel is already up while we wait,
    // so pairing is not delayed by this.
    let mut sync_roots = sync_roots_for_groups(state, &spec.effective_group_ids);
    for _ in 0..200 {
        if !sync_roots.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        sync_roots = sync_roots_for_groups(state, &spec.effective_group_ids);
    }

    let dependencies = peer_sync_session_deps(state);
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            state.block_store.clone(),
        )),
        spec.effective_group_ids,
        sync_roots,
        Some(state.forward_tx.clone()),
        dependencies,
    );
    state.peers.register_session(peer_device_id.to_string(), session.clone());

    if let Err(e) = session.clone().run().await {
        tracing::warn!(peer = %peer_device_id, generation = session_index, error = %e, "peer sync session ended with an error");
    }
    end_session_if_current(state, peer_device_id, &session);
    // No channel registry to clean up, and nothing to revoke: the session
    // and this scope held the only handles to the `QuicPeerChannel`, and its
    // `Drop` closes the connection and stops its stream driver. The
    // zombie-channel class that made `revoke()` mandatory for the transport
    // this replaces cannot arise -- a QUIC connection is not registered in a
    // per-key demux table that a superseded generation could go on answering
    // from.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use std::net::SocketAddr as StdSocketAddr;
    use yadorilink_local_storage::FsBlockStore;

    #[test]
    fn peer_key_pinning_detects_key_changes() {
        let mut pins = HashMap::new();

        assert!(matches!(
            verify_or_pin_peer_key(&mut pins, "device-a", &[1u8; 32]),
            PeerKeyDecision::NewlyPinned
        ));
        assert!(matches!(
            verify_or_pin_peer_key(&mut pins, "device-a", &[1u8; 32]),
            PeerKeyDecision::AlreadyPinned
        ));
        assert!(matches!(
            verify_or_pin_peer_key(&mut pins, "device-a", &[2u8; 32]),
            PeerKeyDecision::Mismatch
        ));
    }

    #[test]
    fn policy_service_key_pin_decision_requires_tofu_or_rotation() {
        let endpoint = "https://coord.example";
        let mut pins = HashMap::new();

        let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [1u8; 32]).unwrap();
        assert_eq!(key, [1u8; 32]);
        assert_eq!(decision, PolicyServiceKeyPinDecision::NewPin);

        pins.insert(endpoint.to_string(), hex::encode([1u8; 32]));
        let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [1u8; 32]).unwrap();
        assert_eq!(key, [1u8; 32]);
        assert_eq!(decision, PolicyServiceKeyPinDecision::AlreadyPinned);

        let (key, decision) = policy_service_key_pin_decision(&pins, endpoint, [2u8; 32]).unwrap();
        assert_eq!(key, [1u8; 32]);
        assert_eq!(decision, PolicyServiceKeyPinDecision::RotationRequired);
    }

    /// `pin_peer_signing_key` is a thin wrapper around `verify_or_pin_peer_key`,
    /// so its refuse-on-change behavior is the same generic pin/verify logic
    /// `peer_key_pinning_detects_key_changes` above already exercises
    /// directly; the persisting `NewlyPinned` path is covered there.
    #[test]
    fn device_key_pinning_refuses_a_changed_key() {
        let mut pins = HashMap::new();

        // Already-pinned matching key: accepted, no change.
        pins.insert("device-a".to_string(), hex::encode([7u8; 32]));
        assert!(!pin_peer_signing_key(&mut pins, "device-a", &[7u8; 32]).unwrap());

        // Changed key: refused.
        assert!(pin_peer_signing_key(&mut pins, "device-a", &[9u8; 32]).unwrap());
    }

    /// Everything that is not a 32-byte Ed25519 key is one outcome:
    /// unusable. There is no shape of netmap entry in which a peer without
    /// a device key is admissible, because that key is what authenticates
    /// its transport -- so absence is not a weaker form of presence, it is
    /// an invalid entry.
    #[test]
    fn a_peer_without_a_usable_device_key_is_not_admissible() {
        use base64::Engine;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        assert_eq!(decode_peer_signing_key(None), None, "absent");
        assert_eq!(decode_peer_signing_key(Some("")), None, "empty");
        assert_eq!(decode_peer_signing_key(Some("not base64!!")), None, "undecodable");
        assert_eq!(decode_peer_signing_key(Some(&encode(&[1u8; 31]))), None, "too short");
        assert_eq!(decode_peer_signing_key(Some(&encode(&[1u8; 33]))), None, "too long");
        assert_eq!(decode_peer_signing_key(Some(&encode(&[1u8; 32]))), Some([1u8; 32]));
    }

    /// The netmap WebSocket URL builder's loopback/scheme validation:
    /// remote `http://` is refused, loopback `http://` maps to `ws://`, and
    /// `https://` maps to `wss://`.
    #[test]
    fn ws_netmap_url_rejects_remote_http_and_accepts_loopback_and_https() {
        use super::ws_netmap::netmap_ws_url;

        assert!(netmap_ws_url("http://coordination.example", "device-1").is_err());
        assert_eq!(
            netmap_ws_url("http://127.0.0.1:8787", "device-1").unwrap(),
            "ws://127.0.0.1:8787/netmap/subscribe?deviceId=device-1"
        );
        assert_eq!(
            netmap_ws_url("https://coordination.example", "device-1").unwrap(),
            "wss://coordination.example/netmap/subscribe?deviceId=device-1"
        );
    }

    /// Regression test: an earlier version of `netmap_ws_url` hand-rolled
    /// the host extraction by splitting on `:`, which silently mangled an
    /// IPv6 loopback literal (`[::1]`) since the address itself contains
    /// colons. Parsing with the `url` crate handles this correctly.
    #[test]
    fn ws_netmap_url_handles_an_ipv6_loopback_literal() {
        use super::ws_netmap::netmap_ws_url;

        assert_eq!(
            netmap_ws_url("http://[::1]:8787", "device-1").unwrap(),
            "ws://[::1]:8787/netmap/subscribe?deviceId=device-1"
        );
    }

    // --- peer_orchestrator tests -------------------------------
    //
    // `state.peers.sessions`/`state.peers.peer_statuses` are keyed on real
    // `Arc<PeerSyncSession>`/`PeerChannel` types from other crates, so a
    // couple of these tests build one real (but peer-less) `PeerChannel`
    // against a candidate address that never answers — a lightweight "fake
    // transport": `PeerChannel::connect` registers on the shared socket and
    // spawns its actor without blocking on completing a handshake with a
    // live peer, so no second device is needed.

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        DaemonState::new("local-device".into(), sync_state, store)
    }

    /// An orphaned link is never handed back as a sync root -- an incoming
    /// peer change for its group must have nowhere local to land, the same
    /// as if this device had no link for that group at all.
    /// A group whose root cannot be named unambiguously must be OMITTED, not
    /// resolved by chance. Before this, the `HashMap::insert` loop here took the
    /// LAST matching row while `link_gate_for_group` -- consulted by the same
    /// apply path -- took the FIRST: two components in one process disagreeing
    /// about which folder is "the" root for one group, at the same moment.
    /// Omitting it leaves the peer change undelivered (recoverable) rather than
    /// applied against the wrong folder (not).
    #[tokio::test]
    async fn sync_roots_for_groups_omits_an_ambiguous_group() {
        let state = test_state();
        state
            .replica_coordinator
            .link_repository()
            .add_link("/home/alice/Photos", "group-1")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .force_second_live_link_for_test("/home/alice/PhotosCopy", "group-1")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link("/home/alice/Docs", "group-2")
            .unwrap();

        let roots = sync_roots_for_groups(&state, &["group-1".to_string(), "group-2".to_string()]);

        assert!(
            !roots.contains_key("group-1"),
            "an ambiguous group must not resolve to either of its roots, got {roots:?}"
        );
        assert_eq!(
            roots.get("group-2"),
            Some(&PathBuf::from("/home/alice/Docs")),
            "an unrelated healthy group must still resolve -- the refusal is per-group"
        );
    }

    #[tokio::test]
    async fn sync_roots_for_groups_excludes_an_orphaned_link() {
        let state = test_state();
        state
            .replica_coordinator
            .link_repository()
            .add_link("/home/alice/Photos", "group-1")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link("/home/alice/Docs", "group-2")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .mark_link_orphaned("/home/alice/Photos")
            .unwrap();

        let roots = sync_roots_for_groups(&state, &["group-1".to_string(), "group-2".to_string()]);

        assert!(!roots.contains_key("group-1"), "an orphaned link's group must not resolve");
        assert_eq!(roots.get("group-2"), Some(&PathBuf::from("/home/alice/Docs")));
    }

    /// One live QUIC channel, on a real connection between two loopback
    /// endpoints created for it.
    ///
    /// These are session-lifecycle, teardown and registry tests: what they
    /// need is a channel object with the production type and the production
    /// lifecycle, not one whose bytes go anywhere. The accepting side is
    /// deliberately dropped, so nothing is ever read off the other end.
    async fn fake_channel() -> Arc<QuicPeerChannel> {
        async fn device() -> (Arc<QuicPeerEndpoint>, [u8; 32], StdSocketAddr) {
            let hub =
                yadorilink_transport::TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
                    .await
                    .unwrap();
            let addr = hub.local_addr();
            let signing = DeviceSigningKeyPair::generate();
            let public = signing.public_bytes();
            (QuicPeerEndpoint::new(hub, signing).unwrap(), public, addr)
        }
        let (dialer, dialer_key, _) = device().await;
        let (acceptor, acceptor_key, acceptor_addr) = device().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);
        let connection = tokio::time::timeout(
            Duration::from_secs(10),
            dialer.connect(acceptor_addr, acceptor_key),
        )
        .await
        .expect("the dial must resolve")
        .expect("the dial must succeed");
        QuicPeerChannel::new(connection, ConnectRole::Dial)
    }

    /// The accept-side generation-replacement fix this test exists for:
    /// `await_inbound_replacement` must claim a peer's freshly-dialed,
    /// already-selected second connection while an earlier one to the
    /// same peer is still live -- not only after that earlier one ends.
    /// Before this fix, `run_one_generation`'s select had nothing to
    /// notice a second inbound connection with (`await_better_path`/
    /// `await_relay_session_loss` both return `pending` for a non-`Dial`
    /// role), so the fresh connection would sit unclaimed in
    /// `QuicPeerEndpoint`'s own per-peer inbound queue until the stale
    /// generation's QUIC connection hit its own idle timeout.
    ///
    /// The 10s bound is deliberately far under `PEER_IDLE_TIMEOUT`'s 30s:
    /// a test that only asserted "eventually reconnects" would still pass
    /// via that slow path, silently reintroducing the tens-of-seconds
    /// stall this fix exists to remove.
    #[tokio::test]
    async fn accept_side_claims_a_fresh_selected_connection_without_waiting_for_the_old_one_to_end()
    {
        async fn device() -> (Arc<QuicPeerEndpoint>, [u8; 32], StdSocketAddr) {
            let hub =
                yadorilink_transport::TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
                    .await
                    .unwrap();
            let addr = hub.local_addr();
            let signing = DeviceSigningKeyPair::generate();
            let public = signing.public_bytes();
            (QuicPeerEndpoint::new(hub, signing).unwrap(), public, addr)
        }
        let (dialer, dialer_key, _) = device().await;
        let (acceptor, acceptor_key, acceptor_addr) = device().await;
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);

        // Old generation: dial once, and claim it exactly the way
        // `run_one_generation`'s own initial `connect_to_peer` call does.
        let first_connection = tokio::time::timeout(
            Duration::from_secs(10),
            dialer.connect(acceptor_addr, acceptor_key),
        )
        .await
        .expect("the first dial must resolve")
        .expect("the first dial must succeed");
        let first_accepted =
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(dialer_key))
                .await
                .expect("the acceptor must claim the first connection")
                .expect("the acceptor's endpoint must still be alive");
        let old_channel = QuicPeerChannel::new(first_accepted, ConnectRole::Accept);
        // Held for the rest of this test -- nothing here ever closes it,
        // matching "an earlier connection is still live" exactly.
        let _first_connection = first_connection;

        // The peer's own reconnect: a second, independent dial to the
        // same acceptor while the first is still held above.
        let dialer_for_second = dialer.clone();
        let second_dial =
            tokio::spawn(
                async move { dialer_for_second.connect(acceptor_addr, acceptor_key).await },
            );

        let started = tokio::time::Instant::now();
        let replacement = tokio::time::timeout(
            Duration::from_secs(10),
            await_inbound_replacement(&acceptor, dialer_key, ConnectRole::Accept),
        )
        .await
        .expect(
            "accept-side replacement must resolve well within the QUIC idle timeout, not by \
             falling through to it",
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(10),
            "replacement took {elapsed:?} -- too close to (or past) the 30s idle timeout this \
             fix exists to avoid waiting for"
        );
        assert!(
            !Arc::ptr_eq(&replacement.channel, &old_channel),
            "the replacement must be a genuinely distinct connection from the original \
             generation, not the same one observed twice"
        );

        second_dial.await.unwrap().expect("the second dial must succeed");
    }

    /// This device's QUIC endpoint, installed into `diff_state` the way
    /// `ensure_quic_endpoint` would, so teardown tests can observe the
    /// authorized set revocation actually acts on.
    async fn install_test_quic_endpoint(diff_state: &NetmapDiffState) -> Arc<QuicPeerEndpoint> {
        let hub =
            yadorilink_transport::TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
                .await
                .unwrap();
        let endpoint = QuicPeerEndpoint::new(hub, DeviceSigningKeyPair::generate()).unwrap();
        diff_state
            .quic_endpoint
            .set(endpoint.clone())
            .unwrap_or_else(|_| panic!("this test installs the endpoint exactly once"));
        endpoint
    }

    fn fake_session(
        state: &Arc<DaemonState>,
        channel: Arc<QuicPeerChannel>,
    ) -> Arc<PeerSyncSession> {
        PeerSyncSession::new_with_forwarding(
            channel,
            "local-device".into(),
            "device-b".into(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            vec![],
            HashMap::new(),
            Some(state.forward_tx.clone()),
        )
    }

    /// An existing session suppresses only duplicate transport creation;
    /// authoritative metadata is applied before this check.
    #[tokio::test]
    async fn duplicate_peer_suppression_skips_already_connected_peer() {
        let state = test_state();
        let channel = fake_channel().await;
        let session = fake_session(&state, channel);

        assert!(!peer_already_connected(&state, "device-b"));

        state.peers.register_session("device-b".into(), session);
        assert!(peer_already_connected(&state, "device-b"));
        // An unrelated peer id is never suppressed by another peer's entry.
        assert!(!peer_already_connected(&state, "device-c"));
    }

    #[tokio::test]
    async fn authoritative_netmap_replaces_metadata_for_an_existing_session() {
        let state = test_state();
        let session = fake_session(&state, fake_channel().await);
        state.peers.register_session("device-b".into(), session.clone());

        let initial_groups = HashSet::from(["group-1".to_string(), "group-2".to_string()]);
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            Some([7; 32]),
            &initial_groups,
            &initial_groups,
            false,
            &std::sync::Mutex::new(HashMap::new()),
        );
        assert!(session.shares_group("group-2"));
        assert!(state.peer_is_writer("device-b", "group-2"));
        assert!(state.peer_group_is_full_replica("device-b", "group-2"));

        let generation_before = state.membership_generation();
        let demoted_groups = HashSet::from(["group-1".to_string()]);
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            None,
            &demoted_groups,
            &HashSet::new(),
            false,
            &std::sync::Mutex::new(HashMap::new()),
        );

        assert!(session.shares_group("group-1"));
        assert!(!session.shares_group("group-2"));
        assert!(state.peer_is_writer("device-b", "group-1"));
        assert!(!state.peer_is_writer("device-b", "group-2"));
        assert!(!state.peer_group_is_full_replica("device-b", "group-1"));
        assert!(!state.peer_group_is_full_replica("device-b", "group-2"));
        assert_eq!(state.peer_signing_key("device-b"), None);
        assert!(state.membership_generation() > generation_before);
    }

    /// M3 Pass 4: `RelayCapability` and full-replica status are two
    /// independent axes on the SAME device -- see `crate::route`'s own
    /// doc comment for the `Durability != Connectivity` invariant this
    /// pins. Neither combination may be inferred from the other:
    /// full-replica-but-not-relay-capable and relay-capable-but-not-
    /// full-replica must both be representable and correctly reported.
    #[tokio::test]
    async fn relay_capability_and_full_replica_status_are_independent() {
        let state = test_state();
        let groups = HashSet::from(["group-1".to_string()]);

        // device-b: full replica, NOT relay-capable.
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            None,
            &groups,
            &groups,
            false,
            &std::sync::Mutex::new(HashMap::new()),
        );
        assert!(state.peer_group_is_full_replica("device-b", "group-1"));
        assert_eq!(
            state.peer_relay_capability("device-b"),
            crate::route::RelayCapability::Disabled
        );

        // device-c: relay-capable, NOT full replica.
        apply_authoritative_peer_metadata(
            &state,
            "device-c",
            None,
            &groups,
            &HashSet::new(),
            true,
            &std::sync::Mutex::new(HashMap::new()),
        );
        assert!(!state.peer_group_is_full_replica("device-c", "group-1"));
        assert_eq!(state.peer_relay_capability("device-c"), crate::route::RelayCapability::Capable);

        // Neither device's OTHER axis moved.
        assert!(!state.peer_group_is_full_replica("device-c", "group-1"));
        assert_eq!(
            state.peer_relay_capability("device-b"),
            crate::route::RelayCapability::Disabled
        );
    }

    #[test]
    fn duplicate_device_ids_are_rejected_before_snapshot_application() {
        use super::ws_netmap::{AdmittedNetmapMessage, WsNetmapMessage};

        let generation = StdMutex::new(None);

        let duplicate: WsNetmapMessage = serde_json::from_value(serde_json::json!({
            "type": "netmap",
            "snapshotGeneration": "1",
            "peers": [
                {
                    "deviceId": "device-b",
                    "signingPublicKeyBase64": "AA==",
                    "endpoints": [],
                    "sharedGroupIds": []
                },
                {
                    "deviceId": "device-b",
                    "signingPublicKeyBase64": "AQ==",
                    "endpoints": [],
                    "sharedGroupIds": []
                }
            ]
        }))
        .unwrap();

        // This is the exact admission gate used by the receive loop. A
        // duplicate snapshot cannot reach the policy, diff, key-pin,
        // metadata, or session application phase below that gate.
        assert!(AdmittedNetmapMessage::admit(duplicate, &generation).is_err());
        assert_eq!(*generation.lock().unwrap(), None);

        let unique: WsNetmapMessage = serde_json::from_value(serde_json::json!({
            "type": "netmap",
            "snapshotGeneration": "1",
            "peers": [
                {
                    "deviceId": "device-b",
                    "signingPublicKeyBase64": "AA==",
                    "endpoints": [],
                    "sharedGroupIds": []
                },
                {
                    "deviceId": "device-c",
                    "signingPublicKeyBase64": "AQ==",
                    "endpoints": [],
                    "sharedGroupIds": []
                }
            ]
        }))
        .unwrap();
        assert!(AdmittedNetmapMessage::admit(unique, &generation).is_ok());
        assert_eq!(*generation.lock().unwrap(), Some(1));
    }

    #[test]
    fn stale_or_replayed_netmap_generation_is_rejected_across_attempts() {
        use super::ws_netmap::{AdmittedNetmapMessage, NetmapAdmissionError, WsNetmapMessage};

        fn message(generation: &str) -> WsNetmapMessage {
            serde_json::from_value(serde_json::json!({
                "type": "netmap",
                "snapshotGeneration": generation,
                "peers": []
            }))
            .unwrap()
        }

        let last_generation = StdMutex::new(None);
        assert!(AdmittedNetmapMessage::admit(message("9"), &last_generation).is_ok());
        assert!(matches!(
            AdmittedNetmapMessage::admit(message("9"), &last_generation),
            Err(NetmapAdmissionError::StaleGeneration)
        ));
        assert!(matches!(
            AdmittedNetmapMessage::admit(message("8"), &last_generation),
            Err(NetmapAdmissionError::StaleGeneration)
        ));
        assert!(AdmittedNetmapMessage::admit(message("10"), &last_generation).is_ok());
        assert_eq!(*last_generation.lock().unwrap(), Some(10));
    }

    #[test]
    fn missing_or_malformed_netmap_generation_fails_closed() {
        use super::ws_netmap::{AdmittedNetmapMessage, NetmapAdmissionError, WsNetmapMessage};

        let missing = serde_json::from_value::<WsNetmapMessage>(serde_json::json!({
            "type": "netmap",
            "peers": []
        }));
        assert!(missing.is_err());

        let malformed: WsNetmapMessage = serde_json::from_value(serde_json::json!({
            "type": "netmap",
            "snapshotGeneration": "not-a-generation",
            "peers": []
        }))
        .unwrap();
        let last_generation = StdMutex::new(None);
        assert!(matches!(
            AdmittedNetmapMessage::admit(malformed, &last_generation),
            Err(NetmapAdmissionError::InvalidGeneration)
        ));
        assert_eq!(*last_generation.lock().unwrap(), None);
    }

    /// Status transitions: a peer session starts `Connecting`, then reaches
    /// a terminal reachability. `Connected` reports as connected;
    /// `Unreachable` carries the reason and is not "connected".
    #[tokio::test]
    async fn status_transitions_start_connecting_then_reach_a_terminal_state() {
        let state = test_state();

        assert!(state.peers.reachability("device-b").is_none());

        mark_connecting(&state, "device-b");
        {
            let reachability = state.peers.reachability("device-b").unwrap();
            assert_eq!(reachability, PeerReachability::Connecting);
            assert!(!reachability.is_connected());
        }

        set_reachability(
            &state,
            "device-b",
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        {
            let reachability = state.peers.reachability("device-b").unwrap();
            assert!(reachability.is_connected());
            assert_eq!(reachability.as_str(), "connected");
        }

        set_reachability(
            &state,
            "device-b",
            PeerReachability::Unreachable(UnreachableCategory::NoResponse),
        );
        {
            let reachability = state.peers.reachability("device-b").unwrap();
            assert!(!reachability.is_connected());
            assert_eq!(reachability.as_str(), "unreachable");
            assert_eq!(reachability.unreachable_category_str(), "no_response");
        }
    }

    /// A session ending must remove BOTH the session and its status entry.
    ///
    /// The status entry is the one that used to be easy to leave behind:
    /// re-marking a peer "disconnected" forever, rather than removing it,
    /// left `yadorilink status` reporting a peer that no longer has a
    /// session at all, and kept the session's own transport channel alive
    /// through the registry entry holding it.
    #[tokio::test]
    async fn session_end_removes_both_the_session_and_its_status() {
        let state = test_state();
        let channel = fake_channel().await;
        let session = fake_session(&state, channel.clone());

        mark_connecting(&state, "device-b");
        set_reachability(
            &state,
            "device-b",
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        state.peers.register_session("device-b".into(), session.clone());

        assert!(state.peers.has_session("device-b"));
        assert!(state.peers.reachability("device-b").is_some());

        end_session(&state, "device-b");

        assert!(!state.peers.has_session("device-b"));
        assert!(state.peers.reachability("device-b").is_none());

        // Every strong reference this module held is gone; only this test's
        // own locals and the clone inside `session` remain.
        drop(session);
        assert_eq!(Arc::strong_count(&channel), 1);
    }

    // --- Netmap-diff-driven teardown integration tests -------------------

    fn fake_session_for(
        state: &Arc<DaemonState>,
        channel: Arc<QuicPeerChannel>,
        peer_device_id: &str,
        shared_group_ids: Vec<String>,
    ) -> Arc<PeerSyncSession> {
        PeerSyncSession::new_with_forwarding(
            channel,
            "local-device".into(),
            peer_device_id.into(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            shared_group_ids,
            HashMap::new(),
            Some(state.forward_tx.clone()),
        )
    }

    /// Registers a connected peer the way a successful connect attempt
    /// would: a live connection in the direct-route registry, a session and
    /// status entry, its pinned signing key recorded, and that key
    /// authorized on this device's endpoint -- everything
    /// `teardown_peer`/`apply_netmap_diff` act on. Returns both halves
    /// revocation has to reach: the key, and the live connection.
    async fn register_fake_peer(
        state: &Arc<DaemonState>,
        diff_state: &NetmapDiffState,
        endpoint: &Arc<QuicPeerEndpoint>,
        peer_device_id: &str,
        shared_group_ids: Vec<String>,
    ) -> ([u8; 32], Arc<QuicPeerChannel>) {
        let _ = diff_state;
        let channel = fake_channel().await;
        let session = fake_session_for(state, channel.clone(), peer_device_id, shared_group_ids);
        set_reachability(
            state,
            peer_device_id,
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        state.peers.register_session(peer_device_id.to_string(), session);
        let peer_public_key = DeviceSigningKeyPair::generate().public_bytes();
        state.record_peer_signing_key(peer_device_id, peer_public_key);
        endpoint.authorize(peer_public_key);
        state.set_direct_channel(peer_device_id.to_string(), channel.clone(), 1);
        (peer_public_key, channel)
    }

    /// A whole-device removal (`diff.removed_devices`) withdraws the
    /// device's key from the endpoint's authorized set -- which is what
    /// revocation *is* with raw public keys, there being no CA, CRL or OCSP
    /// to express it -- *and* immediately drops the peer from
    /// `state.peers.sessions`. The second half matters on its own:
    /// `hydration.rs`'s `candidate_sessions` reads that map live, so
    /// removing it here is what makes a revoked device stop being offered
    /// as a hydration candidate right away rather than once its session
    /// times out on its own.
    #[tokio::test]
    async fn full_device_revocation_withdraws_authorization_and_drops_hydration_candidate() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let endpoint = install_test_quic_endpoint(&diff_state).await;
        let (peer_public_key, channel) =
            register_fake_peer(&state, &diff_state, &endpoint, "device-b", vec!["group-1".into()])
                .await;
        assert!(endpoint.is_authorized(&peer_public_key));
        assert!(channel.is_open());

        let diff = NetmapDiff {
            removed_devices: vec!["device-b".to_string()],
            removed_group_edges: vec![],
        };
        apply_netmap_diff(&diff, &state, &diff_state);

        assert!(
            !endpoint.is_authorized(&peer_public_key),
            "whole-device revocation must withdraw the device's key, so a fresh handshake from \
             it is refused rather than merely its current connection ended"
        );
        assert!(
            !channel.is_open(),
            "whole-device revocation must also END the connection the device already has -- \
             withdrawing the key alone only refuses its NEXT handshake, and would leave a \
             revoked device's live session carrying traffic until it idled out"
        );
        assert!(state.direct_channel("device-b").is_none());
        assert!(
            !state.peers.has_session("device-b"),
            "revoked device must be immediately gone from the peer registry, which hydration's \
             candidate_sessions reads live"
        );
        assert!(state.peers.reachability("device-b").is_none());
    }

    /// A group-edge-only removal (the device is still present in
    /// `removed_group_edges` but *not* in `removed_devices`, because it
    /// still shares another group) must leave the connection authorized and
    /// the session up -- distinct from the whole-device case above, proving
    /// `apply_netmap_diff` really does treat the two differently rather
    /// than tearing down on any diff entry at all.
    #[tokio::test]
    async fn group_edge_revocation_leaves_the_connection_and_session_up() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let endpoint = install_test_quic_endpoint(&diff_state).await;
        let (peer_public_key, channel) = register_fake_peer(
            &state,
            &diff_state,
            &endpoint,
            "device-b",
            vec!["group-1".into(), "group-2".into()],
        )
        .await;

        let diff = NetmapDiff {
            removed_devices: vec![],
            removed_group_edges: vec![("device-b".to_string(), "group-2".to_string())],
        };
        apply_netmap_diff(&diff, &state, &diff_state);

        assert!(
            endpoint.is_authorized(&peer_public_key),
            "a device that still shares another group must stay authorized"
        );
        assert!(
            channel.is_open(),
            "a group-edge-only revocation must leave the connection itself up"
        );
        assert!(
            state.peers.has_session("device-b"),
            "a group-edge-only revocation must not remove the still-authorized session"
        );
    }

    /// the gap section 2 explicitly left open — a group-edge-only
    /// removal must call `session.revoke_group(group_id)` on the
    /// still-live session so `yadorilink-sync-core`'s per-request
    /// re-validation (section 4) actually reflects the narrower
    /// revocation, not just leave the transport layer untouched. This is
    /// the daemon-level wiring test proving the exact fix in
    /// `apply_netmap_diff`'s `removed_group_edges` loop; the full
    /// coordination-plane-to-daemon flow is exercised end-to-end in
    /// `tests/revocation_end_to_end.rs`.
    #[tokio::test]
    async fn group_edge_revocation_calls_session_revoke_group() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let endpoint = install_test_quic_endpoint(&diff_state).await;
        let (_peer_public_key, _channel) = register_fake_peer(
            &state,
            &diff_state,
            &endpoint,
            "device-b",
            vec!["group-1".into(), "group-2".into()],
        )
        .await;
        let session = state.peers.session("device-b").unwrap();
        assert!(session.shares_group("group-1"));
        assert!(session.shares_group("group-2"));

        let diff = NetmapDiff {
            removed_devices: vec![],
            removed_group_edges: vec![("device-b".to_string(), "group-2".to_string())],
        };
        apply_netmap_diff(&diff, &state, &diff_state);

        assert!(
            !session.shares_group("group-2"),
            "group-edge revocation must call session.revoke_group so live re-validation \
             reflects it, not just leave the transport layer untouched"
        );
        assert!(session.shares_group("group-1"), "the remaining shared group must stay authorized");
    }

    /// `teardown_peer` aborts the in-flight `PeerSyncSession`
    /// task, not just the transport channel — a session stuck awaiting
    /// something that isn't unblocked by the channel closing (e.g. a
    /// spawned per-message handler task, per `PeerSyncSession::run`'s doc
    /// comment on `MAX_IN_FLIGHT_MESSAGES_PER_PEER`) must not be left
    /// running past a whole-device revocation.
    #[tokio::test]
    async fn teardown_peer_aborts_the_session_task() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let still_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let still_running_clone = still_running.clone();
        let handle = tokio::spawn(async move {
            // Simulates a session task blocked on something a mere
            // channel-close doesn't unblock (e.g. a hydration timeout
            // future, or a grandchild task's own await) — only an
            // external `.abort` ends this.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            still_running_clone.store(true, Ordering::Relaxed);
        });
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".to_string(), handle);
        set_reachability(
            &state,
            "device-b",
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );

        teardown_peer(&state, &diff_state, "device-b");

        assert!(
            !diff_state
                .session_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("device-b"),
            "teardown_peer must remove the aborted task's handle"
        );
        assert!(
            !still_running.load(Ordering::Relaxed),
            "the aborted session task must never reach its post-sleep code"
        );
    }

    /// `peer_has_live_supervisor` is the netmap-update loop's dedup source
    /// of truth for whether to spawn a new supervisor -- it must say "yes,
    /// already supervised" while a supervisor is asleep in its reconnect
    /// backoff (no live session, but its task is still running), not just
    /// while a session is actually connected. `state.peers.session()` alone
    /// (the OLD dedup check) would be empty in exactly this situation and
    /// spawn a second, racing supervisor for the same peer.
    #[tokio::test]
    async fn peer_has_live_supervisor_reflects_a_backoff_sleeping_task_not_just_a_live_session() {
        let diff_state = NetmapDiffState::new();
        assert!(
            !peer_has_live_supervisor(&diff_state, "device-b"),
            "no task at all must not be reported as supervised"
        );

        // Simulates a supervisor mid-backoff-sleep between reconnect
        // attempts: no live session anywhere, but its task is still
        // running.
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".to_string(), handle);
        assert!(
            peer_has_live_supervisor(&diff_state, "device-b"),
            "a running (even backoff-sleeping) supervisor task must count as already supervised"
        );

        // A finished task must not count -- otherwise a peer whose
        // supervisor genuinely exited (e.g. a bug, or the not-actually-
        // infinite test double above) would be stuck unsupervised forever.
        let finished = tokio::spawn(async {});
        finished.await.unwrap();
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-c".to_string(), tokio::spawn(async {}));
        tokio::task::yield_now().await;
        assert!(
            !peer_has_live_supervisor(&diff_state, "device-c"),
            "a finished task must not count as an active supervisor"
        );
    }

    /// `teardown_peer` must clear `desired_peers` too, not just
    /// `channels`/`session_tasks`/the session itself -- otherwise a
    /// reconnect attempt that started just before `teardown_peer`'s abort
    /// actually lands could still read a (stale, about-to-be-revoked)
    /// connect spec and reconnect anyway, resurrecting a peer this exact
    /// call is trying to permanently remove.
    #[tokio::test]
    async fn teardown_peer_clears_the_desired_connect_spec() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        diff_state.desired_peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            "device-b".to_string(),
            PeerConnectSpec {
                candidates: vec!["127.0.0.1:9".parse().unwrap()],
                effective_group_ids: vec!["group-1".to_string()],
            },
        );

        teardown_peer(&state, &diff_state, "device-b");

        assert!(
            !diff_state
                .desired_peers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("device-b"),
            "teardown_peer must clear the desired connect spec so a reconnect attempt racing \
             the abort finds nothing to reconnect to"
        );
    }

    /// `run_one_peer_session_attempt` reads `desired_peers` fresh at the
    /// START of every call, not once at supervisor-spawn time -- this is
    /// the mechanism that lets a supervisor asleep in backoff pick up a
    /// later netmap push's updated endpoint/groups instead of retrying a
    /// stale one forever. Proven here at the boundary that actually matters
    /// for correctness: no entry at all means no session is established
    /// (rather than connecting with some leftover/default spec).
    #[tokio::test]
    async fn run_one_peer_session_attempt_is_a_no_op_with_no_desired_spec() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();

        run_one_peer_session_attempt(
            &state,
            "local-device",
            "device-b",
            &diff_state,
            0,
            &Arc::new(AtomicU32::new(1)),
        )
        .await;

        assert!(
            !state.peers.has_session("device-b"),
            "an attempt with no desired connect spec for the peer must never establish a session"
        );
        assert!(state.direct_channel("device-b").is_none());
    }

    /// LAN discovery's regression: an announced address must become a
    /// GENUINE dial candidate through the real production path -- not just
    /// sit recorded in a side map -- and a connection that actually
    /// succeeds via one must produce a real `CandidateSource::LocalDiscovery`
    /// trace entry, not merely the `#[cfg(test)]`-only fixture
    /// `connection_trace.rs`'s own enum-shape tests construct by hand.
    /// Exercises `handle_lan_announcement` and `run_one_peer_session_attempt`
    /// exactly as `run`/`spawn_peer_session` call them, not a hand-rolled
    /// substitute for either.
    #[tokio::test]
    async fn a_lan_discovered_candidate_becomes_a_genuine_dial_candidate_and_is_traced() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();

        // The acceptor: a real, independently-bound QUIC endpoint -- the
        // peer this test's dialer must actually reach.
        let acceptor_hub =
            yadorilink_transport::TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
                .await
                .unwrap();
        let acceptor_addr = acceptor_hub.local_addr();
        let acceptor_signing = DeviceSigningKeyPair::generate();
        let acceptor_key = acceptor_signing.public_bytes();
        let acceptor = QuicPeerEndpoint::new(acceptor_hub, acceptor_signing).unwrap();

        // The dialer's own endpoint, pre-installed the same way
        // `install_test_quic_endpoint` does for other tests, authorized
        // against the acceptor's key exactly as the real handshake needs.
        let dialer_hub =
            yadorilink_transport::TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
                .await
                .unwrap();
        let dialer_signing = DeviceSigningKeyPair::generate();
        let dialer_key = dialer_signing.public_bytes();
        let dialer = QuicPeerEndpoint::new(dialer_hub, dialer_signing).unwrap();
        dialer.authorize(acceptor_key);
        acceptor.authorize(dialer_key);
        diff_state
            .quic_endpoint
            .set(dialer)
            .unwrap_or_else(|_| panic!("this test installs the endpoint exactly once"));

        state.record_peer_signing_key("device-b", acceptor_key);

        // A coordination-provided candidate that goes nowhere -- a discard
        // address, the same convention
        // `spawn_peer_session_reconnects_after_the_session_ends_naturally`
        // uses -- so the ONLY way this attempt can possibly succeed is
        // through the LAN-discovered candidate below.
        let discard: StdSocketAddr = "127.0.0.1:9".parse().unwrap();
        diff_state.desired_peers.lock().unwrap_or_else(|p| p.into_inner()).insert(
            "device-b".to_string(),
            PeerConnectSpec { candidates: vec![discard], effective_group_ids: vec![] },
        );

        // Exercises the real announcement-handling path end to end, not a
        // hand-populated `lan_discovered` map.
        handle_lan_announcement(
            yadorilink_transport::PeerAnnouncement {
                public_key: acceptor_key,
                addr: acceptor_addr,
            },
            &state,
            &diff_state,
        );
        assert_eq!(
            diff_state
                .lan_discovered
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get("device-b")
                .map(|entries| entries.iter().map(|(addr, _)| *addr).collect::<Vec<_>>()),
            Some(vec![acceptor_addr]),
            "a LAN announcement from an already-pinned peer with an existing connect spec must \
             be recorded as a candidate for that peer"
        );

        let accept_handle = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), acceptor.accept(dialer_key)).await
        });

        // Spawned, not awaited directly: a successful attempt proceeds into
        // `run_one_generation`, which runs the session until it ends --
        // this test only needs the connect-and-trace side effects that
        // happen before that point, not the session's whole lifetime.
        let state_for_attempt = state.clone();
        let diff_state_for_attempt = diff_state.clone();
        let attempt_handle = tokio::spawn(async move {
            // "device-a" (not the other tests' usual "local-device") is
            // deliberate: `connect_role` picks `Dial` only for the
            // lexicographically smaller id, and this test specifically
            // needs the Dial branch -- the one that actually consults
            // `attempt_candidates` -- to be exercised, not the symmetric
            // "both sides wait to accept, so a timeout proves nothing
            // about candidates" case a same-shaped-but-role-agnostic test
            // like the reconnect test above tolerates.
            run_one_peer_session_attempt(
                &state_for_attempt,
                "device-a",
                "device-b",
                &diff_state_for_attempt,
                0,
                &Arc::new(AtomicU32::new(1)),
            )
            .await;
        });

        accept_handle
            .await
            .unwrap()
            .expect("the acceptor must observe an inbound connection within its timeout")
            .expect("the acceptor's endpoint must still be alive");

        // Poll rather than sleep a fixed guess: the trace entry is written
        // synchronously right after `connect_to_peer` resolves, well before
        // `run_one_generation` (which this test never waits on) does
        // anything session-shaped.
        let mut traces = Vec::new();
        for _ in 0..100 {
            traces = state.telemetry.recent_connection_attempts(Some("device-b"));
            if traces.iter().any(|t| t.candidate_source == "local_discovery") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            traces
                .iter()
                .any(|t| t.candidate_source == "local_discovery" && t.outcome == "connected"),
            "a successful connection over a LAN-discovered candidate must produce a real (not \
             test-fixture-only) CandidateSource::LocalDiscovery trace entry, got: {traces:?}"
        );

        attempt_handle.abort();
    }

    /// The core bug an adversarial review caught in this file's first LAN-
    /// discovery wiring attempt: `start_lan_discovery` used to snapshot the
    /// authorized-key set ONCE at call time, via a set-of-keys collected
    /// before the netmap loop -- the ONLY production writer of that set --
    /// had ever run. The snapshot was therefore always empty, and every
    /// real announcement was silently and permanently dropped, regardless
    /// of anything pinned afterward. This test goes through the REAL seam
    /// (`start_lan_discovery` itself, exactly as `run` calls it, over a
    /// real UDP socket) rather than `handle_lan_announcement` directly --
    /// deliberately reproducing the exact timing gap the bug depended on:
    /// discovery starts with ZERO peers pinned, and only afterward is a
    /// peer key pinned, to prove the authorization check is genuinely
    /// live rather than a startup-time snapshot.
    #[tokio::test]
    async fn lan_discovery_started_before_any_peer_is_pinned_still_authorizes_one_pinned_later() {
        use prost::Message as _;

        let state = test_state();
        state.set_device_signing_key(DeviceSigningKeyPair::generate().signing);
        let diff_state = NetmapDiffState::new();

        // Port 0: an OS-assigned ephemeral port, so this test cannot
        // collide with the real `LAN_DISCOVERY_BROADCAST_PORT` or with any
        // other test doing the same.
        let bound_addr = start_lan_discovery(&state, &diff_state, 0)
            .await
            .expect("discovery must start even with zero peers pinned yet");

        // Only NOW is a peer actually pinned -- the real ordering `run`'s
        // own startup produces, since the netmap loop populates
        // `peer_netmap_metadata` asynchronously, well after
        // `start_lan_discovery` has already returned and started listening.
        let peer_signing = DeviceSigningKeyPair::generate();
        let peer_key = peer_signing.public_bytes();
        state.record_peer_signing_key("device-b", peer_key);
        diff_state.desired_peers.lock().unwrap_or_else(|p| p.into_inner()).insert(
            "device-b".to_string(),
            PeerConnectSpec { candidates: vec![], effective_group_ids: vec![] },
        );

        // A real UDP announcement sent to the real bound socket -- not a
        // direct call into daemon-side handling -- so this exercises the
        // actual `DiscoveryFilters::allows` check the bug lived in.
        let announced_port = 51820u16;
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let msg = yadorilink_ipc_proto::local_discovery::LocalAnnouncement {
            public_key: peer_key.to_vec(),
            wg_port: announced_port as u32,
        };
        sender.send_to(&msg.encode_to_vec(), bound_addr).await.unwrap();

        let mut candidates = Vec::new();
        for _ in 0..100 {
            candidates = diff_state
                .lan_discovered
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get("device-b")
                .map(|entries| entries.iter().map(|(addr, _)| *addr).collect::<Vec<_>>())
                .unwrap_or_default();
            if !candidates.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert_eq!(
            candidates.len(),
            1,
            "an announcement from a peer pinned AFTER discovery started must still be accepted \
             -- if this is empty, the authorization check regressed back to a startup-time \
             snapshot"
        );
        assert_eq!(candidates[0].port(), announced_port);
    }

    /// The exact gap an adversarial review's own simulation found: the TTL
    /// used to be enforced only on the WRITE path
    /// (`handle_lan_announcement`'s prune-on-insert), so an entry that was
    /// announced once and never again -- an attacker gone quiet, or a real
    /// peer that left the network -- stayed handed out to every dialer
    /// forever, since nothing ever wrote to that peer's entry again to
    /// trigger a prune. No sleeping or paused clock needed: `Instant`
    /// arithmetic constructs a synthetic "now" on both sides of the TTL
    /// boundary directly, so this is fast and exact rather than
    /// timing-sensitive.
    #[test]
    fn ttl_filtered_lan_candidates_excludes_an_entry_past_its_ttl_even_without_a_rewrite() {
        let addr: StdSocketAddr = "203.0.113.9:51820".parse().unwrap();
        let announced_at = Instant::now();
        let mut lan_discovered = HashMap::new();
        lan_discovered.insert("device-b".to_string(), vec![(addr, announced_at)]);

        let still_within_ttl = announced_at + LAN_DISCOVERED_CANDIDATE_TTL - Duration::from_secs(1);
        assert_eq!(
            ttl_filtered_lan_candidates(&lan_discovered, "device-b", still_within_ttl),
            vec![addr],
            "an entry read just before its TTL expires must still be offered as a candidate"
        );

        let past_ttl = announced_at + LAN_DISCOVERED_CANDIDATE_TTL + Duration::from_secs(1);
        assert_eq!(
            ttl_filtered_lan_candidates(&lan_discovered, "device-b", past_ttl),
            Vec::<StdSocketAddr>::new(),
            "an entry read past its TTL must be excluded from the candidate list even though \
             nothing ever re-wrote it -- read-path enforcement, not just write-path pruning"
        );
    }

    /// The end-to-end reconnect contract `spawn_peer_session`'s doc comment
    /// promises: a session that ends NATURALLY -- here, a dial to an address
    /// that never answers -- must be followed by a second connect attempt,
    /// not silence. `session_index` incrementing past its first value is the
    /// observable proof a second attempt actually happened; a paused clock
    /// advanced in steps makes the real connect-timeout budget plus
    /// reconnect backoff resolve without the test taking anywhere near that
    /// long in wall-clock time.
    #[tokio::test(start_paused = true)]
    async fn spawn_peer_session_reconnects_after_the_session_ends_naturally() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        // Both identities the QUIC handshake needs: this device's own, and
        // the peer's pinned key to verify the answer against. Without the
        // second the attempt short-circuits before ever dialling, which
        // would make this test pass for the wrong reason.
        state.set_device_signing_key(DeviceSigningKeyPair::generate().signing);
        state.record_peer_signing_key("device-b", DeviceSigningKeyPair::generate().public_bytes());
        // Discard, TCP-style: nothing listens there, so the handshake never
        // completes and the attempt ends on its own timeout -- exactly the
        // "natural end" case this reconnect loop exists for, as opposed to a
        // teardown, which a different test covers.
        let candidate: StdSocketAddr = "127.0.0.1:9".parse().unwrap();
        diff_state.desired_peers.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            "device-b".to_string(),
            PeerConnectSpec { candidates: vec![candidate], effective_group_ids: vec![] },
        );
        let session_index = Arc::new(AtomicU32::new(0));
        let _handle = spawn_peer_session(
            state.clone(),
            "local-device".to_string(),
            "device-b".to_string(),
            diff_state.clone(),
            session_index.clone(),
        );

        // Advance in bounded steps (not one giant jump) so every timer this
        // loop sets along the way -- the connect attempt's own timeout, then
        // the reconnect backoff sleep -- actually gets to fire and let the
        // supervisor task re-poll and set its next timer, rather than the
        // paused clock racing past several of them before the task has had a
        // chance to observe any of them elapsing.
        let mut observed_second_attempt = false;
        for _ in 0..120 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            if session_index.load(Ordering::Relaxed) >= 2 {
                observed_second_attempt = true;
                break;
            }
        }

        assert!(
            observed_second_attempt,
            "the supervisor must start a second connect attempt after the first one ends on its \
             own -- got session_index={}",
            session_index.load(Ordering::Relaxed)
        );
    }

    /// The direct-route registry's two ordering rules, together, because
    /// they close the same race from opposite ends: a stale supervisor
    /// generation must neither replace a newer generation's route nor evict
    /// it on the way out.
    ///
    /// The race is real rather than theoretical: `teardown_peer`'s
    /// `handle.abort()` only cancels the old supervisor at its next
    /// `.await`, so a new supervisor can connect and register while the old
    /// one is still running its own cleanup. Since the relay layer consults
    /// this registry to decide whether an unchained direct path exists, an
    /// entry lost or replaced by a stale generation is a correctness
    /// problem, not untidiness.
    #[tokio::test]
    async fn a_stale_generation_can_neither_replace_nor_evict_a_newer_route() {
        let state = test_state();
        let old_channel = fake_channel().await;
        let new_channel = fake_channel().await;

        state.set_direct_channel("device-b".to_string(), old_channel.clone(), 1);
        state.set_direct_channel("device-b".to_string(), new_channel.clone(), 2);
        assert!(
            state.direct_channel("device-b").is_some_and(|c| Arc::ptr_eq(&c, &new_channel)),
            "the newer generation's publish must win"
        );
        assert!(
            !old_channel.is_open(),
            "the superseded generation's connection must be CLOSED, not merely unregistered -- \
             the old session still holds a reference to it, so dropping the map entry would \
             leave two live connections to one peer"
        );
        assert!(new_channel.is_open(), "the winning generation's connection must stay up");

        // The stale generation publishing SECOND in real time, which is what
        // an aborted-but-not-yet-cancelled supervisor produces.
        state.set_direct_channel("device-b".to_string(), old_channel.clone(), 1);
        assert!(
            state.direct_channel("device-b").is_some_and(|c| Arc::ptr_eq(&c, &new_channel)),
            "a stale generation's publish must be rejected outright, not overwrite the live route"
        );

        // The stale generation's own natural-end cleanup must be a no-op
        // against the newer entry rather than removing it by key.
        state.remove_direct_channel_if_current("device-b", &old_channel);
        assert!(
            state.direct_channel("device-b").is_some_and(|c| Arc::ptr_eq(&c, &new_channel)),
            "cleanup keyed to the OLD generation's channel must not evict the newer one"
        );

        state.remove_direct_channel_if_current("device-b", &new_channel);
        assert!(
            state.direct_channel("device-b").is_none(),
            "the entry must actually go once the current generation's own cleanup runs"
        );
    }

    #[tokio::test]
    async fn pinned_peer_key_mismatch_tears_down_session_and_authorization() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let endpoint = install_test_quic_endpoint(&diff_state).await;
        let (peer_public_key, _channel) =
            register_fake_peer(&state, &diff_state, &endpoint, "device-b", vec!["group-1".into()])
                .await;
        // The peer's own key, not an arbitrary one: `teardown_peer` revokes
        // whatever key the netmap currently records for the device, so a
        // fixture whose metadata disagreed with its registration would be
        // asserting against a key nothing ever authorized.
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            Some(peer_public_key),
            &HashSet::from(["group-1".to_string()]),
            &HashSet::from(["group-1".to_string()]),
            false,
            &std::sync::Mutex::new(HashMap::new()),
        );
        let handle = tokio::spawn(std::future::pending::<()>());
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".to_string(), handle);

        let mut pins = HashMap::new();
        assert!(matches!(
            verify_or_pin_peer_key(&mut pins, "device-b", &[1; 32]),
            PeerKeyDecision::NewlyPinned
        ));
        let decision = verify_or_pin_peer_key(&mut pins, "device-b", &[2; 32]);
        match decision {
            PeerKeyDecision::Mismatch => teardown_peer(&state, &diff_state, "device-b"),
            _ => panic!("changed pinned key must be rejected as a mismatch"),
        }

        assert!(!endpoint.is_authorized(&peer_public_key));
        assert!(!state.peers.has_session("device-b"));
        assert!(!diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
        assert_eq!(state.peer_signing_key("device-b"), None);
        assert!(!state.peer_is_writer("device-b", "group-1"));
        assert!(!state.peer_group_is_full_replica("device-b", "group-1"));
    }

    /// `run_netmap_attempt`'s dedup check (`peer_already_connected`,
    /// unchanged by this task) only ever suppresses opening a *second*
    /// session for an already-connected peer; it never re-adds one that
    /// `apply_netmap_diff` just tore down within the same update, since
    /// `teardown_peer` removes the `state.peers.sessions` entry that check
    /// reads before the subsequent `for peer in update.peers` loop runs.
    #[test]
    fn diff_netmap_reused_from_transport_classifies_a_realistic_mixed_update() {
        // Exercises the exact type (`yadorilink_transport::NetmapSnapshot`)
        // and function `run_netmap_attempt` calls, from this crate's side
        // of the boundary — a lightweight regression guard against the
        // two crates' notion of a netmap snapshot drifting apart.
        let mut previous: NetmapSnapshot = HashMap::new();
        previous.insert("device-a".into(), HashSet::from(["group-1".to_string()]));
        previous.insert(
            "device-b".into(),
            HashSet::from(["group-1".to_string(), "group-2".to_string()]),
        );

        let mut current: NetmapSnapshot = HashMap::new();
        current.insert("device-b".into(), HashSet::from(["group-1".to_string()]));

        let diff = diff_netmap(&previous, &current);

        assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
        assert_eq!(diff.removed_group_edges, vec![("device-b".to_string(), "group-2".to_string())]);
    }

    /// Regression guard for the graceful-shutdown interaction: an earlier
    /// version of `run` drove its reconnect loop through `supervise::spawn_restarting`,
    /// which retries inside a second, independently `tokio::spawn`ed task — externally
    /// aborting the task *running* `run` (as `main.rs`'s `JoinSet::shutdown` does)
    /// only cancelled `run`'s `.await` on that task's `JoinHandle`, leaving the
    /// retry loop running detached and reconnecting forever past the "shutdown".
    /// This test would have failed under that design: it counts real connection
    /// attempts against a listener that always fails the handshake immediately,
    /// aborts `run`'s task once at least one attempt has happened, then asserts
    /// the count stays flat.
    #[tokio::test]
    async fn run_task_stops_retrying_once_its_own_task_is_aborted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicU32::new(0));
        {
            let accept_count = accept_count.clone();
            tokio::spawn(async move {
                // Every connection is closed immediately — every attempt
                // `run` makes fails fast and moves on to backoff.
                while let Ok((stream, _)) = listener.accept().await {
                    accept_count.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            });
        }

        let state = test_state();
        let config = OrchestratorConfig {
            coordination_addr: format!("http://{addr}"),
            access_token: "test-token".into(),
            device_id: "local-device".into(),
        };

        let handle = tokio::spawn(run(config, state));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while accept_count.load(Ordering::SeqCst) == 0 {
            assert!(tokio::time::Instant::now() < deadline, "run never attempted to connect");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        handle.abort();
        let count_at_abort = accept_count.load(Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;

        // Backoff's initial delay is ~1s; a detached retry loop still
        // running would have made at least one more attempt within this window.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            count_at_abort,
            "a connection attempt happened after run's own task was aborted — the reconnect loop is still running detached"
        );
    }

    /// `reconnect_delay` is the pure function driving `run`'s inline backoff —
    /// test its growth/cap behavior directly rather than through live networking.
    /// ±25% jitter means exact values aren't checked, only that consecutive
    /// attempts clearly grow and the schedule is eventually capped at
    /// `BackoffConfig::RECONNECT.max`, preventing tight busy-retry loops
    /// or unbounded growth.
    #[test]
    fn reconnect_delay_grows_then_caps_at_the_configured_max() {
        let d0 = reconnect_delay(0);
        let d1 = reconnect_delay(1);
        let d2 = reconnect_delay(2);
        assert!(
            d0 >= Duration::from_millis(500),
            "attempt 0 delay {d0:?} looks like a tight retry loop, not ~1s initial backoff"
        );
        assert!(d1 > d0, "attempt 1 delay {d1:?} did not grow past attempt 0's {d0:?}");
        assert!(d2 > d1, "attempt 2 delay {d2:?} did not grow past attempt 1's {d1:?}");

        let d_far = reconnect_delay(50);
        assert!(
            d_far <= BackoffConfig::RECONNECT.max,
            "a far-future attempt's delay {d_far:?} exceeded the configured cap {:?}",
            BackoffConfig::RECONNECT.max
        );
    }

    /// *starts* and *continues* in the first place.
    #[tokio::test]
    async fn run_resubscribes_repeatedly_after_a_simulated_drop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicU32::new(0));
        {
            let accept_count = accept_count.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    accept_count.fetch_add(1, Ordering::SeqCst);
                    drop(stream); // simulate the coordination server dropping the connection
                }
            });
        }

        let state = test_state();
        let config = OrchestratorConfig {
            coordination_addr: format!("http://{addr}"),
            access_token: "test-token".into(),
            device_id: "local-device".into(),
        };

        let handle = tokio::spawn(run(config, state));

        let first_batch_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while accept_count.load(Ordering::SeqCst) == 0 {
            assert!(
                tokio::time::Instant::now() < first_batch_deadline,
                "run never attempted to connect at all"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let count_after_first_attempt = accept_count.load(Ordering::SeqCst);

        // Give the reconnect loop real time to sleep out its backoff and
        // come back for another try — proves this isn't a one-shot
        // "fail once and give up forever" path.
        //
        let second_batch_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while accept_count.load(Ordering::SeqCst) <= count_after_first_attempt {
            assert!(
                tokio::time::Instant::now() < second_batch_deadline,
                "run made {count_after_first_attempt} connection attempt(s) then stopped retrying — no re-subscription after a drop"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        handle.abort();
    }
}
