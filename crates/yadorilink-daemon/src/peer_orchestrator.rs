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
use std::time::Duration;

use tokio::task::JoinHandle;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_transport::{
    diff_netmap, public_key_from_bytes, run_burst, CandidateClass, DeviceKeyPair, NatClass,
    NetmapDiff, NetmapSnapshot, PeerChannel, PunchConfig, PunchDecision, PunchLimiter, PunchTarget,
};

use crate::connection_trace::{AddressClass, AttemptOutcome, CandidateSource};
use crate::coordination_client::EndpointCandidate;
use crate::daemon_state::{DaemonState, PeerReachability, PeerStatusInfo, UnreachableCategory};
use crate::device_config;
use crate::error::DaemonError;
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
    /// device_id -> its live `PeerChannel`, so a whole-device revocation
    /// can call [`PeerChannel::revoke`] on the right one. Populated by
    /// `spawn_peer_session` once `PeerChannel::connect` succeeds (mirrors
    /// `DaemonState::sessions`' own insert-on-connect,
    /// removed-on-session-end lifecycle).
    channels: Arc<StdMutex<HashMap<String, Arc<PeerChannel>>>>,
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
}

impl NetmapDiffState {
    fn new() -> Self {
        Self {
            previous: Arc::new(StdMutex::new(HashMap::new())),
            last_snapshot_generation: Arc::new(StdMutex::new(None)),
            channels: Arc::new(StdMutex::new(HashMap::new())),
            session_tasks: Arc::new(StdMutex::new(HashMap::new())),
            punch_limiter: Arc::new(StdMutex::new(PunchLimiter::new(PunchConfig::default()))),
        }
    }
}

/// Forwards each punch-burst probe into a peer channel's candidate race,
/// which makes the transport send a WireGuard handshake at the address — the
/// handshake itself is the probe, so no separate probe protocol is needed.
struct ChannelPunchTarget {
    channel: Arc<PeerChannel>,
}

impl PunchTarget for ChannelPunchTarget {
    fn probe<'a>(
        &'a self,
        candidate: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.channel.add_direct_candidate(candidate).await;
        })
    }
}

/// Reacts to inbound rendezvous signals: for each, run a synchronized probe
/// burst that feeds the peer's offered candidates into its existing channel,
/// so both sides open their NAT mappings at roughly the same moment. A signal
/// for a peer with no live channel yet is dropped — the next netmap push
/// spawns that peer's session and our own rendezvous initiation re-opens the
/// exchange.
fn handle_incoming_rendezvous(
    signals: Vec<(String, Vec<SocketAddr>)>,
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) {
    for (from_device_id, candidates) in signals {
        if candidates.is_empty() {
            continue;
        }
        let channel = diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&from_device_id)
            .cloned();
        let Some(channel) = channel else {
            tracing::debug!(peer = %from_device_id, "rendezvous signal for a peer with no active channel yet; ignoring");
            continue;
        };
        // Record that a punch was attempted so classification can reach
        // `UdpBlocked` if no attempt ever confirms a direct path.
        state.nat_observations.record_punch_attempt(false);
        tokio::spawn(async move {
            let target = ChannelPunchTarget { channel };
            run_burst(&target, &candidates, &PunchConfig::default()).await;
        });
    }
}

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
    validation_cache: &std::sync::Mutex<HashMap<String, bool>>,
) -> HashSet<String> {
    // Seed identity only. Group authorization is withheld until the local
    // policy + retained-history validator positively admits it.
    state.replace_peer_netmap_metadata(device_id, signing_key, &HashSet::new(), &HashSet::new());

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
    );
    if let Some(session) = state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(device_id)
        .cloned()
    {
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
                let stored = state.sync_state.policy_watermark(&log.group_id)?;
                match policy.watermark_verdict(stored.as_ref()) {
                    crate::change_policy::WatermarkVerdict::Accept(watermark) => {
                        // Persist the (never-lowered) watermark BEFORE adopting
                        // the snapshot, so the anti-rollback guarantee is
                        // durable even if the daemon dies immediately after —
                        // a restart then still sees the higher watermark and
                        // refuses the old chain.
                        state.sync_state.upsert_policy_watermark(&log.group_id, &watermark)?;
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
pub async fn run(
    config: OrchestratorConfig,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
) -> Result<(), DaemonError> {
    let session_index = Arc::new(AtomicU32::new(0));
    // Created once here (not per-attempt) so it survives a
    // coordination-stream reconnect — see `NetmapDiffState`'s doc
    // comment.
    let diff_state = NetmapDiffState::new();

    let mut attempt: u32 = 0;
    loop {
        match run_netmap_attempt(&config, &keypair, &state, &session_index, &diff_state).await {
            Ok(()) => {
                tracing::warn!(attempt, "coordination netmap stream ended; reconnecting");
                // A clean stream end still means the coordination-plane
                // connection is no longer up (`run` is about to redial),
                // not a per-peer attempt so `peer_device_id` is empty.
                state.connection_traces.record(
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
                state.connection_traces.record(
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
        new_authority_key_base64: String,
        signer_key_id_base64: String,
        signature_base64: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsNetmapPeer {
        device_id: String,
        wireguard_public_key_base64: String,
        /// Ed25519 signing key used to authenticate this peer's change
        /// history, distributed alongside the WireGuard key. Optional:
        /// devices registered before signing keys existed have none, and
        /// the field may be absent on an older coordination plane, so its
        /// absence is normal and simply means change-history signing is not
        /// yet available with this peer.
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
        keypair: &Arc<DeviceKeyPair>,
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
        state.connection_traces.record(
            "",
            CandidateSource::CoordinationPlane,
            AddressClass::Wan,
            AttemptOutcome::Connected,
            0,
            "",
            true,
            Some(true),
        );

        let mut peer_key_pins = load_peer_key_pins()?;
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

            for peer in update.peers {
                let Ok(public_key_bytes) = base64::engine::general_purpose::STANDARD
                    .decode(&peer.wireguard_public_key_base64)
                else {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid base64 public key; revoking any existing session");
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                };
                match verify_or_pin_peer_key(&mut peer_key_pins, &peer.device_id, &public_key_bytes)
                {
                    PeerKeyDecision::AlreadyPinned => {}
                    PeerKeyDecision::NewlyPinned => save_peer_key_pins(&peer_key_pins)?,
                    PeerKeyDecision::Mismatch => {
                        tracing::error!(
                            device_id = %peer.device_id,
                            "netmap peer WireGuard key changed from pinned value; revoking any existing session"
                        );
                        teardown_peer(state, diff_state, &peer.device_id);
                        continue;
                    }
                }
                let signing_key_bytes = match peer.signing_public_key_base64.as_deref() {
                    None | Some("") => None,
                    Some(encoded) => {
                        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
                        else {
                            tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid signing key; revoking any existing session");
                            teardown_peer(state, diff_state, &peer.device_id);
                            continue;
                        };
                        if bytes.len() != 32 {
                            tracing::warn!(device_id = %peer.device_id, "netmap peer signing key is not 32 bytes; revoking any existing session");
                            teardown_peer(state, diff_state, &peer.device_id);
                            continue;
                        }
                        Some(bytes)
                    }
                };
                if pin_peer_signing_key(
                    &mut signing_key_pins,
                    &peer.device_id,
                    signing_key_bytes.clone(),
                )? {
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                }
                let Ok(peer_public) = public_key_from_bytes(&public_key_bytes) else {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid public key; revoking any existing session");
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                };
                let authorized_groups: HashSet<String> =
                    peer.shared_group_ids.iter().cloned().collect();
                let full_replica_groups: HashSet<String> =
                    peer.full_replica_group_ids.iter().cloned().collect();
                if !full_replica_groups.is_subset(&authorized_groups) {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer advertises full-replica groups it is not authorized for; revoking any existing session");
                    teardown_peer(state, diff_state, &peer.device_id);
                    continue;
                }
                let effective_authorized_groups = apply_authoritative_peer_metadata(
                    state,
                    &peer.device_id,
                    signing_key_bytes.as_deref().and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()),
                    &authorized_groups,
                    &full_replica_groups,
                    &retained_group_validation_cache,
                );
                let candidates: Vec<SocketAddr> =
                    peer.endpoints.iter().filter_map(|e| e.address.parse().ok()).collect();
                let existing_session = {
                    let sessions =
                        state.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    sessions.get(&peer.device_id).cloned()
                };
                if let Some(session) = existing_session {
                    session.replace_coordination_candidates(candidates).await;
                    continue;
                }

                // Offer this device's server-reflexive candidates so a peer we
                // can't reach directly can still be hole-punched (rate-limited
                // per peer; a no-op when we have no reflexive candidate).
                maybe_initiate_rendezvous(&peer.device_id, config, state, diff_state);

                let device_id = peer.device_id.clone();
                let mut effective_group_ids: Vec<String> =
                    effective_authorized_groups.into_iter().collect();
                effective_group_ids.sort();
                let handle = spawn_peer_session(
                    state.clone(),
                    keypair.clone(),
                    config.device_id.clone(),
                    device_id.clone(),
                    peer_public,
                    candidates,
                    effective_group_ids,
                    session_index.fetch_add(1, Ordering::Relaxed),
                    diff_state.clone(),
                );
                diff_state
                    .session_tasks
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(device_id, handle);
            }
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

fn load_peer_key_pins() -> Result<HashMap<String, String>, DaemonError> {
    load_key_pins(peer_key_pins_path())
}

/// The Ed25519 change-history signing keys, pinned exactly like the
/// WireGuard keys above (same file lifecycle, same refuse-on-change rule),
/// but in their own file so the two key spaces never collide.
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

/// Pins `device_id`'s Ed25519 signing key the same way `verify_or_pin_peer_key`
/// pins its WireGuard key, returning `true` when the key changed from a
/// previously-pinned value so the caller refuses the peer. `signing_key`
/// is `None` when the netmap carried none for this peer — nothing to pin or
/// check, so the peer is accepted (change-history signing is simply
/// unavailable with it, per this change's migration story).
fn pin_peer_signing_key(
    pins: &mut HashMap<String, String>,
    device_id: &str,
    signing_key: Option<Vec<u8>>,
) -> Result<bool, DaemonError> {
    let Some(signing_key) = signing_key else {
        return Ok(false);
    };
    match verify_or_pin_peer_key(pins, device_id, &signing_key) {
        PeerKeyDecision::AlreadyPinned => Ok(false),
        PeerKeyDecision::NewlyPinned => {
            save_signing_key_pins(pins)?;
            Ok(false)
        }
        PeerKeyDecision::Mismatch => {
            tracing::error!(
                device_id = %device_id,
                "netmap peer signing key changed from pinned value; refusing connection"
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
fn save_peer_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    save_key_pins(peer_key_pins_path(), pins)
}

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

fn peer_key_pins_path() -> PathBuf {
    device_config::config_dir().join("peer_keys.json")
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
#[cfg(test)]
fn peer_already_connected(state: &DaemonState, peer_device_id: &str) -> bool {
    state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(peer_device_id)
}

/// Records `peer_device_id`'s current reachability for the control socket,
/// overwriting any previous value.
fn set_reachability(state: &DaemonState, peer_device_id: &str, reachability: PeerReachability) {
    state
        .peer_statuses
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(peer_device_id.to_string(), PeerStatusInfo { reachability });
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
    state.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(peer_device_id);
    state
        .peer_statuses
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(peer_device_id);
}

/// Acts on one netmap update's diff (`diff_netmap`'s output). Whole-device
/// removals get torn down entirely; group-edge removals leave the
/// transport layer alone (the tunnel stays up — that's simply the
/// *absence* of a teardown call here) but now call
/// [`PeerSyncSession::revoke_group`] on that peer's still-live session
/// (found via `state.sessions`, the same map `teardown_peer` reads for
/// the whole-device case) so `yadorilink-sync-core`'s per-request
/// re-validation actually learns about the narrower revocation instead
/// of continuing to check the construction-time `shared_group_ids`
/// snapshot forever. `PeerSyncSession` has no reference to any
/// daemon-level "current netmap" of its own, and a `PeerChannel` has no
/// concept of a session or a group at all — `state.sessions` is the one
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
        if let Some(session) =
            state.sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(device_id)
        {
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
        // `state.sessions`), or its session may have just ended on its
        // own between this diff being computed and this loop running. In
        // either case there is nothing currently live to re-validate,
        // and any future session for this device is constructed fresh
        // from a subsequent (already-diffed-against) netmap snapshot, so
        // it will never pick group_id back up incorrectly.
    }
}

/// tears `device_id` down entirely — revokes its `PeerChannel`
/// (see `PeerChannel::revoke`'s doc comment: this is what actually stops
/// the WireGuard tunnel/actor and refuses any further handshake attempt
/// from this key), aborts its `PeerSyncSession` task (so any
/// in-flight request it's awaiting on is cancelled immediately rather
/// than left to notice its channel died), and removes it from
/// `DaemonState`.
///
/// That last step is hydration-candidate-pruning wiring:
/// `hydration::hydrate_inner` looks up authorized candidate peers live from
/// `state.sessions` on every hydration attempt (not a cached/snapshotted
/// candidate list), so removing this entry here — synchronously, in the
/// same update that detected the revocation — is what makes a removed
/// device immediately stop being offered as a multi-peer hydration
/// candidate, rather than only once its session notices the torn-down
/// channel and exits on its own (`end_session` would have run anyway at
/// that point, just later).
fn teardown_peer(state: &Arc<DaemonState>, diff_state: &NetmapDiffState, device_id: &str) {
    if let Some(channel) = diff_state
        .channels
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(device_id)
    {
        channel.revoke();
    }
    if let Some(handle) = diff_state
        .session_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(device_id)
    {
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

#[allow(clippy::too_many_arguments)]
fn spawn_peer_session(
    state: Arc<DaemonState>,
    keypair: Arc<DeviceKeyPair>,
    local_device_id: String,
    peer_device_id: String,
    peer_public: boringtun::x25519::PublicKey,
    candidates: Vec<SocketAddr>,
    shared_group_ids: Vec<String>,
    session_index: u32,
    diff_state: NetmapDiffState,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        mark_connecting(&state, &peer_device_id);

        // All peer channels share this device's one long-lived UDP socket, so
        // the NAT candidates it advertises describe the exact binding data
        // flows on. A bind failure here means no direct transport at all —
        // report the peer unreachable rather than dropping it silently.
        let shared = match state.ensure_shared_socket().await {
            Ok(shared) => shared,
            Err(e) => {
                tracing::warn!(peer = %peer_device_id, error = %e, "failed to bind the shared transport socket");
                set_reachability(
                    &state,
                    &peer_device_id,
                    PeerReachability::Unreachable(UnreachableCategory::NoResponse),
                );
                return;
            }
        };

        // An empty candidate set is not an error — the channel is created
        // and immediately reports `Unreachable { NoCandidates }`, which
        // `poll_reachability` surfaces. A `connect` error here is therefore
        // a genuine construction failure, reported as unreachable rather than
        // dropping the peer silently.
        let connect_result = PeerChannel::connect(
            keypair.secret.clone(),
            peer_public,
            session_index,
            candidates,
            shared,
        )
        .await;

        let channel = match connect_result {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::warn!(peer = %peer_device_id, error = %e, "failed to establish peer channel");
                state.connection_traces.record(
                    peer_device_id.clone(),
                    CandidateSource::DirectPath,
                    AddressClass::Unknown,
                    AttemptOutcome::Failed,
                    0,
                    UnreachableCategory::NoResponse.as_str(),
                    false,
                    None,
                );
                // The status entry stays so `yadorilink status` shows
                // "cannot connect"; the next netmap push re-attempts (this
                // peer is not in `state.sessions`, so it is not suppressed
                // as connected).
                set_reachability(
                    &state,
                    &peer_device_id,
                    PeerReachability::Unreachable(UnreachableCategory::NoResponse),
                );
                return;
            }
        };

        // registered so a later netmap-diff teardown
        // (`teardown_peer`) can find and `revoke` this exact channel —
        // dropping every `Arc<PeerChannel>` clone this task will go on to
        // hand out (below, and via `PeerSyncSession`) is not by itself
        // enough to stop the actor (see `PeerChannel::revoke`'s doc
        // comment), so `teardown_peer` needs a live reference, not just
        // to out-live every other clone.
        diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.clone(), channel.clone());

        // Reflect the channel's live reachability into status: it starts
        // `Connecting` while candidates race, becomes `Connected` once a
        // direct path is confirmed, or `Unreachable` if the race is lost.
        tokio::spawn(poll_reachability(state.clone(), peer_device_id.clone(), channel.clone()));

        let sync_roots = sync_roots_for_groups(&state, &shared_group_ids);
        let session = PeerSyncSession::new_with_forwarding(
            channel,
            local_device_id,
            peer_device_id.clone(),
            state.sync_state.clone(),
            state.block_store.clone(),
            shared_group_ids.clone(),
            sync_roots,
            Some(state.forward_tx.clone()),
        );
        // Every session shares this daemon's one global upload/download
        // token-bucket pair (never an independent per-session copy), and
        // its own disk-headroom preflight is turned on only once
        // `main.rs` has opted the whole daemon into enforcement (see
        // `DaemonState::disk_headroom_enforcement_enabled`'s doc comment
        // for why that's not just always-on here).
        session.set_rate_limiters(state.rate_limiters.clone());
        if state.disk_headroom_enforcement_enabled() {
            session.set_headroom_enforced(true);
        }
        // Lets this session's `reconcile_one_file` force a racing local
        // change out of this device's per-link debounce accumulators
        // before comparing/applying a peer update — see
        // `PendingLocalChangeFlush for DaemonState`'s doc comment
        // (`link_manager.rs`).
        session.set_pending_local_change_flush(state.clone());
        // Admit incoming change-history changes only when this device has
        // pinned the author's signing key and the author is an authorized
        // writer for the change's group — both mirrored from the netmap onto
        // `DaemonState`. Without an authenticator a session announces heads
        // and serves stored changes but never admits an incoming one.
        session.set_change_authenticator(crate::change_auth::NetmapChangeAuthenticator::new(
            state.clone(),
        ));
        // Lets this session answer an incoming peer `HandoffLeaseRequest` by
        // running this device's own target-side lease flow — see
        // `HandoffLeaseResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        session.set_handoff_lease_responder(state.clone());
        session.set_block_write_activity_provider(state.clone());
        // Lets this session answer an incoming peer `HandoffTicketRequest`
        // (from a different device removing/revoking this one) by running
        // this device's own removed-device-ticket flow — see
        // `HandoffTicketResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        session.set_handoff_ticket_responder(state.clone());
        // Lets this session answer an incoming peer `RebootstrapSnapshotRequest`
        // and process an incoming `RebootstrapSnapshotResponse` by running this
        // device's own signing identity and pinned-key trust resolver — see
        // `DaemonRebootstrapHandler`'s doc comment (`rebootstrap_handler.rs`).
        session.set_rebootstrap_handler(crate::rebootstrap_handler::DaemonRebootstrapHandler::new(
            state.clone(),
        ));
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.clone(), session.clone());

        if let Err(e) = session.run().await {
            tracing::warn!(peer = %peer_device_id, error = %e, "peer sync session ended with an error");
        }
        end_session(&state, &peer_device_id);
        // The session ended on its own (not via `teardown_peer`, which
        // already would have removed this entry) — clean up the
        // bookkeeping `teardown_peer` would otherwise use to find a
        // channel that no longer has a live session behind it. This
        // task's own `session_tasks` entry is left for
        // `prune_finished_session_tasks` to sweep (see that function's
        // doc comment for why this task can't remove it itself).
        diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&peer_device_id);
    })
}

/// Reflects the channel's reachability into status, waking on each change
/// via the transport's reachability watch (with a periodic re-check so it
/// also notices session teardown promptly).
///
/// Exits as soon as `end_session` removes this peer's
/// `peer_statuses` entry, which drops this task's `Arc<PeerChannel>`
/// clone — the other clone (held by `PeerSyncSession`) is dropped at the
/// same time via the `sessions` map, so once both this task and the
/// `sessions` entry are gone, nothing keeps a disconnected peer's
/// `PeerChannel` (and the actor task/UDP socket it owns) alive.
async fn poll_reachability(
    state: Arc<DaemonState>,
    peer_device_id: String,
    channel: Arc<PeerChannel>,
) {
    let mut reachability_rx = channel.reachability_watch();
    let mut previous: Option<PeerReachability> = None;
    loop {
        // Snapshot the current reachability and, when connected, the class
        // of the confirmed path. Computed inside this block so the watch
        // borrow guard is dropped before any lock or `.await` below.
        let (current, connected_class) = {
            let reachability = reachability_rx.borrow_and_update();
            let connected_class = match &*reachability {
                yadorilink_transport::PeerReachability::Connected { path } => {
                    Some(candidate_class_to_address(*path))
                }
                _ => None,
            };
            (map_transport_reachability(&reachability), connected_class)
        };
        {
            let mut statuses =
                state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(info) = statuses.get_mut(&peer_device_id) else { break }; // session ended
            info.reachability = current;
        }
        // A reachability transition is itself a meaningful connection event
        // (a confirmed direct path, or the loss of one) — recorded once per
        // transition, not once per change notification.
        if previous != Some(current) {
            record_reachability_transition(&state, &peer_device_id, current, connected_class);
        }
        previous = Some(current);
        // Wake immediately on a reachability change, but also re-check at
        // least every couple of seconds so this task still exits promptly
        // once `end_session` removes the status entry, even if the channel
        // never reports another change.
        tokio::select! {
            changed = reachability_rx.changed() => {
                if changed.is_err() {
                    break; // the channel's actor (watch sender) is gone
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
        }
    }
}

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
        PeerReachability::Connected => {
            // A confirmed direct path means UDP got through, so record a punch
            // success — this keeps NAT classification from misjudging the
            // network as UDP-blocked once any peer connects.
            state.nat_observations.record_punch_attempt(true);
            state.connection_traces.record(
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
        PeerReachability::Unreachable(category) => state.connection_traces.record(
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

// depends on the transport's reachability/candidate-class type shapes.
fn map_transport_reachability(
    reachability: &yadorilink_transport::PeerReachability,
) -> PeerReachability {
    use yadorilink_transport::PeerReachability as Transport;
    match reachability {
        Transport::Connecting { .. } => PeerReachability::Connecting,
        Transport::Connected { .. } => PeerReachability::Connected,
        Transport::Unreachable { category, .. } => {
            PeerReachability::Unreachable(map_transport_category(category))
        }
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

fn map_transport_category(
    category: &yadorilink_transport::UnreachableCategory,
) -> UnreachableCategory {
    use yadorilink_transport::UnreachableCategory as Transport;
    match category {
        Transport::NoCandidates => UnreachableCategory::NoCandidates,
        Transport::NoResponse => UnreachableCategory::NoResponse,
        Transport::UdpBlocked => UnreachableCategory::UdpBlocked,
        Transport::HandshakeRefused => UnreachableCategory::HandshakeRefused,
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
fn sync_roots_for_groups(state: &DaemonState, group_ids: &[String]) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    for group_id in group_ids {
        match state.sync_state.live_link_local_path_for_group(group_id) {
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
// directly (each peer's device id, public key, and pre-bound direct
// endpoint), and this seam opens the exact same `PeerChannel` /
// `PeerSyncSession` those discovered peers would have gotten -- every stage
// below `run_netmap_attempt` (session construction, forwarding, rate
// limiting, materialization) is the identical production code path.
//
// The pre-bound-socket pairing mirrors the way the sync-core two-device DST
// harness pairs devices in-sim: two UDP sockets bound on the loopback of a
// single simulation node, each side dialing the other's address. All of
// this is compiled only under `--cfg madsim`; production has no such seam
// and its behavior is byte-for-byte unchanged.

/// One already-authorized peer in a harness-supplied static netmap, plus
/// the pre-bound local UDP socket this device uses to reach it. Compiled
/// only under the deterministic simulator.
#[cfg(madsim)]
pub struct SimPeer {
    pub device_id: String,
    pub public_key: boringtun::x25519::PublicKey,
    pub shared_group_ids: Vec<String>,
    /// The peer's direct endpoint address(es) to dial. The harness has told
    /// the peer this device's single shared-socket address (see
    /// [`SimDiscovery::local_socket`]) as its candidate, so both sides can dial
    /// each other directly.
    pub peer_candidates: Vec<SocketAddr>,
}

/// The static-netmap discovery input the harness injects in place of the
/// coordination netmap stream. Passed to [`run_sim`], which is spawned as
/// the peer-orchestrator essential task under `--cfg madsim` instead of the
/// real [`run`].
#[cfg(madsim)]
pub struct SimDiscovery {
    pub keypair: Arc<DeviceKeyPair>,
    pub local_device_id: String,
    pub peers: Vec<SimPeer>,
    /// This device's single pre-bound shared UDP socket (one per device, not
    /// one per peer). Every peer channel demultiplexes off it, and each peer's
    /// candidate list points at its address.
    pub local_socket: tokio::net::UdpSocket,
}

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
    let SimDiscovery { keypair, local_device_id, peers, local_socket } = discovery;

    // Seed the device static key (for the hub's MAC1 gate), then install this
    // device's single shared socket before opening any channel so every peer
    // session demultiplexes off the one binding.
    let device_public = boringtun::x25519::PublicKey::from(&keypair.secret);
    state.set_device_static_public(device_public.to_bytes());
    state.set_shared_socket(yadorilink_transport::TransportHub::from_socket(
        local_socket,
        Some(device_public),
    ));

    for peer in peers {
        if peer_already_connected(&state, &peer.device_id) {
            continue;
        }
        let handle = spawn_direct_peer_session(
            state.clone(),
            keypair.clone(),
            local_device_id.clone(),
            peer.device_id.clone(),
            peer.public_key,
            peer.peer_candidates,
            peer.shared_group_ids,
            session_index.fetch_add(1, Ordering::Relaxed),
            diff_state.clone(),
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
/// forwarding/rate-limit/materialization wiring as production.
#[cfg(madsim)]
#[allow(clippy::too_many_arguments)]
fn spawn_direct_peer_session(
    state: Arc<DaemonState>,
    keypair: Arc<DeviceKeyPair>,
    local_device_id: String,
    peer_device_id: String,
    peer_public: boringtun::x25519::PublicKey,
    candidates: Vec<SocketAddr>,
    shared_group_ids: Vec<String>,
    session_index: u32,
    diff_state: NetmapDiffState,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        mark_connecting(&state, &peer_device_id);

        // `run_sim` installed the device's shared socket before spawning any
        // session, so it is always present here.
        let shared = state
            .shared_socket()
            .expect("run_sim installs the shared socket before opening channels");

        let channel = match PeerChannel::connect(
            keypair.secret.clone(),
            peer_public,
            session_index,
            candidates,
            shared,
        )
        .await
        {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::warn!(peer = %peer_device_id, error = %e, "failed to establish direct peer channel in-sim");
                end_session(&state, &peer_device_id);
                return;
            }
        };

        diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.clone(), channel.clone());

        // Reflect the channel's live reachability into status: it starts
        // `Connecting` while candidates race, becomes `Connected` once a
        // direct path is confirmed, or `Unreachable` if the race is lost.
        tokio::spawn(poll_reachability(state.clone(), peer_device_id.clone(), channel.clone()));

        // The static netmap can race the harness linking the shared folder
        // (in production a device knows its links before a netmap peer
        // appears; in-sim the daemon boots and this seam runs before the
        // harness has called `add_link`). Received files materialize into
        // `sync_roots`, so wait briefly for the shared group's local root
        // to appear before starting the session rather than constructing it
        // with an empty root map. The channel is already up while we wait,
        // so pairing is not delayed by this.
        let mut sync_roots = sync_roots_for_groups(&state, &shared_group_ids);
        for _ in 0..200 {
            if !sync_roots.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            sync_roots = sync_roots_for_groups(&state, &shared_group_ids);
        }

        let session = PeerSyncSession::new_with_forwarding(
            channel,
            local_device_id,
            peer_device_id.clone(),
            state.sync_state.clone(),
            state.block_store.clone(),
            shared_group_ids,
            sync_roots,
            Some(state.forward_tx.clone()),
        );
        session.set_rate_limiters(state.rate_limiters.clone());
        if state.disk_headroom_enforcement_enabled() {
            session.set_headroom_enforced(true);
        }
        session.set_pending_local_change_flush(state.clone());
        // Admit incoming change-history changes only when this device has
        // pinned the author's signing key and the author is an authorized
        // writer for the change's group — both mirrored from the netmap onto
        // `DaemonState`. Without an authenticator a session announces heads
        // and serves stored changes but never admits an incoming one.
        session.set_change_authenticator(crate::change_auth::NetmapChangeAuthenticator::new(
            state.clone(),
        ));
        // Lets this session answer an incoming peer `HandoffLeaseRequest` by
        // running this device's own target-side lease flow — see
        // `HandoffLeaseResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        session.set_handoff_lease_responder(state.clone());
        session.set_block_write_activity_provider(state.clone());
        // Lets this session answer an incoming peer `HandoffTicketRequest`
        // (from a different device removing/revoking this one) by running
        // this device's own removed-device-ticket flow — see
        // `HandoffTicketResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        session.set_handoff_ticket_responder(state.clone());
        // Lets this session answer an incoming peer `RebootstrapSnapshotRequest`
        // and process an incoming `RebootstrapSnapshotResponse` by running this
        // device's own signing identity and pinned-key trust resolver — see
        // `DaemonRebootstrapHandler`'s doc comment (`rebootstrap_handler.rs`).
        session.set_rebootstrap_handler(crate::rebootstrap_handler::DaemonRebootstrapHandler::new(
            state.clone(),
        ));
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.clone(), session.clone());

        if let Err(e) = session.run().await {
            tracing::warn!(peer = %peer_device_id, error = %e, "peer sync session ended with an error");
        }
        end_session(&state, &peer_device_id);
        diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&peer_device_id);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
    use std::net::SocketAddr as StdSocketAddr;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

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

    /// The Ed25519 signing key is pinned with the same refuse-on-change
    /// rule as the WireGuard key; a peer that never advertised one is simply
    /// accepted (change-history signing is unavailable with it, not an
    /// error). The persisting `NewlyPinned` path is exercised by the
    /// WireGuard-key store above, which shares the same code.
    #[test]
    fn signing_key_pinning_refuses_a_changed_key_and_tolerates_absence() {
        let mut pins = HashMap::new();

        // No signing key advertised: nothing to pin, peer accepted.
        assert!(!pin_peer_signing_key(&mut pins, "device-a", None).unwrap());
        assert!(pins.is_empty());

        // Already-pinned matching key: accepted, no change.
        pins.insert("device-a".to_string(), hex::encode([7u8; 32]));
        assert!(!pin_peer_signing_key(&mut pins, "device-a", Some(vec![7u8; 32])).unwrap());

        // Changed key: refused.
        assert!(pin_peer_signing_key(&mut pins, "device-a", Some(vec![9u8; 32])).unwrap());
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
    // `state.sessions`/`state.peer_statuses` are keyed on real
    // `Arc<PeerSyncSession>`/`PeerChannel` types from other crates, so a
    // couple of these tests build one real (but peer-less) `PeerChannel`
    // against a candidate address that never answers — a lightweight "fake
    // transport": `PeerChannel::connect` registers on the shared socket and
    // spawns its actor without blocking on a WireGuard handshake with a live
    // peer, so no second device is needed.

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
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
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        state
            .sync_state
            .force_second_live_link_for_test("/home/alice/PhotosCopy", "group-1")
            .unwrap();
        state.sync_state.add_link("/home/alice/Docs", "group-2").unwrap();

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
        state.sync_state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.sync_state.add_link("/home/alice/Docs", "group-2").unwrap();
        state.sync_state.mark_link_orphaned("/home/alice/Photos").unwrap();

        let roots = sync_roots_for_groups(&state, &["group-1".to_string(), "group-2".to_string()]);

        assert!(!roots.contains_key("group-1"), "an orphaned link's group must not resolve");
        assert_eq!(roots.get("group-2"), Some(&PathBuf::from("/home/alice/Docs")));
    }

    fn gen_keypair() -> (StaticSecret, X25519PublicKey) {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        (secret, public)
    }

    /// A `PeerChannel` that's real enough to exercise `state.sessions`'s
    /// concrete type and to be handed to `poll_reachability`, but doesn't
    /// need (or wait for) an actual peer on the other end — its candidate
    /// address never answers, so the channel just races it and stays
    /// unconnected, which is all these lifecycle/teardown tests need.
    async fn fake_channel() -> Arc<PeerChannel> {
        let (secret, _public) = gen_keypair();
        let (_peer_secret, peer_public) = gen_keypair();
        let candidate: StdSocketAddr = "127.0.0.1:9".parse().unwrap();
        let shared = yadorilink_transport::TransportHub::bind(
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            None,
        )
        .await
        .unwrap();
        Arc::new(
            PeerChannel::connect(secret, peer_public, 0, vec![candidate], shared).await.unwrap(),
        )
    }

    fn fake_session(state: &Arc<DaemonState>, channel: Arc<PeerChannel>) -> Arc<PeerSyncSession> {
        PeerSyncSession::new_with_forwarding(
            channel,
            "local-device".into(),
            "device-b".into(),
            state.sync_state.clone(),
            state.block_store.clone(),
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

        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".into(), session);
        assert!(peer_already_connected(&state, "device-b"));
        // An unrelated peer id is never suppressed by another peer's entry.
        assert!(!peer_already_connected(&state, "device-c"));
    }

    #[tokio::test]
    async fn authoritative_netmap_replaces_metadata_for_an_existing_session() {
        let state = test_state();
        let session = fake_session(&state, fake_channel().await);
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".into(), session.clone());

        let initial_groups = HashSet::from(["group-1".to_string(), "group-2".to_string()]);
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            Some([7; 32]),
            &initial_groups,
            &initial_groups,
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
                    "wireguardPublicKeyBase64": "AA==",
                    "endpoints": [],
                    "sharedGroupIds": []
                },
                {
                    "deviceId": "device-b",
                    "wireguardPublicKeyBase64": "AQ==",
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
                    "wireguardPublicKeyBase64": "AA==",
                    "endpoints": [],
                    "sharedGroupIds": []
                },
                {
                    "deviceId": "device-c",
                    "wireguardPublicKeyBase64": "AQ==",
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

        assert!(state
            .peer_statuses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get("device-b")
            .is_none());

        mark_connecting(&state, "device-b");
        {
            let statuses =
                state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let info = statuses.get("device-b").unwrap();
            assert_eq!(info.reachability, PeerReachability::Connecting);
            assert!(!info.reachability.is_connected());
        }

        set_reachability(&state, "device-b", PeerReachability::Connected);
        {
            let statuses =
                state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let info = statuses.get("device-b").unwrap();
            assert!(info.reachability.is_connected());
            assert_eq!(info.reachability.as_str(), "connected");
        }

        set_reachability(
            &state,
            "device-b",
            PeerReachability::Unreachable(UnreachableCategory::NoResponse),
        );
        {
            let statuses =
                state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let info = statuses.get("device-b").unwrap();
            assert!(!info.reachability.is_connected());
            assert_eq!(info.reachability.as_str(), "unreachable");
            assert_eq!(info.reachability.unreachable_category_str(), "no_response");
        }
    }

    /// Cleanup on session drop: ending a session
    /// removes both the `sessions` and `peer_statuses` entries, and that
    /// removal is what makes a still-running `poll_reachability` task exit
    /// (dropping its `Arc<PeerChannel>` clone) instead of polling a dead
    /// peer forever.
    #[tokio::test]
    async fn session_end_removes_state_and_stops_the_status_poller() {
        let state = test_state();
        let channel = fake_channel().await;
        let session = fake_session(&state, channel.clone());

        mark_connecting(&state, "device-b");
        set_reachability(&state, "device-b", PeerReachability::Connected);
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".into(), session.clone());

        let poller =
            tokio::spawn(poll_reachability(state.clone(), "device-b".into(), channel.clone()));

        assert!(state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
        assert!(state
            .peer_statuses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));

        end_session(&state, "device-b");

        assert!(!state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
        assert!(!state
            .peer_statuses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));

        // `poll_reachability` only checks every 2s; give it a couple of
        // ticks to observe the removed entry and exit.
        tokio::time::timeout(Duration::from_secs(5), poller)
            .await
            .expect("poll_reachability task must exit once its peer_statuses entry is removed")
            .unwrap();

        // Every strong reference this module held (`sessions` entry,
        // `poll_reachability`'s clone) is gone; only this test's own
        // `session`/`channel` locals and the channel clone inside
        // `session` remain.
        drop(session);
        assert_eq!(Arc::strong_count(&channel), 1);
    }

    // --- Netmap-diff-driven teardown integration tests -------------------

    fn fake_session_for(
        state: &Arc<DaemonState>,
        channel: Arc<PeerChannel>,
        peer_device_id: &str,
        shared_group_ids: Vec<String>,
    ) -> Arc<PeerSyncSession> {
        PeerSyncSession::new_with_forwarding(
            channel,
            "local-device".into(),
            peer_device_id.into(),
            state.sync_state.clone(),
            state.block_store.clone(),
            shared_group_ids,
            HashMap::new(),
            Some(state.forward_tx.clone()),
        )
    }

    /// Registers a fake connected peer the same way `spawn_peer_session`
    /// would once `PeerChannel::connect` succeeds: `state.sessions`,
    /// `state.peer_statuses`, and `diff_state.channels` all populated —
    /// everything `teardown_peer`/`apply_netmap_diff` act on.
    async fn register_fake_peer(
        state: &Arc<DaemonState>,
        diff_state: &NetmapDiffState,
        peer_device_id: &str,
        shared_group_ids: Vec<String>,
    ) -> Arc<PeerChannel> {
        let channel = fake_channel().await;
        let session = fake_session_for(state, channel.clone(), peer_device_id, shared_group_ids);
        set_reachability(state, peer_device_id, PeerReachability::Connected);
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.to_string(), session);
        diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_device_id.to_string(), channel.clone());
        channel
    }

    /// A whole-device removal (`diff.removed_devices`) tears
    /// the tunnel down entirely — `PeerChannel::revoke` is called (handshake-refusal
    /// primitive; exercised cryptographically for
    /// real in `yadorilink_transport::peer_channel`'s own tests) — *and*
    /// immediately drops the peer from `state.sessions`, which is exactly
    /// what is required: `hydration.rs`'s `candidate_sessions` reads
    /// `state.sessions` live, so removing it here is what makes the
    /// device stop being offered as a hydration candidate right away,
    /// not merely once its session times out on its own.
    #[tokio::test]
    async fn full_device_revocation_tears_down_channel_and_drops_hydration_candidate() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let channel =
            register_fake_peer(&state, &diff_state, "device-b", vec!["group-1".into()]).await;
        assert!(!channel.is_revoked());

        let diff = NetmapDiff {
            removed_devices: vec!["device-b".to_string()],
            removed_group_edges: vec![],
        };
        apply_netmap_diff(&diff, &state, &diff_state);

        assert!(channel.is_revoked(), "whole-device revocation must revoke its PeerChannel");
        assert!(
            !state
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("device-b"),
            "revoked device must be immediately gone from state.sessions, which hydration's \
             candidate_sessions reads live"
        );
        assert!(!state
            .peer_statuses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
        assert!(!diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
    }

    /// A group-edge-only removal (the device is still
    /// present in `removed_group_edges` but *not* in `removed_devices`,
    /// because it still shares another group) must leave the
    /// tunnel/`PeerChannel` up and the session connected — distinct from
    /// the whole-device case above, proving `apply_netmap_diff` really
    /// does treat the two differently rather than tearing down on any
    /// diff entry at all.
    #[tokio::test]
    async fn group_edge_revocation_leaves_tunnel_and_session_up() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let channel = register_fake_peer(
            &state,
            &diff_state,
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
            !channel.is_revoked(),
            "a device that still shares another group must keep its tunnel up"
        );
        assert!(
            state
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key("device-b"),
            "a group-edge-only revocation must not remove the still-authorized session"
        );
        assert!(diff_state
            .channels
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
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
        let _channel = register_fake_peer(
            &state,
            &diff_state,
            "device-b",
            vec!["group-1".into(), "group-2".into()],
        )
        .await;
        let session = state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get("device-b")
            .unwrap()
            .clone();
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
        set_reachability(&state, "device-b", PeerReachability::Connected);

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

    #[tokio::test]
    async fn pinned_peer_key_mismatch_tears_down_session_and_authorization() {
        let state = test_state();
        let diff_state = NetmapDiffState::new();
        let channel =
            register_fake_peer(&state, &diff_state, "device-b", vec!["group-1".into()]).await;
        apply_authoritative_peer_metadata(
            &state,
            "device-b",
            Some([7; 32]),
            &HashSet::from(["group-1".to_string()]),
            &HashSet::from(["group-1".to_string()]),
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

        assert!(channel.is_revoked());
        assert!(!state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key("device-b"));
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
    /// `teardown_peer` removes the `state.sessions` entry that check
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
        let keypair = Arc::new(DeviceKeyPair::generate());
        let config = OrchestratorConfig {
            coordination_addr: format!("http://{addr}"),
            access_token: "test-token".into(),
            device_id: "local-device".into(),
        };

        let handle = tokio::spawn(run(config, keypair, state));

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
        let keypair = Arc::new(DeviceKeyPair::generate());
        let config = OrchestratorConfig {
            coordination_addr: format!("http://{addr}"),
            access_token: "test-token".into(),
            device_id: "local-device".into(),
        };

        let handle = tokio::spawn(run(config, keypair, state));

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
