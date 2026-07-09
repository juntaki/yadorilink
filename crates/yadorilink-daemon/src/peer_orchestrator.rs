//! Connects the daemon to the coordination plane's netmap stream and, for
//! each authorized peer that appears, establishes a `PeerChannel` (design
//! D6/D10: relay-first, racing local+public candidates, auto-upgrading)
//! and runs a `PeerSyncSession` over it (tasks 7.1's "establish transport
//! sessions").
//!
//! Deliberately simple for this MVP: once a peer session is established
//! it is never torn down here even if later removed from the netmap
//! (ACL-revocation teardown is a documented follow-up); this only ever
//! *adds* sessions as new peers appear.
//!
//! daemon-reliability reliability hardening/reliability hardening: the coordination netmap subscription
//! (channel connect, RPC, stream, and — for its own first attempt — the
//! shared relay hub) used to be one-shot: any failure, including one on
//! the very first attempt before the network was up, permanently ended
//! `run` and left the daemon with no P2P sync until a human restarted it.
//! `run` now retries that whole setup forever with backoff (every failure
//! — initial or later — is just another attempt); `run` itself stays up
//! for the daemon's whole lifetime (see its doc comment).
//!
//! That retry loop deliberately runs *inline* in `run`'s own task rather
//! than via `supervise::spawn_restarting`: `spawn_restarting` retries
//! inside a second, independently `tokio::spawn`ed task, so externally
//! aborting the task *running* `run` (as `main.rs`'s reliability hardening graceful
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

use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
#[cfg(not(feature = "http-coordination"))]
use tonic::transport::{Channel, ClientTlsConfig};
#[cfg(not(feature = "http-coordination"))]
use yadorilink_ipc_proto::coordination::netmap_service_client::NetmapServiceClient;
#[cfg(not(feature = "http-coordination"))]
use yadorilink_ipc_proto::coordination::StreamNetmapRequest;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_transport::{
    diff_netmap, public_key_from_bytes, DeviceKeyPair, NetmapDiff, NetmapSnapshot, PeerChannel,
    RelayHub, TransportMode,
};

use crate::connection_trace::{AddressClass, AttemptOutcome, CandidateSource};
use crate::daemon_state::{DaemonState, PeerStatusInfo};
use crate::device_config;
use crate::error::DaemonError;
use crate::supervise::BackoffConfig;

pub struct OrchestratorConfig {
    pub coordination_addr: String,
    pub relay_addr: SocketAddr,
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
/// `Arc`) so it survives a coordination-stream reconnect (reliability hardening/reliability hardening): a
/// revocation observed before a stream drop must still apply after the
/// stream reconnects, and — just as importantly — a fresh reconnect's
/// first snapshot must be diffed against the *last real* netmap, not an
/// empty one (an empty "previous" would report zero removals no matter
/// what changed, silently forgetting any revocation the diff hasn't
/// already acted on).
#[derive(Clone)]
struct NetmapDiffState {
    previous: Arc<StdMutex<NetmapSnapshot>>,
    /// device_id -> its live `PeerChannel`, so a whole-device revocation
    /// can call [`PeerChannel::revoke`] on the right one. Populated by
    /// `spawn_peer_session` once `PeerChannel::connect` succeeds (mirrors
    /// `DaemonState::sessions`' own insert-on-connect,
    /// remove-on-session-end lifecycle).
    channels: Arc<StdMutex<HashMap<String, Arc<PeerChannel>>>>,
    /// device_id -> the `JoinHandle` for its `spawn_peer_session` task, so
    /// a whole-device revocation can abort the in-flight
    /// `PeerSyncSession::run()` (and whatever it's mid-request on)
    /// immediately rather than relying on it to notice its `PeerChannel`
    /// died on its own. A session that ends on its own (not via
    /// revocation) leaves its now-finished handle here for
    /// `prune_finished_session_tasks` to sweep — only the task that
    /// inserted a handle (this module's own update loop) can remove it,
    /// a spawned task cannot reach into this map to remove its own entry.
    session_tasks: Arc<StdMutex<HashMap<String, JoinHandle<()>>>>,
}

impl NetmapDiffState {
    fn new() -> Self {
        Self {
            previous: Arc::new(StdMutex::new(HashMap::new())),
            channels: Arc::new(StdMutex::new(HashMap::new())),
            session_tasks: Arc::new(StdMutex::new(HashMap::new())),
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
/// failure this module retries (reliability hardening/reliability hardening: coordination connect, the
/// stream RPC itself, the shared relay hub's initial connect) — it does
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
    // One relay connection for this whole device, shared by every peer
    // session — see `RelayHub`'s docs for why a per-peer relay connection
    // is broken (the relay registers exactly one connection per public
    // key). Connected lazily on the first netmap-subscription attempt and
    // cached here so a later netmap-stream reconnect reuses it rather
    // than opening a second relay connection under the same key.
    let relay_hub_cell: OnceCell<Arc<RelayHub>> = OnceCell::new();
    // Created once here (not per-attempt) so it survives a
    // coordination-stream reconnect — see `NetmapDiffState`'s doc
    // comment.
    let diff_state = NetmapDiffState::new();

    let mut attempt: u32 = 0;
    loop {
        match run_netmap_attempt(
            &config,
            &keypair,
            &state,
            &relay_hub_cell,
            &session_index,
            &diff_state,
        )
        .await
        {
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
                    "",
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
                    "",
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

/// `run_netmap_attempt`'s WebSocket-based counterpart, talking to the
/// HTTP coordination service's `/netmap/subscribe` route
/// (`src/routes/netmap.ts` forwarding to
/// `src/durable-objects/netmap-device.ts`) instead of the gRPC
/// `StreamNetmap` RPC. Same signature, same reconnect contract (`run`'s
/// inline backoff loop calls this exactly the way it calls the gRPC
/// version), same downstream diff/spawn-session logic below this
/// function — only the transport and wire format differ.
#[cfg(feature = "http-coordination")]
mod ws_netmap {
    use base64::Engine;
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};
    use tokio_tungstenite::tungstenite::Message;

    use super::*;

    #[derive(serde::Deserialize)]
    struct WsNetmapMessage {
        #[serde(rename = "type")]
        #[allow(dead_code)]
        kind: String,
        peers: Vec<WsNetmapPeer>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WsNetmapPeer {
        device_id: String,
        wireguard_public_key_base64: String,
        endpoints: Vec<WsEndpoint>,
        shared_group_ids: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct WsEndpoint {
        address: String,
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

    /// Matches on `url`'s typed `Host` enum rather than `host_str()` -- for
    /// an IPv6 literal, `host_str()` returns the bracketed authority form
    /// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a
    /// first attempt at this fix used `host_str()` this way and shipped
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
        relay_hub_cell: &OnceCell<Arc<RelayHub>>,
        session_index: &Arc<AtomicU32>,
        diff_state: &NetmapDiffState,
    ) -> Result<(), DaemonError> {
        let url = netmap_ws_url(&config.coordination_addr, &config.device_id)?;
        let auth_value = HeaderValue::from_str(&format!("Bearer {}", config.access_token))
            .map_err(|_| DaemonError::Config("access token is not a valid header value".into()))?;
        let request = Request::builder()
            .uri(url)
            .header("Authorization", auth_value)
            .body(())
            .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;

        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
        // Mirrors the gRPC path: record a successful coordination-plane
        // connect before the (possibly also failing) relay-hub connect
        // below, so a doctor read mid-outage can distinguish the two.
        state.connection_traces.record(
            "",
            CandidateSource::CoordinationPlane,
            AddressClass::Wan,
            AttemptOutcome::Connected,
            0,
            "",
            true,
            "",
            Some(true),
        );

        // reliability hardening: identical to the gRPC path's relay-hub connect below —
        // the relay hub is transport-agnostic with respect to how the
        // netmap itself was fetched.
        let relay_hub = match relay_hub_cell
            .get_or_try_init(|| async {
                RelayHub::connect(config.relay_addr, keypair.secret.clone())
                    .await
                    .map_err(DaemonError::from)
            })
            .await
        {
            Ok(hub) => {
                state.connection_traces.record(
                    "",
                    CandidateSource::Relay,
                    AddressClass::RelayHop,
                    AttemptOutcome::Connected,
                    0,
                    "",
                    true,
                    "",
                    Some(true),
                );
                hub.clone()
            }
            Err(e) => {
                state.connection_traces.record(
                    "",
                    CandidateSource::Relay,
                    AddressClass::RelayHop,
                    AttemptOutcome::Failed,
                    0,
                    "relay_connect_error",
                    false,
                    "",
                    None,
                );
                return Err(e);
            }
        };

        let mut peer_key_pins = load_peer_key_pins()?;

        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            let text = match msg {
                Message::Text(text) => text,
                Message::Close(_) => break,
                // Ping/Pong/Binary/Frame: not a netmap update, nothing to do.
                _ => continue,
            };
            let Ok(update) = serde_json::from_str::<WsNetmapMessage>(&text) else {
                tracing::warn!("received malformed netmap message; ignoring");
                continue;
            };

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

            for peer in update.peers {
                if peer_already_connected(state, &peer.device_id) {
                    continue;
                }
                let Ok(public_key_bytes) = base64::engine::general_purpose::STANDARD
                    .decode(&peer.wireguard_public_key_base64)
                else {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid base64 public key, skipping");
                    continue;
                };
                match verify_or_pin_peer_key(&mut peer_key_pins, &peer.device_id, &public_key_bytes)
                {
                    PeerKeyDecision::AlreadyPinned => {}
                    PeerKeyDecision::NewlyPinned => save_peer_key_pins(&peer_key_pins)?,
                    PeerKeyDecision::Mismatch => {
                        tracing::error!(
                            device_id = %peer.device_id,
                            "netmap peer WireGuard key changed from pinned value; refusing connection"
                        );
                        continue;
                    }
                }
                let Ok(peer_public) = public_key_from_bytes(&public_key_bytes) else {
                    tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid public key, skipping");
                    continue;
                };
                let candidates: Vec<SocketAddr> =
                    peer.endpoints.iter().filter_map(|e| e.address.parse().ok()).collect();

                let device_id = peer.device_id.clone();
                let handle = spawn_peer_session(
                    state.clone(),
                    keypair.clone(),
                    relay_hub.clone(),
                    config.device_id.clone(),
                    device_id.clone(),
                    peer_public,
                    candidates,
                    peer.shared_group_ids,
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
        // retrying rather than treating as permanent (reliability hardening).
        Ok(())
    }
}

#[cfg(feature = "http-coordination")]
use ws_netmap::run_netmap_attempt;

/// One full attempt at the coordination netmap subscription: connect (or
/// reuse) the shared relay hub, connect the coordination gRPC channel,
/// open the `StreamNetmap` RPC, and process updates until the stream ends
/// or errors. Called repeatedly by `run`'s inline reconnect loop — every
/// `Err` (and a clean stream end, treated the same way by the caller) is
/// just another attempt, never a permanent failure.
#[cfg(not(feature = "http-coordination"))]
async fn run_netmap_attempt(
    config: &OrchestratorConfig,
    keypair: &Arc<DeviceKeyPair>,
    state: &Arc<DaemonState>,
    relay_hub_cell: &OnceCell<Arc<RelayHub>>,
    session_index: &Arc<AtomicU32>,
    diff_state: &NetmapDiffState,
) -> Result<(), DaemonError> {
    let channel = coordination_channel(&config.coordination_addr).await?;
    let mut client = NetmapServiceClient::new(channel);

    let mut request =
        tonic::Request::new(StreamNetmapRequest { device_id: config.device_id.clone() });
    let auth_value = format!("Bearer {}", config.access_token)
        .parse()
        .map_err(|_| DaemonError::Config("access token is not a valid header value".into()))?;
    request.metadata_mut().insert("authorization", auth_value);

    let mut stream = client.stream_netmap(request).await?.into_inner();
    // The `StreamNetmap` RPC just opened successfully — record it as a
    // connected coordination-plane attempt before this function moves on
    // to the (possibly also failing) relay-hub connect below, so a
    // doctor read mid-outage can still see "coordination plane itself is
    // reachable" separately from "relay is reachable".
    state.connection_traces.record(
        "",
        CandidateSource::CoordinationPlane,
        AddressClass::Wan,
        AttemptOutcome::Connected,
        0,
        "",
        true,
        "",
        Some(true),
    );

    // reliability hardening: the relay hub's own initial connect is just another attempt
    // inside this same backoff loop — `get_or_try_init` leaves the cell
    // uninitialized on error, so the next call (next reconnect attempt)
    // retries it, but never reconnects a relay hub that's already up.
    let relay_hub = match relay_hub_cell
        .get_or_try_init(|| async {
            RelayHub::connect(config.relay_addr, keypair.secret.clone())
                .await
                .map_err(DaemonError::from)
        })
        .await
    {
        Ok(hub) => {
            state.connection_traces.record(
                "",
                CandidateSource::Relay,
                AddressClass::RelayHop,
                AttemptOutcome::Connected,
                0,
                "",
                true,
                "",
                Some(true),
            );
            hub.clone()
        }
        Err(e) => {
            state.connection_traces.record(
                "",
                CandidateSource::Relay,
                AddressClass::RelayHop,
                AttemptOutcome::Failed,
                0,
                "relay_connect_error",
                false,
                "",
                None,
            );
            return Err(e);
        }
    };

    let mut peer_key_pins = load_peer_key_pins()?;

    while let Some(update) = stream.message().await? {
        // Diff this snapshot against the previously-held one *before*
        // acting on the new peer list below, so a device that dropped
        // out of this exact update is torn down in the same pass it's
        // noticed missing, rather than only on some later update.
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

        for peer in update.peers {
            if peer_already_connected(state, &peer.device_id) {
                continue; // already connected — see module docs on teardown
            }
            match verify_or_pin_peer_key(
                &mut peer_key_pins,
                &peer.device_id,
                &peer.wireguard_public_key,
            ) {
                PeerKeyDecision::AlreadyPinned => {}
                PeerKeyDecision::NewlyPinned => save_peer_key_pins(&peer_key_pins)?,
                PeerKeyDecision::Mismatch => {
                    tracing::error!(
                        device_id = %peer.device_id,
                        "netmap peer WireGuard key changed from pinned value; refusing connection"
                    );
                    continue;
                }
            }
            let Ok(peer_public) = public_key_from_bytes(&peer.wireguard_public_key) else {
                tracing::warn!(device_id = %peer.device_id, "netmap peer has an invalid public key, skipping");
                continue;
            };
            let candidates: Vec<SocketAddr> =
                peer.endpoints.iter().filter_map(|e| e.address.parse().ok()).collect();

            let device_id = peer.device_id.clone();
            let handle = spawn_peer_session(
                state.clone(),
                keypair.clone(),
                relay_hub.clone(),
                config.device_id.clone(),
                device_id.clone(),
                peer_public,
                candidates,
                peer.shared_group_ids,
                session_index.fetch_add(1, Ordering::Relaxed),
                diff_state.clone(),
            );
            // stored immediately (synchronously, right after
            // `spawn_peer_session` returns its `JoinHandle` — before the
            // task's own `PeerChannel::connect().await` has necessarily
            // finished) so a revocation racing a still-connecting session
            // can still abort it.
            diff_state
                .session_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(device_id, handle);
        }
    }
    // The server closed the stream without an error — still worth
    // retrying rather than treating as permanent (reliability hardening).
    Ok(())
}

#[cfg(not(feature = "http-coordination"))]
async fn coordination_channel(addr: &str) -> Result<Channel, DaemonError> {
    let mut endpoint = Channel::from_shared(addr.to_string())
        .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;
    let uri = endpoint.uri().clone();
    match uri.scheme_str() {
        Some("https") => {
            endpoint = endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?;
        }
        Some("http") if is_loopback_host(uri.host()) => {}
        Some("http") => {
            return Err(DaemonError::Config(
                "remote coordination addresses must use https://".into(),
            ))
        }
        _ => {
            return Err(DaemonError::Config(
                "coordination address must use http:// or https://".into(),
            ))
        }
    }
    Ok(endpoint.connect().await?)
}

#[cfg(not(feature = "http-coordination"))]
fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else { return false };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

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
    let path = peer_key_pins_path();
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err.into()),
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
/// each writer's own `open()` independently truncates to empty, so two
/// interleaved writes can leave the file containing the tail of one
/// writer's bytes appended after the other's, valid JSON followed by
/// "trailing characters" that fails every future parse of the file for
/// every reader, permanently, until something notices and repairs it by
/// hand. `rename` on both Unix and Windows replaces `path` atomically as
/// a single filesystem operation — a concurrent reader either sees the
/// old complete file or the new complete file, never a mix of both.
fn save_peer_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    let path = peer_key_pins_path();
    let Some(parent) = path.parent() else {
        return Err(DaemonError::Config("peer key pins path has no parent directory".into()));
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

/// Whether `peer_device_id` already has a running session — the dedup
/// check `run_netmap_attempt`'s update loop uses to avoid opening a
/// second `PeerChannel`/`PeerSyncSession` for a peer that's already
/// connected (module docs on the deliberately-simple session lifecycle).
fn peer_already_connected(state: &DaemonState, peer_device_id: &str) -> bool {
    state
        .sessions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .contains_key(peer_device_id)
}

/// Status-transition step 1/2 (the relevant behavior "status transition ordering"):
/// a session about to attempt connecting is reported disconnected, same
/// as one that's never been seen — there's no separate "connecting"
/// state exposed over the control socket.
fn mark_connecting(state: &DaemonState, peer_device_id: &str) {
    state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
        peer_device_id.to_string(),
        PeerStatusInfo { connected: false, path_kind: "disconnected".into() },
    );
}

/// Status-transition step 2/2: the `PeerChannel` connected successfully.
/// Always reports `"relay"` at this point — `TransportMode::Auto` starts
/// on relay and only upgrades to direct later, which `poll_path_status`
/// picks up.
fn mark_connected(state: &DaemonState, peer_device_id: &str) {
    state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
        peer_device_id.to_string(),
        PeerStatusInfo { connected: true, path_kind: "relay".into() },
    );
}

/// reliability hardening: called when a peer session ends — whether it never got past
/// connecting, or ran and later errored/returned — removing *both* the
/// `sessions` and `peer_statuses` entries, instead of the prior behavior
/// of merely re-marking the status "disconnected" forever. Removing the
/// `peer_statuses` entry is what makes `poll_path_status`'s
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
        // finished `PeerChannel::connect` yet (the relevant behavior synchronous
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
/// from this key, the relevant behavior), aborts its `PeerSyncSession` task (so any
/// in-flight request it's awaiting on is cancelled immediately rather
/// than left to notice its channel died), and removes it from
/// `DaemonState`.
///
/// That last step 's hydration-candidate-pruning wiring:
/// `hydration.rs`'s `candidate_sessions` is a *live* query over
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
}

/// Hygiene, not correctness: a session that ends on its own (channel
/// error, peer-initiated close, etc. — not a netmap-diff-driven
/// `teardown_peer`) leaves its now-finished `JoinHandle` sitting in
/// `session_tasks` forever, since only the loop that inserted a handle
/// (this module's own update loop, not the spawned task itself) can
/// remove it. Swept once per netmap update so a long-lived daemon with
/// many peer connect/disconnect cycles doesn't accumulate finished
/// handles indefinitely; `.abort()`ing an already-finished handle is a
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
    relay_hub: Arc<RelayHub>,
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

        let connect_result = PeerChannel::connect(
            TransportMode::Auto,
            keypair.secret.clone(),
            peer_public,
            session_index,
            Some(relay_hub),
            candidates,
            None,
        )
        .await;

        let channel = match connect_result {
            Ok(c) => {
                // `TransportMode::Auto` always starts on relay (design
                // D6/D10), so a successful `connect` here is a
                // relay-path connection — the subsequent direct upgrade
                // (if any) is recorded separately by `poll_path_status`
                // below.
                state.connection_traces.record(
                    peer_device_id.clone(),
                    CandidateSource::Relay,
                    AddressClass::RelayHop,
                    AttemptOutcome::Connected,
                    0,
                    "",
                    true,
                    "",
                    Some(true),
                );
                Arc::new(c)
            }
            Err(e) => {
                tracing::warn!(peer = %peer_device_id, error = %e, "failed to establish peer channel");
                state.connection_traces.record(
                    peer_device_id.clone(),
                    CandidateSource::CoordinationPlane,
                    AddressClass::Unknown,
                    AttemptOutcome::Failed,
                    0,
                    e.category(),
                    false,
                    "",
                    None,
                );
                end_session(&state, &peer_device_id); // nothing was ever established; drop the stale "connecting" status entry too
                return;
            }
        };

        // registered so a later netmap-diff teardown
        // (`teardown_peer`) can find and `revoke()` this exact channel —
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

        mark_connected(&state, &peer_device_id);
        tokio::spawn(poll_path_status(state.clone(), peer_device_id.clone(), channel.clone()));

        let sync_roots = sync_roots_for_groups(&state, &shared_group_ids);
        let session = PeerSyncSession::new_with_forwarding(
            channel,
            local_device_id,
            peer_device_id.clone(),
            state.sync_state.clone(),
            state.block_store.clone(),
            shared_group_ids,
            sync_roots,
            Some(state.forward_tx.clone()),
            Some(state.presence_tx.clone()),
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

/// `PeerChannel` doesn't push path-change events, so this just polls
/// `current_path()` for status reporting (the relevant behavior) — a reasonable
/// trade-off given how infrequently the path actually changes.
///
/// reliability hardening: exits as soon as `end_session` removes this peer's
/// `peer_statuses` entry, which drops this task's `Arc<PeerChannel>`
/// clone — the other clone (held by `PeerSyncSession`) is dropped at the
/// same time via the `sessions` map, so once both this task and the
/// `sessions` entry are gone, nothing keeps a disconnected peer's
/// `PeerChannel` (and the actor task/UDP socket it owns) alive.
async fn poll_path_status(
    state: Arc<DaemonState>,
    peer_device_id: String,
    channel: Arc<PeerChannel>,
) {
    let mut previous_path: Option<yadorilink_transport::PathKind> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut statuses =
            state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(info) = statuses.get_mut(&peer_device_id) else { break }; // session ended
        let current = channel.current_path();
        info.path_kind = match current {
            yadorilink_transport::PathKind::Direct => "direct".into(),
            yadorilink_transport::PathKind::Relay => "relay".into(),
        };
        // A path-kind transition is itself a meaningful connection event
        // (a direct/NAT-traversed upgrade, or a fallback back to relay)
        // — recorded once per transition, not once per poll tick.
        if previous_path.is_some_and(|p| p != current) {
            let (source, class) = match current {
                yadorilink_transport::PathKind::Direct => {
                    (CandidateSource::DirectPath, AddressClass::Wan)
                }
                yadorilink_transport::PathKind::Relay => {
                    (CandidateSource::Relay, AddressClass::RelayHop)
                }
            };
            state.connection_traces.record(
                peer_device_id.clone(),
                source,
                class,
                AttemptOutcome::Connected,
                0,
                "",
                true,
                "",
                Some(true),
            );
        }
        previous_path = Some(current);
    }
}

fn sync_roots_for_groups(state: &DaemonState, group_ids: &[String]) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    if let Ok(links) = state.sync_state.list_links() {
        for link in links {
            if group_ids.contains(&link.group_id) {
                roots.insert(link.group_id, PathBuf::from(link.local_path));
            }
        }
    }
    roots
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

    #[cfg(not(feature = "http-coordination"))]
    #[test]
    fn loopback_host_detection_accepts_only_local_hosts() {
        assert!(is_loopback_host(Some("localhost")));
        assert!(is_loopback_host(Some("127.0.0.1")));
        assert!(is_loopback_host(Some("[::1]")));
        assert!(!is_loopback_host(Some("203.0.113.10")));
        assert!(!is_loopback_host(Some("coordination.example")));
    }

    /// The WebSocket path's equivalent loopback/scheme validation,
    /// mirroring the gRPC path's
    /// `loopback_host_detection_accepts_only_local_hosts` above.
    #[cfg(feature = "http-coordination")]
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
    #[cfg(feature = "http-coordination")]
    #[test]
    fn ws_netmap_url_handles_an_ipv6_loopback_literal() {
        use super::ws_netmap::netmap_ws_url;

        assert_eq!(
            netmap_ws_url("http://[::1]:8787", "device-1").unwrap(),
            "ws://[::1]:8787/netmap/subscribe?deviceId=device-1"
        );
    }

    // --- the relevant behavior: peer_orchestrator tests -------------------------------
    //
    // `state.sessions`/`state.peer_statuses` are keyed on real
    // `Arc<PeerSyncSession>`/`PeerChannel` types from other crates, so a
    // couple of these tests build one real (but peer-less) `PeerChannel`
    // over a local, in-process relay server — the same lightweight "fake
    // transport" pattern `yadorilink-sync-core`'s `tests/peer_session.rs`
    // uses (`PeerChannel::connect` only registers with the relay hub and
    // spawns its actor; it does not block on a WireGuard handshake with a
    // live peer, so no second device is needed).

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("local-device".into(), sync_state, store)
    }

    async fn start_test_relay() -> StdSocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = yadorilink_transport::relay_server::serve(listener).await;
        });
        addr
    }

    fn gen_keypair() -> (StaticSecret, X25519PublicKey) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519PublicKey::from(&secret);
        (secret, public)
    }

    /// A `PeerChannel` that's real enough to exercise `state.sessions`'s
    /// concrete type and to be handed to `poll_path_status`, but doesn't
    /// need (or wait for) an actual peer on the other end.
    async fn fake_channel(relay_addr: StdSocketAddr) -> Arc<PeerChannel> {
        let (secret, _public) = gen_keypair();
        let (_peer_secret, peer_public) = gen_keypair();
        let hub = RelayHub::connect(relay_addr, secret.clone()).await.unwrap();
        Arc::new(
            PeerChannel::connect(
                TransportMode::RelayOnly,
                secret,
                peer_public,
                0,
                Some(hub),
                vec![],
                None,
            )
            .await
            .unwrap(),
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
            Some(state.presence_tx.clone()),
        )
    }

    /// reliability hardening/3's netmap loop skips a peer already present in
    /// `state.sessions` rather than opening a second `PeerChannel` for it
    /// — the exact check `run_netmap_attempt` guards `spawn_peer_session`
    /// calls with.
    #[tokio::test]
    async fn duplicate_peer_suppression_skips_already_connected_peer() {
        let state = test_state();
        let relay_addr = start_test_relay().await;
        let channel = fake_channel(relay_addr).await;
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

    /// the relevant behavior "status transition ordering": a peer session goes
    /// disconnected -> connected (never skipping straight to connected,
    /// never regressing mid-connect) as `spawn_peer_session` drives it.
    #[tokio::test]
    async fn status_transitions_go_disconnected_then_connected_in_order() {
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
            assert!(!info.connected);
            assert_eq!(info.path_kind, "disconnected");
        }

        mark_connected(&state, "device-b");
        {
            let statuses =
                state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let info = statuses.get("device-b").unwrap();
            assert!(info.connected);
            assert_eq!(info.path_kind, "relay");
        }
    }

    /// reliability hardening / the relevant behavior "cleanup on session drop": ending a session
    /// removes both the `sessions` and `peer_statuses` entries, and that
    /// removal is what makes a still-running `poll_path_status` task exit
    /// (dropping its `Arc<PeerChannel>` clone) instead of polling a dead
    /// peer forever.
    #[tokio::test]
    async fn session_end_removes_state_and_stops_the_status_poller() {
        let state = test_state();
        let relay_addr = start_test_relay().await;
        let channel = fake_channel(relay_addr).await;
        let session = fake_session(&state, channel.clone());

        mark_connecting(&state, "device-b");
        mark_connected(&state, "device-b");
        state
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".into(), session.clone());

        let poller =
            tokio::spawn(poll_path_status(state.clone(), "device-b".into(), channel.clone()));

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

        // `poll_path_status` only checks every 2s; give it a couple of
        // ticks to observe the removed entry and exit.
        tokio::time::timeout(Duration::from_secs(5), poller)
            .await
            .expect("poll_path_status task must exit once its peer_statuses entry is removed")
            .unwrap();

        // Every strong reference this module held (`sessions` entry,
        // `poll_path_status`'s clone) is gone; only this test's own
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
            Some(state.presence_tx.clone()),
        )
    }

    /// Registers a fake connected peer the same way `spawn_peer_session`
    /// would once `PeerChannel::connect` succeeds: `state.sessions`,
    /// `state.peer_statuses`, and `diff_state.channels` all populated —
    /// everything `teardown_peer`/`apply_netmap_diff` act on.
    async fn register_fake_peer(
        state: &Arc<DaemonState>,
        diff_state: &NetmapDiffState,
        relay_addr: StdSocketAddr,
        peer_device_id: &str,
        shared_group_ids: Vec<String>,
    ) -> Arc<PeerChannel> {
        let channel = fake_channel(relay_addr).await;
        let session = fake_session_for(state, channel.clone(), peer_device_id, shared_group_ids);
        mark_connected(state, peer_device_id);
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

    /// the relevant behavior: a whole-device removal (`diff.removed_devices`) tears
    /// the tunnel down entirely — `PeerChannel::revoke()` is called (task
    /// 2.4's handshake-refusal primitive; exercised cryptographically for
    /// real in `yadorilink_transport::peer_channel`'s own tests) — *and*
    /// immediately drops the peer from `state.sessions`, which is exactly
    /// requires: `hydration.rs`'s `candidate_sessions` reads
    /// `state.sessions` live, so removing it here is what makes the
    /// device stop being offered as a hydration candidate right away,
    /// not merely once its session times out on its own.
    #[tokio::test]
    async fn full_device_revocation_tears_down_channel_and_drops_hydration_candidate() {
        let state = test_state();
        let relay_addr = start_test_relay().await;
        let diff_state = NetmapDiffState::new();
        let channel =
            register_fake_peer(&state, &diff_state, relay_addr, "device-b", vec!["group-1".into()])
                .await;
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
             candidate_sessions reads live (the relevant behavior)"
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

    /// the relevant behavior: a group-edge-only removal (the device is still
    /// present in `removed_group_edges` but *not* in `removed_devices`,
    /// because it still shares another group per D3) must leave the
    /// tunnel/`PeerChannel` up and the session connected — distinct from
    /// the whole-device case above, proving `apply_netmap_diff` really
    /// does treat the two differently rather than tearing down on any
    /// diff entry at all.
    #[tokio::test]
    async fn group_edge_revocation_leaves_tunnel_and_session_up() {
        let state = test_state();
        let relay_addr = start_test_relay().await;
        let diff_state = NetmapDiffState::new();
        let channel = register_fake_peer(
            &state,
            &diff_state,
            relay_addr,
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
        let relay_addr = start_test_relay().await;
        let diff_state = NetmapDiffState::new();
        let _channel = register_fake_peer(
            &state,
            &diff_state,
            relay_addr,
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
            // external `.abort()` ends this.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            still_running_clone.store(true, Ordering::Relaxed);
        });
        diff_state
            .session_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert("device-b".to_string(), handle);
        mark_connected(&state, "device-b");
        state.peer_statuses.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
            "device-b".into(),
            PeerStatusInfo { connected: true, path_kind: "relay".into() },
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

    /// Regression guard for the graceful-shutdown interaction the module
    /// doc comment explains: an earlier version of `run` drove its
    /// reconnect loop through `supervise::spawn_restarting`, which retries
    /// inside a second, independently `tokio::spawn`ed task — externally
    /// aborting the task *running* `run` (as `main.rs`'s
    /// `JoinSet::shutdown` does for reliability hardening) only cancelled `run`'s
    /// `.await` on that other task's `JoinHandle`, leaving the actual
    /// retry loop running detached and reconnecting forever past the
    /// "shutdown". This test would have failed under that design: it
    /// counts real connection attempts against a listener that always
    /// fails the handshake immediately, aborts `run`'s task once at least
    /// one attempt has happened, then asserts the count stays flat —
    /// proving nothing kept retrying behind the abort.
    #[tokio::test]
    async fn run_task_stops_retrying_once_its_own_task_is_aborted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicU32::new(0));
        {
            let accept_count = accept_count.clone();
            tokio::spawn(async move {
                // Every connection is closed immediately — every attempt
                // `run` makes fails fast and moves on to backoff, giving
                // this test a fast, deterministic per-attempt signal.
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
            relay_addr: addr,
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

        // Backoff's initial delay is ~1s (`BackoffConfig::RECONNECT`); a
        // detached retry loop still running would have made at least one
        // more attempt well within this window.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            count_at_abort,
            "a connection attempt happened after run's own task was aborted — the reconnect loop is still running detached"
        );
    }

    /// `reconnect_delay`
    /// is the pure function driving `run`'s inline backoff — test its
    /// growth/cap behavior directly rather than through live networking
    /// (fragile: real connect/RPC/relay-handshake timing on a dropped
    /// socket varies enough between runs and platforms that asserting on
    /// wall-clock gaps between real network attempts is not reliable).
    /// ±25% jitter means exact values aren't checked, only that
    /// consecutive attempts clearly grow and the schedule is eventually
    /// capped at `BackoffConfig::RECONNECT.max`, matching reliability hardening's "cap
    /// ~30-60s" — not a tight busy-retry loop (attempt 0 near-zero) and
    /// not unbounded growth (a very late attempt still near-zero from
    /// integer overflow, say).
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

    /// simulates a
    /// coordination-plane drop (a listener that accepts and immediately
    /// closes every connection, as if the server crashed or reset the
    /// TCP connection right after accept) and asserts `run` actually
    /// re-subscribes repeatedly (reliability hardening/reliability hardening — no permanent give-up)
    /// rather than giving up after the first failure. Combined with
    /// `reconnect_delay_grows_then_caps_at_the_configured_max` above
    /// (which covers the backoff *schedule* deterministically), this
    /// covers that reconnection actually *happens* end-to-end through
    /// `run`'s real code path. Distinct from
    /// `run_task_stops_retrying_once_its_own_task_is_aborted` above,
    /// which only proves retrying *stops* on abort — this proves it
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
            relay_addr: addr,
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
        // "fail once and give up forever" path (the exact bug reliability hardening/
        // reliability hardening fixed).
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
