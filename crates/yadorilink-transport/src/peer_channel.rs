//! Transport-path-agnostic per-peer channel (the relevant behavior): `yadorilink-sync-core`
//! sends/receives plain application messages here and never knows whether
//! the underlying WireGuard session is currently relayed or direct — or
//! which of possibly several direct candidates (LAN, NAT-traversed
//! public, or one learned later via local broadcast discovery) ended up
//! being used.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::error::TransportError;
use crate::relay_hub::RelayHub;
use crate::reliable::{decode_frame, encode_ack_frame, DecodedFrame, ReliableRecv, ReliableSend};
use crate::tunn_wrapper::{WgTunnel, MAX_WIREGUARD_DATAGRAM_LEN};
use crate::udp_batching::UdpBatchingSupport;

const TICK_INTERVAL: Duration = Duration::from_millis(500);
/// How often direct candidates are (re-)probed: all of them concurrently
/// until one is confirmed (the relevant behavior racing), then just the confirmed
/// one as a keepalive/liveness check (the relevant behavior upgrade attempts).
const DIRECT_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// reliability hardening: how long a `Direct`-path channel can go without receiving
/// *any* direct-socket traffic before it's treated as dead and failed
/// back to relay. WireGuard itself sends a keepalive roughly every 25s
/// when otherwise idle (`tunn_wrapper::KEEPALIVE_SECS`), and this actor
/// additionally re-probes every `DIRECT_PROBE_INTERVAL` (5s) — four
/// missed probe cycles is comfortably past a single dropped
/// keepalive/probe round-trip (avoiding flapping on a single lost UDP
/// packet) while still failing back well inside a user-noticeable stall.
const DIRECT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTBOUND_BATCH: usize = 16;
const MAX_DIRECT_RECV_BATCH: usize = 16;
/// How often the actor checks for a due standalone ack and/or a due
/// retransmit (`ReliableSend::due_retransmits`,
/// `ReliableRecv::take_ack_dirty`). Well under the RTT-adaptive retransmit
/// timeout itself (`reliable.rs`'s `RttEstimator`, 100ms-5s) so this
/// interval never meaningfully delays a retransmit past its computed
/// deadline — it just bounds how finely that deadline is checked.
const RELIABLE_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// security hardening: fixed cap on how many direct-endpoint candidates a single
/// `PeerChannel` will hold at once. An attacker who knows an authorized
/// peer's public key can mint an unbounded number of distinct
/// `(key, addr)` local-discovery candidates (SEC-30's per-source rate
/// limit is ~16/10s but has no upstream cap); this bounds the resulting
/// memory and the per-cycle probe/send fan-out regardless. Comfortably
/// fits the realistic legitimate set (a handful of LAN interfaces plus a
/// relay-observed public address) while still being small.
const MAX_DIRECT_CANDIDATES: usize = 8;

// --- Netmap-diff logic ----------------------------------------------
//
// The coordination plane's `stream_netmap` currently pushes a *full* netmap
// snapshot, never a delta. `NetmapUpdate::removed_peer_device_ids` is defined
// in the proto but is sent empty, and `is_full_update` is `true`. So the
// client side (`yadorilink-daemon`'s `peer_orchestrator`) must diff each new
// snapshot against whatever it held before, to find what was revoked. This
// module owns that pure diff logic; `peer_orchestrator` owns holding the
// "previous" snapshot across updates and acting on the result.

/// One netmap snapshot, keyed by `device_id` (stable across calls per
/// device; device registration inserts a fresh row or marks one removed,
/// never rotates a key under an existing `device_id`) mapping to the set of
/// folder groups this device and the peer currently share.
///
/// A `HashSet`, not a `Vec`, deliberately: the coordination plane's
/// `compute_netmap` has no `ORDER BY` on the group-membership query
/// backing a peer's `shared_group_ids`, so the same peer's group list can
/// legitimately come back in a different order across two consecutive
/// calls with no group actually added or removed. Diffing by position
/// would misclassify a reorder as a group being both removed and added.
pub type NetmapSnapshot = HashMap<String, HashSet<String>>;

/// The result of [`diff_netmap`]: what disappeared between two netmap
/// snapshots, split by blast-radius: a whole device losing all shared
/// groups versus one shared group among several being revoked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetmapDiff {
    /// Device ids present in `previous` but entirely absent from
    /// `current` — no authorized group remains between the local device
    /// and this peer (whole-device revocation, e.g. `device remove`, or a
    /// `share revoke` that was this pair's only shared group). Since
    /// `compute_netmap` only ever lists a peer it shares at least one
    /// group with (a peer with zero shared groups is omitted entirely,
    /// never present with an empty group set), a device's disappearance
    /// from the snapshot *is* the signal — the relevant behavior tears its
    /// `PeerChannel` down entirely for each of these.
    pub removed_devices: Vec<String>,
    /// `(device_id, group_id)` pairs present in `previous` whose device is
    /// *still* present in `current` (so at least one other shared group
    /// remains) but that specific group is no longer shared (`share
    /// revoke` of one group among several) — the relevant behavior narrower case:
    /// the tunnel/`PeerChannel` stays up, only that group's sync activity
    /// stops (enforced by `yadorilink-sync-core`'s per-request
    /// re-validation, not by this transport-level diff).
    pub removed_group_edges: Vec<(String, String)>,
}

/// Diffs `current` against `previous` (the relevant behavior), classifying every
/// device that lost at least one shared group as either a whole-device
/// removal ([`NetmapDiff::removed_devices`]) or a narrower group-edge
/// removal ([`NetmapDiff::removed_group_edges`]). Devices present in
/// `current` but not `previous` (newly authorized) and groups unchanged
/// between the two snapshots produce no diff entries — this function
/// only ever reports *removals*. Output order is sorted for
/// deterministic logging/testing (`HashMap`/`HashSet` iteration order is
/// not stable).
pub fn diff_netmap(previous: &NetmapSnapshot, current: &NetmapSnapshot) -> NetmapDiff {
    let mut removed_devices = Vec::new();
    let mut removed_group_edges = Vec::new();

    for (device_id, previous_groups) in previous {
        match current.get(device_id) {
            None => removed_devices.push(device_id.clone()),
            Some(current_groups) => {
                for group_id in previous_groups {
                    if !current_groups.contains(group_id) {
                        removed_group_edges.push((device_id.clone(), group_id.clone()));
                    }
                }
            }
        }
    }

    removed_devices.sort();
    removed_group_edges.sort();
    NetmapDiff { removed_devices, removed_group_edges }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Relay,
    Direct,
}

/// Provenance of a learned direct-endpoint candidate (security hardening): the
/// coordination plane is authenticated (its candidates come from the
/// peer's registered netmap, supplied once at `PeerChannel::connect`
/// time), whereas local network discovery (`local_discovery`, fed in at
/// runtime via `add_direct_candidate`/`candidate_rx`, see `src/lib.rs`) is
/// unauthenticated LAN broadcast traffic that anyone on the same network
/// segment can forge (SEC-29). Discovery-sourced candidates are always
/// evicted first when the candidate list is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateSource {
    Discovery,
    Coordination,
}

/// One learned direct-endpoint candidate together with its provenance and
/// when it was learned, so [`insert_candidate`] can rank/evict fairly.
struct DirectCandidate {
    addr: SocketAddr,
    source: CandidateSource,
    added_at: Instant,
}

/// Which transport(s) a [`PeerChannel`] is allowed to use. `Auto` starts on
/// relay (always works) and transparently upgrades to direct once reachable.
pub enum TransportMode {
    RelayOnly,
    DirectOnly,
    Auto,
}

pub struct PeerChannel {
    outbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    current_path: Arc<AtomicU8>,
    candidate_tx: mpsc::Sender<SocketAddr>,
    /// This device's public IP:port as observed by the relay at connect
    /// time (the relevant behavior netcheck). `None` for `DirectOnly` channels, which
    /// never talk to a relay. Reported to the coordination plane's
    /// `report_endpoint` by the daemon.
    observed_address: Option<String>,
    /// Set by [`revoke`] and checked by `handle_datagram` before
    /// processing *any* further datagram — including a subsequent,
    /// otherwise-valid WireGuard
    /// handshake attempt from this same peer. Separate from `shutdown`
    /// (which wakes the actor loop to exit) so the refusal is effective
    /// immediately and synchronously, not only once the actor notices the
    /// wake-up on its next poll.
    ///
    /// [`revoke`]: PeerChannel::revoke
    revoked: Arc<AtomicBool>,
    /// Wakes the actor loop (`run_actor`'s `biased` `select!`) to break
    /// out and run its normal exit cleanup (relay deregistration)
    /// immediately on [`revoke`],
    /// rather than only on the next `TICK_INTERVAL` tick or once every
    /// `Arc<PeerChannel>` clone happens to be dropped (dropping the
    /// clones alone does not stop the actor — its `tick`/`direct_probe`
    /// intervals keep the `select!` loop alive independent of channel
    /// state).
    ///
    /// [`revoke`]: PeerChannel::revoke
    shutdown: Arc<Notify>,
    /// Shared with `ActorState` (same pattern as
    /// `revoked`/`current_path`). Starts `false`; flipped by
    /// [`enable_reliable_delivery`] once `peer_session.rs`'s `ClusterConfig`
    /// handshake confirms *both* sides advertised `supports_reliable_
    /// delivery`. Only gates whether THIS device wraps its own outbound
    /// sends — receiving and acking is always format-agnostic regardless
    /// of this flag (see `reliable.rs`'s module doc comment), so there is
    /// no negotiation race between the two directions independently
    /// flipping this at different times.
    ///
    /// [`enable_reliable_delivery`]: PeerChannel::enable_reliable_delivery
    reliable_enabled: Arc<AtomicBool>,
}

impl PeerChannel {
    /// Establishes a channel to a peer. `relay_hub` is this device's
    /// single shared relay connection (see `relay_hub.rs` for why it must
    /// be shared across every `PeerChannel`, not one-per-peer), used for
    /// `RelayOnly`/`Auto` modes; `direct_candidates` are the peer's known
    /// endpoints (from the coordination plane's netmap, highest priority
    /// — typically LAN addresses — first) for `DirectOnly`/`Auto` modes.
    /// All candidates are raced concurrently rather than tried one at a
    /// time.
    ///
    /// `direct_socket` lets a caller supply a pre-bound local UDP socket
    /// (its bound port is what must be exchanged with the peer as this
    /// device's own candidate address, e.g. via the coordination plane).
    /// If `None`, a fresh ephemeral-port socket is bound automatically —
    /// the normal production path.
    pub async fn connect(
        mode: TransportMode,
        local_secret: StaticSecret,
        peer_public: PublicKey,
        session_index: u32,
        relay_hub: Option<Arc<RelayHub>>,
        direct_candidates: Vec<SocketAddr>,
        direct_socket: Option<UdpSocket>,
    ) -> Result<Self, TransportError> {
        let peer_public_bytes = peer_public.to_bytes();
        let relay = match (&mode, &relay_hub) {
            (TransportMode::RelayOnly | TransportMode::Auto, Some(hub)) => {
                Some(RelayRoute { hub: hub.clone(), inbound: hub.register(peer_public_bytes) })
            }
            (TransportMode::RelayOnly, None) => {
                return Err(TransportError::NoRoute("relay-only mode requires a relay hub".into()))
            }
            _ => None,
        };

        let direct_socket = match mode {
            TransportMode::DirectOnly | TransportMode::Auto => {
                Some(Arc::new(match direct_socket {
                    Some(s) => s,
                    None => UdpSocket::bind("0.0.0.0:0").await?,
                }))
            }
            TransportMode::RelayOnly => None,
        };

        if matches!(mode, TransportMode::DirectOnly) && direct_candidates.is_empty() {
            return Err(TransportError::NoRoute(
                "direct-only mode requires at least one candidate address".into(),
            ));
        }

        let initial_path = match mode {
            TransportMode::DirectOnly => PathKind::Direct,
            _ => PathKind::Relay,
        };

        let observed_address = relay_hub.as_ref().map(|h| h.observed_address());

        let tunn = WgTunnel::new(local_secret, peer_public, session_index);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(64);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(64);
        let (candidate_tx, candidate_rx) = mpsc::channel::<SocketAddr>(16);
        let current_path = Arc::new(AtomicU8::new(path_to_u8(initial_path)));
        let revoked = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());
        let udp_batching = UdpBatchingSupport::detect();
        let reliable_enabled = Arc::new(AtomicBool::new(false));

        // security hardening: candidates supplied here come from the caller's
        // coordination-plane netmap (see the doc comment on `connect`'s
        // `direct_candidates` param) — highest provenance, so they are
        // inserted as `Coordination` and are never evicted to admit a
        // later discovery-supplied candidate. Still routed through
        // `insert_candidate` so the fixed cap applies uniformly even to
        // the initial set.
        let mut bounded_candidates: Vec<DirectCandidate> = Vec::new();
        for addr in direct_candidates {
            insert_candidate(&mut bounded_candidates, None, addr, CandidateSource::Coordination);
        }

        spawn_actor(ActorState {
            tunn,
            relay,
            peer_public_bytes,
            direct_socket,
            direct_candidates: bounded_candidates,
            confirmed_direct_addr: None,
            last_direct_rx: None,
            outbound_rx,
            candidate_rx,
            inbound_tx,
            current_path: current_path.clone(),
            allow_direct: !matches!(mode, TransportMode::RelayOnly),
            allow_relay: !matches!(mode, TransportMode::DirectOnly),
            revoked: revoked.clone(),
            shutdown: shutdown.clone(),
            udp_batching,
            reliable_enabled: reliable_enabled.clone(),
            reliable_send: ReliableSend::new(),
            reliable_recv: ReliableRecv::new(),
        });

        Ok(Self {
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            current_path,
            candidate_tx,
            observed_address,
            revoked,
            shutdown,
            reliable_enabled,
        })
    }

    /// Called once `peer_session.rs`'s `ClusterConfig` handshake confirms
    /// *both* sides advertised `supports_reliable_delivery` — from this
    /// point on, this device's
    /// own outbound sends via [`send`](Self::send) are wrapped with the
    /// seq/ack framing (`reliable.rs`) and retransmitted until acked
    /// rather than relying solely on the 30s/90s per-message-type
    /// backstops. Idempotent (setting an already-`true` flag is a no-op).
    /// The *receiving* side of this channel is always format-agnostic
    /// regardless of whether this has been called — see `reliable.rs`'s
    /// module doc comment for why that closes the negotiation race.
    pub fn enable_reliable_delivery(&self) {
        self.reliable_enabled.store(true, Ordering::Relaxed);
    }

    /// This device's public endpoint as observed by the relay (the relevant behavior).
    pub fn observed_address(&self) -> Option<&str> {
        self.observed_address.as_deref()
    }

    /// PERF-6: accepts anything cheaply convertible into `Bytes` (a `Vec<u8>`
    /// converts with no copy — `Bytes::from(Vec<u8>)` just takes ownership
    /// of the existing allocation) rather than requiring `Vec<u8>`
    /// specifically, so a caller that already holds a refcounted `Bytes`
    /// (or wants to hand the same encoded buffer to more than one
    /// destination) never has to materialize a fresh owned copy just to
    /// call this.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), TransportError> {
        self.outbound_tx.send(payload.into()).await.map_err(|_| TransportError::RelayClosed)
    }

    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.inbound_rx.lock().await.recv().await
    }

    pub fn current_path(&self) -> PathKind {
        u8_to_path(self.current_path.load(Ordering::Relaxed))
    }

    /// Adds a newly-learned direct candidate at runtime (the relevant behavior) — e.g.
    /// one surfaced by local broadcast discovery after this channel was
    /// already established. Ignored if the channel doesn't use a direct
    /// path at all (`RelayOnly`).
    pub async fn add_direct_candidate(&self, addr: SocketAddr) {
        let _ = self.candidate_tx.send(addr).await;
    }

    /// Tears this channel down in response to a whole-device revocation
    /// (the relevant behavior) and, from this moment on, refuses to process any further
    /// datagram on this channel — including a subsequent WireGuard
    /// handshake attempt from this same peer's key (the relevant behavior), which is
    /// otherwise cryptographically indistinguishable from a legitimate
    /// reconnect attempt by an unrevoked peer.
    ///
    /// Marks the channel revoked immediately (synchronously, before this
    /// call returns) and wakes the actor loop to exit and run its usual
    /// cleanup (relay deregistration) right away rather than waiting for
    /// its next tick. Idempotent and safe to call more than once, e.g. if
    /// a caller races a netmap update against a session that is already
    /// ending on its own.
    ///
    /// Does *not* by itself abort a caller's in-flight `send`/`recv` — see
    /// `send`/`recv`'s doc comments: those return promptly once the actor
    /// exits and drops its ends of the channel, which callers (e.g.
    /// `yadorilink-sync-core`'s `PeerSyncSession::run`) already treat as
    /// "the session ended."
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
    }

    /// Whether [`revoke`](Self::revoke) has been called on this channel.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Relaxed)
    }
}

fn path_to_u8(p: PathKind) -> u8 {
    match p {
        PathKind::Relay => 0,
        PathKind::Direct => 1,
    }
}

fn u8_to_path(v: u8) -> PathKind {
    match v {
        1 => PathKind::Direct,
        _ => PathKind::Relay,
    }
}

struct RelayRoute {
    hub: Arc<RelayHub>,
    inbound: mpsc::Receiver<Vec<u8>>,
}

struct ActorState {
    tunn: WgTunnel,
    relay: Option<RelayRoute>,
    peer_public_bytes: [u8; 32],
    direct_socket: Option<Arc<UdpSocket>>,
    /// All known direct candidates for this peer, raced concurrently until
    /// one is confirmed. Bounded at [`MAX_DIRECT_CANDIDATES`] and
    /// provenance-ranked (security hardening) — always insert via
    /// [`insert_candidate`], never push directly, so the cap and eviction
    /// policy actually apply.
    direct_candidates: Vec<DirectCandidate>,
    /// The candidate that has actually answered, once one has. Once set,
    /// sends target only this address instead of racing the whole list.
    confirmed_direct_addr: Option<SocketAddr>,
    /// reliability hardening: when the last datagram (of any kind, including a WireGuard
    /// keepalive or one that failed to decrypt) arrived on the direct
    /// socket. `None` means never — used to detect a gone-quiet direct
    /// path and fail back to relay.
    last_direct_rx: Option<Instant>,
    outbound_rx: mpsc::Receiver<Bytes>,
    candidate_rx: mpsc::Receiver<SocketAddr>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    current_path: Arc<AtomicU8>,
    allow_direct: bool,
    allow_relay: bool,
    /// Mirrors [`PeerChannel::revoke`]'s doc comment — checked at the top
    /// of `handle_datagram` so a revoked channel refuses to process
    /// anything further, and mirrored from the same `Arc` the
    /// `PeerChannel` handle exposes so a caller's `revoke()` takes effect
    /// without a round trip through the actor's message channels.
    revoked: Arc<AtomicBool>,
    /// See [`PeerChannel::revoke`]'s doc comment on `shutdown`.
    shutdown: Arc<Notify>,
    udp_batching: UdpBatchingSupport,
    /// Shared with [`PeerChannel::enable_reliable_delivery`] — gates
    /// whether `handle_outbound_batch` wraps this device's own outbound
    /// sends. See that method's doc comment.
    reliable_enabled: Arc<AtomicBool>,
    /// Send-side sequence/unacked-buffer/RTT state, owned solely by this
    /// actor task (see `reliable.rs`).
    reliable_send: ReliableSend,
    /// Receive-side dedup/ack state, owned solely by this actor task
    /// (see `reliable.rs`).
    reliable_recv: ReliableRecv,
}

async fn run_actor(mut state: ActorState) {
    tracing::debug!(
        mode = ?state.udp_batching.mode(),
        kernel_batching = state.udp_batching.uses_kernel_batching(),
        "direct UDP batching support detected"
    );
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    let mut direct_probe = tokio::time::interval(DIRECT_PROBE_INTERVAL);
    let mut reliable_tick = tokio::time::interval(RELIABLE_CHECK_INTERVAL);
    let mut direct_recv_buf = vec![0u8; MAX_WIREGUARD_DATAGRAM_LEN];

    loop {
        tokio::select! {
            biased;

            // Checked first (this `select!` is `biased`) so a revocation
            // wins over any datagram/tick that happens to be ready in
            // the same poll, and the actor exits (running the same
            // relay-unregister cleanup as any other loop exit below)
            // without waiting out `TICK_INTERVAL`.
            _ = state.shutdown.notified() => {
                tracing::info!(
                    peer = %hex::encode(state.peer_public_bytes),
                    "peer channel revoked; tearing down"
                );
                break;
            }

            Some(payload) = state.outbound_rx.recv() => {
                handle_outbound_batch(&mut state, payload).await;
            }

            Some(addr) = state.candidate_rx.recv() => {
                // Runtime-added candidates (`add_direct_candidate`) are
                // local-discovery-sourced (see the doc comment on that
                // method) — lowest provenance, subject to eviction first
                // under security hardening's cap.
                if state.allow_direct {
                    insert_candidate(
                        &mut state.direct_candidates,
                        state.confirmed_direct_addr,
                        addr,
                        CandidateSource::Discovery,
                    );
                }
            }

            Some(payload) = recv_relay(&mut state.relay) => {
                handle_datagram(&mut state, &payload, PathKind::Relay, None).await;
            }

            Ok((n, from)) = recv_direct(&state.direct_socket, &mut direct_recv_buf), if state.direct_socket.is_some() => {
                state.last_direct_rx = Some(Instant::now());
                let datagram = direct_recv_buf[..n].to_vec();
                handle_datagram(&mut state, &datagram, PathKind::Direct, Some(from)).await;
                drain_ready_direct_datagrams(&mut state, &mut direct_recv_buf).await;
            }

            _ = tick.tick() => {
                if let Some(dgram) = state.tunn.tick() {
                    send_batch_via_current_path(&state, vec![dgram]).await;
                }
                evaluate_direct_liveness(&mut state);
            }

            // Gated so a connection that never negotiates reliable
            // delivery (an un-upgraded peer, or — as found investigating
            // seed 3298840590 — a lost/never-completed `ClusterConfig`
            // handshake) pays zero recurring
            // scheduling cost from this timer, keeping its behavior
            // identical to before this layer existed. `has_pending_ack`
            // (not `reliable_enabled` alone) covers the asymmetric window
            // where this device hasn't enabled its own sends yet but has
            // already received a reliable-framed DATA frame from a peer
            // that has — that ack must still go out (see `reliable_send_
            // due`'s own doc comment).
            _ = reliable_tick.tick(), if state.reliable_enabled.load(Ordering::Relaxed) || state.reliable_recv.has_pending_ack() => {
                reliable_send_due(&mut state).await;
            }

            _ = direct_probe.tick(), if state.allow_direct && !state.direct_candidates.is_empty() => {
                // Tasks 4.5/4.6/4.10: race every unconfirmed candidate
                // concurrently; once confirmed, this just keeps that one
                // path alive and still re-probes the others in case a
                // better (e.g. newly-reachable local) one appears.
                if let Some(socket) = &state.direct_socket {
                    if let Some(probe) = state.tunn.probe() {
                        for candidate in &state.direct_candidates {
                            let _ = state
                                .udp_batching
                                .send_batch(socket, std::slice::from_ref(&probe), candidate.addr)
                                .await;
                        }
                    }
                }
            }

            else => break,
        }
    }

    if let Some(relay) = &state.relay {
        relay.hub.unregister(&state.peer_public_bytes);
    }
}

async fn handle_outbound_batch(state: &mut ActorState, first_payload: Bytes) {
    let mut payloads = Vec::with_capacity(MAX_OUTBOUND_BATCH);
    payloads.push(first_payload);
    while payloads.len() < MAX_OUTBOUND_BATCH {
        match state.outbound_rx.try_recv() {
            Ok(payload) => payloads.push(payload),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    let mut datagrams = Vec::new();
    for payload in payloads {
        // Wrap with the seq/ack framing once this device has confirmed
        // the peer supports it (`reliable_enabled`, flipped by
        // `PeerChannel::enable_reliable_delivery`).
        // If the unacked buffer is already at `ReliableSend::MAX_UNACKED`
        // (a sustained-loss/overload edge case, not the common path),
        // this one message is sent unwrapped rather than blocking the
        // whole actor loop waiting for space — a documented, deliberate
        // simplification: true cross-task backpressure would need a
        // permit shared back to `PeerChannel::send`'s callers, follow-up
        // if the sweep shows this firing in practice.
        let framed: Bytes =
            if state.reliable_enabled.load(Ordering::Relaxed) && !state.reliable_send.is_full() {
                let (ack_lo, ack_bits) = state.reliable_recv.current_ack();
                state.reliable_recv.take_ack_dirty();
                state.reliable_send.wrap_and_track(&payload, ack_lo, ack_bits)
            } else {
                payload
            };
        match state.tunn.encrypt_message(&framed) {
            Ok(encrypted) => {
                datagrams.extend(encrypted);
            }
            Err(e) => tracing::warn!(error = %e, "failed to encrypt outbound message"),
        }
    }

    send_batch_via_current_path(state, datagrams).await;
}

/// Checked every `RELIABLE_CHECK_INTERVAL` (`run_actor`'s `reliable_tick`
/// branch). Sends a standalone ack frame when one is due — deliberately
/// independent of `state.reliable_enabled`
/// (see `PeerChannel::enable_reliable_delivery`'s doc comment and `reliable
/// .rs`'s `ReliableRecv::ack_dirty` doc comment): this device may have
/// received reliable-framed DATA frames from a peer that has confirmed
/// support before this device's own `ClusterConfig` round-trip completes,
/// and that peer still needs its acks regardless of which direction has
/// switched to sending wrapped frames first. Also retransmits any unacked
/// outbound frame past its RTT-adaptive deadline.
async fn reliable_send_due(state: &mut ActorState) {
    let mut frames: Vec<Bytes> = Vec::new();
    if state.reliable_recv.take_ack_dirty() {
        let (ack_lo, ack_bits) = state.reliable_recv.current_ack();
        frames.push(encode_ack_frame(ack_lo, ack_bits));
    }
    frames.extend(state.reliable_send.due_retransmits());
    if frames.is_empty() {
        return;
    }

    let mut datagrams = Vec::new();
    for frame in &frames {
        match state.tunn.encrypt_message(frame) {
            Ok(encrypted) => datagrams.extend(encrypted),
            Err(e) => tracing::warn!(error = %e, "failed to encrypt reliable-delivery frame"),
        }
    }
    send_batch_via_current_path(state, datagrams).await;
}

async fn drain_ready_direct_datagrams(state: &mut ActorState, recv_buf: &mut [u8]) {
    let Some(socket) = state.direct_socket.clone() else { return };
    match state
        .udp_batching
        .try_recv_batch(&socket, MAX_DIRECT_RECV_BATCH.saturating_sub(1), recv_buf.len())
        .await
    {
        Ok(datagrams) => {
            for datagram in datagrams {
                state.last_direct_rx = Some(Instant::now());
                handle_datagram(state, &datagram.bytes, PathKind::Direct, Some(datagram.from))
                    .await;
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(err) => {
            tracing::debug!(error = %err, "failed to drain ready direct UDP datagram batch");
        }
    }
}

fn spawn_actor(state: ActorState) {
    let peer = state.peer_public_bytes;
    let actor = tokio::spawn(run_actor(state));
    tokio::spawn(async move {
        if let Err(err) = actor.await {
            tracing::error!(peer = %hex::encode(peer), error = %err, "peer channel actor task panicked");
        }
    });
}

async fn recv_relay(relay: &mut Option<RelayRoute>) -> Option<Vec<u8>> {
    match relay {
        Some(r) => r.inbound.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_direct(
    socket: &Option<Arc<UdpSocket>>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn handle_datagram(
    state: &mut ActorState,
    datagram: &[u8],
    via: PathKind,
    from_addr: Option<SocketAddr>,
) {
    // A revoked channel refuses to process anything further, including
    // a datagram that would otherwise be a perfectly valid WireGuard
    // handshake initiation from
    // this same (now-unauthorized) peer key — refusal doesn't depend on
    // whether the loop has already noticed `shutdown` and broken out yet.
    if state.revoked.load(Ordering::Relaxed) {
        tracing::debug!(
            peer = %hex::encode(state.peer_public_bytes),
            ?via,
            "dropping datagram on a revoked peer channel"
        );
        return;
    }

    let result = state.tunn.handle_incoming(datagram);
    // Captured before `result.messages`/`result.to_send` are moved out by
    // the loops below — security hardening's confirm/upgrade gate needs this.
    let authenticated = result.authenticated;

    if !result.to_send.is_empty() {
        send_batch_via(state, result.to_send, via).await;
    }

    for message in result.messages {
        // Every decrypted plaintext message is checked against the
        // marker-byte framing regardless of this device's own
        // `reliable_enabled` state — receiving is always
        // format-agnostic (see `reliable.rs`'s module doc comment), so a
        // peer that has started sending wrapped frames is understood
        // immediately, even before this device's own `ClusterConfig`
        // round-trip confirms mutual support.
        match decode_frame(Bytes::from(message)) {
            DecodedFrame::Legacy(bytes) => {
                let _ = state.inbound_tx.send(bytes.to_vec()).await;
            }
            DecodedFrame::Ack { ack_lo, ack_bits } => {
                state.reliable_send.on_ack(ack_lo, ack_bits);
            }
            DecodedFrame::Data { seq, ack_lo, ack_bits, payload } => {
                state.reliable_send.on_ack(ack_lo, ack_bits);
                if state.reliable_recv.observe(seq) {
                    let _ = state.inbound_tx.send(payload.to_vec()).await;
                }
            }
        }
    }

    // security hardening: a direct-socket datagram may confirm a candidate and
    // upgrade the path only when it was cryptographically meaningful
    // (`authenticated` — decrypted WireGuard data, or an authenticated
    // handshake transition), never on mere receipt. Before this fix the
    // block below ran for *any* inbound datagram, so a single junk UDP
    // packet from an arbitrary address — no keys, MAC, or handshake
    // required — was enough to hijack path selection and blackhole real
    // traffic. `evaluate_direct_liveness` (driven off the actor's regular
    // tick) is unchanged and still detects the inverse case: a confirmed
    // Direct path that's gone quiet, failing back to Relay.
    if via == PathKind::Direct && state.allow_direct && authenticated {
        // hardening: only ever confirm an address that is
        // already a known candidate (coordination- or discovery-supplied)
        // — authenticated traffic alone, from an address we never
        // solicited or learned of, isn't enough to adopt as the direct
        // endpoint. If we can't confirm this datagram's address, don't
        // switch the path either: switching away from Relay only makes
        // sense together with (or after) an actual confirmed candidate.
        let now_direct = if state.confirmed_direct_addr.is_some() {
            true
        } else if let Some(addr) =
            from_addr.filter(|a| state.direct_candidates.iter().any(|c| c.addr == *a))
        {
            tracing::debug!(%addr, "direct candidate confirmed");
            state.confirmed_direct_addr = Some(addr);
            true
        } else {
            if let Some(addr) = from_addr {
                tracing::debug!(
                    %addr,
                    "authenticated direct traffic from an address that is not a known candidate; not confirming"
                );
            }
            false
        };

        if now_direct {
            let previous = u8_to_path(
                state.current_path.swap(path_to_u8(PathKind::Direct), Ordering::Relaxed),
            );
            if previous != PathKind::Direct {
                tracing::info!(
                    peer = %hex::encode(state.peer_public_bytes),
                    "path transition: relay -> direct"
                );
            }
        }
    }
}

/// Inserts `addr` into `candidates` if not already present, enforcing
/// [`MAX_DIRECT_CANDIDATES`] (security hardening): when full, evicts the oldest
/// `Discovery`-sourced candidate that isn't `confirmed`, and refuses the
/// insert entirely if nothing is safely evictable (every current entry is
/// either `confirmed` or `Coordination`-sourced) — a confirmed or
/// coordination-supplied candidate is never displaced to admit a
/// discovery-supplied one.
fn insert_candidate(
    candidates: &mut Vec<DirectCandidate>,
    confirmed: Option<SocketAddr>,
    addr: SocketAddr,
    source: CandidateSource,
) {
    if candidates.iter().any(|c| c.addr == addr) {
        return;
    }

    if candidates.len() >= MAX_DIRECT_CANDIDATES {
        let evictable = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.source == CandidateSource::Discovery && Some(c.addr) != confirmed)
            .min_by_key(|(_, c)| c.added_at)
            .map(|(idx, _)| idx);

        match evictable {
            Some(idx) => {
                let evicted = candidates.remove(idx);
                tracing::debug!(
                    evicted = %evicted.addr,
                    %addr,
                    "direct candidate cap reached; evicting oldest discovery-supplied candidate"
                );
            }
            None => {
                tracing::debug!(
                    %addr,
                    ?source,
                    "direct candidate list is full of confirmed/coordination-supplied entries; dropping new candidate"
                );
                return;
            }
        }
    }

    tracing::debug!(%addr, ?source, "adding direct candidate");
    candidates.push(DirectCandidate { addr, source, added_at: Instant::now() });
}

/// reliability hardening: if this channel is currently on the Direct path but hasn't
/// heard anything on the direct socket in `DIRECT_LIVENESS_TIMEOUT`, the
/// path is presumed dead (a NAT rebinding, a dropped local link, etc.)
/// and the channel fails back to Relay so sync keeps moving instead of
/// silently stalling forever on a one-way-dead direct path — matching
/// `handle_datagram`'s Relay->Direct upgrade with the missing inverse
/// transition. Only applies when a relay fallback actually exists
/// (`allow_relay`); `DirectOnly` channels have nowhere to fail back to.
fn evaluate_direct_liveness(state: &mut ActorState) {
    if !state.allow_relay {
        return;
    }
    if u8_to_path(state.current_path.load(Ordering::Relaxed)) != PathKind::Direct {
        return;
    }
    let Some(last_rx) = state.last_direct_rx else { return };
    if last_rx.elapsed() < DIRECT_LIVENESS_TIMEOUT {
        return;
    }

    tracing::warn!(
        peer = %hex::encode(state.peer_public_bytes),
        elapsed_secs = last_rx.elapsed().as_secs(),
        "direct path liveness lost (missed keepalives); path transition: direct -> relay"
    );
    state.current_path.store(path_to_u8(PathKind::Relay), Ordering::Relaxed);
    // Forget the confirmed address so a later successful direct receive
    // re-confirms (and re-logs) the upgrade from scratch rather than
    // silently trusting a candidate that just proved unreliable.
    state.confirmed_direct_addr = None;
}

async fn send_batch_via_current_path(state: &ActorState, datagrams: Vec<Vec<u8>>) {
    let path = u8_to_path(state.current_path.load(Ordering::Relaxed));
    send_batch_via(state, datagrams, path).await;
}

async fn send_batch_via(state: &ActorState, datagrams: Vec<Vec<u8>>, path: PathKind) {
    if datagrams.is_empty() {
        return;
    }

    match path {
        PathKind::Relay if state.allow_relay => {
            if let Some(relay) = &state.relay {
                for dgram in datagrams {
                    let _ = relay.hub.send_forward(state.peer_public_bytes, dgram);
                }
            }
        }
        PathKind::Direct if state.allow_direct => {
            let Some(socket) = &state.direct_socket else { return };
            match state.confirmed_direct_addr {
                // Once a candidate has proven reachable, stop racing and
                // send only there.
                Some(addr) => {
                    let _ = state.udp_batching.send_batch(socket, &datagrams, addr).await;
                }
                // Not yet confirmed: race every candidate with this
                // datagram too, not just probes, so app data isn't stuck
                // waiting for a separate probe round-trip to finish first.
                None => {
                    for candidate in &state.direct_candidates {
                        let _ =
                            state.udp_batching.send_batch(socket, &datagrams, candidate.addr).await;
                    }
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal `ActorState` for exercising `evaluate_direct_liveness`
    /// in isolation, without standing up real sockets or a relay — `Instant`
    /// arithmetic simulates elapsed time instead of real sleeps, so these
    /// tests run instantly rather than waiting out `DIRECT_LIVENESS_TIMEOUT`.
    fn make_state(
        allow_relay: bool,
        initial_path: PathKind,
        last_direct_rx: Option<Instant>,
    ) -> ActorState {
        let local_secret = StaticSecret::from([1u8; 32]);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        let tunn = WgTunnel::new(local_secret, peer_public, 0);
        let (_outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(1);
        let (_candidate_tx, candidate_rx) = mpsc::channel::<SocketAddr>(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(1);
        ActorState {
            tunn,
            relay: None,
            peer_public_bytes: peer_public.to_bytes(),
            direct_socket: None,
            direct_candidates: vec![],
            confirmed_direct_addr: Some("127.0.0.1:41641".parse().unwrap()),
            last_direct_rx,
            outbound_rx,
            candidate_rx,
            inbound_tx,
            current_path: Arc::new(AtomicU8::new(path_to_u8(initial_path))),
            allow_direct: true,
            allow_relay,
            revoked: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
            udp_batching: UdpBatchingSupport::detect(),
            reliable_enabled: Arc::new(AtomicBool::new(false)),
            reliable_send: ReliableSend::new(),
            reliable_recv: ReliableRecv::new(),
        }
    }

    /// reliability hardening's core behavior: a Direct-path channel that's heard nothing
    /// on its direct socket in over `DIRECT_LIVENESS_TIMEOUT` fails back
    /// to Relay and forgets the stale confirmed address.
    #[test]
    fn stale_direct_path_fails_back_to_relay() {
        let mut state =
            make_state(true, PathKind::Direct, Some(Instant::now() - Duration::from_secs(25)));

        evaluate_direct_liveness(&mut state);

        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Relay);
        assert!(state.confirmed_direct_addr.is_none());
    }

    /// A Direct path that's still receiving traffic within the timeout
    /// must be left alone.
    #[test]
    fn fresh_direct_path_is_left_alone() {
        let mut state = make_state(true, PathKind::Direct, Some(Instant::now()));

        evaluate_direct_liveness(&mut state);

        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Direct);
        assert!(state.confirmed_direct_addr.is_some());
    }

    /// `DirectOnly` channels (`allow_relay == false`) have no relay to
    /// fail back to, so a stale direct path must not be forced to Relay
    /// (that would leave the channel with no usable path at all).
    #[test]
    fn direct_only_channel_never_fails_back_since_there_is_no_relay() {
        let mut state =
            make_state(false, PathKind::Direct, Some(Instant::now() - Duration::from_secs(999)));

        evaluate_direct_liveness(&mut state);

        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Direct);
    }

    /// A channel already on Relay has nothing to time out.
    #[test]
    fn relay_path_is_unaffected_by_liveness_check() {
        let mut state = make_state(true, PathKind::Relay, None);

        evaluate_direct_liveness(&mut state);

        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Relay);
    }

    /// Builds an `ActorState` for exercising `handle_datagram`'s
    /// security hardening confirm/upgrade gate directly: unconfirmed, starting on
    /// Relay, with `candidates` as the known direct-endpoint set. Uses the
    /// same fixed local/peer keypair as [`make_state`] so a real
    /// handshake initiation from a `WgTunnel` built with the mirrored
    /// keypair ([2u8; 32] local / [1u8; 32] peer, session index 1)
    /// validates against it.
    fn make_pre_confirm_state(candidates: Vec<DirectCandidate>) -> ActorState {
        let local_secret = StaticSecret::from([1u8; 32]);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        let tunn = WgTunnel::new(local_secret, peer_public, 0);
        let (_outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(1);
        let (_candidate_tx, candidate_rx) = mpsc::channel::<SocketAddr>(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(1);
        ActorState {
            tunn,
            relay: None,
            peer_public_bytes: peer_public.to_bytes(),
            direct_socket: None,
            direct_candidates: candidates,
            confirmed_direct_addr: None,
            last_direct_rx: None,
            outbound_rx,
            candidate_rx,
            inbound_tx,
            current_path: Arc::new(AtomicU8::new(path_to_u8(PathKind::Relay))),
            allow_direct: true,
            allow_relay: true,
            revoked: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
            udp_batching: UdpBatchingSupport::detect(),
            reliable_enabled: Arc::new(AtomicBool::new(false)),
            reliable_send: ReliableSend::new(),
            reliable_recv: ReliableRecv::new(),
        }
    }

    /// security hardening (the relevant behavior): a junk datagram — not a valid WireGuard
    /// packet at all, so it never decrypts or advances the handshake —
    /// arriving on the direct socket from a *known* candidate address
    /// must not confirm that candidate or switch the path to Direct.
    /// Using a known candidate address isolates this test to the
    /// authentication gate itself (the relevant behavior), separately from the
    /// task-1.2 known-candidate check exercised below.
    #[tokio::test]
    async fn junk_datagram_does_not_confirm_or_switch_direct_path() {
        let attacker_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        let mut state = make_pre_confirm_state(vec![DirectCandidate {
            addr: attacker_addr,
            source: CandidateSource::Coordination,
            added_at: Instant::now(),
        }]);

        handle_datagram(&mut state, &[0xAAu8; 200], PathKind::Direct, Some(attacker_addr)).await;

        assert!(state.confirmed_direct_addr.is_none());
        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Relay);
    }

    /// security hardening (the relevant behavior hardening): authenticated-looking gating
    /// alone isn't tested here — this proves that even if a datagram
    /// *did* decrypt, an address that isn't a known candidate still can't
    /// be confirmed. Regression-tests against accidentally dropping the
    /// candidate-membership check while fixing security hardening.
    #[tokio::test]
    async fn authenticated_traffic_from_unknown_address_does_not_confirm() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let unlisted_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        // No candidates at all — `unlisted_addr` is not among them.
        let mut state = make_pre_confirm_state(vec![]);

        handle_datagram(&mut state, &init, PathKind::Direct, Some(unlisted_addr)).await;

        assert!(state.confirmed_direct_addr.is_none());
        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Relay);
    }

    /// security hardening / reliability hardening combined (the relevant behavior ): after a
    /// spoofed junk datagram is rejected, the channel must still be
    /// routable over Relay — no blackhole. Re-sending junk repeatedly
    /// (the exploit's "just re-send every 20s") must not eventually
    /// succeed either, and `send_via_current_path` (the relevant behavior send path)
    /// still reads `current_path`, which this proves stays `Relay`.
    #[tokio::test]
    async fn spoofed_junk_datagram_leaves_channel_routable_over_relay() {
        let attacker_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();
        let mut state = make_pre_confirm_state(vec![DirectCandidate {
            addr: attacker_addr,
            source: CandidateSource::Coordination,
            added_at: Instant::now(),
        }]);

        for _ in 0..5 {
            handle_datagram(&mut state, &[0xAAu8; 200], PathKind::Direct, Some(attacker_addr))
                .await;
        }

        assert!(state.confirmed_direct_addr.is_none());
        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Relay);
        assert!(state.allow_relay, "relay fallback must remain available");
    }

    /// Positive control for the two tests above (): real
    /// WireGuard traffic from the correct peer (a genuine handshake
    /// initiation) at a known candidate address *does* confirm and
    /// upgrade the path — proving the security hardening gate distinguishes junk
    /// from authenticated traffic rather than simply never confirming
    /// anything, i.e. the legitimate relay -> direct upgrade still works.
    #[tokio::test]
    async fn authenticated_handshake_confirms_and_upgrades_direct_path() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        // Simulates the real peer's side of the handshake, using the
        // mirror of `make_pre_confirm_state`'s fixed keypair.
        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        let mut state = make_pre_confirm_state(vec![DirectCandidate {
            addr: peer_addr,
            source: CandidateSource::Coordination,
            added_at: Instant::now(),
        }]);

        handle_datagram(&mut state, &init, PathKind::Direct, Some(peer_addr)).await;

        assert_eq!(state.confirmed_direct_addr, Some(peer_addr));
        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Direct);
    }

    /// security hardening (the relevant behavior): a flood of distinct discovery-sourced
    /// candidates never grows the list past `MAX_DIRECT_CANDIDATES`, and
    /// confirmed / coordination-supplied candidates are never evicted to
    /// make room for a discovery-supplied one.
    #[test]
    fn direct_candidate_list_is_bounded_and_protects_high_provenance_entries() {
        let mut candidates: Vec<DirectCandidate> = Vec::new();

        // A few coordination-plane-supplied candidates (e.g. LAN
        // interfaces plus a relay-observed public address).
        let coordination_addrs: Vec<SocketAddr> =
            (0..3).map(|i| format!("10.0.0.{i}:41641").parse().unwrap()).collect();
        for addr in &coordination_addrs {
            insert_candidate(&mut candidates, None, *addr, CandidateSource::Coordination);
        }

        // A discovery-sourced candidate that has since been confirmed —
        // must survive eviction pressure just like a coordination one.
        let confirmed_addr: SocketAddr = "10.0.1.1:41641".parse().unwrap();
        insert_candidate(&mut candidates, None, confirmed_addr, CandidateSource::Discovery);
        let confirmed = Some(confirmed_addr);

        // An attacker who knows the peer's public key mints far more
        // distinct `(key, addr)` pairs than the cap allows by varying the
        // announced port (security hardening's exploit).
        for port in 0..64u16 {
            let addr: SocketAddr = format!("10.0.2.1:{}", 50_000 + port).parse().unwrap();
            insert_candidate(&mut candidates, confirmed, addr, CandidateSource::Discovery);
        }

        assert_eq!(candidates.len(), MAX_DIRECT_CANDIDATES);
        for addr in &coordination_addrs {
            assert!(
                candidates.iter().any(|c| c.addr == *addr),
                "coordination-supplied candidate {addr} was evicted by a discovery flood"
            );
        }
        assert!(
            candidates.iter().any(|c| c.addr == confirmed_addr),
            "confirmed candidate was evicted by a discovery flood"
        );
    }

    /// A discovery flood that arrives once every slot is already
    /// protected (confirmed or coordination-supplied) simply can't get
    /// in — proving `insert_candidate` never silently exceeds the cap
    /// even when nothing is evictable, rather than e.g. falling back to
    /// evicting a protected entry.
    #[test]
    fn insert_candidate_refuses_new_entries_when_nothing_is_evictable() {
        let mut candidates: Vec<DirectCandidate> = Vec::new();
        let protected_addrs: Vec<SocketAddr> = (0..MAX_DIRECT_CANDIDATES)
            .map(|i| format!("10.0.0.{i}:41641").parse().unwrap())
            .collect();
        for addr in &protected_addrs {
            insert_candidate(&mut candidates, None, *addr, CandidateSource::Coordination);
        }
        assert_eq!(candidates.len(), MAX_DIRECT_CANDIDATES);

        let flood_addr: SocketAddr = "10.0.9.9:9999".parse().unwrap();
        insert_candidate(&mut candidates, None, flood_addr, CandidateSource::Discovery);

        assert_eq!(candidates.len(), MAX_DIRECT_CANDIDATES);
        assert!(!candidates.iter().any(|c| c.addr == flood_addr));
        for addr in &protected_addrs {
            assert!(candidates.iter().any(|c| c.addr == *addr));
        }
    }

    // --- Diff logic tests -------------------------------------------

    fn snapshot(entries: &[(&str, &[&str])]) -> NetmapSnapshot {
        entries
            .iter()
            .map(|(device_id, groups)| {
                (device_id.to_string(), groups.iter().map(|g| g.to_string()).collect())
            })
            .collect()
    }

    /// the relevant behavior: a device that disappears from the netmap entirely
    /// (D3's whole-device revocation, e.g. `device remove`, or a `share
    /// revoke` of a pair's only shared group) is classified as a removed
    /// device, not a removed group edge — even though, from a pure
    /// group-set-arithmetic point of view, "lost its only group" and
    /// "lost the device entirely" look similar; the diff must key off
    /// device presence in `current`, not just group-set difference.
    #[test]
    fn device_absent_from_current_netmap_is_classified_as_removed_device() {
        let previous =
            snapshot(&[("device-a", &["group-1", "group-2"]), ("device-b", &["group-1"])]);
        let current = snapshot(&[("device-b", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
        assert!(
            diff.removed_group_edges.is_empty(),
            "a wholly-removed device must not also be reported as a group-edge removal: {:?}",
            diff.removed_group_edges
        );
    }

    /// the relevant behavior: a device that's still present in the current netmap,
    /// but with fewer shared groups than before, is a group-edge removal
    /// (D3's narrower case, `share revoke` while another group is still
    /// shared) — the device itself must not appear in `removed_devices`,
    /// since the tunnel is meant to stay up.
    #[test]
    fn device_present_with_fewer_groups_is_classified_as_removed_group_edge() {
        let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
        let current = snapshot(&[("device-a", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(
            diff.removed_devices.is_empty(),
            "a device that still shares another group must not be torn down: {:?}",
            diff.removed_devices
        );
        assert_eq!(diff.removed_group_edges, vec![("device-a".to_string(), "group-2".to_string())]);
    }

    /// A snapshot with no changes at all (including a peer's group list
    /// merely coming back in a different order, since `NetmapSnapshot`
    /// values are `HashSet`s) produces an empty diff.
    #[test]
    fn unchanged_netmap_produces_no_diff() {
        let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
        let current = snapshot(&[("device-a", &["group-2", "group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(diff.removed_devices.is_empty());
        assert!(diff.removed_group_edges.is_empty());
    }

    /// A brand-new peer (present in `current`, absent from `previous`) is
    /// an addition, not a removal — `diff_netmap` only ever reports what
    /// disappeared.
    #[test]
    fn newly_added_peer_produces_no_diff_entries() {
        let previous = snapshot(&[]);
        let current = snapshot(&[("device-a", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert!(diff.removed_devices.is_empty());
        assert!(diff.removed_group_edges.is_empty());
    }

    /// A single netmap update can carry both kinds of removal at once
    /// (e.g. one `device remove` and one unrelated `share revoke` landing
    /// in the same pushed snapshot) — both must be classified correctly
    /// in the same diff.
    #[test]
    fn mixed_update_classifies_each_device_independently() {
        let previous = snapshot(&[
            ("device-a", &["group-1"]),            // fully removed below
            ("device-b", &["group-1", "group-2"]), // loses group-2 only
            ("device-c", &["group-1"]),            // unchanged
        ]);
        let current = snapshot(&[("device-b", &["group-1"]), ("device-c", &["group-1"])]);

        let diff = diff_netmap(&previous, &current);

        assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
        assert_eq!(diff.removed_group_edges, vec![("device-b".to_string(), "group-2".to_string())]);
    }

    // --- Revocation tests ---------------------------------------------

    /// `revoke()` wakes the actor loop to exit (rather than the
    /// loop only ever exiting via the fallthrough `else` arm, which never
    /// fires on its own here — see `run_actor`'s `shutdown` branch).
    #[tokio::test]
    async fn revoke_wakes_the_actor_loop_to_exit() {
        let state = make_pre_confirm_state(vec![]);
        let channel_revoked = state.revoked.clone();
        let channel_shutdown = state.shutdown.clone();

        // Simulates `PeerChannel::revoke()` without needing a full
        // `PeerChannel::connect()` (which would need a real relay/socket).
        channel_revoked.store(true, Ordering::Relaxed);
        channel_shutdown.notify_one();

        let notified = state.shutdown.notified();
        tokio::time::timeout(Duration::from_millis(100), notified)
            .await
            .expect("a revoked channel's shutdown Notify must already be signaled");
        assert!(state.revoked.load(Ordering::Relaxed));
    }

    /// the relevant behavior core behavior: once a channel is revoked,
    /// `handle_datagram` refuses to process *any* further datagram — this
    /// specifically includes what would otherwise be a completely valid
    /// WireGuard handshake initiation from the correct (now-revoked) peer
    /// key, proving refusal isn't merely "drop garbage" but an explicit
    /// authorization gate independent of whether the datagram is
    /// cryptographically legitimate.
    #[tokio::test]
    async fn revoked_channel_refuses_a_valid_handshake_attempt_from_the_same_peer() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        let mut state = make_pre_confirm_state(vec![DirectCandidate {
            addr: peer_addr,
            source: CandidateSource::Coordination,
            added_at: Instant::now(),
        }]);
        state.revoked.store(true, Ordering::Relaxed);

        handle_datagram(&mut state, &init, PathKind::Direct, Some(peer_addr)).await;

        assert!(
            state.confirmed_direct_addr.is_none(),
            "a revoked peer's handshake must not confirm a direct candidate"
        );
        assert_eq!(
            u8_to_path(state.current_path.load(Ordering::Relaxed)),
            PathKind::Relay,
            "a revoked peer's handshake must not upgrade the path"
        );
    }

    /// Positive control for the test above: the *same* handshake
    /// initiation, against an otherwise-identical, non-revoked channel,
    /// does confirm and upgrade — proving the refusal above comes from
    /// the revocation check, not from some other reason the handshake
    /// failed to land.
    #[tokio::test]
    async fn non_revoked_channel_still_accepts_the_same_handshake_attempt() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_addr: SocketAddr = "203.0.113.9:41641".parse().unwrap();

        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        let mut state = make_pre_confirm_state(vec![DirectCandidate {
            addr: peer_addr,
            source: CandidateSource::Coordination,
            added_at: Instant::now(),
        }]);
        assert!(!state.revoked.load(Ordering::Relaxed));

        handle_datagram(&mut state, &init, PathKind::Direct, Some(peer_addr)).await;

        assert_eq!(state.confirmed_direct_addr, Some(peer_addr));
        assert_eq!(u8_to_path(state.current_path.load(Ordering::Relaxed)), PathKind::Direct);
    }
}
