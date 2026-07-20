//! Per-peer channel: `yadorilink-sync-core` sends/receives plain
//! application messages here and never knows which of possibly several
//! direct candidates (LAN, NAT-traversed public, or one learned later via
//! local broadcast discovery) ended up carrying the WireGuard session.
//!
//! Sync data travels exclusively over direct peer-to-peer paths this
//! device establishes itself; there is no operator-run forwarding path. A
//! peer for which no candidate ever yields an authenticated path is
//! reported as [`PeerReachability::Unreachable`] with a failure category
//! rather than being routed anywhere else.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use tokio::sync::{mpsc, watch, Mutex, Notify};

use crate::error::TransportError;
use crate::nat::CandidateClass;
use crate::reliable::{decode_frame, encode_ack_frame, DecodedFrame, ReliableRecv, ReliableSend};
use crate::supervise::BackoffConfig;
use crate::transport_hub::{DatagramKind, InboundDatagram, TransportHub};
use crate::tunn_wrapper::WgTunnel;

const TICK_INTERVAL: Duration = Duration::from_millis(500);
/// How often direct candidates are (re-)probed: all of them concurrently
/// until one is confirmed, then just the confirmed
/// one as a keepalive/liveness check.
const DIRECT_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// How long a confirmed direct path can go without receiving *any*
/// direct-socket traffic before it's treated as dead. WireGuard itself
/// sends a keepalive roughly every 25s when otherwise idle
/// (`tunn_wrapper::KEEPALIVE_SECS`), and this actor additionally re-probes
/// every `DIRECT_PROBE_INTERVAL` (5s) — four missed probe cycles is
/// comfortably past a single dropped keepalive/probe round-trip (avoiding
/// flapping on a single lost UDP packet) while still detecting a genuine
/// path loss well inside a user-noticeable stall. On loss the channel
/// re-races its candidates (re-traversal) rather than stalling.
const DIRECT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a full candidate race runs without any candidate producing an
/// authenticated path before the peer is declared unreachable. Same span
/// as [`DIRECT_LIVENESS_TIMEOUT`]: roughly four `DIRECT_PROBE_INTERVAL`
/// rounds, long enough to ride out transient loss on an otherwise-workable
/// candidate but short enough that a genuinely unreachable peer surfaces
/// quickly.
const CANDIDATE_RACE_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTBOUND_BATCH: usize = 16;
const MAX_DIRECT_RECV_BATCH: usize = 16;
/// How often the actor checks for a due standalone ack and/or a due
/// retransmit (`ReliableSend::due_retransmits`,
/// `ReliableRecv::take_ack_dirty`). Well under the RTT-adaptive retransmit
/// timeout itself (`reliable.rs`'s `RttEstimator`, 100ms-5s) so this
/// interval never meaningfully delays a retransmit past its computed
/// deadline — it just bounds how finely that deadline is checked.
const RELIABLE_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// fixed cap on how many direct-endpoint candidates a single
/// `PeerChannel` will hold at once. An attacker who knows an authorized
/// peer's public key can mint an unbounded number of distinct
/// `(key, addr)` local-discovery candidates (per-source rate
/// limit is ~16/10s but has no upstream cap); this bounds the resulting
/// memory and the per-cycle probe/send fan-out regardless. Comfortably
/// fits the realistic legitimate set (a handful of LAN interfaces plus a
/// public address) while still being small.
const MAX_DIRECT_CANDIDATES: usize = 8;

// --- Netmap-diff logic ----------------------------------------------
//
// The coordination plane's netmap subscription always pushes a *full*
// netmap snapshot, never a delta. So the client side
// (`yadorilink-daemon`'s `peer_orchestrator`) is the one that must
// diff each new snapshot against whatever it held before, to find what
// was revoked. This module owns that pure diff logic; `peer_orchestrator`
// owns holding the "previous" snapshot across updates and acting on the
// result (tearing down `PeerChannel`s via [`PeerChannel::revoke`]).

/// One netmap snapshot, keyed by `device_id` (stable across calls per
/// device — the coordination plane's device registration only ever
/// inserts a fresh device or marks one removed, never rotates a key under an
/// existing `device_id`) mapping to the set of folder groups this device
/// and the peer currently share.
///
/// A `HashSet`, not a `Vec`, deliberately: the coordination plane does not
/// guarantee a stable order for a peer's `shared_group_ids`, so the same
/// peer's group list can
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
    /// from the snapshot *is* the signal — this tears its
    /// `PeerChannel` down entirely for each of these.
    pub removed_devices: Vec<String>,
    /// `(device_id, group_id)` pairs present in `previous` whose device is
    /// *still* present in `current` (so at least one other shared group
    /// remains) but that specific group is no longer shared (`share
    /// revoke` of one group among several) — a narrower case:
    /// the tunnel/`PeerChannel` stays up, only that group's sync activity
    /// stops (enforced by `yadorilink-sync-core`'s per-request
    /// authorization checks).
    pub removed_group_edges: Vec<(String, String)>,
}

/// Diffs `current` against `previous`, classifying every
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

/// Classifies a confirmed endpoint address into the coarsest
/// [`CandidateClass`] derivable from the address alone. Provenance that
/// would distinguish a port-mapped address from a server-reflexive one
/// isn't tracked per confirmed address, so any global-scope IPv4 endpoint
/// is reported as server-reflexive; global IPv6 as an IPv6 host; and any
/// private/loopback/link-local address as LAN.
fn classify_endpoint(addr: SocketAddr) -> CandidateClass {
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_loopback() || v4.is_link_local() {
                CandidateClass::Lan
            } else {
                CandidateClass::ServerReflexive
            }
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // fc00::/7 unique-local and fe80::/10 link-local are LAN-scoped,
            // as is loopback; any other global v6 address is a v6 host path.
            if v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                CandidateClass::Lan
            } else {
                CandidateClass::Ipv6Host
            }
        }
    }
}

/// Why a peer could not be reached after a full candidate race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCategory {
    /// No endpoint candidate is known at all (none from the netmap, none
    /// from local discovery).
    NoCandidates,
    /// Candidates were probed but stayed silent — no authenticated reply
    /// on any of them (typically endpoint-dependent-mapping NAT or CGNAT
    /// on both sides).
    NoResponse,
    /// Even LAN/STUN probes fail to leave the host — UDP is blocked
    /// outright. (Distinguished once the NAT-traversal suite lands; the
    /// state machine here never asserts it on its own yet.)
    UdpBlocked,
    /// The peer is reachable on the network but refused the handshake
    /// (netmap/key mismatch) — a distinct failure from network
    /// unreachability.
    HandshakeRefused,
}

/// Per-peer reachability, surfaced to the daemon via a `watch` channel
/// (see [`PeerChannel::reachability_watch`]) and mapped verbatim onto
/// IPC/status so the user sees a plain "cannot connect" (plus the failure
/// category) instead of a silently-forwarded session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// Candidates are being raced; `attempt` counts how many full races
    /// have already been exhausted for this peer.
    Connecting { attempt: u32 },
    /// An authenticated direct path is confirmed, over an endpoint of the
    /// given class.
    Connected { path: CandidateClass },
    /// Every known candidate was exhausted without an authenticated path.
    /// Bounded-backoff re-attempts continue; `next_retry` is when the next
    /// race is due (a newly learned candidate re-races immediately
    /// regardless).
    Unreachable { category: UnreachableCategory, next_retry: Instant },
}

/// Provenance of a learned direct-endpoint candidate: the
/// coordination plane is authenticated (its candidates come from the
/// peer's registered netmap, supplied once at `PeerChannel::connect`
/// time), whereas local network discovery (`local_discovery`, fed in at
/// runtime via `add_direct_candidate`/`candidate_rx`, see `src/lib.rs`) is
/// unauthenticated LAN broadcast traffic that anyone on the same network
/// segment can forge. Discovery-sourced candidates are always
/// evicted first when the candidate list is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

enum CandidateUpdate {
    Learned(SocketAddr),
    CoordinationSnapshot(Vec<SocketAddr>),
}

pub struct PeerChannel {
    outbound_tx: mpsc::Sender<Bytes>,
    inbound_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    reachability_rx: watch::Receiver<PeerReachability>,
    candidate_tx: mpsc::Sender<CandidateUpdate>,
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
    /// out and exit immediately on [`revoke`],
    /// rather than only on the next `TICK_INTERVAL` tick or once every
    /// `Arc<PeerChannel>` clone happens to be dropped (dropping the
    /// clones alone does not stop the actor — its `tick`/`direct_probe`
    /// intervals keep the `select!` loop alive independent of channel
    /// state).
    ///
    /// [`revoke`]: PeerChannel::revoke
    shutdown: Arc<Notify>,
    /// Shared with `ActorState` (same pattern as
    /// `revoked`). Starts `false`; flipped by
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
    /// Establishes a direct channel to a peer. `direct_candidates` are the
    /// peer's known endpoints (from the coordination plane's netmap,
    /// highest priority — typically LAN addresses — first). All candidates
    /// are raced concurrently rather than tried one at a time. An empty
    /// candidate set is not an error: the peer simply starts
    /// [`Unreachable`](PeerReachability::Unreachable) with category
    /// [`NoCandidates`](UnreachableCategory::NoCandidates) until one is
    /// learned via [`add_direct_candidate`](Self::add_direct_candidate).
    ///
    /// `shared` is this device's single long-lived UDP socket (see
    /// [`TransportHub`]); the channel neither binds nor owns a socket of
    /// its own. It registers under `session_index` in the shared socket's
    /// demultiplexer, and every send and receive for this peer travels over
    /// that one socket so the NAT candidates this device advertises describe
    /// the exact binding data flows on. `session_index` must be unique per
    /// live channel on the device — it is the high 24 bits of every WireGuard
    /// receiver index boringtun assigns this session, which is what the
    /// demultiplexer routes inbound datagrams by.
    pub async fn connect(
        local_secret: StaticSecret,
        peer_public: PublicKey,
        session_index: u32,
        direct_candidates: Vec<SocketAddr>,
        shared: Arc<TransportHub>,
    ) -> Result<Self, TransportError> {
        let peer_public_bytes = peer_public.to_bytes();

        // Register with the peer's known candidate addresses so the hub can
        // order handshake-initiation trials by source endpoint.
        let inbound_demux_rx = shared.register_channel(session_index, &direct_candidates);

        let tunn = WgTunnel::new(local_secret, peer_public, session_index);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(64);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(64);
        let (candidate_tx, candidate_rx) = mpsc::channel::<CandidateUpdate>(16);
        let revoked = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(Notify::new());
        let reliable_enabled = Arc::new(AtomicBool::new(false));

        // candidates supplied here come from the caller's
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

        let backoff = BackoffConfig::RECONNECT;
        let now = Instant::now();
        let (initial_reachability, attempt, race_started_at) = if bounded_candidates.is_empty() {
            (
                PeerReachability::Unreachable {
                    category: UnreachableCategory::NoCandidates,
                    next_retry: now + backoff.next(0),
                },
                1,
                None,
            )
        } else {
            (PeerReachability::Connecting { attempt: 0 }, 0, Some(now))
        };
        let (reachability_tx, reachability_rx) = watch::channel(initial_reachability);

        spawn_actor(ActorState {
            tunn,
            peer_public_bytes,
            shared,
            session_index,
            inbound_demux_rx,
            direct_candidates: bounded_candidates,
            confirmed_direct_addr: None,
            last_direct_rx: None,
            outbound_rx,
            candidate_rx,
            inbound_tx,
            reachability: initial_reachability,
            reachability_tx,
            backoff,
            attempt,
            race_started_at,
            revoked: revoked.clone(),
            shutdown: shutdown.clone(),
            reliable_enabled: reliable_enabled.clone(),
            reliable_send: ReliableSend::new(),
            reliable_recv: ReliableRecv::new(),
        });

        Ok(Self {
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            reachability_rx,
            candidate_tx,
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

    /// accepts anything cheaply convertible into `Bytes` (a `Vec<u8>`
    /// converts with no copy — `Bytes::from(Vec<u8>)` just takes ownership
    /// of the existing allocation) rather than requiring `Vec<u8>`
    /// specifically, so a caller that already holds a refcounted `Bytes`
    /// (or wants to hand the same encoded buffer to more than one
    /// destination) never has to materialize a fresh owned copy just to
    /// call this.
    pub async fn send(&self, payload: impl Into<Bytes>) -> Result<(), TransportError> {
        self.outbound_tx.send(payload.into()).await.map_err(|_| TransportError::ChannelClosed)
    }

    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.inbound_rx.lock().await.recv().await
    }

    /// This peer's current reachability. See
    /// [`reachability_watch`](Self::reachability_watch) for change-driven
    /// consumption.
    pub fn reachability(&self) -> PeerReachability {
        *self.reachability_rx.borrow()
    }

    /// A `watch` receiver that observes every reachability transition for
    /// this peer, for a status/orchestration consumer that wants to react
    /// to changes rather than poll [`reachability`](Self::reachability).
    pub fn reachability_watch(&self) -> watch::Receiver<PeerReachability> {
        self.reachability_rx.clone()
    }

    /// Adds a newly-learned direct candidate at runtime — e.g.
    /// one surfaced by local broadcast discovery after this channel was
    /// already established. If the peer is currently unreachable, this
    /// resets the retry backoff and re-races immediately.
    pub async fn add_direct_candidate(&self, addr: SocketAddr) {
        let _ = self.candidate_tx.send(CandidateUpdate::Learned(addr)).await;
    }

    /// Replaces only the coordination-plane-owned candidates while retaining
    /// locally discovered addresses. A full netmap is authoritative, so an
    /// endpoint omitted from the newer snapshot must stop being raced.
    pub async fn replace_coordination_candidates(&self, candidates: Vec<SocketAddr>) {
        let _ = self.candidate_tx.send(CandidateUpdate::CoordinationSnapshot(candidates)).await;
    }

    /// Tears this channel down in response to a whole-device revocation
    /// and, from this moment on, refuses to process any further
    /// datagram on this channel — including a subsequent WireGuard
    /// handshake attempt from this same peer's key, which is
    /// otherwise cryptographically indistinguishable from a legitimate
    /// reconnect attempt by an unrevoked peer.
    ///
    /// Marks the channel revoked immediately (synchronously, before this
    /// call returns) and wakes the actor loop to exit right away rather
    /// than waiting for its next tick. Idempotent and safe to call more
    /// than once, e.g. if a caller races a netmap update against a session
    /// that is already ending on its own.
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

struct ActorState {
    tunn: WgTunnel,
    peer_public_bytes: [u8; 32],
    /// This device's single transport hub. All sends for this peer go out over
    /// it, targeted at whichever candidate(s) are being raced or the one
    /// confirmed path.
    shared: Arc<TransportHub>,
    /// This channel's demux key, unregistered from the shared socket when the
    /// actor exits so the session index is freed and no stale routing remains.
    session_index: u32,
    /// Inbound datagrams the shared socket's demultiplexer routed to this
    /// channel — transport-data/handshake-response/cookie packets by receiver
    /// index, plus handshake-initiation probes offered to every channel.
    inbound_demux_rx: mpsc::Receiver<InboundDatagram>,
    /// All known direct candidates for this peer, raced concurrently until
    /// one is confirmed. Bounded at [`MAX_DIRECT_CANDIDATES`] and
    /// provenance-ranked — always insert via
    /// [`insert_candidate`], never push directly, so the cap and eviction
    /// policy actually apply.
    direct_candidates: Vec<DirectCandidate>,
    /// The candidate that has actually answered, once one has. Once set,
    /// sends target only this address instead of racing the whole list.
    confirmed_direct_addr: Option<SocketAddr>,
    /// when the last datagram (of any kind, including a WireGuard
    /// keepalive or one that failed to decrypt) arrived on the direct
    /// socket. `None` means never — used to detect a gone-quiet confirmed
    /// path and trigger re-traversal.
    last_direct_rx: Option<Instant>,
    outbound_rx: mpsc::Receiver<Bytes>,
    candidate_rx: mpsc::Receiver<CandidateUpdate>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// Actor-local mirror of the reachability published on
    /// `reachability_tx` — mutated by the transition helpers, then pushed
    /// to the watch channel via [`set_reachability`].
    reachability: PeerReachability,
    reachability_tx: watch::Sender<PeerReachability>,
    /// Backoff schedule for candidate-race re-attempts once a peer is
    /// unreachable (madsim-deterministic jitter — see `supervise.rs`).
    backoff: BackoffConfig,
    /// How many full candidate races have been exhausted for this peer;
    /// the backoff input and the `Connecting`/`Unreachable` attempt count.
    /// Reset to 0 whenever a path confirms or a fresh candidate is learned.
    attempt: u32,
    /// When the current `Connecting` candidate race began, for the
    /// [`CANDIDATE_RACE_TIMEOUT`] exhaustion check. `None` outside a race.
    race_started_at: Option<Instant>,
    /// Mirrors [`PeerChannel::revoke`]'s doc comment — checked at the top
    /// of `handle_datagram` so a revoked channel refuses to process
    /// anything further, and mirrored from the same `Arc` the
    /// `PeerChannel` handle exposes so a caller's `revoke` takes effect
    /// without a round trip through the actor's message channels.
    revoked: Arc<AtomicBool>,
    /// See [`PeerChannel::revoke`]'s doc comment on `shutdown`.
    shutdown: Arc<Notify>,
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
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    let mut direct_probe = tokio::time::interval(DIRECT_PROBE_INTERVAL);
    let mut reliable_tick = tokio::time::interval(RELIABLE_CHECK_INTERVAL);

    loop {
        tokio::select! {
            biased;

            // Checked first (this `select!` is `biased`) so a revocation
            // wins over any datagram/tick that happens to be ready in
            // the same poll, and the actor exits without waiting out
            // `TICK_INTERVAL`.
            _ = state.shutdown.notified() => {
                tracing::info!(
                    peer = %hex::encode(state.peer_public_bytes),
                    "peer channel revoked; tearing down"
                );
                break;
            }

            Some(inbound) = state.inbound_demux_rx.recv() => {
                handle_inbound(&mut state, inbound).await;
                drain_ready_direct_datagrams(&mut state).await;
            }

            Some(payload) = state.outbound_rx.recv() => {
                handle_outbound_batch(&mut state, payload).await;
            }

            Some(update) = state.candidate_rx.recv() => {
                match update {
                    CandidateUpdate::Learned(addr) => learn_candidate(&mut state, addr),
                    CandidateUpdate::CoordinationSnapshot(candidates) => {
                        replace_coordination_candidates(&mut state, candidates)
                    }
                }
            }

            _ = tick.tick() => {
                if let Some(dgram) = state.tunn.tick() {
                    send_batch_direct(&state, vec![dgram]).await;
                }
                evaluate_reachability(&mut state);
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

            _ = direct_probe.tick(), if should_probe(&state) => {
                // race every unconfirmed candidate
                // concurrently; once confirmed, this just keeps that one
                // path alive and still re-probes the others in case a
                // better (e.g. newly-reachable local) one appears. Gated
                // off while unreachable so a peer in backoff isn't probed
                // until its next scheduled race.
                if let Some(probe) = state.tunn.probe() {
                    for candidate in &state.direct_candidates {
                        let _ = state
                            .shared
                            .send_batch(std::slice::from_ref(&probe), candidate.addr)
                            .await;
                    }
                }
            }

            else => break,
        }
    }

    // Free the demux registration so the shared socket stops routing to a
    // torn-down channel and the session index can be reused.
    state.shared.unregister_channel(state.session_index);
}

/// Handles one demultiplexed inbound datagram, updating direct-path liveness.
/// A [`DatagramKind::Direct`] datagram was routed here by WireGuard receiver
/// index, so it unquestionably belongs to this channel and refreshes liveness
/// regardless of whether it decrypted (a keepalive that fails to decrypt still
/// proves the peer is sending to us on this path). A
/// [`DatagramKind::HandshakeProbe`] was offered to every channel, so it only
/// counts as ours — and only refreshes liveness — if it authenticated.
async fn handle_inbound(state: &mut ActorState, inbound: InboundDatagram) {
    let InboundDatagram { data, from, kind } = inbound;
    let authenticated = handle_datagram(state, &data, Some(from)).await;
    if kind == DatagramKind::Direct || authenticated {
        state.last_direct_rx = Some(Instant::now());
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

    send_batch_direct(state, datagrams).await;
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
    send_batch_direct(state, datagrams).await;
}

/// Drains any datagrams the demultiplexer has already queued for this channel
/// beyond the one that woke the actor, so a burst delivered between wakeups is
/// processed in one turn rather than one datagram per `select!` iteration.
/// Bounded so a sustained inbound flood cannot starve the rest of the loop.
async fn drain_ready_direct_datagrams(state: &mut ActorState) {
    for _ in 1..MAX_DIRECT_RECV_BATCH {
        match state.inbound_demux_rx.try_recv() {
            Ok(inbound) => handle_inbound(state, inbound).await,
            Err(_) => break,
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

/// Processes one datagram through the WireGuard tunnel and the reachability
/// confirm gate. Returns whether the datagram was cryptographically
/// authenticated (decrypted data or an authenticated handshake transition) —
/// the caller uses this to decide whether a handshake-initiation probe offered
/// to every channel actually belonged to this one.
async fn handle_datagram(
    state: &mut ActorState,
    datagram: &[u8],
    from_addr: Option<SocketAddr>,
) -> bool {
    // A revoked channel refuses to process anything further, including
    // a datagram that would otherwise be a perfectly valid WireGuard
    // handshake initiation from
    // this same (now-unauthorized) peer key — refusal doesn't depend on
    // whether the loop has already noticed `shutdown` and broken out yet.
    if state.revoked.load(Ordering::Relaxed) {
        tracing::debug!(
            peer = %hex::encode(state.peer_public_bytes),
            "dropping datagram on a revoked peer channel"
        );
        return false;
    }

    let result = state.tunn.handle_incoming(datagram);
    // Captured before `result.messages`/`result.to_send` are moved out by
    // the loops below — the confirm gate needs this.
    let authenticated = result.authenticated;

    if !result.to_send.is_empty() {
        send_batch_direct(state, result.to_send).await;
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

    // A direct-socket datagram may confirm a candidate and move the peer
    // to `Connected` only when it was cryptographically meaningful
    // (`authenticated` — decrypted WireGuard data, or an authenticated
    // handshake transition), never on mere receipt. Confirming on any
    // inbound datagram would let a single junk UDP packet from an
    // arbitrary address — no keys, MAC, or handshake required — hijack
    // path selection and blackhole real traffic.
    if authenticated && state.confirmed_direct_addr.is_none() {
        // hardening: only ever confirm an address that is
        // already a known candidate (coordination- or discovery-supplied)
        // — authenticated traffic alone, from an address we never
        // solicited or learned of, isn't enough to adopt as the direct
        // endpoint.
        if let Some(addr) =
            from_addr.filter(|a| state.direct_candidates.iter().any(|c| c.addr == *a))
        {
            tracing::debug!(%addr, "direct candidate confirmed");
            state.confirmed_direct_addr = Some(addr);
            state.attempt = 0;
            state.race_started_at = None;
            set_reachability(state, PeerReachability::Connected { path: classify_endpoint(addr) });
        } else if let Some(addr) = from_addr {
            tracing::debug!(
                %addr,
                "authenticated direct traffic from an address that is not a known candidate; not confirming"
            );
        }
    }

    authenticated
}

/// Learns a runtime-surfaced (local-discovery) candidate. If the peer is
/// currently unreachable, a genuinely new candidate resets the retry
/// backoff and starts a fresh race immediately rather than waiting out the
/// current backoff interval.
fn learn_candidate(state: &mut ActorState, addr: SocketAddr) {
    let added = insert_candidate(
        &mut state.direct_candidates,
        state.confirmed_direct_addr,
        addr,
        CandidateSource::Discovery,
    );
    if added {
        // Keep the hub's source-narrowing hints current for this channel.
        state.shared.note_channel_candidate(state.session_index, addr);
    }
    if added && matches!(state.reachability, PeerReachability::Unreachable { .. }) {
        state.attempt = 0;
        state.race_started_at = Some(Instant::now());
        set_reachability(state, PeerReachability::Connecting { attempt: 0 });
    }
}

fn replace_coordination_candidates(state: &mut ActorState, candidates: Vec<SocketAddr>) {
    let authoritative: HashSet<SocketAddr> = candidates.into_iter().collect();
    let before: HashSet<(SocketAddr, CandidateSource)> = state
        .direct_candidates
        .iter()
        .map(|candidate| (candidate.addr, candidate.source))
        .collect();
    state.direct_candidates.retain(|candidate| {
        candidate.source != CandidateSource::Coordination || authoritative.contains(&candidate.addr)
    });
    for addr in authoritative {
        insert_candidate(
            &mut state.direct_candidates,
            state.confirmed_direct_addr,
            addr,
            CandidateSource::Coordination,
        );
        state.shared.note_channel_candidate(state.session_index, addr);
    }
    let after: HashSet<(SocketAddr, CandidateSource)> = state
        .direct_candidates
        .iter()
        .map(|candidate| (candidate.addr, candidate.source))
        .collect();
    if before == after {
        return;
    }

    if state
        .confirmed_direct_addr
        .is_some_and(|confirmed| !state.direct_candidates.iter().any(|c| c.addr == confirmed))
    {
        state.confirmed_direct_addr = None;
        state.last_direct_rx = None;
    }
    state.attempt = 0;
    if state.direct_candidates.is_empty() {
        state.race_started_at = None;
        set_reachability(
            state,
            PeerReachability::Unreachable {
                category: UnreachableCategory::NoCandidates,
                next_retry: Instant::now() + state.backoff.next(0),
            },
        );
    } else {
        state.race_started_at = Some(Instant::now());
        set_reachability(state, PeerReachability::Connecting { attempt: 0 });
    }
}

/// Publishes a reachability transition to the watch channel and logs
/// state-kind changes (Connected/Unreachable at a visible level so a
/// stalled sync is diagnosable; Connecting at debug). A no-op if the state
/// is unchanged.
fn set_reachability(state: &mut ActorState, next: PeerReachability) {
    if state.reachability == next {
        return;
    }
    if std::mem::discriminant(&state.reachability) != std::mem::discriminant(&next) {
        match next {
            PeerReachability::Connecting { attempt } => tracing::debug!(
                peer = %hex::encode(state.peer_public_bytes),
                attempt,
                "peer reachability: connecting (racing candidates)"
            ),
            PeerReachability::Connected { path } => tracing::info!(
                peer = %hex::encode(state.peer_public_bytes),
                ?path,
                "peer reachability: connected"
            ),
            PeerReachability::Unreachable { category, .. } => tracing::warn!(
                peer = %hex::encode(state.peer_public_bytes),
                ?category,
                "peer reachability: unreachable (cannot connect)"
            ),
        }
    }
    state.reachability = next;
    let _ = state.reachability_tx.send(next);
}

/// Whether the direct-probe timer should fire: only while actively racing
/// or keeping a confirmed path alive, and never with an empty candidate
/// set. A peer in `Unreachable` backoff is deliberately not probed until
/// its next scheduled race (driven from [`evaluate_reachability`]).
fn should_probe(state: &ActorState) -> bool {
    !state.direct_candidates.is_empty()
        && matches!(
            state.reachability,
            PeerReachability::Connecting { .. } | PeerReachability::Connected { .. }
        )
}

/// Enters the unreachable state with a bounded-backoff `next_retry`,
/// choosing the failure category from what the race actually saw
/// (no candidates at all vs. candidates that stayed silent).
fn enter_unreachable(state: &mut ActorState, now: Instant) {
    let category = if state.direct_candidates.is_empty() {
        UnreachableCategory::NoCandidates
    } else {
        UnreachableCategory::NoResponse
    };
    let delay = state.backoff.next(state.attempt);
    state.attempt = state.attempt.saturating_add(1);
    state.race_started_at = None;
    set_reachability(state, PeerReachability::Unreachable { category, next_retry: now + delay });
}

/// Drives the reachability state machine on each `TICK_INTERVAL`:
/// a stalled candidate race lands in `Unreachable`; a confirmed path gone
/// quiet re-races (re-traversal); and an `Unreachable` peer re-races once
/// its backoff elapses.
fn evaluate_reachability(state: &mut ActorState) {
    let now = Instant::now();
    match state.reachability {
        PeerReachability::Connecting { .. } => {
            // Confirmation is handled synchronously in `handle_datagram`;
            // here we only detect a race that ran out of time.
            if state.confirmed_direct_addr.is_some() {
                return;
            }
            if state.direct_candidates.is_empty() {
                enter_unreachable(state, now);
            } else if let Some(started) = state.race_started_at {
                if now.duration_since(started) >= CANDIDATE_RACE_TIMEOUT {
                    enter_unreachable(state, now);
                }
            } else {
                state.race_started_at = Some(now);
            }
        }
        PeerReachability::Connected { .. } => {
            let Some(last_rx) = state.last_direct_rx else { return };
            if last_rx.elapsed() < DIRECT_LIVENESS_TIMEOUT {
                return;
            }
            tracing::warn!(
                peer = %hex::encode(state.peer_public_bytes),
                elapsed_secs = last_rx.elapsed().as_secs(),
                "direct path liveness lost (missed keepalives); re-racing candidates"
            );
            // Forget the confirmed address so a later successful direct
            // receive re-confirms from scratch rather than trusting a
            // candidate that just proved unreliable, and start a fresh
            // race with the backoff reset.
            state.confirmed_direct_addr = None;
            state.attempt = 0;
            state.race_started_at = Some(now);
            set_reachability(state, PeerReachability::Connecting { attempt: 0 });
        }
        PeerReachability::Unreachable { next_retry, .. } => {
            if now < next_retry {
                return;
            }
            if state.direct_candidates.is_empty() {
                // Nothing to race; re-arm the backoff timer and stay
                // NoCandidates until a candidate is learned.
                let delay = state.backoff.next(state.attempt);
                state.attempt = state.attempt.saturating_add(1);
                set_reachability(
                    state,
                    PeerReachability::Unreachable {
                        category: UnreachableCategory::NoCandidates,
                        next_retry: now + delay,
                    },
                );
            } else {
                state.race_started_at = Some(now);
                set_reachability(state, PeerReachability::Connecting { attempt: state.attempt });
            }
        }
    }
}

/// Inserts `addr` into `candidates` if not already present, enforcing
/// [`MAX_DIRECT_CANDIDATES`]: when full, evicts the oldest
/// `Discovery`-sourced candidate that isn't `confirmed`, and refuses the
/// insert entirely if nothing is safely evictable (every current entry is
/// either `confirmed` or `Coordination`-sourced) — a confirmed or
/// coordination-supplied candidate is never displaced to admit a
/// discovery-supplied one. Returns whether a new candidate was actually
/// added (`false` for a duplicate or a refused insert).
fn insert_candidate(
    candidates: &mut Vec<DirectCandidate>,
    confirmed: Option<SocketAddr>,
    addr: SocketAddr,
    source: CandidateSource,
) -> bool {
    if candidates.iter().any(|c| c.addr == addr) {
        return false;
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
                return false;
            }
        }
    }

    tracing::debug!(%addr, ?source, "adding direct candidate");
    candidates.push(DirectCandidate { addr, source, added_at: Instant::now() });
    true
}

async fn send_batch_direct(state: &ActorState, datagrams: Vec<Vec<u8>>) {
    if datagrams.is_empty() {
        return;
    }
    match state.confirmed_direct_addr {
        // Once a candidate has proven reachable, stop racing and
        // send only there.
        Some(addr) => {
            let _ = state.shared.send_batch(&datagrams, addr).await;
        }
        // Not yet confirmed: race every candidate with this
        // datagram too, not just probes, so app data isn't stuck
        // waiting for a separate probe round-trip to finish first.
        None => {
            for candidate in &state.direct_candidates {
                let _ = state.shared.send_batch(&datagrams, candidate.addr).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_hub::TransportHub;
    use tokio::net::UdpSocket;

    fn peer_addr() -> SocketAddr {
        "203.0.113.9:41641".parse().unwrap()
    }

    /// Builds an `ActorState` over a real loopback shared socket for exercising
    /// the reachability state machine and confirm gate directly. Uses a
    /// fixed local/peer keypair ([1u8; 32] local / [2u8; 32] peer) so a
    /// handshake initiation from a mirrored `WgTunnel` ([2u8; 32] local /
    /// [1u8; 32] peer, session index 1) validates against it. Datagrams are
    /// fed to `handle_datagram` directly, so the shared socket's own receive
    /// loop is inert here.
    async fn make_state(
        reachability: PeerReachability,
        candidates: Vec<DirectCandidate>,
        confirmed: Option<SocketAddr>,
    ) -> ActorState {
        let local_secret = StaticSecret::from([1u8; 32]);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        let tunn = WgTunnel::new(local_secret, peer_public, 0);
        let (_outbound_tx, outbound_rx) = mpsc::channel::<Bytes>(1);
        let (_candidate_tx, candidate_rx) = mpsc::channel::<CandidateUpdate>(1);
        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(1);
        let (reachability_tx, _reachability_rx) = watch::channel(reachability);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let shared = TransportHub::from_socket(socket, None);
        let inbound_demux_rx = shared.register_channel(0, &[]);
        ActorState {
            tunn,
            peer_public_bytes: peer_public.to_bytes(),
            shared,
            session_index: 0,
            inbound_demux_rx,
            direct_candidates: candidates,
            confirmed_direct_addr: confirmed,
            last_direct_rx: None,
            outbound_rx,
            candidate_rx,
            inbound_tx,
            reachability,
            reachability_tx,
            backoff: BackoffConfig::RECONNECT,
            attempt: 0,
            race_started_at: None,
            revoked: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
            reliable_enabled: Arc::new(AtomicBool::new(false)),
            reliable_send: ReliableSend::new(),
            reliable_recv: ReliableRecv::new(),
        }
    }

    fn coordination_candidate(addr: SocketAddr) -> DirectCandidate {
        DirectCandidate { addr, source: CandidateSource::Coordination, added_at: Instant::now() }
    }

    #[tokio::test]
    async fn authoritative_endpoint_update_replaces_only_coordination_candidates() {
        let old_coordination: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let discovery: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let new_coordination: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let mut state = make_state(
            PeerReachability::Connected { path: CandidateClass::Lan },
            vec![
                coordination_candidate(old_coordination),
                DirectCandidate {
                    addr: discovery,
                    source: CandidateSource::Discovery,
                    added_at: Instant::now(),
                },
            ],
            Some(old_coordination),
        )
        .await;

        replace_coordination_candidates(&mut state, vec![new_coordination]);

        assert!(!state.direct_candidates.iter().any(|c| c.addr == old_coordination));
        assert!(state.direct_candidates.iter().any(|c| c.addr == discovery));
        assert!(state.direct_candidates.iter().any(|c| c.addr == new_coordination));
        assert_eq!(state.confirmed_direct_addr, None);
        assert!(matches!(state.reachability, PeerReachability::Connecting { attempt: 0 }));
    }

    // --- Reachability state-machine tests ----------------------------

    /// A candidate race that runs past `CANDIDATE_RACE_TIMEOUT` without
    /// confirming any candidate lands in `Unreachable` with the
    /// `NoResponse` category (candidates were present but stayed silent).
    #[tokio::test]
    async fn exhausted_candidate_race_becomes_unreachable_no_response() {
        let mut state = make_state(
            PeerReachability::Connecting { attempt: 0 },
            vec![coordination_candidate(peer_addr())],
            None,
        )
        .await;
        state.race_started_at = Some(Instant::now() - Duration::from_secs(25));

        evaluate_reachability(&mut state);

        assert!(matches!(
            state.reachability,
            PeerReachability::Unreachable { category: UnreachableCategory::NoResponse, .. }
        ));
    }

    /// A race with no candidates at all becomes `Unreachable` with the
    /// `NoCandidates` category immediately (nothing to race).
    #[tokio::test]
    async fn empty_candidate_race_becomes_unreachable_no_candidates() {
        let mut state = make_state(PeerReachability::Connecting { attempt: 0 }, vec![], None).await;
        state.race_started_at = Some(Instant::now());

        evaluate_reachability(&mut state);

        assert!(matches!(
            state.reachability,
            PeerReachability::Unreachable { category: UnreachableCategory::NoCandidates, .. }
        ));
    }

    /// A newly learned candidate for an unreachable peer resets the
    /// backoff attempt count and re-races immediately (`Connecting`)
    /// rather than waiting out the current retry interval.
    #[tokio::test]
    async fn newly_learned_candidate_resets_backoff_and_reraces() {
        let mut state = make_state(
            PeerReachability::Unreachable {
                category: UnreachableCategory::NoResponse,
                next_retry: Instant::now() + Duration::from_secs(30),
            },
            vec![],
            None,
        )
        .await;
        state.attempt = 5;

        learn_candidate(&mut state, peer_addr());

        assert!(matches!(state.reachability, PeerReachability::Connecting { attempt: 0 }));
        assert_eq!(state.attempt, 0);
        assert!(state.direct_candidates.iter().any(|c| c.addr == peer_addr()));
    }

    /// An unreachable peer whose backoff has elapsed re-races its known
    /// candidates (back to `Connecting`), carrying the escalated attempt
    /// count forward.
    #[tokio::test]
    async fn unreachable_backoff_expiry_reraces_candidates() {
        let mut state = make_state(
            PeerReachability::Unreachable {
                category: UnreachableCategory::NoResponse,
                next_retry: Instant::now() - Duration::from_secs(1),
            },
            vec![coordination_candidate(peer_addr())],
            None,
        )
        .await;
        state.attempt = 3;

        evaluate_reachability(&mut state);

        assert!(matches!(state.reachability, PeerReachability::Connecting { attempt: 3 }));
    }

    /// A confirmed direct path that goes quiet past
    /// `DIRECT_LIVENESS_TIMEOUT` re-races candidates (re-traversal) rather
    /// than stalling, clearing the stale confirmed address.
    #[tokio::test]
    async fn confirmed_path_liveness_loss_triggers_retraversal() {
        let mut state = make_state(
            PeerReachability::Connected { path: CandidateClass::Lan },
            vec![coordination_candidate(peer_addr())],
            Some(peer_addr()),
        )
        .await;
        state.last_direct_rx = Some(Instant::now() - Duration::from_secs(25));

        evaluate_reachability(&mut state);

        assert!(matches!(state.reachability, PeerReachability::Connecting { attempt: 0 }));
        assert!(state.confirmed_direct_addr.is_none());
    }

    // --- Confirm-gate tests ------------------------------------------

    /// A junk datagram — not a valid WireGuard
    /// packet at all, so it never decrypts or advances the handshake —
    /// arriving from a *known* candidate address must not confirm that
    /// candidate or move the peer to `Connected`. Using a known candidate
    /// address isolates this to the authentication gate itself.
    #[tokio::test]
    async fn junk_datagram_does_not_confirm_or_connect() {
        let mut state = make_state(
            PeerReachability::Connecting { attempt: 0 },
            vec![coordination_candidate(peer_addr())],
            None,
        )
        .await;

        handle_datagram(&mut state, &[0xAAu8; 200], Some(peer_addr())).await;

        assert!(state.confirmed_direct_addr.is_none());
        assert!(matches!(state.reachability, PeerReachability::Connecting { .. }));
    }

    /// Even a datagram that *does* decrypt (a genuine handshake
    /// initiation) from an address that isn't a known candidate must not
    /// be confirmed — regression guard against dropping the
    /// candidate-membership check.
    #[tokio::test]
    async fn authenticated_traffic_from_unknown_address_does_not_confirm() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        // No candidates at all — the source address is not among them.
        let mut state = make_state(PeerReachability::Connecting { attempt: 0 }, vec![], None).await;

        handle_datagram(&mut state, &init, Some(peer_addr())).await;

        assert!(state.confirmed_direct_addr.is_none());
        assert!(matches!(state.reachability, PeerReachability::Connecting { .. }));
    }

    /// Positive control: a genuine handshake initiation from the correct
    /// peer at a known candidate address confirms the candidate and moves
    /// the peer to `Connected` — proving the gate distinguishes junk from
    /// authenticated traffic rather than never confirming anything.
    #[tokio::test]
    async fn authenticated_handshake_confirms_and_connects() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        let mut state = make_state(
            PeerReachability::Connecting { attempt: 0 },
            vec![coordination_candidate(peer_addr())],
            None,
        )
        .await;

        handle_datagram(&mut state, &init, Some(peer_addr())).await;

        assert_eq!(state.confirmed_direct_addr, Some(peer_addr()));
        assert!(matches!(state.reachability, PeerReachability::Connected { .. }));
    }

    /// Once revoked, `handle_datagram` refuses to process *any* further
    /// datagram — including what would otherwise be a completely valid
    /// WireGuard handshake initiation from the correct (now-revoked) peer
    /// key — so it never confirms a candidate or connects.
    #[tokio::test]
    async fn revoked_channel_refuses_a_valid_handshake_attempt() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);
        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");

        let mut state = make_state(
            PeerReachability::Connecting { attempt: 0 },
            vec![coordination_candidate(peer_addr())],
            None,
        )
        .await;
        state.revoked.store(true, Ordering::Relaxed);

        handle_datagram(&mut state, &init, Some(peer_addr())).await;

        assert!(state.confirmed_direct_addr.is_none());
        assert!(matches!(state.reachability, PeerReachability::Connecting { .. }));
    }

    // --- Candidate-bounding tests ------------------------------------

    /// A flood of distinct discovery-sourced
    /// candidates never grows the list past `MAX_DIRECT_CANDIDATES`, and
    /// confirmed / coordination-supplied candidates are never evicted to
    /// make room for a discovery-supplied one.
    #[test]
    fn direct_candidate_list_is_bounded_and_protects_high_provenance_entries() {
        let mut candidates: Vec<DirectCandidate> = Vec::new();

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
        // announced port.
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
    /// even when nothing is evictable.
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
        let added = insert_candidate(&mut candidates, None, flood_addr, CandidateSource::Discovery);

        assert!(!added);
        assert_eq!(candidates.len(), MAX_DIRECT_CANDIDATES);
        assert!(!candidates.iter().any(|c| c.addr == flood_addr));
    }

    // --- Candidate class ---------------------------------------------

    #[test]
    fn classify_endpoint_maps_address_scopes() {
        assert_eq!(classify_endpoint("192.168.1.5:41641".parse().unwrap()), CandidateClass::Lan);
        assert_eq!(classify_endpoint("10.0.0.9:41641".parse().unwrap()), CandidateClass::Lan);
        assert_eq!(
            classify_endpoint("198.51.100.7:41641".parse().unwrap()),
            CandidateClass::ServerReflexive
        );
    }

    // --- Netmap diff tests -------------------------------------------

    fn snapshot(entries: &[(&str, &[&str])]) -> NetmapSnapshot {
        entries
            .iter()
            .map(|(device_id, groups)| {
                (device_id.to_string(), groups.iter().map(|g| g.to_string()).collect())
            })
            .collect()
    }

    /// A device that disappears from the netmap entirely
    /// (whole-device revocation) is classified as a removed device, not a
    /// removed group edge — the diff must key off device presence in
    /// `current`, not just group-set difference.
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

    /// A device still present but with fewer shared groups is a group-edge
    /// removal (the tunnel is meant to stay up), not a device removal.
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

    /// A single netmap update can carry both kinds of removal at once —
    /// both must be classified correctly in the same diff.
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
}
