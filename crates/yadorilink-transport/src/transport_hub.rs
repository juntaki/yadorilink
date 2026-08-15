//! The device's single logical transport endpoint — a `TransportHub` — shared
//! by every [`PeerChannel`] and by NAT candidate gathering (STUN, port
//! mapping).
//!
//! Why one endpoint: a NAT maps an *(internal address, internal port)* to an
//! external endpoint, tied to the exact local port packets leave from — it
//! does not extend the mapping to other local ports. So the reflexive /
//! port-mapped candidates a device advertises are only reachable if the data
//! answering an inbound connection leaves from, and arrives on, the *same*
//! socket those candidates were observed for.
//!
//! Demultiplexing (normative):
//! - STUN: magic cookie **and** a transaction id we actually have pending →
//!   the prober; otherwise dropped.
//! - WireGuard transport-data / handshake-response / cookie-reply: routed to
//!   the owning channel by receiver index (its high 24 bits are the channel's
//!   session index — boringtun issues local indices as
//!   `session_index << 8 | cyclic`); an unknown index is dropped.
//! - WireGuard handshake **initiation**: carries only a sender index, so a
//!   receiver index cannot route it. We (1) verify MAC1 against this device's
//!   static public key (a cheap reject of anything not addressed to us, plus
//!   cookie/rate-limiting under load) via boringtun's `RateLimiter`, then
//!   (2) narrow by source endpoint — channels whose known candidates match the
//!   source are offered it first — and (3) offer it to the authorized channels
//!   (the netmap set: only authorized peers ever have a channel) for bounded
//!   trial decapsulation. The source IP:port is a narrowing hint, never
//!   identity; a path is confirmed only by authenticated traffic (the rule in
//!   [`crate::peer_channel`] is unchanged).
//! - Anything else is dropped.
//!
//! Physically the hub drives a [`UdpEndpoint`]: a dual-stack IPv4 + IPv6 socket
//! pair bound to one logical port (the IPv6 half is v6-only via `socket2` so the
//! two do not collide), so a peer is reachable over either family and IPv6 host
//! candidates are first-class. Either half may be absent (a single-socket
//! harness, or a host without usable IPv6). The demux above is family-agnostic.
//!
//! [`PeerChannel`]: crate::peer_channel::PeerChannel

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::nat::stun::{StunIoFuture, StunSocket};
use crate::tunn_wrapper::MAX_WIREGUARD_DATAGRAM_LEN;
use crate::udp_batching::UdpBatchingSupport;

/// How many inbound datagrams may queue for a single channel (or the prober)
/// before the demultiplexer drops the surplus. WireGuard and STUN both
/// tolerate loss, and a bounded per-consumer queue keeps one slow consumer
/// from backing up the single shared receive loop for every other peer.
const DEMUX_QUEUE_DEPTH: usize = 256;

/// Per-device handshake-initiation rate ceiling for the hub's MAC1 gate.
/// boringtun's own default is private; this is the same order of magnitude — a
/// generous ceiling that still bounds an initiation flood to one budget per
/// device rather than one per peer session.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// How many recent STUN transaction ids the hub remembers, so a binding
/// response is accepted only if it answers a request we actually sent.
const STUN_PENDING_DEPTH: usize = 64;

/// M3 Pass 2: how many MAC1-verified handshake initiations may queue
/// waiting for a worker before the surplus is dropped -- the same
/// tolerates-loss reasoning as `DEMUX_QUEUE_DEPTH`, sized the same. This
/// queue exists so `recv_loop` NEVER performs the identity-resolution
/// crypto step itself (see `identify_and_route_initiation`'s own doc
/// comment) -- a flood of otherwise-valid initiations can only ever back
/// up behind this one bounded queue, never stall the single shared
/// receive loop that every OTHER peer's data/control traffic also
/// depends on.
const HANDSHAKE_INGRESS_QUEUE_DEPTH: usize = 256;

/// M3 Pass 2: fixed worker pool size draining the handshake-ingress
/// queue. Small and fixed (not spawned per-packet, not scaled with N
/// registered peers) -- unbounded/per-packet spawning was exactly the
/// kind of amplification this pass exists to close, just one layer up
/// (worker count instead of decapsulate-attempt count).
const HANDSHAKE_WORKER_COUNT: usize = 4;

/// Whether an inbound datagram was demultiplexed to its owning channel by
/// WireGuard receiver index (definitely for that channel), offered to a
/// channel as a handshake-initiation probe (for that channel only if its
/// static key authenticates it), or unwrapped from a relay envelope --
/// M3 Pass 8 closeout: route provenance that survives all the way to
/// `PeerChannel`'s own confirm gate, so a relay-delivered datagram can
/// NEVER be interpreted as evidence of a direct route, regardless of
/// whether its outer source address happens to coincide with a known
/// direct candidate (see `unwrap_relay_envelope`'s own doc comment for
/// the wire format this is threaded from).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    /// Routed by receiver index, from a datagram that arrived as genuine
    /// raw UDP (no relay envelope): this datagram belongs to the
    /// receiving channel's WireGuard session AND physically arrived over
    /// this device's own direct network path.
    Direct,
    /// A MAC1-verified handshake initiation offered to authorized channels;
    /// only the channel whose static key decapsulates it is the recipient.
    /// Also only ever produced from genuine raw (non-relay-wrapped) UDP --
    /// see `Relay`'s own doc comment for the relay-wrapped counterpart.
    HandshakeProbe,
    /// Unwrapped from a relay envelope (`unwrap_relay_envelope`) -- the
    /// opaque WireGuard bytes inside are cryptographically exactly as
    /// meaningful as `Direct`/`HandshakeProbe` traffic (same `Tunn::
    /// decapsulate` call, same authentication), but the ENVELOPE itself
    /// proves this arrived via a relaying peer's own forwarding socket,
    /// not this device's real address. `PeerChannel`'s confirm gate must
    /// never promote traffic of this kind to a confirmed direct path,
    /// no matter what its outer UDP source address happens to be.
    Relay,
}

/// M3 Pass 8 closeout: the relay envelope's own fixed marker -- a `u32`
/// value no genuine WireGuard packet can ever produce as its own leading
/// 4 bytes (every real WireGuard message type -- handshake init/response/
/// cookie-reply/transport-data -- starts with a small `u32` LE
/// discriminant, 1 through 4; boringtun's own `Tunn::parse_incoming_
/// packet` rejects anything else as unparseable). Using an unreachable
/// discriminant value means envelope detection can never collide with,
/// misinterpret, or be confused for a genuine WireGuard packet -- the two
/// wire formats are unambiguous by construction, checked in the fixed
/// order `unwrap_relay_envelope` then `Tunn::parse_incoming_packet`.
/// M3 Pass 8 closeout: whether a datagram being routed through the demux
/// arrived wrapped in a relay envelope or not -- threaded through every
/// routing function so the `DatagramKind` an `InboundDatagram` is finally
/// tagged with always reflects it, regardless of which specific routing
/// path (receiver-index, handshake-probe broadcast, or identified
/// initiation) it takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutedKind {
    Direct,
    Relay,
}

impl RoutedKind {
    /// The `DatagramKind` for a receiver-index-routed datagram.
    fn direct_kind(self) -> DatagramKind {
        match self {
            RoutedKind::Direct => DatagramKind::Direct,
            RoutedKind::Relay => DatagramKind::Relay,
        }
    }
    /// The `DatagramKind` for a handshake-initiation offered/identified
    /// this way. Deliberately collapses to the SAME `DatagramKind::Relay`
    /// a receiver-index-routed relay datagram gets -- no separate
    /// "relay handshake probe" variant exists, because everything that
    /// matters to a consumer (`PeerChannel`'s confirm gate, its liveness
    /// bump) is simply "did this arrive via a relay", not which specific
    /// routing path identified it.
    fn probe_kind(self) -> DatagramKind {
        match self {
            RoutedKind::Direct => DatagramKind::HandshakeProbe,
            RoutedKind::Relay => DatagramKind::Relay,
        }
    }
}

const RELAY_ENVELOPE_MARKER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
const RELAY_ENVELOPE_HEADER_LEN: usize = RELAY_ENVELOPE_MARKER.len() + 8;

/// M3 Pass 8 closeout: `yadorilink-daemon`'s `relay_forwarder.rs` wraps
/// every datagram it forwards toward a relay session's destination in
/// this envelope (`RELAY_ENVELOPE_MARKER` + little-endian `u64` relay
/// session id + the opaque WireGuard bytes verbatim) BEFORE sending it
/// raw over its own dedicated forwarding socket -- rather than sending
/// those WireGuard bytes completely unwrapped, indistinguishable from
/// genuine direct UDP the way earlier passes did. `B` (the relay) still
/// never decrypts or inspects the WireGuard payload itself -- opaque
/// PAYLOAD forwarding is preserved exactly as designed -- this envelope
/// only wraps the OUTER transport framing, which is not, and never was,
/// required to be opaque: `B` already knows a relay session exists (it
/// admitted it), the session id, and the destination it's forwarding to;
/// this envelope reveals nothing to any observer that admission didn't
/// already require `B` to know.
///
/// Returns the session id and the inner opaque bytes if `datagram` has a
/// valid envelope header, `None` otherwise (too short, or the marker
/// doesn't match -- i.e., this is ordinary, non-relay-wrapped traffic).
fn unwrap_relay_envelope(datagram: &[u8]) -> Option<(u64, &[u8])> {
    if datagram.len() < RELAY_ENVELOPE_HEADER_LEN {
        return None;
    }
    if datagram[..RELAY_ENVELOPE_MARKER.len()] != RELAY_ENVELOPE_MARKER {
        return None;
    }
    let session_id_bytes: [u8; 8] =
        datagram[RELAY_ENVELOPE_MARKER.len()..RELAY_ENVELOPE_HEADER_LEN].try_into().ok()?;
    Some((u64::from_le_bytes(session_id_bytes), &datagram[RELAY_ENVELOPE_HEADER_LEN..]))
}

/// The sibling of [`unwrap_relay_envelope`] -- wraps opaque WireGuard
/// bytes for a relay session's forwarding send. `pub` (not `pub(crate)`):
/// called from `yadorilink-daemon`'s `relay_forwarder.rs`, a different
/// crate.
pub fn wrap_relay_envelope(relay_session_id: u64, opaque_wg_bytes: &[u8]) -> Vec<u8> {
    let mut wrapped = Vec::with_capacity(RELAY_ENVELOPE_HEADER_LEN + opaque_wg_bytes.len());
    wrapped.extend_from_slice(&RELAY_ENVELOPE_MARKER);
    wrapped.extend_from_slice(&relay_session_id.to_le_bytes());
    wrapped.extend_from_slice(opaque_wg_bytes);
    wrapped
}

/// One inbound datagram delivered to a channel's demux queue.
#[derive(Debug)]
pub struct InboundDatagram {
    pub data: Vec<u8>,
    pub from: SocketAddr,
    pub kind: DatagramKind,
}

/// A registered channel: where to deliver its datagrams, the source IPs
/// (from its known candidates) used to order initiation trials (kept for
/// the back-compat broadcast fallback -- see `offer_initiation`'s own doc
/// comment), and the peer's own static public key (M3 Pass 2) for O(1)
/// exact dispatch once an initiation's sender is identified.
struct ChannelEntry {
    sender: mpsc::Sender<InboundDatagram>,
    candidate_ips: HashSet<IpAddr>,
    peer_public: [u8; 32],
}

/// A raw inbound datagram handed to whoever is currently registered to
/// receive STUN replies (`(payload, sender address)`).
type StunDatagram = (Vec<u8>, SocketAddr);

/// The demux routing table, shared between [`TransportHub`], its receive
/// loop, and (M3 Pass 2) its handshake-identification worker pool.
struct DemuxRegistry {
    channels: Mutex<HashMap<u32, ChannelEntry>>,
    /// M3 Pass 2: peer static public key bytes -> session index, the O(1)
    /// exact-dispatch index `identify_and_route_initiation` uses once
    /// `parse_handshake_anon` reveals an initiation's real sender. Kept as
    /// a SEPARATE map from `channels` (not folded into `ChannelEntry`
    /// itself) so a lookup here never needs to hold `channels`' own lock
    /// for longer than the immediate follow-up `get`.
    by_peer_public: Mutex<HashMap<[u8; 32], u32>>,
    stun_tx: Mutex<Option<mpsc::Sender<StunDatagram>>>,
    /// Transaction ids of binding requests sent but not yet answered (bounded
    /// ring; a response with an unknown id is dropped).
    stun_pending: Mutex<VecDeque<[u8; 12]>>,
    /// MAC1 verifier keyed on this device's static public key. `None` when the
    /// device identity was not supplied (tests / pre-identity startup): the
    /// initiation gate then falls back to offering initiations to every
    /// authorized channel without the cheap MAC1 pre-reject.
    rate_limiter: Option<RateLimiter>,
    /// M3 Pass 2: this device's own WireGuard static keypair, set once via
    /// [`TransportHub::set_device_identity`] -- NOT required at
    /// construction (`bind`/`from_socket` keep their existing
    /// `device_public`-only signatures, unchanged for every existing
    /// caller). While unset, `identify_and_route_initiation` falls back to
    /// `offer_initiation`'s broadcast-to-every-channel behavior (still
    /// off the receive loop, via the bounded worker pool -- see that
    /// function's own doc comment); every real production caller DOES
    /// call `set_device_identity`, closing the O(N^2) cost this pass
    /// exists to eliminate. `StaticSecret` is held here the same way
    /// every registered channel's own `Tunn` already holds an identical
    /// copy of this same device secret -- not a new class of exposure,
    /// just one more copy of already-in-process key material.
    device_identity: OnceLock<(StaticSecret, PublicKey)>,
    /// M3 Pass 2: where `handle_initiation` enqueues a MAC1-verified
    /// initiation for the worker pool to identify and route -- set once
    /// at construction (`DemuxRegistry::new`), never `None` after that
    /// (unlike `rate_limiter`/`device_identity`, this is unconditional:
    /// every hub gets bounded ingress + a worker pool, whether or not it
    /// ever calls `set_device_identity`).
    handshake_ingress_tx: mpsc::Sender<(Vec<u8>, SocketAddr, RoutedKind)>,
}

impl DemuxRegistry {
    /// Returns the registry and the receiving half of its handshake-
    /// ingress queue -- the caller (`TransportHub::assemble`) is
    /// responsible for spawning the worker pool that drains it, the same
    /// way it's responsible for spawning `recv_loop` itself.
    fn new(
        device_public: Option<PublicKey>,
    ) -> (Self, mpsc::Receiver<(Vec<u8>, SocketAddr, RoutedKind)>) {
        let (handshake_ingress_tx, handshake_ingress_rx) =
            mpsc::channel(HANDSHAKE_INGRESS_QUEUE_DEPTH);
        let registry = Self {
            channels: Mutex::new(HashMap::new()),
            by_peer_public: Mutex::new(HashMap::new()),
            stun_tx: Mutex::new(None),
            stun_pending: Mutex::new(VecDeque::with_capacity(STUN_PENDING_DEPTH)),
            rate_limiter: device_public.map(|pk| RateLimiter::new(&pk, HANDSHAKE_RATE_LIMIT)),
            device_identity: OnceLock::new(),
            handshake_ingress_tx,
        };
        (registry, handshake_ingress_rx)
    }

    /// Routes one received datagram. Returns a datagram to send back (a
    /// WireGuard cookie reply produced by the MAC1 gate when under load),
    /// which the receive loop is responsible for delivering.
    ///
    /// M3 Pass 8 closeout: checks for a relay envelope FIRST -- see
    /// `unwrap_relay_envelope`'s own doc comment -- before attempting to
    /// parse `datagram` as a raw WireGuard packet, so a relay-wrapped
    /// datagram is routed with `DatagramKind::Relay`/`RelayHandshakeProbe`
    /// throughout, never `Direct`/`HandshakeProbe`, regardless of its
    /// outer UDP source address. A cookie reply produced while handling
    /// relay-wrapped traffic still goes back to the OUTER `from` (the
    /// relay's own forwarding socket) -- WireGuard cookie replies are
    /// themselves opaque protocol bytes the relay is already expected to
    /// forward onward, exactly like everything else in this session.
    fn route(&self, datagram: &[u8], from: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
        if let Some((_relay_session_id, inner)) = unwrap_relay_envelope(datagram) {
            return self.route_kind(inner, from, RoutedKind::Relay);
        }
        self.route_kind(datagram, from, RoutedKind::Direct)
    }

    fn route_kind(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        routed: RoutedKind,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        match Tunn::parse_incoming_packet(datagram) {
            Ok(Packet::HandshakeInit(_)) => return self.handle_initiation(datagram, from, routed),
            Ok(Packet::HandshakeResponse(p)) => {
                self.route_by_index(p.receiver_idx, datagram, from, routed)
            }
            Ok(Packet::PacketCookieReply(p)) => {
                self.route_by_index(p.receiver_idx, datagram, from, routed)
            }
            Ok(Packet::PacketData(p)) => {
                self.route_by_index(p.receiver_idx, datagram, from, routed)
            }
            // STUN is this device's OWN local NAT discovery -- never
            // meaningful relayed (a relay envelope only ever wraps
            // WireGuard bytes; `relay_forwarder.rs` never wraps STUN).
            Err(_) if routed == RoutedKind::Direct => self.maybe_route_stun(datagram, from),
            Err(_) => {}
        }
        None
    }

    fn route_by_index(
        &self,
        receiver_idx: u32,
        datagram: &[u8],
        from: SocketAddr,
        routed: RoutedKind,
    ) {
        let session_index = receiver_idx >> 8;
        let channels = self.channels.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = channels.get(&session_index) {
            // M3 Pass 1: was `let _ = ...`, silently discarding a full-queue
            // drop with no signal anywhere -- a real observability gap the
            // handshake fan-in reproducer's own review flagged (it could
            // only measure wasted decapsulate attempts, not whether queue
            // saturation was ALSO contributing). Log-only, no behavior
            // change: `try_send`'s drop-on-full semantics are unchanged.
            // Matched specifically on `Full`, not any error: the
            // channel's own actor task exiting (`Closed`) is a completely
            // different condition (the channel is gone, not merely busy)
            // and a Codex review caught an earlier version of this fix
            // conflating the two under one "queue full" message.
            if let Err(mpsc::error::TrySendError::Full(_)) =
                entry.sender.try_send(InboundDatagram {
                    data: datagram.to_vec(),
                    from,
                    kind: routed.direct_kind(),
                })
            {
                tracing::debug!(
                    session_index,
                    "dropped inbound datagram: channel demux queue full"
                );
            }
        }
    }

    /// Handles a handshake initiation per the normative rules: a cheap MAC1
    /// gate stays HERE, inline in the receive loop's own call stack (a
    /// single Blake2s MAC check -- no asymmetric crypto, cheap enough that
    /// moving it off the hot path would only add latency for no real
    /// liveness benefit). Everything past the gate -- identifying the real
    /// sender and dispatching to its channel, M3 Pass 2's whole point -- is
    /// handed to the bounded handshake-ingress queue instead of being done
    /// here. Returns a cookie reply to send if the gate produced one.
    fn handle_initiation(
        &self,
        datagram: &[u8],
        from: SocketAddr,
        routed: RoutedKind,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        if let Some(limiter) = self.rate_limiter.as_ref() {
            // A cookie reply is at most COOKIE_REPLY_SZ (64) bytes.
            let mut scratch = [0u8; 256];
            match limiter.verify_packet(Some(from.ip()), datagram, &mut scratch) {
                Ok(_) => {}
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    return Some((cookie.to_vec(), from));
                }
                // MAC1 mismatch (not addressed to this device) or rate limited:
                // drop without touching any channel.
                Err(_) => return None,
            }
        }
        // Bounded, drop-on-full -- the same tolerates-loss semantics as
        // every other demux path in this file. A full queue here means
        // the worker pool is genuinely saturated (not merely "many peers
        // registered", which M3 Pass 2's whole point is to make no longer
        // matter) -- WireGuard's own retry timers cover a dropped
        // initiation the same way they already cover any other lost
        // packet.
        if self.handshake_ingress_tx.try_send((datagram.to_vec(), from, routed)).is_err() {
            tracing::debug!("dropped handshake initiation: ingress queue full");
        }
        None
    }

    /// M3 Pass 2: runs in a worker pool, OFF the single shared receive
    /// loop -- see `handle_initiation`'s own doc comment for why
    /// everything past the MAC1 gate lives here instead.
    ///
    /// The algorithmic fix this pass exists to land: `boringtun` already
    /// exposes exactly the seam WireGuard's own Noise IK handshake design
    /// makes possible -- `parse_handshake_anon` decrypts message-1's
    /// `encrypted_static` field using ONLY this device's own static
    /// private key and the packet's own (plaintext) ephemeral public key,
    /// revealing the real initiator's static public key with ONE
    /// Diffie-Hellman + ONE AEAD decrypt, REGARDLESS of how many peers
    /// this device has registered -- no candidate-key trial-decryption
    /// required (see boringtun's own `noise::handshake::parse_handshake_
    /// anon`/`HalfHandshake`, and its `device` module's own reference
    /// demux, which uses exactly this pattern). Once identified, a single
    /// hash-map lookup (`by_peer_public`) finds the ONE channel to
    /// dispatch to -- that channel's own actor still runs the real,
    /// full, session-establishing `Tunn::decapsulate` on ITS OWN tunnel
    /// exactly as before (a Codex-review clarification: `handle_incoming`
    /// (`tunn_wrapper.rs`) calls `decapsulate` a second time with an
    /// empty datagram per boringtun's own documented drain contract --
    /// still O(1) work on the ONE correctly-identified channel's tunnel,
    /// not a second trial against a different peer), but now against
    /// ONE channel per initiation, not every REGISTERED PEER's channel
    /// per initiation. This is what actually closes the O(N^2) cost the
    /// `handshake_fan_in.rs` reproducer measured (M3 Pass 1) -- a bounded
    /// queue and worker pool alone (M3 Pass 2's OTHER half, above and in
    /// `TransportHub::assemble`) only bounds concurrency; it does not
    /// reduce the total crypto work, which is what this function does.
    ///
    /// Falls back to the OLD broadcast-to-every-channel behavior
    /// (`offer_initiation`) only when [`Self::device_identity`] was never
    /// set -- every real production caller DOES set it (see
    /// `TransportHub::set_device_identity`'s own doc comment); this
    /// fallback exists purely for backward compatibility with existing
    /// callers/tests that construct a hub without a device identity at
    /// all, not as a normal operating mode.
    fn identify_and_route_initiation(&self, datagram: &[u8], from: SocketAddr, routed: RoutedKind) {
        let Ok(Packet::HandshakeInit(parsed)) = Tunn::parse_incoming_packet(datagram) else {
            // Re-parses (recv_loop already parsed this once to route it
            // here at all) -- cheap, structural-only, and avoids needing
            // to thread a borrowed, buffer-lifetime-tied parse result
            // through the ingress queue's owned `Vec<u8>` item.
            return;
        };
        let Some((device_secret, device_public)) = self.device_identity.get() else {
            self.offer_initiation(datagram, from, routed);
            return;
        };
        match parse_handshake_anon(device_secret, device_public, &parsed) {
            Ok(half) => {
                let session_index = {
                    let by_peer_public =
                        self.by_peer_public.lock().unwrap_or_else(|p| p.into_inner());
                    by_peer_public.get(&half.peer_static_public).copied()
                };
                let Some(session_index) = session_index else {
                    // Identified, but no locally-registered channel for
                    // that public key -- an unrecognized/unauthorized
                    // initiator. Correct WireGuard behavior is to drop,
                    // not to fall back to trying every channel: identity
                    // resolution already succeeded, it just didn't match
                    // anyone we know.
                    return;
                };
                let channels = self.channels.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(entry) = channels.get(&session_index) {
                    if let Err(mpsc::error::TrySendError::Full(_)) =
                        entry.sender.try_send(InboundDatagram {
                            data: datagram.to_vec(),
                            from,
                            kind: routed.probe_kind(),
                        })
                    {
                        tracing::debug!(
                            session_index,
                            "dropped identified handshake initiation: channel demux queue full"
                        );
                    }
                }
            }
            // Malformed, replayed, or otherwise not a genuine message-1
            // -- drop. Never falls back to the broadcast path: a packet
            // that fails identity resolution isn't an ambiguous case
            // needing trial-decryption against every peer, it's simply
            // not a valid initiation.
            Err(_) => {
                tracing::debug!("dropped handshake initiation: identity resolution failed");
            }
        }
    }

    /// The back-compat fallback path (see `identify_and_route_initiation`'s
    /// own doc comment for when this actually runs): offers a MAC1-
    /// verified initiation to every authorized channel, ordering those
    /// whose known candidates match the source endpoint first. Only the
    /// channel whose static key decapsulates it adopts the exchange. This
    /// is the ORIGINAL, pre-M3-Pass-2 behavior, preserved unconditionally
    /// for any caller that never provides a device identity.
    fn offer_initiation(&self, datagram: &[u8], from: SocketAddr, routed: RoutedKind) {
        let channels = self.channels.lock().unwrap_or_else(|p| p.into_inner());
        let src_ip = from.ip();
        // `false` (source-matching) sorts before `true`, so matching channels
        // are offered the initiation first.
        let mut ordered: Vec<&ChannelEntry> = channels.values().collect();
        ordered.sort_by_key(|entry| !entry.candidate_ips.contains(&src_ip));
        // M3 Pass 1: was `let _ = ...`, same silent-drop gap as
        // `route_by_index` above -- log-only, no behavior change. Matched
        // specifically on `Full`, same reasoning as `route_by_index`.
        for entry in ordered {
            if let Err(mpsc::error::TrySendError::Full(_)) =
                entry.sender.try_send(InboundDatagram {
                    data: datagram.to_vec(),
                    from,
                    kind: routed.probe_kind(),
                })
            {
                tracing::debug!("dropped handshake-initiation probe: channel demux queue full");
            }
        }
    }

    fn maybe_route_stun(&self, datagram: &[u8], from: SocketAddr) {
        if !stun::message::is_message(datagram) || datagram.len() < 20 {
            return;
        }
        let mut txn = [0u8; 12];
        txn.copy_from_slice(&datagram[8..20]);
        {
            let mut pending = self.stun_pending.lock().unwrap_or_else(|p| p.into_inner());
            match pending.iter().position(|t| *t == txn) {
                Some(pos) => {
                    pending.remove(pos); // one response per request
                }
                None => return, // unknown transaction id: drop
            }
        }
        if let Some(tx) = self.stun_tx.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = tx.try_send((datagram.to_vec(), from));
        }
    }

    fn register_stun_txn(&self, txn: [u8; 12]) {
        let mut pending = self.stun_pending.lock().unwrap_or_else(|p| p.into_inner());
        if pending.len() >= STUN_PENDING_DEPTH {
            pending.pop_front();
        }
        pending.push_back(txn);
    }
}

/// One logical UDP endpoint: an IPv4 socket and an IPv6 socket bound to the
/// *same* port (the IPv6 half is v6-only so the two do not collide), presenting
/// one logical port to peers. Either half may be absent — production binds
/// both; the simulation harness / `from_socket` adopts a single socket, and a
/// host with no usable IPv6 keeps only the v4 half. A datagram is sent from the
/// socket matching the destination's address family, so candidate addresses
/// stay real v4 / v6 (no v4-mapped ambiguity).
struct UdpEndpoint {
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
    batching: UdpBatchingSupport,
}

impl UdpEndpoint {
    fn socket_for(&self, addr: SocketAddr) -> io::Result<&Arc<UdpSocket>> {
        let sock = if addr.is_ipv4() { self.v4.as_ref() } else { self.v6.as_ref() };
        sock.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no socket bound for this destination address family",
            )
        })
    }

    async fn send_batch(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> io::Result<usize> {
        self.batching.send_batch(self.socket_for(addr)?, datagrams, addr).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let socket = self.socket_for(addr)?;
        // `madsim`'s simulated `send_to` takes `(dst, buf)`, the reverse of
        // real tokio's `(buf, dst)` — the shim quirk `udp_batching` and
        // `local_discovery` document.
        #[cfg(not(madsim))]
        {
            socket.send_to(buf, addr).await
        }
        #[cfg(madsim)]
        {
            socket.send_to(addr, buf).await.map(|()| buf.len())
        }
    }
}

/// Widens a UDP socket's kernel receive/send buffers well past the OS
/// default, which is far too small for this application's actual traffic
/// pattern: a single large sync-engine block (default 128 KiB) fragments
/// into ~110 datagrams that this device's actor loop enqueues in one burst
/// (`handle_outbound_batch`), and on the receiving side must all land in the
/// kernel's per-socket receive queue before user space drains any of them.
/// Confirmed as the actual root cause of a 100%-reproducing transport test
/// failure on Linux (never on macOS): Linux's default UDP receive buffer
/// (`net.core.rmem_default`, 208 KiB on a stock kernel) is smaller than one
/// burst's real kernel-accounted footprint (raw payload plus per-datagram
/// `sk_buff` overhead), so datagrams beyond the buffer's capacity are
/// silently dropped by the kernel before this process ever sees them --
/// deterministically, not as transient loss -- while macOS's much larger
/// default (`net.inet.udp.recvspace`, ~768 KiB) happens to comfortably
/// absorb the same burst. Reliable delivery retransmits the *whole* message
/// (not just the missing fragment) on timeout, so this repeats identically
/// on every retry: no timeout or retry budget fixes a genuine kernel-level
/// drop. 4 MiB comfortably covers several concurrent large-block transfers
/// on the one shared socket every channel funnels through, with real
/// margin above a single burst. Best-effort: some sandboxed environments
/// refuse to raise a socket's buffer past a lower administrative cap, which
/// is not fatal (the OS default is merely a worse starting point for the
/// same traffic, not a hard failure), so a rejection is only logged.
#[cfg(not(madsim))]
fn widen_socket_buffers(socket: &UdpSocket) {
    const BUFFER_SIZE: usize = 4 * 1024 * 1024;
    let sock_ref = socket2::SockRef::from(socket);
    if let Err(e) = sock_ref.set_recv_buffer_size(BUFFER_SIZE) {
        tracing::debug!(error = %e, "failed to widen UDP socket receive buffer");
    }
    if let Err(e) = sock_ref.set_send_buffer_size(BUFFER_SIZE) {
        tracing::debug!(error = %e, "failed to widen UDP socket send buffer");
    }
}

/// Binds a v6-only UDP socket on `port` (the same port the v4 half holds). The
/// `only_v6` flag is essential: without it the OS default (dual-stack on Linux)
/// would also claim v4 on `port` and collide with the separate v4 socket.
#[cfg(not(madsim))]
fn bind_v6_only(port: u16) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv6Addr, SocketAddrV6};

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
    let socket = UdpSocket::from_std(sock.into())?;
    widen_socket_buffers(&socket);
    Ok(socket)
}

/// The single per-device transport endpoint. Cloneable-by-`Arc`; every peer
/// channel and the NAT prober/mapper share one instance so all traffic — data
/// and candidate discovery alike — leaves from and returns to the same NAT
/// binding.
pub struct TransportHub {
    endpoint: Arc<UdpEndpoint>,
    local_addr: SocketAddr,
    registry: Arc<DemuxRegistry>,
    recv_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// M3 Pass 2: the fixed handshake-identification worker pool draining
    /// `registry`'s ingress queue -- see `identify_and_route_initiation`'s
    /// own doc comment. Aborted on drop the same as `recv_tasks`.
    handshake_worker_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Raw UDP payload byte counters for this hub's bound socket(s) —
    /// every datagram this hub sends or receives, regardless of whether the
    /// demux ultimately routes it to a channel, the STUN prober, or drops
    /// it. Exists for the M6 benchmark harness's "wire bytes" metric, which
    /// needs a ground truth the harness itself never had (see
    /// `crates/yadorilink-bench/DESIGN.md`); nothing in production reads
    /// these today.
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
    /// Datagram counts alongside the byte counters above, for a
    /// packets/sec metric.
    tx_packets: Arc<AtomicU64>,
    rx_packets: Arc<AtomicU64>,
}

impl Drop for TransportHub {
    fn drop(&mut self) {
        // Stop the receive loops and handshake workers when the last
        // handle goes away rather than leaving them parked holding the
        // sockets/queue open.
        for task in &self.recv_tasks {
            task.abort();
        }
        for task in &self.handshake_worker_tasks {
            task.abort();
        }
    }
}

impl TransportHub {
    /// Binds a fresh hub on `addr`'s port (use port 0 for an OS-chosen stable
    /// ephemeral port) and starts its receive loops. Production binds a
    /// dual-stack pair — an IPv4 socket on `addr` and a v6-only IPv6 socket on
    /// the same port — so a peer can be reached over either family. If the
    /// IPv6 half can't be bound (no usable v6, port race), the hub runs v4-only.
    /// `device_public` is this device's WireGuard static public key for the
    /// MAC1 initiation gate; `None` degrades the gate to offering initiations
    /// to every authorized channel.
    pub async fn bind(addr: SocketAddr, device_public: Option<PublicKey>) -> io::Result<Arc<Self>> {
        let primary = UdpSocket::bind(addr).await?;
        #[cfg(not(madsim))]
        widen_socket_buffers(&primary);
        let primary = Arc::new(primary);
        let local_addr = primary.local_addr()?;
        let (v4, v6) = if addr.is_ipv4() {
            #[cfg(not(madsim))]
            let v6 = bind_v6_only(local_addr.port()).ok().map(Arc::new);
            // Under simulation the shimmed socket has no dual-stack notion, so
            // the hub stays single-socket (v4), matching the harness.
            #[cfg(madsim)]
            let v6: Option<Arc<UdpSocket>> = None;
            if v6.is_none() {
                tracing::debug!("transport hub bound IPv4-only (no IPv6 half)");
            }
            (Some(primary), v6)
        } else {
            (None, Some(primary))
        };
        Ok(Self::assemble(v4, v6, local_addr, device_public))
    }

    /// Adopts an already-bound socket (the deterministic-simulation harness
    /// pre-binds one per device, as do most integration tests) as the
    /// endpoint's single half and starts its receive loop. Widens the
    /// adopted socket's kernel buffers the same way `bind`'s own sockets
    /// are (see `widen_socket_buffers`'s doc comment) -- skipped under
    /// simulation, where the shimmed socket has no real kernel buffer to
    /// widen.
    pub fn from_socket(socket: UdpSocket, device_public: Option<PublicKey>) -> Arc<Self> {
        #[cfg(not(madsim))]
        widen_socket_buffers(&socket);
        let local_addr =
            socket.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = Arc::new(socket);
        let (v4, v6) =
            if local_addr.is_ipv4() { (Some(socket), None) } else { (None, Some(socket)) };
        Self::assemble(v4, v6, local_addr, device_public)
    }

    /// Builds the hub from whichever address-family sockets are present,
    /// spawns one receive loop per socket, and (M3 Pass 2) spawns the
    /// fixed handshake-identification worker pool draining the registry's
    /// ingress queue.
    fn assemble(
        v4: Option<Arc<UdpSocket>>,
        v6: Option<Arc<UdpSocket>>,
        local_addr: SocketAddr,
        device_public: Option<PublicKey>,
    ) -> Arc<Self> {
        let endpoint = Arc::new(UdpEndpoint {
            v4: v4.clone(),
            v6: v6.clone(),
            batching: UdpBatchingSupport::detect(),
        });
        let (registry, handshake_ingress_rx) = DemuxRegistry::new(device_public);
        let registry = Arc::new(registry);
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let rx_packets = Arc::new(AtomicU64::new(0));
        let recv_tasks = [v4, v6]
            .into_iter()
            .flatten()
            .map(|sock| {
                tokio::spawn(recv_loop(
                    sock,
                    endpoint.clone(),
                    registry.clone(),
                    rx_bytes.clone(),
                    rx_packets.clone(),
                ))
            })
            .collect();
        // A single receiver shared across a fixed worker pool via
        // `tokio::sync::Mutex` -- `mpsc::Receiver` has no built-in
        // multi-consumer support, and this queue's throughput needs are
        // modest (handshake initiations only, not the data plane), so the
        // lock contention this adds is negligible next to the crypto work
        // each worker actually does per item.
        let handshake_ingress_rx = Arc::new(tokio::sync::Mutex::new(handshake_ingress_rx));
        let handshake_worker_tasks = (0..HANDSHAKE_WORKER_COUNT)
            .map(|_| tokio::spawn(handshake_worker(handshake_ingress_rx.clone(), registry.clone())))
            .collect();
        Arc::new(Self {
            endpoint,
            local_addr,
            registry,
            recv_tasks,
            handshake_worker_tasks,
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes,
            tx_packets: Arc::new(AtomicU64::new(0)),
            rx_packets,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// M3 Pass 2: provides this device's own WireGuard static keypair so
    /// `identify_and_route_initiation` can resolve an incoming
    /// initiation's real sender in O(1) crypto work instead of falling
    /// back to trial-broadcasting it to every registered channel -- see
    /// that function's own doc comment for the full mechanism. Optional
    /// and idempotent (a second call is a silent no-op, matching this
    /// codebase's own `OnceLock::set`-and-discard convention elsewhere,
    /// e.g. `DaemonState::set_device_static_public`): every EXISTING
    /// caller that never calls this keeps working exactly as before
    /// (the pre-M3-Pass-2 broadcast fallback), so this is purely additive
    /// -- real production callers should call it once, right after
    /// constructing the hub, with the same static secret every
    /// `PeerChannel::connect` call for this device already uses.
    pub fn set_device_identity(&self, secret: StaticSecret) {
        let public = PublicKey::from(&secret);
        let _ = self.registry.device_identity.set((secret, public));
    }

    /// Registers a channel under its WireGuard session index and returns the
    /// receiver for datagrams the demultiplexer routes to it. `candidates`
    /// seed the source-narrowing used to order initiation trials (the
    /// back-compat broadcast fallback's own ordering -- see
    /// `offer_initiation`'s doc comment). `peer_public` is this channel's
    /// peer's own static public key (M3 Pass 2), indexed for O(1) exact
    /// dispatch once `identify_and_route_initiation` resolves an
    /// initiation's real sender. Datagrams for an unregistered index are
    /// dropped.
    pub fn register_channel(
        &self,
        session_index: u32,
        candidates: &[SocketAddr],
        peer_public: PublicKey,
    ) -> mpsc::Receiver<InboundDatagram> {
        let (tx, rx) = mpsc::channel(DEMUX_QUEUE_DEPTH);
        let candidate_ips = candidates.iter().map(|a| a.ip()).collect();
        let peer_public_bytes = peer_public.to_bytes();
        self.registry.channels.lock().unwrap_or_else(|p| p.into_inner()).insert(
            session_index,
            ChannelEntry { sender: tx, candidate_ips, peer_public: peer_public_bytes },
        );
        self.registry
            .by_peer_public
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer_public_bytes, session_index);
        rx
    }

    /// Adds a candidate IP for a channel's source-narrowing (called when the
    /// channel learns a new candidate at runtime).
    pub fn note_channel_candidate(&self, session_index: u32, addr: SocketAddr) {
        if let Some(entry) =
            self.registry.channels.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&session_index)
        {
            entry.candidate_ips.insert(addr.ip());
        }
    }

    /// Removes a channel's demux registration (on teardown/revocation).
    pub fn unregister_channel(&self, session_index: u32) {
        let removed =
            self.registry.channels.lock().unwrap_or_else(|p| p.into_inner()).remove(&session_index);
        if let Some(entry) = removed {
            // Removes by VALUE match, not merely by the key a caller
            // happens to supply: if a session index were ever reused
            // across channels (not expected today, but this is cheap
            // insurance), an unregister for the OLD channel must never
            // evict a DIFFERENT, newer channel that happens to now sit at
            // the same public-key entry.
            let mut by_peer_public =
                self.registry.by_peer_public.lock().unwrap_or_else(|p| p.into_inner());
            if by_peer_public.get(&entry.peer_public) == Some(&session_index) {
                by_peer_public.remove(&entry.peer_public);
            }
        }
    }

    /// Registers the STUN prober's receiver for recognized binding responses.
    pub fn register_stun(&self) -> mpsc::Receiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::channel(DEMUX_QUEUE_DEPTH);
        *self.registry.stun_tx.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
        rx
    }

    /// Records the transaction id of a binding request just sent, so its
    /// response passes the demux's known-transaction check.
    pub fn register_stun_txn(&self, txn: [u8; 12]) {
        self.registry.register_stun_txn(txn);
    }

    /// Sends a batch of datagrams to one address through the hub's endpoint.
    pub async fn send_batch(&self, datagrams: &[Vec<u8>], addr: SocketAddr) -> io::Result<usize> {
        let result = self.endpoint.send_batch(datagrams, addr).await;
        // `send_batch_fallback` returns `Ok` only once every datagram in the
        // slice has been individually sent (see its own doc comment) -- an
        // error aborts before returning, so there is no partial-success
        // count to reconcile against.
        if result.is_ok() {
            let sent: u64 = datagrams.iter().map(|d| d.len() as u64).sum();
            self.tx_bytes.fetch_add(sent, Ordering::Relaxed);
            self.tx_packets.fetch_add(datagrams.len() as u64, Ordering::Relaxed);
        }
        result
    }

    /// Sends a single datagram through the hub's endpoint.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let result = self.endpoint.send_to(buf, addr).await;
        if result.is_ok() {
            self.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Total raw UDP payload bytes this hub has sent, across every channel,
    /// STUN probe, and cookie reply sharing its socket(s) -- see the
    /// `tx_bytes` field doc for why this exists.
    pub fn wire_bytes_sent(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Total raw UDP payload bytes this hub has received, counted at the
    /// socket regardless of how the demux subsequently routes (or drops)
    /// each datagram -- see the `rx_bytes` field doc for why this exists.
    pub fn wire_bytes_received(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    /// Datagram counts to pair with `wire_bytes_sent`/`wire_bytes_received`
    /// for a packets/sec metric.
    pub fn wire_packets_sent(&self) -> u64 {
        self.tx_packets.load(Ordering::Relaxed)
    }

    pub fn wire_packets_received(&self) -> u64 {
        self.rx_packets.load(Ordering::Relaxed)
    }
}

async fn recv_loop(
    recv_socket: Arc<UdpSocket>,
    endpoint: Arc<UdpEndpoint>,
    registry: Arc<DemuxRegistry>,
    rx_bytes: Arc<AtomicU64>,
    rx_packets: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; MAX_WIREGUARD_DATAGRAM_LEN];
    loop {
        match recv_socket.recv_from(&mut buf).await {
            Ok((n, from)) => {
                rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                rx_packets.fetch_add(1, Ordering::Relaxed);
                // A cookie reply goes back out the family-matched socket.
                if let Some((reply, dst)) = registry.route(&buf[..n], from) {
                    let _ = endpoint.send_to(&reply, dst).await;
                }
            }
            Err(e) => {
                // A transient receive error should not kill the hub; back off
                // one scheduler yield and keep serving.
                tracing::debug!(error = %e, "transport hub receive error");
                tokio::task::yield_now().await;
            }
        }
    }
}

/// M3 Pass 2: one member of the fixed handshake-identification worker
/// pool -- drains `ingress_rx` (shared with its sibling workers behind a
/// `tokio::sync::Mutex`, since `mpsc::Receiver` has no built-in multi-
/// consumer support) and calls `identify_and_route_initiation` for each
/// item. See that function's own doc comment for the actual work done
/// here; this loop is just the plumbing that keeps it off `recv_loop`.
async fn handshake_worker(
    ingress_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr, RoutedKind)>>>,
    registry: Arc<DemuxRegistry>,
) {
    loop {
        // The lock is held only long enough to pull one item off the
        // queue -- `identify_and_route_initiation` (the actual crypto/
        // lookup work) runs after releasing it, so a slow identification
        // never blocks a sibling worker from picking up the NEXT queued
        // item.
        let next = { ingress_rx.lock().await.recv().await };
        match next {
            Some((datagram, from, routed)) => {
                registry.identify_and_route_initiation(&datagram, from, routed)
            }
            // The sender half (owned by `DemuxRegistry`, itself owned by
            // the `Arc<TransportHub>` this worker's own task holds a
            // clone of) is gone -- structurally unreachable while this
            // task is still running, since the task would already have
            // been aborted by `TransportHub::drop` first. Exit cleanly
            // rather than spin.
            None => break,
        }
    }
}

/// A [`StunSocket`] backed by the hub for sending and by the demux's STUN queue
/// for receiving, so binding requests leave from — and their responses are
/// attributed to — the exact socket that carries WireGuard data. Registers
/// each request's transaction id with the hub so only solicited responses are
/// routed back.
pub struct HubStunSocket {
    hub: Arc<TransportHub>,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl HubStunSocket {
    /// Registers a STUN receive queue on `hub` and returns a socket the prober
    /// can drive. Only one should be live per hub (registration replaces any
    /// previous one).
    pub fn new(hub: Arc<TransportHub>) -> Self {
        let rx = hub.register_stun();
        Self { hub, rx: tokio::sync::Mutex::new(rx) }
    }
}

impl StunSocket for HubStunSocket {
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> StunIoFuture<'a, usize> {
        // Remember this request's transaction id so its response is accepted.
        if buf.len() >= 20 {
            let mut txn = [0u8; 12];
            txn.copy_from_slice(&buf[8..20]);
            self.hub.register_stun_txn(txn);
        }
        Box::pin(async move { self.hub.send_to(buf, target).await })
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> StunIoFuture<'a, (usize, SocketAddr)> {
        Box::pin(async move {
            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some((data, from)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "hub STUN queue closed")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A minimal but structurally valid WireGuard transport-data packet whose
    /// receiver index is `receiver_idx`, so `parse_incoming_packet` classifies
    /// it as `PacketData` and the demux routes it by `receiver_idx >> 8`.
    fn wg_data_packet(receiver_idx: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&4u32.to_le_bytes()); // WireGuard DATA type
        pkt.extend_from_slice(&receiver_idx.to_le_bytes());
        pkt.extend_from_slice(&0u64.to_le_bytes()); // counter
        pkt.extend_from_slice(&[0u8; 20]); // encrypted payload padding to >= 32 bytes
        pkt
    }

    /// A binding request/response carrying `txn`, built via the same `stun`
    /// codec so the magic cookie and transaction id are laid out correctly.
    fn stun_message(txn: [u8; 12], success: bool) -> Vec<u8> {
        use stun::agent::TransactionId;
        use stun::message::{Message, BINDING_REQUEST, BINDING_SUCCESS};
        let mut msg = Message::new();
        let typ = if success { BINDING_SUCCESS } else { BINDING_REQUEST };
        msg.build(&[Box::new(typ), Box::new(TransactionId(txn))]).expect("encode stun");
        msg.raw
    }

    fn registry_without_gate() -> DemuxRegistry {
        // These unit tests exercise `DemuxRegistry` directly (no
        // `TransportHub`/worker pool spawned), so the ingress-queue
        // receiver half is unused here -- routing a handshake initiation
        // in these tests goes through `offer_initiation` directly (or, if
        // exercising `route()` itself, only cares about its enqueue-vs-
        // drop behavior, not what a worker would later do with it).
        let (registry, _handshake_ingress_rx) = DemuxRegistry::new(None);
        registry
    }

    #[test]
    fn routes_data_by_receiver_index() {
        let registry = registry_without_gate();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            7,
            ChannelEntry { sender: tx_a, candidate_ips: HashSet::new(), peer_public: [7u8; 32] },
        );
        registry.channels.lock().unwrap().insert(
            9,
            ChannelEntry { sender: tx_b, candidate_ips: HashSet::new(), peer_public: [9u8; 32] },
        );

        assert!(registry.route(&wg_data_packet((7 << 8) | 3), addr("203.0.113.1:5000")).is_none());

        let to_a = rx_a.try_recv().expect("session 7 receives its data");
        assert_eq!(to_a.kind, DatagramKind::Direct);
        assert!(rx_b.try_recv().is_err(), "session 9 must not receive session 7's data");
    }

    /// M3 Pass 8 closeout: the SAME opaque WireGuard bytes, wrapped in a
    /// relay envelope (`wrap_relay_envelope`, exactly as `yadorilink-
    /// daemon`'s `relay_forwarder.rs` does before its own raw socket send),
    /// route to the SAME channel by the SAME receiver index -- but tagged
    /// `DatagramKind::Relay`, not `Direct`. This is the demux-level half
    /// of the address-collision fix: even though the ENVELOPE's own
    /// carrier arrives at this exact function with an outer source
    /// address that could coincidentally match a known direct candidate
    /// (irrelevant here, since `route`/`route_kind` never even look at
    /// candidate lists -- that happens one layer up, in `PeerChannel`),
    /// the KIND alone is what proves provenance from this point on.
    #[test]
    fn relay_enveloped_datagram_routes_with_relay_kind() {
        let registry = registry_without_gate();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            7,
            ChannelEntry { sender: tx_a, candidate_ips: HashSet::new(), peer_public: [7u8; 32] },
        );

        let inner = wg_data_packet((7 << 8) | 3);
        let enveloped = wrap_relay_envelope(42, &inner);
        assert!(registry.route(&enveloped, addr("203.0.113.9:9999")).is_none());

        let to_a = rx_a.try_recv().expect("session 7 receives the unwrapped relay data");
        assert_eq!(to_a.kind, DatagramKind::Relay);
        assert_eq!(to_a.data, inner, "the envelope header must not leak into the inner data");
    }

    /// The relay-envelope marker (`0xFFFFFFFF`) is deliberately a value no
    /// real WireGuard message type ever produces -- if it were EVER
    /// misparsed as genuine WireGuard traffic instead, that would be a
    /// route-provenance hole of its own. Bytes that merely start with the
    /// marker but are too short to carry a full envelope header must
    /// simply fail to route (dropped), never partially unwrap.
    #[test]
    fn a_short_datagram_that_only_looks_like_an_envelope_header_is_dropped() {
        let registry = registry_without_gate();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            7,
            ChannelEntry { sender: tx_a, candidate_ips: HashSet::new(), peer_public: [7u8; 32] },
        );

        let mut too_short = RELAY_ENVELOPE_MARKER.to_vec();
        too_short.extend_from_slice(&[0u8; 3]); // short of the full u64 session id
        assert!(registry.route(&too_short, addr("203.0.113.9:9999")).is_none());
        assert!(rx_a.try_recv().is_err());
    }

    #[test]
    fn data_for_an_unregistered_index_is_dropped() {
        let registry = registry_without_gate();
        let (tx, mut rx) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            1,
            ChannelEntry { sender: tx, candidate_ips: HashSet::new(), peer_public: [1u8; 32] },
        );
        assert!(registry.route(&wg_data_packet((42 << 8) | 1), addr("203.0.113.1:5000")).is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stun_response_is_routed_only_for_a_known_transaction_id() {
        let registry = registry_without_gate();
        let (stun_tx, mut stun_rx) = mpsc::channel(8);
        *registry.stun_tx.lock().unwrap() = Some(stun_tx);

        let known = [1u8; 12];
        let unknown = [2u8; 12];
        registry.register_stun_txn(known);

        // Unknown transaction id → dropped.
        registry.route(&stun_message(unknown, true), addr("1.1.1.1:3478"));
        assert!(stun_rx.try_recv().is_err());

        // Known one → routed to the prober, and consumed (one response).
        registry.route(&stun_message(known, true), addr("1.1.1.1:3478"));
        assert!(stun_rx.try_recv().is_ok());
        registry.route(&stun_message(known, true), addr("1.1.1.1:3478"));
        assert!(stun_rx.try_recv().is_err(), "a transaction id is only good for one response");
    }

    #[test]
    fn initiation_without_gate_is_offered_source_matching_channel_first() {
        // Exercises `offer_initiation` directly, not through `route()` --
        // M3 Pass 2 moved everything past the (here, absent) MAC1 gate off
        // `route()`'s own call stack into a bounded ingress queue a worker
        // pool drains asynchronously, so a synchronous `route()` call can
        // no longer observe the routing outcome inline the way this test
        // (and its own name) needs to. `offer_initiation` is exactly the
        // ordering logic under test here, called with no `TransportHub`/
        // workers involved at all -- same coverage, no longer coupled to
        // the (now-async, elsewhere-tested) ingress-queue plumbing.
        let registry = registry_without_gate();
        let (tx_match, mut rx_match) = mpsc::channel(8);
        let (tx_other, mut rx_other) = mpsc::channel(8);
        let mut match_ips = HashSet::new();
        match_ips.insert(addr("198.51.100.4:41641").ip());
        registry.channels.lock().unwrap().insert(
            1,
            ChannelEntry { sender: tx_match, candidate_ips: match_ips, peer_public: [1u8; 32] },
        );
        registry.channels.lock().unwrap().insert(
            2,
            ChannelEntry {
                sender: tx_other,
                candidate_ips: HashSet::new(),
                peer_public: [2u8; 32],
            },
        );

        // A 148-byte handshake initiation (type in the first four bytes).
        let mut init = Vec::new();
        init.extend_from_slice(&1u32.to_le_bytes());
        init.extend_from_slice(&[0u8; 144]);
        registry.offer_initiation(&init, addr("198.51.100.4:41641"), RoutedKind::Direct);

        assert_eq!(rx_match.try_recv().unwrap().kind, DatagramKind::HandshakeProbe);
        assert_eq!(rx_other.try_recv().unwrap().kind, DatagramKind::HandshakeProbe);
    }

    /// M3 Pass 8 closeout (route-provenance review, Low): the sibling of
    /// `initiation_without_gate_is_offered_source_matching_channel_first`
    /// above, proving `RoutedKind::Relay` threads through the SAME
    /// broadcast-fallback path just as correctly as `RoutedKind::Direct`
    /// does -- a relay-enveloped handshake initiation (this device has no
    /// identity set, so `identify_and_route_initiation` falls back to
    /// `offer_initiation` exactly like the no-identity case above) must
    /// still be tagged `DatagramKind::Relay`, never `HandshakeProbe`.
    #[test]
    fn relay_routed_initiation_without_gate_is_offered_as_relay_kind() {
        let registry = registry_without_gate();
        let (tx, mut rx) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            1,
            ChannelEntry { sender: tx, candidate_ips: HashSet::new(), peer_public: [1u8; 32] },
        );

        let mut init = Vec::new();
        init.extend_from_slice(&1u32.to_le_bytes());
        init.extend_from_slice(&[0u8; 144]);
        registry.offer_initiation(&init, addr("198.51.100.4:41641"), RoutedKind::Relay);

        assert_eq!(rx.try_recv().unwrap().kind, DatagramKind::Relay);
    }

    /// M3 Pass 8 closeout (route-provenance review, Low): the queue-send
    /// half of the SAME gap -- `route()` itself, given a relay-enveloped
    /// handshake initiation, must enqueue it onto `handshake_ingress_tx`
    /// tagged `RoutedKind::Relay`, not silently default back to `Direct`.
    /// Doesn't need a running worker: `handshake_ingress_rx` is peeked
    /// directly, exercising exactly the one hop the review flagged as
    /// untested (`route`/`route_kind`/`handle_initiation`'s own queue
    /// send), independent of `identify_and_route_initiation`/`offer_
    /// initiation`, both already covered by their own dedicated tests.
    #[test]
    fn route_enqueues_a_relay_enveloped_initiation_tagged_as_relay() {
        let (registry, mut ingress_rx) = DemuxRegistry::new(None);

        let mut init = Vec::new();
        init.extend_from_slice(&1u32.to_le_bytes());
        init.extend_from_slice(&[0u8; 144]);
        let enveloped = wrap_relay_envelope(7, &init);

        assert!(registry.route(&enveloped, addr("198.51.100.4:41641")).is_none());

        let (queued_datagram, _from, routed) =
            ingress_rx.try_recv().expect("a relay-enveloped initiation must reach the queue");
        assert_eq!(queued_datagram, init, "the envelope header must not leak into the queued item");
        assert_eq!(routed, RoutedKind::Relay);
    }

    #[tokio::test]
    async fn endpoint_selects_socket_by_destination_family() {
        let v4 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let endpoint =
            UdpEndpoint { v4: Some(v4), v6: None, batching: UdpBatchingSupport::detect() };
        // A v4 destination resolves to the v4 socket.
        assert!(endpoint.socket_for(addr("127.0.0.1:9")).is_ok());
        // A v6 destination with no v6 half is a clean "no socket for family".
        let err = endpoint.socket_for("[::1]:9".parse().unwrap()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn bind_yields_a_stable_port_and_a_v4_half() {
        let hub = TransportHub::bind((std::net::Ipv4Addr::UNSPECIFIED, 0).into(), None)
            .await
            .expect("bind hub");
        assert_ne!(hub.local_port(), 0);
        // The v4 half is always present, so a v4 send never hits the
        // "no socket for family" path (it may still fail to route, but not for
        // lack of a socket).
        assert!(hub.endpoint.v4.is_some());
        // The v6 half is present whenever the host could bind it on the same
        // port; when it is, it shares the v4 half's port.
        if let Some(v6) = hub.endpoint.v6.as_ref() {
            assert_eq!(v6.local_addr().unwrap().port(), hub.local_port());
        }
    }

    #[test]
    fn junk_datagram_is_dropped() {
        let registry = registry_without_gate();
        let (tx, mut rx) = mpsc::channel(8);
        registry.channels.lock().unwrap().insert(
            1,
            ChannelEntry { sender: tx, candidate_ips: HashSet::new(), peer_public: [1u8; 32] },
        );
        let (stun_tx, mut stun_rx) = mpsc::channel(8);
        *registry.stun_tx.lock().unwrap() = Some(stun_tx);

        registry.route(&[0xAAu8; 64], addr("203.0.113.9:1234"));

        assert!(rx.try_recv().is_err());
        assert!(stun_rx.try_recv().is_err());
    }
}
