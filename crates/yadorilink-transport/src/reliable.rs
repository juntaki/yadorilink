//! A minimal ARQ (automatic-repeat-request) shim over the lossy
//! UDP/WireGuard datagram pipe (`peer_channel.rs`'s actor). Every
//! application-level message (already an opaque, encrypted-
//! at-a-lower-layer `Bytes` blob from this module's point of view) is
//! wrapped with a small header carrying a per-peer send sequence number
//! plus piggybacked ack info, retransmitted on an RTT-adaptive timeout
//! until acknowledged, and deduplicated on receipt — turning a single lost
//! datagram into a sub-second-to-few-seconds recovery instead of the 30s/
//! 90s per-message-type backstops (`DEFAULT_HYDRATION_TIMEOUT`, the full-
//! index resync interval) this replaces as the *primary* recovery path
//! (those backstops stay, demoted to last-resort).
//!
//! Reliable, NOT in-order: the sync protocol's version-vector-based apply
//! already tolerates reordering and re-delivery, so this only needs
//! "every message eventually arrives at least once" — no head-of-line
//! blocking, no reorder buffer.
//!
//! Self-describing wire framing (not a proto change): a legacy (pre-this-
//! change) `SyncMessage` encoding's first byte is always one of the
//! `oneof` field tags in `sync.proto` — `(field_num << 3) | 2` for a
//! length-delimited embedded message, `field_num` in 1..=9 today, so the
//! first byte is always in `{0x0A, 0x12, 0x1A, 0x22, 0x2A, 0x32, 0x3A,
//! 0x42, 0x4A}`. `FRAME_MARKER_DATA` (0x01) corresponds to protobuf field
//! 0 with wire type 1 (64-bit/fixed64) — field 0 does not exist in
//! protobuf, so this byte can never be the first byte of a legacy-encoded
//! message. `FRAME_MARKER_ACK` (0x02) is field 0/wire-type-2 (length-
//! delimited), equally impossible.
//! This makes every frame self-describing regardless of local negotiation
//! state, closing the negotiation race a "negotiate then switch" scheme
//! would otherwise have (`enable_reliable_delivery` flips independently on
//! each side once `ClusterConfig`'s `supports_reliable_delivery` bit
//! confirms mutual support — see `peer_session.rs`'s handshake).

use bytes::{BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

const FRAME_MARKER_DATA: u8 = 0x01;
const FRAME_MARKER_ACK: u8 = 0x02;
const DATA_HEADER_LEN: usize = 1 + 8 + 8 + 4; // marker + seq + ack_lo + ack_bits
const ACK_FRAME_LEN: usize = 1 + 8 + 4; // marker + ack_lo + ack_bits

/// A window of up to 32 out-of-order seqs above `ack_lo` — matches
/// `ack_bits`'s width. Selective acks beyond this window simply aren't
/// reported (the sender still retransmits them; they get cumulative-acked
/// once earlier gaps fill in), so this is a size/complexity trade-off, not
/// a correctness bound.
const SELECTIVE_ACK_WINDOW: u64 = 32;

/// ±25% jitter, matching the existing `NOT_FOUND_RETRY_JITTER_FRACTION`
/// convention elsewhere in the sync stack — see `ReliableSend::
/// due_retransmits`'s doc comment for why this matters here specifically
/// (de-correlating retransmits from an observed burst-correlated loss
/// pattern), not just avoiding synchronized retry storms in general.
fn jittered(base: Duration) -> Duration {
    const JITTER_FRACTION: f64 = 0.25;
    let jitter = rand::random_range(-JITTER_FRACTION..=JITTER_FRACTION);
    base.mul_f64(1.0 + jitter)
}

pub(crate) enum DecodedFrame {
    /// Not one of this layer's frames — pass through unchanged, exactly as
    /// before this layer existed (a peer that hasn't enabled reliable
    /// delivery, or a message sent before negotiation completed).
    Legacy(Bytes),
    Data {
        seq: u64,
        ack_lo: u64,
        ack_bits: u32,
        payload: Bytes,
    },
    Ack {
        ack_lo: u64,
        ack_bits: u32,
    },
}

pub(crate) fn decode_frame(bytes: Bytes) -> DecodedFrame {
    match bytes.first().copied() {
        Some(FRAME_MARKER_DATA) if bytes.len() >= DATA_HEADER_LEN => {
            let seq = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
            let ack_lo = u64::from_le_bytes(bytes[9..17].try_into().unwrap());
            let ack_bits = u32::from_le_bytes(bytes[17..21].try_into().unwrap());
            let payload = bytes.slice(DATA_HEADER_LEN..);
            DecodedFrame::Data { seq, ack_lo, ack_bits, payload }
        }
        Some(FRAME_MARKER_ACK) if bytes.len() == ACK_FRAME_LEN => {
            let ack_lo = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
            let ack_bits = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
            DecodedFrame::Ack { ack_lo, ack_bits }
        }
        _ => DecodedFrame::Legacy(bytes),
    }
}

fn encode_data_frame(seq: u64, ack_lo: u64, ack_bits: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(DATA_HEADER_LEN + payload.len());
    buf.put_u8(FRAME_MARKER_DATA);
    buf.put_u64_le(seq);
    buf.put_u64_le(ack_lo);
    buf.put_u32_le(ack_bits);
    buf.put_slice(payload);
    buf.freeze()
}

pub(crate) fn encode_ack_frame(ack_lo: u64, ack_bits: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(ACK_FRAME_LEN);
    buf.put_u8(FRAME_MARKER_ACK);
    buf.put_u64_le(ack_lo);
    buf.put_u32_le(ack_bits);
    buf.freeze()
}

/// A self-contained EWMA smoothed-RTT estimator, local to this layer.
/// `yadorilink_sync_core::adaptive_window::AdaptiveWindow` already tracks a
/// smoothed RTT, but `sync-core` *depends on* `yadorilink-transport` (see
/// that crate's `Cargo.toml`) — this layer lives in `yadorilink-transport`
/// itself, so reusing `AdaptiveWindow` directly would be a reverse
/// dependency. This mirrors its EWMA approach (same shape of estimator)
/// without sharing the type; it tracks RTT only, not a congestion window
/// (this layer's retransmit timing needs a timeout, not an in-flight cap).
struct RttEstimator {
    smoothed: Option<Duration>,
}

impl RttEstimator {
    const EWMA_ALPHA: f64 = 0.25;
    /// Retransmit timeout = `RTO_MULTIPLIER * smoothed_RTT`, clamped to
    /// `[MIN_RTO, MAX_RTO]`. `RTO_MULTIPLIER` of 4 leaves comfortable
    /// margin above ordinary jitter (observed same-session RTTs are
    /// single-digit milliseconds — DST trace, 2026-07-09) before treating a
    /// message as lost, while `MIN_RTO` keeps a still-RTT-naive connection
    /// (no samples yet) from retransmitting too eagerly and `MAX_RTO`
    /// bounds the worst case far below the 30s/90s backstops this layer
    /// replaces as the primary recovery path.
    const RTO_MULTIPLIER: f64 = 4.0;
    const MIN_RTO: Duration = Duration::from_millis(100);
    const MAX_RTO: Duration = Duration::from_secs(5);
    /// Used before any RTT sample exists yet (the very first message(s) on
    /// a fresh connection) — conservative (higher than `MIN_RTO` alone)
    /// since there is no signal yet about this link's real latency.
    const INITIAL_RTO: Duration = Duration::from_millis(300);

    fn new() -> Self {
        Self { smoothed: None }
    }

    fn on_sample(&mut self, rtt: Duration) {
        self.smoothed = Some(match self.smoothed {
            None => rtt,
            Some(prev) => Duration::from_secs_f64(
                prev.as_secs_f64() * (1.0 - Self::EWMA_ALPHA)
                    + rtt.as_secs_f64() * Self::EWMA_ALPHA,
            ),
        });
    }

    fn retransmit_timeout(&self) -> Duration {
        match self.smoothed {
            Some(rtt) => rtt.mul_f64(Self::RTO_MULTIPLIER).clamp(Self::MIN_RTO, Self::MAX_RTO),
            None => Self::INITIAL_RTO,
        }
    }
}

struct UnackedEntry {
    frame: Bytes,
    sent_at: Instant,
    attempts: u32,
}

/// Result of one `ReliableSend::due_retransmits` call -- see that method's
/// own doc comment for why `exhausted` means the caller must tear down the
/// whole channel, not just skip the one seq.
pub(crate) struct RetransmitOutcome {
    pub(crate) due: Vec<Bytes>,
    pub(crate) exhausted: bool,
}

/// How many times an unacked message is retransmitted before this layer
/// gives up on it (the message is dropped from the buffer; existing
/// liveness/backstop mechanisms — `DIRECT_LIVENESS_TIMEOUT`, the 30s/90s
/// per-type backstops — cover a peer that is genuinely gone, not this
/// layer). Bounds the buffer's worst-case retransmit cost per message at
/// `MAX_RETRANSMIT_ATTEMPTS * MAX_RTO` (a few tens of seconds), never
/// unbounded.
const MAX_RETRANSMIT_ATTEMPTS: u32 = 8;

/// Caps the exponential-backoff-multiplied retransmit deadline
/// (`ReliableSend::due_retransmits`) — without this, `RttEstimator::MAX_RTO`
/// (5s) times the backoff multiplier's own cap (16x) could reach 80s,
/// defeating the point of replacing the 30s/90s backstops this layer
/// exists to beat.
const MAX_BACKED_OFF_RTO: Duration = Duration::from_secs(8);

/// Send-side state: per-peer sequence assignment, the unacked-retransmit
/// buffer, and the RTT estimator driving retransmit timing. Owned solely
/// by the actor task (`ActorState`) — no external synchronization needed.
pub(crate) struct ReliableSend {
    next_seq: u64,
    unacked: BTreeMap<u64, UnackedEntry>,
    rtt: RttEstimator,
}

impl ReliableSend {
    pub(crate) fn new() -> Self {
        // Seq starts at 1 so 0 is free to mean "nothing sent/received yet"
        // on the receive side (`ReliableRecv::highest_contiguous`).
        Self { next_seq: 1, unacked: BTreeMap::new(), rtt: RttEstimator::new() }
    }

    /// Bounded per-peer buffer ("bounded buffers + backpressure, never
    /// unbounded memory"): once this many messages are awaiting ack,
    /// further sends block until one clears. Mirrors the existing
    /// `MAX_IN_FLIGHT_MESSAGES_PER_PEER` semaphore's role one layer down —
    /// this is about unacked *reliable-delivery* frames specifically, not
    /// the broader in-flight-message-processing bound.
    pub(crate) const MAX_UNACKED: usize = 256;

    pub(crate) fn is_full(&self) -> bool {
        self.unacked.len() >= Self::MAX_UNACKED
    }

    /// How many more entries can be tracked before hitting `MAX_UNACKED`.
    /// The caller-side credit `handle_outbound_batch` must reserve BEFORE
    /// dequeueing a batch, not re-check via `is_full()` mid-batch: `unacked`
    /// only grows inside `wrap_and_track`, so a stale `is_full()` read taken
    /// once before a multi-payload batch can't see the batch's own,
    /// still-in-progress growth -- see `wrap_and_track`'s own doc comment
    /// and `handle_outbound_batch_never_overcommits_the_unacked_window`.
    pub(crate) fn remaining_capacity(&self) -> usize {
        Self::MAX_UNACKED.saturating_sub(self.unacked.len())
    }

    #[cfg(test)]
    pub(crate) fn unacked_len(&self) -> usize {
        self.unacked.len()
    }

    /// Assigns the next sequence number and wraps `payload` into a DATA
    /// frame carrying `ack_lo`/`ack_bits` (the current receive-side ack
    /// state, piggybacked so a standalone ack frame is only needed when
    /// there is no outbound traffic to ride along with), tracking it in
    /// the unacked buffer for retransmission. Returns the encoded frame
    /// ready to hand to `WgTunnel::encrypt_message`.
    ///
    /// Deliberately unbounded here -- capping `MAX_UNACKED` is the
    /// CALLER's job (reserve capacity via `remaining_capacity` before
    /// dequeueing a batch to wrap; see that method's own doc comment for
    /// why an in-loop `is_full()` re-check is not equivalent). This method
    /// only asserts the invariant its caller is supposed to already be
    /// upholding, so a violation fails loudly at the call site that broke
    /// it rather than silently growing the window past its bound.
    pub(crate) fn wrap_and_track(&mut self, payload: &[u8], ack_lo: u64, ack_bits: u32) -> Bytes {
        debug_assert!(
            self.unacked.len() < Self::MAX_UNACKED,
            "reliable send window overcommitted: {} entries already tracked at MAX_UNACKED={}",
            self.unacked.len(),
            Self::MAX_UNACKED
        );
        let seq = self.next_seq;
        self.next_seq += 1;
        let frame = encode_data_frame(seq, ack_lo, ack_bits, payload);
        self.unacked.insert(
            seq,
            UnackedEntry { frame: frame.clone(), sent_at: Instant::now(), attempts: 1 },
        );
        frame
    }

    /// Clears acked entries (cumulative `ack_lo` plus the selective
    /// `ack_bits` window above it) and feeds each cleared entry's
    /// round-trip time into the RTT estimator.
    pub(crate) fn on_ack(&mut self, ack_lo: u64, ack_bits: u32) {
        let cumulative: Vec<u64> = self.unacked.range(..=ack_lo).map(|(seq, _)| *seq).collect();
        for seq in cumulative {
            if let Some(entry) = self.unacked.remove(&seq) {
                self.rtt.on_sample(entry.sent_at.elapsed());
            }
        }
        for i in 0..32u64 {
            if ack_bits & (1 << i) != 0 {
                if let Some(entry) = self.unacked.remove(&(ack_lo + 1 + i)) {
                    self.rtt.on_sample(entry.sent_at.elapsed());
                }
            }
        }
    }

    /// Returns frames whose retransmit deadline has passed, bumping their
    /// attempt count, PLUS whether any entry exhausted
    /// `MAX_RETRANSMIT_ATTEMPTS` this call.
    ///
    /// An exhausted entry is NOT silently dropped-and-continued: this
    /// layer is reliable-but-not-ordered, not reliable-but-partial. Once a
    /// receiver's `highest_contiguous` frontier is stuck behind a seq that
    /// truly never arrives, EVERY later seq is permanently unrepresentable
    /// by the cumulative ack and, once enough later traffic accumulates,
    /// eventually falls outside `SELECTIVE_ACK_WINDOW` too — an alive,
    /// actively-receiving peer becomes indistinguishable from an
    /// unreachable one for the rest of this ARQ epoch (see
    /// `a_permanently_lost_seq_poisons_the_cumulative_ack_forever` and
    /// `exhausted_retransmit_gives_up_while_receiver_is_still_alive_and_
    /// receiving`, this module's own characterization tests). Dropping
    /// only the one exhausted seq and continuing the same sequence space
    /// -- the previous behavior -- left that poisoning permanent for the
    /// rest of the connection's life. The caller (`peer_channel.rs`'s
    /// `reliable_send_due`) must therefore treat `exhausted` as "this
    /// channel's ARQ epoch is no longer trustworthy, tear it down" -- a
    /// fresh reconnect starts a fresh sequence space, which existing
    /// liveness/reachability machinery already re-establishes exactly like
    /// any other channel failure.
    ///
    /// Each entry's deadline is `RttEstimator::retransmit_timeout`,
    /// doubled per retry attempt already made (exponential backoff — a
    /// link that's actually losing repeatedly shouldn't be hammered at a
    /// fixed rate) and independently jittered (±25%, same fraction as the
    /// existing `NOT_FOUND_RETRY_JITTER_FRACTION` convention). The jitter
    /// is not cosmetic: this layer's own investigation (DST trace,
    /// 2026-07-09) found the underlying transport loses datagrams in a
    /// *burst-correlated* way (two datagrams sent close together were both
    /// lost together) — retransmitting every entry at an identical,
    /// deterministic offset from its send time would re-hit the same burst
    /// window on every attempt instead of de-correlating from it.
    pub(crate) fn due_retransmits(&mut self) -> RetransmitOutcome {
        let now = Instant::now();
        let mut due = Vec::new();
        let mut exhausted = Vec::new();
        for (seq, entry) in self.unacked.iter_mut() {
            let backoff = 2u32.saturating_pow(entry.attempts.saturating_sub(1)).min(16);
            let rto = jittered((self.rtt.retransmit_timeout() * backoff).min(MAX_BACKED_OFF_RTO));
            if now.duration_since(entry.sent_at) < rto {
                continue;
            }
            if entry.attempts >= MAX_RETRANSMIT_ATTEMPTS {
                // Anti-silent-drop: this message is being given up on after
                // exhausting every retransmit attempt — the same class of
                // silent-loss failure mode this session spent considerable
                // effort chasing elsewhere (lost block-fetches, lost
                // index-updates). Unlike a plain per-message drop, this now
                // also poisons the whole channel's ARQ epoch (see this
                // method's own doc comment) -- the caller tears the channel
                // down instead of continuing to trust it.
                tracing::warn!(
                    seq,
                    attempts = entry.attempts,
                    frame_len = entry.frame.len(),
                    "reliable-delivery exhausted every retransmit attempt for a seq; tearing \
                     down this channel's ARQ epoch rather than silently continuing with a \
                     permanently-poisoned ack frontier"
                );
                exhausted.push(*seq);
            } else {
                entry.attempts += 1;
                entry.sent_at = now;
                due.push(entry.frame.clone());
            }
        }
        let any_exhausted = !exhausted.is_empty();
        for seq in exhausted {
            self.unacked.remove(&seq);
        }
        RetransmitOutcome { due, exhausted: any_exhausted }
    }
}

/// Receive-side state: duplicate suppression + the ack info to report
/// back. Owned solely by the actor task.
pub(crate) struct ReliableRecv {
    /// Everything with seq `<= highest_contiguous` has been delivered.
    /// Starts at 0 ("nothing yet") since real seqs start at 1.
    highest_contiguous: u64,
    /// Seqs `> highest_contiguous` already delivered out of order —
    /// bounded by `SELECTIVE_ACK_WINDOW`-scale gaps in practice (this
    /// layer is reliable, not ordered, so a later seq can arrive and be
    /// delivered before an earlier gap fills in).
    out_of_order: HashSet<u64>,
    /// Set whenever new ack-worthy state arrives (a DATA frame observed,
    /// new or duplicate); cleared once an ack (piggybacked or standalone)
    /// carrying the current state has actually been sent. Checked
    /// independently of this device's own `reliable_enabled` send-mode
    /// (an ack for a received frame must go out even before this side has
    /// enabled sending its own reliable-framed messages — see
    /// `peer_channel.rs`'s retransmit-tick doc comment).
    ack_dirty: bool,
}

impl ReliableRecv {
    pub(crate) fn new() -> Self {
        Self { highest_contiguous: 0, out_of_order: HashSet::new(), ack_dirty: false }
    }

    #[cfg(test)]
    pub(crate) fn highest_contiguous(&self) -> u64 {
        self.highest_contiguous
    }

    /// Records `seq` as received; returns `true` if this is the first time
    /// (deliver to the application) or `false` if it's a retransmit of an
    /// already-delivered seq (drop the payload, but the caller still acks).
    pub(crate) fn observe(&mut self, seq: u64) -> bool {
        self.ack_dirty = true;
        if seq <= self.highest_contiguous {
            return false;
        }
        if !self.out_of_order.insert(seq) {
            return false;
        }
        while self.out_of_order.remove(&(self.highest_contiguous + 1)) {
            self.highest_contiguous += 1;
        }
        true
    }

    /// The current `(ack_lo, ack_bits)` to report — cumulative low-water
    /// mark plus a bitmap of out-of-order seqs received within
    /// `SELECTIVE_ACK_WINDOW` above it.
    pub(crate) fn current_ack(&self) -> (u64, u32) {
        let ack_lo = self.highest_contiguous;
        let mut bits = 0u32;
        for i in 0..SELECTIVE_ACK_WINDOW {
            if self.out_of_order.contains(&(ack_lo + 1 + i)) {
                bits |= 1 << i;
            }
        }
        (ack_lo, bits)
    }

    /// Returns whether an ack is due and clears the flag — call this right
    /// before actually sending an ack (piggybacked or standalone) so a
    /// send that fails to go out (e.g. encrypt error) doesn't silently
    /// lose the "ack is due" signal; on failure the caller should not have
    /// called this, or should treat it as still dirty. In practice both
    /// callers (piggyback in `handle_outbound_batch`, standalone on the
    /// retransmit tick) call this only once they're committed to sending.
    pub(crate) fn take_ack_dirty(&mut self) -> bool {
        std::mem::replace(&mut self.ack_dirty, false)
    }

    /// Non-mutating peek at whether an ack is due — used to decide whether
    /// the retransmit-tick branch should even run this iteration (see
    /// `peer_channel.rs`'s `reliable_tick` gating) without consuming the
    /// dirty flag the way [`take_ack_dirty`](Self::take_ack_dirty) does.
    pub(crate) fn has_pending_ack(&self) -> bool {
        self.ack_dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_bytes_never_decode_as_data_or_ack() {
        // Every possible SyncMessage oneof field (1..=9), length-delimited
        // wire type -- the complete, real set of first bytes a legacy
        // encoding can ever produce.
        for field in 1u8..=9 {
            let first_byte = (field << 3) | 2;
            assert_ne!(first_byte, FRAME_MARKER_DATA);
            assert_ne!(first_byte, FRAME_MARKER_ACK);
        }
    }

    #[test]
    fn round_trip_data_frame() {
        let frame = encode_data_frame(42, 10, 0b101, b"hello");
        match decode_frame(frame) {
            DecodedFrame::Data { seq, ack_lo, ack_bits, payload } => {
                assert_eq!(seq, 42);
                assert_eq!(ack_lo, 10);
                assert_eq!(ack_bits, 0b101);
                assert_eq!(&payload[..], b"hello");
            }
            _ => panic!("expected Data frame"),
        }
    }

    #[test]
    fn round_trip_ack_frame() {
        let frame = encode_ack_frame(7, 0b11);
        match decode_frame(frame) {
            DecodedFrame::Ack { ack_lo, ack_bits } => {
                assert_eq!(ack_lo, 7);
                assert_eq!(ack_bits, 0b11);
            }
            _ => panic!("expected Ack frame"),
        }
    }

    #[test]
    fn short_or_unrecognized_bytes_are_legacy() {
        assert!(matches!(decode_frame(Bytes::from_static(&[0x0A, 0x01])), DecodedFrame::Legacy(_)));
        assert!(matches!(
            decode_frame(Bytes::from_static(&[FRAME_MARKER_DATA])),
            DecodedFrame::Legacy(_)
        ));
        assert!(matches!(decode_frame(Bytes::new()), DecodedFrame::Legacy(_)));
    }

    #[test]
    fn recv_dedup_delivers_once_and_advances_contiguous() {
        let mut recv = ReliableRecv::new();
        assert!(recv.observe(1));
        assert!(!recv.observe(1)); // duplicate
        assert!(recv.observe(3)); // out of order
        assert_eq!(recv.current_ack(), (1, 0b10)); // seq 3 = ack_lo(1)+1+1, bit index 1
        assert!(recv.observe(2)); // fills the gap
        assert_eq!(recv.current_ack().0, 3); // now contiguous through 3
    }

    /// A single permanently-lost seq poisons `highest_contiguous` forever:
    /// the receiver has no "give up and skip a gap" mechanism, so once a
    /// seq is truly never going to arrive, every later seq is stuck
    /// out-of-order and unackable via the cumulative low-water mark.
    /// `SELECTIVE_ACK_WINDOW` only covers 32 slots above `ack_lo`, so once
    /// enough later traffic arrives, even the selective ack can no longer
    /// represent it -- from the sender's point of view, a peer that has
    /// actually received (and delivered to its application) dozens of
    /// later messages looks indistinguishable from one that received
    /// nothing at all past seq 9.
    #[test]
    fn a_permanently_lost_seq_poisons_the_cumulative_ack_forever() {
        let mut recv = ReliableRecv::new();
        for seq in 1..=9u64 {
            assert!(recv.observe(seq));
        }
        // seq 10 is never observed -- permanently lost.
        for seq in 11..=50u64 {
            recv.observe(seq);
        }
        let (ack_lo, ack_bits) = recv.current_ack();
        assert_eq!(
            ack_lo, 9,
            "highest_contiguous is stuck at 9 despite 40 later messages (11..=50) having been \
             delivered to the application"
        );
        // seq 42 = ack_lo + 1 + 32, one past the last representable
        // selective-ack bit (index 31 covers ack_lo + 1 + 31 = 41).
        assert_eq!(ack_bits & (1 << 31), 1 << 31, "seq 41 is still representable (last in-window)");
        // Nothing beyond the window is representable at all -- there is no
        // bit for seq 42, 43, ..., 50: `current_ack` structurally cannot
        // report them regardless of how much later traffic keeps arriving.
    }

    /// The other half of the same poisoning, from the sender's side: once
    /// `due_retransmits` gives up on a seq (its own doc comment: "the peer
    /// is presumed unreachable"), that presumption is false whenever the
    /// receiver is alive and receiving everything else -- the message is
    /// simply dropped from `unacked` and never sent again, matching
    /// `a_permanently_lost_seq_poisons_the_cumulative_ack_forever`'s
    /// receive-side finding: the receiver was never actually unreachable,
    /// it just can never report catching up on this one seq.
    #[test]
    fn exhausted_retransmit_gives_up_while_receiver_is_still_alive_and_receiving() {
        let mut send = ReliableSend::new();
        // Directly construct an already-exhausted, long-overdue entry
        // (same crate/module -- `UnackedEntry`'s fields are private to
        // `reliable.rs`) rather than waiting out real retransmit
        // backoff/RTO delays (tens of real seconds) in a unit test.
        send.unacked.insert(
            10,
            UnackedEntry {
                frame: encode_data_frame(10, 0, 0, b"lost"),
                sent_at: Instant::now() - Duration::from_secs(100),
                attempts: MAX_RETRANSMIT_ATTEMPTS,
            },
        );
        let outcome = send.due_retransmits();
        assert!(
            outcome.due.is_empty(),
            "an already-exhausted entry produces no further retransmit"
        );
        assert!(
            outcome.exhausted,
            "the caller must be told this seq exhausted its retransmit budget, so it can tear \
             the whole channel down instead of silently continuing"
        );
        assert!(
            !send.unacked.contains_key(&10),
            "the exhausted entry is removed from the unacked buffer (the channel is about to be \
             torn down regardless, so nothing depends on retrying it further)"
        );

        // Meanwhile the receiver genuinely never got seq 10, but is very
        // much alive: it keeps receiving and delivering everything after
        // it.
        let mut recv = ReliableRecv::new();
        for seq in 1..=9u64 {
            recv.observe(seq);
        }
        for seq in 11..=50u64 {
            recv.observe(seq);
        }
        assert_eq!(
            recv.current_ack().0,
            9,
            "the sender gave up believing the peer is unreachable, but the receiver's \
             cumulative ack frontier is permanently stuck at 9 regardless -- this session's \
             own ARQ state for this seq can never self-heal without a new epoch (a fresh \
             PeerChannel/session), no matter how long both sides stay up"
        );
    }

    #[test]
    fn send_ack_clears_cumulative_and_selective() {
        let mut send = ReliableSend::new();
        let f1 = send.wrap_and_track(b"a", 0, 0);
        let f2 = send.wrap_and_track(b"b", 0, 0);
        let f3 = send.wrap_and_track(b"c", 0, 0);
        assert!(matches!(decode_frame(f1), DecodedFrame::Data { seq: 1, .. }));
        assert!(matches!(decode_frame(f2), DecodedFrame::Data { seq: 2, .. }));
        assert!(matches!(decode_frame(f3), DecodedFrame::Data { seq: 3, .. }));
        assert_eq!(send.unacked.len(), 3);
        send.on_ack(1, 0b10); // acks seq 1 cumulatively, seq 3 selectively (ack_lo+1+1=3)
        assert_eq!(send.unacked.len(), 1);
        assert!(send.unacked.contains_key(&2));
    }
}
