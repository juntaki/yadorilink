//! Two layers of framing sit between an application message and a raw
//! WireGuard datagram:
//!
//! 1. **Fragmentation** ([`fragment_message`] / [`Reassembler`]): splits an
//!    arbitrary-length application message into bounded-size fragments,
//!    since a single WireGuard datagram should stay well under typical
//!    network MTU.
//! 2. **IP shim** ([`wrap_ipv4`] / [`unwrap_ipv4`]): `boringtun::noise::Tunn`
//!    is designed to tunnel real IP packets to a TUN device — its decode
//!    path (`validate_decapsulated_packet`) rejects any payload that
//!    doesn't start with a valid-looking IPv4/IPv6 header. Rather than
//!    fork boringtun or stand up a real OS TUN interface (which would
//!    require elevated privileges and full IP routing), each fragment is
//!    wrapped in a minimal synthetic IPv4 header before encapsulation and
//!    unwrapped after decapsulation. This keeps the real WireGuard
//!    handshake/encryption (via the unmodified upstream crate) while
//!    treating the tunnel as a plain authenticated-message channel.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const IPV4_HEADER_LEN: usize = 20;
const FRAG_HEADER_LEN: usize = 8;
/// Conservative cap keeping wrapped fragments under typical path MTU once
/// WireGuard's own framing overhead is added.
pub const MAX_FRAGMENT_PAYLOAD: usize = 1200;
const MAX_FRAGMENTS_PER_MESSAGE: usize = u16::MAX as usize;
const MAX_INBOUND_FRAGMENTS_PER_MESSAGE: u16 = 1024;
const MAX_PENDING_MESSAGES: usize = 128;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const PARTIAL_MESSAGE_TTL: Duration = Duration::from_secs(30);

/// Wraps `payload` in a minimal synthetic IPv4 header so it passes
/// boringtun's IP-packet validation. The header carries no real routing
/// information — source/dest addresses are fixed placeholders.
pub fn wrap_ipv4(payload: &[u8]) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + payload.len();
    let mut out = Vec::with_capacity(total_len);
    out.push(0x45); // version 4, IHL 5 (20-byte header)
    out.push(0); // DSCP/ECN
    out.extend_from_slice(&(total_len as u16).to_be_bytes()); // offset 2..4
    out.extend_from_slice(&[0u8; 8]); // id/flags/fragoff/ttl/protocol
    out.extend_from_slice(&[10, 0, 0, 1]); // offset 12..16: fake src ip
    out.extend_from_slice(&[10, 0, 0, 2]); // offset 16..20: fake dst ip
    out.extend_from_slice(payload);
    out
}

/// Reverses [`wrap_ipv4`]. Returns `None` if `packet` doesn't look like a
/// shim-wrapped payload (defensive; boringtun already validated the header
/// shape before this is called in practice).
pub fn unwrap_ipv4(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    Some(&packet[IPV4_HEADER_LEN..])
}

/// Splits `payload` into fragments no larger than [`MAX_FRAGMENT_PAYLOAD`],
/// each prefixed with an 8-byte header: `msg_id: u32, frag_index: u16,
/// frag_count: u16` (all big-endian).
pub fn fragment_message(
    msg_id: u32,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, crate::TransportError> {
    if payload.is_empty() {
        return Ok(vec![build_fragment(msg_id, 0, 1, &[])]);
    }
    let frag_count = payload.len().div_ceil(MAX_FRAGMENT_PAYLOAD);
    if frag_count > MAX_FRAGMENTS_PER_MESSAGE {
        return Err(crate::TransportError::MessageTooLarge(
            payload.len(),
            MAX_FRAGMENTS_PER_MESSAGE,
        ));
    }
    let fragments = payload
        .chunks(MAX_FRAGMENT_PAYLOAD)
        .enumerate()
        .map(|(i, chunk)| build_fragment(msg_id, i as u16, frag_count as u16, chunk))
        .collect();
    Ok(fragments)
}

fn build_fragment(msg_id: u32, frag_index: u16, frag_count: u16, chunk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
    out.extend_from_slice(&msg_id.to_be_bytes());
    out.extend_from_slice(&frag_index.to_be_bytes());
    out.extend_from_slice(&frag_count.to_be_bytes());
    out.extend_from_slice(chunk);
    out
}

struct PartialMessage {
    frag_count: u16,
    received: HashMap<u16, Vec<u8>>,
    buffered_bytes: usize,
    last_seen: Instant,
}

/// Reassembles fragments produced by [`fragment_message`] back into
/// complete application messages. One `Reassembler` per peer session.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u32, PartialMessage>,
    buffered_bytes: usize,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one fragment in. Returns `Some(message)` once all fragments
    /// for that message's `msg_id` have arrived (order-independent).
    pub fn insert(&mut self, fragment: &[u8]) -> Option<Vec<u8>> {
        if fragment.len() < FRAG_HEADER_LEN {
            return None;
        }
        let msg_id = u32::from_be_bytes(fragment[0..4].try_into().unwrap());
        let frag_index = u16::from_be_bytes(fragment[4..6].try_into().unwrap());
        let frag_count = u16::from_be_bytes(fragment[6..8].try_into().unwrap());
        let chunk = &fragment[FRAG_HEADER_LEN..];

        if frag_count == 0
            || frag_count > MAX_INBOUND_FRAGMENTS_PER_MESSAGE
            || frag_index >= frag_count
            || chunk.len() > MAX_FRAGMENT_PAYLOAD
        {
            return None;
        }

        let now = Instant::now();
        self.prune_expired(now);

        if let Some(entry) = self.pending.get(&msg_id) {
            if entry.frag_count != frag_count {
                self.remove_pending(msg_id);
                return None;
            }
        } else {
            self.make_room_for_new_message(now);
            self.pending.insert(
                msg_id,
                PartialMessage {
                    frag_count,
                    received: HashMap::new(),
                    buffered_bytes: 0,
                    last_seen: now,
                },
            );
        }

        let entry = self.pending.get_mut(&msg_id)?;
        entry.last_seen = now;
        if let std::collections::hash_map::Entry::Vacant(slot) = entry.received.entry(frag_index) {
            if self.buffered_bytes + chunk.len() > MAX_PENDING_BYTES {
                self.remove_pending(msg_id);
                return None;
            }
            slot.insert(chunk.to_vec());
            entry.buffered_bytes += chunk.len();
            self.buffered_bytes += chunk.len();
        }

        if entry.received.len() == entry.frag_count as usize {
            let complete = self.pending.remove(&msg_id).unwrap();
            self.buffered_bytes -= complete.buffered_bytes;
            let mut out = Vec::with_capacity(complete.buffered_bytes);
            for index in 0..complete.frag_count {
                let part = complete.received.get(&index)?;
                out.extend_from_slice(part);
            }
            Some(out)
        } else {
            None
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter_map(|(&msg_id, partial)| {
                (now.duration_since(partial.last_seen) > PARTIAL_MESSAGE_TTL).then_some(msg_id)
            })
            .collect();
        for msg_id in expired {
            // agmsg investigation, 2026-07-09: this used to discard a
            // partial message with no trace at all -- a real observability
            // gap, since a genuine network losing one fragment (not just
            // this session's own madsim-timing artifact) makes an entire
            // large index/block message vanish with nothing logged
            // anywhere to explain a resync/timeout further up the stack.
            if let Some(partial) = self.pending.get(&msg_id) {
                tracing::warn!(
                    msg_id,
                    received = partial.received.len(),
                    expected = partial.frag_count,
                    "dropping incomplete fragmented message: not all fragments arrived within \
                     the reassembly TTL"
                );
            }
            self.remove_pending(msg_id);
        }
    }

    fn make_room_for_new_message(&mut self, now: Instant) {
        while self.pending.len() >= MAX_PENDING_MESSAGES {
            let Some(oldest) = self.oldest_pending_message(now) else {
                break;
            };
            self.remove_pending(oldest);
        }
    }

    fn oldest_pending_message(&self, now: Instant) -> Option<u32> {
        self.pending
            .iter()
            .max_by_key(|(_, partial)| now.duration_since(partial.last_seen))
            .map(|(&msg_id, _)| msg_id)
    }

    fn remove_pending(&mut self, msg_id: u32) {
        if let Some(removed) = self.pending.remove(&msg_id) {
            self.buffered_bytes -= removed.buffered_bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let payload = b"hello wireguard";
        let wrapped = wrap_ipv4(payload);
        assert_eq!(unwrap_ipv4(&wrapped).unwrap(), payload);
    }

    #[test]
    fn fragment_and_reassemble_roundtrip() {
        let payload = vec![7u8; MAX_FRAGMENT_PAYLOAD * 3 + 42];
        let fragments = fragment_message(1, &payload).unwrap();
        assert_eq!(fragments.len(), 4);

        let mut reassembler = Reassembler::new();
        let mut result = None;
        // Feed out of order to prove order-independence.
        for frag in fragments.iter().rev() {
            result = reassembler.insert(frag);
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn empty_message_roundtrips() {
        let fragments = fragment_message(2, &[]).unwrap();
        assert_eq!(fragments.len(), 1);
        let mut reassembler = Reassembler::new();
        assert_eq!(reassembler.insert(&fragments[0]), Some(vec![]));
    }

    #[test]
    fn malformed_large_fragment_count_is_dropped_without_pending_state() {
        let fragment = build_fragment(3, 0, MAX_INBOUND_FRAGMENTS_PER_MESSAGE + 1, b"x");
        let mut reassembler = Reassembler::new();

        assert_eq!(reassembler.insert(&fragment), None);
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.buffered_bytes, 0);
    }

    #[test]
    fn out_of_range_fragment_index_is_dropped_without_pending_state() {
        let fragment = build_fragment(4, 3, 3, b"x");
        let mut reassembler = Reassembler::new();

        assert_eq!(reassembler.insert(&fragment), None);
        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.buffered_bytes, 0);
    }

    #[test]
    fn inconsistent_fragment_count_discards_partial_message() {
        let mut reassembler = Reassembler::new();
        assert_eq!(reassembler.insert(&build_fragment(5, 0, 2, b"a")), None);
        assert_eq!(reassembler.insert(&build_fragment(5, 1, 3, b"b")), None);

        assert!(reassembler.pending.is_empty());
        assert_eq!(reassembler.buffered_bytes, 0);
    }

    /// sync-correctness-fixes task 3.3: a message with a genuine gap
    /// (fragment 1 of 3 never arrives) must never be reported complete —
    /// `insert` should keep returning `None` for every fragment that
    /// does arrive, and the message should stay pending (not silently
    /// treated as done with a hole spliced out, which would hand a
    /// caller truncated/corrupt reassembled bytes).
    #[test]
    fn claimed_complete_with_a_gap_never_reassembles() {
        let mut reassembler = Reassembler::new();
        assert_eq!(reassembler.insert(&build_fragment(6, 0, 3, b"a")), None);
        // frag_index 1 is deliberately never inserted.
        assert_eq!(reassembler.insert(&build_fragment(6, 2, 3, b"c")), None);

        // Still incomplete: exactly the two received fragments are
        // buffered, not silently considered done.
        assert!(reassembler.pending.contains_key(&6));
        assert_eq!(reassembler.pending[&6].received.len(), 2);

        // The still-missing fragment later completes it correctly — the
        // gap wasn't corrupted/dropped by the earlier out-of-order insert.
        assert_eq!(reassembler.insert(&build_fragment(6, 1, 3, b"b")), Some(b"abc".to_vec()));
        assert!(!reassembler.pending.contains_key(&6));
    }

    #[test]
    fn pending_reassembly_state_is_capped() {
        let mut reassembler = Reassembler::new();

        for msg_id in 0..(MAX_PENDING_MESSAGES as u32 + 16) {
            assert_eq!(reassembler.insert(&build_fragment(msg_id, 0, 2, b"x")), None);
        }

        assert!(reassembler.pending.len() <= MAX_PENDING_MESSAGES);
        assert!(reassembler.buffered_bytes <= MAX_PENDING_BYTES);
    }
}
