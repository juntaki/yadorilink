use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::framing::{fragment_message, unwrap_ipv4, wrap_ipv4, Reassembler, MAX_FRAGMENT_PAYLOAD};

/// Default WireGuard keepalive interval (seconds), matching the upstream
/// default so NAT bindings stay open.
const KEEPALIVE_SECS: u16 = 25;

/// Scratch buffer size for any boringtun call that might flush a queued
/// packet (`decapsulate`'s repeat-with-empty-datagram loop, `update_timers`)
/// rather than just a control message. Must be large enough for the biggest
/// possible queued item: a max-size fragment plus the IPv4 shim header plus
/// boringtun's own `DATA_OVERHEAD_SZ` (32 bytes) — sized with margin.
const WG_SCRATCH_BUF_SIZE: usize = MAX_FRAGMENT_PAYLOAD + 20 + 128;
pub const MAX_WIREGUARD_DATAGRAM_LEN: usize = 4 * 1024;

pub struct IncomingResult {
    /// Raw WireGuard datagrams that must be sent back out (handshake
    /// responses, keepalives, cookie replies).
    pub to_send: Vec<Vec<u8>>,
    /// Fully-reassembled application messages decoded from this datagram.
    pub messages: Vec<Vec<u8>>,
    /// True iff this datagram was cryptographically
    /// meaningful — it decrypted successfully as WireGuard data (even an
    /// empty keepalive/probe that never completes a full reassembled
    /// message) or advanced an authenticated handshake transition that
    /// produced a datagram to send back. False for anything that failed
    /// to decrypt/parse (junk, garbage, a replayed or malformed packet).
    /// Callers must not treat mere *receipt* of a datagram as proof of
    /// anything; only this flag is.
    pub authenticated: bool,
}

/// Wraps a single `boringtun::noise::Tunn` peer session with message-level
/// fragmentation/reassembly and the IPv4 shim (see `framing.rs`), turning
/// boringtun's IP-tunnel-oriented API into a plain authenticated,
/// encrypted message channel to one peer.
pub struct WgTunnel {
    tunn: Tunn,
    reassembler: Reassembler,
    next_msg_id: u32,
}

impl WgTunnel {
    pub fn new(local_secret: StaticSecret, peer_public: PublicKey, session_index: u32) -> Self {
        let tunn =
            Tunn::new(local_secret, peer_public, None, Some(KEEPALIVE_SECS), session_index, None);
        Self { tunn, reassembler: Reassembler::new(), next_msg_id: 0 }
    }

    /// Encrypts one application message, returning zero or more raw
    /// WireGuard datagrams to send. If no session is established yet, this
    /// returns a handshake-initiation datagram and queues the message
    /// internally (boringtun's own queue) for automatic flush once the
    /// handshake completes via `handle_incoming`.
    pub fn encrypt_message(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::TransportError> {
        let msg_id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);

        let mut out = Vec::new();
        for fragment in fragment_message(msg_id, payload)? {
            let wrapped = wrap_ipv4(&fragment);
            let mut buf = vec![0u8; WG_SCRATCH_BUF_SIZE];
            if let TunnResult::WriteToNetwork(bytes) = self.tunn.encapsulate(&wrapped, &mut buf) {
                out.push(bytes.to_vec());
            }
        }
        Ok(out)
    }

    /// Feeds one received raw WireGuard datagram through the tunnel,
    /// handling the handshake state machine and returning any datagrams
    /// that must be sent back plus any application messages that became
    /// fully reassembled as a result.
    pub fn handle_incoming(&mut self, datagram: &[u8]) -> IncomingResult {
        if datagram.len() > MAX_WIREGUARD_DATAGRAM_LEN {
            tracing::warn!(len = datagram.len(), "dropping oversized wireguard datagram");
            return IncomingResult {
                to_send: Vec::new(),
                messages: Vec::new(),
                authenticated: false,
            };
        }

        let mut to_send = Vec::new();
        let mut messages = Vec::new();
        let mut authenticated = false;
        let mut next_input: Option<Vec<u8>> = Some(datagram.to_vec());

        // Per boringtun's documented contract: a WriteToNetwork result must
        // be followed by a repeat call with an empty datagram until Done,
        // to flush queued/subsequent packets (e.g. a newly-established
        // session's backlog).
        while let Some(input) = next_input.take() {
            let mut buf = vec![0u8; WG_SCRATCH_BUF_SIZE.max(input.len())];
            match self.tunn.decapsulate(None, &input, &mut buf) {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    tracing::warn!(error = ?e, "wireguard decapsulate error");
                    break;
                }
                TunnResult::WriteToNetwork(bytes) => {
                    // decapsulate only reaches this arm for a datagram that
                    // parsed as a valid WireGuard control message (handshake
                    // init/response/cookie) and advanced the handshake state
                    // machine — junk bytes hit `Err` above instead, so this
                    // is a genuine authenticated transition.
                    authenticated = true;
                    to_send.push(bytes.to_vec());
                    next_input = Some(Vec::new());
                }
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                    // Decryption succeeded — this is real WireGuard data
                    // (possibly an empty keepalive/probe), cryptographically
                    // proving the sender holds the session keys, even when
                    // it never becomes a fully-reassembled application
                    // message (e.g. a bare keepalive).
                    authenticated = true;
                    if let Some(fragment) = unwrap_ipv4(bytes) {
                        if let Some(full_message) = self.reassembler.insert(fragment) {
                            messages.push(full_message);
                        }
                    }
                    break;
                }
            }
        }

        IncomingResult { to_send, messages, authenticated }
    }

    /// Drives WireGuard's internal timers (handshake retry, keepalive).
    /// Should be called periodically (e.g. every 250ms-1s) regardless of
    /// traffic. Returns a datagram to send, if the timer tick produced one
    /// (boringtun only emits one when a timer condition is actually due —
    /// this is not a way to force traffic on demand; see `probe`).
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; WG_SCRATCH_BUF_SIZE];
        match self.tunn.update_timers(&mut buf) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    /// Unconditionally produces a datagram right now: a handshake
    /// initiation if no session exists yet, or an empty (keepalive-style)
    /// data packet if one does. Used to actively probe a candidate path
    /// (e.g., during direct-path upgrade attempts) without waiting
    /// on `tick`'s internal timer gating.
    pub fn probe(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; WG_SCRATCH_BUF_SIZE];
        match self.tunn.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_incoming_datagram_is_dropped_without_panic() {
        let local = StaticSecret::from([1u8; 32]);
        let peer = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer);
        let mut tunnel = WgTunnel::new(local, peer_public, 0);

        let result = tunnel.handle_incoming(&vec![0u8; MAX_WIREGUARD_DATAGRAM_LEN + 1]);

        assert!(result.to_send.is_empty());
        assert!(result.messages.is_empty());
        assert!(!result.authenticated);
    }

    /// Security foundation: a datagram that is not a valid WireGuard
    /// packet at all (no keys, no MAC, no handshake) must decapsulate to
    /// `TunnResult::Err` and therefore never set `authenticated`, however
    /// many bytes it contains — this is what an off-path attacker who only
    /// knows the peer's `IP:port` can send.
    #[test]
    fn junk_datagram_is_not_authenticated() {
        let local = StaticSecret::from([1u8; 32]);
        let peer = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer);
        let mut tunnel = WgTunnel::new(local, peer_public, 0);

        let result = tunnel.handle_incoming(&[0xAAu8; 200]);

        assert!(result.to_send.is_empty());
        assert!(result.messages.is_empty());
        assert!(!result.authenticated);
    }

    /// A real WireGuard handshake initiation from the correct peer must be
    /// recognized as authenticated (it produces a handshake response),
    /// even though it carries no application message of its own — this is
    /// the positive control proving the `authenticated` flag isn't simply
    /// always false.
    #[test]
    fn genuine_handshake_initiation_is_authenticated() {
        let local_secret = StaticSecret::from([1u8; 32]);
        let local_public = PublicKey::from(&local_secret);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);

        let mut local_tunnel = WgTunnel::new(local_secret, peer_public, 0);
        let mut peer_tunnel = WgTunnel::new(peer_secret, local_public, 1);

        let init = peer_tunnel.probe().expect("fresh tunnel produces a handshake initiation");
        let result = local_tunnel.handle_incoming(&init);

        assert!(result.authenticated);
        assert!(!result.to_send.is_empty(), "a handshake initiation must produce a response");
    }
}
