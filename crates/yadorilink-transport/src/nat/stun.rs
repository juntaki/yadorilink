//! STUN binding client: learn this device's server-reflexive (publicly
//! mapped) UDP address by asking one or more public STUN servers what source
//! address they saw our packet arrive from.
//!
//! Scope is deliberately the RFC 8489 binding subset — a binding request, a
//! binding success response, and the XOR-MAPPED-ADDRESS attribute. No TURN
//! allocations, no long-term credentials, no message integrity: a binding
//! response only tells us our own mapping, and the connection it enables is
//! still gated on a real WireGuard handshake, so a forged binding response
//! can at worst waste one candidate slot. Message encode/decode and
//! transaction-id matching go through the `stun` crate's audit-reviewed RFC
//! 8489 codec; the prober loop, refresh policy, and observation recording
//! stay ours.
//!
//! The prober is generic over a [`StunSocket`] so the binding exchange can be
//! unit-tested against a scripted fake, and so the production wiring can run
//! it over the *same* socket the transport sends data on (the mapping is only
//! useful if it corresponds to the data socket's NAT binding).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use stun::addr::MappedAddress;
use stun::agent::TransactionId;
use stun::message::{Getter, Message, BINDING_REQUEST, BINDING_SUCCESS};
use stun::xoraddr::XorMappedAddress;

use super::{jittered, CandidateClass, CandidateSink, CandidateSource, ObservationLog};

/// Default bounded refresh interval. Mapped addresses expire; a device that
/// never re-probes would keep advertising a dead binding.
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
/// How long to wait for a single server's response before treating it as a
/// timeout. Short because a reachable STUN server answers in one round trip.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Configuration for the STUN prober, populated from device config. An empty
/// `servers` list disables STUN entirely (no packets sent, no third party
/// learns the device's address from this feature).
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// Resolved STUN server addresses to query.
    pub servers: Vec<SocketAddr>,
    /// Bounded re-probe interval.
    pub refresh_interval: Duration,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self { servers: Vec::new(), refresh_interval: DEFAULT_REFRESH_INTERVAL }
    }
}

impl StunConfig {
    pub fn is_enabled(&self) -> bool {
        !self.servers.is_empty()
    }
}

/// Boxed future returned by [`StunSocket`] methods, so the trait stays
/// object-safe without `async fn`.
pub type StunIoFuture<'a, T> =
    Pin<Box<dyn std::future::Future<Output = io::Result<T>> + Send + 'a>>;

/// A datagram socket the prober can send binding requests over and receive
/// responses on. Abstracted so the exchange is testable against a fake and so
/// production can supply the transport's own data socket.
pub trait StunSocket: Send + Sync {
    fn send_to<'a>(&'a self, buf: &'a [u8], target: SocketAddr) -> StunIoFuture<'a, usize>;

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> StunIoFuture<'a, (usize, SocketAddr)>;
}

impl StunSocket for tokio::net::UdpSocket {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        target: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            // `madsim`'s simulated `UdpSocket::send_to` takes `(dst, buf)`,
            // the reverse of real tokio's `(buf, dst)` — the same shim quirk
            // `local_discovery` documents.
            #[cfg(not(madsim))]
            {
                tokio::net::UdpSocket::send_to(self, buf, target).await
            }
            #[cfg(madsim)]
            {
                // The simulated `send_to` also returns `()` rather than the
                // sent length; a datagram send is all-or-nothing either way.
                tokio::net::UdpSocket::send_to(self, target, buf).await.map(|()| buf.len())
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>
    {
        Box::pin(async move { tokio::net::UdpSocket::recv_from(self, buf).await })
    }
}

/// Encodes a binding request carrying the given 96-bit transaction id and no
/// attributes, using the `stun` crate's message codec. The transaction id must
/// be freshly random per request so a response can be matched to it and
/// off-path responses rejected.
pub fn encode_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Message::new();
    msg.typ = BINDING_REQUEST;
    msg.transaction_id = TransactionId(*transaction_id);
    // Serializes the 20-byte header (type, zero length, magic cookie,
    // transaction id) into `raw`; there are no attributes to append.
    msg.encode();
    msg.raw
}

/// Parses a binding success response, returning the mapped address it carries.
/// Returns `None` for anything that is not a well-formed success response to
/// *our* transaction (not a STUN message, wrong type, wrong transaction id, or
/// carrying no address attribute) — the caller treats that exactly like no
/// response. XOR-MAPPED-ADDRESS is preferred; the legacy MAPPED-ADDRESS is
/// accepted as a fallback for older servers.
pub fn parse_binding_response(
    buf: &[u8],
    expected_transaction_id: &[u8; 12],
) -> Option<SocketAddr> {
    if !stun::message::is_message(buf) {
        return None;
    }
    let mut msg = Message::new();
    msg.raw = buf.to_vec();
    msg.decode().ok()?;
    if msg.typ != BINDING_SUCCESS {
        return None;
    }
    if msg.transaction_id.0 != *expected_transaction_id {
        return None;
    }
    let mut xor = XorMappedAddress::default();
    if xor.get_from(&msg).is_ok() {
        return Some(SocketAddr::new(xor.ip, xor.port));
    }
    let mut mapped = MappedAddress::default();
    if mapped.get_from(&msg).is_ok() {
        return Some(SocketAddr::new(mapped.ip, mapped.port));
    }
    None
}

fn random_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    // A transaction id needs to be unpredictable enough to reject off-path
    // responses, not cryptographically strong.
    for chunk in id.chunks_mut(4) {
        let r: u32 = rand::random();
        let bytes = r.to_be_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    id
}

/// The result of probing a set of STUN servers once.
#[derive(Debug, Default, Clone)]
pub struct StunRoundResult {
    /// Per-server mapped address, for servers that answered.
    pub mappings: Vec<(SocketAddr, SocketAddr)>,
    /// Servers that were queried but did not answer in time.
    pub timed_out: Vec<SocketAddr>,
}

impl StunRoundResult {
    /// The distinct server-reflexive addresses observed, as candidates.
    fn reflexive_candidates(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = self.mappings.iter().map(|(_, mapped)| *mapped).collect();
        addrs.sort_by_key(|a| a.to_string());
        addrs.dedup();
        addrs
    }
}

/// Probes each server once over `socket`, returning what each reported. Sends
/// all requests, then collects responses until every server has answered or
/// the per-round timeout elapses, matching each response to its request by
/// transaction id.
pub async fn probe_round<S: StunSocket + ?Sized>(
    socket: &S,
    servers: &[SocketAddr],
) -> StunRoundResult {
    let mut result = StunRoundResult::default();
    if servers.is_empty() {
        return result;
    }

    // One transaction id per server so responses are attributable even when
    // they arrive out of order on the shared socket.
    let mut pending: Vec<(SocketAddr, [u8; 12])> = Vec::with_capacity(servers.len());
    for &server in servers {
        let txn = random_transaction_id();
        let request = encode_binding_request(&txn);
        if socket.send_to(&request, server).await.is_ok() {
            pending.push((server, txn));
        } else {
            result.timed_out.push(server);
        }
    }

    let deadline = tokio::time::Instant::now() + RESPONSE_TIMEOUT;
    let mut recv_buf = [0u8; 512];
    while !pending.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut recv_buf)).await;
        let Ok(Ok((n, _from))) = recv else {
            break; // timed out or socket error; whatever is left is a timeout
        };
        // Match by transaction id rather than source address: some servers
        // answer from a different address/port than the one queried.
        let datagram = &recv_buf[..n];
        if let Some(pos) =
            pending.iter().position(|(_, txn)| parse_binding_response(datagram, txn).is_some())
        {
            let (server, txn) = pending.remove(pos);
            if let Some(mapped) = parse_binding_response(datagram, &txn) {
                result.mappings.push((server, mapped));
            }
        }
    }
    for (server, _) in pending {
        result.timed_out.push(server);
    }
    result
}

/// Long-lived STUN prober. Owns the refresh loop: probes on start, then on a
/// bounded jittered interval and whenever a network change is signalled.
/// Publishes the server-reflexive candidate to the shared sink only when it
/// changes, and records every observation for classification.
pub struct StunProber<S: StunSocket + 'static> {
    socket: Arc<S>,
    config: StunConfig,
    sink: Arc<CandidateSink>,
    observations: ObservationLog,
}

impl<S: StunSocket + 'static> CandidateSource for StunProber<S> {
    fn name(&self) -> &'static str {
        "stun"
    }
    fn class(&self) -> CandidateClass {
        CandidateClass::ServerReflexive
    }
}

impl<S: StunSocket + 'static> StunProber<S> {
    pub fn new(
        socket: Arc<S>,
        config: StunConfig,
        sink: Arc<CandidateSink>,
        observations: ObservationLog,
    ) -> Self {
        Self { socket, config, sink, observations }
    }

    /// Runs the refresh loop until `network_changed` closes. Each tick — the
    /// initial one, each interval expiry, and each network-change signal —
    /// re-probes and republishes on change. Returns immediately (a no-op
    /// task) when STUN is disabled by an empty server list.
    pub async fn run(self, mut network_changed: tokio::sync::mpsc::Receiver<()>) {
        if !self.config.is_enabled() {
            return;
        }
        // Probe once immediately so a candidate is available without waiting
        // out the first interval.
        self.refresh().await;
        loop {
            let delay = jittered(self.config.refresh_interval);
            tokio::select! {
                _ = tokio::time::sleep(delay) => self.refresh().await,
                changed = network_changed.recv() => {
                    match changed {
                        Some(()) => self.refresh().await,
                        None => return, // signal source dropped: shut down
                    }
                }
            }
        }
    }

    async fn refresh(&self) {
        let result = probe_round(self.socket.as_ref(), &self.config.servers).await;
        for (server, mapped) in &result.mappings {
            self.observations.record_stun_mapping(*server, *mapped);
        }
        for server in &result.timed_out {
            self.observations.record_stun_timeout(*server);
        }
        // Publish the (possibly empty) reflexive candidate set; the sink
        // suppresses no-op republishes on its own.
        self.sink.publish(CandidateClass::ServerReflexive, result.reflexive_candidates());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Builds a binding success response carrying an XOR-MAPPED-ADDRESS via the
    /// same `stun` codec, so the round-trip tests parse bytes produced by an
    /// independent encode path rather than ones the parser itself laid out.
    fn build_xor_response(transaction_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let mut msg = Message::new();
        let xor = XorMappedAddress { ip: mapped.ip(), port: mapped.port() };
        msg.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(TransactionId(*transaction_id)),
            Box::new(xor),
        ])
        .expect("encode binding success response");
        msg.raw
    }

    #[test]
    fn binding_request_round_trips_ipv4_mapped_address() {
        let txn = [7u8; 12];
        let request = encode_binding_request(&txn);
        // A request is a valid header addressed to the right transaction.
        assert_eq!(u16::from_be_bytes([request[0], request[1]]), BINDING_REQUEST.value());
        assert_eq!(&request[8..20], &txn);

        let mapped = addr("203.0.113.9:51234");
        let response = build_xor_response(&txn, mapped);
        assert_eq!(parse_binding_response(&response, &txn), Some(mapped));
    }

    #[test]
    fn binding_response_round_trips_ipv6_mapped_address() {
        let txn = [3u8; 12];
        let mapped = addr("[2001:db8::1]:41641");
        let response = build_xor_response(&txn, mapped);
        assert_eq!(parse_binding_response(&response, &txn), Some(mapped));
    }

    #[test]
    fn response_for_a_different_transaction_is_rejected() {
        let sent = [1u8; 12];
        let other = [2u8; 12];
        let response = build_xor_response(&other, addr("203.0.113.9:51234"));
        assert_eq!(parse_binding_response(&response, &sent), None);
    }

    #[test]
    fn response_with_wrong_magic_cookie_is_rejected() {
        let txn = [9u8; 12];
        let mut response = build_xor_response(&txn, addr("203.0.113.9:5000"));
        response[4] ^= 0xFF; // corrupt the magic cookie
        assert_eq!(parse_binding_response(&response, &txn), None);
    }

    #[test]
    fn legacy_mapped_address_is_accepted_as_fallback() {
        let txn = [4u8; 12];
        let mapped = addr("198.51.100.2:6000");
        let mut msg = Message::new();
        let attr = MappedAddress { ip: mapped.ip(), port: mapped.port() };
        msg.build(&[Box::new(BINDING_SUCCESS), Box::new(TransactionId(txn)), Box::new(attr)])
            .expect("encode legacy mapped-address response");
        assert_eq!(parse_binding_response(&msg.raw, &txn), Some(mapped));
    }

    /// A fake socket that answers each queried server with a scripted mapped
    /// address, so `probe_round` can be exercised without real networking.
    struct ScriptedSocket {
        answers: std::collections::HashMap<SocketAddr, SocketAddr>,
        outbox: Mutex<std::collections::VecDeque<Vec<u8>>>,
    }

    impl StunSocket for ScriptedSocket {
        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            target: SocketAddr,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<usize>> + Send + 'a>> {
            // Extract this request's transaction id and, if we have a scripted
            // answer for the target, queue the corresponding response.
            let mut txn = [0u8; 12];
            txn.copy_from_slice(&buf[8..20]);
            if let Some(mapped) = self.answers.get(&target).copied() {
                let response = build_xor_response(&txn, mapped);
                self.outbox.lock().unwrap().push_back(response);
            }
            let n = buf.len();
            Box::pin(async move { Ok(n) })
        }

        fn recv_from<'a>(
            &'a self,
            buf: &'a mut [u8],
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>
        {
            let next = self.outbox.lock().unwrap().pop_front();
            Box::pin(async move {
                match next {
                    Some(response) => {
                        buf[..response.len()].copy_from_slice(&response);
                        Ok((response.len(), addr("203.0.113.1:3478")))
                    }
                    // Nothing queued: block forever so the round-timeout path
                    // is what ends the wait, as it would in production.
                    None => std::future::pending().await,
                }
            })
        }
    }

    #[tokio::test]
    async fn probe_round_reports_disagreeing_ports_from_two_servers() {
        let server_a = addr("1.1.1.1:3478");
        let server_b = addr("8.8.8.8:3478");
        let mut answers = std::collections::HashMap::new();
        answers.insert(server_a, addr("203.0.113.7:5000"));
        answers.insert(server_b, addr("203.0.113.7:6000"));
        let socket = ScriptedSocket { answers, outbox: Mutex::new(Default::default()) };

        let result = probe_round(&socket, &[server_a, server_b]).await;
        assert_eq!(result.mappings.len(), 2);
        assert!(result.timed_out.is_empty());
        // Two mapped ports for one socket: the symmetric-NAT signal.
        let ports: std::collections::HashSet<u16> =
            result.mappings.iter().map(|(_, m)| m.port()).collect();
        assert_eq!(ports.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn probe_round_marks_a_silent_server_as_timed_out() {
        let server = addr("192.0.2.123:3478");
        let socket = ScriptedSocket {
            answers: std::collections::HashMap::new(),
            outbox: Mutex::new(Default::default()),
        };
        let result = probe_round(&socket, &[server]).await;
        assert!(result.mappings.is_empty());
        assert_eq!(result.timed_out, vec![server]);
    }
}
