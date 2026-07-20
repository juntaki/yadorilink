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
use std::sync::{Arc, Mutex};

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::PublicKey;
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

/// Whether an inbound datagram was demultiplexed to its owning channel by
/// WireGuard receiver index (definitely for that channel) or offered to a
/// channel as a handshake-initiation probe (for that channel only if its
/// static key authenticates it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    /// Routed by receiver index: this datagram belongs to the receiving
    /// channel's WireGuard session.
    Direct,
    /// A MAC1-verified handshake initiation offered to authorized channels;
    /// only the channel whose static key decapsulates it is the recipient.
    HandshakeProbe,
}

/// One inbound datagram delivered to a channel's demux queue.
#[derive(Debug)]
pub struct InboundDatagram {
    pub data: Vec<u8>,
    pub from: SocketAddr,
    pub kind: DatagramKind,
}

/// A registered channel: where to deliver its datagrams, and the source IPs
/// (from its known candidates) used to order initiation trials.
struct ChannelEntry {
    sender: mpsc::Sender<InboundDatagram>,
    candidate_ips: HashSet<IpAddr>,
}

/// The demux routing table, shared between [`TransportHub`] and its receive
/// loop.
struct DemuxRegistry {
    channels: Mutex<HashMap<u32, ChannelEntry>>,
    stun_tx: Mutex<Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
    /// Transaction ids of binding requests sent but not yet answered (bounded
    /// ring; a response with an unknown id is dropped).
    stun_pending: Mutex<VecDeque<[u8; 12]>>,
    /// MAC1 verifier keyed on this device's static public key. `None` when the
    /// device identity was not supplied (tests / pre-identity startup): the
    /// initiation gate then falls back to offering initiations to every
    /// authorized channel without the cheap MAC1 pre-reject.
    rate_limiter: Option<RateLimiter>,
}

impl DemuxRegistry {
    fn new(device_public: Option<PublicKey>) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            stun_tx: Mutex::new(None),
            stun_pending: Mutex::new(VecDeque::with_capacity(STUN_PENDING_DEPTH)),
            rate_limiter: device_public.map(|pk| RateLimiter::new(&pk, HANDSHAKE_RATE_LIMIT)),
        }
    }

    /// Routes one received datagram. Returns a datagram to send back (a
    /// WireGuard cookie reply produced by the MAC1 gate when under load),
    /// which the receive loop is responsible for delivering.
    fn route(&self, datagram: &[u8], from: SocketAddr) -> Option<(Vec<u8>, SocketAddr)> {
        match Tunn::parse_incoming_packet(datagram) {
            Ok(Packet::HandshakeInit(_)) => return self.handle_initiation(datagram, from),
            Ok(Packet::HandshakeResponse(p)) => self.route_by_index(p.receiver_idx, datagram, from),
            Ok(Packet::PacketCookieReply(p)) => self.route_by_index(p.receiver_idx, datagram, from),
            Ok(Packet::PacketData(p)) => self.route_by_index(p.receiver_idx, datagram, from),
            Err(_) => self.maybe_route_stun(datagram, from),
        }
        None
    }

    fn route_by_index(&self, receiver_idx: u32, datagram: &[u8], from: SocketAddr) {
        let session_index = receiver_idx >> 8;
        let channels = self.channels.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = channels.get(&session_index) {
            let _ = entry.sender.try_send(InboundDatagram {
                data: datagram.to_vec(),
                from,
                kind: DatagramKind::Direct,
            });
        }
    }

    /// Handles a handshake initiation per the normative rules: MAC1 gate, then
    /// source-narrowed offering to authorized channels for bounded trial
    /// decapsulation. Returns a cookie reply to send if the gate produced one.
    fn handle_initiation(
        &self,
        datagram: &[u8],
        from: SocketAddr,
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
        self.offer_initiation(datagram, from);
        None
    }

    /// Offers a MAC1-verified initiation to every authorized channel, ordering
    /// those whose known candidates match the source endpoint first. Only the
    /// channel whose static key decapsulates it adopts the exchange.
    fn offer_initiation(&self, datagram: &[u8], from: SocketAddr) {
        let channels = self.channels.lock().unwrap_or_else(|p| p.into_inner());
        let src_ip = from.ip();
        // `false` (source-matching) sorts before `true`, so matching channels
        // are offered the initiation first.
        let mut ordered: Vec<&ChannelEntry> = channels.values().collect();
        ordered.sort_by_key(|entry| !entry.candidate_ips.contains(&src_ip));
        for entry in ordered {
            let _ = entry.sender.try_send(InboundDatagram {
                data: datagram.to_vec(),
                from,
                kind: DatagramKind::HandshakeProbe,
            });
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
    UdpSocket::from_std(sock.into())
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
}

impl Drop for TransportHub {
    fn drop(&mut self) {
        // Stop the receive loops when the last handle goes away rather than
        // leaving them parked on `recv_from` holding the sockets open.
        for task in &self.recv_tasks {
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
        let primary = Arc::new(UdpSocket::bind(addr).await?);
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
    /// pre-binds one per device) as the endpoint's single half and starts its
    /// receive loop.
    pub fn from_socket(socket: UdpSocket, device_public: Option<PublicKey>) -> Arc<Self> {
        let local_addr =
            socket.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = Arc::new(socket);
        let (v4, v6) =
            if local_addr.is_ipv4() { (Some(socket), None) } else { (None, Some(socket)) };
        Self::assemble(v4, v6, local_addr, device_public)
    }

    /// Builds the hub from whichever address-family sockets are present and
    /// spawns one receive loop per socket, all feeding the shared demux.
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
        let registry = Arc::new(DemuxRegistry::new(device_public));
        let recv_tasks = [v4, v6]
            .into_iter()
            .flatten()
            .map(|sock| tokio::spawn(recv_loop(sock, endpoint.clone(), registry.clone())))
            .collect();
        Arc::new(Self { endpoint, local_addr, registry, recv_tasks })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Registers a channel under its WireGuard session index and returns the
    /// receiver for datagrams the demultiplexer routes to it. `candidates`
    /// seed the source-narrowing used to order initiation trials. Datagrams
    /// for an unregistered index are dropped.
    pub fn register_channel(
        &self,
        session_index: u32,
        candidates: &[SocketAddr],
    ) -> mpsc::Receiver<InboundDatagram> {
        let (tx, rx) = mpsc::channel(DEMUX_QUEUE_DEPTH);
        let candidate_ips = candidates.iter().map(|a| a.ip()).collect();
        self.registry
            .channels
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(session_index, ChannelEntry { sender: tx, candidate_ips });
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
        self.registry.channels.lock().unwrap_or_else(|p| p.into_inner()).remove(&session_index);
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
        self.endpoint.send_batch(datagrams, addr).await
    }

    /// Sends a single datagram through the hub's endpoint.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.endpoint.send_to(buf, addr).await
    }
}

async fn recv_loop(
    recv_socket: Arc<UdpSocket>,
    endpoint: Arc<UdpEndpoint>,
    registry: Arc<DemuxRegistry>,
) {
    let mut buf = vec![0u8; MAX_WIREGUARD_DATAGRAM_LEN];
    loop {
        match recv_socket.recv_from(&mut buf).await {
            Ok((n, from)) => {
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
        DemuxRegistry::new(None)
    }

    #[test]
    fn routes_data_by_receiver_index() {
        let registry = registry_without_gate();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        registry
            .channels
            .lock()
            .unwrap()
            .insert(7, ChannelEntry { sender: tx_a, candidate_ips: HashSet::new() });
        registry
            .channels
            .lock()
            .unwrap()
            .insert(9, ChannelEntry { sender: tx_b, candidate_ips: HashSet::new() });

        assert!(registry.route(&wg_data_packet((7 << 8) | 3), addr("203.0.113.1:5000")).is_none());

        let to_a = rx_a.try_recv().expect("session 7 receives its data");
        assert_eq!(to_a.kind, DatagramKind::Direct);
        assert!(rx_b.try_recv().is_err(), "session 9 must not receive session 7's data");
    }

    #[test]
    fn data_for_an_unregistered_index_is_dropped() {
        let registry = registry_without_gate();
        let (tx, mut rx) = mpsc::channel(8);
        registry
            .channels
            .lock()
            .unwrap()
            .insert(1, ChannelEntry { sender: tx, candidate_ips: HashSet::new() });
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
        let registry = registry_without_gate();
        let (tx_match, mut rx_match) = mpsc::channel(8);
        let (tx_other, mut rx_other) = mpsc::channel(8);
        let mut match_ips = HashSet::new();
        match_ips.insert(addr("198.51.100.4:41641").ip());
        registry
            .channels
            .lock()
            .unwrap()
            .insert(1, ChannelEntry { sender: tx_match, candidate_ips: match_ips });
        registry
            .channels
            .lock()
            .unwrap()
            .insert(2, ChannelEntry { sender: tx_other, candidate_ips: HashSet::new() });

        // A 148-byte handshake initiation (type in the first four bytes).
        let mut init = Vec::new();
        init.extend_from_slice(&1u32.to_le_bytes());
        init.extend_from_slice(&[0u8; 144]);
        registry.route(&init, addr("198.51.100.4:41641"));

        assert_eq!(rx_match.try_recv().unwrap().kind, DatagramKind::HandshakeProbe);
        assert_eq!(rx_other.try_recv().unwrap().kind, DatagramKind::HandshakeProbe);
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
        if hub.endpoint.v6.is_some() {
            assert_eq!(
                hub.endpoint.v6.as_ref().unwrap().local_addr().unwrap().port(),
                hub.local_port()
            );
        }
    }

    #[test]
    fn junk_datagram_is_dropped() {
        let registry = registry_without_gate();
        let (tx, mut rx) = mpsc::channel(8);
        registry
            .channels
            .lock()
            .unwrap()
            .insert(1, ChannelEntry { sender: tx, candidate_ips: HashSet::new() });
        let (stun_tx, mut stun_rx) = mpsc::channel(8);
        *registry.stun_tx.lock().unwrap() = Some(stun_tx);

        registry.route(&[0xAAu8; 64], addr("203.0.113.9:1234"));

        assert!(rx.try_recv().is_err());
        assert!(stun_rx.try_recv().is_err());
    }
}
