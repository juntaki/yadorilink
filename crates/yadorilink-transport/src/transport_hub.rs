//! The device's single logical transport endpoint -- a `TransportHub` --
//! shared by the QUIC endpoint that carries peer traffic and by NAT
//! candidate gathering (STUN, port mapping).
//!
//! Why one endpoint: a NAT maps an *(internal address, internal port)* to an
//! external endpoint, tied to the exact local port packets leave from -- it
//! does not extend the mapping to other local ports. So the reflexive /
//! port-mapped candidates a device advertises are only reachable if the data
//! answering an inbound connection leaves from, and arrives on, the *same*
//! socket those candidates were observed for. That invariant is why QUIC is
//! driven through this hub rather than being given a socket of its own; see
//! [`crate::quic_socket`].
//!
//! Demultiplexing (normative), checked in this order:
//! - relay envelope: the fixed [`RELAY_ENVELOPE_MARKER`] leading four bytes.
//!   Checked FIRST, and deliberately so: a relay-carried packet arrives from
//!   the relaying device's address, and handing it onward as though it came
//!   from the peer would present that address as the peer's own. It goes to
//!   the QUIC endpoint like everything else, but under the *synthetic*
//!   address [`crate::relay_path`] mints for that relay session, so quinn
//!   sees one steady path per session instead of the relay's address
//!   migrating under it.
//! - STUN: the magic cookie **and** a transaction id this device actually
//!   has pending -> the prober; otherwise dropped.
//! - everything else is QUIC's, and goes to the endpoint sharing this
//!   socket, which authenticates the sender itself. The source address is
//!   never identity here; it is at most a hint, and authentication happens
//!   one layer up.
//!
//! Physically the hub drives a [`UdpEndpoint`]: a dual-stack IPv4 + IPv6
//! socket pair bound to one logical port (the IPv6 half is v6-only via
//! `socket2` so the two do not collide), so a peer is reachable over either
//! family and IPv6 host candidates are first-class. Either half may be
//! absent (a single-socket harness, or a host without usable IPv6). The
//! demux above is family-agnostic.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
#[cfg(not(madsim))]
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::nat::stun::{StunIoFuture, StunSocket};
use crate::udp_batching::UdpBatchingSupport;

/// How many recent STUN transaction ids the hub remembers, so a binding
/// response is accepted only if it answers a request we actually sent.
const STUN_PENDING_DEPTH: usize = 64;

/// The largest datagram this hub will read off the socket.
///
/// QUIC packets are kept under the path MTU, and the relay envelope adds a
/// fixed 12-byte header on top of one. This is comfortably above both, so a
/// legitimate datagram is never truncated, while still bounding the buffer
/// the receive loop holds per iteration.
const MAX_DATAGRAM_LEN: usize = 2048;

/// The relay envelope's fixed marker. Byte 0 is `0x00` specifically so the
/// three wire formats sharing this socket stay unambiguous by construction:
///
/// - every QUIC packet has the fixed bit `0x40` set in byte 0, so a marker
///   with that bit clear can never be mistaken for one (an earlier marker
///   predating this socket's QUIC-only demux had that bit set, chosen for a
///   transport this hub no longer carries);
/// - STUN also has `byte0 & 0xC0 == 0`, but is additionally identified by
///   its magic cookie at bytes 4..8, and the envelope is checked *first*
///   regardless, so the overlap in the leading bits is not reachable.
const RELAY_ENVELOPE_MARKER: [u8; 4] = [0x00, 0xFF, 0xFF, 0xFF];
const RELAY_ENVELOPE_HEADER_LEN: usize = RELAY_ENVELOPE_MARKER.len() + 8;

/// M3 Pass 8 closeout: `yadorilink-daemon`'s `relay_forwarder.rs` wraps
/// every datagram it forwards toward a relay session's destination in
/// this envelope (`RELAY_ENVELOPE_MARKER` + little-endian `u64` relay
/// session id + the opaque peer-traffic bytes verbatim) BEFORE sending it
/// raw over its own dedicated forwarding socket -- rather than sending
/// those bytes completely unwrapped, indistinguishable from genuine direct
/// UDP the way earlier passes did. `B` (the relay) still never decrypts or
/// inspects the forwarded payload itself -- opaque PAYLOAD forwarding is
/// preserved exactly as designed -- this envelope only wraps the OUTER
/// transport framing, which is not, and never was, required to be opaque:
/// `B` already knows a relay session exists (it admitted it), the session
/// id, and the destination it's forwarding to; this envelope reveals
/// nothing to any observer that admission didn't already require `B` to
/// know.
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

/// The sibling of [`unwrap_relay_envelope`] -- wraps opaque forwarded
/// peer-traffic bytes for a relay session's forwarding send. `pub` (not
/// `pub(crate)`): called from `yadorilink-daemon`'s `relay_forwarder.rs`, a
/// different crate.
pub fn wrap_relay_envelope(relay_session_id: u64, opaque_peer_bytes: &[u8]) -> Vec<u8> {
    let mut wrapped = Vec::with_capacity(RELAY_ENVELOPE_HEADER_LEN + opaque_peer_bytes.len());
    wrapped.extend_from_slice(&RELAY_ENVELOPE_MARKER);
    wrapped.extend_from_slice(&relay_session_id.to_le_bytes());
    wrapped.extend_from_slice(opaque_peer_bytes);
    wrapped
}

pub(crate) struct DemuxRegistry {
    stun_tx: Mutex<Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
    /// Where every datagram that is neither a relay envelope nor a STUN
    /// response goes: the QUIC endpoint sharing this socket, which
    /// authenticates the sender itself. `None` until
    /// [`TransportHub::register_quic`]; such datagrams are dropped until
    /// then, which is the correct behavior for a device with no endpoint
    /// yet rather than a gap.
    quic_tx: Mutex<Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>>,
    /// Inbound QUIC datagrams dropped because the queue above was full --
    /// see [`TransportHub::register_quic`] for why dropping is the right
    /// outcome, and why it must still be counted rather than silent.
    quic_dropped: AtomicU64,
    /// Relay-carried datagrams dropped because no synthetic path could be
    /// minted for them -- see [`DemuxRegistry::route`] and
    /// [`crate::relay_path`]'s own bounds.
    relay_dropped: AtomicU64,
    /// Synthetic addresses for relay-carried paths, in both directions --
    /// see [`crate::relay_path`]. Owned by the registry rather than by the
    /// hub so the demux (which routes inbound relay envelopes) and the send
    /// path (which resolves synthetic destinations) reach the same table
    /// with no reference cycle between them.
    relay: crate::relay_path::RelayPathRouter,
    /// Transaction ids of binding requests sent but not yet answered (bounded
    /// ring; a response with an unknown id is dropped).
    stun_pending: Mutex<VecDeque<[u8; 12]>>,
}

impl DemuxRegistry {
    fn new(local_addr: SocketAddr) -> Self {
        Self {
            stun_tx: Mutex::new(None),
            quic_tx: Mutex::new(None),
            quic_dropped: AtomicU64::new(0),
            relay_dropped: AtomicU64::new(0),
            relay: crate::relay_path::RelayPathRouter::new(local_addr),
            stun_pending: Mutex::new(VecDeque::with_capacity(STUN_PENDING_DEPTH)),
        }
    }

    /// Routes one received datagram to whichever of the three protocols
    /// sharing this socket owns it.
    ///
    /// The order is what keeps the three wire formats unambiguous. The relay
    /// envelope is checked first because a relay-carried packet arrives from
    /// the relaying device's address, so passing it onward unmarked would
    /// present that address as the peer's. STUN is matched on its own strict
    /// shape rather than as "whatever was left over", so the genuine
    /// remainder -- and only that -- reaches QUIC.
    fn route(&self, datagram: &[u8], from: SocketAddr) {
        if let Some((relay_session_id, inner)) = unwrap_relay_envelope(datagram) {
            // Relay-carried peer traffic reaches quinn under the synthetic
            // address minted for this relay session, never under `from` --
            // `from` is the relaying device's dedicated forwarding socket,
            // and presenting it as the peer's own would make every packet
            // read as a path migration. The router refuses to mint a path
            // when its bounded table is full or the payload cannot be a
            // QUIC packet; that refusal is counted rather than silent, so a
            // device being flooded with envelope-shaped datagrams is
            // diagnosable instead of merely quiet.
            match self.relay.inject_from_relay_envelope(from, relay_session_id, inner) {
                Some(synthetic) => self.route_quic(inner, synthetic),
                None => {
                    self.relay_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }
        if self.maybe_route_stun(datagram, from) {
            return;
        }
        self.route_quic(datagram, from);
    }

    /// Hands one datagram to the QUIC endpoint sharing this socket, if one
    /// has registered. A closed receiver means the endpoint was dropped
    /// without unregistering; clear the slot so later datagrams take the
    /// cheap `None` path instead of re-failing per packet.
    fn route_quic(&self, datagram: &[u8], from: SocketAddr) {
        let mut slot = self.quic_tx.lock().unwrap_or_else(|p| p.into_inner());
        let Some(tx) = slot.as_ref() else {
            return;
        };
        match tx.try_send((datagram.to_vec(), from)) {
            Ok(()) => {}
            // The endpoint is not draining fast enough. Dropping is the
            // correct outcome and the same one the kernel would reach on a
            // full receive buffer: QUIC reads it as congestion signal and
            // backs off, which is what should happen. Counted rather than
            // silent so an overloaded receiver is diagnosable.
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.quic_dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The endpoint was dropped without unregistering; clear the slot
            // so later datagrams take the cheap `None` path.
            Err(mpsc::error::TrySendError::Closed(_)) => *slot = None,
        }
    }

    fn maybe_route_stun(&self, datagram: &[u8], from: SocketAddr) -> bool {
        if !stun::message::is_message(datagram) || datagram.len() < 20 {
            return false;
        }
        let mut txn = [0u8; 12];
        txn.copy_from_slice(&datagram[8..20]);
        {
            let mut pending = self.stun_pending.lock().unwrap_or_else(|p| p.into_inner());
            match pending.iter().position(|t| *t == txn) {
                Some(pos) => {
                    pending.remove(pos); // one response per request
                }
                // Not a transaction this device is waiting for, so it is not
                // ours to claim -- let the caller keep classifying.
                None => return false,
            }
        }
        if let Some(tx) = self.stun_tx.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            let _ = tx.try_send((datagram.to_vec(), from));
        }
        true
    }

    /// Requesting-side ingress: the payload of a `RelayData` frame that
    /// arrived on the control connection with a relay, presented to quinn
    /// under this path's synthetic address.
    ///
    /// The path is checked rather than assumed: a `RelayData` for a session
    /// this device has already closed must not be able to conjure traffic
    /// from an address quinn no longer has a path for.
    pub(crate) fn inject_relay_control(&self, synthetic: SocketAddr, payload: &[u8]) -> bool {
        if !self.relay.touch_control_path(synthetic) {
            return false;
        }
        self.route_quic(payload, synthetic);
        true
    }

    pub(crate) fn close_relay_path(&self, synthetic: SocketAddr) {
        self.relay.close_relay_path(synthetic);
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
/// pattern: QUIC packetizes a stream at roughly its path-MTU packet size
/// (~1200 bytes), so a single large sync-engine block (default 128 KiB, see
/// [`crate::quic_peer_channel`]'s framing) becomes on the order of a hundred
/// QUIC packets that quinn can burst out as its congestion window grows, and
/// on the receiving side those packets must all land in the kernel's
/// per-socket receive queue before quinn's endpoint task drains any of them.
/// Confirmed as the actual root cause of a 100%-reproducing transport test
/// failure on Linux (never on macOS): Linux's default UDP receive buffer
/// (`net.core.rmem_default`, 208 KiB on a stock kernel) is smaller than one
/// burst's real kernel-accounted footprint (raw payload plus per-datagram
/// `sk_buff` overhead), so datagrams beyond the buffer's capacity are
/// silently dropped by the kernel before this process ever sees them --
/// deterministically, not as transient loss -- while macOS's much larger
/// default (`net.inet.udp.recvspace`, ~768 KiB) happens to comfortably
/// absorb the same burst. Unlike an isolated loss, a kernel-level receive-
/// buffer overflow drops a contiguous run of the burst at once, so QUIC's
/// own loss recovery -- which retransmits only the missing packets, not the
/// whole block -- re-sends into the same undersized buffer and hits the
/// same overflow again: no timeout or retry budget fixes a genuine
/// kernel-level drop, only headroom does. 4 MiB comfortably covers several
/// concurrent large-block transfers on the one shared socket every channel
/// funnels through, with real margin above a single burst. Best-effort:
/// some sandboxed environments refuse to raise a socket's buffer past a
/// lower administrative cap, which is not fatal (the OS default is merely a
/// worse starting point for the same traffic, not a hard failure), so a
/// rejection is only logged.
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
    /// Which carriers most recently refused a datagram -- see the `CARRIER_*`
    /// bits.
    ///
    /// This exists because quinn's write-readiness poller carries no
    /// destination. One poller therefore stands for three independent
    /// carriers, and without recording which of them said `WouldBlock` the
    /// only answers available are "ready if any is ready", which spins
    /// whenever the blocked carrier is not the free one, or "ready only if
    /// all are ready", which stalls a send that could have gone out. Keeping
    /// the set turns the question back into the one quinn is actually
    /// asking: is the carrier that refused me usable yet.
    #[cfg(not(madsim))]
    blocked_carriers: AtomicU8,
}

/// The carriers a datagram can leave this hub through, as bits in
/// [`TransportHub::blocked_carriers`].
///
/// They are independent: the IPv4 socket being writable says nothing about
/// the IPv6 socket, and neither says anything about the queue in front of a
/// relay control connection. Naming them lets write readiness answer for the
/// one that actually refused a send.
#[cfg(not(madsim))]
const CARRIER_V4: u8 = 1 << 0;
#[cfg(not(madsim))]
const CARRIER_V6: u8 = 1 << 1;
#[cfg(not(madsim))]
const CARRIER_RELAY_CONTROL: u8 = 1 << 2;

/// Inbound STUN responses the demux will hold for the prober. STUN is a
/// low-rate request/response exchange this device initiates itself, so this
/// only has to absorb a scheduling hiccup, and a response with no pending
/// transaction id has already been dropped before it gets here.
const STUN_INBOUND_QUEUE_DEPTH: usize = 64;

/// Inbound QUIC datagrams the demux will hold for the endpoint before
/// dropping. Deep enough to absorb a scheduling hiccup between the receive
/// loop and the endpoint's own task, small enough that a hostile sender
/// cannot turn it into meaningful memory pressure.
const QUIC_INBOUND_QUEUE_DEPTH: usize = 1024;

impl Drop for TransportHub {
    fn drop(&mut self) {
        // Stop the receive loops when the last handle goes away rather
        // than leaving them parked holding the sockets open.
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
    pub async fn bind(addr: SocketAddr) -> io::Result<Arc<Self>> {
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
        Ok(Self::assemble(v4, v6, local_addr))
    }

    /// Adopts an already-bound socket (the deterministic-simulation harness
    /// pre-binds one per device, as do most integration tests) as the
    /// endpoint's single half and starts its receive loop. Widens the
    /// adopted socket's kernel buffers the same way `bind`'s own sockets
    /// are (see `widen_socket_buffers`'s doc comment) -- skipped under
    /// simulation, where the shimmed socket has no real kernel buffer to
    /// widen.
    pub fn from_socket(socket: UdpSocket) -> Arc<Self> {
        #[cfg(not(madsim))]
        widen_socket_buffers(&socket);
        let local_addr =
            socket.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = Arc::new(socket);
        let (v4, v6) =
            if local_addr.is_ipv4() { (Some(socket), None) } else { (None, Some(socket)) };
        Self::assemble(v4, v6, local_addr)
    }

    /// Builds the hub from whichever address-family sockets are present and
    /// spawns one receive loop per socket.
    fn assemble(
        v4: Option<Arc<UdpSocket>>,
        v6: Option<Arc<UdpSocket>>,
        local_addr: SocketAddr,
    ) -> Arc<Self> {
        let endpoint = Arc::new(UdpEndpoint {
            v4: v4.clone(),
            v6: v6.clone(),
            batching: UdpBatchingSupport::detect(),
        });
        let registry = Arc::new(DemuxRegistry::new(local_addr));
        let rx_bytes = Arc::new(AtomicU64::new(0));
        let rx_packets = Arc::new(AtomicU64::new(0));
        let tx_bytes = Arc::new(AtomicU64::new(0));
        let tx_packets = Arc::new(AtomicU64::new(0));
        let recv_tasks = [v4, v6]
            .into_iter()
            .flatten()
            .map(|sock| {
                tokio::spawn(recv_loop(
                    sock,
                    registry.clone(),
                    rx_bytes.clone(),
                    rx_packets.clone(),
                ))
            })
            .collect();
        Arc::new(Self {
            endpoint,
            local_addr,
            registry,
            recv_tasks,
            tx_bytes,
            rx_bytes,
            tx_packets,
            rx_packets,
            #[cfg(not(madsim))]
            blocked_carriers: AtomicU8::new(0),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Registers the STUN prober's receiver for recognized binding responses.
    pub fn register_stun(&self) -> mpsc::Receiver<(Vec<u8>, SocketAddr)> {
        let (tx, rx) = mpsc::channel(STUN_INBOUND_QUEUE_DEPTH);
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
        // Nothing batches over a relay path -- quinn sends one datagram at a
        // time through this hub, and the NAT machinery only ever addresses
        // real endpoints. Refused rather than quietly sent, because a
        // synthetic address reaching here is a routing bug, and sending it
        // for real would put a datagram on the wire addressed to a reserved
        // range.
        if crate::relay_path::is_synthetic_relay_addr(addr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a relay path carries no batched sends",
            ));
        }
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

    /// Registers the QUIC endpoint sharing this socket and returns its
    /// inbound datagram queue. Everything the demux cannot claim as a relay
    /// envelope or a STUN response is delivered here.
    ///
    /// Bounded, and dropping on overflow. It must not block: this queue is
    /// filled from the single receive loop that serves *every* protocol on
    /// this socket, so waiting here would stall STUN and relay traffic
    /// behind a slow QUIC endpoint. It must not be unbounded
    /// either: the receive loop actively copies datagrams out of the kernel
    /// buffer into this queue, so an unbounded one lets any sender who can
    /// reach this port convert kernel-bounded traffic into unbounded heap
    /// growth. Dropping the excess is what the kernel itself would do on a
    /// full receive buffer, and QUIC already reads loss as a congestion
    /// signal.
    ///
    /// Fails if a live QUIC endpoint is already registered on this hub.
    /// "One endpoint per device" is an architecture invariant -- a second
    /// binding would need its own mapping through every NAT in the path,
    /// which is the whole reason this bridge exists -- and silently
    /// replacing the registration would strand the first endpoint: it would
    /// keep every connection it holds and receive nothing on any of them,
    /// which is about the hardest failure shape there is to diagnose from
    /// the outside. An already-dropped registration is not a conflict, so a
    /// hub whose endpoint has gone can be given a new one.
    pub fn register_quic(
        &self,
    ) -> Result<mpsc::Receiver<(Vec<u8>, SocketAddr)>, crate::TransportError> {
        let mut registered = self.registry.quic_tx.lock().unwrap_or_else(|p| p.into_inner());
        if registered.as_ref().is_some_and(|tx| !tx.is_closed()) {
            return Err(crate::TransportError::NoRoute(
                "this transport hub already has a live QUIC endpoint; a device has exactly one"
                    .to_string(),
            ));
        }
        let (tx, rx) = mpsc::channel(QUIC_INBOUND_QUEUE_DEPTH);
        *registered = Some(tx);
        Ok(rx)
    }

    /// Synchronous single-datagram send, for `quinn`'s `AsyncUdpSocket::
    /// try_send`, which must not block and must report `WouldBlock` rather
    /// than drop.
    ///
    /// Native only: the simulator's `UdpSocket` exposes no synchronous send
    /// at all, so the bridge queues there instead. Keeping the real path
    /// synchronous matters -- routing it through a queue would add an
    /// allocation and a channel hop to every datagram, on the order of
    /// 750,000 of them per GiB, which is the per-packet cost this transport
    /// work exists to remove.
    #[cfg(not(madsim))]
    pub fn try_send_datagram(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        // A synthetic destination is a relay path, not a place on the
        // network. It is resolved before the socket is chosen at all: the
        // addresses these handles are drawn from are reserved ranges, so
        // letting one reach `socket_for` would send a real datagram to an
        // address that means nothing.
        let addr = match self.resolve_relay_destination(buf, addr)? {
            Some(real) => real,
            None => return Ok(()),
        };
        let socket = self.endpoint.socket_for(addr)?;
        let carrier = if addr.is_ipv4() { CARRIER_V4 } else { CARRIER_V6 };
        match socket.try_send_to(buf, addr) {
            Ok(sent) => {
                // A send that got through is proof this carrier has room,
                // so anything parked on it should retry -- clearing here is
                // what makes that happen without waiting for a wakeup.
                self.clear_blocked_carrier(carrier);
                self.tx_bytes.fetch_add(sent as u64, Ordering::Relaxed);
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.mark_blocked_carrier(carrier);
                }
                Err(e)
            }
        }
    }

    /// Records that `carrier` refused a datagram, so write readiness knows
    /// which of the three to answer for.
    #[cfg(not(madsim))]
    fn mark_blocked_carrier(&self, carrier: u8) {
        self.blocked_carriers.fetch_or(carrier, Ordering::Release);
    }

    #[cfg(not(madsim))]
    fn clear_blocked_carrier(&self, carrier: u8) {
        self.blocked_carriers.fetch_and(!carrier, Ordering::Release);
    }

    /// Write-readiness for whichever carrier last refused a datagram.
    ///
    /// quinn's poller carries no destination, so one poller stands for all
    /// three carriers this hub can send through: the IPv4 socket, the IPv6
    /// socket, and the bounded queue in front of a relay control connection.
    /// Neither obvious answer is correct. "Ready if any is ready" spins: the
    /// blocked send is retried immediately, refused again, and asked again,
    /// with nothing having changed. "Ready only if all are ready" stalls a
    /// send that could have gone out, because an unrelated idle carrier
    /// gates it.
    ///
    /// So this answers for the carriers that actually said `WouldBlock` --
    /// [`Self::blocked_carriers`] -- and for no others. Each blocked carrier
    /// gets this waker registered, and readiness on any of them is reported,
    /// because any of them becoming free means at least one parked send can
    /// now proceed. A carrier reported ready is cleared, so a send that
    /// blocks again re-arms it rather than inheriting a stale claim.
    ///
    /// An empty set means nothing has refused a send, and readiness is
    /// reported immediately: there is nothing to wait for, and parking would
    /// be a deadlock rather than back-pressure.
    #[cfg(not(madsim))]
    pub fn poll_quic_send_ready(
        &self,
        poller_id: u64,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let blocked = self.blocked_carriers.load(Ordering::Acquire);
        if blocked == 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        // Registered before any readiness is reported, so a carrier draining
        // between the check and the registration wakes this poller rather
        // than being missed.
        let mut ready: Option<io::Result<()>> = None;

        if blocked & CARRIER_RELAY_CONTROL != 0
            && self.registry.relay.poll_control_writable(poller_id, cx).is_ready()
        {
            self.clear_blocked_carrier(CARRIER_RELAY_CONTROL);
            ready = Some(Ok(()));
        }

        for (carrier, socket) in
            [(CARRIER_V4, self.endpoint.v4.as_ref()), (CARRIER_V6, self.endpoint.v6.as_ref())]
        {
            if blocked & carrier == 0 {
                continue;
            }
            let Some(socket) = socket else {
                // A family with no socket cannot be what refused a send --
                // that fails as `AddrNotAvailable`, not `WouldBlock` -- so a
                // bit set for one is stale bookkeeping. Cleared rather than
                // waited on, which would park forever.
                self.clear_blocked_carrier(carrier);
                continue;
            };
            if let std::task::Poll::Ready(result) = socket.poll_send_ready(cx) {
                self.clear_blocked_carrier(carrier);
                ready = Some(result);
            }
        }

        match ready {
            Some(result) => std::task::Poll::Ready(result),
            None => std::task::Poll::Pending,
        }
    }

    /// Sends a single datagram through the hub's endpoint.
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        // Same relay-path resolution as `try_send_datagram`, for the two
        // callers that reach the socket asynchronously: the simulated QUIC
        // writer task, and anything above that sends one datagram at a time.
        let addr = match self.resolve_relay_destination(buf, addr)? {
            Some(real) => real,
            None => return Ok(buf.len()),
        };
        let result = self.endpoint.send_to(buf, addr).await;
        if result.is_ok() {
            self.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Resolves an outbound destination that may be one of this process's
    /// synthetic relay handles.
    ///
    /// `Ok(Some(addr))` means "send this to `addr` over a real socket" --
    /// either because the destination was never synthetic, or because it
    /// named a relay path whose return leg *is* raw UDP straight back to the
    /// relay's dedicated forwarding socket (the destination side of a relay
    /// session, which needs no envelope: that socket already identifies the
    /// session). `Ok(None)` means the datagram has been handed to the relay
    /// control queue instead and there is nothing left for the socket to do.
    /// An error is quinn's ordinary `WouldBlock` back-pressure from that
    /// queue being full.
    fn resolve_relay_destination(
        &self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> io::Result<Option<SocketAddr>> {
        match self.registry.relay.resolve(addr) {
            None if crate::relay_path::is_synthetic_relay_addr(addr) => {
                // A path that closed under an in-flight send. Dropping it is
                // exactly the loss a closed path implies, and QUIC treats it
                // as such; sending it for real is the one thing that must
                // not happen.
                Ok(None)
            }
            None => Ok(Some(addr)),
            Some(crate::relay_path::RelayEgress::Raw(real)) => Ok(Some(real)),
            Some(crate::relay_path::RelayEgress::Control) => {
                match self.registry.relay.try_send(addr, buf) {
                    Ok(()) => {
                        #[cfg(not(madsim))]
                        self.clear_blocked_carrier(CARRIER_RELAY_CONTROL);
                        Ok(None)
                    }
                    Err(error) => {
                        #[cfg(not(madsim))]
                        if error.kind() == io::ErrorKind::WouldBlock {
                            self.mark_blocked_carrier(CARRIER_RELAY_CONTROL);
                        }
                        Err(error)
                    }
                }
            }
        }
    }

    /// Allocates a stable id for one of quinn's write-readiness pollers, and
    /// forgets one that is going away -- see
    /// [`Self::poll_quic_send_ready`].
    pub fn next_send_poller_id() -> u64 {
        crate::relay_path::RelayPathRouter::next_poller_id()
    }

    #[cfg(not(madsim))]
    pub fn forget_send_poller(&self, poller_id: u64) {
        self.registry.relay.forget_control_poller(poller_id);
    }

    /// Opens a relay path this device is the *requester* of, and returns the
    /// handle that owns it.
    ///
    /// The synthetic address on the handle is what this device's QUIC
    /// endpoint should be told the peer is at; `egress` is where the packets
    /// quinn sends there are handed off, as `RelayData` on the control
    /// connection with the relaying peer. Dropping the handle closes the
    /// path, so a relay session that ends cannot leave a synthetic address
    /// behind with nothing left to use it.
    pub fn open_relay_path(
        &self,
        egress: Arc<dyn crate::relay_path::RelayControlEgress>,
    ) -> Result<crate::relay_path::RelayPathHandle, crate::TransportError> {
        let addr = self.registry.relay.open_control_path(egress)?;
        Ok(crate::relay_path::RelayPathHandle::new(Arc::downgrade(&self.registry), addr))
    }

    /// Envelope-shaped datagrams the demux refused to route to a relay path
    /// -- a full path table, or a payload that could not be a QUIC packet.
    pub fn relay_datagrams_dropped(&self) -> u64 {
        self.registry.relay_dropped.load(Ordering::Relaxed)
    }

    /// Relayed datagrams this device handed to a relay control connection
    /// that would not take them. Ordinary datagram loss as far as QUIC is
    /// concerned -- it retransmits -- but a rising count means the control
    /// connection to the relay is the bottleneck, which is worth being able
    /// to see rather than infer.
    pub fn relay_control_send_failures(&self) -> u64 {
        self.registry.relay.control_send_failures()
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
    registry: Arc<DemuxRegistry>,
    rx_bytes: Arc<AtomicU64>,
    rx_packets: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM_LEN];
    loop {
        match recv_socket.recv_from(&mut buf).await {
            Ok((n, from)) => {
                rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                rx_packets.fetch_add(1, Ordering::Relaxed);
                registry.route(&buf[..n], from);
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
/// attributed to — the exact socket that carries peer data. Registers
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

    /// A registry with the QUIC arm registered, so a test can assert what
    /// reached it -- which is now the demux's whole "everything else" case.
    fn registry_with_quic() -> (DemuxRegistry, mpsc::Receiver<(Vec<u8>, SocketAddr)>) {
        let registry = DemuxRegistry::new(addr("127.0.0.1:41641"));
        let (tx, rx) = mpsc::channel(8);
        *registry.quic_tx.lock().unwrap() = Some(tx);
        (registry, rx)
    }

    /// The demux's whole job in three rules, which have to stay unambiguous
    /// against each other because all three protocols share one socket.
    #[tokio::test]
    async fn each_protocol_claims_only_its_own_datagrams() {
        let (registry, mut quic_rx) = registry_with_quic();
        let (stun_tx, mut stun_rx) = mpsc::channel(8);
        *registry.stun_tx.lock().unwrap() = Some(stun_tx);
        let txn = [1u8; 12];
        registry.register_stun_txn(txn);

        // A relay envelope is claimed by its marker, before anything else
        // gets to look at it. Its payload does reach QUIC -- that is the
        // whole point of relaying -- but never under the address it
        // physically arrived from, which belongs to the relaying device.
        let relay_socket = addr("203.0.113.5:41641");
        registry.route(&wrap_relay_envelope(7, &[0xC0, 1, 2, 3]), relay_socket);
        let (payload, from) = quic_rx.try_recv().expect("a relayed payload reaches the endpoint");
        assert_eq!(payload, vec![0xC0, 1, 2, 3]);
        assert_ne!(from, relay_socket, "the relaying device's address must never be presented");
        assert!(crate::relay_path::is_synthetic_relay_addr(from));
        assert!(stun_rx.try_recv().is_err());
        assert_eq!(registry.relay_dropped.load(Ordering::Relaxed), 0);

        // STUN is claimed by its own shape plus a transaction this device
        // actually has outstanding.
        registry.route(&stun_message(txn, true), addr("1.1.1.1:3478"));
        assert!(stun_rx.try_recv().is_ok());
        assert!(quic_rx.try_recv().is_err(), "a STUN response must not reach the endpoint");

        // Everything else is QUIC's, including a STUN-shaped message whose
        // transaction id this device never sent.
        registry.route(&stun_message([2u8; 12], true), addr("1.1.1.1:3478"));
        assert!(quic_rx.try_recv().is_ok(), "an unrecognized STUN response falls through to QUIC");
        registry.route(&[0xC0u8; 64], addr("203.0.113.9:1234"));
        let (datagram, from) = quic_rx.try_recv().expect("an unclaimed datagram goes to QUIC");
        assert_eq!(datagram, vec![0xC0u8; 64]);
        assert_eq!(from, addr("203.0.113.9:1234"));
    }

    /// A datagram too short to hold an envelope header cannot be one, and
    /// must not be truncated into a claim -- the length check has to come
    /// before the marker comparison.
    #[tokio::test]
    async fn a_short_datagram_that_only_looks_like_an_envelope_header_is_dropped() {
        let (registry, mut quic_rx) = registry_with_quic();

        // The marker alone, with no session id after it.
        registry.route(&RELAY_ENVELOPE_MARKER, addr("203.0.113.5:41641"));

        let (datagram, _from) =
            quic_rx.try_recv().expect("a too-short would-be envelope is not an envelope");
        assert_eq!(datagram, RELAY_ENVELOPE_MARKER.to_vec());
        assert_eq!(registry.relay_dropped.load(Ordering::Relaxed), 0);
    }

    /// The envelope round-trips: what `wrap_relay_envelope` produces is what
    /// `unwrap_relay_envelope` reads back, session id and payload intact.
    /// The two halves run on opposite devices, so they have to be exact
    /// inverses.
    #[test]
    fn a_relay_envelope_round_trips_its_session_id_and_payload() {
        let payload = b"opaque peer bytes";
        let wrapped = wrap_relay_envelope(0x0123_4567_89AB_CDEF, payload);

        let (session_id, inner) = unwrap_relay_envelope(&wrapped).expect("a valid envelope");

        assert_eq!(session_id, 0x0123_4567_89AB_CDEF);
        assert_eq!(inner, payload);
    }

    /// Byte 0 of the marker has QUIC's fixed bit clear, which is what keeps
    /// an envelope from ever being shape-ambiguous with a QUIC packet. A
    /// relation between the two wire formats, so it is checked rather than
    /// only described.
    #[test]
    fn the_relay_marker_cannot_be_mistaken_for_a_quic_packet() {
        const QUIC_FIXED_BIT: u8 = 0x40;
        assert_eq!(RELAY_ENVELOPE_MARKER[0] & QUIC_FIXED_BIT, 0);
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
        let hub = TransportHub::bind((std::net::Ipv4Addr::UNSPECIFIED, 0).into())
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

    /// Proves the wire counters are complete for both send paths
    /// (`send_to`/`send_batch`) against a REAL second socket's own observed
    /// receive count -- not just "the counter incremented by something", but
    /// "the counter matches exactly what a real peer received".
    #[tokio::test]
    async fn wire_counters_match_bytes_a_real_peer_actually_received() {
        let hub_a = TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("bind hub A");
        let hub_b = TransportHub::bind((std::net::Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("bind hub B");
        let b_addr = hub_b.local_addr();

        let single = b"single-send-payload";
        hub_a.send_to(single, b_addr).await.expect("send_to");
        let batch = vec![b"batch-one".to_vec(), b"batch-two-longer".to_vec()];
        hub_a.send_batch(&batch, b_addr).await.expect("send_batch");

        let expected_bytes =
            single.len() as u64 + batch.iter().map(|d| d.len() as u64).sum::<u64>();
        let expected_packets = 1 + batch.len() as u64;

        // `recv_loop` runs on a spawned task -- poll rather than assume
        // it has already processed both sends by the time we get here.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if hub_b.wire_bytes_received() >= expected_bytes {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                panic!(
                    "hub B only observed {} of {expected_bytes} expected bytes within 5s",
                    hub_b.wire_bytes_received()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert_eq!(
            hub_a.wire_bytes_sent(),
            expected_bytes,
            "hub A's own send-side counter must match exactly what it sent"
        );
        assert_eq!(hub_a.wire_packets_sent(), expected_packets);
        assert_eq!(
            hub_b.wire_bytes_received(),
            expected_bytes,
            "hub B's receive-side counter must match exactly what hub A sent -- a real \
             cross-socket check, not just self-consistency within one hub"
        );
        assert_eq!(hub_b.wire_packets_received(), expected_packets);
    }
}
