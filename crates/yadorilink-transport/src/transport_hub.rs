//! The device's single logical transport endpoint -- a `TransportHub` --
//! that the QUIC endpoint carrying peer traffic is driven through; see
//! [`crate::quic_socket`].
//!
//! Every received datagram goes to the QUIC endpoint registered on this
//! socket, which authenticates the sender itself. The source address is
//! never identity here; it is at most a hint, and authentication happens one
//! layer up.
//!
//! Physically the hub drives a [`UdpEndpoint`]: a dual-stack IPv4 + IPv6
//! socket pair bound to one logical port (the IPv6 half is v6-only via
//! `socket2` so the two do not collide), so a peer is reachable over either
//! family and IPv6 host candidates are first-class. Either half may be
//! absent (a single-socket harness, or a host without usable IPv6). The
//! demux above is family-agnostic.

use std::io;
use std::net::SocketAddr;
#[cfg(not(turmoil))]
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::sim_net::UdpSocket;
use tokio::sync::mpsc;

use crate::udp_batching::UdpBatchingSupport;

/// The largest datagram this hub will read off the socket.
///
/// QUIC packets are kept under the path MTU. This is comfortably above it,
/// so a legitimate datagram is never truncated, while still bounding the
/// buffer the receive loop holds per iteration.
const MAX_DATAGRAM_LEN: usize = 2048;

/// A demuxed datagram sink: the raw bytes plus who they came from.
type DatagramSender = Mutex<Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>>;

pub(crate) struct DemuxRegistry {
    /// Where every received datagram goes: the QUIC endpoint sharing this
    /// socket, which authenticates the sender itself.
    /// `None` until [`TransportHub::register_quic`]; such datagrams are
    /// dropped until then, which is the correct behavior for a device with
    /// no endpoint yet rather than a gap.
    quic_tx: DatagramSender,
}

impl DemuxRegistry {
    #[allow(unused_variables)]
    fn new(local_addr: SocketAddr) -> Self {
        Self { quic_tx: Mutex::new(None) }
    }

    /// Routes one received datagram to the QUIC endpoint.
    fn route(&self, datagram: &[u8], from: SocketAddr) {
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
            Err(mpsc::error::TrySendError::Full(_)) => {}
            // The endpoint was dropped without unregistering; clear the slot
            // so later datagrams take the cheap `None` path.
            Err(mpsc::error::TrySendError::Closed(_)) => *slot = None,
        }
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
        socket.send_to(buf, addr).await
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
#[cfg(not(turmoil))]
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
#[cfg(not(turmoil))]
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
/// channel shares one instance.
pub struct TransportHub {
    endpoint: Arc<UdpEndpoint>,
    local_addr: SocketAddr,
    registry: Arc<DemuxRegistry>,
    recv_tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Raw UDP payload byte counter for this hub's bound socket(s) --
    /// every datagram this hub sends. Exists for a benchmark harness's
    /// "wire bytes" metric, which needs a ground truth the harness cannot
    /// observe itself; nothing in production reads it today. The receive
    /// side's counterparts are owned by the recv tasks.
    tx_bytes: Arc<AtomicU64>,
    /// Datagram count alongside the byte counter above, for a
    /// packets/sec metric.
    tx_packets: Arc<AtomicU64>,
    /// Which carriers most recently refused a datagram -- see the `CARRIER_*`
    /// bits.
    ///
    /// This exists because quinn's write-readiness poller carries no
    /// destination. One poller therefore stands for several independent
    /// carriers, and without recording which of them said `WouldBlock` the
    /// only answers available are "ready if any is ready", which spins
    /// whenever the blocked carrier is not the free one, or "ready only if
    /// all are ready", which stalls a send that could have gone out. Keeping
    /// the set turns the question back into the one quinn is actually
    /// asking: is the carrier that refused me usable yet.
    #[cfg(not(turmoil))]
    blocked_carriers: AtomicU8,
}

/// The carriers a datagram can leave this hub through, as bits in
/// [`TransportHub::blocked_carriers`].
///
/// They are independent: the IPv4 socket being writable says nothing about
/// the IPv6 socket, and neither says anything about a TURN allocation's own
/// dedicated socket. Naming them lets write readiness answer for the one
/// that actually refused a send.
#[cfg(not(turmoil))]
const CARRIER_V4: u8 = 1 << 0;
#[cfg(not(turmoil))]
const CARRIER_V6: u8 = 1 << 1;

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
        #[cfg(not(turmoil))]
        widen_socket_buffers(&primary);
        let primary = Arc::new(primary);
        let local_addr = primary.local_addr()?;
        let (v4, v6) = if addr.is_ipv4() {
            #[cfg(not(turmoil))]
            let v6 = bind_v6_only(local_addr.port()).ok().map(Arc::new);
            // Under simulation the shimmed socket has no dual-stack notion, so
            // the hub stays single-socket (v4), matching the harness.
            #[cfg(turmoil)]
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
        #[cfg(not(turmoil))]
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
            tx_packets,
            #[cfg(not(turmoil))]
            blocked_carriers: AtomicU8::new(0),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Whether this hub holds a bound IPv6 socket (production binds both
    /// halves when the host has usable IPv6; a host with none, `from_socket`,
    /// and the simulation harness keep only the v4 half). The one thing this
    /// answers for -- see [`crate::quic_socket::TransportHubQuicSocket`] --
    /// is whether the `quinn` endpoint bridged onto this hub should present
    /// itself as dual-stack-capable, since [`Self::local_addr`] alone (an
    /// IPv4 address even on a fully dual-stack hub, kept that way because it
    /// backs logging call sites that must not change meaning here)
    /// cannot answer that.
    pub fn has_ipv6(&self) -> bool {
        self.endpoint.v6.is_some()
    }

    pub fn local_port(&self) -> u16 {
        self.local_addr.port()
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

    /// Registers the QUIC endpoint sharing this socket and returns its
    /// inbound datagram queue. Every received datagram is delivered here.
    ///
    /// Bounded, and dropping on overflow. It must not block: this queue is
    /// filled from the single receive loop that serves *every* protocol on
    /// this socket, so waiting here would stall the socket behind a slow
    /// QUIC endpoint. It must not be unbounded
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
    #[cfg(not(turmoil))]
    pub fn try_send_datagram(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        // A synthetic destination is a TURN path, not a place on the
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
    /// which one to answer for.
    #[cfg(not(turmoil))]
    fn mark_blocked_carrier(&self, carrier: u8) {
        self.blocked_carriers.fetch_or(carrier, Ordering::Release);
    }

    #[cfg(not(turmoil))]
    fn clear_blocked_carrier(&self, carrier: u8) {
        self.blocked_carriers.fetch_and(!carrier, Ordering::Release);
    }

    /// Write-readiness for whichever carrier last refused a datagram.
    ///
    /// quinn's poller carries no destination, so one poller stands for every
    /// carrier this hub can send through: the IPv4 socket, the IPv6 socket,
    /// and a TURN allocation's own dedicated socket. Neither obvious answer
    /// is correct. "Ready if any is ready" spins: the
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
    #[cfg(not(turmoil))]
    pub fn poll_quic_send_ready(
        &self,
        // Kept in the signature: quinn's `UdpPoller` contract hands one per
        // poller, and the V4/V6 sockets register their own wakers through
        // `poll_send_ready`. The only map that ever indexed by it was the
        // TURN router's.
        _poller_id: u64,
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
        let result = self.endpoint.send_to(buf, addr).await;
        if result.is_ok() {
            self.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Allocates a stable id for one of quinn's write-readiness pollers, and
    /// forgets one that is going away -- see
    /// [`Self::poll_quic_send_ready`].
    pub fn next_send_poller_id() -> u64 {
        static NEXT_POLLER_ID: AtomicU64 = AtomicU64::new(0);
        NEXT_POLLER_ID.fetch_add(1, Ordering::Relaxed)
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

#[cfg(test)]
mod tests;
