//! Lets a `quinn` endpoint run over this device's one UDP socket (the
//! transport hub's), instead of binding a second port of its own.
//!
//! ## Why this exists at all
//!
//! `quinn::Endpoint::server`/`new` take a `std::net::UdpSocket` and own it
//! end to end. That is what the bench-only bulk plane does, and it is why
//! that plane binds a separate port. A separate port is not acceptable for
//! the real mesh: a second port would need its own mapping through every NAT
//! and firewall in the path -- precisely what the single-socket design
//! avoids.
//!
//! `Endpoint::new_with_abstract_socket` takes an `Arc<dyn AsyncUdpSocket>`
//! instead, which is the seam this module fills. Candidate racing keeps
//! working unchanged because, as far as the operating system is concerned,
//! nothing about the socket changed.
//!
//! It pays for itself twice. A prior bulk-transport module (since removed)
//! was excluded from simulation builds for exactly this reason: quinn
//! drives raw UDP sockets below `tokio::net::UdpSocket`, outside what a
//! simulator can intercept -- `quinn-udp` reaches past the runtime for
//! GSO, GRO and `sendmmsg`. Driven
//! through the hub, quinn never touches those paths, so every datagram goes
//! out through the hub's socket, which the simulation build swaps for a
//! simulated one (see `sim_net.rs`). The same bridge that preserves the NAT-candidate invariant is
//! what makes QUIC simulatable.

#[cfg(turmoil)]
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::mpsc;

use crate::transport_hub::TransportHub;

/// A `quinn::Runtime` built on this crate's `tokio`, reading the clock
/// through `tokio::time` so a simulated run's timeline is the one quinn's
/// deadlines live on.
///
/// There must be no simulation-only QUIC stack, only a simulation-aware
/// clock and spawner. quinn's own `Runtime::now` doc says as much --
/// "allows simulating the flow of time for testing".
#[derive(Debug)]
pub struct HubQuinnRuntime;

impl Runtime for HubQuinnRuntime {
    fn new_timer(&self, t: std::time::Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(HubTimer(Box::pin(tokio::time::sleep_until(to_timer_instant(t)))))
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    /// Never reached: this runtime is only ever used with
    /// `Endpoint::new_with_abstract_socket`, which supplies the socket. A
    /// hard error rather than a silent fallback to an OS socket -- falling
    /// back would quietly re-bind the second port this module exists to
    /// avoid, and would do it in exactly the case nobody is watching.
    fn wrap_udp_socket(&self, _sock: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this endpoint must be built with new_with_abstract_socket over the transport hub",
        ))
    }

    fn now(&self) -> std::time::Instant {
        now_instant()
    }
}

/// The clock quinn should read, and the timeline its deadlines live on.
///
/// Read through `tokio::time::Instant` rather than `std::time::Instant::now()`
/// so that a paused or simulated tokio clock is the one quinn sees. Reading
/// the wall clock while every timer fired on another timeline would put its
/// loss-detection and idle-timeout deadlines at an arbitrary offset from the
/// events they are meant to bound. That failure is silent: the handshake
/// still completes, and only timing-dependent behavior goes wrong.
pub(crate) fn now_instant() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

fn to_timer_instant(t: std::time::Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(t)
}

/// quinn's `AsyncTimer` over the aliased tokio's `Sleep`. Boxed-and-pinned
/// rather than structurally pinned so this type stays `Unpin` and needs no
/// projection macro (this crate does not depend on one).
struct HubTimer(Pin<Box<tokio::time::Sleep>>);

impl fmt::Debug for HubTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HubTimer")
    }
}

impl AsyncTimer for HubTimer {
    fn reset(mut self: Pin<&mut Self>, t: std::time::Instant) {
        self.0.as_mut().reset(to_timer_instant(t));
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self.0.as_mut(), cx)
    }
}

/// One inbound datagram the hub's demux classified as QUIC.
pub(crate) type QuicDatagram = (Vec<u8>, SocketAddr);

/// How many datagrams the simulated send path may hold before it reports
/// `WouldBlock`.
///
/// The number is not the point; having one is. Natively, quinn's writes go
/// straight into a kernel socket buffer that is finite, so a sender outrunning
/// the network gets `EWOULDBLOCK` and quinn paces itself against it. The
/// simulator has no such buffer, so the queue standing in for it has to
/// impose the same shape of limit -- otherwise simulated runs exercise a
/// transport that never experiences send backpressure, and every reconnect,
/// chaos and load result measured there describes a system that does not
/// ship. Chosen to be the same order as a default kernel send buffer holds
/// at QUIC's packet size (a couple of hundred KiB, ~1200 bytes each), so a
/// legitimate congestion-window burst passes and a runaway producer does
/// not.
#[cfg(turmoil)]
const SIMULATED_SEND_QUEUE_DEPTH: usize = 256;

/// The simulated send path's queue and its write-readiness signal.
///
/// Under simulation there is no usable synchronous send primitive -- the
/// simulated `UdpSocket` has no `poll_send_ready` to pair a refusal with a
/// wakeup -- so quinn's synchronous `try_send` has to hand the datagram to a
/// writer task. That makes this
/// queue the only place backpressure can come from, so it has to produce
/// both halves of it: a refusal when full, and a wakeup when drained.
///
/// The queue's own capacity *is* the readiness signal, and it is the one quinn needs: it says
/// whether this device can accept another datagram right now.
#[cfg(turmoil)]
struct SimulatedSendQueue {
    tx: mpsc::Sender<QuicDatagram>,
    /// Every blocked poller's waker, keyed by poller.
    ///
    /// A map rather than a single slot, because quinn creates a poller per
    /// caller that needs write readiness -- that is what `create_io_poller`
    /// is for -- and several of them can be blocked on this one queue at
    /// once. Keeping one waker would mean the second poller to block
    /// overwrites the first, so when capacity returned only the last one
    /// registered would be woken and the others would stay parked until
    /// something unrelated happened to poll them. Waking all of them costs
    /// at most a few spurious polls, which is the cheap direction to be
    /// wrong in.
    wakers: StdMutex<HashMap<u64, std::task::Waker>>,
}

#[cfg(turmoil)]
impl SimulatedSendQueue {
    fn enqueue(&self, datagram: QuicDatagram) -> io::Result<()> {
        match self.tx.try_send(datagram) {
            Ok(()) => Ok(()),
            // The contract quinn expects from a real socket: not sent, not
            // dropped, ask again when writable. Reporting success here and
            // queueing anyway is what turns kernel-bounded traffic into
            // unbounded heap, and hides the pacing quinn would otherwise do.
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "hub writer task is gone"))
            }
        }
    }

    fn poll_writable(&self, poller_id: u64, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.tx.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "hub writer task is gone",
            )));
        }
        // Registered BEFORE the capacity check, so a dequeue landing between
        // the two wakes this poller rather than being missed -- the reverse
        // order loses exactly the wakeup that would have unstuck it.
        self.wakers.lock().unwrap_or_else(|p| p.into_inner()).insert(poller_id, cx.waker().clone());
        if self.tx.capacity() > 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// Wakes every poller waiting on capacity, not just the most recent one.
    fn wake_writers(&self) {
        let waiting: Vec<std::task::Waker> =
            self.wakers.lock().unwrap_or_else(|p| p.into_inner()).drain().map(|(_, w)| w).collect();
        for waker in waiting {
            waker.wake();
        }
    }

    /// Forgets a poller that is going away, so a dropped one does not leave
    /// its waker in the map for the rest of the endpoint's life.
    fn forget(&self, poller_id: u64) {
        self.wakers.lock().unwrap_or_else(|p| p.into_inner()).remove(&poller_id);
    }
}

/// The `AsyncUdpSocket` a `quinn::Endpoint` is built on so it shares the
/// hub's socket. See this module's own doc comment for why.
///
/// ## The dual-stack boundary lives here, not in `TransportHub`
///
/// `quinn::Endpoint::new_with_abstract_socket` decides, ONCE, whether the
/// endpoint it builds may dial IPv6 addresses at all -- from this type's own
/// [`local_addr`](AsyncUdpSocket::local_addr): if that reports an IPv4
/// address, `quinn` sets its internal `endpoint.ipv6 = false` and refuses
/// every subsequent IPv6 dial with `InvalidRemoteAddress`, before ever
/// reaching [`try_send`](AsyncUdpSocket::try_send) -- even though the hub
/// underneath is fully capable of sending it (see [`TransportHub`]'s own
/// dual-socket design). [`report_ipv6`] is this boundary's answer to that:
/// when the hub has a bound IPv6 half, this reports the logical dual-stack
/// address `[::]:port` instead of the hub's own (always-IPv4)
/// [`TransportHub::local_addr`], which is deliberately left alone -- it
/// backs logging call sites whose meaning must not change.
///
/// Reporting IPv6 upward has a real consequence downward, though: once
/// `quinn` believes this endpoint is dual-stack, it normalizes every IPv4
/// destination it hands to [`try_send`] into its IPv4-mapped IPv6 form
/// (`::ffff:a.b.c.d`) -- see `quinn::Endpoint::connect_with`'s own
/// `ensure_ipv6`. The hub's [`UdpEndpoint::socket_for`] picks a real v4 vs.
/// v6 socket purely off `SocketAddr::is_ipv4()`, which a mapped address
/// answers `false` to -- unmapped, every IPv4 send from a dual-stack-
/// reporting endpoint would silently go out the v6-only socket instead,
/// which cannot reach an IPv4-only peer at all. [`to_hub_addr`] undoes the
/// mapping right at this boundary, before the hub ever sees the address, so
/// the hub's own v4/v6 selection keeps working exactly as it did before this
/// boundary reported IPv6 at all.
///
/// The receive path needs the identical normalization in the OTHER
/// direction: a real IPv4 peer's datagram arrives on the hub's real v4
/// socket carrying a plain IPv4 source address, but a `quinn` endpoint that
/// believes itself dual-stack expects every address it sees -- outbound
/// destinations and inbound sources alike -- in the same normalized shape,
/// so that the SAME peer is never represented two different ways depending
/// on which leg of the conversation produced the address. [`to_quinn_addr`]
/// re-maps an inbound IPv4 source into its IPv4-mapped IPv6 form before
/// [`poll_recv`](AsyncUdpSocket::poll_recv) hands it to `quinn`, mirroring
/// [`to_hub_addr`] exactly.
///
/// Neither mapping does anything when [`report_ipv6`] is false (a host with
/// no usable IPv6, or `TransportHub::from_socket`'s single-socket adoption):
/// `quinn`'s own `endpoint.ipv6` is false in that case too, so it never
/// produces a mapped address to begin with, and this boundary stays a
/// byte-for-byte pass-through -- unchanged from this type's pre-dual-stack
/// behavior.
pub struct TransportHubQuicSocket {
    /// Native only: the send path there is the hub's own synchronous
    /// `try_send_datagram`, so the socket calls the hub directly. Under
    /// simulation the send path is the writer task, which holds its own
    /// handle, and this one would be dead weight.
    #[cfg(not(turmoil))]
    hub: Arc<TransportHub>,
    /// The address reported to `quinn` via `AsyncUdpSocket::local_addr` --
    /// NOT necessarily `hub.local_addr()`. See this type's own doc comment.
    local_addr: SocketAddr,
    /// Whether [`local_addr`] reports IPv6 (and both address-mapping
    /// helpers are therefore active). Cached at construction rather than
    /// re-derived from `local_addr.is_ipv6()` on every send/receive purely
    /// to make the two questions ("what do I tell quinn" and "am I in
    /// dual-stack mode") impossible to accidentally answer inconsistently
    /// if one is ever changed without the other.
    report_ipv6: bool,
    /// Datagrams the demux routed here. `Mutex` because `poll_recv` takes
    /// `&self` while the receiver needs `&mut`; quinn drives exactly one
    /// receive task per endpoint, so this is uncontended in practice.
    inbound: StdMutex<mpsc::Receiver<QuicDatagram>>,
    /// Simulation only -- see `try_send`.
    #[cfg(turmoil)]
    outbound: Arc<SimulatedSendQueue>,
}

/// Undoes `quinn`'s IPv4-mapped-IPv6 normalization (`::ffff:a.b.c.d`) right
/// before the hub picks a real socket by address family -- see
/// [`TransportHubQuicSocket`]'s own doc comment for why this exists. A
/// non-mapped address, or any IPv6 address that is not an IPv4 mapping,
/// passes through unchanged.
fn to_hub_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// The receive-path mirror of [`to_hub_addr`]: maps a real IPv4 source
/// address into its IPv4-mapped IPv6 form before handing it to `quinn`, so
/// an endpoint `quinn` believes is dual-stack never sees the same peer
/// represented two different ways depending on which leg of the
/// conversation produced the address. A no-op when `report_ipv6` is false.
fn to_quinn_addr(addr: SocketAddr, report_ipv6: bool) -> SocketAddr {
    if !report_ipv6 {
        return addr;
    }
    match addr {
        SocketAddr::V4(v4) => {
            SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        SocketAddr::V6(_) => addr,
    }
}

impl fmt::Debug for TransportHubQuicSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportHubQuicSocket")
            .field("local_addr", &self.local_addr)
            .field("report_ipv6", &self.report_ipv6)
            .finish()
    }
}

impl TransportHubQuicSocket {
    /// Registers the QUIC arm of `hub`'s demux and returns the socket a
    /// `quinn::Endpoint` should be built on.
    ///
    /// Exactly one may exist per hub, and a second is refused rather than
    /// allowed to replace the first -- see
    /// [`TransportHub::register_quic`](crate::TransportHub::register_quic).
    pub fn new(hub: Arc<TransportHub>) -> Result<Arc<Self>, crate::TransportError> {
        // The address reported to quinn is NOT necessarily the hub's own
        // `local_addr()` -- see this type's own doc comment for the full
        // reasoning. `hub.local_addr()`'s own meaning is left untouched for
        // its other callers (logging).
        let report_ipv6 = hub.has_ipv6();
        let local_addr = if report_ipv6 {
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                hub.local_addr().port(),
            )
        } else {
            hub.local_addr()
        };
        let inbound = hub.register_quic()?;

        #[cfg(turmoil)]
        let outbound = {
            // The simulated `UdpSocket` cannot satisfy quinn's synchronous
            // `try_send` directly: it has a `try_send_to` but no
            // `poll_send_ready`, so a refusal there could never be paired
            // with a wakeup. The datagram goes to a writer task
            // through a BOUNDED queue, and that queue is what makes the
            // simulated send path behave like the native one: refuse when
            // full, wake when drained. See `SIMULATED_SEND_QUEUE_DEPTH`.
            let (tx, mut rx) = mpsc::channel::<QuicDatagram>(SIMULATED_SEND_QUEUE_DEPTH);
            let queue = Arc::new(SimulatedSendQueue { tx, wakers: StdMutex::new(HashMap::new()) });
            let hub = hub.clone();
            let writer_queue = queue.clone();
            tokio::spawn(async move {
                while let Some((datagram, dst)) = rx.recv().await {
                    // Woken immediately on dequeue rather than after the
                    // send: capacity is what the poller is waiting for, and
                    // it is free the moment the datagram leaves the queue.
                    writer_queue.wake_writers();
                    // `try_send` has already told quinn this datagram was
                    // accepted, so a failure here cannot be reported back to
                    // it -- quinn will see the loss and retransmit, which is
                    // the same recovery a genuinely dropped packet gets.
                    // Logged rather than discarded so a simulated run that
                    // fails this way is diagnosable instead of looking like
                    // inexplicable loss.
                    if let Err(error) = hub.send_to(&datagram, dst).await {
                        tracing::debug!(%error, %dst, "simulated QUIC datagram send failed");
                    }
                }
            });
            queue
        };

        Ok(Arc::new(Self {
            #[cfg(not(turmoil))]
            hub,
            local_addr,
            report_ipv6,
            inbound: StdMutex::new(inbound),
            #[cfg(turmoil)]
            outbound,
        }))
    }
}

impl AsyncUdpSocket for TransportHubQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HubUdpPoller { socket: self, id: TransportHub::next_send_poller_id() })
    }

    /// `Transmit::src_ip` is ignored: the hub picks its outgoing socket from
    /// the destination's address family (it holds a v4/v6 pair on one port),
    /// which is what keeps candidate addresses unambiguous. Honouring a
    /// source hint would mean overriding that choice, and there is no
    /// multi-homing story here for it to serve -- a device has exactly one
    /// hub binding, and which local address a peer should use is decided by
    /// candidate discovery, not per-datagram.
    ///
    /// `Transmit::ecn` is likewise ignored; ECN codepoints are not settable
    /// through the socket API this bridge has, and `RecvMeta` below reports
    /// `None` to match. Losing ECN costs congestion-control precision, not
    /// correctness.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Undo quinn's own IPv4-mapped-IPv6 normalization before the hub
        // ever sees the address -- see this type's own doc comment. A no-op
        // for a genuinely IPv6 destination, or when quinn was never told
        // this endpoint is dual-stack in the first place.
        let destination = to_hub_addr(transmit.destination);
        #[cfg(not(turmoil))]
        {
            self.hub.try_send_datagram(transmit.contents, destination)
        }
        #[cfg(turmoil)]
        {
            self.outbound.enqueue((transmit.contents.to_vec(), destination))
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut inbound = self.inbound.lock().unwrap_or_else(|p| p.into_inner());
        let mut filled = 0;
        while filled < bufs.len() && filled < meta.len() {
            // Only the first datagram may register a waker: once at least
            // one is in hand, returning it beats parking for more.
            let next = match inbound.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => datagram,
                // The hub is gone. Reporting this as an error rather than
                // pending stops quinn's receive task from parking forever
                // against a queue nothing can ever fill again.
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "transport hub demux closed",
                    )))
                }
                Poll::Pending if filled == 0 => return Poll::Pending,
                Poll::Pending => break,
            };
            let (datagram, from) = next;
            // A datagram larger than the buffer quinn offered cannot be
            // delivered intact, and a truncated QUIC packet fails
            // authentication anyway. Skip it rather than hand over a
            // silently short read that would surface as a decrypt failure
            // far from the cause.
            if datagram.len() > bufs[filled].len() {
                tracing::debug!(
                    len = datagram.len(),
                    capacity = bufs[filled].len(),
                    "dropping oversized inbound QUIC datagram"
                );
                continue;
            }
            bufs[filled][..datagram.len()].copy_from_slice(&datagram);
            meta[filled] = RecvMeta {
                len: datagram.len(),
                stride: datagram.len(),
                // Mirrors `try_send`'s own mapping in the other direction --
                // see this type's own doc comment. A no-op unless quinn was
                // told this endpoint is dual-stack.
                addr: to_quinn_addr(from, self.report_ipv6),
                ecn: None,
                dst_ip: None,
            };
            filled += 1;
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// GSO and GRO are both off. quinn would otherwise hand this bridge a
    /// single `Transmit` describing several datagrams to be split by the
    /// kernel, which is exactly the `quinn-udp` path the hub does not go
    /// through and the simulator cannot observe.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Write-readiness for [`TransportHubQuicSocket`].
///
/// One per caller that needs it, which is the point of quinn's
/// `create_io_poller`: several can be waiting at once, and each has to be
/// woken on its own.
struct HubUdpPoller {
    socket: Arc<TransportHubQuicSocket>,
    /// This poller's own slot in whichever waker map it registers with: the
    /// simulated send queue's, or -- natively -- the hub's TURN send
    /// queue's. The kernel socket registers each poller's waker itself and
    /// needs no id, but the queue in front of a TURN allocation does, since
    /// several pollers can be blocked on it at once.
    id: u64,
}

impl Drop for HubUdpPoller {
    fn drop(&mut self) {
        // Nothing to forget on the native path: the only waker map this hub
        // ever had belonged to the TURN router, and the V4/V6 sockets register
        // their own wakers through `poll_send_ready`.
        #[cfg(turmoil)]
        {
            self.socket.outbound.forget(self.id);
        }
    }
}

impl fmt::Debug for HubUdpPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HubUdpPoller")
    }
}

impl UdpPoller for HubUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        #[cfg(not(turmoil))]
        {
            self.socket.hub.poll_quic_send_ready(self.id, _cx)
        }
        #[cfg(turmoil)]
        {
            self.socket.outbound.poll_writable(self.id, _cx)
        }
    }
}

#[cfg(test)]
mod tests;
