//! Relay-carried peer traffic, presented to `quinn` as an ordinary UDP path.
//!
//! ## Why a synthetic address, and not the relay's real one
//!
//! A relayed packet physically arrives from the relaying device's address,
//! not the peer's. Handing it to quinn under that address would be wrong in
//! two separate ways: quinn would read every packet as the peer migrating
//! its path, and the relay's address would enter path validation as though
//! it belonged to the peer. So each relay path gets a stable **synthetic**
//! `SocketAddr` that means "this peer, by way of that relay". Every packet
//! for the path leaves through it and every packet from the path arrives
//! claiming it, so to quinn a relayed peer is an ordinary UDP path that
//! never migrates -- connection ids, loss recovery, flow control and
//! encryption all keep working untouched.
//!
//! The address is an opaque local handle. It deliberately encodes nothing:
//! not the relay, not the peer, not the session. The two ends of a relayed
//! connection do not agree on the value and never need to, because it is
//! only a token this process uses to tell one remote path from another. It
//! is drawn from `240.0.0.0/4` (IPv4 "reserved for future use", RFC 1112
//! s 4) or from `0100::/64` (the IPv6 discard-only prefix, RFC 6666) so it
//! can never collide with an address a real peer could be reached at, and
//! so a synthetic address that somehow escaped onto a socket would be
//! dropped by the first router that saw it rather than delivered somewhere
//! unintended.
//!
//! ## The two directions are not symmetric
//!
//! The relay gives every session its own `connect()`-ed ephemeral UDP
//! socket. That socket *is* the session demultiplexer, so only one of the
//! two legs needs an envelope:
//!
//! ```text
//! A -> C   A quinn -> synthetic addr -> bounded queue -> RelayData on the
//!          A-B control connection -> B's dedicated socket -> envelope ->
//!          C's hub demux -> synthetic addr -> C quinn
//!
//! C -> A   C quinn -> synthetic addr -> RAW UDP, no envelope, straight back
//!          to B's dedicated socket -> RelayData on the B-A control
//!          connection -> injected at A under the synthetic addr -> A quinn
//! ```
//!
//! Hence two ingress points rather than one: [`RelayPathHandle::inject`] on
//! the requesting side, whose bytes arrive on a control connection, and
//! [`RelayPathRouter::inject_from_relay_envelope`] on the destination side,
//! whose bytes arrive as an enveloped datagram on the shared socket.
//!
//! Nothing here authenticates anybody. It cannot: the payload is an inner
//! QUIC packet, and only the inner connection's own TLS decides who the
//! peer is. What this module owes the rest of the system is that a stream
//! of unauthenticated, envelope-shaped datagrams cannot cost more than a
//! fixed amount of memory -- see [`MAX_INBOUND_RELAY_PATHS`].

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
#[cfg(not(madsim))]
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

/// The first octet of every synthetic IPv4 handle: `240.0.0.0/4`, reserved
/// by RFC 1112 s 4 and never assigned to anything. See the module comment.
const SYNTHETIC_V4_PREFIX: u32 = 0xF000_0000;
const SYNTHETIC_V4_MASK: u32 = 0x0FFF_FFFF;

/// The first segment of every synthetic IPv6 handle: `0100::/64`, the
/// discard-only prefix (RFC 6666).
const SYNTHETIC_V6_PREFIX: u16 = 0x0100;

/// The port every synthetic handle carries. Handles are told apart by
/// address, not port; a fixed non-zero port keeps the value a well-formed
/// `SocketAddr` that quinn and the diagnostics that print it can handle
/// without a special case.
const SYNTHETIC_PORT: u16 = 1;

/// How many *inbound* relay paths -- ones minted by an envelope arriving on
/// the shared socket -- this device will hold at once.
///
/// This bound is the whole security-relevant property of this module.
/// Anything that can reach this device's port can send envelope-shaped
/// datagrams, and each unrecognized session id would otherwise mint a fresh
/// mapping that lives until it expires. The inner QUIC connection's own TLS
/// still decides who the peer is, so an unbounded table is not an
/// authentication hole -- it is a plain resource-exhaustion bug, which is
/// reason enough. Comfortably above the number of relay sessions a device
/// could legitimately be the destination of at once (the relay's own
/// concurrent-session cap is far lower), and small enough that a full table
/// is a few kilobytes.
const MAX_INBOUND_RELAY_PATHS: usize = 64;

/// How many *outbound* relay paths -- ones this device opened itself as the
/// relay requester -- may exist at once. Not attacker-reachable (only this
/// device's own connection supervisor opens one), but bounded for the same
/// reason every other table here is: a bug that forgets to close them must
/// stop at a fixed cost rather than growing without limit.
const MAX_OUTBOUND_RELAY_PATHS: usize = 32;

/// How long a relay path may sit with no traffic in either direction before
/// it can be evicted to make room for a new one.
///
/// Longer than the QUIC idle timeout on the connection riding it, so a path
/// is only ever reclaimed after the connection that needed it is itself
/// certainly gone. Shorter than anything that would let a burst of
/// unrecognized envelopes pin the table for the rest of the process's life.
const RELAY_PATH_IDLE_EXPIRY: Duration = Duration::from_secs(120);

/// How many outbound relayed datagrams may be queued for the relay control
/// connections before [`RelayPathRouter::try_send`] reports `WouldBlock`.
///
/// A relayed QUIC packet travels inside a `RelayData` frame, which itself
/// travels over a QUIC control stream -- so quinn's *synchronous*
/// `try_send` sits in front of a send that completes later. That is the
/// same mismatch the simulated socket has, and it needs the same answer:
/// a bounded queue, a refusal when it is full, and a wakeup when it drains.
/// Enqueueing without a bound would turn a peer that stops reading into
/// unbounded heap on this device, and would hide the pacing quinn does when
/// it is told to wait.
///
/// One queue for the whole device rather than one per path: it makes the
/// relay egress budget a device-wide quantity (which is what it physically
/// is -- one socket, one process), and it is what lets a single write-
/// readiness poll answer for every relay path at once. quinn's poller
/// carries no destination, so a per-path queue could not be polled for the
/// right path anyway.
const RELAY_CONTROL_QUEUE_DEPTH: usize = 256;

/// Where a relay-requesting device sends the QUIC packets it wants carried:
/// as `RelayData` on the control connection with the relaying peer.
///
/// Defined here and implemented in the daemon, which is the only layer that
/// knows about relay grants, sessions and peers -- this crate cannot depend
/// on it.
///
/// Synchronous and best-effort by design. The relay leg is a datagram
/// carrier standing in for a UDP send, so a `false` return is exactly as
/// harmful as a dropped packet: QUIC sees the loss and retransmits.
pub trait RelayControlEgress: Send + Sync {
    /// Hands one QUIC packet to the relaying peer. Returns whether the
    /// control channel accepted it.
    fn send_relay_data(&self, payload: Vec<u8>) -> bool;
}

/// What a synthetic address stands for.
enum RelayPathKind {
    /// The requesting side ("A"). Outbound packets become `RelayData` on the
    /// control connection with the relay; inbound ones arrive the same way
    /// and are injected through [`RelayPathHandle::inject`].
    Control(Arc<dyn RelayControlEgress>),
    /// The destination side ("C"). Outbound packets go straight back to the
    /// relay's dedicated per-session forwarding socket as **raw UDP with no
    /// envelope** -- that socket is `connect()`-ed to this device, so it
    /// already identifies the session and needs nothing added to say so.
    Envelope { relay_outer_addr: SocketAddr },
}

impl fmt::Debug for RelayPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayPathKind::Control(_) => f.write_str("Control"),
            RelayPathKind::Envelope { .. } => f.write_str("Envelope"),
        }
    }
}

struct RelayPath {
    kind: RelayPathKind,
    /// Refreshed on every packet in either direction; read only by the
    /// eviction sweep, so a coarse value is fine.
    last_active: Instant,
}

/// Where an outbound datagram addressed to a synthetic handle actually has
/// to go, resolved by [`RelayPathRouter::resolve`].
pub(crate) enum RelayEgress {
    /// Hand it to the relay control queue -- see
    /// [`RelayPathRouter::try_send`].
    Control,
    /// Send it as an ordinary datagram to this address, unchanged.
    Raw(SocketAddr),
}

#[derive(Default)]
struct RouterState {
    by_addr: HashMap<SocketAddr, RelayPath>,
    /// `(relay forwarding socket address, relay session id) -> synthetic
    /// address`, so a second envelope for a session already seen reuses the
    /// mapping the first one minted instead of presenting quinn with a new
    /// path. Only inbound (`Envelope`) paths are indexed: an outbound one is
    /// found through the [`RelayPathHandle`] its opener holds.
    inbound_index: HashMap<(SocketAddr, u64), SocketAddr>,
    outbound_paths: usize,
    inbound_paths: usize,
    next_handle: u32,
}

/// The routing table mapping synthetic addresses to relay paths, plus the
/// bounded queue that carries the requesting side's outbound packets.
///
/// Lives inside the transport hub's demux registry, so the hub's send path
/// can resolve a synthetic destination and its receive path can inject an
/// enveloped datagram, with no reference cycle between the two.
pub(crate) struct RelayPathRouter {
    state: StdMutex<RouterState>,
    /// The address family every synthetic handle is minted in, taken from
    /// the hub's own binding. It has to match: quinn refuses to dial an IPv6
    /// address from an endpoint it believes is IPv4-only, and the whole
    /// point of a synthetic address is that quinn treats it as ordinary.
    family_is_v4: bool,
    control_queue: mpsc::Sender<(Arc<dyn RelayControlEgress>, Vec<u8>)>,
    /// Every write-readiness poller currently parked on `control_queue`
    /// having room, keyed so one poller's registration cannot overwrite
    /// another's. Same reasoning as the simulated send queue's own waker
    /// map: quinn creates a poller per caller that needs write readiness,
    /// and several can be blocked at once. Shared with the writer task,
    /// which is what wakes them.
    ///
    /// Native only. Under simulation quinn's write readiness comes from the
    /// simulated send queue instead -- there is no synchronous send there at
    /// all, so every datagram, relayed or not, is already paced by that
    /// queue and a second source of back-pressure would be redundant.
    #[cfg(not(madsim))]
    control_wakers: Arc<StdMutex<HashMap<u64, std::task::Waker>>>,
    /// Envelope-shaped datagrams dropped because the inbound path table was
    /// full of live entries, or because the payload could not be a QUIC
    /// packet. Counted rather than silent so a device being flooded, or one
    /// whose relay is misbehaving, is diagnosable instead of merely quiet.
    inbound_dropped: AtomicU64,
    /// Outbound relayed datagrams the relay control connection refused --
    /// ordinary datagram loss, but worth a number. Shared with the writer
    /// task, which is where the refusal is observed.
    control_send_failed: Arc<AtomicU64>,
}

/// Hands out one id per write-readiness poller, so each has its own slot in
/// the waker map it registers with rather than sharing one -- see
/// [`RelayPathRouter::poll_control_writable`].
static NEXT_RELAY_POLLER_ID: AtomicU64 = AtomicU64::new(0);

impl RelayPathRouter {
    /// Builds the router for a hub bound at `local_addr` and starts the task
    /// that drains the relay control queue.
    pub(crate) fn new(local_addr: SocketAddr) -> Self {
        let (tx, mut rx) =
            mpsc::channel::<(Arc<dyn RelayControlEgress>, Vec<u8>)>(RELAY_CONTROL_QUEUE_DEPTH);
        // The writer task holds only the queue's receiver and the two cells
        // it reports through -- never the router itself. A task that kept
        // the router alive would keep the hub's demux registry alive with
        // it, and neither would ever be dropped.
        let control_send_failed = Arc::new(AtomicU64::new(0));
        let control_wakers: Arc<StdMutex<HashMap<u64, std::task::Waker>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let failed_for_task = control_send_failed.clone();
        let wakers_for_task = control_wakers.clone();
        tokio::spawn(async move {
            while let Some((egress, payload)) = rx.recv().await {
                // Woken on dequeue rather than after the send: capacity is
                // what a blocked poller is waiting for, and it is free the
                // moment the datagram leaves the queue.
                wake_all(&wakers_for_task);
                if !egress.send_relay_data(payload) {
                    failed_for_task.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        Self {
            state: StdMutex::new(RouterState::default()),
            family_is_v4: local_addr.is_ipv4(),
            control_queue: tx,
            #[cfg(not(madsim))]
            control_wakers,
            inbound_dropped: AtomicU64::new(0),
            control_send_failed,
        }
    }

    /// Mints a synthetic address for a relay path this device is opening as
    /// the requester, or reports that this device already holds as many as
    /// it will.
    pub(crate) fn open_control_path(
        &self,
        egress: Arc<dyn RelayControlEgress>,
    ) -> Result<SocketAddr, crate::TransportError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_instant();
        evict_expired(&mut state, now);
        if state.outbound_paths >= MAX_OUTBOUND_RELAY_PATHS {
            return Err(crate::TransportError::NoRoute(
                "this device already holds the maximum number of relay paths".to_string(),
            ));
        }
        let addr = mint_addr(&mut state, self.family_is_v4);
        state
            .by_addr
            .insert(addr, RelayPath { kind: RelayPathKind::Control(egress), last_active: now });
        state.outbound_paths += 1;
        Ok(addr)
    }

    /// Forgets `addr`, whatever kind of path it named. Idempotent.
    pub(crate) fn close_relay_path(&self, addr: SocketAddr) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        remove_path(&mut state, addr);
    }

    /// Where a datagram addressed to `addr` should actually go, or `None` if
    /// `addr` is not a synthetic handle this device knows.
    ///
    /// Returning `None` for an unknown *synthetic* address matters as much
    /// as resolving a known one: a datagram addressed to a synthetic handle
    /// must never fall through to the real socket, where it would be sent to
    /// a reserved address that means nothing.
    pub(crate) fn resolve(&self, addr: SocketAddr) -> Option<RelayEgress> {
        if !is_synthetic_relay_addr(addr) {
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_instant();
        let path = state.by_addr.get_mut(&addr)?;
        path.last_active = now;
        match &path.kind {
            RelayPathKind::Control(_) => Some(RelayEgress::Control),
            RelayPathKind::Envelope { relay_outer_addr } => Some(RelayEgress::Raw(*relay_outer_addr)),
        }
    }

    /// Enqueues one outbound datagram for the relay control connection that
    /// owns `addr`.
    ///
    /// Reports `WouldBlock` when the queue is full, which is the contract a
    /// real socket has and the one quinn paces itself against: not sent, not
    /// dropped, ask again when writable. Answering `Ok` and queueing anyway
    /// is what turns kernel-bounded traffic into unbounded heap.
    pub(crate) fn try_send(&self, addr: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let egress = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match state.by_addr.get(&addr).map(|path| &path.kind) {
                Some(RelayPathKind::Control(egress)) => egress.clone(),
                // Resolved a moment ago and gone now: the path closed
                // between the two. Indistinguishable from the datagram being
                // lost on the relay leg, which is what it effectively is.
                _ => return Ok(()),
            }
        };
        match self.control_queue.try_send((egress, payload.to_vec())) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "relay control writer is gone"))
            }
        }
    }

    /// Write-readiness for the relay control queue.
    ///
    /// Registered before the capacity check so a dequeue landing between the
    /// two wakes this poller rather than being missed.
    #[cfg(not(madsim))]
    pub(crate) fn poll_control_writable(&self, poller_id: u64, cx: &mut Context<'_>) -> Poll<()> {
        // Keyed by the caller's own stable id rather than a fresh one per
        // poll: quinn re-polls write readiness constantly, and a new entry
        // each time would grow this map without bound between drains, which
        // is the same unbounded-table mistake the path tables are bounded to
        // avoid. One slot per poller also means a second poller blocking
        // cannot overwrite the first's registration and leave it parked.
        self.control_wakers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(poller_id, cx.waker().clone());
        if self.control_queue.capacity() > 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Forgets a poller that is going away, so a dropped one does not leave
    /// its waker in the map for the rest of the endpoint's life.
    #[cfg(not(madsim))]
    pub(crate) fn forget_control_poller(&self, poller_id: u64) {
        self.control_wakers.lock().unwrap_or_else(|p| p.into_inner()).remove(&poller_id);
    }

    /// Allocates a stable id for one write-readiness poller.
    pub(crate) fn next_poller_id() -> u64 {
        NEXT_RELAY_POLLER_ID.fetch_add(1, Ordering::Relaxed)
    }

    /// Destination-side ingress: one enveloped datagram arrived on the
    /// shared socket from `relay_outer_addr`, carrying `relay_session_id`.
    ///
    /// Returns the synthetic address the payload should be presented to
    /// quinn under, or `None` if it must be dropped -- either because the
    /// payload cannot be a QUIC packet, or because the inbound table is full
    /// of paths that are still live.
    ///
    /// Refusing rather than evicting a live path is the deliberate choice.
    /// The table is bounded because an attacker can mint entries in it; if a
    /// full table evicted the oldest live entry, that attacker could push
    /// out the relay path a real connection is running on, which is a worse
    /// outcome than refusing the new one.
    pub(crate) fn inject_from_relay_envelope(
        &self,
        relay_outer_addr: SocketAddr,
        relay_session_id: u64,
        payload: &[u8],
    ) -> Option<SocketAddr> {
        // Every QUIC packet has the fixed bit set in byte 0. A payload that
        // fails this is not something quinn could act on, so minting a
        // mapping for it would be pure cost -- and minting is exactly what
        // an unauthenticated sender would be trying to make this device do.
        if payload.first().is_none_or(|byte| byte & 0x40 == 0) {
            self.inbound_dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_instant();
        let key = (relay_outer_addr, relay_session_id);
        if let Some(&addr) = state.inbound_index.get(&key) {
            if let Some(path) = state.by_addr.get_mut(&addr) {
                path.last_active = now;
                return Some(addr);
            }
            // Index and table disagreed, which only the eviction sweep can
            // cause; drop the stale index entry and mint below.
            state.inbound_index.remove(&key);
        }
        evict_expired(&mut state, now);
        if state.inbound_paths >= MAX_INBOUND_RELAY_PATHS {
            self.inbound_dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let addr = mint_addr(&mut state, self.family_is_v4);
        state.by_addr.insert(
            addr,
            RelayPath { kind: RelayPathKind::Envelope { relay_outer_addr }, last_active: now },
        );
        state.inbound_index.insert(key, addr);
        state.inbound_paths += 1;
        tracing::debug!(%relay_outer_addr, relay_session_id, %addr, "opened an inbound relay path");
        Some(addr)
    }

    /// Requesting-side ingress: refreshes `addr`'s activity clock and
    /// reports whether it is still a live control path, so the caller knows
    /// whether the bytes are worth handing to quinn.
    pub(crate) fn touch_control_path(&self, addr: SocketAddr) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = now_instant();
        match state.by_addr.get_mut(&addr) {
            Some(path @ RelayPath { kind: RelayPathKind::Control(_), .. }) => {
                path.last_active = now;
                true
            }
            _ => false,
        }
    }

    /// Outbound relayed datagrams the relay control connection would not
    /// take -- see `control_send_failed`.
    pub(crate) fn control_send_failures(&self) -> u64 {
        self.control_send_failed.load(Ordering::Relaxed)
    }
}

fn wake_all(wakers: &StdMutex<HashMap<u64, std::task::Waker>>) {
    let waiting: Vec<std::task::Waker> =
        wakers.lock().unwrap_or_else(|p| p.into_inner()).drain().map(|(_, w)| w).collect();
    for waker in waiting {
        waker.wake();
    }
}

/// Drops every path with no traffic in either direction for
/// [`RELAY_PATH_IDLE_EXPIRY`]. Called before minting rather than on a timer:
/// the table only needs to be tidy at the moment something wants room in it,
/// and a sweep tied to allocation cannot itself be a source of wakeups.
fn evict_expired(state: &mut RouterState, now: Instant) {
    let expired: Vec<SocketAddr> = state
        .by_addr
        .iter()
        .filter(|(_, path)| now.saturating_duration_since(path.last_active) >= RELAY_PATH_IDLE_EXPIRY)
        .map(|(addr, _)| *addr)
        .collect();
    for addr in expired {
        remove_path(state, addr);
    }
}

fn remove_path(state: &mut RouterState, addr: SocketAddr) {
    let Some(path) = state.by_addr.remove(&addr) else {
        return;
    };
    match path.kind {
        RelayPathKind::Control(_) => state.outbound_paths = state.outbound_paths.saturating_sub(1),
        RelayPathKind::Envelope { .. } => {
            state.inbound_paths = state.inbound_paths.saturating_sub(1);
            state.inbound_index.retain(|_, indexed| *indexed != addr);
        }
    }
}

/// Allocates a synthetic address not already in the table.
///
/// The counter is monotonic so a freshly closed path's address is not handed
/// straight back out -- a datagram still in flight for the old path would
/// otherwise be delivered to quinn as if it belonged to the new one. The
/// occupancy check is what keeps that true across the counter wrapping,
/// which needs 2^28 paths to reach and cannot happen with the table bounded
/// as it is, but costs one hash lookup to rule out entirely.
fn mint_addr(state: &mut RouterState, family_is_v4: bool) -> SocketAddr {
    loop {
        let handle = state.next_handle;
        state.next_handle = state.next_handle.wrapping_add(1);
        let ip = if family_is_v4 {
            IpAddr::V4(Ipv4Addr::from(SYNTHETIC_V4_PREFIX | (handle & SYNTHETIC_V4_MASK)))
        } else {
            let mut octets = [0u8; 16];
            octets[0..2].copy_from_slice(&SYNTHETIC_V6_PREFIX.to_be_bytes());
            octets[12..16].copy_from_slice(&handle.to_be_bytes());
            IpAddr::V6(Ipv6Addr::from(octets))
        };
        let addr = SocketAddr::new(ip, SYNTHETIC_PORT);
        if !state.by_addr.contains_key(&addr) {
            return addr;
        }
    }
}

/// Whether `addr` is one of this process's synthetic relay handles rather
/// than an address a peer could really be reached at.
///
/// Exported because the layer above has to know: a connection whose remote
/// address is synthetic is relay-carried, and relay-carried traffic must
/// never promote a peer to a confirmed *direct* route. Below this point
/// quinn cannot tell the difference, so the distinction has to be drawn
/// here.
pub fn is_synthetic_relay_addr(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => u32::from(v4) & !SYNTHETIC_V4_MASK == SYNTHETIC_V4_PREFIX,
        IpAddr::V6(v6) => v6.segments()[0] == SYNTHETIC_V6_PREFIX && v6.segments()[1..4] == [0, 0, 0],
    }
}

/// The clock this module measures path idleness on -- the same one quinn
/// reads, so a path's lifetime is measured on the same timeline as the
/// connection riding it, including under simulation.
fn now_instant() -> Instant {
    crate::quic_socket::now_instant()
}

/// A relay path this device opened as the requester, and the only way to
/// feed bytes into it.
///
/// Closing is tied to the handle's lifetime rather than left to a separate
/// call, because the failure mode of forgetting is a synthetic address that
/// stays in the table with nothing left to use it. The daemon holds one of
/// these for as long as the relay session exists and drops it when the
/// session ends.
pub struct RelayPathHandle {
    /// `Weak` so a handle outliving its hub -- which is ordinary at
    /// shutdown, where drop order between the two is not fixed -- neither
    /// keeps the hub alive nor panics on the way out.
    router: Weak<crate::transport_hub::DemuxRegistry>,
    addr: SocketAddr,
}

impl fmt::Debug for RelayPathHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayPathHandle").field("synthetic_addr", &self.addr).finish()
    }
}

impl RelayPathHandle {
    pub(crate) fn new(router: Weak<crate::transport_hub::DemuxRegistry>, addr: SocketAddr) -> Self {
        Self { router, addr }
    }

    /// The address quinn should be told this peer is at.
    pub fn synthetic_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Feeds one relay-carried QUIC packet -- the payload of a `RelayData`
    /// frame that arrived on the control connection with the relay -- into
    /// this device's QUIC endpoint under this path's synthetic address.
    ///
    /// Returns whether it was delivered. `false` means the path has been
    /// closed or the endpoint's inbound queue is full, both of which are
    /// ordinary datagram loss from QUIC's point of view.
    pub fn inject(&self, payload: &[u8]) -> bool {
        let Some(registry) = self.router.upgrade() else {
            return false;
        };
        registry.inject_relay_control(self.addr, payload)
    }
}

impl Drop for RelayPathHandle {
    fn drop(&mut self) {
        if let Some(registry) = self.router.upgrade() {
            registry.close_relay_path(self.addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address literal")
    }

    struct NullEgress;

    impl RelayControlEgress for NullEgress {
        fn send_relay_data(&self, _payload: Vec<u8>) -> bool {
            true
        }
    }

    /// A QUIC long-header packet's first byte, which is what the inbound
    /// path check looks at.
    const QUIC_BYTE: u8 = 0xC0;

    #[tokio::test]
    async fn a_synthetic_address_is_never_an_address_a_peer_could_have() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let path = router.open_control_path(Arc::new(NullEgress)).expect("first path opens");
        assert!(is_synthetic_relay_addr(path));
        for real in ["127.0.0.1:41641", "192.168.1.5:41641", "198.51.100.7:1", "[::1]:41641"] {
            assert!(!is_synthetic_relay_addr(addr(real)), "{real} must not read as synthetic");
        }
    }

    /// Two envelopes for the same relay session must present quinn with the
    /// SAME address -- a fresh one per packet is exactly the continuous path
    /// migration this whole mechanism exists to avoid.
    #[tokio::test]
    async fn one_relay_session_maps_to_one_stable_address() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let outer = addr("203.0.113.9:5000");
        let first = router.inject_from_relay_envelope(outer, 7, &[QUIC_BYTE, 1, 2]).unwrap();
        let second = router.inject_from_relay_envelope(outer, 7, &[QUIC_BYTE, 3, 4]).unwrap();
        assert_eq!(first, second);
        // A different session on the same relay socket is a different path.
        let other = router.inject_from_relay_envelope(outer, 8, &[QUIC_BYTE, 5]).unwrap();
        assert_ne!(first, other);
    }

    /// The destination side answers a relay path with raw UDP to the relay's
    /// own forwarding socket -- no envelope, because that socket already
    /// identifies the session.
    #[tokio::test]
    async fn the_destination_side_answers_with_raw_udp_to_the_relay_socket() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let outer = addr("203.0.113.9:5000");
        let synthetic = router.inject_from_relay_envelope(outer, 7, &[QUIC_BYTE]).unwrap();
        match router.resolve(synthetic) {
            Some(RelayEgress::Raw(target)) => assert_eq!(target, outer),
            _ => panic!("a destination-side path must resolve to a raw send at the relay"),
        }
    }

    /// The requesting side's outbound packets go to the control queue, not
    /// to any real address.
    #[tokio::test]
    async fn the_requesting_side_sends_through_the_control_queue() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let synthetic = router.open_control_path(Arc::new(NullEgress)).unwrap();
        assert!(matches!(router.resolve(synthetic), Some(RelayEgress::Control)));
        assert!(router.try_send(synthetic, &[QUIC_BYTE, 1, 2]).is_ok());
    }

    /// Anything that can reach this device's port can send envelope-shaped
    /// datagrams, so unknown session ids must stop minting mappings at a
    /// fixed count rather than growing the table without limit.
    #[tokio::test]
    async fn unrecognized_envelopes_cannot_grow_the_table_without_limit() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let outer = addr("203.0.113.9:5000");
        let mut minted = 0;
        for session_id in 0..(MAX_INBOUND_RELAY_PATHS as u64 * 4) {
            if router.inject_from_relay_envelope(outer, session_id, &[QUIC_BYTE]).is_some() {
                minted += 1;
            }
        }
        assert_eq!(minted, MAX_INBOUND_RELAY_PATHS);
        assert!(router.inbound_dropped.load(Ordering::Relaxed) > 0, "refusals must be counted, not silent");
    }

    /// A payload that cannot be a QUIC packet is refused before it can cost
    /// a table entry.
    #[tokio::test]
    async fn a_payload_that_cannot_be_quic_mints_nothing() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let outer = addr("203.0.113.9:5000");
        assert!(router.inject_from_relay_envelope(outer, 1, &[0x00, 0x01]).is_none());
        assert!(router.inject_from_relay_envelope(outer, 2, &[]).is_none());
        assert_eq!(router.inbound_dropped.load(Ordering::Relaxed), 2);
    }

    /// A device cannot be made to hold an unbounded number of paths it
    /// opened itself either.
    #[tokio::test]
    async fn outbound_paths_are_bounded_too() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let mut opened = Vec::new();
        for _ in 0..MAX_OUTBOUND_RELAY_PATHS {
            opened.push(router.open_control_path(Arc::new(NullEgress)).expect("within the bound"));
        }
        assert!(router.open_control_path(Arc::new(NullEgress)).is_err());
        // Closing one makes room again.
        router.close_relay_path(opened.pop().unwrap());
        assert!(router.open_control_path(Arc::new(NullEgress)).is_ok());
    }

    /// A closed path stops resolving, so a datagram addressed to it is never
    /// sent to the reserved address the handle was drawn from.
    #[tokio::test]
    async fn a_closed_path_resolves_to_nothing() {
        let router = RelayPathRouter::new(addr("0.0.0.0:41641"));
        let synthetic = router.open_control_path(Arc::new(NullEgress)).unwrap();
        router.close_relay_path(synthetic);
        assert!(router.resolve(synthetic).is_none());
    }

    /// An IPv6 hub mints IPv6 handles: quinn refuses to dial an address of a
    /// family its endpoint does not have, so a mismatch here would make
    /// relay unusable on a v6-only device.
    #[tokio::test]
    async fn the_handle_family_follows_the_hub_binding() {
        let v6 = RelayPathRouter::new(addr("[::]:41641"));
        let path = v6.open_control_path(Arc::new(NullEgress)).unwrap();
        assert!(path.is_ipv6());
        assert!(is_synthetic_relay_addr(path));
    }
}
