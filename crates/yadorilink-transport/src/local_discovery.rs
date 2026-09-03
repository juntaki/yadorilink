//! Local UDP broadcast and mDNS multicast discovery: finds already
//! authorized peers on the local network independent of the coordination
//! plane, matching Syncthing's local-discovery pattern
//! (studied for architecture only — MPL-2.0, not copied).
//!
//! Deliberately unauthenticated at this layer: a forged announcement cannot
//! complete a real handshake without the corresponding private key, so the
//! blast radius of a spoofed broadcast is bounded to rate-limited discovery
//! noise. Announcements do include the device's stable public key, an
//! accepted LAN privacy trade-off; this module only surfaces keys the
//! caller's own live `is_authorized` callback currently accepts —
//! [`start_local_discovery`] takes a callback rather than a fixed set
//! precisely so it can be started before any peer is known and keep
//! working correctly as authorization changes over the process lifetime,
//! with no restart needed on the caller's part.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use prost::Message;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use yadorilink_ipc_proto::local_discovery::LocalAnnouncement;

use crate::error::TransportError;

pub type PublicKeyBytes = [u8; 32];

const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
const BROADCAST_ADDR: &str = "255.255.255.255";
const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const SOURCE_RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_ANNOUNCEMENTS_PER_SOURCE_WINDOW: usize = 16;
const RECENT_ANNOUNCEMENT_TTL: Duration = Duration::from_secs(5);
/// How many distinct source IPs `DiscoveryFilters::source_windows` will
/// track at once. `allows` now checks this rate limit BEFORE the
/// authorization callback (a deliberate reorder so a flooder is rejected
/// cheaply before this module ever pays for the caller's expensive
/// authorization check) -- which means, unlike before that reorder, this
/// map now receives an entry for every distinct source IP that sends
/// ANY decodable datagram, authorized or not. Without a bound it would
/// grow without limit under a flood of spoofed source addresses. Generous
/// relative to any real LAN's host count, evicting the least-recently-
/// active entry once full rather than refusing new sources outright, so a
/// flood of forged sources cannot wall off room for a genuinely new device
/// showing up on the network.
const MAX_TRACKED_DISCOVERY_SOURCES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnnouncement {
    pub public_key: PublicKeyBytes,
    /// The announcer's address: source IP as observed by this socket,
    /// combined with the transport port it announced.
    pub addr: SocketAddr,
}

/// Starts the announcer/listener. Returns the socket's bound local address
/// (useful for logging, and for tests that want to feed it packets
/// directly rather than relying on OS broadcast delivery, which behaves
/// inconsistently across sandboxed/virtualized environments) and a
/// receiver of announcements observed from other devices.
///
/// `is_authorized` is consulted LIVE, on every received announcement, not
/// snapshotted once at start time: a caller with no authorized peers yet
/// (the common case at startup, before anything has been paired) can start
/// discovery immediately and have it begin working the moment a peer is
/// later authorized, with no restart or explicit refresh needed on the
/// caller's part. It must be cheap and non-blocking -- it runs inline in
/// this task's own receive loop for every inbound packet.
pub async fn start_local_discovery(
    my_public_key: PublicKeyBytes,
    my_wg_port: u16,
    broadcast_port: u16,
    is_authorized: impl Fn(&PublicKeyBytes) -> bool + Send + Sync + 'static,
) -> Result<(SocketAddr, mpsc::Receiver<PeerAnnouncement>), TransportError> {
    let socket = UdpSocket::bind(("0.0.0.0", broadcast_port)).await?;
    // Broadcast/multicast are LAN peer-discovery mechanics with no
    // meaning under a deterministic single-process simulation (a DST
    // scenario connects simulated peers directly, never via real
    // broadcast/mDNS) — `madsim`'s simulated
    // `UdpSocket` doesn't implement these OS-socket-option methods at
    // all, so this whole step is skipped under `--cfg madsim` rather
    // than attempting to fake OS multicast semantics in a simulator that
    // has no LAN to broadcast on.
    #[cfg(not(madsim))]
    {
        socket.set_broadcast(true)?;
        if let Err(err) = socket.join_multicast_v4(MDNS_MULTICAST_ADDR, Ipv4Addr::UNSPECIFIED) {
            tracing::debug!(error = %err, "mDNS multicast join failed; continuing with UDP broadcast discovery");
        }
        if let Err(err) = socket.set_multicast_loop_v4(true) {
            tracing::debug!(error = %err, "failed to enable mDNS multicast loopback");
        }
    }
    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);

    let (tx, rx) = mpsc::channel(32);
    // Erased and `Arc`-wrapped once so a restart (below) can cheaply share
    // the SAME live callback across `DiscoveryFilters` instances rather
    // than needing to re-capture or re-clone caller state — the callback
    // itself owns whatever live data it reads, this task just holds a
    // handle to it. Restarting with fresh rate-limit/dedup state (as
    // opposed to the authorization check itself) is fine since restarts
    // are rare and that state exists to bound noise, not to preserve
    // history across a crash.
    let is_authorized: Arc<dyn Fn(&PublicKeyBytes) -> bool + Send + Sync> = Arc::new(is_authorized);
    crate::supervise::spawn_restarting(
        "local-discovery",
        crate::supervise::BackoffConfig::RECONNECT,
        move || {
            let socket = socket.clone();
            let tx = tx.clone();
            let filters = DiscoveryFilters::new(is_authorized.clone());
            let announce_port =
                if broadcast_port == 0 { local_addr.port() } else { broadcast_port };
            async move {
                run_discovery(socket, my_public_key, my_wg_port, announce_port, filters, tx).await
            }
        },
    );

    Ok((local_addr, rx))
}

async fn run_discovery(
    socket: Arc<UdpSocket>,
    my_public_key: PublicKeyBytes,
    my_wg_port: u16,
    announce_port: u16,
    mut filters: DiscoveryFilters,
    announcements_tx: mpsc::Sender<PeerAnnouncement>,
) {
    let mut announce_interval = tokio::time::interval(ANNOUNCE_INTERVAL);
    let mut recv_buf = vec![0u8; 1024];
    let announcement_dests = announcement_destinations(announce_port);

    loop {
        tokio::select! {
            // tokio::time::interval's first tick completes immediately, so
            // this also serves as the initial announcement on startup.
            _ = announce_interval.tick() => {
                let msg = LocalAnnouncement {
                    public_key: my_public_key.to_vec(),
                    wg_port: my_wg_port as u32,
                };
                let bytes = msg.encode_to_vec();
                for dest in &announcement_dests {
                    // `madsim`'s simulated `UdpSocket::send_to` takes
                    // `(dst, buf)`, the reverse of real tokio's
                    // `(buf, dst)` — see this module's
                    // `#[cfg(not(madsim))]` broadcast/multicast setup
                    // above for the broader context.
                    #[cfg(not(madsim))]
                    let _ = socket.send_to(&bytes, dest).await;
                    #[cfg(madsim)]
                    let _ = socket.send_to(*dest, &bytes).await;
                }
            }
            Ok((n, from)) = socket.recv_from(&mut recv_buf) => {
                handle_datagram(&recv_buf[..n], from, &my_public_key, &mut filters, &announcements_tx).await;
            }
        }
    }
}

fn announcement_destinations(port: u16) -> Vec<SocketAddr> {
    let mut destinations = Vec::with_capacity(2);
    if let Ok(addr) = format!("{BROADCAST_ADDR}:{port}").parse::<SocketAddr>() {
        destinations.push(addr);
    }
    destinations.push(SocketAddr::V4(SocketAddrV4::new(MDNS_MULTICAST_ADDR, port)));
    destinations
}

struct DiscoveryFilters {
    is_authorized: Arc<dyn Fn(&PublicKeyBytes) -> bool + Send + Sync>,
    source_windows: HashMap<IpAddr, SourceWindow>,
    recent_announcements: HashMap<(PublicKeyBytes, SocketAddr), Instant>,
}

struct SourceWindow {
    started_at: Instant,
    count: usize,
}

impl DiscoveryFilters {
    fn new(is_authorized: Arc<dyn Fn(&PublicKeyBytes) -> bool + Send + Sync>) -> Self {
        Self { is_authorized, source_windows: HashMap::new(), recent_announcements: HashMap::new() }
    }

    fn allows(&mut self, source: IpAddr, public_key: PublicKeyBytes, addr: SocketAddr) -> bool {
        // Cheap, purely local checks first -- rate limiting and dedup need
        // no shared state, so they must reject a flooder before this
        // function ever pays for `is_authorized` below, which (in the
        // daemon's real callback) acquires a shared mutex and does an
        // O(peers) scan -- a mutex that also serializes the daemon's
        // change-authorization path elsewhere. Running the expensive check
        // first (an earlier version of this function did) would let an
        // unauthenticated flooder force that cost on every packet it sent,
        // regardless of whether it could ever pass.
        let now = Instant::now();
        if !self.source_windows.contains_key(&source)
            && self.source_windows.len() >= MAX_TRACKED_DISCOVERY_SOURCES
        {
            // Full, and this is a genuinely new source -- evict the
            // least-recently-active tracked source to make room, the same
            // shape as `NetmapDiffState::lan_discovered`'s own bounded
            // cache in the daemon crate. Bounds this map's size regardless
            // of how many distinct (real or spoofed) source IPs send
            // datagrams here, not just how many pass authorization.
            if let Some(oldest) =
                self.source_windows.iter().min_by_key(|(_, w)| w.started_at).map(|(ip, _)| *ip)
            {
                self.source_windows.remove(&oldest);
            }
        }
        let source_window =
            self.source_windows.entry(source).or_insert(SourceWindow { started_at: now, count: 0 });
        if now.duration_since(source_window.started_at) > SOURCE_RATE_WINDOW {
            source_window.started_at = now;
            source_window.count = 0;
        }
        if source_window.count >= MAX_ANNOUNCEMENTS_PER_SOURCE_WINDOW {
            return false;
        }
        source_window.count += 1;

        self.recent_announcements
            .retain(|_, last_seen| now.duration_since(*last_seen) <= RECENT_ANNOUNCEMENT_TTL);
        let recent_key = (public_key, addr);
        if self.recent_announcements.contains_key(&recent_key) {
            return false;
        }

        // Only now the potentially-expensive live authorization check, for
        // whatever survived the cheap checks above.
        if !(self.is_authorized)(&public_key) {
            return false;
        }

        self.recent_announcements.insert(recent_key, now);
        true
    }
}

async fn handle_datagram(
    data: &[u8],
    from: SocketAddr,
    my_public_key: &PublicKeyBytes,
    filters: &mut DiscoveryFilters,
    announcements_tx: &mpsc::Sender<PeerAnnouncement>,
) {
    let Ok(announcement) = LocalAnnouncement::decode(data) else { return };
    let Ok(public_key): Result<PublicKeyBytes, _> = announcement.public_key.as_slice().try_into()
    else {
        return;
    };
    if &public_key == my_public_key {
        return; // our own broadcast, looped back
    }
    let Ok(wg_port) = u16::try_from(announcement.wg_port) else { return };
    let addr = SocketAddr::new(from.ip(), wg_port);
    if !filters.allows(from.ip(), public_key, addr) {
        return;
    }
    let _ = announcements_tx.send(PeerAnnouncement { public_key, addr }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds a packet directly to the discovery socket's bound address
    /// rather than relying on OS broadcast delivery (unreliable across
    /// sandboxed/virtualized CI environments) — this still exercises the
    /// real decode/self-filter/forward logic end to end.
    async fn send_raw(from_port: u16, to: SocketAddr, msg: &LocalAnnouncement) {
        let sender = UdpSocket::bind(("127.0.0.1", from_port)).await.unwrap();
        sender.send_to(&msg.encode_to_vec(), to).await.unwrap();
    }

    #[tokio::test]
    async fn announcement_from_another_device_is_surfaced() {
        let my_key = [1u8; 32];
        let their_key = [2u8; 32];
        let (addr, mut rx) =
            start_local_discovery(my_key, 41641, 0, move |k: &PublicKeyBytes| *k == their_key)
                .await
                .unwrap();

        send_raw(
            0,
            // `addr` is the discovery socket's own bound address, which is
            // the wildcard `0.0.0.0` (not a valid send destination) since
            // it listens on all interfaces — target loopback explicitly.
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port()),
            &LocalAnnouncement { public_key: their_key.to_vec(), wg_port: 51820 },
        )
        .await;

        let announcement =
            tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        assert_eq!(announcement.public_key, their_key);
        assert_eq!(announcement.addr.port(), 51820);
    }

    #[tokio::test]
    async fn self_announcement_is_filtered_out() {
        let my_key = [3u8; 32];
        let their_key = [4u8; 32];
        let (addr, mut rx) =
            start_local_discovery(my_key, 41641, 0, move |k: &PublicKeyBytes| *k == their_key)
                .await
                .unwrap();

        send_raw(
            0,
            // `addr` is the discovery socket's own bound address, which is
            // the wildcard `0.0.0.0` (not a valid send destination) since
            // it listens on all interfaces — target loopback explicitly.
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port()),
            &LocalAnnouncement { public_key: my_key.to_vec(), wg_port: 41641 },
        )
        .await;

        // No announcement should ever arrive for our own key; confirm the
        // channel stays empty rather than waiting for a fixed timeout.
        let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            result.is_err(),
            "self-announcement should have been filtered, but something arrived"
        );
    }

    #[tokio::test]
    async fn unauthorized_announcement_is_filtered_out() {
        let my_key = [5u8; 32];
        let authorized_key = [6u8; 32];
        let (addr, mut rx) =
            start_local_discovery(my_key, 41641, 0, move |k: &PublicKeyBytes| *k == authorized_key)
                .await
                .unwrap();

        send_raw(
            0,
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), addr.port()),
            &LocalAnnouncement { public_key: [7u8; 32].to_vec(), wg_port: 51820 },
        )
        .await;

        let result = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(result.is_err(), "unauthorized announcement should have been filtered");
    }

    #[tokio::test]
    async fn mdns_announcement_without_broadcast_is_surfaced_after_filters() {
        let my_key = [10u8; 32];
        let their_key = [11u8; 32];
        let (tx, mut rx) = mpsc::channel(32);
        let mut filters =
            DiscoveryFilters::new(Arc::new(move |k: &PublicKeyBytes| *k == their_key));
        let from: SocketAddr = "192.0.2.10:5353".parse().unwrap();
        let msg = LocalAnnouncement { public_key: their_key.to_vec(), wg_port: 51820 };

        handle_datagram(&msg.encode_to_vec(), from, &my_key, &mut filters, &tx).await;

        let announcement =
            tokio::time::timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
        assert_eq!(announcement.public_key, their_key);
        assert_eq!(announcement.addr, "192.0.2.10:51820".parse().unwrap());
    }

    #[test]
    fn announcements_are_sent_to_broadcast_and_mdns_multicast() {
        let destinations = announcement_destinations(21027);

        assert!(destinations.contains(&"255.255.255.255:21027".parse().unwrap()));
        assert!(
            destinations.contains(&SocketAddr::V4(SocketAddrV4::new(MDNS_MULTICAST_ADDR, 21027,)))
        );
    }

    #[tokio::test]
    async fn duplicate_announcements_are_suppressed() {
        let my_key = [8u8; 32];
        let their_key = [9u8; 32];
        let (tx, mut rx) = mpsc::channel(32);
        let mut filters =
            DiscoveryFilters::new(Arc::new(move |k: &PublicKeyBytes| *k == their_key));
        let from: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let msg = LocalAnnouncement { public_key: their_key.to_vec(), wg_port: 51820 };
        let data = msg.encode_to_vec();

        handle_datagram(&data, from, &my_key, &mut filters, &tx).await;
        handle_datagram(&data, from, &my_key, &mut filters, &tx).await;

        assert!(rx.recv().await.is_some());
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err(), "duplicate announcement should have been suppressed");
    }

    /// `allows` now runs its cheap rate-limit/dedup checks BEFORE the
    /// (potentially expensive, caller-supplied) authorization check -- a
    /// deliberate reorder for containment, but one that means
    /// `source_windows` gets an entry for every distinct source IP that
    /// sends anything decodable, authorized or not. Anything reachable at
    /// all can send datagrams from as many spoofed source addresses as it
    /// likes, so this map must stop growing at a fixed count rather than
    /// scaling with attacker effort -- the same shape
    /// `relay_path::tests::unrecognized_envelopes_cannot_grow_the_table_
    /// without_limit` already establishes for an analogous unauthenticated
    /// table elsewhere in this crate.
    #[test]
    fn source_windows_cannot_grow_without_limit_under_a_spoofed_source_flood() {
        let mut filters = DiscoveryFilters::new(Arc::new(|_: &PublicKeyBytes| false));
        for i in 0..(MAX_TRACKED_DISCOVERY_SOURCES as u32 * 4) {
            let source = IpAddr::V4(Ipv4Addr::from(i));
            let addr = SocketAddr::new(source, 51820);
            // Authorization always fails, so this only exercises the
            // rate-limit/dedup path -- exactly the one now reachable
            // without ever passing authorization.
            assert!(!filters.allows(source, [0u8; 32], addr));
        }
        assert_eq!(filters.source_windows.len(), MAX_TRACKED_DISCOVERY_SOURCES);
    }
}
