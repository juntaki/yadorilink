//! NAT traversal: recovering direct reachability when a pair of devices is
//! not on the same LAN.
//!
//! The transport already does the load-bearing half of connection
//! establishment — it races every known endpoint candidate concurrently and
//! treats a candidate as confirmed only once authenticated WireGuard traffic
//! arrives over it (a stronger connectivity check than a STUN binding
//! success). What that machinery lacks is *candidate gathering* beyond LAN
//! addresses and *simultaneity* between two NATed peers. This module supplies
//! exactly those pieces and nothing more:
//!
//! - [`stun`]: learn the device's server-reflexive (publicly mapped) address.
//! - [`portmap`]: ask the router for an explicit external port mapping.
//! - [`punch`]: drive two peers to probe each other at the same instant so
//!   both NATs open a mapping.
//! - [`classify`]: turn the passive observations above into a NAT verdict for
//!   diagnostics and unreachable-peer explanations.
//!
//! Every candidate produced here flows out through the same reporting path
//! `local_candidates` already uses; every timer draws from the same
//! simulation-friendly clock as the reconnect backoff, so the whole suite
//! runs unchanged under deterministic simulation.

pub mod classify;
pub mod portmap;
pub mod punch;
pub mod stun;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use tokio::sync::watch;

/// The kind of endpoint candidate, ordered by how much we prefer to connect
/// over it. A same-LAN path beats a router-mapped port, which beats a global
/// IPv6 host address, which beats a STUN-learned server-reflexive mapping
/// (the least reliable, since it only works while the NAT keeps that binding
/// and only for endpoint-independent NATs).
///
/// The `Ord` derive orders variants low-to-high, so `ServerReflexive` is the
/// smallest and `Lan` the largest — declare them in ascending preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateClass {
    /// STUN-discovered public mapping; usable only across endpoint-
    /// independent NATs and only while the mapping lives.
    ServerReflexive,
    /// A global-scope IPv6 host address; direct when both peers have v6.
    Ipv6Host,
    /// A router-granted external port mapping (PCP / NAT-PMP / UPnP-IGD);
    /// reachable without hole punching for as long as the lease holds.
    PortMapped,
    /// A same-network interface address; always preferred when reachable.
    Lan,
}

impl CandidateClass {
    /// Numeric priority carried alongside a reported candidate. Kept on the
    /// same scale as the pre-existing LAN priority so a mixed candidate set
    /// (LAN addresses reported the old way, new classes reported here) sorts
    /// consistently on the receiving side.
    pub const fn priority(self) -> i32 {
        match self {
            CandidateClass::Lan => 100,
            CandidateClass::PortMapped => 80,
            CandidateClass::Ipv6Host => 60,
            CandidateClass::ServerReflexive => 40,
        }
    }
}

/// One endpoint candidate with its class-derived priority. This is what the
/// merged candidate stream yields; the daemon reports each to the
/// coordination plane exactly as it already reports LAN addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub class: CandidateClass,
}

impl Candidate {
    pub fn new(addr: SocketAddr, class: CandidateClass) -> Self {
        Self { addr, class }
    }

    pub fn priority(&self) -> i32 {
        self.class.priority()
    }
}

/// A source of endpoint candidates (STUN, port mapping, local interfaces).
/// Sources are long-lived tasks that publish their current contribution into
/// a shared [`CandidateSink`]; this trait only carries the metadata the
/// diagnostics surface wants, so a source stays a plain spawned task rather
/// than an object the sink has to poll.
pub trait CandidateSource: Send + Sync {
    /// Stable, human-readable name for logs and the connectivity doctor.
    fn name(&self) -> &'static str;
    /// The class of candidate this source contributes.
    fn class(&self) -> CandidateClass;
}

struct CandidateSinkState {
    /// Current contribution of each class. A class fully replaces its prior
    /// contribution on every publish (STUN's fresh mapped address supersedes
    /// the stale one) rather than accumulating, so a mapping that goes away
    /// disappears from the merged set on the next publish.
    by_class: BTreeMap<CandidateClass, Vec<SocketAddr>>,
    /// Last set handed to subscribers, canonicalized (sorted, deduped), so a
    /// publish that does not change the merged set does not wake them —
    /// avoiding candidate-report churn on the coordination plane.
    last_published: Vec<Candidate>,
}

/// The merged, deduplicated set of this device's local endpoint candidates
/// across every source. Sources call [`CandidateSink::publish`] with their
/// class's current addresses; subscribers hold a [`watch::Receiver`] and see
/// the merged set only when it actually changes.
pub struct CandidateSink {
    state: Mutex<CandidateSinkState>,
    tx: watch::Sender<Vec<Candidate>>,
}

impl CandidateSink {
    /// Creates an empty sink and a receiver pre-seeded with the empty set.
    pub fn new() -> (std::sync::Arc<Self>, watch::Receiver<Vec<Candidate>>) {
        let (tx, rx) = watch::channel(Vec::new());
        let sink = std::sync::Arc::new(Self {
            state: Mutex::new(CandidateSinkState {
                by_class: BTreeMap::new(),
                last_published: Vec::new(),
            }),
            tx,
        });
        (sink, rx)
    }

    /// Replaces the candidates contributed by `class` and, if the merged set
    /// changed, notifies subscribers. Passing an empty `addrs` retracts the
    /// class entirely (e.g. STUN went dark, or a port-mapping lease was
    /// released).
    pub fn publish(&self, class: CandidateClass, addrs: Vec<SocketAddr>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if addrs.is_empty() {
            state.by_class.remove(&class);
        } else {
            state.by_class.insert(class, addrs);
        }
        let merged = Self::merge(&state.by_class);
        if merged != state.last_published {
            state.last_published = merged.clone();
            // A send error only means every receiver has been dropped, which
            // is a normal shutdown, not a failure to react to.
            let _ = self.tx.send(merged);
        }
    }

    /// The current merged candidate set, for callers that want a snapshot
    /// without subscribing (diagnostics, an initial report).
    pub fn snapshot(&self) -> Vec<Candidate> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Self::merge(&state.by_class)
    }

    fn merge(by_class: &BTreeMap<CandidateClass, Vec<SocketAddr>>) -> Vec<Candidate> {
        let mut merged: Vec<Candidate> = Vec::new();
        for (class, addrs) in by_class {
            for &addr in addrs {
                // Same address can legitimately appear under two classes
                // (a mapped external port equal to a server-reflexive one);
                // keep the higher-priority class only.
                match merged.iter_mut().find(|c| c.addr == addr) {
                    Some(existing) if existing.class < *class => existing.class = *class,
                    Some(_) => {}
                    None => merged.push(Candidate::new(addr, *class)),
                }
            }
        }
        // Deterministic order: highest priority first, then by address, so
        // the change comparison and any downstream logging are stable.
        merged.sort_by(|a, b| {
            b.class.cmp(&a.class).then_with(|| a.addr.to_string().cmp(&b.addr.to_string()))
        });
        merged
    }
}

/// Whether a router port mapping has been obtained, for the classifier and
/// diagnostics. Distinct from "we have a port-mapped candidate" so a failure
/// is a recorded observation rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortMappingStatus {
    /// Not attempted yet, or port mapping is disabled.
    #[default]
    Unknown,
    /// Every attempted protocol declined or was unavailable.
    Unavailable,
    /// A mapping was granted.
    Mapped,
}

/// Passive observations about this device's NAT/firewall behavior, gathered
/// from traffic the system already sends. [`classify`](classify::classify)
/// turns a snapshot of this into a [`NatClass`](classify::NatClass); the
/// connectivity doctor renders it directly.
#[derive(Debug, Clone, Default)]
pub struct NatObservations {
    /// Mapped address each reached STUN server reported for our data socket,
    /// keyed by the server queried. Two servers reporting different mapped
    /// *ports* is the signature of endpoint-dependent (symmetric) mapping.
    pub stun_mappings: BTreeMap<SocketAddr, SocketAddr>,
    /// True once any STUN server answered at all — separates a UDP-blocked
    /// network (nothing ever answers) from one with no servers configured.
    pub stun_any_response: bool,
    /// True once STUN was attempted on the current network (so the absence
    /// of a response is meaningful rather than "not tried").
    pub stun_attempted: bool,
    /// This device's own local interface addresses at observation time, to
    /// compare against the mapped address (equal ⇒ no NAT; private-and-
    /// different ⇒ another NAT or CGNAT in the path).
    pub local_addrs: Vec<IpAddr>,
    /// Outcome of router port mapping.
    pub port_mapping: PortMappingStatus,
    /// True once any hole-punch probe was answered on the current network.
    pub punch_any_success: bool,
    /// True once a coordinated punch has been attempted and none succeeded,
    /// so "UDP blocked" can be distinguished from "not yet tried".
    pub punch_attempted: bool,
}

/// A shared, thread-safe handle to [`NatObservations`] that every source
/// records into. Cloneable; all clones point at the same state.
#[derive(Clone, Default)]
pub struct ObservationLog {
    inner: std::sync::Arc<Mutex<NatObservations>>,
}

impl ObservationLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one STUN server's reported mapped address for our socket.
    pub fn record_stun_mapping(&self, server: SocketAddr, mapped: SocketAddr) {
        let mut obs = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        obs.stun_attempted = true;
        obs.stun_any_response = true;
        obs.stun_mappings.insert(server, mapped);
    }

    /// Records that STUN was attempted against `server` but got no answer.
    pub fn record_stun_timeout(&self, _server: SocketAddr) {
        let mut obs = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        obs.stun_attempted = true;
    }

    /// Replaces the recorded set of local interface addresses.
    pub fn set_local_addrs(&self, addrs: Vec<IpAddr>) {
        let mut obs = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        obs.local_addrs = addrs;
    }

    pub fn set_port_mapping(&self, status: PortMappingStatus) {
        let mut obs = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        obs.port_mapping = status;
    }

    pub fn record_punch_attempt(&self, succeeded: bool) {
        let mut obs = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        obs.punch_attempted = true;
        if succeeded {
            obs.punch_any_success = true;
        }
    }

    /// A consistent snapshot for classification or diagnostics.
    pub fn snapshot(&self) -> NatObservations {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// A `[0, 1)` jitter fraction drawn the same way the reconnect backoff draws
/// it: from the simulator's seed-derived RNG under `--cfg madsim` (so a run
/// seed reproduces every refresh/punch schedule) and from real entropy
/// otherwise. Mirrors `supervise::fastrand_unit_interval`; kept local because
/// that one is private to its module and the two must not share a dependency
/// edge. Jitter here only needs to decorrelate timers, not be
/// cryptographically random.
pub(crate) fn unit_jitter() -> f64 {
    #[cfg(madsim)]
    {
        madsim::rand::random::<f64>()
    }
    #[cfg(not(madsim))]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static STATE: AtomicU64 = AtomicU64::new(0);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        let prev = STATE.fetch_add(seed | 1, Ordering::Relaxed);
        let mut z = prev.wrapping_add(0x9E3779B97F4A7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Applies up to +/-25% jitter to a base interval, for decorrelating periodic
/// refreshes across devices. Never returns zero or more than +25%.
pub(crate) fn jittered(base: std::time::Duration) -> std::time::Duration {
    let frac = unit_jitter(); // [0, 1)
    let magnitude = base.mul_f64(0.25 * frac);
    if frac < 0.5 {
        base.saturating_sub(magnitude)
    } else {
        base.saturating_add(magnitude)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn candidate_class_priority_orders_lan_over_reflexive() {
        assert!(CandidateClass::Lan > CandidateClass::PortMapped);
        assert!(CandidateClass::PortMapped > CandidateClass::Ipv6Host);
        assert!(CandidateClass::Ipv6Host > CandidateClass::ServerReflexive);
        assert!(CandidateClass::Lan.priority() > CandidateClass::PortMapped.priority());
        assert!(CandidateClass::PortMapped.priority() > CandidateClass::Ipv6Host.priority());
        assert!(CandidateClass::Ipv6Host.priority() > CandidateClass::ServerReflexive.priority());
    }

    #[test]
    fn sink_merges_classes_and_reports_on_change() {
        let (sink, mut rx) = CandidateSink::new();
        assert!(rx.borrow().is_empty());

        sink.publish(CandidateClass::Lan, vec![addr("192.168.1.5:41641")]);
        assert!(rx.has_changed().unwrap());
        let merged = rx.borrow_and_update().clone();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].class, CandidateClass::Lan);

        sink.publish(CandidateClass::ServerReflexive, vec![addr("203.0.113.7:5000")]);
        let merged = rx.borrow_and_update().clone();
        assert_eq!(merged.len(), 2);
        // Highest priority sorts first.
        assert_eq!(merged[0].class, CandidateClass::Lan);
        assert_eq!(merged[1].class, CandidateClass::ServerReflexive);
    }

    #[test]
    fn sink_does_not_notify_when_merged_set_is_unchanged() {
        let (sink, mut rx) = CandidateSink::new();
        sink.publish(CandidateClass::Lan, vec![addr("192.168.1.5:41641")]);
        assert!(rx.has_changed().unwrap());
        rx.borrow_and_update();

        // Republishing the identical contribution must not wake subscribers.
        sink.publish(CandidateClass::Lan, vec![addr("192.168.1.5:41641")]);
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn sink_retracts_class_on_empty_publish() {
        let (sink, mut rx) = CandidateSink::new();
        sink.publish(CandidateClass::ServerReflexive, vec![addr("203.0.113.7:5000")]);
        rx.borrow_and_update();
        sink.publish(CandidateClass::ServerReflexive, Vec::new());
        let merged = rx.borrow_and_update().clone();
        assert!(merged.is_empty());
    }

    #[test]
    fn sink_keeps_higher_priority_class_for_duplicate_address() {
        let (sink, _rx) = CandidateSink::new();
        let shared = addr("203.0.113.7:5000");
        sink.publish(CandidateClass::ServerReflexive, vec![shared]);
        sink.publish(CandidateClass::PortMapped, vec![shared]);
        let merged = sink.snapshot();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].class, CandidateClass::PortMapped);
    }

    #[test]
    fn observation_log_records_disagreeing_stun_mappings() {
        let log = ObservationLog::new();
        log.record_stun_mapping(addr("1.1.1.1:3478"), addr("203.0.113.7:5000"));
        log.record_stun_mapping(addr("8.8.8.8:3478"), addr("203.0.113.7:6000"));
        let snap = log.snapshot();
        assert!(snap.stun_any_response);
        assert_eq!(snap.stun_mappings.len(), 2);
    }

    #[test]
    fn jittered_stays_within_bounds() {
        let base = std::time::Duration::from_secs(100);
        for _ in 0..64 {
            let j = jittered(base);
            assert!(j >= base.mul_f64(0.75));
            assert!(j <= base.mul_f64(1.25));
        }
    }
}
