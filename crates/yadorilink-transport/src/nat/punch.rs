//! Coordinated UDP hole punching: when two authorized peers are both online
//! but not yet connected, a content-blind rendezvous signal delivered over
//! the coordination plane makes both start probing each other's candidates at
//! the same instant, so each NAT's outbound mapping is open when the other's
//! probes arrive.
//!
//! There is no separate punch protocol on the wire. The "probe" is the
//! transport's ordinary WireGuard handshake initiation — feeding a peer's
//! candidate into the connection's candidate race (the same entry point LAN
//! discovery uses) makes the transport send a handshake at it, and the
//! existing rule that only authenticated traffic confirms a path applies
//! unchanged. This module owns two concerns and nothing else: the *timing* of
//! a synchronized burst, and the *bounds* that stop a peer being probed
//! forever. Symmetric NAT on both sides is out of scope: it is classified,
//! the peer is marked unreachable, and store-and-forward carries propagation.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use super::jittered;

/// Tuning for punch bursts and per-peer bounds.
#[derive(Debug, Clone, Copy)]
pub struct PunchConfig {
    /// Hard cap on coordinated attempts against one peer before it is judged
    /// unreachable rather than probed indefinitely.
    pub max_attempts: u32,
    /// First inter-attempt backoff; doubles each attempt up to `max_backoff`.
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// How many times each candidate is probed within a single burst (a few
    /// repeats absorb the small skew between the two sides starting).
    pub burst_probes: u32,
    /// Spacing between probe rounds within a burst.
    pub burst_spacing: Duration,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            burst_probes: 5,
            burst_spacing: Duration::from_millis(200),
        }
    }
}

/// What the limiter decides when a punch against a peer is requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchDecision {
    /// Go ahead and run a burst now.
    Proceed,
    /// Too soon since the last attempt; try again after this delay.
    BackOff { retry_after: Duration },
    /// The per-peer attempt bound is spent; treat the peer as unreachable.
    Exhausted,
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerPunchState {
    attempts: u32,
    next_allowed_at: Option<tokio::time::Instant>,
}

/// Per-peer punch bounds and backoff. Pure decision logic (no I/O, no
/// clock of its own — the caller passes `now`), so it is fully testable and
/// behaves identically under simulation. `K` is the peer identity, typically
/// a WireGuard public key.
pub struct PunchLimiter<K: Eq + Hash> {
    config: PunchConfig,
    peers: HashMap<K, PeerPunchState>,
}

impl<K: Eq + Hash> PunchLimiter<K> {
    pub fn new(config: PunchConfig) -> Self {
        Self { config, peers: HashMap::new() }
    }

    /// Decides whether a punch against `peer` may proceed at `now`, updating
    /// the peer's attempt count and next-allowed time when it does.
    pub fn on_request(&mut self, peer: K, now: tokio::time::Instant) -> PunchDecision {
        let config = self.config;
        let state = self.peers.entry(peer).or_default();
        if state.attempts >= config.max_attempts {
            return PunchDecision::Exhausted;
        }
        if let Some(next) = state.next_allowed_at {
            if now < next {
                return PunchDecision::BackOff { retry_after: next - now };
            }
        }
        // Backoff after this attempt: initial << attempts, capped, jittered so
        // two peers that started together do not stay lock-stepped.
        let shift = state.attempts.min(20);
        let scaled = config.initial_backoff.saturating_mul(1u32 << shift).min(config.max_backoff);
        state.attempts += 1;
        state.next_allowed_at = Some(now + jittered(scaled));
        PunchDecision::Proceed
    }

    /// Clears a peer's punch state after a path is confirmed, so a later
    /// disconnect starts from a clean slate rather than an exhausted bound.
    pub fn on_success(&mut self, peer: &K) {
        self.peers.remove(peer);
    }

    /// Current attempt count for a peer (diagnostics).
    pub fn attempts(&self, peer: &K) -> u32 {
        self.peers.get(peer).map(|s| s.attempts).unwrap_or(0)
    }
}

/// A connection into which punch probes are injected. The production
/// implementation forwards each candidate to the peer's channel candidate
/// race (`PeerChannel::add_direct_candidate`), which makes the transport send
/// a WireGuard handshake at it.
pub trait PunchTarget: Send + Sync {
    fn probe<'a>(
        &'a self,
        candidate: SocketAddr,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Runs one synchronized burst: probes every candidate `burst_probes` times,
/// spaced by a jittered interval. Both peers run this on receiving the same
/// rendezvous signal, so their bursts overlap and each NAT sees the other's
/// probe while its own outbound mapping is open. Timing draws from the tokio
/// clock, so it is deterministic under simulation.
pub async fn run_burst(target: &dyn PunchTarget, candidates: &[SocketAddr], config: &PunchConfig) {
    if candidates.is_empty() {
        return;
    }
    for round in 0..config.burst_probes {
        for &candidate in candidates {
            target.probe(candidate).await;
        }
        // No trailing sleep after the final round.
        if round + 1 < config.burst_probes {
            tokio::time::sleep(jittered(config.burst_spacing)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn first_request_proceeds_then_backs_off() {
        let mut limiter = PunchLimiter::new(PunchConfig::default());
        let now = tokio::time::Instant::now();
        assert_eq!(limiter.on_request(1u8, now), PunchDecision::Proceed);
        // Immediately after, the same peer must wait.
        match limiter.on_request(1u8, now) {
            PunchDecision::BackOff { retry_after } => assert!(retry_after > Duration::ZERO),
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_are_bounded_then_exhausted() {
        let config = PunchConfig { max_attempts: 3, ..PunchConfig::default() };
        let mut limiter = PunchLimiter::new(config);
        let mut now = tokio::time::Instant::now();
        let mut proceeds = 0;
        for _ in 0..3 {
            if limiter.on_request(7u8, now) == PunchDecision::Proceed {
                proceeds += 1;
            }
            // Jump past the backoff window each time.
            now += Duration::from_secs(600);
        }
        assert_eq!(proceeds, 3);
        assert_eq!(limiter.on_request(7u8, now), PunchDecision::Exhausted);
    }

    #[tokio::test(start_paused = true)]
    async fn success_resets_the_bound() {
        let config = PunchConfig { max_attempts: 1, ..PunchConfig::default() };
        let mut limiter = PunchLimiter::new(config);
        let now = tokio::time::Instant::now();
        assert_eq!(limiter.on_request(9u8, now), PunchDecision::Proceed);
        assert_eq!(
            limiter.on_request(9u8, now + Duration::from_secs(600)),
            PunchDecision::Exhausted
        );
        limiter.on_success(&9u8);
        assert_eq!(limiter.on_request(9u8, now + Duration::from_secs(600)), PunchDecision::Proceed);
    }

    /// Records every candidate a burst probes, for asserting the burst shape.
    struct RecordingTarget {
        probed: Mutex<Vec<SocketAddr>>,
    }

    impl PunchTarget for RecordingTarget {
        fn probe<'a>(
            &'a self,
            candidate: SocketAddr,
        ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.probed.lock().unwrap().push(candidate);
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn burst_probes_every_candidate_each_round() {
        let target = RecordingTarget { probed: Mutex::new(Vec::new()) };
        let config = PunchConfig {
            burst_probes: 3,
            burst_spacing: Duration::from_millis(100),
            ..PunchConfig::default()
        };
        let candidates = [addr("203.0.113.7:5000"), addr("198.51.100.2:6000")];
        run_burst(&target, &candidates, &config).await;
        let probed = target.probed.lock().unwrap();
        // 2 candidates * 3 rounds.
        assert_eq!(probed.len(), 6);
        assert_eq!(probed.iter().filter(|a| **a == candidates[0]).count(), 3);
        assert_eq!(probed.iter().filter(|a| **a == candidates[1]).count(), 3);
    }
}
