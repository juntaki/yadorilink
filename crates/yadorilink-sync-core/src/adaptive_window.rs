//! An AIMD-style, per-peer adaptive
//! in-flight block-fetch window.
//!
//! Before this change, the number of concurrently outstanding
//! `PeerSyncSession::fetch_block` requests to one peer was a fixed
//! constant everywhere it mattered — `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
//! (peer_session.rs, SEC-13's inbound-message concurrency bound) and
//! `PER_PEER_IN_FLIGHT_WINDOW` (yadorilink-daemon::hydration's multi-peer
//! fetch dispatcher, PERF-5's fixed lane count). Fast, low-RTT links never
//! got to pipeline past that fixed count; slow/lossy ones got pushed to
//! send that many requests regardless of whether the link could sustain
//! them.
//!
//! `AdaptiveWindow` replaces the *lane-count* half of that (the daemon's
//! per-candidate fetch concurrency) with a controller driven by real
//! observed conditions on this session: smoothed RTT (EWMA) and explicit
//! timeout/loss signals. It does **not** touch `MAX_IN_FLIGHT_MESSAGES_PER_PEER` —
//! that constant remains the fixed security ceiling (SEC-13's DoS bound
//! on *inbound* message handling) this controller's own `max` is
//! constructed to never exceed, so the adaptive window composes with,
//! rather than replaces, the existing security hardening: max never
//! exceeds the per-peer concurrency bound set by that hardening.
//!
//! Pure and synchronous (no I/O, no async) so it's directly unit-testable
//! — see the `tests` module below for the grow/shrink/ceiling/floor
//! proofs. `PeerSyncSession` (peer_session.rs) owns one instance per
//! session and feeds it real `fetch_block` outcomes; `yadorilink-daemon`'s
//! multi-peer dispatcher reads `PeerSyncSession::fetch_window()` in place
//! of the old fixed lane constant.

use std::sync::Mutex as StdMutex;
use std::time::Duration;

/// AIMD "AI" (additive increase) step applied to the window on every
/// `on_success` call that does *not* show RTT inflation — one more
/// concurrent in-flight request per healthy round trip, the standard
/// conservative TCP-congestion-control-style growth rate.
const ADDITIVE_INCREASE_STEP: f64 = 1.0;

/// AIMD "MD" (multiplicative decrease) factor applied on a timeout/loss
/// signal (`on_timeout`) or an RTT-inflation signal (`on_success` when the
/// new sample is much worse than the smoothed baseline) — halves the
/// window, the standard TCP-congestion-control-style back-off.
const MULTIPLICATIVE_DECREASE_FACTOR: f64 = 0.5;

/// EWMA smoothing factor for the RTT baseline: `new = old*(1-ALPHA) +
/// sample*ALPHA`. Low-ish so one noisy sample doesn't itself look like
/// "inflation" against its own freshly-updated baseline.
const RTT_EWMA_ALPHA: f64 = 0.25;

/// A fresh RTT sample counts as "inflated" (and triggers a multiplicative
/// back-off, same as an explicit timeout) once it exceeds the smoothed
/// baseline by this factor — multiplicatively backing off on
/// timeouts/loss or RTT inflation. Chosen loosely (50% worse than
/// baseline) so ordinary jitter on a real network doesn't itself look like
/// congestion; only a genuine, sustained latency increase does.
const RTT_INFLATION_FACTOR: f64 = 1.5;

struct WindowState {
    /// Fractional so additive growth/multiplicative backoff compose
    /// smoothly across many calls instead of getting stuck at an integer
    /// step boundary — `current()` rounds and clamps this to `[min, max]`
    /// for callers.
    window: f64,
    smoothed_rtt: Option<Duration>,
}

/// Per-peer AIMD in-flight window controller. `min`/`max` are fixed for
/// the controller's lifetime (`max` is clamped at construction to never
/// exceed the caller-supplied hard ceiling).
pub struct AdaptiveWindow {
    min: usize,
    max: usize,
    state: StdMutex<WindowState>,
}

impl AdaptiveWindow {
    /// `initial`/`min` are the controller's starting point and floor;
    /// `hard_ceiling` is the pre-existing, non-adaptive per-peer
    /// concurrency bound (`PeerSyncSession` passes
    /// `MAX_IN_FLIGHT_MESSAGES_PER_PEER`) that `max` is clamped to never
    /// exceed, regardless of what's passed as `max`. `initial` is itself
    /// clamped into the resulting `[min, max]` range.
    pub fn new(initial: usize, min: usize, max: usize, hard_ceiling: usize) -> Self {
        let min = min.max(1);
        let max = max.min(hard_ceiling).max(min);
        let initial = initial.clamp(min, max);
        Self {
            min,
            max,
            state: StdMutex::new(WindowState { window: initial as f64, smoothed_rtt: None }),
        }
    }

    /// The current recommended number of concurrent in-flight requests —
    /// always within `[min, max]`, regardless of how many
    /// `on_success`/`on_timeout` calls have run.
    pub fn current(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (state.window.round() as i64).clamp(self.min as i64, self.max as i64) as usize
    }

    /// Records a successful, answered `fetch_block` round trip and its
    /// observed latency (a smoothed RTT — an EWMA of
    /// block-request-response latency). Grows the window additively unless this
    /// sample itself shows RTT inflation relative to the smoothed
    /// baseline, in which case it backs off multiplicatively instead —
    /// the same "or RTT inflation" back-off trigger `on_timeout` also
    /// uses, just observed via latency rather than an outright missing
    /// reply.
    pub fn on_success(&self, rtt: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let rtt_secs = rtt.as_secs_f64();
        let inflated = match state.smoothed_rtt {
            Some(baseline) if baseline.as_secs_f64() > 0.0 => {
                rtt_secs > baseline.as_secs_f64() * RTT_INFLATION_FACTOR
            }
            // No baseline yet (first sample) — nothing to compare against,
            // never treated as inflation.
            _ => false,
        };
        state.smoothed_rtt = Some(match state.smoothed_rtt {
            None => rtt,
            Some(baseline) => Duration::from_secs_f64(
                baseline.as_secs_f64() * (1.0 - RTT_EWMA_ALPHA) + rtt_secs * RTT_EWMA_ALPHA,
            ),
        });
        if inflated {
            state.window = (state.window * MULTIPLICATIVE_DECREASE_FACTOR).max(self.min as f64);
        } else {
            state.window = (state.window + ADDITIVE_INCREASE_STEP).min(self.max as f64);
        }
    }

    /// Records an explicit loss/timeout signal — a `fetch_block` request
    /// this peer never answered within the caller's own bound (see
    /// `PeerSyncSession::record_fetch_timeout`'s doc comment for why this
    /// can't be observed from inside `fetch_block` itself). Always backs
    /// off multiplicatively, floored at `min` — this controller never lets
    /// a sustained-bad-link peer starve completely (still bounded below,
    /// not just above).
    pub fn on_timeout(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.window = (state.window * MULTIPLICATIVE_DECREASE_FACTOR).max(self.min as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_the_clamped_initial_value() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        assert_eq!(w.current(), 4);
    }

    #[test]
    fn initial_above_max_is_clamped_down_at_construction() {
        let w = AdaptiveWindow::new(999, 1, 64, 64);
        assert_eq!(w.current(), 64);
    }

    #[test]
    fn max_is_clamped_to_the_hard_ceiling_even_if_a_larger_max_is_requested() {
        // A caller-requested `max` above the pre-existing hard security
        // ceiling never actually takes effect.
        let w = AdaptiveWindow::new(4, 1, 1_000_000, /* hard_ceiling */ 64);
        assert_eq!(w.max, 64);
    }

    /// Additively grows the in-flight window while RTT is
    /// stable, clamped to [min, max]. Real proof, not just the math in
    /// isolation: repeated fast, stable-RTT successes must move the
    /// window up, one step at a time, and never past `max` even under a
    /// long burst of perfect conditions.
    #[test]
    fn grows_additively_under_repeated_low_stable_rtt_and_never_exceeds_the_ceiling() {
        let ceiling = 64;
        let w = AdaptiveWindow::new(4, 1, ceiling, ceiling);
        let before = w.current();
        for _ in 0..5 {
            w.on_success(Duration::from_millis(10));
        }
        let after_five = w.current();
        assert!(after_five > before, "window should have grown: {before} -> {after_five}");

        // A long burst of perfect, identical-RTT conditions — proves the
        // ceiling holds even under sustained "ideal" input, not just a
        // handful of samples.
        for _ in 0..500 {
            w.on_success(Duration::from_millis(10));
        }
        assert!(
            w.current() <= ceiling,
            "adaptive window must never exceed the pre-existing hard concurrency ceiling, got {}",
            w.current()
        );
        assert_eq!(
            w.current(),
            ceiling,
            "sustained perfect conditions should saturate at the ceiling"
        );
    }

    /// Multiplicatively backs off on timeouts/loss. Real
    /// proof: grow the window under good conditions, then inject
    /// timeouts (simulating packet loss / an unresponsive peer) and show
    /// the window actually shrinks, floored at `min`.
    #[test]
    fn shrinks_multiplicatively_on_injected_timeouts_and_floors_at_min() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..20 {
            w.on_success(Duration::from_millis(10));
        }
        let grown = w.current();
        assert!(grown > 4, "should have grown from the initial 4 first, got {grown}");

        for _ in 0..30 {
            w.on_timeout();
        }
        let shrunk = w.current();
        assert!(
            shrunk < grown,
            "window should have shrunk under sustained timeouts: {grown} -> {shrunk}"
        );
        assert_eq!(shrunk, 1, "sustained loss should floor the window at min, got {shrunk}");
    }

    /// Backs off on RTT inflation too, not just an
    /// outright missing reply — a real degraded-but-still-answering link
    /// (rising latency, no explicit loss/timeout) must still shrink the
    /// window.
    #[test]
    fn shrinks_on_rtt_inflation_without_any_explicit_timeout() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..10 {
            w.on_success(Duration::from_millis(10));
        }
        let grown = w.current();
        assert!(grown > 4);

        // Same peer, same session — no timeouts at all, but every
        // round trip is now several times slower than the established
        // baseline (RTT inflation, not loss).
        for _ in 0..10 {
            w.on_success(Duration::from_millis(200));
        }
        assert!(
            w.current() < grown,
            "RTT inflation alone (no explicit timeout) should still shrink the window: {grown} -> {}",
            w.current()
        );
    }

    /// Grows and shrinks within bounds — a full
    /// degrade-then-recover cycle, proving the window is not a one-way
    /// ratchet in either direction.
    #[test]
    fn recovers_and_grows_again_after_conditions_improve() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..20 {
            w.on_success(Duration::from_millis(10));
        }
        let grown = w.current();

        for _ in 0..30 {
            w.on_timeout();
        }
        let shrunk = w.current();
        assert!(shrunk < grown);

        // Conditions recover: the link answers quickly and reliably
        // again. Reset the baseline expectation implicitly via repeated
        // stable samples (the EWMA re-converges) and confirm real growth
        // resumes from the shrunk point.
        for _ in 0..40 {
            w.on_success(Duration::from_millis(10));
        }
        assert!(
            w.current() > shrunk,
            "window should grow back once conditions improve: {shrunk} -> {}",
            w.current()
        );
    }

    #[test]
    fn never_drops_below_min_even_under_unbounded_sustained_timeouts() {
        let w = AdaptiveWindow::new(4, 2, 64, 64);
        for _ in 0..1000 {
            w.on_timeout();
        }
        assert_eq!(w.current(), 2);
    }

    #[test]
    fn min_floor_is_at_least_one_even_if_zero_is_requested() {
        let w = AdaptiveWindow::new(4, 0, 64, 64);
        for _ in 0..1000 {
            w.on_timeout();
        }
        assert_eq!(w.current(), 1, "a peer must always get at least one in-flight slot");
    }
}
