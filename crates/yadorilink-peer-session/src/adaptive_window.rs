//! An AIMD-style, per-peer adaptive
//! in-flight block-fetch window.
//!
//! Before this change, the number of concurrently outstanding
//! `PeerSyncSession::fetch_block` requests to one peer was a fixed
//! constant everywhere it mattered — `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
//! (peer_session.rs, inbound-message concurrency bound) and
//! `PER_PEER_IN_FLIGHT_WINDOW` (yadorilink-daemon::hydration's multi-peer
//! fetch dispatcher, fixed lane count). Fast, low-RTT links never
//! got to pipeline past that fixed count; slow/lossy ones got pushed to
//! send that many requests regardless of whether the link could sustain
//! them.
//!
//! `AdaptiveWindow` replaces the *lane-count* half of that (the daemon's
//! per-candidate fetch concurrency) with a controller driven by real
//! observed conditions on this session: smoothed RTT (EWMA) and explicit
//! timeout/loss signals. It does **not** touch `MAX_IN_FLIGHT_MESSAGES_PER_PEER` —
//! that constant remains the fixed security ceiling (DoS bound
//! on *inbound* message handling) this controller's own `max` is
//! constructed to never exceed, so the adaptive window composes with,
//! rather than replaces, the existing security hardening: max never
//! exceeds the per-peer concurrency bound set by that hardening.
//!
//! Pure and synchronous (no I/O, no async) so it's directly unit-testable
//! — see the `tests` module below for the grow/shrink/ceiling/floor
//! proofs. `PeerSyncSession` (peer_session.rs) owns one instance per
//! session and feeds it real `fetch_block` outcomes; `yadorilink-daemon`'s
//! multi-peer dispatcher reads `PeerSyncSession::fetch_window` in place
//! of the old fixed lane constant.

use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

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

/// Fallback debounce window for collapsing repeated multiplicative-
/// decrease signals into one, used until a real RTT sample exists (see
/// `WindowState::last_backoff`'s own doc comment) -- standard TCP-
/// congestion-control practice ("at most one window reduction per RTT")
/// applied here because several concurrent in-flight requests launched
/// together share one underlying congestion event: if that event causes
/// N of them to time out, treating each as an INDEPENDENT signal
/// collapses the window N times for what is really ONE episode. Confirmed
/// directly as a real bug, not a theoretical one: an initial 8-request
/// burst (`topology_simultaneous_reconnect_and_relay_hydration_failure.
/// rs`'s relay-recovery scenario) produced 4 near-simultaneous timeouts,
/// collapsing a window of 4 to its floor of 1 within a single dispatch
/// attempt -- even though the window never saw a genuinely NEW congestion
/// signal after the first. Once a real RTT sample exists, that baseline
/// -- not this fallback -- is the debounce window (the textbook choice);
/// this fixed fallback only covers the gap before any sample exists,
/// which is exactly the first-burst case above. Chosen comfortably
/// shorter than any real, separate congestion episode would need to
/// develop, but comfortably longer than how far apart several timeouts
/// from ONE simultaneous burst actually land (observed: within the same
/// polling tick of each other).
const BACKOFF_DEBOUNCE_FALLBACK: Duration = Duration::from_millis(500);

struct WindowState {
    /// Fractional so additive growth/multiplicative backoff compose
    /// smoothly across many calls instead of getting stuck at an integer
    /// step boundary — `current` rounds and clamps this to `[min, max]`
    /// for callers.
    window: f64,
    smoothed_rtt: Option<Duration>,
    /// When the most recent multiplicative decrease was actually applied
    /// -- `None` until the first one. See `BACKOFF_DEBOUNCE_FALLBACK`'s
    /// own doc comment for why repeated timeout/congestion signals within
    /// one debounce window collapse into a single backoff instead of each
    /// halving the window independently.
    last_backoff: Option<Instant>,
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
            state: StdMutex::new(WindowState {
                window: initial as f64,
                smoothed_rtt: None,
                last_backoff: None,
            }),
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
    ///
    /// `queue_position` is how many requests to this same peer were
    /// outstanding at the moment THIS one was sent, this one included (so
    /// `1` means it had no live sibling at send time, i.e. an ISOLATED
    /// round trip).
    ///
    /// It matters because this controller's whole reason for existing is
    /// to size a PIPELINE (see this module's own doc comment): once more
    /// than one request to a peer is in flight at once, that peer's own
    /// dispatch order need not match send order at all -- confirmed
    /// directly, a real 8-request burst answered in positions
    /// `8,6,1,7,4,5,2,3` relative to send order, not the strictly serial
    /// FIFO a naive model assumes. A pipelined reply's elapsed time is
    /// therefore not attributable to any fixed share of "this request's
    /// real round trip" -- it is contaminated by however much of every
    /// OTHER concurrently in-flight request's own service time happened
    /// to land ahead of it, in an order this controller cannot recover
    /// after the fact. Reading that contaminated latency as RTT inflation
    /// used to collapse the window to `min` on the very first real
    /// multi-block transfer regardless of how healthy the link actually
    /// was -- the opposite of this controller's purpose.
    ///
    /// So a pipelined sample (`queue_position > 1`) never touches the RTT
    /// baseline and never triggers the inflation back-off -- there is no
    /// way to tell, from latency alone, whether it reflects the link or
    /// simply its siblings' own work ahead of it. It still grows the
    /// window additively: a successful reply under real concurrent load
    /// IS positive evidence this many requests in flight is sustainable,
    /// regardless of the shape of any one reply's latency. Only an
    /// ISOLATED sample (`queue_position <= 1`, no sibling in flight when
    /// it was sent) is trustworthy evidence of the link's own RTT, so
    /// only isolated samples update the smoothed baseline and can trigger
    /// the multiplicative back-off. Real degradation under concurrent
    /// load is still caught -- just via `on_timeout`/`on_congestion`
    /// (explicit loss and explicit `Busy`), which this change does not
    /// touch, rather than via inferring it from a queued reply's latency.
    pub fn on_success(&self, rtt: Duration, queue_position: usize) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if queue_position > 1 {
            // Pipelined: real success, but its latency proves nothing
            // about the link on its own (see this function's own doc
            // comment) -- grow, but leave the RTT baseline and the
            // inflation check alone.
            state.window = (state.window + ADDITIVE_INCREASE_STEP).min(self.max as f64);
            return;
        }
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
            self.apply_debounced_backoff(&mut state);
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
        self.apply_debounced_backoff(&mut state);
    }

    /// Records an explicit congestion signal that is neither a healthy
    /// round trip nor an outright timeout/loss — specifically,
    /// `FetchOutcome::Busy`: the peer DID answer, quickly, but said its own
    /// serve queue is over capacity right now. Backs off multiplicatively
    /// like `on_timeout`, but does NOT touch the smoothed RTT baseline
    /// (there is no meaningful "round trip time" for a request the peer
    /// never actually served) — `on_success` must never be called for this
    /// outcome: a fast `Busy` reply is not evidence the link/peer can
    /// sustain more concurrent requests, it's the opposite, and treating
    /// it as a successful round trip would grow the window into exactly
    /// the congestion `Busy` is reporting (fast Busy -> looks like a
    /// healthy RTT -> window grows -> more requests sent -> more Busy).
    pub fn on_congestion(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.apply_debounced_backoff(&mut state);
    }

    /// Applies one multiplicative decrease, unless a backoff already
    /// landed within the current debounce window (the smoothed RTT once
    /// known, `BACKOFF_DEBOUNCE_FALLBACK` before that) -- see
    /// `WindowState::last_backoff` and `BACKOFF_DEBOUNCE_FALLBACK`'s own
    /// doc comments for why. Debounced calls are a deliberate no-op: they
    /// still represent real signals (the peer/link genuinely is
    /// congested), just not NEW evidence beyond what the most recent
    /// backoff already accounted for.
    fn apply_debounced_backoff(&self, state: &mut WindowState) {
        let debounce_window = state.smoothed_rtt.unwrap_or(BACKOFF_DEBOUNCE_FALLBACK);
        let debounced =
            state.last_backoff.is_some_and(|last| last.elapsed() < debounce_window);
        if debounced {
            return;
        }
        state.window = (state.window * MULTIPLICATIVE_DECREASE_FACTOR).max(self.min as f64);
        state.last_backoff = Some(Instant::now());
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
            w.on_success(Duration::from_millis(10), 1);
        }
        let after_five = w.current();
        assert!(after_five > before, "window should have grown: {before} -> {after_five}");

        // A long burst of perfect, identical-RTT conditions — proves the
        // ceiling holds even under sustained "ideal" input, not just a
        // handful of samples.
        for _ in 0..500 {
            w.on_success(Duration::from_millis(10), 1);
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
    ///
    /// Each injected timeout is spaced past the debounce window (see
    /// `apply_debounced_backoff`'s own doc comment): this test is about
    /// SEPARATE, real congestion episodes over time, distinct from
    /// `repeated_timeouts_from_one_burst_collapse_to_a_single_backoff`
    /// below, which specifically proves several timeouts arriving
    /// together do NOT each apply their own backoff.
    #[test]
    fn shrinks_multiplicatively_on_injected_timeouts_and_floors_at_min() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..20 {
            w.on_success(Duration::from_millis(10), 1);
        }
        let grown = w.current();
        assert!(grown > 4, "should have grown from the initial 4 first, got {grown}");

        // The growth phase above established a ~10ms smoothed RTT, which
        // `on_timeout` itself never touches but which IS what the
        // debounce window reads -- so a real gap comfortably above 10ms
        // between calls is enough for each to count as a separate episode.
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            w.on_timeout();
        }
        let shrunk = w.current();
        assert!(
            shrunk < grown,
            "window should have shrunk under sustained timeouts: {grown} -> {shrunk}"
        );
        assert_eq!(shrunk, 1, "sustained loss should floor the window at min, got {shrunk}");
    }

    /// R3g: several concurrent requests launched together share ONE
    /// underlying congestion event -- if that event causes more than one
    /// of them to time out, each `on_timeout` call is a signal about the
    /// SAME episode, not independent evidence of repeated NEW congestion.
    /// Confirmed as a real bug, not a theoretical one: an initial 8-
    /// request burst produced 4 near-simultaneous timeouts, collapsing a
    /// window of 4 to its floor of 1 within a single dispatch attempt
    /// (`topology_simultaneous_reconnect_and_relay_hydration_failure.rs`'s
    /// relay-recovery scenario).
    #[test]
    fn repeated_timeouts_from_one_burst_collapse_to_a_single_backoff() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        // No RTT baseline yet (`on_timeout` never sets one), so the
        // debounce window is `BACKOFF_DEBOUNCE_FALLBACK` -- these 4 calls,
        // fired back-to-back with no delay, land well inside it.
        for _ in 0..4 {
            w.on_timeout();
        }
        assert_eq!(
            w.current(),
            2,
            "4 near-simultaneous timeouts from one burst must apply exactly one halving \
             (4 -> 2), not one independent halving per signal (which would floor to 1)"
        );
    }

    /// The debounce window is not a permanent latch: once it genuinely
    /// elapses, the NEXT timeout is treated as a new episode and backs
    /// off again.
    #[test]
    fn a_timeout_after_the_debounce_window_elapses_applies_a_new_backoff() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        w.on_timeout();
        assert_eq!(w.current(), 2, "first timeout must apply its own halving");
        std::thread::sleep(BACKOFF_DEBOUNCE_FALLBACK + Duration::from_millis(50));
        w.on_timeout();
        assert_eq!(w.current(), 1, "a timeout genuinely after the debounce window must back off again");
    }

    /// Regression: `Busy` (an explicit, fast congestion signal -- see
    /// `on_congestion`'s own doc comment for why this must never reach
    /// `on_success`) must shrink the window like a timeout, not grow it
    /// like a healthy round trip. Confirmed via repeated `on_congestion`
    /// calls specifically (not `on_timeout`) so this test would catch a
    /// regression that routed `Busy` through the wrong method even if
    /// `on_timeout` itself stayed correct.
    ///
    /// Spaced past the debounce window for the same reason `shrinks_
    /// multiplicatively_on_injected_timeouts_and_floors_at_min` is -- see
    /// that test's own doc comment.
    #[test]
    fn on_congestion_shrinks_multiplicatively_and_never_grows_the_window() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..20 {
            w.on_success(Duration::from_millis(10), 1);
        }
        let grown = w.current();
        assert!(grown > 4, "should have grown from the initial 4 first, got {grown}");

        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            w.on_congestion();
        }
        let shrunk = w.current();
        assert!(
            shrunk < grown,
            "window should have shrunk under sustained Busy congestion signals: {grown} -> {shrunk}"
        );
        assert_eq!(shrunk, 1, "sustained Busy should floor the window at min, got {shrunk}");
    }

    /// `on_congestion` must never grow the window even from a single call
    /// at the floor -- distinguishes it from `on_success`, which would
    /// grow from `min` on its very first call.
    #[test]
    fn on_congestion_never_grows_the_window_even_a_single_call() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        let before = w.current();
        w.on_congestion();
        assert!(
            w.current() <= before,
            "a single Busy congestion signal must never grow the window: {before} -> {}",
            w.current()
        );
    }

    /// Backs off on RTT inflation too, not just an
    /// outright missing reply — a real degraded-but-still-answering link
    /// (rising latency, no explicit loss/timeout) must still shrink the
    /// window.
    #[test]
    fn shrinks_on_rtt_inflation_without_any_explicit_timeout() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..10 {
            w.on_success(Duration::from_millis(10), 1);
        }
        let grown = w.current();
        assert!(grown > 4);

        // Same peer, same session — no timeouts at all, but every
        // round trip is now several times slower than the established
        // baseline (RTT inflation, not loss).
        for _ in 0..10 {
            w.on_success(Duration::from_millis(200), 1);
        }
        assert!(
            w.current() < grown,
            "RTT inflation alone (no explicit timeout) should still shrink the window: {grown} -> {}",
            w.current()
        );
    }

    /// Regression: a healthy link served through a deep, REAL pipeline
    /// (replies arriving out of send order, not the strictly serial FIFO a
    /// naive model would assume) must not read as RTT inflation just
    /// because a queued reply's own elapsed time is large. This is a real
    /// captured 8-request burst, `(elapsed_us, queue_position_at_send)` in
    /// actual arrival order -- notice positions arrive as `8,6,1,7,4,5,2,3`
    /// relative to send order, and elapsed time does not track position at
    /// all (see `on_success`'s own doc comment for how this was captured).
    /// Under the naive per-reply-RTT design this controller shipped with,
    /// several of these would have read as inflation and collapsed the
    /// window to `min`; here every entry but the one true isolated sample
    /// (`queue_position == 1`) must be treated as pipelined and grow the
    /// window regardless of its own elapsed time.
    #[test]
    fn pipelined_replies_out_of_send_order_never_read_as_inflation() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        let before = w.current();
        const REAL_BURST: [(u64, usize); 8] = [
            (11_903, 8),
            (18_616, 6),
            (29_922, 1),
            (40_668, 7),
            (51_561, 4),
            (60_998, 5),
            (64_522, 2),
            (68_075, 3),
        ];
        for (elapsed_us, queue_position) in REAL_BURST {
            w.on_success(Duration::from_micros(elapsed_us), queue_position);
        }
        assert!(
            w.current() > before,
            "a real pipelined burst, however out of order or however large any single \
             reply's own latency, must never collapse the window: {before} -> {}",
            w.current()
        );
    }

    /// Complementary regression: an ISOLATED reply (`queue_position == 1`,
    /// no sibling in flight at send time) is the one case where a large
    /// latency IS trustworthy evidence of real degradation, and must still
    /// shrink the window exactly as before this change -- otherwise this
    /// fix would have traded a false-negative-proof controller (always
    /// grows) for the false-positive-proof one it replaced.
    #[test]
    fn an_isolated_slow_reply_still_shrinks_the_window() {
        let w = AdaptiveWindow::new(4, 1, 64, 64);
        for _ in 0..10 {
            w.on_success(Duration::from_millis(10), 1);
        }
        let grown = w.current();
        assert!(grown > 4);
        for _ in 0..10 {
            w.on_success(Duration::from_millis(200), 1);
        }
        assert!(
            w.current() < grown,
            "an isolated (unpipelined) slow reply must still read as RTT inflation: \
             {grown} -> {}",
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
            w.on_success(Duration::from_millis(10), 1);
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
            w.on_success(Duration::from_millis(10), 1);
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
        // No RTT baseline (`on_timeout` never sets one), so each call must
        // be spaced past `BACKOFF_DEBOUNCE_FALLBACK` to count as a
        // separate episode -- see `repeated_timeouts_from_one_burst_
        // collapse_to_a_single_backoff`'s own doc comment for why rapid
        // repeated calls no longer each apply their own halving.
        for _ in 0..4 {
            std::thread::sleep(BACKOFF_DEBOUNCE_FALLBACK + Duration::from_millis(50));
            w.on_timeout();
        }
        assert_eq!(w.current(), 1, "a peer must always get at least one in-flight slot");
    }
}
