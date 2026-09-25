//! The jitter source a turmoil build draws from, so a run seed reproduces
//! the reconnect and NAT-refresh schedules it produced last time.
//!
//! # Why this exists at all
//!
//! Backoff jitter is the one place this crate deliberately wants
//! nondeterminism in production: two devices that restart together must not
//! retry in lockstep. Under simulation that same call is the difference
//! between a seed reproducing a failure and a seed reproducing nothing, so
//! each substrate has to point it somewhere seeded.
//!
//! turmoil seeds only turmoil's own randomness (link latency, host ordering);
//! `Builder::rng_seed` is not reachable by application code and does not
//! touch a PRNG the application owns. Without this module a turmoil build
//! would silently fall through to the production path and seed its jitter
//! from the wall clock -- green, reproducible-looking, and reproducing
//! nothing.
//!
//! # Why a thread-local and not a port
//!
//! The harness runs many independently-seeded simulations at once, one per
//! OS thread, and each must be isolated from the others. A thread-local is
//! exactly that scope and costs one function call. The alternative -- an
//! injected RNG interface threaded through the transport's construction --
//! would put a simulation-shaped parameter on a production type to serve a
//! use that never occurs in production.

#![cfg(turmoil)]

use std::cell::Cell;

/// The stream an unseeded thread draws from.
///
/// This started out as a panic, on the reasoning that an unseeded draw meant
/// a harness bug. It does not. The DST runner seeds every thread it runs a
/// simulation on, in one place, before the simulation starts -- so a
/// scenario is seeded by construction and the panic could never fire for
/// one. What it did fire for was this crate's own unit tests, which draw
/// backoff jitter with no simulation anywhere in sight and are perfectly
/// entitled to: they are asserting that backoff doubles and caps, not that
/// it replays.
///
/// A fixed constant rather than the wall clock, so even those runs stay
/// reproducible. Deliberately not zero: the mixing below turns a zero seed
/// into a stream that starts with a visibly non-uniform run.
const UNSEEDED: u64 = 0x5EED_0000_0000_0001;

thread_local! {
    /// `None` until a simulation claims this thread; see [`UNSEEDED`] for
    /// what a draw before that means and why it is not an error.
    static STATE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Binds this OS thread's jitter stream to `seed`, for the simulation about
/// to run on it. Called by the DST runner before the simulation starts, once
/// per run, so consecutive runs on a reused thread each get their own
/// stream rather than continuing the previous one's.
pub fn seed_this_thread(seed: u64) {
    // Mixed rather than used raw so that seeds which differ only in their
    // low bits -- exactly the shape the harness generates, `base + i` --
    // do not produce jitter streams that start out nearly identical.
    STATE.with(|state| state.set(Some(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)));
}

/// A `[0, 1)` draw from this thread's stream.
pub(crate) fn unit_interval() -> f64 {
    let next = STATE.with(|state| {
        let current = state.get().unwrap_or(UNSEEDED);
        let next = current.wrapping_add(0x9E37_79B9_7F4A_7C15);
        state.set(Some(next));
        next
    });
    // splitmix64's finalizer, the same one the production path uses -- the
    // difference between the two is where the seed comes from, not how the
    // bits are mixed.
    let mut z = next;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_reproduces_the_same_stream() {
        seed_this_thread(42);
        let first: Vec<f64> = (0..16).map(|_| unit_interval()).collect();
        seed_this_thread(42);
        let second: Vec<f64> = (0..16).map(|_| unit_interval()).collect();
        assert_eq!(first, second, "re-seeding must restart the stream, not continue it");
        assert!(first.iter().all(|v| (0.0..1.0).contains(v)), "draws must stay in [0, 1)");
    }

    /// The unseeded path is a real path, not a safety net nobody takes --
    /// every unit test in this crate that exercises backoff goes through it
    /// -- so it has to be reproducible like any other.
    #[test]
    fn an_unseeded_thread_still_draws_a_reproducible_stream() {
        let drawn: Vec<f64> = (0..8).map(|_| unit_interval()).collect();
        assert!(drawn.iter().all(|v| (0.0..1.0).contains(v)), "draws must stay in [0, 1)");
        assert!(
            drawn.windows(2).any(|w| w[0] != w[1]),
            "an unseeded stream must still vary, not repeat one value"
        );
    }

    #[test]
    fn adjacent_seeds_do_not_produce_the_same_stream() {
        seed_this_thread(1000);
        let a: Vec<f64> = (0..8).map(|_| unit_interval()).collect();
        seed_this_thread(1001);
        let b: Vec<f64> = (0..8).map(|_| unit_interval()).collect();
        assert_ne!(a, b, "the harness generates seeds as base + i, so these must diverge");
    }
}
