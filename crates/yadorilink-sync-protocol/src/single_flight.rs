//! One reconciliation per peer and group, however much happens meanwhile.
//!
//! When new possession lands while a reconciliation is running, the answer is
//! not another reconciliation. It is a marker that the running one is now
//! working from a stale view, so that exactly one more pass follows it — not
//! one per event.
//!
//! Without this, a burst of arrivals turns into a burst of concurrent
//! sessions against the same peer, each re-deriving nearly the same
//! difference, each competing for the same lanes and the same writer. That is
//! the amplification shape the redesign exists to remove; it must not be
//! reintroduced by the thing meant to keep peers up to date.
//!
//! Periodic sweeps have no role here. They are for auditing lost wake-ups and
//! crashes, never the ordinary route to convergence: correctness comes from
//! comparing durable sets, so a missed wake-up costs latency and nothing else.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

/// Per-key single-flight with epoch coalescing.
#[derive(Debug)]
pub struct SingleFlight<K> {
    state: Mutex<HashMap<K, KeyState>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct KeyState {
    /// Incremented every time something makes the current view stale.
    epoch: u64,
    /// Which run currently owns this key, if any.
    ///
    /// A generation rather than a bool: settling and releasing are one
    /// transition, but a guard can still run afterwards on an error path, and
    /// by then a different run may legitimately own the key. Comparing
    /// generations means a stale guard can only ever release ITS own
    /// ownership, never a successor's.
    owner: Option<u64>,
    /// Hands out owner generations.
    next_owner: u64,
}

/// What a [`SingleFlight::run`] call did.
#[derive(Debug, PartialEq, Eq)]
pub enum Flight {
    /// The closure ran this many times. More than once means the view went
    /// stale while it was running.
    Ran { passes: usize },
    /// Another caller already holds this key. That caller will observe the
    /// epoch bumped in the meantime and make a further pass, so this call
    /// does nothing rather than starting a second concurrent reconciliation.
    Coalesced,
}

impl<K: Eq + Hash + Clone> Default for SingleFlight<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone> SingleFlight<K> {
    pub fn new() -> Self {
        Self { state: Mutex::new(HashMap::new()) }
    }

    /// Mark `key`'s view stale. Cheap, non-blocking, and safe to call from
    /// anywhere — it neither spawns nor waits.
    pub fn wake(&self, key: &K) {
        let mut state = self.state.lock().expect("single-flight state poisoned");
        state.entry(key.clone()).or_default().epoch += 1;
    }

    /// Run `work` until it has observed the current epoch.
    ///
    /// At most one call per key is in flight. `work` is an async closure taking
    /// no arguments; it is re-run only if the epoch moved while it was running.
    pub async fn run<F, Fut, T, E>(&self, key: K, mut work: F) -> Result<Flight, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let Some(generation) = self.claim(&key) else {
            return Ok(Flight::Coalesced);
        };

        // Covers the error paths. The success path settles and releases as one
        // transition in `settle_or_keep`, after which this guard finds itself
        // no longer the owner and does nothing.
        let _guard = ReleaseOnDrop { owner: self, key: key.clone(), generation };

        let mut passes = 0usize;
        loop {
            let observed = self.epoch(&key);
            work().await?;
            passes += 1;

            // Settled only if nothing went stale during that pass -- decided
            // and released together, so no wake can fall between the two.
            if self.settle_or_keep(&key, observed, generation) {
                #[cfg(test)]
                settle_hook::fire();
                return Ok(Flight::Ran { passes });
            }
        }
    }

    /// Take ownership of `key`, returning this run's generation.
    fn claim(&self, key: &K) -> Option<u64> {
        let mut state = self.state.lock().expect("single-flight state poisoned");
        let entry = state.entry(key.clone()).or_default();
        if entry.owner.is_some() {
            return None;
        }
        let generation = entry.next_owner;
        entry.next_owner += 1;
        entry.owner = Some(generation);
        Some(generation)
    }

    /// Give up ownership, but only if this run still holds it.
    fn release(&self, key: &K, generation: u64) {
        let mut state = self.state.lock().expect("single-flight state poisoned");
        if let Some(entry) = state.get_mut(key) {
            if entry.owner == Some(generation) {
                entry.owner = None;
            }
        }
    }

    /// Decide, in ONE critical section, whether this run is finished.
    ///
    /// Settling and releasing must be a single transition. Split apart, a
    /// `wake` landing between them is lost outright: the newcomer that tries
    /// to claim still sees the key held and coalesces, and the owner then
    /// releases anyway -- leaving the key idle, the epoch unconsumed, and
    /// nothing scheduled to look again. Where the wake is itself the only
    /// scheduling event, nothing ever looks again.
    ///
    /// Returns `true` when this run may return; `false` when the epoch moved
    /// and it must make another pass, keeping ownership throughout.
    fn settle_or_keep(&self, key: &K, observed: u64, generation: u64) -> bool {
        let mut state = self.state.lock().expect("single-flight state poisoned");
        let entry = state.entry(key.clone()).or_default();
        if entry.epoch != observed {
            return false;
        }
        if entry.owner == Some(generation) {
            entry.owner = None;
        }
        true
    }

    fn epoch(&self, key: &K) -> u64 {
        let mut state = self.state.lock().expect("single-flight state poisoned");
        state.entry(key.clone()).or_default().epoch
    }
}

struct ReleaseOnDrop<'a, K: Eq + Hash + Clone> {
    owner: &'a SingleFlight<K>,
    key: K,
    generation: u64,
}

impl<K: Eq + Hash + Clone> Drop for ReleaseOnDrop<'_, K> {
    fn drop(&mut self) {
        self.owner.release(&self.key, self.generation);
    }
}

/// A shareable handle, for the common case of one scheduler behind an `Arc`.
pub type SharedSingleFlight<K> = Arc<SingleFlight<K>>;

/// Test-only seam at the exact instant a runner has decided it is settled.
///
/// The bug this exists to pin lives between that decision and the key
/// actually becoming free, which is unreachable from outside: it is
/// nanoseconds wide and has no observable edge. A hook here lets a test
/// stand in for the scheduler that raced it, deterministically and with no
/// thread or timer.
#[cfg(test)]
mod settle_hook;

#[cfg(test)]
mod tests;
