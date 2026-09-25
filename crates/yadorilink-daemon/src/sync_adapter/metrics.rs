//! What the reconciliation path did, for a scale run to read back.
//!
//! Global atomic counters, because a scale run has to be able to say *why*
//! it converged, not only that it did. The old path's numbers were what
//! exposed the storm — 560-676 verification attempts per unique Change is not a slow protocol,
//! it is a protocol re-deriving the same answer hundreds of times.
//!
//! The two amplification ratios are the point of this module:
//!
//! ```text
//!   verifications / unique staged hash    ≈ 1  if each Change is proved once
//!   stage calls   / unique staged hash    ≈ 1  if each Change is stored once
//! ```
//!
//! Reconciliation should hold both near 1 by construction, because a peer
//! asks only for what a set comparison said it lacks. Measuring it is how
//! that stops being a claim.
//!
//! Process-global atomics, like the module they mirror: these are fixed call
//! sites, and nothing here attributes a count to a peer or a session. The
//! store's own concurrency high-water mark is not here, because it belongs to
//! a store instance rather than to the process -- read it from
//! `SyncStack::store_metrics`.

use std::sync::atomic::{AtomicU64, Ordering};

static SESSIONS: AtomicU64 = AtomicU64::new(0);
static ROUNDS: AtomicU64 = AtomicU64::new(0);
static WANTED: AtomicU64 = AtomicU64::new(0);
static BUNDLES_SERVED: AtomicU64 = AtomicU64::new(0);
static BUNDLES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static VERIFICATIONS: AtomicU64 = AtomicU64::new(0);
static STAGE_CALLS: AtomicU64 = AtomicU64::new(0);
static STAGED_NEW: AtomicU64 = AtomicU64::new(0);
static BEHIND_WAKES: AtomicU64 = AtomicU64::new(0);

/// One reconciliation session this device initiated, and what it cost.
pub fn record_session(rounds: usize, wanted: usize) {
    SESSIONS.fetch_add(1, Ordering::Relaxed);
    ROUNDS.fetch_add(rounds as u64, Ordering::Relaxed);
    WANTED.fetch_add(wanted as u64, Ordering::Relaxed);
}

/// Bundles handed to a peer that asked for them.
pub fn record_bundles_served(n: usize) {
    BUNDLES_SERVED.fetch_add(n as u64, Ordering::Relaxed);
}

/// One delivery: how many bundles arrived, how many verified, and how many
/// were newly staged.
///
/// All three counted at one call site so they cannot drift apart. `received`
/// above `verified` means bundles were rejected; `verified` far above `new`
/// means the same Change is being proved repeatedly, which is precisely the
/// amplification this module exists to detect.
pub fn record_delivery(received: usize, verified: usize, newly_staged: usize) {
    BUNDLES_RECEIVED.fetch_add(received as u64, Ordering::Relaxed);
    VERIFICATIONS.fetch_add(verified as u64, Ordering::Relaxed);
    STAGE_CALLS.fetch_add(1, Ordering::Relaxed);
    STAGED_NEW.fetch_add(newly_staged as u64, Ordering::Relaxed);
}

/// One session in which this device turned out to be the one behind, and so
/// scheduled its own pull.
pub fn record_behind_wake() {
    BEHIND_WAKES.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationStats {
    pub sessions: u64,
    pub rounds: u64,
    pub wanted: u64,
    pub bundles_served: u64,
    pub bundles_received: u64,
    pub verifications: u64,
    pub stage_calls: u64,
    pub staged_new: u64,
    pub behind_wakes: u64,
}

impl ReconciliationStats {
    /// Verifications per Change actually staged. The old path's equivalent
    /// ran at 560-676.
    ///
    /// `None` when nothing was staged, which is not a ratio of zero: a run
    /// that moved nothing has no amplification to report, and reporting 0
    /// would read as the best possible result.
    pub fn verification_amplification(&self) -> Option<f64> {
        (self.staged_new > 0).then(|| self.verifications as f64 / self.staged_new as f64)
    }

    /// Stage calls per Change actually staged.
    pub fn staging_amplification(&self) -> Option<f64> {
        (self.staged_new > 0).then(|| self.stage_calls as f64 / self.staged_new as f64)
    }
}

pub fn stats() -> ReconciliationStats {
    ReconciliationStats {
        sessions: SESSIONS.load(Ordering::Relaxed),
        rounds: ROUNDS.load(Ordering::Relaxed),
        wanted: WANTED.load(Ordering::Relaxed),
        bundles_served: BUNDLES_SERVED.load(Ordering::Relaxed),
        bundles_received: BUNDLES_RECEIVED.load(Ordering::Relaxed),
        verifications: VERIFICATIONS.load(Ordering::Relaxed),
        stage_calls: STAGE_CALLS.load(Ordering::Relaxed),
        staged_new: STAGED_NEW.load(Ordering::Relaxed),
        behind_wakes: BEHIND_WAKES.load(Ordering::Relaxed),
    }
}

pub fn reset() {
    for counter in [
        &SESSIONS,
        &ROUNDS,
        &WANTED,
        &BUNDLES_SERVED,
        &BUNDLES_RECEIVED,
        &VERIFICATIONS,
        &STAGE_CALLS,
        &STAGED_NEW,
        &BEHIND_WAKES,
    ] {
        counter.store(0, Ordering::Relaxed);
    }
}
