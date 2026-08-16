//! Wakes the ephemeral conflict-copy retirement loop (`engine_wrapper.rs`'s
//! `run_ephemeral_conflict_copy_retire_loop`) promptly whenever a group's
//! admitted DAG frontier advances or a materialization job reaches
//! `Completed` -- the two events after which a previously-justified
//! conflict copy can become unjustified (see
//! `retire_unjustified_ephemeral_conflict_copies`'s own doc comment for what
//! "unjustified" means). Before this, retirement's only trigger was a bare
//! 1s poll over every linked group, which is what let `row14_strict_
//! acceptance` observe seconds of pure delay between a copy becoming
//! unjustified and its retirement even starting.
//!
//! Unlike `MaterializationWake`'s single process-wide `Notify` (that
//! loop's own poll is cheap and indexed, so a coarse "something changed,
//! re-poll everything" wake is sufficient), retirement's own per-group
//! audit is comparatively expensive (a full local frontier walk per
//! ephemeral-shaped file), so this tracks WHICH groups actually became
//! dirty: a busy group's frontier churn must not turn into work for every
//! other quiet linked group on every wake.
use std::collections::BTreeSet;
use std::sync::Mutex;

pub struct RetirementWake {
    dirty: Mutex<BTreeSet<String>>,
    notify: tokio::sync::Notify,
}

impl Default for RetirementWake {
    fn default() -> Self {
        Self::new()
    }
}

impl RetirementWake {
    pub fn new() -> Self {
        Self { dirty: Mutex::new(BTreeSet::new()), notify: tokio::sync::Notify::new() }
    }

    /// Marks `group_id` dirty for retirement re-evaluation and wakes the
    /// retirement loop. Safe under any number of concurrent producers (DAG
    /// admission, job completion): `BTreeSet::insert` naturally coalesces
    /// repeated marks for the same group arriving between two drains into
    /// one re-evaluation, exactly the coalescing behavior a retirement
    /// audit storm needs.
    pub fn mark_dirty(&self, group_id: &str) {
        self.dirty
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group_id.to_string());
        self.notify.notify_one();
    }

    /// Removes and returns every group marked dirty since the last drain.
    /// The consumer is responsible for re-marking (via a fresh
    /// `mark_dirty`) any group whose retire pass it could not actually run
    /// this round (e.g. `MaterializationAuditGuard` contention with a full
    /// audit already in flight) -- `drain` itself makes no retry guarantee,
    /// matching `MaterializationWake`'s own "coarse signal, not a promise"
    /// contract.
    pub fn drain(&self) -> BTreeSet<String> {
        std::mem::take(&mut *self.dirty.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Resolves once `mark_dirty` is called (or spuriously) -- callers must
    /// always pair this with a fallback timeout in a `select!`, exactly
    /// like `MaterializationWake::materialization_wake_notified`.
    pub async fn retirement_wake_notified(&self) {
        self.notify.notified().await;
    }
}
