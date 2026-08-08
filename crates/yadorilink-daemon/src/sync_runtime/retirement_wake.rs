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
//!
//! State is a per-group `requested`/`completed` generation pair, not a
//! plain dirty flag/set. A plain dirty set (insert on mark, remove on
//! drain) makes correctness depend on every consumer exit path -- ran
//! cleanly, skipped on guard contention, transient error, retry-required --
//! re-marking dirty on every path that did not truly finish the work, with
//! no structural guard against missing one. A `mark_dirty` that lands
//! between a consumer's drain and its completion is silently absorbed by
//! that drain either way, so a frontier change during an in-flight audit
//! can be lost. Generations make "is there unretired work" a monotonic
//! comparison instead: `pending()` reports a group whenever `requested >
//! completed`, and only an explicit `complete(group, generation)` call --
//! made only once a pass has genuinely verified that generation's work --
//! advances `completed`. A `mark_dirty` racing an in-flight pass simply
//! bumps `requested` past the generation that pass is targeting, so
//! `pending()` reports the group again immediately after `complete` is
//! called for the stale generation: nothing to lose, because nothing is
//! cleared just by looking at it.
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Default)]
struct GroupGenerations {
    requested: u64,
    completed: u64,
}

pub struct RetirementWake {
    groups: Mutex<BTreeMap<String, GroupGenerations>>,
    notify: tokio::sync::Notify,
}

impl Default for RetirementWake {
    fn default() -> Self {
        Self::new()
    }
}

impl RetirementWake {
    pub fn new() -> Self {
        Self { groups: Mutex::new(BTreeMap::new()), notify: tokio::sync::Notify::new() }
    }

    /// Marks `group_id` dirty for retirement re-evaluation (bumping its
    /// requested generation) and wakes the retirement loop. Safe under any
    /// number of concurrent producers (DAG admission, job completion):
    /// repeated marks for the same group arriving before it is next
    /// completed all coalesce into the same target generation the next
    /// pass claims via `pending`.
    pub fn mark_dirty(&self, group_id: &str) {
        {
            let mut groups = self.groups.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            groups.entry(group_id.to_string()).or_default().requested += 1;
        }
        self.notify.notify_one();
    }

    /// Every group whose requested generation is ahead of its completed
    /// generation, paired with the generation a pass claiming it right now
    /// should aim to complete. Read-only -- unlike the old `drain()`,
    /// nothing is consumed or reset here. A pass must call `complete` with
    /// the paired generation once it has genuinely verified that
    /// generation's state, and only then does the group stop being
    /// reported. A pass that could not actually run (guard contention,
    /// transient error, retry-required) simply does not call `complete`,
    /// and the group keeps being reported on every subsequent `pending`
    /// call with no separate re-mark required.
    pub fn pending(&self) -> BTreeMap<String, u64> {
        self.groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, g)| g.requested > g.completed)
            .map(|(group_id, g)| (group_id.clone(), g.requested))
            .collect()
    }

    /// Records that `group_id`'s retirement state has been genuinely
    /// verified through `generation` (the value `pending` returned for it
    /// when the now-finishing pass started). Monotonic: never regresses
    /// `completed`, so an out-of-order or duplicate call from a slow pass
    /// can never un-complete a generation a newer pass already recorded.
    /// If `mark_dirty` landed while the pass ran, `requested` is now ahead
    /// of `generation`, so `pending` reports the group again immediately --
    /// this is the mechanism that makes an event arriving mid-audit
    /// provoke exactly one follow-up audit rather than being lost.
    pub fn complete(&self, group_id: &str, generation: u64) {
        let mut groups = self.groups.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(g) = groups.get_mut(group_id) {
            if generation > g.completed {
                g.completed = generation;
            }
        }
    }

    /// Resolves once `mark_dirty` is called (or spuriously) -- callers must
    /// always pair this with a fallback timeout in a `select!`, exactly
    /// like `MaterializationWake::materialization_wake_notified`.
    pub async fn retirement_wake_notified(&self) {
        self.notify.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_then_pending_reports_the_group() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        let pending = wake.pending();
        assert_eq!(pending.get("g1"), Some(&1));
    }

    #[test]
    fn repeated_marks_before_claim_coalesce_but_still_advance_requested() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        wake.mark_dirty("g1");
        wake.mark_dirty("g1");
        // Coalesced into one pending entry, but the target generation
        // reflects every mark that landed, not just the first.
        assert_eq!(wake.pending().len(), 1);
        assert_eq!(wake.pending().get("g1"), Some(&3));
    }

    #[test]
    fn complete_at_claimed_generation_clears_pending() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        let generation = *wake.pending().get("g1").unwrap();
        wake.complete("g1", generation);
        assert!(wake.pending().is_empty());
    }

    #[test]
    fn mark_during_claimed_pass_stays_pending_after_stale_complete() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        let claimed_generation = *wake.pending().get("g1").unwrap();
        // A new event lands while the pass claiming `claimed_generation`
        // is still running.
        wake.mark_dirty("g1");
        // The in-flight pass finishes and reports success for the
        // generation it actually claimed -- not the new one.
        wake.complete("g1", claimed_generation);
        // Exactly one follow-up audit's worth of pending work remains.
        let pending = wake.pending();
        assert_eq!(pending.get("g1"), Some(&(claimed_generation + 1)));
    }

    #[test]
    fn busy_pass_that_never_completes_leaves_group_pending() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        let _claimed_generation = *wake.pending().get("g1").unwrap();
        // Guard contention / transient error / retry-required: the pass
        // never calls `complete` at all.
        assert_eq!(wake.pending().get("g1"), Some(&1));
    }

    #[test]
    fn out_of_order_complete_never_regresses_completed() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        wake.mark_dirty("g1");
        // A late pass for generation 1 reports success after a pass for
        // generation 2 already completed.
        wake.complete("g1", 2);
        wake.complete("g1", 1);
        assert!(wake.pending().is_empty());
    }

    #[test]
    fn success_with_no_new_event_is_clean() {
        let wake = RetirementWake::new();
        wake.mark_dirty("g1");
        wake.mark_dirty("g2");
        let g1_generation = *wake.pending().get("g1").unwrap();
        wake.complete("g1", g1_generation);
        let pending = wake.pending();
        assert!(!pending.contains_key("g1"));
        assert!(pending.contains_key("g2"));
    }

    #[test]
    fn complete_for_unknown_group_is_a_harmless_no_op() {
        let wake = RetirementWake::new();
        wake.complete("never-marked", 1);
        assert!(wake.pending().is_empty());
    }
}
