//! Work-class scheduling primitive (design §15/§15.1/§15.2, §22.2): bounds
//! how much of a shared, concurrency-limited resource (SQLite writer turns,
//! hashing worker slots, file descriptors, disk-write slots -- one
//! [`WorkClassQueue`] per resource the caller wants to arbitrate) any one
//! work class can take, so background work can never starve interactive
//! hydration or canonical materialization, and so no single class is
//! starved out entirely.
//!
//! **Admission control, not an owning scheduler.** This is an async
//! `acquire`/RAII-guard primitive a caller awaits immediately before doing
//! the work itself -- it never spawns a thread or task of its own and owns
//! no execution. Everything it blocks on is a `tokio::sync` primitive
//! (`oneshot`), the same choice [`crate::block_serve::BlockServeEngine`]'s
//! `FairDispatchQueue` and [`crate::rate_limiter::TokenBucket`] already
//! make in this crate. That matters beyond style: this crate's DST harness
//! (`tests/dst_support`) simulates by intercepting `tokio`'s clock and
//! scheduler under `--cfg madsim`; a component that instead spawned an
//! `std::thread` or ran its own event loop would be invisible to and
//! uncontrollable by the simulator. Building this as admission control that
//! callers await keeps it inside that simulated envelope for free.
//!
//! # Classes (design §15.1)
//!
//! Six classes, this module's own priority order:
//!
//! 1. [`WorkClass::InteractiveLocalPreservation`] -- capturing a local edit
//!    the user is actively waiting on (the write that must land before the
//!    application's own save/flush call returns).
//! 2. [`WorkClass::ApplicationRequestedHydration`] -- materializing content
//!    an application explicitly opened/read and is blocked on right now.
//! 3. [`WorkClass::CanonicalRemoteMaterialization`] -- applying an incoming
//!    remote change to reach the canonical desired state (not requested by
//!    a foreground open, but still on the path other peers' convergence
//!    depends on).
//! 4. [`WorkClass::RepairAndRestore`] -- re-deriving or re-fetching content
//!    after loss/corruption/an explicit restore request.
//! 5. [`WorkClass::RetainedPreimageClassification`] -- classifying/authoring
//!    a retained preimage in the background (design §11.2's single-pass
//!    capture pipeline) -- the 40 GB VM image case this module exists to
//!    keep off the interactive path.
//! 6. [`WorkClass::RetirementCompactionCleanup`] -- retirement, compaction
//!    and cleanup (design §12/§18.1's stub compaction, block GC).
//!
//! # What "cannot starve" means here
//!
//! Strict priority is deliberately rejected: it would let the lowest class
//! never run at all under sustained higher-class load, and design §16/§22.2
//! are explicit that background custody/compaction/classification work that
//! never runs means retained obligations accumulate forever -- a different
//! kind of starvation, not a fix for it. Instead this is **weighted fair
//! queuing with a virtual-time admission order**: each class carries a
//! monotonically increasing "virtual time" (cumulative granted cost divided
//! by its weight); whenever a slot frees, admission goes to the pending
//! class with the *lowest* virtual time, not the highest static priority.
//! Two consequences, both proven by [`self::tests`] rather than asserted:
//!
//! - **A class that has been idle sits at (or is rebased toward) virtual
//!   time zero.** A fresh interactive request racing a sustained,
//!   continuously-requeuing background stream in a lower class has strictly
//!   lower virtual time than that stream's already-elevated one, so it wins
//!   the very next release -- zero intervening background grants, not
//!   "however deep the background queue happens to be." See
//!   `interactive_request_is_not_queued_behind_a_sustained_background_stream`.
//! - **A class that has already run sits at (or decays toward) that same
//!   floor once it goes idle -- it does not stay parked at its own
//!   already-elevated virtual time forever.** Charging is grant-count-based,
//!   not wall-clock-based (this module has no clock of its own -- see the
//!   preceding paragraph on why), so "idle" here means two things at once,
//!   both required: *(a)* at least one grant to some other class has
//!   happened since this class was last charged, and *(b)* this class
//!   currently has no pending waiter of its own. `(b)` is load-bearing on
//!   its own, not a restatement of `(a)`: a class can be continuously
//!   backlogged -- always holding a queued waiter -- while still losing
//!   every race to higher-weight contenders for many consecutive releases,
//!   which satisfies `(a)` on every single one of those releases even
//!   though the class never stopped competing. Checking only `(a)` (as an
//!   earlier version of this code did) forgives a still-backlogged class's
//!   debt the moment *any* other class wins once, which defeats the
//!   cost-weighted budget for exactly the large-cost, still-queued stream
//!   this fairness ledger exists to bound -- see
//!   `a_continuously_backlogged_class_does_not_get_its_debt_forgiven_mid_cycle`.
//!   Only when both hold does every charge sweep the class and clamp its
//!   virtual time down to at most [`WorkClassQueue::debt_forgiveness_bound`]
//!   (one minimum-cost grant's worth of virtual time for this queue's
//!   least-weighted configured class) above the shared floor. A class that
//!   is *continuously* contending -- always has a waiter queued -- is never
//!   swept, so its true cost-proportional debt for an already-in-flight
//!   stream of large-cost items is untouched; only a class that has
//!   genuinely stopped asking for the resource has its historical debt
//!   bounded. This does **not** restore the zero-intervening-grants
//!   property above for a previously-charged class: it bounds how far
//!   behind an idle class's stale virtual time can leave it to at most one
//!   more grant of whatever the fastest-accumulating contender is (exactly
//!   one, when that contender is itself the least-weighted class charging
//!   minimum cost -- the scenario this exists for), not zero. See
//!   `previously_charged_interactive_class_does_not_stay_behind_a_sustained_background_stream`.
//!   The bound is a fixed ceiling, not a reset to zero: a class that goes
//!   idle can never end up *below* the shared floor from this, so idle time
//!   never banks a class credit toward jumping ahead of a fresh arrival --
//!   only ever forgives debt down to a small positive constant above where
//!   a fresh arrival already sits.
//! - **This module proves two distinct kinds of anti-starvation, and
//!   forgiveness must not blur them.** The properties above and below are
//!   about *grant-count* starvation -- every class eventually wins some
//!   admission, at a rate bounded below by a positive constant -- which
//!   does follow from virtual time only ever being lowered (never raised
//!   beyond a class's own true charges) toward the shared floor. That is
//!   not the same claim as *cost/service-time* fairness -- that a class's
//!   total granted cost over time stays within its weighted share. A class
//!   that wins grants often enough to avoid grant-count starvation can
//!   still take far more service time than its weight allows if its
//!   accumulated cost-debt gets wiped out while it is still the one asking
//!   for the resource; that is precisely the failure the waiter-emptiness
//!   condition above closes. Forgiving only classes with no pending waiter
//!   keeps the grant-count guarantee (an idle class's stale debt cannot
//!   permanently exile it once it returns) without granting free
//!   service-time credit to a class that never left.
//! - **When every class is simultaneously and continuously backlogged**
//!   (the genuine worst case: nobody is ever idle), grants converge to each
//!   class's weight share of the total (`weight_i / sum(weights)`), so the
//!   lowest class's throughput is bounded below by a positive constant, not
//!   zero, however long the higher classes stay busy. See
//!   `lowest_class_keeps_making_progress_under_sustained_higher_class_load`.
//!
//! # What a budget bounds
//!
//! `max_active` bounds **concurrency** (how many admitted items may be
//! in flight on this resource at once), not bytes or wall time -- the right
//! quantity for the resources design §15.1 lists (SQLite writer turns,
//! hashing worker slots, file descriptors, disk-write slots: all naturally
//! concurrency-bounded, not byte-rate-bounded; byte/sec throughput is
//! already [`crate::rate_limiter::TokenBucket`]'s separate job and composes
//! independently with this one). A large-file classification and a small
//! metadata update both consume exactly one admission slot each -- but they
//! are *not* comparable by count for fairness purposes, so `acquire` also
//! takes a caller-supplied `cost` (bytes, an estimated-duration proxy, or
//! any consistent unit) that feeds *only* the virtual-time fairness ledger,
//! never the admission gate itself. A class that keeps winning slots with
//! large-cost items cedes proportionally more future turns to the other
//! classes than one that wins the same slot count with small-cost items --
//! this is exactly how count-based admission avoids being gamed by a class
//! that floods many tiny requests (each cheap virtual-time charge) while
//! still weighting fairness by the true cost when cost varies.
//!
//! # Preemption
//!
//! **None.** This primitive only ever prevents a background item from
//! *starting* when the budget is exhausted; it never interrupts one already
//! admitted. That is a deliberate correctness constraint, not just a
//! scheduling simplification: design §11.2's single-pass classification
//! produces one signed, complete result from one pass over an object's
//! bytes, and a partially-completed classification is not a usable partial
//! result -- there is no valid "resume from 60%" state, only "discard and
//! reclassify from the start." Interrupting mid-item would therefore cost
//! strictly more total work (the interrupted attempt's bytes are wasted)
//! than letting it finish, and would need this primitive to understand
//! classification-specific resumability it has no business knowing about.
//! The cost of not preempting is bounded by `max_active`: at most
//! `max_active` already-admitted lower-class items can be "in the way" of a
//! newly arriving interactive request, and (per the virtual-time argument
//! above) none of them get to start a *second* item ahead of it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

/// Design §15.1's six work classes, declared in this module's own priority
/// order (lowest variant discriminant = highest default weight). See this
/// module's own doc comment for what falls in each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkClass {
    InteractiveLocalPreservation,
    ApplicationRequestedHydration,
    CanonicalRemoteMaterialization,
    RepairAndRestore,
    RetainedPreimageClassification,
    RetirementCompactionCleanup,
}

/// Total number of [`WorkClass`] variants -- the fixed array width every
/// per-class table in this module uses instead of a `HashMap`, since the
/// class set is closed and small.
const NUM_CLASSES: usize = 6;

impl WorkClass {
    /// Every class, in this module's declared priority order. Used to
    /// derive default weights and to iterate all classes without repeating
    /// the list.
    pub const ALL: [WorkClass; NUM_CLASSES] = [
        WorkClass::InteractiveLocalPreservation,
        WorkClass::ApplicationRequestedHydration,
        WorkClass::CanonicalRemoteMaterialization,
        WorkClass::RepairAndRestore,
        WorkClass::RetainedPreimageClassification,
        WorkClass::RetirementCompactionCleanup,
    ];

    fn index(self) -> usize {
        match self {
            WorkClass::InteractiveLocalPreservation => 0,
            WorkClass::ApplicationRequestedHydration => 1,
            WorkClass::CanonicalRemoteMaterialization => 2,
            WorkClass::RepairAndRestore => 3,
            WorkClass::RetainedPreimageClassification => 4,
            WorkClass::RetirementCompactionCleanup => 5,
        }
    }

    /// Default relative weight: each class one power of two below the one
    /// above it, so under simultaneous sustained backlog in every class,
    /// higher classes get a materially larger share while the lowest class
    /// (weight 1 of a total 63) still converges to a positive, nonzero
    /// share rather than zero. Tunable per resource via
    /// [`WorkClassQueue::with_weights`] -- these are a reasonable default,
    /// not a load-bearing constant.
    fn default_weight(self) -> u64 {
        1 << (NUM_CLASSES - 1 - self.index())
    }
}

struct Waiter {
    id: u64,
    cost: u64,
    tx: tokio::sync::oneshot::Sender<WorkClassGuard>,
}

struct QueueState {
    active: usize,
    /// Per-class cumulative granted cost divided by that class's weight --
    /// this module's doc comment calls it "virtual time". Increases when
    /// charged on a grant to this class; can also be pulled *down* (never
    /// up) by the shared min-rebase or by [`WorkClassQueue::charge_and_rebase`]'s
    /// idle-debt-forgiveness sweep. Admission always favors the pending
    /// class with the smallest entry.
    virtual_time: [f64; NUM_CLASSES],
    /// Total grants made so far across every class, monotonically
    /// increasing. Compared against `last_charged_seq` to tell whether a
    /// class has gone at least one grant without being charged itself --
    /// this module's own notion of "idle", since it has no clock of its
    /// own to measure elapsed real time with.
    release_seq: u64,
    /// `release_seq` as of each class's most recent charge. A class is
    /// "stale" (eligible for debt forgiveness) exactly when its entry here
    /// is behind the current `release_seq`.
    last_charged_seq: [u64; NUM_CLASSES],
    waiters: [VecDeque<Waiter>; NUM_CLASSES],
    waiting: usize,
    next_waiter_id: u64,
}

/// Weighted-fair-queuing admission control for one shared, concurrency-
/// bounded resource across the six design §15.1 work classes. See this
/// module's own doc comment for the fairness argument, budget semantics and
/// preemption decision.
pub struct WorkClassQueue {
    state: StdMutex<QueueState>,
    weights: [u64; NUM_CLASSES],
    max_active: usize,
    /// Snapshot of `state.waiting`, kept outside the mutex for cheap
    /// observability (e.g. a status/metrics call) without contending the
    /// admission path's own lock.
    waiting_snapshot: AtomicU64,
    /// The idle-debt-forgiveness ceiling: one minimum-cost (`cost` of 1)
    /// grant's worth of virtual time for this queue's least-weighted
    /// configured class (`1.0 / weights.min()`). Scales with whatever
    /// weights this queue was actually constructed with rather than a bare
    /// constant, so the bound means the same thing -- "about one grant to
    /// the class that accumulates virtual time fastest" -- under custom
    /// weights too. See this module's own doc comment and
    /// [`WorkClassQueue::charge_and_rebase`].
    debt_forgiveness_bound: f64,
}

impl WorkClassQueue {
    /// A queue with `max_active` concurrency slots and each class's
    /// [`WorkClass::default_weight`].
    pub fn new(max_active: usize) -> Arc<Self> {
        Self::with_weights(max_active, WorkClass::ALL.map(WorkClass::default_weight))
    }

    /// A queue with `max_active` concurrency slots and caller-supplied
    /// per-class weights (indexed by [`WorkClass::index`] order, i.e.
    /// [`WorkClass::ALL`]'s order). Every weight must be nonzero -- a
    /// zero-weight class would divide by zero on its very first grant.
    pub fn with_weights(max_active: usize, weights: [u64; NUM_CLASSES]) -> Arc<Self> {
        assert!(weights.iter().all(|&w| w > 0), "every work-class weight must be nonzero");
        let debt_forgiveness_bound = 1.0 / *weights.iter().min().expect("NUM_CLASSES > 0") as f64;
        Arc::new(Self {
            state: StdMutex::new(QueueState {
                active: 0,
                virtual_time: [0.0; NUM_CLASSES],
                release_seq: 0,
                last_charged_seq: [0; NUM_CLASSES],
                waiters: std::array::from_fn(|_| VecDeque::new()),
                waiting: 0,
                next_waiter_id: 0,
            }),
            weights,
            max_active,
            waiting_snapshot: AtomicU64::new(0),
            debt_forgiveness_bound,
        })
    }

    /// Waits for an admission slot for `class`'s `cost`-weighted turn.
    /// Returns immediately (no queueing) while fewer than `max_active`
    /// items are in flight; otherwise queues behind this class's own prior
    /// waiters (FIFO within a class) and is granted the earliest release
    /// for which this class holds the globally lowest virtual time among
    /// classes with a pending waiter -- see this module's own doc comment.
    ///
    /// `cost` feeds only the fairness ledger (see "What a budget bounds"
    /// above), never the admission gate; `0` is treated as `1` so a caller
    /// that genuinely has no cost estimate still participates in fairness
    /// rather than acquiring free turns.
    ///
    /// Cancel-safe: if this future is dropped at any point after a slot is
    /// granted (including after the grant raced ahead of this future being
    /// polled again), the already-constructed [`WorkClassGuard`] is dropped
    /// along with it and releases the slot exactly as a normal completion
    /// would -- never leaked. While still queued (not yet granted),
    /// dropping this future removes the waiter immediately (see
    /// [`WaiterCancelGuard`]) rather than leaving a dead entry for a later
    /// release to discover.
    pub async fn acquire(self: &Arc<Self>, class: WorkClass, cost: u64) -> WorkClassGuard {
        let idx = class.index();
        let cost = cost.max(1);
        let (id, rx) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.active < self.max_active {
                state.active += 1;
                self.charge_and_rebase(&mut state, idx, cost);
                return WorkClassGuard { queue: self.clone(), class };
            }
            let id = state.next_waiter_id;
            state.next_waiter_id += 1;
            let (tx, rx) = tokio::sync::oneshot::channel();
            state.waiters[idx].push_back(Waiter { id, cost, tx });
            state.waiting += 1;
            self.waiting_snapshot.store(state.waiting as u64, Ordering::Relaxed);
            (id, rx)
        };
        let _cancel_guard = WaiterCancelGuard { queue: self, idx, id };
        rx.await.expect("oneshot sender never dropped without sending a guard")
    }

    fn charge_and_rebase(&self, state: &mut QueueState, idx: usize, cost: u64) {
        state.virtual_time[idx] += cost as f64 / self.weights[idx] as f64;
        state.release_seq += 1;
        state.last_charged_seq[idx] = state.release_seq;

        // Rebase every class down by the current minimum so the values
        // stay bounded across a long-running daemon instead of climbing
        // forever -- purely a numerical-range precaution (relative order,
        // and therefore every admission decision, is unchanged by
        // subtracting the same constant from every entry). Mirrors
        // `block_serve::FairDispatchState::bytes_granted`'s own rebase.
        // This is always followed by the min entry sitting at exactly 0.0
        // -- either it already was (the `if` below is a no-op), or the
        // subtraction puts it there -- which the debt-forgiveness sweep
        // just below relies on.
        if let Some(&min) = state.virtual_time.iter().min_by(|a, b| a.partial_cmp(b).unwrap()) {
            if min > 0.0 {
                for v in state.virtual_time.iter_mut() {
                    *v -= min;
                }
            }
        }

        // Idle-debt forgiveness (this module's doc comment has the full
        // argument): a class is eligible only when it is genuinely not
        // competing right now -- it has gone at least one grant without
        // being charged itself *and* currently holds no pending waiter.
        // The waiter check is load-bearing: without it, a class that is
        // continuously backlogged (always has a waiter queued, just losing
        // every race to higher-weight contenders) would have its debt
        // forgiven the instant any other single class won a grant, even
        // though it never stopped asking for the resource -- exactly the
        // cost/service-time starvation the module doc's "two distinct
        // kinds of anti-starvation" bullet warns against. Eligible classes
        // have any virtual time beyond `debt_forgiveness_bound` above the
        // shared floor (0.0, per the invariant just established) forgiven
        // down to that bound, and only ever downward -- never below the
        // floor, so idle time can never bank a class credit toward jumping
        // ahead of a fresh arrival.
        let stale_and_idle: Vec<usize> = (0..NUM_CLASSES)
            .filter(|&i| {
                state.release_seq > state.last_charged_seq[i]
                    && state.waiters[i].is_empty()
                    && state.virtual_time[i] > self.debt_forgiveness_bound
            })
            .collect();
        for i in stale_and_idle {
            state.virtual_time[i] = self.debt_forgiveness_bound;
        }
    }

    fn release_and_admit_next(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active -= 1;
        loop {
            if state.active >= self.max_active {
                break;
            }
            let idx =
                (0..NUM_CLASSES).filter(|&i| !state.waiters[i].is_empty()).min_by(|&a, &b| {
                    state.virtual_time[a].partial_cmp(&state.virtual_time[b]).unwrap()
                });
            let Some(idx) = idx else { break };
            let waiter = state.waiters[idx].pop_front().expect("idx filtered on non-empty");
            state.waiting -= 1;
            state.active += 1;
            self.charge_and_rebase(&mut state, idx, waiter.cost);
            let guard = WorkClassGuard { queue: self.clone(), class: WorkClass::ALL[idx] };
            match waiter.tx.send(guard) {
                Ok(()) => {}
                Err(guard) => {
                    // The waiter's future was dropped (cancelled) after
                    // this grant was already committed but before it could
                    // be delivered. Suppress its `Drop` (which would try to
                    // re-lock `state` and deadlock -- this loop still holds
                    // it) and undo the grant ourselves, exactly like
                    // `block_serve::FairDispatchQueue::release_and_wake_next`'s
                    // own `Err` arm.
                    std::mem::forget(guard);
                    state.active -= 1;
                }
            }
        }
        self.waiting_snapshot.store(state.waiting as u64, Ordering::Relaxed);
    }

    /// How many items are currently admitted (in flight) on this resource,
    /// across every class.
    pub fn active_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).active
    }

    /// How many items are currently queued (not yet admitted), across every
    /// class. Cheap: reads an atomic snapshot rather than taking the
    /// admission lock.
    pub fn waiting_count(&self) -> usize {
        self.waiting_snapshot.load(Ordering::Relaxed) as usize
    }

    #[cfg(test)]
    fn waiting_count_for_class(&self, class: WorkClass) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).waiters[class.index()].len()
    }

    #[cfg(test)]
    fn virtual_time_for_class(&self, class: WorkClass) -> f64 {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).virtual_time[class.index()]
    }
}

/// Removes waiter `id` from class `idx`'s queue on drop, if it is still
/// there -- armed for the whole time [`WorkClassQueue::acquire`] awaits its
/// oneshot receiver. A no-op once the waiter has actually been granted:
/// `release_and_admit_next` has already popped it out of `waiters` by then,
/// so there is nothing left with this `id` to find. See
/// [`WorkClassQueue::acquire`]'s own doc comment.
struct WaiterCancelGuard<'a> {
    queue: &'a Arc<WorkClassQueue>,
    idx: usize,
    id: u64,
}

impl Drop for WaiterCancelGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap_or_else(|p| p.into_inner());
        let queue = &mut state.waiters[self.idx];
        let Some(pos) = queue.iter().position(|w| w.id == self.id) else { return };
        queue.remove(pos);
        state.waiting -= 1;
        self.queue.waiting_snapshot.store(state.waiting as u64, Ordering::Relaxed);
    }
}

/// An admitted turn on one [`WorkClassQueue`]. Do the admitted work while
/// holding this, then drop it (explicitly or by scope exit) to release the
/// slot and admit the next-fairest waiter, if any. Never interrupts work in
/// progress -- see this module's own "Preemption" doc section; this is a
/// pure admission gate.
pub struct WorkClassGuard {
    queue: Arc<WorkClassQueue>,
    class: WorkClass,
}

impl WorkClassGuard {
    pub fn class(&self) -> WorkClass {
        self.class
    }
}

impl Drop for WorkClassGuard {
    fn drop(&mut self) {
        self.queue.release_and_admit_next();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The class list is exactly design §15.1's six items, in its stated
    /// order -- a regression test on `WorkClass::ALL`/`index` staying in
    /// sync with each other and with the design doc, not just a
    /// restatement of the enum.
    #[test]
    fn class_list_matches_design_section_15_1() {
        let names: Vec<&str> = WorkClass::ALL
            .iter()
            .map(|c| match c {
                WorkClass::InteractiveLocalPreservation => "interactive local preservation",
                WorkClass::ApplicationRequestedHydration => "application-requested hydration",
                WorkClass::CanonicalRemoteMaterialization => "canonical remote materialization",
                WorkClass::RepairAndRestore => "repair and restore",
                WorkClass::RetainedPreimageClassification => {
                    "retained-preimage classification/authoring"
                }
                WorkClass::RetirementCompactionCleanup => "retirement, compaction and cleanup",
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "interactive local preservation",
                "application-requested hydration",
                "canonical remote materialization",
                "repair and restore",
                "retained-preimage classification/authoring",
                "retirement, compaction and cleanup",
            ]
        );
        for (i, c) in WorkClass::ALL.iter().enumerate() {
            assert_eq!(c.index(), i, "WorkClass::ALL order must match WorkClass::index");
        }
    }

    /// Below `max_active`, every class is admitted immediately -- no
    /// fairness machinery engages while the resource is not contended.
    #[tokio::test]
    async fn admits_immediately_below_max_active() {
        let queue = WorkClassQueue::new(4);
        let g1 = queue.acquire(WorkClass::InteractiveLocalPreservation, 1).await;
        let g2 = queue.acquire(WorkClass::RetirementCompactionCleanup, 1_000_000).await;
        assert_eq!(queue.active_count(), 2);
        assert_eq!(queue.waiting_count(), 0);
        drop(g1);
        drop(g2);
        assert_eq!(queue.active_count(), 0);
    }

    /// Core property: a fresh interactive request racing a sustained,
    /// continuously-requeuing background stream in the lowest class is
    /// admitted at the very next release -- zero intervening background
    /// grants -- regardless of how long the background stream has already
    /// been running or how deep its own backlog. This is the literal
    /// "a user waiting for a file they just opened must not queue behind a
    /// background preimage classification of a 40 GB VM image" requirement.
    #[tokio::test(start_paused = true)]
    async fn interactive_request_is_not_queued_behind_a_sustained_background_stream() {
        let queue = WorkClassQueue::new(1);

        // Simulate one huge classification followed immediately by more of
        // the same class's work: hold the single slot, release it, and
        // re-acquire the same class right away, forever, in the
        // background -- exactly the "sustained lower-class demand"
        // scenario the design calls out.
        let bg_queue = queue.clone();
        let bg_grants = Arc::new(AtomicU64::new(0));
        let bg_grants_counter = bg_grants.clone();
        let bg = tokio::spawn(async move {
            loop {
                let g = bg_queue
                    .acquire(WorkClass::RetainedPreimageClassification, 40_000_000_000)
                    .await;
                bg_grants_counter.fetch_add(1, Ordering::SeqCst);
                // Model a real classification actually taking time to run
                // (not an instant loop) so the background task is
                // genuinely holding the slot, not just spinning between
                // two always-ready futures.
                tokio::time::sleep(Duration::from_millis(1)).await;
                drop(g);
                // Yield so the interactive request queued below gets a
                // chance to be observed as waiting before this loop grabs
                // the slot again.
                tokio::task::yield_now().await;
            }
        });

        // Let the background stream run for a while and build up an
        // elevated virtual time before interactive ever asks for anything.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let grants_before = bg_grants.load(Ordering::SeqCst);
        assert!(grants_before > 0, "background stream should have made some progress by now");

        let interactive_grant_order = Arc::new(AtomicU64::new(0));
        let order_marker = interactive_grant_order.clone();
        let bg_grants_at_interactive_grant = bg_grants.clone();
        let interactive_grants_seen = Arc::new(AtomicU64::new(u64::MAX));
        let interactive_grants_seen_writer = interactive_grants_seen.clone();
        let interactive_queue = queue.clone();
        let interactive = tokio::spawn(async move {
            let _g = interactive_queue.acquire(WorkClass::InteractiveLocalPreservation, 1).await;
            order_marker.fetch_add(1, Ordering::SeqCst);
            interactive_grants_seen_writer
                .store(bg_grants_at_interactive_grant.load(Ordering::SeqCst), Ordering::SeqCst);
        });

        tokio::time::timeout(Duration::from_secs(5), interactive)
            .await
            .expect("interactive request must not be starved by the sustained background stream")
            .unwrap();

        let bg_grants_when_interactive_landed = interactive_grants_seen.load(Ordering::SeqCst);
        // At most one additional background grant could have raced ahead
        // between "let it run for a while" and the interactive request
        // being enqueued (it may have arrived mid-hold); the property
        // under test is that the background stream does not get to
        // complete a *second* full turn once interactive is waiting.
        assert!(
            bg_grants_when_interactive_landed <= grants_before + 1,
            "expected interactive to be admitted within at most one intervening background \
             grant (already-in-flight item), got {} background grants before vs {} at the \
             point interactive was granted",
            grants_before,
            bg_grants_when_interactive_landed
        );

        bg.abort();
    }

    /// The property above only ever exercised a class starting at virtual
    /// time zero -- exactly the case where it trivially holds. This is the
    /// regression test for the previously-charged case (this module's own
    /// "Medium" defect this fix addresses): interactive is charged a large
    /// cost once, goes fully idle, and *then* has to race a sustained
    /// lowest-class stream that has been accumulating virtual time from
    /// zero the whole time interactive was idle. Before the
    /// debt-forgiveness sweep in `charge_and_rebase`, interactive's stale
    /// virtual time left it needing the background stream to independently
    /// climb all the way back up to interactive's own charged value before
    /// it could win -- exactly 100 background-only grants for the costs
    /// used below, confirmed by running this scenario against the
    /// pre-fix code. This test drives the two classes deterministically
    /// (no sleeps, no wall clock, no raciness) round by round instead of
    /// relying on a background task outrunning a timer, so the assertion
    /// pins an exact bound rather than a probabilistic one.
    #[tokio::test]
    async fn previously_charged_interactive_class_does_not_stay_behind_a_sustained_background_stream(
    ) {
        let queue = WorkClassQueue::new(1);

        // Charge interactive once for a large cost, then let it go fully
        // idle -- this is the "already been charged" precondition the
        // superseded property never covered.
        drop(queue.acquire(WorkClass::InteractiveLocalPreservation, 3200).await);
        assert_eq!(queue.active_count(), 0);
        assert_eq!(queue.waiting_count(), 0);

        // The lowest class grabs the only slot and, from here on, always
        // has a fresh waiter of its own queued the instant the slot frees
        // -- the "sustained, continuously-requeuing" stream.
        let mut held = queue.acquire(WorkClass::RetirementCompactionCleanup, 1).await;

        let interactive_queue = queue.clone();
        let interactive = tokio::spawn(async move {
            interactive_queue.acquire(WorkClass::InteractiveLocalPreservation, 1).await
        });
        while queue.waiting_count_for_class(WorkClass::InteractiveLocalPreservation) == 0 {
            tokio::task::yield_now().await;
        }

        // Round-trip background grants one at a time: queue the next
        // background waiter, release the currently-held slot (letting
        // `release_and_admit_next` pick whichever of the two waiters has
        // the lower virtual time), and check whether interactive won yet.
        let mut background_only_rounds = 0u32;
        loop {
            let next_bg_queue = queue.clone();
            let next_bg = tokio::spawn(async move {
                next_bg_queue.acquire(WorkClass::RetirementCompactionCleanup, 1).await
            });
            while queue.waiting_count_for_class(WorkClass::RetirementCompactionCleanup) == 0 {
                tokio::task::yield_now().await;
            }
            drop(held);
            background_only_rounds += 1;
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            if interactive.is_finished() {
                next_bg.abort();
                break;
            }
            held = tokio::time::timeout(Duration::from_secs(2), next_bg)
                .await
                .expect("background round must still be granted while interactive waits")
                .unwrap();
            assert!(
                background_only_rounds <= 10,
                "interactive must not need more than a small constant number of intervening \
                 background grants regardless of its own historical virtual time; still waiting \
                 after {background_only_rounds} background-only rounds"
            );
        }
        interactive.await.unwrap();

        // The exact bound this fix guarantees: at most one more grant to
        // whichever class is currently accumulating virtual time fastest
        // (here, the lowest class itself, charging minimum cost) once
        // interactive's stale debt has been forgiven down to
        // `debt_forgiveness_bound`. Before the fix this was 100, not <= 2.
        assert!(
            background_only_rounds <= 2,
            "expected interactive's stale virtual time to be forgiven within one background \
             grant of arriving, took {background_only_rounds} background-only rounds"
        );
    }

    /// Regression test for the Medium debt-forgiveness defect: a class that
    /// is *continuously* backlogged (always has a pending waiter of its
    /// own) must not have its accumulated cost-debt wiped out just because
    /// some other class won a single intervening grant. Before the fix,
    /// eligibility for forgiveness was judged purely by "has any other
    /// class won since I was last charged" -- true on every single grant to
    /// a faster-accumulating class, even for a class that never stopped
    /// asking for the resource -- so a backlogged large-cost class had its
    /// debt clamped down to the forgiveness bound release after release,
    /// letting it re-win far sooner than its true cost entitles. This test
    /// drives the two classes deterministically (no sleeps, no wall clock)
    /// and asserts the backlogged class's virtual time is bit-for-bit
    /// unchanged across several intervening grants to a cheap class.
    #[tokio::test]
    async fn a_continuously_backlogged_class_does_not_get_its_debt_forgiven_mid_cycle() {
        let queue = WorkClassQueue::new(1);

        // The lowest-weight class wins one huge-cost grant, immediately
        // admitted since the slot is free.
        let big = queue.acquire(WorkClass::RetirementCompactionCleanup, 1000).await;
        let expected_big_vt =
            1000.0 / WorkClass::RetirementCompactionCleanup.default_weight() as f64;
        assert_eq!(
            queue.virtual_time_for_class(WorkClass::RetirementCompactionCleanup),
            expected_big_vt
        );

        // Before releasing, queue the lowest class's *next* request -- it
        // must stay backlogged (a pending waiter of its own) through every
        // round below, never going idle.
        let q_big = queue.clone();
        let big_waiter = tokio::spawn(async move {
            q_big.acquire(WorkClass::RetirementCompactionCleanup, 1000).await
        });
        while queue.waiting_count_for_class(WorkClass::RetirementCompactionCleanup) == 0 {
            tokio::task::yield_now().await;
        }

        let mut held = big;
        for round in 0..5 {
            // A cheap, fast-accumulating interactive request races the
            // backlogged lowest class for the single slot and, by virtual
            // time, always wins -- its own virtual time stays far below
            // the lowest class's 1000-cost debt across these few rounds.
            let q_small = queue.clone();
            let small = tokio::spawn(async move {
                q_small.acquire(WorkClass::InteractiveLocalPreservation, 1).await
            });
            while queue.waiting_count_for_class(WorkClass::InteractiveLocalPreservation) == 0 {
                tokio::task::yield_now().await;
            }
            drop(held);
            held = tokio::time::timeout(Duration::from_secs(2), small)
                .await
                .expect("the cheap class's grant must not be blocked by the backlogged class")
                .unwrap();
            assert_eq!(
                held.class(),
                WorkClass::InteractiveLocalPreservation,
                "round {round}: the cheap class must keep winning while the backlogged class's \
                 own huge debt is untouched"
            );

            // The backlogged class's virtual time must be exactly
            // unchanged by this intervening grant -- not forgiven --
            // because it never stopped holding a pending waiter of its
            // own.
            assert_eq!(
                queue.virtual_time_for_class(WorkClass::RetirementCompactionCleanup),
                expected_big_vt,
                "round {round}: a continuously backlogged class's debt must not be forgiven by \
                 an intervening grant to another class"
            );
            assert_eq!(
                queue.waiting_count_for_class(WorkClass::RetirementCompactionCleanup),
                1,
                "round {round}: the backlogged class must still have its own pending waiter \
                 throughout"
            );
        }

        // Once the cheap class stops contending, the backlogged class
        // finally gets its turn -- it was never starved outright, only
        // correctly made to pay its real debt first.
        drop(held);
        let finished_big = tokio::time::timeout(Duration::from_secs(2), big_waiter)
            .await
            .expect("the backlogged class must eventually be admitted once nothing outraces it")
            .unwrap();
        assert_eq!(finished_big.class(), WorkClass::RetirementCompactionCleanup);
    }

    /// Worst case: every class, including the lowest, is simultaneously
    /// and continuously backlogged (nobody is ever idle). Even then the
    /// lowest class's share of total grants converges to its weight's
    /// fraction of the total -- a positive constant, not zero -- so
    /// sustained higher-class load can slow it down but never starves it
    /// out entirely, satisfying design §22.2's "background custody,
    /// compaction and cleanup cannot starve interactive hydration or
    /// canonical materialization" from the other direction: interactive
    /// load must not starve the lowest class either, or retained
    /// obligations queued behind it would accumulate forever (design §16).
    #[tokio::test]
    async fn lowest_class_keeps_making_progress_under_sustained_higher_class_load() {
        let queue = WorkClassQueue::new(1);
        let total_weight: u64 = WorkClass::ALL.iter().map(|c| c.default_weight()).sum();
        let grant_counts: Arc<[AtomicU64; NUM_CLASSES]> =
            Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));

        const GRANTS_PER_CLASS_TARGET: u64 = 400;
        let total_target = GRANTS_PER_CLASS_TARGET * NUM_CLASSES as u64;

        let mut tasks = Vec::new();
        for class in WorkClass::ALL {
            let queue = queue.clone();
            let counts = grant_counts.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    if counts.iter().map(|c| c.load(Ordering::SeqCst)).sum::<u64>() >= total_target
                    {
                        return;
                    }
                    let g = queue.acquire(class, 1).await;
                    counts[class.index()].fetch_add(1, Ordering::SeqCst);
                    drop(g);
                    tokio::task::yield_now().await;
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }

        let lowest = WorkClass::RetirementCompactionCleanup;
        let lowest_count = grant_counts[lowest.index()].load(Ordering::SeqCst);
        let total_granted: u64 = grant_counts.iter().map(|c| c.load(Ordering::SeqCst)).sum();
        let expected_share =
            lowest.default_weight() as f64 / total_weight as f64 * total_granted as f64;

        assert!(lowest_count > 0, "lowest class must make nonzero progress under sustained load");
        // Generous tolerance (half the ideal share either way) -- this is
        // proving "converges to a positive share", not pinning an exact
        // scheduling trace.
        assert!(
            lowest_count as f64 > expected_share * 0.5,
            "lowest class got {lowest_count} of {total_granted} grants, expected roughly \
             {expected_share:.1} ({}% of {total_granted}); starved well below its weight share",
            (lowest.default_weight() as f64 / total_weight as f64) * 100.0
        );
    }

    /// Custom weights are honored: equal weights make two contending
    /// classes converge to roughly equal shares, unlike the skewed
    /// default.
    #[tokio::test]
    async fn custom_weights_change_the_convergent_share() {
        let mut weights = WorkClass::ALL.map(WorkClass::default_weight);
        weights[WorkClass::InteractiveLocalPreservation.index()] = 1;
        weights[WorkClass::RetirementCompactionCleanup.index()] = 1;
        let queue = WorkClassQueue::with_weights(1, weights);

        let a_count = Arc::new(AtomicU64::new(0));
        let b_count = Arc::new(AtomicU64::new(0));
        const TARGET: u64 = 300;

        let qa = queue.clone();
        let ca = a_count.clone();
        let a = tokio::spawn(async move {
            while ca.load(Ordering::SeqCst) < TARGET {
                let g = qa.acquire(WorkClass::InteractiveLocalPreservation, 1).await;
                ca.fetch_add(1, Ordering::SeqCst);
                drop(g);
                tokio::task::yield_now().await;
            }
        });
        let qb = queue.clone();
        let cb = b_count.clone();
        let b = tokio::spawn(async move {
            while cb.load(Ordering::SeqCst) < TARGET {
                let g = qb.acquire(WorkClass::RetirementCompactionCleanup, 1).await;
                cb.fetch_add(1, Ordering::SeqCst);
                drop(g);
                tokio::task::yield_now().await;
            }
        });
        let _ = tokio::join!(a, b);

        let a = a_count.load(Ordering::SeqCst) as f64;
        let b = b_count.load(Ordering::SeqCst) as f64;
        let ratio = a / b;
        assert!(
            (0.6..1.7).contains(&ratio),
            "equal weights should converge to roughly equal shares, got a={a} b={b} ratio={ratio}"
        );
    }

    /// `cost` affects only the fairness ledger, never the admission gate:
    /// a single request far larger than any prior grant is still admitted
    /// as soon as a slot is free, never blocked on its own size.
    #[tokio::test]
    async fn large_cost_does_not_block_admission_when_a_slot_is_free() {
        let queue = WorkClassQueue::new(1);
        let g = tokio::time::timeout(
            Duration::from_secs(2),
            queue.acquire(WorkClass::RetainedPreimageClassification, 40_000_000_000),
        )
        .await
        .expect("a large cost must not itself block admission when the slot is free");
        assert_eq!(g.class(), WorkClass::RetainedPreimageClassification);
    }

    /// Dropping a still-queued acquire future (e.g. the caller's own
    /// `tokio::time::timeout` elapsing) removes it from the waiter list
    /// immediately rather than leaving a dead entry, and never leaks the
    /// `waiting` count.
    #[tokio::test(start_paused = true)]
    async fn cancelling_a_queued_acquire_removes_it_immediately() {
        let queue = WorkClassQueue::new(1);
        let _held = queue.acquire(WorkClass::InteractiveLocalPreservation, 1).await;

        let q2 = queue.clone();
        let waiter =
            tokio::spawn(
                async move { q2.acquire(WorkClass::RetirementCompactionCleanup, 1).await },
            );
        // Give the waiter a chance to actually queue.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(queue.waiting_count_for_class(WorkClass::RetirementCompactionCleanup), 1);

        waiter.abort();
        // Give the abort's drop glue a chance to run.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(queue.waiting_count_for_class(WorkClass::RetirementCompactionCleanup), 0);
        assert_eq!(queue.waiting_count(), 0);
    }

    /// A guard granted to a waiter whose future was already cancelled by
    /// the time the grant arrived does not leak the admission slot -- the
    /// next waiter (if any) still gets admitted promptly.
    #[tokio::test(start_paused = true)]
    async fn a_grant_racing_a_cancellation_does_not_leak_the_slot() {
        let queue = WorkClassQueue::new(1);
        let held = queue.acquire(WorkClass::InteractiveLocalPreservation, 1).await;

        let q2 = queue.clone();
        let first_waiter =
            tokio::spawn(
                async move { q2.acquire(WorkClass::RetirementCompactionCleanup, 1).await },
            );
        tokio::time::sleep(Duration::from_millis(20)).await;

        let q3 = queue.clone();
        let second_waiter =
            tokio::spawn(async move { q3.acquire(WorkClass::RepairAndRestore, 1).await });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Release the held slot and, in the same instant, abort the first
        // waiter -- either can win the race with the release's internal
        // grant, exercising the `Err` (cancelled-before-delivery) arm of
        // `release_and_admit_next` at least some of the time across
        // repeated runs.
        drop(held);
        first_waiter.abort();

        let second = tokio::time::timeout(Duration::from_secs(2), second_waiter)
            .await
            .expect("the second waiter must still be admitted, not stuck behind a leaked slot")
            .unwrap();
        assert_eq!(second.class(), WorkClass::RepairAndRestore);
    }
}
