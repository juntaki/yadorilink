//! The Convergence Engine's scheduler loop: claims every currently-runnable
//! `projection_obligations` row (bumped by DAG admission — `dag_store::
//! admit_change`/`admit_prepared_emission` — not enqueued by `PeerSyncSession
//! ::handle_change_batch`, which no longer schedules anything at all) and
//! drives them to completion on its own schedule, using the SAME
//! `reconcile_local_materialization_audit` / `reconcile_group_paths` /
//! `materialize` machinery this codebase already had and already tests --
//! this engine only changes *when*, *from where*, and *off which claim
//! source* that machinery runs, not what it does internally.
//!
//! `projection_obligations` has no in-flight state at all: claiming
//! (`dag_claim_runnable_obligations`) is a plain read, never a claim-and-mark
//! transition, so unlike the retired job-table scheduler this needs no
//! stale-active-processing reclaim at startup or on a same-process failure
//! between claim and completion -- there is nothing to go stale in the
//! first place. Completion is one atomic (G, E, durable-proof) decision per
//! path (`complete_one_obligation`/`complete_zero_work_obligation`), and
//! retry/backoff (`dag_mark_obligation_attempt_failed`/`dag_defer_
//! obligation_without_penalty`) is obligation-native, not modeled on a
//! separate job-state machine.
//!
//! Every SQLite call this file makes is synchronous and blocks the calling
//! thread (`yadorilink-sqlite-runtime` has no async surface at all, by
//! design), and several of them are per-path loops over a claimed batch of up
//! to `MAX_JOBS_PER_TICK_PER_GROUP` rows. This is a `spawn_restarting` async
//! task, so every one of them goes through `run_blocking_sweep_offloaded` --
//! the crate's shared `block_in_place`-when-multi-threaded guard -- rather
//! than running on the worker that polls the tick. `pool.rs`'s own contract
//! states the requirement outright: an async caller must do the wrapping on
//! its own side, because the SQLite layer has no runtime to yield to.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};

use yadorilink_peer_session::ports::PeerReplicaStatePort;
use yadorilink_replica_domain::ids::ChangeHash;

use crate::daemon_state::{run_blocking_sweep_offloaded, DaemonState};

use super::backoff::next_backoff;

/// Upper bound on how many jobs a single tick claims — keeps one tick's
/// worth of work bounded even if a large batch just enqueued many paths at
/// once; the rest are picked up on the next tick (which the same
/// `notify_materialization_wake` call that triggered this one leaves armed
/// to fire again immediately, since nothing here waits on the notify before
/// the next unconditional poll).
const MAX_JOBS_PER_TICK: u32 = 256;

/// Per-group share of `MAX_JOBS_PER_TICK` a single claim call will take —
/// without this, a group that keeps admitting many paths could crowd every
/// other group's jobs out of the claim entirely (a real gap an independent
/// review caught: a plain `LIMIT` has no per-group fairness). Deliberately
/// smaller than `MAX_JOBS_PER_TICK` so at least a couple of distinct groups
/// are always represented in one tick's claimed batch, but generous enough
/// (half of `MAX_JOBS_PER_TICK`) to comfortably cover a single heavy
/// group's realistic per-tick job count without throttling its own
/// legitimate churn.
const MAX_JOBS_PER_TICK_PER_GROUP: u32 = 128;

/// Fallback poll interval when no `materialization_wake` fires — the
/// no-better-signal case the design accounts for; the primary path is the
/// event-driven wake fired by `enqueue_pending`'s caller.
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How many groups' audits run concurrently. Without this, `run_once`
/// processing groups one at a time meant one group with many slow, blocked
/// (sole-source-unreachable) attempts could hold up every other group's
/// otherwise-instant materialization for the whole tick — CONV-1 keeps
/// message *intake* unblocked, but the engine itself would still have its
/// own head-of-line blocking across groups without this. Kept small (not
/// unbounded) since each group audit can itself spend real wall-clock time
/// in a block fetch; a handful of groups stalled on unreachable sources
/// should not turn into an unbounded fan-out of blocked network attempts.
const MAX_CONCURRENT_GROUP_AUDITS: usize = 4;

/// Bounded per-attempt path budget — a confirmed, reproduced regression
/// (see `fix/conflict-copy-convergence-obligation-20260723`): handing an
/// entire claimed batch of paths to a single `reconcile_paths_directly`
/// call processes every path's blocks fully serially, and a large backlog
/// of not-yet-referenced/genuinely-missing blocks was measured
/// accumulating into a 40+ second single call with no intermediate
/// progress. Capping how many paths one attempt is asked to resolve, and
/// rotating which bounded subset gets the attempt each tick, bounds a
/// single call's worst case while still giving every path its turn across
/// a few ticks. Shared by `process_group` (the legacy `materialization_
/// jobs` driver) and `process_group_via_obligations`.
const MAX_PATHS_PER_RECONCILE_ATTEMPT: usize = 8;

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Pure rotation math for `process_group`'s peer selection, pulled out so
/// it can be unit-tested directly without a real multi-device harness (an
/// independent review flagged the lack of any dedicated test for the
/// peer-failover fix — a full integration test hit unrelated test-harness
/// complexity and was dropped, but this pure core is cheap to verify in
/// isolation). Returns the candidate indices to try this call, in order,
/// starting at `cursor % candidate_count` and wrapping around, capped at
/// `max_attempts` (or `candidate_count`, whichever is smaller). Returns an
/// empty `Vec` if there are no candidates at all.
fn rotation_indices(candidate_count: usize, cursor: usize, max_attempts: usize) -> Vec<usize> {
    if candidate_count == 0 {
        return Vec::new();
    }
    let start = cursor % candidate_count;
    let attempts = candidate_count.min(max_attempts);
    (0..attempts).map(|offset| (start + offset) % candidate_count).collect()
}

/// `rotation_indices` with an optional origin-first preference: the
/// candidate at `origin` (the peer that authored the changes triggering
/// this tick's budgeted jobs) is tried FIRST — it is the peer most likely
/// to actually hold the block content those jobs need, since every other
/// candidate may have admitted the change history without hydrating the
/// content yet — while the total attempt budget stays exactly
/// `max_attempts`. If the origin already sits inside this tick's rotation
/// window it is moved to the front; otherwise it is prepended and the
/// window's last slot is dropped to make room. The caller must NOT advance
/// the rotation cursor by the raw tried count afterwards — see
/// `process_group`'s cursor-advance comment for the prefix-consumption rule
/// that keeps a rotated-out-but-untried candidate from being skipped.
fn origin_first_indices(
    candidate_count: usize,
    cursor: usize,
    max_attempts: usize,
    origin: Option<usize>,
) -> Vec<usize> {
    let mut indices = rotation_indices(candidate_count, cursor, max_attempts);
    let Some(origin) = origin else { return indices };
    if origin >= candidate_count || max_attempts == 0 {
        return indices;
    }
    match indices.iter().position(|&i| i == origin) {
        Some(pos) => {
            indices.remove(pos);
        }
        None => {
            // Not in the window — make room so the budget is unchanged.
            indices.pop();
        }
    }
    indices.insert(0, origin);
    indices
}

/// The author preferred as this tick's fetch origin: the device that
/// authored the largest share of the budgeted jobs' triggering changes
/// (deterministic tie-break: lexicographically smallest device id).
/// `None` when no author can be determined at all.
fn majority_author(authors: impl IntoIterator<Item = String>) -> Option<String> {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for author in authors {
        *tally.entry(author).or_default() += 1;
    }
    tally.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(author, _)| author)
}

/// Resolves the origin-first fetch preference from the CURRENT desired-state
/// winner rather than a stored triggering change: `ClaimedObligation` carries
/// no `version_hash` at all (by
/// design -- desired state is always recomputed fresh, never carried from
/// claim time), so there is no historical "which change created this
/// obligation" to look up even heuristically. An obligation represents
/// current desired state, not "what invalidated it first," so deriving the
/// fetch-source preference from the path's current resolved winner is the
/// more accurate source anyway, not merely a workaround for the missing
/// field: `resolve_path_heads`'s own winner is exactly the author whose
/// content this attempt is actually trying to materialize, correct even
/// across a divergent-branch/conflict-copy resolution where "the change
/// that first bumped the obligation's generation" could name a losing
/// branch's author instead. `session` only needs to be ABLE to resolve DAG
/// state (`diagnostic_path_heads`'s own doc comment: "identical result
/// regardless of which peer session it's called through — this reads
/// purely local state"), so the caller may pass whichever session it
/// already has in hand rather than constructing a new one for this alone.
fn origin_candidate_index_for_obligations<S>(
    session: &yadorilink_peer_session::peer_session::PeerSyncSession,
    group_id: &str,
    budget: &BTreeSet<String>,
    candidates: &[(String, S)],
) -> Option<usize> {
    let authors = budget.iter().filter_map(|path| {
        let heads = session.diagnostic_path_heads(group_id, path).ok()?;
        match yadorilink_replica_engine::conflict::resolve_path_heads(path, &heads) {
            yadorilink_replica_engine::conflict::PathResolution::Present { winner, .. } => {
                heads.get(winner).map(|head| head.device_id.clone())
            }
            yadorilink_replica_engine::conflict::PathResolution::Absent => None,
        }
    });
    let author = majority_author(authors)?;
    candidates.iter().position(|(device_id, _)| *device_id == author)
}

/// Runs the Convergence Engine's scheduler loop forever. Intended to be
/// spawned via `supervise::spawn_restarting` (never `spawn_logged`) — unlike
/// `DaemonState`'s other periodic tasks, a silent stop here does not just
/// skip one sweep, it stops all materialization for every group for the
/// rest of the daemon's life, which is a strictly worse failure mode.
///
/// No startup recovery step runs before the loop starts: `run_once`'s claim
/// (`dag_claim_runnable_obligations`) is a plain read, never a claim-and-mark
/// transition, so there is no in-flight state a crash could leave stale for
/// this to reclaim in the first place.
pub async fn run(state: Arc<DaemonState>) {
    // Diagnostic-only tick counter, for the
    // `fix/conflict-copy-convergence-obligation-20260723` investigation --
    // proves directly whether this loop is still iterating at all (as
    // opposed to inferring it from whether `run_once` happened to find any
    // claimable work) and which branch woke it each time.
    let mut tick: u64 = 0;
    loop {
        let outcome = run_once(&state).await;
        tick += 1;
        // Work-conserving: an immediately-runnable backlog must not wait
        // out a full tick interval (or however long until the next
        // `Notify`) just because 8 paths already got their turn this
        // tick. `MaterializationWake` is a coarse "something changed"
        // signal, not a work-count -- draining is decided here, from
        // `run_once`'s own aggregated outcome, not from that signal.
        // `yield_now` (not a bare `continue`, and never a sleep) hands
        // the executor a chance to run other ready tasks between ticks
        // without giving up this loop's own turn for any real duration,
        // so a large healthy backlog drains as fast as each tick's own
        // real work allows, not throttled by an unrelated fixed interval.
        if outcome.immediate_backlog {
            tracing::debug!(
                local_device_id = %state.device_id,
                tick,
                "engine loop draining an immediate backlog without waiting"
            );
            tokio::task::yield_now().await;
            continue;
        }
        tracing::debug!(local_device_id = %state.device_id, tick, "engine loop about to wait for next wake");
        tokio::select! {
            _ = state.replica_coordinator.materialization_wake().materialization_wake_notified() => {
                tracing::debug!(local_device_id = %state.device_id, tick, "engine loop woken by wake_notified");
            }
            _ = tokio::time::sleep(FALLBACK_POLL_INTERVAL) => {
                tracing::debug!(local_device_id = %state.device_id, tick, "engine loop woken by fallback poll");
            }
        }
    }
}

/// Whether `run`'s own scheduler loop should immediately drive another
/// `run_once` tick instead of sleeping/waiting on the wake `Notify` --
/// see `run`'s own doc comment for why "8 processed, sleep regardless of
/// what's left" was a real work-conserving-scheduler bug, not merely a
/// throughput tuning question.
struct RunOnceOutcome {
    immediate_backlog: bool,
}

/// One scheduler tick: claims every currently-runnable `projection_
/// obligations` row, groups by `group_id`, and drives up to
/// `MAX_CONCURRENT_GROUP_AUDITS` groups' worth of `process_group_via_
/// obligations` concurrently — one stalled group (e.g. every path waiting
/// on an unreachable sole source) must not hold up another group whose
/// obligations could complete instantly. This is the Phase C cutover
/// itself: `projection_obligations` is the live claim source, not
/// `materialization_jobs` — `process_group`/the legacy job-claim path
/// below are no longer reachable from here, kept only until Phase D
/// removes them outright.
async fn run_once(state: &Arc<DaemonState>) -> RunOnceOutcome {
    // Per-tick timing, kept as a `debug!`-level diagnostic (downgraded
    // 2026-09-01 from an investigation-era `warn!`, which fired on every
    // tick -- too noisy for production `warn!`, but still worth keeping at
    // `debug!` since it distinguishes "run_once is stuck inside an
    // already-started tick" from "ticks keep completing but claim returns
    // zero", the two fundamentally different ways obligations_claimed can
    // freeze for tens of seconds -- exactly the question the decision-9
    // dual-scheduler stall needed answered.
    let c4_attr_run_once_started = std::time::Instant::now();
    let now = now_unix_nanos();
    // One read claiming up to `MAX_JOBS_PER_TICK` rows -- see
    // `claim_runnable_obligations`'s own doc comment for why this needs no
    // stale-active-processing reclaim the way the legacy job claim did:
    // there is no in-flight state here to go stale in the first place.
    let c4_attr_claim_started = std::time::Instant::now();
    let runnable = match run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.sqlite().dag_claim_runnable_obligations(
            now,
            MAX_JOBS_PER_TICK_PER_GROUP,
            MAX_JOBS_PER_TICK,
        )
    }) {
        Ok(obligations) => obligations,
        Err(e) => {
            tracing::warn!(error = %e, "convergence engine failed to claim runnable obligations");
            return RunOnceOutcome { immediate_backlog: false };
        }
    };
    tracing::debug!(
        claim_ms = c4_attr_claim_started.elapsed().as_millis() as u64,
        claimed_count = runnable.len(),
        "C4_ATTR_ENGINE dag_claim_runnable_obligations returned"
    );
    if runnable.is_empty() {
        tracing::debug!(
            run_once_ms = c4_attr_run_once_started.elapsed().as_millis() as u64,
            "C4_ATTR_ENGINE run_once returning (nothing runnable)"
        );
        return RunOnceOutcome { immediate_backlog: false };
    }
    // This tick's claim itself hit the global cap -- there may be MORE
    // runnable obligations this call never even fetched, regardless of how
    // any individual group's own attempt turns out. `process_group_via_
    // obligations`'s own `deferred_runnable` only ever reasons about the
    // batch it was actually handed, so this is the one signal that has to
    // be captured at this level instead.
    let claim_hit_cap = runnable.len() as u32 >= MAX_JOBS_PER_TICK;

    let mut obligations_by_group: HashMap<
        String,
        Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>,
    > = HashMap::new();
    for obligation in runnable {
        obligations_by_group.entry(obligation.group_id.clone()).or_default().push(obligation);
    }
    // Diagnostic-only: visibility into exactly which (group, path) pairs
    // `claim_runnable_obligations` actually selected this tick -- same
    // reasoning as the legacy claim's own equivalent log line (see the
    // `taguchi_row_14` intermittent-stall investigation this mirrors):
    // without this, a path that silently stops being claimed (rather than
    // being completed/backed-off/deferred) is invisible.
    for (group_id, obligations) in &obligations_by_group {
        tracing::debug!(
            local_device_id = %state.device_id,
            group_id = %group_id,
            claimed_count = obligations.len(),
            claimed_paths = ?obligations.iter().map(|o| o.path.as_str()).collect::<Vec<_>>(),
            "claimed obligations this tick"
        );
    }
    let mut group_ids: Vec<String> = obligations_by_group.keys().cloned().collect();
    group_ids.sort();

    let mut any_group_immediate_backlog = false;
    let mut next_idx = 0usize;
    let mut in_flight = FuturesUnordered::new();
    while next_idx < group_ids.len() && in_flight.len() < MAX_CONCURRENT_GROUP_AUDITS {
        let group_id = group_ids[next_idx].clone();
        let obligations = obligations_by_group.remove(&group_id).unwrap_or_default();
        in_flight.push(process_group_via_obligations(state, group_id, obligations, None, None));
        next_idx += 1;
    }
    while let Some(outcome) = in_flight.next().await {
        if outcome.audit_healthy && outcome.deferred_runnable {
            any_group_immediate_backlog = true;
        }
        if next_idx < group_ids.len() {
            let group_id = group_ids[next_idx].clone();
            let obligations = obligations_by_group.remove(&group_id).unwrap_or_default();
            in_flight.push(process_group_via_obligations(state, group_id, obligations, None, None));
            next_idx += 1;
        }
    }
    tracing::debug!(
        run_once_ms = c4_attr_run_once_started.elapsed().as_millis() as u64,
        "C4_ATTR_ENGINE run_once returning (groups processed)"
    );
    RunOnceOutcome { immediate_backlog: any_group_immediate_backlog || claim_hit_cap }
}

/// Test-only: drives exactly one scheduler tick and reports whether `run`'s
/// own loop would immediately continue draining afterward (see
/// `RunOnceOutcome`'s own doc comment) -- `run_once` itself is private (this
/// whole module is `mod engine_impl`, not reachable from outside
/// `yadorilink-daemon::convergence` at all), so an external integration
/// test needs a minimal seam to drive the scheduler deterministically one
/// tick at a time rather than only through `run`'s own infinite loop. Only
/// the boolean an external caller can actually act on is exposed --
/// `RunOnceOutcome`/`ProcessGroupOutcome` stay private, matching this
/// crate's `test-support` feature's existing "expose the minimum a test
/// needs, not the internals" convention (see `Cargo.toml`'s own doc
/// comment on that feature).
#[cfg(any(test, feature = "test-support"))]
pub async fn run_once_for_test(state: &Arc<DaemonState>) -> bool {
    run_once(state).await.immediate_backlog
}

/// Drives every claimed job in one group to a conclusion: rotating through
/// every currently-connected, group-sharing peer session in round-robin
/// order (a per-group cursor on `DaemonState`, advanced every call — the
/// same shape as the pre-existing `materialization_repair_cursors` rotation,
/// but this engine's own, since the two run on independent schedules)
/// rather than always picking whichever session happens to be first in
/// `candidate_sessions`'s `HashMap` iteration order. A block a peer doesn't
/// have would otherwise be retried against that SAME unhelpful peer
/// indefinitely — `ensure_blocks_present`'s block fetch is scoped to the one
/// session the audit runs through, so which session gets picked directly
/// determines which peer's content is actually reachable this attempt.
///
/// Tries the next candidate only for whatever paths are still outstanding
/// after the previous one's attempt — a `Present`-branch content path is
/// finished the moment ANY candidate's clean audit shows it's no longer
/// unapplied; no need to keep trying further peers for paths already
/// resolved.
/// What one `process_group` call actually accomplished, for `run_once`'s
/// own work-conserving decision (see [`RunOnceOutcome`]): whether this
/// group's own audit mechanism was trustworthy at all this tick, and
/// whether this tick's claim for this group held more runnable jobs than
/// one attempt's budget could cover. Neither field alone answers "should
/// the scheduler keep draining without sleeping":
///
/// - `deferred_runnable` without `audit_healthy` means every candidate
///   this tick was unreachable, or every attempt raced a concurrent
///   admission/guard contention -- a systemic problem a DIFFERENT budget
///   window is unlikely to escape either, so immediately retrying would
///   just burn CPU re-hitting the same failure instead of the same dead
///   *paths* -- falling back to the ordinary wait/retry cadence is safer.
/// - `audit_healthy` without `deferred_runnable` means this group's
///   entire runnable backlog already fit inside this tick's budget --
///   nothing left to immediately drain FOR THIS GROUP (though another
///   group might still have its own backlog), regardless of whether this
///   specific window's content happened to resolve yet.
/// - `audit_healthy` WITH `deferred_runnable` is the case worth calling
///   out explicitly: even if every one of THIS window's budgeted paths
///   individually failed to resolve (still-fetching content, say), the
///   budget cursor always rotates forward regardless of outcome (see its
///   own comment below) -- so the NEXT tick's window is guaranteed to be
///   a genuinely different, not-yet-attempted set of paths, never a
///   repeat of this tick's own failure. Gating immediate continuation on
///   "did THIS window resolve something" (an earlier version of this
///   fix did) reintroduced exactly the bug this fix targets for a mixed
///   backlog: a healthy peer with some content ready and some not yet
///   fetched would sleep a full tick interval before ever reaching the
///   ready paths, just because they happened to land in a later window
///   than an unready one.
struct ProcessGroupOutcome {
    audit_healthy: bool,
    deferred_runnable: bool,
}

/// `RecordKind` -> `MaterializedObjectKind`, for computing the desired-side
/// hash a freshly published exact evidence must be closed against. The same
/// correspondence is already implemented once, inline, in
/// `replica_coordinator::peer_replica_state`'s publish impl (which maps the
/// identical `ExactActualState::Object.kind` to build the write it sends to
/// `path_materialized_generations`); duplicated here rather than exposed as
/// a shared helper because it is a trivial, obviously-correct three-arm
/// match with no room to diverge silently, and a shared export would add a
/// cross-module dependency for a one-line mapping.
fn map_record_kind_for_completion_hash(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind {
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind;
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}

/// A test-only rendezvous letting a deterministic-interleaving test pause
/// a worker at the exact instant it has decided to settle a path --
/// immediately after it has computed everything it needs (the desired
/// hash/evidence, the claimed generation) and immediately before it issues
/// its own publish or completion call -- so the test can interleave an
/// independent mutator's own fence bump in between, then release the
/// worker to observe whether that call correctly fails. Never constructed
/// in production: every call site that consults one takes
/// `Option<&Arc<BeforeCompletionHook>>` and is a no-op when `None`, which
/// is what every non-hooked caller (every live production path, plus the
/// existing `drive_obligations_once_for_test`) passes. Not itself
/// `cfg`-gated (unlike most of this module's obligation-driven-worker
/// code): `process_group` -- the always-live scheduler -- also accepts one
/// via `process_group_with_hooks`, so the type must be nameable in a plain
/// production build even though nothing in production ever builds one.
///
/// A bare `Notify` is not enough here: signaling "I'm parked" and "you may
/// proceed" are two independent directions, and a single `Notify` cannot
/// represent both without a race between the worker's own wait and the
/// test's own notify potentially landing before the worker starts
/// listening. Two `Notify`s give each direction its own, order-independent
/// signal.
pub struct BeforeCompletionHook {
    parked: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
}

/// Test-only rendezvous, kept as permanent regression-test infrastructure
/// for `unrelated_path_head_movement_must_not_discard_an_already_settled_
/// attempt` (the heads-stability-fence removal this hook was built to
/// pin -- that fence is gone from production code, but this hook is what
/// lets the regression test park a candidate attempt at the exact window
/// the old fence used to gate, so the test keeps proving the fence stays
/// gone). Same rendezvous shape as [`BeforeCompletionHook`], but for the OTHER,
/// earlier pause point `process_group_via_obligations` has -- immediately
/// after one candidate's `reconcile_paths_directly` attempt has resolved
/// (desired state/evidence computed for every claimed path in that
/// attempt), and immediately before the group's `dag_group_heads` is
/// re-read to decide `before == after`. `BeforeCompletionHook` cannot reach
/// this window: it only pauses once `before == after` has ALREADY been
/// checked and passed, so it can never let a test interleave a change
/// admission that the heads-stability fence itself should observe. Never
/// constructed in production, same as `BeforeCompletionHook`.
pub struct BeforeHeadsAfterHook {
    parked: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
}

impl BeforeHeadsAfterHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { parked: tokio::sync::Notify::new(), proceed: tokio::sync::Notify::new() })
    }

    async fn pause(&self) {
        self.parked.notify_one();
        self.proceed.notified().await;
    }

    pub async fn wait_parked(&self) {
        self.parked.notified().await;
    }

    pub fn resume(&self) {
        self.proceed.notify_one();
    }
}

impl BeforeCompletionHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { parked: tokio::sync::Notify::new(), proceed: tokio::sync::Notify::new() })
    }

    /// Called from inside the worker, immediately before it issues its
    /// completion CAS: announces that it has parked, then waits for the
    /// test to call [`Self::resume`].
    async fn pause(&self) {
        self.parked.notify_one();
        self.proceed.notified().await;
    }

    /// Called from the test: blocks until the worker has actually reached
    /// its `pause()` call (not merely until the worker task was spawned),
    /// so the test's own subsequent fence bump is guaranteed to land while
    /// the worker is genuinely parked, never before it gets there.
    pub async fn wait_parked(&self) {
        self.parked.notified().await;
    }

    /// Called from the test, after its own interleaved mutation has
    /// committed: releases the parked worker to proceed to its completion
    /// CAS.
    pub fn resume(&self) {
        self.proceed.notify_one();
    }
}

/// Closes one path's claimed obligation against the evidence
/// `reconcile_paths_directly` just settled it with, publishing first for an
/// exact outcome (reusing the identical publish call `process_group`'s own
/// CONV-7 arm makes) and using the exact-outcome or non-exact-outcome
/// compound completion as appropriate. Any failure at any step (a lost
/// publish CAS race, a publish error, a lost completion CAS race) simply
/// leaves the obligation outstanding for a later claim to re-resolve from
/// scratch — never treated as this path's final word: a rejected
/// publication must not close its obligation.
async fn complete_one_obligation(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    claimed_generation: i64,
    claimed_incarnation: i64,
    evidence: &yadorilink_peer_session::peer_session::SettlementEvidence,
    causal_basis: &[ChangeHash],
    hooks: Option<&Arc<BeforeCompletionHook>>,
) {
    use yadorilink_peer_session::peer_session::SettlementEvidence;
    use yadorilink_peer_session::ports::ExactActualState;
    use yadorilink_sync_sqlite::materialized_generation::{
        compute_resolved_path_state_hash, MaterializedObjectKind,
    };
    use yadorilink_sync_sqlite::projection_obligations::NonExactProofKind;

    if let Some((exact_state, expected_mutation_generation)) = evidence.as_exact_actual_state() {
        let group_id_owned = group_id.to_string();
        let path_owned = path.to_string();
        let causal_basis_owned = causal_basis.to_vec();
        let exact_state_for_publish = exact_state.clone();
        let published = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.dag_publish_materialized_generation_if_fence_current(
                &group_id_owned,
                &path_owned,
                &causal_basis_owned,
                exact_state_for_publish,
                expected_mutation_generation,
            )
        });
        match published {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven publish CAS lost the race; leaving obligation outstanding \
                     for re-resolution"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    group_id,
                    path,
                    error = %e,
                    "obligation-driven publish failed; leaving obligation outstanding"
                );
                return;
            }
        }
        let (object_kind, version) = match &exact_state {
            ExactActualState::Object { kind, version, .. } => {
                (map_record_kind_for_completion_hash(*kind), Some(*version))
            }
            ExactActualState::Absent => (MaterializedObjectKind::Absent, None),
        };
        let desired_hash =
            compute_resolved_path_state_hash(group_id, path, object_kind, version.as_ref());
        if let Some(hook) = hooks {
            hook.pause().await;
        }
        let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
        crate::c4_diag::record_completion_attempted();
        let closed = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.sqlite().dag_complete_obligation_if_exact_proof_current(
                &group_id_owned,
                &path_owned,
                claimed_generation,
                claimed_incarnation,
                &desired_hash,
            )
        });
        match closed {
            Ok(true) => {
                crate::c4_diag::record_completion_closed();
                // Same reasoning as `process_group`'s own post-`Completed`
                // wakes: a copy this attempt just made durable could have
                // superseded some OTHER, still-live ephemeral conflict
                // copy's justification, or be exactly the sibling change
                // that clears some held path's hazard.
                state.replica_coordinator.retirement_wake().mark_dirty(group_id);
                state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
            }
            Ok(false) => {
                crate::c4_diag::record_completion_cas_lost();
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven completion CAS did not close; obligation left outstanding \
                     for re-resolution"
                );
            }
            Err(e) => tracing::warn!(
                group_id,
                path,
                error = %e,
                "obligation-driven completion failed; obligation left outstanding"
            ),
        }
    } else {
        let kind = match evidence {
            SettlementEvidence::PolicyPlaceholder => NonExactProofKind::Placeholder,
            SettlementEvidence::HazardHeld { .. } => NonExactProofKind::HazardHeld,
            SettlementEvidence::IgnoreExcluded => NonExactProofKind::IgnoreExcluded,
            SettlementEvidence::ExactObject { .. } | SettlementEvidence::ExactAbsent { .. } => {
                unreachable!("as_exact_actual_state already handled both exact variants above")
            }
        };
        let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
        crate::c4_diag::record_completion_attempted();
        let closed = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.sqlite().dag_complete_obligation_if_non_exact_proof_current(
                &group_id_owned,
                &path_owned,
                claimed_generation,
                claimed_incarnation,
                kind,
            )
        });
        match closed {
            Ok(true) => {
                crate::c4_diag::record_completion_closed();
                state.replica_coordinator.retirement_wake().mark_dirty(group_id);
                state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
            }
            Ok(false) => {
                crate::c4_diag::record_completion_cas_lost();
                tracing::debug!(
                    group_id,
                    path,
                    "obligation-driven non-exact completion CAS did not close; obligation left \
                     outstanding for re-resolution"
                );
            }
            Err(e) => tracing::warn!(
                group_id,
                path,
                error = %e,
                "obligation-driven non-exact completion failed; obligation left outstanding"
            ),
        }
    }
}

/// Closes one path's claimed obligation against zero-work-close evidence
/// (`PeerSyncSession::zero_work_settlement_for_path`) -- unlike
/// `complete_one_obligation`, this never publishes: the evidence already
/// describes a proof row that is current right now (the zero-work
/// pre-check confirmed this itself, immediately before returning it), so
/// there is nothing to write. The close is exactly the same compound
/// exact-outcome completion statement a real materialization would use,
/// re-establishing currency at the actual moment of close -- the pre-
/// check's own read and disk revalidation only ever authorized SKIPPING
/// physical work, never the close itself.
async fn complete_zero_work_obligation(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    claimed_generation: i64,
    claimed_incarnation: i64,
    evidence: &yadorilink_peer_session::peer_session::SettlementEvidence,
    hooks: Option<&Arc<BeforeCompletionHook>>,
) {
    use yadorilink_peer_session::ports::ExactActualState;
    use yadorilink_sync_sqlite::materialized_generation::{
        compute_resolved_path_state_hash, MaterializedObjectKind,
    };

    let Some((exact_state, _mutation_generation)) = evidence.as_exact_actual_state() else {
        // The zero-work pre-check only ever produces exact evidence (see
        // its own doc comment) -- unreachable in practice, but fail safe
        // rather than panic if that ever changes.
        return;
    };
    let (object_kind, version) = match &exact_state {
        ExactActualState::Object { kind, version, .. } => {
            (map_record_kind_for_completion_hash(*kind), Some(*version))
        }
        ExactActualState::Absent => (MaterializedObjectKind::Absent, None),
    };
    let desired_hash = compute_resolved_path_state_hash(group_id, path, object_kind, version.as_ref());
    if let Some(hook) = hooks {
        hook.pause().await;
    }
    let (group_id_owned, path_owned) = (group_id.to_string(), path.to_string());
    let closed = run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.sqlite().dag_complete_obligation_if_exact_proof_current(
            &group_id_owned,
            &path_owned,
            claimed_generation,
            claimed_incarnation,
            &desired_hash,
        )
    });
    match closed {
        // Deliberately no retirement/hazard-recheck wake here, unlike
        // `complete_one_obligation`'s exact-outcome arm: a zero-work close
        // means the path already matched its desired state BEFORE this
        // attempt ran, so nothing physically changed just now for a
        // sibling to react to -- whatever originally wrote this content
        // already woke retirement/hazard at that time, through its own
        // (exact-outcome) completion.
        Ok(true) => {}
        Ok(false) => tracing::debug!(
            group_id,
            path,
            "zero-work completion CAS did not close; obligation left outstanding for \
             re-resolution -- an independent mutator raced this decision"
        ),
        Err(e) => tracing::warn!(
            group_id,
            path,
            error = %e,
            "zero-work completion failed; obligation left outstanding"
        ),
    }
}

/// Drives every currently-claimable `projection_obligations` row for one
/// group through the SAME `reconcile_paths_directly`/CONV-7 stable-frontier
/// machinery `process_group` uses, closing each path's obligation via the
/// atomic compound completion instead of a bare `materialization_jobs`
/// state transition.
///
/// This is `run_once`'s own live claim source (Phase C cutover): `process_
/// group` and `materialization_jobs` remain in the codebase only for Phase
/// D to remove, no longer reachable from any live scheduling path.
///
/// Per-group path-budget rotation, a persistent cross-tick peer-rotation
/// cursor, origin-first fetch preference, and generation-guarded retry/
/// backoff (`attempt_count`/`next_attempt_at`) are all ported below, using
/// their own dedicated cursors (`DaemonState::obligation_engine_path_
/// budget_cursors`/`obligation_engine_cursors`), kept separate from
/// `process_group`'s so the two drivers' rotation state
/// never perturbs each other while both exist side by side.
///
/// The zero-work-close pre-check never requires a connected peer -- an
/// already-satisfied local projection must close with zero peers online --
/// but does not unconditionally construct the synthetic LOCAL session
/// (`DaemonState::local_retirement_session`) to get there: it prefers an
/// already-live candidate session when one exists, falling back to the
/// local session only when there are none. `local_retirement_session`'s
/// first-ever construction for a group re-validates this device's own
/// retained-history trust as a side effect (`NetmapChangeAuthenticator::
/// new`), which can transiently revoke every OTHER already-connected
/// session's authorization for this group if that validation briefly comes
/// back unavailable -- skipping the construction whenever a live candidate
/// already exists avoids ever triggering that side effect in the
/// overwhelmingly common case where it isn't needed at all. Only the paths
/// the pre-check cannot close need a real fetch, which is the point at
/// which "is any peer connected" first becomes a real question; "no peer
/// shares this group" is then treated as a stable condition (real, growing
/// backoff via `dag_mark_obligation_attempt_failed`, mirroring the legacy
/// job-based scheduler's own equivalent), distinct from a single tick's
/// guard-contention/raced read (the no-penalty defer further below).
async fn process_group_via_obligations(
    state: &Arc<DaemonState>,
    group_id: String,
    claimed: Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>,
    hooks: Option<&Arc<BeforeCompletionHook>>,
    heads_hook: Option<&Arc<BeforeHeadsAfterHook>>,
) -> ProcessGroupOutcome {
    if claimed.is_empty() {
        return ProcessGroupOutcome { audit_healthy: false, deferred_runnable: false };
    }
    // Per-call start marker, kept at `debug!` (downgraded 2026-09-01 --
    // it fires on every claimed group every tick, too noisy for
    // production `warn!`). Pairs with the "C4_DIAG: slow obligation tick"
    // end-of-call `warn!` further below (that one stays `warn!`, since
    // it's threshold-gated): if this start marker appears without a
    // matching end marker for tens of seconds, this call is stuck
    // in-flight, not merely absent.
    tracing::debug!(
        group_id = %group_id,
        claimed_count = claimed.len(),
        claimed_paths = ?claimed.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
        "C4_ATTR_ENGINE process_group_via_obligations starting"
    );
    let claimed_generation: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.invalidation_generation)).collect();
    // Phase E finding (obligation row-incarnation ABA): carried alongside
    // `claimed_generation` into every completion-family call below, exactly
    // like `invalidation_generation` itself -- see `ClaimedObligation`'s own
    // doc comment for why `G` alone is not a safe claim token on its own.
    let claimed_incarnation: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.obligation_incarnation)).collect();
    let claimed_attempt: BTreeMap<String, i64> =
        claimed.iter().map(|c| (c.path.clone(), c.attempt_count)).collect();
    // PERMANENT per-tick cost attribution: feeds `crate::c4_diag`'s
    // `ObligationEngineStats` counters (also relied on by the 128-8
    // zero-work-precheck regression test) and the slow-obligation-tick
    // alarm below. Throughput here is (paths resolved per tick) / (tick
    // duration), and only the first factor is visible from the outside -- it
    // is pinned at MAX_PATHS_PER_RECONCILE_ATTEMPT. Whether a slow catch-up is
    // "the window is small" or "each tick is expensive", and if the latter
    // WHICH half of the tick is expensive, is not otherwise observable.
    let c4_diag_tick_started = std::time::Instant::now();
    let c4_diag_claimed = claimed.len();
    crate::c4_diag::record_obligations_claimed(c4_diag_claimed);

    // Per-group path-budget rotation — same reasoning as `process_group`'s
    // own `MAX_PATHS_PER_RECONCILE_ATTEMPT` windowing: a single
    // `reconcile_paths_directly` call handed this group's ENTIRE
    // still-outstanding budget would process every path's blocks fully
    // serially, and the claim call's own per-group/total limits bound how
    // much gets CLAIMED per tick, not how much one attempt is asked to
    // resolve in a single call. Chosen BEFORE the zero-work pre-check below
    // (not after, as an earlier version of this function did): a zero-work
    // resolution is itself a real per-path DAG-ancestry walk
    // (`combined_heads`), not a free operation, so pre-checking every one
    // of up to 128 claimed paths when at most `MAX_PATHS_PER_RECONCILE_
    // ATTEMPT` of them can ever reach a real reconcile attempt this tick
    // was an up-to-16x resolution amplification with no corresponding
    // throughput benefit -- the other claimed-but-unwindowed rows are a
    // plain read from `claim_runnable_obligations` (never marked in-flight
    // by claiming alone), so leaving them completely untouched this tick is
    // correct and costs nothing; they remain claimable on a future tick.
    let mut all_paths: Vec<String> = claimed_generation.keys().cloned().collect();
    all_paths.sort();
    let path_budget_start = {
        let cursors =
            state.obligation_engine_path_budget_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(&group_id).copied().unwrap_or(0) % all_paths.len().max(1)
    };
    let budget_indices =
        rotation_indices(all_paths.len(), path_budget_start, MAX_PATHS_PER_RECONCILE_ATTEMPT);
    let windowed_paths: Vec<String> = budget_indices.iter().map(|&i| all_paths[i].clone()).collect();
    {
        let mut cursors =
            state.obligation_engine_path_budget_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(
            group_id.clone(),
            (path_budget_start + budget_indices.len().max(1)) % all_paths.len().max(1),
        );
    }
    let deferred_runnable = all_paths.len() > windowed_paths.len();
    let mut budget: BTreeSet<String> = windowed_paths.into_iter().collect();
    let windowed_len = budget.len();

    // Candidates are fetched up front -- this is a pure read with no
    // construction side effect, unlike `local_retirement_session` below --
    // so the zero-work pre-check can prefer an already-live session when
    // one exists, and the "no peer" backoff further below can see the same
    // list without a second, potentially different, fetch.
    let mut candidates = crate::hydration::candidate_sessions(state, &group_id);
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    // Zero-work-close pre-check: without any block fetch or disk write,
    // ask whether each of THIS TICK'S WINDOWED paths (at most
    // `MAX_PATHS_PER_RECONCILE_ATTEMPT`, chosen above -- not every claimed
    // path) already, verifiably, holds its current desired state -- a
    // purely local read plus a disk stat, never a peer round trip, so it
    // must never depend on a peer being connected at all: an
    // already-satisfied local projection must be closeable with zero peers
    // online, exactly as it would be with ten. Prefers an already-live
    // candidate session when one exists (identical to `process_group`'s
    // own "any session answers this identically" reasoning); falls back to
    // the synthetic local session (the same one the hazard/ignore-recheck
    // sweeps use) ONLY when there are no live candidates at all, rather
    // than unconditionally constructing one -- `local_retirement_session`'s
    // first-ever construction for a group re-validates this device's own
    // retained-history trust as a side effect (`NetmapChangeAuthenticator::
    // new`), which can transiently quarantine every OTHER already-connected
    // session's authorization for this group if that validation is not yet
    // available; skipping the construction whenever a live candidate
    // already exists avoids triggering that side effect on the
    // (overwhelmingly common) case where one isn't even needed. A path
    // this confirms is closed immediately and removed from the budget
    // handed to the ordinary reconcile loop below — it never reaches
    // `reconcile_paths_directly`/`materialize` at all this tick.
    let zero_work_session = match candidates.first() {
        Some((_, session)) => session.clone(),
        None => state.local_retirement_session(&group_id),
    };
    crate::c4_diag::record_zero_work_attempted(budget.len());
    // C4_ATTR (temporary, remove after investigation): unconditional,
    // per-tick timing for JUST this loop -- 2026-09-02 100k/30k
    // acceptance-run attribution. `zero_work_settlement_for_path` (called
    // per windowed path below) runs entirely BEFORE `reconcile_group_
    // paths` is ever reached, so its cost is invisible to that function's
    // own `c4_attr::ReconcileCallTimer` -- confirmed via a 30k harness
    // reproduction where the sender device's `reconcile_group_paths`
    // calls showed 83.5% of wall time as `unattributed_ms` (including a
    // single 309.7s call), with `dag_resolution_ms` accounting for only
    // ~16.5% of it. `zero_work_settlement_for_path`'s own doc comment
    // already names this exact mechanism (a per-path `combined_heads` ->
    // `store_live_heads_for_path` walk with "no memoization across paths
    // or across ticks", previously measured on a real 91k-path catch-up
    // at "~6.6s per tick to advance 8 paths"), but nothing logs its cost
    // unconditionally -- the existing `precheck_ms` a few lines below
    // only fires at `debug!` (below `info!`) and only when this loop
    // closes the ENTIRE windowed budget via zero-work, not on every tick.
    let c4_attr_zero_work_precheck_started = std::time::Instant::now();
    for path in budget.iter().cloned().collect::<Vec<_>>() {
        let session = zero_work_session.clone();
        let group_id_for_check = group_id.clone();
        let path_for_check = path.clone();
        let settlement = run_blocking_sweep_offloaded(move || {
            session.zero_work_settlement_for_path(&group_id_for_check, &path_for_check)
        });
        match settlement {
            Ok(Some(evidence)) => {
                if let (Some(&claimed_g), Some(&claimed_i)) =
                    (claimed_generation.get(&path), claimed_incarnation.get(&path))
                {
                    complete_zero_work_obligation(
                        state, &group_id, &path, claimed_g, claimed_i, &evidence, hooks,
                    )
                    .await;
                }
                budget.remove(&path);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    group_id = %group_id,
                    path,
                    error = %e,
                    "zero-work-close pre-check failed; falling through to a real attempt"
                );
            }
        }
    }
    let c4_diag_precheck_elapsed = c4_diag_tick_started.elapsed();
    let c4_diag_precheck_closed = windowed_len.saturating_sub(budget.len());
    crate::c4_diag::record_zero_work_closed(c4_diag_precheck_closed);
    // C4_ATTR (temporary, remove after investigation): unconditional --
    // logged every tick, regardless of whether the zero-work loop closed
    // the whole budget -- see this loop's own start-of-loop comment.
    tracing::info!(
        group_id = %group_id,
        windowed = windowed_len,
        precheck_closed = c4_diag_precheck_closed,
        zero_work_precheck_ms = c4_attr_zero_work_precheck_started.elapsed().as_millis() as u64,
        "C4_ATTR zero-work pre-check loop call-local timing"
    );
    if budget.is_empty() {
        tracing::debug!(
            group_id = %group_id,
            claimed = c4_diag_claimed,
            windowed = windowed_len,
            precheck_closed = c4_diag_precheck_closed,
            precheck_ms = c4_diag_precheck_elapsed.as_millis() as u64,
            "C4_DIAG: obligation tick closed entirely in the zero-work pre-check"
        );
        return ProcessGroupOutcome { audit_healthy: true, deferred_runnable };
    }
    let windowed_budget = budget;

    // Only now does whether any peer is connected actually matter -- every
    // path the zero-work pre-check couldn't already close needs a real
    // fetch/materialize attempt, which does need somewhere to fetch from.
    // Reuses the SAME `candidates` fetched at the top of this function
    // (a peer connecting/disconnecting in the brief window since is an
    // accepted race the rest of this scheduler already tolerates via its
    // own CAS-based completion, not something worth a second fetch here).
    if candidates.is_empty() {
        // Unlike a guard-contention/raced-read tick (see the no-penalty
        // defer below), "no peer shares this group right now" is a stable
        // condition, not a transient blip -- it stays true every tick until
        // one connects. Applying real, growing backoff (not the no-penalty
        // defer) keeps a permanently-offline group from being re-examined
        // at full speed forever; mirrors `process_group`'s own `back_off_
        // group` call for the identical case.
        let now = now_unix_nanos();
        for path in &windowed_budget {
            let Some(&claimed_g) = claimed_generation.get(path) else { continue };
            let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
            let attempt_count = claimed_attempt.get(path).copied().unwrap_or(0);
            let next_attempt_at =
                now + next_backoff((attempt_count as u32).saturating_add(1)).as_nanos() as i64;
            let path_owned = path.clone();
            let group_id_owned = group_id.clone();
            let _ = run_blocking_sweep_offloaded(move || {
                state.replica_coordinator.sqlite().dag_mark_obligation_attempt_failed(
                    &group_id_owned,
                    &path_owned,
                    claimed_g,
                    claimed_i,
                    next_attempt_at,
                    now,
                )
            });
        }
        crate::c4_diag::record_obligations_backed_off(windowed_budget.len());
        return ProcessGroupOutcome { audit_healthy: false, deferred_runnable };
    }

    const MAX_PEERS_PER_TICK: usize = 2;
    // Persistent cross-tick peer-rotation cursor (`obligation_engine_
    // cursors`): advancing by a fixed amount regardless of how many
    // candidates this call actually tried would re-try an early candidate
    // every tick while a later one is reached far less often.
    let peer_rotation_start = {
        let cursors = state.obligation_engine_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(&group_id).copied().unwrap_or(0) % candidates.len()
    };
    // Origin-first fetch preference, resolved from the current desired-state
    // winner (see `origin_candidate_index_for_obligations`'s own doc
    // comment) rather than a stored triggering change — reuses
    // `zero_work_session` rather than constructing anything new.
    let origin_index =
        origin_candidate_index_for_obligations(&zero_work_session, &group_id, &windowed_budget, &candidates);
    let rotation_window = rotation_indices(candidates.len(), peer_rotation_start, MAX_PEERS_PER_TICK);
    let indices =
        origin_first_indices(candidates.len(), peer_rotation_start, MAX_PEERS_PER_TICK, origin_index);

    let mut remaining: BTreeSet<String> = windowed_budget;
    let mut any_trustworthy_audit = false;
    let mut tried = 0usize;

    for &candidate_index in &indices {
        if remaining.is_empty() {
            break;
        }
        tried += 1;
        let (_, session) = &candidates[candidate_index];
        let heads_before = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.sqlite().dag_group_heads(&group_id)
        });
        crate::c4_diag::record_reconcile_attempt_started();
        let attempt_result = session.reconcile_paths_directly(&group_id, remaining.clone()).await;
        if let Some(h) = heads_hook {
            h.pause().await;
        }
        let heads_after = run_blocking_sweep_offloaded(|| {
            state.replica_coordinator.sqlite().dag_group_heads(&group_id)
        });
        if matches!(attempt_result, Ok(Some(_))) {
            crate::c4_diag::record_reconcile_attempt_with_result();
        }

        match (attempt_result, heads_before, heads_after) {
            // Phase-E finding: the group-wide `before == after` comparison
            // this arm used to require before publishing/completing ANY of
            // this attempt's settlements was proven unnecessary --
            // `unrelated_path_head_movement_must_not_discard_an_already_
            // settled_attempt` (RED against the old gated code) and
            // `same_path_admission_while_parked_is_independently_rejected_
            // by_generation_cas` (already GREEN) together show that the
            // per-path completion CAS below (claimed generation/incarnation
            // plus the live mutation fence -- see `complete_one_obligation`)
            // already decides currency on its own, per path, regardless of
            // whether some OTHER path's admission moved the group's heads
            // in between. Gating the whole attempt on group-wide stability
            // was actively harmful: the `wait_ready_first` two-arm
            // comparison's own catch-up admits unrelated historical changes
            // fast enough (~15/s) that a stable before/after window across
            // an entire `reconcile_paths_directly` call became rare, so
            // this attempt's already-resolved settlements were repeatedly
            // discarded for reasons unconnected to the paths they targeted.
            (Ok(Some(attempt)), Ok(before), Ok(after)) => {
                any_trustworthy_audit = true;
                remaining.retain(|p| !attempt.path_fully_resolved(p));
                let settled_count = attempt.settled_with_evidence().count();
                if before == after {
                    crate::c4_diag::record_reconcile_attempt_heads_stable(settled_count);
                } else {
                    // Informational only (the heads-stability fence this
                    // used to help diagnose is gone) -- kept as part of
                    // the permanent `ObligationEngineStats` surface since
                    // it costs nothing and is still a legitimate "how
                    // often did an attempt's window see unrelated head
                    // movement" signal.
                    crate::c4_diag::record_reconcile_attempt_heads_changed(settled_count);
                }
                for (path, evidence) in attempt.settled_with_evidence() {
                    let Some(&claimed_g) = claimed_generation.get(path) else { continue };
                    let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
                    complete_one_obligation(
                        state, &group_id, path, claimed_g, claimed_i, evidence, &before, hooks,
                    )
                    .await;
                }
            }
            (Ok(None), _, _) => {
                // Skipped: guard contention or the group's link gate is no
                // longer live. Leave `remaining` untouched.
            }
            (Err(e), _, _) => {
                tracing::warn!(
                    group_id = %group_id,
                    error = %e,
                    "obligation-driven reconciliation failed for this group"
                );
            }
            (_, Err(e), _) | (_, _, Err(e)) => {
                tracing::warn!(
                    group_id = %group_id,
                    error = %e,
                    "obligation-driven driver failed to read this group's DAG heads"
                );
            }
        }
    }

    {
        // Advance by how many of the ROTATION window's leading positions
        // were actually consumed, not by raw `tried` — same prefix rule
        // `process_group`'s own cursor advance uses, for the identical
        // reason: with an origin-first preference, raw `tried` can include
        // an out-of-window origin attempt (which must not move the
        // rotation at all) or an in-window origin tried out of position
        // (which must not let the cursor skip a window candidate that
        // never got its own turn).
        let tried_set: BTreeSet<usize> = indices.iter().take(tried).copied().collect();
        let advance = rotation_window.iter().take_while(|i| tried_set.contains(i)).count();
        let mut cursors = state.obligation_engine_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(group_id.clone(), (peer_rotation_start + advance) % candidates.len());
    }

    // Retry/backoff bookkeeping for every path still outstanding
    // (`remaining` never shrinks below what `path_fully_resolved` removed
    // above -- see that arm's own comment). A `HazardHeld`/`IgnoreExcluded`/
    // `PolicyPlaceholder` settlement is never in `remaining` at all: it was
    // `is_settled`, so `path_fully_resolved` already dropped it, and its own
    // dedicated liveness mechanism (the hazard-recheck sweep, the ignore-set
    // refresh) — not this generic backoff — owns re-arming it later. Only a
    // genuine `RetryRequired` (or a path no candidate got to examine at all
    // this tick) ever reaches here.
    let backoff_now = now_unix_nanos();
    if !any_trustworthy_audit {
        // Nothing this tick was learned about ANY budgeted path — every
        // candidate was skipped (guard contention) or raced a concurrent
        // admission. A short, fixed, UNPENALIZED reschedule (mirroring
        // `process_group`'s own `skip_reschedule_batch`) avoids a tight
        // busy-loop against a systemic condition without treating it as a
        // real per-path failure.
        let next_attempt_at = backoff_now + Duration::from_millis(200).as_nanos() as i64;
        for path in &remaining {
            let Some(&claimed_g) = claimed_generation.get(path) else { continue };
            let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
            let path_owned = path.clone();
            let group_id_owned = group_id.clone();
            let _ = run_blocking_sweep_offloaded(move || {
                state.replica_coordinator.sqlite().dag_defer_obligation_without_penalty(
                    &group_id_owned,
                    &path_owned,
                    claimed_g,
                    claimed_i,
                    next_attempt_at,
                    backoff_now,
                )
            });
        }
        crate::c4_diag::record_obligations_deferred(remaining.len());
    } else {
        for path in &remaining {
            let Some(&claimed_g) = claimed_generation.get(path) else { continue };
            let Some(&claimed_i) = claimed_incarnation.get(path) else { continue };
            let attempt_count = claimed_attempt.get(path).copied().unwrap_or(0);
            let next_attempt_at = backoff_now
                + next_backoff((attempt_count as u32).saturating_add(1)).as_nanos() as i64;
            let path_owned = path.clone();
            let group_id_owned = group_id.clone();
            let _ = run_blocking_sweep_offloaded(move || {
                state.replica_coordinator.sqlite().dag_mark_obligation_attempt_failed(
                    &group_id_owned,
                    &path_owned,
                    claimed_g,
                    claimed_i,
                    next_attempt_at,
                    backoff_now,
                )
            });
        }
        crate::c4_diag::record_obligations_failed(remaining.len());
    }

    // PERMANENT slow-tick alarm: `warn` only past a threshold, so a
    // healthy fast tick stays silent while a catch-up that is spending
    // seconds per 8 paths says so.
    let c4_diag_tick_elapsed = c4_diag_tick_started.elapsed();
    if c4_diag_tick_elapsed >= Duration::from_millis(250) {
        tracing::warn!(
            group_id = %group_id,
            claimed = c4_diag_claimed,
            precheck_closed = c4_diag_precheck_closed,
            precheck_ms = c4_diag_precheck_elapsed.as_millis() as u64,
            windowed = windowed_len,
            still_unresolved = remaining.len(),
            candidates_tried = tried,
            tick_ms = c4_diag_tick_elapsed.as_millis() as u64,
            "C4_DIAG: slow obligation tick"
        );
    }
    ProcessGroupOutcome { audit_healthy: any_trustworthy_audit, deferred_runnable }
}

/// Shared body for [`drive_obligations_once_for_test`] and
/// [`drive_obligations_once_for_test_with_hooks`]: claims every currently-
/// runnable `projection_obligations` row across all groups and drives each
/// group's claimed batch through [`process_group_via_obligations`],
/// forwarding `hooks` (`None` from the plain entrypoint) unchanged.
#[cfg(any(test, feature = "test-support"))]
async fn drive_obligations_once_for_test_inner(
    state: &Arc<DaemonState>,
    per_group_limit: u32,
    total_limit: u32,
    hooks: Option<&Arc<BeforeCompletionHook>>,
    heads_hook: Option<&Arc<BeforeHeadsAfterHook>>,
) -> bool {
    let now = now_unix_nanos();
    let claimed = match run_blocking_sweep_offloaded(|| {
        state.replica_coordinator.sqlite().dag_claim_runnable_obligations(now, per_group_limit, total_limit)
    }) {
        Ok(claimed) => claimed,
        Err(e) => {
            tracing::warn!(error = %e, "obligation-driven test entrypoint failed to claim");
            return false;
        }
    };
    let mut by_group: HashMap<String, Vec<yadorilink_sync_sqlite::projection_obligations::ClaimedObligation>> =
        HashMap::new();
    for obligation in claimed {
        by_group.entry(obligation.group_id.clone()).or_default().push(obligation);
    }
    let mut any_healthy = false;
    for (group_id, group_claimed) in by_group {
        let outcome =
            process_group_via_obligations(state, group_id, group_claimed, hooks, heads_hook).await;
        any_healthy = any_healthy || outcome.audit_healthy;
    }
    any_healthy
}

/// Test-only: claims every currently-runnable `projection_obligations` row
/// across all groups and drives each group's claimed batch through
/// [`process_group_via_obligations`] — the obligation-driven counterpart of
/// [`run_once_for_test`], for proving the obligation-driven claim path is
/// correct end-to-end before any cutover wires this claim source into the
/// live `run_once`
/// loop. Returns whether at least one group's audit was trustworthy this
/// call, which is enough for a focused test to assert real progress
/// happened without depending on `run_once`'s own work-conserving
/// `immediate_backlog` semantics (not meaningful here since nothing repeats
/// this call automatically).
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test(state: &Arc<DaemonState>, per_group_limit: u32, total_limit: u32) -> bool {
    drive_obligations_once_for_test_inner(state, per_group_limit, total_limit, None, None).await
}

/// Identical to [`drive_obligations_once_for_test`], except every
/// completion decision this tick makes pauses at [`BeforeCompletionHook`]
/// immediately before its own completion CAS, letting a deterministic-
/// interleaving test land an independent mutation in between. Intended to
/// be spawned onto its own task (see [`BeforeCompletionHook`]'s own doc
/// comment) so the calling test can drive the interleaving from its own,
/// separate task while this one sits parked.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test_with_hooks(
    state: &Arc<DaemonState>,
    per_group_limit: u32,
    total_limit: u32,
    hooks: &Arc<BeforeCompletionHook>,
) -> bool {
    drive_obligations_once_for_test_inner(state, per_group_limit, total_limit, Some(hooks), None).await
}

/// Identical to [`drive_obligations_once_for_test`], except every
/// candidate attempt this tick makes pauses at [`BeforeHeadsAfterHook`]
/// immediately after `reconcile_paths_directly` resolves and immediately
/// before the group's post-attempt `dag_group_heads` re-read, letting a
/// deterministic-interleaving test admit an independent change in between
/// and observe whether the heads-stability fence discards this attempt's
/// settlements as a result.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test_with_heads_hook(
    state: &Arc<DaemonState>,
    per_group_limit: u32,
    total_limit: u32,
    heads_hook: &Arc<BeforeHeadsAfterHook>,
) -> bool {
    drive_obligations_once_for_test_inner(state, per_group_limit, total_limit, None, Some(heads_hook)).await
}

#[cfg(test)]
mod tests {
    use super::{majority_author, origin_first_indices, rotation_indices, MAX_PATHS_PER_RECONCILE_ATTEMPT};

    #[test]
    fn no_candidates_yields_no_attempts() {
        assert_eq!(rotation_indices(0, 0, 2), Vec::<usize>::new());
        assert_eq!(rotation_indices(0, 5, 2), Vec::<usize>::new());
    }

    #[test]
    fn tries_up_to_max_attempts_starting_at_the_cursor() {
        assert_eq!(rotation_indices(6, 0, 2), vec![0, 1]);
        assert_eq!(rotation_indices(6, 3, 2), vec![3, 4]);
    }

    #[test]
    fn wraps_around_past_the_end_of_the_candidate_list() {
        assert_eq!(rotation_indices(6, 5, 2), vec![5, 0]);
        assert_eq!(rotation_indices(3, 2, 2), vec![2, 0]);
    }

    #[test]
    fn caps_at_candidate_count_when_max_attempts_is_larger() {
        assert_eq!(rotation_indices(2, 0, 5), vec![0, 1]);
    }

    #[test]
    fn a_stale_cursor_far_past_the_candidate_count_still_normalizes_correctly() {
        // The cursor is persisted across ticks and the candidate set can
        // shrink between ticks (a peer disconnects) — a stored cursor value
        // that no longer fits must still normalize via modulo, not panic
        // or index out of bounds.
        assert_eq!(rotation_indices(3, 100, 2), vec![1, 2]);
    }

    /// F2 / decision-9 regression, exact form: `process_group_via_
    /// obligations`'s own path-budget window is exactly `rotation_indices`
    /// called with the real `MAX_PATHS_PER_RECONCILE_ATTEMPT` constant, no
    /// further logic in between (`windowed_paths` is a straight 1:1 index
    /// map). `zero_work_precheck_examines_at_most_the_path_budget_window_
    /// per_tick` (below) proves the full async engine respects this bound
    /// too, but that test's own assertion is deliberately loosened to
    /// tolerate cross-test pollution of the process-global `c4_diag`
    /// counters it reads (see that test's own comment) -- it could not
    /// catch a regression from 8 to, say, 12 or 16. This test has no
    /// global state, no async machinery, and no tolerance: it ties the
    /// production constant directly to `rotation_indices`'s own
    /// already-exact contract.
    #[test]
    fn the_path_budget_window_is_exactly_bounded_by_max_paths_per_reconcile_attempt() {
        let indices = rotation_indices(50, 0, MAX_PATHS_PER_RECONCILE_ATTEMPT);
        assert_eq!(
            indices.len(),
            MAX_PATHS_PER_RECONCILE_ATTEMPT,
            "50 claimed paths must window down to exactly MAX_PATHS_PER_RECONCILE_ATTEMPT \
             ({MAX_PATHS_PER_RECONCILE_ATTEMPT}), not a looser bound"
        );
        // Fewer claimed paths than the budget must never be padded or
        // over-counted -- the window is capped at, not filled to, the
        // constant.
        let short = rotation_indices(3, 0, MAX_PATHS_PER_RECONCILE_ATTEMPT);
        assert_eq!(short.len(), 3);
    }

    #[test]
    fn full_rotation_across_repeated_calls_reaches_every_candidate_within_a_few_ticks() {
        // Simulates what `process_group` does across successive ticks:
        // advance the cursor by exactly how many indices were returned
        // (the fix for a real bug an independent review caught — advancing
        // by a fixed 1 regardless of how many were tried left candidate 1
        // freshly re-tried every tick while candidate 2 only got reached
        // every other tick, so a 6-candidate group took 5 ticks to reach
        // every peer once instead of 3).
        let candidate_count = 6;
        let max_attempts = 2;
        let mut cursor = 0usize;
        let mut seen: Vec<usize> = Vec::new();
        for _ in 0..(candidate_count / max_attempts) {
            let indices = rotation_indices(candidate_count, cursor, max_attempts);
            seen.extend(&indices);
            cursor = (cursor + indices.len()) % candidate_count;
        }
        // Every candidate reached exactly once — no gaps (a peer skipped
        // forever) and no overlap (a peer re-tried before every other peer
        // got its first try), achievable here since candidate_count is
        // evenly divisible by max_attempts.
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn no_origin_preference_is_plain_rotation() {
        assert_eq!(origin_first_indices(6, 3, 2, None), rotation_indices(6, 3, 2));
    }

    #[test]
    fn an_origin_inside_the_window_moves_to_the_front_without_a_duplicate() {
        // Window at cursor 3 is [3, 4]; origin 4 must lead, 3 stays.
        assert_eq!(origin_first_indices(6, 3, 2, Some(4)), vec![4, 3]);
        // Origin already first is a no-op.
        assert_eq!(origin_first_indices(6, 3, 2, Some(3)), vec![3, 4]);
    }

    #[test]
    fn an_origin_outside_the_window_replaces_the_last_slot() {
        // Window at cursor 0 is [0, 1]; origin 5 takes the lead and the
        // attempt budget stays 2, so window position 1 waits its turn.
        assert_eq!(origin_first_indices(6, 0, 2, Some(5)), vec![5, 0]);
    }

    #[test]
    fn a_stale_origin_index_past_the_candidate_count_is_ignored() {
        // The candidate set can shrink between resolving the origin and
        // building the order (a peer disconnects) — never index past it.
        assert_eq!(origin_first_indices(3, 0, 2, Some(7)), vec![0, 1]);
        assert_eq!(origin_first_indices(0, 0, 2, Some(0)), Vec::<usize>::new());
    }

    #[test]
    fn origin_preference_never_starves_the_rotation() {
        // The fairness contract behind `process_group`'s prefix-based
        // cursor advance: with a PERSISTENT origin preference (one author
        // with a standing backlog) and every attempt tried each tick, every
        // other candidate is still reached within a bounded number of
        // ticks — the origin eats one attempt slot, it does not freeze the
        // rotation.
        let candidate_count = 4;
        let max_attempts = 2;
        let origin = 3usize;
        let mut cursor = 0usize;
        let mut seen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
        for _ in 0..candidate_count {
            let window = rotation_indices(candidate_count, cursor, max_attempts);
            let indices = origin_first_indices(candidate_count, cursor, max_attempts, Some(origin));
            seen.extend(&indices);
            let tried: std::collections::BTreeSet<usize> = indices.iter().copied().collect();
            let advance = window.iter().take_while(|i| tried.contains(i)).count();
            cursor = (cursor + advance) % candidate_count;
        }
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn majority_author_picks_the_most_frequent_with_a_deterministic_tie_break() {
        assert_eq!(majority_author(Vec::<String>::new()), None);
        assert_eq!(
            majority_author(vec!["b".into(), "a".into(), "b".into()]),
            Some("b".to_string())
        );
        // Equal counts: the lexicographically smallest id wins, so every
        // replica running this election lands on the same preference.
        assert_eq!(majority_author(vec!["b".into(), "a".into()]), Some("a".to_string()));
    }
}

/// The obligation-driven scheduler's own CONV-7 publication arm
/// (`attempt.settled_with_evidence()` above), driven with a REAL,
/// deterministic race against a real `DaemonState`. No existing harness in
/// this crate can drive `process_group_via_obligations` deterministically --
/// `DaemonState::new` always starts a `MaintenanceCoordinator` that runs its
/// own concurrent ticks, and `DaemonState::build` (the maintenance-free
/// constructor) is `pub(crate)`, unreachable from an external `tests/*.rs`
/// crate. Living in-crate, as a sibling to `mod tests` above, is what makes
/// this possible: `process_group_via_obligations` itself is a private
/// sibling item, and `DaemonState::build` starts nothing else that could
/// race our own manual call.
#[cfg(test)]
mod process_group_publication_tests {
    use super::{
        drive_obligations_once_for_test, drive_obligations_once_for_test_with_heads_hook,
        drive_obligations_once_for_test_with_hooks, BeforeCompletionHook, BeforeHeadsAfterHook,
        DaemonState, MAX_PATHS_PER_RECONCILE_ATTEMPT,
    };
    use crate::convergence::engine_impl::complete_one_obligation;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_peer_session::peer_session::PeerSyncSession;
    use yadorilink_peer_session::ports::{PeerBlockStream, PeerMessageChannel, PeerReplicaStatePort};
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use yadorilink_root_authority::root_identity::VerifiedRoot;
    use yadorilink_transport::TransportError;

    const GROUP: &str = "group-a";

    fn empty_version(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    /// A channel with nothing on the far end: no real peer ever connects,
    /// since the candidate session's `state` is the SAME `ReplicaCoordinator`
    /// as the device under test and every path used here is zero-block, so
    /// `materialize()` never needs a fetch. `open_block_stream`/`accept_
    /// block_stream` must never be reached in this test's scenario; they
    /// return/hang rather than panic so a future accidental call surfaces
    /// as an ordinary timeout, not a crash.
    struct NoopChannel;

    #[async_trait::async_trait]
    impl PeerMessageChannel for NoopChannel {
        async fn send(&self, _payload: Vec<u8>) -> Result<(), TransportError> {
            Ok(())
        }
        fn try_send(&self, _payload: Vec<u8>) -> bool {
            true
        }
        async fn recv(&self) -> Option<Vec<u8>> {
            std::future::pending().await
        }
        async fn open_block_stream(&self) -> Result<Box<dyn PeerBlockStream>, TransportError> {
            Err(TransportError::ChannelClosed)
        }
        async fn accept_block_stream(&self) -> Option<Box<dyn PeerBlockStream>> {
            std::future::pending().await
        }
    }

    /// Builds a maintenance-free `DaemonState` (via `DaemonState::build`,
    /// not `DaemonState::new`) with `GROUP` fully adopted (link + verified
    /// root + startup-ready) and a stubbed root-commit authority (the
    /// sanctioned test-only escape hatch `DaemonState::test_root_commit_
    /// authorities` documents -- the real `impl RootCommitAuthorityProvider
    /// for DaemonState` otherwise needs a live `LinkRuntime`, which nothing
    /// here starts), plus one registered candidate `PeerSyncSession` so
    /// `process_group` has somewhere to route its reconcile attempt.
    async fn build_state_with_adopted_group() -> (Arc<DaemonState>, tempfile::TempDir, std::path::PathBuf)
    {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let replica_coordinator =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let block_store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());

        replica_coordinator.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
        VerifiedRoot::open(&root, GROUP, replica_coordinator.as_ref()).unwrap();
        let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP);
        replica_coordinator.startup_readiness().mark_group_ready(GROUP, generation);

        let build = DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
        let state = build.state;
        state.test_root_commit_authorities.lock().unwrap().insert(
            GROUP.to_string(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        );

        let deps = crate::peer_orchestrator::peer_sync_session_deps(&state);
        let session = PeerSyncSession::new_with_dependencies(
            Arc::new(NoopChannel),
            "device-local".to_string(),
            "device-peer".to_string(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), root.clone())]),
            Some(state.forward_tx.clone()),
            deps,
        );
        state.peers.register_session("device-peer".to_string(), session);

        (state, root_dir, root)
    }

    fn admit_change(state: &DaemonState, device: &str, key: &SigningKey, path: &str, version: &FileVersion) -> Change {
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId(device.to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(path.to_string()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(version), true)
            .unwrap();
        change
    }

    /// End to end: with nothing racing the obligation-driven worker's
    /// single reconcile attempt, admitting a change must both publish the
    /// real materialized generation AND close its `projection_obligations`
    /// row via the exact-outcome compound completion primitive -- proven
    /// not merely by "the row is gone" but by cross-checking the desired
    /// hash the completion closed against equals the same hash the
    /// desired-side builder independently computes for this content.
    /// Confirmed genuinely RED by passing the WRONG claimed generation
    /// (`claimed_g + 1`) to the completion call inside
    /// `complete_one_obligation`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stable_frontier_closes_the_obligation_via_the_exact_completion_primitive() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[81u8; 32]);
        let version = empty_version(1_700_000_100);
        admit_change(&state, "device-a", &key, "obligated.txt", &version);

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "obligated.txt")
            .unwrap()
            .expect("admission must have created an obligation");
        assert_eq!(obligation_before.invalidation_generation, 1);

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy, "the one, unraced candidate attempt must be trustworthy");

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "obligated.txt")
                .unwrap()
                .is_none(),
            "a stable-frontier, fully-settled attempt must close the obligation"
        );
        let basis = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "obligated.txt")
            .unwrap()
            .expect("the exact outcome must also publish a usable materialized generation");
        let resolution = yadorilink_replica_engine::conflict::PathResolution::Present {
            winner: 0,
            conflict_copies: vec![],
        };
        let desired_hash = state
            .replica_coordinator
            .sqlite()
            .dag_desired_resolved_path_state_hash(GROUP, "obligated.txt", &resolution, Some(&version.version_hash))
            .unwrap();
        assert_eq!(
            basis.resolved_path_state_hash, desired_hash,
            "the published proof's own hash must equal Stage 1's independently-computed desired \
             hash for the same content -- not merely 'some hash'"
        );
    }

    /// Regression test (hazard-held case, 1 of 2 sibling cases guarded
    /// here): a hazard-held settlement must close its obligation via the
    /// non-exact completion
    /// primitive, but must never publish an exact materialized generation
    /// -- `path_materialized_generations` staying empty is what lets a
    /// later hazard-clear-and-recheck genuinely re-materialize the path
    /// instead of a stale exact row short-circuiting it. Genuine hazard
    /// detection is not reliably reachable through this Linux sandbox's
    /// real `process_group` pipeline (`NamePolicy::local()` is POSIX here,
    /// and this host's filesystems are case/normalization-sensitive), so
    /// this test manufactures the held state directly and drives the SAME
    /// completion primitive `process_group_via_obligations` calls in
    /// production -- exactly the pattern `hazard_recheck_tests::a_held_
    /// path_is_re_examined_and_cleared_by_the_sweep_alone` (`engine_
    /// wrapper.rs`) already uses for the same reason. Confirmed genuinely
    /// RED by temporarily swapping the `HazardHeld` evidence below for an
    /// `ExactAbsent` one: the exact/non-exact split routes through
    /// materially different completion machinery (the exact side CASes on
    /// a filesystem mutation fence this test never bumped), so the swap
    /// fails this test's very first assertion (obligation completion
    /// itself) rather than reaching the exact-generation check -- equally
    /// conclusive proof this test is not vacuous, and a stronger failure
    /// mode than a silently-wrong classification would be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn hazard_held_settlement_does_not_publish_an_exact_generation() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[92u8; 32]);
        let version = empty_version(1_700_001_000);
        let change = admit_change(&state, "device-a", &key, "held.txt", &version);

        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &yadorilink_replica_domain::file::FileRecord {
                    path: "held.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 1_700_001_000,
                    blocks: vec![],
                    deleted: false,
                },
                "device-a",
                &change.change_hash(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .replica_coordinator
            .materialization_state_repository()
            .set_held(GROUP, "held.txt", "case_collision", 1_000)
            .unwrap();

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "held.txt")
            .unwrap()
            .expect("admission must have created an obligation");

        complete_one_obligation(
            &state,
            GROUP,
            "held.txt",
            obligation.invalidation_generation,
            obligation.obligation_incarnation,
            &yadorilink_peer_session::peer_session::SettlementEvidence::HazardHeld {
                reason: "case_collision".to_string(),
            },
            &[],
            None,
        )
        .await;

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "held.txt")
                .unwrap()
                .is_none(),
            "a hazard-held settlement must still close the obligation via the non-exact primitive"
        );
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_materialized_generation(GROUP, "held.txt")
                .unwrap()
                .is_none(),
            "a hazard hold must never publish an exact materialized generation -- nothing was \
             written to disk"
        );
        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(GROUP, "held.txt")
                .unwrap()
                .map(|h| h.reason),
            Some("case_collision".to_string()),
            "the durable held-reason record must still be the source of truth for why this path \
             is stuck"
        );
    }

    /// Regression test (on-demand placeholder case, 2 of 2 sibling cases
    /// guarded here): a path settled by writing an on-demand placeholder
    /// must still close its
    /// obligation (via the non-exact completion primitive), but
    /// `path_materialized_generations` must hold NO row for it -- a
    /// placeholder is a policy-authorized deferral, never an exact claim
    /// about disk. Confirmed genuinely RED by temporarily swapping the
    /// OnDemand branch's terminal `Ok(MaterializeResult::Settled(
    /// SettlementEvidence::PolicyPlaceholder))` in `peer_session.rs` for an
    /// `ExactAbsent` one: the exact/non-exact split routes through
    /// materially different completion machinery (the exact side CASes on
    /// a filesystem mutation fence this scenario's fence snapshot does not
    /// satisfy), so the swap fails this test's very first assertion
    /// (obligation completion itself) rather than reaching the exact-
    /// generation check -- equally conclusive proof this test is not
    /// vacuous, and a stronger failure mode than a silently-wrong
    /// classification would be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn on_demand_placeholder_settlement_does_not_publish_an_exact_generation() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(
                &root.to_string_lossy(),
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();
        let key = SigningKey::from_bytes(&[91u8; 32]);
        let version = empty_version(1_700_000_900);
        admit_change(&state, "device-a", &key, "deferred.txt", &version);

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy, "the one, unraced candidate attempt must be trustworthy");

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "deferred.txt")
                .unwrap()
                .is_none(),
            "a placeholder settlement under a stable frontier must still close the obligation"
        );
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_materialized_generation(GROUP, "deferred.txt")
                .unwrap()
                .is_none(),
            "an on-demand placeholder must never publish an exact materialized generation -- it \
             is a scheduler-level settlement, not a claim about disk"
        );
        assert_eq!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state(GROUP, "deferred.txt")
                .unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Placeholder),
            "the durable record of what actually happened must be the placeholder state itself"
        );

        // With no exact record published, a later policy change to eager
        // must still find real hydration
        // work outstanding for this path -- not silently short-circuited by
        // a stale `path_materialized_generations` row that was never there.
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(
                &root.to_string_lossy(),
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
            )
            .unwrap();
        let candidates = state
            .replica_coordinator
            .materialization_state_repository()
            .list_materialization_repair_candidates(GROUP)
            .unwrap();
        assert_eq!(
            candidates,
            vec!["deferred.txt".to_string()],
            "an eager policy change must find the placeholder path as real outstanding \
             hydration work"
        );
    }

    /// Proves the `redelivered_known` removal was safe -- once admission-
    /// time invalidation (`bump_projection_obligations_for_touched_paths`)
    /// is the ONLY re-arm mechanism left (no redelivery-triggered re-
    /// enqueue exists anywhere any more), a path whose obligation already
    /// closed must still be correctly re-invalidated by a genuinely NEW,
    /// causally-descended admission -- not stuck forever just because its
    /// prior obligation row was deleted on completion. No redelivery of
    /// the first change happens anywhere in this test; the second
    /// admission alone is what re-arms it. Uses the real exact-outcome
    /// completion primitive (via `drive_obligations_once_for_test`, a real
    /// materialize + a real `dag_complete_obligation_if_exact_proof_
    /// current` call) rather than a hand-simulated non-exact stand-in, so
    /// the "obligation disappears" half of this proof is as faithful as
    /// this crate's own harness can make it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn completed_projection_is_invalidated_by_new_admission_without_any_duplicate_or_redelivery_traffic(
    ) {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[85u8; 32]);
        let version_1 = empty_version(1_700_000_500);
        let change_1 = admit_change(&state, "device-a", &key, "reinvalidated.txt", &version_1);

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
                .unwrap()
                .is_none(),
            "sanity: the first admission must fully settle and close its obligation"
        );

        // A genuinely NEW admission -- causally descended from the first,
        // never a redelivery of it -- touching the same path a second time.
        let version_2 = empty_version(1_700_000_600);
        let change_2 = Change::create_signed(
            vec![change_1.compute_hash()],
            change_1.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".to_string()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath("reinvalidated.txt".to_string()),
                version: version_2.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change_2, std::slice::from_ref(&version_2), true)
            .unwrap();

        let obligation_after_new_admission = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
            .unwrap()
            .expect(
                "a genuinely new admission on an already-settled path must re-create its \
                 obligation -- nothing else re-arms it any more",
            );
        assert_eq!(
            obligation_after_new_admission.invalidation_generation, 1,
            "a fresh row after the prior one was deleted on completion starts at generation 1 \
             again -- generation only needs to be locally monotonic between claim and close, \
             not globally monotonic across the path's whole history"
        );

        let healthy_again = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy_again, "the second, genuinely new obligation must also resolve cleanly");
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "reinvalidated.txt")
                .unwrap()
                .is_none(),
            "the second admission's own obligation must also close"
        );
    }

    /// The raced counterpart of the previous test, corrected by the
    /// Phase-E `wait_ready_first` stall investigation: a concurrent,
    /// UNRELATED admission ("other2.txt") landing mid-reconcile must NOT
    /// block "raced2.txt"'s own settlement -- this is the same scenario as
    /// `unrelated_path_head_movement_must_not_discard_an_already_settled_
    /// attempt` above, proven end to end here via a real `path_lock`-forced
    /// delay instead of `BeforeHeadsAfterHook`. This test used to assert
    /// the OPPOSITE (that the obligation must be left outstanding) under
    /// the old group-wide `before == after` heads-stability fence; that
    /// fence discarded raced2.txt's own already-resolved settlement purely
    /// because an unrelated path moved the group's heads in between, which
    /// `unrelated_path_head_movement_must_not_discard_an_already_settled_
    /// attempt`'s own doc comment explains was the direct mechanism behind
    /// the `wait_ready_first` arm's near-total stall. Confirmed genuinely
    /// RED against the (now-removed) `before == after` guard by restoring
    /// it locally and re-running: raced2.txt's publish/completion never ran,
    /// reproducing this test's own old (incorrect) expectation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn frontier_moving_mid_reconcile_on_an_unrelated_path_does_not_block_completion() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key_a = SigningKey::from_bytes(&[82u8; 32]);
        let key_b = SigningKey::from_bytes(&[83u8; 32]);
        let version = empty_version(1_700_000_200);
        admit_change(&state, "device-a", &key_a, "raced2.txt", &version);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "raced2.txt")
                .unwrap()
                .is_some(),
            "sanity: admission must have created an obligation"
        );

        let path_lock = state.replica_coordinator.path_lock(GROUP, "raced2.txt");
        let held = path_lock.lock().await;

        let state2 = state.clone();
        let handle = tokio::spawn(async move { drive_obligations_once_for_test(&state2, 128, 256).await });

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let version_b = empty_version(1_700_000_201);
        admit_change(&state, "device-b", &key_b, "other2.txt", &version_b);

        drop(held);
        let _ = handle.await.unwrap();

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_materialized_generation(GROUP, "raced2.txt")
                .unwrap()
                .is_some(),
            "raced2.txt's own settlement must publish even though an UNRELATED path's admission \
             moved the group's heads mid-reconcile"
        );
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "raced2.txt")
                .unwrap()
                .is_none(),
            "raced2.txt's obligation must close -- nothing about raced2.txt itself changed \
             during this attempt"
        );
    }

    fn symlink_version(mtime: i64, target: &[u8]) -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: Some(target.to_vec()),
                record_kind: RecordKind::Symlink,
                xattrs: Vec::new(),
            },
        )
    }

    /// Zero-work half: an obligation whose desired hash already
    /// matches a usable, disk-revalidating `path_materialized_generations`
    /// record -- published here directly, simulating a prior successful
    /// cycle, WITHOUT ever calling the obligation-driven worker first --
    /// closes on its very first claim with zero physical work. Proven not
    /// merely by "it closed" but by the published row's own `GenerationId`
    /// being byte-for-byte unchanged (a real materialize+republish always
    /// mints a fresh one) and the symlink's own filesystem identity
    /// (`object_id`, its inode) being unchanged (a real write always
    /// replaces the object via a fresh temp+rename). Uses a symlink, not a
    /// plain file: its `symlink_target_digest` discriminator is content,
    /// not a clock reading, so the assertion holds regardless of this
    /// sandbox's own birth-time-clock granularity (confirmed `Coarse` here
    /// via the real probe, which alone would leave a plain regular file's
    /// identity permanently `Ambiguous`, never `Confirmed`, on this exact
    /// filesystem). Confirmed genuinely RED by making `zero_work_
    /// settlement_for_path` unconditionally return `Ok(None)` (never
    /// authorizing the skip) -- that version made this test's
    /// `generation_id` assertion fail, since a real materialize ran and
    /// minted a new one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn zero_work_close_performs_no_physical_work() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[91u8; 32]);
        let version = symlink_version(1_700_000_300, b"target-content");
        admit_change(&state, "device-a", &key, "already-correct-link", &version);

        // Simulate "a prior successful materialize already left disk and
        // the proof table in agreement" -- written directly, never through
        // `drive_obligations_once_for_test`, which must not be called
        // before this point: the very first claim of this obligation must
        // already find zero work to do.
        let out_path = root.join("already-correct-link");
        std::os::unix::fs::symlink("target-content", &out_path).unwrap();
        let identity =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        assert!(
            identity.symlink_target_digest.is_some(),
            "sanity: a symlink observation must populate its content-based discriminator"
        );
        let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
        let fence = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, "already-correct-link").unwrap();
        let published = state
            .replica_coordinator
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                "already-correct-link",
                &heads,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Symlink,
                    version: version.version_hash,
                    identity: Some(identity),
                },
                fence,
            )
            .unwrap();
        assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

        let basis_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "already-correct-link")
            .unwrap()
            .unwrap();

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy, "the zero-work close itself still counts as a trustworthy tick");

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "already-correct-link")
                .unwrap()
                .is_none(),
            "the obligation must close"
        );
        let basis_after = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "already-correct-link")
            .unwrap()
            .unwrap();
        assert_eq!(
            basis_after.generation_id, basis_before.generation_id,
            "a zero-work close must never re-publish -- the GenerationId must be byte-for-byte \
             unchanged, not merely equal in content"
        );
        let identity_after =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        assert_eq!(
            identity_after.object_id, identity.object_id,
            "a zero-work close must never touch disk -- the symlink's own inode must be \
             unchanged, not merely its content"
        );
    }

    /// The zero-work close's companion: a usable record whose hash matches but whose
    /// disk revalidation fails (here, by publishing with no recorded
    /// `filesystem_identity` at all -- `revalidate_identity_against_disk`'s
    /// own doc comment: "there is nothing to revalidate against, so this
    /// check cannot confirm anything") must fail closed into a REAL
    /// materialize, not a zero-work close -- proven by a freshly minted
    /// `GenerationId` after the tick, this time carrying a real recorded
    /// identity a real write always produces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_usable_record_that_fails_revalidation_performs_real_work_instead() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[92u8; 32]);
        let version = empty_version(1_700_000_400);
        admit_change(&state, "device-a", &key, "unrevalidatable.txt", &version);

        let out_path = root.join("unrevalidatable.txt");
        std::fs::write(&out_path, b"").unwrap();
        let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
        let fence = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, "unrevalidatable.txt").unwrap();
        let published = state
            .replica_coordinator
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                "unrevalidatable.txt",
                &heads,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: version.version_hash,
                    // No identity recorded -- revalidation can never
                    // confirm this record, by design.
                    identity: None,
                },
                fence,
            )
            .unwrap();
        assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

        let basis_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "unrevalidatable.txt")
            .unwrap()
            .unwrap();

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy);

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "unrevalidatable.txt")
                .unwrap()
                .is_none(),
            "the obligation must still close -- via real work this time"
        );
        let basis_after = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "unrevalidatable.txt")
            .unwrap()
            .unwrap();
        assert_ne!(
            basis_after.generation_id, basis_before.generation_id,
            "a record that fails revalidation must be closed by a REAL materialize -- a fresh \
             GenerationId, not the pre-existing unrevalidatable one"
        );
        assert!(
            basis_after.filesystem_identity.is_some(),
            "the real materialize's own publish always records a real identity"
        );
    }

    /// Sanity check for `BeforeCompletionHook` itself, before it becomes
    /// load-bearing for any race regression: parking and resuming with
    /// nothing interleaved must reproduce the exact same outcome as the
    /// unhooked entrypoint -- the hook must be able to observe the worker
    /// reaching its pause point without changing what happens afterward.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn before_completion_hook_pauses_and_resumes_without_changing_the_outcome() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[93u8; 32]);
        let version = empty_version(1_700_000_500);
        admit_change(&state, "device-a", &key, "hooked.txt", &version);

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await
        });

        hooks.wait_parked().await;
        // Nothing interleaved here -- this is the sanity case, not a race.
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "hooked.txt")
                .unwrap()
                .is_some(),
            "the obligation must still be outstanding while the worker is parked before its own \
             completion CAS"
        );
        hooks.resume();

        let healthy = handle.await.unwrap();
        assert!(healthy);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "hooked.txt")
                .unwrap()
                .is_none(),
            "resuming an uninterleaved pause must close the obligation exactly as the unhooked \
             path does"
        );
    }

    /// The publication race: a real materialize succeeds and publishes
    /// evidence under a live mutation-fence value E, but before the
    /// completion CAS runs, an INDEPENDENT mutator (one the DAG never saw)
    /// bumps the fence to E+1 and rewrites the path. The claimed DAG-side
    /// generation `G` never moves in this scenario at all -- proving that
    /// the completion's refusal comes from the live fence mismatch (b), not
    /// from any generation check (a). Confirmed genuinely RED by
    /// temporarily dropping the fence/hash `EXISTS` clause from
    /// `complete_obligation_if_exact_proof_current`'s `DELETE` statement
    /// (leaving only the generation check): the completion then wrongly
    /// reported success and closed the obligation despite the independent
    /// mutation. Restored and reconfirmed GREEN.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publication_succeeds_but_later_mutation_before_close_prevents_completion() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[94u8; 32]);
        let version = empty_version(1_700_000_600);
        admit_change(&state, "device-a", &key, "raced-publish.txt", &version);

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced-publish.txt")
            .unwrap()
            .expect("admission must have created an obligation");
        let claimed_g = obligation_before.invalidation_generation;

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await
        });

        // The worker parks only after a real materialize published its
        // evidence under a live fence value -- confirm that proof is
        // genuinely usable right now, before racing it.
        hooks.wait_parked().await;
        let proof_before_race = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "raced-publish.txt")
            .unwrap()
            .expect("the publish this worker just made must be usable at the moment it parks");

        // An independent mutator the DAG never saw: bumps the fence AND
        // rewrites the path, entirely outside this attempt's own view.
        let out_path = root.join("raced-publish.txt");
        std::fs::write(&out_path, b"independent-mutator-content").unwrap();
        state
            .replica_coordinator
            .dag_bump_mutation_fence(GROUP, "raced-publish.txt", "independent-mutator")
            .unwrap();

        hooks.resume();
        let _ = handle.await.unwrap();

        let obligation_after = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced-publish.txt")
            .unwrap()
            .expect("a raced completion must never close the obligation");
        assert_eq!(
            obligation_after.invalidation_generation, claimed_g,
            "G never moved in this scenario -- the obligation must be left at exactly the \
             generation it was claimed at, proving the refusal came from the live fence \
             mismatch, not a generation check"
        );
        assert_eq!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_materialized_generation(GROUP, "raced-publish.txt")
                .unwrap(),
            None,
            "the proof this attempt published is now unusable -- its own fence value no longer \
             equals the path's live fence, which the independent mutator advanced"
        );
        // Sanity: the proof really was different before and after the race,
        // not merely absent both times for an unrelated reason.
        assert!(proof_before_race.filesystem_identity.is_some());
    }

    /// The zero-work variant of the same race: a worker's identity
    /// revalidation passes (the record is usable and its hash matches the
    /// freshly resolved desired state), genuinely entering the zero-work
    /// branch -- proven here by the path's own inode being unchanged right
    /// up to the pause point, since a real materialize would already have
    /// rewritten it via a fresh temp+rename before ever reaching this same
    /// pause point. Then, before the completion statement runs, an
    /// independent mutator bumps the fence and rewrites the path. The
    /// completion must still refuse to close -- proving explicitly that
    /// 3.16's revalidation could not have caught this (its own stat ran
    /// *before* the interleaving mutation) and that the only real
    /// guarantee comes from the completion's own live fence re-check. A
    /// second, uninterleaved tick afterward must then perform REAL
    /// physical work (not another zero-work skip) and succeed, since the
    /// record the first attempt would have relied on is no longer usable.
    /// Confirmed genuinely RED against an `invalidation_generation`-only
    /// completion by temporarily replacing the fence/hash `EXISTS` clause
    /// with a tautology: the completion then wrongly closed the obligation
    /// despite the independent mutation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn zero_work_revalidation_raced_by_mutator_cannot_close() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[95u8; 32]);
        let version = symlink_version(1_700_000_700, b"original-target");
        admit_change(&state, "device-a", &key, "raced-zero-work-link", &version);

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
            .unwrap()
            .expect("admission must have created an obligation");
        let claimed_g = obligation_before.invalidation_generation;

        // Simulate a prior successful cycle, exactly like `zero_work_close_
        // performs_no_physical_work` -- disk and the proof table already
        // agree, entirely independent of anything the worker itself does.
        let out_path = root.join("raced-zero-work-link");
        std::os::unix::fs::symlink("original-target", &out_path).unwrap();
        let identity_at_seed =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        let heads = state.replica_coordinator.sqlite().dag_group_heads(GROUP).unwrap();
        let fence = state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, "raced-zero-work-link").unwrap();
        let published = state
            .replica_coordinator
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                "raced-zero-work-link",
                &heads,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::Symlink,
                    version: version.version_hash,
                    identity: Some(identity_at_seed.clone()),
                },
                fence,
            )
            .unwrap();
        assert!(published, "sanity: the simulated prior-cycle publish must itself succeed");

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await
        });

        hooks.wait_parked().await;
        // The zero-work branch was genuinely entered: the object's own
        // inode is unchanged since seeding, proving no real write ran
        // between the claim and this pause point.
        let identity_at_pause =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        assert_eq!(
            identity_at_pause.object_id, identity_at_seed.object_id,
            "the worker must have taken the zero-work path -- a real materialize would already \
             have rewritten this object via a fresh temp+rename before reaching this pause point"
        );

        // An independent mutator the DAG never saw: bumps the fence AND
        // rewrites the path out from under the revalidation that already
        // passed.
        std::fs::remove_file(&out_path).unwrap();
        std::os::unix::fs::symlink("independent-mutator-target", &out_path).unwrap();
        state
            .replica_coordinator
            .dag_bump_mutation_fence(GROUP, "raced-zero-work-link", "independent-mutator")
            .unwrap();

        hooks.resume();
        let _ = handle.await.unwrap();

        let obligation_after = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
            .unwrap()
            .expect("a raced zero-work completion must never close the obligation");
        assert_eq!(
            obligation_after.invalidation_generation, claimed_g,
            "G never moved -- the refusal must come from the live fence mismatch the \
             revalidation's own earlier stat could not have observed, not a generation check"
        );
        let basis_after_race = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "raced-zero-work-link")
            .unwrap();
        assert_eq!(
            basis_after_race, None,
            "the record the zero-work decision relied on is now unusable -- its fence no longer \
             equals the path's live fence"
        );

        // A second, uninterleaved tick must perform REAL physical work
        // this time (the old record is unusable, so there is nothing left
        // to skip against) and actually close.
        let healthy_second_tick = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy_second_tick);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "raced-zero-work-link")
                .unwrap()
                .is_none(),
            "the second tick must close the obligation via real work"
        );
        let basis_final = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "raced-zero-work-link")
            .unwrap()
            .expect("the second tick's real materialize must publish a fresh, usable proof");
        let identity_final =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        assert_ne!(
            identity_final.object_id, identity_at_pause.object_id,
            "the second tick's real materialize must have actually rewritten the object -- a \
             fresh inode, not the independent mutator's own leftover one"
        );
        assert_eq!(
            basis_final.filesystem_identity.map(|i| i.object_id),
            Some(identity_final.object_id),
            "the freshly published proof must describe the object the real materialize actually \
             produced"
        );
    }

    /// The deferred crash-cycle regression: desired state cycles A -> B ->
    /// A around a crash that lands strictly between B's physical mutation
    /// and its publication/close. The path materializes to A and closes
    /// normally; a second admission makes B desired; a mutator (standing
    /// in for the worker's own materialize call, immediately before an
    /// unmodeled crash) bumps the fence and rewrites disk to B, but the
    /// crash means NEITHER the publish NOR the completion for B ever runs;
    /// a third admission cycles the desired state back to A. The worker
    /// must not read the still-present, hash-matching original A proof as
    /// "already satisfied" -- its fence no longer matches (B's mutator
    /// moved it), so it must perform a REAL materialize back to A rather
    /// than a false zero-work close that would silently leave disk on B
    /// forever.
    ///
    /// "With identity revalidation disabled" (this task's own extra
    /// requirement) is proven architecturally rather than via a runtime
    /// toggle: `dag_zero_work_settlement_if_already_current`'s own code
    /// returns `None` the instant `dag_lookup_materialized_generation`
    /// reports no usable row, before `revalidate_identity_against_disk` is
    /// ever called -- so asserting that lookup already returns `None`
    /// right after the third admission (checked explicitly below, before
    /// the recovering tick even runs) proves the fence check alone
    /// accounts for this, independent of whatever identity revalidation
    /// would or would not have separately concluded.
    ///
    /// Confirmed genuinely RED by temporarily replacing `lookup_
    /// materialized_generation`'s own fence-join predicate
    /// (`g.published_under_mutation_generation = f.mutation_generation`)
    /// with a tautology: the stale A proof was then wrongly reported
    /// usable immediately after the third admission, exactly reproducing
    /// what a "the fence only moves when a publish actually succeeds"
    /// implementation would do -- a crashed, unpublished mutation would
    /// leave the fence (and thus the old proof's apparent validity)
    /// completely untouched, letting a later desired-state cycle-back
    /// silently confirm zero work while disk was actually still on B.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn desired_state_cycling_back_after_a_crash_mid_mutation_does_not_close_with_zero_work() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[96u8; 32]);
        let path = "cycle-link";
        let out_path = root.join(path);

        // A materializes and closes normally.
        let version_a = symlink_version(1_700_000_800, b"content-a");
        let change_a = admit_change(&state, "device-a", &key, path, &version_a);
        assert!(drive_obligations_once_for_test(&state, 128, 256).await);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, path)
                .unwrap()
                .is_none(),
            "sanity: A must materialize and close normally"
        );
        assert_eq!(std::fs::read_link(&out_path).unwrap().to_str().unwrap().as_bytes(), b"content-a");
        let basis_a = state.replica_coordinator.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap().unwrap();

        // A second admission, causally descending from the first, makes B
        // desired. Deliberately never ticked.
        let version_b = symlink_version(1_700_000_801, b"content-b");
        let change_b = Change::create_signed(
            vec![change_a.change_hash()],
            change_a.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put { path: SyncPath(path.to_string()), version: version_b.version_hash, origin: PutOrigin::Direct }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change_b, std::slice::from_ref(&version_b), true)
            .unwrap();

        // Stands in for the worker's own materialize call immediately
        // before an unmodeled crash: the fence is bumped (the established
        // "before the first mutating syscall" ordering) and disk is
        // physically rewritten to B, but the crash means neither the
        // publish nor the completion for B ever runs.
        std::fs::remove_file(&out_path).unwrap();
        std::os::unix::fs::symlink("content-b", &out_path).unwrap();
        state.replica_coordinator.dag_bump_mutation_fence(GROUP, path, "simulated-crash-write").unwrap();

        // A third admission, causally descending from the second, cycles
        // the desired state back to A.
        let change_a2 = Change::create_signed(
            vec![change_b.change_hash()],
            change_b.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put { path: SyncPath(path.to_string()), version: version_a.version_hash, origin: PutOrigin::Direct }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change_a2, std::slice::from_ref(&version_a), true)
            .unwrap();

        // Architectural proof that the fence check alone rejects the stale
        // A proof, before any identity revalidation could even run.
        assert_eq!(
            state.replica_coordinator.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap(),
            None,
            "the crash-orphaned A proof must already be unusable via the fence check alone, \
             even though its hash matches the freshly-restored desired state and disk still \
             visibly holds B"
        );

        // The recovering tick must perform REAL work, not a false
        // zero-work close.
        assert!(drive_obligations_once_for_test(&state, 128, 256).await);
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, path)
                .unwrap()
                .is_none(),
            "the obligation must close via real work"
        );
        assert_eq!(
            std::fs::read_link(&out_path).unwrap().to_str().unwrap().as_bytes(),
            b"content-a",
            "disk must end holding A, not the crash-orphaned B a false zero-work close would \
             have silently left behind forever"
        );
        let basis_final = state.replica_coordinator.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap().unwrap();
        assert_ne!(
            basis_final.generation_id, basis_a.generation_id,
            "a fresh publish from the recovering real materialize, not the original A publish \
             reused"
        );
    }

    /// The obligation-driven scheduler's own version of the publication
    /// race: a lost fence CAS (`Ok(false)`, a perfectly normal outcome, not
    /// an error) must never be treated as "this path settled" --
    /// `complete_one_obligation` must leave the obligation outstanding for
    /// re-resolution, not silently close it, while disk actually holds
    /// whatever the independent mutator wrote. Migrated from this test's
    /// original `materialization_jobs`-based form (which asserted a
    /// `Backoff` job state) once Phase D retired that table as a
    /// scheduling source -- the obligation-driven completion path handles
    /// this race differently (leaves the row completely untouched rather
    /// than an explicit penalized backoff, since it's evidence of
    /// legitimate concurrent activity, not a real failure), but the
    /// essential property is identical: never falsely mark complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_lost_publication_cas_leaves_the_obligation_outstanding_not_completed() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[97u8; 32]);
        let version = empty_version(1_700_000_900);
        admit_change(&state, "device-a", &key, "obligation-scheduler-race.txt", &version);

        let generation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "obligation-scheduler-race.txt")
            .unwrap()
            .expect("sanity: an obligation must exist after admission")
            .invalidation_generation;

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await
        });

        // The worker parks only after a real materialize succeeded and is
        // about to publish -- an independent mutator races it here.
        hooks.wait_parked().await;
        let out_path = root.join("obligation-scheduler-race.txt");
        std::fs::write(&out_path, b"independent-mutator-content").unwrap();
        state
            .replica_coordinator
            .dag_bump_mutation_fence(GROUP, "obligation-scheduler-race.txt", "independent-mutator")
            .unwrap();
        hooks.resume();
        let _ = handle.await.unwrap();

        let obligation_after_race = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "obligation-scheduler-race.txt")
            .unwrap()
            .expect(
                "a lost publication CAS must never let the obligation close -- this device can \
                 no longer vouch for what disk holds, exactly the race Stage 3/4's fence \
                 mechanism exists to detect",
            );
        assert_eq!(
            obligation_after_race.invalidation_generation, generation_before,
            "sanity: no new admission happened here, only an independent disk mutation"
        );
        assert_eq!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_materialized_generation(GROUP, "obligation-scheduler-race.txt")
                .unwrap(),
            None,
            "sanity: nothing was actually published under the now-stale fence value"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            b"independent-mutator-content",
            "the independent mutator's own content must survive -- the raced worker's publish \
             lost and must not have overwritten it"
        );
    }

    /// A second candidate session, registered for a test that needs two
    /// distinct peer slots so `process_group_via_obligations`'s own
    /// rotation window (`MAX_PEERS_PER_TICK = 2`) actually tries a second
    /// one -- mirrors `build_state_with_adopted_group`'s own
    /// session-construction exactly, under a different device id.
    fn register_second_candidate_session(state: &Arc<DaemonState>, root: &std::path::Path) {
        let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
        let session = PeerSyncSession::new_with_dependencies(
            Arc::new(NoopChannel),
            "device-local".to_string(),
            "device-peer-2".to_string(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(state.block_store.clone())),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), root.to_path_buf())]),
            Some(state.forward_tx.clone()),
            deps,
        );
        state.peers.register_session("device-peer-2".to_string(), session);
    }

    /// A version whose one content block was never stored anywhere -- both
    /// `NoopChannel`-backed candidates in this test's harness refuse
    /// `open_block_stream`, so materializing this version can never
    /// succeed via either one, leaving it `RetryRequired` forever. Exists
    /// purely to force a tick's rotation to try a SECOND candidate (the
    /// first one's own attempt never empties `remaining`).
    fn version_with_an_unfetchable_block(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![yadorilink_replica_domain::file::VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(vec![0x42; 32]),
                size: 4,
            }],
            4,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    /// Both the live job-based scheduler and the obligation-driven worker
    /// share this shape: `if remaining.is_empty() { break }`, but the
    /// reconcile call handed to the NEXT candidate was the ORIGINAL
    /// `budget`, not the shrunk `remaining` -- meaning a path a candidate
    /// already settled and closed gets handed to a SECOND candidate again
    /// within the very same tick, purely because SOME OTHER path in the
    /// budget is still unresolved. Proven here at the obligation-driven
    /// worker (the more consequential of the two: a redundant re-attempt
    /// there means a real second materialize/publish against a path whose
    /// obligation the first attempt already deleted): a fully-resolvable
    /// path is settled by the first candidate; an unrelated,
    /// permanently-unfetchable path forces the rotation to try a second
    /// candidate; `complete_one_obligation`'s own `BeforeCompletionHook`
    /// pause must fire EXACTLY ONCE for the settled path this tick, since
    /// a correct worker never asks the second candidate to examine it
    /// again -- counted directly by racing the hook's pause against the
    /// worker task's own completion, rather than inferring it indirectly
    /// from published state, since (as an earlier draft of this exact test
    /// found) a redundant republish under an unchanged fence is not
    /// otherwise distinguishable from a legitimate one by the time the
    /// whole tick has already finished. Confirmed genuinely RED by
    /// temporarily reverting the reconcile call back to `budget.clone()`:
    /// the pause fired twice, once per candidate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_settled_path_is_never_handed_to_a_second_candidate_in_the_same_tick() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        register_second_candidate_session(&state, &root);
        // `live_authorized_groups` only ever starts from the constructor's
        // one-time snapshot; nothing in this bare unit-test harness performs
        // the ongoing netmap-driven re-validation a running daemon
        // (`run(state)`) would (see `shares_group`'s own doc comment). An
        // earlier draft of this exact test silently ran with only ONE
        // candidate ever authorized -- the very race window this test needs
        // two live candidates to exercise -- until this explicit re-grant
        // was added; it is a direct stand-in for the real netmap grant a
        // live daemon would issue.
        for (_, session) in state.peers.all_sessions() {
            session.grant_group(GROUP);
        }

        let key = SigningKey::from_bytes(&[98u8; 32]);
        admit_change(&state, "device-a", &key, "settles-on-first-candidate.txt", &empty_version(1_700_001_000));
        admit_change(&state, "device-a", &key, "never-resolves.txt", &version_with_an_unfetchable_block(1_700_001_001));

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let mut handle =
            tokio::spawn(async move { drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await });

        let mut pause_count = 0usize;
        let healthy = loop {
            tokio::select! {
                _ = hooks.wait_parked() => {
                    pause_count += 1;
                    hooks.resume();
                }
                result = &mut handle => {
                    break result.unwrap();
                }
            }
        };
        assert!(healthy);

        assert_eq!(
            pause_count, 1,
            "the settled path's own completion pause must fire exactly once this tick -- a \
             second firing means a second candidate redundantly re-examined a path the first \
             one already closed"
        );
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "settles-on-first-candidate.txt")
                .unwrap()
                .is_none(),
            "sanity: the resolvable path must have closed"
        );
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "never-resolves.txt")
                .unwrap()
                .is_some(),
            "sanity: the unfetchable path must still be outstanding -- this is what forces a \
             second candidate to be tried at all"
        );
    }

    /// The obligation-driven scheduler's own per-group path-budget rotation
    /// (ported from `process_group`'s `MAX_PATHS_PER_RECONCILE_ATTEMPT`
    /// windowing): a group with more outstanding paths than one attempt's
    /// cap must only have a bounded window resolved per call, with the
    /// unresolved remainder picked up by a later call, not handed to
    /// `reconcile_paths_directly` all at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn obligation_driven_path_budget_rotation_resolves_the_remainder_on_a_later_call() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[91u8; 32]);
        let path_count = MAX_PATHS_PER_RECONCILE_ATTEMPT + 2;
        for i in 0..path_count {
            let version = empty_version(1_700_000_200 + i as i64);
            admit_change(&state, "device-a", &key, &format!("budget-{i:02}.txt"), &version);
        }

        let closed_count = || {
            (0..path_count)
                .filter(|i| {
                    state
                        .replica_coordinator
                        .sqlite()
                        .dag_lookup_projection_obligation(GROUP, &format!("budget-{i:02}.txt"))
                        .unwrap()
                        .is_none()
                })
                .count()
        };

        let healthy_first = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy_first);
        assert_eq!(
            closed_count(),
            MAX_PATHS_PER_RECONCILE_ATTEMPT,
            "exactly one path-budget window's worth of paths must close on the first call"
        );

        let healthy_second = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy_second);
        assert_eq!(
            closed_count(),
            path_count,
            "the remainder must close once the path-budget cursor reaches it on a later call"
        );
    }

    /// `crate::c4_diag`'s counters are process-wide globals shared by the
    /// whole test binary -- serializes every test in this module that reads
    /// them via `reset()`/`stats()`, mirroring `yadorilink-sync-sqlite`'s
    /// own `c4_diag_test_guard` (same reasoning: a sibling test's own
    /// obligation-engine ticks running concurrently would otherwise
    /// silently inflate this one's reset-to-stats window).
    fn c4_diag_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// F2 / decision-9 regression (128-claim / 8-path zero-work-precheck
    /// amplification): before this fix, the zero-work pre-check loop ran
    /// over every claimed path (up to the claim limit), even though at
    /// most `MAX_PATHS_PER_RECONCILE_ATTEMPT` of them could ever reach a
    /// real reconcile attempt the same tick -- an up-to-16x resolution
    /// amplification with no throughput benefit. Seeds well more than
    /// `MAX_PATHS_PER_RECONCILE_ATTEMPT` runnable obligations (comfortably
    /// inside the claim limit) and asserts one scheduler tick attempts a
    /// zero-work check for AT MOST `MAX_PATHS_PER_RECONCILE_ATTEMPT` of
    /// them, and that repeated ticks eventually rotate through every one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn zero_work_precheck_examines_at_most_the_path_budget_window_per_tick() {
        let _guard = c4_diag_test_guard();
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[97u8; 32]);
        const N: usize = MAX_PATHS_PER_RECONCILE_ATTEMPT * 3 + 1;
        for i in 0..N {
            let version = empty_version(1_700_000_500 + i as i64);
            admit_change(&state, "device-a", &key, &format!("precheck-{i:03}.txt"), &version);
        }

        // `crate::c4_diag`'s counters are process-wide globals shared by
        // the whole test binary (see `c4_diag_test_guard`'s own doc
        // comment) -- this file has many OTHER tests driving the
        // obligation engine that do not take that guard, so a strict
        // `<= MAX_PATHS_PER_RECONCILE_ATTEMPT` bound is not reliably
        // reproducible under full concurrent test execution even with the
        // guard held (it only serializes tests that opt in). A tolerance
        // of double the window still separates the bug this pins (the OLD
        // code attempted all N=25 paths every tick) from a HANDFUL of
        // concurrent-sibling-test contributions by a comfortable margin.
        crate::c4_diag::reset();
        drive_obligations_once_for_test(&state, 128, 256).await;
        let attempted_first_tick = crate::c4_diag::stats().zero_work_attempted;
        const TOLERANCE: u64 = (MAX_PATHS_PER_RECONCILE_ATTEMPT * 2) as u64;
        assert!(
            attempted_first_tick <= TOLERANCE,
            "one scheduler tick must not zero-work-check meaningfully more than the path-budget \
             window (MAX_PATHS_PER_RECONCILE_ATTEMPT={MAX_PATHS_PER_RECONCILE_ATTEMPT}, \
             tolerance={TOLERANCE}) out of {N} seeded/claimable paths; got {attempted_first_tick} \
             -- the pre-fix behavior attempted all {N}"
        );

        // Every path must still eventually be covered across repeated
        // ticks -- the fix must narrow PER-TICK amplification, not silently
        // drop coverage of the unwindowed remainder.
        let closed_count = |state: &Arc<DaemonState>| {
            (0..N)
                .filter(|i| {
                    state
                        .replica_coordinator
                        .sqlite()
                        .dag_lookup_projection_obligation(GROUP, &format!("precheck-{i:03}.txt"))
                        .unwrap()
                        .is_none()
                })
                .count()
        };
        for _ in 0..(N / MAX_PATHS_PER_RECONCILE_ATTEMPT + 2) {
            drive_obligations_once_for_test(&state, 128, 256).await;
        }
        assert_eq!(
            closed_count(&state),
            N,
            "every seeded path must eventually close across repeated ticks, not just the first \
             tick's windowed subset"
        );
    }

    /// A genuine `RetryRequired` outcome (an unfetchable block, so
    /// `materialize` can never settle the path) must back the obligation
    /// off -- not be reclaimed again on the very next tick, which would
    /// otherwise spin retrying the identical unreachable fetch as fast as
    /// the scheduler loop can tick.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_genuine_retry_required_outcome_backs_off_instead_of_spinning() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[97u8; 32]);
        admit_change(&state, "device-a", &key, "unfetchable.bin", &version_with_an_unfetchable_block(1_700_002_000));

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy, "the one, unraced candidate attempt must itself be trustworthy");

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "unfetchable.bin")
            .unwrap()
            .expect("an unfetchable path must remain outstanding, never falsely closed");
        assert_eq!(obligation.attempt_count, 1, "the failed attempt must be recorded");
        assert!(
            obligation.next_attempt_at > 1_700_002_000,
            "the backoff deadline must be pushed into the future, not left immediately claimable"
        );

        let immediate_reclaim = state
            .replica_coordinator
            .sqlite()
            .dag_claim_runnable_obligations(1_700_002_000, 128, 256)
            .unwrap();
        assert!(
            immediate_reclaim.is_empty(),
            "must not be reclaimable again before its own backoff deadline passes"
        );
    }

    /// No connected peer at all is a stable condition (it stays true every
    /// tick until one connects), not a transient race -- it must back off
    /// durably (a real, growing delay, exactly like a genuine `RetryRequired`
    /// outcome), never spin at full speed re-checking `candidate_sessions`
    /// every tick forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_connected_peer_backs_off_durably_instead_of_spinning() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        state.peers.remove("device-peer");
        let key = SigningKey::from_bytes(&[96u8; 32]);
        admit_change(&state, "device-a", &key, "no-peer.txt", &empty_version(1_700_004_000));

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(!healthy, "no candidate at all must never report a trustworthy audit");

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "no-peer.txt")
            .unwrap()
            .expect("must remain outstanding with no peer to serve it");
        assert_eq!(obligation.attempt_count, 1, "no-peer-connected must count as a real failed attempt");
        assert!(
            obligation.next_attempt_at > 1_700_004_000,
            "must be backed off into the future, not left immediately reclaimable"
        );
    }

    /// `origin_candidate_index_for_obligations` must resolve the path's
    /// CURRENT desired-state winner's author, not merely echo whichever
    /// device happens to be first in `candidates`. Two candidate sessions
    /// are registered ("device-peer", "device-peer-2"); the admitted
    /// change's own author id is "device-peer-2", so the resolved winner's
    /// `device_id` must match that candidate specifically, regardless of
    /// its position in the (alphabetically-sorted) candidate list.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn origin_first_resolves_the_current_desired_state_winners_author() {
        let (state, _root_dir, root) = build_state_with_adopted_group().await;
        register_second_candidate_session(&state, &root);
        for (_, session) in state.peers.all_sessions() {
            session.grant_group(GROUP);
        }

        // The admitted change's author is itself one of the two candidate
        // device ids -- realistic in that the authoring peer is exactly who
        // is most likely to actually hold this content.
        let key = SigningKey::from_bytes(&[95u8; 32]);
        admit_change(&state, "device-peer-2", &key, "origin-test.txt", &empty_version(1_700_005_000));

        let candidates = crate::hydration::candidate_sessions(&state, GROUP);
        assert_eq!(candidates.len(), 2, "sanity: both candidates must be registered");
        let budget: std::collections::BTreeSet<String> = ["origin-test.txt".to_string()].into();

        let origin_index = super::origin_candidate_index_for_obligations(
            &candidates[0].1,
            GROUP,
            &budget,
            &candidates,
        );
        let origin_index = origin_index.expect("a resolvable winner must produce an origin preference");
        assert_eq!(
            candidates[origin_index].0, "device-peer-2",
            "the origin preference must name the path's actual current-desired-state author"
        );
    }

    /// Disk-pressure handling is not scheduler-specific machinery to port:
    /// `process_group_via_obligations` reaches the exact same `materialize`/
    /// `preflight_disk_headroom` path `process_group` does, through the
    /// exact same `reconcile_paths_directly` entry point -- so a headroom
    /// failure surfaces as an ordinary retriable outcome here too, with no
    /// separate disk-space check needed in the scheduler itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_disk_headroom_failure_is_an_ordinary_retriable_outcome_not_a_false_close() {
        let (state, root_dir, _root) = build_state_with_adopted_group().await;
        let session = state.peers.session("device-peer").expect("sanity: candidate must be registered");
        // An impossible headroom reserve guarantees `check_disk_headroom`
        // rejects every write, standing in for a genuinely full disk.
        session.set_headroom_enforced(true);
        session.set_headroom_override_bytes(Some(u64::MAX));

        let key = SigningKey::from_bytes(&[94u8; 32]);
        admit_change(&state, "device-a", &key, "no-space.txt", &empty_version(1_700_006_000));

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy, "the candidate attempt itself is trustworthy -- the write failing is not a raced/skipped audit");

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "no-space.txt")
            .unwrap()
            .expect("a disk-pressure failure must never falsely close the obligation");
        assert_eq!(obligation.attempt_count, 1, "a real materialize failure must count as a failed attempt");
        assert!(
            obligation.next_attempt_at > 1_700_006_000,
            "must be backed off, exactly like any other genuine RetryRequired outcome"
        );
        assert!(
            !root_dir.path().join("no-space.txt").exists(),
            "sanity: the write must have actually been blocked, not silently succeeded"
        );
    }

    /// A real exact-outcome obligation completion must wake the retirement
    /// and hazard-recheck loops -- the SAME reasoning `process_group`'s own
    /// post-`Completed` wakes already document (a copy this attempt just
    /// made durable could supersede a sibling conflict copy's justification,
    /// or be exactly the sibling change that clears some held path's
    /// hazard), now needed here too since Phase D removes the legacy
    /// completion path (and its wakes) entirely.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_real_completion_wakes_retirement_and_hazard_recheck() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[93u8; 32]);
        admit_change(&state, "device-a", &key, "wakes-siblings.txt", &empty_version(1_700_007_000));

        assert!(state.replica_coordinator.retirement_wake().pending().get(GROUP).is_none());
        assert!(state.replica_coordinator.hazard_recheck_wake().pending().get(GROUP).is_none());

        let healthy = drive_obligations_once_for_test(&state, 128, 256).await;
        assert!(healthy);
        assert!(
            state.replica_coordinator.sqlite().dag_lookup_projection_obligation(GROUP, "wakes-siblings.txt").unwrap().is_none(),
            "sanity: the obligation must have actually closed"
        );

        assert!(
            state.replica_coordinator.retirement_wake().pending().get(GROUP).is_some(),
            "a real completion must mark the retirement loop dirty for this group"
        );
        assert!(
            state.replica_coordinator.hazard_recheck_wake().pending().get(GROUP).is_some(),
            "a real completion must mark the hazard-recheck loop dirty for this group"
        );
    }

    /// Phase-E `wait_ready_first` stall investigation, boundary 1 of 2: the
    /// group-wide heads-stability fence itself (`process_group_via_
    /// obligations`'s `before == after` on `dag_group_heads`, gating
    /// whether an ENTIRE `reconcile_paths_directly` attempt's settlements
    /// publish/complete, or are discarded whole).
    ///
    /// x.txt's own attempt resolves (its desired state/evidence is fully
    /// computed) while parked at [`BeforeHeadsAfterHook`] -- the pause
    /// point strictly BETWEEN the pre-attempt `heads_before` read and the
    /// post-attempt `heads_after` re-read, which [`BeforeCompletionHook`]
    /// cannot reach (it only pauses once `before == after` has ALREADY
    /// been checked and passed). While parked, an UNRELATED path
    /// (`y-unrelated.txt`) is admitted -- a genuinely new historical
    /// change, exactly like the two-arm test's own `wait_ready_first`
    /// catch-up admitting new changes at ~15/s while B's per-tick
    /// `reconcile_paths_directly` calls are in flight -- which moves the
    /// group's heads without ever touching x.txt.
    ///
    /// Expected (and currently RED): x.txt's own settlement must still
    /// close, because nothing about x.txt itself changed -- the per-path
    /// completion CAS (claimed generation/incarnation plus the live
    /// mutation fence, exercised by `publication_succeeds_but_later_
    /// mutation_before_close_prevents_completion` and `zero_work_
    /// revalidation_raced_by_mutator_cannot_close` above) is what should
    /// decide currency, not a whole-group heads comparison. Under the
    /// current code this assertion fails: `before != after` discards the
    /// WHOLE attempt, including x.txt's own already-resolved settlement,
    /// leaving its obligation outstanding for no reason connected to
    /// x.txt at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unrelated_path_head_movement_must_not_discard_an_already_settled_attempt() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[100u8; 32]);
        admit_change(&state, "device-a", &key, "x.txt", &empty_version(1_700_008_000));

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "x.txt")
                .unwrap()
                .is_some(),
            "sanity: admission must have created an obligation for x.txt"
        );

        let heads_hook = BeforeHeadsAfterHook::new();
        let state2 = state.clone();
        let heads_hook2 = heads_hook.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_heads_hook(&state2, 128, 256, &heads_hook2).await
        });

        // Parked exactly after x.txt's own attempt resolved, before the
        // group's post-attempt heads re-read.
        heads_hook.wait_parked().await;

        // A genuinely new historical change, touching ONLY an unrelated
        // path -- advances the group's heads without touching x.txt.
        let key_y = SigningKey::from_bytes(&[101u8; 32]);
        admit_change(&state, "device-a", &key_y, "y-unrelated.txt", &empty_version(1_700_008_001));

        heads_hook.resume();
        let _ = handle.await.unwrap();

        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "x.txt")
                .unwrap()
                .is_none(),
            "x.txt's own settlement must close even though an UNRELATED path's admission moved \
             the group's heads during the same reconcile attempt -- an unrelated path's DAG \
             activity must not invalidate a settlement this attempt already resolved for a \
             DIFFERENT path"
        );
    }

    /// Phase-E `wait_ready_first` stall investigation, boundary 2 of 2 (the
    /// converse control): proves the per-path completion CAS alone --
    /// independent of the heads-stability fence above -- already refuses
    /// to close a stale attempt when the SAME path it targets is admitted
    /// again while the attempt is in flight. This is the DAG-admission/`G`
    /// analogue of `publication_succeeds_but_later_mutation_before_close_
    /// prevents_completion` above (which races the live mutation fence
    /// `E`, not a DAG admission).
    ///
    /// x2.txt's first attempt is parked at the EXISTING
    /// [`BeforeCompletionHook`] -- after publish, immediately before the
    /// completion CAS, i.e. strictly AFTER the heads-stability fence
    /// already passed, so this scenario cannot be explained by that fence
    /// at all. While parked, a SECOND change touching x2.txt itself is
    /// admitted, causally descending from the first. The completion CAS
    /// must reject: its claimed generation/incarnation token no longer
    /// matches x2.txt's now-current row.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_path_admission_while_parked_is_independently_rejected_by_generation_cas() {
        let (state, _root_dir, _root) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[102u8; 32]);
        let version_x1 = empty_version(1_700_009_000);
        let change_x1 = admit_change(&state, "device-a", &key, "x2.txt", &version_x1);

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "x2.txt")
            .unwrap()
            .expect("admission must have created an obligation for x2.txt");
        let claimed_g = obligation_before.invalidation_generation;

        let hooks = BeforeCompletionHook::new();
        let state2 = state.clone();
        let hooks2 = hooks.clone();
        let handle = tokio::spawn(async move {
            drive_obligations_once_for_test_with_hooks(&state2, 128, 256, &hooks2).await
        });

        hooks.wait_parked().await;

        // A SECOND change touching the SAME path, causally descending
        // from the first -- the in-flight attempt's own claimed
        // generation is now behind the DAG's current one.
        let version_x2 = empty_version(1_700_009_001);
        let change_x2 = Change::create_signed(
            vec![change_x1.change_hash()],
            change_x1.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-a".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath("x2.txt".to_string()),
                version: version_x2.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change_x2, std::slice::from_ref(&version_x2), true)
            .unwrap();

        hooks.resume();
        let _ = handle.await.unwrap();

        let obligation_after = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "x2.txt")
            .unwrap()
            .expect(
                "the stale attempt must NOT close x2.txt's obligation -- a new admission \
                 touching the SAME path while it was in flight must leave it outstanding for \
                 re-resolution",
            );
        assert_ne!(
            obligation_after.invalidation_generation, claimed_g,
            "x2.txt's own generation must have moved due to the second admission touching it \
             directly, proving the refusal came from the per-path generation CAS, not the \
             (in this scenario already-passed) heads-stability fence"
        );
    }
}
