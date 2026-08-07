//! The Convergence Engine's scheduler loop: picks up `materialization_jobs`
//! rows `PeerSyncSession::handle_change_batch` enqueues (CONV-1: it never
//! awaits the fetch/materialize work itself) and drives them to completion
//! on its own schedule, using the SAME `reconcile_local_materialization_audit`
//! / `reconcile_group_paths` / `materialize` machinery this codebase already
//! had and already tests — this engine only changes *when* and *from where*
//! that machinery runs, not what it does internally.
//!
//! Stage 1 only ever drives a job through `Pending -> Planning ->
//! (Completed | Backoff)`; `WaitingForSource`/`WaitingForCredit`/`Fetching`/
//! `ReadyToCommit` are reachable states in `MaterializationJobState`'s own
//! transition table (for stage 2/3's credit-aware scheduling) but nothing in
//! this file produces them yet — `claim_runnable_jobs`'s query already
//! includes them for forward compatibility, but a stage-1-only build never
//! actually creates a job in one of those states, so `run_once`'s blind
//! `job.state -> Planning` transition (legal only from `Pending`/`Backoff`)
//! never has to handle them today.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::sync_error::SyncError;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sync_sqlite::dag_store::DagHashDisposition;
use yadorilink_sync_sqlite::{MaterializationJob, MaterializationJobState};

use crate::daemon_state::DaemonState;

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

/// How long an *active-processing* job (`Planning`/`Fetching`/
/// `ReadyToCommit` — states with no `next_retry_at` of their own) may sit
/// unchanged before `claim_runnable_jobs` treats it as abandoned and
/// reclaims it, independently of any daemon restart. Covers the case an
/// independent review caught: a job whose owning tick died between
/// claiming it and writing its final outcome (a scheduler-task panic, or
/// the final `Backoff`/`Completed` write itself failing) would otherwise
/// stay stuck in that exact state until the next full daemon restart —
/// `resume_after_restart` alone cannot help a same-process failure that
/// never actually restarts anything. Comfortably longer than this engine's
/// own worst-case single attempt (`MAX_PEERS_PER_TICK` sequential peer
/// tries, each up to `HYDRATION_TIMEOUT`) so a job still being legitimately
/// worked on is never mistaken for abandoned.
const STALE_ACTIVE_PROCESSING_THRESHOLD: Duration = Duration::from_secs(120);

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

/// Resolves the origin-first preference for `process_group`: describes each
/// budgeted job's `version_hash` (the admitted change that most recently
/// touched the path in the trigger batch — a heuristic for, not a
/// guarantee of, the path's winning author; resolution to a true winner is
/// deliberately deferred to the reconcile call itself) and returns the
/// index in `candidates` of the majority author's live session. `None`
/// when the author is this device itself, not currently connected, or no
/// job's hash resolves (e.g. the all-zero no-version sentinel).
fn origin_candidate_index<S>(
    state: &Arc<DaemonState>,
    jobs_in_group: &[MaterializationJob],
    budget: &BTreeSet<String>,
    candidates: &[(String, S)],
) -> Option<usize> {
    let authors = jobs_in_group.iter().filter(|job| budget.contains(&job.path)).filter_map(|job| {
        let bytes: [u8; 32] = job.version_hash.as_slice().try_into().ok()?;
        if bytes == [0u8; 32] {
            return None;
        }
        match state
            .replica_coordinator
            .change_history_repository()
            .dag_describe_hash(&ChangeHash(bytes))
        {
            Ok(DagHashDisposition::Admitted { change, .. }) => Some(change.device_id.0),
            _ => None,
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
pub async fn run(state: Arc<DaemonState>) {
    // A failure here means the daemon may hold non-terminal job rows this
    // engine's own stale-active-processing reclaim (see
    // `STALE_ACTIVE_PROCESSING_THRESHOLD`) would otherwise eventually pick
    // back up on its own — but a start-of-day recovery failure is still
    // worth treating as fatal-to-this-attempt rather than silently
    // deferring everything to that slower reclaim path. Return (not just
    // log-and-continue) so `supervise::spawn_restarting` treats this as a
    // failed attempt and retries with backoff, rather than starting a
    // scheduler loop on top of an unrecovered job table.
    if let Err(e) = resume_after_restart(&state) {
        tracing::error!(error = %e, "convergence engine failed to recover jobs at startup");
        return;
    }
    // Diagnostic-only tick counter, for the
    // `fix/conflict-copy-convergence-obligation-20260723` investigation --
    // proves directly whether this loop is still iterating at all (as
    // opposed to inferring it from whether `run_once` happened to find any
    // claimable work) and which branch woke it each time.
    let mut tick: u64 = 0;
    loop {
        run_once(&state).await;
        tick += 1;
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

/// Re-arms every job not `Completed`/`Superseded` to `Pending` at startup —
/// an in-progress job surviving a crash/restart is the normal case, not a
/// special one. In-memory fetch/gate state never survives a crash regardless
/// of what the row says, so resetting to `Pending` (re-planning from
/// scratch against the real, persisted block store) is the correct and
/// cheap thing to do rather than trying to resurrect partial fetch state
/// that was never itself persisted.
///
/// Deliberately calls `materialization_recover_after_restart`, NOT
/// `materialization_enqueue_pending` — a real bug an independent review
/// caught: `enqueue_pending`'s "same version + non-terminal state = no-op"
/// rule (correct for its own purpose — an ordinary re-admission must not
/// discard real in-progress work) means re-enqueuing a job at its OWN
/// unchanged `version_hash` (exactly what a crash-recovered row has, since
/// nothing new was admitted) is *always* a no-op for anything already past
/// `Pending` — silently leaving a job crashed mid-`Planning`/`Fetching`/
/// `ReadyToCommit` stuck in that exact state forever, invisible to
/// `claim_runnable_jobs`. `recover_after_restart` is a dedicated,
/// unconditional bulk re-arm with no such version guard.
fn resume_after_restart(state: &Arc<DaemonState>) -> Result<(), SyncError> {
    let now = now_unix_nanos();
    let recovered = state
        .replica_coordinator
        .materialization_job_repository()
        .materialization_recover_after_restart(now)?;
    if recovered > 0 {
        tracing::info!(count = recovered, "resumed unfinished materialization jobs after restart");
    }
    Ok(())
}

/// One scheduler tick: claims every currently-runnable job, groups by
/// `group_id`, and drives up to `MAX_CONCURRENT_GROUP_AUDITS` groups'
/// worth of `process_group` concurrently — one stalled group (e.g. every
/// path waiting on an unreachable sole source) must not hold up another
/// group whose jobs could complete instantly.
async fn run_once(state: &Arc<DaemonState>) {
    let now = now_unix_nanos();
    let stale_active_before = now - STALE_ACTIVE_PROCESSING_THRESHOLD.as_nanos() as i64;
    let runnable = match state
        .replica_coordinator
        .materialization_job_repository()
        .materialization_claim_runnable_jobs(
            now,
            stale_active_before,
            MAX_JOBS_PER_TICK_PER_GROUP,
            MAX_JOBS_PER_TICK,
        ) {
        Ok(jobs) => jobs,
        Err(e) => {
            tracing::warn!(error = %e, "convergence engine failed to claim runnable jobs");
            return;
        }
    };
    if runnable.is_empty() {
        return;
    }

    let mut jobs_by_group: HashMap<String, Vec<MaterializationJob>> = HashMap::new();
    for job in runnable {
        jobs_by_group.entry(job.group_id.clone()).or_default().push(job);
    }
    // Diagnostic-only: visibility into exactly which (group, path) pairs
    // `claim_runnable_jobs` actually selected this tick, for the
    // `taguchi_row_14` intermittent-stall investigation (see
    // `fix/conflict-copy-convergence-obligation-20260723`) — without this,
    // a path that silently stops being claimed (rather than being
    // completed/backed-off/rescheduled) is invisible.
    for (group_id, jobs) in &jobs_by_group {
        tracing::debug!(
            local_device_id = %state.device_id,
            group_id = %group_id,
            claimed_count = jobs.len(),
            claimed_paths = ?jobs.iter().map(|j| j.path.as_str()).collect::<Vec<_>>(),
            "claimed jobs this tick"
        );
    }
    let mut group_ids: Vec<String> = jobs_by_group.keys().cloned().collect();
    group_ids.sort();

    let mut next_idx = 0usize;
    let mut in_flight = FuturesUnordered::new();
    while next_idx < group_ids.len() && in_flight.len() < MAX_CONCURRENT_GROUP_AUDITS {
        let group_id = group_ids[next_idx].clone();
        let jobs = jobs_by_group.remove(&group_id).unwrap_or_default();
        in_flight.push(process_group(state, group_id, jobs));
        next_idx += 1;
    }
    while in_flight.next().await.is_some() {
        if next_idx < group_ids.len() {
            let group_id = group_ids[next_idx].clone();
            let jobs = jobs_by_group.remove(&group_id).unwrap_or_default();
            in_flight.push(process_group(state, group_id, jobs));
            next_idx += 1;
        }
    }
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
async fn process_group(
    state: &Arc<DaemonState>,
    group_id: String,
    jobs_in_group: Vec<MaterializationJob>,
) {
    if jobs_in_group.is_empty() {
        return;
    }
    // Diagnostic-only: wall-clock duration of one whole `process_group`
    // call, for the `taguchi_row_14` intermittent-stall investigation (see
    // `fix/conflict-copy-convergence-obligation-20260723`) -- a DB dump at
    // a real stall showed every claimed job stuck in `Planning` with
    // `attempt=0` (never reaching ANY finalization branch), which is only
    // possible if some call this function awaits hangs well past what a
    // normal tick should take. This traces exactly how long each call
    // actually takes, to confirm or rule that out directly instead of
    // inferring it from job-table state alone.
    let process_group_started = std::time::Instant::now();
    let claimed_job_count = jobs_in_group.len();
    let mut candidates = crate::hydration::candidate_sessions(state, &group_id);
    // Stable, deterministic order — `candidate_sessions` returns a `HashMap`
    // iteration order with no ordering guarantee at all; without this, the
    // rotation cursor below would be rotating through an order that can
    // silently reshuffle between calls, defeating the point of rotating.
    candidates.sort_by(|a, b| a.0.cmp(&b.0));

    let now = now_unix_nanos();
    if candidates.is_empty() {
        back_off_group(state, &jobs_in_group, "no connected peer shares this folder group");
        return;
    }

    // Best-effort: claim each targeted job into `Planning`. A failure here
    // (illegal/lost-race no-op) just means this job's final Completed/
    // Backoff transition below will also no-op (its `from: Planning` guard
    // will not match), leaving it exactly where it already was for a future
    // tick to pick up — never silently wrong, only silently deferred.
    for job in &jobs_in_group {
        let _ =
            state.replica_coordinator.materialization_job_repository().materialization_transition(
                &job.group_id,
                &job.path,
                &job.version_hash,
                job.state,
                MaterializationJobState::Planning,
                None,
                None,
                now,
            );
    }

    // Read-only here — advanced by however many candidates this call
    // *actually* tries, once that's known, after the loop below. A real
    // gap an independent review caught: unconditionally advancing by one
    // regardless of `attempts` (2 per tick) meant candidate 1 was retried
    // every tick while candidate 2 was only reached every other tick —
    // e.g. a 6-candidate group took 5 ticks to reach every peer once
    // instead of 3, needlessly repeating job-level backoff on paths a
    // still-untried later candidate could have resolved sooner.
    let start = {
        let cursors = state.convergence_engine_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(&group_id).copied().unwrap_or(0) % candidates.len()
    };

    let mut remaining: BTreeSet<String> = jobs_in_group.iter().map(|j| j.path.clone()).collect();

    // Bounded per-attempt path budget — a confirmed, reproduced regression
    // (see `fix/conflict-copy-convergence-obligation-20260723`): handing an
    // ENTIRE claimed batch (up to `MAX_JOBS_PER_TICK_PER_GROUP`, 128 paths)
    // to a single `reconcile_paths_directly` call processes every path's
    // blocks fully serially, and a large backlog of not-yet-referenced/
    // genuinely-missing blocks was measured accumulating into a 40+ second
    // single call with literally no intermediate log output — nothing else
    // in the daemon (not even the 1s-fallback engine tick loop) can make
    // progress while one such call is in flight. Capping how many paths one
    // attempt is asked to resolve, and rotating WHICH bounded subset gets
    // the attempt each tick (this cursor, separate from `convergence_engine_
    // cursors`'s peer rotation), bounds a single call's worst case while
    // still giving every path its turn across a few ticks.
    //
    // A path outside this tick's budget is NOT a failure — it was simply
    // never attempted this tick, and must not be penalized with a real
    // `Backoff` (`considered`, built below, is exactly the set the
    // finalization loop uses to tell "attempted and still unresolved" apart
    // from "never got a turn this tick").
    const MAX_PATHS_PER_RECONCILE_ATTEMPT: usize = 8;
    let sorted: Vec<&String> = remaining.iter().collect();
    let path_budget_start = {
        let cursors =
            state.convergence_engine_path_budget_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.get(&group_id).copied().unwrap_or(0) % sorted.len().max(1)
    };
    let budget_indices =
        rotation_indices(sorted.len(), path_budget_start, MAX_PATHS_PER_RECONCILE_ATTEMPT);
    let budget: BTreeSet<String> = budget_indices.iter().map(|&i| sorted[i].clone()).collect();
    {
        let mut cursors =
            state.convergence_engine_path_budget_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(
            group_id.clone(),
            (path_budget_start + budget_indices.len().max(1)) % sorted.len().max(1),
        );
    }
    // The set the finalization loop uses to distinguish "attempted and
    // still unresolved" (stays in `remaining`, eligible for real `Backoff`)
    // from "never got a turn this tick" (rescheduled without penalty,
    // regardless of `remaining`).
    let considered: BTreeSet<String> = budget.clone();

    // Whether ANY candidate this tick produced a trustworthy (not skipped,
    // not raced-by-a-concurrent-admission) audit result — if none did, this
    // tick learned nothing reliable about any job's true status, so nothing
    // should be marked `Completed`/penalized with a real `Backoff`; see the
    // reschedule-without-penalty path below.
    let mut any_trustworthy_audit = false;

    // Bounded, not exhaustive: trying every candidate sequentially in one
    // tick (an earlier version of this fix did) multiplies a single tick's
    // latency by the candidate count — measured to reliably slow down an
    // already-adversarial many-device scenario (`taguchi_row_14`) enough to
    // trip its stall detector. Capping here just means full rotation takes
    // a few extra ticks (each ~1s apart) to reach every peer instead of
    // one — a much better trade than one slow tick blocking this group's
    // whole conclusion on every candidate in turn.
    const MAX_PEERS_PER_TICK: usize = 2;
    // Origin-first fetch preference: the authoring peer is the one place
    // the budgeted paths' content is guaranteed to have existed, so it goes
    // first in the attempt order whenever it is connected — every other
    // candidate may hold the admitted change history without the blocks.
    // The plain rotation window is kept alongside because the cursor
    // advance below is defined in terms of rotation positions, not raw
    // attempts.
    let origin_index = origin_candidate_index(state, &jobs_in_group, &budget, &candidates);
    if let Some(origin) = origin_index {
        tracing::debug!(
            group_id = %group_id,
            origin_peer_id = %candidates[origin].0,
            "convergence engine preferring the authoring peer as this tick's first fetch candidate"
        );
    }
    let rotation_window = rotation_indices(candidates.len(), start, MAX_PEERS_PER_TICK);
    let indices = origin_first_indices(candidates.len(), start, MAX_PEERS_PER_TICK, origin_index);
    // How many candidates this call actually tried before `remaining` went
    // empty (or `indices` was exhausted) — the cursor advances by this
    // many, not by a fixed 1, so the next tick picks up exactly where this
    // one left off instead of re-trying an already-tried candidate.
    let mut tried = 0usize;

    for &candidate_index in &indices {
        if remaining.is_empty() {
            break;
        }
        tried += 1;
        let (_, session) = &candidates[candidate_index];

        // CONV-7 freshness guard: snapshot this group's DAG heads immediately
        // before and after this candidate's reconcile call. `handle_change_
        // batch` can admit a new change (from a concurrent peer session) at
        // any point during the call's run — since materializing is no
        // longer synchronous with admission (that's the whole point of this
        // engine), the call may resolve and write a path's content against
        // a DAG state a concurrent admission has already superseded by the
        // time it finishes. If the heads changed during the call, this
        // attempt's `ProjectionAttempt` cannot be trusted (see the
        // regression this closes: a concurrent admission superseding a
        // path's resolution mid-call left that path permanently stale and
        // never re-examined).
        // `Err` on either read must NOT collapse to an empty `Vec` via
        // `unwrap_or_default` (a real bug an independent review caught):
        // two failed reads would both produce an empty `Vec` and compare
        // equal, reading as "heads did not change" when the truth is
        // simply unknown. Treat either read failing as automatically
        // untrustworthy instead.
        let heads_before = state.replica_coordinator.sqlite().dag_group_heads(&group_id);
        let audit_started = std::time::Instant::now();
        // Directly re-resolves exactly this tick's still-outstanding paths
        // against CURRENT DAG heads — see `reconcile_paths_directly`'s own
        // doc comment for the confirmed bug this replaces (a completion
        // check based on whether a DAG change happened to still be
        // "unapplied", which stopped being examined at all once that
        // change's own projection succeeded once, regardless of whether
        // this path's resolution was ever actually re-verified against
        // disk).
        let attempt_result = session.reconcile_paths_directly(&group_id, budget.clone()).await;
        let audit_elapsed = audit_started.elapsed();
        if audit_elapsed > Duration::from_secs(2) {
            // Diagnostic-only: see `process_group`'s own timing comment —
            // isolates whether a slow tick is caused by THIS specific
            // candidate's reconcile call, as opposed to something else in
            // `process_group`.
            tracing::warn!(
                local_device_id = %state.device_id,
                candidate_peer_id = %candidates[candidate_index].0,
                group_id = %group_id,
                elapsed_ms = audit_elapsed.as_millis(),
                "reconcile_paths_directly took unusually long"
            );
        }
        let heads_after = state.replica_coordinator.sqlite().dag_group_heads(&group_id);

        // `Ok(None)` means this call was skipped (another audit for this
        // group already in flight, e.g. the pre-existing 90s periodic
        // sweep, or the group's link went away mid-tick) — genuinely
        // different from a real failed attempt, and must not be penalized
        // the same way (see `reschedule_after_skip`'s doc comment).
        match (attempt_result, heads_before, heads_after) {
            (Ok(Some(attempt)), Ok(before), Ok(after)) if before == after => {
                any_trustworthy_audit = true;
                // The ONLY way a path leaves `remaining`: `path_fully_
                // resolved` is true in this attempt's report -- settled AND
                // no conflict copy derived from it is still outstanding in
                // `retry` (an independent review caught this call site using
                // bare `is_settled` alone, which let a job retire while its
                // derived conflict-copy obligation was still pending). A
                // path in neither `settled` nor `retry` cannot occur
                // (`reconcile_group_paths` guarantees every examined path
                // lands in exactly one), but even if it somehow did,
                // `path_fully_resolved` returning `false` for it means it
                // correctly stays in `remaining`.
                remaining.retain(|p| !attempt.path_fully_resolved(p));
            }
            (Ok(Some(_)), Ok(_), Ok(_)) => {
                // Heads changed mid-call — a concurrent admission may have
                // already superseded whatever this attempt resolved.
                // Leave `remaining` untouched; the next candidate/tick
                // re-resolves against the now-current heads.
            }
            (Ok(None), _, _) => {
                // Skipped: guard contention or the group's link gate is no
                // longer live. Leave `remaining` untouched.
            }
            (Err(e), _, _) => {
                tracing::warn!(
                    group_id = %group_id,
                    error = %e,
                    "convergence engine's direct path reconciliation failed for this group"
                );
            }
            (_, Err(e), _) | (_, _, Err(e)) => {
                tracing::warn!(
                    group_id = %group_id,
                    error = %e,
                    "convergence engine failed to read this group's DAG heads around a \
                     reconcile attempt"
                );
            }
        }
    }

    // Advance the cursor by how many of the ROTATION window's leading
    // positions were actually consumed — not by the raw tried count. With
    // the origin-first preference in the attempt order, raw `tried` can
    // include an out-of-window origin attempt (which must not move the
    // rotation at all) or an in-window origin tried out of position (which
    // must not let the cursor jump past a window candidate that never got
    // its turn). The prefix rule handles both: the cursor moves past a
    // window position only if that position and every one before it were
    // tried this tick. Without an origin preference this degenerates to
    // exactly the old advance-by-tried behavior (the tried set IS a window
    // prefix), which an independent review had already fixed once — a
    // fixed +1 regardless of `attempts` made rotation take 5 ticks instead
    // of 3 to reach every peer of a 6-candidate group.
    {
        let tried_set: BTreeSet<usize> = indices.iter().take(tried).copied().collect();
        let advance = rotation_window.iter().take_while(|i| tried_set.contains(i)).count();
        let mut cursors =
            state.convergence_engine_cursors.lock().unwrap_or_else(|p| p.into_inner());
        cursors.insert(group_id.clone(), (start + advance) % candidates.len());
    }

    let now = now_unix_nanos();
    // Diagnostic-only: a cheap digest of this group's heads right at
    // finalization time, for the `taguchi_row_14` intermittent-stall
    // investigation (see `fix/conflict-copy-convergence-obligation-20260723`)
    // — correlates "what this engine believed" against the per-path audit
    // logs emitted deeper in `reconcile_local_materialization_audit`.
    let dag_heads_digest = state
        .replica_coordinator
        .sqlite()
        .dag_group_heads(&group_id)
        .ok()
        .map(|heads| heads.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>().join(","));
    for job in &jobs_in_group {
        if !any_trustworthy_audit {
            // No candidate this tick produced a trustworthy read — reschedule
            // quickly without incrementing `attempt`/penalizing backoff (this
            // group's own audit guard is contended, or every attempt raced a
            // concurrent admission); the next tick tries again from scratch.
            let next_retry_at = now + Duration::from_millis(200).as_nanos() as i64;
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id = %job.group_id,
                job_path = %job.path,
                job_version_hash = %hex::encode(&job.version_hash),
                dag_heads_digest = ?dag_heads_digest,
                job_state_before = "Planning",
                job_state_after = "rescheduled (no penalty)",
                "job rescheduled without penalty: no trustworthy audit this tick"
            );
            let _ = state
                .replica_coordinator
                .materialization_job_repository()
                .materialization_reschedule_after_skip(
                    &job.group_id,
                    &job.path,
                    &job.version_hash,
                    MaterializationJobState::Planning,
                    next_retry_at,
                    now,
                );
        } else if !considered.contains(&job.path) {
            // This path was never attempted this tick at all (excluded by
            // `MAX_PATHS_PER_RECONCILE_ATTEMPT`'s budget) — not a failure,
            // just not its turn yet. Reschedule quickly without penalty,
            // exactly like the no-trustworthy-audit case, so the next
            // tick's rotating budget window reaches it soon instead of
            // piling on backoff for work that was never even tried.
            let next_retry_at = now + Duration::from_millis(200).as_nanos() as i64;
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id = %job.group_id,
                job_path = %job.path,
                job_version_hash = %hex::encode(&job.version_hash),
                dag_heads_digest = ?dag_heads_digest,
                job_state_before = "Planning",
                job_state_after = "rescheduled (no penalty)",
                "job rescheduled without penalty: excluded by this tick's path budget"
            );
            let _ = state
                .replica_coordinator
                .materialization_job_repository()
                .materialization_reschedule_after_skip(
                    &job.group_id,
                    &job.path,
                    &job.version_hash,
                    MaterializationJobState::Planning,
                    next_retry_at,
                    now,
                );
        } else if remaining.contains(&job.path) {
            let next_retry_at = now + next_backoff(job.attempt + 1).as_nanos() as i64;
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id = %job.group_id,
                job_path = %job.path,
                job_version_hash = %hex::encode(&job.version_hash),
                dag_heads_digest = ?dag_heads_digest,
                job_state_before = "Planning",
                job_state_after = "Backoff",
                projection_status = "retry",
                "job marked Backoff: direct projection reported this path as needing retry"
            );
            let _ = state
                .replica_coordinator
                .materialization_job_repository()
                .materialization_mark_backoff(
                    &job.group_id,
                    &job.path,
                    &job.version_hash,
                    MaterializationJobState::Planning,
                    "materialization attempt did not complete against any reachable peer; see \
                 daemon logs for the specific fetch/disk error",
                    next_retry_at,
                    now,
                );
        } else {
            tracing::debug!(
                local_device_id = %state.device_id,
                group_id = %job.group_id,
                job_path = %job.path,
                job_version_hash = %hex::encode(&job.version_hash),
                dag_heads_digest = ?dag_heads_digest,
                job_state_before = "Planning",
                job_state_after = "Completed",
                projection_status = "settled",
                "job marked Completed after direct projection verification"
            );
            let _ = state
                .replica_coordinator
                .materialization_job_repository()
                .materialization_transition(
                    &job.group_id,
                    &job.path,
                    &job.version_hash,
                    MaterializationJobState::Planning,
                    MaterializationJobState::Completed,
                    None,
                    None,
                    now,
                );
        }
    }
    let elapsed = process_group_started.elapsed();
    if elapsed > Duration::from_secs(2) {
        tracing::warn!(
            local_device_id = %state.device_id,
            group_id = %group_id,
            claimed_job_count,
            tried,
            elapsed_ms = elapsed.as_millis(),
            "process_group took unusually long this tick"
        );
    } else {
        tracing::debug!(
            local_device_id = %state.device_id,
            group_id = %group_id,
            claimed_job_count,
            tried,
            elapsed_ms = elapsed.as_millis(),
            "process_group finished"
        );
    }
}

fn back_off_group(state: &Arc<DaemonState>, jobs: &[MaterializationJob], waiting_reason: &str) {
    let now = now_unix_nanos();
    for job in jobs {
        let next_retry_at = now + next_backoff(job.attempt + 1).as_nanos() as i64;
        let _ = state
            .replica_coordinator
            .materialization_job_repository()
            .materialization_mark_backoff(
                &job.group_id,
                &job.path,
                &job.version_hash,
                job.state,
                waiting_reason,
                next_retry_at,
                now,
            );
    }
}

#[cfg(test)]
mod tests {
    use super::{majority_author, origin_first_indices, rotation_indices};

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
