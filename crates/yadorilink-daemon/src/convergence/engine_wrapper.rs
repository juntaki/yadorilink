//! Runs the existing materialization engine together with the independent
//! retroactive conflict-copy repair loop.
//!
//! Keeping the repair as a wrapper leaves `engine.rs` available for Stage 3 to
//! evolve independently. If either essential loop exits, this wrapper exits and
//! `DaemonState`'s existing `spawn_restarting` supervision restarts both.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_peer_session::peer_session::RetirementAttempt;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::RetroactiveRepairOutcome;
use yadorilink_root_authority::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

use crate::daemon_state::DaemonState;

const REPAIR_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// The retirement loop's own backstop cadence, now that
/// `RetirementWake`-driven events (DAG frontier advanced, materialization
/// job completed) are its primary trigger -- see
/// `run_ephemeral_conflict_copy_retire_loop`'s own doc comment. Kept far
/// looser than a correctness-critical poll needs to be: this pass exists
/// only to catch a group whose dirty mark was somehow lost (a crash between
/// the state change and the `notify_retirement_wake` call, or a group
/// linked after an earlier mark for it was already drained), not to carry
/// ordinary retirement latency.
const RETIREMENT_BACKSTOP_INTERVAL: Duration = Duration::from_secs(30);

/// `RETIREMENT_BACKSTOP_INTERVAL` itself, for a test that needs to wait
/// past it deterministically (see `retirement_backstop_group_
/// deauthorization.rs`'s own doc comment) without hardcoding a duplicate
/// value that would silently stop exercising the real regression if this
/// constant is ever retuned.
#[cfg(any(test, feature = "test-support"))]
pub fn retirement_backstop_interval_for_tests() -> Duration {
    RETIREMENT_BACKSTOP_INTERVAL
}
/// Same role as `RETIREMENT_BACKSTOP_INTERVAL`, for the hazard re-check
/// loop's own `HazardRecheckWake`-driven events -- a correctness backstop
/// only, for a mark lost to a crash or a race with linking.
const HAZARD_RECHECK_BACKSTOP_INTERVAL: Duration = Duration::from_secs(30);
/// The ignore-recheck loop's own backstop cadence -- unlike the retirement
/// and hazard loops, this one is backstop-only, with no event-driven fast
/// path yet (see `run_ignore_recheck_loop`'s own doc comment for why that
/// is an acceptable, deliberate scope boundary for now). Matches
/// `HAZARD_RECHECK_BACKSTOP_INTERVAL` so an ignore-policy edit and a lifted
/// hazard hold carry the same worst-case re-arm latency.
const IGNORE_RECHECK_BACKSTOP_INTERVAL: Duration = Duration::from_secs(30);
/// Each rank gets an exclusive window before the next deterministic fallback
/// becomes eligible. This only suppresses duplicate work: after enough
/// unchanged-frontier windows every authorized writer may act.
const REPAIR_FAILOVER_RANK_INTERVAL: Duration = Duration::from_secs(5);

fn eligible_rank_for_elapsed(elapsed: Duration) -> usize {
    (elapsed.as_millis() / REPAIR_FAILOVER_RANK_INTERVAL.as_millis())
        .try_into()
        .unwrap_or(usize::MAX)
}

/// See `engine_impl::run_once_for_test`'s own doc comment -- this is the
/// only way to drive the Convergence Engine's scheduler deterministically
/// one tick at a time from outside `yadorilink-daemon` at all, since
/// `engine_impl` (this module's own sibling, `mod engine_impl` -- not
/// `pub`) is otherwise unreachable from an external integration test.
#[cfg(any(test, feature = "test-support"))]
pub async fn run_once_for_test(state: &Arc<DaemonState>) -> bool {
    super::engine_impl::run_once_for_test(state).await
}

/// See `engine_impl::drive_obligations_once_for_test`'s own doc comment --
/// the obligation-driven worker's counterpart of [`run_once_for_test`],
/// exposed the same way for the same reason.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test(
    state: &Arc<DaemonState>,
    per_group_limit: u32,
    total_limit: u32,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test(state, per_group_limit, total_limit).await
}

/// See `engine_impl::BeforeCompletionHook`'s own doc comment -- re-exported
/// so a deterministic-interleaving test outside `yadorilink-daemon` can
/// construct one and drive it.
#[cfg(any(test, feature = "test-support"))]
pub use super::engine_impl::BeforeCompletionHook;

/// See `engine_impl::drive_obligations_once_for_test_with_hooks`'s own doc
/// comment -- exposed the same way as [`drive_obligations_once_for_test`].
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test_with_hooks(
    state: &Arc<DaemonState>,
    per_group_limit: u32,
    total_limit: u32,
    hooks: &Arc<BeforeCompletionHook>,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test_with_hooks(state, per_group_limit, total_limit, hooks).await
}

pub async fn run(state: Arc<DaemonState>) {
    // Each loop is spawned as its own task rather than raced directly via
    // `tokio::select!` on the bare futures: `run_retroactive_repair_loop`
    // calls several synchronous, blocking `SyncState` methods; racing that
    // future directly alongside the main engine's on the SAME task would
    // let a slow synchronous call in this poll starve the engine's own tick
    // for as long as it runs (`select!` only gets to poll whichever branch
    // it currently has control in) -- exactly the kind of added per-tick
    // latency the row-14 stress scenario's stall detector is tuned to
    // catch. Spawning each onto its own task lets tokio schedule them on
    // genuinely separate worker threads (the blocking `SyncState` calls
    // inside the repair loop are themselves further isolated via
    // `spawn_blocking` at each call site below, since a plain
    // `tokio::spawn` alone only guarantees a *possibly*-different async
    // worker thread, not the dedicated blocking pool -- see
    // `run_retroactive_repair_loop`'s own doc comment).
    //
    // Explicit abort-and-await of the four survivors below, not a bare
    // `tokio::select!` on the five `JoinHandle`s alone, gives the "either
    // dies, all restart" semantics this wrapper's own doc comment
    // describes: a `JoinHandle` a `select!` branch drops only DETACHES its
    // task rather than cancelling it (it keeps running), so
    // `spawn_restarting`'s subsequent restart would otherwise leave the old
    // survivors running undetached alongside a brand new set of tasks --
    // duplicate materialization engines or repair loops, compounding on
    // every restart. `tokio::task::JoinSet` would give this same shape more
    // directly, but is unavailable under `madsim-tokio`'s shim (no
    // `JoinSet` at all), so this manual select-then-abort-and-await
    // reproduces its exact "aborts every remaining task and awaits their
    // completion" contract explicitly -- this function never returns while
    // any of the five tasks is still alive.
    let engine_state = state.clone();
    let retire_state = state.clone();
    let hazard_recheck_state = state.clone();
    let ignore_recheck_state = state.clone();
    let mut engine_handle = tokio::spawn(super::engine_impl::run(engine_state));
    let mut repair_handle = tokio::spawn(run_retroactive_repair_loop(state));
    let mut retire_handle = tokio::spawn(run_ephemeral_conflict_copy_retire_loop(retire_state));
    let mut hazard_recheck_handle = tokio::spawn(run_hazard_recheck_loop(hazard_recheck_state));
    let mut ignore_recheck_handle = tokio::spawn(run_ignore_recheck_loop(ignore_recheck_state));
    tokio::select! {
        _ = &mut engine_handle => {}
        _ = &mut repair_handle => {}
        _ = &mut retire_handle => {}
        _ = &mut hazard_recheck_handle => {}
        _ = &mut ignore_recheck_handle => {}
    }
    for handle in [
        &mut engine_handle,
        &mut repair_handle,
        &mut retire_handle,
        &mut hazard_recheck_handle,
        &mut ignore_recheck_handle,
    ] {
        handle.abort();
        let _ = handle.await;
    }
}

/// Retires ephemeral conflict copies -- ones whose losing branch has since
/// been superseded with no cross-branch merge, so no admitted change ever
/// carries them, and a device that already materialized one keeps it
/// forever while a device that first reconciles after the window closed
/// never derives it: byte-identical DAGs, permanently different file sets
/// (see `PeerSyncSession::retire_unjustified_ephemeral_conflict_copies`'s
/// own doc comment). Confirmed live: `row14_strict_acceptance` stalled with
/// one device (out of six, all on an identical three-head DAG frontier)
/// holding a conflict copy every device's own `resolve_path_heads` agreed
/// was no longer required.
///
/// Primarily event-driven, not polled: `RetirementWake::mark_dirty` fires
/// after exactly the two events that can change a copy's justification --
/// this device's own DAG frontier advancing (locally authored or admitted
/// from a peer) and a materialization job reaching `Completed` -- so this
/// loop reacts within one wake rather than waiting up to a whole poll
/// interval. `RETIREMENT_BACKSTOP_INTERVAL` remains as a correctness
/// backstop only, for a mark lost to a crash or a race with linking, not as
/// the primary liveness path the way the old flat 1s poll was. Before this
/// loop existed at all, this audit was reachable only through the legacy
/// periodic materialization-repair sweep in `daemon_state.rs`; Stage 2's
/// Convergence Engine (`engine.rs`) drives ordinary path reconciliation
/// through `reconcile_paths_directly` instead, which never calls it. A
/// group whose sweep interval is long -- or, as `row14_strict_acceptance`
/// sets for its own strict acceptance bar, disabled for the whole run,
/// specifically to prove the Convergence Engine's own mechanism converges
/// without the legacy sweep's help -- then had no path left that ever
/// retired a copy at all.
async fn run_ephemeral_conflict_copy_retire_loop(state: Arc<DaemonState>) {
    loop {
        tokio::select! {
            _ = state.replica_coordinator.retirement_wake().retirement_wake_notified() => {
                let pending = state.replica_coordinator.retirement_wake().pending();
                run_retirement_pass(&state, pending).await;
            }
            _ = tokio::time::sleep(RETIREMENT_BACKSTOP_INTERVAL) => {
                if let Some(groups) = list_linked_groups_for_retirement(&state).await {
                    // Backstop recovery for a mark lost before this
                    // generation-tracked state existed for the group at
                    // all (e.g. linked after an earlier drop, or after a
                    // crash) -- `mark_dirty` makes every linked group
                    // reportable by `pending`, matching the old flat
                    // poll's "just re-check everything" behavior.
                    for group_id in &groups {
                        state.replica_coordinator.retirement_wake().mark_dirty(group_id);
                    }
                    let pending = state.replica_coordinator.retirement_wake().pending();
                    run_retirement_pass(&state, pending).await;
                }
            }
        }
    }
}

/// Every currently linked, non-paused, non-orphaned group -- the backstop
/// pass's own candidate set, since (unlike an event-driven wake) it has no
/// narrower dirty set to go on.
async fn list_linked_groups_for_retirement(state: &Arc<DaemonState>) -> Option<BTreeSet<String>> {
    let replica_coordinator_for_links = state.replica_coordinator.clone();
    match tokio::task::spawn_blocking(move || {
        replica_coordinator_for_links.link_repository().list_links()
    })
    .await
    {
        Ok(Ok(links)) => Some(
            links
                .into_iter()
                .filter(|link| !link.paused && !link.orphaned)
                .map(|link| link.group_id)
                .collect(),
        ),
        Ok(Err(error)) => {
            tracing::warn!(%error, "ephemeral conflict-copy retire audit could not list links");
            None
        }
        Err(error) => {
            tracing::error!(
                %error,
                "ephemeral conflict-copy retire audit's list_links task panicked"
            );
            None
        }
    }
}

/// Runs `ConvergenceRetirementService::reconcile_group` for each group in
/// `pending` (group id -> the generation `RetirementWake::pending` reported
/// for it) -- no live peer session involved (see
/// `DaemonState::local_retirement_session`'s own doc comment for why
/// retirement's own decision was never actually dependent on which, or
/// any, peer happened to be connected). `RetirementWake::complete` is
/// called for a group ONLY when `settles_generation` says the outcome was
/// `RetirementAttempt::Settled` -- see that function's and
/// `RetirementAttempt`'s own doc comments for why `Busy` and
/// `RetryRequired` must not be treated as completions. Not completing
/// leaves the group in `pending` with no separate re-mark needed -- see
/// `RetirementWake::pending`'s own doc comment.
async fn run_retirement_pass(state: &Arc<DaemonState>, pending: BTreeMap<String, u64>) {
    let service = super::retirement_service::ConvergenceRetirementService::new(state.clone());
    for (group_id, generation) in pending {
        match service.reconcile_group(&group_id).await {
            Ok(attempt) if settles_generation(&attempt) => {
                state.replica_coordinator.retirement_wake().complete(&group_id, generation);
            }
            // `Busy` (a full audit already holds this group's guard) or
            // `RetryRequired` (ran, but at least one copy's evaluation was
            // not verified against the targeted frontier) -- neither
            // settles this pass's target generation. Left pending; the
            // next wake or backstop tries again.
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    %group_id,
                    %error,
                    "ephemeral conflict-copy retire audit failed"
                );
            }
        }
    }
}

/// Whether `attempt` means the pass that produced it may be treated as
/// having genuinely verified the frontier generation it targeted -- the
/// single place the "only `Settled` completes a generation" contract is
/// enforced, factored out so a test can exercise the decision without any
/// `PeerSyncSession`/`DaemonState` plumbing.
fn settles_generation(attempt: &RetirementAttempt) -> bool {
    matches!(attempt, RetirementAttempt::Settled { .. })
}

/// Re-evaluates every currently-`HazardHeld` path in a group whenever this
/// device's DAG frontier advances or a materialization job completes --
/// see `MaterializationStateRepository::list_held_paths`'s own doc comment
/// for why nothing else ever re-visits a held path once the sibling that
/// caused its hold changes. Structurally identical to
/// `run_ephemeral_conflict_copy_retire_loop`: event-driven via
/// `HazardRecheckWake`, with `HAZARD_RECHECK_BACKSTOP_INTERVAL` as a
/// correctness backstop only for a mark lost to a crash or a race with
/// linking. Uses a separate `RetirementWake` instance
/// (`hazard_recheck_wake`), not the retirement loop's own, since `pending`/
/// `complete` are consumer-specific -- see that field's own doc comment.
async fn run_hazard_recheck_loop(state: Arc<DaemonState>) {
    loop {
        tokio::select! {
            _ = state.replica_coordinator.hazard_recheck_wake().retirement_wake_notified() => {
                let pending = state.replica_coordinator.hazard_recheck_wake().pending();
                run_hazard_recheck_pass(&state, pending).await;
            }
            _ = tokio::time::sleep(HAZARD_RECHECK_BACKSTOP_INTERVAL) => {
                if let Some(groups) = list_linked_groups_for_retirement(&state).await {
                    for group_id in &groups {
                        state.replica_coordinator.hazard_recheck_wake().mark_dirty(group_id);
                    }
                    let pending = state.replica_coordinator.hazard_recheck_wake().pending();
                    run_hazard_recheck_pass(&state, pending).await;
                }
            }
        }
    }
}

/// For each group in `pending` (group id -> the generation `RetirementWake::
/// pending` reported for it), lists its currently-held paths and, if any,
/// re-resolves them directly against this device's current DAG heads via
/// `reconcile_paths_directly` -- the SAME entry point the Convergence
/// Engine's own per-job completion oracle uses, run here against a session
/// that is never actually peer-dependent for this decision: a held path's
/// hazard status follows only local DAG/disk state (see `DaemonState::
/// local_retirement_session`'s own doc comment). Prefers an already-live
/// candidate session for the group when one exists, falling back to the
/// synthetic local session (`DaemonState::local_retirement_session`) only
/// when there are none -- identical to `process_group_via_obligations`'s
/// own zero-work pre-check guard, and for the same reason: `local_
/// retirement_session`'s first-ever construction for a group triggers
/// `NetmapChangeAuthenticator::new` -> `validate_linked_history_best_effort`,
/// which can transiently quarantine every OTHER already-connected session's
/// authorization for this group if that validation is briefly unavailable.
/// This backstop pass runs on its own 30s timer, independent of peer-connect
/// timing, so it is realistic for it to be the first caller to need a
/// session for a group whose real peers already connected. A group whose
/// listing came back empty, or whose `reconcile_paths_directly` call
/// genuinely ran (`Some(_)`, regardless of what it found -- a still-
/// hazardous path is a correctly re-verified outcome, not a failure to
/// complete this generation), completes its generation. A listing failure
/// or a skipped attempt (`None`: guard contention, or the group is not
/// `LinkGate::Live` right now) leaves the group pending for the next wake
/// or backstop.
async fn run_hazard_recheck_pass(state: &Arc<DaemonState>, pending: BTreeMap<String, u64>) {
    for (group_id, generation) in pending {
        let replica_coordinator_for_list = state.replica_coordinator.clone();
        let list_group_id = group_id.clone();
        let held_paths = match tokio::task::spawn_blocking(move || {
            replica_coordinator_for_list.materialization_state_repository().list_held_paths(&list_group_id)
        })
        .await
        {
            Ok(Ok(paths)) => paths,
            Ok(Err(error)) => {
                tracing::warn!(%error, %group_id, "hazard recheck could not list held paths");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, %group_id, "hazard recheck's list_held_paths task panicked");
                continue;
            }
        };
        if held_paths.is_empty() {
            state.replica_coordinator.hazard_recheck_wake().complete(&group_id, generation);
            continue;
        }
        let session = crate::hydration::candidate_sessions(state, &group_id)
            .into_iter()
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, session)| session)
            .unwrap_or_else(|| state.local_retirement_session(&group_id));
        match session
            .reconcile_paths_directly(&group_id, held_paths.into_iter().collect())
            .await
        {
            Ok(Some(_)) => {
                state.replica_coordinator.hazard_recheck_wake().complete(&group_id, generation);
            }
            // `None`: the audit guard was already held by another attempt,
            // or the group is not `LinkGate::Live` right now -- nothing was
            // actually re-verified, so this generation stays pending for
            // the next wake or backstop.
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%group_id, %error, "hazard recheck's direct reconciliation failed");
            }
        }
    }
}

/// Re-arms a `projection_obligations` row parked at `'ignore_blocked'`
/// (`complete_obligation_if_non_exact_proof_current`'s `IgnoreExcluded`
/// arm -- see that variant's own doc comment) once a periodic re-check
/// confirms the path is no longer locally ignored, closing the liveness
/// gap the `IGNORE_SET_REFRESH_INTERVAL` cache-TTL fix alone left open: a
/// live-reloading ignore-set cache only ever changes what a FUTURE
/// `is_locally_ignored` call sees, it does nothing for a path whose
/// obligation was already parked before the reload, since nothing else
/// ever calls `is_locally_ignored` for it again on its own.
///
/// Deliberately backstop-only for now, unlike the retirement/hazard loops
/// (no `RetirementWake`-style event-driven fast path): the natural trigger
/// -- "the ignore-set cache for this group just reloaded from a changed
/// `.yadorilinkignore`" -- fires deep inside `yadorilink-peer-session`'s
/// `effective_ignore_set`, and wiring a cross-crate notification back into
/// this loop is a possible follow-up, not required to close the liveness
/// gap itself: the `IGNORE_RECHECK_BACKSTOP_INTERVAL` poll alone already
/// bounds worst-case re-arm latency, exactly the same tradeoff this
/// codebase already accepted for the hazard-recheck loop's own 30s
/// backstop.
///
/// Spawned for real from `run` (Phase C cutover), alongside the retirement
/// and hazard-recheck loops: `process_group_via_obligations` is now the
/// live claim source, so an `'ignore_blocked'` row is a real, live
/// possibility, not merely a test-driven one.
async fn run_ignore_recheck_loop(state: Arc<DaemonState>) {
    loop {
        tokio::time::sleep(IGNORE_RECHECK_BACKSTOP_INTERVAL).await;
        if let Some(groups) = list_linked_groups_for_retirement(&state).await {
            for group_id in &groups {
                run_ignore_recheck_pass(&state, group_id).await;
            }
        }
    }
}

/// Lists `group_id`'s currently-`'ignore_blocked'` paths and re-checks
/// EACH ONE against the current, live ignore-policy verdict alone -- never
/// by attempting a reconcile/materialize. A path still matching the
/// current ignore set is left exactly where it is; a path that no longer
/// matches is re-armed back to `'pending'` immediately, then the ordinary
/// obligation claim cycle (a live candidate peer, not this sweep) produces
/// the real fetch/materialize/completion for it.
///
/// This deliberately does NOT drive a reconcile attempt the way the
/// hazard-recheck sweep does: an independent review caught a real
/// permanent-stall bug in an earlier version of this function, which
/// gated re-arm on `ProjectionAttempt::is_settled(path)` after calling
/// `reconcile_paths_directly` through `local_retirement_session` --
/// backed by a `LoopbackPeerMessageChannel` whose `open_block_stream`
/// always returns `ChannelClosed`. A path whose content requires an
/// actual block fetch (anything but the trivial empty-content case) can
/// therefore never `is_settled` through that session, so it could never
/// re-arm at all: an unignored file needing real content would stay
/// `'ignore_blocked'` forever, invisible to the production scheduler
/// (which only ever claims `'pending'` rows). The bug's own reproduction
/// needs a `FileVersion` with a real (non-empty) block absent from the
/// local store — the pre-existing regression test used `empty_version()`,
/// which is trivially "materializable" with no blocks at all and so never
/// exercised the ChannelClosed path. The fix here removes the dependency
/// on full settlement entirely: whether a path is still ignored is a pure,
/// local, synchronous policy question that has nothing to do with whether
/// its content can currently be fetched.
///
/// This deliberately avoids `state.local_retirement_session` (a real
/// `PeerSyncSession`, previously used only for its
/// `is_path_locally_ignored` accessor): that session's own first-ever
/// construction for a group triggers `NetmapChangeAuthenticator::new` ->
/// `validate_linked_history_best_effort`, which can transiently quarantine
/// every OTHER already-connected session's authorization for this group if
/// that validation is not yet available (see
/// `process_group_via_obligations`'s doc comment). Whether a path is
/// locally ignored has nothing to do with peer/session state at all --
/// this pass loads the group's `EffectiveIgnoreSet` directly from its sync
/// root, the same source `PeerSyncSession::effective_ignore_set` reads
/// from, without ever constructing a session. Unlike that session-cached
/// accessor, this has no last-known-good fallback: a transient sync-root
/// resolution failure re-arms rather than leaving the path parked, which
/// is safe (the ordinary claim cycle re-evaluates ignore policy again
/// downstream) and strictly better than risking the quarantine side effect.
async fn run_ignore_recheck_pass(state: &Arc<DaemonState>, group_id: &str) {
    let replica_coordinator_for_list = state.replica_coordinator.clone();
    let list_group_id = group_id.to_string();
    let ignore_blocked_paths = match tokio::task::spawn_blocking(move || {
        replica_coordinator_for_list.sqlite().dag_list_ignore_blocked_paths(&list_group_id)
    })
    .await
    {
        Ok(Ok(paths)) => paths,
        Ok(Err(error)) => {
            tracing::warn!(%error, %group_id, "ignore recheck could not list ignore-blocked paths");
            return;
        }
        Err(error) => {
            tracing::error!(%error, %group_id, "ignore recheck's list_ignore_blocked_paths task panicked");
            return;
        }
    };
    if ignore_blocked_paths.is_empty() {
        return;
    }
    let sync_roots = crate::peer_orchestrator::sync_roots_for_groups(
        state,
        std::slice::from_ref(&group_id.to_string()),
    );
    let ignore_set = sync_roots.get(group_id).map(|root| {
        EffectiveIgnoreSet::load_for_link_root(root).unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only())
    });
    let mut any_rearmed = false;
    for path in &ignore_blocked_paths {
        let still_ignored = ignore_set
            .as_ref()
            .is_some_and(|set| is_ignore_file_relative_path(path) || set.is_ignored(path, false));
        if still_ignored {
            continue;
        }
        let replica_coordinator_for_rearm = state.replica_coordinator.clone();
        let rearm_group_id = group_id.to_string();
        let rearm_path = path.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        match tokio::task::spawn_blocking(move || {
            replica_coordinator_for_rearm.sqlite().dag_rearm_ignore_blocked_obligation(
                &rearm_group_id,
                &rearm_path,
                now,
            )
        })
        .await
        {
            Ok(Ok(rearmed)) => any_rearmed = any_rearmed || rearmed,
            Ok(Err(error)) => {
                tracing::warn!(%error, %group_id, path, "ignore recheck failed to re-arm a path");
            }
            Err(error) => {
                tracing::error!(%error, %group_id, path, "ignore recheck's re-arm task panicked");
            }
        }
    }
    if any_rearmed {
        state.replica_coordinator.materialization_wake().notify_materialization_wake();
    }
}

/// Every direct `SyncState` call in this loop's body is wrapped in
/// `spawn_blocking` (`list_links`, `dag_group_heads`, and `get_file`
/// further below), not called inline -- these are synchronous, blocking
/// SQLite calls, and a plain `tokio::spawn` around this whole function
/// (`run`, above) only guarantees these run on SOME async worker thread,
/// not tokio's dedicated blocking-pool thread. Calling them inline here
/// would still risk blocking whichever async worker happens to be running
/// this task, competing with the main engine's own tick for that worker
/// exactly as directly co-scheduling the two loops on one task did before
/// `run` started spawning them separately.
async fn run_retroactive_repair_loop(state: Arc<DaemonState>) {
    let mut observed_heads: HashMap<String, Vec<ChangeHash>> = HashMap::new();
    let mut failover_frontiers: HashMap<String, (Vec<ChangeHash>, tokio::time::Instant)> =
        HashMap::new();

    loop {
        let replica_coordinator_for_links = state.replica_coordinator.clone();
        let groups = match tokio::task::spawn_blocking(move || {
            replica_coordinator_for_links.link_repository().list_links()
        })
        .await
        {
            Ok(Ok(links)) => links
                .into_iter()
                .filter(|link| !link.paused && !link.orphaned)
                .map(|link| link.group_id)
                .collect::<BTreeSet<_>>(),
            Ok(Err(error)) => {
                tracing::warn!(%error, "retroactive conflict-copy repair could not list links");
                tokio::time::sleep(REPAIR_POLL_INTERVAL).await;
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "retroactive conflict-copy repair's list_links task panicked");
                tokio::time::sleep(REPAIR_POLL_INTERVAL).await;
                continue;
            }
        };
        observed_heads.retain(|group_id, _| groups.contains(group_id));
        failover_frontiers.retain(|group_id, _| groups.contains(group_id));

        for group_id in groups {
            let replica_coordinator_for_heads = state.replica_coordinator.clone();
            let heads_group_id = group_id.clone();
            let mut heads = match tokio::task::spawn_blocking(move || {
                replica_coordinator_for_heads.sqlite().dag_group_heads(&heads_group_id)
            })
            .await
            {
                Ok(Ok(heads)) => heads,
                Ok(Err(error)) => {
                    tracing::warn!(%error, %group_id, "retroactive conflict-copy repair could not read DAG heads");
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, %group_id, "retroactive conflict-copy repair's dag_group_heads task panicked");
                    continue;
                }
            };
            heads.sort();
            if observed_heads.get(&group_id) == Some(&heads) {
                continue;
            }
            let first_seen = match failover_frontiers.get(&group_id) {
                Some((tracked, first_seen)) if tracked == &heads => *first_seen,
                _ => {
                    let now = tokio::time::Instant::now();
                    failover_frontiers.insert(group_id.clone(), (heads.clone(), now));
                    now
                }
            };
            let eligible_rank = eligible_rank_for_elapsed(first_seen.elapsed());

            let Some(signing_key) = state.device_signing_key() else {
                // A registered daemon wires this during startup. Do not cache the
                // heads: once the key arrives, the unchanged frontier still needs
                // its first repair pass.
                continue;
            };

            let replica_coordinator = state.replica_coordinator.clone();
            let device_id = state.device_id.clone();
            let repair_group = group_id.clone();
            let repair = tokio::task::spawn_blocking(move || {
                let emitter = ChangeEmitter::new(device_id, signing_key);
                replica_coordinator.repair_retroactive_conflict_copy_obligations(
                    &repair_group,
                    &emitter,
                    eligible_rank,
                )
            })
            .await;

            let outcome = match repair {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(error)) => {
                    // Includes policy-unavailable and transient SQLite failures.
                    // Do not cache this frontier; retry it on the next poll.
                    tracing::warn!(%error, %group_id, "retroactive conflict-copy repair deferred");
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, %group_id, "retroactive conflict-copy repair task panicked");
                    continue;
                }
            };

            match outcome {
                RetroactiveRepairOutcome::NothingToDo { committed_frontier } => {
                    // Cache only the exact frontier examined inside the atomic
                    // repair transaction. Re-reading here is incorrect: a peer
                    // could admit a new head after that transaction and before
                    // this task runs, and caching that unexamined head would
                    // suppress its repair.
                    observed_heads.insert(group_id.clone(), committed_frontier);
                    failover_frontiers.remove(&group_id);
                }
                RetroactiveRepairOutcome::PermanentlyBlocked { path, committed_frontier } => {
                    // This frontier's obligation at `path` alone exceeds the
                    // bounded change size and cannot yet be split across
                    // multiple carriers, so re-examining this exact frontier
                    // every poll can only ever reproduce the same result --
                    // cache it exactly like a real no-op, rather than
                    // re-running full-history planning and re-acquiring the
                    // SQLite writer lock once a second forever. A NEW head
                    // (e.g. one that resolves some of `path`'s concurrent
                    // losers through ordinary use) still re-examines this
                    // group on the next poll, since `observed_heads` is keyed
                    // on the frontier, not the group alone.
                    tracing::warn!(
                        %group_id,
                        %path,
                        "retroactive conflict-copy repair permanently blocked at this frontier: \
                         obligation exceeds the bounded change size and cannot yet be split \
                         across multiple carriers"
                    );
                    observed_heads.insert(group_id.clone(), committed_frontier);
                    failover_frontiers.remove(&group_id);
                }
                RetroactiveRepairOutcome::AwaitingFailover { local_rank, committed_frontier } => {
                    tracing::debug!(
                        %group_id,
                        ?local_rank,
                        eligible_rank,
                        frontier = ?committed_frontier,
                        "retroactive conflict-copy repair waiting for deterministic failover rank"
                    );
                }
                RetroactiveRepairOutcome::Repaired { repaired_paths, committed_frontier: _ } => {
                    // A successful bounded carrier is deliberately not cached. It
                    // may have left additional eligible source paths behind, so
                    // the next poll examines its new head and drains another
                    // batch. The first eventual no-op caches the final frontier.
                    tracing::info!(
                        %group_id,
                        repaired_paths = ?repaired_paths,
                        "authored retroactive conflict-copy merge resolution"
                    );
                    state.record_activity();
                    // Announces unconditionally (`repaired_paths` is already
                    // known non-empty), never gated on whether this device
                    // happens to have the repaired source materialized yet.
                    // Using `DaemonState::broadcast_change`'s own
                    // `records`-derived path here would be wrong: the carrier
                    // this just authored is already a durable DAG fact
                    // regardless of this device's local materialization
                    // state, and a peer must learn of it immediately rather
                    // than only after the next periodic audit -- see
                    // `announce_heads_to_group_peers`'s own doc comment.
                    state.announce_heads_to_group_peers(&group_id).await;
                    failover_frontiers.remove(&group_id);
                }
            }
        }

        tokio::time::sleep(REPAIR_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_unlocks_one_additional_rank_per_stable_frontier_window() {
        assert_eq!(eligible_rank_for_elapsed(Duration::ZERO), 0);
        assert_eq!(eligible_rank_for_elapsed(Duration::from_millis(4_999)), 0);
        assert_eq!(eligible_rank_for_elapsed(Duration::from_secs(5)), 1);
        assert_eq!(eligible_rank_for_elapsed(Duration::from_millis(14_999)), 2);
        assert_eq!(eligible_rank_for_elapsed(Duration::from_secs(15)), 3);
    }

    #[test]
    fn only_settled_settles_generation() {
        assert!(settles_generation(&RetirementAttempt::Settled { retired: 0 }));
        assert!(settles_generation(&RetirementAttempt::Settled { retired: 3 }));
        assert!(!settles_generation(&RetirementAttempt::Busy));
        assert!(!settles_generation(&RetirementAttempt::RetryRequired));
    }

    /// Guard-contention (`Busy`) failure injection: `RetirementWake::
    /// complete` must not be called for the claimed generation, so the
    /// group stays reported by `pending` for the next wake/backstop.
    #[test]
    fn busy_outcome_leaves_generation_pending() {
        let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
        wake.mark_dirty("g1");
        let claimed = *wake.pending().get("g1").unwrap();
        if settles_generation(&RetirementAttempt::Busy) {
            wake.complete("g1", claimed);
        }
        assert_eq!(wake.pending().get("g1"), Some(&1));
    }

    /// Transient-retry failure injection: a `RetryRequired` outcome (a
    /// copy's tombstone materialize hit a transient block/disk condition)
    /// must equally not complete the claimed generation.
    #[test]
    fn retry_required_outcome_leaves_generation_pending() {
        let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
        wake.mark_dirty("g1");
        let claimed = *wake.pending().get("g1").unwrap();
        if settles_generation(&RetirementAttempt::RetryRequired) {
            wake.complete("g1", claimed);
        }
        assert_eq!(wake.pending().get("g1"), Some(&1));
    }

    /// The core lost-wakeup regression test: an event landing WHILE a
    /// pass is auditing generation 1 must not be swallowed by that pass's
    /// own (successful) completion -- it must provoke exactly one
    /// follow-up audit, which then settles cleanly with no event left
    /// over.
    #[test]
    fn event_during_audit_provokes_exactly_one_follow_up_audit() {
        let wake = crate::sync_runtime::retirement_wake::RetirementWake::new();
        wake.mark_dirty("g1");
        let claimed_generation_1 = *wake.pending().get("g1").unwrap();
        assert_eq!(claimed_generation_1, 1);

        // A DAG admission (or job completion) lands while the pass that
        // claimed generation 1 is still auditing.
        wake.mark_dirty("g1");

        // That in-flight pass finishes and reports success for the
        // generation it actually claimed, not the new one.
        if settles_generation(&RetirementAttempt::Settled { retired: 1 }) {
            wake.complete("g1", claimed_generation_1);
        }

        // Exactly one follow-up audit's worth of pending work remains --
        // the mid-audit event was not lost.
        let pending = wake.pending();
        assert_eq!(pending.get("g1"), Some(&2));

        let claimed_generation_2 = *pending.get("g1").unwrap();
        if settles_generation(&RetirementAttempt::Settled { retired: 0 }) {
            wake.complete("g1", claimed_generation_2);
        }
        assert!(wake.pending().is_empty());
    }
}

/// `run_hazard_recheck_pass`'s own regression coverage: proves a path
/// marked `HazardHeld` gets re-examined and un-held by the sweep alone,
/// with no fresh incoming record for that exact path -- the gap
/// `MaterializationStateRepository::list_held_paths`'s own doc comment
/// describes. Marks the path held via a direct `set_held` call rather than
/// through real case-fold/normalization hazard detection: those checks
/// probe the real tempdir's filesystem (`hazard::is_case_insensitive_
/// filesystem`/`is_normalization_insensitive_filesystem`), which is a
/// no-op on this crate's own Linux CI/dev tempdirs regardless of policy --
/// see `crate::convergence`'s own `hazard_reason_tests` for why those
/// tests skip outright there. A path this device's own `hazard_reason_for`
/// call (invoked fresh, inside `materialize`, every time
/// `reconcile_paths_directly` resolves it) finds NOT hazardous already
/// clears its own hold as a documented side effect of successful
/// reconciliation -- what nothing does today is ever CALL that
/// reconciliation for a held path with no new incoming record of its own,
/// which is exactly what this sweep exists to do.
#[cfg(test)]
mod hazard_recheck_tests {
    use super::{run_hazard_recheck_pass, DaemonState};
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use yadorilink_root_authority::root_identity::VerifiedRoot;

    const GROUP: &str = "hazard-recheck-group";

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

    /// Same shape as `process_group_publication_tests::
    /// build_state_with_adopted_group` (`engine.rs`), trimmed to what this
    /// module needs: no candidate `PeerSyncSession` is registered, since
    /// `DaemonState::local_retirement_session` builds its own synthetic
    /// loopback session independently of `state.peers`.
    async fn build_state_with_adopted_group() -> (Arc<DaemonState>, tempfile::TempDir) {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let replica_coordinator =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let block_store = Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());

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

        (state, root_dir)
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

    /// The core regression: a path manually marked held (standing in for
    /// any real hazard reason) with an already-admitted, trivially-
    /// materializable DAG version gets written to disk and un-held by
    /// `run_hazard_recheck_pass` alone -- no new incoming record for this
    /// exact path is ever admitted or announced. RED-confirmed by
    /// commenting out the `reconcile_paths_directly` call inside `run_
    /// hazard_recheck_pass` (leaving only the empty-listing early return):
    /// the held path then never gets re-examined at all, exactly the gap
    /// this closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_path_is_re_examined_and_cleared_by_the_sweep_alone() {
        let (state, root_dir) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[81u8; 32]);
        let version = empty_version(1_700_000_000);
        let change = admit_change(&state, "device-a", &key, "held.txt", &version);

        // `set_held` is an UPDATE on an existing `files` row (see its own
        // doc comment) -- production always reaches it through `hold_
        // record`, which upserts the index row first. Mirrors that here
        // directly rather than going through real hazard detection (see
        // this test module's own doc comment for why); a DAG-backed row
        // needs its authoring change attached (`upsert_file_with_origin_
        // and_author`), or the schema's own constraint rejects it.
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &yadorilink_replica_domain::file::FileRecord {
                    path: "held.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 1_700_000_000,
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
            .set_held(GROUP, "held.txt", "test_injected_hazard", 1_000)
            .unwrap();
        assert!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(GROUP, "held.txt")
                .unwrap()
                .is_some(),
            "sanity: the path must actually be held before the sweep runs"
        );

        state.replica_coordinator.hazard_recheck_wake().mark_dirty(GROUP);
        let pending = state.replica_coordinator.hazard_recheck_wake().pending();
        run_hazard_recheck_pass(&state, pending).await;

        assert!(
            state
                .replica_coordinator
                .materialization_state_repository()
                .get_held_state(GROUP, "held.txt")
                .unwrap()
                .is_none(),
            "the sweep must clear a hold whose hazard is already gone, with no fresh incoming \
             record for this exact path"
        );
        assert!(
            root_dir.path().join("held.txt").exists(),
            "clearing the hold must come from a real, successful reconciliation -- the path \
             must actually materialize to disk, not just have its hold bit flipped"
        );
    }

    /// A group with nothing held at all must settle its generation on the
    /// FIRST pass (the empty-listing early-return branch) -- otherwise a
    /// busy group with no real hazards would spin `pending` forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_group_with_nothing_held_settles_immediately() {
        let (state, _root_dir) = build_state_with_adopted_group().await;

        state.replica_coordinator.hazard_recheck_wake().mark_dirty(GROUP);
        let pending = state.replica_coordinator.hazard_recheck_wake().pending();
        let generation = *pending.get(GROUP).unwrap();
        run_hazard_recheck_pass(&state, pending).await;

        assert_eq!(
            state.replica_coordinator.hazard_recheck_wake().pending().get(GROUP),
            None,
            "settled generation must not still be reported pending"
        );
        let _ = generation;
    }
}

/// `run_ignore_recheck_pass`'s own regression coverage: proves the
/// liveness gap the `IGNORE_SET_REFRESH_INTERVAL` cache-TTL fix alone left
/// open (see `run_ignore_recheck_loop`'s own doc comment) is actually
/// closed -- a path parked `'ignore_blocked'` gets re-examined and re-armed
/// by the sweep alone, with no fresh incoming record for that exact path.
#[cfg(test)]
mod ignore_recheck_tests {
    use super::{run_ignore_recheck_pass, DaemonState};
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_peer_session::peer_session::PeerSyncSession;
    use yadorilink_peer_session::ports::{PeerBlockStream, PeerMessageChannel};
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use yadorilink_root_authority::root_identity::VerifiedRoot;
    use yadorilink_sync_sqlite::projection_obligations::NonExactProofKind;
    use yadorilink_transport::TransportError;

    /// A channel with nothing on the far end -- registering a session
    /// bound to this is enough to make this group's `candidate_sessions()`
    /// non-empty, so `process_group_via_obligations` does not take its
    /// "no live candidate" durable-backoff branch. `materialize()` never
    /// needs a fetch for this module's own tests (every path is either
    /// zero-block or deliberately unfetchable and never asserted to
    /// converge through it), so `open_block_stream` returning
    /// `ChannelClosed` is never actually exercised for real content.
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

    /// Registers a candidate session for `GROUP`, mirroring `convergence::
    /// engine`'s own `build_state_with_adopted_group` -- needed only by
    /// tests that go on to drive the real obligation scheduler
    /// (`drive_obligations_once_for_test`) and expect it to actually
    /// reconcile, not just back off for lack of any candidate.
    fn register_candidate_session(state: &Arc<DaemonState>, root: &std::path::Path) {
        let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
        let session = PeerSyncSession::new_with_dependencies(
            Arc::new(NoopChannel),
            "device-local".to_string(),
            "device-peer".to_string(),
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(state.block_store.clone())),
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), root.to_path_buf())]),
            Some(state.forward_tx.clone()),
            deps,
        );
        state.peers.register_session("device-peer".to_string(), session);
    }

    const GROUP: &str = "ignore-recheck-group";

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

    /// Same shape as `hazard_recheck_tests::build_state_with_adopted_group`.
    async fn build_state_with_adopted_group() -> (Arc<DaemonState>, tempfile::TempDir) {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let replica_coordinator =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let block_store = Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());

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

        (state, root_dir)
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

    /// The core regression: a path parked `'ignore_blocked'` (standing in
    /// for a real ignore-policy settlement -- see this module's own doc
    /// comment for why a direct park, not real `.yadorilinkignore`
    /// matching, is used here, mirroring `hazard_recheck_tests`' own
    /// direct-`set_held` convention) with an already-admitted, trivially-
    /// materializable DAG version is re-armed back to `'pending'` by
    /// `run_ignore_recheck_pass` alone -- no new incoming record for this
    /// exact path, and no `.yadorilinkignore` edit for the sweep to react
    /// to -- and then converges for real once the ordinary obligation-
    /// driven scheduler picks it up. RED-confirmed by commenting out the
    /// re-arm loop inside `run_ignore_recheck_pass` (leaving only the
    /// empty-listing early return): the parked path then never gets
    /// re-examined at all, exactly the gap this closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ignore_blocked_path_is_re_examined_and_rearmed_by_the_sweep_alone() {
        let (state, root_dir) = build_state_with_adopted_group().await;
        // No `local_retirement_session` pre-warm needed here (unlike
        // `hazard_recheck_tests`' analogous setup): `run_ignore_recheck_
        // pass` is a pure ignore-policy query now (Phase E finding) and
        // never constructs any `PeerSyncSession` at all, so there is no
        // first-construction-after-registration ordering hazard to avoid.
        register_candidate_session(&state, &root_dir.path().canonicalize().unwrap());
        let key = SigningKey::from_bytes(&[82u8; 32]);
        admit_change(&state, "device-a", &key, "was-ignored.txt", &empty_version(1_700_000_000));

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
            .unwrap()
            .expect("admission must have created an obligation");
        let claimed_g = obligation_before.invalidation_generation;
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_complete_obligation_if_non_exact_proof_current(
                    GROUP,
                    "was-ignored.txt",
                    claimed_g,
                    obligation_before.obligation_incarnation,
                    NonExactProofKind::IgnoreExcluded,
                )
                .unwrap(),
            "sanity: parking the obligation as ignore_blocked must succeed"
        );
        assert_eq!(
            state
                .replica_coordinator
                .sqlite()
                .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
                .unwrap()
                .unwrap()
                .state,
            "ignore_blocked",
            "sanity: the path must actually be parked before the sweep runs"
        );

        run_ignore_recheck_pass(&state, GROUP).await;

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "was-ignored.txt")
            .unwrap()
            .expect("re-arming must not delete the obligation");
        assert_eq!(
            obligation.state, "pending",
            "the sweep must re-arm a path whose ignore-exclusion is already gone, with no \
             fresh incoming record for this exact path"
        );
        assert_eq!(obligation.invalidation_generation, claimed_g, "re-arming must not bump G");

        // The re-arm alone doesn't materialize anything -- it just hands
        // the path back to the ordinary scheduler. Confirm that scheduler
        // actually converges it, end to end.
        assert!(crate::convergence::engine::drive_obligations_once_for_test(&state, 128, 256).await);
        assert!(
            root_dir.path().join("was-ignored.txt").exists(),
            "the ordinary obligation-driven scheduler must materialize the re-armed path to disk"
        );
    }

    /// The specific permanent-stall bug an independent review caught: the
    /// PREVIOUS version of `run_ignore_recheck_pass` gated re-arm on
    /// `ProjectionAttempt::is_settled(path)` after driving a reconcile
    /// attempt through `local_retirement_session` -- backed by a
    /// `LoopbackPeerMessageChannel` whose `open_block_stream` always
    /// returns `ChannelClosed`. A path needing an actual block fetch could
    /// therefore never `is_settled` through that session, so it could
    /// never re-arm at all -- permanently stuck `'ignore_blocked'` even
    /// after the user un-ignored it. This test's own `FileVersion` carries
    /// a real, non-empty block that is never written to the local block
    /// store, specifically so a reconcile/materialize attempt through the
    /// local-only session would hit exactly that `ChannelClosed` failure
    /// -- proving re-arm depends only on the ignore-policy verdict, never
    /// on whether the content happens to be fetchable through whichever
    /// session ran the check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unignoring_a_path_whose_content_cannot_be_locally_fetched_still_rearms_it() {
        let (state, _root_dir) = build_state_with_adopted_group().await;
        let key = SigningKey::from_bytes(&[83u8; 32]);
        let version = FileVersion::new(
            vec![yadorilink_replica_domain::file::VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(vec![9u8; 32]),
                size: 4096,
            }],
            4096,
            FileMeta {
                mtime_unix_nanos: 1_700_000_200,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        admit_change(&state, "device-a", &key, "needs-a-real-fetch.bin", &version);

        let obligation_before = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "needs-a-real-fetch.bin")
            .unwrap()
            .expect("admission must have created an obligation");
        let claimed_g = obligation_before.invalidation_generation;
        assert!(
            state
                .replica_coordinator
                .sqlite()
                .dag_complete_obligation_if_non_exact_proof_current(
                    GROUP,
                    "needs-a-real-fetch.bin",
                    claimed_g,
                    obligation_before.obligation_incarnation,
                    NonExactProofKind::IgnoreExcluded,
                )
                .unwrap(),
            "sanity: parking the obligation as ignore_blocked must succeed"
        );

        run_ignore_recheck_pass(&state, GROUP).await;

        let obligation = state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "needs-a-real-fetch.bin")
            .unwrap()
            .expect("re-arming must not delete the obligation");
        assert_eq!(
            obligation.state, "pending",
            "the sweep must re-arm a path whose ignore-exclusion is gone regardless of whether \
             its content can be fetched through this sweep's own local-only session -- \
             materialization is the ordinary scheduler's job, not this sweep's"
        );
        assert_eq!(obligation.invalidation_generation, claimed_g, "re-arming must not bump G");
    }

    /// A group with nothing parked at all must return immediately without
    /// touching anything -- the empty-listing early-return branch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_group_with_nothing_ignore_blocked_is_a_no_op() {
        let (state, _root_dir) = build_state_with_adopted_group().await;
        run_ignore_recheck_pass(&state, GROUP).await;
        assert!(state.replica_coordinator.sqlite().dag_list_ignore_blocked_paths(GROUP).unwrap().is_empty());
    }
}
