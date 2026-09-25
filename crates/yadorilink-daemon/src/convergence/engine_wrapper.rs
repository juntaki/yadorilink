//! Runs the existing materialization engine together with the independent
//! retroactive conflict-copy repair loop.
//!
//! Keeping the repair as a wrapper leaves `engine.rs` free to evolve
//! independently. If either essential loop exits, this wrapper exits and
//! `DaemonState`'s existing `spawn_restarting` supervision restarts both.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use crate::local_convergence::types::RetirementAttempt;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::RetroactiveRepairOutcome;
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

use crate::daemon_state::DaemonState;

pub use super::engine_impl::ConvergenceEngine;

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
pub async fn run_once_for_test(engine: &ConvergenceEngine) -> bool {
    super::engine_impl::run_once_for_test(engine).await
}

/// See `engine_impl::drive_obligations_once_for_test`'s own doc comment --
/// the obligation-driven worker's counterpart of [`run_once_for_test`],
/// exposed the same way for the same reason.
#[cfg(any(test, feature = "test-support"))]
pub async fn drive_obligations_once_for_test(
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test(engine, per_group_limit, total_limit).await
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
    engine: &ConvergenceEngine,
    per_group_limit: u32,
    total_limit: u32,
    hooks: &Arc<BeforeCompletionHook>,
) -> bool {
    super::engine_impl::drive_obligations_once_for_test_with_hooks(
        engine,
        per_group_limit,
        total_limit,
        hooks,
    )
    .await
}

pub async fn run(engine: Arc<ConvergenceEngine>) {
    let state = engine.state().clone();
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
    // every restart. This manual select-then-abort-and-await reproduces
    // `tokio::task::JoinSet`'s "aborts every remaining task and awaits their
    // completion" contract explicitly -- this function never returns while
    // any of the five tasks is still alive.
    let retire_state = state.clone();
    let hazard_recheck_state = state.clone();
    let ignore_recheck_state = state.clone();
    let mut engine_handle = tokio::spawn(super::engine_impl::run(engine));
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
/// own doc comment). Without retirement, one device (of several, all on an
/// identical multi-head DAG frontier) can keep holding a conflict copy
/// every device's own `resolve_path_heads` agrees is no longer required.
///
/// Primarily event-driven, not polled: `RetirementWake::mark_dirty` fires
/// after exactly the two events that can change a copy's justification --
/// this device's own DAG frontier advancing (locally authored or admitted
/// from a peer) and a materialization job reaching `Completed` -- so this
/// loop reacts within one wake rather than waiting up to a whole poll
/// interval. `RETIREMENT_BACKSTOP_INTERVAL` remains as a correctness
/// backstop only, for a mark lost to a crash or a race with linking, not as
/// the primary liveness path. This loop is needed because the Convergence
/// Engine (`engine.rs`) drives ordinary path reconciliation through
/// `reconcile_paths_directly`, which never calls this audit; the periodic
/// materialization-repair sweep in `daemon_state.rs` does, but a group
/// whose sweep interval is long -- or disabled for a whole run, as strict
/// acceptance tests do to prove the Convergence Engine's own mechanism
/// converges without it -- would otherwise have no path that ever retires
/// a copy at all.
async fn run_ephemeral_conflict_copy_retire_loop(state: Arc<DaemonState>) {
    loop {
        tokio::select! {
            _ = state.replica_coordinator.retirement_wake().retirement_wake_notified() => {
                let pending = state.replica_coordinator.retirement_wake().pending();
                run_retirement_pass(&state, pending).await;
            }
            _ = tokio::time::sleep(RETIREMENT_BACKSTOP_INTERVAL) => {
                // Counted so a test waiting past this interval can check that
                // the tick it is waiting for actually happened, rather than
                // assume a long enough sleep implies one. Observation only;
                // nothing reads it to decide anything.
                state.note_retirement_backstop_tick();
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
/// for it) -- no peer session involved, because retirement's decision never
/// depended on which, or any, peer happened to be connected.
/// `RetirementWake::complete` is
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
/// Engine's own per-job completion oracle uses. A held path's hazard status
/// follows only local DAG and disk state, so this decision is not
/// peer-dependent at all. It still prefers an already-live candidate session
/// when one exists, because a peer is what makes content the recheck may need
/// obtainable; with none, the local executor runs the same pass and a path
/// waiting on content it cannot get stays held.
///
/// What it no longer does is manufacture a session to run local work through.
/// That used to trigger `NetmapChangeAuthenticator::new` ->
/// `validate_linked_history_best_effort`, which can transiently quarantine
/// every OTHER already-connected session's
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
        let local_for_list = state.local_convergence();
        let list_group_id = group_id.clone();
        let held_paths = match tokio::task::spawn_blocking(move || {
            let held = replica_coordinator_for_list
                .materialization_state_repository()
                .list_held_paths(&list_group_id)?;
            // A path held because its existing file is unreadable to its
            // owner is re-examined only once something it was held against
            // has changed: re-running it unchanged can only reach the same
            // hold again. A failed check keeps the path in the pass.
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                held.into_iter()
                    .filter(|path| {
                        !local_for_list
                            .metadata_unprovable_hold_unchanged(&list_group_id, path)
                            .unwrap_or_else(|error| {
                                tracing::debug!(
                                    %error,
                                    group_id = %list_group_id,
                                    path = %path,
                                    "could not tell whether a metadata hold is unchanged; \
                                     re-examining it"
                                );
                                false
                            })
                    })
                    .collect::<Vec<_>>(),
            )
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
        let paths: std::collections::BTreeSet<String> = held_paths.into_iter().collect();
        let peer = crate::hydration::candidate_sessions(state, &group_id)
            .into_iter()
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, session)| session);
        let outcome = match peer {
            Some(session) => match state.peers.local_convergence(
                yadorilink_peer_session::convergence_driver::ConvergenceDriver::peer_device_id(
                    session.as_ref(),
                ),
            ) {
                Some(local) => local
                    .reconcile_paths_directly(
                        &(session.clone()
                            as std::sync::Arc<
                                dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                            >),
                        &group_id,
                        paths,
                    )
                    .await,
                None => Ok(None),
            },
            // No peer is connected. The re-check still runs: a hazard resolves
            // for purely local reasons -- the name that was in the way is gone,
            // the conflicting row was retired -- and this device needs nobody's
            // help to notice. What it cannot do alone is obtain content it does
            // not hold, and a path waiting on that stays held, which is what
            // being unable to reach anyone has always meant here.
            None => state.local_convergence().reconcile_paths(&group_id, paths).await,
        };
        match outcome {
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
/// Spawned for real from `run`, alongside the retirement and
/// hazard-recheck loops: `process_group_via_obligations` is the live
/// claim source, so an `'ignore_blocked'` row is a real, live
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
/// hazard-recheck sweep does: gating re-arm on
/// `ProjectionAttempt::is_settled(path)` after running reconciliation
/// with no way to obtain content at all would stall permanently. A path whose content
/// requires an actual block fetch (anything but the trivial empty-content
/// case) could never `is_settled` on such a pass, so it could never
/// re-arm at all: an unignored file needing real content would stay
/// `'ignore_blocked'` forever, invisible to the production scheduler
/// (which only ever claims `'pending'` rows). Reproducing that needs a
/// `FileVersion` with a real (non-empty) block absent from the local store
/// -- `empty_version()` is trivially "materializable" with no blocks at
/// all and so never exercises the ChannelClosed path. This function has
/// no dependency on full settlement at all: whether a path is still ignored is a pure,
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
        EffectiveIgnoreSet::load_for_link_root(root)
            .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only())
    });
    let mut any_rearmed = false;
    for path in &ignore_blocked_paths {
        // The same rule as `LocalConvergenceExecutor::is_locally_ignored`:
        // a directory-only pattern covers a path the namespace places a
        // directory at.
        let still_ignored = ignore_set.as_ref().is_some_and(|set| {
            is_ignore_file_relative_path(path)
                || set.is_ignored(path, false)
                || (set.is_ignored(path, true)
                    && matches!(
                        state.replica_coordinator.desired_path_state(group_id, path),
                        Ok(yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory { .. }
                            | yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory)
                    ))
        });
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
                RetroactiveRepairOutcome::PlanStale { reason } => {
                    // Something the plan was built against moved while this
                    // pass ran, and nothing was written. The next poll plans
                    // against the state that actually exists now. Deliberately
                    // not cached — caching the frontier here would suppress
                    // exactly the re-plan this asks for, and for
                    // `ObligationsChanged` that frontier has not even moved.
                    tracing::debug!(
                        %group_id,
                        ?reason,
                        "retroactive conflict-copy repair re-driving: the plan went stale"
                    );
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
                    // `note_local_commit_for_group`'s own doc comment.
                    //
                    // Flush BEFORE announcing, for the identical reason
                    // `broadcast_change` itself does -- this repair carrier
                    // calls `note_local_commit_for_group` directly rather
                    // than going through `broadcast_change`, so without this
                    // it would get no checkpoint-flush trigger at all: the
                    // repair Change would be announced but never Published,
                    // a peer's fetch would find no evidence to serve, and
                    // the carrier would silently never arrive (exercised by
                    // every mesh chaos test whose conflict resolution routes
                    // through this carrier path).
                    state.flush_pending_checkpoint_for_group(&group_id).await;
                    state.note_local_commit_for_group(&group_id).await;
                    failover_frontiers.remove(&group_id);
                }
            }
        }

        tokio::time::sleep(REPAIR_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
#[path = "engine_wrapper/tests.rs"]
mod tests;

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
#[path = "engine_wrapper/hazard_recheck_tests.rs"]
mod hazard_recheck_tests;

/// `run_ignore_recheck_pass`'s own regression coverage: proves the
/// liveness gap the `IGNORE_SET_REFRESH_INTERVAL` cache-TTL fix alone left
/// open (see `run_ignore_recheck_loop`'s own doc comment) is actually
/// closed -- a path parked `'ignore_blocked'` gets re-examined and re-armed
/// by the sweep alone, with no fresh incoming record for that exact path.
#[cfg(test)]
#[path = "engine_wrapper/ignore_recheck_tests.rs"]
mod ignore_recheck_tests;
