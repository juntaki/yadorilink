//! Runs the existing materialization engine together with the independent
//! retroactive conflict-copy repair loop.
//!
//! Keeping the repair as a wrapper leaves `engine.rs` available for Stage 3 to
//! evolve independently. If either essential loop exits, this wrapper exits and
//! `DaemonState`'s existing `spawn_restarting` supervision restarts both.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::RetroactiveRepairOutcome;
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
/// Each rank gets an exclusive window before the next deterministic fallback
/// becomes eligible. This only suppresses duplicate work: after enough
/// unchanged-frontier windows every authorized writer may act.
const REPAIR_FAILOVER_RANK_INTERVAL: Duration = Duration::from_secs(5);

fn eligible_rank_for_elapsed(elapsed: Duration) -> usize {
    (elapsed.as_millis() / REPAIR_FAILOVER_RANK_INTERVAL.as_millis())
        .try_into()
        .unwrap_or(usize::MAX)
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
    // Explicit abort-and-await of the two survivors below, not a bare
    // `tokio::select!` on the three `JoinHandle`s alone, gives the "either
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
    // any of the three tasks is still alive.
    let engine_state = state.clone();
    let retire_state = state.clone();
    let mut engine_handle = tokio::spawn(super::engine_impl::run(engine_state));
    let mut repair_handle = tokio::spawn(run_retroactive_repair_loop(state));
    let mut retire_handle = tokio::spawn(run_ephemeral_conflict_copy_retire_loop(retire_state));
    tokio::select! {
        _ = &mut engine_handle => {}
        _ = &mut repair_handle => {}
        _ = &mut retire_handle => {}
    }
    for handle in [&mut engine_handle, &mut repair_handle, &mut retire_handle] {
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
                let dirty = state.replica_coordinator.retirement_wake().drain();
                run_retirement_pass(&state, dirty).await;
            }
            _ = tokio::time::sleep(RETIREMENT_BACKSTOP_INTERVAL) => {
                if let Some(groups) = list_linked_groups_for_retirement(&state).await {
                    run_retirement_pass(&state, groups).await;
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

/// Runs `PeerSyncSession::retire_conflict_copies_only` for each of `groups`,
/// trying every candidate session in turn (matching the legacy sweep's own
/// resilience to one stale/erroring session) and re-marking a group dirty
/// if no session could actually run its audit this pass, so it is retried
/// on the next wake or backstop rather than silently dropped -- see
/// `RetirementWake::drain`'s own doc comment for why the caller carries
/// this responsibility.
async fn run_retirement_pass(state: &Arc<DaemonState>, groups: BTreeSet<String>) {
    for group_id in groups {
        // Any currently-connected peer session for this group can run the
        // audit -- it is driven by this device's own local DAG/file state,
        // not by which specific peer object it is invoked through.
        let candidates = crate::hydration::candidate_sessions(state, &group_id);
        if candidates.is_empty() {
            // No live session for this group at all right now (e.g. no
            // peer has ever connected) -- nothing can run the audit
            // through yet. Not an error: a solo/offline group's ephemeral
            // conflict copies simply cannot retire until some session
            // exists. Re-mark dirty so a future connect's own trigger, or
            // the next backstop pass, tries again.
            state.replica_coordinator.retirement_wake().mark_dirty(&group_id);
            continue;
        }
        let mut last_error = None;
        let mut ran = false;
        for (peer_id, session) in &candidates {
            match session.clone().retire_conflict_copies_only(&group_id).await {
                // `Ok(true)` actually ran the audit; `Ok(false)` means a
                // full `reconcile_local_materialization_audit` was already
                // in flight for this group through some session -- that
                // audit's own retire step covers this same evaluation, so
                // either way there is nothing further to try on another
                // peer.
                Ok(_) => {
                    ran = true;
                    last_error = None;
                    break;
                }
                Err(error) => {
                    tracing::warn!(
                        %group_id,
                        peer = %peer_id,
                        %error,
                        "ephemeral conflict-copy retire audit peer failed; trying another peer"
                    );
                    last_error = Some(error);
                }
            }
        }
        if let Some(error) = last_error {
            tracing::warn!(
                %group_id,
                %error,
                "ephemeral conflict-copy retire audit failed for every connected peer this tick"
            );
        }
        if !ran {
            state.replica_coordinator.retirement_wake().mark_dirty(&group_id);
        }
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
}
