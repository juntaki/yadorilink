//! Three of the four per-link background tasks `LinkRuntimeFactory::build`
//! spawns: the debounce **accumulator** (raw filesystem events -> windowed
//! batches), the **executor** (batches -> chunk/index/broadcast, plus this
//! link's startup scan+redrive retry loop), and the periodic
//! dirty-journal-redrive backstop task. Each function here spawns exactly
//! one of those and returns its `JoinHandle` -- `LinkRuntimeFactory::build`
//! wires their shared inputs (channels, `Arc` clones) and collects the
//! handles into the `Vec<JoinHandle<()>>` a `LinkRuntime` is built from.
//!
//! The 4th task, the periodic live materialization-repair task, is
//! deliberately NOT here: it needs `DaemonState::root_lease_for` (through
//! `LinkRegistry`, not this module tree's own narrow
//! `LinkRuntimeDependencies` bundle), so the daemon's own `LinkRuntimeController` spawns it
//! directly and passes the resulting `JoinHandle` into
//! `LinkRuntimeFactory::build` -- see that function's own doc comment for
//! why. Keeping this whole module tree free of `DaemonState` is what keeps
//! it out of the `daemon_state`/`link_registry` dependency cycle (see this
//! crate's own architecture-boundary checks).
//!
//! Moved here from the daemon's own `LinkRuntimeController` as a pure relocation -- every task's
//! logic is byte-identical to before the move; only the closures'
//! previously-inline captures are now this module's function parameters.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_filesystem_sync::debounce::{self, DebounceFlush};
use yadorilink_local_capture::LocalChangeProcessor;
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};
use yadorilink_root_authority::root_identity::RootVerificationStatePort;

use crate::link_runtime::dependencies::LinkRuntimeDependencies;
use crate::link_runtime::operations::capture_local_change::announce_local_change;
use crate::link_runtime::startup::{ensure_initial_change_history, GroupStartupReadyGuard};

/// How often the live dirty-path-journal redrive pass runs for this link.
/// `record_dirty_path`/`redrive_dirty_journal` (`local_change.rs`) exist
/// precisely because a local edit's own index+DAG write can fail
/// transiently (most commonly `SQLITE_BUSY`/`SQLITE_LOCKED` under real
/// concurrent load), leaving the edit journaled but never emitted as a
/// change -- before this, the ONLY consumer of that journal was the
/// one-shot startup rescan (`redrive_dirty_journal`'s own call site in this
/// module's own `spawn_executor_task`), so a failure that happened *during*
/// a live run (not at startup) sat un-synced for the rest of the run unless
/// the exact same path happened to be touched again. Confirmed as a real,
/// reproduced convergence gap (not merely a slowness one) on a contended
/// host: pre-writer-gate, a full mesh of paired sessions could push
/// `SQLITE_BUSY` past even a widened `retry_on_database_locked` (the
/// `SyncState` writer gate has since made that own-process shape
/// impossible, though other transient write failures remain), and nothing
/// during normal operation
/// ever looked at `local_dirty_paths` again afterward. Short relative to
/// `MATERIALIZATION_REPAIR_INTERVAL` (that one walks the whole linked
/// folder; this one is a single indexed query, a no-op read when nothing is
/// journaled) -- the whole point is closing this gap fast, not merely
/// eventually.
const DIRTY_JOURNAL_REDRIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The debounce accumulator task: reads raw filesystem events off
/// `events_rx` and coalesces them into windowed batches sent on
/// `flush_tx`. Never touches `DaemonState` at all -- it only knows about
/// `yadorilink_filesystem_sync::debounce`'s own types.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_accumulator_task(
    events_rx: tokio::sync::mpsc::Receiver<yadorilink_filesystem_sync::watcher::FsChangeEvent>,
    overflowed: Arc<std::sync::atomic::AtomicBool>,
    watcher_guard: yadorilink_filesystem_sync::watcher::WatcherGuard,
    flush_tx: tokio::sync::mpsc::Sender<DebounceFlush>,
    flush_request_rx: tokio::sync::mpsc::Receiver<debounce::FlushPathRequest>,
    flush_all_request_rx: tokio::sync::mpsc::Receiver<debounce::FlushAllRequest>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Kept alive for this task's whole lifetime — dropping it would
        // stop the underlying OS watch.
        let _watcher_guard = watcher_guard;
        debounce::run_debouncer(
            debounce::DebounceConfig::default(),
            events_rx,
            flush_tx,
            overflowed,
            flush_request_rx,
            flush_all_request_rx,
        )
        .await;
    })
}

/// Whether tombstone suppression may be cleared after checking (and, if
/// actually pending, running) duplicate-root recovery for this startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateRecoveryOutcome {
    /// Nothing was pending, or a pending set fully resolved: suppression
    /// may be cleared.
    Complete,
    /// A pending set still has unresolved paths: keep suppression armed.
    StillPending,
    /// The durable pending state could not be read at all: fail closed,
    /// keep suppression armed.
    UnknownFailClosed,
}

/// The duplicate-root recovery gate: `corroborate_and_resolve` (the
/// expensive per-live-row pass -- re-reading/re-hashing every live indexed
/// file against disk) must run ONLY when durable state says duplicate-root
/// recovery is actually pending for this group. An ordinary startup with
/// nothing pending must not pay for a full content pass over the linked
/// folder just to find out there is nothing to do.
///
/// Every real dependency is taken as an already-resolved value or an
/// injected closure precisely so a unit test can prove
/// `corroborate_and_resolve` is never invoked on the "not pending" path
/// without needing a real index or disk -- see `tests` below.
fn resolve_duplicate_recovery_gate<E: std::fmt::Display>(
    group_id: &str,
    pending: Result<bool, E>,
    corroborate_and_resolve: impl FnOnce(),
    recheck_pending: impl FnOnce() -> Result<bool, E>,
) -> DuplicateRecoveryOutcome {
    match pending {
        Ok(false) => DuplicateRecoveryOutcome::Complete,
        Ok(true) => {
            corroborate_and_resolve();
            match recheck_pending() {
                Ok(false) => DuplicateRecoveryOutcome::Complete,
                Ok(true) => DuplicateRecoveryOutcome::StillPending,
                Err(error) => {
                    tracing::warn!(
                        group_id = %group_id,
                        error = %error,
                        "could not re-check duplicate-recovery state after corroboration; \
                         keeping deletion suppression fail-closed"
                    );
                    DuplicateRecoveryOutcome::UnknownFailClosed
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                group_id = %group_id,
                error = %error,
                "could not determine duplicate-recovery state; keeping deletion \
                 suppression fail-closed"
            );
            DuplicateRecoveryOutcome::UnknownFailClosed
        }
    }
}

/// The synchronous pass that runs immediately after a link's initial scan:
/// re-checks disk/index convergence for the duplicate-root recovery gate, then
/// bootstraps this group's change history from the rows the scan just wrote.
/// Returns the startup failure string, if any, for the caller's retry loop.
///
/// Extracted from `spawn_executor_task` so it can be handed to `spawn_blocking`
/// whole. Both halves are open-ended in exactly the way the scan that precedes
/// them is: `list_files` reads this group's entire index,
/// `indexed_path_is_corroborated` re-reads and re-hashes every live indexed
/// file against its recorded blocks (a full content pass over the linked
/// folder) -- but only when `resolve_duplicate_recovery_gate` determines
/// duplicate-root recovery is actually pending -- and
/// `ensure_initial_change_history` converts the whole index into signed
/// history. Run inline on the executor task, all of that holds the polling
/// worker for its duration on every link start.
fn post_scan_convergence_and_history(
    deps: &Arc<LinkRuntimeDependencies>,
    local_path: &str,
    group_id: &str,
    root: &std::path::Path,
    records_is_empty: bool,
) -> Option<String> {
    let mut history_failure = None;
    // A successful *additive* scan proves only that present
    // disk entries were indexed. It deliberately leaves live
    // rows originating at the departed duplicate root intact,
    // so it does not prove disk/index convergence. Keep the
    // deletion gate armed until every live indexed path is
    // present; otherwise the next authoritative scan would
    // tombstone precisely the rows recovery preserved.
    let outcome = resolve_duplicate_recovery_gate(
        group_id,
        deps.replica_coordinator.link_repository().duplicate_recovery_pending(group_id),
        || {
            if let Ok(rows) = deps.replica_coordinator.file_index_repository().list_files(group_id)
            {
                for row in rows.into_iter().filter(|row| !row.deleted) {
                    if matches!(
                        deps.replica_coordinator.indexed_path_is_corroborated(root, group_id, &row),
                        Ok(true)
                    ) {
                        if let Err(error) = deps
                            .replica_coordinator
                            .link_repository()
                            .resolve_duplicate_recovery_path(group_id, &row.path)
                        {
                            tracing::warn!(group_id = %group_id, path = %row.path, error = %error, "could not persist duplicate-recovery path progress");
                        }
                    }
                }
            }
        },
        || deps.replica_coordinator.link_repository().duplicate_recovery_pending(group_id),
    );
    if outcome == DuplicateRecoveryOutcome::Complete {
        if let Err(e) =
            deps.replica_coordinator.link_repository().set_suppress_tombstones(local_path, false)
        {
            tracing::warn!(
                local_path = %local_path,
                error = %e,
                "could not clear this link's additive-scan flag after disk/index \
                 convergence; its deletions stay suppressed until this succeeds"
            );
        }
    }
    // `scan_existing_files_with_ignore` uses the batched index
    // writer and therefore does not append DAG changes itself.
    // Re-run the idempotent import after the rows exist so a peer
    // that negotiates change-history sync has heads to request.
    if !records_is_empty {
        // Re-establish DAG heads now that the batched scan's rows
        // exist, so a peer negotiating change-history sync has heads
        // to request. `ensure_initial_change_history` fails closed
        // (a registered device with no signing key is a
        // configuration error, not a legitimate no-emitter path --
        // see its own doc comment), so any error here is surfaced
        // rather than silently discarded, keeping a missing
        // post-scan history bootstrap observable instead of failing
        // invisibly.
        if let Err(error) = ensure_initial_change_history(deps, group_id) {
            tracing::error!(
                local_path = %local_path,
                group_id = %group_id,
                error = %error,
                "post-scan change-history bootstrap failed; group startup remains closed"
            );
            history_failure = Some(format!("post-scan change-history bootstrap failed: {error}"));
        }
    }
    history_failure
}

/// The executor task: this link's startup scan+redrive retry loop (which
/// resolves `startup_ready_guard`), then the live flush loop that consumes
/// `flush_rx` for the rest of this link's lifetime.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_executor_task(
    executor_deps: Arc<LinkRuntimeDependencies>,
    executor_local_path: String,
    executor_group_id: String,
    executor_processor: Arc<LocalChangeProcessor>,
    executor_root: PathBuf,
    executor_ignore_set: Arc<EffectiveIgnoreSet>,
    // Withhold this boot's initial-scan tombstone emission when the startup
    // interrupted-materialization repair pass errored for this group (see
    // the daemon's own `LinkRuntimeController::start_gating_tombstones`). Fail-closed: a
    // crash-mid-materialize whose repair could not disambiguate it this
    // boot must not be tombstoned.
    executor_emit_tombstones: bool,
    // Armed by `LinkRuntimeFactory::build`'s caller before its fallible
    // setup and *moved* in here, so the window between opening this group's
    // startup generation and taking ownership of it is not merely small but
    // empty: there is no path on which the generation exists without the
    // guard covering it.
    startup_ready_guard: GroupStartupReadyGuard,
    mut flush_rx: tokio::sync::mpsc::Receiver<DebounceFlush>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut executor_ignore_set = executor_ignore_set;
        let executor_canonical_root =
            executor_root.canonicalize().unwrap_or_else(|_| executor_root.clone());
        // Resolves this group's startup barrier exactly once: `Ready` on the
        // normal path just before the live flush loop below, or `Failed` on any
        // path that does not complete — a caught scan/redrive error, a scan
        // task panic surfaced as `JoinError`, or an unwind/task-abort caught by
        // the guard's `Drop`. Peer apply for the group is then deferred
        // (fail-closed) rather than admitted over a half-built index. The guard
        // carries the current `StartupGeneration`, re-armed on each retry below.
        let mut startup_ready_guard = startup_ready_guard;
        // Bounded startup retry. A transient scan/redrive fault (a brief
        // disk-full/EIO, a panic in the blocking scan task) must not wedge peer
        // apply for the group forever behind a `Failed` gate that nothing
        // re-opens. On failure the executor supersedes its generation with a
        // fresh `begin_group_startup` and re-runs the idempotent
        // scan+redrive; only after exhausting the attempts does it settle on
        // `Failed`, which a later relink/watcher restart can still recover.
        const STARTUP_MAX_ATTEMPTS: u32 = 3;
        let mut attempt: u32 = 1;
        let startup_outcome: Result<(), String> = loop {
            // `scan_existing_files` walks the whole
            // linked folder and, for every not-already-current file, reads
            // and chunks it — synchronous `std::fs` I/O plus CPU-bound
            // hashing, run directly here would otherwise monopolize this
            // tokio worker thread for the whole initial scan (a large folder
            // or a few multi-GB files stall every other task — peer message
            // handling, heartbeats, control-socket responses — scheduled on
            // the same worker for the duration). `spawn_blocking` moves it
            // onto Tokio's dedicated blocking-thread pool instead; `processor`
            // is already `Arc`-wrapped, so cloning it into the 'static
            // closure is cheap.
            let scan_result = {
                let processor = executor_processor.clone();
                let group_id = executor_group_id.clone();
                let root = executor_root.clone();
                let ignore_set = executor_ignore_set.clone();
                let emit_tombstones = executor_emit_tombstones;
                // The initial scan chunks and
                // indexes every not-already-current file — a genuine
                // sync-critical write, held for the guard's whole duration
                // (including the `spawn_blocking` await) so an update install
                // never starts mid-scan.
                let _write_activity = executor_deps.begin_write_activity();
                // `spawn_blocking` is unavailable under the single-threaded
                // deterministic simulator (there is no blocking-thread pool to
                // offload to). The offload is purely a production runtime-hygiene
                // optimization; running the identical synchronous scan inline
                // drives the exact same work to the exact same result in-sim.
                // Wrapped in `Ok` so the `match` below sees the same
                // `Result<Result<_, _>, JoinError>` shape either way.
                #[cfg(not(madsim))]
                {
                    tokio::task::spawn_blocking(move || {
                        processor.scan_existing_files_with_ignore_gated(
                            &group_id,
                            &root,
                            ignore_set.as_ref(),
                            emit_tombstones,
                        )
                    })
                    .await
                }
                #[cfg(madsim)]
                {
                    Ok::<_, tokio::task::JoinError>(
                        processor.scan_existing_files_with_ignore_gated(
                            &group_id,
                            &root,
                            ignore_set.as_ref(),
                            emit_tombstones,
                        ),
                    )
                }
            };
            let scan_failure: Option<String> = match scan_result {
                Ok(Ok(records)) => {
                    // Offloaded for the same reason the scan above is, with
                    // the same deterministic-simulator exception -- see
                    // `post_scan_convergence_and_history`'s own doc for what
                    // runs in there. A panicking blocking task is folded into
                    // the same startup-failure string the scan task's own
                    // `JoinError` produces, so this link's bounded startup
                    // retry can re-run it rather than wedging the group's gate.
                    #[cfg(not(madsim))]
                    let history_failure = {
                        let deps = executor_deps.clone();
                        let local_path = executor_local_path.clone();
                        let group_id = executor_group_id.clone();
                        let root = executor_root.clone();
                        let records_is_empty = records.is_empty();
                        match tokio::task::spawn_blocking(move || {
                            post_scan_convergence_and_history(
                                &deps,
                                &local_path,
                                &group_id,
                                &root,
                                records_is_empty,
                            )
                        })
                        .await
                        {
                            Ok(history_failure) => history_failure,
                            Err(join_err) => {
                                tracing::warn!(
                                    error = %join_err,
                                    local_path = %executor_local_path,
                                    "post-scan convergence/history task panicked"
                                );
                                Some(format!(
                                    "post-scan convergence/history task panicked: {join_err}"
                                ))
                            }
                        }
                    };
                    #[cfg(madsim)]
                    let history_failure = post_scan_convergence_and_history(
                        &executor_deps,
                        &executor_local_path,
                        &executor_group_id,
                        &executor_root,
                        records.is_empty(),
                    );
                    // One batched broadcast for the whole initial scan
                    // (batch processing) instead of one peer message per
                    // pre-existing file.
                    if history_failure.is_none() {
                        announce_local_change(
                            &executor_deps,
                            &executor_local_path,
                            &executor_group_id,
                            records,
                        )
                        .await;
                    }
                    history_failure
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, local_path = %executor_local_path, "failed to scan pre-existing files");
                    Some(format!("initial scan failed: {e}"))
                }
                Err(join_err) => {
                    tracing::warn!(error = %join_err, local_path = %executor_local_path, "initial scan task panicked");
                    Some(format!("initial scan task panicked: {join_err}"))
                }
            };

            // Startup rescan of the durable dirty-path journal. Any local edit that
            // was detected before a previous crash/restart — or left unprocessed by
            // a multi-second disk-full/EIO that outlived the in-flight retry — is
            // re-driven here, before the live watcher loop resumes, so a detected
            // edit is never silently lost across a restart. Runs after the initial
            // scan (whose own writes journal-and-clear the paths they touch), so an
            // edit already reconciled by the scan resolves to a no-op `None` and is
            // simply cleared. A redrive failure keeps the barrier closed (below),
            // so peer apply cannot race ahead of an un-redriven offline edit.
            let redrive_failure: Option<String> = {
                let _write_activity = executor_deps.begin_write_activity();
                match executor_processor
                    .redrive_dirty_journal(&executor_group_id, &executor_root)
                    .await
                {
                    Ok(outcome) => {
                        if !outcome.records.is_empty() {
                            announce_local_change(
                                &executor_deps,
                                &executor_local_path,
                                &executor_group_id,
                                outcome.records,
                            )
                            .await;
                        }
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            local_path = %executor_local_path,
                            "failed to re-drive the dirty-path journal at startup"
                        );
                        Some(format!("dirty-journal redrive failed: {e}"))
                    }
                }
            };

            match scan_failure.or(redrive_failure) {
                None => break Ok(()),
                Some(reason) if attempt >= STARTUP_MAX_ATTEMPTS => break Err(reason),
                Some(reason) => {
                    tracing::warn!(
                        attempt,
                        max_attempts = STARTUP_MAX_ATTEMPTS,
                        local_path = %executor_local_path,
                        group_id = %executor_group_id,
                        reason = %reason,
                        "group startup did not complete; retrying with a fresh generation"
                    );
                    attempt += 1;
                    // Supersede the just-failed generation with a fresh one and
                    // re-run the idempotent scan+redrive. Re-arming the guard
                    // keeps its `Drop`/`mark_*` targeting the generation now in
                    // flight, so a panic mid-retry still fails the right one.
                    // Uses `replica_coordinator`'s `StartupReadinessRegistry`
                    // accessor, consistent with `GroupStartupReadyGuard::mark_ready`/
                    // `mark_failed` (`startup.rs`) and `link_runtime_controller.rs`'s
                    // own initial `begin_group_startup` call, which construct/resolve
                    // generations the same way. Since Phase 7D-10.6's shared-registry
                    // fix, `replica_coordinator.startup_readiness()` and
                    // `sync_state.startup_readiness()` are provably the SAME live
                    // `Arc<StartupReadinessRegistry>` (see
                    // `ReplicaCoordinator::from_database`'s own doc comment and
                    // `replica_coordinator::local_mutation::tests::
                    // path_lock_is_shared_with_the_underlying_sync_state_registry`'s
                    // sibling proof for `PathLockRegistry`) -- mixing accessors here
                    // no longer orphans a generation.
                    let next_generation = executor_deps
                        .replica_coordinator
                        .startup_readiness()
                        .begin_group_startup(&executor_group_id);
                    startup_ready_guard.begin_generation(next_generation);
                }
            }
        };

        // Publish the startup outcome for this group's barrier. On success peer
        // apply proceeds against the up-to-date index; on exhausted retries it
        // stays fail-closed (`Failed`) until a relink/watcher restart supersedes
        // it. Either way local edits are untouched — they live in the index and
        // the dirty-path journal, so a `Failed` only defers peer apply. Resolving
        // here (rather than at end of scope) is also what orders the live flush
        // loop below *after* the barrier resolves: the flush loop and peer apply
        // then observe a fully-committed startup snapshot. The guard lives to end
        // of scope but is now defused, so its eventual `Drop` is a no-op.
        match startup_outcome {
            Ok(()) => startup_ready_guard.mark_ready(),
            Err(reason) => {
                tracing::error!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    attempts = STARTUP_MAX_ATTEMPTS,
                    reason = %reason,
                    "group startup failed after retries; deferring peer apply (fail-closed) for this group until it is relinked or the watcher restarts"
                );
                startup_ready_guard.mark_failed(reason);
            }
        }
        // Kept at `debug!` (downgraded 2026-09-01 from an investigation-era
        // `warn!`, which fired on every debounced flush -- too noisy for
        // production `warn!` on an active sync): is the executor task
        // still alive and draining flushes, or stuck?
        let mut c4_attr_flushes_received: u64 = 0;
        let mut c4_attr_flushes_completed: u64 = 0;
        while let Some(flush) = flush_rx.recv().await {
            c4_attr_flushes_received += 1;
            let c4_attr_flush_kind = if matches!(flush, DebounceFlush::RescanRequired) {
                "RescanRequired"
            } else {
                "Paths"
            };
            let c4_attr_start = std::time::Instant::now();
            tracing::debug!(
                flush_kind = c4_attr_flush_kind,
                flushes_received_total = c4_attr_flushes_received,
                flushes_completed_total = c4_attr_flushes_completed,
                "C4_ATTR_EXECUTOR flush received"
            );
            let burst_fallback = matches!(flush, DebounceFlush::RescanRequired);
            let ignore_file_changed = flush_touches_ignore_file(&executor_canonical_root, &flush);
            if burst_fallback || ignore_file_changed {
                match EffectiveIgnoreSet::load_for_link_root(&executor_root) {
                    Ok(updated) => executor_ignore_set = Arc::new(updated),
                    Err(e) => tracing::warn!(
                        error = %e,
                        local_path = %executor_local_path,
                        "failed to reload ignore patterns; using the previous effective set"
                    ),
                }
            }
            let flush = if ignore_file_changed {
                tracing::info!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "ignore patterns changed; running a full reconciliation scan"
                );
                DebounceFlush::RescanRequired
            } else {
                flush
            };
            if burst_fallback {
                // Every fallback trigger is logged, not silent. A large but
                // fully-known event burst no longer reaches `RescanRequired`
                // at all (see `debounce.rs`'s own doc comment) -- reaching
                // this arm now means precision was genuinely lost (a real
                // watcher-channel overflow, or the executor backlog merge
                // already having absorbed one).
                tracing::warn!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "debounce reported a full reconciliation scan is required"
                );
            }
            // `process_flush` chunks every
            // touched file (or, for a `RescanRequired`, runs the same
            // full-scan chunking as above) directly on whatever worker
            // polls this future — same blocking-runtime hazard as the
            // initial scan. `process_flush` is `async` (it holds an async
            // per-path lock across the read-compare-write), so it can't be
            // moved into `spawn_blocking` as-is; `block_in_place` is
            // Tokio's documented bridge for exactly this "blocking work
            // interleaved with async code" case — it hands this worker's
            // other queued tasks off to another worker for the duration,
            // without requiring the future/closure to be `'static` (unlike
            // `spawn_blocking`, it can run in place, so no extra `Arc`
            // clones are needed here).
            // Every flush chunks/indexes
            // touched files (or runs a full reconciliation scan) — held
            // across the whole `block_in_place`/`block_on` call so an
            // update install never starts mid-flush.
            let _write_activity = executor_deps.begin_write_activity();
            // Freshly read for THIS flush, not reused from
            // `executor_emit_tombstones` (frozen once, at link-start,
            // before this link's startup scan even ran): the two-live-
            // roots recovery flag can be armed or cleared at any point
            // during an established link's live lifetime, and a value
            // captured before that would silently defeat this exact
            // protection the instant it goes stale in the dangerous
            // direction (armed after capture, cleared only at the next
            // daemon restart). `executor_emit_tombstones` itself is still
            // ANDed in as a lower bound -- this boot's startup materialization-
            // repair failure (if any) must keep suppressing this link's
            // tombstones for the rest of the boot, same as the startup
            // scan itself was gated. Computed unconditionally but only
            // actually consulted for `RescanRequired` -- see
            // `scan_existing_files_with_ignore_gated_for_established_link`'s
            // own doc comment for why a `Paths` flush never needs this.
            let live_emit_tombstones = executor_emit_tombstones
                && !executor_deps
                    .replica_coordinator
                    .link_repository()
                    .suppress_tombstones_for_group(&executor_group_id)
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            group_id = %executor_group_id,
                            error = %e,
                            "cannot tell whether this group's live rescan must be additive; \
                             suppressing its deletions for this pass"
                        );
                        true
                    });
            if burst_fallback {
                // A `RescanRequired` full-reconciliation scan already commits
                // its detected changes to the DAG in durable, bounded chunks
                // as it walks (`reconcile_disk_with_ignore`'s own chunk
                // loop) -- but until this fix, nothing surfaced that
                // progress to connected peers until the WHOLE scan returned.
                // For a real 15,000-file scan that withheld peer visibility
                // for the scan's entire length (measured: ~75s of zero
                // peer-visible progress, C4 15k live-burst investigation,
                // 2026-09-01) even though the source device's own index/DAG
                // kept advancing the whole time -- a head-of-line-blocking
                // bug, not a correctness one. Streaming each durably-
                // committed chunk to `announce_local_change` as it lands
                // fixes this without changing what gets committed, in what
                // order, or when: only when each already-durable chunk
                // becomes peer-visible.
                let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::unbounded_channel::<
                    Vec<yadorilink_replica_domain::file::FileRecord>,
                >();
                let announce_deps = executor_deps.clone();
                let announce_local_path = executor_local_path.clone();
                let announce_group_id = executor_group_id.clone();
                let announce_task = tokio::spawn(async move {
                    while let Some(records) = chunk_rx.recv().await {
                        announce_local_change(
                            &announce_deps,
                            &announce_local_path,
                            &announce_group_id,
                            records,
                        )
                        .await;
                    }
                });

                #[cfg(not(madsim))]
                let flush_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        executor_processor.process_flush_with_ignore_streaming(
                            &executor_group_id,
                            &executor_root,
                            flush,
                            executor_ignore_set.as_ref(),
                            live_emit_tombstones,
                            &mut |chunk_records| {
                                let _ = chunk_tx.send(chunk_records.to_vec());
                            },
                        ),
                    )
                });
                // See the non-streaming arm below for why madsim awaits
                // directly instead of using `block_in_place`.
                #[cfg(madsim)]
                let flush_result = executor_processor
                    .process_flush_with_ignore_streaming(
                        &executor_group_id,
                        &executor_root,
                        flush,
                        executor_ignore_set.as_ref(),
                        live_emit_tombstones,
                        &mut |chunk_records| {
                            let _ = chunk_tx.send(chunk_records.to_vec());
                        },
                    )
                    .await;
                // Closes the channel so `announce_task`'s `while let Some`
                // ends once every already-sent chunk is drained, then waits
                // for that draining to actually finish before this flush is
                // considered complete (so `flushes_completed_total`/the
                // completion log below stay accurate, and so a later flush's
                // own writes never race this one's still-in-flight
                // announcements).
                drop(chunk_tx);
                let _ = announce_task.await;

                c4_attr_flushes_completed += 1;
                tracing::debug!(
                    flush_kind = c4_attr_flush_kind,
                    flushes_received_total = c4_attr_flushes_received,
                    flushes_completed_total = c4_attr_flushes_completed,
                    elapsed_ms = c4_attr_start.elapsed().as_millis() as u64,
                    ok = flush_result.is_ok(),
                    records = flush_result.as_ref().map(|o| o.records.len()).unwrap_or(0),
                    "C4_ATTR_EXECUTOR flush completed"
                );
                // `outcome.records` is deliberately NOT passed to
                // `announce_local_change` again here -- every record it
                // contains was already announced, per chunk, as
                // `on_chunk_committed` fired above. Doing so again would
                // double-announce the whole scan.
                if let Err(e) = flush_result {
                    tracing::warn!(error = %e, local_path = %executor_local_path, "failed to process a local-change batch")
                }
            } else {
                #[cfg(not(madsim))]
                let flush_result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        executor_processor.process_flush_with_ignore(
                            &executor_group_id,
                            &executor_root,
                            flush,
                            executor_ignore_set.as_ref(),
                            live_emit_tombstones,
                        ),
                    )
                });
                // The deterministic simulator runs a single-threaded runtime:
                // `block_in_place` and a nested `Handle::block_on` both panic
                // there. `process_flush_with_ignore` is already `async`, so
                // awaiting it directly drives the exact same work to the exact
                // same result — the `block_in_place` wrapper above is only a
                // multi-thread runtime-hygiene optimization (offloading the
                // synchronous chunk/hash/write bursts onto a sibling worker),
                // which has no meaning under the single-threaded simulator.
                #[cfg(madsim)]
                let flush_result = executor_processor
                    .process_flush_with_ignore(
                        &executor_group_id,
                        &executor_root,
                        flush,
                        executor_ignore_set.as_ref(),
                        live_emit_tombstones,
                    )
                    .await;
                c4_attr_flushes_completed += 1;
                tracing::debug!(
                    flush_kind = c4_attr_flush_kind,
                    flushes_received_total = c4_attr_flushes_received,
                    flushes_completed_total = c4_attr_flushes_completed,
                    elapsed_ms = c4_attr_start.elapsed().as_millis() as u64,
                    ok = flush_result.is_ok(),
                    records = flush_result.as_ref().map(|o| o.records.len()).unwrap_or(0),
                    "C4_ATTR_EXECUTOR flush completed"
                );
                match flush_result {
                    Ok(outcome) => {
                        announce_local_change(
                            &executor_deps,
                            &executor_local_path,
                            &executor_group_id,
                            outcome.records,
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, local_path = %executor_local_path, "failed to process a local-change batch")
                    }
                }
            }
        }
    })
}

/// Live backstop for `redrive_dirty_journal` -- see
/// `DIRTY_JOURNAL_REDRIVE_INTERVAL`'s doc comment for why this exists as
/// its own periodic task rather than relying on the startup-only rescan in
/// `spawn_executor_task` or a coincidental re-touch of the same path. Takes
/// its own `Arc<LocalChangeProcessor>` clone (cheap -- it only holds `Arc`
/// references) rather than sharing the executor task's: `redrive_dirty_
/// journal` ultimately calls the same `process_flush` the live watcher loop
/// uses, and is written to be idempotent/safe to call concurrently with it
/// (a path already resolved by the live loop is simply cleared as a
/// no-op), so this task needs no coordination with the watcher loop.
pub(crate) fn spawn_dirty_journal_task(
    dirty_journal_processor: Arc<LocalChangeProcessor>,
    dirty_journal_deps: Arc<LinkRuntimeDependencies>,
    dirty_journal_root: PathBuf,
    dirty_journal_local_path: String,
    dirty_journal_group_id: String,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DIRTY_JOURNAL_REDRIVE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let _write_activity = dirty_journal_deps.begin_write_activity();
            let redrive_result = dirty_journal_processor
                .redrive_dirty_journal(&dirty_journal_group_id, &dirty_journal_root)
                .await;
            match redrive_result {
                Ok(outcome) => {
                    if !outcome.records.is_empty() {
                        announce_local_change(
                            &dirty_journal_deps,
                            &dirty_journal_local_path,
                            &dirty_journal_group_id,
                            outcome.records,
                        )
                        .await;
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    local_path = %dirty_journal_local_path,
                    group_id = %dirty_journal_group_id,
                    "periodic live dirty-journal redrive failed"
                ),
            }
        }
    })
}

/// Moved here from the daemon's own `LinkRuntimeController` alongside `spawn_executor_task` --
/// its only caller -- as part of the same relocation: byte-identical
/// logic, `pub(crate)` only because the daemon's own `LinkRuntimeController`'s own test module
/// still exercises the live-watch path this feeds into, not because
/// anything outside this module tree calls it directly.
pub(crate) fn flush_touches_ignore_file(root: &std::path::Path, flush: &DebounceFlush) -> bool {
    match flush {
        DebounceFlush::Paths(paths) => paths.iter().any(|(path, _, _)| {
            path.strip_prefix(root).ok().is_some_and(is_ignore_file_relative_path)
        }),
        DebounceFlush::RescanRequired => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_duplicate_recovery_gate, DuplicateRecoveryOutcome};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeError;

    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "fake error")
        }
    }

    // Ordinary startup: nothing pending. The expensive corroboration pass
    // must never run -- proven directly (not via timing) by panicking if
    // the closure is ever invoked, and `recheck_pending` must likewise
    // never be consulted since there was nothing to recheck.
    #[test]
    fn no_recovery_pending_skips_corroboration_and_completes_immediately() {
        let outcome = resolve_duplicate_recovery_gate::<FakeError>(
            "group",
            Ok(false),
            || panic!("corroborate_and_resolve must not run when nothing is pending"),
            || panic!("recheck_pending must not run when nothing was pending to begin with"),
        );
        assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
    }

    // Armed recovery, fully resolved this pass: corroboration runs exactly
    // once and, since the durable pending set is now empty, the gate
    // reports Complete so suppression may clear.
    #[test]
    fn pending_recovery_runs_corroboration_once_and_completes_when_pending_clears() {
        let mut corroborate_calls = 0;
        let outcome = resolve_duplicate_recovery_gate(
            "group",
            Ok::<bool, FakeError>(true),
            || corroborate_calls += 1,
            || Ok(false),
        );
        assert_eq!(corroborate_calls, 1);
        assert_eq!(outcome, DuplicateRecoveryOutcome::Complete);
    }

    // Armed recovery, still unresolved after this pass (some paths were
    // not corroborated): suppression must stay armed.
    #[test]
    fn pending_recovery_stays_pending_when_recheck_still_reports_pending() {
        let mut corroborate_calls = 0;
        let outcome = resolve_duplicate_recovery_gate(
            "group",
            Ok::<bool, FakeError>(true),
            || corroborate_calls += 1,
            || Ok(true),
        );
        assert_eq!(corroborate_calls, 1);
        assert_eq!(outcome, DuplicateRecoveryOutcome::StillPending);
    }

    // Corroboration ran, but the post-corroboration recheck itself could
    // not be read: fail closed exactly like the initial-read failure does,
    // not optimistically treated as resolved.
    #[test]
    fn unreadable_recheck_after_corroboration_fails_closed() {
        let mut corroborate_calls = 0;
        let outcome = resolve_duplicate_recovery_gate(
            "group",
            Ok::<bool, FakeError>(true),
            || corroborate_calls += 1,
            || Err(FakeError),
        );
        assert_eq!(corroborate_calls, 1, "corroboration must still run once pending was true");
        assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
    }

    // The durable pending state itself could not be read: fail closed.
    // Corroboration must not run against an unknown state, and
    // suppression must stay armed rather than being cleared optimistically.
    #[test]
    fn unreadable_pending_state_fails_closed_without_running_corroboration() {
        let outcome = resolve_duplicate_recovery_gate(
            "group",
            Err(FakeError),
            || panic!("corroborate_and_resolve must not run when pending state is unknown"),
            || -> Result<bool, FakeError> {
                panic!("recheck_pending must not run when the initial read already failed")
            },
        );
        assert_eq!(outcome, DuplicateRecoveryOutcome::UnknownFailClosed);
    }
}
