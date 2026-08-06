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
use yadorilink_root_authority::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_local_capture::LocalChangeProcessor;
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
                    let mut history_failure = None;
                    // A successful *additive* scan proves only that present
                    // disk entries were indexed. It deliberately leaves live
                    // rows originating at the departed duplicate root intact,
                    // so it does not prove disk/index convergence. Keep the
                    // deletion gate armed until every live indexed path is
                    // present; otherwise the next authoritative scan would
                    // tombstone precisely the rows recovery preserved.
                    if let Ok(rows) = executor_deps.replica_coordinator.file_index_repository().list_files(&executor_group_id) {
                        for row in rows.into_iter().filter(|row| !row.deleted) {
                            if matches!(
                                executor_deps.replica_coordinator.indexed_path_is_corroborated(
                                    executor_root.as_path(),
                                    &executor_group_id,
                                    &row,
                                ),
                                Ok(true)
                            ) {
                                if let Err(error) = executor_deps
                                    .replica_coordinator
                                    .link_repository().resolve_duplicate_recovery_path(&executor_group_id, &row.path)
                                {
                                    tracing::warn!(group_id = %executor_group_id, path = %row.path, error = %error, "could not persist duplicate-recovery path progress");
                                }
                            }
                        }
                    }
                    let recovery_complete = matches!(
                        executor_deps.replica_coordinator.link_repository().duplicate_recovery_pending(&executor_group_id),
                        Ok(false)
                    );
                    if recovery_complete {
                        if let Err(e) = executor_deps
                            .replica_coordinator
                            .link_repository().set_suppress_tombstones(&executor_local_path, false)
                        {
                            tracing::warn!(
                                local_path = %executor_local_path,
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
                    if !records.is_empty() {
                        // Re-establish DAG heads now that the batched scan's rows
                        // exist, so a peer negotiating change-history sync has heads
                        // to request. `ensure_initial_change_history` fails closed
                        // (a registered device with no signing key is a
                        // configuration error, not a legitimate no-emitter path --
                        // see its own doc comment), so any error here is surfaced
                        // rather than silently discarded, keeping a missing
                        // post-scan history bootstrap observable instead of failing
                        // invisibly.
                        if let Err(error) =
                            ensure_initial_change_history(&executor_deps, &executor_group_id)
                        {
                            tracing::error!(
                                local_path = %executor_local_path,
                                group_id = %executor_group_id,
                                error = %error,
                                "post-scan change-history bootstrap failed; group startup remains closed"
                            );
                            history_failure =
                                Some(format!("post-scan change-history bootstrap failed: {error}"));
                        }
                    }
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
        while let Some(flush) = flush_rx.recv().await {
            let burst_fallback = matches!(flush, DebounceFlush::BurstFallback);
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
                DebounceFlush::BurstFallback
            } else {
                flush
            };
            if burst_fallback {
                // Every fallback trigger is logged, not silent.
                tracing::warn!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "event burst exceeded the debounce threshold; falling back to a full reconciliation scan"
                );
            }
            // `process_flush` chunks every
            // touched file (or, for a `BurstFallback`, runs the same
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
            #[cfg(not(madsim))]
            let flush_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(
                    executor_processor.process_flush_with_ignore(
                        &executor_group_id,
                        &executor_root,
                        flush,
                        executor_ignore_set.as_ref(),
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
                )
                .await;
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
        DebounceFlush::BurstFallback => false,
    }
}
