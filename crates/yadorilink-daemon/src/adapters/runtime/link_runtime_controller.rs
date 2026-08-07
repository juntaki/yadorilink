//! Starts/stops the background tasks that watch one linked folder
//! (watcher, chunking-and-indexing, broadcast to connected peers, and
//! shell-extension status push). Two tasks per link: a debounce
//! **accumulator** that only ever reads raw filesystem
//! events and coalesces them into windowed batches
//! (`yadorilink_filesystem_sync::debounce`), and an **executor** that consumes
//! those batches and does the actual chunk/index/broadcast work — kept
//! separate so a slow executor flush never blocks the accumulator from
//! continuing to observe new events.
//!
//! `LinkRuntimeController` is the single entry point every daemon caller
//! now goes through for starting, stopping, resuming, and sweeping a
//! link's runtime -- replacing the free functions this daemon used to
//! expose from its own now-removed link-manager module. A pure
//! relocation: every method's logic below is byte-identical to its former
//! free-function body, only the receiver changed from an explicit `state`
//! parameter to `&self`.
//!
//! `new`/`start`/`start_with_source`/`stop`/`resume` are `pub`, not
//! `pub(crate)`, purely so this crate's own external integration-test
//! binaries under `tests/` -- which compile as separate crates and so
//! never see `#[cfg(test)]`/`pub(crate)` items regardless of how they're
//! built -- can still drive a link's lifecycle directly, the same
//! external-reachability reason `ControlContext::from_state` is `pub`.
//! `start_gating_tombstones`/`run_retention_expiry_sweep`/
//! `run_disk_reconcile_backstop_sweep` stay `pub(crate)`: no external test
//! calls them today.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::{FolderWatchSource, RealFolderWatchSource};
#[cfg(test)]
use yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet;

use crate::daemon_state::DaemonState;
use crate::error::DaemonError;
use crate::link_registry::LinkRegistry;
use crate::link_runtime::factory::LinkRuntimeFactory;
use crate::link_runtime::operations::capture_local_change::announce_local_change;
use crate::link_runtime::startup::GroupStartupReadyGuard;

/// How often each link's
/// background task re-runs `materialization::repair_interrupted_
/// materializations` during live operation, not just at daemon startup —
/// defense-in-depth against whatever bug might leave a `Hydrated` index
/// record disagreeing with what's actually on disk (the direct fixes are
/// in `try_apply_metadata_only_update` and this module's debounce-batch
/// executor; this is a coarse, low-frequency safety net on top of those,
/// not a substitute for them). Same order of magnitude as
/// `yadorilink_peer_session::peer_session::DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`
/// (90s) -- frequent enough to bound how long a divergence can persist,
/// infrequent enough that a full per-link disk scan is negligible
/// overhead against normal sync traffic.
const MATERIALIZATION_REPAIR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

pub struct LinkRuntimeController {
    state: Arc<DaemonState>,
}

impl LinkRuntimeController {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) fn is_ready(&self, local_path: &str) -> bool {
        self.state.links.runtime(local_path).is_some()
    }

    pub fn start(&self, local_path: String, group_id: String) -> Result<(), DaemonError> {
        self.start_inner(local_path, group_id, Arc::new(RealFolderWatchSource), true)
    }

    /// Same as `start`, but takes
    /// an explicit `FolderWatchSource` so a DST scenario can substitute a
    /// synthetic event source in place of the real OS filesystem watcher,
    /// while every other production code path below (debounce, indexing,
    /// broadcast, materialization) runs unchanged.
    pub fn start_with_source(
        &self,
        local_path: String,
        group_id: String,
        watcher_source: Arc<dyn FolderWatchSource>,
    ) -> Result<(), DaemonError> {
        self.start_inner(local_path, group_id, watcher_source, true)
    }

    /// Same as `start`, but lets the daemon's startup path suppress
    /// this link's initial-scan tombstone emission for this boot.
    ///
    /// Startup runs the interrupted-materialization repair pass for every link
    /// before restarting its watcher; that pass is what disambiguates a
    /// crash-mid-materialize (missing target, blocks present, an open
    /// materialization intent -> reconstruct) from an offline user delete (missing
    /// target, no intent -> tombstone). When repair ERRORED for this link's group,
    /// its disambiguation input is unavailable, so the initial reconcile scan must
    /// not classify a `Hydrated`-but-missing file as a deletion. Passing
    /// `emit_tombstones = false` then defers this scan's delete emission to a later
    /// boot on which repair succeeds — fail-closed. See
    /// `LocalChangeProcessor::scan_existing_files_with_ignore_gated`.
    pub(crate) fn start_gating_tombstones(
        &self,
        local_path: String,
        group_id: String,
        emit_tombstones: bool,
    ) -> Result<(), DaemonError> {
        self.start_inner(local_path, group_id, Arc::new(RealFolderWatchSource), emit_tombstones)
    }

    fn start_inner(
        &self,
        local_path: String,
        group_id: String,
        watcher_source: Arc<dyn FolderWatchSource>,
        emit_tombstones: bool,
    ) -> Result<(), DaemonError> {
        let state = &self.state;
        // Close this group's startup barrier and arm its fail-closed guard FIRST,
        // before any fallible step below. `app::run` calls this for every existing
        // link *before* it spawns the peer orchestrator, so a peer change arriving
        // later observes the barrier closed and waits (in its own apply path) until
        // the startup reconciliation has published its results, instead of racing
        // the scan's stale-snapshot batch commit. Per-group: this only gates this
        // group's peer apply, never an unrelated group's.
        //
        // The ordering is load-bearing, not stylistic. Every fallible step from
        // here on -- whether in this function or inside
        // `LinkRuntimeFactory::build`, below -- drops the guard and publishes
        // `Failed` for this generation. Returning early with NO gate registered
        // would instead leave the group *absent* from the registry, and an
        // absent gate reads as Ready (`wait_group_ready`) — so a failed watcher
        // bind (OS watch limit, unmounted root, permissions) would admit peer
        // changes into a folder this boot never scanned and let them overwrite
        // un-indexed local content. Do not add a fallible step above this pair.
        // Infallible (plain `Arc` clones), so deriving it up here -- before
        // the guard-arming pair below -- does not violate that pair's own
        // "no fallible work above it" rule. Every remaining step that touches
        // the per-link runtime module tree
        // (`link_runtime.rs`/`link_runtime/operations/*.rs`) threads this
        // narrow bundle instead of `state` from here on -- see
        // `LinkRuntimeDependencies`'s own doc for why.
        let deps = state.link_runtime_dependencies();

        let startup_generation =
            state.replica_coordinator.startup_readiness().begin_group_startup(&group_id);
        let startup_ready_guard =
            GroupStartupReadyGuard::new(deps.clone(), group_id.clone(), startup_generation);

        // Below the guard-arming pair above, per that block's own rule -- and
        // itself as early as every remaining fallible step below allows: see
        // `LinkSlotStartingGuard`'s own doc for the start-vs-stop zombie-
        // runtime race a `Starting` placeholder published this early closes.
        let link_slot_guard = LinkRegistry::reserve_starting(&state.links, local_path.clone())?;

        // Periodic live repair pass — see MATERIALIZATION_REPAIR_INTERVAL's doc
        // comment. Spawned here, in `LinkRuntimeController`, rather than inside
        // `LinkRuntimeFactory::build`: this is the one per-link background task
        // that needs a full `Arc<DaemonState>` (`DaemonState::root_lease_for`,
        // which resolves through `LinkRegistry` — something the `link_runtime`
        // module tree's own narrow `LinkRuntimeDependencies` bundle deliberately
        // excludes), and keeping that module tree free of `DaemonState` is what
        // keeps it out of the `daemon_state`/`link_registry` dependency cycle
        // (see this crate's own architecture-boundary checks). Its own
        // logic/closure body is unchanged from before this task-set's
        // construction moved into `LinkRuntimeFactory::build`; only its call
        // site did. First tick is after one full interval
        // (`tokio::time::interval`'s default), not immediately, since this same
        // function's own startup repair pass (inside `LinkRuntimeFactory::build`,
        // right after acquiring this link's `SyncRootLock`) already just ran
        // once for this link before its watcher started.
        let repair_state = state.clone();
        let repair_root = PathBuf::from(&local_path);
        let repair_group_id = group_id.clone();
        let repair_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MATERIALIZATION_REPAIR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let replica_coordinator = repair_state.replica_coordinator.clone();
                let block_store = repair_state.block_store.clone();
                let root = repair_root.clone();
                let group_id = repair_group_id.clone();
                let root_lease = match repair_state.root_lease_for(&group_id) {
                    Ok(lease) => lease,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            local_path = %repair_root.display(),
                            "periodic live materialization repair: no live root lease for this link"
                        );
                        continue;
                    }
                };
                // Same spawn_blocking rationale as the initial scan in the
                // executor task: this walks the whole linked folder
                // synchronously. And the same deterministic-simulator exception
                // — no blocking-thread pool there, so the identical walk runs
                // inline, wrapped in `Ok` to preserve the `Result<_, JoinError>`
                // shape the match expects. `root_op` is admitted INSIDE the
                // closure and held for the whole repair call, including the
                // disk walk/reconstruct work that precedes its own DB commits,
                // not just their `verify`.
                #[cfg(not(madsim))]
                let repair_result = tokio::task::spawn_blocking(move || {
                    crate::link_runtime::operations::repair_materialization::repair_interrupted_materializations(
                        &replica_coordinator,
                        &block_store,
                        &root_lease,
                        &root,
                        &group_id,
                    )
                })
                .await;
                #[cfg(madsim)]
                let repair_result =
                    crate::link_runtime::operations::repair_materialization::repair_interrupted_materializations(
                        &replica_coordinator,
                        &block_store,
                        &root_lease,
                        &root,
                        &group_id,
                    );
                #[cfg(madsim)]
                let repair_result = Ok::<_, tokio::task::JoinError>(repair_result);
                match repair_result {
                    Ok(Ok(report)) if report.is_empty() => {}
                    Ok(Ok(report)) => tracing::info!(
                        local_path = %repair_root.display(),
                        reconstructed = report.reconstructed.len(),
                        demoted_to_placeholder = report.demoted_to_placeholder.len(),
                        "periodic live repair found and fixed a materialization/disk divergence"
                    ),
                    Ok(Err(e)) => tracing::warn!(
                        error = %e,
                        local_path = %repair_root.display(),
                        "periodic live materialization repair failed for linked folder"
                    ),
                    Err(join_err) => tracing::warn!(
                        error = %join_err,
                        local_path = %repair_root.display(),
                        "periodic live materialization repair task panicked"
                    ),
                }
            }
        });

        // Every remaining fallible step -- the per-group/per-link pre-checks,
        // acquiring the `SyncRootLock`/building the `RootLease`, startup
        // materialization/restore repair, binding the watcher, spawning the
        // accumulator/executor/dirty-journal background tasks, and constructing
        // the `LinkFlushHandle` -- lives in `LinkRuntimeFactory::build` now.
        // This function's own remaining job is just: derive `deps`, arm the two
        // guards above, spawn `repair_handle` (above), delegate to the factory,
        // and publish the result -- see `LinkRuntimeFactory`'s own doc for the
        // exact scope split.
        //
        // `repair_handle` is already running by this point (spawned above, so
        // it's covered by the same `Starting` slot every other in-flight setup
        // step is), unlike in the pre-factory version of this function, where
        // its spawn was the second-to-last statement -- reachable only once
        // every fallible step already succeeded. `build`'s own `?` can still
        // fail after that, so its `AbortHandle` is grabbed first and explicitly
        // aborted on that path: a dropped (not aborted) `JoinHandle` would
        // otherwise leave this infinite-loop task running forever, orphaned,
        // logging "no live root lease for this link" on every tick.
        let repair_abort_handle = repair_handle.abort_handle();
        let runtime = match LinkRuntimeFactory::new(deps).build(
            local_path.clone(),
            group_id.clone(),
            watcher_source,
            emit_tombstones,
            startup_ready_guard,
            repair_handle,
        ) {
            Ok(runtime) => runtime,
            Err(e) => {
                repair_abort_handle.abort();
                return Err(e);
            }
        };

        // Published as a single atomic slot transition (`Starting` -> `Ready`)
        // only now that every fallible step above has succeeded -- see
        // `LinkRuntime`'s own doc for why this used to be (and no longer is)
        // three separate map inserts, and `LinkSlotStartingGuard`'s own doc
        // for why the slot was reserved as `Starting` back at this function's
        // very start rather than appearing from nothing right here.
        link_slot_guard.publish(Arc::new(runtime));
        Ok(())
    }

    /// `async`, and genuinely waits for every task to actually stop, rather than
    /// just requesting cancellation and returning immediately -- the difference
    /// matters because the root lock is released at the end of this function,
    /// and a lock released while a task is still running is not actually
    /// exclusive to anyone. `abort()` alone does not make that safe: the
    /// executor task's initial scan runs inside `tokio::task::spawn_blocking`
    /// (see `start`'s own comment on why), and a blocking closure
    /// already running on Tokio's blocking thread pool cannot be interrupted
    /// mid-execution by `abort()` -- it keeps running to completion regardless,
    /// still reading/chunking files and committing index/DAG writes against
    /// this root. Without awaiting the handle afterward, `stop`
    /// used to return (and the caller could immediately re-link/hand the root
    /// to another process) while that scan was still physically running,
    /// letting the still-running old scan's batch commits land against a root
    /// a new owner had already started operating on. Awaiting each handle
    /// after `abort()` blocks until the task actually observes the
    /// cancellation at its own next await point -- for the executor task, that
    /// is precisely the `spawn_blocking` scan's own `.await`, so this
    /// necessarily waits for the scan closure to finish running, not merely
    /// for cancellation to be requested.
    ///
    /// Awaiting `tasks` alone is not sufficient, though (K15): a peer session's
    /// targeted flush (`LinkFlushHandle::flush_pending_local_change` and
    /// friends) and the disk-reconcile backstop sweep
    /// (`run_disk_reconcile_backstop_sweep`) both hold their own `Arc` clone of
    /// the flush handle, reachable independent of `link_runtimes`, and can be
    /// mid-commit when this function's map removal runs. `flush_handle.fence`
    /// (a `LinkOpFence`) closes that: `begin_stopping` is called BEFORE the
    /// task-abort loop below (so no new one of those operations is admitted
    /// from this point on), and `wait_drained` is called AFTER it (so any
    /// operation already admitted -- necessarily started before `begin_
    /// stopping`, since admission and the stopping flag are checked under the
    /// same atomic re-check in `LinkOpFence::try_begin` -- has genuinely
    /// finished) before `root_lock` is allowed to drop.
    pub async fn stop(&self, local_path: &str) {
        let state = &self.state;
        // Serializes concurrent `stop` calls for the SAME
        // `local_path` (the control socket spawns one task per connection, so
        // two overlapping `Unlink`s are a real shape, not hypothetical) -- see
        // `DaemonState::link_watch_stop_locks`'s own doc for the race this
        // closes: without it, a second concurrent call can find `link_runtimes`
        // already emptied by the first and skip waiting entirely, racing ahead
        // to drop the root lock while the first call's awaited scan is still
        // genuinely running. Held for this whole function, including every
        // await below.
        let per_link_lock = state.links.stop_lock(local_path);
        let _stop_guard = per_link_lock.lock().await;

        // Waits out a `LinkSlot::Starting` entry rather than treating it as
        // absent -- see `LinkSlotStartingGuard`'s own doc for the zombie-
        // runtime race this closes. `notified.as_mut().enable()` before the
        // re-check is technically redundant here (`link_lifecycle_notify` is
        // woken via `notify_waiters`, which tokio's own docs guarantee a
        // `Notified` future observes as soon as it is constructed, not only
        // once polled/enabled -- see `LinkOpFence::wait_drained`'s identical,
        // corrected comment) but costs nothing and is kept for the same
        // future-proofing reason.
        //
        // A `Starting` entry is only ever PEEKED here, never removed: this
        // call does not own resolving it (the in-progress `start_inner`
        // call, via `LinkSlotStartingGuard`, does), and removing then
        // re-inserting it would open its own gap -- a concurrent `reserve`
        // for the same path could observe the map momentarily empty and
        // wrongly succeed, producing two live `Starting` reservations for one
        // path. Once this loop observes `Ready`, nothing else can change that
        // entry out from under it before the actual removal just below: `per_
        // link_lock` already serializes this against every other
        // `stop` call for this path, and `LinkSlotStartingGuard::
        // reserve` refuses to touch a path that already has ANY entry
        // (`Starting` or `Ready`), so no concurrent start can clobber a
        // `Ready` entry either.
        // The wait loop and the resolving removal both now live in
        // `LinkRegistry::wait_and_take_ready` itself -- see that method's own
        // doc for the exact same reasoning (a `Starting` entry is only ever
        // peeked, never removed and re-inserted, until it resolves) that used
        // to live here.
        let Some(runtime) = state.links.wait_and_take_ready(local_path).await else { return };
        // `link_runtimes` was the only place this `Arc` was ever cloned from,
        // so removing it there leaves exactly one strong reference: this one.
        // Unwrapping it gives owned access to `tasks` (needed to await each
        // handle by value below) while keeping `root_lock` alive, still held,
        // until this whole function returns.
        let runtime = Arc::try_unwrap(runtime).unwrap_or_else(|shared| {
            panic!(
                "stop: Arc<LinkRuntime> for {local_path} unexpectedly still shared \
                 ({} refs) after removal from link_runtimes",
                Arc::strong_count(&shared)
            )
        });

        // begin_stopping -> abort+await tasks -> wait_drained -> drop root_lock,
        // in that order -- see `LinkRuntime::shutdown`'s own doc for why.
        runtime.shutdown().await;
    }

    /// Resumes a paused link and re-broadcasts its currently-indexed files to
    /// connected peers. Unpausing alone only lifts the gate on *future*
    /// propagation — any change indexed *while* paused was queued locally
    /// (guarantee: `SyncState` itself is the backlog) but never
    /// actually sent, since `announce_local_change` only ever checks the
    /// pause flag once, at the moment each change is first processed. Resume
    /// must therefore flush that backlog itself, not just flip the flag.
    /// Peers that are already fully caught up simply see `ChangeOrdering::Equal`
    /// for everything and no-op — re-sending the whole current index is
    /// simple and correct, just not the cheapest possible resume.
    pub async fn resume(&self, local_path: &str) -> Result<(), crate::sync_error::SyncError> {
        let state = &self.state;
        let link = state
            .replica_coordinator
            .link_repository()
            .list_links()?
            .into_iter()
            .find(|l| l.local_path == local_path)
            .ok_or_else(|| crate::sync_error::SyncError::NotFound(format!("link {local_path}")))?;
        if link.orphaned {
            return Err(crate::sync_error::SyncError::InvalidInput(format!(
                "cannot resume orphaned link {local_path}: its coordination-side authorization is gone"
            )));
        }
        state.replica_coordinator.link_repository().ensure_unambiguous_group(&link.group_id)?;
        state.replica_coordinator.link_repository().set_paused(local_path, false)?;
        let group_id = link.group_id;
        match state.replica_coordinator.link_repository().link_gate_for_group(&group_id)? {
            yadorilink_replica_domain::session_state::LinkGate::Live {
                local_path: live_path,
                ..
            } if live_path == local_path => {}
            _ => {
                return Err(crate::sync_error::SyncError::InvalidInput(format!(
                    "cannot resume {local_path}: it is not the group's single live link"
                )))
            }
        }
        // Closes the gap this
        // fn's own doc comment doesn't cover -- a change still sitting
        // undispatched in the debounce accumulator (not yet even in
        // `SyncState`) at the moment of resume isn't part of the backlog
        // `list_files` below can see at all. Force it into the index first,
        // so the snapshot broadcast a few lines down reflects this link's true
        // current state rather than racing whatever quiet-period window that
        // change's own debounce window happened to still be in.
        if let Some(runtime) = state.links.runtime(local_path) {
            runtime.flush_pending_local_changes(&group_id).await;
        }
        let records = state.replica_coordinator.file_index_repository().list_files(&group_id)?;
        state.broadcast_change(&group_id, records).await;
        Ok(())
    }

    /// Runs `SyncState::expire_superseded_
    /// and_trashed_versions` for every currently-registered link, applying the
    /// fixed built-in retention policy — a version exceeding both the built-in
    /// version-count and age bounds is swept. Bounded and synchronous (SQLite
    /// calls only, no network I/O), matching this module's other maintenance
    /// sweeps (e.g. `DaemonState`'s pending-broadcast-retry loop) which also run
    /// plain `SyncState` calls directly on the async runtime rather than via
    /// `spawn_blocking` — a link's superseded/trashed backlog is bounded by
    /// the built-in retention policy, so this is not expected to be a large or
    /// slow scan. Logs (rather than propagating) a per-link failure so one link's
    /// error never stops the sweep from covering the rest — matching
    /// `resume`'s and `announce_local_change`'s existing "log and
    /// continue" error-handling shape for background maintenance work.
    /// Re-checks free space for every currently-Degraded link whose
    /// backoff window has elapsed. Thin delegate to
    /// `DaemonState::recheck_degraded_links`, which already narrows to
    /// `links`/`governance_config` internally -- this method exists only
    /// so `DegradedLinkRecheckJob` can hold the same `Arc<LinkRuntimeController>`
    /// its sibling maintenance jobs use instead of a full `Arc<DaemonState>`.
    pub(crate) fn recheck_degraded_links(&self) {
        self.state.recheck_degraded_links();
    }

    pub(crate) fn run_retention_expiry_sweep(&self) {
        let state = &self.state;
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(error = %e, "retention-expiry sweep: failed to list links");
                return;
            }
        };
        let now_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        for link in links {
            match state
                .replica_coordinator
                .expire_superseded_and_trashed_versions(&link.group_id, now_unix_nanos)
            {
                Ok(expired_count) if expired_count > 0 => {
                    tracing::debug!(
                        group_id = %link.group_id,
                        local_path = %link.local_path,
                        expired_count,
                        "retention-expiry sweep removed aged-out superseded/trashed versions"
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        group_id = %link.group_id,
                        local_path = %link.local_path,
                        "retention-expiry sweep failed for this link"
                    );
                }
            }
        }
    }

    /// A periodic, filesystem-watcher-event-
    /// *independent* disk-authoritative reconcile — the eventual-consistency
    /// backstop for a local write whose OS watcher event never arrives at all
    /// (e.g. an FSEvents blind window opened by `watch` tearing down and
    /// recreating its entire event stream — see `watcher.rs`'s module doc;
    /// this was the confirmed root cause of a `taguchi_v3` row 8
    /// non-convergence). No
    /// watcher-triggered recovery (the registrar's own `reconcile_new_
    /// directory_subtree` safety net) can reach a loss like this one, since
    /// that safety net only ever walks a *newly-registered* directory — it
    /// never revisits the *already*-watched link root, or a directory whose
    /// own creation event was itself lost.
    ///
    /// Deliberately **add-only** (`LocalChangeProcessor::reconcile_added_
    /// files`): indexes a disk file with no existing index row, and nothing
    /// else — never re-versions an already-indexed file whose on-disk content
    /// changed, never tombstones an indexed file missing from disk. Those two
    /// operations mutate an already-known path and are the ones `watcher.rs`'s
    /// module doc documents as unsafe to run this often (they can re-derive or
    /// false-delete a file mid-conflict-resolution between two devices —
    /// reproduced deterministically against the registration-mutex-contention
    /// race that made this fallback necessary). A file with no index row has never
    /// been broadcast or adopted by a peer, so indexing it carries none of
    /// that hazard — it's byte-for-byte what a live create event would have
    /// done.
    ///
    /// Skips paused links entirely: a paused link intentionally
    /// does not propagate, and indexing+broadcasting from this sweep would
    /// violate that the same way a live local change would. A link paused
    /// during a watcher-event loss is still covered once it resumes:
    /// `resume`'s own broadcast re-emits `list_files`, and the next
    /// sweep tick after resume runs normally for it.
    ///
    /// Also skips an orphaned link — its coordination-side authorization is
    /// permanently gone, so there is nothing left to sync it against. In
    /// practice this link never has a `LinkFlushHandle` to begin with (its
    /// watcher is stopped the moment `EnrollmentRecoveryService::reconcile_once` marks it
    /// orphaned, and never restarted), so the check below is defense in depth,
    /// not the primary mechanism.
    ///
    /// Skips a link with no `LinkFlushHandle` yet registered (the brief window
    /// between `add_link` and `start` completing) rather than
    /// erroring — the next tick covers it once registration finishes.
    pub(crate) async fn run_disk_reconcile_backstop_sweep(&self) {
        let state = &self.state;
        // Infallible, same as `start_inner`'s own derivation --
        // everything below that touches the per-link runtime module tree goes
        // through this narrow bundle instead of `state` from here on.
        let deps = state.link_runtime_dependencies();
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(error = %e, "disk-reconcile-backstop: failed to list links");
                return;
            }
        };
        for link in links {
            if link.paused || link.orphaned {
                continue;
            }
            let Some(runtime) = state.links.runtime(&link.local_path) else { continue };
            // Held for this whole sweep pass so `stop`'s
            // `wait_drained` genuinely waits for it -- see `RootLease`'s own
            // doc; this is the second of the two call sites (`LinkFlushHandle`'s
            // own methods are the other) that used to let a write land after
            // the root lock had already been handed to a new owner (K15).
            // `reconcile_added_files_from_disk` itself refuses admission (and
            // returns `None`) once `stop` has called
            // `begin_stopping` for this link.
            let _write_activity = deps.begin_write_activity();
            let Some(result) = runtime.reconcile_added_files_from_disk(&link.group_id) else {
                continue;
            };
            match result {
                Ok(records) if !records.is_empty() => {
                    tracing::info!(
                        group_id = %link.group_id,
                        local_path = %link.local_path,
                        count = records.len(),
                        "disk-reconcile-backstop recovered file(s) never delivered by the local \
                         filesystem watcher"
                    );
                    announce_local_change(&deps, &link.local_path, &link.group_id, records).await;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        group_id = %link.group_id,
                        local_path = %link.local_path,
                        "disk-reconcile-backstop failed for this link"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        // A registered device with no signing key fails closed (see
        // `ensure_initial_change_history`'s doc comment) -- every test using
        // this shared harness needs one wired, matching `change_auth.rs`'s
        // and `rebootstrap_handler.rs`'s own `test_state()` helpers.
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        state
    }

    fn sample_record(path: &str) -> yadorilink_replica_domain::file::FileRecord {
        yadorilink_replica_domain::file::FileRecord {
            path: path.to_string(),
            size: 10,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        }
    }

    /// Like `sample_record`, but with a size and single block hash that
    /// actually corroborate `content` on disk — `sample_record`'s placeholder
    /// size/empty blocks never match real bytes, so a test relying on
    /// `VerifiedRoot`/root-identity adoption corroborating a real file (not
    /// just referencing its path) needs this instead.
    fn record_matching_disk_content(
        path: &str,
        content: &[u8],
    ) -> yadorilink_replica_domain::file::FileRecord {
        use sha2::{Digest, Sha256};
        yadorilink_replica_domain::file::FileRecord {
            path: path.to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                hash: Sha256::digest(content).to_vec(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        }
    }

    /// A `FolderWatchSource` whose `watch` always fails — models the OS-level
    /// reasons a watcher bind can fail on a perfectly healthy database: the
    /// per-user watch limit exhausted on a large tree, an unmounted root, or a
    /// permissions error.
    struct FailingWatchSource;

    impl FolderWatchSource for FailingWatchSource {
        fn watch(
            &self,
            _root: &Path,
            _ignore_set: Arc<EffectiveIgnoreSet>,
        ) -> Result<
            yadorilink_filesystem_sync::watcher::FolderWatcher,
            yadorilink_filesystem_sync::watcher::WatcherError,
        > {
            Err(yadorilink_filesystem_sync::watcher::WatcherError::Io(std::io::Error::other(
                "watch limit reached",
            )))
        }
    }

    /// When watcher setup fails, the group's gate must exist and be `Failed` —
    /// NOT absent. An absent gate reads as Ready (`wait_group_ready` admits a
    /// group that never entered startup), so a link whose watcher never bound
    /// would admit peer changes into a folder this boot never scanned, letting
    /// them overwrite un-indexed local content. The failure is silent at the
    /// call site (`app::run` logs and continues), so the gate is the only thing
    /// standing between a failed watcher and that overwrite.
    #[tokio::test]
    async fn failed_watcher_setup_must_fail_the_gate_not_leave_it_absent() {
        let state = test_state();
        let root = tempfile::tempdir().unwrap();
        let controller = LinkRuntimeController::new(state.clone());

        let result = controller.start_with_source(
            root.path().to_string_lossy().into_owned(),
            "g".to_string(),
            Arc::new(FailingWatchSource),
        );
        assert!(result.is_err(), "a failing watch source must surface an error to the caller");

        // The decisive assertion: fail-closed, not fail-open. Before the guard
        // was armed ahead of the fallible setup, `begin_group_startup` was never
        // reached on this path and this returned Ok(()) — the bug.
        let ready = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state.replica_coordinator.wait_group_ready("g"),
        )
        .await
        .expect("wait_group_ready must resolve, not park forever on a Starting gate");
        assert!(
            ready.is_err(),
            "a link whose watcher failed to bind must DEFER peer apply (Err(StartupFailed)), \
             never admit it as ready"
        );
    }

    /// A link whose row is already `OnDemand` (e.g. from before the
    /// placeholder-pipeline gate existed, or committed by any other path)
    /// must refuse to start watching -- the same invariant `finish_link_
    /// setup`/`set_storage_mode` enforce at *creation* time, applied here to
    /// a row that's already on disk, since neither entry point's refusal
    /// helps a row that's already committed OnDemand.
    #[tokio::test]
    async fn an_existing_on_demand_link_refuses_to_start_while_the_pipeline_is_not_connected() {
        let state = test_state();
        let root = tempfile::tempdir().unwrap();
        let local_path = root.path().to_string_lossy().into_owned();
        state.replica_coordinator.link_repository().add_link(&local_path, "g").unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_materialization_policy(
                &local_path,
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();

        let controller = LinkRuntimeController::new(state.clone());
        let result = controller.start_with_source(
            local_path.clone(),
            "g".to_string(),
            Arc::new(RealFolderWatchSource),
        );

        assert!(
            result.is_err(),
            "an existing OnDemand link must refuse to start while no placeholder pipeline is \
             connected, not silently watch/materialize anyway"
        );
        assert!(
            !state.links.has_entry(&local_path),
            "a refused start must not leave a zombie Starting/Ready slot behind"
        );
    }

    #[tokio::test]
    async fn resume_refuses_an_orphaned_link() {
        let state = test_state();
        let local_path = "/tmp/photos";
        state.replica_coordinator.link_repository().add_link(local_path, "group-1").unwrap();
        state.replica_coordinator.link_repository().mark_link_orphaned(local_path).unwrap();

        let controller = LinkRuntimeController::new(state.clone());
        let err = controller
            .resume(local_path)
            .await
            .expect_err("an orphaned link must never be re-enabled by Resume");
        assert!(err.to_string().contains("orphaned"), "got {err}");
    }

    /// The retention-expiry sweep actually removes aged-out superseded
    /// versions under the fixed built-in retention policy — a real, if
    /// minimal, end-to-end proof that `DaemonState::new`'s periodic call
    /// reaches `SyncState::expire_superseded_and_trashed_versions` correctly.
    #[tokio::test]
    async fn run_retention_expiry_sweep_removes_aged_out_versions_under_the_fixed_policy() {
        let state = test_state();
        state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

        // Thirteen versions: twelve become superseded, one is current.
        // `sample_record`'s `mtime_unix_nanos: 0` (1970) is far older than
        // the built-in 30-day age bound, so every superseded row is beyond
        // the age axis; the built-in 10-version count bound then keeps only
        // the ten most recent superseded rows, expiring the two oldest.
        for size in 1..=13u64 {
            let mut record = sample_record("a.jpg");
            record.size = size;
            state
                .replica_coordinator
                .file_index_repository()
                .upsert_file_with_origin("group-1", &record, "device-a", &permit)
                .unwrap();
        }

        assert_eq!(
            state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap().len(),
            13
        );

        let controller = LinkRuntimeController::new(state.clone());
        controller.run_retention_expiry_sweep();

        let remaining =
            state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap();
        assert_eq!(
            remaining.len(),
            11,
            "current version plus the ten most recent superseded ones survive"
        );
    }

    /// A link with no superseded/trashed rows to sweep, or no links at
    /// all, is a harmless no-op — the sweep must never error out or panic
    /// on an empty/idle daemon.
    #[tokio::test]
    async fn run_retention_expiry_sweep_is_a_harmless_no_op_with_nothing_to_expire() {
        let state = test_state();
        let controller = LinkRuntimeController::new(state.clone());
        controller.run_retention_expiry_sweep(); // no links registered at all
        state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file("group-1", &sample_record("a.jpg"), &permit)
            .unwrap();
        controller.run_retention_expiry_sweep(); // one link, only a current version
        assert_eq!(
            state.replica_coordinator.sqlite().dag_list_versions("group-1", "a.jpg").unwrap().len(),
            1
        );
    }

    // --- The two-live-roots recovery, at the daemon seam ---------------------

    /// Starts a watch the way production does and waits for its initial scan to
    /// finish, so the assertion is about what the REAL startup path did rather
    /// than about a hand-simulated primitive.
    async fn start_watch_and_await_scan(state: &Arc<DaemonState>, root: &Path, group: &str) {
        let controller = LinkRuntimeController::new(state.clone());
        controller
            .start_with_source(
                root.to_string_lossy().into_owned(),
                group.to_string(),
                Arc::new(RealFolderWatchSource),
            )
            .expect("the watch must start");
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state.replica_coordinator.wait_group_ready(group),
        )
        .await
        .expect("the initial scan must finish")
        .expect("the initial scan must succeed");
    }

    /// THE C15 SEAM, driven through the real watch-start path.
    ///
    /// After a recovery out of the two-live-roots state, the departed root's
    /// rows are still in the group's index (`DELETE FROM files` is keyed by
    /// path). The survivor's initial scan is root-scoped and authoritative, so
    /// unless the additive-scan flag is honoured it reads every one of those
    /// paths as deleted and tombstones them to every device -- the remedy
    /// deleting the files it was meant to save.
    ///
    /// Deliberately NOT hand-simulated: an earlier test called
    /// `suppress_tombstones_for_group` and `scan_existing_files_with_ignore_gated`
    /// itself, which meant the ENTIRE daemon wiring could be deleted with
    /// "292 passed; 0 failed" -- it exercised the primitives and never the seam
    /// that consults them. This one deletes nothing by hand: it starts a watch
    /// exactly as `app::run` and the `link` handler do, and only the production
    /// read of the flag stands between it and a tombstone.
    #[tokio::test]
    async fn the_survivors_first_scan_after_a_recovery_emits_no_tombstones() {
        let state = test_state();
        let root = tempfile::tempdir().unwrap();
        let group = "group-1";
        std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();

        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.path().to_string_lossy(), group)
            .unwrap();
        // Unlike the other tests sharing `test_state()`, this one pre-seeds
        // the index with rows (below) before the watch starts, so
        // `ensure_initial_change_history` has real DAG history to establish
        // and genuinely calls into local-emission authorization -- which
        // `DaemonState::new`'s real provider withholds for a linked group
        // with no verified policy loaded (exactly the fail-closed behavior
        // this branch just restored). This test is about tombstone-
        // suppression/duplicate-recovery scan behavior, not policy
        // resolution, so bypass it the same way `index.rs`'s own tests do.
        // Local edits route through `replica_coordinator` exclusively
        // (7D-10.9 removed `DaemonState.replica_coordinator`) -- `DaemonState::new`'s
        // real provider would otherwise withhold exactly as the comment
        // above describes.
        state.replica_coordinator.set_local_change_auth_provider(std::sync::Arc::new(
            |_group_id| Ok(yadorilink_replica_domain::change::ChangeAuth::PLACEHOLDER),
        ));
        // The survivor's own file, indexed and present: that is what corroborates
        // the root, so the root-identity check adopts rather than refusing it as
        // a possible bare mountpoint. Without it this test would never reach the
        // tombstone decision it is about. Must actually match the bytes just
        // written above — `sample_record`'s placeholder size/blocks would not
        // corroborate and `VerifiedRoot::open` below would refuse.
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(group, &record_matching_disk_content("in-a.txt", b"aaa"), &permit)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            group,
            state.replica_coordinator.as_ref(),
        )
        .unwrap();
        // A path that only ever existed under the folder the user just unlinked,
        // still indexed for the group -- the shape a second root leaves behind.
        // `ensure_initial_change_history` now genuinely emits DAG history for
        // pre-existing index rows (fail-closed restored), which needs a real,
        // hash-consistent `FileVersion` -- `sample_record`'s placeholder
        // size/empty blocks would fail that, so use `record_matching_disk_content`
        // instead even though this content is never written to this test's disk
        // (the whole point: it only ever existed on the departed root).
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(group, &record_matching_disk_content("only-in-b.txt", b"bbb"), &permit)
            .unwrap();

        // Exactly what the unlink handler's recovery arms on the survivor:
        // both the additive-scan flag AND the durable set of paths that must
        // reappear before `duplicate_recovery_pending` will call it resolved
        // (see `control_socket::unlink`'s own pairing of these two calls).
        state.replica_coordinator.link_repository().arm_duplicate_recovery_paths(group).unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_suppress_tombstones(&root.path().to_string_lossy(), true)
            .unwrap();

        start_watch_and_await_scan(&state, root.path(), group).await;

        let departed = state
            .replica_coordinator
            .file_index_repository()
            .get_file(group, "only-in-b.txt")
            .unwrap()
            .unwrap();
        assert!(
            !departed.deleted,
            "the survivor's first scan after a two-live-roots recovery must delete nothing -- \
             this path can still hydrate from a peer that holds it"
        );
        assert!(
            state
                .replica_coordinator
                .link_repository()
                .suppress_tombstones_for_group(group)
                .unwrap(),
            "the gate must remain armed while a live indexed row is still absent from disk"
        );
    }

    /// Once disk covers the entire live index, ordinary delete propagation can
    /// resume. A successful scan alone is insufficient; this converged case
    /// pins the stronger clear condition.
    #[tokio::test]
    async fn a_clean_scan_closes_the_additive_window() {
        let state = test_state();
        let root = tempfile::tempdir().unwrap();
        let group = "group-1";
        std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();

        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.path().to_string_lossy(), group)
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .set_suppress_tombstones(&root.path().to_string_lossy(), true)
            .unwrap();

        start_watch_and_await_scan(&state, root.path(), group).await;

        assert!(
            !state
                .replica_coordinator
                .link_repository()
                .suppress_tombstones_for_group(group)
                .unwrap(),
            "one clean full scan must close the additive window, or ordinary delete propagation \
             is broken for this link forever"
        );
    }

    /// Sync-root single-instance ownership (design doc §15), driven through
    /// the real watch-start/stop path rather than calling
    /// `SyncRootLock::acquire` directly: while the watch is running, another
    /// attempt to acquire the same root's lock must be refused (a second
    /// daemon process pointed at this folder), and once the watch is
    /// stopped, that lock must be releasable again (this device re-linking
    /// the same folder, or another process taking it over).
    #[tokio::test]
    async fn starting_a_watch_holds_the_sync_root_lock_until_stopped() {
        let state = test_state();
        let root = tempfile::tempdir().unwrap();
        let group = "group-1";
        std::fs::write(root.path().join("in-a.txt"), b"aaa").unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.path().to_string_lossy(), group)
            .unwrap();

        start_watch_and_await_scan(&state, root.path(), group).await;

        let err = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
            .expect_err("the root must be exclusively owned while its watch is running");
        assert!(err.to_string().contains("already in use"), "unexpected error: {err}");

        let controller = LinkRuntimeController::new(state.clone());
        controller.stop(&root.path().to_string_lossy()).await;

        let _reacquired = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(
            root.path(),
        )
        .expect("stopping the watch must release the sync-root lock so it can be re-acquired");
    }

    /// HIGH-1 concurrent-stop regression: the control socket spawns one
    /// task per connection, so two overlapping `Unlink`s for the same path
    /// (a genuine, not hypothetical, shape) both call `stop`.
    /// Without `DaemonState::link_watch_stop_locks` serializing them, the
    /// second call would find `link_tasks` already emptied by the first
    /// and skip waiting entirely, racing ahead to drop the root lock while
    /// the first call's own wait (for a still-running task) is still in
    /// progress.
    ///
    /// Exercises the serialization primitive directly rather than trying
    /// to race a real slow scan (inherently timing-sensitive): pre-holds
    /// the per-link stop lock exactly as an in-flight `stop` would,
    /// confirms a concurrent second call genuinely blocks on it (not
    /// merely "eventually completes", which would also be true if
    /// unserialized), then releases and confirms it proceeds.
    #[tokio::test]
    async fn concurrent_stop_calls_for_the_same_path_are_serialized() {
        let state = test_state();
        let local_path = "/some/link/path".to_string();

        let per_link_lock = state.links.stop_lock(&local_path);
        let held = per_link_lock.lock().await;

        let state_for_task = state.clone();
        let path_for_task = local_path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let stop_task = tokio::spawn(async move {
            let controller = LinkRuntimeController::new(state_for_task);
            let _ = started_tx.send(());
            controller.stop(&path_for_task).await;
        });
        started_rx.await.unwrap();
        // Give the spawned task every chance to have raced ahead if it
        // were NOT actually serialized -- a generous margin, not a tight
        // race, since this assertion is about "definitely still blocked",
        // not about timing precision.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !stop_task.is_finished(),
            "a concurrent stop for the same path must block on the held per-link \
             lock, not race ahead while it is held"
        );

        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(2), stop_task)
            .await
            .expect("stop must proceed once the per-link lock is released")
            .unwrap();
    }

    /// The per-group refusal at the daemon seam. `start_inner` runs
    /// the scan that emits the tombstones, so an ambiguous group must never get
    /// a watcher at all -- and the refusal must be scoped to that group, since a
    /// per-database halt would brick the daemon for every folder the user has.
    #[tokio::test]
    async fn an_ambiguous_group_is_refused_a_watcher_while_healthy_groups_still_start() {
        let state = test_state();
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let root_c = tempfile::tempdir().unwrap();

        state
            .replica_coordinator
            .link_repository()
            .add_link(&root_a.path().to_string_lossy(), "group-1")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), "group-1")
            .unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root_c.path().to_string_lossy(), "group-2")
            .unwrap();

        let controller = LinkRuntimeController::new(state.clone());
        let err = controller
            .start_with_source(
                root_a.path().to_string_lossy().into_owned(),
                "group-1".to_string(),
                Arc::new(RealFolderWatchSource),
            )
            .expect_err("a twice-linked group must not get a watcher: the scan is what deletes");
        assert!(
            format!("{err}").contains("group-1"),
            "the refusal must name the group it is about, got: {err}"
        );

        // The non-negotiable: per-GROUP, never per-DATABASE.
        start_watch_and_await_scan(&state, root_c.path(), "group-2").await;
    }
}
