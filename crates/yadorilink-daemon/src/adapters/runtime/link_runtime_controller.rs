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

use crate::daemon_state::run_blocking_sweep_offloaded;
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
        // site did. First tick is deliberately delayed a full interval, NOT
        // immediate -- `tokio::time::interval`'s own first tick fires
        // immediately (a well-known gotcha, see its docs), which would race
        // this same function's own startup repair pass (inside
        // `LinkRuntimeFactory::build`, right after acquiring this link's
        // `SyncRootLock`) that already just ran once for this link before
        // its watcher started -- a confirmed, reproduced bug: an
        // immediate first tick landed microseconds after a fresh restart,
        // grabbed a just-synced file's path lock before a live incoming
        // peer edit reached it, read the disk bytes as "diverged," and
        // quarantined them. `interval_at` with an explicit first deadline
        // is what actually delays it (plain `interval` does not, despite
        // what this comment used to claim).
        let repair_state = state.clone();
        let repair_root = PathBuf::from(&local_path);
        let repair_group_id = group_id.clone();
        let repair_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + MATERIALIZATION_REPAIR_INTERVAL,
                MATERIALIZATION_REPAIR_INTERVAL,
            );
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
                // synchronously. `root_op` is admitted INSIDE the
                // closure and held for the whole repair call, including the
                // disk walk/reconstruct work that precedes its own DB commits,
                // not just their `verify`.
                let repair_result = tokio::task::spawn_blocking(move || {
                    crate::link_runtime::operations::repair_materialization::repair_interrupted_materializations(
                        &replica_coordinator,
                        &block_store,
                        &root_lease,
                        &root,
                        &group_id,
                        yadorilink_filesystem_sync::materialization_repair::RepairMode::Live,
                    )
                })
                .await;
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
        // `link_runtimes` was the only place this `Arc` was ever
        // DURABLY cloned from, so removing it there leaves exactly one
        // strong reference in the steady state -- but a genuine, narrow
        // exception exists: `RootCommitAuthorityProvider::root_lease_for`
        // (`root_commit_authority.rs`) does `self.links.runtime(&local_
        // path).map(|runtime| runtime.root_lease().clone())` -- a bare,
        // unfenced PEEK at the same registry entry, entirely outside the
        // `begin_stopping`/`wait_drained` sequencing above. That peek's
        // own `Arc<LinkRuntime>` clone is dropped the instant the
        // closure returns (no `.await` inside `root_lease_for`, so
        // nothing can suspend mid-peek) -- but on a real multi-threaded
        // runtime, that whole synchronous peek can genuinely be
        // in-flight on a DIFFERENT OS thread at the exact instant this
        // function's own removal-then-unwrap runs on this one, which is
        // an ordinary, expected data race on the refcount, not a fence
        // bug (exercised by `topology_soak_lane.rs`'s `RestartNode` op
        // racing concurrent `hydrate`/`evict` calls). The window is microsecond-scale by
        // construction, so a few bounded, near-immediate retries let it
        // clear on its own almost every time, keeping this function on
        // its normal clean-shutdown path; only a genuinely persistent
        // failure (a real bug elsewhere holding the Arc across an await,
        // which retrying cannot fix) falls through to the same graceful
        // degraded fallback `app.rs::graceful_shutdown` already
        // establishes as correct for an unexpectedly-shared Arc here --
        // log loudly and abort tasks directly rather than panic the
        // whole link-stop caller over what is, in that case, still a
        // real anomaly worth knowing about but not worth taking the
        // daemon down for.
        const MAX_UNWRAP_RETRIES: u32 = 20;
        const UNWRAP_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(5);
        let mut candidate = runtime;
        let mut attempt = 0;
        let runtime = loop {
            match Arc::try_unwrap(candidate) {
                Ok(runtime) => break runtime,
                Err(shared) if attempt < MAX_UNWRAP_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(UNWRAP_RETRY_BACKOFF).await;
                    candidate = shared;
                }
                Err(shared) => {
                    tracing::error!(
                        local_path,
                        refs = Arc::strong_count(&shared),
                        attempts = attempt,
                        "stop: Arc<LinkRuntime> still shared after removal from link_runtimes \
                         and every retry; falling back to abort-only teardown"
                    );
                    shared.abort_tasks();
                    return;
                }
            }
        };

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
    /// recreating its entire event stream — see `watcher.rs`'s module doc).
    /// No
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
            // `reconcile_added_files_from_disk` is synchronous and open-ended:
            // it loads the link's ignore set from disk, reads the group's whole
            // index out of SQLite, then `walkdir`s the entire link folder and,
            // for every path with no index row, reads/chunks/SHA-256s the file
            // and writes its blocks. That is exactly the work the *initial*
            // scan already offloads (`link_runtime/tasks.rs`'s `spawn_blocking`
            // around `scan_existing_files_with_ignore_gated`), and the case
            // this backstop exists for -- a watcher that never bound, or lost
            // its events -- is precisely the case where the whole folder is
            // unindexed, so a single sweep can be arbitrarily long. Run
            // directly from this task it would hold the polling worker for that
            // entire pass, per link, every sweep tick.
            //
            // The call is plain synchronous (no future to drive), so it needs
            // no `Handle::block_on` bridge the way `tasks.rs`'s `async`
            // `process_flush_with_ignore` does -- the shared
            // `run_blocking_sweep_offloaded` guard is enough, and it carries
            // the current-thread-runtime fallback with it.
            let reconciled = run_blocking_sweep_offloaded(|| {
                runtime.reconcile_added_files_from_disk(&link.group_id)
            });
            let Some(result) = reconciled else {
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
mod tests;
