//! Starts/stops the background tasks that watch one linked folder
//! (task 5.2's watcher, wired to task 5.3/6.1's chunking-and-indexing,
//! task 5.5's broadcast to connected peers, and task 8.5's shell-extension
//! status push). Two tasks per link, per batch-sync-optimizations design
//! D7: a debounce **accumulator** that only ever reads raw filesystem
//! events and coalesces them into windowed batches
//! (`yadorilink_sync_core::debounce`), and an **executor** that consumes
//! those batches and does the actual chunk/index/broadcast work — kept
//! separate so a slow executor flush never blocks the accumulator from
//! continuing to observe new events.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Weak};

use yadorilink_ipc_proto::shellipc::{
    MaterializationState as ShellMaterializationState, StatusPush, SyncState as ShellSyncState,
};
use yadorilink_sync_core::debounce::{self, DebounceFlush};
use yadorilink_sync_core::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::materialization;
use yadorilink_sync_core::peer_session::PendingLocalChangeFlush;
use yadorilink_sync_core::types::{FileRecord, LinkMode};
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, RealFolderWatchSource,
};

use crate::daemon_state::DaemonState;
use crate::error::DaemonError;

/// fix-materialization-disk-index-divergence: how often each link's
/// background task re-runs `materialization::repair_interrupted_
/// materializations` during live operation, not just at daemon startup —
/// defense-in-depth against whatever bug might leave a `Hydrated` index
/// record disagreeing with what's actually on disk (the direct fixes are
/// in `try_apply_metadata_only_update` and this module's debounce-batch
/// executor; this is a coarse, low-frequency safety net on top of those,
/// not a substitute for them). Same order of magnitude as
/// `yadorilink_sync_core::peer_session::DEFAULT_FULL_INDEX_RESYNC_INTERVAL`
/// (90s) -- frequent enough to bound how long a divergence can persist,
/// infrequent enough that a full per-link disk scan is negligible
/// overhead against normal sync traffic.
const MATERIALIZATION_REPAIR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(120);

/// add-folder-direction-modes: small shared helper, same shape as
/// `yadorilink_sync_core::peer_session`'s private `now_unix_nanos` (that
/// one isn't `pub`, and this module has no other reason to depend on
/// `peer_session` directly) — used to timestamp `receive_only_changed`
/// entries the same way `record_out_of_sync` timestamps its own.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// fix-local-edit-swallowed-by-self-echo-race task 1.1's chosen plumbing:
/// lets `yadorilink_sync_core::peer_session::PeerSyncSession::
/// reconcile_one_file` force this specific link's debounce accumulator to
/// flush and index any pending, undispatched local change for one path
/// *before* a peer's write or tombstone for that same path is
/// compared/applied. Registered into `DaemonState::link_flush_handles`
/// (keyed by `local_path`, same as `link_tasks`) by `start_link_watch`
/// below, and removed by `stop_link_watch`; reached from a
/// `PeerSyncSession` via `PendingLocalChangeFlush for DaemonState`, whose
/// `group_id` it's given is resolved to a `local_path` via
/// `sync_state.list_links()`.
///
/// Held with a `Weak<DaemonState>` (not `Arc`): this handle is itself
/// stored inside `DaemonState::link_flush_handles`, so an `Arc` back-
/// reference here would be a permanent reference cycle.
pub struct LinkFlushHandle {
    state: Weak<DaemonState>,
    flush_request_tx: tokio::sync::mpsc::Sender<debounce::FlushPathRequest>,
    flush_all_request_tx: tokio::sync::mpsc::Sender<debounce::FlushAllRequest>,
    processor: Arc<LocalChangeProcessor>,
    root: PathBuf,
    /// `root`, canonicalized once at construction — the debounce
    /// accumulator's `pending` map is keyed by the raw OS watcher's own
    /// `FsChangeEvent::path`, which (per `local_change.rs::process_event_
    /// with_ignore`'s doc comment) is already fully-resolved (e.g.
    /// `/private/var/...` on macOS, not the `/var/...` symlink most
    /// callers construct their root from) — joining `rel_path` onto the
    /// *non*-canonical `root` instead would never match a real pending
    /// entry's key at all.
    canonical_root: PathBuf,
    local_path: String,
}

/// Bounded wait for `LinkFlushHandle::flush_pending_local_change`'s round
/// trip to this link's debounce accumulator — design.md's Risk section:
/// this must never block a peer message handler indefinitely if the
/// accumulator task is somehow stalled or backlogged. A single bounded
/// wait, not a jittered multi-attempt retry like `peer_session`'s
/// `RECONCILE_RETRY_*`: there's nothing transient to retry against here
/// (either the accumulator answers almost instantly, since it's just a
/// `HashMap` lookup/removal, or something is genuinely wrong with it), and
/// retrying an already-timed-out request would only compound the delay on
/// this critical path.
const FORCE_FLUSH_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

impl LinkFlushHandle {
    async fn flush_pending_local_change(&self, group_id: &str, rel_path: &str) {
        let path = self.canonical_root.join(rel_path);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .flush_request_tx
            .send(debounce::FlushPathRequest {
                path: path.clone(),
                mode: debounce::FlushMode::ExactPath,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return; // this link's accumulator task is gone
        }
        let found = match tokio::time::timeout(FORCE_FLUSH_REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(found)) => found,
            Ok(Err(_)) => None, // accumulator dropped the reply sender without answering
            Err(_) => {
                tracing::warn!(
                    group_id,
                    path = %path.display(),
                    "timed out waiting for this link's debounce accumulator to answer a targeted \
                     flush request; proceeding without one"
                );
                None
            }
        };
        // fix-local-change-lost-under-registration-mutex-contention (scope
        // widened during scenario 5's investigation — see design.md's
        // Decisions section): a `None` reply here means the debounce
        // accumulator has nothing queued for this path, but that no longer
        // means there is nothing local to protect — a brand-new file
        // inside a brand-new, not-yet-watched directory can still be
        // genuinely *undiscovered* at this point (no `FsChangeEvent` for
        // it has ever been produced, so it was never a candidate to be
        // queued here in the first place). Fall back to a direct,
        // disk-authoritative check for this exact path rather than
        // treating "nothing queued" as "nothing to do".
        let Some((found_path, kind, observed_at)) = found else {
            self.capture_undiscovered_local_change(group_id, &path).await;
            return;
        };
        tracing::info!(
            group_id,
            path = %path.display(),
            "forcing a pending local change to flush and index before a racing peer update for \
             the same path is applied"
        );
        let Some(state) = self.state.upgrade() else { return };
        match self
            .processor
            .process_flush(
                group_id,
                &self.root,
                DebounceFlush::Paths(vec![(found_path, kind, observed_at)]),
            )
            .await
        {
            Ok(outcome) => {
                announce_local_change(&state, &self.local_path, group_id, outcome.records).await;
                for (path, editing) in outcome.presence_changes {
                    announce_presence_change(&state, group_id, path, editing).await;
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a pending local change ahead of a racing peer update"
            ),
        }
    }

    /// fix-case-fold-sibling-local-change-not-flushed-before-reconcile:
    /// like `flush_pending_local_change` above, but looks for a *different*
    /// pending path in this link's debounce accumulator that case-fold-
    /// collides with `rel_path` (same parent directory, case-equal final
    /// component, different exact bytes) rather than `rel_path` itself.
    ///
    /// Closes a race `flush_pending_local_change` alone cannot: on a
    /// case-insensitive filesystem, `peer_session::hazard_reason_for_
    /// policy`'s `state.list_files(group_id)` read (used to detect a
    /// case-fold collision before materializing an incoming record) only
    /// sees what's already indexed in `SyncState` — it has no visibility
    /// into this device's own not-yet-flushed local write to the
    /// colliding sibling name, still sitting undispatched in this
    /// accumulator. Without this call, that local write can lose the race
    /// entirely: the incoming record for the other case-variant
    /// materializes for real (no hazard detected, because the sibling
    /// wasn't indexed yet) instead of being held, exactly the kind of
    /// artifact-free silent overwrite `fix-local-edit-swallowed-by-
    /// self-echo-race` already closed for the exact-same-path case.
    ///
    /// Deliberately no `capture_undiscovered_local_change` fallback here
    /// (unlike `flush_pending_local_change`): that fallback exists for a
    /// path this device is specifically being asked to protect. A
    /// case-fold sibling this device has never even locally observed yet
    /// is not something to synthesize a change for defensively — if
    /// nothing is pending, there is nothing more to flush ahead of the
    /// hazard check than what `SyncState` (about to be read) already
    /// reflects.
    async fn flush_case_fold_sibling(&self, group_id: &str, rel_path: &str) {
        let path = self.canonical_root.join(rel_path);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .flush_request_tx
            .send(debounce::FlushPathRequest {
                path,
                mode: debounce::FlushMode::CaseFoldSibling,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return; // this link's accumulator task is gone
        }
        let found = match tokio::time::timeout(FORCE_FLUSH_REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(found)) => found,
            Ok(Err(_)) => None,
            Err(_) => {
                tracing::warn!(
                    group_id,
                    rel_path,
                    "timed out waiting for this link's debounce accumulator to answer a \
                     case-fold sibling flush request; proceeding without one"
                );
                None
            }
        };
        let Some((sibling_path, kind, observed_at)) = found else { return };
        tracing::info!(
            group_id,
            rel_path,
            sibling_path = %sibling_path.display(),
            "forcing a case-fold sibling's pending local change to flush and index before a \
             racing peer update for the colliding name is applied"
        );
        let Some(state) = self.state.upgrade() else { return };
        match self
            .processor
            .process_flush(
                group_id,
                &self.root,
                DebounceFlush::Paths(vec![(sibling_path, kind, observed_at)]),
            )
            .await
        {
            Ok(outcome) => {
                announce_local_change(&state, &self.local_path, group_id, outcome.records).await;
                for (path, editing) in outcome.presence_changes {
                    announce_presence_change(&state, group_id, path, editing).await;
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a case-fold sibling's pending local change ahead of a \
                 racing peer update"
            ),
        }
    }

    /// fix-resume-does-not-flush-pending-local-changes: drains and indexes
    /// *every* currently-pending, undispatched local change in this link's
    /// debounce accumulator — called by `resume_link` immediately before
    /// it snapshots this link's current state to broadcast on resume.
    ///
    /// Without this, resuming a link that was paused while a local change
    /// was still sitting undispatched (announced/indexed only once its own
    /// debounce window's quiet period elapses) can broadcast a stale
    /// snapshot that silently omits it — and get no second chance to send
    /// it, since a paused link's own local changes are indexed but never
    /// propagated while paused (`announce_local_change`'s doc comment), so
    /// nothing re-triggers a send for that exact path until either another
    /// local change to it, or the next periodic full-index resync,
    /// happens to occur.
    async fn flush_all_pending_local_changes(&self, group_id: &str) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .flush_all_request_tx
            .send(debounce::FlushAllRequest { reply: reply_tx })
            .await
            .is_err()
        {
            return; // this link's accumulator task is gone
        }
        let drained = match tokio::time::timeout(FORCE_FLUSH_REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(drained)) => drained,
            Ok(Err(_)) => Vec::new(),
            Err(_) => {
                tracing::warn!(
                    group_id,
                    "timed out waiting for this link's debounce accumulator to answer a \
                     flush-all request before resume; proceeding without one"
                );
                Vec::new()
            }
        };
        if drained.is_empty() {
            return;
        }
        tracing::info!(
            group_id,
            count = drained.len(),
            "forcing every pending local change to flush and index before this link's resume \
             broadcast reflects its current state"
        );
        let Some(state) = self.state.upgrade() else { return };
        match self
            .processor
            .process_flush(group_id, &self.root, DebounceFlush::Paths(drained))
            .await
        {
            Ok(outcome) => {
                announce_local_change(&state, &self.local_path, group_id, outcome.records).await;
                for (path, editing) in outcome.presence_changes {
                    announce_presence_change(&state, group_id, path, editing).await;
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush this link's pending local changes ahead of its resume \
                 broadcast"
            ),
        }
    }

    /// fix-local-change-lost-under-registration-mutex-contention: the
    /// debounce-accumulator flush above (`FlushPathRequest`) only ever
    /// recovers a local change that some path has already been turned
    /// into an `FsChangeEvent` and queued for — i.e. one the watcher (or
    /// `watcher::reconcile_new_directory_subtree`'s own discovery
    /// synthesis) has already observed. It cannot help with a path that
    /// is still entirely undiscovered: `notify`'s `watch()` call for a
    /// brand-new directory is a real OS-level `FSEventStream`
    /// stop/recreate that can itself take up to ~1s (`watcher.rs`'s
    /// module doc comment), and the synthesized "this file already
    /// exists" event for anything already inside that directory only
    /// fires once that call returns — so a file that was written to disk
    /// moments ago, inside a moments-old sibling directory, can still
    /// have produced *no* `FsChangeEvent` at all by the time a peer's
    /// conflicting write for the same path is being reconciled. Without
    /// this fallback, `reconcile_one_file` would find no local record
    /// (nothing has indexed this device's own write yet), treat the
    /// incoming write as a plain new file, and materialize it straight
    /// over this device's own, never-yet-observed bytes — silently and
    /// permanently destroying a genuine local edit with no conflict ever
    /// detected (see `directory_conflict_matrix.rs`'s
    /// `concurrently_creating_same_named_directory_with_a_conflicting_
    /// file_inside`, and this change's design.md).
    ///
    /// `LocalChangeProcessor::process_event` re-derives everything
    /// (`FsChangeKind`, content/blocks/mtime) directly from disk
    /// (`local_change.rs`'s own `effective_kind` re-derivation and
    /// self-echo suppression) and has no dependency on `watched_dirs` or
    /// whatever state the watcher subsystem happens to be in — so calling
    /// it here, for this exact path, closes the gap unconditionally
    /// rather than needing to know *why* the path wasn't discovered yet.
    /// The `FsChangeKind` passed in is irrelevant either way:
    /// `process_event`'s dispatch always re-derives the true kind from a
    /// fresh `symlink_metadata` call before acting on it.
    ///
    /// Deliberately run to completion with no additional timeout, mirroring
    /// `flush_pending_local_change`'s own `process_flush` call above: the
    /// only bounded step in either path is the cheap accumulator
    /// round-trip: once there is real work to do (a file that may need
    /// chunking), letting it finish is strictly better than truncating it
    /// mid-way and leaving this exact race unresolved. The overwhelmingly
    /// common case — no local file at this path at all, a plain new
    /// record from a peer — is already cheap: skipped entirely by the
    /// `symlink_metadata` guard below, and via the size+mtime fast path
    /// (PERF-2) when a local file exists but hasn't changed.
    ///
    /// Only ever synthesizes `CreatedOrModified`, deliberately: this
    /// fallback exists to protect a genuine local *creation* racing an
    /// incoming peer write for the same not-yet-indexed path — a real
    /// file already on disk that this device hasn't discovered/indexed
    /// yet. It is not the right place to also synthesize `Removed` for a
    /// path with no file on disk: `local_change.rs`'s `Removed` branch
    /// only guards against "no index entry at all", not "already marked
    /// deleted" (nothing needs that second guard today, since a real
    /// watcher only ever fires one genuine `Removed` per deletion) — an
    /// unconditional fallback call for a path that's already tombstoned
    /// would call `SyncState::mark_deleted_at` again, which unconditionally
    /// re-increments that path's version vector and re-stamps its
    /// tombstone `mtime_unix_nanos` to "now" even though nothing local
    /// changed, corrupting the very version-vector comparison
    /// `reconcile_one_file` is about to make (confirmed: this exact
    /// pre-guard-less version caused a spurious conflict-copy in
    /// `collision_matrix.rs`'s `concurrent_edit_delete_edit_wins_when_
    /// later_leaves_no_conflict_artifact`, which expects a later edit to
    /// win a delete outright with no conflict artifact). Skipping when
    /// `path` doesn't exist on disk needs no such guard: `COR-8`
    /// (`local_change.rs`'s own comment on its `Removed` branch) already
    /// treats "no index entry for this path" as nothing to protect, and a
    /// file created-then-deleted before ever being discovered/indexed is
    /// exactly that case — net zero, nothing to propagate.
    async fn capture_undiscovered_local_change(&self, group_id: &str, path: &Path) {
        if path.symlink_metadata().is_err() {
            return; // nothing on disk at this path — nothing to protect
        }
        let Some(state) = self.state.upgrade() else { return };
        let event =
            FsChangeEvent { path: path.to_path_buf(), kind: FsChangeKind::CreatedOrModified };
        match self.processor.process_event(group_id, &self.root, &event).await {
            Ok(LocalChangeOutcome::FileChanged(record)) => {
                tracing::info!(
                    group_id,
                    path = %path.display(),
                    "captured a not-yet-discovered local change directly from disk before a \
                     racing peer update for the same path is applied"
                );
                announce_local_change(&state, &self.local_path, group_id, vec![record]).await;
            }
            Ok(LocalChangeOutcome::PresenceChanged { path, editing }) => {
                announce_presence_change(&state, group_id, path, editing).await;
            }
            // This call always synthesizes `FsChangeKind::CreatedOrModified`
            // (see this fn's own doc comment) — `FilesChanged` only ever
            // originates from the `Removed` branch, so unreachable here in
            // practice, but `LocalChangeOutcome` is matched exhaustively.
            Ok(LocalChangeOutcome::FilesChanged(records)) => {
                announce_local_change(&state, &self.local_path, group_id, records).await;
            }
            Ok(LocalChangeOutcome::None) => {} // genuinely nothing local at this path
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                path = %path.display(),
                "failed to check for a not-yet-discovered local change ahead of a racing peer \
                 update"
            ),
        }
    }
}

impl DaemonState {
    /// Shared by both `PendingLocalChangeFlush` methods below: resolves
    /// `group_id` to its `LinkFlushHandle`, if this device is actively
    /// linked (and watching) that group at all.
    fn link_flush_handle_for(&self, group_id: &str) -> Option<Arc<LinkFlushHandle>> {
        let local_path = match self.sync_state.list_links() {
            Ok(links) => links.into_iter().find(|l| l.group_id == group_id).map(|l| l.local_path),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "failed to look up this group's local link");
                None
            }
        };
        let local_path = local_path?;
        self.link_flush_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&local_path)
            .cloned()
    }
}

impl PendingLocalChangeFlush for DaemonState {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Some(handle) = self.link_flush_handle_for(group_id) {
                handle.flush_pending_local_change(group_id, rel_path).await;
            }
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Some(handle) = self.link_flush_handle_for(group_id) {
                handle.flush_case_fold_sibling(group_id, rel_path).await;
            }
        })
    }
}

pub fn start_link_watch(
    state: Arc<DaemonState>,
    local_path: String,
    group_id: String,
) -> Result<(), DaemonError> {
    start_link_watch_with_source(state, local_path, group_id, Arc::new(RealFolderWatchSource))
}

/// add-deterministic-sync-testing: same as `start_link_watch`, but takes
/// an explicit `FolderWatchSource` so a DST scenario can substitute a
/// synthetic event source in place of the real OS filesystem watcher,
/// while every other production code path below (debounce, indexing,
/// broadcast, materialization) runs unchanged.
pub fn start_link_watch_with_source(
    state: Arc<DaemonState>,
    local_path: String,
    group_id: String,
    watcher_source: Arc<dyn FolderWatchSource>,
) -> Result<(), DaemonError> {
    // Bind the watcher *before* the initial scan below: `notify` starts
    // buffering OS-level events into its channel as soon as it's created,
    // so any file created mid-scan is still caught (see `scan_existing_files`'s
    // doc comment for why the scan is needed at all — a watcher alone only
    // reports changes from the moment it starts). The accumulator task
    // (spawned below) starts draining those events immediately, but the
    // executor task doesn't consume the flushes it produces until after
    // the scan below completes — matching the original ordering guarantee
    // even though accumulation and scanning now happen concurrently.
    let ignore_set = Arc::new(EffectiveIgnoreSet::load_for_link_root(Path::new(&local_path))?);
    let watcher = watcher_source.watch(Path::new(&local_path), ignore_set.clone())?;
    let processor = Arc::new(LocalChangeProcessor::new(
        state.sync_state.clone(),
        state.block_store.clone(),
        state.device_id.clone(),
    ));
    let root = PathBuf::from(&local_path);

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    // fix-local-edit-swallowed-by-self-echo-race task 1.1: a small
    // channel is enough — a targeted flush request is a single in-flight
    // round trip per racing path, not a backlog like `flush_tx` above.
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    // fix-resume-does-not-flush-pending-local-changes: same sizing
    // rationale as `flush_request_tx` above — a single in-flight round
    // trip per resume, not a backlog.
    let (flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);

    let executor_state = state.clone();
    let executor_local_path = local_path.clone();
    let executor_group_id = group_id.clone();
    let executor_processor = processor.clone();
    let executor_root = root.clone();
    let executor_ignore_set = ignore_set.clone();
    let executor_handle = tokio::spawn(async move {
        let mut executor_ignore_set = executor_ignore_set;
        let executor_canonical_root =
            executor_root.canonicalize().unwrap_or_else(|_| executor_root.clone());
        // sync-performance PERF-1: `scan_existing_files` walks the whole
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
            // add-automatic-updates task 2.4: the initial scan chunks and
            // indexes every not-already-current file — a genuine
            // sync-critical write, held for the guard's whole duration
            // (including the `spawn_blocking` await) so an update install
            // never starts mid-scan.
            let _write_activity = executor_state.begin_write_activity();
            tokio::task::spawn_blocking(move || {
                processor.scan_existing_files_with_ignore(&group_id, &root, ignore_set.as_ref())
            })
            .await
        };
        match scan_result {
            Ok(Ok(records)) => {
                // One batched broadcast for the whole initial scan
                // (batch-sync-optimizations design D5) instead of one
                // peer message per pre-existing file.
                announce_local_change(
                    &executor_state,
                    &executor_local_path,
                    &executor_group_id,
                    records,
                )
                .await;
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, local_path = %executor_local_path, "failed to scan pre-existing files")
            }
            Err(join_err) => {
                tracing::warn!(error = %join_err, local_path = %executor_local_path, "initial scan task panicked")
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
                // design D8: every fallback trigger is logged, not silent.
                tracing::warn!(
                    local_path = %executor_local_path,
                    group_id = %executor_group_id,
                    "event burst exceeded the debounce threshold; falling back to a full reconciliation scan"
                );
            }
            // sync-performance PERF-1: `process_flush` chunks every
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
            // add-automatic-updates task 2.4: every flush chunks/indexes
            // touched files (or runs a full reconciliation scan) — held
            // across the whole `block_in_place`/`block_on` call so an
            // update install never starts mid-flush.
            let _write_activity = executor_state.begin_write_activity();
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
            match flush_result {
                Ok(outcome) => {
                    announce_local_change(
                        &executor_state,
                        &executor_local_path,
                        &executor_group_id,
                        outcome.records,
                    )
                    .await;
                    for (path, editing) in outcome.presence_changes {
                        announce_presence_change(
                            &executor_state,
                            &executor_group_id,
                            path,
                            editing,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, local_path = %executor_local_path, "failed to process a local-change batch")
                }
            }
        }
    });

    let (events_rx, overflowed, watcher_guard) = watcher.split();
    let accumulator_handle = tokio::spawn(async move {
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
    });

    // fix-local-edit-swallowed-by-self-echo-race task 1.1: registered
    // before the tasks below are handed to `link_tasks` so a peer session
    // can never observe a `link_tasks` entry for this link without a
    // matching flush handle also being reachable.
    state.link_flush_handles.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(
        local_path.clone(),
        Arc::new(LinkFlushHandle {
            state: Arc::downgrade(&state),
            flush_request_tx,
            flush_all_request_tx,
            processor: processor.clone(),
            root: root.clone(),
            canonical_root: root.canonicalize().unwrap_or_else(|_| root.clone()),
            local_path: local_path.clone(),
        }),
    );

    // fix-materialization-disk-index-divergence: periodic live repair
    // pass — see MATERIALIZATION_REPAIR_INTERVAL's doc comment. First
    // tick is after one full interval (tokio::time::interval's default),
    // not immediately, since the startup repair pass in main.rs already
    // just ran for every link before any watcher (including this one)
    // started.
    let repair_state = state.clone();
    let repair_root = root.clone();
    let repair_group_id = group_id.clone();
    let repair_handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(MATERIALIZATION_REPAIR_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let sync_state = repair_state.sync_state.clone();
            let block_store = repair_state.block_store.clone();
            let root = repair_root.clone();
            let group_id = repair_group_id.clone();
            // Same spawn_blocking rationale as the initial scan above:
            // this walks the whole linked folder synchronously.
            let repair_result = tokio::task::spawn_blocking(move || {
                materialization::repair_interrupted_materializations(
                    &sync_state,
                    block_store.as_ref(),
                    &root,
                    &group_id,
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

    state
        .link_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(local_path, vec![accumulator_handle, executor_handle, repair_handle]);
    Ok(())
}

fn flush_touches_ignore_file(root: &Path, flush: &DebounceFlush) -> bool {
    match flush {
        DebounceFlush::Paths(paths) => paths.iter().any(|(path, _, _)| {
            path.strip_prefix(root).ok().is_some_and(is_ignore_file_relative_path)
        }),
        DebounceFlush::BurstFallback => false,
    }
}

pub fn stop_link_watch(state: &DaemonState, local_path: &str) {
    if let Some(handles) =
        state.link_tasks.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(local_path)
    {
        for handle in handles {
            handle.abort();
        }
    }
    state
        .link_flush_handles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(local_path);
}

/// Resumes a paused link and re-broadcasts its currently-indexed files to
/// connected peers. Unpausing alone only lifts the gate on *future*
/// propagation — any change indexed *while* paused was queued locally
/// (task 6.8's guarantee: `SyncState` itself is the backlog) but never
/// actually sent, since `announce_local_change` only ever checks the
/// pause flag once, at the moment each change is first processed. Resume
/// must therefore flush that backlog itself, not just flip the flag.
/// Peers that are already fully caught up simply see `VvOrdering::Equal`
/// for everything and no-op — re-sending the whole current index is
/// simple and correct, just not the cheapest possible resume.
pub async fn resume_link(
    state: &DaemonState,
    local_path: &str,
) -> Result<(), yadorilink_sync_core::SyncError> {
    state.sync_state.set_paused(local_path, false)?;
    let Some(group_id) = state
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.local_path == local_path)
        .map(|l| l.group_id)
    else {
        return Ok(());
    };
    // fix-resume-does-not-flush-pending-local-changes: closes the gap this
    // fn's own doc comment doesn't cover -- a change still sitting
    // undispatched in the debounce accumulator (not yet even in
    // `SyncState`) at the moment of resume isn't part of the backlog
    // `list_files` below can see at all. Force it into the index first,
    // so the snapshot broadcast a few lines down reflects this link's true
    // current state rather than racing whatever quiet-period window that
    // change's own debounce window happened to still be in.
    let handle = state
        .link_flush_handles
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(local_path)
        .cloned();
    if let Some(handle) = handle {
        handle.flush_all_pending_local_changes(&group_id).await;
    }
    let records = state.sync_state.list_files(&group_id)?;
    state.broadcast_change(&group_id, records).await;
    Ok(())
}

/// add-file-version-history task 2.4: runs `SyncState::expire_superseded_
/// and_trashed_versions` for every currently-registered link, using each
/// link's own retention policy — the periodic sweep design D2 requires
/// ("a version exceeding both retention_max_versions and
/// retention_max_age_days is swept"). Bounded and synchronous (SQLite
/// calls only, no network I/O), matching this module's other maintenance
/// sweeps (e.g. `DaemonState`'s presence-TTL-refresh loop) which also run
/// plain `SyncState` calls directly on the async runtime rather than via
/// `spawn_blocking` — a link's superseded/trashed backlog is bounded by
/// its own retention policy, so this is not expected to be a large or slow
/// scan. Logs (rather than propagating) a per-link failure so one link's
/// error never stops the sweep from covering the rest — matching
/// `resume_link`'s and `announce_local_change`'s existing "log and
/// continue" error-handling shape for background maintenance work.
pub fn run_retention_expiry_sweep(state: &DaemonState) {
    let links = match state.sync_state.list_links() {
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
        match state.sync_state.expire_superseded_and_trashed_versions(
            &link.group_id,
            link.retention_policy,
            now_unix_nanos,
        ) {
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

/// add-disk-reconcile-backstop: a periodic, filesystem-watcher-event-
/// *independent* disk-authoritative reconcile — the eventual-consistency
/// backstop for a local write whose OS watcher event never arrives at all
/// (e.g. an FSEvents blind window opened by `watch()` tearing down and
/// recreating its entire event stream — see `watcher.rs`'s module doc, and
/// `openspec/changes/investigate-rename-to-identical-name-non-convergence/
/// design.md`'s confirmed root cause for `taguchi_v3` row 8). No
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
/// false-delete a file mid-conflict-resolution between two devices,
/// reproduced deterministically against `fix-local-change-lost-under-
/// registration-mutex-contention`). A file with no index row has never
/// been broadcast or adopted by a peer, so indexing it carries none of
/// that hazard — it's byte-for-byte what a live create event would have
/// done.
///
/// Skips paused links entirely (task 2.2): a paused link intentionally
/// does not propagate, and indexing+broadcasting from this sweep would
/// violate that the same way a live local change would. A link paused
/// during a watcher-event loss is still covered once it resumes:
/// `resume_link`'s own broadcast re-emits `list_files`, and the next
/// sweep tick after resume runs normally for it.
///
/// Skips a link with no `LinkFlushHandle` yet registered (the brief window
/// between `add_link` and `start_link_watch` completing) rather than
/// erroring — the next tick covers it once registration finishes.
pub async fn run_disk_reconcile_backstop_sweep(state: &Arc<DaemonState>) {
    let links = match state.sync_state.list_links() {
        Ok(links) => links,
        Err(e) => {
            tracing::warn!(error = %e, "disk-reconcile-backstop: failed to list links");
            return;
        }
    };
    for link in links {
        if link.paused {
            continue;
        }
        let handle = state
            .link_flush_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&link.local_path)
            .cloned();
        let Some(handle) = handle else { continue };
        match handle.processor.reconcile_added_files(&link.group_id, &handle.root) {
            Ok(records) if !records.is_empty() => {
                tracing::info!(
                    group_id = %link.group_id,
                    local_path = %link.local_path,
                    count = records.len(),
                    "disk-reconcile-backstop recovered file(s) never delivered by the local \
                     filesystem watcher"
                );
                announce_local_change(state, &link.local_path, &link.group_id, records).await;
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

/// add-folder-direction-modes task 4.1: changes `local_path`'s directional
/// mode and triggers the rescan/reconcile design.md requires — "the new
/// gating and divergence sets are recomputed against current on-disk and
/// peer state, rather than waiting for the next incidental FS or index
/// event." Two things happen, deliberately distinct from `override_link`/
/// `revert_link` below (which *reconcile content divergence* — an
/// explicit, user-initiated "local wins"/"peer wins" decision): this
/// function only ever recomputes *gating*, never resolves a content
/// disagreement on its own.
///
/// 1. If the new mode still sends (`send-receive`/`send-only`) and the
///    link isn't paused, re-broadcasts the link's whole current index —
///    the same "re-send everything, already-caught-up peers just see
///    `VvOrdering::Equal` and no-op" shape `resume_link` already uses,
///    so a link that just left `receive-only` (where local edits were
///    queued as receive-only-changed instead of sent) immediately pushes
///    its current state rather than waiting for the next unrelated local
///    edit.
/// 2. Clears whichever divergence set the *new* mode's gate can no longer
///    produce — `out_of_sync` if the new mode isn't `send-only`,
///    `receive_only_changed` if the new mode isn't `receive-only`. This
///    is not a silent content resolution (no file content or index
///    version is touched, matching the "no data loss" invariant): the
///    live per-batch mode lookup in `PeerSyncSession::reconcile_files`/
///    the check in `announce_local_change` above mean the paths that were
///    gated are, from this call onward, handled by ordinary
///    (un-gated) reconciliation the next time either side has something
///    to say about them — these bookkeeping rows would otherwise become
///    permanently stale markers for a mode that no longer applies.
pub async fn set_link_mode_and_reconcile(
    state: &DaemonState,
    local_path: &str,
    mode: LinkMode,
) -> Result<(), yadorilink_sync_core::SyncError> {
    state.sync_state.set_link_mode(local_path, mode)?;
    let Some(link) =
        state.sync_state.list_links()?.into_iter().find(|l| l.local_path == local_path)
    else {
        return Ok(());
    };

    if !link.paused && mode != LinkMode::ReceiveOnly {
        let records = state.sync_state.list_files(&link.group_id)?;
        state.broadcast_change(&link.group_id, records).await;
    }

    if mode != LinkMode::SendOnly {
        for path in state.sync_state.list_out_of_sync(&link.group_id)? {
            state.sync_state.clear_out_of_sync(&link.group_id, &path)?;
        }
    }
    if mode != LinkMode::ReceiveOnly {
        for path in state.sync_state.list_receive_only_changed(&link.group_id)? {
            state.sync_state.clear_receive_only_changed(&link.group_id, &path)?;
        }
    }
    Ok(())
}

/// add-folder-direction-modes task 3.1: `override` (send-only only) — the
/// explicit action design.md describes as "broadcast the local records for
/// the out-of-sync paths through the normal local-change path, clearing
/// the out-of-sync set. Local wins." Unlike `set_link_mode_and_reconcile`
/// above, this *does* resolve content divergence — deliberately, since the
/// user explicitly asked for it. Returns the number of paths reconciled.
///
/// Rejected (not silently no-op) when the link isn't `send-only`, or is
/// paused — pause "trumps everything regardless of mode" (design.md), so
/// broadcasting here would be a silent no-op while still clearing the
/// out-of-sync set, falsely reporting the divergence as resolved when the
/// peer never actually received anything.
pub async fn override_link(
    state: &DaemonState,
    local_path: &str,
) -> Result<u64, yadorilink_sync_core::SyncError> {
    let link = state
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.local_path == local_path)
        .ok_or_else(|| yadorilink_sync_core::SyncError::NotFound(format!("link {local_path}")))?;
    if link.mode != LinkMode::SendOnly {
        return Err(yadorilink_sync_core::SyncError::InvalidLinkMode(format!(
            "override is only valid on a send-only link; {local_path} is currently {}",
            link.mode.as_db_str()
        )));
    }
    if link.paused {
        return Err(yadorilink_sync_core::SyncError::InvalidLinkMode(format!(
            "cannot override {local_path}: link is paused (resume it first)"
        )));
    }

    let paths = state.sync_state.list_out_of_sync(&link.group_id)?;
    let mut records = Vec::with_capacity(paths.len());
    for path in &paths {
        if let Some(record) = state.sync_state.get_file(&link.group_id, path)? {
            records.push(record);
        }
    }
    state.broadcast_change(&link.group_id, records).await;
    for path in &paths {
        state.sync_state.clear_out_of_sync(&link.group_id, path)?;
    }
    Ok(paths.len() as u64)
}

/// add-folder-direction-modes task 3.2: `revert` (receive-only only) — the
/// explicit action design.md describes as "discard the un-sent local
/// changes for the locally-changed paths and re-pull the peer-authoritative
/// state, clearing the receive-only-changed set. Peer wins."
///
/// **Judgment call, documented rather than papered over**: this crate's
/// peer-sync wire protocol (`yadorilink-ipc-proto`'s `sync.proto`) is
/// push-only — a peer sends a full index once per connection
/// (`PeerSyncSession::run`) and an `IndexUpdate` whenever its own state
/// changes; there is no "give me your current record for this path"
/// request message, and per proposal.md's explicit non-goals this change
/// must not touch "how bytes move" or add new wire mechanics. So "re-pull
/// the peer-authoritative state" cannot mean a synchronous fetch here.
/// Instead, this **discards this device's local causal claim** for each
/// locally-changed path by resetting its version vector to empty
/// (`VersionVector::new()`) — since `VersionVector::compare` reads an empty
/// vector as strictly behind any vector with a positive counter, the very
/// next index this device receives for that path (the peer's next
/// reconnect, which already re-sends a full index unconditionally, or its
/// next local edit) is adopted through the completely ordinary
/// `VvOrdering::Before` path — the *same* already-existing, unmodified
/// apply/materialize machinery every other incoming update uses, "peer
/// wins" with no new conflict copy. This reuses 100% existing propagation;
/// it does not force an immediate network round trip with an offline or
/// idle peer. Returns the number of paths reverted.
pub async fn revert_link(
    state: &DaemonState,
    local_path: &str,
) -> Result<u64, yadorilink_sync_core::SyncError> {
    let link = state
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.local_path == local_path)
        .ok_or_else(|| yadorilink_sync_core::SyncError::NotFound(format!("link {local_path}")))?;
    if link.mode != LinkMode::ReceiveOnly {
        return Err(yadorilink_sync_core::SyncError::InvalidLinkMode(format!(
            "revert is only valid on a receive-only link; {local_path} is currently {}",
            link.mode.as_db_str()
        )));
    }
    if link.paused {
        return Err(yadorilink_sync_core::SyncError::InvalidLinkMode(format!(
            "cannot revert {local_path}: link is paused (resume it first)"
        )));
    }

    let paths = state.sync_state.list_receive_only_changed(&link.group_id)?;
    for path in &paths {
        if let Some(record) = state.sync_state.get_file(&link.group_id, path)? {
            let voided = yadorilink_sync_core::types::FileRecord {
                version: yadorilink_sync_core::version_vector::VersionVector::new(),
                ..record
            };
            state.sync_state.upsert_file(&link.group_id, &voided)?;
        }
        state.sync_state.clear_receive_only_changed(&link.group_id, path)?;
    }
    Ok(paths.len() as u64)
}

/// Broadcasts a batch of locally-indexed changes to connected peers as one
/// wire message per peer (unless the link is paused — task 6.8; batch
/// broadcast is batch-sync-optimizations design D5), and pushes one
/// shell-extension status update per file regardless (task 8.5 — `StatusPush`
/// stays per-file even when the peer-facing broadcast batches, design D5's
/// explicit call-out: UI feedback and peer wire efficiency are different
/// concerns). Shared by both the initial scan and the live watch loop.
/// A no-op for an empty batch.
///
/// add-folder-direction-modes task 2.2/2.3: a `receive-only` link never
/// propagates a local modification (design.md's propagation-gating table)
/// — gated here, alongside the pre-existing `paused` gate, since this is
/// the one place every local change (watcher-driven and initial-scan
/// alike) funnels through on its way to `DaemonState::broadcast_change`.
/// Gated identically to a local tombstone (task 2.3: `records` carries
/// deletions the same way it carries content — nothing here branches on
/// `record.deleted`, so a gated local deletion is recorded as
/// receive-only-changed exactly like any other gated edit). The file is
/// still indexed either way (`LocalChangeProcessor` already did that
/// before this function ever runs — task 6.8's "queued backlog" applies to
/// mode-gating too, not just pause), so no data is lost, only marked
/// diverged until an explicit `revert` (or `set-mode` back to
/// `send-receive`/`send-only`) — see `revert_link`.
async fn announce_local_change(
    state: &Arc<DaemonState>,
    local_path: &str,
    group_id: &str,
    records: Vec<FileRecord>,
) {
    if records.is_empty() {
        return;
    }

    let link = state
        .sync_state
        .list_links()
        .ok()
        .and_then(|links| links.into_iter().find(|l| l.local_path == local_path));
    let paused = link.as_ref().map(|l| l.paused).unwrap_or(false);
    let mode = link.as_ref().map(|l| l.mode).unwrap_or(LinkMode::SendReceive);

    // Local changes are always indexed (task 6.8's "queued backlog");
    // only *propagation* is gated — on pause (unchanged) and, per
    // add-folder-direction-modes, on receive-only mode.
    if !paused {
        if mode == LinkMode::ReceiveOnly {
            let recorded_at = now_unix_nanos();
            for record in &records {
                if let Err(e) = state.sync_state.record_receive_only_changed(
                    group_id,
                    &record.path,
                    recorded_at,
                ) {
                    tracing::warn!(
                        error = %e,
                        path = %record.path,
                        group_id,
                        "failed to record a receive-only-changed item"
                    );
                }
            }
        } else {
            state.broadcast_change(group_id, records.clone()).await;
        }
    }

    for record in &records {
        let absolute_path = Path::new(local_path).join(&record.path).to_string_lossy().to_string();
        let shell_state = if record.deleted {
            ShellSyncState::Unspecified
        } else if record.path.contains("(conflicted copy") {
            ShellSyncState::Error
        } else {
            ShellSyncState::Synced
        };
        // A genuine local edit always has full content on disk already —
        // this path never produces a placeholder (that's
        // `PeerSyncSession::materialize`'s job, for records adopted
        // *from* a peer, not local ones).
        let materialization_state = if record.deleted {
            ShellMaterializationState::Unspecified
        } else {
            ShellMaterializationState::Hydrated
        };
        // No connected shell extension is not an error — the push channel
        // simply has no subscribers yet. Not this push's concern (it
        // reports a local file *content* change, not edit-presence) —
        // always empty here; the shell-IPC status *query* path resolves
        // this properly.
        let _ = state.status_push_tx.send(StatusPush {
            path: absolute_path,
            state: shell_state as i32,
            materialization_state: materialization_state as i32,
            open_elsewhere_device_id: String::new(),
        });
    }
}

/// Updates this device's own active-edit tracking and broadcasts the
/// presence signal to connected peers (task 9.3) — the mirror of
/// `announce_local_change`, for a `LocalChangeOutcome::PresenceChanged`
/// instead of a `FileChanged`. `path` is relative to the linked folder.
async fn announce_presence_change(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: String,
    editing: bool,
) {
    let key = (group_id.to_string(), path.clone());
    if editing {
        state
            .active_local_edits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key);
    } else {
        state
            .active_local_edits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
    }
    state.broadcast_presence(group_id, &path, editing).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;
    use yadorilink_sync_core::version_vector::VersionVector;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    fn sample_record(path: &str) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 10,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    /// batch-sync-optimizations task 2.3 / design D5: `StatusPush` stays
    /// one-per-file for the shell extension even when the peer-facing
    /// broadcast batches many files into a single wire message — these
    /// are different concerns (local UI feedback vs. peer wire
    /// efficiency), and only the latter should batch.
    #[tokio::test]
    async fn announce_local_change_pushes_one_status_update_per_file_even_when_batched() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        let mut push_rx = state.status_push_tx.subscribe();

        let records = vec![sample_record("a.jpg"), sample_record("b.jpg"), sample_record("c.jpg")];
        announce_local_change(&state, "/tmp/photos", "group-1", records).await;

        let mut seen_paths = std::collections::HashSet::new();
        for _ in 0..3 {
            let push = tokio::time::timeout(std::time::Duration::from_secs(1), push_rx.recv())
                .await
                .expect("expected a StatusPush")
                .unwrap();
            seen_paths.insert(push.path);
        }
        // Path::join (production's own construction, see
        // announce_local_change above) uses the OS's native separator --
        // `\` on Windows, `/` elsewhere -- so the expected set must too,
        // rather than hardcoding `/` and failing on every Windows run.
        assert_eq!(
            seen_paths,
            std::collections::HashSet::from(
                ["a.jpg", "b.jpg", "c.jpg"]
                    .map(|name| Path::new("/tmp/photos").join(name).to_string_lossy().to_string())
            )
        );
        // No fourth push — exactly one per file, not more.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
            .await
            .is_err());
    }

    /// add-folder-direction-modes task 2.2/5.1: a `receive-only` link never
    /// broadcasts a local change — `announce_local_change` must record it
    /// as receive-only-changed instead of calling `broadcast_change` (no
    /// connected peer sessions exist in this unit test, so any attempted
    /// send would be an unobservable no-op either way; what's actually
    /// verified is the divergence bookkeeping itself). The shell-extension
    /// `StatusPush` still fires — mode gates peer propagation only, not
    /// local UI feedback.
    #[tokio::test]
    async fn announce_local_change_on_receive_only_link_records_divergence_instead_of_broadcasting()
    {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::ReceiveOnly).unwrap();
        let mut push_rx = state.status_push_tx.subscribe();

        let records = vec![sample_record("a.jpg"), sample_record("b.jpg")];
        announce_local_change(&state, "/tmp/photos", "group-1", records).await;

        assert_eq!(state.sync_state.count_receive_only_changed("group-1").unwrap(), 2);
        assert_eq!(
            state.sync_state.list_receive_only_changed("group-1").unwrap(),
            vec!["a.jpg".to_string(), "b.jpg".to_string()]
        );

        // StatusPush is unaffected by mode gating.
        for _ in 0..2 {
            tokio::time::timeout(std::time::Duration::from_secs(1), push_rx.recv())
                .await
                .expect("expected a StatusPush")
                .unwrap();
        }
    }

    /// A `send-only` link's local changes are unaffected by
    /// add-folder-direction-modes — only the *incoming* direction is gated
    /// (in `yadorilink-sync-core::peer_session`, not here), so a send-only
    /// link's local edits keep broadcasting exactly like `send-receive`,
    /// and nothing is ever recorded as receive-only-changed for one.
    #[tokio::test]
    async fn announce_local_change_on_send_only_link_records_no_divergence() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();

        announce_local_change(&state, "/tmp/photos", "group-1", vec![sample_record("a.jpg")]).await;

        assert_eq!(state.sync_state.count_receive_only_changed("group-1").unwrap(), 0);
    }

    /// add-folder-direction-modes task 3.1: `override` on a valid,
    /// unpaused send-only link clears every out-of-sync path and reports
    /// how many it reconciled. No peer session is connected in this unit
    /// test (`broadcast_change` fans out over `state.sessions`, empty
    /// here), so this specifically verifies the local-side bookkeeping —
    /// the actual peer delivery is exercised by
    /// `yadorilink-sync-core`'s own `PeerSyncSession::send_index_update`
    /// tests and this crate's two-device integration tests.
    #[tokio::test]
    async fn override_link_clears_out_of_sync_and_reports_the_count() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        state.sync_state.upsert_file("group-1", &sample_record("b.jpg")).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.jpg", 100).unwrap();
        state.sync_state.record_out_of_sync("group-1", "b.jpg", 200).unwrap();

        let reconciled = override_link(&state, "/tmp/photos").await.unwrap();

        assert_eq!(reconciled, 2);
        assert_eq!(state.sync_state.count_out_of_sync("group-1").unwrap(), 0);
    }

    #[tokio::test]
    async fn override_link_rejects_a_link_that_is_not_send_only() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        // Default mode is send-receive.
        let err = override_link(&state, "/tmp/photos").await.unwrap_err();
        assert!(matches!(err, yadorilink_sync_core::SyncError::InvalidLinkMode(_)));
    }

    #[tokio::test]
    async fn override_link_rejects_a_paused_link() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.set_paused("/tmp/photos", true).unwrap();

        let err = override_link(&state, "/tmp/photos").await.unwrap_err();
        assert!(matches!(err, yadorilink_sync_core::SyncError::InvalidLinkMode(_)));
    }

    /// add-folder-direction-modes task 3.2: `revert` on a valid, unpaused
    /// receive-only link voids the local causal claim (empty version
    /// vector) for every locally-changed path and clears the
    /// receive-only-changed set.
    #[tokio::test]
    async fn revert_link_voids_local_version_and_clears_receive_only_changed() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::ReceiveOnly).unwrap();
        state.sync_state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        state.sync_state.record_receive_only_changed("group-1", "a.jpg", 100).unwrap();

        let reverted = revert_link(&state, "/tmp/photos").await.unwrap();

        assert_eq!(reverted, 1);
        assert_eq!(state.sync_state.count_receive_only_changed("group-1").unwrap(), 0);
        let record = state.sync_state.get_file("group-1", "a.jpg").unwrap().unwrap();
        assert_eq!(
            record.version.compare(&sample_record("a.jpg").version),
            yadorilink_sync_core::version_vector::VvOrdering::Before,
            "a voided version must read as strictly behind any peer version with a positive \
             counter, so the next incoming update adopts it as VvOrdering::Before (peer wins)"
        );
    }

    #[tokio::test]
    async fn revert_link_rejects_a_link_that_is_not_receive_only() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        let err = revert_link(&state, "/tmp/photos").await.unwrap_err();
        assert!(matches!(err, yadorilink_sync_core::SyncError::InvalidLinkMode(_)));
    }

    #[tokio::test]
    async fn revert_link_rejects_a_paused_link() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::ReceiveOnly).unwrap();
        state.sync_state.set_paused("/tmp/photos", true).unwrap();
        let err = revert_link(&state, "/tmp/photos").await.unwrap_err();
        assert!(matches!(err, yadorilink_sync_core::SyncError::InvalidLinkMode(_)));
    }

    /// add-folder-direction-modes task 4.1: leaving `send-only` clears any
    /// out-of-sync bookkeeping (no longer producible under the new mode);
    /// leaving `receive-only` clears receive-only-changed the same way.
    /// Switching mode while staying within the same divergence-producing
    /// mode (not exercised here — there is no such transition, each mode
    /// is a single state) is covered by the sibling tests below not
    /// clearing the *other* set.
    #[tokio::test]
    async fn set_link_mode_and_reconcile_clears_divergence_no_longer_producible_under_the_new_mode()
    {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.jpg", 100).unwrap();

        set_link_mode_and_reconcile(&state, "/tmp/photos", LinkMode::SendReceive).await.unwrap();

        assert_eq!(state.sync_state.list_links().unwrap()[0].mode, LinkMode::SendReceive);
        assert_eq!(
            state.sync_state.count_out_of_sync("group-1").unwrap(),
            0,
            "out-of-sync bookkeeping from the old send-only mode must not survive the switch \
             away from it"
        );
    }

    #[tokio::test]
    async fn set_link_mode_and_reconcile_leaves_out_of_sync_untouched_when_staying_send_only() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.set_link_mode("/tmp/photos", LinkMode::SendOnly).unwrap();
        state.sync_state.record_out_of_sync("group-1", "a.jpg", 100).unwrap();

        set_link_mode_and_reconcile(&state, "/tmp/photos", LinkMode::SendOnly).await.unwrap();

        assert_eq!(state.sync_state.count_out_of_sync("group-1").unwrap(), 1);
    }

    /// An empty batch must not push anything or attempt to broadcast.
    #[tokio::test]
    async fn announce_local_change_is_a_no_op_for_an_empty_batch() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        let mut push_rx = state.status_push_tx.subscribe();

        announce_local_change(&state, "/tmp/photos", "group-1", vec![]).await;

        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
            .await
            .is_err());
    }

    /// add-file-version-history task 2.4/2.5: the retention-expiry sweep
    /// actually removes an aged-out superseded version, respecting each
    /// link's own configured retention policy — a real, if minimal,
    /// end-to-end proof that `DaemonState::new`'s periodic call reaches
    /// `SyncState::expire_superseded_and_trashed_versions` correctly.
    #[tokio::test]
    async fn run_retention_expiry_sweep_removes_aged_out_versions_per_link_policy() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        // `max_age_days` deliberately non-zero (`0` disables that axis
        // entirely, per `RetentionPolicy`'s union-retain rule — a version
        // is retained if it's within *either* bound, so an unlimited age
        // axis alone would keep everything regardless of `max_versions`).
        // `sample_record`'s `mtime_unix_nanos: 0` (1970) is already far
        // older than any positive `max_age_days`, so the age axis is
        // exceeded too — both bounds must be exceeded for the union-retain
        // rule to actually expire anything.
        state
            .sync_state
            .set_retention_policy(
                "/tmp/photos",
                yadorilink_sync_core::index::RetentionPolicy { max_versions: 1, max_age_days: 1 },
            )
            .unwrap();

        // Two superseded versions plus the current one; only the single
        // most recent superseded version should survive a max_versions=1
        // policy.
        state
            .sync_state
            .upsert_file_with_origin("group-1", &sample_record("a.jpg"), "device-a")
            .unwrap();
        let mut v2 = sample_record("a.jpg");
        v2.size = 20;
        state.sync_state.upsert_file_with_origin("group-1", &v2, "device-a").unwrap();
        let mut v3 = sample_record("a.jpg");
        v3.size = 30;
        state.sync_state.upsert_file_with_origin("group-1", &v3, "device-a").unwrap();

        assert_eq!(state.sync_state.list_versions("group-1", "a.jpg").unwrap().len(), 3);

        run_retention_expiry_sweep(&state);

        let remaining = state.sync_state.list_versions("group-1", "a.jpg").unwrap();
        assert_eq!(
            remaining.len(),
            2,
            "current version plus the single most recent superseded one"
        );
    }

    /// A link with no superseded/trashed rows to sweep, or no links at
    /// all, is a harmless no-op — the sweep must never error out or panic
    /// on an empty/idle daemon.
    #[tokio::test]
    async fn run_retention_expiry_sweep_is_a_harmless_no_op_with_nothing_to_expire() {
        let state = test_state();
        run_retention_expiry_sweep(&state); // no links registered at all
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        run_retention_expiry_sweep(&state); // one link, only a current version
        assert_eq!(state.sync_state.list_versions("group-1", "a.jpg").unwrap().len(), 1);
    }
}
