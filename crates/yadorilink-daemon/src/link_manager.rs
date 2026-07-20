//! Starts/stops the background tasks that watch one linked folder
//! (watcher, chunking-and-indexing, broadcast to connected peers, and
//! shell-extension status push). Two tasks per link: a debounce
//! **accumulator** that only ever reads raw filesystem
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
use yadorilink_sync_core::root_identity::indexed_path_is_corroborated;
use yadorilink_sync_core::types::FileRecord;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, RealFolderWatchSource,
};
use yadorilink_sync_core::SyncError;

use crate::daemon_state::DaemonState;
use crate::error::DaemonError;

/// How often each link's
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

/// Lets `yadorilink_sync_core::peer_session::PeerSyncSession::
/// reconcile_one_file` force this specific link's debounce accumulator to
/// flush and index any pending, undispatched local change for one path
/// *before* a peer's write or tombstone for that same path is
/// compared/applied. Registered into `DaemonState::link_flush_handles`
/// (keyed by `local_path`, same as `link_tasks`) by `start_link_watch`
/// below, and removed by `stop_link_watch`; reached from a
/// `PeerSyncSession` via `PendingLocalChangeFlush for DaemonState`, whose
/// `group_id` it's given is resolved to a `local_path` via
/// `sync_state.list_links`.
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
/// trip to this link's debounce accumulator: this must never block a peer
/// message handler indefinitely if the accumulator task is somehow
/// stalled or backlogged. A single bounded wait, not a jittered
/// multi-attempt retry like `peer_session`'s `RECONCILE_RETRY_*`: there's
/// nothing transient to retry against here (either the accumulator
/// answers almost instantly, since it's just a `HashMap` lookup/removal,
/// or something is genuinely wrong with it), and retrying an
/// already-timed-out request would only compound the delay on this
/// critical path.
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
        // Scope widened during scenario 5's investigation: a `None` reply
        // here means the debounce accumulator has nothing queued for this
        // path, but that no longer means there is nothing local to
        // protect — a brand-new file
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
        let _write_activity = state.begin_write_activity();
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
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a pending local change ahead of a racing peer update"
            ),
        }
    }

    /// Like `flush_pending_local_change` above, but looks for a *different*
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
    /// artifact-free silent overwrite already closed for the
    /// exact-same-path case.
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
        let _write_activity = state.begin_write_activity();
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
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a case-fold sibling's pending local change ahead of a \
                 racing peer update"
            ),
        }
    }

    /// Drains and indexes
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
        let _write_activity = state.begin_write_activity();
        match self
            .processor
            .process_flush(group_id, &self.root, DebounceFlush::Paths(drained))
            .await
        {
            Ok(outcome) => {
                announce_local_change(&state, &self.local_path, group_id, outcome.records).await;
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush this link's pending local changes ahead of its resume \
                 broadcast"
            ),
        }
    }

    /// The debounce-accumulator flush above (`FlushPathRequest`) only ever
    /// recovers a local change that some path has already been turned
    /// into an `FsChangeEvent` and queued for — i.e. one the watcher (or
    /// `watcher::reconcile_new_directory_subtree`'s own discovery
    /// synthesis) has already observed. It cannot help with a path that
    /// is still entirely undiscovered: `notify`'s `watch` call for a
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
    /// file_inside`).
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
    ///  when a local file exists but hasn't changed.
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
    /// `path` doesn't exist on disk needs no such guard: ``
    /// (`local_change.rs`'s own comment on its `Removed` branch) already
    /// treats "no index entry for this path" as nothing to protect, and a
    /// file created-then-deleted before ever being discovered/indexed is
    /// exactly that case — net zero, nothing to propagate.
    async fn capture_undiscovered_local_change(&self, group_id: &str, path: &Path) {
        if path.symlink_metadata().is_err() {
            return; // nothing on disk at this path — nothing to protect
        }
        let Some(state) = self.state.upgrade() else { return };
        let _write_activity = state.begin_write_activity();
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

/// Builds a linked folder's local-change processor, wiring in change-history
/// (change-DAG) emission when this device has both a registered identity and
/// a signing key.
///
/// Emission is enabled only *after* the group's existing on-disk index has
/// been established as the root of its change history
/// (`ensure_initial_import`). That ordering is required: the import must
/// precede the first live mutation or any admitted peer change so history
/// starts at the observed present rather than fabricating a past. Both the
/// import and the processor are byte-identical to the pre-change-history
/// behavior when no emitter is wired (an unregistered device, or one whose
/// signing key can't be loaded), so this never changes behavior without an
/// identity to sign under.
fn build_change_processor(
    state: &Arc<DaemonState>,
    group_id: &str,
) -> Result<LocalChangeProcessor, SyncError> {
    let processor = LocalChangeProcessor::new(
        state.sync_state.clone(),
        state.block_store.clone(),
        state.device_id.clone(),
    );
    // Emission needs both a stable device id to attribute changes to and a
    // signing key wired at startup. A device with no identity, or a code path
    // (tests) that never wired a signing key, leaves emission off — behavior
    // byte-identical to before change history existed.
    if state.device_id.is_empty() {
        return Ok(processor);
    }
    Ok(processor.with_change_emitter(ensure_initial_change_history(state, group_id)?))
}

fn ensure_initial_change_history(
    state: &Arc<DaemonState>,
    group_id: &str,
) -> Result<Arc<yadorilink_sync_core::dag_store::ChangeEmitter>, SyncError> {
    // A *registered* device (non-empty `device_id`, checked by the caller)
    // with no signing key wired is a fail-closed condition, not a legitimate
    // no-emitter path: without a `ChangeEmitter`, local edits get indexed but
    // never recorded as DAG `Change`s, so this device's own edits would never
    // reach a peer through change-history sync at all -- silent data loss
    // from the group's perspective, not merely "emission off." Only a
    // genuinely *unregistered* device (empty `device_id`, handled entirely by
    // `build_change_processor`'s own early return above) is exempt.
    let signing_key = state.device_signing_key().ok_or_else(|| {
        SyncError::CorruptState(format!(
            "registered device {} has no signing key; refusing index-only sync",
            state.device_id
        ))
    })?;
    let emitter = Arc::new(yadorilink_sync_core::dag_store::ChangeEmitter::new(
        state.device_id.clone(),
        signing_key,
    ));
    // Idempotent, so it is safe both before and after the asynchronous initial
    // disk scan. The post-scan call matters for a newly linked, populated
    // folder: the first call sees an empty index, while the batched scan writes
    // index rows without going through the per-change DAG emitter.
    match yadorilink_sync_core::dag_import::ensure_initial_import(
        &state.sync_state,
        group_id,
        &emitter,
    ) {
        Ok(outcome) => {
            tracing::debug!(?outcome, group_id, "change-history initial import checked");
            Ok(emitter)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                group_id,
                "change-history initial import failed; emission disabled for this folder"
            );
            Err(e)
        }
    }
}

/// Resolves a group's startup-readiness barrier exactly once, fail-*closed*.
/// Mirrors `HydrationStateGuard`: an explicit success call (`mark_ready`)
/// publishes the good state, while `Drop` on the unfinished path — an early
/// return, a panic that unwinds the executor, or a task abort — transitions the
/// group to `Failed` instead of Ready. A startup that does not complete
/// therefore DEFERS (fail-closed) peer apply for the group rather than opening
/// the gate over a half-built index, where an incoming peer change could
/// overwrite un-indexed local content or skip an offline edit the dirty-journal
/// redrive never got to re-apply. Recovery is a subsequent `begin_group_startup`
/// (relink / watcher restart / the executor's own bounded retry), which
/// supersedes the failure and re-runs startup.
///
/// The guard carries the `StartupGeneration` it owns, and every transition
/// routes through the generation-checked `SyncState` methods, so an aborted old
/// executor's late `Drop` can neither open nor fail a newer generation's gate.
struct GroupStartupReadyGuard {
    state: Arc<DaemonState>,
    group_id: String,
    generation: yadorilink_sync_core::index::StartupGeneration,
    resolved: bool,
}

impl GroupStartupReadyGuard {
    fn new(
        state: Arc<DaemonState>,
        group_id: String,
        generation: yadorilink_sync_core::index::StartupGeneration,
    ) -> Self {
        Self { state, group_id, generation, resolved: false }
    }

    /// Success path: publish `Ready` for this generation and defuse the
    /// fail-closed `Drop`.
    fn mark_ready(&mut self) {
        self.state.sync_state.mark_group_ready(&self.group_id, self.generation);
        self.resolved = true;
    }

    /// Explicit failure path — a caught scan/redrive error, or a `JoinError`
    /// from a scan task that panicked inside `spawn_blocking` (which does NOT
    /// unwind this future). Publishes `Failed` for this generation and defuses
    /// the `Drop`.
    fn mark_failed(&mut self, reason: impl Into<String>) {
        self.state.sync_state.mark_group_failed(&self.group_id, self.generation, reason);
        self.resolved = true;
    }

    /// Re-arm for a retry: adopt the fresh generation returned by a new
    /// `begin_group_startup` so a subsequent `mark_*`/`Drop` targets the
    /// generation actually in flight.
    fn begin_generation(&mut self, generation: yadorilink_sync_core::index::StartupGeneration) {
        self.generation = generation;
        self.resolved = false;
    }
}

impl Drop for GroupStartupReadyGuard {
    fn drop(&mut self) {
        if !self.resolved {
            // Unwound before completing (panic / early return / task abort):
            // fail-closed. The generation check inside `mark_group_failed` makes
            // this a no-op when a newer startup has already superseded us.
            self.state.sync_state.mark_group_failed(
                &self.group_id,
                self.generation,
                "startup task did not complete (panicked, aborted, or returned early)",
            );
        }
    }
}

pub fn start_link_watch(
    state: Arc<DaemonState>,
    local_path: String,
    group_id: String,
) -> Result<(), DaemonError> {
    start_link_watch_inner(state, local_path, group_id, Arc::new(RealFolderWatchSource), true)
}

/// Same as `start_link_watch`, but takes
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
    start_link_watch_inner(state, local_path, group_id, watcher_source, true)
}

/// Same as `start_link_watch`, but lets the daemon's startup path suppress
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
pub fn start_link_watch_gating_tombstones(
    state: Arc<DaemonState>,
    local_path: String,
    group_id: String,
    emit_tombstones: bool,
) -> Result<(), DaemonError> {
    start_link_watch_inner(
        state,
        local_path,
        group_id,
        Arc::new(RealFolderWatchSource),
        emit_tombstones,
    )
}

fn start_link_watch_inner(
    state: Arc<DaemonState>,
    local_path: String,
    group_id: String,
    watcher_source: Arc<dyn FolderWatchSource>,
    emit_tombstones: bool,
) -> Result<(), DaemonError> {
    // Close this group's startup barrier and arm its fail-closed guard FIRST,
    // before any fallible step below. `app::run` calls this for every existing
    // link *before* it spawns the peer orchestrator, so a peer change arriving
    // later observes the barrier closed and waits (in its own apply path) until
    // the startup reconciliation has published its results, instead of racing
    // the scan's stale-snapshot batch commit. Per-group: this only gates this
    // group's peer apply, never an unrelated group's.
    //
    // The ordering is load-bearing, not stylistic. Every `?` from here on drops
    // the guard and publishes `Failed` for this generation. Returning early with
    // NO gate registered would instead leave the group *absent* from the
    // registry, and an absent gate reads as Ready (`wait_group_ready`) — so a
    // failed watcher bind (OS watch limit, unmounted root, permissions) would
    // admit peer changes into a folder this boot never scanned and let them
    // overwrite un-indexed local content. Do not add a fallible step above this
    // pair; add it below, where the guard already covers it.
    let startup_generation = state.sync_state.begin_group_startup(&group_id);
    let startup_ready_guard =
        GroupStartupReadyGuard::new(state.clone(), group_id.clone(), startup_generation);

    // Below the guard-arming pair above, per that block's own rule: this `?`
    // drops the guard and publishes `Failed` for this group's generation, which
    // is exactly the intended outcome -- the group refuses to sync, loudly,
    // while every other group on this device carries on.
    //
    // Checked here, up front, rather than left to the scan inside the spawned
    // executor below: this refusal is deterministic, and the executor's failure
    // disposition RETRIES to `STARTUP_MAX_ATTEMPTS`, which would turn one
    // actionable error into N identical log lines that no retry can fix.
    state.sync_state.ensure_unambiguous_group(&group_id)?;

    // The additive-scan window, read HERE rather than at the caller, and ANDed
    // with whatever the caller already decided.
    //
    // A recovery out of the two-live-roots state arms this flag on the surviving
    // link: the folder that was unlinked leaves its rows behind in this group's
    // index (`DELETE FROM files` is only ever keyed by path), and the scan below
    // is root-scoped and authoritative, so without this it reads every one of
    // them as deleted and tombstones them to every device -- the remedy
    // destroying the files it was meant to save.
    //
    // This USED to live in `app::run`, which made it a rule every caller had to
    // remember and only one of them did: `start_link_watch` and
    // `start_link_watch_with_source` both hardcode `emit_tombstones = true`, so
    // the `link` control-socket handler (which starts a watch on a freshly
    // linked folder) silently ignored the flag entirely. That is the same
    // "several independent lookups, each failing open on its own" shape
    // `SyncState::link_gate_for_group` exists to refuse: any single one failing
    // open is sufficient for the loss, so the read has to be ONE seam every
    // entry point funnels through, not a discipline. Every `start_link_watch*`
    // variant reaches this line.
    //
    // A failure to READ the flag suppresses too: "I could not tell" must never
    // resolve to "deleting is fine".
    let suppress_after_recovery = match state.sync_state.suppress_tombstones_for_group(&group_id) {
        Ok(suppress) => suppress,
        Err(e) => {
            tracing::error!(
                group_id = %group_id,
                error = %e,
                "cannot tell whether this group's scan must be additive; suppressing its \
                 deletions for this run"
            );
            true
        }
    };
    let emit_tombstones = emit_tombstones && !suppress_after_recovery;

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
    let processor = Arc::new(build_change_processor(&state, &group_id)?);

    let root = PathBuf::from(&local_path);

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    // A small
    // channel is enough — a targeted flush request is a single in-flight
    // round trip per racing path, not a backlog like `flush_tx` above.
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    // Same sizing
    // rationale as `flush_request_tx` above — a single in-flight round
    // trip per resume, not a backlog.
    let (flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);

    let executor_state = state.clone();
    let executor_local_path = local_path.clone();
    let executor_group_id = group_id.clone();
    let executor_processor = processor.clone();
    let executor_root = root.clone();
    let executor_ignore_set = ignore_set.clone();
    // Withhold this boot's initial-scan tombstone emission when the startup
    // interrupted-materialization repair pass errored for this group (see
    // `start_link_watch_gating_tombstones`). Fail-closed: a crash-mid-materialize
    // whose repair could not disambiguate it this boot must not be tombstoned.
    let executor_emit_tombstones = emit_tombstones;
    let executor_handle = tokio::spawn(async move {
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
        //
        // Armed by `start_link_watch_inner` before its fallible setup and *moved*
        // in here, so the window between opening this group's startup generation
        // and taking ownership of it is not merely small but empty: there is no
        // path on which the generation exists without the guard covering it.
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
                let _write_activity = executor_state.begin_write_activity();
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
                    if let Ok(rows) = executor_state.sync_state.list_files(&executor_group_id) {
                        for row in rows.into_iter().filter(|row| !row.deleted) {
                            if matches!(
                                indexed_path_is_corroborated(
                                    executor_root.as_path(),
                                    &executor_group_id,
                                    &executor_state.sync_state,
                                    &row,
                                ),
                                Ok(true)
                            ) {
                                if let Err(error) = executor_state
                                    .sync_state
                                    .resolve_duplicate_recovery_path(&executor_group_id, &row.path)
                                {
                                    tracing::warn!(group_id = %executor_group_id, path = %row.path, error = %error, "could not persist duplicate-recovery path progress");
                                }
                            }
                        }
                    }
                    let recovery_complete = matches!(
                        executor_state.sync_state.duplicate_recovery_pending(&executor_group_id),
                        Ok(false)
                    );
                    if recovery_complete {
                        if let Err(e) = executor_state
                            .sync_state
                            .set_suppress_tombstones(&executor_local_path, false)
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
                            ensure_initial_change_history(&executor_state, &executor_group_id)
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
                            &executor_state,
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
                let _write_activity = executor_state.begin_write_activity();
                match executor_processor
                    .redrive_dirty_journal(&executor_group_id, &executor_root)
                    .await
                {
                    Ok(outcome) => {
                        if !outcome.records.is_empty() {
                            announce_local_change(
                                &executor_state,
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
                    let next_generation =
                        executor_state.sync_state.begin_group_startup(&executor_group_id);
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
            let _write_activity = executor_state.begin_write_activity();
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
                        &executor_state,
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

    // Registered
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

    // Periodic live repair
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
            // this walks the whole linked folder synchronously. And the
            // same deterministic-simulator exception — no blocking-thread
            // pool there, so the identical walk runs inline, wrapped in `Ok`
            // to preserve the `Result<_, JoinError>` shape the match expects.
            #[cfg(not(madsim))]
            let repair_result = tokio::task::spawn_blocking(move || {
                materialization::repair_interrupted_materializations(
                    &sync_state,
                    block_store.as_ref(),
                    &root,
                    &group_id,
                )
            })
            .await;
            #[cfg(madsim)]
            let repair_result = Ok::<_, tokio::task::JoinError>(
                materialization::repair_interrupted_materializations(
                    &sync_state,
                    block_store.as_ref(),
                    &root,
                    &group_id,
                ),
            );
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
/// (guarantee: `SyncState` itself is the backlog) but never
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
    let link = state
        .sync_state
        .list_links()?
        .into_iter()
        .find(|l| l.local_path == local_path)
        .ok_or_else(|| yadorilink_sync_core::SyncError::NotFound(format!("link {local_path}")))?;
    if link.orphaned {
        return Err(yadorilink_sync_core::SyncError::InvalidInput(format!(
            "cannot resume orphaned link {local_path}: its coordination-side authorization is gone"
        )));
    }
    state.sync_state.ensure_unambiguous_group(&link.group_id)?;
    state.sync_state.set_paused(local_path, false)?;
    let group_id = link.group_id;
    match state.sync_state.link_gate_for_group(&group_id)? {
        yadorilink_sync_core::index::LinkGate::Live { local_path: live_path, .. }
            if live_path == local_path => {}
        _ => {
            return Err(yadorilink_sync_core::SyncError::InvalidInput(format!(
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
        match state
            .sync_state
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
/// `resume_link`'s own broadcast re-emits `list_files`, and the next
/// sweep tick after resume runs normally for it.
///
/// Also skips an orphaned link — its coordination-side authorization is
/// permanently gone, so there is nothing left to sync it against. In
/// practice this link never has a `LinkFlushHandle` to begin with (its
/// watcher is stopped the moment `pending_enrollment::reconcile` marks it
/// orphaned, and never restarted), so the check below is defense in depth,
/// not the primary mechanism.
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
        if link.paused || link.orphaned {
            continue;
        }
        let handle = state
            .link_flush_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&link.local_path)
            .cloned();
        let Some(handle) = handle else { continue };
        let _write_activity = state.begin_write_activity();
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

/// Whether a locally-indexed change may propagate right now. The authoritative
/// group gate is deliberately fail-closed: no live link, pause, orphaning,
/// ambiguity, a path mismatch, or a database error all suppress broadcast.
fn link_should_propagate(state: &DaemonState, local_path: &str, group_id: &str) -> bool {
    match state.sync_state.link_gate_for_group(group_id) {
        Ok(yadorilink_sync_core::index::LinkGate::Live { local_path: live_path, .. })
            if live_path == local_path =>
        {
            true
        }
        Ok(_) => false,
        Err(e) => {
            tracing::warn!(
                error = %e,
                group_id,
                local_path,
                "cannot verify that this link is live and writable; suppressing local-change propagation"
            );
            false
        }
    }
}

/// Broadcasts a batch of locally-indexed changes to connected peers as one
/// wire message per peer (unless the link is paused; batch processing is
/// used), and pushes one
/// shell-extension status update per file regardless (`StatusPush`
/// stays per-file even when the peer-facing broadcast batches: UI feedback
/// and peer wire efficiency are different concerns). Shared by both the
/// initial scan and the live watch loop.
/// A no-op for an empty batch.
async fn announce_local_change(
    state: &Arc<DaemonState>,
    local_path: &str,
    group_id: &str,
    records: Vec<FileRecord>,
) {
    if records.is_empty() {
        return;
    }

    // Local changes are always indexed ("queued backlog"), but propagation
    // requires the group's single authoritative live link. Never turn a link
    // table read failure or a raced unlink into permission to broadcast.
    if link_should_propagate(state, local_path, group_id) {
        state.broadcast_change(group_id, records.clone()).await;
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
        // simply has no subscribers yet.
        let _ = state.status_push_tx.send(StatusPush {
            path: absolute_path,
            state: shell_state as i32,
            materialization_state: materialization_state as i32,
        });
    }
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
        let state = DaemonState::new("device-a".into(), sync_state, store);
        // A registered device with no signing key fails closed (see
        // `ensure_initial_change_history`'s doc comment) -- every test using
        // this shared harness needs one wired, matching `change_auth.rs`'s
        // and `rebootstrap_handler.rs`'s own `test_state()` helpers.
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        state
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

    /// Like `sample_record`, but with a size and single block hash that
    /// actually corroborate `content` on disk — `sample_record`'s placeholder
    /// size/empty blocks never match real bytes, so a test relying on
    /// `VerifiedRoot`/root-identity adoption corroborating a real file (not
    /// just referencing its path) needs this instead.
    fn record_matching_disk_content(path: &str, content: &[u8]) -> FileRecord {
        use sha2::{Digest, Sha256};
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            version,
            blocks: vec![yadorilink_sync_core::types::BlockInfo {
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
        ) -> Result<yadorilink_sync_core::watcher::FolderWatcher, yadorilink_sync_core::SyncError>
        {
            Err(yadorilink_sync_core::SyncError::Io(std::io::Error::other("watch limit reached")))
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

        let result = start_link_watch_with_source(
            state.clone(),
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
            state.sync_state.wait_group_ready("g"),
        )
        .await
        .expect("wait_group_ready must resolve, not park forever on a Starting gate");
        assert!(
            ready.is_err(),
            "a link whose watcher failed to bind must DEFER peer apply (Err(StartupFailed)), \
             never admit it as ready"
        );
    }

    /// A startup that unwinds/returns early before calling `mark_ready` (its
    /// guard drops while unresolved) must transition the group to `Failed`, so
    /// peer apply fail-closes — it must NOT be released as ready over the
    /// half-built index. This is the core of the fail-open fix: a startup panic
    /// can no longer open the gate.
    #[tokio::test]
    async fn startup_panic_must_not_release_peer_apply_as_ready() {
        let state = test_state();
        let generation = state.sync_state.begin_group_startup("g");
        // Model a startup that panics / returns early before `mark_ready`: the
        // guard is dropped while still unresolved.
        {
            let _guard = GroupStartupReadyGuard::new(state.clone(), "g".to_string(), generation);
        }
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state.sync_state.wait_group_ready("g"),
        )
        .await
        .expect("wait must resolve, not hang");
        assert!(
            result.is_err(),
            "a startup that dropped its guard without completing must fail-close peer apply, \
             never open the gate as ready over a half-built index"
        );
    }

    /// Aborting the startup task (as `stop_link_watch` does with
    /// `handle.abort()`) drops its guard mid-startup, which must transition the
    /// group to `Failed` (fail-closed) rather than leaving it wedged in
    /// `Starting` or opening it as ready.
    #[tokio::test]
    async fn startup_task_abort_transitions_group_to_failed() {
        let state = test_state();
        let generation = state.sync_state.begin_group_startup("g");

        let task_state = state.clone();
        let handle = tokio::spawn(async move {
            let _guard = GroupStartupReadyGuard::new(task_state, "g".to_string(), generation);
            // Startup is "in progress": hold the guard across an await that
            // parks until the task is aborted.
            std::future::pending::<()>().await;
        });

        // Let the task reach the park point so its guard is actually constructed
        // and held across the await, then abort mid-startup.
        tokio::task::yield_now().await;
        handle.abort();
        let _ = handle.await;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            state.sync_state.wait_group_ready("g"),
        )
        .await
        .expect("wait must resolve, not hang");
        assert!(
            result.is_err(),
            "aborting the startup task must transition the group to Failed (fail-closed), \
             not leave it wedged or open it as ready"
        );
    }

    /// `StatusPush` stays
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

    /// Propagation permission comes from the authoritative group gate. Missing,
    /// paused and orphaned links all fail closed; only the exact live path passes.
    #[tokio::test]
    async fn link_should_propagate_is_fail_closed() {
        let state = test_state();
        let local_path = "/tmp/photos";
        let group_id = "group-1";

        assert!(
            !link_should_propagate(&state, local_path, group_id),
            "no live link must not be interpreted as permission to broadcast"
        );
        state.sync_state.add_link(local_path, group_id).unwrap();
        assert!(link_should_propagate(&state, local_path, group_id));
        assert!(
            !link_should_propagate(&state, "/tmp/some-other-root", group_id),
            "a stale watcher for a different path must not broadcast for the group"
        );
        state.sync_state.set_paused(local_path, true).unwrap();
        assert!(!link_should_propagate(&state, local_path, group_id));
        state.sync_state.set_paused(local_path, false).unwrap();
        state.sync_state.mark_link_orphaned(local_path).unwrap();
        assert!(!link_should_propagate(&state, local_path, group_id));
    }

    #[tokio::test]
    async fn resume_refuses_an_orphaned_link() {
        let state = test_state();
        let local_path = "/tmp/photos";
        state.sync_state.add_link(local_path, "group-1").unwrap();
        state.sync_state.mark_link_orphaned(local_path).unwrap();

        let err = resume_link(&state, local_path)
            .await
            .expect_err("an orphaned link must never be re-enabled by Resume");
        assert!(err.to_string().contains("orphaned"), "got {err}");
    }

    /// Marking a link orphaned never touches its on-disk files — only a
    /// local bookkeeping flag flips. The folder and its contents must be
    /// exactly as they were, byte for byte, after the link transitions.
    #[tokio::test]
    async fn orphaning_a_link_leaves_its_on_disk_files_untouched() {
        let state = test_state();
        let folder = tempfile::tempdir().unwrap();
        let file_path = folder.path().join("keepsake.txt");
        std::fs::write(&file_path, b"never delete me").unwrap();
        let local_path = folder.path().to_string_lossy().to_string();
        state.sync_state.add_link(&local_path, "group-1").unwrap();

        state.sync_state.mark_link_orphaned(&local_path).unwrap();

        assert_eq!(std::fs::read(&file_path).unwrap(), b"never delete me");
        assert!(state.sync_state.list_links().unwrap().iter().any(|l| l.orphaned));

        // And sync propagation for this now-orphaned link is suppressed,
        // the same guarantee `link_should_propagate_excludes_paused_and_
        // orphaned` proves in isolation -- exercised here end to end
        // through `announce_local_change` against the real orphaned row.
        let mut push_rx = state.status_push_tx.subscribe();
        announce_local_change(&state, &local_path, "group-1", vec![sample_record("new.txt")]).await;
        // The per-file shell-status push still fires (local indexing UI
        // feedback is unconditional); only peer propagation is gated, which
        // has no directly observable effect here with zero connected
        // peers. This call completing without panicking, combined with the
        // isolated gate test above, is the coverage for that path.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
            .await
            .is_ok());
    }

    /// The retention-expiry sweep actually removes aged-out superseded
    /// versions under the fixed built-in retention policy — a real, if
    /// minimal, end-to-end proof that `DaemonState::new`'s periodic call
    /// reaches `SyncState::expire_superseded_and_trashed_versions` correctly.
    #[tokio::test]
    async fn run_retention_expiry_sweep_removes_aged_out_versions_under_the_fixed_policy() {
        let state = test_state();
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();

        // Thirteen versions: twelve become superseded, one is current.
        // `sample_record`'s `mtime_unix_nanos: 0` (1970) is far older than
        // the built-in 30-day age bound, so every superseded row is beyond
        // the age axis; the built-in 10-version count bound then keeps only
        // the ten most recent superseded rows, expiring the two oldest.
        for size in 1..=13u64 {
            let mut record = sample_record("a.jpg");
            record.size = size;
            state.sync_state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();
        }

        assert_eq!(state.sync_state.list_versions("group-1", "a.jpg").unwrap().len(), 13);

        run_retention_expiry_sweep(&state);

        let remaining = state.sync_state.list_versions("group-1", "a.jpg").unwrap();
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
        run_retention_expiry_sweep(&state); // no links registered at all
        state.sync_state.add_link("/tmp/photos", "group-1").unwrap();
        state.sync_state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        run_retention_expiry_sweep(&state); // one link, only a current version
        assert_eq!(state.sync_state.list_versions("group-1", "a.jpg").unwrap().len(), 1);
    }

    // --- The two-live-roots recovery, at the daemon seam ---------------------

    /// Starts a watch the way production does and waits for its initial scan to
    /// finish, so the assertion is about what the REAL startup path did rather
    /// than about a hand-simulated primitive.
    async fn start_watch_and_await_scan(state: &Arc<DaemonState>, root: &Path, group: &str) {
        start_link_watch_with_source(
            state.clone(),
            root.to_string_lossy().into_owned(),
            group.to_string(),
            Arc::new(RealFolderWatchSource),
        )
        .expect("the watch must start");
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            state.sync_state.wait_group_ready(group),
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

        state.sync_state.add_link(&root.path().to_string_lossy(), group).unwrap();
        // Unlike the other tests sharing `test_state()`, this one pre-seeds
        // the index with rows (below) before the watch starts, so
        // `ensure_initial_change_history` has real DAG history to establish
        // and genuinely calls into local-emission authorization -- which
        // `DaemonState::new`'s real provider withholds for a linked group
        // with no verified policy loaded (exactly the fail-closed behavior
        // this branch just restored). This test is about tombstone-
        // suppression/duplicate-recovery scan behavior, not policy
        // resolution, so bypass it the same way `index.rs`'s own tests do.
        state.sync_state.set_local_change_auth_provider(std::sync::Arc::new(|_group_id| {
            Ok(yadorilink_sync_core::change::ChangeAuth::PLACEHOLDER)
        }));
        // The survivor's own file, indexed and present: that is what corroborates
        // the root, so the root-identity check adopts rather than refusing it as
        // a possible bare mountpoint. Without it this test would never reach the
        // tombstone decision it is about. Must actually match the bytes just
        // written above — `sample_record`'s placeholder size/blocks would not
        // corroborate and `VerifiedRoot::open` below would refuse.
        state
            .sync_state
            .upsert_file(group, &record_matching_disk_content("in-a.txt", b"aaa"))
            .unwrap();
        yadorilink_sync_core::root_identity::VerifiedRoot::open(
            root.path(),
            group,
            &state.sync_state,
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
            .sync_state
            .upsert_file(group, &record_matching_disk_content("only-in-b.txt", b"bbb"))
            .unwrap();

        // Exactly what the unlink handler's recovery arms on the survivor:
        // both the additive-scan flag AND the durable set of paths that must
        // reappear before `duplicate_recovery_pending` will call it resolved
        // (see `control_socket::unlink`'s own pairing of these two calls).
        state.sync_state.arm_duplicate_recovery_paths(group).unwrap();
        state.sync_state.set_suppress_tombstones(&root.path().to_string_lossy(), true).unwrap();

        start_watch_and_await_scan(&state, root.path(), group).await;

        let departed = state.sync_state.get_file(group, "only-in-b.txt").unwrap().unwrap();
        assert!(
            !departed.deleted,
            "the survivor's first scan after a two-live-roots recovery must delete nothing -- \
             this path can still hydrate from a peer that holds it"
        );
        assert!(
            state.sync_state.suppress_tombstones_for_group(group).unwrap(),
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

        state.sync_state.add_link(&root.path().to_string_lossy(), group).unwrap();
        state.sync_state.set_suppress_tombstones(&root.path().to_string_lossy(), true).unwrap();

        start_watch_and_await_scan(&state, root.path(), group).await;

        assert!(
            !state.sync_state.suppress_tombstones_for_group(group).unwrap(),
            "one clean full scan must close the additive window, or ordinary delete propagation \
             is broken for this link forever"
        );
    }

    /// The per-group refusal at the daemon seam. `start_link_watch_inner` runs
    /// the scan that emits the tombstones, so an ambiguous group must never get
    /// a watcher at all -- and the refusal must be scoped to that group, since a
    /// per-database halt would brick the daemon for every folder the user has.
    #[tokio::test]
    async fn an_ambiguous_group_is_refused_a_watcher_while_healthy_groups_still_start() {
        let state = test_state();
        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let root_c = tempfile::tempdir().unwrap();

        state.sync_state.add_link(&root_a.path().to_string_lossy(), "group-1").unwrap();
        state
            .sync_state
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), "group-1")
            .unwrap();
        state.sync_state.add_link(&root_c.path().to_string_lossy(), "group-2").unwrap();

        let err = start_link_watch_with_source(
            state.clone(),
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
