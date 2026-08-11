//! Watcher-driven local-change capture for one link, admitted through its
//! `RootLease`. `LinkFlushHandle` (constructed here, held inside
//! `LinkRuntime`) and its four operation methods -- a peer session's
//! targeted flush, reached via `PendingLocalChangeFlush`, and this link's
//! resume-time flush-all -- are the "CaptureLocalChange" operation: each
//! admits its own `LinkOperation` from `self.root_lease` before calling
//! into `LocalChangeProcessor`, held for that call's whole duration.
//!
//! This module owns `LinkFlushHandle` end to end (struct, constructor, and
//! operation methods) so the daemon's own `LinkRuntimeController` -- which constructs a handle via
//! [`LinkFlushHandle::new`] alongside the watcher/debounce-accumulator
//! wiring that feeds it, and calls its `pub(crate)` operation methods --
//! never needs to see its fields. The daemon-wide lookup/trait impl that
//! reach a link's handle from a `group_id` (resolving through the daemon's
//! link table) live on the daemon-wide runtime state itself, not here --
//! this module only ever sees the narrow [`LinkRuntimeDependencies`]
//! bundle, never that wider type.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use yadorilink_filesystem_sync::debounce::{self, DebounceFlush};
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_ipc_proto::shellipc::{
    MaterializationState as ShellMaterializationState, StatusPush, SyncState as ShellSyncState,
};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_peer_session::peer_session::PendingLocalFlushOutcome;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_root_authority::root_commit::RootLease;

use crate::link_runtime::dependencies::LinkRuntimeDependencies;
use crate::replica_coordinator::ReplicaCoordinator;

/// Lets `yadorilink_peer_session::peer_session::PeerSyncSession::
/// reconcile_one_file` force this specific link's debounce accumulator to
/// flush and index any pending, undispatched local change for one path
/// *before* a peer's write or tombstone for that same path is
/// compared/applied. Held inside the `LinkRuntime` registered into the
/// daemon's link registry (keyed by `local_path`) by
/// the daemon's own `LinkRuntimeController::start`, and removed by `LinkRuntimeController::stop`;
/// reached from a `PeerSyncSession` via the daemon-wide runtime state's own
/// `PendingLocalChangeFlush` implementation, whose `group_id` it's given is
/// resolved to a `local_path` via `sync_state.list_links`.
///
/// Held with a `Weak<LinkRuntimeDependencies>` (not `Arc`): this handle is
/// itself reachable from the daemon-wide runtime state (through the link
/// registry), and `LinkRuntimeDependencies` itself reaches back to that
/// same state (via `LinkRuntimeHostPort`), so an `Arc` back-reference here
/// would be a permanent reference cycle -- the same shape of cycle a weak
/// (not strong) back-reference to the daemon-wide state here always had to
/// close.
pub struct LinkFlushHandle {
    deps: Weak<LinkRuntimeDependencies>,
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
    /// Gates every local mutation this handle can produce, and (via the
    /// same `Arc<LinkRuntime>` `LinkRuntimeController::stop` holds) is what makes its
    /// wait for this link's teardown genuine rather than best-effort. Owns
    /// the same `SyncRootLock` `LinkRuntime` itself holds a clone of -- see
    /// `RootLease`'s own doc.
    root_lease: Arc<RootLease>,
}

impl LinkFlushHandle {
    /// `root` is taken by value and canonicalized once here rather than by
    /// the caller: `canonical_root`'s own doc explains why the canonical
    /// form (not the caller's raw path) is what the debounce accumulator's
    /// keys actually match against.
    pub(crate) fn new(
        deps: &Arc<LinkRuntimeDependencies>,
        flush_request_tx: tokio::sync::mpsc::Sender<debounce::FlushPathRequest>,
        flush_all_request_tx: tokio::sync::mpsc::Sender<debounce::FlushAllRequest>,
        processor: Arc<LocalChangeProcessor>,
        root: PathBuf,
        local_path: String,
        root_lease: Arc<RootLease>,
    ) -> Self {
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        Self {
            deps: Arc::downgrade(deps),
            flush_request_tx,
            flush_all_request_tx,
            processor,
            root,
            canonical_root,
            local_path,
            root_lease,
        }
    }
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
    pub(crate) async fn flush_pending_local_change(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let path = self.canonical_root.join(rel_path);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        // Bounded like the reply wait below: this channel (capacity 4) is
        // shared by every concurrent peer message handler reconciling a
        // path against this link, and can back up under a duplicate-
        // delivery storm. An unbounded `.send().await` here would then park
        // the calling message handler -- and the peer-session slot it
        // holds -- indefinitely, with no log and no error, which is
        // exactly the failure this bound closes.
        let send_result = tokio::time::timeout(
            FORCE_FLUSH_REQUEST_TIMEOUT,
            self.flush_request_tx.send(debounce::FlushPathRequest {
                path: path.clone(),
                mode: debounce::FlushMode::ExactPath,
                reply: reply_tx,
            }),
        )
        .await;
        match send_result {
            Err(_) => {
                tracing::warn!(
                    group_id,
                    path = %path.display(),
                    "timed out enqueueing a targeted flush request to this link's debounce \
                     accumulator; deferring this reconciliation"
                );
                return PendingLocalFlushOutcome::RetryRequired;
            }
            Ok(Err(_)) => return PendingLocalFlushOutcome::Settled, // accumulator task is gone
            Ok(Ok(())) => {}
        }
        let found = match tokio::time::timeout(FORCE_FLUSH_REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(found)) => found,
            Ok(Err(_)) => None, // accumulator dropped the reply sender without answering
            Err(_) => {
                tracing::warn!(
                    group_id,
                    path = %path.display(),
                    "timed out waiting for this link's debounce accumulator to answer a targeted \
                     flush request; deferring this reconciliation"
                );
                return PendingLocalFlushOutcome::RetryRequired;
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
            return PendingLocalFlushOutcome::Settled;
        };
        tracing::info!(
            group_id,
            path = %path.display(),
            "forcing a pending local change to flush and index before a racing peer update for \
             the same path is applied"
        );
        let Some(deps) = self.deps.upgrade() else { return PendingLocalFlushOutcome::Settled };
        let Ok(_op) = self.root_lease.begin_operation() else {
            return PendingLocalFlushOutcome::Settled;
        };
        let _write_activity = deps.begin_write_activity();
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
                announce_local_change(&deps, &self.local_path, group_id, outcome.records).await;
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a pending local change ahead of a racing peer update"
            ),
        }
        PendingLocalFlushOutcome::Settled
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
    pub(crate) async fn flush_case_fold_sibling(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let path = self.canonical_root.join(rel_path);
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        // Bounded for the same reason as `flush_pending_local_change`'s
        // enqueue above -- see that call's comment.
        let send_result = tokio::time::timeout(
            FORCE_FLUSH_REQUEST_TIMEOUT,
            self.flush_request_tx.send(debounce::FlushPathRequest {
                path,
                mode: debounce::FlushMode::CaseFoldSibling,
                reply: reply_tx,
            }),
        )
        .await;
        match send_result {
            Err(_) => {
                tracing::warn!(
                    group_id,
                    rel_path,
                    "timed out enqueueing a case-fold sibling flush request to this link's \
                     debounce accumulator; deferring this reconciliation"
                );
                return PendingLocalFlushOutcome::RetryRequired;
            }
            Ok(Err(_)) => return PendingLocalFlushOutcome::Settled, // accumulator task is gone
            Ok(Ok(())) => {}
        }
        let found = match tokio::time::timeout(FORCE_FLUSH_REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(found)) => found,
            Ok(Err(_)) => None,
            Err(_) => {
                tracing::warn!(
                    group_id,
                    rel_path,
                    "timed out waiting for this link's debounce accumulator to answer a \
                     case-fold sibling flush request; deferring this reconciliation"
                );
                return PendingLocalFlushOutcome::RetryRequired;
            }
        };
        let Some((sibling_path, kind, observed_at)) = found else {
            return PendingLocalFlushOutcome::Settled;
        };
        tracing::info!(
            group_id,
            rel_path,
            sibling_path = %sibling_path.display(),
            "forcing a case-fold sibling's pending local change to flush and index before a \
             racing peer update for the colliding name is applied"
        );
        let Some(deps) = self.deps.upgrade() else { return PendingLocalFlushOutcome::Settled };
        let Ok(_op) = self.root_lease.begin_operation() else {
            return PendingLocalFlushOutcome::Settled;
        };
        let _write_activity = deps.begin_write_activity();
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
                announce_local_change(&deps, &self.local_path, group_id, outcome.records).await;
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush a case-fold sibling's pending local change ahead of a \
                 racing peer update"
            ),
        }
        PendingLocalFlushOutcome::Settled
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
    pub(crate) async fn flush_all_pending_local_changes(&self, group_id: &str) {
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
        let Some(deps) = self.deps.upgrade() else { return };
        let Ok(_op) = self.root_lease.begin_operation() else { return };
        let _write_activity = deps.begin_write_activity();
        match self
            .processor
            .process_flush(group_id, &self.root, DebounceFlush::Paths(drained))
            .await
        {
            Ok(outcome) => {
                announce_local_change(&deps, &self.local_path, group_id, outcome.records).await;
            }
            Err(e) => tracing::warn!(
                error = %e,
                group_id,
                "failed to force-flush this link's pending local changes ahead of its resume \
                 broadcast"
            ),
        }
    }

    /// The disk-reconcile backstop sweep's per-link operation (see
    /// the daemon's own `LinkRuntimeController::run_disk_reconcile_backstop_sweep`'s own doc for why
    /// it exists and why it is add-only): admits a `LinkOperation` from
    /// this link's `RootLease`, then runs the add-only disk-authoritative
    /// reconcile. `None` means the lease refused admission (this link is
    /// already stopping) -- the caller skips it and lets the next sweep
    /// tick cover it once its successor is up; `Some` carries the
    /// underlying reconcile result either way.
    pub(crate) fn reconcile_added_files_from_disk(
        &self,
        group_id: &str,
    ) -> Option<Result<Vec<FileRecord>, yadorilink_local_capture::LocalCaptureError>> {
        let _op = self.root_lease.begin_operation().ok()?;
        Some(self.processor.reconcile_added_files(group_id, &self.root))
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
        let Some(deps) = self.deps.upgrade() else { return };
        let Ok(_op) = self.root_lease.begin_operation() else { return };
        let _write_activity = deps.begin_write_activity();
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
                announce_local_change(&deps, &self.local_path, group_id, vec![record]).await;
            }
            // This call always synthesizes `FsChangeKind::CreatedOrModified`
            // (see this fn's own doc comment) — `FilesChanged` only ever
            // originates from the `Removed` branch, so unreachable here in
            // practice, but `LocalChangeOutcome` is matched exhaustively.
            Ok(LocalChangeOutcome::FilesChanged(records)) => {
                announce_local_change(&deps, &self.local_path, group_id, records).await;
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

    /// M1-3: routes a File-Provider-originated create/modify/delete
    /// notification (macOS `NSFileProviderReplicatedExtension`'s own
    /// `createItem`/`modifyItem`/`deleteItem`, relayed via `yadorilink-daemon`'s
    /// shell_ipc `LocalWriteRequest` handler) through the EXACT same
    /// `LocalChangeProcessor::process_event` path a live filesystem
    /// watcher's own `FsChangeEvent` would take -- no File-Provider-specific
    /// sync logic exists anywhere in the daemon; this is purely a second
    /// *signal source* for that one existing admission path.
    ///
    /// Unlike `capture_undiscovered_local_change` above (a defensive,
    /// `CreatedOrModified`-only fallback for a path racing a peer update),
    /// `kind` here is whatever the caller actually observed -- a `Removed`
    /// notification from a real, one-time OS delete callback is not a
    /// speculative synthesis, so none of that method's "don't
    /// double-tombstone an already-deleted path" concern applies: a genuine
    /// watcher fires exactly one `Removed` per deletion, and this is that
    /// same shape of event, just sourced from the File Provider system
    /// instead of `notify`.
    ///
    /// `process_event` never trusts the OS-supplied metadata that
    /// accompanied the original File Provider callback (`createItem`'s
    /// `contents`/`modifyItem`'s `newContents`/`changedFields`) -- by the
    /// time this call reaches it, the caller (the shell_ipc handler) has
    /// already discarded all of that; only `rel_path` and `kind` survive.
    /// `process_event` re-observes whatever is actually on disk at that
    /// path right now, exactly as it does for a live filesystem-watcher
    /// event.
    pub(crate) async fn capture_local_write(
        &self,
        group_id: &str,
        rel_path: &str,
        kind: FsChangeKind,
    ) -> Result<LocalChangeOutcome, String> {
        let path = self.canonical_root.join(rel_path);
        let Some(deps) = self.deps.upgrade() else {
            return Err("link is shutting down".to_string());
        };
        let _op = self
            .root_lease
            .begin_operation()
            .map_err(|_| "link is not currently accepting local writes".to_string())?;
        let _write_activity = deps.begin_write_activity();
        let event = FsChangeEvent { path, kind };
        let outcome = self
            .processor
            .process_event(group_id, &self.root, &event)
            .await
            .map_err(|e| e.to_string())?;
        let records = match &outcome {
            LocalChangeOutcome::FileChanged(record) => vec![record.clone()],
            LocalChangeOutcome::FilesChanged(records) => records.clone(),
            LocalChangeOutcome::None => Vec::new(),
        };
        announce_local_change(&deps, &self.local_path, group_id, records).await;
        Ok(outcome)
    }
}

/// Whether a locally-indexed change may propagate right now. The authoritative
/// group gate is deliberately fail-closed: no live link, pause, orphaning,
/// ambiguity, a path mismatch, or a database error all suppress broadcast.
pub(crate) fn link_should_propagate(
    replica_coordinator: &ReplicaCoordinator,
    local_path: &str,
    group_id: &str,
) -> bool {
    match replica_coordinator.link_repository().link_gate_for_group(group_id) {
        Ok(yadorilink_replica_domain::session_state::LinkGate::Live {
            local_path: live_path,
            ..
        }) if live_path == local_path => true,
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
pub(crate) async fn announce_local_change(
    deps: &Arc<LinkRuntimeDependencies>,
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
    if link_should_propagate(&deps.replica_coordinator, local_path, group_id) {
        deps.broadcast_change(group_id, records.clone()).await;
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
        deps.telemetry.push_status(StatusPush {
            path: absolute_path,
            state: shell_state as i32,
            materialization_state: materialization_state as i32,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;

    use super::*;
    use crate::link_runtime::dependencies::LinkRuntimeHostPort;

    /// A `LinkRuntimeHostPort` that does nothing -- these tests are about
    /// `announce_local_change`'s own local-indexing/status-push/propagation-
    /// gate behavior, not about the daemon-wide broadcast/write-activity/
    /// signing-key operations the real host implementation reaches; there
    /// are no connected peers in any of these tests, so a real broadcast
    /// would be a no-op anyway.
    struct NoopHost;

    impl LinkRuntimeHostPort for NoopHost {
        fn broadcast_change<'a>(
            &'a self,
            _group_id: &'a str,
            _records: Vec<FileRecord>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }

        fn begin_write_activity(&self) -> Box<dyn Send + '_> {
            Box::new(())
        }

        fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
            None
        }
    }

    fn test_deps() -> Arc<LinkRuntimeDependencies> {
        let store_dir = tempfile::tempdir().unwrap();
        let block_store =
            Arc::new(yadorilink_local_storage::FsBlockStore::new(store_dir.path()).unwrap());
        let replica_coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
        Arc::new(LinkRuntimeDependencies {
            replica_coordinator,
            block_store,
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
            device_id: "device-a".to_string(),
            host: Arc::new(NoopHost),
        })
    }

    fn sample_record(path: &str) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 10,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        }
    }

    /// `StatusPush` stays
    /// one-per-file for the shell extension even when the peer-facing
    /// broadcast batches many files into a single wire message — these
    /// are different concerns (local UI feedback vs. peer wire
    /// efficiency), and only the latter should batch.
    #[tokio::test]
    async fn announce_local_change_pushes_one_status_update_per_file_even_when_batched() {
        let deps = test_deps();
        deps.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
        let mut push_rx = deps.telemetry.subscribe_status();

        let records = vec![sample_record("a.jpg"), sample_record("b.jpg"), sample_record("c.jpg")];
        announce_local_change(&deps, "/tmp/photos", "group-1", records).await;

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
        let deps = test_deps();
        deps.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
        let mut push_rx = deps.telemetry.subscribe_status();

        announce_local_change(&deps, "/tmp/photos", "group-1", vec![]).await;

        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
            .await
            .is_err());
    }

    /// Propagation permission comes from the authoritative group gate. Missing,
    /// paused and orphaned links all fail closed; only the exact live path passes.
    #[tokio::test]
    async fn link_should_propagate_is_fail_closed() {
        let replica_coordinator = ReplicaCoordinator::open_in_memory().unwrap();
        let local_path = "/tmp/photos";
        let group_id = "group-1";

        assert!(
            !link_should_propagate(&replica_coordinator, local_path, group_id),
            "no live link must not be interpreted as permission to broadcast"
        );
        replica_coordinator.link_repository().add_link(local_path, group_id).unwrap();
        assert!(link_should_propagate(&replica_coordinator, local_path, group_id));
        assert!(
            !link_should_propagate(&replica_coordinator, "/tmp/some-other-root", group_id),
            "a stale watcher for a different path must not broadcast for the group"
        );
        replica_coordinator.link_repository().set_paused(local_path, true).unwrap();
        assert!(!link_should_propagate(&replica_coordinator, local_path, group_id));
        replica_coordinator.link_repository().set_paused(local_path, false).unwrap();
        replica_coordinator.link_repository().mark_link_orphaned(local_path).unwrap();
        assert!(!link_should_propagate(&replica_coordinator, local_path, group_id));
    }

    /// Marking a link orphaned never touches its on-disk files — only a
    /// local bookkeeping flag flips. The folder and its contents must be
    /// exactly as they were, byte for byte, after the link transitions.
    #[tokio::test]
    async fn orphaning_a_link_leaves_its_on_disk_files_untouched() {
        let deps = test_deps();
        let folder = tempfile::tempdir().unwrap();
        let file_path = folder.path().join("keepsake.txt");
        std::fs::write(&file_path, b"never delete me").unwrap();
        let local_path = folder.path().to_string_lossy().to_string();
        deps.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();

        deps.replica_coordinator.link_repository().mark_link_orphaned(&local_path).unwrap();

        assert_eq!(std::fs::read(&file_path).unwrap(), b"never delete me");
        assert!(deps
            .replica_coordinator
            .link_repository()
            .list_links()
            .unwrap()
            .iter()
            .any(|l| l.orphaned));

        // And sync propagation for this now-orphaned link is suppressed,
        // the same guarantee `link_should_propagate_excludes_paused_and_
        // orphaned` proves in isolation -- exercised here end to end
        // through `announce_local_change` against the real orphaned row.
        let mut push_rx = deps.telemetry.subscribe_status();
        announce_local_change(&deps, &local_path, "group-1", vec![sample_record("new.txt")]).await;
        // The per-file shell-status push still fires (local indexing UI
        // feedback is unconditional); only peer propagation is gated, which
        // has no directly observable effect here with zero connected
        // peers. This call completing without panicking, combined with the
        // isolated gate test above, is the coverage for that path.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
            .await
            .is_ok());
    }

    fn test_link_flush_handle(
        deps: &Arc<LinkRuntimeDependencies>,
        root: &Path,
        flush_request_tx: tokio::sync::mpsc::Sender<debounce::FlushPathRequest>,
    ) -> LinkFlushHandle {
        let root_lock =
            yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root).unwrap();
        let root_lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::new(
            root_lock,
            "group-1".to_string(),
            1,
        ));
        let processor = Arc::new(LocalChangeProcessor::new(
            deps.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                deps.block_store.clone(),
            )),
            deps.device_id.clone(),
            root_lease.clone(),
        ));
        let (flush_all_request_tx, _flush_all_request_rx) = tokio::sync::mpsc::channel(1);
        LinkFlushHandle::new(
            deps,
            flush_request_tx,
            flush_all_request_tx,
            processor,
            root.to_path_buf(),
            root.display().to_string(),
            root_lease,
        )
    }

    /// The targeted-flush channel (`flush_request_tx`, capacity 4 in
    /// production) is shared by every concurrent peer message handler
    /// reconciling a path against this link. Under a duplicate-delivery
    /// storm it can stay permanently full -- this proves a message handler
    /// calling `flush_pending_local_change` against a full, never-drained
    /// channel gets a `RetryRequired` back within its bound (never parks
    /// indefinitely holding its caller's message-handling permit), rather
    /// than the previous unbounded `.send().await`.
    #[tokio::test(start_paused = true)]
    async fn flush_pending_local_change_returns_retry_required_when_the_channel_stays_full() {
        let deps = test_deps();
        let root_dir = tempfile::tempdir().unwrap();
        let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
        // Occupy the channel's one slot and never drain it -- simulates the
        // accumulator task being backlogged/stalled behind other requests.
        let (occupy_reply_tx, _occupy_reply_rx) = tokio::sync::oneshot::channel();
        flush_request_tx
            .try_send(debounce::FlushPathRequest {
                path: root_dir.path().join("occupied"),
                mode: debounce::FlushMode::ExactPath,
                reply: occupy_reply_tx,
            })
            .unwrap();

        let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

        let flush_task = tokio::spawn(async move {
            handle.flush_pending_local_change("group-1", "shared.bin").await
        });
        tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1))
            .await;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), flush_task)
            .await
            .expect("flush_pending_local_change must return promptly once its enqueue bound elapses, not park indefinitely")
            .unwrap();
        assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
    }

    /// Mirrors the exact-path case above for the case-fold-sibling flush.
    #[tokio::test(start_paused = true)]
    async fn flush_case_fold_sibling_returns_retry_required_when_the_channel_stays_full() {
        let deps = test_deps();
        let root_dir = tempfile::tempdir().unwrap();
        let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
        let (occupy_reply_tx, _occupy_reply_rx) = tokio::sync::oneshot::channel();
        flush_request_tx
            .try_send(debounce::FlushPathRequest {
                path: root_dir.path().join("occupied"),
                mode: debounce::FlushMode::ExactPath,
                reply: occupy_reply_tx,
            })
            .unwrap();

        let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

        let flush_task =
            tokio::spawn(
                async move { handle.flush_case_fold_sibling("group-1", "shared.bin").await },
            );
        tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1))
            .await;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), flush_task)
            .await
            .expect("flush_case_fold_sibling must return promptly once its enqueue bound elapses, not park indefinitely")
            .unwrap();
        assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
    }
}
