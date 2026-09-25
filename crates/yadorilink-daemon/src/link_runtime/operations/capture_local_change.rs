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
        // A `None` reply
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
            return self.capture_undiscovered_local_change(group_id, rel_path, &path).await;
        };
        tracing::info!(
            group_id,
            path = %path.display(),
            "forcing a pending local change to flush and index before a racing peer update for \
             the same path is applied"
        );
        self.flush_one_path(group_id, rel_path, found_path, kind, observed_at).await
    }

    /// Captures `rel_path`'s current disk state -- see
    /// `PendingLocalChangeFlush::capture_local_path_state`. Whatever is
    /// queued or on disk is captured by `flush_pending_local_change`; when
    /// nothing answers to the path at all, the flush executor is run with
    /// a `Removed` event for it, which re-stats the path, tombstones a row
    /// the index still holds live, and does nothing for a row that is
    /// already a tombstone or was never indexed.
    pub(crate) async fn capture_local_path_state(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let flushed = self.flush_pending_local_change(group_id, rel_path).await;
        if flushed == PendingLocalFlushOutcome::RetryRequired {
            return flushed;
        }
        let path = self.canonical_root.join(rel_path);
        if path.symlink_metadata().is_ok() {
            return flushed;
        }
        self.flush_one_path(group_id, rel_path, path, FsChangeKind::Removed, now_unix_nanos()).await
    }

    /// Runs one path through this link's ordinary flush executor -- which
    /// journals it dirty, captures it, and clears the row only once the
    /// capture committed -- and reports whether the path is now captured.
    async fn flush_one_path(
        &self,
        group_id: &str,
        rel_path: &str,
        path: PathBuf,
        kind: FsChangeKind,
        observed_at: i64,
    ) -> PendingLocalFlushOutcome {
        let Some(deps) = self.deps.upgrade() else { return PendingLocalFlushOutcome::Settled };
        let Ok(_op) = self.root_lease.begin_operation() else {
            return PendingLocalFlushOutcome::Settled;
        };
        let _write_activity = deps.begin_write_activity();
        let flushed = match self
            .processor
            .process_flush(
                group_id,
                &self.root,
                DebounceFlush::Paths(vec![(path.clone(), kind, observed_at)]),
            )
            .await
        {
            Ok(outcome) => {
                // Before announcing: a flush that produced NO record still cleared
                // the dirty rows that were a capture barrier, and
                // `announce_local_change` returns immediately on an empty
                // record set. Re-asking admission must not be conditioned on
                // there being something to announce.
                deps.note_capture_settled(group_id);
                announce_local_change(&deps, &self.local_path, group_id, outcome.records).await;
                true
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    group_id,
                    "failed to force-flush a pending local change ahead of a racing peer update"
                );
                false
            }
        };
        // A flush processes each path on its own and reports a path it
        // could not capture only by leaving its dirty-journal row in
        // place (the file changed while it was read, a block-store fault
        // outlived its retries, ...). Such a path holds a local edit this
        // device has not authored, so the caller must not write over it.
        let still_dirty = || {
            deps.replica_coordinator
                .dirty_path_repository()
                .is_path_dirty(group_id, rel_path)
                .unwrap_or(true)
        };
        if !flushed || still_dirty() {
            tracing::info!(
                group_id,
                path = %path.display(),
                "a pending local change could not be captured ahead of a racing peer update; \
                 deferring this reconciliation"
            );
            return PendingLocalFlushOutcome::RetryRequired;
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
        // Through the same helper as the exact path, so a sibling whose
        // capture failed or left it journaled dirty (it changed while it
        // was read) reports `RetryRequired`: the hazard check about to run
        // reads only the index, and cannot see a sibling that never made
        // it in.
        let Some(sibling_rel) = LocalChangeProcessor::dirty_journal_key(&self.root, &sibling_path)
        else {
            return PendingLocalFlushOutcome::RetryRequired;
        };
        self.flush_one_path(group_id, &sibling_rel, sibling_path, kind, observed_at).await
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
                // Before announcing: a flush that produced NO record still cleared
                // the dirty rows that were a capture barrier, and
                // `announce_local_change` returns immediately on an empty
                // record set. Re-asking admission must not be conditioned on
                // there being something to announce.
                deps.note_capture_settled(group_id);
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
    /// path with no file on disk. The `Removed` branch now treats an
    /// already-tombstoned row as nothing to author, but a speculative
    /// `Removed` for a live row whose file merely has not appeared yet
    /// would still tombstone it -- and before that guard existed, an
    /// unconditional fallback call for a path that's already tombstoned
    /// re-stamped its tombstone even though nothing local changed,
    /// corrupting the very version-vector comparison
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
    ///
    /// Reports `RetryRequired` whenever this path may still hold a local
    /// edit that was not captured -- the file changed while it was read,
    /// or the capture failed. The caller is about to write to this path;
    /// "settled" there would license overwriting bytes this device never
    /// authored.
    async fn capture_undiscovered_local_change(
        &self,
        group_id: &str,
        rel_path: &str,
        path: &Path,
    ) -> PendingLocalFlushOutcome {
        if path.symlink_metadata().is_err() {
            // nothing on disk at this path — nothing to protect
            return PendingLocalFlushOutcome::Settled;
        }
        {
            let Some(deps) = self.deps.upgrade() else { return PendingLocalFlushOutcome::Settled };
            let Ok(_op) = self.root_lease.begin_operation() else {
                return PendingLocalFlushOutcome::Settled;
            };
            let _write_activity = deps.begin_write_activity();
            // A bare `process_event`, not the flush executor: this runs for
            // every incoming update to a path that exists on disk, and for
            // an unchanged file its fast path writes nothing, where the
            // executor would journal the path dirty and clear it again --
            // two commits per path on the batched path. A capture that
            // cannot finish (`RetryLater`) journals the path itself.
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
                Ok(LocalChangeOutcome::FilesChanged(records)) => {
                    announce_local_change(&deps, &self.local_path, group_id, records).await;
                }
                Ok(LocalChangeOutcome::None) => {}
                Ok(LocalChangeOutcome::RetryLater) => {
                    tracing::info!(
                        group_id,
                        path = %path.display(),
                        "a local file changed while it was captured ahead of a racing peer \
                         update; deferring this reconciliation"
                    );
                    return PendingLocalFlushOutcome::RetryRequired;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        group_id,
                        path = %path.display(),
                        "failed to check for a not-yet-discovered local change ahead of a racing \
                         peer update; deferring this reconciliation"
                    );
                    return PendingLocalFlushOutcome::RetryRequired;
                }
            }
        }
        // A row an earlier pass left behind (the file changed while it was
        // read) still marks this path unsettled, even though this capture
        // succeeded. Only then pay for the flush executor: it re-journals
        // and re-captures the path and clears the row once the capture
        // commits, so a stale row does not defer this path forever.
        let dirty = match self.deps.upgrade() {
            Some(deps) => deps
                .replica_coordinator
                .dirty_path_repository()
                .is_path_dirty(group_id, rel_path)
                .unwrap_or(true),
            None => return PendingLocalFlushOutcome::Settled,
        };
        if !dirty {
            return PendingLocalFlushOutcome::Settled;
        }
        self.flush_one_path(
            group_id,
            rel_path,
            path.to_path_buf(),
            FsChangeKind::CreatedOrModified,
            now_unix_nanos(),
        )
        .await
    }

    /// Routes a File-Provider-originated create/modify/delete
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
            LocalChangeOutcome::None | LocalChangeOutcome::RetryLater => Vec::new(),
        };
        announce_local_change(&deps, &self.local_path, group_id, records).await;
        Ok(outcome)
    }

    /// Resume's local catch-up for a paused item: every change the pause
    /// held under `rel_path` is still on disk (nothing else recorded it),
    /// so this re-reads that subtree through the ordinary capture path
    /// (`LocalChangeProcessor::capture_resumed_item`) and announces what it
    /// authored, exactly as a drained debounce flush does.
    pub(crate) async fn capture_resumed_item(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<(), String> {
        let Some(deps) = self.deps.upgrade() else {
            return Err("link is shutting down".to_string());
        };
        let _op = self
            .root_lease
            .begin_operation()
            .map_err(|_| "link is not currently accepting local writes".to_string())?;
        let _write_activity = deps.begin_write_activity();
        let outcome = self
            .processor
            .capture_resumed_item(group_id, &self.root, rel_path)
            .await
            .map_err(|e| e.to_string())?;
        // Same order as every other flush here: the flush may have cleared
        // dirty rows even when it authored nothing.
        deps.note_capture_settled(group_id);
        announce_local_change(&deps, &self.local_path, group_id, outcome.records).await;
        Ok(())
    }

    /// Mint-or-read a Windows CfAPI generation token for `rel_path`,
    /// persisting a freshly-minted one so a later `LocalMutationStore::
    /// inspect_windows_placeholder` call has something durable to compare
    /// against, and so a repeat call for the SAME still-placeholder path
    /// (this is polled by `shell_ipc.rs`'s `ListFolderFilesRequest` handler
    /// every time `yadorilink-cfapi-host.exe` asks, up to every 30s) gets
    /// back the exact same value instead of a fresh one each time --
    /// idempotent by construction, which is also what makes this safe
    /// across a daemon restart: the persisted value in the index, not
    /// anything held only in this process's memory, is the source of
    /// truth a later read reads back.
    ///
    /// Review finding: an earlier version of this method read (`database.
    /// read`, not serialized against this process's own writer lock), then
    /// separately minted and wrote (`database.write`) -- two concurrent
    /// callers for the SAME path (two overlapping `ListFolderFilesRequest`
    /// handlers) could both observe "nothing recorded yet" and both mint
    /// and persist, with the later write silently winning while
    /// `cfapi-host.exe` might have already created a real placeholder
    /// carrying the EARLIER (now-orphaned) generation -- permanently
    /// `Unknown`/`Dirty` for that path until it transitions out of
    /// `Placeholder` and back. `record_placeholder_generation_if_absent`
    /// does the check-then-write in ONE `database.write` closure, so this
    /// is no longer racy: whichever caller's mint actually gets persisted,
    /// every caller (including ones that lost the race) gets back that
    /// same winning value.
    ///
    /// Admits its own `LinkOperation` the same way every other mutating
    /// method on this handle does -- `record_placeholder_generation_if_absent`
    /// requires a `RootCommitPermit`, and this is the one seam that can
    /// mint one for this call.
    pub(crate) fn ensure_windows_placeholder_generation(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<u64, String> {
        let Some(deps) = self.deps.upgrade() else {
            return Err("link is shutting down".to_string());
        };
        let op = self
            .root_lease
            .begin_operation()
            .map_err(|_| "link is not currently accepting local writes".to_string())?;
        let repo = deps.replica_coordinator.materialization_state_repository();
        let candidate = yadorilink_local_storage::PlaceholderDiskIdentity {
            dev: 0,
            ino: yadorilink_local_storage::mint_windows_placeholder_generation(),
        };
        let winner = repo
            .record_placeholder_generation_if_absent(
                group_id,
                rel_path,
                candidate,
                yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
                &op.permit(),
            )
            .map_err(|e| e.to_string())?;
        Ok(winner.ino)
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
mod tests;

/// Wall-clock observation time for a capture this handle starts itself
/// (no watcher event supplied one).
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
