//! `LinkRuntime`: the per-link runtime this crate publishes into
//! `LinkRegistry` once every fallible step of
//! the daemon's own `LinkRuntimeController::start_inner` has succeeded. Owns the tasks
//! that watch/index/broadcast a linked folder's changes and the
//! `yadorilink_root_authority::root_commit::RootLease` every mutation those
//! tasks (and every other subsystem touching this link -- peer apply,
//! periodic repair, targeted flush, the disk-reconcile backstop sweep)
//! must go through.
//!
//! This module holds `LinkRuntime` itself and, in [`operations`], every
//! per-link operation admitted through a `RootLease`:
//! `operations::capture_local_change` and
//! `operations::repair_materialization` (see the daemon's own
//! `root_commit_authority` module for the third, "ApplyPeerChange" -- it
//! lives outside this module tree since it needs `DaemonState` directly,
//! not the narrow per-link bundle this module tree is built against).
//! The daemon's own `LinkRuntimeController` sits above this module and depends on it, never the
//! reverse: it owns
//! only the watcher/debounce-accumulator task wiring and constructs a
//! `LinkRuntime`/`LinkFlushHandle` from the pieces this module defines.
//! The `Starting`/`Ready` slot lifecycle around a `LinkRuntime` (`LinkSlot`,
//! `StartingReservation`) is owned by `crate::link_registry`, not this
//! module -- this module depends on `link_registry` (for `LinkRegistry`/
//! `DrainedLink`), never the reverse.

use std::sync::Arc;

use tokio::task::JoinHandle;
use yadorilink_replica_domain::file::FileRecord;

use crate::link_runtime::operations::capture_local_change::LinkFlushHandle;

pub(crate) mod dependencies;
pub(crate) mod factory;
pub(crate) mod operations;
pub(crate) mod startup;
pub(crate) mod tasks;

/// Per-link fence closing K15: `LinkFlushHandle`'s methods (a peer session's
/// targeted flush, reached via `PendingLocalChangeFlush`) and the
/// disk-reconcile backstop sweep (`run_disk_reconcile_backstop_sweep`) both
/// hold their own `Arc` clone of state reachable independent of
/// `LinkRegistry` — removing that map's entry alone does not stop either of
/// them from still being mid-`process_flush`, still committing index/DAG
/// writes against a root `stop_link_watch` is about to hand back (by
/// dropping the root lock) to a new owner.
///
/// `stop_link_watch` calls `begin_stopping` before it aborts this link's own
/// tasks (so no new targeted flush or backstop pass is admitted once
/// teardown has begun), then -- after awaiting those tasks exactly as
/// before -- calls `wait_drained`, which blocks until every operation
/// already admitted has dropped its `LinkOperation`, before dropping the root
/// lock. A local mutation is therefore never in flight across the boundary
/// where ownership of the root changes hands. See
/// `yadorilink_root_authority::root_commit::RootLease` for the mechanism itself
/// (this crate no longer defines its own fence type -- `RootLease` owns
/// both the `SyncRootLock` and the admit/drain gate in one place, shared by
/// every subsystem below via `Arc`).
///
/// One linked folder's whole runtime, published as a single `LinkRegistry`
/// entry once every fallible step in `start_link_watch_inner` has already
/// succeeded. Used to be three independently-updated maps (`link_tasks`,
/// `link_flush_handles`, `link_root_locks`), registered and torn down at
/// different points -- see `crate::link_registry`'s own doc for why that
/// let a targeted flush or the disk-reconcile backstop sweep keep
/// committing writes after `stop_link_watch` had already dropped the root
/// lock (K15).
///
/// `stop_link_watch` removes this entry, then: aborts and awaits `tasks`
/// (unchanged from before), calls `flush_handle`'s `LinkOpFence::
/// begin_stopping` before that abort (so no new targeted flush or backstop
/// pass is admitted once teardown starts) and `wait_drained` after it
/// (so any already-admitted one has genuinely finished), and only then lets
/// `root_lock` drop.
pub struct LinkRuntime {
    /// The debounce accumulator, executor, periodic repair, and
    /// dirty-journal tasks -- aborted and awaited together by
    /// `stop_link_watch`/`abort_tasks`.
    tasks: Vec<JoinHandle<()>>,
    flush_handle: Arc<LinkFlushHandle>,
    /// The same lease `flush_handle` holds its own `Arc` clone of -- kept
    /// here too so `shutdown` can call `begin_stopping`/`wait_drained`
    /// without going through `flush_handle`, and so the underlying
    /// `SyncRootLock` (owned by the lease, not this struct directly) stays
    /// alive for as long as either clone does.
    root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
}

impl LinkRuntime {
    /// Assembles a fully-built runtime from its already-constructed pieces
    /// -- called only by the daemon's own `LinkRuntimeController::start_inner` once every
    /// fallible setup step (watcher, debounce wiring, `LinkFlushHandle`,
    /// `RootLease`) has already succeeded. Field construction stays outside
    /// this module's own external surface: everything but this constructor
    /// and the semantic operations below is private to `link_runtime` and
    /// its submodules.
    pub(crate) fn new(
        tasks: Vec<JoinHandle<()>>,
        flush_handle: Arc<LinkFlushHandle>,
        root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
    ) -> Self {
        Self { tasks, flush_handle, root_lease }
    }

    /// Forces every currently-pending, undispatched local change in this
    /// link's debounce accumulator to flush and index -- see
    /// `LinkFlushHandle::flush_all_pending_local_changes`'s own doc for why
    /// `resume_link` needs this.
    pub(crate) async fn flush_pending_local_changes(&self, group_id: &str) {
        self.flush_handle.flush_all_pending_local_changes(group_id).await;
    }

    /// The disk-reconcile backstop sweep's per-link operation -- see
    /// `LinkFlushHandle::reconcile_added_files_from_disk`'s own doc.
    /// `None` means this link's `RootLease` refused admission (already
    /// stopping); `Some` carries the underlying reconcile result.
    pub(crate) fn reconcile_added_files_from_disk(
        &self,
        group_id: &str,
    ) -> Option<Result<Vec<FileRecord>, yadorilink_local_capture::LocalCaptureError>> {
        self.flush_handle.reconcile_added_files_from_disk(group_id)
    }

    /// Forces a racing peer write's targeted-flush request for one path --
    /// see `LinkFlushHandle::flush_pending_local_change`'s own doc. Reached
    /// from the daemon-wide runtime state's own `PendingLocalChangeFlush`
    /// implementation, which a `PeerSyncSession` calls into.
    pub(crate) async fn flush_pending_local_change(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> yadorilink_peer_session::peer_session::PendingLocalFlushOutcome {
        self.flush_handle.flush_pending_local_change(group_id, rel_path).await
    }

    /// Same as [`Self::flush_pending_local_change`], for a case-fold
    /// sibling collision -- see `LinkFlushHandle::flush_case_fold_sibling`'s
    /// own doc.
    pub(crate) async fn flush_case_fold_sibling(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> yadorilink_peer_session::peer_session::PendingLocalFlushOutcome {
        self.flush_handle.flush_case_fold_sibling(group_id, rel_path).await
    }

    /// M1-3: routes a File-Provider-originated local write notification
    /// through this link's `LocalChangeProcessor` -- see
    /// `LinkFlushHandle::capture_local_write`'s own doc. Reached from
    /// `shell_ipc`'s `LocalWriteRequest` handler via `LinkRegistry::runtime`.
    pub(crate) async fn capture_local_write(
        &self,
        group_id: &str,
        rel_path: &str,
        kind: yadorilink_filesystem_sync::watcher::FsChangeKind,
    ) -> Result<yadorilink_local_capture::LocalChangeOutcome, String> {
        self.flush_handle.capture_local_write(group_id, rel_path, kind).await
    }

    /// The one deliberate exception to this type's "no raw internal-type
    /// getter" rule: `yadorilink_peer_session::peer_session::
    /// RootCommitAuthorityProvider` (implemented by `DaemonState` in the
    /// daemon's own `root_commit_authority` module) is an EXTERNAL trait
    /// contract
    /// (`yadorilink-sync-core`'s own `PeerSyncSession` calls through it)
    /// whose signature returns `Option<Arc<RootLease>>` verbatim -- there
    /// is no semantic operation to wrap this in on our side, since the
    /// admit/mutate logic that consumes the lease lives entirely on the
    /// other side of that boundary, in `yadorilink-sync-core`. Every other
    /// caller of `LinkRuntime` should use the narrower operations above
    /// instead.
    pub(crate) fn root_lease(&self) -> &Arc<yadorilink_root_authority::root_commit::RootLease> {
        &self.root_lease
    }

    /// Aborts every internal task without waiting for them to stop or
    /// draining the operation fence -- the same best-effort teardown
    /// `stop_link_watch` used to give a caller no choice but to reimplement
    /// by hand. Real production shutdown additionally awaits these tasks
    /// and drains the fence (see `stop_link_watch`); this is for a harness
    /// that only needs "stop reacting to new events, don't leak the OS
    /// lock" before moving on to its next iteration.
    pub fn abort_tasks(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }

    /// The real two-phase teardown: refuses new admission to `root_lease`,
    /// aborts and awaits every task, then drains the lease -- so every
    /// operation this link can produce has genuinely finished -- before the
    /// underlying `SyncRootLock` is allowed to drop when `self` (and every
    /// other `Arc<RootLease>` clone) goes out of scope.
    ///
    /// Shared by `stop_link_watch` (single-link unlink) and `app::
    /// graceful_shutdown` (whole-process shutdown): both are the same
    /// "this link is going away, for good" case. Before this method
    /// existed, only `stop_link_watch` got the real teardown --
    /// `graceful_shutdown` called `abort_tasks` alone and then dropped
    /// the root lock immediately, reopening K15 during its own shutdown
    /// window (`graceful_shutdown` does not exit the process immediately
    /// afterward -- it still drains in-flight broadcasts, up to 3s, and
    /// checkpoints SQLite, so a scan/flush/backstop operation still mid-
    /// commit at that point was racing a root a new owner could already be
    /// operating on).
    pub async fn shutdown(mut self) {
        self.root_lease.begin_stopping();
        for handle in &self.tasks {
            handle.abort();
        }
        for handle in self.tasks.drain(..) {
            let _ = handle.await;
        }
        self.root_lease.wait_drained().await;
    }
}
