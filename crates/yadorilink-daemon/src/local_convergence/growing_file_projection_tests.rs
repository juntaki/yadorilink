#![cfg(test)]
//! A file this device is still writing must never be overwritten with
//! this device's own older version of it.
//!
//! The shape these pin down came from a real device: a `git clone` into
//! the sync folder. Git creates its pack file empty and streams into it.
//! The empty file is captured, becomes this device's own head, and is
//! projected back onto disk -- over the pack git is still writing. Every
//! barrier between the two let it through:
//!
//! * the pre-materialize flush tried to capture the growing file, the
//!   capture failed on it, and the flush reported the path as settled;
//! * the last-line disk check before the write skipped a row with no
//!   blocks, and skipped a row whose capture raced its own disk
//!   observation (left `Placeholder`, with nothing proving what is on
//!   disk).
//!
//! The overwrite is silent and permanent: no conflict copy, and a later
//! rescan sees disk matching the (stale) indexed version.

use super::*;
use crate::link_runtime::dependencies::{LinkRuntimeDependencies, LinkRuntimeHostPort};
use crate::link_runtime::operations::capture_local_change::LinkFlushHandle;
use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::{
    PeerSyncSession, PendingLocalChangeFlush, PendingLocalFlushOutcome,
};
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

pub(super) const GROUP: &str = "growing-file-group";
pub(super) const LOCAL_DEVICE: &str = "device-local";

struct NoopHost;

impl LinkRuntimeHostPort for NoopHost {
    fn note_capture_settled(&self, _group_id: &str) {}

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

    fn device_signing_key(&self) -> Option<SigningKey> {
        None
    }
}

/// The production flush guard: this link's own `LinkFlushHandle`, whose
/// accumulator never has anything queued, so every guard call falls back
/// to capturing the path straight from disk -- the route a file takes
/// when its watcher events have already drained or never arrived.
///
/// `after_guard`, when set, runs once, right after the next exact-path
/// guard call returns: a write that lands after the guard looked and
/// before the projection that asked it reaches the disk.
struct LinkFlush {
    handle: Arc<LinkFlushHandle>,
    after_guard: AfterGuardHook,
}

pub(super) type AfterGuardHook = Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

impl PendingLocalChangeFlush for LinkFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async move {
            let outcome = self.handle.flush_pending_local_change(group_id, rel_path).await;
            let hook = self.after_guard.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            outcome
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(self.handle.flush_case_fold_sibling(group_id, rel_path))
    }

    fn capture_local_path_state<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(self.handle.capture_local_path_state(group_id, rel_path))
    }
}

pub(super) struct Harness {
    pub(super) session: Arc<PeerSyncSession>,
    pub(super) convergence: Arc<super::LocalConvergenceExecutor>,
    pub(super) state: Arc<ReplicaCoordinator>,
    processor: Arc<LocalChangeProcessor>,
    root: std::path::PathBuf,
    flush: Arc<LinkFlushHandle>,
    pending_sibling: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
    /// See `LinkFlush`: only consulted when built `through_link_flush`.
    pub(super) after_guard: AfterGuardHook,
    _deps: Arc<LinkRuntimeDependencies>,
    _store_dir: tempfile::TempDir,
    _root_dir: tempfile::TempDir,
}

impl Harness {
    /// `through_link_flush`: route the executor's pre-materialize guard
    /// through a real `LinkFlushHandle` over the same processor this
    /// harness captures with. Otherwise the guard is the permissive no-op
    /// (it captures nothing), which is what "a write the flush did not
    /// capture" looks like to the materialize under test.
    pub(super) fn new(through_link_flush: bool) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let local_path = root.to_string_lossy().to_string();
        state.link_repository().add_link(&local_path, GROUP).unwrap();
        state
            .link_repository()
            .set_materialization_policy(&local_path, MaterializationPolicy::Eager)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, state.as_ref())
            .unwrap();

        let root_lock =
            yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(&root).unwrap();
        let root_lease = Arc::new(RootLease::new(root_lock, GROUP.to_string(), 1));
        let processor = Arc::new(
            LocalChangeProcessor::new(
                state.clone(),
                Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                    store.clone(),
                )),
                LOCAL_DEVICE.to_string(),
                root_lease.clone(),
            )
            .with_change_emitter(Arc::new(ChangeEmitter::new(
                LOCAL_DEVICE,
                SigningKey::from_bytes(&[7u8; 32]),
            ))),
        );

        let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
        let deps = Arc::new(LinkRuntimeDependencies {
            replica_coordinator: state.clone(),
            block_store: store.clone(),
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
            device_id: LOCAL_DEVICE.to_string(),
            host: Arc::new(NoopHost),
        });
        // An accumulator with nothing pending for any exact path: answers
        // every targeted flush with "nothing queued for that path". A
        // case-fold sibling request is answered with whatever
        // `pending_sibling` holds, as if a watcher event for it were
        // still queued.
        let pending_sibling: Arc<std::sync::Mutex<Option<std::path::PathBuf>>> = Arc::default();
        let (flush_request_tx, mut flush_request_rx) =
            tokio::sync::mpsc::channel::<yadorilink_filesystem_sync::debounce::FlushPathRequest>(4);
        let accumulator_sibling = pending_sibling.clone();
        tokio::spawn(async move {
            while let Some(request) = flush_request_rx.recv().await {
                let found = match request.mode {
                    yadorilink_filesystem_sync::debounce::FlushMode::ExactPath => None,
                    yadorilink_filesystem_sync::debounce::FlushMode::CaseFoldSibling => {
                        accumulator_sibling
                            .lock()
                            .unwrap()
                            .take()
                            .map(|path| (path, FsChangeKind::CreatedOrModified, 1))
                    }
                };
                let _ = request.reply.send(found);
            }
        });
        let (flush_all_request_tx, _flush_all_request_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(LinkFlushHandle::new(
            &deps,
            flush_request_tx,
            flush_all_request_tx,
            processor.clone(),
            root.clone(),
            local_path,
            root_lease,
        ));

        let (channel, _peer_end) =
            yadorilink_peer_session::ports::InMemoryPeerChannel::connected_pair();
        let transports = yadorilink_peer_session::ports::in_memory_transports(&channel);
        let mut session_deps =
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive();
        let after_guard: AfterGuardHook = Arc::default();
        if through_link_flush {
            session_deps.pending_local_change_flush =
                Arc::new(LinkFlush { handle: handle.clone(), after_guard: after_guard.clone() });
        }
        let sync_roots = HashMap::from([(GROUP.to_string(), root.clone())]);
        let session = PeerSyncSession::over_substrate(
            LOCAL_DEVICE.to_string(),
            "device-remote".to_string(),
            state.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            crate::replica_coordinator::engine_ports::build_peer_replica_engine(
                &state,
                store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            ),
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            vec![GROUP.to_string()],
            sync_roots.clone(),
            transports,
            None,
            session_deps.clone(),
        );
        let convergence = super::LocalConvergenceExecutor::new(
            state.clone(),
            LOCAL_DEVICE.to_string(),
            session_deps.root_commit_authority_provider.clone(),
            session_deps.pending_local_change_flush.clone(),
            sync_roots,
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            session_deps.block_write_activity_provider.clone(),
            super::HeadroomPolicy::disabled(),
        );
        Self {
            session,
            convergence,
            state,
            processor,
            root,
            flush: handle,
            pending_sibling,
            after_guard,
            _deps: deps,
            _store_dir: store_dir,
            _root_dir: root_dir,
        }
    }

    pub(super) fn path(&self, rel: &str) -> std::path::PathBuf {
        self.root.join(rel)
    }

    /// Captures `rel` the way a watcher event would.
    pub(super) async fn capture(&self, rel: &str) -> LocalChangeOutcome {
        self.processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent { path: self.path(rel), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .expect("capturing a file that is not changing must succeed")
    }

    /// Captures `rels` the way one debounced flush of the watcher does:
    /// eligible paths are committed together as one batch.
    pub(super) async fn capture_flush(&self, rels: &[&str]) {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let paths =
            rels.iter().map(|rel| (self.path(rel), FsChangeKind::CreatedOrModified, now)).collect();
        self.processor
            .process_flush(
                GROUP,
                &self.root,
                yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths),
            )
            .await
            .expect("the flush must run");
    }

    /// Re-drives the dirty journal, as the daemon's backstop does: every
    /// path a scan or a failed capture left dirty is captured again.
    pub(super) async fn redrive(&self) {
        self.processor
            .redrive_dirty_journal(GROUP, &self.root)
            .await
            .expect("the redrive must run");
    }

    /// A full capture scan of the root: the pass a restart runs, which
    /// signs a delete for every indexed path it does not find on disk.
    pub(super) fn scan(&self) -> Vec<FileRecord> {
        tokio::task::block_in_place(|| {
            self.processor.scan_existing_files(GROUP, &self.root).expect("the scan must run")
        })
    }

    /// This device's own current head for `rel`.
    pub(super) fn own_head(&self, rel: &str) -> PathHead {
        let heads = self.convergence.combined_heads(GROUP, rel, None).unwrap();
        assert_eq!(heads.len(), 1, "sanity: exactly one live head for {rel}");
        assert_eq!(heads[0].device_id, LOCAL_DEVICE, "sanity: the head is this device's own");
        heads[0].clone()
    }

    pub(super) async fn materialize_own_head(&self, rel: &str) -> MaterializeResult {
        self.materialize_own_head_under(rel, MaterializationPolicy::Eager).await
    }

    async fn materialize_own_head_under(
        &self,
        rel: &str,
        policy: MaterializationPolicy,
    ) -> MaterializeResult {
        let head = self.own_head(rel);
        self.convergence
            .materialize_dag_content_head(GROUP, rel, rel, &head, policy, None, None)
            .await
            .expect("materialize must not error")
    }
}

pub(super) fn append(path: &std::path::Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

/// Git's first step: an empty pack file, captured as an empty version
/// (`Hydrated`, no blocks). Git then streams into it before any capture
/// sees the new bytes. Projecting this device's own empty head at that
/// moment must not truncate what git has written -- an empty block list
/// means the file on disk must be empty, and it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_empty_head_is_not_written_over_bytes_appended_since_it_was_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    assert_eq!(
        h.state.get_materialization_state(GROUP, "tmp_pack").unwrap(),
        Some(MaterializationState::Hydrated),
        "sanity: a stable capture proves what it read"
    );

    append(&h.path("tmp_pack"), b"PACK streamed by a program that is still writing");

    let _ = h.materialize_own_head("tmp_pack").await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK streamed by a program that is still writing",
        "this device's own empty head must not be projected over newer local bytes"
    );
}

/// The on-demand lane writes a placeholder, not content, but a
/// placeholder written over a file is just as destructive: it replaces
/// the bytes with a sparse file of the row's size. The same last-line
/// check must stand in front of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_head_is_not_written_as_a_placeholder_over_bytes_appended_since_it_was_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));

    append(&h.path("tmp_pack"), b"PACK streamed by a program that is still writing");

    let result = h.materialize_own_head_under("tmp_pack", MaterializationPolicy::OnDemand).await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK streamed by a program that is still writing",
        "the on-demand lane must not write a placeholder over newer local bytes"
    );
    assert!(
        matches!(result, MaterializeResult::RetryRequired),
        "a declined placeholder write must be retried, got {result:?}"
    );
}

/// The same, for a capture whose own disk observation raced the write:
/// the row names what was read, but nothing proves what is on disk, so it
/// is left `Placeholder`. That is not a placeholder this device wrote --
/// the file holds real bytes, newer than the row -- and projecting the
/// row's version over it destroys them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_head_is_not_written_over_newer_bytes_under_an_unproven_placeholder_row() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"PACK first chunk").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    // What a capture whose closing observation raced leaves behind: the
    // row keeps the version that was read, and the claim that disk holds
    // it is retired (`Hydrated` -> `Placeholder`). No placeholder
    // generation is recorded: this device never wrote a placeholder here.
    h.state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "tmp_pack",
            MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    append(&h.path("tmp_pack"), b" + the rest of the pack");

    let _ = h.materialize_own_head("tmp_pack").await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK first chunk + the rest of the pack",
        "this device's own head must not be projected over newer local bytes under a \
         Placeholder row it never wrote a placeholder for"
    );
}

/// End to end through a projection pass, with the production flush guard
/// in front of it: the file keeps growing while the guard tries to
/// capture it. The guard cannot capture a file that changes while it is
/// read, so it must say so, and the pass must leave the path alone and
/// retry it -- not project this device's own stale head over the file.
/// Once the writer finishes, a later pass captures the whole file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_still_being_written_is_retried_by_projection_and_captured_once_it_settles() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));

    append(&pack, b"PACK header ");
    // Still being written: every read of the file races another append.
    let grow = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
        .await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);
    let attempt = attempt.unwrap().expect("sanity: the pass must actually run");

    let on_disk = std::fs::read(&pack).unwrap();
    assert!(
        on_disk.starts_with(b"PACK header more pack "),
        "the projection pass must not overwrite a file that is still being written; disk now \
         holds {} bytes: {:?}",
        on_disk.len(),
        String::from_utf8_lossy(&on_disk)
    );
    assert!(
        !attempt.is_settled("tmp_pack"),
        "a path whose local edit could not be captured must not be reported settled"
    );

    // The writer is done. The next pass captures what it wrote. That
    // capture moves the path's head in the middle of the pass, so the pass
    // itself defers; the one after it finds this device's own new head
    // already on disk and settles without writing.
    let expected = std::fs::read(&pack).unwrap();
    let mut settled = false;
    for _ in 0..3 {
        let attempt = h
            .convergence
            .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
        assert_eq!(std::fs::read(&pack).unwrap(), expected, "the finished file must be untouched");
        if attempt.is_settled("tmp_pack") {
            settled = true;
            break;
        }
    }
    let row = h.state.get_file(GROUP, "tmp_pack").unwrap().expect("the path is indexed");
    assert_eq!(row.size, expected.len() as u64, "the finished file must have been captured");
    assert!(
        !h.state.dirty_path_repository().is_path_dirty(GROUP, "tmp_pack").unwrap(),
        "once captured, the path must no longer be journaled dirty"
    );
    assert!(settled, "once captured, this device's own head matches disk and the path settles");
}

/// On a case-insensitive volume a program streaming into `foo.pack` and a
/// peer's new `Foo.pack` name the same file. The exact-path guard for
/// `Foo.pack` cannot see `foo.pack` (its leaf bytes differ), so the only
/// thing standing between the growing file and the incoming write is the
/// case-fold sibling guard. When it cannot capture the sibling -- the file
/// changes while it is read -- it must say so, not report the path
/// settled: the hazard check reads only the index, and the sibling never
/// made it in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_fold_sibling_guard_defers_when_the_sibling_cannot_be_captured() {
    let h = Harness::new(true);
    let sibling = h.path("foo.pack");
    std::fs::write(&sibling, b"PACK header ").unwrap();
    *h.pending_sibling.lock().unwrap() = Some(sibling.clone());
    let grow = sibling.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(sibling.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let outcome = h.flush.flush_case_fold_sibling(GROUP, "Foo.pack").await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&sibling);

    assert!(
        h.state.get_file(GROUP, "foo.pack").unwrap().is_none(),
        "sanity: a file that changed while it was read is not indexed"
    );
    assert_eq!(
        outcome,
        PendingLocalFlushOutcome::RetryRequired,
        "a case-fold sibling left uncaptured must defer the write to the colliding name"
    );
}

/// The guard runs for every incoming update to a path that exists on
/// disk, including in the ordinary batch's prepare step. For a file that
/// has not changed since it was captured there is nothing to capture, and
/// the guard must not cost a database write: journaling the path dirty
/// and clearing it again are two fsyncing commits per path, which turns a
/// bulk remote update of N files into 2N extra commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_on_an_unchanged_captured_file_writes_nothing() {
    let h = Harness::new(true);
    std::fs::write(h.path("stable.txt"), b"captured and unchanged").unwrap();
    assert!(matches!(h.capture("stable.txt").await, LocalChangeOutcome::FileChanged(_)));

    let database = h.state.database();
    let before = database.write_transaction_count();
    let outcome = h.flush.flush_pending_local_change(GROUP, "stable.txt").await;
    let writes = database.write_transaction_count() - before;

    assert_eq!(outcome, PendingLocalFlushOutcome::Settled);
    assert_eq!(writes, 0, "the guard on an unchanged, captured file must not write");
}

/// The guard itself, with nothing behind it: a file that changes while
/// the guard reads it cannot be captured, and the guard must report that
/// rather than license a write to the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_reports_a_file_that_changes_while_it_is_read_as_not_settled() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"PACK header ").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    append(&pack, b"more pack ");
    let grow = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let outcome = h.flush.flush_pending_local_change(GROUP, "tmp_pack").await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);

    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
    assert!(
        h.state.dirty_path_repository().is_path_dirty(GROUP, "tmp_pack").unwrap(),
        "the uncaptured edit must stay journaled for a later capture"
    );
}

/// A delete is as final as a content write. A tombstone arriving for a
/// file whose bytes moved on since this device captured it must be
/// retried, not applied -- once captured, the edit meets the tombstone as
/// a concurrent edit instead of vanishing. With the permissive guard the
/// last-line disk check is the only thing in the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstone_is_not_applied_over_bytes_changed_since_they_were_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("notes.txt"), b"captured").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    append(&h.path("notes.txt"), b" and then edited");

    let mut tombstone = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap();
    tombstone.deleted = true;
    tombstone.blocks.clear();
    tombstone.size = 0;
    let result = h
        .convergence
        .materialize_tombstone(
            GROUP,
            &tombstone,
            "device-remote",
            None,
            &RootCommitPermit::for_tests(),
        )
        .await
        .expect("materialize_tombstone must not error");

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        b"captured and then edited",
        "a tombstone must not delete bytes this device never captured"
    );
    assert_eq!(result, MaterializeResult::RetryRequired);
}

/// A peer's delete that descends from this device's own capture makes the
/// path resolve Absent, and projecting that deletes whatever is on disk.
/// When the guard cannot capture the file (it changes while it is read),
/// its answer is the only thing that stops the delete: here each read's
/// racing write is undone before the pass reaches the disk check, so the
/// file looks exactly like the captured version. The pass must defer the
/// path, not delete the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_resolution_defers_when_the_guard_cannot_capture_the_file() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"PACK v1").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    let own = h.own_head("tmp_pack");
    let remote = ChangeEmitter::new("device-remote", SigningKey::from_bytes(&[9u8; 32]));
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::emit_local_change_onto(
                conn,
                GROUP,
                vec![yadorilink_replica_domain::ids::ChangeHash(own.change_hash)],
                vec![yadorilink_replica_domain::change::Op::Delete {
                    path: yadorilink_replica_domain::ids::SyncPath("tmp_pack".into()),
                }],
                &remote,
            )
        })
        .unwrap();
    assert!(
        matches!(
            resolve_path_heads(
                "tmp_pack",
                &h.convergence.combined_heads(GROUP, "tmp_pack", None).unwrap()
            ),
            PathResolution::Absent
        ),
        "sanity: the peer's delete supersedes this device's capture"
    );

    // Rewritten in place with the same bytes, so the guard has to read it,
    // and every read races a write that is undone again right after.
    std::fs::write(&pack, b"PACK v1").unwrap();
    let racing = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&racing, b" and more");
        std::fs::OpenOptions::new().write(true).open(&racing).unwrap().set_len(7).unwrap();
        true
    });
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
        .await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);
    let attempt = attempt.unwrap().expect("sanity: the pass must actually run");

    assert!(
        pack.exists(),
        "an Absent resolution must not delete a file the guard could not capture"
    );
    assert!(!attempt.is_settled("tmp_pack"), "the path must be left for a later pass");
}
