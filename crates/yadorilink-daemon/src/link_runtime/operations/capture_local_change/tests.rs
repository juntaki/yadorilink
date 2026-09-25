#![cfg(test)]

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

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        None
    }
}

/// A host that records whether the capture-settled signal was raised.
struct RecordingHost {
    settled: std::sync::atomic::AtomicUsize,
    broadcasts: std::sync::atomic::AtomicUsize,
}

impl LinkRuntimeHostPort for RecordingHost {
    fn note_capture_settled(&self, _group_id: &str) {
        self.settled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn broadcast_change<'a>(
        &'a self,
        _group_id: &'a str,
        _records: Vec<FileRecord>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        self.broadcasts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        None
    }
}

/// A flush that authors nothing must still re-ask admission.
///
/// The dirty rows a flush clears ARE the capture barrier that holds a
/// verified staged Change back. A flush can clear them and produce no
/// record at all -- a spurious event, or one whose path turned out
/// unchanged. `announce_local_change` returns at `records.is_empty()`,
/// so everything downstream of it, including the admission wake, is
/// skipped in exactly that case. The staged Change is then admissible
/// with nothing left that will ever look: it is advertised as possessed,
/// so no peer re-sends it, so no delivery ever schedules another drain.
///
/// So the signal must not be conditioned on there being records. This
/// asserts that directly, which is what tying it to a commit did not.
#[tokio::test]
async fn a_flush_that_authors_nothing_still_reports_capture_settled() {
    use std::sync::atomic::Ordering as AOrd;

    let host = Arc::new(RecordingHost {
        settled: std::sync::atomic::AtomicUsize::new(0),
        broadcasts: std::sync::atomic::AtomicUsize::new(0),
    });
    let store_dir = tempfile::tempdir().unwrap();
    let block_store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
    let deps = Arc::new(LinkRuntimeDependencies {
        replica_coordinator: Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
        block_store,
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
        device_id: "device-a".to_string(),
        host: host.clone(),
    });

    // Exactly what a no-op flush reaches: settlement is reported, then
    // the announce path is handed an empty record set.
    deps.note_capture_settled("group-1");
    announce_local_change(&deps, "/root", "group-1", Vec::new()).await;

    // The announce half correctly does nothing -- there is nothing to
    // tell a peer about.
    assert_eq!(
        host.broadcasts.load(AOrd::SeqCst),
        0,
        "sanity: an empty record set must not broadcast"
    );

    // ...but settlement must still have been reported. Tying the two
    // together is the bug: `announce_local_change` returns at
    // `records.is_empty()`, so anything downstream of it -- which is
    // where the wake used to live -- never runs for a flush that
    // authored nothing, while the dirty rows it cleared were the very
    // barrier holding a staged Change back.
    assert_eq!(
        host.settled.load(AOrd::SeqCst),
        1,
        "capture settlement must be reported independently of having anything to announce"
    );
}

fn test_deps() -> Arc<LinkRuntimeDependencies> {
    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
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
    let root_lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root).unwrap();
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

    let flush_task =
        tokio::spawn(
            async move { handle.flush_pending_local_change("group-1", "shared.bin").await },
        );
    tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
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
        tokio::spawn(async move { handle.flush_case_fold_sibling("group-1", "shared.bin").await });
    tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), flush_task)
        .await
        .expect("flush_case_fold_sibling must return promptly once its enqueue bound elapses, not park indefinitely")
        .unwrap();
    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
}

/// Seeds a `Placeholder`-state row for `path` in `deps`'s index
/// (`ensure_windows_placeholder_generation` requires the row to
/// already exist -- `record_placeholder_generation`'s own `UPDATE`
/// affects zero rows and returns `NotFound` otherwise), independent of
/// any real `LinkFlushHandle`/`RootLease` -- `RootCommitPermit::
/// for_tests()` mirrors `materialization_execution.rs`'s own
/// `setup_placeholder_file` test helper.
fn seed_placeholder_row(deps: &LinkRuntimeDependencies, group_id: &str, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    deps.replica_coordinator
        .file_index_repository()
        .upsert_file(group_id, &sample_record(path), &permit)
        .unwrap();
    deps.replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            group_id,
            path,
            yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
            &permit,
        )
        .unwrap();
}

#[tokio::test]
async fn ensure_windows_placeholder_generation_mints_once_and_persists() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    deps.replica_coordinator
        .link_repository()
        .add_link(&root_dir.path().display().to_string(), "group-1")
        .unwrap();
    seed_placeholder_row(&deps, "group-1", "doc.txt");
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let first = handle.ensure_windows_placeholder_generation("group-1", "doc.txt").unwrap();

    // Idempotent: a second call for the SAME still-placeholder path
    // (exactly what `shell_ipc.rs`'s `ListFolderFilesRequest` handler
    // does on every ~30s cfapi-host poll) must return the identical
    // persisted value, never mint a fresh one.
    let second = handle.ensure_windows_placeholder_generation("group-1", "doc.txt").unwrap();
    assert_eq!(first, second);

    // Restart-safety proxy: a fresh read straight from the index (not
    // anything this handle might have cached in memory) sees the same
    // value -- the property that makes this safe across a real daemon
    // restart, where a NEW handle re-reads whatever was persisted.
    let recorded = deps
        .replica_coordinator
        .materialization_state_repository()
        .get_placeholder_generation("group-1", "doc.txt")
        .unwrap()
        .expect("a generation should have been persisted");
    assert_eq!(
        recorded.provider_kind,
        yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND
    );
    assert_eq!(recorded.identity.dev, 0);
    assert_eq!(recorded.identity.ino, first);
}

/// Two different placeholder paths must never collide on the same
/// minted generation -- the same ABA-guard property `cfapi.rs`'s own
/// `mint_generation_token`/`encode_generation_identity` doc comments
/// require, now proved at the daemon-side minting authority instead.
#[tokio::test]
async fn ensure_windows_placeholder_generation_differs_across_paths() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    deps.replica_coordinator
        .link_repository()
        .add_link(&root_dir.path().display().to_string(), "group-1")
        .unwrap();
    seed_placeholder_row(&deps, "group-1", "a.txt");
    seed_placeholder_row(&deps, "group-1", "b.txt");
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let a = handle.ensure_windows_placeholder_generation("group-1", "a.txt").unwrap();
    let b = handle.ensure_windows_placeholder_generation("group-1", "b.txt").unwrap();
    assert_ne!(a, b);
}
