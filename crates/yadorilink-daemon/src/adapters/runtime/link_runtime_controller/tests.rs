#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
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

/// Retention is a version-count cap (`RETENTION_MAX_VERSIONS =
/// 10`) AND an age cap (`RETENTION_MAX_AGE_DAYS = 30`) -- a row is
/// pruned only once it is beyond BOTH. The test above already proves
/// the sweep removes aged-out SUPERSEDED history; this proves the
/// specific boundary that remains: a currently-TRASHED path's history prunes the same way,
/// without disturbing `list_trashed`'s own visibility of it.
///
/// `list_trashed`'s own doc comment is explicit that it always
/// surfaces a currently-deleted path's LATEST trashed version, not
/// every historical one -- which is exactly why that latest version
/// can never itself be the one this sweep prunes (it is always rank
/// 1 among this path's `superseded`/`trashed` rows): only OLDER
/// history goes away, never the entry `list_trashed`/`trash restore`
/// actually needs.
#[tokio::test]
async fn run_retention_expiry_sweep_prunes_old_history_without_disturbing_a_trashed_paths_visibility(
) {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    // Eleven versions (v1..v11), each `mtime_unix_nanos: 0` (1970, far
    // older than the 30-day age bound) -- then a delete, flipping v11
    // from `current` to `trashed` and inserting a fresh tombstone as
    // the path's new `current` row. Ten superseded (v1..v10) + one
    // trashed (v11) = 11 rows in {superseded, trashed}, putting v1
    // (oldest by version_seq) at rank 11, past RETENTION_MAX_VERSIONS.
    for size in 1..=11u64 {
        let mut record = sample_record("gone.jpg");
        record.size = size;
        state
            .replica_coordinator
            .file_index_repository()
            .upsert_file_with_origin("group-1", &record, "device-a", &permit)
            .unwrap();
    }
    state
        .replica_coordinator
        .file_index_repository()
        .mark_deleted("group-1", "gone.jpg", "device-a", &permit)
        .unwrap();

    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "gone.jpg").unwrap().len(),
        12,
        "11 upserts plus the delete-created tombstone"
    );
    let trashed =
        state.replica_coordinator.file_index_repository().list_trashed("group-1").unwrap();
    assert_eq!(trashed.len(), 1, "the deleted path must be visible in trash before the sweep");
    assert_eq!(trashed[0].path, "gone.jpg");

    let controller = LinkRuntimeController::new(state.clone());
    controller.run_retention_expiry_sweep();

    let remaining =
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "gone.jpg").unwrap();
    assert_eq!(remaining.len(), 11, "exactly the one version beyond the count cap is pruned");
    assert!(
        remaining.iter().all(|v| v.size != 1),
        "specifically the oldest version (size marker 1) must be the one pruned"
    );

    // The still-relevant trash entry itself must be entirely
    // unaffected -- expiry prunes stale HISTORY, never the version
    // `list_trashed`/`trash restore` actually needs.
    let trashed =
        state.replica_coordinator.file_index_repository().list_trashed("group-1").unwrap();
    assert_eq!(trashed.len(), 1, "the trashed path must still be visible after the sweep");
    assert_eq!(trashed[0].path, "gone.jpg");
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
    // A bound on a hang, not a speed assertion: the backstop-sweep test
    // scans 10,200 directories, which can take well over 10s on a loaded
    // CI runner.
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
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
    // Local edits route through `replica_coordinator` exclusively --
    // `DaemonState::new`'s
    // real provider would otherwise withhold exactly as the comment
    // above describes.
    state
        .replica_coordinator
        .set_local_policy_head_provider(std::sync::Arc::new(|_group_id| Ok([0u8; 32])));
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
        state.replica_coordinator.link_repository().suppress_tombstones_for_group(group).unwrap(),
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
        !state.replica_coordinator.link_repository().suppress_tombstones_for_group(group).unwrap(),
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

    let _reacquired = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root.path())
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

/// The disk-reconcile backstop's per-link operation
/// (`reconcile_added_files_from_disk`) is synchronous and walks the entire
/// linked folder. This pins that the sweep no longer runs it on the worker
/// that polls it.
///
/// Discriminating by construction: the runtime has exactly one worker
/// thread and the sweep runs in a spawned task (not in the test's own
/// `block_on` thread, which is not a worker and would therefore never have
/// held a core to begin with). A second spawned task loops on
/// `tokio::task::yield_now` throughout, counting how many times it gets
/// rescheduled. Run inline, the sweep's task owns the only core from the
/// moment it starts until it returns, and the counter advances zero
/// times for that whole window; offloaded, `block_in_place` hands the
/// core -- and the counter task queued on it -- to a replacement thread
/// before the walk begins, and the count keeps climbing.
///
/// Cooperative rescheduling, not a real-time ticker: an earlier version
/// of this test used a `tokio::time::sleep(1ms)` loop and compared its
/// tick rate against wall-clock elapsed time, which measured this
/// fixture correctly on Linux and macOS but failed on real
/// windows-latest CI runners even when the worker genuinely was freed --
/// confirmed via that failure's own numbers (63 ticks across 675ms,
/// ~10.7ms/tick) that Windows's own timer resolution is coarser than the
/// 1ms this test's old tolerance assumed, not that the offload stopped
/// happening. `yield_now` has no such platform-dependent floor: it is
/// rescheduled the instant the runtime's ready queue reaches it again,
/// bounded only by scheduler overhead, so the offloaded/inline gap stays
/// enormous (thousands of reschedules vs. essentially none) regardless
/// of host OS, CPU speed, or machine load.
///
/// The fixture is directories, not files, deliberately:
/// `local_change.rs`'s own `run_capture_pass_off_worker` covers the
/// per-file chunk/verify passes, which a directory never reaches, so a
/// file-based fixture would measure that offload rather than this one.
///
/// The group has no policy, so the initial scan withholds every directory
/// entry into the dirty journal and the sweep finds all 10,200 of them
/// unindexed. The dirty journal's periodic re-drive must leave those rows
/// alone while the policy is unavailable: re-capturing every one of them on
/// this same single worker would starve the counter whether or not the
/// sweep is offloaded. This test does not wait for a re-drive tick, so it
/// only catches a regression there when a tick lands inside the measured
/// sweep; the deterministic guard for that gate is
/// `redrive_leaves_withheld_paths_untouched_until_the_policy_arrives` in
/// `yadorilink-local-capture`'s `local_change` tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_disk_reconcile_backstop_sweep_does_not_hold_the_worker_that_polls_it() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let group = "group-1";
    for outer in 0..200 {
        let dir = root.path().join(format!("d{outer}"));
        std::fs::create_dir(&dir).unwrap();
        for inner in 0..50 {
            std::fs::create_dir(dir.join(format!("s{inner}"))).unwrap();
        }
    }
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group)
        .unwrap();
    start_watch_and_await_scan(&state, root.path(), group).await;

    let reschedules = Arc::new(AtomicU64::new(0));
    let counter_started = Arc::new(tokio::sync::Notify::new());
    let counter = {
        let reschedules = reschedules.clone();
        let counter_started = counter_started.clone();
        tokio::spawn(async move {
            counter_started.notify_one();
            loop {
                tokio::task::yield_now().await;
                reschedules.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    // An explicit signal that the counter task has actually started
    // (rather than a fixed delay guessed to be "surely enough"), so "no
    // reschedules" during the sweep can only mean the worker was held,
    // never that the counter task had not begun running yet.
    counter_started.notified().await;

    let controller = LinkRuntimeController::new(state.clone());
    let before = reschedules.load(Ordering::Relaxed);
    tokio::spawn(async move { controller.run_disk_reconcile_backstop_sweep().await })
        .await
        .expect("the sweep task must not panic");
    let during = reschedules.load(Ordering::Relaxed) - before;
    counter.abort();

    // A generous but still highly discriminating floor: run inline, the
    // counter task cannot be scheduled even once while the sweep holds
    // the only worker (0, plus at most a handful from unavoidable
    // scheduling slop around the spawn boundaries); offloaded, a
    // `yield_now` loop sharing a free worker for the whole multi-
    // hundred-directory walk manages many thousands. 100 sits far above
    // any plausible slop and far below any genuinely offloaded run, with
    // no dependency on wall-clock time at all.
    assert!(
        during > 100,
        "the disk-reconcile backstop's whole-folder walk ran on the worker that polls the \
         sweep: a yield-now loop sharing the runtime's only worker was rescheduled only \
         {during} times while the sweep ran (expected at least 100)"
    );
}
