//! Native is the only authority: a group that already holds indexed rows
//! without a native record is refused at start, not projected under rules it was
//! never authored under.

mod support;

use std::sync::Arc;

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "legacy-group";

fn device() -> (Arc<DaemonState>, tempfile::TempDir, tempfile::TempDir, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new("device-a".to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    (state, tempfile::tempdir().unwrap(), store_dir, index_dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_with_indexed_rows_and_no_native_record_is_not_started() {
    let (state, root, _store, _index) = device();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    state
        .replica_coordinator
        .database()
        .write(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, version_seq) \
                 VALUES (?1, 'old.txt', 0, 0, '[]', 1)",
                [GROUP],
            )?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();

    let started = LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string());
    let error = started.expect_err("a legacy group must be refused");
    assert!(error.to_string().contains("before native authority"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_group_starts_and_is_recorded_native() {
    let (state, root, _store, _index) = device();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();
    let recorded = state
        .replica_coordinator
        .database()
        .write(|conn| yadorilink_sync_sqlite::group_authority::recorded_authority(conn, GROUP))
        .unwrap();
    assert_eq!(recorded.as_deref(), Some("native"));
}
