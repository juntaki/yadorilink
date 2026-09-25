//! Live-daemon-lifecycle proof for authoring-identity atomicity: a real, single-device local scan+import of ~2,000
//! pre-existing files, polling the exact predicate
//! `yadorilink_sqlite_runtime::schema`'s startup check uses, and a real
//! graceful stop + reopen through the production `ReplicaCoordinator::open`
//! path (which runs that same startup check).
//!
//! Deliberately single-device: the bug under test is entirely local (the
//! transition from "file-index only" to "DAG-backed" during initial
//! scan/import), so no peer, no coordination plane, and no policy admission
//! are needed at all -- matching `large_folder_scale_sanity.rs`'s own
//! rationale for using `connect_two_daemons`'s simpler pairing instead of
//! `FakeCoordination`, taken one step further since this test does not even
//! need a second device.
//!
//! Not run in CI, same rationale as the scale sanity file this borrows its
//! `Device` setup shape from: run explicitly with `cargo test --release -p
//! yadorilink-daemon --test authoring_identity_live_proof -- --ignored --nocapture`.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use support::ensure_device_signing_key;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const FILE_COUNT: usize = 2_000;
const IMPORT_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

struct Device {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_dir: tempfile::TempDir,
    _db_dir: tempfile::TempDir,
    db_path: PathBuf,
}

fn new_device(device_id: &str) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.db");
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    ensure_device_signing_key(&state);
    Device {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        store_dir,
        _db_dir: db_dir,
        db_path,
    }
}

/// The exact predicate `yadorilink_sqlite_runtime::schema`'s startup check
/// uses (mirrored here rather than made `pub` there, matching how this
/// codebase generally keeps a private invariant private and lets a test
/// restate it deliberately -- a copy that drifts from the real check is
/// itself a signal worth seeing fail).
fn invalid_authoring_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM files f
         WHERE f.state = 'current' AND f.version_seq > 0
           AND (EXISTS(SELECT 1 FROM changes c WHERE c.group_id = f.group_id)
                OR EXISTS(SELECT 1 FROM pruned_changes pc WHERE pc.group_id = f.group_id))
           AND (f.authoring_change_hash IS NULL
                OR length(f.authoring_change_hash) != 32
                OR NOT EXISTS(
                    SELECT 1 FROM changes c
                     WHERE c.group_id = f.group_id
                       AND c.change_hash = f.authoring_change_hash
                    UNION ALL
                    SELECT 1 FROM pruned_changes pc
                     WHERE pc.group_id = f.group_id
                       AND pc.change_hash = f.authoring_change_hash
                ))",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn group_has_any_change(conn: &rusqlite::Connection, group_id: &str) -> bool {
    let changes: i64 = conn
        .query_row("SELECT COUNT(*) FROM changes WHERE group_id = ?1", [group_id], |row| row.get(0))
        .unwrap();
    let pruned: i64 = conn
        .query_row("SELECT COUNT(*) FROM pruned_changes WHERE group_id = ?1", [group_id], |row| {
            row.get(0)
        })
        .unwrap();
    changes + pruned > 0
}

fn current_row_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM files WHERE state = 'current' AND version_seq > 0",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

#[ignore = "live-daemon-lifecycle proof -- run explicitly, not in CI (see module doc)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ensure_initial_import_keeps_the_invariant_zero_from_first_dag_backed_commit_onward() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    support::ensure_isolated_config_dir();
    let group_id = "p0-2k-proof-group";

    let device = new_device("p0-2k-a");
    for i in 0..FILE_COUNT {
        let path = device.root.path().join(format!("file{i:05}.bin"));
        std::fs::write(&path, format!("payload for file {i}").repeat(8)).unwrap();
    }

    let local_path = device.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path.clone(), group_id.to_string())
        .expect("starting the link runtime for a fresh, pre-populated root");

    // Poll the SAME on-disk DB the daemon is writing (WAL mode: a second
    // connection reading concurrently is the normal, supported case, not a
    // hack) until the invariant's own precondition (the group has become
    // DAG-backed) is true, tracking whether the invariant was EVER violated
    // from that instant on, and recording the sample immediately before it
    // too (informational -- non-zero there is expected and fine).
    let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
    let mut became_dag_backed = false;
    let mut invalid_just_before_dag_backed: Option<i64> = None;
    let mut max_invalid_after_dag_backed: i64 = 0;
    let mut samples_after_dag_backed: u64 = 0;
    let deadline = tokio::time::Instant::now() + IMPORT_TIMEOUT;

    loop {
        let dag_backed_now = group_has_any_change(&poll_conn, group_id);
        let invalid_now = invalid_authoring_rows(&poll_conn);

        if dag_backed_now && !became_dag_backed {
            became_dag_backed = true;
            // `invalid_just_before_dag_backed` was already captured on the
            // previous iteration below; nothing further to do here besides
            // marking the transition.
        }
        if !became_dag_backed {
            invalid_just_before_dag_backed = Some(invalid_now);
        } else {
            samples_after_dag_backed += 1;
            max_invalid_after_dag_backed = max_invalid_after_dag_backed.max(invalid_now);
            assert_eq!(
                invalid_now, 0,
                "invariant violated: {invalid_now} current DAG-backed row(s) lack verified \
                 authoring identity, sampled after the group became DAG-backed (the live \
                 scan/import path must stamp authoring identity atomically with the row)"
            );
        }

        let done = became_dag_backed
            && current_row_count(&poll_conn) as usize >= FILE_COUNT
            && invalid_now == 0;
        if done {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "initial import did not converge within {IMPORT_TIMEOUT:?}: \
                 became_dag_backed={became_dag_backed} current_rows={} invalid_now={invalid_now}",
                current_row_count(&poll_conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    drop(poll_conn);

    assert!(became_dag_backed, "the group never became DAG-backed at all -- import did not run");
    eprintln!(
        "invariant proof: invalid_just_before_dag_backed={invalid_just_before_dag_backed:?} \
         (informational, non-zero is fine), max_invalid_after_dag_backed={max_invalid_after_dag_backed} \
         (must be 0), samples_after_dag_backed={samples_after_dag_backed}"
    );
    assert_eq!(max_invalid_after_dag_backed, 0);

    // Graceful stop, matching the original 100k test's own failed step --
    // confirm nothing regressed here at this scale with the fix in place.
    LinkRuntimeController::new(device.state.clone()).stop(&local_path).await;
    let signing_key = device.state.device_signing_key().expect("signing key was set");
    drop(device.state);

    // Real reopen through the exact production path
    // (`ReplicaCoordinator::open` -> `SyncDatabase::open` -> `init_schema`)
    // that rejected the 92,582-row database in the original 100k run.
    //
    // Retried with backoff, matching `large_folder_scale_sanity.rs`'s own
    // `restart_device` precedent: SQLite's file lock is not guaranteed
    // released the instant `LinkRuntimeController::stop`'s future resolves
    // (a background executor task can still be mid-flush), so an immediate
    // reopen attempt racing that teardown is an expected transient, not a
    // corruption finding on its own -- only a reopen that NEVER succeeds,
    // or one that succeeds onto a schema-rejected DB, is.
    let mut open_attempts = 0;
    let sync_state = loop {
        match ReplicaCoordinator::open(&device.db_path) {
            Ok(coordinator) => break Arc::new(coordinator),
            Err(error) if open_attempts < 10 => {
                open_attempts += 1;
                eprintln!(
                    "reopening the index DB failed (attempt {open_attempts}/10): {error}; retrying"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => panic!(
                "reopening the index DB failed after 10 retries: {error} -- this is exactly the \
                 startup rejection the fix was supposed to prevent"
            ),
        }
    };
    let final_conn = rusqlite::Connection::open(&device.db_path).unwrap();
    assert_eq!(
        invalid_authoring_rows(&final_conn),
        0,
        "invariant must hold after a clean reopen too"
    );

    let restarted_state = DaemonState::new(
        device.device_id.clone(),
        sync_state,
        Arc::new(SegmentBlockStore::new(device.store_dir.path()).unwrap()),
    );
    restarted_state.set_device_signing_key(signing_key);
    // Not exercised further -- reaching a clean, error-free reopen is the
    // assertion this test exists to make.
    drop(restarted_state);
}
