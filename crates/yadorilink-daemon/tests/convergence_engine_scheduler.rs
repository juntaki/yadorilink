//! Regression coverage for the Convergence Engine scheduler fix
//! (Competitive Hardening C4 finding): `run`'s own loop used to sleep a
//! full tick interval (or wait on the coarse `MaterializationWake`
//! `Notify`) after every `run_once` call, REGARDLESS of whether that
//! call's own group-processing attempts left a large, immediately-runnable
//! backlog behind -- `MAX_PATHS_PER_RECONCILE_ATTEMPT` (8, deliberately
//! unchanged here -- see `engine.rs`'s own doc comment on it) bounds one
//! ATTEMPT's worst-case latency, but nothing forced the scheduler to
//! actually rest once that attempt finished. `run_once`'s `RunOnceOutcome`/
//! `run`'s own `yield_now`-not-sleep decision is what this file exercises;
//! `run_once`'s live claim source is now `projection_obligations`, driven
//! through `process_group_via_obligations`, not the retired
//! `materialization_jobs` scheduler.
//!
//! **Scope note**: a fully hermetic, single-tick-precise test of
//! `process_group_via_obligations`'s own budget-selection boundary (e.g. "exactly 8 of 20
//! claimed jobs reach `Planning`, the other 12 are never touched at all")
//! would need either a real connected peer session constructed with no
//! concurrently-running background engine tick racing it, or a production
//! seam to inject a fake `candidate_sessions` result -- `DaemonState::new`
//! unconditionally starts `MaintenanceCoordinator` (which owns this exact
//! engine loop), and `DaemonState::build` (the maintenance-free
//! constructor) is `pub(crate)`, unreachable from this external
//! integration-test crate. This file's own tests are therefore built
//! around properties that stay deterministic even with that background
//! loop genuinely running alongside them -- a real, connected two-device
//! scenario, and a real, permanently-peerless one -- rather than
//! asserting exact per-tick job-table state.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use support::{
    connect_two_daemons, daemon_status_summary, ensure_device_signing_key, real_entry_names,
    wait_until_with_context,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::convergence::engine::run_once_for_test;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath};

const GROUP: &str = "scheduler-test-group";

fn new_device(device_id: &str) -> (Arc<DaemonState>, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    ensure_device_signing_key(&state);
    (state, store_dir)
}

/// Deterministic, no background-engine race possible: a device with NO
/// connected peer ever, for this group, takes the obligation-driven
/// scheduler's own "no candidate session shares this folder group" branch
/// every single tick -- both this test's own manual `run_once_for_test`
/// call and the background engine's automatic ticks agree on this outcome
/// regardless of interleaving, since neither can ever find a candidate
/// session. This is exactly the "zero progress" case the scheduler fix
/// must not treat as an immediate-backlog signal -- a permanently-
/// unreachable backlog must fall back to its ordinary per-path backoff/
/// retry timing, not spin the scheduler loop tight forever finding nothing
/// to do.
///
/// The backlog is seeded via a REAL DAG admission (a `Change` authored by
/// a device that is never registered as a peer session here, referencing
/// blocks this device never receives), not a direct legacy
/// `materialization_enqueue_pending` call -- `run_once` no longer reads
/// `materialization_jobs` at all post-cutover, so seeding that table alone
/// would make every claim empty and this assertion vacuously true instead
/// of genuinely exercising the "no candidate peer" durable-backoff path in
/// `process_group_via_obligations`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_progress_never_reports_an_immediate_backlog() {
    support::ensure_isolated_config_dir();
    let (state, root) = new_device("sched-lonely");
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, GROUP.to_string()).unwrap();

    let key = SigningKey::from_bytes(&[7u8; 32]);
    for i in 0..20 {
        let path = format!("unreachable-{i:03}.txt");
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![i as u8; 32]), size: 100 }],
            100,
            FileMeta {
                mtime_unix_nanos: i as i64,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("sched-remote-ghost".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(path),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        state
            .replica_coordinator
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version), true)
            .unwrap();
    }

    // Several manual ticks, not just one -- proves this holds steadily,
    // not just on the very first call before anything has settled.
    for _ in 0..5 {
        assert!(
            !run_once_for_test(&state).await,
            "a permanently unreachable backlog (no connected peer) must never report an \
             immediate backlog -- there is nothing an immediate re-drive could accomplish"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Real two-device scenario: more small files than one attempt's budget
/// (`MAX_PATHS_PER_RECONCILE_ATTEMPT`, 8) land on A before B ever links,
/// so B's initial import enqueues more materialization jobs than one tick
/// can budget. Before the scheduler fix, `run`'s loop slept a full
/// `FALLBACK_POLL_INTERVAL` (1s, or however long until the next
/// `MaterializationWake` notify) after every `run_once` call regardless
/// of how much runnable backlog remained -- syncing N files older than
/// the budget cost at least `ceil(N / 8) - 1` extra full seconds of pure
/// sleep, on top of whatever real work each tick did. This asserts
/// convergence well under that old floor, proving the scheduler is
/// actually work-conserving now rather than merely happening to finish
/// eventually.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn more_files_than_the_attempt_budget_converge_without_artificial_per_tick_sleeps() {
    support::ensure_isolated_config_dir();
    const FILE_COUNT: usize = 24;
    // The old bug's own minimum floor for this file count, purely from
    // sleeping a full second after every 8-file budget window instead of
    // draining the remaining backlog immediately -- `ceil(24/8) - 1 = 2`
    // full seconds of dead sleep alone, before any real work. Chosen from
    // the fix's own mechanism, not tuned to this environment's throughput.
    const OLD_BUG_MINIMUM_SLEEP_FLOOR: Duration = Duration::from_secs(2);

    let (state_a, root_a) = new_device("sched-a");
    let (state_b, root_b) = new_device("sched-b");

    for i in 0..FILE_COUNT {
        std::fs::write(root_a.path().join(format!("file-{i:03}.txt")), format!("content {i}"))
            .unwrap();
    }

    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, GROUP).unwrap();
    LinkRuntimeController::new(state_a.clone()).start(local_path_a, GROUP.to_string()).unwrap();
    let local_path_b = root_b.path().to_string_lossy().to_string();
    state_b.replica_coordinator.link_repository().add_link(&local_path_b, GROUP).unwrap();
    LinkRuntimeController::new(state_b.clone())
        .start(local_path_b.clone(), GROUP.to_string())
        .unwrap();

    let started = Instant::now();
    connect_two_daemons(
        &state_a,
        "sched-a",
        &state_b,
        "sched-b",
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;

    wait_until_with_context(
        || real_entry_names(root_b.path()).len() >= FILE_COUNT,
        Duration::from_secs(30),
        || {
            format!(
                "{FILE_COUNT} files never converged on B; B has {}; device A: {}; device B: {}",
                real_entry_names(root_b.path()).len(),
                daemon_status_summary(&state_a),
                daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < OLD_BUG_MINIMUM_SLEEP_FLOOR,
        "{FILE_COUNT} files (over the {}-file attempt budget) took {elapsed:?} to converge -- \
         at or above the old bug's own {OLD_BUG_MINIMUM_SLEEP_FLOOR:?} minimum floor from \
         sleeping a full tick interval after every budget window regardless of remaining \
         backlog, suggesting that regression came back",
        8,
    );
}
