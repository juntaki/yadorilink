//! Chaos test: per the "Coordination Plane Availability Independence"
//! requirement, two devices that already hold a valid netmap and an
//! established peer session must keep syncing directly with each other even
//! after the coordination plane becomes completely unreachable — it is only
//! needed for new pairings, ACL changes, and endpoint-candidate refresh.
//!
//! This drives the real daemon stack (real `DaemonState` +
//! `link_manager::start_link_watch` + `peer_orchestrator::run`, discovering
//! its peer from the in-process fake coordination plane's netmap) rather than
//! the lighter-weight `connect_two_daemons` pairing, so the coordination-plane
//! outage is a genuine outage of the seam the orchestrator actually depends on:
//! taking the fake down aborts its listener (future reconnects fail) and closes
//! every live netmap WebSocket, exactly as a real plane vanishing would.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{daemon_status_summary, register_with_fake, wait_until, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::{link_manager, peer_orchestrator};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_transport::DeviceKeyPair;

struct TestDaemon {
    state: Arc<DaemonState>,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the process
    // tears the temp dir down on exit.
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { state }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(state.clone(), local_path, group_id.to_string()).unwrap();
}

/// Diagnostic-only: one device's index state for `path` -- distinguishes
/// "never arrived in the index at all" (delivery/DAG-admission never
/// reached it) from "indexed but not materialized" (e.g. stuck
/// `Hydrating`/`Placeholder`, or held) from "DAG head advanced, index says
/// live, but the bytes never landed on disk" (a materialization bug).
/// Mirrors `monkey_chaos.rs`'s `describe_index_state`.
fn describe_index_state(state: &DaemonState, group_id: &str, path: &str) -> String {
    let record = state.sync_state.get_file(group_id, path);
    let materialization = state.sync_state.get_materialization_state(group_id, path);
    let held = state.sync_state.get_held_state(group_id, path);
    let heads = state
        .sync_state
        .dag_group_heads(group_id)
        .map(|hs| hs.iter().map(|h| h.to_hex()).collect::<Vec<_>>());
    format!(
        "record={record:?} materialization={materialization:?} held={held:?} \
         dag_group_heads={heads:?}"
    )
}

fn spawn_orchestrator(
    coordination_addr: String,
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, keypair, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_keep_syncing_after_coordination_plane_goes_unreachable() {
    let _ = tracing_subscriber::fmt::try_init();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let fake_host = fake.addr().trim_start_matches("http://").to_string();

    let keypair_a = Arc::new(DeviceKeyPair::generate());
    let keypair_b = Arc::new(DeviceKeyPair::generate());
    let device_a_id = "device-a";
    let device_b_id = "device-b";
    let group_id = "chaos-group";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, keypair_a.public_bytes(), &[group_id])
        .await;
    register_with_fake(&fake, &daemon_b.state, device_b_id, keypair_b.public_bytes(), &[group_id])
        .await;

    // Seed the healthy-sync probe before linking so the deterministic initial
    // scan captures it. Watcher behavior is exercised by the post-outage
    // writes below; this probe only establishes the pre-outage baseline.
    std::fs::write(root_a.path().join("before-outage.txt"), b"synced while healthy").unwrap();
    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_b.state, root_b.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), keypair_a, daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), keypair_b, daemon_b.state.clone());

    // Establish both peer sessions before checking the healthy-sync probe.
    wait_until_with_context(
        || {
            daemon_a
                .state
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(device_b_id)
                && daemon_b
                    .state
                    .sessions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains_key(device_a_id)
        },
        Duration::from_secs(60),
        || {
            format!(
                "peer sessions did not connect\ndaemon-a: {}\ndaemon-b: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state)
            )
        },
    )
    .await;

    // Confirm an initial sync works *before* the outage.
    wait_until_with_context(
        || root_b.path().join("before-outage.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "initial sync failed\ndaemon-a: {}\ndaemon-b: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state)
            )
        },
    )
    .await;

    // Confirm the LIVE watcher -> debounce -> DAG-emit -> announce path also
    // works before the outage, not just the initial-scan path
    // `before-outage.txt` exercised above. Without this, a post-outage sync
    // failure below is ambiguous between "coordination unavailability broke
    // peer sync" (what this test exists to catch) and "the live watcher
    // pipeline has an unrelated bug" (this test's post-outage writes would
    // otherwise be the *first* time either device's live watcher is
    // exercised at all in this scenario) -- indistinguishable failure modes
    // without a working live-watcher baseline recorded first.
    std::fs::write(root_a.path().join("live-before-outage.txt"), b"live watcher works").unwrap();
    wait_until_with_context(
        || root_b.path().join("live-before-outage.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "pre-outage LIVE watcher sync failed (coordination plane is still up here -- \
                 this isolates a live-watcher-pipeline bug from a coordination-availability bug)\n\
                 daemon-a: {}\ndaemon-b: {}\ndaemon-a live-before-outage.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "live-before-outage.txt"),
            )
        },
    )
    .await;

    // Simulate the coordination plane vanishing completely: abort its accept
    // loop (freeing the port, so every future reconnect fails immediately —
    // connection refused, not just slow) and drop every live netmap
    // subscription.
    fake.shutdown();
    wait_until(
        || {
            std::net::TcpStream::connect_timeout(
                &fake_host.parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_err()
        },
        Duration::from_secs(5),
    )
    .await;

    // The already-established peer session must keep working in both
    // directions with no coordination plane involved at all.
    std::fs::write(root_a.path().join("after-outage-from-a.txt"), b"a keeps syncing").unwrap();
    std::fs::write(root_b.path().join("after-outage-from-b.txt"), b"b keeps syncing").unwrap();

    wait_until_with_context(
        || root_b.path().join("after-outage-from-a.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "post-outage A-to-B sync failed\ndaemon-a: {}\ndaemon-b: {}\n\
                 daemon-a after-outage-from-a.txt: {}\ndaemon-b after-outage-from-a.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "after-outage-from-a.txt"),
                describe_index_state(&daemon_b.state, group_id, "after-outage-from-a.txt"),
            )
        },
    )
    .await;
    wait_until_with_context(
        || root_a.path().join("after-outage-from-b.txt").exists(),
        Duration::from_secs(30),
        || {
            format!(
                "post-outage B-to-A sync failed\ndaemon-a: {}\ndaemon-b: {}\n\
                 daemon-a after-outage-from-b.txt: {}\ndaemon-b after-outage-from-b.txt: {}",
                daemon_status_summary(&daemon_a.state),
                daemon_status_summary(&daemon_b.state),
                describe_index_state(&daemon_a.state, group_id, "after-outage-from-b.txt"),
                describe_index_state(&daemon_b.state, group_id, "after-outage-from-b.txt"),
            )
        },
    )
    .await;

    assert_eq!(
        std::fs::read(root_b.path().join("after-outage-from-a.txt")).unwrap(),
        b"a keeps syncing"
    );
    assert_eq!(
        std::fs::read(root_a.path().join("after-outage-from-b.txt")).unwrap(),
        b"b keeps syncing"
    );
}
