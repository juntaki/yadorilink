//! Full-stack revocation tests: the in-process fake coordination plane plus
//! real `peer_orchestrator::run` daemons proving the revocation flow end to
//! end: coordination-plane netmap push → daemon netmap diff →
//! `PeerSyncSession::revoke_group` wiring → sync-engine re-validation. They
//! also guard the "coordination plane availability independence" invariant for
//! already-authorized, already-connected peers.
//!
//! Uses the full daemon stack (real `DaemonState` + `link_manager::
//! start_link_watch` + `peer_orchestrator::run`, discovering peers from the
//! fake's netmap) rather than the lighter-weight `connect_two_daemons` pairing,
//! since what's under test here is the daemon-level coordination wiring itself.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::{link_manager, peer_orchestrator};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_transport::DeviceKeyPair;

static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

fn spawn_orchestrator(
    coordination_addr: String,
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
) {
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, keypair, state).await;
    });
}

/// Two devices sharing *two* groups (`group-revoked`, so the tunnel is left up
/// once one edge is revoked, and `group-control`, so there's something still-
/// authorized to prove kept working) — access is revoked against
/// `group-revoked` for device A while a real sync session is up. Proves the
/// push lands and is diffed into `removed_group_edges`, the daemon calls
/// `session.revoke_group` so `shares_group` flips, a request for that group
/// issued after the flip is refused, and the tunnel plus the other shared
/// group keep working throughout — a narrow, not a whole-device, teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_revoke_mid_session_stops_serving_the_revoked_group_but_not_others() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let keypair_a = Arc::new(DeviceKeyPair::generate());
    let keypair_b = Arc::new(DeviceKeyPair::generate());
    let device_a_id = "device-a-share-revoke";
    let device_b_id = "device-b-share-revoke";
    let group_revoked = "group-revoked";
    let group_control = "group-control";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);

    let root_a_revoked = tempfile::tempdir().unwrap();
    let root_a_control = tempfile::tempdir().unwrap();
    let root_b_revoked = tempfile::tempdir().unwrap();
    let root_b_control = tempfile::tempdir().unwrap();

    register_with_fake(
        &fake,
        &daemon_a.state,
        device_a_id,
        keypair_a.public_bytes(),
        &[group_revoked, group_control],
    )
    .await;
    register_with_fake(
        &fake,
        &daemon_b.state,
        device_b_id,
        keypair_b.public_bytes(),
        &[group_revoked, group_control],
    )
    .await;

    link(&daemon_a.state, root_a_revoked.path(), group_revoked);
    link(&daemon_a.state, root_a_control.path(), group_control);
    link(&daemon_b.state, root_b_revoked.path(), group_revoked);
    link(&daemon_b.state, root_b_control.path(), group_control);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), keypair_a, daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), keypair_b, daemon_b.state.clone());

    wait_until(
        || {
            daemon_a
                .state
                .sessions
                .lock()
                .unwrap()
                .get(device_b_id)
                .is_some_and(|session| session.change_dag_negotiated())
        },
        Duration::from_secs(40),
    )
    .await;

    // Sanity: both groups sync normally before any revocation.
    std::fs::write(root_b_revoked.path().join("before-revoke.txt"), b"synced pre-revoke").unwrap();
    wait_until(
        || root_a_revoked.path().join("before-revoke.txt").exists(),
        Duration::from_secs(40),
    )
    .await;
    std::fs::write(root_b_control.path().join("before-revoke.txt"), b"control pre-revoke").unwrap();
    wait_until(
        || root_a_control.path().join("before-revoke.txt").exists(),
        Duration::from_secs(40),
    )
    .await;

    // B's live session-to-A serves A's requests; its `shares_group` must flip.
    let session_b_to_a = {
        let sessions = daemon_b.state.sessions.lock().unwrap();
        sessions.get(device_a_id).expect("B must have a live session to A by now").clone()
    };
    assert!(session_b_to_a.shares_group(group_revoked));
    assert!(session_b_to_a.shares_group(group_control));

    fake.revoke(device_a_id, group_revoked);

    // The push → netmap diff → `session.revoke_group` wiring flips
    // `shares_group` for the revoked group within the propagation bound.
    wait_until(|| !session_b_to_a.shares_group(group_revoked), Duration::from_secs(10)).await;
    assert!(
        session_b_to_a.shares_group(group_control),
        "revoking one group edge must not affect the other shared group's authorization"
    );

    // Mid-session re-validation: a request for the now-revoked group, issued
    // after propagation is confirmed, must be refused rather than served.
    std::fs::write(root_b_revoked.path().join("after-revoke.txt"), b"must not reach A").unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !root_a_revoked.path().join("after-revoke.txt").exists(),
        "a file written to the revoked group after propagation was confirmed must never reach \
         the now-unauthorized device"
    );

    // The still-authorized control group keeps syncing, and the tunnel stays up
    // on both sides — no whole-device teardown was triggered.
    std::fs::write(root_b_control.path().join("after-revoke.txt"), b"control keeps working")
        .unwrap();
    wait_until(|| root_a_control.path().join("after-revoke.txt").exists(), Duration::from_secs(40))
        .await;
    assert!(
        daemon_a
            .state
            .peer_statuses
            .lock()
            .unwrap()
            .get(device_b_id)
            .map(|s| s.reachability.is_connected())
            .unwrap_or(false),
        "the tunnel must stay up for a group-edge-only revocation"
    );
    assert!(
        daemon_b
            .state
            .peer_statuses
            .lock()
            .unwrap()
            .get(device_a_id)
            .map(|s| s.reachability.is_connected())
            .unwrap_or(false),
        "the tunnel must stay up for a group-edge-only revocation"
    );
}

/// `device remove` while the affected peer (device A) has never once subscribed
/// to the coordination plane: device B is removed entirely while A's daemon has
/// not started yet, so when A finally subscribes its very first netmap already
/// reflects B's removal and A never establishes a session to B. Device C is an
/// unrevoked control on the same group, proving A's connection logic works and
/// B's absence is specifically the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_remove_while_peer_offline_is_reflected_on_its_next_subscribe() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let keypair_a = Arc::new(DeviceKeyPair::generate());
    let keypair_b = Arc::new(DeviceKeyPair::generate());
    let keypair_c = Arc::new(DeviceKeyPair::generate());
    let device_a_id = "device-a-offline";
    let device_b_id = "device-b-removed";
    let device_c_id = "device-c-control";
    let group_id = "shared";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_c = new_test_daemon(device_c_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_c = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, keypair_a.public_bytes(), &[group_id])
        .await;
    register_with_fake(&fake, &daemon_c.state, device_c_id, keypair_c.public_bytes(), &[group_id])
        .await;
    // B is a member, then removed entirely before A's daemon ever subscribes.
    fake.register_device(
        device_b_id,
        keypair_b.public_bytes(),
        keypair_b.public_bytes(),
        "127.0.0.1:1".to_string(),
        &[group_id],
    );
    fake.remove_device(device_b_id);

    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_c.state, root_c.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), keypair_a, daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_c_id.to_string(), keypair_c, daemon_c.state.clone());

    // Positive control: A connects normally to the still-authorized peer C.
    wait_until(
        || daemon_a.state.sessions.lock().unwrap().contains_key(device_c_id),
        Duration::from_secs(40),
    )
    .await;

    // A must never establish a session to the removed device.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !daemon_a.state.sessions.lock().unwrap().contains_key(device_b_id),
        "an offline device reconnecting after its peer was removed must never establish a \
         session to the removed device"
    );
    assert!(
        !daemon_a.state.peer_statuses.lock().unwrap().contains_key(device_b_id),
        "a removed device must never even appear as connecting/connected in peer status"
    );
}

/// The "Coordination Plane Availability Independence" invariant: two devices
/// confirm sync works, the coordination plane is then made completely
/// unreachable, and sync in both directions must keep working uninterrupted —
/// the netmap-diff re-validation wiring must never be on the peer-to-peer sync
/// path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn already_authorized_devices_keep_syncing_while_coordination_plane_is_unreachable() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let fake_host = fake.addr().trim_start_matches("http://").to_string();

    let keypair_a = Arc::new(DeviceKeyPair::generate());
    let keypair_b = Arc::new(DeviceKeyPair::generate());
    let device_a_id = "device-a-outage";
    let device_b_id = "device-b-outage";
    let group_id = "shared";

    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    register_with_fake(&fake, &daemon_a.state, device_a_id, keypair_a.public_bytes(), &[group_id])
        .await;
    register_with_fake(&fake, &daemon_b.state, device_b_id, keypair_b.public_bytes(), &[group_id])
        .await;

    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_b.state, root_b.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), keypair_a, daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), keypair_b, daemon_b.state.clone());

    wait_until(
        || {
            daemon_a
                .state
                .sessions
                .lock()
                .unwrap()
                .get(device_b_id)
                .is_some_and(|session| session.change_dag_negotiated())
        },
        Duration::from_secs(40),
    )
    .await;

    std::fs::write(root_a.path().join("before-outage.txt"), b"synced while healthy").unwrap();
    wait_until(|| root_b.path().join("before-outage.txt").exists(), Duration::from_secs(40)).await;

    // Take the coordination plane down completely.
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

    // Already-authorized, already-connected devices keep syncing both ways.
    std::fs::write(root_a.path().join("after-outage-from-a.txt"), b"a keeps syncing").unwrap();
    std::fs::write(root_b.path().join("after-outage-from-b.txt"), b"b keeps syncing").unwrap();
    wait_until(|| root_b.path().join("after-outage-from-a.txt").exists(), Duration::from_secs(40))
        .await;
    wait_until(|| root_a.path().join("after-outage-from-b.txt").exists(), Duration::from_secs(40))
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
