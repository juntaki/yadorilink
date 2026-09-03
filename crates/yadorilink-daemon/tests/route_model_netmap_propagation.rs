//! M3 Pass 4 acceptance: `RelayCapability` (crate::route) is sourced from
//! the real coordination-plane netmap wire path (`WsNetmapPeer::
//! relay_capable` -> `FakeCoordination`'s own `relayCapable` field ->
//! `peer_orchestrator::apply_authoritative_peer_metadata` ->
//! `DaemonState::peer_relay_capability`) end to end, through the real
//! `peer_orchestrator::run` stack -- not just the unit-level
//! `relay_capability_and_full_replica_status_are_independent` test in
//! `peer_orchestrator.rs`'s own module, which drives
//! `apply_authoritative_peer_metadata` directly and never touches the wire
//! serialization/deserialization at all. Confirms independence from
//! full-replica status the same way, but over the real wire.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_daemon::route::RelayCapability;
use yadorilink_local_storage::FsBlockStore;

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { device_id: device_id.to_string(), state, _root: tempfile::tempdir().unwrap() }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_capable_propagates_over_the_real_netmap_wire_independent_of_full_replica() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "route-model-group";

    let hub = new_test_daemon("route-model-hub");
    register_with_fake(&fake, &hub.state, &hub.device_id, &[group_id]).await;
    let hub_root = tempfile::tempdir().unwrap();
    link(&hub.state, hub_root.path(), group_id);

    // nas: relay-capable, NOT a full replica -- the "connectivity anchor,
    // not necessarily a storage anchor" case this pass's design explicitly
    // keeps separable.
    let nas = new_test_daemon("route-model-nas");
    register_with_fake(&fake, &nas.state, &nas.device_id, &[group_id]).await;
    link(&nas.state, nas._root.path(), group_id);
    fake.set_relay_capable(&nas.device_id, true);

    // archivist: a full replica, NOT relay-capable -- the reverse
    // combination, so neither role can be silently coupled to the other.
    let archivist = new_test_daemon("route-model-archivist");
    register_with_fake(&fake, &archivist.state, &archivist.device_id, &[group_id]).await;
    link(&archivist.state, archivist._root.path(), group_id);
    fake.set_full_replica(&archivist.device_id, group_id, true);

    spawn_orchestrator(fake.addr(), hub.device_id.clone(), hub.state.clone());
    spawn_orchestrator(fake.addr(), nas.device_id.clone(), nas.state.clone());
    spawn_orchestrator(fake.addr(), archivist.device_id.clone(), archivist.state.clone());

    // M3 Pass 4 (independent-review finding): both axes -- relay
    // capability AND full-replica status -- belong in the SAME wait
    // predicate. `netmap_frame_for` iterates peers and each peer's own
    // `apply_authoritative_peer_metadata` call awaits real async session
    // work in between (see peer_orchestrator.rs's own netmap-apply loop),
    // so the two devices' metadata is not guaranteed to land atomically --
    // waiting on relay capability alone and then immediately asserting
    // full-replica status separately was a genuine ordering race.
    wait_until_with_context(
        || {
            hub.state.peer_relay_capability(&nas.device_id) == RelayCapability::Capable
                && hub.state.peer_relay_capability(&archivist.device_id)
                    == RelayCapability::Disabled
                && !hub.state.peer_group_is_full_replica(&nas.device_id, group_id)
                && hub.state.peer_group_is_full_replica(&archivist.device_id, group_id)
        },
        Duration::from_secs(30),
        || {
            format!(
                "relay capability / full-replica status never propagated as expected over the \
                 real netmap wire: nas relay={:?} full_replica={} archivist relay={:?} \
                 full_replica={}",
                hub.state.peer_relay_capability(&nas.device_id),
                hub.state.peer_group_is_full_replica(&nas.device_id, group_id),
                hub.state.peer_relay_capability(&archivist.device_id),
                hub.state.peer_group_is_full_replica(&archivist.device_id, group_id),
            )
        },
    )
    .await;
}
