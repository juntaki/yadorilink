//! M5-A Pass 2: canonical 3-node topology -- N (Full Replica,
//! relay-capable, "home NAS" role conceptually), M and W (On-Demand,
//! "Mac"/"Windows" roles conceptually). Shared, reusable base for
//! M5-A's automated acceptance passes (moved here from
//! `tests/topology_n_m_w.rs` once a second test binary needed it too --
//! integration test FILES are separate crates and cannot `use` each
//! other directly, only shared `tests/support/` modules).
//!
//! Real production code at every layer this exercises: real
//! `DaemonState`, real `peer_orchestrator`-driven `PeerChannel`/
//! WireGuard-shaped sessions over loopback UDP (same pattern as
//! `relay_chaos.rs`), real DAG mutation propagation via the real
//! filesystem watcher (`std::fs::write` on a linked local folder, not a
//! raw DB upsert -- `monkey_chaos.rs`'s established convention), real
//! `MaterializationPolicy::OnDemand` storage mode
//! (`storage_mode_orchestration.rs`'s API), real custody-confirmation
//! sweep (`DaemonState::refresh_custody_confirmation`, the same method
//! `DurabilityConfirmationJob` calls periodically in production), real
//! `group_durability_status` derivation.
//!
//! **Not** OS-native (CfAPI/File Provider) acceptance -- this proves the
//! application/daemon/transport/storage integration above the
//! platform-native boundary, not Explorer/Finder lifecycle behavior. See
//! `dst_three_device_mesh_chaos.rs` for the equivalent deterministic-
//! simulation (madsim, simulated network) coverage this complements, and
//! `relay_chaos.rs`/`relay_session_e2e.rs` for the real-transport relay
//! coverage this reuses the relay-anchor role from.
//!
//! `#![allow(dead_code)]`: every integration test FILE under `tests/` is
//! its own separate compilation unit that includes the whole `support`
//! module tree via `mod support;`, regardless of which parts it actually
//! uses -- `-D warnings` clippy (this crate's CI gate) sees every item
//! here as dead code from the perspective of any sibling test binary
//! that doesn't happen to reference `topology`, exactly like
//! `fake_coordination.rs`'s existing per-method `#[allow(dead_code)]`
//! annotations already handle for the same reason, just applied at the
//! module level here since every item in this file is in the same boat.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use super::fake_coordination::FakeCoordination;
use super::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_transport::DeviceKeyPair;

/// One node in the canonical N/M/W topology. `root` is the linked local
/// folder; kept public so scenario tests can `std::fs::write`/read
/// directly into it, exercising the real watcher/hydration path rather
/// than a bypass helper.
pub struct TopologyNode {
    pub device_id: String,
    pub state: Arc<DaemonState>,
    pub keypair: Arc<DeviceKeyPair>,
    pub root: tempfile::TempDir,
}

fn new_node(device_id: &str) -> TopologyNode {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TopologyNode {
        device_id: device_id.to_string(),
        state,
        keypair: Arc::new(DeviceKeyPair::generate()),
        root: tempfile::tempdir().unwrap(),
    }
}

fn link_eager(node: &TopologyNode, group_id: &str) {
    let local_path = node.root.path().to_string_lossy().to_string();
    node.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(node.state.clone()).start(local_path, group_id.to_string()).unwrap();
}

/// `LinkRuntimeController::start` fail-closes an `OnDemand` link unless
/// `on_demand_pipeline_is_connected()` reports a real platform-native
/// placeholder provider is wired up -- true only on real macOS/Windows
/// hardware in production. `OverrideForTest` is the test-only escape
/// hatch this crate already wires a `test-support`-feature dev-dependency
/// for; it forces the gate open for THIS THREAD only, matching this
/// function's own synchronous, one-time-at-link-start call site (not
/// re-checked on every hydration operation), so it does not need to
/// cover the multi-threaded tokio runtime's worker threads.
fn link_on_demand(node: &TopologyNode, group_id: &str) {
    let _override = yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
    let local_path = node.root.path().to_string_lossy().to_string();
    node.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    node.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&local_path, MaterializationPolicy::OnDemand)
        .unwrap();
    LinkRuntimeController::new(node.state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(
    coordination_addr: String,
    node: &TopologyNode,
) -> tokio::task::JoinHandle<()> {
    let device_id = node.device_id.clone();
    let log_device_id = device_id.clone();
    let keypair = node.keypair.clone();
    let state = node.state.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, keypair, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    })
}

/// A real handshake-complete, DAG-negotiated session exists between
/// `state` and `peer_device_id` -- the same predicate `relay_chaos.rs`
/// uses, kept identical rather than duplicated with drift.
pub fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state
        .peers
        .session(peer_device_id)
        .is_some_and(|s| s.peer_handshake_received() && s.change_dag_negotiated())
}

/// Stands up the canonical N(FullReplica,RelayCapable)/M(OnDemand)/
/// W(OnDemand) topology sharing `group_id`, spawns real orchestrators
/// for all three, and waits for full mesh connectivity (N<->M, N<->W,
/// M<->W) before returning. N is registered as the group's full-replica
/// writer with the coordination plane (`fake.set_full_replica`) and
/// marked relay-capable on both sides (`set_local_relay_capable` +
/// `fake.set_relay_capable`) so relay-fallback scenarios can use it as
/// the anchor without extra per-test setup.
pub async fn stand_up_canonical_topology(
    fake: &FakeCoordination,
    group_id: &str,
) -> (TopologyNode, TopologyNode, TopologyNode, TopologyHandles) {
    let n = new_node("topology-n-nas");
    let m = new_node("topology-m-mac");
    let w = new_node("topology-w-windows");

    for node in [&n, &m, &w] {
        register_with_fake(
            fake,
            &node.state,
            &node.device_id,
            node.keypair.public_bytes(),
            &[group_id],
        )
        .await;
    }
    link_eager(&n, group_id);
    link_on_demand(&m, group_id);
    link_on_demand(&w, group_id);

    fake.set_full_replica(&n.device_id, group_id, true);
    n.state.set_local_relay_capable(true);
    fake.set_relay_capable(&n.device_id, true);

    let orchestrators =
        [&n, &m, &w].map(|node| spawn_orchestrator(fake.addr(), node)).into_iter().collect();

    wait_until_with_context(
        || {
            fully_connected(&n.state, &m.device_id)
                && fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
        },
        Duration::from_secs(60),
        || {
            format!(
                "canonical topology never reached full mesh: n<->m={} n<->w={} m<->w={}",
                fully_connected(&n.state, &m.device_id),
                fully_connected(&n.state, &w.device_id),
                fully_connected(&m.state, &w.device_id),
            )
        },
    )
    .await;

    (n, m, w, TopologyHandles { orchestrators })
}

/// A test's own mesh-wide background tasks -- `peer_orchestrator::run`
/// runs an unbounded reconnect-supervision loop per device for the rest
/// of the process unless aborted. Every scenario using this topology
/// must call [`Self::shutdown`] (or hold this until the test's natural
/// end, where `Drop` aborts as a fallback) before returning: a test
/// binary can have more than one `#[tokio::test]`, all running
/// concurrently in the SAME process by default, so an un-torn-down mesh
/// from one test competes for CPU/UDP sockets with a sibling test's own
/// mesh -- the exact, previously-documented failure mode
/// `connect_two_daemons_with_handles`'s own doc comment describes for
/// `monkey_chaos.rs`'s per-iteration case.
pub struct TopologyHandles {
    orchestrators: Vec<tokio::task::JoinHandle<()>>,
}

impl TopologyHandles {
    pub fn shutdown(self) {
        for handle in &self.orchestrators {
            handle.abort();
        }
    }
}

impl Drop for TopologyHandles {
    fn drop(&mut self) {
        for handle in &self.orchestrators {
            handle.abort();
        }
    }
}
