//! M5-A Pass 2: canonical 3-node topology -- N (Full Replica,
//! relay-capable, "home NAS" role conceptually), M and W (On-Demand,
//! "Mac"/"Windows" roles conceptually). Reusable base for M5-A's
//! automated acceptance passes.
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

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
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
    keypair: Arc<DeviceKeyPair>,
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
/// of the process unless aborted. Every scenario in this file must call
/// [`Self::shutdown`] (or hold this until the test's natural end, where
/// `Drop` aborts as a fallback) before returning: this file has more
/// than one `#[tokio::test]`, all running concurrently in the SAME
/// process by default, so an un-torn-down mesh from one test competes
/// for CPU/UDP sockets with a sibling test's own mesh -- the exact,
/// previously-documented failure mode `connect_two_daemons_with_handles`'s
/// own doc comment describes for `monkey_chaos.rs`'s per-iteration case.
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

/// M5-A Pass 3 scenario A/B/C (combined): all three peers direct-connect;
/// M writes a file through the real filesystem watcher; N and W converge
/// on the exact same content; W then authors its own file, and N/M
/// converge on THAT (M5-A Pass 3 scenario C, symmetric direction); N's
/// durability status is checked once a real custody-confirmation sweep
/// has run.
///
/// Both directions run in ONE test function (not two `#[tokio::test]`s
/// sharing one mesh-spawning helper) deliberately: `cargo test` runs
/// every `#[test]`/`#[tokio::test]` in a file's binary CONCURRENTLY by
/// default, and two independently-spawned 3-node meshes (6 real
/// `peer_orchestrator` reconnect-supervision loops, 6 UDP sockets, 6
/// SQLite pools) in the same process measurably starve each other's
/// handshake budget -- confirmed directly: splitting this into two
/// tests, even with orchestrator-task teardown on each, still flaked on
/// the mesh-connectivity wait under concurrent execution. One mesh per
/// process avoids the contention entirely rather than chasing a resource
/// budget that will only get more contended as later M5-A passes scale
/// node count up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn happy_path_direct_convergence_and_hydration() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-happy-path-group";

    let (n, m, w, _handles) = stand_up_canonical_topology(&fake, group_id).await;

    // M authors real content through the real watcher/debounce/executor
    // path -- not a raw DB upsert (M5-A Pass 3's "real common DAG/sync
    // path" requirement).
    let path = m.root.path().join("shared.txt");
    std::fs::write(&path, b"hello from M").unwrap();

    wait_until_with_context(
        || std::fs::read(n.root.path().join("shared.txt")).ok().as_deref() == Some(b"hello from M"),
        Duration::from_secs(30),
        || "N never converged on M's content".to_string(),
    )
    .await;

    // W is On-Demand: the file lands as a placeholder until something
    // above the platform-native boundary requests it -- in production, a
    // real OS callback (Windows FETCH_DATA / macOS "make available
    // offline"); here, the same `hydration::hydrate` entry point those
    // callbacks ultimately drive. Wait for it to land in the DAG first
    // (placeholder record present), then hydrate, then verify exact
    // bytes.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "shared.txt" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "W never saw shared.txt's DAG record".to_string(),
    )
    .await;
    yadorilink_daemon::hydration::hydrate(&w.state, group_id, "shared.txt")
        .await
        .expect("hydration should succeed once a connected peer holds the content");
    assert_eq!(
        std::fs::read(w.root.path().join("shared.txt")).unwrap(),
        b"hello from M",
        "W's hydrated content must be the exact bytes M authored"
    );

    // Genuine M4 finding, not a test bug: in THIS canonical topology N is
    // the group's ONLY full replica -- M and W are both On-Demand, so
    // neither is a durability holder. `classify()`'s `Protected` path
    // deliberately requires an OTHER confirmed full-replica peer, never
    // this device's own local completeness alone (the exact conflation
    // the M4 audit closed -- see `durability_service.rs`'s own doc
    // comment). With no other full-replica peer configured, this is
    // structurally `AtRisk`: a single point of failure, correctly
    // reported as such -- "one full copy on an always-on device" is only
    // `Protected` once a SECOND full replica (or a fresh peer handoff
    // confirmation) exists. A real custody-confirmation sweep (the same
    // call `DurabilityConfirmationJob` makes periodically in production)
    // must positively confirm this, not just leave it at the
    // never-swept-yet default.
    n.state.refresh_custody_confirmation(group_id).await;
    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::AtRisk,
        "a lone full-replica anchor with no other full-replica peer must read AtRisk, \
         never Protected, from its own local completeness alone"
    );

    // Symmetric direction (M5-A Pass 3 scenario C): W authors content;
    // N and M converge on it.
    let path = w.root.path().join("from-w.txt");
    std::fs::write(&path, b"hello from W").unwrap();

    wait_until_with_context(
        || std::fs::read(n.root.path().join("from-w.txt")).ok().as_deref() == Some(b"hello from W"),
        Duration::from_secs(30),
        || "N never converged on W's content".to_string(),
    )
    .await;
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "from-w.txt" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || "M never saw from-w.txt's DAG record".to_string(),
    )
    .await;
    yadorilink_daemon::hydration::hydrate(&m.state, group_id, "from-w.txt")
        .await
        .expect("hydration should succeed once a connected peer holds the content");
    assert_eq!(
        std::fs::read(m.root.path().join("from-w.txt")).unwrap(),
        b"hello from W",
        "M's hydrated content must be the exact bytes W authored"
    );

    // Read-model truthfulness through the REAL wire boundary -- the exact
    // surface the CLI/desktop app actually read, not `DaemonState`
    // internals (`queries::link_status`'s canonical types are
    // deliberately `pub(crate)`; going through the real control socket,
    // same as `desktop_status_parity.rs`/`storage_mode_orchestration.rs`
    // already do, exercises `control_socket.rs`'s wire-conversion
    // functions too, closing the gap an earlier draft of this test left
    // -- M5-A Pass 3's "CLI/desktop-facing semantic status model"
    // requirement).
    let socket_dir = tempfile::tempdir().unwrap();
    let control_socket_path = socket_dir.path().join("w-daemon.sock");
    let serve_path = control_socket_path.clone();
    let w_state_for_serve = w.state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(
                w_state_for_serve,
            )),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = tokio::net::UnixStream::connect(&control_socket_path).await.unwrap();
    yadorilink_ipc_proto::framing::write_message(
        &mut stream,
        &yadorilink_ipc_proto::daemonctl::DaemonControlRequest {
            payload: Some(
                yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload::Status(
                    yadorilink_ipc_proto::daemonctl::StatusRequest {},
                ),
            ),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    let resp = yadorilink_ipc_proto::framing::read_message::<
        yadorilink_ipc_proto::daemonctl::DaemonControlResponse,
    >(&mut stream)
    .await
    .unwrap()
    .unwrap();
    let Some(yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload::Status(status)) =
        resp.payload
    else {
        panic!("expected a Status response, got {:?}", resp.payload);
    };
    let w_link = status
        .links
        .iter()
        .find(|l| l.group_id == group_id)
        .expect("W's real control socket must report the shared group");
    assert_eq!(
        w_link.local_storage_state(),
        yadorilink_ipc_proto::daemonctl::LocalStorageState::OnDemand,
        "W's wire-reported local storage state must truthfully be OnDemand"
    );
    assert_eq!(
        w_link.fetch_availability(),
        yadorilink_ipc_proto::daemonctl::FetchAvailability::AvailableNow,
        "W has both files fully hydrated locally now, so fetch_availability must read \
         AvailableNow through the real wire boundary"
    );
}
