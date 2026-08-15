//! Minimal real two-`DaemonState` pairing, adapted from
//! `crates/yadorilink-daemon/tests/support/mod.rs`'s `connect_two_daemons_
//! with_channels` and its dependencies.
//!
//! This is a deliberate DUPLICATION, not a shared dependency:
//! `tests/support` lives under `crates/yadorilink-daemon/tests/`, which
//! Cargo only compiles for that crate's own integration-test binaries
//! (`mod support;` inside a `tests/*.rs` file) -- it is not part of
//! `yadorilink-daemon`'s library surface, so an external crate like this one
//! cannot `use` it. Extracting it into a shared `#[cfg(test)]`-free library
//! (a `yadorilink-daemon-testkit` crate, say) is a reasonable follow-up if
//! this copy and the test one drift, but is out of scope for the first
//! benchmark scenario: only the direct-pairing subset below is needed here,
//! not the other ~700 lines of matrix/chaos-test scaffolding in that file.
//! If production's peer-pairing wiring changes, mirror the change here too
//! (this file carries the same warning `spawn_paired_session` does in the
//! original).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::time::Instant;

use yadorilink_daemon::change_policy::{verify_group_policy_log, GroupPolicyLog, GroupPolicyState};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_transport::{PeerChannel, TransportHub};

/// A real, fully wired daemon under bench control: its `DaemonState`, the
/// temp directories backing its block store and sync root (kept alive for
/// the device's lifetime), and the shared transport hub the wire-bytes
/// metric reads from directly.
pub struct BenchDevice {
    pub device_id: String,
    pub state: Arc<DaemonState>,
    pub root: tempfile::TempDir,
    pub hub: Arc<TransportHub>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

/// Points every process-global config lookup at an empty, process-local temp
/// dir, exactly like the integration tests' `ensure_isolated_config_dir` --
/// see that function's doc comment for why this must run before any
/// `DaemonState` exists and must run only once per process.
pub fn ensure_isolated_config_dir() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    });
}

/// Builds one real device: fresh `FsBlockStore`, in-memory sync index,
/// change-signing key, a loopback-bound `TransportHub`, and one link
/// registered for `group_id` rooted at a fresh temp directory.
pub async fn new_device(device_id: &str, group_id: &str) -> anyhow::Result<BenchDevice> {
    ensure_isolated_config_dir();
    let store_dir = tempfile::tempdir()?;
    let store = Arc::new(FsBlockStore::new(store_dir.path())?);
    // File-backed (not `open_in_memory`, which is gated behind the
    // integration tests' `test-support` feature) -- also the same path
    // production's `app::run` uses via `ReplicaCoordinator::open`.
    let index_dir = tempfile::tempdir()?;
    let replica_coordinator =
        Arc::new(yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            index_dir.path().join("index.db"),
        )?);
    let state = DaemonState::new(device_id.to_string(), replica_coordinator, store);
    ensure_device_signing_key(&state);

    let root = tempfile::tempdir()?;
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), group_id)?;

    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let hub = TransportHub::from_socket(udp, None);
    state.set_shared_socket(hub.clone());

    Ok(BenchDevice {
        device_id: device_id.to_string(),
        state,
        root,
        hub,
        _store_dir: store_dir,
        _index_dir: index_dir,
    })
}

/// Starts the real production link-runtime (real OS filesystem watcher,
/// real debounce/scan/index pipeline) for `device`'s already-registered
/// link.
pub fn start_link_watch(device: &BenchDevice, group_id: &str) -> anyhow::Result<()> {
    let local_path = device.root.path().to_string_lossy().to_string();
    yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(
        device.state.clone(),
    )
    .start(local_path, group_id.to_string())
    .map_err(|e| anyhow::anyhow!("start_link_watch({}): {e}", device.device_id))
}

/// Pairs two already-constructed devices directly over loopback with a real
/// `PeerSyncSession` each way, waits for the change-DAG handshake to
/// negotiate, and returns the two session tasks' handles. Mirrors
/// `connect_two_daemons_with_channels` in the integration-test support
/// module -- see this file's module doc for why it is copied rather than
/// imported.
pub async fn pair_devices(
    a: &BenchDevice,
    b: &BenchDevice,
    group_id: &str,
) -> anyhow::Result<[tokio::task::JoinHandle<()>; 2]> {
    let shared_group_ids = [group_id.to_string()];
    install_bootstrap_policies(&a.state, &shared_group_ids);
    install_bootstrap_policies(&b.state, &shared_group_ids);

    let addr_a = a.hub.local_addr();
    let addr_b = b.hub.local_addr();
    let index_a = a.state.peers.session_count() as u32;
    let index_b = b.state.peers.session_count() as u32;

    let verifying_a = ensure_device_signing_key(&a.state);
    let verifying_b = ensure_device_signing_key(&b.state);

    let (secret_a, public_a) = gen_transport_keypair();
    let (secret_b, public_b) = gen_transport_keypair();
    let channel_a = Arc::new(
        PeerChannel::connect(secret_a, public_b, index_a, vec![addr_b], a.hub.clone()).await?,
    );
    let channel_b = Arc::new(
        PeerChannel::connect(secret_b, public_a, index_b, vec![addr_a], b.hub.clone()).await?,
    );

    let (session_a, handle_a) = spawn_paired_session(
        &a.state,
        &a.device_id,
        &b.device_id,
        channel_a,
        &shared_group_ids,
        verifying_b,
    );
    let (session_b, handle_b) = spawn_paired_session(
        &b.state,
        &b.device_id,
        &a.device_id,
        channel_b,
        &shared_group_ids,
        verifying_a,
    );

    wait_until(
        || session_a.change_dag_negotiated() && session_b.change_dag_negotiated(),
        Duration::from_secs(10),
    )
    .await?;

    Ok([handle_a, handle_b])
}

pub async fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while !cond() {
        if Instant::now() > deadline {
            anyhow::bail!("condition never became true within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

fn ensure_device_signing_key(state: &Arc<DaemonState>) -> [u8; 32] {
    if let Some(existing) = state.device_signing_key() {
        return existing.verifying_key().to_bytes();
    }
    let keypair = yadorilink_transport::DeviceSigningKeyPair::generate();
    let verifying = keypair.public_bytes();
    state.set_device_signing_key(keypair.signing);
    verifying
}

fn gen_transport_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn install_bootstrap_policies(state: &DaemonState, group_ids: &[String]) {
    let service_key = [1u8; 32];
    let mut policies: HashMap<String, GroupPolicyState> = state
        .replica_coordinator
        .link_repository()
        .list_links()
        .map(|links| {
            links
                .into_iter()
                .filter_map(|link| {
                    state.group_policy_state(&link.group_id).map(|p| (link.group_id, p))
                })
                .collect()
        })
        .unwrap_or_default();
    for group_id in group_ids {
        let log = GroupPolicyLog {
            group_id: group_id.clone(),
            current_seq: 0,
            current_epoch: 0,
            policy_head: vec![0; 32],
            records: Vec::new(),
        };
        let policy = verify_group_policy_log(&service_key, &log)
            .expect("empty bootstrap policy must verify");
        policies.insert(group_id.clone(), policy);
    }
    state.replace_group_policy_states(policies);
}

fn spawn_paired_session(
    state: &Arc<DaemonState>,
    local_device_id: &str,
    peer_device_id: &str,
    channel: Arc<PeerChannel>,
    shared_group_ids: &[String],
    peer_verifying_key: [u8; 32],
) -> (Arc<PeerSyncSession>, tokio::task::JoinHandle<()>) {
    state.record_peer_signing_key(peer_device_id, peer_verifying_key);
    for group_id in shared_group_ids {
        state.set_peer_group_writer(peer_device_id, group_id, true);
    }

    let sync_roots = sync_roots_for_groups(state, shared_group_ids);
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        local_device_id.to_string(),
        peer_device_id.to_string(),
        state.replica_coordinator.clone(),
        Arc::new(yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            state.block_store.clone(),
        )),
        shared_group_ids.to_vec(),
        sync_roots,
        Some(state.forward_tx.clone()),
        PeerSyncSessionDeps {
            pending_local_change_flush: state.clone(),
            change_authenticator: yadorilink_daemon::change_auth::NetmapChangeAuthenticator::new(
                state.clone(),
            ),
            handoff_lease_responder: state.clone(),
            handoff_ticket_responder: state.clone(),
            root_commit_authority_provider: state.clone(),
            ..PeerSyncSessionDeps::standalone()
        },
    );
    session.set_rate_limiters(state.rate_limiters.clone());
    session.set_block_serve_engine(state.block_serve_engine.clone());
    session.set_full_index_resync_interval(Duration::from_secs(1));
    state.set_materialization_repair_sweep_interval(Duration::from_secs(1));
    if state.disk_headroom_enforcement_enabled() {
        session.set_headroom_enforced(true);
    }
    state.peers.register_session(peer_device_id.to_string(), session.clone());
    let peer_id = peer_device_id.to_string();
    let running_session = session.clone();
    let identity_session = session.clone();
    let state_for_task = state.clone();
    let handle = tokio::spawn(async move {
        let result = running_session.run().await;
        state_for_task.peers.remove_if_current(&peer_id, &identity_session);
        if let Err(error) = result {
            tracing::error!(%error, peer = %peer_id, "paired peer session exited");
        }
    });
    (session, handle)
}

fn sync_roots_for_groups(
    state: &Arc<DaemonState>,
    group_ids: &[String],
) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    if let Ok(links) = state.replica_coordinator.link_repository().list_links() {
        for link in links {
            if group_ids.contains(&link.group_id) {
                roots.insert(link.group_id, PathBuf::from(link.local_path));
            }
        }
    }
    roots
}
