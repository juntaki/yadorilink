//! M3 Pass 7 (chaos/convergence): multi-peer relay fan-in over the same
//! real orchestrator-managed harness `relay_session_e2e.rs` (Pass 5's
//! provider side) and `relay_failover.rs` (Pass 6's requester side) each
//! already prove piecemeal -- here, ONE relay device forwarding for
//! SEVERAL concurrent requester-opened sessions at once, driven through
//! the exact same `RelayCarrier`/`RelayGrantSource` production wiring
//! Pass 6b built.
//!
//! **Scope note**: this exercises fan-in and session-isolation over real
//! sockets/sessions, not the full `dst_*.rs` madsim deterministic-
//! simulation suite (randomized seeds, fault-schedule generators,
//! network-partition/restart injection) that the rest of this crate's
//! chaos coverage runs on. No existing `dst_*.rs` scenario drives
//! `PeerChannel::connect_with_relay`/`RelayCarrier` at all yet (verified
//! by inspection) -- extending that generator/oracle machinery with
//! relay-aware fault scenarios (simulated relay-device restart, network
//! partition specifically severing a relay hop, multi-seed randomized
//! fan-in) is real, additional scope beyond what this file covers, and is
//! recorded as a follow-up rather than attempted here piecemeal.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    keypair: Arc<DeviceKeyPair>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon {
        device_id: device_id.to_string(),
        state,
        keypair: Arc::new(DeviceKeyPair::generate()),
        _root: tempfile::tempdir().unwrap(),
    }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
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

fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state
        .peers
        .session(peer_device_id)
        .is_some_and(|s| s.peer_handshake_received() && s.change_dag_negotiated())
}

/// Same adapter as `relay_session_e2e.rs`'s own `TestGrantSource` --
/// duplicated rather than shared, matching this test suite's existing
/// convention of small, file-local test doubles (see e.g. `relay_
/// failover.rs`'s own `DenyingRelayCarrier`).
struct TestGrantSource {
    fake: FakeCoordination,
    source_device_id: String,
}

impl yadorilink_daemon::relay_carrier::RelayGrantSource for TestGrantSource {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        _relay_device_id: &'a str,
        _group_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<yadorilink_daemon::relay_grant::RelayGrant>>
                + Send
                + 'a,
        >,
    > {
        let grant = self.fake.issue_relay_grant(&self.source_device_id, destination_device_id, 60);
        Box::pin(async move { grant })
    }
}

/// M3 Pass 7: one relay (B) concurrently forwarding for a requester (A)
/// reaching THREE independent destinations (C1, C2, C3) at once -- the
/// multi-peer fan-in case the pass's own scope calls for. Proves: B opens
/// exactly three DISTINCT sessions (no accidental collapse/reuse across
/// different destinations), each carries only its OWN destination's
/// bytes (no cross-talk between concurrently-open sessions sharing one
/// relay), and closing them leaves B's forwarder with zero stale/leaked
/// sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn multi_peer_fan_in_through_one_relay() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "relay-chaos-fan-in-group";

    let a = new_test_daemon("relay-chaos-a");
    let b = new_test_daemon("relay-chaos-b");
    let destinations = [
        new_test_daemon("relay-chaos-c1"),
        new_test_daemon("relay-chaos-c2"),
        new_test_daemon("relay-chaos-c3"),
    ];

    for daemon in std::iter::once(&a).chain(std::iter::once(&b)).chain(destinations.iter()) {
        register_with_fake(
            &fake,
            &daemon.state,
            &daemon.device_id,
            daemon.keypair.public_bytes(),
            &[group_id],
        )
        .await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.keypair.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.keypair.clone(), b.state.clone());
    for c in &destinations {
        spawn_orchestrator(fake.addr(), c.device_id.clone(), c.keypair.clone(), c.state.clone());
    }

    wait_until_with_context(
        || {
            fully_connected(&a.state, &b.device_id)
                && destinations.iter().all(|c| fully_connected(&b.state, &c.device_id))
        },
        Duration::from_secs(60),
        || {
            format!(
                "required hops never connected: a<->b={} b<->c1={} b<->c2={} b<->c3={}",
                fully_connected(&a.state, &b.device_id),
                fully_connected(&b.state, &destinations[0].device_id),
                fully_connected(&b.state, &destinations[1].device_id),
                fully_connected(&b.state, &destinations[2].device_id),
            )
        },
    )
    .await;

    a.state.set_relay_grant_source(Arc::new(TestGrantSource {
        fake: fake.clone(),
        source_device_id: a.device_id.clone(),
    }));

    // Fan in: open (or, on any retry, reuse) a relay session toward all
    // three destinations concurrently, each carrying its own distinct
    // payload.
    let payloads: Vec<Vec<u8>> = (0..destinations.len())
        .map(|i| format!("payload for destination {i}").into_bytes())
        .collect();
    let sends = destinations.iter().zip(payloads.iter()).map(|(c, payload)| {
        let a_state = a.state.clone();
        let peer_public = c.keypair.public_bytes();
        let payload = payload.clone();
        async move {
            yadorilink_transport::RelayCarrier::send_via_relay(
                &*a_state,
                &peer_public,
                bytes::Bytes::from(payload),
            )
            .await
        }
    });
    let results = futures_util::future::join_all(sends).await;
    assert!(results.iter().all(|sent| *sent), "every destination's send must succeed: {results:?}");

    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == destinations.len(),
        Duration::from_secs(10),
        || {
            format!(
                "expected {} distinct concurrent relay sessions on B, got {}",
                destinations.len(),
                b.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;

    // Session isolation: each destination's requester-tracked session id
    // is DISTINCT (no accidental collapse across different destinations
    // through the same relay), and each one's forwarded-byte count
    // matches ONLY its own payload -- proving no cross-talk between
    // concurrently-open sessions sharing one relay device.
    let session_ids: Vec<u64> = destinations
        .iter()
        .map(|c| {
            a.state
                .requester_relay_session_id_for_destination_test(&c.keypair.public_bytes())
                .expect("A must have recorded a requester session for this destination")
        })
        .collect();
    let mut sorted_ids = session_ids.clone();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    assert_eq!(
        sorted_ids.len(),
        destinations.len(),
        "every destination must get its own distinct relay session id, got {session_ids:?}"
    );
    for (session_id, payload) in session_ids.iter().zip(payloads.iter()) {
        wait_until_with_context(
            || {
                b.state.relay_forwarder.session_bytes_forwarded(*session_id)
                    == Some(payload.len() as u64)
            },
            Duration::from_secs(10),
            || {
                format!(
                    "session {session_id} forwarded {:?} bytes, expected exactly {} (no cross-talk)",
                    b.state.relay_forwarder.session_bytes_forwarded(*session_id),
                    payload.len()
                )
            },
        )
        .await;
    }

    // Full lifecycle: closing every session leaves zero stale/leaked
    // entries on B's forwarder.
    for session_id in &session_ids {
        // No public "close as requester" API exists yet (Pass 7 scope,
        // not Pass 6's) -- close directly via the forwarder, the same
        // mechanism `relay_session_handler::handle_relay_close` uses on
        // the provider side, to prove cleanup itself works even without
        // a requester-initiated close frame.
        b.state.relay_forwarder.close_session(*session_id, "test_complete");
    }
    wait_until_with_context(
        || b.state.relay_forwarder.active_session_count() == 0,
        Duration::from_secs(10),
        || {
            format!(
                "B did not clean up all fan-in sessions (active_session_count={})",
                b.state.relay_forwarder.active_session_count()
            )
        },
    )
    .await;
}
