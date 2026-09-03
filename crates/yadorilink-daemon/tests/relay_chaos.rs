//! Multi-peer relay fan-in: ONE relay device forwarding for SEVERAL
//! concurrent requester-opened relay paths at once, over the same real
//! orchestrator-managed harness `relay_session_e2e.rs` uses for the
//! provider side.
//!
//! This drives the relay layer directly -- open a path per destination and
//! push a datagram down each -- rather than through a full peer connection
//! on top. That is deliberate: what is under test here is the relay's own
//! session isolation and byte accounting, so the datagrams are opaque test
//! payloads and the assertions are about which session carried which bytes.
//! `topology_relay_fan_in_reconnect_chaos.rs` covers the other half, a real
//! QUIC connection running over a relay path while connectivity flaps.
//!
//! **Scope note**: this exercises fan-in and session-isolation over real
//! sockets/sessions, not the full `dst_*.rs` madsim deterministic-
//! simulation suite (randomized seeds, fault-schedule generators,
//! network-partition/restart injection) that the rest of this crate's
//! chaos coverage runs on -- extending that generator/oracle machinery with
//! relay-aware fault scenarios is real, additional scope beyond what this
//! file covers.

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

fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state.peers.session(peer_device_id).is_some_and(|s| s.peer_handshake_received())
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
        register_with_fake(&fake, &daemon.state, &daemon.device_id, &[group_id]).await;
        link(&daemon.state, daemon._root.path(), group_id);
    }
    b.state.set_local_relay_capable(true);
    fake.set_relay_capable(&b.device_id, true);

    spawn_orchestrator(fake.addr(), a.device_id.clone(), a.state.clone());
    spawn_orchestrator(fake.addr(), b.device_id.clone(), b.state.clone());
    for c in &destinations {
        spawn_orchestrator(fake.addr(), c.device_id.clone(), c.state.clone());
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

    // Fan in: open a relay path toward all three destinations
    // concurrently, each carrying its own distinct payload.
    //
    // The payloads are sent by addressing each path's synthetic address on
    // A's own transport hub -- exactly what this device's QUIC endpoint
    // does for a relayed peer, one layer lower. Each is shaped like a QUIC
    // long-header packet (the fixed bit set in byte 0) because that is what
    // the destination's demux requires of anything it will route to a relay
    // path; nothing here depends on the destinations acting on them.
    let payloads: Vec<Vec<u8>> = (0..destinations.len())
        .map(|i| {
            let mut payload = vec![0xC0u8];
            payload.extend_from_slice(format!("payload for destination {i}").as_bytes());
            payload
        })
        .collect();
    let opens = destinations.iter().map(|c| {
        let a_state = a.state.clone();
        let device_id = c.device_id.clone();
        let peer_public = c
            .state
            .device_signing_key()
            .expect("destination has a device key")
            .verifying_key()
            .to_bytes();
        async move {
            yadorilink_daemon::relay_carrier::open_relay_path_for_test(
                &a_state,
                &device_id,
                &peer_public,
            )
            .await
        }
    });
    let opened: Vec<_> = futures_util::future::join_all(opens).await;
    assert!(
        opened.iter().all(|path| path.is_some()),
        "every destination must get a relay path: {:?}",
        opened.iter().map(|p| p.is_some()).collect::<Vec<_>>()
    );
    let opened: Vec<yadorilink_daemon::relay_carrier::OpenedRelayPath> =
        opened.into_iter().flatten().collect();

    let hub = a.state.shared_socket().expect("A has a bound transport hub");
    for (path, payload) in opened.iter().zip(payloads.iter()) {
        hub.try_send_datagram(payload, path.path.synthetic_addr())
            .expect("A's hub accepts a datagram addressed to a live relay path");
    }

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

    // Session isolation: each destination's session id is DISTINCT (no
    // accidental collapse across different destinations through the same
    // relay), and each one's forwarded-byte count matches ONLY its own
    // payload -- proving no cross-talk between concurrently-open sessions
    // sharing one relay device.
    let session_ids: Vec<u64> = opened.iter().map(|path| path.session_id).collect();
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
        // Closed on the provider directly, the same mechanism
        // `relay_session_handler::handle_relay_close` reaches, so this
        // proves the forwarder's own cleanup rather than the requester's
        // close frame reaching it.
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
