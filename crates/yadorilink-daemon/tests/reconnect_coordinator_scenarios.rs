//! M3 Pass 3 acceptance: the `ReconnectCoordinator` (a single global
//! semaphore bounding how many peer supervisors may be mid-handshake-attempt
//! at once, see `peer_orchestrator::NetmapDiffState::reconnect_semaphore`)
//! plus the ABA-race fix to `NetmapDiffState::channels`'s natural-session-end
//! cleanup (`remove_channel_if_current`).
//!
//! Drives the real production stack exactly like `reconnect_handshake_stress.
//! rs` and `chaos_coordination_unreachable.rs` (real `DaemonState` +
//! `LinkRuntimeController` + `peer_orchestrator::run` against an in-process
//! `FakeCoordination`), star-topology rather than full mesh: a hub device
//! plus N leaves, each leaf sharing a group with the hub ONLY (never with
//! each other) -- keeps connection count and this file's own runtime cost at
//! O(N), not O(N^2), which is exactly the N-to-1 fan-in shape Pass 1/2/3
//! measure and fix, and is also the shape a real "many peers reconnecting to
//! one already-established machine" event actually has (a laptop waking from
//! sleep, a Wi-Fi roam, a network flap).
//!
//! **What "simultaneous" means here:** `FakeCoordination::revoke` and
//! `register_device` are plain synchronous methods (no `.await` inside their
//! own body) -- calling them back-to-back in a tight loop with no `.await`
//! between iterations cannot be interleaved with anything else on this
//! task, so the whole batch really does land as one atomic moment from the
//! runtime's perspective, not merely "close together". Only the
//! `register_with_fake` re-registration loop (which does real socket setup)
//! is unavoidably sequential; that's fine, since by that point the
//! simultaneous *loss* has already landed and every affected leaf's own
//! supervisor is independently racing its own reconnect regardless of what
//! order this test happens to call `register_with_fake` in.
//!
//! **What "connection loss" means for scenario B:** this file reuses the
//! same revoke-then-reregister technique `reconnect_handshake_stress.rs`
//! itself uses as its network-blip stand-in (see that file's own module doc
//! comment) rather than inventing a lower-level socket-cut simulation --
//! consistent with this codebase's established convention for these
//! full-stack tests, and honestly documented as such here too.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{daemon_status_summary, register_with_fake, wait_until_with_context};
use tokio::task::JoinHandle;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;

// --- shared harness (mirrors reconnect_handshake_stress.rs /
// chaos_coordination_unreachable.rs; each full-stack test file in this
// crate keeps its own copy of this scaffolding by established convention,
// not shared-imported) ------------------------------------------------

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the
    // process tears the temp dir down on exit.
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon {
        device_id: device_id.to_string(),
        state,
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
    state: Arc<DaemonState>,
) -> JoinHandle<()> {
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
    })
}

/// A hub plus `n_leaves` leaves, star-topology (see this file's own module
/// doc comment). `leaf_groups[i]` is the one group leaf `i` and the hub
/// share; leaves never share a group with each other.
struct StarMesh {
    fake: FakeCoordination,
    hub: TestDaemon,
    leaves: Vec<TestDaemon>,
    leaf_groups: Vec<String>,
    // Kept alive for the mesh's lifetime -- one per hub-side group link;
    // dropping any of these would tear that link down.
    _hub_roots: Vec<tempfile::TempDir>,
}

/// `scenario`-namespaced: `peer_keys.json`'s pinning store lives at a
/// SINGLE, process-wide path (`ensure_isolated_config_dir`'s `Once`-bound
/// temp dir), shared by every `#[tokio::test]` function in this one binary
/// -- unlike every other full-stack test file in this crate, which each
/// hold exactly one such test. Two scenarios that both named a device
/// "hub" would pin two DIFFERENT real keypairs to that one device_id, and
/// whichever scenario runs second would see every connection to "hub"
/// silently torn down as a pinned-key mismatch (this was a real, first-try
/// failure in this file's own history: `reconnect_during_active_sync`
/// failing at the simplest possible 1-hub-1-leaf setup, only when run
/// after another scenario in the same process, was the tell). Every
/// scenario below MUST pass its own unique `scenario` string here.
async fn spawn_star_mesh(scenario: &str, n_leaves: usize) -> StarMesh {
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let hub = new_test_daemon(&format!("{scenario}-hub"));
    let leaf_groups: Vec<String> =
        (0..n_leaves).map(|i| format!("{scenario}-star-group-{i}")).collect();
    let hub_group_refs: Vec<&str> = leaf_groups.iter().map(String::as_str).collect();
    register_with_fake(
        &fake,
        &hub.state,
        &hub.device_id,
        &hub_group_refs,
    )
    .await;

    let mut hub_roots = Vec::with_capacity(n_leaves);
    for group in &leaf_groups {
        let root = tempfile::tempdir().unwrap();
        link(&hub.state, root.path(), group);
        hub_roots.push(root);
    }

    let mut leaves = Vec::with_capacity(n_leaves);
    for (i, group) in leaf_groups.iter().enumerate() {
        let leaf = new_test_daemon(&format!("{scenario}-leaf-{i}"));
        register_with_fake(
            &fake,
            &leaf.state,
            &leaf.device_id,
            &[group.as_str()],
        )
        .await;
        link(&leaf.state, leaf._root.path(), group);
        leaves.push(leaf);
    }

    spawn_orchestrator(fake.addr(), hub.device_id.clone(), hub.state.clone());
    for leaf in &leaves {
        spawn_orchestrator(
            fake.addr(),
            leaf.device_id.clone(),
            leaf.state.clone(),
        );
    }

    StarMesh { fake, hub, leaves, leaf_groups, _hub_roots: hub_roots }
}

async fn wait_for_star_connected(mesh: &StarMesh, timeout: Duration, context: &str) {
    wait_until_with_context(
        || {
            mesh.leaves.iter().all(|leaf| {
                mesh.hub
                    .state
                    .peers
                    .session(&leaf.device_id)
                    .is_some_and(|s| s.peer_handshake_received())
                    && leaf
                        .state
                        .peers
                        .session(&mesh.hub.device_id)
                        .is_some_and(|s| s.peer_handshake_received())
            })
        },
        timeout,
        || {
            let missing: Vec<_> = mesh
                .leaves
                .iter()
                .filter(|leaf| !mesh.hub.state.peers.has_session(&leaf.device_id))
                .map(|l| l.device_id.clone())
                .collect();
            format!(
                "star mesh did not fully connect ({context}): hub missing sessions with \
                 {missing:?}\nhub: {}",
                daemon_status_summary(&mesh.hub.state)
            )
        },
    )
    .await;
}

async fn wait_for_all_leaves_disconnected(mesh: &StarMesh, timeout: Duration, context: &str) {
    wait_until_with_context(
        || mesh.leaves.iter().all(|leaf| !mesh.hub.state.peers.has_session(&leaf.device_id)),
        timeout,
        || {
            let still_connected: Vec<_> = mesh
                .leaves
                .iter()
                .filter(|leaf| mesh.hub.state.peers.has_session(&leaf.device_id))
                .map(|l| l.device_id.clone())
                .collect();
            format!("not all leaves disconnected simultaneously ({context}): {still_connected:?}")
        },
    )
    .await;
}

// --- scenarios: 10 peers flap / 20 peers lose connection, both at once --

async fn simultaneous_flap_scenario(scenario: &str, n_leaves: usize, timeout: Duration) {
    support::ensure_isolated_config_dir();
    let mesh = spawn_star_mesh(scenario, n_leaves).await;
    wait_for_star_connected(&mesh, timeout, "initial star formation").await;

    // The simultaneous loss itself: see this file's own module doc comment
    // for why this tight, `.await`-free loop is genuinely simultaneous, not
    // merely "close together".
    for (leaf, group) in mesh.leaves.iter().zip(mesh.leaf_groups.iter()) {
        mesh.fake.revoke(&leaf.device_id, group);
    }
    wait_for_all_leaves_disconnected(&mesh, timeout, "post-revoke teardown").await;

    // Lets any packet still in flight from the torn-down generation drain
    // before the next generation's handshake starts on the same shared UDP
    // socket -- mirrors `reconnect_handshake_stress.rs`'s own fix for the
    // exact same class of stale-in-flight-packet flake.
    tokio::time::sleep(Duration::from_millis(300)).await;

    for (leaf, group) in mesh.leaves.iter().zip(mesh.leaf_groups.iter()) {
        register_with_fake(
            &mesh.fake,
            &leaf.state,
            &leaf.device_id,
            &[group.as_str()],
        )
        .await;
    }

    wait_for_star_connected(&mesh, timeout, "post-flap reconnect").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn ten_peers_flap_simultaneously() {
    simultaneous_flap_scenario("flap10", 10, Duration::from_secs(60)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn twenty_peers_lose_connection_simultaneously() {
    simultaneous_flap_scenario("flap20", 20, Duration::from_secs(90)).await;
}

// --- scenario: reconnect while a transfer is genuinely mid-flight -------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reconnect_during_active_sync() {
    support::ensure_isolated_config_dir();
    let mesh = spawn_star_mesh("midsync", 1).await;
    wait_for_star_connected(&mesh, Duration::from_secs(60), "initial formation").await;

    let leaf = &mesh.leaves[0];
    let group = &mesh.leaf_groups[0];
    let hub_root = &mesh._hub_roots[0];

    // Large enough that, on loopback, it is very unlikely to have already
    // fully landed by the time the churn below fires immediately after.
    let payload = vec![0xABu8; 8 * 1024 * 1024];
    std::fs::write(leaf._root.path().join("mid-sync.bin"), &payload).unwrap();

    // Fired immediately, with no wait for the transfer to finish -- the
    // whole point is that the revoke/reconnect below genuinely lands while
    // the file is still in flight, not after it already completed.
    mesh.fake.revoke(&leaf.device_id, group);
    wait_until_with_context(
        || !mesh.hub.state.peers.has_session(&leaf.device_id),
        Duration::from_secs(30),
        || "leaf did not disconnect after mid-sync revoke".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    register_with_fake(
        &mesh.fake,
        &leaf.state,
        &leaf.device_id,
        &[group.as_str()],
    )
    .await;

    wait_until_with_context(
        || {
            std::fs::metadata(hub_root.path().join("mid-sync.bin"))
                .map(|m| m.len() as usize == payload.len())
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || {
            format!(
                "file did not fully replicate after reconnect-during-sync churn\nhub: {}\nleaf: {}",
                daemon_status_summary(&mesh.hub.state),
                daemon_status_summary(&leaf.state),
            )
        },
    )
    .await;
    assert_eq!(std::fs::read(hub_root.path().join("mid-sync.bin")).unwrap(), payload);
}

// --- scenario: the reconnect supervisor task itself restarts ------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn reconnect_after_supervisor_restart() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group = "restart-group";

    // Namespaced device IDs -- see `spawn_star_mesh`'s own doc comment for
    // why: `peer_keys.json`'s pinning store is shared process-wide across
    // every scenario in this one test binary.
    let hub = new_test_daemon("restart-hub");
    let leaf = new_test_daemon("restart-leaf-0");
    register_with_fake(&fake, &hub.state, &hub.device_id, &[group])
        .await;
    register_with_fake(&fake, &leaf.state, &leaf.device_id, &[group])
        .await;
    let hub_root = tempfile::tempdir().unwrap();
    link(&hub.state, hub_root.path(), group);
    link(&leaf.state, leaf._root.path(), group);

    let _hub_handle = spawn_orchestrator(
        fake.addr(),
        hub.device_id.clone(),
        hub.state.clone(),
    );
    let leaf_handle = spawn_orchestrator(
        fake.addr(),
        leaf.device_id.clone(),
        leaf.state.clone(),
    );

    wait_until_with_context(
        || {
            hub.state
                .peers
                .session(&leaf.device_id)
                .is_some_and(|s| s.peer_handshake_received())
        },
        Duration::from_secs(60),
        || "initial pair did not connect".to_string(),
    )
    .await;

    // Revoked first, deliberately, so the OLD supervisor's channel tears
    // down through the real, already-tested `teardown_peer` path (not left
    // as a zombie the abort below can't reach: `PeerChannel::connect`'s own
    // background actor task is independent of `run`'s task tree, so
    // aborting the outer orchestrator task alone would NOT reliably stop
    // it). What's actually novel to THIS test is the abort immediately
    // after: it kills `run`'s own top-level task, taking its
    // `NetmapDiffState` -- and with it the `ReconnectCoordinator`'s
    // semaphore -- down with it, exactly as a real supervisor
    // crash/restart would. The freshly spawned orchestrator below gets a
    // brand-new `NetmapDiffState::new()` (a brand-new semaphore, an empty
    // `channels`/`session_tasks` map) and must still reconnect cleanly.
    fake.revoke(&leaf.device_id, group);
    wait_until_with_context(
        || !hub.state.peers.has_session(&leaf.device_id),
        Duration::from_secs(30),
        || "hub never noticed the leaf's pre-restart revoke".to_string(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    leaf_handle.abort();

    let _new_leaf_handle = spawn_orchestrator(
        fake.addr(),
        leaf.device_id.clone(),
        leaf.state.clone(),
    );
    register_with_fake(&fake, &leaf.state, &leaf.device_id, &[group])
        .await;

    wait_until_with_context(
        || {
            hub.state
                .peers
                .session(&leaf.device_id)
                .is_some_and(|s| s.peer_handshake_received())
        },
        Duration::from_secs(60),
        || {
            format!(
                "leaf did not reconnect after its own supervisor task restarted\nhub: {}",
                daemon_status_summary(&hub.state)
            )
        },
    )
    .await;
}

// --- scenario: one permanently-failing peer must not starve the rest ----

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn pathological_peer_does_not_starve_healthy_peers() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    const N_HEALTHY: usize = 5;
    let healthy_groups: Vec<String> =
        (0..N_HEALTHY).map(|i| format!("healthy-group-{i}")).collect();
    let pathological_group = "pathological-group";

    // Namespaced device IDs -- see `spawn_star_mesh`'s own doc comment for
    // why: `peer_keys.json`'s pinning store is shared process-wide across
    // every scenario in this one test binary.
    let hub = new_test_daemon("pathological-hub");
    let mut hub_groups: Vec<&str> = healthy_groups.iter().map(String::as_str).collect();
    hub_groups.push(pathological_group);
    register_with_fake(&fake, &hub.state, &hub.device_id, &hub_groups)
        .await;

    let mut hub_roots = Vec::with_capacity(N_HEALTHY + 1);
    for group in &healthy_groups {
        let root = tempfile::tempdir().unwrap();
        link(&hub.state, root.path(), group);
        hub_roots.push(root);
    }
    let pathological_root = tempfile::tempdir().unwrap();
    link(&hub.state, pathological_root.path(), pathological_group);
    hub_roots.push(pathological_root);

    let mut healthy_leaves = Vec::with_capacity(N_HEALTHY);
    for (i, group) in healthy_groups.iter().enumerate() {
        let leaf = new_test_daemon(&format!("healthy-leaf-{i}"));
        register_with_fake(
            &fake,
            &leaf.state,
            &leaf.device_id,
            &[group.as_str()],
        )
        .await;
        link(&leaf.state, leaf._root.path(), group);
        healthy_leaves.push(leaf);
    }

    // The pathological peers: registered with the fake so the hub's netmap
    // carries them as desired peers, but each pointed at its own real,
    // bound, and deliberately never-read UDP socket -- every handshake
    // initiation the hub sends any of them vanishes into genuine silence
    // (not a closed port, which can resolve faster via an ICMP unreachable
    // and would understate truly silent peers). No orchestrator is spawned
    // for any of them: they exist purely as permanently-failing targets
    // that the hub's own supervisors retry forever, repeatedly acquiring
    // and releasing the ReconnectCoordinator's global permits.
    //
    // Deliberately MORE pathological peers than
    // `RECONNECT_HANDSHAKE_CONCURRENCY` (4): with only one (this test's
    // first-draft version), 3 of the 4 global permits are always free no
    // matter what, so the healthy leaves below can connect trivially
    // regardless of whether the coordinator's fairness/bound is correct at
    // all -- that version could not fail even if the semaphore were deleted
    // entirely (a real gap caught in independent review). With enough
    // pathological peers to legitimately consume every permit at once, the
    // healthy leaves' progress genuinely depends on permits being returned
    // and fairly redistributed, not merely on some being left over.
    // `peer_orchestrator::RECONNECT_HANDSHAKE_CONCURRENCY` is private to
    // that module (not `pub`), so this is hardcoded rather than imported --
    // kept deliberately above it (+2), not merely equal to it, so the
    // healthy leaves' fair share doesn't depend on this test's own exact
    // value tracking production's constant precisely.
    const N_PATHOLOGICAL: usize = 4 + 2;
    for i in 0..N_PATHOLOGICAL {
        // Leaked deliberately: each socket must stay bound (and unread) for
        // the whole test so the hub's initiations keep vanishing into it,
        // not get rebound/reused once this scope's local drops.
        let pathological_socket: &'static std::net::UdpSocket =
            Box::leak(Box::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap()));
        // A distinct key per pathological peer, so each is its own device
        // as far as the netmap is concerned.
        let pathological_key = yadorilink_transport::DeviceSigningKeyPair::generate();
        fake.register_device(
            &format!("pathological-peer-{i}"),
            pathological_key.public_bytes(),
            pathological_key.public_bytes(),
            pathological_socket.local_addr().unwrap().to_string(),
            &[pathological_group],
        );
    }

    spawn_orchestrator(fake.addr(), hub.device_id.clone(), hub.state.clone());
    for leaf in &healthy_leaves {
        spawn_orchestrator(
            fake.addr(),
            leaf.device_id.clone(),
            leaf.state.clone(),
        );
    }

    wait_until_with_context(
        || {
            healthy_leaves.iter().all(|leaf| {
                hub.state
                    .peers
                    .session(&leaf.device_id)
                    .is_some_and(|s| s.peer_handshake_received())
            })
        },
        Duration::from_secs(60),
        || {
            format!(
                "healthy leaves did not all connect despite the pathological peer's continuous \
                 failing retries -- possible ReconnectCoordinator starvation\nhub: {}",
                daemon_status_summary(&hub.state)
            )
        },
    )
    .await;

    // `has_session` alone isn't the right check here: a `PeerSyncSession` is
    // registered as soon as `PeerChannel::connect` succeeds STRUCTURALLY
    // (channel object created), before any real handshake completes on the
    // wire -- so it's always true almost immediately regardless of whether
    // the peer ever actually answers. The real sanity signal is that the
    // handshake itself never completes.
    for i in 0..N_PATHOLOGICAL {
        assert!(
            !hub.state
                .peers
                .session(&format!("pathological-peer-{i}"))
                .is_some_and(|s| s.peer_handshake_received()),
            "sanity: pathological-peer-{i} must genuinely never complete a handshake -- \
             otherwise this test isn't exercising what it claims to"
        );
    }
}
