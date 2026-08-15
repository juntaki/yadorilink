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
/// than a bypass helper. `store_path`/`db_path` are real on-disk
/// locations (never in-memory) SPECIFICALLY so [`restart_node`] can
/// reopen the exact same persisted state a real daemon restart would --
/// `ReplicaCoordinator::open_in_memory()` (this file's own earlier,
/// restart-incapable version) loses everything the moment the
/// `DaemonState` is dropped, which would make any restart scenario
/// vacuous by construction.
pub struct TopologyNode {
    pub device_id: String,
    pub state: Arc<DaemonState>,
    pub keypair: Arc<DeviceKeyPair>,
    pub root: tempfile::TempDir,
    /// Own the block-store and index-DB temp directories for this node's
    /// whole lifetime (across any number of `restart_node` calls) so they
    /// are cleaned up on drop -- an earlier version of this struct leaked
    /// both via `Box::leak` (needed then for a `&'static Path` this struct
    /// no longer holds), permanently littering the OS temp directory on
    /// every test run.
    store_dir: tempfile::TempDir,
    db_dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    /// This device's change-history signing identity -- kept here
    /// (rather than only living inside `DaemonState`, which never
    /// persists it: `DaemonState::device_signing_key` is a plain
    /// in-memory `Mutex<Option<SigningKey>>`) SPECIFICALLY so
    /// [`restart_node`] can re-apply the SAME key to the fresh
    /// `DaemonState`. A real device restart reloads its persistent
    /// identity key from `key_secret_store` (OS keyring); without this,
    /// a "restarted" node here would get a brand-new RANDOM signing key
    /// from `support::ensure_device_signing_key`'s own generate-if-unset
    /// fallback, and every change it retained/authored before the
    /// restart would then fail signature verification against its own
    /// (wrong) new identity -- a test-harness gap, not a production one,
    /// confirmed by tracing `yadorilink_daemon::change_auth`'s own
    /// "signature does not verify against the claimed device key" error
    /// during M5-A Pass 5 restart-convergence testing.
    signing_key: ed25519_dalek::SigningKey,
}

pub fn new_node(device_id: &str) -> TopologyNode {
    // Suffixed with a per-process-unique counter: `ensure_isolated_config_
    // dir` gives each TEST BINARY (process) its own isolated pin-file
    // directory, but a test binary with more than one `#[tokio::test]`
    // function runs them CONCURRENTLY in that SAME process by default --
    // two such tests both calling `stand_up_canonical_topology` would
    // otherwise mint the exact same literal device ids
    // ("topology-n-nas"/etc.) with DIFFERENT randomly-generated keys, and
    // race each other writing the SAME shared `peer_keys.json`/`signing_
    // keys.json` pin files, corrupting whichever one loses the race with
    // a "key changed from pinned value; refusing connection" error --
    // confirmed as the actual cause of `m_restart_recovers_and_resyncs_
    // with_both_peers`/`w_restart_...`/`n_restart_...` all failing when
    // this file grew from one `#[tokio::test]` to three. No other file
    // using this module has more than one test function per binary
    // (each of those is its own separate process), so this was never
    // triggered until now; suffixing here (rather than serializing the
    // tests) keeps them running concurrently, matching this crate's
    // established convention elsewhere.
    static NODE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NODE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let device_id = format!("{device_id}-{unique}");
    let device_id = device_id.as_str();
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.db");
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    let signing_key = yadorilink_transport::DeviceSigningKeyPair::generate().signing;
    state.set_device_signing_key(signing_key.clone());
    TopologyNode {
        device_id: device_id.to_string(),
        state,
        keypair: Arc::new(DeviceKeyPair::generate()),
        root: tempfile::tempdir().unwrap(),
        signing_key,
        store_dir,
        db_dir,
        db_path,
    }
}

/// Simulates a real daemon restart for one topology node: stops the old
/// node's link runtime (watcher/debounce/executor/repair tasks --
/// `LinkRuntimeController::stop`, the SAME real teardown production/
/// `monkey_chaos.rs` use, awaited to genuine completion, not just
/// fire-and-abort), drops the old `DaemonState` (the caller's own
/// `TopologyHandles` must ALSO be torn down for the old node's
/// orchestrator -- see that struct's own doc comment for why a plain
/// `JoinHandle` abort used to leave the old node's per-peer supervisors,
/// and the `Arc<DaemonState>`/`ReplicaCoordinator` they hold, running
/// concurrently with the "restarted" node), and rebuilds a fresh
/// `DaemonState` against the EXACT SAME on-disk block store and index
/// DB, preserving device identity (id + transport keypair + signing key,
/// exactly like a real device restarting keeps its own key material) and
/// the same linked local folder. The caller is responsible for
/// re-registering with the coordination plane and re-spawning an
/// orchestrator for the returned node -- this function only performs the
/// state-reload half of a restart, matching how `DaemonState::new`
/// itself is the real production restart entry point (it reads
/// persisted latches/policy straight from the reopened
/// `ReplicaCoordinator`).
pub async fn restart_node(node: TopologyNode) -> TopologyNode {
    LinkRuntimeController::new(node.state.clone()).stop(&node.root.path().to_string_lossy()).await;
    let store = Arc::new(FsBlockStore::new(node.store_dir.path()).unwrap());
    // Bounded retry: the OLD generation's SQLite connection pool can still
    // be mid-close (a genuine, if narrow, race between `stop()` above
    // returning and its underlying `r2d2` pool actually releasing its file
    // lock) -- observed as a real, reproducible "database is locked" error
    // reopening the SAME db path here, worse under concurrent CPU load
    // when several tests each restart a node at once. Retrying a few times
    // with a short backoff closes that harness-only race without masking
    // a genuine, persistent failure (still panics with the real error if
    // it never clears).
    let mut open_attempts = 0;
    let sync_state = loop {
        match ReplicaCoordinator::open(&node.db_path) {
            Ok(coordinator) => break Arc::new(coordinator),
            Err(error) if open_attempts < 10 => {
                open_attempts += 1;
                tracing::warn!(
                    %error,
                    open_attempts,
                    "restart_node: reopening the index DB failed, retrying (likely the old \
                     generation's connection pool still closing)"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("restart_node: could not reopen the index DB: {error}"),
        }
    };
    let state = DaemonState::new(node.device_id.clone(), sync_state, store);
    // Re-apply the SAME signing identity `signing_key`'s own doc comment
    // explains why: a real restart reloads this from persistent storage,
    // never generates a new one -- letting `support::ensure_device_
    // signing_key`'s generate-if-unset fallback fire here instead would
    // silently give this node a different identity than the one that
    // authored/retained its pre-restart change history.
    state.set_device_signing_key(node.signing_key.clone());
    // Resume watching every persisted link -- matching production's own
    // real startup sequence EXACTLY (`app.rs`'s own "Resume watching
    // every previously-linked folder" step: links survive a restart,
    // their watchers are simply restarted). Missing this was a real bug
    // in an earlier version of this function: a fresh `DaemonState` has
    // the link ROW in its reopened database, but no active
    // `LinkRuntimeController` watching the folder until something calls
    // `start` again -- so this device's OWN local writes after a
    // "restart" never even reached the DAG. `OverrideForTest` is applied
    // unconditionally (harmless for an Eager link, required for
    // OnDemand) rather than duplicating `link_on_demand`'s own policy
    // branch here.
    let links = state.replica_coordinator.link_repository().list_links().unwrap();
    for link in links.iter().filter(|l| !l.orphaned) {
        let _override = yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable();
        LinkRuntimeController::new(state.clone())
            .start(link.local_path.clone(), link.group_id.clone())
            .unwrap();
    }
    TopologyNode {
        device_id: node.device_id,
        state,
        keypair: node.keypair,
        root: node.root,
        store_dir: node.store_dir,
        db_dir: node.db_dir,
        db_path: node.db_path,
        signing_key: node.signing_key,
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
pub fn link_on_demand(node: &TopologyNode, group_id: &str) {
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

/// Spawns `node`'s orchestrator on a DEDICATED child Tokio runtime,
/// returned so the caller's `TopologyHandles` can later kill it and
/// everything it transitively spawned in one shot.
///
/// `peer_orchestrator::run` itself spawns one DETACHED (bare
/// `tokio::spawn`, no `JoinHandle` retained anywhere) per-peer
/// reconnect-supervisor task per peer (`spawn_peer_session` and its
/// madsim sibling) -- by design, matching production's own assumption
/// that these only ever stop via the whole PROCESS exiting, never a
/// supervising caller cancelling just this daemon's orchestrator layer
/// in isolation. Aborting only the top-level `run()` task (this
/// function's OWN earlier version) does NOT cascade to those detached
/// children: Tokio's `tokio::spawn` schedules an INDEPENDENT task, and
/// dropping/aborting a `JoinHandle` never aborts the task it was handed
/// out for unless that exact handle's `.abort()` is called. A restart
/// test that only aborted the top-level handle therefore left the "old"
/// node's per-peer supervisors (and everything they hold: `Arc<DaemonState>`
/// clones, the old `ReplicaCoordinator`/SQLite connection, old
/// `PeerChannel`/`PeerSyncSession` objects) running concurrently with the
/// "restarted" node's fresh ones -- confirmed as a real finding in an
/// M5-A Pass 5 Codex review of the restart-recovery fix this topology
/// exists to test.
///
/// A dedicated child runtime is the fix: every `tokio::spawn` call made
/// by code POLLED on that runtime (including `run()`'s own internal
/// spawns, and everything THEY spawn in turn) resolves to that SAME
/// runtime as its ambient context, since `tokio::spawn` always targets
/// "whichever runtime is currently driving this task" -- not the
/// runtime the calling code happened to be written in. `TopologyHandles`
/// dropping (or explicitly shutting down) that runtime therefore aborts
/// the whole tree at once, with zero production-code changes: this is a
/// pure test-harness technique, not a new production shutdown API (which
/// `peer_orchestrator` genuinely has none of today -- adding one is real,
/// separate scope beyond this restart-recovery fix).
pub fn spawn_orchestrator(
    coordination_addr: String,
    node: &TopologyNode,
) -> tokio::runtime::Runtime {
    let device_id = node.device_id.clone();
    let log_device_id = device_id.clone();
    let keypair = node.keypair.clone();
    let state = node.state.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("building a dedicated per-node orchestrator runtime must not fail in tests");
    runtime.spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, keypair, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
    runtime
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

    let orchestrators: Vec<(String, tokio::runtime::Runtime)> = [&n, &m, &w]
        .map(|node| (node.device_id.clone(), spawn_orchestrator(fake.addr(), node)))
        .into_iter()
        .collect();

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

/// A test's own mesh-wide background tasks -- each entry is the
/// dedicated child runtime [`spawn_orchestrator`] created for one node
/// (see that function's own doc comment for why a whole runtime, not
/// just a `JoinHandle`, is what's needed to actually kill everything a
/// node's orchestrator transitively spawns). Every scenario using this
/// topology must call [`Self::shutdown`] (or hold this until the test's
/// natural end, where `Drop` shuts down as a fallback) before returning:
/// a test binary can have more than one `#[tokio::test]`, all running
/// concurrently in the SAME process by default, so an un-torn-down mesh
/// from one test competes for CPU/UDP sockets with a sibling test's own
/// mesh -- the exact, previously-documented failure mode
/// `connect_two_daemons_with_handles`'s own doc comment describes for
/// `monkey_chaos.rs`'s per-iteration case.
pub struct TopologyHandles {
    orchestrators: Vec<(String, tokio::runtime::Runtime)>,
}

impl TopologyHandles {
    pub fn shutdown(mut self) {
        for (_, runtime) in self.orchestrators.drain(..) {
            shutdown_runtime(runtime);
        }
    }

    /// Removes and shuts down ONLY `device_id`'s own orchestrator
    /// runtime, leaving every other node's untouched -- required for a
    /// single-node restart scenario, where M/W must keep running (their
    /// own reconnect supervisors are what actually notice N coming back)
    /// while only N's old generation is torn down. A plain `drop(handles)`
    /// (this struct's own `Drop` impl) would incorrectly kill EVERY
    /// node's orchestrator at once -- exactly wrong for "restart just
    /// one node." Panics if `device_id` has no registered runtime --
    /// silently doing nothing here would mask exactly the class of bug
    /// this whole struct exists to prevent (a caller that assumed a
    /// node's old generation was torn down when it never was), per an
    /// M5-A Pass 5 Codex review finding.
    ///
    /// Unlike `shutdown`/`Drop` (which use `shutdown_background` -- see
    /// that function's own doc comment for why they must not block), this
    /// method genuinely WAITS for the old generation's tasks to finish
    /// (bounded, via `shutdown_timeout`) before returning: a restart
    /// scenario's very next step reopens the SAME on-disk block store and
    /// index DB the old generation's still-running `spawn_blocking` store/
    /// compression work could still be touching (a real race a Codex
    /// review round caught in an earlier version of this fix, where this
    /// method used the same non-blocking `shutdown_background` the other
    /// two do). The wait itself runs inside `spawn_blocking` -- off this
    /// async task's own worker thread -- specifically so blocking here
    /// cannot deadlock against this SAME test's outer Tokio runtime.
    pub async fn take_and_shutdown(&mut self, device_id: &str) {
        let index = self
            .orchestrators
            .iter()
            .position(|(id, _)| id == device_id)
            .unwrap_or_else(|| panic!("no registered orchestrator runtime for {device_id:?}"));
        let (_, runtime) = self.orchestrators.remove(index);
        const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let start = std::time::Instant::now();
            runtime.shutdown_timeout(SHUTDOWN_DEADLINE);
            // `shutdown_timeout` does not report whether it hit the
            // deadline -- Tokio's own docs say unfinished work and its
            // threads are simply LEAKED and keep running if it does. A
            // caller here is about to reopen the exact on-disk store/DB
            // that leaked, still-running work (e.g. a peer session's
            // `spawn_blocking` store reads/writes) could still be
            // touching, so silently returning after a hit deadline would
            // reintroduce the exact race this method exists to close.
            // Measuring elapsed time against the same deadline (with a
            // small margin so ordinary scheduling jitter right at
            // completion can't false-positive) is the only signal
            // available; a genuine timeout leaves `elapsed` at
            // approximately the full deadline, while a real completion
            // returns as soon as tasks finish, almost always well under it.
            assert!(
                start.elapsed() < SHUTDOWN_DEADLINE - Duration::from_millis(500),
                "orchestrator runtime for {device_id:?} did not fully drain within its \
                 {SHUTDOWN_DEADLINE:?} shutdown deadline -- leaked tasks may still be touching \
                 the on-disk store/DB this test is about to reopen"
            );
        })
        .await
        .expect("orchestrator runtime teardown task panicked");
    }

    /// Registers `device_id`'s orchestrator runtime (e.g. the one
    /// [`spawn_orchestrator`] returns after [`restart_node`]) so it's
    /// tracked by this struct's own `Drop`/`shutdown`/`take_and_shutdown`
    /// exactly like the original three nodes' -- required for a SECOND
    /// restart cycle to have anything to tear down, and so the fresh
    /// generation's own per-peer supervisors don't outlive the test
    /// (the exact leak this struct's own doc comment describes) just
    /// because they were spawned after the initial
    /// `stand_up_canonical_topology` call.
    pub fn insert(&mut self, device_id: String, runtime: tokio::runtime::Runtime) {
        self.orchestrators.push((device_id, runtime));
    }
}

/// `shutdown_background` (not a plain `drop`, and not
/// `shutdown_timeout`): returns immediately without blocking this
/// thread, which matters here since this runs from INSIDE the test's
/// own async runtime -- a blocking wait for another runtime's worker
/// threads to fully drain would risk an executor-on-executor deadlock if
/// anything on that thread pool is (even transitively) waiting on this
/// one. The child runtime's worker threads still exit promptly on their
/// own once their tasks observe the shutdown signal at their next yield
/// point.
fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_background();
}

impl Drop for TopologyHandles {
    fn drop(&mut self) {
        for (_, runtime) in self.orchestrators.drain(..) {
            shutdown_runtime(runtime);
        }
    }
}
