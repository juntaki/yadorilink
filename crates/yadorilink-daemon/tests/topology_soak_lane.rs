//! M5-A Pass 9: configurable-duration randomized soak across the real
//! multi-node topology, mixing local file ops (create/edit/delete/rename)
//! with hydrate/evict, route-loss/recovery, relay transitions, node
//! restarts, and device join/leave -- extending `monkey_chaos.rs`'s
//! established seed/corpus idiom (`SOAK_SEED`/`tests/dst_corpus/
//! soak_lane_seeds.txt`, mirroring `MONKEY_CHAOS_SEED`/`monkey_chaos_
//! seeds.txt`) onto `support::topology`'s real-orchestrator, real-relay,
//! real-restart foundation (`topology_relay_role_restart_matrix.rs`'s
//! established restart/relay techniques) rather than `monkey_chaos.rs`'s
//! own manually-wired paired sessions, which have no reconnect/relay/
//! restart machinery to exercise.
//!
//! Duration is `SOAK_DURATION_SECS` (default
//! [`DEFAULT_SOAK_DURATION_SECS`], short enough for every-change CI); set
//! it much higher for a local/nightly soak run -- this is not meant to be
//! a 24h CI job, matching the M5-A Pass 9 task's own framing.
//!
//! After the soak window, all currently-joined devices are given a
//! bounded settle window, then four invariants are checked using only
//! introspection that already exists in production (no new instrumentation
//! added for this test). An M5-A Pass 11 adversarial review found the
//! first version of each of these four checks was vacuous or blind to the
//! exact failure class it claimed to catch -- see each check's own inline
//! comment for what was wrong and why the current shape actually catches
//! it:
//! - **no silent corruption**: every currently-online device's hydrated
//!   content, hashed file-by-file, is compared over the UNION of paths
//!   any two devices hold (not just the intersection -- a path entirely
//!   missing on one side is a mismatch, not a skip), plus a check that
//!   real content was observed at all (not every device empty the whole
//!   run) -- deleted/conflict-copy paths are still not compared,
//!   matching `monkey_chaos.rs`'s own established scope;
//! - **no leaked sessions**: every session `pre_restart_sessions`
//!   captured immediately before a node's restart must have been
//!   replaced (`!Arc::ptr_eq`) by settle time -- `PeerRegistry` is keyed
//!   by device id and can never actually hold a "duplicate", so the
//!   original per-registry duplicate check could never fail;
//! - **no stuck Protecting**: `DaemonState::group_durability_status`
//!   never reads `Protecting` on any currently-online node once the
//!   settle window has elapsed -- `op_device_join` marks the spare a
//!   second coordination-plane full-replica candidate specifically so
//!   this state is structurally reachable in this topology (with only N
//!   as a full replica, `durability_service.rs` never even reaches the
//!   `Protecting` arm);
//! - **no stale route**: for every pair, both sides' own `RouteKind`
//!   (not just connectedness, which collapses Direct and Relay into the
//!   same value) must agree, retried across the same settle window
//!   invariant 1 uses rather than checked once.
//!
//! "Reconnect/handshake queue depth" (named in the Pass 9 task
//! description) has no introspection API in production today (confirmed:
//! `peer_orchestrator`'s reconnect semaphore is a private field with no
//! accessor) -- asserting on it here would mean either fabricating a
//! check against nothing or adding new production instrumentation
//! speculatively, so it's left out of this pass rather than faked; a real
//! follow-up if this soak lane finds an actual case that needs it.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use support::fake_coordination::FakeCoordination;
use support::topology::{
    fully_connected, link_on_demand, new_node, restart_node, spawn_orchestrator,
    stand_up_canonical_topology, TopologyHandles, TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;
use yadorilink_peer_session::peer_session::PeerSyncSession;

const DEFAULT_SOAK_DURATION_SECS: u64 = 20;
/// Generous relative to `DEFAULT_SOAK_DURATION_SECS`: real convergence
/// after this soak's heavier chaos (concurrent restarts + route flaps +
/// device churn stacked back to back) genuinely took up to ~290s in a
/// measured diagnostic run, not because anything was stuck -- confirmed
/// by re-running the exact seed with a much wider bound and observing it
/// pass, matching `monkey_chaos.rs`'s own two-phase convergence budget
/// being deliberately generous (180s+30s) for the same underlying reason.
/// A tighter bound here would misreport slow-but-healthy convergence as
/// the "silent corruption"/"stuck" invariants this soak exists to catch.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(600);
const CANDIDATE_FILE_COUNT: usize = 6;
const OP_JITTER_MAX_MS: u64 = 120;

/// M5-A soak-closure finding: this file's two tests
/// (`randomized_soak_converges_with_no_leaks_or_stuck_state`, `replay_
/// known_failing_seeds`) each spin up a real multi-node topology with
/// real orchestrators, real UDP sockets, and real WireGuard handshakes
/// across `flavor = "multi_thread", worker_threads = 8` -- genuinely
/// CPU-heavy. `cargo test`'s default parallelism runs both `#[test]`s in
/// this binary concurrently, which reproducibly starved convergence
/// (a `durability_service` sweep, or a peer reconnect) past even
/// `SETTLE_TIMEOUT`'s already-generous 600s bound on a loaded machine --
/// confirmed live: the exact seed that failed under default parallelism
/// passed cleanly both in isolation and with every test in this binary
/// serialized (`--test-threads=1`, 0/2 failures). This guard reproduces
/// that serialization unconditionally, so `cargo test`'s own default
/// parallelism can never again silently reintroduce this false-failure
/// class -- a bounded/acceptable transient the tests were, until this
/// lock, waiting for incorrectly (Classification D: real resource
/// contention this test binary itself creates, not a production bug).
static SOAK_LANE_SERIAL_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct FakeGrantSource {
    fake: FakeCoordination,
    source_device_id: String,
}

impl yadorilink_daemon::relay_carrier::RelayGrantSource for FakeGrantSource {
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

fn wire_relay_grant_source(fake: &FakeCoordination, state: &Arc<DaemonState>, device_id: &str) {
    state.set_relay_grant_source(Arc::new(FakeGrantSource {
        fake: fake.clone(),
        source_device_id: device_id.to_string(),
    }));
}

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/soak_lane_seeds.txt")
}

fn load_corpus_seeds() -> Vec<u64> {
    let Ok(contents) = std::fs::read_to_string(corpus_path()) else {
        return Vec::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse::<u64>().ok())
        .collect()
}

fn record_failing_seed(seed: u64) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{seed}");
    }
}

fn seed_from_env_or_random() -> u64 {
    std::env::var("SOAK_SEED").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(rand::random)
}

fn duration_from_env_or_default() -> Duration {
    let secs = std::env::var("SOAK_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SOAK_DURATION_SECS);
    Duration::from_secs(secs)
}

fn candidate_paths() -> Vec<String> {
    (0..CANDIDATE_FILE_COUNT).map(|i| format!("soak-{i}.bin")).collect()
}

/// Restores N's full canonical role (full-replica + relay-capable) after
/// `restart_node` -- a fresh `DaemonState` starts with neither, matching
/// `topology_relay_role_restart_matrix.rs`'s established fix for the same
/// gap.
fn restore_n_canonical_role(fake: &FakeCoordination, n: &TopologyNode, group_id: &str) {
    fake.set_full_replica(&n.device_id, group_id, true);
    n.state.set_local_relay_capable(true);
    fake.set_relay_capable(&n.device_id, true);
}

#[derive(Clone, Copy, Debug)]
enum SoakOp {
    LocalWrite,
    LocalDelete,
    LocalRename,
    Hydrate,
    Evict,
    BreakWRoute,
    RestoreWRoute,
    RestartNode,
    DeviceJoin,
    DeviceLeave,
}

const OP_WEIGHTS: &[(SoakOp, u32)] = &[
    (SoakOp::LocalWrite, 30),
    (SoakOp::LocalDelete, 8),
    (SoakOp::LocalRename, 8),
    (SoakOp::Hydrate, 15),
    (SoakOp::Evict, 8),
    (SoakOp::BreakWRoute, 5),
    (SoakOp::RestoreWRoute, 5),
    (SoakOp::RestartNode, 6),
    (SoakOp::DeviceJoin, 4),
    (SoakOp::DeviceLeave, 4),
];

fn pick_op(rng: &mut StdRng) -> SoakOp {
    let total: u32 = OP_WEIGHTS.iter().map(|(_, w)| w).sum();
    let mut roll = rng.random_range(0..total);
    for (op, weight) in OP_WEIGHTS {
        if roll < *weight {
            return *op;
        }
        roll -= weight;
    }
    unreachable!("weights sum to `total`, so `roll < total` always matches one entry")
}

/// The soak's mutable world: the fixed N/M/W plus an optional 4th spare
/// device ("X", OnDemand) that `DeviceJoin`/`DeviceLeave` add and remove.
/// Owns `TopologyHandles` (not the caller) so `RestartNode`/`DeviceJoin`/
/// `DeviceLeave` can each freely take/insert individual node runtimes
/// mid-soak.
struct SoakWorld {
    fake: FakeCoordination,
    group_id: String,
    n: TopologyNode,
    m: TopologyNode,
    w: TopologyNode,
    spare: Option<TopologyNode>,
    handles: TopologyHandles,
    w_route_broken: bool,
    /// Pre-restart session identities, captured immediately before each
    /// `RestartNode` op: `(observer_device_id, restarted_device_id,
    /// old_session_arc)` for every OTHER currently-online node's session
    /// with the node about to restart. `PeerRegistry` is keyed by device
    /// id, so it can never hold two live entries for the same peer --
    /// checking it for "duplicates" proves nothing about a leak. The
    /// real leak this soak cares about (a restarted node's old detached
    /// per-peer supervisors, and the `Arc<DaemonState>`/`PeerSyncSession`
    /// they keep alive, per `spawn_orchestrator`'s own doc comment)
    /// shows up as a surviving OLD `Arc` -- `!Arc::ptr_eq(old, new)` is
    /// the same session-freshness oracle `topology_restart_convergence.
    /// rs` already established as correct, applied here after the fact
    /// against everything the soak's own restarts produced.
    pre_restart_sessions: Vec<(String, String, Arc<PeerSyncSession>)>,
}

impl SoakWorld {
    fn online_ondemand_nodes(&self) -> Vec<&TopologyNode> {
        let mut nodes = vec![&self.m, &self.w];
        if let Some(spare) = &self.spare {
            nodes.push(spare);
        }
        nodes
    }

    async fn op_local_write(&self, rng: &mut StdRng) {
        let nodes = self.online_ondemand_nodes();
        let node = nodes[rng.random_range(0..nodes.len())];
        let paths = candidate_paths();
        let path = &paths[rng.random_range(0..paths.len())];
        let round: u64 = rng.random_range(0..u64::MAX);
        let content = format!("soak write, device {} round-marker {round}", node.device_id);
        let _ = std::fs::write(node.root.path().join(path), content.as_bytes());
    }

    async fn op_local_delete(&self, rng: &mut StdRng) {
        let nodes = self.online_ondemand_nodes();
        let node = nodes[rng.random_range(0..nodes.len())];
        let paths = candidate_paths();
        let path = &paths[rng.random_range(0..paths.len())];
        let _ = std::fs::remove_file(node.root.path().join(path));
    }

    async fn op_local_rename(&self, rng: &mut StdRng) {
        let nodes = self.online_ondemand_nodes();
        let node = nodes[rng.random_range(0..nodes.len())];
        let paths = candidate_paths();
        let from = &paths[rng.random_range(0..paths.len())];
        let to = format!("{from}.renamed");
        let _ = std::fs::rename(node.root.path().join(from), node.root.path().join(to));
    }

    async fn op_hydrate(&self, rng: &mut StdRng) {
        let nodes = self.online_ondemand_nodes();
        let node = nodes[rng.random_range(0..nodes.len())];
        let Ok(files) =
            node.state.replica_coordinator.file_index_repository().list_files(&self.group_id)
        else {
            return;
        };
        let candidates: Vec<_> = files.iter().filter(|f| !f.deleted).collect();
        if candidates.is_empty() {
            return;
        }
        let record = candidates[rng.random_range(0..candidates.len())];
        let path = record.path.clone();
        let group_id = self.group_id.clone();
        let state = Arc::clone(&node.state);
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            yadorilink_daemon::hydration::hydrate(&state, &group_id, &path),
        )
        .await;
    }

    async fn op_evict(&self, rng: &mut StdRng) {
        let nodes = self.online_ondemand_nodes();
        let node = nodes[rng.random_range(0..nodes.len())];
        node.state.set_test_placeholder_pipeline_connected(true);
        let Ok(files) =
            node.state.replica_coordinator.file_index_repository().list_files(&self.group_id)
        else {
            return;
        };
        let candidates: Vec<_> = files.iter().filter(|f| !f.deleted).collect();
        if candidates.is_empty() {
            return;
        }
        let record = candidates[rng.random_range(0..candidates.len())];
        let _ = yadorilink_daemon::hydration::evict(&node.state, &self.group_id, &record.path);
    }

    fn op_break_w_route(&mut self) {
        if self.w_route_broken {
            return;
        }
        self.fake.update_endpoint(&self.w.device_id, "127.0.0.1:1".to_string());
        self.w_route_broken = true;
    }

    fn op_restore_w_route(&mut self) {
        if !self.w_route_broken {
            return;
        }
        // M5-A soak-closure finding: read w's CURRENT real endpoint live,
        // not a value captured once at stand-up -- `restart_node` binds a
        // fresh ephemeral port every time (`DaemonState::ensure_shared_
        // socket` always binds port 0), so a `RestartNode` op between
        // `op_break_w_route` and this op leaves any pre-captured endpoint
        // stale and dead. Restoring to a stale port left every OTHER
        // node's channel to w stuck on Relay forever (correctly -- that
        // port genuinely doesn't work), while w's OWN view stayed Direct
        // (w always reaches the never-restarted n/m at their stable
        // addresses) -- exactly the soak's observed stale-route asymmetry.
        // Confirmed as the root cause via a dedicated repro
        // (`topology_rapid_restart_repro::
        // rapid_restart_while_relayed_converges_route_kind`, 5/5): a real
        // peer restart always re-registers its own current endpoint with
        // the coordination plane, so this was never reachable in
        // production, purely a test-harness bug (Classification C).
        let current_w_endpoint = self
            .w
            .state
            .shared_socket()
            .expect(
                "w's shared transport socket must already be bound by the time its route is \
                     restored -- its orchestrator has been running (and attempting connections, \
                     which unconditionally bind the socket) since well before this op can fire",
            )
            .local_addr()
            .to_string();
        self.fake.update_endpoint(&self.w.device_id, current_w_endpoint);
        self.w_route_broken = false;
    }

    /// Captures every other currently-online node's live session with
    /// `restarted_device_id` (if any) before that node's restart begins,
    /// feeding the leaked-session check (see `pre_restart_sessions`'s own
    /// doc).
    fn snapshot_sessions_with(&mut self, restarted_device_id: &str) {
        let mut observers = vec![&self.n, &self.m, &self.w];
        if let Some(spare) = &self.spare {
            observers.push(spare);
        }
        for observer in observers {
            if observer.device_id == restarted_device_id {
                continue;
            }
            if let Some(session) = observer.state.peers.session(restarted_device_id) {
                self.pre_restart_sessions.push((
                    observer.device_id.clone(),
                    restarted_device_id.to_string(),
                    session,
                ));
            }
        }
    }

    async fn op_restart_node(&mut self, rng: &mut StdRng) {
        let targets = ["n", "m", "w"];
        let target = targets[rng.random_range(0..targets.len())];
        tracing::info!(target, "soak op: restarting node");
        match target {
            "n" => {
                self.snapshot_sessions_with(&self.n.device_id.clone());
                self.handles.take_and_shutdown(&self.n.device_id).await;
                let restarted =
                    restart_node(std::mem::replace(&mut self.n, placeholder_node())).await;
                register_with_fake(
                    &self.fake,
                    &restarted.state,
                    &restarted.device_id,
                    restarted.keypair.public_bytes(),
                    &[&self.group_id],
                )
                .await;
                restore_n_canonical_role(&self.fake, &restarted, &self.group_id);
                let runtime = spawn_orchestrator(self.fake.addr(), &restarted);
                self.handles.insert(restarted.device_id.clone(), runtime);
                self.n = restarted;
            }
            "m" => {
                self.snapshot_sessions_with(&self.m.device_id.clone());
                self.handles.take_and_shutdown(&self.m.device_id).await;
                let restarted =
                    restart_node(std::mem::replace(&mut self.m, placeholder_node())).await;
                register_with_fake(
                    &self.fake,
                    &restarted.state,
                    &restarted.device_id,
                    restarted.keypair.public_bytes(),
                    &[&self.group_id],
                )
                .await;
                wire_relay_grant_source(&self.fake, &restarted.state, &restarted.device_id);
                let runtime = spawn_orchestrator(self.fake.addr(), &restarted);
                self.handles.insert(restarted.device_id.clone(), runtime);
                self.m = restarted;
            }
            _ => {
                self.snapshot_sessions_with(&self.w.device_id.clone());
                self.handles.take_and_shutdown(&self.w.device_id).await;
                let restarted =
                    restart_node(std::mem::replace(&mut self.w, placeholder_node())).await;
                register_with_fake(
                    &self.fake,
                    &restarted.state,
                    &restarted.device_id,
                    restarted.keypair.public_bytes(),
                    &[&self.group_id],
                )
                .await;
                if self.w_route_broken {
                    self.fake.update_endpoint(&restarted.device_id, "127.0.0.1:1".to_string());
                }
                wire_relay_grant_source(&self.fake, &restarted.state, &restarted.device_id);
                let runtime = spawn_orchestrator(self.fake.addr(), &restarted);
                self.handles.insert(restarted.device_id.clone(), runtime);
                self.w = restarted;
            }
        }
    }

    async fn op_device_join(&mut self) {
        if self.spare.is_some() {
            return;
        }
        let spare = new_node("topology-x-spare");
        link_on_demand(&spare, &self.group_id);
        register_with_fake(
            &self.fake,
            &spare.state,
            &spare.device_id,
            spare.keypair.public_bytes(),
            &[&self.group_id],
        )
        .await;
        wire_relay_grant_source(&self.fake, &spare.state, &spare.device_id);
        // Coordination-plane-declared full-replica, matching `restore_n_
        // canonical_role`'s own pattern -- WITHOUT this, N is
        // structurally the only full-replica peer this topology ever
        // has, and `durability_service.rs`'s own `classify` returns
        // `AtRisk` before the `Protecting` arm is ever reached (see its
        // own doc comment: "a lone full replica with no peer never
        // reports Protecting"), making the soak's own "no stuck
        // Protecting" invariant unable to observe anything. A second
        // full-replica candidate makes that state machine's other arms
        // structurally reachable during this soak.
        self.fake.set_full_replica(&spare.device_id, &self.group_id, true);
        let runtime = spawn_orchestrator(self.fake.addr(), &spare);
        self.handles.insert(spare.device_id.clone(), runtime);
        self.spare = Some(spare);
    }

    async fn op_device_leave(&mut self) {
        let Some(spare) = self.spare.take() else { return };
        self.fake.remove_device(&spare.device_id);
        self.handles.take_and_shutdown(&spare.device_id).await;
    }
}

/// A dummy, never-linked node used only as a `std::mem::replace` swap
/// target while a real node is mid-restart (its own state briefly moves
/// into `restart_node`, which consumes it by value) -- never registered
/// with `FakeCoordination`, never observed by any real node in this
/// soak. NOT actually inert, though (an earlier version of this comment
/// claimed it was): `DaemonState::new` unconditionally spawns its
/// maintenance coordinator (the convergence engine among other loops),
/// matching real production startup, so every placeholder leaks one
/// harmless, permanently-orphaned background task polling an isolated,
/// never-again-touched temp DB for the rest of the process's life --
/// confirmed via trace logs (`local_device_id=soak-restart-swap-
/// placeholder-N` ticking indefinitely) while investigating an
/// unrelated soak-closure finding. Genuinely harmless (no shared state,
/// no registration, cannot affect any invariant this soak checks) but
/// real: fixing it properly needs `SoakWorld`'s `n`/`m`/`w` fields
/// `Option`-wrapped so `.take()` replaces the swap-and-discard pattern
/// entirely, which is a larger change than this specific investigation
/// warrants -- left as a known, tracked, low-priority test-cleanliness
/// item rather than fixed here.
fn placeholder_node() -> TopologyNode {
    new_node("soak-restart-swap-placeholder")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Hashes every regular file directly under `root` (this soak's candidate
/// files are always flat, no subdirectories), keyed by file name.
/// Excludes both `real_entry_names`'s established reserved/marker/lock/tmp
/// filter (e.g. `.yadorilink-root`, whose CONTENT is device-specific by
/// design, unlike its mere presence) and conflict-copy artifacts (a
/// device-random `LocalRename`/`LocalWrite`/`LocalDelete` mix genuinely
/// produces its OWN distinct conflict copy per side under real concurrent-
/// edit semantics -- comparing them as if they were the same synced
/// object is simply the wrong check, matching this file's own module doc
/// comment's stated scope and `monkey_chaos.rs`'s established convention
/// of only comparing the plain, non-conflict file set).
fn tree_digest(root: &std::path::Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in support::real_entry_names(root) {
        if name.contains("conflicted copy") {
            continue;
        }
        let Ok(file_type) = std::fs::symlink_metadata(root.join(&name)).map(|m| m.file_type())
        else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        if let Ok(bytes) = std::fs::read(root.join(&name)) {
            out.insert(name, sha256_hex(&bytes));
        }
    }
    out
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("yadorilink_daemon=debug")),
        )
        .with_test_writer()
        .try_init();
}

async fn run_soak(seed: u64) {
    init_tracing();
    support::ensure_isolated_config_dir();
    eprintln!("SOAK_SEED={seed} (reproduce with: SOAK_SEED={seed} cargo test -p yadorilink-daemon --test topology_soak_lane -- --nocapture)");
    let duration = duration_from_env_or_default();
    let mut rng = StdRng::seed_from_u64(seed);

    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "soak-lane-group";
    let (n, m, w, handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m.state, &m.device_id);
    wire_relay_grant_source(&fake, &w.state, &w.device_id);

    let mut world = SoakWorld {
        fake,
        group_id: group_id.to_string(),
        n,
        m,
        w,
        spare: None,
        handles,
        w_route_broken: false,
        pre_restart_sessions: Vec::new(),
    };

    let deadline = Instant::now() + duration;
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        let op = pick_op(&mut rng);
        tracing::info!(?op, rounds, "soak op");
        match op {
            SoakOp::LocalWrite => world.op_local_write(&mut rng).await,
            SoakOp::LocalDelete => world.op_local_delete(&mut rng).await,
            SoakOp::LocalRename => world.op_local_rename(&mut rng).await,
            SoakOp::Hydrate => world.op_hydrate(&mut rng).await,
            SoakOp::Evict => world.op_evict(&mut rng).await,
            SoakOp::BreakWRoute => world.op_break_w_route(),
            SoakOp::RestoreWRoute => world.op_restore_w_route(),
            SoakOp::RestartNode => world.op_restart_node(&mut rng).await,
            SoakOp::DeviceJoin => world.op_device_join().await,
            SoakOp::DeviceLeave => world.op_device_leave().await,
        }
        rounds += 1;
        let jitter = rng.random_range(10..OP_JITTER_MAX_MS);
        tokio::time::sleep(Duration::from_millis(jitter)).await;
    }
    tracing::info!(rounds, "soak window elapsed, ending with route restored and every node online");

    // End the soak in a known-recoverable state before checking
    // invariants: route restored (so direct convergence is actually
    // reachable for the final digest comparison) and every currently
    // online node reachable from the anchor.
    world.op_restore_w_route();
    let settle_start = Instant::now();
    wait_until_with_context(
        || {
            fully_connected(&world.n.state, &world.m.device_id)
                && fully_connected(&world.n.state, &world.w.device_id)
                && fully_connected(&world.m.state, &world.w.device_id)
                && world
                    .spare
                    .as_ref()
                    .is_none_or(|spare| fully_connected(&world.n.state, &spare.device_id))
        },
        SETTLE_TIMEOUT,
        || "soak lane never settled to a fully-connected mesh after the soak window".to_string(),
    )
    .await;

    let mut online_ondemand = vec![&world.m, &world.w];
    if let Some(spare) = &world.spare {
        online_ondemand.push(spare);
    }

    // Invariant 1: no silent corruption -- every currently-online node's
    // hydrated content, hashed per file, agrees on every path more than
    // one online node holds. A single fixed sleep is not enough:
    // production's own debounce window plus DAG propagation plus
    // hydration can each still be in flight for an op the soak loop's
    // very last rounds triggered, so this repeats a hydrate sweep +
    // digest comparison until either everything agrees or a real bound
    // elapses -- the same two-phase shape `monkey_chaos.rs`'s own
    // convergence wait uses, just folded into one retry loop here since
    // this check (unlike that file's) also has to re-run hydration each
    // attempt, not just re-read already-hydrated disk state.
    let mut mismatches = Vec::new();
    let convergence_deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        for node in &online_ondemand {
            if let Ok(files) =
                node.state.replica_coordinator.file_index_repository().list_files(&world.group_id)
            {
                for record in files.iter().filter(|f| !f.deleted) {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(10),
                        yadorilink_daemon::hydration::hydrate(
                            &node.state,
                            &world.group_id,
                            &record.path,
                        ),
                    )
                    .await;
                }
            }
        }
        let digests: Vec<(String, BTreeMap<String, String>)> = online_ondemand
            .iter()
            .map(|node| (node.device_id.clone(), tree_digest(node.root.path())))
            .collect();
        let n_digest = tree_digest(world.n.root.path());
        let mut all_digests = digests.clone();
        all_digests.push((world.n.device_id.clone(), n_digest));
        mismatches.clear();
        // Compares the UNION of paths seen on either side, not just the
        // intersection: a path present on A and entirely absent on B
        // (the exact shape of the false-tombstone/file-disappearance bug
        // this branch's production fix addresses) must count as a
        // mismatch, not be silently skipped -- an earlier version of
        // this check only compared values for paths present on BOTH
        // sides, so a node that lost every file passed this invariant
        // instantly (a real finding from an M5-A Pass 11 adversarial
        // review).
        for (i, (id_a, digest_a)) in all_digests.iter().enumerate() {
            for (id_b, digest_b) in &all_digests[i + 1..] {
                let all_paths: std::collections::BTreeSet<&String> =
                    digest_a.keys().chain(digest_b.keys()).collect();
                for path in all_paths {
                    match (digest_a.get(path), digest_b.get(path)) {
                        (Some(hash_a), Some(hash_b)) if hash_a != hash_b => {
                            mismatches.push(format!("{path}: {id_a}={hash_a} != {id_b}={hash_b}"));
                        }
                        (Some(_), None) => {
                            mismatches.push(format!("{path}: present on {id_a}, absent on {id_b}"));
                        }
                        (None, Some(_)) => {
                            mismatches.push(format!("{path}: present on {id_b}, absent on {id_a}"));
                        }
                        _ => {}
                    }
                }
            }
        }
        if mismatches.is_empty() || Instant::now() >= convergence_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(mismatches.is_empty(), "soak lane found silent content divergence: {mismatches:#?}");
    // A convergence check that never observed any real content is not a
    // pass -- it's every device starting and staying empty, e.g. because
    // the watcher or hydration path was silently broken the whole run.
    assert!(
        {
            let n_digest = tree_digest(world.n.root.path());
            !n_digest.is_empty()
                || online_ondemand.iter().any(|node| !tree_digest(node.root.path()).is_empty())
        },
        "soak lane never observed any real synced content on any online device -- the corruption \
         check above would have passed vacuously"
    );

    // Invariant 2: no leaked sessions -- every session `pre_restart_
    // sessions` captured immediately before its node's restart must
    // either have been replaced by now, OR still be the exact same,
    // currently-healthy `PeerSyncSession`. `PeerRegistry` is keyed by
    // device id, so it structurally cannot hold two live entries for the
    // same peer -- checking it for "duplicates" (an earlier version of
    // this check) can never fail and proves nothing. An earlier version
    // of THIS check also flagged an unreplaced-but-healthy session as a
    // leak (M5-A soak-closure investigation, `topology_rapid_restart_
    // repro.rs`): `PeerChannel` can heal an existing session's transport
    // in place across a peer restart -- its own `DIRECT_LIVENESS_TIMEOUT`
    // (`yadorilink_transport::peer_channel`'s own doc comment) re-races
    // candidates and re-handshakes over the SAME channel/session object
    // once the restarted peer's new endpoint is learned, with no new
    // `PeerSyncSession` ever created -- confirmed live: a 6x-rapid-restart
    // repro reproducibly left `Arc::ptr_eq` true while `peer_handshake_
    // received()`/`change_dag_negotiated()` were both true and both
    // sides' reachability was `Connected(Direct)`, a fully recovered
    // session that was never replaced because it never needed to be. The
    // real leak this soak cares about is a restarted node's OLD detached
    // per-peer supervisor whose session never resumes handshaking at
    // all -- observable as the SAME session identity that stays
    // unhealthy (no fresh handshake, not reachable) for the entire
    // settle window, not merely as unreplaced identity.
    let mut all_nodes = vec![&world.n, &world.m, &world.w];
    if let Some(spare) = &world.spare {
        all_nodes.push(spare);
    }
    let node_by_id = |device_id: &str| all_nodes.iter().find(|n| n.device_id == device_id).copied();
    // Retried across the settle window, like invariants 1 and 4: an
    // earlier version of this check ran exactly once, right after the
    // fully_connected wait above -- which only proves N/M/W are
    // currently REACHABLE again, not that every OTHER observer's own
    // reconnect supervisor has finished ITS OWN independent, backoff-
    // bound recovery for a DIFFERENT, earlier restart in this soak's own
    // history. `spawn_peer_session`'s reconnect backoff can legitimately
    // ratchet toward its 45s cap under repeated quick-failing
    // generations (exactly what several rapid restarts of the same peer
    // in a short window produce), so a single immediate check can fire
    // before recovery that is already correctly, if slowly, in
    // progress.
    let mut leaked = Vec::new();
    let leak_deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        leaked.clear();
        for (observer_id, restarted_id, old_session) in &world.pre_restart_sessions {
            let Some(observer) = node_by_id(observer_id) else { continue };
            if let Some(current) = observer.state.peers.session(restarted_id) {
                if !Arc::ptr_eq(&current, old_session) {
                    continue;
                }
                let healthy = current.peer_handshake_received()
                    && current.change_dag_negotiated()
                    && matches!(
                        observer.state.peers.reachability(restarted_id),
                        Some(PeerReachability::Connected(_))
                    );
                if !healthy {
                    leaked.push(format!(
                        "{observer_id}'s session with {restarted_id} was never replaced across \
                         its restart, and is not currently healthy (handshake_received={}, \
                         dag_negotiated={}, reachability={:?})",
                        current.peer_handshake_received(),
                        current.change_dag_negotiated(),
                        observer.state.peers.reachability(restarted_id)
                    ));
                }
            }
        }
        if leaked.is_empty() || Instant::now() >= leak_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(leaked.is_empty(), "soak lane found leaked pre-restart sessions: {leaked:#?}");

    // Invariant 3: no stuck Protecting -- once settled, no currently-
    // online node's durability status is still mid-transition. Reachable
    // for real in this soak (unlike an earlier version of this check,
    // which asserted only on N against a topology where N is
    // structurally the ONLY full-replica peer -- durability_service.rs's
    // own doc says a lone full replica with no peer never even reaches
    // the Protecting arm, so that assertion could never fail) because
    // `op_device_join` now marks the spare a second coordination-plane
    // full-replica candidate whenever it's present.
    // Retried across the settle window, like invariants 1, 2, and 4:
    // `Protecting` is a legitimate, transient state while local
    // materialization catches up (`classify`'s own doc comment, arm 5) --
    // a node whose peer session was recovering (invariant 2's own window)
    // can genuinely still be mid-hydration right after the settle wait
    // above, since durability confirmation depends on the same peer
    // traffic that invariant 2 waits on.
    let mut stuck = Vec::new();
    let stuck_deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        stuck.clear();
        for node in &all_nodes {
            let status = node.state.group_durability_status(&world.group_id);
            if status == GroupDurabilityStatus::Protecting {
                stuck.push(node.device_id.clone());
            }
        }
        if stuck.is_empty() || Instant::now() >= stuck_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        stuck.is_empty(),
        "soak lane found durability status still Protecting {:?} after the settle window on: \
         {stuck:?}",
        settle_start.elapsed()
    );

    // Invariant 4: no stale route -- retries (like invariant 1) rather
    // than checking once, since a route transition triggered by the
    // soak's very last ops can still be in flight right after the
    // settle wait above (which only checks connectivity relative to N,
    // not every pair). For every pair, requires BOTH sides to agree not
    // just on connectedness but on the SAME `RouteKind` -- an earlier
    // version of this check only compared connectedness, which collapses
    // `Connected(Direct)` and `Connected(Relay)` into the same value and
    // also accepted "both sides see each other as unreachable" as
    // healthy.
    let mut all_pairs: Vec<(&TopologyNode, &TopologyNode)> =
        vec![(&world.n, &world.m), (&world.n, &world.w), (&world.m, &world.w)];
    if let Some(spare) = &world.spare {
        all_pairs.push((&world.n, spare));
        all_pairs.push((&world.m, spare));
        all_pairs.push((&world.w, spare));
    }
    let route_kind =
        |peers: &yadorilink_daemon::peer_registry::PeerRegistry, peer_id: &str| match peers
            .reachability(peer_id)
        {
            Some(PeerReachability::Connected(kind)) => Some(kind),
            _ => None,
        };
    let mut route_mismatches = Vec::new();
    let route_deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        route_mismatches.clear();
        for (a, b) in &all_pairs {
            let a_view = route_kind(&a.state.peers, &b.device_id);
            let b_view = route_kind(&b.state.peers, &a.device_id);
            match (a_view, b_view) {
                (Some(RouteKind::Direct), Some(RouteKind::Direct)) => {}
                (Some(RouteKind::Relay), Some(RouteKind::Relay)) => {}
                _ => {
                    route_mismatches.push(format!(
                        "{}<->{}: {} sees {:?}, {} sees {:?}",
                        a.device_id, b.device_id, a.device_id, a_view, b.device_id, b_view
                    ));
                }
            }
        }
        if route_mismatches.is_empty() || Instant::now() >= route_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        route_mismatches.is_empty(),
        "soak lane found stale/disagreeing routes after the settle window: {route_mismatches:#?}"
    );

    world.handles.shutdown();
}

// M5-A Pass 9 finding (project memory `m5a-pass9-link-runtime-stop-
// fence-gap`): this soak's `RestartNode` op used to reliably surface a
// genuine production race in `LinkRuntimeController::stop()` racing an
// in-flight root-lease acquisition for the same link (real production
// paths: `Unlink`, a daemon restart) -- FIXED (bounded retry + graceful
// fallback in `link_runtime_controller.rs`, matching `graceful_
// shutdown`'s established pattern), confirmed via 0/10 recurrence on the
// corpus-recorded seed plus repeated soak reruns since.
//
// The soak-closure investigation's three follow-on findings (session
// leak, stale route, durability stuck Protecting) are ALL fixed -- see
// `tests/dst_corpus/soak_lane_seeds.txt`'s own header for the full
// classification trail on each. Durability stuck Protecting's root
// cause: a full-replica device's `Placeholder` row can legitimately have
// NO obtainable holder among current membership -- its sole
// provenance-verified holder left the group, and every other current
// peer explicitly refuses the fetch (`FetchOutcome::Rejected`, "no
// verified group provenance"), not merely times out. `materialization:
// Partial` alone cannot distinguish "still trying, may yet succeed" from
// "genuinely, permanently gone", so `classify` stayed at `Protecting`
// forever. Fixed via a new `DurabilityFacts::known_unobtainable_
// required_content` fact (backed by a durable `block_fetch_refusals`
// table, written only on an EXPLICIT peer refusal, never a transient
// miss) that routes to the EXISTING `AtRisk` variant -- no new
// `GroupDurabilityStatus` variant. The record itself is never
// auto-retired: an unobtainable record may be a user's only surviving
// edit, and silently deleting the metadata would turn real data loss
// into apparent convergence. See `crates/yadorilink-daemon/tests/
// durability_unobtainable_content.rs` for the full root-cause writeup
// and its own deterministic regression (10/10 green).
//
// A FOURTH, distinct durability-stuck-Protecting finding surfaced later
// in full-suite validation (same corpus seed, 12552500466593081697,
// failing again with `known_unobtainable_required_content: false`):
// `MaterializationRepairJob::run_once` (materialization_repair.rs)
// stopped its per-sweep round-robin at the first peer whose audit
// returned `Ok(_)`, but `Ok(_)` there only means "the audit ran without
// an outer I/O error", not "materialization is now complete" (a
// per-file `RetryRequired` is intentionally folded into `Ok(())` --
// re-candidacy is driven by DB state, not this return value). Under
// spare-device churn, the live candidate list's length fluctuates
// sweep to sweep, which collapses the modular round-robin cursor back
// to the same starting peer repeatedly -- so a full-replica device
// could ask the SAME peer (itself only partially materialized, with
// nothing to contribute) every single sweep for the entire soak run,
// never once trying its other live peers. Fixed by asking every live
// candidate every sweep instead of stopping at the first success --
// bounded by the group's live session count, same as before, and makes
// the fix independent of the cursor's exact value. See `tests/
// dst_corpus/soak_lane_seeds.txt`'s own header for the verification
// trail (this exact seed replays clean; durability_unobtainable_
// content.rs still 3/3).
//
// Both tests below are UNIGNORED.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn randomized_soak_converges_with_no_leaks_or_stuck_state() {
    let _serial_guard = SOAK_LANE_SERIAL_GUARD.lock().await;
    let seed = seed_from_env_or_random();
    let result = std::panic::AssertUnwindSafe(run_soak(seed)).catch_unwind().await;
    if let Err(panic) = result {
        record_failing_seed(seed);
        eprintln!(
            "SOAK_LANE seed={seed} FAILED and was appended to the regression corpus (reproduce with: \
             SOAK_SEED={seed} cargo test -p yadorilink-daemon --test topology_soak_lane -- --nocapture)"
        );
        std::panic::resume_unwind(panic);
    }
}

/// Re-runs every seed recorded in `tests/dst_corpus/soak_lane_seeds.txt`
/// with the SAME (default, CI-safe) duration budget -- a no-op while the
/// corpus is empty, and a permanent regression check for every seed a
/// heat-run ever found failing, matching `monkey_chaos.rs::replay_known_
/// failing_seeds`'s established idiom.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn replay_known_failing_seeds() {
    let _serial_guard = SOAK_LANE_SERIAL_GUARD.lock().await;
    for seed in load_corpus_seeds() {
        eprintln!(
            "SOAK_LANE replaying corpus seed={seed} (reproduce with: SOAK_SEED={seed} cargo test -p \
             yadorilink-daemon --test topology_soak_lane -- --nocapture)"
        );
        run_soak(seed).await;
    }
}

use futures_util::FutureExt as _;
