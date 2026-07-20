//! Deterministic-simulation *workload sweep* through two real daemon
//! lifecycles. This extends `dst_daemon_two_device.rs` (which proves two
//! in-sim `app::run` daemons discover each other and converge on a *single*
//! file) into a multi-round, multi-operation workload -- solo
//! writes/edits/deletes plus concurrent same-path races -- and then runs the
//! full multi-device oracle suite (`check_convergence`, `check_no_loss`,
//! `check_conflict_copy_accounting`, `check_structural`) against both real
//! daemon roots + `SyncState`s at quiescence.
//!
//! WHY THIS TEST EXISTS. The `yadorilink-sync-core` chaos scenarios drive a
//! *bare* `PeerSyncSession` directly, without a `DaemonState`. That bare
//! harness surfaced a consistent data-loss class -- `[NoLoss]` (a write not
//! causally superseded absent from every device, live or as a conflict copy)
//! and `[StructuralIndexDiskMismatch]` (a live index row with no file on
//! disk). The open hypothesis is that these are *harness artifacts*: the bare
//! `PeerSyncSession` lacks the production daemon's self-healing
//! (`repair_interrupted_materializations` / forward-rebroadcast) and real
//! transport, so a transient mid-sync state that the real daemon would repair
//! is observed by the bare harness as a terminal loss. This sweep answers
//! that question empirically by running the *same oracle* the bare harness
//! runs, but against the *real daemon* end to end. If the two classes are
//! absent here where the bare harness showed them, the daemon's self-healing
//! closes them (artifact confirmed); if they persist, it is a real product
//! bug and the seed + sequence is the reproduction.
//!
//! Everything below discovery is the identical production path
//! (`PeerChannel`, `PeerSyncSession`, `broadcast_change`, materialization,
//! and the daemon's periodic self-healing sweep). Only the coordination-plane
//! discovery is replaced by the `#[cfg(madsim)]` static-netmap seam, and the
//! OS watcher by `SimulatedFolderWatchSource` -- exactly as in
//! `dst_daemon_two_device.rs`. Production code is unchanged.
//!
//! Only compiled/run under `RUSTFLAGS="--cfg madsim"`.

#![cfg(madsim)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use yadorilink_daemon::app::{self, DaemonConfig};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
use yadorilink_daemon::peer_orchestrator::{SimDiscovery, SimPeer};
use yadorilink_sync_core::debounce::DebounceConfig;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::version_vector::{VersionVector, VvOrdering};
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource};
use yadorilink_transport::DeviceKeyPair;

// --------------------------------------------------------------------------
// The real multi-device oracle, reused verbatim from
// `yadorilink-sync-core`'s `tests/dst_support`. `oracle.rs` only depends on
// `super::case_ir::ContentTable` and `super::content_hash`; when included as
// a crate-root module its `super` is this test's crate root, so those two
// items are provided here at crate root and then `oracle.rs` is
// `#[path]`-included *unchanged* -- so this sweep runs the identical checker
// the bare-`PeerSyncSession` chaos scenarios run, which is the whole point (a
// fork of the oracle would not answer the fidelity question).
//
// `content_hash` is used only *inside* the oracle (cross-device convergence
// comparison + no-corruption disk hashing); it is never compared against a
// production-computed hash, so a std-only deterministic hash keeps this test
// dependency-free while remaining faithful.
pub fn content_hash(bytes: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Minimal, API-compatible re-declaration of
/// `dst_support::case_ir::ContentTable` (the real one carries extra
/// serde/`Case`-IR machinery this sweep does not need). The oracle only calls
/// `get` / `contains_bytes`; `insert` is the harness's registration entry.
pub mod case_ir {
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct ContentTable {
        entries: HashMap<u64, Vec<u8>>,
    }

    impl ContentTable {
        pub fn insert(&mut self, content_id: u64, bytes: Vec<u8>) -> u64 {
            self.entries.insert(content_id, bytes);
            content_id
        }
        pub fn get(&self, content_id: u64) -> Option<&Vec<u8>> {
            self.entries.get(&content_id)
        }
        pub fn contains_bytes(&self, bytes: &[u8]) -> bool {
            self.entries.values().any(|v| v.as_slice() == bytes)
        }
        pub fn iter(&self) -> impl Iterator<Item = (&u64, &Vec<u8>)> {
            self.entries.iter()
        }
    }
}

#[path = "../../yadorilink-sync-core/tests/dst_support/oracle.rs"]
pub mod oracle;

use case_ir::ContentTable;
use oracle::{GlobalOracle, Violation, ViolationKind};

const GROUP_ID: &str = "dst-daemon-sweep-group";

// --------------------------------------------------------------------------
// Deterministic mtime stamping (mirrors `dst_daemon_two_device.rs` /
// `dst_daemon_smoke.rs`). madsim virtualizes `SystemTime::now` but not the
// kernel's inode-mtime stamping, so every file the harness writes gets an
// explicit, seed-derived, strictly-increasing mtime -- both for
// replayability and so successive edits to one path are seen as real changes
// and so conflict tie-breaking (higher mtime wins) is deterministic.

fn base_mtime_nanos(seed: u64) -> i64 {
    (seed as i64).wrapping_mul(1_000_000_000).wrapping_add(1_000_000_000)
}

fn stamp_deterministic_mtime(path: &Path, nanos: i64) -> Result<(), String> {
    let modified = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

// --------------------------------------------------------------------------
// Per-daemon handle (same shape as `dst_daemon_two_device.rs`).

struct SimDaemon {
    idx: usize,
    device_id: String,
    state: Arc<DaemonState>,
    root: PathBuf,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
    _config_dir: tempfile::TempDir,
    _block_store_dir: tempfile::TempDir,
    _watch_root_dir: tempfile::TempDir,
}

impl SimDaemon {
    fn sync_state(&self) -> &SyncState {
        self.state.sync_state.as_ref()
    }
    fn get_record(&self, path: &str) -> Option<(VersionVector, bool, u64)> {
        self.sync_state()
            .get_file(GROUP_ID, path)
            .ok()
            .flatten()
            .map(|r| (r.version, r.deleted, r.size))
    }
}

async fn boot_daemon(
    idx: usize,
    device_id: &str,
    sim_discovery: SimDiscovery,
) -> Result<(SimDaemon, tokio::task::JoinHandle<anyhow::Result<()>>), String> {
    let config_dir = tempfile::tempdir().map_err(|e| format!("config tempdir: {e}"))?;
    let block_store_dir = tempfile::tempdir().map_err(|e| format!("block-store tempdir: {e}"))?;
    let watch_root_dir = tempfile::tempdir().map_err(|e| format!("watch-root tempdir: {e}"))?;
    let root =
        watch_root_dir.path().canonicalize().map_err(|e| format!("canonicalize root: {e}"))?;

    let probe: app::StateProbe = Arc::new(Mutex::new(None));
    let config = DaemonConfig {
        config_dir: config_dir.path().to_path_buf(),
        block_store_root: block_store_dir.path().to_path_buf(),
        sync_db_path: config_dir.path().join("sync-state.sqlite3"),
        control_socket_path: config_dir.path().join("daemon.sock"),
        shell_ipc_socket_path: config_dir.path().join("shell.sock"),
        keypair_path: config_dir.path().join("wg_key"),
        state_probe: Some(probe.clone()),
        sim_discovery: Some(sim_discovery),
        // This test uses the real, un-decorated block store (no fault injection).
        block_store_override: None,
    };

    let handle = tokio::spawn(app::run(config));
    let state = wait_for_state(&probe, Duration::from_secs(30))
        .await
        .ok_or_else(|| "daemon never reached steady state".to_string())?;

    state
        .sync_state
        .add_link(&root.to_string_lossy(), GROUP_ID)
        .map_err(|e| format!("add_link: {e}"))?;
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(64);
    link_manager::start_link_watch_with_source(
        state.clone(),
        root.to_string_lossy().to_string(),
        GROUP_ID.to_string(),
        Arc::new(watch_source),
    )
    .map_err(|e| format!("start_link_watch_with_source: {e}"))?;

    Ok((
        SimDaemon {
            idx,
            device_id: device_id.to_string(),
            state,
            root,
            events_tx,
            _config_dir: config_dir,
            _block_store_dir: block_store_dir,
            _watch_root_dir: watch_root_dir,
        },
        handle,
    ))
}

// --------------------------------------------------------------------------
// Tiny deterministic RNG so op parameters (which device, content jitter,
// timing) are seed-derived and replayable without pulling in `rand`.

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1))
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

// --------------------------------------------------------------------------
// Workload driver.

/// The mutable bookkeeping the driver threads through each op: the oracle
/// history, the content table, and the monotonic counters for content ids
/// and mtimes.
struct Driver {
    seed: u64,
    oracle: GlobalOracle,
    content_table: ContentTable,
    next_content_id: u64,
    tick: i64,
    rng: Lcg,
}

impl Driver {
    fn new(seed: u64) -> Self {
        Driver {
            seed,
            oracle: GlobalOracle::new(),
            content_table: ContentTable::default(),
            next_content_id: 1,
            tick: 0,
            rng: Lcg::new(seed),
        }
    }

    fn next_mtime(&mut self) -> i64 {
        self.tick += 1;
        base_mtime_nanos(self.seed).wrapping_add(self.tick.wrapping_mul(1_000_000))
    }

    /// Registers a fresh, unique content blob and returns `(content_id, bytes)`.
    fn new_content(&mut self, path: &str, device_idx: usize) -> (u64, Vec<u8>) {
        let id = self.next_content_id;
        self.next_content_id += 1;
        let salt = self.rng.next_u64();
        let bytes = format!(
            "seed={} cid={} path={} dev={} salt={:016x} :: {}",
            self.seed,
            id,
            path,
            device_idx,
            salt,
            "x".repeat((salt % 37) as usize)
        )
        .into_bytes();
        self.content_table.insert(id, bytes.clone());
        (id, bytes)
    }
}

/// Writes `bytes` into `daemon`'s linked root at `rel`, stamps a
/// deterministic mtime, and delivers the synthetic watcher event -- the exact
/// local-write path `dst_daemon_two_device.rs` uses.
async fn local_write(
    daemon: &SimDaemon,
    rel: &str,
    bytes: &[u8],
    mtime: i64,
) -> Result<(), String> {
    let abs = daemon.root.join(rel);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    std::fs::write(&abs, bytes).map_err(|e| format!("write {rel}: {e}"))?;
    stamp_deterministic_mtime(&abs, mtime)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    daemon
        .events_tx
        .send(FsChangeEvent { path: abs, kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher event channel closed early".to_string())
}

/// Deletes `daemon`'s local file at `rel` and delivers the `Removed` event.
async fn local_delete(daemon: &SimDaemon, rel: &str) -> Result<(), String> {
    let abs = daemon.root.join(rel);
    let _ = std::fs::remove_file(&abs);
    tokio::time::sleep(Duration::from_millis(5)).await;
    daemon
        .events_tx
        .send(FsChangeEvent { path: abs, kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "watcher event channel closed early".to_string())
}

const LOCAL_INDEX_TIMEOUT: Duration = Duration::from_secs(90);
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(150);

/// Waits until `daemon` has durably indexed a *live* record for `rel` whose
/// version strictly advances past `prev`, then returns that version -- the VV
/// the write carried at the moment it was durably applied (what the oracle's
/// no-loss/accounting checks compare against). Best-effort: if reconciliation
/// with the peer has already merged in the peer's counters by the time we
/// read, the recorded VV still correctly reflects this device's own advanced
/// counter, which is all the causal-supersession logic needs.
async fn wait_write_applied(
    daemon: &SimDaemon,
    rel: &str,
    prev: &VersionVector,
) -> Result<VersionVector, String> {
    wait_for(
        || match daemon.get_record(rel) {
            Some((v, deleted, _)) => !deleted && v.compare(prev) == VvOrdering::After,
            None => false,
        },
        LOCAL_INDEX_TIMEOUT,
    )
    .await
    .map_err(|_| format!("daemon {} never indexed live write for {rel}", daemon.device_id))?;
    Ok(daemon.get_record(rel).map(|(v, _, _)| v).unwrap_or_default())
}

/// Waits until `daemon` has durably tombstoned `rel` (deleted row, or the row
/// gone), then returns its version.
async fn wait_delete_applied(
    daemon: &SimDaemon,
    rel: &str,
    prev: &VersionVector,
) -> Result<VersionVector, String> {
    wait_for(
        || match daemon.get_record(rel) {
            Some((_, deleted, _)) => deleted,
            None => true,
        },
        LOCAL_INDEX_TIMEOUT,
    )
    .await
    .map_err(|_| format!("daemon {} never tombstoned {rel}", daemon.device_id))?;
    Ok(daemon.get_record(rel).map(|(v, _, _)| v).unwrap_or_else(|| prev.clone()))
}

/// A solo write/edit by `daemon`: apply locally, record it into the oracle
/// with its real applied VV, then wait for the peer to converge on the bytes
/// (keeps rounds causally ordered so later solo ops get proper supersession
/// VVs).
async fn op_solo_write(
    d: &mut Driver,
    daemon: &SimDaemon,
    peer: &SimDaemon,
    rel: &str,
) -> Result<(), String> {
    let prev = daemon.get_record(rel).map(|(v, _, _)| v).unwrap_or_default();
    let (cid, bytes) = d.new_content(rel, daemon.idx);
    let mtime = d.next_mtime();
    local_write(daemon, rel, &bytes, mtime).await?;
    let version = wait_write_applied(daemon, rel, &prev).await?;
    d.oracle.record_write(rel, daemon.idx, cid, version);

    // Wait for the peer to materialize these exact bytes (live path).
    let peer_file = peer.root.join(rel);
    let want = bytes.clone();
    wait_for(|| std::fs::read(&peer_file).map(|c| c == want).unwrap_or(false), CONVERGE_TIMEOUT)
        .await
        .map_err(|_| format!("peer {} never converged on {rel}", peer.device_id))?;
    Ok(())
}

/// A solo delete by `daemon`: apply locally, record the tombstone, wait for
/// the peer to drop the file.
async fn op_solo_delete(
    d: &mut Driver,
    daemon: &SimDaemon,
    peer: &SimDaemon,
    rel: &str,
) -> Result<(), String> {
    let prev = daemon.get_record(rel).map(|(v, _, _)| v).unwrap_or_default();
    local_delete(daemon, rel).await?;
    let version = wait_delete_applied(daemon, rel, &prev).await?;
    d.oracle.record_delete(rel, daemon.idx, version);

    let peer_file = peer.root.join(rel);
    wait_for(|| !peer_file.exists(), CONVERGE_TIMEOUT)
        .await
        .map_err(|_| format!("peer {} never dropped deleted {rel}", peer.device_id))?;
    Ok(())
}

/// A concurrent race: BOTH daemons edit the same path in the same round
/// before either has propagated. Each side's own local write is recorded with
/// the VV it carried when applied; convergence/conflict-copy accounting is
/// left to the terminal oracle after the whole sweep settles.
async fn op_race(d: &mut Driver, a: &SimDaemon, b: &SimDaemon, rel: &str) -> Result<(), String> {
    let prev_a = a.get_record(rel).map(|(v, _, _)| v).unwrap_or_default();
    let prev_b = b.get_record(rel).map(|(v, _, _)| v).unwrap_or_default();
    let (cid_a, bytes_a) = d.new_content(rel, a.idx);
    let (cid_b, bytes_b) = d.new_content(rel, b.idx);
    let mtime_a = d.next_mtime();
    let mtime_b = d.next_mtime();

    // Fire both local writes back-to-back, before waiting on either -- this is
    // what makes the two writes genuinely concurrent.
    local_write(a, rel, &bytes_a, mtime_a).await?;
    local_write(b, rel, &bytes_b, mtime_b).await?;

    let ver_a = wait_write_applied(a, rel, &prev_a).await?;
    d.oracle.record_write(rel, a.idx, cid_a, ver_a);
    let ver_b = wait_write_applied(b, rel, &prev_b).await?;
    d.oracle.record_write(rel, b.idx, cid_b, ver_b);
    Ok(())
}

const P0: &str = "p0.txt";
const P1: &str = "p1.txt";
const P2: &str = "p2.txt";

/// Drives one seed's full multi-round workload against two freshly-booted
/// real daemons and returns the terminal oracle violations (empty == clean).
async fn scenario_body(seed: u64) -> Result<Vec<Violation>, String> {
    // No coordination server in-sim => not "logged in"; point process-global
    // config lookups at an empty temp dir. Mirrors the smoke/two-device tests.
    let shared_config_dir =
        tempfile::tempdir().map_err(|e| format!("shared config tempdir: {e}"))?;
    std::env::set_var("YADORILINK_CONFIG_DIR", shared_config_dir.path());

    let keypair_a = DeviceKeyPair::generate();
    let keypair_b = DeviceKeyPair::generate();
    let public_a = keypair_a.public;
    let public_b = keypair_b.public;
    let keypair_a = Arc::new(keypair_a);
    let keypair_b = Arc::new(keypair_b);

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind socket_a: {e}"))?;
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind socket_b: {e}"))?;
    let addr_a = socket_a.local_addr().map_err(|e| format!("addr_a: {e}"))?;
    let addr_b = socket_b.local_addr().map_err(|e| format!("addr_b: {e}"))?;

    let sim_a = SimDiscovery {
        keypair: keypair_a,
        local_device_id: "device-a".to_string(),
        peers: vec![SimPeer {
            device_id: "device-b".to_string(),
            public_key: public_b,
            shared_group_ids: vec![GROUP_ID.to_string()],
            local_socket: socket_a,
            peer_candidates: vec![addr_b],
        }],
    };
    let sim_b = SimDiscovery {
        keypair: keypair_b,
        local_device_id: "device-b".to_string(),
        peers: vec![SimPeer {
            device_id: "device-a".to_string(),
            public_key: public_a,
            shared_group_ids: vec![GROUP_ID.to_string()],
            local_socket: socket_b,
            peer_candidates: vec![addr_a],
        }],
    };

    let (daemon_a, run_a) = boot_daemon(0, "device-a", sim_a).await?;
    let (daemon_b, run_b) = boot_daemon(1, "device-b", sim_b).await?;

    // Pin the session clock onto the same seed-derived timeline the stamped
    // mtimes sit on (matches the two-device test).
    yadorilink_sync_core::peer_session::set_test_clock_override(base_mtime_nanos(seed));

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Assert pairing before generating traffic.
    wait_for(
        || {
            session_connected(&daemon_a.state, "device-b")
                && session_connected(&daemon_b.state, "device-a")
        },
        Duration::from_secs(30),
    )
    .await
    .map_err(|_| "peers never established a PeerChannel session in-sim".to_string())?;

    let mut d = Driver::new(seed);

    // ---- The workload: solo writes/edits, a delete, and multiple same-path
    // concurrent races. Content, mtimes (hence conflict winners), and
    // scheduler interleavings all vary by seed; the op *shape* is fixed so
    // every seed exercises the whole class the deliverable cares about.
    //
    // Round 0: A creates P0 (solo).
    op_solo_write(&mut d, &daemon_a, &daemon_b, P0).await?;
    // Round 1: B creates P1 (solo, proves B->A direction too).
    op_solo_write(&mut d, &daemon_b, &daemon_a, P1).await?;
    // Round 2: concurrent creation race on P2 (both sides create it at once).
    op_race(&mut d, &daemon_a, &daemon_b, P2).await?;
    // Round 3: A edits the now-shared P0 (solo edit, supersedes round 0).
    op_solo_write(&mut d, &daemon_a, &daemon_b, P0).await?;
    // Round 4: seed-chosen device deletes P1 (solo delete).
    let (del_dev, del_peer) =
        if d.rng.below(2) == 0 { (&daemon_a, &daemon_b) } else { (&daemon_b, &daemon_a) };
    op_solo_delete(&mut d, del_dev, del_peer, P1).await?;
    // Round 5: concurrent edit race on the existing P0.
    op_race(&mut d, &daemon_a, &daemon_b, P0).await?;
    // Round 6: another concurrent edit race on P2 (which itself began as a
    // race), stacking a second divergence on a path that already has one.
    op_race(&mut d, &daemon_a, &daemon_b, P2).await?;

    // ---- Settle to quiescence: stop driving, let debounce drain,
    // reconciliation finish, and the daemon's periodic self-healing sweep run,
    // all under fast-forwarded simulated time.
    tokio::time::sleep(DebounceConfig::default().max_flush_interval + Duration::from_secs(120))
        .await;

    // Best-effort wait for the two roots' full file sets (including conflict
    // copies) to match; even if this times out we still run the oracle so a
    // real divergence is reported rather than hidden.
    let root_a = daemon_a.root.clone();
    let root_b = daemon_b.root.clone();
    let _ = wait_for(|| flat_snapshot(&root_a) == flat_snapshot(&root_b), Duration::from_secs(180))
        .await;

    // ---- Run the full oracle suite against both real roots + SyncStates.
    let devices: [(&Path, &SyncState); 2] = [
        (daemon_a.root.as_path(), daemon_a.sync_state()),
        (daemon_b.root.as_path(), daemon_b.sync_state()),
    ];

    let mut violations = Vec::new();
    violations.extend(d.oracle.check_convergence(&devices));
    violations.extend(d.oracle.check_no_loss(&d.content_table, &devices));
    violations.extend(d.oracle.check_conflict_copy_accounting(
        &d.content_table,
        &devices,
        GROUP_ID,
    ));
    violations.extend(d.oracle.check_structural(GROUP_ID, &devices));

    // Graceful shutdown of both daemons.
    daemon_a.state.shutdown_tx.send(true).map_err(|e| format!("shutdown A: {e}"))?;
    daemon_b.state.shutdown_tx.send(true).map_err(|e| format!("shutdown B: {e}"))?;
    for (name, handle) in [("A", run_a), ("B", run_b)] {
        match tokio::time::timeout(Duration::from_secs(10), handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => return Err(format!("daemon {name} run returned error: {e}")),
            Ok(Err(join)) => return Err(format!("daemon {name} task panicked: {join}")),
            Err(_) => return Err(format!("daemon {name} did not shut down within the timeout")),
        }
    }

    Ok(violations)
}

/// A flat name -> byte-length snapshot of a root's top-level files, used only
/// as a cheap "have the two roots stopped changing relative to each other"
/// settle signal (the authoritative check is the oracle's `check_convergence`).
fn flat_snapshot(root: &Path) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_file() {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    out.insert(entry.file_name().to_string_lossy().into_owned(), len);
                }
            }
        }
    }
    out
}

fn session_connected(state: &DaemonState, peer_device_id: &str) -> bool {
    state.sessions.lock().unwrap_or_else(|p| p.into_inner()).contains_key(peer_device_id)
}

async fn wait_for_state(probe: &app::StateProbe, timeout: Duration) -> Option<Arc<DaemonState>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(state) = probe.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            return Some(state);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for<F: Fn() -> bool>(cond: F, timeout: Duration) -> Result<(), ()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn run_scenario(seed: u64) -> Result<Vec<Violation>, String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(2400));
    rt.block_on(scenario_body(seed))
}

/// The sweep: over `DST_VARIATIONS` seeds (default 12, starting at `DST_SEED`,
/// default 1), drive the multi-round two-real-daemon workload and run the
/// oracle. Prints a per-seed report and a class tally, then asserts the
/// no-loss / structural-index-disk-mismatch classes never appeared -- so a
/// green run *is* the "harness-artifact confirmed" verdict, and a red run
/// carries the reproducing seed + the exact violating class in its output.
#[test]
fn multi_op_two_daemon_sweep_in_sim() {
    let base_seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let variations: u64 =
        std::env::var("DST_VARIATIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(12);

    let mut clean = 0u64;
    let mut errored: Vec<(u64, String)> = Vec::new();
    let mut class_tally: BTreeMap<String, u64> = BTreeMap::new();
    let mut noloss_or_structural: Vec<(u64, Violation)> = Vec::new();

    for i in 0..variations {
        let seed = base_seed.wrapping_add(i);
        match run_scenario(seed) {
            Ok(violations) if violations.is_empty() => {
                clean += 1;
                println!("[sweep] seed {seed}: CLEAN (0 violations)");
            }
            Ok(violations) => {
                println!("[sweep] seed {seed}: {} violation(s):", violations.len());
                for v in &violations {
                    println!("    {v}");
                    *class_tally.entry(format!("{:?}", v.kind)).or_default() += 1;
                    if matches!(
                        v.kind,
                        ViolationKind::NoLoss | ViolationKind::StructuralIndexDiskMismatch
                    ) {
                        noloss_or_structural.push((seed, v.clone()));
                    }
                }
            }
            Err(e) => {
                println!("[sweep] seed {seed}: HARNESS ERROR: {e}");
                errored.push((seed, e));
            }
        }
    }

    println!("\n================ DST DAEMON SWEEP SUMMARY ================");
    println!("seeds run          : {variations} (base {base_seed})");
    println!("clean (0 viol.)    : {clean}");
    println!("harness errors     : {}", errored.len());
    println!("violation classes  : {class_tally:?}");
    println!("[NoLoss]/[StructuralIndexDiskMismatch] occurrences : {}", noloss_or_structural.len());
    for (seed, v) in &noloss_or_structural {
        println!("    seed {seed}: {v}");
    }
    println!("=========================================================\n");

    // A harness error (a daemon that never paired, never converged on a solo
    // write, or never shut down) is a fidelity failure of the sweep itself,
    // not a product verdict -- surface it loudly.
    assert!(errored.is_empty(), "harness errors on seeds: {errored:?}");

    // THE VERDICT. The bare-`PeerSyncSession` harness showed these two classes;
    // if the real daemon closes them across every seed, that confirms the
    // harness-artifact hypothesis. If any appear here, it is a real product
    // bug and this assertion's message carries the reproducing seed.
    assert!(
        noloss_or_structural.is_empty(),
        "REAL PRODUCT BUG: [NoLoss]/[StructuralIndexDiskMismatch] persisted through the real \
         daemon on {} seed(s): {:?}",
        noloss_or_structural.len(),
        noloss_or_structural
    );
}
