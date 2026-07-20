//! Deterministic-simulation two-device test: boots *two* real daemon
//! lifecycles (`app::run(DaemonConfig)`) inside one `madsim` simulation
//! node, pairs them over a static-netmap discovery seam (no coordination
//! server, no relay), links the same group folder on both, writes a file on
//! daemon A, and asserts daemon B materializes it -- an end-to-end proof
//! that two in-sim daemons can discover each other and converge on a file's
//! content under the seeded, simulated scheduler.
//!
//! This builds on `dst_daemon_smoke.rs` (which proves a *single* daemon
//! boots and indexes in-sim). The one thing the real daemon cannot do
//! in-simulation is discover peers over its coordination-plane netmap
//! stream: the coordination server is a separate service that isn't
//! compiled into the simulation. So discovery is replaced by a
//! `#[cfg(madsim)]` seam on the peer orchestrator
//! (`peer_orchestrator::run_sim` / `SimDiscovery`) that takes a static
//! netmap -- each peer's device id, public key, and pre-bound direct UDP
//! endpoint -- supplied by this harness. Every stage below discovery
//! (`PeerChannel`, `PeerSyncSession`, `broadcast_change` fan-out,
//! materialization) is the identical production code path.
//!
//! Peer transport is direct-only over two loopback UDP sockets on a single
//! simulation node -- the same way `yadorilink-sync-core`'s two-device DST
//! harness pairs devices in-sim (madsim intercepts the tokio UDP sockets).
//!
//! What is stubbed/seamed so no real coordination network is touched (all
//! `#[cfg(madsim)]`-gated, production unchanged):
//!   - Peer discovery: the static-netmap seam above, in place of the
//!     `tonic`/WebSocket coordination netmap stream.
//!   - Control socket + shell-IPC (`UnixListener`): not started under
//!     `--cfg madsim` (see `app.rs`); each daemon is driven through
//!     `DaemonState`/`shutdown_tx` via the `state_probe` seam.
//!   - Local filesystem watcher: replaced by `SimulatedFolderWatchSource`,
//!     exactly as in `dst_daemon_smoke.rs`.
//!
//! Only compiled/run under `RUSTFLAGS="--cfg madsim"`.

#![cfg(madsim)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use yadorilink_daemon::app::{self, DaemonConfig};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
use yadorilink_daemon::peer_orchestrator::{SimDiscovery, SimPeer};
use yadorilink_sync_core::debounce::DebounceConfig;
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource};
use yadorilink_transport::DeviceKeyPair;

const GROUP_ID: &str = "dst-daemon-two-device-group";

/// Seed-derived deterministic mtime (unix-nanos) stamped onto files the
/// harness writes, so the real `LocalChangeProcessor` indexes a replayable
/// `mtime_unix_nanos` rather than a kernel-stamped wall-clock value. Mirrors
/// `dst_daemon_smoke.rs`'s `deterministic_mtime_nanos` (same rationale --
/// madsim virtualizes `SystemTime::now` but not the kernel's inode mtime
/// stamping).
fn deterministic_mtime_nanos(seed: u64) -> i64 {
    (seed as i64).wrapping_mul(1_000_000_000).wrapping_add(1_000_000_000)
}

/// Stamps `path`'s on-disk mtime to `nanos` (stable-since-1.75
/// `File::set_times`), mirroring `dst_daemon_smoke.rs`. Production code is
/// untouched -- this only controls what the real indexing path reads back.
fn stamp_deterministic_mtime(path: &Path, nanos: i64) -> Result<(), String> {
    let modified = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

/// A single simulated daemon under test: its published `DaemonState`, its
/// linked folder root, and the watcher event sender the harness uses to
/// deliver synthetic filesystem events. The temp dirs are kept alive for
/// the whole scenario.
struct SimDaemon {
    state: Arc<DaemonState>,
    root: std::path::PathBuf,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
    _config_dir: tempfile::TempDir,
    _block_store_dir: tempfile::TempDir,
    _watch_root_dir: tempfile::TempDir,
}

/// Builds a `DaemonConfig` on fresh temp dirs, boots `app::run` as an in-sim
/// task, and waits for it to publish its `DaemonState`. `sim_discovery`
/// carries this daemon's identity/keypair and the static netmap entry for
/// its one peer.
async fn boot_daemon(
    sim_discovery: SimDiscovery,
) -> Result<(SimDaemon, tokio::task::JoinHandle<anyhow::Result<()>>), String> {
    let config_dir = tempfile::tempdir().map_err(|e| format!("config tempdir: {e}"))?;
    let block_store_dir = tempfile::tempdir().map_err(|e| format!("block-store tempdir: {e}"))?;
    let watch_root_dir = tempfile::tempdir().map_err(|e| format!("watch-root tempdir: {e}"))?;
    // Canonicalize the watched root (macOS's tempdir lives under a /var ->
    // /private/var symlink), matching the watcher's internal behavior --
    // same note as `dst_daemon_smoke.rs`.
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

    // Link the shared folder through the production wiring, substituting the
    // simulated watch source for the real OS watcher. `add_link` records the
    // link (so the peer session's `sync_roots` -- hence materialization --
    // finds this device's local root), and the watch source lets the
    // harness deliver synthetic events for local writes.
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

async fn scenario_body(seed: u64) -> Result<(), String> {
    // No coordination server in-sim => not "logged in"; point the
    // process-global config lookups at an empty temp dir so `device_config`
    // is absent (each daemon's identity comes from its `SimDiscovery`
    // instead) and no per-user state is touched. Mirrors the smoke test.
    let shared_config_dir =
        tempfile::tempdir().map_err(|e| format!("shared config tempdir: {e}"))?;
    std::env::set_var("YADORILINK_CONFIG_DIR", shared_config_dir.path());

    // Two device keypairs; each daemon's static netmap lists the *other's*
    // public key.
    let keypair_a = DeviceKeyPair::generate();
    let keypair_b = DeviceKeyPair::generate();
    let public_a = keypair_a.public;
    let public_b = keypair_b.public;
    let keypair_a = Arc::new(keypair_a);
    let keypair_b = Arc::new(keypair_b);

    // Pre-bind one direct UDP socket per daemon on the simulation node's
    // loopback; each daemon dials the other's address as its direct
    // candidate (madsim intercepts these sockets). Same shape as the
    // sync-core two-device DST harness.
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

    // Boot both real daemon lifecycles as in-sim tasks. Each links the
    // shared folder on the way up (inside `boot_daemon`).
    let (daemon_a, run_a) = boot_daemon(sim_a).await?;
    let (daemon_b, run_b) = boot_daemon(sim_b).await?;

    // Pin the session clock onto the same seed-derived synthetic timeline
    // the stamped mtimes sit on, matching the smoke test.
    let mtime_nanos = deterministic_mtime_nanos(seed);
    yadorilink_sync_core::peer_session::set_test_clock_override(mtime_nanos);

    // Give both peer channels a beat to pair up under simulated time before
    // generating traffic (not strictly required -- the first index update
    // drives the handshake -- but keeps the causal order clean).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Assert the pairing actually happened (partial-success checkpoint):
    // each daemon should have a connected session for the other.
    wait_for(
        || {
            session_connected(&daemon_a.state, "device-b")
                && session_connected(&daemon_b.state, "device-a")
        },
        Duration::from_secs(30),
    )
    .await
    .map_err(|_| "peers never established a PeerChannel session in-sim".to_string())?;

    // Daemon A writes a file into its linked folder, stamped onto the
    // deterministic timeline, then delivers the synthetic watcher event.
    let content = b"hello from daemon A, across the simulated network";
    let file_a = daemon_a.root.join("hello.txt");
    std::fs::write(&file_a, content).map_err(|e| format!("write file: {e}"))?;
    stamp_deterministic_mtime(&file_a, mtime_nanos)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    daemon_a
        .events_tx
        .send(FsChangeEvent { path: file_a.clone(), kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher event channel closed early".to_string())?;

    // Let A's debounce fire and index, then the change broadcast to B and
    // B materialize it -- all under fast-forwarded simulated time.
    let file_b = daemon_b.root.join("hello.txt");
    wait_for(
        || file_b.exists() && std::fs::read(&file_b).map(|c| c == content).unwrap_or(false),
        DebounceConfig::default().max_flush_interval + Duration::from_secs(60),
    )
    .await
    .map_err(|_| {
        format!(
            "daemon B never materialized the file synced from A (exists={}, sessions_b={:?})",
            file_b.exists(),
            daemon_b
                .state
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        )
    })?;

    let got = std::fs::read(&file_b).map_err(|e| format!("read file on B: {e}"))?;
    if got != content {
        return Err(format!("content diverged on B: got {} bytes", got.len()));
    }

    // Graceful shutdown of both daemons through the same watch channel the
    // control socket's `Shutdown` request uses.
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
    Ok(())
}

fn session_connected(state: &DaemonState, peer_device_id: &str) -> bool {
    state.sessions.lock().unwrap_or_else(|p| p.into_inner()).contains_key(peer_device_id)
}

/// Polls the probe slot (under simulated time) until `app::run` publishes
/// its `DaemonState`, or the deadline passes. Mirrors `dst_daemon_smoke.rs`.
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

/// Polls `cond` under simulated time until it holds or the deadline passes.
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

fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Simulated time is fast-forwarded; this is a ceiling on scheduler
    // steps, not real wall-clock.
    rt.set_time_limit(Duration::from_secs(600));
    rt.block_on(scenario_body(seed))
}

/// Two in-sim daemons discover each other via the static-netmap seam and
/// converge on a file written on A appearing, byte-identical, on B.
#[test]
fn two_daemons_discover_and_sync_a_file_in_sim() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
}
