//! Deterministic-simulation smoke test: boots the *real* daemon lifecycle
//! (`app::run(DaemonConfig)`) inside a `madsim` simulation node and drives
//! one end-to-end local-change indexing cycle under the seeded, simulated
//! scheduler.
//!
//! Unlike the `yadorilink-sync-core` DST harness (which reproduces the
//! watcher -> debounce -> indexing pipeline directly against
//! `yadorilink-sync-core`, since that crate cannot depend on the daemon),
//! this test starts the production `app::run` entry point itself: the same
//! startup sequence, `DaemonState`, essential-task supervisor, and
//! top-level shutdown `select!` the real binary runs. It is the first
//! end-to-end proof that the daemon can boot and reach steady state
//! in-simulation.
//!
//! What is stubbed away so no real network/socket is touched in-sim (all
//! seams are `#[cfg(madsim)]`/`cfg(not(madsim))`-gated, so production
//! behavior is unchanged):
//!   - Peer orchestrator (`tonic` coordination client): started only when a
//!     device config *and* an access token are present. This test points
//!     `YADORILINK_CONFIG_DIR` at an empty temp dir, so the daemon is "not
//!     logged in" and the orchestrator is never started — no `tonic`.
//!   - Update-check scheduler (`reqwest`): not spawned under `--cfg madsim`
//!     (see `daemon_state.rs`).
//!   - Control socket + shell-IPC (`UnixListener`): their essential tasks
//!     are not started under `--cfg madsim` (see `app.rs`); this test
//!     drives the daemon through `DaemonState`/`shutdown_tx` directly via
//!     the `state_probe` seam instead.
//!
//! Only compiled/run under `RUSTFLAGS="--cfg madsim"`; a plain `cargo test`
//! never builds this file.

#![cfg(madsim)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use yadorilink_daemon::app::{self, DaemonConfig};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
use yadorilink_sync_core::debounce::DebounceConfig;
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource};

const GROUP_ID: &str = "dst-daemon-smoke-group";

/// The seed-derived deterministic mtime (unix-nanos) the harness stamps
/// onto every file it writes, so the real `LocalChangeProcessor` indexes a
/// replayable `mtime_unix_nanos` rather than a kernel-stamped real
/// wall-clock value.
///
/// WHY THIS IS NEEDED: madsim virtualizes `SystemTime::now`/`clock_gettime`
/// (so every daemon `now_unix()` read is already per-seed deterministic
/// in-sim), but it does *not* intercept the kernel's inode-mtime stamping —
/// a real `std::fs::write` gets a real wall-clock mtime. The daemon's
/// indexing reads that mtime straight off `metadata.modified()`
/// (`sync-core::local_change`) into the persisted `FileRecord`, so without
/// this stamp two same-seed runs diverge on mtime (verified: three runs
/// produced three distinct nanosecond mtimes). This is the one real
/// wall-clock leak into observable in-sim index state.
///
/// The value mirrors `sync-core`'s `dst_support::HarnessClock::from_seed`
/// origin (`seed * 1e9`) plus one `MTIME_STEP_NANOS` (+1s), and is pushed
/// onto `sync-core`'s process-wide session-clock override too, so conflict
/// resolution's `now_unix_nanos` sits on the same synthetic timeline the
/// stamped mtimes do — the same reuse the `sync-core` DST scenarios make.
fn deterministic_mtime_nanos(seed: u64) -> i64 {
    (seed as i64).wrapping_mul(1_000_000_000).wrapping_add(1_000_000_000)
}

/// Stamps `path`'s on-disk mtime to `nanos`, mirroring `sync-core`'s
/// `dst_support::fs_ops` stamp (the stable-since-1.75 `File::set_times`
/// primitive, no extra crate). Production code is untouched — this only
/// controls what the real indexing path later reads back off the file.
fn stamp_deterministic_mtime(path: &Path, nanos: i64) -> Result<(), String> {
    let modified = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

/// A stable, comparable snapshot of one group's indexed state: the tuple
/// `(relative path, mtime in unix-nanos, per-block content hashes as hex)`
/// for every live (non-deleted) `FileRecord`, sorted by path. This is the
/// observable index state a replay-equivalence check must find byte-
/// identical across two runs of the same seed (paths + mtimes + content
/// hashes — the three things a redelivered index carries).
type IndexSnapshot = Vec<(String, i64, Vec<String>)>;

/// Reads the linked group's live records out of `DaemonState` and folds
/// them into a deterministic, order-independent [`IndexSnapshot`].
fn capture_index(state: &DaemonState) -> Result<IndexSnapshot, String> {
    let files = state.sync_state.list_files(GROUP_ID).map_err(|e| format!("list_files: {e}"))?;
    let mut snapshot: IndexSnapshot = files
        .iter()
        .filter(|r| !r.deleted)
        .map(|r| {
            let hashes = r
                .blocks
                .iter()
                .map(|b| b.hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>())
                .collect::<Vec<_>>();
            (r.path.clone(), r.mtime_unix_nanos, hashes)
        })
        .collect();
    snapshot.sort();
    Ok(snapshot)
}

/// One seeded, fully deterministic simulated run of the whole scenario,
/// returning the resulting [`IndexSnapshot`] so callers can assert on it
/// (e.g. the replay-equivalence gate) rather than only on success/failure.
fn run_scenario(seed: u64) -> Result<IndexSnapshot, String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Simulated time is fast-forwarded, so this is a ceiling on scheduler
    // steps, not real wall-clock — generous headroom over what the scenario
    // needs (a debounce window plus a couple of short polls).
    rt.set_time_limit(Duration::from_secs(120));
    rt.block_on(scenario_body(seed))
}

async fn scenario_body(seed: u64) -> Result<IndexSnapshot, String> {
    // Isolate every process-global config lookup (`device_config::load`,
    // `token_store::load_access_token`, `UpdateManager`) onto an empty temp
    // dir. Empty => not logged in, no registered device => the peer
    // orchestrator (and its `tonic` coordination client) is never started.
    let config_dir = tempfile::tempdir().map_err(|e| format!("config tempdir: {e}"))?;
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    let block_store_dir = tempfile::tempdir().map_err(|e| format!("block-store tempdir: {e}"))?;
    let watch_root_dir = tempfile::tempdir().map_err(|e| format!("watch-root tempdir: {e}"))?;
    // Canonicalize the watched root up front, matching what the real
    // watcher does internally — macOS's tempdir lives under a `/var` symlink
    // to `/private/var`, so path-prefix stripping during indexing would
    // otherwise silently mismatch (same note as the sync-core DST harness).
    let root =
        watch_root_dir.path().canonicalize().map_err(|e| format!("canonicalize root: {e}"))?;

    // The slot `app::run` publishes its `DaemonState` into once built.
    let probe: app::StateProbe = Arc::new(Mutex::new(None));

    let config = DaemonConfig {
        config_dir: config_dir.path().to_path_buf(),
        block_store_root: block_store_dir.path().to_path_buf(),
        sync_db_path: config_dir.path().join("sync-state.sqlite3"),
        control_socket_path: config_dir.path().join("daemon.sock"),
        shell_ipc_socket_path: config_dir.path().join("shell.sock"),
        keypair_path: config_dir.path().join("wg_key"),
        state_probe: Some(probe.clone()),
        // This smoke test drives a single daemon with no peers, so it never
        // supplies a static netmap (that is the two-device test's job).
        sim_discovery: None,
        // This test uses the real, un-decorated block store (no fault injection).
        block_store_override: None,
    };

    // Boot the real daemon lifecycle as an in-sim task. It owns its whole
    // lifecycle and only returns on graceful shutdown (or a fatal essential
    // task death), so we drive it from the outside via `state`/`shutdown_tx`.
    let daemon = tokio::spawn(app::run(config));

    // 1) BOOTS + REACHES STEADY STATE: wait for `run` to publish its state.
    let state: Arc<DaemonState> =
        wait_for_state(&probe, Duration::from_secs(30)).await.ok_or_else(|| {
            "daemon never reached steady state (no DaemonState published)".to_string()
        })?;

    // 2) WATCHES: link a folder through the production wiring, substituting
    // the simulated watch source for the real OS filesystem watcher. Every
    // downstream stage (debounce, indexing, materialization) is the real
    // daemon code.
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(64);
    link_manager::start_link_watch_with_source(
        state.clone(),
        root.to_string_lossy().to_string(),
        GROUP_ID.to_string(),
        Arc::new(watch_source),
    )
    .map_err(|e| format!("start_link_watch_with_source: {e}"))?;

    // 3) INDEXES: write a file, then deliver the synthetic watcher event for
    // it. The scenario controls the timing relative to the write, exactly
    // like the sync-core harness.
    let file_path = root.join("hello.txt");
    let content = b"hello daemon, from inside the simulator";
    std::fs::write(&file_path, content).map_err(|e| format!("write file: {e}"))?;
    // Pin this write's mtime (and, via the session-clock override, conflict
    // resolution's `now`) onto one seed-derived synthetic timeline, so the
    // real indexing path reads a replayable mtime instead of the kernel's
    // real wall-clock stamp. See `deterministic_mtime_nanos`.
    let mtime_nanos = deterministic_mtime_nanos(seed);
    stamp_deterministic_mtime(&file_path, mtime_nanos)?;
    yadorilink_sync_core::peer_session::set_test_clock_override(mtime_nanos);
    tokio::time::sleep(Duration::from_millis(5)).await;
    events_tx
        .send(FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher event channel closed early".to_string())?;

    // Let the debounce quiet-period / max-flush-interval fire under
    // simulated (fast-forwarded) time, then the flush executor index it.
    tokio::time::sleep(DebounceConfig::default().max_flush_interval + Duration::from_millis(500))
        .await;

    // Observe the index update: the real `LocalChangeProcessor` should have
    // written a `FileRecord` for the file we created.
    let snapshot = capture_index(&state)?;
    let indexed = snapshot.iter().any(|(path, _, _)| path.ends_with("hello.txt"));
    if !indexed {
        return Err(format!("file was not indexed by the daemon; snapshot = {snapshot:?}"));
    }

    // 4) SHUTS DOWN CLEANLY: request graceful shutdown through the same
    // watch channel the control socket's `Shutdown` request would use, then
    // confirm `app::run` returns `Ok(())` within a bounded simulated window.
    state.shutdown_tx.send(true).map_err(|e| format!("send shutdown: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), daemon).await {
        Ok(Ok(Ok(()))) => Ok(snapshot),
        Ok(Ok(Err(e))) => Err(format!("daemon run returned error: {e}")),
        Ok(Err(join)) => Err(format!("daemon task panicked: {join}")),
        Err(_) => Err("daemon did not shut down within the timeout".to_string()),
    }
}

/// Polls the probe slot (under simulated time) until `app::run` publishes
/// its `DaemonState`, or the deadline passes.
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

/// Single-seed smoke run. A fixed seed is enough for a plumbing smoke test;
/// broadening into a many-seed sweep (like the sync-core harness) is a
/// follow-up once the daemon boot path is proven in-sim.
#[test]
fn boots_watches_and_indexes_in_sim() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let snapshot = run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
    assert!(
        snapshot.iter().any(|(path, _, _)| path.ends_with("hello.txt")),
        "seed {seed}: expected hello.txt in the indexed snapshot, got {snapshot:?}"
    );
}

/// P1.6 replay-equivalence gate: the whole daemon boot -> watch -> index
/// cycle must be time-deterministic, so running the *same seed twice*
/// produces a byte-identical index snapshot (paths + mtimes + content
/// hashes). This is the concrete guard that no real wall-clock leaks into
/// observable in-sim state; if a future change reintroduces a
/// kernel-stamped mtime (or any other real-clock read) into the persisted
/// index, the two snapshots diverge and this fails.
#[test]
fn same_seed_replays_byte_identically() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let first = run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} run 1 failed: {e}"));
    let second = run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} run 2 failed: {e}"));
    assert_eq!(
        first, second,
        "seed {seed}: index snapshot was not replay-identical across two runs\n\
         run 1 = {first:?}\nrun 2 = {second:?}"
    );
}
