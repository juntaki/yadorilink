//! Deterministic-simulation crash/restart recovery test: boots the *real*
//! daemon lifecycle (`app::run(DaemonConfig)`) inside a `madsim` simulation
//! node, drives one local-change indexing cycle, then simulates an
//! **ungraceful crash** (the running daemon task is aborted outright, with
//! no `shutdown_tx` graceful path) leaving persistent state — the on-disk
//! block store and the sqlite `SyncState` — behind on temp paths, plus a
//! deliberately interrupted-materialization footprint (a stuck `Hydrating`
//! index row and an orphaned `.yadorilink-tmp` file in the linked folder).
//! A fresh `app::run` is then booted over the *same* paths and the same
//! device identity; the assertions prove the daemon comes back up cleanly,
//! its real startup recovery ran, and the previously-indexed file survives
//! the crash consistent with disk.
//!
//! This is the whole-daemon analogue of `yadorilink-sync-core`'s
//! `dst_disk_crash_chaos.rs`, which crash-restarts a bare `SyncState`. Here
//! the production `app::run` entry point runs the real startup recovery
//! sequence itself. The passes this test exercises both run
//! *unconditionally* at every boot — before `DaemonState` is published, so
//! by the time the restart's state probe fires the recovery has already
//! completed:
//!   - `SyncState::reset_stale_hydrating_to_placeholder` (resets rows a
//!     crash left stuck mid-hydration), and
//!   - `materialization::cleanup_stale_temp_files` over the block-store root
//!     (removes orphaned `.yadorilink-tmp` files a crash left behind).
//!
//! What is stubbed away so no real network/socket is touched in-sim (all
//! seams are `#[cfg(madsim)]`-gated, so production behavior is unchanged) —
//! identical to `dst_daemon_smoke.rs`:
//!   - Peer orchestrator / update-check scheduler / control + shell-IPC
//!     sockets are not started under `--cfg madsim`; the daemon is driven
//!     through `DaemonState`/`shutdown_tx` via the `state_probe` seam.
//!   - The initial linked-folder watch is fed by
//!     `SimulatedFolderWatchSource` in place of the real OS watcher.
//!
//! Why the link is NOT persisted across the crash: `app::run`'s own startup
//! resumes watching every *persisted* link (`sync_state.list_links()`) via
//! the production `RealFolderWatchSource`, which builds a real `notify` OS
//! watcher — and `notify` spawns a system thread, which madsim forbids
//! (`attempt to spawn a system thread in simulation`). So this test links
//! the folder for the pre-crash indexing pass with a *simulated* source but
//! without `add_link`, exactly as `dst_daemon_smoke.rs` does; the indexed
//! `FileRecord`s persist in sqlite independent of the links table, so the
//! crash/restart of the *index* is fully exercised while the restart boots
//! with no link to auto-resume. The per-link startup passes
//! (`repair_interrupted_materializations` and the per-folder
//! `cleanup_stale_temp_files`) therefore aren't reached in-sim; covering
//! them would need a `#[cfg(madsim)]` seam on the link-resume path so the
//! restart can re-attach a simulated watch source (a production change, out
//! of scope for this first cut).
//!
//! Only compiled/run under `RUSTFLAGS="--cfg madsim"`.

#![cfg(madsim)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use yadorilink_daemon::app::{self, DaemonConfig};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
use yadorilink_sync_core::debounce::DebounceConfig;
use yadorilink_sync_core::types::MaterializationState;
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource};

const GROUP_ID: &str = "dst-daemon-crash-group";

/// Seed-derived deterministic mtime (unix-nanos) stamped onto files the
/// harness writes, so the real `LocalChangeProcessor` indexes a replayable
/// `mtime_unix_nanos` rather than a kernel-stamped wall-clock value. Mirrors
/// `dst_daemon_smoke.rs`'s `deterministic_mtime_nanos` (same rationale:
/// madsim virtualizes `SystemTime::now` but not the kernel's inode mtime
/// stamping).
fn deterministic_mtime_nanos(seed: u64) -> i64 {
    (seed as i64).wrapping_mul(1_000_000_000).wrapping_add(1_000_000_000)
}

/// Stamps `path`'s on-disk mtime to `nanos` (stable-since-1.75
/// `File::set_times`), mirroring `dst_daemon_smoke.rs`. Production code is
/// untouched — this only controls what the real indexing path reads back.
fn stamp_deterministic_mtime(path: &Path, nanos: i64) -> Result<(), String> {
    let modified = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

/// A stable snapshot of one group's indexed state: `(relative path,
/// per-block content hashes as hex)` for every live (non-deleted)
/// `FileRecord`, sorted by path. The block hashes are content-derived, so
/// comparing them across a crash proves the persisted index still describes
/// the same bytes. (mtime/version are intentionally left out: the restart's
/// real-watcher resume re-scans the folder, and only the content identity
/// needs to be crash-stable for the "index matches disk" invariant.)
type IndexSnapshot = Vec<(String, Vec<String>)>;

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
            (r.path.clone(), hashes)
        })
        .collect();
    snapshot.sort();
    Ok(snapshot)
}

/// A booted in-sim daemon: its published `DaemonState` and the join handle
/// of the `app::run` task, so the harness can either request graceful
/// shutdown or `abort()` it outright to simulate a crash.
struct BootedDaemon {
    state: Arc<DaemonState>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Boots `app::run` as an in-sim task over the supplied persistent paths and
/// waits for it to publish its `DaemonState`. Paths are passed in (rather
/// than freshly-allocated temp dirs) so the caller can boot a *second*
/// daemon over the *same* on-disk state after a crash.
async fn boot_daemon(
    config_dir: &Path,
    block_store_root: &Path,
    sync_db_path: &Path,
) -> Result<BootedDaemon, String> {
    let probe: app::StateProbe = Arc::new(Mutex::new(None));
    let config = DaemonConfig {
        config_dir: config_dir.to_path_buf(),
        block_store_root: block_store_root.to_path_buf(),
        sync_db_path: sync_db_path.to_path_buf(),
        control_socket_path: config_dir.join("daemon.sock"),
        shell_ipc_socket_path: config_dir.join("shell.sock"),
        keypair_path: config_dir.join("wg_key"),
        state_probe: Some(probe.clone()),
        sim_discovery: None,
        // This test uses the real, un-decorated block store (no fault injection).
        block_store_override: None,
    };
    let handle = tokio::spawn(app::run(config));
    let state = wait_for_state(&probe, Duration::from_secs(30)).await.ok_or_else(|| {
        "daemon never reached steady state (no DaemonState published)".to_string()
    })?;
    Ok(BootedDaemon { state, handle })
}

/// Lists any orphaned `<name>.yadorilink-tmp.<digits>.<digits>` temp files
/// directly under `dir` — the crash footprint the startup
/// `cleanup_stale_temp_files` pass is responsible for removing.
fn orphaned_tmp_files(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(".yadorilink-tmp.") {
                found.push(name);
            }
        }
    }
    found.sort();
    found
}

async fn scenario_body(seed: u64) -> Result<(), String> {
    // Persistent state lives on temp dirs kept alive for the whole scenario
    // (they must survive the crash so the restart reopens the *same* block
    // store + sqlite). An empty config dir => the daemon is "not logged in",
    // so the peer orchestrator (and its `tonic` client) never starts —
    // identical to `dst_daemon_smoke.rs`.
    let config_dir = tempfile::tempdir().map_err(|e| format!("config tempdir: {e}"))?;
    let block_store_dir = tempfile::tempdir().map_err(|e| format!("block-store tempdir: {e}"))?;
    let watch_root_dir = tempfile::tempdir().map_err(|e| format!("watch-root tempdir: {e}"))?;
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    // Canonicalize the watched root up front (macOS's tempdir lives under a
    // /var -> /private/var symlink), matching the watcher's internal
    // behavior — same note as `dst_daemon_smoke.rs`.
    let root =
        watch_root_dir.path().canonicalize().map_err(|e| format!("canonicalize root: {e}"))?;
    let sync_db_path = config_dir.path().join("sync-state.sqlite3");

    // Pin the session clock onto the seed-derived synthetic timeline the
    // stamped mtimes sit on. It is process-global, so it also governs the
    // restarted daemon's indexing — set once, up front.
    let mtime_nanos = deterministic_mtime_nanos(seed);
    yadorilink_sync_core::peer_session::set_test_clock_override(mtime_nanos);

    // ---- Boot 1: index one file through the real daemon pipeline. --------
    let daemon1 = boot_daemon(config_dir.path(), block_store_dir.path(), &sync_db_path).await?;

    // Wire the simulated watch source for this run. Deliberately no
    // `add_link`: persisting the link would make the *restart* auto-resume
    // it via the real OS watcher (a forbidden system-thread spawn under
    // madsim). The indexed `FileRecord`s persist independently of the links
    // table, so the crash/restart of the index is still fully exercised.
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(64);
    link_manager::start_link_watch_with_source(
        daemon1.state.clone(),
        root.to_string_lossy().to_string(),
        GROUP_ID.to_string(),
        Arc::new(watch_source),
    )
    .map_err(|e| format!("start_link_watch_with_source: {e}"))?;

    let file_path = root.join("hello.txt");
    let content = b"hello daemon, survive the crash and come back consistent";
    std::fs::write(&file_path, content).map_err(|e| format!("write file: {e}"))?;
    stamp_deterministic_mtime(&file_path, mtime_nanos)?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    events_tx
        .send(FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher event channel closed early".to_string())?;

    // Let the debounce window fire and the flush executor index it.
    tokio::time::sleep(DebounceConfig::default().max_flush_interval + Duration::from_millis(500))
        .await;

    let pre_snapshot = capture_index(&daemon1.state)?;
    let indexed_path = pre_snapshot
        .iter()
        .find(|(path, _)| path.ends_with("hello.txt"))
        .map(|(path, _)| path.clone())
        .ok_or_else(|| format!("file was not indexed before crash; snapshot = {pre_snapshot:?}"))?;
    // The file must actually be materialized on disk before we crash.
    match std::fs::read(&file_path) {
        Ok(got) if got == content => {}
        Ok(got) => return Err(format!("pre-crash on-disk content mismatch: {} bytes", got.len())),
        Err(e) => return Err(format!("pre-crash file missing on disk: {e}")),
    }

    // ---- Stage an interrupted-materialization footprint. -----------------
    // (a) A stuck `Hydrating` row — as if the crash hit mid-hydration. The
    //     startup `reset_stale_hydrating_to_placeholder` must clear it.
    daemon1
        .state
        .sync_state
        .set_materialization_state(GROUP_ID, &indexed_path, MaterializationState::Hydrating)
        .map_err(|e| format!("set Hydrating: {e}"))?;
    // (b) An orphaned temp file in the block-store root — as if the crash
    //     hit between an `FsBlockStore::put` writing its temp and the final
    //     rename. The block-store-root `cleanup_stale_temp_files` pass runs
    //     unconditionally at startup (it does not depend on any persisted
    //     link) and must remove it. Naming matches `unique_tmp_path`:
    //     `<name>.yadorilink-tmp.<pid>.<n>`.
    let block_store_root = block_store_dir.path().to_path_buf();
    let orphan_tmp =
        block_store_root.join(format!("block.yadorilink-tmp.{}.1", std::process::id()));
    std::fs::write(&orphan_tmp, b"interrupted block-store put temp")
        .map_err(|e| format!("write orphan tmp: {e}"))?;
    assert!(
        !orphaned_tmp_files(&block_store_root).is_empty(),
        "sanity: orphaned temp file should exist before the crash"
    );

    // ---- CRASH: abort the running daemon task with no graceful shutdown. --
    // No `shutdown_tx` send — the task is killed outright, exactly as a
    // `SIGKILL`/power-loss would. The block store + sqlite files persist on
    // the temp paths; only the process state is gone.
    daemon1.handle.abort();
    drop(events_tx);
    drop(daemon1.state);
    // Yield under simulated time so the aborted task and its spawned
    // essential tasks are reaped before the restart reopens the same state.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ---- RESTART: fresh app::run over the SAME paths / device identity. ---
    let daemon2 = boot_daemon(config_dir.path(), block_store_dir.path(), &sync_db_path).await?;
    // Give the restart's post-`state`-publish work (real-watcher resume +
    // initial disk scan) a beat to settle under simulated time. The recovery
    // itself already ran before `state` was published.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 1) Clean boot: reaching here means `app::run` published `DaemonState`.
    // 2) The previously-indexed file survives, consistent with disk.
    let post_snapshot = capture_index(&daemon2.state)?;
    let post_hashes = post_snapshot
        .iter()
        .find(|(path, _)| path.ends_with("hello.txt"))
        .map(|(_, hashes)| hashes.clone())
        .ok_or_else(|| format!("hello.txt missing from index after restart; {post_snapshot:?}"))?;
    let pre_hashes = pre_snapshot
        .iter()
        .find(|(path, _)| path.ends_with("hello.txt"))
        .map(|(_, hashes)| hashes.clone())
        .expect("pre_snapshot had hello.txt");
    if post_hashes != pre_hashes {
        return Err(format!(
            "hello.txt block hashes changed across crash: pre={pre_hashes:?} post={post_hashes:?}"
        ));
    }
    match std::fs::read(&file_path) {
        Ok(got) if got == content => {}
        Ok(got) => {
            return Err(format!("post-restart on-disk content mismatch: {} bytes", got.len()))
        }
        Err(e) => return Err(format!("post-restart file missing on disk: {e}")),
    }

    // 3) Startup recovery ran:
    //    (a) no orphaned `.yadorilink-tmp` remains in the block-store root.
    let leftover = orphaned_tmp_files(&block_store_root);
    if !leftover.is_empty() {
        return Err(format!("orphaned temp files survived recovery: {leftover:?}"));
    }
    //    (b) no index row was left stuck `Hydrating` — a second reset must
    //        now be a no-op (startup already cleared the staged one).
    let still_stale = daemon2
        .state
        .sync_state
        .reset_stale_hydrating_to_placeholder()
        .map_err(|e| format!("reset_stale_hydrating (post-check): {e}"))?;
    if still_stale != 0 {
        return Err(format!(
            "{still_stale} row(s) were still stuck Hydrating after startup recovery"
        ));
    }

    // 4) Structural invariant: every live (non-deleted) index row is backed
    //    by a real file on disk (no live-row-without-file — a corruption
    //    class the crash window could otherwise open).
    for (path, _) in &post_snapshot {
        let on_disk = root.join(path);
        if !on_disk.exists() {
            return Err(format!("live index row {path:?} has no backing file on disk"));
        }
    }

    // ---- Clean shutdown of the restarted daemon (graceful this time). ----
    daemon2.state.shutdown_tx.send(true).map_err(|e| format!("send shutdown: {e}"))?;
    match tokio::time::timeout(Duration::from_secs(10), daemon2.handle).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(e))) => Err(format!("restarted daemon run returned error: {e}")),
        Ok(Err(join)) => Err(format!("restarted daemon task panicked: {join}")),
        Err(_) => Err("restarted daemon did not shut down within the timeout".to_string()),
    }
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

fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Simulated time is fast-forwarded; this is a ceiling on scheduler steps,
    // not real wall-clock — generous headroom over two boots + a crash.
    rt.set_time_limit(Duration::from_secs(300));
    rt.block_on(scenario_body(seed))
}

/// The daemon crashes (ungraceful abort) after indexing a file with an
/// interrupted-materialization footprint staged, then restarts over the same
/// state and recovers cleanly: the file survives consistent with disk, the
/// orphaned temp file is gone, and no row is left stuck `Hydrating`.
#[test]
fn crashes_and_recovers_indexed_state_in_sim() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
}
