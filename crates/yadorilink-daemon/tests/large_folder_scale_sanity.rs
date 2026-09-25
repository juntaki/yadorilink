//! One representative ~100k-entry folder tree
//! (not a benchmark project -- a single structural sanity case). Real
//! two-device stack throughout: real `DaemonState`, real file-backed
//! `ReplicaCoordinator`/index DB (so restart is genuine, not vacuous),
//! real directly-paired `PeerSyncSession` over loopback QUIC (same
//! `support::connect_two_daemons` primitive `load_many_small_files.rs`
//! already uses at 200-file scale), real filesystem watcher/scanner,
//! real block store.
//!
//! Deliberately NOT `support::topology`'s `FakeCoordination`-driven
//! harness: that path requires the group's policy snapshot to be
//! admitted via a netmap round trip before any local change can be
//! authored (`SyncError::PolicyUnavailable`), which every existing
//! `topology.rs`-based test avoids only by writing content AFTER
//! `fully_connected`, never before. This file's whole point is
//! pre-existing content on disk before a link ever starts (the "initial
//! full sync" case `load_many_small_files.rs` already establishes at a
//! smaller scale), so it uses that file's own simpler
//! `connect_two_daemons` pairing instead, which needs no coordination
//! plane or policy admission at all.
//!
//! Bar this file checks: initial import completes, initial sync completes, a
//! restart completes, a single-file edit propagates, a rename/delete
//! storm recovers, and the persisted index DB stays proportionate to
//! file count (no pathological/superlinear growth). "No memory
//! explosion" is not measured directly (no portable, precise in-test RSS
//! assertion exists in this codebase) -- the practical proxy is that
//! this whole test, holding ~100k in-memory path strings/records at
//! once at several points, completes at all rather than being OOM-killed
//! or grinding to a functional halt.
//!
//! Deliberately NOT a benchmark: no timing assertions beyond a single
//! generous not-hung ceiling per phase, no iteration/statistics, no
//! micro-tuning target. If this ever needs to become a real perf
//! benchmark, that is C9's job, not this file's.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use support::ensure_device_signing_key;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

/// ~90k small files, spread evenly across ~9k top-level directories (10
/// each) -- exercises "many files, many directories" without deep
/// nesting complexity that would test the directory-scan/watch path
/// rather than this file's own target (raw entry-count scale).
const DIR_COUNT: usize = 9_000;
const FILES_PER_DIR: usize = 10;
const SMALL_FILE_COUNT: usize = DIR_COUNT * FILES_PER_DIR;
/// ~1k medium files at the root, each large enough to span multiple
/// content-defined blocks (`DEFAULT_BLOCK_SIZE` is 128 KiB) -- exercises
/// real multi-block chunking/transfer at scale, not just many tiny
/// single-block files.
const MEDIUM_FILE_COUNT: usize = 1_000;
const MEDIUM_FILE_SIZE: usize = 300 * 1024;
const TOTAL_ENTRY_COUNT: usize = DIR_COUNT + SMALL_FILE_COUNT + MEDIUM_FILE_COUNT;

/// Generous, not a tight correctness gate -- same rationale as
/// `load_many_small_files.rs`'s own timeouts, scaled up for ~500x the
/// entry count and real (if tmpfs-backed) per-file/per-block I/O this
/// scale actually does.
const INITIAL_SYNC_TIMEOUT: Duration = Duration::from_secs(3 * 60 * 60);
const RESTART_RECONCILE_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const INCREMENTAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const STORM_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How often the import-progress loop re-walks B's filesystem
/// (`count_real_files_recursive`) to refresh its cached file count.
/// `count_real_files_recursive` is a full recursive directory walk over up
/// to ~9,000 directories / ~91,000 entries -- doing that every loop tick
/// (the loop's own polling granularity used to BE this walk, at 500ms) means
/// up to 3 hours of continuous full-tree walking, which is real, avoidable
/// I/O load competing with the import it's trying to observe. Detection
/// latency of a few seconds costs nothing against a multi-hour timeout.
const IMPORT_DISK_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
/// How often the (cheap) progress heartbeat logs: two atomic reads
/// (`writer_gate_stats::stats`) plus two `COUNT(*)` queries (`count_live_files`),
/// using whatever `count_real_files_recursive` sample is currently cached
/// rather than forcing a fresh walk.
const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// How often the (expensive) deep diagnostic logs: DAG heads on both
/// sides, the missing-ancestor frontier, B's unapplied-change count, and
/// the sorted call-site/hold-site breakdowns (each of which locks a
/// `Mutex`, clones every entry into a `Vec`, and sorts it) -- real cost,
/// deliberately paid only this often rather than on every heartbeat.
const DEEP_DIAG_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Also force a deep-diagnostic emission (throttled to no more often than
/// this) whenever the cached file count hasn't moved in this long --
/// turns "on_b stopped changing" into a diagnosable event within about a
/// minute instead of only at the next scheduled 5-minute mark.
const DEEP_DIAG_STALL_THRESHOLD: Duration = Duration::from_secs(60);

/// Deterministic, non-repeating-enough-to-dedup-away content for one
/// medium file -- a real chained hash so CDC/fixed chunking sees
/// genuine multi-block content instead of one repeated byte pattern
/// trivially compressible or accidentally block-aligned.
fn medium_file_content(seed: u64) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(MEDIUM_FILE_SIZE);
    let mut block = Sha256::digest(seed.to_le_bytes()).to_vec();
    while out.len() < MEDIUM_FILE_SIZE {
        block = Sha256::digest(&block).to_vec();
        out.extend_from_slice(&block);
    }
    out.truncate(MEDIUM_FILE_SIZE);
    out
}

/// Builds the ~100k-entry tree directly under `root`. Returns the
/// relative paths of a handful of files spread across the tree, for
/// later spot-checks/storm operations without re-deriving the naming
/// scheme in the test body itself.
fn build_large_tree(root: &Path) -> Vec<String> {
    let mut sampled = Vec::new();
    let mut file_index = 0usize;
    for dir_idx in 0..DIR_COUNT {
        let dir_name = format!("dir-{dir_idx:05}");
        let dir_path = root.join(&dir_name);
        std::fs::create_dir(&dir_path).unwrap();
        for _ in 0..FILES_PER_DIR {
            let file_name = format!("f-{file_index:07}.txt");
            std::fs::write(dir_path.join(&file_name), format!("small file {file_index}")).unwrap();
            if file_index.is_multiple_of(7_000) {
                sampled.push(format!("{dir_name}/{file_name}"));
            }
            file_index += 1;
        }
    }
    for i in 0..MEDIUM_FILE_COUNT {
        let file_name = format!("medium-{i:04}.bin");
        std::fs::write(root.join(&file_name), medium_file_content(i as u64)).unwrap();
        if i % 250 == 0 {
            sampled.push(file_name);
        }
    }
    sampled
}

/// Recursively counts real (non-reserved, non-temp-artifact) regular
/// files under `dir` -- the multi-directory-deep equivalent of
/// `support::real_entry_names`, which only lists one directory's own
/// immediate top-level entries and so cannot see files nested under
/// this tree's ~9k subdirectories.
fn count_real_files_recursive(dir: &Path) -> usize {
    let mut count = 0;
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        if yadorilink_root_authority::reserved_namespace::is_reserved_component(&name) {
            continue;
        }
        let name_str = name.to_string_lossy();
        if name_str == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
            || name_str == yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME
            || name_str.contains(".yadorilink-tmp.")
        {
            continue;
        }
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_dir() {
            count += count_real_files_recursive(&entry.path());
        } else if file_type.is_file() {
            count += 1;
        }
    }
    count
}

fn init_tracing() {
    // Default (no `RUST_LOG` set): `error` everywhere except this file's
    // own `c4_scale`-targeted progress logs, at `info`. This file's own
    // logs (every `tracing::info!`/`tracing::warn!` call site here) are
    // all explicitly tagged `target: "c4_scale"` for exactly this reason
    // -- an earlier bare-`info` default surfaced this file's own progress
    // markers fine, but also every OTHER crate's own info/warn output
    // (workspace-wide), which at real ~100k scale means things like the
    // per-block "peer reported block as not_found after retrying" warning
    // (`yadorilink_peer_session`) firing tens of thousands of times over a
    // multi-hour run, drowning the handful of progress lines that actually
    // matter for watching a long run live. A diagnostic run that needs
    // those wider logs back sets `RUST_LOG` explicitly (e.g.
    // `RUST_LOG=warn,c4_scale=info`), which `try_from_default_env` below
    // still takes priority over this default.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error,c4_scale=info")),
        )
        .with_test_writer()
        .try_init();
}

/// One device's persistent state for this test: unlike
/// `load_many_small_files.rs`'s in-memory `ReplicaCoordinator`, this
/// file needs a genuine on-disk index DB so restart is real, not
/// vacuous -- `db_dir` is kept alive alongside `state` for exactly that
/// reason (dropping it would delete the DB out from under a later
/// restart).
struct Device {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_dir: tempfile::TempDir,
    _db_dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
}

fn new_device(device_id: &str) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.db");
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    ensure_device_signing_key(&state);
    Device {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        store_dir,
        _db_dir: db_dir,
        db_path,
    }
}

/// Restarts `device` in place: stops its link runtime, drops the old
/// `DaemonState`/`ReplicaCoordinator` (closing the old SQLite
/// connection pool), and reopens a fresh `DaemonState` against the SAME
/// on-disk index DB and block store -- preserving device identity (the
/// signing key) exactly like a real restart reloading it from the OS
/// keyring, matching `support::topology::restart_node`'s own established
/// discipline for this workspace's other restart scenarios.
async fn restart_device(mut device: Device, group_id: &str) -> Device {
    let local_path = device.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(device.state.clone()).stop(&local_path).await;
    let signing_key = device.state.device_signing_key().expect("signing key was set");
    drop(device.state);

    let mut open_attempts = 0;
    let sync_state = loop {
        match ReplicaCoordinator::open(&device.db_path) {
            Ok(coordinator) => break Arc::new(coordinator),
            Err(error) if open_attempts < 10 => {
                open_attempts += 1;
                tracing::warn!(
                    target: "c4_scale",
                    %error,
                    open_attempts,
                    "reopening the index DB failed, retrying"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("could not reopen the index DB: {error}"),
        }
    };
    let state = DaemonState::new(
        device.device_id.clone(),
        sync_state,
        Arc::new(SegmentBlockStore::new(device.store_dir.path()).unwrap()),
    );
    state.set_device_signing_key(signing_key);
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();

    device.state = state;
    device
}

// Not run in CI -- same rationale as `load_many_small_files.rs`'s
// identically-tagged test: a real-wall-clock scale sanity case's value
// comes from being run deliberately when this area of the code changes,
// not from gating every push on a run that can take a very long time at
// this entry count. Run locally with `cargo test -- --ignored`.
