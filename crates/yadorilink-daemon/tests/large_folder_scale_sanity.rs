//! Competitive Hardening C4: one representative ~100k-entry folder tree
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
//! Exit bar this file checks, matching the Competitive Hardening C4
//! stage exactly: initial import completes, initial sync completes, a
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

use support::{daemon_status_summary, ensure_device_signing_key, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;

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
/// (`c4_diag::stats`) plus two `COUNT(*)` queries (`count_live_files`),
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
            if file_index % 7_000 == 0 {
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
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
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
        Arc::new(FsBlockStore::new(device.store_dir.path()).unwrap()),
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
#[ignore = "large-scale sanity case -- run explicitly, not in CI (see module doc)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hundred_thousand_entry_folder_survives_import_sync_restart_and_storms() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let group_id = "c4-scale-group";

    let a = new_device("c4-a");
    let mut b = new_device("c4-b");

    tracing::info!(
        target: "c4_scale",
        TOTAL_ENTRY_COUNT,
        "building the C4 tree on device A before it ever links"
    );
    let build_started = std::time::Instant::now();
    let sampled_paths = build_large_tree(a.root.path());
    tracing::info!(target: "c4_scale", elapsed = ?build_started.elapsed(), "C4 tree built on disk");
    assert_eq!(
        count_real_files_recursive(a.root.path()),
        SMALL_FILE_COUNT + MEDIUM_FILE_COUNT,
        "sanity: the generator itself produced the expected file count before any sync began"
    );

    // Linking after the tree already exists on A (B stays empty) —
    // matching `load_many_small_files.rs`'s own "initial full index
    // exchange", the `sync-engine` spec's "Initial Full Sync"
    // requirement, exercised at ~500x that file's own scale.
    let local_path_a = a.root.path().to_string_lossy().to_string();
    a.state.replica_coordinator.link_repository().add_link(&local_path_a, group_id).unwrap();
    LinkRuntimeController::new(a.state.clone()).start(local_path_a, group_id.to_string()).unwrap();
    let local_path_b = b.root.path().to_string_lossy().to_string();
    b.state.replica_coordinator.link_repository().add_link(&local_path_b, group_id).unwrap();
    LinkRuntimeController::new(b.state.clone())
        .start(local_path_b.clone(), group_id.to_string())
        .unwrap();

    let (session_handles, session_channels) = support::connect_two_daemons_with_channels(
        &a.state,
        "c4-a",
        &b.state,
        "c4-b",
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    let sync_started = std::time::Instant::now();
    // Periodic import/sync progress snapshot, mirroring the storm phase's own
    // block below: the plain `wait_until_with_context` this replaces polls
    // silently, so a run that is technically progressing but far too slowly to
    // finish is indistinguishable from a hard stall until the (multi-hour)
    // deadline fires.
    //
    // Three different cadences, deliberately NOT all run on the loop's own
    // tick: `count_real_files_recursive` is a full recursive walk over up to
    // ~9,000 directories / ~91,000 entries, so re-running it on every tick
    // (this loop used to BOTH tick and re-walk every 500ms) means up to 3
    // hours of continuous full-tree walking competing with the import it's
    // trying to observe, for detection latency nobody needs against a
    // multi-hour timeout. Likewise, `call_site_stats`/`hold_site_stats` each
    // lock a `Mutex`, clone every entry into a `Vec`, and sort it -- real
    // cost, worth paying only at `DEEP_DIAG_INTERVAL`'s cadence (or when
    // progress has visibly stalled, or near the deadline), not on every
    // lightweight heartbeat.
    {
        let target = SMALL_FILE_COUNT + MEDIUM_FILE_COUNT;
        let deadline = tokio::time::Instant::now() + INITIAL_SYNC_TIMEOUT;
        let mut cached_on_b = count_real_files_recursive(b.root.path());
        let mut last_disk_sample = tokio::time::Instant::now();
        let mut last_progress_log = tokio::time::Instant::now();
        let mut last_deep_diag = tokio::time::Instant::now();
        let mut last_progress_change = (tokio::time::Instant::now(), cached_on_b);
        loop {
            if last_disk_sample.elapsed() >= IMPORT_DISK_SAMPLE_INTERVAL {
                cached_on_b = count_real_files_recursive(b.root.path());
                last_disk_sample = tokio::time::Instant::now();
                if cached_on_b != last_progress_change.1 {
                    last_progress_change = (tokio::time::Instant::now(), cached_on_b);
                }
            }
            if cached_on_b >= target {
                break;
            }
            let now = tokio::time::Instant::now();
            if now > deadline {
                panic!(
                    "initial import/sync of {TOTAL_ENTRY_COUNT} entries never converged; B has \
                     {cached_on_b} real files so far; device A: {}; device B: {}",
                    daemon_status_summary(&a.state),
                    daemon_status_summary(&b.state),
                );
            }
            let stalled = last_progress_change.0.elapsed() >= DEEP_DIAG_STALL_THRESHOLD;
            let near_deadline =
                deadline.saturating_duration_since(now) <= DEEP_DIAG_STALL_THRESHOLD;
            let deep_diag_due = last_deep_diag.elapsed() >= DEEP_DIAG_INTERVAL
                || ((stalled || near_deadline)
                    && last_deep_diag.elapsed() >= DEEP_DIAG_STALL_THRESHOLD);
            if last_progress_log.elapsed() >= PROGRESS_LOG_INTERVAL {
                let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
                let a_indexed = a
                    .state
                    .replica_coordinator
                    .file_index_repository()
                    .count_live_files(group_id)
                    .unwrap_or(0);
                let b_indexed = b
                    .state
                    .replica_coordinator
                    .file_index_repository()
                    .count_live_files(group_id)
                    .unwrap_or(0);
                tracing::info!(
                    target: "c4_scale",
                    on_b = cached_on_b,
                    target,
                    a_indexed,
                    b_indexed,
                    writer_gate_acquisitions = gate_acquisitions,
                    writer_gate_wait_ms = gate_wait.as_millis() as u64,
                    import_elapsed_ms = sync_started.elapsed().as_millis() as u64,
                    "C4_IMPORT_PROGRESS"
                );
                last_progress_log = tokio::time::Instant::now();
            }
            if deep_diag_due {
                let top_call_sites: String = yadorilink_sqlite_runtime::c4_diag::call_site_stats()
                    .iter()
                    .take(20)
                    .map(|(loc, n)| format!("{n}x {loc}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                tracing::info!(target: "c4_scale", top_call_sites, "C4_IMPORT_CALL_SITES");
                let top_hold_sites: String = yadorilink_sqlite_runtime::c4_diag::hold_site_stats()
                    .iter()
                    .take(20)
                    .map(|(loc, n, micros)| format!("{}ms/{n}x {loc}", micros / 1000))
                    .collect::<Vec<_>>()
                    .join(" | ");
                tracing::info!(target: "c4_scale", top_hold_sites, "C4_IMPORT_HOLD_SITES");
                // Where is B actually stuck? Separates "the changes never
                // arrived" from "the DAG caught up but projection has not run"
                // from "projection ran but the bytes are not on disk yet" --
                // three completely different bugs that look identical from
                // `on_b` alone. Same shape as `rename_delete_modest_scale.rs`'s
                // own storm-phase block.
                let a_heads = a
                    .state
                    .replica_coordinator
                    .sqlite()
                    .dag_group_heads(group_id)
                    .unwrap_or_default();
                let b_heads = b
                    .state
                    .replica_coordinator
                    .sqlite()
                    .dag_group_heads(group_id)
                    .unwrap_or_default();
                let a_heads_missing_on_b = b
                    .state
                    .replica_coordinator
                    .sqlite()
                    .dag_missing_ancestor_frontier(a_heads.iter().copied())
                    .map(|f| f.len())
                    .unwrap_or(usize::MAX);
                let b_unapplied_changes = b
                    .state
                    .replica_coordinator
                    .change_history_repository()
                    .dag_list_unapplied_changes(group_id)
                    .map(|c| c.len())
                    .unwrap_or(usize::MAX);
                tracing::info!(
                    target: "c4_scale",
                    a_group_heads = a_heads.len(),
                    b_group_heads = b_heads.len(),
                    a_heads_missing_on_b,
                    b_unapplied_changes,
                    on_b = cached_on_b,
                    stalled,
                    near_deadline,
                    "C4_IMPORT_B_STATE"
                );
                last_deep_diag = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    tracing::info!(
        target: "c4_scale",
        elapsed = ?sync_started.elapsed(),
        TOTAL_ENTRY_COUNT,
        "initial import + sync of the C4 tree completed"
    );

    // Spot-check content on a scattered sample, not every file -- this is
    // a structural sanity case, not a byte-for-byte audit of 91k files.
    for rel_path in &sampled_paths {
        let a_bytes = std::fs::read(a.root.path().join(rel_path)).unwrap();
        let b_bytes = std::fs::read(b.root.path().join(rel_path))
            .unwrap_or_else(|e| panic!("B never materialized sampled path {rel_path:?}: {e}"));
        assert_eq!(a_bytes, b_bytes, "content mismatch for sampled path {rel_path:?}");
    }

    // No pathological/superlinear DB growth: a rough, deliberately loose
    // sanity bound (not a tuned perf target) -- a healthy per-file index
    // row plus its version history is at most a few hundred bytes; a
    // structural bug that duplicated rows per file or per sync round
    // would blow well past this, while ordinary SQLite page overhead at
    // this row count would not.
    let db_size_bytes = std::fs::metadata(&b.db_path).unwrap().len();
    let max_reasonable_bytes = (TOTAL_ENTRY_COUNT as u64) * 4_096;
    assert!(
        db_size_bytes < max_reasonable_bytes,
        "device B's index DB is {db_size_bytes} bytes for {TOTAL_ENTRY_COUNT} entries -- \
         over the {max_reasonable_bytes}-byte sanity bound, suggesting unbounded/duplicated \
         per-file growth rather than ordinary index overhead"
    );

    // Restart completes: reopen the SAME persisted ~100k-row index DB
    // and block store. The interesting failure mode here isn't "does it
    // restart" in the abstract -- it's "does the startup reconciliation
    // scan over ~91k already-materialized files complete in bounded
    // time and without re-fetching anything," which the
    // `RESTART_RECONCILE_TIMEOUT` wait below directly proves.
    //
    // The pre-restart session's own channels are closed FIRST (the real
    // disconnect primitive -- see `connect_two_daemons_with_channels`'s
    // own doc comment for why aborting the task handles is not enough:
    // `PeerSyncSession::run` spawns its own detached child tasks that
    // only unwind via `run`'s normal close-observed exit path) so the
    // OLD generation's `PeerSyncSession` -- which independently holds a
    // strong `Arc` on the pre-restart `DaemonState`/`ReplicaCoordinator`
    // -- actually releases it, instead of running concurrently against
    // the SAME on-disk root/index DB as the freshly reopened post-
    // restart generation. Two live generations fighting over the same
    // sync-root lock sidecar file is exactly what produced a real,
    // reproduced failure here: "sync-root lock sidecar ... could not be
    // re-observed" well into the post-restart phase.
    //
    // `drop(session_channels)` alone does NOT do this: each session task
    // was spawned holding its own `Arc<QuicPeerChannel>` clone (see
    // `connect_two_daemons_with_channels`'s `channel_a.clone()`/
    // `channel_b.clone()`), so dropping only the caller's copy never
    // brings the refcount to zero, `QuicPeerChannel`'s `Drop` never
    // fires, `recv()` never observes a close, and `PeerSyncSession::run`
    // never exits -- the `handle.await` below would then hang forever, a
    // real hang this file's own calibration run at ~1k-file scale hit
    // (confirmed: `close_revoked`/`is_open` is the exact working pattern
    // `exec_bit_metadata_conflict.rs`'s
    // `shared_history_unix_mode_only_divergence_converges_after_reconnect`
    // already uses for this same "genuinely sever the pairing" need).
    // Explicitly closing the connection, independent of how many `Arc`
    // clones exist, is what actually makes `recv()` return `None`.
    for channel in &session_channels {
        channel.close_revoked();
    }
    wait_until_with_context(
        || session_channels.iter().all(|channel| !channel.is_open()),
        Duration::from_secs(10),
        || "pre-restart peer connections never closed".to_string(),
    )
    .await;
    drop(session_channels);
    for handle in session_handles {
        let _ = handle.await;
    }
    // `count_real_files_recursive(b.root.path()) >= expected` is true the
    // instant `restart_device` returns -- B's ~91k files never left disk
    // across restart, so that condition proves nothing about whether the
    // restarted runtime's own startup reconciliation (disk scan ->
    // post-scan convergence/history -> dirty-journal redrive ->
    // `startup_ready_guard.mark_ready()`) ever ran to completion.
    // `restart_device` itself stays exactly as async as a real restart is:
    // it returns once the new `LinkRuntime` has been started, not once
    // startup has reached Ready. Only `wait_group_ready()` below proves
    // Ready; the file-count/index checks after it are a separate
    // corruption sanity check, not the readiness signal.
    let restart_started = std::time::Instant::now();
    b = restart_device(b, group_id).await;
    let (_session_handles, _session_channels) = support::connect_two_daemons_with_channels(
        &a.state,
        "c4-a",
        &b.state,
        "c4-b",
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    match tokio::time::timeout(
        RESTART_RECONCILE_TIMEOUT,
        b.state.replica_coordinator.wait_group_ready(group_id),
    )
    .await
    {
        Err(_) => panic!(
            "device B's restarted link never completed startup reconciliation within \
             {RESTART_RECONCILE_TIMEOUT:?}; device B: {}",
            daemon_status_summary(&b.state),
        ),
        Ok(Err(failed)) => panic!(
            "device B's restarted link startup failed instead of becoming Ready: {failed:?}; \
             device B: {}",
            daemon_status_summary(&b.state),
        ),
        Ok(Ok(())) => {}
    }
    let restart_to_ready = restart_started.elapsed();
    tracing::info!(
        target: "c4_scale",
        elapsed = ?restart_to_ready,
        "C4_RESTART_READY: device B's restarted link reported real startup Ready"
    );

    // The restart itself must not have lost or corrupted anything: still
    // exactly the same real file count immediately after B comes back.
    assert_eq!(
        count_real_files_recursive(b.root.path()),
        SMALL_FILE_COUNT + MEDIUM_FILE_COUNT,
        "device B's on-disk file count changed across its own restart"
    );
    // Ready must mean a complete live index, not just "the bytes on disk
    // happen to still be there from before restart" -- an incomplete index
    // with a full disk would pass the byte-count check above while still
    // being a false "Ready".
    let restarted_index_count = b
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .unwrap()
        .into_iter()
        .filter(|r| !r.deleted)
        .count();
    assert_eq!(
        restarted_index_count,
        SMALL_FILE_COUNT + MEDIUM_FILE_COUNT,
        "restart reported Ready with an incomplete live index"
    );
    tracing::info!(
        target: "c4_scale",
        elapsed = ?restart_started.elapsed(),
        "device B restart + reconcile completed"
    );

    // A single-file edit still propagates correctly at this scale -- not
    // just bulk initial sync. Split the wait into the same causal
    // boundaries `c4_diag` already distinguishes for the import phase
    // above, so a stall here is attributable instead of only visible as
    // "B's bytes never changed" -- local DAG admission on A, anti-entropy
    // delivery to B's DAG, and B's own materialization onto disk are three
    // different bugs that look identical from the file content alone. If
    // the final wait below times out, its panic states which of these
    // boundaries was last proven.
    yadorilink_peer_session::c4_diag::reset();
    let a_heads_before = a.state.replica_coordinator.sqlite().dag_group_heads(group_id).unwrap();
    let rel_path = sampled_paths[0].clone();
    let edited_path = a.root.path().join(&rel_path);
    let incremental_started = std::time::Instant::now();
    std::fs::write(&edited_path, b"edited after restart, at scale").unwrap();

    // Boundary 1+2: A's own DAG admits the edit, giving us the exact new
    // `ChangeHash` to track through the rest of the boundaries below.
    wait_until_with_context(
        || {
            a.state.replica_coordinator.sqlite().dag_group_heads(group_id).unwrap_or_default()
                != a_heads_before
        },
        INCREMENTAL_TIMEOUT,
        || {
            format!(
                "post-restart edit to {rel_path:?} was never even admitted into A's own DAG \
                 (watcher/debounce/local-capture stall on the origin device, before any \
                 anti-entropy is involved); device A: {}",
                daemon_status_summary(&a.state),
            )
        },
    )
    .await;
    let new_a_head = a
        .state
        .replica_coordinator
        .sqlite()
        .dag_group_heads(group_id)
        .unwrap()
        .into_iter()
        .find(|h| !a_heads_before.contains(h))
        .expect("a new head must exist: dag_group_heads just proved it differs from before");
    tracing::info!(
        target: "c4_scale",
        elapsed = ?incremental_started.elapsed(),
        "C4_INCREMENTAL_BOUNDARY: A admitted the new change into its own DAG"
    );

    // Boundary 3: the exact new change reaches B via anti-entropy.
    wait_until_with_context(
        || {
            b.state
                .replica_coordinator
                .change_history_repository()
                .dag_has_change(&new_a_head)
                .unwrap_or(false)
        },
        INCREMENTAL_TIMEOUT,
        || {
            let protocol = yadorilink_peer_session::c4_diag::stats();
            format!(
                "post-restart edit's new DAG change never reached device B via anti-entropy \
                 (A admitted it locally, but B never received it) -- last proven boundary: A \
                 DAG admission only; protocol: {protocol:?}; device A: {}; device B: {}",
                daemon_status_summary(&a.state),
                daemon_status_summary(&b.state),
            )
        },
    )
    .await;
    tracing::info!(
        target: "c4_scale",
        elapsed = ?incremental_started.elapsed(),
        protocol = ?yadorilink_peer_session::c4_diag::stats(),
        "C4_INCREMENTAL_BOUNDARY: B received the new change via anti-entropy"
    );

    // Boundary 4+5: B's projection obligation for the edited path settles
    // and the bytes land on disk.
    wait_until_with_context(
        || {
            std::fs::read(b.root.path().join(&rel_path)).ok()
                == Some(b"edited after restart, at scale".to_vec())
        },
        INCREMENTAL_TIMEOUT,
        || {
            format!(
                "device B has the new change in its DAG but never materialized it onto disk at \
                 {rel_path:?} (projection obligation stuck) -- last proven boundary: B has the \
                 exact new DAG change; device B: {}",
                daemon_status_summary(&b.state),
            )
        },
    )
    .await;
    tracing::info!(
        target: "c4_scale",
        elapsed = ?incremental_started.elapsed(),
        "C4_INCREMENTAL_BOUNDARY: B materialized the new change onto disk"
    );

    // Rename/delete storm recovers: a real batch mutation across several
    // hundred paths at once, spread across many directories (renaming
    // every file in a run of directories, deleting every file in a
    // disjoint run of directories) -- the shape most likely to expose an
    // O(N^2) reconcile/negotiation path or an unbounded per-change-batch
    // payload, not just one change at a time.
    // `RECONCILE_CHUNK_OP_LIMIT`/`IMPORT_BATCH_OP_LIMIT` already bound
    // any single change's own op count; this proves the bulk path that
    // exercises those limits still converges.
    // C4_DIAG (temporary, remove after investigation): zero the writer-gate
    // counters right before the storm's own filesystem mutations, so the
    // stats logged below reflect only this storm's DB write-transaction
    // cost, not startup/import's.
    yadorilink_sqlite_runtime::c4_diag::reset();
    let c4_diag_storm_started = std::time::Instant::now();

    let storm_dirs = 50.min(DIR_COUNT / 2);
    let mut renamed_paths = Vec::with_capacity(storm_dirs * FILES_PER_DIR);
    let mut old_renamed_paths = Vec::with_capacity(storm_dirs * FILES_PER_DIR);
    for dir_idx in 0..storm_dirs {
        let dir_name = format!("dir-{dir_idx:05}");
        let dir_path = a.root.path().join(&dir_name);
        for i in 0..FILES_PER_DIR {
            let global_index = dir_idx * FILES_PER_DIR + i;
            let from_name = format!("f-{global_index:07}.txt");
            let to_name = format!("renamed-{global_index:07}.txt");
            std::fs::rename(dir_path.join(&from_name), dir_path.join(&to_name)).unwrap();
            renamed_paths.push(format!("{dir_name}/{to_name}"));
            old_renamed_paths.push(format!("{dir_name}/{from_name}"));
        }
    }
    let mut deleted_paths = Vec::with_capacity(storm_dirs * FILES_PER_DIR);
    for dir_idx in storm_dirs..(2 * storm_dirs) {
        let dir_name = format!("dir-{dir_idx:05}");
        let dir_path = a.root.path().join(&dir_name);
        for i in 0..FILES_PER_DIR {
            let global_index = dir_idx * FILES_PER_DIR + i;
            let name = format!("f-{global_index:07}.txt");
            std::fs::remove_file(dir_path.join(&name)).unwrap();
            deleted_paths.push(format!("{dir_name}/{name}"));
        }
    }
    tracing::info!(
        target: "c4_scale",
        renamed = renamed_paths.len(),
        deleted = deleted_paths.len(),
        "rename/delete storm issued on device A"
    );

    // C4_DIAG (temporary, calibration-only instrumentation, not a
    // production concern): periodic progress snapshot during the storm
    // wait, added after several re-measurements showed writer_gate slow-
    // acquisition COUNT climbing across successive fixes (234 -> 564 ->
    // 693) with no way to tell "more throughput fit into the same 900s
    // window" apart from "actually got worse" -- the plain `wait_until_
    // with_context` this replaces polls silently and only logs
    // `c4_diag::stats()` on SUCCESS, which never fired in any storm run so
    // far since every one has timed out. This logs the same total
    // (gate_acquisitions, gate_wait) -- not just the >500ms-warn subset
    // grepped from logs before -- plus how many of the storm's own
    // correctness checks already hold, every ~30s, and includes it in the
    // timeout panic message too.
    {
        let total_checks = renamed_paths.len() + old_renamed_paths.len() + deleted_paths.len();
        let deadline = tokio::time::Instant::now() + STORM_RECOVERY_TIMEOUT;
        let mut last_progress_log = tokio::time::Instant::now();
        loop {
            let correct_on_b =
                renamed_paths.iter().filter(|p| b.root.path().join(p).exists()).count()
                    + old_renamed_paths.iter().filter(|p| !b.root.path().join(p).exists()).count()
                    + deleted_paths.iter().filter(|p| !b.root.path().join(p).exists()).count();
            if correct_on_b == total_checks {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
                let call_sites = yadorilink_sqlite_runtime::c4_diag::call_site_stats();
                let top_call_sites: String = call_sites
                    .iter()
                    .take(15)
                    .map(|(loc, n)| format!("{n}x {loc}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                panic!(
                    "condition never became true within {STORM_RECOVERY_TIMEOUT:?}:\n\
                     rename/delete storm never converged on device B; correct_on_b={correct_on_b}/\
                     {total_checks} writer_gate_acquisitions={gate_acquisitions} \
                     writer_gate_wait_ms={} storm_elapsed_ms={}; device A: {}; device B: {}\n\
                     top write() call sites: {top_call_sites}",
                    gate_wait.as_millis(),
                    c4_diag_storm_started.elapsed().as_millis(),
                    daemon_status_summary(&a.state),
                    daemon_status_summary(&b.state),
                );
            }
            if last_progress_log.elapsed() >= Duration::from_secs(30) {
                let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
                tracing::info!(
                    target: "c4_scale",
                    correct_on_b,
                    total_checks,
                    writer_gate_acquisitions = gate_acquisitions,
                    writer_gate_wait_ms = gate_wait.as_millis() as u64,
                    storm_elapsed_ms = c4_diag_storm_started.elapsed().as_millis() as u64,
                    "C4_STORM_PROGRESS"
                );
                let call_sites = yadorilink_sqlite_runtime::c4_diag::call_site_stats();
                let top_call_sites: String = call_sites
                    .iter()
                    .take(10)
                    .map(|(loc, n)| format!("{n}x {loc}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                tracing::info!(target: "c4_scale", top_call_sites, "C4_STORM_CALL_SITES");
                last_progress_log = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    tracing::info!(target: "c4_scale", "rename/delete storm converged on device B");
    // C4_DIAG (temporary, remove after investigation): the top-line figures
    // the third-bottleneck investigation is comparing before/after Stage-1
    // dirty-journal batching -- total DB write-transaction (fsync) count,
    // cumulative time every writer spent waiting to acquire `writer_gate`,
    // and this storm's own wall-clock convergence time.
    {
        let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
        tracing::warn!(
            target: "c4_scale",
            gate_acquisitions,
            gate_wait_ms = gate_wait.as_millis() as u64,
            storm_elapsed_ms = c4_diag_storm_started.elapsed().as_millis() as u64,
            "C4_DIAG: storm summary"
        );
    }
}
