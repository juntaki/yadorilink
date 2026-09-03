//! Phase-E block-not-found root-cause investigation: isolates whether
//! connecting device B to device A BEFORE A's own startup scan (importing/
//! indexing a large pre-existing tree) has finished creates a scale-
//! sensitive race between A's still-in-progress local scan and B's block-
//! serving requests against A.
//!
//! `large_folder_scale_sanity.rs`'s real 100k run connects B to A
//! immediately after starting both link runtimes, without ever waiting for
//! A's own `wait_group_ready`. At that run's true scale, essentially every
//! block B has requested came back `not_found` after exhausting retries
//! (see the investigation's own findings) -- but the existing
//! `load_many_small_files.rs`-style 200-file tests use the identical
//! immediate-connect sequencing and never show this, which is what makes a
//! scale-sensitive startup-scan/serving race plausible rather than a
//! structural bug in the connect sequencing itself.
//!
//! Two arms, same tree, same scale, run back to back:
//!   Arm A ("connect_immediately"): start A -> start B -> connect
//!     immediately -- the current production/test shape.
//!   Arm B ("wait_ready_first"): start A -> `wait_group_ready(A)` ->
//!     sample-check a few of A's own files' block provenance directly
//!     against A's local state -> only then start B and connect.
//!
//! Deliberately NOT asserting a specific outcome: this prints each arm's
//! `c4_diag` not_found-family counters (`dont_have_not_referenced`,
//! `dont_have_store_read_failed`, `rejected_no_provenance`) side by side,
//! plus whether B reached the full file count within the observation
//! window, so the first broken causal boundary can be read directly from
//! the output using the investigation's own decision matrix:
//!   - Arm A shows not_found activity, Arm B does not -> startup scan x
//!     serving/reconcile race.
//!   - Both arms show `dont_have_store_read_failed` -> source CAS/write/
//!     retention problem, unrelated to connect timing.
//!   - `store_get_ok` but `dont_have_not_referenced` -> reference/DAG/
//!     index serve-gate problem.
//!   - No not_found activity in either arm, but B still doesn't reach the
//!     target -> receiver fetch/projection/materialization problem.
//!
//! Scale is configurable via `C4_RACE_DIR_COUNT`/`C4_RACE_MEDIUM_FILE_
//! COUNT` env vars (defaulting to ~15,000 small files across 1,500
//! directories plus 50 medium files) so this can be run at whatever scale
//! actually reproduces the not_found pattern without editing this file.
//! Not run in CI -- same rationale as `large_folder_scale_sanity.rs`'s own
//! module doc.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use support::ensure_device_signing_key;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;

const FILES_PER_DIR: usize = 10;
const MEDIUM_FILE_SIZE: usize = 300 * 1024;
const DEFAULT_DIR_COUNT: usize = 1_500;
const DEFAULT_MEDIUM_FILE_COUNT: usize = 50;

/// How long each arm waits for B to reach the full file count before
/// giving up and reporting whatever `c4_diag` state it observed. Not a
/// correctness gate (this test doesn't assert convergence) -- just bounds
/// how long a non-reproducing arm spends waiting.
///
/// Overridable via `C4_RACE_OBSERVATION_WINDOW_SECS` rather than a fixed
/// constant: 15k and 100k need materially different windows at the same
/// steady-state throughput (a 15k process-isolated run needed ~21
/// minutes end to end; 100k would need proportionally longer), and this
/// scenario's own scale is already env-driven via `C4_RACE_DIR_COUNT`/
/// `C4_RACE_MEDIUM_FILE_COUNT` -- the timeout should scale the same way,
/// not be hand-edited in the source per run.
const DEFAULT_OBSERVATION_WINDOW_SECS: u64 = 15 * 60;

fn observation_window() -> Duration {
    let secs = std::env::var("C4_RACE_OBSERVATION_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OBSERVATION_WINDOW_SECS);
    Duration::from_secs(secs)
}

fn scale_from_env() -> (usize, usize) {
    let dir_count = std::env::var("C4_RACE_DIR_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_DIR_COUNT);
    let medium_file_count = std::env::var("C4_RACE_MEDIUM_FILE_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MEDIUM_FILE_COUNT);
    (dir_count, medium_file_count)
}

/// Same chained-hash content generator as `large_folder_scale_sanity.rs`'s
/// own `medium_file_content`.
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

/// Parameterized equivalent of `large_folder_scale_sanity.rs`'s own
/// `build_large_tree`. Returns a handful of sampled relative paths for the
/// wait-ready arm's own pre-connect sample check.
fn build_tree(root: &Path, dir_count: usize, medium_file_count: usize) -> Vec<String> {
    let mut sampled = Vec::new();
    let mut file_index = 0usize;
    for dir_idx in 0..dir_count {
        let dir_name = format!("dir-{dir_idx:05}");
        let dir_path = root.join(&dir_name);
        std::fs::create_dir(&dir_path).unwrap();
        for _ in 0..FILES_PER_DIR {
            let file_name = format!("f-{file_index:07}.txt");
            std::fs::write(dir_path.join(&file_name), format!("small file {file_index}")).unwrap();
            if file_index % 500 == 0 {
                sampled.push(format!("{dir_name}/{file_name}"));
            }
            file_index += 1;
        }
    }
    for i in 0..medium_file_count {
        let file_name = format!("medium-{i:04}.bin");
        std::fs::write(root.join(&file_name), medium_file_content(i as u64)).unwrap();
        if i % 25 == 0 {
            sampled.push(file_name);
        }
    }
    sampled
}

/// Same recursive real-file counter as `large_folder_scale_sanity.rs`'s
/// own `count_real_files_recursive`.
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

/// TEMPORARY (block-not-found root-cause investigation): a one-shot dump of
/// A's own source-of-truth DAG state, taken right after A reports startup
/// Ready and before B is ever started -- resolves the "39 vs 13,795
/// changes" ambiguity directly: `c4_diag::ProtocolStats::changes_new`
/// counts `Change` objects received over the wire, not ops or unique paths,
/// so it cannot by itself say how many individual file puts a small number
/// of changes actually carries (`IMPORT_BATCH_OP_LIMIT`-bounded multi-op
/// changes can easily cover all of a large import in very few `Change`s).
fn log_source_dag_snapshot(arm_name: &'static str, state: &Arc<DaemonState>, group_id: &str) {
    use std::collections::HashSet;
    use yadorilink_replica_domain::change::Op;

    let changes = state
        .replica_coordinator
        .change_history_repository()
        .dag_list_group_changes(group_id)
        .unwrap_or_default();
    let heads = state.replica_coordinator.sqlite().dag_group_heads(group_id).unwrap_or_default();

    let mut op_counts: Vec<usize> = changes.iter().map(|c| c.ops.len()).collect();
    let total_ops: usize = op_counts.iter().sum();
    let mut touched_paths: HashSet<&str> = HashSet::new();
    for change in &changes {
        for op in &change.ops {
            match op {
                Op::Put { path, .. } | Op::Delete { path } => {
                    touched_paths.insert(path.as_str());
                }
                Op::Move { from, to, .. } => {
                    touched_paths.insert(from.as_str());
                    touched_paths.insert(to.as_str());
                }
            }
        }
    }
    op_counts.sort_unstable();
    let percentile = |p: f64| -> usize {
        if op_counts.is_empty() {
            0
        } else {
            op_counts[(((op_counts.len() - 1) as f64) * p).round() as usize]
        }
    };
    tracing::warn!(
        arm_name,
        change_count = changes.len(),
        total_ops,
        unique_touched_paths = touched_paths.len(),
        op_count_min = op_counts.first().copied().unwrap_or(0),
        op_count_p50 = percentile(0.50),
        op_count_p95 = percentile(0.95),
        op_count_max = op_counts.last().copied().unwrap_or(0),
        group_head_count = heads.len(),
        "C4_DIAG: source-DAG snapshot after A reported Ready"
    );
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
}

struct Device {
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _db_dir: tempfile::TempDir,
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
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _db_dir: db_dir,
    }
}

#[derive(Debug)]
struct ArmResult {
    arm_name: &'static str,
    on_b: usize,
    target: usize,
    reached_target: bool,
    elapsed_since_b_connected: Duration,
    protocol: yadorilink_peer_session::c4_diag::ProtocolStats,
    /// TEMPORARY: `process_group_via_obligations`'s own group-wide
    /// heads-stability fence counters, sampled on device B -- see
    /// `yadorilink_daemon::c4_diag`'s own module doc for what each field
    /// isolates.
    obligation_engine: yadorilink_daemon::c4_diag::ObligationEngineStats,
}

/// Runs one arm: builds a fresh tree on a fresh A, optionally waits for
/// A's own startup Ready (plus a sample provenance check) before starting
/// B, connects both, then observes for up to `observation_window()`.
async fn run_arm(
    arm_name: &'static str,
    dir_count: usize,
    medium_file_count: usize,
    wait_for_a_ready_first: bool,
) -> ArmResult {
    let group_id = "c4-race-group";
    let target = dir_count * FILES_PER_DIR + medium_file_count;

    // C4_ATTR (temporary, remove after investigation): Pass 4's runtime
    // wake-up-lag probe -- see `yadorilink_peer_session::c4_attr`'s own
    // "Pass 4" module doc. Spawned once per simulated device before either
    // does any real work, so it is running for the whole observation
    // window below.
    yadorilink_peer_session::c4_attr::spawn_runtime_lag_probe("A");
    let a = new_device("race-a");
    let sampled_paths = build_tree(a.root.path(), dir_count, medium_file_count);
    assert_eq!(
        count_real_files_recursive(a.root.path()),
        target,
        "sanity: the generator itself produced the expected file count before any sync began"
    );

    let local_path_a = a.root.path().to_string_lossy().to_string();
    a.state.replica_coordinator.link_repository().add_link(&local_path_a, group_id).unwrap();
    LinkRuntimeController::new(a.state.clone()).start(local_path_a, group_id.to_string()).unwrap();

    if wait_for_a_ready_first {
        let window = observation_window();
        let ready_wait_started = std::time::Instant::now();
        match tokio::time::timeout(
            window,
            a.state.replica_coordinator.wait_group_ready(group_id),
        )
        .await
        {
            Ok(Ok(())) => {
                tracing::warn!(
                    arm_name,
                    elapsed = ?ready_wait_started.elapsed(),
                    "C4_DIAG: source device A reported startup Ready before B was ever started"
                );
                log_source_dag_snapshot(arm_name, &a.state, group_id);
            }
            Ok(Err(failed)) => {
                panic!("arm {arm_name}: source device A's own startup failed: {failed:?}");
            }
            Err(_) => {
                panic!(
                    "arm {arm_name}: source device A never reached startup Ready within {:?}",
                    window
                );
            }
        }

        // Sample-check A's own view of a few files it just scanned:
        // does its live record reference real blocks, and does its own
        // local block store actually have them? This is exactly what
        // `dump_source_side_block_diagnostic` checks reactively on the
        // first `not_found` -- checking it proactively here, on a source
        // that just reported Ready, is the control case.
        for rel_path in sampled_paths.iter().take(5) {
            let record =
                a.state.replica_coordinator.file_index_repository().get_file(group_id, rel_path);
            match record {
                Ok(Some(r)) if !r.deleted && !r.blocks.is_empty() => {
                    for block in &r.blocks {
                        let hash_hex = hex::encode(&block.hash);
                        let store_result = a.state.block_store.get(&hash_hex);
                        tracing::warn!(
                            arm_name,
                            rel_path,
                            hash = %hash_hex,
                            store_get_ok = store_result.is_ok(),
                            store_get_len = ?store_result.as_ref().ok().map(|d| d.len()),
                            store_get_error = ?store_result.as_ref().err().map(|e| e.to_string()),
                            "C4_DIAG: pre-connect sample check of A's own block provenance"
                        );
                    }
                }
                other => {
                    tracing::warn!(
                        arm_name,
                        rel_path,
                        record = ?other,
                        "C4_DIAG: pre-connect sample check found no usable live record on A"
                    );
                }
            }
        }
    }

    // C4_ATTR (temporary, remove after investigation): see the identical
    // probe spawned for device A above.
    yadorilink_peer_session::c4_attr::spawn_runtime_lag_probe("B");
    let b = new_device("race-b");
    let local_path_b = b.root.path().to_string_lossy().to_string();
    b.state.replica_coordinator.link_repository().add_link(&local_path_b, group_id).unwrap();
    LinkRuntimeController::new(b.state.clone())
        .start(local_path_b.clone(), group_id.to_string())
        .unwrap();

    yadorilink_peer_session::c4_diag::reset();
    yadorilink_daemon::c4_diag::reset();
    yadorilink_peer_session::c4_reconcile_timing::reset();
    let b_connected_at = std::time::Instant::now();
    let (_session_handles, _session_channels) = support::connect_two_daemons_with_channels(
        &a.state,
        "race-a",
        &b.state,
        "race-b",
        std::slice::from_ref(&group_id.to_string()),
    )
    .await;

    let deadline = tokio::time::Instant::now() + observation_window();
    let mut on_b = count_real_files_recursive(b.root.path());
    let mut last_progress_log = tokio::time::Instant::now();
    while on_b < target && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        on_b = count_real_files_recursive(b.root.path());
        if last_progress_log.elapsed() >= Duration::from_secs(15) {
            let protocol = yadorilink_peer_session::c4_diag::stats();
            let obligation_engine = yadorilink_daemon::c4_diag::stats();
            tracing::warn!(
                arm_name,
                on_b,
                target,
                elapsed = ?b_connected_at.elapsed(),
                dont_have_not_referenced = protocol.dont_have_not_referenced,
                dont_have_store_read_failed = protocol.dont_have_store_read_failed,
                rejected_no_provenance = protocol.rejected_no_provenance,
                "C4_DIAG: race arm progress"
            );
            tracing::warn!(
                arm_name,
                ?obligation_engine,
                "C4_DIAG: obligation-engine heads-stability-fence progress"
            );
            // C4_ATTR (temporary, remove after investigation): aggregate
            // count/avg/max for every "normal" (not individually logged)
            // BlockRequest, satisfying the attribution run's own "keep
            // aggregate count/total/max for normal requests" requirement
            // without a per-request line for the common, fast case -- see
            // `c4_attr`'s own module doc.
            tracing::warn!(
                arm_name,
                slow_reconcile_count = yadorilink_peer_session::c4_attr::slow_reconcile_count(),
                summary = %yadorilink_peer_session::c4_attr::responder_and_requester_summary(),
                "C4_ATTR: block-request responder/requester aggregate summary"
            );
            last_progress_log = tokio::time::Instant::now();
        }
    }

    let _ = b; // keep B (and its channels/handles) alive through the observation window above

    ArmResult {
        arm_name,
        on_b,
        target,
        reached_target: on_b >= target,
        elapsed_since_b_connected: b_connected_at.elapsed(),
        protocol: yadorilink_peer_session::c4_diag::stats(),
        obligation_engine: yadorilink_daemon::c4_diag::stats(),
    }
}

#[ignore = "large-scale investigation case -- run explicitly, not in CI (see module doc)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn startup_scan_serving_race_two_arm_comparison() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let (dir_count, medium_file_count) = scale_from_env();
    let total = dir_count * FILES_PER_DIR + medium_file_count;
    tracing::warn!(
        dir_count,
        medium_file_count,
        total,
        "C4_DIAG: starting two-arm startup-scan/serving-race comparison"
    );

    let arm_connect_immediately =
        run_arm("connect_immediately", dir_count, medium_file_count, false).await;
    let arm_wait_ready_first =
        run_arm("wait_ready_first", dir_count, medium_file_count, true).await;

    tracing::warn!(
        ?arm_connect_immediately,
        "C4_DIAG: two-arm comparison result -- connect_immediately"
    );
    tracing::warn!(
        ?arm_wait_ready_first,
        "C4_DIAG: two-arm comparison result -- wait_ready_first"
    );
}

/// Just the `wait_ready_first` arm -- the one that stalled catastrophically
/// (339/15,050, 2.25%, never reaching the target within the observation
/// window) before the group-wide heads-stability fence in
/// `convergence::engine::process_group_via_obligations` was removed (see
/// `unrelated_path_head_movement_must_not_discard_an_already_settled_
/// attempt` in that module). `connect_immediately` already fully converged
/// before the fix and needs no re-confirmation here.
#[ignore = "large-scale investigation case -- run explicitly, not in CI (see module doc)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn startup_scan_serving_race_wait_ready_first_only() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let (dir_count, medium_file_count) = scale_from_env();
    let total = dir_count * FILES_PER_DIR + medium_file_count;
    tracing::warn!(
        dir_count,
        medium_file_count,
        total,
        "C4_DIAG: starting wait_ready_first-only re-run after the heads-stability-fence fix"
    );

    let arm_wait_ready_first =
        run_arm("wait_ready_first", dir_count, medium_file_count, true).await;

    tracing::warn!(
        ?arm_wait_ready_first,
        "C4_DIAG: wait_ready_first-only result (post-fix)"
    );
}

/// A deterministic per-role Ed25519 identity for [`startup_scan_serving_
/// race_process_isolated`] -- fixed, not random, specifically so the two
/// independently-launched OS processes can pair with each other knowing
/// only this test's own hardcoded constants, no rendezvous/IPC needed.
/// Acceptable for a one-off diagnostic experiment; never for anything
/// long-lived (see that fn's own doc for the full context).
fn fixed_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// C4_ATTR (temporary, remove after investigation): process-isolation
/// experiment. `startup_scan_serving_race_wait_ready_first_only` (above)
/// runs A and B in the SAME process/tokio runtime, so Pass 4's finding
/// (multi-second wake-up lag on both sides, coinciding with slow
/// `BlockRequest`s) could be a real per-device bottleneck OR an artifact
/// of sharing one runtime between two simulated devices. This variant
/// answers that by running the IDENTICAL small-file scenario with A and B
/// as two SEPARATE OS processes, each with its own tokio runtime, talking
/// real QUIC over two fixed loopback ports (this crate's other daemon
/// integration tests already pair over real QUIC via `support::connect_
/// two_daemons_with_channels` -- this fn's only structural difference is
/// running the two sides' setup in two independent processes instead of
/// one shared `tokio::test`).
///
/// Launch it twice, once per role, within a few seconds of each other (A
/// retries its dial if B is not listening yet; B simply waits to accept):
///
/// ```sh
/// C4_ISOLATED_ROLE=A C4_RACE_DIR_COUNT=200 C4_RACE_MEDIUM_FILE_COUNT=0 RUST_LOG=info \
///   cargo test -p yadorilink-daemon --test startup_scan_block_serving_race \
///   startup_scan_serving_race_process_isolated -- --ignored --nocapture --test-threads=1
///
/// C4_ISOLATED_ROLE=B C4_RACE_DIR_COUNT=200 C4_RACE_MEDIUM_FILE_COUNT=0 RUST_LOG=info \
///   cargo test -p yadorilink-daemon --test startup_scan_block_serving_race \
///   startup_scan_serving_race_process_isolated -- --ignored --nocapture --test-threads=1
/// ```
///
/// A never returns on its own (it has no target of its own to reach --
/// just keeps serving B's requests) -- kill it externally once B's own
/// run has answered the experiment's stop condition.
#[ignore = "large-scale investigation case -- run explicitly as two separate OS processes, one per C4_ISOLATED_ROLE (see this fn's own doc)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn startup_scan_serving_race_process_isolated() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let role = std::env::var("C4_ISOLATED_ROLE")
        .expect("set C4_ISOLATED_ROLE=A or C4_ISOLATED_ROLE=B (see this fn's own doc)");
    let (dir_count, medium_file_count) = scale_from_env();
    let group_id = "c4-race-group";
    let target = dir_count * FILES_PER_DIR + medium_file_count;

    const ADDR_A: &str = "127.0.0.1:47101";
    const ADDR_B: &str = "127.0.0.1:47102";
    const SEED_A: u8 = 0xAA;
    const SEED_B: u8 = 0xBB;

    match role.as_str() {
        "A" => {
            yadorilink_peer_session::c4_attr::spawn_runtime_lag_probe("A");
            let a = new_device("race-a");
            build_tree(a.root.path(), dir_count, medium_file_count);
            // Overrides `new_device`'s own random key -- must happen before
            // `LinkRuntimeController::start` below, per `ensure_device_
            // signing_key`'s own doc comment.
            a.state.set_device_signing_key(fixed_signing_key(SEED_A));
            // Must happen BEFORE `LinkRuntimeController::start` below: a
            // linked group is fail-closed on local DAG emission until a
            // verified policy snapshot exists (see `install_bootstrap_
            // policy`'s own doc comment). A's initial scan runs a one-shot
            // change-history bootstrap import as part of `start` --
            // confirmed by a smoke run of this exact fn that installing
            // the policy only after `wait_group_ready` returned still let
            // that one-shot import fail with "emission disabled for this
            // folder" and `wait_group_ready` returned `Ok(())` anyway (it
            // gates the filesystem scan, not DAG emission), leaving A with
            // literally nothing to sync for the rest of the run.
            support::install_bootstrap_policy(&a.state, &[group_id.to_string()]);
            let local_path_a = a.root.path().to_string_lossy().to_string();
            a.state
                .replica_coordinator
                .link_repository()
                .add_link(&local_path_a, group_id)
                .unwrap();
            LinkRuntimeController::new(a.state.clone())
                .start(local_path_a, group_id.to_string())
                .unwrap();
            let window = observation_window();
            match tokio::time::timeout(
                window,
                a.state.replica_coordinator.wait_group_ready(group_id),
            )
            .await
            {
                Ok(Ok(())) => tracing::warn!("C4_ATTR: isolated-A reported startup Ready"),
                Ok(Err(failed)) => panic!("isolated-A's own startup failed: {failed:?}"),
                Err(_) => panic!("isolated-A never reached Ready within {window:?}"),
            }

            let udp =
                tokio::net::UdpSocket::bind(ADDR_A).await.expect("bind A's fixed loopback port");
            let hub = yadorilink_transport::TransportHub::from_socket(udp);
            a.state.set_shared_socket(hub.clone());
            let endpoint_a = yadorilink_transport::QuicPeerEndpoint::new(
                hub,
                yadorilink_transport::DeviceSigningKeyPair {
                    signing: fixed_signing_key(SEED_A),
                    verifying: fixed_signing_key(SEED_A).verifying_key(),
                },
            )
            .expect("build A's QUIC endpoint");
            let key_b_bytes = fixed_signing_key(SEED_B).verifying_key().to_bytes();
            endpoint_a.authorize(key_b_bytes);

            // Harness invariant fix: A used to dial exactly once and then
            // sit in `std::future::pending()` forever, which meant
            // restarting ONLY B (its process, and therefore its QUIC
            // connection to A) left A waiting on a stream nobody would
            // ever open again -- the operator had to know to restart BOTH
            // sides together, discovered the hard way during the 15k run.
            // This loop makes A re-dial on its own whenever its session
            // with B exits (peer gone, e.g. B's process restarted for a
            // fresh run), so a solo B restart reconnects without any
            // operator-side invariant to remember.
            loop {
                // Retries because B may not have bound its own fixed port
                // yet -- the two processes are launched independently,
                // with no ordering guarantee.
                let connection = loop {
                    match endpoint_a.connect(ADDR_B.parse().unwrap(), key_b_bytes).await {
                        Ok(conn) => break conn,
                        Err(error) => {
                            tracing::debug!(%error, "isolated-A: dial to B not ready yet, retrying");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                };
                let channel_a = yadorilink_transport::QuicPeerChannel::new(
                    connection,
                    yadorilink_transport::ConnectRole::Dial,
                );
                let (session_a, handle_a) = support::spawn_paired_session(
                    &a.state,
                    "race-a",
                    "race-b",
                    channel_a,
                    &[group_id.to_string()],
                    key_b_bytes,
                );
                support::wait_until(
                    || session_a.peer_handshake_received(),
                    std::time::Duration::from_secs(30),
                )
                .await;
                tracing::warn!("C4_ATTR: isolated-A paired with B");

                // Blocks until THIS session's own task exits -- the same
                // signal `spawn_paired_session`'s own exit handler uses to
                // clean up `state.peers`. Re-dials afterward instead of
                // returning, so this fn only ever exits when the process
                // itself is killed externally.
                let _ = handle_a.await;
                tracing::warn!("C4_ATTR: isolated-A's session with B exited; re-dialing");
            }
        }
        "B" => {
            yadorilink_peer_session::c4_attr::spawn_runtime_lag_probe("B");
            let b = new_device("race-b");
            b.state.set_device_signing_key(fixed_signing_key(SEED_B));
            // Same ordering fix as A's own -- see that branch's comment.
            support::install_bootstrap_policy(&b.state, &[group_id.to_string()]);
            let local_path_b = b.root.path().to_string_lossy().to_string();
            b.state
                .replica_coordinator
                .link_repository()
                .add_link(&local_path_b, group_id)
                .unwrap();
            LinkRuntimeController::new(b.state.clone())
                .start(local_path_b, group_id.to_string())
                .unwrap();

            let udp =
                tokio::net::UdpSocket::bind(ADDR_B).await.expect("bind B's fixed loopback port");
            let hub = yadorilink_transport::TransportHub::from_socket(udp);
            b.state.set_shared_socket(hub.clone());
            let endpoint_b = yadorilink_transport::QuicPeerEndpoint::new(
                hub,
                yadorilink_transport::DeviceSigningKeyPair {
                    signing: fixed_signing_key(SEED_B),
                    verifying: fixed_signing_key(SEED_B).verifying_key(),
                },
            )
            .expect("build B's QUIC endpoint");
            let key_a_bytes = fixed_signing_key(SEED_A).verifying_key().to_bytes();
            endpoint_b.authorize(key_a_bytes);

            let connection = endpoint_b
                .accept(key_a_bytes)
                .await
                .expect("A must dial within this test's own connection lifetime");
            let channel_b = yadorilink_transport::QuicPeerChannel::new(
                connection,
                yadorilink_transport::ConnectRole::Accept,
            );
            let (session_b, _handle_b) = support::spawn_paired_session(
                &b.state,
                "race-b",
                "race-a",
                channel_b,
                &[group_id.to_string()],
                key_a_bytes,
            );
            support::wait_until(
                || session_b.peer_handshake_received(),
                std::time::Duration::from_secs(30),
            )
            .await;
            let b_connected_at = std::time::Instant::now();
            tracing::warn!("C4_ATTR: isolated-B paired with A; observing convergence");

            let deadline = tokio::time::Instant::now() + observation_window();
            let mut on_b = count_real_files_recursive(b.root.path());
            let mut last_progress_log = tokio::time::Instant::now();
            while on_b < target && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(500)).await;
                on_b = count_real_files_recursive(b.root.path());
                if last_progress_log.elapsed() >= Duration::from_secs(10) {
                    // C4_ATTR (temporary, remove after investigation): the
                    // 15k isolated run's own minimal metric set (per the
                    // process-isolation experiment's own follow-up
                    // instructions) -- progress, elapsed, and the
                    // obligation engine's completion accounting
                    // (`completion_attempted`/`completion_closed`/
                    // `completion_cas_lost`, an EXISTING accessor, not new
                    // instrumentation). Tokio lag >100ms and Block RTT
                    // >500ms are already covered by this fn's own runtime-
                    // lag probe and `c4_attr::report_requester_rtt`
                    // (Passes 3/4), which log independently of this tick.
                    let obligation_engine = yadorilink_daemon::c4_diag::stats();
                    tracing::warn!(
                        on_b,
                        target,
                        elapsed = ?b_connected_at.elapsed(),
                        completion_attempted = obligation_engine.completion_attempted,
                        completion_closed = obligation_engine.completion_closed,
                        completion_cas_lost = obligation_engine.completion_cas_lost,
                        "C4_ATTR: isolated-B progress"
                    );
                    last_progress_log = tokio::time::Instant::now();
                }
            }
            let obligation_engine = yadorilink_daemon::c4_diag::stats();
            tracing::warn!(
                on_b,
                target,
                reached_target = on_b >= target,
                elapsed = ?b_connected_at.elapsed(),
                completion_attempted = obligation_engine.completion_attempted,
                completion_closed = obligation_engine.completion_closed,
                completion_cas_lost = obligation_engine.completion_cas_lost,
                "C4_ATTR: isolated-B final result"
            );
        }
        other => panic!("C4_ISOLATED_ROLE must be \"A\" or \"B\", got {other:?}"),
    }
}
