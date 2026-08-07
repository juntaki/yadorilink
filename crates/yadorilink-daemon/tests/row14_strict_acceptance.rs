//! Strict release-candidate acceptance harness for the `taguchi_row_14`
//! permanent-stall fix (`fix/conflict-copy-convergence-obligation-20260723`).
//! `TestDevice`/`setup_device`/etc. are intentionally duplicated from
//! `taguchi_collision_matrix.rs` rather than shared -- matches this
//! codebase's existing convention of self-contained daemon integration test
//! binaries (see that file's own doc comment for the same reasoning).
//!
//! This is deliberately a *stricter* bar than "the row-14 test passed":
//!
//! 1. The periodic 90s materialization-repair sweep is disabled for the
//!    whole run (`set_default_materialization_repair_sweep_interval_for_
//!    tests`), so a pass can only be attributed to the Convergence
//!    Engine's own per-tick reconciliation -- never the old sweep quietly
//!    rescuing it, which would make it impossible to tell which mechanism
//!    actually converged the run.
//! 2. The longest no-progress gap seen during the run is tracked directly
//!    (not merely whether it crossed the stall-panic threshold) and must
//!    stay comfortably under it -- "never actually stalled" is a stronger
//!    claim than "recovered before the watchdog fired."
//! 3. After convergence, every device's `materialization_jobs` table must
//!    have zero non-terminal rows left -- nothing stuck in `Planning`/
//!    `Backoff`/`Pending` forever, invisible only because the strict
//!    content-hash comparison happened to pass anyway.
//! 4. The strict content-hash comparison itself (inherited from the
//!    ordinary row-14 test) already covers "a path that went through a
//!    retriable placeholder ends up with disk content matching the
//!    winner" -- every device's bytes must match, not just their file-name
//!    sets.
//!
//! Panics, background-task restarts, and SQLite lock errors during a run
//! are deliberately NOT asserted against from *inside* this test -- they're
//! checked by the acceptance script that repeatedly invokes this binary,
//! grepping each iteration's full captured stdout/stderr, since a
//! backgrounded `supervise::spawn_restarting` task's own panic does not
//! automatically fail the top-level `#[tokio::test]`.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{open_file_backed_replica_coordinator, real_entry_names, TestAccount};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::{
    set_default_materialization_repair_sweep_interval_for_tests, DaemonState,
};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};
use yadorilink_transport::DeviceKeyPair;

const ABSOLUTE_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(900);
const STALL_TIMEOUT: Duration = Duration::from_secs(90);
/// Any no-progress gap beyond this is loud evidence the run came
/// uncomfortably close to a real stall, even if it never actually crossed
/// `STALL_TIMEOUT` -- see this file's own acceptance-criteria doc comment.
const MAX_ACCEPTABLE_PROGRESS_GAP: Duration = Duration::from_secs(60);

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let keypair = Arc::new(DeviceKeyPair::generate());
    let device_id = support::register_device(account, name, keypair.public_bytes()).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

async fn connect_all_pairs(devices: &[TestDevice], group_ids: &[String]) {
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            support::connect_two_daemons(
                &devices[i].state,
                &devices[i].device_id,
                &devices[j].state,
                &devices[j].device_id,
                group_ids,
            )
            .await;
        }
    }
}

async fn n_synced_devices(n: usize, test_name: &str) -> (Vec<TestDevice>, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "taguchi-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_watching(device, &group_id).await;
    }
    connect_all_pairs(&devices, std::slice::from_ref(&group_id)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (devices, group_id)
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Edit,
    Delete,
    Rename,
}

/// Mirrors row 14's own factor assignment exactly (op-pattern level 2:
/// edit/delete/rename cycled across devices).
const PATTERN: &[Op] = &[Op::Edit, Op::Delete, Op::Rename];

fn apply_op(root: &std::path::Path, device_idx: usize, op: Op, round: u32) {
    // path level 1 ("all same"): every device targets the identical name.
    let target = "shared.bin";
    let path = root.join(target);
    let content = format!("round {round} device {device_idx} target {target}");
    match op {
        Op::Edit => {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        Op::Delete => {
            let _ = std::fs::remove_file(&path);
        }
        Op::Rename => {
            if path.exists() {
                let renamed = root.join(format!("{target}.renamed-{device_idx}-r{round}"));
                let _ = std::fs::rename(&path, renamed);
            } else {
                std::fs::write(&path, content.as_bytes()).unwrap();
            }
        }
    }
}

fn snapshot(root: &std::path::Path) -> std::collections::HashMap<String, String> {
    use sha2::Digest;
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read(root.join(&name)).unwrap_or_default();
            (name, hex::encode(sha2::Sha256::digest(&content)))
        })
        .collect()
}

/// Diagnostic-only three-layer snapshot for the
/// `fix/conflict-copy-convergence-obligation-20260723` investigation --
/// classifies a stall on a specific conflict-copy path into one of:
///
/// A. The winner or loser Change itself is genuinely UNKNOWN to a device
///    (never received) -- a real DAG-propagation gap.
/// B. The Change is known but ORPHANED (buffered, missing ancestors) or
///    its parent closure has gaps on an otherwise-admitted change -- a
///    post-admission DAG-management gap (orphan promotion, batching).
/// C. Every device agrees on the DAG (same heads, same `resolve_path_heads`
///    outcome, this conflict-copy correctly appears in `conflict_copies`
///    everywhere) but a device's own job/audit history never re-examined
///    it -- a Convergence Engine projection-trigger gap, NOT a DAG
///    propagation gap.
/// D. Resolution and job state agree everywhere but the conflict-copy
///    still never lands on disk -- a pure projection/materialization bug.
///
/// Identifies the winner/loser `ChangeHash` values by finding a device
/// whose own `resolve_path_heads(source_path)` call already produces a
/// `ConflictCopy` matching `target_conflict_copy_path` by name -- avoids
/// having to reverse-parse the conflict-copy filename (its embedded hash8
/// is a losing FILE VERSION hash prefix, not a `ChangeHash`, so it cannot
/// be used to look up the change directly).
fn dump_conflict_diagnostic_snapshot(
    devices: &[TestDevice],
    group_id: &str,
    source_path: &str,
    target_conflict_copy_path: &str,
) -> String {
    let mut winner_hash: Option<ChangeHash> = None;
    let mut loser_hash: Option<ChangeHash> = None;
    let mut resolution_by_device: Vec<String> = Vec::new();

    for (i, device) in devices.iter().enumerate() {
        let session =
            device.state.peers.all_sessions().into_iter().next().map(|(_, session)| session);
        let Some(session) = session else {
            resolution_by_device.push(format!("device-{i}: no peer session available"));
            continue;
        };
        match session.diagnostic_path_heads(group_id, source_path) {
            Ok(heads) => match resolve_path_heads(source_path, &heads) {
                PathResolution::Present { winner, conflict_copies } => {
                    resolution_by_device.push(format!(
                        "device-{i}: Present winner_device={} winner_hash={} conflict_copies={:?}",
                        heads[winner].device_id,
                        hex::encode(heads[winner].change_hash),
                        conflict_copies.iter().map(|c| c.path.clone()).collect::<Vec<_>>()
                    ));
                    if winner_hash.is_none() {
                        winner_hash = Some(ChangeHash(heads[winner].change_hash));
                    }
                    for cc in &conflict_copies {
                        if cc.path == target_conflict_copy_path && loser_hash.is_none() {
                            loser_hash = Some(ChangeHash(heads[cc.head].change_hash));
                        }
                    }
                }
                PathResolution::Absent => {
                    resolution_by_device.push(format!("device-{i}: Absent"));
                }
            },
            Err(e) => {
                resolution_by_device.push(format!("device-{i}: error reading path heads: {e}"));
            }
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "=== conflict diagnostic snapshot: source_path={source_path:?} \
         target_conflict_copy_path={target_conflict_copy_path:?} ===\n"
    ));
    out.push_str(&format!(
        "identified winner_hash={:?} loser_hash={:?}\n",
        winner_hash.map(|h| hex::encode(h.0)),
        loser_hash.map(|h| hex::encode(h.0)),
    ));
    for line in &resolution_by_device {
        out.push_str(line);
        out.push('\n');
    }

    for (i, device) in devices.iter().enumerate() {
        let heads = device.state.replica_coordinator.sqlite().dag_group_heads(group_id).ok();
        out.push_str(&format!(
            "device-{i}: dag_group_heads={:?}\n",
            heads.map(|hs| hs.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>())
        ));
        let job = device
            .state
            .replica_coordinator
            .materialization_job_repository()
            .materialization_get_job(group_id, source_path)
            .ok()
            .flatten();
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        out.push_str(&format!(
            "device-{i}: materialization_job({source_path:?}) = {}\n",
            match job {
                Some(j) => format!(
                    "state={:?} attempt={} version_hash={} age_since_updated_at={:?} \
                     waiting_reason={:?}",
                    j.state,
                    j.attempt,
                    hex::encode(&j.version_hash),
                    Duration::from_nanos((now_nanos - j.updated_at).max(0) as u64),
                    j.waiting_reason
                ),
                None => "no job row".to_string(),
            }
        ));
        for (label, hash) in [("winner", winner_hash), ("loser", loser_hash)] {
            let Some(hash) = hash else { continue };
            let has_change = device
                .state
                .replica_coordinator
                .change_history_repository()
                .dag_has_change(&hash)
                .unwrap_or(false);
            let has_orphan_or_change = device
                .state
                .replica_coordinator
                .change_history_repository()
                .dag_has_change_or_buffered_orphan(&hash)
                .unwrap_or(false);
            let status = if has_change {
                "admitted"
            } else if has_orphan_or_change {
                "orphaned (buffered, cannot recurse into its own parents -- no public API reads \
                 orphan content)"
            } else {
                "UNKNOWN (never received at all)"
            };
            out.push_str(&format!(
                "device-{i}: {label} change {} = {status}\n",
                hex::encode(hash.0)
            ));
            if has_change {
                let mut missing = Vec::new();
                let mut visited = std::collections::HashSet::new();
                let mut stack = vec![hash];
                while let Some(h) = stack.pop() {
                    if !visited.insert(h) {
                        continue;
                    }
                    match device.state.replica_coordinator.sqlite().dag_get_change(&h) {
                        Ok(Some(change)) => {
                            for parent in &change.parents {
                                if device
                                    .state
                                    .replica_coordinator
                                    .change_history_repository()
                                    .dag_has_change(parent)
                                    .unwrap_or(false)
                                {
                                    stack.push(*parent);
                                } else {
                                    missing.push(*parent);
                                }
                            }
                        }
                        _ => missing.push(h),
                    }
                }
                if !missing.is_empty() {
                    out.push_str(&format!(
                        "device-{i}: {label} parent-closure gaps: {:?}\n",
                        missing.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>()
                    ));
                }
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn row14_strict_acceptance() {
    static TRACING_INIT: std::sync::Once = std::sync::Once::new();
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });

    // Criterion 1: the old periodic repair sweep must not be able to help
    // this run at all -- set the override BEFORE any `DaemonState::new`
    // call, closing the race `set_materialization_repair_sweep_interval`
    // alone cannot (see that function's own doc comment).
    set_default_materialization_repair_sweep_interval_for_tests(Duration::from_secs(3600));

    // Diagnostic-only: a runtime heartbeat, independent of any device's own
    // work, for the `fix/conflict-copy-convergence-obligation-20260723`
    // investigation. If this keeps ticking every ~1s throughout a run that
    // otherwise shows a long silent gap, the gap is a genuine (if slow)
    // async wait somewhere in the engine's own call chain, not worker-
    // thread starvation; if the heartbeat ALSO goes silent, something is
    // monopolizing this runtime's worker threads with blocking synchronous
    // work.
    tokio::spawn(async {
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick += 1;
            tracing::info!(tick, "runtime heartbeat");
        }
    });

    let device_count = 6;
    let (devices, group_id) = n_synced_devices(device_count, "row14-strict").await;
    let round_count = 10u32;
    let stagger = Duration::from_millis(100);

    for round in 0..round_count {
        for (idx, device) in devices.iter().enumerate() {
            let op = PATTERN[idx % PATTERN.len()];
            apply_op(device.root.path(), idx, op, round);
            tokio::time::sleep(stagger).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Criterion 2: custom wait loop tracking the longest no-progress gap
    // directly, instead of `support::wait_until_or_stalled` (which only
    // ever reports whether the panic threshold was crossed, not how close
    // a run came).
    let started = Instant::now();
    let mut last_progress_value: Vec<_> = devices.iter().map(|d| snapshot(d.root.path())).collect();
    let mut last_progress_at = started;
    let mut max_gap = Duration::ZERO;
    loop {
        let converged = {
            let reference = snapshot(devices[0].root.path());
            devices[1..].iter().all(|d| snapshot(d.root.path()) == reference)
        };
        if converged {
            break;
        }
        let now = Instant::now();
        if now.duration_since(started) > ABSOLUTE_CONVERGENCE_TIMEOUT {
            let entries = devices
                .iter()
                .enumerate()
                .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                .collect::<Vec<_>>()
                .join("; ");
            panic!(
                "row14_strict_acceptance: never converged within {ABSOLUTE_CONVERGENCE_TIMEOUT:?}: \
                 {entries}"
            );
        }
        let current: Vec<_> = devices.iter().map(|d| snapshot(d.root.path())).collect();
        if current != last_progress_value {
            last_progress_value = current;
            last_progress_at = now;
        } else {
            let gap = now.duration_since(last_progress_at);
            if gap > max_gap {
                max_gap = gap;
            }
            if gap > STALL_TIMEOUT {
                let entries = devices
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; ");
                // Diagnostic-only: find a name present on some but not all
                // devices (the asymmetric path) and dump the three-layer
                // classification snapshot for it before panicking -- see
                // `dump_conflict_diagnostic_snapshot`'s own doc comment.
                let mut name_counts: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for d in &devices {
                    for name in real_entry_names(d.root.path()) {
                        *name_counts.entry(name).or_insert(0) += 1;
                    }
                }
                let mut asymmetric: Vec<String> = name_counts
                    .into_iter()
                    .filter(|(_, count)| *count > 0 && *count < devices.len())
                    .map(|(name, _)| name)
                    .collect();
                // Prefer a conflict-copy name if one is asymmetric -- it
                // has a clear `source_path` ("shared.bin") to run
                // `resolve_path_heads`/the fixpoint against. A bare
                // asymmetric direct-path name (no conflict-copy involved)
                // is its OWN source_path instead.
                asymmetric.sort_by_key(|n| !n.contains("(conflicted copy"));
                let diagnostic = asymmetric
                    .into_iter()
                    .next()
                    .map(|name| {
                        let source_path =
                            if name.contains("(conflicted copy") { "shared.bin" } else { &name };
                        dump_conflict_diagnostic_snapshot(&devices, &group_id, source_path, &name)
                    })
                    .unwrap_or_else(|| {
                        "no asymmetric path found (all devices agree on names; divergence must \
                         be pure content-hash mismatch)"
                            .to_string()
                    });
                panic!(
                    "row14_strict_acceptance: convergence stalled: no progress for over \
                     {STALL_TIMEOUT:?} ({:?} elapsed): {entries}\n{diagnostic}",
                    started.elapsed()
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("row14_strict_acceptance: max no-progress gap observed = {max_gap:?}");
    assert!(
        max_gap <= MAX_ACCEPTABLE_PROGRESS_GAP,
        "row14_strict_acceptance: max no-progress gap {max_gap:?} exceeded the strict \
         acceptance bound {MAX_ACCEPTABLE_PROGRESS_GAP:?} (even though it stayed under the \
         {STALL_TIMEOUT:?} panic threshold) -- this run came uncomfortably close to a real stall"
    );

    // A final settle window before the strict content-hash comparison,
    // matching the ordinary row-14 test's own reasoning.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Criterion 4 (content correctness, including any path that passed
    // through a retriable placeholder along the way).
    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(snap, reference, "row14_strict_acceptance: device-{i} diverged from device-0");
    }

    // Criterion 3: nothing left non-terminal in any device's job table.
    // Bounded extra wait (distinct from the STALL_TIMEOUT machinery above,
    // which only tracks visible DISK progress) -- content can converge
    // correctly while a job row's own bookkeeping simply hasn't caught up
    // within the fixed 2s settle window yet (a job legitimately still
    // mid-cycle is not the same claim as "stuck forever"). Genuinely stuck
    // rows will still be non-empty after this bounded wait; a merely-
    // lagging bookkeeping write will not.
    const JOB_TABLE_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(30);
    let quiescence_deadline = Instant::now() + JOB_TABLE_QUIESCENCE_TIMEOUT;
    loop {
        let all_quiescent = devices.iter().all(|d| {
            d.state
                .replica_coordinator
                .materialization_job_repository()
                .materialization_list_unfinished_jobs()
                .map(|jobs| jobs.is_empty())
                .unwrap_or(false)
        });
        if all_quiescent || Instant::now() >= quiescence_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    for (i, device) in devices.iter().enumerate() {
        let unfinished = device
            .state
            .replica_coordinator
            .materialization_job_repository()
            .materialization_list_unfinished_jobs()
            .unwrap();
        assert!(
            unfinished.is_empty(),
            "row14_strict_acceptance: device-{i} has {} non-terminal materialization_jobs row(s) \
             left after convergence (group={group_id}): {:?}",
            unfinished.len(),
            unfinished
        );
    }
}
