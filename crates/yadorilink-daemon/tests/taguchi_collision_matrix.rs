//! A Taguchi-method (orthogonal-array) designed matrix of N-device (3-6)
//! concurrent-operation collision scenarios, run through the real daemon
//! stack, complementing `collision_matrix.rs` (fixed 2-device, hand-picked
//! scenarios) and `monkey_chaos.rs` (unbounded random exploration).
//!
//! Five factors, four levels each, covered pairwise-exhaustively by a
//! single L16(4^5) orthogonal array (16 runs instead of 4^5 = 1024 for a
//! full factorial) -- see each `FACTOR_*` table below for the level
//! definitions, and `L16` for the array itself. Each of the 16 rows is
//! its own `#[tokio::test]` so `cargo test`'s own reporting shows exactly
//! which factor combination(s), if any, fail.
//!
//! `TestDevice`/`setup_device`/`start_watching` are intentionally
//! duplicated from `three_way_concurrent_edit_conflict.rs`/`monkey_chaos.rs`/
//! `collision_matrix.rs` rather than shared -- matches this codebase's
//! existing convention of self-contained daemon integration test binaries.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_sync_state, real_entry_names, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // Uses file-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see
    // open_file_backed_sync_state's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let keypair = Arc::new(DeviceKeyPair::generate());
    let device_id = support::register_device(account, name, keypair.public_bytes()).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_sync_state();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate. Without
    // this, nothing this device writes is ever emitted to its peers.
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
    device.state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(device.state.clone(), local_path, group_id.to_string()).unwrap();
}

/// Pairs every device directly with every other device over loopback,
/// standing in for the coordination-driven mesh a live netmap would
/// establish among all N devices sharing this group -- since
/// `connect_two_daemons` only wires one pair per call, an N-device row
/// needs one call per unique pair (a full mesh), not a chain.
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

// --- Factor B: per-device operation, one enum value per device role -----

#[derive(Clone, Copy, Debug)]
enum Op {
    Create,
    Edit,
    Delete,
    Rename,
}

/// FACTOR B (operation pattern) -- the sequence of `Op`s assigned to
/// devices 0, 1, 2,... (cycled if there are more devices than pattern
/// entries).
fn op_pattern(level: u8) -> &'static [Op] {
    match level {
        1 => &[Op::Edit],
        2 => &[Op::Edit, Op::Delete, Op::Rename],
        3 => &[Op::Delete],
        4 => &[Op::Create, Op::Edit, Op::Delete, Op::Rename],
        _ => unreachable!(),
    }
}

/// FACTOR C (timing stagger, in milliseconds between each device's own
/// operation being issued) -- 0 means "as close to simultaneous as this
/// harness can arrange" (issued back-to-back with no sleep in between).
fn stagger_ms(level: u8) -> u64 {
    match level {
        1 => 0,
        2 => 10,
        3 => 100,
        4 => 500,
        _ => unreachable!(),
    }
}

/// FACTOR E (round repetition) -- how many times the whole per-device
/// operation pattern is repeated (each repetition targeting the same
/// path assignment, so later rounds' operations race whatever the
/// previous round converged to, or is still converging toward) before
/// the final convergence check.
fn rounds(level: u8) -> u32 {
    match level {
        1 => 1,
        2 => 3,
        3 => 5,
        4 => 10,
        _ => unreachable!(),
    }
}

/// FACTOR D (target path relationship) -- computes the path each device
/// index operates on for a given repetition round.
fn target_path(level: u8, device_idx: usize, device_count: usize, round: u32) -> String {
    match level {
        1 => "shared.bin".to_string(),
        2 => {
            if device_idx < device_count / 2 { "shared-a.bin" } else { "shared-b.bin" }.to_string()
        }
        // device 0 always renames shared.bin -> shared-renamed.bin (this
        // overrides device 0's Factor-B-assigned Op for the Rename step
        // itself, applied in `apply_op`); every other device's
        // Factor-B-assigned op still targets the original name,
        // deliberately racing the disappearance of that name.
        3 => "shared.bin".to_string(),
        4 => format!("solo-{device_idx}-r{round}.bin"),
        _ => unreachable!(),
    }
}

fn apply_op(
    root: &std::path::Path,
    path_level: u8,
    device_idx: usize,
    op: Op,
    round: u32,
    device_count: usize,
) {
    let target = target_path(path_level, device_idx, device_count, round);
    let path = root.join(&target);
    let content = format!("round {round} device {device_idx} target {target}");

    // FACTOR D level 3 (RenameRace): device 0 is always the one racing
    // the target's disappearance via rename, regardless of its assigned
    // Factor-B op, so every row actually exercises "one device renames
    // the shared target while others concurrently touch the old name".
    if path_level == 3 && device_idx == 0 {
        if path.exists() {
            let renamed = root.join(format!("shared-renamed-r{round}.bin"));
            std::fs::rename(&path, &renamed).unwrap();
        } else {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        return;
    }

    match op {
        Op::Create | Op::Edit => {
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

/// A device's real (non-artifact) entries keyed by name, valued by a content
/// hash -- the content-aware snapshot both the convergence wait and the final
/// strict assertion compare on. A name-only comparison is satisfied trivially
/// before any content propagates (every device holding its own local write
/// under the same name), so convergence must be judged on content too.
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

/// Runs one Taguchi-array row: sets up `device_count` real devices,
/// applies each device's Factor-B/D-driven operation (staggered per
/// Factor C) for `rounds` repetitions, then asserts every device
/// eventually converges on an identical final file set (name -> content
/// hash) -- the only correctness property this harness checks; it does
/// not assert a *specific* winner (that's `collision_matrix.rs`'s job
/// for hand-picked, deterministic scenarios). Divergence here means one
/// of the fixed bugs (or a new one) resurfaced under this specific
/// factor combination.
async fn run_taguchi_row(
    row_name: &str,
    device_count_level: u8,
    op_pattern_level: u8,
    stagger_level: u8,
    path_level: u8,
    rounds_level: u8,
) {
    let device_count = match device_count_level {
        1 => 3,
        2 => 4,
        3 => 5,
        4 => 6,
        _ => unreachable!(),
    };
    let (devices, group_id) = n_synced_devices(device_count, row_name).await;
    let _ = group_id;
    let pattern = op_pattern(op_pattern_level);
    let stagger = Duration::from_millis(stagger_ms(stagger_level));
    let round_count = rounds(rounds_level);

    for round in 0..round_count {
        for (idx, device) in devices.iter().enumerate() {
            let op = pattern[idx % pattern.len()];
            apply_op(device.root.path(), path_level, idx, op, round, device_count);
            if !stagger.is_zero() {
                tokio::time::sleep(stagger).await;
            }
        }
        // Let this round's operations start propagating before the next
        // round pushes more onto the same paths -- a fixed, generous
        // pause rather than a stability wait, since intermediate rounds
        // are deliberately racy and not expected to have converged yet.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Wait for genuine convergence on the full name->content snapshot, not
    // merely equal file-NAME sets: a name-set match is reached trivially
    // before any content has propagated (each device still holding only its
    // own local write under the shared name), so a name-only wait would
    // declare convergence mid-flight and race the strict content assertion
    // below. Comparing content hashes here makes the wait actually block
    // until every device holds byte-identical files.
    let devices_ref = &devices;
    wait_until_with_context(
        || {
            let reference = snapshot(devices_ref[0].root.path());
            devices_ref[1..].iter().all(|d| snapshot(d.root.path()) == reference)
        },
        Duration::from_secs(120),
        || {
            devices_ref
                .iter()
                .enumerate()
                .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                .collect::<Vec<_>>()
                .join("; ")
        },
    )
    .await;

    // A final settle window before the strict content-hash comparison,
    // matching monkey_chaos.rs's own reasoning: even after the content-aware
    // wait above reports convergence, a brief pause guards against a change
    // that was still in-flight the instant the poll happened to observe
    // equality.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(
            snap, reference,
            "{row_name}: device-{i} diverged from device-0 (device_count={device_count}, \
             op_pattern_level={op_pattern_level}, stagger_level={stagger_level}, \
             path_level={path_level}, rounds={round_count})"
        );
    }
}

// --- L16(4^5) orthogonal array rows: (A device-count, B op-pattern, C stagger, D path, E rounds) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_01_dc3_op_all_edit_stag_sim_path_all_same_r1() {
    run_taguchi_row("taguchi-01", 1, 1, 1, 1, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_02_dc3_op_edit_del_rename_stag_micro_path_two_groups_r3() {
    run_taguchi_row("taguchi-02", 1, 2, 2, 2, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_03_dc3_op_all_delete_stag_small_path_rename_race_r5() {
    run_taguchi_row("taguchi-03", 1, 3, 3, 3, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_04_dc3_op_c_e_d_r_stag_large_path_all_different_r10() {
    run_taguchi_row("taguchi-04", 1, 4, 4, 4, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_05_dc4_op_all_edit_stag_micro_path_rename_race_r10() {
    run_taguchi_row("taguchi-05", 2, 1, 2, 3, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_06_dc4_op_edit_del_rename_stag_sim_path_all_different_r5() {
    run_taguchi_row("taguchi-06", 2, 2, 1, 4, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_07_dc4_op_all_delete_stag_large_path_all_same_r3() {
    run_taguchi_row("taguchi-07", 2, 3, 4, 1, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_08_dc4_op_c_e_d_r_stag_small_path_two_groups_r1() {
    run_taguchi_row("taguchi-08", 2, 4, 3, 2, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_09_dc5_op_all_edit_stag_small_path_all_different_r3() {
    run_taguchi_row("taguchi-09", 3, 1, 3, 4, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_10_dc5_op_edit_del_rename_stag_large_path_rename_race_r1() {
    run_taguchi_row("taguchi-10", 3, 2, 4, 3, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_11_dc5_op_all_delete_stag_sim_path_two_groups_r10() {
    run_taguchi_row("taguchi-11", 3, 3, 1, 2, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_12_dc5_op_c_e_d_r_stag_micro_path_all_same_r5() {
    run_taguchi_row("taguchi-12", 3, 4, 2, 1, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_13_dc6_op_all_edit_stag_large_path_two_groups_r5() {
    run_taguchi_row("taguchi-13", 4, 1, 4, 2, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_14_dc6_op_edit_del_rename_stag_small_path_all_same_r10() {
    run_taguchi_row("taguchi-14", 4, 2, 3, 1, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_15_dc6_op_all_delete_stag_micro_path_all_different_r1() {
    run_taguchi_row("taguchi-15", 4, 3, 2, 4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_row_16_dc6_op_c_e_d_r_stag_sim_path_rename_race_r3() {
    run_taguchi_row("taguchi-16", 4, 4, 1, 3, 2).await;
}
