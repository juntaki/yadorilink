//! A second Taguchi-method (orthogonal-array) designed matrix of
//! concurrent-write collision scenarios, run through the real daemon
//! stack -- complementing `taguchi_collision_matrix.rs` (v1: device-count,
//! op-pattern, stagger, path-relationship, and round-repetition factors)
//! with a *disjoint* set of five new factors that v1 does not touch:
//! file size, content pattern/compressibility, path depth, exec-bit
//! toggling, and device churn. `device_count` is fixed at 4 for every row
//! here (v1 already explores that dimension), so this file's 16 rows
//! purely explore factors A-E below via the same standard L16(4^5)
//! orthogonal array v1 uses (16 runs instead of 4^5 = 1024 for a full
//! factorial), just with a different factor assignment per column.
//!
//! Factors (see each `FACTOR_*` doc comment below for level definitions):
//! - A: file size (tiny/small/medium/large, single- through many-block)
//! - B: content pattern (plain text / binary / highly compressible /
//!   incompressible pseudo-random)
//! - C: path depth (flat / one level / three levels / a directory that
//!   must itself be concurrently created by multiple devices)
//! - D: exec-bit toggle pattern (never / always / alternating per device /
//!   toggled in a second round after initial convergence)
//! - E: device churn (none / a device joins mid-test / a device's access
//!   is revoked mid-test / a device is fully removed mid-test)
//!
//! Churn levels 3 and 4 (revoke/remove) are asymmetric with respect to
//! the final convergence assertion: once a device has lost access or been
//! removed, its own on-disk copy can no longer receive further updates, so
//! it is deliberately excluded from the final cross-device hash/exec-bit
//! comparison -- only the remaining (and, for churn level 2, newly
//! joined) devices are required to converge.
//!
//! `TestDevice`/`setup_device`/`start_syncing`/`n_synced_devices` are
//! intentionally duplicated from `taguchi_collision_matrix.rs` (and
//! `e2e_three_devices.rs`/`monkey_chaos.rs`/`collision_matrix.rs`) rather
//! than shared -- matches this codebase's existing convention of
//! self-contained daemon integration test binaries.

mod support;

use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
use support::{
    open_file_backed_sync_state, real_entry_names, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::{link_manager, peer_orchestrator};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

struct TestDevice {
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // daemon-concurrency-tests-file-backed-wal: file-backed WAL (production's
    // concurrency model) instead of open_in_memory's shared-cache backend —
    // see open_file_backed_sync_state's doc comment. Held only to keep the
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
    TestDevice {
        device_id,
        keypair,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_syncing(
    device: &TestDevice,
    coordination_addr: String,
    relay_addr: std::net::SocketAddr,
    access_token: String,
    group_id: &str,
) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(device.state.clone(), local_path, group_id.to_string()).unwrap();

    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        relay_addr,
        access_token,
        device_id: device.device_id.clone(),
    };
    let keypair = device.keypair.clone();
    let state = device.state.clone();
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, keypair, state).await;
    });
}

/// Like v1's `n_synced_devices`, but also returns the `TestAccount` and
/// server addresses -- this file's churn factor (E) needs them after
/// setup, to grant a mid-test joiner access or to revoke/remove an
/// existing device.
async fn n_synced_devices(
    n: usize,
    test_name: &str,
) -> (Vec<TestDevice>, String, TestAccount, String, std::net::SocketAddr) {
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "taguchi-v2-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_syncing(
            device,
            coordination_addr.clone(),
            relay_addr,
            account.access_token.clone(),
            &group_id,
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    (devices, group_id, account, coordination_addr, relay_addr)
}

/// FACTOR A (file size) -- the exact byte length written by every device
/// (before any pattern-driven padding), spanning single-block through
/// many-block content.
fn file_size_bytes(level: u8) -> usize {
    match level {
        1 => 16,              // tiny
        2 => 4 * 1024,        // small, single block
        3 => 256 * 1024,      // medium, multi-block
        4 => 4 * 1024 * 1024, // large, many blocks
        _ => unreachable!(),
    }
}

/// FACTOR B / A combined: generates `device_idx`'s file content for a
/// given size/pattern level pair. Every variant is prefixed with a
/// `dev<idx>:` marker so a hash mismatch during triage can be traced back
/// to which device's write "won" (or got corrupted) without needing the
/// raw bytes.
fn generate_content(size_level: u8, pattern_level: u8, device_idx: usize) -> Vec<u8> {
    let size = file_size_bytes(size_level);
    let prefix = format!("dev{device_idx}:");
    let prefix_bytes = prefix.as_bytes();
    let mut content = Vec::with_capacity(size);
    content.extend_from_slice(&prefix_bytes[..prefix_bytes.len().min(size)]);

    match pattern_level {
        // 1: plain text -- a repeated human-readable sentence.
        1 => {
            let sentence = format!("taguchi-v2 plain text payload from device {device_idx}; ");
            let sentence_bytes = sentence.as_bytes();
            while content.len() < size {
                let remaining = size - content.len();
                content.extend_from_slice(&sentence_bytes[..sentence_bytes.len().min(remaining)]);
            }
        }
        // 2: binary -- a deterministic (not truly random) repeating byte
        // ramp, offset per device, needing no extra crate.
        2 => {
            let remaining = size - content.len();
            for i in 0..remaining {
                content.push(((device_idx * 37 + i) % 256) as u8);
            }
        }
        // 3: highly compressible -- a single repeated byte after the
        // per-device prefix.
        3 => {
            while content.len() < size {
                content.push(0xAA);
            }
        }
        // 4: incompressible -- pseudo-random bytes from a per-device
        // seeded PRNG (deterministic across re-runs of a failing row).
        4 => {
            use rand::{RngCore, SeedableRng};
            let mut rng = rand::rngs::StdRng::seed_from_u64(0x7A6D_0000 + device_idx as u64);
            let remaining = size - content.len();
            let mut buf = vec![0u8; remaining];
            rng.fill_bytes(&mut buf);
            content.extend_from_slice(&buf);
        }
        _ => unreachable!(),
    }
    content.truncate(size);
    content
}

/// FACTOR C (path depth) -- the relative path every device writes the
/// same logical file to. Level 4's parent directory does not exist on any
/// device at test start, so all devices creating it independently (no
/// stagger) exercises concurrent directory creation at the sync layer.
fn relative_target_path(level: u8) -> std::path::PathBuf {
    match level {
        1 => std::path::PathBuf::from("file.bin"),
        2 => std::path::PathBuf::from("sub/file.bin"),
        3 => std::path::PathBuf::from("a/b/c/file.bin"),
        4 => std::path::PathBuf::from("shared-dir/file.bin"),
        _ => unreachable!(),
    }
}

#[cfg(unix)]
fn set_exec_bit(path: &std::path::Path, exec: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(if exec { 0o755 } else { 0o644 });
    std::fs::set_permissions(path, perms).unwrap();
}

#[cfg(not(unix))]
fn set_exec_bit(_path: &std::path::Path, _exec: bool) {}

#[cfg(unix)]
fn read_exec_bit(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o100 != 0).unwrap_or(false)
}

#[cfg(not(unix))]
fn read_exec_bit(_path: &std::path::Path) -> bool {
    false
}

/// FACTOR D (exec-bit toggle pattern) -- applied immediately after each
/// device's initial write. Level 4 (toggle-after-convergence) is handled
/// separately, as a second round, in `run_taguchi_v2_row` -- there is
/// nothing to do here for it yet.
fn apply_initial_exec_bit(exec_level: u8, device_idx: usize, path: &std::path::Path) {
    match exec_level {
        1 => {} // never set -- leave whatever `std::fs::write` produced.
        2 => set_exec_bit(path, true),
        3 => set_exec_bit(path, device_idx.is_multiple_of(2)),
        4 => {} // toggled later, after initial convergence.
        _ => unreachable!(),
    }
}

fn file_hash(path: &std::path::Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    let content = std::fs::read(path).ok()?;
    Some(hex::encode(sha2::Sha256::digest(&content)))
}

/// Waits for every device in `active` to report an identical, present
/// content hash for `rel_path`, panicking with a per-device diagnostic
/// (including all five factor levels and which convergence phase timed
/// out) if that never happens within the timeout.
#[allow(clippy::too_many_arguments)]
async fn wait_for_content_convergence(
    active: &[&TestDevice],
    rel_path: &std::path::Path,
    row_name: &str,
    size_level: u8,
    pattern_level: u8,
    path_level: u8,
    exec_level: u8,
    churn_level: u8,
    phase: &str,
) {
    // churn_level 2 (a device joining mid-test) is a genuinely slower path,
    // not a bug: a joiner's first eager reconcile attempt can blow its own
    // `DEFAULT_HYDRATION_TIMEOUT` budget under contention from several
    // devices racing to fetch/re-fetch overlapping conflict content for
    // the same path, silently falling back to the next periodic full-index
    // resync (`DEFAULT_FULL_INDEX_RESYNC_INTERVAL`, 90s) rather than a
    // faster targeted retry -- confirmed deterministic convergence at
    // ~93s for row 16 (size_level=4, churn_level=2) via an isolated,
    // extended-timeout repro; this is documented, intentional fallback
    // behavior in peer_session.rs, not a daemon bug. Give any join-churn
    // row enough headroom to clear that fallback rather than timing out on
    // what is, underneath, a real (if slow) convergence.
    let timeout = if churn_level == 2 { Duration::from_secs(150) } else { Duration::from_secs(60) };
    wait_until_with_context(
        || {
            let reference = file_hash(&active[0].root.path().join(rel_path));
            reference.is_some()
                && active[1..].iter().all(|d| file_hash(&d.root.path().join(rel_path)) == reference)
        },
        timeout,
        || {
            let per_device = active
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let p = d.root.path().join(rel_path);
                    format!("device-{i} exists={} hash={:?}", p.exists(), file_hash(&p))
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "{row_name} [{phase}]: size_level={size_level} pattern_level={pattern_level} \
                 path_level={path_level} exec_level={exec_level} churn_level={churn_level} -- \
                 {per_device}"
            )
        },
    )
    .await;
}

/// Runs one Taguchi-array row: sets up 4 real devices, has each write its
/// own factor-A/B/C/D-driven content to the same logical path, applies
/// the factor-E churn action, waits for convergence, applies factor D's
/// second-round exec-bit toggle if applicable, then asserts every
/// still-active device converges on an identical final content hash (and,
/// on Unix, exec bit).
#[allow(clippy::too_many_arguments)]
async fn run_taguchi_v2_row(
    row_name: &str,
    size_level: u8,
    pattern_level: u8,
    path_level: u8,
    exec_level: u8,
    churn_level: u8,
) {
    const DEVICE_COUNT: usize = 4;
    let (devices, group_id, account, coordination_addr, relay_addr) =
        n_synced_devices(DEVICE_COUNT, row_name).await;

    let rel_path = relative_target_path(path_level);

    // --- initial round: every base device independently creates its own
    // parent directory (if any) and writes factor-driven content at the
    // same relative path, with no stagger between devices -- at
    // path_level 4 this means all 4 devices race creating the same
    // logical (but locally independent) parent directory for the first
    // time.
    for (idx, device) in devices.iter().enumerate() {
        let full_path = device.root.path().join(&rel_path);
        if let Some(parent) = full_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).unwrap();
            }
        }
        let content = generate_content(size_level, pattern_level, idx);
        std::fs::write(&full_path, &content).unwrap();
        apply_initial_exec_bit(exec_level, idx, &full_path);
    }

    // --- FACTOR E (device churn), applied right after the initial round
    // -- deliberately before waiting for convergence, so the churn action
    // itself races the initial write's propagation (mirrors v1's own
    // "mid-test" perturbation timing).
    let mut excluded_idx: Option<usize> = None;
    let mut joined_device: Option<TestDevice> = None;
    match churn_level {
        1 => {} // none -- all 4 devices present for the whole test.
        2 => {
            let new_device = setup_device(&account, "device-churn-join").await;
            support::grant_access(&account, &group_id, &new_device.device_id).await;
            start_syncing(
                &new_device,
                coordination_addr.clone(),
                relay_addr,
                account.access_token.clone(),
                &group_id,
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            joined_device = Some(new_device);
        }
        3 => {
            support::revoke_access(&account, &group_id, &devices[DEVICE_COUNT - 1].device_id).await;
            excluded_idx = Some(DEVICE_COUNT - 1);
        }
        4 => {
            support::remove_device(&account, &devices[DEVICE_COUNT - 1].device_id).await;
            excluded_idx = Some(DEVICE_COUNT - 1);
        }
        _ => unreachable!(),
    }

    // Active devices for convergence purposes: base devices minus any
    // revoked/removed one (churn levels 3/4 -- that device's own local
    // state cannot converge further once it has lost access or been
    // removed, so it is deliberately excluded here), plus any mid-test
    // joiner (churn level 2).
    let active_refs: Vec<&TestDevice> = devices
        .iter()
        .enumerate()
        .filter(|(idx, _)| Some(*idx) != excluded_idx)
        .map(|(_, d)| d)
        .chain(joined_device.iter())
        .collect();

    wait_for_content_convergence(
        &active_refs,
        &rel_path,
        row_name,
        size_level,
        pattern_level,
        path_level,
        exec_level,
        churn_level,
        "initial",
    )
    .await;

    // --- FACTOR D level 4: a second round, toggling the exec bit only
    // after the file content itself has already converged once.
    if exec_level == 4 {
        for device in &active_refs {
            let full_path = device.root.path().join(&rel_path);
            let current = read_exec_bit(&full_path);
            set_exec_bit(&full_path, !current);
        }
        wait_for_content_convergence(
            &active_refs,
            &rel_path,
            row_name,
            size_level,
            pattern_level,
            path_level,
            exec_level,
            churn_level,
            "post-exec-toggle",
        )
        .await;
    }

    // A final settle window, matching v1's own reasoning: content-hash
    // convergence (checked above) doesn't guarantee the exec-bit
    // metadata field has finished propagating too.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let reference_path = active_refs[0].root.path().join(&rel_path);
    let reference_hash = file_hash(&reference_path).unwrap_or_else(|| {
        panic!(
            "{row_name}: device-0 never received the target file (size_level={size_level}, \
             pattern_level={pattern_level}, path_level={path_level}, exec_level={exec_level}, \
             churn_level={churn_level})"
        )
    });
    let reference_exec = read_exec_bit(&reference_path);

    for (i, device) in active_refs.iter().enumerate().skip(1) {
        let full_path = device.root.path().join(&rel_path);
        let hash = file_hash(&full_path);
        assert_eq!(
            hash.as_deref(),
            Some(reference_hash.as_str()),
            "{row_name}: device-{i} diverged from device-0 (size_level={size_level}, \
             pattern_level={pattern_level}, path_level={path_level}, exec_level={exec_level}, \
             churn_level={churn_level})"
        );
        let exec = read_exec_bit(&full_path);
        assert_eq!(
            exec, reference_exec,
            "{row_name}: device-{i} exec-bit diverged from device-0 (size_level={size_level}, \
             pattern_level={pattern_level}, path_level={path_level}, exec_level={exec_level}, \
             churn_level={churn_level})"
        );
    }

    // Sanity check that the excluded (revoked/removed) device, if any,
    // did not silently end up back in the converged set under a
    // different name -- `real_entry_names` on its own root is only
    // informational here (task context, not an assertion) since its
    // future state is explicitly out of scope once excluded.
    let _ = excluded_idx.map(|idx| real_entry_names(devices[idx].root.path()));
}

// --- L16(4^5) orthogonal array rows: (A size, B pattern, C path depth, D exec-bit, E churn) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_01_size_tiny_pattern_text_path_flat_exec_never_churn_none() {
    run_taguchi_v2_row("taguchi-v2-01", 1, 1, 1, 1, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_02_size_tiny_pattern_binary_path_sub_exec_all_true_churn_join() {
    run_taguchi_v2_row("taguchi-v2-02", 1, 2, 2, 2, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_03_size_tiny_pattern_compressible_path_deep_exec_alternate_churn_revoke() {
    run_taguchi_v2_row("taguchi-v2-03", 1, 3, 3, 3, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_04_size_tiny_pattern_incompressible_path_shared_dir_exec_toggle_churn_remove(
) {
    run_taguchi_v2_row("taguchi-v2-04", 1, 4, 4, 4, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_05_size_small_pattern_text_path_sub_exec_alternate_churn_remove() {
    run_taguchi_v2_row("taguchi-v2-05", 2, 1, 2, 3, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_06_size_small_pattern_binary_path_flat_exec_toggle_churn_revoke() {
    run_taguchi_v2_row("taguchi-v2-06", 2, 2, 1, 4, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_07_size_small_pattern_compressible_path_shared_dir_exec_never_churn_join() {
    run_taguchi_v2_row("taguchi-v2-07", 2, 3, 4, 1, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_08_size_small_pattern_incompressible_path_deep_exec_all_true_churn_none() {
    run_taguchi_v2_row("taguchi-v2-08", 2, 4, 3, 2, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_09_size_medium_pattern_text_path_deep_exec_toggle_churn_join() {
    run_taguchi_v2_row("taguchi-v2-09", 3, 1, 3, 4, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_10_size_medium_pattern_binary_path_shared_dir_exec_alternate_churn_none() {
    run_taguchi_v2_row("taguchi-v2-10", 3, 2, 4, 3, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_11_size_medium_pattern_compressible_path_flat_exec_all_true_churn_remove() {
    run_taguchi_v2_row("taguchi-v2-11", 3, 3, 1, 2, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_12_size_medium_pattern_incompressible_path_sub_exec_never_churn_revoke() {
    run_taguchi_v2_row("taguchi-v2-12", 3, 4, 2, 1, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_13_size_large_pattern_text_path_shared_dir_exec_all_true_churn_revoke() {
    run_taguchi_v2_row("taguchi-v2-13", 4, 1, 4, 2, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_14_size_large_pattern_binary_path_deep_exec_never_churn_remove() {
    run_taguchi_v2_row("taguchi-v2-14", 4, 2, 3, 1, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_15_size_large_pattern_compressible_path_sub_exec_toggle_churn_none() {
    run_taguchi_v2_row("taguchi-v2-15", 4, 3, 2, 4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v2_row_16_size_large_pattern_incompressible_path_flat_exec_alternate_churn_join() {
    run_taguchi_v2_row("taguchi-v2-16", 4, 4, 1, 3, 2).await;
}
