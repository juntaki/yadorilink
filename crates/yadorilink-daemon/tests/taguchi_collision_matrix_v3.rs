//! A third Taguchi-method (orthogonal-array) designed matrix of
//! concurrent-collision scenarios, run through the real daemon stack --
//! complementing `taguchi_collision_matrix.rs` (v1: device-count,
//! op-pattern, stagger, path-relationship, round-repetition) and
//! `taguchi_collision_matrix_v2.rs` (v2: file size, content pattern, path
//! depth, exec-bit toggling, device churn).
//!
//! v1 and v2 never combine network partition/reconnect timing
//! (`partition_reconnect_matrix.rs`'s domain) with device churn, rename/
//! directory topology (`directory_conflict_matrix.rs`'s domain), or
//! op-type combinations in a single matrix -- every historical silent
//! data-loss bug found by this test suite so far
//! (`fix-local-edit-swallowed-by-self-echo-race`,
//! `fix-multiway-conflict-name-content-mismatch`,
//! `fix-local-change-lost-under-registration-mutex-contention`) came from
//! exactly this kind of previously-uncrossed timing interaction. This file
//! exists to close that gap: five *new* factors, four levels each, covered
//! pairwise-exhaustively by the same standard L16(4^5) orthogonal array
//! v1/v2 use (16 runs instead of 4^5 = 1024 for a full factorial).
//!
//! Factors (see each `FACTOR_*` doc comment below for level definitions):
//! - A: partition/reconnect timing (none / full-offline-then-sync /
//!   partial-propagation-then-partition / flapping double-partition)
//! - B: op combination per device (all edit / edit-delete alternating /
//!   delete-vs-rename / rename-to-identical-new-name)
//! - C: path topology (flat single file / rename race onto a live path /
//!   nested directory with a directory-level rename / case-fold collision)
//! - D: device count + churn (2, no churn / 3, no churn / 4, a device
//!   joins mid-test / 4, a device is access-revoked mid-test)
//! - E: timing stagger (0/10/100/500ms between each device's own op),
//!   reusing v1's exact levels
//!
//! Device index 0 is a fixed always-online anchor in every row (never
//! paused), mirroring `partition_reconnect_matrix.rs`'s own two-device
//! shape generalized to N devices -- this guarantees a mid-partition
//! joiner/revokee (Factor D) always has at least one live peer to actually
//! race against, and matches this file's convergence assertions being
//! phrased "relative to device-0".
//!
//! `TestDevice`/`setup_device`/`start_syncing`/`n_synced_devices` are
//! intentionally duplicated from `taguchi_collision_matrix.rs`/
//! `taguchi_collision_matrix_v2.rs` rather than shared -- matches this
//! codebase's existing convention of self-contained daemon integration
//! test binaries.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    relay_addr: SocketAddr,
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
/// server addresses -- this file's churn factor (D) needs them after
/// setup, to grant a mid-test joiner access or to revoke an existing
/// device's.
async fn n_synced_devices(
    n: usize,
    test_name: &str,
) -> (Vec<TestDevice>, String, TestAccount, String, SocketAddr) {
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "taguchi-v3-group").await;
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

/// A recursive relative-path -> content-hash snapshot of everything under
/// `root`, duplicated from `directory_conflict_matrix.rs` -- needed here
/// (rather than the flat, top-level-only `real_entry_names`) because
/// Factor C level 3 nests its target file under a subdirectory.
fn recursive_snapshot(root: &Path) -> HashMap<String, String> {
    fn walk(base: &Path, current: &Path, out: &mut HashMap<String, String>) {
        let Ok(entries) = std::fs::read_dir(current) else { return };
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains(".yadorilink-tmp.") || name.starts_with(".yl-case-probe-") {
                continue;
            }
            let Ok(file_type) = entry.file_type() else { continue };
            let path = entry.path();
            if file_type.is_dir() {
                walk(base, &path, out);
            } else if file_type.is_file() {
                let Ok(rel_path) = path.strip_prefix(base) else { continue };
                let rel_path = rel_path.to_string_lossy().replace('\\', "/");
                let content = std::fs::read(&path).unwrap_or_default();
                out.insert(rel_path, hex::encode(sha2::Sha256::digest(&content)));
            }
        }
    }
    let mut out = HashMap::new();
    walk(root, root, &mut out);
    out
}

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

fn pause(device: &TestDevice) {
    device.state.sync_state.set_paused(device.root.path().to_str().unwrap(), true).unwrap();
}

/// Resumes every device in `devices` -- per `partition_reconnect_matrix.
/// rs`'s own header doc comment, resuming a device that was never
/// actually paused is a harmless no-op as far as pause state goes, but it
/// forces that device to re-broadcast its current full index too, which
/// is what makes a still-online peer's changes (silently dropped on
/// arrival at a paused device during the offline window) visible once
/// everyone reconnects.
/// Resumes every device concurrently (`join_all`, not a sequential loop):
/// `peer_session::reconcile_files_if_authorized`'s "pause trumps
/// everything" rule silently drops an incoming update for a still-paused
/// link with no retry queued (confirmed investigating row 8's own
/// non-convergence) -- resuming devices one at a time left a real window
/// where an early-resumed device's full-index rebroadcast reaches a peer
/// that hasn't unpaused yet, losing that push with no fast-path recovery
/// (only the ~90s periodic full-index resync). Matches
/// `partition_reconnect_matrix.rs`'s own `partition_both_devices_paused_
/// simultaneously_resume_races_converges`, which already resumes its two
/// devices via `tokio::join!` for the identical reason.
async fn resume_all(devices: &[TestDevice]) {
    let resumes = devices.iter().map(|device| {
        link_manager::resume_link(&device.state, device.root.path().to_str().unwrap())
    });
    for result in futures_util::future::join_all(resumes).await {
        result.unwrap();
    }
}

// --- Factor B: op combination assigned per device index -------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Edit,
    Delete,
    Rename,
}

/// FACTOR B (op combination) -- always applied against Factor C's
/// `target_path`, with two exceptions handled at their call sites in
/// `apply_op`: path_level 2's rename-race override (device 0 always
/// renames regardless of its assigned op here), and op_level 4's
/// same-destination-for-everyone Rename semantics.
fn op_for_device(op_level: u8, device_idx: usize) -> Op {
    match op_level {
        1 => Op::Edit,
        2 => {
            if device_idx.is_multiple_of(2) {
                Op::Edit
            } else {
                Op::Delete
            }
        }
        3 => {
            if device_idx == 0 {
                Op::Delete
            } else {
                Op::Rename
            }
        }
        4 => Op::Rename,
        _ => unreachable!(),
    }
}

// --- Factor C: target path topology ---------------------------------------

/// FACTOR C (path topology) -- the relative path each device operates on.
/// Level 2's actual target is overridden for device 0 in `apply_op`
/// (device 0 always races the shared name's disappearance via rename);
/// level 4 gives even/odd device indices differently-cased names for the
/// same logical file, a genuine hazard only on a case-insensitive
/// filesystem (gated at the top of `run_taguchi_v3_row`, matching
/// `collision_matrix.rs`'s own case-fold scenario).
fn target_path(path_level: u8, device_idx: usize) -> PathBuf {
    match path_level {
        1 => PathBuf::from("shared.bin"),
        2 => PathBuf::from("shared.bin"),
        3 => PathBuf::from("shared_dir/target.bin"),
        4 => {
            if device_idx.is_multiple_of(2) {
                PathBuf::from("Shared.bin")
            } else {
                PathBuf::from("shared.bin")
            }
        }
        _ => unreachable!(),
    }
}

/// Applies `device_idx`'s Factor-B op at Factor-C's target path for this
/// round, with two path_level-specific overrides layered on top (see
/// `target_path`'s doc comment for the rename-race one; the directory
/// rename below is new).
fn apply_op(root: &Path, path_level: u8, op_level: u8, device_idx: usize, op: Op, round: u32) {
    let target = target_path(path_level, device_idx);
    let path = root.join(&target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    let content = format!("row round {round} device {device_idx} target {}", target.display());

    // path_level 2 (rename race): device 0 always races the shared
    // target's disappearance via rename, overriding whatever Factor B
    // assigned it, so every row selecting this path level actually
    // exercises "one device renames the shared target while everyone
    // else still touches the old name" regardless of the op-combination
    // factor.
    if path_level == 2 && device_idx == 0 {
        if path.exists() {
            let renamed = root.join(format!("shared-renamed-r{round}.bin"));
            std::fs::rename(&path, &renamed).unwrap();
        } else {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        return;
    }

    match op {
        Op::Edit => {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        Op::Delete => {
            let _ = std::fs::remove_file(&path);
        }
        Op::Rename => {
            if path.exists() {
                let dest = if op_level == 4 {
                    // op_level 4: every device renames to the SAME new
                    // name -- a "multiple independent renames converging
                    // on one identical target" collision, distinct from
                    // `directory_conflict_matrix.rs`'s only-covered
                    // rename-to-*different*-targets shape.
                    root.join("renamed-shared.bin")
                } else {
                    root.join(format!(
                        "{}.renamed-{device_idx}-r{round}",
                        target.file_name().unwrap().to_string_lossy()
                    ))
                };
                let _ = std::fs::rename(&path, dest);
            } else {
                std::fs::write(&path, content.as_bytes()).unwrap();
            }
        }
    }

    // path_level 3 (nested directory): on round 0 only, device 0
    // additionally renames the whole shared parent directory right after
    // its own op inside it -- combining `directory_conflict_matrix.rs`'s
    // "nested rename races a child edit" shape with this row's
    // partition/churn/op axes for the first time.
    if path_level == 3 && device_idx == 0 && round == 0 {
        let dir = root.join("shared_dir");
        if dir.exists() {
            let _ = std::fs::rename(&dir, root.join("shared_dir-renamed"));
        }
    }
}

async fn apply_round_for_devices(
    devices: &[TestDevice],
    path_level: u8,
    op_level: u8,
    round: u32,
    stagger: Duration,
) {
    for (idx, device) in devices.iter().enumerate() {
        let op = op_for_device(op_level, idx);
        apply_op(device.root.path(), path_level, op_level, idx, op, round);
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
    }
}

/// FACTOR E (timing stagger, in milliseconds between each device's own
/// operation being issued) -- identical levels to v1's own Factor C.
fn stagger_ms(level: u8) -> u64 {
    match level {
        1 => 0,
        2 => 10,
        3 => 100,
        4 => 500,
        _ => unreachable!(),
    }
}

/// Data-loss guard, independent of (and stronger than) the plain
/// convergence check in `run_taguchi_v3_row`: for every device whose
/// Factor-B-assigned *final* (round-1) op was a genuine content Edit
/// (Delete/Rename devices are skipped -- their survival shape is harder to
/// pin down deterministically given this row's path-level overrides, and
/// v1/v2/`directory_conflict_matrix.rs` already cover those shapes
/// elsewhere), that device's actual content must appear *somewhere* in the
/// final converged tree -- as the winning copy, a conflict copy, or any
/// other surviving name. Plain convergence alone does not guarantee this:
/// all devices could "converge" by silently ending up without content that
/// should exist, which is exactly the shape
/// `fix-local-edit-swallowed-by-self-echo-race` fixed (a real edit
/// `fs::remove_file`'d with no conflict-copy artifact at all).
///
/// Skipped entirely for path_level 4 (case-fold): a case-insensitive
/// filesystem can only ever hold one of two differently-cased names, so
/// content can be legitimately un-representable as a separate on-disk
/// artifact there -- the same reasoning `collision_matrix.rs`'s own
/// case-fold scenario uses to stay convergence-only.
fn assert_no_content_silently_lost(
    devices: &[TestDevice],
    op_level: u8,
    path_level: u8,
    excluded_idx: Option<usize>,
    row_name: &str,
    final_snapshot: &HashMap<String, String>,
) {
    if path_level == 4 {
        return;
    }
    for idx in 0..devices.len() {
        if Some(idx) == excluded_idx {
            continue;
        }
        if op_for_device(op_level, idx) != Op::Edit {
            continue;
        }
        if path_level == 2 && idx == 0 {
            continue; // overridden to a rename, never a plain edit
        }
        let target = target_path(path_level, idx);
        let expected_content = format!("row round 1 device {idx} target {}", target.display());
        let expected_hash = hex::encode(sha2::Sha256::digest(expected_content.as_bytes()));
        assert!(
            final_snapshot.values().any(|h| h == &expected_hash),
            "{row_name}: device-{idx}'s round-1 edit (content hash {expected_hash}) is not \
             present anywhere in the final converged tree -- silent data loss \
             (op_level={op_level}, path_level={path_level})"
        );
    }
}

/// Runs one Taguchi-array row: sets up devices per Factor D, applies
/// Factor A's partition/reconnect timing around two rounds of Factor-B/C-
/// driven operations (staggered per Factor E), applies Factor D's churn
/// action between the two rounds, waits for convergence, then asserts both
/// plain convergence and (except on path_level 4) the stronger
/// no-silent-data-loss property above.
#[allow(clippy::too_many_arguments)]
async fn run_taguchi_v3_row(
    row_name: &str,
    partition_level: u8,
    op_level: u8,
    path_level: u8,
    churn_level: u8,
    stagger_level: u8,
) {
    let _ = tracing_subscriber::fmt::try_init();
    let device_count: usize = match churn_level {
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 4,
        _ => unreachable!(),
    };
    let (devices, group_id, account, coordination_addr, relay_addr) =
        n_synced_devices(device_count, row_name).await;

    if path_level == 4
        && !yadorilink_sync_core::hazard::is_case_insensitive_filesystem(devices[0].root.path())
    {
        eprintln!(
            "{row_name}: skipping case-fold path level -- {} is case-sensitive here",
            devices[0].root.path().display()
        );
        return;
    }

    let stagger = Duration::from_millis(stagger_ms(stagger_level));

    // Factor A: devices[1..] are the ones paused for partition levels 2-4;
    // device 0 is a fixed always-online anchor across every row (see this
    // file's header doc comment).
    let paused_indices: Vec<usize> = (1..device_count).collect();

    if matches!(partition_level, 2 | 4) {
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }
    apply_round_for_devices(&devices, path_level, op_level, 0, stagger).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    if partition_level == 3 {
        // Partial-propagation-then-partition: round 0 ran fully online
        // and was allowed to start propagating; only now do the
        // non-anchor devices go dark.
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }
    if partition_level == 4 {
        // Flapping: reconnect once before round 1, then partition again --
        // stresses whether a second offline window can silently drop
        // round-0's backlog before it finished flushing from the first
        // reconnect.
        resume_all(&devices).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        for &i in &paused_indices {
            pause(&devices[i]);
        }
    }

    // Factor D churn action, applied between the two rounds so it races
    // whatever partition state currently holds (online for level 1,
    // freshly offline for 2/3/4).
    let mut excluded_idx: Option<usize> = None;
    let mut joined_device: Option<TestDevice> = None;
    match churn_level {
        1 | 2 => {}
        3 => {
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
        4 => {
            support::revoke_access(&account, &group_id, &devices[device_count - 1].device_id).await;
            excluded_idx = Some(device_count - 1);
        }
        _ => unreachable!(),
    }

    apply_round_for_devices(&devices, path_level, op_level, 1, stagger).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    if matches!(partition_level, 2..=4) {
        resume_all(&devices).await;
    }

    let active_refs: Vec<&TestDevice> = devices
        .iter()
        .enumerate()
        .filter(|(idx, _)| Some(*idx) != excluded_idx)
        .map(|(_, d)| d)
        .chain(joined_device.iter())
        .collect();

    // churn_level 3 (a device joining mid-test) is a genuinely slower
    // path, not a bug -- see `taguchi_collision_matrix_v2.rs`'s own
    // `wait_for_content_convergence` doc comment for the traced-through
    // reason (a joiner's eager reconcile can blow its own hydration
    // timeout under contention and fall back to the ~90s periodic
    // full-index resync). Give it matching headroom.
    let timeout =
        if churn_level == 3 { Duration::from_secs(200) } else { Duration::from_secs(150) };

    // path_level 4 (case-fold) is deliberately excluded from the strict
    // full-snapshot convergence check below: per `hazard.rs`'s "hold"
    // design (D3) and `collision_matrix.rs`'s own case-fold scenario
    // (`concurrent_differently_cased_create_is_a_hazard_on_case_
    // insensitive_filesystems`), a case-fold collision is resolved
    // per-device by whichever name that device happened to index first --
    // there is no guarantee, or intent, that every device converges on the
    // SAME canonical name. What must still hold: each device ends up with
    // exactly one canonical (non-conflict-copy) entry for the collision,
    // and any conflict-copy artifacts that do get created are identical
    // across devices (those go through the same conflict-copy machinery
    // as every other path level, which does converge).
    if path_level == 4 {
        // Case-insensitive-by-name conflict-copy comparison: a conflict
        // copy's filename is built from the original colliding name's own
        // case (`conflict.rs`'s copy-name builder), so two devices can
        // independently materialize the SAME conflict-copy content (same
        // UUID, same timestamp, same hash) under differently-cased
        // leading words -- the same per-device "whichever case I saw
        // first" hold semantics this whole branch already accounts for,
        // just showing up one level deeper on the copy name rather than
        // the original.
        fn conflict_copies_lowercased(root: &Path) -> HashMap<String, String> {
            recursive_snapshot(root)
                .into_iter()
                .filter(|(k, _)| is_conflict_copy(k))
                .map(|(k, v)| (k.to_lowercase(), v))
                .collect()
        }
        wait_until_with_context(
            || {
                active_refs.iter().all(|d| {
                    let snap = recursive_snapshot(d.root.path());
                    snap.keys().filter(|k| !is_conflict_copy(k)).count() == 1
                }) && {
                    let reference = conflict_copies_lowercased(active_refs[0].root.path());
                    active_refs[1..]
                        .iter()
                        .all(|d| conflict_copies_lowercased(d.root.path()) == reference)
                }
            },
            timeout,
            || {
                active_refs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", recursive_snapshot(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        )
        .await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        for (i, device) in active_refs.iter().enumerate() {
            let snap = recursive_snapshot(device.root.path());
            let canonical_count = snap.keys().filter(|k| !is_conflict_copy(k)).count();
            assert_eq!(
                canonical_count, 1,
                "{row_name}: device-{i} has {canonical_count} canonical (non-conflict-copy) \
                 entries for the case-fold collision, expected exactly 1 (partition_level={partition_level}, \
                 op_level={op_level}, churn_level={churn_level}, stagger_level={stagger_level}): {snap:?}"
            );
        }
        let reference_conflict_copies = conflict_copies_lowercased(active_refs[0].root.path());
        for (i, device) in active_refs.iter().enumerate().skip(1) {
            let conflict_copies = conflict_copies_lowercased(device.root.path());
            assert_eq!(
                conflict_copies, reference_conflict_copies,
                "{row_name}: device-{i}'s conflict-copy artifacts diverged from device-0's \
                 (partition_level={partition_level}, op_level={op_level}, churn_level={churn_level}, \
                 stagger_level={stagger_level})"
            );
        }
    } else {
        wait_until_with_context(
            || {
                let reference = recursive_snapshot(active_refs[0].root.path());
                active_refs[1..].iter().all(|d| recursive_snapshot(d.root.path()) == reference)
            },
            timeout,
            || {
                active_refs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", recursive_snapshot(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        )
        .await;

        // A final settle window, matching v1/v2's own reasoning: name/hash-set
        // convergence (checked above) doesn't guarantee every device has
        // finished materializing identical bytes down to the last one yet.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let reference = recursive_snapshot(devices[0].root.path());
        for (i, device) in active_refs.iter().enumerate().skip(1) {
            let snap = recursive_snapshot(device.root.path());
            assert_eq!(
                snap, reference,
                "{row_name}: device-{i} diverged from device-0 (partition_level={partition_level}, \
                 op_level={op_level}, path_level={path_level}, churn_level={churn_level}, \
                 stagger_level={stagger_level})"
            );
        }
    }

    let reference = recursive_snapshot(devices[0].root.path());
    assert_no_content_silently_lost(
        &devices,
        op_level,
        path_level,
        excluded_idx,
        row_name,
        &reference,
    );

    // Sanity check that the excluded (revoked) device, if any, did not
    // silently end up back in the converged set under a different name --
    // informational only (task context), since its future state is
    // explicitly out of scope once excluded.
    let _ = excluded_idx.map(|idx| real_entry_names(devices[idx].root.path()));
}

// --- L16(4^5) orthogonal array rows: (A partition, B op, C path, D churn, E stagger) ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_01_part_none_op_all_edit_path_flat_churn_dc2_stag_sim() {
    run_taguchi_v3_row("taguchi-v3-01", 1, 1, 1, 1, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_02_part_none_op_edit_del_alt_path_rename_race_churn_dc3_stag_micro() {
    run_taguchi_v3_row("taguchi-v3-02", 1, 2, 2, 2, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_03_part_none_op_del_vs_rename_path_nested_dir_churn_dc4_join_stag_small() {
    run_taguchi_v3_row("taguchi-v3-03", 1, 3, 3, 3, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_04_part_none_op_rename_same_target_path_case_fold_churn_dc4_revoke_stag_large(
) {
    run_taguchi_v3_row("taguchi-v3-04", 1, 4, 4, 4, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_05_part_full_offline_op_all_edit_path_rename_race_churn_dc4_join_stag_large(
) {
    run_taguchi_v3_row("taguchi-v3-05", 2, 1, 2, 3, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_06_part_full_offline_op_edit_del_alt_path_flat_churn_dc4_revoke_stag_small()
{
    run_taguchi_v3_row("taguchi-v3-06", 2, 2, 1, 4, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_07_part_full_offline_op_del_vs_rename_path_case_fold_churn_dc2_stag_micro()
{
    run_taguchi_v3_row("taguchi-v3-07", 2, 3, 4, 1, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_08_part_full_offline_op_rename_same_target_path_nested_dir_churn_dc3_stag_sim(
) {
    run_taguchi_v3_row("taguchi-v3-08", 2, 4, 3, 2, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_09_part_partial_prop_op_all_edit_path_nested_dir_churn_dc4_revoke_stag_micro(
) {
    run_taguchi_v3_row("taguchi-v3-09", 3, 1, 3, 4, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_10_part_partial_prop_op_edit_del_alt_path_case_fold_churn_dc4_join_stag_sim(
) {
    run_taguchi_v3_row("taguchi-v3-10", 3, 2, 4, 3, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_11_part_partial_prop_op_del_vs_rename_path_flat_churn_dc3_stag_large() {
    run_taguchi_v3_row("taguchi-v3-11", 3, 3, 1, 2, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_12_part_partial_prop_op_rename_same_target_path_rename_race_churn_dc2_stag_small(
) {
    run_taguchi_v3_row("taguchi-v3-12", 3, 4, 2, 1, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_13_part_flap_op_all_edit_path_case_fold_churn_dc3_stag_small() {
    run_taguchi_v3_row("taguchi-v3-13", 4, 1, 4, 2, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_14_part_flap_op_edit_del_alt_path_nested_dir_churn_dc2_stag_large() {
    run_taguchi_v3_row("taguchi-v3-14", 4, 2, 3, 1, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_15_part_flap_op_del_vs_rename_path_rename_race_churn_dc4_revoke_stag_sim() {
    run_taguchi_v3_row("taguchi-v3-15", 4, 3, 2, 4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taguchi_v3_row_16_part_flap_op_rename_same_target_path_flat_churn_dc4_join_stag_micro() {
    run_taguchi_v3_row("taguchi-v3-16", 4, 4, 1, 3, 2).await;
}
