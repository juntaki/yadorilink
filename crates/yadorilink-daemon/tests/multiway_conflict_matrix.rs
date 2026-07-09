//! Permanent, generalized regression test superseding the temporary
//! `three_way_conflict_diag.rs` diagnostic (task 4.1 of the
//! `fix-multiway-conflict-name-content-mismatch` OpenSpec change --
//! see `openspec/changes/fix-multiway-conflict-name-content-mismatch/`
//! for the full mechanism writeup).
//!
//! Background: `peer_session.rs`'s `resolve_and_apply_conflict` hardcodes
//! `self.local_device_id`/`self.peer_device_id` when naming a conflict
//! copy. That's correct for a single pairwise resolution, but once a
//! third (or later) device's edit triggers a *second* round of
//! pairwise resolution involving a path that no longer represents this
//! device's own unmediated edit, the naming can misattribute content --
//! producing a conflict-copy path that embeds one device's id but
//! actually holds a DIFFERENT device's content. This is a REAL,
//! CONFIRMED, UNFIXED bug (~50% repro rate for the original 3-device
//! simultaneous case per prior investigation).
//!
//! This file generalizes that one scenario into a small matrix across
//! device count (3, 4, 5, 6) and write timing (simultaneous vs
//! staggered), all asserting the SAME correctness property the
//! diagnostic checked: after convergence, every device must agree on
//! the exact same (name -> content-hash) map. A "mismatch" bug
//! manifests as devices disagreeing about which name holds which
//! content, NOT merely differing file counts -- so the assertion below
//! compares full snapshots, never just `.len()`.
//!
//! Because the underlying bug is unfixed, some of these tests may
//! legitimately FAIL, intermittently, when run against the real daemon
//! stack -- that is expected and is the point: this file is meant to be
//! run repeatedly (e.g. via a heat-run script) across the device-count /
//! timing grid to characterize the bug's actual repro-rate envelope,
//! which feeds directly into verifying the fix for the OpenSpec change
//! above. Do not weaken the core assertion to a file-count check to make
//! these pass -- that would silently hide the bug this file exists to
//! catch.

mod support;

use std::collections::HashMap;
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

// `TestDevice`/`setup_device`/`start_syncing`/`n_synced_devices` are
// intentionally duplicated from `taguchi_collision_matrix.rs` (and
// friends) rather than shared -- matches this codebase's existing
// convention of self-contained daemon integration test binaries.

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

async fn n_synced_devices(n: usize, test_name: &str) -> Vec<TestDevice> {
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "multiway-conflict-group").await;
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
    devices
}

fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read(root.join(&name)).unwrap_or_default();
            (name, hex::encode(sha2::Sha256::digest(&content)))
        })
        .collect()
}

/// Sets up `device_count` real synced devices, has every device write
/// DISTINCT content to the SAME brand-new path with `stagger_ms`
/// between each device's write (0 = back-to-back, no sleep, matching
/// the original diagnostic's "simultaneous" case -- a nonzero stagger
/// gives each write time to propagate and be adopted sequentially
/// rather than racing as a genuine concurrent conflict), waits for
/// name-set convergence, settles briefly, then asserts every device's
/// full (name -> content-hash) snapshot is IDENTICAL to every other
/// device's -- not merely that they have the same file COUNT, since
/// the actual bug is devices disagreeing on which name holds which
/// content.
async fn run_multiway_row(device_count: usize, stagger_ms: u64, row_name: &str) {
    let _ = tracing_subscriber::fmt::try_init();
    let devices = n_synced_devices(device_count, row_name).await;
    let stagger = Duration::from_millis(stagger_ms);

    for (i, device) in devices.iter().enumerate() {
        std::fs::write(
            device.root.path().join("shared.bin"),
            format!("device {i} content for {row_name}"),
        )
        .unwrap();
        tracing::info!(device_idx = i, device_id = %device.device_id, row_name, "wrote shared.bin");
        if !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
    }

    let devices_ref = &devices;
    wait_until_with_context(
        || {
            let reference = real_entry_names(devices_ref[0].root.path());
            devices_ref[1..].iter().all(|d| real_entry_names(d.root.path()) == reference)
        },
        Duration::from_secs(30),
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
    tokio::time::sleep(Duration::from_secs(2)).await;

    for (i, device) in devices.iter().enumerate() {
        let device_ids: Vec<&str> = devices.iter().map(|d| d.device_id.as_str()).collect();
        tracing::info!(
            device_idx = i,
            device_id = %device.device_id,
            all_device_ids = ?device_ids,
            snapshot = ?snapshot(device.root.path()),
            row_name,
            "final snapshot (name -> content hash)"
        );
    }

    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(
            snap, reference,
            "{row_name}: device-{i} diverged from device-0 (device_count={device_count}, \
             stagger_ms={stagger_ms}) -- expect NAME-vs-CONTENT mismatch in a conflict copy \
             if the multiway conflict naming bug is present (a conflict-copy path embeds one \
             device's id but holds a DIFFERENT device's content, due to chained pairwise \
             resolution misattributing self.local_device_id/self.peer_device_id once `local` \
             no longer represents this device's own unmediated edit)"
        );
    }
}

// --- 4 device counts x 2 timings = 8 rows ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_simultaneous_write_never_mismatches_name_and_content() {
    run_multiway_row(3, 0, "multiway-3-sim").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_staggered_write_never_mismatches_name_and_content() {
    run_multiway_row(3, 50, "multiway-3-stag").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_devices_simultaneous_write_never_mismatches_name_and_content() {
    run_multiway_row(4, 0, "multiway-4-sim").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_devices_staggered_write_never_mismatches_name_and_content() {
    run_multiway_row(4, 50, "multiway-4-stag").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_devices_simultaneous_write_never_mismatches_name_and_content() {
    run_multiway_row(5, 0, "multiway-5-sim").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_devices_staggered_write_never_mismatches_name_and_content() {
    run_multiway_row(5, 50, "multiway-5-stag").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn six_devices_simultaneous_write_never_mismatches_name_and_content() {
    run_multiway_row(6, 0, "multiway-6-sim").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn six_devices_staggered_write_never_mismatches_name_and_content() {
    run_multiway_row(6, 50, "multiway-6-stag").await;
}
