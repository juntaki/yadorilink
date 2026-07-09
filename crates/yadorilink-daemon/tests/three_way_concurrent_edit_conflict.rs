//! Regression coverage for `fix-multiway-conflict-name-content-mismatch`:
//! when three or more devices concurrently edit the same path, a
//! conflict-copy's deterministic name must always match the content
//! actually materialized under it, and every device must independently
//! converge on the same (name, content) pairing.
//!
//! Found via the Taguchi orthogonal-array test matrix
//! (`taguchi_collision_matrix.rs`), which surfaced 2/16 failing rows, both
//! at the "simultaneous" timing level with 3+ devices editing the same
//! path. This file is the deterministic, minimal reproduction that let the
//! bug be root-caused and fixed (`resolve_and_apply_conflict`'s naming was
//! attributing a conflict-copy's identity to whichever peer session
//! happened to process it, rather than the content's true origin device
//! -- see `openspec/changes/fix-multiway-conflict-name-content-mismatch`).

mod support;

use std::sync::Arc;
use std::time::Duration;

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

/// A device's real (non-artifact) entries, keyed by name, valued by
/// content -- plain content (not a hash) so a failure's assertion message
/// is directly readable without needing a separate lookup.
fn snapshot(root: &std::path::Path) -> std::collections::HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_devices_editing_the_same_new_file_simultaneously_never_mismatches_name_and_content()
{
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, "three-way-conflict@example.com").await;

    let mut devices = Vec::new();
    for i in 0..3 {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "three-way-conflict-group").await;
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

    // All 3 devices independently create "shared.bin" with DISTINCT
    // content, issued back-to-back with no pause between them -- a real
    // 50ms stagger between writes gives each write enough time to
    // propagate and be adopted sequentially rather than racing as a
    // genuine concurrent conflict, so the zero-stagger timing here is
    // deliberate, not an oversight.
    for (i, device) in devices.iter().enumerate() {
        std::fs::write(device.root.path().join("shared.bin"), format!("content from device {i}"))
            .unwrap();
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

    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(
            snap, reference,
            "device-{i} diverged from device-0 -- a conflict-copy name matching on both devices but \
             holding different content indicates the fix-multiway-conflict-name-content-mismatch bug \
             has resurfaced (resolve_and_apply_conflict attributing a conflict copy's identity to the \
             wrong origin device)"
        );
    }
}
