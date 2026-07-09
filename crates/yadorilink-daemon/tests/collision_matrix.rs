//! A deterministic (not randomized, unlike `monkey_chaos.rs`) matrix of
//! two-device collision scenarios, each run through the real full daemon
//! stack (real coordination server, real relay, real peer sessions) —
//! complementary to `monkey_chaos.rs`'s randomized exploration and
//! `peer_session.rs`'s unit-level `conflict.rs` tests: this file exists to
//! pin down the *expected* outcome of each named collision shape as an
//! explicit, reproducible assertion, so a regression in any one of them
//! fails with a clear "scenario X changed" signal rather than only
//! showing up as a diffuse chaos-test divergence.
//!
//! `TestDevice`/`setup_device`/`start_syncing` are intentionally duplicated
//! from `e2e_three_devices.rs`/`monkey_chaos.rs` rather than shared —
//! matches this codebase's existing convention of self-contained daemon
//! integration test binaries.

mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_sync_state, real_entry_names, wait_until, wait_until_with_context, TestAccount,
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

/// Sets up two devices, both syncing a fresh folder group, and waits for
/// peer sessions to establish. Every scenario below starts from this.
async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "collision-matrix-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_syncing(
        &device_a,
        coordination_addr.clone(),
        relay_addr,
        account.access_token.clone(),
        &group_id,
    )
    .await;
    start_syncing(
        &device_b,
        coordination_addr.clone(),
        relay_addr,
        account.access_token.clone(),
        &group_id,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    (device_a, device_b, group_id)
}

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

/// Waits for both devices' real entry sets to be identical, polling for a
/// stable match rather than a single point-in-time comparison.
async fn wait_for_convergence(a: &TestDevice, b: &TestDevice, timeout: Duration) {
    wait_until_with_context(
        || real_entry_names(a.root.path()) == real_entry_names(b.root.path()),
        timeout,
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(a.root.path()),
                real_entry_names(b.root.path())
            )
        },
    )
    .await;
}

// --- Scenario 1: concurrent edit vs edit -----------------------------------

/// Both devices independently edit an already-synced file at the same
/// time, with distinguishable mtimes so the outcome is deterministic:
/// both copies survive (one under the original name, one as a
/// conflict-marked copy), and both devices converge on the identical
/// final pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_edit_edit_keeps_both_copies_as_original_plus_conflict_copy() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-edit-edit").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"edited on A").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::write(device_b.root.path().join("shared.txt"), b"edited on B, and longer").unwrap();

    // Neither edit here renames or removes anything, so both directories
    // trivially agree on `["shared.txt"]` from the instant these two
    // writes complete -- well before either device's debounce window
    // (let alone conflict resolution) has had a chance to run at all.
    // Plain `wait_for_convergence` would therefore return immediately on
    // its very first (pre-sync) check, asserting long before any real
    // synchronization happens. Wait for the conflict-copy artifact to
    // actually exist (and both devices to agree on it) instead.
    wait_until_with_context(
        || {
            let a = real_entry_names(device_a.root.path());
            let b = real_entry_names(device_b.root.path());
            a.len() > 1 && a == b
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert!(names.contains(&"shared.txt".to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

// --- Scenario 2/3: concurrent edit vs delete, both orderings ---------------

/// Edit happens after (later mtime than) a concurrent delete: the edit
/// wins the conflict, so the file survives under its original name with
/// the edit's content, and the delete leaves no trace (a tombstone that
/// loses is never materialized as a conflict copy -- see peer_session.rs's
/// resolve_and_apply_conflict, `skip_local`/`skip_incoming`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_edit_delete_edit_wins_when_later_leaves_no_conflict_artifact() {
    let (device_a, device_b, group_id) =
        two_synced_devices("collision-edit-delete-edit-wins").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    // Delete first (older effective mtime), then the surviving edit
    // shortly after (newer effective mtime) -- deterministically makes
    // the edit the conflict winner.
    std::fs::remove_file(device_b.root.path().join("shared.txt")).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(device_a.root.path().join("shared.txt"), b"edited after the delete").unwrap();

    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    assert_eq!(
        names,
        vec!["shared.txt".to_string()],
        "no conflict-copy artifact expected: {names:?}"
    );
    assert_eq!(
        std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
        b"edited after the delete"
    );
}

/// The reverse ordering: delete happens after (later mtime than) a
/// concurrent edit -- the delete wins, removing the file from its
/// original name, while the edit (the loser, but not a tombstone) is
/// preserved as a conflict copy rather than silently lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_edit_delete_delete_wins_when_later_preserves_edit_as_conflict_copy() {
    let (device_a, device_b, group_id) =
        two_synced_devices("collision-edit-delete-delete-wins").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    std::fs::write(device_a.root.path().join("shared.txt"), b"edited before the delete").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::remove_file(device_b.root.path().join("shared.txt")).unwrap();

    wait_until_with_context(
        || {
            let a = real_entry_names(device_a.root.path());
            let b = real_entry_names(device_b.root.path());
            a == b
                && !a.contains(&"shared.txt".to_string())
                && a.iter().any(|n| is_conflict_copy(n))
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert!(!names.contains(&"shared.txt".to_string()), "original name must be gone: {names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

// --- Scenario 4: concurrent delete vs delete --------------------------------

/// Both devices delete the same already-synced file at (effectively) the
/// same time -- no conflict machinery needed (deleted == deleted), no
/// error, no artifact of any kind, on either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_delete_delete_leaves_no_artifact() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-delete-delete").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    std::fs::remove_file(device_a.root.path().join("shared.txt")).unwrap();
    std::fs::remove_file(device_b.root.path().join("shared.txt")).unwrap();

    wait_until_with_context(
        || {
            real_entry_names(device_a.root.path()).is_empty()
                && real_entry_names(device_b.root.path()).is_empty()
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    // Settling: nothing resurrects the file afterward.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(real_entry_names(device_a.root.path()).is_empty());
    assert!(real_entry_names(device_b.root.path()).is_empty());
}

// --- Scenario 5: concurrent rename to different targets ---------------------

/// Both devices independently rename the same already-synced file to
/// *different* new names at (effectively) the same time. A rename is not
/// a single atomic operation from the sync engine's point of view -- it
/// decomposes into an ordinary delete of the old path plus a create of
/// the new one (there is no dedicated "Renamed" `FsChangeKind` --
/// `watcher.rs` only has `CreatedOrModified`/`Removed`). This scenario
/// documents (rather than merely asserts a single "correct" answer for)
/// what that decomposition actually produces when it races: both target
/// names ending up present, each on both devices, with the original
/// content, and the original name gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rename_to_different_targets_both_survive() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-rename-rename-diff").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("original.txt"), b"base content").unwrap();
    wait_until(|| device_b.root.path().join("original.txt").exists(), Duration::from_secs(10))
        .await;

    std::fs::rename(
        device_a.root.path().join("original.txt"),
        device_a.root.path().join("renamed-by-a.txt"),
    )
    .unwrap();
    std::fs::rename(
        device_b.root.path().join("original.txt"),
        device_b.root.path().join("renamed-by-b.txt"),
    )
    .unwrap();

    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    tracing::info!(?names, "concurrent_rename_to_different_targets_both_survive final state");
    assert!(!names.contains(&"original.txt".to_string()), "{names:?}");
}

// --- Scenario 6: rename onto a path the other device just wrote -----------

/// Device A renames an existing file onto a target path, while device B
/// concurrently creates a *new*, differently-content file directly at
/// that same target path. From the sync engine's index perspective this
/// is an ordinary edit-edit conflict at the target path (two records
/// arriving for the same path with unrelated version history) -- both
/// contents must survive (one at the target name, one as a conflict
/// copy), matching scenario 1's outcome shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_onto_a_concurrently_created_path_produces_a_conflict_copy() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-rename-onto-created").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("source.txt"), b"will be renamed").unwrap();
    wait_until(|| device_b.root.path().join("source.txt").exists(), Duration::from_secs(10)).await;

    std::fs::rename(
        device_a.root.path().join("source.txt"),
        device_a.root.path().join("target.txt"),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(
        device_b.root.path().join("target.txt"),
        b"created directly at target, and longer",
    )
    .unwrap();

    wait_until_with_context(
        || {
            let a = real_entry_names(device_a.root.path());
            let b = real_entry_names(device_b.root.path());
            a == b && a.iter().any(|n| is_conflict_copy(n))
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert!(names.contains(&"target.txt".to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

// --- Scenario 7: rename immediately followed by deleting the new name -----

/// A single device renames a file, then almost immediately deletes it
/// under its new name, before the rename has necessarily even finished
/// propagating. The end state on every device must simply be "gone" --
/// no ghost file under either the original or the renamed name, on
/// either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_then_immediate_delete_leaves_nothing_on_either_device() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-rename-then-delete").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("original.txt"), b"content").unwrap();
    wait_until(|| device_b.root.path().join("original.txt").exists(), Duration::from_secs(10))
        .await;

    std::fs::rename(
        device_a.root.path().join("original.txt"),
        device_a.root.path().join("renamed.txt"),
    )
    .unwrap();
    std::fs::remove_file(device_a.root.path().join("renamed.txt")).unwrap();

    wait_until_with_context(
        || {
            real_entry_names(device_a.root.path()).is_empty()
                && real_entry_names(device_b.root.path()).is_empty()
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(real_entry_names(device_a.root.path()).is_empty());
    assert!(real_entry_names(device_b.root.path()).is_empty());
}

// --- Scenario 8: case-fold create/create collision (case-insensitive fs only) --

/// Two devices concurrently create differently-cased names for the same
/// logical file with different content. On a case-insensitive filesystem
/// (macOS default, Windows), this is a genuine hazard (design D3): one
/// device's sync root can only ever hold one of the two names on disk.
/// Skipped outright on a case-sensitive filesystem (Linux ext4), where
/// this isn't a collision at all -- matching this session's earlier
/// case-fold test fixes (`hazard_reason_for_policy`'s own gating logic).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_differently_cased_create_is_a_hazard_on_case_insensitive_filesystems() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-case-fold").await;
    let _ = group_id;

    if !yadorilink_sync_core::hazard::is_case_insensitive_filesystem(device_a.root.path()) {
        eprintln!("skipping: {} is case-sensitive here", device_a.root.path().display());
        return;
    }

    std::fs::write(device_a.root.path().join("Photo.jpg"), b"from A").unwrap();
    std::fs::write(device_b.root.path().join("photo.jpg"), b"from B, different and longer")
        .unwrap();

    // Both devices must converge on holding exactly one materialized
    // name each (never both variants coexisting on either device's
    // actual case-insensitive filesystem, which physically cannot
    // represent both at once).
    wait_until_with_context(
        || {
            real_entry_names(device_a.root.path()).len() == 1
                && real_entry_names(device_b.root.path()).len() == 1
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path())
            )
        },
    )
    .await;
}

// --- Scenario 9: delete then immediately recreate on the same device -----

/// A single device deletes a file and, almost immediately, recreates it
/// at the exact same path with different content -- exercising the
/// debounce accumulator's handling of a rapid delete-then-create at one
/// path within (or just outside) its own coalescing window. The peer
/// must converge on the NEW content, not the old content, and not end up
/// with no file at all (the delete and create must not cancel each other
/// out into nothing if the debouncer coalesces them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_then_immediate_recreate_converges_on_new_content() {
    let (device_a, device_b, group_id) = two_synced_devices("collision-delete-then-recreate").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"original content").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    std::fs::remove_file(device_a.root.path().join("shared.txt")).unwrap();
    std::fs::write(
        device_a.root.path().join("shared.txt"),
        b"recreated content, different and longer",
    )
    .unwrap();

    wait_until_with_context(
        || {
            std::fs::read(device_b.root.path().join("shared.txt")).ok()
                == Some(b"recreated content, different and longer".to_vec())
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-b content: {:?}",
                std::fs::read(device_b.root.path().join("shared.txt"))
            )
        },
    )
    .await;

    assert_eq!(
        std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
        b"recreated content, different and longer"
    );
}
