//! Deterministic two-device collision scenarios for a dimension
//! `collision_matrix.rs` doesn't touch: the Unix owner-executable bit and
//! metadata-only (no content change) touches, as distinct from ordinary
//! content-edit conflicts. Same full-daemon-stack, hand-picked-scenario
//! convention as `collision_matrix.rs` — see that file's header for the
//! rationale this one inherits wholesale.
//!
//! `TestDevice`/`setup_device`/`start_syncing`/`two_synced_devices` are
//! duplicated from `collision_matrix.rs` rather than shared, matching this
//! codebase's existing convention of self-contained daemon integration
//! test binaries.
//!
//! **Load-bearing context this file's assertions were written against**
//! (see `yadorilink-sync-core::types::owner_exec_bit_from_metadata`'s doc
//! comment, and `chunker::apply_exec_bit`/`peer_session`'s
//! `try_apply_metadata_only_update`/`apply_incoming_wire_metadata`):
//! `owner_exec_bit_from_metadata` — the capture-side primitive that would
//! read a locally-observed file's real owner-exec bit off its
//! `std::fs::Metadata` — is not called anywhere from
//! `LocalChangeProcessor::scan_existing_files` or its watcher-event path
//! today. The wire schema (`proto::FileInfo::exec_bit`) and the
//! materialization-side apply (`apply_exec_bit`, `SyncState::get_exec_bit`/
//! `set_exec_bit`) all exist and are exercised elsewhere (e.g.
//! `peer_session.rs`'s own unit tests seed `set_exec_bit` directly), but
//! nothing on the local-capture side ever calls `set_exec_bit` for a real
//! chmod a user performs on their own synced folder — so a local exec-bit
//! change is invisible to the sync engine end to end, and any subsequent
//! materialization of that same path (from an unrelated peer edit) can
//! silently reset it back to whatever `get_exec_bit` already had on
//! record (typically `false`, the column default). Scenarios below assert
//! accordingly: convergence/no-crash and *agreement* between devices
//! where the "correct" value is genuinely ambiguous, and a direct
//! same-exec-bit assertion only where the brand-new-file baseline case
//! makes the expected behavior unambiguous (and is expected, per the gap
//! above, to fail until that capture-side wiring lands).

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
    let group_id = support::create_folder_group(&account, "exec-bit-metadata-group").await;
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

/// Reads back the real owner-exec bit a materialized file carries on
/// disk — the same bit `chunker::apply_exec_bit` sets/clears and
/// `types::owner_exec_bit_from_metadata` would (if wired) capture.
/// Unix-only: intentionally not given a non-unix stub, since every call
/// site is itself behind a `#[cfg(unix)]` block.
#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o100 != 0).unwrap_or(false)
}

// --- Scenario 1: concurrent exec-bit toggle vs. content edit --------------

/// Device A flips an already-synced file's exec bit to true (chmod only,
/// no content change) while device B concurrently edits the file's
/// content (content only, no permission change), with a small stagger for
/// deterministic ordering.
///
/// Per this file's header: A's chmod is invisible to `local_change.rs`'s
/// watcher pipeline today (no capture-side call to
/// `owner_exec_bit_from_metadata`), so A's local index version never
/// advances — from the sync engine's point of view only B produced a
/// real change. That makes this a plain fast-forward update, not a
/// genuine two-version conflict: no conflict-copy artifact is expected,
/// and B's content should simply win outright on both devices. The exec
/// bit is asserted as agreement-between-devices rather than a fixed
/// value, since re-materializing B's update onto A's file may reset
/// whatever A's chmod left behind — that reset is itself a real
/// candidate bug this assertion is positioned to catch if it ever
/// diverges between devices instead of resetting identically on both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_exec_bit_toggle_true_vs_content_edit() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping concurrent_exec_bit_toggle_true_vs_content_edit: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) =
            two_synced_devices("exec-bit-toggle-vs-content-edit").await;
        let _ = group_id;

        std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
        wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10))
            .await;

        // A: exec bit only, no content change.
        std::fs::set_permissions(
            device_a.root.path().join("shared.txt"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
                                                             // B: content only, no permission change.
        std::fs::write(device_b.root.path().join("shared.txt"), b"edited on B, exec bit untouched")
            .unwrap();

        wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

        let names = real_entry_names(device_a.root.path());
        assert_eq!(
            names,
            vec!["shared.txt".to_string()],
            "an exec-bit-only local change must never advance the version vector, so this must \
             not surface as a genuine conflict (no conflict-copy artifact expected): {names:?}"
        );
        assert_eq!(
            std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
            b"edited on B, exec bit untouched"
        );
        assert_eq!(
            std::fs::read(device_b.root.path().join("shared.txt")).unwrap(),
            b"edited on B, exec bit untouched"
        );

        let exec_a = is_executable(&device_a.root.path().join("shared.txt"));
        let exec_b = is_executable(&device_b.root.path().join("shared.txt"));
        assert_eq!(
            exec_a, exec_b,
            "both devices must agree on the same final exec-bit state after convergence, \
             whatever that state is (device-a={exec_a} device-b={exec_b})"
        );
    }
}

// --- Scenario 2: pure metadata conflict, opposite exec-bit values ----------

/// Both devices toggle the SAME already-synced file's exec bit to
/// opposite values (A: true, B: false) with no content change at all on
/// either side — a pure metadata conflict with no content divergence.
///
/// This is the highest-value new case in this file: per this file's
/// header, an exec-bit-only chmod on either device is invisible to
/// `local_change.rs`'s watcher pipeline (neither the size nor the mtime
/// changes, so `build_record_for_created_or_modified`'s own size+mtime
/// fast path returns `None` before any chunking happens), meaning
/// *neither* side's change is ever detected, broadcast, or reconciled at
/// all. The expected-if-this-gap-is-real outcome is that the two devices
/// silently diverge (A stays executable, B stays non-executable) with no
/// error, no hang, and no visible sign of disagreement — which is exactly
/// what the direct equality assertion below is positioned to catch. This
/// assertion is intentionally not softened to convergence-only: an
/// unnoticed permission divergence between devices, with no crash and no
/// conflict artifact to signal it, is the real behavior worth pinning
/// down here, not a limitation of this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_exec_bit_true_vs_false_no_content_change() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping concurrent_exec_bit_true_vs_false_no_content_change: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) =
            two_synced_devices("exec-bit-true-vs-false-no-content").await;
        let _ = group_id;

        std::fs::write(device_a.root.path().join("shared.txt"), b"base content, never edited")
            .unwrap();
        wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10))
            .await;

        // Both devices touch only permissions, at (effectively) the same
        // time, to opposite values.
        std::fs::set_permissions(
            device_a.root.path().join("shared.txt"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(
            device_b.root.path().join("shared.txt"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        // No FileRecord-level event is expected to fire at all for either
        // side, so there's nothing to "wait for convergence" on beyond a
        // fixed settle window: confirm the daemon doesn't crash or hang,
        // then inspect the actual end state.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let names = real_entry_names(device_a.root.path());
        assert_eq!(names, vec!["shared.txt".to_string()], "{names:?}");
        assert_eq!(
            std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
            b"base content, never edited"
        );
        assert_eq!(
            std::fs::read(device_b.root.path().join("shared.txt")).unwrap(),
            b"base content, never edited"
        );

        let exec_a = is_executable(&device_a.root.path().join("shared.txt"));
        let exec_b = is_executable(&device_b.root.path().join("shared.txt"));
        assert_eq!(
            exec_a, exec_b,
            "a pure exec-bit-only conflict (no content divergence at all) must still converge \
             to an identical final exec-bit state on both devices, not silently diverge with no \
             error and no conflict artifact: device-a={exec_a} device-b={exec_b}"
        );
    }
}

// --- Scenario 3: metadata-only touch racing a genuine content edit --------

/// Device A "touches" an already-synced file — rewrites the exact same
/// bytes, which bumps the real mtime with no actual content change —
/// concurrently with device B performing a genuine content edit.
///
/// Unlike the exec-bit scenarios above, this one needs no
/// platform-specific permission bit at all, so it runs unconditionally:
/// `build_record_for_created_or_modified`'s content-hash self-echo
/// suppression (comparing freshly-chunked blocks against what's already
/// indexed) means A's rewrite never produces a version-bumping
/// `FileRecord` regardless of the mtime bump, so it must not be able to
/// race against — let alone beat — B's real edit. The expected outcome is
/// unambiguous: B's edit simply wins, with no spurious conflict-copy
/// artifact generated against A's no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_only_touch_race_with_real_content_edit() {
    let (device_a, device_b, group_id) = two_synced_devices("exec-bit-touch-vs-real-edit").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"original content").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    // A: rewrite byte-identical content -- bumps mtime, changes nothing
    // real. B: a genuine content edit, shortly after.
    std::fs::write(device_a.root.path().join("shared.txt"), b"original content").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(device_b.root.path().join("shared.txt"), b"a genuine content edit from B")
        .unwrap();

    wait_for_convergence(&device_a, &device_b, Duration::from_secs(20)).await;

    let names = real_entry_names(device_a.root.path());
    assert_eq!(
        names,
        vec!["shared.txt".to_string()],
        "a no-op touch (identical bytes rewritten) must never generate a conflict-copy artifact \
         against a concurrent real edit: {names:?}"
    );
    assert_eq!(
        std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
        b"a genuine content edit from B"
    );
    assert_eq!(
        std::fs::read(device_b.root.path().join("shared.txt")).unwrap(),
        b"a genuine content edit from B"
    );
}

// --- Scenario 4: baseline sanity -- new executable file propagation -------

/// Not a conflict: the simplest possible sanity case, establishing
/// whether this harness surfaces exec-bit propagation behavior at all
/// before the conflict scenarios above are trusted. Device A creates a
/// brand-new executable file (mode 0o755) with content; device B should
/// receive it with the SAME owner-exec bit set, not just the same
/// content.
///
/// Per this file's header, `owner_exec_bit_from_metadata` is never called
/// from `local_change.rs`'s record-building path today, so this device-A
/// creation is expected to be captured as an ordinary (non-executable, as
/// far as the sync engine knows) file, and device B is expected to
/// receive a non-executable copy despite A's own file being executable.
/// This assertion is intentionally left as a direct, unsoftened equality
/// check rather than convergence-only: this scenario exists specifically
/// to canary whether exec-bit propagation works at all, and a failure
/// here is the expected, correct signal of that real gap, not a flaky or
/// ambiguous test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exec_bit_set_on_brand_new_file_propagates_to_peer() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping exec_bit_set_on_brand_new_file_propagates_to_peer: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) = two_synced_devices("exec-bit-new-file-baseline").await;
        let _ = group_id;

        let path_a = device_a.root.path().join("script.sh");
        std::fs::write(&path_a, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&path_a, std::fs::Permissions::from_mode(0o755)).unwrap();

        wait_until_with_context(
            || {
                std::fs::read(device_b.root.path().join("script.sh")).ok()
                    == Some(b"#!/bin/sh\necho hi\n".to_vec())
            },
            Duration::from_secs(10),
            || format!("device-b entries: {:?}", real_entry_names(device_b.root.path())),
        )
        .await;

        assert!(
            is_executable(&path_a),
            "sanity: device-a's own file must still be executable after its own chmod"
        );
        assert!(
            is_executable(&device_b.root.path().join("script.sh")),
            "device-b must receive the SAME owner-exec bit device-a set on a brand-new file, \
             not just the same content"
        );
    }
}
