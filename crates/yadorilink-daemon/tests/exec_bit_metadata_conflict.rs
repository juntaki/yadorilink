//! Deterministic two-device collision scenarios for a dimension the broader
//! collision-matrix coverage doesn't touch: the Unix owner-executable bit and
//! metadata-only (no content change) touches, as distinct from ordinary
//! content-edit conflicts. Same full-daemon-stack, hand-picked-scenario
//! convention as the rest of this suite.
//!
//! `TestDevice`/`setup_device`/`start_watching`/`two_synced_devices` are
//! self-contained here rather than shared, matching this codebase's existing
//! convention of self-contained daemon integration test binaries.
//!
//! **Load-bearing context this file's assertions were written against**
//! (see `yadorilink-sync-core::types::owner_exec_bit_from_metadata`'s doc
//! comment, and `chunker::apply_exec_bit`/`peer_session`'s
//! `try_apply_metadata_only_update`/`apply_incoming_wire_metadata`):
//! `owner_exec_bit_from_metadata` — the capture-side primitive that reads a
//! locally-observed file's real owner-exec bit off its `std::fs::Metadata`
//! — is now wired into `LocalChangeProcessor`'s record-building path: the
//! size+mtime fast path compares the on-disk owner-exec bit against the
//! indexed one and advances the file's version when they differ, so a real
//! `chmod` on a synced file is captured, broadcast, and reconciled like any
//! other change. The wire schema (`proto::FileInfo::exec_bit`) and the
//! materialization-side apply (`apply_exec_bit`, `SyncState::get_exec_bit`/
//! `set_exec_bit`) exist and are exercised end to end. The scenarios below
//! assert against that wired behavior: a brand-new executable file
//! propagates its exec bit to peers (scenario 4); an exec-bit-only chmod
//! advances the version, so toggling it while a peer concurrently edits
//! content is a genuine two-version conflict that surfaces a conflict copy
//! (scenario 1); opposite exec-bit-only chmods with identical content still
//! converge to an agreed exec-bit state on both devices (scenario 2); and a
//! no-op identical-bytes touch still never produces a version-bumping
//! record, so it cannot race a real edit (scenario 3).

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_sync_state, real_entry_names, wait_until, wait_until_with_context, TestAccount,
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
    // change-DAG emitter is wired and local edits actually propagate.
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

/// Sets up two devices, both syncing a fresh folder group, and waits for
/// peer sessions to establish. Every scenario below starts from this.
async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "exec-bit-metadata-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_watching(&device_a, &group_id).await;
    start_watching(&device_b, &group_id).await;

    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    (device_a, device_b, group_id)
}

/// A device's real (non-artifact) entries, keyed by name, valued by content —
/// plain content (not a hash) so a failure's assertion message is directly
/// readable. Used as the convergence signal for the exec-bit conflict scenario,
/// where a bare file-name-set match is satisfied before the conflict's content
/// actually propagates. Only exercised by the `#[cfg(unix)]` exec-bit conflict
/// scenario, so it is unused on non-unix builds.
#[allow(dead_code)]
fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
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

/// A conflict-copy artifact carries the `conflicted copy` marker in its name
/// (see `yadorilink-sync-core::conflict`). Only exercised by the exec-bit
/// conflict scenario below, which is itself `#[cfg(unix)]`.
#[cfg(unix)]
fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

// --- Scenario 1: concurrent exec-bit toggle vs. content edit --------------

/// Device A flips an already-synced file's exec bit to true (chmod only,
/// no content change) while device B concurrently edits the file's
/// content (content only, no permission change), with a small stagger for
/// deterministic ordering.
///
/// Per this file's header: A's exec-bit-only chmod is now captured by
/// `local_change.rs`'s record-building path and advances A's local index
/// version. So A's permission change and B's content edit are two
/// independent version-bumping changes to the same file — a genuine
/// concurrent conflict. B's edit is the later write, so it wins the
/// `shared.txt` name on both devices while A's losing side is preserved as
/// exactly one conflict copy. The exec bit is asserted as
/// agreement-between-devices rather than a fixed value, since both devices
/// materialize the same winning version — a divergence there would be a
/// real candidate bug this assertion is positioned to catch.
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

        // A's chmod and B's content edit both advance their own versions, so
        // this is a genuine concurrent conflict whose conflict-copy artifact
        // takes real synchronization to appear. Both directories already agree
        // on `["shared.txt"]` from the instant the two writes land -- well
        // before conflict resolution runs -- and even a two-entry name-set
        // match (original + conflict copy) can appear on both sides before the
        // conflict's *content* has actually propagated. Wait for a full
        // name->content snapshot match with more than one entry, so this can't
        // pass until both devices genuinely hold the same resolved bytes.
        wait_until_with_context(
            || {
                let a = snapshot(device_a.root.path());
                let b = snapshot(device_b.root.path());
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
        assert_eq!(
            names.iter().filter(|n| is_conflict_copy(n)).count(),
            1,
            "A's exec-bit-only chmod now advances A's version vector, so it and \
             B's concurrent content edit are a genuine conflict that must surface \
             exactly one conflict copy: {names:?}"
        );
        // DAG conflict resolution deliberately ignores wall-clock ordering and
        // chooses the canonical name by (lamport, change hash). Which content
        // owns `shared.txt` is therefore not an mtime contract; the durability
        // contract is that both replicas make the same choice and preserve
        // both the base+chmod version and B's edited bytes.
        let final_snapshot = snapshot(device_a.root.path());
        let mut contents: Vec<_> = final_snapshot.values().cloned().collect();
        contents.sort();
        assert_eq!(
            contents,
            vec!["base".to_string(), "edited on B, exec bit untouched".to_string()]
        );

        let exec_a = is_executable(&device_a.root.path().join("shared.txt"));
        let exec_b = is_executable(&device_b.root.path().join("shared.txt"));
        assert_eq!(
            exec_a, exec_b,
            "both devices must agree on shared.txt's final exec-bit state after \
             convergence (device-a={exec_a} device-b={exec_b})"
        );
    }
}

// --- Scenario 2: pure metadata conflict, opposite exec-bit values ----------

/// Both devices toggle the SAME already-synced file's exec bit to
/// opposite values (A: true, B: false) with no content change at all on
/// either side — a pure metadata conflict with no content divergence.
///
/// This is the highest-value case in this file: both sides change only the
/// exec bit, with byte-identical content on both. Exec-bit capture is now
/// wired, so a chmod is a real observed change rather than a no-op; the
/// direct equality assertion below pins down that the two devices converge
/// to the *same* final exec-bit state rather than silently diverging (A
/// executable, B non-executable) with no error, no hang, and no conflict
/// artifact to signal it. It is intentionally not softened to
/// convergence-only: an unnoticed permission divergence between devices is
/// the real regression worth pinning down here, not a limitation of this
/// test.
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

    // A's byte-identical rewrite never produces a version-bumping record, so
    // only B's edit propagates -- but both directories trivially agree on
    // `["shared.txt"]` from the instant the writes land, before that edit
    // reaches A. Wait for A to actually receive B's new content rather than a
    // bare name match.
    wait_until_with_context(
        || {
            std::fs::read(device_a.root.path().join("shared.txt")).ok()
                == Some(b"a genuine content edit from B".to_vec())
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a entries={:?} content={:?}",
                real_entry_names(device_a.root.path()),
                std::fs::read(device_a.root.path().join("shared.txt")).ok()
            )
        },
    )
    .await;

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
/// Per this file's header, `owner_exec_bit_from_metadata` is now wired into
/// `local_change.rs`'s record-building path, so device A's brand-new
/// executable file is captured with its owner-exec bit set and device B
/// should receive an executable copy, not just the same content. This
/// assertion is intentionally left as a direct, unsoftened equality check
/// rather than convergence-only: this scenario is the canary that exec-bit
/// propagation works at all, so a failure here is a real regression, not a
/// flaky or ambiguous test.
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
