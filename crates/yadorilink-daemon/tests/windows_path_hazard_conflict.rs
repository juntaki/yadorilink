//! Two-device races around Windows-specific path-naming hazards, run
//! through the real full daemon stack — complementary to
//! `yadorilink-sync-core/src/hazard.rs`'s pure unit tests (`RESERVED_
//! BASENAMES`, `invalid_name_reason`, `NamePolicy`), which only prove the
//! hazard-detection *logic* in isolation against a bare `SyncState` +
//! tempdir. This file instead exercises what actually happens end-to-end
//! when two real devices race to create a hazardous name, going through
//! the genuine peer-session reconcile/materialize/conflict path.
//!
//! Ground truth for every assertion below, read directly out of
//! `peer_session.rs` before writing this file (not guessed):
//!
//! - `PeerSyncSession::hazard_reason_for` always evaluates
//!   `hazard::NamePolicy::local` — i.e. gated on *this device's own*
//!   real host platform, never on any wire-carried "I am Windows" flag.
//!   Since both simulated devices in this file's tests share one OS
//!   process, that means either *both* devices apply the Windows rules or
//!   *neither* does — there is no way, within one test run, to have one
//!   simulated device be "the Windows one." `cfg!(windows)` therefore
//!   branches per test-run, not per device.
//! - The hazard check only ever runs inside `materialize`/`hydrate_file`
//!   — i.e. only when a device is about to write a *record* (its own or a
//!   peer's) to disk. A file a device created itself via a direct
//!   `std::fs::write` (discovered by `local_change.rs`'s scan/watch, not
//!   routed through `materialize` at all — confirmed by grep: no
//!   `hazard`/`held` reference anywhere in `local_change.rs`) is *never*
//!   hazard-checked against its own device's policy; it simply sits on
//!   disk. The hazard only ever bites the *other* device, when it
//!   receives that record over the wire and tries to materialize it
//!   locally.
//! - `hold_record` (`peer_session.rs`) never renames and never writes
//!   under any alternate name — a held record only gets a
//!   `SyncState::upsert_file`/`set_held` pair; `SyncState::get_held_state`
//!   is the direct, non-flaky way to observe that from a test, rather
//!   than inferring "held" from a timing-sensitive absence-of-file check.
//! - For a genuine same-path create/create race (scenario 1 below), both
//!   devices run `resolve_and_apply_conflict`, which calls `materialize`
//!   for *both* the winning path (the original name) and the losing path
//!   (`conflict::conflict_copy_path`'s `"<stem> (conflicted copy, <ts>,
//!  <device>).<ext>"` shape) — on both devices, since materializing the
//!   locally-already-present side is not skipped just because it's
//!   "already right" (its final path may have changed to the conflict-
//!   copy name). Critically, `windows_invalid_name_detail`'s reserved-
//!   basename check compares the stem *before the first `.`* for an exact
//!   match — `"CON (conflicted copy,..., device-b)"` is not `"CON"`, so
//!   the conflict-copy variant is never itself reserved even when the
//!   original bare name is. That makes the Windows-specific outcome for
//!   scenario 1 a verified prediction, not a guess: the original name is
//!   held (never on disk, on either device), while the conflict-copy name
//!   materializes normally.

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

// --- Shared two-device harness (duplicated from collision_matrix.rs, matching
// this codebase's convention of self-contained daemon integration test
// binaries rather than sharing across `tests/*.rs`) ---------------------------

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
    // Give the device a change-signing key before its link watch starts (see
    // `start_watching`), so the change-DAG emitter is wired from the first edit
    // and local changes actually propagate — a key set afterward would leave
    // emission off and nothing would sync.
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

async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "windows-path-hazard-group").await;
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

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

/// A directory's real (non-artifact) entries as a name→content map — plain
/// text content (not a hash) so a failure's assertion message stays directly
/// readable. Used for convergence waits so equality means both devices agree
/// on names *and* the bytes under each name, not merely on the name set — a
/// bare name-set-equality wait is satisfied the instant two devices happen to
/// list the same filenames, which can be true transiently before content has
/// actually propagated and been materialized under those names.
fn snapshot(dir: &std::path::Path) -> std::collections::HashMap<String, String> {
    real_entry_names(dir)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(dir.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

/// A capability probe for a candidate filename this test wants to create on
/// the *current* host filesystem — some of the names below (a literal `:`,
/// trailing space/dot) are only guaranteed valid on POSIX filesystems, and
/// even there a given mount could reject or silently normalize them. Rather
/// than let `std::fs::write` panic the test for a reason that has nothing to
/// do with the sync engine, probe first in a scratch tempdir, and skip
/// (mirroring `collision_matrix.rs`'s `is_case_insensitive_filesystem`-gated
/// case-fold test) if this host can't literally represent the name.
fn host_supports_literal_filename(name: &str) -> bool {
    let probe_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let path = probe_dir.path().join(name);
    if std::fs::write(&path, b"probe").is_err() {
        return false;
    }
    // Confirm the name round-trips exactly rather than being silently
    // normalized (e.g. a trailing dot/space stripped at write time) by some
    // filesystem or OS layer unrelated to this crate's own hazard logic.
    let preserved = real_entry_names(probe_dir.path()).contains(&name.to_string());
    let _ = std::fs::remove_file(&path);
    preserved
}

// --- Scenario 1: concurrent create of a Windows-reserved device basename ----

/// Both devices concurrently create a file named `CON.txt` — a Windows-
/// reserved device basename (`hazard.rs`'s `RESERVED_BASENAMES`) — with
/// different content, racing exactly like `collision_matrix.rs` scenario 1's
/// ordinary edit-edit conflict, except at a name that is only ordinary on
/// some platforms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_of_a_windows_reserved_basename() {
    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-reserved-basename").await;

    std::fs::write(device_a.root.path().join("CON.txt"), b"from A").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::write(device_b.root.path().join("CON.txt"), b"from B, different and longer").unwrap();

    if cfg!(windows) {
        // Verified from peer_session.rs (see this file's header comment):
        // the winning side's path is still literally "CON.txt", which
        // `hazard_reason_for` holds on *both* devices (each applies its own
        // NamePolicy::local when materializing the record assigned to
        // that path) — so it must never appear as a real on-disk entry on
        // either device, while the conflict-copy side (a different stem)
        // must materialize normally on both.
        wait_until_with_context(
            || {
                device_a.state.sync_state.get_held_state(&group_id, "CON.txt").unwrap().is_some()
                    && device_b
                        .state
                        .sync_state
                        .get_held_state(&group_id, "CON.txt")
                        .unwrap()
                        .is_some()
            },
            Duration::from_secs(20),
            || "expected \"CON.txt\" to end up held on both devices under a Windows policy".into(),
        )
        .await;

        // Full name→content convergence (not a bare name-set equality): both
        // devices must agree on the conflict-copy artifact's bytes, not just
        // that both happen to list a conflict-copy name.
        wait_until_with_context(
            || {
                let a = snapshot(device_a.root.path());
                let b = snapshot(device_b.root.path());
                a == b && a.keys().any(|n| is_conflict_copy(n))
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
        assert!(
            !names.contains(&"CON.txt".to_string()),
            "held name must never reach disk: {names:?}"
        );
        assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
    } else {
        // Not reserved on the current (non-Windows) host platform:
        // NamePolicy::local is Posix, so `invalid_name_reason` always
        // returns None here (hazard.rs's own
        // `posix_policy_never_holds_anything_windows_would_reject` unit
        // test already pins that down) — this degenerates to an ordinary
        // create/create conflict, same shape as collision_matrix.rs
        // scenario 1.
        //
        // Deliberately not plain `wait_for_convergence`: both devices
        // trivially agree on `["CON.txt"]` the instant the two
        // `std::fs::write` calls complete — before either device's
        // debounce window, let alone real conflict resolution, has run at
        // all — so a bare name-set-equality wait returns immediately and
        // this assertion would then race real synchronization instead of
        // waiting for it (the exact premature-convergence trap
        // `collision_matrix.rs`'s `concurrent_edit_edit_keeps_both_copies_
        // as_original_plus_conflict_copy` documents and works around).
        // Wait for the conflict-copy artifact to actually exist AND for
        // both devices to agree on every file's *content* (a name→content
        // snapshot), so this can't pass on a transient name-set match
        // before content has propagated under each name.
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
        assert!(names.contains(&"CON.txt".to_string()), "{names:?}");
        assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
    }
}

// --- Scenario 2: concurrent create of trailing-dot vs. trailing-space names -

/// One device creates `notes.txt.` (trailing dot), the other creates
/// `notes.txt ` (trailing space) — two hazardous name variants on Windows,
/// but two ordinary and completely distinct filenames on the current host
/// whenever it isn't Windows. Since the two strings are literally different,
/// `hazard::case_fold_collision` (which only ever compares same-directory
/// siblings that fold to the same lowercase name) never even considers them
/// related to one another — this is not a collision at any layer except
/// each name's own individual Windows-invalid-name check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_with_trailing_dot_or_space() {
    if !host_supports_literal_filename("probe.txt.")
        || !host_supports_literal_filename("probe.txt ")
    {
        eprintln!(
            "skipping: this host filesystem can't literally represent a trailing-dot or \
             trailing-space filename"
        );
        return;
    }

    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-trailing-dot-space").await;

    std::fs::write(device_a.root.path().join("notes.txt."), b"trailing dot from A").unwrap();
    std::fs::write(device_b.root.path().join("notes.txt "), b"trailing space from B").unwrap();

    if cfg!(windows) {
        // Two unrelated, non-colliding paths -- each is hazard-checked only
        // by the *receiving* device (see header comment: a device's own
        // locally-authored file never goes through `materialize` at all).
        // So device-b must hold A's "notes.txt." (never write it under
        // that name), and device-a must hold B's "notes.txt " -- while
        // each device's own locally-created file is untouched on its own
        // disk, since local_change.rs never hazard-checks a device's own
        // already-on-disk file.
        wait_until_with_context(
            || {
                device_b.state.sync_state.get_held_state(&group_id, "notes.txt.").unwrap().is_some()
                    && device_a
                        .state
                        .sync_state
                        .get_held_state(&group_id, "notes.txt ")
                        .unwrap()
                        .is_some()
            },
            Duration::from_secs(20),
            || "expected device-b to hold A's trailing-dot name and device-a to hold B's trailing-space name".into(),
        )
        .await;

        let a_names = real_entry_names(device_a.root.path());
        let b_names = real_entry_names(device_b.root.path());
        assert!(a_names.contains(&"notes.txt.".to_string()), "{a_names:?}");
        assert!(
            !a_names.contains(&"notes.txt ".to_string()),
            "held, must not reach disk: {a_names:?}"
        );
        assert!(b_names.contains(&"notes.txt ".to_string()), "{b_names:?}");
        assert!(
            !b_names.contains(&"notes.txt.".to_string()),
            "held, must not reach disk: {b_names:?}"
        );
    } else {
        // Ordinary, non-hazardous, non-colliding filenames here: both must
        // simply coexist as two distinct real files on both devices once
        // sync converges -- never a conflict of any kind. Wait on a full
        // name→content snapshot so this holds only once each device has
        // actually materialized the peer's file (with its bytes), not the
        // instant both filenames merely appear in the listing.
        wait_until_with_context(
            || {
                let a = snapshot(device_a.root.path());
                let b = snapshot(device_b.root.path());
                a == b && a.contains_key("notes.txt.") && a.contains_key("notes.txt ")
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
        assert_eq!(
            names.iter().filter(|n| is_conflict_copy(n)).count(),
            0,
            "two literally-distinct names must never produce a conflict copy: {names:?}"
        );
    }
}

// --- Scenario 3: concurrent create with Windows-illegal characters ---------

/// Both devices create files whose names contain characters illegal on
/// Windows (`<>:"|?*`) at two distinct, non-colliding names. Same shape as
/// scenario 2 (two independent hazardous-elsewhere names, not a collision
/// with each other) but exercising the forbidden-character branch of
/// `windows_invalid_name_detail` rather than the trailing-dot/space branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_with_illegal_windows_characters() {
    let name_a = "report:v2.txt";
    let name_b = "report<final>.txt";
    if !host_supports_literal_filename(name_a) || !host_supports_literal_filename(name_b) {
        eprintln!(
            "skipping: this host filesystem can't literally represent a filename containing \
             one of Windows' forbidden characters"
        );
        return;
    }

    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-illegal-characters").await;

    std::fs::write(device_a.root.path().join(name_a), b"colon name from A").unwrap();
    std::fs::write(device_b.root.path().join(name_b), b"angle bracket name from B").unwrap();

    if cfg!(windows) {
        // Same asymmetric held-on-the-receiver-only shape as scenario 2:
        // each device's own locally-authored illegal-character file stays
        // untouched on its own disk (never hazard-checked, matching header
        // comment), while the *other* device holds it on receipt and never
        // writes it under that name.
        wait_until_with_context(
            || {
                device_b.state.sync_state.get_held_state(&group_id, name_a).unwrap().is_some()
                    && device_a
                        .state
                        .sync_state
                        .get_held_state(&group_id, name_b)
                        .unwrap()
                        .is_some()
            },
            Duration::from_secs(20),
            || format!("expected device-b to hold {name_a:?} and device-a to hold {name_b:?}"),
        )
        .await;

        let a_names = real_entry_names(device_a.root.path());
        let b_names = real_entry_names(device_b.root.path());
        assert!(a_names.contains(&name_a.to_string()), "{a_names:?}");
        assert!(!a_names.contains(&name_b.to_string()), "held, must not reach disk: {a_names:?}");
        assert!(b_names.contains(&name_b.to_string()), "{b_names:?}");
        assert!(!b_names.contains(&name_a.to_string()), "held, must not reach disk: {b_names:?}");
    } else {
        // Neither name is hazardous under a Posix policy -- both must
        // propagate end to end and converge on both devices, since the
        // hazard logic exists to protect a Windows peer even when this
        // particular test happens to run on a non-Windows one. Wait on a
        // full name→content snapshot so convergence means both devices hold
        // both files with their correct bytes, not just matching names.
        wait_until_with_context(
            || {
                let a = snapshot(device_a.root.path());
                let b = snapshot(device_b.root.path());
                a == b && a.contains_key(name_a) && a.contains_key(name_b)
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

        assert_eq!(std::fs::read(device_b.root.path().join(name_a)).unwrap(), b"colon name from A");
        assert_eq!(
            std::fs::read(device_a.root.path().join(name_b)).unwrap(),
            b"angle bracket name from B"
        );
    }
}

// --- Scenario 4: a full path near Windows' traditional MAX_PATH (260) ------

/// Builds a relative path (nested directories plus a filename) long enough
/// that the *full* path -- including the temp sync root -- comfortably
/// exceeds Windows' traditional 260-character `MAX_PATH` (without
/// `\\?\`-prefix long-path support). Both devices create it concurrently
/// with different content, same shape as `collision_matrix.rs` scenario 1,
/// checked directly at the deep path rather than via a root-level directory
/// listing (`real_entry_names` only lists one directory's immediate
/// entries).
///
/// This specifically needs re-verification on the real Windows test machine
/// from manual Windows VM testing: `MAX_PATH` is an OS/Win32-API-level
/// constraint that has nothing to do with this crate's own `hazard.rs`
/// logic, so nothing read while writing this file rules out a real failure
/// there (e.g. `CreateFileW` rejecting the path outright, or requiring the
/// `\\?\` long-path prefix this codebase's materialization writes don't
/// appear to add). On the current platform this is expected to simply work,
/// since Linux/macOS impose no such component-count-independent path-length
/// ceiling in the range this test builds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_path_near_windows_max_path_length() {
    const MIN_TOTAL_LEN: usize = 300; // comfortably over the 260 MAX_PATH threshold
    const SEGMENT: &str = "a-fairly-long-directory-name-segment-used-only-to-pad-the-full-path";

    let rel_dir = deeply_nested_relative_dir(SEGMENT, MIN_TOTAL_LEN);
    let file_name = "deep-file-near-the-windows-max-path-length-threshold.txt";

    let (device_a, device_b, group_id) = two_synced_devices("windows-hazard-long-path").await;
    let _ = &group_id;

    let dir_a = device_a.root.path().join(&rel_dir);
    let dir_b = device_b.root.path().join(&rel_dir);
    let full_len_a = dir_a.join(file_name).to_string_lossy().len();
    assert!(full_len_a > 260, "test setup bug: path isn't actually long ({full_len_a} chars)");

    if std::fs::create_dir_all(&dir_a).is_err() || std::fs::create_dir_all(&dir_b).is_err() {
        eprintln!(
            "skipping: this host filesystem/path-length limit rejected a {full_len_a}-char path \
             during test setup, unrelated to the sync engine itself"
        );
        return;
    }

    std::fs::write(dir_a.join(file_name), b"from A, deep path").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::write(dir_b.join(file_name), b"from B, deep path, different and longer").unwrap();

    // Full name→content convergence at the deep directory: both devices must
    // agree on the bytes under every entry (including the conflict copy), not
    // merely on the name set, which can match transiently before content has
    // been materialized under the winning/conflict-copy names.
    wait_until_with_context(
        || {
            let a = snapshot(&dir_a);
            let b = snapshot(&dir_b);
            a == b && a.keys().any(|n| is_conflict_copy(n))
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a deep dir={:?} device-b deep dir={:?}",
                real_entry_names(&dir_a),
                real_entry_names(&dir_b)
            )
        },
    )
    .await;

    let names = real_entry_names(&dir_a);
    assert!(names.contains(&file_name.to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

/// Nests copies of `segment` under one another until the *relative* path
/// (not yet joined to any sync root) alone would push a `root.join(rel).
/// join(file)` well past `min_total_len` even for a short temp-root prefix
/// -- deliberately generous rather than computed against either device's
/// actual root length, so the same nesting applies identically to both
/// devices' sync roots regardless of their exact (similar, but not
/// guaranteed byte-identical) tempdir path lengths.
fn deeply_nested_relative_dir(segment: &str, min_total_len: usize) -> std::path::PathBuf {
    let mut rel = std::path::PathBuf::new();
    while rel.as_os_str().len() < min_total_len {
        rel.push(segment);
    }
    rel
}
