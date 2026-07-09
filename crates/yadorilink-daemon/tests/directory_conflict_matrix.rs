//! A two-device matrix of DIRECTORY-level collision scenarios, run
//! through the real full daemon stack (real coordination server, real
//! relay, real peer sessions) -- complementary to `collision_matrix.rs`
//! (whose scenarios all collide on a single *file*), `monkey_chaos.rs`,
//! and `taguchi_collision_matrix.rs`, none of which exercise a directory
//! being renamed/deleted/created concurrently while it (or its contents)
//! are also being touched by the other device.
//!
//! Key background fact this whole file leans on (confirmed by reading
//! `local_change.rs`, `watcher.rs`, `materialization.rs`, and
//! `peer_session.rs` before writing any of this): **a directory is never,
//! itself, a tracked index entity.**
//! `local_change.rs::build_record_for_created_or_modified` explicitly
//! returns `None` for any non-file lstat ("directory event, or exotic
//! entry"), and `scan_existing_files`'s walker skips anything that isn't
//! a file or a symlink. `types::RecordKind::Directory` exists only as a
//! wire-compatibility enum value (`domain_record_kind_from_proto`/
//! `apply_incoming_wire_metadata`) -- it is never assigned by any local
//! scan or watch path. Consequently there is no directory-level tombstone,
//! no "recursive delete" message, and no directory-rename decomposition
//! anywhere in this engine: every scenario below reduces, one way or
//! another, to how the *files* underneath a directory operation do or
//! don't individually generate their own fs-level events. That reduction
//! is straightforward for a recursive delete (`remove_dir_all` unlinks
//! each file individually -- one real `Removed` event per file, same as
//! `collision_matrix.rs`'s file-level scenarios) but is NOT straightforward
//! for a directory *rename* (a single fs-level rename of the directory
//! entry itself, which never touches its children's inodes or names, so
//! no fs event fires for them at all -- `watcher.rs`'s
//! `register_new_directory_tree`, run for the renamed-to side, only adds
//! *future* watches into the newly-appeared subtree, it never synthesizes
//! creation events for files already inside it). Scenarios 1 and 3 below
//! are written with that asymmetry front and center; see each one's own
//! doc comment for the specific reasoning and what is (and isn't) safe to
//! assert as a result.
//!
//! `TestDevice`/`setup_device`/`start_syncing` are intentionally
//! duplicated from `collision_matrix.rs`/`monkey_chaos.rs`/
//! `taguchi_collision_matrix.rs` rather than shared -- matches this
//! codebase's existing convention of self-contained daemon integration
//! test binaries.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sha2::Digest;
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
    // daemon-concurrency-tests-file-backed-wal: this file's scenarios all
    // drive concurrent multi-device writes and conflict resolution under
    // load, so `SyncState` is opened file-backed WAL (production's
    // concurrency model) rather than `open_in_memory`'s shared-cache
    // backend — see `open_file_backed_sync_state`'s doc comment. Held only
    // to keep the backing temp file alive for the test's duration.
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
    let group_id = support::create_folder_group(&account, "directory-collision-group").await;
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

/// A recursive relative-path -> content-hash snapshot of everything under
/// `root`, for scenarios where the flat, non-recursive `real_entry_names`
/// (top-level only, by design -- see its own doc comment) isn't enough to
/// check nested directory contents. Written as a plain recursive
/// `std::fs::read_dir` walk (this crate doesn't depend on `walkdir`
/// itself; that's a `yadorilink-sync-core`-only dependency), skipping the
/// same two transient artifacts `real_entry_names` already accounts for
/// (an in-progress materialization temp file, and the case-fold hazard
/// probe file) so a raw listing race with either never inflates a
/// convergence check.
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

// --- Scenario 1: concurrent directory rename to different targets ---------

/// Both devices independently rename the same already-synced directory
/// (containing several files) to *different* new names at (effectively)
/// the same time.
///
/// This is deliberately NOT written as a nested version of
/// `collision_matrix.rs`'s `concurrent_rename_to_different_targets_both_survive`,
/// despite the superficially similar name, because the mechanism is not
/// analogous. A *file* rename fires a `RenameMode::From`/`To` pair against
/// that file's own tracked index row -- `process_event` decomposes it into
/// a real `Removed` (old path) + `CreatedOrModified` (new path) pair, so
/// the file-level scenario has a knowable shape. A *directory* rename is a
/// single fs-level rename of the directory entry itself: the files inside
/// it aren't touched (same inode, same name, same parent-relative
/// position) so the OS/notify backend never reports any event for them at
/// all. `watcher.rs`'s `register_new_directory_tree` (invoked for the
/// renamed-to path, since it's observed as a `CreatedOrModified` directory
/// event) only registers *future* watches into the newly-appeared
/// subtree -- it does not walk the subtree and synthesize "here are the
/// files already inside it" events. Nothing in `link_manager.rs` runs a
/// periodic full local rescan either (only an ignore-file change or an
/// event-count burst trigger a `BurstFallback` reconciliation scan, and a
/// single directory rename is nowhere near that threshold).
///
/// The upshot: whether (and how) the renamed directory's *contents* ever
/// propagate to the peer at all is a genuinely open question this test
/// exists to answer empirically, not a shape derivable from the existing
/// decomposition rules -- so this is a convergence-only assertion
/// (comparing the two devices' own recursive snapshots against *each
/// other*, not against a presumed "both new names, all files present"
/// shape), mirroring `taguchi_collision_matrix.rs`'s own philosophy for
/// shapes it can't fully predict either. A timeout here is itself a
/// meaningful, reproducible finding (the two devices never learn about
/// each other's rename), not a flake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_directory_rename_to_different_targets() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-rename-rename-diff").await;
    let _ = group_id;

    let dir_a = device_a.root.path().join("shared_dir");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::write(dir_a.join("a.txt"), b"content a").unwrap();
    std::fs::write(dir_a.join("b.txt"), b"content b").unwrap();
    std::fs::write(dir_a.join("c.txt"), b"content c").unwrap();

    wait_until(|| device_b.root.path().join("shared_dir/c.txt").exists(), Duration::from_secs(10))
        .await;

    std::fs::rename(
        device_a.root.path().join("shared_dir"),
        device_a.root.path().join("renamed-by-a"),
    )
    .unwrap();
    std::fs::rename(
        device_b.root.path().join("shared_dir"),
        device_b.root.path().join("renamed-by-b"),
    )
    .unwrap();

    wait_until_with_context(
        || recursive_snapshot(device_a.root.path()) == recursive_snapshot(device_b.root.path()),
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    // The one certainty regardless of how (or whether) the rename's
    // contents propagate: each device physically renamed its *own*
    // "shared_dir" away, so that name is gone from both, unconditionally.
    assert!(
        !real_entry_names(device_a.root.path()).contains(&"shared_dir".to_string()),
        "{:?}",
        real_entry_names(device_a.root.path())
    );
    assert!(
        !real_entry_names(device_b.root.path()).contains(&"shared_dir".to_string()),
        "{:?}",
        real_entry_names(device_b.root.path())
    );
}

// --- Scenario 2: delete a directory while the peer adds a file inside it ---

/// Device A deletes an already-synced directory (with existing files)
/// entirely, while device B concurrently ADDS a brand-new file inside
/// that same directory -- racing the directory's disappearance.
///
/// Unlike scenario 1's rename, `std::fs::remove_dir_all` individually
/// unlinks every file inside the directory -- one real `unlink` syscall,
/// and therefore one real `Removed` fs event, per file, each against that
/// file's own tracked index row. So each pre-existing file genuinely gets
/// tombstoned (`process_event`'s `Removed` branch: `mark_deleted` fires
/// because `get_file` finds an existing row for it) and broadcast --
/// this is not the same propagation gap as scenario 1.
///
/// Checked `materialization.rs` and `peer_session.rs` directly for any
/// directory-level tombstone or recursive-delete concept ("rmdir"/
/// "remove_dir"/directory-tombstone handling): there is none.
/// `RecordKind::Directory` is the only directory-shaped thing either file
/// deals with, and it's a wire-compatibility value only
/// (`domain_record_kind_from_proto`/`apply_incoming_wire_metadata`),
/// never assigned locally. So there is no "delete this whole directory"
/// message on the wire at all -- from the sync engine's point of view, a
/// directory delete is indistinguishable from "someone deleted these N
/// specific files that happen to share a parent path prefix". Device B's
/// brand-new file was never one of those N files, so it cannot be lost by
/// this deletion; and `chunker.rs`'s file-write helpers unconditionally
/// `create_dir_all(parent)` before writing, so the parent directory is
/// transparently recreated wherever it's needed to hold the survivor
/// (materializing B's new file back onto device A, whose own on-disk
/// "target_dir" no longer exists at that point).
///
/// Assertion shape used: the specific, reasoned outcome above, not a bare
/// convergence check -- the property that MUST hold is that the new
/// file's content is not silently lost on either device, and this test
/// pins down the exact final shape (both pre-existing files gone, the new
/// one present with its real content) that reasoning predicts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_directory_while_peer_adds_a_file_inside_it() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-delete-vs-add-inside").await;
    let _ = group_id;

    let dir_a = device_a.root.path().join("target_dir");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::write(dir_a.join("existing-1.txt"), b"existing content one").unwrap();
    std::fs::write(dir_a.join("existing-2.txt"), b"existing content two").unwrap();

    wait_until(
        || device_b.root.path().join("target_dir/existing-2.txt").exists(),
        Duration::from_secs(10),
    )
    .await;

    std::fs::remove_dir_all(&dir_a).unwrap();
    std::fs::write(
        device_b.root.path().join("target_dir/new_from_b.txt"),
        b"brand new content from device b",
    )
    .unwrap();

    let new_file_hash = hex::encode(sha2::Sha256::digest(b"brand new content from device b"));

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.get("target_dir/new_from_b.txt") == Some(&new_file_hash)
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    let snap_b = recursive_snapshot(device_b.root.path());
    assert_eq!(snap_a, snap_b);
    assert!(!snap_a.contains_key("target_dir/existing-1.txt"), "{snap_a:?}");
    assert!(!snap_a.contains_key("target_dir/existing-2.txt"), "{snap_a:?}");
    assert_eq!(snap_a.get("target_dir/new_from_b.txt"), Some(&new_file_hash));
}

// --- Scenario 3: a subdirectory rename races a child file edit ------------

/// Device A renames a subdirectory (containing `child.txt`) to a new
/// name, while device B -- unaware of A's rename -- concurrently edits
/// `child.txt`'s content via its own original nested path.
///
/// Per scenario 1's reasoning, A's rename never touches `child.txt`'s own
/// tracked index row at all (no fs event fires for it). Device B's edit,
/// by contrast, is an ordinary local edit against a path B's own index
/// still considers live -- a real `CreatedOrModified` event, chunked,
/// indexed, and broadcast normally. When that incoming update reaches
/// device A, A's own index *also* still considers "subdir/child.txt" live
/// (again: the rename never touched that row), so A treats it as an
/// ordinary incoming update to an existing path, and `materialize`'s
/// `create_dir_all(parent)` transparently recreates "subdir" (which A
/// physically renamed away) to hold it.
///
/// That specific mechanism is a reasoned prediction, not something this
/// test can fully verify without running it (deferred), so -- per the
/// same "don't presume a fully-derived shape" caution as scenario 1 --
/// this only asserts the one property that must hold regardless of the
/// exact resolution path: B's edited content is not silently lost. It
/// must appear *somewhere* in each device's final tree (the original
/// nested path, the renamed one, or a conflict copy), not "nowhere".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nested_rename_races_a_child_file_edit() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-nested-rename-vs-edit").await;
    let _ = group_id;

    let subdir_a = device_a.root.path().join("subdir");
    std::fs::create_dir_all(&subdir_a).unwrap();
    std::fs::write(subdir_a.join("child.txt"), b"original child content").unwrap();

    wait_until(|| device_b.root.path().join("subdir/child.txt").exists(), Duration::from_secs(10))
        .await;

    std::fs::rename(
        device_a.root.path().join("subdir"),
        device_a.root.path().join("subdir-renamed"),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(
        device_b.root.path().join("subdir/child.txt"),
        b"edited by b, racing a's directory rename",
    )
    .unwrap();

    let edited_hash =
        hex::encode(sha2::Sha256::digest(b"edited by b, racing a's directory rename"));

    wait_until_with_context(
        || {
            recursive_snapshot(device_a.root.path()).values().any(|h| h == &edited_hash)
                && recursive_snapshot(device_b.root.path()).values().any(|h| h == &edited_hash)
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;
}

// --- Scenario 4: same-named new directory, non-overlapping contents -------

/// No prior sync state: both devices, at (effectively) the same time,
/// create a brand-new directory with the SAME name but DIFFERENT,
/// non-overlapping files inside (device A creates `newdir/only-a.txt`,
/// device B creates `newdir/only-b.txt`).
///
/// Since a directory is never its own tracked index entity (see this
/// file's header comment), this is not a collision at the sync-engine
/// level at all -- "newdir/only-a.txt" and "newdir/only-b.txt" are simply
/// two unrelated, non-overlapping file paths, each synced independently
/// and normally, with `chunker.rs`'s `create_dir_all(parent)`
/// transparently creating "newdir" on whichever device doesn't already
/// have it. This is therefore a confident, specific-outcome assertion
/// (not a convergence-only one, and not the "reduces to a conflict" shape
/// of scenario 5): both files must end up present under "newdir/" on both
/// devices, with no conflict copy and no data loss -- a same-named
/// directory collision with non-conflicting contents inside must merge,
/// not produce a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrently_creating_same_named_directory_with_different_files_inside() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-create-create-merge").await;
    let _ = group_id;

    std::fs::create_dir_all(device_a.root.path().join("newdir")).unwrap();
    std::fs::create_dir_all(device_b.root.path().join("newdir")).unwrap();
    std::fs::write(device_a.root.path().join("newdir/only-a.txt"), b"only on a originally")
        .unwrap();
    std::fs::write(device_b.root.path().join("newdir/only-b.txt"), b"only on b originally")
        .unwrap();

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.contains_key("newdir/only-a.txt") && a.contains_key("newdir/only-b.txt")
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    assert!(!snap_a.keys().any(|k| is_conflict_copy(k)), "{snap_a:?}");
}

// --- Scenario 5: same-named new directory, a genuinely conflicting file ---

/// Same setup as scenario 4, but both devices write DIFFERENT content to
/// the SAME filename inside the same-named new directory
/// (`newdir/shared.txt`).
///
/// Again, the directory itself carries no identity at the sync-engine
/// level -- "newdir/shared.txt" is a single, ordinary file path, and two
/// devices independently creating it with unrelated version histories is
/// exactly the shape `collision_matrix.rs`'s scenario 1
/// (`concurrent_edit_edit_keeps_both_copies_as_original_plus_conflict_copy`)
/// already pins down, just one level deeper. Both contents must survive:
/// one under the original nested name, one as a conflict copy --
/// `conflict.rs`'s conflict-copy name builder preserves the directory
/// prefix (`<dir>{stem} (conflicted copy, ...).<ext>`), so the copy stays
/// nested under "newdir/" rather than flattening to the sync root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrently_creating_same_named_directory_with_a_conflicting_file_inside() {
    let (device_a, device_b, group_id) =
        two_synced_devices("dir-collision-create-create-conflict").await;
    let _ = group_id;

    std::fs::create_dir_all(device_a.root.path().join("newdir")).unwrap();
    std::fs::write(device_a.root.path().join("newdir/shared.txt"), b"from device a").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::create_dir_all(device_b.root.path().join("newdir")).unwrap();
    std::fs::write(
        device_b.root.path().join("newdir/shared.txt"),
        b"from device b, different and longer",
    )
    .unwrap();

    wait_until_with_context(
        || {
            let a = recursive_snapshot(device_a.root.path());
            let b = recursive_snapshot(device_b.root.path());
            a == b && a.contains_key("newdir/shared.txt") && a.keys().any(|k| is_conflict_copy(k))
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a={:?} device-b={:?}",
                recursive_snapshot(device_a.root.path()),
                recursive_snapshot(device_b.root.path())
            )
        },
    )
    .await;

    let snap_a = recursive_snapshot(device_a.root.path());
    assert_eq!(snap_a.keys().filter(|k| is_conflict_copy(k)).count(), 1, "{snap_a:?}");
    assert!(
        snap_a.keys().filter(|k| is_conflict_copy(k)).all(|k| k.starts_with("newdir/")),
        "conflict copy should stay nested under newdir/: {snap_a:?}"
    );
}
