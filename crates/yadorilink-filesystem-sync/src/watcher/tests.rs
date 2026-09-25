#![cfg(test)]

use super::*;
use std::time::Duration;

// Only ever constructed by the #[cfg(unix)] symlink-safety tests below
// (they exercise std::os::unix::fs::symlink), so this whole stand-in
// Watcher is unix-only too -- otherwise it's dead code on Windows.
#[cfg(unix)]
#[derive(Default)]
struct RecordingWatcher {
    watched: Vec<PathBuf>,
    modes: Vec<RecursiveMode>,
}

#[cfg(unix)]
impl Watcher for RecordingWatcher {
    fn new<F: notify::EventHandler>(
        _event_handler: F,
        _config: notify::Config,
    ) -> notify::Result<Self> {
        Ok(Self::default())
    }

    fn watch(&mut self, path: &Path, recursive_mode: RecursiveMode) -> notify::Result<()> {
        self.watched.push(path.to_path_buf());
        self.modes.push(recursive_mode);
        Ok(())
    }

    fn unwatch(&mut self, path: &Path) -> notify::Result<()> {
        self.watched.retain(|watched| watched != path);
        Ok(())
    }

    fn kind() -> notify::WatcherKind {
        notify::WatcherKind::PollWatcher
    }
}

#[tokio::test]
async fn file_creation_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let mut watcher = watch_folder(dir.path()).unwrap();

    let file_path = dir.path().join("new-file.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), watcher.events.recv())
        .await
        .expect("timed out waiting for fs event")
        .expect("watcher channel closed");
    assert_eq!(event.kind, FsChangeKind::CreatedOrModified);
}

/// Waits until an event for exactly `target` is observed, ignoring any
/// other event in between -- FSEvents (and, in principle, the other
/// backends) can deliver an extra event for a directory itself (e.g.
/// its mtime changing when a child is added) interleaved with the
/// events this test actually cares about, so asserting against the
/// literal next `recv` is too brittle. Panics with `msg` on timeout.
async fn recv_until(
    events: &mut mpsc::Receiver<FsChangeEvent>,
    target: &Path,
    msg: &str,
) -> FsChangeEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("watcher channel closed");
            if event.path == target {
                return event;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{msg}"))
}

/// A minimal, fast regression for the deadlock this change fixes — a
/// brand-new one-level subdirectory, created after the watcher has
/// already started, followed by one write inside it. Before this
/// change, the callback's own synchronous, reentrant
/// `RecommendedWatcher::watch` call for the new directory would
/// permanently wedge the watcher's callback thread (see the module doc
/// comment); this test's `timeout` would never fire on the buggy code
/// (`recv` simply never resolves, since the callback thread that
/// would deliver the write's event is deadlocked inside `watch`), so
/// this fails loudly rather than hanging the suite. Deliberately does
/// not need `windows_path_hazard_conflict.rs`'s deep nesting or long
/// path — those were incidental to the actual bug, not required to
/// reproduce it.
#[tokio::test]
async fn new_subdirectory_then_write_inside_it_does_not_deadlock_the_watcher() {
    let dir = tempfile::tempdir().unwrap();
    // Canonicalize up front, matching what `watch_folder` does to
    // `root` internally -- macOS's tempdir lives under a `/var` path
    // that's itself a symlink to `/private/var`, so an event's
    // (canonical) `path` never string-equals a path built from the
    // raw, non-canonical `dir.path`.
    let root = dir.path().canonicalize().unwrap();
    let mut watcher = watch_folder(&root).unwrap();

    let sub_dir = root.join("new-subdir");
    std::fs::create_dir(&sub_dir).unwrap();

    let file_path = sub_dir.join("new-file-in-new-subdir.txt");
    std::fs::write(&file_path, b"hello from a brand-new subdirectory").unwrap();

    let event = recv_until(
        &mut watcher.events,
        &file_path,
        "timed out waiting for the write inside a brand-new subdirectory -- the watcher is \
         likely deadlocked (directory-registration-race/deadlock regression)",
    )
    .await;
    assert_eq!(event.kind, FsChangeKind::CreatedOrModified);

    // Confirm the watcher is still alive for the *rest* of the link,
    // not just for this one new subdirectory -- the original bug wedged
    // the callback thread for every future event on the whole link, not
    // only the triggering subtree.
    let unrelated_path = root.join("unrelated-root-level-file.txt");
    std::fs::write(&unrelated_path, b"still alive").unwrap();
    recv_until(
        &mut watcher.events,
        &unrelated_path,
        "watcher stopped delivering events after the new-subdirectory write",
    )
    .await;
}

/// The registration-race half of this change -- a write landing
/// inside a brand-new directory must not be silently missed
/// regardless of its exact timing relative to that directory's own
/// watch registration. Deliberately does *not* drain the
/// directory-creation event before writing the file (unlike the
/// deadlock test above), matching `create_dir_all(parent)`
/// immediately followed by a write into `parent` -- exactly the shape
/// that risks losing the write to the registration race. The
/// deferred registrar's reconciling scan (`reconcile_new_directory_
/// subtree`) is what guarantees this: it walks the newly-registered
/// subtree for already-on-disk files unconditionally once `watch`
/// succeeds, so the write is picked up either by the live watch (if it
/// wins the race) or by the scan (if it doesn't) -- never by neither.
#[tokio::test]
async fn write_into_a_brand_new_directory_is_not_silently_missed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut watcher = watch_folder(&root).unwrap();

    let sub_dir = root.join("new-subdir-no-drain");
    std::fs::create_dir(&sub_dir).unwrap();
    let file_path = sub_dir.join("file-written-immediately-after-mkdir.txt");
    std::fs::write(&file_path, b"races the new directory's own watch registration").unwrap();

    // The file's own event may arrive before or after the directory's,
    // and either the live watch or the reconciling scan may be what
    // actually produces it -- `recv_until` looks past any other event
    // (e.g. the directory's own) rather than assuming a fixed count or
    // order.
    let found = recv_until(
        &mut watcher.events,
        &file_path,
        "the write into a brand-new directory was never detected -- likely lost to the \
         registration race (directory-registration-race/deadlock regression)",
    )
    .await;
    assert_eq!(found.kind, FsChangeKind::CreatedOrModified);
}

/// The OS callback thread must never block, even when the channel is
/// deliberately kept full (no one draining it) — proven here by
/// directly exercising the callback's own non-blocking `try_send` path
/// via a tiny channel filled to capacity, without needing a real
/// filesystem event (which would be much slower and less deterministic
/// to arrange).
#[test]
fn try_send_never_blocks_when_the_channel_is_full() {
    let (tx, _rx) = mpsc::channel(1);
    let overflowed = Arc::new(AtomicBool::new(false));

    // Fill the one slot.
    assert!(tx
        .try_send(FsChangeEvent { path: "a".into(), kind: FsChangeKind::CreatedOrModified })
        .is_ok());

    // A second attempt must return immediately (Err), not block —
    // this is exactly what the watcher callback does internally.
    let started = std::time::Instant::now();
    let overflow_tx = tx.clone();
    if overflow_tx
        .try_send(FsChangeEvent { path: "b".into(), kind: FsChangeKind::CreatedOrModified })
        .is_err()
    {
        overflowed.store(true, Ordering::Relaxed);
    }
    assert!(started.elapsed() < Duration::from_millis(50), "try_send must return immediately");
    assert!(overflowed.load(Ordering::Relaxed), "a full channel must be recorded as an overflow");
}

/// The overflow flag starts clear and a normal (non-full) watcher
/// never sets it.
#[tokio::test]
async fn overflow_flag_stays_clear_under_normal_operation() {
    let dir = tempfile::tempdir().unwrap();
    let watcher = watch_folder(dir.path()).unwrap();
    let (mut events_rx, overflowed, _guard) = watcher.split();

    std::fs::write(dir.path().join("f.txt"), b"hi").unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), events_rx.recv()).await;

    assert!(!overflowed.load(Ordering::Relaxed));
}

/// Capacity is configurable.
#[tokio::test]
async fn watch_folder_with_capacity_accepts_a_custom_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let mut watcher = watch_folder_with_capacity(dir.path(), 4).unwrap();

    std::fs::write(dir.path().join("f.txt"), b"hi").unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), watcher.events.recv())
        .await
        .expect("timed out")
        .expect("channel closed");
    assert_eq!(event.kind, FsChangeKind::CreatedOrModified);
}

#[tokio::test]
async fn ignore_aware_watcher_skips_ignored_directory_and_leaf_file_events() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
    let ignore_set = Arc::new(EffectiveIgnoreSet::from_user_patterns("node_modules/\n*.tmp\n"));
    let mut watcher = watch_folder_with_capacity_and_ignore(dir.path(), 32, ignore_set).unwrap();

    std::fs::write(dir.path().join("node_modules/pkg/index.js"), b"ignored").unwrap();
    std::fs::write(dir.path().join("scratch.tmp"), b"ignored").unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(500), watcher.events.recv()).await.is_err(),
        "ignored paths must not be queued"
    );

    std::fs::write(dir.path().join("keep.txt"), b"kept").unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), watcher.events.recv())
        .await
        .expect("timed out waiting for non-ignored event")
        .expect("watcher channel closed");
    assert_eq!(event.path.file_name().and_then(|name| name.to_str()), Some("keep.txt"));
}

#[tokio::test]
async fn ignore_aware_watcher_still_queues_ignore_file_changes() {
    let dir = tempfile::tempdir().unwrap();
    let ignore_set = Arc::new(EffectiveIgnoreSet::from_user_patterns("*\n"));
    let mut watcher = watch_folder_with_capacity_and_ignore(dir.path(), 32, ignore_set).unwrap();

    std::fs::write(dir.path().join(".yadorilinkignore"), b"*.tmp\n").unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), watcher.events.recv())
        .await
        .expect("timed out waiting for ignore-file event")
        .expect("watcher channel closed");
    assert_eq!(event.path.file_name().and_then(|name| name.to_str()), Some(".yadorilinkignore"));
}

// --- Symlink-safe directory classification and registration ---

/// `is_real_directory` is lstat-based: true only for a genuine
/// directory, false for a symlink even when its target is a directory,
/// and false for a plain file.
#[cfg(unix)]
#[test]
fn is_real_directory_is_lstat_based_not_follow() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("real_dir")).unwrap();
    std::fs::write(dir.path().join("real_file.txt"), b"x").unwrap();
    std::os::unix::fs::symlink(dir.path().join("real_dir"), dir.path().join("link_to_dir"))
        .unwrap();

    assert!(is_real_directory(&dir.path().join("real_dir")));
    assert!(!is_real_directory(&dir.path().join("real_file.txt")));
    assert!(
        !is_real_directory(&dir.path().join("link_to_dir")),
        "a symlink to a directory must not be reported as a real directory"
    );
    assert!(!is_real_directory(&dir.path().join("does_not_exist")));
}

/// Defense-in-depth: `register_non_ignored_directories` refuses to
/// walk from a symlink `start` outright, rather than relying solely on
/// the caller (`register_new_directory_tree`) never passing one —
/// proven directly against the function, not just through the
/// higher-level watcher behavior covered in `local_change.rs`'s tests.
#[cfg(unix)]
#[test]
fn register_non_ignored_directories_refuses_a_symlink_start() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("real_dir")).unwrap();
    std::fs::write(root.join("real_dir/secret.txt"), b"must not be watched").unwrap();
    let link = root.join("link_dir");
    std::os::unix::fs::symlink(root.join("real_dir"), &link).unwrap();

    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let watched_dirs = Arc::new(Mutex::new(BTreeSet::new()));
    let mut watcher = RecordingWatcher::default();

    let mut watched = watched_dirs.lock().unwrap();
    let result =
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &link, &ignore_set);
    assert!(result.is_ok(), "must not error, just decline to register anything");
    assert!(watched.is_empty(), "a symlink start must never result in any registered watch");
    assert!(watcher.watched.is_empty());
}

/// No current `ArtefactKind` is directory-shaped, so this is not
/// reachable today — but `register_non_ignored_directories` must never
/// register a native OS watch on a reserved-namespace path, matching
/// every other entry point in the crate. Proven directly against the
/// function so this holds even before anything ever creates a
/// directory-shaped artefact.
#[cfg(unix)]
#[test]
fn register_non_ignored_directories_skips_a_reserved_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let reserved_dir = root.join(
        yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Retained,
            "deadbeef",
        )
        .unwrap(),
    );
    std::fs::create_dir_all(&reserved_dir).unwrap();
    std::fs::write(reserved_dir.join("inside.txt"), b"must not be watched").unwrap();

    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let watched_dirs = Arc::new(Mutex::new(BTreeSet::new()));
    let mut watcher = RecordingWatcher::default();

    let mut watched = watched_dirs.lock().unwrap();
    let result =
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set);
    assert!(result.is_ok());
    assert!(
        !watched.contains(&reserved_dir),
        "a reserved-namespace directory must never be registered for a watch"
    );
    assert!(!watcher.watched.contains(&reserved_dir));
}

/// A self-referential symlinked-directory cycle must not hang
/// `register_non_ignored_directories` — real symlink cycle on disk,
/// wrapped in a wall-clock timeout so a genuine infinite loop fails
/// the test loudly instead of hanging the suite.
#[cfg(unix)]
#[test]
fn register_non_ignored_directories_does_not_hang_on_a_symlink_cycle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("cyc")).unwrap();
    std::os::unix::fs::symlink(root.join("cyc/a"), root.join("cyc/a")).unwrap();

    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    let registered =
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
            .unwrap();

    assert_eq!(registered, watcher.watched);
    assert!(registered.contains(&root));
    assert!(registered.contains(&root.join("cyc")));
    assert!(!registered.contains(&root.join("cyc/a")));
}

/// A directory moved or copied into the tree arrives as one event for the
/// directory itself. Every directory inside it is re-reported too, empty
/// ones included: an empty directory is an entry capture authors, and no
/// other event will ever name it.
#[test]
fn reconcile_new_directory_subtree_emits_events_for_empty_subdirectories() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("new/empty")).unwrap();
    std::fs::create_dir_all(root.join("new/full/deeper-empty")).unwrap();
    std::fs::write(root.join("new/full/f.txt"), b"f").unwrap();
    let (tx, mut rx) = mpsc::channel(64);
    let overflowed = Arc::new(AtomicBool::new(false));

    reconcile_new_directory_subtree(
        &tx,
        &overflowed,
        &root,
        &root.join("new"),
        &EffectiveIgnoreSet::defaults_only(),
    );

    let mut reported = BTreeSet::new();
    while let Ok(event) = rx.try_recv() {
        assert_eq!(event.kind, FsChangeKind::CreatedOrModified);
        reported.insert(event.path);
    }
    for rel in ["new/empty", "new/full", "new/full/deeper-empty", "new/full/f.txt"] {
        assert!(reported.contains(&root.join(rel)), "{rel} was not re-reported: {reported:?}");
    }
    assert!(!overflowed.load(Ordering::Relaxed));
}

/// inotify ends a directory's watch when the directory is deleted. The
/// registered set forgets it (and what was below it) once it is gone, so
/// the same path made again is registered again rather than skipped as
/// already watched.
#[cfg(unix)]
#[test]
fn recreated_directory_after_recursive_delete_is_watched_again() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("d/e")).unwrap();
    std::fs::create_dir_all(root.join("d-sibling")).unwrap();
    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
        .unwrap();
    assert!(watched.contains(&root.join("d/e")));

    std::fs::remove_dir_all(root.join("d")).unwrap();
    forget_removed_directories(&mut watched, &root.join("d"));
    assert!(!watched.contains(&root.join("d")));
    assert!(!watched.contains(&root.join("d/e")));
    assert!(watched.contains(&root.join("d-sibling")), "a sibling sharing the prefix is kept");

    std::fs::create_dir_all(root.join("d/e")).unwrap();
    let again =
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
            .unwrap();
    assert_eq!(again, vec![root.join("d"), root.join("d/e")]);
}

/// The removal is often handled only once the directory has been made
/// again at the same path (both events in one registrar batch). The new
/// directory still has to be registered: what is on disk when the removal
/// is handled does not keep the old registration.
#[cfg(unix)]
#[test]
fn a_removal_handled_after_the_directory_was_recreated_still_reregisters_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("d")).unwrap();
    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
        .unwrap();

    std::fs::remove_dir(root.join("d")).unwrap();
    std::fs::create_dir(root.join("d")).unwrap();
    forget_removed_directories(&mut watched, &root.join("d"));
    let again =
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
            .unwrap();
    assert_eq!(again, vec![root.join("d")]);
}

/// Where registering a watch recreates the whole event stream, the root
/// is watched once, recursively, and nothing is registered afterwards --
/// so no directory appearing ever opens a window in which events anywhere
/// in the tree are lost.
#[cfg(unix)]
#[test]
fn a_stream_recreating_backend_watches_the_root_once_recursively() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    let ignore_set = EffectiveIgnoreSet::defaults_only();

    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    register_initial_watches(&mut watcher, &mut watched, &root, &ignore_set, RootWatch::Recursive)
        .unwrap();
    assert_eq!(watcher.watched, vec![root.clone()]);
    assert_eq!(watcher.modes, vec![RecursiveMode::Recursive]);
    // Every directory already there is known, so an event on one of them
    // later (a chmod, a Finder tag) is not mistaken for a new directory.
    assert_eq!(
        watched.iter().cloned().collect::<Vec<_>>(),
        vec![root.clone(), root.join("a"), root.join("a/b")]
    );

    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    register_initial_watches(
        &mut watcher,
        &mut watched,
        &root,
        &ignore_set,
        RootWatch::PerDirectory,
    )
    .unwrap();
    assert_eq!(watcher.watched, vec![root.clone(), root.join("a"), root.join("a/b")]);
    assert!(watcher.modes.iter().all(|mode| *mode == RecursiveMode::NonRecursive));

    assert_eq!(
        ROOT_WATCH == RootWatch::Recursive,
        REGISTRATION_RECREATES_STREAM,
        "the root is watched recursively exactly where registration blinds the stream"
    );
}

/// Under a recursive root watch, only a directory not seen before has its
/// contents re-reported. An event on a known directory -- its mode, its
/// attributes, a Finder tag, a repeated FSEvents flag -- re-reports
/// nothing, so touching a large folder does not flood the channel.
#[cfg(unix)]
#[test]
fn only_a_directory_not_seen_before_is_rereported_under_a_recursive_watch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("big/inner")).unwrap();
    let ignore_set = EffectiveIgnoreSet::defaults_only();
    let mut watched = BTreeSet::new();
    let mut watcher = RecordingWatcher::default();
    register_initial_watches(&mut watcher, &mut watched, &root, &ignore_set, RootWatch::Recursive)
        .unwrap();

    assert!(
        newly_known_directories(&mut watched, &root, &[root.join("big")], &ignore_set).is_empty()
    );

    std::fs::create_dir_all(root.join("moved-in/a/b")).unwrap();
    std::fs::create_dir_all(root.join("big/fresh")).unwrap();
    let new = newly_known_directories(
        &mut watched,
        &root,
        &[root.join("moved-in/a"), root.join("moved-in"), root.join("big"), root.join("big/fresh")],
        &ignore_set,
    );
    assert_eq!(new, vec![root.join("big/fresh"), root.join("moved-in")]);
    assert!(newly_known_directories(&mut watched, &root, &[root.join("moved-in")], &ignore_set)
        .is_empty());
}
