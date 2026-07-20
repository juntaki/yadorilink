//! Local filesystem change detection, watching a linked folder
//! for create/modify/delete/rename events without requiring a manual scan
//! trigger (`sync-engine` spec's "Local Change Detection" requirement).
//!
//! `notify`'s `RecommendedWatcher::watch`/`unwatch` must never be called
//! synchronously from within the watcher's own event-callback closure.
//! Every one of `notify` 8.2's backends (verified directly against its
//! vendored source, not assumed) funnels callback delivery and
//! watch-registration requests through the *same single dedicated event-
//! loop thread*: macOS FSEvents delivers callbacks on a `CFRunLoop` thread
//! and `watch`'s `stop` step busy-waits for that exact thread to go
//! idle before reconfiguring; Linux inotify and Windows
//! `ReadDirectoryChangesW` both process a `watch` call as a message sent
//! to that same event-loop thread, then block the caller on a reply that
//! only that thread can send. Calling `watch` reentrantly from inside
//! the callback therefore blocks the one thread the backend needs in order
//! to ever unblock it — an indefinite deadlock on every backend, not an
//! FSEvents-specific quirk. See `spawn_new_directory_registrar` below,
//! which hands new-directory registration off to a tokio task instead.
//!
//! Moving `watch` off the callback thread closed that deadlock, but not a
//! residual gap — confirmed directly against `notify` 8.2.0's vendored
//! FSEvents source (`fsevent.rs`): `watch_inner`/`unwatch_inner` always
//! call `stop` (tear down the *entire* `FSEventStream` and block until
//! its dedicated thread joins) followed by `run` (a brand-new
//! `FSEventStreamCreate`, covering every currently-watched path, not just
//! the one being added/removed). `since_when` is fixed to
//! `kFSEventStreamEventIdSinceNow` once, at `FsEventWatcher` construction,
//! and is never advanced to the last-delivered event ID on a restart — so
//! the recreated stream genuinely starts "since now" at whatever moment
//! `FSEventStreamCreate` happens to run. Any real filesystem event for
//! *any* watched path (not only the newly-registered one) that lands in
//! the gap between the old stream stopping and the new one starting is
//! never delivered by the OS at all: not delayed, not coalesced, not
//! recoverable by anything watching the callback — confirmed empirically
//! too (raw `notify::Event`-level instrumentation during a 100%-
//! reproducible failure showed zero trace of the lost event ever reaching
//! the callback). Every `register_new_directory_tree` call is a `watch`
//! call, so it always opens this window. Since this is an OS-level
//! delivery gap this codebase's own code cannot observe or narrow (there
//! is nothing to lock more tightly — `notify` itself never sees the
//! event, so which specific path, if any, was affected is unknowable from
//! here), the fix in `spawn_new_directory_registrar` below is a
//! reconciling safety net rather than a targeted capture: every
//! registration trigger re-scans from `root` (not just the specific
//! directory that triggered it) for any directory not yet in
//! `watched_dirs`, registering and reconciling each one found this way —
//! this is how a lost rename's *destination* directory (never reported by
//! the callback as "new" at all) still gets discovered and its contents
//! indexed. This scan is purely path-level (which directories exist and
//! are/aren't already watched) and never touches file content or the
//! index — deliberately not implemented by reusing the watcher-channel-
//! overflow/`DebounceFlush::BurstFallback` full index-vs-disk
//! reconciliation, which was tried first and found unsafe: triggering a
//! full `scan_existing_files_with_ignore` this often can re-derive and
//! re-version a file that's concurrently mid-conflict-resolution between
//! two devices, permanently stalling convergence (reproduced
//! deterministically — see `spawn_new_directory_registrar`'s doc comment
//! for the full account).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::error::SyncError;
use crate::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};

/// Default channel capacity between the OS watcher callback and whatever
/// consumes `FolderWatcher::events` — a tuning knob for how early the
/// overflow fallback (see `overflowed`) engages, not the only thing
/// standing between "keep events" and "block the OS callback thread"
/// (non-blocking `try_send`, below, already guarantees the latter
/// regardless of capacity).
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsChangeKind {
    CreatedOrModified,
    Removed,
}

#[derive(Debug, Clone)]
pub struct FsChangeEvent {
    pub path: PathBuf,
    pub kind: FsChangeKind,
}

/// Keeps the underlying OS watcher alive for as long as this is held;
/// dropping it stops watching.
pub struct FolderWatcher {
    _watcher: WatcherGuard,
    pub events: mpsc::Receiver<FsChangeEvent>,
    overflowed: Arc<AtomicBool>,
}

/// Keeps whatever underlying event source is producing `FolderWatcher`'s
/// events alive for as long as this is held; dropping it stops that
/// source. Opaque (not the concrete `notify` watcher type) so that
/// `FolderWatchSource` implementations other than `RealFolderWatchSource`
/// (a simulated source feeding synthetic `FsChangeEvent`s under a
/// deterministic-simulation test harness) can return a `FolderWatcher` too,
/// without this crate's consumers (`run_debouncer` and everyone above it)
/// ever needing to know which kind they're holding.
pub struct WatcherGuard {
    _guard: Box<dyn std::any::Any + Send + Sync>,
}

impl FolderWatcher {
    /// Splits into the event receiver, the overflow flag (see
    /// `watch_folder`'s doc comment), and an opaque guard that keeps
    /// the underlying OS watch alive for as long as it's held: the
    /// debounce accumulator needs to own `events` and the
    /// overflow flag directly, in a different task than whatever holds
    /// the OS-watcher guard, since the accumulator and the executor
    /// consuming its output are two independently-scheduled tasks.
    pub fn split(self) -> (mpsc::Receiver<FsChangeEvent>, Arc<AtomicBool>, WatcherGuard) {
        (self.events, self.overflowed, self._watcher)
    }
}

/// Watches `root` with the default channel capacity — see
/// `watch_folder_with_capacity` for the full behavior and the overflow
/// flag's meaning.
pub fn watch_folder(root: &Path) -> Result<FolderWatcher, SyncError> {
    watch_folder_with_capacity(root, DEFAULT_CHANNEL_CAPACITY)
}

pub fn watch_folder_with_ignore(
    root: &Path,
    ignore_set: Arc<EffectiveIgnoreSet>,
) -> Result<FolderWatcher, SyncError> {
    watch_folder_with_capacity_and_ignore(root, DEFAULT_CHANNEL_CAPACITY, ignore_set)
}

/// Watches `root` for filesystem events, delivered on `FolderWatcher::events`
/// with the given channel `capacity`.
///
/// The OS callback (running on notify's own thread, not tokio) uses a
/// non-blocking `try_send` rather than `blocking_send`: it never blocks
/// waiting for a consumer, regardless of how full the channel gets or
/// how slow the consumer is. When the channel is full,
/// that specific event's data is unavoidably dropped — there is no way
/// to block without risking the *upstream* OS-level notification queue
/// (inotify/FSEvents/`ReadDirectoryChangesW`) overflowing instead, which
/// would be silent and undetectable. Instead, a drop is recorded via
/// `overflowed` (an `AtomicBool`, checked and cleared by the consumer —
/// see `FolderWatcher::split`), which the debounce accumulator treats as
/// a trigger for the same full-reconciliation recovery as an oversized
/// debounce burst: an overflow means precise per-path tracking is no
/// longer trustworthy, so only a full rescan restores a correct index —
/// but nothing is ever silently, permanently lost.
pub fn watch_folder_with_capacity(
    root: &Path,
    capacity: usize,
) -> Result<FolderWatcher, SyncError> {
    let ignore_set = Arc::new(EffectiveIgnoreSet::load_for_link_root(root)?);
    watch_folder_with_capacity_and_ignore(root, capacity, ignore_set)
}

pub fn watch_folder_with_capacity_and_ignore(
    root: &Path,
    capacity: usize,
    ignore_set: Arc<EffectiveIgnoreSet>,
) -> Result<FolderWatcher, SyncError> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let (tx, rx) = mpsc::channel(capacity);
    let overflowed = Arc::new(AtomicBool::new(false));
    let callback_overflowed = overflowed.clone();
    let watcher_holder: Arc<Mutex<Option<RecommendedWatcher>>> = Arc::new(Mutex::new(None));
    let watched_dirs = Arc::new(Mutex::new(HashSet::new()));
    let callback_root = root.clone();
    let callback_ignore_set = ignore_set.clone();

    // The callback below must never call `RecommendedWatcher::watch`
    // itself (see the module doc comment) — it only ever sends the
    // newly-observed directory's path over this unbounded channel.
    // Unbounded (not the bounded, drop-on-full `tx`/`overflowed` pair
    // above): a dropped `FsChangeEvent` is recoverable by design (the
    // consumer's overflow-triggered full rescan, per `watch_folder_with_
    // capacity`'s doc comment), but a dropped new-directory registration
    // request has no such recovery path — the directory's watch would
    // simply never be registered, and nothing would ever retry it. These
    // messages are just `PathBuf`s and only ever produced on genuine new-
    // directory events (not a hot per-event path), so never bounding this
    // channel is safe.
    let (new_dir_tx, new_dir_rx) = mpsc::unbounded_channel::<PathBuf>();
    let callback_new_dir_tx = new_dir_tx.clone();
    // The registrar task (spawned below, after `watcher_holder` is
    // populated) needs its own handle to synthesize reconciliation events
    // through the same `FsChangeEvent` channel/overflow flag the callback
    // uses — cloned here, before `tx`/`overflowed` are moved into the
    // callback closure below.
    let registrar_tx = tx.clone();
    let registrar_overflowed = overflowed.clone();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        let Ok(event) = res else { return };
        let enqueue_path = |path: PathBuf, kind: FsChangeKind| {
            if !should_queue_path(&callback_root, &callback_ignore_set, &path, kind) {
                return;
            }
            // `path.is_dir` follows a symlink to decide, which would let
            // a freshly-created symlink-to-directory register recursive
            // watches into whatever it points to (including outside
            // `root`) — use an lstat-equivalent check instead so a
            // symlink is never treated as something to descend into,
            // matching the scanner's lstat-first classification.
            if matches!(kind, FsChangeKind::CreatedOrModified) && is_real_directory(&path) {
                // Send-only, off this callback thread — see the module
                // doc comment and `spawn_new_directory_registrar` below.
                // `send` on an unbounded channel only fails if the
                // receiving task is gone (shutdown race), never because
                // it's full; either way there is nothing more to do here.
                let _ = callback_new_dir_tx.send(path.clone());
            }
            if tx.try_send(FsChangeEvent { path, kind }).is_err() {
                callback_overflowed.store(true, Ordering::Relaxed);
            }
        };

        // A plain `EventKind::Modify(_) => CreatedOrModified` blanket
        // match (the previous behavior) misclassifies a rename's *source*
        // path as a live edit — `process_event` then sees the path no
        // longer exists on disk and just drops the event (`None`), so the
        // old path's index row is never tombstoned and propagates to
        // peers as live forever. `ModifyKind::Name` carries a `RenameMode`
        // telling us which of the (possibly two) `event.paths` is the old
        // path, the new path, or both — classify each accordingly instead
        // of collapsing every rename mode to `CreatedOrModified`.
        if let EventKind::Modify(ModifyKind::Name(rename_mode)) = event.kind {
            let pairs: Vec<(PathBuf, FsChangeKind)> = match rename_mode {
                RenameMode::From => {
                    event.paths.into_iter().map(|p| (p, FsChangeKind::Removed)).collect()
                }
                RenameMode::To => {
                    event.paths.into_iter().map(|p| (p, FsChangeKind::CreatedOrModified)).collect()
                }
                RenameMode::Both => {
                    let mut paths = event.paths.into_iter();
                    match (paths.next(), paths.next()) {
                        (Some(from), Some(to)) => {
                            vec![
                                (from, FsChangeKind::Removed),
                                (to, FsChangeKind::CreatedOrModified),
                            ]
                        }
                        // Malformed (should always carry exactly two paths
                        // per notify's own contract) — fail soft rather
                        // than panic or silently drop.
                        (Some(only), None) => vec![(only, FsChangeKind::CreatedOrModified)],
                        (None, _) => vec![],
                    }
                }
                // `Any`/`Other`: the backend can't tell us which side this
                // is. Treating it as a removal risks false-tombstoning a
                // file that was actually just renamed *in* (not deleted);
                // treating it as CreatedOrModified — the previous,
                // unconditional behavior — is the conservative choice
                // here, same as before this fix for these two modes.
                RenameMode::Any | RenameMode::Other => {
                    event.paths.into_iter().map(|p| (p, FsChangeKind::CreatedOrModified)).collect()
                }
            };
            for (path, kind) in pairs {
                enqueue_path(path, kind);
            }
            return;
        }

        let kind = match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => FsChangeKind::CreatedOrModified,
            EventKind::Remove(_) => FsChangeKind::Removed,
            _ => return,
        };
        for path in event.paths {
            enqueue_path(path, kind);
        }
    })
    .map_err(SyncError::from)?;

    {
        let mut watched = watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)?;
    }
    *watcher_holder.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(watcher);

    // The registrar task owns only a `Weak` handle to `watcher_holder` —
    // the `WatcherGuard` returned below (via `FolderWatcher`/`FolderWatcher::
    // split`) holds the only strong `Arc`. When that guard is dropped, the
    // `RecommendedWatcher` (and, with it, this closure and its own
    // `new_dir_tx` clone) is dropped, so `new_dir_rx.recv` below
    // eventually returns `None` and this task exits on its own — no
    // separate abort handle is needed, and this task's lifetime is tied
    // exactly to the underlying OS watch's, matching `WatcherGuard`'s own
    // documented contract ("dropping it stops watching").
    spawn_new_directory_registrar(
        Arc::downgrade(&watcher_holder),
        watched_dirs,
        root.clone(),
        ignore_set,
        new_dir_rx,
        registrar_tx,
        registrar_overflowed,
    );

    Ok(FolderWatcher {
        _watcher: WatcherGuard { _guard: Box::new(watcher_holder) },
        events: rx,
        overflowed,
    })
}

/// Constructs a `FolderWatcher` for a linked folder root.
/// `link_manager::start_link_watch` depends on this trait (rather than
/// calling `watch_folder_with_ignore` directly) so a deterministic-
/// simulation test scenario can substitute a source that feeds synthetic
/// `FsChangeEvent`s under simulated timing instead of a real OS
/// filesystem watcher, while every consumer downstream of the returned
/// `FolderWatcher` (the debounce accumulator, indexing, peer
/// reconciliation, materialization) runs the same production code either
/// way.
pub trait FolderWatchSource: Send + Sync {
    fn watch(
        &self,
        root: &Path,
        ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, SyncError>;
}

/// The real, OS-backed `FolderWatchSource` — what every production
/// caller and today's existing tests use.
pub struct RealFolderWatchSource;

impl FolderWatchSource for RealFolderWatchSource {
    fn watch(
        &self,
        root: &Path,
        ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, SyncError> {
        watch_folder_with_ignore(root, ignore_set)
    }
}

/// A `FolderWatchSource` a deterministic-simulation test scenario
/// constructs itself, feeding synthetic `FsChangeEvent`s through the same
/// `mpsc` channel/overflow-flag boundary a real OS watcher would, so
/// `run_debouncer` and everything above it (indexing, peer reconciliation,
/// materialization) runs unmodified against events the scenario script
/// controls directly instead of ones a real filesystem produces. Pure
/// channel plumbing — no OS or `madsim`-specific API — so it works
/// identically whether the binary is built against real `tokio` or
/// `madsim`'s simulated shim; only the *scheduling* around it differs.
///
/// `watch` can only be called once per instance (mirroring a real
/// link's one-watcher-per-root lifecycle); a second call is a
/// programming error in the scenario driver, not a recoverable runtime
/// condition.
pub struct SimulatedFolderWatchSource {
    events_rx: std::sync::Mutex<Option<mpsc::Receiver<FsChangeEvent>>>,
    overflowed: Arc<AtomicBool>,
}

impl SimulatedFolderWatchSource {
    /// Returns the source (to hand to `link_manager::start_link_watch_
    /// with_source`-equivalent wiring) paired with the `Sender` a DST
    /// scenario uses to inject synthetic filesystem events afterward.
    pub fn new(capacity: usize) -> (Self, mpsc::Sender<FsChangeEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                events_rx: std::sync::Mutex::new(Some(rx)),
                overflowed: Arc::new(AtomicBool::new(false)),
            },
            tx,
        )
    }
}

impl FolderWatchSource for SimulatedFolderWatchSource {
    fn watch(
        &self,
        _root: &Path,
        _ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, SyncError> {
        let events = self
            .events_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| {
                SyncError::from(std::io::Error::other(
                    "SimulatedFolderWatchSource::watch called more than once",
                ))
            })?;
        Ok(FolderWatcher {
            _watcher: WatcherGuard { _guard: Box::new(()) },
            events,
            overflowed: self.overflowed.clone(),
        })
    }
}

/// Runs off the FSEvents/inotify/`ReadDirectoryChangesW` callback thread —
/// see the module doc comment for why that call site can never do this
/// work itself. Receives newly-observed directory paths from the callback
/// closure (`new_dir_rx`) purely as a trigger signal — see below for why
/// the actual registration scan below always starts at `root`, not at the
/// specific path a given trigger names.
///
/// A `watch` call opens an OS-level blind window (module doc comment)
/// that can lose a live event for *any* currently-watched path, not only
/// the specific directory that triggered this iteration — so scanning
/// only that one directory's subtree (the original, narrower approach)
/// cannot discover a directory that appeared elsewhere in the tree as a
/// result of a lost event (e.g. a
/// lost rename's *destination* name, which the callback never got a
/// chance to report at all). Scanning from `root` instead — via
/// `register_new_directory_tree`, unchanged except for this call's `start`
/// argument — is index-free and safe to run this often: it is a pure
/// path-registration walk (`register_non_ignored_directories`'s existing
/// logic, exactly what the initial startup registration already does from
/// `root`), calling `watcher.watch` only for directories not already in
/// `watched_dirs`; every already-known directory is untouched. This
/// deliberately does *not* reuse the watcher-channel-overflow /
/// `DebounceFlush::BurstFallback` full index-vs-disk reconciliation
/// (`local_change.rs::scan_existing_files_with_ignore`) as the recovery
/// mechanism — confirmed via direct experiment that doing so is unsafe:
/// triggering it this often (once per directory-watch registration, not
/// only on a rare genuine channel overflow) can re-derive and re-version
/// a file that is concurrently mid-conflict-resolution between two
/// devices, colliding with peer_session.rs's own version-vector
/// comparison and permanently stalling convergence (reproduced
/// deterministically, isolated from unrelated confounds, with
/// `directory_conflict_matrix.rs`'s `concurrently_creating_same_named_
/// directory_with_a_conflicting_file_inside` — a file it never touches).
/// The scan below cannot cause this: it never looks at file content or the
/// index, only at which *directories* are already watched.
///
/// For every directory this scan newly registers (including, but not
/// limited to, the one that triggered this iteration), closes the
/// registration-race window (a write landing in the gap between
/// "directory observed" and "watch registered" would otherwise be
/// silently missed forever) by synthesizing a
/// `CreatedOrModified` event for every real file already present in it,
/// exactly as if the watcher had observed each one live — this is what
/// recovers a lost rename's destination content: it was never reported as
/// "new" by the callback, but this scan still discovers it directly on
/// disk and registers/reconciles it like any other not-yet-watched
/// directory.
///
/// Requires an active tokio runtime (`tokio::spawn`) — true of every real
/// caller: `link_manager::start_link_watch` runs inside the daemon's tokio
/// runtime, and this module's own tests are all `#[tokio::test]`.
fn spawn_new_directory_registrar(
    watcher_holder: Weak<Mutex<Option<RecommendedWatcher>>>,
    watched_dirs: Arc<Mutex<HashSet<PathBuf>>>,
    root: PathBuf,
    ignore_set: Arc<EffectiveIgnoreSet>,
    mut new_dir_rx: mpsc::UnboundedReceiver<PathBuf>,
    tx: mpsc::Sender<FsChangeEvent>,
    overflowed: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        while let Some(new_dir) = new_dir_rx.recv().await {
            match register_new_directory_tree(
                &watcher_holder,
                &watched_dirs,
                &root,
                &root,
                &ignore_set,
            ) {
                Ok(newly_registered) if !newly_registered.is_empty() => {
                    // Strictly after `watch` has succeeded for each of
                    // these subtrees, never concurrent with it.
                    for dir in &newly_registered {
                        reconcile_new_directory_subtree(&tx, &overflowed, &root, dir, &ignore_set);
                    }
                }
                Ok(_) => {
                    // Nothing was newly registered anywhere in the tree
                    // (e.g. a redundant notification for an
                    // already-watched directory, or the watcher/guard is
                    // already gone on a shutdown race) — no
                    // `watch`/`stop`/recreate cycle occurred, so no
                    // OS-level blind window could have opened; nothing to
                    // reconcile.
                }
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        trigger = %new_dir.display(),
                        "failed to re-register the watched directory tree"
                    );
                }
            }
        }
    });
}

/// Emits a synthesized `CreatedOrModified` event (through the same
/// channel/overflow discipline as a live callback event — using a
/// non-blocking `try_send`, never a blocking send that could stall this
/// a slow consumer) for every real (non-symlink) file already
/// present under `start`, so a
/// write that landed there before this subtree's watch registration
/// completed is still picked up by `local_change.rs`'s ordinary dispatch,
/// exactly as if the watcher had seen it live. Only ever called after
/// `register_new_directory_tree` reports `start` among the directories it
/// just newly registered (see `spawn_new_directory_registrar`) — never
/// concurrent with, or ahead of, that registration succeeding.
fn reconcile_new_directory_subtree(
    tx: &mpsc::Sender<FsChangeEvent>,
    overflowed: &Arc<AtomicBool>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) {
    let walker =
        walkdir::WalkDir::new(start).follow_links(false).into_iter().filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            if !entry.file_type().is_dir() {
                return true;
            }
            let Ok(relative_path) = entry.path().strip_prefix(root) else { return false };
            !ignore_set.is_ignored(relative_path, true)
        });

    for entry in walker.filter_map(Result::ok) {
        // `file_type` is lstat-based here (no `follow_links`, matching
        // `register_non_ignored_directories`'s own reasoning) — a symlink
        // is neither `is_dir` nor `is_file`, so it's correctly skipped
        // rather than treated as a file to synthesize an event for.
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_path_buf();
        if !should_queue_path(root, ignore_set, &path, FsChangeKind::CreatedOrModified) {
            continue;
        }
        if tx.try_send(FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified }).is_err() {
            overflowed.store(true, Ordering::Relaxed);
        }
    }
}

fn should_queue_path(
    root: &Path,
    ignore_set: &EffectiveIgnoreSet,
    path: &Path,
    kind: FsChangeKind,
) -> bool {
    let Ok(relative_path) = path.strip_prefix(root) else { return false };
    if relative_path.as_os_str().is_empty() {
        return false;
    }
    if is_ignore_file_relative_path(relative_path) {
        return true;
    }
    // Lstat-equivalent, not `path.is_dir` — a symlink to a
    // directory must be treated as a (symlink) leaf for ignore-pattern
    // purposes, not as a directory, matching the scanner's classification
    // and keeping this consistent with `is_real_directory` above.
    let is_dir = matches!(kind, FsChangeKind::CreatedOrModified) && is_real_directory(path);
    !ignore_set.is_ignored(relative_path, is_dir)
}

/// True only for a genuine directory — never for a symlink, even one
/// whose target is a directory (the watcher must never treat a symlink
/// as something to register recursive/new-subtree watches into,
/// mirroring the scanner's lstat-first classification in
/// `local_change.rs`). `symlink_metadata` never follows the final path
/// component, unlike `Path::is_dir`.
fn is_real_directory(path: &Path) -> bool {
    path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false)
}

/// Now called only from `spawn_new_directory_registrar`'s tokio task,
/// never from the watcher callback thread directly (see the module doc
/// comment for why).
/// Returns an empty `Vec` both when registration genuinely finds nothing
/// new to watch and when there is nothing to do (the watcher has already
/// been dropped, e.g. a shutdown race between this call and
/// `FolderWatcher`/`WatcherGuard` being dropped) — the caller's
/// reconciling scan is harmless to run on an empty list in either case,
/// and treating "already gone" as an error would just be extra noise on
/// an ordinary shutdown path. A non-empty `Vec` lists every directory this
/// call newly registered a watch on (each is a genuine `stop`/recreate
/// cycle on the underlying OS watch — see the module doc comment — so the
/// caller reconciles each one's contents).
fn register_new_directory_tree(
    watcher_holder: &Weak<Mutex<Option<RecommendedWatcher>>>,
    watched_dirs: &Arc<Mutex<HashSet<PathBuf>>>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) -> Result<Vec<PathBuf>, SyncError> {
    let Some(watcher_holder) = watcher_holder.upgrade() else { return Ok(Vec::new()) };
    let mut watcher_guard = watcher_holder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(watcher) = watcher_guard.as_mut() else { return Ok(Vec::new()) };
    let mut watched = watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    register_non_ignored_directories(watcher, &mut watched, root, start, ignore_set)
}

/// Returns every directory under `start`'s subtree this call newly
/// registered a watch on — empty when every directory in `start`'s
/// subtree was already registered (`watched.insert` returning `false`
/// throughout), so no OS-level `stop`/recreate cycle occurred and there
/// is nothing for a caller to reconcile.
fn register_non_ignored_directories<W: Watcher>(
    watcher: &mut W,
    watched: &mut HashSet<PathBuf>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) -> Result<Vec<PathBuf>, SyncError> {
    // Defense-in-depth: refuse to walk from a symlink root.
    // walkdir's `follow_links(false)` (explicit below) does NOT protect an
    // explicitly-given walk root — verified empirically that
    // `WalkDir::new(symlink_to_dir)` still descends into the target at
    // depth 1 even in non-following mode; only entries *discovered
    // during* a walk are protected by `follow_links(false)`. The one
    // caller that can pass a freshly-observed path here
    // (`register_new_directory_tree`, from the watcher callback) already
    // guards this via `is_real_directory` before ever reaching this
    // function, but this holds the invariant even if a future call site
    // forgets to.
    match start.symlink_metadata() {
        Ok(m) if m.is_dir() => {}
        _ => return Ok(Vec::new()),
    }

    let walker =
        walkdir::WalkDir::new(start).follow_links(false).into_iter().filter_entry(|entry| {
            if entry.depth() == 0 && entry.path() == root {
                return true;
            }
            if !entry.file_type().is_dir() {
                return true;
            }
            let Ok(relative_path) = entry.path().strip_prefix(root) else { return false };
            !ignore_set.is_ignored(relative_path, true)
        });

    let mut newly_registered = Vec::new();
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_dir() {
            continue;
        }
        if watched.insert(entry.path().to_path_buf()) {
            watcher.watch(entry.path(), RecursiveMode::NonRecursive).map_err(SyncError::from)?;
            newly_registered.push(entry.path().to_path_buf());
        }
    }
    Ok(newly_registered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingWatcher {
        watched: Vec<PathBuf>,
    }

    impl Watcher for RecordingWatcher {
        fn new<F: notify::EventHandler>(
            _event_handler: F,
            _config: notify::Config,
        ) -> notify::Result<Self> {
            Ok(Self::default())
        }

        fn watch(&mut self, path: &Path, _recursive_mode: RecursiveMode) -> notify::Result<()> {
            self.watched.push(path.to_path_buf());
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
        assert!(
            overflowed.load(Ordering::Relaxed),
            "a full channel must be recorded as an overflow"
        );
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
        let mut watcher =
            watch_folder_with_capacity_and_ignore(dir.path(), 32, ignore_set).unwrap();

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
        let mut watcher =
            watch_folder_with_capacity_and_ignore(dir.path(), 32, ignore_set).unwrap();

        std::fs::write(dir.path().join(".yadorilinkignore"), b"*.tmp\n").unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), watcher.events.recv())
            .await
            .expect("timed out waiting for ignore-file event")
            .expect("watcher channel closed");
        assert_eq!(
            event.path.file_name().and_then(|name| name.to_str()),
            Some(".yadorilinkignore")
        );
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
        let watched_dirs = Arc::new(Mutex::new(HashSet::new()));
        let mut watcher = RecordingWatcher::default();

        let mut watched = watched_dirs.lock().unwrap();
        let result =
            register_non_ignored_directories(&mut watcher, &mut watched, &root, &link, &ignore_set);
        assert!(result.is_ok(), "must not error, just decline to register anything");
        assert!(watched.is_empty(), "a symlink start must never result in any registered watch");
        assert!(watcher.watched.is_empty());
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
        let mut watched = HashSet::new();
        let mut watcher = RecordingWatcher::default();
        let registered =
            register_non_ignored_directories(&mut watcher, &mut watched, &root, &root, &ignore_set)
                .unwrap();

        assert_eq!(registered, watcher.watched);
        assert!(registered.contains(&root));
        assert!(registered.contains(&root.join("cyc")));
        assert!(!registered.contains(&root.join("cyc/a")));
    }
}
