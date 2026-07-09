//! Bridges a raw filesystem event (the watcher) into an indexed,
//! chunked `FileRecord` . Local changes are always
//! indexed immediately regardless of the link's pause state — pausing
//! only stops *propagating* changes to peers, so nothing is
//! lost while paused; `SyncState` itself is the queued-change backlog.
//!
//! The "rename doesn't re-transfer content" falls out of this
//! design for free: chunking is content-addressed, so renaming a file
//! without editing it re-derives the exact same block hashes the local
//! store (and any peer that already synced the old path) already holds —
//! `ensure_blocks_present`'s dedup check means no bytes cross the network
//! for the unchanged content, even though the wire protocol has no
//! dedicated "rename" message.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use crate::chunker::{chunk_file, chunk_file_content_defined, CDC_SIZE_THRESHOLD};
use crate::debounce::DebounceFlush;
use crate::error::SyncError;
use crate::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use crate::index::SyncState;
use crate::presence::office_lock_file_target;
use crate::types::{
    owner_exec_bit_from_metadata, ChunkingPolicy, FileRecord, MaterializationState, RecordKind,
};
use crate::watcher::{FsChangeEvent, FsChangeKind};

/// Same shape as this crate's other private `now_unix_nanos` helpers —
/// the default `process_event_with_ignore_at`'s `Removed` branch falls
/// back to when the caller has no better (debounce-observed) timestamp
/// to supply.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// What one filesystem event turned out to mean, once interpreted —
/// `process_event`'s result. Distinct from a plain `Option<FileRecord>`
/// since an Office lock-file event (`edit-presence-awareness`) is
/// meaningful but must never be indexed/versioned/propagated as an
/// ordinary file change (spec "Lock file is never treated as a synced
/// file itself").
#[derive(Debug, Clone, PartialEq)]
pub enum LocalChangeOutcome {
    /// Nothing worth acting on: a directory event, a file that vanished
    /// again before it could be read, a placeholder's own write, or
    /// content that hashed identical to what was already indexed.
    None,
    /// An ordinary file was created, modified, or deleted.
    FileChanged(FileRecord),
    /// A `Removed` event for a path with no index row of its own
    /// (directories are never tracked as their own row — see
    /// `build_record_for_created_or_modified`'s doc comment) turned out
    /// to have live child records still indexed underneath it as a
    /// directory prefix (i.e. `path` used to be a directory that was
    /// deleted, or renamed away, and this device never
    /// received/synthesized an individual event for each child inside
    /// it — see `watcher.rs`'s `RenameMode::From` handling). Every such
    /// child has now been tombstoned; each is reported here so the
    /// caller broadcasts all of them, not just one.
    FilesChanged(Vec<FileRecord>),
    /// This device started (`editing: true`) or stopped (`false`) editing
    /// `path` (relative to the linked folder — the *original* file's
    /// path, not the lock file's), per Office's lock-file convention.
    PresenceChanged { path: String, editing: bool },
}

/// Extra classification produced when `build_record_for_created_or_modified`
/// determines a path is a symlink — carried
/// alongside, not inside, the `FileRecord` it returns. Like
/// `types::RecordKind` itself (see its doc comment), this is index-local
/// metadata surfaced through dedicated `SyncState` columns
/// (`set_record_kind`/`set_symlink_target`/`set_symlink_out_of_root`)
/// rather than a `FileRecord` field, so every existing `FileRecord { .. }`
/// construction site keeps compiling unchanged. The caller applies it via
/// `LocalChangeProcessor::apply_symlink_classification` immediately after
/// writing the `FileRecord` itself (`upsert_file`/`upsert_files_batch`),
/// since those setters require the row to already exist.
#[derive(Debug, Clone, PartialEq)]
struct SymlinkClassification {
    /// The raw, unresolved target text exactly as returned by
    /// `std::fs::read_link` — never dereferenced.
    target: String,
    /// `true` when the target is an absolute path, or —
    /// resolved syntactically (never touching the filesystem) against the
    /// symlink's own parent directory — lands outside the linked folder's
    /// root.
    out_of_root: bool,
}

pub struct LocalChangeProcessor {
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
    device_id: String,
}

/// How much of a disk-vs-index reconciliation scan is allowed to mutate
/// the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileScope {
    /// The full startup / burst-fallback reconciliation: index new files,
    /// re-version files whose on-disk content changed, drop now-ignored
    /// rows, and tombstone indexed files no longer on disk.
    Full,
    /// Add-only: index *only* files present on disk with no existing index
    /// row. Never re-versions a file that already has a row and never
    /// tombstones a row whose path isn't on disk. This is the sole
    /// disk-reconcile shape safe to run on a frequent, unconditional
    /// schedule (the periodic backstop for OS-watcher event loss): a
    /// file with no index row has never been broadcast and so cannot
    /// collide with a
    /// concurrent mid-conflict resolution the way re-versioning or
    /// tombstoning an already-known path can (the hazard `watcher.rs`'s
    /// module doc documents as "found unsafe").
    AddOnly,
}

impl LocalChangeProcessor {
    pub fn new(
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
        device_id: String,
    ) -> Self {
        Self { state, store, device_id }
    }

    /// Indexes every pre-existing file under `root` that isn't already
    /// indexed (`sync-engine` spec's "Initial Full Sync" requirement).
    /// Necessary because a filesystem watcher, by nature, only reports
    /// changes from the moment it starts — files already present when a
    /// folder is linked (or created while the daemon wasn't running)
    /// would otherwise never enter the index at all. Call once, before
    /// starting the live watch on `root`.
    ///
    /// Skips files whose size already matches an existing, non-deleted
    /// index entry, so restarting the daemon doesn't spuriously bump every
    /// unchanged file's version vector on every scan.
    ///
    /// batch-sync-optimizations : the existing index and
    /// materialization states are bulk-loaded once up front (rather than
    /// one `get_file`/`get_materialization_state` query per walked entry),
    /// and every newly-indexed or changed record is committed in a single
    /// transaction at the end — so a folder with a very large number of
    /// pre-existing files (e.g. a git repository's `.git/objects/`) scans
    /// in a bounded number of SQLite round trips rather than one per file.
    pub fn scan_existing_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, SyncError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.scan_existing_files_with_ignore(group_id, root, &ignore_set)
    }

    pub fn scan_existing_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, SyncError> {
        self.reconcile_disk_with_ignore(group_id, root, ignore_set, ReconcileScope::Full)
    }

    /// The add-only disk reconcile the periodic backstop runs. Walks
    /// `root` and returns/indexes a `FileRecord` only for a regular file
    /// or symlink that is present on disk but has **no** existing index
    /// row — recovering a local write whose OS filesystem-watcher event
    /// was never delivered (e.g. it fell into an FSEvents stream-recreate
    /// blind window, see `watcher.rs`'s module doc). It
    /// never re-versions an already-indexed file whose on-disk content
    /// changed and never tombstones an indexed file missing from disk (both
    /// of which `scan_existing_files_with_ignore` does): those mutate an
    /// already-known path and are unsafe to run this often (they can
    /// re-derive or false-delete a file mid-conflict-resolution between two
    /// devices). Indexing a file that has no row yet is byte-for-byte what a
    /// live create event would have done, so it carries none of that hazard.
    pub fn reconcile_added_files_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, SyncError> {
        self.reconcile_disk_with_ignore(group_id, root, ignore_set, ReconcileScope::AddOnly)
    }

    /// Like `reconcile_added_files_with_ignore`, but loads `root`'s ignore
    /// set itself — the periodic backstop's own convenience entry point,
    /// mirroring `scan_existing_files`'s relationship to `scan_existing_
    /// files_with_ignore`.
    pub fn reconcile_added_files(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<Vec<FileRecord>, SyncError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.reconcile_added_files_with_ignore(group_id, root, &ignore_set)
    }

    fn reconcile_disk_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        scope: ReconcileScope,
    ) -> Result<Vec<FileRecord>, SyncError> {
        // Canonicalize once, up front, so paths built by walking `root`
        // match what `process_event` will independently canonicalize
        // `root` to internally — otherwise `strip_prefix` inside
        // `process_event` silently fails for every entry (the same class
        // of mismatch its own doc comment warns about for OS watchers).
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let root = root.as_path();

        let existing_by_path: std::collections::HashMap<String, FileRecord> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .map(|record| (record.path.clone(), record))
            .collect();
        let materialization_by_path = self.state.list_materialization_states(group_id)?;

        // Becoming ignored is not a deletion. Drop this device's local
        // index row so future sync work no longer considers the path,
        // but do not emit a tombstone and do not touch the on-disk file.
        // This mutates an existing index row, so it is a
        // `Full`-scope-only step — the add-only backstop never removes
        // or re-versions a known path.
        if scope == ReconcileScope::Full {
            let ignored_existing_paths: Vec<String> = existing_by_path
                .keys()
                .filter(|path| is_excluded_from_sync(Path::new(path), false, ignore_set))
                .cloned()
                .collect();
            for path in &ignored_existing_paths {
                self.state.remove_file(group_id, path)?;
            }
        }

        let mut records = Vec::new();
        let mut seen_paths = std::collections::HashSet::new();
        // Classification info for any symlink discovered this scan,
        // applied via `SyncState` setters once the corresponding
        // `FileRecord` rows are actually written below (those setters
        // require the row to already exist).
        let mut pending_symlinks: Vec<(String, SymlinkClassification)> = Vec::new();
        // Exec-bit updates for paths
        // whose content (size) is unchanged this scan, applied after the
        // batch write below for the same reason `pending_symlinks` is —
        // `SyncState::set_exec_bit` is `UPDATE`-only and requires the row
        // to already exist.
        let mut pending_exec_bits: Vec<(String, bool)> = Vec::new();
        // `follow_links(false)` is walkdir's default, but stated
        // explicitly here — verified (not assumed) that this default is
        // what makes a symlinked directory get enumerated as a single
        // leaf entry rather than descended into; see
        // `watcher::register_non_ignored_directories` for the one place
        // that default alone was NOT sufficient (an explicitly-given walk
        // root that is itself a symlink is still descended into even with
        // `follow_links(false)` — a walkdir quirk that doesn't apply here
        // since `root` is always canonicalized above, but is guarded
        // there defensively regardless).
        let walker =
            walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                let Ok(rel_path) = entry.path().strip_prefix(root) else { return false };
                !is_excluded_from_sync(rel_path, entry.file_type().is_dir(), ignore_set)
            });
        for entry in walker.filter_map(Result::ok) {
            // A symlink (whatever it points to) is admitted
            // here as its own leaf entry — `entry.file_type()` reflects
            // lstat metadata (never follows) since `follow_links(false)`
            // is in effect, so a symlink to a directory shows up here as
            // `is_symlink() == true`, `is_dir() == false`, and walkdir
            // never descends into it to enumerate its contents. Anything
            // that's neither a regular file nor a symlink (a directory,
            // or something exotic) is skipped, same as before.
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            let Ok(rel_path) = path.strip_prefix(root) else { continue };
            let rel_path = rel_path.to_string_lossy().replace('\\', "/");
            if is_excluded_from_sync(Path::new(&rel_path), false, ignore_set) {
                continue;
            }

            // A lock file left over from a prior session (e.g. after a
            // crash) is not a "pre-existing file needing indexing" at
            // all — it's not indexed even when freshly observed by
            // `process_event` below, so scanning it is a pure no-op; skip
            // it outright rather than paying for the lookup. Deliberately
            // not added to `seen_paths` either: a lock file was never
            // indexed under its own name, so it can't be tombstoned
            // below. (Office lock files are never symlinks in practice,
            // but the check is skipped for one anyway rather than relying
            // on that.)
            if !file_type.is_symlink()
                && office_lock_file_target(entry.file_name().to_str().unwrap_or("")).is_some()
            {
                continue;
            }
            seen_paths.insert(rel_path.clone());

            let existing = existing_by_path.get(&rel_path).cloned();

            // In add-only scope, a path that already has an index row is
            // left entirely untouched — no re-hash, no re-version, no
            // exec-bit update. The backstop only recovers files the
            // index has never seen (whose live watcher event was lost);
            // anything already indexed is the live watcher's /
            // conflict-resolution's business, and re-deriving it here is
            // exactly the unsafe re-versioning `watcher.rs`'s module doc
            // warns about.
            if scope == ReconcileScope::AddOnly && existing.is_some() {
                continue;
            }

            let entry_metadata = entry.metadata().ok();
            let already_current = match (&existing, &entry_metadata) {
                (Some(existing), Some(metadata)) => {
                    !existing.deleted && existing.size == metadata.len()
                }
                _ => false,
            };
            if already_current {
                // Content (size) is
                // unchanged, but this file's exec bit may never have been
                // captured at all (it predates this change and the
                // `exec_bit` column defaults to `false`), or may have been
                // chmod-only-changed since the last scan with no live
                // watcher running to catch it via
                // `build_record_for_created_or_modified`'s own fast path.
                // Reuse the `Metadata` already fetched above for the size
                // comparison — no extra syscall — rather than falling
                // through to that function's full machinery for what is,
                // by definition here, an unchanged-content file. Symlinks
                // carry no exec bit, so this only
                // applies to a genuine regular file.
                if file_type.is_file() {
                    if let (Some(existing), Some(metadata)) = (&existing, &entry_metadata) {
                        let on_disk_exec_bit = owner_exec_bit_from_metadata(metadata);
                        let indexed_exec_bit = self.state.get_exec_bit(group_id, &rel_path)?;
                        if on_disk_exec_bit != indexed_exec_bit {
                            let mut record = existing.clone();
                            record.version.increment(&self.device_id);
                            records.push(record);
                            pending_exec_bits.push((rel_path.clone(), on_disk_exec_bit));
                        }
                    }
                }
                continue;
            }

            let materialization_state = materialization_by_path.get(&rel_path).copied();
            let (outcome, classification, exec_bit) = self.build_record_for_created_or_modified(
                group_id,
                root,
                rel_path.clone(),
                path,
                existing,
                materialization_state,
            )?;
            if let LocalChangeOutcome::FileChanged(record) = outcome {
                records.push(record);
                if let Some(classification) = classification {
                    pending_symlinks.push((rel_path.clone(), classification));
                }
                if let Some(exec_bit) = exec_bit {
                    pending_exec_bits.push((rel_path, exec_bit));
                }
            }
        }

        // COR-2: the walk above only ever adds/updates files that still
        // exist on disk — it never notices a file that vanished (deleted,
        // or renamed away, since the watcher classifies a rename-source
        // as `CreatedOrModified`, see `watcher.rs`). Without this, a
        // missed removal propagates to peers as a live file forever, and
        // even the "full reconciliation" this function IS the recovery
        // path for can't fix it. Tombstone any indexed, not-already-
        // deleted file whose path wasn't observed in this walk.
        // Tombstoning increments an existing row's version, so it is
        // `Full`-scope only — the add-only backstop never deletes a
        // known path (a file missing from disk this pass might be
        // mid-materialization or mid-conflict-resolution; only the
        // deliberate full reconciliation is allowed to tombstone).
        if scope == ReconcileScope::Full {
            for (path, existing) in &existing_by_path {
                if existing.deleted || seen_paths.contains(path) {
                    continue;
                }
                if is_excluded_from_sync(Path::new(path), false, ignore_set) {
                    continue;
                }
                let mut tombstone = existing.clone();
                tombstone.deleted = true;
                tombstone.version.increment(&self.device_id);
                records.push(tombstone);
            }
        }

        // A scan is always this device's own local content — same origin
        // as `process_event`'s single-file write path below.
        self.state.upsert_files_batch(group_id, &records, &self.device_id)?;
        // Applied after the batch write above, since
        // `set_record_kind`/`set_symlink_target`/`set_symlink_out_of_root`
        // all require the row to already exist.
        for (path, classification) in &pending_symlinks {
            self.apply_symlink_classification(group_id, path, classification)?;
        }
        // wire-local-exec-bit-capture: same "apply after write" ordering as
        // `pending_symlinks` above.
        for (path, exec_bit) in &pending_exec_bits {
            self.state.set_exec_bit(group_id, path, *exec_bit)?;
        }
        Ok(records)
    }

    /// Processes one filesystem event under a linked folder rooted at
    /// `root`, updating the local index (for an ordinary file change) and
    /// returning what happened. The caller is responsible for
    /// broadcasting a `FileChanged` record to connected, unpaused peer
    /// sessions via `PeerSyncSession::send_index_update`, or a
    /// `PresenceChanged` signal via the presence-broadcast path
    /// (`edit-presence-awareness`) — never both for the same event.
    pub async fn process_event(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
    ) -> Result<LocalChangeOutcome, SyncError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.process_event_with_ignore(group_id, root, event, &ignore_set).await
    }

    pub async fn process_event_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<LocalChangeOutcome, SyncError> {
        self.process_event_with_ignore_at(group_id, root, event, ignore_set, None).await
    }

    /// Like `process_event_with_ignore`, but for a `Removed` event lets the
    /// caller supply the watcher's own observed time for `mark_deleted_at`
    /// instead of defaulting to "now" — see `mark_deleted_at`'s doc comment
    /// for why this matters. `process_flush_with_ignore` (the debounced
    /// batch path, where an event may have been sitting in the debounce
    /// accumulator for a while before this dispatch runs) is the only
    /// caller that has a better answer than "now"; every direct
    /// `process_event`/`process_event_with_ignore` caller (a live
    /// undebounced call, every existing test) keeps getting `None` =>
    /// "now", identical to this method's behavior before this parameter
    /// existed.
    async fn process_event_with_ignore_at(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
        observed_at_unix_nanos: Option<i64>,
    ) -> Result<LocalChangeOutcome, SyncError> {
        // OS-level watchers (notify's FSEvents backend on macOS in
        // particular) report fully-resolved paths — e.g. `/private/var/...`
        // rather than the `/var/...` symlink most callers construct their
        // root from (via `tempfile::tempdir()` or otherwise). Without
        // canonicalizing `root` too, `strip_prefix` below silently fails
        // for every event, and no local change is ever detected. `root`
        // is the watched directory itself, so it's expected to still
        // exist here (unlike `event.path`, which may already be gone for
        // a `Removed` event and so isn't safe to canonicalize).
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let Ok(rel_path) = event.path.strip_prefix(&root) else {
            return Ok(LocalChangeOutcome::None);
        };
        let rel_path = rel_path.to_string_lossy().replace('\\', "/");
        if rel_path.is_empty() {
            return Ok(LocalChangeOutcome::None);
        }
        if is_ignore_file_relative_path(Path::new(&rel_path)) {
            return Ok(LocalChangeOutcome::None);
        }

        // Office lock-file convention: recognized before any
        // ordinary indexing logic runs — per spec, `~$<name>.<ext>` is
        // never indexed, versioned, or propagated as a normal file.
        // Appearance/disappearance instead signals this device starting
        // or stopping editing the *original* file.
        let filename = Path::new(&rel_path).file_name().and_then(|f| f.to_str()).unwrap_or("");
        if let Some(target_name) = office_lock_file_target(filename) {
            let target_rel_path = match Path::new(&rel_path).parent() {
                Some(parent) if parent != Path::new("") => {
                    format!("{}/{}", parent.to_string_lossy(), target_name)
                }
                _ => target_name.to_string(),
            };
            let editing = matches!(event.kind, FsChangeKind::CreatedOrModified);
            return Ok(LocalChangeOutcome::PresenceChanged { path: target_rel_path, editing });
        }
        if is_excluded_from_sync(&rel_path, event.path.is_dir(), ignore_set) {
            return Ok(LocalChangeOutcome::None);
        }

        // COR-5: hold the per-(group,path) lock for the whole
        // read-compare-write below, so this local-change indexing can
        // never interleave with `PeerSyncSession::reconcile_one_file`
        // applying an incoming version for the same path concurrently —
        // see `SyncState::path_lock`'s doc comment.
        let path_lock = self.state.path_lock(group_id, &rel_path);
        let _guard = path_lock.lock().await;

        // `event.kind` reflects whatever `debounce.rs`'s per-path
        // coalescing last saw
        // -- a `HashMap<PathBuf, FsChangeKind>` where a later event for
        // the same path simply overwrites an earlier one. A genuine local
        // deletion's `Removed` event can be overwritten within the same
        // debounce window by an unrelated `CreatedOrModified` event for
        // the identical path -- most commonly this device's own sync
        // engine materializing an incoming peer update (a real disk
        // write the watcher can't distinguish from a genuine local edit)
        // racing this device's own delete -- silently discarding the
        // fact that a deletion ever happened, with no error and no
        // trace: `mark_deleted` (the `Removed` branch below) is simply
        // never called for this flush. Re-deriving whether the path is
        // currently a live entry directly from disk here, immediately
        // before dispatch, rather than trusting the coalesced kind,
        // closes this whole class of watcher-kind-vs-reality mismatches
        // symmetrically (a stale `CreatedOrModified` whose target has
        // since been deleted is exactly as wrong as a stale `Removed`
        // whose target has since been recreated) -- this is the same
        // principle Syncthing (`lib/model/folder.go`'s `scanSubdirs`,
        // reached via its watch-aggregator regardless of the aggregated
        // event kind), Nextcloud desktop (`discovery.cpp`'s `localEntry`
        // re-stat, ignoring `FolderWatcher`'s untyped path-only signal),
        // and Unison (diffing current disk state against the last-synced
        // archive) all independently converge on: the watcher is a
        // trigger to re-examine a path, not a source of truth for
        // classifying what happened to it. `symlink_metadata` (not
        // `Path::exists`, which follows symlinks) matches this file's
        // own lstat-first convention elsewhere (see
        // `build_record_for_created_or_modified`'s identical check just
        // below, and `is_real_directory` in `watcher.rs`).
        let effective_kind = if event.path.symlink_metadata().is_ok() {
            FsChangeKind::CreatedOrModified
        } else {
            FsChangeKind::Removed
        };

        match effective_kind {
            FsChangeKind::Removed => {
                // COR-8: `mark_deleted` creates a brand-new tombstone row
                // even for a path that was never indexed — an editor's
                // atomic-save (temp file created then renamed away)
                // coalesces to exactly this case, and peers would
                // otherwise receive and store a tombstone for a file they
                // never had, accumulating mesh-wide junk over repeated
                // saves. Only mark-deleted (and broadcast) a path that
                // already has an index entry.
                if self.state.get_file(group_id, &rel_path)?.is_none() {
                    // `rel_path` itself was never a tracked file (a
                    // directory is never its own index row), but it may
                    // just have been a directory that disappeared —
                    // deleted outright, or renamed away (`watcher.rs`'s
                    // `RenameMode::From` reports the vacated directory
                    // path itself as an ordinary `Removed` event, no
                    // different from a single file's delete; nothing
                    // synthesizes an individual event for whatever used
                    // to live inside it). If this device still has any
                    // live records filed under `rel_path` as a directory
                    // prefix, they are now orphaned: the directory that
                    // held them is confirmed gone from disk, so a later
                    // local recreation at the exact same relative path
                    // must not find that stale row still "existing" and
                    // treat a brand-new write as an edit to it, silently
                    // inheriting whatever version-vector history a peer
                    // may have since merged into it (confirmed via
                    // `taguchi_collision_matrix_v3.rs`'s row 9: a real,
                    // reproducible silent-content-loss shape, not merely
                    // a convergence delay).
                    let prefix = format!("{rel_path}/");
                    let orphaned: Vec<String> = self
                        .state
                        .list_files(group_id)?
                        .into_iter()
                        .filter(|r| !r.deleted && r.path.starts_with(&prefix))
                        .map(|r| r.path)
                        .collect();
                    if orphaned.is_empty() {
                        return Ok(LocalChangeOutcome::None);
                    }
                    let now = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                    let mut records = Vec::with_capacity(orphaned.len());
                    for orphan_path in &orphaned {
                        self.state.mark_deleted_at(group_id, orphan_path, &self.device_id, now)?;
                        if let Some(record) = self.state.get_file(group_id, orphan_path)? {
                            records.push(record);
                        }
                    }
                    return Ok(LocalChangeOutcome::FilesChanged(records));
                }
                self.state.mark_deleted_at(
                    group_id,
                    &rel_path,
                    &self.device_id,
                    observed_at_unix_nanos.unwrap_or_else(now_unix_nanos),
                )?;
                Ok(match self.state.get_file(group_id, &rel_path)? {
                    Some(record) => LocalChangeOutcome::FileChanged(record),
                    None => LocalChangeOutcome::None,
                })
            }
            FsChangeKind::CreatedOrModified => {
                let materialization_state =
                    self.state.get_materialization_state(group_id, &rel_path)?;
                let existing = self.state.get_file(group_id, &rel_path)?;
                let (outcome, classification, exec_bit) = self
                    .build_record_for_created_or_modified(
                        group_id,
                        &root,
                        rel_path.clone(),
                        &event.path,
                        existing,
                        materialization_state,
                    )?;
                if let LocalChangeOutcome::FileChanged(record) = &outcome {
                    // A local edit's origin is this device itself.
                    self.state.upsert_file_with_origin(group_id, record, &self.device_id)?;
                    // Applied after the write above, since
                    // the setters require the row to already exist.
                    if let Some(classification) = &classification {
                        self.apply_symlink_classification(group_id, &rel_path, classification)?;
                    }
                    // wire-local-exec-bit-capture: same ordering
                    // requirement as symlink classification above —
                    // `SyncState::set_exec_bit` is `UPDATE`-only and
                    // requires the row to already exist.
                    if let Some(exec_bit) = exec_bit {
                        self.state.set_exec_bit(group_id, &rel_path, exec_bit)?;
                    }
                }
                Ok(outcome)
            }
        }
    }

    /// Builds the `FileRecord` for a `CreatedOrModified` event without
    /// writing it to the index — shared by `process_event` (which writes
    /// immediately, one file at a time) and `scan_existing_files` (which
    /// batches writes via `upsert_files_batch`, batch-sync-optimizations
    /// ). `existing` and `materialization_state` are supplied by
    /// the caller rather than looked up here, so a bulk-loading caller
    /// (`scan_existing_files`) never issues a per-file query for them.
    ///
    /// wire-local-exec-bit-capture: the third element of the returned tuple
    /// is the owner-exec bit to persist via `SyncState::set_exec_bit`, when
    /// this call determined one needs capturing — `None` for a symlink
    /// (no exec bit of its own) or when nothing changed. Returned rather
    /// than applied directly here, mirroring `SymlinkClassification`'s own
    /// "apply after write" shape: `set_exec_bit` is `UPDATE`-only and the
    /// index row may not exist yet at this point (a brand-new file, not
    /// written until the caller's `upsert_file_with_origin`/
    /// `upsert_files_batch` runs).
    fn build_record_for_created_or_modified(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        materialization_state: Option<MaterializationState>,
    ) -> Result<(LocalChangeOutcome, Option<SymlinkClassification>, Option<bool>), SyncError> {
        // classify via an lstat-equivalent check first —
        // `symlink_metadata` never follows the final path component,
        // unlike `Path::is_file`/`std::fs::metadata` (used further below,
        // now only reached once a symlink has already been ruled out
        // here, so those later calls are safe to leave following-by-
        // default: at that point `path` is confirmed to be a genuine
        // regular file, not a symlink, so stat and lstat agree anyway).
        let Ok(lstat) = std::fs::symlink_metadata(path) else {
            return Ok((LocalChangeOutcome::None, None, None)); // already gone again
        };

        if lstat.file_type().is_symlink() {
            let (outcome, classification) =
                self.build_symlink_record(group_id, root, rel_path, path, existing, &lstat)?;
            return Ok((outcome, classification, None));
        }

        if !lstat.is_file() {
            return Ok((LocalChangeOutcome::None, None, None)); // directory event, or exotic entry
        }

        // A placeholder's own creation/refresh (`peer_session::materialize`
        // writing a sparse file for an `OnDemand` folder — see
        // `chunker::write_placeholder`) fires this same
        // `CreatedOrModified` event on this device's own watcher. Its
        // content is a sparse stand-in, not the file's real bytes, so
        // chunking it would both waste effort and index wrong block
        // hashes — skip immediately, mirroring the self-echo suppression
        // below but before the expensive (and here, actively incorrect)
        // chunking step.
        if matches!(
            materialization_state,
            Some(MaterializationState::Placeholder | MaterializationState::Hydrating)
        ) {
            return Ok((LocalChangeOutcome::None, None, None));
        }

        // sync-performance PERF-2: a size+mtime fast-path, checked before
        // any chunking. A filesystem watcher routinely reports a
        // `CreatedOrModified` event for a file whose bytes never actually
        // changed — this device's own self-echo (see the block-hash
        // comparison further down, which already resolves this case to
        // `None`, just after paying for a full read+chunk+hash first), an
        // editor's atomic rewrite that restores identical content, or a
        // backup/sync tool that bumps mtime without touching bytes. When
        // both `size` *and* `mtime` match a non-deleted index entry, trust
        // that match and skip straight to `None` — a `stat` is orders of
        // magnitude cheaper than reading and chunking the whole file.
        //
        // Trade-off, deliberate: this is a quick check, not a guarantee —
        // exactly the same trust model rsync's default (non `--checksum`)
        // mode uses. A pathological writer that changes a file's bytes
        // while preserving both its exact size and its exact mtime (e.g.
        // an explicit `utimes` restore after editing) would be missed.
        // That combination essentially never happens by accident, and the
        // whole point of this optimization is to avoid re-reading content
        // to rule it out; anything that changes size or mtime — the
        // overwhelming majority of real edits — still falls through to
        // the full chunk-and-compare path below.
        if let Some(existing) = &existing {
            if !existing.deleted {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let current_mtime_matches = metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i64)
                        == Some(existing.mtime_unix_nanos);
                    if existing.size == metadata.len() && current_mtime_matches {
                        // Size and
                        // mtime matching isn't the whole "nothing changed"
                        // story — a `chmod` (owner-exec bit toggle) touches
                        // neither, so compare the exec bit too, off the
                        // same `Metadata` already fetched above (no extra
                        // syscall), before trusting this fast path's no-op
                        // conclusion. When only the exec bit differs, this
                        // is exactly the "metadata-only change" shape
                        // `try_apply_metadata_only_update` (`peer_session.
                        // rs`) already applies on the receiving side for a
                        // peer's advertised bit — mirrored here for local
                        // capture: bump the version (broadcast-worthy)
                        // without re-chunking.
                        let on_disk_exec_bit = owner_exec_bit_from_metadata(&metadata);
                        let indexed_exec_bit = self.state.get_exec_bit(group_id, &rel_path)?;
                        if on_disk_exec_bit == indexed_exec_bit {
                            // size, mtime, AND exec bit all
                            // unchanged — preserve the existing no-op
                            // behavior exactly.
                            return Ok((LocalChangeOutcome::None, None, None));
                        }
                        let mut record = existing.clone();
                        record.version.increment(&self.device_id);
                        return Ok((
                            LocalChangeOutcome::FileChanged(record),
                            None,
                            Some(on_disk_exec_bit),
                        ));
                    }
                }
            }
        }

        // content-defined-chunking : content-defined chunking
        // only applies when the link opted in *and* the file is at or
        // above the size threshold — everything else uses the original
        // fixed-size chunker unchanged, so self-echo suppression below
        // (which just compares whatever this device's chunker just
        // produced against what's indexed) needs no algorithm-awareness
        // either way ().
        let use_cdc = self.state.chunking_policy_for_group(group_id)?
            == Some(ChunkingPolicy::ContentDefined)
            && std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= CDC_SIZE_THRESHOLD;
        let blocks = if use_cdc {
            chunk_file_content_defined(self.store.as_ref(), path)?
        } else {
            chunk_file(self.store.as_ref(), path)?
        };

        // Content-addressed dedup, applied here as self-echo suppression:
        // applying a peer's update writes the file to disk
        // (`peer_session::materialize`), which — with no special-casing —
        // this *same* watcher would otherwise see as a brand-new local
        // edit, increment the version for, and rebroadcast, which the
        // peer's own watcher then does right back, forever, racing into
        // spurious conflicts. If the
        // freshly chunked content hashes to exactly the blocks already
        // indexed, nothing actually changed — regardless of *why* the fs
        // event fired — so there is nothing to re-index.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.blocks == blocks {
                return Ok((LocalChangeOutcome::None, None, None));
            }
        }

        let metadata = std::fs::metadata(path)?;
        let mtime_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        // Content genuinely changed
        // (or this is a brand-new file), reached below the fast path above
        // — capture the exec bit here too, off the same `Metadata` already
        // fetched for `mtime_unix_nanos`, so a brand-new executable file's
        // exec bit is indexed from its first appearance rather than only
        // discoverable later via a subsequent metadata-only update.
        let exec_bit = owner_exec_bit_from_metadata(&metadata);

        let mut version = existing.map(|f| f.version).unwrap_or_default();
        version.increment(&self.device_id);

        let record = FileRecord {
            path: rel_path,
            size: metadata.len(),
            mtime_unix_nanos,
            version,
            blocks,
            deleted: false,
        };
        Ok((LocalChangeOutcome::FileChanged(record), None, Some(exec_bit)))
    }

    /// Builds a symlink leaf record: the target's raw text
    /// and the out-of-root/absolute flag, never dereferencing the target
    /// to decide either. No content is read or chunked — a symlink record
    /// carries no blocks ().
    fn build_symlink_record(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: String,
        path: &Path,
        existing: Option<FileRecord>,
        lstat: &std::fs::Metadata,
    ) -> Result<(LocalChangeOutcome, Option<SymlinkClassification>), SyncError> {
        // `read_link` reads the raw target text without dereferencing it —
        // safe, unlike `metadata`/`canonicalize`, which is exactly the
        // dereference forbids.
        let raw_target = std::fs::read_link(path)?;
        let target_text = raw_target.to_string_lossy().into_owned();
        let out_of_root = symlink_target_is_out_of_root(root, path, &raw_target);
        let size = lstat.len();
        let mtime_unix_nanos = lstat
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);

        // Self-echo/no-op suppression, mirroring the regular-file
        // fast-path above: a redundant watcher event (or an unchanged
        // rescan) for a symlink whose target text hasn't actually changed
        // must not bump the version vector every time it fires. `size`
        // alone can't disambiguate two different targets of the same
        // length, so the actual stored target text is checked too — a
        // lookup bounded to symlink paths only, not every scanned file.
        if let Some(existing) = &existing {
            if !existing.deleted && existing.size == size {
                let previously_symlink =
                    self.state.get_record_kind(group_id, &rel_path)? == Some(RecordKind::Symlink);
                let previous_target = self.state.get_symlink_target(group_id, &rel_path)?;
                if previously_symlink && previous_target.as_deref() == Some(target_text.as_str()) {
                    return Ok((LocalChangeOutcome::None, None));
                }
            }
        }

        let mut version = existing.map(|f| f.version).unwrap_or_default();
        version.increment(&self.device_id);

        let record = FileRecord {
            path: rel_path,
            size,
            mtime_unix_nanos,
            version,
            blocks: Vec::new(),
            deleted: false,
        };
        let classification = SymlinkClassification { target: target_text, out_of_root };
        Ok((LocalChangeOutcome::FileChanged(record), Some(classification)))
    }

    /// Applies a symlink's classification to its already-
    /// written index row — `SyncState::set_record_kind`/
    /// `set_symlink_target`/`set_symlink_out_of_root` all require the row
    /// to exist, so this must run strictly after the caller's
    /// `upsert_file`/`upsert_files_batch`.
    fn apply_symlink_classification(
        &self,
        group_id: &str,
        rel_path: &str,
        classification: &SymlinkClassification,
    ) -> Result<(), SyncError> {
        self.state.set_record_kind(group_id, rel_path, RecordKind::Symlink)?;
        self.state.set_symlink_target(group_id, rel_path, Some(classification.target.as_str()))?;
        self.state.set_symlink_out_of_root(group_id, rel_path, classification.out_of_root)?;
        Ok(())
    }

    /// Turns one debounce-window flush (`debounce::DebounceFlush`) into
    /// indexed records — the executor half of 's accumulator/executor
    /// split. `DebounceFlush::Paths` is processed one path at a time via
    /// `process_event` (each individually indexed and self-echo-checked,
    /// exactly as a live single-event call would be); `DebounceFlush::BurstFallback`
    /// runs a full `scan_existing_files` reconciliation instead. Presence
    /// changes encountered while processing paths are reported separately
    /// from `records` since they aren't `FileRecord`s and don't belong on
    /// the batch-broadcast path.
    ///
    /// Each path in a
    /// `DebounceFlush::Paths` batch is processed independently — one
    /// path's error (logged, not silently dropped) does not prevent the
    /// batch's other, unrelated paths from still being processed. A
    /// batch's paths come from a `HashMap` (no ordering guarantee), and
    /// the real filesystem watcher only ever fires once for a given real
    /// change: the previous behavior (`?` inside this loop, aborting the
    /// whole batch on the first error) could permanently lose an
    /// already-detected, unrelated event — including a local deletion
    /// that would otherwise have self-corrected a stale index row — to a
    /// transient failure (e.g. a exhausted-retry database-lock error
    /// under heavy concurrent load) on a completely different path
    /// earlier in iteration order.
    pub async fn process_flush(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
    ) -> Result<FlushOutcome, SyncError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.process_flush_with_ignore(group_id, root, flush, &ignore_set).await
    }

    pub async fn process_flush_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        flush: DebounceFlush,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<FlushOutcome, SyncError> {
        match flush {
            DebounceFlush::Paths(paths) => {
                let mut records = Vec::new();
                let mut presence_changes = Vec::new();
                for (path, kind, observed_at) in paths {
                    let event_path = path.clone();
                    match self
                        .process_event_with_ignore_at(
                            group_id,
                            root,
                            &FsChangeEvent { path, kind },
                            ignore_set,
                            Some(observed_at),
                        )
                        .await
                    {
                        Ok(LocalChangeOutcome::FileChanged(record)) => records.push(record),
                        Ok(LocalChangeOutcome::FilesChanged(orphaned)) => records.extend(orphaned),
                        Ok(LocalChangeOutcome::PresenceChanged { path, editing }) => {
                            presence_changes.push((path, editing));
                        }
                        Ok(LocalChangeOutcome::None) => {}
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                path = %event_path.display(),
                                group_id,
                                "failed to process one path in a debounced batch; continuing with \
                                 the rest of the batch rather than discarding it"
                            );
                        }
                    }
                }
                Ok(FlushOutcome { records, presence_changes })
            }
            DebounceFlush::BurstFallback => {
                let records = self.scan_existing_files_with_ignore(group_id, root, ignore_set)?;
                Ok(FlushOutcome { records, presence_changes: Vec::new() })
            }
        }
    }
}

fn is_excluded_from_sync(
    relative_path: impl AsRef<Path>,
    is_dir: bool,
    ignore_set: &EffectiveIgnoreSet,
) -> bool {
    let relative_path = relative_path.as_ref();
    is_ignore_file_relative_path(relative_path) || ignore_set.is_ignored(relative_path, is_dir)
}

/// path-string analysis only — never dereferences `raw_target`
/// (no `canonicalize`, no `metadata`, no filesystem read of the target at
/// all) to decide whether it escapes `root`. `link_path` is the symlink's
/// own absolute path (used only for its parent directory, to resolve a
/// relative target); `raw_target` is exactly what `std::fs::read_link`
/// returned. Returns `true` if the target is absolute, or if — resolved
/// syntactically against the symlink's parent — it lands outside `root`.
fn symlink_target_is_out_of_root(root: &Path, link_path: &Path, raw_target: &Path) -> bool {
    if raw_target.is_absolute() {
        return true;
    }
    let parent = link_path.parent().unwrap_or(link_path);
    let joined = parent.join(raw_target);
    let normalized = normalize_syntactic(&joined);
    !normalized.starts_with(root)
}

/// Syntactic (non-filesystem-touching) `.`/`..` normalization — NOT
/// `Path::canonicalize`, which resolves symlinks and touches the
/// filesystem (exactly what is forbidden here: dereferencing the
/// target is the one thing this check must not do). A `..` that has
/// nothing left to pop (already at the start of an absolute path) is kept
/// literally rather than dropped, so the caller's `starts_with(root)`
/// check conservatively treats it as escaping rather than silently
/// accepting it.
fn normalize_syntactic(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The result of processing one debounce flush — see `process_flush`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FlushOutcome {
    pub records: Vec<FileRecord>,
    /// `(path, editing)` pairs — the caller broadcasts each individually
    /// via the presence-signal path, not the batch-broadcast path.
    pub presence_changes: Vec<(String, bool)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_local_storage::FsBlockStore;

    fn processor() -> (LocalChangeProcessor, tempfile::TempDir, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        (LocalChangeProcessor::new(state, store, "device-a".into()), store_dir, root_dir)
    }

    /// `process_event` canonicalizes `root` internally (see its doc
    /// comment — real OS watchers report fully-resolved paths, e.g.
    /// macOS's `/private/var/...` for what looks like `/var/...`), so
    /// tests that hand-construct `FsChangeEvent`s (rather than using a
    /// real `watch_folder`) must build paths from an already-canonical
    /// root to stay consistent, exactly as a real watcher's paths would be.
    fn canonical_root(root_dir: &tempfile::TempDir) -> std::path::PathBuf {
        root_dir.path().canonicalize().unwrap()
    }

    fn expect_file_changed(outcome: LocalChangeOutcome) -> FileRecord {
        match outcome {
            LocalChangeOutcome::FileChanged(record) => record,
            other => panic!("expected FileChanged, got {other:?}"),
        }
    }

    /// sync-performance PERF-2: wraps a real `FsBlockStore` and counts
    /// `put` calls, so a test can prove the size+mtime fast-path actually
    /// skipped chunking (chunking always calls `put` at least once per
    /// block — see `chunker::chunk_file`) rather than merely asserting on
    /// the returned outcome, which the pre-existing self-echo suppression
    /// could also produce (just after paying for a full chunk first).
    struct CountingBlockStore {
        inner: FsBlockStore,
        put_calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingBlockStore {
        fn new(dir: &std::path::Path) -> Self {
            Self {
                inner: FsBlockStore::new(dir).unwrap(),
                put_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn put_call_count(&self) -> usize {
            self.put_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl yadorilink_local_storage::BlockStore for CountingBlockStore {
        fn put(&self, data: &[u8]) -> Result<String, yadorilink_local_storage::StorageError> {
            self.put_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.put(data)
        }
        fn get(&self, hash: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
            self.inner.get(hash)
        }
        fn delete(&self, hash: &str) -> Result<(), yadorilink_local_storage::StorageError> {
            self.inner.delete(hash)
        }
        fn exists(&self, hash: &str) -> Result<bool, yadorilink_local_storage::StorageError> {
            self.inner.exists(hash)
        }
        fn list_by_prefix(
            &self,
            prefix: &str,
        ) -> Result<Vec<String>, yadorilink_local_storage::StorageError> {
            self.inner.list_by_prefix(prefix)
        }
        // This test double's whole job is counting `put` calls (see its
        // own doc comment) — every other method,
        // this one included, is a pure passthrough to the wrapped real
        // `FsBlockStore`, not something these PERF-2 tests exercise.
        fn sweep(
            &self,
            live_hashes: &std::collections::HashSet<String>,
            older_than: std::time::SystemTime,
            dry_run: bool,
        ) -> Result<yadorilink_local_storage::GcReport, yadorilink_local_storage::StorageError>
        {
            self.inner.sweep(live_hashes, older_than, dry_run)
        }
    }

    fn processor_with_counting_store(
    ) -> (LocalChangeProcessor, Arc<CountingBlockStore>, tempfile::TempDir, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(CountingBlockStore::new(store_dir.path()));
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        (
            LocalChangeProcessor::new(state, store.clone(), "device-a".into()),
            store,
            store_dir,
            root_dir,
        )
    }

    /// sync-performance PERF-2: a `CreatedOrModified` event for a file
    /// whose size and mtime are both unchanged from the indexed record
    /// must resolve via the fast-path — no new block ever gets `put` into
    /// the store, proving the file was never re-read/re-chunked at all
    /// (not even to reach the pre-existing self-echo comparison, which
    /// would still require a full chunk first).
    #[tokio::test]
    async fn unchanged_size_and_mtime_skips_rechunking_entirely() {
        let (proc, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        let file_path = root.join("steady.bin");
        std::fs::write(&file_path, vec![b'x'; 5_000_000]).unwrap();

        let first = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let calls_after_first = store.put_call_count();
        assert!(calls_after_first > 0, "the initial index must actually chunk the file");

        // No filesystem-level change at all: same bytes, same size, same
        // mtime — exactly what a self-echo or a redundant watcher event
        // for the same save looks like.
        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(outcome, LocalChangeOutcome::None);
        assert_eq!(
            store.put_call_count(),
            calls_after_first,
            "size+mtime fast-path must skip chunking entirely, not just suppress the resulting record"
        );
        let indexed = proc.state.get_file("group-1", "steady.bin").unwrap().unwrap();
        assert_eq!(
            indexed.version, first.version,
            "no spurious version bump from an unchanged file"
        );
    }

    /// sync-performance PERF-2's documented trade-off: the fast-path
    /// trusts size+mtime without re-reading content (rsync's default
    /// "quick check" semantics — see the code comment on the fast-path
    /// itself). This test pins down that trade-off explicitly: content
    /// that differs from what's indexed, but happens to keep the exact
    /// same size *and* have its mtime reset to the exact same instant, is
    /// accepted as unchanged and never re-chunked — a deliberate,
    /// documented limitation, not an oversight.
    #[tokio::test]
    async fn identical_size_and_mtime_with_different_bytes_is_still_treated_as_unchanged() {
        let (proc, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edge-case.bin");
        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let indexed_before = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();
        let calls_after_first = store.put_call_count();
        let original_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_before.mtime_unix_nanos as u64);

        // Same length (20 bytes), different bytes, mtime forced back to
        // exactly what was indexed — the pathological case the fast-path
        // knowingly accepts.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        // Windows' SetFileTime requires the handle to have been opened with
        // write access -- File::open is read-only there and fails this
        // with ACCESS_DENIED (Unix's utimensat has no such requirement, so
        // this only ever surfaced on this suite's first real Windows run).
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            LocalChangeOutcome::None,
            "size+mtime match is trusted even though bytes differ — documented trade-off"
        );
        assert_eq!(store.put_call_count(), calls_after_first, "no re-chunking attempted");
        let indexed_after = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_eq!(
            indexed_after.blocks, indexed_before.blocks,
            "index still reflects the original content — the trade-off's known limitation"
        );
    }

    #[tokio::test]
    async fn created_file_is_chunked_and_indexed() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(record.path, "hello.txt");
        assert_eq!(record.size, 11);
        assert_eq!(record.blocks.len(), 1);
        assert_eq!(record.version.get("device-a"), 1);
    }

    #[tokio::test]
    async fn rename_produces_identical_block_hashes_as_the_original() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let original = root.join("original.txt");
        std::fs::write(&original, b"unchanged content").unwrap();
        let created = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: original.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        // Simulate a rename: delete the old path, create the new one with
        // byte-identical content (nothing edited).
        std::fs::remove_file(&original).unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: original, kind: FsChangeKind::Removed },
        )
        .await
        .unwrap();

        let renamed = root.join("renamed.txt");
        std::fs::write(&renamed, b"unchanged content").unwrap();
        let recreated = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: renamed, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(
            created.blocks, recreated.blocks,
            "unchanged content must hash to identical blocks"
        );
    }

    #[tokio::test]
    async fn removed_file_is_marked_deleted_with_incremented_version() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("bye.txt");
        std::fs::write(&file_path, b"data").unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

        // `process_event` now derives Removed-vs-CreatedOrModified from
        // the path's actual
        // current disk state rather than trusting `event.kind` verbatim
        // (closing a race where a debounce-coalesced `Removed` could be
        // silently overwritten by an unrelated later write to the same
        // path) -- so this synthetic `Removed` event must correspond to a
        // real deletion, matching what a genuine watcher would only ever
        // report after the fact.
        std::fs::remove_file(&file_path).unwrap();
        let tombstone = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::Removed },
            )
            .await
            .unwrap(),
        );

        assert!(tombstone.deleted);
        assert_eq!(tombstone.version.get("device-a"), 2);
    }

    #[tokio::test]
    async fn deleting_never_indexed_ignored_paths_generates_no_tombstone() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");

        let user_ignored = root.join("scratch.tmp");
        let user_outcome = proc
            .process_event_with_ignore(
                "group-1",
                &root,
                &FsChangeEvent { path: user_ignored, kind: FsChangeKind::Removed },
                &ignore_set,
            )
            .await
            .unwrap();
        assert_eq!(user_outcome, LocalChangeOutcome::None);
        assert!(proc.state.get_file("group-1", "scratch.tmp").unwrap().is_none());

        let built_in_ignored = root.join(".DS_Store");
        let built_in_outcome = proc
            .process_event_with_ignore(
                "group-1",
                &root,
                &FsChangeEvent { path: built_in_ignored, kind: FsChangeKind::Removed },
                &ignore_set,
            )
            .await
            .unwrap();
        assert_eq!(built_in_outcome, LocalChangeOutcome::None);
        assert!(proc.state.get_file("group-1", ".DS_Store").unwrap().is_none());
    }

    /// / on-demand-sync spec "Placeholder creation is not treated
    /// as a local edit": a placeholder's own write must not be indexed as
    /// a genuine local change, or chunked (which would index wrong content
    /// — the placeholder's sparse bytes, not the file's real ones).
    #[tokio::test]
    async fn placeholder_write_is_not_treated_as_a_local_edit() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("placeholder.bin");

        // Simulate what `peer_session::materialize` does for an `OnDemand`
        // folder: index a record, then mark it Placeholder, before the
        // sparse file itself is written to disk.
        let mut version = crate::version_vector::VersionVector::new();
        version.increment("device-b");
        proc.state
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 5_000_000,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![crate::types::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: 5_000_000,
                    }],
                    deleted: false,
                },
            )
            .unwrap();
        proc.state
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
            )
            .unwrap();
        crate::chunker::write_placeholder(&file_path, 5_000_000, 0).unwrap();

        let result = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            LocalChangeOutcome::None,
            "a placeholder's own write must not be indexed as a local edit"
        );
        let record = proc.state.get_file("group-1", "placeholder.bin").unwrap().unwrap();
        assert_eq!(record.version.get("device-b"), 1);
        assert_eq!(record.version.get("device-a"), 0, "no spurious local version bump");
    }

    /// / edit-presence-awareness spec "Lock file appearance is
    /// detected" and "Lock file is never treated as a synced file itself".
    #[tokio::test]
    async fn office_lock_file_appearance_signals_presence_not_a_file_change() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let lock_path = root.join("~$report.docx");
        std::fs::write(&lock_path, b"").unwrap();

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: lock_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            LocalChangeOutcome::PresenceChanged { path: "report.docx".to_string(), editing: true }
        );
        // Never indexed as a file in its own right, under either name.
        assert!(proc.state.get_file("group-1", "~$report.docx").unwrap().is_none());
        assert!(proc.state.get_file("group-1", "report.docx").unwrap().is_none());
    }

    /// / spec "Lock file removal is detected".
    #[tokio::test]
    async fn office_lock_file_removal_signals_presence_stopped() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let lock_path = root.join("~$Budget 2026.xlsx");

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: lock_path, kind: FsChangeKind::Removed },
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            LocalChangeOutcome::PresenceChanged {
                path: "Budget 2026.xlsx".to_string(),
                editing: false
            }
        );
    }

    /// Presence detection must resolve nested paths correctly too — the
    /// signaled path is the original file's path *within the linked
    /// folder*, not just its bare filename.
    #[tokio::test]
    async fn office_lock_file_in_a_subdirectory_resolves_the_full_relative_path() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("Projects")).unwrap();
        let lock_path = root.join("Projects").join("~$plan.docx");
        std::fs::write(&lock_path, b"").unwrap();

        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: lock_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        assert_eq!(
            outcome,
            LocalChangeOutcome::PresenceChanged {
                path: "Projects/plan.docx".to_string(),
                editing: true
            }
        );
    }

    /// `scan_existing_files` must never index a stale lock file
    /// left over from a prior crash.
    #[test]
    fn scan_existing_files_skips_lock_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("report.docx"), b"real content").unwrap();
        std::fs::write(root.join("~$other.docx"), b"").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["report.docx"]);
    }

    #[test]
    fn scan_existing_files_skips_ignored_directories_and_leaf_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("node_modules/\nsrc/*.log\n");
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), b"ignored dependency").unwrap();
        std::fs::write(root.join("src/debug.log"), b"ignored log").unwrap();
        std::fs::write(root.join("src/keep.txt"), b"kept").unwrap();
        std::fs::write(root.join(".yadorilinkignore"), b"node_modules/\n").unwrap();

        let records = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["src/keep.txt"]);
        assert!(proc.state.get_file("group-1", "node_modules/pkg/index.js").unwrap().is_none());
        assert!(proc.state.get_file("group-1", "src/debug.log").unwrap().is_none());
        assert!(proc.state.get_file("group-1", ".yadorilinkignore").unwrap().is_none());
    }

    #[test]
    fn scan_existing_files_drops_newly_ignored_index_entries_without_tombstones() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("keep.txt"), b"kept").unwrap();
        std::fs::write(root.join("ignored.txt"), b"still on disk").unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 2);
        assert!(proc.state.get_file("group-1", "ignored.txt").unwrap().is_some());

        let ignore_set = EffectiveIgnoreSet::from_user_patterns("ignored.txt\n");
        let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &ignore_set).unwrap();

        assert!(
            rescan.iter().all(|record| record.path != "ignored.txt"),
            "newly ignored paths must not be emitted as tombstones: {rescan:?}"
        );
        assert!(proc.state.get_file("group-1", "ignored.txt").unwrap().is_none());
        assert_eq!(std::fs::read(root.join("ignored.txt")).unwrap(), b"still on disk");
        assert!(proc.state.get_file("group-1", "keep.txt").unwrap().is_some());
    }

    #[test]
    fn scan_existing_files_indexes_previously_ignored_file_after_pattern_removal() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("build.log"), b"now wanted").unwrap();
        let ignored = EffectiveIgnoreSet::from_user_patterns("*.log\n");
        let first_scan = proc.scan_existing_files_with_ignore("group-1", &root, &ignored).unwrap();
        assert!(first_scan.is_empty());
        assert!(proc.state.get_file("group-1", "build.log").unwrap().is_none());

        let unignored = EffectiveIgnoreSet::defaults_only();
        let rescan = proc.scan_existing_files_with_ignore("group-1", &root, &unignored).unwrap();

        assert_eq!(rescan.len(), 1);
        assert_eq!(rescan[0].path, "build.log");
        assert!(proc.state.get_file("group-1", "build.log").unwrap().is_some());
    }

    /// A single scan correctly handles
    /// a mix of already-current, changed, and brand-new files together,
    /// using the bulk-loaded `list_files`/`list_materialization_states`
    /// maps () rather than a per-file lookup for any of them.
    #[test]
    fn scan_existing_files_handles_a_mix_of_unchanged_changed_and_new_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        std::fs::write(root.join("unchanged.txt"), b"same content").unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1);
        let original_version = first_scan[0].version.clone();

        // Now: leave "unchanged.txt" alone, modify "unchanged.txt" would
        // contradict its name, so instead add a genuinely-changed file
        // and a genuinely-new file, then rescan everything together.
        std::fs::write(root.join("changed-later.txt"), b"v1").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        std::fs::write(root.join("changed-later.txt"), b"v2, now longer").unwrap();
        std::fs::write(root.join("brand-new.txt"), b"never seen before").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: std::collections::HashSet<&str> =
            records.iter().map(|r| r.path.as_str()).collect();
        // "unchanged.txt" is already current (same size) so it's not
        // re-indexed by this final scan; the other two are.
        assert_eq!(paths, std::collections::HashSet::from(["changed-later.txt", "brand-new.txt"]));

        let final_state = proc.state.get_file("group-1", "unchanged.txt").unwrap().unwrap();
        assert_eq!(final_state.version, original_version, "untouched file's version must not bump");
        let changed = proc.state.get_file("group-1", "changed-later.txt").unwrap().unwrap();
        assert_eq!(changed.size, "v2, now longer".len() as u64);
    }

    /// `scan_existing_files` must
    /// not skip a genuine placeholder (OnDemand sync) during a bulk scan —
    /// the bulk-loaded materialization-state map () must still
    /// correctly prevent chunking a placeholder's sparse bytes, exactly as
    /// the old per-file `get_materialization_state` lookup did.
    #[test]
    fn scan_existing_files_still_skips_placeholders_when_bulk_loading_materialization_state() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        let mut version = crate::version_vector::VersionVector::new();
        version.increment("device-b");
        proc.state
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 2_000_000,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![crate::types::BlockInfo {
                        hash: vec![0xCD; 32],
                        offset: 0,
                        size: 2_000_000,
                    }],
                    deleted: false,
                },
            )
            .unwrap();
        proc.state
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
            )
            .unwrap();
        crate::chunker::write_placeholder(&root.join("placeholder.bin"), 2_000_000, 0).unwrap();
        std::fs::write(root.join("ordinary.txt"), b"a real file").unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["ordinary.txt"],
            "the placeholder must not be re-indexed by the scan"
        );

        let record = proc.state.get_file("group-1", "placeholder.bin").unwrap().unwrap();
        assert_eq!(record.version.get("device-b"), 1);
        assert_eq!(
            record.version.get("device-a"),
            0,
            "no spurious local version bump from the scan"
        );
    }

    /// Scanning a folder with a large
    /// number of small pre-existing files completes well within a bound
    /// that would be blown by an O(file count) synchronous SQLite
    /// round-trip pattern (the pre-D4 behavior) — a smoke check for the
    /// bulk-load-and-batch-commit approach without needing to instrument
    /// individual query counts.
    ///
    /// This is deliberately a *coarse*
    /// regression guard, not a micro-performance gate. The bulk-load
    /// approach normally finishes in well under a second; the pre-D4
    /// per-file synchronous round-trip pattern this guards against would
    /// be dominated by thousands of individual SQLite commits and land in
    /// the tens-of-seconds range or worse. A generous absolute bound
    /// (rather than the original tight 5s one) tolerates a host that is
    /// transiently oversubscribed by concurrent builds/tests without
    /// losing the ability to catch that specific O(file count) regression
    /// shape — elapsed time is always printed so a passing-but-slow run
    /// is still visible with `--nocapture`.
    #[test]
    fn scan_existing_files_completes_quickly_for_thousands_of_small_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        const FILE_COUNT: usize = 3000;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("object-{i}.bin")), format!("content {i}")).unwrap();
        }

        let started = std::time::Instant::now();
        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let elapsed = started.elapsed();
        eprintln!(
            "scan_existing_files_completes_quickly: {FILE_COUNT} files scanned in {elapsed:?}"
        );

        assert_eq!(records.len(), FILE_COUNT);
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), FILE_COUNT);
        const COARSE_BOUND: std::time::Duration = std::time::Duration::from_secs(60);
        assert!(
            elapsed < COARSE_BOUND,
            "scanning {FILE_COUNT} small files took {elapsed:?}, expected well under \
             {COARSE_BOUND:?} even under heavy host load with bulk-loaded index \
             reconciliation (a per-file synchronous round-trip regression would be \
             far slower than this bound, not merely close to it)"
        );

        // A second scan with nothing changed must find everything already
        // current — no records re-indexed, no version bumps.
        let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(second_scan.is_empty(), "an unchanged folder must not be re-indexed on rescan");
    }

    /// batch-sync-optimizations (executor half): a `Paths` flush
    /// indexes every listed path and returns the resulting records,
    /// exactly as individual `process_event` calls would.
    #[tokio::test]
    async fn process_flush_paths_indexes_each_path_and_returns_records() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb").unwrap();

        let flush = crate::debounce::DebounceFlush::Paths(vec![
            (root.join("a.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("b.txt"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt", "b.txt"]);
        assert!(outcome.presence_changes.is_empty());
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn process_flush_paths_skips_ignored_files_and_ignore_config_file() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("*.tmp\n");
        std::fs::write(root.join("keep.txt"), b"kept").unwrap();
        std::fs::write(root.join("scratch.tmp"), b"ignored").unwrap();
        std::fs::write(root.join(".yadorilinkignore"), b"*.tmp\n").unwrap();

        let flush = crate::debounce::DebounceFlush::Paths(vec![
            (root.join("keep.txt"), FsChangeKind::CreatedOrModified, 0),
            (root.join("scratch.tmp"), FsChangeKind::CreatedOrModified, 0),
            (root.join(".yadorilinkignore"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome =
            proc.process_flush_with_ignore("group-1", &root, flush, &ignore_set).await.unwrap();

        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].path, "keep.txt");
        assert!(proc.state.get_file("group-1", "scratch.tmp").unwrap().is_none());
        assert!(proc.state.get_file("group-1", ".yadorilinkignore").unwrap().is_none());
    }

    /// A `BurstFallback` flush runs a full reconciliation scan instead of
    /// per-path processing.
    #[tokio::test]
    async fn process_flush_burst_fallback_runs_full_scan() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("a.txt"), b"aaa").unwrap();
        std::fs::write(root.join("b.txt"), b"bbb").unwrap();
        std::fs::write(root.join("c.txt"), b"ccc").unwrap();

        let outcome = proc
            .process_flush("group-1", &root, crate::debounce::DebounceFlush::BurstFallback)
            .await
            .unwrap();

        let mut paths: Vec<&str> = outcome.records.iter().map(|r| r.path.as_str()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), 3);
    }

    /// A `Paths` flush containing a lock-file event reports it as a
    /// presence change, separate from `records` — it must never appear as
    /// a `FileRecord` (spec "Lock file is never treated as a synced file
    /// itself").
    #[tokio::test]
    async fn process_flush_paths_separates_presence_changes_from_file_records() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("report.docx"), b"content").unwrap();
        std::fs::write(root.join("~$report.docx"), b"").unwrap();

        let flush = crate::debounce::DebounceFlush::Paths(vec![
            (root.join("report.docx"), FsChangeKind::CreatedOrModified, 0),
            (root.join("~$report.docx"), FsChangeKind::CreatedOrModified, 0),
        ]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].path, "report.docx");
        assert_eq!(outcome.presence_changes, vec![("report.docx".to_string(), true)]);
    }

    /// Self-echo
    /// suppression still applies per-path when processing a `Paths`
    /// flush — a path whose content already matches what's indexed
    /// (as if a peer-applied write's own resulting event landed in this
    /// debounce window) produces no record, exactly as an immediate
    /// single-event `process_event` call would.
    #[tokio::test]
    async fn process_flush_paths_applies_self_echo_suppression_per_path() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("synced.bin");
        std::fs::write(&file_path, b"peer-applied content").unwrap();

        // Index it first (simulating `peer_session::materialize` having
        // already written this exact content before its own triggered
        // watcher event ever reaches the debounce flush).
        let first_flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path.clone(),
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let first = proc.process_flush("group-1", &root, first_flush).await.unwrap();
        assert_eq!(first.records.len(), 1);

        // A second flush for the same, unchanged path — as if the
        // materialize-triggered watcher event arrived in its own later
        // window — must be suppressed, not re-indexed or re-broadcast.
        let second_flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let second = proc.process_flush("group-1", &root, second_flush).await.unwrap();
        assert!(second.records.is_empty(), "unchanged content must not be re-indexed");
    }

    /// The
    /// placeholder/hydrating skip still applies when processing a `Paths`
    /// flush, exactly as `process_event` does directly — a placeholder's
    /// own on-disk representation is never chunked as if it were real
    /// content, even when reached via the debounce/flush path.
    #[tokio::test]
    async fn process_flush_paths_skips_placeholders_exactly_like_process_event() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("placeholder.bin");

        let mut version = crate::version_vector::VersionVector::new();
        version.increment("device-b");
        proc.state
            .upsert_file(
                "group-1",
                &FileRecord {
                    path: "placeholder.bin".into(),
                    size: 4_000_000,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![crate::types::BlockInfo {
                        hash: vec![0xEE; 32],
                        offset: 0,
                        size: 4_000_000,
                    }],
                    deleted: false,
                },
            )
            .unwrap();
        proc.state
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
            )
            .unwrap();
        crate::chunker::write_placeholder(&file_path, 4_000_000, 0).unwrap();

        let flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            0,
        )]);
        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();

        assert!(outcome.records.is_empty(), "a placeholder's own write must not be indexed");
        let record = proc.state.get_file("group-1", "placeholder.bin").unwrap().unwrap();
        assert_eq!(record.version.get("device-a"), 0, "no spurious local version bump");
    }

    /// An overflow signal (as a real
    /// watcher would set on a dropped event, simulated here by setting
    /// the flag directly — see `watcher::watch_folder_with_capacity`'s
    /// own tests for proof the flag is set correctly under a genuine
    /// full channel) reaches the debouncer and, once flushed through
    /// `process_flush`'s `BurstFallback` handling, produces a fully
    /// correct index — including files whose individual creation events
    /// were never tracked at all, because the whole point of this
    /// recovery path is not needing them.
    #[tokio::test]
    async fn watcher_overflow_recovers_to_a_fully_correct_index_via_full_rescan() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let proc = Arc::new(proc);

        // These files exist on disk, but no event for any of them is
        // ever sent into the debouncer — standing in for what a real
        // overflow drops.
        const FILE_COUNT: usize = 25;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("dropped-{i}.bin")), format!("content {i}")).unwrap();
        }

        let (_events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(4);
        let overflowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let config = crate::debounce::DebounceConfig {
            quiet_period: std::time::Duration::from_millis(20),
            max_flush_interval: std::time::Duration::from_millis(100),
            burst_threshold: 1000,
        };
        let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
        let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(crate::debounce::run_debouncer(
            config,
            events_rx,
            flush_tx,
            overflowed,
            flush_requests_rx,
            flush_all_requests_rx,
        ));

        let flush = tokio::time::timeout(std::time::Duration::from_secs(2), flush_rx.recv())
            .await
            .expect("overflow never produced a flush")
            .unwrap();
        assert_eq!(flush, crate::debounce::DebounceFlush::BurstFallback);

        let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
        assert_eq!(outcome.records.len(), FILE_COUNT, "the full rescan must discover every file");
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), FILE_COUNT);
        for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
            let record = proc.state.get_file("group-1", &format!("dropped-{i}.bin")).unwrap();
            assert!(record.is_some(), "file dropped-{i}.bin is missing from the recovered index");
        }
    }

    /// A
    /// rename whose watcher event is missed entirely (the scenario a
    /// dropped/overflowed event stream produces, or simply a device that
    /// was offline while the rename happened) must be fully recovered by
    /// the next full rescan — the old path tombstoned, the new path
    /// indexed as live, and the old path never resurrected by a later
    /// scan (idempotency: nothing about a stable, already-tombstoned
    /// path should look "new" to a subsequent rescan).
    #[tokio::test]
    async fn scan_existing_files_recovers_a_dropped_rename_without_resurrecting_the_old_path() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        let old_path = root.join("original.txt");
        std::fs::write(&old_path, b"content").unwrap();
        let scanned = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(scanned.len(), 1);
        assert!(!proc.state.get_file("group-1", "original.txt").unwrap().unwrap().deleted);

        // Simulate a rename whose watcher event never arrived (dropped by
        // an overflow, or the device was offline) — from the index's
        // point of view, `original.txt` just vanished and `renamed.txt`
        // appeared, with no event ever processed for either.
        std::fs::rename(&old_path, root.join("renamed.txt")).unwrap();

        let recovered = proc.scan_existing_files("group-1", &root).unwrap();
        let old_record = recovered.iter().find(|r| r.path == "original.txt");
        let new_record = recovered.iter().find(|r| r.path == "renamed.txt");
        assert!(
            old_record.is_some_and(|r| r.deleted),
            "old path must be tombstoned: {recovered:?}"
        );
        assert!(
            new_record.is_some_and(|r| !r.deleted),
            "new path must be indexed as live: {recovered:?}"
        );
        assert!(
            proc.state.get_file("group-1", "original.txt").unwrap().unwrap().deleted,
            "tombstone must actually be persisted to the index, not just returned"
        );

        // A further rescan (nothing changed on disk since) must not
        // resurrect the now-stable tombstone — the old path shouldn't
        // even appear in the returned records again, since nothing about
        // it changed.
        let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            second_scan.iter().all(|r| r.path != "original.txt"),
            "a stable tombstone must not be re-emitted/re-bumped by a later rescan: {second_scan:?}"
        );
        assert!(proc.state.get_file("group-1", "original.txt").unwrap().unwrap().deleted);
    }

    /// The add-only reconcile
    /// (`reconcile_added_files`) indexes only a disk file with no existing
    /// index row — an already-indexed file whose on-disk content changed,
    /// and an indexed file missing from disk, are both left byte-identical
    /// (no re-version, no tombstone). This is the property that makes it
    /// safe to run unconditionally on a frequent periodic schedule, unlike
    /// `scan_existing_files` (which does re-version/tombstone those two
    /// cases, and is documented — `watcher.rs`'s module doc — as unsafe to
    /// run that often against a possibly-mid-conflict-resolution index).
    #[tokio::test]
    async fn reconcile_added_files_only_indexes_disk_files_with_no_existing_row() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        // (a) current: already indexed, on-disk content unchanged.
        std::fs::write(root.join("current.txt"), b"unchanged").unwrap();
        // (b) size-changed-on-disk: indexed once, then its disk content
        // changes size *after* indexing, without going through `scan_
        // existing_files` again (mirroring a watcher-missed edit).
        std::fs::write(root.join("changed.txt"), b"original").unwrap();
        // (c) indexed-but-disk-missing: indexed once, then deleted from
        // disk directly (mirroring a watcher-missed delete).
        std::fs::write(root.join("missing.txt"), b"will be deleted").unwrap();

        let initial = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(initial.len(), 3);
        let current_version_before =
            proc.state.get_file("group-1", "current.txt").unwrap().unwrap().version.clone();
        let changed_version_before =
            proc.state.get_file("group-1", "changed.txt").unwrap().unwrap().version.clone();
        let missing_version_before =
            proc.state.get_file("group-1", "missing.txt").unwrap().unwrap().version.clone();

        // Now make (b) and (c) diverge from the index without dispatching
        // any event for them, and add (d): a brand-new file the index has
        // never seen.
        std::fs::write(root.join("changed.txt"), b"a longer, different body").unwrap();
        std::fs::remove_file(root.join("missing.txt")).unwrap();
        std::fs::write(root.join("new.txt"), b"never indexed before").unwrap();

        let added = proc.reconcile_added_files("group-1", &root).unwrap();
        assert_eq!(
            added.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            vec!["new.txt"],
            "the add-only reconcile must emit a record only for the genuinely new file: {added:?}"
        );
        assert!(!added[0].deleted);

        // (a)/(b)/(c) must be byte-identical in the index to their
        // pre-reconcile state -- no re-version, no tombstone.
        let current_after = proc.state.get_file("group-1", "current.txt").unwrap().unwrap();
        assert_eq!(current_after.version, current_version_before);
        assert!(!current_after.deleted);

        let changed_after = proc.state.get_file("group-1", "changed.txt").unwrap().unwrap();
        assert_eq!(
            changed_after.version, changed_version_before,
            "a size-changed-on-disk file must not be re-versioned by the add-only reconcile"
        );
        assert!(!changed_after.deleted);

        let missing_after = proc.state.get_file("group-1", "missing.txt").unwrap().unwrap();
        assert_eq!(
            missing_after.version, missing_version_before,
            "a disk-missing indexed file must not be tombstoned by the add-only reconcile"
        );
        assert!(
            !missing_after.deleted,
            "the add-only reconcile must never tombstone an existing row"
        );

        // The new file is actually persisted to the index, not just
        // returned -- and a second add-only pass is idempotent (nothing
        // new to add, and still no mutation of the other three rows).
        assert!(proc.state.get_file("group-1", "new.txt").unwrap().is_some());
        let second = proc.reconcile_added_files("group-1", &root).unwrap();
        assert!(
            second.is_empty(),
            "a second add-only pass with nothing new must emit nothing: {second:?}"
        );
    }

    /// Once the accumulator's internal
    /// delivery queue is forced past capacity by a backlog (D4.4
    /// — see `debounce`'s own `executor_backlog_trigger_...` test for the
    /// queue-collapse mechanism in isolation), the resulting
    /// `BurstFallback` still recovers a fully-correct index end to end,
    /// exactly like the watcher-overflow path.
    #[tokio::test]
    async fn executor_backlog_recovers_to_a_fully_correct_index_via_full_rescan() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let proc = Arc::new(proc);

        const FILE_COUNT: usize = 30;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("obj-{i}.bin")), format!("content {i}")).unwrap();
        }

        let (events_tx, events_rx) = tokio::sync::mpsc::channel(256);
        // Never drained: forces the internal ready_queue to collapse into
        // a BurstFallback once it exceeds DEFAULT_EXECUTOR_CHANNEL_CAPACITY.
        let (flush_tx, mut flush_rx) = tokio::sync::mpsc::channel(1);
        let config = crate::debounce::DebounceConfig {
            quiet_period: std::time::Duration::from_millis(15),
            max_flush_interval: std::time::Duration::from_millis(60),
            burst_threshold: 1000,
        };
        let (_flush_requests_tx, flush_requests_rx) = tokio::sync::mpsc::channel(1);
        let (_flush_all_requests_tx, flush_all_requests_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(crate::debounce::run_debouncer(
            config,
            events_rx,
            flush_tx,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            flush_requests_rx,
            flush_all_requests_rx,
        ));

        // Many separate, well-spaced single-path windows — each one is a
        // *real* file (so a non-fallback flush would also reconstruct
        // correctly), but there are enough of them, undrained, that the
        // delivery queue must eventually collapse. The gap needs real
        // headroom above quiet_period (15ms): on a slower/more contended
        // CI runner (observed on windows-latest at the old 25ms gap), a
        // slow-to-be-polled debouncer task can let several sends queue up
        // and then process them back-to-back, merging windows that were
        // meant to stay separate and never reaching the collapse this
        // test means to exercise (same root cause as, and fixed the same
        // way as, debounce.rs's sibling test).
        for i in 0..(crate::debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY + 5) {
            events_tx
                .send(FsChangeEvent {
                    path: root.join(format!("obj-{i}.bin")),
                    kind: FsChangeKind::CreatedOrModified,
                })
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        // Now drain everything and process each flush through the same
        // executor logic `link_manager` uses. The gap between flushes is
        // bounded by max_flush_interval (60ms) under normal scheduling,
        // but this per-recv timeout needs real headroom above that on a
        // slow/contended CI runner (observed needing more than 500ms on
        // this suite's first real Windows run) -- it only ends the loop
        // once flushes genuinely stop arriving, so a generous bound here
        // doesn't weaken what the test verifies, just how patiently it
        // waits for a real signal.
        let mut total_records = Vec::new();
        while let Ok(Some(flush)) =
            tokio::time::timeout(std::time::Duration::from_secs(3), flush_rx.recv()).await
        {
            let outcome = proc.process_flush("group-1", &root, flush).await.unwrap();
            total_records.extend(outcome.records);
        }

        // Whether via individually-tracked paths or the collapsed
        // fallback's full rescan, every file must end up correctly
        // indexed — no permanent gaps from the collapse.
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), FILE_COUNT);
        for i in [0, FILE_COUNT / 2, FILE_COUNT - 1] {
            assert!(
                proc.state.get_file("group-1", &format!("obj-{i}.bin")).unwrap().is_some(),
                "file obj-{i}.bin is missing from the recovered index"
            );
        }
    }

    /// A link with no registered
    /// chunking policy (the state every pre-existing test in this module
    /// already exercises, and every link before this change existed)
    /// continues to use fixed-size chunking exactly as before — no
    /// regression from adding the CDC code path.
    #[tokio::test]
    async fn no_chunking_policy_registered_uses_fixed_size_chunking_unchanged() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        // No `add_link` call at all — matches how every other test in this
        // module already operates, and is deliberately the same as an
        // upgrade from before this change existed.
        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        let expected = crate::chunker::chunk_file(
            &FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap(),
            &file_path,
        )
        .unwrap();
        assert_eq!(record.blocks.len(), expected.len());
        assert_eq!(record.blocks[0].size, expected[0].size, "must match chunk_file's fixed sizing");
    }

    /// Even with a `ContentDefined`
    /// policy set, a file below `CDC_SIZE_THRESHOLD` still uses fixed-size
    /// chunking — the size gate applies regardless of policy.
    #[tokio::test]
    async fn content_defined_policy_small_file_still_uses_fixed_size_chunking() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let local_path = root.to_string_lossy().to_string();
        proc.state.add_link(&local_path, "group-1").unwrap();
        proc.state
            .set_chunking_policy(&local_path, crate::types::ChunkingPolicy::ContentDefined)
            .unwrap();

        let file_path = root.join("small.txt");
        std::fs::write(&file_path, b"well below the CDC size threshold").unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        // Fixed-size chunking of a file this small always produces
        // exactly one block covering the whole file — CDC's minimum chunk
        // size (512 KiB) alone would make this assertion distinguish the
        // two even without inspecting exact boundaries.
        assert_eq!(record.blocks.len(), 1);
        assert_eq!(record.blocks[0].size, "well below the CDC size threshold".len() as u32);
    }

    /// A `ContentDefined`-policy link's
    /// file at or above the size threshold is actually chunked with CDC —
    /// verified by comparing against `chunk_file_content_defined`'s direct
    /// output (deterministic for the same content/parameters), and
    /// confirming it differs from what fixed-size chunking would have
    /// produced for the same content.
    #[tokio::test]
    async fn content_defined_policy_large_file_uses_cdc() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let local_path = root.to_string_lossy().to_string();
        proc.state.add_link(&local_path, "group-1").unwrap();
        proc.state
            .set_chunking_policy(&local_path, crate::types::ChunkingPolicy::ContentDefined)
            .unwrap();

        // Deterministic pseudo-random content, at the size threshold —
        // real CDC boundary-finding depends on actual byte entropy.
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let content: Vec<u8> =
            (0..crate::chunker::CDC_SIZE_THRESHOLD as usize).map(|_| rng.random()).collect();
        let file_path = root.join("big.bin");
        std::fs::write(&file_path, &content).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        let throwaway_store = FsBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap();
        let expected_cdc =
            crate::chunker::chunk_file_content_defined(&throwaway_store, &file_path).unwrap();
        let expected_fixed = crate::chunker::chunk_file(&throwaway_store, &file_path).unwrap();

        assert_eq!(record.blocks, expected_cdc, "must match chunk_file_content_defined's output");
        assert_ne!(
            record.blocks, expected_fixed,
            "CDC output must differ from what fixed-size chunking would have produced"
        );
    }

    // --- Symlink pruning and cycle safety ---

    /// A symlink inside the folder is recorded as a symlink
    /// record — correct raw target text, no content blocks, and
    /// `record_kind = Symlink` in the index (not folded into `FileRecord`
    /// — see `types::RecordKind`'s doc comment).
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_inside_folder_is_recorded_as_a_symlink_with_no_blocks() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("real.txt"), b"target content").unwrap();
        let link_path = root.join("link.txt");
        std::os::unix::fs::symlink("real.txt", &link_path).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert_eq!(record.path, "link.txt");
        assert!(record.blocks.is_empty(), "a symlink record must carry no content blocks");
        assert_eq!(
            proc.state.get_record_kind("group-1", "link.txt").unwrap(),
            Some(crate::types::RecordKind::Symlink)
        );
        assert_eq!(
            proc.state.get_symlink_target("group-1", "link.txt").unwrap(),
            Some("real.txt".to_string())
        );
        assert!(!proc.state.get_symlink_out_of_root("group-1", "link.txt").unwrap());
        // The target file itself must still be indexed normally and
        // separately — the symlink never dereferences into it.
        let target_record = proc.state.get_file("group-1", "real.txt").unwrap();
        assert!(target_record.is_none(), "target wasn't scanned in this single-event test");
    }

    /// `scan_existing_files` classifies a pre-existing
    /// symlink the same way a live watcher event does.
    #[cfg(unix)]
    #[test]
    fn scan_existing_files_records_a_symlink_with_correct_target_text() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("real.txt"), b"target content").unwrap();
        std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let link_record = records.iter().find(|r| r.path == "link.txt").unwrap();
        assert!(link_record.blocks.is_empty());
        assert_eq!(
            proc.state.get_record_kind("group-1", "link.txt").unwrap(),
            Some(crate::types::RecordKind::Symlink)
        );
        assert_eq!(
            proc.state.get_symlink_target("group-1", "link.txt").unwrap(),
            Some("real.txt".to_string())
        );

        // The regular file target is indexed too, as its own unrelated
        // record — proves the symlink and its target are two independent
        // entries, not one dereferenced into the other.
        let target_record = records.iter().find(|r| r.path == "real.txt").unwrap();
        assert!(!target_record.blocks.is_empty());
    }

    /// A symlinked directory's contents never appear as
    /// separate scanned records — only the symlink itself is enumerated,
    /// as a single leaf entry, never descended into as a subtree.
    #[cfg(unix)]
    #[test]
    fn symlinked_directory_contents_never_appear_as_separate_scanned_records() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("real_dir")).unwrap();
        std::fs::write(root.join("real_dir/secret.txt"), b"must not leak").unwrap();
        std::os::unix::fs::symlink("real_dir", root.join("link_dir")).unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();

        assert!(paths.contains(&"link_dir"), "the symlink itself must be recorded: {paths:?}");
        assert!(
            !paths.iter().any(|p| p.starts_with("link_dir/")),
            "nothing inside the symlinked directory may be enumerated via the link: {paths:?}"
        );
        assert_eq!(
            proc.state.get_record_kind("group-1", "link_dir").unwrap(),
            Some(crate::types::RecordKind::Symlink)
        );
        // The real directory's own (non-symlinked) path is scanned
        // normally and independently.
        assert!(paths.contains(&"real_dir/secret.txt"));
    }

    /// The same "never descend into a symlinked directory"
    /// guarantee holds for the watcher's directory-registration path, not
    /// just the scanner — a `CreatedOrModified` event for a freshly
    /// created symlink-to-directory must not cause the watcher to start
    /// watching (and thus later report file events for) anything inside
    /// the target.
    #[cfg(unix)]
    #[tokio::test]
    async fn watcher_never_registers_watches_inside_a_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("real_dir")).unwrap();
        let mut watcher = crate::watcher::watch_folder(&root).unwrap();

        std::os::unix::fs::symlink(root.join("real_dir"), root.join("link_dir")).unwrap();
        // The very first event received isn't necessarily this one:
        // macOS FSEvents' watch stream can have a small replay window
        // covering moments just before it starts, so the `real_dir`
        // creation above (right before watch_folder) can legitimately
        // surface here too (observed reproducing in real CI) -- loop
        // past anything unrelated, same tolerance the leak-check below
        // already applies to this same FSEvents quirk.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_link_dir = false;
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let event = tokio::time::timeout(remaining, watcher.events.recv())
                .await
                .expect("timed out waiting for the symlink-creation event")
                .expect("watcher channel closed");
            if event.path.file_name().and_then(|n| n.to_str()) == Some("link_dir") {
                saw_link_dir = true;
                break;
            }
        }
        assert!(saw_link_dir, "the symlink creation itself must still be reported");

        // A file written *through* the symlinked directory into its real
        // target must never surface as a watched event *under the link's
        // own path* — proof no recursive watch was registered on the
        // target via the link. Checked as "strictly inside link_dir"
        // (`link_dir/<something>`), not merely "mentions link_dir"
        // anywhere: macOS FSEvents can legitimately emit more than one
        // coalesced notification for the link's own creation (a known,
        // pre-existing source of flakiness this crate's other comments
        // already call out), which would be a false positive for a
        // cruder substring check but says nothing about a leak.
        std::fs::write(root.join("real_dir/new_file.txt"), b"leak?").unwrap();
        let link_dir_path = root.join("link_dir");
        let mut leaked = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match tokio::time::timeout(remaining, watcher.events.recv()).await {
                Ok(Some(ev)) => {
                    if ev.path.starts_with(&link_dir_path) && ev.path != link_dir_path {
                        leaked = Some(ev);
                        break;
                    }
                    // Some other, unrelated event (e.g. a duplicate
                    // notification about `link_dir`'s own creation, or the
                    // legitimate `real_dir/new_file.txt` event reached via
                    // its real, directly-watched path) — keep draining.
                }
                _ => break,
            }
        }
        assert!(
            leaked.is_none(),
            "the watcher must never report an event reached only via the symlinked directory: {leaked:?}"
        );
    }

    /// A symlink with an absolute target is flagged.
    #[cfg(unix)]
    #[tokio::test]
    async fn absolute_target_symlink_is_flagged() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let link_path = root.join("abs_link");
        std::os::unix::fs::symlink("/etc/passwd", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(proc.state.get_symlink_out_of_root("group-1", "abs_link").unwrap());
        assert_eq!(
            proc.state.get_symlink_target("group-1", "abs_link").unwrap(),
            Some("/etc/passwd".to_string()),
            "the raw target text is still recorded and synced, never rewritten"
        );
    }

    /// A relative symlink target that syntactically resolves
    /// outside the linked folder's root (via `..`) is flagged too, without
    /// ever dereferencing the target (the target need not even exist).
    #[cfg(unix)]
    #[tokio::test]
    async fn out_of_root_relative_target_symlink_is_flagged() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        let link_path = root.join("subdir/escape_link");
        // Climbs above `root` itself: subdir/../.. -> above root.
        std::os::unix::fs::symlink("../../outside/nonexistent", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(proc.state.get_symlink_out_of_root("group-1", "subdir/escape_link").unwrap());
    }

    /// A relative target that stays inside the folder root
    /// (even via a `..` that doesn't actually escape) is NOT flagged.
    #[cfg(unix)]
    #[tokio::test]
    async fn in_root_relative_target_symlink_is_not_flagged() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("sibling.txt"), b"data").unwrap();
        let link_path = root.join("subdir/in_root_link");
        // subdir/../sibling.txt -> root/sibling.txt: still inside root.
        std::os::unix::fs::symlink("../sibling.txt", &link_path).unwrap();

        expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(!proc.state.get_symlink_out_of_root("group-1", "subdir/in_root_link").unwrap());
    }

    /// a self-referential symlinked-directory cycle (`a -> a`)
    /// must not hang or recurse when scanned — proven with a real
    /// wall-clock timeout around the scan (run on a background thread,
    /// since `scan_existing_files` is synchronous) so a genuine infinite
    /// loop fails the test loudly instead of hanging the suite forever.
    /// This is expected to pass structurally, not by luck: the design means
    /// the scanner never descends into ANY symlinked directory, cyclic or
    /// not, so there is no recursive call into the cycle to bound in the
    /// first place — this test exists to confirm that reasoning against
    /// real filesystem behavior rather than trusting it blindly.
    #[cfg(unix)]
    #[test]
    fn self_referential_symlinked_directory_cycle_does_not_hang_or_recurse() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("cyc")).unwrap();
        // cyc/a -> cyc/a (a symlink whose own path is its target).
        std::os::unix::fs::symlink(root.join("cyc/a"), root.join("cyc/a")).unwrap();
        std::fs::write(root.join("ordinary.txt"), b"unrelated").unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let proc = Arc::new(proc);
        let proc_clone = proc.clone();
        let root_clone = root.clone();
        std::thread::spawn(move || {
            let result = proc_clone.scan_existing_files("group-1", &root_clone);
            let _ = tx.send(result);
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("scan_existing_files hung on a self-referential symlink cycle");
        let records = result.unwrap();

        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"cyc/a"), "the cyclic symlink itself must still be recorded");
        assert!(paths.contains(&"ordinary.txt"));
        assert_eq!(
            proc.state.get_record_kind("group-1", "cyc/a").unwrap(),
            Some(crate::types::RecordKind::Symlink)
        );
    }

    /// a two-hop symlinked-directory cycle (`a/b -> a`, i.e. a
    /// directory containing a symlink back to one of its own ancestors)
    /// also must not hang or recurse.
    #[cfg(unix)]
    #[test]
    fn ancestor_referencing_symlinked_directory_cycle_does_not_hang_or_recurse() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::create_dir_all(root.join("a")).unwrap();
        // a/b -> a (points back up at its own parent).
        std::os::unix::fs::symlink(root.join("a"), root.join("a/b")).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let proc = Arc::new(proc);
        let proc_clone = proc.clone();
        let root_clone = root.clone();
        std::thread::spawn(move || {
            let result = proc_clone.scan_existing_files("group-1", &root_clone);
            let _ = tx.send(result);
        });

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("scan_existing_files hung on an ancestor-referencing symlink cycle");
        let records = result.unwrap();
        let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains(&"a/b"));
        assert!(
            !paths.iter().any(|p| p.starts_with("a/b/")),
            "must never descend through the cycle"
        );
    }

    /// `normalize_syntactic`/`symlink_target_is_out_of_root`
    /// never touch the filesystem — proven by pointing at a target that
    /// does not exist at all (`read_link`-based classification must not
    /// require or attempt to resolve it).
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_classification_does_not_require_the_target_to_exist() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let link_path = root.join("dangling_link");
        std::os::unix::fs::symlink("this/path/does/not/exist.txt", &link_path).unwrap();

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: link_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(record.blocks.is_empty());
        assert_eq!(
            proc.state.get_symlink_target("group-1", "dangling_link").unwrap(),
            Some("this/path/does/not/exist.txt".to_string())
        );
        assert!(!proc.state.get_symlink_out_of_root("group-1", "dangling_link").unwrap());
    }
}
