//! Bridges a raw filesystem event into an indexed,
//! chunked `FileRecord`. Local changes are always
//! indexed immediately regardless of the link's pause state — pausing
//! only stops *propagating* changes to peers, so nothing is
//! lost while paused; `SyncState` itself is the queued-change backlog.
//!
//! The property that renaming a file doesn't re-transfer content falls out of this
//! design for free: chunking is content-addressed, so renaming a file
//! without editing it re-derives the exact same block hashes the local
//! store (and any peer that already synced the old path) already holds —
//! `ensure_blocks_present`'s dedup check means no bytes cross the network
//! for the unchanged content, even though the wire protocol has no
//! dedicated "rename" message.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use crate::change::{encoded_op_len, BlockHash, FileMeta, FileVersion, Op, SyncPath, VersionBlock};
use crate::chunker::{chunk_file, chunk_file_content_defined, CDC_SIZE_THRESHOLD};
use crate::dag_store::ChangeEmitter;
use crate::debounce::DebounceFlush;
use crate::error::SyncError;
use crate::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use crate::index::{LocalFileMetaColumns, SyncState};
use crate::root_identity::{is_root_marker_relative_path, VerifiedRoot};
use crate::types::{owner_exec_bit_from_metadata, FileRecord, MaterializationState, RecordKind};
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

/// True when a filesystem `Metadata`'s mtime equals the mtime an index row
/// recorded (`FileRecord::mtime_unix_nanos`, stored as nanoseconds since the
/// Unix epoch). Deriving this in one place keeps the "unchanged file" verdict
/// identical no matter which path reaches it: the per-file fast path
/// (`build_record_for_created_or_modified`) and the bulk startup/offline
/// reconcile scan (`reconcile_disk_with_ignore`) MUST agree, or a same-size
/// edit one path treats as a no-op the other would silently keep at the stale
/// version.
fn metadata_mtime_matches(metadata: &std::fs::Metadata, indexed_mtime_unix_nanos: i64) -> bool {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        == Some(indexed_mtime_unix_nanos)
}

/// True when `rel_path` (a root-relative index path, `/`-separated) sits
/// under any of the `failed_prefixes` a partial scan collected — the
/// root-relative directories the walk could not read. Matching is on whole
/// path components (`Path::starts_with`), so `foo` matches `foo/bar` but not
/// `foobar`; an empty prefix (the walk root itself failed) matches every
/// path. Used to scope offline-delete tombstone suppression to the failed
/// subtree(s) only, never tombstoning a path whose directory was unreadable.
fn path_is_within_failed_subtree(rel_path: &str, failed_prefixes: &[String]) -> bool {
    let candidate = Path::new(rel_path);
    failed_prefixes.iter().any(|prefix| candidate.starts_with(Path::new(prefix)))
}

/// What one filesystem event turned out to mean, once interpreted —
/// `process_event`'s result.
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
}

/// Extra classification produced when `build_record_for_created_or_modified`
/// determines a path is a symlink — carried
/// alongside, not inside, the `FileRecord` it returns. Like
/// `types::RecordKind` itself (see its doc comment), this is index-local
/// metadata surfaced through dedicated `SyncState` columns
/// (`set_record_kind`/`set_symlink_target`/`set_symlink_out_of_root`)
/// rather than a `FileRecord` field, so every existing `FileRecord {.. }`
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

/// Builds the local index metadata columns for a created/modified record from
/// the same inputs [`LocalChangeProcessor::content_op`] uses to build the
/// record's `FileVersion`, so the two are guaranteed to agree: a symlink's
/// classification produces `RecordKind::Symlink` + its target / out-of-root
/// flag (and no exec bit); a regular file produces `RecordKind::File` + its
/// exec bit (and a cleared symlink target/flag). Threading the result into the
/// emitting transaction (rather than applying it via post-commit setters) is
/// what makes the index row's metadata atomic with the emitted change's
/// `FileVersion`.
fn metadata_columns_for(
    classification: &Option<SymlinkClassification>,
    exec_bit: Option<bool>,
) -> LocalFileMetaColumns {
    match classification {
        Some(c) => LocalFileMetaColumns {
            record_kind: RecordKind::Symlink,
            symlink_target: Some(c.target.clone()),
            symlink_out_of_root: c.out_of_root,
            exec_bit: false,
        },
        None => LocalFileMetaColumns {
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            exec_bit: exec_bit.unwrap_or(false),
        },
    }
}

pub struct LocalChangeProcessor {
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
    device_id: String,
    /// When set, every accepted local mutation additionally appends a signed
    /// change to the history DAG in the same transaction as its index write.
    /// `None` (the default) preserves the pre-DAG behavior exactly — the
    /// index write happens on its own, no change is emitted — so a build that
    /// hasn't provisioned a signing key is unaffected. The daemon injects the
    /// emitter once the device's signing key is loaded.
    change_emitter: Option<Arc<ChangeEmitter>>,
}

/// Max ops in a single reconciliation-emitted change. Matches the initial
/// import's [`crate::dag_import::IMPORT_BATCH_OP_LIMIT`] so a bulk offline
/// diff converts into a chain of same-sized changes whichever path (import or
/// reconcile) first observes it, and stays far under the change decoder's hard
/// [`crate::change::MAX_OPS`] (65536) per-change ceiling.
const RECONCILE_CHUNK_OP_LIMIT: usize = crate::dag_import::IMPORT_BATCH_OP_LIMIT;

/// Max canonical op-bytes in a single reconciliation-emitted change. A change
/// cannot be wire-split, so one change must fit in one delivered
/// `ChangeBatch` message; the transport rejects any inbound message larger
/// than `MAX_INBOUND_FRAGMENTS_PER_MESSAGE` (1024) * `MAX_FRAGMENT_PAYLOAD`
/// (1200 B) ≈ 1.2 MiB. 256 KiB stays well under that (leaving room for the
/// change's fixed header, parents, and signature, and letting several changes
/// still share one batch message) while a pathological run of long paths — up
/// to `RECONCILE_CHUNK_OP_LIMIT` * ~4 KiB ≈ 4 MiB if bounded by op-count
/// alone — is instead split by this byte cap. At least one op is always taken
/// per chunk, so a single over-cap op (never possible: one op is at most a
/// 4 KiB-ish path plus 37 bytes) could not wedge the loop. Shares
/// [`crate::change::MAX_CHANGE_OP_BYTES`] with the initial import so the two
/// byte bounds can never drift.
const RECONCILE_CHUNK_BYTE_LIMIT: usize = crate::change::MAX_CHANGE_OP_BYTES;

/// How much of a disk-vs-index reconciliation scan is allowed to mutate
/// the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileMode {
    /// The full startup / burst-fallback reconciliation: index new files,
    /// re-version files whose on-disk content changed, drop now-ignored
    /// rows, and tombstone indexed files no longer on disk.
    Full { emit_tombstones: bool },
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

impl ReconcileMode {
    fn is_full(self) -> bool {
        matches!(self, Self::Full { .. })
    }

    fn is_add_only(self) -> bool {
        matches!(self, Self::AddOnly)
    }

    fn emits_tombstones(self) -> bool {
        matches!(self, Self::Full { emit_tombstones: true })
    }
}

impl LocalChangeProcessor {
    pub fn new(
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
        device_id: String,
    ) -> Self {
        Self { state, store, device_id, change_emitter: None }
    }

    /// Enables change-history emission: from here on, accepted local
    /// mutations dual-write a signed change alongside the index mutation.
    pub fn with_change_emitter(mut self, emitter: Arc<ChangeEmitter>) -> Self {
        self.change_emitter = Some(emitter);
        self
    }

    /// Builds the content version op for a created/updated record, together
    /// with the full [`FileVersion`] it references. The version hash covers the
    /// file's block list, size, and the metadata in scope at the write site
    /// (mtime, exec bit, and symlink target/kind when the record is a symlink).
    /// The op carries only the hash; the returned version carries the block
    /// list a receiver needs to materialize it, and is persisted alongside the
    /// emitted change.
    fn content_op(
        &self,
        record: &FileRecord,
        is_create: bool,
        exec_bit: bool,
        symlink_target: Option<String>,
    ) -> (Op, FileVersion) {
        // The chunker's real per-block sizes are in scope here, so the version
        // carries each block's exact length; a receiver rebuilds offsets from
        // them and validates each fetched block against its declared size.
        let blocks = record
            .blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect();
        let record_kind =
            if symlink_target.is_some() { RecordKind::Symlink } else { RecordKind::File };
        let meta = FileMeta {
            mtime_unix_nanos: record.mtime_unix_nanos,
            exec_bit,
            symlink_target,
            record_kind,
        };
        let version = FileVersion::new(blocks, record.size, meta);
        let version_hash = version.version_hash;
        let path = SyncPath(record.path.clone());
        let op = if is_create {
            Op::Create { path, version: version_hash }
        } else {
            Op::Update { path, version: version_hash }
        };
        (op, version)
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
    /// The existing index and
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
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones: true },
        )
    }

    /// Same as `scan_existing_files_with_ignore`, but lets the caller suppress
    /// this pass's missing-file tombstone emission via `emit_tombstones`.
    ///
    /// The startup crash-vs-offline-delete disambiguation depends on the
    /// interrupted-materialization repair pass having run first: repair is what
    /// distinguishes a crash-mid-materialize (missing target, blocks present
    /// locally, an open materialization intent -> reconstruct) from an offline
    /// user delete (missing target, no intent -> tombstone). When that repair
    /// pass ERRORED for this group on this boot, its disambiguation input is
    /// unavailable, so a `Hydrated`-but-missing file cannot be safely told apart
    /// from a genuine deletion. Passing `emit_tombstones = false` then defers
    /// ALL of this scan's delete emission to a later boot on which repair
    /// succeeds — fail-closed: never emit a delete when a crash cannot be told
    /// from a delete. A path is still indexed/updated as usual; only the
    /// missing-file tombstone step is withheld.
    ///
    /// `emit_tombstones = true` reproduces `scan_existing_files_with_ignore`
    /// exactly.
    pub fn scan_existing_files_with_ignore_gated(
        &self,
        group_id: &str,
        root: &Path,
        ignore_set: &EffectiveIgnoreSet,
        emit_tombstones: bool,
    ) -> Result<Vec<FileRecord>, SyncError> {
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(
            group_id,
            &root,
            ignore_set,
            ReconcileMode::Full { emit_tombstones },
        )
    }

    /// Establishes this link's root identity for a caller that has only a path.
    ///
    /// Every public reconcile entry point funnels through here, so verification
    /// is unconditional: there is no entry point that scans an unverified root,
    /// and `reconcile_disk_with_ignore`'s `&VerifiedRoot` parameter is what
    /// makes that structural rather than a convention a new entry point could
    /// quietly break.
    fn verified_root(&self, group_id: &str, root: &Path) -> Result<VerifiedRoot, SyncError> {
        VerifiedRoot::open(root, group_id, &self.state)
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
        // Root identity is still verified, even though this scope cannot
        // tombstone and so cannot cause the loss that motivates the check. The
        // converse hazard is what makes it worth paying for here: an add-only
        // walk of a *wrong* filesystem indexes that volume's files as new
        // members of this group and pushes them to every device. That is not
        // silent loss, but it is silent pollution, and this is a periodic
        // backstop — it would land repeatedly and unattended.
        let root = self.verified_root(group_id, root)?;
        self.reconcile_disk_with_ignore(group_id, &root, ignore_set, ReconcileMode::AddOnly)
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

    /// The single choke point every disk reconcile passes through, and the
    /// reason it takes a [`VerifiedRoot`] rather than a `&Path`.
    ///
    /// A scan is *authoritative*: a path it does not find on disk becomes a
    /// tombstone that propagates to every device. That is only sound if the
    /// directory walked is genuinely this link's folder, which an existence
    /// check cannot establish — an unmounted volume leaves its mountpoint
    /// behind as an empty directory that passes every such check, and the scan
    /// then reads a whole folder as deleted. `VerifiedRoot` is the proof that
    /// the check ran, carried in the type rather than repeated at each call
    /// site, so a future entry point cannot reintroduce the gap by forgetting
    /// it: there is no way to hand this function a root without having verified
    /// one first. It also arrives already canonical, which subsumes the bare
    /// `root.canonicalize()?` this used to open with — the walked entries must
    /// relativize against the same resolution `process_event` performs
    /// internally, or `strip_prefix` silently fails for every entry (the same
    /// class of mismatch that function's own doc comment warns about for OS
    /// watchers).
    fn reconcile_disk_with_ignore(
        &self,
        group_id: &str,
        root: &VerifiedRoot,
        ignore_set: &EffectiveIgnoreSet,
        mode: ReconcileMode,
    ) -> Result<Vec<FileRecord>, SyncError> {
        let root = root.path();

        let existing_by_path: std::collections::HashMap<String, FileRecord> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .map(|record| (record.path.clone(), record))
            .collect();
        let materialization_by_path = self.state.list_materialization_states(group_id)?;

        // Test-only seam: fires right after the whole-index snapshot
        // (`existing_by_path`) has been read but before any record derived from
        // it is committed below. It lets a test deterministically inject a
        // concurrent peer change for a scanned path into exactly the
        // snapshot-vs-commit window this scan's missing per-path locking used to
        // leave open, to prove the group startup barrier closes it. Compiled out
        // entirely in non-test builds.
        #[cfg(test)]
        scan_test_hooks::fire_post_snapshot(group_id);

        // Whether this group already has change history, so the reconciliation
        // below must route its detected changes through the change-emission
        // path (the offline-edit/offline-delete case). A group whose DAG is
        // still empty is deliberately left to the chunked initial import that
        // runs right after the scan, so this fix never changes how a first
        // link's whole index becomes history.
        let has_dag_history =
            self.change_emitter.is_some() && !self.state.dag_group_heads(group_id)?.is_empty();

        // Becoming ignored is not a deletion. Drop this device's local
        // index row so future sync work no longer considers the path,
        // but do not emit a tombstone and do not touch the on-disk file.
        // This mutates an existing index row, so it is a
        // `Full`-scope-only step — the add-only backstop never removes
        // or re-versions a known path.
        if mode.is_full() {
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
        // exec-bit updates for paths
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
        // A walk error means `seen_paths` is not an authoritative inventory
        // *for the subtree that failed* — a file's absence from `seen_paths`
        // there might just mean we could not read its directory, not that it
        // was deleted, so absence must not be converted into a tombstone
        // under that subtree. But it says nothing about cleanly-walked
        // subtrees, so suppression is scoped per-failed-prefix rather than
        // disabling tombstoning for the whole scan: one persistently-erroring
        // directory must not indefinitely defer a real deletion elsewhere
        // (which a peer that evicted the file could then re-hydrate). Each
        // failed directory's root-relative prefix is collected here and
        // consulted in the tombstone loop below. If an error carries no path
        // at all (it cannot be attributed to a subtree), fall back to the
        // conservative whole-scan suppression via `scan_complete`.
        let mut scan_complete = true;
        let mut failed_prefixes: Vec<String> = Vec::new();
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    match error.path().and_then(|p| p.strip_prefix(root).ok()) {
                        Some(rel) => {
                            // The root-relative directory (or entry) walkdir
                            // could not read. An empty prefix means the walk
                            // root itself failed, which `starts_with("")`
                            // matches for every path — i.e. the whole tree is
                            // suppressed, the correct outcome when the root is
                            // unreadable.
                            failed_prefixes
                                .push(rel.to_string_lossy().replace('\\', "/"));
                        }
                        None => {
                            // No attributable path — cannot scope the
                            // suppression, so fail safe for the entire pass.
                            scan_complete = false;
                        }
                    }
                    tracing::warn!(
                        group_id,
                        root = %root.display(),
                        error = %error,
                        "filesystem scan was partial; tombstone reconciliation is \
                         suppressed for the affected subtree"
                    );
                    continue;
                }
            };
            // a symlink (whatever it points to) is admitted
            // here as its own leaf entry — `entry.file_type` reflects
            // lstat metadata (never follows) since `follow_links(false)`
            // is in effect, so a symlink to a directory shows up here as
            // `is_symlink == true`, `is_dir == false`, and walkdir
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
            if mode.is_add_only() && existing.is_some() {
                continue;
            }

            let entry_metadata = entry.metadata().ok();
            // "Already current" must be judged on the *same* basis as the
            // per-file path (`build_record_for_created_or_modified`'s fast
            // path): the cheap size+mtime stat gate first (via the shared
            // `metadata_mtime_matches` helper), then a content verification
            // before the no-op is trusted. A size-only gate is strictly
            // weaker than both that path and the live watcher (which
            // re-hashes on Modify): an offline edit that preserves the byte
            // length but changes the bytes (a flag flip, a same-length
            // hash/uuid swap, an in-place binary/DB edit) would be skipped
            // here, pinning the index at the stale version while disk holds
            // new bytes.
            //
            // Closing the tail: an edit that preserves BOTH size and mtime
            // (`touch -r`, archive extraction that restores timestamps, an
            // in-place same-length overwrite) is invisible to any stat-only
            // check, so a regular file that passes the size+mtime gate is
            // additionally verified against its indexed block hashes with
            // `disk_bytes_match_indexed_blocks` — the same content check the
            // per-file fast path now applies. That verifier reads the file
            // once, comparing each indexed block's SHA-256 in sequence and
            // early-exiting on the first mismatch, without re-chunking or
            // writing any block to the store. When the bytes differ (or any
            // size/mtime mismatch), the path falls through to
            // `build_record_for_created_or_modified` below, which re-chunks
            // and re-versions. Symlinks carry no blocks (their identity is
            // the target text, checked in `build_symlink_record`), so they
            // keep the stat-only verdict and fall through to that path
            // unchanged. The read cost is bounded: it lands only on files
            // that already matched size+mtime, only on the infrequent full
            // startup/burst-fallback scan — the high-frequency `AddOnly`
            // backstop never reaches this path for an already-indexed file
            // (it `continue`s above at `existing.is_some()`).
            let already_current = match (&existing, &entry_metadata) {
                (Some(existing), Some(metadata)) => {
                    !existing.deleted
                        && existing.size == metadata.len()
                        && metadata_mtime_matches(metadata, existing.mtime_unix_nanos)
                        && (!file_type.is_file()
                            || crate::materialization::disk_bytes_match_indexed_blocks(
                                path,
                                &existing.blocks,
                            )?)
                }
                _ => false,
            };
            if already_current {
                // content (size) is
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

        // the walk above only ever adds/updates files that still
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
        // `emit_tombstones` is `false` when the interrupted-materialization
        // repair pass that must run before this scan ERRORED for this group on
        // this boot: without repair's crash-vs-offline-delete disambiguation, a
        // `Hydrated`-but-missing file cannot be safely told apart from a
        // genuine deletion, so ALL delete emission is deferred to a later boot
        // on which repair succeeds. Fail-closed: never emit a delete when a
        // crash cannot be told from a delete. See
        // `scan_existing_files_with_ignore_gated`.
        if mode.emits_tombstones() && scan_complete {
            for (path, existing) in &existing_by_path {
                if existing.deleted || seen_paths.contains(path) {
                    continue;
                }
                if is_excluded_from_sync(Path::new(path), false, ignore_set) {
                    continue;
                }
                // Fail-safe, per-subtree: never tombstone a path that lives
                // under a directory this pass could not walk — its absence
                // from `seen_paths` may be an unread directory, not a real
                // deletion. `Path::starts_with` matches on whole path
                // components, so the prefix `broken` suppresses `broken/x`
                // but never `broken-sibling/x`. Paths under cleanly-walked
                // subtrees are still tombstoned normally.
                if path_is_within_failed_subtree(path, &failed_prefixes) {
                    continue;
                }
                // Never tombstone a path with an open materialization intent: a
                // crash interrupted its write (the file is missing precisely
                // because the rename never completed), and the durable intent
                // is the signal that the interrupted-materialization repair
                // pass must reconstruct it from the locally-present blocks — not
                // that the user deleted it. Absent this check, a crash
                // mid-eager-materialize whose repair could not run (or errored)
                // this boot would be misread here as an offline deletion and a
                // `Delete` propagated group-wide, silently destroying a fully
                // reconstructable file. Fail-closed: an errored intent lookup
                // propagates via `?` rather than falling through to a tombstone.
                if self.state.has_materialization_intent(group_id, path)? {
                    continue;
                }
                let mut tombstone = existing.clone();
                tombstone.deleted = true;
                tombstone.version.increment(&self.device_id);
                records.push(tombstone);
            }
        }

        // Route the reconciliation's detected changes through the same
        // change-emission path a live `process_event` uses, so an offline
        // edit or delete picked up only by this startup scan advances the
        // group's change-history DAG — not merely the local index — closing
        // the gap where a change-history-negotiating peer would otherwise
        // never learn of it. Only a group that already has history takes this
        // path (see `has_dag_history`); an empty record set emits nothing, so
        // re-running the scan never appends a duplicate head. A scan is always
        // this device's own local content — same origin as `process_event`'s
        // single-file write path.
        if has_dag_history && !records.is_empty() {
            // Present only when `has_dag_history` already required it.
            let emitter = self.change_emitter.as_ref().expect("emitter present");
            let exec_by_path: std::collections::HashMap<&str, bool> =
                pending_exec_bits.iter().map(|(p, b)| (p.as_str(), *b)).collect();
            let classification_by_path: std::collections::HashMap<&str, &SymlinkClassification> =
                pending_symlinks.iter().map(|(p, c)| (p.as_str(), c)).collect();

            // Build the emission payload for every detected record, aligned
            // 1:1 with `records`: its op, the `FileVersion` a create/update
            // references (`None` for a tombstone), and the local metadata
            // columns to write in the SAME transaction as the change so the
            // index row's kind/target/exec-bit can never lag the version the
            // change carries across a crash.
            let mut ops: Vec<Op> = Vec::with_capacity(records.len());
            let mut versions: Vec<Option<FileVersion>> = Vec::with_capacity(records.len());
            let mut metas: Vec<Option<LocalFileMetaColumns>> = Vec::with_capacity(records.len());
            for record in &records {
                if record.deleted {
                    ops.push(Op::Delete { path: SyncPath(record.path.clone()) });
                    versions.push(None);
                    metas.push(None);
                } else {
                    // A path that was live before this scan is an `Update`;
                    // a path that is new or was tombstoned is a `Create` —
                    // exactly how `process_event` classifies the same record.
                    let was_live =
                        existing_by_path.get(&record.path).map(|e| !e.deleted).unwrap_or(false);
                    let exec_bit = exec_by_path.get(record.path.as_str()).copied().unwrap_or(false);
                    let classification: Option<SymlinkClassification> =
                        classification_by_path.get(record.path.as_str()).map(|c| (*c).clone());
                    let symlink_target = classification.as_ref().map(|c| c.target.clone());
                    let (op, version) =
                        self.content_op(record, !was_live, exec_bit, symlink_target);
                    let exec_for_meta =
                        if classification.is_some() { None } else { Some(exec_bit) };
                    ops.push(op);
                    versions.push(Some(version));
                    metas.push(Some(metadata_columns_for(&classification, exec_for_meta)));
                }
            }

            // A bulk offline diff (e.g. deleting or renaming 100k files while
            // the daemon was stopped) would otherwise become a single change
            // with 100k ops — which no peer can decode (over `change::MAX_OPS`)
            // and no wire message can carry (over the transport fragment cap),
            // stranding that head permanently un-propagatable. Split it into
            // op-count- and byte-bounded chunks, each committed as its own
            // change. Because `dag_store::emit_local_change` takes the group's
            // current heads as parents and each chunk commits before the next
            // runs, the chunks form a single linear chain converging on one
            // head. A crash mid-way leaves the already-committed chunks durable;
            // the remaining disk-vs-index diff is re-derived and re-emitted
            // (chaining onto the last committed chunk) by the next scan.
            let mut committed: Vec<FileRecord> = Vec::new();
            let mut withheld_from: Option<usize> = None;
            let mut start = 0usize;
            while start < records.len() {
                let mut end = start;
                let mut chunk_bytes = 0usize;
                while end < records.len() {
                    let op_bytes = encoded_op_len(&ops[end]);
                    // Always take at least one op (`end == start`), so a single
                    // over-cap op could never wedge the loop; otherwise stop at
                    // either bound.
                    if end > start
                        && (end - start >= RECONCILE_CHUNK_OP_LIMIT
                            || chunk_bytes + op_bytes > RECONCILE_CHUNK_BYTE_LIMIT)
                    {
                        break;
                    }
                    chunk_bytes += op_bytes;
                    end += 1;
                }
                let chunk_records = &records[start..end];
                let chunk_ops: Vec<Op> = ops[start..end].to_vec();
                let chunk_versions: Vec<FileVersion> =
                    versions[start..end].iter().flatten().cloned().collect();
                let chunk_metas = &metas[start..end];
                match self.state.upsert_files_batch_emitting_change(
                    group_id,
                    chunk_records,
                    &self.device_id,
                    chunk_ops,
                    &chunk_versions,
                    chunk_metas,
                    emitter,
                ) {
                    Ok(_) => committed.extend_from_slice(chunk_records),
                    // The group's policy is stale or has not loaded yet this
                    // run, so the emit withheld this chunk rather than stamp a
                    // placeholder-auth change every valid-policy peer would
                    // reject (see `upsert_file_emitting_change`). Any earlier
                    // chunks already committed are real emitted changes and
                    // stand; do NOT fall back to a DAG-silent index write for
                    // the rest. Journal this chunk and the remaining tail dirty
                    // (below) so the dirty-journal re-drive re-emits them — with
                    // a real authorization stamp — once policy heals, leaving
                    // the index unadvanced for them so a later full rescan can
                    // still re-derive the same diff.
                    Err(SyncError::PolicyUnavailable) => {
                        withheld_from = Some(start);
                        break;
                    }
                    Err(e) => return Err(e),
                }
                start = end;
            }

            if let Some(from) = withheld_from {
                let observed = now_unix_nanos();
                for record in &records[from..] {
                    let kind = if record.deleted {
                        FsChangeKind::Removed
                    } else {
                        FsChangeKind::CreatedOrModified
                    };
                    if let Err(e) = self.state.record_dirty_path(
                        group_id,
                        &record.path,
                        dirty_kind_str(kind),
                        observed,
                    ) {
                        tracing::warn!(
                            error = %e,
                            path = %record.path,
                            group_id,
                            "failed to journal a policy-withheld offline change; a later \
                             full rescan re-derives it from the unadvanced index"
                        );
                    }
                }
                // Broadcast only the chunks that durably entered the DAG; the
                // withheld tail re-emits via the dirty journal.
                return Ok(committed);
            }
            Ok(records)
        } else {
            // The group has no change DAG yet (a first link's whole index is
            // seeded into history by the chunked initial import that runs right
            // after this scan), so an index-only write here is not a silent DAG
            // divergence — there is no DAG to diverge from. The metadata columns
            // are applied as ordinary post-write setters (there is no change to
            // keep them atomic with, and these setters require the row the
            // batch write above just created).
            self.state.upsert_files_batch(group_id, &records, &self.device_id)?;
            for (path, classification) in &pending_symlinks {
                self.apply_symlink_classification(group_id, path, classification)?;
            }
            for (path, exec_bit) in &pending_exec_bits {
                self.state.set_exec_bit(group_id, path, *exec_bit)?;
            }
            Ok(records)
        }
    }

    /// Processes one filesystem event under a linked folder rooted at
    /// `root`, updating the local index (for an ordinary file change) and
    /// returning what happened. The caller is responsible for
    /// broadcasting a `FileChanged` record to connected, unpaused peer
    /// sessions via `PeerSyncSession::send_index_update`.
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
        // root from (via `tempfile::tempdir` or otherwise). Without
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

        if is_excluded_from_sync(&rel_path, event.path.is_dir(), ignore_set) {
            return Ok(LocalChangeOutcome::None);
        }

        // hold the per-(group,path) lock for the whole
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
                // `mark_deleted` creates a brand-new tombstone row
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
                        match &self.change_emitter {
                            Some(emitter) => {
                                self.state.mark_deleted_emitting_change(
                                    group_id,
                                    orphan_path,
                                    &self.device_id,
                                    now,
                                    emitter,
                                )?;
                            }
                            None => {
                                self.state.mark_deleted_at(
                                    group_id,
                                    orphan_path,
                                    &self.device_id,
                                    now,
                                )?;
                            }
                        }
                        if let Some(record) = self.state.get_file(group_id, orphan_path)? {
                            records.push(record);
                        }
                    }
                    return Ok(LocalChangeOutcome::FilesChanged(records));
                }
                let observed = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                match &self.change_emitter {
                    Some(emitter) => {
                        self.state.mark_deleted_emitting_change(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                            emitter,
                        )?;
                    }
                    None => {
                        self.state.mark_deleted_at(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                        )?;
                    }
                }
                Ok(match self.state.get_file(group_id, &rel_path)? {
                    Some(record) => LocalChangeOutcome::FileChanged(record),
                    None => LocalChangeOutcome::None,
                })
            }
            FsChangeKind::CreatedOrModified => {
                let materialization_state =
                    self.state.get_materialization_state(group_id, &rel_path)?;
                let existing = self.state.get_file(group_id, &rel_path)?;
                // Whether the path currently has live (non-tombstoned)
                // content decides `Create` vs `Update` for the emitted change.
                let was_live = existing.as_ref().map(|e| !e.deleted).unwrap_or(false);
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
                    match &self.change_emitter {
                        Some(emitter) => {
                            let symlink_target = classification.as_ref().map(|c| c.target.clone());
                            let (op, version) = self.content_op(
                                record,
                                !was_live,
                                exec_bit.unwrap_or(false),
                                symlink_target.clone(),
                            );
                            // The record kind / symlink target / out-of-root
                            // flag / exec bit are written in the SAME
                            // transaction as the emitted change (folded into
                            // `upsert_file_emitting_change`), mirroring exactly
                            // the `FileMeta` `content_op` put in the
                            // `FileVersion` above. A crash can therefore never
                            // leave the index row's metadata columns lagging
                            // the change's `FileVersion` — the old post-commit
                            // `set_*` setters are gone from this emit path.
                            let meta = metadata_columns_for(&classification, exec_bit);
                            self.state.upsert_file_emitting_change(
                                group_id,
                                record,
                                &self.device_id,
                                vec![op],
                                std::slice::from_ref(&version),
                                Some(&meta),
                                emitter,
                            )?;
                        }
                        None => {
                            self.state.upsert_file_with_origin(
                                group_id,
                                record,
                                &self.device_id,
                            )?;
                            // No DAG emission here (no signing key provisioned),
                            // so there is no DAG/index divergence hazard: apply
                            // the metadata columns as ordinary post-write
                            // updates. The setters are `UPDATE`-only and require
                            // the row the write above just created.
                            if let Some(classification) = &classification {
                                self.apply_symlink_classification(
                                    group_id,
                                    &rel_path,
                                    classification,
                                )?;
                            }
                            if let Some(exec_bit) = exec_bit {
                                self.state.set_exec_bit(group_id, &rel_path, exec_bit)?;
                            }
                        }
                    }
                }
                Ok(outcome)
            }
        }
    }

    /// Builds the `FileRecord` for a `CreatedOrModified` event without
    /// writing it to the index — shared by `process_event` (which writes
    /// immediately, one file at a time) and `scan_existing_files` (which
    /// batches writes via `upsert_files_batch`, batch-processing changes
    /// ). `existing` and `materialization_state` are supplied by
    /// the caller rather than looked up here, so a bulk-loading caller
    /// (`scan_existing_files`) never issues a per-file query for them.
    ///
    /// The third element of the returned tuple
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
        if matches!(materialization_state, Some(MaterializationState::Placeholder)) {
            return Ok((LocalChangeOutcome::None, None, None));
        }

        // a size+mtime fast-path, checked before
        // any chunking. A filesystem watcher routinely reports a
        // `CreatedOrModified` event for a file whose bytes never actually
        // changed — this device's own self-echo (see the block-hash
        // comparison further down, which already resolves this case to
        // `None`, just after paying for a full read+chunk+hash first), an
        // editor's atomic rewrite that restores identical content, or a
        // backup/sync tool that bumps mtime without touching bytes. When
        // both `size` *and* `mtime` match a non-deleted index entry, that
        // is only "probably unchanged": a `stat` is orders of magnitude
        // cheaper than reading and chunking the whole file, but it is not,
        // on its own, a correctness guarantee.
        //
        // For data integrity we must not trust the stat verdict blindly.
        // A content edit that preserves BOTH byte length and mtime — an
        // in-place same-length overwrite, or any writer that restores the
        // mtime via `utimes`/`touch -r` after editing — would otherwise be
        // silently missed here, pinning the index (and every peer) at the
        // stale version while disk holds new bytes. So before taking the
        // no-op path, verify the on-disk bytes against the indexed block
        // hashes with `disk_bytes_match_indexed_blocks`: it streams the
        // file comparing each indexed block's SHA-256 in sequence and
        // early-exits on the first mismatch, without re-chunking (no
        // content-defined boundary search) and without writing any block to
        // the store — much cheaper than the full chunk path, and it runs
        // only for files that already passed the cheap size+mtime gate. If
        // the bytes differ, this whole fast-path is skipped and the edit
        // falls through to the full chunk-and-compare path below, which
        // re-versions the record and emits the change.
        if let Some(existing) = &existing {
            if !existing.deleted {
                if let Ok(metadata) = std::fs::metadata(path) {
                    let current_mtime_matches =
                        metadata_mtime_matches(&metadata, existing.mtime_unix_nanos);
                    if existing.size == metadata.len()
                        && current_mtime_matches
                        && crate::materialization::disk_bytes_match_indexed_blocks(
                            path,
                            &existing.blocks,
                        )?
                    {
                        // size, mtime, AND content are all verified
                        // identical here — but that still isn't the whole
                        // "nothing changed" story: a `chmod` (owner-exec bit
                        // toggle) touches none of them, so compare the exec
                        // bit too, off the same `Metadata` already fetched
                        // above (no extra syscall), before trusting this
                        // fast path's no-op conclusion. When only the exec
                        // bit differs, this
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

        // Chunking algorithm is chosen automatically from file size: files
        // at or above the size threshold use content-defined chunking (so
        // an internal edit re-transfers only the affected region), and
        // everything below uses the original fixed-size chunker. Self-echo
        // suppression below just compares whatever this device's chunker
        // produced against what's indexed, so it needs no algorithm-
        // awareness either way.
        let use_cdc = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= CDC_SIZE_THRESHOLD;
        let blocks = if use_cdc {
            chunk_file_content_defined(self.store.as_ref(), path)?
        } else {
            chunk_file(self.store.as_ref(), path)?
        };
        // Chunking has read these bytes from this group's local filesystem,
        // hashed them, and durably put them in the shared physical store.
        // Record that fact separately from peer-controlled metadata so block
        // serving cannot infer group ownership from a FileVersion reference.
        let block_hashes: Vec<Vec<u8>> = blocks.iter().map(|block| block.hash.clone()).collect();
        self.state.record_group_block_provenance(group_id, &block_hashes)?;

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
        // content genuinely changed
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
    /// carries no blocks.
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
        // dereference that is forbidden.
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
    /// runs a full `scan_existing_files` reconciliation instead.
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
                for (path, kind, observed_at) in paths {
                    // Journal this detected edit durably *before* any
                    // block-store/index work runs. The debounce accumulator
                    // has already drained the path, so if the process below
                    // crashes, restarts, or hits a multi-second disk-full/EIO
                    // and the retry loop eventually gives up, the in-memory
                    // knowledge that this path changed would otherwise be lost
                    // — a permanent split-brain. The row survives until the
                    // read/blockify/put/index+DAG step commits (cleared on the
                    // `Ok` arms below); a startup rescan and the on-failure
                    // retry both re-drive whatever is still journaled. Keyed by
                    // the same relative path the index uses, so the
                    // materialization-repair quarantine (`is_path_dirty`) sees
                    // it too. A journal write failure is itself only logged:
                    // losing the belt-and-suspenders row must not abort
                    // processing the edit the normal way.
                    let dirty_key = relative_key(root, &path);
                    if let Some(key) = &dirty_key {
                        if let Err(e) = self.state.record_dirty_path(
                            group_id,
                            key,
                            dirty_kind_str(kind),
                            observed_at,
                        ) {
                            tracing::warn!(
                                error = %e,
                                path = %path.display(),
                                group_id,
                                "failed to journal a dirty local path before processing; \
                                 proceeding with best-effort in-memory handling"
                            );
                        }
                    }
                    // A path's chunk/index step reads and writes content-
                    // addressed blocks through the block store. A *transient*
                    // block-store fault there — a disk-full
                    // (`SyncError::DiskPressure`) or an EIO
                    // (`SyncError::Storage(StorageError::Io)`) — must not
                    // silently drop this already-detected local edit: the
                    // debounce accumulator has already drained this path, and
                    // no live-repair sweep revisits a `Hydrated` row whose
                    // on-disk bytes then silently drifted, so a dropped local
                    // write here is a permanent split-brain (two devices at
                    // the identical version vector with different on-disk
                    // bytes, which — equal VV being the sync identity — never
                    // reconcile). This mirrors the peer-materialize
                    // `reconstruct_file` guard (`PeerSyncSession::materialize`):
                    // the transient fault clears on a later, non-faulting
                    // attempt, so re-run this path's indexing a bounded number
                    // of times before giving up. Nothing is upserted on a
                    // failed attempt (chunking runs before any index write), so
                    // a retry is idempotent — it re-derives the same record and
                    // the same single version increment. A genuinely permanent
                    // error (anything not classified retriable) is not retried
                    // and fails exactly as before, so there is no
                    // unbounded/spin-forever risk.
                    let mut attempt = 0u32;
                    loop {
                        let result = self
                            .process_event_with_ignore_at(
                                group_id,
                                root,
                                &FsChangeEvent { path: path.clone(), kind },
                                ignore_set,
                                Some(observed_at),
                            )
                            .await;
                        // The read/blockify/put/index+DAG step for this path
                        // committed (or was a no-op), so its durable dirty-journal
                        // row is no longer needed — clear it. A crash in the
                        // narrow window between the index+DAG commit and this
                        // delete just leaves the row for the next rescan, which
                        // re-reads the path, finds disk == index, and clears it
                        // as a `None` outcome: idempotent, never a lost edit.
                        let clear_dirty = || {
                            if let Some(key) = &dirty_key {
                                if let Err(e) = self.state.clear_dirty_path(group_id, key) {
                                    tracing::warn!(
                                        error = %e,
                                        path = %key,
                                        group_id,
                                        "failed to clear a processed dirty-path journal row; \
                                         a later rescan will re-verify and clear it"
                                    );
                                }
                            }
                        };
                        match result {
                            Ok(LocalChangeOutcome::FileChanged(record)) => {
                                records.push(record);
                                clear_dirty();
                                break;
                            }
                            Ok(LocalChangeOutcome::FilesChanged(orphaned)) => {
                                records.extend(orphaned);
                                clear_dirty();
                                break;
                            }
                            Ok(LocalChangeOutcome::None) => {
                                clear_dirty();
                                break;
                            }
                            Err(SyncError::PolicyUnavailable) => {
                                // The group's policy is stale, so the emit path
                                // withheld this edit's change rather than stamp
                                // it with a placeholder authorization context —
                                // a placeholder-auth change would become a local
                                // DAG head every valid-policy peer rejects,
                                // stranding this and every descendant change on
                                // an un-replicable branch. This is expected and
                                // transient, not a failure: leave the durable
                                // dirty-journal row in place (do NOT clear it)
                                // so the startup/backstop re-drive re-emits the
                                // path — with a real authorization stamp — once a
                                // valid policy snapshot restores the group.
                                // Nothing was written to the index or the DAG
                                // (the emit path returns before opening its write
                                // transaction), and the user's on-disk bytes are
                                // untouched; only the change emission is deferred.
                                let reason = SyncError::PolicyUnavailable.to_string();
                                if let Some(key) = &dirty_key {
                                    if let Err(je) =
                                        self.state.mark_dirty_path_attempt(group_id, key, &reason)
                                    {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                tracing::info!(
                                    path = %path.display(),
                                    group_id,
                                    "withheld a local change because the group's policy is \
                                     stale; left the path journaled dirty to re-emit once a \
                                     valid policy snapshot is admitted"
                                );
                                break;
                            }
                            Err(e) => {
                                if is_retriable_block_store_error(&e)
                                    && attempt < MAX_LOCAL_INDEX_RETRIES
                                {
                                    attempt += 1;
                                    // Short backoff before re-reading/re-
                                    // writing the content-addressed blocks.
                                    // Under the deterministic simulator this
                                    // advances virtual time at no real cost;
                                    // in production it gives a transient disk
                                    // fault a moment to clear.
                                    tokio::time::sleep(LOCAL_INDEX_RETRY_BACKOFF).await;
                                    continue;
                                }
                                // Retries exhausted (or a permanent error).
                                // Leave the dirty-journal row in place — record
                                // the failure so the daemon's startup rescan
                                // (and any later flush touching the path)
                                // re-drives it rather than dropping the edit.
                                if let Some(key) = &dirty_key {
                                    if let Err(je) = self.state.mark_dirty_path_attempt(
                                        group_id,
                                        key,
                                        &e.to_string(),
                                    ) {
                                        tracing::warn!(
                                            error = %je,
                                            path = %key,
                                            group_id,
                                            "failed to record a dirty-path processing attempt"
                                        );
                                    }
                                }
                                tracing::warn!(
                                    error = %e,
                                    path = %path.display(),
                                    group_id,
                                    attempts = attempt,
                                    "failed to process one path in a debounced batch after \
                                     retries; left journaled dirty for re-drive on rescan/restart"
                                );
                                break;
                            }
                        }
                    }
                }
                Ok(FlushOutcome { records })
            }
            DebounceFlush::BurstFallback => {
                let records = self.scan_existing_files_with_ignore(group_id, root, ignore_set)?;
                Ok(FlushOutcome { records })
            }
        }
    }

    /// Re-drives every path still journaled dirty for `group_id` through the
    /// normal flush executor — the daemon's startup rescan and the durability
    /// backstop against a crash, a restart, or a disk fault that outlived the
    /// in-flight retry. Each `local_dirty_paths` row is turned back into the
    /// exact `FsChangeEvent` the debounce executor would have processed and run
    /// through `process_flush`, which re-reads the path, re-derives its record,
    /// commits the index + change DAG, and (on success) clears the row. A path
    /// whose on-disk content already matches the index resolves to `None` and
    /// is simply cleared — idempotent, never a spurious re-edit; one that still
    /// can't be processed stays journaled for the next attempt. Returns the
    /// produced records so the caller can announce them exactly as a live
    /// flush would.
    pub async fn redrive_dirty_journal(
        &self,
        group_id: &str,
        root: &Path,
    ) -> Result<FlushOutcome, SyncError> {
        let dirty = self.state.list_dirty_paths(group_id)?;
        if dirty.is_empty() {
            return Ok(FlushOutcome::default());
        }
        tracing::info!(
            group_id,
            count = dirty.len(),
            "re-driving journaled local dirty paths (startup/backstop rescan)"
        );
        // Reconstruct absolute event paths the same way the watcher produced
        // them — `process_event_with_ignore_at` re-relativizes against a
        // canonicalized `root`, so joining onto the canonical root here round-
        // trips to the stored relative key.
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let paths: Vec<(PathBuf, FsChangeKind, i64)> = dirty
            .into_iter()
            .map(|d| {
                (
                    canonical_root.join(&d.path),
                    dirty_kind_from_str(&d.change_kind),
                    d.observed_at_unix_nanos,
                )
            })
            .collect();
        self.process_flush(group_id, root, DebounceFlush::Paths(paths)).await
    }
}

/// How many times a single path's chunk/index step is retried when it fails
/// with a *transient* block-store fault before the flush gives up on that
/// path. Bounded so a genuinely-stuck store can never spin forever; large
/// enough that a brief disk blip (or, under the deterministic simulator, a
/// fault decorator's "every Nth op" schedule) reliably clears on a later,
/// non-faulting attempt. Kept in line with the peer-materialize reconstruct
/// guard's own bound.
const MAX_LOCAL_INDEX_RETRIES: u32 = 20;

/// Backoff between local-index retry attempts (see `MAX_LOCAL_INDEX_RETRIES`).
const LOCAL_INDEX_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Whether a `SyncError` from a path's chunk/index step is a *transient*
/// block-store fault that a bounded retry can clear, versus a permanent
/// error that must fail as before. Only the two transient disk-fault shapes
/// are retriable: a disk-full rejection (`DiskPressure`, from the block
/// store's own headroom preflight or an ENOSPC on write) and a bare
/// block-store I/O error (an EIO on the underlying `put`/`get`, which the
/// `From<StorageError>` impl wraps as `Storage(Io)` — never the top-level
/// `Io` variant, which is a filesystem call). Every other error — a checksum
/// mismatch (a torn/corrupt block), a missing block, an invalid path, or a
/// database/path-escape error — is permanent: retrying it just wastes
/// attempts, so it is classified non-retriable and fails immediately,
/// exactly as before this guard existed.
fn is_retriable_block_store_error(e: &SyncError) -> bool {
    matches!(
        e,
        SyncError::DiskPressure { .. }
            | SyncError::Storage(yadorilink_local_storage::StorageError::Io(_))
    )
}

/// The link-relative, forward-slash-normalized key for `path` under `root` —
/// the exact form the index and the `local_dirty_paths` journal use as a path
/// key, so a journaled dirty row and the record it corresponds to always agree.
/// Mirrors `process_event_with_ignore_at`'s own relativization (canonicalize
/// `root`, `strip_prefix`, `\` → `/`). Returns `None` when `path` is not under
/// `root` or is the root itself — cases the executor treats as a no-op anyway.
fn relative_key(root: &Path, path: &Path) -> Option<String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let rel = path.strip_prefix(&root).ok()?;
    let rel = rel.to_string_lossy().replace('\\', "/");
    if rel.is_empty() {
        return None;
    }
    Some(rel)
}

/// Serialized `FsChangeKind` as stored in the `local_dirty_paths` journal, so a
/// startup/backstop re-drive can reconstruct the exact `FsChangeEvent`.
fn dirty_kind_str(kind: FsChangeKind) -> &'static str {
    match kind {
        FsChangeKind::CreatedOrModified => "created_or_modified",
        FsChangeKind::Removed => "removed",
    }
}

/// Inverse of [`dirty_kind_str`]. Any unrecognized value maps to
/// `CreatedOrModified` — the safe default, since re-reading a path that turns
/// out to be absent still self-corrects to a deletion inside `process_event`.
fn dirty_kind_from_str(s: &str) -> FsChangeKind {
    match s {
        "removed" => FsChangeKind::Removed,
        _ => FsChangeKind::CreatedOrModified,
    }
}

fn is_excluded_from_sync(
    relative_path: impl AsRef<Path>,
    is_dir: bool,
    ignore_set: &EffectiveIgnoreSet,
) -> bool {
    let relative_path = relative_path.as_ref();
    // The sync-root marker is this device's own identity file
    // (`crate::root_identity`), not user content: every device mints its own
    // token, so syncing it would overwrite a peer's identity with ours and
    // produce a conflicted copy of the very file that proves which folder this
    // is. Excluded here — the one place scan, watch, and the becoming-ignored
    // index cleanup all consult — rather than as a pattern in the default
    // ignore set, because a user-editable `.yadorilinkignore` can negate a
    // pattern (`!.yadorilink-root`) and must not be able to.
    is_root_marker_relative_path(relative_path)
        || is_ignore_file_relative_path(relative_path)
        || ignore_set.is_ignored(relative_path, is_dir)
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
/// filesystem (dereferencing the
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
}

/// Test-only injection point for `reconcile_disk_with_ignore`. A hook, if set,
/// is invoked right after the scan has read its whole-index snapshot and before
/// it commits any record derived from that snapshot. Keyed nowhere — the hook
/// itself inspects the `group_id` and no-ops for scans it does not care about —
/// so a serial test guard plus a per-test sentinel group keep it from
/// perturbing the other scan tests in this crate. Compiled out of non-test
/// builds; production `reconcile_disk_with_ignore` never references it.
#[cfg(test)]
pub(crate) mod scan_test_hooks {
    use std::sync::{Arc, Mutex};

    type Hook = Arc<dyn Fn(&str) + Send + Sync>;
    static POST_SNAPSHOT: Mutex<Option<Hook>> = Mutex::new(None);

    pub(crate) fn set_post_snapshot_hook(hook: Option<Hook>) {
        *POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()) = hook;
    }

    pub(crate) fn fire_post_snapshot(group_id: &str) {
        // Clone the Arc out and release the registry lock before invoking, so a
        // hook that blocks (the deterministic startup-race tests do) never holds
        // this lock while parked.
        let hook = POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(hook) = hook {
            hook(group_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::ChangeAuth;
    use crate::version_vector::VersionVector;
    use std::sync::Mutex;
    use yadorilink_local_storage::FsBlockStore;

    fn processor() -> (LocalChangeProcessor, tempfile::TempDir, tempfile::TempDir) {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        (LocalChangeProcessor::new(state, store, "device-a".into()), store_dir, root_dir)
    }

    // --- Startup-scan vs incoming-peer-apply race (group startup barrier) ---
    //
    // These two tests are the deterministic core of the barrier: the same real
    // `scan_existing_files_with_ignore` scan is paused (via `scan_test_hooks`)
    // exactly between reading its whole-index snapshot and committing the record
    // it derives from that snapshot, while a concurrent peer change for the same
    // path is injected. Without the barrier the scan's blind, un-path-locked
    // batch commit clobbers the peer change (last-writer overwrite); with the
    // barrier the peer apply waits for startup to finish, so it is ordered after
    // the scan commit and survives.

    const RACE_GROUP: &str = "startup-race-group";
    const RACE_PATH: &str = "raced.txt";
    const PEER_MTIME: i64 = 7_777_777;

    // Serializes the two tests that install the process-wide scan hook so they
    // never observe each other's hook. Other scan tests use different group ids,
    // and the hook no-ops for any group but `RACE_GROUP`, so they are unaffected.
    static SCAN_RACE_TEST_GUARD: Mutex<()> = Mutex::new(());

    struct Latch {
        raised: Mutex<bool>,
        cv: std::sync::Condvar,
    }

    impl Latch {
        fn new() -> Self {
            Self { raised: Mutex::new(false), cv: std::sync::Condvar::new() }
        }
        fn raise(&self) {
            *self.raised.lock().unwrap_or_else(|p| p.into_inner()) = true;
            self.cv.notify_all();
        }
        fn wait(&self) {
            let mut raised = self.raised.lock().unwrap_or_else(|p| p.into_inner());
            while !*raised {
                raised = self.cv.wait(raised).unwrap_or_else(|p| p.into_inner());
            }
        }
    }

    /// Builds a fixture whose index already holds an *old* row for `RACE_PATH`
    /// and whose on-disk file has different content — so the real scan detects a
    /// change and commits a fresh (stale-relative-to-any-peer-write) record.
    fn build_race_fixture(
    ) -> (LocalChangeProcessor, Arc<SyncState>, std::path::PathBuf, EffectiveIgnoreSet, tempfile::TempDir, tempfile::TempDir)
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();

        state.add_link(&root.to_string_lossy(), RACE_GROUP).unwrap();

        let mut base_version = VersionVector::new();
        base_version.increment("device-a");
        state
            .upsert_file(
                RACE_GROUP,
                &FileRecord {
                    path: RACE_PATH.to_string(),
                    size: 1,
                    mtime_unix_nanos: 1,
                    version: base_version,
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();

        std::fs::write(root.join(RACE_PATH), b"offline-local-edit-content").unwrap();

        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let processor = LocalChangeProcessor::new(state.clone(), store, "device-a".into());
        (processor, state, root, ignore_set, store_dir, root_dir)
    }

    /// A concurrent peer change for the same path: a distinct device advances the
    /// version, and a sentinel mtime lets the assertion tell whose record is
    /// current after the race.
    fn race_peer_record() -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-b");
        FileRecord {
            path: RACE_PATH.to_string(),
            size: 4,
            mtime_unix_nanos: PEER_MTIME,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    /// FIX ASSERTED: with the group startup barrier, a peer change injected
    /// after the scan snapshots but before it commits is ordered *after* startup
    /// completes and is NOT overwritten by the scan's stale-snapshot record.
    #[tokio::test]
    async fn startup_barrier_prevents_stale_overwrite_of_concurrent_peer_change() {
        let _serial = SCAN_RACE_TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();

        // As `start_link_watch` does synchronously before spawning the executor.
        let generation = state.begin_group_startup(RACE_GROUP);

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
                if gid != RACE_GROUP {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            })));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
        });

        // Scan has read the old snapshot and is paused before its commit.
        snapshot_read.wait();

        // Inject the peer change through the same gated sequence production uses:
        // wait for the group to be ready, then apply under the path lock. The
        // barrier is closed, so this parks instead of racing the scan.
        let peer_state = state.clone();
        let peer_task = tokio::spawn(async move {
            peer_state.wait_group_ready(RACE_GROUP).await.unwrap();
            let path_lock = peer_state.path_lock(RACE_GROUP, RACE_PATH);
            let _guard = path_lock.lock().await;
            peer_state.upsert_file(RACE_GROUP, &race_peer_record()).unwrap();
        });

        // Let the scan commit its stale-snapshot record first...
        release_scan.raise();
        scan_handle.join().unwrap();
        // ...then complete startup, which is what releases the parked peer apply.
        state.mark_group_ready(RACE_GROUP, generation);
        peer_task.await.unwrap();
        scan_test_hooks::set_post_snapshot_hook(None);

        let current = state.get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
        assert_eq!(
            current.mtime_unix_nanos, PEER_MTIME,
            "with the startup barrier the peer change is ordered after the scan's commit and \
             survives as the current record"
        );
    }

    /// REPRODUCES THE BUG the barrier exists to prevent: an unordered peer apply
    /// lands in the scan's snapshot-vs-commit window and the scan's blind batch
    /// commit overwrites it. This is the failing-without half of the acceptance
    /// pair — the only difference from the test above is that the peer apply is
    /// not ordered against the scan.
    ///
    /// It also pins the second mechanism that now prevents this: the apply below
    /// skips `wait_group_ready` deliberately, because for a live link with no
    /// registered gate that call no longer returns `Ok`. It refuses, which is
    /// asserted first — so reaching the overwrite requires bypassing the gate
    /// entirely, and both facts are proven in one place: the race is real, and
    /// the gate does not admit it.
    #[tokio::test]
    async fn startup_scan_stale_overwrites_concurrent_peer_change_without_barrier() {
        let _serial = SCAN_RACE_TEST_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let (processor, state, root, ignore_set, _store_dir, _root_dir) = build_race_fixture();
        // Deliberately no `begin_group_startup`: models a startup that never
        // registered a gate for a link that is nonetheless live.
        assert!(
            state.wait_group_ready(RACE_GROUP).await.is_err(),
            "a live link with no startup gate must refuse peer apply; the overwrite below is only \
             reachable by bypassing the gate, which is what makes this the negative control"
        );

        let snapshot_read = Arc::new(Latch::new());
        let release_scan = Arc::new(Latch::new());
        {
            let snapshot_read = snapshot_read.clone();
            let release_scan = release_scan.clone();
            scan_test_hooks::set_post_snapshot_hook(Some(Arc::new(move |gid: &str| {
                if gid != RACE_GROUP {
                    return;
                }
                snapshot_read.raise();
                release_scan.wait();
            })));
        }

        let scan_root = root.clone();
        let scan_handle = std::thread::spawn(move || {
            processor.scan_existing_files_with_ignore(RACE_GROUP, &scan_root, &ignore_set).unwrap();
        });

        snapshot_read.wait();

        // The peer apply runs immediately in the snapshot-vs-commit window,
        // bypassing the gate that just refused it (asserted above) to show what
        // that refusal is protecting against.
        {
            let path_lock = state.path_lock(RACE_GROUP, RACE_PATH);
            let _guard = path_lock.lock().await;
            state.upsert_file(RACE_GROUP, &race_peer_record()).unwrap();
        }

        // The scan now commits its stale record on top of the peer change.
        release_scan.raise();
        scan_handle.join().unwrap();
        scan_test_hooks::set_post_snapshot_hook(None);

        let current = state.get_file(RACE_GROUP, RACE_PATH).unwrap().unwrap();
        assert_ne!(
            current.mtime_unix_nanos, PEER_MTIME,
            "without the startup barrier the scan's stale-snapshot commit overwrites the \
             concurrent peer change — the race the barrier closes"
        );
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

    /// Gives `root` a sync-root marker for `group`, the way a healthy install
    /// acquires one: adopt while the index is still empty, which is what a real
    /// first link does.
    ///
    /// Needed only by tests that then index a file with no on-disk counterpart.
    /// Such a root is empty with a non-empty index — byte-for-byte what an
    /// unmounted volume looks like — so `VerifiedRoot::open` would (correctly)
    /// refuse to scan it. Adopting first states the thing those tests actually
    /// assume but cannot otherwise express: the volume is mounted, and the file
    /// really is missing from a folder that really is this link's.
    fn adopt_root(proc: &LocalChangeProcessor, group: &str, root: &std::path::Path) {
        crate::root_identity::VerifiedRoot::open(root, group, &proc.state).unwrap();
    }

    fn expect_file_changed(outcome: LocalChangeOutcome) -> FileRecord {
        match outcome {
            LocalChangeOutcome::FileChanged(record) => record,
            other => panic!("expected FileChanged, got {other:?}"),
        }
    }

    /// wraps a real `FsBlockStore` and counts
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
        // `FsBlockStore`, not something these tests exercise.
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

    /// a `CreatedOrModified` event for a file
    /// whose size and mtime are both unchanged from the indexed record
    /// must resolve via the fast-path — no new block ever gets `put` into
    /// the store, proving the file was never re-chunked. The fast-path does
    /// now read the bytes once to verify them against the indexed block
    /// hashes (`disk_bytes_match_indexed_blocks`, so a size+mtime-preserved
    /// content edit can't slip through), but that verification streams and
    /// compares without ever re-chunking or writing a block — exactly what
    /// the unchanged `put` count proves: no store churn, no re-index.
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

    /// DI-3 tail closed: a content edit that preserves BOTH the byte length
    /// AND the mtime (an in-place same-length overwrite, or any writer that
    /// restores mtime via `utimes` after editing) must NOT be trusted as
    /// unchanged on the strength of the stat metadata alone. The size+mtime
    /// fast-path now verifies the on-disk bytes against the indexed block
    /// hashes before concluding "no-op", so this edit is detected and
    /// re-indexed rather than silently pinning the index at the stale
    /// version while disk holds new bytes.
    #[tokio::test]
    async fn identical_size_and_mtime_with_different_bytes_is_now_detected() {
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
        // exactly what was indexed — size AND mtime now both match the
        // index, so only a content comparison can tell this apart from a
        // genuine no-op.
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

        let record = expect_file_changed(
            proc.process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );

        assert!(!record.deleted, "the edit must surface as a live change, not a tombstone");
        assert_ne!(
            record.blocks, indexed_before.blocks,
            "the detected edit must carry the new on-disk content's blocks"
        );
        assert!(
            store.put_call_count() > calls_after_first,
            "detecting the size+mtime-preserved edit requires actually re-chunking the new bytes"
        );
        let indexed_after = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_after.blocks, indexed_before.blocks,
            "the index must be re-versioned to the new content, not left at the stale blocks"
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

    /// Placeholder creation is not treated
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

    #[tokio::test]
    async fn local_edit_while_hydrating_is_captured() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edited-during-hydration.bin");
        std::fs::write(&file_path, b"initial bytes").unwrap();
        proc.process_event(
            "group-1",
            &root,
            &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();
        proc.state
            .set_materialization_state(
                "group-1",
                "edited-during-hydration.bin",
                MaterializationState::Hydrating,
            )
            .unwrap();

        std::fs::write(&file_path, b"new local bytes that must win").unwrap();
        let outcome = proc
            .process_event(
                "group-1",
                &root,
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap();

        let changed = expect_file_changed(outcome);
        assert_eq!(changed.size, b"new local bytes that must win".len() as u64);
        assert_eq!(changed.version.get("device-a"), 2);
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

    /// a single scan correctly handles
    /// a mix of already-current, changed, and brand-new files together,
    /// using the bulk-loaded `list_files`/`list_materialization_states`
    /// maps rather than a per-file lookup for any of them.
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

    /// A full scan is authoritative only when its root was actually
    /// traversable. A temporarily unavailable mount/root must not look like
    /// an empty directory and turn every previously indexed path into a
    /// tombstone that is then propagated to the mesh.
    #[test]
    fn root_unavailable_scan_must_not_tombstone_indexed_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        std::fs::remove_dir_all(&root).unwrap();
        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "an unavailable scan root must not be reported as complete");
        let indexed = proc.state.get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "an incomplete scan must never create a tombstone");
    }

    /// The case an existence check structurally cannot catch, and the reason the
    /// guard is an identity check rather than an availability one: unmounting a
    /// volume leaves its mountpoint behind as an ordinary EMPTY directory. The
    /// root still exists, still canonicalizes, still walks — it just has nothing
    /// in it. Every indexed file therefore looks deleted, and a full scan is
    /// authoritative, so without this the whole folder tombstones and those
    /// tombstones replicate to every device: unplugging a drive destroys the
    /// data everywhere.
    ///
    /// Deliberately does NOT `remove_dir_all` the root — that is the
    /// already-covered root-*removed* case above, which the old
    /// `canonicalize()?` guard caught. The point here is that the directory is
    /// present and readable and the scan must still refuse.
    #[test]
    fn empty_but_present_root_must_not_tombstone_indexed_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        // Simulate the unmount: the mountpoint directory survives, empty. The
        // marker went with the volume, exactly as the content did — that is why
        // it is the marker, and not the path, that carries the identity.
        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::remove_file(root.join(crate::root_identity::ROOT_MARKER_FILE_NAME)).unwrap();
        assert!(root.is_dir(), "the mountpoint directory must still be present for this test");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "and it must be empty");

        let result = proc.scan_existing_files("group-1", &root);

        assert!(
            result.is_err(),
            "an empty-but-present root is indistinguishable from an unmounted volume and must \
             not be reported as an authoritative empty scan"
        );
        let indexed = proc.state.get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(
            !indexed.deleted,
            "a scan that could not establish its root's identity must emit no tombstone"
        );
    }

    /// The wrong-volume variant: something IS mounted at the root and it does
    /// carry a marker, but the marker is not this link's. A restored backup,
    /// another device's copy of the same folder, or a different volume mounted
    /// at the same path. Its contents are not this link's history, so scanning
    /// it authoritatively would tombstone everything the real folder holds.
    #[test]
    fn a_root_marked_for_a_different_link_must_not_tombstone_indexed_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        // Swap in a foreign volume: same path, populated, but a marker naming a
        // different group and token.
        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::write(root.join("someone-elses-file.txt"), b"not ours").unwrap();
        std::fs::write(
            root.join(crate::root_identity::ROOT_MARKER_FILE_NAME),
            br#"{"group_id":"a-different-group","root_token":"0123456789abcdef"}"#,
        )
        .unwrap();

        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "a root carrying another link's marker must be refused");
        let indexed = proc.state.get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "refusing must emit no tombstone");
        assert!(
            proc.state.get_file("group-1", "someone-elses-file.txt").unwrap().is_none(),
            "and must not index the foreign volume's contents into this group"
        );
    }

    /// The token half of the check, isolated: the marker names the right group,
    /// so only the persisted token can tell this folder from the real one. This
    /// is the restored-backup / duplicated-copy case — the group is genuinely
    /// ours, the folder is not.
    #[test]
    fn a_root_whose_marker_token_is_not_the_adopted_one_must_not_tombstone_indexed_files() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        proc.state.add_link(&root.to_string_lossy(), "group-1").unwrap();
        proc.state.set_link_root_token_for_group("group-1", "the-token-we-really-adopted").unwrap();

        std::fs::remove_file(root.join("survives.txt")).unwrap();
        std::fs::write(
            root.join(crate::root_identity::ROOT_MARKER_FILE_NAME),
            br#"{"group_id":"group-1","root_token":"a-stale-token-from-a-copy"}"#,
        )
        .unwrap();

        let result = proc.scan_existing_files("group-1", &root);

        assert!(result.is_err(), "a marker whose token is not the adopted one must be refused");
        let indexed = proc.state.get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "refusing must emit no tombstone");
    }

    /// The backfill path that makes the guard deployable: an install that
    /// predates root identity has no marker on any link. Refusing those would
    /// break every existing install on upgrade, so a root that corroborates the
    /// index (its files are really there) is adopted in place and scans on.
    #[test]
    fn an_unmarked_root_that_still_holds_its_indexed_files_is_adopted_on_upgrade() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        std::fs::write(root.join("survives.txt"), b"durable bytes").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();
        // Rewind to the pre-upgrade shape: index populated, no marker anywhere.
        std::fs::remove_file(root.join(crate::root_identity::ROOT_MARKER_FILE_NAME)).unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            root.join(crate::root_identity::ROOT_MARKER_FILE_NAME).exists(),
            "the upgrade boot must adopt the folder it just corroborated"
        );
        assert!(!records.iter().any(|r| r.deleted), "adoption must not tombstone anything");
        let indexed = proc.state.get_file("group-1", "survives.txt").unwrap().unwrap();
        assert!(!indexed.deleted);
    }

    /// Indexes a `Hydrated`-but-missing file: a `FileRecord` with real block
    /// info marked `Hydrated`, whose bytes are NOT present on disk. This is the
    /// shape the startup Full scan sees for both a crash-mid-materialize (the
    /// rename never completed) and a genuine offline deletion — the two are told
    /// apart only by the materialization intent.
    fn index_hydrated_missing_file(proc: &LocalChangeProcessor, group: &str, path: &str) {
        let mut version = crate::version_vector::VersionVector::new();
        version.increment("device-b");
        proc.state
            .upsert_file(
                group,
                &FileRecord {
                    path: path.into(),
                    size: 11,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![crate::types::BlockInfo {
                        hash: vec![0xAB; 32],
                        offset: 0,
                        size: 11,
                    }],
                    deleted: false,
                },
            )
            .unwrap();
        proc.state.set_materialization_state(group, path, MaterializationState::Hydrated).unwrap();
    }

    /// The crux crash-safety guarantee: a crash mid-eager-materialize leaves a
    /// `Hydrated` row whose file is missing but whose write is still recorded by
    /// an OPEN materialization intent. The startup Full scan must NOT tombstone
    /// it — it is reconstructable from the locally-present blocks and repair
    /// will heal it. Tombstoning here would propagate a `Delete` group-wide and
    /// silently destroy a fully-reconstructable file.
    #[test]
    fn crash_mid_materialize_missing_file_with_open_intent_is_not_tombstoned() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&proc, "group-1", &root);
        index_hydrated_missing_file(&proc, "group-1", "doc.txt");
        // The durable "materialization write in progress" signal a crash left
        // behind — the disambiguator that makes this a crash, not a deletion.
        proc.state.begin_materialization_intent("group-1", "doc.txt", &[0xAB; 32]).unwrap();

        // A normal boot's Full scan (tombstones enabled). The file is absent
        // from disk, so it is a tombstone candidate — but the open intent must
        // veto that.
        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            !records.iter().any(|r| r.path == "doc.txt" && r.deleted),
            "a missing file with an open materialization intent must not be tombstoned"
        );
        let indexed = proc.state.get_file("group-1", "doc.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the index row must be left intact for repair to reconstruct");
    }

    /// The behavior that MUST be preserved alongside the fix: a file that was
    /// cleanly materialized (no lingering intent) and then deleted or renamed
    /// away while the daemon was stopped is a genuine offline deletion. The
    /// startup Full scan must still tombstone it so the deletion propagates.
    #[test]
    fn offline_deleted_hydrated_file_with_no_intent_is_still_tombstoned() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        // The root is verified and really is this link's folder, so a missing
        // file here is a genuine deletion, not an unmounted volume.
        adopt_root(&proc, "group-1", &root);
        index_hydrated_missing_file(&proc, "group-1", "gone.txt");
        // No materialization intent: the write had completed and its intent was
        // cleared, so the missing file is a real deletion.

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        assert!(
            records.iter().any(|r| r.path == "gone.txt" && r.deleted),
            "a missing file with no materialization intent must still be tombstoned"
        );
        let indexed = proc.state.get_file("group-1", "gone.txt").unwrap().unwrap();
        assert!(indexed.deleted, "the genuine offline deletion must be recorded as a tombstone");
    }

    /// The defense-in-depth gate: when the startup interrupted-materialization
    /// repair pass ERRORED for the group this boot, its crash-vs-offline-delete
    /// disambiguation is unavailable, so the Full scan must emit NO deletes this
    /// boot — even for a missing file with no intent (which, on a healthy boot,
    /// would be a genuine deletion). The delete is deferred to a later boot on
    /// which repair succeeds. Fail-closed.
    #[test]
    fn repair_errored_boot_suppresses_all_scan_tombstones() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        adopt_root(&proc, "group-1", &root);
        index_hydrated_missing_file(&proc, "group-1", "deferred.txt");
        // Deliberately NO intent: on a healthy boot this would tombstone. The
        // repair-errored gate must still withhold it.
        let ignore_set = EffectiveIgnoreSet::from_user_patterns("");

        let records = proc
            .scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, false)
            .unwrap();

        assert!(
            !records.iter().any(|r| r.deleted),
            "no delete may be emitted on a boot whose repair errored for the group"
        );
        let indexed = proc.state.get_file("group-1", "deferred.txt").unwrap().unwrap();
        assert!(!indexed.deleted, "the delete decision must be deferred, not recorded this boot");

        // And the same missing file DOES tombstone once repair is healthy
        // (tombstones enabled) — proving the gate, not the file, was the reason
        // it was spared above.
        let healthy = proc
            .scan_existing_files_with_ignore_gated("group-1", &root, &ignore_set, true)
            .unwrap();
        assert!(
            healthy.iter().any(|r| r.path == "deferred.txt" && r.deleted),
            "the deferred deletion must propagate on a later healthy boot"
        );
    }

    /// `scan_existing_files` must
    /// not skip a genuine placeholder (OnDemand sync) during a bulk scan —
    /// the bulk-loaded materialization-state map must still
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

    /// A scan's store cost must be exactly known: one `put` per new file's
    /// single block on the first pass, and — the part that carries the
    /// weight — **zero** puts on a rescan that finds nothing changed.
    ///
    /// This is asserted by counting rather than by timing, because a
    /// wall-clock bound cannot express the property. Every `put` costs two
    /// fsyncs (the block's own `sync_all`, plus the directory `sync_all` that
    /// publishes it), so a scan's elapsed time is set by the filesystem behind
    /// `TMPDIR`, not by the scan's algorithm: the same code on the same commit
    /// runs in well under a second on tmpfs, where fsync is free, and in tens
    /// of seconds to minutes on ext4, overlayfs, or APFS, where it is not. No
    /// single bound both fails on a real regression and passes on ordinary
    /// hardware, so a timed version of this test measures the disk instead of
    /// the code — and a scan that got 50x algorithmically slower would still
    /// sit far inside any bound loose enough to be green on a real disk.
    ///
    /// Counting also catches what a timing bound provably cannot. The rescan's
    /// no-op is *not* established by the returned records being empty: a
    /// rescan that re-chunked every file would still return nothing, because
    /// re-chunking unchanged bytes reproduces the identical block hashes and
    /// the resulting record is then suppressed as a self-echo — after paying a
    /// full re-chunk and two fsyncs per file. Only the put count tells those
    /// two apart, which is the reason `CountingBlockStore` exists (see its
    /// doc).
    ///
    /// `FILE_COUNT` is deliberately small. Once the assertion is an exact
    /// count instead of a stopwatch, per-file work is visible at any count
    /// above one, so writing thousands of files — and paying thousands of
    /// fsyncs — buys no additional detection.
    #[test]
    fn scan_puts_one_block_per_new_file_and_rescans_without_touching_the_store() {
        let (proc, store, _store_dir, root_dir) = processor_with_counting_store();
        let root = canonical_root(&root_dir);

        // Each file is far below one chunk, so "one put per file" is the
        // entire store cost of indexing the set.
        const FILE_COUNT: usize = 24;
        for i in 0..FILE_COUNT {
            std::fs::write(root.join(format!("object-{i}.bin")), format!("content {i}")).unwrap();
        }

        let records = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(records.len(), FILE_COUNT);
        assert_eq!(proc.state.list_files("group-1").unwrap().len(), FILE_COUNT);
        assert_eq!(
            store.put_call_count(),
            FILE_COUNT,
            "indexing {FILE_COUNT} single-block files must cost exactly one block put each; \
             a higher count means a file was chunked more than once in a single scan"
        );

        // A rescan with nothing changed must be settled entirely by the
        // size+mtime gate and its content verification, which reads bytes but
        // never writes a block.
        let second_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(second_scan.is_empty(), "an unchanged folder must not be re-indexed on rescan");
        assert_eq!(
            store.put_call_count(),
            FILE_COUNT,
            "a rescan that finds nothing changed must not put a single block; a count that grew \
             here means every unchanged file was re-chunked and re-stored at two fsyncs apiece, \
             which the empty record list asserted above cannot detect"
        );
    }

    /// batch-processing changes (executor half): a `Paths` flush
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

    /// self-echo
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

    /// the
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

    /// an overflow signal (as a real
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

    /// a
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

    /// once the accumulator's internal
    /// delivery queue is forced past capacity by a backlog
    /// (see `debounce`'s own `executor_backlog_trigger_...` test for the
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

    /// a file below the size threshold is chunked with the fixed-size
    /// chunker — the automatic size-based decision picks fixed for small
    /// files with no per-folder configuration involved.
    #[tokio::test]
    async fn small_file_uses_fixed_size_chunking() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("hello.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

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

    /// a file at or above the size threshold is
    /// automatically chunked with CDC — verified by comparing against
    /// `chunk_file_content_defined`'s direct output (deterministic for the
    /// same content/parameters), and confirming it differs from what
    /// fixed-size chunking would have produced for the same content.
    #[tokio::test]
    async fn large_file_uses_content_defined_chunking() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

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

    /// a symlink inside the folder is recorded as a symlink
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

    /// a symlinked directory's contents never appear as
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

    /// the same "never descend into a symlinked directory"
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

    /// a symlink with an absolute target is flagged.
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

    /// a relative symlink target that syntactically resolves
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

    /// a relative target that stays inside the folder root
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
    /// This is expected to pass structurally, not by luck: the rule means
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

    /// The real authorization stamp a healthy policy hands local emission in
    /// the stale-policy tests below — any non-placeholder value works; these
    /// tests only care that it is *not* the all-zero placeholder and that it
    /// reaches the emitted change verbatim once policy is healthy.
    const TEST_REAL_AUTH: ChangeAuth =
        ChangeAuth { auth_seq: 5, auth_epoch: 2, policy_head_hash: [3u8; 32] };

    /// Builds a change-emitting processor whose local-emission auth provider is
    /// driven by the returned flag: `false` (the initial value) makes the
    /// provider report the group's policy as stale (`Err(PolicyUnavailable)`),
    /// and flipping it to `true` makes the provider hand back
    /// [`TEST_REAL_AUTH`] — the exact transition the daemon's provider
    /// undergoes when a failed policy snapshot is later superseded by a valid
    /// one. The `TempDir`s are returned so the caller keeps them alive.
    fn processor_with_toggleable_policy() -> (
        LocalChangeProcessor,
        Arc<SyncState>,
        Arc<std::sync::atomic::AtomicBool>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        use crate::change::PolicyUnavailable;
        use ed25519_dalek::SigningKey;
        use std::sync::atomic::Ordering;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());

        let policy_healthy = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let policy_healthy = policy_healthy.clone();
            state.set_local_change_auth_provider(Arc::new(move |_group_id| {
                if policy_healthy.load(Ordering::SeqCst) {
                    Ok(TEST_REAL_AUTH)
                } else {
                    Err(PolicyUnavailable)
                }
            }));
        }

        let emitter = Arc::new(ChangeEmitter::new("device-a", SigningKey::from_bytes(&[7u8; 32])));
        let proc = LocalChangeProcessor::new(state.clone(), store, "device-a".into())
            .with_change_emitter(emitter);
        let root_dir = tempfile::tempdir().unwrap();
        (proc, state, policy_healthy, store_dir, root_dir)
    }

    /// While a group's policy is stale the auth provider returns
    /// `Err(PolicyUnavailable)`, and a local edit must then produce NO DAG
    /// change — appending a placeholder-auth change here would create a local
    /// head every valid-policy peer rejects, stranding an un-replicable
    /// branch. The edit must not be lost either: the path stays in the durable
    /// dirty-path journal so a later re-drive can emit it once policy heals.
    #[tokio::test]
    async fn stale_policy_withholds_the_dag_change_but_keeps_the_path_journaled_dirty() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let group = "group-1";
        let flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();

        // No record is announced and — crucially — the group's history is still
        // empty: no placeholder-auth change entered the DAG.
        assert!(outcome.records.is_empty(), "a stale-policy edit must not announce a record");
        assert!(
            state.dag_group_heads(group).unwrap().is_empty(),
            "no placeholder-auth change may enter the DAG while policy is stale"
        );
        // The edit is not lost: it remains journaled dirty for re-drive.
        assert!(state.is_path_dirty(group, "note.txt").unwrap());
        assert!(state.list_dirty_paths(group).unwrap().iter().any(|d| d.path == "note.txt"));
    }

    /// The coordination plane's netmap push carries a `policyInvalidGroupIds`
    /// list naming groups whose stored policy state is malformed or corrupt
    /// on the coordination plane's side (see the coordination worker's
    /// netmap-computation and policy-distribution modules, which isolate
    /// such a group out of the push rather than trust it). The daemon's
    /// netmap client has no field for that list at all, so nothing ever
    /// marks a group named there stale -- unlike the whole-policy-portion
    /// failure this module's `stale_policy_withholds_...` test above covers,
    /// a per-group `policyInvalidGroupIds` entry reaches this emission layer
    /// only through the local-emission auth provider. In the daemon the
    /// unified group-policy resolver funnels a coordinator-flagged group
    /// through `mark_group_policy_stale` and reports it `Withhold`, so the
    /// provider returns `Err(PolicyUnavailable)` for exactly that group while
    /// healthy groups keep getting a real stamp. The group-aware provider
    /// installed below stands in for that resolver at this layer.
    #[tokio::test]
    async fn policy_invalid_group_id_stops_local_dag_emission_for_that_group() {
        let (proc, state, _policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        // Only the coordinator-flagged group withholds; every other group
        // still resolves to a real stamp. This is what the daemon's resolver
        // does once `policyInvalidGroupIds` is consumed.
        state.set_local_change_auth_provider(std::sync::Arc::new(|group_id| {
            if group_id == "policy-invalid-group" {
                Err(crate::change::PolicyUnavailable)
            } else {
                Ok(crate::change::ChangeAuth::PLACEHOLDER)
            }
        }));

        let root = canonical_root(&root_dir);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let group = "policy-invalid-group";
        let flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        let outcome = proc.process_flush(group, &root, flush).await.unwrap();

        assert!(
            outcome.records.is_empty(),
            "a local edit in a group the coordination plane flagged policy-invalid must be \
             withheld, not DAG-committed like a healthy group's edit"
        );
        assert!(
            state.dag_group_heads(group).unwrap().is_empty(),
            "no change may enter the DAG for a policy-invalid group; the daemon funnels \
             `policyInvalidGroupIds` through the same withholding staleness gate"
        );
    }

    /// Once the policy heals — the provider flips from `Err(PolicyUnavailable)`
    /// to `Ok(auth)` — re-driving the dirty journal emits the previously
    /// withheld edit as a real, non-placeholder-auth change and clears the
    /// journal row, so the deferred edit replicates normally.
    #[tokio::test]
    async fn healed_policy_reemits_the_withheld_edit_with_real_auth_and_clears_the_journal() {
        use std::sync::atomic::Ordering;

        let (proc, state, policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let file_path = root.join("note.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let group = "group-1";
        let flush = crate::debounce::DebounceFlush::Paths(vec![(
            file_path,
            FsChangeKind::CreatedOrModified,
            1_000,
        )]);
        // Stale phase: withheld, journaled dirty (asserted in full by the test
        // above; here it is only the precondition for the re-drive).
        proc.process_flush(group, &root, flush).await.unwrap();
        assert!(state.dag_group_heads(group).unwrap().is_empty());
        assert!(state.is_path_dirty(group, "note.txt").unwrap());

        // Policy heals; the backstop re-drive re-emits the withheld edit.
        policy_healthy.store(true, Ordering::SeqCst);
        let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert_eq!(redriven.records.len(), 1, "the healed re-drive emits the withheld edit");

        let heads = state.dag_group_heads(group).unwrap();
        assert_eq!(heads.len(), 1, "exactly one change now heads the group");
        let change = state.dag_get_change(&heads[0]).unwrap().expect("emitted change is stored");
        assert_eq!(change.auth_seq, TEST_REAL_AUTH.auth_seq);
        assert_eq!(change.auth_epoch, TEST_REAL_AUTH.auth_epoch);
        assert_eq!(change.policy_head_hash, TEST_REAL_AUTH.policy_head_hash);
        assert_ne!(
            change.auth_seq,
            ChangeAuth::PLACEHOLDER.auth_seq,
            "the re-emitted change must carry the real auth, not the placeholder"
        );

        // The journal row is cleared on the successful re-emission.
        assert!(!state.is_path_dirty(group, "note.txt").unwrap());
        assert!(state.list_dirty_paths(group).unwrap().is_empty());
    }

    /// A restart reconciliation scan that detects an offline edit while the
    /// group's policy is stale must NOT fall back to a DAG-silent index write.
    /// The historical fallback wrote the batch through the non-emitting
    /// `upsert_files_batch`, advancing the local index to match disk — so a
    /// later rescan saw no disk-vs-index diff and the change never entered the
    /// DAG, and (unlike the live `process_flush` path) nothing was journaled
    /// dirty to re-drive it either. The edit was stranded outside the DAG
    /// forever. The scan must instead withhold the index write, leave the
    /// index unadvanced, and journal the path dirty, so the dirty-journal
    /// re-drive re-emits the change and the DAG head advances once policy
    /// heals. This test fails on the old silent fallback (the DAG head never
    /// advances past the pre-edit head).
    #[tokio::test]
    async fn stale_policy_scan_withholds_index_write_then_reemits_offline_edit_once_healed() {
        use std::sync::atomic::Ordering;

        let (proc, state, policy_healthy, _store_dir, root_dir) =
            processor_with_toggleable_policy();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let file_path = root.join("report.txt");

        // A healthy-policy live edit establishes the group's first DAG history.
        policy_healthy.store(true, Ordering::SeqCst);
        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: the live edit established one DAG head");

        // Policy goes stale; the file is edited offline (daemon "stopped").
        policy_healthy.store(false, Ordering::SeqCst);
        std::fs::write(&file_path, b"version two, edited offline while policy was stale").unwrap();

        // The restart scan detects the offline edit, but policy is stale: it
        // must withhold both the DAG change and the index write and journal the
        // path dirty. The old silent fallback wrote the index here.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records =
            proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(
            scan_records.is_empty(),
            "a stale-policy scan must announce nothing — no record ever entered the DAG"
        );
        assert_eq!(
            state.dag_group_heads(group).unwrap(),
            heads_before,
            "no change may enter the DAG while policy is stale"
        );
        // The index must NOT have advanced to the offline content: advancing it
        // is exactly what poisoned re-derivation in the old silent fallback.
        let indexed = state.get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version one".len() as u64,
            "the scan must not silently advance the index while policy is stale"
        );
        // The withheld edit is journaled dirty for the re-drive.
        assert!(
            state.is_path_dirty(group, "report.txt").unwrap(),
            "the policy-withheld offline edit must be journaled dirty for re-drive"
        );

        // Policy heals; the dirty-journal re-drive re-emits the withheld edit.
        policy_healthy.store(true, Ordering::SeqCst);
        let redriven = proc.redrive_dirty_journal(group, &root).await.unwrap();
        assert_eq!(
            redriven.records.len(),
            1,
            "the healed re-drive emits the previously withheld offline edit"
        );

        let heads_after = state.dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "the offline edit must advance the DAG head once policy heals; the silent fallback \
             left it stranded outside the DAG forever"
        );
        let indexed = state.get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version two, edited offline while policy was stale".len() as u64,
            "the re-drive reconciles the index to the offline content"
        );
        assert!(
            !state.is_path_dirty(group, "report.txt").unwrap(),
            "the journal row is cleared on the successful re-emission"
        );
    }

    /// Builds a processor with change-history emission wired against a
    /// plain, always-succeeding local-change auth (unlike
    /// `processor_with_toggleable_policy`'s stale/healed toggle) — plus
    /// direct access to the underlying `SyncState` and `ChangeEmitter` so a
    /// test can inspect DAG heads and re-run the DAG-import path the same
    /// way the daemon's restart sequence does.
    fn processor_with_emitter(
    ) -> (LocalChangeProcessor, Arc<SyncState>, Arc<ChangeEmitter>, tempfile::TempDir, tempfile::TempDir)
    {
        use ed25519_dalek::SigningKey;

        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let emitter = Arc::new(ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32])));
        let proc = LocalChangeProcessor::new(state.clone(), store, "device-a".into())
            .with_change_emitter(emitter.clone());
        let root_dir = tempfile::tempdir().unwrap();
        (proc, state, emitter, store_dir, root_dir)
    }

    /// Reproduces the restart gap in the change-history DAG: a file edited
    /// while the daemon isn't running is picked up by the startup disk-vs-
    /// index reconciliation scan (`scan_existing_files_with_ignore`), which
    /// updates the local index via the batched, non-DAG-emitting writer
    /// (`SyncState::upsert_files_batch`) — never appending a change to the
    /// group's change-history DAG the way a live `process_event` call would.
    /// The restart sequence's other chance to backfill that change,
    /// re-running the idempotent initial import
    /// (`dag_import::ensure_initial_import`, exactly as
    /// `yadorilink-daemon`'s `link_manager.rs` does right after the scan),
    /// is gated on the group's DAG still being empty (see `dag_import`'s
    /// module doc) and so is a no-op once real history already exists. The
    /// on-disk file and the local index both show the new content, but the
    /// DAG head a change-history-aware peer negotiates against never moves.
    #[tokio::test]
    async fn offline_edit_after_existing_dag_history_must_append_new_head_on_restart() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let file_path = root.join("report.txt");

        // A live edit while the daemon is running establishes the group's
        // first DAG history, exactly as a normal local save does.
        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: the live edit established one DAG head");

        // The daemon is "stopped": the file is edited directly on disk, with
        // no processor call observing the edit as it happens.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();

        // The daemon "restarts": its startup scan reconciles the index
        // against disk (the real path every linked folder's restart runs),
        // then re-runs the idempotent initial import, mirroring
        // `yadorilink-daemon`'s restart sequence exactly.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records =
            proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(!scan_records.is_empty(), "sanity: the restart scan must notice the offline edit");
        crate::dag_import::ensure_initial_import(&state, group, &emitter).unwrap();

        // The local index reflects the offline edit...
        let indexed = state.get_file(group, "report.txt").unwrap().unwrap();
        assert_eq!(
            indexed.size,
            b"version two, edited while the daemon was stopped".len() as u64,
            "sanity: the local index was reconciled to the offline edit"
        );

        // ...but the change-history DAG must have advanced past the
        // pre-restart head too, so a peer that only negotiates via DAG heads
        // (never a legacy full-index sync) can still learn about the
        // offline edit.
        let heads_after = state.dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "an offline edit picked up by the restart scan must append a new DAG change, not \
             just update the local index"
        );
    }

    /// Same restart gap as `offline_edit_after_existing_dag_history_must_
    /// append_new_head_on_restart`, for an offline deletion: the startup
    /// scan tombstones the local index row for a file removed while the
    /// daemon wasn't running, but that tombstone never becomes a `Delete`
    /// change in the group's history DAG.
    #[tokio::test]
    async fn offline_delete_after_existing_dag_history_must_append_delete_change() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let file_path = root.join("report.txt");
        // Deleting the group's only file leaves an empty root, which is
        // indistinguishable from an unmounted volume unless the folder's
        // identity was established first — as a real link's would have been.
        adopt_root(&proc, group, &root);

        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: one DAG head after the initial live edit");

        // The daemon is "stopped"; the file is deleted directly on disk.
        std::fs::remove_file(&file_path).unwrap();

        // Restart: scan + re-run the idempotent import, exactly as above.
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        let scan_records =
            proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(
            scan_records.iter().any(|r| r.path == "report.txt" && r.deleted),
            "sanity: the restart scan must tombstone the offline delete"
        );
        crate::dag_import::ensure_initial_import(&state, group, &emitter).unwrap();

        let indexed = state.get_file(group, "report.txt").unwrap().unwrap();
        assert!(indexed.deleted, "sanity: the local index reflects the offline delete");

        let heads_after = state.dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after, heads_before,
            "an offline delete picked up by the restart scan must append a Delete change to \
             the DAG, not just tombstone the local index row"
        );
    }

    /// The restart scan now routes an offline edit through the same
    /// DAG-emitting path a live edit uses, so the change reaches the group's
    /// history at scan time rather than updating the index only. Re-running
    /// the reconciliation must therefore be idempotent: neither a second scan
    /// of the unchanged file nor the dirty-journal redrive
    /// (`redrive_dirty_journal`, the daemon's restart backstop) may append a
    /// duplicate head or clear the already-emitted change. The DAG head must
    /// stay advanced past the pre-edit head and remain a single head — the
    /// redrive must never silently leave the group's history stuck, nor fork
    /// or drop the change it just emitted.
    #[tokio::test]
    async fn dirty_journal_redrive_must_not_clear_a_change_missing_from_dag() {
        let (proc, state, emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let file_path = root.join("report.txt");

        std::fs::write(&file_path, b"version one").unwrap();
        expect_file_changed(
            proc.process_event(
                group,
                &root,
                &FsChangeEvent { path: file_path.clone(), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
        );
        let heads_before = state.dag_group_heads(group).unwrap();

        // Offline edit picked up by the restart scan, exactly as the
        // append-on-restart test above: the scan now routes the change through
        // the same DAG-emitting path a live edit uses, so it appends the
        // change to the group's history at scan time. The re-run initial
        // import is a no-op once real history exists.
        std::fs::write(&file_path, b"version two, edited while the daemon was stopped").unwrap();
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, &emitter).unwrap();

        let heads_after_scan = state.dag_group_heads(group).unwrap();
        assert_ne!(
            heads_after_scan, heads_before,
            "the restart scan must append the offline edit to the DAG at scan time, exactly \
             as the append-on-restart test proves"
        );
        assert_eq!(
            heads_after_scan.len(),
            1,
            "the offline edit must advance to a single new head, not fork the group's history"
        );

        // Re-running the reconciliation must be idempotent. A second scan of
        // the (now unchanged) on-disk file finds nothing to emit, so it must
        // not append a duplicate head for the already-committed change.
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, &emitter).unwrap();
        assert_eq!(
            state.dag_group_heads(group).unwrap(),
            heads_after_scan,
            "re-running the scan on an already-emitted change must not append a duplicate head"
        );

        // The dirty-journal redrive must likewise neither clear the
        // already-emitted change (reverting the DAG head to before the edit)
        // nor re-append it as a duplicate — it must leave the emitted change
        // intact.
        proc.redrive_dirty_journal(group, &root).await.unwrap();

        let heads_final = state.dag_group_heads(group).unwrap();
        assert_eq!(
            heads_final, heads_after_scan,
            "the dirty-journal redrive must leave the already-emitted change intact — neither \
             clearing it nor appending a duplicate head"
        );
        assert_ne!(
            heads_final, heads_before,
            "the redrive must never silently leave the group's history stuck at the pre-edit head"
        );
    }

    /// Walks the linear chain of changes from `head` back to (but excluding)
    /// `stop`, tip-first. Asserts every step has exactly one parent, i.e. the
    /// chain is linear — the shape a chunked reconciliation must produce so a
    /// crash can resume from the last committed chunk and the DAG never forks.
    fn linear_chain_back_to(
        state: &SyncState,
        head: crate::change::ChangeHash,
        stop: &crate::change::ChangeHash,
    ) -> Vec<crate::change::Change> {
        let mut chain = Vec::new();
        let mut cur = head;
        while &cur != stop {
            let change = state.dag_get_change(&cur).unwrap().unwrap();
            assert_eq!(
                change.parents.len(),
                1,
                "a chunked reconciliation must form a linear chain (exactly one parent per change)"
            );
            let parent = change.parents[0].clone();
            chain.push(change);
            cur = parent;
        }
        chain
    }

    fn version_hash_for_path(
        change: &crate::change::Change,
        path: &str,
    ) -> crate::change::VersionHash {
        for op in &change.ops {
            match op {
                Op::Create { path: p, version } | Op::Update { path: p, version }
                    if p.as_str() == path =>
                {
                    return *version;
                }
                _ => {}
            }
        }
        panic!("no create/update op for {path} in change");
    }

    /// A symlink picked up by the DAG-emitting startup scan must land its index
    /// metadata columns (record kind / target / out-of-root) in the SAME
    /// committed state as the `FileVersion` the
    /// emitted change carries — no separate post-commit setter that a crash
    /// could tear from the emit. The old code applied those columns via
    /// `set_record_kind`/`set_symlink_*` AFTER the emit committed, so a crash
    /// in between left the DAG saying "symlink -> target" while the index row
    /// still showed the old (or default) columns. This asserts consistency
    /// immediately after the single emitting scan call, with no setter run.
    #[cfg(unix)]
    #[test]
    fn scan_emits_symlink_metadata_atomically_with_its_file_version() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        // Establish DAG history so the scan takes the emitting path.
        std::fs::write(root.join("seed.txt"), b"seed").unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, proc.change_emitter.as_ref().unwrap())
            .unwrap();
        let heads_before = state.dag_group_heads(group).unwrap();

        // Offline: a new symlink whose raw target escapes the root.
        std::os::unix::fs::symlink("../outside", root.join("link")).unwrap();
        let scanned = proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        assert!(scanned.iter().any(|r| r.path == "link"), "sanity: the scan noticed the symlink");

        // Index metadata columns are correct right after the single emitting
        // scan call — no post-commit setter was needed.
        assert_eq!(state.get_record_kind(group, "link").unwrap(), Some(RecordKind::Symlink));
        assert_eq!(state.get_symlink_target(group, "link").unwrap(), Some("../outside".to_string()));
        assert!(state.get_symlink_out_of_root(group, "link").unwrap());
        assert!(!state.get_exec_bit(group, "link").unwrap());

        // ...and the DAG `FileVersion` the emitted change references agrees
        // exactly (same single committed state, not a later reconciliation).
        let heads_after = state.dag_group_heads(group).unwrap();
        assert_ne!(heads_after, heads_before, "the symlink must have emitted a change");
        let chain = linear_chain_back_to(&state, heads_after[0].clone(), &heads_before[0]);
        let vh = version_hash_for_path(&chain[chain.len() - 1], "link");
        let version = state.dag_get_file_version(group, &vh).unwrap().unwrap();
        assert_eq!(version.meta.record_kind, RecordKind::Symlink);
        assert_eq!(version.meta.symlink_target.as_deref(), Some("../outside"));
        assert!(!version.meta.exec_bit);
        // The two views are one and the same commit — the whole point of FIX A.
        assert_eq!(
            state.get_record_kind(group, "link").unwrap(),
            Some(version.meta.record_kind),
        );
        assert_eq!(state.get_symlink_target(group, "link").unwrap(), version.meta.symlink_target);
    }

    /// Exec-bit counterpart of the symlink case above: an executable regular
    /// file picked up by the emitting scan must have its `exec_bit` index column set
    /// in the same commit as the change's `FileVersion` — not by a separate
    /// `set_exec_bit` after the commit.
    #[cfg(unix)]
    #[test]
    fn scan_emits_exec_bit_atomically_with_its_file_version() {
        use std::os::unix::fs::PermissionsExt;

        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        std::fs::write(root.join("seed.txt"), b"seed").unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, proc.change_emitter.as_ref().unwrap())
            .unwrap();
        let heads_before = state.dag_group_heads(group).unwrap();

        // Offline: a new executable script.
        let script = root.join("run.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        assert!(state.get_exec_bit(group, "run.sh").unwrap(), "exec bit set right after the emit");
        assert_eq!(state.get_record_kind(group, "run.sh").unwrap(), Some(RecordKind::File));
        assert_eq!(state.get_symlink_target(group, "run.sh").unwrap(), None);

        let heads_after = state.dag_group_heads(group).unwrap();
        let chain = linear_chain_back_to(&state, heads_after[0].clone(), &heads_before[0]);
        let vh = version_hash_for_path(&chain[chain.len() - 1], "run.sh");
        let version = state.dag_get_file_version(group, &vh).unwrap().unwrap();
        assert!(version.meta.exec_bit, "the emitted FileVersion carries the exec bit too");
        assert_eq!(state.get_exec_bit(group, "run.sh").unwrap(), version.meta.exec_bit);
    }

    /// Op-count cap: a bulk offline diff of more than
    /// `RECONCILE_CHUNK_OP_LIMIT` (1024) paths, picked up by one restart scan,
    /// must be emitted as MULTIPLE chained changes each within the op-count
    /// bound — never one oversized change that no peer could decode
    /// (`change::MAX_OPS`) and no wire message could carry.
    #[test]
    fn bulk_offline_reconcile_chunks_by_op_count_into_a_chain() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        let n = RECONCILE_CHUNK_OP_LIMIT + 3;
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"a").unwrap();
        }
        // Seed history from the initial index, then take it offline.
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, proc.change_emitter.as_ref().unwrap())
            .unwrap();
        let heads_before = state.dag_group_heads(group).unwrap();
        assert_eq!(heads_before.len(), 1, "sanity: import converged on one head");

        // Offline-modify every file (different size => re-versioned by the scan).
        for i in 0..n {
            std::fs::write(root.join(format!("f{i}")), b"abc").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        let heads_after = state.dag_group_heads(group).unwrap();
        assert_eq!(heads_after.len(), 1, "the chunk chain must converge on a single head");
        let chain = linear_chain_back_to(&state, heads_after[0].clone(), &heads_before[0]);
        assert!(
            chain.len() >= 2,
            "{n} changed paths must split into >= 2 chained changes, got {}",
            chain.len()
        );
        let mut total_ops = 0usize;
        for change in &chain {
            assert!(
                change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT,
                "every chunk must stay within the op-count bound"
            );
            let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
            assert!(bytes <= RECONCILE_CHUNK_BYTE_LIMIT, "every chunk must stay within the byte bound");
            total_ops += change.ops.len();
        }
        assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
    }

    /// Byte cap: a diff of FEWER than the op-count
    /// limit but with long paths that exceed `RECONCILE_CHUNK_BYTE_LIMIT` must
    /// still split into multiple chained changes — proving the split is driven
    /// by encoded size, not op count alone (op count alone would leave a single
    /// multi-hundred-KiB change no wire message could deliver).
    #[test]
    fn bulk_offline_reconcile_chunks_by_encoded_bytes_into_a_chain() {
        let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
        let root = canonical_root(&root_dir);
        let group = "group-1";
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(&root).unwrap();

        std::fs::create_dir(root.join("d")).unwrap();
        // ~289 bytes/op * 1000 ops ~= 282 KiB > 256 KiB, yet 1000 < 1024 ops,
        // so only the byte cap can split this.
        let n = 1000usize;
        assert!(n < RECONCILE_CHUNK_OP_LIMIT, "this test must stay under the op-count cap");
        let name = |i: usize| format!("d/{:0>250}", i);
        for i in 0..n {
            std::fs::write(root.join(name(i)), b"a").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();
        crate::dag_import::ensure_initial_import(&state, group, proc.change_emitter.as_ref().unwrap())
            .unwrap();
        let heads_before = state.dag_group_heads(group).unwrap();

        for i in 0..n {
            std::fs::write(root.join(name(i)), b"abc").unwrap();
        }
        proc.scan_existing_files_with_ignore(group, &root, &ignore_set).unwrap();

        let heads_after = state.dag_group_heads(group).unwrap();
        let chain = linear_chain_back_to(&state, heads_after[0].clone(), &heads_before[0]);
        assert!(
            chain.len() >= 2,
            "a >256 KiB diff of {n} (< op-count-cap) paths must split by bytes into >= 2 changes, \
             got {}",
            chain.len()
        );
        let mut total_ops = 0usize;
        for change in &chain {
            let bytes: usize = change.ops.iter().map(encoded_op_len).sum();
            assert!(
                bytes <= RECONCILE_CHUNK_BYTE_LIMIT,
                "every chunk must stay within the byte bound, got {bytes}"
            );
            assert!(change.ops.len() <= RECONCILE_CHUNK_OP_LIMIT);
            total_ops += change.ops.len();
        }
        assert_eq!(total_ops, n, "the chain's ops must cover every changed path exactly once");
    }

    /// The startup/offline full-reconcile scan must decide "already current"
    /// on the same basis as the per-file path (`build_record_for_created_or_
    /// modified`): size *and* mtime, not size alone. An offline edit that
    /// preserves the byte length but changes the file's bytes (and its
    /// mtime) — a flag flip, a same-length hash/uuid swap, an in-place binary
    /// or DB edit — must be detected and re-indexed on restart, not skipped.
    /// A size-only gate leaves the index pinned to the stale version while
    /// disk holds new bytes: silent divergence that only heals if a peer
    /// happens to re-advertise the path, with a silent-data-loss tail if a
    /// later remote edit overwrites the un-indexed local edit.
    #[test]
    fn startup_scan_detects_same_size_edit_with_changed_mtime() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edge-case.bin");

        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();

        // Same length (20 bytes), different bytes, and a distinctly newer
        // mtime — forced explicitly so the test never depends on filesystem
        // timestamp granularity happening to advance between the two writes.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        let new_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64)
            + std::time::Duration::from_secs(2);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(new_mtime)
            .unwrap();

        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
            "a same-size offline edit whose mtime changed must be detected by the restart scan, \
             not short-circuited as already-current: {rescan:?}"
        );

        let indexed_v2 = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_v2.blocks, indexed_v1.blocks,
            "the re-index must capture the new on-disk content, not keep the stale blocks"
        );
        assert_eq!(
            indexed_v2.version.get("device-a"),
            2,
            "the detected offline edit must advance the file's version"
        );
    }

    /// DI-3 tail closed on the startup/offline full-reconcile path too: an
    /// offline edit that preserves BOTH the byte length AND the mtime
    /// (`touch -r`, an archive extraction that restores timestamps, an
    /// in-place same-length overwrite) must still be detected on restart.
    /// The `already_current` stat gate now verifies the on-disk bytes
    /// against the indexed block hashes before short-circuiting, so a
    /// same-size same-mtime content change is re-indexed rather than left
    /// pinned at the stale version — the same content-verified identity
    /// test the per-file/watcher path applies.
    #[test]
    fn startup_scan_detects_same_size_and_mtime_edit() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("edge-case.bin");

        std::fs::write(&file_path, vec![b'A'; 20]).unwrap();
        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();

        // Same length (20 bytes), different bytes, and mtime forced back to
        // exactly the indexed instant — size AND mtime both match, so only
        // a content comparison can distinguish this from an unchanged file.
        std::fs::write(&file_path, vec![b'B'; 20]).unwrap();
        let original_mtime = std::time::UNIX_EPOCH
            + std::time::Duration::from_nanos(indexed_v1.mtime_unix_nanos as u64);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file_path)
            .unwrap()
            .set_modified(original_mtime)
            .unwrap();

        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().any(|r| r.path == "edge-case.bin" && !r.deleted),
            "a same-size, same-mtime offline edit must be detected by the restart scan, \
             not short-circuited as already-current: {rescan:?}"
        );

        let indexed_v2 = proc.state.get_file("group-1", "edge-case.bin").unwrap().unwrap();
        assert_ne!(
            indexed_v2.blocks, indexed_v1.blocks,
            "the re-index must capture the new on-disk content, not keep the stale blocks"
        );
        assert_eq!(
            indexed_v2.version.get("device-a"),
            2,
            "the detected offline edit must advance the file's version"
        );
    }

    /// Teeth for the content-verifying fast-path: a genuinely unchanged
    /// file (same bytes, same size, same mtime) must NOT be re-emitted as a
    /// change on a repeat scan. The content check must confirm the no-op,
    /// never manufacture spurious churn that would bump the version vector
    /// and re-broadcast an identical file on every restart.
    #[test]
    fn startup_scan_leaves_unchanged_file_untouched() {
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);
        let file_path = root.join("steady.bin");
        std::fs::write(&file_path, vec![b'Z'; 4096]).unwrap();

        let first_scan = proc.scan_existing_files("group-1", &root).unwrap();
        assert_eq!(first_scan.len(), 1, "sanity: the initial scan indexes the file");
        let indexed_v1 = proc.state.get_file("group-1", "steady.bin").unwrap().unwrap();

        // No change at all — the file's bytes, size, and mtime are exactly
        // as indexed, so a second scan must treat it as a no-op.
        let rescan = proc.scan_existing_files("group-1", &root).unwrap();
        assert!(
            rescan.iter().all(|r| r.path != "steady.bin"),
            "an unchanged file must not be re-emitted by a repeat scan: {rescan:?}"
        );
        let indexed_v2 = proc.state.get_file("group-1", "steady.bin").unwrap().unwrap();
        assert_eq!(
            indexed_v2.version, indexed_v1.version,
            "an unchanged file's version must not advance across scans"
        );
        assert_eq!(indexed_v2.blocks, indexed_v1.blocks, "unchanged blocks stay identical");
    }

    /// A single un-walkable subtree must not disable offline-delete
    /// tombstoning for the *entire* scan. Tombstone suppression is
    /// fail-safe (never tombstone a path whose directory we could not read),
    /// but that suppression must be scoped to the failed subtree: a
    /// confirmed deletion under a cleanly-walked subtree must still be
    /// tombstoned even when an unrelated subtree errored, otherwise a
    /// persistently-erroring directory defers a real deletion indefinitely
    /// and a peer that evicted the file can re-hydrate it.
    #[test]
    #[cfg(unix)]
    fn tombstone_suppression_is_scoped_to_the_failed_subtree() {
        use std::os::unix::fs::PermissionsExt;
        let (proc, _store_dir, root_dir) = processor();
        let root = canonical_root(&root_dir);

        std::fs::create_dir(root.join("clean")).unwrap();
        std::fs::create_dir(root.join("broken")).unwrap();
        std::fs::write(root.join("clean/keep.txt"), b"in the clean subtree").unwrap();
        std::fs::write(root.join("broken/other.txt"), b"in the broken subtree").unwrap();
        proc.scan_existing_files("group-1", &root).unwrap();

        // Offline delete of a file under the CLEAN subtree.
        std::fs::remove_file(root.join("clean/keep.txt")).unwrap();

        // Make the OTHER subtree un-walkable so the scan hits a walk error
        // there — and only there.
        std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        let records = proc.scan_existing_files("group-1", &root).unwrap();

        // Restore permissions immediately so TempDir cleanup can remove it.
        std::fs::set_permissions(root.join("broken"), std::fs::Permissions::from_mode(0o755))
            .unwrap();

        assert!(
            records.iter().any(|r| r.path == "clean/keep.txt" && r.deleted),
            "a confirmed deletion under a cleanly-walked subtree must still be tombstoned even \
             when an unrelated subtree failed to walk: {records:?}"
        );
        let clean_indexed = proc.state.get_file("group-1", "clean/keep.txt").unwrap().unwrap();
        assert!(clean_indexed.deleted, "the clean-subtree tombstone must be persisted");

        // Fail-safe: the file under the un-walkable subtree must NOT be
        // tombstoned — its absence could not be confirmed this pass.
        let broken_indexed = proc.state.get_file("group-1", "broken/other.txt").unwrap().unwrap();
        assert!(
            !broken_indexed.deleted,
            "a path under the failed subtree must never be tombstoned — absence unconfirmed"
        );
    }

    // --- One live link per group: the dominant harm --------------------------

    /// THE ANCHOR TEST. The index is group-scoped and path-relative while this
    /// scan is root-scoped and authoritative, so with two live roots on one
    /// group, root A's scan finds root B's indexed paths absent from its own
    /// `seen_paths` and tombstones them -- signed changes that ride the
    /// change-DAG to EVERY device. That is silent, group-wide, cross-device loss
    /// of the user's own data.
    ///
    /// Asserts on the emitted RECORDS, not merely that the call is `Err`: an
    /// `Err` returned AFTER the tombstones were pushed is still group-wide loss.
    /// The scan must not reach the tombstone loop at all.
    ///
    /// BOTH ROOTS ARE MARKED WITH THE SAME TOKEN, AND THAT IS THE POINT. An
    /// earlier version of this test left root B unmarked, which made it a FALSE
    /// ANCHOR: an unmarked B sends `VerifiedRoot::open` down the adoption path,
    /// whose token write trips `set_link_root_token_for_group`'s fan-out assert
    /// -- so the refusal came from the WRITER, and disabling the entire
    /// read-side gate left this test PASSING. It named the gate and tested
    /// something else. (Measured: with `ensure_unambiguous_group_on_conn`'s
    /// `paths.len() > 1` forced to `false`, `1 passed; 0 failed`.)
    ///
    /// Two rows carrying ONE token is also the realistic already-duplicated
    /// state rather than a contrivance: it is exactly what the pre-fix
    /// by-`group_id` token writer manufactured, stamping both rows on any
    /// database that already had two links. In it, `open` finds a marker whose
    /// token matches what is persisted and returns `Ok` WITHOUT WRITING -- so no
    /// writer assert can fire, and the read-side gate is the only thing standing
    /// between the user and the tombstones. Measured with the gate disabled:
    /// `SCAN SUCCEEDED, tombstoned = ["only-in-a.txt"]`.
    #[test]
    fn a_full_scan_of_an_ambiguous_group_emits_zero_tombstones() {
        let (processor, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        processor.state.add_link(&root_a.path().to_string_lossy(), group).unwrap();

        // Two files live under root A and are indexed for the group.
        std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
        std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
        let scanned = processor.scan_existing_files(group, root_a.path()).unwrap();
        assert_eq!(scanned.len(), 2, "the healthy scan must index both files");
        assert!(scanned.iter().all(|r| !r.deleted));

        // Root B holds ONE of the group's files -- the realistic shape, since a
        // second root gets populated by hydration from a peer or by the user
        // copying some of the folder in.
        std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();

        // Both roots marked with the group's ONE persisted token: the
        // already-duplicated database. Every identity check now PASSES for
        // either root -- which is precisely why sharing a token is the damage
        // and not the safety. Nothing after this writes a token, so the writer's
        // fan-out assert is out of the picture and only the gate is left.
        //
        // Read while the group is still healthy: once it is ambiguous this
        // resolver refuses, exactly as it should.
        let token = processor
            .state
            .link_root_token_for_group(group)
            .unwrap()
            .expect("root A's scan above must have adopted it");
        crate::root_identity::write_root_marker_for_test(root_b.path(), group, &token);

        // Now the user is in the two-live-roots state -- reachable today, and
        // the state this fix must make safe rather than merely prevent.
        processor
            .state
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();

        // B's ROW carries the same token too. Without this, B's row token is
        // NULL and the token resolver -- a first-row-wins `ORDER BY local_path`
        // -- returns `None` whenever B happens to sort first, sending `open`
        // down its backfill WRITE and back into the writer's fan-out assert.
        // That would make this test's verdict depend on tempdir naming: the gate
        // on one run, the writer on the next. Both rows, one token, is also the
        // honest shape of the state the pre-fix writer produced.
        processor
            .state
            .set_link_root_token_for_path_for_test(&root_b.path().to_string_lossy(), &token)
            .unwrap();

        // Scan root B, NOT root A. This direction is the whole bug: B's scan is
        // root-scoped and authoritative, but the index it reconciles against is
        // group-scoped, so A's `only-in-a.txt` is "indexed for this group but
        // absent from the root I just walked" -> tombstone -> signed change ->
        // every device. Scanning A instead would be vacuous: A's own file is
        // present under A, so that scan emits no tombstone whether or not the
        // fix exists.
        let result = processor.scan_existing_files(group, root_b.path());

        let err = match result {
            Err(e) => e,
            Ok(records) => {
                let tombstoned: Vec<_> =
                    records.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
                panic!(
                    "a scan of an ambiguous group must refuse, not pick a root. SCAN SUCCEEDED, \
                     tombstoned = {tombstoned:?} -- each of those is a signed deletion bound for \
                     every device"
                );
            }
        };
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");

        // And the index is untouched: nothing was tombstoned on the way out.
        let indexed = processor.state.list_files(group).unwrap();
        assert!(
            indexed.iter().all(|r| !r.deleted),
            "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
        );
    }

    /// The original anchor's state, kept as its own case now that the anchor
    /// above has moved to the token-sharing one: an UNMARKED second root, where
    /// the refusal comes from the token writer's fan-out assert on the adoption
    /// path rather than from the read-side gate. Defence in depth, and labelled
    /// as such -- it is not evidence about the gate.
    #[test]
    fn a_full_scan_of_an_ambiguous_group_with_an_unadopted_second_root_emits_zero_tombstones() {
        let (processor, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        processor.state.add_link(&root_a.path().to_string_lossy(), group).unwrap();
        std::fs::write(root_a.path().join("shared.txt"), b"hello").unwrap();
        std::fs::write(root_a.path().join("only-in-a.txt"), b"world").unwrap();
        processor.scan_existing_files(group, root_a.path()).unwrap();

        // One of the group's files is present under B, so B is "corroborated"
        // and the marker check would ADOPT it: `IndexedFilesAllMissing` only
        // fires when NOT ONE indexed file is present.
        std::fs::write(root_b.path().join("shared.txt"), b"hello").unwrap();
        processor
            .state
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();

        let err = processor
            .scan_existing_files(group, root_b.path())
            .expect_err("a scan of an ambiguous group must refuse, not pick a root");
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");

        let indexed = processor.state.list_files(group).unwrap();
        assert!(
            indexed.iter().all(|r| !r.deleted),
            "no indexed file may be tombstoned by a scan of an ambiguous group, got {indexed:?}"
        );
    }

    /// The fix's own remedy must not destroy data. `DELETE FROM files` is only
    /// ever keyed by path, so unlinking B leaves B's rows in the GROUP's index;
    /// A's next scan is root-scoped and authoritative and would read every one
    /// of them as deleted and tombstone them to every device. Obeying the error
    /// message ("unlink the other one") would then delete the files the message
    /// told the user to save.
    ///
    /// Measured before this flag existed: the survivor's scan emitted
    /// `["only-in-b.txt"]`.
    #[test]
    fn the_survivors_first_post_recovery_scan_emits_no_tombstones() {
        let (processor, _store_dir, root_a) = processor();
        let root_b = tempfile::tempdir().unwrap();
        let group = "group-1";

        processor.state.add_link(&root_a.path().to_string_lossy(), group).unwrap();
        std::fs::write(root_a.path().join("in-a.txt"), b"aaa").unwrap();
        processor.scan_existing_files(group, root_a.path()).unwrap();

        // A path that only ever existed under B, indexed for the group -- the
        // shape a second root produces by hydrating from a peer.
        processor
            .state
            .force_second_live_link_for_test(&root_b.path().to_string_lossy(), group)
            .unwrap();
        processor
            .state
            .upsert_file(
                group,
                &FileRecord {
                    path: "only-in-b.txt".into(),
                    size: 3,
                    mtime_unix_nanos: 1,
                    version: Default::default(),
                    blocks: vec![],
                    deleted: false,
                },
            )
            .unwrap();

        // Recovery, exactly as `SyncError::AmbiguousLink` instructs, plus the
        // additive-scan flag the daemon's unlink handler arms on the survivor.
        processor.state.remove_link(&root_b.path().to_string_lossy()).unwrap();
        processor
            .state
            .set_suppress_tombstones(&root_a.path().to_string_lossy(), true)
            .unwrap();

        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root_a.path()).unwrap();
        let emit_tombstones = !processor.state.suppress_tombstones_for_group(group).unwrap();
        let out = processor
            .scan_existing_files_with_ignore_gated(group, root_a.path(), &ignore_set, emit_tombstones)
            .unwrap();

        let tombstoned: Vec<_> =
            out.iter().filter(|r| r.deleted).map(|r| r.path.clone()).collect();
        assert!(
            tombstoned.is_empty(),
            "the survivor's first scan after recovery must delete nothing -- these paths can \
             still hydrate from a peer that holds them, got {tombstoned:?}"
        );
        let still_live = processor.state.get_file(group, "only-in-b.txt").unwrap().unwrap();
        assert!(!still_live.deleted, "the departed root's file must not be tombstoned");
    }
}
