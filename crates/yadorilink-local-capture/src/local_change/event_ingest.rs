//! Live filesystem event processing: turns one `FsChangeEvent` into a
//! committed (or batch-deferred) local mutation.

use std::path::Path;

use crate::error::LocalCaptureError;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_storage::read_replicated_xattrs;
use yadorilink_replica_domain::change::Op;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::session_state::ChangeContent;
use yadorilink_root_authority::fs_identity::disk_race_fingerprint;
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};
use yadorilink_sync_sqlite::file_index::ImportedActualState;

use super::disk_observation::{
    closed_disk_observation_if_unraced, exact_leaf_exists_as_directory,
    exact_leaf_exists_as_file_or_symlink,
};
use super::flush::PendingBatchedCommit;
use super::path_policy::{
    is_excluded_from_sync, path_to_wire_relative_string, skip_reason_for_inadmissible_wire_path,
};
use super::record_builder::{file_and_authoring, metadata_columns_for};
use super::{now_unix_nanos, LocalChangeOutcome, LocalChangeProcessor};

/// `process_event_with_ignore_at`'s outcome once batching exists: either
/// the event was fully classified and its mutation committed synchronously,
/// exactly as this function always behaved before batching (`Ready` --
/// what every caller other than the `DebounceFlush::Paths` loop always
/// gets, since they pass `pending_batch: None`), or the simple,
/// DAG-emitting create/modify/delete case applied and a mutation was
/// prepared and pushed onto `pending_batch` instead of being committed
/// here (`Deferred`) -- only the `DebounceFlush::Paths` loop ever sees
/// this, and it alone is responsible for resolving every `Deferred` path
/// once its batch's `flush_pending_batch` call runs.
#[derive(Debug)]
pub(super) enum EventOutcome {
    Ready(LocalChangeOutcome),
    Deferred,
}

impl LocalChangeProcessor {
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
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let ignore_set = EffectiveIgnoreSet::load_for_link_root(root)?;
        self.process_event_with_ignore(group_id, root, event, &ignore_set).await
    }

    pub async fn process_event_with_ignore(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        // `pending_batch: None` always yields `EventOutcome::Ready` --
        // `Deferred` is only ever produced when a batch sink is supplied,
        // which only `process_flush_with_ignore`'s `DebounceFlush::Paths`
        // loop ever does.
        match self
            .process_event_with_ignore_at(group_id, root, event, ignore_set, None, None)
            .await?
        {
            EventOutcome::Ready(outcome) => Ok(outcome),
            EventOutcome::Deferred => unreachable!(
                "process_event_with_ignore_at only defers when given a pending_batch sink"
            ),
        }
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
    ///
    /// `pending_batch`, when `Some`, lets the simple, DAG-emitting
    /// create/modify/delete case (not a symlink, an emitter configured)
    /// defer its commit into a shared batch instead of committing here --
    /// see [`EventOutcome::Deferred`]/[`PendingBatchedCommit`]'s own docs.
    /// `None` (every caller but `process_flush_with_ignore`'s
    /// `DebounceFlush::Paths` loop) always yields `EventOutcome::Ready`,
    /// identical to this function's behavior before batching existed.
    #[allow(
        clippy::too_many_lines,
        clippy::excessive_nesting,
        reason = "one filesystem event's complete decision path, written \
                  as a single top-to-bottom sequence: root canonicalization, \
                  ignore and symlink classification, self-echo/placeholder \
                  suppression, then either an immediate commit or a \
                  deferral into the caller's pending batch. The nesting is \
                  the batched-vs-immediate fork, which must stay adjacent to \
                  the prepare-time snapshots (index state, authoring change \
                  hash, disk fingerprint) it captures for later revalidation"
    )]
    pub(super) async fn process_event_with_ignore_at(
        &self,
        group_id: &str,
        root: &Path,
        event: &FsChangeEvent,
        ignore_set: &EffectiveIgnoreSet,
        observed_at_unix_nanos: Option<i64>,
        pending_batch: Option<&mut Vec<PendingBatchedCommit>>,
    ) -> Result<EventOutcome, LocalCaptureError> {
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
        // The live watcher previously authored local changes, updated the
        // index and emitted tombstones against `root` for the rest of this
        // process's life with no ownership re-check at all — the gap
        // `verified_root_of_established_link`'s own doc describes. Checked
        // before anything else below touches the index or DAG.
        self.verified_root_of_established_link(group_id, &root)?;
        let Ok(rel_path) = event.path.strip_prefix(&root) else {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        };
        // A name that cannot be represented losslessly as this crate's
        // UTF-8 wire path (see `path_to_wire_relative_string`'s own doc
        // comment) is treated as a no-op event -- better than silently
        // colliding it with some other file via lossy conversion. Logged,
        // since this is a live watcher event a user might reasonably
        // expect to have been synced.
        let Some(rel_path) = path_to_wire_relative_string(rel_path) else {
            tracing::warn!(
                group_id,
                path = %event.path.display(),
                "skipping a local change event for a path that cannot be represented \
                 losslessly as this crate's UTF-8 wire path"
            );
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        };
        if rel_path.is_empty() {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }
        if is_ignore_file_relative_path(Path::new(&rel_path)) {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        // Whether a directory-only pattern (`build/`) covers the path. What
        // is on disk says, never following a symlink; a path that is gone
        // cannot be asked, so its index row's kind says.
        let is_dir = match event.path.symlink_metadata() {
            Ok(meta) => meta.is_dir(),
            Err(_) => self
                .state
                .canonical_current_row(group_id, &rel_path)?
                .is_some_and(|row| row.snapshot.record_kind == RecordKind::Directory),
        };
        if is_excluded_from_sync(&rel_path, is_dir, ignore_set) {
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        // Same rule as the scan walk's own copy of this check, and the same
        // reason as the lossy-wire-path skip above: a name admission refuses
        // permanently must never be prepared into a batch, because the batch
        // commits as one signed change and its refusal would fail every
        // other path in it. Returning `None` rather than an error is also
        // what lets any dirty-journal row a pre-fix build already left
        // behind for such a path finally clear on its next re-drive. See
        // `skip_reason_for_inadmissible_wire_path`.
        if let Some(reason) = skip_reason_for_inadmissible_wire_path(&rel_path) {
            tracing::warn!(
                group_id,
                path = %rel_path,
                reason,
                "skipping a local change event for a file whose name can never enter this \
                 group's change history; it stays on disk untouched but is not synced"
            );
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        // A paused item's edit is held, not captured: see `paused_items`.
        // Resolving to "nothing to do" also clears any dirty-journal row
        // the flush recorded for it, so the held edit never blocks remote
        // admission for this path while the pause lasts.
        if self.is_under_user_pause(group_id, &rel_path)? {
            tracing::debug!(group_id, path = %rel_path, "holding a local change to a paused item");
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

        // hold the per-(group,path) lock for the whole
        // read-compare-write below, so this local-change indexing can
        // never interleave with `PeerSyncSession::reconcile_one_file`
        // applying an incoming version for the same path concurrently —
        // see `LocalMutationStore::path_lock`'s doc comment.
        let path_lock = self.state.path_lock(group_id, &rel_path);
        let _guard = path_lock.lock().await;

        // A path a snapshot install holds is left unauthored the same way,
        // but asked only now, under the lock. The reconciliation that
        // releases a hold works under this lock too, and a save that lands
        // after it placed the installed placeholder produces no event but
        // this one: read before the lock, the hold it is about to release
        // would drop that save for good. Read here, the flush waits for the
        // release and captures the save as an edit of the installed version.
        if self.is_paused(group_id, &rel_path)? {
            tracing::debug!(
                group_id,
                path = %rel_path,
                "holding a local change to a path awaiting snapshot install reconciliation"
            );
            return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
        }

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
        let effective_kind = match event.path.symlink_metadata() {
            // Nothing answers to this name at all: a genuine removal.
            Err(_) => FsChangeKind::Removed,
            // A directory, captured as an entry of its own below -- under
            // its exact name only, for the same case-fold reason as a file.
            Ok(meta) if meta.is_dir() => {
                if exact_leaf_exists_as_directory(&root, &rel_path) {
                    return Ok(EventOutcome::Ready(self.capture_directory(
                        group_id,
                        &root,
                        &rel_path,
                        &event.path,
                    )?));
                }
                return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
            }
            Ok(_) => {
                // Something answers to this name, but on a case- or
                // normalization-insensitive volume (macOS, Windows) that
                // is not proof it is THIS exact leaf: the lookup resolves
                // to whatever sibling folds to the same name, which for a
                // held collision is a DIFFERENT record's file. Treating
                // that as evidence about this path is the same case-fold
                // hazard `exact_leaf_exists_as_file_or_symlink` already
                // exists to answer for the scan's own disk check, so this
                // reuses it rather than adding a second mechanism.
                //
                // Confirmed on real APFS, not hypothetical: an event for
                // "photo.jpg" whose only on-disk sibling is a held
                // "Photo.jpg" was classified `CreatedOrModified` and then
                // built its record from `Photo.jpg`'s metadata -- so this
                // device authored and PROPAGATED a local change claiming
                // "photo.jpg" held the other file's content and size.
                //
                // Reclassifying as `Removed` would be equally wrong in the
                // other direction: this branch's delete path has no held
                // guard, so it would tombstone the held row instead. With
                // no evidence about the exact leaf, the only supportable
                // answer is to draw no conclusion and leave the row alone;
                // a later event, or the scan's own re-examination, still
                // re-drives the path once the collision clears.
                if exact_leaf_exists_as_file_or_symlink(&root, &rel_path) {
                    FsChangeKind::CreatedOrModified
                } else {
                    tracing::debug!(
                        group_id,
                        path = %rel_path,
                        "ignoring a local change event whose exact leaf does not exist; a \
                         case-fold sibling answers to the name, and it is a different record"
                    );
                    return Ok(EventOutcome::Ready(LocalChangeOutcome::None));
                }
            }
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
                // Content and authoring identity from ONE read, so the
                // batched path's revalidation compares against a prepare
                // snapshot some single row actually held.
                let (existing_for_delete, authoring_change_hash_at_prepare) = file_and_authoring(
                    &rel_path,
                    self.state.canonical_current_row(group_id, &rel_path)?,
                );
                // A row that is already a tombstone is treated like no row:
                // this deletion was authored once already, and a repeat
                // (a scratch name recreated and removed again, the same
                // deletion in a later debounce window, or a peer's
                // deletion this device projected coming back through its
                // own watcher) must not mint another Delete on top of it.
                let existing_is_directory = self
                    .state
                    .canonical_current_row(group_id, &rel_path)?
                    .is_some_and(|row| row.snapshot.record_kind == RecordKind::Directory);
                if existing_for_delete.as_ref().is_none_or(|row| row.deleted)
                    || existing_is_directory
                {
                    // The path was a directory: an explicit one (its row
                    // says so), or one with no row of its own, structural or
                    // never captured. It was deleted, or renamed away --
                    // `watcher.rs`'s `RenameMode::From` reports the vacated
                    // directory itself as an ordinary `Removed`, and nothing
                    // synthesizes an event for what used to live inside it.
                    // Every entry this device observed there is deleted now:
                    // left live, a later recreation at the same path would
                    // find the stale row still "existing" and read a
                    // brand-new write as an edit to it (a real,
                    // reproducible silent-content-loss shape, not merely a
                    // convergence delay). A repeated `Removed` for a path
                    // already tombstoned finds nothing live and authors
                    // nothing. Entries whose delete this flush's batch
                    // already holds are left to it.
                    let pending_deletes: Vec<String> = pending_batch
                        .as_ref()
                        .map(|batch| {
                            batch
                                .iter()
                                .filter(|pending| {
                                    matches!(
                                        pending.mutation,
                                        yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete { .. }
                                    )
                                })
                                .map(|pending| pending.rel_path.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    let now = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                    return Ok(EventOutcome::Ready(
                        self.delete_vanished_directory(
                            group_id,
                            &root,
                            &rel_path,
                            &pending_deletes,
                            now,
                        )
                        .await?,
                    ));
                }
                let observed = observed_at_unix_nanos.unwrap_or_else(now_unix_nanos);
                // A copy name the namespace placed another entry's leaf
                // under: the deletion is that entry's (see
                // `LocalMutationStore::write_through_source`).
                let write_through = match &self.change_emitter {
                    Some(_) => self.state.write_through_source(group_id, &rel_path)?,
                    None => None,
                };
                match &self.change_emitter {
                    Some(emitter) => {
                        // The simple, common delete case: an existing row,
                        // a real emitter -- eligible to defer into a shared
                        // batch commit instead of committing here. Builds
                        // the exact same tombstone `FileRecord`
                        // `mark_deleted_emitting_change` builds internally
                        // (deleted=true, mtime stamped with this event's
                        // observed time, everything else carried forward
                        // from the current row) so the batched and
                        // immediate paths produce byte-identical rows.
                        if let Some(batch) = pending_batch {
                            let mut record =
                                existing_for_delete.clone().unwrap_or_else(|| FileRecord {
                                    path: rel_path.clone(),
                                    size: 0,
                                    mtime_unix_nanos: 0,
                                    blocks: vec![],
                                    deleted: false,
                                });
                            record.deleted = true;
                            record.mtime_unix_nanos = observed;
                            let op = Op::Delete {
                                path: SyncPath(
                                    write_through.clone().unwrap_or_else(|| rel_path.clone()),
                                ),
                            };
                            batch.push(PendingBatchedCommit {
                                rel_path: rel_path.clone(),
                                event_path: event.path.clone(),
                                observed_at_unix_nanos: observed,
                                index_state_at_prepare: existing_for_delete,
                                authoring_change_hash_at_prepare,
                                disk_fingerprint_at_prepare: disk_race_fingerprint(&event.path),
                                mutation:
                                    yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete {
                                        record,
                                        op,
                                    },
                            });
                            return Ok(EventOutcome::Deferred);
                        }
                        if let Some(source) = write_through {
                            // Absent evidence, as below: the path's own
                            // lock is held and it was just seen gone.
                            self.state.commit_write_through_deletion(
                                group_id,
                                &rel_path,
                                &source,
                                &self.device_id,
                                observed,
                                emitter,
                                &self.begin_operation()?.permit(),
                            )?;
                            return Ok(EventOutcome::Ready(
                                match self.state.get_file(group_id, &rel_path)? {
                                    Some(record) => LocalChangeOutcome::FileChanged(record),
                                    None => LocalChangeOutcome::None,
                                },
                            ));
                        }
                        self.state.mark_deleted_emitting_change(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                            // Safe to publish an Absent proof here:
                            // `effective_kind`'s own `symlink_metadata`
                            // re-check (this function's entry) confirmed
                            // `rel_path` -- the SAME path `_guard` above
                            // locks for this whole call -- is gone from
                            // disk, immediately before this branch and
                            // under that same lock the whole way through.
                            true,
                            emitter,
                            &self.begin_operation()?.permit(),
                        )?;
                    }
                    None => {
                        self.state.mark_deleted_at(
                            group_id,
                            &rel_path,
                            &self.device_id,
                            observed,
                            &self.begin_operation()?.permit(),
                        )?;
                    }
                }
                Ok(EventOutcome::Ready(match self.state.get_file(group_id, &rel_path)? {
                    Some(record) => LocalChangeOutcome::FileChanged(record),
                    None => LocalChangeOutcome::None,
                }))
            }
            FsChangeKind::CreatedOrModified => {
                // A file or symlink now stands where this device observed a
                // directory: the directory was removed (its `Removed` may
                // have been coalesced into this event) and something else
                // made at its name. What it held is deleted first, exactly
                // as for the directory's own removal; the new leaf then
                // replaces the directory's entry below.
                let replaced_directory =
                    self.state.canonical_current_row(group_id, &rel_path)?.is_some_and(|row| {
                        !row.snapshot.deleted && row.snapshot.record_kind == RecordKind::Directory
                    });
                if replaced_directory || self.state.has_live_descendant_row(group_id, &rel_path)? {
                    let pending_deletes: Vec<String> = pending_batch
                        .as_ref()
                        .map(|batch| {
                            batch
                                .iter()
                                .filter(|pending| {
                                    matches!(
                                        pending.mutation,
                                        yadorilink_replica_domain::session_state::PreparedLocalMutation::Delete { .. }
                                    )
                                })
                                .map(|pending| pending.rel_path.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    self.delete_vanished_directory(
                        group_id,
                        &root,
                        &rel_path,
                        &pending_deletes,
                        observed_at_unix_nanos.unwrap_or_else(now_unix_nanos),
                    )
                    .await?;
                }
                let materialization_state =
                    self.state.get_materialization_state(group_id, &rel_path)?;
                let placeholder_generation =
                    self.state.get_placeholder_generation(group_id, &rel_path)?;
                // Content and authoring identity from ONE read, so both
                // reflect the identical moment.
                let (existing, authoring_change_hash_at_prepare) = file_and_authoring(
                    &rel_path,
                    self.state.canonical_current_row(group_id, &rel_path)?,
                );
                // Cloned before the call below moves `existing` --
                // `PendingBatchedCommit` needs its own snapshot of the
                // index state this preparation was based on, to revalidate
                // against later at batch-commit time.
                let existing_at_prepare = existing.clone();
                // Captured before this event's own content read below, so
                // the eventual commit-time proof-publication check
                // (`fingerprint_before_content_read == disk_race_
                // fingerprint(&event.path)` immediately before the
                // single-immediate commit call, further down) can detect a
                // race across the WHOLE read-through-commit window, not
                // just the narrower prepare-to-commit window the batched
                // path's own `disk_fingerprint_at_prepare` already covers.
                let fingerprint_before_content_read = disk_race_fingerprint(&event.path);
                let (outcome, classification, unix_mode) = self
                    .build_record_for_created_or_modified(
                        group_id,
                        &root,
                        rel_path.clone(),
                        &event.path,
                        existing,
                        materialization_state,
                        placeholder_generation,
                        // One file is this route's whole batch: nothing to
                        // pool across, so its blocks are committed per file
                        // exactly as before.
                        None,
                    )?;
                if outcome == LocalChangeOutcome::RetryLater {
                    // Nothing was captured, but the path holds a local edit:
                    // keep it journaled dirty, on every route. The debounced
                    // flush journaled it already; a direct caller (the
                    // pre-materialize guard, a File Provider notification)
                    // did not, and without the row nothing re-drives the
                    // edit and nothing holds a remote change for this path
                    // back until it is captured.
                    self.journal_uncaptured_local_edit(
                        group_id,
                        &rel_path,
                        observed_at_unix_nanos.unwrap_or_else(now_unix_nanos),
                    )?;
                    return Ok(EventOutcome::Ready(outcome));
                }
                if let LocalChangeOutcome::FileChanged(record) = &outcome {
                    // Re-verified here, immediately before the commit below,
                    // not just relied on from this function's entry check
                    // above: `build_record_for_created_or_modified` just did
                    // this event's actual file I/O and chunking/hashing,
                    // which for a large file is real elapsed time during
                    // which this process's OS root lock could have had its
                    // sidecar unlinked-and-recreated out from under it (see
                    // `verified_root_of_established_link`'s own doc for that
                    // race). Closing that window at commit time, not only at
                    // dispatch time, is what a single entry-time check
                    // cannot do. This used to be a standalone `self.
                    // verified_root_of_established_link(group_id, &root)?`
                    // call here; that re-check is now folded into
                    // `self.begin_operation()?.permit()`'s own `verify` (called by each
                    // `LocalMutationStore` mutation below, immediately before its
                    // commit), alongside the daemon's lifecycle-fence check
                    // the standalone call never covered.
                    // A local edit's origin is this device itself.
                    match &self.change_emitter {
                        Some(emitter) => {
                            let symlink_target = classification.as_ref().map(|c| c.target.clone());
                            // A fresh open, not the same handle
                            // `build_record_for_created_or_modified` chunked
                            // through above -- a weaker same-bytes guarantee
                            // than `single_pass_capture.rs`'s own xattr read,
                            // but xattrs are a best-effort metadata capture
                            // (see `read_replicated_xattrs`'s own doc
                            // comment), not content integrity, so a rare
                            // race here reads as "no attributes this time,"
                            // never a corrupt result. Never scanned for a
                            // symlink, matching `unix_mode`'s own `None`
                            // there.
                            let xattrs = if classification.is_none() {
                                std::fs::File::open(&event.path)
                                    .map(|file| read_replicated_xattrs(&file))
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            let (mut op, version) = self.content_op(
                                record,
                                unix_mode.flatten(),
                                symlink_target.clone(),
                                xattrs.clone(),
                            );
                            // A copy name the namespace placed another
                            // entry's leaf under: the edit is that entry's
                            // (see `LocalMutationStore::write_through_source`).
                            // The row stays at the copy name.
                            if let Some(source) =
                                self.state.write_through_source(group_id, &rel_path)?
                            {
                                if let Op::Put { path, .. } = &mut op {
                                    *path = SyncPath(source);
                                }
                            }
                            // The record kind / symlink target / out-of-root
                            // flag / exec bit are written in the SAME
                            // transaction as the emitted change (folded into
                            // `upsert_file_emitting_change`), mirroring exactly
                            // the `FileMeta` `content_op` put in the
                            // `FileVersion` above. A crash can therefore never
                            // leave the index row's metadata columns lagging
                            // the change's `FileVersion` — the old post-commit
                            // `set_*` setters are gone from this emit path.
                            let meta = metadata_columns_for(&classification, unix_mode, xattrs);
                            // The simple, common create/modify case: not a
                            // symlink, a real emitter -- eligible to defer
                            // into a shared batch commit instead of
                            // committing here. A symlink
                            // (`classification.is_some()`) always commits
                            // immediately below, unbatched -- rare enough
                            // that it is not worth the added complexity of
                            // proving its batched revalidation covers the
                            // same identity/target checks this path relies
                            // on elsewhere.
                            if classification.is_none() {
                                if let Some(batch) = pending_batch {
                                    batch.push(PendingBatchedCommit {
                                        rel_path: rel_path.clone(),
                                        event_path: event.path.clone(),
                                        observed_at_unix_nanos: observed_at_unix_nanos
                                            .unwrap_or_else(now_unix_nanos),
                                        index_state_at_prepare: existing_at_prepare,
                                        authoring_change_hash_at_prepare,
                                        disk_fingerprint_at_prepare: disk_race_fingerprint(&event.path),
                                        mutation:
                                            yadorilink_replica_domain::session_state::PreparedLocalMutation::Upsert {
                                                record: record.clone(),
                                                op,
                                                version,
                                                meta: Some(meta),
                                            },
                                    });
                                    return Ok(EventOutcome::Deferred);
                                }
                            }
                            // Zero-field `phase T_*` marker: a timestamp anchor for offline
                            // timing analysis of captured logs.
                            tracing::trace!(
                                "phase T_author_start: authoritative FileRecord/DAG commit begins"
                            );
                            // This commit happens right here, with nothing
                            // between the bracket closing and the write, so
                            // the observation needs no second
                            // re-verification of its own -- unlike a
                            // scanned path, whose mutation waits for its
                            // chunk (see `DiskObservation`).
                            let filesystem_identity = closed_disk_observation_if_unraced(
                                &event.path,
                                fingerprint_before_content_read,
                            )
                            .map(|observation| observation.identity);
                            self.state.upsert_file_emitting_change(
                                group_id,
                                record,
                                &self.device_id,
                                ChangeContent {
                                    ops: vec![op],
                                    versions: std::slice::from_ref(&version),
                                },
                                Some(&meta),
                                filesystem_identity.as_ref(),
                                crate::ports::LocalChangeEmission {
                                    emitter,
                                    permit: &self.begin_operation()?.permit(),
                                },
                            )?;
                            tracing::trace!("phase T_author_done: authoritative FileRecord/DAG commit completes");
                        }
                        None => {
                            tracing::trace!(
                                "phase T_author_start: authoritative FileRecord/DAG commit begins"
                            );
                            // No signing key yet, so no DAG emission -- but
                            // the row, the proof for what is on disk and the
                            // `Hydrated` that proof earns still land in one
                            // transaction. `record`'s bytes were read from
                            // this device's own disk to build it, so the
                            // identity observed here describes what a reader
                            // would find.
                            let meta = metadata_columns_for(&classification, unix_mode, Vec::new());
                            // The version these bytes hash to, built from
                            // the same record and the same metadata the row
                            // beside it is getting -- so the proof names
                            // exactly the version the index row derives.
                            // There is no emitted change here to take it
                            // from: an unregistered device has no signing
                            // key, so nothing else in this arm computes one.
                            let (_, version) = self.content_op(
                                record,
                                unix_mode.flatten(),
                                classification.as_ref().map(|c| c.target.clone()),
                                Vec::new(),
                            );
                            let observed = if record.deleted {
                                None
                            } else {
                                closed_disk_observation_if_unraced(
                                    &event.path,
                                    fingerprint_before_content_read,
                                )
                                .map(|observation| {
                                    ImportedActualState {
                                        filesystem_identity: observation.identity,
                                        record_kind: version.meta.record_kind,
                                        version_hash: version.version_hash,
                                    }
                                })
                            };
                            self.state.upsert_files_batch(
                                group_id,
                                std::slice::from_ref(record),
                                &self.device_id,
                                std::slice::from_ref(&Some(meta)),
                                std::slice::from_ref(&observed),
                                &self.begin_operation()?.permit(),
                            )?;
                            tracing::trace!("phase T_author_done: authoritative FileRecord/DAG commit completes");
                        }
                    }
                }
                Ok(EventOutcome::Ready(outcome))
            }
        }
    }
}
