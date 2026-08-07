//! `FileIndexRepository` owns the plain file-record CRUD subset of the
//! `files` table -- upserts, tombstones, version listing, and per-file
//! metadata columns (record kind, symlink target, exec bit, pinning,
//! last-accessed, block provenance queries that read `files` directly).
//! `files` also carries version history (via `version_seq`, not a separate
//! table) and on-demand-sync placeholder state; the placeholder-lifecycle
//! subset of `files` columns (`materialization_state`, held state, live
//! block-hash/eviction queries) is owned by the sibling
//! `yadorilink-sync-core` `MaterializationStateRepository` instead -- a
//! responsibility split over the same table, not a storage boundary, per
//! `docs/design/syncstate-repository-ownership.md`.
//!
//! `upsert_file_emitting_change`/`upsert_files_batch_emitting_change`/
//! `mark_deleted_emitting_change` take an already-resolved `ChangeAuth` as a
//! parameter rather than resolving it themselves: the authorization provider
//! (`local_change_auth_provider`) lives on `yadorilink-sync-core`'s
//! `SyncState`, not on any repository, since it is not `files`-table state --
//! see `SyncState::upsert_file_emitting_change`'s own one-line delegate for
//! the resolve step this repository's version does not do.
//!
//! Moved from `yadorilink-sync-core`: the only
//! `yadorilink-sync-core` dependency this module had (`state_model`'s
//! `ChangeContent`/`DurabilityRoot`/`DurabilityRoots`/`LocalFileMetaColumns`/
//! `MaterializedGenerationBackfillReport`/`TrashedFile`) is now owned by
//! `yadorilink_replica_domain::session_state`, mirroring where Phase 7D-6
//! already put `CurrentVersionRecord`/`HeldState`/`LinkGate`/`VersionRecord`/
//! `VersionState`. This module is pure SQL/rusqlite, no filesystem or
//! daemon dependency, so it needed no port boundary of its own -- it moves
//! the same direct way `dag_store`/`materialization_jobs`/
//! `filesystem_transaction` already did.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::dag_store::{self, ChangeEmitter};
use crate::error::SyncSqliteError;
use crate::materialized_generation::MaterializedObjectKind;
use yadorilink_replica_domain::change::{ChangeAuth, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};
use yadorilink_replica_domain::session_state::{
    ChangeContent, DurabilityRoot, DurabilityRoots, LocalFileMetaColumns,
    MaterializedGenerationBackfillReport, TrashedFile, VersionRecord, VersionState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Capabilities and authorization shared by every local change emission.
/// Keeping them together prevents repository callers from accidentally
/// pairing an emitter with a permit or authorization stamp from another
/// operation while keeping mutation-specific data explicit.
#[derive(Clone, Copy)]
pub struct ChangeEmissionContext<'a, 'permit> {
    pub emitter: &'a ChangeEmitter,
    pub permit: &'a RootCommitPermit<'permit>,
    pub auth: ChangeAuth,
}

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Deliberately duplicated here
/// rather than depending on `yadorilink-sync-core`'s own `index.rs::
/// now_unix_nanos` (private and `#[cfg(test)]`-only there) -- this crate
/// sits strictly below sync-core in the dependency graph and must not reach
/// back up to it. Same shape as this crate's other
/// `dag_store`/`materialization_job_repository`/`retention_roots` copies.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

pub struct FileIndexRepository {
    database: Arc<SyncDatabase>,
}

impl FileIndexRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Plain, origin-agnostic upsert — delegates to
    /// `upsert_file_with_origin` with an empty (unknown) origin. Kept for
    /// every existing caller (overwhelmingly test fixtures that don't care
    /// who "wrote" a record) so this signature never needed to change; see
    /// `upsert_file_with_origin`'s doc comment for the real semantics and
    /// which two production call sites use it directly instead.
    pub fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.upsert_file_with_origin(group_id, record, "", permit)
    }

    /// The version-retaining write path — see the free function `upsert_file_in_tx` (this
    /// method's entire implementation) for the exact supersede/trash/
    /// promote-scaffold logic. `origin_device_id` is the local device id
    /// for a local edit, or the sending peer's device id when adopting a
    /// remote version; an empty string means "unknown" (`upsert_file`'s
    /// default), recorded as SQL `NULL` rather than the literal empty
    /// string.
    pub fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, None)?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Projected-row upsert that attaches the verified authoring change in
    /// the same SQLite transaction as the current-row mutation.
    pub fn upsert_file_with_origin_and_author(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(authoring_change_hash))?;
            permit.verify()?;
            Ok(())
        })
    }

    /// Upserts many records for one group inside a single SQLite
    /// transaction (batch processing) — used by
    /// `LocalChangeProcessor::scan_existing_files` so a large initial scan
    /// commits once instead of once per file. Semantically identical to
    /// calling `upsert_file_with_origin` for each record in order (same
    /// `origin_device_id` for the whole batch — a scan is always this
    /// device's own local device id); a no-op (no transaction opened) for
    /// an empty batch.
    pub fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        if records.is_empty() {
            return Ok(());
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for record in records {
                upsert_file_in_tx(tx, group_id, record, origin_device_id, None)?;
            }
            permit.verify()?;
            Ok(())
        })
    }

    /// Upserts one record and appends the signed change describing it, in one
    /// transaction. Returns the appended change's hash. `versions` are the
    /// content-addressed file versions the change's ops reference (empty for a
    /// pure delete); each is persisted in the same transaction, so a change and
    /// the version bytes needed to materialize it on any receiver can never
    /// diverge across a crash. `meta`, when `Some`, is the record's local
    /// metadata (record kind, symlink target/out-of-root, exec bit), written
    /// in the SAME transaction so the index row's metadata columns can never
    /// lag the `FileVersion`/DAG change across a crash between the commit and a
    /// separate post-commit setter; pass `None` to leave those columns as
    /// `upsert_file_in_tx` left them.
    /// `permit` is re-verified inside the write transaction, immediately
    /// before commit -- not merely required to be present. See
    /// `root_commit::RootCommitPermit`'s own doc for why this is a
    /// required parameter rather than a caller-side convention.
    ///
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// resolved by `SyncState::upsert_file_emitting_change`'s own one-line
    /// call to `local_emission_auth` before this method is reached, since
    /// `local_change_auth_provider` lives on `SyncState`, not here. See
    /// this crate's `docs/design/syncstate-repository-ownership.md` for why
    /// that one line stays put while the rest of this body moved.
    pub fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        emission: ChangeEmissionContext<'_, '_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let change = dag_store::emit_local_change(
                tx,
                group_id,
                content.ops.clone(),
                emission.auth,
                emission.emitter,
            )?;
            for version in content.versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            let change_hash = change.compute_hash();
            upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(&change_hash))?;
            if let Some(meta) = meta {
                apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
            }
            // Re-verified here, immediately before commit, not merely at
            // this call's entry -- root ownership/lifecycle can change
            // during the work above (chunking/hashing already happened
            // in the caller before this call, but `emit_local_change`'s
            // own DB work takes real time too).
            emission.permit.verify()?;
            Ok(change_hash)
        })
    }

    /// Upserts a batch of records under a single change (one change carrying
    /// every op), in one transaction — the shape used by an initial folder
    /// scan. Returns the appended change's hash, or `None` for an empty batch.
    ///
    /// `metas`, when non-empty, is aligned 1:1 with `records`: index `i`'s
    /// `Some` value is that record's local metadata (record kind, symlink
    /// target/out-of-root, exec bit), written in the SAME transaction so the
    /// index row's metadata columns can never lag the `FileVersion`/DAG change
    /// across a crash between the commit and a separate post-commit setter. A
    /// `None` element (e.g. a tombstone) leaves that row's columns as
    /// `upsert_file_in_tx` left them; passing an empty `metas` leaves every
    /// row's columns untouched.
    ///
    /// Callers with a large detected batch MUST split it into op-count- and
    /// encoded-byte-bounded chunks and call this once per chunk: each call
    /// commits its own change whose parents are the previous chunk's committed
    /// head (see `dag_store::emit_local_change`), so the chunks form a linear
    /// chain no single wire message / decode bound can reject.
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see [`Self::upsert_file_emitting_change`]'s doc comment for why it is
    /// a parameter here rather than resolved internally.
    pub fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        emission: ChangeEmissionContext<'_, '_>,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        if records.is_empty() {
            return Ok(None);
        }
        // A length mismatch here would commit index rows whose emitted change
        // carries a different set of ops, or whose metadata columns land on the
        // wrong row — silent divergence, exactly what this dual-write exists to
        // prevent. It can only arise from a caller bug (the one production
        // caller slices `records`/`ops`/`metas` in lockstep), so fail fast here,
        // before the transaction opens, rather than let it reach the write.
        if content.ops.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} ops for {} records (one op per record is required)",
                content.ops.len(),
                records.len()
            )));
        }
        if !metas.is_empty() && metas.len() != records.len() {
            return Err(SyncSqliteError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} metas for {} records (metas must be empty or aligned 1:1 with records)",
                metas.len(),
                records.len()
            )));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let change = dag_store::emit_local_change(
                tx,
                group_id,
                content.ops.clone(),
                emission.auth,
                emission.emitter,
            )?;
            let change_hash = change.compute_hash();
            for version in content.versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            for (idx, record) in records.iter().enumerate() {
                upsert_file_in_tx(tx, group_id, record, origin_device_id, Some(&change_hash))?;
                if let Some(Some(meta)) = metas.get(idx) {
                    apply_local_meta_columns_in_tx(tx, group_id, &record.path, meta)?;
                }
            }
            emission.permit.verify()?;
            Ok(Some(change_hash))
        })
    }

    /// Marks a file deleted (tombstone), preserving its version vector
    /// lineage so the deletion itself propagates as a normal index update.
    /// Stamps the tombstone's `mtime_unix_nanos` with "now" — the right
    /// choice for every caller of this method (a full-rescan recovery, a
    /// direct test, `hydration.rs`'s bookkeeping): none of them have an
    /// earlier, more accurate observation of when the deletion actually
    /// happened to prefer instead. `mark_deleted_at` is the one exception
    /// (see its own doc comment).
    pub fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.mark_deleted_at(group_id, path, device_id, now_unix_nanos(), permit)
    }

    /// Like `mark_deleted`, but stamps the tombstone with a caller-supplied
    /// observed time instead of "now".
    ///
    /// `local_change.rs`'s
    /// debounced dispatch of a `Removed` event is the one caller that
    /// needs this — a local deletion can sit in the debounce accumulator
    /// for up to `DebounceConfig::quiet_period` (default 300ms) before
    /// `mark_deleted` actually runs, so stamping "now" *at dispatch time*
    /// would record a tombstone time systematically *later* than the
    /// deletion's true, watcher-observed moment — unlike a concurrent
    /// edit's `mtime_unix_nanos`, which is always the file's own real
    /// content-modification time (`std::fs::metadata`), never delayed by
    /// debounce. That asymmetry alone can invert the correct chronological
    /// order between a genuinely-earlier delete and a genuinely-later
    /// edit once `conflict.rs` compares them — confirmed via
    /// `concurrent_edit_delete_edit_wins_when_later_leaves_no_conflict_artifact`
    /// regressing under a naive "now at dispatch time" stamp. Passing the
    /// debounce accumulator's own per-path last-observed timestamp here
    /// (`debounce::DebounceFlush::Paths`'s third tuple element) closes
    /// that gap.
    pub fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        // Stamp the tombstone
        // with the deletion's own observed time, not the mtime carried
        // forward from the file's last live content (the field above is
        // only overwritten here, nowhere else in this function) — a stale
        // content mtime gives `conflict.rs`'s `a_is_loser`/
        // `resolve_conflict_names` no correct chronological signal to
        // order a concurrent edit against this delete once the race that
        // used to mask the conflict path entirely is fixed (see
        // `peer_session::PeerSyncSession::reconcile_one_file`).
        record.mtime_unix_nanos = observed_at_unix_nanos;
        // `device_id` is a known origin
        // (this device, for a local delete) — routes through
        // `upsert_file_with_origin` so the tombstone row itself records it,
        // and so the row it supersedes (the file's last live content, if
        // any) is retained as `state = 'trashed'` rather than discarded —
        // see `upsert_file_in_tx`'s doc comment for the exact rule.
        self.upsert_file_with_origin(group_id, &record, device_id, permit)
    }

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction. Mirrors [`mark_deleted_at`](Self::mark_deleted_at)'s
    /// tombstone construction (observed-time stamp, version-vector bump,
    /// origin-recording upsert that retains the superseded live row as
    /// trash) while additionally emitting the change.
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see [`Self::upsert_file_emitting_change`]'s doc comment for why it is
    /// a parameter here rather than resolved internally.
    pub fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emission: ChangeEmissionContext<'_, '_>,
    ) -> Result<ChangeHash, SyncSqliteError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        record.mtime_unix_nanos = observed_at_unix_nanos;
        let ops = vec![Op::Delete { path: SyncPath(path.to_string()) }];
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let change = dag_store::emit_local_change(
                tx,
                group_id,
                ops.clone(),
                emission.auth,
                emission.emitter,
            )?;
            let change_hash = change.compute_hash();
            upsert_file_in_tx(tx, group_id, &record, device_id, Some(&change_hash))?;
            emission.permit.verify()?;
            Ok(change_hash)
        })
    }

    pub fn remove_file(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<bool, SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )? > 0)
        })
    }

    pub fn get_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<FileRecord>, SyncSqliteError> {
        // Retried like every writer below: a shared-cache in-memory database
        // (every test's `open_in_memory`) can hand a plain read `DatabaseLocked`
        // (or, under sustained contention past `busy_timeout`'s window,
        // `DatabaseBusy` — see `retry_on_database_locked`'s own doc comment)
        // while a concurrent writer holds the table, so a caller polling state
        // from a background task (e.g. a wire-convergence test reading while a
        // real `PeerSyncSession::run()` loop writes) must retry a read here too.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(u64, i64, String, i64)> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            row.map(|(size, mtime, blocks_json, deleted)| {
                row_to_record(path.to_string(), size, mtime, &blocks_json, deleted)
            })
            .transpose()
        })
    }

    /// The `state = 'current'` row for `(group, path)` read as ONE atomic
    /// statement, carrying every column a `FileVersion` identity needs
    /// (blocks, size, mtime, record kind, symlink target, exec bit). Unlike
    /// stitching `get_file` together with the separate `get_record_kind`/
    /// `get_symlink_target`/`get_exec_bit` accessors — each its own
    /// `SELECT ... state = 'current'` — this cannot tear across a concurrent
    /// metadata/content transition: every field comes from the same row, so
    /// the `change::VersionHash` derived via [`CurrentVersionRecord::
    /// to_file_version`] always describes a version some single row actually
    /// held, never a hybrid snapshot of two. This is the read the durability
    /// custody path (eviction querier + responder) must use to reconstruct
    /// the current version's identity. `None` if there is no current row.
    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncSqliteError> {
        // See `get_file`'s comment: retried for the same read-vs-writer
        // `DatabaseLocked` reason.
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, size, mtime_unix_nanos, blocks_json, deleted FROM \
                 files WHERE group_id = ?1 AND state = 'current'",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get(4)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, mtime, blocks_json, deleted) = row?;
                // Fail the whole listing closed on a corrupt row rather than
                // silently dropping content or emitting a defaulted record: a
                // directory listing built from partially-corrupt index rows is a
                // worse failure than a hard, diagnosable error (the corrupt path is
                // named by `row_to_record`'s `warn!`).
                out.push(row_to_record(path, size, mtime, &blocks_json, deleted)?);
            }
            Ok(out)
        })
    }

    /// Bulk-loads every local
    /// `FileRecord` (including tombstones — deleted rows are not filtered
    /// here, matching `get_file`'s own behavior) whose `path` is in
    /// `paths`, for `group_id`, keyed by path — the batched counterpart to
    /// calling `get_file` once per path. Mirrors the existing bulk-load
    /// pattern `LocalChangeProcessor::scan_existing_files` already uses via
    /// `list_files` — collecting the batch of incoming paths/hashes and
    /// issuing set-based queries, then diffing in memory — but scoped to
    /// exactly the requested paths via `WHERE path IN (...)`
    /// rather than loading the whole group — the right shape for
    /// materialization audits, where the requested paths are often a handful
    /// of records out of a much larger indexed group, not the whole file list.
    ///
    /// Chunks the `IN (...)` query at `GET_FILES_BY_PATHS_CHUNK_SIZE`
    /// paths per round trip (SQLite's compiled bound-parameter limit is a
    /// real, if generous, ceiling — chunking avoids ever depending on it
    /// being large enough for an arbitrarily big `paths`). A no-op query
    /// for an empty `paths`. A path with no matching row is simply absent
    /// from the returned map, exactly as `get_file` returning `None` for a
    /// path with no row.
    pub fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, SyncSqliteError> {
        const GET_FILES_BY_PATHS_CHUNK_SIZE: usize = 500;
        if paths.is_empty() {
            return Ok(HashMap::new());
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut out = HashMap::with_capacity(paths.len());
            for chunk in paths.chunks(GET_FILES_BY_PATHS_CHUNK_SIZE) {
                let placeholders =
                    std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT path, size, mtime_unix_nanos, blocks_json, deleted \
                     FROM files WHERE group_id = ? AND state = 'current' AND path IN \
                     ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let params = std::iter::once(&group_id as &dyn rusqlite::ToSql)
                    .chain(chunk.iter().map(|p| p as &dyn rusqlite::ToSql));
                let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get::<_, String>(3)?,
                        r.get(4)?,
                    ))
                })?;
                for row in rows {
                    let (path, size, mtime, blocks_json, deleted) = row?;
                    // Fail closed on a corrupt row (same rationale as `list_files`).
                    let record = row_to_record(path.clone(), size, mtime, &blocks_json, deleted)?;
                    out.insert(path, record);
                }
            }
            Ok(out)
        })
    }

    /// A single retained version by its exact `version_seq` — the restore
    /// engine's lookup for `yadorilink restore <path> --version
    /// <id>`. `None` if no row exists at all for this exact
    /// `(group_id, path, version_seq)`.
    pub fn get_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<VersionRecord>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            #[allow(clippy::type_complexity)]
            let row: Option<(
                u64,
                i64,
                String,
                i64,
                String,
                Option<String>,
                String,
                Option<Vec<u8>>,
                i64,
            )> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted, state, \
                            origin_device_id, record_kind, symlink_target, exec_bit \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                    rusqlite::params![group_id, path, version_seq],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                            r.get(8)?,
                        ))
                    },
                )
                .optional()?;
            row.map(
                |(
                    size,
                    mtime,
                    blocks_json,
                    deleted,
                    state,
                    origin_device_id,
                    record_kind,
                    symlink_target,
                    exec_bit,
                )| {
                    version_record(
                        path.to_string(),
                        version_seq,
                        size,
                        mtime,
                        &blocks_json,
                        deleted,
                        &state,
                        origin_device_id,
                        &record_kind,
                        symlink_target,
                        exec_bit,
                    )
                },
            )
            .transpose()
        })
    }

    /// spec "Deletion Enters Recoverable Trash" / CLI "trash list": every
    /// path currently in the trashed state for `group_id` — i.e. a path
    /// whose `current` row is itself a tombstone (`deleted = 1`) and that
    /// has at least one retained `state = 'trashed'` row (the last live
    /// content before that deletion). Returns the *most recent* trashed
    /// row per path (its highest `version_seq`) alongside the tombstone's
    /// own `mtime_unix_nanos` as the deletion time — the pair `trash
    /// restore` needs (last-known size/content, and when it was deleted).
    /// A path deleted, restored, and deleted again correctly surfaces only
    /// its latest trashed version, not every historical one (`list_versions`
    /// is the place for full history).
    pub fn list_trashed(&self, group_id: &str) -> Result<Vec<TrashedFile>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                        c.mtime_unix_nanos
                 FROM files t
                 JOIN (
                     SELECT path, MAX(version_seq) AS max_seq FROM files
                     WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
                 ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
                 JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
                 WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
                 ORDER BY c.mtime_unix_nanos DESC",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok(TrashedFile {
                    path: r.get(0)?,
                    version_seq: r.get(1)?,
                    last_known_size: r.get::<_, u64>(2)?,
                    origin_device_id: r.get(4)?,
                    deleted_at_unix_nanos: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Whether `(group_id, path)` has a genuine current row -- one this
    /// device actually indexed at some point -- as opposed to no row at
    /// all, or only the `version_seq = 0` scaffold
    /// [`ensure_bootstrap_row_for_metadata`] creates for a path it has
    /// never seen. `get_file(...).is_some()` alone cannot make this
    /// distinction: `apply_incoming_wire_metadata` (`peer_session.rs`)
    /// always bootstraps that scaffold before `materialize` runs, for
    /// EVERY never-before-seen incoming record including a tombstone, so
    /// a caller that only checks `is_some()` to decide "is there real
    /// content here to protect" sees the scaffold and wrongly answers yes.
    pub fn has_real_current_row(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            conn.query_row(
                "SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current' \
                 AND version_seq > 0 LIMIT 1",
                rusqlite::params![group_id, path],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(SyncSqliteError::from)
        })
    }

    /// The device that originated `path`'s current version, if recorded.
    /// `None` when there is no current row, or when the row predates origin
    /// tracking / was created locally without an origin stamp. Used to
    /// distinguish content this device received from a peer (a full replica of
    /// the group necessarily holds it) from a brand-new local edit no peer has
    /// yet — the fail-closed input to on-demand cache-reclamation custody.
    pub fn current_version_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<Option<String>> = conn
                .query_row(
                    "SELECT origin_device_id FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Option<String>>(0),
                )
                .optional()?;
            Ok(origin.flatten())
        })
    }

    /// Creates a `version_seq = 0` scaffold row
    /// for `path` if (and only if) no `current` row exists for it yet — the
    /// `apply_incoming_wire_metadata` bootstrap need (`peer_session.rs`):
    /// its four metadata setters (`set_record_kind`/`set_symlink_target`/
    /// `set_symlink_out_of_root`/`set_exec_bit`) are `UPDATE`-only and error
    /// if no row exists yet for a path this device has genuinely never seen
    /// before. `version_seq = 0` is a sentinel `upsert_file_in_tx`'s own
    /// `files_supersede_prior_current` trigger recognizes specially: the
    /// *next* real `upsert_file`/`upsert_file_with_origin` call for this
    /// path deletes this scaffold outright and starts real history at
    /// `version_seq = 1`, rather than leaving a spurious empty first
    /// version behind. A no-op if a current row already exists (an update
    /// to a previously-seen path) — the bootstrap is only ever needed for a
    /// path this device has never indexed at all.
    pub fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        // This write, like every sibling
        // per-path metadata setter below it (`set_record_kind`,
        // `set_symlink_target`, `set_symlink_out_of_root`, `set_exec_bit`,
        // `set_held`/`clear_held`) sits directly on `reconcile_one_file`'s
        // "adopt a brand-new path from a peer" hot path, called
        // concurrently (up to `MAX_CONCURRENT_RECONCILES` at a time, times
        // however many `handle_message` tasks are in flight) against the
        // exact same shared-cache-mode connection pool
        // `upsert_file_with_origin`'s doc comment on `retry_on_database_
        // locked`/`new_immediate_write_transaction` describes -- but,
        // unlike that function, this one was never wrapped, so a burst
        // large enough to produce real concurrent writers hit an
        // unretried `SQLITE_LOCKED` here and the whole reconcile attempt
        // was dropped, indistinguishable in effect from the semaphore/
        // head-of-line-blocking stall this change's periodic resync
        // exists to recover from. Found via this change's own burst
        // reproduction (real `database table is locked: files` errors
        // observed under load, not a hypothetical) -- fixed the same way
        // `upsert_file_with_origin` already is, so a resync round's own
        // retried reconciles aren't undermined by this same gap.
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id)
                 SELECT ?1, ?2, 0, 0, '[]', 0, 0, 'current', NULL
                  WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// Best-effort backfill of `path_materialized_generations`
    /// (`crate::materialized_generation`) from this group's existing index
    /// rows. Populates a generation only where the stored data honestly
    /// supports one — see the returned report for exactly what was skipped
    /// and why; a fabricated basis would be worse than a missing row, since
    /// everything downstream will trust this table as the answer to "what
    /// does the disk reflect". Not wired into `open`/`init`: this is a
    /// callable, not an automatic migration step, so whoever adds the first
    /// reader of this table also decides whether and when to run this.
    ///
    /// # What "honestly derivable" means here
    ///
    /// A live (`deleted = 0`), `materialization_state = 'hydrated'` current
    /// row with no in-flight `materialization_intents` entry is treated as
    /// materialized: its `authoring_change_hash`, when present, becomes the
    /// generation's one-member causal basis (not the full concurrent-heads
    /// frontier a real resolver would compute — this backfill only knows
    /// the one change each row already names), and its content/kind become
    /// the generation's version and object kind.
    /// [`yadorilink_root_authority::fs_identity::FileIdentity`] is always `None` here: the
    /// index has no platform identity for a path it never observed a live
    /// handle for, and this function does no disk I/O.
    ///
    /// Tombstones (`deleted = 1`) are never backfilled here, on purpose.
    /// `upsert_file_in_tx`'s `authoring_blob.or(authoring_change_hash)`
    /// fallback (this file, the branch that supersedes an existing row)
    /// means a plain `mark_deleted`/`mark_deleted_at` tombstone inherits
    /// whatever authoring hash the row it replaced already had — the last
    /// edit's change, not the deletion's. Only `mark_deleted_emitting_change`
    /// writes a tombstone whose hash actually names the deletion, and
    /// nothing on disk today distinguishes the two kinds of tombstone after
    /// the fact. Recording an absent generation with the wrong basis is
    /// exactly the silent-misattribution failure this table exists to
    /// avoid, so every tombstone is skipped and counted rather than guessed
    /// at — see [`MaterializedGenerationBackfillReport::skipped_deleted_tombstones`].
    pub fn backfill_materialized_generations(
        &self,
        group_id: &str,
    ) -> Result<MaterializedGenerationBackfillReport, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let mut report = MaterializedGenerationBackfillReport::default();

            let deleted_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND state = 'current' AND deleted = 1",
            rusqlite::params![group_id],
            |r| r.get(0),
        )?;
            report.skipped_deleted_tombstones = deleted_count as u64;

            let not_confirmed_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM files f \
             WHERE f.group_id = ?1 AND f.state = 'current' AND f.deleted = 0 \
               AND (f.materialization_state != 'hydrated' \
                    OR EXISTS (SELECT 1 FROM materialization_intents mi \
                               WHERE mi.group_id = f.group_id AND mi.path = f.path))",
                rusqlite::params![group_id],
                |r| r.get(0),
            )?;
            report.skipped_not_confirmed_materialized = not_confirmed_count as u64;

            #[allow(clippy::type_complexity)]
            let candidates: Vec<(
                String,
                u64,
                i64,
                String,
                String,
                Option<Vec<u8>>,
                i64,
                Option<Vec<u8>>,
            )> = {
                let mut stmt = conn.prepare(
                    "SELECT f.path, f.size, f.mtime_unix_nanos, f.blocks_json, f.record_kind, \
                        f.symlink_target, f.exec_bit, f.authoring_change_hash \
                 FROM files f \
                 WHERE f.group_id = ?1 AND f.state = 'current' AND f.deleted = 0 \
                   AND f.materialization_state = 'hydrated' \
                   AND NOT EXISTS (SELECT 1 FROM materialization_intents mi \
                                   WHERE mi.group_id = f.group_id AND mi.path = f.path)",
                )?;
                let rows = stmt.query_map(rusqlite::params![group_id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<Vec<u8>>>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };

            for (
                path,
                size,
                mtime_unix_nanos,
                blocks_json,
                record_kind,
                symlink_target,
                exec_bit,
                authoring_blob,
            ) in candidates
            {
                let Some(authoring_blob) = authoring_blob else {
                    report.skipped_no_authoring_hash += 1;
                    continue;
                };
                let authoring_hash: [u8; 32] = authoring_blob.try_into().map_err(|_| {
                    SyncSqliteError::CorruptState(format!(
                        "invalid authoring_change_hash length for {group_id}/{path}"
                    ))
                })?;
                let authoring_change_hash = ChangeHash(authoring_hash);

                let blocks: Vec<BlockInfo> =
                    serde_json::from_str(&blocks_json).map_err(|error| {
                        SyncSqliteError::CorruptState(format!(
                            "stored block list for current version of {path} is corrupt: {error}"
                        ))
                    })?;
                let record_kind = RecordKind::from_db_str(&record_kind);
                let file_version = FileVersion::from_index_row(
                    blocks,
                    size,
                    mtime_unix_nanos,
                    record_kind,
                    exec_bit != 0,
                    symlink_target,
                );
                let version_hash = file_version.compute_hash();
                let object_kind = match record_kind {
                    RecordKind::File => MaterializedObjectKind::RegularFile,
                    RecordKind::Directory => MaterializedObjectKind::Directory,
                    RecordKind::Symlink => MaterializedObjectKind::Symlink,
                };

                crate::materialized_generation::record_materialized_generation(
                    conn,
                    group_id,
                    &path,
                    std::slice::from_ref(&authoring_change_hash),
                    object_kind,
                    Some(&version_hash),
                    None,
                    now_unix_nanos(),
                )?;
                report.populated += 1;
            }

            Ok(report)
        })
    }

    /// The kind of on-disk entry this record represents. `None`
    /// if no row exists for `group_id`/`path` at all — distinct from `Some
    /// (RecordKind::File)`, which is a real row that just hasn't been
    /// classified as anything else.
    pub fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let kind: Option<String> = conn
                .query_row(
                    "SELECT record_kind FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(kind.as_deref().map(RecordKind::from_db_str))
        })
    }

    // `retry_on_database_locked`-wrapped
    // for the same reason as `ensure_bootstrap_row_for_metadata` just
    // above -- see its doc comment for the full diagnostic story.
    pub fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let affected = conn.execute(
                "UPDATE files SET record_kind = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![kind.as_db_str(), group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The raw, unresolved symlink target bytes, exactly as captured — only
    /// meaningful when `get_record_kind` returns `Symlink`; `None`
    /// otherwise (either no row, or a row that isn't a symlink).
    pub fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let target: Option<Option<Vec<u8>>> = conn
                .query_row(
                    "SELECT symlink_target FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(target.flatten())
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET symlink_target = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![target, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// `true` when this symlink's raw target is an absolute
    /// path, or resolves (syntactically — see
    /// `local_change::symlink_target_is_out_of_root`, never by
    /// dereferencing) outside the linked folder's root. Only meaningful
    /// when `get_record_kind` returns `Symlink`; defaults to `false`
    /// otherwise, matching `get_exec_bit`'s default-to-`false` shape for
    /// an unknown/never-set row. Deliberately a distinct column from
    /// `held_reason`/`held_since_unix_nanos` — see the migration comment
    /// in `init` for why this flag doesn't gate materialization the way
    /// held state does.
    pub fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let flag: Option<i64> = conn
                .query_row(
                    "SELECT symlink_out_of_root FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(flag.unwrap_or(0) != 0)
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET symlink_out_of_root = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![out_of_root as i64, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The owner-executable bit. Defaults to `false` for any
    /// row — including every pre-existing one from before this column
    /// existed — matching `is_pinned`'s existing default-to-`false` shape
    /// for an unknown/never-set row.
    pub fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let exec_bit: Option<i64> = conn
                .query_row(
                    "SELECT exec_bit FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(exec_bit.unwrap_or(0) != 0)
        })
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            let affected = conn.execute(
                "UPDATE files SET exec_bit = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![exec_bit as i64, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The device id that
    /// actually produced this path's *current* content, as already
    /// recorded by every `upsert_file_with_origin` call (the
    /// `origin_device_id` column has existed since file-version-history
    /// support was added, previously write-only from this query's point of
    /// view — used for version-history attribution, never read back
    /// during conflict resolution). `None` for a row with no recorded
    /// origin (an empty string is stored as SQL `NULL`, per
    /// `upsert_file_in_tx`'s existing convention) — callers fall back to
    /// their own best guess (typically `self.local_device_id`/
    /// `self.peer_device_id`) in that case, matching the pre-this-fix
    /// behavior for a record that predates this column being consulted.
    pub fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let origin: Option<String> = conn
                .query_row(
                    "SELECT origin_device_id FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            Ok(origin)
        })
    }

    /// Returns the retained DAG change that authored the current projected
    /// row. `None` is deliberately preserved for pre-v7 rows and any legacy
    /// writer; callers must treat it as unverifiable, never as equality.
    pub fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT authoring_change_hash FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            blob.map(|bytes| {
                let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                    SyncSqliteError::CorruptState(format!(
                        "invalid authoring_change_hash length for {group_id}/{path}"
                    ))
                })?;
                Ok(ChangeHash(hash))
            })
            .transpose()
        })
    }

    /// Attaches verified DAG authorship to the current row. This is called
    /// while the path lock is held immediately after projection.
    pub fn set_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
        hash: &ChangeHash,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            let affected = conn.execute(
                "UPDATE files SET authoring_change_hash = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![&hash.0[..], group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    pub fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let pinned: Option<i64> = conn
                .query_row(
                    "SELECT pinned FROM files WHERE group_id = ?1 AND path = ?2 AND \
                     state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(pinned.unwrap_or(0) != 0)
        })
    }

    pub fn set_pinned(
        &self,
        group_id: &str,
        path: &str,
        pinned: bool,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET pinned = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![pinned as i64, group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Records `unix_ts` as this file's last-accessed time:
    /// called on hydration completion, and best-effort from the eviction
    /// sweep's `fs::metadata.accessed` fallback for already-hydrated
    /// files.
    pub fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), SyncSqliteError> {
        let affected = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE files SET last_accessed_unix = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![unix_ts, group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncSqliteError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Whether any current or retained materialized index version in `group_id`
    /// references `block_hash`. A DAG conflict may move a losing version to a
    /// derived path after its original current row has become superseded.
    pub fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare("SELECT blocks_json FROM files WHERE group_id = ?1")?;
            let mut rows = stmt.query([group_id])?;
            while let Some(row) = rows.next()? {
                let blocks_json: String = row.get(0)?;
                let blocks: Vec<BlockInfo> =
                    serde_json::from_str(&blocks_json).map_err(|error| {
                        // A malformed stored block list is locally-corrupt state, not an
                        // absent referent — classify it as `CorruptState`, not
                        // `NotFound`, so the whole "stored block list is malformed"
                        // fault is reported one consistent way.
                        SyncSqliteError::CorruptState(format!(
                            "stored block list is corrupt: {error}"
                        ))
                    })?;
                if blocks.iter().any(|block| block.hash.as_slice() == block_hash) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Every user-recoverable durability root for `group_id`: the single set
    /// a full-replica handoff must cover so that demoting/unlinking/revoking
    /// the group's last eager replica can never silently lose recoverable
    /// history, not just the current head. A root is `(path, change::
    /// VersionHash)`, one entry per still-restorable `(path, version_seq)`
    /// row, so the same `path` legitimately appears more than once when
    /// several of its versions are each still retained.
    ///
    /// The three categories that actually exist in this schema today all
    /// live in the same `files` table, distinguished only by `state`
    /// ([`VersionState`]) — there is no separate version-history, trash, or
    /// conflict-copy table:
    ///
    /// - **current** (`state = 'current'`): the live head of every file —
    ///   the same set `list_files` returns.
    /// - **retained superseded** (`state = 'superseded'`): prior versions not
    ///   yet swept by [`Self::expire_superseded_and_trashed_versions`],
    ///   restorable via `versions`/`restore --version`.
    /// - **trash-restorable** (`state = 'trashed'`): deleted-but-in-retention
    ///   content, restorable via `trash restore`, not yet swept by the same
    ///   expiry.
    ///
    /// Conflict copies are NOT a fourth category — there is no
    /// `RecordKind::ConflictCopy` or marker column (see
    /// `conflict::is_conflict_copy_of`): a conflict copy is written as an
    /// ordinary `state = 'current'` row under a synthetic
    /// `"name (conflicted copy, ...)"` path, so it is already covered by the
    /// `current` scan above with no extra query.
    ///
    /// A non-deleted row of any of the three states carries real, restorable
    /// block content — `live_block_hashes_with_extra_roots`'s own doc
    /// comment establishes the identical fact for the block-store GC live
    /// set. Directories and symlinks carry no blocks and are excluded
    /// (`record_kind != 'file'`, itself a per-row column so this can filter
    /// in SQL directly rather than needing a second per-path lookup); a
    /// `deleted = 1` row is also excluded — its `blocks_json` is always `[]`
    /// by construction.
    ///
    /// Also returns a stable digest over the root set (roots sorted by path,
    /// each root's block sequence kept ordered — see
    /// [`durability_roots_digest`]) so a caller can capture it when
    /// readiness is first confirmed and re-check it immediately before
    /// committing a role loss, detecting the set changing out from under
    /// that confirmation. For the daemon-driven commit paths that must be
    /// atomic against a concurrent index write, use
    /// [`Self::recheck_digest_then_set_materialization_policy`] /
    /// [`Self::recheck_digest_then_remove_link`] instead of comparing a
    /// separately-read digest, which re-enumerate and commit in one
    /// transaction so no write can interleave.
    ///
    /// Deliberately NOT used by per-file eviction custody
    /// ([`Self::list_versions`]/the daemon's `confirm_version_present_via_
    /// peer`), which stays a `VersionPresent` check for the ONE evicted
    /// exact version — routing eviction through the whole-group root set
    /// would ask an on-demand device to prove custody of history it was
    /// never asked to hold in the first place. GC unification (a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`Self::list_dirty_paths`) ∪ a grace window) is out
    /// of scope here; this function only answers the handoff/durability
    /// question.
    pub fn enumerate_group_durability_roots(
        &self,
        group_id: &str,
    ) -> Result<DurabilityRoots, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            enumerate_group_durability_roots_on_conn(conn, group_id)
        })
    }

    /// The `(path, version_seq)` identity of every row
    /// [`Self::enumerate_group_durability_roots`] would enumerate for
    /// `group_id`, in the same order over the same `WHERE` clause. `
    /// DurabilityRoot` itself (`path` + `block_hashes`) carries no
    /// `version_seq` — it identifies content, not a specific retained row —
    /// so a caller that needs to pin the *exact rows* a handoff-readiness
    /// check just verified (see [`Self::record_handoff_lease`]) reads this
    /// sibling query instead. Deliberately a separate, read-only query
    /// rather than a change to `DurabilityRoot`'s own shape: this crate's
    /// durability-root type is shared, public-facing wire surface, not
    /// something this lease-pinning feature owns.
    ///
    /// Not run in the same transaction as the digest capture it is normally
    /// paired with (see `daemon_state`'s handoff-lease request path) — a
    /// small, documented gap matching every other "digest captured, then a
    /// separate read/commit" pattern this crate already accepts elsewhere
    /// (e.g. [`Self::full_replica_handoff_ready_digest`]'s own doc comment).
    /// Pinning is defense in depth on top of, not a replacement for, the
    /// existing digest re-check gates.
    pub fn enumerate_group_durability_root_versions(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, i64)>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, version_seq FROM files \
                 WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
                   AND state IN ('current', 'superseded', 'trashed') \
                 ORDER BY path, version_seq",
            )?;
            let rows =
                stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The retention-expiry sweep — deletes the index row (never the
    /// blocks; leaves actual block reclamation to a future
    /// block-store GC) for any `superseded`/`trashed` version of
    /// `group_id` that exceeds *both* the built-in version-count bound
    /// ([`RETENTION_MAX_VERSIONS`], by recency rank among that path's own
    /// superseded/trashed rows) and the built-in age bound
    /// ([`RETENTION_MAX_AGE_DAYS`], by wall-clock age from `now_unix_nanos`).
    /// This is the union-retain / intersection-expire rule: a version is kept
    /// while it is within *either* bound, and expired only once it is beyond
    /// *both*, so recent history and recently-changed history are both kept.
    /// Retention is a fixed built-in policy applied to every link; it is not
    /// configurable. The `current` row for any path is never a candidate —
    /// the `WHERE state IN ('superseded', 'trashed')` below structurally
    /// excludes it, matching the rule that the current live version is never
    /// subject to retention expiry. Returns the number of rows deleted.
    ///
    /// `pinned` is the `(path, version_seq)` set an outstanding handoff lease
    /// still protects (see `HandoffLease`'s doc comment) — resolved by
    /// `SyncState::expire_superseded_and_trashed_versions` via
    /// `HandoffLeaseRepository::leased_version_keys_for_group` and passed in
    /// as a parameter, since `handoff_leases` is not `files`-table state and
    /// therefore not this repository's own concern to read (mirrors
    /// `upsert_file_emitting_change`'s already-resolved-`ChangeAuth`
    /// parameter pattern). A pinned row is retained past both bounds until
    /// the lease is confirmed/released/expires.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
        pinned: &HashSet<(String, i64)>,
    ) -> Result<usize, SyncSqliteError> {
        const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
        let age_cutoff_unix_nanos =
            now_unix_nanos.saturating_sub(RETENTION_MAX_AGE_DAYS.saturating_mul(NANOS_PER_DAY));

        // Opens its own DEFERRED transaction (rather than going through
        // `write_immediate`, which is always IMMEDIATE) on purpose: this
        // sweep is read-heavy (the whole candidate SELECT below) before its
        // handful of DELETEs, and taking the write lock only once a
        // candidate is actually found to delete -- SQLite's default
        // deferred-lock-upgrade behavior -- is the original, deliberate
        // choice here, preserved unchanged by this conversion.
        self.database.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            let candidates: Vec<(String, i64)> = {
                // `rnk = 1` is the most recently superseded/trashed row for a
                // given path; the newest `RETENTION_MAX_VERSIONS` rows survive on
                // the count axis alone. A row is deleted only when it is beyond
                // both the count bound and the age bound.
                let mut stmt = tx.prepare(
                    "SELECT path, version_seq FROM (
                    SELECT path, version_seq, mtime_unix_nanos,
                           ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_seq DESC) AS rnk
                    FROM files WHERE group_id = ?1 AND state IN ('superseded', 'trashed')
                 )
                 WHERE rnk > ?2 AND mtime_unix_nanos < ?3",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![group_id, RETENTION_MAX_VERSIONS, age_cutoff_unix_nanos],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )?;
                rows.collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    // A leased row is retained past both bounds until the lease is
                    // confirmed/released/expires -- see `pinned`'s own doc note
                    // above for why the time check (not merely `state`) is what
                    // actually matters.
                    .filter(|key| !pinned.contains(key))
                    .collect()
            };
            for (path, version_seq) in &candidates {
                tx.execute(
                    "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                    rusqlite::params![group_id, path, version_seq],
                )?;
            }
            tx.commit()?;
            Ok(candidates.len())
        })
    }
}

/// The shared version-retaining write
/// path behind `SyncState::upsert_file_with_origin` and
/// `SyncState::upsert_files_batch` — see `upsert_file_with_origin`'s doc
/// comment for the full semantics. Takes an open `Transaction` rather than
/// checking out its own pooled connection so a batch caller can commit
/// once for many records (mirroring the pre-existing `upsert_files_batch`
/// shape) while a single-record caller still gets the same atomicity via
/// its own one-record transaction — see `new_immediate_write_transaction`'s
/// doc comment for why that transaction must be opened `IMMEDIATE`, not
/// rusqlite's default `DEFERRED`.
///
/// sync-performance: `upsert_file_with_origin` is the hot path for every
/// local edit and every peer-adopted change, so this is written for two
/// SQLite round trips, not the more obvious three (a `SELECT` to find the
/// current row, an `INSERT` for the new one, an `UPDATE` to flip the old
/// one). An earlier draft chased this down to a *single* round trip with
/// an `AFTER INSERT` trigger; that turned out not to be the actual
/// bottleneck (see `new_immediate_write_transaction`) and introduced its
/// own correctness risk (a trigger recursing into the same table its own
/// statement is still executing over), so it was reverted in favor of this
/// plainer two-statement version.
///
/// The first round trip below is an `UPDATE... RETURNING`: it flips
/// whatever row is currently `state = 'current'` (if any) to
/// `superseded`/`trashed` per 's rule *and* returns everything
/// needed to build the new current row, so no separate up-front `SELECT`
/// is needed before it.
pub fn upsert_file_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
    authoring_change_hash: Option<&ChangeHash>,
) -> Result<(), SyncSqliteError> {
    let blocks_json = serde_json::to_string(&record.blocks)?;
    let origin: Option<&str> =
        if origin_device_id.is_empty() { None } else { Some(origin_device_id) };
    let authoring_blob = authoring_change_hash.map(|hash| &hash.0[..]);

    #[allow(clippy::type_complexity)]
    let flipped: Option<(
        i64,
        i64,
        String,
        i64,
        Option<i64>,
        String,
        Option<Vec<u8>>,
        i64,
        Option<String>,
        Option<i64>,
        i64,
        Option<Vec<u8>>,
    )> = tx
        .query_row(
            "UPDATE files SET state = CASE WHEN deleted = 0 AND ?3 = 1 THEN 'trashed' ELSE 'superseded' END
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'
             RETURNING version_seq, deleted, materialization_state, pinned, last_accessed_unix,
                       record_kind, symlink_target, exec_bit, held_reason, held_since_unix_nanos,
                       symlink_out_of_root, authoring_change_hash",
            rusqlite::params![group_id, record.path, record.deleted as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .optional()?;

    match flipped {
        None => {
            // Brand new path.
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, version_seq, state, origin_device_id, authoring_change_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 'current', ?7, ?8)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    authoring_blob,
                ],
            )?;
        }
        // The `apply_incoming_wire_metadata` bootstrap scaffold
        // (`version_seq = 0`, created by `ensure_bootstrap_row_for_metadata`)
        // was never a genuine observed version — the `UPDATE` above
        // incorrectly flipped it to superseded/trashed as a side effect of
        // matching `state = 'current'`; undo that and promote it to
        // version 1 in place (an `UPDATE`, not a fresh `INSERT`, so
        // whatever `record_kind`/`symlink_target`/`exec_bit`/etc. its own
        // setters already wrote onto it survives untouched) instead of
        // leaving a spurious empty first version in this path's history.
        // Rare (a scaffold row exists for at most the moment between its
        // own creation and this call), so the extra round trip here
        // doesn't cost the common case anything.
        Some((0, ..)) => {
            tx.execute(
                "UPDATE files SET size = ?1, mtime_unix_nanos = ?2, blocks_json = ?3, deleted = ?4, version_seq = 1, state = 'current', origin_device_id = ?5, authoring_change_hash = ?6
                 WHERE group_id = ?7 AND path = ?8 AND version_seq = 0",
                rusqlite::params![
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    authoring_blob,
                    group_id,
                    record.path,
                ],
            )?;
        }
        Some((
            old_seq,
            _old_deleted,
            materialization_state,
            pinned,
            last_accessed_unix,
            record_kind,
            symlink_target,
            exec_bit,
            held_reason,
            held_since_unix_nanos,
            symlink_out_of_root,
            authoring_change_hash,
        )) => {
            // Every per-file column `FileRecord` doesn't carry
            // (materialization state, pinned, record kind, symlink target,
            // exec bit, held state) is copied forward from the row just
            // superseded — already in hand from the `RETURNING` above, no
            // extra read needed — so a version bump alone never silently
            // resets any of them to their column defaults. Which new
            // `state` the old row ended up as (`trashed` vs `superseded`)
            // was already decided by the `CASE` in the `UPDATE` above.
            tx.execute(
                "INSERT INTO files (
                    group_id, path, size, mtime_unix_nanos, blocks_json, deleted,
                    version_seq, state, origin_device_id,
                    materialization_state, pinned, last_accessed_unix, record_kind,
                    symlink_target, exec_bit, held_reason, held_since_unix_nanos,
                    symlink_out_of_root, authoring_change_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'current', ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    blocks_json,
                    record.deleted as i64,
                    old_seq + 1,
                    origin,
                    materialization_state,
                    pinned,
                    last_accessed_unix,
                    record_kind,
                    symlink_target,
                    exec_bit,
                    held_reason,
                    held_since_unix_nanos,
                    symlink_out_of_root,
                    authoring_blob.or(authoring_change_hash.as_deref()),
                ],
            )?;
        }
    }
    Ok(())
}

/// Writes a path's local metadata columns (record kind, symlink target /
/// out-of-root flag, exec bit) inside `tx`, the SAME transaction that just
/// wrote its `current` row via [`upsert_file_in_tx`]. This is the atomic,
/// in-transaction counterpart to the standalone `set_record_kind`/
/// `set_symlink_target`/`set_symlink_out_of_root`/`set_exec_bit` setters — it
/// must run strictly after `upsert_file_in_tx` (these are `UPDATE`s and need
/// the row to already exist), so the index columns and the emitted change's
/// `FileVersion` commit as one unit.
pub fn apply_local_meta_columns_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    meta: &LocalFileMetaColumns,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE files SET record_kind = ?1, symlink_target = ?2, symlink_out_of_root = ?3, exec_bit = ?4
         WHERE group_id = ?5 AND path = ?6 AND state = 'current'",
        rusqlite::params![
            meta.record_kind.as_db_str(),
            meta.symlink_target,
            meta.symlink_out_of_root as i64,
            meta.exec_bit as i64,
            group_id,
            path,
        ],
    )?;
    Ok(())
}

/// Shared enumeration of `group_id`'s durability roots over an arbitrary
/// connection (a pooled read connection, or a write transaction for the
/// atomic re-check-and-commit paths). See
/// [`SyncState::enumerate_group_durability_roots`] for the category
/// semantics; keeping the query in one place guarantees the digest the
/// atomic commit re-checks is computed exactly like the one the readiness
/// check first captured.
pub fn enumerate_group_durability_roots_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<DurabilityRoots, SyncSqliteError> {
    // `record_kind = 'file'` in the WHERE clause is also the source of truth
    // for the `FileMeta` reconstructed below: every row this query returns is
    // already known to be a regular file, so `record_kind` is `RecordKind::
    // File` and `symlink_target` is `None` by construction — no need to read
    // either column back out.
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, blocks_json, exec_bit FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut roots = Vec::new();
    for row in rows {
        let (path, size, mtime_unix_nanos, blocks_json, exec_bit) = row?;
        // A malformed stored block list is locally-corrupt state — report it as
        // `CorruptState` (like every other malformed-block-list path) rather
        // than letting the bare `?` classify it as a generic `Json`/protocol
        // error.
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "stored block list for {path} is corrupt: {error}"
            ))
        })?;
        // Reconstruct the exact `FileVersion` this row describes and derive
        // its `version_hash` via the SAME `compute_hash()` the change-DAG
        // itself hashes versions with — see `FileVersion::from_index_row`.
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            exec_bit != 0,
            None,
        );
        roots.push(DurabilityRoot {
            path,
            blocks: version.blocks,
            version_hash: version.version_hash,
        });
    }
    let digest = durability_roots_digest(&roots);
    Ok(DurabilityRoots { roots, digest })
}

/// The fixed, built-in version-retention bounds applied to every link: a
/// superseded or trashed version is retained while it is within *either*
/// bound and expired only once it exceeds *both* (union-retain, intersection-
/// expire). The current/live version is never subject to retention. Retention
/// is not per-link configurable.
pub(crate) const RETENTION_MAX_VERSIONS: i64 = 10;

pub(crate) const RETENTION_MAX_AGE_DAYS: i64 = 30;

/// Canonicalizes `roots` and hashes the length-prefixed concatenation.
/// Order-independence is applied only ACROSS roots (sorted by `(path,
/// version_hash)`), so the caller's collection order does not affect the
/// digest. Each root's identity is its `version_hash` alone — the SHA-256 of
/// its canonical `FileVersion` encoding, which already binds the ordered
/// block list, each block's declared size, and the version's metadata, so
/// any real change to the underlying content or metadata (including a block
/// reorder) changes `version_hash` and therefore this digest. This is the
/// property the digest re-confirm before a daemon-driven role-loss commit
/// relies on: the same underlying set (same paths, same per-file version
/// identities) always digests the same, and any real change changes it.
pub fn durability_roots_digest(roots: &[DurabilityRoot]) -> [u8; 32] {
    let mut canonical: Vec<(&str, &[u8; 32])> =
        roots.iter().map(|r| (r.path.as_str(), r.version_hash.as_bytes())).collect();
    canonical.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));

    let mut hasher = Sha256::new();
    for (path, version_hash) in &canonical {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(version_hash.as_slice());
    }
    hasher.finalize().into()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn version_record(
    path: String,
    version_seq: i64,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
    state: &str,
    origin_device_id: Option<String>,
    record_kind: &str,
    symlink_target: Option<Vec<u8>>,
    exec_bit: i64,
) -> Result<VersionRecord, SyncSqliteError> {
    // Fail closed on a corrupt `blocks_json` column rather than coercing it to
    // an empty block list. A silent default would mask genuine index/DB
    // corruption as a legitimately empty version; a valid `"[]"` still parses
    // to an empty list and stays a valid empty record — only an unparseable
    // column errors. Log the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list for a retained version is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    let record_kind = RecordKind::from_db_str(record_kind);
    let exec_bit = exec_bit != 0;
    // Derive this exact row's `version_hash` the same way the durability-root
    // enumeration does — reconstruct the `FileVersion` this row describes and
    // hash it via `compute_hash()` — so a caller comparing a peer's queried
    // hash against this field is comparing against the canonical identity,
    // never a value re-derived from a different subset of columns.
    let version_hash = FileVersion::from_index_row(
        blocks.clone(),
        size,
        mtime_unix_nanos,
        record_kind,
        exec_bit,
        symlink_target.clone(),
    )
    .version_hash;
    Ok(VersionRecord {
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        blocks,
        deleted: deleted != 0,
        state: VersionState::from_db_str(state),
        origin_device_id,
        record_kind,
        symlink_target,
        exec_bit,
        version_hash,
    })
}

pub(crate) fn row_to_record(
    path: String,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
) -> Result<FileRecord, SyncSqliteError> {
    // Fail closed on a corrupt stored block list rather than coercing it to a
    // default: a defaulted (empty) block list would read as "file has no
    // content" and mask genuine index/DB corruption. A valid `"[]"` still
    // parses to a valid empty record; only an unparseable column errors. Log
    // the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list is corrupt; failing closed");
        SyncSqliteError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    Ok(FileRecord { path, size, mtime_unix_nanos, blocks, deleted: deleted != 0 })
}
