//! `ChangeHistoryRepository` owns the DAG-facing (`dag_*`/`append_*`) API
//! surface. It has no table of its own -- every method here is a thin
//! pool-checkout-and-delegate wrapper to a free function in
//! [`crate::dag_store`], which already take a plain `&Connection`/
//! `&Transaction` and own the real DAG persistence, keyed off whatever
//! tables `dag_store`'s own schema defines. See
//! `docs/design/syncstate-repository-ownership.md`'s `ChangeHistoryRepository
//! (DAG)` section: this cluster was confirmed by direct read of
//! `dag_store`'s own doc comment ("Every function here takes a plain
//! `&Connection`... this is what lets a local mutation append its change
//! and mutate the file index atomically, in one commit").
//!
//! `append_initial_import`/`append_history_backfill` take an already-resolved
//! `ChangeAuth` as a parameter rather than resolving it themselves, mirroring
//! [`crate::file_index::FileIndexRepository::upsert_file_emitting_change`]:
//! the authorization provider (`local_change_auth_provider`) lives on
//! `yadorilink_sync_core::index::SyncState`, not on any repository, since it
//! is not DAG-table state -- see `SyncState::append_initial_import`'s own
//! one-line resolve-then-delegate for the step this repository's version
//! does not do.
//!
//! `record_group_block_provenance`/`group_has_block_provenance`/
//! `dag_group_file_version_references_block` were left behind on
//! `FileIndexRepository` by the file-index split (Phase 5 Commit 12) despite
//! being pure `dag_store` delegates -- they belong here, alongside every
//! other `dag_store` pass-through.
//!
//! Moved here from `yadorilink-sync-core::repository::change_history`
//! (Phase 7D-9F): this repository never had any real coupling to a
//! `sync-core`-local type -- it was already calling into this crate's own
//! `dag_store` free functions and already depended on nothing but
//! `yadorilink-replica-domain` value types, so the move is a pure location
//! change plus a `SyncError` -> `SyncSqliteError` return-type swap (this
//! crate's own established error type already covers every variant this
//! repository's bodies raise: `Sqlite`/`Pool`/`Json` via `?`,
//! `CorruptState` explicitly).

use std::collections::HashSet;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};

use crate::dag_store::{self, ChangeEmitter, ChangeOrdering};
use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Conservative bound on how many remote Changes' versions+admission share
/// ONE writer_gate hold via [`ChangeHistoryRepository::
/// dag_admit_change_batch_with_versions`]. Chosen to amortize per-
/// transaction/fsync overhead under sustained remote admission (the
/// measurement that motivated this: `dag_admit_change_with_versions`'s own
/// single-Change `write_immediate` call held the writer_gate for 97.6% of a
/// real, sustained-admission 45.9s window, ~62 acquisitions/s) without
/// holding the gate for an unboundedly large batch and starving the
/// projection/completion writers that must interleave with admission.
/// Deliberately NOT derived from `IMPORT_BATCH_OP_LIMIT`/
/// `MAX_CHANGE_OP_BYTES` (the WIRE-message-size bounds
/// `local_change.rs::RECONCILE_CHUNK_OP_LIMIT` uses) -- this bounds
/// TRANSACTION/gate-hold size, a different axis than wire-message size, and
/// the two happen to want different numbers for different reasons.
pub const REMOTE_ADMISSION_BATCH_SIZE: usize = 8;

/// One remote Change ready for admission, as
/// [`ChangeHistoryRepository::dag_admit_change_batch_with_versions`] wants
/// it -- the same three arguments [`ChangeHistoryRepository::
/// dag_admit_change_with_versions`] takes for one Change, bundled so a
/// caller can collect a `Vec<PendingAdmission>` before calling the batch
/// method once.
pub struct PendingAdmission<'a> {
    pub change: &'a Change,
    pub versions: &'a [FileVersion],
    pub applied: bool,
}

pub struct ChangeHistoryRepository {
    database: Arc<SyncDatabase>,
}

impl ChangeHistoryRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Appends a group's initial-import changes in a single transaction, but
    /// only if the group's history is still empty. Each element of `batches`
    /// becomes one signed change carrying those ops; the changes chain
    /// linearly (each takes the previous as its parent, exactly as normal
    /// local emission does), so a large existing index converts into a
    /// bounded chain of bounded-size changes that converges to a single head.
    /// Returns the number of changes appended, or `None` if the group already
    /// had history — an import already ran, or normal emission / peer
    /// admission has begun. The emptiness check runs *inside* the write
    /// transaction, so a crash mid-import rolls back cleanly (the next run
    /// redoes it) and a second concurrent caller observes the committed
    /// result and does nothing, making the whole import idempotent. See
    /// `yadorilink_daemon::dag_import` (relocated there in Phase 7D-10.5) for
    /// the caller that builds `batches` from the index and the
    /// call-ordering it requires.
    ///
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see this module's own doc comment for why it is a parameter here
    /// rather than resolved internally.
    pub fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
        auth: ChangeAuth,
    ) -> Result<Option<usize>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // A non-empty head set means this group already has history: an
            // earlier import committed, or emission / peer admission has run.
            // Re-importing would inject a second root behind the existing
            // frontier, so skip entirely.
            if !dag_store::group_heads(tx, group_id)?.is_empty() {
                return Ok(None);
            }
            // Persist every referenced version in the same transaction as the
            // import changes. Keyed by content hash, so passing the flat set
            // (not per-batch) is correct regardless of which change references
            // which version.
            for version in versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            let mut appended = 0usize;
            for ops in batches {
                let change =
                    dag_store::emit_local_change(tx, group_id, ops.clone(), auth, emitter)?;
                let hash = change.compute_hash();
                for op in ops {
                    let paths: [&str; 2] = match op {
                        Op::Put { path, .. } | Op::Delete { path } => {
                            [path.as_str(), path.as_str()]
                        }
                        Op::Move { from, to, .. } => [from.as_str(), to.as_str()],
                    };
                    for path in paths.into_iter().take(if paths[0] == paths[1] { 1 } else { 2 }) {
                        set_authoring_change_hash_in_tx(tx, group_id, path, &hash)?;
                    }
                }
                appended += 1;
            }
            Ok(Some(appended))
        })
    }

    // --- Change-history read / admit API (used by peer sync) ---
    //
    // These read the DAG store and admit verified peer changes. Admission is
    // deliberately separate from verification: a caller MUST run
    // `yadorilink_replica_domain::change::verify_change` (hash + signature against the peer's
    // pinned signing key + group authorization) before calling
    // `dag_admit_change`, since the pinned key and authorization live in the
    // peer/coordination layer, not here.

    /// The most recent change `device_id` authored that touches `path`.
    ///
    /// [`yadorilink_sync_sqlite::file_index::FileIndexRepository::get_authoring_change_hash`]
    /// answers the same question from the *current projection*, and therefore
    /// cannot answer it at all for a path whose row is gone: a delete removes
    /// the row, and a rename moves it to the destination. This reads the
    /// retained history instead, so a delete's and a rename source's
    /// authoring identity are both recoverable — which is what any
    /// causal-supersession check over a path's full lifetime needs.
    /// `dag_list_group_changes` is ordered by `(lamport, change_hash)`, so the
    /// last match is the causally latest one.
    pub fn dag_last_authored_change_for_path(
        &self,
        group_id: &str,
        device_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let changes = dag_store::list_group_changes(conn, group_id)?;
            Ok(changes
                .iter()
                .rev()
                .find(|change| {
                    change.device_id.as_str() == device_id
                        && change.ops.iter().any(|op| match op {
                            yadorilink_replica_domain::change::Op::Put { path: p, .. }
                            | yadorilink_replica_domain::change::Op::Delete { path: p } => {
                                p.as_str() == path
                            }
                            yadorilink_replica_domain::change::Op::Move { from, to, .. } => {
                                from.as_str() == path || to.as_str() == path
                            }
                        })
                })
                .map(|change| change.change_hash()))
        })
    }

    /// Paths represented anywhere in this group's retained change history.
    pub fn dag_group_history_paths(
        &self,
        group_id: &str,
    ) -> Result<HashSet<String>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::group_history_paths(conn, group_id))
    }

    /// Appends repair operations to an already-initialized DAG without
    /// rewriting the index. The caller must hold each affected path lock and
    /// re-check history after acquiring it.
    ///
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see this module's own doc comment for why it is a parameter here
    /// rather than resolved internally.
    pub fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
        auth: ChangeAuth,
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for version in versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            let change = dag_store::emit_local_change(tx, group_id, ops.clone(), auth, emitter)?;
            let hash = change.compute_hash();
            for op in &ops {
                let paths: &[&yadorilink_replica_domain::ids::SyncPath] = match op {
                    Op::Put { path, .. } | Op::Delete { path } => &[path],
                    Op::Move { from, to, .. } => &[from, to],
                };
                for path in paths {
                    // History backfill is also a low-level DAG fixture API and
                    // may legitimately author an op before any index
                    // projection exists. When a current row does exist, bind
                    // it in this same transaction; otherwise later DAG
                    // materialization creates it with this hash.
                    tx.execute(
                        "UPDATE files SET authoring_change_hash = ?1
                         WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                        rusqlite::params![&hash.0[..], group_id, path.as_str()],
                    )?;
                }
            }
            Ok(hash)
        })
    }

    /// Every admitted-but-not-yet-projected change for `group_id`, oldest-first
    /// — the reconciliation layer's re-projection worklist (see
    /// [`dag_store::list_unapplied`]). The `applied` flag is the durable retry
    /// state: a change stays here until its path projection actually succeeds.
    pub fn dag_list_unapplied_changes(
        &self,
        group_id: &str,
    ) -> Result<Vec<Change>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| dag_store::list_unapplied(conn, group_id))
    }

    /// Whether a change is already present in the applied store.
    pub fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| dag_store::has_change(conn, hash))
    }

    pub fn dag_has_change_or_pruned(
        &self,
        group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            dag_store::has_change_or_pruned(conn, group_id, hash)
        })
    }

    /// Compares two authoring identities using one checked-out connection.
    /// `None` means at least one hash is not verified retained/pruned history
    /// for this group. Keeping existence checks and both ancestry walks on one
    /// connection avoids four pool/query round-trips per reconciled record.
    pub fn dag_compare_authoring(
        &self,
        group_id: &str,
        local: &ChangeHash,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            compare_authoring_on_conn(conn, group_id, local, incoming)
        })
    }

    /// Reads the current row's author (`files.authoring_change_hash`) and
    /// compares it to `incoming` on the same SQLite connection. Used by the
    /// large-index prefilter hot path. Reads a single `files` column to seed
    /// the comparison, but the comparison itself is DAG-authoring logic
    /// (`compare_authoring_on_conn`, the same helper `dag_compare_authoring`
    /// above uses) -- it lives here, not on `FileIndexRepository`, because
    /// what it answers is "how does this change relate to the current
    /// authoring lineage", not a `files`-table CRUD question.
    pub fn current_authoring_relation(
        &self,
        group_id: &str,
        path: &str,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let local_bytes = conn
                .query_row(
                    "SELECT authoring_change_hash FROM files
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
                .optional()?
                .flatten();
            let Some(local_bytes) = local_bytes else { return Ok(None) };
            let local = ChangeHash(local_bytes.try_into().map_err(|bytes: Vec<u8>| {
                SyncSqliteError::CorruptState(format!(
                    "current row {group_id}/{path} has an invalid {}-byte authoring identity",
                    bytes.len()
                ))
            })?);
            compare_authoring_on_conn(conn, group_id, &local, incoming)
        })
    }

    /// Whether a change is already known locally at all — admitted or still
    /// buffered as an orphan. See `dag_store::has_change_or_buffered_orphan`.
    pub fn dag_has_change_or_buffered_orphan(
        &self,
        hash: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::has_change_or_buffered_orphan(conn, hash))
    }

    /// Read-only DAG-progress diagnostics for one group. See
    /// [`dag_store::GroupDagDiagnostics`]; consumed by convergence
    /// tests/tools only, never by a production sync path.
    pub fn dag_group_diagnostics(
        &self,
        group_id: &str,
    ) -> Result<dag_store::GroupDagDiagnostics, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::group_dag_diagnostics(conn, group_id))
    }

    /// Where one specific hash stands locally (admitted / orphaned /
    /// missing). See [`dag_store::DagHashDisposition`]; diagnostic only.
    pub fn dag_describe_hash(
        &self,
        hash: &ChangeHash,
    ) -> Result<dag_store::DagHashDisposition, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| dag_store::describe_hash(conn, hash))
    }

    /// Every admitted change for `group_id`, decoded. See
    /// [`dag_store::list_group_changes`]; diagnostic only.
    pub fn dag_list_group_changes(&self, group_id: &str) -> Result<Vec<Change>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::list_group_changes(conn, group_id))
    }

    /// Persists a content-addressed file version, transactionally. Idempotent;
    /// used by the change-transfer path to store a peer's version bytes before
    /// admitting the changes that reference them.
    pub fn dag_put_file_version(
        &self,
        group_id: &str,
        version: &FileVersion,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            dag_store::put_file_version(tx, group_id, version)?;
            Ok(())
        })
    }

    pub fn dag_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            dag_store::group_file_version_references_block(conn, group_id, block_hash)
        })
    }

    /// Records blocks whose bytes this device actually obtained through the
    /// group. Peer-provided FileVersion/change metadata never calls this.
    pub fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError> {
        // `write_immediate`, not `write`: `dag_store::record_group_block_
        // provenance` executes one `INSERT OR IGNORE` per hash in
        // `block_hashes`, and `write` opens no transaction of its own,
        // leaving each of those `execute` calls to run as its own
        // SQLite autocommit transaction -- under this database's
        // `synchronous = FULL` (see `SyncDatabase::open`'s own doc
        // comment), that is one `fsync` PER HASH. For a large file's
        // block list (hundreds of blocks for a multi-hundred-MB transfer
        // under content-defined chunking) that serialized fsync-per-row
        // cost was measured, via a temporary M6PHASE timer on the free
        // function below, at multiple SECONDS for a single call -- the
        // dominant real cost of the source-side "durable ->
        // authoritative_commit" phase this call sits directly in:
        // `LocalChangeProcessor::build_record_for_created_or_modified`
        // calls this immediately after chunking returns, before the
        // authoritative `FileRecord`/DAG commit.
        // Wrapping the whole batch in one `IMMEDIATE` transaction commits
        // (and fsyncs) it once, not once per row -- every row is still
        // `INSERT OR IGNORE`d exactly as before, so an idempotent re-run
        // after a crash mid-batch is unaffected; a crash now leaves this
        // group's provenance for the batch either fully recorded or not
        // recorded at all, which is a strictly stronger atomicity
        // guarantee than the previous per-row commit ever gave (that
        // left provenance for an arbitrary row prefix on a crash mid-loop).
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            dag_store::record_group_block_provenance(tx, group_id, block_hashes)
        })
    }

    /// Whether `ancestor` is a strict ancestor of `descendant`.
    pub fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::is_ancestor(conn, ancestor, descendant))
    }

    /// Admits a verified peer change transactionally: applies it (and
    /// promotes any orphans it unblocks) if its ancestry is complete,
    /// otherwise holds it in the bounded orphanage. Idempotent on duplicate
    /// delivery.
    pub fn dag_admit_change(
        &self,
        change: &Change,
        applied: bool,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        self.dag_admit_change_with_versions(change, &[], applied)
    }

    /// Atomically persists a verified peer change's referenced versions and
    /// admits the change. Admission failure rolls every version write back.
    ///
    /// A `CausalAuthViolation` failure gets one extra step after that
    /// rollback: `admit_change` cannot clean up a rejected change's
    /// buffered descendants (if any) itself, because any mutation it made
    /// would roll back right along with the `Err` this `write_immediate`
    /// call returns on -- `write_immediate` only commits on `Ok`. Re-running
    /// the cleanup here, in its own separate transaction, is what actually
    /// makes it persist. See `dag_store::admit_change`'s own `Violated`
    /// branch and `drop_orphan_subtree`'s doc comment for the full picture
    /// this closes: without it, a buffered orphan built on top of a
    /// revoked-writer's rejected replay would stay stuck in the buffer
    /// forever, reappearing in every future anti-entropy round.
    pub fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        let result = self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for version in versions {
                dag_store::put_file_version(tx, change.group_id.as_str(), version)?;
            }
            dag_store::admit_change(tx, change, applied)
        });
        if matches!(result, Err(SyncSqliteError::CausalAuthViolation)) {
            self.database.write_immediate::<_, SyncSqliteError>(|tx| {
                dag_store::drop_orphan_subtree_for_rejected_change(tx, &change.compute_hash())
            })?;
        }
        result
    }

    /// Bounded micro-batch sibling of [`Self::dag_admit_change_with_versions`]:
    /// admits every item in `items` in order, taking at most
    /// `REMOTE_ADMISSION_BATCH_SIZE` writer_gate holds regardless of how
    /// large `items` is -- see [`REMOTE_ADMISSION_BATCH_SIZE`]'s own doc for
    /// why this exists (a sustained-remote-admission writer_gate contention
    /// measurement, C4, 2026-09-01: `dag_admit_change_with_versions`'s
    /// single-Change `write_immediate` call held the gate for 97.6% of a
    /// real 45.9s window). The chunking happens INSIDE this function, not
    /// by caller convention -- a caller cannot accidentally create one
    /// unboundedly large writer_gate hold by handing this an arbitrarily
    /// long `items`.
    ///
    /// Two-tier design per chunk, chosen so the overwhelmingly common
    /// (all-succeed) case pays no per-item overhead beyond the plain writes
    /// themselves:
    ///
    /// - **Healthy fast path**: every item in the chunk is admitted directly
    ///   against the SAME outer transaction, no per-item `Savepoint` --
    ///   `results[i]` for `i` in this chunk is `Ok(...)` for every item, and
    ///   the whole chunk commits once.
    /// - **Exceptional fallback**: the moment any item in the chunk fails
    ///   (for its own reason -- rejected, `CausalAuthViolation`, anything
    ///   [`dag_store::admit_change`]/[`dag_store::put_file_version`] can
    ///   return), the WHOLE chunk's fast-path attempt is abandoned (nothing
    ///   in it commits -- the transaction rolls back on `Drop`, same as
    ///   `write_immediate` always does on `Err`) and the SAME chunk is
    ///   replayed through [`Self::dag_admit_change_with_versions`], one item
    ///   at a time, in original order -- the pre-existing, already-correct
    ///   sequential path, unchanged. This gives EXACT sequential semantics
    ///   for the rare failure case: for `[valid A, invalid B, valid C]`, B's
    ///   own durable rejected-change cleanup (`CausalAuthViolation`'s
    ///   `drop_orphan_subtree_for_rejected_change`) runs and completes
    ///   before C is even attempted, byte-identical to calling
    ///   `dag_admit_change_with_versions` three times in a row -- never the
    ///   batch-collected-and-delayed cleanup an earlier revision of this
    ///   function used, which could let C observe a different intermediate
    ///   state than sequential admission would have left it.
    ///
    /// A failure to even open the chunk's outer transaction, or to commit it
    /// after every item in the fast path already succeeded, is a genuine
    /// INFRASTRUCTURE failure -- structurally distinguished from a per-item
    /// failure (an internal flag is set only from inside the per-item loop's
    /// own error paths, never reachable from `write_immediate`'s own
    /// checkout/transaction-open/commit code) -- and is fail-closed: every
    /// item in that chunk gets a description of the same infrastructure
    /// failure back, and the chunk is NOT replayed sequentially (replaying
    /// would retry the same broken infrastructure once per item instead of
    /// surfacing the real problem once, and unlike a per-item rejection, an
    /// infrastructure failure's outcome is not guaranteed deterministic on
    /// retry).
    pub fn dag_admit_change_batch_with_versions(
        &self,
        items: &[PendingAdmission<'_>],
    ) -> Vec<Result<dag_store::AdmitResult, SyncSqliteError>> {
        let mut results = Vec::with_capacity(items.len());
        for chunk in items.chunks(REMOTE_ADMISSION_BATCH_SIZE) {
            results.extend(self.admit_one_bounded_chunk(chunk));
        }
        results
    }

    /// One `REMOTE_ADMISSION_BATCH_SIZE`-or-fewer-item chunk of
    /// [`Self::dag_admit_change_batch_with_versions`] -- see that method's
    /// own doc comment for the fast-path/fallback design this implements.
    fn admit_one_bounded_chunk(
        &self,
        chunk: &[PendingAdmission<'_>],
    ) -> Vec<Result<dag_store::AdmitResult, SyncSqliteError>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        // Set only from inside the per-item loop below, right before it
        // returns `Err` -- never reachable from `write_immediate`'s own
        // pool-checkout/transaction-open/commit code, all of which run
        // outside `operation`'s own body. This is what lets the `Err` arm
        // below tell "one of our items failed" (safe, deterministic to
        // replay) apart from "the transaction itself failed" (not).
        let item_failure = std::cell::Cell::new(false);
        let fast_path = self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let mut chunk_results = Vec::with_capacity(chunk.len());
            for item in chunk {
                for version in item.versions {
                    if let Err(e) = dag_store::put_file_version(tx, item.change.group_id.as_str(), version) {
                        item_failure.set(true);
                        return Err(e);
                    }
                }
                match dag_store::admit_change(tx, item.change, item.applied) {
                    Ok(admitted) => chunk_results.push(admitted),
                    Err(e) => {
                        item_failure.set(true);
                        return Err(e);
                    }
                }
            }
            Ok(chunk_results)
        });
        match fast_path {
            Ok(chunk_results) => chunk_results.into_iter().map(Ok).collect(),
            Err(_) if item_failure.get() => {
                // Exceptional fallback: nothing in this chunk's fast-path
                // attempt committed (the whole transaction rolled back), so
                // replaying every item -- including whichever ones would
                // have succeeded -- through the existing sequential path is
                // exactly as correct as if the fast path had never been
                // tried.
                chunk
                    .iter()
                    .map(|item| {
                        self.dag_admit_change_with_versions(item.change, item.versions, item.applied)
                    })
                    .collect()
            }
            Err(e) => {
                // Infrastructure failure: pool checkout, transaction open,
                // or the commit itself (every item in the fast-path loop
                // above already returned `Ok`, so `item_failure` is still
                // `false`). Fail closed, no replay.
                let message = e.to_string();
                chunk
                    .iter()
                    .map(|_| {
                        Err(SyncSqliteError::CorruptState(format!(
                            "remote-admission micro-batch's outer transaction failed \
                             (infrastructure, not any item's own admission outcome): {message}"
                        )))
                    })
                    .collect()
            }
        }
    }

    /// Marks a stored change as materialized into the index.
    pub fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| dag_store::mark_applied(conn, hash))
    }

    /// Records a device's acknowledged head for a group. This single-head
    /// convenience is preserved verbatim for the heads-exchange path; it maps
    /// onto the multi-head frontier store as a one-element frontier (replacing
    /// any prior one). Callers with a full frontier use
    /// [`yadorilink_replica_engine::compaction::record_acknowledged_frontier`] instead, which
    /// stores every head.
    pub fn dag_set_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
        hash: &ChangeHash,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            dag_store::set_device_frontier(tx, group_id, device_id, std::slice::from_ref(hash))
        })
    }

    /// A device's acknowledged frontier for a group as a single head, if any —
    /// the smallest by hash when several were recorded. Preserved for the
    /// heads-exchange path's single-head hint; the full multi-head frontier is
    /// available through the compaction store trait.
    pub fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, SyncSqliteError> {
        Ok(self
            .database
            .read(|conn| dag_store::get_device_frontier(conn, group_id, device_id))?
            .into_iter()
            .next())
    }
}

pub(crate) fn set_authoring_change_hash_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    let affected = tx.execute(
        "UPDATE files SET authoring_change_hash = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
        rusqlite::params![&hash.0[..], group_id, path],
    )?;
    if affected != 1 {
        return Err(SyncSqliteError::CorruptState(format!(
            "failed to attach authoring identity to {group_id}/{path}"
        )));
    }
    Ok(())
}

pub(crate) fn compare_authoring_on_conn(
    conn: &Connection,
    group_id: &str,
    local: &ChangeHash,
    incoming: &ChangeHash,
) -> Result<Option<ChangeOrdering>, SyncSqliteError> {
    if !dag_store::has_change_or_pruned(conn, group_id, local)?
        || !dag_store::has_change_or_pruned(conn, group_id, incoming)?
    {
        return Ok(None);
    }
    if local == incoming {
        return Ok(Some(ChangeOrdering::Equal));
    }
    if dag_store::is_ancestor(conn, local, incoming)? {
        return Ok(Some(ChangeOrdering::Before));
    }
    if dag_store::is_ancestor(conn, incoming, local)? {
        return Ok(Some(ChangeOrdering::After));
    }
    Ok(Some(ChangeOrdering::Concurrent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::Op;
    use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

    fn schema_init(conn: &Connection) -> Result<(), DatabaseError> {
        dag_store::init_dag_schema(conn).map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
    }

    /// `yadorilink_sqlite_runtime::c4_diag`'s counters are process-wide
    /// globals, shared by every test in this binary. Only
    /// `batched_admission_reduces_writer_gate_acquisitions_to_ceil_n_over_
    /// batch_size` reads them, but every test below that calls
    /// `dag_admit_change*` still needs to hold this lock while doing so --
    /// otherwise a sibling test's own admission calls, running concurrently
    /// on another thread, silently inflate that one test's `reset()`-to-
    /// `stats()` window. Confirmed genuinely necessary, not defensive
    /// overkill: without it, `cargo test --test-threads=4` on this module
    /// reproducibly failed the acquisition-count assertion (wrong count,
    /// different assertion line each run) in 3 of 3 repeated full-suite
    /// runs; the SAME test in isolation (`-- batched_admission_reduces...`)
    /// always passed.
    fn c4_diag_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn open_test_repo() -> ChangeHistoryRepository {
        let database = Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"));
        ChangeHistoryRepository::new(database)
    }

    fn real_auth(seq: u64, epoch: u64) -> ChangeAuth {
        ChangeAuth { auth_seq: seq, auth_epoch: epoch, policy_head_hash: [seq as u8 ^ 0x5A; 32] }
    }

    fn create_op(path: &str) -> Op {
        Op::Delete { path: yadorilink_replica_domain::ids::SyncPath(path.to_string()) }
    }

    /// Codex-caught follow-up to the `orphan_integrity::drop_orphan_subtree`
    /// fix (C4-10 review, second pass): `admit_change` cannot durably clean
    /// up a rejected change's buffered descendants itself, since any
    /// mutation it makes rolls back right along with the `Err` it returns --
    /// `write_immediate` only commits on `Ok`. This test goes through the
    /// REAL `ChangeHistoryRepository` (a real `SyncDatabase`, a real
    /// `write_immediate` transaction), unlike `dag_store::tests`'s own
    /// otherwise-identical scenario (which calls `admit_change` directly on
    /// a bare, autocommit `rusqlite::Connection` and so cannot see this
    /// class of bug at all) -- this is the one that actually proves the
    /// cleanup persists in production.
    #[test]
    fn dropping_a_causal_auth_violation_persists_its_descendant_cleanup() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[42u8; 32]));
        let root =
            dag_store::emit_local_change(&sender, "g", vec![create_op("a")], real_auth(10, 2), &em)
                .unwrap();
        let mid =
            dag_store::emit_local_change(&sender, "g", vec![create_op("b")], real_auth(3, 1), &em)
                .unwrap();
        let leaf =
            dag_store::emit_local_change(&sender, "g", vec![create_op("c")], real_auth(3, 1), &em)
                .unwrap();

        let repo = open_test_repo();
        assert!(repo.dag_admit_change(&root, true).unwrap().outcome == dag_store::AdmitOutcome::Applied);
        assert!(
            repo.dag_admit_change(&leaf, true).unwrap().outcome == dag_store::AdmitOutcome::Orphaned
        );

        // mid's parent (root) is already live, so this goes through
        // `admit_change`'s top-level `Violated` branch, not `promote_
        // orphans`'s -- exactly the call path the first Codex finding
        // missed.
        let result = repo.dag_admit_change(&mid, true);
        assert!(matches!(result, Err(SyncSqliteError::CausalAuthViolation)));

        repo.database
            .read::<_, SyncSqliteError>(|conn| {
                assert!(
                    !dag_store::has_change_or_buffered_orphan(conn, &leaf.compute_hash()).unwrap(),
                    "leaf must not remain buffered once its parent is permanently rejected -- \
                     the cleanup must persist despite the rejected admission's own rollback"
                );
                Ok(())
            })
            .unwrap();
    }

    // C4 writer-gate convoy fix (2026-09-01): `dag_admit_change_batch_with_
    // versions` regression coverage. See that method's own doc comment for
    // the guarantees these five tests each check.

    /// Batch amplification: N healthy remote Changes admitted through the
    /// OLD one-call-per-Change path cause N writer_gate acquisitions; the
    /// SAME N Changes admitted through the new batched path, chunked at
    /// `REMOTE_ADMISSION_BATCH_SIZE`, must cause only `ceil(N /
    /// REMOTE_ADMISSION_BATCH_SIZE)`. Confirmed genuinely RED by calling
    /// `dag_admit_change_with_versions` once per item instead of chunking
    /// through the batch method: the batched-path assertion below then
    /// fails (17 acquisitions instead of 3), since the whole reduction is
    /// exactly what did not exist before this fix.
    #[test]
    fn batched_admission_reduces_writer_gate_acquisitions_to_ceil_n_over_batch_size() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[11u8; 32]));
        // Deliberately not a multiple of REMOTE_ADMISSION_BATCH_SIZE (8), to
        // prove the batching rounds UP (ceil), not down.
        let n = 17;
        let changes: Vec<Change> = (0..n)
            .map(|i| {
                dag_store::emit_local_change(
                    &sender,
                    "g",
                    vec![create_op(&format!("p{i}"))],
                    ChangeAuth::PLACEHOLDER,
                    &em,
                )
                .unwrap()
            })
            .collect();

        // OLD path, for direct comparison in the same test: N calls, N
        // acquisitions -- unaffected by this fix, still correct.
        let sequential_repo = open_test_repo();
        yadorilink_sqlite_runtime::c4_diag::reset();
        for change in &changes {
            sequential_repo.dag_admit_change(change, true).unwrap();
        }
        let (sequential_acquisitions, _) = yadorilink_sqlite_runtime::c4_diag::stats();
        assert_eq!(
            sequential_acquisitions, n as u64,
            "sanity: the pre-existing one-call-per-Change path must still take one gate \
             acquisition per Change"
        );

        // NEW path: chunk into REMOTE_ADMISSION_BATCH_SIZE-sized micro-batches.
        let batched_repo = open_test_repo();
        yadorilink_sqlite_runtime::c4_diag::reset();
        let items: Vec<PendingAdmission> = changes
            .iter()
            .map(|c| PendingAdmission { change: c, versions: &[], applied: true })
            .collect();
        for chunk in items.chunks(REMOTE_ADMISSION_BATCH_SIZE) {
            for result in batched_repo.dag_admit_change_batch_with_versions(chunk) {
                assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
            }
        }
        let (batched_acquisitions, _) = yadorilink_sqlite_runtime::c4_diag::stats();
        let expected = (n as u64).div_ceil(REMOTE_ADMISSION_BATCH_SIZE as u64);
        assert_eq!(
            batched_acquisitions, expected,
            "{n} Changes chunked at {REMOTE_ADMISSION_BATCH_SIZE} must take ceil({n} / \
             {REMOTE_ADMISSION_BATCH_SIZE}) = {expected} gate acquisitions, not {n}"
        );
    }

    /// Mixed success/failure: valid A / invalid (CausalAuthViolation) B /
    /// valid C, all three in ONE micro-batch call, must leave A and C
    /// admitted exactly as sequential admission would -- B's failure must
    /// not roll back its batch-mates. Confirmed genuinely RED by removing
    /// the per-item `tx.savepoint()` (accepting the outer transaction's
    /// first `Err` as fatal to the whole batch, matching the naive
    /// non-savepoint approach this test exists to rule out): A and C would
    /// then both come back `Err` too, since the outer `write_immediate`
    /// closure's first `?` would abort the whole transaction.
    #[test]
    fn one_items_causal_auth_violation_does_not_roll_back_its_batch_mates() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[22u8; 32]));

        let a = dag_store::emit_local_change(&sender, "g", vec![create_op("a")], real_auth(10, 2), &em)
            .unwrap();
        // b pins an OLDER auth coordinate than its own parent (a) -- the
        // exact CausalAuthViolation shape the existing single-item test
        // above already establishes.
        let b = dag_store::emit_local_change(&sender, "g", vec![create_op("b")], real_auth(3, 1), &em)
            .unwrap();
        // c is a fully independent change (its own root, unrelated path),
        // sharing nothing causally with a/b -- a fresh sender/emitter pair,
        // since `emit_local_change` always chains onto ITS OWN emitter's
        // current head: reusing `em`/`sender` here would make c a CHILD of
        // b (the very thing this test needs c to NOT be).
        let independent_sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&independent_sender).unwrap();
        let independent_em = ChangeEmitter::new("device-B", SigningKey::from_bytes(&[23u8; 32]));
        let c = dag_store::emit_local_change(
            &independent_sender,
            "g",
            vec![create_op("c")],
            ChangeAuth::PLACEHOLDER,
            &independent_em,
        )
        .unwrap();

        let repo = open_test_repo();
        let items = [
            PendingAdmission { change: &a, versions: &[], applied: true },
            PendingAdmission { change: &b, versions: &[], applied: true },
            PendingAdmission { change: &c, versions: &[], applied: true },
        ];
        let mut results = repo.dag_admit_change_batch_with_versions(&items).into_iter();
        let result_a = results.next().unwrap();
        let result_b = results.next().unwrap();
        let result_c = results.next().unwrap();

        assert!(
            matches!(result_a.unwrap().outcome, dag_store::AdmitOutcome::Applied),
            "a must be admitted -- it precedes the rejected item and shares no fate with it"
        );
        assert!(
            matches!(result_b, Err(SyncSqliteError::CausalAuthViolation)),
            "b's own violation must still surface as its own item result"
        );
        assert!(
            matches!(result_c.unwrap().outcome, dag_store::AdmitOutcome::Applied),
            "c must be admitted -- b's rejection, earlier in the same batch, must not roll back \
             a later, unrelated item"
        );
        repo.database
            .read::<_, SyncSqliteError>(|conn| {
                assert!(dag_store::has_change(conn, &a.compute_hash()).unwrap());
                assert!(dag_store::has_change(conn, &c.compute_hash()).unwrap());
                assert!(
                    !dag_store::has_change_or_buffered_orphan(conn, &b.compute_hash()).unwrap(),
                    "b's own cleanup must still run despite being inside a larger batch"
                );
                Ok(())
            })
            .unwrap();
    }

    /// P2a-final: an invalid parent (B, `CausalAuthViolation`) immediately
    /// followed by B's OWN descendant (C) in the same batch input -- the
    /// exact scenario that made the earlier savepoint-based design's
    /// delayed cleanup timing not obviously equivalent to sequential
    /// admission (sequential B-then-C runs B's durable rejected-change
    /// cleanup BEFORE C is ever attempted; a design that only collects and
    /// runs that cleanup after the whole outer transaction commits lets C
    /// observe a different intermediate state). Proves batched admission of
    /// `[b, c]` produces IDENTICAL per-item outcomes and IDENTICAL final
    /// durable state to admitting them sequentially, one call each.
    #[test]
    fn invalid_parent_followed_by_its_own_descendant_in_one_batch_matches_sequential_admission() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[66u8; 32]));
        let root = dag_store::emit_local_change(&sender, "g", vec![create_op("root")], real_auth(10, 2), &em)
            .unwrap();
        // b pins an OLDER auth coordinate than its own parent (root) --
        // CausalAuthViolation, exactly as the existing single-item test
        // establishes.
        let b = dag_store::emit_local_change(&sender, "g", vec![create_op("b")], real_auth(3, 1), &em)
            .unwrap();
        // c is b's OWN child (same emitter, chains onto b) -- the
        // scenario-defining detail: c's real causal parent is the change
        // that is about to be permanently rejected.
        let c = dag_store::emit_local_change(&sender, "g", vec![create_op("c")], real_auth(3, 1), &em)
            .unwrap();

        // Sequential reference: root admitted first (shared setup), then b
        // and c admitted one call each.
        let sequential_repo = open_test_repo();
        sequential_repo.dag_admit_change(&root, true).unwrap();
        let seq_b = sequential_repo.dag_admit_change(&b, true);
        let seq_c = sequential_repo.dag_admit_change(&c, true).unwrap();

        // Batched: same root setup, then b and c admitted together in ONE
        // micro-batch call.
        let batched_repo = open_test_repo();
        batched_repo.dag_admit_change(&root, true).unwrap();
        let items = [
            PendingAdmission { change: &b, versions: &[], applied: true },
            PendingAdmission { change: &c, versions: &[], applied: true },
        ];
        let mut batch_results = batched_repo.dag_admit_change_batch_with_versions(&items).into_iter();
        let batch_b = batch_results.next().unwrap();
        let batch_c = batch_results.next().unwrap().unwrap();

        assert!(matches!(seq_b, Err(SyncSqliteError::CausalAuthViolation)));
        assert!(
            matches!(batch_b, Err(SyncSqliteError::CausalAuthViolation)),
            "b's own violation must surface identically whether admitted sequentially or batched"
        );
        assert_eq!(
            seq_c.outcome,
            batch_c.outcome,
            "c's own outcome must match between sequential and batched admission"
        );
        assert_eq!(
            seq_c.outcome,
            dag_store::AdmitOutcome::Orphaned,
            "sanity: c's real parent (b) was never durably admitted, so c must buffer as an \
             orphan, not apply"
        );

        for (label, repo) in [("sequential", &sequential_repo), ("batched", &batched_repo)] {
            repo.database
                .read::<_, SyncSqliteError>(|conn| {
                    assert!(
                        !dag_store::has_change_or_buffered_orphan(conn, &b.compute_hash()).unwrap(),
                        "[{label}] b's cleanup must have fully run: no durable row, no buffered \
                         descendant referencing it"
                    );
                    assert!(
                        dag_store::has_change_or_buffered_orphan(conn, &c.compute_hash()).unwrap()
                            && !dag_store::has_change(conn, &c.compute_hash()).unwrap(),
                        "[{label}] c must be buffered (present in the orphan store) but NOT \
                         durably admitted, since its real parent b never durably landed"
                    );
                    Ok(())
                })
                .unwrap();
        }
    }

    /// Parent/orphan chain, out-of-order, inside one micro-batch: admitting
    /// `[leaf, parent]` (child before its own parent) in ONE batch call must
    /// produce the identical final state sequential admission of the same
    /// two items, in the same order, would -- leaf buffers as an orphan on
    /// its own item, then gets promoted as a side effect of parent's own
    /// admission a moment later, ALL inside the same outer transaction (the
    /// promotion sees the leaf's own already-committed-to-the-outer-
    /// transaction buffered row, exactly as it would see a separately
    /// committed one). Confirmed genuinely RED by admitting `parent` before
    /// `leaf` in the item slice instead (reversing the order the real bug
    /// this batching change could introduce would get wrong): the
    /// assertions below (leaf `Orphaned` at its own index, parent's
    /// `newly_admitted` containing leaf's hash) fail under that reversed
    /// order, proving this test actually depends on order being preserved
    /// rather than passing vacuously regardless of it.
    #[test]
    fn out_of_order_parent_child_inside_one_micro_batch_promotes_exactly_as_sequential_admission_would()
    {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[33u8; 32]));
        let parent = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("parent")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let leaf = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("leaf")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();

        let repo = open_test_repo();
        // leaf BEFORE parent -- the out-of-order arrival this test targets.
        let items = [
            PendingAdmission { change: &leaf, versions: &[], applied: true },
            PendingAdmission { change: &parent, versions: &[], applied: true },
        ];
        let mut results = repo.dag_admit_change_batch_with_versions(&items).into_iter();
        let leaf_result = results.next().unwrap().unwrap();
        let parent_result = results.next().unwrap().unwrap();

        assert_eq!(
            leaf_result.outcome,
            dag_store::AdmitOutcome::Orphaned,
            "leaf's own item result must show Orphaned -- its parent had not been admitted yet \
             at leaf's own position in the batch"
        );
        assert_eq!(
            parent_result.outcome,
            dag_store::AdmitOutcome::Applied,
            "parent must admit cleanly"
        );
        assert!(
            parent_result.newly_admitted.contains(&leaf.compute_hash()),
            "parent's own AdmitResult must report leaf as promoted alongside it -- the same \
             `newly_admitted` shape sequential admission (admit leaf, then admit parent) would \
             produce, since promote_orphans finds leaf already buffered in the same outer \
             transaction"
        );
        repo.database
            .read::<_, SyncSqliteError>(|conn| {
                assert!(
                    dag_store::has_change(conn, &leaf.compute_hash()).unwrap(),
                    "leaf must be durably promoted, not left buffered, once its own micro-batch \
                     completes"
                );
                Ok(())
            })
            .unwrap();
    }

    /// Projection: every genuinely admitted Change in a micro-batch must
    /// still bump the correct `projection_obligations` row for the paths
    /// its own ops touch -- the bump happens inside `admit_change` itself
    /// (unchanged by this fix), but this test proves it still fires when
    /// `admit_change` runs against a `Savepoint` instead of directly
    /// against the outer `Transaction`.
    #[test]
    fn batched_admission_still_bumps_projection_obligations_for_touched_paths() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[44u8; 32]));
        let a = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("path-a")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let b = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("path-b")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();

        let repo = open_test_repo();
        let items = [
            PendingAdmission { change: &a, versions: &[], applied: true },
            PendingAdmission { change: &b, versions: &[], applied: true },
        ];
        for result in repo.dag_admit_change_batch_with_versions(&items) {
            assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
        }
        repo.database
            .read::<_, SyncSqliteError>(|conn| {
                for path in ["path-a", "path-b"] {
                    let obligation =
                        crate::projection_obligations::lookup_projection_obligation(conn, "g", path)
                            .unwrap();
                    assert!(
                        obligation.is_some(),
                        "{path} must have a projection obligation after batched admission"
                    );
                    assert!(
                        obligation.unwrap().invalidation_generation >= 1,
                        "{path}'s obligation must show a genuine invalidation, not a placeholder \
                         row"
                    );
                }
                Ok(())
            })
            .unwrap();
    }

    /// Duplicate replay: re-admitting an already-admitted Change alongside a
    /// genuinely new one, in the same micro-batch, must not bump the
    /// already-admitted one's obligation a second time (PROJ-1: "a Change
    /// receipt is not a projection event," still enforced per-item inside a
    /// batch) -- while the genuinely new Change still gets its own bump.
    #[test]
    fn duplicate_replay_inside_a_batch_does_not_double_bump_its_own_obligation() {
        let _guard = c4_diag_test_guard();
        let sender = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&sender).unwrap();
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[55u8; 32]));
        let already_known = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("path-known")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let genuinely_new = dag_store::emit_local_change(
            &sender,
            "g",
            vec![create_op("path-new")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();

        let repo = open_test_repo();
        repo.dag_admit_change(&already_known, true).unwrap();
        let generation_before = repo
            .database
            .read::<_, SyncSqliteError>(|conn| {
                crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-known")
            })
            .unwrap()
            .unwrap()
            .invalidation_generation;

        let items = [
            PendingAdmission { change: &already_known, versions: &[], applied: true },
            PendingAdmission { change: &genuinely_new, versions: &[], applied: true },
        ];
        for result in repo.dag_admit_change_batch_with_versions(&items) {
            assert!(matches!(result.unwrap().outcome, dag_store::AdmitOutcome::Applied));
        }

        let generation_after = repo
            .database
            .read::<_, SyncSqliteError>(|conn| {
                crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-known")
            })
            .unwrap()
            .unwrap()
            .invalidation_generation;
        assert_eq!(
            generation_before, generation_after,
            "re-delivering an already-admitted Change inside a batch must not bump its \
             obligation's invalidation_generation again"
        );

        let new_obligation = repo
            .database
            .read::<_, SyncSqliteError>(|conn| {
                crate::projection_obligations::lookup_projection_obligation(conn, "g", "path-new")
            })
            .unwrap();
        assert!(
            new_obligation.is_some(),
            "the genuinely new Change in the same batch must still get its own obligation"
        );
    }
}
