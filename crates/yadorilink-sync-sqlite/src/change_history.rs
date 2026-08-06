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
            .read::<_, SyncSqliteError>(|conn| Ok(dag_store::group_history_paths(conn, group_id)?))
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
        self.database
            .read::<_, SyncSqliteError>(|conn| Ok(dag_store::list_unapplied(conn, group_id)?))
    }

    /// Whether a change is already present in the applied store.
    pub fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| Ok(dag_store::has_change(conn, hash)?))
    }

    pub fn dag_has_change_or_pruned(
        &self,
        group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(dag_store::has_change_or_pruned(conn, group_id, hash)?)
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
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(dag_store::has_change_or_buffered_orphan(conn, hash)?)
        })
    }

    /// Read-only DAG-progress diagnostics for one group. See
    /// [`dag_store::GroupDagDiagnostics`]; consumed by convergence
    /// tests/tools only, never by a production sync path.
    pub fn dag_group_diagnostics(
        &self,
        group_id: &str,
    ) -> Result<dag_store::GroupDagDiagnostics, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(dag_store::group_dag_diagnostics(conn, group_id)?)
        })
    }

    /// Where one specific hash stands locally (admitted / orphaned /
    /// missing). See [`dag_store::DagHashDisposition`]; diagnostic only.
    pub fn dag_describe_hash(
        &self,
        hash: &ChangeHash,
    ) -> Result<dag_store::DagHashDisposition, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| Ok(dag_store::describe_hash(conn, hash)?))
    }

    /// Every admitted change for `group_id`, decoded. See
    /// [`dag_store::list_group_changes`]; diagnostic only.
    pub fn dag_list_group_changes(&self, group_id: &str) -> Result<Vec<Change>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| Ok(dag_store::list_group_changes(conn, group_id)?))
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
        Ok(self.database.read::<_, SyncSqliteError>(|conn| {
            dag_store::group_file_version_references_block(conn, group_id, block_hash)
        })?)
    }

    /// Records blocks whose bytes this device actually obtained through the
    /// group. Peer-provided FileVersion/change metadata never calls this.
    pub fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncSqliteError> {
        Ok(self.database.write::<_, SyncSqliteError>(|conn| {
            dag_store::record_group_block_provenance(conn, group_id, block_hashes)
        })?)
    }

    /// Whether `ancestor` is a strict ancestor of `descendant`.
    pub fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(dag_store::is_ancestor(conn, ancestor, descendant)?)
        })
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
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(dag_store::admit_change(tx, change, applied)?)
        })
    }

    /// Atomically persists a verified peer change's referenced versions and
    /// admits the change. Admission failure rolls every version write back.
    pub fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for version in versions {
                dag_store::put_file_version(tx, change.group_id.as_str(), version)?;
            }
            Ok(dag_store::admit_change(tx, change, applied)?)
        })
    }

    /// Marks a stored change as materialized into the index.
    pub fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| Ok(dag_store::mark_applied(conn, hash)?))
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
            Ok(dag_store::set_device_frontier(tx, group_id, device_id, std::slice::from_ref(hash))?)
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
