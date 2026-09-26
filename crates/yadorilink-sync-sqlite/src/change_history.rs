//! `ChangeHistoryRepository` owns the DAG-facing (`dag_*`/`append_*`) API
//! surface. It has no table of its own -- every method here is a thin
//! pool-checkout-and-delegate wrapper to a free function in
//! [`crate::dag_store`], which already take a plain `&Connection`/
//! `&Transaction` and own the real DAG persistence, keyed off whatever
//! tables `dag_store`'s own schema defines. This cluster follows
//! `dag_store`'s own doc comment ("Every function here
//! takes a plain `&Connection`... this is what lets a local mutation
//! append its change and mutate the file index atomically, in one
//! commit"). `record_group_block_provenance`/`group_has_block_provenance`/
//! `dag_group_file_version_references_block` live here rather than on
//! `FileIndexRepository` because they are pure `dag_store` delegates,
//! like every other `dag_store` pass-through.

use std::collections::HashSet;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};

use crate::dag_store::{self, ChangeEmitter, ChangeOrdering};
use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_engine::conflict::PathHead;
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
    /// `Some` for a remotely-verified Change: its authorization evidence is
    /// attached in the SAME transaction as the Change admission itself
    /// (the atomic-receive requirement: a crash must never produce a stranded Change with no
    /// evidence, or evidence with no Change). `None` for a local Change:
    /// local emission stays Pending (no evidence) until `flush_pending_
    /// checkpoint` obtains one later.
    pub evidence: Option<&'a yadorilink_replica_engine::ports::ChangeEvidence>,
}

/// Outcome of one [`ChangeHistoryRepository::append_initial_import`] attempt.
///
/// A plain `Option<usize>` used to be enough (`Some` = committed, `None` =
/// "group already had history, did nothing"), but that collapsed two
/// different facts into one: "every current row is already covered" and "a
/// concurrent write added an unbound row this attempt's snapshot never saw,
/// so nothing was committed and the caller must retry with a fresh
/// snapshot" both used to answer `Ok(None)`, and the daemon's own restart
/// integrity check (`yadorilink_sqlite_runtime::init_schema`) would only
/// discover the difference later; this type keeps the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportAppendOutcome {
    /// Committed this many batched import changes, binding every row this
    /// attempt targeted.
    Committed(usize),
    /// Every current row for this group already carries a verified
    /// authoring identity -- nothing to do. Covered by an earlier import,
    /// or entirely by backfill/live emission reaching every row first.
    FullyCovered,
    /// At least one current row lacking a verified authoring identity
    /// exists for this group that this attempt's `batches` do not cover --
    /// a concurrent write (another scan chunk, backfill, or live emission)
    /// changed the group's unbound-row set after the caller's snapshot was
    /// taken. Nothing was committed. The caller must rebuild `batches`/
    /// `versions` from a fresh snapshot (via
    /// [`crate::file_index::FileIndexRepository::list_unauthored_current_paths`])
    /// and call this again -- see `yadorilink_daemon::dag_import::
    /// ensure_initial_import`'s retry loop.
    StaleSnapshot,
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
    /// `yadorilink_daemon::dag_import` for
    /// the caller that builds `batches` from the index and the
    /// call-ordering it requires.
    ///
    /// `known_excluded` names paths the caller has already decided can
    /// NEVER enter history (`yadorilink_daemon::dag_import`'s reserved-
    /// namespace/sync-root-lock collision check) -- deliberately,
    /// permanently uncovered by any `batches` this or any future attempt
    /// will ever build, as opposed to a row that is merely NOT YET covered
    /// because a concurrent write raced this attempt's snapshot. Without
    /// this distinction the freshness check below cannot tell "a genuinely
    /// new unbound row appeared, retry" from "the one row that can never be
    /// bound is still unbound, as expected, forever" -- and would retry the
    /// latter until `yadorilink_daemon::dag_import::ensure_initial_import`'s
    /// retry budget is exhausted.
    pub fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
        known_excluded: &HashSet<String>,
        actual_state: &std::collections::HashMap<String, crate::file_index::ImportedActualState>,
    ) -> Result<ImportAppendOutcome, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // Re-derived FRESH here, inside the write transaction, rather
            // than trusting the caller's `batches` for WHICH rows still need
            // binding: `batches` was built from a snapshot taken outside
            // this transaction (`ensure_initial_import`'s `list_files`
            // call), and a concurrent write for this group -- another scan
            // chunk, `backfill_missing_history` claiming a path first, a
            // live emission -- can land in the gap between that snapshot
            // and this commit. Closing that authoring-identity race means
            // the transaction that makes a group's unbound-row count hit
            // zero must decide that from the database's own current state,
            // not from a value computed before the transaction opened.
            let unbound = crate::file_index::unauthored_current_paths_in_tx(tx, group_id)?;
            // Which rows this transaction is actually the one binding.
            // Only those may have an actual-state proof adopted from the
            // caller's observation: a row someone else bound in the gap
            // since that observation was taken has had its own content
            // written by whoever bound it, and that writer recorded its
            // own proof. Adopting a stale observation over the top would
            // assert that the path already holds content it may not.
            let binding_now: HashSet<&str> = unbound.iter().map(String::as_str).collect();
            if unbound.iter().all(|path| known_excluded.contains(path)) {
                return Ok(ImportAppendOutcome::FullyCovered);
            }

            let wanted: HashSet<String> =
                batches.iter().flatten().flat_map(op_paths).map(str::to_owned).collect();
            // An `unbound` entry that is neither `wanted` nor
            // `known_excluded` is the actual race: something else made a
            // row unbound (or left it unbound) after this attempt's
            // snapshot was taken, and this attempt's ops cannot bind a row
            // they never mention. Commit nothing -- committing `batches`
            // as-is would make the group DAG-backed while that row remains
            // permanently unbound, exactly the invariant this whole
            // mechanism exists to prevent. The reverse (an entry in
            // `wanted` no longer in `unbound`, because something else
            // already bound it first) is harmless: this attempt's
            // `set_authoring_change_hash_in_tx` below just re-stamps that
            // path with an equally-valid authoring change, a no-op in
            // effect.
            if unbound.iter().any(|path| !wanted.contains(path) && !known_excluded.contains(path)) {
                return Ok(ImportAppendOutcome::StaleSnapshot);
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
                let change = dag_store::emit_local_change(tx, group_id, ops.clone(), emitter)?;
                let hash = change.compute_hash();
                for path in ops.iter().flat_map(op_paths) {
                    set_authoring_change_hash_in_tx(tx, group_id, path, &hash)?;
                    // Same transaction as the change that put this path
                    // into history: the proof and the history it proves
                    // can never disagree across a crash, because there is
                    // no moment where one exists without the other.
                    if binding_now.contains(path) {
                        record_import_capture(tx, group_id, path, &hash, actual_state)?;
                    }
                }
                appended += 1;
            }
            Ok(ImportAppendOutcome::Committed(appended))
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
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for version in versions {
                dag_store::put_file_version(tx, group_id, version)?;
            }
            let change = dag_store::emit_local_change(tx, group_id, ops.clone(), emitter)?;
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

    /// Whether a change is already present in the retained store.
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

    /// Whether `hash` is a verified authoring identity for a row of this
    /// group ([`dag_store::is_verified_authoring_change`]).
    pub fn dag_is_verified_authoring_change(
        &self,
        group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            dag_store::is_verified_authoring_change(conn, group_id, hash)
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

    /// [`Self::dag_group_file_version_references_block`], restricted to the
    /// published subgraph plus verified pruned-witness evidence -- see
    /// `dag_store::published_view::published_group_file_version_references_block`.
    /// The block-serving authorization boundary a peer request must be
    /// checked against; the raw method above stays for purely local callers
    /// (retroactive conflict-copy repair reading its own already-verified
    /// history).
    pub fn dag_published_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            dag_store::published_view::published_group_file_version_references_block(
                conn, group_id, block_hash,
            )
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
        // cost was measured, via a temporary timer on the free
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

    /// `path`'s live heads: the changes touching it that are causally
    /// maximal in the currently admitted DAG, already normalized into the
    /// form `resolve_path_heads` consumes.
    ///
    /// A read of the derived path frontier, maintained in the same
    /// transaction that admits a change -- see `dag_store::path_frontier`'s
    /// own module doc comment. Nothing here decodes an encoded change,
    /// walks ancestry, or costs anything proportional to the group's
    /// history.
    pub fn dag_path_live_heads(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<PathHead>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::live_path_heads(conn, group_id, path))
    }

    /// The heads `path` resolves from ([`dag_store::path_gamma_heads`]).
    pub fn dag_path_gamma_heads(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<PathHead>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| dag_store::path_gamma_heads(conn, group_id, path))
    }

    /// Admits a verified peer change transactionally: applies it (and
    /// promotes any orphans it unblocks) if its ancestry is complete,
    /// otherwise holds it in the bounded orphanage. Idempotent on duplicate
    /// delivery.
    pub fn dag_admit_change(
        &self,
        change: &Change,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        self.dag_admit_change_with_versions(change, &[])
    }

    /// Atomically persists a verified peer change's referenced versions and
    /// admits the change. Admission failure rolls every version write back.
    ///
    pub fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        self.dag_admit_one_with_versions(&PendingAdmission { change, versions, evidence: None })
    }

    /// [`Self::dag_admit_change_with_versions`], but for a remotely-verified
    /// Change whose authorization evidence must be attached in the SAME
    /// transaction as the Change admission itself -- see [`PendingAdmission
    /// ::evidence`]'s own doc comment. The daemon's
    /// `ReplicaCoordinator` (`peer_replica_state.rs`) is the only production
    /// caller; every other caller (local emission, tests)
    /// keeps using the plain `evidence`-less method above.
    pub fn dag_admit_change_with_versions_and_evidence(
        &self,
        change: &Change,
        versions: &[FileVersion],
        evidence: &yadorilink_replica_engine::ports::ChangeEvidence,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        self.dag_admit_one_with_versions(&PendingAdmission {
            change,
            versions,
            evidence: Some(evidence),
        })
    }

    /// [`Self::dag_admit_change_with_versions`]'s body, taking the whole
    /// [`PendingAdmission`] so the batch path's sequential fallback can call
    /// it per-item.
    fn dag_admit_one_with_versions(
        &self,
        item: &PendingAdmission<'_>,
    ) -> Result<dag_store::AdmitResult, SyncSqliteError> {
        let PendingAdmission { change, versions, evidence } = *item;
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            for version in versions {
                dag_store::put_file_version(tx, change.group_id.as_str(), version)?;
            }
            let result = dag_store::admit_change(tx, change)?;
            if let Some(evidence) = evidence {
                let hash = change.compute_hash();
                dag_store::published_view::attach_authorization_evidence_on_conn(
                    tx,
                    &evidence.checkpoint_hash,
                    change.group_id.as_str(),
                    change.device_id.as_str(),
                    evidence.checkpoint_seq,
                    &evidence.checkpoint_encoded,
                    &evidence.checkpoint_signature,
                    &evidence.author_signing_public_key,
                    &[(hash, evidence.merkle_proof_encoded.clone())],
                )?;
            }
            Ok(result)
        })
    }

    /// Bounded micro-batch sibling of [`Self::dag_admit_change_with_versions`]:
    /// admits every item in `items` in order, taking at most
    /// `REMOTE_ADMISSION_BATCH_SIZE` writer_gate holds regardless of how
    /// large `items` is -- see [`REMOTE_ADMISSION_BATCH_SIZE`]'s own doc for
    /// why this exists (under sustained remote admission,
    /// `dag_admit_change_with_versions`'s one-`write_immediate`-per-Change
    /// shape can hold the writer gate almost continuously). The chunking happens INSIDE this
    /// function, not
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
    ///   (rejected, or anything [`dag_store::admit_change`]/
    ///   [`dag_store::put_file_version`] can return), the WHOLE chunk's
    ///   fast-path attempt is abandoned (nothing in it commits -- the
    ///   transaction rolls back on `Drop`, same as `write_immediate` always
    ///   does on `Err`) and the SAME chunk is replayed through
    ///   [`Self::dag_admit_change_with_versions`], one item at a time, in
    ///   original order -- the pre-existing, already-correct sequential
    ///   path, unchanged. This gives EXACT sequential semantics for the
    ///   rare failure case: for `[valid A, invalid B, valid C]`, B's own
    ///   failure is fully resolved before C is even attempted,
    ///   byte-identical to calling `dag_admit_change_with_versions` three
    ///   times in a row.
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
                    if let Err(e) =
                        dag_store::put_file_version(tx, item.change.group_id.as_str(), version)
                    {
                        item_failure.set(true);
                        return Err(e);
                    }
                }
                match admit_with_evidence(tx, item) {
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
                chunk.iter().map(|item| self.dag_admit_one_with_versions(item)).collect()
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

/// Records that the import change `hash` captured `path` off this device's
/// disk, adopting the caller's observed actual state for it when one exists.
///
/// Only for a row this transaction binds: such a row was read off this
/// device's disk by the scan whose emission this import is, so the change is
/// a capture of that disk -- whether or not the import could still prove what
/// the disk holds. A row another writer bound first carries that writer's own
/// record, and is left to it.
fn record_import_capture(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    path: &str,
    hash: &ChangeHash,
    actual_state: &std::collections::HashMap<String, crate::file_index::ImportedActualState>,
) -> Result<(), SyncSqliteError> {
    crate::local_capture_provenance::record_local_capture_in_tx(tx, group_id, path, hash)?;
    if let Some(observed) = actual_state.get(path) {
        crate::file_index::adopt_local_capture_actual_state(
            tx,
            group_id,
            path,
            observed.record_kind,
            &observed.version_hash,
            &observed.filesystem_identity,
        )?;
    }
    Ok(())
}

/// Admits one item's change and, for a remotely-verified one, attaches its
/// authorization evidence in the same transaction.
fn admit_with_evidence(
    tx: &rusqlite::Transaction<'_>,
    item: &PendingAdmission<'_>,
) -> Result<dag_store::AdmitResult, SyncSqliteError> {
    let admitted = dag_store::admit_change(tx, item.change)?;
    if let Some(evidence) = item.evidence {
        let hash = item.change.compute_hash();
        dag_store::published_view::attach_authorization_evidence_on_conn(
            tx,
            &evidence.checkpoint_hash,
            item.change.group_id.as_str(),
            item.change.device_id.as_str(),
            evidence.checkpoint_seq,
            &evidence.checkpoint_encoded,
            &evidence.checkpoint_signature,
            &evidence.author_signing_public_key,
            &[(hash, evidence.merkle_proof_encoded.clone())],
        )?;
    }
    Ok(admitted)
}

/// Every path one `Op` touches -- both ends of a `Move`, deduplicated when
/// they happen to be equal. Shared by `append_initial_import`'s "which
/// paths does this batch cover" computation and its authoring-stamp loop,
/// so the two can never silently drift out of sync with each other.
fn op_paths(op: &Op) -> Vec<&str> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path.as_str()],
        Op::Move { from, to, .. } if from.as_str() == to.as_str() => vec![from.as_str()],
        Op::Move { from, to, .. } => vec![from.as_str(), to.as_str()],
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
    // A change the installed base carries is behind every change written
    // on the base: after the epoch reset that installed it, retained and
    // pruned history are exactly the changes written on it.
    let carried_by_base = |hash: &ChangeHash| -> Result<Option<bool>, SyncSqliteError> {
        if dag_store::has_change_or_pruned(conn, group_id, hash)? {
            return Ok(Some(false));
        }
        Ok(dag_store::is_verified_authoring_change(conn, group_id, hash)?.then_some(true))
    };
    let (Some(local_in_base), Some(incoming_in_base)) =
        (carried_by_base(local)?, carried_by_base(incoming)?)
    else {
        return Ok(None);
    };
    if local == incoming {
        return Ok(Some(ChangeOrdering::Equal));
    }
    match (local_in_base, incoming_in_base) {
        (true, true) => return Ok(Some(ChangeOrdering::Concurrent)),
        (true, false) => return Ok(Some(ChangeOrdering::Before)),
        (false, true) => return Ok(Some(ChangeOrdering::After)),
        (false, false) => {}
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
mod tests;
