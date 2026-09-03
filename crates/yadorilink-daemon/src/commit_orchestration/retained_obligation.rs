//! Retained obligations (design `preimage-capture.md` §5.5/§12): the
//! identity-checked physical unlink that finalizes a retained preimage's
//! automatic deletion.
//!
//! # Crate history
//!
//! The SQL-backed half of this lifecycle -- the `retained_preimages`
//! schema, obligation CRUD ([`create`], [`get`], [`record_late_write`],
//! [`record_captured_change`], [`mark_authorization_permanently_lost`],
//! [`set_capacity_degraded`] -- all re-exported here from their real home),
//! the durability-proof reads, the read-only deletion decision
//! ([`evaluate_deletion`]), and the orphaned `captured_authoring` root
//! sweep -- lives in
//! [`yadorilink_sync_sqlite::retained_obligation`]. See that module's own
//! doc comment for the full design: durable representation's two-leg proof,
//! the grace-clock policy, and the orphaned-root sweep's concurrency
//! reasoning all still apply unchanged to what moved.
//!
//! What lives here is exactly the piece that must never leave a crate with
//! both a real `rusqlite::Connection` and real filesystem access: the
//! identity-checked filesystem unlink ([`unlink_and_complete_deletion`])
//! and the two-phase intent/finalize state transition around it
//! ([`delete_if_eligible`]/[`complete_deletion_after_unlink`] and their
//! `_unchecked` cores). Both read `std::fs`,
//! `yadorilink_root_authority::fs_identity`, and
//! `yadorilink_filesystem_sync::fs_commit::ParentDirHandle`, none of which
//! `yadorilink-sync-sqlite` may depend on -- the same filesystem-execution/
//! SQL split this whole crate-split lineage follows. Deletion is
//! deliberately split this way: this module durably prepares an
//! identity-bound [`DeletionOutcome::UnlinkPending`], the caller removes
//! exactly that object through
//! [`yadorilink_filesystem_sync::fs_commit::ParentDirHandle`], and this
//! module atomically releases the DAG root and obligation only after
//! absence is confirmed.
//!
//! Moved here from `yadorilink-sync-core` (a later pass following the same
//! precedent this crate's `commit_orchestration` module already
//! documents): this file needs both `rusqlite::Connection` and real
//! filesystem mutation in the same call, which `yadorilink-filesystem-sync`
//! (no `rusqlite` dependency, by design) and `yadorilink-sync-sqlite` (must
//! never mutate the filesystem, by design) can never host together.
//! `yadorilink-daemon` already depends on `rusqlite` in production
//! (`commit_orchestration::orchestrator`/`plan_driver`, moved here for the
//! identical reason) and already depends on `yadorilink-filesystem-sync`'s
//! `ParentDirHandle`, so it is the first crate in the dependency graph able
//! to host this combination without violating either rule. Had zero real
//! callers anywhere in the workspace outside its own tests at the time of
//! this move (verified by a workspace-wide grep) -- a pure relocation, not
//! a behavior change; wiring a real caller remains future work, matching
//! `orchestrator`/`plan_driver`'s own still-unwired state.
//!
//! # Why deletion does not need the block liveness gate
//!
//! [`yadorilink_filesystem_sync::block_liveness::BlockLivenessGate`] arbitrates one specific
//! race: a block-store reference write (new content being committed) versus
//! physical block-store GC (content-addressed block bytes being unlinked).
//! A retained preimage's on-disk artefact is not a content-addressed block —
//! it is a plain file living at its own reserved-namespace path (§10,
//! `ArtefactKind::Retained`), entirely outside the block store. Deleting it
//! is an ordinary filesystem removal of that one artefact, not a block-store
//! GC operation, so the gate's writer/deleter mutual exclusion does not
//! apply to it: nothing this module's deletion touches is a block the gate
//! protects. The two durability-proof legs
//! [`yadorilink_sync_sqlite::retained_obligation::evaluate_deletion`]
//! depends on are also each independently safe against a concurrent
//! GC/compaction pass: leg 1 accepts a pruned stub (compaction cannot make
//! it false by running), and leg 2 is backed by ordinary `files`-row
//! retention that a correct compaction pass must already preserve (§13) —
//! so a racing compactor can only ever make that verification observe a
//! transient "not yet provable" state, which this module's fail-closed rule
//! already treats as `Retain`, never a false `Eligible`.
//!
//! # Who calls this, and when
//!
//! Not decided by this module -- every entry point here is unwired state
//! until a future orchestrator drives it (see `captured_authoring`'s own
//! receipts: nothing yet calls
//! [`yadorilink_sync_sqlite::retained_obligation::create`] either).

use std::path::Path;

use rusqlite::Connection;

use yadorilink_filesystem_sync::fs_commit::{ParentDirHandle, RemoveChildIdentityError};
use yadorilink_filesystem_sync::single_pass_capture::StabilityFingerprint;
use yadorilink_root_authority::fs_identity::{FileIdentity, IdentityComparison};
use yadorilink_sync_sqlite::dag_store::{self, RetentionClass};
use yadorilink_sync_sqlite::SyncSqliteError;
// The SQL-backed half of this lifecycle (schema, CRUD, durability proof,
// the read-only deletion decision, the orphaned-root sweep) lives in
// `yadorilink-sync-sqlite` -- see this crate's own module doc, "crate
// split" section, and that module's own doc comment for the full design.
// Deliberately a plain `use`, not `pub use`: nothing outside this crate
// names these through `yadorilink_sync_core::retained_obligation::*` today
// (verified by a workspace grep before this move), so there is no
// compatibility path to preserve.
use yadorilink_sync_sqlite::retained_obligation::{
    evaluate_deletion, get, load_deletion_intent, reject_time_regression, require_enabled,
    CAPTURED_AUTHORING_RETENTION_OWNER_KIND,
};
// Pure deletion-decision policy types this module's own signatures still
// need directly (`DeletionOutcome`'s `RetentionReason` field,
// `unlink_and_complete_deletion`'s `&dyn WriterExclusionProven` parameter).
use yadorilink_replica_engine::retained_obligation::{
    DeletionDecision, RetentionReason, WriterExclusionProven,
};

/// Outcome of the retained-preimage deletion state machine.
#[derive(Debug)]
pub enum DeletionOutcome {
    Retained(RetentionReason),
    /// A durable deletion intent exists. The obligation row and retention root
    /// still exist; the named object must be removed only if it matches
    /// `filesystem_identity`, then finalized through
    /// [`complete_deletion_after_unlink`]. Repeating preparation returns the
    /// same intent, so a crash before or after unlink is recoverable.
    UnlinkPending {
        custody_path: String,
        filesystem_identity: Vec<u8>,
    },
    /// The physical object is absent and the obligation/root hand-off has been
    /// durably finalized. A completed intent tombstone remains for recovery.
    Deleted {
        custody_path: String,
    },
}

/// Gated entry point: refuses while
/// [`yadorilink_sync_sqlite::filesystem_transaction::EXECUTION_ENABLED`] is
/// `false`. See [`delete_if_eligible_unchecked`] for the ungated core this
/// delegates to, and for what this module's own tests call directly while
/// the gate is closed.
pub fn delete_if_eligible(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
    observed_fingerprint: StabilityFingerprint,
    writer_exclusion: &dyn WriterExclusionProven,
) -> Result<DeletionOutcome, yadorilink_sync_sqlite::retained_obligation::RetainedObligationError> {
    require_enabled()?;
    delete_if_eligible_unchecked(
        conn,
        group_id,
        retained_id,
        now_unix_nanos,
        observed_fingerprint,
        writer_exclusion,
    )
}

/// The ungated core of [`delete_if_eligible`] — see that function's doc.
/// Exercised directly by this module's own tests (matching the `_unchecked`
/// seam `custody_transfer`/`captured_authoring` already use), and intended
/// as the eventual entry point for recovery code that must be able to run
/// this decision regardless of the forward execution gate.
///
/// The decision ([`yadorilink_sync_sqlite::retained_obligation::evaluate_deletion`])
/// and its consequences (releasing `captured_authoring`'s retention root,
/// deleting the row) run inside one `IMMEDIATE` transaction this function
/// opens itself, rather than trusting a caller to wrap them: `IMMEDIATE`
/// takes SQLite's write lock at `BEGIN`, so a concurrent writer (another
/// connection's `record_late_write`, for instance) is provably serialized
/// either fully before this transaction starts or fully after it commits —
/// never observably in between. The final `DELETE` is additionally
/// conditional on every field the decision was made against, not a plain
/// `DELETE ... WHERE retained_id = ?`; if it ever matches zero rows this
/// reports
/// [`yadorilink_sync_sqlite::retained_obligation::RetainedObligationError::StaleDecision`]
/// rather than silently treating a mismatch as success, since inside this
/// transaction that should be structurally impossible and is worth
/// surfacing as a hard error if it ever is not. Takes `&mut Connection`
/// (not `&Connection`, unlike every other function in this module) because
/// opening a transaction requires exclusive access to the connection for
/// its duration — this is the one entry point in this module for which
/// that exclusivity is load-bearing.
pub fn delete_if_eligible_unchecked(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
    observed_fingerprint: StabilityFingerprint,
    writer_exclusion: &dyn WriterExclusionProven,
) -> Result<DeletionOutcome, yadorilink_sync_sqlite::retained_obligation::RetainedObligationError> {
    use yadorilink_sync_sqlite::retained_obligation::RetainedObligationError;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    if let Some(intent) = load_deletion_intent(&tx, group_id, retained_id)? {
        if intent.state == "completed" {
            tx.commit()?;
            return Ok(DeletionOutcome::Deleted { custody_path: intent.custody_path });
        }
        let current = get(&tx, group_id, retained_id)?;
        if current.as_ref().is_some_and(|obligation| {
            obligation.updated_at_unix_nanos == intent.obligation_updated_at_unix_nanos
        }) {
            tx.commit()?;
            return Ok(DeletionOutcome::UnlinkPending {
                custody_path: intent.custody_path,
                filesystem_identity: intent.filesystem_identity,
            });
        }
        // A lifecycle update that serialized before preparation is safe to
        // re-evaluate only while the custody object still exists. If the object
        // is already absent, this intent is the sole durable evidence that a
        // physical unlink happened; keep it and fail closed rather than
        // laundering the state back into an ordinary obligation.
        match std::fs::symlink_metadata(&intent.custody_path) {
            Ok(_) => {
                tx.execute(
                    "DELETE FROM retained_preimage_deletion_intents \
                     WHERE group_id = ?1 AND retained_id = ?2 AND state = 'unlink_pending'",
                    rusqlite::params![group_id, retained_id],
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
                    "retained deletion intent for {retained_id:?} no longer matches the \
                     obligation, but custody object {:?} is already absent; keeping the \
                     intent and retention root for explicit recovery",
                    intent.custody_path
                ))));
            }
            Err(error) => return Err(RetainedObligationError::Sync(SyncSqliteError::Io(error))),
        }
    }

    let Some(obligation) = get(&tx, group_id, retained_id)? else {
        return Err(RetainedObligationError::NotFound {
            group_id: group_id.to_string(),
            retained_id: retained_id.to_string(),
        });
    };
    reject_time_regression(retained_id, obligation.updated_at_unix_nanos, now_unix_nanos)?;

    let decision = evaluate_deletion(
        &tx,
        &obligation,
        now_unix_nanos,
        observed_fingerprint,
        writer_exclusion,
    )?;
    let DeletionDecision::Eligible = decision else {
        let DeletionDecision::Retain(reason) = decision else { unreachable!() };
        return Ok(DeletionOutcome::Retained(reason));
    };

    let Some(recorded_identity_blob) = obligation.filesystem_identity.as_deref() else {
        return Ok(DeletionOutcome::Retained(RetentionReason::FilesystemIdentityUnproven));
    };
    let recorded_identity =
        yadorilink_sync_sqlite::file_identity_codec::decode_file_identity(recorded_identity_blob)?;
    let observed_identity = match FileIdentity::observe_path(Path::new(&obligation.custody_path)) {
        Ok(identity) => identity,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
                "retained artefact {:?} is already absent before a deletion intent was prepared",
                obligation.custody_path
            ))));
        }
        Err(error) => return Err(RetainedObligationError::Sync(SyncSqliteError::Io(error))),
    };
    let parent = Path::new(&obligation.custody_path).parent().ok_or_else(|| {
        SyncSqliteError::CorruptState("retained custody path has no parent".into())
    })?;
    let granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(parent);
    if !matches!(
        observed_identity.compare(&recorded_identity, granularity),
        IdentityComparison::SameObject
    ) {
        return Ok(DeletionOutcome::Retained(RetentionReason::FilesystemIdentityUnproven));
    }
    let deletion_identity =
        yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(&observed_identity);

    tx.execute(
        "INSERT INTO retained_preimage_deletion_intents \
         (group_id, retained_id, custody_path, filesystem_identity, \
          obligation_updated_at_unix_nanos, state, prepared_at_unix_nanos, completed_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'unlink_pending', ?6, NULL)",
        rusqlite::params![
            group_id,
            retained_id,
            &obligation.custody_path,
            &deletion_identity,
            obligation.updated_at_unix_nanos,
            now_unix_nanos,
        ],
    )?;
    tx.commit()?;

    Ok(DeletionOutcome::UnlinkPending {
        custody_path: obligation.custody_path,
        filesystem_identity: deletion_identity,
    })
}

/// Finalizes a prepared deletion only after the custody path is confirmed
/// absent. The obligation and captured-authoring retention root remain durable
/// until this transaction commits; a crash after unlink but before this call is
/// therefore recovered by repeating it.
pub fn complete_deletion_after_unlink(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
) -> Result<DeletionOutcome, yadorilink_sync_sqlite::retained_obligation::RetainedObligationError> {
    require_enabled()?;
    complete_deletion_after_unlink_unchecked(conn, group_id, retained_id, now_unix_nanos)
}

pub fn complete_deletion_after_unlink_unchecked(
    conn: &mut Connection,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
) -> Result<DeletionOutcome, yadorilink_sync_sqlite::retained_obligation::RetainedObligationError> {
    use yadorilink_sync_sqlite::retained_obligation::RetainedObligationError;

    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let intent = load_deletion_intent(&tx, group_id, retained_id)?.ok_or_else(|| {
        RetainedObligationError::StaleDecision { retained_id: retained_id.to_string() }
    })?;
    if intent.state == "completed" {
        tx.commit()?;
        return Ok(DeletionOutcome::Deleted { custody_path: intent.custody_path });
    }
    match std::fs::symlink_metadata(&intent.custody_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
                "refusing to finalize retained deletion while {:?} still exists",
                intent.custody_path
            ))));
        }
        Err(error) => return Err(RetainedObligationError::Sync(SyncSqliteError::Io(error))),
    }

    let obligation = get(&tx, group_id, retained_id)?.ok_or_else(|| {
        RetainedObligationError::StaleDecision { retained_id: retained_id.to_string() }
    })?;
    if obligation.updated_at_unix_nanos != intent.obligation_updated_at_unix_nanos {
        return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
            "retained deletion removed custody object {:?}, but obligation {retained_id:?} \
             changed after intent preparation; keeping the intent, obligation and retention \
             root for explicit recovery",
            intent.custody_path
        ))));
    }
    reject_time_regression(retained_id, obligation.updated_at_unix_nanos, now_unix_nanos)?;
    let captured_change_hash = obligation.last_captured_change_hash.ok_or_else(|| {
        RetainedObligationError::StaleDecision { retained_id: retained_id.to_string() }
    })?;

    dag_store::release_retention_root(
        &tx,
        CAPTURED_AUTHORING_RETENTION_OWNER_KIND,
        retained_id,
        group_id,
        &captured_change_hash,
        RetentionClass::FullPayload,
    )?;
    let deleted = tx.execute(
        "DELETE FROM retained_preimages \
         WHERE group_id = ?1 AND retained_id = ?2 AND updated_at_unix_nanos = ?3",
        rusqlite::params![group_id, retained_id, intent.obligation_updated_at_unix_nanos],
    )?;
    if deleted != 1 {
        return Err(RetainedObligationError::StaleDecision {
            retained_id: retained_id.to_string(),
        });
    }
    tx.execute(
        "UPDATE retained_preimage_deletion_intents \
         SET state = 'completed', completed_at_unix_nanos = ?3 \
         WHERE group_id = ?1 AND retained_id = ?2 AND state = 'unlink_pending'",
        rusqlite::params![group_id, retained_id, now_unix_nanos],
    )?;
    tx.commit()?;
    Ok(DeletionOutcome::Deleted { custody_path: intent.custody_path })
}

/// Safe forward driver for automatic deletion. It persists the intent first,
/// removes only the exact object recorded by that intent, and finalizes the DB
/// hand-off afterward. Every intermediate state is retryable after a crash.
pub fn unlink_and_complete_deletion(
    conn: &mut Connection,
    parent_dir: &ParentDirHandle,
    group_id: &str,
    retained_id: &str,
    now_unix_nanos: i64,
    observed_fingerprint: StabilityFingerprint,
    writer_exclusion: &dyn WriterExclusionProven,
) -> Result<DeletionOutcome, yadorilink_sync_sqlite::retained_obligation::RetainedObligationError> {
    use yadorilink_sync_sqlite::retained_obligation::RetainedObligationError;

    require_enabled()?;
    let prepared = delete_if_eligible_unchecked(
        conn,
        group_id,
        retained_id,
        now_unix_nanos,
        observed_fingerprint,
        writer_exclusion,
    )?;
    let DeletionOutcome::UnlinkPending { custody_path, filesystem_identity } = prepared else {
        return Ok(prepared);
    };
    let path = Path::new(&custody_path);
    let parent = path.parent().ok_or_else(|| {
        RetainedObligationError::Sync(SyncSqliteError::CorruptState(
            "retained custody path has no parent".into(),
        ))
    })?;
    let expected_parent = parent.canonicalize().map_err(SyncSqliteError::Io)?;
    let actual_parent = parent_dir.path().canonicalize().map_err(SyncSqliteError::Io)?;
    if expected_parent != actual_parent {
        return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
            "retained deletion parent mismatch: intent names {:?}, handle names {:?}",
            expected_parent, actual_parent
        ))));
    }
    let name = path.file_name().ok_or_else(|| {
        RetainedObligationError::Sync(SyncSqliteError::CorruptState(
            "retained custody path has no final component".into(),
        ))
    })?;
    let expected_identity =
        yadorilink_sync_sqlite::file_identity_codec::decode_file_identity(&filesystem_identity)?;
    let granularity =
        yadorilink_root_authority::fs_capabilities::probe_birth_time_granularity(parent_dir.path());
    match parent_dir.remove_child_if_identity_matches(name, &expected_identity, granularity) {
        Ok(()) | Err(RemoveChildIdentityError::Absent) => {}
        Err(error) => {
            return Err(RetainedObligationError::Sync(SyncSqliteError::CorruptState(format!(
                "identity-checked retained artefact unlink refused for {name:?}: {error:?}"
            ))));
        }
    }
    complete_deletion_after_unlink_unchecked(conn, group_id, retained_id, now_unix_nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::{
        BlockInfo, FileMeta, FileVersion, RecordKind, VersionBlock,
    };
    use yadorilink_replica_domain::ids::{
        BlockHash, ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
    };
    use yadorilink_replica_engine::retained_obligation::{NoWriterExclusionProof, ObligationState};
    use yadorilink_sync_sqlite::retained_obligation::{
        create, grace_period_nanos, init_retained_obligations_schema,
        mark_authorization_permanently_lost, orphan_root_grace_period_nanos,
        record_captured_change, record_late_write, set_capacity_degraded,
        sweep_orphaned_captured_authoring_roots, sweep_orphaned_captured_authoring_roots_unchecked,
        NewObligation, OrphanRootSweepReport, RetainedObligationError,
    };

    /// Test-only stand-in for a real writer-exclusion proof -- always
    /// `true`, used ONLY by tests that specifically want to isolate the
    /// other three deletion preconditions (grace/fingerprint/durable-
    /// representation) from this fourth one. Every test that is not
    /// specifically about `WriterExclusionUnproven` itself should use this
    /// rather than `NoWriterExclusionProof`, exactly the same way
    /// `RootCommitPermit::for_tests()` exists so unrelated tests don't have
    /// to thread real lifecycle proof through.
    struct AlwaysProvenWriterExclusion;

    impl WriterExclusionProven for AlwaysProvenWriterExclusion {
        fn writer_exclusion_proven(&self, _group_id: &str, _retained_id: &str) -> bool {
            true
        }
    }

    /// Like [`open`], but backed by a real file so a second [`Connection`] to
    /// the same path shares the same database -- needed to drive a genuine
    /// cross-connection race (see the `critical2_*` race test below), which
    /// two `:memory:` connections can never see each other's writes for.
    fn open_file_backed(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        yadorilink_sync_sqlite::dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
        yadorilink_sync_sqlite::dag_store::init_dag_schema(&conn).unwrap();
        init_retained_obligations_schema(&conn).unwrap();
        create_test_files_table(&conn);
        conn
    }

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        yadorilink_sync_sqlite::dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
        yadorilink_sync_sqlite::dag_store::init_dag_schema(&conn).unwrap();
        init_retained_obligations_schema(&conn).unwrap();
        create_test_files_table(&conn);
        conn
    }

    /// The shape of the shared `files` index this module reads from -- a
    /// hand-built subset of `index.rs`'s real schema, but wide enough to
    /// exercise `verify_durable_representation`'s content-derived leg 2:
    /// `blocks_json`/`size`/`mtime_unix_nanos`/`record_kind`/
    /// `symlink_target`/`unix_mode` are exactly the columns
    /// `FileVersion::from_index_row` re-derives a version identity from.
    fn create_test_files_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                group_id            TEXT NOT NULL,
                path                TEXT NOT NULL,
                deleted             INTEGER NOT NULL DEFAULT 0,
                authoring_change_hash BLOB,
                blocks_json         TEXT NOT NULL DEFAULT '[]',
                size                INTEGER NOT NULL DEFAULT 0,
                mtime_unix_nanos    INTEGER NOT NULL DEFAULT 0,
                record_kind         TEXT NOT NULL DEFAULT 'file',
                symlink_target      BLOB,
                unix_mode            INTEGER NOT NULL DEFAULT 0,
                xattrs_json         TEXT NOT NULL DEFAULT '[]'
            );",
        )
        .unwrap();
    }

    fn new_obligation<'a>(id: &'a str, group_id: &'a str) -> NewObligation<'a> {
        NewObligation {
            retained_id: id,
            originating_transaction_id: Some("txn-1"),
            source_epoch: Some(3),
            group_id,
            original_path: "a/b.txt",
            custody_path: ".yadorilink-v1-retained.ep0",
            parent_directory_identity: b"parent-id-bytes",
            filesystem_identity: Some(b"fs-id-bytes"),
            original_parent_basis_id: "basis-1",
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Whether `result` failed because SQLite's own busy timeout (set on
    /// every race test's connections below) expired before this side of the
    /// race could acquire the write lock at all -- the *third* legitimate
    /// outcome the `critical1_*`/`critical2_*` races below account for,
    /// alongside the two ordinary commit orderings. Matches the same two
    /// error codes (`DatabaseLocked` and `DatabaseBusy`) `index.rs`'s own
    /// `is_database_locked_error` does, for the same reason: which of the
    /// two SQLite reports depends on journal mode, not on anything this
    /// module controls. This is not the operation *failing its own logic*
    /// (that is `NonMonotonicTime`/`StaleDecision`, handled separately) --
    /// it is the operation never having started at all, so a caller that
    /// sees this must reason about the *other* side of the race having run
    /// to completion alone, not about any partial effect from this one.
    fn is_database_busy_error<T>(result: &Result<T, RetainedObligationError>) -> bool {
        matches!(
            result,
            Err(RetainedObligationError::Sync(SyncSqliteError::Sqlite(
                rusqlite::Error::SqliteFailure(e, _)
            )))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }

    /// Admits a real change and puts a matching `files` row whose own
    /// content columns genuinely re-derive to the captured version's hash --
    /// both legs of `verify_durable_representation` proven for real, not
    /// stubbed, and not merely via `authoring_change_hash` column equality.
    fn author_and_materialize(
        conn: &Connection,
        group_id: &str,
        byte: u8,
    ) -> (ChangeHash, VersionHash) {
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![byte; 32]), size: 4 }],
            4,
            FileMeta {
                mtime_unix_nanos: 1,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        dag_store::put_file_version(conn, group_id, &version).unwrap();
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d1".into()),
            FolderGroupId(group_id.into()),
            vec![Op::Put {
                path: SyncPath("a/b.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        dag_store::admit_change(conn, &change, false).unwrap();
        let hash = change.compute_hash();
        dag_store::register_retention_root(
            conn,
            CAPTURED_AUTHORING_RETENTION_OWNER_KIND,
            "ep0",
            group_id,
            &hash,
            RetentionClass::FullPayload,
        )
        .unwrap();
        let blocks_json =
            serde_json::to_string(&vec![BlockInfo { hash: vec![byte; 32], offset: 0, size: 4 }])
                .unwrap();
        conn.execute(
            "INSERT INTO files \
             (group_id, path, deleted, authoring_change_hash, blocks_json, size, \
              mtime_unix_nanos, record_kind, symlink_target, unix_mode) \
             VALUES (?1, 'a/b.txt', 0, ?2, ?3, 4, 1, 'file', NULL, -1)",
            rusqlite::params![group_id, &hash.0[..], blocks_json],
        )
        .unwrap();
        (hash, version.version_hash)
    }

    #[test]
    fn create_starts_known_old_with_grace_clock_running() {
        let conn = open();
        let obligation = create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        assert_eq!(obligation.state, ObligationState::KnownOld);
        assert_eq!(obligation.retain_until_unix_nanos, 1_000 + grace_period_nanos());
        assert!(obligation.last_captured_change_hash.is_none());
        assert!(obligation.last_captured_version_hash.is_none());
        assert!(obligation.last_fingerprint.is_none());
        assert!(!obligation.capacity_degraded);
    }

    #[test]
    fn create_is_idempotent_for_a_byte_for_byte_retry() {
        let conn = open();
        let first = create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        let second = create(&conn, &new_obligation("ep0", "g"), 9_999).unwrap();
        // The retry's `now` is ignored -- the original row, clock included,
        // survives untouched.
        assert_eq!(first.retain_until_unix_nanos, second.retain_until_unix_nanos);
        assert_eq!(first.created_at_unix_nanos, second.created_at_unix_nanos);
    }

    #[test]
    fn create_refuses_a_retained_id_reused_for_a_different_object() {
        let conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        let mut conflicting = new_obligation("ep0", "g");
        conflicting.original_path = "different/path.txt";
        let err = create(&conn, &conflicting, 1_000).unwrap_err();
        assert!(matches!(
            err,
            RetainedObligationError::ObligationIdentityConflict { retained_id } if retained_id == "ep0"
        ));
    }

    #[test]
    fn deletion_precondition_1_expiry_missing_retains() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        // Content settles (late write) *before* it is captured, so the
        // capture genuinely describes the content this obligation now
        // holds -- unlike the critical1 regression test below, this is the
        // legitimate ordering.
        let observed = StabilityFingerprint([0u8; 32]);
        record_late_write(&mut conn, "g", "ep0", observed, 1_000).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xAB);
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 1_000).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        // Grace clock restarted by the capture at t=1000, so t=1000 is
        // still inside the window -- everything else (fingerprint, DAG,
        // conflict copy, and the captured-change/version pairing) is
        // proven, only expiry is missing.
        let decision =
            evaluate_deletion(&conn, &obligation, 1_000, observed, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::GraceWindowNotExpired));
    }

    #[test]
    fn deletion_precondition_2_fingerprint_changed_retains() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xAB);
        let recorded = StabilityFingerprint([1u8; 32]);
        record_late_write(&mut conn, "g", "ep0", recorded, 0).unwrap();
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        let stale_handle_wrote_again = StabilityFingerprint([2u8; 32]);
        let decision = evaluate_deletion(
            &conn,
            &obligation,
            after_grace,
            stale_handle_wrote_again,
            &NoWriterExclusionProof,
        )
        .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::FingerprintChanged));
    }

    #[test]
    fn deletion_precondition_3a_no_captured_change_retains() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let fp = StabilityFingerprint([3u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::NoCapturedChange));
    }

    #[test]
    fn deletion_precondition_3b_dag_representation_unproven_retains() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let fp = StabilityFingerprint([4u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        // A change hash this replica never actually admitted -- not proof of
        // anything, and must not be trusted as if it were. Written directly,
        // bypassing `record_captured_change`'s own validation of this exact
        // case (see `record_captured_change_refuses_a_change_hash_it_has_never_admitted`
        // below), so this test still exercises `evaluate_deletion`'s own
        // independent leg-1 defense in depth: even a row that reached this
        // state some other way must never be treated as proven.
        let bogus_hash = ChangeHash([0xEE; 32]);
        let bogus_version = VersionHash([0xFF; 32]);
        conn.execute(
            "UPDATE retained_preimages SET last_captured_change_hash = ?1, \
             last_captured_version_hash = ?2, state = 'divergent' WHERE retained_id = 'ep0'",
            rusqlite::params![&bogus_hash.0[..], &bogus_version.0[..]],
        )
        .unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::DagRepresentationUnproven));
    }

    #[test]
    fn record_captured_change_refuses_a_change_hash_it_has_never_admitted() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let bogus_hash = ChangeHash([0xEE; 32]);
        let bogus_version = VersionHash([0xFF; 32]);
        let err = record_captured_change(&mut conn, "g", "ep0", bogus_hash, bogus_version, 0)
            .unwrap_err();
        assert!(matches!(err, RetainedObligationError::CapturedChangeVersionMismatch { .. }));
        // Refused, not silently applied.
        assert!(get(&conn, "g", "ep0").unwrap().unwrap().last_captured_change_hash.is_none());
    }

    /// The "wrong hand-off" the report describes: a real, admitted change
    /// paired with a version it never actually wrote must not be accepted
    /// just because both halves individually exist somewhere in this
    /// replica's state.
    #[test]
    fn record_captured_change_refuses_a_real_change_paired_with_an_unrelated_version() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let (hash, _actual_version_hash) = author_and_materialize(&conn, "g", 0xAB);
        let unrelated_version = VersionHash([0x11; 32]);
        let err =
            record_captured_change(&mut conn, "g", "ep0", hash, unrelated_version, 0).unwrap_err();
        assert!(matches!(err, RetainedObligationError::CapturedChangeVersionMismatch { .. }));
    }

    /// Critical-2 regression: a same-group change that genuinely writes the
    /// claimed version, but at a path unrelated to this obligation's own
    /// `original_path`, must be refused exactly like an unrelated version
    /// hash is -- version equality on an op found *somewhere* in the change
    /// is not proof about the specific object this obligation is retaining.
    /// Before the fix, `captured_change_actually_writes` accepted this: a
    /// same-group change writing the right version at the wrong path would
    /// later let `verify_durable_representation`'s leg 2 find a real `files`
    /// row for that *other* path and report the pairing durable, deleting
    /// bytes that were never captured anywhere.
    #[test]
    fn record_captured_change_refuses_a_same_group_change_writing_the_right_version_at_the_wrong_path(
    ) {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();

        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![0x42; 32]), size: 4 }],
            4,
            FileMeta {
                mtime_unix_nanos: 1,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        dag_store::put_file_version(&conn, "g", &version).unwrap();
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d1".into()),
            FolderGroupId("g".into()),
            vec![Op::Put {
                // Same group as "ep0", genuinely writes `version`, but at a
                // path that has nothing to do with `new_obligation`'s
                // `original_path` ("a/b.txt").
                path: SyncPath("completely/unrelated/path.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        dag_store::admit_change(&conn, &change, false).unwrap();
        let hash = change.compute_hash();

        let err = record_captured_change(&mut conn, "g", "ep0", hash, version.version_hash, 0)
            .unwrap_err();
        assert!(matches!(err, RetainedObligationError::CapturedChangeVersionMismatch { .. }));
        // Refused, not silently applied.
        assert!(get(&conn, "g", "ep0").unwrap().unwrap().last_captured_change_hash.is_none());
    }

    #[test]
    fn deletion_precondition_3c_conflict_copy_unproven_retains() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let fp = StabilityFingerprint([5u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();

        // A real, admitted change -- DAG representation genuinely durable --
        // but deliberately never materialized as a `files` row: nothing
        // outside this obligation's own record actually protects the
        // content yet.
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![9u8; 32]), size: 4 }],
            4,
            FileMeta {
                mtime_unix_nanos: 1,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        dag_store::put_file_version(&conn, "g", &version).unwrap();
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d1".into()),
            FolderGroupId("g".into()),
            vec![Op::Put {
                path: SyncPath("a/b.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        dag_store::admit_change(&conn, &change, false).unwrap();
        let hash = change.compute_hash();

        record_captured_change(&mut conn, "g", "ep0", hash, version.version_hash, 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::ConflictCopyUnproven));
    }

    /// Critical-3 regression: `index.rs`'s `upsert_file_in_tx` carries
    /// `authoring_change_hash` forward onto an upsert that supplies no fresh
    /// authoring hash of its own, so a path later overwritten with unrelated
    /// content can still carry a stale, no-longer-true `authoring_change_hash`.
    /// Column equality alone must not be treated as proof.
    #[test]
    fn critical3_stale_authoring_hash_on_unrelated_content_does_not_prove_durability() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let fp = StabilityFingerprint([8u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xAB);
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();

        // Simulate the carry-forward: the row still says `authoring_change_hash
        // = hash`, but its actual content columns now describe something
        // else entirely -- exactly what a later unrelated overwrite through
        // `upsert_file_in_tx`'s `authoring_blob.or(old_hash)` fallback would
        // leave behind.
        let unrelated_blocks_json =
            serde_json::to_string(&vec![BlockInfo { hash: vec![0x99; 32], offset: 0, size: 9 }])
                .unwrap();
        conn.execute(
            "UPDATE files SET blocks_json = ?1, size = 9 WHERE group_id = 'g' AND path = 'a/b.txt'",
            rusqlite::params![unrelated_blocks_json],
        )
        .unwrap();

        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();
        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::ConflictCopyUnproven));
    }

    /// The fourth precondition, in isolation: every other leg (grace,
    /// fingerprint, DAG representation, conflict-copy) satisfied, but
    /// `writer_exclusion.writer_exclusion_proven` returns `false` --
    /// exactly `NoWriterExclusionProof`, the only implementation reachable
    /// in production today (see its own doc comment). Retained-artifact
    /// auto-deletion must stay closed on this alone, the same way
    /// `local_recovery_only_is_never_automatically_deleted_even_once_
    /// everything_else_is_provable` proves for that other unconditional
    /// gate.
    #[test]
    fn writer_exclusion_unproven_retains_even_once_everything_else_is_provable() {
        let dir = tempfile::tempdir().unwrap();
        let custody_path = dir.path().join("custody-ep0");
        std::fs::write(&custody_path, b"retained preimage bytes").unwrap();
        let observed = FileIdentity::observe_path(&custody_path).unwrap();
        let filesystem_identity =
            yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(&observed);
        let custody_path_str = custody_path.to_string_lossy().into_owned();

        let mut conn = open();
        create(
            &conn,
            &NewObligation {
                retained_id: "ep0",
                originating_transaction_id: Some("txn-1"),
                source_epoch: Some(3),
                group_id: "g",
                original_path: "a/b.txt",
                custody_path: &custody_path_str,
                parent_directory_identity: b"parent-id-bytes",
                filesystem_identity: Some(&filesystem_identity),
                original_parent_basis_id: "basis-1",
            },
            0,
        )
        .unwrap();
        let fp = StabilityFingerprint([7u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xCE);
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        // Every other leg is satisfied (proven by the neighboring
        // `all_three_preconditions_satisfied_...` test using the exact same
        // fixture shape with `AlwaysProvenWriterExclusion` instead) -- only
        // `NoWriterExclusionProof` differs here.
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::WriterExclusionUnproven));

        // The gated forward driver must refuse identically, not merely the
        // pure decision function.
        let outcome = delete_if_eligible_unchecked(
            &mut conn,
            "g",
            "ep0",
            after_grace,
            fp,
            &NoWriterExclusionProof,
        )
        .unwrap();
        assert!(
            matches!(outcome, DeletionOutcome::Retained(RetentionReason::WriterExclusionUnproven)),
            "expected Retained(WriterExclusionUnproven), got {outcome:?}"
        );
        assert!(custody_path.exists(), "an unproven writer-exclusion decision must not unlink");
    }

    #[test]
    fn all_three_preconditions_satisfied_is_eligible_and_deletion_releases_the_dag_root() {
        // A real file at a real custody path is required now: eligibility
        // verifies the obligation's `filesystem_identity` against the
        // object actually observed at `custody_path`, not merely a
        // placeholder byte string.
        let dir = tempfile::tempdir().unwrap();
        let custody_path = dir.path().join("custody-ep0");
        std::fs::write(&custody_path, b"retained preimage bytes").unwrap();
        let observed = FileIdentity::observe_path(&custody_path).unwrap();
        let filesystem_identity =
            yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(&observed);
        let custody_path_str = custody_path.to_string_lossy().into_owned();

        let mut conn = open();
        create(
            &conn,
            &NewObligation {
                retained_id: "ep0",
                originating_transaction_id: Some("txn-1"),
                source_epoch: Some(3),
                group_id: "g",
                original_path: "a/b.txt",
                custody_path: &custody_path_str,
                parent_directory_identity: b"parent-id-bytes",
                filesystem_identity: Some(&filesystem_identity),
                original_parent_basis_id: "basis-1",
            },
            0,
        )
        .unwrap();
        let fp = StabilityFingerprint([6u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xCD);
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();

        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &AlwaysProvenWriterExclusion)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Eligible);

        // Phase one: preparing the intent must not touch disk yet.
        let prepared = delete_if_eligible_unchecked(
            &mut conn,
            "g",
            "ep0",
            after_grace,
            fp,
            &AlwaysProvenWriterExclusion,
        )
        .unwrap();
        let DeletionOutcome::UnlinkPending { custody_path: pending_path, .. } = prepared else {
            panic!("expected UnlinkPending, got {prepared:?}");
        };
        assert_eq!(pending_path, obligation.custody_path);
        assert!(custody_path.exists(), "the intent alone must not have unlinked anything");
        assert!(get(&conn, "g", "ep0").unwrap().is_some(), "the obligation row survives phase one");

        // Phase two: the real unlink, then finalizing.
        std::fs::remove_file(&custody_path).unwrap();
        let outcome =
            complete_deletion_after_unlink_unchecked(&mut conn, "g", "ep0", after_grace).unwrap();
        let DeletionOutcome::Deleted { custody_path: deleted_path } = outcome else {
            panic!("expected Deleted, got {outcome:?}");
        };
        assert_eq!(deleted_path, obligation.custody_path);
        assert!(get(&conn, "g", "ep0").unwrap().is_none());

        // The `full_payload` root `captured_authoring` registered is gone --
        // released on its behalf, not merely forgotten by this module.
        let remaining: i64 =
            conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn local_recovery_only_is_never_automatically_deleted_even_once_everything_else_is_provable() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let fp = StabilityFingerprint([7u8; 32]);
        record_late_write(&mut conn, "g", "ep0", fp, 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xEF);
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();
        mark_authorization_permanently_lost(&conn, "g", "ep0", 0).unwrap();
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();
        assert_eq!(obligation.state, ObligationState::LocalRecoveryOnly);

        let after_grace = grace_period_nanos() + 1;
        let decision =
            evaluate_deletion(&conn, &obligation, after_grace, fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::LocalRecoveryOnly));

        let outcome = delete_if_eligible_unchecked(
            &mut conn,
            "g",
            "ep0",
            after_grace,
            fp,
            &NoWriterExclusionProof,
        )
        .unwrap();
        assert!(matches!(outcome, DeletionOutcome::Retained(RetentionReason::LocalRecoveryOnly)));
        assert!(get(&conn, "g", "ep0").unwrap().is_some());
    }

    /// Critical-1 regression: a late write observed *after* a capture must
    /// invalidate that capture's binding, not merely update the fingerprint
    /// next to it. Before the fix, this exact sequence let
    /// `evaluate_deletion` validate the new fingerprint against the *old*
    /// capture's durability proof -- approving deletion of bytes that were
    /// never authored anywhere.
    #[test]
    fn critical1_late_write_after_capture_invalidates_the_stale_capture() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xAB);
        let stale_fp = StabilityFingerprint([1u8; 32]);
        record_late_write(&mut conn, "g", "ep0", stale_fp, 0).unwrap();
        record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 0).unwrap();

        // A stale handle writes again after this capture -- new bytes, new
        // fingerprint -- without a fresh capture ever being taken for them.
        let new_bytes_fp = StabilityFingerprint([2u8; 32]);
        let obligation = record_late_write(&mut conn, "g", "ep0", new_bytes_fp, 0).unwrap();

        // The stale capture's binding must be gone entirely, not merely
        // fingerprint-mismatched -- a caller that later (incorrectly)
        // re-observes `stale_fp` must still find nothing to validate
        // durability against.
        assert!(obligation.last_captured_change_hash.is_none());
        assert!(obligation.last_captured_version_hash.is_none());

        let after_grace = grace_period_nanos() + 1;
        let decision = evaluate_deletion(
            &conn,
            &obligation,
            after_grace,
            new_bytes_fp,
            &NoWriterExclusionProof,
        )
        .unwrap();
        assert_eq!(decision, DeletionDecision::Retain(RetentionReason::NoCapturedChange));

        // Even re-observing the stale fingerprint (the exploit's actual
        // shape: a caller re-runs quiescence, sees the old fingerprint
        // again transiently, and evaluates against it) still cannot reach
        // `Eligible`, since the captured-change pairing is gone regardless
        // of which fingerprint is presented.
        let decision_with_stale_fp =
            evaluate_deletion(&conn, &obligation, after_grace, stale_fp, &NoWriterExclusionProof)
                .unwrap();
        assert_eq!(
            decision_with_stale_fp,
            DeletionDecision::Retain(RetentionReason::FingerprintChanged)
        );
    }

    /// Critical-1 regression: before the fix, `record_late_write` and
    /// `record_captured_change` each read the obligation, decided what to
    /// write, and then wrote unconditionally as two separate autocommitting
    /// statements -- a window in which a worker's read could be stale by the
    /// time its write landed. Concretely: a worker reads the obligation and
    /// validates an *old* capture (`hash`/`version_hash`) against it, then
    /// pauses before its `UPDATE`; a second connection's late write commits
    /// in between, storing a fresh fingerprint and clearing the capture
    /// pairing; the first worker resumes and unconditionally writes the old
    /// capture back, leaving the row internally well-formed -- a new
    /// fingerprint paired with a capture that describes bytes nobody wrote
    /// anymore. Racing the two real connections against each other (now that
    /// each operation's read and write are one `IMMEDIATE` transaction) must
    /// never let that pairing happen: either the late write commits first
    /// and the capture attempt is refused as non-monotonic against the
    /// fresher clock it would otherwise overwrite, or the capture commits
    /// first and the late write -- which always applies; it does not
    /// validate against existing content -- unconditionally clears it
    /// afterward. Both interleavings converge on the same final state, never
    /// a torn one.
    #[test]
    fn critical1_race_late_write_vs_capture_never_pairs_a_stale_capture_with_a_newer_fingerprint() {
        use std::sync::{Arc, Barrier};

        for i in 0..12u8 {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("race.sqlite3");
            let mut conn_a = open_file_backed(&db_path);
            let mut conn_b = open_file_backed(&db_path);
            conn_a.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
            conn_b.busy_timeout(std::time::Duration::from_secs(5)).unwrap();

            create(&conn_a, &new_obligation("ep0", "g"), 0).unwrap();
            let (hash, version_hash) = author_and_materialize(&conn_a, "g", i);

            let barrier = Arc::new(Barrier::new(2));
            let barrier2 = Arc::clone(&barrier);
            let new_fp = StabilityFingerprint([i.wrapping_add(50); 32]);

            let capturer = std::thread::spawn(move || {
                barrier2.wait();
                record_captured_change(&mut conn_a, "g", "ep0", hash, version_hash, 10)
            });

            barrier.wait();
            let late_write_result = record_late_write(&mut conn_b, "g", "ep0", new_fp, 20);
            let capture_result = capturer.join().unwrap();

            // A third legitimate interleaving on a sufficiently slow host:
            // the busy timeout set above still expired before one side of
            // the race got the write lock at all -- see
            // `is_database_busy_error`'s doc. That side's operation simply
            // never ran; it is not a torn state, and the other side must
            // still have run to completion alone.
            if is_database_busy_error(&late_write_result) {
                // The late write never ran, so nothing else was contending
                // for the lock -- the capture must have gone through.
                capture_result.unwrap_or_else(|e| {
                    panic!(
                        "iteration {i}: late write lost the lock race but capture also \
                         failed: {e:?}"
                    )
                });
                let obligation = get(&conn_b, "g", "ep0").unwrap().unwrap();
                // Proves the late write left no trace at all, not a partial
                // one: the fingerprint `create` never set is still absent,
                // and the capture's hash/version pair landed together,
                // exactly as `record_captured_change` writes them.
                assert_eq!(
                    obligation.last_fingerprint, None,
                    "iteration {i}: a late write that never ran must not have touched the \
                     fingerprint"
                );
                assert_eq!(obligation.last_captured_change_hash, Some(hash));
                assert_eq!(obligation.last_captured_version_hash, Some(version_hash));
                continue;
            }
            if is_database_busy_error(&capture_result) {
                // The capture never ran, so nothing else was contending for
                // the lock -- the late write, which never validates against
                // existing content, must always apply regardless.
                late_write_result.unwrap_or_else(|e| {
                    panic!(
                        "iteration {i}: capture lost the lock race but late write also \
                         failed: {e:?}"
                    )
                });
                let obligation = get(&conn_b, "g", "ep0").unwrap().unwrap();
                assert_eq!(
                    obligation.last_fingerprint,
                    Some(new_fp),
                    "iteration {i}: the late write's fingerprint must be the one on record"
                );
                assert!(
                    obligation.last_captured_change_hash.is_none(),
                    "iteration {i}: a capture that never ran must leave no captured pairing \
                     behind"
                );
                continue;
            }

            match capture_result {
                Ok(_) => {}
                Err(RetainedObligationError::NonMonotonicTime { .. }) => {}
                other => panic!("iteration {i}: unexpected capture outcome: {other:?}"),
            }
            // The late write never validates against existing content, so it
            // must always apply regardless of interleaving.
            late_write_result.unwrap_or_else(|e| {
                panic!("iteration {i}: late write must always apply, got {e:?}")
            });

            // Whichever order the two transactions actually serialized in,
            // the row must never pair the *old* capture with the *new*
            // fingerprint -- the late write always wins the pairing, either
            // directly or by having already invalidated the capture's
            // premise before the capture could commit.
            let obligation = get(&conn_b, "g", "ep0").unwrap().unwrap();
            assert_eq!(
                obligation.last_fingerprint,
                Some(new_fp),
                "iteration {i}: the late write's fingerprint must be the one on record"
            );
            assert!(
                obligation.last_captured_change_hash.is_none(),
                "iteration {i}: a capture of the pre-late-write bytes must never survive \
                 paired with the post-late-write fingerprint"
            );
        }
    }

    /// Critical-2 regression: the eligibility decision and its consequences
    /// (retention-root release, row deletion) must be one atomic unit. Races
    /// two real connections to the same file-backed database against each
    /// other repeatedly; every interleaving must land in one of exactly two
    /// consistent outcomes, never a deletion that proceeded past a late
    /// write it should have retained for.
    #[test]
    fn critical2_concurrent_late_write_races_delete_and_never_produces_a_torn_state() {
        use std::sync::{Arc, Barrier};

        for i in 0..12u8 {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("race.sqlite3");
            let mut conn_a = open_file_backed(&db_path);
            let mut conn_b = open_file_backed(&db_path);
            conn_a.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
            conn_b.busy_timeout(std::time::Duration::from_secs(5)).unwrap();

            // A real file at a real custody path: eligibility verifies the
            // obligation's `filesystem_identity` against the object
            // actually observed at `custody_path`.
            let custody_path = dir.path().join(format!("custody-ep0-{i}"));
            std::fs::write(&custody_path, [i; 16]).unwrap();
            let observed = FileIdentity::observe_path(&custody_path).unwrap();
            let filesystem_identity =
                yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(&observed);
            let custody_path_str = custody_path.to_string_lossy().into_owned();
            create(
                &conn_a,
                &NewObligation {
                    retained_id: "ep0",
                    originating_transaction_id: Some("txn-1"),
                    source_epoch: Some(3),
                    group_id: "g",
                    original_path: "a/b.txt",
                    custody_path: &custody_path_str,
                    parent_directory_identity: b"parent-id-bytes",
                    filesystem_identity: Some(&filesystem_identity),
                    original_parent_basis_id: "basis-1",
                },
                0,
            )
            .unwrap();
            let (hash, version_hash) = author_and_materialize(&conn_a, "g", i);
            let fp = StabilityFingerprint([i; 32]);
            record_late_write(&mut conn_a, "g", "ep0", fp, 0).unwrap();
            record_captured_change(&mut conn_a, "g", "ep0", hash, version_hash, 0).unwrap();

            let after_grace = grace_period_nanos() + 1;
            let barrier = Arc::new(Barrier::new(2));
            let barrier2 = Arc::clone(&barrier);
            let new_fp = StabilityFingerprint([i.wrapping_add(100); 32]);

            let deleter = std::thread::spawn(move || {
                barrier2.wait();
                delete_if_eligible_unchecked(
                    &mut conn_a,
                    "g",
                    "ep0",
                    after_grace,
                    fp,
                    &NoWriterExclusionProof,
                )
            });

            barrier.wait();
            let late_write_result = record_late_write(&mut conn_b, "g", "ep0", new_fp, after_grace);
            let delete_result = deleter.join().unwrap();

            // A third legitimate interleaving on a sufficiently slow host:
            // the busy timeout set above still expired before one side of
            // the race got the write lock at all -- see
            // `is_database_busy_error`'s doc. That side's operation simply
            // never ran, so the other side ran alone, against whichever
            // state actually existed at that point -- never a torn one.
            if is_database_busy_error(&late_write_result) {
                // The late write never ran, so nothing else was contending
                // for the deleter's lock -- its own decision, made against
                // the unchanged pre-race state (already durable and past
                // grace, by this test's own setup), must go through exactly
                // as if there were no contention at all.
                match delete_result {
                    Ok(outcome) => assert!(
                        matches!(outcome, DeletionOutcome::UnlinkPending { .. }),
                        "iteration {i}: a late write that never ran must not have blocked a \
                         deletion the unchanged pre-race state already made eligible, got \
                         {outcome:?}"
                    ),
                    Err(e) => panic!(
                        "iteration {i}: late write lost the lock race but delete also \
                         failed: {e:?}"
                    ),
                }
                continue;
            }
            if is_database_busy_error(&delete_result) {
                // The deleter never ran, so nothing else was contending for
                // the late write's lock -- it must have applied, and nothing
                // can have been deleted out from under it.
                late_write_result.unwrap_or_else(|e| {
                    panic!(
                        "iteration {i}: delete lost the lock race but late write also \
                         failed: {e:?}"
                    )
                });
                let obligation = get(&conn_b, "g", "ep0").unwrap();
                assert!(
                    obligation.is_some(),
                    "iteration {i}: a delete that never ran must not have removed the row"
                );
                assert_eq!(
                    obligation.unwrap().last_fingerprint,
                    Some(new_fp),
                    "iteration {i}: the late write's fingerprint must be the one on record"
                );
                continue;
            }

            match (late_write_result, delete_result) {
                // The late write landed first (whether before the deleter's
                // `IMMEDIATE` transaction began, or serialized ahead of it) --
                // the deleter's own re-evaluation inside its transaction must
                // see the fresh state and retain, never delete.
                (Ok(_), Ok(outcome)) => {
                    assert!(
                        matches!(outcome, DeletionOutcome::Retained(_)),
                        "iteration {i}: a late write that landed before the delete decision \
                         must force retain, got {outcome:?}"
                    );
                }
                // The delete prepared its intent first, so the late write's
                // own `reject_deletion_in_progress` guard refuses it --
                // never silently applying against a row a deletion is
                // already committed to.
                (
                    Err(RetainedObligationError::DeletionInProgress { .. }),
                    Ok(DeletionOutcome::UnlinkPending { .. }),
                ) => {}
                other => panic!("iteration {i}: unexpected interleaving outcome: {other:?}"),
            }
        }
    }

    #[test]
    fn a_late_write_after_local_recovery_only_is_refused_terminal() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        mark_authorization_permanently_lost(&conn, "g", "ep0", 0).unwrap();
        let err = record_late_write(&mut conn, "g", "ep0", StabilityFingerprint([0u8; 32]), 0)
            .unwrap_err();
        assert!(matches!(err, RetainedObligationError::Terminal { .. }));
    }

    #[test]
    fn an_undecodable_state_is_a_hard_error_never_treated_as_safe_to_delete() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        conn.execute(
            "UPDATE retained_preimages SET state = 'not_a_real_state' WHERE retained_id = 'ep0'",
            [],
        )
        .unwrap();
        let err = get(&conn, "g", "ep0").unwrap_err();
        assert!(matches!(err, SyncSqliteError::CorruptState(_)));
        // The gated deletion path propagates the same failure rather than
        // reaching any branch that could return `Eligible`.
        let err = delete_if_eligible_unchecked(
            &mut conn,
            "g",
            "ep0",
            i64::MAX,
            StabilityFingerprint([0; 32]),
            &NoWriterExclusionProof,
        )
        .unwrap_err();
        assert!(matches!(err, RetainedObligationError::Sync(SyncSqliteError::CorruptState(_))));
    }

    #[test]
    fn capacity_degraded_never_changes_state_or_the_grace_clock() {
        let conn = open();
        let before = create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let after = set_capacity_degraded(&conn, "g", "ep0", true, 500).unwrap();
        assert!(after.capacity_degraded);
        assert_eq!(after.state, before.state);
        assert_eq!(after.retain_until_unix_nanos, before.retain_until_unix_nanos);
    }

    #[test]
    fn gated_entry_point_refuses_while_execution_is_disabled() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 0).unwrap();
        let err = delete_if_eligible(
            &mut conn,
            "g",
            "ep0",
            i64::MAX,
            StabilityFingerprint([0; 32]),
            &NoWriterExclusionProof,
        )
        .unwrap_err();
        assert!(matches!(err, RetainedObligationError::NotEnabled));
    }

    /// Medium: an out-of-order `record_late_write` must not overwrite a
    /// newer deadline with an older one.
    #[test]
    fn record_late_write_refuses_a_now_older_than_the_obligations_own_clock() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        record_late_write(&mut conn, "g", "ep0", StabilityFingerprint([1u8; 32]), 5_000).unwrap();
        let err = record_late_write(&mut conn, "g", "ep0", StabilityFingerprint([2u8; 32]), 4_999)
            .unwrap_err();
        assert!(matches!(err, RetainedObligationError::NonMonotonicTime { .. }));
        // Refused, not applied -- the row still reflects the earlier, later
        // call.
        let obligation = get(&conn, "g", "ep0").unwrap().unwrap();
        assert_eq!(obligation.retain_until_unix_nanos, 5_000 + grace_period_nanos());
    }

    /// Same guarantee for `record_captured_change` -- the other writer of
    /// `retain_until_unix_nanos`.
    #[test]
    fn record_captured_change_refuses_a_now_older_than_the_obligations_own_clock() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        record_late_write(&mut conn, "g", "ep0", StabilityFingerprint([1u8; 32]), 5_000).unwrap();
        let (hash, version_hash) = author_and_materialize(&conn, "g", 0xAB);
        let err =
            record_captured_change(&mut conn, "g", "ep0", hash, version_hash, 4_999).unwrap_err();
        assert!(matches!(err, RetainedObligationError::NonMonotonicTime { .. }));
    }

    /// And for the deletion entry point itself -- a caller must not be able
    /// to make the grace-window check pass by supplying a `now` older than
    /// what this obligation already recorded.
    #[test]
    fn delete_if_eligible_unchecked_refuses_a_now_older_than_the_obligations_own_clock() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        record_late_write(&mut conn, "g", "ep0", StabilityFingerprint([1u8; 32]), 5_000).unwrap();
        let err = delete_if_eligible_unchecked(
            &mut conn,
            "g",
            "ep0",
            4_999,
            StabilityFingerprint([1u8; 32]),
            &NoWriterExclusionProof,
        )
        .unwrap_err();
        assert!(matches!(err, RetainedObligationError::NonMonotonicTime { .. }));
    }

    /// Documents the cross-module string contract this module's doc comment
    /// describes in prose -- if `captured_authoring`'s own constant ever
    /// changes, this test (not just a comment) catches the mismatch.
    #[test]
    fn releases_the_same_owner_kind_captured_authoring_registers_under() {
        assert_eq!(CAPTURED_AUTHORING_RETENTION_OWNER_KIND, "captured_authoring");
    }

    fn root_still_registered(conn: &Connection, retained_id: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM dag_retention_roots \
             WHERE owner_kind = ?1 AND owner_id = ?2)",
            rusqlite::params![CAPTURED_AUTHORING_RETENTION_OWNER_KIND, retained_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn register_captured_authoring_root(conn: &Connection, retained_id: &str, group_id: &str) {
        dag_store::register_retention_root(
            conn,
            CAPTURED_AUTHORING_RETENTION_OWNER_KIND,
            retained_id,
            group_id,
            &ChangeHash([9u8; 32]),
            RetentionClass::FullPayload,
        )
        .unwrap();
    }

    /// A root whose `retained_id` still names a live obligation must survive
    /// a sweep no matter that obligation's own state or eligibility -- the
    /// sweep never substitutes its own judgment for `delete_if_eligible`'s.
    #[test]
    fn sweep_retains_a_root_whose_obligation_exists_and_is_not_eligible() {
        let mut conn = open();
        create(&conn, &new_obligation("ep0", "g"), 1_000).unwrap();
        register_captured_authoring_root(&conn, "ep0", "g");

        // Far past any grace window -- proves retention here is because the
        // obligation exists, not because the sweep ran too soon to tell.
        let report = sweep_orphaned_captured_authoring_roots_unchecked(
            &mut conn,
            1_000 + orphan_root_grace_period_nanos() * 100,
        )
        .unwrap();

        assert_eq!(
            report,
            OrphanRootSweepReport {
                released: 0,
                retained_live_obligation: 1,
                retained_within_grace: 0,
            }
        );
        assert!(root_still_registered(&conn, "ep0"));
    }

    /// A root whose obligation was never created at all (the lifecycle
    /// described by item 20.41 -- never driven, or removed some other way)
    /// is released once it has aged past the window, and its change becomes
    /// prunable again.
    #[test]
    fn sweep_releases_a_root_whose_obligation_is_genuinely_gone() {
        let mut conn = open();
        register_captured_authoring_root(&conn, "ep0", "g");
        // Deliberately no `create` call for "ep0" -- this obligation's
        // lifecycle was never driven.

        let far_future =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64
                + orphan_root_grace_period_nanos() * 100;
        let report =
            sweep_orphaned_captured_authoring_roots_unchecked(&mut conn, far_future).unwrap();

        assert_eq!(
            report,
            OrphanRootSweepReport {
                released: 1,
                retained_live_obligation: 0,
                retained_within_grace: 0,
            }
        );
        assert!(
            !root_still_registered(&conn, "ep0"),
            "the orphaned root must be released, unblocking pruning of its change"
        );
    }

    /// The window case: a root registered with no obligation yet must not be
    /// released while it is still plausibly mid-registration by an
    /// orchestrator that creates the root and the obligation as two separate
    /// steps -- and the obligation this window protects can still be
    /// created afterward without ever having lost its root.
    #[test]
    fn sweep_does_not_release_an_obligation_less_root_within_the_grace_window() {
        let mut conn = open();
        register_captured_authoring_root(&conn, "ep0", "g");

        let just_registered =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let report =
            sweep_orphaned_captured_authoring_roots_unchecked(&mut conn, just_registered).unwrap();

        assert_eq!(
            report,
            OrphanRootSweepReport {
                released: 0,
                retained_live_obligation: 0,
                retained_within_grace: 1,
            }
        );
        assert!(root_still_registered(&conn, "ep0"));

        // The orchestrator now reaches its second step: the obligation this
        // root was always for is created, having never lost its root.
        create(&conn, &new_obligation("ep0", "g"), just_registered).unwrap();
        assert!(get(&conn, "g", "ep0").unwrap().is_some());
        assert!(root_still_registered(&conn, "ep0"));
    }

    /// The `EXECUTION_ENABLED`-gated entry point refuses while the shared
    /// filesystem-transaction-engine gate stays closed, matching every other
    /// mutating entry point in this module.
    #[test]
    fn the_sweep_gated_entry_point_refuses_while_execution_is_disabled() {
        let mut conn = open();
        register_captured_authoring_root(&conn, "ep0", "g");
        let err = sweep_orphaned_captured_authoring_roots(&mut conn, 1_000).unwrap_err();
        assert!(matches!(err, RetainedObligationError::NotEnabled));
        assert!(root_still_registered(&conn, "ep0"));
    }
}
