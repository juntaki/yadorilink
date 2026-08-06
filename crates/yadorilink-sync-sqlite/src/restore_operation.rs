//! `RestoreOperationRepository` owns the `restore_operations` table -- the
//! crash-safe journal of a restore whose replacement file and index update
//! have not both been durably committed yet.
//!
//! Moved from `yadorilink-sync-core::repository::restore_operation` (Phase
//! 7D-9E) -- a plain `Arc<SyncDatabase>`-backed repository with no
//! `SyncState` coupling of its own; `RestoreOperation`/`RestoreCommitOutcome`/
//! `RestoreOperationState` already live in
//! `yadorilink_filesystem_sync::materialization_types` (Phase 7D-9C), so this
//! move only relocates the SQL half, not the value types.
//!
//! `record_restore_operation_emitting_change` (`restore_operations` + DAG
//! change emission) and `commit_restore_operation` (`restore_operations` +
//! `files` + DAG `applied` state) are two of the ownership doc's "Known
//! cross-cluster atomic operations" -- reaching directly into `dag_store`
//! free functions and raw `files`-table SQL inside their own transaction,
//! exactly as
//! [`crate::handoff_lease::HandoffLeaseRepository::record_handoff_lease_atomic`]
//! already reaches into `files` for its own atomic pin. Decomposing either
//! into separate repository calls would reopen the crash window the single
//! transaction exists to close.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::dag_store::{self, ChangeEmitter};
use crate::error::SyncSqliteError;
use crate::file_index::{apply_local_meta_columns_in_tx, upsert_file_in_tx};
use yadorilink_filesystem_sync::materialization_types::{
    RestoreCommitOutcome, RestoreOperation, RestoreOperationState,
};
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;
use yadorilink_sqlite_runtime::SyncDatabase;

// Deliberately a private, module-local duplicate rather than a shared helper
// across the crate boundary -- same reasoning as `dirty_path.rs`'s/
// `file_index.rs`'s own identical `now_unix_nanos` (see their doc comments).
fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

pub struct RestoreOperationRepository {
    database: Arc<SyncDatabase>,
}

impl RestoreOperationRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    pub fn record_restore_operation(
        &self,
        operation: &RestoreOperation,
    ) -> Result<(), SyncSqliteError> {
        let blocks_json = serde_json::to_string(&operation.record.blocks)?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO restore_operations
                 (operation_id, group_id, path, target_version_seq,
                  expected_current_version_seq, state, size,
                  mtime_unix_nanos, blocks_json, origin_device_id,
                  authoring_change_hash, created_at_unix_nanos,
                  record_kind, symlink_target, symlink_out_of_root, exec_bit)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                rusqlite::params![
                    operation.operation_id,
                    operation.group_id,
                    operation.path,
                    operation.target_version_seq,
                    operation.expected_current_version_seq,
                    operation.state.as_db_str(),
                    operation.record.size as i64,
                    operation.record.mtime_unix_nanos,
                    &blocks_json,
                    operation.origin_device_id,
                    operation.authoring_change_hash.as_ref().map(|hash| hash.0.as_slice()),
                    now_unix_nanos(),
                    operation.meta.record_kind.as_db_str(),
                    operation.meta.symlink_target.as_deref(),
                    operation.meta.symlink_out_of_root,
                    operation.meta.exec_bit,
                ],
            )?;
            Ok(())
        })
    }

    /// Authors the restore's `Put`, stores its exact `FileVersion`, and
    /// persists the crash-recovery journal in one transaction. The disk
    /// replacement happens only after this returns, so every recovery path
    /// already has the durable author identity it must publish.
    ///
    /// `auth` is the already-resolved authorization stamp for `group_id` --
    /// see [`crate::file_index::FileIndexRepository::upsert_file_emitting_change`]'s
    /// doc comment for why it is a parameter here rather than resolved
    /// internally (`local_change_auth_provider` lives on `SyncState`, not on
    /// any repository).
    pub fn record_restore_operation_emitting_change(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        auth: ChangeAuth,
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let path = SyncPath(operation.path.clone());
            let change = dag_store::emit_local_change(
                tx,
                &operation.group_id,
                vec![Op::Put { path, version: version.version_hash, origin: PutOrigin::Direct }],
                auth,
                emitter,
            )?;
            dag_store::put_file_version(tx, &operation.group_id, version)?;
            let change_hash = change.compute_hash();
            // The direct restore is not on disk/index yet. Keep the change
            // eligible for ordinary DAG projection until commit below marks
            // it applied. If reconstruction fails or the process crashes,
            // discarding the journal cannot strand an applied=true change
            // whose content was never published.
            tx.execute(
                "UPDATE changes SET applied = 0 WHERE change_hash = ?1",
                [&change_hash.0[..]],
            )?;
            let blocks_json = serde_json::to_string(&operation.record.blocks)?;
            tx.execute(
                "INSERT INTO restore_operations
                 (operation_id, group_id, path, target_version_seq,
                  expected_current_version_seq, state, size, mtime_unix_nanos,
                  blocks_json, origin_device_id,
                  authoring_change_hash, created_at_unix_nanos,
                  record_kind, symlink_target, symlink_out_of_root, exec_bit)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                rusqlite::params![
                    operation.operation_id,
                    operation.group_id,
                    operation.path,
                    operation.target_version_seq,
                    operation.expected_current_version_seq,
                    operation.state.as_db_str(),
                    operation.record.size as i64,
                    operation.record.mtime_unix_nanos,
                    blocks_json,
                    operation.origin_device_id,
                    change_hash.0.as_slice(),
                    now_unix_nanos(),
                    operation.meta.record_kind.as_db_str(),
                    operation.meta.symlink_target.as_deref(),
                    operation.meta.symlink_out_of_root,
                    operation.meta.exec_bit,
                ],
            )?;
            Ok(change_hash)
        })
    }

    pub fn mark_restore_disk_committed(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE restore_operations SET state = 'disk_committed' WHERE operation_id = ?1",
                [operation_id],
            )?)
        })?;
        if changed == 0 {
            return Err(SyncSqliteError::CorruptState(format!(
                "restore operation disappeared before disk commit: {operation_id}"
            )));
        }
        Ok(())
    }

    pub fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT operation_id, group_id, path, target_version_seq, state,
                        size, mtime_unix_nanos, blocks_json, origin_device_id,
                        expected_current_version_seq, authoring_change_hash,
                        record_kind, symlink_target, symlink_out_of_root, exec_bit
                 FROM restore_operations WHERE group_id = ?1
                 ORDER BY created_at_unix_nanos, operation_id",
            )?;
            let rows = stmt.query_map([group_id], restore_operation_from_row)?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    pub fn discard_restore_operation(&self, operation_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM restore_operations WHERE operation_id = ?1", [operation_id])?;
            Ok(())
        })
    }

    /// Atomically publishes the exact journaled version and removes its
    /// recovery marker. A second recovery pass observes no row and therefore
    /// cannot append another version.
    pub fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let operation = tx
                .query_row(
                    "SELECT operation_id, group_id, path, target_version_seq, state,
                            size, mtime_unix_nanos, blocks_json, origin_device_id,
                            expected_current_version_seq, authoring_change_hash,
                            record_kind, symlink_target, symlink_out_of_root, exec_bit
                     FROM restore_operations WHERE operation_id = ?1",
                    [operation_id],
                    restore_operation_from_row,
                )
                .optional()?;
            let Some(operation) = operation else {
                return Ok(RestoreCommitOutcome::Missing);
            };
            let current_version_seq: Option<i64> = tx
                .query_row(
                    "SELECT version_seq FROM files
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![operation.group_id, operation.path],
                    |row| row.get(0),
                )
                .optional()?;
            if current_version_seq != operation.expected_current_version_seq {
                return Ok(RestoreCommitOutcome::Superseded);
            }
            upsert_file_in_tx(
                tx,
                &operation.group_id,
                &operation.record,
                &operation.origin_device_id,
                operation.authoring_change_hash.as_ref(),
            )?;
            // The atomic, in-transaction counterpart to `upsert_file_in_tx`
            // every other local content emission already applies its own
            // `LocalFileMetaColumns` through -- without this, a restored
            // symlink or executable version would recreate the correct
            // bytes/link on disk (see `restore_to_version_inner`'s own
            // record-kind dispatch) while the `current` row stayed
            // classified as whatever it was before the restore.
            apply_local_meta_columns_in_tx(
                tx,
                &operation.group_id,
                &operation.path,
                &operation.meta,
            )?;
            if let Some(author) = operation.authoring_change_hash.as_ref() {
                let encoded: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT encoded FROM changes WHERE change_hash = ?1",
                        [&author.0[..]],
                        |row| row.get(0),
                    )
                    .optional()?;
                let change = encoded
                    .as_deref()
                    .map(Change::from_wire_bytes)
                    .transpose()
                    .map_err(|error| {
                        SyncSqliteError::CorruptState(format!(
                            "restore authoring change cannot be decoded: {error}"
                        ))
                    })?
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
                            "restore operation {} references missing authoring change {}",
                            operation.operation_id,
                            author.to_hex()
                        ))
                    })?;
                let has_pending_derived_copy = change
                    .ops
                    .iter()
                    .any(|op| matches!(op, Op::Put { origin: PutOrigin::ConflictCopy { .. }, .. }));
                if !has_pending_derived_copy {
                    dag_store::mark_applied(tx, author)?;
                }
            }
            tx.execute("DELETE FROM restore_operations WHERE operation_id = ?1", [operation_id])?;
            Ok(RestoreCommitOutcome::Committed(operation.record))
        })
    }
}

pub(crate) fn restore_operation_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RestoreOperation> {
    let blocks_json: String = row.get(7)?;
    let blocks = serde_json::from_str(&blocks_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let state_text: String = row.get(4)?;
    let state = RestoreOperationState::from_db_str(&state_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, error.into())
    })?;
    let path: String = row.get(2)?;
    Ok(RestoreOperation {
        operation_id: row.get(0)?,
        group_id: row.get(1)?,
        path: path.clone(),
        target_version_seq: row.get(3)?,
        expected_current_version_seq: row.get(9)?,
        state,
        record: FileRecord {
            path,
            size: row.get::<_, i64>(5)? as u64,
            mtime_unix_nanos: row.get(6)?,
            blocks,
            deleted: false,
        },
        origin_device_id: row.get(8)?,
        authoring_change_hash: row
            .get::<_, Option<Vec<u8>>>(10)?
            .map(|bytes| {
                bytes.try_into().map(ChangeHash).map_err(|bytes: Vec<u8>| {
                    rusqlite::Error::FromSqlConversionFailure(
                        10,
                        rusqlite::types::Type::Blob,
                        format!("invalid authoring change hash length: {}", bytes.len()).into(),
                    )
                })
            })
            .transpose()?,
        meta: LocalFileMetaColumns {
            record_kind: RecordKind::from_db_str(&row.get::<_, String>(11)?),
            symlink_target: row.get(12)?,
            symlink_out_of_root: row.get(13)?,
            exec_bit: row.get(14)?,
        },
    })
}
