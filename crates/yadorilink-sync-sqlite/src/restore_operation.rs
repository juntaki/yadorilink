//! `RestoreOperationRepository` owns the `restore_operations` table -- the
//! crash-safe journal of a restore whose replacement file and index update
//! have not both been durably committed yet.
//! `record_restore_operation_emitting_change` (`restore_operations` + DAG
//! change emission) and `commit_restore_operation` (`restore_operations` +
//! `files` + DAG state) are two of the ownership doc's "Known
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
use crate::materialization_state::MaterializationStateRepository;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, MaterializationState};
use yadorilink_replica_domain::session_state::{
    RestoreCommitOutcome, RestoreOperation, RestoreOperationState,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

// Deliberately a private, module-local duplicate rather than a shared helper
// across the crate boundary -- same reasoning as `dirty_path.rs`'s/
// `file_index.rs`'s own identical `now_unix_nanos` (see their doc comments).
fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

/// Where a recorded restore's entry is written: by the restore itself at
/// its own path, or by the ordinary projection, wherever the namespace
/// places it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePlacement {
    InPlace,
    Projection,
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
                  record_kind, symlink_target, symlink_out_of_root, unix_mode, xattrs_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
                    crate::file_index::encode_unix_mode_column(operation.meta.unix_mode),
                    crate::file_index::encode_xattrs_column(&operation.meta.xattrs),
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
    ///
    /// `permit` is verified inside the transaction, so a restore whose root
    /// was lost after admission authors no change and journals nothing.
    pub fn record_restore_operation_emitting_change(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
    ) -> Result<ChangeHash, SyncSqliteError> {
        self.record_restore(operation, version, emitter, permit, None).map(|(hash, _)| hash)
    }

    /// Authors the restore's `Put` as
    /// [`Self::record_restore_operation_emitting_change`] does, and decides
    /// in the same transaction whether the restore writes its entry itself.
    ///
    /// It does when `disk_allows_in_place` (the caller's reading of the
    /// disk: no synced file or symlink is an ancestor, and nothing of the
    /// other shape occupies the path) and the namespace, with this change
    /// admitted, keeps the entry at its own path. Only then is the journal
    /// row written. Otherwise the ordinary projection places the entry --
    /// the obligation the change opened drives it -- and there is no
    /// journal row at all: no instant exists at which a crash could leave
    /// startup recovery a row for a write that was never going to happen.
    pub fn record_restore_placing(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
        disk_allows_in_place: bool,
    ) -> Result<(ChangeHash, RestorePlacement), SyncSqliteError> {
        self.record_restore(operation, version, emitter, permit, Some(disk_allows_in_place))
    }

    fn record_restore(
        &self,
        operation: &RestoreOperation,
        version: &FileVersion,
        emitter: &ChangeEmitter,
        permit: &RootCommitPermit,
        disk_allows_in_place: Option<bool>,
    ) -> Result<(ChangeHash, RestorePlacement), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            let path = SyncPath(operation.path.clone());
            let change = dag_store::emit_local_change(
                tx,
                &operation.group_id,
                vec![Op::Put { path, version: version.version_hash, origin: PutOrigin::Direct }],
                emitter,
            )?;
            dag_store::put_file_version(tx, &operation.group_id, version)?;
            let change_hash = change.compute_hash();
            let placement = match disk_allows_in_place {
                None => RestorePlacement::InPlace,
                Some(false) => RestorePlacement::Projection,
                Some(true) => {
                    use crate::desired_state::{desired_path_state, DesiredPathState};
                    let desired =
                        desired_path_state(tx, &operation.group_id, &operation.path)?;
                    if matches!(
                        (version.meta.record_kind, desired),
                        (RecordKind::Directory, DesiredPathState::ExplicitDirectory { .. })
                            | (
                                RecordKind::File | RecordKind::Symlink,
                                DesiredPathState::Entry { .. }
                            )
                    ) {
                        RestorePlacement::InPlace
                    } else {
                        RestorePlacement::Projection
                    }
                }
            };
            if placement == RestorePlacement::Projection {
                return Ok((change_hash, placement));
            }
            // The restored content is not on disk yet. What keeps that
            // visible is the restore journal row written just below plus the
            // projection obligation `emit_local_change` already bumped for
            // this path -- not a flag on the change. A crash before the disk
            // write leaves both, and recovery replays from them; discarding
            // the journal cannot strand a change claiming content that was
            // never published, because nothing claims it.
            let blocks_json = serde_json::to_string(&operation.record.blocks)?;
            tx.execute(
                "INSERT INTO restore_operations
                 (operation_id, group_id, path, target_version_seq,
                  expected_current_version_seq, state, size, mtime_unix_nanos,
                  blocks_json, origin_device_id,
                  authoring_change_hash, created_at_unix_nanos,
                  record_kind, symlink_target, symlink_out_of_root, unix_mode, xattrs_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
                    crate::file_index::encode_unix_mode_column(operation.meta.unix_mode),
                    crate::file_index::encode_xattrs_column(&operation.meta.xattrs),
                ],
            )?;
            Ok((change_hash, placement))
        })
    }

    pub fn mark_restore_disk_committed(
        &self,
        operation_id: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
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
                        record_kind, symlink_target, symlink_out_of_root, unix_mode, xattrs_json
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
    ///
    /// Two callers reach this, and they are not the same kind of writer.
    ///
    /// The LIVE restore performed the disk write itself, under this path's
    /// lock, having bumped the mutation fence to a known epoch first. It
    /// passes that epoch as `wrote_under_mutation_generation`, and its
    /// proof is published by CASing against it -- so if anything touched
    /// the path in between, this attempt no longer knows what is on disk
    /// and publishes nothing at all, journal row included. Routing it
    /// through the external-adoption API instead (which mints a FRESH
    /// epoch on its way to recording the write) is what made the restore's
    /// own epoch unusable the moment it was recorded, and left the proof
    /// with no version besides.
    ///
    /// STARTUP RECOVERY did not write anything. It found a journal row, a
    /// process that died somewhere around the rename, and disk bytes it
    /// re-verified against the journaled version under the path's lock.
    /// There is no epoch it could CAS against -- the journal does not
    /// persist one -- so it passes `None` and adopts what it verified,
    /// minting an epoch for it, exactly as an external observation does.
    /// Its proof carries the same exact version either way.
    ///
    /// Both lanes pass the permit of the `LinkOperation` they hold, and it
    /// is verified inside this transaction, before anything is written: a
    /// root lost between the write and this commit publishes no row, no
    /// proof, and leaves the journal entry standing for recovery.
    pub fn commit_restore_operation(
        &self,
        operation_id: &str,
        identity: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
        wrote_under_mutation_generation: Option<i64>,
        permit: &RootCommitPermit,
    ) -> Result<RestoreCommitOutcome, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            permit.verify()?;
            let operation = tx
                .query_row(
                    "SELECT operation_id, group_id, path, target_version_seq, state,
                            size, mtime_unix_nanos, blocks_json, origin_device_id,
                            expected_current_version_seq, authoring_change_hash,
                            record_kind, symlink_target, symlink_out_of_root, unix_mode, xattrs_json
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
            // Checked HERE, before this transaction writes anything, and
            // not only by the CAS further down. `write_immediate` commits
            // whatever its closure returns `Ok` for, so an early return
            // taken after the row upsert below would commit that upsert:
            // the path would advance to the restored version with no proof
            // behind it, carrying forward whatever `materialization_state`
            // the row it superseded had -- the unprovable claim this whole
            // module exists to make unreachable -- while the journal entry
            // it left standing named a version sequence that no longer
            // matched, so no later attempt could commit it either.
            //
            // A read here is conclusive for the whole transaction, not
            // merely a hint: `BEGIN IMMEDIATE` takes SQLite's write lock at
            // the start, so no other writer can advance this fence until
            // this transaction ends.
            if let Some(expected) = wrote_under_mutation_generation {
                let live: Option<i64> = tx
                    .query_row(
                        "SELECT mutation_generation FROM path_actual_mutation_fences \
                         WHERE group_id = ?1 AND path = ?2",
                        rusqlite::params![operation.group_id, operation.path],
                        |row| row.get(0),
                    )
                    .optional()?;
                if live != Some(expected) {
                    return Ok(RestoreCommitOutcome::FenceLost);
                }
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
            // Explicit, not implicit via the schema's own column default
            // (`Placeholder` as of v25). `reconcile_restore_operations`'s
            // `Hydrated` is published only together with the proof that
            // earns it. The one record-kind arm that writes nothing --
            // a Windows symlink with no opt-in -- observes no identity, so
            // it now simply does not claim to hold content, instead of
            // claiming it and relying on an unsettled projection obligation
            // to keep anything from believing the claim.
            match identity {
                Some(identity) => {
                    // The version this restore actually materialized,
                    // derived from the row the two calls above have just
                    // written -- the one canonical derivation, the same
                    // one every guard and every reader uses. Not
                    // recomputed from the journal's own copy of the
                    // record: that would be a second derivation of one
                    // fact, and the two can only be guaranteed to agree if
                    // there is one.
                    let restored_version = crate::store::read_canonical_current_row(
                        tx,
                        &operation.group_id,
                        &operation.path,
                    )?
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
                            "restored row for {} vanished inside its own commit",
                            operation.path
                        ))
                    })?
                    .version_hash();
                    match wrote_under_mutation_generation {
                        Some(expected) => {
                            let outcome = crate::exact_materialized_commit::
                                commit_internal_materialized_state_if_fence_current(
                                    tx,
                                    &operation.group_id,
                                    &operation.path,
                                    None,
                                    &crate::exact_materialized_commit::ExactMaterializedState::Object {
                                        kind: operation.meta.record_kind,
                                        version: restored_version,
                                        identity: Box::new(Some(*identity)),
                                    },
                                    expected,
                                    // The supersession guard for this
                                    // commit is the version-seq check
                                    // above, taken from the same
                                    // transaction. An `ExpectedAuthoring`
                                    // would ask a second, weaker question
                                    // about a row this call has already
                                    // rewritten.
                                    None,
                                    now_unix_nanos(),
                                )?;
                            match outcome {
                                crate::exact_materialized_commit::
                                    InternalMaterializedCommit::Published(_) => {}
                                // Unreachable: the fence was checked above
                                // under this transaction's own write lock,
                                // and nothing between there and here
                                // touches it, so a refusal now means the
                                // isolation that argument rests on did not
                                // hold. Report it as the error it is --
                                // which also rolls the transaction back,
                                // the only safe outcome once the row has
                                // already been rewritten in it.
                                refused => {
                                    return Err(SyncSqliteError::CorruptState(format!(
                                        "restore commit for {} was refused ({refused:?}) after \
                                         its fence was confirmed inside the same transaction",
                                        operation.path
                                    )));
                                }
                            }
                        }
                        None => {
                            crate::file_index::adopt_local_capture_actual_state(
                                tx,
                                &operation.group_id,
                                &operation.path,
                                operation.meta.record_kind,
                                &restored_version,
                                identity,
                            )?;
                            MaterializationStateRepository::set_materialization_state_in_tx(
                                tx,
                                &operation.group_id,
                                &operation.path,
                                MaterializationState::Hydrated,
                            )?;
                        }
                    }
                }
                // Nothing was observed, so nothing is proven -- the one
                // record-kind arm that writes no bytes at all (a Windows
                // symlink with no opt-in) lands here. The row just written
                // inherited its predecessor's `materialization_state`, and
                // the predecessor's proof is still current against the
                // fence in the recovery lane, so both have to go: this new
                // version is not what either of them describes.
                None => {
                    crate::file_index::retire_unproven_actual_state_in_tx(
                        tx,
                        &operation.group_id,
                        &operation.path,
                    )?;
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
            unix_mode: crate::file_index::decode_unix_mode_column(row.get(14)?),
            xattrs: crate::file_index::decode_xattrs_column(&row.get::<_, String>(15)?).map_err(
                |error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        15,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                },
            )?,
        },
    })
}

/// `RestoreCommitOutcome::FenceLost` promises that nothing was written --
/// the journal row included, since it is the only durable record that a
/// write was ever in flight.
///
/// Keeping that promise is not automatic. The row upsert and its metadata
/// land near the top of this transaction, before the version being
/// published can even be derived from them, and `write_immediate` commits
/// whatever a closure returns `Ok` for. An early return after those writes
/// therefore commits them: the path advances to the restored version with
/// no proof, carrying forward whatever `materialization_state` the row it
/// superseded had -- the exact unprovable claim this module exists to make
/// unreachable -- while the retained journal entry now names a version
/// sequence that no longer matches, so no later attempt can commit it
/// either.
#[cfg(test)]
mod fence_lost_atomicity_tests;

/// A restore authors its change long before it writes the bytes, and the
/// path's materialized basis must not outlive that gap as if it were
/// current.
#[cfg(test)]
mod basis_currency_tests;
