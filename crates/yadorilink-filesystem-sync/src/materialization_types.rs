//! Pure value types describing materialization/eviction/restore state,
//! carrying no `SyncState`/SQL/rusqlite dependency of their own -- moved out
//! of `yadorilink-sync-core`'s `state_model.rs` (Phase 7D-9C) because
//! `yadorilink_filesystem_sync::materialization_execution::
//! MaterializationExecutionPort` returns/consumes them and a trait
//! definition cannot name a type that still lives in a crate depending on
//! the one defining the trait. `yadorilink-sync-core`'s `index.rs`
//! re-exports these at their original path (`crate::index::TypeName`; it
//! re-exported them via the now-deleted `state_model.rs` at the time of this
//! move, Phase 7D-10.1), so this move needed no consumer repoint -- same
//! shape as `CurrentVersionRecord`/`HeldState`/`LinkGate`'s earlier move to
//! `yadorilink_replica_domain::session_state`.

use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;

/// One restore whose replacement file and index update have not both been
/// durably committed yet. The intended new record is persisted before the
/// filesystem rename so startup recovery can finish the exact same version
/// instead of manufacturing a second version-vector increment.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreOperation {
    pub operation_id: String,
    pub group_id: String,
    pub path: String,
    pub target_version_seq: i64,
    pub expected_current_version_seq: Option<i64>,
    pub state: RestoreOperationState,
    pub record: FileRecord,
    pub origin_device_id: String,
    /// The signed DAG change authored for this restore before the filesystem
    /// replacement begins. Recovery publishes the journaled row with this
    /// identity, so a crash cannot make a restored edit inherit its source
    /// version's author.
    pub authoring_change_hash: Option<ChangeHash>,
    /// The restored version's own classification columns — carried
    /// alongside `record` (a bare `FileRecord`, which has no room for
    /// these) so `commit_restore_operation` can apply them to the
    /// `current` row via [`LocalFileMetaColumns`]/
    /// `apply_local_meta_columns_in_tx`, the SAME atomic in-transaction
    /// counterpart every other local content emission already uses.
    pub meta: LocalFileMetaColumns,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RestoreCommitOutcome {
    Committed(FileRecord),
    Missing,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOperationState {
    Prepared,
    DiskCommitted,
}

impl RestoreOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::DiskCommitted => "disk_committed",
        }
    }

    /// Returns a plain `String` error, not this crate's own
    /// `MaterializationExecutionError` (or `yadorilink-sync-core`'s
    /// `SyncError`): the one real caller
    /// (`yadorilink-sync-core::repository::restore_operation`'s row decoder)
    /// wraps this straight into a `rusqlite::Error::FromSqlConversionFailure`
    /// via `Box<dyn std::error::Error + Send + Sync>`'s blanket `From<String>`
    /// impl, so no richer error type is needed here.
    pub fn from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "disk_committed" => Ok(Self::DiskCommitted),
            other => Err(format!("unknown restore operation state: {other}")),
        }
    }
}

/// One candidate for the automatic eviction sweep, in the order
/// `list_evictable_files` returns them: least-recently-accessed first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictableFile {
    pub path: String,
    pub size: u64,
    pub last_accessed_unix: Option<i64>,
}
