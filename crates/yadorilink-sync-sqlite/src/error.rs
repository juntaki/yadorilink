//! This crate's own error type -- used for every `SyncDatabase::read`/
//! `write`/`write_immediate` call this crate makes (satisfying
//! `yadorilink_sqlite_runtime::SqlOperationError`), and returned by every
//! public method. Callers that need their own error type (today,
//! `yadorilink-sync-core`'s `SyncError`) convert at their own boundary --
//! this crate does not know `SyncError` exists.

#[derive(Debug, thiserror::Error)]
pub enum SyncSqliteError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("corrupt state: {0}")]
    CorruptState(String),

    /// `file_index`'s `blocks_json` encode/decode. Mirrors
    /// `yadorilink-sync-core::SyncError::Json`.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A caller supplied an argument that is structurally invalid for the
    /// operation -- rejected up front, before any state is written. Today
    /// this is only `materialization_jobs`'s illegal-job-state-transition
    /// guard; mirrors `yadorilink-sync-core::SyncError::InvalidInput`, which
    /// this variant bridges to at that crate's boundary (see
    /// `impl From<SyncSqliteError> for SyncError`).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// `dag_store::admit_change` found a change whose pinned authorization
    /// coordinate is older than one of its own causal parents' -- the
    /// revoked-writer-replay attack `4175e8cd` closed. A distinct variant
    /// (rather than folding into `InvalidInput`) so `ChangeHistoryRepository
    /// ::dag_admit_change[_with_versions]` can recognize it specifically and
    /// run a follow-up cleanup pass outside the now-rolled-back admission
    /// transaction (see those methods' own doc comments) -- string-matching
    /// `InvalidInput`'s message would work today but silently break the
    /// moment that message's wording ever changed.
    #[error("change pins an authorization coordinate older than its causal parent")]
    CausalAuthViolation,

    /// An I/O failure surfaced while satisfying a
    /// [`yadorilink_root_authority::root_commit::RootCommitPermit::verify`]
    /// re-check inside a write transaction (see
    /// `materialization_job_repository`'s intent-journal writes). Not
    /// produced by this crate's own SQL paths, which fail through
    /// `SyncSqliteError::Sqlite` instead.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// `filesystem_transaction`'s execution gate (`EXECUTION_ENABLED =
    /// false` for the whole of this phase): every mutating function calls
    /// `require_execution_enabled` first and fails closed with this rather
    /// than performing any write. Mirrors
    /// `yadorilink-sync-core::SyncError::NotImplemented`.
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    /// A filesystem transaction's `execution_generation` fence rejected a
    /// caller whose `expected` generation no longer matches the
    /// transaction's `current` one. Mirrors
    /// `yadorilink-sync-core::SyncError::ExecutionGenerationFenced`.
    #[error(
        "filesystem transaction {transaction_id} execution_generation is stale: expected \
         {expected}, currently {current}"
    )]
    ExecutionGenerationFenced { transaction_id: String, expected: i64, current: i64 },

    /// A requested hierarchical path reservation
    /// (`filesystem_transaction_reservations`) overlaps a reservation
    /// another transaction already holds. Mirrors
    /// `yadorilink-sync-core::SyncError::ReservationConflict`.
    #[error(
        "reservation for {path:?} (transaction {transaction_id}) conflicts with an existing \
         reservation held by transaction {blocking_transaction_id}"
    )]
    ReservationConflict { transaction_id: String, path: String, blocking_transaction_id: String },

    /// A filesystem-transaction-engine phase/state transition's
    /// compare-and-swap `UPDATE` matched the row's id and its
    /// `execution_generation`, but not the phase/state the caller's
    /// legality check actually validated against -- a sibling transition
    /// raced this one. Mirrors `yadorilink-sync-core::SyncError::TransitionRaced`.
    #[error(
        "{subject}: expected phase/state {expected_state:?} but it is now {current_state:?} -- \
         a concurrent transition raced this one to the same execution_generation"
    )]
    TransitionRaced { subject: String, expected_state: String, current_state: String },

    /// A path names a component reserved for transaction artefacts somewhere
    /// it must not: a peer change naming one before DAG admission, a
    /// collision detected at artefact creation, or one found unexpectedly at
    /// startup. Fail-closed and carries the exact path -- the offending path
    /// is never admitted, materialized or deleted. Mirrors
    /// `yadorilink-sync-core::SyncError::ReservedNamespaceCollision`.
    #[error("path {0:?} names a reserved artefact component and cannot be used here")]
    ReservedNamespaceCollision(String),

    /// A path component would not survive a Windows peer's own path
    /// normalization (Windows silently drops a trailing `.` or ` ` from a
    /// path component in most Win32 APIs). Fail-closed: the offending path
    /// is never admitted, materialized, or trusted as faithfully represented
    /// on disk. Mirrors `yadorilink-sync-core::SyncError::NonPortablePath`.
    #[error(
        "path {0:?} has a component that is not portable to every platform this group may sync \
         to (Windows silently strips a trailing '.' or ' ') and cannot be used here"
    )]
    NonPortablePath(String),

    /// A hex-decode failure -- `captured_authoring`'s own block-hash
    /// handling today. Mirrors `yadorilink-sync-core::SyncError::Hex`.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A chunking/content-addressing failure surfaced while classifying a
    /// retained preimage. Mirrors `yadorilink-sync-core::SyncError::Chunking`.
    #[error("chunking error: {0}")]
    Chunking(String),

    /// A block-store failure not otherwise covered above -- `captured_
    /// authoring`'s own boundary with `yadorilink_local_storage::BlockStore`.
    /// Mirrors `yadorilink-sync-core::SyncError::Storage`.
    #[error("storage error: {0}")]
    Storage(#[from] yadorilink_local_storage::StorageError),

    /// A folder group has more than one live link on this device -- refused
    /// rather than resolved, since guessing which root is the real one risks
    /// tombstoning the other's files group-wide. Mirrors
    /// `yadorilink-sync-core::SyncError::AmbiguousLink`, which this variant
    /// bridges to losslessly at that crate's boundary (see `impl
    /// From<SyncSqliteError> for SyncError`) -- structurally, not as a
    /// flattened message string, the same fix `impl
    /// From<yadorilink_root_authority::RootAuthorityError> for
    /// SyncSqliteError` below needed for its own `AmbiguousLink` arm.
    #[error(
        "folder group {group_id} is linked to {} folders on this device ({}); sync is stopped \
         for this folder group until exactly one remains",
        local_paths.len(),
        local_paths.join(", ")
    )]
    AmbiguousLink { group_id: String, local_paths: Vec<String> },

    /// `MaterializationStatePort::mark_deleted_emitting_change`'s own
    /// `local_emission_auth` pre-check: the group's policy has not loaded
    /// this run, so a change-emitting write withheld its emission rather
    /// than stamp a placeholder-auth change. Mirrors
    /// `yadorilink-sync-core::SyncError::PolicyUnavailable`/
    /// `yadorilink_filesystem_sync::materialization_execution::
    /// MaterializationExecutionError::PolicyUnavailable`, this crate's own
    /// bridge for the same `yadorilink_replica_domain::change::
    /// PolicyUnavailable` marker.
    #[error("no verified policy is currently loaded for this group")]
    PolicyUnavailable,
}

impl From<yadorilink_replica_domain::change::PolicyUnavailable> for SyncSqliteError {
    fn from(_: yadorilink_replica_domain::change::PolicyUnavailable) -> Self {
        SyncSqliteError::PolicyUnavailable
    }
}

impl From<yadorilink_replica_domain::codec::ChangeError> for SyncSqliteError {
    fn from(error: yadorilink_replica_domain::codec::ChangeError) -> Self {
        SyncSqliteError::CorruptState(error.to_string())
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for SyncSqliteError {
    fn from(err: yadorilink_root_authority::RootAuthorityError) -> Self {
        use yadorilink_root_authority::RootAuthorityError as E;
        // Captured before the match below moves `err` -- `AmbiguousLink`'s
        // arm has no dedicated SyncSqliteError variant yet, so it falls
        // back to CorruptState carrying this crate's own formatted message
        // rather than reconstructing the group_id/local_paths fields.
        match err {
            E::Io(e) => SyncSqliteError::Io(e),
            E::NotFound(msg) => SyncSqliteError::NotFound(msg),
            E::CorruptState(msg) => SyncSqliteError::CorruptState(msg),
            E::ReservedNamespaceCollision(msg) => SyncSqliteError::ReservedNamespaceCollision(msg),
            // No dedicated variant yet -- root-identity mismatches haven't
            // had a sync-sqlite call site until Phase 7D-9B's `VerifiedRoot`
            // split. `CorruptState` is the closest existing shape (a
            // fail-closed condition the caller cannot repair by retrying).
            E::RootIdentityMismatch(msg) => SyncSqliteError::CorruptState(msg),
            // Lossless, not flattened to a message string: `link.rs`'s own
            // move to this crate (Phase 7D-9B follow-up) gives `AmbiguousLink`
            // a real sync-sqlite call site with the same "callers match on the
            // structured variant, not the message" requirement
            // `SyncError::AmbiguousLink`'s own doc comment already documents
            // for its round trip through `RootAuthorityError`.
            E::AmbiguousLink { group_id, local_paths } => {
                SyncSqliteError::AmbiguousLink { group_id, local_paths }
            }
        }
    }
}

/// `retained_obligation`'s `ObligationState::from_str`/
/// `evaluate_deletion_pre_durability` (7D-9D move from `yadorilink-sync-core`)
/// return `yadorilink_replica_engine::error::ReplicaEngineError` -- mirrors
/// `yadorilink-sync-core::SyncError`'s own identical bridge for the same
/// type. `ReplicaEngineError` has no `Io`/`InvalidInput`-shaped variant of
/// its own distinct from `Storage`, so `Storage` collapses to
/// `SyncSqliteError::CorruptState` here too: a replica-engine "storage"
/// failure reaching this crate is always a decode/consistency problem on
/// data this crate itself owns reading, never a live I/O failure (those
/// already surface as `SyncSqliteError::Io`/`Sqlite` directly).
impl From<yadorilink_replica_engine::error::ReplicaEngineError> for SyncSqliteError {
    fn from(error: yadorilink_replica_engine::error::ReplicaEngineError) -> Self {
        use yadorilink_replica_engine::error::ReplicaEngineError as E;
        match error {
            E::CorruptState(msg) => SyncSqliteError::CorruptState(msg),
            E::InvalidInput(msg) => SyncSqliteError::InvalidInput(msg),
            E::Storage(msg) => SyncSqliteError::CorruptState(msg),
        }
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for SyncSqliteError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            SyncSqliteError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}
