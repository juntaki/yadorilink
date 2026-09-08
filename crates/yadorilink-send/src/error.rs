//! This crate's single error type. `store.rs`'s `SendStore::read`/`write`/
//! `write_immediate` closures return this directly (via `SqlOperationError`,
//! matching the exact seam `yadorilink-sqlite-runtime`'s own doc comment
//! describes for `yadorilink-sync-core::SyncError`), so a store call site
//! never converts through a second, storage-only error enum first.

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("database error: {0}")]
    Database(#[from] yadorilink_sqlite_runtime::DatabaseError),

    #[error("local storage error: {0}")]
    Storage(#[from] yadorilink_local_storage::StorageError),

    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("wire decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("unknown transfer id: {0}")]
    UnknownTransfer(String),

    #[error("transfer {0} was offered to a different device than the one this connection authenticated as")]
    WrongPeer(String),

    #[error("no known address for device {0}")]
    NoKnownAddress(String),

    #[error("no known signing key for device {0}")]
    NoKnownDeviceKey(String),

    #[error("peer rejected the offer: {0}")]
    OfferRejected(String),

    #[error("peer rejected the pull: {0}")]
    PullRejected(String),

    #[error("manifest is empty: {0} contains no readable files")]
    EmptyManifest(String),

    #[error("chunk {chunk_index} of file {file_index} failed integrity verification")]
    ChunkHashMismatch { file_index: u32, chunk_index: u32 },

    #[error("peer sent malformed data: {0}")]
    Protocol(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl yadorilink_sqlite_runtime::SqlOperationError for SendError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            SendError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}

pub type Result<T> = std::result::Result<T, SendError>;
