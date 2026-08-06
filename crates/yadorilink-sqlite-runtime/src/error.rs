//! Errors this crate's own constructors (`SyncDatabase::open`/
//! `open_in_memory`, schema bootstrap) can raise directly.
//!
//! `SyncDatabase::read`/`write`/`write_immediate` do NOT use this type --
//! they are generic over the caller's own error type via
//! [`SqlOperationError`], so a caller (e.g. `yadorilink-sync-core`, whose
//! own `SyncError` already has `#[from] rusqlite::Error`/
//! `#[from] r2d2::Error`) never needs to convert through this crate's own
//! error enum on every read/write call site -- only `open`/schema
//! bootstrap, which have no caller-supplied error type to be generic
//! over, use `DatabaseError` directly.

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("unsupported database schema version {on_disk_version} (this build supports {supported_version})")]
    UnsupportedSchemaDowngrade { on_disk_version: i32, supported_version: i32 },

    #[error("corrupt database schema: {0}")]
    CorruptSchema(String),
}

/// The bound `SyncDatabase::read`/`write`/`write_immediate` require of a
/// caller's own error type: it must be constructible from the two error
/// kinds a connection checkout or SQL statement can raise, and must be
/// able to tell [`crate::retry_on_database_locked`] whether a given value
/// represents a transient `SQLITE_LOCKED`/`SQLITE_BUSY` condition (the only
/// thing that's retried) versus a genuine, unretryable failure.
///
/// This is the seam that lets `SyncDatabase` live in a crate with zero
/// dependency on any caller's own error enum: `yadorilink-sync-core`'s
/// `SyncError` implements this trait on its own side (it already has
/// `#[from] rusqlite::Error` and `#[from] r2d2::Error`), so every existing
/// repository closure keeps returning `Result<T, SyncError>` completely
/// unchanged.
pub trait SqlOperationError: From<rusqlite::Error> + From<r2d2::Error> {
    fn is_locked(&self) -> bool;
}

impl SqlOperationError for DatabaseError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            DatabaseError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}
