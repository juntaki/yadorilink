//! This crate's own error type, following the exact shape
//! `yadorilink-peer-session::error::PeerSessionError` established in Phase
//! 7D-6 (`crates/yadorilink-peer-session/src/error.rs`): a thiserror-based
//! enum with only the variants this module's own code paths actually need,
//! not a blind copy of a lower-level crate's full variant list.
//!
//! `LocalChangeProcessor`'s own code never *constructs* a `SyncSqliteError`
//! variant of its own — every error it returns is either propagated via `?`
//! from a `LocalMutationStore`/`BlockContentStore` call (both of which
//! return `Result<_, yadorilink_sync_sqlite::SyncSqliteError>` since Phase
//! 7D-10 narrowed `LocalMutationStore`'s associated error surface off the
//! wider `yadorilink_sync_core::SyncError` -- `LocalMutationStore`'s trait
//! definition lives in this crate, and `yadorilink-daemon`'s `ReplicaCoordinator`
//! impl (this trait's sole implementor since Phase 7D-10's sync-core
//! deletion pass) delegates straight to `yadorilink-sync-sqlite` repository
//! calls that already return `SyncSqliteError` natively) or matched by
//! variant (`SyncSqliteError::PolicyUnavailable`) without ever being
//! rebuilt. A single transparent wrapping variant is therefore everything
//! this crate's own public API (`LocalChangeProcessor`'s methods) needs.
//!
//! No reverse `impl From<LocalCaptureError> for SyncSqliteError` is added:
//! per the ledger, `local_change.rs`'s only production consumer is
//! `yadorilink-daemon`, not `yadorilink-sync-sqlite` itself (unlike
//! `peer_session.rs`, which still had transitional callers inside
//! sync-core during its own move) — the daemon consumes
//! `LocalCaptureError` directly, so sync-sqlite never needs to know this
//! type exists.
#[derive(Debug, thiserror::Error)]
pub enum LocalCaptureError {
    #[error(transparent)]
    SyncCore(#[from] yadorilink_sync_sqlite::SyncSqliteError),
}

/// Routes every conversion through `SyncSqliteError`'s own `From` impl
/// rather than wrapping the source type directly, so its special-casing
/// (e.g. the `Storage(StorageError::DiskPressure { .. })` shape
/// `is_retriable_block_store_error`'s classification depends on) is
/// preserved byte-for-byte — this crate's own `?`-propagation sites are the
/// same ones `local_change.rs` always had, just converting to the narrower
/// `SyncSqliteError` (Phase 7D-10) instead of the wider `SyncError`.
impl From<std::io::Error> for LocalCaptureError {
    fn from(err: std::io::Error) -> Self {
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}

impl From<yadorilink_local_storage::StorageError> for LocalCaptureError {
    fn from(err: yadorilink_local_storage::StorageError) -> Self {
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for LocalCaptureError {
    fn from(err: yadorilink_root_authority::RootAuthorityError) -> Self {
        LocalCaptureError::SyncCore(yadorilink_sync_sqlite::SyncSqliteError::from(err))
    }
}
