//! Shared SQLite runtime: connection pool, in-process writer
//! serialization, and schema bootstrap for every SQLite-backed storage
//! crate in this workspace.

mod database;
mod error;
mod pool;
mod schema;

// Permanent writer-gate observability -- see `database::writer_gate_stats`'s own
// header comment.
pub use database::writer_gate_stats;
pub use database::SyncDatabase;
pub use error::{DatabaseError, SqlOperationError};
pub use pool::{ConnectionPool, BUSY_TIMEOUT, STATEMENT_CACHE_CAPACITY};
pub use schema::{
    check_replica_schema_generation, check_schema_version_supported, init_schema, table_exists,
    SCHEMA_VERSION,
};
