//! Shared SQLite runtime: connection pool, in-process writer serialization,
//! and schema bootstrap for every SQLite-backed storage crate in this
//! workspace. Owns exactly:
//!
//! - a single connection pool
//! - a single process-local writer gate
//! - connection initialization and PRAGMA configuration
//! - `read`/`write`/`write_immediate` transaction helpers
//! - schema bootstrap/migration DDL for the shared database file
//!
//! Deliberately does NOT own: repository queries, row/domain-type mapping,
//! change-admission policy, durability judgment, or any other business
//! logic -- those stay in the crates that consume `SyncDatabase` (today,
//! `yadorilink-sync-core`'s own repositories; Phase 7D-5's
//! `yadorilink-replica-sqlite` adapters next).
//!
//! Extracted out of `yadorilink-sync-core` (Phase 7D-4) as a pure
//! mechanical move -- pool size, timeouts, locking order, transaction
//! mode, retry behavior, and PRAGMA settings are all unchanged from the
//! pre-move implementation.

mod database;
mod error;
mod pool;
mod schema;

pub use database::SyncDatabase;
pub use error::{DatabaseError, SqlOperationError};
pub use pool::{ConnectionPool, BUSY_TIMEOUT};
pub use schema::{init_schema, table_exists, SCHEMA_VERSION};
