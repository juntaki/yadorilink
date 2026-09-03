//! Thin sequencing shim over `yadorilink_sqlite_runtime::init_schema`,
//! independently duplicated from `yadorilink_sync_core::storage::schema`
//! (see this module's parent `mod.rs` doc comment for why). `yadorilink-daemon`
//! is its own composition root here exactly as `yadorilink-sync-core` is for
//! `SyncState`, and sequences its own `pre_dag_schema` ->
//! `yadorilink_sqlite_runtime::init_schema` -> `post_dag_schema` steps
//! directly, for the same ordering reason that crate's own module doc
//! comment describes (the authoring-identity triggers `pre_dag_schema`
//! creates reference `changes`/`pruned_changes`, which only exist once
//! `dag_store::init_dag_schema` has run).

use rusqlite::Connection;

use crate::sync_error::SyncError;

/// Sequenced by [`crate::replica_coordinator`]'s own `schema_init`, used by
/// `ReplicaCoordinator::open`/`open_in_memory` to reproduce
/// `SyncState::open`/`open_in_memory`'s own schema-bootstrap sequencing when
/// opening a database of its own.
pub fn pre_dag_schema(conn: &Connection) -> Result<(), yadorilink_sqlite_runtime::DatabaseError> {
    // `conflict_copy_provenance` must exist BEFORE `init_dag_schema` runs:
    // that call's own internal retained-history repair pass promotes
    // orphans, which runs carrier validation against this table.
    yadorilink_sync_sqlite::dag_store::init_conflict_copy_provenance_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    yadorilink_sync_sqlite::dag_store::init_dag_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    yadorilink_sync_sqlite::materialized_generation::init_materialized_generation_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    yadorilink_sync_sqlite::filesystem_transaction::init_filesystem_transaction_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    yadorilink_sync_sqlite::captured_authoring::init_captured_authoring_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    yadorilink_sync_sqlite::retained_obligation::init_retained_obligations_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    Ok(())
}

/// See [`pre_dag_schema`]'s doc comment above.
pub fn post_dag_schema(conn: &Connection) -> Result<(), yadorilink_sqlite_runtime::DatabaseError> {
    yadorilink_sync_sqlite::rebootstrap_store::init_rebootstrap_schema(conn)
        .map_err(|e| schema_err(SyncError::from(e)))?;
    Ok(())
}

fn schema_err(err: SyncError) -> yadorilink_sqlite_runtime::DatabaseError {
    yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(err.to_string())
}
