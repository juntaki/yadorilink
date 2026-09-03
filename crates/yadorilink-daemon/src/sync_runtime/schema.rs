//! Thin sequencing shim over `yadorilink_sqlite_runtime::init_schema`.
//! `yadorilink-daemon` is the composition root for schema bootstrap: it
//! sequences its own `pre_dag_schema` -> `yadorilink_sqlite_runtime::init_schema`
//! -> `post_dag_schema` steps directly, because the authoring-identity
//! triggers `pre_dag_schema` creates reference `changes`/`pruned_changes`,
//! which only exist once `dag_store::init_dag_schema` has run.

use rusqlite::Connection;

use crate::sync_error::SyncError;

/// Sequenced by [`crate::replica_coordinator`]'s own `schema_init`, which
/// `ReplicaCoordinator::open`/`open_in_memory` use to bootstrap a database's
/// schema from scratch.
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
