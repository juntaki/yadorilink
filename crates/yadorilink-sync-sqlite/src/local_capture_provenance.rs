//! Which of this device's own changes were derived from capturing its own
//! disk.
//!
//! A change this device authors is one of two kinds, and they call for
//! opposite treatment when projected back onto the same disk:
//!
//! * a **capture**: local capture read a file (or observed its absence)
//!   and signed what it saw. The disk was the source of the change, so
//!   projecting it can never legitimately change the disk. If the disk no
//!   longer holds what was captured, what is there is a newer local state,
//!   to be captured in turn -- never overwritten with the older one.
//! * an **intentional mutation**: a restore, a repair carrier, and every
//!   other change authored in order to change the disk. The disk not
//!   holding it yet is the point.
//!
//! The signed change does not say which one it is: a restore and a capture
//! are both ordinary `Put`s. So the capture routes record it themselves, in
//! the transaction that emits the change, and nothing else writes here. The
//! initial import is one of them: it emits the rows the first scan read off
//! this disk, for the paths it binds. A change with no record is treated as
//! an intentional mutation -- the conservative reading, since it is how
//! every own change was projected before this record existed. History
//! backfill is left unrecorded on purpose: it re-emits whatever index row
//! it finds missing from history, whichever writer left it there (a row
//! projection wrote, such as a derived conflict copy, is one it already
//! has to exclude), so nothing proves its change describes this disk.
//!
//! One row per path, naming the most recent capture of it. That is exact
//! for the question asked of it: "is this path's winning own head the
//! change a capture of this path emitted?" A capture's change supersedes
//! every earlier own head of the path, so an older capture of it is never
//! the winner again; and a later non-capture change (a restore) has a
//! different hash from the one recorded, so it is correctly not a capture.
//! The table is bounded by the number of paths ever captured.
//!
//! A captured deletion is recorded too, so that it replaces the record of
//! the capture it deleted. Nothing asks about a deletion itself yet: only a
//! content head can be written over newer local state.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::ids::ChangeHash;

pub fn init_local_capture_provenance_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS local_capture_changes (
            group_id    TEXT NOT NULL,
            path        TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        "#,
    )?;
    Ok(())
}

/// Records that `change_hash` was emitted by local capture for `path`, in
/// the caller's transaction -- the one that emits the change. Called only
/// by the capture routes of `file_index` and by the initial import, which
/// emits the first scan's rows.
pub(crate) fn record_local_capture_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    change_hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "INSERT INTO local_capture_changes (group_id, path, change_hash) VALUES (?1, ?2, ?3)
         ON CONFLICT (group_id, path) DO UPDATE SET change_hash = excluded.change_hash",
    )?
    .execute(rusqlite::params![group_id, path, &change_hash.0[..]])?;
    Ok(())
}

/// Whether `change_hash` is the change local capture most recently emitted
/// for `path`: this device's disk was its source.
pub fn is_local_capture(
    conn: &Connection,
    group_id: &str,
    path: &str,
    change_hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let recorded: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT change_hash FROM local_capture_changes WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?;
    Ok(recorded.is_some_and(|recorded| recorded.as_slice() == change_hash.0.as_slice()))
}
