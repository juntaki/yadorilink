//! `DirtyPathRepository` owns the `local_dirty_paths` table -- the local
//! journal of detected-but-not-yet-processed local edits, surviving watcher
//! misses, disk faults, and restarts.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::session_state::DirtyPath;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Deliberately duplicated here
/// rather than depending on `yadorilink-sync-core`'s own `index.rs::
/// now_unix_nanos` (private and `#[cfg(test)]`-only there) -- this crate
/// sits strictly below sync-core in the dependency graph and must not reach
/// back up to it. Same reasoning as `materialization_job_repository`'s own
/// identical duplication.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

pub struct DirtyPathRepository {
    database: Arc<SyncDatabase>,
}

impl DirtyPathRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Records `path` as a detected-but-not-yet-processed local edit for
    /// `group_id`, *before* the read/blockify/put/index+DAG step runs. Keeps
    /// the earliest `first_seen_unix_nanos` across repeated events for the same
    /// path (so `INSERT ... ON CONFLICT` updates only the kind/observation
    /// time), and resets `attempts`/`last_error` since a fresh event is a fresh
    /// detection, not a continued failure. The row survives until
    /// [`Self::clear_dirty_path`] runs after the step commits, so a crash or a
    /// multi-second block-store fault mid-processing cannot drop the edit — the
    /// daemon re-drives it on startup and on retry.
    pub fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        let now = now_unix_nanos();
        // This row is the only durable record of the edit until the real
        // index+DAG write commits (see this fn's own doc comment) -- a
        // transient `SQLITE_LOCKED`/`SQLITE_BUSY` here, previously
        // unretried, meant the journal itself could silently never be
        // written for an edit that also then failed its real write for the
        // same reason, leaving no record anywhere to re-drive later.
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "INSERT INTO local_dirty_paths \
                 (group_id, path, change_kind, first_seen_unix_nanos, observed_at_unix_nanos, \
                  attempts, last_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL) \
                 ON CONFLICT(group_id, path) DO UPDATE SET \
                  change_kind = excluded.change_kind, \
                  observed_at_unix_nanos = excluded.observed_at_unix_nanos, \
                  attempts = 0, last_error = NULL",
                rusqlite::params![group_id, path, change_kind, now, observed_at_unix_nanos],
            )?;
            Ok(())
        })
    }

    /// Records that a processing attempt for `path` failed: increments
    /// `attempts` and stores `last_error`, leaving the dirty row in place so it
    /// is retried. A no-op (updates zero rows) if the path is no longer
    /// journaled — a concurrent success may have already cleared it.
    pub fn mark_dirty_path_attempt(
        &self,
        group_id: &str,
        path: &str,
        last_error: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE local_dirty_paths SET attempts = attempts + 1, last_error = ?3 \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path, last_error],
            )?;
            Ok(())
        })
    }

    /// Clears `path` from the dirty journal once its read/blockify/put/index+DAG
    /// step has committed. Not an error if the path wasn't recorded — mirrors
    /// `clear_held`'s "callers don't need to check first" contract.
    pub fn clear_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncSqliteError> {
        permit.verify()?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "DELETE FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// Whether `path` currently has a pending local edit journaled for
    /// `group_id`. The materialization-repair / reconcile write paths consult
    /// this before overwriting an on-disk file from the (older) index, so a
    /// newer local edit the watcher hasn't yet indexed is quarantined rather
    /// than destroyed.
    pub fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// Every currently journaled dirty path for `group_id`, oldest-first — the
    /// daemon's startup rescan worklist. Ordered by `first_seen_unix_nanos` so
    /// the longest-outstanding edits are re-driven first.
    pub fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, change_kind, observed_at_unix_nanos, attempts \
                 FROM local_dirty_paths WHERE group_id = ?1 \
                 ORDER BY first_seen_unix_nanos, path",
            )?;
            let rows = stmt.query_map([group_id], |r| {
                Ok(DirtyPath {
                    path: r.get(0)?,
                    change_kind: r.get(1)?,
                    observed_at_unix_nanos: r.get(2)?,
                    attempts: r.get::<_, i64>(3)? as u32,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}
