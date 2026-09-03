//! `MaterializationIntentRepository` owns the crash-recovery intent
//! journal, `materialization_intents`, whose rows record "a materialization
//! write for this path is in progress" so a startup repair can disambiguate
//! a `Hydrated`-but-missing file from an interrupted write. This is a
//! distinct concept from per-file `materialization_state` on the `files`
//! table, which `yadorilink-sync-core`'s `MaterializationStateRepository`
//! owns.
//!
//! `begin_materialization_intent`/`clear_materialization_intent`/
//! `has_materialization_intent` are plain CRUD directly on
//! `materialization_intents`.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Deliberately duplicated here
/// rather than depending on `yadorilink-sync-core`'s own `index.rs::
/// now_unix_nanos` (private and `#[cfg(test)]`-only there) -- this crate
/// sits strictly below sync-core in the dependency graph and must not reach
/// back up to it. Same reasoning as this crate's existing
/// `RESERVED_NAMESPACE_RULES_VERSION` constant duplication in `store.rs`.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

pub struct MaterializationIntentRepository {
    database: Arc<SyncDatabase>,
}

impl MaterializationIntentRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Records the durable "materialization write in progress" intent for
    /// `(group_id, path)`, targeting `target_version_hash`'s content. MUST be
    /// called (and its write committed — `PRAGMA synchronous = FULL` is set at
    /// open) *before* the temp-write-then-rename that materializes that content
    /// begins, so a crash between the two leaves the intent durably present.
    /// Overwrites any prior intent for the same path.
    pub fn begin_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        let now = now_unix_nanos();
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "INSERT INTO materialization_intents \
                 (group_id, path, target_version_hash, created_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(group_id, path) DO UPDATE SET \
                  target_version_hash = excluded.target_version_hash, \
                  created_at_unix_nanos = excluded.created_at_unix_nanos",
                rusqlite::params![group_id, path, target_version_hash, now],
            )?;
            Ok(())
        })
    }

    /// Clears the materialization intent for `(group_id, path)` once the write
    /// + rename + fsync has completed. Idempotent: a no-op when no intent
    ///   exists (e.g. a redundant clear, or a path that was never journaled).
    pub fn clear_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
        permit: &RootCommitPermit,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            permit.verify()?;
            conn.execute(
                "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// `_in_tx` counterpart of [`Self::begin_materialization_intent`], for a
    /// caller that already holds an open transaction spanning more writes
    /// than just this one (C4-6: bounded batching of receiver-side
    /// materialization commits). Identical SQL/semantics.
    pub fn begin_materialization_intent_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        now: i64,
    ) -> Result<(), SyncSqliteError> {
        tx.execute(
            "INSERT INTO materialization_intents \
             (group_id, path, target_version_hash, created_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(group_id, path) DO UPDATE SET \
              target_version_hash = excluded.target_version_hash, \
              created_at_unix_nanos = excluded.created_at_unix_nanos",
            rusqlite::params![group_id, path, target_version_hash, now],
        )?;
        Ok(())
    }

    /// `_in_tx` counterpart of [`Self::clear_materialization_intent`]. See
    /// [`Self::begin_materialization_intent_in_tx`]'s doc comment for why
    /// this exists.
    pub fn clear_materialization_intent_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        tx.execute(
            "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Whether an in-progress materialization intent exists for
    /// `(group_id, path)` — the crash-vs-offline-delete disambiguator repair
    /// consults for a `Hydrated`-but-missing file.
    pub fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// Every path in `group_id` that currently carries an intent, as one read.
    ///
    /// The table is empty in steady state (an intent lives only for the
    /// duration of one materialize, or past a crash inside it), so this is a
    /// near-free way for a whole-group sweep to learn the exact set instead of
    /// paying a per-path question -- or a per-path unconditional write -- for
    /// an answer that is almost always "none".
    pub fn list_materialization_intent_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt =
                conn.prepare("SELECT path FROM materialization_intents WHERE group_id = ?1")?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut paths = std::collections::HashSet::new();
            for row in rows {
                paths.insert(row?);
            }
            Ok(paths)
        })
    }
}
