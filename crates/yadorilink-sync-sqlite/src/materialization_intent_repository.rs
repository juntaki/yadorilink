//! `MaterializationIntentRepository` owns the crash-recovery intent
//! journal, `materialization_intents`, whose rows record "a
//! materialization write for this path is in progress" so a startup repair
//! can disambiguate a `Present`-but-missing file from an interrupted
//! write. `begin_materialization_intent`/`clear_materialization_intent`/
//! `has_materialization_intent` are plain CRUD directly on
//! `materialization_intents`.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

/// Current wall-clock time in nanoseconds since the Unix epoch, clamped to
/// `0` if the clock reads before the epoch. Same reasoning as this crate's
/// existing `RESERVED_NAMESPACE_RULES_VERSION` constant duplication in
/// `store.rs`.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Before an intent for `path` is (re)written to `target`, keeps the target
/// of the intent it replaces when that differs: an unproven earlier write
/// whose bytes may already be on disk (see `materialization_replaced_targets`).
fn keep_replaced_target(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    target: &[u8],
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO materialization_replaced_targets \
         (group_id, path, target_version_hash) \
         SELECT group_id, path, target_version_hash FROM materialization_intents \
          WHERE group_id = ?1 AND path = ?2 AND kind = 'write' AND target_version_hash != ?3",
        rusqlite::params![group_id, path, target],
    )?;
    Ok(())
}

/// Clears `path`'s intent and, with it, the targets it had replaced --
/// the targets first. Where the two statements commit separately, a crash
/// between them then leaves the intent with no recorded targets (a capture
/// may author one of those contents again, as before they were recorded),
/// never recorded targets with no intent, which a later unrelated write of
/// the path would inherit and refuse a genuine edit restoring that content.
fn delete_intent(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM materialization_replaced_targets WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
    )?;
    conn.execute(
        "DELETE FROM materialization_intents WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
        rusqlite::params![group_id, path],
    )?;
    Ok(())
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
            keep_replaced_target(conn, group_id, path, target_version_hash)?;
            conn.execute(
                "INSERT INTO materialization_intents \
                 (group_id, path, target_version_hash, created_at_unix_nanos) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(group_id, path, kind) DO UPDATE SET \
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
            delete_intent(conn, group_id, path)
        })
    }

    /// `_in_tx` counterpart of [`Self::begin_materialization_intent`], for a
    /// caller that already holds an open transaction spanning more writes
    /// than just this one (bounded batching of receiver-side
    /// materialization commits). Identical SQL/semantics.
    pub fn begin_materialization_intent_in_tx(
        tx: &rusqlite::Transaction,
        group_id: &str,
        path: &str,
        target_version_hash: &[u8],
        now: i64,
    ) -> Result<(), SyncSqliteError> {
        keep_replaced_target(tx, group_id, path, target_version_hash)?;
        tx.execute(
            "INSERT INTO materialization_intents \
             (group_id, path, target_version_hash, created_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(group_id, path, kind) DO UPDATE SET \
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
        delete_intent(tx, group_id, path)
    }

    /// Whether an in-progress materialization intent exists for
    /// `(group_id, path)` — the crash-vs-offline-delete disambiguator repair
    /// consults for a `Present`-but-missing file.
    pub fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        let count: i64 = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2 \
                     AND kind = 'write'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )?)
        })?;
        Ok(count > 0)
    }

    /// The live intent's `target_version_hash` for `(group_id, path)`, if one
    /// is open right now -- the projection fence local capture consults to
    /// tell a materialize-in-flight echo apart from a genuine concurrent
    /// local edit. `has_materialization_intent` alone cannot do this job: it
    /// answers "is *a* write in flight" but not "in flight toward *what*",
    /// and a caller that suppressed on presence alone would just as
    /// willingly suppress a real edit racing a DIFFERENT target. See
    /// `LocalMutationStore::materialization_intent_target`'s own doc comment
    /// for the full mechanism this backs.
    pub fn materialization_intent_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT target_version_hash FROM materialization_intents \
                     WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
                    rusqlite::params![group_id, path],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()?)
        })
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
            let mut stmt = conn.prepare(
                "SELECT path FROM materialization_intents WHERE group_id = ?1 AND kind = 'write'",
            )?;
            let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
            let mut paths = std::collections::HashSet::new();
            for row in rows {
                paths.insert(row?);
            }
            Ok(paths)
        })
    }
}

/// Releases not yet written. A released record only names a file that is
/// gone, which recovery clears without touching anything, so the delete does
/// not have to be durable before the writer moves on: it is carried by the next
/// record's transaction instead of costing a write of its own. One queue is
/// shared by every ledger of a database.
#[derive(Default)]
pub struct TempReleaseQueue(std::sync::Mutex<Vec<(String, String)>>);

/// Past this many unwritten releases the next release writes them itself.
const MAX_QUEUED_RELEASES: usize = 256;

/// The durable record of temp files writers are about to create:
/// `materialization_tmp_files`. See that table's schema comment. The
/// repository is a [`yadorilink_local_storage::TempFileLedger`] bound to one
/// group, so a writer in `yadorilink-local-storage` records through it without
/// knowing about the database.
#[derive(Clone)]
pub struct MaterializationTempLedger {
    database: Arc<SyncDatabase>,
    group_id: String,
    releases: Arc<TempReleaseQueue>,
}

impl MaterializationTempLedger {
    pub fn new(
        database: Arc<SyncDatabase>,
        group_id: &str,
        releases: Arc<TempReleaseQueue>,
    ) -> Self {
        Self { database, group_id: group_id.to_string(), releases }
    }

    fn take_queued(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.releases.0.lock().unwrap_or_else(|p| p.into_inner()))
    }

    fn requeue(&self, mut released: Vec<(String, String)>) {
        let mut queue = self.releases.0.lock().unwrap_or_else(|p| p.into_inner());
        released.append(&mut queue);
        *queue = released;
    }

    fn delete_released(
        conn: &rusqlite::Connection,
        released: &[(String, String)],
    ) -> Result<(), SyncSqliteError> {
        for (group_id, tmp_path) in released {
            conn.execute(
                "DELETE FROM materialization_tmp_files WHERE group_id = ?1 AND tmp_path = ?2",
                rusqlite::params![group_id, tmp_path],
            )?;
        }
        Ok(())
    }

    /// Every temp file recorded for `group_id`, as the absolute paths the
    /// writers recorded, after the queued releases are written.
    pub fn list(&self) -> Result<Vec<String>, SyncSqliteError> {
        let released = self.take_queued();
        if !released.is_empty() {
            self.database
                .write::<_, SyncSqliteError>(|conn| Self::delete_released(conn, &released))
                .inspect_err(|_| self.requeue(released.clone()))?;
        }
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT tmp_path FROM materialization_tmp_files WHERE group_id = ?1 \
                 ORDER BY tmp_path",
            )?;
            let rows = stmt.query_map([&self.group_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
    }

    /// Forgets a recorded temp file (recovery, after the file is gone).
    pub fn forget(&self, tmp_path: &str) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            Self::delete_released(conn, &[(self.group_id.clone(), tmp_path.to_string())])
        })
    }
}

fn utf8_tmp_path(
    tmp_path: &std::path::Path,
) -> Result<&str, yadorilink_local_storage::StorageError> {
    tmp_path.to_str().ok_or_else(|| {
        yadorilink_local_storage::StorageError::Io(std::io::Error::other(
            "a temp file path that is not UTF-8 cannot be recorded",
        ))
    })
}

impl yadorilink_local_storage::TempFileLedger for MaterializationTempLedger {
    fn record(
        &self,
        tmp_path: &std::path::Path,
    ) -> Result<(), yadorilink_local_storage::StorageError> {
        let tmp_path = utf8_tmp_path(tmp_path)?;
        let released = self.take_queued();
        let written = self.database.write::<_, SyncSqliteError>(|conn| {
            Self::delete_released(conn, &released)?;
            conn.execute(
                "INSERT OR IGNORE INTO materialization_tmp_files (group_id, tmp_path) \
                 VALUES (?1, ?2)",
                rusqlite::params![self.group_id, tmp_path],
            )?;
            Ok(())
        });
        written.map_err(|e| {
            self.requeue(released);
            yadorilink_local_storage::StorageError::Io(std::io::Error::other(format!(
                "temp file ledger: {e}"
            )))
        })
    }

    fn release(&self, tmp_path: &std::path::Path) {
        let Some(tmp_path) = tmp_path.to_str() else { return };
        let full = {
            let mut queue = self.releases.0.lock().unwrap_or_else(|p| p.into_inner());
            queue.push((self.group_id.clone(), tmp_path.to_string()));
            queue.len() >= MAX_QUEUED_RELEASES
        };
        if full {
            let released = self.take_queued();
            if let Err(error) = self
                .database
                .write::<_, SyncSqliteError>(|conn| Self::delete_released(conn, &released))
            {
                self.requeue(released);
                tracing::warn!(%error, "could not write queued temp file releases; recovery clears them");
            }
        }
    }
}
