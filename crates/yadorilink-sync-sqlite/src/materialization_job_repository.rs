//! `MaterializationJobRepository` owns the on-demand-sync materialization
//! *queue* -- the `materialization_jobs` table (created by
//! [`crate::materialization_jobs::init_materialization_jobs_schema`]) --
//! plus the tightly-coupled
//! crash-recovery intent journal, `materialization_intents`, whose rows
//! record "a materialization write for this path is in progress" so a
//! startup repair can disambiguate a `Hydrated`-but-missing file from an
//! interrupted write. This is a distinct concept from per-file
//! `materialization_state` on the `files` table, which
//! `yadorilink-sync-core`'s `MaterializationStateRepository` owns.
//!
//! Every `materialization_*` queue method here is a thin delegate to a free
//! function in [`crate::materialization_jobs`], which already takes a plain
//! `&Connection` and owns the real queue persistence and transition rules.
//! `begin_materialization_intent`/`clear_materialization_intent`/
//! `has_materialization_intent` are plain CRUD directly on
//! `materialization_intents` (no `materialization_jobs` module involved).

use std::sync::Arc;

use crate::error::SyncSqliteError;
use crate::materialization_jobs::{self, MaterializationJob, MaterializationJobState};
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

pub struct MaterializationJobRepository {
    database: Arc<SyncDatabase>,
}

impl MaterializationJobRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Upserts a `Pending` materialization job for `(group_id, path)` — see
    /// `materialization_jobs::enqueue_pending` for the supersession/no-op
    /// rules. This is the single write `handle_change_batch` performs in
    /// place of calling `reconcile_group_paths` inline.
    pub fn materialization_enqueue_pending(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &[u8],
        trigger_lamport: u64,
        now: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::enqueue_pending(
                conn,
                group_id,
                path,
                version_hash,
                trigger_lamport,
                now,
            )
        })
    }

    /// Fetches the current materialization job row for `(group_id, path)`.
    pub fn materialization_get_job(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationJob>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| materialization_jobs::get_job(conn, group_id, path))
    }

    /// Transitions `(group_id, path)`'s job state; see
    /// `materialization_jobs::transition` for the legal-transition,
    /// version-guarded, and lost-race-is-a-noop semantics. `expected_version_hash`
    /// must be the version the caller's own attempt was actually working on —
    /// a mismatch (a concurrent re-arm to a newer version) makes this a no-op
    /// rather than clobbering the newer row.
    #[allow(clippy::too_many_arguments)]
    pub fn materialization_transition(
        &self,
        group_id: &str,
        path: &str,
        expected_version_hash: &[u8],
        from: MaterializationJobState,
        to: MaterializationJobState,
        waiting_reason: Option<&str>,
        next_retry_at: Option<i64>,
        now: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::transition(
                conn,
                group_id,
                path,
                expected_version_hash,
                from,
                to,
                waiting_reason,
                next_retry_at,
                now,
            )
        })
    }

    /// Marks `(group_id, path)`'s job into `Backoff`, incrementing its
    /// attempt counter and scheduling the next retry. Version-guarded exactly
    /// like `materialization_transition` above.
    #[allow(clippy::too_many_arguments)]
    pub fn materialization_mark_backoff(
        &self,
        group_id: &str,
        path: &str,
        expected_version_hash: &[u8],
        from: MaterializationJobState,
        waiting_reason: &str,
        next_retry_at: i64,
        now: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::mark_backoff(
                conn,
                group_id,
                path,
                expected_version_hash,
                from,
                waiting_reason,
                next_retry_at,
                now,
            )
        })
    }

    /// Reschedules `(group_id, path)`'s job with a short fixed delay,
    /// WITHOUT incrementing `attempt` — for when the caller's own attempt
    /// never actually ran (audit contention), not a real failure. See
    /// `materialization_jobs::reschedule_after_skip`'s doc comment.
    pub fn materialization_reschedule_after_skip(
        &self,
        group_id: &str,
        path: &str,
        expected_version_hash: &[u8],
        from: MaterializationJobState,
        next_retry_at: i64,
        now: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::reschedule_after_skip(
                conn,
                group_id,
                path,
                expected_version_hash,
                from,
                next_retry_at,
                now,
            )
        })
    }

    /// Marks `(group_id, path)`'s job `Superseded` iff it still matches
    /// `stale_version_hash` — the CONV-7 enforcement primitive, called both
    /// promptly on a newer head's admission and authoritatively from the
    /// engine's in-lock freshness check immediately before a commit.
    pub fn materialization_mark_superseded_if_version_matches(
        &self,
        group_id: &str,
        path: &str,
        stale_version_hash: &[u8],
        now: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::mark_superseded_if_version_matches(
                conn,
                group_id,
                path,
                stale_version_hash,
                now,
            )
        })
    }

    /// Every job currently runnable (`Pending`, or waiting/backoff with an
    /// elapsed `next_retry_at`) — the Convergence Engine scheduler's own
    /// polling primitive, used as the fallback alongside its event-driven
    /// wake notifications.
    pub fn materialization_claim_runnable_jobs(
        &self,
        now: i64,
        stale_active_before: i64,
        per_group_limit: u32,
        total_limit: u32,
    ) -> Result<Vec<MaterializationJob>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            materialization_jobs::claim_runnable_jobs(
                conn,
                now,
                stale_active_before,
                per_group_limit,
                total_limit,
            )
        })
    }

    /// Every job not `Completed`/`Superseded` — used once at daemon startup
    /// to resume in-flight materialization after a crash/restart.
    pub fn materialization_list_unfinished_jobs(
        &self,
    ) -> Result<Vec<MaterializationJob>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(materialization_jobs::list_unfinished_jobs)
    }

    /// Unconditionally re-arms every non-terminal materialization job to
    /// `Pending` — the daemon-startup crash-recovery primitive. See
    /// `materialization_jobs::recover_after_restart`'s doc comment for why
    /// this must NOT be implemented via `materialization_enqueue_pending`.
    /// Returns the number of rows re-armed.
    pub fn materialization_recover_after_restart(
        &self,
        now: i64,
    ) -> Result<usize, SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            materialization_jobs::recover_after_restart(conn, now)
        })
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
        permit: &RootCommitPermit<'_>,
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
        permit: &RootCommitPermit<'_>,
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
}
