//! Persistence for the Convergence Engine's durable materialization jobs,
//! stored in the same SQLite database as the file index and change DAG.
//!
//! A `materialization_jobs` row, keyed `(group_id, path)`, replaces the old
//! `applied: bool` + retry-on-next-batch model: it is a single source of
//! truth for "why is this path not materialized yet" that survives a daemon
//! restart and never depends on transient in-memory state or log output.
//! Message handling (`peer_session.rs`'s `handle_change_batch`) only ever
//! upserts a row here — it never awaits the fetch/materialize work itself;
//! the engine that drives a job through its states lives in the daemon
//! crate (`yadorilink_daemon::convergence`), which calls the functions here
//! plus the DAG/path-resolution primitives already in this crate.
//!
//! Every function here takes a plain `&Connection`, matching `dag_store`'s
//! convention: a `rusqlite::Transaction` dereferences to `Connection`, so a
//! caller that needs this write to commit atomically with another can pass
//! `&tx` instead of going through `SyncState`'s own pooled-connection
//! wrapper methods.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;

/// Creates the `materialization_jobs` table if it does not exist. New table
/// only — like `dag_store::init_dag_schema`'s own tables, a bare `CREATE
/// TABLE IF NOT EXISTS` is the whole migration.
pub fn init_materialization_jobs_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS materialization_jobs (
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            version_hash      BLOB NOT NULL,
            priority          INTEGER NOT NULL DEFAULT 0,
            state             TEXT NOT NULL,
            attempt           INTEGER NOT NULL DEFAULT 0,
            next_retry_at     INTEGER,
            waiting_reason    TEXT,
            last_progress_at  INTEGER NOT NULL,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        CREATE INDEX IF NOT EXISTS idx_materialization_jobs_runnable
            ON materialization_jobs (state, next_retry_at);
        "#,
    )?;
    // Lightweight migration, same idempotent shape as `index.rs`'s own
    // `ALTER TABLE ... ADD COLUMN` loop: a database from before this column
    // existed silently keeps `trigger_lamport = 0` on every pre-existing
    // row, which is safe -- `enqueue_pending`'s guard below only ever
    // widens what a plain 0 already permits (any real lamport is >= 0).
    //
    // Carries the triggering change's lamport directly on the row so the
    // re-arm guard (`enqueue_pending`'s `WHERE` clause) can compare and
    // write in a single statement. A confirmed, reproduced race (an
    // independent review caught this) made the previous shape -- a
    // separate `SELECT` in `existing_nonterminal_job_lamport` followed by
    // an unconditional `INSERT ... ON CONFLICT DO UPDATE` here -- not
    // atomic: two concurrent peer sessions could both read the same
    // pre-update lamport, decide their own (different) trigger is newer,
    // and then race their writes, letting whichever write lands SECOND win
    // regardless of which trigger was actually causally newer. Comparing
    // inside the same statement that writes closes that window; no two
    // writers can observe a stale row between reading it and writing it.
    match conn.execute(
        "ALTER TABLE materialization_jobs ADD COLUMN trigger_lamport INTEGER NOT NULL DEFAULT 0",
        [],
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
            if msg.starts_with("duplicate column name") =>
        {
            // Already migrated.
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// A materialization job's current state. Stored as `TEXT`, not an integer
/// discriminant, so the table stays human-debuggable (`sqlite3 ... 'select
/// state, waiting_reason from materialization_jobs'`) without decoding — the
/// whole stated point of this table is answering "why is this not done yet"
/// without tracing logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MaterializationJobState {
    Pending,
    Planning,
    WaitingForSource,
    WaitingForCredit,
    Fetching,
    ReadyToCommit,
    Backoff,
    Completed,
    Superseded,
}

impl MaterializationJobState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MaterializationJobState::Pending => "pending",
            MaterializationJobState::Planning => "planning",
            MaterializationJobState::WaitingForSource => "waiting_for_source",
            MaterializationJobState::WaitingForCredit => "waiting_for_credit",
            MaterializationJobState::Fetching => "fetching",
            MaterializationJobState::ReadyToCommit => "ready_to_commit",
            MaterializationJobState::Backoff => "backoff",
            MaterializationJobState::Completed => "completed",
            MaterializationJobState::Superseded => "superseded",
        }
    }

    /// Fail-closed, unlike `MaterializationPolicy::from_db_str`'s lenient
    /// default: an unparseable job state means the job table itself is
    /// corrupt, and silently coercing it to `Pending` would re-run
    /// materialization from an assumed-clean state over whatever the job
    /// actually was mid-way through — the same class of masked corruption
    /// `blocks_json` parsing already refuses to allow
    /// elsewhere in this crate.
    pub fn from_db_str(s: &str) -> Result<Self, SyncSqliteError> {
        match s {
            "pending" => Ok(MaterializationJobState::Pending),
            "planning" => Ok(MaterializationJobState::Planning),
            "waiting_for_source" => Ok(MaterializationJobState::WaitingForSource),
            "waiting_for_credit" => Ok(MaterializationJobState::WaitingForCredit),
            "fetching" => Ok(MaterializationJobState::Fetching),
            "ready_to_commit" => Ok(MaterializationJobState::ReadyToCommit),
            "backoff" => Ok(MaterializationJobState::Backoff),
            "completed" => Ok(MaterializationJobState::Completed),
            "superseded" => Ok(MaterializationJobState::Superseded),
            other => Err(SyncSqliteError::CorruptState(format!(
                "materialization_jobs row has an unrecognized state: {other:?}"
            ))),
        }
    }

    /// Whether `self -> to` is a legal job-state transition. Enforced by
    /// every write in this module so an illegal transition is caught at the
    /// point it would be written, not discovered later from a job stuck in
    /// an impossible state.
    ///
    /// | From                | Legal To                                                                        |
    /// |---------------------|----------------------------------------------------------------------------------|
    /// | Pending             | Planning, Superseded                                                             |
    /// | Planning            | WaitingForSource, WaitingForCredit, Fetching, ReadyToCommit, Backoff, Completed, Superseded, Planning (stale reclaim) |
    /// | WaitingForSource     | Fetching, Backoff, Superseded                                                   |
    /// | WaitingForCredit     | Fetching, Backoff, Superseded                                                   |
    /// | Fetching            | ReadyToCommit, WaitingForSource, WaitingForCredit, Backoff, Superseded, Planning (stale reclaim) |
    /// | Backoff             | Planning, Superseded                                                             |
    /// | ReadyToCommit       | Completed, Superseded, Planning (stale reclaim)                                 |
    /// | Completed           | Superseded                                                                       |
    /// | Superseded          | *(terminal — no legal transition out)*                                          |
    ///
    /// `Planning -> Completed` (alongside `ReadyToCommit -> Completed`) is
    /// a confirmed, reproduced fix (see
    /// `fix/conflict-copy-convergence-obligation-20260723`): Stage 1's
    /// engine (`crates/yadorilink-daemon/src/convergence/engine.rs`) only
    /// ever drives a job through `Pending -> Planning -> (Completed |
    /// Backoff)` -- it never uses the `WaitingForSource`/`WaitingForCredit`/
    /// `Fetching`/`ReadyToCommit` states Stage 2/3 will need, so its own
    /// `Planning -> Completed` call had no legal path in this table at all.
    /// The call site discarded the resulting error (`let _ = ...`), so this
    /// was a SILENT no-op: every job the engine believed it had completed
    /// stayed in `Planning` forever (until the next admission re-armed it,
    /// or the 120s stale-reclaim cycled it back through `Planning` again --
    /// never actually reaching a terminal state). Content still converged
    /// correctly regardless, since `materialize`/`reconcile_group_paths`
    /// write disk directly, independent of this table entirely -- which is
    /// exactly why this went unnoticed until a dedicated test asserted the
    /// job table itself reaches quiescence, not just final disk content.
    ///
    /// The three "stale reclaim" entries exist for `claim_runnable_jobs`'s
    /// stale-active-processing reclaim (see its own doc comment) — a job
    /// abandoned mid-attempt (its owning tick died between claiming it and
    /// writing a real outcome) resets to `Planning` to restart, regardless
    /// of which active-processing state it was abandoned in.
    pub fn can_transition_to(self, to: MaterializationJobState) -> bool {
        use MaterializationJobState::*;
        match (self, to) {
            (Pending, Planning | Superseded) => true,
            (
                Planning,
                WaitingForSource | WaitingForCredit | Fetching | ReadyToCommit | Backoff
                | Completed | Superseded,
            ) => true,
            (WaitingForSource, Fetching | Backoff | Superseded) => true,
            (WaitingForCredit, Fetching | Backoff | Superseded) => true,
            (
                Fetching,
                ReadyToCommit | WaitingForSource | WaitingForCredit | Backoff | Superseded,
            ) => true,
            (Backoff, Planning | Superseded) => true,
            (ReadyToCommit, Completed | Superseded) => true,
            (Completed, Superseded) => true,
            // Reclaim of a stale active-processing row (see
            // `claim_runnable_jobs`'s `stale_active_before` clause and
            // `crates/yadorilink-daemon/src/convergence/engine.rs`'s
            // `STALE_ACTIVE_PROCESSING_THRESHOLD`): any state a job can be
            // abandoned mid-attempt in — including `Planning` itself,
            // reclaimed after the tick that put it there never wrote a
            // further outcome — resets to `Planning` to restart the
            // attempt, exactly as `resume_after_restart`'s Pending re-arm
            // eventually leads to via a fresh claim. Superseded is
            // deliberately excluded: a superseded row is terminal, not
            // reclaimable.
            (Planning | Fetching | ReadyToCommit, Planning) => true,
            (Superseded, _) => false,
            _ => false,
        }
    }
}

/// A `materialization_jobs` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializationJob {
    pub group_id: String,
    pub path: String,
    pub version_hash: Vec<u8>,
    pub priority: i64,
    pub state: MaterializationJobState,
    pub attempt: u32,
    pub next_retry_at: Option<i64>,
    pub waiting_reason: Option<String>,
    pub last_progress_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// Lamport clock of the change whose admission most recently (re-)armed
    /// this job — see `enqueue_pending`'s own doc comment for why this is
    /// stored on the row instead of re-derived via a lookup of
    /// `version_hash`'s change.
    pub trigger_lamport: u64,
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<MaterializationJob> {
    let state_str: String = row.get("state")?;
    let state = MaterializationJobState::from_db_str(&state_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(MaterializationJob {
        group_id: row.get("group_id")?,
        path: row.get("path")?,
        version_hash: row.get("version_hash")?,
        priority: row.get("priority")?,
        state,
        attempt: row.get::<_, i64>("attempt")? as u32,
        next_retry_at: row.get("next_retry_at")?,
        waiting_reason: row.get("waiting_reason")?,
        last_progress_at: row.get("last_progress_at")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        trigger_lamport: row.get::<_, i64>("trigger_lamport")? as u64,
    })
}

/// Error returned when an update in this module would perform an illegal
/// job-state transition (validated against
/// `MaterializationJobState::can_transition_to`). Wrapped up as
/// `SyncSqliteError::InvalidInput` (this crate's existing "rejected before any
/// state is written" variant) rather than a bespoke variant, since the
/// caller-facing contract is the same: a bad transition is refused, not
/// partially applied.
fn invalid_transition(from: MaterializationJobState, to: MaterializationJobState) -> SyncSqliteError {
    SyncSqliteError::InvalidInput(format!(
        "illegal materialization job transition: {:?} -> {:?}",
        from, to
    ))
}

/// Fetches the current job row for `(group_id, path)`, if any.
pub fn get_job(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<MaterializationJob>, SyncSqliteError> {
    conn.query_row(
        "SELECT group_id, path, version_hash, priority, state, attempt, next_retry_at, \
         waiting_reason, last_progress_at, created_at, updated_at, trigger_lamport \
         FROM materialization_jobs WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        row_to_job,
    )
    .optional()
    .map_err(Into::into)
}

/// Upserts a `Pending` job for `(group_id, path)` at `version_hash`/
/// `trigger_lamport` — the single write `handle_change_batch` performs
/// instead of calling `reconcile_group_paths` inline. Bounded, local-only,
/// no network/disk-content I/O: exactly the operation CONV-1 requires
/// message handling to do instead of awaiting a fetch.
///
/// If an existing row for this path is not yet terminal (`Completed`/
/// `Superseded`) and `trigger_lamport` is causally at least as new as the
/// row's own, it is re-armed to `Pending` at the new `version_hash`/
/// `trigger_lamport` regardless of its current state (this *is*
/// supersession — an in-flight attempt for the old version must not be
/// trusted to still be correct once a newer head is admitted;
/// `commit_ready_job`'s own in-lock freshness check is the second,
/// authoritative enforcement point, but re-arming here promptly wakes the
/// scheduler rather than waiting for that job's own backoff to expire). If
/// the existing row already matches `version_hash` and is non-terminal, or
/// `trigger_lamport` is causally OLDER than the row's own while the row is
/// still non-terminal, the row is left alone rather than being reset to
/// `Pending`:
///
/// - Same version, non-terminal: a real in-progress attempt, must not be
///   reset (loses no information, an identical admission has nothing new
///   to say).
///
/// - Same version, `Completed`: ALSO a no-op -- a confirmed, reproduced
///   livelock (see `fix/conflict-copy-convergence-obligation-20260723`): a
///   change this device already applied gets re-forwarded/re-mentioned by
///   routine mesh traffic (gossip, resync) with no new information at all,
///   yet every such mention used to unconditionally reset an
///   already-correctly-`Completed` job back to `Pending` -- observed
///   racing the SAME job's own claim/finalize cycle closely enough to
///   occasionally leave it stuck in `Planning` with no further trigger to
///   re-drive it (invisible to `claim_runnable_jobs` for a full
///   `STALE_ACTIVE_PROCESSING_THRESHOLD`, 120s). `Superseded` remains
///   excluded deliberately: it is a terminal statement about a STALE
///   version, so a fresh admission at that same (now superseded) hash
///   should still be examined rather than silently dropped, in case
///   something upstream legitimately un-supersedes it (not expected today,
///   but this function has no way to know that, so it stays conservative
///   here).
///
/// - Different version, non-terminal, causally older `trigger_lamport`: a
///   confirmed, reproduced livelock (see the same branch) with the DAG's
///   live head set genuinely unchanged, several concurrent (non-winning)
///   changes touching the same path, arriving out of causal order across
///   separate batches, each independently re-arming this path's job to
///   `Pending` with their own hash -- discarding real in-flight work each
///   time for no actual new information.
///
/// The version/state/lamport comparison and the write happen in the SAME
/// `INSERT ... ON CONFLICT DO UPDATE ... WHERE` statement rather than a
/// separate `SELECT` followed by a conditional `INSERT`/`UPDATE` -- an
/// independent review caught the previous two-step shape as a genuine race:
/// two concurrent peer sessions could each read the row's pre-update
/// `trigger_lamport`, each independently decide their own (different)
/// trigger is not older, and then have their writes race, letting whichever
/// one commits SECOND win even if it was actually the causally OLDER
/// trigger. A single UPSERT statement's `WHERE` clause is evaluated by
/// SQLite atomically against the row's current, fully up-to-date content at
/// the moment it resolves the conflict, so no writer can act on a value
/// another writer has since superseded.
pub fn enqueue_pending(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version_hash: &[u8],
    trigger_lamport: u64,
    now: i64,
) -> Result<(), SyncSqliteError> {
    let trigger_lamport = i64::try_from(trigger_lamport).unwrap_or(i64::MAX);
    conn.execute(
        "INSERT INTO materialization_jobs \
         (group_id, path, version_hash, priority, state, attempt, next_retry_at, \
          waiting_reason, last_progress_at, created_at, updated_at, trigger_lamport) \
         VALUES (?1, ?2, ?3, 0, 'pending', 0, NULL, NULL, ?4, ?4, ?4, ?5) \
         ON CONFLICT (group_id, path) DO UPDATE SET \
            version_hash = excluded.version_hash, \
            state = 'pending', \
            attempt = 0, \
            next_retry_at = NULL, \
            waiting_reason = NULL, \
            last_progress_at = excluded.last_progress_at, \
            updated_at = excluded.updated_at, \
            trigger_lamport = excluded.trigger_lamport \
         WHERE \
            NOT ( \
                materialization_jobs.version_hash = excluded.version_hash \
                AND materialization_jobs.state != 'superseded' \
            ) \
            AND ( \
                materialization_jobs.state IN ('completed', 'superseded') \
                OR excluded.trigger_lamport >= materialization_jobs.trigger_lamport \
            )",
        rusqlite::params![group_id, path, version_hash, now, trigger_lamport],
    )?;
    Ok(())
}

/// Transitions `(group_id, path)`'s job to `to`, validating the transition
/// is legal for its current stored state first. `waiting_reason`/
/// `next_retry_at` are set as given (callers pass `None` for states that
/// have no wait). Returns `Ok(false)` (a no-op, not an error) if the job row
/// no longer exists, its state has already moved on to something this
/// caller's expected `from` doesn't match, or (critically)
/// `expected_version_hash` no longer matches the row's current
/// `version_hash` — the caller lost a race with a concurrent
/// supersession/re-arm and should simply stop, not retry.
///
/// The version guard matters beyond the state guard: a caller that claimed
/// this job, ran a (possibly slow) materialization attempt for
/// `expected_version_hash`, and is now writing back its outcome must not
/// clobber a *newer* admission that re-armed this row to a different
/// version while the attempt was in flight (`enqueue_pending` re-arms to
/// `Pending` on a version change, which by itself does not block a
/// same-state-different-version `UPDATE` from also matching — the version
/// check here is what actually closes that race).
#[allow(clippy::too_many_arguments)]
pub fn transition(
    conn: &Connection,
    group_id: &str,
    path: &str,
    expected_version_hash: &[u8],
    from: MaterializationJobState,
    to: MaterializationJobState,
    waiting_reason: Option<&str>,
    next_retry_at: Option<i64>,
    now: i64,
) -> Result<bool, SyncSqliteError> {
    if !from.can_transition_to(to) {
        return Err(invalid_transition(from, to));
    }
    let updated = conn.execute(
        "UPDATE materialization_jobs SET state = ?1, waiting_reason = ?2, next_retry_at = ?3, \
         last_progress_at = ?4, updated_at = ?4 \
         WHERE group_id = ?5 AND path = ?6 AND state = ?7 AND version_hash = ?8",
        rusqlite::params![
            to.as_db_str(),
            waiting_reason,
            next_retry_at,
            now,
            group_id,
            path,
            from.as_db_str(),
            expected_version_hash,
        ],
    )?;
    Ok(updated > 0)
}

/// Marks `(group_id, path)`'s job as failed-this-attempt, incrementing
/// `attempt` and scheduling `next_retry_at` via the caller-supplied backoff
/// duration (see `yadorilink_daemon::convergence::backoff::next_backoff`,
/// which computes this from `attempt`) — the fallback path for a job with
/// no more specific wake condition. `waiting_reason` records why, so the row
/// stays self-explanatory without tracing logs. Version-guarded exactly like
/// `transition` — see its doc comment for the race this closes: a caller
/// reporting a failed attempt for `expected_version_hash` must not
/// clobber a newer re-armed row with a stale backoff schedule.
#[allow(clippy::too_many_arguments)]
pub fn mark_backoff(
    conn: &Connection,
    group_id: &str,
    path: &str,
    expected_version_hash: &[u8],
    from: MaterializationJobState,
    waiting_reason: &str,
    next_retry_at: i64,
    now: i64,
) -> Result<bool, SyncSqliteError> {
    if !from.can_transition_to(MaterializationJobState::Backoff) {
        return Err(invalid_transition(from, MaterializationJobState::Backoff));
    }
    let updated = conn.execute(
        "UPDATE materialization_jobs SET state = 'backoff', waiting_reason = ?1, \
         next_retry_at = ?2, attempt = attempt + 1, updated_at = ?3 \
         WHERE group_id = ?4 AND path = ?5 AND state = ?6 AND version_hash = ?7",
        rusqlite::params![
            waiting_reason,
            next_retry_at,
            now,
            group_id,
            path,
            from.as_db_str(),
            expected_version_hash,
        ],
    )?;
    Ok(updated > 0)
}

/// Marks `(group_id, path)`'s job `Backoff` with a short, fixed
/// `next_retry_at` and WITHOUT incrementing `attempt` — for a caller whose
/// own attempt never actually got a chance to run (e.g. the Convergence
/// Engine's `run_once` finding `reconcile_local_materialization_audit` was
/// skipped due to another audit already in flight for the same group).
/// Distinct from `mark_backoff`: that function is for a *real* failed
/// attempt, and incrementing `attempt` there is what drives the growing
/// backoff schedule — applying that same penalty to a job that was never
/// actually attempted this tick would extend its retry delay for no reason,
/// and (compounded across many jobs sharing a contended group) risks
/// exactly the kind of spurious multi-second stall this table exists to
/// make diagnosable rather than silently amplify.
pub fn reschedule_after_skip(
    conn: &Connection,
    group_id: &str,
    path: &str,
    expected_version_hash: &[u8],
    from: MaterializationJobState,
    next_retry_at: i64,
    now: i64,
) -> Result<bool, SyncSqliteError> {
    if !from.can_transition_to(MaterializationJobState::Backoff) {
        return Err(invalid_transition(from, MaterializationJobState::Backoff));
    }
    let updated = conn.execute(
        "UPDATE materialization_jobs SET state = 'backoff', \
         waiting_reason = 'a concurrent materialization audit was already running for this \
         group; retrying shortly', next_retry_at = ?1, updated_at = ?2 \
         WHERE group_id = ?3 AND path = ?4 AND state = ?5 AND version_hash = ?6",
        rusqlite::params![
            next_retry_at,
            now,
            group_id,
            path,
            from.as_db_str(),
            expected_version_hash,
        ],
    )?;
    Ok(updated > 0)
}

/// Marks `(group_id, path)`'s job `Superseded` if it currently matches
/// `stale_version_hash` and is not already terminal — a no-op (not an
/// error) if the row has moved on to a different version or state already,
/// since that means a concurrent writer already resolved it. This is the
/// enforcement primitive for CONV-7: called both promptly (when a newer
/// head is admitted, via `enqueue_pending`'s re-arm above) and
/// authoritatively (from `commit_ready_job`'s in-lock freshness check,
/// immediately before any write would land).
pub fn mark_superseded_if_version_matches(
    conn: &Connection,
    group_id: &str,
    path: &str,
    stale_version_hash: &[u8],
    now: i64,
) -> Result<bool, SyncSqliteError> {
    let updated = conn.execute(
        "UPDATE materialization_jobs SET state = 'superseded', waiting_reason = NULL, \
         next_retry_at = NULL, updated_at = ?1 \
         WHERE group_id = ?2 AND path = ?3 AND version_hash = ?4 AND state != 'superseded'",
        rusqlite::params![now, group_id, path, stale_version_hash],
    )?;
    Ok(updated > 0)
}

/// Unconditionally re-arms every non-terminal job (anything not `Completed`/
/// `Superseded`) to `Pending`, regardless of its current state or version —
/// the daemon-startup crash-recovery primitive. Deliberately NOT built on
/// `enqueue_pending`: that function's "same version + non-terminal = no-op"
/// rule is correct for its own purpose (a routine re-admission must not
/// discard real in-progress work), but is exactly wrong here — a job
/// crash-recovery is re-arming necessarily has the SAME version it did
/// before the crash (nothing new was admitted; the daemon just restarted),
/// so `enqueue_pending` would treat every single one as a no-op and leave
/// it stuck in whatever non-`Pending` state it crashed in, forever (a
/// `Planning`/`Fetching`/`ReadyToCommit` row is never claimed by
/// `claim_runnable_jobs`, which only picks up `Pending` or a due
/// `Backoff`/`WaitingFor*` row). One bulk `UPDATE` in a single statement —
/// no per-row round trip, no version comparison — because at restart every
/// row's in-memory fetch/gate state is already gone regardless of what its
/// persisted state says, so there is nothing to preserve.
pub fn recover_after_restart(conn: &Connection, now: i64) -> Result<usize, SyncSqliteError> {
    let updated = conn.execute(
        "UPDATE materialization_jobs SET state = 'pending', next_retry_at = NULL, \
         waiting_reason = 'recovered after daemon restart', updated_at = ?1 \
         WHERE state NOT IN ('completed', 'superseded')",
        rusqlite::params![now],
    )?;
    Ok(updated)
}

/// Every job currently runnable, capped per group so one group with many
/// pending paths cannot crowd every other group out of a single claim call
/// (a real gap an independent review caught: `LIMIT` alone with no
/// per-group fairness meant a group that keeps admitting many paths could
/// starve every other group indefinitely). A job is runnable if it is:
/// - `Pending` (always runnable);
/// - a waiting/backoff state whose `next_retry_at` has elapsed; or
/// - an *active-processing* state (`Planning`/`Fetching`/`ReadyToCommit` —
///   states with no `next_retry_at` of their own) that has sat unchanged
///   since before `stale_active_before`. This is the recovery path for a
///   job whose owning engine tick died between claiming it and writing its
///   outcome (a scheduler-task panic, a final `Backoff`/`Completed`
///   write itself failing, or any other abandonment short of a full daemon
///   restart) — another real gap an independent review caught: without
///   this, only `resume_after_restart` at daemon *startup* could ever
///   un-stick such a job, so a mid-tick failure that didn't crash the whole
///   process left it stuck until the next restart. `stale_active_before`
///   should be comfortably longer than this engine's own worst-case single
///   attempt (multiple sequential peer attempts, each up to
///   `HYDRATION_TIMEOUT`) so a job still being legitimately worked on is
///   never mistaken for abandoned.
///
/// Within each group, ranked by `priority DESC, next_retry_at ASC` (a
/// `Pending` job, with no `next_retry_at`, sorts before one merely due for
/// retry) and capped at `per_group_limit`; the overall result is still
/// capped at `total_limit`.
pub fn claim_runnable_jobs(
    conn: &Connection,
    now: i64,
    stale_active_before: i64,
    per_group_limit: u32,
    total_limit: u32,
) -> Result<Vec<MaterializationJob>, SyncSqliteError> {
    // `path ASC` is a deterministic final tie-breaker, not a priority
    // signal: without it, two rows with equal `priority` and equally-NULL
    // `next_retry_at` (e.g. a fresh `Pending` row and a reclaimed stale
    // `Planning` row for the same group) rank against each other in
    // otherwise-unspecified order.
    let mut stmt = conn.prepare(
        "WITH runnable AS ( \
            SELECT *, ROW_NUMBER() OVER ( \
                PARTITION BY group_id ORDER BY priority DESC, next_retry_at ASC, path ASC \
            ) AS group_rank \
            FROM materialization_jobs \
            WHERE state = 'pending' \
               OR (state IN ('backoff', 'waiting_for_source', 'waiting_for_credit') \
                   AND next_retry_at IS NOT NULL AND next_retry_at <= ?1) \
               OR (state IN ('planning', 'fetching', 'ready_to_commit') \
                   AND updated_at <= ?2) \
         ) \
         SELECT group_id, path, version_hash, priority, state, attempt, next_retry_at, \
                waiting_reason, last_progress_at, created_at, updated_at, trigger_lamport \
         FROM runnable \
         WHERE group_rank <= ?3 \
         ORDER BY priority DESC, next_retry_at ASC, path ASC \
         LIMIT ?4",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![now, stale_active_before, per_group_limit, total_limit],
        row_to_job,
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Every job not `Completed`/`Superseded` — used at daemon startup to
/// resume in-flight work after a crash/restart. Callers reset each to
/// `Planning` with `next_retry_at = now` (see
/// `yadorilink_daemon::convergence::job_store::resume_after_restart`):
/// in-memory fetch/gate state never survives a crash regardless of what the
/// row says, so re-planning against the real block store is the correct
/// and cheap thing to do rather than trying to resurrect partial fetch
/// state that was never persisted.
pub fn list_unfinished_jobs(conn: &Connection) -> Result<Vec<MaterializationJob>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT group_id, path, version_hash, priority, state, attempt, next_retry_at, \
         waiting_reason, last_progress_at, created_at, updated_at, trigger_lamport \
         FROM materialization_jobs WHERE state NOT IN ('completed', 'superseded')",
    )?;
    let rows = stmt.query_map([], row_to_job)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_materialization_jobs_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = open_test_db();
        // Calling init again must not error (CREATE TABLE IF NOT EXISTS).
        init_materialization_jobs_schema(&conn).unwrap();
    }

    #[test]
    fn enqueue_then_get_round_trips() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
        assert_eq!(job.version_hash, b"hash1");
        assert_eq!(job.attempt, 0);
        assert!(job.waiting_reason.is_none());
    }

    #[test]
    fn enqueue_same_version_while_non_terminal_is_a_noop() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        // Re-enqueuing the same version while Planning must not reset progress.
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 102, 102).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Planning);
    }

    #[test]
    fn enqueue_new_version_rearms_to_pending() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            MaterializationJobState::Fetching,
            None,
            None,
            102,
        )
        .unwrap();
        // A newer DAG head for the same path arrives.
        enqueue_pending(&conn, "g1", "a.txt", b"hash2", 103, 103).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
        assert_eq!(job.version_hash, b"hash2");
    }

    /// Regression test for a confirmed, reproduced livelock (see
    /// `fix/conflict-copy-convergence-obligation-20260723`): routine mesh
    /// traffic (gossip, resync) keeps re-mentioning a path whose change
    /// this device already applied, with no new information at all. Before
    /// this fix, `enqueue_pending` unconditionally reset an already-
    /// `Completed` job back to `Pending` even when the incoming
    /// `version_hash` exactly matched what had already completed --
    /// observed racing the same job's own claim/finalize cycle closely
    /// enough to occasionally leave it stuck in `Planning` for a full
    /// `STALE_ACTIVE_PROCESSING_THRESHOLD` (120s) with nothing left to
    /// re-drive it. A same-hash re-admission of an already-settled job
    /// must be a true no-op.
    #[test]
    fn enqueue_same_version_while_completed_is_a_noop() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            MaterializationJobState::Completed,
            None,
            None,
            102,
        )
        .unwrap();
        // Routine re-forwarding of the same, already-applied change --
        // must not reset the job away from Completed.
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 103, 103).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Completed);
        assert_eq!(job.updated_at, 102, "a true no-op must not even touch updated_at");
    }

    /// A genuinely NEWER version must still re-arm an already-`Completed`
    /// job -- the no-op fix above must not accidentally suppress real
    /// supersession.
    #[test]
    fn enqueue_new_version_still_rearms_a_completed_job() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            MaterializationJobState::Completed,
            None,
            None,
            102,
        )
        .unwrap();
        enqueue_pending(&conn, "g1", "a.txt", b"hash2", 103, 103).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
        assert_eq!(job.version_hash, b"hash2");
    }

    /// Regression test for a confirmed, non-atomic-race bug an independent
    /// review caught (see `fix/conflict-copy-convergence-obligation-20260723`):
    /// the guard against re-arming a job to a causally OLDER trigger used to
    /// be a separate `SELECT` (read the existing job's lamport) followed by a
    /// conditional `INSERT`/`UPDATE`, done as two round-trips from the
    /// caller. Two concurrent callers could each read the same pre-update
    /// row, each decide their own (different) trigger was not older, and
    /// then race their writes -- letting whichever one committed SECOND win
    /// even if it was causally older. `enqueue_pending` now folds the
    /// comparison into the SAME `INSERT ... ON CONFLICT DO UPDATE ... WHERE`
    /// statement as the write, so this test exercises the guard directly
    /// through the public function rather than needing two threads to prove
    /// the comparison and the write can no longer be pulled apart.
    #[test]
    fn enqueue_pending_rejects_a_causally_older_trigger_for_a_nonterminal_job() {
        let conn = open_test_db();
        // trigger_lamport = 10, still Pending (non-terminal).
        enqueue_pending(&conn, "g1", "a.txt", b"hash-new", 10, 100).unwrap();
        // A causally OLDER admission (lamport 5) for a different version
        // arrives late -- must be rejected; the row keeps tracking the
        // newer trigger/version.
        enqueue_pending(&conn, "g1", "a.txt", b"hash-old", 5, 101).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.version_hash, b"hash-new");
        assert_eq!(job.trigger_lamport, 10);
        assert_eq!(job.updated_at, 100, "a rejected re-arm must not even touch updated_at");
    }

    /// A terminal job (`Completed`/`Superseded`) has nothing further to
    /// protect, so a fresh admission always supersedes it regardless of
    /// lamport ordering -- the lamport guard applies only to non-terminal
    /// rows, matching `enqueue_new_version_still_rearms_a_completed_job`'s
    /// same-direction guarantee but with a DECREASING lamport, which the
    /// guard must not reject.
    #[test]
    fn enqueue_pending_lamport_guard_does_not_apply_to_a_completed_job() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            MaterializationJobState::Completed,
            None,
            None,
            102,
        )
        .unwrap();
        // A causally OLDER-looking trigger (lamport 1, far below the
        // completed job's own 100) still re-arms it -- terminal state
        // bypasses the lamport comparison entirely.
        enqueue_pending(&conn, "g1", "a.txt", b"hash2", 1, 103).unwrap();
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
        assert_eq!(job.version_hash, b"hash2");
        assert_eq!(job.trigger_lamport, 1);
    }

    #[test]
    fn claim_runnable_returns_pending_and_due_backoff_but_not_future_backoff() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "pending.txt", b"h", 100, 100).unwrap();

        enqueue_pending(&conn, "g1", "due.txt", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "due.txt",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        mark_backoff(
            &conn,
            "g1",
            "due.txt",
            b"h",
            MaterializationJobState::Planning,
            "no reachable peer",
            150,
            102,
        )
        .unwrap();

        enqueue_pending(&conn, "g1", "future.txt", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "future.txt",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        mark_backoff(
            &conn,
            "g1",
            "future.txt",
            b"h",
            MaterializationJobState::Planning,
            "no reachable peer",
            9_999,
            102,
        )
        .unwrap();

        let runnable = claim_runnable_jobs(&conn, 200, 0, 100, 10).unwrap();
        let paths: Vec<&str> = runnable.iter().map(|j| j.path.as_str()).collect();
        assert!(paths.contains(&"pending.txt"));
        assert!(paths.contains(&"due.txt"));
        assert!(!paths.contains(&"future.txt"));
    }

    /// Regression test for a real gap an independent review caught: a plain
    /// `LIMIT` with no per-group fairness lets one group with many pending
    /// paths crowd out every other group's jobs from a single claim call.
    #[test]
    fn claim_runnable_jobs_caps_per_group_so_one_group_cannot_starve_another() {
        let conn = open_test_db();
        for i in 0..10 {
            enqueue_pending(&conn, "busy-group", &format!("busy-{i}.bin"), b"h", 100, 100).unwrap();
        }
        enqueue_pending(&conn, "quiet-group", "quiet.bin", b"h", 100, 100).unwrap();

        // Per-group cap of 3, overall cap generous (20) — without the
        // per-group cap, busy-group's 10 pending jobs alone would already
        // exhaust a small overall limit before quiet-group's single job is
        // ever considered.
        let runnable = claim_runnable_jobs(&conn, 200, 0, 3, 20).unwrap();
        let busy_count = runnable.iter().filter(|j| j.group_id == "busy-group").count();
        let quiet_count = runnable.iter().filter(|j| j.group_id == "quiet-group").count();
        assert_eq!(busy_count, 3, "busy-group must be capped at the per-group limit");
        assert_eq!(quiet_count, 1, "quiet-group's job must still be claimed despite busy-group");
    }

    /// Regression test for a real gap an independent review caught: without
    /// this, a job whose owning engine tick died between claiming it and
    /// writing its final outcome (a scheduler-task panic, or the final
    /// Backoff/Completed write itself failing) stayed stuck in an active-
    /// processing state (`Planning`/`Fetching`/`ReadyToCommit`, none of
    /// which `claim_runnable_jobs` otherwise ever re-selects) until the next
    /// full daemon restart — `resume_after_restart` alone cannot help a
    /// same-process failure that never actually restarts the daemon.
    #[test]
    fn claim_runnable_jobs_reclaims_stale_active_processing_states_but_not_fresh_ones() {
        let conn = open_test_db();

        enqueue_pending(&conn, "g1", "stale.bin", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "stale.bin",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101, // updated_at = 101, well before the staleness cutoff below
        )
        .unwrap();

        enqueue_pending(&conn, "g1", "fresh.bin", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "fresh.bin",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            199, // updated_at = 199, just before "now" — still legitimately in flight
        )
        .unwrap();

        // now=200, stale_active_before=150: "stale.bin" (updated_at=101) is
        // older than the cutoff and gets reclaimed; "fresh.bin"
        // (updated_at=199) is not.
        let runnable = claim_runnable_jobs(&conn, 200, 150, 100, 100).unwrap();
        let paths: std::collections::BTreeSet<&str> =
            runnable.iter().map(|j| j.path.as_str()).collect();
        assert!(
            paths.contains("stale.bin"),
            "a Planning job stuck past the staleness cutoff \
                 must be reclaimed even with no daemon restart"
        );
        assert!(
            !paths.contains("fresh.bin"),
            "a Planning job still within the staleness window must not be reclaimed out from \
             under whichever tick is legitimately still processing it"
        );
    }

    #[test]
    fn mark_superseded_if_version_matches_is_noop_for_a_different_version() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        // A concurrent writer already moved this job to hash2.
        enqueue_pending(&conn, "g1", "a.txt", b"hash2", 101, 101).unwrap();
        let changed =
            mark_superseded_if_version_matches(&conn, "g1", "a.txt", b"hash1", 102).unwrap();
        assert!(!changed);
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
        assert_eq!(job.version_hash, b"hash2");
    }

    #[test]
    fn mark_superseded_if_version_matches_supersedes_the_matching_row() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        let changed =
            mark_superseded_if_version_matches(&conn, "g1", "a.txt", b"hash1", 102).unwrap();
        assert!(changed);
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Superseded);
    }

    #[test]
    fn list_unfinished_jobs_excludes_completed_and_superseded() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "done.txt", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "done.txt",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "done.txt",
            b"h",
            MaterializationJobState::Planning,
            MaterializationJobState::ReadyToCommit,
            None,
            None,
            102,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "done.txt",
            b"h",
            MaterializationJobState::ReadyToCommit,
            MaterializationJobState::Completed,
            None,
            None,
            103,
        )
        .unwrap();

        enqueue_pending(&conn, "g1", "stuck.txt", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "stuck.txt",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();

        let unfinished = list_unfinished_jobs(&conn).unwrap();
        let paths: Vec<&str> = unfinished.iter().map(|j| j.path.as_str()).collect();
        assert!(!paths.contains(&"done.txt"));
        assert!(paths.contains(&"stuck.txt"));
    }

    /// Regression test for a real bug an independent review caught: crash
    /// recovery must NOT be implemented via `enqueue_pending` (its "same
    /// version + non-terminal = no-op" rule, correct for ordinary
    /// re-admission, would leave a job crashed mid-`Planning`/`Fetching`/
    /// `ReadyToCommit` stuck in that exact state forever, since
    /// `claim_runnable_jobs` never picks those up). Every non-terminal state
    /// must become `Pending` (and therefore claimable) after
    /// `recover_after_restart`; `Completed`/`Superseded` must be untouched.
    #[test]
    fn recover_after_restart_rearms_every_non_terminal_state_to_pending() {
        let conn = open_test_db();

        // One job in each non-terminal state.
        let non_terminal = [
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            MaterializationJobState::WaitingForSource,
            MaterializationJobState::WaitingForCredit,
            MaterializationJobState::Fetching,
            MaterializationJobState::ReadyToCommit,
            MaterializationJobState::Backoff,
        ];
        for (i, &state) in non_terminal.iter().enumerate() {
            let path = format!("job-{i}.bin");
            enqueue_pending(&conn, "g1", &path, b"h", 100, 100).unwrap();
            // Drive each job to its target state via legal transitions.
            match state {
                MaterializationJobState::Pending => {}
                MaterializationJobState::Planning => {
                    transition(
                        &conn,
                        "g1",
                        &path,
                        b"h",
                        MaterializationJobState::Pending,
                        MaterializationJobState::Planning,
                        None,
                        None,
                        101,
                    )
                    .unwrap();
                }
                MaterializationJobState::WaitingForSource
                | MaterializationJobState::WaitingForCredit
                | MaterializationJobState::Fetching
                | MaterializationJobState::ReadyToCommit => {
                    transition(
                        &conn,
                        "g1",
                        &path,
                        b"h",
                        MaterializationJobState::Pending,
                        MaterializationJobState::Planning,
                        None,
                        None,
                        101,
                    )
                    .unwrap();
                    transition(
                        &conn,
                        "g1",
                        &path,
                        b"h",
                        MaterializationJobState::Planning,
                        state,
                        None,
                        None,
                        102,
                    )
                    .unwrap();
                }
                MaterializationJobState::Backoff => {
                    transition(
                        &conn,
                        "g1",
                        &path,
                        b"h",
                        MaterializationJobState::Pending,
                        MaterializationJobState::Planning,
                        None,
                        None,
                        101,
                    )
                    .unwrap();
                    mark_backoff(
                        &conn,
                        "g1",
                        &path,
                        b"h",
                        MaterializationJobState::Planning,
                        "test backoff",
                        9_999,
                        102,
                    )
                    .unwrap();
                }
                MaterializationJobState::Completed | MaterializationJobState::Superseded => {
                    unreachable!("not in non_terminal")
                }
            }
        }

        // One Completed job and one Superseded job, which must be untouched.
        enqueue_pending(&conn, "g1", "done.bin", b"h", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "done.bin",
            b"h",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "done.bin",
            b"h",
            MaterializationJobState::Planning,
            MaterializationJobState::ReadyToCommit,
            None,
            None,
            102,
        )
        .unwrap();
        transition(
            &conn,
            "g1",
            "done.bin",
            b"h",
            MaterializationJobState::ReadyToCommit,
            MaterializationJobState::Completed,
            None,
            None,
            103,
        )
        .unwrap();

        enqueue_pending(&conn, "g1", "superseded.bin", b"h", 100, 100).unwrap();
        mark_superseded_if_version_matches(&conn, "g1", "superseded.bin", b"h", 101).unwrap();

        let recovered = recover_after_restart(&conn, 200).unwrap();
        assert_eq!(recovered, non_terminal.len(), "every non-terminal job must be re-armed");

        for i in 0..non_terminal.len() {
            let path = format!("job-{i}.bin");
            let job = get_job(&conn, "g1", &path).unwrap().unwrap();
            assert_eq!(
                job.state,
                MaterializationJobState::Pending,
                "{path} must be Pending after recovery"
            );
        }

        let done = get_job(&conn, "g1", "done.bin").unwrap().unwrap();
        assert_eq!(done.state, MaterializationJobState::Completed, "Completed must be untouched");
        let superseded = get_job(&conn, "g1", "superseded.bin").unwrap().unwrap();
        assert_eq!(
            superseded.state,
            MaterializationJobState::Superseded,
            "Superseded must be untouched"
        );

        // And every recovered job must now actually be claimable.
        let runnable = claim_runnable_jobs(&conn, 200, 0, 100, 100).unwrap();
        let runnable_paths: std::collections::BTreeSet<&str> =
            runnable.iter().map(|j| j.path.as_str()).collect();
        for i in 0..non_terminal.len() {
            let path = format!("job-{i}.bin");
            assert!(runnable_paths.contains(path.as_str()), "{path} must be claimable");
        }
        assert!(!runnable_paths.contains("done.bin"));
        assert!(!runnable_paths.contains("superseded.bin"));
    }

    #[test]
    fn from_db_str_fails_closed_on_garbage() {
        let err = MaterializationJobState::from_db_str("not-a-real-state").unwrap_err();
        assert!(matches!(err, SyncSqliteError::CorruptState(_)));
    }

    // One assertion per legal-transition-table cell (the specified state
    // machine's own matrix), covering every state as both a `from` and,
    // where legal, a `to`.
    #[test]
    fn transition_table_matches_design_matrix() {
        use MaterializationJobState::*;
        let legal: &[(MaterializationJobState, MaterializationJobState)] = &[
            (Pending, Planning),
            (Pending, Superseded),
            (Planning, WaitingForSource),
            (Planning, WaitingForCredit),
            (Planning, Fetching),
            (Planning, ReadyToCommit),
            (Planning, Backoff),
            (Planning, Completed),
            (Planning, Superseded),
            (WaitingForSource, Fetching),
            (WaitingForSource, Backoff),
            (WaitingForSource, Superseded),
            (WaitingForCredit, Fetching),
            (WaitingForCredit, Backoff),
            (WaitingForCredit, Superseded),
            (Fetching, ReadyToCommit),
            (Fetching, WaitingForSource),
            (Fetching, WaitingForCredit),
            (Fetching, Backoff),
            (Fetching, Superseded),
            (Backoff, Planning),
            (Backoff, Superseded),
            (ReadyToCommit, Completed),
            (ReadyToCommit, Superseded),
            (Completed, Superseded),
            // Stale active-processing reclaim (see `can_transition_to`'s
            // own doc comment on this arm).
            (Planning, Planning),
            (Fetching, Planning),
            (ReadyToCommit, Planning),
        ];
        for &(from, to) in legal {
            assert!(from.can_transition_to(to), "{from:?} -> {to:?} should be legal");
        }

        let all = [
            Pending,
            Planning,
            WaitingForSource,
            WaitingForCredit,
            Fetching,
            ReadyToCommit,
            Backoff,
            Completed,
            Superseded,
        ];
        for &from in &all {
            for &to in &all {
                let expected = legal.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "unexpected legality for {from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn illegal_transition_is_rejected_and_leaves_row_unchanged() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        // Pending -> Fetching is not a legal direct transition (must go
        // through Planning first).
        let err = transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Fetching,
            None,
            None,
            101,
        )
        .unwrap_err();
        assert!(matches!(err, SyncSqliteError::InvalidInput(_)));
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Pending);
    }

    #[test]
    fn transition_is_a_noop_when_current_state_no_longer_matches_expected_from() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        // A concurrent writer moves it to Planning first.
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        // This caller still thinks it's Pending -> Planning is legal in the
        // abstract, but the row has already moved past it, so the
        // conditional UPDATE affects zero rows.
        let changed = transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            102,
        )
        .unwrap();
        assert!(!changed);
    }

    // Regression test for a race an independent review caught: a state-only
    // compare-and-swap is NOT sufficient to prevent a stale write-back from
    // clobbering a re-armed row, because the row can cycle back through the
    // SAME state name for a NEWER version before the stale caller's write
    // lands. Concretely: an engine claims this job at (Planning, hash1) and
    // starts a slow attempt; a newer change re-arms the row to (Pending,
    // hash2); the engine's own next tick claims THAT and advances it to
    // (Planning, hash2) — now the state matches what the original stale
    // caller expects (`Planning`) even though the version does not. Only the
    // version guard (not the state guard alone) catches this.
    #[test]
    fn transition_does_not_clobber_a_row_rearmed_to_a_newer_version_mid_attempt() {
        let conn = open_test_db();
        enqueue_pending(&conn, "g1", "a.txt", b"hash1", 100, 100).unwrap();
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            101,
        )
        .unwrap();
        // A newer change for this path is admitted while this caller's
        // attempt (still claimed at hash1) is in flight.
        enqueue_pending(&conn, "g1", "a.txt", b"hash2", 102, 102).unwrap();
        // The engine's own next tick claims the re-armed row and advances it
        // back to Planning — for hash2, not hash1.
        transition(
            &conn,
            "g1",
            "a.txt",
            b"hash2",
            MaterializationJobState::Pending,
            MaterializationJobState::Planning,
            None,
            None,
            103,
        )
        .unwrap();

        // The original, now-stale caller (still working off hash1) reports
        // its outcome. Its expected `from` (`Planning`) matches the row's
        // CURRENT state, so a state-only guard would wrongly let this
        // through; the version guard must still refuse it.
        let transitioned = transition(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            MaterializationJobState::ReadyToCommit,
            None,
            None,
            104,
        )
        .unwrap();
        assert!(!transitioned);
        let backed_off = mark_backoff(
            &conn,
            "g1",
            "a.txt",
            b"hash1",
            MaterializationJobState::Planning,
            "stale attempt",
            9_999,
            104,
        )
        .unwrap();
        assert!(!backed_off);

        // The row is exactly where the (correct, current) hash2 attempt left
        // it — untouched by the stale hash1 write-back.
        let job = get_job(&conn, "g1", "a.txt").unwrap().unwrap();
        assert_eq!(job.state, MaterializationJobState::Planning);
        assert_eq!(job.version_hash, b"hash2");
        assert_eq!(job.attempt, 0);
    }
}
