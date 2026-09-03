//! The desired-side fence and the Convergence Engine's own live claim
//! source. `projection_obligations` records, per `(group_id, path)`, a
//! durable `invalidation_generation` bumped by exactly one statement
//! whenever a genuine DAG state transition (not-admitted -> admitted, for a
//! primary change, a promoted orphan, a local emission, or a startup
//! self-heal promotion) touches that path, plus the obligation-native retry/
//! backoff state (`attempt_count`/`next_attempt_at`) and the parked
//! `'ignore_blocked'` state a path settles into when its own materialization
//! is excluded by ignore policy rather than genuinely completed.
//! `materialization_jobs` (`materialization_jobs.rs`) is a retired, no
//! longer scheduled-off-of table now — the engine claims and drives
//! entirely from this one.
//!
//! Network redelivery of an already-admitted change never reaches
//! [`bump_projection_obligations_for_touched_paths`] at all: it is called
//! only from the four durable-transition seams inside `dag_store` (see that
//! module's own `admit_change`/`admit_prepared_emission`/`init_dag_schema`),
//! never from message/batch receipt. This is what makes "a Change receipt is
//! not a projection event" a property of the call graph, not a runtime
//! check.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::Change;

pub fn init_projection_obligations_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS projection_obligations (
            group_id                TEXT NOT NULL,
            path                    TEXT NOT NULL,
            invalidation_generation INTEGER NOT NULL,
            state                   TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            updated_at              INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        -- Backs `obligation_incarnation` below: a real SQLite `AUTOINCREMENT`
        -- sequence (via `sqlite_sequence`) never reuses a value, unlike a
        -- plain table's own implicit rowid, which SQLite CAN reassign to a
        -- later row once the row that held it is deleted. That reuse is
        -- exactly what `obligation_incarnation` exists to rule out for
        -- `projection_obligations` itself (see `bump_projection_obligations_
        -- for_touched_paths`'s own doc comment for the ABA this closes), so
        -- the identity source it depends on has to genuinely never repeat.
        CREATE TABLE IF NOT EXISTS projection_obligation_incarnations (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );
        "#,
    )?;
    // Lightweight migration, same idempotent shape as `materialization_jobs`'s
    // own `trigger_lamport` column: a database from before these columns
    // existed keeps `attempt_count = 0`/`next_attempt_at = 0` on every
    // pre-existing row, which is safe -- both defaults mean "never failed,
    // immediately claimable," exactly what a row with no attempt history
    // yet should read as.
    //
    // `attempt_count`/`next_attempt_at` back the scheduler's own retry
    // backoff (`mark_obligation_attempt_failed`): a transient failure
    // advances `next_attempt_at` into the future without touching
    // `invalidation_generation`, so `claim_runnable_obligations` stops
    // reclaiming the row until then; a fresh admission's bump (`bump_
    // projection_obligations_for_touched_paths`) unconditionally resets
    // both back to 0, since a new desired state must never be delayed by
    // an old generation's backoff. `HazardHeld`/`IgnoreExcluded` settlements
    // are deliberately NOT recorded through this mechanism at all -- they
    // close (or stay outstanding) via their own dedicated liveness sweeps
    // (the hazard-recheck loop, the ignore-set refresh), never generic
    // scheduler backoff; see `yadorilink-daemon`'s `process_group_via_
    // obligations` for where that separation is enforced.
    // `obligation_incarnation` migrates the same idempotent way, defaulting
    // existing rows to the sentinel `0` -- safe forever, not just at
    // migration time, because `projection_obligation_incarnations`'
    // `AUTOINCREMENT` sequence starts at 1 and only grows, so `0` is never
    // handed out to any row's fresh incarnation and can never collide with
    // one. A pre-migration row is, by construction, the only live
    // incarnation of its `(group_id, path)` at the moment the migration
    // runs (nothing holds an in-memory `ClaimedObligation` across a process
    // restart, which a schema migration requires), so it needs no more than
    // this one shared, permanently-unique sentinel.
    for stmt in [
        "ALTER TABLE projection_obligations ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE projection_obligations ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE projection_obligations ADD COLUMN obligation_incarnation INTEGER NOT NULL DEFAULT 0",
    ] {
        match conn.execute(stmt, []) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.starts_with("duplicate column name") =>
            {
                // Already migrated.
            }
            Err(e) => return Err(e.into()),
        }
    }
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_projection_obligations_runnable
             ON projection_obligations (state, next_attempt_at);",
    )?;
    Ok(())
}

/// Bumps (or creates, at generation 1) the projection obligation for every
/// path in `touched_paths`, via one `INSERT ... ON CONFLICT DO UPDATE` per
/// path. Called ALONGSIDE
/// `dag_store`'s existing `bump_execution_fence_for_change`/`_for_promoted`
/// at their existing four call sites, reusing those call sites' own
/// `op_touched_paths` extraction rather than re-deriving touched paths here.
///
/// Runs inside whatever transaction the caller is already in -- this
/// function opens none of its own. For the three DAG-side seams
/// (`admit_change`'s primary/promoted-orphan arms, `admit_prepared_
/// emission`) that transaction is the caller's `write_immediate`; for
/// startup self-heal it is `init_dag_schema`'s own explicit
/// `unchecked_transaction` (C4-12 Stage 0.5.2). A no-op for an empty
/// `touched_paths` (matches `bump_execution_fence_for_change`'s own
/// early-return shape for the same case).
///
/// **Phase E finding (obligation row-incarnation ABA)**: `invalidation_
/// generation` alone identifies a claim only for as long as the row it was
/// read from keeps existing. The completion primitives below all `DELETE`
/// the row on success (`IgnoreExcluded` is the one exception -- see its own
/// doc comment), and a fresh `INSERT` here after that delete has no memory
/// of what generation the deleted row was last at, so it restarts at `1` --
/// identical to any still-in-flight claim issued back when the path's very
/// first obligation was created. `claim_runnable_obligations`'s own doc
/// comment already documents that two workers concurrently holding a claim
/// on the same STILL-OUTSTANDING obligation is expected and tolerated; that
/// reasoning silently assumed the row underneath both claims stays the same
/// row for the obligation's whole lifetime, which delete-then-reinsert
/// breaks. `obligation_incarnation` closes this the same way `invalidation_
/// generation` closes staleness WITHIN a row's lifetime: it identifies the
/// row's OWN lifetime, assigned fresh (from `projection_obligation_
/// incarnations`, an `AUTOINCREMENT` sequence that never repeats a value)
/// only on a genuine fresh `INSERT`, and left untouched by the `ON CONFLICT`
/// arm so an ordinary bump of a still-existing row keeps its incarnation
/// while `invalidation_generation` increments underneath it. Every
/// completion-family primitive's CAS now matches on `(group_id, path,
/// invalidation_generation, obligation_incarnation)` together, so a claim
/// issued against a since-deleted incarnation can never match a later,
/// unrelated incarnation that happens to share the same generation number.
pub fn bump_projection_obligations_for_touched_paths(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    for path in touched_paths {
        // Always allocates a fresh incarnation id, even on the (far more
        // common) `ON CONFLICT` bump-in-place path where it goes unused --
        // wasting an `i64` SEQUENCE VALUE is free; the alternative (a
        // conditional allocation) would need to know in advance whether the
        // upsert below is about to insert or update, which is exactly the
        // information a single upsert statement doesn't expose. The ROW
        // this INSERT creates, however, is immediately deleted again right
        // below (a Codex review's finding on an earlier draft of this fix:
        // leaving it in place made `projection_obligation_incarnations`
        // grow by one permanent row per touched-path event -- unbounded
        // storage growth proportional to total admitted mutations, not to
        // live obligations). This is safe: SQLite's `AUTOINCREMENT` tracks
        // the high-water mark for this table in `sqlite_sequence`
        // independently of which rows currently exist, so deleting the row
        // can never cause a later `INSERT` to reuse `fresh_incarnation`.
        conn.execute("INSERT INTO projection_obligation_incarnations DEFAULT VALUES", [])?;
        let fresh_incarnation = conn.last_insert_rowid();
        conn.execute(
            "DELETE FROM projection_obligation_incarnations WHERE id = ?1",
            rusqlite::params![fresh_incarnation],
        )?;
        conn.execute(
            "INSERT INTO projection_obligations
                (group_id, path, invalidation_generation, state, attempt_count,
                 next_attempt_at, created_at, updated_at, obligation_incarnation)
             VALUES (?1, ?2, 1, 'pending', 0, ?3, ?3, ?3, ?4)
             ON CONFLICT (group_id, path) DO UPDATE SET
                invalidation_generation = invalidation_generation + 1,
                state = 'pending',
                attempt_count = 0,
                next_attempt_at = ?3,
                updated_at = ?3",
            rusqlite::params![group_id, path, now_unix_nanos, fresh_incarnation],
        )?;
    }
    Ok(())
}

/// Diagnostic/test-only read of one path's current obligation, or `None` if
/// no admission has ever touched it. Not consumed by any production
/// scheduling path yet -- that is Stage 4's claim mechanism.
pub fn lookup_projection_obligation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<ProjectionObligation>, SyncSqliteError> {
    conn.query_row(
        "SELECT invalidation_generation, state, attempt_count, next_attempt_at, created_at,
                updated_at, obligation_incarnation
           FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |r| {
            Ok(ProjectionObligation {
                invalidation_generation: r.get(0)?,
                state: r.get(1)?,
                attempt_count: r.get(2)?,
                next_attempt_at: r.get(3)?,
                created_at: r.get(4)?,
                updated_at: r.get(5)?,
                obligation_incarnation: r.get(6)?,
            })
        },
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionObligation {
    pub invalidation_generation: i64,
    pub state: String,
    pub attempt_count: i64,
    pub next_attempt_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// See [`bump_projection_obligations_for_touched_paths`]'s own doc
    /// comment (Phase E finding: obligation row-incarnation ABA).
    pub obligation_incarnation: i64,
}

/// One obligation a claim call handed to a worker: enough to drive an
/// attempt (`group_id`, `path`) and enough to close it afterward
/// (`invalidation_generation`, the generation `G` this claim observed).
/// Deliberately carries no version hash: unlike `MaterializationJob`, the
/// desired state is always recomputed fresh at resolve time, never carried
/// from claim time, so there is nothing here that could go stale between
/// claim and close other than `G` itself and `obligation_incarnation`,
/// which the completion primitives re-check directly (Phase E finding: `G`
/// alone is not enough -- see `bump_projection_obligations_for_touched_
/// paths`'s own doc comment for the row-incarnation ABA this closes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedObligation {
    pub group_id: String,
    pub path: String,
    pub invalidation_generation: i64,
    /// Identifies the specific row incarnation this claim's `invalidation_
    /// generation` was read from. Carried alongside `invalidation_
    /// generation` into every completion-family call so a claim issued
    /// against a since-deleted-and-recreated row can never match its
    /// replacement merely because the replacement's own generation counter
    /// happened to start over at the same number.
    pub obligation_incarnation: i64,
    /// How many prior attempts at this SAME `invalidation_generation` have
    /// already failed (`mark_obligation_attempt_failed`) -- 0 for an
    /// obligation that has never failed, or that a fresh admission just
    /// reset. A caller computes its own backoff duration from this (see
    /// `yadorilink-daemon`'s reuse of `next_backoff`), the same way
    /// `MaterializationJob::attempt` already drives the legacy scheduler's
    /// backoff.
    pub attempt_count: i64,
}

/// Every currently-runnable obligation (`state = 'pending'` AND its
/// `next_attempt_at` backoff deadline has passed), fairly windowed per group
/// exactly like `materialization_jobs::claim_runnable_jobs`. This is a plain
/// read, not a claim-and-mark-in-flight operation: `state` stays purely
/// advisory here (a fresh admission's bump unconditionally resets it back to
/// `'pending'` regardless of what a claim observed), so nothing about this
/// function's correctness depends on the row's `state` surviving between
/// this read and the eventual completion call -- that safety is entirely
/// the completion primitive's `invalidation_generation` CAS's job. A worker
/// that reclaims the same still-outstanding obligation on a later tick
/// before a prior attempt finishes is therefore a performance question
/// (redundant concurrent work), never a correctness one.
pub fn claim_runnable_obligations(
    conn: &Connection,
    now_unix_nanos: i64,
    per_group_limit: u32,
    total_limit: u32,
) -> Result<Vec<ClaimedObligation>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "WITH runnable AS ( \
            SELECT group_id, path, invalidation_generation, obligation_incarnation, \
                   attempt_count, updated_at, \
                   ROW_NUMBER() OVER ( \
                PARTITION BY group_id ORDER BY updated_at ASC, path ASC \
            ) AS group_rank \
            FROM projection_obligations \
            WHERE state = 'pending' AND next_attempt_at <= ?1 \
         ) \
         SELECT group_id, path, invalidation_generation, obligation_incarnation, attempt_count \
         FROM runnable \
         WHERE group_rank <= ?2 \
         ORDER BY updated_at ASC, path ASC \
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(rusqlite::params![now_unix_nanos, per_group_limit, total_limit], |r| {
        Ok(ClaimedObligation {
            group_id: r.get(0)?,
            path: r.get(1)?,
            invalidation_generation: r.get(2)?,
            obligation_incarnation: r.get(3)?,
            attempt_count: r.get(4)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Records a failed attempt at exactly `claimed_invalidation_generation`:
/// increments `attempt_count` and sets `next_attempt_at` to the caller-
/// computed backoff deadline (`next_backoff`-style, mirroring `materialization_
/// jobs`'s own `materialization_mark_backoff`). Conditioned on the
/// generation being UNCHANGED since the claim -- exactly like the
/// completion primitives -- so a concurrent fresh admission that already
/// reset this path's attempt state (a new desired state must never be
/// delayed by an old generation's backoff) is never overwritten by a
/// stale failure report arriving after it. Returns whether the row was
/// actually still at that generation; `Ok(false)` is not an error, merely
/// "already superseded, nothing to do."
///
/// Deliberately only ever called for a genuine transient `RetryRequired`
/// outcome -- a `HazardHeld`/`IgnoreExcluded` settlement has its own
/// dedicated re-arm liveness (the hazard-recheck sweep, the ignore-set
/// refresh) and must never be folded into this generic backoff, or a path
/// correctly held for policy reasons would incorrectly inherit an
/// unrelated exponential retry delay on top of its own liveness mechanism.
pub fn mark_obligation_attempt_failed(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    next_attempt_at: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET attempt_count = attempt_count + 1,
                next_attempt_at = ?5,
                updated_at = ?6
          WHERE group_id = ?1 AND path = ?2 AND invalidation_generation = ?3
            AND obligation_incarnation = ?4",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            next_attempt_at,
            now_unix_nanos
        ],
    )?;
    Ok(affected == 1)
}

/// Reschedules a short, fixed delay with NO attempt penalty -- unlike
/// [`mark_obligation_attempt_failed`], `attempt_count` is left untouched.
/// For the "this tick learned nothing reliable" case (every candidate this
/// tick was skipped by guard contention, or every read raced a concurrent
/// admission): the obligation itself was never actually re-examined, so
/// treating it as a real failed attempt would needlessly accelerate its
/// backoff toward the cap for a systemic scheduling condition that has
/// nothing to do with this specific path. Same generation-gating as
/// [`mark_obligation_attempt_failed`].
pub fn defer_obligation_without_penalty(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    next_attempt_at: i64,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET next_attempt_at = ?5,
                updated_at = ?6
          WHERE group_id = ?1 AND path = ?2 AND invalidation_generation = ?3
            AND obligation_incarnation = ?4",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            next_attempt_at,
            now_unix_nanos
        ],
    )?;
    Ok(affected == 1)
}

/// The earliest `next_attempt_at` among every currently-`'pending'`
/// obligation NOT YET runnable (`next_attempt_at > now`) -- available for a
/// scheduler loop that wants a precise timer wake instead of its own coarse
/// poll interval whenever a backed-off retry is the only thing left
/// outstanding. Not required for correctness today: the Convergence
/// Engine's existing 1-second fallback poll (`FALLBACK_POLL_INTERVAL`)
/// already bounds worst-case retry latency to about a second regardless of
/// backoff, which is sufficient liveness for the initial obligation-driven
/// cutover -- a dynamic earliest-deadline timer built on this query is a
/// possible future optimization, not a Phase B/C requirement. `None` when
/// there is nothing pending at all, or everything pending is already
/// runnable (in which case the caller should be draining, not computing a
/// wake deadline).
pub fn earliest_pending_next_attempt_at(
    conn: &Connection,
    now_unix_nanos: i64,
) -> Result<Option<i64>, SyncSqliteError> {
    // `SELECT MIN(...)` always returns exactly one row (NULL, not zero rows,
    // when nothing matches), so this reads the aggregate directly rather
    // than treating a NULL result as `QueryReturnedNoRows`.
    conn.query_row(
        "SELECT MIN(next_attempt_at) FROM projection_obligations
          WHERE state = 'pending' AND next_attempt_at > ?1",
        rusqlite::params![now_unix_nanos],
        |r| r.get::<_, Option<i64>>(0),
    )
    .map_err(SyncSqliteError::from)
}

/// The single atomic compound completion for an EXACT outcome (a real
/// `path_materialized_generations` proof). Establishes, at one instant --
/// the instant this `DELETE` commits, not at any earlier read -- all of:
///
/// (a) DAG-side currency: `invalidation_generation` still equals the
///     claimed generation `G`;
/// (b) filesystem-side currency of the proof: its
///     `published_under_mutation_generation` still equals the path's
///     LIVE `mutation_generation`, read as part of THIS statement;
/// (c) the proof still describes the state this obligation claims: its
///     `resolved_path_state_hash` still equals `desired_hash`.
///
/// Zero rows affected (`Ok(false)`) is the verdict "not closed" -- the
/// obligation is left exactly where it was, at `G` (or already re-armed
/// at some `G' > G` if a fresh admission moved it), to be re-claimed and
/// re-resolved from scratch on a later tick. This must run inside a
/// `write_immediate` transaction (never a plain `write`, never DEFERRED)
/// so that no fence bump, publication, or obligation bump from another
/// writer can land between this statement's read and its write -- the
/// whole point of "one instant" is that this single `DELETE`'s own
/// atomicity is what provides it, not a lock this function takes itself.
/// (c) is checked even though (b) alone rules out "same fence generation,
/// different content" under the current invariants -- kept as defense in
/// depth: it is cheap, locally checkable, and is exactly the check that
/// still fails closed if a future mutator is ever added that moves bytes
/// without moving the fence, which is the premise (b) alone depends on.
pub fn complete_obligation_if_exact_proof_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    desired_resolved_path_state_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "DELETE FROM projection_obligations
          WHERE group_id = ?1 AND path = ?2
            AND invalidation_generation = ?3
            AND obligation_incarnation = ?4
            AND EXISTS (
                 SELECT 1
                   FROM path_materialized_generations g
                   JOIN path_actual_mutation_fences f
                     ON f.group_id = g.group_id AND f.path = g.path
                  WHERE g.group_id = ?1 AND g.path = ?2
                    AND g.published_under_mutation_generation = f.mutation_generation
                    AND g.resolved_path_state_hash = ?5
            )",
        rusqlite::params![
            group_id,
            path,
            claimed_invalidation_generation,
            claimed_obligation_incarnation,
            desired_resolved_path_state_hash
        ],
    )?;
    Ok(affected == 1)
}

/// Which durable, live proof to re-check in the SAME transaction as the
/// close, for an outcome that never publishes to
/// `path_materialized_generations` at all and so has nothing for the
/// exact-outcome check's (b)/(c) to compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonExactProofKind {
    /// Closes against the EXISTING `MaterializationState::Placeholder`
    /// state on the path's current `files` row. A placeholder that gets
    /// hydrated between the worker's decision and this close leaves the
    /// path MORE satisfied than the obligation required (benign to miss
    /// closing this tick; the next admission or the periodic repair
    /// candidate scan re-examines it regardless) -- this direction of
    /// staleness is harmless, unlike the hazard-hold direction below.
    Placeholder,
    /// Closes against the EXISTING `held_reason` on the path's current
    /// `files` row (any non-NULL reason, not a specific one -- logic that
    /// decided this exact reason no longer applies would itself already
    /// have cleared `held_reason` and re-driven `materialize`, which is a
    /// fresh attempt with its own fresh claim, not this one). A hold
    /// lifted between decision and this close is the HARMFUL direction
    /// (the path now needs real work, and nothing re-arms a closed
    /// obligation on its own) -- the same-transaction re-read here closes
    /// the narrow race at the instant of THIS close, but the broader
    /// "what re-arms a path whose hold is lifted later" gap is a real,
    /// separately-tracked one, out of scope here; that re-arming is the
    /// hazard engine's own responsibility, not this completion
    /// primitive's.
    HazardHeld,
    /// Unlike `Placeholder`/`HazardHeld`, an ignore-policy decision has NO
    /// durable, queryable proof row at all -- `is_locally_ignored` is a
    /// live, in-memory, per-session check against the current ignore sets,
    /// never persisted to `files` or anywhere else. There is therefore
    /// nothing for a same-transaction SQL re-read to compare against for
    /// this outcome: this variant's completion checks ONLY (a) -- the
    /// DAG-side generation CAS.
    ///
    /// This variant does NOT delete the obligation row the way the other
    /// two do: it transitions `state` to `'ignore_blocked'` instead,
    /// leaving the row (and its `invalidation_generation`) in place. An
    /// ignore-policy decision has no durable proof to invalidate the way a
    /// lifted hazard hold does, so nothing can tell a fresh admission's own
    /// bump apart from an unrelated one -- deleting the row here would mean
    /// NOTHING durably remembers this path was ever ignore-blocked, and a
    /// later `.yadorilinkignore` edit un-ignoring it would have no
    /// obligation left to re-arm at all. Parking it in `'ignore_blocked'`
    /// instead gives a periodic re-check sweep (`yadorilink-daemon`'s
    /// ignore-recheck loop, mirroring the existing hazard-recheck loop) a
    /// durable row to find and `rearm_ignore_blocked_obligation` back to
    /// `'pending'` once the path is no longer locally ignored.
    IgnoreExcluded,
}

/// The non-exact-outcome counterpart of
/// [`complete_obligation_if_exact_proof_current`]. Re-reads the outcome's
/// own durable proof (per [`NonExactProofKind`]) in the SAME transaction
/// as the close -- never a value read earlier in the worker's attempt --
/// so that an independent actor changing that proof between the worker's
/// decision and this commit is observed here, not assumed away. Same
/// `write_immediate`-only requirement as the exact-outcome primitive.
///
/// "Close" means "remove the row" for `Placeholder`/`HazardHeld`, but NOT
/// for `IgnoreExcluded` -- see that variant's own doc comment for why it
/// transitions to `'ignore_blocked'` instead of deleting.
pub fn complete_obligation_if_non_exact_proof_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    claimed_invalidation_generation: i64,
    claimed_obligation_incarnation: i64,
    proof: NonExactProofKind,
) -> Result<bool, SyncSqliteError> {
    let affected = match proof {
        NonExactProofKind::Placeholder => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM files
                      WHERE group_id = ?1 AND path = ?2 AND state = 'current'
                        AND materialization_state = 'placeholder'
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
        NonExactProofKind::HazardHeld => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM files
                      WHERE group_id = ?1 AND path = ?2 AND state = 'current'
                        AND held_reason IS NOT NULL
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
        // See NonExactProofKind::IgnoreExcluded's own doc comment: no
        // durable proof row exists to re-read, so only (a) is checked --
        // and unlike the other two, this parks the row rather than
        // deleting it, so a later re-check sweep has something durable to
        // find and re-arm. Still incarnation-gated: a stale claim from a
        // DIFFERENT, already-deleted incarnation of this same path must
        // never be able to park a brand-new incarnation as ignore-blocked
        // just because the generation numbers happen to coincide.
        NonExactProofKind::IgnoreExcluded => conn.execute(
            "UPDATE projection_obligations
                SET state = 'ignore_blocked'
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND state = 'pending'",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
    };
    Ok(affected == 1)
}

/// Every path in `group_id` currently parked at `'ignore_blocked'` -- the
/// candidate set a periodic re-check sweep re-examines via an ordinary
/// `reconcile_paths_directly` call, exactly like the hazard-recheck loop's
/// own `list_held_paths`.
pub fn list_ignore_blocked_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path FROM projection_obligations WHERE group_id = ?1 AND state = 'ignore_blocked'",
    )?;
    let rows = stmt.query_map(rusqlite::params![group_id], |r| r.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Re-arms one `'ignore_blocked'` obligation back to `'pending'` (and
/// immediately claimable, `next_attempt_at` reset to `now`) once a
/// re-check sweep confirms the path is no longer locally ignored.
/// Deliberately does NOT bump `invalidation_generation`: the DAG-side
/// desired state never actually changed while this path sat blocked, only
/// the LOCAL policy that was blocking it did, so the existing generation
/// still correctly describes what a fresh resolve must satisfy. Guarded on
/// `state = 'ignore_blocked'` (not a generation check, unlike the
/// backoff/completion primitives) -- a fresh admission's own bump already
/// unconditionally resets straight to `'pending'` regardless of the
/// row's prior state, so if one raced this call and got there first, this
/// call correctly becomes a no-op rather than re-arming something already
/// re-armed (or worse, un-doing a newer state).
pub fn rearm_ignore_blocked_obligation(
    conn: &Connection,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE projection_obligations
            SET state = 'pending',
                next_attempt_at = ?3,
                updated_at = ?3
          WHERE group_id = ?1 AND path = ?2 AND state = 'ignore_blocked'",
        rusqlite::params![group_id, path, now_unix_nanos],
    )?;
    Ok(affected == 1)
}

/// Name of the one-time bootstrap migration's marker row in
/// `schema_migration_markers` — see [`bootstrap_obligations_from_legacy_
/// unapplied_changes`]'s own doc comment.
const LEGACY_UNAPPLIED_CHANGES_BOOTSTRAP_MARKER: &str =
    "legacy_applied_changes_to_obligations_bootstrap";

/// One-time upgrade migration: a database that predates complete
/// `projection_obligations`
/// creation on every durable-transition seam can hold retained
/// `changes.applied = 0` rows with no corresponding obligation at all --
/// nothing schedules their projection once the legacy `reproject_
/// unapplied_changes` executor (which used to independently re-drive this
/// exact set) is retired. This backfills a pending obligation for every
/// such row's distinct touched `(group_id, path)` that does not already
/// have one, exactly once per database, so upgrading never silently drops
/// pre-cutover unprojected work.
///
/// Idempotent by construction on two levels: the marker check makes a
/// second call a pure no-op (an early return, no query against `changes`
/// at all), and even without the marker, every insert is `ON CONFLICT ...
/// DO NOTHING` -- this NEVER bumps or replaces an existing obligation's
/// `invalidation_generation`/`state`/incarnation, unlike `bump_projection_
/// obligations_for_touched_paths`'s ordinary upsert. That distinction is
/// load-bearing: a genuine fresh admission's bump is SUPPOSED to invalidate
/// whatever a worker currently holds, but this migration must never
/// re-arm or otherwise disturb an obligation a normal admission already
/// created and that may already be claimed/in-flight.
///
/// May conservatively re-arm a small number of paths whose obligation had
/// already completed (and been deleted) under an intermediate, incomplete
/// version of the obligation-creation rollout, while `changes.applied`
/// still read `0` for the Change that touched them (obligation completion
/// never updates that column — see [`bump_projection_obligations_for_
/// touched_paths`]'s doc comment on why not). That is an acceptable
/// one-time upgrade cost, not a recurring one: this function runs exactly
/// once per database, ever, gated by its own marker -- running it again
/// after the marker is written performs zero work and creates zero new
/// obligations, even for a path whose freshly re-armed obligation from the
/// first run has since completed and been deleted again.
///
/// Runs on whatever transaction the caller supplies -- opens none of its
/// own, matching `bump_projection_obligations_for_touched_paths`'s own
/// shape, so a caller controls the commit boundary (see `init_dag_schema`'s
/// own call site, wrapped in an explicit `unchecked_transaction` so the
/// marker and every backfilled obligation commit atomically or not at
/// all).
pub fn bootstrap_obligations_from_legacy_unapplied_changes(
    conn: &Connection,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migration_markers (
            name         TEXT PRIMARY KEY,
            completed_at INTEGER NOT NULL
        );",
    )?;
    let already_migrated: Option<i64> = conn
        .query_row(
            "SELECT completed_at FROM schema_migration_markers WHERE name = ?1",
            rusqlite::params![LEGACY_UNAPPLIED_CHANGES_BOOTSTRAP_MARKER],
            |r| r.get(0),
        )
        .optional()?;
    if already_migrated.is_some() {
        return Ok(());
    }

    let mut touched_paths: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    {
        let mut stmt =
            conn.prepare("SELECT group_id, encoded FROM changes WHERE applied = 0")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let group_id: String = row.get(0)?;
            let encoded: Vec<u8> = row.get(1)?;
            let change = Change::from_wire_bytes(&encoded).map_err(|error| {
                SyncSqliteError::CorruptState(format!(
                    "legacy-unapplied-changes bootstrap: retained change in group \
                     {group_id} is corrupt: {error}"
                ))
            })?;
            for op in &change.ops {
                for path in crate::dag_store::op_touched_paths(op) {
                    touched_paths.insert((group_id.clone(), path.to_string()));
                }
            }
        }
    }

    for (group_id, path) in &touched_paths {
        // Same "always allocate, immediately delete if unused" fresh-
        // incarnation pattern as `bump_projection_obligations_for_touched_
        // paths` -- see that function's own doc comment for why the waste
        // on the (here, common) `DO NOTHING` conflict path is both safe and
        // cheap.
        conn.execute("INSERT INTO projection_obligation_incarnations DEFAULT VALUES", [])?;
        let fresh_incarnation = conn.last_insert_rowid();
        conn.execute(
            "DELETE FROM projection_obligation_incarnations WHERE id = ?1",
            rusqlite::params![fresh_incarnation],
        )?;
        conn.execute(
            "INSERT INTO projection_obligations
                (group_id, path, invalidation_generation, state, attempt_count,
                 next_attempt_at, created_at, updated_at, obligation_incarnation)
             VALUES (?1, ?2, 1, 'pending', 0, ?3, ?3, ?3, ?4)
             ON CONFLICT (group_id, path) DO NOTHING",
            rusqlite::params![group_id, path, now_unix_nanos, fresh_incarnation],
        )?;
    }

    conn.execute(
        "INSERT INTO schema_migration_markers (name, completed_at) VALUES (?1, ?2)",
        rusqlite::params![LEGACY_UNAPPLIED_CHANGES_BOOTSTRAP_MARKER, now_unix_nanos],
    )?;
    Ok(())
}

/// Group-scoped `changes.applied` compatibility sweep: `changes.applied`
/// is compatibility/diagnostic state only -- nothing schedules off it --
/// but it is still
/// kept eventually-consistent so external tooling reading the column is
/// not permanently misled. Individual obligation completion deliberately
/// does NOT call this (or `dag_mark_applied`) per-path: a `Change` can
/// touch several paths, so one path's obligation closing does not
/// establish the whole `Change` projected, and reconstructing that
/// accurately per-completion would need a path -> Change reverse lookup
/// (and re-checking every OTHER path the same Change touches) on the hot
/// completion path.
///
/// Instead, this marks every retained `applied = 0` Change in `group_id`
/// `applied = 1` in one conditional, set-based statement -- but ONLY once
/// the group has no `'pending'` `projection_obligations` row left
/// (`'ignore_blocked'` rows do not block this: they are policy-settled,
/// not outstanding work, matching how `dag_admitted_unapplied`-style
/// accounting already treats them). Race-safe against a concurrent
/// admission landing between the emptiness check and the update: both are
/// one statement here (the `NOT EXISTS` subquery re-evaluates as part of
/// the same `UPDATE`, not a separate prior read), and the caller is
/// expected to run this inside a `write_immediate` transaction so a
/// concurrent admission's own obligation-table insert either fully
/// precedes or fully follows this statement, never interleaves with it.
/// A later admission naturally inserts its own Change with `applied = 0`
/// and creates/bumps its own obligation regardless of what this call did.
pub fn reconcile_compatibility_applied_flag_for_group(
    conn: &Connection,
    group_id: &str,
) -> Result<usize, SyncSqliteError> {
    let affected = conn.execute(
        "UPDATE changes
            SET applied = 1
          WHERE group_id = ?1
            AND applied = 0
            AND NOT EXISTS (
                SELECT 1 FROM projection_obligations
                 WHERE group_id = ?1 AND state = 'pending'
            )",
        rusqlite::params![group_id],
    )?;
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_projection_obligations_schema(&c).unwrap();
        c
    }

    #[test]
    fn a_first_bump_creates_a_row_at_generation_one() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.invalidation_generation, 1);
        assert_eq!(row.state, "pending");
    }

    #[test]
    fn a_second_bump_increments_the_existing_generation_rather_than_resetting_it() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.invalidation_generation, 2);
        assert_eq!(row.updated_at, 2000);
    }

    /// **Codex review finding on an earlier draft of the ABA fix**: the
    /// incarnation allocator used to leave its `INSERT`ed row in place,
    /// growing `projection_obligation_incarnations` by one permanent row
    /// per touched-path event -- unbounded storage growth proportional to
    /// total admitted mutations over a replica's lifetime, not to live
    /// obligations. The allocator row is now deleted immediately after its
    /// id is captured; this proves the table stays empty across many
    /// bumps, and that incarnation values assigned to genuinely distinct
    /// rows still never collide (`AUTOINCREMENT`'s `sqlite_sequence`
    /// high-water mark is independent of which rows currently exist).
    #[test]
    fn the_incarnation_allocator_table_never_accumulates_rows() {
        let conn = conn();
        for i in 0..50 {
            let path = format!("path-{i}.txt");
            bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 1000).unwrap();
            // A second bump of the SAME path (the common ON CONFLICT
            // bump-in-place case) also allocates-and-discards an unused id.
            bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 2000).unwrap();
        }
        let allocator_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM projection_obligation_incarnations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            allocator_rows, 0,
            "the allocator table must never accumulate rows regardless of how many paths were bumped"
        );

        // Every one of the 50 distinct rows must still have a genuinely
        // unique incarnation -- deleting the allocator row must not have
        // let any of them collide.
        let mut incarnations = std::collections::HashSet::new();
        for i in 0..50 {
            let path = format!("path-{i}.txt");
            let obligation = lookup_projection_obligation(&conn, "g", &path).unwrap().unwrap();
            assert!(
                incarnations.insert(obligation.obligation_incarnation),
                "incarnation {} for {path} collided with an earlier path's incarnation",
                obligation.obligation_incarnation
            );
        }
    }

    #[test]
    fn bumping_one_path_never_touches_an_unrelated_path() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
        let a = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let b = lookup_projection_obligation(&conn, "g", "b.txt").unwrap().unwrap();
        assert_eq!(a.invalidation_generation, 2, "a.txt was bumped twice");
        assert_eq!(b.invalidation_generation, 1, "b.txt must be unaffected by a.txt's second bump");
    }

    #[test]
    fn an_empty_touched_set_is_a_no_op() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &[], 1000).unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM projection_obligations", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn a_path_with_no_admission_ever_has_no_obligation() {
        let conn = conn();
        assert!(lookup_projection_obligation(&conn, "g", "never.txt").unwrap().is_none());
    }

    #[test]
    fn claim_returns_every_pending_obligation_with_its_current_generation() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
        assert_eq!(claimed.len(), 2);
        let a = claimed.iter().find(|c| c.path == "a.txt").unwrap();
        let b = claimed.iter().find(|c| c.path == "b.txt").unwrap();
        assert_eq!(a.invalidation_generation, 2);
        assert_eq!(b.invalidation_generation, 1);
        assert_eq!(a.group_id, "g");
    }

    #[test]
    fn claim_with_no_obligations_returns_empty() {
        let conn = conn();
        assert!(claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap().is_empty());
    }

    #[test]
    fn claim_respects_the_per_group_limit_taking_the_oldest_updated_first() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 2000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["c.txt"], 3000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 10_000, 2, 10).unwrap();
        assert_eq!(claimed.len(), 2);
        let paths: Vec<&str> = claimed.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "b.txt"], "the two oldest-updated rows must win, in order");
    }

    #[test]
    fn claim_respects_the_total_limit_across_groups() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g1", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g2", &["b.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 10_000, 10, 1).unwrap();
        assert_eq!(claimed.len(), 1);
    }

    #[test]
    fn claim_gives_every_group_a_share_rather_than_letting_one_group_crowd_out_another() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "heavy", &["1", "2", "3"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "light", &["only"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 10_000, 1, 10).unwrap();
        let groups: std::collections::BTreeSet<&str> =
            claimed.iter().map(|c| c.group_id.as_str()).collect();
        assert!(groups.contains("heavy") && groups.contains("light"));
    }

    #[test]
    fn a_fresh_obligation_has_zero_attempt_count_and_is_immediately_claimable() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.attempt_count, 0);
        assert_eq!(row.next_attempt_at, 1000);
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].attempt_count, 0);
    }

    #[test]
    fn a_failed_attempt_is_not_reclaimable_until_its_backoff_deadline_passes() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        let claimed_g = claimed[0].invalidation_generation;
        let claimed_i = claimed[0].obligation_incarnation;

        assert!(
            mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 5000, 1000)
                .unwrap()
        );

        assert!(
            claim_runnable_obligations(&conn, 2000, 10, 10).unwrap().is_empty(),
            "must not be reclaimable before its backoff deadline"
        );
        let reclaimed = claim_runnable_obligations(&conn, 5000, 10, 10).unwrap();
        assert_eq!(reclaimed.len(), 1, "must be reclaimable once the backoff deadline passes");
        assert_eq!(reclaimed[0].attempt_count, 1, "the failed attempt must have incremented the count");
    }

    #[test]
    fn a_fresh_admission_resets_attempt_count_and_backoff_even_after_repeated_failures() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        let claimed_g = claimed[0].invalidation_generation;
        let claimed_i = claimed[0].obligation_incarnation;
        mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 100_000, 1000)
            .unwrap();

        // A new DAG admission supersedes the old generation's backoff --
        // the new desired state must be runnable immediately, not delayed
        // by the old generation's failure history.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.invalidation_generation, 2);
        assert_eq!(row.attempt_count, 0, "a new generation must reset the attempt count");
        assert_eq!(row.next_attempt_at, 2000, "a new generation must be immediately runnable");

        let reclaimed = claim_runnable_obligations(&conn, 2000, 10, 10).unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].attempt_count, 0);
    }

    #[test]
    fn a_stale_failure_report_at_a_superseded_generation_is_a_no_op() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        let stale_g = claimed[0].invalidation_generation;
        let claimed_i = claimed[0].obligation_incarnation;

        // A concurrent admission bumps the generation before this stale
        // attempt's own failure report lands -- an ordinary bump-in-place,
        // so the row's incarnation is unchanged; only its generation moves.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

        assert!(
            !mark_obligation_attempt_failed(&conn, "g", "a.txt", stale_g, claimed_i, 100_000, 3000)
                .unwrap(),
            "a failure report at a superseded generation must affect zero rows, even with the \
             correct (unchanged) incarnation"
        );
        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.attempt_count, 0, "the fresh generation's reset must survive the stale report");
        assert_eq!(row.next_attempt_at, 2000, "the fresh generation must stay immediately runnable");
    }

    /// **Phase E finding (obligation row-incarnation ABA), fix verification**:
    /// nothing in `mark_obligation_attempt_failed`'s WHERE clause used to
    /// distinguish "the exact row incarnation this claim was issued
    /// against" from "any current row that happens to carry the same
    /// `(group_id, path, invalidation_generation)` key" -- it was a pure key
    /// match, not a row identity match. `claim_runnable_obligations`'s own
    /// doc comment already documents that two workers concurrently holding
    /// a claim on the SAME still-outstanding obligation is expected,
    /// tolerated behavior ("a performance question, never a correctness
    /// one") -- but that reasoning implicitly assumed the row underneath
    /// both claims stays the SAME row for the obligation's whole lifetime.
    /// It does not: `complete_obligation_if_exact_proof_current` and the
    /// `Placeholder`/`HazardHeld` arms of `complete_obligation_if_non_exact_
    /// proof_current` all `DELETE` the row on success, and `bump_projection_
    /// obligations_for_touched_paths` INSERTs a brand-new row at
    /// `invalidation_generation = 1` (via `ON CONFLICT DO UPDATE`'s INSERT
    /// arm) the next time ANY admission touches that path -- there is no
    /// memory of what generation a deleted row was last at. A claimant
    /// issued before the delete, still holding `G = 1` (the common case:
    /// the very first admission for a path is always `G = 1`), could
    /// therefore complete against a brand-new, entirely unrelated later
    /// obligation for the same path that also happened to start at `G = 1`.
    ///
    /// Confirmed genuinely RED against the pre-fix API (positional 6-arg
    /// `mark_obligation_attempt_failed` with no incarnation parameter): the
    /// stale `mark_obligation_attempt_failed(old_claim.invalidation_
    /// generation, /* no incarnation */)` call matched and corrupted the
    /// reincarnated row. `obligation_incarnation` (assigned fresh, from an
    /// `AUTOINCREMENT` sequence that never repeats a value, only on a
    /// genuine `INSERT`, never on the `ON CONFLICT` bump-in-place arm) now
    /// makes OLD's full claim token strictly stale the moment its own row
    /// is deleted, regardless of what generation number a later, unrelated
    /// incarnation happens to reuse.
    #[test]
    fn stale_claimant_cannot_corrupt_a_reincarnated_obligation_row() {
        let conn = conn();

        // OLD claims the obligation for a.txt at its first-ever generation
        // and incarnation.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let old_claim = claim_runnable_obligations(&conn, 1000, 10, 10)
            .unwrap()
            .into_iter()
            .find(|c| c.path == "a.txt")
            .unwrap();
        assert_eq!(old_claim.invalidation_generation, 1);

        // A DIFFERENT worker successfully completes that SAME obligation --
        // standing in for a real `complete_obligation_if_exact_proof_current`
        // success, which performs exactly this DELETE once its own proof
        // check passes.
        conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = 'g' AND path = 'a.txt' AND invalidation_generation = 1",
            [],
        )
        .unwrap();
        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());

        // A genuinely NEW, unrelated DAG admission later touches the same
        // path -- a fresh incarnation, starting at G = 1 again (identical to
        // OLD's stale claim) since there is no surviving row to conflict
        // against, but with a NEW `obligation_incarnation` value.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 5000).unwrap();
        let reincarnated = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(
            reincarnated.invalidation_generation, 1,
            "sanity: the new admission's row starts fresh at G=1, identical to OLD's stale claim"
        );
        assert_ne!(
            reincarnated.obligation_incarnation, old_claim.obligation_incarnation,
            "sanity: the reincarnated row must get a genuinely different incarnation than OLD's"
        );

        // OLD, still holding its now-stale claim from the deleted
        // incarnation, reports a failed attempt against the generation AND
        // incarnation it originally claimed.
        let affected = mark_obligation_attempt_failed(
            &conn,
            "g",
            "a.txt",
            old_claim.invalidation_generation,
            old_claim.obligation_incarnation,
            99_999,
            5000,
        )
        .unwrap();

        // FIXED: OLD's stale attempt-failure report against a DELETED
        // incarnation must affect zero rows, even though its generation
        // number coincidentally matches the brand-new incarnation's own.
        assert!(
            !affected,
            "OLD's stale claim against a deleted incarnation must not match the new incarnation, \
             even at the same generation number"
        );
        let untouched = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(
            untouched.attempt_count, 0,
            "the new incarnation's attempt_count must be untouched by an attempt nobody made against it"
        );
        assert_eq!(
            untouched.next_attempt_at, 5000,
            "the new incarnation's backoff must be untouched by OLD's stale report"
        );
    }

    #[test]
    fn defer_without_penalty_delays_reclaim_but_never_increments_attempt_count() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        let claimed_g = claimed[0].invalidation_generation;
        let claimed_i = claimed[0].obligation_incarnation;

        assert!(defer_obligation_without_penalty(
            &conn, "g", "a.txt", claimed_g, claimed_i, 1200, 1000
        )
        .unwrap());
        assert!(claim_runnable_obligations(&conn, 1100, 10, 10).unwrap().is_empty());
        let reclaimed = claim_runnable_obligations(&conn, 1200, 10, 10).unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(
            reclaimed[0].attempt_count, 0,
            "a no-trustworthy-audit reschedule must never count as a failed attempt"
        );
    }

    #[test]
    fn earliest_pending_next_attempt_at_ignores_already_runnable_rows() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
        let a = claimed.iter().find(|c| c.path == "a.txt").unwrap();
        mark_obligation_attempt_failed(
            &conn,
            "g",
            "a.txt",
            a.invalidation_generation,
            a.obligation_incarnation,
            9000,
            1000,
        )
        .unwrap();

        // b.txt is still immediately runnable, so the earliest FUTURE
        // deadline must not be confused with it.
        assert_eq!(earliest_pending_next_attempt_at(&conn, 1000).unwrap(), Some(9000));
    }

    #[test]
    fn earliest_pending_next_attempt_at_is_none_when_nothing_is_backed_off() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        assert_eq!(earliest_pending_next_attempt_at(&conn, 1000).unwrap(), None);
    }

    /// Nothing in this module ever moves a row's `state` out of `'pending'`
    /// or otherwise marks it in-flight -- `claim_runnable_obligations` is a
    /// plain `SELECT`, and a fresh admission's bump unconditionally resets
    /// `state` back to `'pending'` regardless of what came before. A row a
    /// worker never got to before a restart is therefore already sitting
    /// exactly where a freshly claimable row needs to be: this is ordinary
    /// durable SQLite state, not something that needs its own crash-
    /// recovery primitive the way a scheduler with genuine in-flight states
    /// (`Planning`/`Fetching`/`ReadyToCommit`) would. This test proves that
    /// directly: it commits an admission, then closes and reopens the
    /// SQLite connection with no claim or completion call in between --
    /// simulating a daemon restart before any worker tick ever touched this
    /// obligation -- and checks it survives with its generation intact and
    /// is still claimable through the real claim entry point, not merely
    /// visible to a diagnostic lookup.
    ///
    /// Confirmed genuinely RED by temporarily changing this module's
    /// `CREATE TABLE IF NOT EXISTS projection_obligations` to `CREATE TEMP
    /// TABLE IF NOT EXISTS projection_obligations`: a `TEMP` table is
    /// scoped to the connection that created it, so the reopened connection
    /// got a fresh, empty table and this test failed (`unwrap()` on `None`)
    /// exactly as it should for genuinely lost state. Restored and
    /// reconfirmed GREEN.
    #[test]
    fn an_obligation_survives_a_connection_restart_with_no_worker_tick_and_stays_claimable() {
        let db_dir = tempfile::tempdir().unwrap();
        let db_path = db_dir.path().join("projection_obligations.sqlite");

        {
            let conn = Connection::open(&db_path).unwrap();
            init_projection_obligations_schema(&conn).unwrap();
            bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
            bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
            // `conn` is dropped here, simulating the process exiting before
            // any worker tick ever claims or completes this obligation.
        }

        // Simulated restart: a fresh connection to the same on-disk
        // database, re-running schema init exactly as daemon startup does.
        let conn = Connection::open(&db_path).unwrap();
        init_projection_obligations_schema(&conn).unwrap();

        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(
            row.invalidation_generation, 2,
            "the pre-restart generation must survive the restart untouched"
        );
        assert_eq!(row.state, "pending");

        let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].path, "a.txt");
        assert_eq!(claimed[0].invalidation_generation, 2);
    }
}

/// Direct, deterministic tests for the compound completion primitives, at
/// the persistence/API level, before any production scheduling change
/// wires them in.
#[cfg(test)]
mod completion_tests {
    use super::*;
    use crate::materialized_generation::{
        bump_mutation_fence, init_materialized_generation_schema, publish_materialized_generation_if_fence_current,
        snapshot_mutation_fence, MaterializedObjectKind,
    };

    /// Full schema this module's tests need: DAG + projection_obligations
    /// (via `init_dag_schema`), the fence/proof tables, and `files` (for
    /// the non-exact-outcome tests) -- `yadorilink_sqlite_runtime::
    /// init_schema` must run AFTER `init_dag_schema` (it assumes `changes`/
    /// `pruned_changes` already exist, per its own doc comment), matching
    /// the real production schema initialization order.
    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&c).unwrap();
        init_materialized_generation_schema(&c).unwrap();
        yadorilink_sqlite_runtime::init_schema(&c).unwrap();
        c
    }

    /// Inserts a minimal, valid `files` row for `(group_id, path)` with the
    /// given materialization/held state -- everything this module's
    /// completion tests need, nothing `set_materialization_state`/
    /// `set_held`'s own richer callers additionally track.
    fn seed_file_row(
        conn: &Connection,
        group_id: &str,
        path: &str,
        materialization_state: &str,
        held_reason: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO files
                (group_id, path, size, mtime_unix_nanos, blocks_json, materialization_state, held_reason)
             VALUES (?1, ?2, 0, 0, '[]', ?3, ?4)",
            rusqlite::params![group_id, path, materialization_state, held_reason],
        )
        .unwrap();
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// The headline case: a claimed generation whose exact proof is
    /// current in every dimension (a), (b), (c) closes.
    #[test]
    fn exact_completion_closes_when_all_three_conditions_hold() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            3000,
        )
        .unwrap()
        .unwrap();

        assert!(
            complete_obligation_if_exact_proof_current(
                &conn,
                "g",
                "a.txt",
                claimed_g,
                claimed_i,
                &published.resolved_path_state_hash,
            )
            .unwrap(),
            "all three conditions hold -- the completion must close"
        );
        assert!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none(),
            "a closed obligation's row must be gone -- completion is represented by absence, not a status column"
        );
    }

    /// (a) fails: an independent DAG admission bumped `invalidation_
    /// generation` past the claimed value between claim and completion.
    #[test]
    fn exact_completion_fails_when_dag_side_generation_moved() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            2000,
        )
        .unwrap()
        .unwrap();

        // An independent admission re-arms the obligation to G+1.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 3000).unwrap();

        assert!(!complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            claimed_g,
            claimed_i,
            &published.resolved_path_state_hash,
        )
        .unwrap());
        assert_eq!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap().invalidation_generation,
            claimed_g + 1,
            "a failed completion must leave the re-armed obligation exactly as it was"
        );
    }

    /// (b) fails: an independent mutator bumped the FILESYSTEM-side fence
    /// (never touching the DAG at all) between publication and
    /// completion. The proof row still exists and its content is
    /// untouched, but it is no longer usable.
    #[test]
    fn exact_completion_fails_when_filesystem_side_fence_moved_even_though_dag_side_did_not() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            2000,
        )
        .unwrap()
        .unwrap();

        // A DAG-invisible mutator (e.g. on-demand hydration/eviction, or a
        // retirement pass for an unrelated reason) bumps the fence without
        // ever touching projection_obligations.
        bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 3000).unwrap();

        assert!(
            !complete_obligation_if_exact_proof_current(
                &conn,
                "g",
                "a.txt",
                claimed_g,
                claimed_i,
                &published.resolved_path_state_hash,
            )
            .unwrap(),
            "a DAG-side-only completion must not close once the filesystem-side proof it points \
             at has been invalidated by a mutator the DAG never saw"
        );
        assert_eq!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap().invalidation_generation,
            claimed_g,
            "the obligation is left outstanding at the SAME generation, to be re-resolved -- it \
             was never invalidated on the DAG side, only the fs-side proof was"
        );
    }

    /// (c) fails: the proof row is usable ((a) and (b) both hold) but its
    /// content is not what this attempt resolved -- currently redundant
    /// with (b) under today's invariants, but checked anyway as defense
    /// in depth.
    #[test]
    fn exact_completion_fails_when_the_usable_proofs_content_does_not_match_the_desired_hash() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            2000,
        )
        .unwrap();

        // A completely different (wrong) desired hash -- not what the
        // usable, current proof actually says.
        assert!(!complete_obligation_if_exact_proof_current(
            &conn, "g", "a.txt", claimed_g, claimed_i, &hash(99)
        )
        .unwrap());
        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_some());
    }

    /// No proof at all: a claimed generation with nothing ever published
    /// for this path must never close -- there is no `EXISTS` row to
    /// satisfy (b)/(c) against.
    #[test]
    fn exact_completion_fails_when_no_proof_was_ever_published() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        assert!(!complete_obligation_if_exact_proof_current(
            &conn, "g", "a.txt", claimed_g, claimed_i, &hash(1)
        )
        .unwrap());
    }

    /// Non-exact: a Placeholder settlement closes while the path's
    /// `files` row still genuinely reads `materialization_state =
    /// 'placeholder'`.
    #[test]
    fn non_exact_placeholder_completion_closes_while_still_a_placeholder() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["p.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "p.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        seed_file_row(&conn, "g", "p.txt", "placeholder", None);

        assert!(complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "p.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::Placeholder,
        )
        .unwrap());
        assert!(lookup_projection_obligation(&conn, "g", "p.txt").unwrap().is_none());
    }

    /// Non-exact: a Placeholder settlement must NOT close once the path
    /// has since been hydrated -- the live, same-transaction re-read is
    /// required even though this specific direction of staleness is
    /// independently benign.
    #[test]
    fn non_exact_placeholder_completion_fails_once_hydrated_in_the_meantime() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["p.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "p.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        seed_file_row(&conn, "g", "p.txt", "hydrated", None);

        assert!(!complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "p.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::Placeholder,
        )
        .unwrap());
        assert!(lookup_projection_obligation(&conn, "g", "p.txt").unwrap().is_some());
    }

    /// Non-exact: a HazardHeld settlement closes while `held_reason` is
    /// still genuinely set.
    #[test]
    fn non_exact_hazard_held_completion_closes_while_still_held() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["h.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "h.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        seed_file_row(&conn, "g", "h.txt", "hydrated", Some("case_collision"));

        assert!(complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "h.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::HazardHeld,
        )
        .unwrap());
        assert!(lookup_projection_obligation(&conn, "g", "h.txt").unwrap().is_none());
    }

    /// Non-exact: a HazardHeld settlement must NOT close once the hold has
    /// been lifted in the meantime -- the HARMFUL staleness direction
    /// (unlike the placeholder case above).
    #[test]
    fn non_exact_hazard_held_completion_fails_once_the_hold_is_lifted() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["h.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "h.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        seed_file_row(&conn, "g", "h.txt", "hydrated", None);

        assert!(!complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "h.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::HazardHeld,
        )
        .unwrap());
        assert!(lookup_projection_obligation(&conn, "g", "h.txt").unwrap().is_some());
    }

    /// Non-exact: IgnoreExcluded has no durable proof row to re-check
    /// (see `NonExactProofKind::IgnoreExcluded`'s own doc comment) -- its
    /// completion checks (a) alone, so a claimed generation that is still
    /// current closes regardless of `files` row state (there need not
    /// even be one).
    #[test]
    fn non_exact_ignore_excluded_completion_parks_rather_than_deletes() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        assert!(complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "i.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::IgnoreExcluded,
        )
        .unwrap());
        let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        assert_eq!(
            row.state, "ignore_blocked",
            "an ignore-excluded settlement must park the row, not delete it, so a later \
             re-check sweep has a durable obligation to re-arm"
        );
        assert_eq!(row.invalidation_generation, claimed_g, "the generation must be left untouched");
        assert!(
            claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap().is_empty(),
            "a parked ignore_blocked row must not be reclaimable through the ordinary claim path"
        );
    }

    #[test]
    fn ignore_blocked_obligation_is_rearmed_and_becomes_claimable_again() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "i.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::IgnoreExcluded,
        )
        .unwrap();
        assert_eq!(list_ignore_blocked_paths(&conn, "g").unwrap(), vec!["i.txt".to_string()]);

        assert!(rearm_ignore_blocked_obligation(&conn, "g", "i.txt", 5000).unwrap());

        let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        assert_eq!(row.state, "pending");
        assert_eq!(row.invalidation_generation, claimed_g, "re-arming must not bump the generation");
        assert_eq!(row.next_attempt_at, 5000, "must be immediately claimable again");
        assert!(list_ignore_blocked_paths(&conn, "g").unwrap().is_empty());

        let reclaimed = claim_runnable_obligations(&conn, 5000, 10, 10).unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].path, "i.txt");
    }

    #[test]
    fn a_fresh_admission_rearms_an_ignore_blocked_path_too() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "i.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::IgnoreExcluded,
        )
        .unwrap();

        // A genuinely new DAG admission must re-arm the path regardless of
        // whatever local scheduler state it was parked in.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 2000).unwrap();

        let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        assert_eq!(row.state, "pending");
        assert_eq!(row.invalidation_generation, claimed_g + 1);
        assert!(list_ignore_blocked_paths(&conn, "g").unwrap().is_empty());
    }

    /// Non-exact: IgnoreExcluded still fails closed on (a) -- a stale
    /// claimed generation is rejected the same as the exact-outcome path.
    #[test]
    fn non_exact_ignore_excluded_completion_fails_when_generation_moved() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;
        bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 2000).unwrap();

        assert!(!complete_obligation_if_non_exact_proof_current(
            &conn,
            "g",
            "i.txt",
            claimed_g,
            claimed_i,
            NonExactProofKind::IgnoreExcluded,
        )
        .unwrap());
    }

    /// Two paths are independent: closing one's obligation must never
    /// affect another's, exact or non-exact.
    #[test]
    fn completing_one_paths_obligation_never_touches_an_unrelated_path() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
        let obligation_a = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let g_a = obligation_a.invalidation_generation;
        let i_a = obligation_a.obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            2000,
        )
        .unwrap()
        .unwrap();

        assert!(complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            g_a,
            i_a,
            &published.resolved_path_state_hash,
        )
        .unwrap());

        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());
        assert!(
            lookup_projection_obligation(&conn, "g", "b.txt").unwrap().is_some(),
            "b.txt's own obligation must be untouched by a.txt's completion"
        );
    }

    /// `exact_completion_fails_when_dag_side_generation_moved` above already
    /// proves the completion CAS itself rejects a stale claimed generation,
    /// reading the re-armed row back with `lookup_projection_obligation`.
    /// This test goes one step further and proves it through the ACTUAL
    /// entry point a worker would reclaim through: after a concurrent,
    /// independent admission bumps the same path mid-attempt,
    /// `claim_runnable_obligations` itself -- not just a diagnostic lookup
    /// -- must hand the re-armed obligation back at the new generation.
    ///
    /// Confirmed genuinely RED by temporarily dropping the `AND
    /// invalidation_generation = ?3` predicate from
    /// `complete_obligation_if_exact_proof_current`'s `DELETE` statement:
    /// the completion then wrongly reported success and deleted the row,
    /// so both the "completion affects zero rows" assertion and the
    /// "still claimable at G+1" assertion failed together. Restored and
    /// reconfirmed GREEN.
    #[test]
    fn a_concurrent_admissions_rearmed_obligation_is_independently_claimable_through_the_claim_api() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
        assert_eq!(claimed.len(), 1);
        let claimed_g = claimed[0].invalidation_generation;
        let claimed_i = claimed[0].obligation_incarnation;

        let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            fence,
            2000,
        )
        .unwrap()
        .unwrap();

        // A concurrent, independent admission re-arms the obligation to
        // G+1 between this worker's claim and its completion attempt.
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 3000).unwrap();

        assert!(
            !complete_obligation_if_exact_proof_current(
                &conn,
                "g",
                "a.txt",
                claimed_g,
                claimed_i,
                &published.resolved_path_state_hash,
            )
            .unwrap(),
            "a completion attempt at the now-stale claimed generation must affect zero rows"
        );

        let reclaimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
        assert_eq!(
            reclaimed.len(),
            1,
            "the re-armed obligation must still be independently claimable, not just visible to a lookup"
        );
        assert_eq!(reclaimed[0].path, "a.txt");
        assert_eq!(
            reclaimed[0].invalidation_generation,
            claimed_g + 1,
            "reclaiming must observe the new generation the concurrent admission produced"
        );
    }

    /// A content-identical verification's SNAPSHOT (never a bump) of the
    /// fence still lets the exact completion close -- the snapshot value
    /// is what the publish CASed on, so it is exactly as "current" as a
    /// real bump's value for this purpose.
    #[test]
    fn exact_completion_closes_for_a_content_identical_verifications_snapshot_epoch() {
        let conn = conn();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        let claimed_g = claimed_obligation.invalidation_generation;
        let claimed_i = claimed_obligation.obligation_incarnation;

        let snapshot = snapshot_mutation_fence(&conn, "g", "a.txt").unwrap();
        assert_eq!(snapshot, 0, "sanity: nothing has mutated this path yet");
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            snapshot,
            2000,
        )
        .unwrap()
        .unwrap();

        assert!(complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            claimed_g,
            claimed_i,
            &published.resolved_path_state_hash,
        )
        .unwrap());
    }
}

/// Regression coverage for the one-time legacy-backlog bootstrap
/// migration and the coarse `changes.
/// applied` compatibility sweep that replaced the retired
/// `reproject_unapplied_changes` executor.
#[cfg(test)]
mod legacy_scheduler_cutover_tests {
    use super::*;
    use crate::dag_store;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{ChangeAuth, Op};
    use yadorilink_replica_domain::ids::{ChangeHash, SyncPath};

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&c).unwrap();
        c
    }

    fn delete_op(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.to_string()) }
    }

    /// Deletes the obligation `emit_local_change`'s own admission just
    /// created for `path`, simulating a database from before obligation
    /// creation was complete on every durable-transition seam: a retained
    /// `applied = 0` Change with no corresponding obligation row at all.
    fn strip_obligation(conn: &Connection, group_id: &str, path: &str) {
        conn.execute(
            "DELETE FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )
        .unwrap();
    }

    /// `emit_local_change` marks its own Change `applied = 1` immediately
    /// (a local emission's ops describe a write this device already made,
    /// so there is no separate materialization step pending) -- forces it
    /// back to `applied = 0` to simulate the "admitted but unapplied" state
    /// these tests need, exactly as a real remote-origin admission
    /// (`admit_change(.., applied: false)`) would have left it.
    fn force_unapplied(conn: &Connection, hash: &ChangeHash) {
        conn.execute("UPDATE changes SET applied = 0 WHERE change_hash = ?1", [&hash.0[..]])
            .unwrap();
    }

    /// `conn()` already runs `init_dag_schema`, which itself calls
    /// `bootstrap_obligations_from_legacy_unapplied_changes` once (finding
    /// nothing to do yet, since no Changes exist at schema-init time, and
    /// writing the marker regardless -- correct real-world behavior for a
    /// brand-new database). These tests want to invoke the migration
    /// AGAIN, deliberately, against state assembled after that first,
    /// trivial run -- so they clear the marker first, isolating the
    /// function's own backfill logic from its schema-init auto-run.
    fn reset_migration_marker(conn: &Connection) {
        conn.execute(
            "DELETE FROM schema_migration_markers WHERE name = ?1",
            rusqlite::params![LEGACY_UNAPPLIED_CHANGES_BOOTSTRAP_MARKER],
        )
        .unwrap();
    }

    #[test]
    fn backfills_an_obligation_for_a_touched_path_with_none_existing() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[1u8; 32]));
        let change =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        strip_obligation(&conn, "g", "a.txt");
        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());
        reset_migration_marker(&conn);

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 5_000).unwrap();

        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.invalidation_generation, 1, "a freshly backfilled obligation starts at G=1");
        assert_eq!(row.state, "pending");
    }

    #[test]
    fn never_bumps_or_replaces_an_existing_obligation() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[2u8; 32]));
        let first =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        // A second admission bumps the SAME path's obligation to G=2 --
        // this row must survive the migration completely untouched, since
        // `emit_local_change`'s own admission already created it correctly.
        let second =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &first.compute_hash());
        force_unapplied(&conn, &second.compute_hash());
        let before = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(before.invalidation_generation, 2, "test precondition: two admissions bump to G=2");
        reset_migration_marker(&conn);

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 5_000).unwrap();

        let after = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(
            after.invalidation_generation, before.invalidation_generation,
            "migration must never bump an already-existing obligation's generation"
        );
        assert_eq!(after.obligation_incarnation, before.obligation_incarnation);
    }

    #[test]
    fn creates_nothing_for_a_change_already_marked_applied() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[3u8; 32]));
        // Never forced unapplied -- `emit_local_change` already leaves it
        // `applied = 1`, exactly the case this test needs.
        dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();
        strip_obligation(&conn, "g", "a.txt");
        reset_migration_marker(&conn);

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 5_000).unwrap();

        assert!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none(),
            "an already-applied Change's path must not get a backfilled obligation"
        );
    }

    #[test]
    fn a_multi_path_change_backfills_every_distinct_touched_path() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[4u8; 32]));
        // One Change touching two distinct paths -- a plain multi-op
        // Change is enough to exercise "every distinct touched path gets
        // backfilled", without needing a real VersionHash for a Move.
        let change = dag_store::emit_local_change(
            &conn,
            "g",
            vec![delete_op("old.txt"), delete_op("new.txt")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        strip_obligation(&conn, "g", "old.txt");
        strip_obligation(&conn, "g", "new.txt");
        reset_migration_marker(&conn);

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 5_000).unwrap();

        assert!(lookup_projection_obligation(&conn, "g", "old.txt").unwrap().is_some());
        assert!(lookup_projection_obligation(&conn, "g", "new.txt").unwrap().is_some());
    }

    #[test]
    fn a_second_invocation_performs_zero_work_and_never_re_arms_a_completed_path() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[5u8; 32]));
        let change =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        strip_obligation(&conn, "g", "a.txt");
        reset_migration_marker(&conn);

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 5_000).unwrap();
        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_some());

        // Simulate the backfilled obligation completing normally (deleted,
        // same as any other successful completion) while `applied` still
        // reads 0 -- the exact upgrade-window gap this migration exists to
        // close, but only ONCE.
        strip_obligation(&conn, "g", "a.txt");

        bootstrap_obligations_from_legacy_unapplied_changes(&conn, 9_000).unwrap();

        assert!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none(),
            "a second invocation must be a pure no-op -- it must NOT re-arm a path whose \
             obligation already completed after the first (and only) real migration pass"
        );
    }

    /// Exercises the REAL production entry point (`dag_store::
    /// init_dag_schema`), not `bootstrap_obligations_from_legacy_
    /// unapplied_changes` called directly -- every other test in this
    /// module resets the migration marker and calls the helper itself,
    /// which proves the helper's own logic but not that the daemon's
    /// actual startup wiring reaches it, runs it inside its own
    /// transaction (not the bare autocommit `conn`), and produces
    /// identical results. Simulates a genuinely legacy-shaped database:
    /// `conn()` already ran the migration once trivially (nothing to
    /// backfill, marker set) as a side effect of setting up schema, so
    /// this strips the marker back off before adding the legacy-shaped
    /// row, mirroring a database whose migration has never actually run.
    #[test]
    fn init_dag_schema_backfills_a_legacy_database_on_a_real_restart() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[9u8; 32]));
        let change =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        strip_obligation(&conn, "g", "a.txt");
        reset_migration_marker(&conn);
        assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());

        // The real startup/upgrade path -- not the helper called directly.
        dag_store::init_dag_schema(&conn).unwrap();

        let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(row.invalidation_generation, 1);
        assert_eq!(row.state, "pending");

        // A second `init_dag_schema` call (an ordinary subsequent daemon
        // restart) must be a pure no-op through the same real wiring --
        // not just through the helper called directly.
        strip_obligation(&conn, "g", "a.txt");
        dag_store::init_dag_schema(&conn).unwrap();
        assert!(
            lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none(),
            "a second real init_dag_schema call must not re-arm a path whose obligation \
             already completed after the first restart's migration pass"
        );
    }

    #[test]
    fn compatibility_sweep_marks_applied_once_the_group_has_no_pending_obligation_left() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[6u8; 32]));
        let change =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        strip_obligation(&conn, "g", "a.txt");
        let unapplied = dag_store::list_unapplied(&conn, "g").unwrap();
        assert_eq!(unapplied.len(), 1, "test precondition: the change is still applied = 0");

        let affected = reconcile_compatibility_applied_flag_for_group(&conn, "g").unwrap();

        assert_eq!(affected, 1);
        assert!(dag_store::list_unapplied(&conn, "g").unwrap().is_empty());
    }

    #[test]
    fn compatibility_sweep_leaves_applied_flag_alone_while_any_pending_obligation_remains() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[7u8; 32]));
        // Two independent single-path changes in the same group -- only
        // "a.txt"'s own obligation completes; "b.txt"'s stays pending.
        let a =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let b =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("b.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &a.compute_hash());
        force_unapplied(&conn, &b.compute_hash());
        strip_obligation(&conn, "g", "a.txt");

        let affected = reconcile_compatibility_applied_flag_for_group(&conn, "g").unwrap();

        assert_eq!(
            affected, 0,
            "the group still has b.txt's pending obligation outstanding, so NEITHER retained \
             applied=0 Change may be marked applied yet -- this is a group-wide gate, not a \
             per-path one"
        );
        assert_eq!(dag_store::list_unapplied(&conn, "g").unwrap().len(), 2);
    }

    #[test]
    fn compatibility_sweep_treats_ignore_blocked_as_settled_not_outstanding() {
        let conn = conn();
        let em = dag_store::ChangeEmitter::new("device-a", SigningKey::from_bytes(&[8u8; 32]));
        let change =
            dag_store::emit_local_change(&conn, "g", vec![delete_op("a.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        force_unapplied(&conn, &change.compute_hash());
        // Park at `ignore_blocked` rather than deleting -- policy-settled,
        // not outstanding work; must not block the sweep the way a genuine
        // `pending` row does (see the previous test).
        conn.execute(
            "UPDATE projection_obligations SET state = 'ignore_blocked' \
             WHERE group_id = 'g' AND path = 'a.txt'",
            [],
        )
        .unwrap();

        let affected = reconcile_compatibility_applied_flag_for_group(&conn, "g").unwrap();

        assert_eq!(
            affected, 1,
            "an ignore_blocked obligation is policy-settled, not outstanding work, and must \
             not permanently withhold the compatibility flag"
        );
    }
}
