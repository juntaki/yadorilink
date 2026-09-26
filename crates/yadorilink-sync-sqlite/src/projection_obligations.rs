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
            attempt_count           INTEGER NOT NULL DEFAULT 0,
            next_attempt_at         INTEGER NOT NULL DEFAULT 0,
            obligation_incarnation  INTEGER NOT NULL DEFAULT 0,
            -- Which bump seam last touched this row; `'remote'` is the
            -- veto-preserving value (see `ObligationOrigin`).
            origin                  TEXT NOT NULL DEFAULT 'remote',
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
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_projection_obligations_runnable
             ON projection_obligations (state, next_attempt_at);",
    )?;
    // The claim below reads it, so it exists wherever obligations do.
    crate::paused_items::init_paused_items_schema(conn)?;
    crate::snapshot_install_hold::init_snapshot_install_hold_schema(conn)?;
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
/// `unchecked_transaction`. A no-op for an empty
/// `touched_paths` (matches `bump_execution_fence_for_change`'s own
/// early-return shape for the same case).
///
/// **Obligation row-incarnation ABA**: `invalidation_
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
        // below (an earlier draft of this fix left it in place:
        // that made `projection_obligation_incarnations`
        // grow by one permanent row per touched-path event -- unbounded
        // storage growth proportional to total admitted mutations, not to
        // live obligations). This is safe: SQLite's `AUTOINCREMENT` tracks
        // the high-water mark for this table in `sqlite_sequence`
        // independently of which rows currently exist, so deleting the row
        // can never cause a later `INSERT` to reuse `fresh_incarnation`.
        conn.prepare_cached("INSERT INTO projection_obligation_incarnations DEFAULT VALUES")?
            .execute([])?;
        let fresh_incarnation = conn.last_insert_rowid();
        conn.prepare_cached("DELETE FROM projection_obligation_incarnations WHERE id = ?1")?
            .execute(rusqlite::params![fresh_incarnation])?;
        // `origin` is always written as `'remote'` here, on BOTH the fresh
        // `INSERT` and the `ON CONFLICT` bump-in-place arm -- this is the
        // universal, conservative default every one of this function's
        // three call sites gets for free. `admit_prepared_emission` (the
        // sole local-authoring seam) additionally calls
        // [`mark_projection_obligations_local_origin`] immediately
        // afterward, in the SAME transaction, to overwrite it to `'local'`
        // for the paths it just touched. Writing `'remote'` unconditionally
        // in the `ON CONFLICT` arm too (not just on first insert) is
        // deliberate: a later REMOTE-authored admission bumping a path an
        // earlier LOCAL emission had marked must reset origin back to
        // `'remote'`, since the row now again describes desired content
        // this device has not necessarily placed -- see `ObligationOrigin`'s
        // own doc comment for why leaving a stale `'local'` tag in place
        // across a subsequent remote bump would be unsound.
        conn.prepare_cached(
            "INSERT INTO projection_obligations
                (group_id, path, invalidation_generation, state, attempt_count,
                 next_attempt_at, created_at, updated_at, obligation_incarnation, origin)
             VALUES (?1, ?2, 1, 'pending', 0, ?3, ?3, ?3, ?4, 'remote')
             ON CONFLICT (group_id, path) DO UPDATE SET
                invalidation_generation = invalidation_generation + 1,
                state = 'pending',
                attempt_count = 0,
                next_attempt_at = ?3,
                updated_at = ?3,
                origin = 'remote'",
        )?
        .execute(rusqlite::params![group_id, path, now_unix_nanos, fresh_incarnation])?;
    }
    Ok(())
}

/// Diagnostic/test-only read of one path's current obligation, or `None` if
/// no admission has ever touched it. Not consumed by any production
/// scheduling path -- production claims go through
/// [`claim_runnable_obligations`].
pub fn lookup_projection_obligation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<ProjectionObligation>, SyncSqliteError> {
    conn.query_row(
        "SELECT invalidation_generation, state, attempt_count, next_attempt_at, created_at,
                updated_at, obligation_incarnation, origin
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
                origin: ObligationOrigin::from_db_str(&r.get::<_, String>(7)?),
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
    /// comment (obligation row-incarnation ABA).
    pub obligation_incarnation: i64,
    /// Which of the four admission seams' bump most recently touched this
    /// row. See [`ObligationOrigin`]'s own doc comment for what this
    /// distinguishes and why it exists.
    pub origin: ObligationOrigin,
}

/// Which kind of DAG admission most recently bumped a `projection_
/// obligations` row -- the distinction the offline-delete-vs-not-yet-placed
/// tombstone veto was missing.
///
/// `bump_projection_obligations_for_touched_paths` bumps identically for
/// EVERY admission -- a primary change, a promoted orphan, a startup
/// self-heal promotion, or a local emission -- because all four are
/// equally genuine "desired state changed" events from the Convergence
/// Engine's scheduling point of view. But they are NOT equally ambiguous
/// for the *offline-delete-vs-not-yet-placed* question the tombstone veto
/// (`has_unsettled_projection_obligation`, in both
/// `yadorilink-local-capture`'s restart scan and
/// `yadorilink-filesystem-sync`'s interrupted-materialization repair pass)
/// exists to answer: a primary change/promoted orphan/self-heal promotion
/// all describe content that arrived (or was buffered) from a PEER -- this
/// device may not yet have written those bytes anywhere, so the path's
/// absence from disk is genuinely ambiguous between "never materialized
/// yet" and "deleted after materializing." A LOCAL emission is different by
/// construction: `admit_prepared_emission`'s caller already observed the
/// bytes on this device's own disk (that observation IS the local capture
/// that produced the change) before the change was ever admitted -- there
/// is no fetch/materialize step for content this device authored itself,
/// so an obligation whose most recent bump was a local emission can never
/// represent "not yet placed." Its path's absence from disk at scan/repair
/// time can only mean a genuine subsequent deletion.
///
/// `Remote` is the fail-closed default (see the schema migration's own doc
/// comment and `bump_projection_obligations_for_touched_paths`'s own doc
/// comment on why the `ON CONFLICT` arm always resets to `Remote`): only
/// `admit_prepared_emission`'s own immediate follow-up call to
/// [`mark_projection_obligations_local_origin`] ever produces `Local`, and
/// any later bump from ANY of the other three seams overwrites it back to
/// `Remote` -- so a path that ever again needs content from elsewhere loses
/// its `Local` tag the instant that need is recorded, never leaving a stale
/// `Local` tag protecting the wrong generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOrigin {
    /// This device authored the change itself; the desired bytes were
    /// already on this device's own disk (observed directly by local
    /// capture) before the obligation was ever created. Never a "not yet
    /// placed" veto reason.
    Local,
    /// The change came from (or through) a peer -- a primary admission, a
    /// promoted orphan, or a startup self-heal promotion. This device may
    /// not have the desired bytes on disk yet. The veto-preserving default.
    Remote,
}

impl ObligationOrigin {
    /// Any value other than the literal `"local"` this crate itself ever
    /// writes -- including a value from some future, not-yet-understood
    /// migration path -- reads as `Remote`, matching the column's own
    /// fail-closed `DEFAULT 'remote'`.
    fn from_db_str(s: &str) -> Self {
        match s {
            "local" => ObligationOrigin::Local,
            _ => ObligationOrigin::Remote,
        }
    }
}

/// Overwrites the `origin` of the just-bumped obligation row for each of
/// `touched_paths` to [`ObligationOrigin::Local`]. Must be called in the
/// SAME transaction as, and strictly after,
/// [`bump_projection_obligations_for_touched_paths`] for the same
/// `touched_paths` -- it updates whatever row currently exists for
/// `(group_id, path)`, which that preceding call is what guarantees is the
/// row this bump just touched, not a stale one from an earlier admission.
///
/// The sole production call site is `admit_prepared_emission` (the local-
/// authoring emission seam) -- see [`ObligationOrigin`]'s own doc comment
/// for why only that seam ever produces `Local`.
pub fn mark_projection_obligations_local_origin(
    conn: &Connection,
    group_id: &str,
    touched_paths: &[&str],
) -> Result<(), SyncSqliteError> {
    for path in touched_paths {
        conn.execute(
            "UPDATE projection_obligations SET origin = 'local'
              WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
    }
    Ok(())
}

/// One obligation a claim call handed to a worker: enough to drive an
/// attempt (`group_id`, `path`) and enough to close it afterward
/// (`invalidation_generation`, the generation `G` this claim observed).
/// Deliberately carries no version hash: unlike `MaterializationJob`, the
/// desired state is always recomputed fresh at resolve time, never carried
/// from claim time, so there is nothing here that could go stale between
/// claim and close other than `G` itself and `obligation_incarnation`,
/// which the completion primitives re-check directly (`G` alone is not
/// enough -- see `bump_projection_obligations_for_touched_
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
///
/// A path covered by a paused item (see `crate::paused_items`) is not
/// runnable: its obligation stays exactly as admission left it, pending,
/// until the item is resumed. Excluded here rather than skipped after the
/// claim, because a paused row skipped later would still take a slot of
/// its group's per-group window on every tick, and the oldest rows fill
/// that window first -- a paused folder with enough held changes would
/// starve every other path of its group.
///
/// A path a snapshot install holds (see `crate::snapshot_install_hold`) is
/// excluded the same way, for a stronger reason: projecting the installed
/// version would overwrite whatever is on disk there, and until the
/// install's reconciliation has looked at it that may be an edit nobody has
/// captured.
pub fn claim_runnable_obligations(
    conn: &Connection,
    now_unix_nanos: i64,
    per_group_limit: u32,
    total_limit: u32,
) -> Result<Vec<ClaimedObligation>, SyncSqliteError> {
    let mut stmt = conn.prepare(&format!(
        "WITH runnable AS ( \
            SELECT group_id, path, invalidation_generation, obligation_incarnation, \
                   attempt_count, updated_at, \
                   ROW_NUMBER() OVER ( \
                PARTITION BY group_id ORDER BY updated_at ASC, path ASC \
            ) AS group_rank \
            FROM projection_obligations \
            WHERE state = 'pending' AND next_attempt_at <= ?1 \
              AND NOT {paused} \
              AND NOT {held} \
         ) \
         SELECT group_id, path, invalidation_generation, obligation_incarnation, attempt_count \
         FROM runnable \
         WHERE group_rank <= ?2 \
         ORDER BY updated_at ASC, path ASC \
         LIMIT ?3",
        paused = crate::paused_items::covered_by_paused_item_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
        held = crate::snapshot_install_hold::held_sql(
            "projection_obligations.group_id",
            "projection_obligations.path",
        ),
    ))?;
    let rows =
        stmt.query_map(rusqlite::params![now_unix_nanos, per_group_limit, total_limit], |r| {
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
/// possible future optimization, not a requirement. `None` when
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
    /// Closes against the path's EXISTING retained-directory record
    /// (`crate::structural_origin::record_retained_directory`): the
    /// replicated entry is settled as deleted, and the physical directory
    /// stays because it is not empty. A record cleared between the
    /// decision and this close (the directory was removed, or the path
    /// took an entry again) leaves the obligation for re-resolution.
    RetainedDirectory,
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
        NonExactProofKind::RetainedDirectory => conn.execute(
            "DELETE FROM projection_obligations
              WHERE group_id = ?1 AND path = ?2
                AND invalidation_generation = ?3
                AND obligation_incarnation = ?4
                AND EXISTS (
                     SELECT 1 FROM retained_directories
                      WHERE group_id = ?1 AND path = ?2
                )",
            rusqlite::params![
                group_id,
                path,
                claimed_invalidation_generation,
                claimed_obligation_incarnation
            ],
        )?,
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

#[cfg(test)]
mod tests;

/// Direct, deterministic tests for the compound completion primitives, at
/// the persistence/API level, before any production scheduling change
/// wires them in.
#[cfg(test)]
mod completion_tests;
