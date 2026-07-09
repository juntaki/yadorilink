//! Local daemon state: the per-device file index (task 5.3) and folder-link
//! registration (task 5.1) with pause/resume (task 6.8). Both live in one
//! SQLite database, mirroring the pattern used by `yadorilink-coordination`.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncError;
use crate::types::{
    BlockInfo, ChunkingPolicy, FileRecord, LinkMode, MaterializationPolicy, MaterializationState,
    RecordKind,
};
use crate::version_vector::VersionVector;

type PathLockKey = (String, String);
type PathLock = Arc<tokio::sync::Mutex<()>>;
type PathLockMap = HashMap<PathLockKey, PathLock>;
pub type ContentHash = String;

/// sync-performance PERF-3: every connection made by the pool waits at
/// most this long for the SQLite write lock (`PRAGMA busy_timeout`)
/// before giving up with `SQLITE_BUSY`, instead of erroring immediately.
/// Under the old design a single `Mutex<Connection>` meant SQLite itself
/// never saw concurrent access from this process, so `SQLITE_BUSY` could
/// only come from an external writer; pooling multiple real connections
/// means two of *our own* threads can now race for SQLite's single
/// writer slot, and without a busy timeout that race would surface as a
/// new, previously-impossible `SyncError::Db` instead of just blocking
/// like the old mutex did. Chosen generously (default r2d2 connection
/// checkout timeout is 30s) so a slow batch write practically never
/// trips it.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The deterministic-simulation test setup's long-sweep hardening: one
/// process-lifetime `ScheduledThreadPool`, shared by *every* r2d2 pool
/// this crate opens under `cfg(madsim)`, instead of letting each
/// `Pool::builder()` default to its own fresh 3-thread pool.
///
/// r2d2 uses this thread pool for connection *establishment* (and, when
/// enabled, reaping — already disabled here via `max_lifetime(None)`/
/// `idle_timeout(None)`). By default `Builder::build` creates a brand-new
/// `ScheduledThreadPool::new(3)` per pool (see r2d2's `config.rs`), and
/// `scheduled_thread_pool`'s `Drop` only *signals* shutdown — it does not
/// join the worker threads — so their real OS-thread teardown lags
/// arbitrarily behind each `SyncState` drop. A DST sweep opens two
/// `SyncState`s per seed and runs thousands of seeds sequentially in one
/// process, so that per-pool ×3 thread churn is exactly the cumulative
/// pressure `dst_two_device_chaos.rs`'s `RESOURCE_EXHAUSTION_MARKER`
/// documents (`WouldBlock`/`EAGAIN` as the process approaches `ulimit
/// -u`). Funnelling every madsim pool through one shared pool makes real
/// thread creation a small constant for the whole sweep instead of
/// `O(3 × pools-per-seed × seeds)`.
///
/// madsim-only (`cfg`, not a runtime `if`): the shared static and its
/// dependency are compiled out of every normal build, so production keeps
/// r2d2's stock per-pool defaults untouched.
#[cfg(madsim)]
fn madsim_shared_thread_pool() -> std::sync::Arc<scheduled_thread_pool::ScheduledThreadPool> {
    use std::sync::OnceLock;
    static SHARED: OnceLock<std::sync::Arc<scheduled_thread_pool::ScheduledThreadPool>> =
        OnceLock::new();
    SHARED
        .get_or_init(|| {
            // 3 threads: matches r2d2's own per-pool default so a single
            // pool's establishment behavior is unchanged; the win is that
            // this is now the *only* such set for the whole process.
            std::sync::Arc::new(scheduled_thread_pool::ScheduledThreadPool::new(3))
        })
        .clone()
}

/// Builds the r2d2 connection pool for a `SyncState`.
///
/// Under `cfg(madsim)` the pool disables r2d2's per-connection reaper
/// (`max_lifetime(None)`/`idle_timeout(None)`) *and* routes establishment
/// through one process-shared `ScheduledThreadPool` (see
/// `madsim_shared_thread_pool`) so a long sequential DST sweep doesn't
/// accumulate OS threads. Every normal build uses r2d2's stock defaults,
/// unchanged.
#[cfg(madsim)]
fn madsim_or_default_pool(
    manager: SqliteConnectionManager,
) -> Result<Pool<SqliteConnectionManager>, SyncError> {
    Ok(Pool::builder()
        .max_lifetime(None)
        .idle_timeout(None)
        .thread_pool(madsim_shared_thread_pool())
        .build(manager)?)
}

#[cfg(not(madsim))]
fn madsim_or_default_pool(
    manager: SqliteConnectionManager,
) -> Result<Pool<SqliteConnectionManager>, SyncError> {
    Ok(Pool::new(manager)?)
}

/// An explicit, monotonically
/// increasing marker for this crate's on-disk schema, stored via SQLite's
/// built-in `PRAGMA user_version` (a plain integer SQLite reserves in the
/// database header specifically for application use — no extra table
/// needed, so this doesn't disturb the crate's existing "no separate
/// schema-version table" convention for detecting *which* migrations have
/// run; every individual migration above still self-detects from the
/// actual table shape exactly as before). This purely adds a fast,
/// explicit downgrade check (`check_schema_not_newer_than_supported`)
/// layered on top: bump this constant whenever a migration changes the
/// on-disk shape in a way an older binary must not silently reopen.
/// Version 1 is the schema as of the first public beta baseline (every
/// migration present in this file up to this point).
pub const SCHEMA_VERSION: i32 = 1;

pub struct SyncState {
    /// sync-performance PERF-3: was a single `Mutex<Connection>` — every
    /// call, including pure reads, serialized through one lock and one
    /// SQLite connection. Now each call checks out its own pooled
    /// connection (`r2d2` + `r2d2_sqlite`) against a WAL-mode database,
    /// so multiple readers (and a reader alongside a writer) proceed
    /// concurrently instead of blocking on each other — SQLite's own WAL
    /// concurrency model, not an in-process lock, now governs access.
    /// Writers still serialize against each other (SQLite allows only one
    /// writer at a time even in WAL mode), handled by `BUSY_TIMEOUT`
    /// rather than an in-process mutex.
    pool: Pool<SqliteConnectionManager>,
    /// COR-5: per-`(group_id, path)` locks serializing local-change
    /// indexing (`LocalChangeProcessor::process_event`) against peer
    /// reconciliation (`PeerSyncSession::reconcile_one_file`) for the
    /// same path — see `path_lock`'s doc comment for the race this
    /// closes. A plain `HashMap` of `Arc<tokio::sync::Mutex<()>>` (not a
    /// single process-wide lock) so unrelated paths never contend with
    /// each other; entries are never removed, but real deployments touch
    /// a bounded number of distinct paths per link, not an unbounded
    /// stream of unique ones. `tokio::sync::Mutex` specifically (not
    /// `std::sync::Mutex`) because `reconcile_one_file` needs to hold the
    /// guard across `.await` points (a block fetch can take real time) —
    /// a `std::sync::MutexGuard` isn't `Send`, which broke `tokio::spawn`
    /// on the per-connection message-handling task the first time this
    /// was tried with a blocking mutex here. The registry map itself
    /// (this outer `Mutex`) stays `std::sync::Mutex`: it's only ever held
    /// briefly to look up/insert an entry, never across an await.
    path_locks: Mutex<PathLockMap>,
}

/// Rebuilds `files` from its pre-this-
/// change shape (primary key `(group_id, path)`) into the version-history
/// shape (primary key `(group_id, path, version_seq)`, plus `state`/
/// `origin_device_id`) — see `SyncState::init`'s call site for why this
/// can't be an `ALTER TABLE ADD COLUMN` like every other migration here.
///
/// A no-op in two cases, both detected purely from `files`' own current
/// shape (no separate schema-version table, matching this crate's existing
/// no-schema-version-table convention): a brand-new database (`files`
/// doesn't exist yet — `SyncState::init`'s own `CREATE TABLE IF NOT
/// EXISTS` creates the final shape directly), and a database that has
/// already been through this migration (`files.version_seq` already
/// exists). Otherwise, creates `files_new` with the full new schema,
/// copies every existing row across — preserving whatever subset of the
/// later `ALTER TABLE ADD COLUMN` columns (`materialization_state`,
/// `pinned`, `record_kind`, etc.) this particular database happens to
/// already have, defaulting any it doesn't — as `version_seq = 1, state =
/// 'current', origin_device_id = NULL` (every pre-existing row was, by
/// definition, the only row that existed for its path; there is no
/// history to backfill, which is honest — this change's retention only
/// starts accruing from the first edit/delete after upgrade), then drops
/// the old table and renames the new one into place.
/// Same shape as
/// `peer_session`'s and `link_manager`'s private `now_unix_nanos` helpers —
/// used by `mark_deleted` to stamp a tombstone with the deletion's own
/// observed time rather than carrying forward stale content mtime.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn migrate_files_table_widen_primary_key(conn: &Connection) -> Result<(), SyncError> {
    if !table_exists(conn, "files")? {
        return Ok(());
    }
    if files_table_has_column(conn, "version_seq")? {
        return Ok(());
    }

    // Every column a prior change has ever added to `files` via `ALTER
    // TABLE ... ADD COLUMN ... DEFAULT ...`, paired with that same
    // default expression (as a literal SQL fragment) — used below only for
    // whichever of these a *given* pre-existing database doesn't already
    // have, so its rows still get the exact same default value they'd get
    // from the ordinary `ALTER TABLE` loop having run instead.
    const OPTIONAL_COLUMNS: &[(&str, &str)] = &[
        ("materialization_state", "'hydrated'"),
        ("pinned", "0"),
        ("last_accessed_unix", "NULL"),
        ("record_kind", "'file'"),
        ("symlink_target", "NULL"),
        ("exec_bit", "0"),
        ("held_reason", "NULL"),
        ("held_since_unix_nanos", "NULL"),
        ("symlink_out_of_root", "0"),
    ];
    let mut select_list =
        String::from("group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted");
    let mut insert_list = select_list.clone();
    for (col, default_expr) in OPTIONAL_COLUMNS {
        insert_list.push_str(", ");
        insert_list.push_str(col);
        select_list.push_str(", ");
        if files_table_has_column(conn, col)? {
            select_list.push_str(col);
        } else {
            select_list.push_str(default_expr);
        }
    }

    conn.execute_batch(&format!(
        r#"
        CREATE TABLE files_new (
            group_id               TEXT NOT NULL,
            path                    TEXT NOT NULL,
            size                    INTEGER NOT NULL,
            mtime_unix_nanos        INTEGER NOT NULL,
            version_json            TEXT NOT NULL,
            blocks_json             TEXT NOT NULL,
            deleted                 INTEGER NOT NULL DEFAULT 0,
            -- Column order from here down matches `SyncState::init`'s own
            -- `CREATE TABLE IF NOT EXISTS files` exactly (`version_seq`/
            -- `state`/`origin_device_id` immediately after `deleted`, then
            -- every optional column in the order its own `ALTER TABLE`
            -- migration originally introduced it) — `PRAGMA table_info`
            -- reports column order, and `fresh_and_upgraded_schema_are_
            -- identical` asserts a fresh database and one rebuilt by this
            -- migration produce byte-for-byte identical output, not just
            -- the same *set* of columns.
            version_seq             INTEGER NOT NULL DEFAULT 1,
            state                   TEXT NOT NULL DEFAULT 'current',
            origin_device_id        TEXT,
            materialization_state   TEXT NOT NULL DEFAULT 'hydrated',
            pinned                  INTEGER NOT NULL DEFAULT 0,
            last_accessed_unix      INTEGER,
            record_kind             TEXT NOT NULL DEFAULT 'file',
            symlink_target          TEXT,
            exec_bit                INTEGER NOT NULL DEFAULT 0,
            held_reason             TEXT,
            held_since_unix_nanos   INTEGER,
            symlink_out_of_root     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path, version_seq)
        );
        INSERT INTO files_new ({insert_list}, version_seq, state, origin_device_id)
            SELECT {select_list}, 1, 'current', NULL FROM files;
        DROP TABLE files;
        ALTER TABLE files_new RENAME TO files;
        "#
    ))?;
    Ok(())
}

/// Reads `PRAGMA user_version` and
/// errors if it's newer than this binary's [`SCHEMA_VERSION`] — an older
/// binary opening state a newer one already migrated. Deliberately checked
/// *before* any migration statement runs (see `init`'s call site), so an
/// unsupported downgrade is refused outright rather than partially applying
/// migrations against a shape this binary doesn't fully understand.
fn check_schema_not_newer_than_supported(conn: &Connection) -> Result<(), SyncError> {
    let on_disk_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if on_disk_version > SCHEMA_VERSION {
        return Err(SyncError::UnsupportedSchemaDowngrade {
            on_disk_version,
            supported_version: SCHEMA_VERSION,
        });
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, SyncError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

fn files_table_has_column(conn: &Connection, column: &str) -> Result<bool, SyncError> {
    let mut stmt = conn.prepare("PRAGMA table_info(files)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The shared version-retaining write
/// path behind `SyncState::upsert_file_with_origin` and
/// `SyncState::upsert_files_batch` — see `upsert_file_with_origin`'s doc
/// comment for the full semantics. Takes an open `Transaction` rather than
/// checking out its own pooled connection so a batch caller can commit
/// once for many records (mirroring the pre-existing `upsert_files_batch`
/// shape) while a single-record caller still gets the same atomicity via
/// its own one-record transaction — see `new_immediate_write_transaction`'s
/// doc comment for why that transaction must be opened `IMMEDIATE`, not
/// rusqlite's default `DEFERRED`.
///
/// sync-performance: `upsert_file_with_origin` is the hot path for every
/// local edit and every peer-adopted change, so this is written for two
/// SQLite round trips, not the more obvious three (a `SELECT` to find the
/// current row, an `INSERT` for the new one, an `UPDATE` to flip the old
/// one). An earlier draft chased this down to a *single* round trip with
/// an `AFTER INSERT` trigger; that turned out not to be the actual
/// bottleneck (see `new_immediate_write_transaction`) and introduced its
/// own correctness risk (a trigger recursing into the same table its own
/// statement is still executing over), so it was reverted in favor of this
/// plainer two-statement version.
///
/// The first round trip below is an `UPDATE ... RETURNING`: it flips
/// whatever row is currently `state = 'current'` (if any) to
/// `superseded`/`trashed` per 's rule *and* returns everything
/// needed to build the new current row, so no separate up-front `SELECT`
/// is needed before it.
fn upsert_file_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    record: &FileRecord,
    origin_device_id: &str,
) -> Result<(), SyncError> {
    let version_json = serde_json::to_string(record.version.counters())?;
    let blocks_json = serde_json::to_string(&record.blocks)?;
    let origin: Option<&str> =
        if origin_device_id.is_empty() { None } else { Some(origin_device_id) };

    #[allow(clippy::type_complexity)]
    let flipped: Option<(
        i64,
        i64,
        String,
        i64,
        Option<i64>,
        String,
        Option<String>,
        i64,
        Option<String>,
        Option<i64>,
        i64,
    )> = tx
        .query_row(
            "UPDATE files SET state = CASE WHEN deleted = 0 AND ?3 = 1 THEN 'trashed' ELSE 'superseded' END
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'
             RETURNING version_seq, deleted, materialization_state, pinned, last_accessed_unix,
                       record_kind, symlink_target, exec_bit, held_reason, held_since_unix_nanos,
                       symlink_out_of_root",
            rusqlite::params![group_id, record.path, record.deleted as i64],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                ))
            },
        )
        .optional()?;

    match flipped {
        None => {
            // Brand new path.
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted, version_seq, state, origin_device_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 'current', ?8)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    version_json,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                ],
            )?;
        }
        // The `apply_incoming_wire_metadata` bootstrap scaffold
        // (`version_seq = 0`, created by `ensure_bootstrap_row_for_metadata`)
        // was never a genuine observed version — the `UPDATE` above
        // incorrectly flipped it to superseded/trashed as a side effect of
        // matching `state = 'current'`; undo that and promote it to
        // version 1 in place (an `UPDATE`, not a fresh `INSERT`, so
        // whatever `record_kind`/`symlink_target`/`exec_bit`/etc. its own
        // setters already wrote onto it survives untouched) instead of
        // leaving a spurious empty first version in this path's history.
        // Rare (a scaffold row exists for at most the moment between its
        // own creation and this call), so the extra round trip here
        // doesn't cost the common case anything.
        Some((0, ..)) => {
            tx.execute(
                "UPDATE files SET size = ?1, mtime_unix_nanos = ?2, version_json = ?3, blocks_json = ?4, deleted = ?5, version_seq = 1, state = 'current', origin_device_id = ?6
                 WHERE group_id = ?7 AND path = ?8 AND version_seq = 0",
                rusqlite::params![
                    record.size,
                    record.mtime_unix_nanos,
                    version_json,
                    blocks_json,
                    record.deleted as i64,
                    origin,
                    group_id,
                    record.path,
                ],
            )?;
        }
        Some((
            old_seq,
            _old_deleted,
            materialization_state,
            pinned,
            last_accessed_unix,
            record_kind,
            symlink_target,
            exec_bit,
            held_reason,
            held_since_unix_nanos,
            symlink_out_of_root,
        )) => {
            // Every per-file column `FileRecord` doesn't carry
            // (materialization state, pinned, record kind, symlink target,
            // exec bit, held state) is copied forward from the row just
            // superseded — already in hand from the `RETURNING` above, no
            // extra read needed — so a version bump alone never silently
            // resets any of them to their column defaults. Which new
            // `state` the old row ended up as (`trashed` vs `superseded`)
            // was already decided by the `CASE` in the `UPDATE` above.
            tx.execute(
                "INSERT INTO files (
                    group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted,
                    version_seq, state, origin_device_id,
                    materialization_state, pinned, last_accessed_unix, record_kind,
                    symlink_target, exec_bit, held_reason, held_since_unix_nanos, symlink_out_of_root
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'current', ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                rusqlite::params![
                    group_id,
                    record.path,
                    record.size,
                    record.mtime_unix_nanos,
                    version_json,
                    blocks_json,
                    record.deleted as i64,
                    old_seq + 1,
                    origin,
                    materialization_state,
                    pinned,
                    last_accessed_unix,
                    record_kind,
                    symlink_target,
                    exec_bit,
                    held_reason,
                    held_since_unix_nanos,
                    symlink_out_of_root,
                ],
            )?;
        }
    }
    Ok(())
}

/// One half of the fix for the `SQLITE_LOCKED: database table is locked`
/// failures `upsert_file_in_tx`'s doc comment describes (found via a
/// `tracing_subscriber`-instrumented rerun of a failing `yadorilink-daemon`
/// integration test — the error was otherwise only logged as a `tracing::
/// warn!` deep inside `PeerSyncSession::reconcile_files`, never surfaced as
/// a panic on its own). `rusqlite::Connection::transaction()` opens a
/// `DEFERRED` transaction by default, which only acquires SQLite's write
/// (`RESERVED`) lock lazily, on the *first write statement actually
/// executed inside it* — not at `BEGIN` time. `upsert_file_in_tx`'s first
/// statement (`UPDATE ... RETURNING`) is a read-then-write, so under this
/// crate's connection pool (many pooled connections concurrently
/// reconciling different files, per `PeerSyncSession::reconcile_files`'s
/// `MAX_CONCURRENT_RECONCILES` concurrent tasks) a deferred transaction's
/// `SHARED`-to-`RESERVED` lock upgrade can lose a race against another
/// pooled connection's concurrent read — SQLite's classic deferred-
/// transaction lock-upgrade pitfall. Opening the transaction `IMMEDIATE`
/// instead acquires the `RESERVED` write lock immediately at `BEGIN`,
/// closing that specific upgrade-race window. The old, pre-this-change
/// `upsert_file` never hit any of this because it was a single `execute()`
/// call with no explicit transaction at all — autocommit for one statement
/// acquires exactly the lock that statement needs, with no separate
/// upgrade step to lose a race on.
///
/// **This alone was not sufficient** — see `retry_on_database_locked`
/// immediately below for the other half, and why: `SQLITE_LOCKED` can also
/// arise from SQLite's shared-cache table-locking directly (independent of
/// the deferred-transaction upgrade problem this function closes), which
/// this crate's `open_in_memory` deliberately opts into (`cache=shared`,
/// required for pooled connections to see the same in-memory database at
/// all) — so both mitigations are needed together, not either alone.
fn new_immediate_write_transaction(
    conn: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, SyncError> {
    Ok(conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?)
}

/// The other half of the `SQLITE_LOCKED` fix (see
/// `new_immediate_write_transaction`'s doc comment for the first half and
/// the full diagnostic story). SQLite's own documentation is explicit that
/// `SQLITE_LOCKED` arising from shared-cache table locking (as opposed to
/// schema corruption or a genuinely permanent conflict) is meant to be
/// handled by the *caller* retrying the whole failed transaction after a
/// short wait — unlike `SQLITE_BUSY`, it is deliberately **not** always
/// auto-retried by `sqlite3_busy_timeout`'s busy handler for every
/// shared-cache lock-conflict shape. Wraps `op` (expected to be a
/// self-contained "check out a connection, open a transaction, do the
/// work, commit" closure — safe to call more than once, since a failed
/// transaction rolls back and leaves no partial state to retry against)
/// and retries it on `SQLITE_LOCKED` specifically, up to a small bounded
/// number of attempts with a short linear backoff. Every other error
/// (including `SQLITE_BUSY`, already handled by `BUSY_TIMEOUT`, and any
/// genuine data error) propagates immediately, unretried.
fn retry_on_database_locked<T>(
    mut op: impl FnMut() -> Result<T, SyncError>,
) -> Result<T, SyncError> {
    const MAX_ATTEMPTS: u32 = 10;
    let mut attempt: u32 = 0;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(e) if attempt + 1 < MAX_ATTEMPTS && is_database_locked_error(&e) => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(5 * attempt as u64));
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_database_locked_error(err: &SyncError) -> bool {
    matches!(
        err,
        SyncError::Db(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

impl SyncState {
    /// Opens (creating if needed) a file-backed database with WAL mode
    /// enabled (sync-performance PERF-3) — WAL lets readers proceed
    /// without blocking behind the single writer SQLite allows at a
    /// time, unlike the default rollback-journal mode. Every pooled
    /// connection additionally gets `BUSY_TIMEOUT` so two of this
    /// process's own writers waiting on each other resolve by retrying,
    /// not erroring.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SyncError> {
        let manager = SqliteConnectionManager::file(path.as_ref()).with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            // journal_mode is itself a query (it returns the mode that
            // was actually applied), hence `pragma_update_and_check`
            // rather than `pragma_update`.
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
            Ok(())
        });
        let pool = madsim_or_default_pool(manager)?;
        let conn = pool.get()?;
        Self::init(&conn)?;
        drop(conn);
        Ok(Self { pool, path_locks: Mutex::new(HashMap::new()) })
    }

    /// Opens an in-memory database, pooled just like the file-backed case
    /// (sync-performance PERF-3). Plain SQLite `:memory:` databases are
    /// private to the single connection that opened them, so naively
    /// pooling one would give each checkout its own empty database and
    /// silently break every write-then-read call pattern. `r2d2_sqlite`'s
    /// `SqliteConnectionManager::memory()` avoids that: it opens
    /// `file:<uuid>?mode=memory&cache=shared` (a *named*, shared-cache
    /// in-memory database — `rusqlite`'s default `OpenFlags` already
    /// include `SQLITE_OPEN_URI`, so the URI form works without extra
    /// flags) so every pooled connection attaches to the *same*
    /// in-memory database, and it internally keeps one extra connection
    /// alive for the manager's lifetime so the database isn't dropped the
    /// instant the pool's checked-out connections all happen to be idle
    /// (shared-cache `:memory:` databases are freed when their last
    /// connection closes). WAL mode is skipped here: SQLite doesn't
    /// support WAL for in-memory databases (the pragma is a no-op), only
    /// `BUSY_TIMEOUT` is needed so pooled writers don't race each other
    /// into `SQLITE_BUSY`. See `pooled_connections_share_in_memory_state`
    /// below for a test proving this actually works across two distinct
    /// pooled connections, not just within one.
    pub fn open_in_memory() -> Result<Self, SyncError> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            Ok(())
        });
        let pool = madsim_or_default_pool(manager)?;
        let conn = pool.get()?;
        Self::init(&conn)?;
        drop(conn);
        Ok(Self { pool, path_locks: Mutex::new(HashMap::new()) })
    }

    /// COR-5: returns the shared lock for `(group_id, path)`, creating it
    /// on first use. Lock it (`.lock().await`) and hold the guard for the
    /// *entire* read-compare-write critical section — re-reading the
    /// current index state after acquiring it, not before — so a local
    /// save (`LocalChangeProcessor::process_event`) and an incoming
    /// peer's newer version for the same path (`PeerSyncSession::
    /// reconcile_one_file`) can never interleave into a state where the
    /// just-saved content is overwritten on disk while the index records
    /// a version/blocks that don't match it (previously reachable: both
    /// paths span multiple independently-locked `SyncState` calls with
    /// no path-level lock at all).
    pub fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.path_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry((group_id.to_string(), path.to_string()))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn init(conn: &Connection) -> Result<(), SyncError> {
        // Refuse to touch a database
        // an older binary migrated *this* binary doesn't understand,
        // before any migration below runs a single statement against it —
        // an unsupported downgrade must error cleanly, not silently drop
        // into the migration loop and potentially reinterpret/clobber
        // columns this binary has never heard of. A brand-new database
        // reads `user_version = 0` (SQLite's own default), which is always
        // `<= SCHEMA_VERSION`, so this never blocks first-run.
        check_schema_not_newer_than_supported(conn)?;

        // Widening `files`' primary key
        // from `(group_id, path)` to `(group_id, path, version_seq)` is not
        // expressible as an `ALTER TABLE ... ADD COLUMN` — SQLite has no
        // syntax to change a declared primary key in place. Must run
        // *before* the `CREATE TABLE IF NOT EXISTS`/`ALTER TABLE` migration
        // below, which only ever adds columns to whatever `files` table
        // already exists; see the function's own doc comment for the
        // rebuild it performs (a no-op on a brand-new database, and
        // idempotent on one already migrated).
        migrate_files_table_widen_primary_key(conn)?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                group_id          TEXT NOT NULL,
                path              TEXT NOT NULL,
                size              INTEGER NOT NULL,
                mtime_unix_nanos  INTEGER NOT NULL,
                version_json      TEXT NOT NULL,
                blocks_json       TEXT NOT NULL,
                deleted           INTEGER NOT NULL DEFAULT 0,
                -- A per-`(group_id,
                -- path)` monotonically increasing counter. Exactly one row
                -- per `(group_id, path)` has `state = 'current'` at a time;
                -- `state` and `origin_device_id` below are additionally
                -- covered by the `ALTER TABLE` loop further down for a
                -- database whose `files` table pre-dates this change but
                -- was somehow left with the old primary key by the rebuild
                -- above (defensive; the rebuild always adds them itself).
                version_seq       INTEGER NOT NULL DEFAULT 1,
                state             TEXT NOT NULL DEFAULT 'current',
                origin_device_id  TEXT,
                PRIMARY KEY (group_id, path, version_seq)
            );

            CREATE TABLE IF NOT EXISTS links (
                local_path TEXT PRIMARY KEY,
                group_id   TEXT NOT NULL,
                paused     INTEGER NOT NULL DEFAULT 0
            );

            -- Divergence tracking for
            -- a gated direction — new tables (not `ALTER TABLE`s), so
            -- `CREATE TABLE IF NOT EXISTS` alone is the whole migration for
            -- these, the same way `files`/`links` themselves were
            -- originally created. Keyed by (group_id, path), like `files`
            -- — a link only ever has one outstanding divergence entry per
            -- path, superseded (via `INSERT OR REPLACE`) by a fresher one
            -- rather than accumulating a history.
            CREATE TABLE IF NOT EXISTS out_of_sync_items (
                group_id               TEXT NOT NULL,
                path                   TEXT NOT NULL,
                recorded_at_unix_nanos INTEGER NOT NULL,
                PRIMARY KEY (group_id, path)
            );
            CREATE TABLE IF NOT EXISTS receive_only_changed_items (
                group_id               TEXT NOT NULL,
                path                   TEXT NOT NULL,
                recorded_at_unix_nanos INTEGER NOT NULL,
                PRIMARY KEY (group_id, path)
            );
            "#,
        )?;
        // Lightweight migrations (on-demand-sync): `CREATE TABLE IF NOT
        // EXISTS` above is a no-op against a database from before these
        // columns existed, so add them explicitly, ignoring the
        // "duplicate column" error on a database that already has them.
        // Existing rows default to `hydrated`/`eager` — every file and
        // link already on disk before this change keeps behaving exactly
        // as it did — no rollback concerns for this migration.
        for stmt in [
            "ALTER TABLE files ADD COLUMN materialization_state TEXT NOT NULL DEFAULT 'hydrated'",
            "ALTER TABLE files ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE files ADD COLUMN last_accessed_unix INTEGER",
            "ALTER TABLE links ADD COLUMN materialization_policy TEXT NOT NULL DEFAULT 'eager'",
            "ALTER TABLE links ADD COLUMN max_local_size_bytes INTEGER",
            // content-defined-chunking: existing links default to
            // 'fixed', the pre-existing behavior — no change without
            // opt-in, matching the migration guarantee already
            // established for materialization_policy above.
            "ALTER TABLE links ADD COLUMN chunking_policy TEXT NOT NULL DEFAULT 'fixed'",
            // Every pre-existing row
            // defaults to `record_kind = 'file'` (the only kind scan/watch
            // ever produced before this change) with no symlink target,
            // `exec_bit = 0` (no workflow depended on the bit being set,
            // since it was never captured or propagated at all), and no
            // held state (nothing was ever held before hazard detection
            // existed) — every existing installation keeps behaving
            // exactly as it did, matching the "no behavior change without
            // opt-in" guarantee already established above.
            "ALTER TABLE files ADD COLUMN record_kind TEXT NOT NULL DEFAULT 'file'",
            "ALTER TABLE files ADD COLUMN symlink_target TEXT",
            "ALTER TABLE files ADD COLUMN exec_bit INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE files ADD COLUMN held_reason TEXT",
            "ALTER TABLE files ADD COLUMN held_since_unix_nanos INTEGER",
            // Whether a symlink's raw target is
            // an absolute path, or resolves (syntactically, never via
            // dereferencing) outside the linked folder's root. Deliberately
            // a *separate* column from `held_reason`/`held_since_unix_nanos`
            // above rather than reusing them: `held_*` (section 4) gates
            // materialization — a held file is never written to disk. An
            // out-of-root/absolute symlink is not held by this flag alone —
            // says it's "synced as a record like any other
            // symlink but flagged", so it must keep materializing normally
            // (as a real symlink on POSIX) while carrying a distinct
            // out-of-scope-risk signal a later policy change can consult.
            // Defaults to 0 (not flagged) for every pre-existing row, same
            // "no behavior change without opt-in" guarantee as every other
            // column in this list.
            "ALTER TABLE files ADD COLUMN symlink_out_of_root INTEGER NOT NULL DEFAULT 0",
            // Per-link opt-in for attempting
            // real Win32 symlink creation on Windows (default 0 — the safe
            // skip-with-visible-status policy describes, since a
            // default assuming `SeCreateSymbolicLinkPrivilege`/Developer
            // Mode would fail unpredictably per-machine). Mirrors
            // `materialization_policy`/`chunking_policy` above: a per-link
            // column on `links`, not a per-file one, since this is a
            // device-local link-wide policy decision, not something that
            // varies symlink-by-symlink.
            "ALTER TABLE links ADD COLUMN windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0",
            // Every pre-existing link
            // defaults to `send_receive` (`LinkMode::default()`'s db
            // string) — the unchanged, original behavior every link had
            // before this column existed, matching the "no behavior change
            // without opt-in" guarantee already established for every
            // other column in this list.
            "ALTER TABLE links ADD COLUMN mode TEXT NOT NULL DEFAULT 'send_receive'",
            // Defensive: `files.version_seq`/
            // `state`/`origin_device_id` are normally already present by the
            // time this loop runs, via either a fresh `CREATE TABLE IF NOT
            // EXISTS` above or `migrate_files_table_widen_primary_key`'s own
            // rebuild — these three are listed here too only so a database
            // that somehow reaches this point without them (there is no
            // known path to that today) still ends up correct rather than
            // erroring on every later query that references these columns.
            "ALTER TABLE files ADD COLUMN version_seq INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE files ADD COLUMN state TEXT NOT NULL DEFAULT 'current'",
            "ALTER TABLE files ADD COLUMN origin_device_id TEXT",
            // A link's retention policy
            // () — two independent, optional bounds. Every
            // pre-existing and freshly-created link defaults to the sane
            // defaults (10 versions / 30 days), matching every other
            // per-link policy column's "no behavior change without opt-in"
            // migration guarantee — a link that predates this change starts
            // retaining history under the default policy from its first
            // post-upgrade edit/delete onward, rather than silently keeping
            // unlimited or zero history.
            "ALTER TABLE links ADD COLUMN retention_max_versions INTEGER NOT NULL DEFAULT 10",
            "ALTER TABLE links ADD COLUMN retention_max_age_days INTEGER NOT NULL DEFAULT 30",
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

        // Stamp the now-current
        // schema version *after* every migration above has run —
        // unconditionally, not just when it changed, so this is exactly as
        // idempotent as the migrations themselves (setting `user_version`
        // to the value it's already at is a harmless no-op restart-safety
        // net if a crash happened between the last migration statement
        // above and this pragma on a previous attempt).
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    // --- File index (task 5.3) ---

    /// Plain, origin-agnostic upsert — delegates to
    /// `upsert_file_with_origin` with an empty (unknown) origin. Kept for
    /// every existing caller (overwhelmingly test fixtures that don't care
    /// who "wrote" a record) so this signature never needed to change; see
    /// `upsert_file_with_origin`'s doc comment for the real semantics and
    /// which two production call sites use it directly instead.
    pub fn upsert_file(&self, group_id: &str, record: &FileRecord) -> Result<(), SyncError> {
        self.upsert_file_with_origin(group_id, record, "")
    }

    /// The version-retaining write path
    /// () — see the free function `upsert_file_in_tx` (this
    /// method's entire implementation) for the exact supersede/trash/
    /// promote-scaffold logic. `origin_device_id` is the local device id
    /// for a local edit, or the sending peer's device id when adopting a
    /// remote version; an empty string means "unknown" (`upsert_file`'s
    /// default), recorded as SQL `NULL` rather than the literal empty
    /// string.
    pub fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            upsert_file_in_tx(&tx, group_id, record, origin_device_id)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Upserts many records for one group inside a single SQLite
    /// transaction (batch-sync-optimizations ) — used by
    /// `LocalChangeProcessor::scan_existing_files` so a large initial scan
    /// commits once instead of once per file. Semantically identical to
    /// calling `upsert_file_with_origin` for each record in order (same
    /// `origin_device_id` for the whole batch — a scan is always this
    /// device's own local device id); a no-op (no transaction opened) for
    /// an empty batch.
    pub fn upsert_files_batch(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
    ) -> Result<(), SyncError> {
        if records.is_empty() {
            return Ok(());
        }
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            for record in records {
                upsert_file_in_tx(&tx, group_id, record, origin_device_id)?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Creates a `version_seq = 0` scaffold row
    /// for `path` if (and only if) no `current` row exists for it yet — the
    /// `apply_incoming_wire_metadata` bootstrap need (`peer_session.rs`):
    /// its four metadata setters (`set_record_kind`/`set_symlink_target`/
    /// `set_symlink_out_of_root`/`set_exec_bit`) are `UPDATE`-only and error
    /// if no row exists yet for a path this device has genuinely never seen
    /// before. `version_seq = 0` is a sentinel `upsert_file_in_tx`'s own
    /// `files_supersede_prior_current` trigger recognizes specially: the
    /// *next* real `upsert_file`/`upsert_file_with_origin` call for this
    /// path deletes this scaffold outright and starts real history at
    /// `version_seq = 1`, rather than leaving a spurious empty first
    /// version behind. A no-op if a current row already exists (an update
    /// to a previously-seen path) — the bootstrap is only ever needed for a
    /// path this device has never indexed at all.
    pub fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncError> {
        // This write, like every sibling
        // per-path metadata setter below it (`set_record_kind`,
        // `set_symlink_target`, `set_symlink_out_of_root`, `set_exec_bit`,
        // `set_held`/`clear_held`) sits directly on `reconcile_one_file`'s
        // "adopt a brand-new path from a peer" hot path, called
        // concurrently (up to `MAX_CONCURRENT_RECONCILES` at a time, times
        // however many `handle_message` tasks are in flight) against the
        // exact same shared-cache-mode connection pool
        // `upsert_file_with_origin`'s doc comment on `retry_on_database_
        // locked`/`new_immediate_write_transaction` describes -- but,
        // unlike that function, this one was never wrapped, so a burst
        // large enough to produce real concurrent writers hit an
        // unretried `SQLITE_LOCKED` here and the whole reconcile attempt
        // was dropped, indistinguishable in effect from the semaphore/
        // head-of-line-blocking stall this change's periodic resync
        // exists to recover from. Found via this change's own burst
        // reproduction (real `database table is locked: files` errors
        // observed under load, not a hypothetical) -- fixed the same way
        // `upsert_file_with_origin` already is, so a resync round's own
        // retried reconciles aren't undermined by this same gap.
        retry_on_database_locked(|| {
            self.pool.get()?.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted, version_seq, state, origin_device_id)
                 SELECT ?1, ?2, 0, 0, '{}', '[]', 0, 0, 'current', NULL
                  WHERE NOT EXISTS (SELECT 1 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current')",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    pub fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, SyncError> {
        let conn = self.pool.get()?;
        let row: Option<(u64, i64, String, String, i64)> = conn
            .query_row(
                "SELECT size, mtime_unix_nanos, version_json, blocks_json, deleted
                 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .ok();
        Ok(row.map(|(size, mtime, version_json, blocks_json, deleted)| {
            row_to_record(path.to_string(), size, mtime, &version_json, &blocks_json, deleted)
        }))
    }

    pub fn remove_file(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let affected = self.pool.get()?.execute(
            "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(affected > 0)
    }

    /// Bulk-loads every non-deleted file's materialization state for
    /// `group_id` (batch-sync-optimizations ) — used by
    /// `LocalChangeProcessor::scan_existing_files` so deciding whether an
    /// on-disk entry is a placeholder (which must never be chunked) costs
    /// one query for the whole scan instead of one per file.
    pub fn list_materialization_states(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashMap<String, MaterializationState>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path, materialization_state FROM files \
             WHERE group_id = ?1 AND deleted = 0 AND state = 'current'",
        )?;
        let rows =
            stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            let (path, state) = row?;
            out.insert(path, MaterializationState::from_db_str(&state));
        }
        Ok(out)
    }

    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path, size, mtime_unix_nanos, version_json, blocks_json, deleted FROM files \
             WHERE group_id = ?1 AND state = 'current'",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (path, size, mtime, version_json, blocks_json, deleted) = row?;
            out.push(row_to_record(path, size, mtime, &version_json, &blocks_json, deleted));
        }
        Ok(out)
    }

    /// Bulk-loads every local
    /// `FileRecord` (including tombstones — deleted rows are not filtered
    /// here, matching `get_file`'s own behavior) whose `path` is in
    /// `paths`, for `group_id`, keyed by path — the batched counterpart to
    /// calling `get_file` once per path. Mirrors the existing bulk-load
    /// pattern `LocalChangeProcessor::scan_existing_files` already uses via
    /// `list_files` — collecting the batch of incoming paths/hashes and
    /// issuing set-based queries, then diffing in memory — but scoped to
    /// exactly the requested paths via `WHERE path IN (...)`
    /// rather than loading the whole group — the right shape for
    /// `reconcile_files`, where an incoming `IndexUpdate` is often a
    /// handful of changed files out of a much larger indexed group, not
    /// the whole group's file list.
    ///
    /// Chunks the `IN (...)` query at `GET_FILES_BY_PATHS_CHUNK_SIZE`
    /// paths per round trip (SQLite's compiled bound-parameter limit is a
    /// real, if generous, ceiling — chunking avoids ever depending on it
    /// being large enough for an arbitrarily big `paths`). A no-op query
    /// for an empty `paths`. A path with no matching row is simply absent
    /// from the returned map, exactly as `get_file` returning `None` for a
    /// path with no row.
    pub fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, SyncError> {
        const GET_FILES_BY_PATHS_CHUNK_SIZE: usize = 500;
        let mut out = HashMap::with_capacity(paths.len());
        if paths.is_empty() {
            return Ok(out);
        }
        let conn = self.pool.get()?;
        for chunk in paths.chunks(GET_FILES_BY_PATHS_CHUNK_SIZE) {
            let placeholders = std::iter::repeat_n("?", chunk.len()).collect::<Vec<_>>().join(",");
            let sql = format!(
                "SELECT path, size, mtime_unix_nanos, version_json, blocks_json, deleted \
                 FROM files WHERE group_id = ? AND state = 'current' AND path IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            let params = std::iter::once(&group_id as &dyn rusqlite::ToSql)
                .chain(chunk.iter().map(|p| p as &dyn rusqlite::ToSql));
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get(5)?,
                ))
            })?;
            for row in rows {
                let (path, size, mtime, version_json, blocks_json, deleted) = row?;
                let record =
                    row_to_record(path.clone(), size, mtime, &version_json, &blocks_json, deleted);
                out.insert(path, record);
            }
        }
        Ok(out)
    }

    pub fn live_block_hashes(&self) -> Result<HashSet<ContentHash>, SyncError> {
        self.live_block_hashes_with_extra_roots(std::iter::empty())
    }

    /// Computes the GC live set from one SQLite snapshot and appends
    /// caller-provided roots. The extra-root hook is intentionally generic
    /// so a future version-history/trash table can contribute retained
    /// blocks without changing `live_block_hashes` again.
    ///
    /// This query is
    /// deliberately **not** filtered by `state` — every row with
    /// `deleted = 0` contributes its blocks regardless of whether it is
    /// `current`, `superseded`, or `trashed`, which is exactly the live-root
    /// contract a future block-store GC must honor (a block referenced by
    /// any retained version, not only the current one, is live). A
    /// `deleted = 1` row's own `blocks_json` is always `[]` (see
    /// `upsert_file_in_tx`/`mark_deleted`), so excluding it changes nothing
    /// — the *prior* live content a delete superseded is retained under
    /// `state = 'trashed'` with `deleted = 0`, and is therefore still
    /// scanned here. No code changes to `BlockStore` itself are required by
    /// this change (`delete` is still never called); this comment and
    /// `live_block_hashes_include_superseded_and_trashed_blocks` below are
    /// the load-bearing documentation of that contract for a future
    /// block-store GC implementation.
    pub fn live_block_hashes_with_extra_roots(
        &self,
        extra_roots: impl IntoIterator<Item = ContentHash>,
    ) -> Result<HashSet<ContentHash>, SyncError> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        let mut live: HashSet<ContentHash> = extra_roots.into_iter().collect();
        {
            let mut stmt = tx.prepare("SELECT blocks_json FROM files WHERE deleted = 0")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            for row in rows {
                let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
                live.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
            }
        }
        tx.commit()?;
        Ok(live)
    }

    /// Marks a file deleted (tombstone), preserving its version vector
    /// lineage so the deletion itself propagates as a normal index update.
    /// Stamps the tombstone's `mtime_unix_nanos` with "now" — the right
    /// choice for every caller of this method (a full-rescan recovery, a
    /// direct test, `hydration.rs`'s bookkeeping): none of them have an
    /// earlier, more accurate observation of when the deletion actually
    /// happened to prefer instead. `mark_deleted_at` is the one exception
    /// (see its own doc comment).
    pub fn mark_deleted(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
    ) -> Result<(), SyncError> {
        self.mark_deleted_at(group_id, path, device_id, now_unix_nanos())
    }

    /// Like `mark_deleted`, but stamps the tombstone with a caller-supplied
    /// observed time instead of "now".
    ///
    /// `local_change.rs`'s
    /// debounced dispatch of a `Removed` event is the one caller that
    /// needs this — a local deletion can sit in the debounce accumulator
    /// for up to `DebounceConfig::quiet_period` (default 300ms) before
    /// `mark_deleted` actually runs, so stamping "now" *at dispatch time*
    /// would record a tombstone time systematically *later* than the
    /// deletion's true, watcher-observed moment — unlike a concurrent
    /// edit's `mtime_unix_nanos`, which is always the file's own real
    /// content-modification time (`std::fs::metadata`), never delayed by
    /// debounce. That asymmetry alone can invert the correct chronological
    /// order between a genuinely-earlier delete and a genuinely-later
    /// edit once `conflict.rs` compares them — confirmed via
    /// `concurrent_edit_delete_edit_wins_when_later_leaves_no_conflict_artifact`
    /// regressing under a naive "now at dispatch time" stamp. Passing the
    /// debounce accumulator's own per-path last-observed timestamp here
    /// (`debounce::DebounceFlush::Paths`'s third tuple element) closes
    /// that gap.
    pub fn mark_deleted_at(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
    ) -> Result<(), SyncError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        // Stamp the tombstone
        // with the deletion's own observed time, not the mtime carried
        // forward from the file's last live content (the field above is
        // only overwritten here, nowhere else in this function) — a stale
        // content mtime gives `conflict.rs`'s `a_is_loser`/
        // `resolve_conflict_names` no correct chronological signal to
        // order a concurrent edit against this delete once the race that
        // used to mask the conflict path entirely is fixed (see
        // `peer_session::PeerSyncSession::reconcile_one_file`).
        record.mtime_unix_nanos = observed_at_unix_nanos;
        record.version.increment(device_id);
        // `device_id` is a known origin
        // (this device, for a local delete) — routes through
        // `upsert_file_with_origin` so the tombstone row itself records it,
        // and so the row it supersedes (the file's last live content, if
        // any) is retained as `state = 'trashed'` rather than discarded —
        // see `upsert_file_in_tx`'s doc comment for the exact rule.
        self.upsert_file_with_origin(group_id, &record, device_id)
    }

    // --- Materialization (on-demand-sync D3, D6) ---

    pub fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, SyncError> {
        let conn = self.pool.get()?;
        let state: Option<String> = conn
            .query_row(
                "SELECT materialization_state FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(state.as_deref().map(MaterializationState::from_db_str))
    }

    pub fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE files SET materialization_state = ?1 \
             WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
            rusqlite::params![state.as_db_str(), group_id, path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// COR-7: `Hydrating` is set right before a block fetch begins
    /// (`peer_session.rs`/`hydration.rs`) and only ever reset back on that
    /// same call's own failure paths — if the process is killed in
    /// between (crash, force-quit, power loss), the row stays
    /// `Hydrating` forever. A stuck `Hydrating` file is excluded from
    /// eviction *and* `build_record_for_created_or_modified` refuses to
    /// chunk it, so a real local edit to that path is silently ignored
    /// until something happens to re-hydrate it — which nothing will,
    /// since nothing believes it's still a placeholder. Called once at
    /// daemon startup (never mid-run, since a live daemon's own
    /// `Hydrating` rows are legitimately in progress) to reset every
    /// stale `Hydrating` row, across every group, back to `Placeholder`
    /// — safe because `Placeholder` just means "not fetched yet," and a
    /// startup is definitionally after any hydration that was running
    /// crashed with it.
    pub fn reset_stale_hydrating_to_placeholder(&self) -> Result<usize, SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE files SET materialization_state = ?1 \
             WHERE materialization_state = ?2 AND state = 'current'",
            rusqlite::params![
                MaterializationState::Placeholder.as_db_str(),
                MaterializationState::Hydrating.as_db_str()
            ],
        )?;
        Ok(affected)
    }

    pub fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let pinned: Option<i64> = conn
            .query_row(
                "SELECT pinned FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(pinned.unwrap_or(0) != 0)
    }

    pub fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE files SET pinned = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
            rusqlite::params![pinned as i64, group_id, path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Records `unix_ts` as this file's last-accessed time ():
    /// called on hydration completion, and best-effort from the eviction
    /// sweep's `fs::metadata().accessed()` fallback for already-hydrated
    /// files.
    pub fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE files SET last_accessed_unix = ?1 \
             WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
            rusqlite::params![unix_ts, group_id, path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    // --- Sync fidelity ---
    //
    // Like `materialization_state`/`pinned` above, these are index-local
    // per-file columns surfaced through dedicated getters/setters rather
    // than as `FileRecord` fields — see `RecordKind`'s doc comment in
    // `types.rs` for why. `upsert_file`'s `INSERT`/`ON CONFLICT` column
    // list deliberately doesn't mention any of them, so (matching
    // `materialization_state`'s existing behavior) a fresh row picks up
    // the column's `DEFAULT` and re-upserting an existing row never resets
    // whatever one of these setters previously recorded for it.

    /// The kind of on-disk entry this record represents (). `None`
    /// if no row exists for `group_id`/`path` at all — distinct from `Some
    /// (RecordKind::File)`, which is a real row that just hasn't been
    /// classified as anything else.
    pub fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, SyncError> {
        let conn = self.pool.get()?;
        let kind: Option<String> = conn
            .query_row(
                "SELECT record_kind FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(kind.as_deref().map(RecordKind::from_db_str))
    }

    // `retry_on_database_locked`-wrapped
    // for the same reason as `ensure_bootstrap_row_for_metadata` just
    // above -- see its doc comment for the full diagnostic story.
    pub fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let affected = self.pool.get()?.execute(
                "UPDATE files SET record_kind = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![kind.as_db_str(), group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The raw, unresolved symlink target text () — only
    /// meaningful when `get_record_kind` returns `Symlink`; `None`
    /// otherwise (either no row, or a row that isn't a symlink).
    pub fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncError> {
        let conn = self.pool.get()?;
        let target: Option<Option<String>> = conn
            .query_row(
                "SELECT symlink_target FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(target.flatten())
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&str>,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let affected = self.pool.get()?.execute(
                "UPDATE files SET symlink_target = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![target, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// `true` when this symlink's raw target is an absolute
    /// path, or resolves (syntactically — see
    /// `local_change::symlink_target_is_out_of_root`, never by
    /// dereferencing) outside the linked folder's root. Only meaningful
    /// when `get_record_kind` returns `Symlink`; defaults to `false`
    /// otherwise, matching `get_exec_bit`'s default-to-`false` shape for
    /// an unknown/never-set row. Deliberately a distinct column from
    /// `held_reason`/`held_since_unix_nanos` — see the migration comment
    /// in `init` for why this flag doesn't gate materialization the way
    /// held state does.
    pub fn get_symlink_out_of_root(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let flag: Option<i64> = conn
            .query_row(
                "SELECT symlink_out_of_root FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(flag.unwrap_or(0) != 0)
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let affected = self.pool.get()?.execute(
                "UPDATE files SET symlink_out_of_root = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![out_of_root as i64, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// The owner-executable bit (). Defaults to `false` for any
    /// row — including every pre-existing one from before this column
    /// existed — matching `is_pinned`'s existing default-to-`false` shape
    /// for an unknown/never-set row.
    pub fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let exec_bit: Option<i64> = conn
            .query_row(
                "SELECT exec_bit FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok();
        Ok(exec_bit.unwrap_or(0) != 0)
    }

    /// The device id that
    /// actually produced this path's *current* content, as already
    /// recorded by every `upsert_file_with_origin` call (the
    /// `origin_device_id` column has existed since file-version-history
    /// support was added, previously write-only from this query's point of
    /// view — used for version-history attribution, never read back
    /// during conflict resolution). `None` for a row with no recorded
    /// origin (an empty string is stored as SQL `NULL`, per
    /// `upsert_file_in_tx`'s existing convention) — callers fall back to
    /// their own best guess (typically `self.local_device_id`/
    /// `self.peer_device_id`) in that case, matching the pre-this-fix
    /// behavior for a record that predates this column being consulted.
    pub fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncError> {
        let conn = self.pool.get()?;
        let origin: Option<String> = conn
            .query_row(
                "SELECT origin_device_id FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get(0),
            )
            .ok()
            .flatten();
        Ok(origin)
    }

    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let affected = self.pool.get()?.execute(
                "UPDATE files SET exec_bit = ?1 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![exec_bit as i64, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// A held file's reason and hold timestamp (), so both
    /// survive a daemon restart. `None` if the row isn't currently held
    /// (either no row, or a row with no `held_reason` recorded) — the two
    /// columns are only ever written/cleared together (`set_held`/
    /// `clear_held`), so they can't independently be half-set.
    pub fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, SyncError> {
        let conn = self.pool.get()?;
        let row: Option<(Option<String>, Option<i64>)> = conn
            .query_row(
                "SELECT held_reason, held_since_unix_nanos FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        Ok(row.and_then(|(reason, since_unix_nanos)| match (reason, since_unix_nanos) {
            (Some(reason), Some(since_unix_nanos)) => Some(HeldState { reason, since_unix_nanos }),
            _ => None,
        }))
    }

    /// Marks a file held with `reason` (e.g. `"case_collision"`,
    /// `"invalid_name"` — a free-form reason string, not a closed enum, so
    /// the hazard-detection logic that actually decides these reasons
    /// isn't constrained by this schema-only task) as of `since_unix_nanos`.
    /// Held state is purely local — a held file's index row keeps
    /// participating in normal index exchange with peers (); this
    /// column is never sent over the wire.
    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let affected = self.pool.get()?.execute(
                "UPDATE files SET held_reason = ?1, held_since_unix_nanos = ?2 \
                 WHERE group_id = ?3 AND path = ?4 AND state = 'current'",
                rusqlite::params![reason, since_unix_nanos, group_id, path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
            }
            Ok(())
        })
    }

    /// Clears a file's held state (: "a held file that is later
    /// tombstoned clears its held state rather than leaving an orphaned
    /// held entry"). A no-op, not an error, if the file wasn't held (or
    /// the row doesn't exist) — callers tombstoning a record don't first
    /// need to check whether it was ever held.
    // Retry-wrapped, same reason as
    // `ensure_bootstrap_row_for_metadata`.
    pub fn clear_held(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            self.pool.get()?.execute(
                "UPDATE files SET held_reason = NULL, held_since_unix_nanos = NULL \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
            )?;
            Ok(())
        })
    }

    /// Hydrated, unpinned, non-deleted files for `group_id`, ordered
    /// least-recently-accessed first (files never accessed sort before
    /// any that have been, per `NULLS FIRST`) — the automatic eviction
    /// sweep's (D6) candidate list, in eviction order.
    pub fn list_evictable_files(&self, group_id: &str) -> Result<Vec<EvictableFile>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path, size, last_accessed_unix FROM files
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0 AND pinned = 0
                AND materialization_state = 'hydrated'
             ORDER BY last_accessed_unix ASC NULLS FIRST",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok(EvictableFile { path: r.get(0)?, size: r.get(1)?, last_accessed_unix: r.get(2)? })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Total on-disk size of every hydrated, non-deleted file in
    /// `group_id`, pinned or not (COR-10). `list_evictable_files` above
    /// deliberately excludes pinned files since they're never eviction
    /// *candidates* — but a pinned-and-hydrated file still occupies real
    /// disk space, so summing only `list_evictable_files`' sizes to
    /// gauge current usage against a folder's disk-usage cap
    /// systematically undercounts it, letting the sweep stop early and
    /// leave usage above the configured cap. Use this for the usage
    /// figure; keep using `list_evictable_files` for which files may
    /// actually be evicted.
    pub fn hydrated_usage_bytes(&self, group_id: &str) -> Result<u64, SyncError> {
        let conn = self.pool.get()?;
        let total: Option<i64> = conn.query_row(
            "SELECT SUM(size) FROM files
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0
                AND materialization_state = 'hydrated'",
            [group_id],
            |r| r.get(0),
        )?;
        Ok(total.unwrap_or(0).max(0) as u64)
    }

    /// Counts of non-deleted files in `group_id` by materialization state
    /// — `yadorilink status`'s per-folder summary (task 5.4), avoiding
    /// dumping every individual file path for what's meant to be a
    /// glance-able overview (matching how `conflict_count` already
    /// summarizes rather than lists).
    pub fn materialization_counts(
        &self,
        group_id: &str,
    ) -> Result<MaterializationCounts, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT materialization_state, COUNT(*) FROM files
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0
             GROUP BY materialization_state",
        )?;
        let rows = stmt
            .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?;
        let mut counts = MaterializationCounts::default();
        for row in rows {
            let (state, count) = row?;
            match MaterializationState::from_db_str(&state) {
                MaterializationState::Hydrated => counts.hydrated = count,
                MaterializationState::Placeholder => counts.placeholder = count,
                MaterializationState::Hydrating => counts.hydrating = count,
            }
        }
        Ok(counts)
    }

    /// A folder group's materialization policy (), by `group_id`
    /// rather than `local_path` — the lookup `PeerSyncSession::materialize`
    /// needs, since it only knows the folder group, not the local path a
    /// caller linked it under. `None` if no link is registered for this
    /// group at all (shouldn't normally happen for a group actively being
    /// synced, but isn't treated as an error here).
    pub fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, SyncError> {
        let conn = self.pool.get()?;
        let policy: Option<String> = conn
            .query_row(
                "SELECT materialization_policy FROM links WHERE group_id = ?1",
                [group_id],
                |r| r.get(0),
            )
            .ok();
        Ok(policy.as_deref().map(MaterializationPolicy::from_db_str))
    }

    /// A folder group's chunking policy (content-defined-chunking design
    /// D3), by `group_id` — the lookup `LocalChangeProcessor` needs, since
    /// it only knows the folder group being chunked for, not the local
    /// path a caller linked it under. `None` if no link is registered for
    /// this group (treated as `Fixed` by callers, matching the DB default).
    pub fn chunking_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<ChunkingPolicy>, SyncError> {
        let conn = self.pool.get()?;
        let policy: Option<String> = conn
            .query_row("SELECT chunking_policy FROM links WHERE group_id = ?1", [group_id], |r| {
                r.get(0)
            })
            .ok();
        Ok(policy.as_deref().map(ChunkingPolicy::from_db_str))
    }

    // --- Folder links (task 5.1, 6.8) ---

    pub fn add_link(&self, local_path: &str, group_id: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR REPLACE INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
            rusqlite::params![local_path, group_id],
        )?;
        Ok(())
    }

    pub fn remove_link(&self, local_path: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
        Ok(())
    }

    pub fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, max_local_size_bytes, \
             chunking_policy, mode, retention_max_versions, retention_max_age_days FROM links",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(FolderLink {
                local_path: r.get(0)?,
                group_id: r.get(1)?,
                paused: r.get::<_, i64>(2)? != 0,
                materialization_policy: MaterializationPolicy::from_db_str(&r.get::<_, String>(3)?),
                max_local_size_bytes: r.get(4)?,
                chunking_policy: ChunkingPolicy::from_db_str(&r.get::<_, String>(5)?),
                mode: LinkMode::from_db_str(&r.get::<_, String>(6)?),
                retention_policy: RetentionPolicy {
                    max_versions: r.get(7)?,
                    max_age_days: r.get(8)?,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // --- Version history & trash ---

    /// : a link's retention policy, by `group_id` — mirrors
    /// `link_mode_for_group`/`chunking_policy_for_group`'s by-`group_id`
    /// lookup shape, since the retention-expiry sweep and the restore/
    /// listing IPC handlers only know the folder group, not the local path
    /// a caller linked it under. `None` if no link is registered for this
    /// group at all; callers treat that the same way `chunking_policy_for_
    /// group`'s `None` is already treated — as the type's own default
    /// (`RetentionPolicy::default()`, matching the columns' `DEFAULT`s).
    pub fn retention_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<RetentionPolicy>, SyncError> {
        let conn = self.pool.get()?;
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT retention_max_versions, retention_max_age_days FROM links \
                 WHERE group_id = ?1",
                [group_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        Ok(row.map(|(max_versions, max_age_days)| RetentionPolicy { max_versions, max_age_days }))
    }

    /// : sets a folder link's retention policy — `yadorilink link
    /// --keep-versions <n> --keep-days <t>` at link time, or `yadorilink
    /// link retention <path> --keep-versions <n> --keep-days <t>`
    /// afterward. Either bound may be `0` (unlimited on that axis, per
    /// — "documented as a storage-growth footgun, not blocked
    /// outright"). Mirrors `set_materialization_policy`/`set_link_mode`'s
    /// by-`local_path` shape.
    pub fn set_retention_policy(
        &self,
        local_path: &str,
        policy: RetentionPolicy,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET retention_max_versions = ?1, retention_max_age_days = ?2 \
             WHERE local_path = ?3",
            rusqlite::params![policy.max_versions, policy.max_age_days, local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// spec "Version Listing": every retained version of `path` (current,
    /// superseded, and trashed alike), newest first. Includes the current
    /// version, per spec's "including the current version" scenario.
    pub fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<VersionRecord>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT version_seq, size, mtime_unix_nanos, blocks_json, deleted, state, origin_device_id \
             FROM files WHERE group_id = ?1 AND path = ?2 ORDER BY version_seq DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![group_id, path], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (version_seq, size, mtime, blocks_json, deleted, state, origin_device_id) = row?;
            out.push(version_record(
                path.to_string(),
                version_seq,
                size,
                mtime,
                &blocks_json,
                deleted,
                &state,
                origin_device_id,
            ));
        }
        Ok(out)
    }

    /// A single retained version by its exact `version_seq` — the restore
    /// engine's lookup (task 3.1) for `yadorilink restore <path> --version
    /// <id>`. `None` if no row exists at all for this exact
    /// `(group_id, path, version_seq)`.
    pub fn get_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<VersionRecord>, SyncError> {
        let conn = self.pool.get()?;
        let row: Option<(u64, i64, String, i64, String, Option<String>)> = conn
            .query_row(
                "SELECT size, mtime_unix_nanos, blocks_json, deleted, state, origin_device_id \
                 FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                rusqlite::params![group_id, path, version_seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .ok();
        Ok(row.map(|(size, mtime, blocks_json, deleted, state, origin_device_id)| {
            version_record(
                path.to_string(),
                version_seq,
                size,
                mtime,
                &blocks_json,
                deleted,
                &state,
                origin_device_id,
            )
        }))
    }

    /// spec "Deletion Enters Recoverable Trash" / CLI "trash list": every
    /// path currently in the trashed state for `group_id` — i.e. a path
    /// whose `current` row is itself a tombstone (`deleted = 1`) and that
    /// has at least one retained `state = 'trashed'` row (the last live
    /// content before that deletion). Returns the *most recent* trashed
    /// row per path (its highest `version_seq`) alongside the tombstone's
    /// own `mtime_unix_nanos` as the deletion time — the pair `trash
    /// restore` needs (last-known size/content, and when it was deleted).
    /// A path deleted, restored, and deleted again correctly surfaces only
    /// its latest trashed version, not every historical one (`list_versions`
    /// is the place for full history).
    pub fn list_trashed(&self, group_id: &str) -> Result<Vec<TrashedFile>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT t.path, t.version_seq, t.size, t.mtime_unix_nanos, t.origin_device_id, \
                    c.mtime_unix_nanos
             FROM files t
             JOIN (
                 SELECT path, MAX(version_seq) AS max_seq FROM files
                 WHERE group_id = ?1 AND state = 'trashed' GROUP BY path
             ) latest ON latest.path = t.path AND latest.max_seq = t.version_seq
             JOIN files c ON c.group_id = ?1 AND c.path = t.path AND c.state = 'current'
             WHERE t.group_id = ?1 AND t.state = 'trashed' AND c.deleted = 1
             ORDER BY c.mtime_unix_nanos DESC",
        )?;
        let rows = stmt.query_map([group_id], |r| {
            Ok(TrashedFile {
                path: r.get(0)?,
                version_seq: r.get(1)?,
                last_known_size: r.get::<_, u64>(2)?,
                origin_device_id: r.get(4)?,
                deleted_at_unix_nanos: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Sets a folder group's default materialization policy for
    /// newly-adopted files () — `yadorilink link --on-demand` or
    /// its Eager-default counterpart.
    pub fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET materialization_policy = ?1 WHERE local_path = ?2",
            rusqlite::params![policy.as_db_str(), local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Sets a folder link's chunking policy (content-defined-chunking
    /// ) — `yadorilink link --content-defined-chunking` or its
    /// Fixed-default counterpart. Device-local; see for why
    /// this doesn't need cross-device agreement.
    pub fn set_chunking_policy(
        &self,
        local_path: &str,
        policy: ChunkingPolicy,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET chunking_policy = ?1 WHERE local_path = ?2",
            rusqlite::params![policy.as_db_str(), local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Whether `group_id`'s link has opted in
    /// to attempting real Win32 symlink creation on Windows, rather than
    /// the default skip-with-visible-status policy (). Mirrors
    /// `materialization_policy_for_group`'s by-`group_id` lookup shape —
    /// `PeerSyncSession::materialize` only knows the folder group, not the
    /// local path a caller linked it under. `false` (not an error) if no
    /// link is registered for this group at all, matching the "default
    /// policy" this column's own `DEFAULT 0` already implies.
    pub fn windows_symlink_opt_in_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let opt_in: Option<i64> = conn
            .query_row(
                "SELECT windows_symlink_opt_in FROM links WHERE group_id = ?1",
                [group_id],
                |r| r.get(0),
            )
            .ok();
        Ok(opt_in.unwrap_or(0) != 0)
    }

    /// Sets a folder link's per-link opt-in for attempting real Windows
    /// symlink materialization (task 3.2) — mirrors
    /// `set_materialization_policy`'s by-`local_path` shape (every other
    /// per-link setting here is addressed by local path, the same surface
    /// a future CLI flag, section 6, would use). Device-local, like every
    /// other policy column on `links`.
    pub fn set_windows_symlink_opt_in(
        &self,
        local_path: &str,
        opt_in: bool,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET windows_symlink_opt_in = ?1 WHERE local_path = ?2",
            rusqlite::params![opt_in as i64, local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Sets (or clears, with `None`) an `OnDemand` folder's automatic
    /// eviction disk-usage cap () — unset means no automatic
    /// eviction, matching the existing manual-only default.
    pub fn set_max_local_size_bytes(
        &self,
        local_path: &str,
        max_bytes: Option<i64>,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET max_local_size_bytes = ?1 WHERE local_path = ?2",
            rusqlite::params![max_bytes, local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    pub fn set_paused(&self, local_path: &str, paused: bool) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET paused = ?1 WHERE local_path = ?2",
            rusqlite::params![paused as i64, local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    // --- Folder direction modes ---

    /// Sets a folder link's directional propagation mode (per this
    /// crate's propagation-gating rules) — `yadorilink link --mode <mode>` or
    /// `yadorilink link set-mode <path> <mode>`. Mirrors
    /// `set_materialization_policy`/`set_chunking_policy`'s by-`local_path`
    /// shape: every other per-link policy setter here is addressed by
    /// local path, the CLI's own addressing scheme.
    pub fn set_link_mode(&self, local_path: &str, mode: LinkMode) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET mode = ?1 WHERE local_path = ?2",
            rusqlite::params![mode.as_db_str(), local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Whether `group_id`'s link is currently
    /// paused, by `group_id` — the lookup `PeerSyncSession::reconcile_
    /// files_if_authorized` needs (pause still stops both directions
    /// regardless of mode, trumping everything — a gate this crate never
    /// previously enforced on the
    /// *incoming*-apply path; only the daemon's local→peer broadcast
    /// checked `paused` before this change). Mirrors `link_mode_for_
    /// group`'s by-`group_id` shape. `false` (not an error) if no link is
    /// registered for this group at all — an unregistered/already-removed
    /// group was never "paused" in any meaningful sense.
    pub fn is_paused_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let paused: Option<i64> = conn
            .query_row("SELECT paused FROM links WHERE group_id = ?1", [group_id], |r| r.get(0))
            .ok();
        Ok(paused.unwrap_or(0) != 0)
    }

    /// A folder link's directional mode, by `group_id` — the lookup
    /// `PeerSyncSession::reconcile_files` needs, since it only knows the
    /// folder group being reconciled, not the local path a caller linked it
    /// under. Mirrors `materialization_policy_for_group`/
    /// `chunking_policy_for_group`'s by-`group_id` shape exactly. `None` if
    /// no link is registered for this group at all; callers treat that the
    /// same way they already treat `chunking_policy_for_group`'s `None` —
    /// as the type's own default (`LinkMode::SendReceive`, matching the
    /// column's `DEFAULT`).
    pub fn link_mode_for_group(&self, group_id: &str) -> Result<Option<LinkMode>, SyncError> {
        let conn = self.pool.get()?;
        let mode: Option<String> = conn
            .query_row("SELECT mode FROM links WHERE group_id = ?1", [group_id], |r| r.get(0))
            .ok();
        Ok(mode.as_deref().map(LinkMode::from_db_str))
    }

    // --- Divergence tracking ---
    //
    // The invariant (no data loss during divergence tracking) is
    // that gating a direction never silently discards state: a send-only
    // link records an out-of-sync item instead of applying a differing
    // incoming change; a receive-only link records a receive-only-changed
    // item instead of sending a local modification. Both sets are cleared
    // only by an explicit `override`/`revert` action (task 3), never
    // automatically. `INSERT OR REPLACE` on `(group_id, path)` — a path
    // already recorded just gets a fresher timestamp, not a second row;
    // there is exactly one outstanding divergence entry per path, not a
    // history of every gated event.

    pub fn record_out_of_sync(
        &self,
        group_id: &str,
        path: &str,
        recorded_at_unix_nanos: i64,
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR REPLACE INTO out_of_sync_items (group_id, path, recorded_at_unix_nanos) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![group_id, path, recorded_at_unix_nanos],
        )?;
        Ok(())
    }

    /// Clears one path's out-of-sync entry (`override`, task 3.1). A no-op,
    /// not an error, if the path wasn't recorded — mirrors `clear_held`'s
    /// same "callers don't need to check first" contract.
    pub fn clear_out_of_sync(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "DELETE FROM out_of_sync_items WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Every currently out-of-sync path for `group_id`, in recorded order —
    /// `override`'s worklist (task 3.1: "re-assert local records for
    /// out-of-sync paths").
    pub fn list_out_of_sync(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path FROM out_of_sync_items WHERE group_id = ?1 ORDER BY recorded_at_unix_nanos",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `yadorilink status`/`link list`'s out-of-sync count (task 4.3).
    pub fn count_out_of_sync(&self, group_id: &str) -> Result<u64, SyncError> {
        let conn = self.pool.get()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM out_of_sync_items WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        Ok(count as u64)
    }

    pub fn record_receive_only_changed(
        &self,
        group_id: &str,
        path: &str,
        recorded_at_unix_nanos: i64,
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR REPLACE INTO receive_only_changed_items (group_id, path, recorded_at_unix_nanos) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![group_id, path, recorded_at_unix_nanos],
        )?;
        Ok(())
    }

    /// Clears one path's receive-only-changed entry (`revert`, task 3.2).
    /// A no-op, not an error, if the path wasn't recorded.
    pub fn clear_receive_only_changed(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "DELETE FROM receive_only_changed_items WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Every currently receive-only-changed path for `group_id`, in
    /// recorded order — `revert`'s worklist (task 3.2).
    pub fn list_receive_only_changed(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path FROM receive_only_changed_items WHERE group_id = ?1 \
             ORDER BY recorded_at_unix_nanos",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `yadorilink status`/`link list`'s receive-only-changed count (task 4.3).
    pub fn count_receive_only_changed(&self, group_id: &str) -> Result<u64, SyncError> {
        let conn = self.pool.get()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM receive_only_changed_items WHERE group_id = ?1",
            [group_id],
            |r| r.get(0),
        )?;
        Ok(count as u64)
    }

    // --- Version history retention expiry ---

    /// The retention-expiry sweep — deletes the index row (never the
    /// blocks; leaves actual block reclamation to a future
    /// block-store GC) for any `superseded`/`trashed` version of
    /// `group_id` that exceeds *both* `policy.max_versions` (by recency
    /// rank among that path's own superseded/trashed rows) and
    /// `policy.max_age_days` (by wall-clock age from `now_unix_nanos`) —
    /// see `RetentionPolicy`'s doc comment for the union-retain/
    /// intersection-expire rule this implements. The `current` row for any
    /// path is never a candidate — the `WHERE state IN ('superseded',
    /// 'trashed')` below structurally excludes it, matching 's
    /// "the current (live) version ... is never subject to this policy".
    /// Returns the number of rows deleted.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        policy: RetentionPolicy,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncError> {
        const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
        let age_cutoff_unix_nanos =
            now_unix_nanos.saturating_sub(policy.max_age_days.saturating_mul(NANOS_PER_DAY));

        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        let candidates: Vec<(String, i64)> = {
            // `rnk = 1` is the most recently superseded/trashed row for a
            // given path; `policy.max_versions` rows survive on the count
            // axis alone. A `0` bound on either axis structurally can never
            // satisfy its own `!= 0` guard, so that axis never contributes
            // to expiry — exactly "unlimited on that axis" ().
            let mut stmt = tx.prepare(
                "SELECT path, version_seq FROM (
                    SELECT path, version_seq, mtime_unix_nanos,
                           ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_seq DESC) AS rnk
                    FROM files WHERE group_id = ?1 AND state IN ('superseded', 'trashed')
                 )
                 WHERE (?2 != 0 AND rnk > ?2) AND (?3 != 0 AND mtime_unix_nanos < ?4)",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![
                    group_id,
                    policy.max_versions,
                    policy.max_age_days,
                    age_cutoff_unix_nanos
                ],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )?;
            rows.collect::<Result<_, _>>()?
        };
        for (path, version_seq) in &candidates {
            tx.execute(
                "DELETE FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                rusqlite::params![group_id, path, version_seq],
            )?;
        }
        tx.commit()?;
        Ok(candidates.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderLink {
    pub local_path: String,
    pub group_id: String,
    pub paused: bool,
    pub materialization_policy: MaterializationPolicy,
    /// Automatic-eviction disk-usage cap in bytes, if configured ().
    pub max_local_size_bytes: Option<i64>,
    /// content-defined-chunking .
    pub chunking_policy: ChunkingPolicy,
    /// This link's directional
    /// propagation mode.
    pub mode: LinkMode,
    /// This link's version-retention
    /// policy.
    pub retention_policy: RetentionPolicy,
}

/// A link's retention policy — two
/// independent, optional bounds on how long a *superseded* or *trashed*
/// version is kept (the current/live version is never subject to this
/// policy). A version is retained as long as it is within *either* bound,
/// and only becomes eligible for expiry once it exceeds *both* (union-
/// retain, intersection-expire — see for the rationale). `0`
/// means unlimited on that axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Maximum number of superseded/trashed versions to keep per file. `0`
    /// = no count-based limit.
    pub max_versions: i64,
    /// Maximum age, in days, of a superseded/trashed version. `0` = no
    /// age-based limit.
    pub max_age_days: i64,
}

impl Default for RetentionPolicy {
    /// 's defaults: 10 versions / 30 days.
    fn default() -> Self {
        RetentionPolicy { max_versions: 10, max_age_days: 30 }
    }
}

/// : which of the three states a `files` row is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionState {
    /// The live version of the file at this path right now (or, if the
    /// file is deleted, the tombstone itself).
    Current,
    /// A version this file had before a later edit (local or adopted)
    /// superseded it.
    Superseded,
    /// The file's last live content before it was deleted — recoverable
    /// via `trash restore` until retention expires.
    Trashed,
}

impl VersionState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            VersionState::Current => "current",
            VersionState::Superseded => "superseded",
            VersionState::Trashed => "trashed",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "superseded" => VersionState::Superseded,
            "trashed" => VersionState::Trashed,
            _ => VersionState::Current,
        }
    }
}

/// One retained version of a file, as returned by `SyncState::list_versions`/
/// `SyncState::get_version` — the CLI's `yadorilink versions <path>` and the
/// restore engine's per-version lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionRecord {
    pub path: String,
    pub version_seq: i64,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
    pub state: VersionState,
    /// The device that produced this version: this device's own id for a
    /// local edit, or the sending peer's device id when adopted from a
    /// remote change (). `None` for versions written before this
    /// change existed, or by a caller using the origin-agnostic
    /// `upsert_file` (design's honest "unknown origin" case).
    pub origin_device_id: Option<String>,
}

/// spec "CLI Trash Commands": one deleted-but-still-recoverable file, as
/// returned by `SyncState::list_trashed`.
#[derive(Debug, Clone, PartialEq)]
pub struct TrashedFile {
    pub path: String,
    /// The `version_seq` of the retained last-live-content row — what
    /// `trash restore` restores to by default.
    pub version_seq: i64,
    pub last_known_size: u64,
    pub origin_device_id: Option<String>,
    /// When the deletion itself (the tombstone's own `current` row) was
    /// recorded.
    pub deleted_at_unix_nanos: i64,
}

#[allow(clippy::too_many_arguments)]
fn version_record(
    path: String,
    version_seq: i64,
    size: u64,
    mtime_unix_nanos: i64,
    blocks_json: &str,
    deleted: i64,
    state: &str,
    origin_device_id: Option<String>,
) -> VersionRecord {
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).unwrap_or_default();
    VersionRecord {
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        blocks,
        deleted: deleted != 0,
        state: VersionState::from_db_str(state),
        origin_device_id,
    }
}

/// One candidate for the automatic eviction sweep (), in the
/// order `list_evictable_files` returns them: least-recently-accessed first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictableFile {
    pub path: String,
    pub size: u64,
    pub last_accessed_unix: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterializationCounts {
    pub hydrated: u64,
    pub placeholder: u64,
    pub hydrating: u64,
}

/// A held file's reason and hold timestamp,
/// as returned by `SyncState::get_held_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldState {
    pub reason: String,
    pub since_unix_nanos: i64,
}

fn row_to_record(
    path: String,
    size: u64,
    mtime_unix_nanos: i64,
    version_json: &str,
    blocks_json: &str,
    deleted: i64,
) -> FileRecord {
    let counters = serde_json::from_str(version_json).unwrap_or_default();
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).unwrap_or_default();
    FileRecord {
        path,
        size,
        mtime_unix_nanos,
        version: VersionVector::from_counters(counters),
        blocks,
        deleted: deleted != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(path: &str) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size: 42,
            mtime_unix_nanos: 1000,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    fn sample_record_with_hash(path: &str, hash_byte: u8) -> FileRecord {
        let mut record = sample_record(path);
        record.blocks = vec![BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 42 }];
        record
    }

    fn hash_hex(hash_byte: u8) -> ContentHash {
        hex::encode(vec![hash_byte; 32])
    }

    /// Correctness — every requested
    /// path with a row comes back, keyed by its own path, and a requested
    /// path with no row is simply absent (not an error, not a spurious
    /// entry), mirroring `get_file` returning `None` for the same case.
    /// Also proves tombstones (`deleted = true`) are included, matching
    /// `get_file`'s own no-filtering behavior — the caller (`reconcile_
    /// files`) needs to see a peer-visible deletion just as much as a live
    /// file when deciding whether an incoming record is new information.
    #[test]
    fn get_files_by_paths_returns_only_matching_rows_and_omits_the_rest() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("a.txt")).unwrap();
        state.upsert_file("group-1", &sample_record("b.txt")).unwrap();
        let mut tombstone = sample_record("c.txt");
        tombstone.deleted = true;
        state.upsert_file("group-1", &tombstone).unwrap();
        // A file that exists in a *different* group must never leak into a
        // query scoped to "group-1".
        state.upsert_file("group-2", &sample_record("a.txt")).unwrap();

        let requested =
            vec!["a.txt".to_string(), "c.txt".to_string(), "never-indexed.txt".to_string()];
        let found = state.get_files_by_paths("group-1", &requested).unwrap();

        assert_eq!(found.len(), 2, "b.txt was never requested; never-indexed.txt has no row");
        assert!(found.contains_key("a.txt"));
        assert!(found["c.txt"].deleted, "tombstones must be included, not filtered out");
        assert!(!found.contains_key("never-indexed.txt"));
        assert!(
            !found.contains_key("b.txt"),
            "an unrequested path must not appear even though it exists"
        );
    }

    #[test]
    fn get_files_by_paths_is_a_no_op_for_an_empty_path_list() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("a.txt")).unwrap();
        assert!(state.get_files_by_paths("group-1", &[]).unwrap().is_empty());
    }

    /// A real regression guard
    /// for "batched set-based query instead of one point query per
    /// record" — mirrors the established style of
    /// `local_change::tests::scan_existing_files_completes_quickly_for_
    /// thousands_of_small_files` (a real timing comparison, not just
    /// instrumenting query counts). One `get_files_by_paths` call for a
    /// few thousand paths must be meaningfully faster than issuing that
    /// many individual `get_file` calls for the same paths — proving the
    /// batched path isn't secretly still O(records) round-trips under the
    /// hood.
    #[test]
    fn get_files_by_paths_is_meaningfully_faster_than_one_get_file_call_per_path() {
        let state = SyncState::open_in_memory().unwrap();
        const FILE_COUNT: usize = 3000;
        let paths: Vec<String> = (0..FILE_COUNT).map(|i| format!("file-{i}.bin")).collect();
        for path in &paths {
            state.upsert_file("group-1", &sample_record(path)).unwrap();
        }

        let looped_started = std::time::Instant::now();
        let mut looped_count = 0;
        for path in &paths {
            if state.get_file("group-1", path).unwrap().is_some() {
                looped_count += 1;
            }
        }
        let looped_elapsed = looped_started.elapsed();

        let batched_started = std::time::Instant::now();
        let batched = state.get_files_by_paths("group-1", &paths).unwrap();
        let batched_elapsed = batched_started.elapsed();

        assert_eq!(looped_count, FILE_COUNT);
        assert_eq!(batched.len(), FILE_COUNT);
        // A 2x threshold flaked on a noisy/shared CI runner (observed
        // 34.98ms vs 61.16ms -- batched genuinely was faster, just not by
        // 2x that particular run); 25% keeps this a real regression
        // guard against the batched path secretly still doing O(records)
        // round-trips under the hood, without chasing CI-noise-sized
        // margins on an absolute-tens-of-milliseconds measurement.
        assert!(
            batched_elapsed * 4 < looped_elapsed * 3,
            "batched get_files_by_paths ({batched_elapsed:?}) should be meaningfully faster \
             than {FILE_COUNT} individual get_file round trips ({looped_elapsed:?}) for the \
             same paths"
        );
    }

    /// link registration and persistence round-trip.
    #[test]
    fn link_lifecycle_add_list_remove() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.add_link("/home/alice/Docs", "group-2").unwrap();

        let links = state.list_links().unwrap();
        assert_eq!(links.len(), 2);
        assert!(links
            .iter()
            .any(|l| l.local_path == "/home/alice/Photos" && l.group_id == "group-1"));
        assert!(!links.iter().any(|l| l.paused));

        state.remove_link("/home/alice/Photos").unwrap();
        let links = state.list_links().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].local_path, "/home/alice/Docs");
    }

    #[test]
    fn live_block_hashes_include_all_non_deleted_materialization_states() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("hydrated.bin", 0x11)).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("placeholder.bin", 0x22)).unwrap();
        state
            .set_materialization_state(
                "group-1",
                "placeholder.bin",
                MaterializationState::Placeholder,
            )
            .unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("hydrating.bin", 0x33)).unwrap();
        state
            .set_materialization_state("group-1", "hydrating.bin", MaterializationState::Hydrating)
            .unwrap();

        let live = state.live_block_hashes().unwrap();

        assert!(live.contains(&hash_hex(0x11)));
        assert!(live.contains(&hash_hex(0x22)));
        assert!(live.contains(&hash_hex(0x33)));
        assert_eq!(live.len(), 3);
    }

    #[test]
    fn live_block_hashes_exclude_tombstones_and_include_extra_roots() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("live.bin", 0x44)).unwrap();
        let mut deleted = sample_record_with_hash("deleted.bin", 0x55);
        deleted.deleted = true;
        state.upsert_file("group-1", &deleted).unwrap();

        let live = state.live_block_hashes_with_extra_roots([hash_hex(0x66)]).unwrap();

        assert!(live.contains(&hash_hex(0x44)));
        assert!(live.contains(&hash_hex(0x66)));
        assert!(!live.contains(&hash_hex(0x55)));
        assert_eq!(live.len(), 2);
    }

    #[test]
    fn live_block_hashes_use_one_snapshot_across_groups() {
        let dir = tempfile::tempdir().unwrap();
        let state = SyncState::open(dir.path().join("state.db")).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 0x77)).unwrap();
        state.upsert_file("group-2", &sample_record_with_hash("b.bin", 0x88)).unwrap();

        let mut writer = state.pool.get().unwrap();
        let tx = writer.transaction().unwrap();
        let uncommitted = sample_record_with_hash("pending.bin", 0x99);
        let version_json = serde_json::to_string(uncommitted.version.counters()).unwrap();
        let blocks_json = serde_json::to_string(&uncommitted.blocks).unwrap();
        tx.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "group-3",
                uncommitted.path,
                uncommitted.size,
                uncommitted.mtime_unix_nanos,
                version_json,
                blocks_json,
                uncommitted.deleted as i64,
            ],
        )
        .unwrap();

        let live_before_commit = state.live_block_hashes().unwrap();
        assert!(live_before_commit.contains(&hash_hex(0x77)));
        assert!(live_before_commit.contains(&hash_hex(0x88)));
        assert!(!live_before_commit.contains(&hash_hex(0x99)));

        tx.commit().unwrap();
        let live_after_commit = state.live_block_hashes().unwrap();
        assert!(live_after_commit.contains(&hash_hex(0x77)));
        assert!(live_after_commit.contains(&hash_hex(0x88)));
        assert!(live_after_commit.contains(&hash_hex(0x99)));
    }

    /// pausing a link doesn't lose already-recorded changes —
    /// the index is the queued-change backlog, and it's untouched by the
    /// pause flag itself (only propagation to peers is gated on it,
    /// handled by the caller per `local_change`'s module docs).
    #[test]
    fn pause_and_resume_preserve_queued_changes() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        state.set_paused("/home/alice/Photos", true).unwrap();
        assert!(state.list_links().unwrap()[0].paused);

        // Changes recorded while paused must still land in the index.
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        state.upsert_file("group-1", &sample_record("b.jpg")).unwrap();
        assert_eq!(state.list_files("group-1").unwrap().len(), 2);

        state.set_paused("/home/alice/Photos", false).unwrap();
        assert!(!state.list_links().unwrap()[0].paused);

        // Nothing was lost across the pause/resume cycle.
        let files = state.list_files("group-1").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn set_paused_on_unknown_link_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_paused("/nope", true).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// Every pre-existing and
    /// freshly-added link defaults to `SendReceive` — the "no behavior
    /// change without opt-in" migration guarantee, same shape as
    /// `new_links_default_to_eager_policy_with_no_cap` above.
    #[test]
    fn new_links_default_to_send_receive_mode() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        assert_eq!(state.list_links().unwrap()[0].mode, LinkMode::SendReceive);
        assert_eq!(state.link_mode_for_group("group-1").unwrap(), Some(LinkMode::SendReceive));
    }

    #[test]
    fn link_mode_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        state.set_link_mode("/home/alice/Photos", LinkMode::SendOnly).unwrap();
        assert_eq!(state.list_links().unwrap()[0].mode, LinkMode::SendOnly);
        assert_eq!(state.link_mode_for_group("group-1").unwrap(), Some(LinkMode::SendOnly));

        state.set_link_mode("/home/alice/Photos", LinkMode::ReceiveOnly).unwrap();
        assert_eq!(state.list_links().unwrap()[0].mode, LinkMode::ReceiveOnly);
        assert_eq!(state.link_mode_for_group("group-1").unwrap(), Some(LinkMode::ReceiveOnly));
    }

    #[test]
    fn set_link_mode_on_unknown_link_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_link_mode("/nope", LinkMode::SendOnly).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    #[test]
    fn link_mode_for_group_on_unknown_group_returns_none() {
        let state = SyncState::open_in_memory().unwrap();
        assert_eq!(state.link_mode_for_group("no-such-group").unwrap(), None);
    }

    /// `is_paused_for_group` reflects
    /// `set_paused`, addressed by `group_id` instead of `local_path` —
    /// the lookup shape `reconcile_files_if_authorized` needs.
    #[test]
    fn is_paused_for_group_reflects_set_paused() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        assert!(!state.is_paused_for_group("group-1").unwrap());

        state.set_paused("/home/alice/Photos", true).unwrap();
        assert!(state.is_paused_for_group("group-1").unwrap());

        state.set_paused("/home/alice/Photos", false).unwrap();
        assert!(!state.is_paused_for_group("group-1").unwrap());
    }

    #[test]
    fn is_paused_for_group_on_unknown_group_returns_false() {
        let state = SyncState::open_in_memory().unwrap();
        assert!(!state.is_paused_for_group("no-such-group").unwrap());
    }

    /// An out-of-sync item survives an
    /// `INSERT OR REPLACE` re-record (a fresher gated event for the same
    /// path doesn't create a second entry) and is removed by `override`'s
    /// `clear_out_of_sync`.
    #[test]
    fn out_of_sync_items_record_list_count_and_clear() {
        let state = SyncState::open_in_memory().unwrap();
        state.record_out_of_sync("group-1", "a.txt", 100).unwrap();
        state.record_out_of_sync("group-1", "b.txt", 200).unwrap();
        // Re-recording the same path must not duplicate it.
        state.record_out_of_sync("group-1", "a.txt", 300).unwrap();
        // A different group's entries must never leak into this group's list.
        state.record_out_of_sync("group-2", "c.txt", 400).unwrap();

        assert_eq!(state.count_out_of_sync("group-1").unwrap(), 2);
        // "a.txt" was re-recorded at 300, later than "b.txt"'s 200, so it
        // now sorts after "b.txt" by `recorded_at_unix_nanos` — proving the
        // re-record replaced the row's timestamp rather than adding a
        // second one (which `count_out_of_sync` above also confirms: still
        // 2, not 3).
        assert_eq!(state.list_out_of_sync("group-1").unwrap(), vec!["b.txt", "a.txt"]);

        state.clear_out_of_sync("group-1", "a.txt").unwrap();
        assert_eq!(state.count_out_of_sync("group-1").unwrap(), 1);
        assert_eq!(state.list_out_of_sync("group-1").unwrap(), vec!["b.txt"]);

        // Clearing a never-recorded path is a harmless no-op, not an error.
        state.clear_out_of_sync("group-1", "never-recorded.txt").unwrap();
    }

    #[test]
    fn receive_only_changed_items_record_list_count_and_clear() {
        let state = SyncState::open_in_memory().unwrap();
        state.record_receive_only_changed("group-1", "a.txt", 100).unwrap();
        state.record_receive_only_changed("group-1", "b.txt", 200).unwrap();
        state.record_receive_only_changed("group-1", "a.txt", 300).unwrap();
        state.record_receive_only_changed("group-2", "c.txt", 400).unwrap();

        assert_eq!(state.count_receive_only_changed("group-1").unwrap(), 2);
        assert_eq!(state.list_receive_only_changed("group-1").unwrap(), vec!["b.txt", "a.txt"]);

        state.clear_receive_only_changed("group-1", "a.txt").unwrap();
        assert_eq!(state.count_receive_only_changed("group-1").unwrap(), 1);
        assert_eq!(state.list_receive_only_changed("group-1").unwrap(), vec!["b.txt"]);

        state.clear_receive_only_changed("group-1", "never-recorded.txt").unwrap();
    }

    /// : existing links (and freshly-added ones with no explicit
    /// policy) default to `Eager` with no configured cap — the "no
    /// behavior change without opt-in" migration guarantee.
    #[test]
    fn new_links_default_to_eager_policy_with_no_cap() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        let link = &state.list_links().unwrap()[0];
        assert_eq!(link.materialization_policy, MaterializationPolicy::Eager);
        assert_eq!(link.max_local_size_bytes, None);
        assert_eq!(
            link.chunking_policy,
            ChunkingPolicy::Fixed,
            "content-defined-chunking task 2.4: new links default to Fixed"
        );
    }

    #[test]
    fn materialization_policy_and_cap_round_trip() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        state
            .set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand)
            .unwrap();
        state.set_max_local_size_bytes("/home/alice/Photos", Some(10_000_000)).unwrap();

        let link = &state.list_links().unwrap()[0];
        assert_eq!(link.materialization_policy, MaterializationPolicy::OnDemand);
        assert_eq!(link.max_local_size_bytes, Some(10_000_000));
    }

    /// content-defined-chunking task 2.4: setting/reading the chunking
    /// policy round-trips correctly, independent of materialization policy.
    #[test]
    fn chunking_policy_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/VMs", "group-1").unwrap();

        state.set_chunking_policy("/home/alice/VMs", ChunkingPolicy::ContentDefined).unwrap();

        let link = &state.list_links().unwrap()[0];
        assert_eq!(link.chunking_policy, ChunkingPolicy::ContentDefined);

        state.set_chunking_policy("/home/alice/VMs", ChunkingPolicy::Fixed).unwrap();
        let link = &state.list_links().unwrap()[0];
        assert_eq!(link.chunking_policy, ChunkingPolicy::Fixed);
    }

    #[test]
    fn set_chunking_policy_on_unknown_link_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_chunking_policy("/nope", ChunkingPolicy::ContentDefined).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// : a freshly-indexed file defaults to `Hydrated` and
    /// unpinned, matching `upsert_file`'s existing (pre-on-demand-sync)
    /// callers, all of which represent genuine local content.
    #[test]
    fn new_file_defaults_to_hydrated_and_unpinned() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();

        assert_eq!(
            state.get_materialization_state("group-1", "a.jpg").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        assert!(!state.is_pinned("group-1", "a.jpg").unwrap());
    }

    #[test]
    fn materialization_state_and_pin_round_trip() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();

        state
            .set_materialization_state("group-1", "a.jpg", MaterializationState::Placeholder)
            .unwrap();
        assert_eq!(
            state.get_materialization_state("group-1", "a.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );

        state.set_pinned("group-1", "a.jpg", true).unwrap();
        assert!(state.is_pinned("group-1", "a.jpg").unwrap());
        state.set_pinned("group-1", "a.jpg", false).unwrap();
        assert!(!state.is_pinned("group-1", "a.jpg").unwrap());
    }

    #[test]
    fn set_materialization_state_on_unknown_file_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state
            .set_materialization_state("group-1", "nope.jpg", MaterializationState::Placeholder)
            .unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// COR-7: a crash mid-hydration must not leave a file permanently
    /// stuck `Hydrating` — daemon startup resets it back to
    /// `Placeholder`. Covers multiple groups and confirms
    /// `Hydrated`/`Placeholder` rows (including in a different group) are
    /// left untouched.
    #[test]
    fn reset_stale_hydrating_to_placeholder_only_touches_hydrating_rows() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("stuck.jpg")).unwrap();
        state.upsert_file("group-1", &sample_record("hydrated.jpg")).unwrap();
        state.upsert_file("group-2", &sample_record("stuck-too.jpg")).unwrap();
        state
            .set_materialization_state("group-1", "stuck.jpg", MaterializationState::Hydrating)
            .unwrap();
        state
            .set_materialization_state("group-2", "stuck-too.jpg", MaterializationState::Hydrating)
            .unwrap();
        // hydrated.jpg left at its default (Hydrated) — never touched.

        let reset_count = state.reset_stale_hydrating_to_placeholder().unwrap();
        assert_eq!(reset_count, 2);

        assert_eq!(
            state.get_materialization_state("group-1", "stuck.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        assert_eq!(
            state.get_materialization_state("group-2", "stuck-too.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        assert_eq!(
            state.get_materialization_state("group-1", "hydrated.jpg").unwrap(),
            Some(MaterializationState::Hydrated)
        );

        // Idempotent: nothing left to reset on a second call.
        assert_eq!(state.reset_stale_hydrating_to_placeholder().unwrap(), 0);
    }

    /// : eviction candidates are hydrated, unpinned, non-deleted
    /// files, ordered least-recently-accessed first (never-accessed
    /// files sort before any that have been accessed at all).
    #[test]
    fn list_evictable_files_excludes_pinned_placeholder_and_deleted_orders_by_lru() {
        let state = SyncState::open_in_memory().unwrap();

        state.upsert_file("group-1", &sample_record("never-accessed.jpg")).unwrap();

        state.upsert_file("group-1", &sample_record("old.jpg")).unwrap();
        state.touch_last_accessed("group-1", "old.jpg", 100).unwrap();

        state.upsert_file("group-1", &sample_record("recent.jpg")).unwrap();
        state.touch_last_accessed("group-1", "recent.jpg", 999).unwrap();

        state.upsert_file("group-1", &sample_record("pinned.jpg")).unwrap();
        state.set_pinned("group-1", "pinned.jpg", true).unwrap();

        state.upsert_file("group-1", &sample_record("placeholder.jpg")).unwrap();
        state
            .set_materialization_state(
                "group-1",
                "placeholder.jpg",
                MaterializationState::Placeholder,
            )
            .unwrap();

        state.mark_deleted("group-1", "gone.jpg", "device-a").unwrap();

        let evictable = state.list_evictable_files("group-1").unwrap();
        let paths: Vec<&str> = evictable.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["never-accessed.jpg", "old.jpg", "recent.jpg"]);
    }

    /// `yadorilink status`'s per-folder materialization summary.
    #[test]
    fn materialization_counts_summarizes_by_state_excluding_deleted() {
        let state = SyncState::open_in_memory().unwrap();

        state.upsert_file("group-1", &sample_record("hydrated-a.jpg")).unwrap();
        state.upsert_file("group-1", &sample_record("hydrated-b.jpg")).unwrap();

        state.upsert_file("group-1", &sample_record("placeholder-a.jpg")).unwrap();
        state
            .set_materialization_state(
                "group-1",
                "placeholder-a.jpg",
                MaterializationState::Placeholder,
            )
            .unwrap();

        state.upsert_file("group-1", &sample_record("hydrating-a.jpg")).unwrap();
        state
            .set_materialization_state(
                "group-1",
                "hydrating-a.jpg",
                MaterializationState::Hydrating,
            )
            .unwrap();

        // Deleted files must not count toward any bucket.
        state.mark_deleted("group-1", "gone.jpg", "device-a").unwrap();

        let counts = state.materialization_counts("group-1").unwrap();
        assert_eq!(counts.hydrated, 2);
        assert_eq!(counts.placeholder, 1);
        assert_eq!(counts.hydrating, 1);
    }

    // --- sync-performance PERF-3: connection-pooling tests ---
    //
    // These reach into `state.pool` directly (a private field, visible
    // here since `tests` is a descendant of the `index` module) to prove
    // properties of the pooling mechanism itself, not just observable
    // behavior through the public API — the public API alone can't
    // distinguish "one connection serialized by a mutex" from "a pool of
    // connections," since both give every caller correct, eventually-
    // consistent results. The mechanism is the point of this task.

    /// Proves the `open_in_memory` shared-cache setup documented on that
    /// constructor actually works, rather than assuming it does: pooled
    /// `:memory:` connections are normally *separate, empty* databases
    /// unless opened as a named, shared-cache URI. Grabs two connections
    /// from the pool simultaneously (so the pool is forced to hand out
    /// two distinct physical connections, not the same one twice — a
    /// single connection can't be checked out to two live guards at
    /// once), writes a row through one, and confirms it's visible
    /// through the *other* without any write going through the first
    /// connection again.
    #[test]
    fn pooled_connections_share_in_memory_state() {
        let state = SyncState::open_in_memory().unwrap();

        let conn_a = state.pool.get().unwrap();
        let conn_b = state.pool.get().unwrap();
        assert!(
            !std::ptr::eq(&raw const *conn_a, &raw const *conn_b),
            "pool.get() while both guards are alive must hand out two distinct connections"
        );

        conn_a.execute_batch("CREATE TABLE shared_probe (v INTEGER)").unwrap();
        conn_a.execute("INSERT INTO shared_probe (v) VALUES (42)", []).unwrap();

        let seen: i64 = conn_b.query_row("SELECT v FROM shared_probe", [], |r| r.get(0)).unwrap();
        assert_eq!(
            seen, 42,
            "a write through one pooled connection must be visible through another"
        );
    }

    /// Proves the concrete concurrency gain WAL mode adds (not just that
    /// the pragma was set without erroring): a reader using a *second*
    /// pooled connection can read while a *first* pooled connection has
    /// an uncommitted write transaction open, and sees the pre-write
    /// value rather than blocking or erroring. Deliberately single-
    /// threaded and sequential — no timing/sleep involved — because
    /// SQLite's blocking behavior on a second connection is either an
    /// immediate success (WAL) or an immediate `SQLITE_BUSY` error
    /// (rollback-journal, this test's counterfactual), not something
    /// that needs a race to observe. WAL is a no-op for `:memory:`
    /// databases, so this uses the file-backed `open` path, exercising
    /// the exact pragma setup `SyncState::open` performs.
    #[test]
    fn wal_mode_lets_a_reader_proceed_while_a_writer_transaction_is_open() {
        let dir = tempfile::tempdir().unwrap();
        let state = SyncState::open(dir.path().join("state.db")).unwrap();
        state.add_link("/some/path", "group-1").unwrap();

        let mut conn_a = state.pool.get().unwrap();
        let tx = conn_a.transaction().unwrap();
        tx.execute("UPDATE links SET paused = 1 WHERE local_path = ?1", ["/some/path"]).unwrap();
        // Not committed yet — conn_a's write is only visible to itself.

        let conn_b = state.pool.get().unwrap();
        let paused: i64 = conn_b
            .query_row("SELECT paused FROM links WHERE local_path = ?1", ["/some/path"], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            paused, 0,
            "a second connection must read the pre-write snapshot, not block and not see \
             uncommitted data"
        );

        drop(tx); // rolls back; conn_a's uncommitted write never lands.
    }

    /// The end-to-end version of the WAL test above, driven entirely
    /// through `SyncState`'s public API across two real threads,
    /// synchronized with channels (not sleeps, so this isn't a timing
    /// guess). A background thread opens a write transaction and then
    /// deliberately blocks — waiting on the *main* thread before it will
    /// commit — while the main thread performs a `list_links` read.
    ///
    /// Under the old `Mutex<Connection>` design this exact scenario is a
    /// guaranteed deadlock: `list_links` would need to lock the same
    /// mutex the writer thread is already holding, and the writer thread
    /// won't unlock it until *after* the read it's blocking returns — a
    /// genuine circular wait with no way out. With a real connection
    /// pool, `list_links` obtains its own connection and completes
    /// immediately, proving reads are no longer serialized behind an
    /// in-flight write.
    #[test]
    fn concurrent_reader_is_not_blocked_by_an_in_flight_writer_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(SyncState::open(dir.path().join("state.db")).unwrap());
        state.add_link("/some/path", "group-1").unwrap();

        let (write_started_tx, write_started_rx) = std::sync::mpsc::channel::<()>();
        let (finish_write_tx, finish_write_rx) = std::sync::mpsc::channel::<()>();

        let writer_state = state.clone();
        let writer = std::thread::spawn(move || {
            let mut conn = writer_state.pool.get().unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute("UPDATE links SET paused = 1 WHERE local_path = ?1", ["/some/path"])
                .unwrap();
            write_started_tx.send(()).unwrap();
            // Hold the transaction open until the main thread has proven
            // its read didn't need to wait for this commit.
            finish_write_rx.recv().unwrap();
            tx.commit().unwrap();
        });

        write_started_rx.recv().unwrap();
        // If this were still serialized behind the writer (the old
        // design), this call would block forever here: the writer
        // thread won't send on `finish_write_tx` until *after*
        // `list_links` returns. Hanging here is itself the failure mode
        // this test rules out.
        let links = state.list_links().unwrap();
        assert!(
            !links[0].paused,
            "reader must see the pre-write value, not block on or observe the in-flight write"
        );

        finish_write_tx.send(()).unwrap();
        writer.join().unwrap();

        let links = state.list_links().unwrap();
        assert!(links[0].paused, "the write is visible once the writer actually commits");
    }

    // --- Record model & index schema ---

    /// The exact pre-sync-fidelity `files`/`links` schema (identical to
    /// the base `CREATE TABLE` block in `SyncState::init`, which itself
    /// already reflects on-demand-sync and content-defined-chunking's
    /// lightweight migrations having long since landed) — used to simulate
    /// a real pre-existing on-disk database that has never seen this
    /// task's migration run.
    const OLD_SCHEMA_SQL: &str = r#"
        CREATE TABLE files (
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            version_json      TEXT NOT NULL,
            blocks_json       TEXT NOT NULL,
            deleted           INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        );

        CREATE TABLE links (
            local_path TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            paused     INTEGER NOT NULL DEFAULT 0
        );
        "#;

    #[derive(Debug, Clone, PartialEq)]
    struct ColumnInfo {
        name: String,
        col_type: String,
        notnull: i64,
        dflt_value: Option<String>,
        pk: i64,
    }

    /// `PRAGMA table_info(<table>)`, in column (`cid`) order — the actual
    /// on-disk shape of a table, not an assumption about what `init`
    /// produces.
    fn table_info(conn: &Connection, table: &str) -> Vec<ColumnInfo> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        stmt.query_map([], |r| {
            Ok(ColumnInfo {
                name: r.get(1)?,
                col_type: r.get(2)?,
                notnull: r.get(3)?,
                dflt_value: r.get(4)?,
                pk: r.get(5)?,
            })
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// a fresh database (created purely through `init`'s normal
    /// `CREATE TABLE IF NOT EXISTS` + lightweight-migration path, exactly
    /// what `SyncState::open_in_memory` does) and a database upgraded from
    /// the real pre-existing (`OLD_SCHEMA_SQL`) schema end up with
    /// byte-for-byte identical `PRAGMA table_info` output for `files` —
    /// verified directly against SQLite, not assumed from reading the
    /// `ALTER TABLE` statements. Also confirms this task's five new
    /// columns are actually present (not just equally absent from both).
    #[test]
    fn fresh_and_upgraded_schema_are_identical() {
        let fresh = SyncState::open_in_memory().unwrap();
        let fresh_conn = fresh.pool.get().unwrap();
        let fresh_schema = table_info(&fresh_conn, "files");

        let old_conn = Connection::open_in_memory().unwrap();
        old_conn.execute_batch(OLD_SCHEMA_SQL).unwrap();
        SyncState::init(&old_conn).unwrap();
        let upgraded_schema = table_info(&old_conn, "files");

        assert_eq!(
            fresh_schema, upgraded_schema,
            "a fresh database and a database upgraded from the pre-existing schema must end up \
             with identical `files` schema"
        );
        for expected in
            ["record_kind", "symlink_target", "exec_bit", "held_reason", "held_since_unix_nanos"]
        {
            assert!(
                fresh_schema.iter().any(|c| c.name == expected),
                "expected column {expected:?} to exist on the fresh schema"
            );
        }
    }

    /// running the migration twice (e.g. two `SyncState::open`
    /// calls against the same on-disk file within one process, or a crash
    /// and restart mid-migration) must not error on SQLite's "duplicate
    /// column name" and must not duplicate any column.
    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        SyncState::init(&conn).unwrap();
        let schema_after_first = table_info(&conn, "files");

        SyncState::init(&conn).unwrap();
        let schema_after_second = table_info(&conn, "files");

        assert_eq!(
            schema_after_first, schema_after_second,
            "re-running the migration must be a pure no-op on an already-migrated schema"
        );
        for col in
            ["record_kind", "symlink_target", "exec_bit", "held_reason", "symlink_out_of_root"]
        {
            assert_eq!(
                schema_after_second.iter().filter(|c| c.name == col).count(),
                1,
                "column {col:?} must appear exactly once, not duplicated"
            );
        }
    }

    /// task 1.2/1.3: a row that existed *before* this task's columns were
    /// added (inserted directly against `OLD_SCHEMA_SQL`, bypassing
    /// `upsert_file` entirely) gets exactly the documented defaults once
    /// the migration runs: `record_kind = 'file'`, no symlink target,
    /// `exec_bit = 0`, and no held state — the "every existing
    /// installation keeps behaving exactly as it did" guarantee, checked
    /// against a real pre-existing row, not a freshly-inserted one.
    #[test]
    fn upgraded_pre_existing_rows_get_correct_defaults() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(OLD_SCHEMA_SQL).unwrap();
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, \
             blocks_json, deleted) VALUES ('group-1', 'pre-existing.txt', 10, 0, '{}', '[]', 0)",
            [],
        )
        .unwrap();

        SyncState::init(&conn).unwrap();

        let row: (String, Option<String>, i64, Option<String>, Option<i64>, i64) = conn
            .query_row(
                "SELECT record_kind, symlink_target, exec_bit, held_reason, \
                 held_since_unix_nanos, symlink_out_of_root FROM files WHERE group_id = 'group-1' \
                 AND path = 'pre-existing.txt'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(row.0, "file");
        assert_eq!(row.1, None);
        assert_eq!(row.2, 0);
        assert_eq!(row.3, None);
        assert_eq!(row.4, None);
        assert_eq!(row.5, 0, "symlink_out_of_root (task 2.4) must also default to unflagged");
    }

    // --- Schema-version
    // stamping, interrupted-migration recovery, and unsupported-downgrade
    // rejection. `OLD_SCHEMA_SQL` above stands in for the first public
    // beta baseline: it's the exact pre-sync-fidelity `files`/`links`
    // shape a real early-beta on-disk database would have had before any
    // of sync-fidelity/folder-direction-modes/file-version-
    // history's migrations existed, which is exactly the fixture state
    // from the first public beta baseline this test group needs — reused
    // here rather than duplicated, since it already faithfully represents
    // that shape and every test below builds on the same `init` call
    // those tests already exercise.

    /// a fresh database ends up with `PRAGMA user_version`
    /// stamped to the current `SCHEMA_VERSION`, not left at SQLite's
    /// default of 0 — the explicit version marker this task adds on top
    /// of the pre-existing shape-detection migrations.
    #[test]
    fn init_stamps_current_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        SyncState::init(&conn).unwrap();
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// (rerun): stamping the schema version is exactly as
    /// idempotent as the column migrations it accompanies — re-running
    /// `init` on an already-current database leaves `user_version`
    /// unchanged and still makes no destructive changes, matching the
    /// spec's "Migration rerun is harmless" scenario.
    #[test]
    fn rerunning_init_leaves_schema_version_unchanged() {
        let conn = Connection::open_in_memory().unwrap();
        SyncState::init(&conn).unwrap();
        SyncState::init(&conn).unwrap();
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// (interrupted migration recovery): simulates a crash that
    /// hit partway through the `ALTER TABLE` loop — some but not all of
    /// the lightweight-migration columns present, mirroring exactly what
    /// a real interrupted upgrade would leave on disk (each `ALTER TABLE`
    /// is its own committed statement, so a crash between two of them
    /// leaves a database with a genuine partial subset of columns, not a
    /// half-written single statement). Confirms `init` resumes cleanly to
    /// the full current schema, with no data loss and no error from
    /// columns that already exist.
    #[test]
    fn interrupted_migration_recovers_on_restart() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(OLD_SCHEMA_SQL).unwrap();
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, \
             blocks_json, deleted) VALUES ('group-1', 'mid-crash.txt', 5, 0, '{}', '[]', 0)",
            [],
        )
        .unwrap();
        // Hand-apply only the *first few* columns the real loop would add,
        // standing in for a process that crashed after those statements
        // committed but before the rest ran.
        conn.execute_batch(
            "ALTER TABLE files ADD COLUMN materialization_state TEXT NOT NULL DEFAULT 'hydrated';
             ALTER TABLE files ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;",
        )
        .unwrap();

        SyncState::init(&conn).unwrap();

        let fresh = Connection::open_in_memory().unwrap();
        SyncState::init(&fresh).unwrap();
        assert_eq!(
            table_info(&conn, "files"),
            table_info(&fresh, "files"),
            "resuming from a partially-migrated database must reach the exact same schema as a \
             fresh one"
        );
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files WHERE path = 'mid-crash.txt'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(row_count, 1, "the row present before the interrupted migration must survive");
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION, "recovery must also complete the version stamp");
    }

    /// / spec "Downgrade blocked": a database whose `user_version`
    /// is newer than this binary's `SCHEMA_VERSION` (i.e. it was migrated
    /// by a newer build) must make `init` fail with
    /// `UnsupportedSchemaDowngrade` instead of running any migration
    /// statement against a shape this binary doesn't know about.
    #[test]
    fn downgrade_to_a_newer_on_disk_schema_is_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        SyncState::init(&conn).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();

        let schema_before = table_info(&conn, "files");
        let err = SyncState::init(&conn).unwrap_err();
        assert!(
            matches!(
                err,
                SyncError::UnsupportedSchemaDowngrade { on_disk_version, supported_version }
                    if on_disk_version == SCHEMA_VERSION + 1 && supported_version == SCHEMA_VERSION
            ),
            "expected UnsupportedSchemaDowngrade, got {err:?}"
        );
        assert_eq!(
            table_info(&conn, "files"),
            schema_before,
            "a rejected downgrade must leave the schema completely untouched"
        );
    }

    /// a freshly-upserted file (the common case: scan/watch
    /// producing a brand-new row via `upsert_file`, which doesn't mention
    /// any of these columns) defaults the same way an upgraded pre-existing
    /// row does — `RecordKind::File`, no symlink target, no exec bit, not
    /// held — matching the shape of `new_file_defaults_to_hydrated_and_unpinned`
    /// above for the pre-existing `materialization_state`/`pinned` columns.
    #[test]
    fn new_file_defaults_to_regular_file_no_exec_bit_not_held() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();

        assert_eq!(state.get_record_kind("group-1", "a.jpg").unwrap(), Some(RecordKind::File));
        assert_eq!(state.get_symlink_target("group-1", "a.jpg").unwrap(), None);
        assert!(!state.get_exec_bit("group-1", "a.jpg").unwrap());
        assert_eq!(state.get_held_state("group-1", "a.jpg").unwrap(), None);
        assert!(!state.get_symlink_out_of_root("group-1", "a.jpg").unwrap());
    }

    /// `record_kind` getter/setter round-trip, matching the
    /// existing `chunking_policy_round_trips`/`materialization_state_and_
    /// pin_round_trip` accessor shape.
    #[test]
    fn record_kind_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("link-or-file")).unwrap();

        assert_eq!(
            state.get_record_kind("group-1", "link-or-file").unwrap(),
            Some(RecordKind::File)
        );

        state.set_record_kind("group-1", "link-or-file", RecordKind::Symlink).unwrap();
        assert_eq!(
            state.get_record_kind("group-1", "link-or-file").unwrap(),
            Some(RecordKind::Symlink)
        );

        state.set_record_kind("group-1", "link-or-file", RecordKind::Directory).unwrap();
        assert_eq!(
            state.get_record_kind("group-1", "link-or-file").unwrap(),
            Some(RecordKind::Directory)
        );
    }

    #[test]
    fn get_record_kind_on_unknown_file_returns_none() {
        let state = SyncState::open_in_memory().unwrap();
        assert_eq!(state.get_record_kind("group-1", "nope").unwrap(), None);
    }

    #[test]
    fn set_record_kind_on_unknown_file_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_record_kind("group-1", "nope", RecordKind::Symlink).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// `symlink_target` getter/setter round-trip, including
    /// clearing it back to `None`.
    #[test]
    fn symlink_target_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("link")).unwrap();
        state.set_record_kind("group-1", "link", RecordKind::Symlink).unwrap();

        assert_eq!(state.get_symlink_target("group-1", "link").unwrap(), None);

        state.set_symlink_target("group-1", "link", Some("../outside/target")).unwrap();
        assert_eq!(
            state.get_symlink_target("group-1", "link").unwrap(),
            Some("../outside/target".to_string())
        );

        state.set_symlink_target("group-1", "link", None).unwrap();
        assert_eq!(state.get_symlink_target("group-1", "link").unwrap(), None);
    }

    /// `symlink_out_of_root` getter/setter round-trip, matching
    /// `exec_bit`'s existing bool-column accessor shape.
    #[test]
    fn symlink_out_of_root_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("escape-link")).unwrap();

        assert!(!state.get_symlink_out_of_root("group-1", "escape-link").unwrap());
        state.set_symlink_out_of_root("group-1", "escape-link", true).unwrap();
        assert!(state.get_symlink_out_of_root("group-1", "escape-link").unwrap());
        state.set_symlink_out_of_root("group-1", "escape-link", false).unwrap();
        assert!(!state.get_symlink_out_of_root("group-1", "escape-link").unwrap());
    }

    #[test]
    fn set_symlink_out_of_root_on_unknown_file_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_symlink_out_of_root("group-1", "nope", true).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// `exec_bit` getter/setter round-trip, matching `is_pinned`/
    /// `set_pinned`'s existing bool-column accessor shape.
    #[test]
    fn exec_bit_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("script.sh")).unwrap();

        assert!(!state.get_exec_bit("group-1", "script.sh").unwrap());
        state.set_exec_bit("group-1", "script.sh", true).unwrap();
        assert!(state.get_exec_bit("group-1", "script.sh").unwrap());
        state.set_exec_bit("group-1", "script.sh", false).unwrap();
        assert!(!state.get_exec_bit("group-1", "script.sh").unwrap());
    }

    #[test]
    fn set_exec_bit_on_unknown_file_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_exec_bit("group-1", "nope", true).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    /// held state round-trips through `set_held`/`get_held_state`
    /// and clears via `clear_held`, surviving in the index the way design
    /// D3 requires (a held file's state and reason must survive a daemon
    /// restart — modeled here by simply reopening state via `get_held_state`
    /// rather than actually restarting a process, since the state itself
    /// lives entirely in the SQLite row, not in memory).
    #[test]
    fn held_state_round_trips_and_clears() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("A.txt")).unwrap();

        assert_eq!(state.get_held_state("group-1", "A.txt").unwrap(), None);

        state.set_held("group-1", "A.txt", "case_collision", 123_456_789).unwrap();
        let held = state.get_held_state("group-1", "A.txt").unwrap().unwrap();
        assert_eq!(held.reason, "case_collision");
        assert_eq!(held.since_unix_nanos, 123_456_789);

        state.clear_held("group-1", "A.txt").unwrap();
        assert_eq!(state.get_held_state("group-1", "A.txt").unwrap(), None);
    }

    /// `clear_held` on a file that was never held (or doesn't exist) is a
    /// deliberate no-op, not an error — 's tombstone-clears-held
    /// -state requirement (task 3.5, a later section) needs to clear held
    /// state unconditionally when applying a tombstone, without first
    /// checking whether the record was ever held.
    #[test]
    fn clear_held_on_never_held_file_is_a_harmless_no_op() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("never-held.txt")).unwrap();
        state.clear_held("group-1", "never-held.txt").unwrap();
        assert_eq!(state.get_held_state("group-1", "never-held.txt").unwrap(), None);

        // Also harmless against a path with no row at all.
        state.clear_held("group-1", "does-not-exist.txt").unwrap();
    }

    #[test]
    fn set_held_on_unknown_file_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state.set_held("group-1", "nope", "case_collision", 0).unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    // --- File version history ---

    fn record_with_size(path: &str, size: u64) -> FileRecord {
        let mut version = VersionVector::new();
        version.increment("device-a");
        FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 1000,
            version,
            blocks: vec![],
            deleted: false,
        }
    }

    /// task 1.3/1.6: three sequential edits to the same path leave exactly
    /// one `current` row and two correctly-ordered `superseded` rows, each
    /// with the `version_seq`/`origin_device_id` `list_versions` promises.
    #[test]
    fn upsert_file_with_origin_produces_one_current_row_and_ordered_superseded_rows() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 10), "device-a")
            .unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 20), "device-b")
            .unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 30), "device-a")
            .unwrap();

        // Exactly one current row, with the latest content.
        let current = state.get_file("group-1", "a.txt").unwrap().unwrap();
        assert_eq!(current.size, 30);

        let versions = state.list_versions("group-1", "a.txt").unwrap();
        assert_eq!(versions.len(), 3, "every edit is retained, including the current version");
        // Newest first.
        assert_eq!(versions[0].version_seq, 3);
        assert_eq!(versions[0].size, 30);
        assert_eq!(versions[0].state, VersionState::Current);
        assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-a"));

        assert_eq!(versions[1].version_seq, 2);
        assert_eq!(versions[1].size, 20);
        assert_eq!(versions[1].state, VersionState::Superseded);
        assert_eq!(versions[1].origin_device_id.as_deref(), Some("device-b"));

        assert_eq!(versions[2].version_seq, 1);
        assert_eq!(versions[2].size, 10);
        assert_eq!(versions[2].state, VersionState::Superseded);
        assert_eq!(versions[2].origin_device_id.as_deref(), Some("device-a"));
    }

    /// `upsert_file` (the plain, origin-agnostic entry point every
    /// pre-existing caller uses unchanged) still records history — just
    /// with `origin_device_id = None` ("unknown"), and every existing
    /// caller keeps compiling with no signature change.
    #[test]
    fn plain_upsert_file_still_retains_history_with_unknown_origin() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &record_with_size("a.txt", 10)).unwrap();
        state.upsert_file("group-1", &record_with_size("a.txt", 20)).unwrap();

        let versions = state.list_versions("group-1", "a.txt").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].origin_device_id, None);
        assert_eq!(versions[1].origin_device_id, None);
    }

    /// A version-1-to-be-superseded promotion shortcut used by
    /// `apply_incoming_wire_metadata`'s bootstrap scaffold (`peer_session.
    /// rs`): a `version_seq = 0` row is promoted in place rather than
    /// superseded, so a peer-adopted file's very first version doesn't
    /// come with a spurious empty "version 0" in its history.
    #[test]
    fn version_seq_zero_scaffold_row_is_promoted_not_superseded() {
        let state = SyncState::open_in_memory().unwrap();
        {
            let conn = state.pool.get().unwrap();
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted, version_seq, state, origin_device_id)
                 VALUES ('group-1', 'a.txt', 0, 0, '{}', '[]', 0, 0, 'current', NULL)",
                [],
            )
            .unwrap();
        }
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 42), "device-a")
            .unwrap();

        let versions = state.list_versions("group-1", "a.txt").unwrap();
        assert_eq!(
            versions.len(),
            1,
            "the scaffold row must be promoted, not superseded alongside it"
        );
        assert_eq!(versions[0].version_seq, 1);
        assert_eq!(versions[0].size, 42);
        assert_eq!(versions[0].state, VersionState::Current);
    }

    /// spec "Deletion Enters Recoverable Trash": deleting a file with live
    /// content flips that content's row to `trashed` (blocks intact) while
    /// the new `current` row is the tombstone itself.
    #[test]
    fn mark_deleted_trashes_prior_live_content_and_retains_blocks() {
        let state = SyncState::open_in_memory().unwrap();
        let mut record = record_with_size("a.txt", 100);
        record.blocks = vec![BlockInfo { hash: vec![0xAB; 32], offset: 0, size: 100 }];
        state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();

        state.mark_deleted("group-1", "a.txt", "device-a").unwrap();

        // The live file is gone.
        let current = state.get_file("group-1", "a.txt").unwrap().unwrap();
        assert!(current.deleted);

        // But its last version is queryable as trash, blocks intact.
        let trashed = state.list_trashed("group-1").unwrap();
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].path, "a.txt");
        assert_eq!(trashed[0].last_known_size, 100);
        assert_eq!(trashed[0].origin_device_id.as_deref(), Some("device-a"));

        let versions = state.list_versions("group-1", "a.txt").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].state, VersionState::Current);
        assert!(versions[0].deleted);
        assert_eq!(versions[1].state, VersionState::Trashed);
        assert!(!versions[1].deleted);
        assert_eq!(versions[1].blocks.len(), 1, "the trashed row must retain its block references");
    }

    /// A tombstone's
    /// `mtime_unix_nanos` must reflect the deletion's own observed time,
    /// not the stale mtime carried forward from the file's last live
    /// content (`record_with_size`'s fixed `1000`) — otherwise
    /// `conflict.rs`'s ordering of a concurrent edit against this delete
    /// has no correct chronological signal to work from.
    #[test]
    fn mark_deleted_stamps_tombstone_mtime_with_deletion_time_not_stale_content_mtime() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 100), "device-a")
            .unwrap();

        let before_delete = now_unix_nanos();
        state.mark_deleted("group-1", "a.txt", "device-a").unwrap();
        let after_delete = now_unix_nanos();

        let tombstone = state.get_file("group-1", "a.txt").unwrap().unwrap();
        assert!(tombstone.deleted);
        assert_ne!(
            tombstone.mtime_unix_nanos, 1000,
            "must not carry forward the pre-deletion content's mtime"
        );
        assert!(
            (before_delete..=after_delete).contains(&tombstone.mtime_unix_nanos),
            "tombstone mtime {} must reflect the deletion's own observed time, within [{before_delete}, {after_delete}]",
            tombstone.mtime_unix_nanos
        );
    }

    /// Deleting a path that was never indexed (`mark_deleted`'s existing
    /// from-scratch-tombstone behavior, COR-8) has no prior content to
    /// trash — `list_trashed` correctly reports nothing recoverable.
    #[test]
    fn mark_deleted_on_a_never_indexed_path_creates_no_trash_entry() {
        let state = SyncState::open_in_memory().unwrap();
        state.mark_deleted("group-1", "never-existed.txt", "device-a").unwrap();
        assert!(state.list_trashed("group-1").unwrap().is_empty());
        assert!(state.get_file("group-1", "never-existed.txt").unwrap().unwrap().deleted);
    }

    /// Deleting an already-deleted (tombstoned) path is a redundant delete
    /// event — the row being superseded is itself already a tombstone with
    /// no real content, so it becomes an unremarkable `superseded` history
    /// row rather than a second, empty trash entry.
    #[test]
    fn redeleting_an_already_deleted_file_does_not_duplicate_trash() {
        let state = SyncState::open_in_memory().unwrap();
        let mut record = record_with_size("a.txt", 100);
        record.blocks = vec![BlockInfo { hash: vec![0xCD; 32], offset: 0, size: 100 }];
        state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();
        state.mark_deleted("group-1", "a.txt", "device-a").unwrap();
        state.mark_deleted("group-1", "a.txt", "device-b").unwrap();

        let trashed = state.list_trashed("group-1").unwrap();
        assert_eq!(trashed.len(), 1, "still exactly one recoverable trash entry, not two");

        let versions = state.list_versions("group-1", "a.txt").unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].state, VersionState::Current); // second tombstone
        assert_eq!(versions[1].state, VersionState::Superseded); // first tombstone, now superseded
        assert_eq!(versions[2].state, VersionState::Trashed); // the original live content
    }

    #[test]
    fn get_version_returns_a_specific_version_and_none_for_an_unknown_seq() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 10), "device-a")
            .unwrap();
        state
            .upsert_file_with_origin("group-1", &record_with_size("a.txt", 20), "device-a")
            .unwrap();

        let v1 = state.get_version("group-1", "a.txt", 1).unwrap().unwrap();
        assert_eq!(v1.size, 10);
        assert_eq!(v1.state, VersionState::Superseded);

        assert!(state.get_version("group-1", "a.txt", 99).unwrap().is_none());
    }

    /// : every new and pre-existing link defaults to 10
    /// versions / 30 days, and the policy round-trips through
    /// `set_retention_policy`.
    #[test]
    fn retention_policy_defaults_and_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        assert_eq!(
            state.retention_policy_for_group("group-1").unwrap(),
            Some(RetentionPolicy::default())
        );
        assert_eq!(state.list_links().unwrap()[0].retention_policy, RetentionPolicy::default());

        state
            .set_retention_policy(
                "/home/alice/Photos",
                RetentionPolicy { max_versions: 5, max_age_days: 0 },
            )
            .unwrap();
        assert_eq!(
            state.retention_policy_for_group("group-1").unwrap(),
            Some(RetentionPolicy { max_versions: 5, max_age_days: 0 })
        );
    }

    #[test]
    fn set_retention_policy_on_unknown_link_errors() {
        let state = SyncState::open_in_memory().unwrap();
        let err = state
            .set_retention_policy("/nope", RetentionPolicy { max_versions: 1, max_age_days: 1 })
            .unwrap_err();
        assert!(matches!(err, SyncError::NotFound(_)));
    }

    const ONE_DAY_NANOS: i64 = 86_400 * 1_000_000_000;

    /// 's union-retain/intersection-expire rule (task 2.5): a
    /// version within either bound survives; one exceeding both is swept;
    /// the current row is never a candidate regardless of policy.
    #[test]
    fn expire_respects_union_retain_intersection_expire_rule() {
        let state = SyncState::open_in_memory().unwrap();
        let now = 1_000 * ONE_DAY_NANOS;

        // Five superseded versions, oldest first (version_seq 1..=5), each
        // one day apart in mtime; version_seq 6 is the current row.
        for i in 1..=6u64 {
            let mut record = record_with_size("a.txt", i);
            record.mtime_unix_nanos = now - (6 - i) as i64 * ONE_DAY_NANOS;
            state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();
        }
        // Superseded rows now have mtimes at now-5d, now-4d, now-3d, now-2d,
        // now-1d (version_seq 1..=5); version_seq 6 is current at `now`.

        // max_versions=2 keeps the 2 most recent superseded rows (seq 5, 4)
        // on the count axis; max_age_days=3 keeps anything newer than 3
        // days old (seq 5, 4, 3) on the age axis. Union: seq 3, 4, 5
        // survive; seq 1, 2 exceed both and are swept.
        let policy = RetentionPolicy { max_versions: 2, max_age_days: 3 };
        let deleted = state.expire_superseded_and_trashed_versions("group-1", policy, now).unwrap();
        assert_eq!(deleted, 2, "seq 1 and 2 exceed both bounds");

        let remaining: Vec<i64> = state
            .list_versions("group-1", "a.txt")
            .unwrap()
            .iter()
            .map(|v| v.version_seq)
            .collect();
        assert_eq!(remaining, vec![6, 5, 4, 3], "current row and seq 3-5 survive, newest first");
    }

    /// Either bound set to `0` disables that axis — a version stays
    /// retained via the other axis's union, matching 's
    /// documented "footgun, not blocked outright" semantics.
    #[test]
    fn expire_treats_a_zero_bound_as_unlimited_on_that_axis() {
        let state = SyncState::open_in_memory().unwrap();
        let now = 1_000 * ONE_DAY_NANOS;
        for i in 1..=3u64 {
            let mut record = record_with_size("a.txt", i);
            record.mtime_unix_nanos = now - (3 - i) as i64 * 365 * ONE_DAY_NANOS; // years old
            state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();
        }

        // Unlimited count, tiny age bound: nothing is swept, since every
        // row is "within" the unlimited count axis.
        let unlimited_count = RetentionPolicy { max_versions: 0, max_age_days: 1 };
        assert_eq!(
            state.expire_superseded_and_trashed_versions("group-1", unlimited_count, now).unwrap(),
            0
        );

        // Unlimited age, tiny count bound: still nothing is swept, since
        // every row is "within" the unlimited age axis.
        let unlimited_age = RetentionPolicy { max_versions: 1, max_age_days: 0 };
        assert_eq!(
            state.expire_superseded_and_trashed_versions("group-1", unlimited_age, now).unwrap(),
            0
        );

        assert_eq!(state.list_versions("group-1", "a.txt").unwrap().len(), 3);
    }

    /// task 4.1-4.3: the live-block-hash root set includes
    /// blocks referenced only by a superseded or trashed version, not just
    /// the current one — the contract a future block-store GC must honor.
    #[test]
    fn live_block_hashes_include_superseded_and_trashed_blocks() {
        let state = SyncState::open_in_memory().unwrap();

        let mut v1 = record_with_size("a.txt", 10);
        v1.blocks = vec![BlockInfo { hash: vec![0x01; 32], offset: 0, size: 10 }];
        state.upsert_file_with_origin("group-1", &v1, "device-a").unwrap();
        let mut v2 = record_with_size("a.txt", 20);
        v2.blocks = vec![BlockInfo { hash: vec![0x02; 32], offset: 0, size: 20 }];
        state.upsert_file_with_origin("group-1", &v2, "device-a").unwrap(); // v1 -> superseded

        let mut trashed_content = record_with_size("b.txt", 30);
        trashed_content.blocks = vec![BlockInfo { hash: vec![0x03; 32], offset: 0, size: 30 }];
        state.upsert_file_with_origin("group-1", &trashed_content, "device-a").unwrap();
        state.mark_deleted("group-1", "b.txt", "device-a").unwrap(); // -> trashed

        let live = state.live_block_hashes().unwrap();
        assert!(live.contains(&hex::encode([0x01; 32])), "superseded version's block must be live");
        assert!(live.contains(&hex::encode([0x02; 32])), "current version's block must be live");
        assert!(live.contains(&hex::encode([0x03; 32])), "trashed version's block must be live");
        assert_eq!(live.len(), 3);
    }
}
