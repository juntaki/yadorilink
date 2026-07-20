//! Local daemon state: the per-device file index and folder-link
//! registration with pause/resume. Both live in one SQLite database.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

#[cfg(not(madsim))]
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::change::{
    Change, ChangeAuth, ChangeHash, DeviceId, FileVersion, FolderGroupId, Op, PolicyUnavailable,
    SyncPath, VersionBlock, VersionHash,
};
use crate::compaction::{Checkpoint, CheckpointStore, CompactionDagStore, DeviceFrontierStore};
use crate::dag_store::{self, ChangeEmitter};
use crate::error::SyncError;
use crate::types::{
    BlockInfo, EnrollmentKind, FileRecord, MaterializationPolicy, MaterializationState, RecordKind,
};
use crate::version_vector::VersionVector;

mod rebootstrap_store;

type PathLockKey = (String, String);
type PathLockMap = HashMap<PathLockKey, Weak<tokio::sync::Mutex<()>>>;

/// Per-group startup-readiness barrier. A group whose filesystem watcher was
/// just (re)started has NOT yet finished reconciling its on-disk state against
/// the index — the startup disk scan reads an old whole-index snapshot and
/// batch-commits records derived from it *without* holding each path's
/// `path_lock`. An incoming peer change applied for the same path in that
/// window (which DOES take `path_lock`) would then be silently clobbered when
/// the scan commits its stale-snapshot record, turning what should be a
/// concurrent conflict into a last-writer overwrite. This gate lets peer-apply
/// (and any other post-startup mutator) wait until the group's startup
/// reconciliation has published its results before touching that group's
/// paths. It is per-group: a slow startup for one group never blocks peer
/// apply for an unrelated, already-ready group.
///
/// The gate is a small generational 3-state machine rather than a plain
/// ready flag. Each startup attempt for a group gets a monotonic
/// [`StartupGeneration`]; the gate tracks the *latest* generation and its
/// phase (`Starting` / `Ready` / `Failed`). Two properties fall out of this:
///   - A startup that does NOT complete (panic, task abort, error) transitions
///     the gate to `Failed`, so peer apply fails *closed* (deferred) instead of
///     being admitted over the half-built index — a startup crash can no longer
///     silently open the gate and let peer changes overwrite un-indexed or
///     un-redriven local state.
///   - A completion is honored only when it carries the group's *current*
///     generation, so a stale straggler (an aborted/unlinked old executor, or
///     an earlier overlapping startup) can neither open nor fail a newer
///     startup's barrier.
struct GroupStartupGate {
    inner: std::sync::Mutex<GroupStartupState>,
    notify: tokio::sync::Notify,
}

struct GroupStartupState {
    /// Monotonic per-group startup generation. Each `begin_group_startup`
    /// bumps it, so a completion carrying an older generation is a stale
    /// straggler and is ignored.
    generation: u64,
    phase: GroupStartupPhase,
}

/// The phase of a group's most-recent startup generation.
enum GroupStartupPhase {
    /// Startup reconciliation for the current generation is in progress; peer
    /// apply parks.
    Starting,
    /// Startup reconciliation published its results; peer apply may proceed.
    Ready,
    /// Startup did not complete (panic, abort, or error). Peer apply is refused
    /// (fail-closed) rather than admitted over a half-built index, until a
    /// fresh `begin_group_startup` supersedes this generation and re-runs
    /// startup. The `String` is a human-readable reason for observability.
    Failed(String),
}

/// Identifies one startup attempt for a group. Returned by
/// [`SyncState::begin_group_startup`] and presented back to
/// [`SyncState::mark_group_ready`] / [`SyncState::mark_group_failed`], which
/// ignore it unless it is still the group's latest generation — so a stale
/// completion from a superseded (unlinked / aborted / relinked / overlapping)
/// startup can never open or fail a newer startup's barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupGeneration(u64);

/// Returned by [`SyncState::wait_group_ready`] when the group's latest startup
/// ended in `Failed`. Peer-apply callers must treat this as "do NOT admit the
/// change" (defer / skip), never as permission to apply against the half-built
/// index a failed startup left behind. The deferral is temporary: a subsequent
/// `begin_group_startup` re-runs startup and, on success, releases the waiters.
#[derive(Clone, Debug)]
pub struct StartupFailed {
    pub group_id: String,
    pub reason: String,
}

impl std::fmt::Display for StartupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group {} startup did not complete: {}", self.group_id, self.reason)
    }
}

impl std::error::Error for StartupFailed {}

type LocalChangeAuthProvider =
    dyn Fn(&str) -> Result<ChangeAuth, PolicyUnavailable> + Send + Sync + 'static;
pub type ContentHash = String;
/// A pinned file's `(path, version_seq)`, as recorded by a handoff lease.
pub type PinnedVersion = (String, i64);

/// The fields of a role-loss operation row not already carried by its
/// `(operation_id, group_id)` key.
pub struct RoleLossOperationParams<'a> {
    pub source_device_id: &'a str,
    pub target_device_id: &'a str,
    pub lease_id: Option<&'a str>,
    pub action: RoleLossAction,
    pub local_path: Option<&'a str>,
    pub now_unix: i64,
}

/// The DAG-facing content of a local edit: the ops to sign into the emitted
/// `Change`, and the `FileVersion`s those ops reference (written to
/// `file_versions` in the same transaction as the change/index update).
pub struct ChangeContent<'a> {
    pub ops: Vec<Op>,
    pub versions: &'a [FileVersion],
}

/// every connection made by the pool waits at
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

/// The connection "pool" backing a [`SyncState`].
///
/// A normal build uses r2d2's real `Pool`. Under deterministic simulation
/// (`--cfg madsim`) it uses [`madsim_inline_pool::InlinePool`] instead.
/// r2d2 establishes *every* connection on a background `ScheduledThreadPool`
/// OS thread — its API has no synchronous-establishment path; even
/// `Pool::get` on an empty pool schedules the work on that thread pool and
/// blocks on the result. The simulator forbids real OS threads unless each
/// test opts in with `set_allow_system_thread(true)`, and a long sweep that
/// opens many `SyncState`s sequentially in one process eventually walks into
/// the OS thread-creation ceiling (`EAGAIN`/`WouldBlock`), which caps how
/// many seeds a single test binary can run. Opening connections inline on
/// the calling task removes the only real thread this crate creates under
/// simulation, so the ceiling — and the `set_allow_system_thread` opt-in —
/// are no longer needed and DST sweeps aren't capped. Production is
/// untouched: this whole path is `cfg`-compiled out of every normal build.
#[cfg(madsim)]
type ConnectionPool = madsim_inline_pool::InlinePool;
#[cfg(not(madsim))]
type ConnectionPool = Pool<SqliteConnectionManager>;

/// A drop-in, thread-free stand-in for r2d2's `Pool`, used only under
/// simulation. `get()` opens a fresh `rusqlite::Connection` synchronously on
/// the calling task rather than on a background establishment thread.
/// `SqliteConnectionManager::connect` already runs the same per-connection
/// init (WAL / `busy_timeout` PRAGMAs) and, for a shared-cache in-memory
/// database, keeps one connection alive internally so the database survives
/// between checkouts — so for this crate's purposes the inline pool behaves
/// like the real one (WAL + `busy_timeout` still govern concurrency;
/// connections simply aren't reused, which is immaterial under simulation).
#[cfg(madsim)]
mod madsim_inline_pool {
    use std::ops::{Deref, DerefMut};

    use r2d2::ManageConnection;
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::Connection;

    use crate::error::SyncError;

    pub(super) struct InlinePool {
        manager: SqliteConnectionManager,
    }

    impl InlinePool {
        pub(super) fn new(manager: SqliteConnectionManager) -> Result<Self, SyncError> {
            // Establish one connection up front so a bad path/URI surfaces
            // at open() time (matching r2d2's build-time establishment) and
            // so a shared-cache in-memory database's internal keep-alive
            // connection is primed before the first checkout.
            let _ = manager.connect()?;
            Ok(Self { manager })
        }

        pub(super) fn get(&self) -> Result<InlineConnection, SyncError> {
            Ok(InlineConnection(self.manager.connect()?))
        }
    }

    /// Owns its `Connection` (unlike r2d2's `PooledConnection`, which
    /// returns the connection to the pool on drop) but `Deref`s to it
    /// identically, so every `pool.get()?` call site compiles unchanged.
    pub(super) struct InlineConnection(Connection);

    impl Deref for InlineConnection {
        type Target = Connection;
        fn deref(&self) -> &Connection {
            &self.0
        }
    }

    impl DerefMut for InlineConnection {
        fn deref_mut(&mut self) -> &mut Connection {
            &mut self.0
        }
    }
}

/// Builds the connection pool for a `SyncState`. Production uses r2d2's real
/// pool; under `--cfg madsim` it uses the thread-free inline pool (see
/// [`ConnectionPool`]).
#[cfg(madsim)]
fn madsim_or_default_pool(manager: SqliteConnectionManager) -> Result<ConnectionPool, SyncError> {
    madsim_inline_pool::InlinePool::new(manager)
}

#[cfg(not(madsim))]
fn madsim_or_default_pool(manager: SqliteConnectionManager) -> Result<ConnectionPool, SyncError> {
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
/// migration present in this file up to this point). Version 2 adds the
/// change-history DAG tables (`crate::dag_store::init_dag_schema`), which are
/// created — like `group_policy_watermark` — by a bare `CREATE TABLE IF NOT
/// EXISTS`, so an older database upgrades in place with no data conversion.
/// Version 3 scopes `file_versions` ownership by `(group_id, version_hash)`;
/// opening a v2 database rebuilds that table before advancing the watermark.
/// Version 4 adds the admitted-change/file-version relation used for block
/// authorization and backfills it from retained admitted changes.
/// Version 5 adds `group_block_provenance`, the non-backfilled record of blocks
/// this device actually obtained through each group. Older binaries must not
/// reopen this shape because their serving and custody logic ignores it.
/// Version 6 adds durable per-path duplicate-root recovery progress.
pub const SCHEMA_VERSION: i32 = 6;

/// The persisted anti-rollback watermark for one group's signed policy log:
/// the highest sequence this device has ever verified, its head hash, and the
/// authority-key generation (number of `RotateAuthority` records) at that
/// head. Stored in the local SQLite database so the guarantee survives a
/// daemon restart — the in-memory verified/stale policy maps are lost on
/// restart, which is exactly the window a replayed *older* (but still
/// signature-valid) chain would exploit to hide a later revoke. The watermark
/// only ever moves forward; the daemon rejects any snapshot that would lower
/// it. The 32-byte hashes are opaque to this crate, which only stores and
/// returns them; the daemon's `change_policy` verifier owns their meaning.
///
/// `authority_key_fingerprint` is the SHA-256 of the group's authority public
/// key at that head. It pins WHICH trust root was verified, not just how many
/// times it rotated (`authority_key_generation`), so the daemon can catch a
/// fork that swaps the authority key without advancing the generation, and an
/// audit can name the exact key that was trusted. It is `None` for a row
/// written before this column existed (see the read path); such a row is
/// treated as "fingerprint unknown", not as a fork, and is backfilled from the
/// next verified snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWatermark {
    pub highest_verified_seq: u64,
    pub highest_verified_head: [u8; 32],
    pub authority_key_generation: u64,
    pub authority_key_fingerprint: Option<[u8; 32]>,
}

/// One journaled local edit awaiting durable processing into the index +
/// change DAG — see the `local_dirty_paths` table. `change_kind` is the
/// serialized [`crate::watcher::FsChangeKind`] (`"created_or_modified"` /
/// `"removed"`) of the most recent watcher event for the path, and
/// `observed_at_unix_nanos` its observation time, so a startup/retry re-drive
/// can reconstruct the exact `FsChangeEvent` the debounce executor would have
/// processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyPath {
    pub path: String,
    pub change_kind: String,
    pub observed_at_unix_nanos: i64,
    pub attempts: u32,
}

/// One restore whose replacement file and index update have not both been
/// durably committed yet. The intended new record is persisted before the
/// filesystem rename so startup recovery can finish the exact same version
/// instead of manufacturing a second version-vector increment.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreOperation {
    pub operation_id: String,
    pub group_id: String,
    pub path: String,
    pub target_version_seq: i64,
    pub expected_current_version_seq: Option<i64>,
    pub state: RestoreOperationState,
    pub record: FileRecord,
    pub origin_device_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RestoreCommitOutcome {
    Committed(FileRecord),
    Missing,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOperationState {
    Prepared,
    DiskCommitted,
}

impl RestoreOperationState {
    fn as_db_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::DiskCommitted => "disk_committed",
        }
    }

    fn from_db_str(value: &str) -> Result<Self, SyncError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "disk_committed" => Ok(Self::DiskCommitted),
            other => {
                Err(SyncError::CorruptState(format!("unknown restore operation state: {other}")))
            }
        }
    }
}

fn restore_operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RestoreOperation> {
    let version_json: String = row.get(7)?;
    let blocks_json: String = row.get(8)?;
    let counters = serde_json::from_str(&version_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let blocks = serde_json::from_str(&blocks_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let state_text: String = row.get(4)?;
    let state = RestoreOperationState::from_db_str(&state_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let path: String = row.get(2)?;
    Ok(RestoreOperation {
        operation_id: row.get(0)?,
        group_id: row.get(1)?,
        path: path.clone(),
        target_version_seq: row.get(3)?,
        expected_current_version_seq: row.get(10)?,
        state,
        record: FileRecord {
            path,
            size: row.get::<_, i64>(5)? as u64,
            mtime_unix_nanos: row.get(6)?,
            version: VersionVector::from_counters(counters),
            blocks,
            deleted: false,
        },
        origin_device_id: row.get(9)?,
    })
}

pub struct SyncState {
    /// was a single `Mutex<Connection>` — every
    /// call, including pure reads, serialized through one lock and one
    /// SQLite connection. Now each call checks out its own pooled
    /// connection (`r2d2` + `r2d2_sqlite`) against a WAL-mode database,
    /// so multiple readers (and a reader alongside a writer) proceed
    /// concurrently instead of blocking on each other — SQLite's own WAL
    /// concurrency model, not an in-process lock, now governs access.
    /// Writers still serialize against each other (SQLite allows only one
    /// writer at a time even in WAL mode), handled by `BUSY_TIMEOUT`
    /// rather than an in-process mutex.
    pool: ConnectionPool,
    /// per-`(group_id, path)` locks serializing local-change
    /// indexing (`LocalChangeProcessor::process_event`) against peer
    /// reconciliation (`PeerSyncSession::reconcile_one_file`) for the
    /// same path — see `path_lock`'s doc comment for the race this
    /// closes. A `HashMap` of per-path `tokio::sync::Mutex` weak references
    /// (not a single process-wide lock) means unrelated paths never contend
    /// with each other. The registry lazily removes
    /// expired entries, so deleted/renamed paths do not accumulate forever
    /// while every concurrent user of a live path still shares one lock.
    /// `tokio::sync::Mutex` specifically (not
    /// `std::sync::Mutex`) because `reconcile_one_file` needs to hold the
    /// guard across `.await` points (a block fetch can take real time) —
    /// a `std::sync::MutexGuard` isn't `Send`, which broke `tokio::spawn`
    /// on the per-connection message-handling task the first time this
    /// was tried with a blocking mutex here. The registry map itself
    /// (this outer `Mutex`) stays `std::sync::Mutex`: it's only ever held
    /// briefly to look up/insert an entry, never across an await.
    path_locks: Mutex<PathLockMap>,
    /// Per-`group_id` startup-readiness barriers (see `GroupStartupGate`).
    /// Absent entry = never entered startup, treated as ready. A `std::sync`
    /// map holding `Arc`s of the gate; the async wait happens on the cloned
    /// `Arc`'s `Notify`, never while this registry lock is held.
    group_startup_gates: Mutex<HashMap<String, Arc<GroupStartupGate>>>,
    /// Supplies the signed policy-log coordinates stamped on locally emitted
    /// DAG changes. Daemon builds set this from their netmap policy state;
    /// tests and standalone sync-core users fall back to `ChangeAuth::PLACEHOLDER`.
    local_change_auth_provider: Mutex<Option<Arc<LocalChangeAuthProvider>>>,
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
    // TABLE... ADD COLUMN... DEFAULT...`, paired with that same
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
/// The first round trip below is an `UPDATE... RETURNING`: it flips
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

/// The local-only per-file metadata columns a local content emission writes
/// alongside its `FileRecord`. Folded into the emitting transaction (rather
/// than applied as separate post-commit `set_record_kind`/`set_symlink_*`/
/// `set_exec_bit` updates) so the materialized index row can never lag the
/// `FileVersion` the emitted change carries across a crash between the commit
/// and the setters. The kind/target/exec-bit values mirror exactly the
/// [`crate::change::FileMeta`] the emitted `FileVersion` carries;
/// `symlink_out_of_root` is an additional purely-local classification never
/// sent on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileMetaColumns {
    pub record_kind: RecordKind,
    pub symlink_target: Option<String>,
    pub symlink_out_of_root: bool,
    pub exec_bit: bool,
}

/// Writes a path's local metadata columns (record kind, symlink target /
/// out-of-root flag, exec bit) inside `tx`, the SAME transaction that just
/// wrote its `current` row via [`upsert_file_in_tx`]. This is the atomic,
/// in-transaction counterpart to the standalone `set_record_kind`/
/// `set_symlink_target`/`set_symlink_out_of_root`/`set_exec_bit` setters — it
/// must run strictly after `upsert_file_in_tx` (these are `UPDATE`s and need
/// the row to already exist), so the index columns and the emitted change's
/// `FileVersion` commit as one unit.
fn apply_local_meta_columns_in_tx(
    tx: &rusqlite::Transaction,
    group_id: &str,
    path: &str,
    meta: &LocalFileMetaColumns,
) -> Result<(), SyncError> {
    tx.execute(
        "UPDATE files SET record_kind = ?1, symlink_target = ?2, symlink_out_of_root = ?3, exec_bit = ?4
         WHERE group_id = ?5 AND path = ?6 AND state = 'current'",
        rusqlite::params![
            meta.record_kind.as_db_str(),
            meta.symlink_target,
            meta.symlink_out_of_root as i64,
            meta.exec_bit as i64,
            group_id,
            path,
        ],
    )?;
    Ok(())
}

/// One half of the fix for the `SQLITE_LOCKED: database table is locked`
/// failures `upsert_file_in_tx`'s doc comment describes (found via a
/// `tracing_subscriber`-instrumented rerun of a failing `yadorilink-daemon`
/// integration test — the error was otherwise only logged as a `tracing::
/// warn!` deep inside `PeerSyncSession::reconcile_files`, never surfaced as
/// a panic on its own). `rusqlite::Connection::transaction` opens a
/// `DEFERRED` transaction by default, which only acquires SQLite's write
/// (`RESERVED`) lock lazily, on the *first write statement actually
/// executed inside it* — not at `BEGIN` time. `upsert_file_in_tx`'s first
/// statement (`UPDATE... RETURNING`) is a read-then-write, so under this
/// crate's connection pool (many pooled connections concurrently
/// reconciling different files, per `PeerSyncSession::reconcile_files`'s
/// `MAX_CONCURRENT_RECONCILES` concurrent tasks) a deferred transaction's
/// `SHARED`-to-`RESERVED` lock upgrade can lose a race against another
/// pooled connection's concurrent read — SQLite's classic deferred-
/// transaction lock-upgrade pitfall. Opening the transaction `IMMEDIATE`
/// instead acquires the `RESERVED` write lock immediately at `BEGIN`,
/// closing that specific upgrade-race window. The old, pre-this-change
/// `upsert_file` never hit any of this because it was a single `execute`
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
    /// enabled — WAL lets readers proceed
    /// without blocking behind the single writer SQLite allows at a
    /// time, unlike the default rollback-journal mode. Every pooled
    /// connection additionally gets `BUSY_TIMEOUT` so two of this
    /// process's own writers waiting on each other resolve by retrying,
    /// not erroring, and `synchronous = FULL` so a committed index
    /// transaction survives an OS crash or power loss.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SyncError> {
        let manager = SqliteConnectionManager::file(path.as_ref()).with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            // journal_mode is itself a query (it returns the mode that
            // was actually applied), hence `pragma_update_and_check`
            // rather than `pragma_update`.
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
            // This index is the durable source of truth for what content
            // exists, so it must not depend on SQLite's compile-time default
            // for `synchronous` (which is only NORMAL under WAL — durable
            // across an application crash but able to lose the last committed
            // transaction on an OS crash or power loss). FULL fsyncs the WAL
            // before reporting a commit, closing that window. Set on every
            // pooled connection (like `busy_timeout` above), since the pragma
            // is per-connection, not stored in the database file.
            conn.pragma_update(None, "synchronous", "FULL")?;
            Ok(())
        });
        let pool = madsim_or_default_pool(manager)?;
        let conn = pool.get()?;
        Self::init(&conn)?;
        drop(conn);
        Ok(Self {
            pool,
            path_locks: Mutex::new(HashMap::new()),
            group_startup_gates: Mutex::new(HashMap::new()),
            local_change_auth_provider: Mutex::new(None),
        })
    }

    /// Opens an in-memory database, pooled just like the file-backed case
    /// . Plain SQLite `:memory:` databases are
    /// private to the single connection that opened them, so naively
    /// pooling one would give each checkout its own empty database and
    /// silently break every write-then-read call pattern. `r2d2_sqlite`'s
    /// `SqliteConnectionManager::memory` avoids that: it opens
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
        Ok(Self {
            pool,
            path_locks: Mutex::new(HashMap::new()),
            group_startup_gates: Mutex::new(HashMap::new()),
            local_change_auth_provider: Mutex::new(None),
        })
    }

    pub fn set_local_change_auth_provider(&self, provider: Arc<LocalChangeAuthProvider>) {
        *self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()) = Some(provider);
    }

    /// The authorization stamp for a change this device is about to emit into
    /// `group_id`, or [`PolicyUnavailable`] if the group's policy is stale and
    /// no real stamp can be produced right now.
    ///
    /// A daemon-installed provider decides: `Ok(auth)` carrying the group's
    /// current authorization context, or `Err(PolicyUnavailable)` when the
    /// group's most recent policy snapshot failed verification (so it is stale
    /// and inbound admission for it fails closed). Standalone sync-core callers
    /// — tests and tools with no policy infrastructure wired in — have no
    /// provider installed and keep using the all-zero placeholder, the
    /// pre-policy compatibility stamp peers still accept while no policy log
    /// exists on either side.
    fn local_emission_auth(&self, group_id: &str) -> Result<ChangeAuth, PolicyUnavailable> {
        match self.local_change_auth_provider.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            Some(provider) => provider(group_id),
            None => Ok(ChangeAuth::PLACEHOLDER),
        }
    }

    /// returns the shared lock for `(group_id, path)`, creating it
    /// on first use. Lock it (`.lock.await`) and hold the guard for the
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
        let key = (group_id.to_string(), path.to_string());
        let mut locks = self.path_locks.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        // A path can disappear permanently after delete/rename. Prune stale
        // weak entries while the short registry lock is already held so a
        // stream of unique paths cannot grow this map without bound.
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn startup_gate(&self, group_id: &str) -> Option<Arc<GroupStartupGate>> {
        self.group_startup_gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
            .cloned()
    }

    /// Opens a fresh startup generation for `group_id`: bumps the group's
    /// monotonic generation and (re-)closes its gate to `Starting`, returning
    /// the new [`StartupGeneration`]. Call this *synchronously*, before spawning
    /// the group's startup/scan task and before any peer session that could
    /// apply a change for the group can run, so the closed gate is observed by
    /// every peer-apply path.
    ///
    /// Re-entry (a re-link, a watcher restart, or a startup retry) *supersedes*
    /// any prior generation — including a `Failed` one — with a new `Starting`
    /// generation. This is the recovery trigger: it clears a previous failure
    /// and re-runs startup, so a `Failed` gate never wedges peer apply forever.
    /// Any straggling completion from the superseded generation is thereafter a
    /// no-op (see `mark_group_ready` / `mark_group_failed`).
    pub fn begin_group_startup(&self, group_id: &str) -> StartupGeneration {
        let mut gates =
            self.group_startup_gates.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match gates.get(group_id) {
            Some(gate) => {
                let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
                state.generation += 1;
                state.phase = GroupStartupPhase::Starting;
                StartupGeneration(state.generation)
            }
            None => {
                gates.insert(
                    group_id.to_string(),
                    Arc::new(GroupStartupGate {
                        inner: std::sync::Mutex::new(GroupStartupState {
                            generation: 0,
                            phase: GroupStartupPhase::Starting,
                        }),
                        notify: tokio::sync::Notify::new(),
                    }),
                );
                StartupGeneration(0)
            }
        }
    }

    /// Opens `group_id`'s startup gate for `generation` and wakes every waiter.
    /// Called once the group's startup reconciliation (disk scan, initial
    /// import, dirty-journal redrive) has committed its results, so peer apply
    /// for the group may now proceed against an up-to-date index.
    ///
    /// A **no-op unless `generation` is still the group's latest**: a stale
    /// completion from a superseded startup (an aborted/unlinked old executor,
    /// or an earlier overlapping startup) must never open a newer generation's
    /// barrier. Also a no-op for a group that never entered startup.
    pub fn mark_group_ready(&self, group_id: &str, generation: StartupGeneration) {
        if let Some(gate) = self.startup_gate(group_id) {
            let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
            if state.generation != generation.0 {
                return;
            }
            state.phase = GroupStartupPhase::Ready;
            drop(state);
            gate.notify.notify_waiters();
        }
    }

    /// Records that `group_id`'s startup for `generation` did NOT complete
    /// (panic, task abort, or error): transitions the gate to `Failed` and
    /// wakes waiters, which then fail *closed* with [`StartupFailed`] rather
    /// than being admitted over the half-built index the failed startup left
    /// behind.
    ///
    /// Like `mark_group_ready`, a **no-op unless `generation` is still the
    /// group's latest** — so a stale abort's guard-drop cannot fail a newer
    /// generation. Recovery is a subsequent `begin_group_startup`, which
    /// supersedes the failure with a fresh `Starting` generation and re-runs
    /// startup. Local edits are unaffected: they live in the index and the
    /// dirty-path journal, independent of this gate, so a failure only *defers*
    /// peer apply, it never drops a local change.
    pub fn mark_group_failed(
        &self,
        group_id: &str,
        generation: StartupGeneration,
        reason: impl Into<String>,
    ) {
        if let Some(gate) = self.startup_gate(group_id) {
            let mut state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
            if state.generation != generation.0 {
                return;
            }
            state.phase = GroupStartupPhase::Failed(reason.into());
            drop(state);
            gate.notify.notify_waiters();
        }
    }

    /// Decides whether peer apply may proceed for a group that has NO startup
    /// gate registered, by asking why it has none.
    ///
    /// Two very different states used to share the `Ok(())` answer. A group
    /// with no link on this device has no startup to wait for and never will —
    /// admitting it is correct, and it is the state during the window between
    /// `add_link` committing the row and `start_link_watch` arming the gate.
    /// But a group that HAS a live link and still has no gate is a link whose
    /// startup never got off the ground: the folder was not scanned this boot,
    /// while the row stays live so the peer path still resolves a root for it.
    /// Admitting that one lets a peer change overwrite local bytes that were
    /// never indexed — with no conflict copy, because the local content never
    /// became a change the DAG could see.
    ///
    /// Deferring the harmless case costs nothing: `StartupFailed` makes the
    /// caller leave the change for re-delivery rather than dropping it, and the
    /// gate appears moments later when the watcher starts.
    ///
    /// An unreadable link table fails closed. Deferring a change we may later
    /// apply is recoverable; applying one over content we could not account for
    /// is not.
    fn absent_gate_verdict(&self, group_id: &str) -> Result<(), StartupFailed> {
        match self.has_live_link_for_group(group_id) {
            Ok(false) => Ok(()),
            Ok(true) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason:
                    "link is live but its startup never registered a gate (watcher start failed \
                         or has not run yet); deferring peer apply until startup completes"
                        .to_string(),
            }),
            Err(e) => Err(StartupFailed {
                group_id: group_id.to_string(),
                reason: format!(
                    "cannot read the link table to decide whether startup is owed: {e}"
                ),
            }),
        }
    }

    /// Whether this device holds a live (non-orphaned) link for `group_id`.
    /// Scoped to one group rather than reusing `list_links` because this runs
    /// on the peer-apply path, once per change batch.
    ///
    /// Counts rather than `EXISTS`: `EXISTS` reads `true` for one live link and
    /// for two alike, so it cannot see the one state that must not proceed. Two
    /// or more is [`SyncError::AmbiguousLink`], which the caller
    /// (`absent_gate_verdict`) already maps to `StartupFailed` under its own
    /// "an unreadable link table fails closed" rule — the change defers rather
    /// than applying against a root we cannot name.
    fn has_live_link_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let live: i64 = conn.query_row(
            "SELECT COUNT(*) FROM links WHERE group_id = ?1 AND orphaned = 0",
            [group_id],
            |r| r.get(0),
        )?;
        Ok(live != 0)
    }

    /// Awaits `group_id`'s startup gate. Returns `Ok(())` once the latest
    /// startup reached `Ready`, or immediately if the group has no link on this
    /// device to run a startup for. Returns `Err(StartupFailed)` — fail-closed — if the latest
    /// startup ended in `Failed`; the caller must then DEFER/skip the change,
    /// not apply it. Holds no lock while parked (the registry lock is released
    /// before awaiting), and must be called *before* acquiring any `path_lock`,
    /// so it can never deadlock against the startup writer.
    pub async fn wait_group_ready(&self, group_id: &str) -> Result<(), StartupFailed> {
        let Some(gate) = self.startup_gate(group_id) else {
            return self.absent_gate_verdict(group_id);
        };
        loop {
            // Arm the notification *before* reading state so a mark that lands
            // between the read and the await is not lost (Notify's documented
            // lost-wakeup-free pattern).
            let notified = gate.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = gate.inner.lock().unwrap_or_else(|p| p.into_inner());
                match &state.phase {
                    GroupStartupPhase::Ready => return Ok(()),
                    GroupStartupPhase::Failed(reason) => {
                        return Err(StartupFailed {
                            group_id: group_id.to_string(),
                            reason: reason.clone(),
                        });
                    }
                    GroupStartupPhase::Starting => {}
                }
            }
            notified.await;
        }
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
        // expressible as an `ALTER TABLE... ADD COLUMN` — SQLite has no
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

            CREATE TABLE IF NOT EXISTS duplicate_recovery_paths (
                group_id TEXT NOT NULL,
                path     TEXT NOT NULL,
                PRIMARY KEY (group_id, path)
            );

            -- One outstanding local link with an unconfirmed coordination-plane
            -- activation -- the crash-safety net for a create/join whose local
            -- link is already committed but whose matching server-side
            -- activation was never confirmed (the caller was killed in that
            -- exact window). Keyed by `operation_id` (idempotent: re-recording after a retry
            -- that reaches the same point again is a plain overwrite, not a
            -- duplicate entry). Lives in the same database as `links` so
            -- `add_link_with_pending_enrollment` can write both in one
            -- transaction -- a local link is never committed without a durable
            -- trace of the coordination-side enrollment it depends on.
            CREATE TABLE IF NOT EXISTS pending_enrollments (
                operation_id TEXT PRIMARY KEY,
                kind         TEXT NOT NULL,
                group_id     TEXT NOT NULL,
                device_id    TEXT NOT NULL,
                local_path   TEXT NOT NULL
            );

            -- Anti-rollback watermark for each group's signed policy log (see
            -- `PolicyWatermark`). One row per group; the daemon advances it
            -- only forward and rejects any snapshot that would move it back,
            -- so a replayed older-but-valid chain cannot survive a restart. A
            -- new additive table, so a bare `CREATE TABLE IF NOT EXISTS` is the
            -- whole migration, like `files`/`links` themselves.
            CREATE TABLE IF NOT EXISTS group_policy_watermark (
                group_id                  TEXT PRIMARY KEY,
                highest_verified_seq      INTEGER NOT NULL,
                highest_verified_head     BLOB NOT NULL,
                authority_key_generation  INTEGER NOT NULL,
                -- SHA-256 of the authority public key at that head. NULLable
                -- because a database created before this column existed keeps
                -- its rows with no fingerprint (see the lightweight migration
                -- below); the read path maps NULL to `None` and the verifier
                -- treats that as "unknown", never as a fork.
                authority_key_fingerprint BLOB
            );
            -- Durable journal of local paths detected as changed but not yet
            -- fully processed into the index + change DAG. A path is recorded
            -- here *before* the read/blockify/put/index+DAG step runs and only
            -- deleted once that step commits, so a crash, restart, or a
            -- multi-second block-store fault (disk-full / EIO) mid-processing
            -- can never silently drop an already-detected local edit: the row
            -- survives and the daemon re-drives it (startup rescan + retry).
            -- One row per `(group_id, path)`; a fresher watcher event for the
            -- same path supersedes `change_kind`/`observed_at_unix_nanos` (via
            -- `INSERT ... ON CONFLICT`) rather than accumulating history, while
            -- `first_seen_unix_nanos` records when the divergence was first
            -- noticed and `attempts`/`last_error` accrue across retries for
            -- diagnosis. A new additive table, so a bare `CREATE TABLE IF NOT
            -- EXISTS` is the whole migration, like `files`/`links` themselves.
            CREATE TABLE IF NOT EXISTS local_dirty_paths (
                group_id               TEXT NOT NULL,
                path                   TEXT NOT NULL,
                change_kind            TEXT NOT NULL,
                first_seen_unix_nanos  INTEGER NOT NULL,
                observed_at_unix_nanos INTEGER NOT NULL,
                attempts               INTEGER NOT NULL DEFAULT 0,
                last_error             TEXT,
                PRIMARY KEY (group_id, path)
            );

            -- Restore spans an atomic filesystem rename and a SQLite index
            -- transaction. Persist the intended new current row before the
            -- rename; completing the index upsert deletes this row in the
            -- same transaction, making startup reconciliation idempotent.
            CREATE TABLE IF NOT EXISTS restore_operations (
                operation_id      TEXT PRIMARY KEY,
                group_id          TEXT NOT NULL,
                path              TEXT NOT NULL,
                target_version_seq INTEGER NOT NULL,
                expected_current_version_seq INTEGER,
                state             TEXT NOT NULL,
                size              INTEGER NOT NULL,
                mtime_unix_nanos  INTEGER NOT NULL,
                version_json      TEXT NOT NULL,
                blocks_json       TEXT NOT NULL,
                origin_device_id  TEXT NOT NULL,
                created_at_unix_nanos INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_restore_operations_path
                ON restore_operations(group_id, path);

            -- A coordination-worker-issued full-replica-handoff lease this
            -- device (as the handoff TARGET) is currently holding, pinning the
            -- exact `(path, version_seq)` rows its own local readiness check
            -- verified at request time against this device's retention sweep
            -- (`expire_superseded_and_trashed_versions`) until the source's
            -- role-loss commit confirms the lease or it is released/expires.
            -- See `HandoffLease`'s doc comment for the full lifecycle. One row
            -- per outstanding lease; a device normally holds at most one
            -- lease per `group_id` at a time, but this is not enforced here
            -- (a stale, not-yet-swept row for an old lease is simply ignored
            -- once its `state`/`expires_at_unix` no longer qualify it as
            -- pinning). A new additive table, so a bare `CREATE TABLE IF NOT
            -- EXISTS` is the whole migration, like `local_dirty_paths` above.
            CREATE TABLE IF NOT EXISTS handoff_leases (
                lease_id             TEXT PRIMARY KEY,
                group_id             TEXT NOT NULL,
                root_digest          BLOB NOT NULL,
                state                TEXT NOT NULL DEFAULT 'provisional',
                pinned_versions_json TEXT NOT NULL,
                created_at_unix      INTEGER NOT NULL,
                expires_at_unix      INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_handoff_leases_group_id ON handoff_leases(group_id);

            -- A durable journal of an in-flight full-replica role-loss
            -- operation (demote/unlink) this device is driving as the
            -- SOURCE device: the coordination-worker role-loss commit
            -- (`commit_handoff_role_loss`) and this device's own matching
            -- local policy/link change are two separate commits, and a
            -- crash -- or a local failure landing AFTER the Worker commit
            -- already succeeded -- must not be left as a silent split
            -- state (Worker thinks this device demoted; local storage
            -- still thinks it's eager). This row is written BEFORE the
            -- Worker commit and only removed once the operation's outcome
            -- is fully settled, one way or the other -- see
            -- `RoleLossOperation`'s doc comment for the full state
            -- machine. A new additive table, so a bare `CREATE TABLE IF
            -- NOT EXISTS` is the whole migration, like `handoff_leases`
            -- above.
            CREATE TABLE IF NOT EXISTS role_loss_operations (
                operation_id     TEXT PRIMARY KEY,
                group_id         TEXT NOT NULL,
                source_device_id TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                lease_id         TEXT,
                worker_membership_generation INTEGER,
                action           TEXT NOT NULL,
                state            TEXT NOT NULL,
                local_path       TEXT,
                attempts         INTEGER NOT NULL DEFAULT 0,
                created_at_unix  INTEGER NOT NULL,
                updated_at_unix  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_role_loss_operations_state
                ON role_loss_operations(state);
            -- Force overrides must remain visible after daemon restart until
            -- a later positive whole-group durability check clears them.
            CREATE TABLE IF NOT EXISTS durability_unknown_latches (
                group_id TEXT PRIMARY KEY
            );
            -- Durable journal of an in-flight materialization write: one row
            -- per `(group_id, path)` whose on-disk content a
            -- temp-write-then-rename is CURRENTLY producing but has not yet
            -- finished and fsynced into place. The row is written BEFORE that
            -- write begins and deleted only AFTER it completes, so startup
            -- repair can tell a genuine crash-mid-materialization (intent
            -- still present => the indexed blocks must be re-assembled onto
            -- disk) apart from a file the user deleted or renamed while the
            -- daemon was stopped (no intent => a real offline deletion that
            -- must propagate as a tombstone, never be silently reconstructed
            -- from the index). `PRAGMA synchronous = FULL` (set at open) makes
            -- the intent durable before the disk write starts, which is what
            -- makes the disambiguation crash-safe. One row per
            -- `(group_id, path)`; a fresh write for the same path overwrites
            -- the previous intent via `INSERT ... ON CONFLICT`. A new additive
            -- table, so a bare `CREATE TABLE IF NOT EXISTS` is the whole
            -- migration, like `local_dirty_paths`/`restore_operations` above.
            CREATE TABLE IF NOT EXISTS materialization_intents (
                group_id              TEXT NOT NULL,
                path                  TEXT NOT NULL,
                target_version_hash   BLOB NOT NULL,
                created_at_unix_nanos INTEGER NOT NULL,
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
            "ALTER TABLE role_loss_operations ADD COLUMN lease_id TEXT",
            "ALTER TABLE role_loss_operations ADD COLUMN worker_membership_generation INTEGER",
            "ALTER TABLE links ADD COLUMN materialization_policy TEXT NOT NULL DEFAULT 'eager'",
            "ALTER TABLE links ADD COLUMN max_local_size_bytes INTEGER",
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
            // `materialization_policy` above: a per-link
            // column on `links`, not a per-file one, since this is a
            // device-local link-wide policy decision, not something that
            // varies symlink-by-symlink.
            "ALTER TABLE links ADD COLUMN windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0",
            // Set once a pending enrollment's `reconcile` pass confirms the
            // coordination-side group/ACL row this link depends on is
            // permanently gone (never just a transient failure) --
            // distinct from `paused`, which is a reversible, user-chosen
            // sync gate. An orphaned link's on-disk files are never
            // touched; only its own further participation in sync is
            // affected. Defaults to 0 (not orphaned) for every
            // pre-existing row, the same "no behavior change without
            // opt-in" guarantee as every other column in this list.
            "ALTER TABLE links ADD COLUMN orphaned INTEGER NOT NULL DEFAULT 0",
            // Opaque per-link identity nonce for this link's sync root, mirrored
            // into a marker file inside the root itself
            // (`crate::root_identity`). The pair is what lets a scan tell "this
            // folder is empty" from "this folder's filesystem is not mounted" --
            // an unmounted volume leaves the bare mountpoint directory behind,
            // which every existence check happily accepts and every scan then
            // reads as "the user deleted everything".
            //
            // NULLable with no default, and that NULL is load-bearing rather
            // than incidental: it is precisely the "this link predates root
            // identity, adopt it on first boot" signal. Defaulting it to a
            // constant would be actively wrong -- a token shared by every link
            // identifies nothing -- and minting one here is impossible, since a
            // migration cannot know whether the root it would be vouching for is
            // currently mounted. Backfill therefore happens in
            // `VerifiedRoot::open`, which can look at the folder.
            "ALTER TABLE links ADD COLUMN root_token TEXT",
            // Set on the SURVIVING link when a group is recovered out of the
            // two-live-roots state by unlinking one of its folders. `DELETE FROM
            // files` is only ever keyed by path, so unlinking a folder leaves
            // that folder's rows in the group's index -- and the survivor's next
            // authoritative full scan would read every one of them as "indexed
            // but not on my disk" and tombstone it to every device. That would
            // make the remedy this fix instructs the user to perform ("unlink
            // the other folder") destroy the very files it was meant to save.
            //
            // While set, the survivor's full scan is ADDITIVE: it indexes what
            // it finds and emits no deletions, so the departed root's paths
            // survive and can hydrate in from a peer that still holds them. The
            // flag clears after one clean full scan. Worst case (a single-device
            // group where no peer holds the content) is a stall, which is
            // recoverable -- the user still has the folder on disk -- rather
            // than a delete, which is not.
            //
            // Defaults to 0 for every pre-existing row: no behavior change
            // without the recovery that sets it, the same guarantee as every
            // other column in this list.
            "ALTER TABLE links ADD COLUMN suppress_tombstones_until_scan INTEGER NOT NULL DEFAULT 0",
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
            // Authority-key fingerprint on the policy watermark. Added
            // NULLable with no default, so every pre-existing watermark row
            // keeps a NULL fingerprint until the next verified snapshot
            // backfills it. A NULL must NOT read as a fork — the verifier
            // treats "no stored fingerprint" as unknown and accepts, matching
            // the "no behavior change without opt-in" guarantee of every
            // column above: an already-trusted chain stays trusted across the
            // upgrade.
            "ALTER TABLE group_policy_watermark ADD COLUMN authority_key_fingerprint BLOB",
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

        // A group has at most ONE live link. Enforced in the schema itself, not
        // only in Rust: the index is group-scoped and path-relative while every
        // scan is root-scoped and authoritative, so two live roots on one group
        // make each root's scan read the other's files as deleted and tombstone
        // them — signed changes that ride the change-DAG to every device. This
        // layer survives a writer that never reads the Rust chokepoint, a raw
        // `sqlite3` session, and a second process.
        //
        // A partial UNIQUE index on `group_id` would be the obvious spelling and
        // is WRONG twice over: `INSERT OR REPLACE` against a UNIQUE index does
        // not error, it DELETES the conflicting row (silent link loss), and the
        // index cannot even be CREATEd on a database that already holds a
        // duplicate — i.e. it fails exactly on the installs that need it. A
        // BEFORE trigger raising ABORT installs cleanly on such a database,
        // leaves both rows intact and visible for recovery, and overrides
        // `INSERT OR REPLACE` rather than being subverted by it.
        //
        // Placed after the `orphaned` ALTER above, and kept there. SQLite
        // resolves a trigger's column references when the trigger FIRES, not
        // when it is created (measured), so this would in fact tolerate being
        // created before that ALTER — every statement in `init` runs before any
        // caller can insert. That tolerance is a coincidence of ordering rather
        // than a guarantee, and it fails loudly and totally if the column is
        // never added at all ("no such column: NEW.orphaned", on every insert),
        // so this stays downstream of the column it depends on, where the
        // dependency is visible.
        //
        // The UPDATE trigger's `WHEN` is scoped to the 0 ← 1 un-orphan
        // transition rather than to `NEW.orphaned = 0` alone. Unscoped, it
        // aborts ordinary pause/policy/token writes on an
        // already-duplicated database — turning a rare data-loss bug into a
        // common "cannot use the app" bug. Transition-scoped, every legitimate
        // update passes and the un-orphan hole still closes. That hole is real
        // and not theoretical: `INSERT OR REPLACE` silently flipped `orphaned`
        // 1 → 0, which is why this trigger exists alongside the INSERT one.
        conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_insert \
             BEFORE INSERT ON links \
             WHEN NEW.orphaned = 0 AND EXISTS ( \
                 SELECT 1 FROM links \
                 WHERE group_id = NEW.group_id AND orphaned = 0 \
                   AND local_path <> NEW.local_path) \
             BEGIN \
                 SELECT RAISE(ABORT, \
                     'links: group already has a live link at a different local_path'); \
             END; \
             CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_unorphan \
             BEFORE UPDATE ON links \
             WHEN NEW.orphaned = 0 AND OLD.orphaned = 1 AND EXISTS ( \
                 SELECT 1 FROM links \
                 WHERE group_id = NEW.group_id AND orphaned = 0 \
                   AND local_path <> NEW.local_path) \
             BEGIN \
                 SELECT RAISE(ABORT, \
                     'links: un-orphaning would give this group a second live link'); \
             END;",
        )?;

        // Change-history DAG tables live in this same database so a change
        // append and the index mutation it justifies commit in one
        // transaction. New tables only, so this is a pure `CREATE TABLE IF
        // NOT EXISTS` migration with no data conversion — safe and
        // idempotent on both a fresh and an already-upgraded database.
        crate::dag_store::init_dag_schema(conn)?;
        rebootstrap_store::init_rebootstrap_schema(conn)?;

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

    // --- File index ---

    /// Plain, origin-agnostic upsert — delegates to
    /// `upsert_file_with_origin` with an empty (unknown) origin. Kept for
    /// every existing caller (overwhelmingly test fixtures that don't care
    /// who "wrote" a record) so this signature never needed to change; see
    /// `upsert_file_with_origin`'s doc comment for the real semantics and
    /// which two production call sites use it directly instead.
    pub fn upsert_file(&self, group_id: &str, record: &FileRecord) -> Result<(), SyncError> {
        self.upsert_file_with_origin(group_id, record, "")
    }

    /// The version-retaining write path — see the free function `upsert_file_in_tx` (this
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
    /// transaction (batch processing) — used by
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

    // --- Change-history dual-write ---
    //
    // These mirror the plain index writes above, but additionally append a
    // signed change to the history DAG in the *same* transaction, so the
    // materialized index and the change that justifies it can never diverge
    // across a crash. The change's parents are the group's current heads, so
    // each accepted local mutation narrows the head set to itself. Callers
    // build the ops (a create/update op needs the file's content version
    // hash, which the caller already has from chunking); this layer owns only
    // the atomic append.
    //
    // Every local emission below stamps the change with the group's current
    // authorization context (membership sequence, epoch, and pinned policy-log
    // head) when the daemon has supplied one. Standalone sync-core callers keep
    // using the all-zero placeholder for compatibility.

    /// Upserts one record and appends the signed change describing it, in one
    /// transaction. Returns the appended change's hash. `versions` are the
    /// content-addressed file versions the change's ops reference (empty for a
    /// pure delete); each is persisted in the same transaction, so a change and
    /// the version bytes needed to materialize it on any receiver can never
    /// diverge across a crash. `meta`, when `Some`, is the record's local
    /// metadata (record kind, symlink target/out-of-root, exec bit), written
    /// in the SAME transaction so the index row's metadata columns can never
    /// lag the `FileVersion`/DAG change across a crash between the commit and a
    /// separate post-commit setter; pass `None` to leave those columns as
    /// `upsert_file_in_tx` left them.
    pub fn upsert_file_emitting_change(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        content: ChangeContent<'_>,
        meta: Option<&LocalFileMetaColumns>,
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        // Resolve the authorization stamp *before* opening the write
        // transaction. When the group's policy is stale this returns
        // `Err(PolicyUnavailable)` (converted to `SyncError::PolicyUnavailable`),
        // so the method returns here without touching the index or the DAG —
        // no placeholder-auth change is ever committed, and the caller keeps
        // the edit journaled dirty to re-emit once policy is healthy.
        let auth = self.local_emission_auth(group_id)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let change =
                dag_store::emit_local_change(&tx, group_id, content.ops.clone(), auth, emitter)?;
            for version in content.versions {
                dag_store::put_file_version(&tx, group_id, version)?;
            }
            upsert_file_in_tx(&tx, group_id, record, origin_device_id)?;
            if let Some(meta) = meta {
                apply_local_meta_columns_in_tx(&tx, group_id, &record.path, meta)?;
            }
            tx.commit()?;
            Ok(change.compute_hash())
        })
    }

    /// Upserts a batch of records under a single change (one change carrying
    /// every op), in one transaction — the shape used by an initial folder
    /// scan. Returns the appended change's hash, or `None` for an empty batch.
    ///
    /// `metas`, when non-empty, is aligned 1:1 with `records`: index `i`'s
    /// `Some` value is that record's local metadata (record kind, symlink
    /// target/out-of-root, exec bit), written in the SAME transaction so the
    /// index row's metadata columns can never lag the `FileVersion`/DAG change
    /// across a crash between the commit and a separate post-commit setter. A
    /// `None` element (e.g. a tombstone) leaves that row's columns as
    /// `upsert_file_in_tx` left them; passing an empty `metas` leaves every
    /// row's columns untouched.
    ///
    /// Callers with a large detected batch MUST split it into op-count- and
    /// encoded-byte-bounded chunks and call this once per chunk: each call
    /// commits its own change whose parents are the previous chunk's committed
    /// head (see `dag_store::emit_local_change`), so the chunks form a linear
    /// chain no single wire message / decode bound can reject.
    pub fn upsert_files_batch_emitting_change(
        &self,
        group_id: &str,
        records: &[FileRecord],
        origin_device_id: &str,
        content: ChangeContent<'_>,
        metas: &[Option<LocalFileMetaColumns>],
        emitter: &ChangeEmitter,
    ) -> Result<Option<ChangeHash>, SyncError> {
        if records.is_empty() {
            return Ok(None);
        }
        // A length mismatch here would commit index rows whose emitted change
        // carries a different set of ops, or whose metadata columns land on the
        // wrong row — silent divergence, exactly what this dual-write exists to
        // prevent. It can only arise from a caller bug (the one production
        // caller slices `records`/`ops`/`metas` in lockstep), so fail fast here,
        // before the transaction opens, rather than let it reach the write.
        if content.ops.len() != records.len() {
            return Err(SyncError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} ops for {} records (one op per record is required)",
                content.ops.len(),
                records.len()
            )));
        }
        if !metas.is_empty() && metas.len() != records.len() {
            return Err(SyncError::CorruptState(format!(
                "upsert_files_batch length mismatch: {} metas for {} records (metas must be empty or aligned 1:1 with records)",
                metas.len(),
                records.len()
            )));
        }
        // Withhold the whole batch when the group's policy is stale (see
        // `upsert_file_emitting_change`) rather than committing a
        // placeholder-auth change; the caller re-drives it once policy heals.
        let auth = self.local_emission_auth(group_id)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let change =
                dag_store::emit_local_change(&tx, group_id, content.ops.clone(), auth, emitter)?;
            for version in content.versions {
                dag_store::put_file_version(&tx, group_id, version)?;
            }
            for (idx, record) in records.iter().enumerate() {
                upsert_file_in_tx(&tx, group_id, record, origin_device_id)?;
                if let Some(Some(meta)) = metas.get(idx) {
                    apply_local_meta_columns_in_tx(&tx, group_id, &record.path, meta)?;
                }
            }
            tx.commit()?;
            Ok(Some(change.compute_hash()))
        })
    }

    /// Tombstones a path and appends the signed `Delete` change describing
    /// it, in one transaction. Mirrors [`mark_deleted_at`](Self::mark_deleted_at)'s
    /// tombstone construction (observed-time stamp, version-vector bump,
    /// origin-recording upsert that retains the superseded live row as
    /// trash) while additionally emitting the change.
    pub fn mark_deleted_emitting_change(
        &self,
        group_id: &str,
        path: &str,
        device_id: &str,
        observed_at_unix_nanos: i64,
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        let mut record = self.get_file(group_id, path)?.unwrap_or(FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        });
        record.deleted = true;
        record.mtime_unix_nanos = observed_at_unix_nanos;
        record.version.increment(device_id);
        let ops = vec![Op::Delete { path: SyncPath(path.to_string()) }];
        // Withhold the tombstone change when the group's policy is stale (see
        // `upsert_file_emitting_change`); no placeholder-auth delete is
        // committed, and the caller keeps the path journaled dirty.
        let auth = self.local_emission_auth(group_id)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let change = dag_store::emit_local_change(&tx, group_id, ops.clone(), auth, emitter)?;
            upsert_file_in_tx(&tx, group_id, &record, device_id)?;
            tx.commit()?;
            Ok(change.compute_hash())
        })
    }

    // --- Materialization-operation journal ---
    //
    // A durable record of "a materialization write for this path is in
    // progress" (see the `materialization_intents` table). The intent is
    // written BEFORE the temp-write-then-rename that puts a version's content
    // on disk begins, and cleared only AFTER that write + rename + fsync
    // completes. Startup/periodic repair
    // (`materialization::repair_interrupted_materializations`) consults it to
    // disambiguate a `Hydrated`-but-missing file: intent present means a crash
    // interrupted the write and the file must be reconstructed from the index;
    // intent absent means the write had already completed and the file was
    // later deleted/renamed offline, which must become a tombstone rather than
    // be silently resurrected from the index.

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
    ) -> Result<(), SyncError> {
        let now = now_unix_nanos();
        retry_on_database_locked(|| {
            self.pool.get()?.execute(
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
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            self.pool.get()?.execute(
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
    ) -> Result<bool, SyncError> {
        let count: i64 = self.pool.get()?.query_row(
            "SELECT COUNT(*) FROM materialization_intents WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Appends a group's initial-import changes in a single transaction, but
    /// only if the group's history is still empty. Each element of `batches`
    /// becomes one signed change carrying those ops; the changes chain
    /// linearly (each takes the previous as its parent, exactly as normal
    /// local emission does), so a large existing index converts into a
    /// bounded chain of bounded-size changes that converges to a single head.
    /// Returns the number of changes appended, or `None` if the group already
    /// had history — an import already ran, or normal emission / peer
    /// admission has begun. The emptiness check runs *inside* the write
    /// transaction, so a crash mid-import rolls back cleanly (the next run
    /// redoes it) and a second concurrent caller observes the committed
    /// result and does nothing, making the whole import idempotent. See
    /// `crate::dag_import` for the caller that builds `batches` from the
    /// index and the call-ordering it requires.
    pub fn append_initial_import(
        &self,
        group_id: &str,
        batches: &[Vec<Op>],
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<Option<usize>, SyncError> {
        // Withhold the whole initial import when the group's policy is stale
        // (see `upsert_file_emitting_change`): committing placeholder-auth
        // import changes would seed the group's history with a root every
        // valid-policy peer rejects. Resolved once, up front — the same stamp
        // is reused for every batch below.
        let auth = self.local_emission_auth(group_id)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            // A non-empty head set means this group already has history: an
            // earlier import committed, or emission / peer admission has run.
            // Re-importing would inject a second root behind the existing
            // frontier, so skip entirely.
            if !dag_store::group_heads(&tx, group_id)?.is_empty() {
                return Ok(None);
            }
            // Persist every referenced version in the same transaction as the
            // import changes. Keyed by content hash, so passing the flat set
            // (not per-batch) is correct regardless of which change references
            // which version.
            for version in versions {
                dag_store::put_file_version(&tx, group_id, version)?;
            }
            let mut appended = 0usize;
            for ops in batches {
                dag_store::emit_local_change(&tx, group_id, ops.clone(), auth, emitter)?;
                appended += 1;
            }
            tx.commit()?;
            Ok(Some(appended))
        })
    }

    // --- Change-history read / admit API (used by peer sync) ---
    //
    // These read the DAG store and admit verified peer changes. Admission is
    // deliberately separate from verification: a caller MUST run
    // `crate::change::verify_change` (hash + signature against the peer's
    // pinned signing key + group authorization) before calling
    // `dag_admit_change`, since the pinned key and authorization live in the
    // peer/coordination layer, not here.

    /// The group's current non-superseded heads.
    pub fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncError> {
        dag_store::group_heads(&*self.pool.get()?, group_id)
    }

    /// Paths represented anywhere in this group's retained change history.
    pub fn dag_group_history_paths(
        &self,
        group_id: &str,
    ) -> Result<std::collections::HashSet<String>, SyncError> {
        dag_store::group_history_paths(&*self.pool.get()?, group_id)
    }

    /// Appends repair operations to an already-initialized DAG without
    /// rewriting the index. The caller must hold each affected path lock and
    /// re-check history after acquiring it.
    pub fn append_history_backfill(
        &self,
        group_id: &str,
        ops: Vec<Op>,
        versions: &[FileVersion],
        emitter: &ChangeEmitter,
    ) -> Result<ChangeHash, SyncError> {
        let auth = self.local_emission_auth(group_id)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            for version in versions {
                dag_store::put_file_version(&tx, group_id, version)?;
            }
            let change = dag_store::emit_local_change(&tx, group_id, ops.clone(), auth, emitter)?;
            let hash = change.compute_hash();
            tx.commit()?;
            Ok(hash)
        })
    }

    /// Every admitted-but-not-yet-projected change for `group_id`, oldest-first
    /// — the reconciliation layer's re-projection worklist (see
    /// [`dag_store::list_unapplied`]). The `applied` flag is the durable retry
    /// state: a change stays here until its path projection actually succeeds.
    pub fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, SyncError> {
        dag_store::list_unapplied(&*self.pool.get()?, group_id)
    }

    /// Whether a change is already present in the applied store.
    pub fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, SyncError> {
        dag_store::has_change(&*self.pool.get()?, hash)
    }

    /// A stored change decoded from its persisted bytes.
    pub fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncError> {
        match dag_store::get_encoded(&*self.pool.get()?, hash)? {
            None => Ok(None),
            Some(bytes) => Change::from_wire_bytes(&bytes)
                .map(Some)
                .map_err(|e| SyncError::NotFound(format!("corrupt stored change: {e}"))),
        }
    }

    /// A stored change's raw encoded bytes, for relaying it onward with its
    /// original signature intact.
    pub fn dag_get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, SyncError> {
        dag_store::get_encoded(&*self.pool.get()?, hash)
    }

    /// Persists a content-addressed file version, transactionally. Idempotent;
    /// used by the change-transfer path to store a peer's version bytes before
    /// admitting the changes that reference them.
    pub fn dag_put_file_version(
        &self,
        group_id: &str,
        version: &FileVersion,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            dag_store::put_file_version(&tx, group_id, version)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Whether a file version is present, keyed by its content hash.
    pub fn dag_has_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<bool, SyncError> {
        dag_store::has_file_version(&*self.pool.get()?, group_id, hash)
    }

    /// A stored file version decoded from its canonical bytes — the block
    /// list, size, and metadata a change op only references by hash.
    pub fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, SyncError> {
        dag_store::get_file_version(&*self.pool.get()?, group_id, hash)
    }

    pub fn dag_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncError> {
        dag_store::group_file_version_references_block(&*self.pool.get()?, group_id, block_hash)
    }

    /// Records blocks whose bytes this device actually obtained through the
    /// group. Peer-provided FileVersion/change metadata never calls this.
    pub fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), SyncError> {
        dag_store::record_group_block_provenance(&*self.pool.get()?, group_id, block_hashes)
    }

    pub fn group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncError> {
        dag_store::group_has_block_provenance(&*self.pool.get()?, group_id, block_hash)
    }

    /// Whether any current or retained materialized index version in `group_id`
    /// references `block_hash`. A DAG conflict may move a losing version to a
    /// derived path after its original current row has become superseded.
    pub fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT blocks_json FROM files WHERE group_id = ?1")?;
        let mut rows = stmt.query([group_id])?;
        while let Some(row) = rows.next()? {
            let blocks_json: String = row.get(0)?;
            let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
                // A malformed stored block list is locally-corrupt state, not an
                // absent referent — classify it as `CorruptState`, not
                // `NotFound`, so the whole "stored block list is malformed"
                // fault is reported one consistent way.
                SyncError::CorruptState(format!("stored block list is corrupt: {error}"))
            })?;
            if blocks.iter().any(|block| block.hash.as_slice() == block_hash) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A stored change's parent hashes — for walking ancestry to compute the
    /// set of changes a peer must send.
    pub fn dag_parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, SyncError> {
        dag_store::parents_of(&*self.pool.get()?, hash)
    }

    /// Whether `ancestor` is a strict ancestor of `descendant`.
    pub fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, SyncError> {
        dag_store::is_ancestor(&*self.pool.get()?, ancestor, descendant)
    }

    /// Admits a verified peer change transactionally: applies it (and
    /// promotes any orphans it unblocks) if its ancestry is complete,
    /// otherwise holds it in the bounded orphanage. Idempotent on duplicate
    /// delivery.
    pub fn dag_admit_change(
        &self,
        change: &Change,
        applied: bool,
    ) -> Result<dag_store::AdmitResult, SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let result = dag_store::admit_change(&tx, change, applied)?;
            tx.commit()?;
            Ok(result)
        })
    }

    /// Atomically persists a verified peer change's referenced versions and
    /// admits the change. Admission failure rolls every version write back.
    pub fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<dag_store::AdmitResult, SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            for version in versions {
                dag_store::put_file_version(&tx, change.group_id.as_str(), version)?;
            }
            let result = dag_store::admit_change(&tx, change, applied)?;
            tx.commit()?;
            Ok(result)
        })
    }

    /// Marks a stored change as materialized into the index.
    pub fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), SyncError> {
        dag_store::mark_applied(&*self.pool.get()?, hash)
    }

    /// Records a device's acknowledged head for a group. This single-head
    /// convenience is preserved verbatim for the heads-exchange path; it maps
    /// onto the multi-head frontier store as a one-element frontier (replacing
    /// any prior one). Callers with a full frontier use
    /// [`crate::compaction::record_acknowledged_frontier`] instead, which
    /// stores every head.
    pub fn dag_set_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
        hash: &ChangeHash,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            dag_store::set_device_frontier(&tx, group_id, device_id, std::slice::from_ref(hash))?;
            tx.commit()?;
            Ok(())
        })
    }

    /// A device's acknowledged frontier for a group as a single head, if any —
    /// the smallest by hash when several were recorded. Preserved for the
    /// heads-exchange path's single-head hint; the full multi-head frontier is
    /// available through the compaction store trait.
    pub fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, SyncError> {
        Ok(dag_store::get_device_frontier(&*self.pool.get()?, group_id, device_id)?
            .into_iter()
            .next())
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
        // Retried like every writer below: a shared-cache in-memory database
        // (every test's `open_in_memory`) can hand a plain read `DatabaseLocked`
        // — not `DatabaseBusy`, which `busy_timeout` already covers — while a
        // concurrent writer holds the table, so a caller polling state from a
        // background task (e.g. a wire-convergence test reading while a real
        // `PeerSyncSession::run()` loop writes) must retry a read here too.
        retry_on_database_locked(|| {
            let conn = self.pool.get()?;
            let row: Option<(u64, i64, String, String, i64)> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, version_json, blocks_json, deleted
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group_id, path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            row.map(|(size, mtime, version_json, blocks_json, deleted)| {
                row_to_record(path.to_string(), size, mtime, &version_json, &blocks_json, deleted)
            })
            .transpose()
        })
    }

    /// The `state = 'current'` row for `(group, path)` read as ONE atomic
    /// statement, carrying every column a `FileVersion` identity needs
    /// (blocks, size, mtime, record kind, symlink target, exec bit). Unlike
    /// stitching `get_file` together with the separate `get_record_kind`/
    /// `get_symlink_target`/`get_exec_bit` accessors — each its own
    /// `SELECT ... state = 'current'` — this cannot tear across a concurrent
    /// metadata/content transition: every field comes from the same row, so
    /// the `change::VersionHash` derived via [`CurrentVersionRecord::
    /// to_file_version`] always describes a version some single row actually
    /// held, never a hybrid snapshot of two. This is the read the durability
    /// custody path (eviction querier + responder) must use to reconstruct
    /// the current version's identity. `None` if there is no current row.
    pub fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, SyncError> {
        let conn = self.pool.get()?;
        #[allow(clippy::type_complexity)]
        let row: Option<(u64, i64, String, i64, String, Option<String>, i64)> = conn
            .query_row(
                "SELECT size, mtime_unix_nanos, blocks_json, deleted, record_kind, \
                        symlink_target, exec_bit \
                 FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(size, mtime, blocks_json, deleted, record_kind, symlink_target, exec_bit)| {
            // Fail closed on a corrupt `blocks_json` column rather than
            // coercing it to an empty block list. An empty list reads
            // downstream as "file has no content" (materialization skips a
            // `blocks.is_empty()` record), so silently defaulting on a parse
            // failure would mask genuine index/DB corruption as a legitimately
            // empty file. A valid `"[]"` still parses to an empty list and
            // stays a valid empty record — only an unparseable column errors.
            let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
                SyncError::CorruptState(format!(
                    "stored block list for current version of {path} is corrupt: {error}"
                ))
            })?;
            Ok(CurrentVersionRecord {
                blocks,
                size,
                mtime_unix_nanos: mtime,
                deleted: deleted != 0,
                record_kind: RecordKind::from_db_str(&record_kind),
                symlink_target,
                exec_bit: exec_bit != 0,
            })
        })
        .transpose()
    }

    pub fn remove_file(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let affected = self.pool.get()?.execute(
            "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(affected > 0)
    }

    /// The device that originated `path`'s current version, if recorded.
    /// `None` when there is no current row, or when the row predates origin
    /// tracking / was created locally without an origin stamp. Used to
    /// distinguish content this device received from a peer (a full replica of
    /// the group necessarily holds it) from a brand-new local edit no peer has
    /// yet — the fail-closed input to on-demand cache-reclamation custody.
    pub fn current_version_origin(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncError> {
        let conn = self.pool.get()?;
        let origin: Option<Option<String>> = conn
            .query_row(
                "SELECT origin_device_id FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![group_id, path],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        Ok(origin.flatten())
    }

    /// Bulk-loads every non-deleted file's materialization state for
    /// `group_id` (batch processing) — used by
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

    /// Block hashes (hex) that back content this device is holding
    /// materialized on disk right now for `group_id`: every block referenced
    /// by a non-deleted, current file that is either hydrated or pinned.
    ///
    /// These blocks must never be reclaimed as on-demand cache — dropping one
    /// would corrupt a file whose bytes are supposed to be present on disk.
    /// Eviction uses this set to compute which of an evicted file's blocks are
    /// safe to reclaim: only blocks NOT in this set (i.e. no longer backing any
    /// locally-present file) may be freed, and only then after full-replica
    /// custody is confirmed. A block that is still shared with another
    /// hydrated/pinned file stays; a block referenced only by placeholdered
    /// (non-hydrated) files is reclaimable because that content is re-fetched
    /// on demand.
    pub fn blocks_backing_local_content(
        &self,
        group_id: &str,
    ) -> Result<HashSet<ContentHash>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT blocks_json FROM files \
             WHERE group_id = ?1 AND deleted = 0 AND state = 'current' \
               AND (materialization_state = 'hydrated' OR pinned = 1)",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        let mut needed: HashSet<ContentHash> = HashSet::new();
        for row in rows {
            let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
            needed.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
        }
        Ok(needed)
    }

    /// Block hashes referenced by any retained row other than the exact
    /// current row being considered for cache eviction. The block store is
    /// device-global, so this scan crosses groups and includes placeholder,
    /// superseded, and trashed rows. A placeholder elsewhere may still retain
    /// the only local copy because its own custody check failed.
    pub fn blocks_referenced_outside_current_file(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<HashSet<ContentHash>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT blocks_json FROM files \
             WHERE deleted = 0 \
               AND NOT (group_id = ?1 AND path = ?2 AND state = 'current')",
        )?;
        let rows = stmt.query_map([group_id, path], |r| r.get::<_, String>(0))?;
        let mut referenced = HashSet::new();
        for row in rows {
            let blocks: Vec<BlockInfo> = serde_json::from_str(&row?)?;
            referenced.extend(blocks.into_iter().map(|block| hex::encode(block.hash)));
        }
        Ok(referenced)
    }

    /// Paths whose own index row already admits it has no bytes: an eager or
    /// pinned `placeholder`, or a `hydrating` row abandoned mid-fetch.
    /// `peer_session::reconcile_local_materialization_audit` re-drives exactly
    /// these through an ordinary peer fetch.
    ///
    /// Deliberately NOT selected, and this must stay that way: a `hydrated` row
    /// whose bytes are missing from disk. That divergence is real, but it is
    /// not repairable from here, because two causes produce a byte-identical
    /// index row —
    ///
    ///   * a crash between the durable `Hydrated` commit and the
    ///     temp-write-then-rename that was meant to follow it, which should be
    ///     reconstructed; and
    ///   * the user deleting or renaming the file away while the daemon was
    ///     stopped, which must NOT be reconstructed.
    ///
    /// The only thing separating them is the durable `materialization_intents`
    /// journal: the crash leaves an intent open, the offline delete does not
    /// (the intent seam in `peer_session`'s `materialize` carries a
    /// `debug_assert!` that no `Hydrated` row is ever committed for a
    /// not-yet-written file without one, which is what makes the journal's
    /// absence meaningful rather than merely unproven). Joining that journal in
    /// here would not rescue the query either: every path returned is fed
    /// straight to `rematerialize_local_records`, which rewrites the file
    /// unconditionally — so widening to `hydrated` silently resurrects the
    /// user's deletion, and the narrow with-intent subset would still be
    /// repaired against the wrong evidence, since this is a query over the
    /// `files` table and "absent from disk" is not a fact it can observe.
    ///
    /// Nor may the caller supply that fact by stat'ing the paths: it holds no
    /// [`crate::root_identity::VerifiedRoot`], and an unmounted volume leaves
    /// its mountpoint behind, so `metadata` succeeds and every `hydrated` file
    /// in the group looks absent at once.
    ///
    /// So `hydrated`-with-no-bytes is owned by
    /// `materialization::repair_interrupted_materializations`, which holds both
    /// missing pieces — it takes a `VerifiedRoot`, and it branches on the intent
    /// journal, reconstructing the crash and classifying the offline delete as a
    /// deletion instead of healing it. The daemon runs that pass at startup and
    /// on a live periodic per-link cadence, and the startup disk-reconcile scan
    /// emits the resulting tombstone. This is a division of labor, not a gap in
    /// it: rows that know they need bytes are repaired over the network from
    /// here; rows that disagree with disk are repaired against disk there.
    pub fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            // `l.orphaned = 0` keeps this fail-closed at the storage layer: an
            // orphaned link's coordination-side authorization is permanently
            // gone, so none of its files are ever repair-eligible. The daemon
            // scheduler already filters orphaned links before calling this, but
            // the core query must not depend on that to stay correct.
            "SELECT f.path FROM files f \
             JOIN links l ON l.group_id = f.group_id \
             WHERE f.group_id = ?1 \
               AND l.orphaned = 0 \
               AND f.deleted = 0 \
               AND f.state = 'current' \
               AND ( \
                 (f.materialization_state = 'placeholder' AND l.materialization_policy = 'eager') \
                 OR (f.materialization_state = 'placeholder' AND f.pinned = 1) \
                 OR f.materialization_state = 'hydrating' \
               ) \
             ORDER BY f.path",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, SyncError> {
        // See `get_file`'s comment: retried for the same read-vs-writer
        // `DatabaseLocked` reason.
        retry_on_database_locked(|| {
            let conn = self.pool.get()?;
            let mut stmt = conn.prepare(
                "SELECT path, size, mtime_unix_nanos, version_json, blocks_json, deleted FROM \
                 files WHERE group_id = ?1 AND state = 'current'",
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
                // Fail the whole listing closed on a corrupt row rather than
                // silently dropping content or emitting a defaulted record: a
                // directory listing built from partially-corrupt index rows is a
                // worse failure than a hard, diagnosable error (the corrupt path is
                // named by `row_to_record`'s `warn!`).
                out.push(row_to_record(path, size, mtime, &version_json, &blocks_json, deleted)?);
            }
            Ok(out)
        })
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
    /// materialization audits, where the requested paths are often a handful
    /// of records out of a much larger indexed group, not the whole file list.
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
                // Fail closed on a corrupt row (same rationale as `list_files`).
                let record =
                    row_to_record(path.clone(), size, mtime, &version_json, &blocks_json, deleted)?;
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

    // --- Materialization (on-demand-sync ) ---

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
            .optional()?;
        Ok(state.as_deref().map(MaterializationState::from_db_str))
    }

    pub fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
    ) -> Result<(), SyncError> {
        let affected = retry_on_database_locked(|| {
            Ok(self.pool.get()?.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current'",
                rusqlite::params![state.as_db_str(), group_id, path],
            )?)
        })?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("file {group_id}/{path}")));
        }
        Ok(())
    }

    /// Atomically changes a current file's materialization state only when
    /// it still matches `expected`. Cleanup guards use this to avoid rolling
    /// back a newer transition performed by another operation.
    pub fn transition_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        next: MaterializationState,
    ) -> Result<bool, SyncError> {
        let affected = retry_on_database_locked(|| {
            Ok(self.pool.get()?.execute(
                "UPDATE files SET materialization_state = ?1 \
                 WHERE group_id = ?2 AND path = ?3 AND state = 'current' \
                   AND materialization_state = ?4",
                rusqlite::params![next.as_db_str(), group_id, path, expected.as_db_str()],
            )?)
        })?;
        Ok(affected == 1)
    }

    /// `Hydrating` is set right before a block fetch begins
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

    /// `Evicting` is set right before eviction writes the placeholder and is
    /// cleared to `Placeholder` only once that placeholder is committed
    /// (`materialization::evict_file`). A crash in that window leaves the row
    /// `Evicting` forever: `reset_stale_hydrating_to_placeholder` above touches
    /// only `Hydrating` rows, `repair_interrupted_materializations` skips every
    /// non-`Hydrated` row, and nothing else reconciles it — so the file is
    /// permanently wedged (status even miscounts it as hydrating). No blocks are
    /// ever lost: physical block reclamation happens only *after* the row has
    /// already transitioned to `Placeholder`, so an `Evicting` row is guaranteed
    /// to still have every block retained. Called once at daemon startup (never
    /// mid-run, since a live daemon's own `Evicting` rows are legitimately an
    /// eviction in progress) to reset every stale `Evicting` row back to
    /// `Placeholder` — the same target, and the same blanket-UPDATE discipline,
    /// as the `Hydrating` reset above, chosen because it is safe for both
    /// interrupted-eviction disk states:
    ///
    /// - If the placeholder was already written before the crash, the row is
    ///   now `Placeholder` over a placeholder file on disk — identical to a
    ///   normally completed eviction (blocks retained), which every other path
    ///   already handles.
    /// - If the crash landed *before* the placeholder write, the real content
    ///   is still fully on disk under a `Placeholder` row. This is the safe
    ///   direction of divergence: `Placeholder` means "re-fetch/verify before
    ///   trusting", so the content is preserved untouched on disk and the
    ///   ordinary hydrate/read path reconciles it later (peer-free, since the
    ///   blocks are retained) — no data loss and no spurious conflict copy.
    ///
    /// Resetting to `Hydrated` instead would be unsafe: for the first sub-case,
    /// `repair_interrupted_materializations` would see a `Hydrated` row whose
    /// on-disk bytes (the zero-filled placeholder) do not match the indexed
    /// blocks, quarantine that placeholder as a divergent "user edit", and
    /// journal it as a new local path — fabricating a zero-filled conflict copy.
    pub fn reset_stale_evicting_to_placeholder(&self) -> Result<usize, SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE files SET materialization_state = ?1 \
             WHERE materialization_state = ?2 AND state = 'current'",
            rusqlite::params![
                MaterializationState::Placeholder.as_db_str(),
                MaterializationState::Evicting.as_db_str()
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
            .optional()?;
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

    /// Records `unix_ts` as this file's last-accessed time:
    /// called on hydration completion, and best-effort from the eviction
    /// sweep's `fs::metadata.accessed` fallback for already-hydrated
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

    /// The kind of on-disk entry this record represents. `None`
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
            .optional()?;
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

    /// The raw, unresolved symlink target text — only
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
            .optional()?;
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
            .optional()?;
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

    /// The owner-executable bit. Defaults to `false` for any
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
            .optional()?;
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
            .optional()?
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

    /// A held file's reason and hold timestamp, so both
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
            .optional()?;
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
    /// participating in normal index exchange with peers; this
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
    /// sweep's candidate list, in eviction order.
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
    /// `group_id`, pinned or not. `list_evictable_files` above
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
    /// — `yadorilink status`'s per-folder summary, avoiding
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
                MaterializationState::Evicting => counts.hydrating += count,
            }
        }
        Ok(counts)
    }

    /// A folder group's materialization policy, by `group_id`
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
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let policy: Option<String> = conn
            .query_row(
                "SELECT materialization_policy FROM links WHERE group_id = ?1 AND orphaned = 0 \
                 ORDER BY local_path",
                [group_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(policy.as_deref().map(MaterializationPolicy::from_db_str))
    }

    // --- Folder links ---

    /// The ONLY way a row enters `links`. Both public insert entry points call
    /// this and nothing else, so the one-live-link-per-group invariant cannot be
    /// forgotten at a future third insert site: there is no other function in
    /// this file that names `INSERT INTO links`.
    ///
    /// Takes a `&Transaction`, not a `&Connection`, on purpose: the check and
    /// the write must be one unit under `BEGIN IMMEDIATE`, or two concurrent
    /// `link` calls each read "no existing live link" and both insert. That
    /// atomicity is also why this lives here and not in the daemon's `link`
    /// handler — a check up there cannot be in the same transaction as the
    /// insert down here, so it is a TOCTOU window by construction. The handler's
    /// own check is an ergonomic early refusal, not the invariant.
    ///
    /// `INSERT OR REPLACE` is deliberately NOT used, here or anywhere else on
    /// this table. Measured, it does three separate silent harms: with a UNIQUE
    /// index present it DELETES the conflicting row instead of erroring; it
    /// resets `root_token` to NULL (re-arming adoption, which disarms the
    /// unmounted-volume guard); and it flips `orphaned` 1 → 0, an un-orphan path
    /// nothing in the code intends. A plain `INSERT` lets the primary key refuse
    /// the repoint case, which also makes the SQL and Rust layers agree instead
    /// of diverge.
    fn insert_link_row(
        tx: &rusqlite::Transaction<'_>,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncError> {
        // A live row for this group at any OTHER path is THE bug: two roots on
        // one group tombstone each other's files group-wide. Never guess which
        // root is meant — refuse and name both. A live row at THIS path is a
        // re-link, handled below.
        let live = Self::live_link_paths_on_conn(tx, group_id)?;
        if live.iter().any(|p| p != local_path) {
            let mut local_paths = live;
            if !local_paths.iter().any(|p| p == local_path) {
                local_paths.push(local_path.to_string());
            }
            local_paths.sort();
            return Err(SyncError::AmbiguousLink { group_id: group_id.to_string(), local_paths });
        }

        let existing_group: Option<String> = tx
            .query_row("SELECT group_id FROM links WHERE local_path = ?1", [local_path], |r| {
                r.get(0)
            })
            .optional()?;
        match existing_group {
            // This path is already registered to a DIFFERENT group. `INSERT OR
            // REPLACE` used to silently repoint the folder while every one of
            // its indexed file rows still belonged to the old group.
            Some(g) if g != group_id => Err(SyncError::InvalidInput(format!(
                "{local_path} is already linked to folder group {g}; unlink it before linking it \
                 to {group_id}"
            ))),
            // Same path, same group: a deliberate re-link (including the
            // idempotent retry after a failed link's rollback). Un-orphan and
            // un-pause EXPLICITLY, preserving `root_token` and the
            // materialization policy — leaving the row untouched instead would
            // make re-linking an orphaned folder a silent no-op.
            Some(_) => {
                tx.execute(
                    "UPDATE links SET paused = 0, orphaned = 0 WHERE local_path = ?1",
                    [local_path],
                )?;
                Ok(())
            }
            None => {
                tx.execute(
                    "INSERT INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
                    rusqlite::params![local_path, group_id],
                )?;
                Ok(())
            }
        }
    }

    pub fn add_link(&self, local_path: &str, group_id: &str) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            Self::insert_link_row(&tx, local_path, group_id)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Commits a new local link together with the pending-enrollment marker
    /// that guards its still-unconfirmed coordination-plane activation, in
    /// one SQLite transaction. Ordering matters: without this, a crash
    /// between the two writes could commit a real local link with no local
    /// trace of the still-Pending coordination-side row it depends on --
    /// exactly the stranded-link case this table's crash-safe create/join
    /// protocol exists to prevent. Wrapping both in a single transaction makes that
    /// window impossible rather than merely narrow; if either write fails,
    /// neither lands, and the caller's own enroll operation can abort
    /// cleanly with no local trace at all.
    pub fn add_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollment,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            tx.execute(
                "INSERT OR REPLACE INTO pending_enrollments \
                 (operation_id, kind, group_id, device_id, local_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    marker.operation_id,
                    marker.kind.as_db_str(),
                    marker.group_id,
                    marker.device_id,
                    marker.local_path,
                ],
            )?;
            Self::insert_link_row(&tx, local_path, group_id)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn remove_link(&self, local_path: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
        Ok(())
    }

    /// Removes a link row and its pending-enrollment marker in ONE SQLite
    /// transaction — the all-or-nothing rollback for a link whose post-commit
    /// setup failed. Doing the two deletes as separate writes (as the earlier
    /// rollback path did) could remove the link but leave the marker if the
    /// second write failed, stranding a marker that names a local path with no
    /// link behind it until a later reconciliation pass. One transaction makes
    /// that half-state impossible: either both rows are gone or neither is.
    /// Mirrors [`Self::orphan_link_and_remove_pending_enrollment`]. Absent
    /// row(s) are not an error — a `DELETE` that matches nothing is a no-op,
    /// matching the idempotence every other enrollment-marker write already
    /// has.
    pub fn remove_link_and_pending_marker(
        &self,
        local_path: &str,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            tx.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn list_links(&self) -> Result<Vec<FolderLink>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT local_path, group_id, paused, materialization_policy, max_local_size_bytes, \
             orphaned FROM links",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(FolderLink {
                local_path: r.get(0)?,
                group_id: r.get(1)?,
                paused: r.get::<_, i64>(2)? != 0,
                materialization_policy: MaterializationPolicy::from_db_str(&r.get::<_, String>(3)?),
                max_local_size_bytes: r.get(4)?,
                orphaned: r.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// This group's sync-root identity nonce, or `None` if the link has not
    /// been adopted yet (it predates the `root_token` column) or no link is
    /// registered for the group at all. See [`crate::root_identity`] for what
    /// the token is and why "not adopted yet" must stay distinguishable from
    /// any particular token value.
    ///
    /// Keyed by `group_id` rather than `local_path`, matching
    /// [`SyncState::materialization_policy_for_group`] and
    /// [`SyncState::windows_symlink_opt_in_for_group`] -- the caller
    /// (`VerifiedRoot::open`) knows the group and the root it was handed, not
    /// which row's `local_path` string that root canonicalizes from.
    ///
    /// A group has at most ONE live link. Two or more is
    /// [`SyncError::AmbiguousLink`] and is refused here rather than resolved.
    /// This comment previously said the opposite — that nothing forbids two
    /// links sharing a `group_id` and that the pair would be "mutually
    /// substitutable". They are not substitutable: the index is group-scoped
    /// and path-relative while every scan is root-scoped and authoritative, so
    /// each root's scan tombstones the other root's files group-wide, on every
    /// device. Sharing a token is what makes the two indistinguishable, not
    /// what makes them safe.
    ///
    /// `orphaned = 0` is load-bearing, not tidying: it makes this read key on
    /// EXACTLY the row set the ambiguity gate one line above counts. Without it
    /// the gate counts LIVE rows while the `SELECT` reads ALL rows and silently
    /// takes the lowest `local_path` — so on the ordinary "1 orphaned + 1 live"
    /// group the DEAD root's token is returned for the LIVE root, and
    /// [`crate::root_identity::VerifiedRoot::open`] either accuses a healthy
    /// root of being a restored backup, or (unmarked root, corroborated
    /// evidence) hands that dead token to `adopt_unmarked_root`, which stamps it
    /// into the LIVE root's marker. That last one manufactures the "two folders
    /// sharing one token, permanently indistinguishable" state this module
    /// exists to prevent, on the READ side, where no writer assert can see it.
    /// Pinned by `the_live_root_does_not_inherit_the_orphaned_roots_token`.
    ///
    /// `None` for an all-orphaned group is correct and does NOT weaken
    /// adoption: `persisted` is not an input to the adopt/refuse decision (see
    /// `adopt_unmarked_root`, which consults on-disk evidence alone and touches
    /// the token strictly AFTER that check has passed), so `None` changes only
    /// WHICH token a legitimate adoption stamps — reuse vs mint — never WHETHER
    /// one happens. Pinned by
    /// `a_token_absent_group_still_refuses_to_adopt_a_bare_root`.
    pub fn link_root_token_for_group(&self, group_id: &str) -> Result<Option<String>, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let token = conn
            .query_row(
                "SELECT root_token FROM links WHERE group_id = ?1 AND orphaned = 0 \
                 ORDER BY local_path",
                [group_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        // Flatten "no link row" and "link row with a NULL token" together: both
        // mean "no adopted identity to check against", and the caller's decision
        // is the same for each.
        Ok(token.flatten())
    }

    /// Records the sync-root identity nonce for a group's link(s).
    ///
    /// Unconditional (it overwrites any existing token) because both callers
    /// need that: adoption only reaches here when the token was absent, and
    /// re-adoption -- the deliberate "this really is a different folder now"
    /// action -- exists precisely to replace it. A group with no link row is not
    /// an error: `SyncState` is used directly, without a link registered, by
    /// tests and by callers that drive a scan against a bare directory, and
    /// there is nothing to persist for them. The marker on disk still carries
    /// the identity in that case.
    ///
    /// The `WHERE` is by `group_id` and so is unqualified by `local_path`: if a
    /// group somehow has two LIVE rows, this stamps the SAME token onto BOTH,
    /// actively manufacturing the "two mutually substitutable roots" state and
    /// making the pair permanently indistinguishable by the very identity check
    /// meant to tell them apart. Asserting on rows-changed turns that fan-out
    /// into a structural detector at the exact site of the damage — no rule for
    /// a future author to remember at a sibling call site. Mirrors
    /// [`Self::mark_link_orphaned`]'s existing rows-changed assert.
    ///
    /// `AND orphaned = 0` is what makes that assert agree with the gate instead
    /// of contradicting it. Without it the gate refuses on >= 2 LIVE rows while
    /// this counts ALL rows, so the ordinary "1 orphaned + 1 live" group — join,
    /// activation never confirmed, link orphaned, user retries the join at a new
    /// folder — is a state the gate calls LEGAL and this writer saw as 2 rows:
    /// `Err(AmbiguousLink)` forever, from `VerifiedRoot::open` AND from
    /// `readopt`, the documented escape hatch (which mints and writes the marker
    /// BEFORE this call, so it could never succeed). The group's sole live root
    /// could never be verified again on that device — permanently unsyncable,
    /// with no attacker and no corruption. Pinned by
    /// `a_group_with_one_orphaned_and_one_live_link_still_verifies_its_live_root`.
    ///
    /// With the filter, `affected > 1` fires on EXACTLY the condition the gate
    /// refuses, which `ensure_single_root` has already rejected at the top of
    /// both constructors — so this goes from contradicting the gate to being
    /// defence-in-depth behind it. `affected == 0` stays `Ok`: the documented
    /// "no link registered / bare-directory scan" case (see
    /// [`Self::ensure_unambiguous_group_on_conn`] on why zero live links is
    /// legal), which an all-orphaned group now also reaches — inert and
    /// idempotent, since the marker holds the identity and re-linking that path
    /// un-orphans the row with its `root_token` preserved.
    pub fn set_link_root_token_for_group(
        &self,
        group_id: &str,
        root_token: &str,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let affected = tx.execute(
                "UPDATE links SET root_token = ?2 WHERE group_id = ?1 AND orphaned = 0",
                rusqlite::params![group_id, root_token],
            )?;
            if affected > 1 {
                // Roll back rather than commit-then-complain. The rows-changed
                // count is only observable AFTER the write, so without the
                // enclosing transaction this would stamp both rows and only
                // then report the problem — deepening the very state it
                // refuses, and leaving the pair indistinguishable exactly as if
                // there had been no check at all.
                //
                // Names the LIVE paths only: every path here is one the user can
                // act on, since the write that failed touched live rows alone.
                // Naming an orphaned row would send the user to `unlink` a
                // folder whose removal changes nothing about this refusal.
                let local_paths = Self::live_link_paths_on_conn(&tx, group_id)?;
                drop(tx);
                return Err(SyncError::AmbiguousLink {
                    group_id: group_id.to_string(),
                    local_paths,
                });
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Forges the two-live-links-on-one-group state that the whole
    /// one-live-link-per-group fix exists to outlaw, by dropping the schema
    /// triggers and inserting behind the Rust chokepoint's back.
    ///
    /// Test-only, and necessarily so: the write side now refuses to produce this
    /// state, so every test that pins what the READ side does about an
    /// already-duplicated database (the state a user can already be in today,
    /// which is the whole point of the fix) has to manufacture it. One helper
    /// rather than per-test raw SQL, so there is exactly one place that knows
    /// how to bypass the guards.
    ///
    /// Returns `Result` rather than unwrapping internally so this file keeps its
    /// "no panic on an index path" property whole (`check-index-read-fail-closed`
    /// enforces it textually, and rightly does not care that these lines are
    /// cfg-gated). Callers are tests and unwrap at their own call site, where a
    /// failure reads as the test's own setup breaking.
    #[cfg(any(test, feature = "test-support"))]
    pub fn force_second_live_link_for_test(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<(), SyncError> {
        let conn = self.pool.get()?;
        conn.execute_batch(
            "DROP TRIGGER links_one_live_root_per_group_insert; \
             DROP TRIGGER links_one_live_root_per_group_unorphan;",
        )?;
        conn.execute(
            "INSERT INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
            rusqlite::params![local_path, group_id],
        )?;
        Ok(())
    }

    /// Stamps `root_token` onto the ONE row at `local_path`, with no ambiguity
    /// check and no orphan filter.
    ///
    /// Test-only, and necessarily so: production's only by-`group_id` token
    /// writer now refuses to stamp two live rows, so the "two rows sharing one
    /// token" state — which the PRE-FIX writer manufactured on any database that
    /// already had two links, and which is the state where the read-side gate is
    /// the ONLY remaining protection — can no longer be produced through the
    /// public API. A test that pins the gate has to build it directly. Keyed by
    /// `local_path` precisely so a test can put a DIFFERENT token on each row
    /// when that is what it means.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_link_root_token_for_path_for_test(
        &self,
        local_path: &str,
        root_token: &str,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET root_token = ?2 WHERE local_path = ?1",
            rusqlite::params![local_path, root_token],
        )?;
        if affected != 1 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Every row's `root_token` for `group_id`, ordered by `local_path`, with NO
    /// ambiguity check — the raw view a test needs to assert that a refusal
    /// stamped nothing. Production code must never resolve a token this way;
    /// that is what [`Self::link_root_token_for_group`] is for.
    #[cfg(any(test, feature = "test-support"))]
    pub fn link_root_tokens_for_group_unchecked_for_test(
        &self,
        group_id: &str,
    ) -> Result<Vec<Option<String>>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT root_token FROM links WHERE group_id = ?1 ORDER BY local_path")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, Option<String>>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Marks a link's coordination-side authorization as permanently gone
    /// (see [`FolderLink::orphaned`]) -- called only once reconciliation
    /// confirms a `Deleted` activation outcome, meaning there is nothing
    /// left to activate. Never touches the link's on-disk files: this only
    /// flips a local bookkeeping flag so sync stops treating the link as
    /// live.
    pub fn mark_link_orphaned(&self, local_path: &str) -> Result<(), SyncError> {
        let affected = self
            .pool
            .get()?
            .execute("UPDATE links SET orphaned = 1 WHERE local_path = ?1", [local_path])?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Marks a link orphaned and drops the pending-enrollment marker that
    /// diagnosed it as such, in one SQLite transaction -- the `Deleted`
    /// activation outcome's reconciliation step.
    /// Ordering matters the same way it does for
    /// `add_link_with_pending_enrollment`: doing this as two separate writes
    /// would let a crash between them drop the marker without ever having
    /// orphaned the link, leaving a phantom-active link that is never
    /// retried (its marker is gone) and never orphaned (the flag was never
    /// set) -- silently stuck forever. One transaction makes that window
    /// impossible. A link that has since been unlinked (no longer present)
    /// is not an error here: the marker is still dropped (there is nothing
    /// left to orphan), matching `reconcile`'s "link absent" branch for
    /// every other activation outcome.
    pub fn orphan_link_and_remove_pending_enrollment(
        &self,
        local_path: &str,
        operation_id: &str,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            tx.execute("UPDATE links SET orphaned = 1 WHERE local_path = ?1", [local_path])?;
            tx.execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
            tx.commit()?;
            Ok(())
        })
    }

    // --- Pending enrollments ---

    /// Persists a marker for a local link that was just committed but whose
    /// coordination-plane activation has not been confirmed yet. Replaces
    /// any existing marker for the same `operation_id` (idempotent).
    /// `add_link_with_pending_enrollment` is the atomic version used when
    /// the link itself is being created in the same step; this standalone
    /// form exists for callers (and tests) that only need the marker.
    pub fn record_pending_enrollment(&self, marker: &PendingEnrollment) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR REPLACE INTO pending_enrollments \
             (operation_id, kind, group_id, device_id, local_path) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                marker.operation_id,
                marker.kind.as_db_str(),
                marker.group_id,
                marker.device_id,
                marker.local_path,
            ],
        )?;
        Ok(())
    }

    /// Removes a marker once its activation (or compensating cancel) has
    /// been confirmed. A no-op if the marker is already gone.
    pub fn remove_pending_enrollment(&self, operation_id: &str) -> Result<(), SyncError> {
        self.pool
            .get()?
            .execute("DELETE FROM pending_enrollments WHERE operation_id = ?1", [operation_id])?;
        Ok(())
    }

    /// Every pending-enrollment marker currently outstanding.
    pub fn list_pending_enrollments(&self) -> Result<Vec<PendingEnrollment>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT operation_id, kind, group_id, device_id, local_path FROM pending_enrollments",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PendingEnrollment {
                operation_id: r.get(0)?,
                kind: EnrollmentKind::from_db_str(&r.get::<_, String>(1)?),
                group_id: r.get(2)?,
                device_id: r.get(3)?,
                local_path: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // --- Version history & trash ---

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
            "SELECT version_seq, size, mtime_unix_nanos, blocks_json, deleted, state, \
                    origin_device_id, record_kind, symlink_target, exec_bit \
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
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, i64>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                version_seq,
                size,
                mtime,
                blocks_json,
                deleted,
                state,
                origin_device_id,
                record_kind,
                symlink_target,
                exec_bit,
            ) = row?;
            out.push(version_record(
                path.to_string(),
                version_seq,
                size,
                mtime,
                &blocks_json,
                deleted,
                &state,
                origin_device_id,
                &record_kind,
                symlink_target,
                exec_bit,
            )?);
        }
        Ok(out)
    }

    /// A single retained version by its exact `version_seq` — the restore
    /// engine's lookup for `yadorilink restore <path> --version
    /// <id>`. `None` if no row exists at all for this exact
    /// `(group_id, path, version_seq)`.
    pub fn get_version(
        &self,
        group_id: &str,
        path: &str,
        version_seq: i64,
    ) -> Result<Option<VersionRecord>, SyncError> {
        let conn = self.pool.get()?;
        #[allow(clippy::type_complexity)]
        let row: Option<(
            u64,
            i64,
            String,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            i64,
        )> = conn
            .query_row(
                "SELECT size, mtime_unix_nanos, blocks_json, deleted, state, origin_device_id, \
                        record_kind, symlink_target, exec_bit \
                 FROM files WHERE group_id = ?1 AND path = ?2 AND version_seq = ?3",
                rusqlite::params![group_id, path, version_seq],
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
                    ))
                },
            )
            .optional()?;
        row.map(
            |(
                size,
                mtime,
                blocks_json,
                deleted,
                state,
                origin_device_id,
                record_kind,
                symlink_target,
                exec_bit,
            )| {
                version_record(
                    path.to_string(),
                    version_seq,
                    size,
                    mtime,
                    &blocks_json,
                    deleted,
                    &state,
                    origin_device_id,
                    &record_kind,
                    symlink_target,
                    exec_bit,
                )
            },
        )
        .transpose()
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
    /// newly-adopted files — `yadorilink link --on-demand` or
    /// its Eager-default counterpart.
    pub fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<(), SyncError> {
        // `orphaned = 0` keeps an orphaned link out of the mutation target:
        // its authorization is permanently gone, so its storage mode must not
        // be changeable as if it were live. Live reads already exclude it; the
        // write target should be hidden too. A match-less UPDATE surfaces as
        // NotFound, same as an unknown path.
        let affected = self.pool.get()?.execute(
            "UPDATE links SET materialization_policy = ?1 \
             WHERE local_path = ?2 AND orphaned = 0",
            rusqlite::params![policy.as_db_str(), local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Whether `group_id`'s link has opted in
    /// to attempting real Win32 symlink creation on Windows, rather than
    /// the default skip-with-visible-status policy. Mirrors
    /// `materialization_policy_for_group`'s by-`group_id` lookup shape —
    /// `PeerSyncSession::materialize` only knows the folder group, not the
    /// local path a caller linked it under. `false` (not an error) if no
    /// link is registered for this group at all, matching the "default
    /// policy" this column's own `DEFAULT 0` already implies.
    ///
    /// `orphaned = 0` for the same reason as every other by-`group_id`
    /// resolver, and this site is why "mirrors `materialization_policy_for_group`"
    /// was not enough: that function IS orphan-filtered and this one was not, so
    /// the claim to mirror it was already false. Unfiltered, the gate counts
    /// LIVE rows while the `SELECT` reads ALL of them and takes the lowest
    /// `local_path` — so on a "1 orphaned + 1 live" group with the orphaned path
    /// sorting first, the LIVE folder is materialized under the DEAD folder's
    /// symlink policy. Pinned by
    /// `an_orphaned_rows_symlink_opt_in_does_not_decide_the_live_links_policy`.
    pub fn windows_symlink_opt_in_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let opt_in: Option<i64> = conn
            .query_row(
                "SELECT windows_symlink_opt_in FROM links \
                 WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                [group_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(opt_in.unwrap_or(0) != 0)
    }

    /// Sets a folder link's per-link opt-in for attempting real Windows
    /// symlink materialization — mirrors
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
    /// eviction disk-usage cap — unset means no automatic
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

    /// Whether `group_id`'s next full scan must be additive — indexing what it
    /// finds but emitting no deletions.
    ///
    /// Set when a group is recovered out of the two-live-roots state by
    /// unlinking one of its folders. See the column's own comment in `init` for
    /// why the ordinary remedy is otherwise destructive.
    ///
    /// Reads the flag for the group's single live link. Ambiguity is refused
    /// (rather than defaulting to `false`) for the same reason as every other
    /// by-`group_id` resolver: `false` here means "deletions are safe to emit",
    /// which is precisely the answer that must never be guessed.
    pub fn suppress_tombstones_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let flag: Option<i64> = conn
            .query_row(
                "SELECT suppress_tombstones_until_scan FROM links \
                 WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                [group_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(flag.unwrap_or(0) != 0)
    }

    /// Arms the additive-scan flag on `local_path`'s link.
    pub fn set_suppress_tombstones(
        &self,
        local_path: &str,
        suppress: bool,
    ) -> Result<(), SyncError> {
        let affected = self.pool.get()?.execute(
            "UPDATE links SET suppress_tombstones_until_scan = ?1 WHERE local_path = ?2",
            rusqlite::params![suppress as i64, local_path],
        )?;
        if affected == 0 {
            return Err(SyncError::NotFound(format!("link {local_path}")));
        }
        Ok(())
    }

    /// Durably records the exact live paths whose presence must be recovered
    /// after removing a duplicate root. Re-arming is idempotent.
    pub fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR IGNORE INTO duplicate_recovery_paths (group_id, path) \
             SELECT group_id, path FROM files \
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0",
            [group_id],
        )?;
        Ok(())
    }

    pub fn resolve_duplicate_recovery_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "DELETE FROM duplicate_recovery_paths WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    pub fn duplicate_recovery_pending(&self, group_id: &str) -> Result<bool, SyncError> {
        Ok(self.pool.get()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM duplicate_recovery_paths WHERE group_id = ?1)",
            [group_id],
            |row| row.get(0),
        )?)
    }

    /// Every live (`orphaned = 0`) `local_path` registered for `group_id`,
    /// ordered by path.
    ///
    /// `ORDER BY` is not cosmetic. Every by-`group_id` resolver in this file
    /// used to be an unordered `query_row`, i.e. a silent first-row-wins over a
    /// set SQLite is free to return in any order — half of what made two links
    /// on one group a *silent* fault instead of a loud one. A stable order also
    /// keeps [`SyncError::AmbiguousLink`]'s message stable between runs, which
    /// is what makes it a usable instruction.
    fn live_link_paths_on_conn(
        conn: &rusqlite::Connection,
        group_id: &str,
    ) -> Result<Vec<String>, SyncError> {
        let mut stmt = conn.prepare(
            "SELECT local_path FROM links WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Refuses `group_id` if it has more than one live link, optionally ignoring
    /// the row at `excluding` (the caller's own path, for a same-path re-link).
    ///
    /// `> 1`, never `!= 1`: zero live links is legal and load-bearing — it is
    /// the documented "no link registered, drive a scan against a bare
    /// directory" case (see [`SyncState::set_link_root_token_for_group`]), which
    /// tests and direct `SyncState` users rely on. Refusing zero here would
    /// break them for no safety gain: with no link there is no second root to
    /// confuse this one with.
    ///
    /// Free function over `&Connection` rather than a method so the write
    /// chokepoint can run it *inside* its open transaction — the check and the
    /// insert must be one unit, or two concurrent `link` calls both pass it.
    fn ensure_unambiguous_group_on_conn(
        conn: &rusqlite::Connection,
        group_id: &str,
        excluding: Option<&str>,
    ) -> Result<(), SyncError> {
        let paths: Vec<String> = Self::live_link_paths_on_conn(conn, group_id)?
            .into_iter()
            .filter(|p| Some(p.as_str()) != excluding)
            .collect();
        if paths.len() > 1 {
            return Err(SyncError::AmbiguousLink {
                group_id: group_id.to_string(),
                local_paths: paths,
            });
        }
        Ok(())
    }

    /// Pooled wrapper over [`Self::ensure_unambiguous_group_on_conn`] — the
    /// read-side seam callers outside this module use to refuse an ambiguous
    /// group before doing anything else.
    pub fn ensure_unambiguous_group(&self, group_id: &str) -> Result<(), SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)
    }

    /// Every live `local_path` for `group_id`, refusing the ambiguous case.
    /// The `Vec` is empty or one element; anything else is
    /// [`SyncError::AmbiguousLink`].
    pub fn live_link_paths_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        let conn = self.pool.get()?;
        Self::live_link_paths_on_conn(&conn, group_id)
    }

    /// The one live `local_path` for `group_id`, or `None` if the group has no
    /// live link. Refuses (rather than guessing) when two or more share the
    /// group — the resolver every by-`group_id` root lookup outside this module
    /// funnels through.
    pub fn live_link_local_path_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        Ok(Self::live_link_paths_on_conn(&conn, group_id)?.into_iter().next())
    }

    /// The single link-table gate the peer-apply path consults before writing
    /// anything for `group_id` — "may this device apply a peer change to this
    /// group, and if so, where and how eagerly?" — in one lookup.
    ///
    /// This exists because that question used to be answered by three
    /// independent by-`group_id` lookups (`paused`, the materialization
    /// policy, and the session's own construction-time root snapshot), each of
    /// which resolved a *missing* link row permissively and on its own: a
    /// deleted row read as "not paused", as "no policy → default Eager", and
    /// left the session's frozen root untouched. Unlinking a folder deletes
    /// exactly that row, so each lookup independently waved through applies
    /// into a folder the user had detached — including the `remove_file` of a
    /// tombstone, against an explicit "your local files are not deleted"
    /// promise. Any single one failing open is sufficient for the loss, so the
    /// gate has to be *one* seam that cannot be defaulted past, not three
    /// hardened lookups.
    ///
    /// Called once per change batch — the same granularity
    /// `has_live_link_for_group` already uses, and cheap at that rate (one
    /// indexed lookup on a table with one row per linked folder).
    ///
    /// `orphaned = 0` is part of the gate, not an afterthought: an orphaned
    /// link's on-disk files are documented as never touched or deleted (see
    /// [`FolderLink::orphaned`]), which the old `paused` lookup did not honour
    /// — it read an orphaned row's `paused = 0` as "not paused" and let the
    /// apply proceed, contradicting the column's own contract.
    ///
    /// Two or more live links is `Err(AmbiguousLink)`, deliberately *not* a new
    /// `LinkGate::Ambiguous` variant: three of this enum's five consumers match
    /// with `matches!`/let-else, so a new variant would compile clean at every
    /// one of them and silently read as "not Live" — the exact fail-open shape
    /// this gate exists to prevent. `?` on a `Result` propagates loudly at all
    /// five instead.
    pub fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, SyncError> {
        let conn = self.pool.get()?;
        Self::ensure_unambiguous_group_on_conn(&conn, group_id, None)?;
        let row: Option<(String, i64, String)> = conn
            .query_row(
                "SELECT local_path, paused, materialization_policy FROM links \
                 WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path",
                [group_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((local_path, paused, policy)) = row else {
            return Ok(LinkGate::NoLiveLink);
        };
        if paused != 0 {
            return Ok(LinkGate::Paused { local_path });
        }
        Ok(LinkGate::Live { local_path, policy: MaterializationPolicy::from_db_str(&policy) })
    }

    /// Whether `group_id`'s link is currently paused, by `group_id`. Pause
    /// stops both directions.
    ///
    /// NOT a safety gate on its own, and must not be used as one: `false`
    /// covers both "a live link that is not paused" and "no live link at all",
    /// so a caller that only checks this admits writes for an unlinked group.
    /// A caller deciding whether it may touch the filesystem wants
    /// [`SyncState::link_gate_for_group`], which distinguishes the two. This
    /// remains only for callers asking the narrow, genuinely boolean question
    /// "has the user paused this link?".
    pub fn is_paused_for_group(&self, group_id: &str) -> Result<bool, SyncError> {
        Ok(matches!(self.link_gate_for_group(group_id)?, LinkGate::Paused { .. }))
    }

    /// Reads the persisted anti-rollback watermark for `group_id`, or `None`
    /// if the group has never been recorded (its first-ever verified snapshot
    /// is always accepted). See [`PolicyWatermark`]. Survives a daemon restart,
    /// which is the whole point: the in-memory verified/stale policy maps are
    /// rebuilt from scratch after a restart, so without this an older
    /// signature-valid chain would be re-adopted, silently dropping a later
    /// revoke.
    pub fn policy_watermark(&self, group_id: &str) -> Result<Option<PolicyWatermark>, SyncError> {
        let conn = self.pool.get()?;
        // `authority_key_fingerprint` is NULL for a row written before that
        // column existed, so read it as an `Option<Vec<u8>>` — a legacy row
        // yields `None`, which the daemon's verifier treats as "unknown", not
        // as a fork. Row shape: `(highest_verified_seq, highest_verified_head,
        // authority_key_generation, authority_key_fingerprint)`.
        type WatermarkRow = (i64, Vec<u8>, i64, Option<Vec<u8>>);
        let row: Option<WatermarkRow> = conn
            .query_row(
                "SELECT highest_verified_seq, highest_verified_head, authority_key_generation, \
                 authority_key_fingerprint \
                 FROM group_policy_watermark WHERE group_id = ?1",
                [group_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((seq, head_blob, generation, fingerprint_blob)) => {
                let highest_verified_head: [u8; 32] =
                    head_blob.as_slice().try_into().map_err(|_| {
                        SyncError::CorruptState(
                            "stored policy watermark head is not 32 bytes".into(),
                        )
                    })?;
                let authority_key_fingerprint = fingerprint_blob
                    .map(|blob| {
                        blob.as_slice().try_into().map_err(|_| {
                            SyncError::CorruptState(
                                "stored policy watermark authority key fingerprint is not 32 bytes"
                                    .into(),
                            )
                        })
                    })
                    .transpose()?;
                Ok(Some(PolicyWatermark {
                    highest_verified_seq: seq as u64,
                    highest_verified_head,
                    authority_key_generation: generation as u64,
                    authority_key_fingerprint,
                }))
            }
        }
    }

    /// Writes (creating or replacing) the anti-rollback watermark for
    /// `group_id`. The forward-only invariant — never lower the watermark — is
    /// enforced by the daemon against the freshly verified chain before it
    /// calls this; this method is the plain persistence sink and does not
    /// itself compare against the stored row.
    pub fn upsert_policy_watermark(
        &self,
        group_id: &str,
        watermark: &PolicyWatermark,
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR REPLACE INTO group_policy_watermark \
             (group_id, highest_verified_seq, highest_verified_head, authority_key_generation, \
              authority_key_fingerprint) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                group_id,
                watermark.highest_verified_seq as i64,
                watermark.highest_verified_head.as_slice(),
                watermark.authority_key_generation as i64,
                // `None` stores SQL NULL — a verified snapshot always carries a
                // fingerprint, so a NULL here only ever comes from persisting a
                // legacy watermark unchanged, never from a fresh verification.
                watermark.authority_key_fingerprint.as_ref().map(|fp| fp.as_slice()),
            ],
        )?;
        Ok(())
    }

    // --- Local dirty-path journal (survive watcher misses, disk faults,
    //     restarts) ---

    /// Records `path` as a detected-but-not-yet-processed local edit for
    /// `group_id`, *before* the read/blockify/put/index+DAG step runs. Keeps
    /// the earliest `first_seen_unix_nanos` across repeated events for the same
    /// path (so `INSERT ... ON CONFLICT` updates only the kind/observation
    /// time), and resets `attempts`/`last_error` since a fresh event is a fresh
    /// detection, not a continued failure. The row survives until
    /// [`clear_dirty_path`] runs after the step commits, so a crash or a
    /// multi-second block-store fault mid-processing cannot drop the edit — the
    /// daemon re-drives it on startup and on retry.
    pub fn record_dirty_path(
        &self,
        group_id: &str,
        path: &str,
        change_kind: &str,
        observed_at_unix_nanos: i64,
    ) -> Result<(), SyncError> {
        let now = now_unix_nanos();
        self.pool.get()?.execute(
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
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "UPDATE local_dirty_paths SET attempts = attempts + 1, last_error = ?3 \
             WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path, last_error],
        )?;
        Ok(())
    }

    /// Clears `path` from the dirty journal once its read/blockify/put/index+DAG
    /// step has committed. Not an error if the path wasn't recorded — mirrors
    /// `clear_held`'s "callers don't need to check first" contract.
    pub fn clear_dirty_path(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "DELETE FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
        )?;
        Ok(())
    }

    /// Whether `path` currently has a pending local edit journaled for
    /// `group_id`. The materialization-repair / reconcile write paths consult
    /// this before overwriting an on-disk file from the (older) index, so a
    /// newer local edit the watcher hasn't yet indexed is quarantined rather
    /// than destroyed.
    pub fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, SyncError> {
        let count: i64 = self.pool.get()?.query_row(
            "SELECT COUNT(*) FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Every currently journaled dirty path for `group_id`, oldest-first — the
    /// daemon's startup rescan worklist. Ordered by `first_seen_unix_nanos` so
    /// the longest-outstanding edits are re-driven first.
    pub fn list_dirty_paths(&self, group_id: &str) -> Result<Vec<DirtyPath>, SyncError> {
        let conn = self.pool.get()?;
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
    }

    // --- Crash-safe restore journal ---

    pub fn record_restore_operation(&self, operation: &RestoreOperation) -> Result<(), SyncError> {
        let version_json = serde_json::to_string(operation.record.version.counters())?;
        let blocks_json = serde_json::to_string(&operation.record.blocks)?;
        self.pool.get()?.execute(
            "INSERT INTO restore_operations
             (operation_id, group_id, path, target_version_seq,
              expected_current_version_seq, state, size,
              mtime_unix_nanos, version_json, blocks_json, origin_device_id,
              created_at_unix_nanos)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                operation.operation_id,
                operation.group_id,
                operation.path,
                operation.target_version_seq,
                operation.expected_current_version_seq,
                operation.state.as_db_str(),
                operation.record.size as i64,
                operation.record.mtime_unix_nanos,
                version_json,
                blocks_json,
                operation.origin_device_id,
                now_unix_nanos(),
            ],
        )?;
        Ok(())
    }

    pub fn mark_restore_disk_committed(&self, operation_id: &str) -> Result<(), SyncError> {
        let changed = self.pool.get()?.execute(
            "UPDATE restore_operations SET state = 'disk_committed' WHERE operation_id = ?1",
            [operation_id],
        )?;
        if changed == 0 {
            return Err(SyncError::CorruptState(format!(
                "restore operation disappeared before disk commit: {operation_id}"
            )));
        }
        Ok(())
    }

    pub fn list_restore_operations(
        &self,
        group_id: &str,
    ) -> Result<Vec<RestoreOperation>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT operation_id, group_id, path, target_version_seq, state,
                    size, mtime_unix_nanos, version_json, blocks_json, origin_device_id,
                    expected_current_version_seq
             FROM restore_operations WHERE group_id = ?1
             ORDER BY created_at_unix_nanos, operation_id",
        )?;
        let rows = stmt.query_map([group_id], restore_operation_from_row)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Atomically publishes the exact journaled version and removes its
    /// recovery marker. A second recovery pass observes no row and therefore
    /// cannot append another version.
    pub fn commit_restore_operation(
        &self,
        operation_id: &str,
    ) -> Result<RestoreCommitOutcome, SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let operation = tx
                .query_row(
                    "SELECT operation_id, group_id, path, target_version_seq, state,
                            size, mtime_unix_nanos, version_json, blocks_json, origin_device_id,
                            expected_current_version_seq
                     FROM restore_operations WHERE operation_id = ?1",
                    [operation_id],
                    restore_operation_from_row,
                )
                .optional()?;
            let Some(operation) = operation else {
                tx.commit()?;
                return Ok(RestoreCommitOutcome::Missing);
            };
            let current_version_seq: Option<i64> = tx
                .query_row(
                    "SELECT version_seq FROM files
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![operation.group_id, operation.path],
                    |row| row.get(0),
                )
                .optional()?;
            if current_version_seq != operation.expected_current_version_seq {
                tx.commit()?;
                return Ok(RestoreCommitOutcome::Superseded);
            }
            upsert_file_in_tx(
                &tx,
                &operation.group_id,
                &operation.record,
                &operation.origin_device_id,
            )?;
            tx.execute("DELETE FROM restore_operations WHERE operation_id = ?1", [operation_id])?;
            tx.commit()?;
            Ok(RestoreCommitOutcome::Committed(operation.record))
        })
    }

    pub fn discard_restore_operation(&self, operation_id: &str) -> Result<(), SyncError> {
        self.pool
            .get()?
            .execute("DELETE FROM restore_operations WHERE operation_id = ?1", [operation_id])?;
        Ok(())
    }

    // --- Version history retention expiry ---

    /// The retention-expiry sweep — deletes the index row (never the
    /// blocks; leaves actual block reclamation to a future
    /// block-store GC) for any `superseded`/`trashed` version of
    /// `group_id` that exceeds *both* the built-in version-count bound
    /// ([`RETENTION_MAX_VERSIONS`], by recency rank among that path's own
    /// superseded/trashed rows) and the built-in age bound
    /// ([`RETENTION_MAX_AGE_DAYS`], by wall-clock age from `now_unix_nanos`).
    /// This is the union-retain / intersection-expire rule: a version is kept
    /// while it is within *either* bound, and expired only once it is beyond
    /// *both*, so recent history and recently-changed history are both kept.
    /// Retention is a fixed built-in policy applied to every link; it is not
    /// configurable. The `current` row for any path is never a candidate —
    /// the `WHERE state IN ('superseded', 'trashed')` below structurally
    /// excludes it, matching the rule that the current live version is never
    /// subject to retention expiry. Returns the number of rows deleted.
    pub fn expire_superseded_and_trashed_versions(
        &self,
        group_id: &str,
        now_unix_nanos: i64,
    ) -> Result<usize, SyncError> {
        const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;
        let age_cutoff_unix_nanos =
            now_unix_nanos.saturating_sub(RETENTION_MAX_AGE_DAYS.saturating_mul(NANOS_PER_DAY));

        // A version an outstanding handoff lease still pins (see
        // `HandoffLease`'s doc comment) must survive this sweep even though
        // it is otherwise beyond both retention bounds — read up front, on
        // this same connection, before the delete transaction below. Unix
        // *seconds*, not nanos, matching `handoff_leases.expires_at_unix`,
        // which holds a TARGET-LOCAL deadline (this device's own clock at
        // pin time + the grant's TTL duration + a fixed safety margin — see
        // `record_handoff_lease_atomic`), never a coordination-worker
        // absolute time. That is what keeps this comparison same-clock on
        // both sides: the stored deadline and `now_unix_seconds` below are
        // both readings of THIS device's own clock.
        let now_unix_seconds = now_unix_nanos / 1_000_000_000;
        let pinned = self.leased_version_keys_for_group(group_id, now_unix_seconds)?;

        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        let candidates: Vec<(String, i64)> = {
            // `rnk = 1` is the most recently superseded/trashed row for a
            // given path; the newest `RETENTION_MAX_VERSIONS` rows survive on
            // the count axis alone. A row is deleted only when it is beyond
            // both the count bound and the age bound.
            let mut stmt = tx.prepare(
                "SELECT path, version_seq FROM (
                    SELECT path, version_seq, mtime_unix_nanos,
                           ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_seq DESC) AS rnk
                    FROM files WHERE group_id = ?1 AND state IN ('superseded', 'trashed')
                 )
                 WHERE rnk > ?2 AND mtime_unix_nanos < ?3",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![group_id, RETENTION_MAX_VERSIONS, age_cutoff_unix_nanos],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                // A leased row is retained past both bounds until the lease is
                // confirmed/released/expires -- see `leased_version_keys_for_
                // group`'s doc comment for why the time check there (not
                // merely `state`) is what actually matters.
                .filter(|key| !pinned.contains(key))
                .collect()
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

    /// Every user-recoverable durability root for `group_id`: the single set
    /// a full-replica handoff must cover so that demoting/unlinking/revoking
    /// the group's last eager replica can never silently lose recoverable
    /// history, not just the current head. A root is `(path, change::
    /// VersionHash)`, one entry per still-restorable `(path, version_seq)`
    /// row, so the same `path` legitimately appears more than once when
    /// several of its versions are each still retained.
    ///
    /// The three categories that actually exist in this schema today all
    /// live in the same `files` table, distinguished only by `state`
    /// ([`VersionState`]) — there is no separate version-history, trash, or
    /// conflict-copy table:
    ///
    /// - **current** (`state = 'current'`): the live head of every file —
    ///   the same set `list_files` returns.
    /// - **retained superseded** (`state = 'superseded'`): prior versions not
    ///   yet swept by [`Self::expire_superseded_and_trashed_versions`],
    ///   restorable via `versions`/`restore --version`.
    /// - **trash-restorable** (`state = 'trashed'`): deleted-but-in-retention
    ///   content, restorable via `trash restore`, not yet swept by the same
    ///   expiry.
    ///
    /// Conflict copies are NOT a fourth category — there is no
    /// `RecordKind::ConflictCopy` or marker column (see
    /// `conflict::is_conflict_copy_of`): a conflict copy is written as an
    /// ordinary `state = 'current'` row under a synthetic
    /// `"name (conflicted copy, ...)"` path, so it is already covered by the
    /// `current` scan above with no extra query.
    ///
    /// A non-deleted row of any of the three states carries real, restorable
    /// block content — `live_block_hashes_with_extra_roots`'s own doc
    /// comment establishes the identical fact for the block-store GC live
    /// set. Directories and symlinks carry no blocks and are excluded
    /// (`record_kind != 'file'`, itself a per-row column so this can filter
    /// in SQL directly rather than needing a second per-path lookup); a
    /// `deleted = 1` row is also excluded — its `blocks_json` is always `[]`
    /// by construction.
    ///
    /// Also returns a stable digest over the root set (roots sorted by path,
    /// each root's block sequence kept ordered — see
    /// [`durability_roots_digest`]) so a caller can capture it when
    /// readiness is first confirmed and re-check it immediately before
    /// committing a role loss, detecting the set changing out from under
    /// that confirmation. For the daemon-driven commit paths that must be
    /// atomic against a concurrent index write, use
    /// [`Self::recheck_digest_then_set_materialization_policy`] /
    /// [`Self::recheck_digest_then_remove_link`] instead of comparing a
    /// separately-read digest, which re-enumerate and commit in one
    /// transaction so no write can interleave.
    ///
    /// Deliberately NOT used by per-file eviction custody
    /// ([`Self::list_versions`]/the daemon's `confirm_version_present_via_
    /// peer`), which stays a `VersionPresent` check for the ONE evicted
    /// exact version — routing eviction through the whole-group root set
    /// would ask an on-demand device to prove custody of history it was
    /// never asked to hold in the first place. GC unification (a future
    /// block-store sweep computing its live set from roots ∪
    /// hydration-in-progress (`MaterializationState::Hydrating`) ∪
    /// dirty/in-flight (`Self::list_dirty_paths`) ∪ a grace window) is out
    /// of scope here; this function only answers the handoff/durability
    /// question.
    pub fn enumerate_group_durability_roots(
        &self,
        group_id: &str,
    ) -> Result<DurabilityRoots, SyncError> {
        // `&*` derefs the pooled connection to `&Connection`, the helper's
        // param type (a write `Transaction` derefs to the same in the atomic
        // commit paths below).
        enumerate_group_durability_roots_on_conn(&*self.pool.get()?, group_id)
    }

    /// The `(path, version_seq)` identity of every row
    /// [`Self::enumerate_group_durability_roots`] would enumerate for
    /// `group_id`, in the same order over the same `WHERE` clause. `
    /// DurabilityRoot` itself (`path` + `block_hashes`) carries no
    /// `version_seq` — it identifies content, not a specific retained row —
    /// so a caller that needs to pin the *exact rows* a handoff-readiness
    /// check just verified (see [`Self::record_handoff_lease`]) reads this
    /// sibling query instead. Deliberately a separate, read-only query
    /// rather than a change to `DurabilityRoot`'s own shape: this crate's
    /// durability-root type is shared, public-facing wire surface, not
    /// something this lease-pinning feature owns.
    ///
    /// Not run in the same transaction as the digest capture it is normally
    /// paired with (see `daemon_state`'s handoff-lease request path) — a
    /// small, documented gap matching every other "digest captured, then a
    /// separate read/commit" pattern this crate already accepts elsewhere
    /// (e.g. [`Self::full_replica_handoff_ready_digest`]'s own doc comment).
    /// Pinning is defense in depth on top of, not a replacement for, the
    /// existing digest re-check gates.
    pub fn enumerate_group_durability_root_versions(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, i64)>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT path, version_seq FROM files \
             WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
               AND state IN ('current', 'superseded', 'trashed') \
             ORDER BY path, version_seq",
        )?;
        let rows =
            stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Records a newly-issued coordination-worker handoff lease for this
    /// device (as the handoff target), in `'provisional'` state — the local
    /// half of the lease-request round trip described on [`HandoffLease`].
    /// `pinned_versions` is normally the exact result of
    /// [`Self::enumerate_group_durability_root_versions`] captured alongside
    /// the digest the lease was requested against. Replaces any existing row
    /// with the same `lease_id` (idempotent retry of a request whose
    /// response was lost).
    pub fn record_handoff_lease(
        &self,
        group_id: &str,
        lease_id: &str,
        root_digest: [u8; 32],
        pinned_versions: &[(String, i64)],
        created_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<(), SyncError> {
        let pinned_json = serde_json::to_string(pinned_versions)?;
        self.pool.get()?.execute(
            "INSERT INTO handoff_leases \
                (lease_id, group_id, root_digest, state, pinned_versions_json, \
                 created_at_unix, expires_at_unix) \
             VALUES (?1, ?2, ?3, 'provisional', ?4, ?5, ?6) \
             ON CONFLICT(lease_id) DO UPDATE SET \
                group_id = excluded.group_id, root_digest = excluded.root_digest, \
                state = 'provisional', pinned_versions_json = excluded.pinned_versions_json, \
                created_at_unix = excluded.created_at_unix, \
                expires_at_unix = excluded.expires_at_unix",
            rusqlite::params![
                lease_id,
                group_id,
                &root_digest[..],
                pinned_json,
                created_at_unix,
                expires_at_unix
            ],
        )?;
        Ok(())
    }

    /// Fixed cushion added on top of the grant's own TTL duration when this
    /// device (the handoff TARGET) computes its LOCAL pin deadline — see
    /// [`Self::record_handoff_lease_atomic`]. The target's pin must
    /// outlive the coordination Worker's own view of the lease under any
    /// realistic clock skew between the two: pinning a little too long only
    /// delays this device's own next retention sweep by that much, while
    /// pinning even slightly too short can let a retention sweep collect a
    /// version the handoff still depends on. The safe direction is always
    /// longer, never shorter.
    pub const HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS: i64 = 60;

    /// Atomically re-enumerates `group_id`'s durability-root version rows
    /// (the identical `WHERE` clause [`Self::enumerate_group_durability_root_
    /// versions`] uses) AND records the handoff-lease pin for exactly that
    /// set, in ONE write transaction — closing the window
    /// [`Self::record_handoff_lease`] alone leaves between a
    /// separately-captured enumeration and the pin write, during which this
    /// device's own retention sweep
    /// ([`Self::expire_superseded_and_trashed_versions`]) could evict a row
    /// that was just enumerated but not yet pinned. Because the
    /// re-enumeration and the `INSERT`/`UPDATE` of `handoff_leases` below run
    /// on the same `IMMEDIATE` transaction, no retention sweep (itself a
    /// separate write transaction) can observe or delete a row in between —
    /// it either runs fully before this call's snapshot or fully after this
    /// call's commit.
    ///
    /// `ttl_seconds` is a DURATION, not a deadline — this device (the
    /// handoff target) always derives its own LOCAL pin deadline as
    /// `created_at_unix + ttl_seconds + `[`HANDOFF_LEASE_PIN_SAFETY_MARGIN_
    /// SECS`], stored as `handoff_leases.expires_at_unix` and later compared
    /// only against this SAME device's own `now_unix` in
    /// [`Self::leased_version_keys_for_group`]. It never accepts or stores
    /// the coordination Worker's own absolute expiry: the Worker computes
    /// that value against its own clock purely for its own bookkeeping/TTL
    /// sweep (`HandoffLeaseGrant`), and comparing an absolute value stamped
    /// by one clock against `now_unix()` read from a different device's
    /// clock is exactly the cross-clock comparison this function is written
    /// to make impossible — under clock skew it could otherwise treat a
    /// still-live lease as already expired (dropping the pin early, reopening
    /// the GC race the lease exists to close) or a dead one as still live
    /// (over-pinning, merely wasteful). `created_at_unix` must be this same
    /// device's own reading of its own clock (`now_unix()` at the call
    /// site), never a value obtained from another device.
    ///
    /// Returns the digest of exactly the set this call pinned — the same
    /// [`durability_roots_digest`] routine [`Self::enumerate_group_
    /// durability_roots`] uses, computed from a `DurabilityRoots` read on
    /// this same transaction/connection — alongside the pinned `(path,
    /// version_seq)` rows themselves, so the caller can compare this digest
    /// against an earlier readiness attestation (captured before the Worker
    /// round trip that produced `lease_id`) and abort — releasing this pin
    /// via [`Self::set_handoff_lease_state`] — on a mismatch, rather than
    /// proceeding under a pin that no longer matches what was attested.
    ///
    /// Always writes in `'provisional'` state, matching
    /// [`Self::record_handoff_lease`]; replaces any existing row with the
    /// same `lease_id` (idempotent retry of a request whose response was
    /// lost), also matching it.
    pub fn record_handoff_lease_atomic(
        &self,
        group_id: &str,
        lease_id: &str,
        created_at_unix: i64,
        ttl_seconds: i64,
    ) -> Result<([u8; 32], Vec<PinnedVersion>), SyncError> {
        // A non-positive TTL cannot produce a safe pin: it yields a deadline
        // at or before `created_at_unix`, so the pin would lapse immediately
        // and reopen the retention/GC race this lease exists to close. Reject
        // it structurally here — fail closed, writing no pin row — so an
        // invalid duration (e.g. a malformed grant that slipped past the
        // caller's own boundary check) can never produce a too-short pin. The
        // safety margin below only ever lengthens a positive TTL; it must not
        // be relied on to rescue a non-positive one.
        if ttl_seconds <= 0 {
            return Err(SyncError::InvalidInput(format!(
                "handoff lease ttl_seconds must be positive, got {ttl_seconds}"
            )));
        }
        let expires_at_unix = created_at_unix
            .saturating_add(ttl_seconds)
            .saturating_add(Self::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS);
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            // IMMEDIATE takes SQLite's write lock at BEGIN, so the
            // re-enumeration and the pin INSERT below observe one snapshot
            // that no concurrent write transaction (in particular a
            // retention sweep) can mutate until this transaction commits.
            let tx = new_immediate_write_transaction(&mut conn)?;
            let current = enumerate_group_durability_roots_on_conn(&tx, group_id)?;
            // Same category/ordering as `enumerate_group_durability_root_
            // versions`, run on the same `tx` so it sees the identical
            // snapshot `current` was just computed from.
            let pinned_versions: Vec<PinnedVersion> = {
                let mut stmt = tx.prepare(
                    "SELECT path, version_seq FROM files \
                     WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
                       AND state IN ('current', 'superseded', 'trashed') \
                     ORDER BY path, version_seq",
                )?;
                let rows = stmt
                    .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            let pinned_json = serde_json::to_string(&pinned_versions)?;
            tx.execute(
                "INSERT INTO handoff_leases \
                    (lease_id, group_id, root_digest, state, pinned_versions_json, \
                     created_at_unix, expires_at_unix) \
                 VALUES (?1, ?2, ?3, 'provisional', ?4, ?5, ?6) \
                 ON CONFLICT(lease_id) DO UPDATE SET \
                    group_id = excluded.group_id, root_digest = excluded.root_digest, \
                    state = 'provisional', pinned_versions_json = excluded.pinned_versions_json, \
                    created_at_unix = excluded.created_at_unix, \
                    expires_at_unix = excluded.expires_at_unix",
                rusqlite::params![
                    lease_id,
                    group_id,
                    &current.digest[..],
                    pinned_json,
                    created_at_unix,
                    expires_at_unix
                ],
            )?;
            tx.commit()?;
            Ok((current.digest, pinned_versions))
        })
    }

    /// Flips a locally-recorded lease's state — `'confirmed'` once the
    /// source's role-loss commit has confirmed it coordination-side,
    /// `'released'`/`'expired'` once it no longer protects anything. A no-op
    /// (`Ok(false)`) if `lease_id` is not recorded locally (e.g. this device
    /// restarted and lost its marker — the lease still terminates on the
    /// coordination-worker side via its own TTL sweep either way, so a
    /// missing local row is not itself a correctness problem, only a
    /// slightly earlier resumption of normal retention for whatever it would
    /// have pinned).
    pub fn set_handoff_lease_state(
        &self,
        lease_id: &str,
        new_state: HandoffLeaseState,
    ) -> Result<bool, SyncError> {
        let changed = self.pool.get()?.execute(
            "UPDATE handoff_leases SET state = ?1 WHERE lease_id = ?2",
            rusqlite::params![new_state.as_db_str(), lease_id],
        )?;
        Ok(changed > 0)
    }

    /// Every handoff lease this device currently has recorded for
    /// `group_id`, regardless of state — a diagnostic/test read, not
    /// consulted directly by retention (see
    /// [`Self::leased_version_keys_for_group`] for the enforcement path).
    pub fn list_handoff_leases_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<HandoffLease>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT lease_id, group_id, root_digest, state, pinned_versions_json, \
                    created_at_unix, expires_at_unix \
             FROM handoff_leases WHERE group_id = ?1 ORDER BY created_at_unix",
        )?;
        let rows = stmt.query_map([group_id], row_to_handoff_lease)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The `(path, version_seq)` set currently pinned against retention
    /// expiry for `group_id`: every row named by a lease that is still
    /// actively protecting it right now — `'provisional'` or `'confirmed'`,
    /// and not yet past its own `expires_at_unix` as of `now_unix`. A lease
    /// past its expiry is treated as not pinning anything even if its `state`
    /// column hasn't yet been flipped to `'expired'` by a sweep (the time
    /// check is authoritative; the state column is bookkeeping for
    /// visibility, not the enforcement mechanism itself) — this is what lets
    /// [`Self::expire_superseded_and_trashed_versions`] stay correct even if
    /// the coordination-worker/local TTL sweeps haven't run yet.
    ///
    /// `now_unix_seconds` (not nanos, unlike most timestamps elsewhere in
    /// this module): `handoff_leases.expires_at_unix` holds a target-local
    /// unix-*seconds* deadline (this device's own clock at pin time + the
    /// grant's TTL duration + a fixed safety margin — see
    /// [`Self::record_handoff_lease_atomic`]), so the comparison here is
    /// against this same device's own clock, in seconds; callers must
    /// convert their nanos clock before calling this (see
    /// [`Self::expire_superseded_and_trashed_versions`]'s call site).
    fn leased_version_keys_for_group(
        &self,
        group_id: &str,
        now_unix_seconds: i64,
    ) -> Result<HashSet<(String, i64)>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT pinned_versions_json FROM handoff_leases \
             WHERE group_id = ?1 AND state IN ('provisional', 'confirmed') \
               AND expires_at_unix > ?2",
        )?;
        let mut pinned = HashSet::new();
        let rows = stmt
            .query_map(rusqlite::params![group_id, now_unix_seconds], |r| r.get::<_, String>(0))?;
        for row in rows {
            let json = row?;
            let versions: Vec<(String, i64)> = serde_json::from_str(&json)?;
            pinned.extend(versions);
        }
        Ok(pinned)
    }

    /// Atomically re-confirms `expected_digest` against `group_id`'s CURRENT
    /// durability-root set and, only if it still matches, flips `local_path`'s
    /// materialization policy to `policy` — both inside a single write
    /// transaction, so no concurrent index write (a watcher-driven local edit)
    /// can land between the re-check and the commit. This is the atomic
    /// counterpart to reading a digest, comparing it, and writing separately:
    /// there the tiny window between the read and the write could admit an
    /// interleaved `files` change that the just-confirmed peer never covered.
    ///
    /// Returns `Ok(true)` if the digest still matched and the policy was
    /// committed, `Ok(false)` if the digest no longer matches (the set moved
    /// after the peer confirmation; nothing is written — fail closed). `Err`
    /// only for a genuine storage error.
    ///
    /// This protects the coordination-plane ROLE flip (eager -> on-demand)
    /// from racing a durability-set change. It is NOT what protects actual
    /// block deletion: reclaiming a specific version's blocks stays
    /// separately gated, per file, by the on-demand eviction custody check
    /// (`confirm_version_present_via_peer` / `holds_version_durably` with
    /// `for_handoff = false`), which is the real backstop against dropping the
    /// last copy of any one version.
    pub fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            // IMMEDIATE takes SQLite's write lock at BEGIN, so the digest
            // re-enumeration below and the policy UPDATE observe one snapshot
            // that no other connection's `files` write can mutate until this
            // transaction commits — the atomicity the separate read-then-write
            // path lacked.
            let tx = new_immediate_write_transaction(&mut conn)?;
            let current = enumerate_group_durability_roots_on_conn(&tx, group_id)?;
            if current.digest != expected_digest {
                // Set moved since the peer confirmation; commit nothing.
                return Ok(false);
            }
            // `orphaned = 0`: an orphaned link's authorization is permanently
            // gone, so its storage-mode role must not be flippable as if live,
            // even on this digest-guarded path.
            let affected = tx.execute(
                "UPDATE links SET materialization_policy = ?1 \
                 WHERE local_path = ?2 AND orphaned = 0",
                rusqlite::params![policy.as_db_str(), local_path],
            )?;
            if affected == 0 {
                return Err(SyncError::NotFound(format!("link {local_path}")));
            }
            tx.commit()?;
            Ok(true)
        })
    }

    /// Atomically re-confirms `expected_digest` against `group_id`'s CURRENT
    /// durability-root set and, only if it still matches, removes `local_path`'s
    /// link row — both inside one write transaction, so no concurrent index
    /// write can interleave between the re-check and the removal. See
    /// [`Self::recheck_digest_then_set_materialization_policy`] for the full
    /// rationale (this is the unlink counterpart of the demote commit) and the
    /// same "protects the role flip, not block deletion" caveat.
    ///
    /// Returns `Ok(true)` if the digest still matched and the link was removed,
    /// `Ok(false)` if the digest no longer matches (nothing removed — fail
    /// closed). A `local_path` with no link row that nonetheless passes the
    /// digest check returns `Ok(true)` (removing an absent row is a no-op),
    /// matching [`Self::remove_link`]'s own idempotent delete.
    pub fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool, SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let current = enumerate_group_durability_roots_on_conn(&tx, group_id)?;
            if current.digest != expected_digest {
                return Ok(false);
            }
            tx.execute("DELETE FROM links WHERE local_path = ?1", [local_path])?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// Opens a new role-loss-operation journal row in `Prepared` state,
    /// BEFORE the coordination-worker role-loss commit the caller is about
    /// to attempt — see [`RoleLossOperation`]'s doc comment. Replaces any
    /// existing row with the same `operation_id` (callers here always
    /// generate a fresh random id per attempt, so this is
    /// belt-and-suspenders, matching [`Self::record_handoff_lease`]'s own
    /// idempotent-upsert idiom).
    pub fn insert_role_loss_operation(
        &self,
        operation_id: &str,
        group_id: &str,
        op: RoleLossOperationParams<'_>,
    ) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT INTO role_loss_operations \
                (operation_id, group_id, source_device_id, target_device_id, lease_id, \
                 worker_membership_generation, action, state, local_path, attempts, \
                 created_at_unix, updated_at_unix) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 'prepared', ?7, 0, ?8, ?8) \
             ON CONFLICT(operation_id) DO UPDATE SET \
                group_id = excluded.group_id, source_device_id = excluded.source_device_id, \
                target_device_id = excluded.target_device_id, lease_id = excluded.lease_id, \
                worker_membership_generation = NULL, action = excluded.action, \
                state = 'prepared', local_path = excluded.local_path, attempts = 0, \
                created_at_unix = excluded.created_at_unix, \
                updated_at_unix = excluded.updated_at_unix",
            rusqlite::params![
                operation_id,
                group_id,
                op.source_device_id,
                op.target_device_id,
                op.lease_id,
                op.action.as_db_str(),
                op.local_path,
                op.now_unix,
            ],
        )?;
        Ok(())
    }

    pub fn mark_role_loss_worker_committed(
        &self,
        operation_id: &str,
        membership_generation: i64,
        now_unix: i64,
    ) -> Result<bool, SyncError> {
        let changed = self.pool.get()?.execute(
            "UPDATE role_loss_operations SET state = 'worker_committed', \
             worker_membership_generation = ?1, updated_at_unix = ?2 \
             WHERE operation_id = ?3",
            rusqlite::params![membership_generation, now_unix, operation_id],
        )?;
        Ok(changed > 0)
    }

    pub fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "INSERT OR IGNORE INTO durability_unknown_latches (group_id) VALUES (?1)",
            rusqlite::params![group_id],
        )?;
        Ok(())
    }

    pub fn clear_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError> {
        self.pool.get()?.execute(
            "DELETE FROM durability_unknown_latches WHERE group_id = ?1",
            rusqlite::params![group_id],
        )?;
        Ok(())
    }

    pub fn list_durability_unknown_latches(&self) -> Result<Vec<String>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT group_id FROM durability_unknown_latches ORDER BY group_id")?;
        let groups = stmt.query_map([], |row| row.get(0))?.collect::<Result<Vec<_>, _>>()?;
        Ok(groups)
    }

    /// Advances a role-loss-operation journal row to `new_state`. Returns
    /// `Ok(false)` if `operation_id` no longer names a row (already deleted
    /// by a concurrent completion or by the reconciliation sweep) — every
    /// caller here treats that as a benign no-op rather than an error.
    pub fn advance_role_loss_operation(
        &self,
        operation_id: &str,
        new_state: RoleLossOperationState,
        now_unix: i64,
    ) -> Result<bool, SyncError> {
        let changed = self.pool.get()?.execute(
            "UPDATE role_loss_operations SET state = ?1, updated_at_unix = ?2 \
             WHERE operation_id = ?3",
            rusqlite::params![new_state.as_db_str(), now_unix, operation_id],
        )?;
        Ok(changed > 0)
    }

    /// Deletes a role-loss-operation journal row — called once its outcome
    /// is fully settled: a normal success (`LocalCommitted`), or a
    /// compensation that completed (`Completed`). Idempotent: deleting an
    /// already-absent row is a no-op, matching [`Self::remove_link`]'s own
    /// idempotent delete.
    pub fn delete_role_loss_operation(&self, operation_id: &str) -> Result<(), SyncError> {
        self.pool
            .get()?
            .execute("DELETE FROM role_loss_operations WHERE operation_id = ?1", [operation_id])?;
        Ok(())
    }

    /// Bumps a role-loss-operation's retry counter and returns the NEW
    /// attempt count — used by the reconciliation sweep
    /// (`daemon_state::run_role_loss_reconciliation_sweep`) purely to log an
    /// escalation past a bounded number of attempts. This never gates
    /// whether a retry happens: a `Compensating` row is retried
    /// indefinitely regardless of `attempts`, since giving up would leave
    /// the split state uncorrected forever (see that sweep's own doc
    /// comment).
    pub fn increment_role_loss_operation_attempts(
        &self,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<i64, SyncError> {
        let attempts: i64 = self.pool.get()?.query_row(
            "UPDATE role_loss_operations SET attempts = attempts + 1, updated_at_unix = ?1 \
             WHERE operation_id = ?2 RETURNING attempts",
            rusqlite::params![now_unix, operation_id],
            |r| r.get(0),
        )?;
        Ok(attempts)
    }

    /// Reads a single role-loss-operation row by id, if it still exists.
    pub fn get_role_loss_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<RoleLossOperation>, SyncError> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                    worker_membership_generation, action, state, local_path, attempts, \
                    created_at_unix, updated_at_unix \
             FROM role_loss_operations WHERE operation_id = ?1",
        )?;
        let mut rows = stmt.query_map([operation_id], row_to_role_loss_operation)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Every role-loss-operation row currently in one of `states` —
    /// consulted by the startup + periodic reconciliation sweep
    /// (`daemon_state::run_role_loss_reconciliation_sweep`), which does not
    /// filter by group id (a crash can leave a stale row behind for any
    /// group this device was ever the source of a handoff for).
    pub fn list_role_loss_operations_in_states(
        &self,
        states: &[RoleLossOperationState],
    ) -> Result<Vec<RoleLossOperation>, SyncError> {
        if states.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = states.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT operation_id, group_id, source_device_id, target_device_id, lease_id, \
                    worker_membership_generation, action, state, local_path, attempts, \
                    created_at_unix, updated_at_unix \
             FROM role_loss_operations WHERE state IN ({placeholders}) \
             ORDER BY created_at_unix"
        );
        let state_strs: Vec<&str> = states.iter().map(|s| s.as_db_str()).collect();
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(state_strs.iter()), row_to_role_loss_operation)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// Shared enumeration of `group_id`'s durability roots over an arbitrary
/// connection (a pooled read connection, or a write transaction for the
/// atomic re-check-and-commit paths). See
/// [`SyncState::enumerate_group_durability_roots`] for the category
/// semantics; keeping the query in one place guarantees the digest the
/// atomic commit re-checks is computed exactly like the one the readiness
/// check first captured.
fn enumerate_group_durability_roots_on_conn(
    conn: &Connection,
    group_id: &str,
) -> Result<DurabilityRoots, SyncError> {
    // `record_kind = 'file'` in the WHERE clause is also the source of truth
    // for the `FileMeta` reconstructed below: every row this query returns is
    // already known to be a regular file, so `record_kind` is `RecordKind::
    // File` and `symlink_target` is `None` by construction — no need to read
    // either column back out.
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, blocks_json, exec_bit FROM files \
         WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
           AND state IN ('current', 'superseded', 'trashed') \
         ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut roots = Vec::new();
    for row in rows {
        let (path, size, mtime_unix_nanos, blocks_json, exec_bit) = row?;
        // A malformed stored block list is locally-corrupt state — report it as
        // `CorruptState` (like every other malformed-block-list path) rather
        // than letting the bare `?` classify it as a generic `Json`/protocol
        // error.
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            SyncError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
        })?;
        // Reconstruct the exact `FileVersion` this row describes and derive
        // its `version_hash` via the SAME `compute_hash()` the change-DAG
        // itself hashes versions with — see `FileVersion::from_index_row`.
        let version = FileVersion::from_index_row(
            blocks,
            size,
            mtime_unix_nanos,
            RecordKind::File,
            exec_bit != 0,
            None,
        );
        roots.push(DurabilityRoot {
            path,
            blocks: version.blocks,
            version_hash: version.version_hash,
        });
    }
    let digest = durability_roots_digest(&roots);
    Ok(DurabilityRoots { roots, digest })
}

// --- History-compaction store wiring ---
//
// The compaction policy in `crate::compaction` is storage-agnostic: it drives
// three narrow traits over the change store. `SyncState` is that store, so it
// implements them by delegating to the same `dag_store` primitives the rest of
// the DAG engine uses. Group identity crosses this seam as a `&FolderGroupId`
// (compaction's currency); each method passes its `.as_str()` down to the
// `&str`-keyed `dag_store` layer, so nothing in `dag_store` changed shape.

impl CompactionDagStore for SyncState {
    fn heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, SyncError> {
        dag_store::group_heads(&*self.pool.get()?, group.as_str())
    }

    fn parents(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        // Change hashes are content-addressed and globally unique, so the edge
        // set is keyed by hash alone; a hash the store no longer holds has no
        // rows, so this returns empty and an ancestry walk stops at the prune
        // boundary — exactly the contract compaction relies on.
        dag_store::parents_of(&*self.pool.get()?, change)
    }

    fn contains_change(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<bool, SyncError> {
        dag_store::has_change(&*self.pool.get()?, change)
    }
}

impl DeviceFrontierStore for SyncState {
    fn set_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), SyncError> {
        // The replace (delete + per-head insert) runs in one transaction so a
        // reader never observes a partially-rewritten frontier.
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            dag_store::set_device_frontier(&tx, group.as_str(), device.as_str(), frontier)?;
            tx.commit()?;
            Ok(())
        })
    }

    fn get_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        dag_store::get_device_frontier(&*self.pool.get()?, group.as_str(), device.as_str())
    }

    fn remove_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<(), SyncError> {
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            dag_store::remove_device_frontier(&tx, group.as_str(), device.as_str())?;
            tx.commit()?;
            Ok(())
        })
    }
}

impl CheckpointStore for SyncState {
    fn latest_checkpoint(&self, group: &FolderGroupId) -> Result<Option<Checkpoint>, SyncError> {
        dag_store::latest_checkpoint(&*self.pool.get()?, group.as_str())
    }

    fn commit_prune(
        &self,
        checkpoint: &Checkpoint,
        pruned: &[ChangeHash],
    ) -> Result<(), SyncError> {
        // The whole prune — checkpoint insert plus every delete from `changes`,
        // `change_parents`, and `group_heads` — commits in a single transaction,
        // so a crash can never leave history half-pruned.
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            dag_store::commit_prune(&tx, checkpoint, pruned)?;
            tx.commit()?;
            Ok(())
        })
    }

    fn history_base_previous_checkpoint_hash(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<[u8; 32]>, SyncError> {
        SyncState::history_base_previous_checkpoint_hash(self, group.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderLink {
    pub local_path: String,
    pub group_id: String,
    pub paused: bool,
    pub materialization_policy: MaterializationPolicy,
    /// Automatic-eviction disk-usage cap in bytes, if configured.
    pub max_local_size_bytes: Option<i64>,
    /// Whether this link's coordination-side authorization has been
    /// confirmed permanently gone (its group/ACL row was cancelled or
    /// removed server-side) -- distinct from `paused`, which is a
    /// reversible, user-chosen sync gate that leaves the coordination-side
    /// authorization intact. Set only once reconciliation confirms the
    /// activation for this link's [`PendingEnrollment`] came back `Deleted`
    /// -- see [`SyncState::mark_link_orphaned`]. An orphaned link's on-disk
    /// files are never touched or deleted; only its participation in sync
    /// stops.
    pub orphaned: bool,
}

/// The link table's verdict on whether this device may apply a peer change to
/// a folder group, and -- when it may -- the two things the apply path needs
/// from the link row: where to write, and how much to materialize. See
/// [`SyncState::link_gate_for_group`].
///
/// Deliberately an enum rather than an `Option<FolderLink>`: "no live link"
/// is a *verdict* the caller must handle, not an absence it may paper over
/// with a default. Every by-`group_id` link lookup this type replaces
/// returned an `Option`/`bool` that a caller resolved permissively
/// (`unwrap_or(Eager)`, `unwrap_or(0) != 0`), so a deleted link row read as
/// "unpaused, eager" -- i.e. an unlinked folder was the *most* permissive
/// state in the table, and a live peer session went on writing into (and
/// deleting inside) a folder the user had detached. There is no correct
/// permissive default here, so this type offers none: a caller that wants to
/// write must match [`LinkGate::Live`] and thereby prove a live link exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGate {
    /// A live, unpaused, non-orphaned link. `local_path` is the root the
    /// apply must write under -- read from the row on this lookup rather than
    /// remembered from an earlier one, so a session can never write to a root
    /// the link table no longer names.
    Live { local_path: String, policy: MaterializationPolicy },
    /// A live link the user paused. Pause stops both directions, but is
    /// reversible and leaves the link -- and its root -- in place, so this
    /// still names one: refusing to *sync* a paused folder is this gate's
    /// job, but the folder is still linked and still where the row says it
    /// is, which read-only callers (status, ignore-set loading) legitimately
    /// need to know. Only [`LinkGate::NoLiveLink`] means "this device has no
    /// folder for this group".
    Paused { local_path: String },
    /// No live link for this group on this device: never linked, unlinked,
    /// or orphaned. The apply must not touch the filesystem -- this device
    /// has no folder to legitimately write into.
    NoLiveLink,
}

/// One outstanding local link with an unconfirmed coordination-plane
/// activation -- the crash-safety net for a create/join whose local link
/// is already committed but whose matching server-side activation was
/// never confirmed (the caller was killed in that exact window). Persisted
/// in the same SQLite database as `FolderLink` so the two can be written in
/// a single transaction (`SyncState::add_link_with_pending_enrollment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub operation_id: String,
    pub kind: EnrollmentKind,
    pub group_id: String,
    pub device_id: String,
    pub local_path: String,
}

/// The fixed, built-in version-retention bounds applied to every link: a
/// superseded or trashed version is retained while it is within *either*
/// bound and expired only once it exceeds *both* (union-retain, intersection-
/// expire). The current/live version is never subject to retention. Retention
/// is not per-link configurable.
pub const RETENTION_MAX_VERSIONS: i64 = 10;
pub const RETENTION_MAX_AGE_DAYS: i64 = 30;

/// Which of the three states a `files` row is in.
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

/// The `state = 'current'` row of a file, read as one atomic statement by
/// [`SyncState::get_current_version_record`] — every column a `FileVersion`
/// identity binds, from a single coherent row so the derived
/// `change::VersionHash` can never be a torn hybrid of two rows.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentVersionRecord {
    pub blocks: Vec<BlockInfo>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub deleted: bool,
    pub record_kind: RecordKind,
    pub symlink_target: Option<String>,
    pub exec_bit: bool,
}

impl CurrentVersionRecord {
    /// Reconstructs the exact `FileVersion` this current row describes and
    /// derives its `change::VersionHash` via `FileVersion::compute_hash()`.
    /// Because every field came from one atomic read, the returned identity
    /// is always one a single row actually held.
    pub fn to_file_version(&self) -> FileVersion {
        FileVersion::from_index_row(
            self.blocks.clone(),
            self.size,
            self.mtime_unix_nanos,
            self.record_kind,
            self.exec_bit,
            self.symlink_target.clone(),
        )
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
    /// remote change. `None` for versions written before this
    /// change existed, or by a caller using the origin-agnostic
    /// `upsert_file` (design's honest "unknown origin" case).
    pub origin_device_id: Option<String>,
    /// This row's own per-row classification/metadata columns — carried per
    /// version (not just current, unlike `get_record_kind`/`get_symlink_
    /// target`/`get_exec_bit`, which only ever read the `current` row),
    /// since a retained superseded/trashed row can predate a later metadata
    /// change and must reconstruct as the `FileVersion` it actually was.
    pub record_kind: RecordKind,
    pub symlink_target: Option<String>,
    pub exec_bit: bool,
    /// The [`change::VersionHash`] of this exact version — SHA-256 of the
    /// canonical `FileVersion` encoding reconstructed from this row's own
    /// columns (see [`FileVersion::from_index_row`]). This is the same hash
    /// the change-DAG uses to identify a version; the peer version-present
    /// responder compares an incoming query's hash against this field rather
    /// than against a separately derived identifier.
    pub version_hash: VersionHash,
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

/// A full-replica-handoff lease this device holds as the handoff TARGET,
/// issued by coordination-worker once this device's own local readiness
/// check confirmed it holds every durability root of the group it is
/// taking over full-replica responsibility for. The lease pins the exact
/// `pinned_versions` rows against [`SyncState::expire_superseded_and_
/// trashed_versions`] for as long as it stays `Provisional`/`Confirmed`,
/// closing the window between "target verified it holds everything" and
/// "source's role-loss commit actually finalizes" during which this
/// device's own retention sweep could otherwise evict a superseded-but-
/// still-needed version out from under the in-flight handoff.
///
/// Lifecycle: a target requests a lease from coordination-worker after its
/// own local readiness check succeeds (`Provisional`); the source's
/// role-loss commit endpoint confirms it (`Confirmed`) atomically with
/// committing the role loss coordination-side; on any failure of that
/// commit — or if nothing ever reaches it — the lease is `Released` (an
/// explicit failure) or `Expired` (a coordination-worker TTL sweep, the
/// backstop for a target or source that crashes mid-handoff). Both
/// terminal-failure states stop the lease from pinning anything; retention
/// resumes normally for whatever it named. This type is only the local,
/// target-side half of the protocol: coordination-worker's own
/// `handoff_leases` table is the authoritative, race-safe home for the
/// lease's actual state transitions (issued, confirmed, released, expired)
/// — this local copy exists purely so this device's own retention sweep has
/// something to consult without a network round trip on every pass.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffLease {
    pub lease_id: String,
    pub group_id: String,
    /// The durability-root-set digest this lease was requested against —
    /// the same digest [`SyncState::enumerate_group_durability_roots`]
    /// would have produced at request time.
    pub root_digest: [u8; 32],
    pub state: HandoffLeaseState,
    /// The exact `(path, version_seq)` rows pinned against retention expiry
    /// — see [`SyncState::enumerate_group_durability_root_versions`].
    pub pinned_versions: Vec<(String, i64)>,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

/// Which state a [`HandoffLease`] is in — see its doc comment for the full
/// lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffLeaseState {
    /// Issued, not yet confirmed by the source's role-loss commit. Actively
    /// pins its versions.
    Provisional,
    /// The source's role-loss commit confirmed this lease coordination-side
    /// — the handoff completed. Actively pins its versions (until it is
    /// separately cleared/expires; a confirmed lease is not automatically
    /// released the instant it confirms, since the caller may still want a
    /// short grace window — see the design note).
    Confirmed,
    /// Explicitly released — the role-loss commit failed, or the local
    /// caller gave up. No longer pins anything.
    Released,
    /// Never confirmed within its TTL; swept by coordination-worker's TTL
    /// sweep. No longer pins anything.
    Expired,
}

impl HandoffLeaseState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            HandoffLeaseState::Provisional => "provisional",
            HandoffLeaseState::Confirmed => "confirmed",
            HandoffLeaseState::Released => "released",
            HandoffLeaseState::Expired => "expired",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "confirmed" => HandoffLeaseState::Confirmed,
            "released" => HandoffLeaseState::Released,
            "expired" => HandoffLeaseState::Expired,
            _ => HandoffLeaseState::Provisional,
        }
    }
}

fn row_to_handoff_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<HandoffLease> {
    let root_digest_vec: Vec<u8> = r.get(2)?;
    let mut root_digest = [0u8; 32];
    if root_digest_vec.len() == 32 {
        root_digest.copy_from_slice(&root_digest_vec);
    }
    let pinned_json: String = r.get(4)?;
    let pinned_versions: Vec<(String, i64)> =
        serde_json::from_str(&pinned_json).unwrap_or_default();
    Ok(HandoffLease {
        lease_id: r.get(0)?,
        group_id: r.get(1)?,
        root_digest,
        state: HandoffLeaseState::from_db_str(&r.get::<_, String>(3)?),
        pinned_versions,
        created_at_unix: r.get(5)?,
        expires_at_unix: r.get(6)?,
    })
}

/// A durable journal row for an in-flight full-replica role-loss operation
/// (demote/unlink) this device is driving as the SOURCE device. Written
/// before the coordination-worker role-loss commit
/// (`coordination_client::commit_handoff_role_loss`) and only removed once
/// the operation's outcome is fully settled, so a crash — or a local
/// failure landing AFTER the Worker commit already succeeded — is always
/// reconciled automatically instead of left as a silent split state (Worker
/// thinks this device demoted; local storage still thinks it's eager).
///
/// State machine:
///
/// ```text
/// Prepared ──(Worker returns definite 4xx rejection)──> [row deleted]
///     │
///     │ (Worker commit succeeds OR response is ambiguous/lost)
///     v
/// WorkerCommitted/Prepared ──(local commit succeeds)──> LocalCommitted ──> [row deleted]
///     │
///     │ (local commit fails: digest mismatch or a storage error)
///     v
/// Compensating ──(Worker revert succeeds)──> Completed ──> [row deleted]
///     │
///     │ (Worker revert fails / unreachable)
///     v
/// Compensating (retried by the reconciliation sweep, never abandoned)
/// ```
///
/// `LocalCommitted` and `Completed` are terminal and are deleted
/// immediately after being written on the normal path; they only persist
/// across a restart if the process crashed in the narrow window between
/// that write and the follow-up delete, in which case the reconciliation
/// sweep's own handling of them is a plain delete (see that sweep's doc
/// comment) — the operation's real outcome was already reached by the
/// preceding write.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleLossOperation {
    pub operation_id: String,
    pub group_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub lease_id: Option<String>,
    pub worker_membership_generation: Option<i64>,
    pub action: RoleLossAction,
    pub state: RoleLossOperationState,
    /// The local link path this operation concerns, when known (unlink
    /// always has one; demote does too, since it also flips a specific
    /// link's materialization policy).
    pub local_path: Option<String>,
    pub attempts: i64,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Which local operation this device was performing when it drove the
/// Worker-side role-loss commit — recorded for diagnosis/logging.
/// `commit_handoff_role_loss`'s Worker-side statement is `"demote"` for
/// both `Demote` and `Unlink` today (both only narrow this device's
/// `storage_mode` to on-demand; unlink does not remove group membership),
/// so both compensate identically — reverting `storage_mode` back to
/// `eager` — see `daemon_state::compensate_role_loss_operation`. `Revoke`
/// is reserved for `durability_force`'s cross-device removal path, which
/// this change does not wire to this journal (that path still uses the
/// pre-existing plain `/revoke` call, not `commit_handoff_role_loss`); a
/// row is never written with this action today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossAction {
    Demote,
    Unlink,
    Revoke,
}

impl RoleLossAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossAction::Demote => "demote",
            RoleLossAction::Unlink => "unlink",
            RoleLossAction::Revoke => "revoke",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "unlink" => RoleLossAction::Unlink,
            "revoke" => RoleLossAction::Revoke,
            _ => RoleLossAction::Demote,
        }
    }
}

/// Which state a [`RoleLossOperation`] is in — see its doc comment for the
/// full state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossOperationState {
    /// Journal row written; the coordination-worker role-loss commit has
    /// not yet been attempted (or its outcome is not yet known to this
    /// process — e.g. a crash mid-request). The reconciliation sweep
    /// treats a `Prepared` row found at startup the same as
    /// `WorkerCommitted`: it cannot locally distinguish "the request never
    /// reached the Worker" from "it reached and committed but the reply
    /// was lost", and asserting `eager` on the Worker is safe either way
    /// (a no-op if the Worker never committed, a correcting revert if it
    /// did) — see that sweep's doc comment.
    Prepared,
    /// The coordination-worker role-loss commit succeeded; the matching
    /// local policy/link change has not yet been attempted (or its outcome
    /// is not yet known — the crash-between-Worker-commit-and-local-commit
    /// case the whole journal exists for).
    WorkerCommitted,
    /// The local policy/link change also succeeded — the operation
    /// completed normally. Terminal; the row is deleted immediately after
    /// this state is written.
    LocalCommitted,
    /// The local change failed (digest mismatch or a storage error) after
    /// the Worker commit already succeeded; a compensating revert (Worker
    /// `storage_mode` back to `eager`) is in flight or pending retry.
    /// Never abandoned: the reconciliation sweep retries a `Compensating`
    /// row indefinitely until the revert is confirmed.
    Compensating,
    /// The compensating revert succeeded — the split state was corrected
    /// and the source device is confirmed `eager` again, both locally and
    /// on the Worker. Terminal; the row is deleted immediately after this
    /// state is written.
    Completed,
}

impl RoleLossOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossOperationState::Prepared => "prepared",
            RoleLossOperationState::WorkerCommitted => "worker_committed",
            RoleLossOperationState::LocalCommitted => "local_committed",
            RoleLossOperationState::Compensating => "compensating",
            RoleLossOperationState::Completed => "completed",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "worker_committed" => RoleLossOperationState::WorkerCommitted,
            "local_committed" => RoleLossOperationState::LocalCommitted,
            "compensating" => RoleLossOperationState::Compensating,
            "completed" => RoleLossOperationState::Completed,
            _ => RoleLossOperationState::Prepared,
        }
    }
}

fn row_to_role_loss_operation(r: &rusqlite::Row<'_>) -> rusqlite::Result<RoleLossOperation> {
    Ok(RoleLossOperation {
        operation_id: r.get(0)?,
        group_id: r.get(1)?,
        source_device_id: r.get(2)?,
        target_device_id: r.get(3)?,
        lease_id: r.get(4)?,
        worker_membership_generation: r.get(5)?,
        action: RoleLossAction::from_db_str(&r.get::<_, String>(6)?),
        state: RoleLossOperationState::from_db_str(&r.get::<_, String>(7)?),
        local_path: r.get(8)?,
        attempts: r.get(9)?,
        created_at_unix: r.get(10)?,
        updated_at_unix: r.get(11)?,
    })
}

/// One user-recoverable durability root — one retained version at `path`
/// (current, superseded, or trashed) a full-replica handoff must be able to
/// hand off. `version_hash` is the [`change::VersionHash`] — the SHA-256 of
/// this version's canonical `FileVersion` encoding (its ordered block list
/// with each block's size, its total size, and its metadata: mtime, exec
/// bit, symlink target, record kind) — computed by reconstructing a
/// `FileVersion` from this row via [`FileVersion::from_index_row`] and
/// calling `compute_hash()`. This is the SAME hash the change-DAG itself
/// uses to identify a version; durability never invents a separate wire
/// identifier. `blocks` is carried alongside (not folded away once the hash
/// is known) because a peer confirmation still needs the ordered block list
/// — with per-block sizes — for its own explicit block/size check and its
/// `get()` checksum-verification loop. See
/// [`SyncState::enumerate_group_durability_roots`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoot {
    pub path: String,
    pub blocks: Vec<VersionBlock>,
    pub version_hash: VersionHash,
}

/// The result of [`SyncState::enumerate_group_durability_roots`]: the full
/// root set plus a stable digest over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoots {
    pub roots: Vec<DurabilityRoot>,
    /// SHA-256 over the roots sorted by `(path, version_hash)`. Stable
    /// regardless of the order SQL returns rows in, so two enumerations of
    /// the same underlying set produce the same digest. `version_hash` binds
    /// the ordered block list, each block's size, and the version's
    /// metadata, so a chunk reorder or a metadata-only change (mtime, exec
    /// bit, symlink target, record kind) changes the digest exactly as it
    /// changes the version identity a peer confirms against. See
    /// [`durability_roots_digest`].
    pub digest: [u8; 32],
}

/// Canonicalizes `roots` and hashes the length-prefixed concatenation.
/// Order-independence is applied only ACROSS roots (sorted by `(path,
/// version_hash)`), so the caller's collection order does not affect the
/// digest. Each root's identity is its `version_hash` alone — the SHA-256 of
/// its canonical `FileVersion` encoding, which already binds the ordered
/// block list, each block's declared size, and the version's metadata, so
/// any real change to the underlying content or metadata (including a block
/// reorder) changes `version_hash` and therefore this digest. This is the
/// property the digest re-confirm before a daemon-driven role-loss commit
/// relies on: the same underlying set (same paths, same per-file version
/// identities) always digests the same, and any real change changes it.
fn durability_roots_digest(roots: &[DurabilityRoot]) -> [u8; 32] {
    let mut canonical: Vec<(&str, &[u8; 32])> =
        roots.iter().map(|r| (r.path.as_str(), r.version_hash.as_bytes())).collect();
    canonical.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));

    let mut hasher = Sha256::new();
    for (path, version_hash) in &canonical {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(version_hash.as_slice());
    }
    hasher.finalize().into()
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
    record_kind: &str,
    symlink_target: Option<String>,
    exec_bit: i64,
) -> Result<VersionRecord, SyncError> {
    // Fail closed on a corrupt `blocks_json` column rather than coercing it to
    // an empty block list. A silent default would mask genuine index/DB
    // corruption as a legitimately empty version; a valid `"[]"` still parses
    // to an empty list and stays a valid empty record — only an unparseable
    // column errors. Log the offending path so the corruption is diagnosable.
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list for a retained version is corrupt; failing closed");
        SyncError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    let record_kind = RecordKind::from_db_str(record_kind);
    let exec_bit = exec_bit != 0;
    // Derive this exact row's `version_hash` the same way the durability-root
    // enumeration does — reconstruct the `FileVersion` this row describes and
    // hash it via `compute_hash()` — so a caller comparing a peer's queried
    // hash against this field is comparing against the canonical identity,
    // never a value re-derived from a different subset of columns.
    let version_hash = FileVersion::from_index_row(
        blocks.clone(),
        size,
        mtime_unix_nanos,
        record_kind,
        exec_bit,
        symlink_target.clone(),
    )
    .version_hash;
    Ok(VersionRecord {
        path,
        version_seq,
        size,
        mtime_unix_nanos,
        blocks,
        deleted: deleted != 0,
        state: VersionState::from_db_str(state),
        origin_device_id,
        record_kind,
        symlink_target,
        exec_bit,
        version_hash,
    })
}

/// One candidate for the automatic eviction sweep, in the
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
) -> Result<FileRecord, SyncError> {
    // Fail closed on a corrupt stored version vector or block list rather than
    // coercing either to a default. A defaulted version vector would silently
    // reset causal history and a defaulted (empty) block list would read as
    // "file has no content" — both mask genuine index/DB corruption. Valid
    // `"{}"`/`"[]"` still parse to a valid empty record; only an unparseable
    // column errors. Log the offending path so the corruption is diagnosable.
    let counters = serde_json::from_str(version_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored version vector is corrupt; failing closed");
        SyncError::CorruptState(format!("stored version vector for {path} is corrupt: {error}"))
    })?;
    let blocks: Vec<BlockInfo> = serde_json::from_str(blocks_json).map_err(|error| {
        tracing::warn!(path = %path, %error, "stored block list is corrupt; failing closed");
        SyncError::CorruptState(format!("stored block list for {path} is corrupt: {error}"))
    })?;
    Ok(FileRecord {
        path,
        size,
        mtime_unix_nanos,
        version: VersionVector::from_counters(counters),
        blocks,
        deleted: deleted != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{BlockHash, FileMeta};

    #[test]
    fn duplicate_recovery_progress_is_durable_and_path_scoped() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("g", &sample_record("a.txt")).unwrap();
        state.upsert_file("g", &sample_record("b.txt")).unwrap();

        state.arm_duplicate_recovery_paths("g").unwrap();
        assert!(state.duplicate_recovery_pending("g").unwrap());
        state.resolve_duplicate_recovery_path("g", "a.txt").unwrap();
        assert!(state.duplicate_recovery_pending("g").unwrap());
        state.resolve_duplicate_recovery_path("g", "b.txt").unwrap();
        assert!(!state.duplicate_recovery_pending("g").unwrap());
    }

    /// A group with no link on this device has no startup to wait for, so
    /// `wait_group_ready` admits it immediately — the barrier never blocks a
    /// group that is not starting up.
    #[tokio::test]
    async fn startup_gate_admits_a_group_with_no_link() {
        let state = SyncState::open_in_memory().unwrap();
        tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("never-started"))
            .await
            .expect("a group with no link must be admitted immediately")
            .expect("a group with no link admits peer apply (Ok, not StartupFailed)");
    }

    /// A group with a LIVE link but no registered gate is a link whose startup
    /// never got off the ground — the folder was not scanned this boot, while
    /// the row stays live so the peer path still resolves a root for it. Peer
    /// apply must DEFER, not be admitted over content that was never indexed.
    ///
    /// This is the same state as the window between `add_link` committing the
    /// row and `start_link_watch` arming the gate; deferring there is free,
    /// because `StartupFailed` leaves the change for re-delivery.
    #[tokio::test]
    async fn startup_gate_defers_a_live_link_that_has_no_gate() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        let verdict =
            tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("group-1"))
                .await
                .expect(
                    "must resolve immediately, not park waiting for a gate that does not exist",
                );
        assert!(
            verdict.is_err(),
            "a live link with no startup gate must defer peer apply, not admit it"
        );
    }

    /// An orphaned link is not a live sync target — its watcher is deliberately
    /// never started, so it owes no startup and must not be treated as one
    /// pending forever.
    #[tokio::test]
    async fn startup_gate_admits_a_group_whose_only_link_is_orphaned() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("group-1"))
            .await
            .expect("must resolve immediately")
            .expect("an orphaned link owes no startup, so its group is admitted");
    }

    /// While startup is in progress the gate blocks; `mark_group_ready` releases it.
    #[tokio::test]
    async fn startup_gate_blocks_until_marked_ready() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let generation = state.begin_group_startup("g");

        // Closed: a wait must not complete on its own.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_group_ready("g"))
                .await
                .is_err(),
            "the gate must stay closed until startup is marked complete"
        );

        let waiter_state = state.clone();
        let waiter = tokio::spawn(async move { waiter_state.wait_group_ready("g").await.unwrap() });
        state.mark_group_ready("g", generation);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("marking the group ready must release the parked waiter")
            .unwrap();
    }

    /// A slow startup for one group must never block peer apply for an unrelated,
    /// already-ready group — the barrier is per-group, not global.
    #[tokio::test]
    async fn startup_gate_is_per_group() {
        let state = SyncState::open_in_memory().unwrap();
        state.begin_group_startup("slow");
        let fast_generation = state.begin_group_startup("fast");
        state.mark_group_ready("fast", fast_generation);

        // The ready group proceeds immediately even though `slow` is still closed.
        tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("fast"))
            .await
            .expect("a ready group must not be blocked by another group's startup")
            .expect("the ready group admits peer apply");
        // ...and `slow` is genuinely still closed.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_group_ready("slow"))
                .await
                .is_err(),
            "the still-starting group must remain closed"
        );
    }

    /// A completion carrying a superseded generation must be ignored — it must
    /// not open a barrier that a newer `begin_group_startup` has re-closed.
    /// This is the generation guard on `mark_group_ready` (defect: a stale
    /// completion opening a new startup's barrier).
    #[tokio::test]
    async fn old_startup_completion_must_not_open_new_generation() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let gen_old = state.begin_group_startup("g");
        // A newer startup (e.g. a relink) supersedes the old one before it
        // finished.
        let _gen_new = state.begin_group_startup("g");

        // The old generation now completes — a straggler. It must NOT open the
        // new generation's still-closed barrier.
        state.mark_group_ready("g", gen_old);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_group_ready("g"))
                .await
                .is_err(),
            "a stale completion for a superseded generation must not open the new gate"
        );
    }

    /// With two overlapping startups sharing a group, the barrier releases only
    /// after the LATEST generation completes; the older completion is a no-op.
    #[tokio::test]
    async fn overlapping_startups_release_only_after_latest_completion() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let gen_a = state.begin_group_startup("g"); // executor A
        let gen_b = state.begin_group_startup("g"); // executor B supersedes A

        // A parked waiter models a peer-apply call.
        let waiter_state = state.clone();
        let waiter = tokio::spawn(async move { waiter_state.wait_group_ready("g").await });

        // A finishes first, but it is stale — it must NOT release peer apply.
        state.mark_group_ready("g", gen_a);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_group_ready("g"))
                .await
                .is_err(),
            "the stale older completion must not release peer apply for the latest startup"
        );

        // The latest generation completes — only now is the waiter released.
        state.mark_group_ready("g", gen_b);
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the latest completion must release the parked waiter")
            .unwrap()
            .expect("wait must return Ok once the latest startup is ready");
    }

    /// A stale abort's guard-drop (an old, superseded executor failing) must
    /// NOT transition the NEW generation to `Failed` — proving the generation
    /// check guards `mark_group_failed` too, not only `mark_group_ready`.
    #[tokio::test]
    async fn aborted_old_startup_must_not_fail_new_generation() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());
        let gen_old = state.begin_group_startup("g");
        let gen_new = state.begin_group_startup("g");

        // The old executor was aborted; its guard drops and fails gen_old.
        state.mark_group_failed("g", gen_old, "old executor aborted");

        // gen_new is still `Starting`, NOT `Failed`: a waiter must park (block),
        // not error out with a stale `StartupFailed`.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), state.wait_group_ready("g"))
                .await
                .is_err(),
            "a stale abort must neither open nor fail the new generation's gate"
        );

        // The new generation completes normally and releases with Ok.
        state.mark_group_ready("g", gen_new);
        tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("g"))
            .await
            .expect("the new generation must release once ready")
            .expect("wait must return Ok, not a stale StartupFailed from the aborted generation");
    }

    /// A failed startup must not drop offline local edits: they live in the
    /// index and the dirty-path journal, independent of the gate, so a
    /// Failed→retry preserves them. Fail-closed only DEFERS peer apply.
    #[tokio::test]
    async fn failed_startup_preserves_offline_changes_until_retry() {
        let state = Arc::new(SyncState::open_in_memory().unwrap());

        // Stage an offline local edit, independent of the startup gate.
        let record = sample_record("offline.txt");
        state.upsert_file("g", &record).unwrap();
        state.record_dirty_path("g", "offline.txt", "modified", 0).unwrap();

        let gen1 = state.begin_group_startup("g");
        // Startup fails (e.g. its scan panicked or the journal redrive errored).
        state.mark_group_failed("g", gen1, "scan panicked");

        // Peer apply is fail-closed while the failure stands...
        let failed = tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("g"))
            .await
            .expect("a resolved failure must not hang")
            .expect_err("a failed startup must fail-close peer apply, not admit it");
        assert_eq!(failed.group_id, "g");

        // ...but the offline local edit and its dirty-journal entry are untouched.
        assert!(
            state.get_file("g", "offline.txt").unwrap().is_some(),
            "the offline local edit must survive the startup failure"
        );
        assert!(
            state.is_path_dirty("g", "offline.txt").unwrap(),
            "the dirty-journal entry must survive so a retry can re-drive it"
        );

        // A subsequent startup (retry / relink) supersedes the failure and, on
        // success, releases peer apply again.
        let gen2 = state.begin_group_startup("g");
        state.mark_group_ready("g", gen2);
        tokio::time::timeout(Duration::from_secs(5), state.wait_group_ready("g"))
            .await
            .expect("retry must resolve")
            .expect("retry success must release peer apply");

        // The local edit is STILL present after recovery — never dropped.
        assert!(
            state.get_file("g", "offline.txt").unwrap().is_some(),
            "the offline local edit must survive Failed→retry recovery"
        );
        assert!(
            state.is_path_dirty("g", "offline.txt").unwrap(),
            "the dirty-journal entry must still be present after recovery"
        );
    }

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

    /// Overwrite a stored column with unparseable JSON, standing in for genuine
    /// index/DB corruption of that column.
    fn corrupt_column(state: &SyncState, path: &str, column: &str) {
        state
            .pool
            .get()
            .unwrap()
            .execute(
                &format!("UPDATE files SET {column} = 'not valid json' WHERE path = ?1"),
                rusqlite::params![path],
            )
            .unwrap();
    }

    // --- `row_to_record` (feeds `get_file`, `list_files`, `get_files_by_paths`)
    //     must fail closed on a corrupt stored column, never mask it as an empty
    //     block list / defaulted version vector. ---

    #[test]
    fn get_file_fails_closed_on_corrupt_blocks_json() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.txt", 7)).unwrap();
        corrupt_column(&state, "file.txt", "blocks_json");
        let result = state.get_file("group-1", "file.txt");
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "corrupt blocks_json must fail closed, got {result:?}"
        );
    }

    #[test]
    fn get_file_fails_closed_on_corrupt_version_json() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.txt", 7)).unwrap();
        corrupt_column(&state, "file.txt", "version_json");
        let result = state.get_file("group-1", "file.txt");
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "corrupt version_json must fail closed, got {result:?}"
        );
    }

    #[test]
    fn get_file_keeps_valid_empty_record() {
        let state = SyncState::open_in_memory().unwrap();
        // `sample_record` has a valid but empty block list, stored as "[]".
        state.upsert_file("group-1", &sample_record("empty.txt")).unwrap();
        let record = state.get_file("group-1", "empty.txt").unwrap().unwrap();
        // A legitimately empty block list stays a valid empty record — only a
        // parse *failure* errors, never a valid `"[]"`.
        assert!(record.blocks.is_empty());
    }

    /// A SQLite error that is *not* `QueryReturnedNoRows` (here the `files`
    /// table is gone entirely, standing in for corruption / I/O / a locked
    /// database / a schema mismatch) must surface as an `Err`, never be
    /// silently collapsed into `Ok(None)`. This is the whole point of reading
    /// via `.optional()?` instead of `.ok()`: `.ok()` maps *every* error to
    /// `None`, and a masked `None` from `get_file` makes the local-change path
    /// treat an existing file as brand-new — emitting a spurious `Create` and a
    /// fresh version vector that diverges from peers. The genuinely-absent path
    /// still reads back as `Ok(None)`.
    #[test]
    fn get_file_propagates_non_no_row_errors() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("present.txt")).unwrap();

        // "No row" is not an error: an absent path is still `Ok(None)`.
        assert!(
            matches!(state.get_file("group-1", "absent.txt"), Ok(None)),
            "a genuinely absent path must read back as Ok(None), not an error"
        );

        // Remove the backing table so the next read hits a real SQLite error
        // ("no such table") rather than an empty result set. Pooled
        // connections share one in-memory database, so this is visible to the
        // connection `get_file` checks out.
        state.pool.get().unwrap().execute_batch("DROP TABLE files").unwrap();

        let result = state.get_file("group-1", "present.txt");
        assert!(
            result.is_err(),
            "a non-QueryReturnedNoRows SQLite error must propagate rather than \
             collapse into Ok(None) (which would emit a spurious Create); got {result:?}"
        );
    }

    #[test]
    fn list_files_fails_the_whole_listing_closed_on_one_corrupt_row() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.txt", 1)).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("b.txt", 2)).unwrap();
        corrupt_column(&state, "b.txt", "blocks_json");
        // One corrupt row fails the whole listing closed rather than silently
        // dropping content or emitting a defaulted record.
        let result = state.list_files("group-1");
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "one corrupt row must fail the whole listing closed, got {result:?}"
        );
    }

    // --- `version_record` (feeds `list_versions` / `get_version`) must fail
    //     closed on a corrupt stored block list. ---

    #[test]
    fn list_versions_fails_closed_on_corrupt_blocks_json() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.txt", 7)).unwrap();
        corrupt_column(&state, "file.txt", "blocks_json");
        let result = state.list_versions("group-1", "file.txt");
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "corrupt blocks_json must fail closed, got {result:?}"
        );
    }

    #[test]
    fn list_versions_keeps_valid_empty_record() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("empty.txt")).unwrap();
        let versions = state.list_versions("group-1", "empty.txt").unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].blocks.is_empty());
    }

    // --- `get_current_version_record` (durability custody read) must fail
    //     closed on a corrupt stored block list. ---

    #[test]
    fn get_current_version_record_fails_closed_on_corrupt_blocks_json() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.txt", 7)).unwrap();
        corrupt_column(&state, "file.txt", "blocks_json");
        let result = state.get_current_version_record("group-1", "file.txt");
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "corrupt blocks_json must fail closed, got {result:?}"
        );
    }

    #[test]
    fn get_current_version_record_keeps_valid_empty_record() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("empty.txt")).unwrap();
        let record = state.get_current_version_record("group-1", "empty.txt").unwrap().unwrap();
        assert!(record.blocks.is_empty());
    }

    #[test]
    fn current_version_record_errors_on_corrupt_blocks_json() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.txt", 7)).unwrap();
        // Corrupt the stored block list so it can no longer be parsed. This
        // stands in for genuine index/DB corruption.
        state
            .pool
            .get()
            .unwrap()
            .execute(
                "UPDATE files SET blocks_json = 'not valid json' \
                 WHERE group_id = 'group-1' AND path = 'file.txt' AND state = 'current'",
                [],
            )
            .unwrap();
        let result = state.get_current_version_record("group-1", "file.txt");
        // Fail closed: a corrupt column must surface as an error, NOT be
        // masked as a record with an empty block list.
        assert!(
            matches!(result, Err(SyncError::CorruptState(_))),
            "corrupt blocks_json must fail closed, got {result:?}"
        );
    }

    #[test]
    fn current_version_record_keeps_valid_empty_block_list() {
        let state = SyncState::open_in_memory().unwrap();
        // `sample_record` has an empty (but valid) block list, stored as "[]".
        state.upsert_file("group-1", &sample_record("empty.txt")).unwrap();
        let current = state.get_current_version_record("group-1", "empty.txt").unwrap().unwrap();
        // A legitimately empty block list stays a valid empty record — only a
        // parse *failure* errors, never a valid `"[]"`.
        assert!(current.blocks.is_empty());
    }

    #[test]
    fn path_lock_reuses_the_same_lock_while_it_is_live() {
        let state = SyncState::open_in_memory().unwrap();
        let first = state.path_lock("group-1", "file.txt");
        let second = state.path_lock("group-1", "file.txt");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(state.path_locks.lock().unwrap().len(), 1);
    }

    #[test]
    fn path_lock_registry_prunes_paths_that_are_no_longer_live() {
        let state = SyncState::open_in_memory().unwrap();
        let old = state.path_lock("group-1", "deleted.txt");
        let old_weak = Arc::downgrade(&old);
        drop(old);
        assert!(old_weak.upgrade().is_none());

        let _current = state.path_lock("group-1", "current.txt");
        let locks = state.path_locks.lock().unwrap();
        assert_eq!(locks.len(), 1);
        assert!(!locks.contains_key(&("group-1".to_string(), "deleted.txt".to_string())));
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

    fn sample_marker(operation_id: &str) -> PendingEnrollment {
        PendingEnrollment {
            operation_id: operation_id.to_string(),
            kind: EnrollmentKind::Create,
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
        }
    }

    /// pending-enrollment marker round-trip: record, list, remove.
    #[test]
    fn pending_enrollment_record_list_remove_round_trips() {
        let state = SyncState::open_in_memory().unwrap();
        state.record_pending_enrollment(&sample_marker("op-1")).unwrap();
        state
            .record_pending_enrollment(&{
                let mut m = sample_marker("op-2");
                m.kind = EnrollmentKind::Join;
                m.group_id = "group-2".to_string();
                m
            })
            .unwrap();

        let markers = state.list_pending_enrollments().unwrap();
        assert_eq!(markers.len(), 2);
        assert!(markers
            .iter()
            .any(|m| m.operation_id == "op-1" && m.kind == EnrollmentKind::Create));
        assert!(markers.iter().any(|m| m.operation_id == "op-2" && m.kind == EnrollmentKind::Join));

        state.remove_pending_enrollment("op-1").unwrap();
        let markers = state.list_pending_enrollments().unwrap();
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].operation_id, "op-2");
    }

    /// Re-recording the same `operation_id` overwrites rather than
    /// duplicates, matching `add_link`'s own `INSERT OR REPLACE` semantics.
    #[test]
    fn pending_enrollment_recording_the_same_operation_id_twice_replaces() {
        let state = SyncState::open_in_memory().unwrap();
        state.record_pending_enrollment(&sample_marker("op-1")).unwrap();
        state
            .record_pending_enrollment(&{
                let mut m = sample_marker("op-1");
                m.local_path = "/home/alice/Elsewhere".to_string();
                m
            })
            .unwrap();

        let markers = state.list_pending_enrollments().unwrap();
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].local_path, "/home/alice/Elsewhere");
    }

    /// The atomic write `add_link_with_pending_enrollment` performs: both
    /// rows land together on success.
    #[test]
    fn add_link_with_pending_enrollment_writes_both_rows_together() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .add_link_with_pending_enrollment(
                "/home/alice/Photos",
                "group-1",
                &sample_marker("op-1"),
            )
            .unwrap();

        assert_eq!(state.list_links().unwrap().len(), 1);
        assert_eq!(state.list_pending_enrollments().unwrap().len(), 1);
    }

    /// A pending-enrollment write failure must prevent the local link from
    /// being created at all -- the whole point of wrapping both writes in
    /// one transaction. Simulated by dropping the `pending_enrollments`
    /// table out from under the connection before the call, so its insert
    /// fails and the transaction rolls back; the `links` insert that would
    /// otherwise have landed must never be visible afterward.
    #[test]
    fn add_link_with_pending_enrollment_failure_rolls_back_the_link_too() {
        let state = SyncState::open_in_memory().unwrap();
        state.pool.get().unwrap().execute_batch("DROP TABLE pending_enrollments").unwrap();

        let result = state.add_link_with_pending_enrollment(
            "/home/alice/Photos",
            "group-1",
            &sample_marker("op-1"),
        );

        assert!(result.is_err(), "the pending-enrollment insert must fail with no such table");
        assert!(
            state.list_links().unwrap().is_empty(),
            "the link must not exist when its pending-enrollment write failed"
        );
    }

    /// An orphaned link keeps its on-disk files (this table records no
    /// on-disk state at all, only bookkeeping -- `orphaned` never triggers a
    /// filesystem delete) and is distinguishable from both an ordinary
    /// active link and a merely paused one.
    #[test]
    fn mark_link_orphaned_flips_only_that_link_and_leaves_paused_independent() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.add_link("/home/alice/Docs", "group-2").unwrap();
        state.set_paused("/home/alice/Docs", true).unwrap();

        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        let links = state.list_links().unwrap();
        let photos = links.iter().find(|l| l.local_path == "/home/alice/Photos").unwrap();
        let docs = links.iter().find(|l| l.local_path == "/home/alice/Docs").unwrap();
        assert!(photos.orphaned, "Photos was explicitly marked orphaned");
        assert!(!photos.paused, "marking orphaned must not implicitly pause");
        assert!(!docs.orphaned, "Docs was never marked orphaned");
        assert!(docs.paused, "Docs' own paused flag must be unaffected by Photos' orphan mark");
    }

    #[test]
    fn mark_link_orphaned_on_an_unknown_path_errors() {
        let state = SyncState::open_in_memory().unwrap();
        assert!(state.mark_link_orphaned("/no/such/link").is_err());
    }

    /// The atomic write `orphan_link_and_remove_pending_enrollment` performs:
    /// both the orphan flag and the marker removal land together on success.
    #[test]
    fn orphan_link_and_remove_pending_enrollment_does_both_together() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.record_pending_enrollment(&sample_marker("op-1")).unwrap();

        state.orphan_link_and_remove_pending_enrollment("/home/alice/Photos", "op-1").unwrap();

        assert!(state.list_links().unwrap()[0].orphaned);
        assert!(state.list_pending_enrollments().unwrap().is_empty());
    }

    /// A failure partway through must roll back the whole thing -- if the
    /// marker removal half fails, the link must NOT be left orphaned with no
    /// marker left to explain why (silently stuck with nothing to retry).
    /// Simulated the same way as
    /// `add_link_with_pending_enrollment_failure_rolls_back_the_link_too`:
    /// dropping `pending_enrollments` out from under the connection so its
    /// delete fails, forcing the whole transaction to roll back.
    #[test]
    fn orphan_link_and_remove_pending_enrollment_failure_leaves_the_link_unorphaned() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.pool.get().unwrap().execute_batch("DROP TABLE pending_enrollments").unwrap();

        let result = state.orphan_link_and_remove_pending_enrollment("/home/alice/Photos", "op-1");

        assert!(result.is_err(), "the pending-enrollment delete must fail with no such table");
        assert!(
            !state.list_links().unwrap()[0].orphaned,
            "the link must not be left orphaned when the marker-removal half of the same \
             transaction failed -- a half-applied result would be silently unrecoverable"
        );
    }

    /// The all-or-nothing post-commit rollback: on success both the link row
    /// and its pending-enrollment marker are dropped together.
    #[test]
    fn remove_link_and_pending_marker_drops_both_together() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.record_pending_enrollment(&sample_marker("op-1")).unwrap();

        state.remove_link_and_pending_marker("/home/alice/Photos", "op-1").unwrap();

        assert!(state.list_links().unwrap().is_empty(), "the link row must be gone");
        assert!(
            state.list_pending_enrollments().unwrap().is_empty(),
            "the marker must be gone in the same step"
        );
    }

    /// If the rollback transaction fails partway, it must leave NO half-state:
    /// the link must NOT be removed while its marker survives (a marker naming
    /// a path with no link behind it, which a later reconciliation would then
    /// have to untangle). Simulated the same way as the orphan-rollback test:
    /// dropping `pending_enrollments` so its DELETE fails, forcing the whole
    /// transaction -- including the link DELETE -- to roll back.
    #[test]
    fn remove_link_and_pending_marker_failure_leaves_both_present() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.pool.get().unwrap().execute_batch("DROP TABLE pending_enrollments").unwrap();

        let result = state.remove_link_and_pending_marker("/home/alice/Photos", "op-1");

        assert!(result.is_err(), "the marker delete must fail with no such table");
        assert_eq!(
            state.list_links().unwrap().len(),
            1,
            "the link must NOT be removed when the marker-removal half of the same transaction \
             failed -- a link gone with its marker stranded would be the half-state this atomic \
             rollback exists to prevent"
        );
    }

    /// An orphaned link is never a materialization-repair candidate: its
    /// coordination-side authorization is permanently gone, so even a
    /// placeholder file under an (otherwise repair-eligible) eager link must
    /// not be returned once the link is orphaned. Fail-closed at the storage
    /// layer, independent of the daemon scheduler's own orphaned-link filter.
    #[test]
    fn list_materialization_repair_candidates_skips_an_orphaned_link() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap(); // eager by default
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        state
            .set_materialization_state("group-1", "a.jpg", MaterializationState::Placeholder)
            .unwrap();

        // While live, the placeholder-under-eager file is a repair candidate.
        assert_eq!(
            state.list_materialization_repair_candidates("group-1").unwrap(),
            vec!["a.jpg".to_string()],
            "a placeholder file under an eager link is repair-eligible while the link is live"
        );

        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        assert!(
            state.list_materialization_repair_candidates("group-1").unwrap().is_empty(),
            "an orphaned link's files must never be repair-eligible"
        );
    }

    /// A live `Hydrated` row is never a repair candidate, however its bytes
    /// look on disk. This query cannot see disk and its consumer rewrites every
    /// path it returns, so selecting `Hydrated` here would rewrite the file of a
    /// user who deleted it while the daemon was stopped -- resurrecting that
    /// deletion. Distinguishing the crash-mid-write case from the offline delete
    /// needs the durable intent journal and a verified root, which only
    /// `materialization::repair_interrupted_materializations` has; this pins the
    /// boundary so the two passes' responsibilities cannot silently merge.
    #[test]
    fn list_materialization_repair_candidates_never_returns_a_hydrated_record() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap(); // eager by default
        state.upsert_file("group-1", &sample_record("a.jpg")).unwrap();
        state
            .set_materialization_state("group-1", "a.jpg", MaterializationState::Hydrated)
            .unwrap();

        assert!(
            state.list_materialization_repair_candidates("group-1").unwrap().is_empty(),
            "a Hydrated record must not be repair-eligible even under an eager link"
        );

        // Pinning is what promotes a placeholder to a candidate, so prove it is
        // not a back door onto the Hydrated row either.
        state.set_pinned("group-1", "a.jpg", true).unwrap();

        assert!(
            state.list_materialization_repair_candidates("group-1").unwrap().is_empty(),
            "pinning a Hydrated record must not make it repair-eligible"
        );
    }

    /// The storage-mode mutation helpers must not target an orphaned link:
    /// its role is fixed once its authorization is gone. `set_materialization_
    /// policy` surfaces a match-less UPDATE as `NotFound` and leaves the stored
    /// policy untouched.
    #[test]
    fn set_materialization_policy_refuses_an_orphaned_link() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap(); // eager by default
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        let result =
            state.set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand);

        assert!(result.is_err(), "an orphaned link is not a live storage-mode mutation target");
        let link = &state.list_links().unwrap()[0];
        assert!(link.orphaned, "the link is still orphaned");
        assert_eq!(
            link.materialization_policy,
            MaterializationPolicy::Eager,
            "the orphaned link's stored policy must be left exactly as it was"
        );
    }

    /// Same guard on the digest-gated demote path: an orphaned link's
    /// storage-mode role must not be flippable even when the durability digest
    /// still matches. A match-less UPDATE inside the confirmed transaction
    /// surfaces as `NotFound`, and the stored policy is left untouched.
    #[test]
    fn recheck_digest_then_set_materialization_policy_refuses_an_orphaned_link() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap(); // eager by default
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 1)).unwrap();
        let digest = state.enumerate_group_durability_roots("group-1").unwrap().digest;
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        let result = state.recheck_digest_then_set_materialization_policy(
            "group-1",
            "/home/alice/Photos",
            MaterializationPolicy::OnDemand,
            digest,
        );

        assert!(
            result.is_err(),
            "an orphaned link must not be demoted even on a still-matching durability digest"
        );
        assert_eq!(
            state.list_links().unwrap()[0].materialization_policy,
            MaterializationPolicy::Eager,
            "the orphaned link's stored policy must be left exactly as it was"
        );
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

    #[test]
    fn policy_watermark_round_trips_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");

        // An unseen group has no watermark yet.
        {
            let state = SyncState::open(&db_path).unwrap();
            assert_eq!(state.policy_watermark("group-1").unwrap(), None);
            let wm = PolicyWatermark {
                highest_verified_seq: 20,
                highest_verified_head: [0xABu8; 32],
                authority_key_generation: 2,
                authority_key_fingerprint: Some([0xEEu8; 32]),
            };
            state.upsert_policy_watermark("group-1", &wm).unwrap();
            assert_eq!(state.policy_watermark("group-1").unwrap(), Some(wm));
        }

        // Reopen the same on-disk database (simulating a daemon restart): the
        // watermark is still there, so a replayed older chain can be rejected.
        {
            let state = SyncState::open(&db_path).unwrap();
            let wm = state.policy_watermark("group-1").unwrap().expect("watermark persists");
            assert_eq!(wm.highest_verified_seq, 20);
            assert_eq!(wm.highest_verified_head, [0xABu8; 32]);
            assert_eq!(wm.authority_key_generation, 2);
            assert_eq!(wm.authority_key_fingerprint, Some([0xEEu8; 32]));

            // An advance replaces the row in place; other groups stay absent.
            let advanced = PolicyWatermark {
                highest_verified_seq: 25,
                highest_verified_head: [0xCDu8; 32],
                authority_key_generation: 3,
                authority_key_fingerprint: Some([0xFFu8; 32]),
            };
            state.upsert_policy_watermark("group-1", &advanced).unwrap();
            assert_eq!(state.policy_watermark("group-1").unwrap(), Some(advanced));
            assert_eq!(state.policy_watermark("group-2").unwrap(), None);

            // A watermark with no fingerprint round-trips as SQL NULL / `None`,
            // the same shape a row written before the column existed reads back
            // as. The verifier must treat this as "unknown", never as a fork.
            let no_fingerprint = PolicyWatermark {
                highest_verified_seq: 5,
                highest_verified_head: [0x01u8; 32],
                authority_key_generation: 1,
                authority_key_fingerprint: None,
            };
            state.upsert_policy_watermark("group-3", &no_fingerprint).unwrap();
            let read_back = state.policy_watermark("group-3").unwrap().expect("watermark persists");
            assert_eq!(read_back.authority_key_fingerprint, None);
            assert_eq!(read_back, no_fingerprint);
        }
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

    /// An unknown group is not "unpaused" — it has no live link at all, and
    /// the two must stay distinguishable. `is_paused_for_group` still answers
    /// `false` here (it is a narrow boolean question, not a gate), so the
    /// assertion that matters is that the *gate* refuses rather than reporting
    /// a permissive "not paused" that a caller could act on.
    #[test]
    fn unknown_group_is_not_paused_but_the_gate_still_refuses_it() {
        let state = SyncState::open_in_memory().unwrap();
        assert!(!state.is_paused_for_group("no-such-group").unwrap());
        assert_eq!(state.link_gate_for_group("no-such-group").unwrap(), LinkGate::NoLiveLink);
    }

    /// The exact unlink shape: a link that was live (and would have gated
    /// `Live`) must gate `NoLiveLink` the instant its row is deleted. This is
    /// the seam that stops a live peer session from applying — and deleting —
    /// inside a folder the user detached.
    #[test]
    fn removing_a_link_flips_the_gate_from_live_to_no_live_link() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        assert_eq!(
            state.link_gate_for_group("group-1").unwrap(),
            LinkGate::Live {
                local_path: "/home/alice/Photos".to_string(),
                policy: MaterializationPolicy::Eager,
            }
        );

        state.remove_link("/home/alice/Photos").unwrap();
        assert_eq!(state.link_gate_for_group("group-1").unwrap(), LinkGate::NoLiveLink);
    }

    /// An orphaned link's on-disk files are documented as never touched or
    /// deleted, so the gate must refuse it. The `paused` column alone cannot
    /// express this: an orphaned row keeps `paused = 0`, which the old lookup
    /// reported as the permissive "not paused".
    #[test]
    fn an_orphaned_link_gates_no_live_link_despite_being_unpaused() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        assert!(!state.is_paused_for_group("group-1").unwrap());
        assert_eq!(state.link_gate_for_group("group-1").unwrap(), LinkGate::NoLiveLink);
    }

    /// Pausing refuses the sync but keeps naming the folder — the link is
    /// still there, so `NoLiveLink` (which means "no folder on this device")
    /// would be the wrong verdict and would break read-only callers.
    #[test]
    fn a_paused_link_gates_paused_and_still_names_its_root() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.set_paused("/home/alice/Photos", true).unwrap();

        assert_eq!(
            state.link_gate_for_group("group-1").unwrap(),
            LinkGate::Paused { local_path: "/home/alice/Photos".to_string() }
        );
    }

    /// Existing links (and freshly-added ones with no explicit
    /// policy) default to `Eager` with no configured cap — the "no
    /// behavior change without opt-in" migration guarantee.
    #[test]
    fn new_links_default_to_eager_policy_with_no_cap() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        let link = &state.list_links().unwrap()[0];
        assert_eq!(link.materialization_policy, MaterializationPolicy::Eager);
        assert_eq!(link.max_local_size_bytes, None);
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

    /// A freshly-indexed file defaults to `Hydrated` and
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

    /// a crash mid-hydration must not leave a file permanently
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

    /// A crash mid-eviction (after `Evicting` is set but before the placeholder
    /// commit transitions it to `Placeholder`) leaves a file permanently stuck
    /// `Evicting`: the `Hydrating` reset ignores it and
    /// `repair_interrupted_materializations` skips every non-`Hydrated` row. The
    /// blocks are always retained (physical reclamation only runs after the row
    /// is already `Placeholder`), so startup recovery resets `Evicting` back to
    /// `Placeholder` — the reconcilable state safe for both interrupted-eviction
    /// disk cases. Reproduce-first: the pre-existing `Hydrating` reset provably
    /// leaves the `Evicting` row untouched; only the dedicated reset clears it.
    #[test]
    fn reset_stale_evicting_to_placeholder_reconciles_only_evicting_rows() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record("wedged.jpg")).unwrap();
        state.upsert_file("group-1", &sample_record("hydrated.jpg")).unwrap();
        state.upsert_file("group-2", &sample_record("wedged-too.jpg")).unwrap();
        state.upsert_file("group-2", &sample_record("still-hydrating.jpg")).unwrap();
        state
            .set_materialization_state("group-1", "wedged.jpg", MaterializationState::Evicting)
            .unwrap();
        state
            .set_materialization_state("group-2", "wedged-too.jpg", MaterializationState::Evicting)
            .unwrap();
        state
            .set_materialization_state(
                "group-2",
                "still-hydrating.jpg",
                MaterializationState::Hydrating,
            )
            .unwrap();

        // The pre-existing recovery for stuck `Hydrating` rows does not reconcile
        // `Evicting` at all — the wedge this fix closes. (Only the stuck
        // `Hydrating` row is reset here.)
        assert_eq!(state.reset_stale_hydrating_to_placeholder().unwrap(), 1);
        assert_eq!(
            state.get_materialization_state("group-1", "wedged.jpg").unwrap(),
            Some(MaterializationState::Evicting),
            "the Hydrating reset must leave Evicting rows stuck (reproduces the wedge)"
        );

        let reset_count = state.reset_stale_evicting_to_placeholder().unwrap();
        assert_eq!(reset_count, 2);

        assert_eq!(
            state.get_materialization_state("group-1", "wedged.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        assert_eq!(
            state.get_materialization_state("group-2", "wedged-too.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );
        // An already-`Hydrated` row and the (now `Placeholder`) formerly-stuck
        // `Hydrating` row are both left as they were by the Evicting reset.
        assert_eq!(
            state.get_materialization_state("group-1", "hydrated.jpg").unwrap(),
            Some(MaterializationState::Hydrated)
        );
        assert_eq!(
            state.get_materialization_state("group-2", "still-hydrating.jpg").unwrap(),
            Some(MaterializationState::Placeholder)
        );

        // Idempotent: nothing left to reset on a second call.
        assert_eq!(state.reset_stale_evicting_to_placeholder().unwrap(), 0);
    }

    /// Eviction candidates are hydrated, unpinned, non-deleted
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

    // --- connection-pooling tests ---
    //
    // These reach into `state.pool` directly (a private field, visible
    // here since `tests` is a descendant of the `index` module) to prove
    // properties of the pooling mechanism itself, not just observable
    // behavior through the public API — the public API alone can't
    // distinguish "one connection serialized by a mutex" from "a pool of
    // connections," since both give every caller correct, eventually-
    // consistent results. The mechanism is what this test is checking.

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

    /// The file-backed index is the durable source of truth, so `open` sets
    /// `synchronous = FULL` explicitly rather than relying on SQLite's
    /// compile-time default (only NORMAL under WAL, which can lose the last
    /// committed transaction on a power loss). `synchronous` is a
    /// per-connection pragma, so this checks a freshly pooled connection to
    /// prove the `with_init` hook applies it to every connection, not just the
    /// first. `PRAGMA synchronous` reports the mode as an integer: 2 == FULL.
    #[test]
    fn open_sets_synchronous_full_on_every_pooled_connection() {
        let dir = tempfile::tempdir().unwrap();
        let state = SyncState::open(dir.path().join("state.db")).unwrap();

        // Drain the connection created during `open`/`init` so the assertion
        // below runs against a connection the pool initialized on demand.
        let conn = state.pool.get().unwrap();
        let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0)).unwrap();
        assert_eq!(
            synchronous, 2,
            "a file-backed index connection must run with synchronous = FULL (2)"
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

    /// An older `files`/`links` schema used to simulate a real
    /// pre-existing on-disk database before the current migrations run.
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
    /// `ALTER TABLE` statements. Also confirms the migrated columns are
    /// actually present (not just equally absent from both).
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

    /// A row that existed before the current columns were added (inserted
    /// directly against `OLD_SCHEMA_SQL`, bypassing
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
        assert_eq!(row.5, 0, "symlink_out_of_root must also default to unflagged");
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
    /// default of 0 — the explicit version marker added on top of the
    /// pre-existing shape-detection migrations.
    #[test]
    fn init_stamps_current_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        SyncState::init(&conn).unwrap();
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn version_four_upgrades_to_current_with_empty_provenance() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 4).unwrap();

        SyncState::init(&conn).unwrap();

        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert!(table_exists(&conn, "group_block_provenance").unwrap());
        let provenance_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM group_block_provenance", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            provenance_rows, 0,
            "v4 metadata must not be treated as proof that block bytes came through a group"
        );
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

    /// A database whose `user_version`
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
    /// existing `materialization_state_and_
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
    /// requires (a held file's state and reason must survive a daemon
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
    /// Deliberate no-op, not an error — tombstone-clears-held
    /// -state requirement (a later section) needs to clear held
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

    /// Three sequential edits to the same path leave exactly
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
    /// from-scratch-tombstone behavior) has no prior content to
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

    const ONE_DAY_NANOS: i64 = 86_400 * 1_000_000_000;

    /// The fixed built-in policy's union-retain/intersection-expire rule: a
    /// superseded version is swept only once it exceeds *both* the built-in
    /// count bound (10) and the built-in age bound (30 days). A version that
    /// exceeds only one axis survives; the current row is never a candidate.
    #[test]
    fn expire_respects_the_fixed_union_retain_intersection_expire_rule() {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;

        // Thirteen versions of one path: version_seq 1..=12 become superseded,
        // version_seq 13 is the current (live) row. `ROW_NUMBER` ranks the
        // superseded rows by version_seq DESC, so seq 12 is rnk 1 (newest
        // superseded) and seq 1 is rnk 12 (oldest superseded).
        for i in 1..=13u64 {
            let mut record = record_with_size("a.txt", i);
            // Ages chosen to exercise each axis independently:
            //   seq 1  (rnk 12): 100 days old  -> beyond count AND age -> swept
            //   seq 2  (rnk 11): 5 days old    -> beyond count, within age -> kept
            //   seq 3  (rnk 10): 100 days old  -> within count -> kept despite age
            //   seq 4..=12       : 5 days old   -> within count -> kept
            let age_days = match i {
                1 | 3 => 100,
                _ => 5,
            };
            record.mtime_unix_nanos = now - age_days * ONE_DAY_NANOS;
            state.upsert_file_with_origin("group-1", &record, "device-a").unwrap();
        }

        let deleted = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(deleted, 1, "only seq 1 exceeds both the count and age bounds");

        let remaining: Vec<i64> = state
            .list_versions("group-1", "a.txt")
            .unwrap()
            .iter()
            .map(|v| v.version_seq)
            .collect();
        assert!(!remaining.contains(&1), "seq 1 exceeded both bounds and was swept");
        assert!(
            remaining.contains(&2),
            "seq 2 is beyond the count bound but within the age bound, so it is retained"
        );
        assert!(
            remaining.contains(&3),
            "seq 3 is old but within the count bound, so it is retained"
        );
        assert!(remaining.contains(&13), "the current live row is never a retention candidate");
    }

    /// Writes 13 versions of `path` with the exact same seq/age shape as
    /// `expire_respects_the_fixed_union_retain_intersection_expire_rule`'s
    /// single-path case: seq 1 is both beyond the count bound (rnk 12 > the
    /// built-in 10) and the age bound (100 days old) -- the one version a
    /// retention sweep would otherwise always collect; seq 13 is current.
    fn write_thirteen_versions_with_seq_one_expirable(
        state: &SyncState,
        group_id: &str,
        path: &str,
        now: i64,
    ) {
        for i in 1..=13u64 {
            let mut record = record_with_size(path, i);
            let age_days = if i == 1 { 100 } else { 5 };
            record.mtime_unix_nanos = now - age_days * ONE_DAY_NANOS;
            state.upsert_file_with_origin(group_id, &record, "device-a").unwrap();
        }
    }

    /// A version an active handoff lease pins survives a retention sweep
    /// that would otherwise have expired it (both bounds exceeded, exactly
    /// like `expire_respects_the_fixed_union_retain_intersection_expire_
    /// rule`'s seq 1) -- and once the lease is released, the very next
    /// sweep collects it normally.
    #[test]
    fn a_provisionally_leased_version_survives_retention_and_is_collected_after_release() {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;
        let now_unix_seconds = now / 1_000_000_000;

        // Two paths, each shaped so their own seq 1 exceeds both retention
        // bounds on its own -- a.txt's seq 1 will be leased, b.txt's seq 1 is
        // an unleased control that must still be swept normally in the same
        // pass.
        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "a.txt", now);
        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "b.txt", now);

        state
            .record_handoff_lease(
                "group-1",
                "lease-1",
                [0x11; 32],
                &[("a.txt".to_string(), 1)],
                now_unix_seconds,
                now_unix_seconds + 900,
            )
            .unwrap();

        let deleted = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(deleted, 1, "only the unleased b.txt seq 1 is swept");
        let a_versions: Vec<i64> = state
            .list_versions("group-1", "a.txt")
            .unwrap()
            .iter()
            .map(|v| v.version_seq)
            .collect();
        assert!(a_versions.contains(&1), "the leased version survives the sweep");
        let b_versions: Vec<i64> = state
            .list_versions("group-1", "b.txt")
            .unwrap()
            .iter()
            .map(|v| v.version_seq)
            .collect();
        assert!(!b_versions.contains(&1), "the unleased control version is swept normally");

        // Confirmed leases pin exactly like provisional ones.
        state.set_handoff_lease_state("lease-1", HandoffLeaseState::Confirmed).unwrap();
        let deleted_while_confirmed =
            state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(deleted_while_confirmed, 0, "a confirmed lease still pins its version");

        // Once released, normal retention resumes on the very next sweep.
        state.set_handoff_lease_state("lease-1", HandoffLeaseState::Released).unwrap();
        let deleted_after_release =
            state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(deleted_after_release, 1, "released, the version is collected normally");
        let a_versions_after: Vec<i64> = state
            .list_versions("group-1", "a.txt")
            .unwrap()
            .iter()
            .map(|v| v.version_seq)
            .collect();
        assert!(!a_versions_after.contains(&1));
    }

    /// A lease past its own `expires_at_unix` stops pinning even while its
    /// `state` column still reads `'provisional'` (no sweep has flipped it
    /// to `'expired'` yet) -- the time check alone is authoritative, exactly
    /// as `leased_version_keys_for_group`'s doc comment describes.
    #[test]
    fn an_expired_but_unswept_lease_no_longer_pins_its_version() {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;
        let now_unix_seconds = now / 1_000_000_000;

        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "a.txt", now);

        // Already expired as of `now_unix_seconds` -- `expires_at_unix` is in
        // the past relative to the sweep's own clock.
        state
            .record_handoff_lease(
                "group-1",
                "lease-1",
                [0x22; 32],
                &[("a.txt".to_string(), 1)],
                now_unix_seconds - 1_000,
                now_unix_seconds - 1,
            )
            .unwrap();

        let deleted = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(
            deleted, 1,
            "an expired lease (even if still recorded as 'provisional') no longer pins"
        );
    }

    /// The clock-skew bug this change closes, reproduced directly at the pin-
    /// derivation layer: [`SyncState::record_handoff_lease_atomic`] takes only
    /// a TTL DURATION plus this device's OWN `created_at_unix` reading, never
    /// an absolute expiry stamped by a different clock, so there is no
    /// cross-clock value for it to be fooled by in the first place. This
    /// simulates a coordination Worker whose clock runs BEHIND this target's
    /// own (equivalently: this target's clock running ahead) -- under the
    /// pre-fix behavior of storing the Worker's absolute `expiresAt`
    /// verbatim, that value would already read as being in the past relative
    /// to this target's own clock, and the very next retention sweep would
    /// drop the pin early, reopening the GC race the lease exists to close.
    /// Here the pin instead survives for exactly `ttl_seconds +
    /// HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS` measured from this target's own
    /// `created_at_unix` -- and the converse also holds: once this target's
    /// own clock passes that same local deadline, the pin lapses.
    #[test]
    fn record_handoff_lease_atomic_pin_deadline_is_derived_from_the_targets_own_clock_plus_ttl_never_a_foreign_absolute_expiry(
    ) {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;
        let now_unix_seconds = now / 1_000_000_000;
        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "a.txt", now);

        // A hypothetical Worker-issued absolute expiry that is already in the
        // past relative to this target's own clock (`now_unix_seconds`) --
        // the exact skew scenario the fix closes. It is never passed to
        // `record_handoff_lease_atomic` at all: only the TTL duration is.
        let worker_absolute_expiry_already_past = now_unix_seconds - 1_000;
        assert!(worker_absolute_expiry_already_past < now_unix_seconds);

        let ttl_seconds = 900;
        state
            .record_handoff_lease_atomic("group-1", "lease-1", now_unix_seconds, ttl_seconds)
            .unwrap();
        let local_deadline =
            now_unix_seconds + ttl_seconds + SyncState::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;

        // One second before this target's OWN local deadline, the pin still
        // holds -- long after the stale Worker-side absolute expiry above
        // would have already lapsed it under the pre-fix behavior.
        let still_pinned_at_nanos = (local_deadline - 1) * 1_000_000_000;
        let deleted_before =
            state.expire_superseded_and_trashed_versions("group-1", still_pinned_at_nanos).unwrap();
        assert_eq!(deleted_before, 0, "the pin must hold up to this target's own local deadline");

        // Once this target's own clock passes that same local deadline, the
        // pin lapses and normal retention resumes -- the converse property.
        let lapsed_at_nanos = (local_deadline + 1) * 1_000_000_000;
        let deleted_after =
            state.expire_superseded_and_trashed_versions("group-1", lapsed_at_nanos).unwrap();
        assert_eq!(
            deleted_after, 1,
            "the pin must lapse once this target's own clock passes its local deadline"
        );
    }

    /// A non-positive TTL can never produce a safe pin (its deadline is at or
    /// before now, so the pin lapses immediately and reopens the GC race), so
    /// [`SyncState::record_handoff_lease_atomic`] rejects it structurally and
    /// writes NO pin row -- fail closed. Checked for both a negative and a
    /// zero TTL; in each case the call errors and the version stays
    /// unprotected (retention collects it normally).
    #[test]
    fn record_handoff_lease_atomic_rejects_a_non_positive_ttl_and_writes_no_pin() {
        for bad_ttl in [-1i64, 0] {
            let state = SyncState::open_in_memory().unwrap();
            let now = 10_000 * ONE_DAY_NANOS;
            let now_unix_seconds = now / 1_000_000_000;
            write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "a.txt", now);

            let result = state.record_handoff_lease_atomic(
                "group-1",
                "lease-bad",
                now_unix_seconds,
                bad_ttl,
            );
            assert!(
                matches!(result, Err(SyncError::InvalidInput(_))),
                "a non-positive ttl ({bad_ttl}) must be rejected, got {result:?}"
            );

            // No pin row was written, so retention collects seq 1 normally --
            // the version is NOT pinned by the rejected lease.
            assert!(
                state.list_handoff_leases_for_group("group-1").unwrap().is_empty(),
                "a rejected non-positive-ttl lease must write no pin row"
            );
            let deleted = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
            assert_eq!(deleted, 1, "the version stays unprotected: nothing pinned it");
        }
    }

    /// `record_handoff_lease_atomic`'s own pin always matches its own
    /// enumeration exactly — checked once with a sweep run immediately
    /// BEFORE it (which only evicts what nothing protects yet — expected,
    /// not a bug) and once with a sweep run immediately AFTER it (which must
    /// evict nothing from what it just pinned, since the enumeration and the
    /// pin landed together in one transaction).
    #[test]
    fn record_handoff_lease_atomic_pins_exactly_its_own_enumeration_regardless_of_a_sweep_immediately_before_or_after(
    ) {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;
        let now_unix_seconds = now / 1_000_000_000;
        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "a.txt", now);
        write_thirteen_versions_with_seq_one_expirable(&state, "group-1", "b.txt", now);

        // A sweep immediately BEFORE any lease exists evicts whatever is not
        // yet pinned — expected: nothing protects it yet.
        let deleted_before = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(
            deleted_before, 2,
            "both a.txt and b.txt seq 1 are unprotected before any lease exists"
        );

        let (digest, pinned) =
            state.record_handoff_lease_atomic("group-1", "lease-1", now_unix_seconds, 900).unwrap();
        let pinned_set: HashSet<_> = pinned.iter().cloned().collect();
        let reenumerated: HashSet<_> = state
            .enumerate_group_durability_root_versions("group-1")
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(
            pinned_set, reenumerated,
            "the atomic pin names exactly the rows a fresh enumeration sees"
        );
        assert_eq!(
            digest,
            state.enumerate_group_durability_roots("group-1").unwrap().digest,
            "the returned digest must be the same routine/value `enumerate_group_durability_roots` produces"
        );

        // A sweep immediately AFTER the atomic call must evict nothing —
        // every remaining row (seq 2..=13 for both paths; seq 1 for each was
        // already gone before the lease existed) is now pinned by the lease
        // that just enumerated them.
        let deleted_after = state.expire_superseded_and_trashed_versions("group-1", now).unwrap();
        assert_eq!(deleted_after, 0, "the atomic pin covers the whole set it just enumerated");
    }

    /// The bug this change closes, reproduced directly: calling
    /// [`SyncState::enumerate_group_durability_root_versions`] and
    /// [`SyncState::record_handoff_lease`] as two SEPARATE steps (the
    /// pre-atomic sequence `daemon_state::request_handoff_lease` used to run)
    /// leaves a real window between them for a retention sweep to run and
    /// evict a row that was already captured in the enumeration — the lease
    /// then pins an identity that no longer exists. This test first
    /// reproduces that window with the two-step sequence, then shows
    /// [`SyncState::record_handoff_lease_atomic`] closes it: the identical
    /// adversarial sweep, run immediately after instead of in between,
    /// evicts nothing, because the enumeration and the pin land together in
    /// one transaction with no seam for the sweep to interleave into.
    #[test]
    fn record_handoff_lease_atomic_closes_the_window_the_separate_enumerate_then_record_sequence_leaves_open(
    ) {
        let state = SyncState::open_in_memory().unwrap();
        let now = 10_000 * ONE_DAY_NANOS;
        let now_unix_seconds = now / 1_000_000_000;

        // --- OLD (non-atomic) sequence: reproduce the documented gap. ---
        write_thirteen_versions_with_seq_one_expirable(&state, "group-old", "a.txt", now);
        let captured = state.enumerate_group_durability_root_versions("group-old").unwrap();
        assert!(
            captured.contains(&("a.txt".to_string(), 1)),
            "the enumeration must have seen seq 1 before anything evicts it"
        );
        // The retention sweep fires in the window between the enumeration
        // above and the `record_handoff_lease` call below — exactly the gap
        // the pre-atomic flow left open.
        let deleted_between =
            state.expire_superseded_and_trashed_versions("group-old", now).unwrap();
        assert_eq!(
            deleted_between, 1,
            "seq 1 is evicted in the window, unprotected by any pin yet"
        );
        // The caller doesn't know that happened, so it pins the now-stale
        // captured list anyway.
        state
            .record_handoff_lease(
                "group-old",
                "lease-old",
                [0x33; 32],
                &captured,
                now_unix_seconds,
                now_unix_seconds + 900,
            )
            .unwrap();
        assert!(
            state.get_version("group-old", "a.txt", 1).unwrap().is_none(),
            "the pin is ineffective: it names a (path, version_seq) row that is already gone"
        );

        // --- NEW (atomic) sequence: the identical fixture, the identical
        // adversarial sweep, but pinned atomically with the enumeration. ---
        write_thirteen_versions_with_seq_one_expirable(&state, "group-new", "a.txt", now);
        let (pinned_digest, pinned) = state
            .record_handoff_lease_atomic("group-new", "lease-new", now_unix_seconds, 900)
            .unwrap();
        assert!(
            pinned.contains(&("a.txt".to_string(), 1)),
            "the atomic pin must cover exactly what it enumerated, including seq 1"
        );
        assert_eq!(
            pinned_digest,
            state.enumerate_group_durability_roots("group-new").unwrap().digest,
            "the returned digest must be the same routine/value `enumerate_group_durability_roots` produces"
        );
        // The exact same sweep, run immediately after instead of in between,
        // now finds seq 1 already pinned — there was no window for it to
        // land in.
        let deleted_after = state.expire_superseded_and_trashed_versions("group-new", now).unwrap();
        assert_eq!(
            deleted_after, 0,
            "the atomic pin already covered seq 1 before this sweep could run"
        );
        assert!(
            state.get_version("group-new", "a.txt", 1).unwrap().is_some(),
            "seq 1 survives: enumerate-then-pin was atomic, so the sweep found it already protected"
        );
    }

    /// The live-block-hash root set includes
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

    // --- Full-replica durability roots ---

    /// `enumerate_group_durability_roots` must reach every category that
    /// actually exists in this schema: the current head, a still-retained
    /// superseded version of the same path, a trash-restorable version, and
    /// a conflict copy (which is just an ordinary current row at a synthetic
    /// path, so it needs no special-cased query to be included).
    #[test]
    fn enumerate_group_durability_roots_includes_current_superseded_trashed_and_conflict_copies() {
        let state = SyncState::open_in_memory().unwrap();

        // Plain current file.
        state.upsert_file("group-1", &sample_record_with_hash("alive.bin", 1)).unwrap();

        // Edited twice: version 1 (hash 2) is retained as `superseded` once
        // version 2 (hash 3) supersedes it — both are still-restorable
        // roots.
        state.upsert_file("group-1", &sample_record_with_hash("history.bin", 2)).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("history.bin", 3)).unwrap();

        // Deleted: its last live content (hash 4) is retained as `trashed`.
        state.upsert_file("group-1", &sample_record_with_hash("gone.bin", 4)).unwrap();
        state.mark_deleted("group-1", "gone.bin", "device-a").unwrap();

        // A conflict copy: an ordinary current row under a synthetic path —
        // no `RecordKind::ConflictCopy` or marker column exists, so this is
        // reached by the plain current-file scan.
        let conflict_copy_path = "shared.txt (conflicted copy, device-b, deadbeef).txt";
        state.upsert_file("group-1", &sample_record_with_hash(conflict_copy_path, 5)).unwrap();

        let roots = state.enumerate_group_durability_roots("group-1").unwrap();
        let mut got: Vec<(String, ContentHash)> = roots
            .roots
            .iter()
            .map(|r| (r.path.clone(), hex::encode(&r.blocks[0].hash.0)))
            .collect();
        got.sort();

        let mut expected = vec![
            ("alive.bin".to_string(), hash_hex(1)),
            ("history.bin".to_string(), hash_hex(2)), // superseded, still retained
            ("history.bin".to_string(), hash_hex(3)), // current
            ("gone.bin".to_string(), hash_hex(4)),    // trashed, still retained
            (conflict_copy_path.to_string(), hash_hex(5)),
        ];
        expected.sort();
        assert_eq!(got, expected);
        // Exactly 5 roots: if the tombstone itself (`gone.bin`'s `current`,
        // `deleted = 1` row) were wrongly included, this count would be 6 —
        // a deleted record has no durable content to hand off.
        assert_eq!(roots.roots.len(), 5, "no extra tombstone/no-block root should appear");
    }

    /// Directories and symlinks carry no blocks to hand off and must be
    /// excluded even though they are ordinary `state = 'current'` rows —
    /// `record_kind` is a per-row column, so this is filtered directly in
    /// SQL rather than needing a second per-path classification lookup.
    #[test]
    fn enumerate_group_durability_roots_excludes_directories_and_symlinks() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("file.bin", 1)).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a-dir", 2)).unwrap();
        state.set_record_kind("group-1", "a-dir", RecordKind::Directory).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a-link", 3)).unwrap();
        state.set_record_kind("group-1", "a-link", RecordKind::Symlink).unwrap();

        let roots = state.enumerate_group_durability_roots("group-1").unwrap();
        assert_eq!(roots.roots.len(), 1);
        assert_eq!(roots.roots[0].path, "file.bin");
    }

    /// An empty group's root set is empty, and its digest is deterministic
    /// (not, say, all-zero by construction) — the base case
    /// `full_replica_handoff_ready`'s "vacuously ready" path relies on being
    /// stable across repeated calls.
    #[test]
    fn enumerate_group_durability_roots_empty_group_has_stable_digest() {
        let state = SyncState::open_in_memory().unwrap();
        let first = state.enumerate_group_durability_roots("group-1").unwrap();
        let second = state.enumerate_group_durability_roots("group-1").unwrap();
        assert!(first.roots.is_empty());
        assert_eq!(first.digest, second.digest);
    }

    /// The digest is a pure function of the underlying root set, not of
    /// SQL's happenstance row order or how many times it's recomputed —
    /// re-enumerating an unchanged group must reproduce exactly the same
    /// digest, which is what the daemon's check-then-recommit re-confirm
    /// relies on to fail closed only on a REAL change.
    #[test]
    fn enumerate_group_durability_roots_digest_is_stable_across_recomputation() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 1)).unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("b.bin", 2)).unwrap();

        let first = state.enumerate_group_durability_roots("group-1").unwrap();
        let second = state.enumerate_group_durability_roots("group-1").unwrap();
        assert_eq!(first.digest, second.digest);
    }

    /// The digest changes when the underlying root set actually changes
    /// (here: a brand-new superseded version appears) — the property the
    /// daemon-driven role-loss commit's digest re-check depends on to detect
    /// a root set that moved between the readiness check and the commit.
    #[test]
    fn enumerate_group_durability_roots_digest_changes_when_set_changes() {
        let state = SyncState::open_in_memory().unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 1)).unwrap();
        let before = state.enumerate_group_durability_roots("group-1").unwrap();

        // A second edit adds a new superseded-version root.
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 2)).unwrap();
        let after = state.enumerate_group_durability_roots("group-1").unwrap();

        assert_ne!(before.digest, after.digest, "adding a retained version must change the digest");
    }

    /// Builds a `DurabilityRoot` the same way the real enumeration does:
    /// `version_hash` is genuinely derived from `blocks`/`size`/`meta` via
    /// `FileVersion::new`, not an independently chosen value — so these tests
    /// exercise the actual property the digest relies on (identical inputs
    /// hash identically; any real difference changes the hash) rather than
    /// merely asserting that two arbitrary hashes differ.
    fn test_root(
        path: &str,
        blocks: Vec<VersionBlock>,
        size: u64,
        meta: FileMeta,
    ) -> DurabilityRoot {
        let version = FileVersion::new(blocks, size, meta);
        DurabilityRoot {
            path: path.to_string(),
            blocks: version.blocks,
            version_hash: version.version_hash,
        }
    }

    fn test_meta() -> FileMeta {
        FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        }
    }

    /// The digest must change when a file's block SEQUENCE is reordered, even
    /// though the set of blocks is unchanged: `version_hash` binds the
    /// ordered block list (`FileVersion::canonical_encoding` preserves block
    /// order rather than sorting it), so a chunk reorder is a genuinely
    /// different version identity, and the digest — built entirely from
    /// `version_hash` — must change with it.
    #[test]
    fn durability_roots_digest_changes_on_a_block_reorder() {
        let block_a = VersionBlock { hash: BlockHash(vec![1u8; 32]), size: 4 };
        let block_b = VersionBlock { hash: BlockHash(vec![2u8; 32]), size: 4 };
        let root_forward =
            test_root("a.bin", vec![block_a.clone(), block_b.clone()], 8, test_meta());
        let root_reordered = test_root("a.bin", vec![block_b, block_a], 8, test_meta());
        assert_ne!(
            root_forward.version_hash, root_reordered.version_hash,
            "reordering a root's block sequence must change its version_hash"
        );
        assert_ne!(
            durability_roots_digest(&[root_forward]),
            durability_roots_digest(&[root_reordered]),
            "reordering a root's block sequence must change the digest"
        );
    }

    /// The digest must also change on a metadata-only difference — same
    /// blocks and size, different `mtime` — since `version_hash` binds the
    /// full `FileVersion` (blocks, size, AND metadata), not merely the block
    /// content. This is the whole point of using `change::VersionHash` as the
    /// durability-root identity instead of a block-list-only fingerprint.
    #[test]
    fn durability_roots_digest_changes_on_a_fileversion_meta_change() {
        let block = VersionBlock { hash: BlockHash(vec![9u8; 32]), size: 4 };
        let mut meta_b = test_meta();
        meta_b.mtime_unix_nanos = 1;
        let root_a = test_root("a.bin", vec![block.clone()], 4, test_meta());
        let root_b = test_root("a.bin", vec![block], 4, meta_b);
        assert_ne!(
            root_a.version_hash, root_b.version_hash,
            "an mtime-only difference must still change the version_hash"
        );
        assert_ne!(
            durability_roots_digest(&[root_a]),
            durability_roots_digest(&[root_b]),
            "a metadata-only version change must change the digest"
        );
    }

    /// Cross-root ordering, in contrast, is NOT significant: the same set of
    /// roots collected in a different order digests identically, so the
    /// re-check only fires on a real content change, never on SQL row-order
    /// happenstance.
    #[test]
    fn durability_roots_digest_is_order_independent_across_roots() {
        let a = test_root(
            "a.bin",
            vec![VersionBlock { hash: BlockHash(vec![1u8; 32]), size: 4 }],
            4,
            test_meta(),
        );
        let b = test_root(
            "b.bin",
            vec![VersionBlock { hash: BlockHash(vec![2u8; 32]), size: 4 }],
            4,
            test_meta(),
        );
        assert_eq!(
            durability_roots_digest(&[a.clone(), b.clone()]),
            durability_roots_digest(&[b, a]),
            "the same root set in a different order must digest identically"
        );
    }

    /// The atomic demote commit: when the re-checked digest still matches the
    /// group's current root set, the policy is flipped and `Ok(true)` is
    /// returned; when the set has moved since the digest was captured, nothing
    /// is written and `Ok(false)` is returned (fail closed). The `Ok(false)`
    /// case is exactly what a concurrent index write interleaving between the
    /// readiness check and the commit produces — the transaction re-reads the
    /// set and refuses rather than committing against a stale confirmation.
    #[test]
    fn recheck_digest_then_set_materialization_policy_commits_only_on_a_matching_digest() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/local/photos", "group-1").unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 1)).unwrap();
        let digest_at_check = state.enumerate_group_durability_roots("group-1").unwrap().digest;

        // A concurrent edit lands after the digest was captured (stands in for
        // the watcher write that would race the commit).
        state.upsert_file("group-1", &sample_record_with_hash("b.bin", 2)).unwrap();

        // Re-check against the now-stale digest: must refuse, and must NOT flip
        // the policy.
        let committed = state
            .recheck_digest_then_set_materialization_policy(
                "group-1",
                "/local/photos",
                MaterializationPolicy::OnDemand,
                digest_at_check,
            )
            .unwrap();
        assert!(!committed, "a stale digest must not commit the policy flip");
        assert_eq!(
            state.materialization_policy_for_group("group-1").unwrap(),
            Some(MaterializationPolicy::Eager),
            "the link must still be eager after a refused demote"
        );

        // Re-capturing the digest against the current set and committing now
        // succeeds and actually flips the policy.
        let fresh = state.enumerate_group_durability_roots("group-1").unwrap().digest;
        let committed = state
            .recheck_digest_then_set_materialization_policy(
                "group-1",
                "/local/photos",
                MaterializationPolicy::OnDemand,
                fresh,
            )
            .unwrap();
        assert!(committed, "a matching digest must commit the policy flip");
        assert_eq!(
            state.materialization_policy_for_group("group-1").unwrap(),
            Some(MaterializationPolicy::OnDemand),
            "the link must be on-demand after a committed demote"
        );
    }

    /// The atomic unlink commit, same contract as the demote counterpart: the
    /// link row is removed only when the re-checked digest still matches, and
    /// a moved set leaves the link in place (`Ok(false)`).
    #[test]
    fn recheck_digest_then_remove_link_removes_only_on_a_matching_digest() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/local/photos", "group-1").unwrap();
        state.upsert_file("group-1", &sample_record_with_hash("a.bin", 1)).unwrap();
        let digest_at_check = state.enumerate_group_durability_roots("group-1").unwrap().digest;

        state.upsert_file("group-1", &sample_record_with_hash("b.bin", 2)).unwrap();

        let removed = state
            .recheck_digest_then_remove_link("group-1", "/local/photos", digest_at_check)
            .unwrap();
        assert!(!removed, "a stale digest must not remove the link");
        assert_eq!(state.list_links().unwrap().len(), 1, "the link must survive a refused unlink");

        let fresh = state.enumerate_group_durability_roots("group-1").unwrap().digest;
        let removed =
            state.recheck_digest_then_remove_link("group-1", "/local/photos", fresh).unwrap();
        assert!(removed, "a matching digest must remove the link");
        assert!(
            state.list_links().unwrap().is_empty(),
            "the link must be gone after a committed unlink"
        );
    }

    // --- Fix-saga: role-loss-operation journal state machine ---------------

    /// The basic lifecycle a normal, fully-successful demote/unlink drives:
    /// `Prepared` on insert, `WorkerCommitted` once the Worker commit lands,
    /// then `LocalCommitted` once the local change also lands -- and the row
    /// is gone afterward, matching `RoleLossOperation`'s own doc comment.
    #[test]
    fn role_loss_operation_advances_through_its_states_and_is_deleted_on_completion() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-a",
                    lease_id: Some("lease-1"),
                    action: RoleLossAction::Demote,
                    local_path: Some("/local/photos"),
                    now_unix: 1_000,
                },
            )
            .unwrap();
        let op = state.get_role_loss_operation("op-1").unwrap().unwrap();
        assert_eq!(op.state, RoleLossOperationState::Prepared);
        assert_eq!(op.group_id, "group-1");
        assert_eq!(op.source_device_id, "device-b");
        assert_eq!(op.target_device_id, "device-a");
        assert_eq!(op.lease_id.as_deref(), Some("lease-1"));
        assert_eq!(op.worker_membership_generation, None);
        assert_eq!(op.action, RoleLossAction::Demote);
        assert_eq!(op.local_path.as_deref(), Some("/local/photos"));
        assert_eq!(op.attempts, 0);

        assert!(state.mark_role_loss_worker_committed("op-1", 42, 1_001).unwrap());
        let op = state.get_role_loss_operation("op-1").unwrap().unwrap();
        assert_eq!(op.state, RoleLossOperationState::WorkerCommitted);
        assert_eq!(op.worker_membership_generation, Some(42));

        assert!(state
            .advance_role_loss_operation("op-1", RoleLossOperationState::LocalCommitted, 1_002)
            .unwrap());
        state.delete_role_loss_operation("op-1").unwrap();
        assert!(
            state.get_role_loss_operation("op-1").unwrap().is_none(),
            "a settled operation's journal row must be gone"
        );
    }

    /// Advancing or deleting a row that no longer exists is a benign no-op
    /// (`Ok(false)`/`Ok(())`), never an error -- every call site in
    /// `control_socket.rs`/`daemon_state.rs` relies on this so a concurrent
    /// completion elsewhere never turns into a spurious failure.
    #[test]
    fn advancing_or_deleting_a_missing_role_loss_operation_is_a_benign_no_op() {
        let state = SyncState::open_in_memory().unwrap();
        assert!(!state
            .advance_role_loss_operation("missing", RoleLossOperationState::Compensating, 1_000)
            .unwrap());
        state.delete_role_loss_operation("missing").unwrap();
        assert!(state.get_role_loss_operation("missing").unwrap().is_none());
    }

    /// `list_role_loss_operations_in_states` is what the reconciliation sweep
    /// consults: it must return exactly the rows in the requested states,
    /// across every group, and none of the rows in a state that wasn't asked
    /// for.
    #[test]
    fn list_role_loss_operations_in_states_filters_correctly_across_groups() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .insert_role_loss_operation(
                "op-a",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-a",
                    lease_id: Some("lease-a"),
                    action: RoleLossAction::Demote,
                    local_path: Some("/local/a"),
                    now_unix: 1_000,
                },
            )
            .unwrap();
        state
            .insert_role_loss_operation(
                "op-b",
                "group-2",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-c",
                    lease_id: Some("lease-b"),
                    action: RoleLossAction::Unlink,
                    local_path: Some("/local/b"),
                    now_unix: 1_000,
                },
            )
            .unwrap();
        state
            .advance_role_loss_operation("op-b", RoleLossOperationState::WorkerCommitted, 1_001)
            .unwrap();
        state
            .insert_role_loss_operation(
                "op-c",
                "group-3",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-d",
                    lease_id: Some("lease-c"),
                    action: RoleLossAction::Demote,
                    local_path: None,
                    now_unix: 1_000,
                },
            )
            .unwrap();
        state
            .advance_role_loss_operation("op-c", RoleLossOperationState::Compensating, 1_001)
            .unwrap();

        let prepared_only =
            state.list_role_loss_operations_in_states(&[RoleLossOperationState::Prepared]).unwrap();
        assert_eq!(
            prepared_only.iter().map(|o| o.operation_id.as_str()).collect::<Vec<_>>(),
            vec!["op-a"]
        );

        let in_flight = state
            .list_role_loss_operations_in_states(&[
                RoleLossOperationState::WorkerCommitted,
                RoleLossOperationState::Compensating,
            ])
            .unwrap();
        let mut ids: Vec<&str> = in_flight.iter().map(|o| o.operation_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["op-b", "op-c"]);

        assert!(state
            .list_role_loss_operations_in_states(&[RoleLossOperationState::Completed])
            .unwrap()
            .is_empty());

        // Empty request list -> empty result, no panic on an empty `IN (...)`.
        assert!(state.list_role_loss_operations_in_states(&[]).unwrap().is_empty());
    }

    /// The retry counter the reconciliation sweep uses purely for escalating
    /// its own logging: it starts at zero and increments by exactly one per
    /// call, returning the new value each time -- and the row is never
    /// deleted or otherwise affected by incrementing it.
    #[test]
    fn increment_role_loss_operation_attempts_counts_up_and_persists() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-a",
                    lease_id: Some("lease-1"),
                    action: RoleLossAction::Demote,
                    local_path: Some("/local/photos"),
                    now_unix: 1_000,
                },
            )
            .unwrap();
        assert_eq!(state.increment_role_loss_operation_attempts("op-1", 1_001).unwrap(), 1);
        assert_eq!(state.increment_role_loss_operation_attempts("op-1", 1_002).unwrap(), 2);
        assert_eq!(state.increment_role_loss_operation_attempts("op-1", 1_003).unwrap(), 3);
        assert_eq!(state.get_role_loss_operation("op-1").unwrap().unwrap().attempts, 3);
    }

    /// `insert_role_loss_operation` is an idempotent upsert keyed on
    /// `operation_id`, matching `record_handoff_lease`'s own idiom: a second
    /// insert with the same id resets it back to `Prepared` with a fresh
    /// `attempts` counter, rather than erroring or leaving stale fields from
    /// an earlier attempt.
    #[test]
    fn re_inserting_the_same_operation_id_resets_it_to_prepared() {
        let state = SyncState::open_in_memory().unwrap();
        state
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-a",
                    lease_id: Some("lease-1"),
                    action: RoleLossAction::Demote,
                    local_path: Some("/local/photos"),
                    now_unix: 1_000,
                },
            )
            .unwrap();
        state
            .advance_role_loss_operation("op-1", RoleLossOperationState::Compensating, 1_001)
            .unwrap();
        state.increment_role_loss_operation_attempts("op-1", 1_002).unwrap();

        state
            .insert_role_loss_operation(
                "op-1",
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-b",
                    target_device_id: "device-a",
                    lease_id: Some("lease-2"),
                    action: RoleLossAction::Demote,
                    local_path: Some("/local/photos"),
                    now_unix: 2_000,
                },
            )
            .unwrap();
        let op = state.get_role_loss_operation("op-1").unwrap().unwrap();
        assert_eq!(op.state, RoleLossOperationState::Prepared);
        assert_eq!(op.attempts, 0);
        assert_eq!(op.created_at_unix, 2_000);
    }

    // --- One live link per group -------------------------------------------
    //
    // The index is group-scoped and path-relative; every scan is root-scoped
    // and authoritative. Two live roots on one group therefore make each
    // root's scan read the other root's files as deleted and tombstone them --
    // signed changes that ride the change-DAG to every device. These tests pin
    // each layer that refuses that state.

    /// Raw SQL, not `add_link`: this pins the SCHEMA layer, which is what
    /// survives a writer that never goes through the Rust chokepoint (a raw
    /// `sqlite3` session, a second process, a future third insert site).
    ///
    /// Uses the EXACT statement production used before this fix
    /// (`INSERT OR REPLACE`), because that is the shape the trigger has to beat:
    /// against a UNIQUE index `INSERT OR REPLACE` does not error, it deletes the
    /// conflicting row. Asserting the surviving row count is what pins that
    /// difference.
    ///
    /// Deliberately performs a REAL insert rather than asserting the trigger's
    /// presence in `sqlite_master`: a presence check cannot tell a working
    /// trigger from one that never fires, so it would be vacuous.
    #[test]
    fn init_installs_the_triggers_and_a_raw_second_link_is_refused() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        let conn = state.pool.get().unwrap();
        let err = conn
            .execute(
                "INSERT OR REPLACE INTO links (local_path, group_id, paused) VALUES (?1, ?2, 0)",
                rusqlite::params!["/home/alice/PhotosCopy", "group-1"],
            )
            .expect_err("the schema itself must refuse a second live link for one group");

        assert!(
            matches!(err, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation),
            "expected a constraint violation from the trigger, got {err:?}"
        );
        assert_eq!(
            state.list_links().unwrap().len(),
            1,
            "the refusal must not have deleted the surviving row"
        );
    }

    /// The guard against turning a rare data-loss bug into a common "cannot use
    /// the app" bug: an un-scoped UPDATE trigger aborts ordinary pause/policy/
    /// token writes. Every step here must pass.
    #[test]
    fn the_triggers_do_not_block_a_legitimate_link_lifecycle() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        state
            .set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand)
            .unwrap();
        state.set_paused("/home/alice/Photos", true).unwrap();
        state.set_paused("/home/alice/Photos", false).unwrap();
        state.set_link_root_token_for_group("group-1", "tok-1").unwrap();
        state.set_max_local_size_bytes("/home/alice/Photos", Some(1_024)).unwrap();
        state.set_windows_symlink_opt_in("/home/alice/Photos", true).unwrap();
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        // Re-link with no live sibling: a legitimate un-orphan.
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        assert!(!state.list_links().unwrap()[0].orphaned);

        state.remove_link("/home/alice/Photos").unwrap();
        assert!(state.list_links().unwrap().is_empty());
    }

    /// The un-orphan path is real, not theoretical: `INSERT OR REPLACE`
    /// silently flipped `orphaned` 1 -> 0. This pins the UPDATE trigger that
    /// closes it.
    #[test]
    fn un_orphaning_into_a_second_live_link_is_refused() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.add_link("/home/alice/PhotosOld", "group-2").unwrap();
        state.mark_link_orphaned("/home/alice/PhotosOld").unwrap();
        // Repoint the orphaned row at group-1 while it is still orphaned (no
        // live-sibling conflict yet), so the only thing left to refuse is the
        // un-orphan itself.
        state
            .pool
            .get()
            .unwrap()
            .execute(
                "UPDATE links SET group_id = 'group-1' WHERE local_path = ?1",
                ["/home/alice/PhotosOld"],
            )
            .unwrap();

        let err = state
            .pool
            .get()
            .unwrap()
            .execute(
                "UPDATE links SET orphaned = 0 WHERE local_path = ?1",
                ["/home/alice/PhotosOld"],
            )
            .expect_err("un-orphaning into a second live link must be refused");

        assert!(
            matches!(err, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation),
            "expected a constraint violation from the un-orphan trigger, got {err:?}"
        );
    }

    /// THE BUG. Also pins that the refusal deletes NOTHING -- the exact
    /// regression a partial UNIQUE index would have introduced, since
    /// `INSERT OR REPLACE` against one DELETES the conflicting row.
    #[test]
    fn a_second_link_on_one_group_is_refused_and_deletes_nothing() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        let err = state
            .add_link("/home/alice/PhotosCopy", "group-1")
            .expect_err("a group must not be linked at two folders");

        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");
        let links = state.list_links().unwrap();
        assert_eq!(links.len(), 1, "the refusal must not delete the existing link");
        assert_eq!(links[0].local_path, "/home/alice/Photos");
    }

    /// The second insert site. The brief's explicit constraint is that BOTH are
    /// covered; this also pins that the refusal does not escape the shared
    /// transaction and strand a marker, which would leave the phantom-active
    /// link `add_link_with_pending_enrollment` exists to prevent.
    #[test]
    fn the_pending_enrollment_insert_site_is_covered_and_rolls_back() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();

        let marker = PendingEnrollment {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: "group-1".to_string(),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/PhotosCopy".to_string(),
        };
        let err = state
            .add_link_with_pending_enrollment("/home/alice/PhotosCopy", "group-1", &marker)
            .expect_err("the pending-enrollment insert site must refuse a second live link too");

        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");
        let links = state.list_links().unwrap();
        assert_eq!(links.len(), 1, "the refusal must not have added or deleted a link");
        assert!(
            state.list_pending_enrollments().unwrap().is_empty(),
            "the marker must roll back with the link -- a stranded marker names a local path with \
             no link behind it and is never retried"
        );
    }

    /// `INSERT OR REPLACE` NULLed `root_token` (re-arming adoption, which
    /// disarms the unmounted-volume guard -> whole-folder tombstoning) and reset
    /// the policy to `eager` (silently re-downloading everything). Both are
    /// silent-loss vectors in their own right.
    #[test]
    fn relinking_the_same_path_preserves_root_token_and_policy() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.set_link_root_token_for_group("group-1", "tok-1").unwrap();
        state
            .set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand)
            .unwrap();

        state.add_link("/home/alice/Photos", "group-1").unwrap();

        assert_eq!(
            state.link_root_token_for_group("group-1").unwrap(),
            Some("tok-1".to_string()),
            "re-linking must not wipe the adopted root token"
        );
        assert_eq!(
            state.materialization_policy_for_group("group-1").unwrap(),
            Some(MaterializationPolicy::OnDemand),
            "re-linking must not silently reset the storage mode to eager"
        );
    }

    /// The same-path branch must un-orphan EXPLICITLY. Leaving the row
    /// untouched instead would make re-linking an orphaned folder a silent
    /// no-op.
    #[test]
    fn relinking_an_orphaned_path_un_orphans_it() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.set_link_root_token_for_group("group-1", "tok-1").unwrap();
        state.mark_link_orphaned("/home/alice/Photos").unwrap();

        state.add_link("/home/alice/Photos", "group-1").unwrap();

        let links = state.list_links().unwrap();
        assert!(!links[0].orphaned, "re-linking an orphaned path must reactivate it, not no-op");
        assert_eq!(
            state.link_root_token_for_group("group-1").unwrap(),
            Some("tok-1".to_string()),
            "the un-orphan must preserve the adopted token"
        );
    }

    /// `INSERT OR REPLACE` silently repointed the folder at a new group while
    /// every one of its indexed file rows still belonged to the old one.
    #[test]
    fn a_path_live_for_another_group_is_refused() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.set_link_root_token_for_group("group-1", "tok-1").unwrap();

        let err = state
            .add_link("/home/alice/Photos", "group-2")
            .expect_err("repointing a linked folder at a different group must be refused");

        assert!(matches!(err, SyncError::InvalidInput(_)), "got {err:?}");
        let links = state.list_links().unwrap();
        assert_eq!(links[0].group_id, "group-1", "the folder must still belong to its group");
        assert_eq!(
            state.link_root_token_for_group("group-1").unwrap(),
            Some("tok-1".to_string()),
            "the refusal must not wipe the token"
        );
    }

    /// The peer-apply seam. Non-vacuous because `peer_session` builds no
    /// `VerifiedRoot` outside `cfg(test)`, so the root-identity gate cannot
    /// reach this path -- this resolver is the only thing covering it.
    #[test]
    fn link_gate_for_group_errs_on_ambiguity() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.force_second_live_link_for_test("/home/alice/PhotosCopy", "group-1").unwrap();

        let err = state
            .link_gate_for_group("group-1")
            .expect_err("the peer-apply gate must refuse to pick one of two roots");
        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");
    }

    /// The unqualified `WHERE group_id = ?1` stamped the SAME token onto BOTH
    /// rows -- the mechanism that makes a duplicate pair permanently
    /// indistinguishable by the very check meant to tell them apart.
    #[test]
    fn set_link_root_token_for_group_refuses_to_fan_out() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/Photos", "group-1").unwrap();
        state.force_second_live_link_for_test("/home/alice/PhotosCopy", "group-1").unwrap();

        let err = state
            .set_link_root_token_for_group("group-1", "tok-fanout")
            .expect_err("stamping one token onto two rows must be refused");

        assert!(matches!(err, SyncError::AmbiguousLink { .. }), "got {err:?}");
        let conn = state.pool.get().unwrap();
        let mut stmt =
            conn.prepare("SELECT root_token FROM links WHERE group_id = 'group-1'").unwrap();
        let tokens: Vec<Option<String>> =
            stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert!(
            tokens.iter().all(|t| t.is_none()),
            "neither row's token may change when the fan-out is refused, got {tokens:?}"
        );
    }

    /// Zero live links stays legal: it is the documented "no link registered,
    /// drive a scan against a bare directory" case. A `!= 1` check would break
    /// it for no safety gain.
    #[test]
    fn ensure_unambiguous_group_allows_zero_links() {
        let state = SyncState::open_in_memory().unwrap();
        state.ensure_unambiguous_group("group-1").unwrap();
    }

    // --- The orphan-filter class: the gate and every by-group resolver must
    // --- key on the SAME row set ---------------------------------------------

    /// R5. The paths in an `AmbiguousLink` ARE the remedy -- the user is told to
    /// `unlink` them. Naming an ORPHANED row sends them to unlink a folder whose
    /// removal changes nothing about the refusal, while the two folders that
    /// actually collide stay linked.
    #[test]
    fn an_ambiguous_link_error_names_only_the_live_folders() {
        let state = SyncState::open_in_memory().unwrap();
        // Sorts first, so an unfiltered `ORDER BY local_path` would list it.
        state.add_link("/home/alice/AAA-dead", "group-1").unwrap();
        state.mark_link_orphaned("/home/alice/AAA-dead").unwrap();
        state.add_link("/home/alice/MMM-live", "group-1").unwrap();
        state.force_second_live_link_for_test("/home/alice/ZZZ-live", "group-1").unwrap();

        let err = state
            .set_link_root_token_for_group("group-1", "tok")
            .expect_err("two live rows must still be refused");

        let SyncError::AmbiguousLink { local_paths, .. } = err else {
            panic!("got {err:?}");
        };
        assert_eq!(
            local_paths,
            vec!["/home/alice/MMM-live".to_string(), "/home/alice/ZZZ-live".to_string()],
            "only the LIVE folders may be named: every path here is one the user is told to \
             unlink, and unlinking the orphaned one resolves nothing"
        );
    }

    /// R2, row-level. The writer's fan-out assert must not be weakened into "it
    /// only touches live rows now, so a second live row is fine": with two LIVE
    /// rows it must still refuse and stamp NOTHING, and an orphaned sibling must
    /// never have its token disturbed.
    #[test]
    fn the_token_writer_stamps_exactly_one_live_row_and_never_the_orphan() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/AAA-dead", "group-1").unwrap();
        state.set_link_root_token_for_group("group-1", "dead-token").unwrap();
        state.mark_link_orphaned("/home/alice/AAA-dead").unwrap();
        state.add_link("/home/alice/MMM-live", "group-1").unwrap();

        state.set_link_root_token_for_group("group-1", "live-token").unwrap();

        assert_eq!(
            state.link_root_tokens_for_group_unchecked_for_test("group-1").unwrap(),
            vec![Some("dead-token".to_string()), Some("live-token".to_string())],
            "the write must land on the LIVE row alone and leave the orphan's identity intact"
        );
    }

    /// R6. The sibling defect, same shape as the token reader's: the gate counts
    /// LIVE rows while this `SELECT` read ALL of them and took the lowest
    /// `local_path`. With the orphaned path sorting first, the LIVE folder gets
    /// materialized under the DEAD folder's symlink policy.
    #[test]
    fn an_orphaned_rows_symlink_opt_in_does_not_decide_the_live_links_policy() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/AAA-dead", "group-1").unwrap();
        state.set_windows_symlink_opt_in("/home/alice/AAA-dead", true).unwrap();
        state.mark_link_orphaned("/home/alice/AAA-dead").unwrap();
        state.add_link("/home/alice/MMM-live", "group-1").unwrap();

        assert!(
            !state.windows_symlink_opt_in_for_group("group-1").unwrap(),
            "the LIVE link never opted in; a dead sibling row must not answer for it"
        );
    }

    /// R8. THE NON-NEGOTIABLE: this refusal is per-GROUP, never per-DATABASE.
    /// `init()` runs on every `SyncState::open` and every link mutation needs the
    /// daemon, so a database-wide halt would brick the daemon for every folder
    /// the user has. An ambiguous G1 must leave G2 completely untouched.
    #[test]
    fn an_ambiguous_group_does_not_halt_any_other_group() {
        let state = SyncState::open_in_memory().unwrap();
        state.add_link("/home/alice/G1-a", "group-1").unwrap();
        state.force_second_live_link_for_test("/home/alice/G1-b", "group-1").unwrap();
        state.add_link("/home/alice/G2", "group-2").unwrap();

        state
            .ensure_unambiguous_group("group-1")
            .expect_err("the poisoned group must refuse -- otherwise this test proves nothing");

        // Every seam the poisoned group refuses at must still serve group-2.
        state.ensure_unambiguous_group("group-2").expect("a healthy group must not be collateral");
        assert!(matches!(state.link_gate_for_group("group-2").unwrap(), LinkGate::Live { .. }));
        state.set_link_root_token_for_group("group-2", "tok-2").unwrap();
        assert_eq!(state.link_root_token_for_group("group-2").unwrap(), Some("tok-2".to_string()));
        assert_eq!(
            state.live_link_local_path_for_group("group-2").unwrap(),
            Some("/home/alice/G2".to_string())
        );
        assert!(!state.suppress_tombstones_for_group("group-2").unwrap());
    }

    /// R7. The message IS the recovery procedure -- it is the only instruction
    /// the user gets. "Move any files you want to keep into ONE of them FIRST"
    /// stated a precondition that does not exist (unlinking never deletes a
    /// file) and read as "unlinking will destroy files", which is what drove a
    /// user who could not tell the two named folders apart to guess.
    #[test]
    fn the_ambiguous_link_message_names_the_real_remedy() {
        let rendered = SyncError::AmbiguousLink {
            group_id: "group-1".into(),
            local_paths: vec!["/home/alice/Photos".into(), "/home/alice/PhotosCopy".into()],
        }
        .to_string();

        assert!(
            !rendered.contains("into ONE of them FIRST"),
            "the false precondition that caused the misrecovery must be gone, got: {rendered}"
        );
        for path in ["/home/alice/Photos", "/home/alice/PhotosCopy"] {
            assert!(rendered.contains(path), "every live folder must be named, got: {rendered}");
        }
        assert!(
            rendered.contains("yadorilink unlink"),
            "the remedy must be a command, got: {rendered}"
        );
        assert!(
            rendered.contains("does not delete any files"),
            "the non-destructive guarantee is what lets the user act; without it they guess, \
             got: {rendered}"
        );
        assert!(
            rendered.contains("sync is stopped for this folder group"),
            "the refusal must read as scoped to this group, not as the app being broken, \
             got: {rendered}"
        );
    }
}
