//! Owns the connection pool and in-process writer serialization that every
//! caller (`yadorilink-sync-core`'s repositories today) writes through.
//! Moved verbatim out of `yadorilink-sync-core` (Phase 7D-4.2) so it can be
//! shared by every future crate that needs SQLite-backed storage without
//! each one duplicating pool/writer-gate/schema-bootstrap machinery of its
//! own -- and, just as importantly, without two independent pools/writer-
//! gates racing each other against the same on-disk file (the exact
//! `SQLITE_LOCKED` bug class `locked_write`'s writer_gate was built to
//! close in the first place).

use std::path::Path;
use std::sync::Mutex;

use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::error::{DatabaseError, SqlOperationError};
use crate::pool::{
    checkout, madsim_or_default_pool, retry_on_database_locked, ConnectionPool, BUSY_TIMEOUT,
};

// `stats`/`reset`/`record_gate_acquisition` below are a small, PERMANENT
// writer-gate observability primitive -- not temporary C4 investigation
// scaffolding, even though they started that way. Repository-level tests
// (e.g. `materialization_job_repository`'s `enqueue_pending_writer_gate_
// tests`) rely on `reset()`/`stats()` to assert that a specific operation
// does or does not take the process-wide write lock at all -- a property
// no amount of row-state inspection alone can observe, since a no-op SQL
// UPDATE and a call that never opens a transaction leave identical
// on-disk state.
//
// `call_sites`/`record_call_site`/`call_site_stats` below are PERMANENT
// too (reclassified 2026-09-01 after a second investigation -- the
// decision-9 dual-scheduler cutover -- relied on them again; see their
// own doc comment for why re-deriving this every time is wasted effort).
//
// `record_gate_hold`/`hold_site_stats` are PERMANENT too, for a reason the
// wait-side counters structurally cannot cover: `record_gate_acquisition`
// times how long a caller WAITED, which by construction never names the
// caller that was holding the gate and made it wait. Every writer-gate
// starvation investigated on this codebase so far has turned on exactly that
// question, and answering it by inference from a wait histogram wasted real
// time twice. Cost is one `Instant::elapsed` and one hash-map update per
// write transaction, inside the gate the caller already holds.
pub mod c4_diag {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static GATE_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
    static GATE_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn record_gate_acquisition(wait: Duration) {
        GATE_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        GATE_WAIT_NANOS.fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
        if wait > Duration::from_millis(500) {
            tracing::warn!(
                wait_ms = wait.as_millis() as u64,
                "C4_DIAG: writer_gate acquisition took a long time"
            );
        }
    }

    /// Total `locked_write` invocations (one per fsync-backed DB write
    /// transaction, regardless of how many rows/paths the caller's closure
    /// covers) and cumulative time spent waiting to acquire `writer_gate`,
    /// since process start or the last [`reset`].
    pub fn stats() -> (u64, Duration) {
        (
            GATE_ACQUISITIONS.load(Ordering::Relaxed),
            Duration::from_nanos(GATE_WAIT_NANOS.load(Ordering::Relaxed)),
        )
    }

    /// Zeroes every counter in this module -- call before a measured storm so
    /// [`stats`], [`call_site_stats`] and [`hold_site_stats`] all reflect only
    /// that run, not whatever earlier setup did.
    pub fn reset() {
        GATE_ACQUISITIONS.store(0, Ordering::Relaxed);
        GATE_WAIT_NANOS.store(0, Ordering::Relaxed);
        call_sites().lock().unwrap_or_else(|p| p.into_inner()).clear();
        hold_sites().lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    // PERMANENT per-call-site attribution (reclassified from an earlier
    // "temporary, remove after investigation" framing: this pulled its
    // weight across two separate C4 investigations on this codebase --
    // the original storm re-measurement that motivated it, and the
    // decision-9 dual-scheduler cutover -- and costs a `#[track_caller]`
    // plus one hash-map update inside a lock the caller already holds, so
    // there is no reason to keep re-adding it every time a new writer-gate
    // question comes up). `record_gate_acquisition` above only counts and
    // times acquisitions in aggregate, which cannot say WHICH of
    // `SyncDatabase::write`/`write_immediate`'s many call sites is
    // actually driving that volume. `#[track_caller]` on both public
    // entry points (and on this function) makes `Location::caller()`
    // resolve to the caller's own call site (file:line), not this
    // module's -- recorded here, inside `locked_write`'s own already-held
    // `writer_gate`, so this adds no additional lock contention beyond
    // what already exists.
    fn call_sites() -> &'static std::sync::Mutex<std::collections::HashMap<String, u64>> {
        static SITES: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
            std::sync::OnceLock::new();
        SITES.get_or_init(Default::default)
    }

    #[track_caller]
    pub(crate) fn record_call_site() {
        let location = std::panic::Location::caller().to_string();
        let mut sites = call_sites().lock().unwrap_or_else(|p| p.into_inner());
        *sites.entry(location).or_insert(0) += 1;
    }

    // Per-call-site writer_gate HOLD time -- the other half of
    // `record_gate_acquisition` above, which can only ever say that a caller
    // waited, never who made it wait. See this module's own header comment.
    fn hold_sites() -> &'static std::sync::Mutex<std::collections::HashMap<String, (u64, u128)>> {
        static SITES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, (u64, u128)>>,
        > = std::sync::OnceLock::new();
        SITES.get_or_init(Default::default)
    }

    pub(crate) fn record_gate_hold(
        location: &'static std::panic::Location<'static>,
        held: Duration,
    ) {
        let mut sites = hold_sites().lock().unwrap_or_else(|p| p.into_inner());
        let entry = sites.entry(location.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += held.as_micros();
        if held > Duration::from_millis(500) {
            tracing::warn!(
                held_ms = held.as_millis() as u64,
                call_site = %location,
                "C4_DIAG: writer_gate was HELD for a long time"
            );
        }
    }

    /// Every distinct `write`/`write_immediate` call site seen since process
    /// start or the last [`reset`], with `(count, total_held_micros)`, sorted
    /// by total held time descending.
    pub fn hold_site_stats() -> Vec<(String, u64, u128)> {
        let sites = hold_sites().lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<(String, u64, u128)> =
            sites.iter().map(|(k, (n, micros))| (k.clone(), *n, *micros)).collect();
        v.sort_by(|a, b| b.2.cmp(&a.2));
        v
    }

    /// Every distinct `write`/`write_immediate` call site seen since
    /// process start or the last [`reset`], with its own acquisition
    /// count, sorted by count descending -- answers "who is actually
    /// calling `SyncDatabase::write*` this many times" directly instead of
    /// by inference.
    pub fn call_site_stats() -> Vec<(String, u64)> {
        let sites = call_sites().lock().unwrap_or_else(|p| p.into_inner());
        let mut v: Vec<(String, u64)> = sites.iter().map(|(k, n)| (k.clone(), *n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

pub struct SyncDatabase {
    /// Each call checks out its own pooled connection (`r2d2` +
    /// `r2d2_sqlite`) against a WAL-mode database, so multiple readers
    /// (and a reader alongside a writer) proceed concurrently instead of
    /// blocking on each other -- SQLite's own WAL concurrency model, not
    /// an in-process lock, governs access. Writers still serialize against
    /// each other (SQLite allows only one writer at a time even in WAL
    /// mode), handled by `BUSY_TIMEOUT` rather than an in-process mutex.
    pool: ConnectionPool,
    /// In-process writer gate: every write transaction issued through this
    /// handle acquires this before touching SQLite, so two of the SAME
    /// process's own threads can never race for SQLite's single writer
    /// slot at all -- the `SQLITE_BUSY`/`SQLITE_LOCKED` family between our
    /// own writers becomes structurally impossible rather than merely
    /// retried (`BUSY_TIMEOUT` and `retry_on_database_locked`'s bounded
    /// retry remain as defense-in-depth for anything external and for
    /// shared-cache table locks). A thread-local re-entrancy check (see
    /// `locked_write`) makes a nested write from within a write closure
    /// run gate-free instead of deadlocking.
    writer_gate: Mutex<()>,
}

impl SyncDatabase {
    /// Opens (creating if needed) a file-backed database with WAL mode
    /// enabled -- WAL lets readers proceed without blocking behind the
    /// single writer SQLite allows at a time, unlike the default
    /// rollback-journal mode. Every pooled connection additionally gets
    /// `BUSY_TIMEOUT` so two of this process's own writers waiting on each
    /// other resolve by retrying, not erroring, and `synchronous = FULL`
    /// so a committed transaction survives an OS crash or power loss.
    ///
    /// Bootstraps on a single, unpooled connection BEFORE the pool exists
    /// at all -- deliberately not the previous shape (build the pool, then
    /// run the WAL pragma and schema bootstrap through `with_init` on
    /// whichever pooled connections happen to get established). Switching
    /// `journal_mode` to WAL is itself a mode change requiring SQLite's
    /// exclusive lock, and `r2d2::Pool::new`/`Pool::builder().build(..)`'s
    /// default `min_idle` eagerly establishes connections up to the pool's
    /// max size at build time, in the background -- so the previous shape
    /// let several of THIS PROCESS's OWN connections race each other to
    /// switch journal mode on the same file concurrently, before
    /// `writer_gate` (or anything else) existed to order them. Confirmed
    /// as a real source of `database is locked` errors observed at
    /// process-startup under load (multiple `SyncDatabase::open` calls in
    /// the same process, e.g. one per simulated device in a multi-device
    /// test). journal_mode is a property persisted in the database FILE
    /// itself (survives connection close), so switching it once here,
    /// before any pooled connection is ever established, means every
    /// later pooled connection simply observes WAL mode already in
    /// effect -- no per-connection WAL pragma is needed or issued by the
    /// pool's own `with_init` any more, only the two purely
    /// per-connection settings (`busy_timeout`, `synchronous`) that carry
    /// no mode-switch race. Schema bootstrap also moves onto this same
    /// bootstrap connection for the identical reason: it used to run on
    /// whichever pooled connection `checkout` happened to hand back,
    /// itself racing the same pool-startup fan-out.
    ///
    /// `schema_init` is the caller's complete schema-bootstrap step, run on
    /// the bootstrap connection before `open` returns -- the sole place
    /// schema initialization happens. This crate does not inspect or
    /// sequence it in any way; the caller (today, `yadorilink-sync-core`'s
    /// composition root) owns what runs and in what order, including
    /// whether/when it calls this crate's own [`crate::schema::init_schema`]
    /// for the core DDL that crate doesn't own. This crate knows no
    /// domain-specific name (DAG, filesystem transaction, materialization
    /// job, ...) here or anywhere else.
    pub fn open(
        path: impl AsRef<Path>,
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        {
            let conn = Connection::open(path)?;
            conn.busy_timeout(BUSY_TIMEOUT)?;
            // journal_mode is itself a query (it returns the mode that
            // was actually applied), hence `pragma_update_and_check`
            // rather than `pragma_update`.
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
            // This database is the durable source of truth for what
            // content exists, so it must not depend on SQLite's
            // compile-time default for `synchronous` (only NORMAL under
            // WAL). FULL fsyncs the WAL before reporting a commit,
            // closing the window where an OS crash or power loss could
            // lose the last committed transaction. Set here too (not just
            // in the pool's own per-connection init below), since this
            // bootstrap connection is also the one `schema_init` runs on.
            conn.pragma_update(None, "synchronous", "FULL")?;
            // Defense-in-depth, ahead of `schema_init` even reaching
            // `crate::schema::init_schema`'s own identical check: see
            // `check_schema_version_supported`'s own doc comment for why
            // this crate calls it directly here too, rather than trusting
            // every current and future `schema_init` closure to reach it.
            crate::schema::check_schema_version_supported(&conn)?;
            schema_init(&conn)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            // No journal_mode pragma here -- see this method's own doc
            // comment for why the bootstrap connection above already
            // switched it once, durably, before this pool (or any pooled
            // connection) existed.
            conn.pragma_update(None, "synchronous", "FULL")?;
            Ok(())
        });
        let pool = madsim_or_default_pool(manager)?;
        Ok(Self { pool, writer_gate: Mutex::new(()) })
    }

    /// Opens an in-memory database, pooled just like the file-backed case.
    /// Plain SQLite `:memory:` databases are private to the single
    /// connection that opened them, so naively pooling one would give
    /// each checkout its own empty database and silently break every
    /// write-then-read call pattern. `r2d2_sqlite`'s
    /// `SqliteConnectionManager::memory` avoids that: it opens
    /// `file:<uuid>?mode=memory&cache=shared` (a *named*, shared-cache
    /// in-memory database) so every pooled connection attaches to the
    /// *same* in-memory database, and it internally keeps one extra
    /// connection alive for the manager's lifetime so the database isn't
    /// dropped the instant every checked-out connection happens to be
    /// idle (shared-cache `:memory:` databases are freed when their last
    /// connection closes). WAL mode is skipped here: SQLite doesn't
    /// support WAL for in-memory databases (the pragma is a no-op), only
    /// `BUSY_TIMEOUT` is needed so pooled writers don't race each other
    /// into `SQLITE_BUSY`.
    pub fn open_in_memory(
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let manager = SqliteConnectionManager::memory().with_init(|conn| {
            conn.busy_timeout(BUSY_TIMEOUT)?;
            Ok(())
        });
        Self::open_with_manager(manager, schema_init)
    }

    fn open_with_manager(
        manager: SqliteConnectionManager,
        schema_init: impl FnOnce(&Connection) -> Result<(), DatabaseError>,
    ) -> Result<Self, DatabaseError> {
        let pool = madsim_or_default_pool(manager)?;
        let conn = checkout::<DatabaseError>(&pool)?;
        // Defense-in-depth -- see `Self::open`'s identical call and
        // `check_schema_version_supported`'s own doc comment for why.
        crate::schema::check_schema_version_supported(&conn)?;
        schema_init(&conn)?;
        drop(conn);
        Ok(Self { pool, writer_gate: Mutex::new(()) })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only raw pool access, for a fixture that needs multiple
    /// concurrently-held raw connections (a deliberate lock-contention
    /// test) or that corrupts the schema directly (`DROP TABLE ...`) --
    /// neither expressible through `read`/`write`/`write_immediate`'s
    /// one-shot closures. Production code must never call this; every real
    /// read or write goes through the three methods below, which is what
    /// keeps `pool` itself private.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pool_for_test(&self) -> &ConnectionPool {
        &self.pool
    }

    /// A read, retried on a transient SQLITE_BUSY/SQLITE_LOCKED (external
    /// process, shared-cache table lock) but NOT serialized against this
    /// process's own writer_gate -- concurrent reads are safe and should not
    /// contend with each other.
    pub fn read<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        retry_on_database_locked(|| {
            let conn = checkout::<E>(&self.pool)?;
            operation(&conn)
        })
    }

    /// A single-statement (or few-statement, no explicit transaction needed)
    /// write, serialized against this process's own writer_gate AND retried
    /// on a transient lock error -- the same guarantee `locked_write`
    /// already gives multi-statement transactional writers, now available to
    /// callers that just need one `execute`/`query_row` without opening
    /// their own transaction.
    #[track_caller]
    pub fn write<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&mut Connection) -> Result<T, E>,
    ) -> Result<T, E> {
        c4_diag::record_call_site();
        self.locked_write(std::panic::Location::caller(), || {
            let mut conn = checkout::<E>(&self.pool)?;
            operation(&mut conn)
        })
    }

    /// A multi-statement write that must commit atomically -- opens an
    /// IMMEDIATE transaction (see `new_immediate_write_transaction`'s own
    /// doc comment for why IMMEDIATE, not the rusqlite default DEFERRED),
    /// serialized against the writer_gate and retried, commits on `Ok`.
    #[track_caller]
    pub fn write_immediate<T, E: SqlOperationError>(
        &self,
        mut operation: impl FnMut(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        c4_diag::record_call_site();
        self.locked_write(std::panic::Location::caller(), || {
            let mut conn = checkout::<E>(&self.pool)?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let result = operation(&tx)?;
            tx.commit().map_err(E::from)?;
            Ok(result)
        })
    }

    /// Runs one write operation with the in-process writer gate held: our
    /// own threads are serialized BEFORE SQLite ever sees a second writer,
    /// making own-process `SQLITE_BUSY`/`SQLITE_LOCKED` contention
    /// structurally impossible instead of retried-until-lucky. The bounded
    /// `retry_on_database_locked` stays underneath as defense-in-depth
    /// (external processes, shared-cache table locks held by readers). A
    /// write closure that re-enters another `locked_write` on the SAME
    /// thread (nested helper calls) is detected via a thread-local flag and
    /// runs gate-free -- already serialized by the outer holder -- so the
    /// non-reentrant mutex can never self-deadlock. The closures never
    /// `.await`, so the flag cannot leak across tasks on a work-stealing
    /// runtime; a panicking closure restores it via the drop guard.
    fn locked_write<T, E: SqlOperationError>(
        &self,
        c4_diag_location: &'static std::panic::Location<'static>,
        op: impl FnMut() -> Result<T, E>,
    ) -> Result<T, E> {
        thread_local! {
            static IN_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        }
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                IN_WRITE.with(|f| f.set(false));
            }
        }
        if IN_WRITE.with(|f| f.get()) {
            return retry_on_database_locked(op);
        }
        // PERMANENT writer-gate observability (see this module's `c4_diag`
        // header comment): total write-transaction count and cumulative
        // time spent waiting to acquire `writer_gate` -- one outer
        // (non-reentrant) `locked_write` call is exactly one fsync-backed
        // commit, regardless of how many rows or paths the caller's
        // closure covers, so this count directly answers "how many DB
        // write transactions has this process done, and how much time did
        // callers spend waiting for the gate" for any future writer-gate
        // contention investigation, not just the one that motivated it.
        let c4_diag_wait_started = std::time::Instant::now();
        let _gate = self.writer_gate.lock().unwrap_or_else(|p| p.into_inner());
        let c4_diag_wait_elapsed = c4_diag_wait_started.elapsed();
        c4_diag::record_gate_acquisition(c4_diag_wait_elapsed);
        IN_WRITE.with(|f| f.set(true));
        let _reset = Reset;
        let c4_diag_held_started = std::time::Instant::now();
        let result = retry_on_database_locked(op);
        c4_diag::record_gate_hold(c4_diag_location, c4_diag_held_started.elapsed());
        result
    }
}

/// One half of the fix for a real, previously-diagnosed
/// `SQLITE_LOCKED: database table is locked` failure class.
/// `rusqlite::Connection::transaction` opens a `DEFERRED` transaction by
/// default, which only acquires SQLite's write (`RESERVED`) lock lazily,
/// on the *first write statement actually executed inside it* -- not at
/// `BEGIN` time. A read-then-write first statement inside a transaction
/// (e.g. `UPDATE ... RETURNING`), under this crate's connection pool (many
/// pooled connections concurrently doing independent work), can lose a
/// `SHARED`-to-`RESERVED` lock-upgrade race against another pooled
/// connection's concurrent read -- SQLite's classic deferred-transaction
/// lock-upgrade pitfall. Opening the transaction `IMMEDIATE` instead
/// acquires the `RESERVED` write lock immediately at `BEGIN`, closing that
/// specific upgrade-race window.
///
/// **This alone was not sufficient** -- see `retry_on_database_locked` in
/// `pool.rs` for the other half, and why: `SQLITE_LOCKED` can also arise
/// from SQLite's shared-cache table-locking directly (independent of the
/// deferred-transaction upgrade problem this function closes), which
/// `open_in_memory` deliberately opts into (`cache=shared`, required for
/// pooled connections to see the same in-memory database at all) -- so
/// both mitigations are needed together, not either alone.
fn new_immediate_write_transaction(
    conn: &mut Connection,
) -> Result<rusqlite::Transaction<'_>, rusqlite::Error> {
    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// The core schema's authoring-identity triggers reference
    /// `changes`/`pruned_changes` (owned by `yadorilink-sync-core`'s
    /// `dag_store`, not this crate) -- stand in with the minimal shape
    /// those triggers query, then run this crate's own core `init_schema`,
    /// so this module's tests can exercise a full `SyncDatabase::open`
    /// standalone, without depending on sync-core.
    fn schema_init(conn: &Connection) -> Result<(), DatabaseError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS pruned_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);",
        )?;
        crate::schema::init_schema(conn)
    }

    fn open_test_db(path: &std::path::Path) -> SyncDatabase {
        SyncDatabase::open(path, schema_init).expect("open")
    }

    /// Regression test for the exact bug this crate's writer_gate exists to
    /// close: two independent callers (standing in for two different
    /// `yadorilink-sync-core` repository types) sharing ONE
    /// `Arc<SyncDatabase>` must never race each other into
    /// `SQLITE_LOCKED`/`SQLITE_BUSY` -- a long write_immediate transaction
    /// on one "repository" must serialize a short write on another
    /// "repository" through the shared writer_gate, not fail.
    #[test]
    fn repositories_sharing_database_do_not_race_independent_writer_gates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = Arc::new(open_test_db(&dir.path().join("writer-gate-regression.sqlite3")));

        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                Ok(conn.execute_batch("CREATE TABLE a (id INTEGER PRIMARY KEY); CREATE TABLE b (id INTEGER PRIMARY KEY);")?)
            })
            .expect("create tables");

        let long_writer_started = Arc::new(AtomicBool::new(false));
        let long_writer_database = database.clone();
        let long_writer_flag = long_writer_started.clone();
        let long_writer = std::thread::spawn(move || {
            long_writer_database.write_immediate::<_, DatabaseError>(|tx| {
                tx.execute("INSERT INTO a (id) VALUES (1)", [])?;
                long_writer_flag.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                Ok::<(), DatabaseError>(())
            })
        });

        while !long_writer_started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }

        // While the long writer_immediate transaction on table `a` is still
        // held, a short write on table `b` through the SAME shared
        // `SyncDatabase` must still succeed -- serialized behind the
        // writer_gate, never `SQLITE_LOCKED`.
        let short_write_result = database.write::<_, DatabaseError>(|conn: &mut Connection| {
            Ok(conn.execute("INSERT INTO b (id) VALUES (2)", [])?)
        });

        long_writer.join().expect("long writer thread panicked").expect("long writer");
        short_write_result.expect(
            "a write on one table must succeed while another write_immediate transaction is \
             held on a different table through the same shared writer_gate, not \
             SQLITE_LOCKED/SQLITE_BUSY",
        );

        let b_count: i64 = database
            .read::<i64, DatabaseError>(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM b", [], |row| row.get(0))?)
            })
            .expect("read back");
        assert_eq!(b_count, 1);
    }

    /// The writer_gate must release even when the write closure itself
    /// returns an error -- otherwise one failed write would permanently
    /// wedge every subsequent write on this `SyncDatabase`.
    #[test]
    fn writer_gate_releases_after_an_operation_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = open_test_db(&dir.path().join("writer-gate-error-release.sqlite3"));
        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
            })
            .expect("create table");

        let failing: Result<(), DatabaseError> =
            database.write::<_, DatabaseError>(|conn: &mut Connection| {
                conn.execute("INSERT INTO t (id) VALUES (1)", [])?;
                Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
            });
        assert!(failing.is_err());

        // The gate must not be wedged: this write must still go through.
        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                Ok(conn.execute("INSERT INTO t (id) VALUES (2)", [])?)
            })
            .expect("writer_gate must have been released after the prior error");
    }

    /// `write_immediate` must leave no partial write behind on failure --
    /// the transaction rolls back rather than committing a half-applied
    /// operation.
    #[test]
    fn write_immediate_leaves_no_partial_write_on_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let database = open_test_db(&dir.path().join("write-immediate-rollback.sqlite3"));
        database
            .write::<_, DatabaseError>(|conn: &mut Connection| {
                Ok(conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?)
            })
            .expect("create table");

        let failing: Result<(), DatabaseError> =
            database.write_immediate::<_, DatabaseError>(|tx| {
                tx.execute("INSERT INTO t (id) VALUES (1)", [])?;
                Err(DatabaseError::CorruptSchema("deliberate test failure".into()))
            });
        assert!(failing.is_err());

        let count: i64 = database
            .read::<i64, DatabaseError>(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))?)
            })
            .expect("read back");
        assert_eq!(count, 0, "a failed write_immediate must not leave a partial row committed");
    }

    /// Data and schema must both survive a close-and-reopen of the same
    /// file-backed database.
    #[test]
    fn data_and_schema_survive_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("reopen-survives.sqlite3");
        {
            let database = open_test_db(&path);
            database
                .write::<_, DatabaseError>(|conn: &mut Connection| {
                    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")?;
                    Ok(conn.execute("INSERT INTO t (id) VALUES (42)", [])?)
                })
                .expect("create + insert");
        }

        let reopened = open_test_db(&path);
        let value: i64 = reopened
            .read::<i64, DatabaseError>(|conn| {
                Ok(conn.query_row("SELECT id FROM t", [], |row| row.get(0))?)
            })
            .expect("read back after reopen");
        assert_eq!(value, 42);
    }

    /// Opening the same database twice in a row (schema already present)
    /// must not fail -- `init_schema`'s own `CREATE TABLE IF NOT EXISTS`
    /// migrations must be idempotent, not just safe to run once.
    #[test]
    fn schema_initialization_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("idempotent-init.sqlite3");
        let _first = open_test_db(&path);
        let _second = open_test_db(&path);
    }
}
