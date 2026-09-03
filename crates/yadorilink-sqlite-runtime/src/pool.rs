//! Connection pool construction, the madsim-only inline-pool stand-in, and
//! the bounded SQLITE_BUSY/SQLITE_LOCKED retry helper. Pure, stateless
//! machinery -- no `SyncDatabase` fields live here; `SyncDatabase` owns its
//! own `pool`/`writer_gate` and calls back into this module. Moved
//! verbatim out of `yadorilink-sync-core` (Phase 7D-4.2) -- no pool size,
//! timeout, locking order, retry behavior, or PRAGMA changed.

use std::time::Duration;

#[cfg(not(madsim))]
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::error::SqlOperationError;

/// every connection made by the pool waits at
/// most this long for the SQLite write lock (`PRAGMA busy_timeout`)
/// before giving up with `SQLITE_BUSY`, instead of erroring immediately.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The connection "pool" backing a [`crate::SyncDatabase`].
///
/// A normal build uses r2d2's real `Pool`. Under deterministic simulation
/// (`--cfg madsim`) it uses [`madsim_inline_pool::InlinePool`] instead --
/// see that module's own doc comment for why.
#[cfg(madsim)]
pub type ConnectionPool = madsim_inline_pool::InlinePool;
#[cfg(not(madsim))]
pub type ConnectionPool = Pool<SqliteConnectionManager>;

/// Checks out a connection from `pool`, converting whichever concrete
/// error type the real `r2d2::Pool` or the madsim inline pool produces
/// into the caller's own error type `E`.
pub(crate) fn checkout<E: SqlOperationError>(pool: &ConnectionPool) -> Result<PooledConnection, E> {
    pool.get().map(PooledConnection).map_err(E::from)
}

#[cfg(not(madsim))]
pub(crate) struct PooledConnection(r2d2::PooledConnection<SqliteConnectionManager>);
#[cfg(madsim)]
pub(crate) struct PooledConnection(madsim_inline_pool::InlineConnection);

impl std::ops::Deref for PooledConnection {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        &self.0
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut rusqlite::Connection {
        &mut self.0
    }
}

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
pub mod madsim_inline_pool {
    use std::ops::{Deref, DerefMut};

    use r2d2::ManageConnection;
    use r2d2_sqlite::SqliteConnectionManager;
    use rusqlite::Connection;

    use crate::error::DatabaseError;

    pub struct InlinePool {
        manager: SqliteConnectionManager,
    }

    impl InlinePool {
        pub(super) fn new(manager: SqliteConnectionManager) -> Result<Self, DatabaseError> {
            // Establish one connection up front so a bad path/URI surfaces
            // at open() time (matching r2d2's build-time establishment) and
            // so a shared-cache in-memory database's internal keep-alive
            // connection is primed before the first checkout.
            let _ = manager.connect()?;
            Ok(Self { manager })
        }

        pub(crate) fn get(&self) -> Result<InlineConnection, rusqlite::Error> {
            Ok(InlineConnection(self.manager.connect()?))
        }
    }

    /// Owns its `Connection` (unlike r2d2's `PooledConnection`, which
    /// returns the connection to the pool on drop) but `Deref`s to it
    /// identically, so every checkout call site compiles unchanged.
    pub struct InlineConnection(Connection);

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

/// Builds the connection pool for a `SyncDatabase`. Production uses r2d2's
/// real pool; under `--cfg madsim` it uses the thread-free inline pool (see
/// [`ConnectionPool`]).
#[cfg(madsim)]
pub(crate) fn madsim_or_default_pool(
    manager: SqliteConnectionManager,
) -> Result<ConnectionPool, crate::error::DatabaseError> {
    madsim_inline_pool::InlinePool::new(manager)
}

#[cfg(not(madsim))]
pub(crate) fn madsim_or_default_pool(
    manager: SqliteConnectionManager,
) -> Result<ConnectionPool, crate::error::DatabaseError> {
    // `Pool::new` (a bare `Pool::builder().build(..)`) defaults `min_idle`
    // to `None`, which r2d2 documents as "maintain as many idle connections
    // as `max_size`" -- i.e. it eagerly establishes connections up to the
    // pool's max size at build time, on background threads, all racing
    // each other against the same file. `SyncDatabase::open`'s own
    // bootstrap connection (see its doc comment) has already put the file
    // into WAL mode before this pool is ever built, so none of these
    // connections' own per-connection init needs to perform a mode switch
    // any more -- but capping the eager fill to 1 still cuts the number of
    // connections concurrently opening the same file at startup, for
    // exactly the same reason `open`'s bootstrap step exists: fewer
    // concurrent openers is strictly safer than more, even once the
    // specific WAL-switch race is closed.
    Ok(Pool::builder().min_idle(Some(1)).build(manager)?)
}

/// The other half of the `SQLITE_LOCKED` fix (see
/// [`crate::database::new_immediate_write_transaction`]'s doc comment for
/// the first half and the full diagnostic story). SQLite's own
/// documentation is explicit that `SQLITE_LOCKED` arising from shared-cache
/// table locking (as opposed to schema corruption or a genuinely permanent
/// conflict) is meant to be handled by the *caller* retrying the whole
/// failed transaction after a short wait. Wraps `op` (expected to be a
/// self-contained "check out a connection, open a transaction, do the
/// work, commit" closure -- safe to call more than once, since a failed
/// transaction rolls back and leaves no partial state to retry against)
/// and retries it on `SQLITE_LOCKED`/`SQLITE_BUSY` specifically (via
/// `E::is_locked`), up to a small bounded number of attempts with a short
/// linear backoff. Every other error (any genuine data error) propagates
/// immediately, unretried.
///
/// The backoff blocks the calling thread (`std::thread::sleep`), for up to
/// 225ms across a fully contended call, and this is deliberate on both
/// counts:
///
/// * Blocking, because every entry point into this crate
///   (`SyncDatabase::read`/`write`/`write_immediate`) is synchronous, as
///   are the ~200 repository call sites that reach them. There is no
///   runtime here to yield to -- this crate has no dependency on tokio or
///   any other async runtime, by design, since it is shared by callers
///   that are not async at all.
/// * 225ms, because that worst case only materializes when the lock
///   genuinely stayed held for that long, in which case the alternative to
///   waiting is failing. This window has already been widened once in
///   response to a reproduced convergence gap where real concurrent load
///   pushed `SQLITE_BUSY` straight past it; shortening it trades a bounded
///   wait for an unbounded correctness risk.
///
/// What follows for callers: an async caller must not reach `read`/
/// `write`/`write_immediate` inline on a runtime worker. A worker blocked
/// here is not parked -- it runs no other task at all for the duration,
/// which surfaces as time-to-schedule for everything else sharing that
/// runtime, up to and including this device's own QUIC endpoint driver
/// missing the window to send an ack promptly, provoking the peer's own
/// loss detection into retransmitting a datagram that was never lost.
/// Async callers must wrap these calls in
/// `block_in_place` or `spawn_blocking`, on their own side, where the
/// runtime is actually visible.
pub(crate) fn retry_on_database_locked<T, E: SqlOperationError>(
    mut op: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    const MAX_ATTEMPTS: u32 = 10;
    let mut attempt: u32 = 0;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(e) if attempt + 1 < MAX_ATTEMPTS && e.is_locked() => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(5 * attempt as u64));
            }
            Err(e) => return Err(e),
        }
    }
}
