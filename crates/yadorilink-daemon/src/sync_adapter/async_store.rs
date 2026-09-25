//! The async/blocking boundary in front of the replica store.
//!
//! ```text
//!   iroh / SyncRuntime / AdmissionCoordinator
//!                 │  await
//!                 ▼
//!         AsyncReplicaStore
//!         ├─ read permits: bounded
//!         └─ write permits: bounded, and one by default
//!                 │  spawn_blocking
//!                 ▼
//!            SyncDatabase  (rusqlite, writer gate)
//! ```
//!
//! # Why a permit, and why before the spawn
//!
//! Moving a synchronous SQLite call onto a blocking thread stops it from
//! occupying a Tokio worker. It does not stop a thousand of them from being
//! started. A `plan_retroactive_merge` writer-gate hold has been measured at
//! up to ~74 seconds; with the gate held that long, a
//! burst of promotions would spawn a blocking task each, and every one of them
//! would park on the writer gate. Tokio worker starvation would be gone and
//! blocking-pool exhaustion would have replaced it — the same stall wearing a
//! different hat.
//!
//! So the permit is acquired *asynchronously, before* `spawn_blocking`. A
//! caller that cannot proceed waits in the async world, where waiting is free,
//! rather than occupying a thread to wait. The number of threads this store can
//! ever hold is its permit count, whatever the offered load.
//!
//! Writes default to a single permit. SQLite admits one writer at a time
//! regardless; extra permits would only convert queueing into parked threads.
//!
//! # Cancellation
//!
//! Once a blocking operation has started it runs to completion. A cancelled
//! async caller loses the *result*, never the operation: the transaction
//! either commits in full or rolls back in full, and nothing observes a
//! half-applied state. Retrying is safe because every operation here is
//! addressed by content — staging a bundle already held does nothing, and
//! promoting a Change already canonical reports exactly that.
//!
//! # What this boundary is for
//!
//! Above it, no SQLite concept exists. There is no `rusqlite::Connection`, no
//! `write_immediate`, no writer gate and no connection pool — only operations
//! named for what they mean. The pool's own guidance today is that "async
//! callers must wrap these calls in `block_in_place` or `spawn_blocking`, on
//! their own side", which is a contract spread across every call site; this
//! store is that contract in one place instead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;
use yadorilink_replica_domain::base_negotiation::BaseAdvertisement;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::base_advertisement;
use yadorilink_sync_sqlite::remote_admission::{self, AdmissionOutcome, AdmissionPlan};
use yadorilink_sync_sqlite::verified_change_store::{self, VerifiedChangeBundle};
use yadorilink_sync_sqlite::SyncSqliteError;

/// How many blocking threads this store may hold at once.
#[derive(Clone, Copy, Debug)]
pub struct StoreLimits {
    /// Concurrent reads. SQLite in WAL mode admits readers alongside a writer,
    /// so this is about bounding threads rather than serialising access.
    pub reads: usize,
    /// Concurrent writes. One by default: SQLite admits a single writer
    /// whatever this says, and a larger number turns queueing into parked
    /// threads without admitting any more work.
    pub writes: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self { reads: 8, writes: 1 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Storage(#[from] SyncSqliteError),

    /// The blocking task ended without producing a result — it panicked, or
    /// the runtime is shutting down.
    #[error("storage operation did not complete: {0}")]
    Incomplete(String),

    /// The store is shutting down and will accept no further work.
    #[error("storage is shutting down")]
    ShuttingDown,
}

/// What the store is currently doing. Exposed because the failure this store
/// exists to prevent — every permit held by a thread parked on the writer gate
/// — is otherwise invisible: the pre-existing inline-blocking fallback in this
/// tree has neither a counter nor a log, so a runtime stalled for seconds
/// looks exactly like a runtime that is merely quiet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreMetrics {
    /// Blocking operations running right now.
    pub in_flight: usize,
    /// The most that have ever run at once.
    pub peak_in_flight: usize,
}

/// Domain-named, async access to the replica store.
#[derive(Clone)]
pub struct AsyncReplicaStore {
    db: Arc<SyncDatabase>,
    reads: Arc<Semaphore>,
    writes: Arc<Semaphore>,
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
}

impl std::fmt::Debug for AsyncReplicaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncReplicaStore").field("metrics", &self.metrics()).finish()
    }
}

impl AsyncReplicaStore {
    pub fn new(db: Arc<SyncDatabase>, limits: StoreLimits) -> Self {
        Self {
            db,
            reads: Arc::new(Semaphore::new(limits.reads.max(1))),
            writes: Arc::new(Semaphore::new(limits.writes.max(1))),
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn metrics(&self) -> StoreMetrics {
        StoreMetrics {
            in_flight: self.in_flight.load(Ordering::Relaxed),
            peak_in_flight: self.peak_in_flight.load(Ordering::Relaxed),
        }
    }

    // --- reads -------------------------------------------------------------

    /// Every hash this node can serve for `group`.
    pub async fn servable_hashes(
        &self,
        group: FolderGroupId,
    ) -> Result<Vec<ChangeHash>, StoreError> {
        self.read(move |db| {
            db.read(|conn| verified_change_store::servable_change_hashes(conn, &group))
        })
        .await
    }

    /// What this device advertises about its history for `group`: its
    /// base, the checkpoint and summary identity behind it, and its active
    /// heads, all read from one snapshot.
    pub async fn base_advertisement(
        &self,
        group: FolderGroupId,
    ) -> Result<BaseAdvertisement, StoreError> {
        self.read(move |db| {
            db.read_snapshot(|conn| base_advertisement::local_base_advertisement(conn, &group.0))
        })
        .await
    }

    /// One servable bundle, from either side of the promotion boundary.
    pub async fn load_servable_bundle(
        &self,
        hash: ChangeHash,
    ) -> Result<Option<VerifiedChangeBundle>, StoreError> {
        self.read(move |db| db.read(|conn| verified_change_store::load_servable(conn, &hash))).await
    }

    /// Staged Changes of `group` whose parents are all canonical.
    pub async fn admissible_candidates(
        &self,
        group: FolderGroupId,
        limit: usize,
    ) -> Result<Vec<ChangeHash>, StoreError> {
        self.read(move |db| {
            db.read(|conn| verified_change_store::admissible_now(conn, &group, limit))
        })
        .await
    }

    /// Work out a promotion with no writer transaction held.
    pub async fn plan_admission(
        &self,
        hash: ChangeHash,
    ) -> Result<Option<AdmissionPlan>, StoreError> {
        self.read(move |db| db.read(|conn| remote_admission::plan_admission(conn, &hash))).await
    }

    // --- writes ------------------------------------------------------------

    /// Durably stage a whole verified delivery, or none of it.
    pub async fn stage_verified_batch(
        &self,
        batch: Vec<VerifiedChangeBundle>,
        now_unix_nanos: i64,
    ) -> Result<Vec<ChangeHash>, StoreError> {
        // `write_immediate`, not `write`: "or none of it" above is the whole
        // contract, and `write` hands back a connection in autocommit where
        // each row lands on its own. A staged object row is what makes a
        // hash servable, so committing it before its version rows publishes
        // a hash this device cannot actually promote -- and the peer, seeing
        // it as possessed, never sends it again.
        self.write(move |db| {
            db.write_immediate(|tx| {
                verified_change_store::stage_verified_bundles(tx, &batch, now_unix_nanos)
            })
        })
        .await
    }

    /// Revalidate a plan and promote, in one short transaction.
    pub async fn commit_admission(
        &self,
        plan: AdmissionPlan,
    ) -> Result<AdmissionOutcome, StoreError> {
        // `write_immediate`, not `write`: a promotion is ten-odd write
        // statements that must land together. `write` hands back a pooled
        // connection in autocommit, where each of those statements commits
        // (and, under `synchronous = FULL`, fsyncs) on its own.
        self.write(move |db| db.write_immediate(|tx| remote_admission::commit_admission(tx, &plan)))
            .await
    }

    // --- the boundary itself -----------------------------------------------

    async fn read<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&SyncDatabase) -> Result<T, SyncSqliteError> + Send + 'static,
    {
        self.run(self.reads.clone(), op).await
    }

    async fn write<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&SyncDatabase) -> Result<T, SyncSqliteError> + Send + 'static,
    {
        self.run(self.writes.clone(), op).await
    }

    async fn run<T, F>(&self, permits: Arc<Semaphore>, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&SyncDatabase) -> Result<T, SyncSqliteError> + Send + 'static,
    {
        // Acquired here, in the async world, so a caller that cannot proceed
        // waits without occupying a thread. Acquiring inside the blocking task
        // would put the wait on a thread, which is the exhaustion this exists
        // to prevent.
        let permit = permits.acquire_owned().await.map_err(|_| StoreError::ShuttingDown)?;

        let db = self.db.clone();
        let in_flight = self.in_flight.clone();
        let peak = self.peak_in_flight.clone();

        let handle = tokio::task::spawn_blocking(move || {
            // Held for the whole blocking call, released when it ends —
            // including on panic, since the permit is dropped with the closure.
            let _permit = permit;

            let now = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
            peak.fetch_max(now, Ordering::Relaxed);
            let result = op(&db);
            in_flight.fetch_sub(1, Ordering::Relaxed);
            result
        });

        // Dropping this handle does not cancel the blocking task. A cancelled
        // caller therefore loses the result and never the operation: the
        // transaction still commits in full or rolls back in full.
        handle.await.map_err(|error| StoreError::Incomplete(error.to_string()))?.map_err(Into::into)
    }
}
