//! Acceptance gates for the async/blocking boundary.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sqlite_runtime::SyncDatabase;

use super::async_store::{AsyncReplicaStore, StoreLimits};

fn db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            yadorilink_sync_sqlite::dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)?;
            yadorilink_sync_sqlite::verified_change_store::init_verified_change_schema(conn)
                .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    )
}

fn group() -> FolderGroupId {
    FolderGroupId("g".into())
}

/// Occupy the writer for as long as the returned sender is not fired.
///
/// This models a measured worst case: a writer-gate hold of up to ~74
/// seconds, with everything else arriving meanwhile.
struct WriterLatch {
    release: Arc<AtomicUsize>,
    holder: Option<std::thread::JoinHandle<()>>,
}

impl WriterLatch {
    fn release(mut self) {
        self.release.store(1, Ordering::SeqCst);
        if let Some(holder) = self.holder.take() {
            holder.join().unwrap();
        }
    }
}

fn latch_the_writer(db: Arc<SyncDatabase>) -> WriterLatch {
    let release = Arc::new(AtomicUsize::new(0));
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();

    let holder = {
        let release = release.clone();
        std::thread::spawn(move || {
            let mut announced = false;
            let _ = db.write(|conn| {
                conn.execute_batch("CREATE TABLE IF NOT EXISTS writer_latch (x INTEGER)")?;
                if !announced {
                    let _ = held_tx.send(());
                    announced = true;
                }
                // Hold the gate until released. This is a dedicated std
                // thread, never a runtime worker, so blocking here is exactly
                // what is intended.
                while release.load(Ordering::SeqCst) == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
            });
        })
    };

    held_rx.recv().expect("writer latch engaged");
    WriterLatch { release, holder: Some(holder) }
}

/// Gate 1: the runtime stays live while the writer is held.
///
/// This is the failure the boundary exists to remove. A synchronous SQLite
/// call made from a session task occupies a runtime worker for its whole
/// duration; with the writer held for tens of seconds, that worker runs no
/// other task at all — up to and including this device's own QUIC endpoint
/// driver, which then misses the window to ack promptly and provokes the
/// peer's loss detection into retransmitting a datagram that was never lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_keeps_running_while_a_write_waits_on_a_held_writer() {
    let db = db();
    let store = AsyncReplicaStore::new(db.clone(), StoreLimits::default());
    let latch = latch_the_writer(db.clone());

    // A write that cannot proceed until the latch is released.
    let blocked = {
        let store = store.clone();
        tokio::spawn(async move { store.stage_verified_batch(Vec::new(), 1).await })
    };

    // Meanwhile the runtime must keep scheduling ordinary work. Two worker
    // threads and a held writer: if the blocked write were occupying a worker
    // inline, this loop would stall.
    let ticks = Arc::new(AtomicUsize::new(0));
    let ticker = {
        let ticks = ticks.clone();
        tokio::spawn(async move {
            for _ in 0..50 {
                ticks.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };

    ticker.await.unwrap();
    assert_eq!(
        ticks.load(Ordering::SeqCst),
        50,
        "the runtime must keep scheduling while a write waits on the writer gate"
    );

    latch.release();
    let _ = blocked.await.unwrap();
}

/// Gate 2: a burst cannot hold more blocking threads than the permit count.
///
/// Wrapping each call in `spawn_blocking` stops a synchronous SQLite call from
/// occupying a runtime worker. It does not stop a thousand of them from being
/// started, each parking on the writer gate — Tokio worker starvation traded
/// for blocking-pool exhaustion. The permit is acquired in the async world,
/// before the spawn, so waiting costs no thread at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_against_a_held_writer_never_exceeds_the_permit_count() {
    const BURST: usize = 200;
    let limits = StoreLimits { reads: 4, writes: 1 };

    let db = db();
    let store = AsyncReplicaStore::new(db.clone(), limits);
    let latch = latch_the_writer(db.clone());

    let mut submitted = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let store = store.clone();
        submitted.push(tokio::spawn(async move {
            let _ = store.stage_verified_batch(Vec::new(), 1).await;
        }));
    }

    // Let every one of them reach the boundary and queue there.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peak = store.metrics().peak_in_flight;
    assert!(
        peak <= limits.reads + limits.writes,
        "{BURST} queued writes held {peak} blocking threads; the limit is {}",
        limits.reads + limits.writes
    );
    assert!(peak >= 1, "the burst must actually have reached the boundary");

    latch.release();
    for task in submitted {
        task.await.unwrap();
    }
}

/// Control for the gate above: the permit is what bounds it.
///
/// With the write permit raised to the size of the burst, the same load holds
/// far more blocking threads at once. If it did not, the bound in the previous
/// test would be a property of the load rather than of the boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_tight_permit_the_same_burst_holds_many_more_threads() {
    const BURST: usize = 64;

    let db = db();
    let store = AsyncReplicaStore::new(db.clone(), StoreLimits { reads: 4, writes: BURST });
    let latch = latch_the_writer(db.clone());

    let mut submitted = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        let store = store.clone();
        submitted.push(tokio::spawn(async move {
            let _ = store.stage_verified_batch(Vec::new(), 1).await;
        }));
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let peak = store.metrics().peak_in_flight;
    assert!(
        peak > 4,
        "with the permit raised, the burst should hold many threads at once; \
         peak was {peak}, so the earlier bound may not be the permit's doing"
    );

    latch.release();
    for task in submitted {
        task.await.unwrap();
    }
}

/// Gate 3: cancelling the waiter loses the result, never the operation.
///
/// Once a blocking operation has started it runs to completion, so the
/// database is left in the state before it or the state after it — never
/// half-applied. Retrying is safe because every operation here is addressed by
/// content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_waiter_leaves_the_database_atomically_before_or_after() {
    let db = db();
    let store = AsyncReplicaStore::new(db.clone(), StoreLimits::default());

    let before = store.servable_hashes(group()).await.unwrap();

    let cancelled = {
        let store = store.clone();
        tokio::spawn(async move { store.stage_verified_batch(Vec::new(), 1).await })
    };
    cancelled.abort();
    let _ = cancelled.await;

    // Whatever happened to the caller, the store is consistent and usable.
    let after = store.servable_hashes(group()).await.unwrap();
    assert_eq!(before, after, "an empty batch changes nothing either way");

    // And the boundary is not left holding a permit: further work proceeds.
    for _ in 0..8 {
        store.servable_hashes(group()).await.unwrap();
    }
    assert_eq!(
        store.metrics().in_flight,
        0,
        "every permit must be released even when its waiter was cancelled"
    );
}

/// Gate 5, as a test rather than a grep: nothing above the boundary can name a
/// SQLite type, because the store's surface does not mention one.
///
/// The pool's own guidance is that "async callers must wrap these calls in
/// `block_in_place` or `spawn_blocking`, on their own side" — a contract
/// spread across every call site, which is what this boundary replaces.
#[tokio::test]
async fn the_store_surface_names_no_sqlite_concept() {
    let store = AsyncReplicaStore::new(db(), StoreLimits::default());

    // Every operation is named for what it means. A caller cannot obtain a
    // connection, a transaction or the writer gate through any of them.
    let _: Vec<yadorilink_replica_domain::ids::ChangeHash> =
        store.servable_hashes(group()).await.unwrap();
    let _: Vec<yadorilink_replica_domain::ids::ChangeHash> =
        store.admissible_candidates(group(), 8).await.unwrap();
}
