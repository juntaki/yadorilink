#![cfg(test)]
//! The metadata step of a window run on its own: when it flushes, what one
//! item's failure does to the others, and what it never applies.
//!
//! The real batch transaction runs against a real database; only the files'
//! tasks (and the path locks they hold) are stood in for by the test.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;
use yadorilink_root_authority::root_commit::{OwnedPermitCheck, RootCommitPermit, RootLease};
use yadorilink_root_authority::sync_root_lock::SyncRootLock;

use super::completion_window::CompletionWindow;
use crate::replica_coordinator::{MetadataApplyItem, ReplicaCoordinator};

const GROUP: &str = "metadata-window-group";

fn columns(mode: u32) -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: Some(mode),
        xattrs: Vec::new(),
    }
}

fn item(path: &str, mode: u32, root_check: OwnedPermitCheck) -> MetadataApplyItem {
    MetadataApplyItem {
        group_id: GROUP.to_owned(),
        path: path.to_owned(),
        columns: columns(mode),
        root_check,
    }
}

fn valid_check() -> OwnedPermitCheck {
    RootCommitPermit::for_tests().owned_check()
}

/// `(unix_mode, version_seq)` of the path's current row, if it has one.
fn row(state: &ReplicaCoordinator, path: &str) -> Option<(i64, i64)> {
    state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            use rusqlite::OptionalExtension;
            Ok(conn
                .query_row(
                    "SELECT unix_mode, version_seq FROM files \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![GROUP, path],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?)
        })
        .unwrap()
}

fn batch_sizes(state: &ReplicaCoordinator) -> Vec<usize> {
    state.test_observers.metadata_batch_sizes.lock().unwrap().clone()
}

#[tokio::test]
async fn a_lone_file_applies_at_once_however_long_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let a = window.join();

    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(3),
        a.submit_metadata(&state, item("a.txt", 0o755, valid_check())),
    )
    .await
    .expect("a lone file must not wait for a batch to fill")
    .unwrap();

    assert!(started.elapsed() < Duration::from_secs(3));
    // The scaffold row (no row existed) carries the columns.
    assert_eq!(row(&state, "a.txt"), Some((0o755, 0)));
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn files_that_queue_together_apply_in_one_transaction() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let participants: Vec<_> = (0..4).map(|_| window.join()).collect();

    let outcomes = tokio::time::timeout(
        Duration::from_secs(3),
        futures_util::future::join_all(participants.iter().enumerate().map(|(i, participant)| {
            let state = &state;
            async move {
                participant
                    .submit_metadata(
                        state,
                        item(&format!("f{i}.txt"), 0o600 + i as u32, valid_check()),
                    )
                    .await
            }
        })),
    )
    .await
    .unwrap();

    assert!(outcomes.iter().all(Result::is_ok));
    for i in 0..4 {
        assert_eq!(row(&state, &format!("f{i}.txt")), Some((0o600 + i as i64, 0)));
    }
    assert_eq!(batch_sizes(&state), vec![4], "four files, one transaction");
}

#[tokio::test]
async fn a_queue_waits_for_a_sibling_that_has_not_reached_the_step_until_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_millis(150));
    let a = window.join();
    let _straggler = window.join();

    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(5),
        a.submit_metadata(&state, item("a.txt", 0o644, valid_check())),
    )
    .await
    .expect("the deadline must flush the queue")
    .unwrap();

    assert!(
        started.elapsed() >= Duration::from_millis(120),
        "applied before the deadline although a sibling could still arrive: {:?}",
        started.elapsed()
    );
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn a_full_queue_applies_without_waiting_for_the_deadline() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (a, b, _straggler) = (window.join(), window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o600, valid_check())),
            b.submit_metadata(&state, item("b.txt", 0o600, valid_check()))
        )
    })
    .await
    .expect("a queue as long as the window's limit must flush");

    assert!(ra.is_ok() && rb.is_ok());
    assert_eq!(batch_sizes(&state), vec![2]);
}

/// A sibling that finishes without ever reaching the step (a directory, a
/// declined path, a failure) must not hold the queue until the deadline.
#[tokio::test]
async fn a_sibling_that_leaves_without_queueing_releases_the_queue() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let a = window.join();
    let sibling = window.join();

    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(a.submit_metadata(&state, item("a.txt", 0o600, valid_check())), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(sibling);
        })
    })
    .await
    .expect("the sibling leaving must let the queue flush");

    outcome.unwrap();
}

/// A sibling already past the step (it applied its metadata and is writing)
/// is not waited for either.
#[tokio::test]
async fn a_sibling_past_the_step_does_not_hold_the_queue() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());
    // b is alone at the step first: a has not arrived, so b waits for it.
    let (rb, ra) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(b.submit_metadata(&state, item("b.txt", 0o600, valid_check())), async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            a.submit_metadata(&state, item("a.txt", 0o600, valid_check())).await
        })
    })
    .await
    .unwrap();
    rb.unwrap();
    ra.unwrap();
    assert_eq!(batch_sizes(&state), vec![2]);

    // b is now past the step and still a participant (it is writing its
    // content); a later file at the step is alone in the queue and flushes.
    let c = window.join();
    tokio::time::timeout(
        Duration::from_secs(3),
        c.submit_metadata(&state, item("c.txt", 0o600, valid_check())),
    )
    .await
    .expect("files past the step must not hold a later file")
    .unwrap();
    assert_eq!(batch_sizes(&state), vec![2, 1]);
    drop((a, b));
}

/// A refused or failing item is that item's outcome only; its own partial
/// writes are rolled back and the others commit.
#[tokio::test]
async fn an_item_that_fails_leaves_the_others_applied_and_itself_unwritten() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    // Fails the column update of one path, after its scaffold row was inserted.
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER poison_one BEFORE UPDATE ON files WHEN NEW.path = 'bad.txt' \
                 BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let window = CompletionWindow::new(3, Duration::from_secs(10));
    let (a, b, c) = (window.join(), window.join(), window.join());

    let (ra, rb, rc) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o700, valid_check())),
            b.submit_metadata(&state, item("bad.txt", 0o700, valid_check())),
            c.submit_metadata(&state, item("c.txt", 0o700, valid_check()))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_ok() && rc.is_ok());
    assert!(rb.is_err(), "the poisoned item is its own failure");
    assert_eq!(row(&state, "a.txt"), Some((0o700, 0)));
    assert_eq!(row(&state, "c.txt"), Some((0o700, 0)));
    assert_eq!(
        row(&state, "bad.txt"),
        None,
        "the failed item's scaffold row survived its savepoint's rollback"
    );
    assert_eq!(batch_sizes(&state), vec![3]);
}

struct ClaimedRoot {
    lease: Arc<RootLease>,
    dir: tempfile::TempDir,
}

fn claimed_root(state: &ReplicaCoordinator) -> ClaimedRoot {
    let dir = tempfile::tempdir().unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(dir.path(), GROUP, state).unwrap();
    let lock = SyncRootLock::acquire(dir.path()).unwrap();
    ClaimedRoot { lease: Arc::new(RootLease::new(lock, GROUP.to_owned(), 0)), dir }
}

/// Each item is checked against its own root permit inside the batch
/// transaction; a root that is no longer this link's fails the whole
/// transaction, even for an item whose own check came first and passed.
#[tokio::test]
async fn a_root_lost_between_two_items_checks_fails_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = claimed_root(&state);
    let operation = root.lease.begin_operation().unwrap();
    let doomed = operation.permit().owned_check();
    let lock_path =
        root.dir.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o600, valid_check())),
            b.submit_metadata(&state, item("b.txt", 0o600, doomed))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err(), "every waiter gets the error");
    assert_eq!(row(&state, "a.txt"), None, "applied for a root that is no longer owned");
    assert_eq!(row(&state, "b.txt"), None);
}

/// A waiter that is gone has released its path lock with the rest of its
/// guards: applying its item would write under a lock nobody holds.
#[tokio::test]
async fn an_item_whose_waiter_was_dropped_is_not_applied_by_a_survivor() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());
    let dropped = tokio::time::timeout(
        Duration::from_millis(60),
        a.submit_metadata(&state, item("a.txt", 0o700, valid_check())),
    )
    .await;
    assert!(dropped.is_err(), "a is still waiting for b when it is dropped");
    drop(a);
    assert!(batch_sizes(&state).is_empty());

    tokio::time::timeout(
        Duration::from_secs(3),
        b.submit_metadata(&state, item("b.txt", 0o700, valid_check())),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row(&state, "b.txt"), Some((0o700, 0)));
    assert_eq!(row(&state, "a.txt"), None, "the dropped waiter's item was applied");
    assert_eq!(batch_sizes(&state), vec![1]);
}

#[tokio::test]
async fn items_queued_when_the_window_is_dropped_stay_unapplied() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let (a, b, _straggler) = (window.join(), window.join(), window.join());

    let both = tokio::time::timeout(Duration::from_millis(80), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o700, valid_check())),
            b.submit_metadata(&state, item("b.txt", 0o700, valid_check()))
        )
    })
    .await;
    assert!(both.is_err(), "the straggler keeps the queue waiting");

    assert_eq!((row(&state, "a.txt"), row(&state, "b.txt")), (None, None));
    assert!(batch_sizes(&state).is_empty());
}

/// The transaction fails after every item was written and before it commits,
/// as a crash in its middle would: all of it goes and every file gets an error.
#[tokio::test]
async fn a_transaction_that_fails_before_it_commits_leaves_every_item_unwritten() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    state.test_observers.metadata_batch_fails_before_commit.store(true, Ordering::SeqCst);
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o600, valid_check())),
            b.submit_metadata(&state, item("b.txt", 0o600, valid_check()))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err());
    assert_eq!((row(&state, "a.txt"), row(&state, "b.txt")), (None, None));
}

/// A path that already has a row keeps its row (no scaffold, no second
/// version); only the metadata columns move.
#[tokio::test]
async fn a_path_with_a_row_gets_only_its_columns_changed() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let record = yadorilink_replica_domain::file::FileRecord {
        path: "x.txt".into(),
        size: 5,
        mtime_unix_nanos: 1,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: vec![7; 32],
            offset: 0,
            size: 5,
        }],
        deleted: false,
    };
    state
        .upsert_file_with_origin(GROUP, &record, "device-peer", &RootCommitPermit::for_tests())
        .unwrap();
    let before = row(&state, "x.txt").unwrap();
    assert!(before.1 >= 1);
    let window = CompletionWindow::new(8, Duration::from_secs(10));
    let a = window.join();

    a.submit_metadata(&state, item("x.txt", 0o751, valid_check())).await.unwrap();

    assert_eq!(row(&state, "x.txt"), Some((0o751, before.1)));
    let rows: i64 = state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND path = 'x.txt'",
                [GROUP],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(rows, 1);
}

/// The root check runs for an item whose own statements fail too: item A
/// passes its check, the root is then replaced, and item B's statement fails.
/// B's failed statements must not hide the lost root: the whole batch fails
/// and A does not commit.
#[tokio::test]
async fn a_root_lost_under_an_item_whose_statements_fail_still_fails_the_whole_batch() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = claimed_root(&state);
    let operation = root.lease.begin_operation().unwrap();
    let doomed = operation.permit().owned_check();
    let lock_path =
        root.dir.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER poison_b BEFORE UPDATE ON files WHEN NEW.path = 'b.txt' \
                 BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let window = CompletionWindow::new(2, Duration::from_secs(10));
    let (a, b) = (window.join(), window.join());

    let (ra, rb) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(
            a.submit_metadata(&state, item("a.txt", 0o600, valid_check())),
            b.submit_metadata(&state, item("b.txt", 0o600, doomed))
        )
    })
    .await
    .unwrap();

    assert!(ra.is_err() && rb.is_err(), "every waiter gets the error");
    assert_eq!(row(&state, "a.txt"), None, "A committed although the root was lost");
}
