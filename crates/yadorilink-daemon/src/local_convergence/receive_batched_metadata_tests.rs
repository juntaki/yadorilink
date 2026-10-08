#![cfg(test)]
//! The metadata step of the files of a concurrent run is applied in batches,
//! and everything the per-file step guaranteed still holds: the apply happens
//! only while the file holds its path lock, a file whose step fails keeps
//! today's state and retry without disturbing the others, and a run that is
//! dropped with files queued applies nothing for them.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::ids::VersionHash;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    names, pin_concurrency, publish, publish_new_files, put, reconcile, run_workload_with, source,
};

const BATCH: u8 = 1;
const PER_FILE: u8 = 2;

fn use_metadata(h: &Harness, mode: u8, max_latency_ms: u64) {
    h.convergence.batch_metadata_override.store(mode, Ordering::Relaxed);
    h.convergence.completion_max_latency_override_ms.store(max_latency_ms, Ordering::Relaxed);
}

fn metadata_batches(h: &Harness) -> Vec<usize> {
    h.state.test_observers.metadata_batch_sizes.lock().unwrap().clone()
}

/// `(unix_mode, version_seq)` of the path's current row, if it has one.
fn row(h: &Harness, path: &str) -> Option<(i64, i64)> {
    h.state
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

fn closed(h: &Harness, path: &str) -> bool {
    h.state.get_materialization_state(GROUP, path).unwrap()
        == Some(yadorilink_replica_domain::session_state::MaterializationState::Present)
        && !h.state.has_materialization_intent(GROUP, path).unwrap()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let waited = std::time::Instant::now();
    while !done() {
        assert!(waited.elapsed() < Duration::from_secs(30), "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn spawn_reconcile(
    h: &Harness,
    files: &[String],
) -> tokio::task::JoinHandle<Option<super::ProjectionAttempt>> {
    let (convergence, files) = (h.convergence.clone(), files.to_vec());
    tokio::spawn(async move {
        convergence
            .reconcile_paths_directly(
                &super::receive_window_concurrency_tests::driver(),
                GROUP,
                files.into_iter().collect(),
            )
            .await
            .unwrap()
    })
}

/// Parks the committing task just before a batched metadata transaction, with
/// every file of the batch queued (each holding its path lock) and nothing of
/// the batch written.
struct Gate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn arm(h: &Harness) -> Arc<Self> {
        let gate = Arc::new(Self { state: Mutex::new((false, false)), changed: Condvar::new() });
        let at_gate = gate.clone();
        *h.state.test_observers.metadata_batch_gate.lock().unwrap() = Some(Arc::new(move || {
            let mut state = at_gate.state.lock().unwrap();
            state.0 = true;
            at_gate.changed.notify_all();
            while !state.1 {
                let (next, timeout) =
                    at_gate.changed.wait_timeout(state, Duration::from_secs(30)).unwrap();
                state = next;
                assert!(!timeout.timed_out(), "the gate was never opened");
            }
        }));
        gate
    }

    fn reached(&self) -> bool {
        self.state.lock().unwrap().0
    }

    fn open(&self) {
        self.state.lock().unwrap().1 = true;
        self.changed.notify_all();
    }
}

/// Eight files of one run apply their metadata in one transaction; with the
/// knob off each applies by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_files_of_a_run_apply_their_metadata_in_one_transaction() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_metadata(&h, BATCH, 10_000);
    let files = names("b", 8);
    let contents = publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
        assert!(closed(&h, name), "{name}");
    }
    assert_eq!(metadata_batches(&h), vec![8], "eight files, one metadata transaction");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_knob_off_every_file_applies_by_itself() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_metadata(&h, PER_FILE, 10_000);
    let files = names("p", 4);
    publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    assert!(files.iter().all(|name| attempt.is_settled(name) && closed(&h, name)));
    assert!(metadata_batches(&h).is_empty(), "no batched transaction ran");
}

/// A lone file never waits for a batch to fill, however long the deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lone_file_in_a_run_applies_without_waiting() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_metadata(&h, BATCH, 20_000);
    let files = names("l", 1);
    publish_new_files(&h, &files).await;

    let attempt = tokio::time::timeout(Duration::from_secs(10), reconcile(&h, &files))
        .await
        .expect("a lone file waited for a batch");

    assert!(attempt.is_settled(&files[0]) && closed(&h, &files[0]));
    assert_eq!(metadata_batches(&h), vec![1]);
}

/// What a poisoned metadata step leaves behind, for comparing the two ways of
/// applying it.
#[derive(Debug, PartialEq)]
struct PoisonOutcome {
    retry: Vec<String>,
    settled: Vec<String>,
    bad_row: Option<(i64, i64)>,
    bad_on_disk: bool,
    bad_intent_open: bool,
    others_closed: Vec<bool>,
}

async fn run_poisoned(mode: u8) -> PoisonOutcome {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_metadata(&h, mode, 10_000);
    let files = names("x", 4);
    publish_new_files(&h, &files).await;
    let bad = files[1].clone();
    // The column update of one path fails, after its scaffold row was written.
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(&format!(
                "CREATE TRIGGER poison_one BEFORE UPDATE ON files WHEN NEW.path = '{bad}' \
                 BEGIN SELECT RAISE(ABORT, 'poisoned'); END;"
            ))?;
            Ok(())
        })
        .unwrap();

    let attempt = reconcile(&h, &files).await;

    PoisonOutcome {
        retry: attempt.retry.iter().cloned().collect(),
        settled: files.iter().filter(|n| attempt.is_settled(n)).cloned().collect(),
        bad_row: row(&h, &bad),
        bad_on_disk: h.path(&bad).exists(),
        bad_intent_open: h.state.has_materialization_intent(GROUP, &bad).unwrap(),
        others_closed: files.iter().filter(|n| **n != bad).map(|n| closed(&h, n)).collect(),
    }
}

/// One file whose step fails is retried exactly as with a step per file: no
/// row, no file, no intent; the others of its batch are applied and settle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_whose_metadata_step_fails_keeps_todays_state_and_the_others_settle() {
    let per_file = run_poisoned(PER_FILE).await;
    let batched = run_poisoned(BATCH).await;

    assert_eq!(batched.retry, vec!["x01.txt".to_string()]);
    assert_eq!(batched.bad_row, None, "the failed file's scaffold row survived: {batched:?}");
    assert!(!batched.bad_on_disk && !batched.bad_intent_open);
    assert_eq!(batched.others_closed, vec![true; 3]);
    assert_eq!(batched, per_file);
}

#[cfg(unix)]
async fn executable_source(h: &Harness, tag: &str, content: &[u8]) -> VersionHash {
    use std::os::unix::fs::PermissionsExt;
    let scratch = format!("zz-source-{tag}");
    std::fs::write(h.path(&scratch), content).unwrap();
    std::fs::set_permissions(h.path(&scratch), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(h.capture(&scratch).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(&scratch).content.unwrap().version_hash)
}

/// Writes this device's older version of `name` with mode 0644 whatever the
/// process umask is: the tests compare modes, and a umask of 002 would give
/// 0664 and make them depend on the host.
#[cfg(unix)]
fn write_own_version(h: &Harness, name: &str, content: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(h.path(name), content).unwrap();
    std::fs::set_permissions(h.path(name), std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
fn mode_of(h: &Harness, name: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(h.path(name)).unwrap().permissions().mode() & 0o777
}

/// The apply happens only while the file holds its path lock. Three paths
/// that already have a row (this device's own older version, mode 0644) are
/// received as newer, executable versions. While their metadata waits in the
/// queue: each still holds its lock, a scan authors nothing for it, its row
/// still has the old mode (nothing was applied before the batch), and the old
/// bytes and mode are on disk. After the batch the files settle with the
/// peer's bytes and mode, and no capture finds a local edit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_apply_waits_for_the_batch_with_the_path_lock_held_and_a_scan_authors_nothing() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_metadata(&h, BATCH, 30_000);
    let files = names("m", 3);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        write_own_version(&h, name, &format!("own version {i}"));
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
        let content = format!("peer's newer version {i}").into_bytes();
        ops.push(put(name, executable_source(&h, &format!("n{i}"), &content).await));
    }
    publish(&h, &ops);
    let old_rows: Vec<_> = files.iter().map(|n| row(&h, n).unwrap()).collect();
    let gate = Gate::arm(&h);
    let task = spawn_reconcile(&h, &files);
    until("the batch reached its transaction", || gate.reached()).await;

    for (i, name) in files.iter().enumerate() {
        assert!(
            h.state.path_lock_registry().path_lock(GROUP, name).try_lock().is_err(),
            "{name} queued its apply without holding its path lock"
        );
        assert_eq!(row(&h, name), Some(old_rows[i]), "{name}: applied before the batch");
        assert_eq!(
            std::fs::read(h.path(name)).unwrap(),
            format!("own version {i}").into_bytes(),
            "{name}"
        );
        assert_eq!(mode_of(&h, name), 0o644, "{name}");
    }
    let authored: Vec<String> =
        h.scan().into_iter().map(|r| r.path).filter(|p| files.contains(p)).collect();
    assert!(authored.is_empty(), "a scan authored a path whose apply was queued: {authored:?}");
    assert!(metadata_batches(&h).is_empty());

    gate.open();
    let attempt = task.await.unwrap().expect("the attempt runs");

    for (i, name) in files.iter().enumerate() {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert_eq!(
            std::fs::read(h.path(name)).unwrap(),
            format!("peer's newer version {i}").into_bytes()
        );
        assert_eq!(mode_of(&h, name), 0o755, "{name}");
        assert!(closed(&h, name), "{name}");
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::None), "{name}");
        assert_eq!(h.native_heads(name).len(), 1, "{name}: a local head beside the peer's");
    }
    assert_eq!(metadata_batches(&h), vec![3]);
    let free: Vec<bool> = files
        .iter()
        .map(|name| h.state.path_lock_registry().path_lock(GROUP, name).try_lock().is_ok())
        .collect();
    assert!(free.iter().all(|free| *free), "a path lock outlived the pass");
}

/// A run dropped while files are queued: nothing of them is applied (no
/// scaffold row), every lock is free, and the next pass settles every file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_dropped_with_files_queued_applies_none_of_them_and_is_recoverable() {
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 3);
    use_metadata(&h, BATCH, 60_000);
    let files = names("d", 3);
    let contents = publish_new_files(&h, &files).await;
    // The third file cannot take its path lock, so the other two wait for it.
    let straggler = h.state.path_lock_registry().path_lock(GROUP, &files[2]);
    let held = straggler.clone().lock_owned().await;
    let task = spawn_reconcile(&h, &files);
    until("two files queued holding their locks", || {
        files[..2]
            .iter()
            .all(|name| h.state.path_lock_registry().path_lock(GROUP, name).try_lock().is_err())
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(metadata_batches(&h).is_empty(), "nothing may apply while a sibling can still arrive");

    task.abort();
    let _ = task.await;

    assert!(metadata_batches(&h).is_empty(), "a dropped run applied something");
    for name in &files[..2] {
        assert_eq!(row(&h, name), None, "{name}: a scaffold row for a file that was dropped");
        assert!(
            h.state.path_lock_registry().path_lock(GROUP, name).try_lock().is_ok(),
            "{name}: the lock leaked"
        );
    }
    drop(held);
    let attempt = reconcile(&h, &files).await;
    for name in &files {
        assert!(attempt.is_settled(name), "{name}: {:?}", attempt.retry);
        assert!(closed(&h, name), "{name}");
        assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
    }
}

/// The end state of a generated workload (new, changed, deleted, moved and
/// colliding names, one file whose blocks are nowhere) is the same with a
/// metadata step per file and with batched steps, and the batched run applies
/// its files' metadata in fewer transactions than files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batched_metadata_pass_ends_in_the_state_of_a_per_file_pass() {
    let (serial_state, serial_disk, _, _, serial_sizes) = run_workload_with(1, 0, PER_FILE).await;
    let (per_file_state, per_file_disk, _, _, per_file_sizes) =
        run_workload_with(8, 0, PER_FILE).await;
    let (batched_state, batched_disk, batched_max, _, batched_sizes) =
        run_workload_with(8, 0, BATCH).await;

    assert!(serial_sizes.is_empty() && per_file_sizes.is_empty());
    assert!(batched_max >= 2, "the workload never overlapped two writes");
    assert_eq!(batched_disk, per_file_disk);
    assert_eq!(batched_state, per_file_state);
    assert_eq!(batched_disk, serial_disk);
    assert_eq!(batched_state, serial_state);
    let applied_in_batches: usize = batched_sizes.iter().sum();
    assert!(applied_in_batches > 0, "no metadata was applied in a batch");
    assert!(
        batched_sizes.len() < applied_in_batches,
        "{applied_in_batches} files applied in {} transactions",
        batched_sizes.len()
    );
}

/// A user changes a file's executable bit AFTER its path is locked and its
/// metadata item is queued; the watcher journals the event (`journal`) or, in
/// the other variant, only the file's ctime moved. The write's baseline is the
/// target as it was before the queue, so the edit is seen when the write is
/// about to replace the file: nothing is replaced, the file is not settled, and
/// the capture that runs once the lock is free authors the mode edit as a
/// local change.
#[cfg(unix)]
async fn a_mode_edit_while_the_metadata_waits_is_not_overwritten(journal: bool) {
    use std::os::unix::fs::PermissionsExt;
    let h = Arc::new(Harness::new(false));
    pin_concurrency(&h, 2);
    use_metadata(&h, BATCH, 30_000);
    let files = names("e", 2);
    let mut ops = Vec::new();
    for (i, name) in files.iter().enumerate() {
        write_own_version(&h, name, &format!("own version {i}"));
        assert!(matches!(h.capture(name).await, LocalChangeOutcome::FileChanged(_)));
        let content = format!("peer's newer version {i}").into_bytes();
        ops.push(put(name, source(&h, &format!("n{i}"), &content).await));
    }
    publish(&h, &ops);
    let edited = files[0].clone();
    let gate = Gate::arm(&h);
    let task = spawn_reconcile(&h, &files);
    until("the batch reached its transaction", || gate.reached()).await;
    std::fs::set_permissions(h.path(&edited), std::fs::Permissions::from_mode(0o755)).unwrap();
    if journal {
        h.state
            .dirty_path_repository()
            .record_dirty_paths_batch(
                GROUP,
                &[(edited.clone(), "watcher".to_owned(), 1)],
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }
    gate.open();
    let attempt = task.await.unwrap().expect("the attempt runs");

    assert!(!attempt.is_settled(&edited), "settled over the user's mode edit");
    assert_eq!(
        std::fs::read(h.path(&edited)).unwrap(),
        b"own version 0".to_vec(),
        "the peer's write replaced the file"
    );
    assert_eq!(mode_of(&h, &edited), 0o755, "the user's mode was replaced");
    // The capture that the retry lets run authors the user's mode edit.
    // The edit is journaled, the row is not in flight, and the capture that
    // runs now authors it.
    assert!(h.state.is_path_dirty(GROUP, &edited).unwrap(), "the edit is not pending");
    assert!(!h.state.has_materialization_intent(GROUP, &edited).unwrap());
    assert!(
        matches!(h.capture(&edited).await, LocalChangeOutcome::FileChanged(_)),
        "the mode edit was never authored"
    );
    assert_eq!(mode_of(&h, &edited), 0o755);
    assert!(attempt.is_settled(&files[1]));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mode_edit_while_the_metadata_waits_in_a_batch_is_not_overwritten() {
    a_mode_edit_while_the_metadata_waits_is_not_overwritten(false).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_journaled_mode_edit_while_the_metadata_waits_in_a_batch_is_not_overwritten() {
    a_mode_edit_while_the_metadata_waits_is_not_overwritten(true).await;
}
