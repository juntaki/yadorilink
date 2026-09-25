#![cfg(test)]

use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Polls for `attempts` to reach `target` instead of sleeping a fixed
/// duration and then asserting a threshold. A fixed sleep + count
/// assertion assumes the host
/// scheduler gives this task's ~1-5ms backoff loop enough real
/// wall-clock progress within that fixed window; under heavy
/// concurrent CPU load (many parallel builds/tests contending for
/// cores) that assumption can be false even though the supervised
/// task's actual restart behavior is correct — this waits (bounded by
/// a generous `timeout`) for the real condition instead, so the test
/// still fails (via the caller's own assertion) on a genuine
/// regression where restarts stop happening, but tolerates transient
/// scheduling delays rather than racing a fixed clock.
async fn wait_for_attempts(attempts: &AtomicU32, target: u32, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while attempts.load(Ordering::SeqCst) < target {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn spawn_restarting_retries_after_a_returning_task() {
    let attempts = Arc::new(AtomicU32::new(0));
    let backoff =
        BackoffConfig { initial: Duration::from_millis(1), max: Duration::from_millis(5) };
    let counted = attempts.clone();
    let handle = spawn_restarting("test-task", backoff, move || {
        let attempts = counted.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
        }
    });

    wait_for_attempts(&attempts, 3, Duration::from_secs(10)).await;
    handle.abort();
    assert!(
        attempts.load(Ordering::SeqCst) >= 3,
        "expected several restarts of ~1-5ms backoff within 10s of polling"
    );
}

#[tokio::test]
async fn spawn_restarting_retries_after_a_panic() {
    let attempts = Arc::new(AtomicU32::new(0));
    let backoff =
        BackoffConfig { initial: Duration::from_millis(1), max: Duration::from_millis(5) };
    let counted = attempts.clone();
    let handle = spawn_restarting("panicky-task", backoff, move || {
        let attempts = counted.clone();
        async move {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                panic!("simulated failure");
            }
        }
    });

    wait_for_attempts(&attempts, 3, Duration::from_secs(10)).await;
    handle.abort();
    assert!(
        attempts.load(Ordering::SeqCst) >= 3,
        "expected retries past the panicking attempts within 10s of polling"
    );
}

#[tokio::test]
async fn spawn_restarting_stops_when_aborted_from_outside() {
    let attempts = Arc::new(AtomicU32::new(0));
    let backoff =
        BackoffConfig { initial: Duration::from_millis(1), max: Duration::from_millis(5) };
    let counted = attempts.clone();
    let handle = spawn_restarting("abortable-task", backoff, move || {
        let attempts = counted.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(10)).await; // never returns on its own
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    handle.abort();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count_after_abort = attempts.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        count_after_abort,
        "must not keep restarting after the supervising handle itself was aborted"
    );
}

#[test]
fn backoff_doubles_and_caps_at_max() {
    let backoff = BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(10) };
    // Jitter is ±25%, so check bounds rather than exact values.
    let d0 = backoff.next(0);
    assert!(d0 >= Duration::from_millis(750) && d0 <= Duration::from_millis(1250));
    let d_large = backoff.next(10);
    assert!(d_large <= Duration::from_secs(10) + Duration::from_millis(1));
}

/// Captures the formatted log output of everything this thread emits while
/// the returned guard lives, at every level.
fn capture_logs() -> (Arc<std::sync::Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(Capture(buffer.clone()))
        .finish();
    (buffer, tracing::subscriber::set_default(subscriber))
}

/// A one-shot task that finishes cleanly did exactly what it was spawned to
/// do; logging that at WARN made every reconnect look like a failure.
#[tokio::test(flavor = "current_thread")]
async fn a_one_shot_task_finishing_cleanly_is_not_a_warning() {
    let (logs, _guard) = capture_logs();
    spawn_one_shot("one-shot-ok", async { Ok(()) }).await.unwrap();
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("one-shot-ok"), "the clean exit is still logged: {logs}");
    assert!(
        !logs.contains("WARN") && !logs.contains("ERROR"),
        "a clean exit is not a warning: {logs}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_one_shot_task_that_fails_is_still_a_warning() {
    let (logs, _guard) = capture_logs();
    spawn_one_shot("one-shot-err", async { Err("boom".into()) }).await.unwrap();
    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("WARN") && logs.contains("boom"), "a failure must be a warning: {logs}");
}
