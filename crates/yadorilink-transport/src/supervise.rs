//! daemon-reliability REL-7/REL-12: every `tokio::spawn` in this crate
//! used to discard its `JoinHandle`, so a panic or early exit in a
//! long-lived task (the relay connection, local discovery) went
//! undetected, unlogged, and unrestarted. This is a small, intentionally
//! duplicated copy of `yadorilink-daemon::supervise` (same design: `Fn`-based
//! restart loop, exponential backoff with jitter capped at 45s) rather
//! than a shared dependency — `yadorilink-daemon` already depends on
//! `yadorilink-transport`, so the reverse dependency would be circular, and
//! promoting this ~50-line utility into its own leaf crate isn't worth
//! the churn for a single call site's worth of logic on each side. Keep
//! this in sync with `yadorilink-daemon/src/supervise.rs` by inspection if
//! either changes.

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Backoff schedule for [`spawn_restarting`]: starts at `initial`, doubles
/// each consecutive attempt, capped at `max`, with up to +/-25% jitter
/// (avoids every reconnecting device on a shared relay/network outage
/// synchronizing their retries).
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl BackoffConfig {
    /// daemon-reliability's suggested range for reconnect loops (relay
    /// connection, local discovery): capped 30-60s, matching
    /// `yadorilink_daemon::supervise::BackoffConfig::RECONNECT`.
    pub const RECONNECT: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(45) };

    fn next(&self, attempt: u32) -> Duration {
        let scale = 1u64 << attempt.min(20); // avoid overflow on a long-lived task
        let backed_off = self.initial.saturating_mul(scale as u32).min(self.max);
        let jitter_frac = fastrand_unit_interval(); // [0, 1)
        let jitter_magnitude = backed_off.mul_f64(0.25 * jitter_frac);
        let jittered = if jitter_frac < 0.5 {
            backed_off.saturating_sub(jitter_magnitude)
        } else {
            backed_off.saturating_add(jitter_magnitude)
        };
        jittered.min(self.max)
    }
}

/// A small, dependency-free `[0, 1)` PRNG (splitmix64 seeded from the
/// current time) — jitter doesn't need to be cryptographically random,
/// just different across processes/restarts.
fn fastrand_unit_interval() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    let prev = STATE.fetch_add(seed | 1, Ordering::Relaxed);
    let mut z = prev.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

/// Spawns a restartable loop: `make_task` is called to produce a fresh
/// future each attempt. If that future ever resolves (a reconnect-and-run
/// loop is only meant to return on a real disconnect) or panics, this
/// logs it with `name` and the attempt count, waits out `backoff`, and
/// calls `make_task` again — forever. Use for tasks that should never
/// permanently give up (the relay connection, local discovery): there is
/// no "stop trying" state, matching `yadorilink_daemon::supervise`'s design.
///
/// Returns the supervising task's own `JoinHandle`; aborting it stops the
/// restart loop (the in-flight attempt is cancelled too).
pub fn spawn_restarting<F, Fut>(
    name: &'static str,
    backoff: BackoffConfig,
    make_task: F,
) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let result = tokio::spawn(make_task()).await;
            match result {
                Ok(()) => {
                    tracing::warn!(task = name, attempt, "supervised task exited; restarting");
                }
                Err(join_err) if join_err.is_panic() => {
                    tracing::error!(task = name, attempt, "supervised task panicked; restarting");
                }
                Err(join_err) => {
                    tracing::info!(task = name, error = %join_err, "supervised task was cancelled; not restarting");
                    return;
                }
            }
            let delay = backoff.next(attempt);
            tracing::info!(task = name, ?delay, "waiting before restart");
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    })
}

/// Spawns a one-shot task, logging (but not restarting) if it panics.
/// Complements [`spawn_restarting`]: use for tasks whose natural end is
/// expected (e.g. one relay server connection's lifetime) so a panic is
/// at least visible instead of silently vanishing with the dropped
/// `JoinHandle` (REL-7's core defect) — restarting a single finished
/// connection handler wouldn't make sense the way restarting a
/// reconnect loop does.
pub fn spawn_logged<Fut>(name: &'static str, task: Fut) -> JoinHandle<()>
where
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(join_err) = tokio::spawn(task).await {
            if join_err.is_panic() {
                tracing::error!(task = name, "supervised task panicked");
            } else {
                tracing::debug!(task = name, "supervised task was cancelled");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

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

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
        assert!(
            attempts.load(Ordering::SeqCst) >= 3,
            "expected several restarts within 50ms of ~1-5ms backoff"
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

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
        assert!(
            attempts.load(Ordering::SeqCst) >= 3,
            "expected retries past the panicking attempts"
        );
    }

    #[tokio::test]
    async fn spawn_logged_reports_panic_without_propagating_it() {
        let handle = spawn_logged("panicky-one-shot", async {
            panic!("simulated one-shot failure");
        });
        // Must not panic the test itself, and must resolve promptly.
        tokio::time::timeout(Duration::from_secs(1), handle).await.unwrap().unwrap();
    }

    #[test]
    fn backoff_doubles_and_caps_at_max() {
        let backoff =
            BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(10) };
        let d0 = backoff.next(0);
        assert!(d0 >= Duration::from_millis(750) && d0 <= Duration::from_millis(1250));
        let d_large = backoff.next(10);
        assert!(d_large <= Duration::from_secs(10) + Duration::from_millis(1));
    }
}
