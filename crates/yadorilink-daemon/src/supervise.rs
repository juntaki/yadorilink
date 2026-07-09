//! daemon-reliability reliability hardening/reliability hardening/reliability hardening: every `tokio::spawn` in the
//! daemon and transport used to discard its `JoinHandle` — a panic or
//! early exit in a critical task (peer orchestrator, relay I/O,
//! mesh-forward/presence/TTL loops) went undetected, unlogged, and
//! unrestarted, leaving the process "up" as a zombie with broken sync.
//! This module gives every long-lived task two things: (1) a name for
//! logging, and (2) an explicit policy for what happens when it exits —
//! restart with backoff, or propagate the exit to whoever's supervising
//! essential tasks together (`main.rs`'s `JoinSet`, reliability hardening).

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

/// Backoff schedule for [`spawn_restarting`]: starts at `initial`,
/// doubles each consecutive failure, capped at `max`, with up to ±25%
/// jitter (avoids every restarting task on a multi-tenant host
/// synchronizing their retries after a shared outage, e.g. the
/// coordination server or relay coming back up).
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl BackoffConfig {
    /// daemon-reliability's own suggested range for reconnect loops
    /// (coordination netmap stream, relay connection): capped 30-60s.
    pub const RECONNECT: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(45) };

    /// A Degraded (disk-pressure) link's periodic free-space re-check
    /// schedule — starts at 5s (disk pressure can resolve quickly, e.g. a
    /// user manually deleting a large file) and caps at 5 minutes (a
    /// persistently full disk shouldn't be re-checked so often it's
    /// effectively a hot loop, but still recovers within a bounded,
    /// documented window once space frees up).
    pub const DEGRADED_LINK_RECHECK: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(5), max: Duration::from_secs(300) };

    /// Steady-state periodic update-check interval. `initial == max`
    /// reuses `next`'s existing ±25% jitter around a fixed point rather
    /// than modeling true escalating backoff — there's no "failure"
    /// being backed off here, just spreading many installs' checks so
    /// they don't all hit the manifest endpoint at the same wall-clock
    /// moment.
    pub const UPDATE_CHECK_INTERVAL: BackoffConfig = BackoffConfig {
        initial: Duration::from_secs(6 * 3600),
        max: Duration::from_secs(6 * 3600),
    };

    /// Backoff after a *failed* update check (manifest fetch/parse/
    /// signature error) — retried sooner than the steady-state interval
    /// above, doubling up to a cap, so a transient network blip recovers
    /// quickly but a persistently broken endpoint doesn't hot-loop
    /// against it.
    pub const UPDATE_CHECK_RETRY: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(60), max: Duration::from_secs(3600) };

    /// Made `pub` (was private, used only by `spawn_restarting` below) so
    /// `daemon_state`'s Degraded-link re-check scheduling can reuse this
    /// exact doubling+jitter+cap schedule instead of a second, independent
    /// backoff implementation.
    pub fn next(&self, attempt: u32) -> Duration {
        let scale = 1u64 << attempt.min(20); // avoid overflow on a long-lived task
        let backed_off = self.initial.saturating_mul(scale as u32).min(self.max);
        // `Duration::mul_f64` panics on a negative factor, so compute the
        // +/-25% jitter magnitude unsigned and apply it as an explicit
        // add/subtract rather than multiplying by a signed fraction.
        let jitter_frac = fastrand_unit_interval(); // [0, 1)
        let jitter_magnitude = backed_off.mul_f64(0.25 * jitter_frac);
        let jittered = if jitter_frac < 0.5 {
            backed_off.saturating_sub(jitter_magnitude)
        } else {
            backed_off.saturating_add(jitter_magnitude)
        };
        // `max` is a true ceiling — jitter must never push the delay
        // above it, only vary it below/around the un-jittered value.
        jittered.min(self.max)
    }
}

/// A small, dependency-free `[0, 1)` PRNG (splitmix64 seeded from the
/// current time) — jitter doesn't need to be cryptographically random,
/// just different across processes/restarts, and this avoids pulling in
/// `rand` as a non-dev dependency for a single call site.
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
/// future each attempt. If that future ever resolves (loops that are
/// meant to run forever, like a reconnect-and-stream loop, only return
/// on a real error) or panics, this logs it at `warn` with `name` and
/// the attempt count, waits out `backoff`, and calls `make_task` again —
/// forever. Use for tasks that should never permanently give up (reliability hardening/
/// reliability hardening/reliability hardening's reconnect loops): there is no "stop trying" state,
/// since the daemon is meant to recover from an arbitrarily long outage
/// on its own.
///
/// Returns the supervising task's own `JoinHandle` — awaiting it never
/// completes under normal operation (the loop is intentionally
/// infinite); it exists so callers can still hold/abort the handle like
/// any other spawned task (e.g. for shutdown, reliability hardening).
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
                    // Cancelled (aborted) — the caller is shutting this
                    // down on purpose (reliability hardening); stop restarting rather
                    // than fighting an intentional abort.
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

/// Spawns a one-shot essential task: logs at `error` if it exits with an
/// `Err` or panics, but does not restart it. Pair with `main.rs`'s
/// essential-task `JoinSet`/`select!` (reliability hardening): when *any* essential
/// task's handle resolves, the daemon should treat that as fatal (log
/// and exit non-zero) rather than silently continuing as a zombie with
/// broken sync — restarting individual essential tasks in place papers
/// over exactly the failure mode reliability hardening exists to surface to a process
/// supervisor instead.
pub fn spawn_logged<Fut>(name: &'static str, task: Fut) -> JoinHandle<()>
where
    Fut: Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
{
    tokio::spawn(async move {
        match task.await {
            Ok(()) => tracing::warn!(task = name, "essential task exited"),
            Err(e) => tracing::error!(task = name, error = %e, "essential task failed"),
        }
    })
}

#[cfg(test)]
mod tests {
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
        let backoff =
            BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(10) };
        // Jitter is ±25%, so check bounds rather than exact values.
        let d0 = backoff.next(0);
        assert!(d0 >= Duration::from_millis(750) && d0 <= Duration::from_millis(1250));
        let d_large = backoff.next(10);
        assert!(d_large <= Duration::from_secs(10) + Duration::from_millis(1));
    }
}
