//! Task 3.5: daemon-side queue retry. Periodically attempts to submit
//! every report still sitting in the local queue (`QueueStore`), guarded
//! by consent state, endpoint availability, and `SubmissionClient`'s own
//! rate limit — this module never makes a network decision on its own
//! that bypasses those checks (see design.md D1/D6 and point 4 of this
//! change's implementation notes: reuse `ConsentStore`/`SubmissionClient`
//! rather than a second consent-check path).

use std::sync::Arc;
use std::time::Duration;

use yadorilink_reporting::schema::ReportType;
use yadorilink_reporting::submission::SubmissionClient;

use crate::daemon_state::DaemonState;

/// How often the background sweep runs. Reports aren't time-sensitive
/// (design.md D6: submission is explicit/asynchronous and must never
/// block sync), so a coarse interval is fine — this is a background
/// safety net for "the user opted into retry and the endpoint was
/// temporarily down," not a hot path.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A queued entry stops being retried automatically after this many
/// failed attempts — left permanently queued (visible via `yadorilink
/// report queue list/show`) for the user to inspect/export/delete
/// manually, rather than retried forever.
pub const MAX_AUTOMATIC_RETRY_ATTEMPTS: u32 = 5;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetrySweepOutcome {
    pub attempted: u32,
    pub submitted: u32,
    pub gave_up: u32,
    /// Set when the sweep made zero network-relevant decisions because
    /// consent/endpoint gating stopped it before even listing the queue —
    /// distinct from "listed the queue and found nothing eligible."
    pub skipped_by_consent_gate: bool,
}

/// Runs one retry sweep and returns immediately — callers that want a
/// recurring background sweep should call this in a loop (see
/// `spawn_periodic`); exposed standalone so tests can call it directly
/// without waiting on `SWEEP_INTERVAL`.
///
/// Consent is re-checked here, not cached from anywhere else (task 3.5's
/// "guarded by consent state"): `queue_retry_enabled` must be on and an
/// endpoint (`consent.endpoint_override`) must be configured, or this
/// returns immediately having made zero calls into `client` — no
/// `client.submit` call is reachable from this function unless both are
/// true, which is what task 3.6's "no network submission when consent is
/// disabled" test exercises.
pub async fn run_retry_sweep_once(
    state: &DaemonState,
    client: &SubmissionClient,
) -> RetrySweepOutcome {
    let consent = state.reporting.consent_or_default();
    if !consent.queue_retry_enabled || consent.endpoint_override.is_none() {
        return RetrySweepOutcome { skipped_by_consent_gate: true, ..Default::default() };
    }

    let mut outcome = RetrySweepOutcome::default();
    let entries = match state.reporting.queue().list() {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(error = %e, "reporting: queue retry sweep failed to list queue");
            return outcome;
        }
    };

    for entry in entries {
        if entry.submit_attempts >= MAX_AUTOMATIC_RETRY_ATTEMPTS {
            continue;
        }
        // A per-report-type consent check on top of `queue_retry_enabled`
        // above: opting into retrying already-queued *usage* reports
        // doesn't imply consent to auto-submit *error* reports, and vice
        // versa (design.md D4: "automatic error submission requires
        // explicit opt-in separate from usage-summary opt-in").
        let allowed = match entry.report_type {
            ReportType::Usage => consent.usage_submission_enabled,
            ReportType::Error => consent.error_submission_enabled,
        };
        if !allowed {
            continue;
        }
        let Ok(Some(envelope)) = state.reporting.queue().show(&entry.report_id) else { continue };
        outcome.attempted += 1;
        match client.submit(&entry.report_id, &envelope, consent.endpoint_override.as_deref()).await
        {
            Ok(_receipt) => {
                let _ = state.reporting.queue().delete(&entry.report_id);
                outcome.submitted += 1;
            }
            Err(e) => {
                tracing::debug!(error = %e, report_id = %entry.report_id, "reporting: queued submission attempt failed");
                // Retryable or not, record the attempt: a permanent
                // failure (e.g. invalid payload) will fail identically on
                // every future sweep, so there is nothing to gain from
                // distinguishing it here — both paths converge on "stop
                // after MAX_AUTOMATIC_RETRY_ATTEMPTS."
                if let Ok(Some(new_count)) =
                    state.reporting.queue().increment_submit_attempts(&entry.report_id)
                {
                    if new_count >= MAX_AUTOMATIC_RETRY_ATTEMPTS || !e.is_retryable() {
                        outcome.gave_up += 1;
                    }
                }
            }
        }
    }
    outcome
}

/// Spawns the recurring background sweep (task 3.5) as a supervised task
/// (REL-8 pattern — logged, not restarted: a panic here would indicate a
/// real bug, not a transient condition worth restarting into).
pub fn spawn_periodic(state: Arc<DaemonState>) {
    crate::supervise::spawn_logged("reporting-queue-retry", async move {
        let Ok(client) = SubmissionClient::with_default_config() else {
            tracing::warn!(
                "reporting: failed to construct submission client; queue retry disabled for this process"
            );
            return Ok(());
        };
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            run_retry_sweep_once(&state, &client).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_reporting::builder::{build_usage_envelope, ReportEnvironment};
    use yadorilink_reporting::schema::{OsFamily, UsagePayload};
    use yadorilink_reporting::submission::{SubmissionClient, SubmissionConfig};
    use yadorilink_sync_core::index::SyncState;

    use super::*;

    /// `YADORILINK_CONFIG_DIR` is a process-global env var (same pattern as
    /// `yadorilink-cli`'s `tests/materialization.rs`'s `YADORILINK_CONTROL_SOCKET`
    /// use), so every test in this module that sets it must hold this
    /// mutex for its whole body. Shared with `daemon_state.rs` and
    /// `device_config.rs` (see `crate::test_support`'s doc comment) — a
    /// module-local mutex here alone does not serialize against those
    /// other modules' own tests touching the same env var.
    use crate::test_support::CONFIG_ENV_MUTEX as TEST_MUTEX;

    async fn test_state() -> (tempfile::TempDir, Arc<DaemonState>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
        let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
        std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
        let state = DaemonState::new("device-under-test".into(), sync_state, store);
        (dir, state)
    }

    fn sample_envelope() -> yadorilink_reporting::schema::ReportEnvelope {
        build_usage_envelope(
            ReportEnvironment {
                generated_at: "2026-01-01T00:00:00Z".into(),
                yadorilink_version: "0.1.0".into(),
                os_family: OsFamily::Linux,
                os_version_bucket: "24.04".into(),
                arch: "x86_64".into(),
                install_channel: None,
                anonymous_reporter_id: None,
            },
            UsagePayload { daemon_uptime_bucket: "<1h".into(), ..Default::default() },
        )
    }

    fn fast_client() -> SubmissionClient {
        SubmissionClient::new(SubmissionConfig {
            timeout: std::time::Duration::from_secs(5),
            min_submit_interval: std::time::Duration::from_millis(0),
        })
        .unwrap()
    }

    /// Task 3.6: the core "no network submission when consent is
    /// disabled" proof for the retry path — a real local HTTP listener
    /// (`wiremock`) with no mock registered, so a request would 404 if it
    /// arrived, and `queue_retry_enabled: false` (the default). Asserts
    /// zero requests reached the endpoint, not just an assertion on
    /// internal state.
    #[tokio::test]
    async fn retry_sweep_makes_no_network_call_when_queue_retry_consent_is_disabled() {
        let _guard = TEST_MUTEX.lock().await;
        let (_dir, state) = test_state().await;
        let server = MockServer::start().await;
        state.reporting.consent().opt_in_usage().unwrap(); // usage submission on...
        state
            .reporting
            .consent()
            .set_endpoint_override(Some(format!("{}/reports", server.uri())))
            .unwrap();
        // ...but queue_retry_enabled is still false (never set) — the gate
        // this test exists to prove.
        state.reporting.queue().enqueue(sample_envelope()).unwrap();

        let client = fast_client();
        let outcome = run_retry_sweep_once(&state, &client).await;

        assert!(outcome.skipped_by_consent_gate);
        assert_eq!(outcome.attempted, 0);
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "no request should reach the endpoint while queue_retry_enabled is false"
        );
        assert_eq!(state.reporting.queue().list().unwrap().len(), 1, "entry remains queued");
    }

    /// Same as above, but with `queue_retry_enabled` on and no endpoint
    /// configured — still zero requests, since "no endpoint" must be free
    /// (mirrors `yadorilink-reporting::submission`'s own task 5.4 test).
    #[tokio::test]
    async fn retry_sweep_makes_no_network_call_when_no_endpoint_is_configured() {
        let _guard = TEST_MUTEX.lock().await;
        let (_dir, state) = test_state().await;
        let server = MockServer::start().await;
        state.reporting.consent().opt_in_usage().unwrap();
        state.reporting.consent().set_queue_retry_enabled(true).unwrap();
        state.reporting.queue().enqueue(sample_envelope()).unwrap();

        let client = fast_client();
        let outcome = run_retry_sweep_once(&state, &client).await;

        assert!(outcome.skipped_by_consent_gate);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The positive path: consent fully enabled, a reachable endpoint —
    /// the queued report is submitted and removed from the queue.
    #[tokio::test]
    async fn retry_sweep_submits_and_clears_a_queued_report_when_fully_consented() {
        let _guard = TEST_MUTEX.lock().await;
        let (_dir, state) = test_state().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/reports"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "receipt_id": "receipt-xyz",
                "submitted_at": "2026-01-01T00:00:05Z",
            })))
            .mount(&server)
            .await;

        state.reporting.consent().opt_in_usage().unwrap();
        state.reporting.consent().set_queue_retry_enabled(true).unwrap();
        state
            .reporting
            .consent()
            .set_endpoint_override(Some(format!("{}/reports", server.uri())))
            .unwrap();
        state.reporting.queue().enqueue(sample_envelope()).unwrap();

        let client = fast_client();
        let outcome = run_retry_sweep_once(&state, &client).await;

        assert!(!outcome.skipped_by_consent_gate);
        assert_eq!(outcome.attempted, 1);
        assert_eq!(outcome.submitted, 1);
        assert!(state.reporting.queue().list().unwrap().is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// An entry already at the automatic-retry cap is skipped entirely —
    /// no network call, no further attempt-count bump.
    #[tokio::test]
    async fn retry_sweep_skips_entries_already_at_the_attempt_cap() {
        let _guard = TEST_MUTEX.lock().await;
        let (_dir, state) = test_state().await;
        let server = MockServer::start().await;
        state.reporting.consent().opt_in_usage().unwrap();
        state.reporting.consent().set_queue_retry_enabled(true).unwrap();
        state
            .reporting
            .consent()
            .set_endpoint_override(Some(format!("{}/reports", server.uri())))
            .unwrap();
        let meta = state.reporting.queue().enqueue(sample_envelope()).unwrap();
        for _ in 0..MAX_AUTOMATIC_RETRY_ATTEMPTS {
            state.reporting.queue().increment_submit_attempts(&meta.report_id).unwrap();
        }

        let client = fast_client();
        let outcome = run_retry_sweep_once(&state, &client).await;

        assert_eq!(outcome.attempted, 0);
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
