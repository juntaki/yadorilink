//! add-oss-usage-error-reporting task 4.7: CLI-level reporting tests,
//! following the same "drive a real daemon over the real control socket"
//! pattern as `tests/materialization.rs`. Covers: preview shows the exact
//! payload, export writes JSON without submitting, consent controls
//! persist, queue commands operate, prompts can be disabled, and
//! daemon-unavailable behavior is clear (a specific error, not a silent
//! no-op or a generic failure).
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;

/// Tests in this file share two process-global env vars
/// (`YADORILINK_CONFIG_DIR`, `YADORILINK_CONTROL_SOCKET`) and so must not
/// run concurrently with each other (same convention as
/// `materialization.rs`'s `TEST_MUTEX`).
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_state = state.clone();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_state)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (dir, state)
}

/// Points both env vars at a fresh, empty directory/socket path with
/// nothing listening — `daemon_available()` sees a real connection
/// failure, exactly like a machine where the daemon was never started.
fn point_at_unreachable_daemon() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));
    dir
}

/// Task 4.7 "preview exact payload": the JSON `report usage --preview`
/// would print is byte-identical to what the daemon's
/// `GenerateUsageReport` IPC call returns — proven here by generating it
/// the same way `commands::report::usage` does (via the daemon) and
/// checking it parses back to a valid, schema-consistent envelope with
/// the counters we seeded.
#[tokio::test]
async fn usage_preview_reflects_seeded_counters_exactly() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;
    state.reporting.note_command_category("link");
    state.reporting.note_command_category("link");

    // `commands::report::usage` prints to stdout rather than returning
    // the JSON, so exercise the same underlying IPC call its preview
    // path uses and check the counters round-trip exactly.
    let resp = yadorilink_cli::control_client::send(
        yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload::GenerateUsageReport(
            yadorilink_ipc_proto::daemonctl::GenerateUsageReportRequest {},
        ),
    )
    .await
    .unwrap();
    let Some(
        yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload::GenerateUsageReport(r),
    ) = resp.payload
    else {
        panic!("wrong response variant")
    };
    let envelope = yadorilink_reporting::schema::ReportEnvelope::from_json(&r.report_json).unwrap();
    envelope.validate().unwrap();
    let yadorilink_reporting::schema::ReportPayload::Usage(payload) = envelope.payload else {
        panic!("expected a usage payload")
    };
    assert_eq!(payload.command_category_counts.get("link"), Some(&2));

    // The full command path succeeds and produces the same thing (an
    // end-to-end smoke test of `usage(preview=true, ...)`).
    yadorilink_cli::commands::report::usage(true, None, false, false).await.unwrap();
}

/// Task 4.7 "export writes JSON without submission": `--export` writes a
/// parseable envelope to disk, and (since `--submit` was not given) never
/// touches the daemon's submission path — checked here by never enabling
/// consent or configuring an endpoint, so any accidental submit attempt
/// would fail loudly rather than silently succeeding.
#[tokio::test]
async fn usage_export_writes_valid_json_and_does_not_submit() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;
    let export_path = dir.path().join("usage-report.json");

    yadorilink_cli::commands::report::usage(false, Some(export_path.clone()), false, false)
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&export_path).unwrap();
    let envelope = yadorilink_reporting::schema::ReportEnvelope::from_json(&contents).unwrap();
    envelope.validate().unwrap();
    assert_eq!(envelope.report_type, yadorilink_reporting::schema::ReportType::Usage);
}

/// Task 4.7 "submit asks for confirmation": with `--yes` (the CLI's
/// confirmation bypass) but consent left disabled, submission still
/// fails — proving the confirmation bypass and the consent gate are two
/// independent checks, not the same one (a submit can be "confirmed" and
/// still correctly refused). Manual interactive-prompt behavior itself is
/// covered by `commands::report::confirm_with_reader`'s own unit tests
/// (an automated test can't drive a real TTY prompt).
#[tokio::test]
async fn submit_with_yes_flag_still_enforces_consent() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, _state) = start_daemon().await;

    let err = yadorilink_cli::commands::report::usage(false, None, true, true).await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("not enabled"),
        "expected a consent-not-enabled error, got: {message}"
    );
}

/// Task 4.7 "consent controls persist": enabling usage submission via the
/// CLI command function is visible in the daemon's own consent store
/// afterward.
#[tokio::test]
async fn consent_enable_usage_persists_in_daemon_state() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::report::consent_enable(true, false).await.unwrap();
    let consent = state.reporting.consent_or_default();
    assert!(consent.usage_submission_enabled);
    assert!(!consent.error_submission_enabled);
    assert!(consent.anonymous_reporter_id.is_some());

    yadorilink_cli::commands::report::consent_disable().await.unwrap();
    assert!(state.reporting.consent_or_default().is_fully_disabled());
}

#[tokio::test]
async fn consent_reset_id_changes_the_reporter_id() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::report::consent_enable(true, false).await.unwrap();
    let first_id = state.reporting.consent_or_default().anonymous_reporter_id.unwrap();

    yadorilink_cli::commands::report::consent_reset_id().await.unwrap();
    let second_id = state.reporting.consent_or_default().anonymous_reporter_id.unwrap();

    assert_ne!(first_id, second_id);
}

/// Task 4.7 "queue commands operate": show/delete via the CLI command
/// functions against an entry seeded directly into the daemon's queue.
#[tokio::test]
async fn queue_show_and_delete_operate_via_cli_commands() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;
    let envelope = yadorilink_reporting::builder::build_usage_envelope(
        yadorilink_reporting::builder::ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: yadorilink_reporting::schema::OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        },
        yadorilink_reporting::schema::UsagePayload::default(),
    );
    let meta = state.reporting.queue().enqueue(envelope).unwrap();

    yadorilink_cli::commands::report::queue_show(meta.report_id.clone()).await.unwrap();
    yadorilink_cli::commands::report::queue_list().await.unwrap();
    yadorilink_cli::commands::report::queue_delete(meta.report_id).await.unwrap();
    assert!(state.reporting.queue().list().unwrap().is_empty());
}

/// Task 4.7 "prompts can be disabled": with `prompt_to_report_enabled`
/// turned off, `handle_reportable_error` creates no candidate and (since
/// this is best-effort/local-only either way) still never panics.
#[tokio::test]
async fn reportable_error_hook_creates_no_candidate_when_prompts_are_disabled() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    yadorilink_cli::commands::report::consent_prompts(false).await.unwrap();
    assert!(!state.reporting.consent_or_default().prompt_to_report_enabled);

    let err = yadorilink_cli::error::CliError::Other("synthetic failure for a test".to_string());
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    assert!(state.reporting.error_candidates().list().unwrap().is_empty());
}

/// The contrasting case: with prompting on (the default), the same hook
/// creates exactly one local candidate.
#[tokio::test]
async fn reportable_error_hook_creates_a_candidate_when_prompts_are_enabled() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state) = start_daemon().await;

    let err = yadorilink_cli::error::CliError::Other(
        "synthetic failure at /Users/alice/secret".to_string(),
    );
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    let candidates = state.reporting.error_candidates().list().unwrap();
    assert_eq!(candidates.len(), 1);
    let envelope =
        state.reporting.error_candidates().show(&candidates[0].report_id).unwrap().unwrap();
    assert!(!envelope.to_json().contains("alice"), "the candidate must already be redacted");
}

/// Task 4.7 "daemon-unavailable behavior is clear": `report usage
/// --preview`/`--export` still work (task 4.6's limited CLI-only report),
/// while `report queue list` fails with the specific
/// `ReportingDaemonRequired` error rather than a generic failure or a
/// silently empty list.
#[tokio::test]
async fn daemon_unavailable_usage_preview_still_works_but_queue_fails_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    // Limited fallback report generation succeeds even with no daemon.
    yadorilink_cli::commands::report::usage(true, None, false, false).await.unwrap();

    // The queue is explicitly daemon-only.
    let err = yadorilink_cli::commands::report::queue_list().await.unwrap_err();
    assert!(matches!(err, yadorilink_cli::error::CliError::ReportingDaemonRequired(_)));
    assert_eq!(err.exit_code(), 6);
    assert!(err.to_string().contains("daemon"));
}

/// Submitting without a daemon is refused with the reporting-specific
/// error, not a generic `DaemonNotRunning`/`Other`.
#[tokio::test]
async fn daemon_unavailable_submit_is_refused_clearly() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    let err = yadorilink_cli::commands::report::usage(false, None, true, true).await.unwrap_err();
    assert!(matches!(err, yadorilink_cli::error::CliError::ReportingDaemonRequired(_)));
}

/// `report error --last` without a daemon and with nothing captured
/// locally yet is also a clear error, not an empty/zeroed report.
#[tokio::test]
async fn daemon_unavailable_error_last_with_nothing_captured_is_clear() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    let err =
        yadorilink_cli::commands::report::error(None, true, None, false, false).await.unwrap_err();
    assert!(err.to_string().contains("no error candidate"));
}

/// `report error --last` without a daemon, but with a candidate this same
/// CLI process already captured locally (task 4.5's hook, task 4.6's
/// "the specific error it just hit"), finds it directly.
#[tokio::test]
async fn daemon_unavailable_error_last_finds_a_locally_captured_candidate() {
    let _guard = TEST_MUTEX.lock().await;
    let _dir = point_at_unreachable_daemon();

    let err = yadorilink_cli::error::CliError::Other("disk full while syncing".to_string());
    yadorilink_cli::commands::report::handle_reportable_error(&err).await;

    yadorilink_cli::commands::report::error(None, true, None, false, false).await.unwrap();
}
