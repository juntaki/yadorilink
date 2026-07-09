//! `yadorilink report ...` (tasks 4.1-4.6): usage/error report preview,
//! export, and submission; consent controls; and local queue management.
//!
//! ## Daemon-backed vs. CLI-only (task 4.6)
//!
//! Every command here first checks whether the daemon control socket is
//! reachable (`daemon_available()`) and prefers routing through it — the
//! daemon owns the live usage counters and is the only thing this crate
//! ever calls `SubmissionClient`/makes a network reporting call through
//! (point 4 of this change: one consent-check path, not two). When the
//! daemon is unreachable:
//! - `usage`: falls back to a genuinely limited report (this process's
//!   own version/OS/arch only, no command/sync counters — those are
//!   daemon-owned runtime state this crate deliberately does not read
//!   directly, even though `counters.json` happens to be a plain file,
//!   because a stale on-disk snapshot masquerading as "current usage"
//!   would be misleading).
//! - `error --last`/`--id`: reads directly from the *shared*
//!   `<config_dir>/reporting/error-candidates/` store via
//!   `yadorilink_daemon::reporting::error_candidates::ErrorCandidateStore`
//!   — this is deliberately **not** treated as daemon-only. See the
//!   module doc comment on `handle_reportable_error` below for why: a
//!   candidate is a finished, self-contained document (unlike the
//!   continuously-mutating counters), and this crate's own 4.5 hook
//!   writes into the exact same store, so "read the shared store
//!   directly" is what makes daemon-created and CLI-created candidates
//!   both show up under `--last` regardless of whether the daemon
//!   happens to be running right now.
//! - `consent *`: same reasoning as error candidates — consent state is
//!   plain local config, not daemon-owned runtime state, so every consent
//!   command works directly against `ConsentStore` when the daemon isn't
//!   reachable (design.md D7's "easy for forks/offline users to disable
//!   or inspect").
//! - `queue *` and `--submit`: **do** require the daemon and fail with a
//!   clear, reporting-specific error (`CliError::ReportingDaemonRequired`)
//!   when it's unavailable — the queue is genuinely daemon-managed
//!   runtime state (task 4.6's explicit example), and submission is the
//!   one network path this crate keeps exclusively behind the daemon.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use yadorilink_daemon::reporting::consent_store::ConsentStore;
use yadorilink_daemon::reporting::error_candidates::ErrorCandidateStore;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::ConsentAction;
use yadorilink_ipc_proto::daemonctl::{
    DeleteQueueItemRequest, FlushQueueRequest, GenerateLastErrorReportRequest,
    GenerateUsageReportRequest, ListQueueItemsRequest, ReportingConsentState,
    ReportingStatusRequest, ShowQueueItemRequest, StatusRequest, SubmitReportRequest,
    UpdateConsentRequest,
};
use yadorilink_reporting::builder::{build_usage_envelope, UsagePayloadBuilder};
use yadorilink_reporting::consent::ConsentState;

use crate::control_client;
use crate::error::CliError;

fn reporting_dir() -> PathBuf {
    crate::device_config::config_dir().join("reporting")
}

fn local_consent_store() -> ConsentStore {
    ConsentStore::new(reporting_dir())
}

fn local_error_candidates() -> ErrorCandidateStore {
    ErrorCandidateStore::new(reporting_dir())
}

async fn daemon_available() -> bool {
    control_client::send(ReqPayload::Status(StatusRequest {})).await.is_ok()
}

fn print_consent(consent: &ReportingConsentState) {
    println!("Usage submission:        {}", on_off(consent.usage_submission_enabled));
    println!("Automatic error submission: {}", on_off(consent.error_submission_enabled));
    println!("Prompt after failures:    {}", on_off(consent.prompt_to_report_enabled));
    println!("Automatic queue retry:    {}", on_off(consent.queue_retry_enabled));
    println!(
        "Anonymous reporter id:    {}",
        consent.anonymous_reporter_id.as_deref().unwrap_or("(none — not opted in yet)")
    );
    println!(
        "Reporting endpoint:       {}",
        consent.endpoint_override.as_deref().unwrap_or("(none configured)")
    );
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn local_consent_to_proto(consent: &ConsentState) -> ReportingConsentState {
    ReportingConsentState {
        usage_submission_enabled: consent.usage_submission_enabled,
        error_submission_enabled: consent.error_submission_enabled,
        prompt_to_report_enabled: consent.prompt_to_report_enabled,
        queue_retry_enabled: consent.queue_retry_enabled,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
        endpoint_override: consent.endpoint_override.clone(),
    }
}

fn write_export(path: &Path, report_json: &str) -> Result<(), CliError> {
    std::fs::write(path, report_json)?;
    println!("Wrote report to {}", path.display());
    Ok(())
}

fn print_redaction_summary(redaction_summary: &[(String, u32)]) {
    if redaction_summary.is_empty() {
        return;
    }
    println!();
    println!("Redacted before this preview (categories, occurrence counts):");
    for (category, count) in redaction_summary {
        println!("  {category}: {count}");
    }
}

/// Interactive submit confirmation (task 4.7 "submit asks for
/// confirmation"), factored so the prompt-reading itself is unit
/// testable without a real terminal — `confirm` (used by real commands)
/// always reads real stdin; tests call `confirm_with_reader` directly
/// with an in-memory reader.
pub fn confirm_with_reader(prompt: &str, assume_yes: bool, reader: &mut impl BufRead) -> bool {
    if assume_yes {
        return true;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm(prompt: &str, assume_yes: bool) -> bool {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    confirm_with_reader(prompt, assume_yes, &mut lock)
}

fn generate_limited_usage_report_json() -> String {
    let consent = local_consent_store().load_or_default();
    let env = yadorilink_daemon::reporting::environment::current(&consent);
    // Deliberately empty/default: no command/sync/error counters — see
    // module doc comment on why this crate doesn't read `counters.json`
    // directly as a substitute.
    let payload = UsagePayloadBuilder::new().build();
    build_usage_envelope(env, payload).to_json()
}

// -- `yadorilink report usage` (task 4.1) --------------------------------

pub async fn usage(
    preview: bool,
    export: Option<PathBuf>,
    submit: bool,
    yes: bool,
) -> Result<(), CliError> {
    let show_preview = preview || (!submit && export.is_none());
    let available = daemon_available().await;

    let report_json = if available {
        let resp =
            control_client::send(ReqPayload::GenerateUsageReport(GenerateUsageReportRequest {}))
                .await?;
        let Some(RespPayload::GenerateUsageReport(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        r.report_json
    } else {
        generate_limited_usage_report_json()
    };

    if show_preview {
        println!("{report_json}");
    }
    if let Some(path) = &export {
        write_export(path, &report_json)?;
    }
    if submit {
        submit_report_json(report_json, "usage", yes).await?;
    }
    Ok(())
}

// -- `yadorilink report error` (task 4.2) --------------------------------

pub async fn error(
    id: Option<String>,
    preview: bool,
    export: Option<PathBuf>,
    submit: bool,
    yes: bool,
) -> Result<(), CliError> {
    let show_preview = preview || (!submit && export.is_none());
    let available = daemon_available().await;

    let (report_json, redaction_summary) = if available {
        let resp = control_client::send(ReqPayload::GenerateLastErrorReport(
            GenerateLastErrorReportRequest { report_id: id.clone() },
        ))
        .await?;
        let Some(RespPayload::GenerateLastErrorReport(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        let summary =
            r.redaction_summary.into_iter().map(|c| (c.category, c.count)).collect::<Vec<_>>();
        (r.report_json, summary)
    } else {
        // See module doc comment: error candidates are shared, not
        // daemon-only, storage.
        let store = local_error_candidates();
        let candidate_id = match &id {
            Some(id) => id.clone(),
            None => {
                store
                    .most_recent()
                    .map_err(|e| CliError::Other(e.to_string()))?
                    .ok_or_else(|| {
                        CliError::Other(
                            "no error candidate is available yet — nothing has been captured \
                         locally, and the daemon is not running to check its own candidates"
                                .to_string(),
                        )
                    })?
                    .report_id
            }
        };
        let (envelope, summary) = store
            .show_with_summary(&candidate_id)
            .map_err(|e| CliError::Other(e.to_string()))?
            .ok_or_else(|| {
                CliError::Other(format!("no error candidate found with id `{candidate_id}`"))
            })?;
        let summary_pairs = summary
            .categories
            .iter()
            .map(|(category, count)| (format!("{category:?}"), *count as u32))
            .collect::<Vec<_>>();
        (envelope.to_json(), summary_pairs)
    };

    if show_preview {
        println!("{report_json}");
        print_redaction_summary(&redaction_summary);
    }
    if let Some(path) = &export {
        write_export(path, &report_json)?;
    }
    if submit {
        submit_report_json(report_json, "error", yes).await?;
    }
    Ok(())
}

async fn submit_report_json(report_json: String, kind: &str, yes: bool) -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(CliError::ReportingDaemonRequired(
            "submitting a report requires the yadorilink daemon (network submission is only \
             ever performed by the daemon) — run `yadorilink daemon start`, or use --export to \
             save the report to a file instead"
                .to_string(),
        ));
    }
    if !confirm(&format!("Submit this {kind} report to the configured reporting endpoint?"), yes) {
        println!("Not submitted.");
        return Ok(());
    }
    let resp =
        control_client::send(ReqPayload::SubmitReport(SubmitReportRequest { report_json })).await?;
    let Some(RespPayload::SubmitReport(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if r.queued_for_retry {
        println!("Submission failed but the report was queued locally for automatic retry.");
    } else {
        println!("Submitted. Receipt: {} (at {})", r.receipt_id, r.submitted_at);
    }
    Ok(())
}

// -- `yadorilink report consent ...` (task 4.3) --------------------------

pub async fn consent_status() -> Result<(), CliError> {
    if daemon_available().await {
        let resp =
            control_client::send(ReqPayload::ReportingStatus(ReportingStatusRequest {})).await?;
        let Some(RespPayload::ReportingStatus(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        if let Some(consent) = &r.consent {
            print_consent(consent);
        }
        println!("Queued unsent reports:    {}", r.queue_count);
        println!("Local error candidates:   {}", r.error_candidate_count);
    } else {
        println!("(daemon not running — showing local consent state only)");
        let consent = local_consent_store().load_or_default();
        print_consent(&local_consent_to_proto(&consent));
        let candidate_count = local_error_candidates().list().map(|v| v.len()).unwrap_or(0);
        println!("Queued unsent reports:    unavailable (daemon not running)");
        println!("Local error candidates:   {candidate_count}");
    }
    Ok(())
}

async fn update_consent(
    action: ConsentAction,
    bool_value: Option<bool>,
    string_value: Option<String>,
) -> Result<(), CliError> {
    if daemon_available().await {
        let resp = control_client::send(ReqPayload::UpdateConsent(UpdateConsentRequest {
            action: action as i32,
            bool_value,
            string_value,
        }))
        .await?;
        let Some(RespPayload::UpdateConsent(r)) = resp.payload else {
            return Err(CliError::Other("unexpected daemon response".into()));
        };
        if let Some(consent) = &r.consent {
            print_consent(consent);
        }
        return Ok(());
    }

    // Daemon unreachable: consent is plain local config (module doc
    // comment) — every action below has a direct `ConsentStore` method.
    let store = local_consent_store();
    let consent = match action {
        ConsentAction::EnableUsage => store.opt_in_usage(),
        ConsentAction::EnableError => store.opt_in_error_reporting(),
        ConsentAction::DisableAll => store.disable_all_submission(),
        ConsentAction::ResetId => store.reset_reporter_id(),
        ConsentAction::SetPrompt => store.set_prompt_to_report_enabled(bool_value.unwrap_or(false)),
        ConsentAction::SetQueueRetry => store.set_queue_retry_enabled(bool_value.unwrap_or(false)),
        ConsentAction::SetEndpoint => {
            store.set_endpoint_override(string_value.filter(|s| !s.is_empty()))
        }
        ConsentAction::Unspecified => {
            return Err(CliError::Other("unspecified consent action".to_string()))
        }
    }
    .map_err(|e| CliError::Other(e.to_string()))?;
    print_consent(&local_consent_to_proto(&consent));
    Ok(())
}

pub async fn consent_enable(usage: bool, error: bool) -> Result<(), CliError> {
    if !usage && !error {
        return Err(CliError::Other(
            "specify at least one of --usage / --error to enable".to_string(),
        ));
    }
    if usage {
        update_consent(ConsentAction::EnableUsage, None, None).await?;
    }
    if error {
        update_consent(ConsentAction::EnableError, None, None).await?;
    }
    Ok(())
}

pub async fn consent_disable() -> Result<(), CliError> {
    update_consent(ConsentAction::DisableAll, None, None).await
}

pub async fn consent_reset_id() -> Result<(), CliError> {
    update_consent(ConsentAction::ResetId, None, None).await
}

pub async fn consent_prompts(enabled: bool) -> Result<(), CliError> {
    update_consent(ConsentAction::SetPrompt, Some(enabled), None).await
}

pub async fn consent_queue_retry(enabled: bool) -> Result<(), CliError> {
    update_consent(ConsentAction::SetQueueRetry, Some(enabled), None).await
}

pub async fn consent_endpoint(url: Option<String>) -> Result<(), CliError> {
    update_consent(ConsentAction::SetEndpoint, None, url).await
}

// -- `yadorilink report queue ...` (task 4.4) — daemon-required ---------

fn require_daemon_for_queue() -> CliError {
    CliError::ReportingDaemonRequired(
        "the report queue lives in daemon-managed storage and cannot be read or changed \
         without the daemon running — run `yadorilink daemon start`"
            .to_string(),
    )
}

pub async fn queue_list() -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(require_daemon_for_queue());
    }
    let resp = control_client::send(ReqPayload::ListQueueItems(ListQueueItemsRequest {})).await?;
    let Some(RespPayload::ListQueueItems(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if r.items.is_empty() {
        println!("(queue is empty)");
    }
    for item in r.items {
        println!(
            "{}  {:<6} queued_at={}  size={}B  attempts={}",
            item.report_id, item.report_type, item.queued_at, item.size_bytes, item.submit_attempts
        );
    }
    Ok(())
}

pub async fn queue_show(report_id: String) -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(require_daemon_for_queue());
    }
    let resp =
        control_client::send(ReqPayload::ShowQueueItem(ShowQueueItemRequest { report_id })).await?;
    let Some(RespPayload::ShowQueueItem(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("{}", r.report_json);
    Ok(())
}

pub async fn queue_delete(report_id: String) -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(require_daemon_for_queue());
    }
    let resp = control_client::send(ReqPayload::DeleteQueueItem(DeleteQueueItemRequest {
        report_id: report_id.clone(),
    }))
    .await?;
    let Some(RespPayload::DeleteQueueItem(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if r.deleted {
        println!("Deleted {report_id} from the queue.");
    } else {
        println!("No queued report found with id {report_id}.");
    }
    Ok(())
}

pub async fn queue_flush() -> Result<(), CliError> {
    if !daemon_available().await {
        return Err(require_daemon_for_queue());
    }
    let resp = control_client::send(ReqPayload::FlushQueue(FlushQueueRequest {})).await?;
    let Some(RespPayload::FlushQueue(r)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    println!("Removed {} queued report(s).", r.removed_count);
    Ok(())
}

// -- reportable-error hook (task 4.5) ------------------------------------

/// Called from `main.rs`'s top-level error path for any command failure
/// worth surfacing to reporting (`CliError::is_reportable`). Two jobs,
/// both best-effort and both entirely local (no network call is
/// reachable from this function — the point of task 4.5's "sending no
/// data"):
/// 1. Persists a local error candidate directly into the *shared*
///    `error-candidates` store (see module doc comment) — this is this
///    change's answer to "where does a CLI-command failure get captured,
///    vs. a daemon-side severe error (task 3.3)?": both write into the
///    exact same on-disk store via the exact same `ErrorCandidateStore`
///    API, just from two different processes/call sites. No IPC message
///    was added for this because a local file write needs no daemon
///    round trip either way, and it means `report error --last` finds
///    whichever kind of candidate (daemon- or CLI-originated) is newest,
///    without the CLI needing to know or care which process created it.
/// 2. Prints a one-line hint suggesting `yadorilink report error --last
///    --preview`.
///
/// Both are skipped entirely if `prompt_to_report_enabled` is off (task
/// 4.7 "prompts can be disabled") — `report consent prompts false`.
/// Never panics, never changes the process's exit code (the caller reads
/// that from the original `CliError` untouched), never blocks on
/// anything beyond a local file write.
pub async fn handle_reportable_error(err: &CliError) {
    let consent = local_consent_store().load_or_default();
    if !consent.prompt_to_report_enabled {
        return;
    }

    let category = err.report_category();
    let builder = yadorilink_reporting::builder::ErrorPayloadBuilder::new(category, "cli")
        .log_lines(vec![err.to_string()]);
    let env = yadorilink_daemon::reporting::environment::current(&consent);
    let (envelope, summary) = yadorilink_reporting::builder::build_error_envelope(env, builder);
    let store = local_error_candidates();
    let _ = store.create_candidate_with_summary(envelope, &summary);

    eprintln!(
        "hint: run `yadorilink report error --last --preview` to see what would be reported \
         (nothing is sent automatically)"
    );
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn confirm_with_reader_accepts_y_and_yes_case_insensitively() {
        assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"y\n".to_vec())));
        assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"Yes\n".to_vec())));
        assert!(confirm_with_reader("ok?", false, &mut Cursor::new(b"YES\n".to_vec())));
    }

    #[test]
    fn confirm_with_reader_rejects_anything_else() {
        assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"n\n".to_vec())));
        assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"\n".to_vec())));
        assert!(!confirm_with_reader("ok?", false, &mut Cursor::new(b"".to_vec())));
    }

    /// Task 4.7 "submit asks for confirmation": `assume_yes` (the CLI's
    /// `--yes` flag) skips reading the reader entirely, so it works even
    /// with a reader that would otherwise reject (proving the flag, not
    /// the input, decided the outcome).
    #[test]
    fn confirm_with_reader_assume_yes_skips_reading_input() {
        assert!(confirm_with_reader("ok?", true, &mut Cursor::new(b"n\n".to_vec())));
        assert!(confirm_with_reader("ok?", true, &mut Cursor::new(b"".to_vec())));
    }
}
