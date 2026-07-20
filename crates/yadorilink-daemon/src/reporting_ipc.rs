//! Daemon-side handlers for the reporting IPC surface added
//! to `daemon_control.proto`. Kept in its own module (like
//! `hydration.rs`) rather than inlined into `control_socket.rs`'s match
//! arms, since each handler needs several lines of translation between
//! the wire messages and `yadorilink_reporting`/`crate::reporting` types.
//!
//! Every handler here returns `Result<T, String>` — `control_socket.rs`
//! wraps `Err` into `RespPayload::Error`, the same convention every other
//! fallible control-socket operation already uses.
//!
//! ("report preview generation returns the exact payload"): the
//! `generate_*` handlers below return `envelope.to_json` verbatim — no
//! re-derivation, no summarized/approximated view — so a CLI `--preview`
//! is guaranteed byte-identical to what `--export`/`--submit` would
//! transmit.

use yadorilink_ipc_proto::daemonctl::{
    ConsentAction, DeleteQueueItemResponse, FlushQueueResponse, GenerateLastErrorReportResponse,
    GenerateUsageReportResponse, ListQueueItemsResponse, QueueItem, RedactionCategoryCount,
    ReportingConsentState, ReportingStatusResponse, ShowQueueItemResponse, SubmitReportResponse,
    UpdateConsentRequest, UpdateConsentResponse,
};
use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::schema::{ReportEnvelope, ReportType};
use yadorilink_reporting::submission::SubmissionClient;

use crate::daemon_state::DaemonState;
use crate::reporting::environment;

fn consent_to_proto(consent: &ConsentState) -> ReportingConsentState {
    ReportingConsentState {
        usage_submission_enabled: consent.usage_submission_enabled,
        error_submission_enabled: consent.error_submission_enabled,
        prompt_to_report_enabled: consent.prompt_to_report_enabled,
        queue_retry_enabled: consent.queue_retry_enabled,
        anonymous_reporter_id: consent.anonymous_reporter_id.clone(),
        endpoint_override: consent.endpoint_override.clone(),
    }
}

pub fn reporting_status(state: &DaemonState) -> ReportingStatusResponse {
    let consent = state.reporting.consent_or_default();
    let queue_count = state.reporting.queue().list().map(|v| v.len()).unwrap_or(0) as u32;
    let error_candidate_count =
        state.reporting.error_candidates().list().map(|v| v.len()).unwrap_or(0) as u32;
    ReportingStatusResponse {
        consent: Some(consent_to_proto(&consent)),
        queue_count,
        error_candidate_count,
    }
}

/// builds and returns a usage report envelope from the
/// daemon's current counters — never persisted/queued by this call alone
/// (that's `SubmitReportRequest`'s job), so generating a
/// preview has no side effect on stored state.
pub fn generate_usage_report(state: &DaemonState) -> GenerateUsageReportResponse {
    let consent = state.reporting.consent_or_default();
    let env = environment::current(&consent);
    let payload = state.reporting.counters().to_usage_payload();
    let envelope = yadorilink_reporting::builder::build_usage_envelope(env, payload);
    GenerateUsageReportResponse { report_json: envelope.to_json() }
}

/// returns the most recent error candidate (`report_id: None`)
/// or a specific one (`report_id: Some(id)`), plus the redaction summary
/// captured when it was created (hook).
pub fn generate_last_error_report(
    state: &DaemonState,
    report_id: Option<String>,
) -> Result<GenerateLastErrorReportResponse, String> {
    let candidates = state.reporting.error_candidates();
    let id = match report_id {
        Some(id) => id,
        None => match candidates.most_recent().map_err(|e| e.to_string())? {
            Some(meta) => meta.report_id,
            None => return Err("no error candidate is available yet".to_string()),
        },
    };
    let Some((envelope, summary)) = candidates.show_with_summary(&id).map_err(|e| e.to_string())?
    else {
        return Err(format!("no error candidate found with id `{id}`"));
    };
    let redaction_summary = summary
        .categories
        .iter()
        .map(|(category, count)| RedactionCategoryCount {
            category: format!("{category:?}"),
            count: *count as u32,
        })
        .collect();
    Ok(GenerateLastErrorReportResponse {
        report_id: id,
        report_json: envelope.to_json(),
        redaction_summary,
    })
}

pub fn list_queue_items(state: &DaemonState) -> Result<ListQueueItemsResponse, String> {
    let items = state
        .reporting
        .queue()
        .list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| QueueItem {
            report_id: m.report_id,
            report_type: match m.report_type {
                ReportType::Usage => "usage".to_string(),
                ReportType::Error => "error".to_string(),
            },
            queued_at: m.queued_at,
            size_bytes: m.size_bytes as u64,
            submit_attempts: m.submit_attempts,
        })
        .collect();
    Ok(ListQueueItemsResponse { items })
}

pub fn show_queue_item(
    state: &DaemonState,
    report_id: &str,
) -> Result<ShowQueueItemResponse, String> {
    match state.reporting.queue().show(report_id).map_err(|e| e.to_string())? {
        Some(envelope) => Ok(ShowQueueItemResponse { report_json: envelope.to_json() }),
        None => Err(format!("no queued report found with id `{report_id}`")),
    }
}

pub fn delete_queue_item(
    state: &DaemonState,
    report_id: &str,
) -> Result<DeleteQueueItemResponse, String> {
    let deleted = state.reporting.queue().delete(report_id).map_err(|e| e.to_string())?;
    Ok(DeleteQueueItemResponse { deleted })
}

pub fn flush_queue(state: &DaemonState) -> Result<FlushQueueResponse, String> {
    let removed = state.reporting.queue().flush().map_err(|e| e.to_string())?;
    Ok(FlushQueueResponse { removed_count: removed as u32 })
}

/// submits a caller-provided envelope (typically fed straight
/// back from `GenerateUsageReport`/`GenerateLastErrorReport`). Consent is
/// re-checked here regardless of what the caller already believes (point
/// 4 of this change's implementation notes) — this is the *only* place in
/// the daemon that ever calls `SubmissionClient::submit`.
pub async fn submit_report(
    state: &DaemonState,
    report_json: &str,
) -> Result<SubmitReportResponse, String> {
    let envelope = ReportEnvelope::from_json(report_json).map_err(|e| e.to_string())?;
    envelope.validate().map_err(|e| e.to_string())?;

    let consent = state.reporting.consent_or_default();
    let allowed = match envelope.report_type {
        ReportType::Usage => consent.usage_submission_enabled,
        ReportType::Error => consent.error_submission_enabled,
    };
    if !allowed {
        return Err(
            "submission is not enabled for this report type — run `yadorilink report consent enable-usage` or `enable-error` first, or use --export instead"
                .to_string(),
        );
    }

    let report_id = uuid::Uuid::new_v4().to_string();
    let client = SubmissionClient::with_default_config().map_err(|e| e.to_string())?;
    match client.submit(&report_id, &envelope, consent.endpoint_override.as_deref()).await {
        Ok(receipt) => Ok(SubmitReportResponse {
            receipt_id: receipt.receipt_id,
            submitted_at: receipt.submitted_at,
            queued_for_retry: false,
        }),
        Err(e) if consent.queue_retry_enabled && e.is_retryable() => {
            state.reporting.queue().enqueue(envelope).map_err(|e| e.to_string())?;
            Ok(SubmitReportResponse {
                receipt_id: String::new(),
                submitted_at: String::new(),
                queued_for_retry: true,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

pub fn update_consent(
    state: &DaemonState,
    req: UpdateConsentRequest,
) -> Result<UpdateConsentResponse, String> {
    let consent_store = state.reporting.consent();
    let result = match ConsentAction::try_from(req.action) {
        Ok(ConsentAction::EnableUsage) => consent_store.opt_in_usage(),
        Ok(ConsentAction::EnableError) => consent_store.opt_in_error_reporting(),
        Ok(ConsentAction::EnableCrashReporting) => consent_store.opt_in_crash_reporting(),
        Ok(ConsentAction::DisableAll) => consent_store.disable_all_submission(),
        Ok(ConsentAction::ResetId) => consent_store.reset_reporter_id(),
        Ok(ConsentAction::SetPrompt) => {
            consent_store.set_prompt_to_report_enabled(req.bool_value.unwrap_or(false))
        }
        Ok(ConsentAction::SetQueueRetry) => {
            consent_store.set_queue_retry_enabled(req.bool_value.unwrap_or(false))
        }
        Ok(ConsentAction::SetEndpoint) => {
            let endpoint = req.string_value.filter(|s| !s.is_empty());
            consent_store.set_endpoint_override(endpoint)
        }
        Ok(ConsentAction::Unspecified) | Err(_) => {
            return Err("unspecified consent action".to_string())
        }
    };
    let consent = result.map_err(|e| e.to_string())?;
    Ok(UpdateConsentResponse { consent: Some(consent_to_proto(&consent)) })
}
