//! CLI diagnostics bundle preview/export.
//!
//! Prefers the real daemon-assembled bundle (`control_client::send`'s
//! `DiagnosticsPreview`/`DiagnosticsExport`, answered by
//! `yadorilink-daemon::diagnostics_ipc::build_bundle`) whenever the daemon
//! is reachable — it has access to daemon-owned status/config/recent-error
//! state this CLI process never reads directly, so daemon-owned state
//! files do not need to be read directly by the CLI. Falls back to
//! `limited_bundle()`
//! (the original CLI-only bundle) only when the daemon itself isn't
//! reachable at all (`CliError::DaemonNotRunning`) — any other daemon-side
//! failure (a malformed response, a genuine `RespPayload::Error`) is
//! propagated rather than silently masked by the fallback, so a real
//! daemon-side bug doesn't just look like "daemon unavailable" to the user.

use std::path::PathBuf;

use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DiagnosticsExportRequest, DiagnosticsPreviewRequest};
use yadorilink_reporting::redact_diagnostics_value;

use crate::control_client;
use crate::error::CliError;

/// Which request variant to send — `Preview`/`Export` both hit the exact
/// same daemon-side assembly (`DiagnosticsBundleResponse` is shared, see
/// `daemon_control.proto`'s doc comment); only the CLI-side disposition of
/// the result differs (print vs write to a file).
enum BundleRequest {
    Preview,
    Export,
}

/// Fetches a diagnostics bundle plus a human-readable label describing
/// where it came from — `"daemon"` / `"daemon-partial"` (task 2.3's
/// bounded-generation fallback) when the daemon answered, or
/// `"cli-only-fallback"` when it wasn't reachable at all.
async fn collect_bundle(request: BundleRequest) -> Result<(Value, usize, String), CliError> {
    let payload = match request {
        BundleRequest::Preview => ReqPayload::DiagnosticsPreview(DiagnosticsPreviewRequest {}),
        BundleRequest::Export => ReqPayload::DiagnosticsExport(DiagnosticsExportRequest {}),
    };
    match control_client::send(payload).await {
        Ok(resp) => {
            let bundle = match resp.payload {
                Some(RespPayload::DiagnosticsPreview(b))
                | Some(RespPayload::DiagnosticsExport(b)) => b,
                _ => return Err(CliError::Other("unexpected daemon response".into())),
            };
            let mut value: Value = serde_json::from_str(&bundle.bundle_json)?;
            // Mirrors `limited_bundle()`'s own `daemon.collection_mode`
            // field below, so a caller inspecting the written/printed
            // bundle sees one consistent place ("daemon.collection_mode")
            // to check the provenance of *any* bundle this command can
            // produce, daemon-backed or CLI-only fallback alike.
            if let Some(daemon_obj) = value.get_mut("daemon").and_then(Value::as_object_mut) {
                daemon_obj.insert("collection_mode".to_string(), json!(bundle.collection_mode));
            }
            let count = bundle.redaction_summary.iter().map(|c| c.count as usize).sum();
            Ok((value, count, bundle.collection_mode))
        }
        // Daemon simply isn't running/reachable at all — fall back to the
        // limited CLI-only bundle (spec "Daemon unavailable fallback")
        // rather than failing the command outright.
        Err(CliError::DaemonNotRunning) => {
            let (bundle, count) = limited_bundle();
            Ok((bundle, count, "cli-only-fallback".to_string()))
        }
        // Any other failure (a decode error, a genuine
        // `RespPayload::Error`) is a real problem worth surfacing, not
        // something the fallback should paper over.
        Err(e) => Err(e),
    }
}

fn included_summary(collection_mode: &str) -> &'static str {
    match collection_mode {
        "daemon" => {
            "daemon-assembled bundle: status, links, recent errors, updates, resources, environment"
        }
        "daemon-partial" => {
            "daemon-assembled bundle (partial: generation hit its bounded time budget)"
        }
        _ => "schema/build/platform metadata, CLI daemon-unavailable fallback state",
    }
}

pub async fn preview() -> Result<(), CliError> {
    let (bundle, redaction_count, collection_mode) = collect_bundle(BundleRequest::Preview).await?;
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    println!();
    println!("Included: {}", included_summary(&collection_mode));
    println!("Redaction categories matched: {redaction_count}");
    Ok(())
}

pub async fn export(path: PathBuf) -> Result<(), CliError> {
    let (bundle, redaction_count, collection_mode) = collect_bundle(BundleRequest::Export).await?;
    let contents = serde_json::to_string_pretty(&bundle)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, contents)?;
    println!("Wrote diagnostics bundle to {}", path.display());
    println!("Included: {}", included_summary(&collection_mode));
    println!("Redaction categories matched: {redaction_count}");
    Ok(())
}

fn limited_bundle() -> (Value, usize) {
    let bundle = json!({
        "schema_version": 1,
        "generated_at": "unknown",
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH
        },
        "daemon": {
            "reachable": false,
            "collection_mode": "cli-only-fallback"
        },
        "links": [],
        "recent_errors": [],
        "updates": {
            "state": "unknown"
        },
        "resources": {
            "disk_state": "unknown",
            "limits": "unknown"
        },
        "environment": {
            "install_channel": "unknown"
        },
        "redaction": {
            "version": 1,
            "pseudonymized_fields": []
        }
    });

    let (redacted, summary) = redact_diagnostics_value(&bundle);
    let count = summary.categories.iter().map(|(_, count)| *count).sum();
    (redacted, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limited_bundle_has_required_top_level_fields() {
        let (bundle, _) = limited_bundle();
        for key in [
            "schema_version",
            "generated_at",
            "yadorilink_version",
            "platform",
            "daemon",
            "links",
            "recent_errors",
            "updates",
            "resources",
            "environment",
            "redaction",
        ] {
            assert!(bundle.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(bundle["daemon"]["reachable"], false);
    }
}
