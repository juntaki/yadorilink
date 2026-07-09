//! Daemon-side handlers for the diagnostics IPC surface added to
//! `daemon_control.proto`. Kept in its own module, mirroring
//! `reporting_ipc.rs`/`update_ipc.rs`'s precedent, rather than inlined
//! into `control_socket.rs`'s match arms.
//!
//! Bundle assembly deliberately reuses existing daemon state readers
//! (`control_socket::list_link_statuses`/`volumes_free_space`/
//! `health_snapshot`, `update_ipc::status_response`, the reporting error-
//! candidate store) rather than re-deriving them a second way: the goal
//! is to export through the daemon so daemon-owned state files do not
//! need to be read directly by the CLI. Redaction is likewise never
//! reimplemented here: every assembled bundle, including the bounded-
//! timeout fallback, is passed through `yadorilink_reporting::
//! redact_diagnostics_value` (the same daemon-independent helper
//! `yadorilink-cli`'s CLI-only fallback bundle already uses) before it
//! ever leaves this module.
//!
//! Bounded generation time and failure handling: bundle assembly runs on
//! a `spawn_blocking` worker thread (mirroring `hydration.rs`'s "move
//! synchronous I/O off the tokio worker" precedent for `BlockStore::put`),
//! wrapped in `tokio::time::timeout` (`hydration::hydrate_with_timeout`'s
//! own established pattern) so a slow or stuck sub-collection (e.g. an
//! unexpectedly large number of files/links to walk) can never hang the
//! control-socket connection -- the caller always gets a response within
//! `DIAGNOSTICS_BUNDLE_TIMEOUT`, either the real bundle or a minimal,
//! still schema-valid `"daemon-partial"` fallback.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use yadorilink_ipc_proto::daemonctl::{DiagnosticsBundleResponse, RedactionCategoryCount};
use yadorilink_reporting::schema::ReportPayload;

use crate::daemon_state::DaemonState;

/// The overall time budget for one bundle-assembly call.
/// Chosen to match `PER_BLOCK_FETCH_TIMEOUT` (`hydration.rs`) -- long
/// enough for a large number of links/files to be walked even on a
/// loaded daemon, short enough that a CLI `diagnose preview`/`export`
/// never appears to hang. Every sub-collection this module performs is
/// local (in-memory state or local disk stat calls, never network I/O),
/// so 5 seconds is generous, not tight.
const DIAGNOSTICS_BUNDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many recent error candidates to summarize in the bundle -- mirrors
/// `folder_ops::AFFECTED_PATHS_SAMPLE_LIMIT`'s "bounded sample, not the
/// full set" convention; a diagnostics bundle is a support artifact, not
/// a full audit log.
const RECENT_ERRORS_SAMPLE_LIMIT: usize = 5;

/// `yadorilink diagnose preview`/`export` (daemon-backed path): both
/// request the exact same assembled-and-redacted bundle -- see this
/// module's doc comment and `daemon_control.proto`'s
/// `DiagnosticsBundleResponse` doc comment for why preview/export share
/// one response shape.
pub async fn build_bundle(state: &Arc<DaemonState>) -> DiagnosticsBundleResponse {
    let assemble_state = state.clone();
    run_bounded(DIAGNOSTICS_BUNDLE_TIMEOUT, move || assemble_bundle_sync(&assemble_state)).await
}

/// The actual bound: runs `work` on a `spawn_blocking` thread and gives
/// it `timeout` to finish. A `work` closure that never returns (the
/// "stuck sub-collection" case) leaves its thread running in the
/// background -- synchronous code can't be forcibly preempted -- but the
/// control socket itself always gets an answer by `timeout`, which is
/// the actual guarantee here ("cannot hang indefinitely").
async fn run_bounded(
    timeout: Duration,
    work: impl FnOnce() -> serde_json::Value + Send + 'static,
) -> DiagnosticsBundleResponse {
    let outcome = tokio::time::timeout(timeout, tokio::task::spawn_blocking(work)).await;
    let (bundle, collection_mode) = match outcome {
        Ok(Ok(bundle)) => (bundle, "daemon"),
        Ok(Err(join_err)) => {
            tracing::warn!(error = %join_err, "diagnostics bundle assembly task panicked");
            (timeout_fallback_bundle(), "daemon-partial")
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                "diagnostics bundle generation exceeded its time budget; returning a partial bundle"
            );
            (timeout_fallback_bundle(), "daemon-partial")
        }
    };
    finish_response(bundle, collection_mode)
}

/// Redacts the assembled bundle and packages it into the wire response --
/// shared by the happy path and the bounded-timeout fallback, since both
/// must go through the exact same redaction pass (idempotent, so
/// redacting the already-minimal fallback is harmless).
fn finish_response(bundle: serde_json::Value, collection_mode: &str) -> DiagnosticsBundleResponse {
    let (redacted, summary) = yadorilink_reporting::redact_diagnostics_value(&bundle);
    let redaction_summary = summary
        .categories
        .iter()
        .map(|(category, count)| RedactionCategoryCount {
            category: format!("{category:?}"),
            count: *count as u32,
        })
        .collect();
    DiagnosticsBundleResponse {
        bundle_json: serde_json::to_string_pretty(&redacted).unwrap_or_else(|_| "{}".to_string()),
        redaction_summary,
        collection_mode: collection_mode.to_string(),
    }
}

/// The real, happy-path bundle -- synchronous by construction (every
/// reader it calls into is itself synchronous), run inside `run_bounded`'s
/// `spawn_blocking` worker. Shape matches the diagnostics bundle schema.
fn assemble_bundle_sync(state: &DaemonState) -> serde_json::Value {
    let links = crate::control_socket::list_link_statuses(state).unwrap_or_default();
    let health = crate::control_socket::health_snapshot(state);
    let volumes = crate::control_socket::volumes_free_space(state, &links);
    let governance = state.governance_config.load_or_default();
    let update_status = crate::update_ipc::status_response(state);
    let install_channel = state.update_manager.platform_info().install_source.clone();

    let bundle_links: Vec<serde_json::Value> = links
        .iter()
        .enumerate()
        .map(|(i, link)| {
            let state_label = if link.degraded {
                "degraded"
            } else if link.paused {
                "paused"
            } else if link.conflict_count > 0 {
                "conflict"
            } else {
                "synced"
            };
            let (path, _) = yadorilink_reporting::redact_diagnostics_text(&link.local_path);
            json!({
                // Sequential, per-bundle pseudonyms -- not a hash of the
                // real group_id/local_path -- deliberately, to give
                // "stable pseudonymous IDs ... over category-level
                // context" so a support engineer can tell "link 1" apart
                // from "link 2" across the *same* bundle's
                // `links`/`recent_errors` sections without ever seeing the
                // real identifier.
                "link_id": format!("link:{:03}", i + 1),
                "group_id": format!("group:{:03}", i + 1),
                "state": state_label,
                "path": path,
            })
        })
        .collect();

    let task_health: Vec<serde_json::Value> = health
        .tasks
        .iter()
        .map(|t| json!({ "name": t.name, "state": if t.alive { "running" } else { "stopped" } }))
        .collect();

    let disk_state = worst_volume_state(volumes.iter().map(|v| v.state.as_str()));
    let limits_state = if governance.upload_limit_bytes_per_sec == 0
        && governance.download_limit_bytes_per_sec == 0
    {
        "unlimited"
    } else {
        "limited"
    };

    json!({
        "schema_version": 1,
        "generated_at": crate::reporting::time::now_rfc3339(),
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH,
        },
        "daemon": {
            "reachable": true,
            "uptime_bucket": uptime_bucket(state.uptime()),
            "task_health": task_health,
        },
        "links": bundle_links,
        "recent_errors": recent_error_entries(state),
        "updates": {
            "state": update_status.state,
            "channel": update_status.channel,
            "available_version": update_status.available_version,
            "mandatory": update_status.mandatory,
            "holdback_reason": update_status.holdback_reason,
        },
        "resources": {
            "disk_state": disk_state,
            "limits": limits_state,
        },
        "environment": {
            "install_channel": install_channel,
        },
        "redaction": {
            "version": 1,
            "pseudonymized_fields": ["link_id", "group_id", "path"],
        },
    })
}

/// The fallback shape: a minimal bundle that still satisfies diagnostics
/// bundle required top-level keys, used whenever `run_bounded` can't
/// produce the real one in time (or the assembly task panicked). Its one
/// `recent_errors` entry is synthesized here, not read from the
/// error-candidate store, precisely so the user/support engineer can see
/// that generation was incomplete rather than silently getting an
/// empty-looking-but-actually-fine bundle.
fn timeout_fallback_bundle() -> serde_json::Value {
    let now = crate::reporting::time::now_rfc3339();
    json!({
        "schema_version": 1,
        "generated_at": now,
        "yadorilink_version": env!("CARGO_PKG_VERSION"),
        "platform": {
            "os_family": std::env::consts::OS,
            "os_version_bucket": "unknown",
            "arch": std::env::consts::ARCH,
        },
        "daemon": {
            "reachable": true,
            "uptime_bucket": "unknown",
            "task_health": [],
        },
        "links": [],
        "recent_errors": [
            {
                "category": "diagnostics_generation_incomplete",
                "timestamp": now,
                "context": "one or more diagnostics sub-collections did not complete within the bundle generation time budget",
            }
        ],
        "updates": { "state": "unknown" },
        "resources": { "disk_state": "unknown", "limits": "unknown" },
        "environment": { "install_channel": "unknown" },
        "redaction": { "version": 1, "pseudonymized_fields": [] },
    })
}

/// Coarse "how long has this daemon been running" bucket, reusing the
/// exact bucket labels `UsagePayload.daemon_uptime_bucket`'s doc comment
/// already establishes for this same concept elsewhere in this codebase
/// (`yadorilink-reporting::schema::UsagePayload`), rather than inventing a
/// second, differently-labeled bucket set for what is conceptually the
/// same measurement.
fn uptime_bucket(uptime: Duration) -> &'static str {
    match uptime.as_secs() {
        0..=3599 => "<1h",
        3600..=86_399 => "1h-1d",
        86_400..=604_799 => "1d-7d",
        _ => ">7d",
    }
}

/// Worst-case classification across every volume `StatusResponse.volumes`
/// reports (using the same `"ok" | "low" | "critical"` convention) --
/// "unknown" when there's nothing to classify (no links, no block-store
/// volume resolvable).
fn worst_volume_state<'a>(states: impl Iterator<Item = &'a str>) -> &'static str {
    let mut saw_any = false;
    let mut worst = "ok";
    for state in states {
        saw_any = true;
        if state == "critical" {
            return "critical";
        }
        if state == "low" {
            worst = "low";
        }
    }
    if !saw_any {
        return "unknown";
    }
    worst
}

/// Recent error categories/timestamps/context (the "recent errors"
/// bundle section), sourced from the same error-candidate store
/// `reporting_ipc::generate_last_error_report` already reads. A
/// dedicated recent-error ring buffer hadn't landed yet at the time this
/// was written, so this reuses the existing error-candidate store as the
/// best available "recent errors" source rather than blocking on that.
fn recent_error_entries(state: &DaemonState) -> Vec<serde_json::Value> {
    let candidates = state.reporting.error_candidates();
    let Ok(metas) = candidates.list() else { return Vec::new() };
    metas
        .into_iter()
        .rev() // newest first -- `list()` returns oldest-first (entry_store's on-disk scan order)
        .take(RECENT_ERRORS_SAMPLE_LIMIT)
        .filter_map(|meta| {
            let envelope = candidates.show(&meta.report_id).ok().flatten()?;
            let ReportPayload::Error(err) = envelope.payload else { return None };
            Some(json!({
                "category": err.error_category,
                "timestamp": envelope.generated_at,
                "context": err.subsystem,
            }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    use super::*;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    /// Diagnostics-specific redaction: a link whose local path carries a
    /// real home-directory fragment must never appear verbatim in the
    /// daemon-assembled bundle -- proves the daemon-side assembly
    /// actually calls into `yadorilink_reporting`'s redaction helpers,
    /// not just that the CLI-only fallback does (already covered by
    /// `yadorilink-reporting::diagnostics`'s own tests).
    #[tokio::test]
    async fn daemon_bundle_redacts_a_real_linked_folder_path() {
        let state = test_state();
        state
            .sync_state
            .add_link(
                "/Users/alice/Documents/secret-project",
                "11111111-2222-3333-4444-555555555555",
            )
            .unwrap();

        let resp = build_bundle(&state).await;

        assert_eq!(resp.collection_mode, "daemon");
        assert!(!resp.bundle_json.contains("/Users/alice"));
        assert!(!resp.bundle_json.contains("alice"));
        assert!(!resp.bundle_json.contains("secret-project"));
        assert!(!resp.bundle_json.contains("11111111-2222-3333-4444-555555555555"));
        // Required diagnostics bundle schema keys are present.
        let parsed: serde_json::Value = serde_json::from_str(&resp.bundle_json).unwrap();
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
            assert!(parsed.get(key).is_some(), "missing bundle key {key}");
        }
        // A stable, non-raw pseudonym stands in for the real identifiers.
        assert!(resp.bundle_json.contains("link:001"));
    }

    /// Bundle generation is bounded -- even if the underlying
    /// sub-collection work is stuck (simulated here with a `thread::sleep`
    /// well longer than the timeout, standing in for e.g. an unexpectedly
    /// huge link/file walk), `run_bounded` still returns within its
    /// timeout, not after the stuck work eventually finishes.
    ///
    /// Deliberately uses a bounded (2s), not unbounded/hours-long,
    /// `thread::sleep` for the injected stuck-collection stand-in: a
    /// `spawn_blocking` OS thread can't be cancelled once started, and
    /// tokio's own runtime teardown (which every `#[tokio::test]` performs
    /// when the test function returns) waits for outstanding blocking
    /// tasks to actually finish before the process can proceed -- an
    /// earlier version of this test used `Duration::from_secs(3600)` here
    /// and, while `run_bounded`'s *return* was still correctly bounded by
    /// `short_timeout`, the test binary itself then hung for up to an hour
    /// at teardown waiting for that detached thread, which defeats the
    /// entire point of this task. 2s is still far longer than
    /// `short_timeout` (proving the bound), while keeping this test's
    /// total wall-clock cost small.
    #[tokio::test]
    async fn bundle_generation_is_bounded_even_if_a_sub_collection_hangs() {
        let state = test_state();
        let short_timeout = Duration::from_millis(150);
        let assemble_state = state.clone();

        let started = Instant::now();
        let resp = run_bounded(short_timeout, move || {
            // Stands in for a sub-collection that doesn't return in time
            // (e.g. a huge log/file scan) -- well longer than
            // `short_timeout`, so this proves the *caller* doesn't wait
            // for it, not merely that the closure itself is slow.
            std::thread::sleep(Duration::from_secs(2));
            assemble_bundle_sync(&assemble_state)
        })
        .await;
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(800),
            "build_bundle must return promptly once its timeout elapses, not wait for the \
             stuck sub-collection to finish (which sleeps for 2s); took {elapsed:?}"
        );
        assert_eq!(resp.collection_mode, "daemon-partial");
        let parsed: serde_json::Value = serde_json::from_str(&resp.bundle_json).unwrap();
        assert!(
            parsed.get("schema_version").is_some(),
            "fallback bundle must still be schema-valid"
        );
    }

    /// The mirror case: well within budget, generation completes normally
    /// and reports `"daemon"`, not `"daemon-partial"`.
    #[tokio::test]
    async fn bundle_generation_reports_full_daemon_mode_when_not_bounded() {
        let state = test_state();
        let resp = build_bundle(&state).await;
        assert_eq!(resp.collection_mode, "daemon");
    }
}
