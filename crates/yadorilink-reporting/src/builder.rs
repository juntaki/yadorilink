//! Allowlist-based construction helpers (task 1.3). `UsagePayload`/
//! `ErrorPayload` already structurally forbid serializing arbitrary
//! internal state (they have no field that could hold a raw struct) —
//! these builders are the ergonomic layer on top: a fluent surface with
//! only the specific setters that correspond to allowed fields, so a
//! call site building a report reads as "here are the coarse facts I'm
//! choosing to report," not "here's my internal state, minus what I
//! remembered to strip out."

use crate::redact::{redact, redact_lines, RedactionSummary};
use crate::schema::{
    ErrorPayload, OsFamily, ReportEnvelope, ReportPayload, ReportType, UsagePayload, SCHEMA_VERSION,
};

#[derive(Debug, Clone, Default)]
pub struct UsagePayloadBuilder {
    payload: UsagePayload,
}

impl UsagePayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled_feature_flags(mut self, flags: Vec<String>) -> Self {
        self.payload.enabled_feature_flags = flags;
        self
    }

    pub fn linked_folder_count(mut self, count: u32) -> Self {
        self.payload.linked_folder_count = count;
        self
    }

    pub fn linked_folder_policy_count(mut self, policy: impl Into<String>, count: u32) -> Self {
        self.payload.linked_folder_policy_counts.insert(policy.into(), count);
        self
    }

    pub fn command_category_count(mut self, category: impl Into<String>, count: u32) -> Self {
        self.payload.command_category_counts.insert(category.into(), count);
        self
    }

    pub fn daemon_uptime_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.payload.daemon_uptime_bucket = bucket.into();
        self
    }

    pub fn sync_state_count(mut self, state: impl Into<String>, count: u32) -> Self {
        self.payload.sync_state_counts.insert(state.into(), count);
        self
    }

    pub fn error_category_count(mut self, category: impl Into<String>, count: u32) -> Self {
        self.payload.error_category_counts.insert(category.into(), count);
        self
    }

    pub fn transfer_size_bucket_count(mut self, bucket: impl Into<String>, count: u32) -> Self {
        self.payload.transfer_size_bucket_counts.insert(bucket.into(), count);
        self
    }

    pub fn latency_bucket_count(mut self, bucket: impl Into<String>, count: u32) -> Self {
        self.payload.latency_bucket_counts.insert(bucket.into(), count);
        self
    }

    pub fn peer_count_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.payload.peer_count_bucket = bucket.into();
        self
    }

    pub fn build(self) -> UsagePayload {
        self.payload
    }
}

#[derive(Debug, Clone, Default)]
pub struct ErrorPayloadBuilder {
    category: String,
    subsystem: String,
    log_lines: Vec<String>,
    backtrace: Option<String>,
}

impl ErrorPayloadBuilder {
    pub fn new(category: impl Into<String>, subsystem: impl Into<String>) -> Self {
        ErrorPayloadBuilder {
            category: category.into(),
            subsystem: subsystem.into(),
            ..Default::default()
        }
    }

    pub fn log_lines(mut self, lines: Vec<String>) -> Self {
        self.log_lines = lines;
        self
    }

    pub fn backtrace(mut self, backtrace: impl Into<String>) -> Self {
        self.backtrace = Some(backtrace.into());
        self
    }

    /// Runs the D5 denylist safety pass over every free-text field
    /// before producing the final payload — the one place in this
    /// builder where raw caller-supplied text (log lines, a backtrace)
    /// is unavoidable, and therefore the one place redaction is
    /// mandatory rather than optional.
    pub fn build(self) -> (ErrorPayload, RedactionSummary) {
        let (sanitized_log_lines, log_summary) = redact_lines(&self.log_lines);
        let (redacted_backtrace, backtrace_summary) = match self.backtrace {
            Some(bt) => {
                let (redacted, summary) = redact(&bt);
                (Some(redacted), summary)
            }
            None => (None, RedactionSummary::default()),
        };
        let mut merged = log_summary;
        for (category, count) in backtrace_summary.categories {
            match merged.categories.iter_mut().find(|(c, _)| *c == category) {
                Some((_, existing)) => *existing += count,
                None => merged.categories.push((category, count)),
            }
        }
        (
            ErrorPayload {
                error_category: self.category,
                subsystem: self.subsystem,
                sanitized_log_lines,
                redacted_backtrace,
            },
            merged,
        )
    }
}

/// Environment facts every envelope needs, gathered once at the call
/// site (typically the daemon or CLI's own `std::env::consts`/version
/// constant) and threaded through here rather than read directly by
/// this crate, so this crate stays free of any platform-detection
/// dependency of its own.
#[derive(Debug, Clone)]
pub struct ReportEnvironment {
    pub generated_at: String,
    pub yadorilink_version: String,
    pub os_family: OsFamily,
    pub os_version_bucket: String,
    pub arch: String,
    pub install_channel: Option<String>,
    pub anonymous_reporter_id: Option<String>,
}

pub fn build_usage_envelope(env: ReportEnvironment, payload: UsagePayload) -> ReportEnvelope {
    ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Usage,
        generated_at: env.generated_at,
        yadorilink_version: env.yadorilink_version,
        os_family: env.os_family,
        os_version_bucket: env.os_version_bucket,
        arch: env.arch,
        install_channel: env.install_channel,
        anonymous_reporter_id: env.anonymous_reporter_id,
        payload: ReportPayload::Usage(payload),
    }
}

/// Returns the envelope plus the redaction summary produced while
/// building the error payload, so a caller (e.g. the CLI's `--preview`)
/// can show the user what was stripped.
pub fn build_error_envelope(
    env: ReportEnvironment,
    builder: ErrorPayloadBuilder,
) -> (ReportEnvelope, RedactionSummary) {
    let (payload, summary) = builder.build();
    let envelope = ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Error,
        generated_at: env.generated_at,
        yadorilink_version: env.yadorilink_version,
        os_family: env.os_family,
        os_version_bucket: env.os_version_bucket,
        arch: env.arch,
        install_channel: env.install_channel,
        anonymous_reporter_id: env.anonymous_reporter_id,
        payload: ReportPayload::Error(payload),
    };
    (envelope, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> ReportEnvironment {
        ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: None,
            anonymous_reporter_id: None,
        }
    }

    fn doc_fixture_env() -> ReportEnvironment {
        ReportEnvironment {
            generated_at: "2026-01-01T00:00:00Z".into(),
            yadorilink_version: "0.1.0".into(),
            os_family: OsFamily::Linux,
            os_version_bucket: "24.04".into(),
            arch: "x86_64".into(),
            install_channel: Some("source".into()),
            anonymous_reporter_id: Some("anon-doc-fixture-0001".into()),
        }
    }

    fn assert_public_doc_fixture_json_is_private(json: &str) {
        let forbidden = [
            "alice",
            "taxes.pdf",
            "/Users",
            "/home",
            "C:\\Users",
            "11111111-2222-3333-4444-555555555555",
            "203.0.113.42",
            "eyJhbGciOiJIUzI1NiJ9",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "hunter2",
            "alice@example.com",
            "file_path",
            "account_id",
            "device_id",
            "group_id",
            "peer_id",
            "auth_token",
            "wireguard_key",
        ];
        for needle in forbidden {
            assert!(!json.contains(needle), "doc fixture leaked sensitive substring: {needle}");
        }
    }

    fn expected_doc_usage_report_fixture() -> ReportEnvelope {
        let payload = UsagePayloadBuilder::new()
            .enabled_feature_flags(vec![
                "on-demand-sync".to_string(),
                "content-defined-chunking".to_string(),
            ])
            .linked_folder_count(3)
            .linked_folder_policy_count("eager", 1)
            .linked_folder_policy_count("on-demand", 2)
            .command_category_count("link", 2)
            .command_category_count("status", 8)
            .daemon_uptime_bucket("1d-7d")
            .sync_state_count("synced", 12)
            .sync_state_count("conflicted", 1)
            .error_category_count("daemon_startup", 1)
            .transfer_size_bucket_count("1MiB-64MiB", 4)
            .latency_bucket_count("100ms-1s", 9)
            .peer_count_bucket("1-2")
            .build();
        build_usage_envelope(doc_fixture_env(), payload)
    }

    fn expected_doc_error_report_fixture() -> ReportEnvelope {
        let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
            .log_lines(vec![
                "failed to scan /private/tmp/taxes.pdf for report fixture".to_string(),
                concat!(
                    "peer 11111111-2222-3333-4444-555555555555 at 203.0.113.42 ",
                    "returned auth Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop"
                )
                .to_string(),
                "relay https://user:hunter2@relay.example.com reported owner alice@example.com"
                    .to_string(),
            ])
            .backtrace(concat!(
                "panicked at /Users/alice with key ",
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            ));
        let (envelope, summary) = build_error_envelope(doc_fixture_env(), builder);
        assert!(!summary.is_empty());
        envelope
    }

    #[test]
    fn usage_builder_produces_a_valid_envelope() {
        let payload = UsagePayloadBuilder::new()
            .linked_folder_count(3)
            .linked_folder_policy_count("eager", 2)
            .linked_folder_policy_count("on-demand", 1)
            .peer_count_bucket("1-2")
            .daemon_uptime_bucket("1d-7d")
            .build();
        let envelope = build_usage_envelope(env(), payload);
        envelope.validate().unwrap();
    }

    #[test]
    fn error_builder_redacts_log_lines_and_backtrace_before_returning() {
        let builder = ErrorPayloadBuilder::new("sync_conflict", "sync-core")
            .log_lines(vec!["reading /Users/alice/secret failed".to_string()])
            .backtrace("panicked at /Users/alice/project/src/main.rs:42".to_string());
        let (envelope, summary) = build_error_envelope(env(), builder);
        envelope.validate().unwrap();
        let json = envelope.to_json();
        assert!(!json.contains("alice"));
        assert!(!summary.is_empty());
    }

    #[test]
    fn error_builder_with_no_free_text_produces_an_empty_redaction_summary() {
        let builder = ErrorPayloadBuilder::new("daemon_startup", "control_socket");
        let (envelope, summary) = build_error_envelope(env(), builder);
        envelope.validate().unwrap();
        assert!(summary.is_empty());
    }

    #[test]
    fn usage_report_fixture_contains_no_private_fields() {
        let expected = expected_doc_usage_report_fixture();
        expected.validate().unwrap();
        let fixture_json = expected.to_json();
        assert_public_doc_fixture_json_is_private(&fixture_json);
    }

    #[test]
    fn error_report_fixture_contains_no_private_fields() {
        let expected = expected_doc_error_report_fixture();
        expected.validate().unwrap();
        let fixture_json = expected.to_json();
        assert!(fixture_json.contains("[REDACTED_HOME]"));
        assert!(fixture_json.contains("[REDACTED_TOKEN]"));
        assert_public_doc_fixture_json_is_private(&fixture_json);
    }
}
