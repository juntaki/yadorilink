//! Shared report schema, redaction, consent, and queue types for
//! YadoriLink's opt-in OSS usage/error reporting (design.md at
//! `openspec/changes/add-oss-usage-error-reporting/`). This crate holds
//! only the shared shape and safety logic — actual persistence (config
//! storage, the on-disk queue) lives in `yadorilink-daemon`, and the
//! optional HTTPS submission client is a separate concern layered on
//! top of `schema::ReportEnvelope`.
//!
//! `schema`, `consent`, `queue`, `redact`, and `builder` deliberately
//! depend on nothing daemon/CLI-specific (no `tokio`, no filesystem
//! access, no clock): every function there is a pure transformation
//! over caller-supplied data, which is what makes the privacy
//! properties in `redact` and `schema::ReportEnvelope::validate`
//! testable in isolation.
//!
//! `submission` is the one exception: it's the optional HTTPS
//! submission client (design.md D6), so it necessarily depends on a
//! minimal-feature `tokio` + `reqwest` for real async I/O — but it's
//! still self-contained, taking only a `&ReportEnvelope` and a plain
//! `Option<&str>` endpoint, with no daemon/CLI/sync/auth types reachable
//! from it.

pub mod builder;
pub mod consent;
pub mod diagnostics;
pub mod queue;
pub mod redact;
pub mod schema;
pub mod submission;

pub use builder::{
    build_error_envelope, build_usage_envelope, ErrorPayloadBuilder, ReportEnvironment,
    UsagePayloadBuilder,
};
pub use consent::ConsentState;
pub use diagnostics::{
    diagnostics_summary_count, redact_diagnostics_text, redact_diagnostics_value,
};
pub use queue::{QueuedReportMetadata, RetentionPolicy, SubmissionReceipt};
pub use redact::{redact, redact_lines, RedactionCategory, RedactionSummary};
pub use schema::{
    ErrorPayload, OsFamily, ReportEnvelope, ReportPayload, ReportType, UsagePayload,
    ValidationError, MAX_REPORT_BYTES, SCHEMA_VERSION,
};
pub use submission::{SubmissionClient, SubmissionConfig, SubmissionError};
