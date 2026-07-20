//! CLI error taxonomy: distinct categories so the exit code and
//! message tell the user what kind of thing went wrong, not just that
//! something did.

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("not logged in — run `yadorilink login`")]
    NotLoggedIn,

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("could not reach the coordination plane: {0}")]
    CoordinationPlaneUnreachable(String),

    // A per-account quota
    // (`quota_exceeded`) or abuse budget (`rate_limited`) was hit. Distinct
    // from a coordination-plane *outage* (which is not the caller's fault and
    // is retryable by waiting) -- this is user-actionable (remove a device,
    // wait out a retry hint, or ask an operator to raise a ceiling), so it
    // carries its own exit code and is not reported as a maintainer-facing bug.
    #[error("{0}")]
    LimitExceeded(String),

    #[error("yadorilink daemon is not running — run `yadorilink daemon start`")]
    DaemonNotRunning,

    // Reserved for future peer-targeted operations (e.g. a "share a link
    // directly with device X" command); no current command path
    // constructs this yet, but the `cli` spec calls for the category to
    // exist as distinct from a general coordination-plane failure.
    #[allow(dead_code)]
    #[error("peer connectivity error: {0}")]
    PeerConnectivity(String),

    #[error("{0}")]
    Other(String),

    // Distinct from the generic `DaemonNotRunning` — this fires
    // specifically when a *reporting* command needed the daemon (the
    // report queue, or `--submit`) and it wasn't reachable, so the
    // message can explain *why* (daemon-owned storage / the one network
    // path) rather than just "start the daemon" with no context for why
    // a reporting command in particular needs it when so many other
    // reporting commands don't.
    #[error("{0}")]
    ReportingDaemonRequired(String),

    // A create/join's activate call could not be confirmed one way or the
    // other (a transport error, timeout, or 5xx from the coordination
    // plane) — the plane may already have committed the activation even
    // though this process never saw a clean response. Distinct from every
    // other error category here: the caller (`commands::share`) has
    // deliberately left the just-committed local link AND its
    // pending-enrollment marker in place rather than rolling them back, so
    // the daemon's own reconciliation sweep can resolve it (finalize to
    // Active, or clean up once the plane confirms it never landed) instead
    // of this process guessing wrong and either stranding a phantom
    // coordination-side edge or deleting a link the plane already counts.
    #[error("{0}")]
    EnrollmentPendingReconciliation(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::NotLoggedIn | CliError::AuthFailed(_) => 2,
            CliError::CoordinationPlaneUnreachable(_) => 3,
            CliError::DaemonNotRunning => 4,
            CliError::PeerConnectivity(_) => 5,
            CliError::Other(_) => 1,
            CliError::ReportingDaemonRequired(_) => 6,
            CliError::LimitExceeded(_) => 7,
            CliError::EnrollmentPendingReconciliation(_) => 8,
        }
    }

    /// Whether this failure is worth surfacing to local error reporting at
    /// all. Excludes the purely user-actionable categories (not logged in,
    /// bad credentials, daemon not started) where the next step is already
    /// obvious from the error message itself and a maintainer-facing
    /// report would add noise, not signal; includes categories more likely
    /// to indicate a real environment/connectivity/bug condition worth a
    /// maintainer seeing.
    pub fn is_reportable(&self) -> bool {
        matches!(
            self,
            CliError::CoordinationPlaneUnreachable(_)
                | CliError::PeerConnectivity(_)
                | CliError::Other(_)
                | CliError::EnrollmentPendingReconciliation(_)
        )
    }

    /// A coarse, stable category label for this error, used as the
    /// `error_category` field of a candidate created by
    /// `commands::report::handle_reportable_error` — never the raw
    /// message (that goes in `log_lines`, already redacted).
    pub fn report_category(&self) -> &'static str {
        match self {
            CliError::NotLoggedIn => "cli_not_logged_in",
            CliError::AuthFailed(_) => "cli_auth_failed",
            CliError::CoordinationPlaneUnreachable(_) => "cli_coordination_plane_unreachable",
            CliError::DaemonNotRunning => "cli_daemon_not_running",
            CliError::PeerConnectivity(_) => "cli_peer_connectivity",
            CliError::Other(_) => "cli_command_failed",
            CliError::ReportingDaemonRequired(_) => "cli_reporting_daemon_required",
            CliError::LimitExceeded(_) => "cli_limit_exceeded",
            CliError::EnrollmentPendingReconciliation(_) => "cli_enrollment_pending_reconciliation",
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            CliError::DaemonNotRunning
        } else {
            CliError::Other(e.to_string())
        }
    }
}

// Unrelated hotfix: `commands/diagnose.rs`'s `preview`/`export` (from a
// separately-committed "cli diagnostics fallback" change) use `?` on
// `serde_json::to_string_pretty`, which needs this conversion and was
// missing it, breaking `cargo build --workspace` for every crate
// downstream of `yadorilink-cli`. Minimal, same-shape fix as every other
// blanket conversion here.
impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Other(e.to_string())
    }
}
