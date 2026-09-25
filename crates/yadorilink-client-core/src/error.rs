//! What a client operation can fail with.
//!
//! [`CoreError`] is lossless: it keeps every category a front end needs to
//! choose an exit code, a banner or a retry, and carries the daemon's typed
//! command errors instead of flattening them to text. Each front end maps it
//! onto its own presentation (the command-line tool keeps its historical
//! messages and exit codes); nothing here decides how an error is shown.

use yadorilink_fapi_client::store::StoreError;
use yadorilink_ipc_proto::daemonctl::{ApplicationCommandError, ApplicationErrorCode};

/// Which coordination-plane limit a [`CoreError::LimitExceeded`] hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// A per-account quota (`quota_exceeded`): remove something first, or
    /// ask an operator to raise the ceiling.
    Quota,
    /// An abuse budget (`rate_limited`): wait and retry.
    RateLimited,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Nobody has signed in on this machine.
    #[error("not logged in — run `yadorilink login`")]
    NotLoggedIn,

    /// A credential store that exists and cannot be used. Deliberately not
    /// folded into [`CoreError::NotLoggedIn`]: signing in again would succeed
    /// and leave the damaged store in place, so the remedy is the store, and
    /// the store's own message names it.
    #[error("{0}")]
    CredentialStore(#[from] StoreError),

    /// The coordination plane (or the Authorization Server) refused this
    /// installation's session.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// The coordination plane answered 403: the session is valid but not
    /// allowed to do this.
    #[error("{0}")]
    Forbidden(String),

    #[error("could not reach the coordination plane: {0}")]
    CoordinationPlaneUnreachable(String),

    /// A quota or rate limit was hit; user-actionable rather than an outage.
    #[error("{message}")]
    LimitExceeded { message: String, kind: LimitKind },

    #[error("yadorilink daemon is not running — run `yadorilink daemon start`")]
    DaemonNotRunning,

    /// The daemon's control socket did not accept, or a quick request got no
    /// answer, within its deadline: the daemon is running but wedged.
    #[error("yadorilink daemon is not responding")]
    DaemonUnresponsive,

    /// The daemon speaks a different control-protocol generation. Pre-release
    /// binaries are one release unit, so this is refused rather than decoded
    /// with protobuf's missing-field defaults.
    #[error(
        "client/daemon protocol version mismatch (client {client}, daemon {daemon}); run matching \
         YadoriLink binaries"
    )]
    DaemonProtocolMismatch { client: u32, daemon: u32 },

    /// The daemon answered the request with a plain error message.
    #[error("{0}")]
    DaemonRejected(String),

    /// The daemon refused an application command with a typed error. This
    /// is the only form of every daemon command refusal, including a create
    /// or join whose activation could not be confirmed
    /// (`ApplicationErrorCode::ActivationAmbiguous`, which the daemon's
    /// reconciliation sweep resolves): match on `code`.
    #[error("{message}")]
    DaemonCommand {
        code: ApplicationErrorCode,
        message: String,
        group_ids: Vec<String>,
        operation_id: Option<String>,
    },

    /// The operation would leave a folder group without a confirmed-ready
    /// full replica, and was refused before anything changed.
    #[error("{message}")]
    DurabilityBlocked { message: String, group_ids: Vec<String> },

    /// An argument was refused before any request was made.
    #[error("{0}")]
    InvalidInput(String),

    #[error("{0}")]
    Io(String),

    #[error("{0}")]
    Other(String),
}

impl CoreError {
    /// The typed form of a daemon application-command refusal. An error code
    /// this build does not know reads as `Unspecified` rather than failing.
    #[must_use]
    pub fn from_command_error(error: ApplicationCommandError) -> Self {
        CoreError::DaemonCommand {
            code: ApplicationErrorCode::try_from(error.code)
                .unwrap_or(ApplicationErrorCode::Unspecified),
            message: error.message,
            group_ids: error.group_ids,
            operation_id: (!error.operation_id.is_empty()).then_some(error.operation_id),
        }
    }

    /// Whether this is a daemon command refusal carrying `code`.
    #[must_use]
    pub fn is_command_error(&self, code: ApplicationErrorCode) -> bool {
        matches!(self, CoreError::DaemonCommand { code: actual, .. } if *actual == code)
    }
}

/// The credential manager's failures, classified.
///
/// `NotEnrolled` ("nobody has signed in here") and `Store` ("there is a
/// credential and it cannot be used") are kept apart because their remedies
/// are opposite. Everything a refresh can fail with lands under one of the two
/// remote categories rather than under `Other`.
impl From<yadorilink_fapi_client::Error> for CoreError {
    fn from(e: yadorilink_fapi_client::Error) -> Self {
        use yadorilink_fapi_client::Error as FapiError;
        match e {
            FapiError::NotEnrolled => CoreError::NotLoggedIn,
            FapiError::Store(store) => CoreError::CredentialStore(store),
            FapiError::Http(_) => CoreError::CoordinationPlaneUnreachable(e.to_string()),
            // A refused refresh is a refused session: the registration was
            // revoked, the refresh token was replayed and took the grant family
            // with it, or the clock is wrong. All three are answered by signing
            // in again, not by retrying.
            FapiError::Response { status: 400 | 401 | 403, .. } => {
                CoreError::AuthFailed(e.to_string())
            }
            FapiError::Response { status: 429 | 500..=599, .. } => {
                CoreError::CoordinationPlaneUnreachable(e.to_string())
            }
            other => CoreError::Other(other.to_string()),
        }
    }
}

/// A missing or refusing control socket means the daemon is not running;
/// every other I/O failure keeps its own message.
impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            CoreError::DaemonNotRunning
        } else {
            CoreError::Io(e.to_string())
        }
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Other(e.to_string())
    }
}

/// Why the daemon could not be asked.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonUnavailableReason {
    NotRunning,
    /// Running but not answering in time: starting it again cannot help.
    Unresponsive,
    ProtocolMismatch {
        client_version: u32,
        daemon_version: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum NetworkErrorKind {
    Unreachable,
    RateLimited,
    /// A create or join whose activation could not be confirmed; the daemon
    /// settles it on its own.
    ActivationPendingReconciliation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PermissionDeniedReason {
    /// The coordination plane refused this installation's session; signing
    /// in again is the remedy.
    SessionRejected,
    Forbidden,
    QuotaExceeded,
    /// The credential store exists and cannot be used; signing in again
    /// would leave it damaged.
    CredentialStoreUnusable,
}

/// The one error a desktop front end sees. Seven cases, each with a typed
/// reason to branch on; `message` is diagnostic English for a details view
/// or tooltip, never primary copy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(uniffi::Error))]
pub enum DesktopError {
    #[error("{message}")]
    NotSignedIn { message: String },
    #[error("{message}")]
    DaemonUnavailable { message: String, reason: DaemonUnavailableReason },
    #[error("{message}")]
    Network { message: String, kind: NetworkErrorKind },
    #[error("{message}")]
    PermissionDenied { message: String, reason: PermissionDeniedReason },
    /// Refused because a folder group would be left without a confirmed
    /// complete copy. `can_force` says whether calling again with `force`
    /// is offered for this operation.
    #[error("{message}")]
    DurabilityBlocked {
        message: String,
        group_ids: Vec<String>,
        operation_id: Option<String>,
        can_force: bool,
    },
    #[error("{message}")]
    InvalidInput { message: String, field: Option<String> },
    #[error("{message}")]
    Internal { message: String, category: String },
}

impl DesktopError {
    /// Maps a client error onto the desktop taxonomy. `can_force` is set by
    /// the few operations that accept a `force` override and were called
    /// without it; it only matters for a durability refusal.
    #[must_use]
    pub fn from_core(error: CoreError, can_force: bool) -> Self {
        let message = error.to_string();
        match error {
            CoreError::NotLoggedIn => DesktopError::NotSignedIn { message },
            CoreError::DaemonNotRunning => DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::NotRunning,
            },
            CoreError::DaemonUnresponsive => DesktopError::DaemonUnavailable {
                message,
                reason: DaemonUnavailableReason::Unresponsive,
            },
            CoreError::DaemonProtocolMismatch { client, daemon } => {
                DesktopError::DaemonUnavailable {
                    message,
                    reason: DaemonUnavailableReason::ProtocolMismatch {
                        client_version: client,
                        daemon_version: daemon,
                    },
                }
            }
            CoreError::CoordinationPlaneUnreachable(_) => {
                DesktopError::Network { message, kind: NetworkErrorKind::Unreachable }
            }
            CoreError::LimitExceeded { kind: LimitKind::RateLimited, .. } => {
                DesktopError::Network { message, kind: NetworkErrorKind::RateLimited }
            }
            CoreError::LimitExceeded { kind: LimitKind::Quota, .. } => {
                denied(message, PermissionDeniedReason::QuotaExceeded)
            }
            CoreError::AuthFailed(_) => denied(message, PermissionDeniedReason::SessionRejected),
            CoreError::Forbidden(_) => denied(message, PermissionDeniedReason::Forbidden),
            CoreError::CredentialStore(_) => {
                denied(message, PermissionDeniedReason::CredentialStoreUnusable)
            }
            CoreError::DurabilityBlocked { group_ids, .. } => DesktopError::DurabilityBlocked {
                message,
                group_ids,
                operation_id: None,
                can_force,
            },
            CoreError::InvalidInput(_) => DesktopError::InvalidInput { message, field: None },
            CoreError::DaemonCommand { code, group_ids, operation_id, .. } => {
                from_command(code, message, group_ids, operation_id, can_force)
            }
            CoreError::DaemonRejected(_) | CoreError::Io(_) | CoreError::Other(_) => {
                DesktopError::Internal { message, category: "cli_command_failed".to_owned() }
            }
        }
    }

    /// An argument refused before any request, naming the argument.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>, field: &str) -> Self {
        DesktopError::InvalidInput { message: message.into(), field: Some(field.to_owned()) }
    }

    /// Whether this is the daemon being unreachable.
    #[must_use]
    pub fn is_daemon_unavailable(&self) -> bool {
        matches!(self, DesktopError::DaemonUnavailable { .. })
    }
}

fn denied(message: String, reason: PermissionDeniedReason) -> DesktopError {
    DesktopError::PermissionDenied { message, reason }
}

/// A typed daemon command refusal, sorted by what a person can do about it.
fn from_command(
    code: ApplicationErrorCode,
    message: String,
    group_ids: Vec<String>,
    operation_id: Option<String>,
    can_force: bool,
) -> DesktopError {
    use ApplicationErrorCode as Code;
    match code {
        // The daemon has no local identity: this device was never registered,
        // and setup is where that is fixed.
        Code::LocalIdentityUnavailable => DesktopError::NotSignedIn { message },
        Code::CoordinationTransport | Code::CoordinationAmbiguous | Code::TicketUnavailable => {
            DesktopError::Network { message, kind: NetworkErrorKind::Unreachable }
        }
        Code::ActivationAmbiguous => DesktopError::Network {
            message,
            kind: NetworkErrorKind::ActivationPendingReconciliation,
        },
        Code::CoordinationRejected | Code::ActivationRejected | Code::PreparationRejected => {
            denied(message, PermissionDeniedReason::Forbidden)
        }
        Code::ReplicaNotReady | Code::DurabilityLatchFailed | Code::RecoveryPending => {
            DesktopError::DurabilityBlocked { message, group_ids, operation_id, can_force }
        }
        Code::TargetNotFound => DesktopError::InvalidInput { message, field: None },
        Code::Unspecified
        | Code::Persistence
        | Code::LocalLinkFailed
        | Code::CompensationPending
        | Code::OperationConflict
        | Code::RecoveryJournalUnavailable => {
            DesktopError::Internal { message, category: command_category(code) }
        }
    }
}

/// `daemon_command_<code>`, from the protocol's own name for the code.
fn command_category(code: ApplicationErrorCode) -> String {
    let name = code.as_str_name();
    let short = name.strip_prefix("APPLICATION_ERROR_CODE_").unwrap_or(name);
    format!("daemon_command_{}", short.to_ascii_lowercase())
}

impl From<CoreError> for DesktopError {
    fn from(error: CoreError) -> Self {
        DesktopError::from_core(error, false)
    }
}

#[cfg(test)]
mod tests;
