#![cfg(test)]

use super::*;

fn command_error(code: i32, operation_id: &str) -> ApplicationCommandError {
    ApplicationCommandError {
        code,
        message: "refused".into(),
        group_ids: vec!["group-1".into()],
        operation_id: operation_id.into(),
    }
}

#[test]
fn a_command_error_keeps_its_code_groups_and_operation() {
    let error = CoreError::from_command_error(command_error(
        ApplicationErrorCode::ReplicaNotReady as i32,
        "op-1",
    ));
    assert!(error.is_command_error(ApplicationErrorCode::ReplicaNotReady));
    assert!(!error.is_command_error(ApplicationErrorCode::TargetNotFound));
    let CoreError::DaemonCommand { message, group_ids, operation_id, .. } = &error else {
        panic!("expected a daemon command error, got {error:?}");
    };
    assert_eq!(message, "refused");
    assert_eq!(group_ids, &["group-1".to_string()]);
    assert_eq!(operation_id.as_deref(), Some("op-1"));
    assert_eq!(error.to_string(), "refused");
}

#[test]
fn an_unknown_command_error_code_reads_as_unspecified_and_an_empty_operation_as_none() {
    let error = CoreError::from_command_error(command_error(9_999, ""));
    assert!(error.is_command_error(ApplicationErrorCode::Unspecified));
    assert!(matches!(error, CoreError::DaemonCommand { operation_id: None, .. }));
}

#[test]
fn a_missing_or_refusing_socket_is_daemon_not_running_and_other_io_keeps_its_message() {
    for kind in [std::io::ErrorKind::NotFound, std::io::ErrorKind::ConnectionRefused] {
        let error = CoreError::from(std::io::Error::new(kind, "x"));
        assert!(matches!(error, CoreError::DaemonNotRunning), "{kind:?}");
    }
    let error = CoreError::from(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe gone"));
    assert!(matches!(&error, CoreError::Io(m) if m == "pipe gone"), "{error:?}");
}

fn command(code: ApplicationErrorCode) -> CoreError {
    CoreError::from_command_error(ApplicationCommandError {
        code: code as i32,
        message: "daemon says no".into(),
        group_ids: vec!["group-1".into()],
        operation_id: "op-7".into(),
    })
}

fn desktop(error: CoreError) -> DesktopError {
    DesktopError::from(error)
}

#[test]
fn signed_out_and_an_unregistered_device_both_read_as_not_signed_in() {
    assert!(matches!(desktop(CoreError::NotLoggedIn), DesktopError::NotSignedIn { .. }));
    assert!(matches!(
        desktop(command(ApplicationErrorCode::LocalIdentityUnavailable)),
        DesktopError::NotSignedIn { .. }
    ));
}

#[test]
fn an_unreachable_or_mismatched_daemon_is_daemon_unavailable_with_its_reason() {
    assert_eq!(
        desktop(CoreError::DaemonNotRunning),
        DesktopError::DaemonUnavailable {
            message: CoreError::DaemonNotRunning.to_string(),
            reason: DaemonUnavailableReason::NotRunning,
        }
    );
    assert_eq!(
        desktop(CoreError::DaemonUnresponsive),
        DesktopError::DaemonUnavailable {
            message: CoreError::DaemonUnresponsive.to_string(),
            reason: DaemonUnavailableReason::Unresponsive,
        }
    );
    let mismatch = CoreError::DaemonProtocolMismatch { client: 3, daemon: 4 };
    let text = mismatch.to_string();
    assert_eq!(
        desktop(mismatch),
        DesktopError::DaemonUnavailable {
            message: text,
            reason: DaemonUnavailableReason::ProtocolMismatch {
                client_version: 3,
                daemon_version: 4
            },
        }
    );
}

#[test]
fn network_failures_carry_their_kind() {
    let cases = [
        (CoreError::CoordinationPlaneUnreachable("down".into()), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::CoordinationTransport), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::CoordinationAmbiguous), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::TicketUnavailable), NetworkErrorKind::Unreachable),
        (
            CoreError::LimitExceeded { message: "slow down".into(), kind: LimitKind::RateLimited },
            NetworkErrorKind::RateLimited,
        ),
        (
            command(ApplicationErrorCode::ActivationAmbiguous),
            NetworkErrorKind::ActivationPendingReconciliation,
        ),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::Network { kind, .. } => assert_eq!(kind, expected, "{label}"),
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn refusals_by_the_coordination_plane_are_permission_denied_with_their_reason() {
    let store = yadorilink_fapi_client::store::StoreError::UnknownBackend("bad".into());
    let cases = [
        (CoreError::AuthFailed("expired".into()), PermissionDeniedReason::SessionRejected),
        (CoreError::Forbidden("not yours".into()), PermissionDeniedReason::Forbidden),
        (command(ApplicationErrorCode::CoordinationRejected), PermissionDeniedReason::Forbidden),
        (command(ApplicationErrorCode::ActivationRejected), PermissionDeniedReason::Forbidden),
        (command(ApplicationErrorCode::PreparationRejected), PermissionDeniedReason::Forbidden),
        (
            CoreError::LimitExceeded { message: "full".into(), kind: LimitKind::Quota },
            PermissionDeniedReason::QuotaExceeded,
        ),
        (CoreError::CredentialStore(store), PermissionDeniedReason::CredentialStoreUnusable),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::PermissionDenied { reason, .. } => {
                assert_eq!(reason, expected, "{label}")
            }
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn durability_refusals_keep_groups_and_operation_and_offer_force_only_when_asked() {
    let blocked = CoreError::DurabilityBlocked {
        message: "no other copy".into(),
        group_ids: vec!["g".into()],
    };
    assert_eq!(
        DesktopError::from_core(blocked, true),
        DesktopError::DurabilityBlocked {
            message: "no other copy".into(),
            group_ids: vec!["g".into()],
            operation_id: None,
            can_force: true,
        }
    );
    for code in [
        ApplicationErrorCode::ReplicaNotReady,
        ApplicationErrorCode::DurabilityLatchFailed,
        ApplicationErrorCode::RecoveryPending,
    ] {
        assert_eq!(
            desktop(command(code)),
            DesktopError::DurabilityBlocked {
                message: "daemon says no".into(),
                group_ids: vec!["group-1".into()],
                operation_id: Some("op-7".into()),
                can_force: false,
            },
            "{code:?}"
        );
    }
}

#[test]
fn bad_arguments_and_missing_targets_are_invalid_input() {
    assert!(matches!(
        desktop(CoreError::InvalidInput("no such group".into())),
        DesktopError::InvalidInput { field: None, .. }
    ));
    assert!(matches!(
        desktop(command(ApplicationErrorCode::TargetNotFound)),
        DesktopError::InvalidInput { .. }
    ));
}

#[test]
fn everything_else_is_internal_with_a_stable_category() {
    let cases = [
        (CoreError::DaemonRejected("x".into()), "cli_command_failed"),
        (CoreError::Other("x".into()), "cli_command_failed"),
        (CoreError::Io("x".into()), "cli_command_failed"),
        (command(ApplicationErrorCode::Persistence), "daemon_command_persistence"),
        (command(ApplicationErrorCode::LocalLinkFailed), "daemon_command_local_link_failed"),
        (command(ApplicationErrorCode::OperationConflict), "daemon_command_operation_conflict"),
        (command(ApplicationErrorCode::CompensationPending), "daemon_command_compensation_pending"),
        (
            command(ApplicationErrorCode::RecoveryJournalUnavailable),
            "daemon_command_recovery_journal_unavailable",
        ),
        (command(ApplicationErrorCode::Unspecified), "daemon_command_unspecified"),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::Internal { category, .. } => assert_eq!(category, expected, "{label}"),
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn the_message_is_always_the_client_errors_own_text() {
    let error = CoreError::AuthFailed("token expired".into());
    let text = error.to_string();
    assert_eq!(desktop(error).to_string(), text);
}
