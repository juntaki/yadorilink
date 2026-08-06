mod enrollment_recovery_service;
mod enrollment_service;
mod governance_service;
mod handoff_service;
mod link_lifecycle_service;
mod materialization_service;
pub(crate) mod membership_operation_identity;
pub(crate) mod model;
pub(crate) mod ports;
mod replica_membership_service;
pub(crate) mod replica_role_service;
mod reporting_command_service;
mod runtime_control_service;
pub(crate) mod services;
mod update_command_service;
mod version_restore_service;

pub(crate) use enrollment_recovery_service::EnrollmentRecoveryService;
#[allow(unused_imports)]
pub(crate) use enrollment_service::{
    CreateAndLinkCommand, EnrollmentError, EnrollmentKind, EnrollmentLinkError, EnrollmentOutcome,
    EnrollmentService, JoinAndLinkCommand,
};
#[allow(unused_imports)]
pub(crate) use governance_service::GovernanceCommandService;
#[allow(unused_imports)]
pub(crate) use handoff_service::{DurabilityCommandService, HandoffCommandService};
#[allow(unused_imports)]
pub(crate) use link_lifecycle_service::LinkLifecycleService;
pub(crate) use materialization_service::MaterializationService;
#[allow(unused_imports)]
pub(crate) use ports::{
    ConsentCommand, InstallOutcome, LastErrorReport, LinkCommand, PendingEnrollmentLinkCommand,
    UpdateConfigCommand, UpdatePolicyView,
};
#[allow(unused_imports)]
pub(crate) use replica_membership_service::{
    MembershipHandoffOutcome, RemoveDeviceCommand, ReplicaMembershipError,
    ReplicaMembershipOutcome, ReplicaMembershipService, RevokeDeviceCommand,
};
pub(crate) use replica_role_service::ReplicaRoleService;
#[allow(unused_imports)]
pub(crate) use reporting_command_service::ReportingCommandService;
#[allow(unused_imports)]
pub(crate) use runtime_control_service::{
    DaemonLifecycleService, GcCommandService, PauseResumeService,
};
#[allow(unused_imports)]
pub(crate) use services::ApplicationServices;
#[allow(unused_imports)]
pub(crate) use update_command_service::UpdateCommandService;
#[allow(unused_imports)]
pub(crate) use version_restore_service::VersionRestoreService;

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn application_service_sources_do_not_depend_on_ipc_proto() {
        for (name, source) in [
            ("enrollment_service", include_str!("enrollment_service.rs")),
            ("enrollment_recovery_service", include_str!("enrollment_recovery_service.rs")),
            ("replica_membership_service", include_str!("replica_membership_service.rs")),
        ] {
            assert!(
                !source.contains(concat!("yadorilink_", "ipc_proto")),
                "{name} must expose protocol-independent application types"
            );
        }
    }
}
