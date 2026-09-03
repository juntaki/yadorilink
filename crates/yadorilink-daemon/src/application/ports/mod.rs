//! `application`'s own boundary traits. Every port here is `dyn`-safe
//! (`BoxFuture`-returning, never `async fn` in a trait) and expressed only
//! in terms of `yadorilink_sync_core`/`application::model` types -- never
//! the daemon-state, coordination-client, control-socket, hydration, or
//! link-manager modules, and never the IPC-proto crate. Concrete
//! implementations live under the adapters module tree, never here.

pub(crate) mod common;
pub(crate) mod enrollment;
pub(crate) mod governance;
pub(crate) mod handoff;
pub(crate) mod link_lifecycle;
pub(crate) mod materialization;
pub(crate) mod membership;
pub(crate) mod replica_role;
pub(crate) mod reporting;
pub(crate) mod runtime_control;
pub(crate) mod update;
pub(crate) mod version_restore;

#[allow(unused_imports)]
pub(crate) use common::BoxFuture;
#[allow(unused_imports)]
pub(crate) use enrollment::{
    EnrollmentAttemptTracker, EnrollmentCoordination, EnrollmentLinkPort, EnrollmentLinkRequest,
    EnrollmentRepository,
};
#[allow(unused_imports)]
pub(crate) use governance::{GovernanceCommandPort, GovernanceLimits};
#[allow(unused_imports)]
pub(crate) use handoff::{
    DurabilityCommandPort, HandoffCommandPort, HandoffLeaseGrant, HandoffTicketGrant,
};
#[allow(unused_imports)]
pub(crate) use link_lifecycle::{
    LinkCommand, LinkRepositoryPort, LinkWatcherPort, PendingEnrollmentLinkCommand,
};
#[allow(unused_imports)]
pub(crate) use materialization::{
    EvictOutcome, MaterializationPort, MaterializationStateSummary, MaterializationStatusSummary,
};
#[allow(unused_imports)]
pub(crate) use membership::{
    HandoffTicketPort, MembershipCoordination, MembershipRepository, ReplicaReadinessPort,
};
#[allow(unused_imports)]
pub(crate) use replica_role::{
    HandoffReadinessPort, LinkRuntimePort, PlaceholderPipelineCapabilityPort,
    ReplicaRoleRepository, RoleLossCoordination, RoleLossJournal,
};
#[allow(unused_imports)]
pub(crate) use reporting::{
    ConsentCommand, LastErrorReport, RedactionCategoryCount as ReportingRedactionCategoryCount,
    ReportingCommandPort, SubmitReportOutcome,
};
#[allow(unused_imports)]
pub(crate) use runtime_control::{
    DaemonLifecyclePort, GcCommandError, GcCommandOutcome, GcPort, LinkPauseResumePort,
};
#[allow(unused_imports)]
pub(crate) use update::{InstallOutcome, UpdateCommandPort, UpdateConfigCommand, UpdatePolicyView};
#[allow(unused_imports)]
pub(crate) use version_restore::VersionRestorePort;
