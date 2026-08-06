//! The single entry point the control socket calls into `application`
//! through. Built exactly once by the production composition root, and
//! handed down through `ControlContext` -- every field wraps a real
//! ports-based service.

use std::sync::Arc;

use super::{
    DaemonLifecycleService, DurabilityCommandService, EnrollmentRecoveryService, EnrollmentService,
    GcCommandService, GovernanceCommandService, HandoffCommandService, LinkLifecycleService,
    MaterializationService, PauseResumeService, ReplicaMembershipService, ReplicaRoleService,
    ReportingCommandService, UpdateCommandService, VersionRestoreService,
};

pub(crate) struct ApplicationServices {
    pub(crate) enrollment: Arc<EnrollmentService>,
    pub(crate) enrollment_recovery: Arc<EnrollmentRecoveryService>,
    pub(crate) materialization: Arc<MaterializationService>,
    pub(crate) membership: Arc<ReplicaMembershipService>,
    pub(crate) replica_role: Arc<ReplicaRoleService>,
    pub(crate) pause_resume: Arc<PauseResumeService>,
    pub(crate) gc: Arc<GcCommandService>,
    pub(crate) lifecycle: Arc<DaemonLifecycleService>,
    pub(crate) durability: Arc<DurabilityCommandService>,
    pub(crate) handoff: Arc<HandoffCommandService>,
    pub(crate) version_restore: Arc<VersionRestoreService>,
    pub(crate) governance: Arc<GovernanceCommandService>,
    pub(crate) reporting: Arc<ReportingCommandService>,
    pub(crate) update: Arc<UpdateCommandService>,
    pub(crate) link_lifecycle: Arc<LinkLifecycleService>,
}
