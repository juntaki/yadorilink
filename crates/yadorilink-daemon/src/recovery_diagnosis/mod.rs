//! Phase 2.1-C2-B: diagnosing a stuck local recovery-journal operation
//! against the coordination plane's own evidence, built in two layers:
//!
//! - **C2-B1** (`identity`/`model`): typed identity qualification only --
//!   does a piece of local/remote evidence agree with the journal row it's
//!   read alongside? No recommendation, no state judgment, no I/O.
//! - **C2-B2** (`classifier`/`reason`): a pure classifier that combines
//!   this qualification with the journal row's own state into a
//!   [`RecoveryRecommendation`] an operator, or a later phase's automatic
//!   reconciler, can act on.
//!
//! Both layers stay pure: every input is a value already produced by
//! Phase 2.1-C2-A (`crate::recovery_snapshot::RecoverySnapshotReader::recovery_local_snapshot`)
//! or Phase 2.1-C1 (`crate::recovery_evidence`). Nothing in this module
//! reads a database, calls the coordination plane, mutates a journal row,
//! or touches IPC/CLI plumbing -- those are all later phases (2.1-C2-C
//! onward).
//!
//! The public entry points are [`diagnose_enrollment`]/
//! [`diagnose_membership`]/[`diagnose_role_loss`] -- each takes only local
//! + remote evidence and builds the B1 qualification internally, so a
//! caller can never combine a qualification built from one evidence pair
//! with a diagnosis for a different one.
//!
//! - **C2-C1** (`service`): assembles a single STABLE diagnosis for one
//!   operation, gated on the local evidence provably not having changed
//!   between the pre-remote-lookup snapshot and a post-lookup re-read. See
//!   `service`'s own doc comment. Still no database mutation and no
//!   coordination-plane mutation.
//! - **C2-C2** (`ipc`): the stable diagnosis exposed over IPC/CLI as
//!   `yadorilink recovery show <domain> <operation-id>` -- centralizes every
//!   Rust -> protobuf conversion so the control socket handler stays thin. This
//!   is the first phase in this module that reaches outside the daemon's own
//!   process (via `yadorilink-ipc-proto`'s wire types); `service`/
//!   `classifier`/`identity`/`model` remain pure and I/O-free exactly as
//!   before.

mod classifier;
mod identity;
pub(crate) mod ipc;
mod model;
mod reason;
mod service;

#[cfg(test)]
mod tests;

pub use classifier::{
    diagnose_enrollment, diagnose_membership, diagnose_role_loss, RecoveryDiagnosis,
    RecoveryEvidenceQualification, RecoveryLocalState, RecoveryRecommendation, RecoveryRemoteState,
};
pub use identity::{qualify_enrollment, qualify_membership, qualify_role_loss};
pub use model::{
    EnrollmentEvidenceQualification, IdentityField, IdentityNotEvaluatedReason,
    IdentityQualificationReason, MembershipEvidenceQualification, ObservationQualification,
    RemoteIdentityQualification, RoleLossEvidenceQualification,
};
pub use reason::RecoveryReasonCode;
pub(crate) use service::{diagnose_stable, StableDiagnosisOutcome};
