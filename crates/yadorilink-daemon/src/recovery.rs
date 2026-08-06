//! Phase 2.1: a read-only inventory over every in-flight local recovery
//! journal -- `enrollment_operations`, `membership_operations`, and
//! `role_loss_operations` -- normalized into one common shape an operator
//! (or the CLI's `recovery list`/`recovery show`) can read without knowing
//! each domain's own row schema.
//!
//! This module is strictly observational. Nothing here writes to any table,
//! retries a remote call, or changes a row's state -- it only reads and
//! decodes. Diagnosis against remote (Worker) evidence and any write-side
//! resolution are later phases (2.1-C and 2.2), deliberately not part of
//! this one.
//!
//! Each domain keeps its own strict decoder
//! (`ReplicaCoordinator::enrollment_repository().scan_all_enrollment_operations()`,
//! `ReplicaCoordinator::membership_operation_repository().scan_membership_operations_in_states()`,
//! `ReplicaCoordinator::role_loss_operation_repository().scan_all_role_loss_operations()`)
//! rather than this module
//! decoding raw SQL rows itself: a single `UNION`-style query across three
//! differently-shaped tables would either lose each domain's own shape
//! validation (see e.g. `validate_enrollment_operation`,
//! `validate_membership_operation_shape`) or have to reimplement it here,
//! duplicating the exact rules each table's own module already encodes. One
//! malformed row in ANY domain is isolated into [`RecoveryInventory::invalid`]
//! rather than failing the whole inventory -- an operator investigating a
//! stuck membership operation must never be blocked by an unrelated corrupt
//! enrollment row, and vice versa. Only an outright database read failure
//! (a lock, a missing table, an I/O error) fails the whole call; that is a
//! `SyncError`, not a per-row concern.
//!
//! Relocated from `yadorilink-sync-core::recovery` (Phase 7D-10): the trait
//! this module is generalized over ([`RecoveryInventorySource`]) has exactly
//! one real implementor left, `yadorilink-daemon`'s own `ReplicaCoordinator`
//! -- `yadorilink-sync-core::index::SyncState` never called `inventory()` or
//! `RecoveryInventorySource` outside its own test suite, which moved here
//! alongside the production code (see this module's own `tests` submodule).

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState, MembershipOperation, MembershipOperationState,
    RoleLossOperation, RoleLossOperationState,
};

/// `RecoveryDomain`/`InvalidRecoveryOperation` moved to
/// `yadorilink_replica_domain::recovery` (Phase 7D-9F) so
/// `yadorilink-sync-sqlite`'s own repository implementations could
/// reference them without a `sync-sqlite -> sync-core` dependency cycle --
/// re-exported here so every existing `crate::recovery::RecoveryDomain`/
/// `crate::recovery::InvalidRecoveryOperation` path (this module's own code
/// below, `yadorilink-cli`) keeps resolving unchanged.
pub use yadorilink_replica_domain::recovery::{InvalidRecoveryOperation, RecoveryDomain};

/// A coarse, operator-facing classification of a [`RecoveryOperationSummary`]
/// -- derived from the row's own domain-specific state (and, for membership,
/// its separate `durability_scope` axis), never itself persisted. This is
/// deliberately coarser than the underlying state enums: an operator
/// scanning `recovery list` needs "is this actively progressing, stuck
/// waiting, of unknown durability impact, blocked on me, or corrupt" more
/// than the exact state name, which `recovery show` still exposes in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySeverity {
    /// Actively progressing through its own saga; no operator action
    /// expected. Includes a terminal state observed only in the narrow
    /// crash window before its row is deleted (see e.g.
    /// [`RoleLossOperationState::LocalCommitted`]'s own doc comment) -- it
    /// is not stuck, just caught mid-cleanup.
    Pending,
    /// Being retried automatically and indefinitely by a reconciliation
    /// sweep (e.g. [`RoleLossOperationState::Compensating`],
    /// [`MembershipOperationState::Ambiguous`] awaiting a resend/lookup).
    Retrying,
    /// The blast radius (which folder groups) this operation puts at risk
    /// is not currently known -- [`MembershipOperation::durability_scope`]
    /// being `Unknown`. Orthogonal to (and reported instead of) the row's
    /// own `state`-derived severity, since durability-unknown is the more
    /// operator-relevant signal regardless of what the remote mutation's
    /// own state currently is.
    DurabilityUnknown,
    /// Automatic recovery has been refused for this row -- operator
    /// attention required. See each domain's own `RecoveryBlocked` variant.
    Blocked,
    /// The row itself failed to decode -- reported via
    /// [`RecoveryInventory::invalid`], never as a [`RecoveryOperationSummary`].
    /// [`RecoverySeverity`] never actually takes this value on a summary;
    /// it exists only so callers matching exhaustively over severity have a
    /// name for "this row never became a summary at all" when reasoning
    /// about the domain as a whole.
    Invalid,
}

/// The full identity of one recovery-journal row: `operation_id` alone is
/// NOT enough, and must never be treated as one -- `enrollment_operations`,
/// `membership_operations`, and `role_loss_operations` are three separate
/// tables with no cross-table uniqueness constraint, so the SAME id can
/// legitimately name a row in more than one domain at once. Every lookup by
/// id (`recovery show`, and the diagnose/plan/apply commands later phases
/// add) must resolve against this pair, not `operation_id` on its own, or
/// it risks silently picking the wrong domain's row -- which, once 2.1-C
/// starts reading domain-specific Worker evidence and 2.2 starts writing
/// resolutions, means diagnosing or mutating the wrong operation entirely.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecoveryOperationKey {
    pub domain: RecoveryDomain,
    pub operation_id: String,
}

/// One local recovery journal row, normalized across all three domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOperationSummary {
    pub operation_id: String,
    pub domain: RecoveryDomain,
    /// The domain-specific action/kind string (`"create"`/`"join"` for
    /// enrollment, `"revoke"`/`"remove-device"` for membership,
    /// `"demote"`/`"unlink"`/`"revoke"` for role-loss) -- kept as the raw
    /// `as_db_str()` value rather than a shared enum, since the three
    /// domains' action spaces don't overlap.
    pub action: String,
    /// The domain-specific state string (e.g. `"activation_pending"`,
    /// `"ambiguous"`, `"worker_committed"`) -- `recovery show` is where the
    /// exact state matters; `severity` is what `recovery list` sorts/filters
    /// by.
    pub state: String,
    pub severity: RecoverySeverity,

    pub group_ids: Vec<String>,
    pub device_id: Option<String>,
    pub local_path: Option<String>,

    pub attempts: i64,
    pub last_error: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

impl RecoveryOperationSummary {
    pub fn key(&self) -> RecoveryOperationKey {
        RecoveryOperationKey { domain: self.domain, operation_id: self.operation_id.clone() }
    }
}

/// The full read-only recovery inventory: every valid row across all three
/// domains, normalized, plus every row that failed to decode.
#[derive(Debug, Clone, Default)]
pub struct RecoveryInventory {
    pub valid: Vec<RecoveryOperationSummary>,
    pub invalid: Vec<InvalidRecoveryOperation>,
}

fn enrollment_severity(state: EnrollmentOperationState) -> RecoverySeverity {
    match state {
        EnrollmentOperationState::RecoveryBlocked => RecoverySeverity::Blocked,
        EnrollmentOperationState::PreparePending
        | EnrollmentOperationState::Prepared
        | EnrollmentOperationState::LocalSetupPending
        | EnrollmentOperationState::ActivationPending
        | EnrollmentOperationState::CancelPending => RecoverySeverity::Pending,
    }
}

fn membership_severity(
    state: MembershipOperationState,
    durability_scope_unknown: bool,
) -> RecoverySeverity {
    // RecoveryBlocked always wins: an operator-attention row is the more
    // urgent signal even if its durability scope also happens to be
    // unknown.
    if state == MembershipOperationState::RecoveryBlocked {
        return RecoverySeverity::Blocked;
    }
    if durability_scope_unknown {
        return RecoverySeverity::DurabilityUnknown;
    }
    match state {
        MembershipOperationState::Ambiguous => RecoverySeverity::Retrying,
        MembershipOperationState::Prepared
        | MembershipOperationState::LocalSettlementPending
        | MembershipOperationState::Completed
        | MembershipOperationState::DefinitelyRejected => RecoverySeverity::Pending,
        MembershipOperationState::RecoveryBlocked => unreachable!("handled above"),
    }
}

fn role_loss_severity(state: RoleLossOperationState) -> RecoverySeverity {
    match state {
        RoleLossOperationState::Compensating => RecoverySeverity::Retrying,
        RoleLossOperationState::Prepared
        | RoleLossOperationState::WorkerCommitted
        | RoleLossOperationState::LocalCommitted
        | RoleLossOperationState::Completed => RecoverySeverity::Pending,
    }
}

/// Normalizes one `enrollment_operations` row into a
/// [`RecoveryOperationSummary`] -- shared by [`inventory`] (which owns its
/// rows after scanning) and [`LocalRecoveryEvidence::summary`] (which only
/// ever holds a borrow), so the two call sites can never independently
/// drift on what a summary actually contains.
fn enrollment_operation_summary(op: &EnrollmentOperation) -> RecoveryOperationSummary {
    RecoveryOperationSummary {
        operation_id: op.operation_id.clone(),
        domain: RecoveryDomain::Enrollment,
        action: op.kind.as_db_str().to_string(),
        state: op.state.as_db_str().to_string(),
        severity: enrollment_severity(op.state),
        group_ids: op.group_id.clone().into_iter().collect(),
        device_id: Some(op.device_id.clone()),
        local_path: Some(op.local_path.clone()),
        attempts: op.attempts,
        last_error: op.last_error.clone(),
        created_at_unix: op.created_at_unix,
        updated_at_unix: op.updated_at_unix,
    }
}

fn membership_operation_summary(op: &MembershipOperation) -> RecoveryOperationSummary {
    let durability_unknown =
        op.durability_scope == yadorilink_replica_domain::session_state::MembershipDurabilityScope::Unknown;
    RecoveryOperationSummary {
        operation_id: op.operation_id.clone(),
        domain: RecoveryDomain::Membership,
        action: op.action.as_db_str().to_string(),
        state: op.state.as_db_str().to_string(),
        severity: membership_severity(op.state, durability_unknown),
        group_ids: op.group_ids.clone(),
        device_id: Some(op.removed_device_id.clone()),
        local_path: None,
        attempts: 0,
        last_error: op.last_error.clone(),
        created_at_unix: op.created_at_unix,
        updated_at_unix: op.updated_at_unix,
    }
}

fn role_loss_operation_summary(op: &RoleLossOperation) -> RecoveryOperationSummary {
    RecoveryOperationSummary {
        operation_id: op.operation_id.clone(),
        domain: RecoveryDomain::RoleLoss,
        action: op.action.as_db_str().to_string(),
        state: op.state.as_db_str().to_string(),
        severity: role_loss_severity(op.state),
        group_ids: vec![op.group_id.clone()],
        device_id: Some(op.source_device_id.clone()),
        local_path: op.local_path.clone(),
        attempts: op.attempts,
        last_error: None,
        created_at_unix: op.created_at_unix,
        updated_at_unix: op.updated_at_unix,
    }
}

/// Narrow capability [`inventory`] needs from whatever holds the three
/// recovery journals -- deliberately just these three accessors, not a
/// wider surface. `ReplicaCoordinator` is this trait's one real implementor
/// (Phase 7D-10): `yadorilink-sync-core::index::SyncState` used to implement
/// it too, purely for its own now-relocated test suite, and never had a
/// production caller of its own.
pub trait RecoveryInventorySource {
    fn enrollment_repository(&self) -> &yadorilink_sync_sqlite::enrollment::EnrollmentRepository;
    fn membership_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::MembershipOperationRepository;
    fn role_loss_operation_repository(
        &self,
    ) -> &yadorilink_sync_sqlite::RoleLossOperationRepository;
}

/// Builds the full read-only recovery inventory across all three local
/// recovery journals. Read-only: does not write to any table, retry any
/// remote call, or otherwise mutate state. A read failure on the underlying
/// database (as opposed to a single malformed row) fails the whole call.
pub fn inventory<S: RecoveryInventorySource>(state: &S) -> Result<RecoveryInventory, SyncError> {
    let mut result = RecoveryInventory::default();

    let enrollment = state.enrollment_repository().scan_all_enrollment_operations()?;
    result.valid.extend(enrollment.valid.iter().map(enrollment_operation_summary));
    result.invalid.extend(enrollment.invalid);

    let membership = state.membership_operation_repository().scan_all_membership_operations()?;
    result.valid.extend(membership.valid.iter().map(membership_operation_summary));
    result.invalid.extend(membership.invalid);

    let role_loss = state.role_loss_operation_repository().scan_all_role_loss_operations()?;
    result.valid.extend(role_loss.valid.iter().map(role_loss_operation_summary));
    result.invalid.extend(role_loss.invalid);

    Ok(result)
}

// ===== Phase 2.1-C2-A: strict local recovery evidence snapshots =====
//
// Read-only, like the inventory above -- but scoped to exactly ONE
// operation (identified by a [`RecoveryOperationKey`]) rather than every row
// in a domain, and gathering every LOCALLY observable piece of evidence
// related to that operation (its own journal row, the folder link it
// concerns, any pending-enrollment marker, any durability latch) from the
// SAME SQLite read transaction. See [`crate::recovery_snapshot::RecoverySnapshotReader::
// recovery_local_snapshot`] for why that single-transaction requirement
// matters: without it, a reconciler running concurrently on another pooled
// connection could mutate a link or marker in between two independently-
// checked-out reads, producing a snapshot that describes an
// operation/link/marker combination that never actually coexisted.
// Diagnosis (Phase 2.1-C2-B) depends on every field here having genuinely
// been true at one single instant.
//
// This module is still strictly observational: nothing here writes to any
// table, calls the coordination plane, or advances `attempts` or any other
// counter. Whether a piece of evidence is "healthy" or "a problem" is not
// decided here either -- that is Phase 2.1-C2-B's qualification job; this
// snapshot only reports what was actually read.

/// One piece of local evidence related to a recovery operation. Deliberately
/// not an `Option<T>`: a caller (Phase 2.1-C2-B's classifier) must be able
/// to tell "no matching row exists in this same transaction"
/// (`ConfirmedAbsent`) apart from "a row exists but this build cannot trust
/// its shape" (`Invalid`) apart from "more than one row could plausibly be
/// THE row for this operation, and none can be singled out" (`Ambiguous`) --
/// collapsing any of these into each other would hand the classifier
/// evidence it cannot safely reason about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalObservation<T> {
    Found(T),
    ConfirmedAbsent,
    Invalid { detail: String },
    Ambiguous { detail: String },
}

/// The subset of a `links` row a recovery diagnosis actually needs --
/// deliberately narrower than `yadorilink_replica_domain::session_state::FolderLink`,
/// which also carries fields (`max_local_size_bytes`, ...) no diagnosis
/// decision reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLinkEvidence {
    pub group_id: String,
    pub local_path: String,
    pub materialization_policy: yadorilink_replica_domain::session_state::MaterializationPolicy,
    pub paused: bool,
    pub orphaned: bool,
    pub root_token_present: bool,
}

/// The identity a `pending_enrollments` marker carries -- mirrors
/// `yadorilink_replica_domain::session_state::PendingEnrollment`, kept as
/// its own type here so this module's public shape does not change if that
/// row's own internal representation ever does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollmentEvidence {
    pub operation_id: String,
    pub kind: yadorilink_replica_domain::session_state::EnrollmentKind,
    pub group_id: String,
    pub device_id: String,
    pub local_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentLocalEvidence {
    pub operation: EnrollmentOperation,
    pub link: LocalObservation<LocalLinkEvidence>,
    pub pending_marker: LocalObservation<PendingEnrollmentEvidence>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MembershipLocalEvidence {
    pub operation: MembershipOperation,
    /// The subset of `operation.group_ids` ∪ `operation.latch_group_ids`
    /// that actually has a `durability_unknown_latches` row right now, read
    /// from the SAME transaction as `operation` -- sorted and deduplicated,
    /// never in raw row order. Whether this is the RIGHT set (missing an
    /// expected latch, carrying an extra one, disagreeing with
    /// `operation.durability_scope`) is Phase 2.1-C2-B's qualification
    /// call, not this snapshot's.
    pub present_durability_latches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoleLossLocalEvidence {
    pub operation: RoleLossOperation,
    pub link: LocalObservation<LocalLinkEvidence>,
}

/// `PartialEq` (not just [`Self::revision`]'s 64-bit fingerprint) exists so
/// Phase 2.1-C2-C can compare a pre-remote-lookup snapshot against a
/// post-lookup re-read directly: `before != after` is the ground-truth
/// staleness check; the fingerprint is a cheap first-pass filter/log field,
/// never the sole authority for "did anything change". No `Eq`: a
/// `MembershipLocalEvidence` carries a `MembershipOperation`, which itself
/// has no `Eq` impl (nothing here needs it beyond direct `==`/`!=`).
#[derive(Debug, Clone, PartialEq)]
pub enum LocalRecoveryEvidence {
    Enrollment(EnrollmentLocalEvidence),
    Membership(MembershipLocalEvidence),
    RoleLoss(RoleLossLocalEvidence),
}

impl LocalRecoveryEvidence {
    /// A fingerprint of EVERY field this snapshot carries -- the operation
    /// row (all of it, not just `state`/`updated_at_unix`) plus every piece
    /// of related evidence (link/marker/latch observations) -- for Phase
    /// 2.1-C2-C's post-remote-lookup re-check: if a fresh
    /// `recovery_local_snapshot` call for the SAME key returns a different
    /// revision, an automatic reconciler mutated something while a remote
    /// lookup was in flight, and the diagnosis built from the OLD snapshot
    /// must be discarded rather than combined with the NEW remote evidence.
    ///
    /// `updated_at_unix` alone cannot stand in for the whole operation row:
    /// two writes landing in the same second (`attempts` incrementing,
    /// `last_error` changing) can share both `state` and `updated_at_unix`,
    /// which an earlier version of this method fingerprinted instead of the
    /// full row -- collapsing a genuine mutation into "no change". Likewise
    /// a link, marker, or latch can change while the operation row itself
    /// is untouched (a durability latch cleared by an unrelated sweep, a
    /// link orphaned) -- also missed by fingerprinting the operation alone.
    /// Hashing the full `Debug` output of everything this snapshot carries
    /// closes both gaps at once, at the cost of the fingerprint no longer
    /// being individually interpretable (`state`/`updated_at_unix` are kept
    /// alongside it purely for human-readable display, not for the
    /// staleness check itself).
    pub fn revision(&self) -> RecoverySnapshotRevision {
        let (state, updated_at_unix) = match self {
            LocalRecoveryEvidence::Enrollment(e) => {
                (e.operation.state.as_db_str(), e.operation.updated_at_unix)
            }
            LocalRecoveryEvidence::Membership(e) => {
                (e.operation.state.as_db_str(), e.operation.updated_at_unix)
            }
            LocalRecoveryEvidence::RoleLoss(e) => {
                (e.operation.state.as_db_str(), e.operation.updated_at_unix)
            }
        };
        let full_evidence_fingerprint = match self {
            LocalRecoveryEvidence::Enrollment(e) => {
                fingerprint_debug(&(&e.operation, &e.link, &e.pending_marker))
            }
            LocalRecoveryEvidence::Membership(e) => {
                fingerprint_debug(&(&e.operation, &e.present_durability_latches))
            }
            LocalRecoveryEvidence::RoleLoss(e) => fingerprint_debug(&(&e.operation, &e.link)),
        };
        RecoverySnapshotRevision {
            state: state.to_string(),
            updated_at_unix,
            full_evidence_fingerprint,
        }
    }

    /// The same normalized [`RecoveryOperationSummary`] shape [`inventory`]
    /// produces for this operation's own row -- built from the SAME
    /// `operation` value this evidence already carries, via the identical
    /// per-domain helper `inventory` itself calls, so a caller combining a
    /// snapshot-derived summary with a `recovery list` summary for the same
    /// operation can never observe the two disagreeing on how a field is
    /// derived.
    pub fn summary(&self) -> RecoveryOperationSummary {
        match self {
            LocalRecoveryEvidence::Enrollment(e) => enrollment_operation_summary(&e.operation),
            LocalRecoveryEvidence::Membership(e) => membership_operation_summary(&e.operation),
            LocalRecoveryEvidence::RoleLoss(e) => role_loss_operation_summary(&e.operation),
        }
    }
}

/// Hashes a value's `Debug` output -- used only to fold arbitrary related
/// evidence (link/marker/latch observations) into a single comparable
/// number for [`LocalRecoveryEvidence::revision`]. `DefaultHasher::new()`
/// uses fixed keys, so this is deterministic within/across runs of the same
/// build; it is a staleness fingerprint, never used for anything
/// security-sensitive.
fn fingerprint_debug(value: &impl std::fmt::Debug) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{value:?}").hash(&mut hasher);
    hasher.finish()
}

/// See [`LocalRecoveryEvidence::revision`]'s doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySnapshotRevision {
    pub state: String,
    pub updated_at_unix: i64,
    pub full_evidence_fingerprint: u64,
}

/// The full result of [`crate::recovery_snapshot::RecoverySnapshotReader::
/// recovery_local_snapshot`] for one `(domain, operation_id)`.
/// `OperationNotFound` and `InvalidOperation` are kept OUT of `Result::Err`
/// deliberately -- neither is a database read failure; both are legitimate,
/// expected answers a caller (Phase 2.1-C2-B/C2-C) must handle without
/// treating them as an operational error. Only a genuine database read
/// failure (connection, I/O, a broken query) is `Err(SyncError)`.
#[derive(Debug, Clone)]
pub enum RecoveryLocalSnapshot {
    Found(Box<LocalRecoveryEvidence>),
    /// No journal row exists for this domain + operation_id in this same
    /// read transaction.
    OperationNotFound {
        key: RecoveryOperationKey,
    },
    /// A journal row exists but could not be strictly decoded.
    InvalidOperation {
        key: RecoveryOperationKey,
        raw_state: Option<String>,
        detail: String,
    },
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_replica_domain::session_state::{
        EnrollmentKind, MembershipCommitMode, MembershipDurabilityScope, MembershipOperationAction,
        RoleLossAction, RoleLossOperationParams,
    };

    pub(crate) fn insert_valid_enrollment_op(state: &ReplicaCoordinator, operation_id: &str) {
        state
            .enrollment_repository().try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: operation_id.to_string(),
                kind: EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::ActivationPending,
                last_error: None,
                attempts: 2,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();
    }

    pub(crate) fn insert_valid_membership_op(state: &ReplicaCoordinator, operation_id: &str) {
        state
            .membership_operation_repository().try_insert_membership_operation(
                operation_id,
                MembershipOperationAction::Revoke,
                MembershipCommitMode::PlainRevoke,
                "device-b",
                &["group-1".to_string()],
                &[],
                &[],
                MembershipOperationState::Prepared,
                MembershipDurabilityScope::Known,
                &[],
                None,
                1,
            )
            .unwrap();
    }

    pub(crate) fn insert_valid_role_loss_op(state: &ReplicaCoordinator, operation_id: &str) {
        state
            .role_loss_operation_repository().insert_role_loss_operation(
                operation_id,
                "group-1",
                RoleLossOperationParams {
                    source_device_id: "device-c",
                    target_device_id: "device-d",
                    lease_id: None,
                    action: RoleLossAction::Demote,
                    local_path: Some("/home/alice/Photos"),
                    now_unix: 1,
                },
            )
            .unwrap();
    }

    #[test]
    fn recovery_inventory_lists_enrollment_membership_and_role_loss_together() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-enroll");
        insert_valid_membership_op(&state, "op-membership");
        insert_valid_role_loss_op(&state, "op-role-loss");

        let inv = crate::recovery::inventory(&state).unwrap();

        assert!(inv.invalid.is_empty());
        assert_eq!(inv.valid.len(), 3);
        let domains: std::collections::HashSet<_> = inv.valid.iter().map(|op| op.domain).collect();
        assert!(domains.contains(&crate::recovery::RecoveryDomain::Enrollment));
        assert!(domains.contains(&crate::recovery::RecoveryDomain::Membership));
        assert!(domains.contains(&crate::recovery::RecoveryDomain::RoleLoss));
    }

    #[test]
    fn recovery_inventory_shows_recovery_blocked_rows_that_the_open_scan_excludes() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .enrollment_repository().try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: "op-blocked".to_string(),
                kind: EnrollmentKind::Create,
                group_id: None,
                group_name: Some("photos".to_string()),
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::RecoveryBlocked,
                last_error: Some("identity mismatch".to_string()),
                attempts: 1,
                created_at_unix: 1,
                updated_at_unix: 1,
            })
            .unwrap();

        // The ordinary reconciliation scan must still exclude it...
        let open_scan = state.enrollment_repository().scan_open_enrollment_operations().unwrap();
        assert!(open_scan.valid.is_empty(), "reconciliation must never see a blocked row");

        // ...but the inventory must show it, with Blocked severity.
        let inv = crate::recovery::inventory(&state).unwrap();
        assert_eq!(inv.valid.len(), 1);
        assert_eq!(inv.valid[0].operation_id, "op-blocked");
        assert_eq!(inv.valid[0].severity, crate::recovery::RecoverySeverity::Blocked);
    }

    #[test]
    fn recovery_inventory_isolates_an_unknown_state_string_into_invalid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO enrollment_operations \
                    (operation_id, kind, group_id, group_name, device_id, local_path, \
                     storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix) \
                 VALUES ('op-malformed', 'create', 'group-1', NULL, 'device-a', '/tmp/broken', \
                    'eager', 'from-the-future', NULL, 0, 1, 1)",
                [],
            )
            .unwrap();

        let inv = crate::recovery::inventory(&state).unwrap();

        assert_eq!(inv.valid.len(), 1);
        assert_eq!(inv.valid[0].operation_id, "op-1");
        assert_eq!(inv.invalid.len(), 1);
        assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-malformed"));
        assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Enrollment);
        assert_eq!(
            inv.invalid[0].raw_state.as_deref(),
            Some("from-the-future"),
            "the exact persisted state must survive even when it fails to decode, so \
             `recovery show` can display it"
        );
    }

    /// A membership row with an unknown `state` string must be reported as
    /// `invalid`, not silently dropped -- `scan_membership_operations_in_states`'s
    /// `WHERE state IN (...)` allow-list would match none of its bound
    /// placeholders and simply omit such a row from BOTH `valid` and
    /// `invalid`, which is why the inventory uses `scan_all_membership_operations`
    /// (no state filter) instead.
    #[test]
    fn recovery_inventory_isolates_an_unknown_membership_state_into_invalid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO membership_operations \
                    (operation_id, action, commit_mode, removed_device_id, group_ids, \
                     target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                     last_error, created_at_unix, updated_at_unix) \
                 VALUES ('op-future-state', 'revoke', 'plain-revoke', 'device-b', '[\"group-1\"]', \
                    '[]', '[]', 'from-the-future', 'known', '[]', NULL, 1, 1)",
                [],
            )
            .unwrap();

        let inv = crate::recovery::inventory(&state).unwrap();

        assert!(inv.valid.iter().any(|op| op.operation_id == "op-1"));
        assert_eq!(inv.invalid.len(), 1);
        assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-future-state"));
        assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
    }

    #[test]
    fn recovery_inventory_isolates_a_malformed_json_array_into_invalid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_role_loss_op(&state, "op-good");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO membership_operations \
                    (operation_id, action, commit_mode, removed_device_id, group_ids, \
                     target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                     last_error, created_at_unix, updated_at_unix) \
                 VALUES ('op-malformed-json', 'revoke', 'plain-revoke', 'device-b', \
                    'not-a-json-array', '[]', '[]', 'prepared', 'known', '[]', NULL, 1, 1)",
                [],
            )
            .unwrap();

        let inv = crate::recovery::inventory(&state).unwrap();

        // The role-loss row (a different domain) is unaffected...
        assert!(inv.valid.iter().any(|op| op.operation_id == "op-good"));
        // ...and the malformed membership row is isolated, not silently dropped.
        assert_eq!(inv.invalid.len(), 1);
        assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-malformed-json"));
        assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
    }

    /// A row whose `operation_id` column is not TEXT at all (corruption, or
    /// a manual repair gone wrong -- a BLOB here) must still be isolated
    /// into `invalid` with `operation_id: None`, never abort the whole
    /// inventory. `row.get::<_, String>(0)?` -- the naive read this replaced
    /// -- would return early on such a row, failing the ENTIRE `inventory()`
    /// call and hiding every other, perfectly healthy operation in every
    /// domain behind it.
    #[test]
    fn recovery_inventory_isolates_a_non_text_operation_id_into_invalid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO membership_operations \
                    (operation_id, action, commit_mode, removed_device_id, group_ids, \
                     target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                     last_error, created_at_unix, updated_at_unix) \
                 VALUES (X'80FF', 'revoke', 'plain-revoke', 'device-b', '[]', '[]', '[]', \
                    'prepared', 'known', '[]', NULL, 1, 1)",
                [],
            )
            .unwrap();

        let inv = crate::recovery::inventory(&state).unwrap();

        assert!(
            inv.valid.iter().any(|op| op.operation_id == "op-1"),
            "a sibling row in a different domain must still be reported"
        );
        assert_eq!(inv.invalid.len(), 1);
        assert_eq!(inv.invalid[0].operation_id, None);
        assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
    }

    /// Negative `attempts` is corruption, not a legitimate value -- the wire
    /// conversion (`recovery_summary_to_proto`) must never receive one to
    /// silently clamp to zero; the row must be isolated as `invalid` before
    /// it ever reaches that conversion.
    #[test]
    fn recovery_inventory_isolates_negative_attempts_into_invalid() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute(
                "INSERT INTO enrollment_operations \
                    (operation_id, kind, group_id, group_name, device_id, local_path, \
                     storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix) \
                 VALUES ('op-negative-attempts', 'create', 'group-1', NULL, 'device-a', \
                    '/tmp/broken', 'eager', 'activation_pending', NULL, -1, 1, 1)",
                [],
            )
            .unwrap();

        let inv = crate::recovery::inventory(&state).unwrap();

        assert_eq!(inv.valid.len(), 0);
        assert_eq!(inv.invalid.len(), 1);
        assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-negative-attempts"));
        assert!(
            inv.invalid[0].detail.contains("negative"),
            "detail was: {}",
            inv.invalid[0].detail
        );
    }

    #[test]
    fn recovery_inventory_does_not_convert_a_db_read_failure_into_an_empty_list() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-1");
        state
            .database()
            .pool_for_test()
            .get()
            .unwrap()
            .execute("DROP TABLE role_loss_operations", [])
            .unwrap();

        let result = crate::recovery::inventory(&state);

        assert!(
            result.is_err(),
            "a genuine DB read failure must propagate as an error, never as an empty inventory"
        );
    }

    #[test]
    fn recovery_inventory_is_read_only() {
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        insert_valid_enrollment_op(&state, "op-enroll");
        insert_valid_membership_op(&state, "op-membership");
        insert_valid_role_loss_op(&state, "op-role-loss");

        let before_enrollment = state.enrollment_repository().scan_all_enrollment_operations().unwrap().valid;
        let before_membership = state.membership_operation_repository().scan_all_membership_operations().unwrap().valid;
        let before_role_loss = state.role_loss_operation_repository().scan_all_role_loss_operations().unwrap().valid;

        let _ = crate::recovery::inventory(&state).unwrap();

        let after_enrollment = state.enrollment_repository().scan_all_enrollment_operations().unwrap().valid;
        let after_membership = state.membership_operation_repository().scan_all_membership_operations().unwrap().valid;
        let after_role_loss = state.role_loss_operation_repository().scan_all_role_loss_operations().unwrap().valid;

        assert_eq!(before_enrollment, after_enrollment);
        assert_eq!(before_membership, after_membership);
        assert_eq!(before_role_loss, after_role_loss);
    }
}
