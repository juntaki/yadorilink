//! Semantic outcome types for `PeerReplicaEngine`'s own methods. Each
//! carries exactly the extra information a caller needs to reproduce the
//! logging `yadorilink-sync-core`'s `peer_session.rs` used to do inline --
//! this crate has no `tracing` dependency, so callers own the actual log
//! emission, keyed off these outcomes.

use std::collections::BTreeSet;

use yadorilink_replica_domain::ids::ChangeHash;

/// `PeerReplicaEngine::record_frontier_and_find_missing`'s result. Frontier
/// recording is always best-effort (a failure there only costs a delayed
/// history-compaction opportunity, never correctness), so a failure surfaces
/// as `record_warning`, not an `Err` -- the missing-ancestor computation
/// still runs and its own failure IS a hard `Err` from the method itself.
pub struct FrontierEvaluation {
    pub missing: Vec<ChangeHash>,
    pub record_warning: Option<FrontierRecordWarning>,
}

pub struct FrontierRecordWarning {
    pub message: String,
}

/// `PeerReplicaEngine::check_causal_auth_monotonicity`'s result.
pub enum CausalAuthOutcome {
    /// A `PLACEHOLDER` auth stamp carries no real coordinate to check.
    Exempt,
    /// The pinned coordinate is non-decreasing relative to every parent's.
    Accepted,
    /// A parent's pinned auth coordinate could not be read (missing or
    /// unreadable) -- the change must be held, not admitted, until the full
    /// missing ancestor frontier (already computed here) arrives.
    Hold { missing_parents: Vec<ChangeHash> },
    /// The change pins an auth coordinate older than one of its parents'.
    Rejected {
        auth_seq: u64,
        auth_epoch: u64,
        max_parent_auth_seq: u64,
        max_parent_auth_epoch: u64,
    },
}

/// One change that became durable as a result of an admission call --
/// `change` itself, or an orphan its arrival promoted.
#[derive(Clone)]
pub struct AdmittedChange {
    pub hash: ChangeHash,
    pub lamport: u64,
    pub touched_paths: BTreeSet<String>,
}

/// `PeerReplicaEngine::admit_authenticated_change`'s result.
pub enum ChangeAdmissionOutcome {
    /// A permanent (namespace-collision/non-portable-path) or transient
    /// admission failure -- either way, this change is not stored.
    Rejected { reason: ChangeAdmissionRejection },
    /// The change was buffered as an orphan; its missing ancestry (already
    /// computed) should be requested.
    Orphaned { missing_parents: Vec<ChangeHash> },
    /// The change (and possibly other orphans it promoted) is now durable.
    Applied { admitted: Vec<AdmittedChange> },
}

pub enum ChangeAdmissionRejection {
    /// Permanent, already durably recorded by the store -- never
    /// re-requested from any peer on a future heads announce.
    ReservedNamespaceCollision { path: String },
    /// Same durability/permanence as `ReservedNamespaceCollision`, for a
    /// path that cannot be faithfully stored on every platform this group
    /// may sync to.
    NonPortablePath { path: String },
    /// An ordinary transient admission failure.
    StorageFailure { message: String },
}

/// `PeerReplicaEngine::holds_version_durably`'s result. Every non-`present`
/// case except an unreadable current-version record is a silent `false` (by
/// design, matching every other condition this check fails closed on); only
/// that one case previously logged, so it is the only one carrying a
/// warning here.
pub struct CustodyEvaluation {
    pub present: bool,
    pub warning: Option<CustodyWarning>,
}

pub struct CustodyWarning {
    pub message: String,
}
