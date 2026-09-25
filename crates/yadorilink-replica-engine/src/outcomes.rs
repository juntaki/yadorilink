//! Semantic outcome types for `PeerReplicaEngine`'s own methods.

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
    /// The Change's own author chain refuses it — equivocation, a forked
    /// author history, a skipped sequence, or a claim to continue a chain it
    /// does not descend. Permanent, like the two path rejections above:
    /// re-delivering the identical Change can never produce another verdict.
    AuthorChainRefused { reason: String },
    /// The Change was written on a different history than this replica's:
    /// its author holds a history base this replica does not. Permanent in
    /// the same way -- the Change can never become admissible here, and its
    /// author's way forward is a re-bootstrap onto this history rather than
    /// a retry of these bytes.
    ForeignHistoryBase { reason: String },
    /// One of the Change's DAG parents is permanently refused here, so the
    /// Change can never have its ancestry. Permanent for as long as that
    /// parent's refusal stands.
    BehindRejectedParent { reason: String },
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
