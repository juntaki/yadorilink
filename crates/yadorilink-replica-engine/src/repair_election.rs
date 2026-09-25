//! Canonical writer-set snapshot and deterministic, leaderless election
//! ranking for background maintenance operations (currently: retroactive
//! conflict-copy repair) that must be safe to run without ever depending
//! on one specific device remaining available. # Why this needs to be its
//! own module If only the current winning path head's own author could
//! repair a late-arriving conflict-copy obligation, then once that device
//! became permanently unavailable (removed, revoked, crashed, or simply
//! never reconnecting), nothing else would step in and the obligation
//! would never resolve — a silent, permanent correctness gap, not just a
//! delay. The answer is not to pick a single deterministic
//! *fallback* device (that still depends on one device's availability,
//! just a different one, and still can't tell a genuinely-departed device
//! from one that is merely slow). It is to make maintenance operations
//! something *any* currently authorized writer may publish — a
//! cryptographically verifiable, idempotent fact any replica can check
//! independently — with election reduced to an optimization that only cuts
//! down on duplicate work, never a correctness or liveness dependency.
//! Repair carriers use this ranking only to stagger duplicate work. Every
//! authorized writer eventually becomes eligible while an obligation's DAG
//! frontier remains unchanged, so election is never a liveness dependency.

use sha2::{Digest, Sha256};

use yadorilink_replica_domain::change::RepairObligation;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId, SyncPath};

/// One device this group's signed policy currently (or, for
/// `GroupPolicyState::writers_at`-style historical queries, as of a given
/// sequence) grants write access to, together with the signing-key
/// fingerprint its Grant bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorizedWriter {
    pub device_id: String,
    pub signing_key_fingerprint: [u8; 32],
}

/// The stable logical identity of one retroactive conflict-copy repair
/// obligation: preserving `losing_change`'s content, which was concurrent
/// with (and lost to) the winner at `source_path`. Two devices that
/// independently notice and repair the SAME obligation compute the same ID
/// — this is what lets duplicate carriers be safe (the existing
/// `conflict_copy_provenance` table already keys on exactly these three
/// fields) and lets every device rank the same candidate writers for the
/// same obligation identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepairObligationId(pub [u8; 32]);

const OBLIGATION_DOMAIN_TAG: &[u8] = b"yadorilink-retroactive-repair-v1";
const OBLIGATION_SET_DOMAIN_TAG: &[u8] = b"yadorilink-retroactive-repair-set-v1";

impl RepairObligationId {
    /// Takes the same normalized, already-validated types the rest of the
    /// DAG/change machinery uses (`FolderGroupId`, `SyncPath`, `ChangeHash`)
    /// rather than raw strings/bytes — this ID must be byte-identical across
    /// every replica, so a caller cannot pass an unnormalized path or an
    /// unvalidated group id that happens to `Display` the same but isn't
    /// the same underlying value.
    pub fn compute(
        group_id: &FolderGroupId,
        source_path: &SyncPath,
        losing_change: &ChangeHash,
    ) -> Self {
        let group_id = group_id.as_str();
        let source_path = source_path.as_str();
        let mut hasher = Sha256::new();
        hasher.update(OBLIGATION_DOMAIN_TAG);
        hasher.update((group_id.len() as u32).to_be_bytes());
        hasher.update(group_id.as_bytes());
        hasher.update((source_path.len() as u32).to_be_bytes());
        hasher.update(source_path.as_bytes());
        hasher.update(losing_change.as_bytes());
        Self(hasher.finalize().into())
    }

    /// One identity for a whole planned obligation SET, so a repair round
    /// elects a single primary for the entire carrier it is about to
    /// publish. Ranking per individual obligation instead put a different
    /// rank-0 device behind each obligation of the same frontier, so
    /// several devices published concurrent carriers for one merge round —
    /// each fork re-opened the frontier, reset every other device's
    /// failover window, and stretched the drain of a busy group's repair
    /// backlog from one round into minutes (measured in
    /// `row14_strict_acceptance`). The set derives deterministically from
    /// the retained DAG frontier (`plan_retroactive_merge`'s derivation is
    /// causally scoped, never disk-scoped), so every replica that sees the
    /// same frontier computes the same set, the same ID, and therefore the
    /// same single primary; the per-rank failover stagger is unchanged.
    /// The caller passes the plan's obligations, which are already in the
    /// carrier's canonical (sorted, deduplicated) order.
    pub fn compute_set(group_id: &FolderGroupId, obligations: &[RepairObligation]) -> Self {
        let group = group_id.as_str();
        let mut hasher = Sha256::new();
        hasher.update(OBLIGATION_SET_DOMAIN_TAG);
        hasher.update((group.len() as u32).to_be_bytes());
        hasher.update(group.as_bytes());
        hasher.update((obligations.len() as u32).to_be_bytes());
        for obligation in obligations {
            let id = Self::compute(group_id, &obligation.source_path, &obligation.losing_change);
            hasher.update(id.0);
        }
        Self(hasher.finalize().into())
    }
}

const ELECTION_DOMAIN_TAG: &[u8] = b"yl-repair-election-v1";

/// The rendezvous-hash score binding one writer to one obligation under one
/// policy head. Exposed only to this crate's own tests: what must be
/// guaranteed is that the score is bound to (changes with) each of its
/// inputs, not that any particular relationship holds between two rankings
/// for two different inputs — a fixed reference-vector test pins the actual
/// ranking behavior; this lets a test isolate "does changing input X change
/// the score" without asserting anything about final rank order, which
/// rendezvous hashing does not promise to change on every input tweak (three
/// items have only six possible orderings).
#[cfg(test)]
fn election_score(
    policy_head: &[u8; 32],
    obligation: RepairObligationId,
    writer: &AuthorizedWriter,
) -> [u8; 32] {
    compute_score(policy_head, obligation, writer)
}

fn compute_score(
    policy_head: &[u8; 32],
    obligation: RepairObligationId,
    writer: &AuthorizedWriter,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ELECTION_DOMAIN_TAG);
    hasher.update(policy_head);
    hasher.update(obligation.0);
    hasher.update((writer.device_id.len() as u32).to_be_bytes());
    hasher.update(writer.device_id.as_bytes());
    hasher.update(writer.signing_key_fingerprint);
    hasher.finalize().into()
}

/// Rendezvous-hashes `writers` for `obligation` under `policy_head`, sorted
/// by descending score — index 0 is rank 0 (primary), index 1 is the first
/// failover, and so on. Every replica that has verified the same
/// `policy_head` computes the identical ranking for the identical
/// obligation, with no communication and no single device's participation
/// required: the whole point is that ranking is a pure function of already
/// signed, already-agreed-upon inputs, never of runtime liveness
/// information.
///
/// Binding the score to `policy_head` (not just the obligation) is
/// deliberate: it re-derives a fresh ranking on every policy change, so a
/// revoked device's rank-0 claim doesn't outlive the revocation by luck of
/// hash, and a newly granted writer is immediately eligible to be elected
/// rather than only after some unrelated re-ranking event.
pub fn rank_writers_for_obligation(
    policy_head: &[u8; 32],
    obligation: RepairObligationId,
    writers: &[AuthorizedWriter],
) -> Vec<AuthorizedWriter> {
    let mut scored: Vec<([u8; 32], AuthorizedWriter)> = writers
        .iter()
        .map(|writer| (compute_score(policy_head, obligation, writer), writer.clone()))
        .collect();
    // Descending score; ties are impossible in practice (a SHA-256 collision
    // between two distinct writer/obligation/policy-head inputs), but break
    // deterministically by device_id if it ever happened, rather than by
    // whatever order `writers` happened to arrive in.
    scored.sort_by(|(score_a, writer_a), (score_b, writer_b)| {
        score_b.cmp(score_a).then_with(|| writer_a.device_id.cmp(&writer_b.device_id))
    });
    scored.into_iter().map(|(_, writer)| writer).collect()
}

/// Why constructing a [`RepairElectionContext`] was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairElectionError {
    /// The candidate writer set contained the same `device_id` more than
    /// once — a caller bug (a correct `GroupPolicyState::writers_at` never
    /// produces this, since it replays a de-duplicating Grant/Revoke map),
    /// but one this constructor refuses to silently paper over by keeping
    /// only one of the entries.
    DuplicateWriter { device_id: String },
}

impl std::fmt::Display for RepairElectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepairElectionError::DuplicateWriter { device_id } => {
                write!(f, "writer set contains device_id {device_id:?} more than once")
            }
        }
    }
}

impl std::error::Error for RepairElectionError {}

/// Bundles one device's view of a single obligation's election: the ranking
/// it computed (see [`rank_writers_for_obligation`]), the policy head that
/// ranking was computed from, and this device's own identity.
///
/// `expected_policy_head` is NOT an authorization pin -- writer
/// authorization for the repair carrier itself happens only at checkpoint
/// issuance, same as any
/// other Change. It exists purely so the repair transaction can re-check,
/// immediately before it commits, that the policy this device elected
/// itself under is still the current one -- a liveness/consistency
/// re-check for the election, not a security boundary.
///
/// Fields are private and the ranking is always derived internally from
/// `expected_policy_head` — never taken as a separate caller-supplied
/// argument — so it is impossible to construct a context whose
/// `ranked_writers` was computed against a different policy head than
/// `expected_policy_head` names.
#[derive(Debug, Clone)]
pub struct RepairElectionContext {
    expected_policy_head: [u8; 32],
    local_device_id: String,
    local_key_fingerprint: [u8; 32],
    ranked_writers: Vec<AuthorizedWriter>,
}

impl RepairElectionContext {
    /// Ranks `writers` for `obligation` under `expected_policy_head` and
    /// bundles the result with this device's own identity. Rejects a
    /// `writers` set containing a duplicate `device_id` rather than silently
    /// deduplicating it, since a duplicate can only mean the caller passed
    /// something other than a genuine `GroupPolicyState` writer snapshot.
    pub fn new(
        expected_policy_head: [u8; 32],
        obligation: RepairObligationId,
        writers: Vec<AuthorizedWriter>,
        local_device_id: String,
        local_key_fingerprint: [u8; 32],
    ) -> Result<Self, RepairElectionError> {
        let mut seen = std::collections::HashSet::with_capacity(writers.len());
        for writer in &writers {
            if !seen.insert(writer.device_id.as_str()) {
                return Err(RepairElectionError::DuplicateWriter {
                    device_id: writer.device_id.clone(),
                });
            }
        }
        let ranked_writers =
            rank_writers_for_obligation(&expected_policy_head, obligation, &writers);
        Ok(Self { expected_policy_head, local_device_id, local_key_fingerprint, ranked_writers })
    }

    pub fn expected_policy_head(&self) -> [u8; 32] {
        self.expected_policy_head
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub fn local_key_fingerprint(&self) -> [u8; 32] {
        self.local_key_fingerprint
    }

    pub fn ranked_writers(&self) -> &[AuthorizedWriter] {
        &self.ranked_writers
    }

    /// This device's rank (0 = primary, elects first) among
    /// `ranked_writers`, or `None` if the local device is not a currently
    /// authorized writer for this obligation at all.
    ///
    /// Matches on BOTH `device_id` and `signing_key_fingerprint`, not
    /// `device_id` alone: a process presenting the right device_id but a
    /// different signing key than the one the group's policy actually
    /// granted is not the authorized writer, regardless of what it calls
    /// itself. Checkpoint issuance still re-checks writer status
    /// independently before the repair carrier's Change can ever become
    /// externally observable, but this keeps an unauthorized process from
    /// even believing it holds rank 0 and repeatedly attempting (and
    /// failing) the primary's work.
    pub fn local_rank(&self) -> Option<usize> {
        self.ranked_writers.iter().position(|writer| {
            writer.device_id == self.local_device_id
                && writer.signing_key_fingerprint == self.local_key_fingerprint
        })
    }
}

#[cfg(test)]
mod tests;
