//! Canonical writer-set snapshot and deterministic, leaderless election
//! ranking for background maintenance operations (currently: retroactive
//! conflict-copy repair) that must be safe to run without ever depending on
//! one specific device remaining available.
//!
//! # Why this needs to be its own module
//!
//! The retroactive conflict-copy repair mechanism's planner today elects
//! only the current winning path head's own author to repair a
//! late-arriving conflict-copy obligation. If that device is ever
//! permanently unavailable (removed, revoked, crashed, or simply never
//! reconnects), nothing else steps in, and the obligation is never resolved
//! — a real, silent, permanent correctness gap, not just a delay (tracked in
//! issue #24).
//!
//! The fix is not to pick a single deterministic *fallback* device (that
//! still depends on one device's availability, just a different one, and
//! still can't tell a genuinely-departed device from one that is merely
//! slow). It is to make maintenance operations something *any* currently
//! authorized writer may publish — a cryptographically verifiable, idempotent
//! fact any replica can check independently — with election reduced to an
//! optimization that only cuts down on duplicate work, never a correctness
//! or liveness dependency.
//!
//! That requires every replica to compute the *same* writer set from the
//! *same* signed policy state, and the *same* deterministic ranking over it,
//! given only public, already-verified inputs (the policy head and the
//! obligation being repaired) — this module is exactly that shared
//! computation, kept dependency-light so both `yadorilink-sync-core`
//! (validates and plans repairs) and `yadorilink-daemon` (owns
//! `GroupPolicyState`, the signed source of truth for a group's writer set)
//! can use it without a crate-dependency cycle.
//!
//! Repair carriers use this ranking only to stagger duplicate work. Every
//! authorized writer eventually becomes eligible while an obligation's DAG
//! frontier remains unchanged, so election is never a liveness dependency.

use sha2::{Digest, Sha256};

use yadorilink_replica_domain::change::{ChangeAuth, RepairObligation};
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId, SyncPath};

/// One device this group's signed policy currently (or, for
/// `GroupPolicyState::writers_at`-style historical queries, as of a given
/// sequence) grants write access to, together with the signing-key
/// fingerprint its Grant bound — the same binding `author_was_writer_at`
/// checks a change's signer against.
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
/// it computed (see [`rank_writers_for_obligation`]), the `ChangeAuth` a
/// repair carrier must be stamped with to be valid against the policy head
/// that ranking was computed from, and this device's own identity.
///
/// Fields are private and the ranking is always derived internally from
/// `expected_auth`'s own `policy_head_hash` — never taken as a separate
/// caller-supplied argument — so it is impossible to construct a context
/// whose `ranked_writers` was computed against a different policy head than
/// `expected_auth` names. Carried end-to-end from election through signing
/// so the repair transaction can re-check, immediately before it commits,
/// that the policy this device elected itself under is still the current
/// one.
#[derive(Debug, Clone)]
pub struct RepairElectionContext {
    expected_auth: ChangeAuth,
    local_device_id: String,
    local_key_fingerprint: [u8; 32],
    ranked_writers: Vec<AuthorizedWriter>,
}

impl RepairElectionContext {
    /// Ranks `writers` for `obligation` under `expected_auth.policy_head_hash`
    /// and bundles the result with this device's own identity. Rejects a
    /// `writers` set containing a duplicate `device_id` rather than silently
    /// deduplicating it, since a duplicate can only mean the caller passed
    /// something other than a genuine `GroupPolicyState` writer snapshot.
    pub fn new(
        expected_auth: ChangeAuth,
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
            rank_writers_for_obligation(&expected_auth.policy_head_hash, obligation, &writers);
        Ok(Self { expected_auth, local_device_id, local_key_fingerprint, ranked_writers })
    }

    pub fn expected_auth(&self) -> ChangeAuth {
        self.expected_auth
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
    /// itself — the same binding `author_was_writer_at` enforces for
    /// ordinary changes. Final signing still re-checks authorization, but
    /// this keeps an unauthorized process from even believing it holds
    /// rank 0 and repeatedly attempting (and failing) the primary's work.
    pub fn local_rank(&self) -> Option<usize> {
        self.ranked_writers.iter().position(|writer| {
            writer.device_id == self.local_device_id
                && writer.signing_key_fingerprint == self.local_key_fingerprint
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer(device_id: &str, fingerprint_byte: u8) -> AuthorizedWriter {
        AuthorizedWriter {
            device_id: device_id.to_string(),
            signing_key_fingerprint: [fingerprint_byte; 32],
        }
    }

    fn group(name: &str) -> FolderGroupId {
        FolderGroupId(name.to_string())
    }

    fn path(name: &str) -> SyncPath {
        SyncPath(name.to_string())
    }

    #[test]
    fn obligation_id_is_stable_and_distinguishes_its_inputs() {
        let losing_a = ChangeHash([1u8; 32]);
        let losing_b = ChangeHash([2u8; 32]);
        let id = RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_a);
        assert_eq!(id, RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_a));
        assert_ne!(
            id,
            RepairObligationId::compute(&group("other-group"), &path("path.bin"), &losing_a)
        );
        assert_ne!(id, RepairObligationId::compute(&group("group"), &path("other.bin"), &losing_a));
        assert_ne!(id, RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_b));
    }

    #[test]
    fn ranking_is_a_permutation_of_the_input_writers() {
        let policy_head = [7u8; 32];
        let obligation =
            RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
        let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
        let ranked = rank_writers_for_obligation(&policy_head, obligation, &writers);
        assert_eq!(ranked.len(), writers.len());
        for w in &writers {
            assert!(ranked.contains(w));
        }
    }

    #[test]
    fn ranking_is_deterministic_across_independent_calls_and_input_order() {
        let policy_head = [7u8; 32];
        let obligation =
            RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
        let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
        let mut shuffled = writers.clone();
        shuffled.reverse();

        let ranked_1 = rank_writers_for_obligation(&policy_head, obligation, &writers);
        let ranked_2 = rank_writers_for_obligation(&policy_head, obligation, &shuffled);
        assert_eq!(ranked_1, ranked_2, "ranking must not depend on the caller's input order");
    }

    /// Pins the actual ranking `rank_writers_for_obligation` produces for a
    /// fixed set of inputs, rather than asserting a property (like "changes
    /// with policy_head") rendezvous hashing does not actually guarantee for
    /// an arbitrary pair of inputs. If this ever fails after a genuinely
    /// intended algorithm change, recompute and update the expected order
    /// deliberately -- do not "fix" it by loosening the assertion.
    #[test]
    fn ranking_matches_a_fixed_reference_vector() {
        let policy_head = [0x11u8; 32];
        let obligation = RepairObligationId::compute(
            &group("group-ref"),
            &path("ref/path.bin"),
            &ChangeHash([0x22u8; 32]),
        );
        let writers =
            vec![writer("device-a", 0xAA), writer("device-b", 0xBB), writer("device-c", 0xCC)];
        let ranked = rank_writers_for_obligation(&policy_head, obligation, &writers);
        let ranked_ids: Vec<&str> = ranked.iter().map(|w| w.device_id.as_str()).collect();
        assert_eq!(ranked_ids, vec!["device-b", "device-a", "device-c"]);
    }

    #[test]
    fn score_is_bound_to_policy_head() {
        let obligation =
            RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
        let w = writer("device-a", 1);
        assert_ne!(
            election_score(&[1u8; 32], obligation, &w),
            election_score(&[2u8; 32], obligation, &w)
        );
    }

    #[test]
    fn score_is_bound_to_obligation() {
        let policy_head = [7u8; 32];
        let obligation_1 = RepairObligationId::compute(
            &group("group"),
            &path("path-1.bin"),
            &ChangeHash([9u8; 32]),
        );
        let obligation_2 = RepairObligationId::compute(
            &group("group"),
            &path("path-2.bin"),
            &ChangeHash([9u8; 32]),
        );
        let w = writer("device-a", 1);
        assert_ne!(
            election_score(&policy_head, obligation_1, &w),
            election_score(&policy_head, obligation_2, &w)
        );
    }

    #[test]
    fn score_is_bound_to_writer_identity_and_fingerprint() {
        let policy_head = [7u8; 32];
        let obligation =
            RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
        let a = writer("device-a", 1);
        let b = writer("device-b", 1);
        let a_other_key = writer("device-a", 2);
        assert_ne!(
            election_score(&policy_head, obligation, &a),
            election_score(&policy_head, obligation, &b),
            "score must depend on device_id"
        );
        assert_ne!(
            election_score(&policy_head, obligation, &a),
            election_score(&policy_head, obligation, &a_other_key),
            "score must depend on the bound signing-key fingerprint, not just device_id"
        );
    }

    fn obligation_fixture() -> RepairObligationId {
        RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]))
    }

    #[test]
    fn context_new_rejects_a_duplicate_device_id() {
        let writers = vec![writer("device-a", 1), writer("device-a", 2)];
        let result = RepairElectionContext::new(
            ChangeAuth::PLACEHOLDER,
            obligation_fixture(),
            writers,
            "device-a".to_string(),
            [1u8; 32],
        );
        assert_eq!(
            result.unwrap_err(),
            RepairElectionError::DuplicateWriter { device_id: "device-a".to_string() }
        );
    }

    #[test]
    fn context_ranks_writers_against_expected_auths_own_policy_head() {
        let auth = ChangeAuth { auth_seq: 1, auth_epoch: 0, policy_head_hash: [7u8; 32] };
        let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
        let context = RepairElectionContext::new(
            auth,
            obligation_fixture(),
            writers.clone(),
            "device-a".to_string(),
            [1u8; 32],
        )
        .unwrap();
        assert_eq!(
            context.ranked_writers(),
            rank_writers_for_obligation(&auth.policy_head_hash, obligation_fixture(), &writers)
        );
        assert_eq!(context.expected_auth(), auth);
    }

    #[test]
    fn local_rank_finds_self_among_ranked_writers() {
        let writers = vec![writer("device-b", 2), writer("device-a", 1), writer("device-c", 3)];
        let context = RepairElectionContext::new(
            ChangeAuth::PLACEHOLDER,
            obligation_fixture(),
            writers,
            "device-a".to_string(),
            [1u8; 32],
        )
        .unwrap();
        assert_eq!(context.ranked_writers()[context.local_rank().unwrap()].device_id, "device-a");
    }

    #[test]
    fn local_rank_is_none_when_not_an_authorized_writer() {
        let context = RepairElectionContext::new(
            ChangeAuth::PLACEHOLDER,
            obligation_fixture(),
            vec![writer("device-a", 1)],
            "device-z".to_string(),
            [1u8; 32],
        )
        .unwrap();
        assert_eq!(context.local_rank(), None);
    }

    /// The liveness gap this whole module exists to close would reopen if a
    /// process presenting the right device_id but the WRONG signing key
    /// could still see itself as rank 0 and keep re-attempting a repair it
    /// isn't actually authorized for.
    #[test]
    fn local_rank_is_none_when_device_id_matches_but_fingerprint_differs() {
        let context = RepairElectionContext::new(
            ChangeAuth::PLACEHOLDER,
            obligation_fixture(),
            vec![writer("device-a", 1)],
            "device-a".to_string(),
            [0xFFu8; 32],
        )
        .unwrap();
        assert_eq!(context.local_rank(), None);
    }
}
