//! Pure decision layer for `yadorilink-sync-core`'s retained-obligation
//! deletion rule (design `preimage-capture.md` §5.5/§12), extracted 7D-9D.
//!
//! # Why only part of `retained_obligation.rs` lives here
//!
//! The full module (`crates/yadorilink-sync-core/src/retained_obligation.rs`)
//! is a `retained_preimages`/`retained_preimage_deletion_intents` SQL-backed
//! state machine: schema creation, row CRUD, and filesystem-identity-checked
//! deletion all take a live `rusqlite::Connection` (or, for deletion, a real
//! filesystem handle) and stay in `yadorilink-sync-core` (eventually
//! `yadorilink-sync-sqlite`/`yadorilink-filesystem-sync` per the dependency
//! plan). What moves here is narrower and self-contained: the read-only
//! three-precondition judgment at the center of automatic deletion
//! (`evaluate_deletion` in the sync-core module) does not itself need a
//! `Connection` -- it combines facts a caller has *already* fetched (the
//! obligation row's own fields, a freshly observed fingerprint comparison,
//! and two durability-proof booleans) into a `DeletionDecision`. Splitting
//! it into a `Connection`-free "pre-durability guards" stage and a
//! `Connection`-free "final writer-exclusion judgment" stage -- with the two
//! SQL-backed durability-proof reads staying in `yadorilink-sync-core`,
//! sandwiched between the two calls into this module -- preserves the
//! original function's exact short-circuiting (a durability query never
//! runs once an earlier guard has already resolved a `Retain`) while making
//! the actual policy (grace window, fingerprint-change, capture-pairing,
//! writer-exclusion) independently unit-testable with no database at all.
//! See `yadorilink-sync-core::retained_obligation::evaluate_deletion` for
//! the orchestration that stitches these two stages back together around
//! its own SQL reads.

use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};

use crate::error::ReplicaEngineError;

/// Design §5.5's three lifecycle states (the initial-retention-policy table
/// in §12 names a fourth row, "capacity limit reached", but that one is
/// deliberately not a `state` value here -- it is an orthogonal flag on the
/// full obligation row in `yadorilink-sync-core`, not part of this decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationState {
    /// Not yet known to differ from what materialization originally
    /// observed, and not yet captured. §12: "retain 24h; any change
    /// reclassifies it divergent." Deletion is never eligible from this
    /// state: without a captured change there is nothing durability could
    /// even be proven about (see [`RetentionReason::NoCapturedChange`]).
    KnownOld,
    /// Either a late write was observed after custody transfer, or the
    /// object has been captured and authored (or both -- authoring always
    /// implies this state). §12: "retain 24h after DAG representation and
    /// required conflict copy are durable."
    Divergent,
    /// This device can no longer prove authorization to act on this
    /// obligation. Terminal: never re-enters `KnownOld`/`Divergent`, and
    /// never automatically deleted -- §12: "`LocalRecoveryOnly` until
    /// operator export/restore/delete."
    LocalRecoveryOnly,
}

impl ObligationState {
    pub fn as_str(self) -> &'static str {
        match self {
            ObligationState::KnownOld => "known_old",
            ObligationState::Divergent => "divergent",
            ObligationState::LocalRecoveryOnly => "local_recovery_only",
        }
    }

    /// Fail-closed by construction: an unrecognized string is an `Err`, not
    /// a silently-assumed default state. Every caller in `yadorilink-sync-core`
    /// reads a row through `get`/`create`/the `record_*` functions, all of
    /// which propagate this as a hard error rather than falling back to
    /// treating an undecodable state as safe to delete.
    pub fn from_str(s: &str) -> Result<Self, ReplicaEngineError> {
        match s {
            "known_old" => Ok(ObligationState::KnownOld),
            "divergent" => Ok(ObligationState::Divergent),
            "local_recovery_only" => Ok(ObligationState::LocalRecoveryOnly),
            other => Err(ReplicaEngineError::CorruptState(format!(
                "retained_preimages.state {other:?} is not a recognized obligation state"
            ))),
        }
    }
}

/// Why [`evaluate_deletion_pre_durability`]/[`evaluate_deletion_final_step`]
/// refused to call an obligation eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionReason {
    /// [`ObligationState::LocalRecoveryOnly`] -- never automatically deleted.
    LocalRecoveryOnly,
    /// `now_unix_nanos < retain_until_unix_nanos`.
    GraceWindowNotExpired,
    /// No fingerprint was ever recorded, or the freshly observed one does
    /// not match `last_fingerprint`.
    FingerprintChanged,
    /// `last_captured_change_hash`/`last_captured_version_hash` are both
    /// absent: either nothing has been authored yet, or a late write most
    /// recently cleared a stale pairing left by an earlier capture -- either
    /// way, durability cannot even be checked until a fresh capture
    /// establishes one for the content this obligation currently holds.
    NoCapturedChange,
    /// The DAG-representation durability leg did not hold.
    DagRepresentationUnproven,
    /// The required-conflict-copy durability leg did not hold.
    ConflictCopyUnproven,
    /// The custody object cannot be bound to a durable filesystem identity,
    /// so an identity-checked unlink cannot be authorized. Decided in
    /// `yadorilink-sync-core`'s own filesystem-identity-checked deletion
    /// path, not by either function in this module -- included here only
    /// because it is one more `RetentionReason` value that path reports.
    FilesystemIdentityUnproven,
    /// [`WriterExclusionProven::writer_exclusion_proven`] returned `false`:
    /// this device cannot prove no other writer could still be authoring
    /// content derived from this retained artifact.
    WriterExclusionUnproven,
}

/// Proof that no other writer -- anywhere in the group, not just on this
/// device -- could still be mid-authoring content that depends on the
/// retained artifact a deletion decision is about to declare eligible.
///
/// Deliberately a SEPARATE guarantee from custody confirmation: custody
/// proves some other device holds a durable REPLICA of already-captured
/// content, which says nothing about whether a writer (on this device or
/// another) could still be producing NEW content whose history depends on
/// the bytes about to be reclaimed.
pub trait WriterExclusionProven {
    /// `true` only if this device can prove, right now, that no writer
    /// anywhere in `group_id` could still be authoring content derived from
    /// `retained_id`'s currently captured content. Fails closed: any
    /// implementation that cannot positively establish this must return
    /// `false`, never `true` on absence of evidence.
    fn writer_exclusion_proven(&self, group_id: &str, retained_id: &str) -> bool;
}

/// The only implementation that exists today. Always `false` -- this
/// codebase has no election/leadership mechanism yet that proves writer
/// exclusion for a specific retained artifact. Retained-artifact
/// auto-deletion must stay closed until a real implementation replaces this
/// one -- see [`WriterExclusionProven`]'s own doc comment for what such an
/// implementation would need to prove.
pub struct NoWriterExclusionProof;

impl WriterExclusionProven for NoWriterExclusionProof {
    fn writer_exclusion_proven(&self, _group_id: &str, _retained_id: &str) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionDecision {
    Retain(RetentionReason),
    Eligible,
}

/// What [`evaluate_deletion_pre_durability`] resolved: either the decision
/// is already final (no durability proof is even reachable), or every guard
/// that needs no SQL has passed and the caller must now prove both
/// durability legs for the returned `(captured_change_hash,
/// captured_version_hash)` pair before calling
/// [`evaluate_deletion_final_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreDurabilityOutcome {
    Decided(DeletionDecision),
    NeedsDurabilityProof { captured_change_hash: ChangeHash, captured_version_hash: VersionHash },
}

/// The read-only guards at the front of automatic deletion that need no SQL
/// at all: terminal state, grace-window expiry, fingerprint-change, and
/// capture pairing. Every one of these was checked, in this exact order,
/// inside the original single `evaluate_deletion` function before it ever
/// touched a `Connection` -- the order matters, because it is what lets a
/// caller skip the (comparatively expensive, and itself fallible on corrupt
/// stored data) durability-proof SQL reads whenever an earlier guard already
/// settles the answer.
///
/// `fingerprint_matches` is a plain bool rather than the two
/// `StabilityFingerprint` values themselves: this crate must not depend on
/// `yadorilink-filesystem-sync` (which defines that type and itself depends
/// on this crate), so the caller compares the recorded and freshly observed
/// fingerprints and reports only the boolean result.
pub fn evaluate_deletion_pre_durability(
    retained_id: &str,
    state: ObligationState,
    retain_until_unix_nanos: i64,
    now_unix_nanos: i64,
    fingerprint_matches: bool,
    last_captured_change_hash: Option<ChangeHash>,
    last_captured_version_hash: Option<VersionHash>,
) -> Result<PreDurabilityOutcome, ReplicaEngineError> {
    if state == ObligationState::LocalRecoveryOnly {
        return Ok(PreDurabilityOutcome::Decided(DeletionDecision::Retain(
            RetentionReason::LocalRecoveryOnly,
        )));
    }
    if now_unix_nanos < retain_until_unix_nanos {
        return Ok(PreDurabilityOutcome::Decided(DeletionDecision::Retain(
            RetentionReason::GraceWindowNotExpired,
        )));
    }
    if !fingerprint_matches {
        return Ok(PreDurabilityOutcome::Decided(DeletionDecision::Retain(
            RetentionReason::FingerprintChanged,
        )));
    }
    // A capture always writes or clears both hashes together (see
    // `yadorilink-sync-core::retained_obligation`'s `record_late_write`/
    // `record_captured_change`) -- exactly one being set means whatever
    // wrote this row broke that invariant, which this function must not
    // paper over by guessing which half to trust.
    match (last_captured_change_hash, last_captured_version_hash) {
        (Some(change_hash), Some(version_hash)) => Ok(PreDurabilityOutcome::NeedsDurabilityProof {
            captured_change_hash: change_hash,
            captured_version_hash: version_hash,
        }),
        (None, None) => {
            Ok(PreDurabilityOutcome::Decided(DeletionDecision::Retain(RetentionReason::NoCapturedChange)))
        }
        _ => Err(ReplicaEngineError::CorruptState(format!(
            "retained obligation {retained_id} has last_captured_change_hash and \
             last_captured_version_hash set independently -- they must always be written \
             together"
        ))),
    }
}

/// The final step of the deletion judgment, run only after the caller has
/// independently proven both durability legs true (via SQL, in
/// `yadorilink-sync-core`) for the pair [`evaluate_deletion_pre_durability`]
/// returned. Writer-exclusion is checked here rather than folded into the
/// pre-durability stage because it is a distinct, independently-pluggable
/// judgment (see [`WriterExclusionProven`]) that has nothing to do with the
/// obligation row's own recorded state -- unlike the pre-durability guards,
/// it does not gate which SQL the caller needs to run next, so it is not
/// itself part of that short-circuiting order.
pub fn evaluate_deletion_final_step(
    group_id: &str,
    retained_id: &str,
    writer_exclusion: &dyn WriterExclusionProven,
) -> DeletionDecision {
    if !writer_exclusion.writer_exclusion_proven(group_id, retained_id) {
        return DeletionDecision::Retain(RetentionReason::WriterExclusionUnproven);
    }
    DeletionDecision::Eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change_hash(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    fn version_hash(byte: u8) -> VersionHash {
        VersionHash([byte; 32])
    }

    struct AlwaysProvenWriterExclusion;
    impl WriterExclusionProven for AlwaysProvenWriterExclusion {
        fn writer_exclusion_proven(&self, _group_id: &str, _retained_id: &str) -> bool {
            true
        }
    }

    #[test]
    fn obligation_state_round_trips_through_its_string_encoding() {
        for state in [ObligationState::KnownOld, ObligationState::Divergent, ObligationState::LocalRecoveryOnly] {
            assert_eq!(ObligationState::from_str(state.as_str()).unwrap(), state);
        }
    }

    #[test]
    fn obligation_state_from_str_rejects_an_unrecognized_value() {
        assert!(ObligationState::from_str("not_a_real_state").is_err());
    }

    #[test]
    fn local_recovery_only_is_retained_regardless_of_every_other_input() {
        let outcome = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::LocalRecoveryOnly,
            0,
            i64::MAX,
            true,
            Some(change_hash(1)),
            Some(version_hash(1)),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PreDurabilityOutcome::Decided(DeletionDecision::Retain(RetentionReason::LocalRecoveryOnly))
        );
    }

    #[test]
    fn grace_window_not_yet_expired_is_retained_before_any_other_guard() {
        let outcome = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::Divergent,
            /* retain_until */ 1_000,
            /* now */ 999,
            true,
            Some(change_hash(1)),
            Some(version_hash(1)),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PreDurabilityOutcome::Decided(DeletionDecision::Retain(RetentionReason::GraceWindowNotExpired))
        );
    }

    #[test]
    fn a_fingerprint_mismatch_is_retained_even_past_grace_expiry() {
        let outcome = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::Divergent,
            0,
            1_000,
            false,
            Some(change_hash(1)),
            Some(version_hash(1)),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PreDurabilityOutcome::Decided(DeletionDecision::Retain(RetentionReason::FingerprintChanged))
        );
    }

    #[test]
    fn no_captured_change_is_retained_rather_than_treated_as_a_durability_failure() {
        let outcome =
            evaluate_deletion_pre_durability("r1", ObligationState::Divergent, 0, 1_000, true, None, None)
                .unwrap();
        assert_eq!(
            outcome,
            PreDurabilityOutcome::Decided(DeletionDecision::Retain(RetentionReason::NoCapturedChange))
        );
    }

    #[test]
    fn an_independently_set_capture_pairing_is_a_hard_corrupt_state_error() {
        let err = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::Divergent,
            0,
            1_000,
            true,
            Some(change_hash(1)),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ReplicaEngineError::CorruptState(_)));

        let err = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::Divergent,
            0,
            1_000,
            true,
            None,
            Some(version_hash(1)),
        )
        .unwrap_err();
        assert!(matches!(err, ReplicaEngineError::CorruptState(_)));
    }

    #[test]
    fn every_guard_passing_hands_the_captured_pair_to_the_caller_for_durability_proof() {
        let outcome = evaluate_deletion_pre_durability(
            "r1",
            ObligationState::Divergent,
            0,
            1_000,
            true,
            Some(change_hash(7)),
            Some(version_hash(9)),
        )
        .unwrap();
        assert_eq!(
            outcome,
            PreDurabilityOutcome::NeedsDurabilityProof {
                captured_change_hash: change_hash(7),
                captured_version_hash: version_hash(9),
            }
        );
    }

    #[test]
    fn final_step_is_eligible_only_once_writer_exclusion_is_proven() {
        assert_eq!(
            evaluate_deletion_final_step("g", "r1", &NoWriterExclusionProof),
            DeletionDecision::Retain(RetentionReason::WriterExclusionUnproven)
        );
        assert_eq!(
            evaluate_deletion_final_step("g", "r1", &AlwaysProvenWriterExclusion),
            DeletionDecision::Eligible
        );
    }
}
