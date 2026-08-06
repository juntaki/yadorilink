//! Plain, `Connection`-free value types shared between
//! `yadorilink-sync-sqlite`'s `filesystem_transaction` row shapes and
//! `yadorilink-replica-engine`'s pure resolution-planning decisions.
//!
//! Hoisted out of `yadorilink-sync-sqlite::filesystem_transaction` (Phase
//! 7D-9D, sixth-pass follow-up): `yadorilink-sync-core::resolution_planning`'s
//! remaining pure functions (`resolution_to_group`, `slice_plan`,
//! `slice_reservation_requests`, `classify_epoch`, and others) are typed
//! directly against these types, and moving those functions to
//! `yadorilink-replica-engine` -- their required destination per
//! `docs/design/phase7d9-dependency-plan.md`'s 7D-9D routing rules -- needs
//! somewhere both `yadorilink-sync-sqlite` (which already depends on
//! `yadorilink-replica-engine`) and `yadorilink-replica-engine` itself can
//! reach them without either crate depending back on the other. Left
//! defined in `yadorilink-sync-sqlite`, that is a straight two-crate cycle,
//! not a "hard to decompose" case. This crate is the lowest shared
//! value-type crate in the whole graph -- the same role it already plays
//! for `session_state::VersionRecord`/`CurrentVersionRecord`/
//! `MaterializationPolicy`/`session_state::LinkGate`'s `DirtyPath`-shaped
//! siblings.
//!
//! Each type's SQL-string codec (`as_db_str`/`from_db_str`) deliberately
//! stays behind in `yadorilink-sync-sqlite::filesystem_transaction`, as a
//! small local trait implemented for the type there (not an inherent
//! `impl` here -- this crate no longer owns the type's defining crate, and
//! an inherent `impl` requires that). This preserves the exact
//! `Result<_, SyncSqliteError>` corrupt-row error path those functions
//! already had, rather than adopting this crate's own `session_state.rs`
//! module's panic-on-corrupt pattern for its own, unrelated db-string enums
//! -- swapping a legitimate error return for a panic on a corrupt-database
//! code path would be a real behavior change this hoist has no reason to
//! introduce.

/// What kind of destination one placement targets. A strict subset of
/// [`ReservationRole`] (no `SubtreeRoot`): a placement always targets one
/// concrete object, never a bare subtree-exclusion marker. The canonical
/// path, conflict-copy paths and retirement targets are the same three
/// kinds of concrete destination a reservation names, restated here for
/// what one epoch's `target_path` can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementRole {
    CanonicalPath,
    ConflictCopy,
    RetirementTarget,
}

/// Every state a placement epoch can be in, transcribed verbatim from a
/// fixed, externally-specified list — not this module's own synthesis,
/// unlike `yadorilink_sync_sqlite::filesystem_transaction::TransactionPhase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochState {
    Allocated,
    Preparing,
    PreparedArtifact,
    AwaitingReservation,
    Prepared,
    Committing,
    Committed,
    Quarantined,
    RequiresPhysicalRecovery,
    CustodyTransferred,
    AwaitingQuiescence,
    ClassifiedKnown,
    ClassifiedDivergent,
    AwaitingCaptureStorage,
    AwaitingCaptureAuthorization,
    CapturedChangeAuthored,
    LocalRecoveryOnly,
    Released,
    Completed,
    Blocked,
}

impl EpochState {
    /// Whether `self -> to` is a legal epoch transition, per the protocol
    /// sequence and its alternative-branch groupings
    /// (`Committed | Quarantined | RequiresPhysicalRecovery`,
    /// `ClassifiedKnown | ClassifiedDivergent`,
    /// `CapturedChangeAuthored | LocalRecoveryOnly`). Three groups are this
    /// module's own connective reading, not a transcription, and are
    /// called out below because a reviewer should be able to find exactly
    /// where the design text stops being explicit:
    ///
    /// - `AwaitingCaptureStorage`/`AwaitingCaptureAuthorization`: the
    ///   protocol does not state their relative order, so both are accepted as direct
    ///   successors of `ClassifiedDivergent`, and either may lead to
    ///   `CapturedChangeAuthored`/`LocalRecoveryOnly` directly, as well as
    ///   `AwaitingCaptureStorage -> AwaitingCaptureAuthorization` once
    ///   storage completes.
    /// - `Blocked`: has no reason column of its own on this table (unlike
    ///   the parent transaction's `blocked_reason`), and the design does
    ///   not say which states can reach it. Treated as reachable from any
    ///   non-terminal state, with no outgoing edge modeled here — recovery
    ///   (a separate, later phase) decides what happens to a blocked
    ///   epoch, not this transition table.
    /// - `(RequiresPhysicalRecovery, Committed)`: design §14.2's "complete
    ///   forward" verdict — late semantic recovery physically confirmed the
    ///   commit this epoch's own recorded expected identities describe
    ///   actually landed, so *this* epoch (not a fresh one) resumes the
    ///   ordinary post-commit pipeline it already models
    ///   (`CustodyTransferred` onward), using the displaced-generation and
    ///   causal-basis bookkeeping already on this row. The other two §14.2
    ///   verdicts — roll back, and convert a newly observed live object into
    ///   a new capture epoch — both end *this* epoch unsuccessfully instead:
    ///   the object still needs to reach its desired placement, and design
    ///   §8.1's own reasoning for why that is a fresh epoch's job, not this
    ///   one's, still holds for those two cases. They reach `Blocked`
    ///   through the generic `(_, Blocked)` rule below, now that
    ///   `RequiresPhysicalRecovery` is no longer terminal (see
    ///   [`is_terminal`][Self::is_terminal]) — the ordinary
    ///   `Blocked -> Planning` replan is what allocates the fresh epoch. A
    ///   future implementation of §14.2 must record, alongside whichever of
    ///   these two transitions it makes, which of the two verdicts it
    ///   reached and why — `Blocked` alone does not distinguish "rolled
    ///   back" from "converting to a capture epoch", and a verdict without a
    ///   reason is not much better than being stuck; this table only models
    ///   that the transition is legal, not what a caller must additionally
    ///   persist to make it auditable.
    /// - `(Committing, Prepared)`: the one other deliberate exception to
    ///   "no going backwards". The commit adapter's `NotStarted(RetryReason)`
    ///   outcome (`FilesystemCommitOutcome::NotStarted`, see §9.3) is a
    ///   proven no-op — the platform's exchange primitive is documented
    ///   atomic, so a failure there is a guarantee the on-disk state is
    ///   exactly what `Prepared` already recorded (displaced snapshot and
    ///   causal basis included), not merely "probably fine". Landing back on
    ///   `Prepared` — the same state, not a new one — is therefore the exact
    ///   fit: the epoch is once again ready to attempt commit from the
    ///   identical recorded snapshot, without re-running preparation.
    ///   This is available only to a caller that actually observed
    ///   `NotStarted` in memory; it is not implied by `Committing` alone.
    ///   A crash between the adapter call and the SQL transaction that would
    ///   record this transition leaves the epoch sitting at `Committing`
    ///   with no durable trace of which outcome fired — recovery cannot
    ///   trust an in-memory-only guarantee it never witnessed, so it must
    ///   treat any epoch still at `Committing` as outcome-unknown and route
    ///   it through `RequiresPhysicalRecovery` regardless of what the crashed
    ///   process actually saw. That residual crash window is not closable
    ///   without holding the commit's SQL write transaction open across the
    ///   platform syscall, which the short commit window's own latency and
    ///   single-writer-lock constraints (see the commit window's own
    ///   comments) already rule out elsewhere in this engine. A non-retryable
    ///   `RetryReason` (e.g. an unsupported volume or an ineligible object
    ///   kind) does not use this edge at all — the caller instead takes the
    ///   pre-existing `(Committing, Blocked)` edge and blocks the parent saga
    ///   through `set_transaction_phase`'s `blocked_reason`, since retrying
    ///   the identical plan would just fail again.
    pub fn can_transition_to(self, to: EpochState) -> bool {
        use EpochState::*;
        if self == to {
            return false;
        }
        if !self.is_terminal() && to == Blocked {
            return true;
        }
        matches!(
            (self, to),
            (Allocated, Preparing)
                | (Preparing, PreparedArtifact)
                | (PreparedArtifact, AwaitingReservation)
                | (AwaitingReservation, Prepared)
                | (Prepared, Committing)
                | (Committing, Committed)
                | (Committing, Quarantined)
                | (Committing, RequiresPhysicalRecovery)
                | (Committing, Prepared)
                | (RequiresPhysicalRecovery, Committed)
                | (Committed, CustodyTransferred)
                | (CustodyTransferred, AwaitingQuiescence)
                | (AwaitingQuiescence, ClassifiedKnown)
                | (AwaitingQuiescence, ClassifiedDivergent)
                | (ClassifiedKnown, Released)
                | (ClassifiedDivergent, AwaitingCaptureStorage)
                | (ClassifiedDivergent, AwaitingCaptureAuthorization)
                | (AwaitingCaptureStorage, AwaitingCaptureAuthorization)
                | (AwaitingCaptureStorage, CapturedChangeAuthored)
                | (AwaitingCaptureStorage, LocalRecoveryOnly)
                | (AwaitingCaptureAuthorization, CapturedChangeAuthored)
                | (AwaitingCaptureAuthorization, LocalRecoveryOnly)
                | (CapturedChangeAuthored, Released)
                | (LocalRecoveryOnly, Released)
                | (Released, Completed)
        )
    }

    /// Whether `self` is a settled epoch outcome that this table models no
    /// outgoing edge from — the same predicate `can_transition_to` uses to
    /// decide whether `Blocked` is still reachable, exposed so callers
    /// outside this table (namely the parent-completion invariant in
    /// `yadorilink_sync_sqlite::filesystem_transaction`'s
    /// `set_transaction_phase_unchecked`) can ask the identical question
    /// rather than re-deriving it.
    ///
    /// "Terminal" here is not a synonym for "successful": `Completed` is
    /// the only member that is also a saga-level success. The other two
    /// each represent a decision this table already considers final for
    /// that one epoch, made for a different reason each time --
    /// - `Quarantined`: a deliberate, legitimate outcome for a
    ///   preserved-but-unresolved object, not a failure of the saga around
    ///   it.
    /// - `Blocked`: the saga-level replan this leads to
    ///   (`TransactionPhase::Blocked` -> `Planning`) redoes the placement
    ///   under a brand-new epoch (epoch numbers are never reused); this one
    ///   is permanently retired, not paused.
    ///
    /// `RequiresPhysicalRecovery` is deliberately **not** in this set,
    /// unlike the other three settled outcomes. It used to be, on the
    /// reasoning that reaching it *is* the output of the mandatory physical
    /// inspection and nothing is owed to that epoch afterward -- but design
    /// §14.2 (late semantic recovery) needs to actually resolve such an
    /// epoch, and `can_transition_to` now models the edge that lets it:
    /// `(RequiresPhysicalRecovery, Committed)` when physical evidence proves
    /// the commit landed as planned, or `(RequiresPhysicalRecovery,
    /// Blocked)` via the generic rule below when it must roll back or
    /// convert to a new capture epoch instead. An epoch sitting there is
    /// therefore genuinely still in flight -- exactly what the
    /// parent-completion invariant needs to keep refusing until late
    /// semantic recovery (not implemented in this crate yet) actually
    /// drives it to one of those two outcomes. Early physical recovery's own
    /// re-observe-and-report handling of a persisted
    /// `RequiresPhysicalRecovery` epoch does not depend on this predicate
    /// and is unchanged by it.
    ///
    /// All members left are "no longer in flight", exactly the property the
    /// parent-completion invariant needs -- not "reached `Completed`",
    /// which neither of the other two can ever do by construction.
    pub fn is_terminal(self) -> bool {
        matches!(self, EpochState::Quarantined | EpochState::Completed | EpochState::Blocked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationScope {
    Exact,
    SubtreeIntent,
    SubtreeExclusive,
}

impl ReservationScope {
    /// Whether `self` and `other`, requested by different transactions
    /// with overlapping ranges, conflict — the exact rules stated for this
    /// design: "`subtree_exclusive` excludes every exact or subtree mutation below
    /// a prefix" (conflicts with everything) and "`subtree_intent` ...
    /// conflicts with another exclusive subtree owner" (conflicts only
    /// with `subtree_exclusive`, not with another `subtree_intent` or with
    /// a plain `exact`). Symmetric by construction — call with either
    /// order.
    pub fn conflicts_with(self, other: ReservationScope) -> bool {
        use ReservationScope::*;
        match (self, other) {
            (SubtreeExclusive, _) | (_, SubtreeExclusive) => true,
            (SubtreeIntent, SubtreeIntent) => false,
            (SubtreeIntent, Exact) | (Exact, SubtreeIntent) => false,
            (Exact, Exact) => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationRole {
    CanonicalPath,
    ConflictCopy,
    RetirementTarget,
    SubtreeRoot,
}

/// One reservation request -- see
/// `yadorilink_sync_sqlite::filesystem_transaction::acquire_reservations`'s
/// own doc for the all-or-none acquisition semantics this feeds.
pub struct NewReservation<'a> {
    pub group_id: &'a str,
    pub transaction_id: &'a str,
    pub scope: ReservationScope,
    pub path: &'a str,
    pub role: ReservationRole,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Moved verbatim from `yadorilink-sync-sqlite`'s
    // `filesystem_transaction.rs` (Phase 7D-9D) along with `EpochState`/
    // `ReservationScope` themselves -- these are pure, no-`Connection`
    // tests, unlike their SQL-round-trip siblings
    // (`epoch_state_committing_can_retreat_to_prepared_after_a_provably_no_op_outcome`
    // and friends), which stayed behind in that crate's own test module.

    #[test]
    fn epoch_state_no_state_transitions_to_itself() {
        // Every state, listed explicitly rather than derived, so a review
        // diff shows exactly which states this test covers.
        let all = [
            EpochState::Allocated,
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
            EpochState::Committed,
            EpochState::Quarantined,
            EpochState::RequiresPhysicalRecovery,
            EpochState::CustodyTransferred,
            EpochState::AwaitingQuiescence,
            EpochState::ClassifiedKnown,
            EpochState::ClassifiedDivergent,
            EpochState::AwaitingCaptureStorage,
            EpochState::AwaitingCaptureAuthorization,
            EpochState::CapturedChangeAuthored,
            EpochState::LocalRecoveryOnly,
            EpochState::Released,
            EpochState::Completed,
            EpochState::Blocked,
        ];
        for state in all {
            assert!(!state.can_transition_to(state), "{state:?} must not transition to itself");
        }
    }

    #[test]
    fn epoch_state_terminal_states_cannot_reach_blocked() {
        assert!(!EpochState::Completed.can_transition_to(EpochState::Blocked));
        assert!(!EpochState::Blocked.can_transition_to(EpochState::Blocked));
        assert!(!EpochState::Quarantined.can_transition_to(EpochState::Blocked));
        // `RequiresPhysicalRecovery` is deliberately absent from this list —
        // see `epoch_state_requires_physical_recovery_can_exit_to_committed_or_blocked`
        // below. It is no longer terminal, so the generic `(_, Blocked)`
        // rule legally applies to it.
    }

    #[test]
    fn epoch_state_requires_physical_recovery_can_exit_to_committed_or_blocked() {
        // §14.2's three verdicts, modeled per `can_transition_to`'s own
        // doc: "complete forward" is the one explicit
        // `(RequiresPhysicalRecovery, Committed)` edge; "roll back" and
        // "convert to a new capture epoch" both end this epoch via the
        // generic `(_, Blocked)` rule, now legal here because
        // `RequiresPhysicalRecovery` is no longer in `EpochState::
        // is_terminal`.
        assert!(EpochState::RequiresPhysicalRecovery.can_transition_to(EpochState::Committed));
        assert!(EpochState::RequiresPhysicalRecovery.can_transition_to(EpochState::Blocked));
        // Nothing else is a legal destination -- this epoch's job is either
        // to resume normally or to retire in favour of a fresh one, never
        // to jump into the middle of either the preparation sequence or the
        // post-commit classification/capture chain.
        for illegal in [
            EpochState::Allocated,
            EpochState::Preparing,
            EpochState::PreparedArtifact,
            EpochState::AwaitingReservation,
            EpochState::Prepared,
            EpochState::Committing,
            EpochState::Quarantined,
            EpochState::CustodyTransferred,
            EpochState::AwaitingQuiescence,
            EpochState::ClassifiedKnown,
            EpochState::ClassifiedDivergent,
            EpochState::AwaitingCaptureStorage,
            EpochState::AwaitingCaptureAuthorization,
            EpochState::CapturedChangeAuthored,
            EpochState::LocalRecoveryOnly,
            EpochState::Released,
            EpochState::Completed,
        ] {
            assert!(
                !EpochState::RequiresPhysicalRecovery.can_transition_to(illegal),
                "RequiresPhysicalRecovery -> {illegal:?} must stay illegal"
            );
        }
    }

    #[test]
    fn epoch_state_rejects_skipping_the_preparation_sequence() {
        assert!(!EpochState::Allocated.can_transition_to(EpochState::Prepared));
        assert!(!EpochState::Allocated.can_transition_to(EpochState::Committed));
        assert!(!EpochState::Preparing.can_transition_to(EpochState::Committing));
    }

    #[test]
    fn epoch_state_never_goes_backwards_outside_blocked() {
        assert!(!EpochState::Committed.can_transition_to(EpochState::Preparing));
        assert!(!EpochState::Released.can_transition_to(EpochState::Committing));
        assert!(!EpochState::Completed.can_transition_to(EpochState::Released));
        // `(Committing, Prepared)` is the one other deliberate exception —
        // see `EpochState::can_transition_to`'s doc for why a proven
        // `NotStarted` outcome is allowed to retreat here. It must stay
        // narrowly scoped: no other already-progressed state may retreat to
        // `Prepared`, and `Prepared` itself may not jump back further still.
        assert!(EpochState::Committing.can_transition_to(EpochState::Prepared));
        assert!(!EpochState::Committed.can_transition_to(EpochState::Prepared));
        assert!(!EpochState::CustodyTransferred.can_transition_to(EpochState::Prepared));
        assert!(!EpochState::Prepared.can_transition_to(EpochState::Allocated));
        assert!(!EpochState::Prepared.can_transition_to(EpochState::PreparedArtifact));
    }

    #[test]
    fn epoch_state_is_terminal_matches_the_documented_three() {
        assert!(EpochState::Quarantined.is_terminal());
        assert!(EpochState::Completed.is_terminal());
        assert!(EpochState::Blocked.is_terminal());
        assert!(!EpochState::RequiresPhysicalRecovery.is_terminal());
        assert!(!EpochState::Committing.is_terminal());
        assert!(!EpochState::Allocated.is_terminal());
    }

    #[test]
    fn reservation_scope_conflict_matrix() {
        use ReservationScope::*;
        assert!(SubtreeExclusive.conflicts_with(SubtreeExclusive));
        assert!(SubtreeExclusive.conflicts_with(SubtreeIntent));
        assert!(SubtreeIntent.conflicts_with(SubtreeExclusive), "must be symmetric");
        assert!(SubtreeExclusive.conflicts_with(Exact));
        assert!(Exact.conflicts_with(SubtreeExclusive), "must be symmetric");
        assert!(!SubtreeIntent.conflicts_with(SubtreeIntent));
        assert!(!SubtreeIntent.conflicts_with(Exact));
        assert!(!Exact.conflicts_with(SubtreeIntent));
        assert!(Exact.conflicts_with(Exact));
    }
}
