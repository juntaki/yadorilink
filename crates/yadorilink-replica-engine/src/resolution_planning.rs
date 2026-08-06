//! Durable resolution planning's pure half (7D-9D move from
//! `yadorilink-sync-core::resolution_planning`). Pure -- no I/O, no
//! `Connection`, no filesystem access.
//!
//! `desired_frontier_hash`/[`PathFrontier`] moved first (sixth pass):
//! they reference only [`yadorilink_replica_domain::ids::ChangeHash`] and
//! this crate's own error type, no entanglement with anything else.
//!
//! Everything else below it -- [`PlannedPlacement`]/[`ExtraReservation`]/
//! [`PlacementGroup`]/[`resolution_to_group`], [`SliceBounds`]/[`PlanSlice`]/
//! [`slice_plan`]/[`slice_reservation_requests`], and the epoch-phase
//! classification group ([`classify_epoch`] and its callers) -- was blocked
//! on a real dependency cycle, not merely undesirable to move: these
//! functions are typed directly against `PlacementRole`/`EpochState`/
//! `ReservationRole`/`ReservationScope`/`NewReservation`, which used to be
//! defined in `yadorilink-sync-sqlite::filesystem_transaction`.
//! `yadorilink-sync-sqlite` already depends on this crate (for
//! `optimistic_placement::select_fast_path`), so this crate depending back
//! on `yadorilink-sync-sqlite`'s types would be a straight two-crate cycle.
//!
//! Resolved (seventh pass) by relocating those five types themselves to
//! `yadorilink-replica-domain::filesystem_placement` -- the lowest shared
//! value-type crate in the graph, which neither this crate nor
//! `yadorilink-sync-sqlite` has any cycle risk depending on. See that
//! module's own doc for the full reasoning, including why the SQL-string
//! codec (`as_db_str`/`from_db_str`) deliberately stayed behind in
//! `yadorilink-sync-sqlite` rather than moving with the types.
//!
//! `epoch_is_provably_untouched_by_adapter` took one further, narrower fix:
//! its original signature was `fn(e: &EpochRecord) -> bool`, and
//! `EpochRecord` itself could not follow `PlacementRole`/`EpochState` to
//! `yadorilink-replica-domain` -- it aggregates `DirectoryIdentity`/
//! `FileIdentity` (from `yadorilink-root-authority`) and `GenerationId`
//! (`yadorilink-sync-sqlite`'s own materialized-generation identity type),
//! and `yadorilink-replica-domain` must not depend on either (both
//! ultimately depend on `yadorilink-replica-domain` themselves -- the
//! reverse would be the exact cycle this whole move exists to avoid).
//! Reading the function's body showed it only ever reads two of
//! `EpochRecord`'s fields (`phase`, `unresolved_block_reason`), so its
//! signature narrowed to take exactly those two plain values instead of
//! the whole row -- `EpochRecord` itself stays in `yadorilink-sync-sqlite`
//! untouched, and its one real call site in `yadorilink-sync-core::
//! resolution_planning::plan_progress` (which stays there, `Connection`-
//! typed) passes `e.phase, e.unresolved_block_reason.as_deref()`.

use std::collections::HashSet;
use std::time::Duration;

use sha2::{Digest, Sha256};

use yadorilink_replica_domain::filesystem_placement::{
    EpochState, NewReservation, PlacementRole, ReservationRole, ReservationScope,
};
use yadorilink_replica_domain::ids::ChangeHash;

use crate::conflict::PathResolution;
use crate::error::ReplicaEngineError;

/// One path's live head set exactly as the resolution that built a plan saw
/// it -- design §4.1's `reflected_frontier`, for a single path. `heads` may
/// arrive in any order and may repeat; [`desired_frontier_hash`]
/// canonicalizes both, the same way
/// [`crate::compaction::Checkpoint::new`] canonicalizes its own frontier.
///
/// `PartialEq`/`Eq` are hand-written, not derived, and canonicalize `heads`
/// (sort, dedup) exactly the way [`desired_frontier_hash`] does before
/// comparing. A derived impl would compare `heads` as an ordered,
/// non-deduped `Vec`, giving this type two different equivalence relations
/// depending on which one a caller happened to reach for -- `==` for a quick
/// comparison, the hash for anything durable -- so two values that hash equal
/// (the relation every staleness check in this crate actually cares about)
/// could compare unequal under `==`. One relation, kept: the hash's, since
/// it is the one every consumer of "are these two frontiers the same"
/// already treats as authoritative.
#[derive(Debug, Clone)]
pub struct PathFrontier {
    pub path: String,
    pub heads: Vec<ChangeHash>,
}

impl PathFrontier {
    /// `heads`, sorted and deduped -- the same canonicalization
    /// [`desired_frontier_hash`] applies before hashing, exposed here so
    /// `PartialEq` can compare against exactly what the hash compares.
    fn canonical_heads(&self) -> Vec<[u8; 32]> {
        let mut heads: Vec<[u8; 32]> = self.heads.iter().map(|h| h.0).collect();
        heads.sort_unstable();
        heads.dedup();
        heads
    }
}

impl PartialEq for PathFrontier {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.canonical_heads() == other.canonical_heads()
    }
}

impl Eq for PathFrontier {}

const DESIRED_FRONTIER_DOMAIN_TAG: &[u8; 8] = b"YLNKdfr\x01";

/// The `desired_frontier_hash` of design §6.1 step 2:
/// `FilesystemResolutionPlan::frontier_hash`, and the value
/// `plan_is_stale`'s caller recomputes to compare against it.
///
/// Until this function existed, nothing in this crate produced that value
/// outside test literals, so the staleness check's authoritative half had a
/// consumer and no producer -- the plan's captured hash and the "current"
/// hash it was compared against were both invented by whichever test needed
/// them to differ. This is the one definition; a second one that encoded
/// the same inputs differently would make two honestly-built hashes compare
/// unequal forever, which reads as "always stale" and replans without end.
///
/// Canonical per design §2 (ascending, deduped) in the style of
/// `crate::compaction::Checkpoint::canonical_encoding`: entries sorted by
/// path, each entry's heads sorted and deduped. Two resolutions that folded
/// the same heads for the same paths therefore hash equal regardless of the
/// order the caller walked either.
///
/// Refuses a repeated path rather than merging its head sets. Two entries
/// for one path mean the caller resolved it twice and cannot say which of
/// the two the plan was actually built from; merging would hash a head set
/// no single resolution ever saw, and the resulting hash would then be
/// compared -- apparently successfully -- against a plan built from one of
/// them.
pub fn desired_frontier_hash(entries: &[PathFrontier]) -> Result<[u8; 32], ReplicaEngineError> {
    let mut canonical: Vec<(&str, Vec<[u8; 32]>)> = entries
        .iter()
        .map(|entry| {
            let mut heads: Vec<[u8; 32]> = entry.heads.iter().map(|h| h.0).collect();
            heads.sort_unstable();
            heads.dedup();
            (entry.path.as_str(), heads)
        })
        .collect();
    canonical.sort_by(|a, b| a.0.cmp(b.0));
    if let Some(window) = canonical.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(ReplicaEngineError::InvalidInput(format!(
            "desired_frontier_hash was given two frontier entries for path {:?}",
            window[0].0
        )));
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(DESIRED_FRONTIER_DOMAIN_TAG);
    put_u32(&mut buf, canonical.len() as u32);
    for (path, heads) in &canonical {
        put_str(&mut buf, path);
        put_u32(&mut buf, heads.len() as u32);
        for head in heads {
            buf.extend_from_slice(head);
        }
    }
    Ok(Sha256::digest(&buf).into())
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

/// One placement this plan wants at one path — becomes exactly one
/// placement epoch (`filesystem_transaction_epochs` row) once its slice
/// commits. `target_generation` is opaque bytes, exactly like
/// `yadorilink_sync_sqlite::filesystem_transaction::NewEpoch::target_generation`
/// — this module does not decode or produce it, only carries it (see that
/// module's own doc on why: no producer/consumer to validate the shape
/// against yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPlacement {
    pub path: String,
    pub role: PlacementRole,
    pub target_generation: Vec<u8>,
}

/// A reservation with no corresponding epoch — the `subtree_intent`/
/// `subtree_exclusive` prefix markers design §17 describes for a directory
/// subtree operation, which excludes a range without allocating one epoch
/// row per descendant (lazy expansion; a bare subtree exclusion is never
/// itself a [`PlannedPlacement`], only ever a reservation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraReservation {
    pub path: String,
    pub scope: ReservationScope,
    pub role: ReservationRole,
}

/// The smallest unit [`slice_plan`] will ever split across two slices. A
/// resolver decision that spans several paths at once — a winning head plus
/// its conflict copies (§11.2) — is exactly one group; a caller that knows
/// two groups are coupled by something this module cannot see on its own
/// (for example a rename's source and destination paths) uses
/// [`PlacementGroup::merge`] to fuse them into one indivisible unit before
/// slicing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementGroup {
    placements: Vec<PlannedPlacement>,
    extra_reservations: Vec<ExtraReservation>,
}

impl PlacementGroup {
    /// Builds a group with no bare subtree reservations. Refuses an empty
    /// group (nothing to place) and a group that names the same path twice
    /// (ambiguous — which placement would own the reservation?).
    pub fn new(placements: Vec<PlannedPlacement>) -> Result<Self, ReplicaEngineError> {
        if placements.is_empty() {
            return Err(ReplicaEngineError::InvalidInput(
                "a placement group must contain at least one placement".to_string(),
            ));
        }
        let mut seen = HashSet::new();
        for p in &placements {
            if !seen.insert(p.path.as_str()) {
                return Err(ReplicaEngineError::InvalidInput(format!(
                    "placement group names path {:?} more than once",
                    p.path
                )));
            }
        }
        Ok(PlacementGroup { placements, extra_reservations: Vec::new() })
    }

    /// Attaches bare subtree reservations (design §17) alongside this
    /// group's concrete placements — reserved together, released together,
    /// never producing an epoch of their own.
    pub fn with_extra_reservations(mut self, extra: Vec<ExtraReservation>) -> Self {
        self.extra_reservations = extra;
        self
    }

    /// Fuses several groups' placements and extra reservations into one
    /// indivisible group. The caller is asserting these groups must commit
    /// as one unit for a reason this module cannot derive on its own (see
    /// the module doc's rename example) — still refuses a duplicate path
    /// across the merged set, for the same reason [`PlacementGroup::new`]
    /// does.
    pub fn merge(groups: Vec<PlacementGroup>) -> Result<PlacementGroup, ReplicaEngineError> {
        let mut placements = Vec::new();
        let mut extra_reservations = Vec::new();
        for g in groups {
            placements.extend(g.placements);
            extra_reservations.extend(g.extra_reservations);
        }
        let mut merged = PlacementGroup::new(placements)?;
        merged.extra_reservations = extra_reservations;
        Ok(merged)
    }

    pub fn placements(&self) -> &[PlannedPlacement] {
        &self.placements
    }

    pub fn extra_reservations(&self) -> &[ExtraReservation] {
        &self.extra_reservations
    }

    /// Deterministic sort key for [`slice_plan`] — the lexicographically
    /// smallest path this group names. Unrelated to
    /// `filesystem_transaction`'s internal `path_key` byte encoding on
    /// purpose: `acquire_reservations` re-sorts by its own canonical key
    /// regardless of the order requests arrive in (see the module doc's
    /// deadlock section), so this ordering only needs to be deterministic
    /// for reproducible slice boundaries across replicas and retries, not
    /// byte-identical to the reservation layer's own key space.
    fn sort_key(&self) -> &str {
        self.placements
            .iter()
            .map(|p| p.path.as_str())
            .chain(self.extra_reservations.iter().map(|r| r.path.as_str()))
            .min()
            .expect("PlacementGroup::new guarantees at least one placement")
    }
}

/// Turns one path's [`crate::conflict::resolve_path_heads`] outcome into the
/// [`PlacementGroup`] it requires — the §11.2 "multi-epoch resolver
/// placement" mapping: a `Present` resolution with conflict copies becomes
/// one canonical placement plus one placement per copy, all one group so
/// they can never be split across slices or partially reserved.
///
/// `head_target_generation[i]` must be the already-encoded opaque target
/// bytes for `heads[i]` (the same slice `resolve_path_heads` was called
/// with) — encoding a target generation is `materialized_generation`'s job,
/// not this module's (see [`PlannedPlacement`]'s doc).
///
/// `absent_removal_target_generation`: `None` when nothing is currently
/// materialized at `path` (an absent resolution with nothing to remove
/// plans nothing); `Some(tombstone_bytes)` when a materialized generation
/// exists and must be captured/removed, producing one `CanonicalPath`
/// placement.
pub fn resolution_to_group(
    path: &str,
    resolution: &PathResolution,
    head_target_generation: &[Vec<u8>],
    absent_removal_target_generation: Option<Vec<u8>>,
) -> Result<Option<PlacementGroup>, ReplicaEngineError> {
    match resolution {
        PathResolution::Absent => Ok(absent_removal_target_generation.map(|bytes| {
            PlacementGroup::new(vec![PlannedPlacement {
                path: path.to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: bytes,
            }])
            .expect("a single placement is always a valid group")
        })),
        PathResolution::Present { winner, conflict_copies } => {
            let winner_bytes = head_target_generation.get(*winner).cloned().ok_or_else(|| {
                ReplicaEngineError::InvalidInput(format!(
                    "resolution for {path:?} names winner head {winner} but only {} target \
                     generations were supplied",
                    head_target_generation.len()
                ))
            })?;
            let mut placements = vec![PlannedPlacement {
                path: path.to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: winner_bytes,
            }];
            for copy in conflict_copies {
                let bytes = head_target_generation.get(copy.head).cloned().ok_or_else(|| {
                    ReplicaEngineError::InvalidInput(format!(
                        "resolution for {path:?} names conflict-copy head {} but only {} target \
                         generations were supplied",
                        copy.head,
                        head_target_generation.len()
                    ))
                })?;
                placements.push(PlannedPlacement {
                    path: copy.path.clone(),
                    role: PlacementRole::ConflictCopy,
                    target_generation: bytes,
                });
            }
            Ok(Some(PlacementGroup::new(placements)?))
        }
    }
}

/// The independent bounds a single executable [`PlanSlice`] never exceeds —
/// the defaults are provisional, not an authoritative SLO.
#[derive(Debug, Clone, Copy)]
pub struct SliceBounds {
    pub max_paths_per_slice: usize,
    pub max_epochs_per_slice: usize,
    pub max_staged_bytes_per_slice: u64,
    pub max_commit_window: Duration,
}

impl Default for SliceBounds {
    fn default() -> Self {
        SliceBounds {
            max_paths_per_slice: 64,
            max_epochs_per_slice: 128,
            max_staged_bytes_per_slice: 256 * 1024 * 1024,
            max_commit_window: Duration::from_millis(250),
        }
    }
}

/// One executable, boundedly-sized slice of a plan — every group in it is
/// reserved, committed and released together via one
/// [`slice_reservation_requests`] call, never split further.
#[derive(Debug, Clone)]
pub struct PlanSlice {
    pub plan_revision: i64,
    pub groups: Vec<PlacementGroup>,
}

impl PlanSlice {
    pub fn placements(&self) -> impl Iterator<Item = &PlannedPlacement> {
        self.groups.iter().flat_map(|g| g.placements.iter())
    }

    pub fn path_count(&self) -> usize {
        self.placements().count()
    }

    /// One placement is always exactly one epoch in this model (never a
    /// bare subtree reservation, see [`ExtraReservation`]).
    pub fn epoch_count(&self) -> usize {
        self.path_count()
    }
}

/// Deterministically splits `groups` into bounded [`PlanSlice`]s, never
/// separating a group's placements across two slices. `group_bytes` gives
/// the staged-byte cost of one group (typically the sum of its winning and
/// conflict-copy content sizes); this module has no I/O of its own to
/// measure that, so it is supplied rather than guessed.
///
/// Groups are visited in [`PlacementGroup`]'s own deterministic sort-key
/// order and packed greedily: a group is added to the current slice unless
/// doing so would exceed a bound *and* the current slice is already
/// non-empty. That second condition is deliberate: a single group that
/// alone exceeds a bound still becomes its own (oversized) slice rather
/// than being torn apart, which would break the "all-or-none across
/// several paths" guarantee for that group.
pub fn slice_plan(
    plan_revision: i64,
    groups: &[PlacementGroup],
    bounds: &SliceBounds,
    group_bytes: impl Fn(&PlacementGroup) -> u64,
) -> Vec<PlanSlice> {
    let mut ordered: Vec<&PlacementGroup> = groups.iter().collect();
    ordered.sort_by(|a, b| a.sort_key().cmp(b.sort_key()));

    let mut slices = Vec::new();
    let mut current: Vec<PlacementGroup> = Vec::new();
    let mut paths = 0usize;
    let mut epochs = 0usize;
    let mut bytes = 0u64;

    for group in ordered {
        let group_paths = group.placements.len();
        let group_epochs = group_paths;
        let group_cost = group_bytes(group);
        let would_exceed = !current.is_empty()
            && (paths + group_paths > bounds.max_paths_per_slice
                || epochs + group_epochs > bounds.max_epochs_per_slice
                || bytes.saturating_add(group_cost) > bounds.max_staged_bytes_per_slice);
        if would_exceed {
            slices.push(PlanSlice { plan_revision, groups: std::mem::take(&mut current) });
            paths = 0;
            epochs = 0;
            bytes = 0;
        }
        current.push(group.clone());
        paths += group_paths;
        epochs += group_epochs;
        bytes = bytes.saturating_add(group_cost);
    }
    if !current.is_empty() {
        slices.push(PlanSlice { plan_revision, groups: current });
    }
    slices
}

/// Flattens every placement and extra reservation in `slice` into the
/// request set for exactly **one**
/// `yadorilink_sync_sqlite::filesystem_transaction::acquire_reservations`
/// call — see that module's doc's deadlock section for why this must never
/// be split into per-group or per-path calls.
pub fn slice_reservation_requests<'a>(
    group_id: &'a str,
    transaction_id: &'a str,
    slice: &'a PlanSlice,
) -> Vec<NewReservation<'a>> {
    let mut out = Vec::new();
    for group in &slice.groups {
        for p in &group.placements {
            out.push(NewReservation {
                group_id,
                transaction_id,
                scope: ReservationScope::Exact,
                path: &p.path,
                role: match p.role {
                    PlacementRole::CanonicalPath => ReservationRole::CanonicalPath,
                    PlacementRole::ConflictCopy => ReservationRole::ConflictCopy,
                    PlacementRole::RetirementTarget => ReservationRole::RetirementTarget,
                },
            });
        }
        for r in &group.extra_reservations {
            out.push(NewReservation {
                group_id,
                transaction_id,
                scope: r.scope,
                path: &r.path,
                role: r.role,
            });
        }
    }
    out
}

/// How `yadorilink_sync_core::resolution_planning`'s `replan`'s epoch sweep
/// and `plan_progress` each read one epoch phase — deliberately ONE
/// exhaustive `match` rather than two independent predicates sitting next
/// to each other.
///
/// The two questions are exact complements of each other for every phase
/// that answers either: "may a replan retire this row?" and "does this row
/// already stand for bytes that landed on disk?" must never both be true,
/// because retiring a row of the second kind is silent data loss — see
/// [`EpochDisposition::CommittedPlacement`]'s own note. Written as two
/// `matches!` lists, keeping them complementary is a maintenance promise;
/// written as one `match` with no wildcard arm, it is a property of the
/// code, and a new [`EpochState`] variant cannot be added without an
/// explicit decision here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EpochDisposition {
    /// Nothing physical has been attempted at `target_path` yet: the epoch
    /// has at most staged an artefact off to the side. A replan may retire
    /// the row precisely because the claim "nothing physical is lost, only
    /// the epoch row's own state" is true for exactly these phases and no
    /// others.
    PreCommitLeftover,
    /// The placement's bytes are on disk, and the row carries the durable
    /// link (`displaced_generation_id`/`displaced_identity`/
    /// `classification_result`) to whatever content the commit overwrote.
    /// Retiring such a row to `Blocked` would strand that link where nothing
    /// can ever author the capture — and, worse, would make `plan_progress`
    /// re-offer the placement, so the driver commits a second time over the
    /// first commit's own output and the user's original bytes become
    /// unrecoverable.
    CommittedPlacement,
    /// Neither: `Committing` (the commit may or may not have landed —
    /// `early_physical_recovery` owns that question, not a generic sweep),
    /// `RequiresPhysicalRecovery` (design owes it a real roll-forward or
    /// roll-back verdict, which a relabel to `Blocked` would preempt),
    /// `Quarantined`/`Blocked` (already settled, and already terminal), and
    /// `Completed`'s two non-committed siblings have no business in either
    /// answer.
    NeitherSweepableNorCommitted,
}

/// The single classification both [`epoch_reflects_committed_placement`] and
/// [`epoch_is_pre_commit_leftover`] read. No wildcard arm, on purpose.
fn classify_epoch(phase: EpochState) -> EpochDisposition {
    use EpochDisposition::*;
    match phase {
        EpochState::Allocated => PreCommitLeftover,
        EpochState::Preparing => PreCommitLeftover,
        EpochState::PreparedArtifact => PreCommitLeftover,
        EpochState::AwaitingReservation => PreCommitLeftover,
        EpochState::Prepared => PreCommitLeftover,
        EpochState::Committing => NeitherSweepableNorCommitted,
        EpochState::Committed => CommittedPlacement,
        EpochState::Quarantined => NeitherSweepableNorCommitted,
        EpochState::RequiresPhysicalRecovery => NeitherSweepableNorCommitted,
        EpochState::CustodyTransferred => CommittedPlacement,
        EpochState::AwaitingQuiescence => CommittedPlacement,
        EpochState::ClassifiedKnown => CommittedPlacement,
        EpochState::ClassifiedDivergent => CommittedPlacement,
        EpochState::AwaitingCaptureStorage => CommittedPlacement,
        EpochState::AwaitingCaptureAuthorization => CommittedPlacement,
        EpochState::CapturedChangeAuthored => CommittedPlacement,
        EpochState::LocalRecoveryOnly => CommittedPlacement,
        EpochState::Released => CommittedPlacement,
        EpochState::Completed => CommittedPlacement,
        EpochState::Blocked => NeitherSweepableNorCommitted,
    }
}

/// Whether an epoch's phase reflects a placement that was actually,
/// durably committed as planned — `Quarantined`/`RequiresPhysicalRecovery`/
/// `Blocked` are excluded even though they are terminal (see the module
/// doc's "Replanning does not lose committed work" reasoning, carried over
/// from `yadorilink-sync-core::resolution_planning`'s own doc).
pub fn epoch_reflects_committed_placement(phase: EpochState) -> bool {
    classify_epoch(phase) == EpochDisposition::CommittedPlacement
}

/// Whether `replan`'s epoch sweep may retire this epoch to `Blocked`. The
/// allow-list is stated positively, and lives here rather than in `replan`
/// itself, so it cannot drift away from
/// [`epoch_reflects_committed_placement`]'s list: both are derived from
/// [`classify_epoch`].
pub fn epoch_is_pre_commit_leftover(phase: EpochState) -> bool {
    classify_epoch(phase) == EpochDisposition::PreCommitLeftover
}

/// Whether an epoch at phase `phase`, with block reason
/// `unresolved_block_reason`, is a non-committed epoch that PROVABLY never
/// mutated the epoch's own `target_path` -- the only case where
/// `yadorilink_sync_core::resolution_planning::plan_progress` may consult
/// `materialized_generation` as a fallback for whether an earlier epoch at
/// the same path is what the disk actually reflects. This is deliberately
/// narrower than "not committed": `NeitherSweepableNorCommitted`
/// (`Committing` / `Blocked` / `Quarantined` / `RequiresPhysicalRecovery`)
/// only means "not committed", not "never touched the target path" -- an
/// earlier version of this fallback conflated the two, which is unsafe: see
/// below for why `Committing` and `RequiresPhysicalRecovery` can never
/// qualify. Note this is about the TARGET path specifically, not "no
/// filesystem call happened at all": a prepare failure can still have
/// written bytes to a reserved staging location before failing (see
/// `orchestrator::block_unpreparable_epoch`) -- that is irrelevant here
/// because `materialized_generation` only records what is at the target
/// path, never a staging location.
///
/// Takes `phase`/`unresolved_block_reason` directly, rather than a whole
/// `EpochRecord`, deliberately -- see this module's own top-of-file doc for
/// why `EpochRecord` itself cannot follow `EpochState` to this crate.
///
/// The only phase that can ever qualify is `Blocked`, and only when
/// `unresolved_block_reason` is unset. Every production writer of `Blocked`,
/// enumerated (not assumed) in this repo as of this doc:
/// - `orchestrator::block_unpreparable_epoch` -- a prepare failure. The
///   target path itself is never touched: a failure can leave real bytes at
///   a reserved *staging* path (see that function's own doc on
///   `PrepareError::ContentVerificationFailed`), but prepare never writes to
///   `target_path`, only to `stage_path`. Provably untouched AT THE TARGET
///   PATH, which is what this predicate is actually about.
/// - `optimistic_placement`'s non-retryable `NotStarted` commit outcome --
///   the platform's own atomic exchange primitive proved the attempt to
///   swap `target_path` never started. Provably untouched.
/// - `replan`'s pre-commit-leftover sweep -- only ever retires epochs
///   [`epoch_is_pre_commit_leftover`] already excludes from
///   [`epoch_reflects_committed_placement`]'s complement here; irrelevant to
///   this predicate either way.
/// - `early_physical_recovery`'s `block` -- the ONE writer that sets
///   `unresolved_block_reason`, precisely because it could NOT determine
///   physical state. "Touched or not" is unknown there, not "not touched"
///   -- this predicate must return `false` for it, which is exactly what
///   checking the reason field (rather than trusting the bare phase) buys.
///
/// `Committing` and `RequiresPhysicalRecovery` can never qualify: an adapter
/// call may already have run for either (that is their entire reason for
/// existing as distinct phases). `Quarantined` has no production writer at
/// all as of this doc (`early_physical_recovery`'s own note that it is
/// "currently unreachable in this crate") -- excluded rather than assumed
/// safe, per the asymmetry a wrong `true` here is a SILENT, permanent
/// disk/plan divergence, while a wrong `false` only delays convergence into
/// a visible `PlanDriverError::PlanNeverSettled`.
///
/// Written as an exhaustive match with no wildcard arm so a newly added
/// `EpochState` variant is a compile error here, not a silent gap.
pub fn epoch_is_provably_untouched_by_adapter(
    phase: EpochState,
    unresolved_block_reason: Option<&str>,
) -> bool {
    match phase {
        EpochState::Blocked => unresolved_block_reason.is_none(),
        EpochState::Allocated
        | EpochState::Preparing
        | EpochState::PreparedArtifact
        | EpochState::AwaitingReservation
        | EpochState::Prepared
        | EpochState::Committing
        | EpochState::Quarantined
        | EpochState::RequiresPhysicalRecovery
        | EpochState::Committed
        | EpochState::CustodyTransferred
        | EpochState::AwaitingQuiescence
        | EpochState::ClassifiedKnown
        | EpochState::ClassifiedDivergent
        | EpochState::AwaitingCaptureStorage
        | EpochState::AwaitingCaptureAuthorization
        | EpochState::CapturedChangeAuthored
        | EpochState::LocalRecoveryOnly
        | EpochState::Released
        | EpochState::Completed => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf(path: &str, heads: &[u8]) -> PathFrontier {
        PathFrontier {
            path: path.to_string(),
            heads: heads.iter().map(|h| ChangeHash([*h; 32])).collect(),
        }
    }

    /// Two devices -- or the same device on two passes -- walk the DAG in
    /// whatever order their own indexes hand back. If that order reached
    /// the hash, two resolutions that folded identical heads would compare
    /// unequal, which the driver reads as "stale" and replans on forever.
    #[test]
    fn desired_frontier_hash_is_independent_of_path_and_head_order() {
        let forward = desired_frontier_hash(&[pf("a.txt", &[1, 2]), pf("b.txt", &[3])]).unwrap();
        let reversed = desired_frontier_hash(&[pf("b.txt", &[3]), pf("a.txt", &[2, 1])]).unwrap();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn desired_frontier_hash_ignores_a_repeated_head_within_one_path() {
        assert_eq!(
            desired_frontier_hash(&[pf("a.txt", &[1, 1, 2])]).unwrap(),
            desired_frontier_hash(&[pf("a.txt", &[2, 1])]).unwrap()
        );
    }

    #[test]
    fn desired_frontier_hash_changes_when_a_head_is_added_to_one_path() {
        assert_ne!(
            desired_frontier_hash(&[pf("a.txt", &[1]), pf("b.txt", &[3])]).unwrap(),
            desired_frontier_hash(&[pf("a.txt", &[1, 9]), pf("b.txt", &[3])]).unwrap(),
            "a new head for one path is exactly the staleness this hash exists to detect"
        );
    }

    #[test]
    fn desired_frontier_hash_changes_when_a_path_leaves_the_scope() {
        assert_ne!(
            desired_frontier_hash(&[pf("a.txt", &[1]), pf("b.txt", &[3])]).unwrap(),
            desired_frontier_hash(&[pf("a.txt", &[1])]).unwrap()
        );
    }

    // A "path boundary collision" test was written here and deleted: it
    // compared `[("ab", [])]` against `[("a", []), ("b", [])]`, which differ
    // in entry count and so hash differently whether or not the path length
    // prefix exists at all. Measured -- stripping `put_str`'s prefix leaves
    // it green. The prefix is kept as ordinary canonical-encoding
    // discipline, not because anything here proves it load-bearing.

    #[test]
    fn desired_frontier_hash_refuses_two_entries_for_one_path() {
        let error = desired_frontier_hash(&[pf("a.txt", &[1]), pf("a.txt", &[2])]).unwrap_err();
        assert!(
            matches!(&error, ReplicaEngineError::InvalidInput(message) if message.contains("a.txt")),
            "unexpected error: {error:?}"
        );
    }

    // --- PathFrontier equivalence (D3 / 24.10) ---------------------------

    /// The exact shape `desired_frontier_hash` already treats as
    /// equivalent (out-of-order, with a repeat) must also compare `==`.
    /// Before this, `PartialEq`/`Eq` were derived, comparing `heads` as an
    /// ordered, non-deduped `Vec` -- two values that hash equal (the
    /// relation every staleness check in this crate actually cares about)
    /// could compare unequal under `==`, giving `PathFrontier` two
    /// different notions of "the same frontier" depending on which one a
    /// caller reached for.
    #[test]
    fn path_frontier_equality_matches_desired_frontier_hash_equality() {
        let a = pf("a.txt", &[1, 1, 2]);
        let b = pf("a.txt", &[2, 1]);
        assert_eq!(
            desired_frontier_hash(std::slice::from_ref(&a)).unwrap(),
            desired_frontier_hash(std::slice::from_ref(&b)).unwrap(),
            "test setup: these two must already be the hash's own notion of equal"
        );
        assert_eq!(
            a, b,
            "out-of-order, with a repeated head, must still compare equal -- the same \
             relation the hash already uses"
        );
    }

    #[test]
    fn path_frontier_equality_still_distinguishes_a_genuinely_different_head_set() {
        assert_ne!(pf("a.txt", &[1]), pf("a.txt", &[1, 2]));
        assert_ne!(pf("a.txt", &[1]), pf("b.txt", &[1]), "the path itself must still matter");
    }

    // --- resolution_to_group / PlacementGroup / slice_plan / slice_reservation_requests
    // Moved verbatim from `yadorilink-sync-core::resolution_planning`'s own
    // test module (Phase 7D-9D, seventh pass) along with the pure functions
    // and types themselves.

    #[test]
    fn resolution_to_group_absent_with_nothing_to_remove_plans_nothing() {
        let resolution = PathResolution::Absent;
        let group = resolution_to_group("gone.txt", &resolution, &[], None).unwrap();
        assert!(group.is_none());
    }

    #[test]
    fn resolution_to_group_absent_with_a_materialized_generation_plans_one_removal() {
        let resolution = PathResolution::Absent;
        let group =
            resolution_to_group("gone.txt", &resolution, &[], Some(b"tombstone".to_vec()))
                .unwrap()
                .unwrap();
        assert_eq!(group.placements().len(), 1);
        assert_eq!(group.placements()[0].role, PlacementRole::CanonicalPath);
        assert_eq!(group.placements()[0].target_generation, b"tombstone");
    }

    #[test]
    fn resolution_to_group_present_with_conflict_copies_plans_one_group() {
        let resolution = PathResolution::Present {
            winner: 0,
            conflict_copies: vec![crate::conflict::ConflictCopy {
                head: 1,
                path: "f (conflict).txt".to_string(),
            }],
        };
        let head_targets = vec![b"winner".to_vec(), b"loser".to_vec()];
        let group = resolution_to_group("f.txt", &resolution, &head_targets, None)
            .unwrap()
            .unwrap();
        assert_eq!(group.placements().len(), 2);
        assert_eq!(group.placements()[0].role, PlacementRole::CanonicalPath);
        assert_eq!(group.placements()[0].target_generation, b"winner");
        assert_eq!(group.placements()[1].role, PlacementRole::ConflictCopy);
        assert_eq!(group.placements()[1].path, "f (conflict).txt");
    }

    fn one_placement_group(path: &str) -> PlacementGroup {
        PlacementGroup::new(vec![PlannedPlacement {
            path: path.to_string(),
            role: PlacementRole::CanonicalPath,
            target_generation: b"g".to_vec(),
        }])
        .unwrap()
    }

    #[test]
    fn slice_plan_packs_groups_that_fit_into_one_slice() {
        let groups = vec![one_placement_group("a.txt"), one_placement_group("b.txt")];
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &groups, &bounds, |_| 0);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].path_count(), 2);
    }

    #[test]
    fn slice_plan_starts_a_new_slice_once_a_bound_would_be_exceeded() {
        let groups = vec![one_placement_group("a.txt"), one_placement_group("b.txt")];
        let bounds = SliceBounds { max_paths_per_slice: 1, ..SliceBounds::default() };
        let slices = slice_plan(0, &groups, &bounds, |_| 0);
        assert_eq!(slices.len(), 2);
    }

    #[test]
    fn slice_plan_never_tears_apart_a_single_oversized_group() {
        let big = PlacementGroup::new(vec![
            PlannedPlacement {
                path: "a.txt".to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: b"g".to_vec(),
            },
            PlannedPlacement {
                path: "b.txt".to_string(),
                role: PlacementRole::CanonicalPath,
                target_generation: b"g".to_vec(),
            },
        ])
        .unwrap();
        let bounds = SliceBounds { max_paths_per_slice: 1, ..SliceBounds::default() };
        let slices = slice_plan(0, &[big], &bounds, |_| 0);
        assert_eq!(slices.len(), 1, "an oversized group must not be split across slices");
        assert_eq!(slices[0].path_count(), 2);
    }

    #[test]
    fn slice_reservation_requests_covers_every_placement_and_extra_reservation() {
        let group = one_placement_group("a.txt").with_extra_reservations(vec![ExtraReservation {
            path: "a".to_string(),
            scope: ReservationScope::SubtreeIntent,
            role: ReservationRole::SubtreeRoot,
        }]);
        let bounds = SliceBounds::default();
        let slices = slice_plan(0, &[group], &bounds, |_| 0);
        let requests = slice_reservation_requests("g", "tx", &slices[0]);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].role, ReservationRole::CanonicalPath);
        assert_eq!(requests[1].role, ReservationRole::SubtreeRoot);
        assert_eq!(requests[1].scope, ReservationScope::SubtreeIntent);
    }

    // --- epoch phase classification --------------------------------------

    #[test]
    fn epoch_reflects_committed_placement_matches_the_documented_committed_states() {
        assert!(epoch_reflects_committed_placement(EpochState::Committed));
        assert!(epoch_reflects_committed_placement(EpochState::CustodyTransferred));
        assert!(epoch_reflects_committed_placement(EpochState::Completed));
        assert!(!epoch_reflects_committed_placement(EpochState::Allocated));
        assert!(!epoch_reflects_committed_placement(EpochState::Committing));
        assert!(!epoch_reflects_committed_placement(EpochState::Quarantined));
        assert!(!epoch_reflects_committed_placement(EpochState::RequiresPhysicalRecovery));
        assert!(!epoch_reflects_committed_placement(EpochState::Blocked));
    }

    #[test]
    fn epoch_is_pre_commit_leftover_matches_the_documented_pre_commit_states() {
        assert!(epoch_is_pre_commit_leftover(EpochState::Allocated));
        assert!(epoch_is_pre_commit_leftover(EpochState::Preparing));
        assert!(epoch_is_pre_commit_leftover(EpochState::Prepared));
        assert!(!epoch_is_pre_commit_leftover(EpochState::Committed));
        assert!(!epoch_is_pre_commit_leftover(EpochState::Committing));
    }

    #[test]
    fn epoch_reflects_committed_placement_and_epoch_is_pre_commit_leftover_are_never_both_true() {
        // The exact complementarity `classify_epoch`'s own doc requires --
        // written as an exhaustive check rather than trusted by construction.
        for state in [
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
        ] {
            assert!(
                !(epoch_reflects_committed_placement(state) && epoch_is_pre_commit_leftover(state)),
                "{state:?} must not be both committed and pre-commit-leftover"
            );
        }
    }

    #[test]
    fn epoch_is_provably_untouched_by_adapter_only_qualifies_blocked_with_no_reason() {
        assert!(epoch_is_provably_untouched_by_adapter(EpochState::Blocked, None));
        assert!(!epoch_is_provably_untouched_by_adapter(EpochState::Blocked, Some("reason")));
        assert!(!epoch_is_provably_untouched_by_adapter(EpochState::Committing, None));
        assert!(!epoch_is_provably_untouched_by_adapter(
            EpochState::RequiresPhysicalRecovery,
            None
        ));
        assert!(!epoch_is_provably_untouched_by_adapter(EpochState::Committed, None));
        assert!(!epoch_is_provably_untouched_by_adapter(EpochState::Allocated, None));
    }
}
