//! Makes conflict-copy creation a durable, replicated DAG fact instead of an
//! ephemeral local re-derivation.
//!
//! Before this module, a conflict copy was materialized purely by
//! `peer_session.rs`'s reconciliation fixpoint re-resolving each path's
//! *current* live heads on every tick: if the winning and losing content
//! heads for a path were ever simultaneously live in a device's own view of
//! the DAG, that device derived and materialized the conflict copy locally,
//! with no corresponding `Change` -- nothing to gossip, nothing durable. A
//! device whose local admission order never produced that moment (its own
//! next batch admitted the winner, the loser, AND whatever later change
//! dominated both, all at once) never derived the obligation and could
//! never rediscover it once the DAG converged past the transient divergence
//! (confirmed, reproduced: see `fix/conflict-copy-convergence-obligation-20260723`).
//!
//! The fix: `Op::Put`'s `PutOrigin::ConflictCopy { source_path, losing_change }`
//! (see `change.rs`) makes a conflict copy a first-class op inside a real,
//! signed, replicated `Change` -- the *carrier* change. Once any device
//! authors it, it gossips like any other change, and any device that ever
//! admits the carrier lands the conflict copy, independent of whether its
//! own local view ever passed through the transient divergence.
//!
//! ## Who authors it, and when
//!
//! Never the reconciliation fixpoint itself -- authoring from there would
//! let every device that independently observes the same transient
//! divergence mint its own sibling carrier (different device, different
//! signature, different hash) for the identical obligation, and worse,
//! creates a live authoring loop (reconcile discovers -> authors -> admits
//! -> re-triggers reconcile). Authoring happens exactly where a *new* local
//! edit's parents causally close over a prior fork: [`derive_required_conflict_copy_ops`]
//! is called from `emit_local_change`/`emit_local_change_onto` with the new
//! change's own `parents` and direct ops, computes whatever conflict copies
//! that specific edit's admission would otherwise silently erase, and the
//! caller folds them into the SAME signed change as the direct ops. Until
//! some local edit closes a fork this way, the old ephemeral
//! fixpoint-resolves-current-heads path is still what shows a conflict copy
//! on disk locally -- this module only makes that preservation durable once
//! it happens, it doesn't change when a conflict first becomes visible.
//!
//! ## Causal identity: carrier, not loser
//!
//! `PathHead` (`yadorilink_replica_engine::conflict`) for the conflict-copy path is *always* the
//! carrier change's own `change_hash`/`lamport`/`device_id` -- never
//! `losing_change`'s. This is deliberate, not an oversight: ordinary DAG
//! path semantics (a later legitimate delete of the conflict-copy path must
//! supersede whatever put content there) only work if the thing being
//! ordered/superseded is what actually touched that path. The `losing_change`
//! referenced by `PutOrigin::ConflictCopy` names *why* the carrier's `Put`
//! exists (for [`validate_conflict_copy_origin`] to check), not a competing
//! identity for the conflict-copy path itself. Using `losing_change`'s own
//! identity there instead would let a slow-to-arrive carrier resurrect a
//! conflict copy the user had already deleted (a later `Delete` D of the
//! conflict-copy path descends from the carrier C that put it there, so D
//! correctly supersedes C via ordinary ancestry -- but D very likely does
//! NOT descend from `losing_change` B itself, since B never touched that
//! literal path; ordering by B's identity would make D and any later
//! stale-arriving carrier look unrelated/concurrent instead of D correctly
//! dominating).
//!
//! ## Idempotency: `conflict_copy_provenance`
//!
//! A local edit only needs to derive a `ConflictCopy` op for a loser once,
//! ever, for the whole group -- once ANY change (authored locally, or
//! admitted from a peer who derived it first) carries a `Put` with
//! `origin: ConflictCopy { source_path, losing_change }`, deriving it again
//! is pure waste (worse: it would let every subsequent local edit touching
//! the same path re-mint a fresh, sibling carrier for a loser already fully
//! preserved). `conflict_copy_provenance` is a derived index, populated the
//! moment any such op is admitted (local authoring, peer admission, orphan
//! promotion, or rebootstrap install) via [`record_conflict_copy_ops_provenance`],
//! queried by [`conflict_copy_already_provisioned`] before deriving.

use std::collections::{BTreeSet, HashSet};

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{Change, ChangePurpose, Op, PutOrigin};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_engine::conflict::{change_touches_path, path_head_from_change, PathHead};
use yadorilink_replica_engine::conflict_authoring as decision;

use super::path_frontier;
use super::retained_history_integrity;

/// Creates the `conflict_copy_provenance` table if it does not exist. New
/// table only -- like every other additive table in this crate, a bare
/// `CREATE TABLE IF NOT EXISTS` is the whole migration.
pub fn init_conflict_copy_provenance_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS conflict_copy_provenance (
            group_id            TEXT NOT NULL,
            source_path         TEXT NOT NULL,
            losing_change_hash  BLOB NOT NULL,
            carrier_change_hash BLOB NOT NULL,
            target_path         TEXT NOT NULL,
            PRIMARY KEY (group_id, source_path, losing_change_hash)
        );
        "#,
    )?;
    Ok(())
}

fn get_change(conn: &Connection, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError> {
    match retained_history_integrity::get_encoded(conn, hash)? {
        None => Ok(None),
        Some(bytes) => Change::from_wire_bytes(&bytes)
            .map(Some)
            .map_err(|e| SyncSqliteError::CorruptState(format!("corrupt stored change: {e}"))),
    }
}

/// Whether a `ConflictCopy` op has ever been durably recorded for this
/// exact `(source_path, losing_change)` pair, anywhere in the group --
/// regardless of whether its carrier is still a live head, has since been
/// superseded, or even whether the conflict-copy path itself was later
/// deleted. Once recorded, the obligation is permanently discharged: a
/// later deletion of the conflict-copy path is a normal, independent edit to
/// that path, not evidence the obligation needs re-deriving.
pub(crate) fn conflict_copy_already_provisioned(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
    losing_change: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM conflict_copy_provenance \
             WHERE group_id = ?1 AND source_path = ?2 AND losing_change_hash = ?3",
            rusqlite::params![group_id, source_path, &losing_change.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(present.is_some())
}

/// The causally-scoped counterpart to [`conflict_copy_already_provisioned`],
/// used ONLY by admission-side validation (`validate_carrier_conflict_copy_ops`,
/// via `derive_required_conflict_copy_ops_with`): true only when the
/// recorded provenance row's own `carrier_change_hash` is `parents` itself
/// or an ancestor of some entry in `parents` -- i.e. actually reachable from
/// the specific change being validated, not merely known to this device
/// from some unrelated branch. See `derive_required_conflict_copy_ops_with`'s
/// own doc comment for why this distinction is load-bearing, not cosmetic.
fn conflict_copy_provisioned_and_reachable(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
    losing_change: &ChangeHash,
    parents: &[ChangeHash],
) -> Result<bool, SyncSqliteError> {
    let carrier_hash_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT carrier_change_hash FROM conflict_copy_provenance \
             WHERE group_id = ?1 AND source_path = ?2 AND losing_change_hash = ?3",
            rusqlite::params![group_id, source_path, &losing_change.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    let Some(carrier_hash_blob) = carrier_hash_blob else { return Ok(false) };
    let carrier_hash = retained_history_integrity::hash_from_blob(carrier_hash_blob)?;
    for p in parents {
        if *p == carrier_hash || retained_history_integrity::is_ancestor(conn, &carrier_hash, p)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Records provenance for every `ConflictCopy`-origin `Put` in `change`'s own
/// ops, keyed by `(group_id, source_path, losing_change)` -- idempotent
/// (`INSERT OR IGNORE`), so calling this more than once for the same change
/// (e.g. once at local authoring time and again if that change is later
/// re-processed) is harmless. Callers admitting/authoring a change must call
/// this in the SAME transaction as appending it, so a crash between the two
/// can never leave a durably-recorded `ConflictCopy` op invisible to future
/// idempotency checks.
pub fn record_conflict_copy_ops_provenance(
    conn: &Connection,
    group_id: &str,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    let carrier_hash = change.compute_hash();
    for op in &change.ops {
        if let Op::Put {
            path,
            origin: PutOrigin::ConflictCopy { source_path, losing_change },
            ..
        } = op
        {
            conn.execute(
                "INSERT OR IGNORE INTO conflict_copy_provenance \
                 (group_id, source_path, losing_change_hash, carrier_change_hash, target_path) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    group_id,
                    source_path.as_str(),
                    &losing_change.0[..],
                    &carrier_hash.0[..],
                    path.as_str(),
                ],
            )?;
        }
    }
    Ok(())
}

/// Generalizes `peer_session.rs`'s current-heads-only path resolution to an
/// arbitrary historical `frontier`: walks backward from `frontier` (instead
/// of the group's *current* live heads) via retained parent edges, collecting
/// every change that touches `path`, then drops any candidate that is a
/// (strict) ancestor of another -- exactly `store_live_heads_for_path`'s own
/// algorithm, parameterized on the seed frontier so it can resolve "what did
/// this path look like right before a specific new change's parents" instead
/// of only "what does it look like right now".
pub fn path_heads_at_frontier(
    conn: &Connection,
    group_id: &str,
    path: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<PathHead>, SyncSqliteError> {
    path_heads_at_frontier_indexed(conn, group_id, path, frontier)
}

/// Whether `frontier` is exactly the group's current head set.
///
/// Set equality, not sequence equality: `group_heads` returns its rows in
/// hash order and a change's parents are canonically sorted, but a caller
/// may hand either one over in any order, and answering "no" to a
/// frontier that is in fact the current one would silently reinstate a
/// walk rather than produce a wrong result -- a performance cliff is
/// harder to notice than a failure.
///
/// Both sides are frontiers, so both are small; this is one indexed query
/// and a comparison of a handful of hashes.
fn frontier_is_current_group_heads(
    conn: &Connection,
    group_id: &str,
    frontier: &[ChangeHash],
) -> Result<bool, SyncSqliteError> {
    let current = super::frontier_index::group_heads(conn, group_id)?;
    if current.len() != frontier.len() {
        return Ok(false);
    }
    let current: HashSet<[u8; 32]> = current.iter().map(|h| h.0).collect();
    Ok(frontier.iter().all(|h| current.contains(&h.0)))
}

/// [`path_heads_at_frontier`]'s body: resolves `path`'s heads at `frontier`
/// from the changes indexed as touching it.
fn path_heads_at_frontier_indexed(
    conn: &Connection,
    group_id: &str,
    path: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<PathHead>, SyncSqliteError> {
    // Start from what is known to touch this path, not from the frontier.
    //
    // This used to descend the DAG from `frontier`, decoding every change
    // it passed and stopping a lineage at the first one that touched
    // `path`. That is proportional to how much history the frontier
    // reaches, not to how often the path was written -- and it is at its
    // worst for a path the walk will not find, because nothing lets it
    // stop early.
    //
    // The cost lands on the case peer-to-peer sync exists for. A device
    // returning from offline brings changes whose parents are its own, so
    // every admission resolves against a frontier that is not the current
    // one and the current-frontier read never applies. Two measurements,
    // both on a returning branch:
    //
    // - Carrying paths this device had never seen, the walk had no toucher
    //   to stop at and descended everything reachable: the last hundred
    //   admissions cost 8.1x the first hundred, growing with position,
    //   making the catch-up quadratic in the branch's own length.
    // - Carrying edits to files that already existed -- the ordinary case
    //   -- it cost a flat 3,780us per admission over 1,000 files, ~29x the
    //   first case. Flat, because editing files in creation order happens
    //   to keep the walk a constant length; flat and expensive is not
    //   better than growing, it is just harder to notice.
    //
    // `change_path_effects` already records every retained change that
    // touches a path, so the candidate set is bounded by how often the
    // path was written. Empty settles the question outright. Otherwise
    // what remains is a question about a handful of changes: which of
    // them this frontier can see, and which of those the others supersede
    // -- both answered by the bounded ancestry decision the admission
    // path uses, and neither requiring a change to be decoded at all.
    let candidates = path_frontier::effects_touching_path(conn, group_id, path)?;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut reachable: Vec<PathHead> = Vec::new();
    for candidate in candidates {
        let hash = ChangeHash(candidate.change_hash);
        let visible = frontier.contains(&hash)
            || frontier.iter().try_fold(false, |seen, head| {
                if seen {
                    return Ok::<bool, SyncSqliteError>(true);
                }
                path_frontier::is_ancestor_bounded(conn, &hash, head)
            })?;
        if visible {
            reachable.push(candidate);
        }
    }

    let mut live = Vec::new();
    for candidate in &reachable {
        let hash = ChangeHash(candidate.change_hash);
        let mut superseded = false;
        for other in &reachable {
            if other.change_hash == candidate.change_hash {
                continue;
            }
            if path_frontier::is_ancestor_bounded(conn, &hash, &ChangeHash(other.change_hash))? {
                superseded = true;
                break;
            }
        }
        if !superseded {
            live.push(candidate.clone());
        }
    }
    Ok(live)
}

/// Like [`path_heads_at_frontier_indexed`], but additionally recovers a
/// "buried root": a genesis-shaped content touch for `path` (one with no
/// ancestor, among the changes reachable from `frontier` that also touch
/// `path`, that itself touches `path`) that a later, SINGLE-PARENT
/// descendant already supersedes -- WITHOUT that descendant's own authorship
/// ever having incorporated a genuinely concurrent SIBLING genesis touch.
///
/// Confirmed, reproduced defect this recovers: four (or more) devices each
/// independently author the group's very first `Put` to a brand-new shared
/// path (four concurrent roots, exactly `two_independent_roots_with_no_
/// common_ancestor_are_still_detected_as_a_fork`'s own shape, generalized
/// past two). If one device's own local write happens to race behind a
/// PEER's already-synced root for the SAME path -- a real, confirmed
/// possibility once propagation latency is comparable to the devices'
/// own write-timing stagger, not a hypothetical -- that device's change is
/// authored with the peer's root as its sole DAG parent, and ordinary DAG
/// ancestry then reads as "this change legitimately supersedes its parent."
/// `path_heads_at_frontier_indexed`'s cheap is-ancestor supersession check
/// cannot distinguish that from a genuine sequential edit (a device reading
/// and replacing content it actually observed) because the two are
/// causally IDENTICAL in DAG-ancestry terms -- the only difference is
/// whether a THIRD, unrelated root ALSO existed concurrently with the
/// buried one at the moment it was superseded, information the plain
/// ancestor check never looks for. The buried root's content is then
/// permanently unrecoverable: it is not the group's live winner, it has no
/// live head of its own, and nothing else ever re-examines it, so
/// `multiway_conflict_matrix.rs`'s `four/five/six_devices_staggered` rows
/// stall forever at N-1 preserved contents.
///
/// The fix generalizes `two_independent_roots_with_no_common_ancestor_are_
/// still_detected_as_a_fork`'s own insight (independently-authored roots
/// with no common ancestor are concurrent, full stop) from "currently live"
/// to "ever existed, anywhere in retained history reachable from the
/// frontier": a genesis touch is only safely dropped once EVERY OTHER
/// genesis touch for the same path is reachable from the candidate
/// descendant -- it genuinely incorporated that sibling, exactly what an
/// honest multi-way resolution's own multi-parent carrier naturally
/// provides once it exists (its own parents name every branch it
/// reconciles, so anything descending from IT has every genesis touch as
/// an ordinary transitive ancestor). A non-genesis (continuation) touch --
/// one whose own parent already touches `path`, e.g. a plain sequential
/// edit of content this device's own author causally could have observed
/// -- is dropped exactly as before, with no extra scrutiny:
/// `late_loser_is_preserved_by_one_elected_merge_resolution`'s own root
/// (root -> device-a -> device-d, an ordinary edit chain, with an unrelated
/// sibling B concurrent only with ROOT, not with A) must keep resolving to
/// exactly one preserved loser (B), not three -- A's intermediate content is
/// legitimately superseded by D regardless of B's existence, since A's own
/// authorship already had root's prior state to build on.
///
/// Deliberately NOT used by ordinary local-edit authoring
/// (`derive_required_conflict_copy_ops`'s own default, `ChangePurpose::
/// Ordinary`): a fresh local edit's own emission genuinely cannot detect a
/// sibling root it has not synced yet -- the walk below cannot recover
/// information the emitting replica does not have -- and unconditionally
/// widening every ordinary edit's frontier walk to full, unbounded history
/// (rather than the cheap early-stopping walk) would reproduce exactly the
/// writer-gate-hold regression `paths_that_can_have_concurrent_heads`'s own
/// doc comment measured (46 planning passes holding the gate for 366 of a
/// 348-second window) on every single local edit instead of only the rare
/// retroactive-repair pass. Used only by [`plan_retroactive_merge`]-driven
/// planning and by admission validation of a `ChangePurpose::
/// RetroactiveRepair` carrier specifically (see
/// `validate_carrier_conflict_copy_ops_parts`), both already-rare,
/// already-expensive code paths that pay a full reachable-history decode
/// regardless (`paths_that_can_have_concurrent_heads`'s own unconditional
/// walk), so the additional pairwise ancestry comparisons here (bounded by
/// the number of changes that ever concurrently touched ONE path, not the
/// group's whole history) add no new order-of-magnitude cost.
pub fn path_heads_at_frontier_including_buried_roots(
    conn: &Connection,
    path: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<PathHead>, SyncSqliteError> {
    // Unlike the early-stopping walk above, this visits EVERY change
    // touching `path` reachable from `frontier`, not just the first one
    // found along each lineage -- required to find a genesis touch a later,
    // unaware single-parent descendant has already superseded.
    let mut candidates: Vec<Change> = Vec::new();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut stack: Vec<ChangeHash> = frontier.to_vec();
    while let Some(hash) = stack.pop() {
        if !visited.insert(hash.0) {
            continue;
        }
        let Some(change) = get_change(conn, &hash)? else { continue };
        if change_touches_path(&change, path) {
            candidates.push(change.clone());
        }
        stack.extend(change.parents.iter().copied());
    }

    let hashes: Vec<ChangeHash> = candidates.iter().map(Change::compute_hash).collect();
    let n = candidates.len();

    // `ancestor[i][j]` == is candidate `i` an ancestor of candidate `j`.
    // Computed once, up front, so the genesis classification and the
    // supersession pass below share it rather than re-issuing the same
    // `is_ancestor` query from two different angles.
    let mut ancestor = vec![vec![false; n]; n];
    for i in 0..n {
        for j in 0..n {
            if i != j {
                ancestor[i][j] =
                    retained_history_integrity::is_ancestor(conn, &hashes[i], &hashes[j])?;
            }
        }
    }

    // A candidate is "genesis" for this path if no OTHER candidate touching
    // the same path is its ancestor -- the start of its own lineage here,
    // never itself a sequential edit of some other candidate's content.
    let is_genesis: Vec<bool> = (0..n).map(|i| !(0..n).any(|j| ancestor[j][i])).collect();

    let mut live = Vec::new();
    for i in 0..n {
        let mut superseded = false;
        for (j, &i_ancestor_of_j) in ancestor[i].iter().enumerate() {
            if i == j || !i_ancestor_of_j {
                continue;
            }
            if !is_genesis[i] {
                // A continuation is dropped by any of its own descendants,
                // exactly like the cheap early-stopping walk already does --
                // its own author had this path's prior state to build on,
                // so nothing further needs checking.
                superseded = true;
                break;
            }
            // `i` is a genesis touch: `j` (its descendant) only properly
            // closes it if every OTHER genesis touch is something `j`
            // itself incorporated (reachable as `j`'s own ancestor).
            //
            // Deliberately NOT also treating a sibling `k` already
            // recorded in `conflict_copy_provenance` as "safe to ignore"
            // here: `conflict_copy_already_provisioned` is a group-wide
            // EXISTENCE check, not scoped to what `j` itself can prove --
            // using it here would let this candidate's own live-ness (and
            // therefore whether THIS SAME op is required) depend on
            // whether some UNRELATED, already-admitted carrier happens to
            // have recorded `k`'s provenance, which can differ between
            // authoring time (before this very carrier's own admission)
            // and a later validator re-examining it (after admission,
            // once this carrier's own provenance rows already exist) --
            // exactly the authoring-vs-validation inconsistency
            // `derive_required_conflict_copy_ops_with`'s own doc comment
            // warns `already_provisioned` must never be conflated across
            // (confirmed: reproduced live as a false rejection on a
            // carrier re-validating its own output). A genuine multi-way
            // resolution already satisfies "reachable from `j`" without
            // any such escape once it exists: the resolving carrier's own
            // parents name every branch it reconciles, so a later
            // superseding descendant naturally has every genesis touch as
            // an ordinary transitive ancestor -- see this function's own
            // doc comment.
            let properly_closes =
                (0..n).filter(|&k| k != i && k != j && is_genesis[k]).all(|k| ancestor[k][j]);
            if properly_closes {
                superseded = true;
                break;
            }
        }
        if !superseded {
            live.push(candidates[i].clone());
        }
    }
    Ok(live.iter().filter_map(|c| path_head_from_change(c, path)).collect())
}

/// Computes the `ConflictCopy` `Put` ops a new local change must carry,
/// given the exact `parents` it will be signed onto and its own `direct_ops`
/// (never including any op this function itself derives). For every path any
/// direct op touches (a `Put`'s `path`, a `Delete`'s `path`, or either side of
/// a `Move` -- exactly the set `collect_op_paths` would compute, since a
/// removal dominates a prior fork just as much as a new put does), resolves
/// that path's live heads AT `parents` (not the group's current heads, which
/// may already include this change's own not-yet-signed effect in a caller
/// that builds `parents` from `group_heads` immediately before calling this).
/// Any losing content head not already durably provisioned
/// (`conflict_copy_already_provisioned`) becomes a `ConflictCopy` `Put` in the
/// returned set, carried by the change these ops are folded into.
///
/// Pure with respect to admission ordering: does not itself record
/// provenance or append anything -- the caller signs the combined op set and
/// is responsible for calling `record_conflict_copy_ops_provenance` once the
/// resulting change is actually appended (never before, and never for a
/// change that then fails to append).
pub fn derive_required_conflict_copy_ops(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    direct_ops: &[Op],
) -> Result<Vec<Op>, SyncSqliteError> {
    derive_required_conflict_copy_ops_with(
        conn,
        group_id,
        parents,
        direct_ops,
        false,
        &|conn, source_path, losing_change| {
            conflict_copy_already_provisioned(conn, group_id, source_path, losing_change)
        },
    )
}

/// Like [`derive_required_conflict_copy_ops`], but resolves each touched
/// path's heads via [`path_heads_at_frontier_including_buried_roots`]
/// instead of the cheap early-stopping walk, so a genesis-shaped root
/// buried by an unaware single-parent descendant is recovered as its own
/// obligation -- see that function's own doc comment for the confirmed
/// defect this exists to close. Used only by retroactive-repair planning
/// (`plan_retroactive_merge`) and by admission validation of a
/// `ChangePurpose::RetroactiveRepair` carrier specifically; never by
/// ordinary local-edit authoring, which cannot detect a sibling root it has
/// not synced yet and would otherwise pay this walk's full-history cost on
/// every edit for no benefit.
pub fn derive_required_conflict_copy_ops_including_buried_roots(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    direct_ops: &[Op],
) -> Result<Vec<Op>, SyncSqliteError> {
    derive_required_conflict_copy_ops_with(
        conn,
        group_id,
        parents,
        direct_ops,
        true,
        &|conn, source_path, losing_change| {
            conflict_copy_already_provisioned(conn, group_id, source_path, losing_change)
        },
    )
}

/// The obligations a change emitted at `parents` must carry, asked the way
/// ADMISSION will ask it.
///
/// [`derive_required_conflict_copy_ops`] asks the group-wide, existence-only
/// question -- "has any carrier, anywhere in this group's history, ever
/// recorded this obligation?" -- which is the right question for
/// idempotency and the wrong one for deciding what to emit. Admission asks
/// the causally-scoped one: was it satisfied by something reachable from
/// THIS carrier's parents. Where the two differ, an author that used the
/// existence-only answer emits a change that its OWN emission-time
/// validation then rejects as deficient, and re-driving derives the same
/// deficient set again. Observed on a six-device mesh as
/// `carrier change is missing a required conflict-copy put` repeating for
/// one losing change until the group stopped converging.
///
/// `include_buried_roots` mirrors the walk the same carrier's validation
/// will use -- see [`derive_required_conflict_copy_ops_including_buried_roots`].
pub fn derive_required_conflict_copy_ops_as_admission_will(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    direct_ops: &[Op],
    include_buried_roots: bool,
) -> Result<Vec<Op>, SyncSqliteError> {
    derive_required_conflict_copy_ops_with(
        conn,
        group_id,
        parents,
        direct_ops,
        include_buried_roots,
        &|conn, source_path, losing_change| {
            conflict_copy_provisioned_and_reachable(
                conn,
                group_id,
                source_path,
                losing_change,
                parents,
            )
        },
    )
}

/// Shared body of [`derive_required_conflict_copy_ops`] (authoring: an
/// existence-only, group-wide idempotency check -- "has ANY carrier,
/// anywhere in this group's history, ever recorded this obligation?") and
/// [`validate_carrier_conflict_copy_ops`]'s own required-set computation
/// (admission: a causally-scoped check -- "was this obligation satisfied
/// by something reachable from the SPECIFIC carrier being validated?").
///
/// These two questions are NOT interchangeable, and conflating them was a
/// real, confirmed bug: reusing the authoring-side existence check for
/// admission validation made a carrier's acceptance depend on which OTHER,
/// unrelated carriers the validating device happened to have already seen
/// -- device A (having separately received some unrelated carrier C that
/// also satisfies the same `(source_path, losing_change)` pair) would
/// admit a change X missing its own required `ConflictCopy` op, while
/// device B (never having received C) would reject the SAME signed change
/// X as deficient. A signed change's validity must depend only on its own
/// content and causal ancestry, never on a validator's incidental local
/// knowledge of unrelated history.
fn derive_required_conflict_copy_ops_with(
    conn: &Connection,
    group_id: &str,
    parents: &[ChangeHash],
    direct_ops: &[Op],
    include_buried_roots: bool,
    already_provisioned: &dyn Fn(&Connection, &str, &ChangeHash) -> Result<bool, SyncSqliteError>,
) -> Result<Vec<Op>, SyncSqliteError> {
    let touched_paths = decision::collect_touched_paths(direct_ops);

    // Resolved once for the whole derivation, not once per path.
    //
    // The walk below answers "what were this path's live heads at
    // `parents`". When `parents` is the group's current head set, that is
    // the question `path_live_heads` already holds the answer to -- it is
    // maintained as changes are admitted for exactly this question -- so
    // the walk has nothing to add and is skipped entirely.
    //
    // This matters because the derivation runs on every admission, once
    // per path the change touches, and each walk visits the whole
    // frontier-reachable DAG. Measured on a single-headed chain: admitting
    // into a group of 9,500 changes cost ~37x what admitting into an empty
    // one did, all of it here. Reading the index instead makes that cost
    // flat, which is what stops the supersession decision from simply
    // having moved from read time to write time.
    //
    // A structural test on the frontier, not on where the change came
    // from. Ordinary local emission always signs onto the current
    // frontier, so it always takes this route; a remote change takes it
    // whenever its parents happen to cover exactly what this device
    // currently holds, which is the ordinary steady state for a device
    // that is merely behind. Anything else -- a genuinely historical
    // frontier, a buried-root derivation -- still walks, because no index
    // answers for a frontier other than the current one, and this is
    // deliberately not the place to start pretending otherwise.
    let frontier_is_current =
        !include_buried_roots && frontier_is_current_group_heads(conn, group_id, parents)?;

    // The fork a change closes by its parents is among the current epoch's
    // heads alone: an installed base's head is no DAG node, so no parent
    // set covers one, and a change supersedes it only by naming it. The
    // live frontier's own reader also carries the base's unnamed heads,
    // so the epoch's are read here -- exactly what the walks below see.
    let heads_at = |conn: &Connection, path: &str| {
        if frontier_is_current {
            return super::path_frontier::live_epoch_path_heads(conn, group_id, path);
        }
        if include_buried_roots {
            path_heads_at_frontier_including_buried_roots(conn, path, parents)
        } else {
            path_heads_at_frontier_indexed(conn, group_id, path, parents)
        }
    };
    let mut derived_ops = Vec::new();
    for path in touched_paths {
        let heads = heads_at(conn, &path)?;
        let directories = directory_head_changes(conn, group_id, &path, &heads)?;
        for candidate in decision::conflict_copy_candidates(&path, &heads, |head| {
            directories.contains(&head.change_hash)
        }) {
            let losing_change = candidate.losing_change;
            if already_provisioned(conn, &path, &losing_change)? {
                tracing::debug!(
                    group_id,
                    source_path = %path,
                    target_path = %candidate.target_path,
                    losing_change = %hex::encode(losing_change.0),
                    "derive_required_conflict_copy_ops: skipping, already durably provisioned"
                );
                continue;
            }
            // A loser with no durable `ConflictCopy` provenance yet is NOT
            // automatically virgin ground: the OLD ephemeral fixpoint may
            // have already materialized it to disk with no DAG record at
            // all, and the user may have since directly edited/deleted that
            // literal path (a confirmed, reproduced bug: deriving a fresh
            // `ConflictCopy` op here for a loser whose target path a later
            // change already touched directly resurrects a conflict copy
            // the user explicitly deleted, once a late-joining device
            // catches up through pure DAG replication with no ephemeral
            // fixpoint of its own to have "already deleted" it against).
            //
            // The suppression must itself be causally scoped, not merely
            // "does ANY history exist at the target path": the deterministic
            // name embeds the loser's own hash, so a coincidental
            // pre-existing (or entirely unrelated) file at that literal path
            // predates or is unrelated to this specific conflict, not a
            // resolution of it -- suppressing derivation there would
            // silently drop the loser's content instead of preserving it.
            // Only an existing head that STRICTLY descends from
            // `losing_change` is evidence of an actual later action ON
            // this conflict's own resolution (the ordinary case: a device
            // edits/deletes/renames the conflict-copy path only after it
            // exists, so any such action necessarily has `losing_change` as
            // an ancestor).
            //
            // The losing change ITSELF is deliberately not such evidence,
            // and treating it as evidence lost content outright
            // (reproduced as a unit test, see
            // `derive_provisions_a_loser_that_itself_touches_its_own_
            // conflict_target`). Whatever the loser did at the target
            // path, it did before -- in fact instead of -- preserving the
            // content it was about to lose at the source path, so it is
            // not a later action on a resolution that had not happened
            // yet. This is reachable from an ordinary user action, not a
            // contrivance: the deterministic target name embeds the losing
            // content's own hash, so a change can only land on it by
            // putting or removing exactly the content it is about to lose
            // -- which is precisely "resolve a conflict by keeping the
            // conflicted copy" (copy its bytes over the real file, delete
            // the copy), and local capture commits one debounce batch as
            // ONE signed change. If a peer edited the same file
            // concurrently, that change is the loser and the content the
            // user deliberately chose to keep is what would be dropped.
            //
            // The one shape where the loser touching its own target IS
            // benign -- the loser having put that very content there
            // itself -- stays suppressed, by the identical-content check
            // below, which is the check that actually establishes the
            // content is preserved.
            let target_heads = heads_at(conn, &candidate.target_path)?;
            // Fallible loop, not `.any(...).unwrap_or(false)`: a DB error or
            // corrupted ancestry index here must fail closed, not silently
            // read as "not already acted on" -- that would let this
            // function derive a fresh `ConflictCopy` op on top of an
            // ancestry check this device could not actually verify,
            // potentially resurrecting an explicitly-deleted conflict copy
            // or signing a new change against corrupted history.
            let mut already_acted_on = false;
            for h in &target_heads {
                if retained_history_integrity::is_ancestor(
                    conn,
                    &losing_change,
                    &ChangeHash(h.change_hash),
                )? {
                    already_acted_on = true;
                    break;
                }
            }
            if already_acted_on {
                tracing::debug!(
                    group_id,
                    source_path = %path,
                    target_path = %candidate.target_path,
                    losing_change = %hex::encode(losing_change.0),
                    "derive_required_conflict_copy_ops: skipping, target path already acted on \
                     after the loser"
                );
                continue;
            }
            // Also skip when the deterministic target path already holds the
            // loser's exact content at this frontier, regardless of WHICH
            // losing_change put it there. The per-losing_change checks above
            // deliberately key on causal descent from this specific loser,
            // and that key has a confirmed, reproduced blind spot (observed
            // live as a carrier storm on a contended host): a straggler
            // carrier that reasserts a stale winner version becomes a fresh
            // concurrent loser with a brand-new change hash but content that
            // an earlier wave's carrier ALREADY preserved at this exact
            // deterministic name (the name embeds the content hash, so same
            // content ⇒ same target). Neither check above can see that —
            // the new loser has no provenance row and the existing target
            // write does not descend from it — so every such straggler
            // re-derived the same copy, each new carrier could itself become
            // the next straggler, and under delivery lag the repair loop
            // re-minted carriers faster than the mesh could converge. A
            // copy whose byte-identical content is already durably at its
            // own deterministic target preserves nothing by being written
            // again; suppressing it bounds the carrier cascade. Causally
            // sound for admission's shared use of this body: the evidence
            // is `path_heads_at_frontier` at the carrier's own parents,
            // identical on every honest validator.
            let already_preserved_identically = decision::content_already_preserved_at_target(
                &target_heads,
                &candidate.losing_content.version_hash,
            );
            if already_preserved_identically {
                tracing::debug!(
                    group_id,
                    source_path = %path,
                    target_path = %candidate.target_path,
                    losing_change = %hex::encode(losing_change.0),
                    "derive_required_conflict_copy_ops: skipping, target already preserves this \
                     exact content at this frontier"
                );
                continue;
            }
            tracing::debug!(
                group_id,
                source_path = %path,
                target_path = %candidate.target_path,
                losing_change = %hex::encode(losing_change.0),
                "derive_required_conflict_copy_ops: deriving a ConflictCopy put"
            );
            derived_ops.push(decision::build_conflict_copy_op(&path, &candidate));
        }
    }
    Ok(derived_ops)
}

/// The change hashes of `path`'s content heads whose version is a
/// Directory, for [`decision::conflict_copy_candidates`] and the claim
/// validators, which resolve a fork under DIR-1: an explicit Directory
/// keeps its path whoever wins the rank, every File or Symlink there (the
/// ranked winner included) is owed its copy, and a Directory is owed none
/// (an empty directory beside `path` carries nothing). See
/// `yadorilink_replica_engine::conflict::resolve_path_heads_keeping_directory`.
///
/// Fails closed with [`SyncSqliteError::NotFound`] when a forked head's
/// version is not held: every change admitted here had its versions checked in,
/// so a missing one is local damage, and guessing its kind would let two
/// validators disagree on the same carrier.
pub(crate) fn directory_head_changes(
    conn: &Connection,
    group_id: &str,
    path: &str,
    heads: &[PathHead],
) -> Result<HashSet<[u8; 32]>, SyncSqliteError> {
    let mut directories = HashSet::new();
    // Kind only decides between distinct contents: with one content class
    // (or none) there is no fork to resolve, and nothing is read, so a
    // replica that does not hold an unforked version is not asked for it.
    if !matches!(
        yadorilink_replica_engine::conflict::resolve_path_heads(path, heads),
        yadorilink_replica_engine::conflict::PathResolution::Present { ref conflict_copies, .. }
            if !conflict_copies.is_empty()
    ) {
        return Ok(directories);
    }
    for head in heads {
        let Some(content) = head.content.as_ref() else {
            continue;
        };
        let version_hash = VersionHash(content.version_hash);
        let version = super::get_file_version(conn, group_id, &version_hash)?.ok_or_else(|| {
            SyncSqliteError::NotFound(format!(
                "live version {} at {path} is not locally resolvable",
                version_hash.to_hex()
            ))
        })?;
        if version.meta.record_kind == yadorilink_replica_domain::file::RecordKind::Directory {
            directories.insert(head.change_hash);
        }
    }
    Ok(directories)
}

/// Store-dependent structural validation for one `Put { origin: ConflictCopy
/// { source_path, losing_change }, .. }` op inside `carrier`. Re-derives and
/// requires exact agreement with what an honest author would have computed
/// via [`derive_required_conflict_copy_ops`], so an unauthorized or corrupt
/// claim is rejected rather than trusted:
///
/// 1. `losing_change` is reachable from `carrier`'s own parents (its content
///    could plausibly have been visible to `carrier`'s author).
/// 2. `losing_change` actually puts content at `source_path` (with the
///    version this op claims).
/// 3. At `carrier`'s parent frontier, that content head is a genuine
///    concurrent LOSER for `source_path` (not the winner, and not already
///    superseded there by something else at that frontier).
/// 4. `path` matches the deterministic name `conflict_copy_path_for_losing_change`
///    computes from `source_path`/the loser's own device/mtime/version.
/// 5. `version` matches the loser's own version hash exactly.
///
/// Callers are responsible for point 6 (no excess/deficient `ConflictCopy`
/// ops across the WHOLE carrier) by validating every such op the carrier
/// contains, not just one in isolation.
/// Takes the carrier's parents rather than the whole carrier: they are the
/// only field of it this check reads, and expressing it that way lets local
/// emission run the check before the carrier has been signed. See
/// [`validate_carrier_conflict_copy_ops_parts`].
// One argument per field of the conflict-copy op being validated.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_conflict_copy_origin(
    conn: &Connection,
    group_id: &str,
    carrier_parents: &[ChangeHash],
    path: &str,
    version: &VersionHash,
    source_path: &str,
    losing_change: &ChangeHash,
    include_buried_roots: bool,
) -> Result<(), SyncSqliteError> {
    // Fallible loop, not `.any(...).unwrap_or(false)`: a DB error or
    // corrupted ancestry index here must fail closed (reject this carrier
    // as unverifiable), not silently read as "not reachable" -- the latter
    // would wrongly reject a genuinely valid carrier depending on this
    // device's own local state/errors rather than the carrier's actual
    // causal validity. Reachability itself needs this device's own ancestry
    // index, so it is checked here rather than folded into
    // `decision::validate_conflict_copy_claim`, which operates only on
    // already-fetched `heads` -- see that function's own doc comment.
    let mut reachable = false;
    for p in carrier_parents {
        if p == losing_change || retained_history_integrity::is_ancestor(conn, losing_change, p)? {
            reachable = true;
            break;
        }
    }
    if !reachable {
        return Err(SyncSqliteError::InvalidInput(format!(
            "conflict-copy put's losing_change {} is not reachable from its carrier's parents",
            hex::encode(losing_change.0),
        )));
    }

    let heads = if include_buried_roots {
        path_heads_at_frontier_including_buried_roots(conn, source_path, carrier_parents)?
    } else {
        path_heads_at_frontier(conn, group_id, source_path, carrier_parents)?
    };
    let directories = directory_head_changes(conn, group_id, source_path, &heads)?;
    decision::validate_conflict_copy_claim(
        &heads,
        path,
        version,
        source_path,
        losing_change,
        |head| directories.contains(&head.change_hash),
    )
    .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))
}

/// Re-derives and validates every `ConflictCopy` `Put` op `carrier` claims,
/// checking both point 6 (no excess/deficient ops) and point 7 (no two ops
/// on the same target path -- already enforced independently by
/// `Change::validate_structure`'s "one op per path" check, not re-verified
/// here) from `validate_conflict_copy_origin`'s own doc comment. The
/// re-derivation itself is exactly `derive_required_conflict_copy_ops`
/// applied to `carrier`'s own (parents, direct ops) -- an honest carrier's
/// `ConflictCopy` ops must be EXACTLY that set, no more, no less.
pub fn validate_carrier_conflict_copy_ops(
    conn: &Connection,
    group_id: &str,
    carrier: &Change,
) -> Result<(), SyncSqliteError> {
    validate_carrier_conflict_copy_ops_parts(
        conn,
        group_id,
        &carrier.parents,
        &carrier.ops,
        &carrier.purpose,
    )
}

/// The body of [`validate_carrier_conflict_copy_ops`], expressed over the
/// three fields of the carrier it actually reads. Neither the signature nor
/// the authorization stamp is consulted, so local emission can run exactly
/// this check on a change it has not signed yet -- see
/// `dag_store::prepare_emission` for why everything database-derived must be
/// settled before an authorization coordinate is acquired.
pub(crate) fn validate_carrier_conflict_copy_ops_parts(
    conn: &Connection,
    group_id: &str,
    carrier_parents: &[ChangeHash],
    carrier_ops: &[Op],
    carrier_purpose: &ChangePurpose,
) -> Result<(), SyncSqliteError> {
    // A `RetroactiveRepair` carrier is validated with the SAME buried-root-
    // aware walk `plan_retroactive_merge`/`prepare_emission` used to compute
    // its obligations in the first place -- see
    // `derive_required_conflict_copy_ops_including_buried_roots`'s own doc
    // comment. `ChangePurpose::Ordinary` (an ordinary local edit's own
    // self-derived `ConflictCopy` ops, folded in at authoring time) keeps
    // the cheap early-stopping walk: it never claims a buried-root-style op,
    // so it never needs the expensive one to validate.
    let include_buried_roots = matches!(carrier_purpose, ChangePurpose::RetroactiveRepair { .. });

    let mut claimed: BTreeSet<(String, ChangeHash)> = BTreeSet::new();
    for op in carrier_ops {
        if let Op::Put {
            path,
            version,
            origin: PutOrigin::ConflictCopy { source_path, losing_change },
        } = op
        {
            validate_conflict_copy_origin(
                conn,
                group_id,
                carrier_parents,
                path.as_str(),
                version,
                source_path.as_str(),
                losing_change,
                include_buried_roots,
            )?;
            claimed.insert((source_path.as_str().to_string(), *losing_change));
        }
        // A re-assertion's provenance is re-derived from the carrier's own
        // parents, never trusted: `naming_device_id` decides how this
        // content is named if it ever loses a later conflict, so an
        // unchecked claim would let a carrier attribute another device's
        // content to itself (or to nobody).
        if let Op::Put {
            path,
            version,
            origin: PutOrigin::Reasserted { original_change, naming_device_id },
        } = op
        {
            // Still a walk, deliberately. Unlike the derivation above,
            // this runs only for a carrier that actually carries a
            // re-assertion, which ordinary editing never produces -- so
            // it is not on the path every admission takes, and routing it
            // through the current-frontier index would buy nothing while
            // widening what depends on that index. The same goes for
            // `validate_conflict_copy_origin`'s own walk.
            let heads = if include_buried_roots {
                path_heads_at_frontier_including_buried_roots(conn, path.as_str(), carrier_parents)?
            } else {
                path_heads_at_frontier(conn, group_id, path.as_str(), carrier_parents)?
            };
            let directories = directory_head_changes(conn, group_id, path.as_str(), &heads)?;
            decision::validate_reassertion_claim(
                &heads,
                path.as_str(),
                version,
                original_change,
                naming_device_id.as_str(),
                |head| directories.contains(&head.change_hash),
            )
            .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))?;
        }
    }

    let direct_ops: Vec<Op> = carrier_ops
        .iter()
        .filter(|op| !matches!(op, Op::Put { origin: PutOrigin::ConflictCopy { .. }, .. }))
        .cloned()
        .collect();

    decision::validate_retroactive_repair_claims(carrier_purpose, &direct_ops, &claimed)
        .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))?;

    // Uses the causally-scoped `conflict_copy_provisioned_and_reachable`
    // here, NOT `derive_required_conflict_copy_ops`'s own default
    // (existence-only) check -- see `derive_required_conflict_copy_ops_with`'s
    // doc comment for why conflating the two let two devices disagree on
    // the admissibility of the identical signed change depending on which
    // OTHER, unrelated carriers each had separately already seen.
    let required = derive_required_conflict_copy_ops_with(
        conn,
        group_id,
        carrier_parents,
        &direct_ops,
        include_buried_roots,
        &|conn, source_path, losing_change| {
            conflict_copy_provisioned_and_reachable(
                conn,
                group_id,
                source_path,
                losing_change,
                carrier_parents,
            )
        },
    )?;
    // `required` itself already excludes every loser causally provisioned by
    // something reachable from `carrier.parents` (via the closure above);
    // `validate_claimed_matches_required` checks both that every remaining
    // required op is claimed (point 6) and the reverse direction -- every
    // op this carrier CLAIMS must actually be required, not just every
    // required op claimed. Each individual claimed op already passed
    // `validate_conflict_copy_origin` above -- confirming it names a real,
    // still-live loser reachable from the carrier's own parents -- but that
    // alone doesn't prove THIS carrier is the one obligated to resolve it:
    // an authorized device could otherwise attach a gratuitous, individually
    // "valid" ConflictCopy claim for some unrelated concurrent fork to a
    // change whose own direct ops don't touch that fork's source path at
    // all, without ever actually closing it (this carrier's real direct ops
    // are on a completely different path). That carrier would still be
    // admitted, and would durably record provenance for an obligation it
    // never genuinely resolved -- letting the actual source conflict remain
    // open while suppressing any FUTURE, genuine carrier from ever being
    // required to resolve it.
    decision::validate_claimed_matches_required(&required, &claimed)
        .map_err(|e| SyncSqliteError::InvalidInput(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests;
