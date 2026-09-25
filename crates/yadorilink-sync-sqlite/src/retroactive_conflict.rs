//! Plans merge-resolution changes for conflict-copy obligations that become
//! visible only after the winner-descending change was already signed.
//!
//! Ordinary authoring can inspect only the parents known at signing time. If a
//! concurrent losing branch arrives later, the old signed change is immutable.
//! The repair publishes a first-class `RetroactiveRepair` change from any
//! currently authorized writer whose deterministic failover rank is eligible.
//! The change directly reasserts the already-current winner version at the
//! source path and signs the exact logical obligations alongside the derived
//! `PutOrigin::ConflictCopy` operations.
//!
//! # Plan optimistically, validate at commit
//!
//! What must hold is that a newly-arriving head does not change the winner
//! between election and signing: a stale version reasserted with a newer
//! Lamport timestamp would be a real corruption. That was previously obtained
//! by running planning, election and emission inside one IMMEDIATE
//! transaction — which also meant holding the process-wide writer gate for the
//! whole traversal. It was measured holding the gate for 366 of one
//! 348-second window across 46 passes, and independently as the dominant
//! writer-gate consumer by a 5-7x margin, up to ~2180s cumulative in one run.
//!
//! The same invariant is obtained far more cheaply by naming what it depends
//! on. Planning captures a [`PublishedFrontierToken`] — the group's heads as
//! it saw them — and runs outside any write transaction. The short commit
//! transaction requires that token to still be current before it emits
//! anything. A frontier that moved means the plan was built against a view
//! that no longer exists, so nothing is written and the pass is re-driven.
//!
//! # The frontier alone is not the whole assumption
//!
//! Planning reads more than the frontier-reachable DAG. `derive_required_
//! conflict_copy_ops` also consults durable conflict-copy provenance — a
//! group-wide existence check — and the retained-history boundary moves under
//! compaction. Treating "the frontier has not moved" as a proxy for "nothing
//! the plan depended on has moved" would be reasoning from a coincidence.
//!
//! So the commit re-runs the derivation itself, for the paths the plan
//! actually selected, and requires the same obligations to come out. That is
//! bounded work — a handful of paths, not the whole group — and it checks the
//! plan's conclusion rather than a stand-in for it. The frontier token is
//! still checked first, because it is the cheapest way to detect the common
//! case and it also pins what emission will derive against.
//!
//! # One snapshot, not several
//!
//! Planning must see a single consistent database. `SyncDatabase::read` opens
//! no transaction, so a multi-statement read through it can observe a
//! different database between one statement and the next — a plan built that
//! way describes a state that never existed. Planning runs through
//! `read_snapshot`, which holds one DEFERRED snapshot throughout and, in WAL
//! mode, excludes no writer while it does.

use std::collections::HashSet;

use rusqlite::Connection;

use crate::dag_store;
use crate::SyncSqliteError;
use yadorilink_replica_domain::change::{
    encoded_op_len, Change, Op, PutOrigin, RepairObligation, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};
use yadorilink_replica_domain::limits::MAX_OPS;
use yadorilink_replica_engine::conflict::{resolve_path_heads_keeping_directory, PathResolution};

/// The final signed change can contain more operations than `direct_ops`,
/// because ordinary authoring adds one conflict-copy operation per unresolved
/// distinct losing version. The canonical byte cap normally binds first, but
/// the decoder's absolute op-count limit remains a second fail-closed bound.
const MAX_RETROACTIVE_CARRIER_OPS: usize = MAX_OPS;

/// The group's published frontier as a plan saw it.
///
/// A plan is only meaningful against the frontier it was built from, so the
/// frontier travels with it and is re-checked before anything is written.
/// Heads are sorted, so this compares by value rather than by the order a
/// query happened to return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedFrontierToken {
    heads: Vec<ChangeHash>,
}

impl PublishedFrontierToken {
    /// The frontier `group_id` has right now.
    pub fn capture(conn: &Connection, group_id: &str) -> Result<Self, SyncSqliteError> {
        let mut heads = dag_store::group_heads(conn, group_id)?;
        heads.sort();
        Ok(Self { heads })
    }

    /// Whether the frontier is still exactly what this token recorded.
    pub fn is_current(&self, conn: &Connection, group_id: &str) -> Result<bool, SyncSqliteError> {
        Ok(Self::capture(conn, group_id)? == *self)
    }

    /// The heads themselves, for a caller that reports the frontier it acted
    /// against.
    pub fn heads(&self) -> &[ChangeHash] {
        &self.heads
    }
}

/// Why a plan may no longer be committed.
///
/// Deliberately not collapsed to "the frontier moved": the frontier is only
/// the cheapest of a plan's assumptions, and the derivation also reads durable
/// conflict-copy provenance and the retained-history boundary, neither of
/// which disturbs the frontier when it changes.
pub type PlanStaleness = yadorilink_replica_domain::session_state::PlanStaleReason;

#[derive(Debug)]
pub struct RetroactivePlan {
    pub direct_ops: Vec<Op>,
    pub obligations: Vec<RepairObligation>,
    pub source_paths: Vec<String>,
    /// The frontier this plan was built against. The commit refuses unless it
    /// is still current.
    pub frontier: PublishedFrontierToken,
}

/// Distinguishes "nothing to do right now" (this device isn't elected for
/// any eligible path, or every eligible path was already repaired) and
/// "there IS an eligible path, but it can never fit in one bounded change on
/// its own" from ordinary transient failures (`Err(SyncError)`, e.g. a
/// database error). The caller needs this distinction to decide whether the
/// current frontier is safe to cache: a transient failure must be retried
/// on the very next poll, but re-planning against the SAME frontier for a
/// path whose own obligation exceeds the bound can only ever produce the
/// same `PathObligationTooLarge` result again -- retrying it every poll
/// forever wins nothing and only holds the SQLite writer lock for no
/// purpose. See `engine_wrapper.rs`'s repair loop, which caches this
/// outcome's frontier exactly like a real no-op.
#[derive(Debug)]
pub enum RetroactiveMergeOutcome {
    Plan(RetroactivePlan),
    /// `path`'s own winner-reassertion-plus-conflict-copies bundle alone
    /// already exceeds the bounded change size, even before considering any
    /// other path. Splitting one path's obligation across multiple carriers
    /// is not implemented; until it is, this obligation cannot be repaired.
    PathObligationTooLarge(BlockedPath),
}

/// One path whose own bundle alone exceeds the bounded change size.
///
/// Carries what the verdict was reached from, so it can be rechecked before
/// being treated as permanent. A verdict is only as good as the state it was
/// computed against, and the state it was computed against includes durable
/// conflict-copy provenance and the retained-history boundary — neither of
/// which moves the frontier when it changes. Reporting this as permanent
/// without a recheck, to a caller that caches permanence keyed on the
/// frontier, would suppress the re-plan a provenance change should have
/// triggered.
#[derive(Clone, Debug)]
pub struct BlockedPath {
    pub path: String,
    /// The winner-reassertion op that was sized. Kept so the recheck sizes
    /// the same bundle rather than a re-derived approximation of it.
    direct_op: Op,
    frontier: PublishedFrontierToken,
}

impl BlockedPath {
    /// The frontier this verdict was reached at.
    pub fn frontier(&self) -> &PublishedFrontierToken {
        &self.frontier
    }

    /// Whether this verdict may still be treated as permanent.
    ///
    /// `None` means it stands: the path's own bundle is still oversized.
    /// `Some` means the state it was computed against has moved, so it must
    /// be re-planned rather than cached.
    pub fn revalidate(
        &self,
        conn: &Connection,
        group_id: &str,
    ) -> Result<Option<PlanStaleness>, SyncSqliteError> {
        if !self.frontier.is_current(conn, group_id)? {
            return Ok(Some(PlanStaleness::FrontierMoved));
        }

        let required_copies = dag_store::derive_required_conflict_copy_ops_including_buried_roots(
            conn,
            group_id,
            self.frontier.heads(),
            std::slice::from_ref(&self.direct_op),
        )?;
        let (count, bytes) = bundle_size(&self.direct_op, &required_copies);

        if exceeds_carrier_bound(count, bytes) {
            Ok(None)
        } else {
            // It fits now. Something the derivation reads has changed — a
            // loser durably provisioned elsewhere, history compacted — and
            // the path is repairable after all.
            Ok(Some(PlanStaleness::ObligationsChanged))
        }
    }
}

/// The op count and encoded byte size of one path's winner reassertion plus
/// the conflict copies it requires.
///
/// Shared by planning and by [`BlockedPath::revalidate`] so the two cannot
/// disagree about what "too large" means.
fn bundle_size(direct_op: &Op, required_copies: &[Op]) -> (usize, usize) {
    let mut count = 1usize;
    let mut bytes = encoded_op_len(direct_op);
    for copy in required_copies {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(encoded_op_len(copy));
    }
    (count, bytes)
}

fn exceeds_carrier_bound(count: usize, bytes: usize) -> bool {
    count > MAX_RETROACTIVE_CARRIER_OPS || bytes > MAX_CHANGE_OP_BYTES
}

impl RetroactivePlan {
    /// Whether this plan may still be committed.
    ///
    /// Must be called inside the commit transaction. Two checks, in cost
    /// order: the frontier token, which is one query and catches the common
    /// case; then a re-run of the plan's own derivation for the paths it
    /// selected, which catches everything else the derivation reads —
    /// conflict-copy provenance, the retained-history boundary — without
    /// having to enumerate those and hope the list stays complete.
    ///
    /// Re-deriving is bounded by the plan's own size, not the group's: the
    /// expensive part of planning was finding which paths matter, and that
    /// answer is already in hand.
    pub fn revalidate(
        &self,
        conn: &Connection,
        group_id: &str,
    ) -> Result<Option<PlanStaleness>, SyncSqliteError> {
        if !self.frontier.is_current(conn, group_id)? {
            return Ok(Some(PlanStaleness::FrontierMoved));
        }

        let rederived = dag_store::derive_required_conflict_copy_ops_including_buried_roots(
            conn,
            group_id,
            self.frontier.heads(),
            &self.direct_ops,
        )?;

        let mut now: Vec<RepairObligation> = rederived
            .iter()
            .filter_map(|op| match op {
                Op::Put {
                    origin: PutOrigin::ConflictCopy { source_path, losing_change }, ..
                } => Some(RepairObligation {
                    source_path: source_path.clone(),
                    losing_change: *losing_change,
                }),
                _ => None,
            })
            .collect();
        let mut planned = self.obligations.clone();
        now.sort();
        planned.sort();

        if now != planned {
            return Ok(Some(PlanStaleness::ObligationsChanged));
        }
        Ok(None)
    }
}

#[cfg(test)]
impl RetroactiveMergeOutcome {
    fn expect_plan(self) -> RetroactivePlan {
        match self {
            RetroactiveMergeOutcome::Plan(plan) => plan,
            other => panic!("expected a resolvable plan, got {other:?}"),
        }
    }
}

/// Plans one bounded merge-resolution change against the frontier visible on
/// `conn`.
///
/// Read-only, and deliberately so: this is the expensive half, and it must not
/// run with the writer gate held. The returned plan carries the frontier it
/// was built against; the caller emits inside a short write transaction that
/// refuses unless that frontier is still current.
pub fn plan_retroactive_merge(
    conn: &Connection,
    group_id: &str,
) -> Result<RetroactiveMergeOutcome, SyncSqliteError> {
    let frontier = PublishedFrontierToken::capture(conn, group_id)?;
    let parents = dag_store::group_heads(conn, group_id)?;
    if parents.is_empty() {
        return Ok(RetroactiveMergeOutcome::Plan(RetroactivePlan {
            direct_ops: Vec::new(),
            obligations: Vec::new(),
            source_paths: Vec::new(),
            frontier,
        }));
    }

    // `decode_cache` is this pre-filter's own by-product (the full,
    // unconditional walk it already performs to find candidate paths); the
    // per-path resolution below now uses the buried-root-aware walk instead
    // (see `dag_store::path_heads_at_frontier_including_buried_roots`'s own
    // doc comment for why), which does its own independent decode rather
    // than sharing this cache -- a bounded, accepted extra cost on this
    // already-rare, already-expensive fork-resolution path.
    let (mut paths, _decode_cache) =
        paths_that_can_have_concurrent_heads(conn, group_id, &parents)?;
    paths.sort();

    let mut direct_ops = Vec::new();
    let mut obligations = Vec::new();
    let mut source_paths = Vec::new();
    let mut predicted_op_count = 0usize;
    let mut predicted_op_bytes = 0usize;
    // The first path found whose own bundle alone exceeds the bound. Kept
    // (not returned immediately) so a single oversized path can never block
    // dictionary-order-later paths that would fit fine on their own -- only
    // reported if the whole pass ends with nothing packable at all.
    let mut blocked_path: Option<BlockedPath> = None;

    for path in paths {
        let heads =
            dag_store::path_heads_at_frontier_including_buried_roots(conn, &path, &parents)?;
        // DIR-1: an explicit Directory keeps `path` whoever wins the rank,
        // so the head carried forward is the best Directory head when there
        // is one, and a File or Symlink that outranks it is owed its copy.
        // Re-asserting that File instead would supersede the Directory.
        let directories = dag_store::directory_head_changes(conn, group_id, &path, &heads)?;
        let PathResolution::Present { winner, conflict_copies } =
            resolve_path_heads_keeping_directory(&path, &heads, |head| {
                directories.contains(&head.change_hash)
            })
        else {
            continue;
        };
        if conflict_copies.is_empty() {
            continue;
        }

        let winner_content = heads[winner]
            .content
            .as_ref()
            .expect("resolve_path_heads only selects a content head as winner");
        // Re-asserted, not `Direct`: this carrier is signed by whichever
        // device the repair election picked, which is generally not the
        // device that wrote `winner_content`. Emitting it as a plain direct
        // put would supersede the real author's head and silently transfer
        // the content's naming identity to the repairer -- so a later
        // conflict would preserve this content under the repairer's name and
        // drop the author's entirely.
        let direct_op = Op::Put {
            path: SyncPath(path.clone()),
            version: VersionHash(winner_content.version_hash),
            origin: PutOrigin::Reasserted {
                original_change: ChangeHash(heads[winner].change_hash),
                naming_device_id: yadorilink_replica_domain::ids::DeviceId(
                    heads[winner].naming_device_id.clone(),
                ),
            },
        };

        // Authoritative derivation, not `conflict_copies` directly: a copy
        // already durably provisioned, or whose target a later change has
        // since touched, is skipped by real authoring (see
        // `derive_required_conflict_copy_ops`'s own doc comment) -- sizing
        // against the raw `resolve_path_heads` prediction could report a
        // path as oversized when the change that would actually be signed
        // fits easily.
        let required_copies = dag_store::derive_required_conflict_copy_ops_including_buried_roots(
            conn,
            group_id,
            &parents,
            std::slice::from_ref(&direct_op),
        )?;

        if required_copies.is_empty() {
            // Every loser this frontier still shows for the path is already
            // durably preserved (each was skipped by the authoritative
            // derivation's provisioned/acted-on/identical-content checks).
            // A carrier emitted here would carry nothing: its only content
            // would be reasserting the already-current winner, i.e. a new
            // head whose sole effect is frontier churn — and under delivery
            // lag that churn is self-sustaining, because every reassertion
            // is itself a change other devices' repair passes react to.
            // The repair exists to make missing copies durable; when none
            // are missing there is nothing to repair, so emit nothing.
            continue;
        }

        let (added_count, added_bytes) = bundle_size(&direct_op, &required_copies);

        if exceeds_carrier_bound(added_count, added_bytes) {
            if blocked_path.is_none() {
                blocked_path = Some(BlockedPath {
                    path: path.clone(),
                    direct_op: direct_op.clone(),
                    frontier: frontier.clone(),
                });
            }
            continue;
        }

        let would_exceed = predicted_op_count.saturating_add(added_count)
            > MAX_RETROACTIVE_CARRIER_OPS
            || predicted_op_bytes.saturating_add(added_bytes) > MAX_CHANGE_OP_BYTES;
        if would_exceed {
            // Doesn't fit this carrier's remaining budget; leave it for the
            // next poll's fresh planning pass rather than searching further
            // dictionary-order paths for a smaller fit.
            break;
        }

        predicted_op_count += added_count;
        predicted_op_bytes += added_bytes;
        obligations.extend(required_copies.iter().map(|copy| {
            let Op::Put { origin: PutOrigin::ConflictCopy { source_path, losing_change }, .. } =
                copy
            else {
                unreachable!("derive_required_conflict_copy_ops only returns conflict-copy puts")
            };
            RepairObligation { source_path: source_path.clone(), losing_change: *losing_change }
        }));
        direct_ops.push(direct_op);
        source_paths.push(path);
    }

    if !direct_ops.is_empty() {
        return Ok(RetroactiveMergeOutcome::Plan(RetroactivePlan {
            direct_ops,
            obligations,
            source_paths,
            frontier,
        }));
    }
    if let Some(blocked) = blocked_path {
        return Ok(RetroactiveMergeOutcome::PathObligationTooLarge(blocked));
    }
    Ok(RetroactiveMergeOutcome::Plan(RetroactivePlan {
        direct_ops: Vec::new(),
        obligations: Vec::new(),
        source_paths: Vec::new(),
        frontier,
    }))
}

/// Every path that MIGHT resolve to more than one live head at `frontier`,
/// found in a single traversal that decodes each reachable change exactly once.
///
/// This is a pre-filter for the planning loop above, not a change to what it
/// decides. A path touched by at most one change reachable from the frontier
/// can have at most one live path head, and `resolve_path_heads` derives a
/// conflict copy only *between* two content heads carrying different version
/// hashes -- with one head there is no "other" class to copy, and with none it
/// resolves `Absent`. Either way the planning loop would `continue`, so
/// dropping such a path here cannot change the plan.
///
/// Why it matters: a per-path frontier walk (see
/// `dag_store::path_heads_at_frontier_including_buried_roots`, which the
/// planning loop above now uses for each candidate path this pre-filter
/// selects) is real, non-trivial work -- a real SQL query +
/// `Change::from_wire_bytes` decode + hash re-verification per reachable
/// hash, plus pairwise ancestry comparisons. Driving that from the group's
/// full history-path set (rather than only the candidates this pre-filter
/// selects) would cost O(paths * reachable changes * ops per change) --
/// on a ~100k-file folder, hours of work, all of it inside the caller's
/// single IMMEDIATE write transaction and therefore holding the
/// process-wide writer gate for its whole duration, which starves every
/// other writer in the daemon. Almost none of that work can find anything: an
/// ordinary folder's paths are touched by exactly one change each, and only
/// genuinely concurrent branches produce the multi-head shape this repair
/// exists for -- this pre-filter's own single traversal (this function's
/// second return value is its own decode cache, no longer consumed by the
/// per-path walk directly, but still useful for the caller's own diagnostics
/// and any future shared-decode optimization) narrows almost every call to
/// zero candidate paths at O(reachable changes) total, not per path.
fn paths_that_can_have_concurrent_heads(
    conn: &Connection,
    group_id: &str,
    frontier: &[ChangeHash],
) -> Result<(Vec<String>, std::collections::HashMap<[u8; 32], Change>), SyncSqliteError> {
    // Fast, group-scoped, fully-indexed existence check: this function can
    // only ever find something if SOME change in this group's retained
    // history has more than one child (a fork from a common ancestor -- one
    // of the two shapes that produce two live, un-merged branches touching
    // the same path) OR the frontier passed in already names more than one
    // head. A linear chain with a single current head (every change has at
    // most one child, AND the group has converged to one frontier head) can
    // never contain a retroactive-repair obligation, full stop -- the walk
    // below exists only to find WHICH paths a real fork touches, not to
    // decide WHETHER one exists.
    //
    // The frontier half of this OR is not an optimization; it is a distinct,
    // REQUIRED case the child-count check alone cannot see. Two (or more)
    // devices independently authoring this group's very first Change to the
    // same path -- the exact shape `multiway_conflict_matrix.rs`'s "N
    // devices, one brand-new shared path, no prior common history" rows and
    // `directory_conflict_matrix.rs`'s create-create row exercise -- each
    // produce a Change with an EMPTY `parents` list. Two changes with no
    // parent at all are concurrent (neither is the other's ancestor) but
    // NEITHER has "more than one child" from any single parent's
    // perspective, because they share no parent to count children under —
    // `change_parents` has no row for either of them, so the query above
    // finds nothing to see, and this function used to report no obligation
    // even though the current frontier already names both roots as live,
    // divergent heads (confirmed: `dag_store::group_heads` returning >1
    // head is exactly the shape the walk's own `stack = frontier.to_vec()`
    // already handles correctly once it runs -- multiple starting points
    // with nothing in common still converge on the same touched path). A
    // frontier that has already re-converged to one head after a genuine
    // historical fork (a merge change with 2 parents) is unaffected by this
    // addition: that shape is exactly what the child-count check exists to
    // keep catching, since the frontier alone would miss it.
    //
    // Uses `changes_by_group` to enumerate this group's own changes and
    // `change_parents_by_parent` for the per-change child count, so this is
    // an indexed lookup per change rather than the walk's own `read_change`
    // (a full `Change::from_wire_bytes` decode of every ops list and
    // signature) -- the same "stay in SQL, use the index, never decode more
    // than the walk actually needs" shape as the `is_ancestor` fix. Still
    // O(this group's retained changes) in the worst case (a real fork
    // forces the full walk below regardless), but replaces N wire-decodes
    // with N indexed COUNTs for the fork-free case this repair almost
    // always runs into -- see `paths_that_can_have_concurrent_heads`'s
    // doc comment for why that cost matters under the writer gate.
    let any_fork: bool = frontier.len() > 1
        || conn.query_row(
            "SELECT EXISTS (
             SELECT 1 FROM changes c
             WHERE c.group_id = ?1
               AND (SELECT COUNT(*) FROM change_parents cp WHERE cp.parent_hash = c.change_hash) > 1
         )",
            [group_id],
            |r| r.get(0),
        )?;
    if !any_fork {
        return Ok((Vec::new(), std::collections::HashMap::new()));
    }

    // `1` once seen, `2` once seen again -- saturating, since only "more than
    // one" matters and the count itself is never reported.
    let mut touch_counts: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let mut visited = HashSet::<[u8; 32]>::new();
    let mut stack = frontier.to_vec();
    let mut decode_cache: std::collections::HashMap<[u8; 32], Change> =
        std::collections::HashMap::new();

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash.0) {
            continue;
        }
        // A compacted parent is a traversal boundary.
        let Some(change) = read_change(conn, &hash)? else { continue };
        decode_cache.insert(hash.0, change.clone());
        // Deduplicated per change, so one change touching a path through
        // several ops (a `Move` plus a later `Put`, say) still counts once --
        // repeated touches by the SAME change are one head, not two.
        let mut touched_by_this_change: HashSet<&str> = HashSet::new();
        for op in &change.ops {
            match op {
                Op::Put { path, .. } | Op::Delete { path } => {
                    touched_by_this_change.insert(path.as_str());
                }
                Op::Move { from, to, .. } => {
                    touched_by_this_change.insert(from.as_str());
                    touched_by_this_change.insert(to.as_str());
                }
            }
        }
        for path in touched_by_this_change.drain() {
            match touch_counts.get_mut(path) {
                Some(count) => *count = 2,
                None => {
                    touch_counts.insert(path.to_string(), 1);
                }
            }
        }
        stack.extend(change.parents.iter().copied());
    }

    let paths: Vec<String> =
        touch_counts.into_iter().filter(|(_, count)| *count > 1).map(|(path, _)| path).collect();
    Ok((paths, decode_cache))
}

fn read_change(conn: &Connection, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError> {
    let Some(encoded) = dag_store::get_encoded(conn, hash)? else {
        return Ok(None);
    };
    let change = Change::from_wire_bytes(&encoded).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "stored retained change {} is not decodable: {error}",
            hash.to_hex()
        ))
    })?;
    if change.compute_hash() != *hash {
        return Err(SyncSqliteError::CorruptState(format!(
            "stored retained change {} does not match its indexed hash",
            hash.to_hex()
        )));
    }
    Ok(Some(change))
}

#[cfg(test)]
mod tests;
