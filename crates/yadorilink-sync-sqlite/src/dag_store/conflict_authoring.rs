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

use yadorilink_replica_domain::change::{Change, ChangePurpose, Op, PutOrigin};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_engine::conflict::{change_touches_path, path_head_from_change, PathHead};
use yadorilink_replica_engine::conflict_authoring as decision;
use crate::error::SyncSqliteError;

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
    path: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let mut candidates: Vec<Change> = Vec::new();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut stack: Vec<ChangeHash> = frontier.to_vec();
    while let Some(h) = stack.pop() {
        if !visited.insert(h.0) {
            continue;
        }
        let Some(change) = get_change(conn, &h)? else { continue };
        if change_touches_path(&change, path) {
            candidates.push(change);
        } else {
            for parent in &change.parents {
                stack.push(*parent);
            }
        }
    }
    let hashes: Vec<ChangeHash> = candidates.iter().map(|c| c.change_hash()).collect();
    let mut live = Vec::new();
    for i in 0..candidates.len() {
        let mut superseded = false;
        for j in 0..candidates.len() {
            if i != j && retained_history_integrity::is_ancestor(conn, &hashes[i], &hashes[j])? {
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
        &|conn, source_path, losing_change| {
            conflict_copy_already_provisioned(conn, group_id, source_path, losing_change)
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
    already_provisioned: &dyn Fn(&Connection, &str, &ChangeHash) -> Result<bool, SyncSqliteError>,
) -> Result<Vec<Op>, SyncSqliteError> {
    let touched_paths = decision::collect_touched_paths(direct_ops);

    let mut derived_ops = Vec::new();
    for path in touched_paths {
        let heads = path_heads_at_frontier(conn, &path, parents)?;
        for candidate in decision::conflict_copy_candidates(&path, &heads) {
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
            // Only an existing head that is `losing_change` itself, or
            // descends from it, is evidence of an actual later action ON
            // this conflict's own resolution (the ordinary case: a device
            // edits/deletes/renames the conflict-copy path only after it
            // exists, so any such action necessarily has `losing_change` as
            // an ancestor).
            let target_heads = path_heads_at_frontier(conn, &candidate.target_path, parents)?;
            // Fallible loop, not `.any(...).unwrap_or(false)`: a DB error or
            // corrupted ancestry index here must fail closed, not silently
            // read as "not already acted on" -- that would let this
            // function derive a fresh `ConflictCopy` op on top of an
            // ancestry check this device could not actually verify,
            // potentially resurrecting an explicitly-deleted conflict copy
            // or signing a new change against corrupted history.
            let mut already_acted_on = false;
            for h in &target_heads {
                if h.change_hash == losing_change.0
                    || retained_history_integrity::is_ancestor(
                        conn,
                        &losing_change,
                        &ChangeHash(h.change_hash),
                    )?
                {
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
pub(crate) fn validate_conflict_copy_origin(
    conn: &Connection,
    carrier_parents: &[ChangeHash],
    path: &str,
    version: &VersionHash,
    source_path: &str,
    losing_change: &ChangeHash,
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

    let heads = path_heads_at_frontier(conn, source_path, carrier_parents)?;
    decision::validate_conflict_copy_claim(&heads, path, version, source_path, losing_change)
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
                carrier_parents,
                path.as_str(),
                version,
                source_path.as_str(),
                losing_change,
            )?;
            claimed.insert((source_path.as_str().to_string(), *losing_change));
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
mod tests {
    use super::*;
    use yadorilink_replica_domain::change::ChangeAuth;
    use yadorilink_replica_domain::file::FileMeta;
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
    use crate::dag_store::{group_heads, init_dag_schema, max_parent_lamport, put_file_version};
    use yadorilink_replica_domain::file::RecordKind;
    use ed25519_dalek::SigningKey;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_dag_schema(&c).unwrap();
        init_conflict_copy_provenance_schema(&c).unwrap();
        c
    }

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    /// Distinct `mtime_unix_nanos` is enough to give each call a genuinely
    /// different `version_hash` (a `FileVersion`'s hash covers its full
    /// canonical encoding, including `meta`) without needing real block
    /// content.
    fn version(mtime: i64) -> yadorilink_replica_domain::file::FileVersion {
        yadorilink_replica_domain::file::FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn put_op(path: &str, v: &yadorilink_replica_domain::file::FileVersion) -> Op {
        Op::Put { path: SyncPath(path.into()), version: v.version_hash, origin: PutOrigin::Direct }
    }

    /// Signs and admits a change directly (bypassing `emit_local_change`,
    /// which only ever knows one device's own current heads), so a test can
    /// construct genuinely concurrent changes from independent devices
    /// sharing one connection -- concurrency is a pure DAG-structural
    /// property (shared parents, neither an ancestor of the other), not
    /// something that requires two physical connections to model.
    fn admit(
        conn: &Connection,
        group_id: &str,
        parents: Vec<ChangeHash>,
        device_id: &str,
        signing_key: &SigningKey,
        ops: Vec<Op>,
    ) -> Change {
        let max_parent_lamport = max_parent_lamport(conn, group_id, &parents).unwrap();
        let change = Change::create_signed(
            parents,
            max_parent_lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId(device_id.to_string()),
            FolderGroupId(group_id.to_string()),
            ops,
            signing_key,
        );
        let result = super::super::admit_change(conn, &change, true).unwrap();
        assert_eq!(result.outcome, super::super::AdmitOutcome::Applied, "admission must succeed");
        change
    }

    /// Admits two concurrent edits to `path` from two distinct devices, both
    /// parented on `root`, and returns `(loser_change, loser_version,
    /// deterministic_target_path)` -- computed the same way
    /// `derive_required_conflict_copy_ops` itself would, so tests can predict
    /// and directly manipulate the exact literal path a real conflict would
    /// derive.
    fn seed_conflict(
        conn: &Connection,
        group_id: &str,
        root: ChangeHash,
        path: &str,
    ) -> (Change, yadorilink_replica_domain::file::FileVersion, String) {
        let version_a = version(100);
        let version_b = version(200);
        put_file_version(conn, group_id, &version_a).unwrap();
        put_file_version(conn, group_id, &version_b).unwrap();
        let change_a =
            admit(conn, group_id, vec![root], "device-a", &key(1), vec![put_op(path, &version_a)]);
        let change_b =
            admit(conn, group_id, vec![root], "device-b", &key(2), vec![put_op(path, &version_b)]);

        let a_hash = change_a.compute_hash();
        let b_hash = change_b.compute_hash();
        let (loser_change, loser_version, loser_device) =
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_a.lamport,
                &a_hash.0,
                change_b.lamport,
                &b_hash.0,
            ) {
                (change_a, version_a, "device-a")
            } else {
                (change_b, version_b, "device-b")
            };
        let target_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            path,
            loser_device,
            0,
            &loser_version.version_hash.0,
        );
        (loser_change, loser_version, target_path)
    }

    /// Regression for the retroactive-carrier storm observed live on a
    /// contended host: after a carrier has already preserved a loser's
    /// content at its deterministic target, a *straggler* change that
    /// reasserts that same stale content (a concurrent carrier signed
    /// against an older frontier is the real-world author of exactly this
    /// shape) becomes a fresh loser with a brand-new change hash. The
    /// per-losing_change dedup checks cannot see that its content is
    /// already preserved — no provenance row exists for the new hash, and
    /// the existing target write does not descend from it — so derivation
    /// used to re-require the identical copy, every straggler's carrier
    /// could itself become the next straggler, and under delivery lag the
    /// repair loop minted carriers faster than the mesh could converge
    /// (four devices, disjoint per-author head sets, the same copy name
    /// carried repeatedly at successive lamports). The identical-content
    /// suppression must make re-derivation come up empty here, while the
    /// positive control (the FIRST derivation, before any carrier exists)
    /// must still require the copy.
    #[test]
    fn a_stale_reassertion_loser_is_not_recarried_once_its_content_is_already_at_the_target() {
        let c = conn();
        let group = "g";
        let version_a = version(100);
        let version_b = version(200);
        put_file_version(&c, group, &version_a).unwrap();
        put_file_version(&c, group, &version_b).unwrap();
        let change_a =
            admit(&c, group, vec![], "device-a", &key(1), vec![put_op("shared.bin", &version_a)]);
        let change_b =
            admit(&c, group, vec![], "device-b", &key(2), vec![put_op("shared.bin", &version_b)]);
        let a_hash = change_a.compute_hash();
        let b_hash = change_b.compute_hash();
        let a_loses = yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
            change_a.lamport,
            &a_hash.0,
            change_b.lamport,
            &b_hash.0,
        );
        let (winner_version, loser_version, loser_device, loser_key, loser_hash) = if a_loses {
            (version_b, version_a, "device-a", key(1), a_hash)
        } else {
            (version_a, version_b, "device-b", key(2), b_hash)
        };

        // A filler change gives the carrier a strictly higher lamport than
        // the straggler below, so the round-2 resolution deterministically
        // keeps the carrier's winner: this test pins the "same stale
        // content re-carried" blind spot, not the (legitimate) case where
        // a resolution flip makes the old winner a genuinely new loser.
        let filler_version = version(300);
        put_file_version(&c, group, &filler_version).unwrap();
        let filler = admit(
            &c,
            group,
            vec![a_hash, b_hash],
            "device-carrier",
            &key(7),
            vec![put_op("filler.txt", &filler_version)],
        );
        let carrier_parents = vec![filler.compute_hash()];

        let winner_reassert = put_op("shared.bin", &winner_version);
        let required = derive_required_conflict_copy_ops(
            &c,
            group,
            &carrier_parents,
            std::slice::from_ref(&winner_reassert),
        )
        .unwrap();
        assert_eq!(
            required.len(),
            1,
            "positive control: the genuine loser must require its copy before any carrier exists"
        );

        // The carrier, exactly as authoring would sign it: winner
        // reassertion plus the derived copy, on its own frontier.
        let mut carrier_ops = vec![winner_reassert.clone()];
        carrier_ops.extend(required);
        let carrier = admit(&c, group, carrier_parents, "device-carrier", &key(7), carrier_ops);

        // The straggler: the loser device reasserts its own stale content,
        // signed against its own LAGGED frontier (only its previous change
        // — it has not yet seen the winner or the carrier, so from its view
        // there is no concurrent loser and honest authoring derives no copy
        // ops). Once admitted here it is concurrent with the carrier: a
        // fresh change hash carrying already-preserved content.
        let straggler = admit(
            &c,
            group,
            vec![loser_hash],
            loser_device,
            &loser_key,
            vec![put_op("shared.bin", &loser_version)],
        );

        let new_frontier = vec![carrier.compute_hash(), straggler.compute_hash()];
        let rederived = derive_required_conflict_copy_ops(
            &c,
            group,
            &new_frontier,
            std::slice::from_ref(&winner_reassert),
        )
        .unwrap();
        assert!(
            rederived.is_empty(),
            "a loser whose exact content the target already preserves at this frontier must not \
             be re-carried; got {rederived:?}"
        );
    }

    /// RED regression (Phase 1 carry-over): a coincidental pre-existing file
    /// at the EXACT deterministic conflict-copy path, created and deleted
    /// entirely independently of this conflict (a sibling branch off the
    /// same root, never touching the source path or descending from either
    /// concurrent edit), must not suppress deriving the loser's real
    /// conflict copy. The original (over-broad) guard treated ANY existing
    /// history at the target path as "already handled" and silently dropped
    /// the loser instead.
    #[test]
    fn derive_still_provisions_a_loser_whose_target_path_has_unrelated_earlier_history() {
        let c = conn();
        let group = "g";
        let root_version = version(0);
        put_file_version(&c, group, &root_version).unwrap();
        let root = admit(
            &c,
            group,
            vec![],
            "device-root",
            &key(9),
            vec![put_op("shared.bin", &root_version)],
        );
        let root_hash = root.compute_hash();

        let (loser_change, loser_version, target_path) =
            seed_conflict(&c, group, root_hash, "shared.bin");

        // Unrelated history at the exact target path, on a sibling branch
        // off the SAME root -- created, then deleted, never touching
        // "shared.bin" and not descending from either concurrent edit.
        let unrelated_version = version(50);
        put_file_version(&c, group, &unrelated_version).unwrap();
        let unrelated_create = admit(
            &c,
            group,
            vec![root_hash],
            "device-unrelated",
            &key(3),
            vec![put_op(&target_path, &unrelated_version)],
        );
        admit(
            &c,
            group,
            vec![unrelated_create.compute_hash()],
            "device-unrelated",
            &key(3),
            vec![Op::Delete { path: SyncPath(target_path.clone()) }],
        );

        let closing_version = version(300);
        put_file_version(&c, group, &closing_version).unwrap();
        let parents = group_heads(&c, group).unwrap();

        let derived = derive_required_conflict_copy_ops(
            &c,
            group,
            &parents,
            &[put_op("shared.bin", &closing_version)],
        )
        .unwrap();

        assert_eq!(derived.len(), 1, "the loser must still be provisioned: {derived:?}");
        let Op::Put {
            path,
            version: derived_version,
            origin: PutOrigin::ConflictCopy { losing_change, .. },
        } = &derived[0]
        else {
            panic!("expected a ConflictCopy put, got {:?}", derived[0]);
        };
        assert_eq!(path.as_str(), target_path);
        assert_eq!(derived_version.0, loser_version.version_hash.0);
        assert_eq!(*losing_change, loser_change.compute_hash());
    }

    /// RED regression (Phase 1 carry-over): an unrelated file still LIVE
    /// (never deleted) at the target path -- not a tombstone -- must also
    /// not block the loser's own provisioning, and the loser's content must
    /// not be silently dropped (only the derivation is checked here; the
    /// resulting head-to-head resolution at the target path, once the
    /// derived Put actually lands, is ordinary same-path DAG dominance, not
    /// a special case this function needs to invent).
    #[test]
    fn derive_still_provisions_a_loser_whose_target_path_has_an_unrelated_live_file() {
        let c = conn();
        let group = "g";
        let root_version = version(0);
        put_file_version(&c, group, &root_version).unwrap();
        let root = admit(
            &c,
            group,
            vec![],
            "device-root",
            &key(9),
            vec![put_op("shared.bin", &root_version)],
        );
        let root_hash = root.compute_hash();

        let (loser_change, loser_version, target_path) =
            seed_conflict(&c, group, root_hash, "shared.bin");

        let unrelated_version = version(50);
        put_file_version(&c, group, &unrelated_version).unwrap();
        admit(
            &c,
            group,
            vec![root_hash],
            "device-unrelated",
            &key(3),
            vec![put_op(&target_path, &unrelated_version)],
        );

        let closing_version = version(300);
        put_file_version(&c, group, &closing_version).unwrap();
        let parents = group_heads(&c, group).unwrap();

        let derived = derive_required_conflict_copy_ops(
            &c,
            group,
            &parents,
            &[put_op("shared.bin", &closing_version)],
        )
        .unwrap();

        assert_eq!(derived.len(), 1, "the loser must still be provisioned: {derived:?}");
        let Op::Put {
            path,
            version: derived_version,
            origin: PutOrigin::ConflictCopy { losing_change, .. },
        } = &derived[0]
        else {
            panic!("expected a ConflictCopy put, got {:?}", derived[0]);
        };
        assert_eq!(path.as_str(), target_path);
        assert_eq!(derived_version.0, loser_version.version_hash.0);
        assert_eq!(*losing_change, loser_change.compute_hash());
    }

    /// Regression: once a conflict copy has been legitimately provisioned and
    /// a LATER change (descending from the loser) directly edits, renames
    /// away from, or deletes that target path, a subsequent derivation for
    /// the same source-path conflict must not re-add (resurrect) it.
    #[test]
    fn derive_does_not_resurrect_a_conflict_copy_deleted_after_provisioning() {
        let c = conn();
        let group = "g";
        let root_version = version(0);
        put_file_version(&c, group, &root_version).unwrap();
        let root = admit(
            &c,
            group,
            vec![],
            "device-root",
            &key(9),
            vec![put_op("shared.bin", &root_version)],
        );
        let root_hash = root.compute_hash();

        let (loser_change, _loser_version, target_path) =
            seed_conflict(&c, group, root_hash, "shared.bin");

        // First closing edit legitimately provisions the conflict copy.
        let first_closing_version = version(300);
        put_file_version(&c, group, &first_closing_version).unwrap();
        let parents_before = group_heads(&c, group).unwrap();
        let first_derived = derive_required_conflict_copy_ops(
            &c,
            group,
            &parents_before,
            &[put_op("shared.bin", &first_closing_version)],
        )
        .unwrap();
        assert_eq!(first_derived.len(), 1, "sanity: the loser is provisioned the first time");
        let mut first_ops = vec![put_op("shared.bin", &first_closing_version)];
        first_ops.extend(first_derived.clone());
        let first_closing = admit(&c, group, parents_before, "device-a", &key(1), first_ops);
        record_conflict_copy_ops_provenance(&c, group, &first_closing).unwrap();

        // The user deletes the now-provisioned conflict copy directly.
        let after_provision_heads = group_heads(&c, group).unwrap();
        admit(
            &c,
            group,
            after_provision_heads,
            "device-a",
            &key(1),
            vec![Op::Delete { path: SyncPath(target_path.clone()) }],
        );

        // A SECOND closing-style edit to "shared.bin" must not resurrect it.
        let second_closing_version = version(400);
        put_file_version(&c, group, &second_closing_version).unwrap();
        let parents_after_delete = group_heads(&c, group).unwrap();
        let second_derived = derive_required_conflict_copy_ops(
            &c,
            group,
            &parents_after_delete,
            &[put_op("shared.bin", &second_closing_version)],
        )
        .unwrap();

        assert!(
            second_derived.is_empty(),
            "the deleted conflict copy for {} (loser {}) must not be re-derived: {second_derived:?}",
            target_path,
            hex::encode(loser_change.compute_hash().0),
        );
    }
}
