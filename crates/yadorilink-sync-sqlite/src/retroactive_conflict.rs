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
//! Planning and emission are performed by `SyncState` in one SQLite IMMEDIATE
//! transaction. That atomic boundary is load-bearing: a newly-arriving head must
//! not change the winner between election and signing, or a stale version could
//! be reasserted with a newer Lamport timestamp.

use std::collections::HashSet;

use rusqlite::Connection;

use crate::dag_store;
use crate::SyncSqliteError;
use yadorilink_replica_domain::change::{
    encoded_op_len, Change, Op, PutOrigin, RepairObligation, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};
use yadorilink_replica_domain::limits::MAX_OPS;
use yadorilink_replica_engine::conflict::{
    change_touches_path, path_head_from_change, resolve_path_heads, PathHead, PathResolution,
};

/// The final signed change can contain more operations than `direct_ops`,
/// because ordinary authoring adds one conflict-copy operation per unresolved
/// distinct losing version. The canonical byte cap normally binds first, but
/// the decoder's absolute op-count limit remains a second fail-closed bound.
const MAX_RETROACTIVE_CARRIER_OPS: usize = MAX_OPS;

#[derive(Debug)]
pub struct RetroactivePlan {
    pub direct_ops: Vec<Op>,
    pub obligations: Vec<RepairObligation>,
    pub source_paths: Vec<String>,
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
    PathObligationTooLarge {
        path: String,
    },
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

/// Plans one bounded merge-resolution change against the exact frontier visible
/// on `conn`. Callers must invoke this and `dag_store::emit_local_change` in the
/// same write transaction.
pub fn plan_retroactive_merge(
    conn: &Connection,
    group_id: &str,
) -> Result<RetroactiveMergeOutcome, SyncSqliteError> {
    let parents = dag_store::group_heads(conn, group_id)?;
    if parents.is_empty() {
        return Ok(RetroactiveMergeOutcome::Plan(RetroactivePlan {
            direct_ops: Vec::new(),
            obligations: Vec::new(),
            source_paths: Vec::new(),
        }));
    }

    let mut paths = paths_that_can_have_concurrent_heads(conn, group_id, &parents)?;
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
    let mut blocked_path: Option<String> = None;

    for path in paths {
        let heads = path_heads_at_frontier(conn, &path, &parents)?;
        let PathResolution::Present { winner, conflict_copies } = resolve_path_heads(&path, &heads)
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
        let direct_op = Op::Put {
            path: SyncPath(path.clone()),
            version: VersionHash(winner_content.version_hash),
            origin: PutOrigin::Direct,
        };

        // Authoritative derivation, not `conflict_copies` directly: a copy
        // already durably provisioned, or whose target a later change has
        // since touched, is skipped by real authoring (see
        // `derive_required_conflict_copy_ops`'s own doc comment) -- sizing
        // against the raw `resolve_path_heads` prediction could report a
        // path as oversized when the change that would actually be signed
        // fits easily.
        let required_copies = dag_store::derive_required_conflict_copy_ops(
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

        let mut added_count = 1usize;
        let mut added_bytes = encoded_op_len(&direct_op);
        for copy in &required_copies {
            added_count = added_count.saturating_add(1);
            added_bytes = added_bytes.saturating_add(encoded_op_len(copy));
        }

        let alone_exceeds =
            added_count > MAX_RETROACTIVE_CARRIER_OPS || added_bytes > MAX_CHANGE_OP_BYTES;
        if alone_exceeds {
            if blocked_path.is_none() {
                blocked_path = Some(path);
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
        }));
    }
    if let Some(path) = blocked_path {
        return Ok(RetroactiveMergeOutcome::PathObligationTooLarge { path });
    }
    Ok(RetroactiveMergeOutcome::Plan(RetroactivePlan {
        direct_ops: Vec::new(),
        obligations: Vec::new(),
        source_paths: Vec::new(),
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
/// Why it matters: `path_heads_at_frontier` below walks the frontier-reachable
/// DAG once *per path*, decoding (and re-verifying the hash of) every change it
/// passes. Driving that from the group's full history-path set therefore costs
/// O(paths * reachable changes * ops per change) -- on a ~100k-file folder,
/// hours of work, all of it inside the caller's single IMMEDIATE write
/// transaction and therefore holding the process-wide writer gate for its whole
/// duration, which starves every other writer in the daemon (measured: 46
/// planning passes holding the gate for 366 of one 348-second window). Almost
/// none of that work can find anything: an ordinary folder's paths are touched
/// by exactly one change each, and only genuinely concurrent branches produce
/// the multi-head shape this repair exists for. One shared traversal reduces
/// the common case to O(reachable changes * ops per change).
fn paths_that_can_have_concurrent_heads(
    conn: &Connection,
    group_id: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<String>, SyncSqliteError> {
    // Fast, group-scoped, fully-indexed existence check: this function can
    // only ever find something if SOME change in this group's retained
    // history has more than one child (a fork -- the only shape that
    // produces two live, un-merged branches touching the same path). A
    // linear chain (every change has at most one child, the overwhelmingly
    // common shape for an ordinary folder with no concurrent writers) can
    // never contain a retroactive-repair obligation, full stop -- the walk
    // below exists only to find WHICH paths a real fork touches, not to
    // decide WHETHER one exists.
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
    // always runs into -- see this module's own measured cost above
    // (46 planning passes holding the writer gate for 366 of one 348s
    // window on a fork-free 30k-file group).
    let any_fork: bool = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM changes c
             WHERE c.group_id = ?1
               AND (SELECT COUNT(*) FROM change_parents cp WHERE cp.parent_hash = c.change_hash) > 1
         )",
        [group_id],
        |r| r.get(0),
    )?;
    if !any_fork {
        return Ok(Vec::new());
    }

    // `1` once seen, `2` once seen again -- saturating, since only "more than
    // one" matters and the count itself is never reported.
    let mut touch_counts: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let mut visited = HashSet::<[u8; 32]>::new();
    let mut stack = frontier.to_vec();

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash.0) {
            continue;
        }
        // A compacted parent is a traversal boundary, exactly as in
        // `path_heads_at_frontier`.
        let Some(change) = read_change(conn, &hash)? else { continue };
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

    Ok(touch_counts.into_iter().filter(|(_, count)| *count > 1).map(|(path, _)| path).collect())
}

fn path_heads_at_frontier(
    conn: &Connection,
    path: &str,
    frontier: &[ChangeHash],
) -> Result<Vec<PathHead>, SyncSqliteError> {
    let mut candidates = Vec::new();
    let mut visited = HashSet::<[u8; 32]>::new();
    let mut stack = frontier.to_vec();

    while let Some(hash) = stack.pop() {
        if !visited.insert(hash.0) {
            continue;
        }
        let Some(change) = read_change(conn, &hash)? else {
            // A compacted parent is a traversal boundary. Current retained path
            // heads above that boundary remain fully resolvable.
            continue;
        };
        if change_touches_path(&change, path) {
            candidates.push(change);
        } else {
            stack.extend(change.parents.iter().copied());
        }
    }

    let hashes: Vec<ChangeHash> = candidates.iter().map(Change::compute_hash).collect();
    let mut live = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let mut superseded = false;
        for (other_index, other_hash) in hashes.iter().enumerate() {
            if index != other_index && dag_store::is_ancestor(conn, &hashes[index], other_hash)? {
                superseded = true;
                break;
            }
        }
        if !superseded {
            if let Some(head) = path_head_from_change(candidate, path) {
                live.push(head);
            }
        }
    }
    Ok(live)
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
mod tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::Connection;

    use super::*;
    use crate::dag_store::{AdmitOutcome, ChangeEmitter};
    use yadorilink_replica_domain::change::{ChangeAuth, ChangePurpose};
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};

    const GROUP: &str = "group";
    const PATH: &str = "shared.bin";

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn version(mtime: i64) -> FileVersion {
        FileVersion::new(
            Vec::<VersionBlock>::new(),
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    fn put_change(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device: &str,
        version: &FileVersion,
        signing_key: &SigningKey,
    ) -> Change {
        put_change_at(PATH, parents, max_parent_lamport, device, version, signing_key)
    }

    fn put_change_at(
        path: &str,
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device: &str,
        version: &FileVersion,
        signing_key: &SigningKey,
    ) -> Change {
        Change::create_signed(
            parents,
            max_parent_lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId(device.to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(path.to_string()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            signing_key,
        )
    }

    fn admit(conn: &Connection, change: &Change) {
        let result = dag_store::admit_change(conn, change, true).unwrap();
        assert_eq!(result.outcome, AdmitOutcome::Applied);
    }

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn).unwrap();
        dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
        conn
    }

    /// Teeth for `paths_that_can_have_concurrent_heads`: a history where most
    /// paths are touched exactly once (the shape of an ordinary folder, and of
    /// every initial import) must still find the one genuinely forked path.
    /// The pre-filter exists so those single-touch paths never drive a
    /// per-path DAG walk; it must not also drop the path that needs one.
    #[test]
    fn a_single_forked_path_is_still_planned_among_many_single_touch_paths() {
        let conn = setup();
        let root_version = version(1);
        let a_version = version(2);
        let b_version = version(3);
        let bystander_version = version(4);
        for value in [&root_version, &a_version, &b_version, &bystander_version] {
            dag_store::put_file_version(&conn, GROUP, value).unwrap();
        }

        let root = put_change(Vec::new(), 0, "root", &root_version, &key(9));
        admit(&conn, &root);
        // Many paths that only ever appear once, chained off the root.
        let mut tip = root.compute_hash();
        let mut tip_lamport = root.lamport;
        for i in 0..25 {
            let change = put_change_at(
                &format!("bystander-{i:03}.bin"),
                vec![tip],
                tip_lamport,
                "device-a",
                &bystander_version,
                &key(1),
            );
            admit(&conn, &change);
            tip = change.compute_hash();
            tip_lamport = change.lamport;
        }
        // Two concurrent writers of the SAME path, neither descending from the
        // other: the only real obligation in this history.
        let a = put_change(vec![tip], tip_lamport, "device-a", &a_version, &key(1));
        admit(&conn, &a);
        let b = put_change(vec![tip], tip_lamport, "device-b", &b_version, &key(2));
        admit(&conn, &b);

        let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
        assert_eq!(
            plan.source_paths,
            vec![PATH.to_string()],
            "the forked path must be planned, and only it"
        );
        assert_eq!(plan.obligations.len(), 1, "exactly one loser to preserve: {plan:?}");
    }

    #[test]
    fn late_loser_is_preserved_by_one_elected_merge_resolution() {
        let conn = setup();
        let root_version = version(1);
        let a_version = version(2);
        let b_version = version(3);
        let d_version = version(4);
        for value in [&root_version, &a_version, &b_version, &d_version] {
            dag_store::put_file_version(&conn, GROUP, value).unwrap();
        }

        let root = put_change(Vec::new(), 0, "root", &root_version, &key(9));
        admit(&conn, &root);
        let a =
            put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
        admit(&conn, &a);
        let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &d_version, &key(4));
        admit(&conn, &d);

        // B arrives only after D was signed from A. D's immutable change could
        // not have carried B's conflict-copy operation at authoring time.
        let b =
            put_change(vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
        admit(&conn, &b);

        let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
        assert_eq!(plan.source_paths, vec![PATH.to_string()]);
        assert_eq!(
            plan.direct_ops,
            vec![Op::Put {
                path: SyncPath(PATH.to_string()),
                version: d_version.version_hash,
                origin: PutOrigin::Direct,
            }]
        );
        assert_eq!(
            plan.obligations,
            vec![RepairObligation {
                source_path: SyncPath(PATH.to_string()),
                losing_change: b.compute_hash(),
            }]
        );

        let emitter = ChangeEmitter::new("device-d", key(4));
        let carrier = dag_store::emit_retroactive_repair(
            &conn,
            GROUP,
            plan.direct_ops,
            plan.obligations.clone(),
            ChangeAuth::PLACEHOLDER,
            &emitter,
        )
        .unwrap();
        assert_eq!(
            carrier.purpose,
            ChangePurpose::RetroactiveRepair { obligations: plan.obligations }
        );
        let mut false_claim = carrier.clone();
        false_claim.purpose = ChangePurpose::RetroactiveRepair {
            obligations: vec![RepairObligation {
                source_path: SyncPath(PATH.to_string()),
                losing_change: ChangeHash([0xFF; 32]),
            }],
        };
        assert!(
            dag_store::validate_carrier_conflict_copy_ops(&conn, GROUP, &false_claim).is_err(),
            "admission validation must reject a repair whose signed obligation differs from \
             the conflict-copy op it carries"
        );
        let conflict_op = carrier
            .ops
            .iter()
            .find(|op| {
                matches!(
                    op,
                    Op::Put {
                        origin: PutOrigin::ConflictCopy { losing_change, .. },
                        ..
                    } if *losing_change == b.compute_hash()
                )
            })
            .expect("the carrier must durably preserve late B");
        let Op::Put { version, .. } = conflict_op else {
            unreachable!();
        };
        assert_eq!(*version, b_version.version_hash);

        assert_eq!(dag_store::group_heads(&conn, GROUP).unwrap(), vec![carrier.compute_hash()]);
        assert!(
            plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan().direct_ops.is_empty(),
            "the merge carrier must close the fork rather than author-loop"
        );
    }

    #[test]
    fn byte_identical_late_branch_is_not_a_conflict() {
        let conn = setup();
        let root_version = version(1);
        let a_version = version(2);
        let shared_version = version(4);
        for value in [&root_version, &a_version, &shared_version] {
            dag_store::put_file_version(&conn, GROUP, value).unwrap();
        }

        let root = put_change(Vec::new(), 0, "root", &root_version, &key(9));
        admit(&conn, &root);
        let a =
            put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
        admit(&conn, &a);
        let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &shared_version, &key(4));
        admit(&conn, &d);
        let b = put_change(
            vec![root.compute_hash()],
            root.lamport,
            "device-b",
            &shared_version,
            &key(2),
        );
        admit(&conn, &b);

        assert!(
            plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan().direct_ops.is_empty(),
            "concurrent heads resolving to the same VersionHash need no copy"
        );
    }

    /// A real-world trigger: a path with a long name (still well under
    /// `MAX_PATH_BYTES`) accumulates enough concurrent losers that the
    /// winner's own reassert-plus-conflict-copies bundle alone exceeds
    /// `MAX_CHANGE_OP_BYTES`, even before any other path is considered. This
    /// must be reported as `PathObligationTooLarge`, not silently skipped
    /// (which would leave the obligation looking like ordinary "nothing to
    /// do") and not returned as an ordinary `SyncError` (which the daemon's
    /// repair loop would otherwise retry against this exact frontier every
    /// second forever -- see `engine_wrapper.rs`).
    #[test]
    fn oversized_single_path_obligation_is_reported_as_permanently_blocked() {
        let conn = setup();
        let long_path = "x".repeat(3500);

        let root_version = version(1);
        dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
        let root = put_change_at(&long_path, Vec::new(), 0, "root", &root_version, &key(9));
        admit(&conn, &root);

        // Enough concurrent siblings off the root that the winner's
        // reassert-plus-(N-1)-conflict-copies bundle comfortably exceeds
        // MAX_CHANGE_OP_BYTES (256 KiB) on the long path alone: each
        // conflict-copy op carries the 3500-byte source_path a second time
        // plus the derived copy's own (longer) target path, so ~39 siblings
        // is already enough -- kept deliberately small (not a shorter path
        // with hundreds of siblings) because `plan_retroactive_merge` is
        // and its own planning cost is quadratic in sibling count.
        const SIBLINGS: u8 = 40;
        for i in 0..SIBLINGS {
            let sibling_version = version(100 + i as i64);
            dag_store::put_file_version(&conn, GROUP, &sibling_version).unwrap();
            let device_id = format!("device-{i}");
            let sibling = put_change_at(
                &long_path,
                vec![root.compute_hash()],
                root.lamport,
                &device_id,
                &sibling_version,
                &key(100 + i),
            );
            admit(&conn, &sibling);
        }

        match plan_retroactive_merge(&conn, GROUP).unwrap() {
            RetroactiveMergeOutcome::PathObligationTooLarge { path } => {
                assert_eq!(path, long_path);
            }
            RetroactiveMergeOutcome::Plan(plan) => {
                panic!("expected oversized obligation, got plan {plan:?}");
            }
        }
    }

    /// The bug this test guards against: a single oversized path used to make
    /// `plan_retroactive_merge` return `Err`/`PathObligationTooLarge`
    /// immediately, before even looking at any dictionary-order-later path --
    /// so a perfectly repairable smaller obligation on another path never got
    /// a chance to be packed. The same elected device here has both an
    /// oversized obligation on `long_path` and a small, easily-resolvable one
    /// on `short_path`; the latter must still be planned.
    #[test]
    fn oversized_path_does_not_block_a_smaller_fixable_path() {
        use yadorilink_replica_engine::conflict::dag_conflict_loser_is_a;

        let conn = setup();
        let long_path = "x".repeat(3500);
        // Sorts strictly after `long_path` (all 'x's): `paths` is processed
        // in sorted order, so this is what actually exercises "oversized
        // path first, skipped, smaller later path still packed" rather than
        // the other way around.
        let short_path = "zzz_small.bin";

        let root_version = version(1);
        dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
        let root = put_change_at(&long_path, Vec::new(), 0, "root", &root_version, &key(9));
        admit(&conn, &root);
        let root_hash = root.compute_hash();

        const SIBLINGS: u8 = 40;
        let mut siblings: Vec<(String, Change)> = Vec::with_capacity(SIBLINGS as usize);
        for i in 0..SIBLINGS {
            let sibling_version = version(100 + i as i64);
            dag_store::put_file_version(&conn, GROUP, &sibling_version).unwrap();
            let device_id = format!("device-{i}");
            let sibling = put_change_at(
                &long_path,
                vec![root_hash],
                root.lamport,
                &device_id,
                &sibling_version,
                &key(100 + i),
            );
            siblings.push((device_id, sibling));
        }
        // The (lamport, hash) tie-break `resolve_path_heads` itself uses --
        // all siblings share `root.lamport`, so this is decided by hash
        // alone. Computed purely from the already-built `Change`s, no DB
        // needed, so the actual winner is known before admitting anything.
        let (winner_device, _) = siblings
            .iter()
            .max_by(|(_, a), (_, b)| {
                if dag_conflict_loser_is_a(
                    root.lamport,
                    &a.compute_hash().0,
                    root.lamport,
                    &b.compute_hash().0,
                ) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
            .cloned()
            .expect("siblings is non-empty");
        for (_, sibling) in &siblings {
            admit(&conn, sibling);
        }

        // Give that SAME winner a second, small, concurrent conflict on an
        // unrelated short path off the same root. Search a losing
        // competitor key purely in memory (no DB writes) so the winner of
        // `long_path` is also the winner of `short_path`, exercising both
        // branches (oversized-and-skipped, small-and-packed) in one call.
        let short_winner_version = version(200);
        let short_winner_change = put_change_at(
            short_path,
            vec![root_hash],
            root.lamport,
            &winner_device,
            &short_winner_version,
            &key(200),
        );
        let short_winner_hash = short_winner_change.compute_hash();
        let (short_loser_version, short_loser_change) = (0..=u8::MAX)
            .find_map(|candidate| {
                let loser_version = version(300 + candidate as i64);
                let loser_change = put_change_at(
                    short_path,
                    vec![root_hash],
                    root.lamport,
                    "short-loser",
                    &loser_version,
                    &key(201u8.wrapping_add(candidate)),
                );
                dag_conflict_loser_is_a(
                    root.lamport,
                    &loser_change.compute_hash().0,
                    root.lamport,
                    &short_winner_hash.0,
                )
                .then_some((loser_version, loser_change))
            })
            .expect("a losing hash must exist among the exhaustive one-byte key candidates");

        dag_store::put_file_version(&conn, GROUP, &short_winner_version).unwrap();
        dag_store::put_file_version(&conn, GROUP, &short_loser_version).unwrap();
        admit(&conn, &short_winner_change);
        admit(&conn, &short_loser_change);

        match plan_retroactive_merge(&conn, GROUP).unwrap() {
            RetroactiveMergeOutcome::Plan(plan) => {
                assert_eq!(
                    plan.source_paths,
                    vec![short_path.to_string()],
                    "the oversized long path must be skipped, not prevent the smaller \
                     fixable short path from being packed"
                );
            }
            RetroactiveMergeOutcome::PathObligationTooLarge { path } => {
                panic!(
                    "the smaller short path must still be packed even though {path} alone \
                     is oversized"
                );
            }
        }
    }

    /// Attribution benchmark for the 2026-09-02 30k device-A-fix acceptance
    /// run (a real gpu-box `many_small_files` reproduction whose `a.log`
    /// showed `repair_retroactive_conflict_copy_obligations`'s own
    /// `write_immediate` transaction -- `replica_coordinator.rs:722`, wired
    /// straight through to this module's `plan_retroactive_merge` --
    /// escalating from 682ms to 57,263ms held across 13 samples over ~6
    /// minutes, holding the process-wide writer gate for the whole span).
    ///
    /// Realistic shape: one device sequentially admits N single-file `Put`
    /// changes, each to its OWN path, each chained onto the group's current
    /// head (`dag_group_heads`) exactly like real local capture does -- a
    /// linear chain of depth N with zero forks, the overwhelmingly common
    /// case (an ordinary folder with no concurrent writer) and exactly the
    /// shape the failing run hit. `pre_fix_walk_only` duplicates
    /// `paths_that_can_have_concurrent_heads`'s walk from before the
    /// group-scoped fork-existence fast path was added (2026-09-02) --
    /// kept here ONLY to quantify the fix, never called from production
    /// code.
    mod scale_benchmark {
        use super::*;
        use std::time::Instant;

        /// Pre-fix shape of `paths_that_can_have_concurrent_heads`: walks
        /// every change reachable from `frontier` back to the retained
        /// boundary, decoding each one, with no way to conclude "no fork
        /// exists" short of walking the whole reachable set. See this
        /// module's own current `paths_that_can_have_concurrent_heads` for
        /// the fixed version (a group-scoped, indexed fork-existence check
        /// short-circuits this walk entirely when the group's retained
        /// history has never forked).
        fn pre_fix_walk_only(
            conn: &Connection,
            frontier: &[ChangeHash],
        ) -> Result<Vec<String>, SyncSqliteError> {
            let mut touch_counts: std::collections::HashMap<String, u8> =
                std::collections::HashMap::new();
            let mut visited = HashSet::<[u8; 32]>::new();
            let mut stack = frontier.to_vec();
            while let Some(hash) = stack.pop() {
                if !visited.insert(hash.0) {
                    continue;
                }
                let Some(change) = read_change(conn, &hash)? else { continue };
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
            Ok(touch_counts
                .into_iter()
                .filter(|(_, count)| *count > 1)
                .map(|(path, _)| path)
                .collect())
        }

        /// Seeds a fork-free linear chain of `n` single-file local `Put`s
        /// directly into `changes`/`change_parents`/`group_heads`, matching
        /// `retained_history_integrity::append_change`'s own insert shape
        /// exactly -- but skipping `dag_store::admit_change`'s validation
        /// (causal-auth monotonicity, conflict-copy carrier checks,
        /// execution-fence/projection-obligation bumps), which is
        /// irrelevant to what this benchmark measures and dominates the
        /// seed-phase cost for no benefit at N in the tens of thousands
        /// (mirrors `dag_is_ancestor_scale_benchmark.rs`'s own
        /// `seed_linear_chain` for exactly this reason). Each change is
        /// still a genuine, validly-signed `Change` (`to_wire_bytes`
        /// round-trips through `read_change`/`Change::from_wire_bytes`
        /// exactly like production data), so `pre_fix_walk_only`'s decode
        /// step exercises the real wire format, not a stub.
        fn seed_fork_free_chain(conn: &Connection, n: u64) -> Vec<ChangeHash> {
            let v = version(1);
            dag_store::put_file_version(conn, GROUP, &v).unwrap();
            let signing_key = key(7);

            let insert_direct = |change: &Change| {
                let hash = change.compute_hash();
                conn.execute(
                    "INSERT INTO changes \
                     (change_hash, group_id, device_id, lamport, encoded, applied, \
                      authenticated_header) \
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                    rusqlite::params![
                        &hash.0[..],
                        change.group_id.as_str(),
                        change.device_id.as_str(),
                        change.lamport as i64,
                        change.to_wire_bytes(),
                        change.authenticated_header_encoding(),
                    ],
                )
                .unwrap();
                for parent in &change.parents {
                    conn.execute(
                        "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) \
                         VALUES (?1, ?2)",
                        rusqlite::params![&hash.0[..], &parent.0[..]],
                    )
                    .unwrap();
                    conn.execute(
                        "DELETE FROM group_heads WHERE group_id = ?1 AND change_hash = ?2",
                        rusqlite::params![change.group_id.as_str(), &parent.0[..]],
                    )
                    .unwrap();
                }
                conn.execute(
                    "INSERT OR IGNORE INTO group_heads (group_id, change_hash) VALUES (?1, ?2)",
                    rusqlite::params![change.group_id.as_str(), &hash.0[..]],
                )
                .unwrap();
                hash
            };

            let root = put_change_at("f0000000.bin", Vec::new(), 0, "device-a", &v, &signing_key);
            let mut tip = insert_direct(&root);
            let mut tip_lamport = root.lamport;
            for i in 1..n {
                let change = put_change_at(
                    &format!("f{i:07}.bin"),
                    vec![tip],
                    tip_lamport,
                    "device-a",
                    &v,
                    &signing_key,
                );
                tip_lamport = change.lamport;
                tip = insert_direct(&change);
            }
            vec![tip]
        }

        fn bench_one_scale(n: u64) {
            let conn = setup();
            let seed_started = Instant::now();
            let frontier = seed_fork_free_chain(&conn, n);
            let seed_elapsed = seed_started.elapsed();

            let t = Instant::now();
            let before = pre_fix_walk_only(&conn, &frontier).unwrap();
            let before_elapsed = t.elapsed();
            assert!(before.is_empty(), "sanity: a fork-free chain has no concurrent paths");

            let t = Instant::now();
            let after = paths_that_can_have_concurrent_heads(&conn, GROUP, &frontier).unwrap();
            let after_elapsed = t.elapsed();
            assert!(after.is_empty(), "sanity: a fork-free chain has no concurrent paths");

            let t = Instant::now();
            let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
            let plan_elapsed = t.elapsed();
            assert!(plan.source_paths.is_empty(), "sanity: nothing to repair in a fork-free chain");

            println!(
                "n={n:>6}  seed={seed_elapsed:>10.2?}  BEFORE(walk-only)={before_elapsed:>10.2?}  \
                 AFTER(fast-path)={after_elapsed:>10.2?}  \
                 plan_retroactive_merge={plan_elapsed:>10.2?}"
            );
        }

        /// Run with:
        ///   cargo test -p yadorilink-sync-sqlite --lib \
        ///     retroactive_conflict::tests::scale_benchmark:: \
        ///     plan_retroactive_merge_latency_vs_chain_depth \
        ///     -- --ignored --nocapture --test-threads=1
        #[test]
        #[ignore = "scale benchmark, not a correctness test -- see module doc comment"]
        fn plan_retroactive_merge_latency_vs_chain_depth() {
            for n in [1_000u64, 5_000, 15_000, 30_000] {
                bench_one_scale(n);
            }
        }

        /// Deterministic regression guard (not ignored -- runs in the
        /// default suite). Both the pre-fix walk and the post-fix
        /// group-scoped existence check are O(this group's retained
        /// change count) -- the fix does not make this O(1), and does not
        /// claim to (see this module's own scale_benchmark doc comment and
        /// `plan_retroactive_merge_latency_vs_chain_depth`'s own measured
        /// numbers: BEFORE/AFTER both grow roughly linearly with n, but
        /// AFTER stays a consistent ~17-18x cheaper at every measured
        /// scale -- 26.46ms->1.44ms at n=1,000 up to 815.24ms->49.00ms at
        /// n=30,000 -- because it replaces N `Change::from_wire_bytes`
        /// decodes with N indexed `change_parents` COUNTs). That constant-
        /// factor win is what matters here: the real 30k run's own
        /// pathology was many REPEATED per-call walks as the group's
        /// history kept growing between polls (682ms -> 57,263ms across 13
        /// samples), so a per-call constant-factor cut of this size cuts
        /// the same cumulative cost by roughly the same factor. 200ms is a
        /// huge margin below the pre-fix walk's own cost at n=20,000
        /// (~550ms extrapolated) and a huge margin above the post-fix cost
        /// (~33ms extrapolated), so this only fails if the expensive decode
        /// path comes back for a fork-free chain.
        #[test]
        fn concurrent_heads_check_for_a_fork_free_chain_avoids_the_pre_fix_decode_cost() {
            let conn = setup();
            let n = 20_000u64;
            let frontier = seed_fork_free_chain(&conn, n);

            let t = Instant::now();
            let paths = paths_that_can_have_concurrent_heads(&conn, GROUP, &frontier).unwrap();
            let elapsed = t.elapsed();

            assert!(paths.is_empty(), "sanity: a fork-free chain has no concurrent paths");
            assert!(
                elapsed.as_millis() < 200,
                "paths_that_can_have_concurrent_heads against a {n}-deep FORK-FREE chain took \
                 {elapsed:?} -- expected a low-double-digit-millisecond indexed existence check \
                 at this depth, nowhere near the pre-fix decode-every-change walk's own cost. \
                 See this module's own scale_benchmark doc comment for the 682ms->57,263ms \
                 production escalation this guards against."
            );
        }
    }
}
