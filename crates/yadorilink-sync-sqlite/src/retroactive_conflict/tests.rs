#![cfg(test)]

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

use super::*;
use crate::dag_store::{AdmitOutcome, ChangeEmitter};
use yadorilink_replica_domain::change::ChangePurpose;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};

const GROUP: &str = "group";
const PATH: &str = "shared.bin";

/// How many concurrent siblings the oversized-obligation tests below fork
/// off one 3500-byte path.
///
/// Sized so the winner's reassert-plus-(N-1)-conflict-copies bundle
/// comfortably exceeds `MAX_CHANGE_OP_BYTES` (256 KiB) on that path alone,
/// and kept no larger than it has to be: `plan_retroactive_merge`'s own
/// planning cost is quadratic in the sibling count.
///
/// What dominates the bundle is the source path each conflict-copy op
/// carries in full (3500 bytes); the copy's own target name does not scale
/// with it, because a conflict-copy name truncates its stem to fit a single
/// 255-byte path component. So a copy costs roughly 3.8 KiB, not twice the
/// source path, and it takes about seventy of them to cross the bound --
/// which is why a count tuned against a shorter name is not enough.
const SIBLINGS: u8 = 80;
/// Signing keys for those siblings: `SIBLING_KEY_BASE..SIBLING_KEY_BASE +
/// SIBLINGS`, chosen to stay clear of every other key these tests use.
const SIBLING_KEY_BASE: u8 = 100;
/// The competitor on the short path, distinct from the root's key and from
/// every sibling key.
const SHORT_LOSER_KEY: u8 = 13;

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
    create_signed_for_tests(
        parents,
        max_parent_lamport,
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
    let result = dag_store::admit_change(conn, change).unwrap();
    assert_eq!(result.outcome, AdmitOutcome::Applied);
}

fn setup() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&conn).unwrap();
    dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
    conn
}

/// The plan is only meaningful against the frontier it was built from, so
/// the frontier travels with it.
#[test]
fn a_plan_carries_the_frontier_it_was_built_against() {
    let conn = setup();
    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    admit(&conn, &put_change(vec![], 0, "device-a", &root_version, &key(1)));

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    let mut expected = dag_store::group_heads(&conn, GROUP).unwrap();
    expected.sort();

    assert_eq!(plan.frontier.heads(), expected.as_slice());
    assert!(plan.frontier.is_current(&conn, GROUP).unwrap());
}

/// A frontier that moves invalidates the plan built against it.
///
/// This is what replaces holding the writer gate across planning: the
/// invariant is named and re-checked at commit, rather than obtained by
/// excluding every other writer for the whole traversal.
#[test]
fn a_frontier_that_moves_invalidates_the_plan_built_against_it() {
    let conn = setup();
    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    let root = put_change(vec![], 0, "device-a", &root_version, &key(1));
    admit(&conn, &root);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert!(plan.frontier.is_current(&conn, GROUP).unwrap());

    // New history lands, exactly as a peer's admission would.
    let follower_version = version(2);
    dag_store::put_file_version(&conn, GROUP, &follower_version).unwrap();
    admit(
        &conn,
        &put_change_at(
            "moved.txt",
            vec![root.compute_hash()],
            root.lamport,
            "device-a",
            &follower_version,
            &key(1),
        ),
    );

    assert!(
        !plan.frontier.is_current(&conn, GROUP).unwrap(),
        "a plan must not be committable against a frontier that has moved"
    );
}

/// An empty frontier and a populated one are distinguishable, so a plan
/// built before any history existed cannot be committed after some does.
#[test]
fn a_frontier_captured_before_any_history_does_not_match_one_after() {
    let conn = setup();
    let empty = PublishedFrontierToken::capture(&conn, GROUP).unwrap();
    assert!(empty.heads().is_empty());
    assert!(empty.is_current(&conn, GROUP).unwrap());

    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    admit(&conn, &put_change(vec![], 0, "device-a", &root_version, &key(1)));

    assert!(!empty.is_current(&conn, GROUP).unwrap());
}

/// A forked history with exactly one outstanding conflict-copy obligation,
/// and a plan built against it.
fn forked_history_with_a_plan() -> (Connection, RetroactivePlan) {
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
    let a = put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &d_version, &key(4));
    admit(&conn, &d);
    // B arrives only after D was signed from A, so D could not have
    // carried B's conflict-copy operation at authoring time.
    let b = put_change(vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    (conn, plan)
}

/// Record durable conflict-copy provenance directly, standing in for some
/// other carrier having satisfied the obligation. Written as raw SQL
/// rather than through the production path, which would also append a
/// Change and so move the frontier — defeating the point of the test.
fn record_provenance(conn: &Connection, obligation: &RepairObligation) {
    conn.execute(
        "INSERT OR REPLACE INTO conflict_copy_provenance \
         (group_id, source_path, losing_change_hash, carrier_change_hash, target_path) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            GROUP,
            obligation.source_path.as_str(),
            &obligation.losing_change.0[..],
            &[0xCCu8; 32][..],
            "conflict-copy-target",
        ],
    )
    .unwrap();
}

/// A plan is only committable against the frontier it was built from.
#[test]
fn a_moved_frontier_makes_the_plan_stale() {
    let conn = setup();
    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    let root = put_change(vec![], 0, "device-a", &root_version, &key(1));
    admit(&conn, &root);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(plan.revalidate(&conn, GROUP).unwrap(), None);

    let follower_version = version(2);
    dag_store::put_file_version(&conn, GROUP, &follower_version).unwrap();
    admit(
        &conn,
        &put_change_at(
            "moved.txt",
            vec![root.compute_hash()],
            root.lamport,
            "device-a",
            &follower_version,
            &key(1),
        ),
    );

    assert_eq!(plan.revalidate(&conn, GROUP).unwrap(), Some(PlanStaleness::FrontierMoved));
}

/// Movement elsewhere is not movement here. A plan for one group must not
/// be invalidated by another group's history advancing, or a busy device
/// would never commit a repair at all.
#[test]
fn another_groups_frontier_moving_leaves_the_plan_committable() {
    let conn = setup();
    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    admit(&conn, &put_change(vec![], 0, "device-a", &root_version, &key(1)));

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();

    // A different group advances.
    let other_version = version(9);
    dag_store::put_file_version(&conn, "other-group", &other_version).unwrap();
    let other = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-a".to_string()),
        FolderGroupId("other-group".to_string()),
        vec![Op::Put {
            path: SyncPath("elsewhere.bin".to_string()),
            version: other_version.version_hash,
            origin: PutOrigin::Direct,
        }],
        &key(1),
    );
    admit(&conn, &other);

    assert_eq!(
        plan.revalidate(&conn, GROUP).unwrap(),
        None,
        "another group's history must not invalidate this group's plan"
    );
}

/// The frontier is checked first because it is cheap, but it is not the
/// whole assumption: planning also reads durable conflict-copy provenance.
/// Recording provenance for an obligation the plan intends to satisfy must
/// make the plan stale, even though it names the very same frontier.
#[test]
fn provenance_recorded_under_an_unmoved_frontier_makes_the_plan_stale() {
    let (conn, plan) = forked_history_with_a_plan();
    assert!(!plan.obligations.is_empty(), "the fixture must produce an obligation");
    assert_eq!(plan.revalidate(&conn, GROUP).unwrap(), None);

    let frontier_before = plan.frontier.clone();

    // Some other carrier durably provisioned this obligation. Nothing in
    // the frontier says so.
    for obligation in &plan.obligations {
        record_provenance(&conn, obligation);
    }

    assert_eq!(
        frontier_before,
        PublishedFrontierToken::capture(&conn, GROUP).unwrap(),
        "the frontier must be unchanged, or this test is proving the wrong thing"
    );
    assert_eq!(
        plan.revalidate(&conn, GROUP).unwrap(),
        Some(PlanStaleness::ObligationsChanged),
        "an unmoved frontier must not be treated as proof that the derivation is unmoved"
    );
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

/// Two devices independently authoring a group's very first Change to the
/// same path -- no prior shared history, so neither Change has a parent
/// at all -- must still be planned as a fork.
///
/// This is the regression `paths_that_can_have_concurrent_heads`'s own
/// doc comment describes: its fast existence check alone (`change_parents`
/// has a row only for a change with a real parent) found nothing to see
/// here and reported no obligation, even though the frontier already
/// named both roots as live, divergent heads -- confirmed as the root
/// cause of `multiway_conflict_matrix.rs`/`directory_conflict_matrix.rs`
/// stalling deterministically at ~90s on exactly this shape (every device
/// creating a brand-new shared path with no common ancestor between
/// them).
#[test]
fn two_independent_roots_with_no_common_ancestor_are_still_detected_as_a_fork() {
    let conn = setup();
    let a_version = version(1);
    let b_version = version(2);
    for value in [&a_version, &b_version] {
        dag_store::put_file_version(&conn, GROUP, value).unwrap();
    }

    let a = put_change(Vec::new(), 0, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    let b = put_change(Vec::new(), 0, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(
        plan.source_paths,
        vec![PATH.to_string()],
        "the two-root conflict must be planned, not silently skipped: {plan:?}"
    );
    assert_eq!(plan.obligations.len(), 1, "exactly one loser to preserve: {plan:?}");
    let losing_change = plan.obligations[0].losing_change;
    assert!(
        losing_change == a.compute_hash() || losing_change == b.compute_hash(),
        "the preserved loser must be one of the two roots: {plan:?}"
    );
    let (winner_change, winner_device, winner_version) = if losing_change == a.compute_hash() {
        (b.compute_hash(), "device-b", b_version.version_hash)
    } else {
        (a.compute_hash(), "device-a", a_version.version_hash)
    };
    assert_eq!(
        plan.direct_ops,
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: winner_version,
            origin: PutOrigin::Reasserted {
                original_change: winner_change,
                naming_device_id: DeviceId(winner_device.to_string()),
            },
        }],
        "the direct op must reassert the deterministic winner's own content, under that \
         winner's own naming identity"
    );
}

/// The fourth `multiway_conflict_matrix.rs` staggered-row defect,
/// distinct from (and downstream of) the two-independent-roots fix
/// above: a device's OWN local write can race BEHIND a peer's
/// already-synced, but genuinely unrelated, root for the very same
/// brand-new path. `device-c`'s local edit is parented directly onto
/// `device-a`'s root purely because that root happened to already be
/// this replica's only known head at commit time -- `device-c` never
/// synced, observed, or otherwise had any causal relationship with
/// `device-b`'s OWN, entirely separate root for the identical path.
/// Ordinary DAG ancestry alone cannot distinguish that from a genuine
/// sequential edit (a device reading and replacing content it actually
/// observed), so the cheap live-heads-only algorithm silently drops
/// `device-a`'s content as "properly superseded" by `device-c` -- even
/// though `device-b`'s sibling root was never reconciled against it.
/// Confirmed, reproduced live: `four/five/six_devices_staggered_write_
/// never_mismatches_name_and_content` stall permanently at N-1
/// preserved contents once propagation latency becomes comparable to
/// the devices' own write-timing stagger.
#[test]
fn a_root_buried_by_an_unaware_single_parent_descendant_is_still_preserved() {
    let conn = setup();
    let a_version = version(1);
    let b_version = version(2);
    let c_version = version(3);
    for value in [&a_version, &b_version, &c_version] {
        dag_store::put_file_version(&conn, GROUP, value).unwrap();
    }

    let a = put_change(Vec::new(), 0, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    // `device-c`'s own local write races behind `device-a`'s
    // already-synced root: it parents directly onto A, in total
    // ignorance that a genuinely concurrent sibling root (B) exists
    // anywhere -- exactly the shape a local write's own emission
    // cannot detect (B has not been synced to this replica yet either).
    let c = put_change(vec![a.compute_hash()], a.lamport, "device-c", &c_version, &key(3));
    admit(&conn, &c);
    // B arrives only afterward, once this replica has already buried A
    // under C.
    let b = put_change(Vec::new(), 0, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(
        plan.source_paths,
        vec![PATH.to_string()],
        "the buried-root conflict must be planned, not silently skipped: {plan:?}"
    );
    let losing_changes: std::collections::BTreeSet<ChangeHash> =
        plan.obligations.iter().map(|o| o.losing_change).collect();
    assert_eq!(
        losing_changes,
        std::collections::BTreeSet::from([a.compute_hash(), b.compute_hash()]),
        "both the buried root A and its never-reconciled sibling B must be preserved: {plan:?}"
    );
    assert_eq!(
        plan.direct_ops,
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: c_version.version_hash,
            origin: PutOrigin::Reasserted {
                original_change: c.compute_hash(),
                naming_device_id: DeviceId("device-c".to_string()),
            },
        }],
        "C has the highest lamport of the three and wins outright"
    );

    // The resulting carrier must itself pass the SAME admission
    // validation a peer would run on receipt -- proving the buried-root
    // obligation is not just planned, but genuinely emittable and
    // acceptable under the wire protocol's own rules.
    let emitter = ChangeEmitter::new("device-c", key(3));
    let carrier = dag_store::emit_retroactive_repair(
        &conn,
        GROUP,
        plan.direct_ops,
        plan.obligations.clone(),
        &emitter,
    )
    .unwrap();
    assert!(
        dag_store::validate_carrier_conflict_copy_ops(&conn, GROUP, &carrier).is_ok(),
        "a carrier preserving a buried root must validate under the SAME rules governing \
         an ordinary conflict-copy carrier"
    );
    assert_eq!(dag_store::group_heads(&conn, GROUP).unwrap(), vec![carrier.compute_hash()]);
    assert!(
        plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan().direct_ops.is_empty(),
        "the merge carrier must close the fork rather than author-loop"
    );
}

/// A repair carrier reasserts the winner's content at the source path,
/// but it is signed by whichever device happened to be elected to author
/// the repair -- which is generally NOT the device that wrote that
/// content. That reassertion supersedes the real author's own head, so
/// the real author stops appearing among the path's live heads at all.
///
/// If the carrier later loses a conflict of its own, the copy preserving
/// its content must still be named after the device that actually wrote
/// the content, never after the repairer that merely carried it forward.
/// Naming it after the repairer produces a converged-but-wrong result
/// rather than a stall: every replica agrees on the same set of names,
/// and that agreed set attributes one device's content to another,
/// duplicating the repairer's id across two names while the true
/// author's id is missing entirely.
///
/// Reassertion may change the carrier identity of a path's head; it must
/// never change the naming identity of the content that head carries.
#[test]
fn a_repair_carrier_does_not_rename_the_content_it_carries_after_itself() {
    let conn = setup();
    let root_version = version(1);
    let a_version = version(2);
    let b_version = version(3);
    let d_version = version(4);
    let e_version = version(5);
    for value in [&root_version, &a_version, &b_version, &d_version, &e_version] {
        dag_store::put_file_version(&conn, GROUP, value).unwrap();
    }

    let root = put_change(Vec::new(), 0, "root", &root_version, &key(9));
    admit(&conn, &root);
    let a = put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    // device-d writes the content that will end up winning the fork, so
    // `d_version` is unambiguously device-d's content from here on.
    let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &d_version, &key(4));
    admit(&conn, &d);
    let b = put_change(vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    // The repair is authored by device-r, a device that has never written
    // this path. Its carrier reasserts device-d's content.
    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(
        plan.direct_ops,
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: d_version.version_hash,
            origin: PutOrigin::Reasserted {
                original_change: d.compute_hash(),
                naming_device_id: DeviceId("device-d".to_string()),
            },
        }],
        "the repair reasserts device-d's winning content under device-d's own naming \
         identity, not its own"
    );
    let carrier = dag_store::emit_retroactive_repair(
        &conn,
        GROUP,
        plan.direct_ops,
        plan.obligations.clone(),
        &ChangeEmitter::new("device-r", key(7)),
    )
    .unwrap();
    assert_eq!(carrier.device_id.as_str(), "device-r");

    // device-e writes concurrently with the carrier -- its branch descends
    // from B only, so neither change is the other's ancestor -- but from
    // far enough along its own branch to outrank the carrier's lamport.
    // Two filler changes at unrelated paths do the ranking: a lamport is
    // exactly `max(parents) + 1`, so the only way to win the tiebreak
    // deterministically (rather than by whichever change hash happens to
    // sort higher) is to genuinely be further along a branch.
    let filler_one = version(6);
    let filler_two = version(7);
    for value in [&filler_one, &filler_two] {
        dag_store::put_file_version(&conn, GROUP, value).unwrap();
    }
    let x1 = put_change_at(
        "filler-one.txt",
        vec![b.compute_hash()],
        b.lamport,
        "device-e",
        &filler_one,
        &key(5),
    );
    admit(&conn, &x1);
    let x2 = put_change_at(
        "filler-two.txt",
        vec![x1.compute_hash()],
        x1.lamport,
        "device-e",
        &filler_two,
        &key(5),
    );
    admit(&conn, &x2);
    let e = put_change(vec![x2.compute_hash()], x2.lamport, "device-e", &e_version, &key(5));
    assert!(
        e.lamport > carrier.lamport,
        "device-e must outrank the carrier outright: e={} carrier={}",
        e.lamport,
        carrier.lamport
    );
    admit(&conn, &e);

    let parents = dag_store::group_heads(&conn, GROUP).unwrap();
    let copies = dag_store::derive_required_conflict_copy_ops_including_buried_roots(
        &conn,
        GROUP,
        &parents,
        &[Op::Put {
            path: SyncPath(PATH.to_string()),
            version: e_version.version_hash,
            origin: PutOrigin::Direct,
        }],
    )
    .unwrap();

    let carried_forward = copies
        .iter()
        .find_map(|op| match op {
            Op::Put { path, version, .. } if version.0 == d_version.version_hash.0 => {
                Some(path.as_str().to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("device-d's content must be preserved as a conflict copy: {copies:?}")
        });

    assert!(
        carried_forward.contains("device-d"),
        "the conflict copy holding device-d's content must be named after device-d, \
         the device that wrote it -- got {carried_forward:?}"
    );
    assert!(
        !carried_forward.contains("device-r"),
        "the conflict copy must NOT be named after device-r, which only carried the \
         content forward as a repair reassertion -- got {carried_forward:?}"
    );
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
    let a = put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &d_version, &key(4));
    admit(&conn, &d);

    // B arrives only after D was signed from A. D's immutable change could
    // not have carried B's conflict-copy operation at authoring time.
    let b = put_change(vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(plan.source_paths, vec![PATH.to_string()]);
    assert_eq!(
        plan.direct_ops,
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: d_version.version_hash,
            origin: PutOrigin::Reasserted {
                original_change: d.compute_hash(),
                naming_device_id: DeviceId("device-d".to_string()),
            },
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
        &emitter,
    )
    .unwrap();
    assert_eq!(carrier.purpose, ChangePurpose::RetroactiveRepair { obligations: plan.obligations });
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
    let a = put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    let d = put_change(vec![a.compute_hash()], a.lamport, "device-d", &shared_version, &key(4));
    admit(&conn, &d);
    let b =
        put_change(vec![root.compute_hash()], root.lamport, "device-b", &shared_version, &key(2));
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
/// A too-large verdict is a verdict about state, and must be rechecked
/// like any other.
///
/// The caller caches permanence keyed on the frontier. But the state this
/// verdict is computed from includes durable conflict-copy provenance,
/// which moves without disturbing the frontier — so a verdict reported
/// unchecked would be cached against a frontier that has not moved, and
/// the path would never be re-planned even once its obligation shrank.
#[test]
fn a_too_large_verdict_is_not_permanent_once_its_obligations_shrink() {
    let conn = setup();
    let long_path = "x".repeat(3500);

    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    let root = put_change_at(&long_path, Vec::new(), 0, "root", &root_version, &key(9));
    admit(&conn, &root);

    let mut losers = Vec::new();
    for i in 0..SIBLINGS {
        let sibling_version = version(100 + i as i64);
        dag_store::put_file_version(&conn, GROUP, &sibling_version).unwrap();
        let sibling = put_change_at(
            &long_path,
            vec![root.compute_hash()],
            root.lamport,
            &format!("device-{i}"),
            &sibling_version,
            &key(SIBLING_KEY_BASE + i),
        );
        admit(&conn, &sibling);
        losers.push(sibling.compute_hash());
    }

    let RetroactiveMergeOutcome::PathObligationTooLarge(blocked) =
        plan_retroactive_merge(&conn, GROUP).unwrap()
    else {
        panic!("expected an oversized obligation");
    };
    assert_eq!(
        blocked.revalidate(&conn, GROUP).unwrap(),
        None,
        "an unchanged world must leave the verdict standing"
    );

    let frontier_before = blocked.frontier().clone();

    // Other carriers durably provisioned every loser. The obligation is
    // gone; the frontier has not moved.
    for losing_change in &losers {
        record_provenance(
            &conn,
            &RepairObligation {
                source_path: SyncPath(long_path.clone()),
                losing_change: *losing_change,
            },
        );
    }

    assert_eq!(
        &frontier_before,
        &PublishedFrontierToken::capture(&conn, GROUP).unwrap(),
        "the frontier must be unchanged, or this test is proving the wrong thing"
    );
    assert_eq!(
        blocked.revalidate(&conn, GROUP).unwrap(),
        Some(PlanStaleness::ObligationsChanged),
        "a too-large verdict must not be adopted as permanent once its obligations shrank"
    );
}

#[test]
fn oversized_single_path_obligation_is_reported_as_permanently_blocked() {
    let conn = setup();
    let long_path = "x".repeat(3500);

    let root_version = version(1);
    dag_store::put_file_version(&conn, GROUP, &root_version).unwrap();
    let root = put_change_at(&long_path, Vec::new(), 0, "root", &root_version, &key(9));
    admit(&conn, &root);

    // Enough concurrent siblings off the root that the winner's
    // reassert-plus-(N-1)-conflict-copies bundle exceeds
    // MAX_CHANGE_OP_BYTES on the long path alone -- see `SIBLINGS` for
    // what sets that count and why it is not smaller.
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
            &key(SIBLING_KEY_BASE + i),
        );
        admit(&conn, &sibling);
    }

    match plan_retroactive_merge(&conn, GROUP).unwrap() {
        RetroactiveMergeOutcome::PathObligationTooLarge(blocked) => {
            let path = blocked.path.clone();
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

    let mut siblings: Vec<(String, u8, Change)> = Vec::with_capacity(SIBLINGS as usize);
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
            &key(SIBLING_KEY_BASE + i),
        );
        siblings.push((device_id, SIBLING_KEY_BASE + i, sibling));
    }
    // The (lamport, hash) tie-break `resolve_path_heads` itself uses --
    // all siblings share `root.lamport`, so this is decided by hash
    // alone. Computed purely from the already-built `Change`s, no DB
    // needed, so the actual winner is known before admitting anything.
    let (winner_device, winner_key, winner_sibling) = siblings
        .iter()
        .max_by(|(_, _, a), (_, _, b)| {
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
    for (_, _, sibling) in &siblings {
        admit(&conn, sibling);
    }

    // Give that SAME winner a second, small, concurrent conflict on an
    // unrelated short path off the same root, so the elected device has
    // both an oversized obligation and a fixable one and a single call
    // exercises both branches (oversized-and-skipped, small-and-packed).
    //
    // Parented on the winner's OWN long-path change, not on the root: a
    // device's changes form a chain, and a second change off the root by
    // a device that already authored one there would fork that device's
    // history instead of continuing it, which admission refuses. Building
    // on its own previous change also makes this the higher-Lamport head
    // on `short_path`, so it wins there outright and no competitor key
    // has to be searched for -- a search that would itself have been
    // wrong here, since every candidate it built consumed one of
    // `short-loser`'s chain positions and only the last was admitted.
    let short_winner_version = version(200);
    let short_winner_change = put_change_at(
        short_path,
        vec![winner_sibling.compute_hash()],
        winner_sibling.lamport,
        &winner_device,
        &short_winner_version,
        &key(winner_key),
    );
    let short_loser_version = version(300);
    let short_loser_change = put_change_at(
        short_path,
        vec![root_hash],
        root.lamport,
        "short-loser",
        &short_loser_version,
        &key(SHORT_LOSER_KEY),
    );

    dag_store::put_file_version(&conn, GROUP, &short_winner_version).unwrap();
    dag_store::put_file_version(&conn, GROUP, &short_loser_version).unwrap();
    admit(&conn, &short_winner_change);
    admit(&conn, &short_loser_change);
    assert!(
        short_winner_change.lamport > short_loser_change.lamport,
        "the elected device must be the short path's winner, or this test proves nothing \
         about a fixable obligation belonging to the same device as the oversized one"
    );

    match plan_retroactive_merge(&conn, GROUP).unwrap() {
        RetroactiveMergeOutcome::Plan(plan) => {
            assert_eq!(
                plan.source_paths,
                vec![short_path.to_string()],
                "the oversized long path must be skipped, not prevent the smaller \
                 fixable short path from being packed"
            );
        }
        RetroactiveMergeOutcome::PathObligationTooLarge(blocked) => {
            let path = blocked.path.clone();
            panic!(
                "the smaller short path must still be packed even though {path} alone \
                 is oversized"
            );
        }
    }
}

/// Scale benchmark for `plan_retroactive_merge`, which runs inside
/// `repair_retroactive_conflict_copy_obligations`'s own `write_immediate`
/// transaction and therefore holds the process-wide writer gate for its
/// whole duration. Without the group-scoped fork-existence fast path, its
/// cost grows with the group's history on every repeated call.
///
/// Realistic shape: one device sequentially admits N single-file `Put`
/// changes, each to its OWN path, each chained onto the group's current
/// head (`dag_group_heads`) exactly like real local capture does -- a
/// linear chain of depth N with zero forks, the overwhelmingly common
/// case (an ordinary folder with no concurrent writer).
/// `pre_fix_walk_only` duplicates `paths_that_can_have_concurrent_heads`'s
/// full-walk shape without the group-scoped fork-existence fast path --
/// kept here ONLY to quantify the difference, never called from
/// production code.
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
        Ok(touch_counts.into_iter().filter(|(_, count)| *count > 1).map(|(path, _)| path).collect())
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
                 (change_hash, group_id, device_id, author_seq, lamport, encoded, \
                  authenticated_header) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    &hash.0[..],
                    change.group_id.as_str(),
                    change.device_id.as_str(),
                    change.author_seq.get() as i64,
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
        let (after, _decode_cache) =
            paths_that_can_have_concurrent_heads(&conn, GROUP, &frontier).unwrap();
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
    /// factor win is what matters here: the cost at scale comes from
    /// many REPEATED per-call walks as the group's history keeps
    /// growing between polls, so a per-call constant-factor cut of this size cuts
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
        let (paths, _decode_cache) =
            paths_that_can_have_concurrent_heads(&conn, GROUP, &frontier).unwrap();
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

/// A repair carrier writes the source path it reasserts and the path of
/// every conflict copy it derives, and each of those paths moves past
/// whatever materialized basis it held. A basis left standing still reads as
/// current, so a later local edit of the path would be parented on it --
/// beside the carrier rather than on it -- and one author would hold two
/// heads of one path. The carrier's emission must retire them, as an
/// ordinary emission does.
#[test]
fn a_repair_carrier_retires_the_basis_of_every_path_it_writes() {
    let conn = setup();
    let root_version = version(1);
    let a_version = version(2);
    let b_version = version(3);
    for value in [&root_version, &a_version, &b_version] {
        dag_store::put_file_version(&conn, GROUP, value).unwrap();
    }
    let root = put_change(Vec::new(), 0, "root", &root_version, &key(9));
    admit(&conn, &root);
    let a = put_change(vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
    admit(&conn, &a);
    let b = put_change(vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
    admit(&conn, &b);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    let emitter = ChangeEmitter::new("device-r", key(7));
    let emit = || {
        dag_store::emit_retroactive_repair(
            &conn,
            GROUP,
            plan.direct_ops.clone(),
            plan.obligations.clone(),
            &emitter,
        )
        .unwrap()
    };
    // Every path the carrier will write, learned from an emission that is
    // then rolled back, so each can hold a basis before the real one.
    let written: Vec<String> = {
        let tx = conn.unchecked_transaction().unwrap();
        let paths = emit()
            .ops
            .iter()
            .map(|op| match op {
                Op::Put { path, .. } | Op::Delete { path } => path.as_str().to_string(),
                other => panic!("a repair carrier writes puts only here, got {other:?}"),
            })
            .collect();
        drop(tx);
        paths
    };
    assert!(
        written.iter().any(|p| p == PATH) && written.len() > 1,
        "the carrier must reassert {PATH} and derive a copy for this to test anything: \
         {written:?}"
    );

    let observed_at = dag_store::group_heads(&conn, GROUP).unwrap();
    for path in &written {
        crate::materialized_generation::record_materialized_generation(
            &conn,
            GROUP,
            path,
            &observed_at,
            crate::materialized_generation::MaterializedObjectKind::Absent,
            None,
            None,
            0,
        )
        .unwrap();
    }

    let carrier = emit();
    let carrier_hash = carrier.compute_hash();
    for path in &written {
        let basis =
            crate::materialized_generation::lookup_materialized_generation(&conn, GROUP, path)
                .unwrap()
                .map(|generation| {
                    dag_store::lookup_causal_basis_members(&conn, &generation.causal_basis_id.0)
                        .unwrap()
                        .expect("an interned basis")
                });
        assert!(
            basis.as_ref().is_none_or(|members| members.contains(&carrier_hash)),
            "{path} was written by the repair carrier {}, yet its basis still reads as \
             current and names only {:?}",
            carrier_hash.to_hex(),
            basis.map(|m| m.iter().map(|h| h.to_hex()).collect::<Vec<_>>()),
        );
    }
}

/// Forks `PATH` into a File `high` that outranks everything (a filler
/// change under it raises its lamport), an explicit Directory, and any
/// `others` (each a root of its own). Returns (high, directory, others).
fn fork_with_a_directory_outranked_by_a_leaf(
    conn: &Connection,
    high_version: &FileVersion,
    others: &[(&FileVersion, &str, u8)],
) -> (Change, Change, Vec<Change>) {
    let directory_version = FileVersion::directory(Some(0o755));
    let filler_version = version(900);
    for value in [high_version, &directory_version, &filler_version] {
        dag_store::put_file_version(conn, GROUP, value).unwrap();
    }
    let filler = put_change_at("filler", Vec::new(), 0, "device-high", &filler_version, &key(1));
    admit(conn, &filler);
    let high = put_change(
        vec![filler.compute_hash()],
        filler.lamport,
        "device-high",
        high_version,
        &key(1),
    );
    admit(conn, &high);
    let directory = put_change(Vec::new(), 0, "device-dir", &directory_version, &key(2));
    admit(conn, &directory);
    let others = others
        .iter()
        .map(|(value, device, signing)| {
            dag_store::put_file_version(conn, GROUP, value).unwrap();
            let change = put_change(Vec::new(), 0, device, value, &key(*signing));
            admit(conn, &change);
            assert!(change.lamport < high.lamport);
            change
        })
        .collect();
    assert!(directory.lamport < high.lamport);
    (high, directory, others)
}

/// DIR-1 in a repair: a Directory at `PATH` keeps `PATH` whoever wins the
/// rank. With a File outranking it and a second File beside them, the
/// repair must re-assert the Directory, not the File, and owe copies for
/// both Files (the ranked winner included) -- re-asserting the File would
/// supersede the Directory on every repairing device.
#[test]
fn a_three_way_fork_repair_keeps_the_directory_and_copies_every_leaf() {
    let conn = setup();
    let high_version = version(2);
    let other_version = version(3);
    let (high, directory, others) = fork_with_a_directory_outranked_by_a_leaf(
        &conn,
        &high_version,
        &[(&other_version, "device-other", 3)],
    );
    let other = &others[0];

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert_eq!(
        plan.direct_ops,
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: FileVersion::directory(Some(0o755)).version_hash,
            origin: PutOrigin::Reasserted {
                original_change: directory.compute_hash(),
                naming_device_id: DeviceId("device-dir".to_string()),
            },
        }],
        "the repair must carry the Directory forward at {PATH}"
    );
    let mut owed: Vec<ChangeHash> = plan.obligations.iter().map(|o| o.losing_change).collect();
    owed.sort();
    let mut expected = vec![high.compute_hash(), other.compute_hash()];
    expected.sort();
    assert_eq!(owed, expected, "both Files are owed a copy, the Directory none");

    let emitter = ChangeEmitter::new("device-r", key(7));
    let carrier = dag_store::emit_retroactive_repair(
        &conn,
        GROUP,
        plan.direct_ops,
        plan.obligations,
        &emitter,
    )
    .unwrap();
    let live = dag_store::live_path_heads(&conn, GROUP, PATH).unwrap();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(live[0].change_hash, carrier.compute_hash().0);
    assert_eq!(
        live[0].content.as_ref().map(|content| content.version_hash),
        Some(FileVersion::directory(Some(0o755)).version_hash.0),
        "the Directory must still be the one live head at {PATH}"
    );
    assert!(
        plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan().direct_ops.is_empty(),
        "the carrier must close the fork"
    );
}

/// DIR-1 in a repair, two heads: a File that outranks a Directory is
/// relocated beside it by the projection, and the repair makes that copy
/// durable (so a later op on the Directory cannot drop the File), carrying
/// the Directory forward at `PATH`.
#[test]
fn a_repair_makes_the_copy_of_a_file_that_outranks_a_directory_durable() {
    let conn = setup();
    let high_version = version(2);
    let (high, directory, _) = fork_with_a_directory_outranked_by_a_leaf(&conn, &high_version, &[]);

    let plan = plan_retroactive_merge(&conn, GROUP).unwrap().expect_plan();
    assert!(
        matches!(
            plan.direct_ops.as_slice(),
            [Op::Put { origin: PutOrigin::Reasserted { original_change, .. }, .. }]
                if *original_change == directory.compute_hash()
        ),
        "{:?}",
        plan.direct_ops
    );
    assert_eq!(
        plan.obligations,
        vec![RepairObligation {
            source_path: SyncPath(PATH.to_string()),
            losing_change: high.compute_hash(),
        }]
    );
    let emitter = ChangeEmitter::new("device-r", key(7));
    dag_store::emit_retroactive_repair(&conn, GROUP, plan.direct_ops, plan.obligations, &emitter)
        .unwrap();
}

/// A carrier that re-asserts the ranked File over a live Directory is
/// refused at admission: that re-assertion would supersede the Directory.
#[test]
fn a_repair_reasserting_a_file_over_a_directory_is_refused() {
    let conn = setup();
    let high_version = version(2);
    let (high, _directory, _) =
        fork_with_a_directory_outranked_by_a_leaf(&conn, &high_version, &[]);
    let heads = dag_store::group_heads(&conn, GROUP).unwrap();
    let max_parent_lamport = dag_store::max_parent_lamport(&conn, GROUP, &heads).unwrap();
    let carrier = create_signed_for_tests(
        heads,
        max_parent_lamport,
        DeviceId("device-r".to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath(PATH.to_string()),
            version: high_version.version_hash,
            origin: PutOrigin::Reasserted {
                original_change: high.compute_hash(),
                naming_device_id: DeviceId("device-high".to_string()),
            },
        }],
        &key(7),
    );
    let verdict = dag_store::validate_carrier_conflict_copy_ops(&conn, GROUP, &carrier);
    assert!(verdict.is_err(), "re-asserting the File over the Directory must be refused");
}
