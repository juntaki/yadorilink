//! Rebootstrap up to the preserved durability barrier: which target, what is
//! saved, how it is replayed, what is durable and what survives a crash. Nothing
//! here installs a target or touches a sync root.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use yadorilink_replica_domain::history_truncation::{HistoryTruncations, RetainedSummary};
use yadorilink_replica_domain::native_checkpoint_seal::NativeSealPolicy;
use yadorilink_replica_domain::signed_delta::RecursivePart;

use crate::native_rebootstrap::{
    begin_rebootstrap, expire_candidate, plan_preservation, rebootstrap_status,
    recover_after_restart, uncovered_own_deltas, verify_target_in_area, BeginError, BeginRequest,
    BlockedReason, CaptureBarrier, Crash, Failpoint, FinalCapture, LeaveIncremental, PlanError,
    PreservationFailure, PreserveContext, Preserved, ReassertAuthority, Reassertability,
    RebootstrapState, RecoveryContentSource, RestartOutcome,
};
use crate::native_rebootstrap_recovery::{new_recovery_id, sha256, RecoveryArea};
use crate::native_rebootstrap_target::{verify_and_prepare_target, verify_stored_target};

use super::history_lifecycle_red::{
    incarnation_of, offline_base, put_op, rem, remove_op, scenario, seed_versions, signed, Offline,
    Scenario,
};
use super::*;

/// A temporary directory that is private to the user, as a daemon's recovery root
/// is.
pub(super) fn private_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

// --- the harness ----------------------------------------------------------------------

/// Where the recovery items of a test live: beside the areas, never in one.
pub(super) fn items_root_of(recovery_root: &Path) -> PathBuf {
    recovery_root.join("persistent-items")
}

/// The test versions' bytes: one byte, the seed.
pub(super) struct SeedContent;

impl RecoveryContentSource for SeedContent {
    fn read_version(&self, version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        Ok(Some(vec![version.blocks[0].hash.0[0]]))
    }

    fn held_blocks(&self, version: &FileVersion) -> Result<Vec<BlockHash>, String> {
        Ok(version.blocks.iter().map(|b| b.hash.clone()).collect())
    }
}

struct NoContent;

impl RecoveryContentSource for NoContent {
    fn read_version(&self, _version: &FileVersion) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn held_blocks(&self, _version: &FileVersion) -> Result<Vec<BlockHash>, String> {
        Ok(Vec::new())
    }
}

pub(super) struct Writer;

impl ReassertAuthority for Writer {
    fn classify(&self, _path: &SyncPath) -> Reassertability {
        Reassertability::Reassertable
    }
}

/// A device that is a Viewer now, or a policy that withholds one path.
pub(super) struct Withholding(pub(super) &'static str);

impl ReassertAuthority for Withholding {
    fn classify(&self, path: &SyncPath) -> Reassertability {
        if path.as_str() == self.0 {
            Reassertability::PolicyWithheld
        } else {
            Reassertability::Reassertable
        }
    }
}

pub(super) struct Viewer;

impl ReassertAuthority for Viewer {
    fn classify(&self, _path: &SyncPath) -> Reassertability {
        Reassertability::NotWriter
    }
}

fn truncated_by(peers: &[&str]) -> HistoryTruncations {
    let mut truncations = HistoryTruncations::default();
    for peer in peers {
        truncations.record(
            peer,
            &group(),
            RetainedSummary { checkpoint_id: [1; 32], frontier_root: [2; 32] },
        );
    }
    truncations
}

/// Publishes `delta` as a writer that does not honour the freeze would: the journal is read as
/// open for the one install and put back. The install-time re-checks are defence in depth
/// against exactly such a writer, and these specs exercise them.
pub(super) fn publish_past_the_freeze(
    c: &Connection,
    who: &AuthorId,
    key: &SigningKey,
    delta: NativeDelta,
) {
    let state: String =
        c.query_row("SELECT state FROM native_rebootstrap_journal", [], |row| row.get(0)).unwrap();
    c.execute("UPDATE native_rebootstrap_journal SET state = 'planning'", []).unwrap();
    publish(c, who, key, delta);
    c.execute("UPDATE native_rebootstrap_journal SET state = ?1", [state]).unwrap();
}

/// A final capture pass that finds nothing to author.
pub(super) struct NoCapture;

impl FinalCapture for NoCapture {
    fn capture(
        &self,
        _: &std::sync::Arc<crate::native_rebootstrap::CaptureAuthority>,
    ) -> CaptureBarrier {
        CaptureBarrier::Completed
    }
}

pub(super) struct Setup<'a> {
    pub(super) connected: Vec<&'a str>,
    pub(super) truncating: Vec<&'a str>,
    pub(super) available: Option<u64>,
    pub(super) capture: CaptureBarrier,
    pub(super) final_capture: &'a dyn FinalCapture,
    pub(super) sync_roots: Vec<PathBuf>,
    pub(super) content: &'a dyn RecoveryContentSource,
    pub(super) authority: &'a dyn ReassertAuthority,
    pub(super) policy: &'a dyn NativeSealPolicy,
}

impl Default for Setup<'static> {
    fn default() -> Self {
        Self {
            connected: vec!["p1"],
            truncating: vec!["p1"],
            available: None,
            capture: CaptureBarrier::Completed,
            final_capture: &NoCapture,
            sync_roots: Vec::new(),
            content: &SeedContent,
            authority: &Writer,
            policy: &Policy,
        }
    }
}

pub(super) fn begin_custom(
    conn: &Connection,
    bundle: NativeBootstrap,
    recovery_root: &Path,
    setup: &Setup<'_>,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Preserved, BeginError> {
    let truncations = truncated_by(&setup.truncating);
    let own_device = DeviceId("device-b".into());
    let group = group();
    begin_rebootstrap(
        conn,
        BeginRequest {
            group: &group,
            own_device: &own_device,
            bundle,
            policy: setup.policy,
            gate: LeaveIncremental { truncations: &truncations, connected: &setup.connected },
        },
        &PreserveContext {
            recovery_root,
            items_root: items_root_of(recovery_root),
            sync_roots: &setup.sync_roots,
            available_bytes: setup.available,
            capture: setup.capture.clone(),
            final_capture: setup.final_capture,
            content: setup.content,
            authority: setup.authority,
            now_unix: 1000,
        },
        hook,
    )
}

/// Preserves with every peer truncated and every default permissive.
pub(super) fn begin_with(
    conn: &Connection,
    bundle: NativeBootstrap,
    recovery_root: &Path,
    hook: &mut dyn FnMut(Failpoint) -> Result<(), Crash>,
) -> Result<Preserved, BeginError> {
    begin_custom(conn, bundle, recovery_root, &Setup::default(), hook)
}

pub(super) fn no_hook(_: Failpoint) -> Result<(), Crash> {
    Ok(())
}

type Snapshot = (([u8; 32], [u8; 32]), yadorilink_replica_domain::native_state::NativeState);

fn snapshot(c: &Connection) -> Snapshot {
    (roots_of(c), crate::native_store::load_state(c, &group()).unwrap())
}

pub(super) fn device_b() -> DeviceId {
    DeviceId("device-b".into())
}

/// The recovery area's files, relative, for "nothing was written" checks.
pub(super) fn files_below(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            out.push(entry.path());
            if entry.path().is_dir() {
                walk(&entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

/// B authored three uncovered deltas: two versions of `x` and one of `y`.
fn three_uncovered(o: &Offline) -> [NativeDelta; 3] {
    let d1 = signed(&o.b1, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
    let d2 = signed(
        &o.b1,
        2,
        Some(d1.delta_hash()),
        vec![put_op("x", 3, vec![rem(&o.b1, 1, d1.delta_hash())])],
    );
    let d3 = signed(&o.b1, 3, Some(d2.delta_hash()), vec![put_op("y", 4, Vec::new())]);
    for d in [&d1, &d2, &d3] {
        publish(&o.b, &o.b1, &device_key(2), d.clone());
    }
    [d1, d2, d3]
}

// --- entering the machine -------------------------------------------------------------

#[test]
fn an_empty_peer_set_never_starts_a_journal() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let setup = Setup { connected: vec![], truncating: vec![], ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), area.path(), &setup, &mut no_hook);
    assert!(matches!(outcome, Err(BeginError::NotLeavingIncremental)), "{outcome:?}");
    assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None, "a journal was started");
    assert!(files_below(area.path()).is_empty(), "something was written");
}

#[test]
fn a_connected_peer_that_has_not_truncated_never_starts_a_journal() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let setup = Setup { connected: vec!["p1", "p2"], truncating: vec!["p1"], ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), area.path(), &setup, &mut no_hook);
    assert!(matches!(outcome, Err(BeginError::NotLeavingIncremental)), "{outcome:?}");
    assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None);
}

/// A bundle the live policy does not vouch for is no candidate.
#[test]
fn a_bundle_that_does_not_verify_never_starts_a_journal() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let denying = StoredPolicyLike { writer: false };
    let setup = Setup { policy: &denying, ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), area.path(), &setup, &mut no_hook);
    assert!(matches!(outcome, Err(BeginError::CandidateRefused(_))), "{outcome:?}");
    assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None);
}

struct StoredPolicyLike {
    writer: bool,
}

impl NativeSealPolicy for StoredPolicyLike {
    fn resolve_authority_key(
        &self,
        key_id: &[u8; 32],
        head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        Policy.resolve_authority_key(key_id, head)
    }

    fn writer_at_policy_point(
        &self,
        _device: &str,
        _fingerprint: &[u8; 32],
        _point: &yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint,
    ) -> bool {
        self.writer
    }
}

// --- the preserve ledger --------------------------------------------------------------

/// Every own delta the target does not cover is uncovered, whichever incarnation of
/// this device authored it and whether or not it was ever published.
#[test]
fn uncovered_own_deltas_span_every_incarnation_published_or_not() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    // A second incarnation of the same device, whose delta was never published.
    let b2 = incarnation_of("device-b", 2);
    let unpublished = signed(&b2, 1, None, vec![put_op("z", 5, Vec::new())]);
    crate::native_store::install_verified_delta(
        &w.b,
        &group(),
        &{
            let mut d = unpublished.clone();
            d.sign(&device_key(2));
            d
        },
        &device_key(2).verifying_key(),
    )
    .unwrap();
    let frontier = crate::native_store::load_frontier(&w.sealer, &group()).unwrap();

    let uncovered = uncovered_own_deltas(&w.b, &group(), &device_b(), &frontier).unwrap();

    let mut got: Vec<(AuthorId, u64)> =
        uncovered.iter().map(|d| (d.delta.author.clone(), d.delta.seq.get())).collect();
    got.sort();
    let mut want = vec![(w.b1.clone(), 2), (b2, 1)];
    want.sort();
    assert_eq!(got, want, "B1/1 is covered; the authorized B1/2 and the unpublished B2/1 are not");
}

/// A row at the target's seq whose hash is not the target's tip means the
/// incarnation forked from the target: all of it is uncovered.
#[test]
fn a_fork_at_the_covered_seq_makes_the_whole_incarnation_uncovered() {
    let sealer = conn();
    let local = conn();
    seed_versions(&sealer);
    seed_versions(&local);
    let b1 = incarnation_of("device-b", 1);
    publish(&sealer, &b1, &device_key(2), signed(&b1, 1, None, vec![put_op("x", 1, Vec::new())]));
    publish(&local, &b1, &device_key(2), signed(&b1, 1, None, vec![put_op("x", 2, Vec::new())]));
    let frontier = crate::native_store::load_frontier(&sealer, &group()).unwrap();

    let uncovered = uncovered_own_deltas(&local, &group(), &device_b(), &frontier).unwrap();

    assert_eq!(uncovered.len(), 1, "the forked B1/1 is not what the target holds");
}

/// A replica whose own incarnation reached `B1/5` while the target holds `B1/3`
/// and newer work from another author. `collect` decides what the log still keeps.
struct CollectedOwn {
    local: Connection,
    target: yadorilink_replica_domain::native_frontier::NativeAuthorFrontier,
}

fn collected_own(collect: &str) -> CollectedOwn {
    let local = conn();
    let sealer = conn();
    seed_versions(&local);
    seed_versions(&sealer);
    let b1 = incarnation_of("device-b", 1);
    let mut prev = None;
    for seq in 1..=5u64 {
        let delta = signed(&b1, seq, prev, vec![put_op(&format!("f{seq}"), 1, Vec::new())]);
        prev = Some(delta.delta_hash());
        publish(&local, &b1, &device_key(2), delta.clone());
        if seq <= 3 {
            publish(&sealer, &b1, &device_key(2), delta);
        }
    }
    let s = incarnation_of("device-s", 1);
    publish(&sealer, &s, &device_key(4), signed(&s, 1, None, vec![put_op("y", 3, Vec::new())]));
    local.execute(&format!("DELETE FROM native_delta_log WHERE {collect}"), []).unwrap();
    local.execute(&format!("DELETE FROM native_delta_bodies WHERE {collect}"), []).unwrap();
    let target = crate::native_store::load_frontier(&sealer, &group()).unwrap();
    CollectedOwn { local, target }
}

/// The log of an own incarnation was collected whole at the floor, so it has no rows
/// at all; the target covers only `B1/3`. `B1/4` and `B1/5` may be a delete the
/// target would resurrect, and with no body they cannot be preserved.
#[test]
fn an_own_incarnation_with_no_log_rows_above_the_target_blocks_it() {
    let w = collected_own("1 = 1");
    let result = uncovered_own_deltas(&w.local, &group(), &device_b(), &w.target);
    assert!(
        matches!(result, Err(PlanError::Blocked(BlockedReason::LocalIntentUnavailable { .. }))),
        "{result:?}"
    );
}

/// The same loss with some rows kept (only the tail was collected) blocks as well.
#[test]
fn an_own_incarnation_missing_only_its_tail_rows_blocks_the_target() {
    let w = collected_own("seq > 3");
    let result = uncovered_own_deltas(&w.local, &group(), &device_b(), &w.target);
    assert!(
        matches!(result, Err(PlanError::Blocked(BlockedReason::LocalIntentUnavailable { .. }))),
        "{result:?}"
    );
}

/// While the log still keeps the bodies, the target is planned normally.
#[test]
fn an_own_incarnation_whose_bodies_are_kept_is_planned_normally() {
    let w = collected_own("seq <= 0");
    let uncovered = uncovered_own_deltas(&w.local, &group(), &device_b(), &w.target).unwrap();
    let seqs: Vec<u64> = uncovered.iter().map(|d| d.delta.seq.get()).collect();
    assert_eq!(seqs, vec![4, 5]);
}

/// Own incarnation `B1` at seq 5, its whole log collected at a floor that names the same
/// position; `target_tip` is the tip a target holds at the given seq.
fn collected_at_floor(
    target_seq: u64,
    target_tip: impl Fn(&[DeltaHash]) -> DeltaHash,
) -> (Connection, yadorilink_replica_domain::native_frontier::NativeAuthorFrontier) {
    let local = conn();
    seed_versions(&local);
    let b1 = incarnation_of("device-b", 1);
    let mut prev = None;
    let mut hashes = Vec::new();
    for seq in 1..=5u64 {
        let delta = signed(&b1, seq, prev, vec![put_op(&format!("f{seq}"), 1, Vec::new())]);
        prev = Some(delta.delta_hash());
        hashes.push(delta.delta_hash());
        publish(&local, &b1, &device_key(2), delta);
    }
    local.execute("DELETE FROM native_delta_log", []).unwrap();
    local.execute("DELETE FROM native_delta_bodies", []).unwrap();
    local
        .execute(
            "INSERT INTO native_history_floor (group_id, checkpoint_id, floor_frontier_root, \
             adopted_at_unixtime) VALUES (?1, X'01', X'02', 0)",
            [group().as_str()],
        )
        .unwrap();
    local
        .execute(
            "INSERT INTO native_checkpoint_frontier (group_id, checkpoint_id, author, \
             incarnation, closed, seq, tip) VALUES (?1, X'01', ?2, ?3, 0, 5, ?4)",
            (
                group().as_str(),
                b1.device.as_str(),
                b1.incarnation.0.as_slice(),
                hashes[4].0.as_slice(),
            ),
        )
        .unwrap();
    let target = std::iter::once((
        b1,
        yadorilink_replica_domain::native_frontier::NativeAuthorFrontierEntry {
            seq: AuthorSeq(target_seq),
            tip: target_tip(&hashes),
        },
    ))
    .collect();
    (local, target)
}

/// A log collected whole at the floor keeps no row at the target's seq, and the target
/// names the same seq with another tip: that is another branch of the incarnation, and the
/// seq alone does not make it covered. What the replica authored cannot be preserved, so the
/// target is refused.
#[test]
fn compacted_own_same_seq_different_tip_is_not_covered() {
    let (local, target) = collected_at_floor(5, |_| DeltaHash([0xEE; 32]));
    let result = uncovered_own_deltas(&local, &group(), &device_b(), &target);
    assert!(
        matches!(result, Err(PlanError::Blocked(BlockedReason::LocalIntentUnavailable { .. }))),
        "{result:?}"
    );
}

/// The same position with the floor's own tip is covered without any log row.
#[test]
fn exact_floor_tip_match_is_covered_without_log() {
    let (local, target) = collected_at_floor(5, |hashes| hashes[4]);
    let uncovered = uncovered_own_deltas(&local, &group(), &device_b(), &target).unwrap();
    assert!(uncovered.is_empty());
}

/// A target below the floor with no retained row has no evidence it is an ancestor of what
/// the replica authored; the replica's later work cannot be preserved, so it is refused.
#[test]
fn target_below_floor_without_ancestry_proof_is_not_covered() {
    let (local, target) = collected_at_floor(3, |hashes| hashes[2]);
    let result = uncovered_own_deltas(&local, &group(), &device_b(), &target);
    assert!(
        matches!(result, Err(PlanError::Blocked(BlockedReason::LocalIntentUnavailable { .. }))),
        "{result:?}"
    );
}

/// A closed own incarnation that authored nothing has a frontier of zero and no
/// rows: there is nothing to preserve.
#[test]
fn an_own_incarnation_with_frontier_zero_has_nothing_to_preserve() {
    let w = collected_own("seq <= 0");
    let idle = incarnation_of("device-b", 2);
    w.local
        .execute(
            "INSERT INTO native_author_frontier (group_id, author, incarnation, seq, tip) \
             VALUES (?1, ?2, ?3, 0, ?4)",
            (GROUP, idle.device.as_str(), idle.incarnation.0.as_slice(), [0u8; 32].as_slice()),
        )
        .unwrap();
    let uncovered = uncovered_own_deltas(&w.local, &group(), &device_b(), &w.target).unwrap();
    assert_eq!(uncovered.len(), 2, "only B1/4 and B1/5; the idle incarnation adds nothing");
}

/// An uncovered delta without its body: the target is not installable, the
/// reason names the delta, the replica and the area are untouched.
#[test]
fn a_missing_body_blocks_the_target_and_writes_nothing() {
    let w = scenario(|b1, h1| vec![remove_op("x", vec![rem(b1, 1, h1)])]);
    w.b.execute("DELETE FROM native_delta_bodies WHERE group_id = ?1 AND seq = 2", [GROUP])
        .unwrap();
    let before = snapshot(&w.b);
    let area = private_tempdir();

    let outcome = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook);

    let hash = w.undelivered.delta_hash();
    assert!(
        matches!(&outcome, Err(BeginError::Blocked(BlockedReason::LocalIntentUnavailable { delta })) if *delta == hash),
        "{outcome:?}"
    );
    assert!(before == snapshot(&w.b), "the replica changed");
    assert!(files_below(area.path()).is_empty(), "the recovery area was written");
    let status = rebootstrap_status(&w.b, &group()).unwrap().expect("the block is surfaced");
    assert_eq!(
        status.state,
        RebootstrapState::Blocked(BlockedReason::LocalIntentUnavailable { delta: hash })
    );
}

/// A body that is not the delta the log names is no exact intent either.
#[test]
fn a_body_that_is_not_the_logged_delta_is_unavailable() {
    let w = scenario(|b1, h1| vec![remove_op("x", vec![rem(b1, 1, h1)])]);
    let other = signed(&w.b1, 2, Some(w.h1), vec![put_op("y", 3, Vec::new())]).to_wire_bytes();
    w.b.execute(
        "UPDATE native_delta_bodies SET encoded_delta = ?1 WHERE group_id = ?2 AND seq = 2",
        (other, GROUP),
    )
    .unwrap();
    let frontier = crate::native_store::load_frontier(&w.sealer, &group()).unwrap();
    let result = uncovered_own_deltas(&w.b, &group(), &device_b(), &frontier);
    assert!(
        matches!(result, Err(PlanError::Blocked(BlockedReason::LocalIntentUnavailable { .. }))),
        "{result:?}"
    );
}

/// Units are the connected components over removal edges: a put and the delete
/// that removes it are one unit, a delta that only follows them in the chain is
/// another. A removal across incarnations puts the creator first whatever the
/// incarnations' order.
#[test]
fn the_replay_orders_by_removal_edges_and_groups_units_by_them() {
    let t = conn();
    seed_versions(&t);
    let a = incarnation_of("device-a", 1);
    let a1 = signed(&a, 1, None, vec![put_op("x", 1, Vec::new())]);
    publish(&t, &a, &device_key(1), a1.clone());
    let target = crate::native_store::load_frontier(&t, &group()).unwrap();
    let (b1, b2) = (incarnation_of("device-b", 1), incarnation_of("device-b", 2));
    let puts = signed(&b2, 1, None, vec![put_op("x", 2, vec![rem(&a, 1, a1.delta_hash())])]);
    let deletes = signed(&b1, 1, None, vec![remove_op("x", vec![rem(&b2, 1, puts.delta_hash())])]);
    let later = signed(&b2, 2, Some(puts.delta_hash()), vec![put_op("y", 3, Vec::new())]);
    for (author, delta) in [(&b2, &puts), (&b1, &deletes), (&b2, &later)] {
        publish(&t, author, &device_key(2), delta.clone());
    }

    let plan = plan_preservation(&t, &group(), &device_b(), &target, [9; 32], &Writer).unwrap();

    let order: Vec<DeltaHash> = plan.order.iter().map(|d| d.hash).collect();
    assert_eq!(
        order,
        vec![puts.delta_hash(), deletes.delta_hash(), later.delta_hash()],
        "the delta that creates a head replays before the one that removes it, though B1 sorts first"
    );
    assert_eq!(
        plan.unit_of,
        vec![0, 0, 1],
        "a put and its delete are one unit; the chain alone does not join"
    );
    assert_eq!(plan.units.len(), 2);
}

#[test]
fn the_parts_of_a_recursive_operation_are_one_unit() {
    let t = conn();
    seed_versions(&t);
    let target = crate::native_store::load_frontier(&t, &group()).unwrap();
    let b1 = incarnation_of("device-b", 1);
    let mut prev = None;
    let mut all = Vec::new();
    for index in 0..3u32 {
        let mut delta = signed(
            &b1,
            u64::from(index) + 1,
            prev,
            vec![put_op(&format!("d/f{index}"), 2, Vec::new())],
        );
        if index < 2 {
            delta.recursive_part = Some(RecursivePart {
                operation_id: yadorilink_replica_domain::recursive_operation::RecursiveOperationId(
                    [7; 16],
                ),
                part_index: index,
                part_count: 2,
            });
        }
        publish(&t, &b1, &device_key(2), delta.clone());
        prev = Some(delta.delta_hash());
        all.push(delta);
    }

    let plan = plan_preservation(&t, &group(), &device_b(), &target, [9; 32], &Writer).unwrap();

    assert_eq!(plan.unit_of, vec![0, 0, 1], "both parts of the operation replay as one unit");
}

#[test]
fn reassertability_is_a_planning_label_per_unit() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let frontier = crate::native_store::load_frontier(&w.sealer, &group()).unwrap();
    for (authority, expected) in [
        (&Writer as &dyn ReassertAuthority, Reassertability::Reassertable),
        (&Viewer, Reassertability::NotWriter),
        (&Withholding("x"), Reassertability::PolicyWithheld),
    ] {
        let plan =
            plan_preservation(&w.b, &group(), &device_b(), &frontier, [9; 32], authority).unwrap();
        assert_eq!(plan.units[0].reassertable, expected);
    }
}

// --- the barrier ------------------------------------------------------------------------

#[test]
fn the_barrier_holds_and_leaves_the_replica_untouched() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let before = snapshot(&w.b);
    let area = private_tempdir();

    let preserved = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();

    assert!(before == snapshot(&w.b), "preserving changed the native state");
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert_eq!(status.state, RebootstrapState::Preserved);
    assert_eq!(status.recovery_id, preserved.recovery_id);
    assert_eq!((status.items_total, status.items_copied), (2, 2), "the version and the delta");
    let intent = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap();
    assert_eq!(intent.deltas.len(), 1);
    assert_eq!(intent.deltas[0].1, w.undelivered.to_wire_bytes());
    assert_eq!(intent.versions.values().collect::<Vec<_>>(), vec![&vec![2u8]]);
    assert_eq!(intent.manifest.target_checkpoint_hash, preserved.checkpoint_hash);
    assert!(intent.manifest.items.iter().all(|item| item.reassertable));
}

#[test]
fn a_capture_pass_that_did_not_complete_blocks_the_plan() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let setup = Setup {
        capture: CaptureBarrier::Partial { detail: "unreadable d/".into() },
        ..Setup::default()
    };
    let outcome = begin_custom(&w.b, built(&w.sealer), area.path(), &setup, &mut no_hook);
    assert!(matches!(
        outcome,
        Err(BeginError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { .. }
        )))
    ));
    assert!(files_below(area.path()).is_empty());
}

#[test]
fn the_space_check_includes_the_target_bundle() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let bundle = built(&w.sealer);
    let bundle_len =
        crate::native_bootstrap_codec::encode_recovery_bundle(&bundle).unwrap().len() as u64;
    let area = private_tempdir();
    let setup = Setup { available: Some(0), ..Setup::default() };

    let outcome = begin_custom(&w.b, bundle, area.path(), &setup, &mut no_hook);

    let Err(BeginError::Blocked(BlockedReason::PreservationFailed(
        PreservationFailure::InsufficientSpace { needed, available: 0 },
    ))) = outcome
    else {
        panic!("not blocked for space: {outcome:?}");
    };
    assert!(needed > bundle_len, "needed {needed} does not even cover the bundle ({bundle_len})");
    assert!(files_below(area.path()).is_empty());
}

#[test]
fn content_that_is_not_held_blocks_with_nothing_destroyed() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let setup = Setup { content: &NoContent, ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), area.path(), &setup, &mut no_hook);
    assert!(
        matches!(
            outcome,
            Err(BeginError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::ContentUnavailable { .. }
            )))
        ),
        "{outcome:?}"
    );
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert!(matches!(status.state, RebootstrapState::Blocked(_)));
    // The restart sweep removes what the block left, and keeps the block visible.
    let restart = recover_after_restart(&w.b, area.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Blocked(_)));
    assert!(recovery_dirs_of(area.path()).is_empty(), "the incomplete area stayed");
}

pub(super) fn recovery_dirs_of(area: &Path) -> Vec<PathBuf> {
    super::history_lifecycle_red::recovery_dirs(area)
}

#[test]
fn a_recovery_root_inside_a_synced_root_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let sync_root = private_tempdir();
    let inside = sync_root.path().join("recovery");
    let setup = Setup { sync_roots: vec![sync_root.path().to_path_buf()], ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), &inside, &setup, &mut no_hook);
    assert!(
        matches!(
            outcome,
            Err(BeginError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::RecoveryAreaUnavailable { .. }
            )))
        ),
        "{outcome:?}"
    );
    // An ancestor of the synced root is refused too.
    let around = private_tempdir();
    let nested = around.path().join("sync");
    fs::create_dir(&nested).unwrap();
    let setup = Setup { sync_roots: vec![nested], ..Setup::default() };
    let outcome = begin_custom(&w.b, built(&w.sealer), around.path(), &setup, &mut no_hook);
    assert!(matches!(outcome, Err(BeginError::Blocked(_))), "{outcome:?}");
}

// --- crash safety -------------------------------------------------------------------------

pub(super) fn crash_at(point: Failpoint) -> impl FnMut(Failpoint) -> Result<(), Crash> {
    move |reached| if reached == point { Err(Crash) } else { Ok(()) }
}

/// A crash before the barrier leaves the old state authoritative, and the
/// restart discards the half-written area (idempotently).
#[test]
fn a_crash_before_preserved_is_discarded_on_restart() {
    for point in [
        Failpoint::AfterTargetDurable,
        Failpoint::AfterRecoveryItem(0),
        Failpoint::AfterRecoveryItem(1),
        Failpoint::BeforeManifest,
    ] {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let before = snapshot(&w.b);
        let area = private_tempdir();

        let outcome = begin_with(&w.b, built(&w.sealer), area.path(), &mut crash_at(point));

        assert!(matches!(outcome, Err(BeginError::Crashed)), "{point:?}: {outcome:?}");
        let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
        assert_eq!(status.state, RebootstrapState::Preserving, "{point:?}: not Preserved yet");
        assert!(before == snapshot(&w.b), "{point:?}: the old state changed");

        let restart = recover_after_restart(&w.b, area.path(), &group()).unwrap();
        assert!(matches!(restart, RestartOutcome::Abandoned { .. }), "{point:?}: {restart:?}");
        assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None);
        assert!(recovery_dirs_of(area.path()).is_empty(), "{point:?}: the area stayed");
        let again = recover_after_restart(&w.b, area.path(), &group()).unwrap();
        assert_eq!(again, RestartOutcome::Idle, "{point:?}: cleanup is idempotent");
        // The group can start over.
        begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    }
}

/// A crash after the barrier resumes from the manifest.
#[test]
fn a_crash_after_preserved_resumes_from_the_manifest() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let outcome =
        begin_with(&w.b, built(&w.sealer), area.path(), &mut crash_at(Failpoint::AtPreserved));
    assert!(matches!(outcome, Err(BeginError::Crashed)));
    assert_eq!(
        rebootstrap_status(&w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved
    );
    // A leftover temporary from an interrupted write does not matter.
    let dir = recovery_dirs_of(area.path()).remove(0);
    fs::write(dir.join(".tmp-0123456789abcdef"), b"partial").unwrap();

    let restart = recover_after_restart(&w.b, area.path(), &group()).unwrap();

    let RestartOutcome::Preserved(preserved) = restart else { panic!("{restart:?}") };
    assert_eq!(preserved.dir, dir);
    assert!(!dir.join(".tmp-0123456789abcdef").exists(), "temporaries are removed on resume");
    assert_eq!(preserved.manifest_sha256, sha256(&fs::read(dir.join("manifest.json")).unwrap()));
}

/// An incomplete area that belongs to no journal is swept; a complete one is
/// the user's data and stays.
#[test]
fn the_restart_sweep_keeps_complete_areas_and_removes_incomplete_ones() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let kept = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    // The rebootstrap completed (its journal is gone); a later crash left an
    // incomplete area behind.
    w.b.execute("DELETE FROM native_rebootstrap_journal", []).unwrap();
    let stray = RecoveryArea::create(
        area.path(),
        &group(),
        &crate::native_rebootstrap_recovery::new_recovery_id(),
        &[],
    )
    .unwrap();

    let restart = recover_after_restart(&w.b, area.path(), &group()).unwrap();

    assert_eq!(restart, RestartOutcome::Idle);
    assert!(kept.dir.exists(), "a complete area was removed");
    assert!(!stray.dir().exists(), "an incomplete area stayed");
}

#[test]
fn a_second_trigger_for_the_same_target_resumes_and_a_new_target_starts_over() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let first_bundle = built(&w.sealer);
    let first = begin_with(&w.b, first_bundle.clone(), area.path(), &mut no_hook).unwrap();

    let again = begin_with(&w.b, first_bundle, area.path(), &mut no_hook).unwrap();
    assert_eq!(again, first, "the same target resumes");
    assert_eq!(recovery_dirs_of(area.path()).len(), 1);

    // Another sealer state is another target.
    let c = incarnation_of("device-c", 1);
    publish(&w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    let second = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();

    assert_ne!(
        second.recovery_id, first.recovery_id,
        "a manifest is never reused for another target"
    );
    assert_ne!(second.checkpoint_hash, first.checkpoint_hash);
    assert_eq!(
        recovery_dirs_of(area.path()),
        vec![second.dir.clone()],
        "the old area was replaced"
    );
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert_eq!(status.recovery_id, second.recovery_id);
    let manifest = RecoveryArea::open_dir(&second.dir).unwrap().read_intent().unwrap().manifest;
    assert_eq!(manifest.target_checkpoint_hash, second.checkpoint_hash);
}

#[test]
fn a_candidate_expires_before_the_barrier_but_not_after() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let outcome = begin_with(
        &w.b,
        built(&w.sealer),
        area.path(),
        &mut crash_at(Failpoint::AfterTargetDurable),
    );
    assert!(matches!(outcome, Err(BeginError::Crashed)));
    assert!(expire_candidate(&w.b, &group(), 2000).unwrap());
    assert_eq!(
        rebootstrap_status(&w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(BlockedReason::CandidateExpired)
    );

    recover_after_restart(&w.b, area.path(), &group()).unwrap();
    begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    assert!(!expire_candidate(&w.b, &group(), 3000).unwrap(), "a durable target does not expire");
}

// --- the stored target is verified locally ----------------------------------------------------

/// The verification half of resuming after a quarantine: the stored target is
/// verified from what is stored alone, whatever the live policy says now.
#[test]
fn a_durably_accepted_target_is_verified_locally_with_no_peer_and_no_authority() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let preserved = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    let Scenario { b, sealer, .. } = w;
    drop(sealer); // the peer is gone
    drop(b); // and so is the database

    let stored = RecoveryArea::open_dir(&preserved.dir).unwrap();
    let verified = verify_target_in_area(&stored, &group()).expect("verifies from the area alone");

    assert_eq!(verified.checkpoint_hash(), preserved.checkpoint_hash);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(preserved.dir.join("target.verification.json")).unwrap())
            .unwrap();
    assert_eq!(record["install_permitted"], true);
    assert!(record["policy_head"].is_string() && record["policy_seq"].is_u64());
}

#[test]
fn a_stored_target_that_was_changed_does_not_verify() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let (_, stored) = verify_and_prepare_target(built(&w.sealer), &group(), &Policy).unwrap();
    verify_stored_target(&group(), &stored).expect("the untouched target verifies");

    // A record that does not permit the install.
    let mut forbidden = stored.clone();
    forbidden.record = String::from_utf8(stored.record.clone())
        .unwrap()
        .replace("\"install_permitted\":true", "\"install_permitted\":false")
        .into_bytes();
    assert!(verify_stored_target(&group(), &forbidden).is_err(), "a record that forbids");

    // A bundle other than the one verified.
    let mut flipped = stored.clone();
    flipped.bundle[40] ^= 1;
    assert!(verify_stored_target(&group(), &flipped).is_err(), "a changed bundle");

    // Material without the seal answers, even with a record updated to match, cannot
    // make the bundle verify: the answers are what it verifies against.
    let mut empty = stored.clone();
    empty.material = br#"{"answers":[],"format_version":1}"#.to_vec();
    let mut record: serde_json::Value = serde_json::from_slice(&stored.record).unwrap();
    record["material_sha256"] = hex::encode(sha256(&empty.material)).into();
    empty.record = serde_json::to_vec(&record).unwrap();
    assert!(verify_stored_target(&group(), &empty).is_err(), "material that vouches for nothing");
}

/// A changed byte in the area is found on resume: the machine is blocked, and the
/// user's data is not deleted.
#[test]
fn a_damaged_area_blocks_the_resume_and_is_kept() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    let preserved = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    let version =
        fs::read_dir(preserved.dir.join("versions")).unwrap().next().unwrap().unwrap().path();
    fs::write(&version, [99u8]).unwrap();

    let restart = recover_after_restart(&w.b, area.path(), &group()).unwrap();

    assert!(
        matches!(restart, RestartOutcome::Blocked(BlockedReason::ManifestInconsistent { .. })),
        "{restart:?}"
    );
    assert!(preserved.dir.exists(), "a damaged area is the user's data and stays");
    assert!(matches!(
        rebootstrap_status(&w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Blocked(_)
    ));
}

// --- the area is local security state -----------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlinked_subdirectory_is_refused_for_writes_and_reads() {
    use std::os::unix::fs::symlink;
    let base = private_tempdir();
    let id = crate::native_rebootstrap_recovery::new_recovery_id();
    let area = RecoveryArea::create(&base.path().join("recovery"), &group(), &id, &[]).unwrap();
    let outside = base.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::remove_dir(area.dir().join("versions")).unwrap();
    symlink(&outside, area.dir().join("versions")).unwrap();
    let version = VersionHash([5; 32]);

    assert!(area.write_version(&version, b"secret").is_err(), "wrote through a symlinked dir");
    assert!(area.read_version(&version).is_err());
    assert!(fs::read_dir(&outside).unwrap().next().is_none(), "something reached the outside");
}

#[cfg(unix)]
#[test]
fn a_symlinked_file_in_the_area_is_refused_when_read_back() {
    use std::os::unix::fs::symlink;
    let base = private_tempdir();
    let id = crate::native_rebootstrap_recovery::new_recovery_id();
    let area = RecoveryArea::create(&base.path().join("recovery"), &group(), &id, &[]).unwrap();
    let secret = base.path().join("secret");
    fs::write(&secret, b"not the bundle").unwrap();
    symlink(&secret, area.dir().join("target.bundle")).unwrap();
    assert!(area.read_target_bundle().is_err(), "read through a symlinked file");
}

#[test]
fn an_area_is_never_created_twice() {
    let base = private_tempdir();
    let id = crate::native_rebootstrap_recovery::new_recovery_id();
    RecoveryArea::create(base.path(), &group(), &id, &[]).unwrap();
    assert!(RecoveryArea::create(base.path(), &group(), &id, &[]).is_err());
    assert!(RecoveryArea::create(base.path(), &group(), "not-hex", &[]).is_err());
}

#[test]
fn the_manifest_is_canonical_versioned_and_self_hashed() {
    let o = offline_base(false);
    three_uncovered(&o);
    let area = private_tempdir();
    let preserved = begin_with(&o.b, built(&o.sealer), area.path(), &mut no_hook).unwrap();
    let bytes = fs::read(preserved.dir.join("manifest.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["format_version"], 3);
    // Any change is found by the self-hash.
    value["created_at"] = 1.into();
    let edited = serde_json::to_vec(&value).unwrap();
    assert!(crate::native_rebootstrap_recovery::Manifest::from_bytes(&edited).is_err());
    assert!(crate::native_rebootstrap_recovery::Manifest::from_bytes(&bytes).is_ok());
    // Written twice, it is the same bytes.
    let manifest = crate::native_rebootstrap_recovery::Manifest::from_bytes(&bytes).unwrap();
    assert_eq!(manifest.to_bytes(), bytes);
    let _ = BTreeMap::<u8, u8>::new();
}

// --- durability is checked, not assumed ------------------------------------------------------------

/// Every file is fsynced before its name is published and its directory after.
#[test]
fn every_file_is_fsynced_and_so_is_its_directory() {
    use crate::native_rebootstrap_recovery::test_hooks::{DIR_SYNCS, FILE_SYNCS};
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    FILE_SYNCS.with(|n| n.set(0));
    DIR_SYNCS.with(|dirs| dirs.borrow_mut().clear());

    begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();

    let files = files_below(area.path()).iter().filter(|p| p.is_file()).count();
    assert!(files >= 7, "bundle, digest, material, record, version, delta and manifest: {files}");
    assert_eq!(FILE_SYNCS.with(|n| n.get()), files, "a file was not fsynced exactly once");
    assert!(
        DIR_SYNCS.with(|dirs| dirs.borrow().len()) >= files,
        "a directory was not fsynced after a rename"
    );
}

/// A copy that does not read back as written is found, not trusted: the machine is
/// blocked and the barrier does not hold.
#[test]
fn a_copy_that_does_not_read_back_blocks_the_barrier() {
    use crate::native_rebootstrap_recovery::test_hooks::CORRUPT_PATH_CONTAINING;
    for damaged in ["/versions/", "/deltas/", "target.bundle", "target.verification.json"] {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let area = private_tempdir();
        CORRUPT_PATH_CONTAINING.with(|t| *t.borrow_mut() = Some(damaged.to_owned()));

        let outcome = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook);

        CORRUPT_PATH_CONTAINING.with(|t| *t.borrow_mut() = None);
        assert!(matches!(outcome, Err(BeginError::Blocked(_))), "{damaged}: {outcome:?}");
        let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
        assert!(matches!(status.state, RebootstrapState::Blocked(_)), "{damaged}: {status:?}");
    }
}

/// Every name that leads to the area is flushed: the directories created for the
/// recovery root, the root, the group and the area itself, and the chain is
/// flushed once more last, after the manifest and before the barrier is declared.
#[test]
fn the_chain_of_directories_to_the_area_is_fsynced_before_the_barrier() {
    use crate::native_rebootstrap_recovery::test_hooks::DIR_SYNCS;
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let base = private_tempdir();
    let root = base.path().join("a").join("b").join("recovery");
    DIR_SYNCS.with(|dirs| dirs.borrow_mut().clear());

    let preserved = begin_with(&w.b, built(&w.sealer), &root, &mut no_hook).unwrap();

    let synced = DIR_SYNCS.with(|dirs| dirs.borrow().clone());
    let group_dir = preserved.dir.parent().unwrap().to_path_buf();
    for created in [
        base.path().to_path_buf(),
        base.path().join("a"),
        base.path().join("a").join("b"),
        root.clone(),
        group_dir.clone(),
        preserved.dir.clone(),
        preserved.dir.join("versions"),
        preserved.dir.join("deltas"),
        preserved.dir.join("verification-material"),
    ] {
        assert!(
            synced.contains(&created),
            "{} was never fsynced; synced {synced:?}",
            created.display()
        );
    }
    let tail = &synced[synced.len() - 4..];
    assert_eq!(
        tail,
        [preserved.dir.clone(), group_dir, root.clone(), root.parent().unwrap().to_path_buf()],
        "the whole chain must be flushed last, from the area up"
    );
}

/// An fsync that fails is an error, not a count: the file is not trusted, the
/// machine is blocked, and the next attempt starts a fresh area.
#[test]
fn a_failed_fsync_blocks_and_the_next_attempt_uses_a_fresh_area() {
    use crate::native_rebootstrap_recovery::test_hooks::FAIL_FILE_SYNC_CONTAINING;
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let area = private_tempdir();
    FAIL_FILE_SYNC_CONTAINING.with(|t| *t.borrow_mut() = Some("/versions/".into()));

    let first = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook);

    FAIL_FILE_SYNC_CONTAINING.with(|t| *t.borrow_mut() = None);
    assert!(matches!(first, Err(BeginError::Blocked(_))), "{first:?}");
    let blocked = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert!(matches!(blocked.state, RebootstrapState::Blocked(_)), "{blocked:?}");

    let second = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook).unwrap();
    assert_ne!(second.recovery_id, blocked.recovery_id, "the failed area must not be reused");
    assert_eq!(recovery_dirs_of(area.path()).len(), 1, "the failed area is swept");
}

// --- the pieces the barrier relies on, each exercised ---------------------------------------------

pub(super) fn preserved_area(w: &Scenario, root: &Path) -> (Preserved, RecoveryArea) {
    let preserved = begin_with(&w.b, built(&w.sealer), root, &mut no_hook).unwrap();
    let area = RecoveryArea::open_dir(&preserved.dir).unwrap();
    (preserved, area)
}

/// A temporary file left by an interrupted write is removed when the machine
/// resumes, wherever in the area it was.
#[test]
fn temporaries_left_by_an_interrupted_write_are_removed_on_resume() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (preserved, _) = preserved_area(&w, root.path());
    let leftovers: Vec<PathBuf> = ["", "versions", "deltas", "verification-material"]
        .iter()
        .map(|sub| preserved.dir.join(sub).join(".tmp-0123456789abcdef"))
        .collect();
    for leftover in &leftovers {
        fs::write(leftover, b"half a file").unwrap();
    }

    recover_after_restart(&w.b, root.path(), &group()).unwrap();

    for leftover in &leftovers {
        assert!(!leftover.exists(), "{} survived the resume", leftover.display());
    }
}

/// The area is the user's data: a file that is readable by others, or a root that
/// is, is not trusted.
#[cfg(unix)]
#[test]
fn an_area_that_is_not_private_is_not_trusted() {
    use std::os::unix::fs::PermissionsExt;
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (preserved, area) = preserved_area(&w, root.path());

    let manifest = preserved.dir.join("manifest.json");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(area.read_manifest_bytes().is_err(), "a group-readable manifest was read");
    assert!(matches!(
        recover_after_restart(&w.b, root.path(), &group()).unwrap(),
        RestartOutcome::Blocked(BlockedReason::ManifestInconsistent { .. })
    ));
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();

    let loose = tempfile::tempdir().unwrap();
    fs::set_permissions(loose.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let created = RecoveryArea::create(loose.path(), &group(), &new_recovery_id(), &[]);
    assert!(created.is_err(), "an area was created under a recovery root that others can read");
}

/// The manifest lists each incarnation that authored an uncovered delta once.
#[test]
fn the_manifest_names_each_old_author_once() {
    let o = offline_base(false);
    three_uncovered(&o);
    let root = private_tempdir();
    let preserved = begin_with(&o.b, built(&o.sealer), root.path(), &mut no_hook).unwrap();
    let manifest = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap().manifest;
    assert_eq!(manifest.deltas.len(), 3);
    assert_eq!(manifest.old_authors, vec![o.b1.clone()], "{:?}", manifest.old_authors);
}

/// A manifest whose parts disagree with each other is refused even though it is
/// correctly self-hashed.
#[test]
fn a_manifest_with_dangling_references_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (_, area) = preserved_area(&w, root.path());
    let good = area.read_intent().unwrap().manifest;
    let bytes_of = |edit: &dyn Fn(&mut crate::native_rebootstrap_recovery::Manifest)| {
        let mut manifest = good.clone();
        edit(&mut manifest);
        manifest.to_bytes()
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("an item names an unknown delta", bytes_of(&|m| m.items[0].delta = DeltaHash([9; 32]))),
        ("an item names a unit that does not exist", bytes_of(&|m| m.items[0].unit = 99)),
        (
            "a put names a version that is not listed",
            bytes_of(&|m| m.items[0].put_version = Some(VersionHash([9; 32]))),
        ),
        ("a delta names a unit that does not exist", bytes_of(&|m| m.deltas[0].unit = 99)),
        ("the delta order omits a delta", bytes_of(&|m| m.delta_order.clear())),
        (
            "a unit names an unlisted delta",
            bytes_of(&|m| m.units[0].deltas = vec![DeltaHash([9; 32])]),
        ),
        ("a recovery id that is not one", bytes_of(&|m| m.recovery_id = "../escape".into())),
    ];
    assert!(crate::native_rebootstrap_recovery::Manifest::from_bytes(&good.to_bytes()).is_ok());
    for (why, bytes) in cases {
        assert!(
            crate::native_rebootstrap_recovery::Manifest::from_bytes(&bytes).is_err(),
            "{why}: the manifest was accepted"
        );
    }
}

/// Creating the area flushes the entry of every directory it creates in that
/// directory's parent, ancestors of the recovery root included.
#[test]
fn creating_the_area_flushes_each_created_directory_in_its_parent() {
    use crate::native_rebootstrap_recovery::test_hooks::DIR_SYNCS;
    let base = private_tempdir();
    let root = base.path().join("a").join("b").join("recovery");
    DIR_SYNCS.with(|dirs| dirs.borrow_mut().clear());

    let area = RecoveryArea::create(&root, &group(), &new_recovery_id(), &[]).unwrap();

    let synced = DIR_SYNCS.with(|dirs| dirs.borrow().clone());
    let group_dir = area.dir().parent().unwrap().to_path_buf();
    for parent in [
        base.path().to_path_buf(),
        base.path().join("a"),
        base.path().join("a").join("b"),
        root.clone(),
        group_dir,
    ] {
        assert!(
            synced.contains(&parent),
            "{} gained an entry that was never flushed",
            parent.display()
        );
    }
}

// --- the area is the one the journal recorded ---------------------------------------------------------

/// A second, different, valid target.
fn other_stored_target() -> crate::native_rebootstrap_target::StoredTarget {
    let other = scenario(|b1, h1| vec![put_op("x", 3, vec![rem(b1, 1, h1)])]);
    verify_and_prepare_target(built(&other.sealer), &group(), &Policy).unwrap().1
}

/// Replaces the stored target of `area` with `other`, keeping the area
/// self-consistent: the digest, the record, the material and the manifest's
/// references to them all agree. `claims_checkpoint` is what the manifest says
/// the target is.
fn swap_in_target(
    area: &RecoveryArea,
    other: &crate::native_rebootstrap_target::StoredTarget,
    claims_checkpoint: Option<[u8; 32]>,
) -> crate::native_rebootstrap_recovery::Manifest {
    let mut manifest = area.read_intent().unwrap().manifest;
    area.write_target_bundle(&other.bundle).unwrap();
    area.write_verification_record(&other.record).unwrap();
    area.write_material(&other.material).unwrap();
    manifest.target_bundle_sha256 = other.bundle_sha256;
    manifest.target_bundle_size = other.bundle.len() as u64;
    manifest.verification_record_sha256 = sha256(&other.record);
    manifest.material_sha256 = sha256(&other.material);
    if let Some(hash) = claims_checkpoint {
        manifest.target_checkpoint_hash = hash;
    }
    area.write_manifest(&manifest).unwrap();
    manifest
}

fn blocked_as_inconsistent(c: &Connection, root: &Path) -> bool {
    matches!(
        recover_after_restart(c, root, &group()).unwrap(),
        RestartOutcome::Blocked(BlockedReason::ManifestInconsistent { .. })
    )
}

/// A manifest that agrees with the files around it but is not the one the barrier
/// recorded is refused.
#[test]
fn a_self_consistent_manifest_the_barrier_did_not_record_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (_, area) = preserved_area(&w, root.path());
    let mut manifest = area.read_intent().unwrap().manifest;
    manifest.created_at += 1;
    area.write_manifest(&manifest).unwrap();
    assert!(area.read_intent().is_ok(), "the swapped area must agree with itself");

    assert!(blocked_as_inconsistent(&w.b, root.path()));
}

/// A whole different target, internally consistent, named by the manifest and by
/// the journal's checkpoint, is still not the bundle the journal recorded.
#[test]
fn a_self_consistent_bundle_the_journal_did_not_record_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (_, area) = preserved_area(&w, root.path());
    let other = other_stored_target();
    let manifest = swap_in_target(&area, &other, Some(other.checkpoint_hash));
    // Everything but the journal's record of the bundle agrees with the swap.
    w.b.execute(
        "UPDATE native_rebootstrap_journal SET manifest_sha256 = ?1, target_checkpoint_hash = ?2",
        (sha256(&manifest.to_bytes()).as_slice(), other.checkpoint_hash.as_slice()),
    )
    .unwrap();

    assert!(blocked_as_inconsistent(&w.b, root.path()));
}

/// A different target whose manifest still claims the journal's checkpoint, and
/// whose digests the journal was made to agree with, is found by verifying it.
#[test]
fn a_stored_target_that_is_not_the_checkpoint_the_journal_names_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let (_, area) = preserved_area(&w, root.path());
    let other = other_stored_target();
    let manifest = swap_in_target(&area, &other, None);
    w.b.execute(
        "UPDATE native_rebootstrap_journal SET manifest_sha256 = ?1, target_bundle_sha256 = ?2",
        (sha256(&manifest.to_bytes()).as_slice(), other.bundle_sha256.as_slice()),
    )
    .unwrap();

    assert!(
        blocked_as_inconsistent(&w.b, root.path()),
        "a stored target of another checkpoint was accepted"
    );
}

// --- the own log must be what the replica authored ----------------------------------------------------

fn blocked_unavailable(outcome: &Result<Preserved, BeginError>) -> bool {
    matches!(outcome, Err(BeginError::Blocked(BlockedReason::LocalIntentUnavailable { .. })))
}

/// A row missing from the middle of an uncovered range is a chain the replica
/// cannot preserve whole: the target is not installable.
#[test]
fn a_gap_in_the_uncovered_own_log_blocks_the_target() {
    let o = offline_base(false);
    three_uncovered(&o);
    o.b.execute("DELETE FROM native_delta_log WHERE seq = 2", []).unwrap();
    let root = private_tempdir();

    let outcome = begin_with(&o.b, built(&o.sealer), root.path(), &mut no_hook);

    assert!(blocked_unavailable(&outcome), "{outcome:?}");
    assert!(files_below(root.path()).iter().all(|p| p.is_dir()), "no file may be written");
}

/// The log ends before the position the replica's own frontier records: the tail
/// of what it authored is gone.
#[test]
fn a_log_that_ends_before_the_authored_position_blocks_the_target() {
    let o = offline_base(false);
    three_uncovered(&o);
    o.b.execute("DELETE FROM native_delta_log WHERE seq = 3", []).unwrap();
    let root = private_tempdir();

    let outcome = begin_with(&o.b, built(&o.sealer), root.path(), &mut no_hook);

    assert!(blocked_unavailable(&outcome), "{outcome:?}");
}

/// A row above the recorded position is not something the replica authored.
#[test]
fn a_log_row_above_the_authored_position_blocks_the_target() {
    let o = offline_base(false);
    three_uncovered(&o);
    o.b.execute("UPDATE native_author_frontier SET seq = 2 WHERE seq = 3", []).unwrap();
    let root = private_tempdir();

    let outcome = begin_with(&o.b, built(&o.sealer), root.path(), &mut no_hook);

    assert!(blocked_unavailable(&outcome), "{outcome:?}");
}

/// The target's position names a row the log does not keep, and nothing says the
/// row was discarded below the replica's floor: the tip cannot be compared with
/// the target's, so it is not known that the incarnation did not fork.
#[test]
fn a_target_position_the_log_cannot_vouch_for_blocks_the_target() {
    let o = offline_base(false);
    let [d1, d2, _] = three_uncovered(&o);
    // The sealer holds B1 up to seq 2.
    for d in [&d1, &d2] {
        publish(&o.sealer, &o.b1, &device_key(2), d.clone());
    }
    o.b.execute("DELETE FROM native_delta_log WHERE seq = 2", []).unwrap();
    let root = private_tempdir();

    let outcome = begin_with(&o.b, built(&o.sealer), root.path(), &mut no_hook);

    assert!(blocked_unavailable(&outcome), "{outcome:?}");

    // The same log is fine once the replica's own floor says rows up to seq 2 were
    // discarded.
    o.b.execute(
        "INSERT INTO native_history_floor (group_id, checkpoint_id, floor_frontier_root, \
         adopted_at_unixtime) VALUES (?1, X'01', X'02', 0)",
        [group().as_str()],
    )
    .unwrap();
    o.b.execute(
        "INSERT INTO native_checkpoint_frontier (group_id, checkpoint_id, author, incarnation, \
         closed, seq, tip) VALUES (?1, X'01', ?2, ?3, 0, 2, ?4)",
        (
            group().as_str(),
            o.b1.device.as_str(),
            o.b1.incarnation.0.as_slice(),
            d2.delta_hash().0.as_slice(),
        ),
    )
    .unwrap();
    let plan = uncovered_own_deltas(
        &o.b,
        &group(),
        &device_b(),
        &verify_native_bootstrap(built(&o.sealer), &group(), &Policy).unwrap().frontier().clone(),
    )
    .unwrap();
    assert_eq!(plan.len(), 1, "only seq 3 is uncovered");
}

// --- resuming, replacing and blocking never lose or leak an area -----------------------------------

/// A delta written past the freeze makes what was preserved stale. Resuming the
/// barrier does not hide it and does not silently plan again: the barrier is
/// blocked, nothing is swept, and an explicit discard lets the same target be
/// planned again under a new recovery id.
#[test]
fn a_write_past_the_freeze_blocks_the_resume_until_the_barrier_is_discarded() {
    let o = offline_base(false);
    let [_, _, d3] = three_uncovered(&o);
    let root = private_tempdir();
    let bundle = built(&o.sealer);
    let first = begin_with(&o.b, bundle.clone(), root.path(), &mut no_hook).unwrap();

    let d4 = signed(&o.b1, 4, Some(d3.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish_past_the_freeze(&o.b, &o.b1, &device_key(2), d4);
    let stale = begin_with(&o.b, bundle.clone(), root.path(), &mut no_hook);

    assert!(
        matches!(stale, Err(crate::native_rebootstrap::BeginError::Blocked(_))),
        "the stale barrier was resumed: {stale:?}"
    );
    assert_eq!(recovery_dirs_of(root.path()), vec![first.dir.clone()], "the area was swept");
    assert!(crate::native_rebootstrap::discard_blocked_rebootstrap(&o.b, root.path(), &group())
        .unwrap());

    let again = begin_with(&o.b, bundle, root.path(), &mut no_hook).unwrap();
    assert_ne!(again.recovery_id, first.recovery_id);
    let manifest = RecoveryArea::open_dir(&again.dir).unwrap().read_intent().unwrap().manifest;
    assert_eq!(manifest.deltas.len(), 4);
    assert_eq!(recovery_dirs_of(root.path()), vec![again.dir.clone()]);
}

/// A capture pass that did not complete is not hidden by resuming: the barrier is
/// reported incomplete and the preserved area is left as it was.
#[test]
fn a_partial_capture_blocks_a_resume_and_leaves_the_barrier_alone() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let bundle = built(&w.sealer);
    let first = begin_with(&w.b, bundle.clone(), root.path(), &mut no_hook).unwrap();
    let setup = Setup {
        capture: CaptureBarrier::Partial { detail: "unreadable directory".into() },
        ..Setup::default()
    };

    let outcome = begin_custom(&w.b, bundle, root.path(), &setup, &mut no_hook);

    assert!(matches!(
        outcome,
        Err(BeginError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { .. }
        )))
    ));
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert_eq!(status.state, RebootstrapState::Preserved);
    assert_eq!(recovery_dirs_of(root.path()), vec![first.dir]);
}

/// Another sealer state, newer than the first.
fn newer_bundle(w: &Scenario) -> NativeBootstrap {
    let c = incarnation_of("device-c", 1);
    publish(&w.sealer, &c, &device_key(3), signed(&c, 1, None, vec![put_op("w", 5, Vec::new())]));
    built(&w.sealer)
}

/// A crash while a new target is being preserved leaves neither the half-written
/// area nor the complete area it was replacing.
#[test]
fn a_crash_while_replacing_a_target_leaks_no_area() {
    for point in [Failpoint::BeforeManifest, Failpoint::AfterManifest] {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let root = private_tempdir();
        begin_with(&w.b, built(&w.sealer), root.path(), &mut no_hook).unwrap();
        let newer = newer_bundle(&w);

        let outcome = begin_with(&w.b, newer, root.path(), &mut crash_at(point));

        assert!(matches!(outcome, Err(BeginError::Crashed)), "{point:?}: {outcome:?}");
        let restart = recover_after_restart(&w.b, root.path(), &group()).unwrap();
        assert!(matches!(restart, RestartOutcome::Abandoned { .. }), "{point:?}: {restart:?}");
        assert!(recovery_dirs_of(root.path()).is_empty(), "{point:?}: an area leaked");
        assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None);
    }
}

/// A crash after the new barrier holds but before the replaced area is swept: the
/// restart sweeps it.
#[test]
fn a_crash_after_the_new_barrier_still_sweeps_the_area_it_replaced() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    begin_with(&w.b, built(&w.sealer), root.path(), &mut no_hook).unwrap();
    let newer = newer_bundle(&w);

    let outcome = begin_with(&w.b, newer, root.path(), &mut crash_at(Failpoint::AtPreserved));

    assert!(matches!(outcome, Err(BeginError::Crashed)));
    assert_eq!(recovery_dirs_of(root.path()).len(), 2, "both areas exist at the crash");
    let restart = recover_after_restart(&w.b, root.path(), &group()).unwrap();
    let RestartOutcome::Preserved(kept) = restart else { panic!("{restart:?}") };
    assert_eq!(recovery_dirs_of(root.path()), vec![kept.dir], "the replaced area leaked");
}

/// A block never discards a complete area: the next attempt checks it again and
/// resumes it once it reads back; a damaged one stays until it is discarded on
/// purpose.
#[cfg(unix)]
#[test]
fn a_blocked_journal_keeps_its_complete_area_and_resumes_when_it_reads_back() {
    use std::os::unix::fs::PermissionsExt;
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let bundle = built(&w.sealer);
    let first = begin_with(&w.b, bundle.clone(), root.path(), &mut no_hook).unwrap();
    let manifest = first.dir.join("manifest.json");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(blocked_as_inconsistent(&w.b, root.path()), "the transient fault must block");

    let blocked = begin_with(&w.b, bundle.clone(), root.path(), &mut no_hook);
    assert!(matches!(blocked, Err(BeginError::Blocked(_))), "{blocked:?}");
    assert_eq!(recovery_dirs_of(root.path()), vec![first.dir.clone()], "the area was discarded");

    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let resumed = begin_with(&w.b, bundle, root.path(), &mut no_hook).unwrap();
    assert_eq!(resumed, first, "the area that read back again must be resumed, not replaced");

    // Only an explicit resolution discards one.
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(blocked_as_inconsistent(&w.b, root.path()));
    assert!(crate::native_rebootstrap::discard_blocked_rebootstrap(&w.b, root.path(), &group())
        .unwrap());
    assert!(recovery_dirs_of(root.path()).is_empty());
    assert_eq!(rebootstrap_status(&w.b, &group()).unwrap(), None);
}

/// A flip-flopping peer cannot make the replica start over: a candidate the
/// preserved target covers is not taken.
#[test]
fn a_candidate_the_preserved_target_covers_does_not_start_over() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let older = built(&w.sealer);
    let newer = newer_bundle(&w);
    let kept = begin_with(&w.b, newer, root.path(), &mut no_hook).unwrap();

    let outcome = begin_with(&w.b, older, root.path(), &mut no_hook);

    assert!(matches!(outcome, Err(BeginError::NotBetterThanCurrent)), "{outcome:?}");
    assert_eq!(recovery_dirs_of(root.path()), vec![kept.dir.clone()]);
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert_eq!(status.recovery_id, kept.recovery_id);
}

/// An area directory owned by another user is not trusted.
#[cfg(unix)]
#[test]
fn an_area_owned_by_another_user_is_refused() {
    let path = Path::new("/some/area");
    assert!(crate::native_rebootstrap_recovery::require_owner(501, 501, path).is_ok());
    assert!(crate::native_rebootstrap_recovery::require_owner(0, 501, path).is_err());
}

// --- the area alone holds every version record ------------------------------------------

/// A version with several blocks and an extended attribute: what the manifest's
/// basic metadata alone cannot reproduce.
fn rich_version() -> FileVersion {
    FileVersion::new(
        vec![
            VersionBlock { hash: BlockHash(vec![7; 32]), size: 3 },
            VersionBlock { hash: BlockHash(vec![8; 32]), size: 5 },
        ],
        8,
        FileMeta {
            mtime_unix_nanos: 77,
            unix_mode: Some(0o640),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: vec![("user.note".to_owned(), b"kept".to_vec())],
        },
    )
}

fn rich_area() -> (tempfile::TempDir, Preserved, FileVersion) {
    let rich = rich_version();
    let w = scenario(|b1, h1| {
        let mut op = put_op("x", 2, vec![rem(b1, 1, h1)]);
        op.put.as_mut().unwrap().version = rich.version_hash;
        vec![op]
    });
    crate::dag_store::put_file_version(&w.b, GROUP, &rich).unwrap();
    let root = private_tempdir();
    let preserved = begin_with(&w.b, built(&w.sealer), root.path(), &mut no_hook).unwrap();
    (root, preserved, rich)
}

#[test]
fn every_preserved_version_record_is_rebuilt_from_the_area_alone() {
    let (_root, preserved, rich) = rich_area();
    // The database and the sync root are gone: only the directory is read.
    let intent = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap();
    assert!(intent.manifest.versions.iter().any(|v| v.version == rich.version_hash));
    assert_eq!(intent.manifest.versions.len(), intent.records.len());
    for entry in &intent.manifest.versions {
        let record = &intent.records[&entry.version];
        assert_eq!(record.compute_hash(), entry.version, "a record does not hash to its version");
        assert_eq!(record.version_hash, entry.version);
    }
    let record = &intent.records[&rich.version_hash];
    assert_eq!(record, &rich, "block list and xattrs must survive");
}

#[test]
fn a_missing_or_altered_version_record_is_refused() {
    let (_root, preserved, rich) = rich_area();
    let path =
        preserved.dir.join("versions").join(format!("{}.record", hex::encode(rich.version_hash.0)));
    let good = fs::read(&path).unwrap();
    let area = RecoveryArea::open_dir(&preserved.dir).unwrap();
    assert!(area.read_intent().is_ok());

    let mut altered = good.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    fs::write(&path, &altered).unwrap();
    assert!(area.read_intent().is_err(), "a tampered record was accepted");

    fs::write(&path, &good).unwrap();
    assert!(area.read_intent().is_ok());
    fs::remove_file(&path).unwrap();
    assert!(area.read_intent().is_err(), "a missing record was accepted");
}

// --- a platform that cannot flush a directory entry --------------------------------------

#[test]
fn only_a_unix_platform_claims_directory_durability() {
    assert_eq!(
        crate::native_rebootstrap_recovery::platform_supports_directory_durability(),
        cfg!(unix)
    );
}

#[test]
fn a_platform_without_directory_durability_starts_nothing() {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            crate::native_rebootstrap_recovery::test_hooks::NO_DIRECTORY_DURABILITY
                .with(|flag| flag.set(false));
        }
    }
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let before = snapshot(&w.b);
    let area = private_tempdir();
    let _restore = Restore;
    crate::native_rebootstrap_recovery::test_hooks::NO_DIRECTORY_DURABILITY
        .with(|flag| flag.set(true));

    let outcome = begin_with(&w.b, built(&w.sealer), area.path(), &mut no_hook);

    assert!(
        matches!(outcome, Err(BeginError::Blocked(BlockedReason::DurabilityUnsupported))),
        "got {outcome:?}"
    );
    assert!(before == snapshot(&w.b), "a refused rebootstrap changed the native state");
    assert!(rebootstrap_status(&w.b, &group()).unwrap().is_none(), "a journal was started");
    assert!(files_below(area.path()).is_empty(), "something was written to the recovery root");
}

#[test]
fn the_windows_gate_stays_closed_until_validated_on_a_windows_host() {
    // Flipping this requires validating directory durability on a real Windows host.
    const { assert!(!crate::native_rebootstrap_recovery::WINDOWS_DIRECTORY_DURABILITY_VALIDATED) };
}

#[test]
fn a_durable_write_renames_then_flushes_the_directory_that_holds_the_new_name() {
    use crate::native_rebootstrap_recovery::{test_hooks::ORDER, write_durable};
    let dir = private_tempdir();
    ORDER.with(|o| o.borrow_mut().clear());
    write_durable(dir.path(), "final", b"bytes").unwrap();
    let order = ORDER.with(|o| o.borrow().clone());
    assert_eq!(order.len(), 2, "{order:?}");
    assert!(order[0].starts_with("rename:.tmp-") && order[0].ends_with("->final"), "{order:?}");
    assert_eq!(order[1], format!("syncdir:{}", dir.path().display()));
    assert_eq!(fs::read(dir.path().join("final")).unwrap(), b"bytes");
}
