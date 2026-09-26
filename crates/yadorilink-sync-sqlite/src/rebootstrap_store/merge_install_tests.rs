#![cfg(test)]
//! Committing a merge of two bases: the snapshot a minted base carries is
//! the namespace projection of the joined summary, it is installed with the
//! same atomic epoch reset a seal commits, and the active history above it
//! starts empty -- so two replicas that sealed apart end up on one base and
//! exchange ordinary changes again.

use super::base_install_tests::open;
use super::seal_namespace_tests::{kind_of, live_rows, project_tree, store_directories};
use super::seal_tests::{admit, delete, key, put, seal, store_versions, version, GROUP};
use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof, merkle_root,
    sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::ids::DeviceId;
use yadorilink_replica_domain::test_authoring::reset_author_sequences;
use yadorilink_replica_engine::namespace::{DirectoryNode, PhysicalNode, Placement};
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;

/// Publishes every retained change not yet published under one genuine
/// authorization checkpoint numbered `seq`. The same changes published
/// under the same number on two replicas carry the same evidence, as one
/// author's checkpoint does wherever it travels.
pub(super) fn publish(conn: &Connection, seq: u64) {
    let leaves: Vec<[u8; 32]> = {
        let mut stmt = conn
            .prepare(
                "SELECT c.change_hash FROM changes c WHERE c.group_id = ?1 AND NOT EXISTS \
                 (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash) \
                 ORDER BY c.change_hash",
            )
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0)).unwrap();
        rows.map(|row| row.unwrap().try_into().unwrap()).collect()
    };
    publish_leaves(conn, seq, leaves);
}

/// Publishes exactly `leaves` under one authorization checkpoint numbered
/// `seq`: the same set under the same number carries the same evidence on
/// every replica that publishes it.
pub(super) fn publish_leaves(conn: &Connection, seq: u64, mut leaves: Vec<[u8; 32]>) {
    leaves.sort();
    let checkpoint = AuthorizationCheckpoint {
        group_id: GROUP.to_string(),
        device_id: "device-a".to_string(),
        signing_key_fingerprint: [1; 32],
        merkle_root: merkle_root(&leaves),
        leaf_count: leaves.len() as u64,
        checkpoint_seq: seq,
        signer_key_id: [2; 32],
        policy_epoch: 1,
        policy_seq: 1,
        policy_head: [3; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, &SigningKey::from_bytes(&[42; 32]));
    let entries: Vec<(ChangeHash, Vec<u8>)> = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            (ChangeHash(*leaf), encode_merkle_proof(&build_merkle_proof(&leaves, index)))
        })
        .collect();
    crate::dag_store::published_view::attach_authorization_evidence(
        conn,
        &checkpoint_hash(&encoded, &signature),
        GROUP,
        "device-a",
        seq,
        &encoded,
        &signature,
        &[7; 32],
        &entries,
    )
    .unwrap();
}

/// The history both replicas share before they part: `A` writes `p`, and
/// `B`, having seen it, writes `q`.
struct Prefix {
    b1: Change,
}

fn shared_prefix(conn: &Connection) -> Prefix {
    reset_author_sequences();
    store_versions(conn);
    store_directories(conn);
    let a1 = admit(conn, "device-a", &[], vec![put("p", &version(1))]);
    let b1 = admit(conn, "device-b", &[&a1], vec![put("q", &version(2))]);
    publish(conn, 1);
    Prefix { b1 }
}

/// A replica that shares the prefix, wrote `after` on top of it, and
/// sealed.
fn sealed_replica(after: impl FnOnce(&Connection, &Prefix)) -> Connection {
    let conn = open();
    let prefix = shared_prefix(&conn);
    after(&conn, &prefix);
    publish(&conn, 2);
    project_tree(&conn);
    seal(&conn);
    conn
}

fn trust(device_id: &str) -> Option<[u8; 32]> {
    Some(key(device_id).verifying_key().to_bytes())
}

fn writers(group_id: &str, signer: &str, signing_key: &[u8; 32]) -> bool {
    group_id == GROUP && *signing_key == key(signer).verifying_key().to_bytes()
}

/// `conn`'s installed base as a peer receives it: signed by `signer`,
/// checked before anything of it is believed.
pub(super) fn as_returning(conn: &Connection, signer: &str) -> VerifiedBaseSummary {
    let side = verify_current_base(conn, GROUP).unwrap();
    let manifest = SnapshotManifest::new_signed(
        side.checkpoint().clone(),
        Vec::new(),
        None,
        DeviceId(signer.to_string()),
        &key(signer),
    )
    .unwrap();
    verify_returning_base(GROUP, &manifest, &side.snapshot().canonical_encoding(), &trust, &writers)
        .unwrap()
}

pub(super) fn merge(conn: &Connection, returning: &VerifiedBaseSummary) -> CommittedMerge {
    let tx = conn.unchecked_transaction().unwrap();
    let merged = commit_foreign_merge(&tx, returning).unwrap();
    tx.commit().unwrap();
    merged
}

fn merge_refused(conn: &Connection, returning: &VerifiedBaseSummary) -> ForeignMergeError {
    let tx = conn.unchecked_transaction().unwrap();
    let error = commit_foreign_merge(&tx, returning).expect_err("the merge is refused");
    drop(tx);
    error
}

fn retained(conn: &Connection) -> usize {
    seal::retained_change_hashes(conn, GROUP).unwrap().len()
}

fn minted(merged: &CommittedMerge) -> HistoryBase {
    match merged.base {
        MergedBase::Minted(base) => base,
        other => panic!("expected a minted base, got {other:?}"),
    }
}

/// Every live row's authoring change has evidence here, so every version
/// the base carries is served.
fn assert_every_live_row_is_published(conn: &Connection) {
    let mut stmt = conn
        .prepare(
            "SELECT path, authoring_change_hash FROM files \
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0",
        )
        .unwrap();
    let rows = stmt
        .query_map([GROUP], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))
        .unwrap();
    for row in rows {
        let (path, author) = row.unwrap();
        let author = ChangeHash(author.try_into().unwrap());
        assert!(
            crate::dag_store::published_view::is_published(conn, &author).unwrap(),
            "{path}'s author {} has no evidence here",
            author.to_hex()
        );
    }
}

/// Two replicas that minted one base hold one base: the same checkpoint,
/// committing to byte-identical snapshots. The minted base id covers the
/// summary but not the snapshot, so nothing else would notice two replicas
/// serving different snapshots under one base.
fn assert_one_merged_base(left: &Connection, right: &Connection) {
    let (left, right) =
        (verify_current_base(left, GROUP).unwrap(), verify_current_base(right, GROUP).unwrap());
    assert!(
        left.snapshot().snapshot_hash() == right.snapshot().snapshot_hash(),
        "both replicas built the same snapshot for the minted base"
    );
    assert_eq!(left.checkpoint(), right.checkpoint(), "both replicas hold the same checkpoint");
}

/// Two replicas share a history, each writes a path the other has not
/// seen, and each seals. Each merges the other's base: both install the
/// same minted base over both writes, retain no change, and serve every row
/// the base carries -- including the rows written by the changes each side
/// sealed as its frontier, whose bodies neither keeps.
#[test]
fn two_replicas_that_sealed_apart_install_one_minted_base() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let from_left = as_returning(&left, "device-d");
    let from_right = as_returning(&right, "device-e");

    let at_left = merge(&left, &from_right);
    let at_right = merge(&right, &from_left);

    assert_eq!(at_left.order, SummaryOrder::Incomparable);
    let base = minted(&at_left);
    assert_eq!(minted(&at_right), base, "both replicas found the same base");
    for conn in [&left, &right] {
        assert_eq!(history_base(conn, GROUP).unwrap(), Some(base));
        assert_eq!(retained(conn), 0, "the active history restarts empty");
        let side = verify_current_base(conn, GROUP).unwrap();
        assert_eq!(side.history_base(), base, "the installed base verifies as this side");
        assert_every_live_row_is_published(conn);
    }
    assert_eq!(
        verify_current_base(&left, GROUP).unwrap().summary_identity(),
        verify_current_base(&right, GROUP).unwrap().summary_identity()
    );
    assert_one_merged_base(&left, &right);
    let rows = live_rows(&left);
    assert_eq!(rows, live_rows(&right), "both replicas hold the same rows");
    assert_eq!(
        rows.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["p", "q", "s", "t"],
        "both writes and the shared history survive"
    );
    let advertised = crate::base_advertisement::local_base_advertisement(&left, GROUP).unwrap();
    assert!(
        as_returning(&left, "device-d").matches_advertisement(&advertised.base),
        "the minted base is advertised as the checkpoint that derives it"
    );
}

/// Above a minted base every author continues from the position the base
/// carries, on the new epoch, from the base's Lamport ceiling, naming no
/// predecessor -- and a replica that installed the same base admits it.
#[test]
fn the_history_above_a_minted_base_is_exchanged_as_ordinary_changes() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let (from_left, from_right) =
        (as_returning(&left, "device-d"), as_returning(&right, "device-e"));
    let base = minted(&merge(&left, &from_right));
    merge(&right, &from_left);
    let summary = history_base_summary(&left, GROUP).unwrap().unwrap();

    store_versions(&left);
    let next = crate::dag_store::emit_local_change(
        &left,
        GROUP,
        vec![put("u", &version(7))],
        &ChangeEmitter::new("device-a", key("device-a")),
    )
    .unwrap();

    assert_eq!(next.history_epoch, HistoryEpoch::Base(base));
    assert!(next.parents.is_empty(), "the first change above the base is a root");
    assert_eq!(next.author_prev, None);
    assert_eq!(
        Some(next.author_seq.get()),
        summary.author_watermark("device-a").map(|s| s.get() + 1)
    );
    assert_eq!(next.lamport, summary.lamport_ceiling + 1);
    store_versions(&right);
    let outcome = crate::dag_store::admit_change(&right, &next).unwrap().outcome;
    assert!(matches!(outcome, crate::dag_store::AdmitOutcome::Applied), "got {outcome:?}");
}

/// A replica whose history one side already holds adopts that side's
/// minted base as it is -- the base another replica minted, installed by
/// its signed manifest -- rather than minting yet another. The minting
/// replica, handed the adopter's older base, keeps its own.
#[test]
fn a_replica_holding_one_side_adopts_the_minted_base() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let behind = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let base = minted(&merge(&left, &as_returning(&right, "device-e")));

    let adopted = merge(&behind, &as_returning(&left, "device-d"));

    assert_eq!(adopted.order, SummaryOrder::ReturningAbsorbsCurrent);
    assert_eq!(adopted.base, MergedBase::Returning(base));
    assert_eq!(history_base(&behind, GROUP).unwrap(), Some(base));
    assert_eq!(live_rows(&behind), live_rows(&left));
    assert_eq!(retained(&behind), 0);
    assert_every_live_row_is_published(&behind);

    let kept = merge(&left, &as_returning(&right, "device-e"));
    assert_eq!(kept.order, SummaryOrder::CurrentAbsorbsReturning);
    assert_eq!(kept.installed, None, "nothing is installed over a base that holds both");
    assert_eq!(history_base(&left, GROUP).unwrap(), Some(base));
}

/// A file `a` on one side and `a/x` on the other come together only in
/// the join. The merged base's rows are the join's namespace projection:
/// `a` is a directory holding `a/x`, and the file sits at its copy name,
/// where a joiner reads it back as `a`'s head.
#[test]
fn a_file_and_a_descendant_from_two_sides_are_placed_as_the_join_projects_them() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("a", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("a/x", &version(6))]);
    });

    minted(&merge(&left, &as_returning(&right, "device-e")));

    let projection = history_base_summary(&left, GROUP).unwrap().unwrap().project(kind_of(&left));
    let projection = projection.unwrap();
    assert!(matches!(
        projection.get("a"),
        Some(PhysicalNode::Directory(DirectoryNode::Structural))
    ));
    let relocated: Vec<&String> = projection
        .nodes()
        .iter()
        .filter(|(_, node)| {
            matches!(node, PhysicalNode::Entry(entry)
                if entry.placement == Placement::Relocated && entry.source == "a")
        })
        .map(|(name, _)| name)
        .collect();
    assert_eq!(relocated.len(), 1);
    let rows = live_rows(&left);
    assert_eq!(rows.get("a"), None, "a structural directory holds no row");
    assert_eq!(rows.get("a/x"), Some(&version(6).version_hash));
    assert_eq!(rows.get(relocated[0]), Some(&version(5).version_hash));
}

/// Both sides wrote `q` after the shared history: two concurrent heads,
/// the winner at `q` and the loser at its conflict copy -- the same rows
/// from either side.
#[test]
fn concurrent_writes_from_two_sides_keep_a_winner_and_a_conflict_copy() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("q", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("q", &version(6))]);
    });
    let (from_left, from_right) =
        (as_returning(&left, "device-d"), as_returning(&right, "device-e"));

    merge(&left, &from_right);
    merge(&right, &from_left);

    assert_one_merged_base(&left, &right);
    let rows = live_rows(&left);
    assert_eq!(rows, live_rows(&right));
    let held: Vec<VersionHash> =
        rows.iter().filter(|(path, _)| path.starts_with('q')).map(|(_, v)| *v).collect();
    assert_eq!(held.len(), 2, "a winner and a copy: {rows:?}");
    assert!(held.contains(&version(5).version_hash) && held.contains(&version(6).version_hash));
}

/// The other side deleted `p` after seeing its write -- without ever
/// holding a row for it -- and wrote nothing else there. The join drops
/// `p`'s head, so the merged base places nothing at `p`; its content stays
/// as history, and the path is held until the reconciliation pass has
/// removed the stale object still on disk under it.
#[test]
fn a_path_the_other_side_deleted_is_removed_by_the_merge() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![delete("p")]);
    });

    minted(&merge(&left, &as_returning(&right, "device-e")));

    assert_eq!(live_rows(&left).get("p"), None);
    let states: Vec<(String, bool)> = {
        let mut stmt = left
            .prepare(
                "SELECT state, deleted FROM files WHERE group_id = ?1 AND path = 'p' \
                 ORDER BY version_seq",
            )
            .unwrap();
        let rows = stmt
            .query_map([GROUP], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0)))
            .unwrap();
        rows.map(Result::unwrap).collect()
    };
    assert!(
        !states.iter().any(|(state, deleted)| state == "current" && !deleted),
        "nothing live is left at p: {states:?}"
    );
    assert!(
        states.iter().any(|(state, deleted)| state == "superseded" && !deleted),
        "p's content stays as history: {states:?}"
    );
    let held: bool = left
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshot_install_holds WHERE group_id = ?1 AND path = 'p')",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert!(held, "the disk still holds p's old content until it is reconciled");
}

/// A change admitted after this replica's side was verified is history
/// above the base the merge would replace, so the commit re-verifies and
/// refuses rather than leaving that change behind.
#[test]
fn history_written_after_the_merge_was_planned_refuses_the_commit() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let before = history_base(&left, GROUP).unwrap();
    let returning = as_returning(&right, "device-e");
    store_versions(&left);
    crate::dag_store::emit_local_change(
        &left,
        GROUP,
        vec![put("u", &version(7))],
        &ChangeEmitter::new("device-a", key("device-a")),
    )
    .unwrap();

    let error = merge_refused(&left, &returning);

    assert!(
        matches!(error, ForeignMergeError::Refused(ForeignMergeRefusal::HistoryAboveBase)),
        "got {error:?}"
    );
    assert_eq!(history_base(&left, GROUP).unwrap(), before);
}

/// A row neither side can vouch for is not carried into a base this
/// replica would then hold and never serve: the merge is refused with
/// nothing written.
#[test]
fn a_row_whose_evidence_no_side_carries_refuses_the_merge() {
    let left = sealed_replica(|conn, prefix| {
        admit(conn, "device-d", &[&prefix.b1], vec![put("s", &version(5))]);
    });
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let side = verify_current_base(&right, GROUP).unwrap();
    let t_author = side
        .snapshot()
        .files
        .iter()
        .find(|file| file.record.path == "t")
        .and_then(|file| file.authoring_change_hash)
        .unwrap();
    // `t`'s author is the frontier change the sealer carried as a body;
    // its witness is what a replica that keeps no body serves `t` by.
    assert!(side.checkpoint().frontier.contains(&t_author));
    let mut parts = side.snapshot().clone();
    parts.published_change_witnesses.retain(|witness| witness.change_hash != t_author);
    let stripped = RebootstrapSnapshot::new(
        parts.group_id,
        parts.files,
        parts.frontier_changes,
        parts.file_versions,
        parts.published_change_witnesses,
        parts.boundary_parent_auth,
        parts.author_state,
        parts.path_heads,
        parts.lamport_ceiling,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(
        side.checkpoint().group_id.clone(),
        side.checkpoint().frontier.clone(),
        stripped.snapshot_hash(),
    );
    let manifest = SnapshotManifest::new_signed(
        checkpoint,
        Vec::new(),
        None,
        DeviceId("device-e".to_string()),
        &key("device-e"),
    )
    .unwrap();
    let returning =
        verify_returning_base(GROUP, &manifest, &stripped.canonical_encoding(), &trust, &writers)
            .unwrap();
    let before = history_base(&left, GROUP).unwrap();

    let error = merge_refused(&left, &returning);

    assert!(
        matches!(
            error,
            ForeignMergeError::Refused(ForeignMergeRefusal::EvidenceNotCarried { ref path, change })
                if path == "t" && change == t_author
        ),
        "got {error:?}"
    );
    assert_eq!(history_base(&left, GROUP).unwrap(), before);
}

/// A head the base carries is evidence it has to carry too, even when no
/// row names it. A base
/// missing that witness is refused as evidence not carried, before
/// anything is written, not left to fail later inside the install.
#[test]
fn a_head_whose_evidence_the_base_does_not_carry_refuses_the_install() {
    let sealed = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let side = verify_current_base(&sealed, GROUP).unwrap();
    let head = side
        .snapshot()
        .path_heads
        .iter()
        .find(|head| head.path == "t")
        .cloned()
        .expect("t's writer is its head");
    // `t`'s row names the same change; a row that names no
    // author leaves the head as the only thing that needs its witness, so
    // the row check cannot answer for the head check.
    let mut parts = side.snapshot().clone();
    for file in &mut parts.files {
        if file.authoring_change_hash == Some(head.change_hash) {
            file.authoring_change_hash = None;
        }
    }
    parts.published_change_witnesses.retain(|witness| witness.change_hash != head.change_hash);
    let stripped = RebootstrapSnapshot::new(
        parts.group_id,
        parts.files,
        parts.frontier_changes,
        parts.file_versions,
        parts.published_change_witnesses,
        parts.boundary_parent_auth,
        parts.author_state,
        parts.path_heads,
        parts.lamport_ceiling,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(
        side.checkpoint().group_id.clone(),
        side.checkpoint().frontier.clone(),
        stripped.snapshot_hash(),
    );
    let fresh = open();
    let tx = fresh.unchecked_transaction().unwrap();

    let error = install_base_for_tests(&tx, &checkpoint, &stripped).expect_err("refused");

    assert!(
        matches!(
            error,
            ForeignMergeError::Refused(ForeignMergeRefusal::EvidenceNotCarried { ref path, change })
                if path == "t" && change == head.change_hash
        ),
        "got {error:?}"
    );
    drop(tx);
    assert_eq!(history_base(&fresh, GROUP).unwrap(), None);
}

/// `snapshot` re-signed by `signer` under a checkpoint that commits to it,
/// as an authorized signer could offer it.
fn re_signed(
    side: &VerifiedBaseSummary,
    snapshot: RebootstrapSnapshot,
    signer: &str,
) -> (SnapshotManifest, Vec<u8>) {
    let checkpoint = Checkpoint::new(
        side.checkpoint().group_id.clone(),
        side.checkpoint().frontier.clone(),
        snapshot.snapshot_hash(),
    );
    let manifest = SnapshotManifest::new_signed(
        checkpoint,
        Vec::new(),
        None,
        DeviceId(signer.to_string()),
        &key(signer),
    )
    .unwrap();
    (manifest, snapshot.canonical_encoding())
}

/// A base whose rows are not the namespace projection of its own `Gamma`
/// is refused as it arrives, however it is signed. Adopting it would
/// install rows that contradict the summary every author is anchored on,
/// and no later change would ever repair the difference: here `t` has a
/// live head and no row, so it would stay missing while the summary says
/// it exists.
#[test]
fn a_returning_base_whose_rows_contradict_its_summary_is_refused() {
    let right = sealed_replica(|conn, prefix| {
        admit(conn, "device-e", &[&prefix.b1], vec![put("t", &version(6))]);
    });
    let side = verify_current_base(&right, GROUP).unwrap();
    let mut parts = side.snapshot().clone();
    parts.files.retain(|file| file.record.path != "t");
    let dropped = RebootstrapSnapshot::new(
        parts.group_id,
        parts.files,
        parts.frontier_changes,
        parts.file_versions,
        parts.published_change_witnesses,
        parts.boundary_parent_auth,
        parts.author_state,
        parts.path_heads,
        parts.lamport_ceiling,
    )
    .unwrap();
    let (manifest, bytes) = re_signed(&side, dropped, "device-e");

    let refusal = verify_returning_base(GROUP, &manifest, &bytes, &trust, &writers)
        .expect_err("rows that contradict the summary are refused");

    assert!(
        matches!(
            refusal,
            ForeignMergeRefusal::SnapshotNotProjection(SealRefusal::WinnerNotMaterialized {
                ref path
            }) if path == "t"
        ),
        "got {refusal:?}"
    );
}
