#![cfg(test)]

use super::*;
use crate::dag_store::{group_heads, init_dag_schema, max_parent_lamport, put_file_version};
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::test_authoring::{create_signed_for_tests, next_author_position};

use yadorilink_replica_domain::file::FileMeta;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;

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
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
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
    let change = create_signed_for_tests(
        parents,
        max_parent_lamport,
        DeviceId(device_id.to_string()),
        FolderGroupId(group_id.to_string()),
        ops,
        signing_key,
    );
    let result = super::super::admit_change(conn, &change).unwrap();
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

/// Regression: a coincidental pre-existing file
/// at the EXACT deterministic conflict-copy path, created and deleted
/// entirely independently of this conflict (a sibling branch off the
/// same root, never touching the source path or descending from either
/// concurrent edit), must not suppress deriving the loser's real
/// conflict copy. An over-broad guard that treated ANY existing history
/// at the target path as "already handled" would silently drop the
/// loser instead.
#[test]
fn derive_still_provisions_a_loser_whose_target_path_has_unrelated_earlier_history() {
    let c = conn();
    let group = "g";
    let root_version = version(0);
    put_file_version(&c, group, &root_version).unwrap();
    let root =
        admit(&c, group, vec![], "device-root", &key(9), vec![put_op("shared.bin", &root_version)]);
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

/// Regression: an unrelated file still LIVE
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
    let root =
        admit(&c, group, vec![], "device-root", &key(9), vec![put_op("shared.bin", &root_version)]);
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
    let root =
        admit(&c, group, vec![], "device-root", &key(9), vec![put_op("shared.bin", &root_version)]);
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

/// A losing change that happens to touch the deterministic conflict
/// target for its OWN losing content must still have that content
/// preserved.
///
/// The "already acted on" suppression exists to stop a conflict copy the
/// user explicitly deleted from being resurrected by a late-joining
/// device. Its evidence has to be an action taken *after* the conflict
/// was resolved, which is what "descends from the loser" expresses. A
/// head that IS the loser itself is not such an action: whatever the
/// loser did at the target path, it did before (in fact, instead of)
/// preserving the content it was about to lose at the source path.
/// Treating it as evidence dropped the content outright -- no conflict
/// copy anywhere, nothing to rediscover, and every replica agreeing on
/// the result.
///
/// The shape below is an ordinary user action, not a contrivance. The
/// deterministic target name embeds the losing content's own hash, so
/// the loser can only land on it by putting or removing exactly the
/// content it is about to lose -- which is what "resolve a conflict by
/// keeping the conflicted copy" does: copy the conflicted copy's bytes
/// over the real file and delete the conflicted copy. Local capture
/// commits one debounce batch as ONE signed change, so both land in the
/// same change. If a peer edited the same file concurrently, that change
/// is the loser, and the content the user deliberately chose to keep is
/// the content at stake.
#[test]
fn derive_provisions_a_loser_that_itself_touches_its_own_conflict_target() {
    let c = conn();
    let group = "g";
    let root_version = version(0);
    put_file_version(&c, group, &root_version).unwrap();
    let root =
        admit(&c, group, vec![], "device-root", &key(9), vec![put_op("shared.bin", &root_version)]);
    let root_hash = root.compute_hash();

    // Both sides are parented on `root` and carry the same lamport, so
    // which one loses is decided by change hash alone -- not something a
    // test can choose up front. Search for a pair where the side that
    // also touches the target path is the loser: that is the case under
    // test, and the search makes it deterministic instead of a coin flip
    // that silently turns the test into a duplicate of the ordinary one.
    //
    // Each side's author sequence is reserved once, before the search, and
    // the candidate the search settles on is the very change that gets
    // admitted below. Re-signing it afterwards would re-draw the sequence
    // and with it the hash, leaving the search to have chosen a loser on a
    // change that never existed -- and then whether this test exercises its
    // own case would depend on what else ran first.
    let (seq_a, prev_a) =
        next_author_position(&FolderGroupId(group.into()), &DeviceId("device-a".into()));
    let (seq_b, prev_b) =
        next_author_position(&FolderGroupId(group.into()), &DeviceId("device-b".into()));
    let mut chosen = None;
    for nonce in 0..64i64 {
        let version_a = version(100 + nonce);
        let version_b = version(100_000 + nonce);
        // The target is a pure function of the path, the losing device
        // and the losing content -- never of the losing change's hash --
        // so it can be computed before the change that references it.
        let target_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            "device-a",
            0,
            &version_a.version_hash.0,
        );
        let ops_a = vec![
            put_op("shared.bin", &version_a),
            Op::Delete { path: SyncPath(target_path.clone()) },
        ];
        let change_a = Change::create_signed(
            vec![root_hash],
            root.lamport,
            DeviceId("device-a".into()),
            seq_a,
            prev_a,
            FolderGroupId(group.into()),
            HistoryEpoch::Genesis,
            ops_a.clone(),
            &key(1),
        );
        let change_b = Change::create_signed(
            vec![root_hash],
            root.lamport,
            DeviceId("device-b".into()),
            seq_b,
            prev_b,
            FolderGroupId(group.into()),
            HistoryEpoch::Genesis,
            vec![put_op("shared.bin", &version_b)],
            &key(2),
        );
        if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
            change_a.lamport,
            &change_a.compute_hash().0,
            change_b.lamport,
            &change_b.compute_hash().0,
        ) {
            chosen = Some((version_a, version_b, target_path, change_a, change_b));
            break;
        }
    }
    let (version_a, version_b, target_path, loser, winner) =
        chosen.expect("a losing device-a change exists within the search range");

    put_file_version(&c, group, &version_a).unwrap();
    put_file_version(&c, group, &version_b).unwrap();
    for change in [&loser, &winner] {
        let result = super::super::admit_change(&c, change).unwrap();
        assert_eq!(result.outcome, super::super::AdmitOutcome::Applied, "admission must succeed");
    }

    // A later local edit closes the fork, which is where obligations are
    // derived.
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

    assert_eq!(
        derived.len(),
        1,
        "the loser's own content must still be preserved at {target_path} (loser {}): {derived:?}",
        hex::encode(loser.compute_hash().0),
    );
    let Op::Put {
        path,
        version: derived_version,
        origin: PutOrigin::ConflictCopy { losing_change, .. },
    } = &derived[0]
    else {
        panic!("expected a ConflictCopy put, got {:?}", derived[0]);
    };
    assert_eq!(path.as_str(), target_path);
    assert_eq!(derived_version.0, version_a.version_hash.0);
    assert_eq!(*losing_change, loser.compute_hash());
}

/// A conflict copy is written by the emitting device, at a path its own
/// caller never named. That path may already hold a materialized basis --
/// here, the device last observed it empty -- and if the basis survives
/// the emission it still reads as current while naming a frontier the
/// copy has moved past. The device's next edit at that path would then be
/// parented beside its own copy rather than on it, leaving two heads of
/// one path by one author.
///
/// So the emission must retire the basis of every path it writes, derived
/// ones included, in the same transaction.
#[test]
fn a_derived_conflict_copy_retires_the_basis_of_the_path_it_writes() {
    let c = conn();
    let group = "g";
    let root_version = version(0);
    put_file_version(&c, group, &root_version).unwrap();
    let root =
        admit(&c, group, vec![], "device-root", &key(9), vec![put_op("shared.bin", &root_version)]);
    let (_, _, target_path) = seed_conflict(&c, group, root.compute_hash(), "shared.bin");

    let observed_at = group_heads(&c, group).unwrap();
    crate::materialized_generation::record_materialized_generation(
        &c,
        group,
        &target_path,
        &observed_at,
        crate::materialized_generation::MaterializedObjectKind::Absent,
        None,
        None,
        0,
    )
    .unwrap();

    let closing_version = version(300);
    put_file_version(&c, group, &closing_version).unwrap();
    let emitter = crate::dag_store::ChangeEmitter::new("device-local", key(4));
    let closing = crate::dag_store::emit_local_change(
        &c,
        group,
        vec![put_op("shared.bin", &closing_version)],
        &emitter,
    )
    .unwrap();
    assert!(
        closing.ops.iter().any(|op| matches!(
            op,
            Op::Put { path, origin: PutOrigin::ConflictCopy { .. }, .. }
                if path.as_str() == target_path
        )),
        "the emission must actually derive the copy at {target_path} for this to test anything"
    );

    let basis =
        crate::materialized_generation::lookup_materialized_generation(&c, group, &target_path)
            .unwrap()
            .map(|generation| {
                crate::dag_store::lookup_causal_basis_members(&c, &generation.causal_basis_id.0)
                    .unwrap()
                    .expect("an interned basis")
            });
    let closing_hash = closing.compute_hash();
    assert!(
        basis.as_ref().is_none_or(|members| members.contains(&closing_hash)),
        "the copy at {target_path} was written by {}, yet the path's basis still reads as \
         current and names only {:?}",
        closing_hash.to_hex(),
        basis.map(|m| m.iter().map(|h| h.to_hex()).collect::<Vec<_>>()),
    );
}

/// A symlink version, distinct per `target`.
fn symlink_version(target: &str) -> yadorilink_replica_domain::file::FileVersion {
    yadorilink_replica_domain::file::FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: Some(target.as_bytes().to_vec()),
            record_kind: RecordKind::Symlink,
            xattrs: Vec::new(),
        },
    )
}

/// Two concurrent heads at `a`, `high` ranking above `low` by lamport
/// (a filler change under `high` raises it), so the per-path winner is
/// fixed whatever the change hashes are. Returns the group's heads.
fn concurrent_at_a(
    c: &Connection,
    group: &str,
    high: &yadorilink_replica_domain::file::FileVersion,
    low: &yadorilink_replica_domain::file::FileVersion,
) -> Vec<ChangeHash> {
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    put_file_version(c, group, high).unwrap();
    put_file_version(c, group, low).unwrap();
    let filler_version = version(900);
    put_file_version(c, group, &filler_version).unwrap();
    let filler =
        admit(c, group, vec![], "device-high", &key(1), vec![put_op("filler", &filler_version)]);
    let high_change = admit(
        c,
        group,
        vec![filler.compute_hash()],
        "device-high",
        &key(1),
        vec![put_op("a", high)],
    );
    let low_change = admit(c, group, vec![], "device-low", &key(2), vec![put_op("a", low)]);
    assert!(high_change.lamport > low_change.lamport);
    group_heads(c, group).unwrap()
}

/// DIR-1: an ExplicitDirectory at a path keeps the path and a File or
/// Symlink there moves to its copy name, whichever ranks higher. So when
/// the File or Symlink wins the per-path rank it is the one owed a copy
/// (the projection has already relocated it there), and the Directory is
/// owed none: an empty directory's copy carries nothing. An op that
/// supersedes both heads at the path -- the user removing or re-capturing
/// the directory -- must carry that copy, or the File's content is gone.
#[test]
fn a_file_or_symlink_that_outranks_a_directory_is_owed_its_copy_and_the_directory_none() {
    for leaf in [version(100), symlink_version("t")] {
        let directory = yadorilink_replica_domain::file::FileVersion::directory(Some(0o755));
        for touch in [
            Op::Delete { path: SyncPath("a".into()) },
            put_op("a", &yadorilink_replica_domain::file::FileVersion::directory(Some(0o700))),
        ] {
            let c = conn();
            let group = "g";
            let heads = concurrent_at_a(&c, group, &leaf, &directory);
            if let Op::Put { version, .. } = &touch {
                put_file_version(
                    &c,
                    group,
                    &yadorilink_replica_domain::file::FileVersion::directory(Some(0o700)),
                )
                .unwrap();
                assert_ne!(*version, directory.version_hash);
            }
            for as_admission in [false, true] {
                let required = if as_admission {
                    derive_required_conflict_copy_ops_as_admission_will(
                        &c,
                        group,
                        &heads,
                        std::slice::from_ref(&touch),
                        true,
                    )
                    .unwrap()
                } else {
                    derive_required_conflict_copy_ops(
                        &c,
                        group,
                        &heads,
                        std::slice::from_ref(&touch),
                    )
                    .unwrap()
                };
                assert_eq!(required.len(), 1, "{touch:?}: {required:?}");
                let Op::Put {
                    version, origin: PutOrigin::ConflictCopy { source_path, .. }, ..
                } = &required[0]
                else {
                    panic!("a conflict-copy put: {required:?}");
                };
                assert_eq!(*version, leaf.version_hash, "the leaf is copied, not the directory");
                assert_eq!(source_path.as_str(), "a");
            }
        }
    }
}

/// DIR-1 with three heads: a File outranking a Directory and a second
/// File. Both Files are owed copies, the Directory none.
#[test]
fn a_three_way_fork_owes_every_leaf_a_copy_and_the_directory_none() {
    let c = conn();
    let group = "g";
    let leaf = version(100);
    let directory = yadorilink_replica_domain::file::FileVersion::directory(Some(0o755));
    concurrent_at_a(&c, group, &leaf, &directory);
    let other = version(101);
    put_file_version(&c, group, &other).unwrap();
    admit(&c, group, vec![], "device-other", &key(3), vec![put_op("a", &other)]);
    let heads = group_heads(&c, group).unwrap();
    let touch = Op::Delete { path: SyncPath("a".into()) };
    let required =
        derive_required_conflict_copy_ops(&c, group, &heads, std::slice::from_ref(&touch)).unwrap();
    let mut copied: Vec<VersionHash> = required
        .iter()
        .map(|op| match op {
            Op::Put { version, origin: PutOrigin::ConflictCopy { .. }, .. } => *version,
            other => panic!("a conflict-copy put: {other:?}"),
        })
        .collect();
    copied.sort_by_key(|v| v.0);
    let mut expected = vec![leaf.version_hash, other.version_hash];
    expected.sort_by_key(|v| v.0);
    assert_eq!(copied, expected);
}

/// DIR-1, the other rank order: the Directory ranks higher, and the File
/// or Symlink that loses is owed its ordinary copy.
#[test]
fn a_file_or_symlink_that_loses_the_rank_to_a_directory_is_owed_its_copy() {
    for leaf in [version(100), symlink_version("t")] {
        let c = conn();
        let group = "g";
        let directory = yadorilink_replica_domain::file::FileVersion::directory(Some(0o755));
        let heads = concurrent_at_a(&c, group, &directory, &leaf);
        let touch = Op::Delete { path: SyncPath("a".into()) };
        let required =
            derive_required_conflict_copy_ops(&c, group, &heads, std::slice::from_ref(&touch))
                .unwrap();
        assert_eq!(required.len(), 1, "{required:?}");
        let Op::Put { version, origin: PutOrigin::ConflictCopy { source_path, .. }, .. } =
            &required[0]
        else {
            panic!("a conflict-copy put: {required:?}");
        };
        assert_eq!(*version, leaf.version_hash);
        assert_eq!(source_path.as_str(), "a");
    }
}

/// Two Directory heads that differ only in mode: the better-ranked one's
/// mode wins and the other is owed nothing.
#[test]
fn a_directory_that_loses_to_a_directory_is_owed_no_copy() {
    let c = conn();
    let group = "g";
    let high = yadorilink_replica_domain::file::FileVersion::directory(Some(0o700));
    let low = yadorilink_replica_domain::file::FileVersion::directory(Some(0o755));
    let heads = concurrent_at_a(&c, group, &high, &low);
    let touch = Op::Delete { path: SyncPath("a".into()) };
    let required =
        derive_required_conflict_copy_ops(&c, group, &heads, std::slice::from_ref(&touch)).unwrap();
    assert!(required.is_empty(), "no empty directory copy is owed; got {required:?}");
}

/// A carrier that claims a copy of a losing Directory claims an obligation
/// no one has: admission refuses it as an excess claim.
#[test]
fn a_carrier_claiming_a_losing_directory_copy_is_refused() {
    let c = conn();
    let group = "g";
    let leaf = version(100);
    let directory = yadorilink_replica_domain::file::FileVersion::directory(Some(0o755));
    let heads = concurrent_at_a(&c, group, &leaf, &directory);
    let low_head = crate::dag_store::live_path_heads(&c, group, "a")
        .unwrap()
        .into_iter()
        .find(|head| {
            head.content
                .as_ref()
                .is_some_and(|content| content.version_hash == directory.version_hash.0)
        })
        .expect("the directory is a live head of a");
    let claim = Op::Put {
        path: SyncPath(yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "a",
            &low_head.naming_device_id,
            low_head.content.as_ref().unwrap().mtime_unix_nanos,
            &directory.version_hash.0,
        )),
        version: directory.version_hash,
        origin: PutOrigin::ConflictCopy {
            source_path: SyncPath("a".into()),
            losing_change: ChangeHash(low_head.change_hash),
        },
    };
    let ops = vec![Op::Delete { path: SyncPath("a".into()) }, claim];
    let verdict =
        validate_carrier_conflict_copy_ops_parts(&c, group, &heads, &ops, &ChangePurpose::Ordinary);
    assert!(verdict.is_err(), "a directory copy claim must be refused; got {verdict:?}");
}
