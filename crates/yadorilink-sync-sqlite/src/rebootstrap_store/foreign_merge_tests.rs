#![cfg(test)]
//! Merging a history written on another base: verifying each side, refusing
//! a forked author position, joining the two summaries, and choosing the
//! base the join stands on.

use super::base_install_tests::open;
use super::seal_tests::{
    admit, build_history, delete, emit, key, project, publish_everything, put, seal,
    store_versions, version, GROUP,
};
use super::*;
use yadorilink_replica_domain::base_negotiation::AdvertisedBase;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;

// --- The merge of two summaries ---------------------------------------

fn hash(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

fn base(byte: u8) -> HistoryBase {
    HistoryBase([byte; 32])
}

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.to_string())
}

fn author(device_id: &str, watermark: u64, tip: u8) -> SnapshotAuthorState {
    SnapshotAuthorState {
        device_id: device_id.to_string(),
        watermark: AuthorSeq(watermark),
        tip_change_hash: hash(tip),
    }
}

fn head(path: &str, change: u8, device_id: &str, seq: u64) -> SnapshotPathHead {
    SnapshotPathHead {
        path: path.to_string(),
        change_hash: hash(change),
        device_id: device_id.to_string(),
        author_seq: AuthorSeq(seq),
        lamport: seq,
        version_hash: VersionHash([change; 32]),
        naming_device_id: device_id.to_string(),
    }
}

fn summary(
    author_state: Vec<SnapshotAuthorState>,
    path_heads: Vec<SnapshotPathHead>,
    lamport_ceiling: u64,
) -> GroupHistorySummary {
    GroupHistorySummary { author_state, path_heads, lamport_ceiling }
}

fn identity(summary: &GroupHistorySummary) -> SummaryIdentity {
    crate::base_advertisement::summary_identity(summary)
}

use yadorilink_replica_domain::base_negotiation::SummaryIdentity;

/// `a` wrote `p` twice; the later summary holds both writes, the earlier
/// only the first.
fn prefix_and_extension() -> (GroupHistorySummary, GroupHistorySummary) {
    let earlier = summary(vec![author("a", 1, 0x11)], vec![head("p", 0x11, "a", 1)], 1);
    let later = summary(vec![author("a", 2, 0x12)], vec![head("p", 0x12, "a", 2)], 2);
    (earlier, later)
}

/// A replica that already holds the returning history keeps its own base:
/// nothing new came into existence, so nothing is minted.
#[test]
fn a_side_that_holds_the_other_history_keeps_its_own_base() {
    let (earlier, later) = prefix_and_extension();

    let merge = plan_summary_merge(&group(), (base(1), &later), (base(2), &earlier)).unwrap();

    assert_eq!(merge.order, SummaryOrder::CurrentAbsorbsReturning);
    assert_eq!(merge.base, MergedBase::Current(base(1)));
    assert_eq!(identity(&merge.summary), identity(&later));
}

/// A returning side that holds this replica's history is adopted as it is,
/// base and all. The planner does not care whether that base was sealed or
/// minted, which is what lets base ids settle instead of being re-minted on
/// every merge that crosses them. A minted base cannot yet arrive as a
/// verified side, though: verification derives every base from its
/// checkpoint, and a minted one is not, so settling end to end waits on how
/// a merged base is bound to a checkpoint.
#[test]
fn a_returning_side_that_holds_this_history_is_adopted_not_reminted() {
    let (earlier, later) = prefix_and_extension();

    let merge = plan_summary_merge(&group(), (base(1), &earlier), (base(2), &later)).unwrap();

    assert_eq!(merge.order, SummaryOrder::ReturningAbsorbsCurrent);
    assert_eq!(merge.base, MergedBase::Returning(base(2)));
    assert_eq!(identity(&merge.summary), identity(&later));
}

/// Two bases over the same history settle on one of them, the same one
/// whichever side merges.
#[test]
fn equal_summaries_settle_on_the_greater_base_whichever_side_merges() {
    let (_, history) = prefix_and_extension();

    let from_low = plan_summary_merge(&group(), (base(1), &history), (base(2), &history)).unwrap();
    let from_high = plan_summary_merge(&group(), (base(2), &history), (base(1), &history)).unwrap();

    assert_eq!(from_low.order, SummaryOrder::Equal);
    assert_eq!(from_low.base, MergedBase::Returning(base(2)));
    assert_eq!(from_high.order, SummaryOrder::Equal);
    assert_eq!(from_high.base, MergedBase::Current(base(2)));

    let same = plan_summary_merge(&group(), (base(1), &history), (base(1), &history)).unwrap();
    assert_eq!(same.base, MergedBase::Current(base(1)), "merging a base with itself is identity");
}

/// Each side holds a write the other has not seen: the join is a history
/// neither base names, and is founded on a base neither side holds -- the
/// same one from either side.
#[test]
fn incomparable_summaries_mint_a_base_neither_side_holds() {
    let left = summary(vec![author("a", 1, 0x11)], vec![head("p", 0x11, "a", 1)], 1);
    let right = summary(vec![author("b", 1, 0x21)], vec![head("p", 0x21, "b", 1)], 1);

    let merge = plan_summary_merge(&group(), (base(1), &left), (base(2), &right)).unwrap();
    let mirrored = plan_summary_merge(&group(), (base(2), &right), (base(1), &left)).unwrap();

    assert_eq!(merge.order, SummaryOrder::Incomparable);
    let MergedBase::Minted(minted) = merge.base else {
        panic!("expected a minted base, got {:?}", merge.base)
    };
    assert_ne!(minted, base(1));
    assert_ne!(minted, base(2));
    assert_eq!(mirrored.base, MergedBase::Minted(minted));
    assert_eq!(identity(&mirrored.summary), identity(&merge.summary));
    assert_eq!(
        minted,
        HistoryBase::mint_merged(&group(), base(1), base(2), &identity(&merge.summary))
    );
    assert_eq!(merge.summary.path_heads.len(), 2, "both concurrent writes stay heads");
}

fn equivocation(result: Result<SummaryMerge, ForeignMergeRefusal>) -> SummaryEquivocation {
    match result {
        Err(ForeignMergeRefusal::Equivocation(equivocation)) => equivocation,
        other => panic!("expected an equivocation refusal, got {other:?}"),
    }
}

/// One position, two changes, both still heads: refused, never joined to
/// one side.
#[test]
fn two_heads_at_one_position_refuse_the_merge() {
    let left = summary(
        vec![author("a", 2, 0x12)],
        vec![head("p", 0x11, "a", 1), head("q", 0x12, "a", 2)],
        2,
    );
    let right = summary(
        vec![author("a", 2, 0x12)],
        vec![head("p", 0x19, "a", 1), head("q", 0x12, "a", 2)],
        2,
    );

    let found = equivocation(plan_summary_merge(&group(), (base(1), &left), (base(2), &right)));

    assert_eq!(found.device_id, "a");
    assert_eq!(found.author_seq, AuthorSeq(1));
    assert_eq!((found.held, found.incoming), (hash(0x11), hash(0x19)));
    assert!(
        matches!(left.join(&right), Err(SyncSqliteError::CorruptState(_))),
        "the join alone refuses it too"
    );
}

/// An author's tip names the change at its watermark whether or not that
/// change is still anyone's head, so a head the other side holds at that
/// position is checked against it.
#[test]
fn a_head_that_disagrees_with_the_other_sides_tip_refuses_the_merge() {
    let left = summary(vec![author("a", 2, 0x12)], Vec::new(), 2);
    let right = summary(vec![author("a", 2, 0x19)], vec![head("p", 0x19, "a", 2)], 2);

    let found = equivocation(plan_summary_merge(&group(), (base(1), &left), (base(2), &right)));

    assert_eq!(found.author_seq, AuthorSeq(2));
    assert_eq!((found.held, found.incoming), (hash(0x12), hash(0x19)));
}

/// One side alone can equivocate: a head at the author's watermark that is
/// not the author's tip.
#[test]
fn one_side_naming_two_changes_at_one_position_refuses_the_merge() {
    let forked = summary(vec![author("a", 1, 0x11)], vec![head("p", 0x19, "a", 1)], 1);
    let other = summary(vec![author("b", 1, 0x21)], vec![head("q", 0x21, "b", 1)], 1);

    let found = equivocation(plan_summary_merge(&group(), (base(1), &other), (base(2), &forked)));

    assert_eq!((found.held, found.incoming), (hash(0x11), hash(0x19)));
}

/// The limit of what a summary can see. `left` wrote `(a, 2)` as `0x12`
/// and superseded it with `(a, 3)`; `right` holds a different change at
/// `(a, 2)`, `0x19`. Nothing in `left` names the change at `(a, 2)` any
/// more, so the merge goes through and keeps `left`'s side. Only admission
/// and the rule that nothing re-signs an existing change can prevent this
/// fork, which is why neither may be relaxed on the strength of this check.
#[test]
fn a_fork_below_what_the_summary_still_names_is_not_seen() {
    let left = summary(vec![author("a", 3, 0x13)], vec![head("p", 0x13, "a", 3)], 3);
    let right = summary(vec![author("a", 2, 0x19)], vec![head("p", 0x19, "a", 2)], 2);

    let merge = plan_summary_merge(&group(), (base(1), &left), (base(2), &right)).unwrap();

    assert_eq!(merge.order, SummaryOrder::CurrentAbsorbsReturning);
    assert_eq!(identity(&merge.summary), identity(&left));
}

// --- Verifying each side ------------------------------------------------

fn trust(device_id: &str) -> Option<[u8; 32]> {
    Some(key(device_id).verifying_key().to_bytes())
}

/// The group's authority in these fixtures: the devices that wrote the
/// history are writers and full replicas, each bound to the key it signs
/// with.
fn writers(group_id: &str, signer: &str, signing_key: &[u8; 32]) -> bool {
    group_id == GROUP
        && matches!(signer, "device-a" | "device-b" | "device-c")
        && *signing_key == key(signer).verifying_key().to_bytes()
}

fn signed(checkpoint: &Checkpoint, signer: &str) -> SnapshotManifest {
    SnapshotManifest::new_signed(
        checkpoint.clone(),
        Vec::new(),
        None,
        DeviceId(signer.to_string()),
        &key(signer),
    )
    .unwrap()
}

fn refused(result: Result<VerifiedBaseSummary, ForeignMergeRefusal>) -> ForeignMergeRefusal {
    match result {
        Err(refusal) => refusal,
        Ok(side) => panic!("expected a refusal, got a verified base {:?}", side.history_base()),
    }
}

/// A snapshot rebuilt from `snapshot` with `edit` applied to its parts,
/// with the checkpoint re-derived so only the edit is wrong.
fn rebuilt(
    snapshot: &RebootstrapSnapshot,
    checkpoint: &Checkpoint,
    edit: impl FnOnce(&mut RebootstrapSnapshot),
) -> (RebootstrapSnapshot, Checkpoint) {
    let mut parts = snapshot.clone();
    edit(&mut parts);
    let snapshot = RebootstrapSnapshot::new(
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
        checkpoint.group_id.clone(),
        checkpoint.frontier.clone(),
        snapshot.snapshot_hash(),
    );
    (snapshot, checkpoint)
}

/// A sealed replica's own base verifies as its side of a merge, and is the
/// base and summary the seal produced.
#[test]
fn a_sealed_base_verifies_as_this_replicas_side() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);

    let side = verify_current_base(&conn, GROUP).unwrap();

    assert_eq!(side.history_base(), sealed.history_base());
    assert_eq!(side.summary_identity(), sealed.summary_identity());
    assert_eq!(
        VerifiedBaseSummary::from_seal(&sealed).unwrap().summary_identity(),
        sealed.summary_identity()
    );
}

/// With no base installed there is no verified summary of this side; the
/// history has to be sealed first.
#[test]
fn a_group_without_a_base_has_no_side_to_merge_yet() {
    let conn = open();
    build_history(&conn);

    let error = verify_current_base(&conn, GROUP).unwrap_err();

    assert!(
        matches!(error, ForeignMergeError::Refused(ForeignMergeRefusal::NoBaseInstalled)),
        "got {error:?}"
    );
}

/// History written above the base is not described by the base's summary,
/// so merging the base alone would leave it out.
#[test]
fn history_above_the_base_must_be_sealed_before_merging() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    store_versions(&conn);
    emit(&conn, "device-a", vec![put("s", &version(5))]);

    let error = verify_current_base(&conn, GROUP).unwrap_err();

    assert!(
        matches!(error, ForeignMergeError::Refused(ForeignMergeRefusal::HistoryAboveBase)),
        "got {error:?}"
    );
}

/// The summary kept for the installed base must be the one its snapshot
/// carries; if it is not, the store is damaged and the merge does not start.
#[test]
fn a_stored_summary_that_is_not_the_snapshots_is_damage() {
    let conn = open();
    build_history(&conn);
    seal(&conn);
    conn.execute(
        "UPDATE history_base_meta SET lamport_ceiling = lamport_ceiling + 1 WHERE group_id = ?1",
        [GROUP],
    )
    .unwrap();

    let error = verify_current_base(&conn, GROUP).unwrap_err();

    assert!(
        matches!(error, ForeignMergeError::Store(SyncSqliteError::CorruptState(_))),
        "got {error:?}"
    );
}

/// A base a peer signed verifies as the returning side, and is the base it
/// advertised.
#[test]
fn a_signed_base_verifies_as_the_returning_side() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);
    let manifest = signed(sealed.checkpoint(), "device-b");
    let bytes = sealed.snapshot().canonical_encoding();

    let side = verify_returning_base(GROUP, &manifest, &bytes, &trust, &writers).unwrap();

    assert_eq!(side.history_base(), sealed.history_base());
    assert_eq!(side.summary_identity(), sealed.summary_identity());
    assert!(side.matches_advertisement(&AdvertisedBase::Installed {
        checkpoint: Box::new(sealed.checkpoint().clone()),
        summary: sealed.summary_identity(),
    }));
    assert!(!side.matches_advertisement(&AdvertisedBase::Installed {
        checkpoint: Box::new(sealed.checkpoint().clone()),
        summary: SummaryIdentity([0; 32]),
    }));
    assert!(!side.matches_advertisement(&AdvertisedBase::Genesis));
}

/// Nothing of a returning base is believed before its signature, its group
/// and its snapshot bytes check out.
#[test]
fn a_returning_base_that_does_not_verify_is_refused() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);
    let manifest = signed(sealed.checkpoint(), "device-b");
    let bytes = sealed.snapshot().canonical_encoding();

    let untrusted = |_: &str| Some(key("device-z").verifying_key().to_bytes());
    assert!(matches!(
        refused(verify_returning_base(GROUP, &manifest, &bytes, &untrusted, &writers)),
        ForeignMergeRefusal::ManifestInvalid { .. }
    ));

    assert!(matches!(
        refused(verify_returning_base("another-group", &manifest, &bytes, &trust, &writers)),
        ForeignMergeRefusal::GroupMismatch { .. }
    ));

    let (other, _) = rebuilt(sealed.snapshot(), sealed.checkpoint(), |parts| {
        parts.lamport_ceiling += 1;
    });
    assert!(matches!(
        refused(verify_returning_base(
            GROUP,
            &manifest,
            &other.canonical_encoding(),
            &trust,
            &writers
        )),
        ForeignMergeRefusal::SnapshotInvalid { .. }
    ));

    let mut padded = bytes.clone();
    padded.push(0);
    assert!(matches!(
        refused(verify_returning_base(GROUP, &manifest, &padded, &trust, &writers)),
        ForeignMergeRefusal::SnapshotInvalid { .. }
    ));
}

/// A signature proves only who signed. A signer the pinned keys accept but
/// the group's authority does not -- a viewer, or a writer whose pinned key
/// is not the one the policy bound to it -- founds no base, however well
/// formed its snapshot is: its summary would otherwise raise an author's
/// watermark and silently drop that author's heads on this side.
#[test]
fn a_returning_base_signed_by_a_device_that_may_not_found_one_is_refused() {
    let conn = open();
    build_history(&conn);
    let sealed = seal(&conn);
    let bytes = sealed.snapshot().canonical_encoding();
    let pinned = |device_id: &str| Some(key(device_id).verifying_key().to_bytes());

    let viewer = signed(sealed.checkpoint(), "device-v");
    assert_eq!(
        refused(verify_returning_base(GROUP, &viewer, &bytes, &pinned, &writers)),
        ForeignMergeRefusal::SignerNotAuthorized { signer: "device-v".into() }
    );

    // The pinned key for device-b is device-z's, and the manifest is signed
    // with it: the signature verifies, but not under the key the policy
    // bound to device-b.
    let rebound = |_: &str| Some(key("device-z").verifying_key().to_bytes());
    let impostor = SnapshotManifest::new_signed(
        sealed.checkpoint().clone(),
        Vec::new(),
        None,
        DeviceId("device-b".to_string()),
        &key("device-z"),
    )
    .unwrap();
    assert_eq!(
        refused(verify_returning_base(GROUP, &impostor, &bytes, &rebound, &writers)),
        ForeignMergeRefusal::SignerNotAuthorized { signer: "device-b".into() }
    );

    let consulted = std::cell::RefCell::new(Vec::new());
    let recording = |group_id: &str, signer: &str, signing_key: &[u8; 32]| {
        consulted.borrow_mut().push((group_id.to_owned(), signer.to_owned(), *signing_key));
        writers(group_id, signer, signing_key)
    };
    let manifest = signed(sealed.checkpoint(), "device-b");
    verify_returning_base(GROUP, &manifest, &bytes, &trust, &recording).unwrap();
    assert_eq!(
        consulted.into_inner(),
        vec![(GROUP.to_owned(), "device-b".to_owned(), key("device-b").verifying_key().to_bytes())],
        "the authority is asked about this group, this signer and the key that verified it"
    );
}

/// Every head's content must travel with the base: a merged base built
/// from a head whose version is missing would name content nobody can
/// reproduce.
#[test]
fn a_returning_head_whose_content_is_not_carried_is_refused() {
    let conn = open();
    let h = build_history(&conn);
    let sealed = seal(&conn);
    let missing = version(2).version_hash;
    let (snapshot, checkpoint) = rebuilt(sealed.snapshot(), sealed.checkpoint(), |parts| {
        parts.file_versions.retain(|encoded| {
            FileVersion::from_canonical_encoding(encoded).unwrap().version_hash != missing
        });
    });
    let manifest = signed(&checkpoint, "device-b");

    let refusal = refused(verify_returning_base(
        GROUP,
        &manifest,
        &snapshot.canonical_encoding(),
        &trust,
        &writers,
    ));

    assert_eq!(
        refusal,
        ForeignMergeRefusal::ContentNotCarried { path: "r".into(), version: missing },
        "A3's version at r is gone ({})",
        h.a3.compute_hash().to_hex()
    );
}

/// A returning base whose own summary names two changes at one position --
/// here, an author's tip that is not the head it wrote at that position --
/// is refused before it is joined with anything.
#[test]
fn a_returning_base_that_equivocates_on_its_own_is_refused() {
    let conn = open();
    let h = build_history(&conn);
    let sealed = seal(&conn);
    let (snapshot, checkpoint) = rebuilt(sealed.snapshot(), sealed.checkpoint(), |parts| {
        for author in &mut parts.author_state {
            if author.device_id == "device-c" {
                author.tip_change_hash = hash(0x77);
            }
        }
    });
    let manifest = signed(&checkpoint, "device-b");

    let refusal = refused(verify_returning_base(
        GROUP,
        &manifest,
        &snapshot.canonical_encoding(),
        &trust,
        &writers,
    ));

    let ForeignMergeRefusal::Equivocation(found) = refusal else {
        panic!("expected an equivocation refusal, got {refusal:?}")
    };
    assert_eq!(found.device_id, "device-c");
    assert_eq!(found.author_seq, h.c1.author_seq);
}

/// `snapshot` with its frontier change `held` replaced by `forged` -- the
/// file rows `held` authored now credit `forged` -- and the checkpoint's
/// frontier re-derived to match, so only the swap is wrong.
fn with_frontier_change(
    snapshot: &RebootstrapSnapshot,
    checkpoint: &Checkpoint,
    held: &Change,
    forged: &Change,
) -> (RebootstrapSnapshot, Checkpoint) {
    let held_hash = held.compute_hash();
    let (snapshot, _) = rebuilt(snapshot, checkpoint, |parts| {
        let slot = parts
            .frontier_changes
            .iter_mut()
            .find(|encoded| Change::from_wire_bytes(encoded).unwrap().compute_hash() == held_hash)
            .expect("the change being replaced is a frontier change");
        *slot = forged.to_wire_bytes();
        for file in &mut parts.files {
            if file.authoring_change_hash == Some(held_hash) {
                file.authoring_change_hash = Some(forged.compute_hash());
            }
        }
    });
    let mut frontier: Vec<ChangeHash> = checkpoint
        .frontier
        .iter()
        .map(|hash| if *hash == held_hash { forged.compute_hash() } else { *hash })
        .collect();
    frontier.sort();
    let checkpoint =
        Checkpoint::new(checkpoint.group_id.clone(), frontier, snapshot.snapshot_hash());
    (snapshot, checkpoint)
}

/// `change` signed again by its author with different parents: the same
/// author position, a different change.
fn re_signed_without_parents(change: &Change) -> Change {
    let mut forged = change.clone();
    forged.parents.clear();
    forged.sign(&key(change.device_id.as_str()));
    assert_ne!(forged.compute_hash(), change.compute_hash());
    forged
}

/// A frontier change travels with a base as a change of its own and names
/// the change at its author position too. One that disagrees with what the
/// same snapshot's summary names there -- here `C1`'s tip and head at `q`
/// -- is refused, even though the summary alone is consistent.
#[test]
fn a_returning_frontier_change_that_disagrees_with_its_own_summary_is_refused() {
    let conn = open();
    let h = build_history(&conn);
    let sealed = seal(&conn);
    let forged = re_signed_without_parents(&h.c1);
    let (snapshot, checkpoint) =
        with_frontier_change(sealed.snapshot(), sealed.checkpoint(), &h.c1, &forged);
    let manifest = signed(&checkpoint, "device-b");

    let refusal = refused(verify_returning_base(
        GROUP,
        &manifest,
        &snapshot.canonical_encoding(),
        &trust,
        &writers,
    ));

    let ForeignMergeRefusal::Equivocation(found) = refusal else {
        panic!("expected an equivocation refusal, got {refusal:?}")
    };
    assert_eq!((found.device_id.as_str(), found.author_seq), ("device-c", h.c1.author_seq));
    assert_eq!((found.held, found.incoming), (h.c1.compute_hash(), forged.compute_hash()));
}

/// A position only a frontier change names on either side -- here a delete
/// by `device-d` that is neither a content head nor its author's tip --
/// is invisible to the summaries, so only the verified merge, which folds
/// in both sides' frontier changes, can see two changes there.
#[test]
fn frontier_changes_that_disagree_across_the_two_sides_refuse_the_merge() {
    let conn = open();
    let h = build_history(&conn);
    let deleted = admit(&conn, "device-d", &[&h.c1], vec![delete("q")]);
    admit(&conn, "device-d", &[], vec![put("s", &version(5))]);
    publish_everything(&conn, 2);
    project(&conn);
    seal(&conn);
    let current = verify_current_base(&conn, GROUP).unwrap();
    let forged = re_signed_without_parents(&deleted);
    let (snapshot, checkpoint) =
        with_frontier_change(current.snapshot(), current.checkpoint(), &deleted, &forged);
    let returning = verify_returning_base(
        GROUP,
        &signed(&checkpoint, "device-b"),
        &snapshot.canonical_encoding(),
        &trust,
        &writers,
    )
    .unwrap();

    plan_summary_merge(
        &group(),
        (current.history_base(), current.summary()),
        (returning.history_base(), returning.summary()),
    )
    .expect("the two summaries alone name no change at the forked position");
    let found = equivocation(merge_foreign_base(&current, &returning));

    assert_eq!((found.device_id.as_str(), found.author_seq), ("device-d", deleted.author_seq));
    assert_eq!((found.held, found.incoming), (deleted.compute_hash(), forged.compute_hash()));
}

/// Two replicas share a history, each writes something the other has not
/// seen, and each seals. Merging the two verified bases mints one fresh
/// base over both writes, the same from either side. A replica that sealed
/// only the shared prefix is absorbed by either one.
#[test]
fn two_replicas_that_sealed_apart_merge_onto_one_minted_base() {
    let shared = open();
    build_history(&shared);
    let prefix = seal(&shared);

    let left = open();
    build_history(&left);
    admit(&left, "device-d", &[], vec![put("s", &version(5))]);
    publish_everything(&left, 2);
    project(&left);
    seal(&left);

    let right = open();
    build_history(&right);
    admit(&right, "device-e", &[], vec![put("t", &version(6))]);
    publish_everything(&right, 2);
    project(&right);
    seal(&right);

    let left_side = verify_current_base(&left, GROUP).unwrap();
    let right_side = verify_current_base(&right, GROUP).unwrap();
    let returning = |side: &VerifiedBaseSummary| {
        verify_returning_base(
            GROUP,
            &signed(side.checkpoint(), "device-b"),
            &side.snapshot().canonical_encoding(),
            &trust,
            &writers,
        )
        .unwrap()
    };

    let at_left = merge_foreign_base(&left_side, &returning(&right_side)).unwrap();
    let at_right = merge_foreign_base(&right_side, &returning(&left_side)).unwrap();

    assert_eq!(at_left.order, SummaryOrder::Incomparable);
    assert!(matches!(at_left.base, MergedBase::Minted(_)));
    assert_eq!(at_left.base, at_right.base, "both replicas found the same base");
    assert_eq!(identity(&at_left.summary), identity(&at_right.summary));
    let paths: Vec<&str> = at_left.summary.path_heads.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"s") && paths.contains(&"t"), "both writes survive: {paths:?}");

    let prefix_side = VerifiedBaseSummary::from_seal(&prefix).unwrap();
    let absorbed = merge_foreign_base(&left_side, &returning(&prefix_side)).unwrap();
    assert_eq!(absorbed.base, MergedBase::Current(left_side.history_base()));
    let adopted = merge_foreign_base(&prefix_side, &returning(&left_side)).unwrap();
    assert_eq!(adopted.base, MergedBase::Returning(left_side.history_base()));
}
