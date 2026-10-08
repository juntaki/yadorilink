use std::collections::BTreeMap;

use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_materialize::{PhysicalNode, Placement};
use yadorilink_replica_domain::native_state::{
    DeltaHash, Dot, HeadPayload, NativeState, PathHeads,
};

use super::*;

fn witness_conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

fn group() -> FolderGroupId {
    FolderGroupId("g".to_string())
}

#[test]
fn witness_for_an_ordinary_path_is_its_own_current_winner() {
    let c = witness_conn();
    let a = dot("a", 1);
    let mut state = NativeState::new();
    state.put(&a.author, SyncPath("x".into()), &[], payload(9)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();

    let w = capture_native_witness(&c, &group(), "x").unwrap();
    assert_eq!(w.physical_path, SyncPath("x".into()));
    assert_eq!(w.logical_source_path, SyncPath("x".into()));
    let shown = w.shown_head.expect("a live head must be shown");
    assert_eq!(shown.payload.version, vh(9));
}

#[test]
fn witness_for_an_absent_path_is_none() {
    let c = witness_conn();
    let w = capture_native_witness(&c, &group(), "nowhere").unwrap();
    assert_eq!(w.logical_source_path, SyncPath("nowhere".into()));
    assert!(w.shown_head.is_none());
}

#[test]
fn witness_for_a_conflict_copy_path_is_the_specific_bound_loser_not_the_winner() {
    let c = witness_conn();
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let mut state = NativeState::new();
    state.put(&winner.author, SyncPath("x".into()), &[], payload(1)).unwrap();
    state.put(&loser.author, SyncPath("x".into()), &[], payload(2)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();

    // Populate the binding the same way real materialization/capture would.
    let heads = heads_map(&[("x", winner.clone(), payload(1)), ("x", loser.clone(), payload(2))]);
    let raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
    ensure_native_projection_bindings(&c, group().as_str(), &heads, &raw).unwrap();
    let bindings = stable_projection_binding::native_bindings(&c, group().as_str()).unwrap();
    let id = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let bound_path = bindings.get(&id).expect("loser must be bound").clone();

    let w = capture_native_witness(&c, &group(), &bound_path).unwrap();
    assert_eq!(w.physical_path, SyncPath(bound_path));
    assert_eq!(
        w.logical_source_path,
        SyncPath("x".into()),
        "must resolve to the LOGICAL source path, not itself"
    );
    let shown = w.shown_head.expect("the specific bound loser must be shown");
    assert_eq!(shown.dot, loser, "must be the loser's own head, not the path's overall winner");
    assert_eq!(shown.payload.version, vh(2));
}

#[test]
fn a_fresh_capture_verifies_as_fresh() {
    let c = witness_conn();
    let a = dot("a", 1);
    let mut state = NativeState::new();
    state.put(&a.author, SyncPath("x".into()), &[], payload(9)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();

    let witness = capture_native_witness(&c, &group(), "x").unwrap();
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );
}

/// What the writer saw is the content its row displayed, not the head that
/// represented it: another head of that content arriving and outranking the
/// captured one changes nothing the writer saw.
#[test]
fn another_head_of_the_shown_content_taking_over_does_not_make_the_capture_stale() {
    let c = witness_conn();
    let v1 = file_version(1_000);
    crate::dag_store::put_file_version(&c, "g", &v1).unwrap();
    let a = dot("a", 1);
    let mut state = NativeState::new();
    state.put(&a.author, SyncPath("x".into()), &[], payload_of(&v1)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "x", &v1);
    let witness = capture_native_witness(&c, &group(), "x").unwrap();
    assert_eq!(witness.shown_class, vec![a.clone()]);

    // The same content from another device, ranked above the captured head.
    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state
        .put(&dot("b", 1).author, SyncPath("x".into()), &[], HeadPayload { ..payload_of(&v1) })
        .unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();

    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );
}

/// A peer superseding or removing the captured heads while the row still
/// shows the captured content leaves the edit concurrent with what is live; it
/// is not stale.
#[test]
fn heads_going_away_while_the_row_still_shows_the_content_is_not_stale() {
    let c = witness_conn();
    let (v1, v2) = (file_version(1_000), file_version(2_000));
    for v in [&v1, &v2] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let a = dot("a", 1);
    let mut state = NativeState::new();
    state.put(&a.author, SyncPath("x".into()), &[], payload_of(&v1)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "x", &v1);
    let witness = capture_native_witness(&c, &group(), "x").unwrap();

    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    state
        .put(&dot("b", 1).author, SyncPath("x".into()), std::slice::from_ref(&a), payload_of(&v2))
        .unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );

    let mut state = crate::native_store::load_state(&c, &group()).unwrap();
    let b = dot("b", 1);
    state.delete(&b.author, SyncPath("x".into()), std::slice::from_ref(&b)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );
}

#[test]
fn a_row_that_vanishes_since_capture_verifies_as_stale_head_gone() {
    let c = witness_conn();
    let v1 = file_version(1_000);
    crate::dag_store::put_file_version(&c, "g", &v1).unwrap();
    let mut state = NativeState::new();
    state.put(&dot("a", 1).author, SyncPath("x".into()), &[], payload_of(&v1)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "x", &v1);
    let witness = capture_native_witness(&c, &group(), "x").unwrap();

    c.execute("DELETE FROM files WHERE group_id = 'g' AND path = 'x'", []).unwrap();

    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::HeadGone)
    );
}

#[test]
fn a_row_appearing_where_none_was_captured_verifies_as_stale() {
    let c = witness_conn();
    let witness = capture_native_witness(&c, &group(), "new").unwrap();
    assert!(witness.shown_version.is_none());

    let v = file_version(1_000);
    write_row(&c, "new", &v);

    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::UnexpectedContentAppeared)
    );
}

/// A peer head that arrives where the writer saw nothing is concurrent with
/// the create, not a reason to refuse it.
#[test]
fn a_head_appearing_where_no_row_was_captured_is_not_stale() {
    let c = witness_conn();
    let witness = capture_native_witness(&c, &group(), "new").unwrap();
    let mut state = NativeState::new();
    state.put(&dot("a", 1).author, SyncPath("new".into()), &[], payload(1)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn dot(name: &str, seq: u64) -> Dot {
    Dot { author: author(name), seq: AuthorSeq(seq) }
}

/// The version a test names by `n`: a smaller `n` is a larger hash, so it beats
/// a larger `n` when the heads are concurrent.
fn vh(n: u8) -> VersionHash {
    VersionHash([255 - n; 32])
}

fn payload(version_byte: u8) -> HeadPayload {
    HeadPayload { version: vh(version_byte), provenance: DeltaHash([version_byte; 32]) }
}

fn kind_of_file(_: &VersionHash) -> Option<RecordKind> {
    Some(RecordKind::File)
}

fn heads_map(entries: &[(&str, Dot, HeadPayload)]) -> BTreeMap<SyncPath, PathHeads> {
    let mut out: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
    for (path, d, p) in entries {
        out.entry(SyncPath((*path).to_owned())).or_default().insert(d.clone(), p.clone());
    }
    out
}

#[test]
fn ensure_assigns_a_fresh_binding_for_a_newly_observed_loser() {
    let c = conn();
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let heads = heads_map(&[("x", winner.clone(), payload(1)), ("x", loser.clone(), payload(2))]);
    let raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();

    ensure_native_projection_bindings(&c, "g", &heads, &raw).unwrap();

    let bindings = stable_projection_binding::native_bindings(&c, "g").unwrap();
    let id = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let bound_path = bindings.get(&id).expect("loser must get a binding");
    assert!(
        bound_path.contains('x'),
        "assigned name should derive from the source path: {bound_path}"
    );
}

#[test]
fn ensure_disambiguates_a_naming_collision_with_an_occupied_path() {
    let c = conn();
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let heads = heads_map(&[("x", winner.clone(), payload(1)), ("x", loser.clone(), payload(2))]);

    // Pre-occupy whatever name attempt 1 would produce by binding some
    // OTHER identity to it first.
    let first = ensure_first_name("x");
    stable_projection_binding::native_bind(
        &c,
        "g",
        &("z".to_string(), "other".to_string(), [2u8; 16], 9),
        &first,
    )
    .unwrap();

    let raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
    ensure_native_projection_bindings(&c, "g", &heads, &raw).unwrap();

    let bindings = stable_projection_binding::native_bindings(&c, "g").unwrap();
    let id = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let bound_path = bindings.get(&id).expect("loser must still get a binding");
    assert_ne!(bound_path, &first, "must not collide with the pre-occupied name");
}

fn ensure_first_name(path: &str) -> String {
    numbered_copy_name(path, [2u8; 32], 1)
}

#[test]
fn one_delta_losing_at_two_paths_gets_two_independent_bindings() {
    let c = conn();
    // Same identity (device+incarnation+seq) loses at both "x" and "y".
    let shared = dot("b", 1);
    let heads = heads_map(&[
        ("x", dot("a", 1), payload(1)),
        ("x", shared.clone(), payload(2)),
        ("y", dot("a", 2), payload(3)),
        ("y", shared.clone(), payload(4)),
    ]);
    let raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
    ensure_native_projection_bindings(&c, "g", &heads, &raw).unwrap();

    let bindings = stable_projection_binding::native_bindings(&c, "g").unwrap();
    let id_x = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let id_y = ("y".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let path_x = bindings.get(&id_x).expect("x's binding must exist");
    let path_y = bindings.get(&id_y).expect("y's binding must exist");
    assert_ne!(path_x, path_y, "the two independent bindings must not collide with each other");
}

#[test]
fn apply_forces_an_existing_bindings_head_off_a_promoted_at_path_placement() {
    let c = conn();
    let loser = dot("b", 1);
    let identity = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    stable_projection_binding::native_bind(&c, "g", &identity, "x (conflict).txt").unwrap();

    // Winner departed: only the loser remains, so the pure resolver's own
    // raw output (simulated here) promotes it to AtPath at "x".
    let heads = heads_map(&[("x", loser.clone(), payload(2))]);
    let mut raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
    raw.insert(
        SyncPath("x".to_string()),
        PhysicalNode::Entry(yadorilink_replica_domain::native_materialize::PlacedEntry {
            kind: RecordKind::File,
            version: vh(2),
            source_dot: loser.clone(),
            placement: Placement::AtPath,
        }),
    );

    let result = apply_native_stable_bindings(&c, "g", &heads, raw, &kind_of_file).unwrap();

    assert!(
        !result.contains_key(&SyncPath("x".to_string())),
        "must not stay promoted at its own account"
    );
    match result.get(&SyncPath("x (conflict).txt".to_string())) {
        Some(PhysicalNode::Entry(e)) => {
            assert_eq!(e.source_dot, loser);
            assert_eq!(e.placement, Placement::ConflictCopy);
        }
        other => panic!("expected the bound head at its stable path, got {other:?}"),
    }
}

#[test]
fn apply_never_destroys_a_live_directory_occupying_the_bound_path() {
    let c = conn();
    let loser = dot("b", 1);
    let identity = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    stable_projection_binding::native_bind(&c, "g", &identity, "x (conflict).txt").unwrap();

    let heads = heads_map(&[("x", loser.clone(), payload(2))]);
    let mut raw: BTreeMap<SyncPath, PhysicalNode> = BTreeMap::new();
    raw.insert(
        SyncPath("x (conflict).txt".to_string()),
        PhysicalNode::Directory(
            yadorilink_replica_domain::native_materialize::DirectoryNode::Structural,
        ),
    );

    let result = apply_native_stable_bindings(&c, "g", &heads, raw, &kind_of_file).unwrap();

    assert_eq!(
        result.get(&SyncPath("x (conflict).txt".to_string())),
        Some(&PhysicalNode::Directory(
            yadorilink_replica_domain::native_materialize::DirectoryNode::Structural
        )),
        "the directory must survive untouched"
    );
}

#[test]
fn own_node_suppresses_a_promotion_when_a_binding_points_elsewhere() {
    let c = conn();
    let loser = dot("b", 1);
    stable_projection_binding::native_bind(
        &c,
        "g",
        &("x".to_string(), "b".to_string(), [1u8; 16], 1u64),
        "x (conflict).txt",
    )
    .unwrap();
    // ... and the placement `ensure` records for that copy, which is what decides.
    stable_projection_binding::native_placement_put(
        &c,
        "g",
        &stable_projection_binding::NativePlacementRow {
            physical_path: "x (conflict).txt".into(),
            source_path: "x".into(),
            author: "b".into(),
            incarnation: [1u8; 16],
            seq: 1,
            provenance: payload(2).provenance.0,
            version: vh(2).0,
            origin: "conflict_copy".into(),
        },
    )
    .unwrap();
    let heads = vec![yadorilink_replica_domain::native_state::LiveHead {
        dot: loser.clone(),
        payload: payload(2),
    }];
    let node =
        Some(PhysicalNode::Entry(yadorilink_replica_domain::native_materialize::PlacedEntry {
            kind: RecordKind::File,
            version: vh(2),
            source_dot: loser,
            placement: Placement::AtPath,
        }));

    let result = apply_native_stable_binding_own_node(&c, "g", "x", &heads, node).unwrap();
    assert!(
        result.is_none(),
        "a promotion to a DIFFERENT path than the bound one must be suppressed"
    );
}

#[test]
fn resolve_physical_path_finds_a_placed_copy_and_none_for_an_ordinary_path() {
    let c = conn();
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let heads = heads_map(&[("x", winner.clone(), payload(1)), ("x", loser.clone(), payload(2))]);
    let mut state = NativeState::new();
    state.heads = heads.clone();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    ensure_native_projection_bindings(&c, "g", &heads, &BTreeMap::new()).unwrap();
    let id = ("x".to_string(), "b".to_string(), [1u8; 16], 1u64);
    let copy = stable_projection_binding::native_bindings(&c, "g").unwrap()[&id].clone();

    let target = resolve_native_physical_path(&c, "g", &copy).unwrap().expect("must resolve");
    assert_eq!(target.source_path, SyncPath("x".to_string()));
    assert_eq!(target.dot, loser);
    assert_eq!(target.payload.version, vh(2));
    assert_eq!(target.origin, PlacementOrigin::ConflictCopy);

    assert!(resolve_native_physical_path(&c, "g", "x.txt").unwrap().is_none());

    // With no row at the copy name and the loser gone, nothing is shown.
    let mut without = NativeState::new();
    without.heads = heads_map(&[("x", winner, payload(1))]);
    crate::native_store::install_state(&c, &group(), &without).unwrap();
    assert!(resolve_native_physical_path(&c, "g", &copy).unwrap().is_none());
}

fn file_version(mtime: i64) -> yadorilink_replica_domain::file::FileVersion {
    yadorilink_replica_domain::file::FileVersion::new(
        Vec::new(),
        0,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn payload_of(version: &yadorilink_replica_domain::file::FileVersion) -> HeadPayload {
    HeadPayload { version: version.version_hash, provenance: DeltaHash(version.version_hash.0) }
}

/// The index row at `path` showing `version`, as the materializer leaves it.
fn write_row(c: &Connection, path: &str, version: &yadorilink_replica_domain::file::FileVersion) {
    let tx = c.unchecked_transaction().unwrap();
    crate::file_index::upsert_file_in_tx(
        &tx,
        "g",
        &yadorilink_replica_domain::file::FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        },
        "device-x",
    )
    .unwrap();
    crate::file_index::apply_local_meta_columns_in_tx(
        &tx,
        "g",
        path,
        &yadorilink_replica_domain::session_state::LocalFileMetaColumns {
            record_kind: version.meta.record_kind,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: Vec::new(),
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

/// A File at `a` and a descendant `a/x`: `a` has to be a directory.
fn file_with_a_descendant(c: &Connection) -> yadorilink_replica_domain::file::FileVersion {
    let file = file_version(1_000);
    let child = file_version(2_000);
    for v in [&file, &child] {
        crate::dag_store::put_file_version(c, "g", v).unwrap();
    }
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("a".into()), &[], payload_of(&file)).unwrap();
    state.put(&author("a"), SyncPath("a/x".into()), &[], payload_of(&child)).unwrap();
    crate::native_store::install_state(c, &group(), &state).unwrap();
    file
}

#[test]
fn a_winner_displaced_by_a_directory_is_placed_at_its_copy_name() {
    let c = conn();
    let file = file_with_a_descendant(&c);

    ensure_native_placements_around(&c, "g", "a/x").unwrap();

    let name = numbered_relocation_name("a", "a", file.version_hash.0, 1);
    let target = resolve_native_physical_path(&c, "g", &name).unwrap();
    assert!(target.is_none(), "no row shows it there yet, so nothing is displayed");
    write_row(&c, &name, &file);
    let target =
        resolve_native_physical_path(&c, "g", &name).unwrap().expect("the row shows the winner");
    assert_eq!(target.source_path, SyncPath("a".into()));
    assert_eq!(target.origin, PlacementOrigin::TreeRelocation);
    assert_eq!(target.payload.version, file.version_hash);
}

#[test]
fn a_displaced_winner_whose_copy_name_is_taken_gets_the_numbered_name() {
    let c = conn();
    let file = file_with_a_descendant(&c);
    let first = numbered_relocation_name("a", "a", file.version_hash.0, 1);
    stable_projection_binding::native_bind(
        &c,
        "g",
        &("z".to_string(), "other".to_string(), [2u8; 16], 9),
        &first,
    )
    .unwrap();

    ensure_native_placements_around(&c, "g", "a/x").unwrap();

    let second = numbered_relocation_name("a", "a", file.version_hash.0, 2);
    let placed: Vec<_> = stable_projection_binding::native_placements_for_source(&c, "g", "a")
        .unwrap()
        .into_iter()
        .map(|row| row.physical_path)
        .collect();
    assert_eq!(placed, vec![second]);
}

#[test]
fn a_reconciliation_hold_names_the_entry_until_its_row_is_replaced() {
    let c = conn();
    let file = file_version(1_000);
    crate::dag_store::put_file_version(&c, "g", &file).unwrap();
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("a".into()), &[], payload_of(&file)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "held copy", &file);

    assert!(record_native_reconciliation_hold(&c, "g", "held copy", "a").unwrap());

    let target = resolve_native_physical_path(&c, "g", "held copy").unwrap().expect("held");
    assert_eq!(target.origin, PlacementOrigin::ReconciliationHold);
    assert_eq!(target.source_path, SyncPath("a".into()));
    // The entry itself is gone from native, but the row still shows it.
    crate::native_store::install_state(&c, &group(), &NativeState::new()).unwrap();
    assert!(resolve_native_physical_path(&c, "g", "held copy").unwrap().is_some());
    // The reconciler removes the row: the placement means nothing now.
    c.execute("DELETE FROM files WHERE group_id = 'g' AND path = 'held copy'", []).unwrap();
    assert!(resolve_native_physical_path(&c, "g", "held copy").unwrap().is_none());
}

#[test]
fn a_hold_is_not_recorded_for_a_row_no_head_of_the_source_shows() {
    let c = conn();
    let file = file_version(1_000);
    let other = file_version(3_000);
    crate::dag_store::put_file_version(&c, "g", &file).unwrap();
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("a".into()), &[], payload_of(&file)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "held copy", &other);

    assert!(!record_native_reconciliation_hold(&c, "g", "held copy", "a").unwrap());
    assert!(resolve_native_physical_path(&c, "g", "held copy").unwrap().is_none());
}

#[test]
fn a_conflict_copy_whose_row_was_replaced_by_another_version_means_nothing_though_its_head_is_live()
{
    let c = conn();
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let loser_version = file_version(2_000);
    let winner_version = file_version(1_000);
    let replacement = file_version(3_000);
    for v in [&winner_version, &loser_version, &replacement] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let mut state = NativeState::new();
    state.put(&winner.author, SyncPath("x".into()), &[], payload_of(&winner_version)).unwrap();
    state.put(&loser.author, SyncPath("x".into()), &[], payload_of(&loser_version)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    ensure_native_placements_around(&c, "g", "x").unwrap();
    let copy = stable_projection_binding::native_placements_for_source(&c, "g", "x")
        .unwrap()
        .remove(0)
        .physical_path;

    // No row written yet: the live head keeps the placement.
    assert!(resolve_native_physical_path(&c, "g", &copy).unwrap().is_some());
    write_row(&c, &copy, &loser_version);
    assert!(resolve_native_physical_path(&c, "g", &copy).unwrap().is_some());
    // The materializer replaces the row with something else while the head
    // is still live.
    write_row(&c, &copy, &replacement);
    assert!(resolve_native_physical_path(&c, "g", &copy).unwrap().is_none());
}

#[test]
fn a_forgotten_placement_does_not_release_a_name_its_stable_binding_still_reserves() {
    let c = conn();
    // The larger version hash wins; `a` is the winner, `b` the bound loser.
    let (mut a, mut b) = (file_version(1_000), file_version(2_000));
    if a.version_hash < b.version_hash {
        std::mem::swap(&mut a, &mut b);
    }
    for v in [&a, &b] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let winner = dot("a", 1);
    let loser = dot("b", 1);
    let mut state = NativeState::new();
    state.put(&winner.author, SyncPath("x".into()), &[], payload_of(&a)).unwrap();
    state.put(&loser.author, SyncPath("x".into()), &[], payload_of(&b)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    ensure_native_placements_around(&c, "g", "x").unwrap();
    let bound =
        stable_projection_binding::native_bindings(&c, "g").unwrap().into_values().next().unwrap();
    // The row at the bound name was replaced: its placement goes stale.
    write_row(&c, &bound, &file_version(9_000));

    // A second loser with the same source, device and version content would
    // want the same first name; it must not get the reserved one.
    let mut again = NativeState::new();
    again.heads = state.heads.clone();
    // Its own delta has its own provenance; the smaller one leaves `b`'s head the
    // representative of the content, as the stale placement's owner.
    let later = HeadPayload { provenance: DeltaHash([0; 32]), ..payload_of(&b) };
    again.put(&dot("c", 1).author, SyncPath("x".into()), &[], later).unwrap();
    crate::native_store::install_state(&c, &group(), &again).unwrap();
    ensure_native_placements_around(&c, "g", "x").unwrap();

    let names: Vec<String> =
        stable_projection_binding::native_bindings(&c, "g").unwrap().into_values().collect();
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "two stable bindings share a name: {names:?}");
}

#[test]
fn a_hold_names_the_representative_of_the_version_class_it_shows() {
    let c = conn();
    let shared = file_version(1_000);
    crate::dag_store::put_file_version(&c, "g", &shared).unwrap();
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload_of(&shared)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload_of(&shared)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "held copy", &shared);

    assert!(record_native_reconciliation_hold(&c, "g", "held copy", "x").unwrap());

    let target = resolve_native_physical_path(&c, "g", "held copy").unwrap().unwrap();
    assert_eq!(target.dot.author, author("b"), "the higher-ranked head represents the class");
}

/// The row a capture was taken from can be replaced between capture and
/// commit while native's winner stays put; that capture is stale.
#[test]
fn a_row_that_shows_other_content_at_commit_makes_the_capture_stale() {
    let c = conn();
    let (v1, v2) = (file_version(1_000), file_version(2_000));
    for v in [&v1, &v2] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload_of(&v1)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    write_row(&c, "x", &v1);

    let witness = capture_native_witness(&c, &group(), "x").unwrap();
    assert_eq!(witness.shown_version, Some(v1.version_hash));
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Fresh
    );

    // The materializer replaces the row with other content; native is unchanged.
    write_row(&c, "x", &v2);
    assert_eq!(
        verify_native_capture_witness(&c, &group(), &witness).unwrap(),
        NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::RowChanged)
    );
}

/// A name a live entry of the level holds is never freed for a copy by
/// forgetting a stale placement that used to be there.
#[test]
fn forgetting_a_stale_placement_does_not_free_a_name_a_live_entry_holds() {
    let c = conn();
    let (winner, loser, squatter) = (file_version(1_000), file_version(2_000), file_version(3_000));
    for v in [&winner, &loser, &squatter] {
        crate::dag_store::put_file_version(&c, "g", v).unwrap();
    }
    let first = numbered_copy_name("x", loser.version_hash.0, 1);
    let mut state = NativeState::new();
    state.put(&author("a"), SyncPath("x".into()), &[], payload_of(&winner)).unwrap();
    state.put(&author("b"), SyncPath("x".into()), &[], payload_of(&loser)).unwrap();
    state.put(&author("z"), SyncPath(first.clone()), &[], payload_of(&squatter)).unwrap();
    crate::native_store::install_state(&c, &group(), &state).unwrap();
    // A stale relocation once held that name; nothing shows it any more.
    stable_projection_binding::native_placement_put(
        &c,
        "g",
        &stable_projection_binding::NativePlacementRow {
            physical_path: first.clone(),
            source_path: "old".into(),
            author: "a".into(),
            incarnation: [1; 16],
            seq: 99,
            provenance: [9; 32],
            version: winner.version_hash.0,
            origin: "tree_relocation".into(),
        },
    )
    .unwrap();

    // The level as its plan sees it: the live file holds `first`.
    let heads = heads_map(&[
        ("x", dot("a", 1), payload_of(&winner)),
        ("x", dot("b", 1), payload_of(&loser)),
        ("old", dot("a", 99), payload_of(&winner)),
    ]);
    let raw = BTreeMap::from([(
        SyncPath(first.clone()),
        PhysicalNode::Entry(yadorilink_replica_domain::native_materialize::PlacedEntry {
            kind: RecordKind::File,
            version: squatter.version_hash,
            source_dot: dot("z", 1),
            placement: Placement::AtPath,
        }),
    )]);
    ensure_native_projection_bindings(&c, "g", &heads, &raw).unwrap();

    let loser_names: Vec<String> =
        stable_projection_binding::native_placements_for_source(&c, "g", "x")
            .unwrap()
            .into_iter()
            .map(|row| row.physical_path)
            .collect();
    assert!(
        !loser_names.contains(&first),
        "the copy must not take the live file's name: {loser_names:?}"
    );
    assert_eq!(loser_names.len(), 1);
}
