//! Differential test of `native_materialize::project_own_node`
//! against DCF's own `yadorilink_replica_engine::namespace::
//! project_own_node`, over the same abstract per-path head set plus the
//! same `has_live_descendant` flag.
//!
//! Compares the *shape* of the result (absent / structural directory /
//! explicit directory / entry-at-path) and, for an entry or an explicit
//! directory, its kind/version — never a conflict-copy path string (see
//! `native_state::resolve_path`'s doc for why: DCF's naming embeds mtime,
//! which native does not track, by decision).

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, VersionHash};
use yadorilink_replica_domain::native_materialize::{
    self, DirectoryNode as NativeDirectoryNode, PhysicalNode as NativePhysicalNode,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadPayload, LiveHead};
use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};
use yadorilink_replica_engine::namespace::{project_own_node, DirectoryNode, PhysicalNode};

#[derive(Clone, Copy, Debug)]
struct HeadSpec {
    author: u8,
    tie_break_byte: u8,
    version_byte: u8,
    kind: RecordKind,
}

fn dcf_heads(specs: &[HeadSpec]) -> Vec<PathHead> {
    specs
        .iter()
        .map(|s| PathHead {
            change_hash: [s.tie_break_byte; 32],
            // DCF orders concurrent heads by rank; hand it the native win order.
            rank: u64::from(s.version_byte)
                + if s.kind == RecordKind::Directory { 1000 } else { 0 },
            device_id: format!("author-{}", s.author),
            naming_device_id: format!("author-{}", s.author),
            content: Some(PathHeadContent {
                version_hash: [s.version_byte; 32],
                mtime_unix_nanos: 0,
            }),
        })
        .collect()
}

fn native_heads(specs: &[HeadSpec]) -> Vec<LiveHead> {
    specs
        .iter()
        .enumerate()
        .map(|(seq, s)| LiveHead {
            dot: Dot {
                author: AuthorId {
                    device: DeviceId(format!("author-{}", s.author)),
                    incarnation: IncarnationId([1u8; 16]),
                },
                seq: AuthorSeq((seq + 1) as u64),
            },
            payload: HeadPayload {
                version: VersionHash([s.version_byte; 32]),
                provenance: DeltaHash([s.tie_break_byte; 32]),
            },
        })
        .collect()
}

fn kind_of_dcf(specs: &[HeadSpec]) -> impl Fn(&[u8; 32]) -> Option<RecordKind> + '_ {
    move |version_hash: &[u8; 32]| {
        specs.iter().find(|s| s.version_byte == version_hash[0]).map(|s| s.kind)
    }
}

fn kind_of_native(specs: &[HeadSpec]) -> impl Fn(&VersionHash) -> Option<RecordKind> + '_ {
    move |version: &VersionHash| {
        specs.iter().find(|s| s.version_byte == version.0[0]).map(|s| s.kind)
    }
}

/// A comparable, name-free shape of either side's result.
#[derive(Debug, PartialEq, Eq)]
enum Shape {
    Absent,
    StructuralDirectory,
    ExplicitDirectory { version_byte: u8 },
    EntryAtPath { kind: RecordKind, version_byte: u8 },
    Other, // a shape neither Absent/Structural/Explicit/EntryAtPath (e.g. a non-AtPath placement)
}

fn dcf_shape(node: Option<PhysicalNode>) -> Shape {
    match node {
        None => Shape::Absent,
        Some(PhysicalNode::Directory(DirectoryNode::Structural)) => Shape::StructuralDirectory,
        Some(PhysicalNode::Directory(DirectoryNode::Explicit { version_hash })) => {
            Shape::ExplicitDirectory { version_byte: version_hash[0] }
        }
        Some(PhysicalNode::Entry(entry))
            if entry.placement == yadorilink_replica_engine::namespace::Placement::AtPath =>
        {
            Shape::EntryAtPath { kind: entry.kind, version_byte: entry.version_hash[0] }
        }
        Some(PhysicalNode::Entry(_)) => Shape::Other,
    }
}

fn native_shape(node: Option<NativePhysicalNode>) -> Shape {
    match node {
        None => Shape::Absent,
        Some(NativePhysicalNode::Directory(NativeDirectoryNode::Structural)) => {
            Shape::StructuralDirectory
        }
        Some(NativePhysicalNode::Directory(NativeDirectoryNode::Explicit { version })) => {
            Shape::ExplicitDirectory { version_byte: version.0[0] }
        }
        Some(NativePhysicalNode::Entry(entry))
            if entry.placement == native_materialize::Placement::AtPath =>
        {
            Shape::EntryAtPath { kind: entry.kind, version_byte: entry.version.0[0] }
        }
        Some(NativePhysicalNode::Entry(_)) => Shape::Other,
    }
}

fn assert_agrees(specs: &[HeadSpec], has_live_descendant: bool) {
    let dcf_result =
        project_own_node("x", &dcf_heads(specs), has_live_descendant, kind_of_dcf(specs)).unwrap();
    let native_result = native_materialize::project_own_node(
        native_heads(specs),
        has_live_descendant,
        kind_of_native(specs),
    )
    .unwrap();
    assert_eq!(
        dcf_shape(dcf_result),
        native_shape(native_result),
        "shape must agree for {specs:?} has_live_descendant={has_live_descendant}"
    );
}

#[test]
fn no_heads_no_descendant_is_absent_on_both_sides() {
    assert_agrees(&[], false);
}

#[test]
fn live_descendant_alone_is_structural_on_both_sides() {
    assert_agrees(&[], true);
}

#[test]
fn a_lone_file_stays_at_path_on_both_sides() {
    assert_agrees(
        &[HeadSpec { author: 1, tie_break_byte: 1, version_byte: 1, kind: RecordKind::File }],
        false,
    );
}

#[test]
fn a_live_descendant_beats_a_file_on_both_sides() {
    assert_agrees(
        &[HeadSpec { author: 1, tie_break_byte: 1, version_byte: 1, kind: RecordKind::File }],
        true,
    );
}

#[test]
fn an_explicit_directory_beats_a_higher_version_file_on_both_sides() {
    assert_agrees(
        &[
            HeadSpec { author: 1, tie_break_byte: 1, version_byte: 9, kind: RecordKind::Directory },
            HeadSpec { author: 2, tie_break_byte: 2, version_byte: 200, kind: RecordKind::File },
        ],
        false,
    );
}

#[test]
fn a_directory_tombstone_with_a_live_descendant_stays_structural_on_both_sides() {
    // No directory head live at all (tombstoned away); only the
    // has_live_descendant flag keeps this a directory.
    assert_agrees(&[], true);
}

#[test]
fn two_directory_heads_pick_the_higher_version_on_both_sides() {
    assert_agrees(
        &[
            HeadSpec { author: 1, tie_break_byte: 1, version_byte: 5, kind: RecordKind::Directory },
            HeadSpec { author: 2, tie_break_byte: 2, version_byte: 6, kind: RecordKind::Directory },
        ],
        false,
    );
}

/// Randomized sweep, same distinct-tie-break-byte discipline as
/// `native_materialize_differential.rs` (a real change_hash/provenance is
/// effectively unique; deliberately colliding it tests an irrelevant
/// degenerate case, not a real divergence risk).
#[test]
fn randomized_agreement_over_many_head_sets_and_descendant_flags() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    let mut rng = Rng(0xFEED_5EED);
    for _ in 0..500 {
        let n = rng.below(5); // 0..=4 heads
        let specs: Vec<HeadSpec> = (0..n)
            .map(|i| {
                // A version is one kind of record, so the kind follows from the version.
                let version_byte = (rng.below(4) + 1) as u8;
                HeadSpec {
                    author: i as u8 + 1,
                    tie_break_byte: (i + 1) as u8,
                    version_byte,
                    kind: if version_byte == 4 { RecordKind::Directory } else { RecordKind::File },
                }
            })
            .collect();
        let has_live_descendant = rng.below(2) == 0;
        assert_agrees(&specs, has_live_descendant);
    }
}

/// Empirically settles what DCF's REAL `project_own_node` actually does once
/// a winner is renamed/deleted away and a single losing head remains alone
/// at the vacated path.
///
/// `project_own_node` decides `Placement::AtPath` vs.
/// `Placement::ConflictCopy` purely from the CURRENT head set it is
/// handed for that path (`is_winner` = highest version among what is
/// passed in) -- it has no memory of a head that used to be there and
/// is gone. So once only ONE head remains live at a path, DCF's real
/// function has no way to keep displaying it under a conflict-copy-
/// styled name: it is unconditionally promoted to `Placement::AtPath`.
/// This test proves that empirically: a lone survivor is promoted --
/// for EITHER a delete or a
/// rename-away of the winner, since both leave the exact same "one
/// head remains" input to this function.
///
/// **Resolved by the stable projection binding**: this promoting behavior, proven
/// here at the PURE resolver level, is now understood to be a bug in
/// DCF's shipping code, not the target semantics for either side. The
/// causal layer this test exercises (`project_own_node` itself, and
/// native's `Op::Move` translation leaving the loser's own dot untouched)
/// is CORRECTLY left exactly as this test still proves it behaves --
/// neither gets "memory" added to it. What changed is a NEW layer ABOVE
/// both: stable projection binding, consulted by the real production
/// call sites (`desired_state::desired_namespace_projection`/
/// `desired_path_state` for DCF; `native_shadow_comparison`'s override
/// for native), which suppresses exactly this promotion once a head has
/// already been recorded as a loser once. See `desired_state::tests::
/// r2_r3_a_loser_conflict_copy_stays_put_when_the_winner_departs` and
/// `native_shadow_comparison::tests::
/// r2_r3_native_a_bound_loser_is_never_promoted_once_alone` for the
/// system-level (not pure-resolver-level) behavior this test's own
/// finding motivated.
#[test]
fn a_lone_surviving_loser_is_promoted_to_at_path_on_both_sides_once_the_winner_is_gone() {
    let winner_and_loser = [
        HeadSpec { author: 1, tie_break_byte: 1, version_byte: 9, kind: RecordKind::File }, // winner
        HeadSpec { author: 2, tie_break_byte: 2, version_byte: 5, kind: RecordKind::File }, // loser
    ];
    // Before: two heads at "foo" -- the loser must be ConflictCopy on
    // both sides (sanity check the setup is a real conflict).
    let before_dcf = project_own_node(
        "foo",
        &dcf_heads(&winner_and_loser),
        false,
        kind_of_dcf(&winner_and_loser),
    )
    .unwrap();
    let loser_before = match before_dcf {
        Some(PhysicalNode::Entry(e))
            if e.placement == yadorilink_replica_engine::namespace::Placement::AtPath =>
        {
            e
        }
        _ => panic!("expected the winner AtPath before any move: {before_dcf:?}"),
    };
    assert_eq!(
        loser_before.version_hash[0], 9,
        "sanity: the higher version is the winner before the move"
    );

    // After: only the loser's head remains at "foo" (as if the winner's
    // head had moved to "bar" -- exactly what a real rename does
    // causally, on both DCF's and native's own model: the winner's head
    // leaves `foo`'s head set entirely, the loser's head is untouched).
    let loser_alone = [winner_and_loser[1]];
    let after_dcf =
        project_own_node("foo", &dcf_heads(&loser_alone), false, kind_of_dcf(&loser_alone))
            .unwrap();
    let after_native = native_materialize::project_own_node(
        native_heads(&loser_alone),
        false,
        kind_of_native(&loser_alone),
    )
    .unwrap();

    let dcf_placement = match after_dcf {
        Some(PhysicalNode::Entry(e)) => e.placement,
        other => panic!("expected an entry, got {other:?}"),
    };
    let native_placement = match after_native {
        Some(NativePhysicalNode::Entry(e)) => e.placement,
        other => panic!("expected an entry, got {other:?}"),
    };
    assert_eq!(
        dcf_placement,
        yadorilink_replica_engine::namespace::Placement::AtPath,
        "DCF's real project_own_node promotes the lone surviving loser to AtPath -- it has no memory of the departed winner"
    );
    assert_eq!(
        native_placement,
        native_materialize::Placement::AtPath,
        "native's pure resolver matches DCF's pure resolver here (both promote) -- this is now understood to be exactly the bug the \
         stable-projection-binding override layer exists to suppress at the system level, not the target behavior"
    );
}
