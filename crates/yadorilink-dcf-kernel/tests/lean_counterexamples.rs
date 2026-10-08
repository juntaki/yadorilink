//! The concrete examples the Lean development decides, replayed on the
//! kernel, plus one example per author-side refusal clause.

mod common;

use common::{change, op, path, Arena, ChangeData, TestState};
use yadorilink_dcf_kernel::{
    step, verify_strict, verify_strict_safe, KernelPreservation, StrictViolation,
};

const ALICE: u8 = 0;
const BOB: u8 = 1;
const CAROL: u8 = 2;

fn replay(arena: &Arena, changes: &[u32]) -> TestState {
    changes.iter().fold(TestState::empty(), |st, c| step(arena, &st, c))
}

#[test]
fn basis_check_needed() {
    let mut arena = Arena::default();
    let b = arena.push(change(BOB, 1, vec![op("u", true, &[])]));
    let c = arena.push(change(CAROL, 1, vec![op("u", true, &[b])]));
    assert_eq!(replay(&arena, &[b, c]).heads_at(&path("u")), &[c]);
    // Stepping the superseder first leaves the basis member as a head: the
    // result depends on arrival order unless membership is checked.
    assert_eq!(replay(&arena, &[c, b]).heads_at(&path("u")), &[c, b]);
}

/// An author's own current head need not be in the basis, so one author
/// may hold several heads at a path; the per-author bound is enforced when a
/// base is sealed, not by the author-side check.
///
#[test]
fn own_heads_may_stay_unresolved() {
    let mut arena = Arena::default();
    let a1 = arena.push(change(ALICE, 1, vec![op("u", true, &[])]));
    let a2 = arena.push(change(ALICE, 2, vec![op("u", true, &[])]));
    let a3 = arena.push(change(ALICE, 3, vec![op("u", true, &[])]));
    assert_eq!(replay(&arena, &[a1, a2, a3]).heads_at(&path("u")), &[a1, a2, a3]);
    assert_eq!(verify_strict(&arena, &replay(&arena, &[a1]), &a2), Ok(()));
    assert_eq!(verify_strict(&arena, &replay(&arena, &[a1, a2]), &a3), Ok(()));
}

#[test]
fn basis_heads_needed() {
    let mut arena = Arena::default();
    let b1 = arena.push(change(BOB, 1, vec![op("u", true, &[])]));
    let b2 = arena.push(change(BOB, 2, vec![op("u", true, &[b1])]));
    let c = arena.push(change(CAROL, 1, vec![op("u", true, &[b1, b2])]));
    let after_b2 = replay(&arena, &[b1, b2]);
    assert_eq!(after_b2.heads_at(&path("u")), &[b2]);
    assert_eq!(
        verify_strict(&arena, &after_b2, &c),
        Err(StrictViolation::BasisNotCurrentHead { path: path("u"), member: b1 })
    );
}

fn q_conflict(_: &String, _: &u32) -> String {
    path("q")
}

/// Lean `SafeExample.proto v`: Alice's `a1` and Bob's `b1` are concurrent at
/// `p`; Alice's `c` observes `b1`, consumes her own `a1` and preserves it
/// at `q` with version `v`.
fn safe_example(v: u64) -> (Arena, u32, u32, u32) {
    let mut arena = Arena { conflict: q_conflict, ..Arena::default() };
    let mut a1 = change(ALICE, 1, vec![op("p", true, &[])]);
    a1.versions.insert(path("p"), 10);
    let a1 = arena.push(a1);
    let mut b1 = change(BOB, 1, vec![op("p", true, &[])]);
    b1.versions.insert(path("p"), 20);
    let b1 = arena.push(b1);
    let mut c = change(ALICE, 2, vec![op("p", true, &[a1, b1]), op("q", true, &[])]);
    c.versions.insert(path("p"), 30);
    c.versions.insert(path("q"), v);
    c.preservations =
        vec![KernelPreservation { source_path: path("p"), source: a1, target_path: path("q") }];
    let c = arena.push(c);
    (arena, a1, b1, c)
}

#[test]
fn preserving_edit_accepted() {
    let (arena, a1, b1, c) = safe_example(10);
    let pre = replay(&arena, &[a1, b1]);
    assert_eq!(pre.heads_at(&path("p")), &[a1, b1]);
    assert_eq!(verify_strict_safe(&arena, &pre, &c), Ok(()));
    let post = step(&arena, &pre, &c);
    assert_eq!(post.heads_at(&path("p")), &[c]);
    assert_eq!(post.heads_at(&path("q")), &[c]);
}

#[test]
fn wrong_version_rejected() {
    let (arena, a1, b1, c) = safe_example(99);
    let pre = replay(&arena, &[a1, b1]);
    assert_eq!(
        verify_strict_safe(&arena, &pre, &c),
        Err(StrictViolation::PreservationVersionMismatch { target_path: path("q") })
    );
}

/// A pre-state with Bob's `b1` at `p` and a check of `data` against it.
fn check_against_b1(
    build: impl FnOnce(u32) -> ChangeData,
) -> Result<(), StrictViolation<String, u32>> {
    let mut arena = Arena::default();
    let mut b1 = change(BOB, 1, vec![op("p", true, &[])]);
    b1.versions.insert(path("p"), 20);
    let b1 = arena.push(b1);
    let pre = replay(&arena, &[b1]);
    let c = arena.push(build(b1));
    verify_strict_safe(&arena, &pre, &c)
}

fn preserve_b1(b1: u32, target: &str) -> KernelPreservation<String, u32> {
    KernelPreservation { source_path: path("p"), source: b1, target_path: path(target) }
}

type CaseBuilder = Box<dyn FnOnce(u32) -> ChangeData>;

#[test]
fn each_refusal_clause_is_reported() {
    // `b1` is change 0, so its canonical conflict path at `p` is `p~0`.
    assert_eq!(common::default_conflict_path(&path("p"), &0), "p~0");
    let cases: Vec<(CaseBuilder, StrictViolation<String, u32>)> = vec![
        (
            Box::new(|_| change(ALICE, 2, vec![op("p", true, &[])])),
            StrictViolation::SeqNotNext { expected: 1, got: 2 },
        ),
        (
            Box::new(|_| change(ALICE, 1, vec![op("x", true, &[]), op("x", false, &[])])),
            StrictViolation::DuplicateTouchedPath { path: path("x") },
        ),
        (
            Box::new(|b1| change(ALICE, 1, vec![op("p", true, &[b1, b1])])),
            StrictViolation::DuplicateBasisMember { path: path("p"), member: 0 },
        ),
        (
            Box::new(|b1| {
                let mut c = change(ALICE, 1, vec![op("p", true, &[b1]), op("p~0", true, &[])]);
                c.preservations = vec![preserve_b1(b1, "p~0"), preserve_b1(b1, "p~0")];
                c
            }),
            StrictViolation::DuplicatePreservationTarget { target_path: path("p~0") },
        ),
        (
            Box::new(|b1| {
                let mut c = change(ALICE, 1, vec![op("p", true, &[]), op("p~0", true, &[])]);
                c.preservations = vec![preserve_b1(b1, "p~0")];
                c
            }),
            StrictViolation::PreservationSourceNotInBasis { source_path: path("p"), source: 0 },
        ),
        (
            Box::new(|b1| {
                let mut c =
                    change(ALICE, 1, vec![op("p", true, &[b1]), op("elsewhere", true, &[])]);
                c.preservations = vec![preserve_b1(b1, "elsewhere")];
                c
            }),
            StrictViolation::PreservationTargetNotCanonical { target_path: path("elsewhere") },
        ),
        (
            Box::new(|b1| {
                let mut c = change(ALICE, 1, vec![op("p", true, &[b1]), op("p~0", false, &[])]);
                c.preservations = vec![preserve_b1(b1, "p~0")];
                c
            }),
            StrictViolation::PreservationTargetNotLanded { target_path: path("p~0") },
        ),
    ];
    for (build, expected) in cases {
        assert_eq!(check_against_b1(build), Err(expected));
    }
}

#[test]
fn preservation_target_with_basis_is_refused() {
    // The target holds Bob's earlier head so a basis there passes the strict
    // clauses and only the preservation clause refuses it.
    let mut arena = Arena::default();
    let mut b1 = change(BOB, 1, vec![op("p", true, &[]), op("p~1", true, &[])]);
    b1.versions.insert(path("p"), 20);
    let b1 = arena.push(b1);
    let mut b2 = change(BOB, 2, vec![op("p", true, &[b1])]);
    b2.versions.insert(path("p"), 21);
    let b2 = arena.push(b2);
    let pre = replay(&arena, &[b1, b2]);
    let mut c = change(ALICE, 1, vec![op("p", true, &[b2]), op("p~1", true, &[b1])]);
    c.versions.insert(path("p~1"), 21);
    c.preservations =
        vec![KernelPreservation { source_path: path("p"), source: b2, target_path: path("p~1") }];
    arena.conflict = |_, _| path("p~1");
    let c = arena.push(c);
    assert_eq!(
        verify_strict_safe(&arena, &pre, &c),
        Err(StrictViolation::PreservationTargetHasBasis { target_path: path("p~1") })
    );
}
