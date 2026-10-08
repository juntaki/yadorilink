//! Randomized properties of the kernel over generated honest histories.
//!
//! A deterministic generator (no external property-testing dependency)
//! builds replicas whose authors write changes that pass the strict-safe
//! author-side check, then compares the kernel against a reference that
//! computes the heads straight from their definition over the history.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{default_conflict_path, op, path, Arena, Author, Change, ChangeData, TestState};
use yadorilink_dcf_kernel::basis_encoding::BasisEncoding;
use yadorilink_dcf_kernel::{
    full_join, in_basis, join, lands, recover_watermark, step, tip_overlay, value_patch,
    verify_strict_safe, BaseRelativeState, KernelPreservation, Protocol, SafeProtocol,
    StrictViolation,
};

const PATHS: [&str; 4] = ["a", "b", "c", "d"];
const SEEDS: u64 = 300;

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[usize::try_from(self.below(items.len() as u64)).unwrap()]
    }
}

#[derive(Clone)]
struct Replica {
    state: TestState,
    history: BTreeSet<Change>,
    tips: BTreeMap<Author, Change>,
}

impl Replica {
    fn new() -> Self {
        Self { state: TestState::empty(), history: BTreeSet::new(), tips: BTreeMap::new() }
    }
}

/// The basis of one path: a random subset of the current heads (own heads
/// included or not), written in a random compact encoding and decoded.
fn honest_basis(rng: &mut Rng, heads: &[Change]) -> Vec<Change> {
    let chosen: Vec<Change> = heads.iter().copied().filter(|_| rng.chance(50)).collect();
    let encoding = match rng.below(3) {
        0 if chosen.len() == heads.len() => BasisEncoding::AllCurrent,
        1 => BasisEncoding::Except(heads.iter().copied().filter(|x| !chosen.contains(x)).collect()),
        _ => BasisEncoding::Explicit(chosen.clone()),
    };
    if encoding == BasisEncoding::AllCurrent {
        assert!(encoding.encoded_members().is_empty());
    }
    let decoded = encoding.decode(heads);
    assert_eq!(decoded, chosen);
    decoded
}

/// A change by `author` that passes the strict-safe check against `st`.
fn honest_change(rng: &mut Rng, arena: &Arena, st: &TestState, author: Author) -> ChangeData {
    let mut data = common::change(author, st.watermark(&author) + 1, Vec::new());
    let mut paths = PATHS.to_vec();
    let touched = 1 + rng.below(3);
    for _ in 0..touched {
        let p = path(paths.remove(usize::try_from(rng.below(paths.len() as u64)).unwrap()));
        let basis = honest_basis(rng, st.heads_at(&p));
        let lands = rng.chance(75);
        if lands {
            data.versions.insert(p.clone(), rng.next());
        }
        for &source in &basis {
            let target = default_conflict_path(&p, &source);
            if !rng.chance(35) {
                continue;
            }
            data.versions.insert(target.clone(), arena.version(&source, &p));
            data.ops.push(op(&target, true, &[]));
            data.preservations.push(KernelPreservation {
                source_path: p.clone(),
                source,
                target_path: target,
            });
        }
        data.ops.push(op(&p, lands, &basis));
    }
    data
}

/// Heads straight from the definition: a change landing at `p` that no
/// member of the history lists in its basis at `p`. In a basis-closed
/// history one signed edge suffices for the transitive relation.
fn reference_heads(arena: &Arena, history: &BTreeSet<Change>, p: &String) -> BTreeSet<Change> {
    history
        .iter()
        .copied()
        .filter(|x| lands(arena, x, p))
        .filter(|x| !history.iter().any(|y| in_basis(arena, y, p, x)))
        .collect()
}

fn all_paths(arena: &Arena, history: &BTreeSet<Change>) -> BTreeSet<String> {
    history.iter().flat_map(|c| arena.ops(c).into_iter().map(|o| o.path)).collect()
}

fn head_set(st: &TestState, p: &String) -> BTreeSet<Change> {
    st.heads_at(p).iter().copied().collect()
}

/// Well-formed entries: no empty entry and no duplicate head. One author
/// may hold several heads at a path, since own heads need not be consumed.
fn assert_well_formed(st: &TestState) {
    for (p, heads) in &st.heads {
        assert!(!heads.is_empty(), "empty entry stored at {p}");
        let unique: BTreeSet<_> = heads.iter().collect();
        assert_eq!(unique.len(), heads.len(), "duplicate head at {p}");
    }
}

/// The represented heads and watermarks match the history.
fn assert_represents(arena: &Arena, st: &TestState, history: &BTreeSet<Change>) {
    for p in all_paths(arena, history) {
        assert_eq!(head_set(st, &p), reference_heads(arena, history, &p), "path {p}");
    }
    let mut counts: BTreeMap<Author, u64> = BTreeMap::new();
    for c in history {
        *counts.entry(arena.author(c)).or_default() += 1;
    }
    assert_eq!(st.watermarks, counts);
}

/// `strictSafe_conservation` and `preservation_target_keeps_heads`.
fn assert_conservation(arena: &Arena, pre: &TestState, post: &TestState, c: Change) {
    let preservations = arena.preservations(&c);
    for (p, heads) in &pre.heads {
        for x in heads {
            let stays = post.heads_at(p).contains(x);
            let preserved_as = preservations.iter().find(|e| &e.source_path == p && &e.source == x);
            let observed = in_basis(arena, &c, p, x) && preserved_as.is_none();
            let preserved = preserved_as.is_some_and(|e| {
                let q = &e.target_path;
                *q == arena.conflict_path(p, x)
                    && post.heads_at(q).contains(&c)
                    && lands(arena, &c, q)
                    && arena.version(&c, q) == arena.version(x, p)
            });
            assert!(stays || observed || preserved, "head {x} at {p} silently lost");
        }
    }
    for e in &preservations {
        for x in pre.heads_at(&e.target_path) {
            assert!(post.heads_at(&e.target_path).contains(x));
        }
    }
}

/// Mutations of an honest change that each break exactly one clause.
fn assert_mutations_refused(
    arena: &mut Arena,
    st: &TestState,
    honest: &ChangeData,
    history: &BTreeSet<Change>,
) {
    for (i, o) in honest.ops.iter().enumerate() {
        // Dropping an unpreserved own head from a basis is not a violation.
        let own = o.basis.iter().position(|x| {
            arena.author(x) == honest.author
                && !honest.preservations.iter().any(|e| e.source_path == o.path && &e.source == x)
        });
        if let Some(pos) = own {
            let mut kept = honest.clone();
            kept.ops[i].basis.remove(pos);
            let id = arena.push(kept);
            assert_eq!(verify_strict_safe(arena, st, &id), Ok(()));
        }
        let stale = history.iter().copied().find(|x| !st.heads_at(&o.path).contains(x));
        if let Some(member) = stale {
            let mut bad = honest.clone();
            bad.ops[i].basis.push(member);
            let id = arena.push(bad);
            let expected = StrictViolation::BasisNotCurrentHead { path: o.path.clone(), member };
            assert_eq!(verify_strict_safe(arena, st, &id), Err(expected));
        }
    }
    if let Some(e) = honest.preservations.first() {
        let mut bad = honest.clone();
        let v = bad.versions.entry(e.target_path.clone()).or_default();
        *v = v.wrapping_add(1);
        let id = arena.push(bad);
        let expected =
            StrictViolation::PreservationVersionMismatch { target_path: e.target_path.clone() };
        assert_eq!(verify_strict_safe(arena, st, &id), Err(expected));
    }
}

/// One verified step on `replica`, checking every step-level property.
fn honest_step(rng: &mut Rng, arena: &mut Arena, replica: &mut Replica, authors: &[Author]) {
    let author = rng.pick(authors);
    let data = honest_change(rng, arena, &replica.state, author);
    assert_mutations_refused(arena, &replica.state, &data, &replica.history);
    let c = arena.push(data);
    assert_eq!(verify_strict_safe(arena, &replica.state, &c), Ok(()));
    let post = step(arena, &replica.state, &c);
    assert_conservation(arena, &replica.state, &post, c);
    assert_well_formed(&post);
    replica.state = post;
    replica.history.insert(c);
    replica.tips.insert(author, c);
}

#[test]
fn verified_steps_stay_well_formed_represent_and_conserve() {
    for seed in 0..SEEDS {
        let mut rng = Rng(seed);
        let mut arena = Arena::default();
        let mut replica = Replica::new();
        for _ in 0..40 {
            honest_step(&mut rng, &mut arena, &mut replica, &[0, 1, 2]);
            assert_represents(&arena, &replica.state, &replica.history);
        }
    }
}

fn base_relative(base: &Replica, side: &Replica) -> BaseRelativeState<String, Change, Author> {
    BaseRelativeState {
        base: base.state.clone(),
        value_patch: value_patch(&base.state.heads, &side.state.heads),
        tip_patch: tip_overlay(&base.state.watermarks, &side.state.watermarks, &side.tips),
    }
}

fn same_heads(x: &TestState, y: &TestState) -> bool {
    let paths: BTreeSet<_> = x.heads.keys().chain(y.heads.keys()).collect();
    x.watermarks == y.watermarks && paths.iter().all(|p| head_set(x, p) == head_set(y, p))
}

/// Two fork-free branches: a common prefix, branch A by authors 0 and 1,
/// and branch B by authors 2 and 3 forked from a random point of A.
fn branches(rng: &mut Rng, arena: &mut Arena) -> (Replica, Replica, Replica, Replica) {
    let mut prefix = Replica::new();
    for _ in 0..rng.below(15) {
        honest_step(rng, arena, &mut prefix, &[0, 1, 2, 3]);
    }
    let mut a = prefix.clone();
    let mut snapshots = vec![a.clone()];
    for _ in 0..rng.below(15) {
        honest_step(rng, arena, &mut a, &[0, 1]);
        snapshots.push(a.clone());
    }
    let fork = snapshots.swap_remove(usize::try_from(rng.below(snapshots.len() as u64)).unwrap());
    let mut b = fork.clone();
    for _ in 0..rng.below(15) {
        honest_step(rng, arena, &mut b, &[2, 3]);
    }
    (prefix, fork, a, b)
}

#[test]
fn join_is_commutative_idempotent_and_exact() {
    for seed in 0..SEEDS {
        let mut rng = Rng(seed ^ 0xA5A5);
        let mut arena = Arena::default();
        let (prefix, fork, a, b) = branches(&mut rng, &mut arena);
        let ab = join(&arena, &a.state, &b.state);
        let ba = join(&arena, &b.state, &a.state);
        assert!(same_heads(&ab, &ba), "seed {seed}: join not commutative");
        assert_eq!(join(&arena, &a.state, &a.state), a.state);
        assert_eq!(join(&arena, &b.state, &b.state), b.state);
        assert_eq!(join(&arena, &a.state, &TestState::empty()), a.state);
        assert_eq!(join(&arena, &TestState::empty(), &a.state), a.state);
        assert_eq!(join(&arena, &ab, &ab), ab);
        assert_well_formed(&ab);
        let union: BTreeSet<Change> = a.history.union(&b.history).copied().collect();
        assert_represents(&arena, &ab, &union);

        // Cross-base: A relative to the prefix, B relative to its fork point.
        let left = base_relative(&prefix, &a);
        let right = base_relative(&fork, &b);
        assert_eq!(full_join(&arena, &left, &right), ab);
        for (author, w) in &a.state.watermarks {
            let recovered =
                recover_watermark(&arena, &left.base.watermarks, &left.tip_patch, author);
            assert_eq!(recovered, *w);
        }
    }
}

#[test]
fn joined_state_accepts_further_verified_steps() {
    for seed in 0..SEEDS / 3 {
        let mut rng = Rng(seed ^ 0x5A5A);
        let mut arena = Arena::default();
        let (_, _, a, b) = branches(&mut rng, &mut arena);
        let mut merged = Replica {
            state: join(&arena, &a.state, &b.state),
            history: a.history.union(&b.history).copied().collect(),
            // Tips are only read to build base-relative states, not here.
            tips: BTreeMap::new(),
        };
        for _ in 0..10 {
            honest_step(&mut rng, &mut arena, &mut merged, &[0, 1, 2, 3]);
            assert_represents(&arena, &merged.state, &merged.history);
        }
    }
}
