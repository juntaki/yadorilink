//! The model against itself: the properties the design relies on
//! (order independence, retirement monotonicity, version non-propagation,
//! checkpoint garbage collection) hold for the executable machine on generated
//! histories, and each of the three counterexamples breaks one of them.

use super::*;
use crate::native_state::Dot;

const SHAPE: Shape = Shape { authors: 3, paths: 3, deltas: 16, versions: 3 };

fn flat(scenario: &Scenario) -> Vec<KeepOp> {
    scenario.deltas.iter().flat_map(ops_of).collect()
}

fn permuted(rng: &mut Rng, ops: &[KeepOp]) -> Vec<KeepOp> {
    rng.permutation(ops.len()).into_iter().map(|i| ops[i].clone()).collect()
}

fn head(path: &str, seq: u64, provenance: u8) -> HeadId {
    HeadId {
        path: SyncPath(path.to_owned()),
        dot: Dot {
            author: AuthorId {
                device: DeviceId("device-x".into()),
                incarnation: IncarnationId([1; 16]),
            },
            seq: AuthorSeq(seq),
        },
        provenance: DeltaHash([provenance; 32]),
    }
}

/// What the generated histories reach, so the properties below are not
/// vacuous.
#[derive(Default)]
struct Coverage {
    kept_heads: usize,
    keeps_of_retired_heads: usize,
    same_version_pairs_one_kept: usize,
    same_version_pairs_both_kept: usize,
    wrongly_named_keeps: usize,
}

fn coverage_of(scenario: &Scenario, coverage: &mut Coverage) {
    let ops = flat(scenario);
    let closed = closed_of_ops(ops.clone());
    coverage.kept_heads += closed.kept.len();
    for op in &ops {
        match op {
            KeepOp::Keep(key) if !closed.live.contains_key(key) => {
                let named = ops.iter().any(|o| matches!(o, KeepOp::Put(k, _) if k == key));
                if named {
                    coverage.keeps_of_retired_heads += 1;
                } else {
                    coverage.wrongly_named_keeps += 1;
                }
            }
            _ => {}
        }
    }
    let live: Vec<(&HeadId, &VersionHash)> = closed.live.iter().collect();
    for (i, (a, va)) in live.iter().enumerate() {
        for (b, vb) in &live[i + 1..] {
            if a.path == b.path && va == vb {
                match (closed.kept.contains(*a), closed.kept.contains(*b)) {
                    (true, true) => coverage.same_version_pairs_both_kept += 1,
                    (true, false) | (false, true) => coverage.same_version_pairs_one_kept += 1,
                    (false, false) => {}
                }
            }
        }
    }
}

/// Order independence: the projection of the machine is the closed form, in every order and
/// with duplicated operations.
#[test]
fn the_machine_projects_the_closed_form_in_every_order() {
    let mut coverage = Coverage::default();
    for seed in 0..400u64 {
        let scenario = generate(seed, SHAPE);
        coverage_of(&scenario, &mut coverage);
        let ops = flat(&scenario);
        let closed = apply_closed(&scenario.deltas);
        assert!(closed.is_well_formed(), "seed {seed}");
        assert_eq!(model_apply(&ops).projection(), closed, "seed {seed}: generation order");
        let mut rng = Rng(seed);
        for round in 0..6 {
            let mut order = permuted(&mut rng, &ops);
            // Duplicate delivery of some operations.
            for _ in 0..rng.below(4) {
                let again = order[rng.below(order.len())].clone();
                let at = rng.below(order.len() + 1);
                order.insert(at, again);
            }
            assert_eq!(
                model_apply(&order).projection(),
                closed,
                "seed {seed} round {round}: the order changed the projection"
            );
        }
    }
    assert!(coverage.kept_heads > 100, "kept heads reached too rarely: {}", coverage.kept_heads);
    assert!(coverage.keeps_of_retired_heads > 20);
    assert!(coverage.same_version_pairs_one_kept > 20, "same-version siblings not exercised");
    assert!(coverage.same_version_pairs_both_kept > 5, "the cohort case not exercised");
    assert!(coverage.wrongly_named_keeps > 5, "no-op keeps not exercised");
}

/// Retirement is permanent: once a retire of a head is among the operations, the head is neither
/// live nor kept, whatever order a late put or keep of it arrives in.
#[test]
fn a_retired_head_never_comes_back() {
    let mut retired_seen = 0usize;
    for seed in 0..300u64 {
        let scenario = generate(seed, SHAPE);
        let ops = flat(&scenario);
        let mut rng = Rng(seed ^ 0x55);
        for _ in 0..4 {
            let order = permuted(&mut rng, &ops);
            let state = model_apply(&order);
            for op in &ops {
                if let KeepOp::Retire(key) = op {
                    retired_seen += 1;
                    assert!(state.retired.contains(key), "seed {seed}");
                    assert!(!state.live.contains_key(key), "seed {seed}: a retired head is live");
                    assert!(!state.keeps.contains(key), "seed {seed}: a retired head is kept");
                }
            }
        }
    }
    assert!(retired_seen > 500);
}

/// A keep names one head: a keep names one head. Another head with the same version at the same
/// path is not kept by it, whichever order they arrive in.
#[test]
fn a_keep_does_not_propagate_to_another_head_with_the_same_version() {
    let version = VersionHash([7; 32]);
    let (h1, h2) = (head("p", 1, 1), head("p", 2, 2));
    let ops = [KeepOp::Put(h1.clone(), version), KeepOp::Put(h2.clone(), version)];
    for order in [
        vec![ops[0].clone(), ops[1].clone(), KeepOp::Keep(h1.clone())],
        vec![KeepOp::Keep(h1.clone()), ops[1].clone(), ops[0].clone()],
        vec![ops[1].clone(), KeepOp::Keep(h1.clone()), ops[0].clone()],
    ] {
        let projection = model_apply(&order).projection();
        assert_eq!(projection.live.len(), 2);
        assert_eq!(projection.kept, BTreeSet::from([h1.clone()]));
        assert_eq!(
            projection.kept_versions(),
            BTreeSet::from([(SyncPath("p".into()), version)]),
            "the planner's kept version comes from the kept head"
        );
    }
    // With h1 retired and h2 alone, nothing is kept: a later head of the same
    // content inherits nothing.
    let after = model_apply(&[
        ops[0].clone(),
        KeepOp::Keep(h1.clone()),
        KeepOp::Retire(h1),
        ops[1].clone(),
    ])
    .projection();
    assert!(after.kept.is_empty() && after.kept_versions().is_empty());

    // Over generated histories: every kept head has a keep that names exactly it.
    for seed in 0..300u64 {
        let scenario = generate(seed, SHAPE);
        let ops = flat(&scenario);
        let closed = closed_of_ops(ops.clone());
        for key in &closed.kept {
            assert!(
                ops.iter().any(|op| matches!(op, KeepOp::Keep(k) if k == key)),
                "seed {seed}: {key:?} is kept without a keep naming it"
            );
        }
    }
}

/// The cohort an author declares: both heads of one version, each named, are
/// kept; the survivor of the cohort keeps the copy name after the other is
/// retired; a head put later without a keep is not kept.
#[test]
fn a_declared_cohort_survives_one_member_and_a_later_head_is_not_kept() {
    let version = VersionHash([3; 32]);
    let (h1, h2, h3) = (head("p", 1, 1), head("p", 2, 2), head("p", 3, 3));
    let ops = vec![
        KeepOp::Put(h1.clone(), version),
        KeepOp::Put(h2.clone(), version),
        KeepOp::Keep(h1.clone()),
        KeepOp::Keep(h2.clone()),
        KeepOp::Retire(h1),
        KeepOp::Put(h3.clone(), version),
    ];
    let projection = model_apply(&ops).projection();
    assert_eq!(projection.kept, BTreeSet::from([h2.clone()]), "H2 survives kept");
    assert!(projection.live.contains_key(&h3) && !projection.kept.contains(&h3));
    // H2 isolated (H3 never put): the version stays kept through H2.
    let alone = model_apply(&ops[..5]).projection();
    assert_eq!(alone.kept_versions(), BTreeSet::from([(SyncPath("p".into()), version)]));
    // H2 retired and H3 alone: not kept.
    let mut later = ops.clone();
    later.insert(5, KeepOp::Retire(h2));
    assert!(model_apply(&later).projection().kept_versions().is_empty());
}

/// Garbage collection: a checkpoint keeps the live heads and their keeps and drops every
/// tombstone and every other keep. For a causally closed covered set and the
/// replay-ignore filter, the compacted replica and the one holding full history
/// agree for every continuation, fresh operations and replays mixed.
#[test]
fn a_compacted_replica_agrees_with_one_that_kept_the_history() {
    let mut dropped_tombstones = 0usize;
    for seed in 0..300u64 {
        let scenario = generate(seed, SHAPE);
        let mut rng = Rng(seed ^ 0xABCD);
        for _ in 0..3 {
            let cut = rng.below(scenario.deltas.len() + 1);
            let covered: Vec<KeepOp> = scenario.deltas[..cut].iter().flat_map(ops_of).collect();
            assert!(
                causally_closed_in(&covered, &flat(&scenario)),
                "seed {seed}: a prefix of the generation order is causally closed"
            );
            let mut later: Vec<KeepOp> = scenario.deltas[cut..].iter().flat_map(ops_of).collect();
            for _ in 0..rng.below(6) {
                if !covered.is_empty() {
                    later.push(covered[rng.below(covered.len())].clone());
                }
            }
            let later = permuted(&mut rng, &later);

            let full = model_apply(&covered);
            dropped_tombstones += full.retired.len();
            let uncompacted = model_continue(full.clone(), &later).projection();
            let compacted = model_continue(gc(&full), &drop_covered(&covered, &later)).projection();
            assert_eq!(compacted, uncompacted, "seed {seed} cut {cut}");
            assert_eq!(uncompacted, apply_closed(&scenario.deltas), "seed {seed} cut {cut}");
        }
    }
    assert!(dropped_tombstones > 200, "the checkpoints dropped few tombstones");
}

/// Mutant: pruning a keep on absence makes arrival order matter. Dropping a keep whose head is not
/// live makes the projection depend on the order.
#[test]
fn the_naive_prune_mutant_is_order_dependent() {
    let h = head("p", 1, 1);
    let put = KeepOp::Put(h.clone(), VersionHash([1; 32]));
    let keep = KeepOp::Keep(h);
    assert_ne!(
        naive_prune_apply(&[keep.clone(), put.clone()]),
        naive_prune_apply(&[put.clone(), keep.clone()]),
        "keep before put loses the keep"
    );
    assert_eq!(
        model_apply(&[keep.clone(), put.clone()]).projection(),
        model_apply(&[put, keep]).projection()
    );
    let mut caught = 0usize;
    for seed in 0..200u64 {
        let scenario = generate(seed, SHAPE);
        let ops = flat(&scenario);
        let closed = apply_closed(&scenario.deltas);
        let mut rng = Rng(seed);
        if (0..6).any(|_| naive_prune_apply(&permuted(&mut rng, &ops)) != closed) {
            caught += 1;
        }
    }
    assert!(caught > 50, "the mutant diverged on only {caught} histories");
}

/// Mutant: dropping the removal record lets a late head come back. A retire that merely deletes lets a
/// late put resurrect the head.
#[test]
fn the_no_tombstone_mutant_resurrects_a_retired_head() {
    let h = head("p", 1, 1);
    let put = KeepOp::Put(h.clone(), VersionHash([1; 32]));
    let retire = KeepOp::Retire(h.clone());
    assert!(no_tombstone_apply(&[put.clone(), retire.clone()]).live.is_empty());
    assert!(no_tombstone_apply(&[retire.clone(), put.clone()]).live.contains_key(&h));
    assert!(model_apply(&[retire, put]).projection().live.is_empty());
    let mut caught = 0usize;
    for seed in 0..200u64 {
        let scenario = generate(seed, SHAPE);
        let ops = flat(&scenario);
        let closed = apply_closed(&scenario.deltas);
        let mut rng = Rng(seed);
        if (0..6).any(|_| no_tombstone_apply(&permuted(&mut rng, &ops)) != closed) {
            caught += 1;
        }
    }
    assert!(caught > 50, "the mutant diverged on only {caught} histories");
}

/// Mutant: collecting history without causal closure brings a head back. A checkpoint that covers a retire without
/// the put it retires lets the later put resurrect the head.
#[test]
fn garbage_collection_without_causal_closure_resurrects_a_head() {
    let h = head("p", 1, 1);
    let put = KeepOp::Put(h.clone(), VersionHash([1; 32]));
    let retire = KeepOp::Retire(h.clone());
    let covered = vec![retire];
    assert!(
        !causally_closed_in(&covered, &[put.clone(), covered[0].clone()]),
        "the covered set lacks the put it retires"
    );
    let later = vec![put.clone()];
    let full = model_apply(&covered);
    let compacted = model_continue(gc(&full), &drop_covered(&covered, &later)).projection();
    let uncompacted = model_continue(full, &later).projection();
    assert!(compacted.live.contains_key(&h), "the mutant resurrects the head");
    assert_ne!(compacted, uncompacted);
    // Closed (the put covered too), the same checkpoint is sound.
    let closed_cover = vec![put, covered[0].clone()];
    assert!(causally_closed(&closed_cover));
    let full = model_apply(&closed_cover);
    let later = vec![KeepOp::Put(h.clone(), VersionHash([1; 32]))];
    assert_eq!(
        model_continue(gc(&full), &drop_covered(&closed_cover, &later)).projection(),
        model_continue(full, &later).projection()
    );
}

/// The generated deltas are well-formed on the wire: they survive an encoding
/// round trip, which refuses duplicate, self-naming and contradictory keeps.
#[test]
fn generated_deltas_are_valid_on_the_wire() {
    for seed in 0..100u64 {
        let scenario = generate(seed, SHAPE);
        for delta in &scenario.deltas {
            let decoded = NativeDelta::from_wire_bytes(&delta.to_wire_bytes())
                .unwrap_or_else(|error| panic!("seed {seed}: {error}"));
            assert_eq!(&decoded, delta);
            decoded
                .verify_signature(
                    &scenario.keys[scenario.author_of
                        [scenario.deltas.iter().position(|d| d == delta).unwrap()]]
                    .verifying_key(),
                )
                .unwrap();
        }
    }
}
