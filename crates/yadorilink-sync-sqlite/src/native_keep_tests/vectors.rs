//! The reference model and the real store against an independently produced
//! set of reference vectors (`keep_vectors.json`, see `VECTOR_FILE`).
//!
//! Each vector gives a small universe of heads and, for three orderings of one
//! multiset of operations (put, keep, retire; with duplicates, late keeps and
//! retires, and same-version heads at new dots), the projection after every
//! prefix and the final projection. The vectors also carry three families of
//! deliberately broken variants (a keep pruned on absence, a retire without a
//! tombstone, and checkpoint collection without causal closure) with the
//! projections the broken variant produces.
//!
//! What is checked:
//!
//! * the reference model reproduces every prefix projection of every ordering
//!   (it is the same machine, including the retirement tombstone, so even an
//!   ordering that delivers a keep before its put matches);
//! * the real store reproduces the expected projection after every delivery
//!   of an *admissible* ordering. An ordering is admissible when every keep or
//!   retire is preceded by a put at the dot it names: the store holds a delta
//!   that names a dot it has not observed, so these are exactly the orderings
//!   it applies without holding. The vectors mark them; the store must not
//!   hold anything while delivering one. For the other orderings the store
//!   must hold at least once and end at the same final projection. The
//!   tombstone of the machine is derived in the store (a retired head is one
//!   whose dot is observed and which is not live), so a repeated put after a
//!   retire is a duplicate delivery there and a tombstoned no-op in the model;
//! * each broken variant in the model produces exactly the vector's
//!   projections and diverges across orderings (or from the unbroken
//!   checkpoint), where the unbroken machine does not.
//!
//! A vector `head` is `[path, author, incarnation, seq, provenance, version]`
//! as small integers. In the model they map directly to a head key. In the
//! store each distinct dot becomes its own single-delta author (so a put never
//! waits on an author's earlier sequence numbers, which the generated-history
//! tests cover), and the provenance of a put head is the hash of the delta that
//! puts it; a keep or retire naming provenance `0` of a head that is put uses
//! that hash, any other naming uses a header no head has, which is a no-op
//! exactly as in the model.
//!
//! The vector file is only present in a checkout that carries it; without it
//! the tests report that they are skipped. Set `YADORILINK_REQUIRE_KEEP_VECTORS`
//! to make a missing file a failure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_keep_model::{
    causally_closed, causally_closed_in, closed_of_ops, drop_covered, gc, model_apply,
    model_continue, naive_prune_apply, no_tombstone_apply, KeepOp, Projection,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadId};
use yadorilink_replica_domain::signed_delta::{HeadRef, NativeDelta};

use super::handwritten::{lookup_for, op, party, put_op, sign, Party};
use super::{admit_native_delta, group, projection_of, store, NativeAdmission};

const VECTOR_FILE: &str = "../../proofs/native-keep/vectors/keep_vectors.json";

fn load() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTOR_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).expect("the reference vectors parse")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            assert!(
                std::env::var_os("YADORILINK_REQUIRE_KEEP_VECTORS").is_none(),
                "the reference vectors are required but missing: {path:?}"
            );
            eprintln!("SKIPPED: the reference vectors are not in this checkout ({path:?})");
            None
        }
        Err(error) => panic!("reading {path:?}: {error}"),
    }
}

#[derive(Clone, Copy)]
struct Head {
    path: u64,
    author: u64,
    incarnation: u64,
    seq: u64,
    provenance: u64,
    version: u64,
}

type Ops = Vec<(u64, usize)>;
type Idx = (BTreeSet<usize>, BTreeSet<usize>);

fn num(value: &Value) -> u64 {
    value.as_u64().expect("a small integer")
}

fn heads_of(value: &Value) -> Vec<Head> {
    value["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .map(|head| {
            let n: Vec<u64> = head.as_array().expect("head").iter().map(num).collect();
            Head {
                path: n[0],
                author: n[1],
                incarnation: n[2],
                seq: n[3],
                provenance: n[4],
                version: n[5],
            }
        })
        .collect()
}

fn ops_in(value: &Value) -> Ops {
    value
        .as_array()
        .expect("ops")
        .iter()
        .map(|o| {
            let o = o.as_array().expect("op");
            (num(&o[0]), num(&o[1]) as usize)
        })
        .collect()
}

fn idx_set(value: &Value) -> BTreeSet<usize> {
    value.as_array().expect("indices").iter().map(|i| num(i) as usize).collect()
}

fn proj_in(value: &Value) -> Idx {
    (idx_set(&value[0]), idx_set(&value[1]))
}

fn version_of(head: &Head) -> VersionHash {
    VersionHash([head.version as u8 + 1; 32])
}

fn path_of(head: &Head) -> SyncPath {
    SyncPath(format!("p{}", head.path))
}

/// The model's key of a vector head, read directly off its fields.
fn model_key(head: &Head) -> HeadId {
    HeadId {
        path: path_of(head),
        dot: Dot {
            author: AuthorId {
                device: DeviceId(format!("a{}", head.author)),
                incarnation: IncarnationId([head.incarnation as u8; 16]),
            },
            seq: AuthorSeq(head.seq),
        },
        provenance: DeltaHash([head.provenance as u8; 32]),
    }
}

fn model_ops(heads: &[Head], ops: &Ops) -> Vec<KeepOp> {
    ops.iter()
        .map(|(kind, i)| {
            let key = model_key(&heads[*i]);
            match kind {
                0 => KeepOp::Put(key, version_of(&heads[*i])),
                1 => KeepOp::Keep(key),
                2 => KeepOp::Retire(key),
                other => panic!("unknown op kind {other}"),
            }
        })
        .collect()
}

fn model_projection(heads: &[Head], (live, kept): &Idx) -> Projection {
    Projection {
        live: live.iter().map(|i| (model_key(&heads[*i]), version_of(&heads[*i]))).collect(),
        kept: kept.iter().map(|i| model_key(&heads[*i])).collect(),
    }
}

fn expected_final(case: &Value) -> Idx {
    (idx_set(&case["live"]), idx_set(&case["kept"]))
}

#[derive(Default)]
struct Seen {
    cases: usize,
    model_steps: usize,
    store_orders: usize,
    store_admissible: usize,
    store_held_orders: usize,
    store_steps: usize,
    duplicates: usize,
    nonempty_kept: usize,
}

/// A case realised as signed deltas: one delta per distinct operation.
struct Realised {
    parties: Vec<Party>,
    deltas: BTreeMap<(u64, usize), (usize, NativeDelta)>,
    /// The real key of each head that some put creates, and its index.
    keys: BTreeMap<HeadId, usize>,
}

/// The single-delta authors of a case, one per distinct dot and per keep or
/// retire.
#[derive(Default)]
struct Registry {
    parties: Vec<Party>,
    by_name: BTreeMap<String, usize>,
}

impl Registry {
    fn get(&mut self, name: String) -> usize {
        if let Some(i) = self.by_name.get(&name) {
            return *i;
        }
        self.parties.push(party(&name, self.parties.len() as u8 + 1));
        self.by_name.insert(name, self.parties.len() - 1);
        self.parties.len() - 1
    }
}

fn dot_name(head: &Head) -> String {
    format!("d{}-i{}-s{}", head.author, head.incarnation, head.seq)
}

fn realise(heads: &[Head], ops: &Ops) -> Realised {
    let mut registry = Registry::default();
    let mut distinct: Vec<(u64, usize)> = ops.clone();
    distinct.sort();
    distinct.dedup();

    let mut deltas: BTreeMap<(u64, usize), (usize, NativeDelta)> = BTreeMap::new();
    let mut real: BTreeMap<usize, HeadId> = BTreeMap::new();
    for (kind, i) in distinct.iter().filter(|(kind, _)| *kind == 0) {
        let head = &heads[*i];
        let who = registry.get(dot_name(head));
        let delta = sign(
            &registry.parties[who],
            1,
            None,
            vec![put_op(&format!("p{}", head.path), head.version as u8 + 1)],
        );
        real.insert(
            *i,
            HeadId { path: path_of(head), dot: delta.dot(), provenance: delta.delta_hash() },
        );
        deltas.insert((*kind, *i), (who, delta));
    }
    for (kind, i) in distinct.iter().filter(|(kind, _)| *kind != 0) {
        let head = &heads[*i];
        // The dot the head names (a dot nothing puts is never observed) and the
        // header: the hash of the delta that puts it, or one no head has.
        let at = registry.get(dot_name(head));
        let dot = Dot { author: registry.parties[at].id.clone(), seq: AuthorSeq(1) };
        let header = match real.get(i) {
            Some(key) if head.provenance == 0 => key.provenance,
            _ => DeltaHash([0xE0 + head.provenance as u8; 32]),
        };
        let name = if *kind == 1 { format!("keep-{i}") } else { format!("retire-{i}") };
        let who = registry.get(name);
        let mut o = op(&format!("p{}", head.path));
        if *kind == 1 {
            o.keeps = vec![HeadRef { dot, provenance: header }];
        } else {
            o.removes = vec![HeadRef { dot, provenance: header }];
        }
        let delta = sign(&registry.parties[who], 1, None, vec![o]);
        deltas.insert((*kind, *i), (who, delta));
    }
    let keys = real.into_iter().map(|(i, key)| (key, i)).collect();
    Realised { parties: registry.parties, deltas, keys }
}

fn store_idx(realised: &Realised, heads: &[Head], projection: &Projection) -> Idx {
    let index = |key: &HeadId| {
        *realised.keys.get(key).unwrap_or_else(|| panic!("the store shows an unknown head {key:?}"))
    };
    let live = projection
        .live
        .iter()
        .map(|(key, version)| {
            let i = index(key);
            assert_eq!(*version, version_of(&heads[i]), "the store's version of head {i}");
            i
        })
        .collect();
    let kept = projection.kept.iter().map(index).collect();
    (live, kept)
}

fn check_model(heads: &[Head], order: &Value, id: u64, order_no: usize, seen: &mut Seen) {
    let ops = ops_in(&order["ops"]);
    let model = model_ops(heads, &ops);
    let prefix = order["prefix"].as_array().expect("prefix");
    assert_eq!(prefix.len(), ops.len(), "case {id} order {order_no}: one projection per step");
    for (step, expected) in prefix.iter().enumerate() {
        let want = model_projection(heads, &proj_in(expected));
        assert!(want.is_well_formed(), "case {id}: an expected keep names a head that is not live");
        let got = model_apply(&model[..=step]).projection();
        assert_eq!(got, want, "case {id} order {order_no} step {step}: the model differs");
        assert_eq!(
            closed_of_ops(model[..=step].iter().cloned()),
            want,
            "case {id} order {order_no} step {step}: the closed form differs"
        );
        seen.model_steps += 1;
    }
}

fn check_store(
    heads: &[Head],
    realised: &Realised,
    order: &Value,
    final_idx: &Idx,
    id: u64,
    order_no: usize,
    seen: &mut Seen,
) {
    let ops = ops_in(&order["ops"]);
    let admissible = order["admissible"].as_bool().expect("admissible");
    let prefix = order["prefix"].as_array().expect("prefix");
    let parties: Vec<&Party> = realised.parties.iter().collect();
    let lookup = lookup_for(&parties);
    let c = store();
    let mut held = false;
    for (step, (kind, i)) in ops.iter().enumerate() {
        let (_, delta) = &realised.deltas[&(*kind, *i)];
        let label = format!("case {id} order {order_no} step {step}");
        match admit_native_delta(&c, &group(), delta, &lookup).unwrap() {
            NativeAdmission::Admitted { .. } => {}
            NativeAdmission::Duplicate => seen.duplicates += 1,
            NativeAdmission::Held { .. } => {
                assert!(!admissible, "{label}: the store held a delta of an admissible ordering");
                held = true;
            }
            other => panic!("{label}: unexpected outcome {other:?}"),
        }
        if admissible {
            let got = store_idx(realised, heads, &projection_of(&c));
            assert_eq!(got, proj_in(&prefix[step]), "{label}: the store differs from the vectors");
            seen.store_steps += 1;
        }
    }
    let got = store_idx(realised, heads, &projection_of(&c));
    assert_eq!(&got, final_idx, "case {id} order {order_no}: the store's final projection");
    if !admissible {
        assert!(held, "case {id} order {order_no}: a keep or retire before its put was not held");
        seen.store_held_orders += 1;
    }
    seen.store_orders += 1;
    seen.store_admissible += usize::from(admissible);
}

#[test]
fn the_model_and_the_store_reproduce_the_reference_vectors() {
    let Some(vectors) = load() else { return };
    assert_eq!(vectors["format"], "native-keep-vectors/1");
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 300, "too few order cases: {}", cases.len());
    let mut seen = Seen::default();
    for case in cases {
        let id = num(&case["id"]);
        let heads = heads_of(case);
        let final_idx = expected_final(case);
        let want = model_projection(&heads, &final_idx);
        assert!(want.is_well_formed(), "case {id}: a kept head is not live");
        seen.nonempty_kept += usize::from(!final_idx.1.is_empty());
        let orders = case["orders"].as_array().expect("orders");
        assert_eq!(orders.len(), 3, "case {id}: three orderings");
        for (order_no, order) in orders.iter().enumerate() {
            check_model(&heads, order, id, order_no, &mut seen);
            let model = model_ops(&heads, &ops_in(&order["ops"]));
            assert_eq!(
                model_apply(&model).projection(),
                want,
                "case {id} order {order_no}: orderings of one multiset must agree"
            );
            let realised = realise(&heads, &ops_in(&order["ops"]));
            check_store(&heads, &realised, order, &final_idx, id, order_no, &mut seen);
        }
        seen.cases += 1;
    }
    assert!(seen.store_admissible >= 300, "admissible orderings: {}", seen.store_admissible);
    assert!(seen.store_held_orders >= 100, "held orderings: {}", seen.store_held_orders);
    assert!(seen.duplicates >= 100, "duplicate deliveries: {}", seen.duplicates);
    assert!(seen.nonempty_kept >= 50, "cases ending with a kept head: {}", seen.nonempty_kept);
    eprintln!(
        "reference vectors: {} cases, {} model steps, {} store orderings ({} admissible, {} held), {} store steps",
        seen.cases,
        seen.model_steps,
        seen.store_orders,
        seen.store_admissible,
        seen.store_held_orders,
        seen.store_steps
    );
}

#[test]
fn the_broken_variants_diverge_from_the_reference_vectors_as_expected() {
    let Some(vectors) = load() else { return };
    let mutants = vectors["mutants"].as_array().expect("mutants");
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    for case in mutants {
        let kind = case["kind"].as_str().expect("kind").to_owned();
        let id = num(&case["id"]);
        let heads = heads_of(case);
        assert!(case["expect_diverges"].as_bool().is_some());
        match kind.as_str() {
            "naive_prune" | "no_tombstone" => {
                let broken: fn(&[KeepOp]) -> Projection =
                    if kind == "naive_prune" { naive_prune_apply } else { no_tombstone_apply };
                let correct = model_projection(&heads, &proj_in(&case["correct"]));
                let mut outputs = BTreeSet::new();
                for order in case["orders"].as_array().expect("orders") {
                    let ops = model_ops(&heads, &ops_in(&order["ops"]));
                    let got = broken(&ops);
                    assert_eq!(
                        got,
                        model_projection(&heads, &proj_in(&order["proj"])),
                        "{kind} {id}: the broken variant differs from the vectors"
                    );
                    assert_eq!(
                        model_apply(&ops).projection(),
                        correct,
                        "{kind} {id}: the unbroken model differs from the vectors"
                    );
                    outputs.insert(format!("{got:?}"));
                }
                assert!(case["expect_diverges"].as_bool().unwrap());
                assert!(outputs.len() > 1, "{kind} {id}: the broken variant did not diverge");
            }
            "gc" => {
                let covered = model_ops(&heads, &ops_in(&case["covered"]));
                let later = model_ops(&heads, &ops_in(&case["later"]));
                let checkpoint = gc(&model_apply(&covered));
                let collected =
                    model_continue(checkpoint, &drop_covered(&covered, &later)).projection();
                let full = model_continue(model_apply(&covered), &later).projection();
                assert_eq!(collected, model_projection(&heads, &proj_in(&case["gc"])), "gc {id}");
                assert_eq!(full, model_projection(&heads, &proj_in(&case["full"])), "gc {id}");
                // The vectors' closure test is the strict one (every keep or
                // retire has its put covered); the model's also accepts a head
                // that no operation of the whole history puts, which nothing
                // can resurrect.
                let closed = case["closed"].as_bool().expect("closed");
                let universe: Vec<KeepOp> = covered.iter().chain(later.iter()).cloned().collect();
                let rust_closed = causally_closed_in(&covered, &universe);
                assert!(!closed || causally_closed(&covered), "gc {id}: closure");
                assert!(!closed || rust_closed, "gc {id}: closure in the history");
                let diverges = collected != full;
                assert_eq!(diverges, case["expect_diverges"].as_bool().unwrap(), "gc {id}");
                assert!(!(rust_closed && diverges), "gc {id}: diverged despite closure");
                assert!(!(closed && diverges), "gc {id}: diverged despite closure");
                if diverges {
                    assert!(!closed && !rust_closed, "gc {id}: a divergence needs an open head");
                }
            }
            other => panic!("unknown vector kind {other}"),
        }
        *per_kind.entry(kind).or_default() += 1;
    }
    for kind in ["naive_prune", "no_tombstone", "gc"] {
        assert!(per_kind.get(kind).copied().unwrap_or(0) >= 12, "too few {kind} vectors");
    }
}
