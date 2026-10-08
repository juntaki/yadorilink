//! The real store against the reference model of head-scoped kept copies
//! (`yadorilink_replica_domain::native_keep_model`).
//!
//! The model's closed form says what a replica that admitted a set of deltas
//! must show: `live = puts \ retires` and `kept = (keeps \ retires) ∩ live`,
//! whatever the order and however many duplicates. Here generated histories
//! are delivered to real stores in many orders, and at every step the store's
//! live heads and live kept heads, and the kept versions the planner reads,
//! must equal the model's projection of the deltas the store has admitted so
//! far (held deltas are not admitted yet, so the model is defined exactly on
//! the admitted, causally closed set).
//!
//! The model's three broken variants correspond to three regressions of the
//! store: pruning a keep on absence, which makes arrival order matter; dropping
//! the removal record, which lets a late head come back; and collecting history
//! without causal closure, which brings a head back after a compacted replica
//! replays covered deltas. Each is covered here or in the
//! bootstrap tests by a test that fails when the mechanism is removed.

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_keep_model::{
    apply_closed, generate, Projection, Rng, Scenario, Shape,
};
use yadorilink_replica_domain::native_state::{DeltaHash, Dot, HeadId};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::native_admission::{admit_native_delta, NativeAdmission};
use crate::native_store;

fn group() -> FolderGroupId {
    FolderGroupId("g1".into())
}

fn store() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    native_store::init_native_tables(&c).unwrap();
    crate::native_admission::init_admission_tables(&c).unwrap();
    crate::native_publication::init_native_publication_tables(&c).unwrap();
    c
}

fn lookup(scenario: &Scenario) -> impl Fn(&AuthorId) -> Option<VerifyingKey> + '_ {
    move |author: &AuthorId| {
        scenario.authors.iter().position(|a| a == author).map(|i| scenario.keys[i].verifying_key())
    }
}

fn dot_of(author: String, incarnation: Vec<u8>, seq: i64) -> Dot {
    Dot {
        author: AuthorId {
            device: DeviceId(author),
            incarnation: IncarnationId(incarnation.try_into().expect("16 bytes")),
        },
        seq: AuthorSeq(seq as u64),
    }
}

/// The store's live heads and live kept heads, in the model's terms.
fn projection_of(c: &Connection) -> Projection {
    let mut projection = Projection::default();
    let mut heads = c
        .prepare("SELECT path, author, incarnation, seq, provenance, version FROM native_heads")
        .unwrap();
    let rows = heads
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (path, author, incarnation, seq, provenance, version) = row.unwrap();
        let key = HeadId {
            path: SyncPath(path),
            dot: dot_of(author, incarnation, seq),
            provenance: DeltaHash(provenance.try_into().expect("32 bytes")),
        };
        projection.live.insert(key, VersionHash(version.try_into().expect("32 bytes")));
    }
    let mut keeps = c
        .prepare("SELECT path, author, incarnation, seq, provenance FROM native_head_keep")
        .unwrap();
    let rows = keeps
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (path, author, incarnation, seq, provenance) = row.unwrap();
        projection.kept.insert(HeadId {
            path: SyncPath(path),
            dot: dot_of(author, incarnation, seq),
            provenance: DeltaHash(provenance.try_into().expect("32 bytes")),
        });
    }
    projection
}

/// The deltas the store has admitted: every author's chain up to the
/// frontier's position.
fn admitted<'a>(c: &Connection, scenario: &'a Scenario) -> Vec<&'a NativeDelta> {
    let frontier = native_store::load_frontier(c, &group()).unwrap();
    scenario
        .deltas
        .iter()
        .filter(|delta| frontier.get(&delta.author).is_some_and(|entry| delta.seq <= entry.seq))
        .collect()
}

/// The invariants every state of the store satisfies: a kept head is a live
/// head with the recorded provenance, the planner reads the kept versions the
/// model derives, and the context agrees with the frontier.
fn assert_invariants(c: &Connection, projection: &Projection, label: &str) {
    assert!(projection.is_well_formed(), "{label}: a keep names a head that is not live");
    let paths: Vec<SyncPath> =
        (0..4).map(yadorilink_replica_domain::native_keep_model::path_name).collect();
    let planner = crate::native_projection_binding::kept_copies_at(c, "g1", paths.iter()).unwrap();
    assert_eq!(planner, projection.kept_versions(), "{label}: the planner's kept versions");
    let state = native_store::load_state(c, &group()).unwrap();
    let frontier = native_store::load_frontier(c, &group()).unwrap();
    for (author, seq) in &state.context {
        assert_eq!(
            frontier.get(author).map(|entry| entry.seq),
            Some(*seq),
            "{label}: context and frontier disagree for {author:?}"
        );
    }
}

#[derive(Default)]
struct Reached {
    held: usize,
    duplicates: usize,
    kept_at_end: usize,
    keeps_dropped: usize,
}

/// Delivers `order` (indexes into the scenario, duplicates allowed) one delta
/// at a time, checking the store against the model after each.
fn deliver_checking(
    c: &Connection,
    scenario: &Scenario,
    order: &[usize],
    label: &str,
    reached: &mut Reached,
) {
    let lookup = lookup(scenario);
    for (step, index) in order.iter().enumerate() {
        let outcome = admit_native_delta(c, &group(), &scenario.deltas[*index], &lookup).unwrap();
        match outcome {
            NativeAdmission::Admitted { .. } => {}
            NativeAdmission::Held { .. } => reached.held += 1,
            NativeAdmission::Duplicate => reached.duplicates += 1,
            other => panic!("{label} step {step}: unexpected outcome {other:?}"),
        }
        let projection = projection_of(c);
        let model = apply_closed(admitted(c, scenario));
        assert_eq!(
            projection, model,
            "{label} step {step}: the store differs from the model of what it admitted"
        );
        assert_invariants(c, &projection, &format!("{label} step {step}"));
    }
}

fn orders_for(scenario: &Scenario, seed: u64) -> Vec<Vec<usize>> {
    let n = scenario.deltas.len();
    let mut rng = Rng(seed ^ 0x5EED);
    let mut orders = vec![(0..n).collect::<Vec<_>>(), (0..n).rev().collect::<Vec<_>>()];
    for _ in 0..2 {
        orders.push(rng.permutation(n));
    }
    // Duplicate deliveries into the random orders.
    for order in orders.iter_mut().skip(2) {
        for _ in 0..3 {
            let again = order[rng.below(order.len())];
            let at = rng.below(order.len() + 1);
            order.insert(at, again);
        }
    }
    orders
}

/// Order independence on the real store: every delivery order of one history, with duplicates,
/// leaves exactly the model's projection at every step and the same final
/// state, with nothing left held.
#[test]
fn the_store_projects_the_model_of_what_it_admitted_in_every_order() {
    const SHAPE: Shape = Shape { authors: 3, paths: 3, deltas: 14, versions: 3 };
    let mut reached = Reached::default();
    for seed in 0..120u64 {
        let scenario = generate(seed, SHAPE);
        let expected = apply_closed(&scenario.deltas);
        for (round, order) in orders_for(&scenario, seed).iter().enumerate() {
            let c = store();
            let label = format!("seed {seed} order {round}");
            deliver_checking(&c, &scenario, order, &label, &mut reached);
            let held: i64 = c
                .query_row("SELECT COUNT(*) FROM native_delta_holds", [], |row| row.get(0))
                .unwrap();
            assert_eq!(held, 0, "{label}: every delta was admitted in the end");
            assert_eq!(
                projection_of(&c),
                expected,
                "{label}: the final state depends on the order"
            );
            reached.kept_at_end += expected.kept.len();
        }
        reached.keeps_dropped += scenario
            .deltas
            .iter()
            .flat_map(|d| &d.ops)
            .map(|op| op.keeps.len())
            .sum::<usize>()
            .saturating_sub(expected.kept.len());
    }
    assert!(reached.held > 200, "holds were exercised too rarely: {}", reached.held);
    assert!(reached.duplicates > 20, "duplicates were exercised too rarely");
    assert!(reached.kept_at_end > 400, "kept heads were reached too rarely");
    assert!(reached.keeps_dropped > 100, "keeps of retired or unmatched heads were too rare");
}

mod vectors;

mod handwritten {
    use ed25519_dalek::SigningKey;

    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef};

    use super::*;

    pub(super) struct Party {
        pub id: AuthorId,
        pub key: SigningKey,
    }

    pub(super) fn party(name: &str, byte: u8) -> Party {
        Party {
            id: AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([byte; 16]) },
            key: SigningKey::from_bytes(&[byte; 32]),
        }
    }

    pub(super) fn put_op(path: &str, version: u8) -> DeltaOp {
        DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: VersionHash([version; 32]) }),
            keeps: Vec::new(),
            keep_put: false,
        }
    }

    pub(super) fn op(path: &str) -> DeltaOp {
        DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: None,
            keeps: Vec::new(),
            keep_put: false,
        }
    }

    pub(super) fn removal(of: &NativeDelta) -> HeadRef {
        HeadRef { dot: of.dot(), provenance: of.delta_hash() }
    }

    pub(super) fn keep(of: &NativeDelta) -> HeadRef {
        HeadRef { dot: of.dot(), provenance: of.delta_hash() }
    }

    pub(super) fn sign(
        party: &Party,
        seq: u64,
        prev: Option<&NativeDelta>,
        ops: Vec<DeltaOp>,
    ) -> NativeDelta {
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: party.id.clone(),
            seq: AuthorSeq(seq),
            prev: prev.map(NativeDelta::delta_hash),
            ops,
            signature: [0u8; 64],
        };
        delta.sign(&party.key);
        delta
    }

    pub(super) fn lookup_for<'a>(
        parties: &'a [&'a Party],
    ) -> impl Fn(&AuthorId) -> Option<VerifyingKey> + 'a {
        move |author: &AuthorId| {
            parties.iter().find(|p| p.id == *author).map(|p| p.key.verifying_key())
        }
    }
}

use handwritten::{keep, lookup_for, op, party, put_op, removal, sign};

fn permutations(n: usize) -> Vec<Vec<usize>> {
    fn go(prefix: &mut Vec<usize>, rest: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if rest.is_empty() {
            out.push(prefix.clone());
            return;
        }
        for i in 0..rest.len() {
            let next = rest.remove(i);
            prefix.push(next);
            go(prefix, rest, out);
            prefix.pop();
            rest.insert(i, next);
        }
    }
    let mut out = Vec::new();
    go(&mut Vec::new(), &mut (0..n).collect(), &mut out);
    out
}

fn admit_all(c: &Connection, deltas: &[&NativeDelta], parties: &[&handwritten::Party]) {
    let lookup = lookup_for(parties);
    for delta in deltas {
        let outcome = admit_native_delta(c, &group(), delta, &lookup).unwrap();
        assert!(
            matches!(outcome, NativeAdmission::Admitted { .. } | NativeAdmission::Held { .. }),
            "{outcome:?}"
        );
    }
    let held: i64 =
        c.query_row("SELECT COUNT(*) FROM native_delta_holds", [], |row| row.get(0)).unwrap();
    assert_eq!(held, 0, "every delta is admitted once all have arrived");
}

/// Permanent retirement on the real store: a keep, a retire and the put they both name arrive in
/// every order. Whatever arrives first is held until the head is observed, the
/// head ends retired, its keep never becomes visible and nothing resurrects it.
#[test]
fn a_keep_and_a_retire_of_one_head_end_retired_in_every_arrival_order() {
    let (a, b, c) = (party("a", 1), party("b", 2), party("c", 3));
    let put = sign(&b, 1, None, vec![put_op("x", 1)]);
    let mut keeps = op("x");
    keeps.keeps = vec![keep(&put)];
    let keeper = sign(&a, 1, None, vec![keeps]);
    let mut retires = op("x");
    retires.removes = vec![removal(&put)];
    let retirer = sign(&c, 1, None, vec![retires]);
    let all = [&put, &keeper, &retirer];

    let mut held_first = 0usize;
    for order in permutations(3) {
        let store = store();
        let parties = [&a, &b, &c];
        let lookup = lookup_for(&parties);
        let mut put_seen = false;
        for index in &order {
            let outcome = admit_native_delta(&store, &group(), all[*index], &lookup).unwrap();
            if *index == 0 {
                put_seen = true;
            }
            if *index != 0 && order[0] == *index {
                // The keep or the retire before the head it names.
                assert!(matches!(outcome, NativeAdmission::Held { .. }), "{outcome:?}");
                held_first += 1;
            } else if put_seen {
                // A keep after a retire of an observed head is a no-op, not parked.
                assert!(
                    matches!(outcome, NativeAdmission::Admitted { .. }),
                    "{order:?}: {outcome:?}"
                );
            }
        }
        let count = |table: &str| -> i64 {
            store.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap()
        };
        assert_eq!(count("native_delta_holds"), 0, "order {order:?}: a delta stayed parked");
        assert_eq!(count("native_head_keep"), 0, "order {order:?}: a keep row of a retired head");
        let projection = projection_of(&store);
        assert!(projection.live.is_empty(), "order {order:?}: the retired head came back");
        assert!(projection.kept.is_empty(), "order {order:?}: a keep of a retired head showed");
        assert_eq!(projection, apply_closed(all));
    }
    assert!(held_first > 0);
}

/// A cohort larger than one op can declare is kept whole: the author of an edit
/// that leaves 70 live heads of one version in place, shown as a copy, signs
/// every exact keep across a chain of its own deltas, none more than
/// `MAX_KEEPS_PER_OP` per op and none refused, and a receiver ends with the
/// same live and kept heads in every arrival order.
#[test]
fn a_cohort_beyond_one_ops_bound_is_kept_across_a_chain_and_replicas_converge() {
    use yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP;
    const COHORT: usize = 70;
    let parties: Vec<handwritten::Party> =
        (0..COHORT + 2).map(|i| party(&format!("p{i}"), i as u8 + 1)).collect();
    let (winner_author, me) = (&parties[COHORT], &parties[COHORT + 1]);
    let winner = sign(winner_author, 1, None, vec![put_op("x", 2)]);
    let cohort: Vec<NativeDelta> =
        (0..COHORT).map(|i| sign(&parties[i], 1, None, vec![put_op("x", 1)])).collect();
    let all_parties: Vec<&handwritten::Party> = parties.iter().collect();
    let lookup = lookup_for(&all_parties);

    // The author's replica: it has every head and shows the cohort as a copy.
    let author_store = store();
    for delta in std::iter::once(&winner).chain(&cohort) {
        admit_native_delta(&author_store, &group(), delta, &lookup).unwrap();
    }
    let path = SyncPath("x".to_owned());
    let winner_head = yadorilink_replica_domain::native_state::LiveHead {
        dot: winner.dot(),
        payload: yadorilink_replica_domain::native_state::HeadPayload {
            version: VersionHash([2; 32]),
            provenance: winner.delta_hash(),
        },
    };
    let witness = yadorilink_replica_domain::native_state::NativeCaptureWitness {
        physical_path: path.clone(),
        logical_source_path: path.clone(),
        shown_version: Some(VersionHash([2; 32])),
        shown_class: vec![winner.dot()],
        shown_head: Some(winner_head),
    };
    let local = crate::local_author::LocalAuthor {
        author: me.id.clone(),
        signing_key: &me.key,
        capture: None,
    };
    crate::native_authoring::author_op_witnessed(
        &author_store,
        &group(),
        &local,
        &yadorilink_replica_domain::local_op::Op::Delete { path: path.clone() },
        &path,
        Some(&witness),
    )
    .expect("a cohort beyond one op's bound is never refused");

    let frontier = native_store::load_frontier(&author_store, &group()).unwrap();
    let signed = frontier[&me.id].seq.get();
    assert!(signed >= 2, "the keeps need a chain: {signed} delta(s)");
    let authored: Vec<NativeDelta> = (1..=signed)
        .map(|seq| {
            let body =
                native_store::fetch_delta_body(&author_store, &group(), &me.id, AuthorSeq(seq))
                    .unwrap()
                    .unwrap();
            assert!(body.len() <= yadorilink_replica_domain::protocol5::MAX_BATCH_ITEM_BYTES);
            NativeDelta::from_wire_bytes(&body).expect("every authored delta decodes")
        })
        .collect();
    let named: BTreeSet<_> = authored
        .iter()
        .flat_map(|delta| delta.ops.iter())
        .inspect(|op| assert!(op.keeps.len() <= MAX_KEEPS_PER_OP))
        .flat_map(|op| op.keeps.iter().map(|k| (k.dot.clone(), k.provenance)))
        .collect();
    let expected: BTreeSet<_> = cohort.iter().map(|d| (d.dot(), d.delta_hash())).collect();
    assert_eq!(named, expected, "every head of the cohort is kept exactly");
    let author_projection = projection_of(&author_store);
    assert_eq!(author_projection.kept.len(), COHORT);
    assert_eq!(author_projection.live.len(), COHORT, "only the winner was removed");

    // Receivers: the puts and the chain in shuffled orders converge.
    let history: Vec<&NativeDelta> =
        std::iter::once(&winner).chain(&cohort).chain(&authored).collect();
    let mut rng = Rng(5);
    for round in 0..6 {
        let order: Vec<usize> =
            if round == 0 { (0..history.len()).collect() } else { rng.permutation(history.len()) };
        let ordered: Vec<&NativeDelta> = order.iter().map(|i| history[*i]).collect();
        let receiver = store();
        admit_all(&receiver, &ordered, &all_parties);
        assert_eq!(projection_of(&receiver), author_projection, "round {round}");
    }
}

/// A keep for a head this replica has never observed stays held until the head
/// arrives, then applies; nothing is recorded before.
#[test]
fn a_keep_for_a_head_never_observed_stays_held_until_the_head_arrives() {
    let (a, b) = (party("a", 1), party("b", 2));
    let put = sign(&b, 1, None, vec![put_op("x", 1)]);
    let mut keeps = op("x");
    keeps.keeps = vec![keep(&put)];
    let keeper = sign(&a, 1, None, vec![keeps]);
    let parties = [&a, &b];
    let lookup = lookup_for(&parties);
    let store = store();
    let held = |c: &Connection| -> i64 {
        c.query_row("SELECT COUNT(*) FROM native_delta_holds", [], |row| row.get(0)).unwrap()
    };
    let outcome = admit_native_delta(&store, &group(), &keeper, &lookup).unwrap();
    assert!(matches!(outcome, NativeAdmission::Held { .. }), "{outcome:?}");
    assert_eq!(held(&store), 1);
    assert!(projection_of(&store).kept.is_empty() && projection_of(&store).live.is_empty());
    admit_native_delta(&store, &group(), &put, &lookup).unwrap();
    assert_eq!(held(&store), 0, "the keep is released by the head it names");
    let projection = projection_of(&store);
    assert_eq!(projection.kept.len(), 1, "the released keep applies");
    assert_eq!(projection, apply_closed([&put, &keeper]));
}

/// A keep applies to the head it names: a later head of the same version at a
/// new dot is not kept, in any arrival order of the whole history.
///
/// Heads H1 (a) and H2 (b) carry version 1 and a winner W (c) version 2. The
/// author d saw them all, saw version 1 as a copy, removed W and kept every head
/// of the cohort. H1 is then retired, leaving H2 isolated: it keeps its copy
/// name. A later head H3 (e) of version 1 declares nothing; once H2 is retired
/// it is alone and takes the real name.
#[test]
fn a_cohort_survivor_keeps_its_copy_name_and_a_later_head_of_the_content_does_not() {
    let (a, b, c, d, e) =
        (party("a", 1), party("b", 2), party("c", 3), party("d", 4), party("e", 5));
    let h1 = sign(&a, 1, None, vec![put_op("x", 1)]);
    let h2 = sign(&b, 1, None, vec![put_op("x", 1)]);
    let w = sign(&c, 1, None, vec![put_op("x", 2)]);
    let mut declare = op("x");
    declare.removes = vec![removal(&w)];
    declare.keeps = vec![keep(&h1), keep(&h2)];
    let declared = sign(&d, 1, None, vec![declare]);
    let mut retire_h1 = op("x");
    retire_h1.removes = vec![removal(&h1)];
    let h1_gone = sign(&a, 2, Some(&h1), vec![retire_h1]);
    let h3 = sign(&e, 1, None, vec![put_op("x", 1)]);
    let mut retire_h2 = op("x");
    retire_h2.removes = vec![removal(&h2)];
    let h2_gone = sign(&b, 2, Some(&h2), vec![retire_h2]);
    let parties = [&a, &b, &c, &d, &e];

    let placements = |c: &Connection| {
        crate::stable_projection_binding::native_placements(c, "g1")
            .unwrap()
            .into_iter()
            .map(|p| (p.physical_path, p.version[0], p.origin))
            .collect::<Vec<_>>()
    };
    let version_of = |c: &Connection, key: &NativeDelta| -> BTreeSet<(String, u64)> {
        projection_of(c)
            .kept
            .iter()
            .filter(|k| k.dot == key.dot())
            .map(|k| (k.path.as_str().to_owned(), k.dot.seq.get()))
            .collect()
    };

    // H2 isolated: nothing but H2 lives, kept, at its copy name.
    let isolated = store();
    admit_all(&isolated, &[&h1, &h2, &w, &declared, &h1_gone], &parties);
    let projection = projection_of(&isolated);
    assert_eq!(projection.live.len(), 1, "only H2 lives");
    assert_eq!(version_of(&isolated, &h2).len(), 1, "H2 is kept");
    assert_eq!(
        placements(&isolated).iter().map(|p| (p.1, p.2.as_str())).collect::<Vec<_>>(),
        vec![(1u8, "conflict_copy")],
        "the isolated cohort survivor keeps its copy name"
    );

    // The same history with H3 and H2's retirement, in orders that put the
    // declaration before, between and after the heads.
    let history = [&h1, &h2, &w, &declared, &h1_gone, &h3, &h2_gone];
    let mut rng = Rng(7);
    let mut finals = Vec::new();
    for round in 0..40 {
        let order: Vec<usize> =
            if round == 0 { (0..history.len()).collect() } else { rng.permutation(history.len()) };
        let ordered: Vec<&NativeDelta> = order.iter().map(|i| history[*i]).collect();
        let store = store();
        admit_all(&store, &ordered, &parties);
        let projection = projection_of(&store);
        assert_eq!(projection, apply_closed(history), "order {order:?}");
        assert_eq!(projection.live.len(), 1, "only H3 lives: {order:?}");
        assert!(projection.kept.is_empty(), "H3 declared nothing and inherits no keep: {order:?}");
        assert!(
            placements(&store).is_empty(),
            "H3 alone takes the real name, in every order: {order:?}: {:?}",
            placements(&store)
        );
        finals.push(projection);
    }
    assert!(finals.windows(2).all(|pair| pair[0] == pair[1]));
}

/// The end state of the cohort history seen through everything a replica reads
/// back: H1 and H2 (version V) are kept, H1 retires, an unkept H3 of V arrives
/// and H2 retires. Only H3 lives, nothing is kept, the copy placement the
/// cohort created is gone, the planner has no kept version for the path and
/// the copy name is not shown, in every one of the arrival orders.
#[test]
fn a_later_unkept_head_is_not_kept_alive_by_the_copy_placement_of_the_cohort() {
    let (a, b, c, d, e) =
        (party("a", 1), party("b", 2), party("c", 3), party("d", 4), party("e", 5));
    // Real versions, so the plan of the final state can resolve what the heads show.
    let version = |mtime: i64| {
        yadorilink_replica_domain::file::FileVersion::new(
            Vec::new(),
            0,
            yadorilink_replica_domain::file::FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: yadorilink_replica_domain::file::RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    };
    let (v, other) = (version(1), version(2));
    let put_of = |v: &yadorilink_replica_domain::file::FileVersion| {
        let mut put = put_op("x", 0);
        put.put.as_mut().unwrap().version = v.version_hash;
        put
    };
    let h1 = sign(&a, 1, None, vec![put_of(&v)]);
    let h2 = sign(&b, 1, None, vec![put_of(&v)]);
    let w = sign(&c, 1, None, vec![put_of(&other)]);
    let mut declare = op("x");
    declare.removes = vec![removal(&w)];
    declare.keeps = vec![keep(&h1), keep(&h2)];
    let declared = sign(&d, 1, None, vec![declare]);
    let mut retire_h1 = op("x");
    retire_h1.removes = vec![removal(&h1)];
    let h1_gone = sign(&a, 2, Some(&h1), vec![retire_h1]);
    let h3 = sign(&e, 1, None, vec![put_of(&v)]);
    let mut retire_h2 = op("x");
    retire_h2.removes = vec![removal(&h2)];
    let h2_gone = sign(&b, 2, Some(&h2), vec![retire_h2]);
    let parties = [&a, &b, &c, &d, &e];
    let history = [&h1, &h2, &w, &declared, &h1_gone, &h3, &h2_gone];
    let path = SyncPath("x".to_owned());

    // The natural order, its reverse, and a spread of others (every one of the
    // 5040 would take close to a minute).
    let mut rng = Rng(11);
    let mut orders: Vec<Vec<usize>> = vec![(0..history.len()).collect()];
    orders.push((0..history.len()).rev().collect());
    orders.extend((0..300).map(|_| rng.permutation(history.len())));
    for order in orders {
        let ordered: Vec<&NativeDelta> = order.iter().map(|i| history[*i]).collect();
        let store = store();
        for version in [&v, &other] {
            crate::dag_store::put_file_version(&store, "g1", version).unwrap();
        }
        admit_all(&store, &ordered, &parties);
        let projection = projection_of(&store);
        assert_eq!(projection, apply_closed(history), "order {order:?}");
        assert_eq!(projection.live.len(), 1, "only H3 lives: {order:?}");
        assert!(projection.kept.is_empty(), "no keep row for H3: {order:?}");
        let kept = crate::native_projection_binding::kept_copies_at(&store, "g1", [&path]).unwrap();
        assert!(kept.is_empty(), "the planner kept set has no version of the path: {order:?}");
        let placements = crate::stable_projection_binding::native_placements(&store, "g1").unwrap();
        assert!(placements.is_empty(), "H3 is not shown at the cohort's copy name: {order:?}");
        let shown = crate::native_projection_binding::shown_copy_versions(&store, "g1", "x");
        assert!(shown.unwrap().is_empty(), "no copy of the path is shown: {order:?}");
        // The physical name the plan gives the surviving head is the real one.
        let plan = crate::native_desired_state::native_plan_level(&store, "g1", "").unwrap();
        let names: Vec<&str> = plan.nodes.keys().map(SyncPath::as_str).collect();
        assert_eq!(names, vec!["x"], "H3 returns to the real name: {order:?}");
    }
}

/// A kept head's version class applies to its same-version siblings while it
/// lives: with kept H2 and unkept H3 both live at version 1, H3 (the only head
/// that is not kept) shows at the copy name, and once H2 retires it is promoted
/// to the real name. Every replica derives the same, in every arrival order.
#[test]
fn an_unkept_sibling_of_a_live_kept_head_shows_as_a_copy_until_the_kept_head_retires() {
    let (a, b, c, d) = (party("a", 1), party("b", 2), party("c", 3), party("d", 4));
    let h2 = sign(&a, 1, None, vec![put_op("x", 1)]);
    let h3 = sign(&b, 1, None, vec![put_op("x", 1)]);
    let w = sign(&c, 1, None, vec![put_op("x", 2)]);
    let mut declare = op("x");
    declare.removes = vec![removal(&w)];
    declare.keeps = vec![keep(&h2)];
    let declared = sign(&d, 1, None, vec![declare]);
    let mut retire = op("x");
    retire.removes = vec![removal(&h2)];
    let h2_gone = sign(&a, 2, Some(&h2), vec![retire]);
    let parties = [&a, &b, &c, &d];

    let placements = |c: &Connection| {
        crate::stable_projection_binding::native_placements(c, "g1")
            .unwrap()
            .into_iter()
            .map(|p| (p.version[0], p.origin.as_str().to_owned()))
            .collect::<Vec<_>>()
    };

    let live_alongside = [&h2, &h3, &w, &declared];
    let promoted = [&h2, &h3, &w, &declared, &h2_gone];
    for (history, expected_live, expected) in [
        (&live_alongside[..], 2usize, vec![(1u8, "conflict_copy".to_owned())]),
        (&promoted[..], 1usize, Vec::new()),
    ] {
        for order in permutations(history.len()) {
            let ordered: Vec<&NativeDelta> = order.iter().map(|i| history[*i]).collect();
            let store = store();
            admit_all(&store, &ordered, &parties);
            let projection = projection_of(&store);
            assert_eq!(projection, apply_closed(history.iter().copied()), "order {order:?}");
            assert_eq!(projection.live.len(), expected_live, "order {order:?}");
            assert_eq!(placements(&store), expected, "order {order:?}");
        }
    }
}

/// A delta that puts at two paths creates two heads that share a dot and are
/// told apart by path: the own-put keep applies to its own op's head only, a
/// removal at one path leaves the other path's head live, and a keep of a
/// head by a later delta names the path of its own op.
#[test]
fn heads_that_share_a_dot_are_kept_and_retired_by_their_own_path() {
    let (a, c) = (party("a", 1), party("c", 3));
    let mut at_p1 = put_op("p1", 1);
    at_p1.keep_put = true;
    let both = sign(&a, 1, None, vec![at_p1, put_op("p2", 1)]);
    let mut retire = op("p1");
    retire.removes = vec![removal(&both)];
    let mut keep_other = op("p2");
    keep_other.keeps = vec![keep(&both)];
    let later = sign(&c, 1, None, vec![retire, keep_other]);

    for order in permutations(2) {
        let all = [&both, &later];
        let store = store();
        admit_all(&store, &[all[order[0]], all[order[1]]], &[&a, &c]);
        let projection = projection_of(&store);
        assert_eq!(projection, apply_closed(all), "order {order:?}");
        let live: Vec<&str> = projection.live.keys().map(|k| k.path.as_str()).collect();
        assert_eq!(live, vec!["p2"], "the removal at p1 leaves p2's head live: {order:?}");
        let kept: Vec<&str> = projection.kept.iter().map(|k| k.path.as_str()).collect();
        assert_eq!(kept, vec!["p2"], "p1's own-put keep went with its head: {order:?}");
    }
    // Without the retirement: p1's head is kept by its own flag, p2's is not
    // until a later delta names it at p2.
    let store = store();
    admit_all(&store, &[&both], &[&a]);
    let projection = projection_of(&store);
    let kept: Vec<&str> = projection.kept.iter().map(|k| k.path.as_str()).collect();
    assert_eq!(kept, vec!["p1"]);
}

/// A keep covers one head, not its content: an own-put keep of a head does not
/// keep another head that carries the same version at the same path.
#[test]
fn an_own_put_keep_does_not_keep_another_head_with_the_same_version() {
    let (a, b, c) = (party("a", 1), party("b", 2), party("c", 3));
    let h1 = sign(&a, 1, None, vec![put_op("x", 1)]);
    let h2 = sign(&b, 1, None, vec![put_op("x", 1)]);
    let mut kept_put = put_op("x", 1);
    kept_put.keep_put = true;
    let h3 = sign(&c, 1, None, vec![kept_put]);
    let all = [&h1, &h2, &h3];
    for order in permutations(3) {
        let store = store();
        admit_all(&store, &[all[order[0]], all[order[1]], all[order[2]]], &[&a, &b, &c]);
        let projection = projection_of(&store);
        assert_eq!(projection.live.len(), 3, "{order:?}");
        let kept: Vec<u64> =
            projection.kept.iter().map(|k| k.dot.author.device.0.len() as u64).collect();
        assert_eq!(kept.len(), 1, "only the head that flagged itself is kept: {order:?}");
        assert!(projection.kept.iter().all(|k| k.dot == h3.dot()), "{order:?}");
    }
}

/// A keep that names a head with the dot of a live head but another
/// provenance is not that head and records nothing.
#[test]
fn a_keep_naming_a_live_dot_with_another_provenance_records_nothing() {
    let (a, b) = (party("a", 1), party("b", 2));
    let head = sign(&b, 1, None, vec![put_op("x", 1)]);
    let mut wrong = op("x");
    wrong.keeps = vec![yadorilink_replica_domain::signed_delta::HeadRef {
        dot: head.dot(),
        provenance: DeltaHash([0x99; 32]),
    }];
    let keeper = sign(&a, 1, None, vec![wrong]);
    for order in permutations(2) {
        let all = [&head, &keeper];
        let store = store();
        admit_all(&store, &[all[order[0]], all[order[1]]], &[&a, &b]);
        let projection = projection_of(&store);
        assert_eq!(projection.live.len(), 1);
        assert!(projection.kept.is_empty(), "order {order:?}");
    }
}
