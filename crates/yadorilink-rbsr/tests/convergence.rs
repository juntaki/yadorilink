//! Convergence properties of the reconciliation state machine.

use std::collections::BTreeSet;

use yadorilink_rbsr::{ItemId, MemoryIndex, RbsrConfig, RbsrMessage, Reconciler};

/// What one full reconciliation cost.
#[derive(Debug, Default)]
struct Cost {
    rounds: usize,
    messages: usize,
    /// Identifiers named across every `Items` message, in both directions.
    /// This is the transferred metadata, and the quantity that must scale with
    /// the difference rather than with the size of the sets.
    listed_ids: usize,
}

/// Drive two reconcilers to settlement, optionally abandoning the session
/// after `abort_after` rounds.
fn reconcile(
    initiator: &mut Reconciler<MemoryIndex>,
    responder: &mut Reconciler<MemoryIndex>,
    abort_after: Option<usize>,
) -> Cost {
    let mut cost = Cost::default();
    let mut in_flight = initiator.initiate();
    let mut initiators_turn = false;

    while !in_flight.is_empty() {
        if Some(cost.rounds) == abort_after {
            // The session is abandoned here. Nothing is flushed, nothing is
            // recorded, the in-flight round is dropped on the floor.
            return cost;
        }

        cost.rounds += 1;
        cost.messages += in_flight.len();
        cost.listed_ids += in_flight
            .iter()
            .map(|message| match message {
                RbsrMessage::Items { ids, .. } => ids.len(),
                RbsrMessage::Fingerprint { .. } => 0,
            })
            .sum::<usize>();

        let side = if initiators_turn { &mut *initiator } else { &mut *responder };
        in_flight = side.ingest(&in_flight).expect("honest peer, valid round");
        initiators_turn = !initiators_turn;

        assert!(
            cost.rounds < 64,
            "reconciliation must terminate; it is still exchanging after {} rounds",
            cost.rounds
        );
    }

    cost
}

fn ids(values: impl IntoIterator<Item = u64>) -> BTreeSet<ItemId> {
    values
        .into_iter()
        .map(|value| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&value.to_be_bytes());
            ItemId::from_bytes(bytes)
        })
        .collect()
}

/// Run a reconciliation and require that both sides learned exactly the true
/// difference — no more, no less.
fn assert_exact_difference(
    left: &BTreeSet<ItemId>,
    right: &BTreeSet<ItemId>,
    config: RbsrConfig,
) -> Cost {
    let mut a = Reconciler::new(MemoryIndex::new(left.iter().copied()), config);
    let mut b = Reconciler::new(MemoryIndex::new(right.iter().copied()), config);

    let cost = reconcile(&mut a, &mut b, None);

    let only_right: BTreeSet<ItemId> = right.difference(left).copied().collect();
    let only_left: BTreeSet<ItemId> = left.difference(right).copied().collect();

    assert_eq!(*a.want(), only_right, "initiator learned the wrong deficit");
    assert_eq!(*a.offer(), only_left, "initiator learned the wrong surplus");
    assert_eq!(*b.want(), only_left, "responder learned the wrong deficit");
    assert_eq!(*b.offer(), only_right, "responder learned the wrong surplus");

    cost
}

#[test]
fn identical_sets_settle_without_naming_a_single_identifier() {
    let set = ids(0..500);
    let cost = assert_exact_difference(&set, &set, RbsrConfig::default());

    assert_eq!(cost.listed_ids, 0, "two peers already in agreement must not enumerate their sets");
    assert_eq!(cost.messages, 1, "one fingerprint should settle it");
}

#[test]
fn empty_against_populated_converges() {
    let populated = ids(0..200);
    assert_exact_difference(&BTreeSet::new(), &populated, RbsrConfig::default());
    assert_exact_difference(&populated, &BTreeSet::new(), RbsrConfig::default());
}

#[test]
fn both_sides_empty_settles_immediately() {
    let cost = assert_exact_difference(&BTreeSet::new(), &BTreeSet::new(), RbsrConfig::default());
    assert_eq!(cost.rounds, 1);
}

/// Gate: work scales with the difference, not with the size of the sets.
///
/// The failure being ruled out is amplification — the old protocol produced a
/// confirmed 560-676x retransmission storm, delivering the same Changes over
/// and over. Here two 100-element sets differing by one identifier must not
/// cause either side to enumerate the other 99.
#[test]
fn cost_scales_with_the_difference_not_with_the_set() {
    let base = ids(0..100);
    let mut divergent = base.clone();
    divergent.extend(ids(1000..1001));

    let cost = assert_exact_difference(&base, &divergent, RbsrConfig::default());

    assert!(
        cost.listed_ids < 100,
        "a one-identifier difference between 100-element sets named {} identifiers; \
         reconciliation is enumerating instead of narrowing",
        cost.listed_ids
    );
}

/// Gate: killing the session at any round boundary costs nothing.
///
/// Reconciliation state is deliberately not durable. This requires that a
/// session abandoned at *every* round boundary, then restarted from the same
/// durable sets, reaches exactly the same answer as one that ran through —
/// with no rescue sweep, no timer and no retained session state.
#[test]
fn a_session_killed_at_any_round_boundary_restarts_from_the_durable_sets() {
    let config = RbsrConfig::default();
    let left = ids((0..400).filter(|value| value % 3 != 0));
    let right = ids((0..400).filter(|value| value % 5 != 0));

    let uninterrupted = {
        let mut a = Reconciler::new(MemoryIndex::new(left.iter().copied()), config);
        let mut b = Reconciler::new(MemoryIndex::new(right.iter().copied()), config);
        reconcile(&mut a, &mut b, None);
        (a.want().clone(), a.offer().clone())
    };

    for kill_after in 0..12 {
        // A session that is killed part-way through.
        let mut a = Reconciler::new(MemoryIndex::new(left.iter().copied()), config);
        let mut b = Reconciler::new(MemoryIndex::new(right.iter().copied()), config);
        reconcile(&mut a, &mut b, Some(kill_after));

        // Everything about that session is now discarded, including whatever
        // it had partially learned. Only the durable sets survive.
        drop(a);
        drop(b);

        let mut a = Reconciler::new(MemoryIndex::new(left.iter().copied()), config);
        let mut b = Reconciler::new(MemoryIndex::new(right.iter().copied()), config);
        reconcile(&mut a, &mut b, None);

        assert_eq!(
            (a.want().clone(), a.offer().clone()),
            uninterrupted,
            "a session killed after {kill_after} rounds must reconcile to the same \
             answer once restarted"
        );
    }
}

/// Randomised over many shapes: disjoint, nested, interleaved, lopsided.
#[test]
fn randomised_set_pairs_converge_to_the_exact_difference() {
    let mut rng = Rng::seeded(0x5EA5_0DED);
    let config = RbsrConfig::default();

    for case in 0..200u32 {
        let universe = 1 + rng.below(600);
        let left_density = rng.below(101) as u32;
        let right_density = rng.below(101) as u32;

        let mut left = BTreeSet::new();
        let mut right = BTreeSet::new();
        for value in 0..universe {
            // Values are hashed into the identifier space so the sets are
            // scattered rather than contiguous, which is what real ChangeHash
            // values look like.
            let id = {
                let bytes = blake3_of(value);
                ItemId::from_bytes(bytes)
            };
            if (rng.below(100) as u32) < left_density {
                left.insert(id);
            }
            if (rng.below(100) as u32) < right_density {
                right.insert(id);
            }
        }

        let cost = assert_exact_difference(&left, &right, config);
        assert!(cost.rounds >= 1, "case {case}: reconciliation must exchange at least one round");
    }
}

/// A small deterministic generator, so a failing case is reproducible from
/// the seed alone and the test pulls in no randomness from the environment.
struct Rng(u64);

impl Rng {
    fn seeded(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A value in `0..limit`.
    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit
    }
}

fn blake3_of(value: u64) -> [u8; 32] {
    // A stand-in for a content hash: any well-distributed map will do.
    let mut state = 0xcbf2_9ce4_8422_2325u64;
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        state ^= value.wrapping_add(0x9e37_79b9_7f4a_7c15);
        state = state.wrapping_mul(0x100_0000_01b3);
        state ^= state >> 29;
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    bytes
}
