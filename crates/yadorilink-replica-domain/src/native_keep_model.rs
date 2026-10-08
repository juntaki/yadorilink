//! A reference model of head-scoped kept copies, for tests.
//!
//! A kept copy is Observed-Remove state scoped to one head. This module is the
//! oracle the stores are checked against, and the generator of the delta
//! histories they are checked on. It has two layers:
//!
//! * [`ModelState`] folds [`KeepOp`]s one at a time with the permanent
//!   retirement tombstone: put and keep of a retired head are no-ops, a retire
//!   removes the head and its keep. Three deliberately broken variants
//!   ([`naive_prune_apply`], [`no_tombstone_apply`], and [`gc`] over a covered
//!   set that is not causally closed) are the regressions the stores must not
//!   have.
//! * [`apply_closed`] is the closed form of the machine: the observable projection of a set of deltas is
//!   `live = puts \ retires`, `kept = (keeps \ retires) ∩ live`, whatever the
//!   order. A real store that admits the same set of deltas, in any order and
//!   with any duplicates, must project exactly this.
//!
//! The projection a store exposes is [`Projection`]: the live heads and the
//! live kept heads, each named by `(path, dot, provenance)`. A delta's own
//! put has provenance `delta_hash()`, a removal or keep names the provenance it
//! saw, and a name that does not match a real head is a no-op, exactly as at
//! admission.
//!
//! # Plugging in an external vector set
//!
//! A vector set from another implementation of this model needs only to emit,
//! per case, the list of [`KeepOp`]s (or the deltas they came from) and the
//! expected [`Projection`]. [`ops_of`] is the one place a delta becomes ops,
//! and [`Projection`] is the one value a store is compared on, so a vector set
//! is run by building the deltas of each case, feeding them through the store
//! (see `Scenario::signed`-style construction below), and comparing the store's
//! projection with the exported one instead of with [`apply_closed`].

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use crate::author::{AuthorId, IncarnationId};
use crate::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::native_state::{DeltaHash, HeadId};
use crate::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};

/// What a store exposes about kept copies: its live heads (with their
/// versions) and, among them, the kept ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Projection {
    pub live: BTreeMap<HeadId, VersionHash>,
    pub kept: BTreeSet<HeadId>,
}

impl Projection {
    /// The `(path, version)` pairs the planner treats as kept copies: a version
    /// is kept at a path while a live head of it there is kept.
    pub fn kept_versions(&self) -> BTreeSet<(SyncPath, VersionHash)> {
        self.kept
            .iter()
            .filter_map(|key| self.live.get(key).map(|version| (key.path.clone(), *version)))
            .collect()
    }

    /// Whether every kept head is live (the store invariant: a keep names a
    /// live head).
    pub fn is_well_formed(&self) -> bool {
        self.kept.iter().all(|key| self.live.contains_key(key))
    }
}

/// One operation of the reference model.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeepOp {
    Put(HeadId, VersionHash),
    Keep(HeadId),
    Retire(HeadId),
}

impl KeepOp {
    pub fn head(&self) -> &HeadId {
        match self {
            KeepOp::Put(key, _) | KeepOp::Keep(key) | KeepOp::Retire(key) => key,
        }
    }
}

/// The operations a delta carries: its puts, the keeps it declares (exact
/// heads and its own put when flagged) and the retirements its removals name.
pub fn ops_of(delta: &NativeDelta) -> Vec<KeepOp> {
    let hash = delta.delta_hash();
    let mut out = Vec::new();
    for op in &delta.ops {
        for removal in &op.removes {
            out.push(KeepOp::Retire(HeadId {
                path: op.path.clone(),
                dot: removal.dot.clone(),
                provenance: removal.provenance,
            }));
        }
        if let Some(put) = &op.put {
            let own = HeadId { path: op.path.clone(), dot: delta.dot(), provenance: hash };
            out.push(KeepOp::Put(own.clone(), put.version));
            if op.keep_put {
                out.push(KeepOp::Keep(own));
            }
        }
        for keep in &op.keeps {
            out.push(KeepOp::Keep(HeadId {
                path: op.path.clone(),
                dot: keep.dot.clone(),
                provenance: keep.provenance,
            }));
        }
    }
    out
}

/// The closed form of the machine: the projection of a set of deltas,
/// independent of order and of duplicates.
pub fn apply_closed<'a>(deltas: impl IntoIterator<Item = &'a NativeDelta>) -> Projection {
    closed_of_ops(deltas.into_iter().flat_map(ops_of))
}

/// [`apply_closed`] over operations.
pub fn closed_of_ops(ops: impl IntoIterator<Item = KeepOp>) -> Projection {
    let mut puts: BTreeMap<HeadId, VersionHash> = BTreeMap::new();
    let mut keeps: BTreeSet<HeadId> = BTreeSet::new();
    let mut retires: BTreeSet<HeadId> = BTreeSet::new();
    for op in ops {
        match op {
            KeepOp::Put(key, version) => {
                puts.insert(key, version);
            }
            KeepOp::Keep(key) => {
                keeps.insert(key);
            }
            KeepOp::Retire(key) => {
                retires.insert(key);
            }
        }
    }
    let live: BTreeMap<HeadId, VersionHash> =
        puts.into_iter().filter(|(key, _)| !retires.contains(key)).collect();
    let kept = keeps.into_iter().filter(|key| live.contains_key(key)).collect();
    Projection { live, kept }
}

/// The reference state machine: live heads, kept heads (including those not yet
/// live), and the permanent retirement tombstones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModelState {
    pub live: BTreeMap<HeadId, VersionHash>,
    pub keeps: BTreeSet<HeadId>,
    pub retired: BTreeSet<HeadId>,
}

impl ModelState {
    /// Put and keep of a retired head are no-ops; a retire
    /// tombstones the head and removes it from the live and kept sets.
    pub fn step(&mut self, op: &KeepOp) {
        match op {
            KeepOp::Put(key, version) => {
                if !self.retired.contains(key) {
                    self.live.insert(key.clone(), *version);
                }
            }
            KeepOp::Keep(key) => {
                if !self.retired.contains(key) {
                    self.keeps.insert(key.clone());
                }
            }
            KeepOp::Retire(key) => {
                self.live.remove(key);
                self.keeps.remove(key);
                self.retired.insert(key.clone());
            }
        }
    }

    /// The projection: live heads, and keeps only of live heads.
    pub fn projection(&self) -> Projection {
        Projection {
            live: self.live.clone(),
            kept: self.keeps.iter().filter(|key| self.live.contains_key(*key)).cloned().collect(),
        }
    }
}

/// Fold the operations from the empty state.
pub fn model_apply(ops: &[KeepOp]) -> ModelState {
    model_continue(ModelState::default(), ops)
}

/// Fold the operations from a given state.
pub fn model_continue(mut state: ModelState, ops: &[KeepOp]) -> ModelState {
    for op in ops {
        state.step(op);
    }
    state
}

/// Garbage collection: a checkpoint keeps only the live heads and their keeps and drops
/// every tombstone and every keep of a non-live head.
pub fn gc(state: &ModelState) -> ModelState {
    ModelState {
        live: state.live.clone(),
        keeps: state.keeps.iter().filter(|key| state.live.contains_key(*key)).cloned().collect(),
        retired: BTreeSet::new(),
    }
}

/// The replay-ignore rule: a re-delivered covered op is
/// dropped.
pub fn drop_covered(covered: &[KeepOp], later: &[KeepOp]) -> Vec<KeepOp> {
    later.iter().filter(|op| !covered.contains(op)).cloned().collect()
}

/// Causal closure: a covered keep or retire of a head implies the put of
/// that head is covered.
pub fn causally_closed(covered: &[KeepOp]) -> bool {
    causally_closed_in(covered, covered)
}

/// [`causally_closed`] for a covered set that is part of a larger history
/// (`universe`): a keep or retire of a head that no delta ever puts (a name
/// whose provenance matches no real head) can never be resurrected by a later
/// put, so only a head the universe does put needs its put covered.
pub fn causally_closed_in(covered: &[KeepOp], universe: &[KeepOp]) -> bool {
    let has_put = |ops: &[KeepOp], key: &HeadId| {
        ops.iter().any(|other| matches!(other, KeepOp::Put(put_key, _) if put_key == key))
    };
    covered.iter().all(|op| match op {
        KeepOp::Put(..) => true,
        KeepOp::Keep(key) | KeepOp::Retire(key) => has_put(covered, key) || !has_put(universe, key),
    })
}

/// Mutant: after every op, drop the keeps of
/// heads that are not live. A keep that arrives before its head is lost.
pub fn naive_prune_apply(ops: &[KeepOp]) -> Projection {
    let mut state = ModelState::default();
    for op in ops {
        state.step(op);
        let live = state.live.clone();
        state.keeps.retain(|key| live.contains_key(key));
    }
    state.projection()
}

/// Mutant: a retire merely deletes, so a late
/// put resurrects the head.
pub fn no_tombstone_apply(ops: &[KeepOp]) -> Projection {
    let mut state = ModelState::default();
    for op in ops {
        match op {
            KeepOp::Put(key, version) => {
                state.live.insert(key.clone(), *version);
            }
            KeepOp::Keep(key) => {
                state.keeps.insert(key.clone());
            }
            KeepOp::Retire(key) => {
                state.live.remove(key);
                state.keeps.remove(key);
            }
        }
    }
    state.projection()
}

/// A small deterministic generator (splitmix64), so a failing history
/// reproduces from its seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }

    /// A random permutation of `0..n`.
    pub fn permutation(&mut self, n: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            order.swap(i, self.below(i + 1));
        }
        order
    }
}

/// How large a generated history is.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub authors: usize,
    pub paths: usize,
    pub deltas: usize,
    /// Distinct versions a put may carry; few, so heads share versions often.
    pub versions: u8,
}

/// A generated history: signed deltas in an order every delta's causal
/// dependencies precede, the keys that signed them and the authors.
pub struct Scenario {
    pub authors: Vec<AuthorId>,
    pub keys: Vec<SigningKey>,
    /// The author index (into `authors`) of each delta.
    pub author_of: Vec<usize>,
    pub deltas: Vec<NativeDelta>,
}

pub const GROUP: &str = "g1";

/// The path names a generated history uses.
pub fn path_name(index: usize) -> SyncPath {
    SyncPath(["a", "b", "c", "d"][index % 4].to_owned())
}

impl Scenario {
    /// The projection of the first `count` deltas in generation order.
    pub fn projection_of_prefix(&self, count: usize) -> Projection {
        apply_closed(&self.deltas[..count])
    }

    /// The deltas an author's own chain and its removals and keeps depend on:
    /// every earlier delta of the same author, and for every dot a removal or
    /// keep names, every delta of that author up to the dot.
    fn dependencies(&self, index: usize) -> Vec<usize> {
        let delta = &self.deltas[index];
        let mut deps: BTreeSet<usize> = BTreeSet::new();
        let mut upto = |author: &AuthorId, seq: AuthorSeq| {
            for (j, other) in self.deltas.iter().enumerate() {
                if other.author == *author && other.seq <= seq && j != index {
                    deps.insert(j);
                }
            }
        };
        upto(&delta.author, AuthorSeq(delta.seq.get().saturating_sub(1)));
        for op in &delta.ops {
            for removal in &op.removes {
                upto(&removal.dot.author, removal.dot.seq);
            }
            for keep in &op.keeps {
                upto(&keep.dot.author, keep.dot.seq);
            }
        }
        deps.into_iter().collect()
    }

    /// `seed` and everything it causally depends on.
    pub fn closure(&self, seeds: &[usize]) -> BTreeSet<usize> {
        let mut closed: BTreeSet<usize> = BTreeSet::new();
        let mut stack: Vec<usize> = seeds.to_vec();
        while let Some(index) = stack.pop() {
            if closed.insert(index) {
                stack.extend(self.dependencies(index));
            }
        }
        closed
    }
}

/// Generates a history: authors that each know a causally closed part of what
/// the others signed, and sign puts, removals of heads they know, keeps of
/// heads they know (live or already retired, rightly or wrongly named) and
/// own-put keeps.
pub fn generate(seed: u64, shape: Shape) -> Scenario {
    let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let authors: Vec<AuthorId> = (0..shape.authors)
        .map(|i| AuthorId {
            device: DeviceId(format!("device-{i}")),
            incarnation: IncarnationId([i as u8 + 1; 16]),
        })
        .collect();
    let keys: Vec<SigningKey> =
        (0..shape.authors).map(|i| SigningKey::from_bytes(&[i as u8 + 11; 32])).collect();
    let mut scenario = Scenario { authors, keys, author_of: Vec::new(), deltas: Vec::new() };
    let mut views: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); shape.authors];
    let mut tips: Vec<Option<(AuthorSeq, DeltaHash)>> = vec![None; shape.authors];

    for index in 0..shape.deltas {
        let who = rng.below(shape.authors);
        // The author first hears of some of what the others signed (with
        // everything that depended on).
        let unseen: Vec<usize> =
            (0..index).filter(|j| !views[who].contains(j) && rng.chance(40)).collect();
        let absorbed = scenario.closure(&unseen);
        views[who].extend(absorbed);

        let known: Vec<&NativeDelta> = views[who].iter().map(|j| &scenario.deltas[*j]).collect();
        let projection = apply_closed(known.iter().copied());
        let known_puts: BTreeMap<HeadId, VersionHash> = known
            .iter()
            .flat_map(|delta| ops_of(delta))
            .filter_map(|op| match op {
                KeepOp::Put(key, version) => Some((key, version)),
                _ => None,
            })
            .collect();

        let (seq, prev) = match tips[who] {
            None => (AuthorSeq::FIRST, None),
            Some((seq, hash)) => (seq.checked_next().expect("a short history"), Some(hash)),
        };

        let path_count = 1 + rng.below(2.min(shape.paths));
        let mut paths: Vec<SyncPath> = Vec::new();
        while paths.len() < path_count {
            let path = path_name(rng.below(shape.paths));
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        let mut ops = Vec::new();
        for path in paths {
            let live_here: Vec<&HeadId> =
                projection.live.keys().filter(|key| key.path == path).collect();
            let mut removes: Vec<HeadRef> = Vec::new();
            for key in &live_here {
                let own = key.dot.author == scenario.authors[who];
                if own || rng.chance(50) {
                    // An author always removes its own heads exactly, so a
                    // history never piles up own heads past the bound.
                    let provenance =
                        if own || rng.chance(88) { key.provenance } else { DeltaHash([0xEE; 32]) };
                    removes.push(HeadRef { dot: key.dot.clone(), provenance });
                }
            }
            // A removal naming a head that is no longer live (or a dot that
            // put elsewhere): admitted, and a no-op.
            if rng.chance(10) {
                if let Some(key) = known_puts.keys().find(|key| {
                    key.path == path
                        && !projection.live.contains_key(*key)
                        && !removes.iter().any(|r| r.dot == key.dot)
                }) {
                    removes.push(HeadRef { dot: key.dot.clone(), provenance: key.provenance });
                }
            }
            let put = rng.chance(75).then(|| DeltaPut {
                version: VersionHash([1 + rng.below(shape.versions as usize) as u8; 32]),
            });
            let mut keeps: Vec<HeadRef> = Vec::new();
            for key in known_puts.keys().filter(|key| key.path == path) {
                if removes.iter().any(|removal| removal.dot == key.dot) || !rng.chance(25) {
                    continue;
                }
                let provenance =
                    if rng.chance(92) { key.provenance } else { DeltaHash([0xDD; 32]) };
                keeps.push(HeadRef { dot: key.dot.clone(), provenance });
            }
            let keep_put = put.is_some() && rng.chance(30);
            if put.is_none() && removes.is_empty() && keeps.is_empty() {
                continue;
            }
            ops.push(DeltaOp { path, removes, put, keeps, keep_put });
        }
        if ops.is_empty() {
            let path = path_name(rng.below(shape.paths));
            let removes: Vec<HeadRef> = projection
                .live
                .keys()
                .filter(|key| key.path == path && key.dot.author == scenario.authors[who])
                .map(|key| HeadRef { dot: key.dot.clone(), provenance: key.provenance })
                .collect();
            ops.push(DeltaOp {
                path,
                removes,
                put: Some(DeltaPut { version: VersionHash([1; 32]) }),
                keeps: Vec::new(),
                keep_put: false,
            });
        }
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: FolderGroupId(GROUP.to_owned()),
            author: scenario.authors[who].clone(),
            seq,
            prev,
            ops,
            signature: [0u8; 64],
        };
        delta.sign(&scenario.keys[who]);
        tips[who] = Some((seq, delta.delta_hash()));
        scenario.author_of.push(who);
        scenario.deltas.push(delta);
        views[who].insert(index);
    }
    scenario
}

#[cfg(test)]
mod tests;
