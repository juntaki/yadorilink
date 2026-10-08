//! The pure transition and join rules of signed per-path bases.
//!
//! A replica state is a watermark per author (the highest gap-free,
//! fork-free sequence number known) and, per path, the list of present heads.
//! Every function here is a deterministic function of its inputs, generic
//! over the change, path, author and version types, so admission, the
//! authoring self-check and reference tests instantiate the same rules.
//!
//! The rules and their guarantees:
//!
//! * [`step`] applies one change: a touched path becomes
//!   `(heads \ basis) ++ [c if c lands content]`, and the author's watermark
//!   becomes the change's sequence number. Correct when the change is next
//!   for its author and every basis member is a member of the history.
//! * [`join`] merges two states: `W = max`, and a head of one side survives
//!   when the other side also holds it or has not seen it. Correct when the
//!   union of the two histories has no author fork.
//! * [`verify_strict`] and [`verify_strict_safe`] are the author-side checks
//!   against the author's own pre-state; passing them keeps every basis made
//!   of current heads and loses no pre-state head silently. They do not make
//!   an author consume its own heads. The live per-author bound (a bounded
//!   number of heads per author per path) is not a kernel rule: the caller
//!   reads the author's bucket after [`step`], holding such a change at
//!   admission and refusing it before signing. At most one head per author
//!   per path is required only when a base is sealed.
//! * [`full_join`] joins two states given relative to different bases,
//!   without any change between the bases.
//! * [`recover_watermark`] reads an author's watermark from its base anchor
//!   and its tip header, so the current watermark is never stored.
//! * [`value_patch`] and [`tip_overlay`] compute the base-relative form of a
//!   state that [`full_join`] and [`recover_watermark`] read back.
//! * [`basis_encoding`] decodes compact bases against pre-state heads.
//!

use std::collections::{BTreeMap, BTreeSet};

pub mod basis_encoding;

/// One touched path of a change as the kernel sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KernelOp<P, C> {
    pub path: P,
    /// Whether the change lands content at `path` (`false` for a delete).
    pub lands: bool,
    /// The heads the change supersedes at `path`.
    pub basis: Vec<C>,
}

/// The signed data of a change the kernel reads.
///
pub trait Protocol {
    type Change: Clone + Ord;
    type Path: Clone + Ord;
    type Author: Clone + Ord;

    fn author(&self, change: &Self::Change) -> Self::Author;
    /// Strictly positive.
    fn seq(&self, change: &Self::Change) -> u64;
    /// Every touched path, at most once each.
    fn ops(&self, change: &Self::Change) -> Vec<KernelOp<Self::Path, Self::Change>>;
}

/// A signed conflict preservation as the kernel sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KernelPreservation<P, C> {
    pub source_path: P,
    pub source: C,
    pub target_path: P,
}

/// A protocol whose changes carry versions and conflict preservations.
///
pub trait SafeProtocol: Protocol {
    type Version: Eq;

    /// The content version `change` lands at `path`.
    fn version(&self, change: &Self::Change, path: &Self::Path) -> Self::Version;
    fn preservations(
        &self,
        change: &Self::Change,
    ) -> Vec<KernelPreservation<Self::Path, Self::Change>>;
    /// The deterministic conflict path of `source`'s version at `path`.
    fn conflict_path(&self, path: &Self::Path, source: &Self::Change) -> Self::Path;
}

/// A replica state. An absent author has watermark 0; an absent path has
/// no heads.
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct State<P: Ord, C, A: Ord> {
    pub watermarks: BTreeMap<A, u64>,
    pub heads: BTreeMap<P, Vec<C>>,
}

/// A state given relative to a base: the base's heads and watermarks, the
/// paths whose heads differ from it, and the tips of the authors that
/// wrote since.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BaseRelativeState<P: Ord, C, A: Ord> {
    pub base: State<P, C, A>,
    /// Paths whose heads differ from `base`; an empty list is a path with
    /// no present entry.
    pub value_patch: BTreeMap<P, Vec<C>>,
    /// The current tip of every author that wrote since `base`.
    pub tip_patch: BTreeMap<A, C>,
}

/// The clause of the author-side rule a change fails.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StrictViolation<P, C> {
    SeqNotNext { expected: u64, got: u64 },
    DuplicateTouchedPath { path: P },
    DuplicateBasisMember { path: P, member: C },
    BasisNotCurrentHead { path: P, member: C },
    DuplicatePreservationTarget { target_path: P },
    PreservationSourceNotInBasis { source_path: P, source: C },
    PreservationTargetNotCanonical { target_path: P },
    PreservationTargetNotLanded { target_path: P },
    PreservationTargetHasBasis { target_path: P },
    PreservationVersionMismatch { target_path: P },
}

impl<P: Ord, C, A: Ord> State<P, C, A> {
    /// The state of the empty history: every watermark 0, no heads.
    ///
    pub fn empty() -> Self {
        Self { watermarks: BTreeMap::new(), heads: BTreeMap::new() }
    }

    /// The watermark of `author` (0 when absent).
    ///
    pub fn watermark(&self, author: &A) -> u64 {
        watermark_of(&self.watermarks, author)
    }

    /// The heads at `path` (empty when absent).
    ///
    pub fn heads_at(&self, path: &P) -> &[C] {
        self.heads.get(path).map_or(&[], Vec::as_slice)
    }
}

impl<P: Ord, C, A: Ord> Default for State<P, C, A> {
    fn default() -> Self {
        Self::empty()
    }
}

fn watermark_of<A: Ord>(watermarks: &BTreeMap<A, u64>, author: &A) -> u64 {
    watermarks.get(author).copied().unwrap_or(0)
}

/// Stores `heads` at `path`, removing the entry when it is empty so that an
/// absent path and a path with no heads compare equal.
fn set_heads<P: Ord, C>(heads: &mut BTreeMap<P, Vec<C>>, path: P, value: Vec<C>) {
    if value.is_empty() {
        heads.remove(&path);
    } else {
        heads.insert(path, value);
    }
}

/// Whether `change` touches `path`.
///
pub fn touched<Pr: Protocol>(protocol: &Pr, change: &Pr::Change, path: &Pr::Path) -> bool {
    protocol.ops(change).iter().any(|op| &op.path == path)
}

/// Whether `change` lands content at `path`.
///
pub fn lands<Pr: Protocol>(protocol: &Pr, change: &Pr::Change, path: &Pr::Path) -> bool {
    protocol.ops(change).iter().any(|op| &op.path == path && op.lands)
}

/// Whether `member` is in the basis `change` signs at `path`.
///
pub fn in_basis<Pr: Protocol>(
    protocol: &Pr,
    change: &Pr::Change,
    path: &Pr::Path,
    member: &Pr::Change,
) -> bool {
    protocol.ops(change).iter().any(|op| &op.path == path && op.basis.contains(member))
}

/// Per touched path: whether any op lands content there, and the union of
/// the bases of the ops at that path. Folding with `any` keeps
/// `touched`/`lands`/`in_basis` exact even for a list with repeated paths,
/// which `verify_strict` rejects but `step` still accepts.
fn ops_by_path<P: Ord, C: Ord>(ops: Vec<KernelOp<P, C>>) -> BTreeMap<P, (bool, BTreeSet<C>)> {
    let mut by_path: BTreeMap<P, (bool, BTreeSet<C>)> = BTreeMap::new();
    for op in ops {
        let entry = by_path.entry(op.path).or_default();
        entry.0 |= op.lands;
        entry.1.extend(op.basis);
    }
    by_path
}

/// Applies `change` to `state`.
///
/// Admission-time transition. The caller has established that the change's
/// sequence number is the author's watermark plus one and that every basis
/// member is a member of the history; without the latter the result would
/// depend on arrival order.
///
pub fn step<Pr: Protocol>(
    protocol: &Pr,
    state: &State<Pr::Path, Pr::Change, Pr::Author>,
    change: &Pr::Change,
) -> State<Pr::Path, Pr::Change, Pr::Author> {
    let mut next = state.clone();
    next.watermarks.insert(protocol.author(change), protocol.seq(change));
    for (path, (lands, basis)) in ops_by_path(protocol.ops(change)) {
        let mut heads: Vec<Pr::Change> =
            state.heads_at(&path).iter().filter(|head| !basis.contains(head)).cloned().collect();
        if lands {
            heads.push(change.clone());
        }
        set_heads(&mut next.heads, path, heads);
    }
    next
}

/// Whether the side with watermarks `watermarks` has not yet seen `change`.
fn unseen<Pr: Protocol>(
    protocol: &Pr,
    watermarks: &BTreeMap<Pr::Author, u64>,
    change: &Pr::Change,
) -> bool {
    protocol.seq(change) > watermark_of(watermarks, &protocol.author(change))
}

/// The joined heads of one path: a left head survives when the right side
/// holds it too or has not seen it; a right head survives when the left
/// side has not seen it.
///
fn join_heads<Pr: Protocol>(
    protocol: &Pr,
    left: &[Pr::Change],
    right: &[Pr::Change],
    left_watermarks: &BTreeMap<Pr::Author, u64>,
    right_watermarks: &BTreeMap<Pr::Author, u64>,
) -> Vec<Pr::Change> {
    let kept_left =
        left.iter().filter(|x| right.contains(x) || unseen(protocol, right_watermarks, x));
    let kept_right = right.iter().filter(|x| unseen(protocol, left_watermarks, x));
    kept_left.chain(kept_right).cloned().collect()
}

/// Joins two states.
///
/// Requires the union of the two histories to have no author fork. Used for
/// merges, sync and recovery alike.
///
pub fn join<Pr: Protocol>(
    protocol: &Pr,
    left: &State<Pr::Path, Pr::Change, Pr::Author>,
    right: &State<Pr::Path, Pr::Change, Pr::Author>,
) -> State<Pr::Path, Pr::Change, Pr::Author> {
    let mut watermarks = left.watermarks.clone();
    for (author, &w) in &right.watermarks {
        let entry = watermarks.entry(author.clone()).or_insert(w);
        *entry = (*entry).max(w);
    }
    let paths: BTreeSet<&Pr::Path> = left.heads.keys().chain(right.heads.keys()).collect();
    let mut heads = BTreeMap::new();
    for path in paths {
        let joined = join_heads(
            protocol,
            left.heads_at(path),
            right.heads_at(path),
            &left.watermarks,
            &right.watermarks,
        );
        set_heads(&mut heads, path.clone(), joined);
    }
    State { watermarks, heads }
}

/// Checks `change` against the author's own pre-state `state`: its
/// sequence number is next, touched paths are distinct, and each basis is
/// duplicate-free and made of current heads.
///
/// An author's own current head is deliberately not required in the basis:
/// a write never supersedes a version its author did not observe, so the
/// same author may hold several unresolved heads at a path. The per-author
/// head bound is enforced when a base is sealed instead.
///
pub fn verify_strict<Pr: Protocol>(
    protocol: &Pr,
    state: &State<Pr::Path, Pr::Change, Pr::Author>,
    change: &Pr::Change,
) -> Result<(), StrictViolation<Pr::Path, Pr::Change>> {
    let author = protocol.author(change);
    let expected = state.watermark(&author).saturating_add(1);
    let got = protocol.seq(change);
    if got != expected {
        return Err(StrictViolation::SeqNotNext { expected, got });
    }
    let ops = protocol.ops(change);
    let mut paths = BTreeSet::new();
    for op in &ops {
        if !paths.insert(&op.path) {
            return Err(StrictViolation::DuplicateTouchedPath { path: op.path.clone() });
        }
    }
    for op in &ops {
        verify_strict_op::<Pr>(state, op)?;
    }
    Ok(())
}

/// The per-op clauses of `verifyStrict`: the basis is duplicate-free and a
/// subset of the current heads.
///
fn verify_strict_op<Pr: Protocol>(
    state: &State<Pr::Path, Pr::Change, Pr::Author>,
    op: &KernelOp<Pr::Path, Pr::Change>,
) -> Result<(), StrictViolation<Pr::Path, Pr::Change>> {
    let mut members = BTreeSet::new();
    for member in &op.basis {
        if !members.insert(member) {
            return Err(StrictViolation::DuplicateBasisMember {
                path: op.path.clone(),
                member: member.clone(),
            });
        }
    }
    let heads = state.heads_at(&op.path);
    if let Some(member) = op.basis.iter().find(|member| !heads.contains(member)) {
        return Err(StrictViolation::BasisNotCurrentHead {
            path: op.path.clone(),
            member: member.clone(),
        });
    }
    Ok(())
}

/// [`verify_strict`] plus, per preservation (optional; no rule requires
/// one): the source is in the basis of
/// its path, the target is the canonical conflict path, the change lands
/// content there with an empty basis and the source's version, and
/// targets are distinct. Every pre-state head then either stays, is in the
/// signed observed part of a basis, or is re-landed at its conflict path.
///
pub fn verify_strict_safe<Pr: SafeProtocol>(
    protocol: &Pr,
    state: &State<Pr::Path, Pr::Change, Pr::Author>,
    change: &Pr::Change,
) -> Result<(), StrictViolation<Pr::Path, Pr::Change>> {
    verify_strict(protocol, state, change)?;
    let preservations = protocol.preservations(change);
    let mut targets = BTreeSet::new();
    for preservation in &preservations {
        if !targets.insert(&preservation.target_path) {
            return Err(StrictViolation::DuplicatePreservationTarget {
                target_path: preservation.target_path.clone(),
            });
        }
    }
    let ops = protocol.ops(change);
    for preservation in &preservations {
        verify_preservation(protocol, change, &ops, preservation)?;
    }
    Ok(())
}

/// The per-preservation clauses of `verifyStrictSafe`.
///
fn verify_preservation<Pr: SafeProtocol>(
    protocol: &Pr,
    change: &Pr::Change,
    ops: &[KernelOp<Pr::Path, Pr::Change>],
    preservation: &KernelPreservation<Pr::Path, Pr::Change>,
) -> Result<(), StrictViolation<Pr::Path, Pr::Change>> {
    let KernelPreservation { source_path, source, target_path } = preservation;
    let source_in_basis = ops.iter().any(|op| &op.path == source_path && op.basis.contains(source));
    if !source_in_basis {
        return Err(StrictViolation::PreservationSourceNotInBasis {
            source_path: source_path.clone(),
            source: source.clone(),
        });
    }
    if *target_path != protocol.conflict_path(source_path, source) {
        return Err(StrictViolation::PreservationTargetNotCanonical {
            target_path: target_path.clone(),
        });
    }
    if !ops.iter().any(|op| &op.path == target_path && op.lands) {
        return Err(StrictViolation::PreservationTargetNotLanded {
            target_path: target_path.clone(),
        });
    }
    if ops.iter().any(|op| &op.path == target_path && !op.basis.is_empty()) {
        return Err(StrictViolation::PreservationTargetHasBasis {
            target_path: target_path.clone(),
        });
    }
    if protocol.version(change, target_path) != protocol.version(source, source_path) {
        return Err(StrictViolation::PreservationVersionMismatch {
            target_path: target_path.clone(),
        });
    }
    Ok(())
}

/// The paths whose heads in `state` differ from `base`, with their current
/// heads (an empty list for a path with no present entry left).
///
pub fn value_patch<P: Ord + Clone, C: Clone + Eq>(
    base: &BTreeMap<P, Vec<C>>,
    state: &BTreeMap<P, Vec<C>>,
) -> BTreeMap<P, Vec<C>> {
    let empty: &[C] = &[];
    let paths: BTreeSet<&P> = base.keys().chain(state.keys()).collect();
    paths
        .into_iter()
        .filter_map(|path| {
            let current = state.get(path).map_or(empty, Vec::as_slice);
            let at_base = base.get(path).map_or(empty, Vec::as_slice);
            (current != at_base).then(|| (path.clone(), current.to_vec()))
        })
        .collect()
}

/// The post-base author state: the tip of every author whose watermark
/// grew since the base, and nothing for the others.
///
pub fn tip_overlay<A: Ord + Clone, C: Clone>(
    base_watermarks: &BTreeMap<A, u64>,
    watermarks: &BTreeMap<A, u64>,
    tips: &BTreeMap<A, C>,
) -> BTreeMap<A, C> {
    tips.iter()
        .filter(|(author, _)| {
            watermark_of(base_watermarks, author) < watermark_of(watermarks, author)
        })
        .map(|(author, tip)| (author.clone(), tip.clone()))
        .collect()
}

/// Rebuilds the full state a base-relative state denotes: the base heads
/// overridden by the value patch, and every watermark recovered from the
/// base anchor and the tip patch.
///
fn rebuild<Pr: Protocol>(
    protocol: &Pr,
    side: &BaseRelativeState<Pr::Path, Pr::Change, Pr::Author>,
) -> State<Pr::Path, Pr::Change, Pr::Author> {
    let mut heads = side.base.heads.clone();
    for (path, value) in &side.value_patch {
        set_heads(&mut heads, path.clone(), value.clone());
    }
    let authors: BTreeSet<&Pr::Author> =
        side.base.watermarks.keys().chain(side.tip_patch.keys()).collect();
    let watermarks = authors
        .into_iter()
        .map(|author| {
            let w = recover_watermark(protocol, &side.base.watermarks, &side.tip_patch, author);
            (author.clone(), w)
        })
        .collect();
    State { watermarks, heads }
}

/// Joins two states given relative to different bases, with no change
/// between the bases: each side is rebuilt from its base, value patch and
/// tip patch, and the two are joined by [`join`].
///
/// Requires each base to be valid and the union of the two histories to
/// have no author fork. A digest-sharing traversal of two authenticated
/// namespaces computes the same result.
///
pub fn full_join<Pr: Protocol>(
    protocol: &Pr,
    left: &BaseRelativeState<Pr::Path, Pr::Change, Pr::Author>,
    right: &BaseRelativeState<Pr::Path, Pr::Change, Pr::Author>,
) -> State<Pr::Path, Pr::Change, Pr::Author> {
    join(protocol, &rebuild(protocol, left), &rebuild(protocol, right))
}

/// The watermark of `author`: the sequence number of its tip in
/// `tip_patch` when it wrote since the base, and its base watermark
/// otherwise.
///
pub fn recover_watermark<Pr: Protocol>(
    protocol: &Pr,
    base_watermarks: &BTreeMap<Pr::Author, u64>,
    tip_patch: &BTreeMap<Pr::Author, Pr::Change>,
    author: &Pr::Author,
) -> u64 {
    match tip_patch.get(author) {
        Some(tip) => protocol.seq(tip),
        None => watermark_of(base_watermarks, author),
    }
}
