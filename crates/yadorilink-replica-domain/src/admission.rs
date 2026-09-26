//! Pure value types describing the outcome of admitting a verified
//! [`crate::change::Change`] into a device's local history, plus the
//! signing identity a device uses to author its own changes.

use crate::ids::{AuthorSeq, ChangeHash};
use crate::rebootstrap::{HistoryBase, HistoryEpoch};
use crate::recursive_operation::RecursiveOperationId;

/// How two changes relate in DAG ancestry order, derived purely from
/// ancestry, never from per-file counters — the version-vector model it
/// replaced could be advanced by a peer, while ancestry is fixed by the
/// signed change bytes themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeOrdering {
    /// The same change.
    Equal,
    /// The left change is an ancestor of the right one.
    Before,
    /// The left change is a descendant of the right one.
    After,
    /// Neither is an ancestor of the other: a genuine fork.
    Concurrent,
}

/// What an author's next change must continue from.
///
/// An author's position is its watermark and this anchor together. The
/// watermark says which sequence comes next; the anchor says what that next
/// change must link to.
///
/// * `ActiveTip` — the change that attained the watermark is part of the
///   current history, and the next change names it as `author_prev`.
/// * `Base` — the watermark was carried by the named history base, which
///   absorbed the change that attained it. The next change links to the
///   base through its own signed history epoch and names no predecessor:
///   a change hash can only name a change, and the change it would name is
///   history the base already stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorAnchor {
    Base(HistoryBase),
    ActiveTip(ChangeHash),
}

impl std::fmt::Display for AuthorAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base(base) => write!(f, "history base {}", base.to_hex()),
            Self::ActiveTip(tip) => write!(f, "tip {}", tip.to_hex()),
        }
    }
}

/// Why a change was refused by its own author's chain.
///
/// Every variant here is final. A change refused for any of these reasons is
/// not stored, not buffered, and not reconsidered: each one says that the
/// author's own history, as this replica knows it, cannot accommodate the
/// change, and nothing a peer could send afterwards makes that untrue. There
/// is deliberately no "hold and see" disposition — the DAG's ordinary orphan
/// buffer already covers everything that is merely early, and a second,
/// sequence-shaped waiting room would only delay a verdict that is already
/// decided.
///
/// Each carries the author's position rather than its identity: the group and
/// device are always the ones of the change being refused, so repeating them
/// here would add nothing a caller does not already hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorChainRefusal {
    /// A different change is already retained at exactly this author's dot.
    /// Two changes at one dot is equivocation: it is outside the merge
    /// domain, because the per-author high-water mark stops deciding
    /// membership the moment one number can name two changes.
    AuthorEquivocation { seq: AuthorSeq, held: ChangeHash },
    /// The change sits at or below the author's watermark, and is not a
    /// change this replica holds. The author's history therefore forked at
    /// or before a position this replica has already passed.
    ///
    /// Not reported as equivocation: the watermark and tip alone do not
    /// prove a collision at this exact sequence — the colliding change may
    /// have been compacted away, or may never have been at this position at
    /// all. What they do prove is that this change contradicts known
    /// history, which is enough to refuse it and not enough to accuse.
    ForkedAuthorHistory { watermark: AuthorSeq, seq: AuthorSeq },
    /// The sequence skips one, and no later delivery can close the skip.
    ///
    /// A skipped sequence on its own is NOT this: author ordering is not DAG
    /// causality, so an author's previous change is routinely not an
    /// ancestor of its next one and can simply be in flight while its
    /// successor is here. That case is held in the ordinary orphan buffer
    /// against the missing predecessor's name, exactly like a missing DAG
    /// parent, and never reaches this refusal.
    ///
    /// This refusal is only for a gap that is decided now and cannot become
    /// undecided:
    ///
    /// * the change names no previous change of its own while claiming a
    ///   position past the first — nothing that could arrive would supply
    ///   the predecessor it declined to name;
    /// * the predecessor it names is one this replica already holds, so
    ///   that predecessor's own position is known and this change's
    ///   sequence contradicts it.
    AuthorSequenceGap { expected: AuthorSeq, found: AuthorSeq },
    /// The sequence is the author's next one, but the change does not link
    /// to what this replica holds as that author's anchor. Against an
    /// active tip, it names some other previous change of its own — it
    /// continues another branch of its own history while claiming this
    /// position. Against a history base, it names any previous change at
    /// all: the change that attained the carried watermark is absorbed into
    /// the base, so the first change on the base names none.
    ///
    /// Compared by identity, never by ancestry. `author_prev` is the author
    /// ordering link and nothing else: the change's DAG parents stay the
    /// causal basis its author actually observed, which for an ordinary
    /// local edit is the basis of the edited bytes rather than that author's
    /// own latest write. Requiring the tip to be a DAG ancestor would refuse
    /// exactly that ordinary edit, while requiring the change to name the
    /// tip refuses only a genuine fork of the author's own chain.
    ///
    /// `named` is `None` when the change names no predecessor while its
    /// author's anchor here is an active tip.
    AuthorPrevMismatch { seq: AuthorSeq, anchor: AuthorAnchor, named: Option<ChangeHash> },
    /// The author's position here was carried by a history base, and the
    /// change is written on a different history than that base. The first
    /// change after a carried position continues it only through its signed
    /// history epoch, so a change on any other history cannot take it.
    AuthorAnchoredOnAnotherBase { seq: AuthorSeq, anchor: HistoryBase, incoming: HistoryEpoch },
    /// The change claims a position for an author this replica has no
    /// record of, yet names a previous change of its own. An author's first
    /// change in a group has no predecessor to name, so a change that
    /// names one is claiming a history this replica was never given.
    AuthorPrevWithoutPredecessor { named: ChangeHash },
    /// This author has reached the highest sequence a change may carry, so
    /// it has no next position at all. Fail-closed: the alternative to
    /// refusing is reusing a dot, and two changes at one dot ends the
    /// per-author ordering every convergence argument here rests on.
    AuthorSequenceExhausted { watermark: AuthorSeq },
    /// The change claims a part of one of its author's recursive
    /// operations, and disagrees with a part of that operation already
    /// admitted on this history about the operation-wide descriptor: its
    /// kind, scope paths, part count or effect-set hash. Only the author
    /// can sign a part of its own operation, so this is the author
    /// contradicting itself. Within one history an author's changes are
    /// admitted in sequence order everywhere, so every replica on it
    /// refuses the same change.
    RecursiveOperationContradicted { operation: RecursiveOperationId, part_index: u32 },
    /// The change claims a part index of one of its author's recursive
    /// operations that another change already carries on this history.
    RecursiveOperationPartHeld {
        operation: RecursiveOperationId,
        part_index: u32,
        held: ChangeHash,
    },
}

impl std::fmt::Display for AuthorChainRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorEquivocation { seq, held } => write!(
                f,
                "author sequence {seq} is already held by a different change ({})",
                held.to_hex()
            ),
            Self::ForkedAuthorHistory { watermark, seq } => write!(
                f,
                "author sequence {seq} is at or below this author's watermark {watermark}, so it \
                 contradicts history this replica already holds"
            ),
            Self::AuthorSequenceGap { expected, found } => {
                write!(f, "author sequence {found} skips past the only admissible one, {expected}")
            }
            Self::AuthorPrevMismatch { seq, anchor, named } => match named {
                Some(named) => write!(
                    f,
                    "author sequence {seq} names {} as its author's previous change, while this \
                     author continues here from {anchor}",
                    named.to_hex(),
                ),
                None => write!(
                    f,
                    "author sequence {seq} names no previous change of its own, while this \
                     author continues here from {anchor}"
                ),
            },
            Self::AuthorAnchoredOnAnotherBase { seq, anchor, incoming } => write!(
                f,
                "author sequence {seq} is written on {incoming}, while this author's position \
                 here was carried by history base {}",
                anchor.to_hex()
            ),
            Self::AuthorPrevWithoutPredecessor { named } => write!(
                f,
                "a first change in this group names {} as its author's previous change, but this \
                 replica has no position at all for that author",
                named.to_hex()
            ),
            Self::AuthorSequenceExhausted { watermark } => write!(
                f,
                "this author has reached the highest sequence a change may carry ({watermark}), \
                 so it has no next position"
            ),
            Self::RecursiveOperationContradicted { operation, part_index } => write!(
                f,
                "part {part_index} of recursive operation {} disagrees with that operation's \
                 recorded kind, paths, part count or effect-set hash",
                operation.to_hex()
            ),
            Self::RecursiveOperationPartHeld { operation, part_index, held } => write!(
                f,
                "part {part_index} of recursive operation {} is already carried by change {}",
                operation.to_hex(),
                held.to_hex()
            ),
        }
    }
}

/// Why a change was refused admission outright, with nothing held back for
/// a retry.
///
/// Distinct verdicts, deliberately not merged into one. A foreign history
/// base says the change belongs to a different history than this replica's;
/// an author-chain refusal says it belongs to this history and its own
/// author's chain cannot take it. Collapsing those two would report a
/// returning device's entire old history as a forked author, which is both
/// wrong and unactionable — the returning device needs a re-bootstrap, not
/// an accusation. A refusal behind a refused parent accuses the change of
/// nothing at all: it only names the parent it can never have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// The change was written on a history this replica is not on. It is
    /// not early, not corrupt, and not unauthorized: it is simply from
    /// another history, and no amount of further delivery makes it
    /// admissible here. The way forward for its author is to install this
    /// replica's base and re-author what is genuinely new onto it.
    ForeignHistoryBase { local: HistoryEpoch, incoming: HistoryEpoch },
    /// The change is on this history, and its own author's chain refuses
    /// it.
    AuthorChain(AuthorChainRefusal),
    /// One of the change's DAG parents is itself permanently refused here,
    /// so its ancestry can never be complete. Not held like a change whose
    /// parent is merely missing: the name it waits on is already settled,
    /// so nothing would ever wake it, and nothing would ask a peer for it
    /// again either.
    BehindRejectedParent { parent: ChangeHash },
    /// The change is on this history and names, as a base head it
    /// observed, a change that is not a head of this history's base at any
    /// path it touches (see
    /// [`crate::change::Change::observed_base_heads`]). Measured against
    /// the base this replica is on, like a foreign history base, and final
    /// for as long as the replica stays on it: a signed claim to have seen
    /// something the base never carried there is not made true by any
    /// later delivery.
    InvalidObservedBaseHead { local: HistoryEpoch, head: ChangeHash },
}

impl std::fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignHistoryBase { local, incoming } => write!(
                f,
                "change was written on {incoming}, while this replica's history is {local}"
            ),
            Self::AuthorChain(refusal) => refusal.fmt(f),
            Self::BehindRejectedParent { parent } => write!(
                f,
                "DAG parent {} is permanently refused here, so this change's ancestry can \
                 never be complete",
                parent.to_hex()
            ),
            Self::InvalidObservedBaseHead { local, head } => write!(
                f,
                "change names {} as an observed base head, which {local} carries at no path the \
                 change touches",
                head.to_hex()
            ),
        }
    }
}

/// Why a change was refused for a path it names.
///
/// Decided from the change's own signed bytes alone, before anything about
/// its ancestry or its author is consulted, and final for the same reason:
/// re-delivering the identical change can never produce another verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRefusal {
    /// The path collides with the reserved artefact namespace this project
    /// writes its own staging and lock files under.
    ReservedNamespaceCollision { path: String },
    /// The path cannot be stored faithfully and unambiguously on every
    /// platform this group may sync to.
    NonPortablePath { path: String },
}

impl std::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReservedNamespaceCollision { path } => {
                write!(f, "reserved namespace collision: {path:?}")
            }
            Self::NonPortablePath { path } => write!(f, "non-portable path: {path:?}"),
        }
    }
}

/// Outcome of admitting a verified change from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The change's ancestry was complete; it (and any orphans it unblocked)
    /// were inserted into `changes`.
    Applied,
    /// Something the change names has not arrived yet — one of its DAG
    /// parents, or the previous change of its own author that it names as
    /// `author_prev` — so it is held in the bounded orphan buffer until
    /// that arrives. Both are the same situation: a named change this
    /// replica does not have, and one holding buffer serves both.
    Orphaned,
    /// The change's ancestry was complete, and its author's own chain
    /// refuses it. Nothing was written and nothing is held: see
    /// [`AuthorChainRefusal`] for why each of these is final.
    RefusedAuthorChain(AuthorChainRefusal),
    /// The change was written on a different history than this replica's.
    /// Nothing was written and nothing is held; see
    /// [`AdmissionRefusal::ForeignHistoryBase`].
    RefusedForeignHistoryBase { local: HistoryEpoch, incoming: HistoryEpoch },
    /// The change names a path no replica may store. Nothing was written
    /// for the change itself; the refusal is recorded durably and whatever
    /// was held waiting on the change is released, in the same transaction.
    /// It is an outcome rather than an error for exactly that reason: an
    /// error rolls back the caller's transaction, and the record and the
    /// release with it.
    RefusedPath(PathRefusal),
    /// One of the change's DAG parents is permanently refused here; see
    /// [`AdmissionRefusal::BehindRejectedParent`]. Nothing was written for
    /// the change and nothing is held.
    RefusedBehindRejectedParent { parent: ChangeHash },
    /// The change names an observed base head its base does not carry at
    /// any path it touches; see [`AdmissionRefusal::InvalidObservedBaseHead`].
    /// Nothing was written for the change and nothing is held.
    RefusedInvalidObservedBaseHead { local: HistoryEpoch, head: ChangeHash },
}

impl AdmitOutcome {
    /// The admission refusal this outcome carries, if any. A path refusal
    /// is not one: it is reported on its own, as a [`PathRefusal`].
    pub fn refusal(&self) -> Option<AdmissionRefusal> {
        match *self {
            Self::Applied | Self::Orphaned | Self::RefusedPath(_) => None,
            Self::RefusedAuthorChain(refusal) => Some(AdmissionRefusal::AuthorChain(refusal)),
            Self::RefusedForeignHistoryBase { local, incoming } => {
                Some(AdmissionRefusal::ForeignHistoryBase { local, incoming })
            }
            Self::RefusedBehindRejectedParent { parent } => {
                Some(AdmissionRefusal::BehindRejectedParent { parent })
            }
            Self::RefusedInvalidObservedBaseHead { local, head } => {
                Some(AdmissionRefusal::InvalidObservedBaseHead { local, head })
            }
        }
    }
}

impl From<AdmissionRefusal> for AdmitOutcome {
    fn from(refusal: AdmissionRefusal) -> Self {
        match refusal {
            AdmissionRefusal::AuthorChain(refusal) => Self::RefusedAuthorChain(refusal),
            AdmissionRefusal::ForeignHistoryBase { local, incoming } => {
                Self::RefusedForeignHistoryBase { local, incoming }
            }
            AdmissionRefusal::BehindRejectedParent { parent } => {
                Self::RefusedBehindRejectedParent { parent }
            }
            AdmissionRefusal::InvalidObservedBaseHead { local, head } => {
                Self::RefusedInvalidObservedBaseHead { local, head }
            }
        }
    }
}

/// The full result of admitting a verified change: its outcome plus the hashes
/// of every change that actually landed in `changes` as a side-effect of this
/// admission. `newly_admitted` is the current change followed by every orphan
/// its arrival unblocked, in the order they were appended. It is empty for
/// `Orphaned`.
///
/// The caller needs the promoted-orphan hashes, not just the current one: when
/// a child change arrives before its parent it is buffered, and the parent's
/// later admission both applies the parent AND promotes the child. Both changes
/// become durable in the same call, so both must have their paths projected and
/// their `applied` flag gated in the same batch — otherwise a promoted orphan's
/// paths would not materialize until the periodic reprojection backstop runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitResult {
    pub outcome: AdmitOutcome,
    pub newly_admitted: Vec<ChangeHash>,
}

/// The material a device needs to sign the changes it originates: its own
/// id and its Ed25519 signing key. Held separately from the store so the
/// store never touches secret key material.
pub struct ChangeEmitter {
    device_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl ChangeEmitter {
    pub fn new(device_id: impl Into<String>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { device_id: device_id.into(), signing_key }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }

    pub fn signing_key_fingerprint(&self) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(self.signing_key.verifying_key().as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered message is persisted into `rejected_changes.reason` and
    /// emitted by `tracing::warn!`, so a broken line-continuation that leaves
    /// a run of spaces in the middle of the sentence is not merely cosmetic.
    /// Every variant must render as a single, normally-spaced sentence.
    #[test]
    fn display_never_produces_a_double_space() {
        let hash = ChangeHash([0u8; 32]);
        let variants = [
            AuthorChainRefusal::AuthorEquivocation { seq: AuthorSeq(1), held: hash },
            AuthorChainRefusal::ForkedAuthorHistory { watermark: AuthorSeq(1), seq: AuthorSeq(2) },
            AuthorChainRefusal::AuthorSequenceGap { expected: AuthorSeq(1), found: AuthorSeq(3) },
            AuthorChainRefusal::AuthorPrevMismatch {
                seq: AuthorSeq(2),
                anchor: AuthorAnchor::ActiveTip(hash),
                named: Some(ChangeHash([1u8; 32])),
            },
            AuthorChainRefusal::AuthorPrevMismatch {
                seq: AuthorSeq(2),
                anchor: AuthorAnchor::ActiveTip(hash),
                named: None,
            },
            AuthorChainRefusal::AuthorPrevMismatch {
                seq: AuthorSeq(2),
                anchor: AuthorAnchor::Base(HistoryBase([2u8; 32])),
                named: Some(hash),
            },
            AuthorChainRefusal::AuthorAnchoredOnAnotherBase {
                seq: AuthorSeq(2),
                anchor: HistoryBase([2u8; 32]),
                incoming: HistoryEpoch::Genesis,
            },
            AuthorChainRefusal::AuthorPrevWithoutPredecessor { named: hash },
            AuthorChainRefusal::AuthorSequenceExhausted { watermark: AuthorSeq::MAX },
        ];

        for variant in variants {
            let rendered = variant.to_string();
            assert!(
                !rendered.contains("  "),
                "rendered message contains a double space: {rendered:?}"
            );
        }
    }
}
