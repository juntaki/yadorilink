//! Signed grouping for one recursive filesystem mutation split across
//! several changes.
//!
//! A recursive delete (`rm -rf a/`) or a directory rename (`a/ -> b/`) is,
//! logically, a finite set of point operations on the explicit entries the
//! mutating device observed under the directory. That set can be far larger
//! than one change may carry, so it is authored as a run of changes — the
//! operation's *parts*. Everything that later has to treat the operation as
//! one unit (restoring a deleted folder from the trash is the motivating
//! case) must be able to name the whole set exactly, and must never have to
//! guess it from author sequence adjacency, timestamps or a shared path
//! prefix: those heuristics either merge two unrelated operations or split
//! one, and they cannot tell a missing part from an operation that simply
//! had fewer parts.
//!
//! So every part carries a [`RecursiveOperation`] descriptor inside the
//! signed, hashed change encoding:
//!
//! * `operation_id` — author-chosen, random, never all zero. Two
//!   operations are the same operation only when they share the author
//!   *and* the id: a group is keyed by `(group, author device,
//!   operation_id)`, so one device can never claim, poison or complete
//!   another device's operation by reusing its id.
//! * `kind` — [`RecursiveOperationKind::RmTree`] with its `root`, or
//!   [`RecursiveOperationKind::RenameTree`] with `from` and `to`. The kind
//!   and its paths are one enum value, so a descriptor whose kind disagrees
//!   with the paths it carries cannot be represented, let alone encoded.
//! * `part_index` / `part_count` — this part's position and the total, so a
//!   reader can tell a complete operation from one with parts still missing
//!   (or lost for good).
//! * `effect_set_hash` — the [`EffectSetHash`] of every effect op of every
//!   part (a derived conflict-copy put is not an effect; see
//!   [`is_recursive_effect`]).
//!   It pins every part to the same observed effect set: parts that agree
//!   on everything else but were cut from different observations disagree
//!   here, and once all `part_count` parts are present the union of their
//!   ops must hash to it, which is what makes "complete" checkable rather
//!   than a count.
//!
//! The per-change well-formedness rules live in
//! [`RecursiveOperation::validate_part`]; the cross-part rules (every part
//! of one operation agrees on kind, paths, part count and effect-set hash;
//! a part index is filled by exactly one change) need the other parts and
//! are enforced where parts are recorded.

use sha2::{Digest, Sha256};

use crate::change::{Op, PutOrigin};
use crate::codec::{put_str, put_u32, ChangeError, Reader};
use crate::ids::{DeviceId, SyncPath};

/// The most parts one recursive operation may be split into. Each part is
/// a full change, so this bounds an operation at millions of entries while
/// keeping a hostile `part_count` from describing an operation no store
/// could ever hold the bookkeeping for.
pub const MAX_RECURSIVE_OPERATION_PARTS: u32 = 1 << 16;

/// Domain tag for [`EffectSetHash::of_effects`]. Distinct from every
/// change and file-version tag so an effect-set digest can never collide
/// with the identity of either.
const EFFECT_SET_DOMAIN_TAG: &[u8; 8] = b"YLNKres\x01";

/// The identity an author gives one recursive operation. 16 random bytes;
/// all-zero is reserved so an unset id cannot pass for a real one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursiveOperationId(pub [u8; 16]);

impl RecursiveOperationId {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Debug for RecursiveOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecursiveOperationId({})", hex::encode(self.0))
    }
}

/// A recursive operation's full name: its author and the id the author
/// gave it. Two parts belong to one operation exactly when their references
/// are equal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RecursiveOperationRef {
    pub author: DeviceId,
    pub operation_id: RecursiveOperationId,
}

/// SHA-256 over the canonical encoding of an operation's whole effect set;
/// see [`EffectSetHash::of_effects`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectSetHash(pub [u8; 32]);

impl std::fmt::Debug for EffectSetHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EffectSetHash({})", hex::encode(self.0))
    }
}

impl EffectSetHash {
    /// The digest of an operation's effect set: every effect op (see
    /// [`is_recursive_effect`]) of every part, in canonical op order, each in its canonical change encoding. The
    /// order the parts were cut in, and which part carries which op, do
    /// not enter it — the same observed set hashes the same however it was
    /// split.
    pub fn of_effects<'a, I>(ops: I) -> Self
    where
        I: IntoIterator<Item = &'a Op>,
    {
        let mut encoded: Vec<Vec<u8>> = ops
            .into_iter()
            .filter(|op| is_recursive_effect(op))
            .map(|op| {
                let mut buf = Vec::new();
                crate::change::encode_op(&mut buf, op);
                buf
            })
            .collect();
        // Byte order of the canonical encoding. Every encoding starts with
        // the op discriminant, so this is a total order that does not
        // depend on how the caller happened to list the ops.
        encoded.sort();
        let mut hasher = Sha256::new();
        hasher.update(EFFECT_SET_DOMAIN_TAG);
        hasher.update((encoded.len() as u64).to_be_bytes());
        for op in &encoded {
            hasher.update(op);
        }
        Self(hasher.finalize().into())
    }
}

/// What a recursive operation did, with the paths that define its scope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RecursiveOperationKind {
    /// A recursive delete of `root` and the explicit entries observed
    /// under it. Every op of every part acts on `root` or a descendant.
    RmTree { root: SyncPath },
    /// A rename of the directory `from` to `to`. Every op acts on a path
    /// at or under `from` (the old namespace) or at or under `to` (the new
    /// one). The two may not nest: a directory cannot be renamed into its
    /// own subtree, nor onto one of its ancestors.
    RenameTree { from: SyncPath, to: SyncPath },
}

impl RecursiveOperationKind {
    const RM_TREE_TAG: u8 = 0;
    const RENAME_TREE_TAG: u8 = 1;

    fn tag(&self) -> u8 {
        match self {
            Self::RmTree { .. } => Self::RM_TREE_TAG,
            Self::RenameTree { .. } => Self::RENAME_TREE_TAG,
        }
    }

    /// Whether `path` lies inside this operation's scope.
    pub fn covers(&self, path: &str) -> bool {
        match self {
            Self::RmTree { root } => is_ancestor_or_self(root.as_str(), path),
            Self::RenameTree { from, to } => {
                is_ancestor_or_self(from.as_str(), path) || is_ancestor_or_self(to.as_str(), path)
            }
        }
    }
}

/// Whether `op` is one of a recursive operation's own effects.
///
/// Every op is, except a conflict-copy put. Closing a fork on a path the
/// operation touches can make the emitting device derive a conflict copy
/// in the same change, and that copy is named as a *sibling* of the forked
/// path — for a fork on the root itself, outside the root. It is not
/// something the user did to the tree, it is re-derivable from the losing
/// change it names and validated as such on its own terms, and restoring
/// the operation must not touch it. So it is neither scope-checked nor
/// part of the operation's effect set.
pub fn is_recursive_effect(op: &Op) -> bool {
    !matches!(op, Op::Put { origin: PutOrigin::ConflictCopy { .. }, .. })
}

/// The ops of `ops` that are a recursive operation's own effects; see
/// [`is_recursive_effect`].
pub fn effect_ops<'a>(ops: &'a [Op]) -> impl Iterator<Item = &'a Op> + 'a {
    ops.iter().filter(|op| is_recursive_effect(op))
}

/// Every path an op acts on: both ends of a move.
fn op_paths(op: &Op) -> Vec<&str> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path.as_str()],
        Op::Move { from, to, .. } => vec![from.as_str(), to.as_str()],
    }
}

/// `ancestor == path`, or `ancestor` is a proper `/`-segment ancestor of
/// `path`. A plain string prefix is not enough: `a` is not an ancestor of
/// `ab`.
pub fn is_ancestor_or_self(ancestor: &str, path: &str) -> bool {
    path == ancestor
        || (path.len() > ancestor.len()
            && path.starts_with(ancestor)
            && path.as_bytes()[ancestor.len()] == b'/')
}

/// The signed descriptor one part of a recursive operation carries. See the
/// module documentation for what each field pins.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecursiveOperation {
    pub operation_id: RecursiveOperationId,
    pub kind: RecursiveOperationKind,
    pub part_index: u32,
    pub part_count: u32,
    pub effect_set_hash: EffectSetHash,
}

/// The fields every part of one operation must agree on — the descriptor
/// with the part index left out. This is what a store keeps once per
/// operation, independently of whether any part's change is still held.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecursiveOperationDescriptor {
    pub operation_id: RecursiveOperationId,
    pub kind: RecursiveOperationKind,
    pub part_count: u32,
    pub effect_set_hash: EffectSetHash,
}

impl RecursiveOperation {
    /// The operation-wide half of this part's descriptor.
    pub fn descriptor(&self) -> RecursiveOperationDescriptor {
        RecursiveOperationDescriptor {
            operation_id: self.operation_id,
            kind: self.kind.clone(),
            part_count: self.part_count,
            effect_set_hash: self.effect_set_hash,
        }
    }

    pub(crate) fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.operation_id.0);
        self.descriptor().encode_kind_into(buf);
        put_u32(buf, self.part_index);
        put_u32(buf, self.part_count);
        buf.extend_from_slice(&self.effect_set_hash.0);
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self, ChangeError> {
        let operation_id =
            RecursiveOperationId(r.take(16)?.try_into().expect("take(16) yields exactly 16 bytes"));
        let kind = decode_kind(r)?;
        let part_index = r.u32()?;
        let part_count = r.u32()?;
        let effect_set_hash = EffectSetHash(r.array32()?);
        Ok(Self { operation_id, kind, part_index, part_count, effect_set_hash })
    }

    /// Store-independent well-formedness of one part: a real id, a part
    /// position inside a bounded part count, clean scope paths (and, for a
    /// rename, two scopes that do not nest), and at least one effect op,
    /// every one of whose paths lies inside the scope. `path_ok` is the change's
    /// own path validation, applied to the scope paths too.
    pub(crate) fn validate_part(
        &self,
        ops: &[Op],
        path_ok: impl Fn(&str) -> Result<(), ChangeError>,
    ) -> Result<(), ChangeError> {
        if self.operation_id.0 == [0u8; 16] {
            return Err(ChangeError::Malformed(
                "recursive operation carries the reserved all-zero operation id".into(),
            ));
        }
        if self.part_count == 0 || self.part_count > MAX_RECURSIVE_OPERATION_PARTS {
            return Err(ChangeError::Malformed(format!(
                "recursive operation part count {} is outside 1..={MAX_RECURSIVE_OPERATION_PARTS}",
                self.part_count
            )));
        }
        if self.part_index >= self.part_count {
            return Err(ChangeError::Malformed(format!(
                "recursive operation part index {} is not below its part count {}",
                self.part_index, self.part_count
            )));
        }
        match &self.kind {
            RecursiveOperationKind::RmTree { root } => path_ok(root.as_str())?,
            RecursiveOperationKind::RenameTree { from, to } => {
                path_ok(from.as_str())?;
                path_ok(to.as_str())?;
                if is_ancestor_or_self(from.as_str(), to.as_str())
                    || is_ancestor_or_self(to.as_str(), from.as_str())
                {
                    return Err(ChangeError::Malformed(
                        "recursive rename's source and destination are the same path or nest \
                         inside one another"
                            .into(),
                    ));
                }
            }
        }
        let mut effect_paths = effect_ops(ops).flat_map(op_paths).peekable();
        if effect_paths.peek().is_none() {
            return Err(ChangeError::Malformed(
                "recursive operation part carries no operations of its own".into(),
            ));
        }
        if let Some(outside) = effect_paths.find(|path| !self.kind.covers(path)) {
            return Err(ChangeError::Malformed(format!(
                "recursive operation part acts on {outside:?}, outside the operation's scope"
            )));
        }
        Ok(())
    }
}

impl RecursiveOperationDescriptor {
    fn encode_kind_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.kind.tag());
        match &self.kind {
            RecursiveOperationKind::RmTree { root } => put_str(buf, root.as_str()),
            RecursiveOperationKind::RenameTree { from, to } => {
                put_str(buf, from.as_str());
                put_str(buf, to.as_str());
            }
        }
    }

    /// A self-delimiting encoding of the descriptor, for a store to keep
    /// the operation-wide fields as one value. Not part of any change's
    /// signed bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.operation_id.0);
        self.encode_kind_into(&mut buf);
        put_u32(&mut buf, self.part_count);
        buf.extend_from_slice(&self.effect_set_hash.0);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes);
        let operation_id =
            RecursiveOperationId(r.take(16)?.try_into().expect("take(16) yields exactly 16 bytes"));
        let kind = decode_kind(&mut r)?;
        let part_count = r.u32()?;
        let effect_set_hash = EffectSetHash(r.array32()?);
        r.expect_end()?;
        Ok(Self { operation_id, kind, part_count, effect_set_hash })
    }
}

fn decode_kind(r: &mut Reader<'_>) -> Result<RecursiveOperationKind, ChangeError> {
    match r.u8()? {
        RecursiveOperationKind::RM_TREE_TAG => {
            Ok(RecursiveOperationKind::RmTree { root: SyncPath(r.string()?) })
        }
        RecursiveOperationKind::RENAME_TREE_TAG => Ok(RecursiveOperationKind::RenameTree {
            from: SyncPath(r.string()?),
            to: SyncPath(r.string()?),
        }),
        other => Err(ChangeError::Encoding(format!(
            "unknown recursive-operation kind discriminant {other}"
        ))),
    }
}

#[cfg(test)]
mod tests;
