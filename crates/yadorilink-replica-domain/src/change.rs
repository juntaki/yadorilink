//! Signed, content-addressed change history — the core data model every
//! sync component codes against.
//!
//! Materialized folder state is a deterministic pure function of the *set*
//! of applied changes: there are no explicit merge nodes. A change carries
//! its parent change hashes (its causal predecessors), the originating
//! device and folder group, its own position in that device's chain within
//! that group (`author_seq`), its operations, a logical (`lamport`)
//! tie-breaker, and an Ed25519 signature by the originating device.
//!
//! The byte layout is hand-specified, not derived from serde or protobuf:
//! it must be reproducible on any device and any future version, because
//! the change's identity *is* the SHA-256 of its canonical encoding.
//! Protobuf/serde output is not canonical across implementations, so it can
//! never back a content hash. The layout is fully length-delimited (every
//! variable field is `u32` big-endian length prefixed), every integer is a
//! fixed-width big-endian value, and every collection is emitted in a
//! defined order (`parents` ascending and deduped, `ops` by `(path,
//! discriminant)`). A leading domain-tag prevents a `FileVersion` encoding
//! from ever colliding with a `Change` encoding.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::codec::{put_str, put_u32, put_u64, ChangeError, Reader};
use crate::ids::{AuthorSeq, ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::limits::{MAX_OPS, MAX_PARENTS, MAX_PATH_BYTES, MAX_PATH_SEGMENTS};
use crate::rebootstrap::{HistoryBase, HistoryEpoch};
use crate::recursive_operation::RecursiveOperation;
use crate::reserved_paths::{IGNORE_FILE_NAME, ROOT_MARKER_FILE_NAME};

/// Domain tag for a `Change`'s canonical encoding. The trailing byte is a
/// format version so an older layout is detectable rather than silently
/// reinterpreted; version 2 carried per-change authorization fields
/// (`auth_seq`, `auth_epoch`, `policy_head_hash`) — author-selected
/// historical pins that a checkpoint-based authorization model does not
/// trust; version 3 collapsed `Op::Create`/`Op::Update` into `Op::Put` and
/// added `PutOrigin`. Version 4 added a signed change purpose, including
/// the logical obligations carried by a retroactive-repair change. Version
/// 5 REMOVES `auth_seq`/`auth_epoch`/`policy_head_hash` entirely: under
/// `AuthorizationCheckpoint`, writer authorization happens only at
/// checkpoint issuance, never by an author-selected historical pin the
/// author could always have chosen favorably — so a `Change`'s signature
/// now authenticates only the immutable change itself (group, device,
/// parents, lamport, purpose, ops), nothing about who was authorized to
/// make it. Version 6 adds the signed `author_seq`, the third component of
/// a change's causal dot `(group_id, device_id, author_seq)`, between
/// `device_id` and `lamport`. Version 7 adds the signed
/// [`HistoryEpoch`](crate::rebootstrap::HistoryEpoch) directly after
/// `group_id`: the history the change was written on, so that a change
/// from a replaced history cannot be mistaken for one written on the
/// current one. Version 8 adds the signed `author_prev` directly after
/// `author_seq`: the author's own immediately preceding change, which is
/// what makes author ordering checkable by identity instead of by DAG
/// ancestry (see [`Change::author_prev`]). Version 9 adds the signed,
/// optional [`RecursiveOperation`] directly after the purpose: the grouping
/// that ties the parts of one chunked recursive delete or directory rename
/// together (see [`Change::recursive_operation`]). All prior versions'
/// bytes can never hash to the same identity as v9's.
///
/// The first seven bytes identify the type; the eighth is the generation.
/// [`Change::from_wire_bytes`] reads the two separately so a buffer from a
/// different generation is refused as
/// [`ChangeError::UnsupportedGeneration`] rather than being lumped in with
/// a corrupt buffer — the reinterpretation itself is never on the table,
/// since v9 reads a recursive-operation discriminant where v8 wrote the
/// parent count's leading byte, and every field after it at the wrong
/// offset.
pub const CHANGE_DOMAIN_TAG: &[u8; 8] = b"YLNKchg\x09";

/// The length of [`CHANGE_DOMAIN_TAG`]'s type-identifying prefix; the one
/// byte after it is the encoding generation.
const CHANGE_DOMAIN_TAG_PREFIX_LEN: usize = 7;
/// Domain tag for [`Change::authenticated_header_encoding`] — the same
/// signed fields as [`Change::canonical_encoding`] with `ops` left out,
/// trailed by the signature. Distinct from `CHANGE_DOMAIN_TAG` so a header
/// encoding can never be mistaken for (or collide with) a full change's wire
/// bytes, even for the zero-op case. Version 2 drops the removed
/// authorization-pin fields, matching `CHANGE_DOMAIN_TAG` v5; version 3
/// carries `author_seq`, matching `CHANGE_DOMAIN_TAG` v6 — a pruned stub
/// must keep the author's dot, since the dot is what a compacted history
/// still has to be able to name; version 4 carries the history epoch,
/// matching `CHANGE_DOMAIN_TAG` v7, for the same reason: a stub that
/// forgot which history it came from could be read as belonging to the
/// one that replaced it; version 5 carries `author_prev`, matching
/// `CHANGE_DOMAIN_TAG` v8 — the author link is part of the dot a compacted
/// history still has to be able to name, exactly like the sequence;
/// version 6 carries the recursive-operation grouping, matching
/// `CHANGE_DOMAIN_TAG` v9, so a compacted part still says which operation
/// it belonged to.
const CHANGE_HEADER_DOMAIN_TAG: &[u8; 8] = b"YLNKchH\x06";
/// Version stamp for the header encoding a pruned causal stub retains
/// (`dag_store`'s `pruned_changes.encoding_version`), bumped only if
/// [`Change::authenticated_header_encoding`]'s layout changes.
pub const PRUNED_STUB_ENCODING_VERSION: i32 = 6;

/// One operation within a change. `Move` is a rename *hint*, not a distinct
/// identity operation: it is semantically exactly `Delete { from }` plus
/// `Put { to, version, origin: Direct }`, and the materialization fold
/// desugars it to that pair. It exists only so a rename can be recognized as
/// one (for UX and transfer-avoidance) rather than as an unrelated delete and
/// put; a first-class per-entry identity model is a post-1.0 item, not this.
///
/// `Create` and `Update` collapse into one `Put`: on the DAG's own authority
/// model, the distinction is entirely derivable from the parent frontier
/// (absent → a create, present → an update) and carries no information a
/// replica couldn't already compute itself. Keeping them as separate
/// variants bought nothing but duplicated fold arms and an unused choice
/// every author had to make.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Op {
    Put { path: SyncPath, version: VersionHash, origin: PutOrigin },
    Delete { path: SyncPath },
    Move { from: SyncPath, to: SyncPath, version: VersionHash },
}

/// Where a `Put`'s content came from — carried in the canonical encoding (and
/// therefore signed and hashed) so a replica never has to trust an
/// unstructured claim about a `Put`'s provenance.
///
/// `ConflictCopy` makes a losing concurrent edit's content a durable,
/// replicated DAG fact instead of an ephemeral local re-derivation: any
/// device that ever admits this `Op` owes (and can independently verify) the
/// exact same conflict-copy path/content, regardless of whether its own
/// local view of the DAG ever passed through a moment where the winning and
/// losing heads were simultaneously live. `source_path` disambiguates which
/// of `losing_change`'s ops this `Put` derives from when that change touches
/// more than one path; `losing_change` itself need not be repeated as a
/// version hash here because the outer `Put::version` already carries the
/// loser's exact content.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PutOrigin {
    Direct,
    ConflictCopy {
        source_path: SyncPath,
        losing_change: ChangeHash,
    },
    /// A retroactive-repair carrier re-asserting content it did not write.
    ///
    /// The carrier is signed by whichever device was elected to author the
    /// repair, so the change's own `device_id` is the repairer -- not the
    /// device that wrote the content being re-asserted. That distinction is
    /// invisible in a plain `Direct` put, and losing it is a real defect:
    /// the re-assertion supersedes the original author's head, so if the
    /// carrier later loses a conflict of its own, the copy preserving its
    /// content gets named after the repairer while the true author's id
    /// disappears from the path entirely.
    ///
    /// `naming_device_id` is therefore carried in the op itself and copied
    /// forward unchanged from the content's own head, never overwritten with
    /// the repairer's id. It is deliberately NOT recovered by looking
    /// `original_change` up in history at naming time: that would make a
    /// path's converged name depend on whether a given replica still retains
    /// that change, so two replicas with different retention could
    /// materialize different names for the same content.
    ///
    /// `original_change` is provenance for admission validation -- it names
    /// the head this re-assertion carries forward, so a receiver can check
    /// the claim rather than trust it -- and is never a naming lookup.
    Reasserted {
        original_change: ChangeHash,
        naming_device_id: DeviceId,
    },
}

/// One logical conflict-copy obligation explicitly claimed by a
/// [`ChangePurpose::RetroactiveRepair`] carrier. The group is supplied by the
/// enclosing [`Change`]; these are the other two inputs to
/// `RepairObligationId::compute`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct RepairObligation {
    pub source_path: SyncPath,
    pub losing_change: ChangeHash,
}

/// Why a change was authored. Ordinary edits may still derive conflict-copy
/// puts as a side effect of closing a fork. A retroactive repair is different:
/// it exists solely to publish one or more previously-unpublished obligations,
/// so those obligations are first-class signed data that admission can
/// independently re-derive and validate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChangePurpose {
    Ordinary,
    RetroactiveRepair { obligations: Vec<RepairObligation> },
}

impl Op {
    /// Stable per-variant discriminant used both in the canonical encoding
    /// and as the secondary key of the canonical op ordering.
    pub fn discriminant(&self) -> u8 {
        match self {
            Op::Put { .. } => 0,
            Op::Delete { .. } => 1,
            Op::Move { .. } => 2,
        }
    }

    /// The primary path an op is keyed on for canonical ordering. For a
    /// `Move` this is the source path, so a rename sorts by where the file
    /// was, matching how the other ops key on the path they act on.
    pub fn primary_path(&self) -> &str {
        match self {
            Op::Put { path, .. } | Op::Delete { path } => path.as_str(),
            Op::Move { from, .. } => from.as_str(),
        }
    }

    fn sort_key(&self) -> (&str, u8) {
        (self.primary_path(), self.discriminant())
    }
}

/// Signals that a group's authorization context cannot be produced right
/// now. An installed authorization provider returns this when the group is
/// *stale* — its most recent policy snapshot failed verification, so its
/// verified state was dropped from the trusted set and inbound change
/// admission for the group fails closed until a valid snapshot restores it.
/// Each engine crate's own error type (e.g. `SyncError::PolicyUnavailable`)
/// converts from this via a local `From` impl.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyUnavailable;

/// A signed, content-addressed change. `parents` are ascending and deduped;
/// `ops` are in canonical `(path, discriminant)` order. The `signature`
/// field is Ed25519 over the canonical encoding of every *other* field, and
/// the change hash is the SHA-256 of those same bytes — so neither the hash
/// nor the signature depends on the signature bytes themselves.
///
/// This signature authenticates only the immutable change itself — group,
/// device, parents, lamport, purpose, ops — never who was authorized to
/// make it. There is deliberately no author-selected historical
/// authorization pin here (an earlier layout carried `auth_seq`/
/// `auth_epoch`/`policy_head_hash`; removed since an author always
/// controls which historical policy point they claim to pin, making such a
/// pin worthless as an authorization fact once any authority-issued
/// evidence exists). Whether a `Change` may become externally observable is
/// decided entirely by `yadorilink_replica_domain::authorization_checkpoint`
/// — an authority-signed checkpoint issued only after a LIVE writer check —
/// never by anything this struct carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    pub parents: Vec<ChangeHash>,
    pub device_id: DeviceId,
    pub group_id: FolderGroupId,
    /// The history this change was written on. Signed and hashed, so it is
    /// not a claim a relay can adjust: a change written under a replaced
    /// history can be told apart from one written on the current one from
    /// the bytes alone, and is never admitted into the wrong one.
    pub history_epoch: HistoryEpoch,
    /// This change's position in its own author's chain within
    /// `group_id`. `(group_id, device_id, author_seq)` is the change's
    /// causal dot: signed, hashed, and unique — no two distinct changes may
    /// ever carry the same one. Unlike `lamport` it counts only this
    /// author's own writes, and it never restarts.
    pub author_seq: AuthorSeq,
    /// The change this author wrote immediately before this one in
    /// `group_id`, or `None` when this is that author's first change here.
    /// Signed and hashed alongside `author_seq`, so the two halves of the
    /// author ordering travel together and neither can be adjusted in
    /// flight.
    ///
    /// **This is author ordering, not causality.** It says only "the same
    /// author wrote that one just before this one". It is deliberately NOT
    /// a DAG parent, and it must never be read as one: not for path
    /// conflict resolution, not for conflict-copy derivation, not for
    /// deciding what wins a path, not as an ancestry edge of any kind.
    /// Anything that decides what a path's content is reads `parents` and
    /// only `parents`.
    ///
    /// The separation is what makes an ordinary local edit admissible
    /// everywhere. A local edit is parented on the causal basis of the
    /// bytes the user actually edited, which is routinely older than that
    /// author's own latest write to some other path — claiming otherwise
    /// would assert the user saw and overwrote work they never saw, a
    /// silent lost update. So the author's previous change is often not a
    /// DAG ancestor of this one, and asking for ancestry would refuse the
    /// ordinary case. Naming it outright costs 33 bytes and is checkable
    /// by identity, with no ancestry query at all.
    pub author_prev: Option<ChangeHash>,
    pub lamport: u64,
    pub purpose: ChangePurpose,
    /// Set when this change is one part of a recursive delete or directory
    /// rename that was split across several changes: which operation, which
    /// part of how many, and the digest of the operation's whole effect
    /// set. Signed and hashed, so the grouping is a fact every replica
    /// reads identically rather than something inferred afterwards from
    /// author-sequence adjacency or a shared path prefix. `None` for every
    /// other change. See [`crate::recursive_operation`].
    pub recursive_operation: Option<RecursiveOperation>,
    pub ops: Vec<Op>,
    pub signature: [u8; 64],
}

// --- Change encoding / hashing / signing -----------------------------------

/// Per-variant tag for `PutOrigin` within a `Put` op's encoding — a second,
/// nested discriminant distinct from `Op::discriminant()`.
fn put_origin_tag(origin: &PutOrigin) -> u8 {
    match origin {
        PutOrigin::Direct => 0,
        PutOrigin::ConflictCopy { .. } => 1,
        PutOrigin::Reasserted { .. } => 2,
    }
}

/// The history epoch's place in the signed bytes: a one-byte discriminant,
/// followed by the base hash when there is one. Fixed width per variant and
/// self-delimiting, like every other field in this layout.
fn put_history_epoch(buf: &mut Vec<u8>, epoch: HistoryEpoch) {
    match epoch {
        HistoryEpoch::Genesis => buf.push(HistoryEpoch::GENESIS_TAG),
        HistoryEpoch::Base(base) => {
            buf.push(HistoryEpoch::BASE_TAG);
            buf.extend_from_slice(&base.0);
        }
    }
}

fn read_history_epoch(r: &mut Reader<'_>) -> Result<HistoryEpoch, ChangeError> {
    match r.u8()? {
        HistoryEpoch::GENESIS_TAG => Ok(HistoryEpoch::Genesis),
        HistoryEpoch::BASE_TAG => Ok(HistoryEpoch::Base(HistoryBase(r.array32()?))),
        other => Err(ChangeError::Encoding(format!("unknown history-epoch discriminant {other}"))),
    }
}

/// The author's previous change in the signed bytes: a one-byte
/// discriminant, followed by the hash when there is one. Fixed width per
/// variant and self-delimiting, like every other field in this layout.
/// Discriminants deliberately match neither 0 nor 1 by accident — they are
/// the same shape the history epoch uses, read the same way.
const AUTHOR_PREV_NONE_TAG: u8 = 0;
const AUTHOR_PREV_SOME_TAG: u8 = 1;

fn put_author_prev(buf: &mut Vec<u8>, author_prev: Option<ChangeHash>) {
    match author_prev {
        None => buf.push(AUTHOR_PREV_NONE_TAG),
        Some(prev) => {
            buf.push(AUTHOR_PREV_SOME_TAG);
            buf.extend_from_slice(&prev.0);
        }
    }
}

fn read_author_prev(r: &mut Reader<'_>) -> Result<Option<ChangeHash>, ChangeError> {
    match r.u8()? {
        AUTHOR_PREV_NONE_TAG => Ok(None),
        AUTHOR_PREV_SOME_TAG => Ok(Some(ChangeHash(r.array32()?))),
        other => {
            Err(ChangeError::Encoding(format!("unknown author-predecessor discriminant {other}")))
        }
    }
}

const RECURSIVE_OPERATION_NONE_TAG: u8 = 0;
const RECURSIVE_OPERATION_SOME_TAG: u8 = 1;

fn put_recursive_operation(buf: &mut Vec<u8>, operation: Option<&RecursiveOperation>) {
    match operation {
        None => buf.push(RECURSIVE_OPERATION_NONE_TAG),
        Some(operation) => {
            buf.push(RECURSIVE_OPERATION_SOME_TAG);
            operation.encode_into(buf);
        }
    }
}

fn read_recursive_operation(r: &mut Reader<'_>) -> Result<Option<RecursiveOperation>, ChangeError> {
    match r.u8()? {
        RECURSIVE_OPERATION_NONE_TAG => Ok(None),
        RECURSIVE_OPERATION_SOME_TAG => Ok(Some(RecursiveOperation::decode(r)?)),
        other => {
            Err(ChangeError::Encoding(format!("unknown recursive-operation discriminant {other}")))
        }
    }
}

/// Appends one op's canonical encoding — exactly the bytes a change's
/// signed encoding carries for it.
pub fn encode_op(buf: &mut Vec<u8>, op: &Op) {
    encode_op_into(buf, op);
}

/// A self-delimiting encoding of an op list, each op in its canonical
/// change encoding: what a store keeps to reconstruct a set of ops after
/// the change that carried them is gone.
pub fn encode_op_list(ops: &[Op]) -> Vec<u8> {
    let mut buf = Vec::new();
    put_u32(&mut buf, ops.len() as u32);
    for op in ops {
        encode_op_into(&mut buf, op);
    }
    buf
}

/// Parses [`encode_op_list`]'s output.
pub fn decode_op_list(bytes: &[u8]) -> Result<Vec<Op>, ChangeError> {
    let mut r = Reader::new(bytes);
    let count = r.bounded_count(5, MAX_OPS)?;
    let mut ops = Vec::with_capacity(count);
    for _ in 0..count {
        ops.push(decode_op(&mut r)?);
    }
    r.expect_end()?;
    Ok(ops)
}

fn encode_op_into(buf: &mut Vec<u8>, op: &Op) {
    buf.push(op.discriminant());
    match op {
        Op::Put { path, version, origin } => {
            put_str(buf, path.as_str());
            buf.extend_from_slice(&version.0);
            buf.push(put_origin_tag(origin));
            match origin {
                PutOrigin::Direct => {}
                PutOrigin::ConflictCopy { source_path, losing_change } => {
                    put_str(buf, source_path.as_str());
                    buf.extend_from_slice(&losing_change.0);
                }
                PutOrigin::Reasserted { original_change, naming_device_id } => {
                    buf.extend_from_slice(&original_change.0);
                    put_str(buf, naming_device_id.as_str());
                }
            }
        }
        Op::Delete { path } => {
            put_str(buf, path.as_str());
        }
        Op::Move { from, to, version } => {
            put_str(buf, from.as_str());
            put_str(buf, to.as_str());
            buf.extend_from_slice(&version.0);
        }
    }
}

/// The canonical encoded byte length of one op, mirroring [`encode_op_into`].
/// The single source of truth for per-op sizing: callers that bound a
/// change's encoded size before emitting it (the initial import and the
/// startup reconcile) share this so their byte accounting can never drift
/// from what `encode_op_into` writes.
pub fn encoded_op_len(op: &Op) -> usize {
    match op {
        Op::Delete { path } => 1 + 4 + path.as_str().len(),
        Op::Put { path, origin: PutOrigin::Direct, .. } => 1 + 4 + path.as_str().len() + 32 + 1,
        Op::Put { path, origin: PutOrigin::ConflictCopy { source_path, .. }, .. } => {
            1 + 4 + path.as_str().len() + 32 + 1 + 4 + source_path.as_str().len() + 32
        }
        Op::Put { path, origin: PutOrigin::Reasserted { naming_device_id, .. }, .. } => {
            1 + 4 + path.as_str().len() + 32 + 1 + 32 + 4 + naming_device_id.as_str().len()
        }
        Op::Move { from, to, .. } => 1 + 4 + from.as_str().len() + 4 + to.as_str().len() + 32,
    }
}

/// Max canonical op-bytes packed into a single locally emitted change — shared
/// by the initial import and the startup reconcile, the two paths that convert
/// a bulk offline diff into a chain of changes. A change cannot be wire-split,
/// so it must fit in one delivered message; the transport rejects any inbound
/// control frame larger than `yadorilink_transport::quic_peer_channel::
/// MAX_CONTROL_FRAME_BYTES` (2 MiB). 256 KiB stays well under that — leaving
/// ample room for the change's fixed header, parents, and signature, plus
/// everything else sharing that same ceiling — while a pathological run of
/// very long paths is split into a chain rather than forming one change no
/// wire message could ever carry.
pub const MAX_CHANGE_OP_BYTES: usize = 256 * 1024;

/// Max encoded payload (changes plus the file versions they reference) packed
/// into a single anti-entropy page.
///
/// Bounding each individual change (above) is not enough: a page carries many
/// of them plus every referenced `FileVersion`, and the whole page goes out as
/// ONE control frame. Sized purely by change COUNT, a page of even a handful of
/// bulk initial-import changes runs past the transport's
/// `yadorilink_transport::quic_peer_channel::MAX_CONTROL_FRAME_BYTES` (2 MiB)
/// ceiling and the send fails outright -- and because anti-entropy re-derives
/// the same delta on every retry, it fails identically forever: the receiver
/// never gets that history at all. Observed on a 20k-file initial import as a
/// repeating `message too large: 2854719 bytes` with the peer stuck at zero
/// files.
///
/// 1 MiB leaves the frame roughly 2x headroom for its own envelope. A single
/// change whose own payload exceeds this is still emitted alone on its own page
/// rather than being dropped or wire-split -- a change is indivisible, so the
/// bound can only ever be best-effort for that case, which is exactly why
/// `MAX_CHANGE_OP_BYTES` keeps individual changes far below the ceiling.
pub const MAX_ANTI_ENTROPY_PAGE_BYTES: usize = 1024 * 1024;

/// Upper bound on how many operations a single synthesized initial-import or
/// reconciliation change carries. A very large existing index (or a bulk
/// offline diff found by the startup reconcile) converts into a chain of
/// changes, each no bigger than this, so an individual change stays
/// comfortably small for storage while the chain as a whole still captures
/// the entire diff. Chosen to keep changes small without producing an
/// excessive number of them for a typical folder. This op-count cap alone
/// does NOT bound a change's encoded size — long paths can make a
/// `IMPORT_BATCH_OP_LIMIT`-op change several MiB — so both callers
/// additionally cap each change by canonical encoded byte size
/// ([`MAX_CHANGE_OP_BYTES`]); the two bounds apply together. Shared here
/// (rather than defined once by whichever crate owns initial import) because
/// `yadorilink-local-capture`'s own startup-reconcile chunking
/// (`RECONCILE_CHUNK_OP_LIMIT`) must match it exactly, and that crate sits
/// below `yadorilink-daemon` (which owns `dag_import`'s initial-import logic)
/// in the dependency graph, so it cannot import the constant from there.
pub const IMPORT_BATCH_OP_LIMIT: usize = 1024;

fn decode_op(r: &mut Reader<'_>) -> Result<Op, ChangeError> {
    let disc = r.u8()?;
    Ok(match disc {
        0 => {
            let path = SyncPath(r.string()?);
            let version = VersionHash(r.array32()?);
            let origin = match r.u8()? {
                0 => PutOrigin::Direct,
                1 => PutOrigin::ConflictCopy {
                    source_path: SyncPath(r.string()?),
                    losing_change: ChangeHash(r.array32()?),
                },
                2 => PutOrigin::Reasserted {
                    original_change: ChangeHash(r.array32()?),
                    naming_device_id: DeviceId(r.string()?),
                },
                other => {
                    return Err(ChangeError::Encoding(format!(
                        "unknown put-origin discriminant {other}"
                    )))
                }
            };
            Op::Put { path, version, origin }
        }
        1 => Op::Delete { path: SyncPath(r.string()?) },
        2 => Op::Move {
            from: SyncPath(r.string()?),
            to: SyncPath(r.string()?),
            version: VersionHash(r.array32()?),
        },
        other => return Err(ChangeError::Encoding(format!("unknown op discriminant {other}"))),
    })
}

impl Change {
    /// Assembles, canonically orders, and signs a change. `parents` need not
    /// be sorted or deduped by the caller — this normalizes them. `lamport`
    /// is `max_parent_lamport + 1`. Above a history base the caller passes
    /// the greater of its parents' greatest value and the base's Lamport
    /// ceiling, so the clock continues past everything the base absorbed;
    /// on the group's original history a root passes `0`, giving
    /// `lamport = 1`.
    ///
    /// `author_seq` is this author's next position in its own chain for
    /// `group_id`, and `author_prev` is the change that author wrote at the
    /// position before it (`None` at sequence 1). Both are the caller's to
    /// supply because only a store knows what this author has already
    /// written there. Production has exactly one caller, the emission
    /// funnel, which reads the author's state and signs in the same breath.
    ///
    /// `author_prev` is NOT a parent and never becomes one: `parents` is
    /// the causal basis the author observed, and that is the only thing
    /// any conflict or content decision reads.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signed(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device_id: DeviceId,
        author_seq: AuthorSeq,
        author_prev: Option<ChangeHash>,
        group_id: FolderGroupId,
        history_epoch: HistoryEpoch,
        ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        Self::create_signed_with_purpose(
            parents,
            max_parent_lamport,
            device_id,
            author_seq,
            author_prev,
            group_id,
            history_epoch,
            ChangePurpose::Ordinary,
            None,
            ops,
            signing_key,
        )
    }

    /// Assembles and signs one part of a recursive delete or directory
    /// rename that was split across several changes. Identical to
    /// [`create_signed`](Self::create_signed) except that the part carries
    /// its signed [`RecursiveOperation`] descriptor.
    #[allow(clippy::too_many_arguments)]
    pub fn create_recursive_part_signed(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device_id: DeviceId,
        author_seq: AuthorSeq,
        author_prev: Option<ChangeHash>,
        group_id: FolderGroupId,
        history_epoch: HistoryEpoch,
        recursive_operation: RecursiveOperation,
        ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        Self::create_signed_with_purpose(
            parents,
            max_parent_lamport,
            device_id,
            author_seq,
            author_prev,
            group_id,
            history_epoch,
            ChangePurpose::Ordinary,
            Some(recursive_operation),
            ops,
            signing_key,
        )
    }

    /// Assembles and signs a first-class retroactive-repair carrier.
    #[allow(clippy::too_many_arguments)]
    pub fn create_repair_signed(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device_id: DeviceId,
        author_seq: AuthorSeq,
        author_prev: Option<ChangeHash>,
        group_id: FolderGroupId,
        history_epoch: HistoryEpoch,
        obligations: Vec<RepairObligation>,
        ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        Self::create_signed_with_purpose(
            parents,
            max_parent_lamport,
            device_id,
            author_seq,
            author_prev,
            group_id,
            history_epoch,
            ChangePurpose::RetroactiveRepair { obligations },
            None,
            ops,
            signing_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_signed_with_purpose(
        mut parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        device_id: DeviceId,
        author_seq: AuthorSeq,
        author_prev: Option<ChangeHash>,
        group_id: FolderGroupId,
        history_epoch: HistoryEpoch,
        mut purpose: ChangePurpose,
        recursive_operation: Option<RecursiveOperation>,
        mut ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        parents.sort();
        parents.dedup();
        ops.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        if let ChangePurpose::RetroactiveRepair { obligations } = &mut purpose {
            obligations.sort();
            obligations.dedup();
        }
        let lamport = max_parent_lamport.saturating_add(1);
        let mut change = Change {
            parents,
            device_id,
            group_id,
            history_epoch,
            author_seq,
            author_prev,
            lamport,
            purpose,
            recursive_operation,
            ops,
            signature: [0u8; 64],
        };
        change.sign(signing_key);
        change
    }

    /// The canonical byte layout hashed to form the change hash and signed
    /// by the originating device. Excludes the `signature` field. Assumes
    /// `parents`/`ops` are already in canonical order (they are, for any
    /// change built via `create_signed` or decoded via `from_wire_bytes`).
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(CHANGE_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        put_history_epoch(&mut buf, self.history_epoch);
        put_str(&mut buf, self.device_id.as_str());
        put_u64(&mut buf, self.author_seq.get());
        put_author_prev(&mut buf, self.author_prev);
        put_u64(&mut buf, self.lamport);
        match &self.purpose {
            ChangePurpose::Ordinary => buf.push(0),
            ChangePurpose::RetroactiveRepair { obligations } => {
                buf.push(1);
                put_u32(&mut buf, obligations.len() as u32);
                for obligation in obligations {
                    put_str(&mut buf, obligation.source_path.as_str());
                    buf.extend_from_slice(&obligation.losing_change.0);
                }
            }
        }
        put_recursive_operation(&mut buf, self.recursive_operation.as_ref());
        put_u32(&mut buf, self.parents.len() as u32);
        for parent in &self.parents {
            buf.extend_from_slice(&parent.0);
        }
        put_u32(&mut buf, self.ops.len() as u32);
        for op in &self.ops {
            encode_op_into(&mut buf, op);
        }
        buf
    }

    pub fn compute_hash(&self) -> ChangeHash {
        ChangeHash(Sha256::digest(self.canonical_encoding()).into())
    }

    /// The signed portion of this change with `ops` left out, followed by its
    /// signature. This is what a pruned causal stub retains so it can remain
    /// authenticated -- who authored it, under what authorization stamp, and
    /// (for a retroactive-repair carrier) which obligations it published --
    /// once its operations, file versions and block payload are gone.
    ///
    /// It is not independently re-verifiable against the signature it
    /// carries: that signature was computed over the *full* canonical
    /// encoding, `ops` included, so checking it against these header-only
    /// bytes would not pass. It is captured only from a change this device
    /// already verified in full before compacting it away, exactly like the
    /// existing `lamport` and parent-edge tombstone it extends -- trusted
    /// because this replica itself is the one that pruned it, not because it
    /// can be re-derived from nothing.
    pub fn authenticated_header_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(CHANGE_HEADER_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        put_history_epoch(&mut buf, self.history_epoch);
        put_str(&mut buf, self.device_id.as_str());
        put_u64(&mut buf, self.author_seq.get());
        put_author_prev(&mut buf, self.author_prev);
        put_u64(&mut buf, self.lamport);
        match &self.purpose {
            ChangePurpose::Ordinary => buf.push(0),
            ChangePurpose::RetroactiveRepair { obligations } => {
                buf.push(1);
                put_u32(&mut buf, obligations.len() as u32);
                for obligation in obligations {
                    put_str(&mut buf, obligation.source_path.as_str());
                    buf.extend_from_slice(&obligation.losing_change.0);
                }
            }
        }
        put_recursive_operation(&mut buf, self.recursive_operation.as_ref());
        put_u32(&mut buf, self.parents.len() as u32);
        for parent in &self.parents {
            buf.extend_from_slice(&parent.0);
        }
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Alias for [`compute_hash`](Self::compute_hash) — the change's
    /// content-addressed identity.
    pub fn change_hash(&self) -> ChangeHash {
        self.compute_hash()
    }

    /// Alias for [`to_wire_bytes`](Self::to_wire_bytes).
    pub fn encode(&self) -> Vec<u8> {
        self.to_wire_bytes()
    }

    /// Alias for [`from_wire_bytes`](Self::from_wire_bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        Self::from_wire_bytes(bytes)
    }

    /// Full serialized form for storage and the wire: the canonical encoding
    /// followed by the 64-byte signature. This is what the `changes.encoded`
    /// column and `ChangeBatch` carry, so a relayed change keeps its
    /// original signature byte-for-byte.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.canonical_encoding();
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parses the `to_wire_bytes` form. The canonical prefix is
    /// self-delimiting, so exactly 64 trailing signature bytes must remain
    /// once it is consumed.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes);
        let tag = r.take(8)?;
        // The type prefix and the generation byte are two different
        // questions with two different answers. A wrong prefix is damage
        // (or a buffer that was never a change at all); a right prefix with
        // a foreign generation is a well-formed change from a build that
        // does not share this layout, and saying so is the whole point --
        // otherwise a mixed-generation group is indistinguishable from a
        // failing disk.
        if tag[..CHANGE_DOMAIN_TAG_PREFIX_LEN] != CHANGE_DOMAIN_TAG[..CHANGE_DOMAIN_TAG_PREFIX_LEN]
        {
            return Err(ChangeError::Encoding("bad change domain tag".into()));
        }
        if tag[CHANGE_DOMAIN_TAG_PREFIX_LEN] != CHANGE_DOMAIN_TAG[CHANGE_DOMAIN_TAG_PREFIX_LEN] {
            return Err(ChangeError::UnsupportedGeneration {
                theirs: tag[CHANGE_DOMAIN_TAG_PREFIX_LEN],
                ours: CHANGE_DOMAIN_TAG[CHANGE_DOMAIN_TAG_PREFIX_LEN],
            });
        }
        let group_id = FolderGroupId(r.string()?);
        let history_epoch = read_history_epoch(&mut r)?;
        let device_id = DeviceId(r.string()?);
        let author_seq = AuthorSeq(r.u64()?);
        // Bounded here and not only in `validate_structure`, because not
        // every path that turns bytes back into a change runs the structural
        // validation: a re-bootstrap snapshot install writes decoded frontier
        // changes straight into the store. The column that receives the
        // sequence is signed 64-bit, so an out-of-range value would land
        // there negative and make the author's retained state unreadable
        // from then on. Rejecting it at the boundary keeps that out of reach
        // of anything a peer can send.
        if author_seq > AuthorSeq::MAX {
            return Err(ChangeError::Encoding(format!(
                "change carries author sequence {author_seq}, which exceeds the highest \
                 storable position {}",
                AuthorSeq::MAX
            )));
        }
        let author_prev = read_author_prev(&mut r)?;
        let lamport = r.u64()?;
        let purpose = match r.u8()? {
            0 => ChangePurpose::Ordinary,
            1 => {
                let count = r.bounded_count(36, MAX_OPS)?;
                let mut obligations = Vec::with_capacity(count);
                for _ in 0..count {
                    obligations.push(RepairObligation {
                        source_path: SyncPath(r.string()?),
                        losing_change: ChangeHash(r.array32()?),
                    });
                }
                ChangePurpose::RetroactiveRepair { obligations }
            }
            other => {
                return Err(ChangeError::Encoding(format!(
                    "unknown change-purpose discriminant {other}"
                )))
            }
        };
        let recursive_operation = read_recursive_operation(&mut r)?;
        // Each parent is a 32-byte hash; each op is at least 5 bytes (a
        // `Delete`: discriminant + empty-path length prefix). Bound both counts
        // before allocating.
        let parent_count = r.bounded_count(32, MAX_PARENTS)?;
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(ChangeHash(r.array32()?));
        }
        let op_count = r.bounded_count(5, MAX_OPS)?;
        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            ops.push(decode_op(&mut r)?);
        }
        let signature: [u8; 64] = r
            .take(64)?
            .try_into()
            .map_err(|_| ChangeError::Encoding("signature must be 64 bytes".into()))?;
        r.expect_end()?;
        Ok(Change {
            parents,
            device_id,
            group_id,
            history_epoch,
            author_seq,
            author_prev,
            lamport,
            purpose,
            recursive_operation,
            ops,
            signature,
        })
    }

    /// Signs the canonical encoding, overwriting `signature`.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing_key.sign(&self.canonical_encoding());
        self.signature = sig.to_bytes();
    }

    /// Verifies the signature against a device's public signing key.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), ChangeError> {
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        public_key.verify(&self.canonical_encoding(), &sig).map_err(|_| ChangeError::BadSignature)
    }

    /// Store-independent structural validation. A well-formed change has:
    /// bounded, strictly-ascending (hence deduped, canonically ordered)
    /// parents that never include its own hash; bounded, canonically ordered
    /// ops; at most one op per touched path (no contradictory multi-ops); no
    /// self-move; and clean, group-relative op paths. The checks that need the
    /// store — the lamport relation (`max(parents')+1`), that every parent is
    /// present in the same history, and that referenced versions belong to the
    /// group — are the admission layer's, not here. `self_hash` is the change's
    /// own computed hash (the caller already has it), used for the
    /// no-self-parent check.
    pub fn validate_structure(&self, self_hash: &ChangeHash) -> Result<(), ChangeError> {
        // Sequence 0 is reserved, so a field left unset cannot pass for an
        // author's real position in its own chain. An author's first change
        // in a group is 1.
        if self.author_seq.get() == 0 {
            return Err(ChangeError::Malformed(
                "change carries author sequence 0, which is not a position in any author chain"
                    .into(),
            ));
        }
        // The sequence and the link it travels with have to agree about
        // whether there is anything before this change. An author's first
        // change has no predecessor to name; every later one has exactly
        // one — a change, or, for the first change an author writes above
        // a history base, the base itself. A base carries each author's
        // position and absorbs the change that attained it, and the link to
        // the base is the signed history epoch rather than `author_prev`,
        // which can only name a change. So a later change naming nothing is
        // well-formed only above a base; whether it really opens its author
        // there is the author chain's question, not this one. A change that
        // disagrees with itself here is malformed rather than refused: no
        // history is consulted to see it, and admission would otherwise have
        // to guess which half to believe.
        let above_a_base = self.history_epoch.base().is_some();
        match (self.author_seq == AuthorSeq::FIRST, self.author_prev.is_some()) {
            (true, true) => {
                return Err(ChangeError::Malformed(
                    "change is its author's first in this group yet names a previous change of \
                     its own"
                        .into(),
                ))
            }
            (false, false) if !above_a_base => {
                return Err(ChangeError::Malformed(format!(
                    "change carries author sequence {}, which follows another change of its own \
                     on the group's original history, yet names no previous change",
                    self.author_seq
                )))
            }
            _ => {}
        }
        // A change that names itself as its author's previous change would
        // close the author chain into a loop of one, exactly as a
        // self-parent would close the DAG. Refused for the same reason and
        // in the same place.
        if self.author_prev.as_ref() == Some(self_hash) {
            return Err(ChangeError::Malformed(
                "change names itself as its author's previous change".into(),
            ));
        }
        // The other end of the same range. The field is chosen by whoever
        // signs the change, and every store that records it keeps it in a
        // signed 64-bit column, so a value above the ceiling would be stored
        // as a negative position and read back as corruption on every later
        // open. Refused as malformed here, where it is still just bytes.
        if self.author_seq > AuthorSeq::MAX {
            return Err(ChangeError::Malformed(format!(
                "change carries author sequence {}, which exceeds the highest storable \
                 position {}",
                self.author_seq,
                AuthorSeq::MAX
            )));
        }
        if self.parents.len() > MAX_PARENTS {
            return Err(ChangeError::Malformed(format!(
                "parent count {} exceeds {MAX_PARENTS}",
                self.parents.len()
            )));
        }
        for pair in self.parents.windows(2) {
            if pair[0] >= pair[1] {
                return Err(ChangeError::Malformed(
                    "parents are not strictly ascending (unsorted or duplicated)".into(),
                ));
            }
        }
        if self.parents.iter().any(|p| p == self_hash) {
            return Err(ChangeError::Malformed("change references itself as a parent".into()));
        }

        if self.ops.len() > MAX_OPS {
            return Err(ChangeError::Malformed(format!(
                "op count {} exceeds {MAX_OPS}",
                self.ops.len()
            )));
        }
        if let ChangePurpose::RetroactiveRepair { obligations } = &self.purpose {
            if obligations.is_empty() {
                return Err(ChangeError::Malformed(
                    "retroactive-repair change has no obligations".into(),
                ));
            }
            if obligations.len() > MAX_OPS {
                return Err(ChangeError::Malformed(format!(
                    "repair obligation count {} exceeds {MAX_OPS}",
                    obligations.len()
                )));
            }
            for pair in obligations.windows(2) {
                if pair[0] >= pair[1] {
                    return Err(ChangeError::Malformed(
                        "repair obligations are not strictly ascending (unsorted or duplicated)"
                            .into(),
                    ));
                }
            }
            for obligation in obligations {
                validate_path(obligation.source_path.as_str())?;
            }
        }
        let mut touched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut prev_key: Option<(&str, u8)> = None;
        for op in &self.ops {
            let key = op.sort_key();
            if prev_key.is_some_and(|pk| key < pk) {
                return Err(ChangeError::Malformed("ops are not in canonical order".into()));
            }
            prev_key = Some(key);
            match op {
                Op::Put { path, origin, .. } => {
                    validate_path(path.as_str())?;
                    if !touched.insert(path.as_str()) {
                        return Err(ChangeError::Malformed(
                            "more than one op acts on the same path in this change".into(),
                        ));
                    }
                    match origin {
                        PutOrigin::Direct => {}
                        PutOrigin::ConflictCopy { source_path, .. } => {
                            validate_path(source_path.as_str())?;
                            if source_path.as_str() == path.as_str() {
                                return Err(ChangeError::Malformed(
                                    "conflict-copy put's source_path equals its own derived path"
                                        .into(),
                                ));
                            }
                        }
                        PutOrigin::Reasserted { naming_device_id, .. } => {
                            // The naming identity is the whole reason this
                            // origin exists, and it ends up verbatim in a
                            // conflict-copy filename. An empty one is not a
                            // harmless default: it would silently produce a
                            // copy named after nobody.
                            if naming_device_id.as_str().is_empty() {
                                return Err(ChangeError::Malformed(
                                    "re-asserted put carries an empty naming_device_id".into(),
                                ));
                            }
                        }
                    }
                }
                Op::Delete { path } => {
                    validate_path(path.as_str())?;
                    if !touched.insert(path.as_str()) {
                        return Err(ChangeError::Malformed(
                            "more than one op acts on the same path in this change".into(),
                        ));
                    }
                }
                Op::Move { from, to, .. } => {
                    validate_path(from.as_str())?;
                    validate_path(to.as_str())?;
                    if from == to {
                        return Err(ChangeError::Malformed(
                            "move source equals destination".into(),
                        ));
                    }
                    if !touched.insert(from.as_str()) || !touched.insert(to.as_str()) {
                        return Err(ChangeError::Malformed(
                            "more than one op acts on the same path in this change".into(),
                        ));
                    }
                }
            }
        }
        if let Some(operation) = &self.recursive_operation {
            // A repair carrier republishes obligations it did not observe
            // being made; it is never a part of a user's recursive
            // mutation, and letting it claim to be one would let a repair
            // enlarge or complete someone's operation.
            if !matches!(self.purpose, ChangePurpose::Ordinary) {
                return Err(ChangeError::Malformed(
                    "a retroactive-repair change cannot be part of a recursive operation".into(),
                ));
            }
            operation.validate_part(&self.ops, validate_path)?;
        }
        Ok(())
    }
}

/// Rejects an op path that could escape the group root or is otherwise unsafe
/// to hand to the filesystem: empty, absolute (POSIX root, a drive letter, or
/// a UNC/backslash root), a `.`/`..`/empty segment, a NUL byte, or exceeding
/// the path length/segment bounds. Paths are the `/`-separated group-relative
/// form the index uses; `\` is treated as a separator too, so a
/// Windows-style `a\..\b` traversal is caught rather than hidden inside one
/// `/`-segment.
fn validate_path(path: &str) -> Result<(), ChangeError> {
    if path.is_empty() {
        return Err(ChangeError::Malformed("empty path".into()));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(ChangeError::Malformed(format!("path exceeds {MAX_PATH_BYTES} bytes")));
    }
    if path.contains('\0') {
        return Err(ChangeError::Malformed("path contains a NUL byte".into()));
    }
    if path.contains('\\') {
        return Err(ChangeError::Malformed(
            "path contains a backslash; canonical wire paths use '/' separators only".into(),
        ));
    }
    if path.starts_with('/') {
        return Err(ChangeError::Malformed("absolute path".into()));
    }
    let is_sep = |c: char| c == '/' || c == '\\';
    let first_segment = path.split(is_sep).next().unwrap_or(path);
    if first_segment == ROOT_MARKER_FILE_NAME || first_segment == IGNORE_FILE_NAME {
        return Err(ChangeError::Malformed(
            "path targets a reserved sync-root control file".into(),
        ));
    }
    // A drive-qualified first segment such as "C:" or "C:foo".
    if first_segment.len() >= 2 && first_segment.as_bytes()[1] == b':' {
        return Err(ChangeError::Malformed("drive-qualified (absolute) path".into()));
    }
    let segments: Vec<&str> = path.split(is_sep).collect();
    if segments.len() > MAX_PATH_SEGMENTS {
        return Err(ChangeError::Malformed(format!("path exceeds {MAX_PATH_SEGMENTS} segments")));
    }
    for seg in segments {
        if seg.is_empty() {
            return Err(ChangeError::Malformed("empty path segment".into()));
        }
        if seg == "." || seg == ".." {
            return Err(ChangeError::Malformed("path contains a '.' or '..' segment".into()));
        }
    }
    Ok(())
}

/// Reconstructs an Ed25519 verifying key from its 32 raw bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ChangeError> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| ChangeError::InvalidKey)?;
    VerifyingKey::from_bytes(&array).map_err(|_| ChangeError::InvalidKey)
}

/// The store-independent admission check for a change arriving from any peer:
/// its encoded bytes hash to the claimed identity, it is structurally
/// well-formed ([`Change::validate_structure`]), its signature verifies
/// against the claimed device's pinned signing key, and that device is
/// authorized to write to the group. Store-dependent checks (the lamport
/// relation, parent presence, referenced-version ownership) are the sync
/// layer's, run after this succeeds. The authorization predicate is
/// supplied by the caller because group membership/roles live outside this
/// crate. A change that fails any check is never returned as valid, so it
/// can never be admitted to the store and therefore never forwarded.
pub fn verify_change<F>(
    change: &Change,
    claimed_hash: &ChangeHash,
    public_key: &VerifyingKey,
    is_authorized: F,
) -> Result<(), ChangeError>
where
    F: FnOnce(&DeviceId, &FolderGroupId) -> bool,
{
    if change.compute_hash() != *claimed_hash {
        return Err(ChangeError::HashMismatch);
    }
    change.validate_structure(claimed_hash)?;
    change.verify_signature(public_key)?;
    if !is_authorized(&change.device_id, &change.group_id) {
        return Err(ChangeError::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::AuthorSeq;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// A stand-in for whatever this author wrote at the position before
    /// the one under test. Its exact value never matters to these tests —
    /// only that a change past sequence 1 names something.
    const PRIOR: ChangeHash = ChangeHash([0xABu8; 32]);

    /// The predecessor link a change at `author_seq` must carry to be
    /// structurally well-formed: nothing at sequence 1, the author's
    /// previous change at every later position.
    fn prev_for(author_seq: AuthorSeq) -> Option<ChangeHash> {
        (author_seq != AuthorSeq::FIRST).then_some(PRIOR)
    }

    fn change_on(history_epoch: HistoryEpoch) -> Change {
        Change::create_signed(
            vec![],
            0,
            DeviceId("author-a".into()),
            AuthorSeq(4),
            prev_for(AuthorSeq(4)),
            FolderGroupId("group-a".into()),
            history_epoch,
            vec![Op::Delete { path: SyncPath("note.txt".into()) }],
            &signing_key(),
        )
    }

    fn change_at(author_seq: AuthorSeq) -> Change {
        change_at_with_prev(author_seq, prev_for(author_seq))
    }

    fn change_at_with_prev(author_seq: AuthorSeq, author_prev: Option<ChangeHash>) -> Change {
        Change::create_signed(
            vec![],
            0,
            DeviceId("author-a".into()),
            author_seq,
            author_prev,
            FolderGroupId("group-a".into()),
            HistoryEpoch::Genesis,
            vec![Op::Delete { path: SyncPath("note.txt".into()) }],
            &signing_key(),
        )
    }

    /// The author sequence is part of what the author signs, not a local
    /// annotation a relay could restate. A change re-stamped with a
    /// different position in its author's chain is a forgery, and the
    /// signature is what says so.
    #[test]
    fn a_flipped_bit_in_the_author_sequence_breaks_the_signature() {
        let change = change_at(AuthorSeq(4));
        let public_key = signing_key().verifying_key();
        change.verify_signature(&public_key).expect("the unmodified change verifies");

        let mut tampered = change.clone();
        tampered.author_seq = AuthorSeq(change.author_seq.get() ^ 1);
        assert_eq!(
            tampered.verify_signature(&public_key),
            Err(ChangeError::BadSignature),
            "re-stamping an author sequence must not survive signature verification"
        );
    }

    /// The author's predecessor link is part of what the author signs, for
    /// the same reason the sequence is: it is half of the author ordering,
    /// and a relay that could restate it could re-point one author's chain
    /// at another branch of its own history without touching the
    /// signature.
    #[test]
    fn a_flipped_bit_in_the_author_predecessor_breaks_the_signature() {
        let change = change_at(AuthorSeq(4));
        let public_key = signing_key().verifying_key();
        change.verify_signature(&public_key).expect("the unmodified change verifies");

        let mut tampered = change.clone();
        let mut named = change.author_prev.expect("a change past sequence 1 names a predecessor");
        named.0[0] ^= 1;
        tampered.author_prev = Some(named);
        assert_eq!(
            tampered.verify_signature(&public_key),
            Err(ChangeError::BadSignature),
            "re-pointing an author's predecessor link must not survive signature verification"
        );

        // Dropping the link entirely is the other half of the same edit,
        // and must not survive either: a change that names nothing would
        // otherwise pass for an author's first.
        let mut dropped = change.clone();
        dropped.author_prev = None;
        assert_eq!(dropped.verify_signature(&public_key), Err(ChangeError::BadSignature));
    }

    /// The predecessor link changes the change's identity, exactly like
    /// every other signed field. Two changes identical but for the author
    /// branch they continue are two different changes.
    #[test]
    fn the_author_predecessor_is_part_of_the_change_hash() {
        let one = change_at_with_prev(AuthorSeq(4), Some(ChangeHash([1u8; 32])));
        let other = change_at_with_prev(AuthorSeq(4), Some(ChangeHash([2u8; 32])));
        assert_ne!(one.compute_hash(), other.compute_hash());
    }

    #[test]
    fn the_authenticated_header_carries_the_author_predecessor() {
        assert_ne!(
            change_at_with_prev(AuthorSeq(4), Some(ChangeHash([1u8; 32])))
                .authenticated_header_encoding(),
            change_at_with_prev(AuthorSeq(4), Some(ChangeHash([2u8; 32])))
                .authenticated_header_encoding()
        );
    }

    #[test]
    fn the_author_predecessor_survives_a_wire_round_trip() {
        let named = change_at(AuthorSeq(9));
        let decoded = Change::from_wire_bytes(&named.to_wire_bytes()).expect("round trip");
        assert_eq!(decoded.author_prev, named.author_prev);
        assert_eq!(decoded, named);

        let first = change_at(AuthorSeq::FIRST);
        let decoded = Change::from_wire_bytes(&first.to_wire_bytes()).expect("round trip");
        assert_eq!(decoded.author_prev, None);
        assert_eq!(decoded, first);
    }

    /// The sequence and the link have to agree about whether anything came
    /// before. Either disagreement is malformed on the bytes alone, with no
    /// history consulted.
    #[test]
    fn the_sequence_and_the_predecessor_link_must_agree() {
        let first_naming_a_predecessor =
            change_at_with_prev(AuthorSeq::FIRST, Some(ChangeHash([1u8; 32])));
        assert!(first_naming_a_predecessor
            .validate_structure(&first_naming_a_predecessor.compute_hash())
            .is_err());

        let later_naming_nothing = change_at_with_prev(AuthorSeq(2), None);
        assert!(later_naming_nothing
            .validate_structure(&later_naming_nothing.compute_hash())
            .is_err());

        let first = change_at(AuthorSeq::FIRST);
        first.validate_structure(&first.compute_hash()).expect("a first change names nothing");
        let later = change_at(AuthorSeq(2));
        later.validate_structure(&later.compute_hash()).expect("a later change names its own");
    }

    /// The one change past its author's first that names nothing: the
    /// first change an author writes above a history base. The base carried
    /// the author's position and absorbed the change that attained it, so
    /// the new change links to the base through its signed history epoch
    /// and has no change to name. On the group's original history there is
    /// no base to carry a position, and naming nothing past the first stays
    /// malformed.
    #[test]
    fn a_change_opening_its_author_on_a_base_names_no_predecessor() {
        let opening = Change::create_signed(
            vec![],
            0,
            DeviceId("author-a".into()),
            AuthorSeq(7),
            None,
            FolderGroupId("group-a".into()),
            HistoryEpoch::Base(HistoryBase([3u8; 32])),
            vec![Op::Delete { path: SyncPath("note.txt".into()) }],
            &signing_key(),
        );
        opening
            .validate_structure(&opening.compute_hash())
            .expect("a change above a base may continue the base rather than a change");

        let on_genesis = change_at_with_prev(AuthorSeq(7), None);
        assert!(on_genesis.validate_structure(&on_genesis.compute_hash()).is_err());
    }

    /// A change that names itself as its author's previous change closes
    /// the author chain into a loop of one, exactly as a self-parent would
    /// close the DAG.
    #[test]
    fn a_change_that_names_itself_as_its_predecessor_is_structurally_invalid() {
        // Asked the way the rule is asked in production: the caller holds
        // the change's own hash and passes it in. A self-naming change is
        // one where that hash is what `author_prev` names, so the test
        // hands `validate_structure` exactly that pair. (Building a genuine
        // self-naming change is impossible by construction — the field is
        // hashed, so naming a hash changes it — which is precisely why the
        // check is cheap to keep.)
        let mut change = change_at(AuthorSeq(4));
        let self_hash = ChangeHash([0xCDu8; 32]);
        change.author_prev = Some(self_hash);
        assert!(change.validate_structure(&self_hash).is_err());
        // The same change measured against its real hash is fine: only the
        // coincidence is refused.
        change.validate_structure(&change.compute_hash()).expect("not self-naming");
    }

    /// The history a change was written on is signed, not annotated. A
    /// relay that re-stamps it — the one edit that would let a returning
    /// device's old history pass for the current one — produces a change
    /// that no longer verifies.
    #[test]
    fn a_rewritten_history_epoch_breaks_the_signature() {
        let change = change_on(HistoryEpoch::Base(HistoryBase([3u8; 32])));
        let public_key = signing_key().verifying_key();
        change.verify_signature(&public_key).expect("the unmodified change verifies");

        for forged in [HistoryEpoch::Genesis, HistoryEpoch::Base(HistoryBase([4u8; 32]))] {
            let mut tampered = change.clone();
            tampered.history_epoch = forged;
            assert_eq!(
                tampered.verify_signature(&public_key),
                Err(ChangeError::BadSignature),
                "re-stamping a change onto {forged} must not survive verification"
            );
        }
    }

    /// And it is part of the change's identity, not merely of its
    /// authenticity: the same ops by the same author at the same position
    /// on two histories are two different changes, so a store keyed by
    /// hash can hold both and confuse neither for the other.
    #[test]
    fn the_same_change_on_two_histories_has_two_hashes() {
        let genesis = change_on(HistoryEpoch::Genesis);
        let based = change_on(HistoryEpoch::Base(HistoryBase([3u8; 32])));
        let other = change_on(HistoryEpoch::Base(HistoryBase([4u8; 32])));
        assert_ne!(genesis.compute_hash(), based.compute_hash());
        assert_ne!(based.compute_hash(), other.compute_hash());
    }

    /// The epoch survives the round trip, and is read back from the place
    /// it was written rather than defaulted.
    #[test]
    fn the_history_epoch_round_trips_through_the_wire_form() {
        for epoch in [HistoryEpoch::Genesis, HistoryEpoch::Base(HistoryBase([9u8; 32]))] {
            let change = change_on(epoch);
            let decoded = Change::from_wire_bytes(&change.to_wire_bytes()).unwrap();
            assert_eq!(decoded.history_epoch, epoch);
            assert_eq!(decoded, change);
        }
    }

    /// The header a pruned stub retains carries the epoch too. A stub that
    /// forgot which history it came from would be readable as belonging to
    /// the history that replaced it.
    #[test]
    fn the_authenticated_header_carries_the_history_epoch() {
        let genesis = change_on(HistoryEpoch::Genesis).authenticated_header_encoding();
        let based =
            change_on(HistoryEpoch::Base(HistoryBase([3u8; 32]))).authenticated_header_encoding();
        assert_ne!(genesis, based);
    }

    /// The sequence is part of the change's identity, so the same content
    /// claimed at two different positions in one author's chain is two
    /// different changes. Without this, an author could occupy two
    /// positions with one hash and a store keyed by hash could not tell
    /// which position it was holding.
    #[test]
    fn the_same_content_at_two_sequences_has_two_hashes() {
        let first = change_at(AuthorSeq(1));
        let second = change_at(AuthorSeq(2));
        assert_eq!(first.ops, second.ops);
        assert_eq!(first.parents, second.parents);
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.group_id, second.group_id);
        assert_eq!(first.lamport, second.lamport);
        assert_ne!(
            first.compute_hash(),
            second.compute_hash(),
            "the author sequence must be part of the change's content-addressed identity"
        );
    }

    /// The same two positions must also stay distinguishable once the
    /// change is reduced to the header a pruned causal stub keeps -- that
    /// header is all a compacted history retains of the author's dot.
    #[test]
    fn the_authenticated_header_carries_the_author_sequence() {
        assert_ne!(
            change_at(AuthorSeq(1)).authenticated_header_encoding(),
            change_at(AuthorSeq(2)).authenticated_header_encoding()
        );
    }

    #[test]
    fn the_author_sequence_survives_a_wire_round_trip() {
        let change = change_at(AuthorSeq(9));
        let decoded = Change::from_wire_bytes(&change.to_wire_bytes()).expect("round trip");
        assert_eq!(decoded.author_seq, AuthorSeq(9));
        assert_eq!(decoded, change);
    }

    /// Zero is reserved so a field nobody filled in cannot pass for a real
    /// position in an author's chain.
    #[test]
    fn author_sequence_zero_is_structurally_invalid() {
        let change = change_at(AuthorSeq(0));
        let hash = change.compute_hash();
        assert!(matches!(change.validate_structure(&hash), Err(ChangeError::Malformed(_))));
    }

    /// The sequence is a `u64` that a peer signs and every store keeps in a
    /// signed 64-bit column. A value the column cannot hold would be
    /// written there negative, and the author's retained position would read
    /// back as corruption on every later open -- so it is refused while it
    /// is still just a field.
    #[test]
    fn an_author_sequence_above_the_storable_ceiling_is_structurally_invalid() {
        let change = change_at(AuthorSeq(AuthorSeq::MAX.get() + 1));
        let hash = change.compute_hash();
        assert!(matches!(change.validate_structure(&hash), Err(ChangeError::Malformed(_))));
        assert!(change_at(AuthorSeq::MAX)
            .validate_structure(&change_at(AuthorSeq::MAX).compute_hash())
            .is_ok());
    }

    /// The same ceiling at the decode boundary, because not every path that
    /// turns wire bytes back into a change runs the structural validation --
    /// a re-bootstrap snapshot install writes decoded frontier changes
    /// straight into the store.
    #[test]
    fn an_author_sequence_above_the_storable_ceiling_does_not_decode() {
        let change = change_at(AuthorSeq(u64::MAX));
        assert!(matches!(
            Change::from_wire_bytes(&change.to_wire_bytes()),
            Err(ChangeError::Encoding(_))
        ));
    }
}
