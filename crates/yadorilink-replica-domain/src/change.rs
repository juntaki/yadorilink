//! Signed, content-addressed change history — the core data model every
//! sync component codes against.
//!
//! Materialized folder state is a deterministic pure function of the *set*
//! of applied changes: there are no explicit merge nodes. A change carries
//! its parent change hashes (its causal predecessors), the originating
//! device and folder group, its operations, a logical (`lamport`)
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
use crate::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::limits::{MAX_OPS, MAX_PARENTS, MAX_PATH_BYTES, MAX_PATH_SEGMENTS};
use crate::reserved_paths::{IGNORE_FILE_NAME, ROOT_MARKER_FILE_NAME};

/// Domain tag for a `Change`'s canonical encoding. The trailing byte is a
/// format version so an older layout is detectable rather than silently
/// reinterpreted; version 2 carries the per-change authorization fields
/// (`auth_seq`, `auth_epoch`, `policy_head_hash`); version 3 collapses
/// `Op::Create`/`Op::Update` into `Op::Put` and adds `PutOrigin` — so v1, v2,
/// and v3 bytes can never hash to the same identity. Version 4 adds a signed
/// change purpose, including the logical obligations carried by a
/// retroactive-repair change.
pub const CHANGE_DOMAIN_TAG: &[u8; 8] = b"YLNKchg\x04";
/// Domain tag for [`Change::authenticated_header_encoding`] — the same
/// signed fields as [`Change::canonical_encoding`] with `ops` left out,
/// trailed by the signature. Distinct from `CHANGE_DOMAIN_TAG` so a header
/// encoding can never be mistaken for (or collide with) a full change's wire
/// bytes, even for the zero-op case.
const CHANGE_HEADER_DOMAIN_TAG: &[u8; 8] = b"YLNKchH\x01";
/// Version stamp for the header encoding a pruned causal stub retains
/// (`dag_store`'s `pruned_changes.encoding_version`), bumped only if
/// [`Change::authenticated_header_encoding`]'s layout changes.
pub const PRUNED_STUB_ENCODING_VERSION: i32 = 1;

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
    ConflictCopy { source_path: SyncPath, losing_change: ChangeHash },
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

/// The authorization context an author binds into a change at creation time.
/// All three fields are covered by the signature and the change hash, so a
/// signed change pins exactly which membership/policy state authorized it and
/// none of them can be restated after the fact:
/// - `auth_seq`: the membership authorization sequence the author held.
/// - `auth_epoch`: the group's authorization epoch the author wrote under; a
///   revoke bumps the epoch, so a revoked writer's later changes are
///   distinguishable from its legitimate old-epoch ones.
/// - `policy_head_hash`: the hash of the policy-log head the author pinned, so
///   a forked, rolled-back, or gapped policy log is detectable at admission.
///
/// Until the policy-log/membership infrastructure is wired in, local emission
/// fills all three with [`ChangeAuth::PLACEHOLDER`] (zeroes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChangeAuth {
    pub auth_seq: u64,
    pub auth_epoch: u64,
    pub policy_head_hash: [u8; 32],
}

impl ChangeAuth {
    /// The all-zero authorization stamp used by local emission until policy
    /// sequencing is threaded down to the emission sites.
    pub const PLACEHOLDER: ChangeAuth =
        ChangeAuth { auth_seq: 0, auth_epoch: 0, policy_head_hash: [0u8; 32] };
}

/// Signals that a group's authorization context cannot be produced right now,
/// so local emission must NOT stamp a change for it. An installed
/// authorization provider returns this when the group is *stale* — its most
/// recent policy snapshot failed verification, so its verified state was
/// dropped from the trusted set and inbound change admission for the group
/// fails closed until a valid snapshot restores it.
///
/// Stamping a [`ChangeAuth::PLACEHOLDER`] change during that window would land
/// a local DAG head that every valid-policy peer rejects, stranding it — and
/// every change descending from it — on a branch that can never replicate. The
/// emit path treats this as a signal to withhold the change entirely and keep
/// the edit journaled dirty so it is re-emitted, with a real authorization
/// stamp, once a valid policy snapshot is admitted. Each engine crate's own
/// error type (e.g. `SyncError::PolicyUnavailable`) converts from this via a
/// local `From` impl.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyUnavailable;

/// A signed, content-addressed change. `parents` are ascending and deduped;
/// `ops` are in canonical `(path, discriminant)` order. The `signature`
/// field is Ed25519 over the canonical encoding of every *other* field, and
/// the change hash is the SHA-256 of those same bytes — so neither the hash
/// nor the signature depends on the signature bytes themselves.
///
/// The `auth_seq` / `auth_epoch` / `policy_head_hash` fields are the author's
/// [`ChangeAuth`] stamp (see that type); they let a replica judge
/// authorization against the membership/policy state the author actually held,
/// not against whatever the log says now.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    pub parents: Vec<ChangeHash>,
    pub device_id: DeviceId,
    pub group_id: FolderGroupId,
    pub lamport: u64,
    pub auth_seq: u64,
    pub auth_epoch: u64,
    pub policy_head_hash: [u8; 32],
    pub purpose: ChangePurpose,
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
    }
}

fn encode_op_into(buf: &mut Vec<u8>, op: &Op) {
    buf.push(op.discriminant());
    match op {
        Op::Put { path, version, origin } => {
            put_str(buf, path.as_str());
            buf.extend_from_slice(&version.0);
            buf.push(put_origin_tag(origin));
            if let PutOrigin::ConflictCopy { source_path, losing_change } = origin {
                put_str(buf, source_path.as_str());
                buf.extend_from_slice(&losing_change.0);
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
        Op::Move { from, to, .. } => 1 + 4 + from.as_str().len() + 4 + to.as_str().len() + 32,
    }
}

/// Max canonical op-bytes packed into a single locally emitted change — shared
/// by the initial import and the startup reconcile, the two paths that convert
/// a bulk offline diff into a chain of changes. A change cannot be wire-split,
/// so it must fit in one delivered message; the transport rejects any inbound
/// message larger than `MAX_INBOUND_FRAGMENTS_PER_MESSAGE` (1024) *
/// `MAX_FRAGMENT_PAYLOAD` (1200 B) ≈ 1.2 MiB. 256 KiB stays well under that —
/// leaving ample room for the change's fixed header, parents, and signature —
/// while a pathological run of very long paths is split into a chain rather
/// than forming one change no wire message could ever carry.
pub const MAX_CHANGE_OP_BYTES: usize = 256 * 1024;

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
    /// is `max_parent_lamport + 1`; pass `0` for `max_parent_lamport` when
    /// there are no parents, giving a root change `lamport = 1`.
    pub fn create_signed(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        auth: ChangeAuth,
        device_id: DeviceId,
        group_id: FolderGroupId,
        ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        Self::create_signed_with_purpose(
            parents,
            max_parent_lamport,
            auth,
            device_id,
            group_id,
            ChangePurpose::Ordinary,
            ops,
            signing_key,
        )
    }

    /// Assembles and signs a first-class retroactive-repair carrier.
    #[allow(clippy::too_many_arguments)]
    pub fn create_repair_signed(
        parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        auth: ChangeAuth,
        device_id: DeviceId,
        group_id: FolderGroupId,
        obligations: Vec<RepairObligation>,
        ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        Self::create_signed_with_purpose(
            parents,
            max_parent_lamport,
            auth,
            device_id,
            group_id,
            ChangePurpose::RetroactiveRepair { obligations },
            ops,
            signing_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_signed_with_purpose(
        mut parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        auth: ChangeAuth,
        device_id: DeviceId,
        group_id: FolderGroupId,
        mut purpose: ChangePurpose,
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
            lamport,
            auth_seq: auth.auth_seq,
            auth_epoch: auth.auth_epoch,
            policy_head_hash: auth.policy_head_hash,
            purpose,
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
        put_str(&mut buf, self.device_id.as_str());
        put_u64(&mut buf, self.lamport);
        put_u64(&mut buf, self.auth_seq);
        put_u64(&mut buf, self.auth_epoch);
        buf.extend_from_slice(&self.policy_head_hash);
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
        put_str(&mut buf, self.device_id.as_str());
        put_u64(&mut buf, self.lamport);
        put_u64(&mut buf, self.auth_seq);
        put_u64(&mut buf, self.auth_epoch);
        buf.extend_from_slice(&self.policy_head_hash);
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
        if tag != CHANGE_DOMAIN_TAG {
            return Err(ChangeError::Encoding("bad change domain tag".into()));
        }
        let group_id = FolderGroupId(r.string()?);
        let device_id = DeviceId(r.string()?);
        let lamport = r.u64()?;
        let auth_seq = r.u64()?;
        let auth_epoch = r.u64()?;
        let policy_head_hash = r.array32()?;
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
            lamport,
            auth_seq,
            auth_epoch,
            policy_head_hash,
            purpose,
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
                    if let PutOrigin::ConflictCopy { source_path, .. } = origin {
                        validate_path(source_path.as_str())?;
                        if source_path.as_str() == path.as_str() {
                            return Err(ChangeError::Malformed(
                                "conflict-copy put's source_path equals its own derived path"
                                    .into(),
                            ));
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
