//! Signed, content-addressed change history — the core data model every
//! sync component codes against.
//!
//! Materialized folder state is a deterministic pure function of the *set*
//! of applied changes: there are no explicit merge nodes. A change carries
//! its parent change hashes (its causal predecessors), the originating
//! device and folder group, its operations, a logical (`lamport`)
//! tie-breaker, and an Ed25519 signature by the originating device.
//!
//! Two encodings live here and both are hand-specified, not derived from
//! serde or protobuf: the byte layout must be reproducible on any device
//! and any future version, because the change's identity *is* the SHA-256
//! of its canonical encoding. Protobuf/serde output is not canonical across
//! implementations, so it can never back a content hash. The layout is
//! fully length-delimited (every variable field is `u32` big-endian length
//! prefixed), every integer is a fixed-width big-endian value, and every
//! collection is emitted in a defined order (`parents` ascending and
//! deduped, `ops` by `(path, discriminant)`). A leading domain-tag prevents
//! a `FileVersion` encoding from ever colliding with a `Change` encoding.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::ignore_patterns::IGNORE_FILE_NAME;
use crate::root_identity::ROOT_MARKER_FILE_NAME;
use crate::types::RecordKind;

/// Domain tag for a `Change`'s canonical encoding. The trailing byte is a
/// format version so an older layout is detectable rather than silently
/// reinterpreted; version 2 carries the per-change authorization fields
/// (`auth_seq`, `auth_epoch`, `policy_head_hash`), so v1 and v2 bytes can
/// never hash to the same identity.
const CHANGE_DOMAIN_TAG: &[u8; 8] = b"YLNKchg\x02";
/// Domain tag for a `FileVersion`'s canonical encoding. Version 2 carries a
/// per-block size alongside each block hash, so v1 and v2 encodings of the
/// same content are distinct byte strings and distinct hashes.
const VERSION_DOMAIN_TAG: &[u8; 8] = b"YLNKver\x02";

/// Bounds enforced while decoding and validating untrusted bytes. They keep a
/// malicious or corrupt encoding from steering an oversized allocation or an
/// unbounded structure into the store; every legitimately produced
/// change/version stays far below them. Counts are checked against these
/// (and against the bytes actually remaining) *before* any `with_capacity`.
pub const MAX_PARENTS: usize = 1024;
pub const MAX_OPS: usize = 1 << 16;
pub const MAX_BLOCKS: usize = 1 << 20;
/// Largest byte length a single block may declare, matching the chunker's own
/// ceiling — a block larger than the chunker can ever emit is malformed.
pub const MAX_BLOCK_SIZE: u32 = crate::chunker::MAX_BLOCK_SIZE as u32;
/// A path may not exceed this many bytes, nor this many `/`-separated
/// segments. Bounds untrusted op paths before they reach the filesystem.
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_PATH_SEGMENTS: usize = 255;

/// SHA-256 of a change's canonical encoding — its content-addressed
/// identity. Two byte-identical encodings hash equal on every device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeHash(pub [u8; 32]);

/// SHA-256 of a `FileVersion`'s canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionHash(pub [u8; 32]);

/// Content hash of a single stored block. Length-prefixed in the canonical
/// encoding rather than fixed at 32 bytes, so the hash width is not baked
/// into the wire format.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockHash(pub Vec<u8>);

/// One block of a file: its content hash and its exact byte length. The size
/// is load-bearing under content-defined chunking — block boundaries are not
/// recoverable from hashes alone — so a receiver can lay out block offsets
/// (prefix sums of these sizes) and validate each fetched block against its
/// declared length. The sum of a version's block sizes must equal the
/// version's total `size`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VersionBlock {
    pub hash: BlockHash,
    pub size: u32,
}

/// A device's stable identity string (the same value used as the
/// `device_id` key throughout the index and wire protocol).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DeviceId(pub String);

/// A synced folder group's identity string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FolderGroupId(pub String);

/// A file path relative to a folder group's root, as an opaque UTF-8 string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SyncPath(pub String);

macro_rules! string_newtype {
    ($t:ty) => {
        impl $t {
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }
        impl From<String> for $t {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
string_newtype!(DeviceId);
string_newtype!(FolderGroupId);
string_newtype!(SyncPath);

impl std::fmt::Debug for ChangeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChangeHash({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for VersionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VersionHash({})", hex::encode(self.0))
    }
}
impl ChangeHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl VersionHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Per-file metadata carried by a `FileVersion` — everything that is part of
/// a file's identity beyond its block content. `mtime` participates in
/// version identity (a metadata-only touch is a distinct version) but never
/// in causality: causality is exclusively DAG ancestry, and the deterministic
/// tie-break among concurrent changes uses `lamport`, never wall-clock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileMeta {
    pub mtime_unix_nanos: i64,
    pub exec_bit: bool,
    pub symlink_target: Option<String>,
    pub record_kind: RecordKind,
}

/// A content-addressed description of one file's bytes plus metadata. Its
/// `version_hash` is the SHA-256 of the canonical encoding of everything
/// *else* in this struct — derived, never itself part of the encoding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FileVersion {
    pub version_hash: VersionHash,
    pub blocks: Vec<VersionBlock>,
    pub size: u64,
    pub meta: FileMeta,
}

/// One operation within a change. `Move` is a rename *hint*, not a distinct
/// identity operation: it is semantically exactly `Delete { from }` plus
/// `Create { to, version }`, and the materialization fold desugars it to that
/// pair. It exists only so a rename can be recognized as one (for UX and
/// transfer-avoidance) rather than as an unrelated delete and create; a
/// first-class per-entry identity model is a post-1.0 item, not this.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Op {
    Create { path: SyncPath, version: VersionHash },
    Update { path: SyncPath, version: VersionHash },
    Delete { path: SyncPath },
    Move { from: SyncPath, to: SyncPath, version: VersionHash },
}

impl Op {
    /// Stable per-variant discriminant used both in the canonical encoding
    /// and as the secondary key of the canonical op ordering.
    pub fn discriminant(&self) -> u8 {
        match self {
            Op::Create { .. } => 0,
            Op::Update { .. } => 1,
            Op::Delete { .. } => 2,
            Op::Move { .. } => 3,
        }
    }

    /// The primary path an op is keyed on for canonical ordering. For a
    /// `Move` this is the source path, so a rename sorts by where the file
    /// was, matching how the other ops key on the path they act on.
    pub fn primary_path(&self) -> &str {
        match self {
            Op::Create { path, .. } | Op::Update { path, .. } | Op::Delete { path } => {
                path.as_str()
            }
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
/// so local emission must NOT stamp a change for it. A daemon-installed
/// authorization provider returns this when the group is *stale* — its most
/// recent policy snapshot failed verification, so its verified state was
/// dropped from the trusted set and inbound change admission for the group
/// fails closed until a valid snapshot restores it.
///
/// Stamping a [`ChangeAuth::PLACEHOLDER`] change during that window would land
/// a local DAG head that every valid-policy peer rejects, stranding it — and
/// every change descending from it — on a branch that can never replicate. The
/// emit path treats this as a signal to withhold the change entirely and keep
/// the edit journaled dirty (see `SyncError::PolicyUnavailable` and the local
/// dirty-path journal) so it is re-emitted, with a real authorization stamp,
/// once a valid policy snapshot is admitted.
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
    pub ops: Vec<Op>,
    pub signature: [u8; 64],
}

/// Rejection reasons for the pure model/crypto layer. Deliberately separate
/// from the crate's `SyncError`: verification runs before anything is
/// admitted to persistent storage, so it never needs to compose with the
/// database-error taxonomy. Callers that admit changes (the peer session)
/// decide how a rejection surfaces and log it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChangeError {
    #[error("change encoding is malformed: {0}")]
    Encoding(String),
    #[error("change hash does not match its encoded bytes")]
    HashMismatch,
    #[error("file version block sizes do not sum to the declared total size")]
    BlockSizeMismatch,
    #[error("structurally invalid change or file version: {0}")]
    Malformed(String),
    #[error("change signature does not verify against the claimed device key")]
    BadSignature,
    #[error("device is not authorized to write to this group")]
    Unauthorized,
    #[error("signing key material is invalid")]
    InvalidKey,
}

// --- Canonical encoding primitives -----------------------------------------

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_i64(buf: &mut Vec<u8>, v: i64) {
    // Two's-complement big-endian — identical to the `u64` layout of the
    // same bit pattern, so a negative pre-epoch mtime is still deterministic.
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_len_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    put_u32(buf, b.len() as u32);
    buf.extend_from_slice(b);
}
fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_len_bytes(buf, s.as_bytes());
}

/// A forward-only cursor over a canonical encoding. Every read is bounds
/// checked, so a truncated or oversized length prefix is a clean
/// `ChangeError::Encoding` rather than a panic.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ChangeError> {
        if self.remaining() < n {
            return Err(ChangeError::Encoding(format!(
                "expected {n} more bytes, {} remaining",
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u32(&mut self) -> Result<u32, ChangeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ChangeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, ChangeError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u8(&mut self) -> Result<u8, ChangeError> {
        Ok(self.take(1)?[0])
    }
    fn len_bytes(&mut self) -> Result<Vec<u8>, ChangeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, ChangeError> {
        let bytes = self.len_bytes()?;
        String::from_utf8(bytes).map_err(|e| ChangeError::Encoding(e.to_string()))
    }
    fn array32(&mut self) -> Result<[u8; 32], ChangeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    /// Reads a `u32` collection count and rejects it before it can size an
    /// allocation: it must not exceed `max`, nor the number of entries the
    /// remaining bytes could possibly encode (each entry is at least
    /// `min_entry_size` bytes). This makes a following `with_capacity(count)`
    /// safe against a hostile length prefix.
    fn bounded_count(&mut self, min_entry_size: usize, max: usize) -> Result<usize, ChangeError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(ChangeError::Malformed(format!("count {count} exceeds bound {max}")));
        }
        if min_entry_size > 0 && count > self.remaining() / min_entry_size {
            return Err(ChangeError::Encoding(format!(
                "count {count} exceeds the {} entries the remaining bytes can hold",
                self.remaining() / min_entry_size
            )));
        }
        Ok(count)
    }
    fn expect_end(&self) -> Result<(), ChangeError> {
        if self.remaining() != 0 {
            return Err(ChangeError::Encoding(format!(
                "{} trailing bytes after change",
                self.remaining()
            )));
        }
        Ok(())
    }
}

fn record_kind_byte(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::File => 0,
        RecordKind::Directory => 1,
        RecordKind::Symlink => 2,
    }
}
fn record_kind_from_byte(b: u8) -> Result<RecordKind, ChangeError> {
    match b {
        0 => Ok(RecordKind::File),
        1 => Ok(RecordKind::Directory),
        2 => Ok(RecordKind::Symlink),
        other => Err(ChangeError::Encoding(format!("unknown record kind {other}"))),
    }
}

// --- FileVersion encoding / hashing ----------------------------------------

impl FileMeta {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(record_kind_byte(self.record_kind));
        buf.push(self.exec_bit as u8);
        put_i64(buf, self.mtime_unix_nanos);
        match &self.symlink_target {
            None => buf.push(0),
            Some(target) => {
                buf.push(1);
                put_str(buf, target);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ChangeError> {
        let record_kind = record_kind_from_byte(r.u8()?)?;
        let exec_bit = match r.u8()? {
            0 => false,
            1 => true,
            other => return Err(ChangeError::Encoding(format!("bad exec bit {other}"))),
        };
        let mtime_unix_nanos = r.i64()?;
        let symlink_target = match r.u8()? {
            0 => None,
            1 => Some(r.string()?),
            other => return Err(ChangeError::Encoding(format!("bad symlink flag {other}"))),
        };
        Ok(FileMeta { record_kind, exec_bit, mtime_unix_nanos, symlink_target })
    }
}

impl FileVersion {
    /// Builds a version from its parts and fills in the derived
    /// `version_hash` by hashing the canonical encoding of everything else.
    pub fn new(blocks: Vec<VersionBlock>, size: u64, meta: FileMeta) -> Self {
        let mut v = FileVersion { version_hash: VersionHash([0u8; 32]), blocks, size, meta };
        v.version_hash = v.compute_hash();
        v
    }

    /// Structural validation of the block layout. Bounded block count always;
    /// then, for a regular file, every block is non-empty and within the
    /// chunker's ceiling, the block list is empty iff the file is empty, and
    /// the per-block sizes sum to the declared total. A symlink or directory
    /// version carries no content blocks — its `size` is metadata (e.g. the
    /// symlink's on-disk length), not a sum of block sizes — so only the
    /// "no blocks" invariant applies. Content hashes are validated elsewhere
    /// (block fetch); this is the size/shape contract a receiver relies on to
    /// derive offsets safely.
    fn validate_blocks(&self) -> Result<(), ChangeError> {
        if self.blocks.len() > MAX_BLOCKS {
            return Err(ChangeError::Malformed(format!(
                "block count {} exceeds {MAX_BLOCKS}",
                self.blocks.len()
            )));
        }
        match self.meta.record_kind {
            RecordKind::File => {
                if self.blocks.is_empty() != (self.size == 0) {
                    return Err(ChangeError::Malformed(
                        "an empty file must carry no blocks and a non-empty file must carry blocks"
                            .into(),
                    ));
                }
                let mut sum: u64 = 0;
                for b in &self.blocks {
                    if b.size == 0 {
                        return Err(ChangeError::Malformed("zero-length block".into()));
                    }
                    if b.size > MAX_BLOCK_SIZE {
                        return Err(ChangeError::Malformed(format!(
                            "block size {} exceeds {MAX_BLOCK_SIZE}",
                            b.size
                        )));
                    }
                    sum += b.size as u64;
                }
                if sum != self.size {
                    return Err(ChangeError::BlockSizeMismatch);
                }
            }
            RecordKind::Symlink | RecordKind::Directory => {
                if !self.blocks.is_empty() {
                    return Err(ChangeError::Malformed(
                        "a symlink or directory version must carry no content blocks".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The canonical byte layout hashed to form `version_hash`. Does not
    /// include `version_hash` itself.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(VERSION_DOMAIN_TAG);
        put_u64(&mut buf, self.size);
        put_u32(&mut buf, self.blocks.len() as u32);
        for block in &self.blocks {
            // Block order is meaningful (it is the file's byte order), so it
            // is preserved, not sorted. Each block carries its exact byte
            // length after its content hash.
            put_len_bytes(&mut buf, &block.hash.0);
            put_u32(&mut buf, block.size);
        }
        self.meta.encode_into(&mut buf);
        buf
    }

    pub fn compute_hash(&self) -> VersionHash {
        VersionHash(Sha256::digest(self.canonical_encoding()).into())
    }

    /// Reconstructs the `FileVersion` a stored `files` index row describes —
    /// its block list (in file-byte order, each with its declared size), its
    /// total size, and its metadata — and derives `version_hash` from it via
    /// [`Self::compute_hash`]. This is the sole place a `files` row is turned
    /// back into a canonical version identity: both the durability-root
    /// enumeration (`index::enumerate_group_durability_roots_on_conn`) and the
    /// peer version-present responder (`peer_session::holds_version_durably`)
    /// go through this rather than each re-deriving the byte layout, so the
    /// exact-version identifier used for durability is always the same
    /// `FileVersion::compute_hash()` the change-DAG itself hashes versions
    /// with — never a separate, ad hoc hash over a subset of these fields.
    pub fn from_index_row(
        blocks: Vec<crate::types::BlockInfo>,
        size: u64,
        mtime_unix_nanos: i64,
        record_kind: RecordKind,
        exec_bit: bool,
        symlink_target: Option<String>,
    ) -> FileVersion {
        let blocks = blocks
            .into_iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash), size: b.size })
            .collect();
        let meta = FileMeta { mtime_unix_nanos, exec_bit, symlink_target, record_kind };
        FileVersion::new(blocks, size, meta)
    }

    /// Recomputes the hash and checks it matches the stored `version_hash`,
    /// then applies the full block-layout validation. Both the hash and the
    /// structural invariants must hold for a stored or received version.
    pub fn verify_hash(&self) -> Result<(), ChangeError> {
        if self.compute_hash() != self.version_hash {
            return Err(ChangeError::HashMismatch);
        }
        self.validate_blocks()
    }

    /// Parses the `canonical_encoding` form back into a `FileVersion`,
    /// re-deriving `version_hash` from the parsed bytes (it is never part of
    /// the encoding). This is the inverse used when a version is read back
    /// from its stored/wire canonical bytes: because the hash is recomputed
    /// here rather than trusted from an external source, the returned
    /// version's `version_hash` always describes its own content, and a
    /// lookup keyed by a referenced hash only matches a version whose bytes
    /// actually hash to it.
    pub fn from_canonical_encoding(bytes: &[u8]) -> Result<FileVersion, ChangeError> {
        let mut r = Reader::new(bytes);
        let tag = r.take(8)?;
        if tag != VERSION_DOMAIN_TAG {
            return Err(ChangeError::Encoding("bad version domain tag".into()));
        }
        let size = r.u64()?;
        // A block encodes at least a 4-byte length prefix and a 4-byte size,
        // so a count larger than the bytes that remain (or than the absolute
        // cap) is malformed — reject before allocating.
        let block_count = r.bounded_count(8, MAX_BLOCKS)?;
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let hash = BlockHash(r.len_bytes()?);
            let block_size = r.u32()?;
            blocks.push(VersionBlock { hash, size: block_size });
        }
        let meta = FileMeta::decode(&mut r)?;
        r.expect_end()?;
        let version = FileVersion::new(blocks, size, meta);
        // Enforce the full block-layout contract on untrusted bytes: hashes
        // pin block content, but only this validation ties the block sizes to
        // the file's size and bounds each block, so a receiver can trust the
        // offsets it derives from them.
        version.validate_blocks()?;
        Ok(version)
    }
}

// --- Change encoding / hashing / signing -----------------------------------

fn encode_op_into(buf: &mut Vec<u8>, op: &Op) {
    buf.push(op.discriminant());
    match op {
        Op::Create { path, version } | Op::Update { path, version } => {
            put_str(buf, path.as_str());
            buf.extend_from_slice(&version.0);
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

/// The canonical encoded byte length of one op, mirroring [`encode_op_into`]:
/// a 1-byte discriminant, a 4-byte path-length prefix, the path bytes, and —
/// for a create/update/move — the 32-byte version hash. The single source of
/// truth for per-op sizing: callers that bound a change's encoded size before
/// emitting it (the initial import and the startup reconcile) share this so
/// their byte accounting can never drift from what `encode_op_into` writes.
pub(crate) fn encoded_op_len(op: &Op) -> usize {
    match op {
        Op::Delete { path } => 1 + 4 + path.as_str().len(),
        Op::Create { path, .. } | Op::Update { path, .. } => 1 + 4 + path.as_str().len() + 32,
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
pub(crate) const MAX_CHANGE_OP_BYTES: usize = 256 * 1024;

fn decode_op(r: &mut Reader<'_>) -> Result<Op, ChangeError> {
    let disc = r.u8()?;
    Ok(match disc {
        0 => Op::Create { path: SyncPath(r.string()?), version: VersionHash(r.array32()?) },
        1 => Op::Update { path: SyncPath(r.string()?), version: VersionHash(r.array32()?) },
        2 => Op::Delete { path: SyncPath(r.string()?) },
        3 => Op::Move {
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
        mut parents: Vec<ChangeHash>,
        max_parent_lamport: u64,
        auth: ChangeAuth,
        device_id: DeviceId,
        group_id: FolderGroupId,
        mut ops: Vec<Op>,
        signing_key: &SigningKey,
    ) -> Self {
        parents.sort();
        parents.dedup();
        ops.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
        let lamport = max_parent_lamport.saturating_add(1);
        let mut change = Change {
            parents,
            device_id,
            group_id,
            lamport,
            auth_seq: auth.auth_seq,
            auth_epoch: auth.auth_epoch,
            policy_head_hash: auth.policy_head_hash,
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
        let mut touched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut prev_key: Option<(&str, u8)> = None;
        for op in &self.ops {
            let key = op.sort_key();
            if prev_key.is_some_and(|pk| key < pk) {
                return Err(ChangeError::Malformed("ops are not in canonical order".into()));
            }
            prev_key = Some(key);
            match op {
                Op::Create { path, .. } | Op::Update { path, .. } | Op::Delete { path } => {
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
    if path.starts_with('/') || path.starts_with('\\') {
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

    fn sample_version() -> FileVersion {
        FileVersion::new(
            vec![
                VersionBlock { hash: BlockHash(vec![0x00, 0x11, 0x22, 0x33]), size: 1000 },
                VersionBlock {
                    hash: BlockHash(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                    size: 234,
                },
            ],
            1234,
            FileMeta {
                mtime_unix_nanos: 1_600_000_000_000_000_000,
                exec_bit: true,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn sample_change() -> Change {
        // Signature is irrelevant to the hash; use a deterministic
        // placeholder so the golden vector below is reproducible without a
        // key. `parents` are already ascending, `ops` already canonical.
        Change {
            parents: vec![ChangeHash([0x11; 32]), ChangeHash([0x22; 32])],
            device_id: DeviceId("device-A".into()),
            group_id: FolderGroupId("group-1".into()),
            lamport: 5,
            auth_seq: 7,
            auth_epoch: 3,
            policy_head_hash: [0x99; 32],
            ops: vec![
                Op::Create {
                    path: SyncPath("a.txt".into()),
                    version: sample_version().version_hash,
                },
                Op::Delete { path: SyncPath("b.txt".into()) },
            ],
            signature: [0u8; 64],
        }
    }

    /// The encoding, and therefore the hash, must never drift. These golden
    /// vectors were computed from the hand-specified byte layout by an
    /// independent implementation; if this assertion ever fails, the
    /// encoding changed and every previously stored change's identity would
    /// silently move with it.
    #[test]
    fn version_hash_matches_golden_vector() {
        assert_eq!(
            sample_version().version_hash.to_hex(),
            "e840ffbc25b273b0f477327b2e2cdabebbf88e266dc3f822b32427743695ebbf",
        );
    }

    #[test]
    fn change_hash_matches_golden_vector() {
        assert_eq!(
            sample_change().compute_hash().to_hex(),
            "9cc20eea16de736da8451b4edc7e9902f57388448077e3e74289eecae72c00b1",
        );
    }

    #[test]
    fn change_wire_round_trips() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut change = sample_change();
        change.sign(&key);
        let bytes = change.to_wire_bytes();
        let decoded = Change::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, change);
        assert_eq!(decoded.compute_hash(), change.compute_hash());
    }

    #[test]
    fn file_version_round_trips_through_meta_variants() {
        for meta in [
            FileMeta {
                mtime_unix_nanos: -42,
                exec_bit: false,
                symlink_target: Some("../elsewhere".into()),
                record_kind: RecordKind::Symlink,
            },
            FileMeta {
                mtime_unix_nanos: i64::MAX,
                exec_bit: true,
                symlink_target: None,
                record_kind: RecordKind::Directory,
            },
        ] {
            // These variants are a symlink and a directory, which carry no
            // content blocks; `size` is metadata for them. The block layout is
            // round-tripped by the file-kind tests above.
            let v = FileVersion::new(vec![], 0, meta);
            // Rehash from parts and confirm the derived hash is stable.
            assert_eq!(v.compute_hash(), v.version_hash);
            v.verify_hash().unwrap();
        }
    }

    #[test]
    fn file_version_decode_rejects_block_size_total_mismatch() {
        // Blocks summing to 3, but the declared total is 99: the layout does
        // not describe the file's size, so decode refuses it rather than hand
        // back offsets that walk off the end.
        let v = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![1, 2, 3]), size: 3 }],
            99,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        assert_eq!(v.verify_hash(), Err(ChangeError::BlockSizeMismatch));
        let bytes = v.canonical_encoding();
        assert_eq!(
            FileVersion::from_canonical_encoding(&bytes),
            Err(ChangeError::BlockSizeMismatch)
        );
    }

    #[test]
    fn version_block_size_is_covered_by_the_hash() {
        // Two versions identical but for one block's declared size hash apart,
        // so a receiver cannot substitute a different block layout.
        let meta = FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        };
        let a = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![9]), size: 4 }],
            4,
            meta.clone(),
        );
        let b = FileVersion::new(vec![VersionBlock { hash: BlockHash(vec![9]), size: 5 }], 5, meta);
        assert_ne!(a.version_hash, b.version_hash);
    }

    #[test]
    fn auth_fields_are_covered_by_the_hash_and_signature() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let mut base = sample_change();
        base.sign(&key);
        base.verify_signature(&key.verifying_key()).unwrap();

        // Each of the three authorization fields is part of the signed and
        // hashed bytes: flipping any one changes the identity and breaks the
        // signature, so an author cannot restate its authorization context.
        for tamper in [
            |c: &mut Change| c.auth_seq ^= 1,
            |c: &mut Change| c.auth_epoch ^= 1,
            |c: &mut Change| c.policy_head_hash[0] ^= 1,
        ] {
            let mut t = base.clone();
            tamper(&mut t);
            assert_ne!(t.compute_hash(), base.compute_hash());
            assert_eq!(t.verify_signature(&key.verifying_key()), Err(ChangeError::BadSignature));
        }
    }

    #[test]
    fn hash_excludes_signature() {
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let mut a = sample_change();
        a.sign(&key_a);
        let mut b = sample_change();
        b.sign(&key_b);
        assert_ne!(a.signature, b.signature);
        assert_eq!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut change = sample_change();
        change.sign(&key);
        change.verify_signature(&key.verifying_key()).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_ops() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut change = sample_change();
        change.sign(&key);
        // Mutate an op after signing: the signature no longer covers it.
        change.ops.push(Op::Delete { path: SyncPath("c.txt".into()) });
        assert_eq!(change.verify_signature(&key.verifying_key()), Err(ChangeError::BadSignature));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let impostor = SigningKey::from_bytes(&[10u8; 32]);
        let mut change = sample_change();
        change.sign(&signer);
        assert_eq!(
            change.verify_signature(&impostor.verifying_key()),
            Err(ChangeError::BadSignature)
        );
    }

    #[test]
    fn verify_change_checks_hash_signature_and_authorization() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let change = Change::create_signed(
            vec![ChangeHash([0x22; 32]), ChangeHash([0x11; 32])],
            4,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("group-1".into()),
            vec![Op::Delete { path: SyncPath("b.txt".into()) }],
            &key,
        );
        let hash = change.compute_hash();
        let pubkey = key.verifying_key();

        verify_change(&change, &hash, &pubkey, |_d, _g| true).unwrap();

        // Wrong claimed hash.
        assert_eq!(
            verify_change(&change, &ChangeHash([0; 32]), &pubkey, |_, _| true),
            Err(ChangeError::HashMismatch)
        );
        // Unauthorized device.
        assert_eq!(
            verify_change(&change, &hash, &pubkey, |_, _| false),
            Err(ChangeError::Unauthorized)
        );
    }

    #[test]
    fn create_signed_normalizes_parents_and_ops() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let change = Change::create_signed(
            // Unsorted + duplicate parents.
            vec![ChangeHash([0x33; 32]), ChangeHash([0x11; 32]), ChangeHash([0x33; 32])],
            10,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d".into()),
            FolderGroupId("g".into()),
            // Out-of-order ops.
            vec![
                Op::Delete { path: SyncPath("z.txt".into()) },
                Op::Create { path: SyncPath("a.txt".into()), version: VersionHash([0; 32]) },
            ],
            &key,
        );
        assert_eq!(change.parents, vec![ChangeHash([0x11; 32]), ChangeHash([0x33; 32])]);
        assert_eq!(change.lamport, 11);
        assert_eq!(change.ops[0].primary_path(), "a.txt");
        assert_eq!(change.ops[1].primary_path(), "z.txt");
        change.verify_signature(&key.verifying_key()).unwrap();
    }

    #[test]
    fn from_wire_rejects_truncation_without_panicking() {
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let mut change = sample_change();
        change.sign(&key);
        let bytes = change.to_wire_bytes();
        for cut in [0, 8, 20, bytes.len() - 1] {
            assert!(Change::from_wire_bytes(&bytes[..cut]).is_err());
        }
    }

    // --- R3 structural validation ---------------------------------------

    /// A `Change` literal (bypasses `create_signed`'s normalization so invalid
    /// structure can be constructed) and its own computed hash.
    fn literal(parents: Vec<ChangeHash>, ops: Vec<Op>) -> Change {
        Change {
            parents,
            device_id: DeviceId("d".into()),
            group_id: FolderGroupId("g".into()),
            lamport: 1,
            auth_seq: 0,
            auth_epoch: 0,
            policy_head_hash: [0u8; 32],
            ops,
            signature: [0u8; 64],
        }
    }
    fn create(path: &str) -> Op {
        Op::Create { path: SyncPath(path.into()), version: VersionHash([1u8; 32]) }
    }
    fn validate(c: &Change) -> Result<(), ChangeError> {
        c.validate_structure(&c.compute_hash())
    }

    #[test]
    fn validate_structure_accepts_a_well_formed_change() {
        let c = literal(
            vec![ChangeHash([0x11; 32]), ChangeHash([0x22; 32])],
            vec![create("a/b.txt"), Op::Delete { path: SyncPath("c.txt".into()) }],
        );
        validate(&c).unwrap();
    }

    #[test]
    fn validate_structure_rejects_unsorted_or_duplicate_parents() {
        let unsorted =
            literal(vec![ChangeHash([0x22; 32]), ChangeHash([0x11; 32])], vec![create("a")]);
        assert!(matches!(validate(&unsorted), Err(ChangeError::Malformed(_))));
        let dup = literal(vec![ChangeHash([0x11; 32]), ChangeHash([0x11; 32])], vec![create("a")]);
        assert!(matches!(validate(&dup), Err(ChangeError::Malformed(_))));
    }

    #[test]
    fn validate_structure_rejects_self_parent() {
        let mut c = literal(vec![], vec![create("a")]);
        let self_hash = c.compute_hash();
        c.parents = vec![self_hash];
        assert!(matches!(c.validate_structure(&self_hash), Err(ChangeError::Malformed(_))));
    }

    #[test]
    fn validate_structure_rejects_non_canonical_op_order() {
        // "b" before "a" is not canonical order.
        let c = literal(vec![], vec![create("b"), create("a")]);
        assert!(matches!(validate(&c), Err(ChangeError::Malformed(_))));
    }

    #[test]
    fn validate_structure_rejects_two_ops_on_one_path() {
        let c = literal(vec![], vec![create("a"), Op::Delete { path: SyncPath("a".into()) }]);
        assert!(matches!(validate(&c), Err(ChangeError::Malformed(_))));
    }

    #[test]
    fn validate_structure_rejects_self_move() {
        let c = literal(
            vec![],
            vec![Op::Move {
                from: SyncPath("a".into()),
                to: SyncPath("a".into()),
                version: VersionHash([1u8; 32]),
            }],
        );
        assert!(matches!(validate(&c), Err(ChangeError::Malformed(_))));
    }

    #[test]
    fn validate_structure_rejects_unsafe_paths() {
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../b",
            "a/./b",
            "C:evil",
            "a\\..\\b",
            "a\0b",
            ".yadorilink-root",
            ".yadorilink-root/child",
            ".yadorilinkignore",
            ".yadorilinkignore/child",
        ] {
            let c = literal(vec![], vec![create(bad)]);
            assert!(
                matches!(validate(&c), Err(ChangeError::Malformed(_))),
                "path {bad:?} should be rejected"
            );
        }
        // A normal nested path is fine.
        validate(&literal(vec![], vec![create("dir/sub/file.txt")])).unwrap();
    }

    #[test]
    fn from_wire_rejects_an_oversized_parent_count_without_allocating() {
        // A parent count far beyond the bytes that follow must be refused at
        // decode, not fed to `Vec::with_capacity`.
        let mut b = Vec::new();
        b.extend_from_slice(CHANGE_DOMAIN_TAG);
        put_str(&mut b, "g");
        put_str(&mut b, "d");
        put_u64(&mut b, 1); // lamport
        put_u64(&mut b, 0); // auth_seq
        put_u64(&mut b, 0); // auth_epoch
        b.extend_from_slice(&[0u8; 32]); // policy_head_hash
        put_u32(&mut b, u32::MAX); // absurd parent count, no parents follow
        assert!(matches!(
            Change::from_wire_bytes(&b),
            Err(ChangeError::Malformed(_)) | Err(ChangeError::Encoding(_))
        ));
    }

    #[test]
    fn verify_change_runs_structural_validation() {
        // A signed but structurally invalid change (two ops on one path) is
        // rejected by the full admission check, not just by signature.
        let key = SigningKey::from_bytes(&[14u8; 32]);
        let mut c = literal(vec![], vec![create("a"), Op::Delete { path: SyncPath("a".into()) }]);
        c.sign(&key);
        let hash = c.compute_hash();
        assert!(matches!(
            verify_change(&c, &hash, &key.verifying_key(), |_, _| true),
            Err(ChangeError::Malformed(_))
        ));
    }

    // --- R3.6 file-version block validation ------------------------------

    fn version_with(blocks: Vec<VersionBlock>, size: u64) -> FileVersion {
        FileVersion::new(
            blocks,
            size,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    #[test]
    fn file_version_rejects_zero_length_and_oversized_blocks() {
        let zero = version_with(vec![VersionBlock { hash: BlockHash(vec![1]), size: 0 }], 0);
        assert!(matches!(zero.verify_hash(), Err(ChangeError::Malformed(_))));

        let over = version_with(
            vec![
                VersionBlock { hash: BlockHash(vec![1]), size: MAX_BLOCK_SIZE },
                VersionBlock { hash: BlockHash(vec![2]), size: 1 },
            ],
            MAX_BLOCK_SIZE as u64 + 1,
        );
        // First block is at the ceiling (allowed); make one exceed it.
        let too_big = version_with(
            vec![VersionBlock { hash: BlockHash(vec![1]), size: MAX_BLOCK_SIZE + 1 }],
            MAX_BLOCK_SIZE as u64 + 1,
        );
        assert!(matches!(too_big.verify_hash(), Err(ChangeError::Malformed(_))));
        // `over` has valid per-block sizes summing to size, so it is accepted.
        over.verify_hash().unwrap();
    }

    #[test]
    fn file_version_enforces_empty_file_iff_empty_blocks() {
        // Non-empty declared size but no blocks.
        let no_blocks = version_with(vec![], 10);
        assert!(matches!(no_blocks.verify_hash(), Err(ChangeError::Malformed(_))));
        // Empty size but a block present (block is non-empty, so sizes can't
        // both be zero and match): rejected.
        let ghost_block = version_with(vec![VersionBlock { hash: BlockHash(vec![1]), size: 4 }], 0);
        assert!(ghost_block.verify_hash().is_err());
        // A genuinely empty file: no blocks, zero size.
        version_with(vec![], 0).verify_hash().unwrap();
    }

    #[test]
    fn symlink_version_has_no_blocks_and_skips_the_size_cross_check() {
        // A symlink's `size` is its on-disk length, unrelated to block sizes,
        // and it carries no content blocks — valid, though the same shape
        // (non-zero size, no blocks) is rejected for a regular file.
        let link = FileVersion::new(
            vec![],
            27,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: Some("../some/target/path".into()),
                record_kind: RecordKind::Symlink,
            },
        );
        link.verify_hash().unwrap();

        // A non-file version that nonetheless carries blocks is malformed.
        let bad = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(vec![1]), size: 4 }],
            4,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: Some("t".into()),
                record_kind: RecordKind::Symlink,
            },
        );
        assert!(matches!(bad.verify_hash(), Err(ChangeError::Malformed(_))));
    }
}
