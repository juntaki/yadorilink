//! File and file-version records -- the projected and content-addressed
//! representations of one path's content and metadata.

use sha2::{Digest, Sha256};

use crate::codec::{put_i64, put_len_bytes, put_u32, ChangeError, Reader};
use crate::ids::{BlockHash, ChangeHash, VersionHash};
use crate::limits::{MAX_BLOCKS, MAX_BLOCK_SIZE_BYTES};

/// Domain tag for a `FileVersion`'s canonical encoding. Version 2 carries a
/// per-block size alongside each block hash, so v1 and v2 encodings of the
/// same content are distinct byte strings and distinct hashes.
const VERSION_DOMAIN_TAG: &[u8; 8] = b"YLNKver\x02";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub hash: Vec<u8>,
    pub offset: u64,
    pub size: u32,
}

fn unknown_persisted_enum(kind: &str, value: &str) -> ! {
    panic!("corrupt local state: unknown persisted {kind} value {value:?}")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RecordKind {
    #[default]
    File,
    Directory,
    Symlink,
}

impl RecordKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "file" => Self::File,
            "directory" => Self::Directory,
            "symlink" => Self::Symlink,
            other => unknown_persisted_enum("record kind", other),
        }
    }
}

/// Current projected content state for one path.
///
/// Causality is intentionally absent: it is represented by the authoring change
/// hash and DAG ancestry, never by per-file counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
}

/// Complete native representation of one projected path.
///
/// `proto::FileInfo` is only a serialization envelope. This type keeps content,
/// filesystem metadata, origin, and verified DAG identity together after
/// decoding, so later code cannot accidentally drop fields by converting the
/// wire message to a bare legacy [`FileRecord`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileProjection {
    pub record: FileRecord,
    pub record_kind: RecordKind,
    pub symlink_target: Option<String>,
    pub symlink_out_of_root: bool,
    pub exec_bit: bool,
    pub origin_device_id: String,
    pub authoring_change_hash: ChangeHash,
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
    /// The symlink's raw, unresolved target, as the *exact* bytes the
    /// platform's own symlink target representation holds — never lossily
    /// converted to/from UTF-8. On Unix this is the target's raw OS bytes
    /// (a symlink target has no UTF-8 requirement there). On Windows this is
    /// the target's UTF-16 code units serialized little-endian, matching
    /// `fs_identity`'s own `target_to_bytes` — the same representation that
    /// already has to survive an unpaired surrogate, which is valid in an
    /// `OsString` there but not valid UTF-8 or UTF-16. `None` for anything
    /// but a symlink. See `Change::encode_into`/`decode` for why the
    /// canonical encoding stores this as a raw length-prefixed byte string
    /// rather than a string field.
    pub symlink_target: Option<Vec<u8>>,
    pub record_kind: RecordKind,
}

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

impl FileMeta {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(record_kind_byte(self.record_kind));
        buf.push(self.exec_bit as u8);
        put_i64(buf, self.mtime_unix_nanos);
        // Raw length-prefixed bytes, not a string put — a symlink target is
        // not required to be valid UTF-8 (see `FileMeta::symlink_target`'s
        // doc), and this canonical encoding must have a representation for
        // every byte string a real target can be, not just ones that happen
        // to be valid UTF-8.
        match &self.symlink_target {
            None => buf.push(0),
            Some(target) => {
                buf.push(1);
                put_len_bytes(buf, target);
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
            1 => Some(r.len_bytes()?),
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
                    if b.size > MAX_BLOCK_SIZE_BYTES {
                        return Err(ChangeError::Malformed(format!(
                            "block size {} exceeds {MAX_BLOCK_SIZE_BYTES}",
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
        crate::codec::put_u64(&mut buf, self.size);
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
    /// enumeration and the peer version-present responder go through this
    /// rather than each re-deriving the byte layout, so the exact-version
    /// identifier used for durability is always the same
    /// `FileVersion::compute_hash()` the change-DAG itself hashes versions
    /// with — never a separate, ad hoc hash over a subset of these fields.
    pub fn from_index_row(
        blocks: Vec<BlockInfo>,
        size: u64,
        mtime_unix_nanos: i64,
        record_kind: RecordKind,
        exec_bit: bool,
        symlink_target: Option<Vec<u8>>,
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
