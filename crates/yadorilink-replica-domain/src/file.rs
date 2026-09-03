//! File and file-version records -- the projected and content-addressed
//! representations of one path's content and metadata.

use sha2::{Digest, Sha256};

use crate::codec::{put_i64, put_len_bytes, put_u32, ChangeError, Reader};
use crate::ids::{BlockHash, ChangeHash, VersionHash};
use crate::limits::{MAX_BLOCKS, MAX_BLOCK_SIZE_BYTES, MAX_XATTRS};

/// Domain tag for a `FileVersion`'s canonical encoding. Version 2 carries a
/// per-block size alongside each block hash, so v1 and v2 encodings of the
/// same content are distinct byte strings and distinct hashes. Version 3
/// replaced the single owner-exec bit with the full `unix_mode` permission
/// word (see `FileMeta::unix_mode`), so v2 and v3 encodings of otherwise
/// identical metadata are also distinct. Version 4 (C1.2a) added `xattrs`
/// (see `FileMeta::xattrs`), so v3 and v4 encodings of otherwise identical
/// metadata are also distinct.
const VERSION_DOMAIN_TAG: &[u8; 8] = b"YLNKver\x04";

/// The only `st_mode` bits this sync tool replicates: owner/group/other
/// read-write-execute (`chmod`'s familiar 3-digit form). Deliberately
/// excludes setuid/setgid/sticky (`0o7000`) and the higher file-type bits --
/// replicating a setuid bit onto another device is a privilege-escalation
/// vector, not a filesystem-fidelity feature, and file type is already
/// carried by `RecordKind`. A mode value is always masked through this
/// before it enters a `FileMeta`, so `unix_mode`'s own range invariant
/// (`0..=0o777`) cannot be violated by a caller forgetting to mask.
pub const REPLICATED_MODE_MASK: u32 = 0o777;

/// The only extended-attribute namespace this sync tool ever replicates,
/// on any platform -- mirrors `yadorilink-local-storage::chunker`'s own
/// capture/apply-side allow-list (Linux's `user.` prefix; every other
/// platform allow-lists nothing at all today). Kept as an independent
/// constant here rather than a shared dependency because this crate
/// cannot depend on `yadorilink-local-storage` (wrong layering direction
/// -- this is the lower-level protocol crate), and `FileMeta::decode`'s
/// own enforcement of it must hold regardless of what any platform's
/// local capture/apply code does: decode is the one place every
/// hand-crafted, signed-but-untrusted `FileVersion` from any peer is
/// forced through before this device trusts any of its fields. If a
/// future platform ever earns its own allow-listed namespace, this
/// constant (and `yadorilink-local-storage`'s matching one) both need
/// updating together.
const REPLICATED_XATTR_ALLOWED_PREFIX: &str = "user.";

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
    pub unix_mode: Option<u32>,
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
    /// The replicated permission bits (`REPLICATED_MODE_MASK`, i.e.
    /// `0..=0o777`), or `None` when the authoring device has no Unix
    /// permission model to report (a Windows peer). `None` is a genuine,
    /// distinct identity state, not a stand-in for "unknown" collapsing to
    /// some fake default -- a peer that cannot represent Unix mode does not
    /// fabricate one (see this field's callers in `yadorilink-daemon` for
    /// how a `None`-authored version is handled when merged with a peer
    /// that does carry a mode).
    pub unix_mode: Option<u32>,
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
    /// Extended attributes this sync tool replicates, sorted by name --
    /// never in the OS's own `listxattr` return order, which is not
    /// guaranteed stable even across two calls on the same unmodified
    /// file, let alone between the two independent capture paths
    /// (`single_pass_capture.rs`/`local_change.rs`) that must derive
    /// identical `FileMeta` for the same file. Deliberately NOT every
    /// xattr a file happens to carry -- only an explicit per-platform
    /// allow-list (`REPLICATED_XATTR_NAMESPACES`-equivalent capture-side
    /// filter) passes through, the same reasoning `REPLICATED_MODE_MASK`
    /// already applies to permission bits: a security-context or
    /// OS-internal attribute (Linux `security.*`/`system.*`/`trusted.*`,
    /// macOS `com.apple.quarantine`/`com.apple.ResourceFork`/
    /// `com.apple.metadata:*`) is either meaningless or actively
    /// dangerous to replicate onto a different device, never a
    /// filesystem-fidelity feature. Empty for a platform/backend with no
    /// xattr capability, a directory or symlink (not scanned), or a file
    /// with no allow-listed attributes -- there is no distinct "not
    /// applicable" state to preserve here the way `unix_mode: None` needs
    /// one, since an empty set already means exactly the same thing in
    /// every one of those cases.
    pub xattrs: Vec<(String, Vec<u8>)>,
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
        match self.unix_mode {
            None => buf.push(0),
            Some(mode) => {
                buf.push(1);
                put_u32(buf, mode);
            }
        }
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
        // `self.xattrs` is required to already be sorted by name -- this
        // encoding trusts that invariant rather than re-sorting here, so
        // a caller that failed to sort would produce a version hash that
        // silently disagrees with the other capture path's for the
        // identical file, which is exactly the failure mode this field's
        // own doc comment warns about. Both `single_pass_capture.rs` and
        // `local_change.rs` sort before constructing a `FileMeta`.
        put_u32(buf, self.xattrs.len() as u32);
        for (name, value) in &self.xattrs {
            put_len_bytes(buf, name.as_bytes());
            put_len_bytes(buf, value);
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ChangeError> {
        let record_kind = record_kind_from_byte(r.u8()?)?;
        let unix_mode = match r.u8()? {
            0 => None,
            1 => {
                let mode = r.u32()?;
                if mode > REPLICATED_MODE_MASK {
                    return Err(ChangeError::Encoding(format!("unix mode {mode:#o} out of range")));
                }
                Some(mode)
            }
            other => return Err(ChangeError::Encoding(format!("bad unix mode flag {other}"))),
        };
        let mtime_unix_nanos = r.i64()?;
        let symlink_target = match r.u8()? {
            0 => None,
            1 => Some(r.len_bytes()?),
            other => return Err(ChangeError::Encoding(format!("bad symlink flag {other}"))),
        };
        let xattr_count = r.bounded_count(8, MAX_XATTRS)?;
        let mut xattrs = Vec::with_capacity(xattr_count);
        let mut previous_name: Option<Vec<u8>> = None;
        for _ in 0..xattr_count {
            let name_bytes = r.len_bytes()?;
            let value = r.len_bytes()?;
            // Sortedness is a canonical-encoding invariant, not merely a
            // house style: two logically-identical xattr sets encoded in
            // different orders would hash differently, so a decoder that
            // didn't enforce this could accept a byte string no honest
            // encoder would ever produce -- the same "no ambiguous
            // canonical form" reasoning `expect_end` already enforces
            // for trailing bytes.
            if let Some(previous) = &previous_name {
                if name_bytes.as_slice() <= previous.as_slice() {
                    return Err(ChangeError::Encoding(
                        "xattr names are not in strictly sorted order".into(),
                    ));
                }
            }
            previous_name = Some(name_bytes.clone());
            let name = String::from_utf8(name_bytes)
                .map_err(|_| ChangeError::Encoding("xattr name is not valid UTF-8".into()))?;
            // Defense against a signed-but-untrusted `FileVersion`: every
            // capture path this codebase has (`single_pass_capture.rs`/
            // `local_change.rs`, and every platform's own read filter in
            // `yadorilink-local-storage::chunker`) already restricts what
            // it PRODUCES to this same allow-list, but decode is the one
            // place that constrains what this device will ever ACCEPT --
            // an authorized peer is still untrusted content, so a
            // hand-crafted `FileVersion` carrying a security-relevant
            // name (Linux `security.*`/`system.*`/`trusted.*`, or
            // anything else outside the allow-list) must never reach
            // `apply_xattrs` at all, regardless of what permissions this
            // receiving process happens to hold. `apply_xattrs` itself
            // also refuses a non-allow-listed name on the write side, as
            // a second, independent layer.
            if !name.starts_with(REPLICATED_XATTR_ALLOWED_PREFIX) {
                return Err(ChangeError::Encoding(format!(
                    "xattr name {name:?} is outside the replicated-xattr allow-list (only \
                     names starting with {REPLICATED_XATTR_ALLOWED_PREFIX:?} are ever replicated)"
                )));
            }
            xattrs.push((name, value));
        }
        Ok(FileMeta { record_kind, unix_mode, mtime_unix_nanos, symlink_target, xattrs })
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

    /// Structural validation of a `FileVersion`'s shape: the block layout,
    /// and its `record_kind`/`symlink_target` consistency.
    ///
    /// Block layout -- bounded block count always; then, for a regular
    /// file, every block is non-empty and within the chunker's ceiling,
    /// the block list is empty iff the file is empty, and the per-block
    /// sizes sum to the declared total. A symlink or directory version
    /// carries no content blocks — its `size` is metadata (e.g. the
    /// symlink's on-disk length), not a sum of block sizes — so only the
    /// "no blocks" invariant applies. Content hashes are validated
    /// elsewhere (block fetch); this is the size/shape contract a
    /// receiver relies on to derive offsets safely.
    ///
    /// `record_kind`/`symlink_target` consistency -- an independent
    /// review's finding: a `RecordKind::Symlink` version with no recorded
    /// target was previously only handled defensively, much further
    /// downstream, by the local materialize path (a policy skip, not a
    /// rejection) — nothing stopped a hand-crafted, signed version from
    /// carrying that combination in the first place. Enforced
    /// symmetrically rather than as a one-off check for the single
    /// combination already observed: `Symlink` requires `Some(target)`,
    /// and every other kind requires `None` (a `File`/`Directory` version
    /// claiming a symlink target it can never use is exactly as malformed
    /// as a targetless symlink, even though nothing has hit that specific
    /// case yet).
    fn validate_structure(&self) -> Result<(), ChangeError> {
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
        match self.meta.record_kind {
            RecordKind::Symlink => {
                if self.meta.symlink_target.is_none() {
                    return Err(ChangeError::Malformed(
                        "a symlink version must carry a recorded target".into(),
                    ));
                }
            }
            RecordKind::File | RecordKind::Directory => {
                if self.meta.symlink_target.is_some() {
                    return Err(ChangeError::Malformed(
                        "only a symlink version may carry a symlink target".into(),
                    ));
                }
            }
        }
        // A Codex CLI review's finding on the symlink_target check just
        // above: `FileMeta::xattrs`'s own doc comment already says a
        // symlink or directory is "not scanned" for xattrs (always
        // empty for those kinds on the capture side), but nothing
        // enforced it here -- and `exact_object_evidence_after_write`
        // deliberately skips xattr verification for every kind but
        // `File` (xattrs are exact-required on Linux only for `File`;
        // see `SettlementEvidence::ExactObject`'s own doc comment for
        // the full target-projection-contract model). A hand-crafted
        // Symlink/Directory version carrying nonempty `xattrs` would
        // otherwise still bake those bytes into `version_hash` while
        // nothing downstream ever verifies, applies, or even LOOKS at
        // them for those kinds -- a logical-identity claim no
        // completion proof for that path could ever actually attest to,
        // for any target.
        if matches!(self.meta.record_kind, RecordKind::Symlink | RecordKind::Directory)
            && !self.meta.xattrs.is_empty()
        {
            return Err(ChangeError::Malformed(
                "a symlink or directory version must carry no replicated extended attributes"
                    .into(),
            ));
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
    #[allow(clippy::too_many_arguments)]
    pub fn from_index_row(
        blocks: Vec<BlockInfo>,
        size: u64,
        mtime_unix_nanos: i64,
        record_kind: RecordKind,
        unix_mode: Option<u32>,
        symlink_target: Option<Vec<u8>>,
        xattrs: Vec<(String, Vec<u8>)>,
    ) -> FileVersion {
        let blocks = blocks
            .into_iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash), size: b.size })
            .collect();
        let meta = FileMeta { mtime_unix_nanos, unix_mode, symlink_target, record_kind, xattrs };
        FileVersion::new(blocks, size, meta)
    }

    /// Recomputes the hash and checks it matches the stored `version_hash`,
    /// then applies the full block-layout validation. Both the hash and the
    /// structural invariants must hold for a stored or received version.
    pub fn verify_hash(&self) -> Result<(), ChangeError> {
        if self.compute_hash() != self.version_hash {
            return Err(ChangeError::HashMismatch);
        }
        self.validate_structure()
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
        version.validate_structure()?;
        Ok(version)
    }
}

#[cfg(test)]
mod file_meta_decode_tests {
    use super::*;

    /// Hand-builds a canonical `FileMeta` encoding directly (rather than
    /// going through `FileMeta`'s own encoder, which cannot be asked to
    /// produce an invalid xattr name in the first place) -- `record_kind`
    /// (`RecordKind::File` = 0), no unix mode, a fixed mtime, no symlink
    /// target, then the xattr list exactly as `FileMeta::decode` expects
    /// it: a `u32` count followed by `(name, value)` length-prefixed
    /// pairs.
    fn encode_file_meta_bytes_with_xattrs(xattrs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0u8);
        buf.push(0u8);
        put_i64(&mut buf, 0);
        buf.push(0u8);
        put_u32(&mut buf, xattrs.len() as u32);
        for (name, value) in xattrs {
            put_len_bytes(&mut buf, name.as_bytes());
            put_len_bytes(&mut buf, value);
        }
        buf
    }

    #[test]
    fn decode_accepts_an_allow_listed_xattr_name() {
        let bytes = encode_file_meta_bytes_with_xattrs(&[("user.a", b"1")]);
        let meta = FileMeta::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(meta.xattrs, vec![("user.a".to_string(), b"1".to_vec())]);
    }

    /// Regression for an independent review's finding: this device's own
    /// capture paths and every platform's apply-side filter in
    /// `yadorilink-local-storage::chunker` already restrict xattr
    /// replication to the `user.` namespace, but nothing stopped a
    /// hand-crafted `FileVersion` from a fully authorized-but-untrusted
    /// peer from carrying a security-relevant name
    /// (`security.*`/`system.*`/`trusted.*` on Linux) straight through
    /// decode and on into `apply_xattrs`. Confirmed genuinely RED by
    /// temporarily removing the allow-list check from `decode`: this call
    /// succeeded instead of being rejected.
    #[test]
    fn decode_rejects_a_non_allow_listed_xattr_name() {
        let bytes = encode_file_meta_bytes_with_xattrs(&[("security.selinux", b"x")]);
        let err = FileMeta::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, ChangeError::Encoding(_)), "got {err:?}");
    }

    /// A mixed list where only the second entry is outside the allow-list
    /// must still be rejected -- the check must not be skippable by
    /// hiding a bad name behind a good one earlier in sort order.
    #[test]
    fn decode_rejects_a_non_allow_listed_xattr_name_mixed_with_an_allowed_one() {
        let bytes = encode_file_meta_bytes_with_xattrs(&[("user.a", b"1"), ("z.trusted", b"x")]);
        let err = FileMeta::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, ChangeError::Encoding(_)), "got {err:?}");
    }
}

#[cfg(test)]
mod record_kind_symlink_target_consistency_tests {
    use super::*;

    fn meta(record_kind: RecordKind, symlink_target: Option<Vec<u8>>) -> FileMeta {
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target,
            record_kind,
            xattrs: Vec::new(),
        }
    }

    #[test]
    fn a_symlink_with_a_recorded_target_is_valid() {
        FileVersion::new(vec![], 0, meta(RecordKind::Symlink, Some(b"target".to_vec())))
            .verify_hash()
            .unwrap();
    }

    #[test]
    fn a_file_and_a_directory_with_no_target_are_valid() {
        FileVersion::new(vec![], 0, meta(RecordKind::File, None)).verify_hash().unwrap();
        FileVersion::new(vec![], 0, meta(RecordKind::Directory, None)).verify_hash().unwrap();
    }

    /// Regression for an independent review's finding: a hand-crafted,
    /// validly-signed `Symlink` version with no recorded target was
    /// previously only ever handled defensively, much further
    /// downstream, by the local materialize path (a policy skip, not a
    /// rejection) -- nothing at the wire-decode/admission boundary
    /// stopped it in the first place. Confirmed genuinely RED by
    /// temporarily removing this specific check from `validate_structure`
    /// (leaving the symmetric `File`/`Directory` checks in place): this
    /// version verified successfully instead of being rejected.
    #[test]
    fn a_symlink_with_no_recorded_target_is_rejected() {
        let err =
            FileVersion::new(vec![], 0, meta(RecordKind::Symlink, None)).verify_hash().unwrap_err();
        assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
    }

    /// The symmetric case the review specifically asked not to skip: a
    /// `File`/`Directory` version claiming a symlink target it can never
    /// use is exactly as malformed as a targetless symlink, even though
    /// no real capture path produces this today.
    #[test]
    fn a_file_or_directory_with_a_symlink_target_is_rejected() {
        let err = FileVersion::new(vec![], 0, meta(RecordKind::File, Some(b"target".to_vec())))
            .verify_hash()
            .unwrap_err();
        assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

        let err =
            FileVersion::new(vec![], 0, meta(RecordKind::Directory, Some(b"target".to_vec())))
                .verify_hash()
                .unwrap_err();
        assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
    }

    /// Regression for a Codex CLI review's finding: `FileMeta::xattrs`'s
    /// own doc comment already says a symlink or directory is "not
    /// scanned" for xattrs, but nothing enforced it -- a hand-crafted
    /// Symlink/Directory version carrying nonempty `xattrs` baked them
    /// into `version_hash` while no completion proof for that path ever
    /// verifies, applies, or even looks at them for those kinds.
    /// Confirmed genuinely RED by temporarily removing this specific
    /// check from `validate_structure` (leaving every other check in
    /// place): both versions below verified successfully instead of
    /// being rejected.
    #[test]
    fn a_symlink_or_directory_with_nonempty_xattrs_is_rejected() {
        let xattrs = vec![("user.a".to_string(), b"1".to_vec())];

        let mut symlink_meta = meta(RecordKind::Symlink, Some(b"target".to_vec()));
        symlink_meta.xattrs = xattrs.clone();
        let err = FileVersion::new(vec![], 0, symlink_meta).verify_hash().unwrap_err();
        assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");

        let mut directory_meta = meta(RecordKind::Directory, None);
        directory_meta.xattrs = xattrs;
        let err = FileVersion::new(vec![], 0, directory_meta).verify_hash().unwrap_err();
        assert!(matches!(err, ChangeError::Malformed(_)), "got {err:?}");
    }
}
