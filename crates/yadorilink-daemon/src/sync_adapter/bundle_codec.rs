//! The wire representation of a proof-carrying Change bundle.
//!
//! A bundle is self-contained by design: everything a receiver needs to
//! verify it offline, carried with it. Nothing in it is looked up from the
//! receiver's own state, and nothing in it identifies a carrier, which is
//! what makes the path a bundle travelled irrelevant to whether it is
//! accepted.
//!
//! The encoding is explicit and length-prefixed throughout. Every declared
//! length is checked against what is actually present before it is believed —
//! these bytes come from a peer that may be adversarial, so a length is a
//! claim, not an instruction.

use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::limits::{MAX_BLOCKS, MAX_OPS};
use yadorilink_sync_sqlite::verified_change_store::{VerifiedChangeBundle, VerifiedCheckpoint};

/// Bumped if the layout below changes. Version 2 added the carried file
/// versions.
const BUNDLE_VERSION: u8 = 2;

/// Ceilings, applied before allocation. Generous against real values and
/// still far below anything that could exhaust memory.
const MAX_CHANGE_BYTES: usize = 8 << 20;
const MAX_CHECKPOINT_BYTES: usize = 64 << 10;
const MAX_PROOF_BYTES: usize = 64 << 10;
const MAX_GROUP_BYTES: usize = 512;
const MAX_DEVICE_BYTES: usize = 512;
const SIGNATURE_BYTES: usize = 64;

/// How many file versions one bundle may carry.
///
/// Derived rather than chosen. A Change refers to at most one version per op,
/// and the domain caps ops at `MAX_OPS`, so a limit below this one would
/// refuse a Change the domain considers valid — the encoder would be the
/// thing deciding what history is expressible.
const MAX_VERSIONS: usize = MAX_OPS;

/// The largest canonical encoding a domain-valid `FileVersion` can have.
///
/// Also derived: `MAX_BLOCKS` entries of a 4-byte length prefix, a 32-byte
/// block hash and a 4-byte size, plus a generous allowance for the domain
/// tag, size, and metadata (which is itself bounded by `MAX_XATTRS`). Same
/// reasoning as above — the codec must not be tighter than the domain.
const MAX_VERSION_BYTES: usize = MAX_BLOCKS * (4 + 32 + 4) + (1 << 20);

/// The ceilings this encoding applies, exposed so a test can check them
/// against the domain's rather than restating them.
pub fn max_versions() -> usize {
    MAX_VERSIONS
}

pub fn max_version_bytes() -> usize {
    MAX_VERSION_BYTES
}

/// Whether one file version's canonical encoding fits.
pub fn check_version_size(len: usize) -> Result<(), BundleCodecError> {
    check("file version", len, MAX_VERSION_BYTES)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BundleCodecError {
    #[error("bundle claims {needed} more bytes but only {available} are present")]
    Truncated { needed: usize, available: usize },

    #[error("bundle declares version {0}, this node encodes version {BUNDLE_VERSION}")]
    UnsupportedVersion(u8),

    #[error("{field} declares {declared} bytes, limit is {limit}")]
    FieldTooLarge { field: &'static str, declared: usize, limit: usize },

    #[error("{field} is not valid UTF-8")]
    NotUtf8 { field: &'static str },

    #[error("{0} unread bytes after the bundle")]
    TrailingBytes(usize),

    #[error("the encoded change does not decode: {0}")]
    UndecodableChange(String),

    #[error("the bundle's bytes hash to a different change than it claims")]
    HashMismatch,

    #[error("bundle declares {declared} file versions, limit is {MAX_VERSIONS}")]
    TooManyVersions { declared: usize },

    #[error("a carried file version does not decode: {0}")]
    UndecodableVersion(String),
}

/// Encode a bundle for the wire.
pub fn encode(bundle: &VerifiedChangeBundle) -> Result<Vec<u8>, BundleCodecError> {
    check("change", bundle.encoded.len(), MAX_CHANGE_BYTES)?;
    check("checkpoint", bundle.checkpoint.encoded.len(), MAX_CHECKPOINT_BYTES)?;
    check("merkle proof", bundle.merkle_proof.len(), MAX_PROOF_BYTES)?;
    check("group id", bundle.checkpoint.group_id.as_str().len(), MAX_GROUP_BYTES)?;
    check("device id", bundle.checkpoint.device_id.len(), MAX_DEVICE_BYTES)?;
    if bundle.checkpoint.signature.len() != SIGNATURE_BYTES {
        return Err(BundleCodecError::FieldTooLarge {
            field: "checkpoint signature",
            declared: bundle.checkpoint.signature.len(),
            limit: SIGNATURE_BYTES,
        });
    }

    let mut out = Vec::new();
    out.push(BUNDLE_VERSION);
    put_bytes(&mut out, &bundle.encoded);
    out.extend_from_slice(&bundle.checkpoint.checkpoint_hash);
    put_str(&mut out, bundle.checkpoint.group_id.as_str());
    put_str(&mut out, &bundle.checkpoint.device_id);
    out.extend_from_slice(&bundle.checkpoint.checkpoint_seq.to_be_bytes());
    put_bytes(&mut out, &bundle.checkpoint.encoded);
    out.extend_from_slice(&bundle.checkpoint.signature);
    out.extend_from_slice(&bundle.checkpoint.author_signing_public_key);
    put_bytes(&mut out, &bundle.merkle_proof);

    if bundle.versions.len() > MAX_VERSIONS {
        return Err(BundleCodecError::TooManyVersions { declared: bundle.versions.len() });
    }
    out.extend_from_slice(&(bundle.versions.len() as u32).to_be_bytes());
    for version in &bundle.versions {
        // The canonical encoding, which is what the version hash is taken
        // over. Sending anything else would let a receiver store bytes whose
        // identity it could not re-derive. `version_hash` itself is not sent:
        // it is recomputed on the far side, so there is no claimed identity
        // to disagree with the content.
        let encoded = version.canonical_encoding();
        check("file version", encoded.len(), MAX_VERSION_BYTES)?;
        put_bytes(&mut out, &encoded);
    }

    Ok(out)
}

/// Decode a bundle received from a peer.
///
/// This checks only that the bytes are well-formed and internally consistent —
/// in particular that the Change's own hash really is the hash of the bytes
/// carried. It performs no cryptographic verification whatsoever; that is
/// [`super::verify`]'s job, and keeping the two apart is what makes each
/// independently testable.
pub fn decode(bytes: &[u8]) -> Result<VerifiedChangeBundle, BundleCodecError> {
    let mut cursor = Cursor { bytes, at: 0 };

    let version = cursor.u8()?;
    if version != BUNDLE_VERSION {
        return Err(BundleCodecError::UnsupportedVersion(version));
    }

    let encoded = cursor.bytes_field("change", MAX_CHANGE_BYTES)?.to_vec();
    let checkpoint_hash = cursor.array32()?;
    let group_id = cursor.str_field("group id", MAX_GROUP_BYTES)?;
    let device_id = cursor.str_field("device id", MAX_DEVICE_BYTES)?;
    let checkpoint_seq = cursor.u64()?;
    let checkpoint_encoded = cursor.bytes_field("checkpoint", MAX_CHECKPOINT_BYTES)?.to_vec();
    let signature = cursor.take(SIGNATURE_BYTES)?.to_vec();
    let author_signing_public_key = cursor.array32()?;
    let merkle_proof = cursor.bytes_field("merkle proof", MAX_PROOF_BYTES)?.to_vec();

    // The declared count is a claim like any other length: it is checked
    // against the ceiling, and then against what is actually here, before a
    // single element is reserved. A peer claiming 65,536 versions in a
    // 200-byte frame allocates nothing.
    let declared_versions = cursor.u32()? as usize;
    if declared_versions > MAX_VERSIONS {
        return Err(BundleCodecError::TooManyVersions { declared: declared_versions });
    }
    // Each version is at minimum a 4-byte length prefix.
    let remaining = bytes.len() - cursor.at;
    if declared_versions * 4 > remaining {
        return Err(BundleCodecError::Truncated {
            needed: declared_versions * 4,
            available: remaining,
        });
    }
    let mut versions = Vec::with_capacity(declared_versions);
    for _ in 0..declared_versions {
        let encoded = cursor.bytes_field("file version", MAX_VERSION_BYTES)?;
        // `from_canonical_encoding` is the bounded decoder: it caps the block
        // count against the bytes actually present, recomputes the version
        // hash from the content rather than trusting a carried one, and
        // applies the full structural contract (block sizes summing to the
        // declared size, symlink/target consistency, xattr rules).
        versions.push(
            FileVersion::from_canonical_encoding(encoded)
                .map_err(|error| BundleCodecError::UndecodableVersion(error.to_string()))?,
        );
    }

    if cursor.at != bytes.len() {
        return Err(BundleCodecError::TrailingBytes(bytes.len() - cursor.at));
    }

    let change = Change::from_wire_bytes(&encoded)
        .map_err(|error| BundleCodecError::UndecodableChange(error.to_string()))?;

    Ok(VerifiedChangeBundle {
        encoded,
        change,
        checkpoint: VerifiedCheckpoint {
            checkpoint_hash,
            group_id: FolderGroupId(group_id),
            device_id,
            checkpoint_seq,
            encoded: checkpoint_encoded,
            signature,
            author_signing_public_key,
        },
        merkle_proof,
        versions,
    })
}

fn check(field: &'static str, len: usize, limit: usize) -> Result<(), BundleCodecError> {
    if len > limit {
        return Err(BundleCodecError::FieldTooLarge { field, declared: len, limit });
    }
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, text: &str) {
    put_bytes(out, text.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], BundleCodecError> {
        let available = self.bytes.len() - self.at;
        if available < count {
            return Err(BundleCodecError::Truncated { needed: count, available });
        }
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BundleCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BundleCodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn u64(&mut self) -> Result<u64, BundleCodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    fn array32(&mut self) -> Result<[u8; 32], BundleCodecError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// A length-prefixed field. The declared length is checked against the
    /// field's ceiling first and against the bytes actually present second,
    /// so neither an oversized claim nor a short buffer causes an allocation.
    fn bytes_field(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> Result<&'a [u8], BundleCodecError> {
        let declared = self.u32()? as usize;
        check(field, declared, limit)?;
        self.take(declared)
    }

    fn str_field(&mut self, field: &'static str, limit: usize) -> Result<String, BundleCodecError> {
        let bytes = self.bytes_field(field, limit)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| BundleCodecError::NotUtf8 { field })
    }
}
