//! Pure signed-object surface of the R3.3 re-bootstrap protocol: a
//! deterministic history-epoch identity ([`HistoryBase`]), a condensed
//! pruned-prefix checkpoint ([`Checkpoint`]/[`CheckpointHash`]), a signed
//! snapshot manifest ([`SnapshotManifest`]), and the signed response bound
//! to one exact requested hash ([`RebootstrapRequired`]). Moved out of
//! `yadorilink-sync-core` in Phase 7D-6: these types are pure sign/verify/
//! encode/decode objects with zero SQL dependency, needed by both
//! `yadorilink-peer-session` (`RebootstrapRequired::decode`, production
//! code) and `yadorilink-sync-core`'s own compaction/checkpoint-store
//! logic (which stays behind, still SQL-backed via `CompactionStore`).
//!
//! `head_descends_from_checkpoint` and anything else that needs
//! `CompactionStore` (a SQL-backed capability) is NOT here -- it stays in
//! `yadorilink-sync-core`'s own `rebootstrap.rs`.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::change;
use crate::codec::ChangeError;
use crate::ids::{ChangeHash, DeviceId, FolderGroupId};

const CHECKPOINT_DOMAIN_TAG: &[u8; 8] = b"YLNKckp\x01";
const HISTORY_BASE_DOMAIN: &[u8; 8] = b"YLNKhbs\x01";
const SNAPSHOT_MANIFEST_DOMAIN: &[u8; 8] = b"YLNKsmf\x01";
const REBOOTSTRAP_REQUIRED_DOMAIN: &[u8; 8] = b"YLNKrbr\x01";
const MAX_REBOOTSTRAP_HEADS: usize = 1024;
const MAX_FRONTIER: usize = 1024;

// --- Private wire codec (own copy -- matches yadorilink-sync-core's
// compaction.rs/rebootstrap.rs private Readers exactly, just returning
// ChangeError instead of SyncError so this module has no dependency back
// onto sync-core) -----------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, value: &str) {
    put_len_bytes(out, value.as_bytes());
}

fn decode_err(message: &str) -> ChangeError {
    ChangeError::Encoding(format!("rebootstrap decode: {message}"))
}

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

    fn take(&mut self, count: usize) -> Result<&'a [u8], ChangeError> {
        if self.remaining() < count {
            return Err(decode_err("unexpected end of input"));
        }
        let out = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, ChangeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], ChangeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn array64(&mut self) -> Result<[u8; 64], ChangeError> {
        Ok(self.take(64)?.try_into().unwrap())
    }

    fn bounded_count(&mut self, min_entry_size: usize, max: usize) -> Result<usize, ChangeError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(decode_err(&format!("count {count} exceeds bound {max}")));
        }
        if min_entry_size > 0 && count > self.remaining() / min_entry_size {
            return Err(decode_err(&format!(
                "count {count} exceeds the {} entries the remaining bytes can hold",
                self.remaining() / min_entry_size
            )));
        }
        Ok(count)
    }

    fn string(&mut self) -> Result<String, ChangeError> {
        let count = self.u32()? as usize;
        let bytes = self.take(count)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| ChangeError::Encoding(e.to_string()))
    }

    fn expect_end(&self) -> Result<(), ChangeError> {
        if self.remaining() != 0 {
            return Err(decode_err("trailing bytes after decode"));
        }
        Ok(())
    }
}

// --- Checkpoint --------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointHash(pub [u8; 32]);

impl CheckpointHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for CheckpointHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CheckpointHash({})", hex::encode(self.0))
    }
}

/// A condensed pruned prefix. `frontier` is canonical ascending+deduped.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    pub group_id: FolderGroupId,
    pub frontier: Vec<ChangeHash>,
    pub snapshot_hash: [u8; 32],
}

impl Checkpoint {
    pub fn new(group_id: FolderGroupId, mut frontier: Vec<ChangeHash>, snapshot_hash: [u8; 32]) -> Self {
        frontier.sort();
        frontier.dedup();
        Self { group_id, frontier, snapshot_hash }
    }

    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(CHECKPOINT_DOMAIN_TAG);
        put_str(&mut buf, self.group_id.as_str());
        put_u32(&mut buf, self.frontier.len() as u32);
        for hash in &self.frontier {
            buf.extend_from_slice(&hash.0);
        }
        buf.extend_from_slice(&self.snapshot_hash);
        buf
    }

    pub fn checkpoint_hash(&self) -> CheckpointHash {
        CheckpointHash(Sha256::digest(self.canonical_encoding()).into())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != CHECKPOINT_DOMAIN_TAG {
            return Err(decode_err("bad checkpoint domain tag"));
        }
        let group_id = FolderGroupId(reader.string()?);
        let count = reader.bounded_count(32, MAX_FRONTIER)?;
        let mut frontier = Vec::with_capacity(count);
        for _ in 0..count {
            frontier.push(ChangeHash(reader.array32()?));
        }
        if !frontier.windows(2).all(|window| window[0] < window[1]) {
            return Err(decode_err("frontier is not strictly ascending"));
        }
        let snapshot_hash = reader.array32()?;
        reader.expect_end()?;
        Ok(Self { group_id, frontier, snapshot_hash })
    }
}

/// Stable identity for the history epoch above one committed checkpoint.
/// Devices may exchange ordinary DAG changes only when they share this base.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryBase(pub [u8; 32]);

impl HistoryBase {
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(HISTORY_BASE_DOMAIN);
        hasher.update(checkpoint.checkpoint_hash().as_bytes());
        Self(hasher.finalize().into())
    }
}

/// Resolves the pinned Ed25519 key for the device identity a signed re-bootstrap
/// object names. Keeping identity resolution inside the verification API avoids
/// a caller accidentally verifying a manifest that claims `device-b` with some
/// unrelated but otherwise-valid `device-a` key.
pub trait RebootstrapTrust {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]>;
}

impl<F> RebootstrapTrust for F
where
    F: Fn(&str) -> Option<[u8; 32]>,
{
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self(device_id)
    }
}

fn manifest_verifying_key<T: RebootstrapTrust + ?Sized>(
    trust: &T,
    signer_device_id: &DeviceId,
) -> Result<VerifyingKey, ChangeError> {
    let key_bytes = trust.signing_key(signer_device_id.as_str()).ok_or_else(|| {
        ChangeError::Malformed(format!(
            "no pinned re-bootstrap signing key for manifest signer {}",
            signer_device_id.as_str()
        ))
    })?;
    change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
        ChangeError::Malformed(format!(
            "pinned re-bootstrap signing key for {} is invalid: {error}",
            signer_device_id.as_str()
        ))
    })
}

/// Signed description of the baseline a stale device must install before DAG
/// synchronization can continue. The snapshot bytes themselves travel over the
/// ordinary content path; `snapshot_hash` remains the checkpoint's opaque
/// materialized-state identity and is verified by the caller-supplied snapshot
/// verifier before the atomic install is allowed to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub group_id: FolderGroupId,
    pub history_base: HistoryBase,
    pub checkpoint: Checkpoint,
    pub current_heads: Vec<ChangeHash>,
    pub previous_checkpoint_hash: Option<[u8; 32]>,
    pub signer_device_id: DeviceId,
    pub signature: [u8; 64],
}

impl SnapshotManifest {
    pub fn new_signed(
        checkpoint: Checkpoint,
        mut current_heads: Vec<ChangeHash>,
        previous_checkpoint_hash: Option<[u8; 32]>,
        signer_device_id: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<Self, ChangeError> {
        current_heads.sort();
        current_heads.dedup();
        if current_heads.len() > MAX_REBOOTSTRAP_HEADS {
            return Err(ChangeError::Malformed(format!(
                "re-bootstrap current-head count {} exceeds {}",
                current_heads.len(),
                MAX_REBOOTSTRAP_HEADS
            )));
        }
        let mut manifest = Self {
            group_id: checkpoint.group_id.clone(),
            history_base: HistoryBase::from_checkpoint(&checkpoint),
            checkpoint,
            current_heads,
            previous_checkpoint_hash,
            signer_device_id,
            signature: [0u8; 64],
        };
        manifest.signature = signing_key.sign(&manifest.signing_bytes()).to_bytes();
        Ok(manifest)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MANIFEST_DOMAIN);
        put_str(&mut out, self.group_id.as_str());
        out.extend_from_slice(&self.history_base.0);
        let checkpoint = self.checkpoint.canonical_encoding();
        put_len_bytes(&mut out, &checkpoint);
        put_u32(&mut out, self.current_heads.len() as u32);
        for head in &self.current_heads {
            out.extend_from_slice(&head.0);
        }
        match self.previous_checkpoint_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(&hash);
            }
            None => out.push(0),
        }
        put_str(&mut out, self.signer_device_id.as_str());
        out
    }

    pub fn manifest_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes());
        hasher.update(self.signature);
        hasher.finalize().into()
    }

    fn verify_with_key(&self, verifying_key: &VerifyingKey) -> Result<(), ChangeError> {
        if self.group_id != self.checkpoint.group_id {
            return Err(ChangeError::Malformed(
                "snapshot manifest group does not match checkpoint group".into(),
            ));
        }
        if self.history_base != HistoryBase::from_checkpoint(&self.checkpoint) {
            return Err(ChangeError::Malformed(
                "snapshot manifest history base does not derive from its checkpoint".into(),
            ));
        }
        if self.checkpoint.frontier.len() > MAX_REBOOTSTRAP_HEADS
            || !self.checkpoint.frontier.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ChangeError::Malformed(
                "snapshot manifest checkpoint frontier is not canonical".into(),
            ));
        }
        if self.current_heads.len() > MAX_REBOOTSTRAP_HEADS
            || !self.current_heads.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ChangeError::Malformed(
                "snapshot manifest current heads are not canonical".into(),
            ));
        }
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifying_key.verify(&self.signing_bytes(), &signature).map_err(|_| {
            ChangeError::Malformed("snapshot manifest signature verification failed".into())
        })
    }

    pub fn verify<T: RebootstrapTrust + ?Sized>(&self, trust: &T) -> Result<(), ChangeError> {
        let verifying_key = manifest_verifying_key(trust, &self.signer_device_id)?;
        self.verify_with_key(&verifying_key)
    }

    /// Full wire encoding: `signing_bytes()` (everything but the signature)
    /// followed by the signature itself. Round trips through `decode`.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != SNAPSHOT_MANIFEST_DOMAIN {
            return Err(decode_err("bad snapshot manifest domain tag"));
        }
        let group_id = FolderGroupId(reader.string()?);
        let history_base = HistoryBase(reader.array32()?);
        let checkpoint_len = reader.u32()? as usize;
        let checkpoint = Checkpoint::decode(reader.take(checkpoint_len)?)?;
        let head_count = reader.bounded_count(32, MAX_REBOOTSTRAP_HEADS)?;
        let mut current_heads = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            current_heads.push(ChangeHash(reader.array32()?));
        }
        if !current_heads.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(decode_err("snapshot manifest current heads are not canonical"));
        }
        let previous_checkpoint_hash = match reader.take(1)?[0] {
            0 => None,
            1 => Some(reader.array32()?),
            _ => return Err(decode_err("bad previous_checkpoint_hash presence tag")),
        };
        let signer_device_id = DeviceId(reader.string()?);
        let signature = reader.array64()?;
        reader.expect_end()?;
        Ok(Self {
            group_id,
            history_base,
            checkpoint,
            current_heads,
            previous_checkpoint_hash,
            signer_device_id,
            signature,
        })
    }
}

/// Sender-authenticated response to one exact request for history that this
/// replica knows it pruned. Binding `requested_hash` to the signed manifest
/// prevents a valid snapshot response for one stale hash from being replayed as
/// proof that an arbitrary unknown/offline-created hash was also pruned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebootstrapRequired {
    pub requested_hash: ChangeHash,
    pub manifest: SnapshotManifest,
    pub signature: [u8; 64],
}

impl RebootstrapRequired {
    pub fn new_signed(
        requested_hash: ChangeHash,
        manifest: SnapshotManifest,
        signing_key: &SigningKey,
    ) -> Self {
        let mut response = Self { requested_hash, manifest, signature: [0u8; 64] };
        response.signature = signing_key.sign(&response.signing_bytes()).to_bytes();
        response
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(REBOOTSTRAP_REQUIRED_DOMAIN);
        out.extend_from_slice(&self.requested_hash.0);
        out.extend_from_slice(&self.manifest.manifest_hash());
        out
    }

    pub fn verify<T: RebootstrapTrust + ?Sized>(&self, trust: &T) -> Result<(), ChangeError> {
        let verifying_key = manifest_verifying_key(trust, &self.manifest.signer_device_id)?;
        self.manifest.verify_with_key(&verifying_key)?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifying_key.verify(&self.signing_bytes(), &signature).map_err(|_| {
            ChangeError::Malformed("RebootstrapRequired signature verification failed".into())
        })
    }

    /// Full wire encoding, needed to transport a `RebootstrapRequired` over
    /// the wire.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(REBOOTSTRAP_REQUIRED_DOMAIN);
        out.extend_from_slice(&self.requested_hash.0);
        put_len_bytes(&mut out, &self.manifest.canonical_encoding());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != REBOOTSTRAP_REQUIRED_DOMAIN {
            return Err(decode_err("bad rebootstrap-required domain tag"));
        }
        let requested_hash = ChangeHash(reader.array32()?);
        let manifest_len = reader.u32()? as usize;
        let manifest = SnapshotManifest::decode(reader.take(manifest_len)?)?;
        let signature = reader.array64()?;
        reader.expect_end()?;
        Ok(Self { requested_hash, manifest, signature })
    }
}
