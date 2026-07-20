//! R3.3 re-bootstrap protocol core.
//!
//! This module deliberately stops short of turning compaction scheduling on.
//! It provides the safety-critical objects and transition contract the wire
//! layer must use first: a deterministic `HistoryBase`, a signed snapshot
//! manifest, a signed `RebootstrapRequired` response bound to the exact hash a
//! returning peer requested, verification, and a single atomic installer seam.
//! Until the daemon wires snapshot transfer/install and DST covers that whole
//! transition, compaction scheduling remains disabled by design.

use std::collections::HashSet;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::change::{self, ChangeHash, DeviceId, FolderGroupId};
use crate::compaction::{Checkpoint, CompactionStore};
use crate::SyncError;

const HISTORY_BASE_DOMAIN: &[u8; 8] = b"YLNKhbs\x01";
const SNAPSHOT_MANIFEST_DOMAIN: &[u8; 8] = b"YLNKsmf\x01";
const REBOOTSTRAP_REQUIRED_DOMAIN: &[u8; 8] = b"YLNKrbr\x01";
const MAX_REBOOTSTRAP_HEADS: usize = 1024;

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
) -> Result<VerifyingKey, SyncError> {
    let key_bytes = trust.signing_key(signer_device_id.as_str()).ok_or_else(|| {
        SyncError::CorruptState(format!(
            "no pinned re-bootstrap signing key for manifest signer {}",
            signer_device_id.as_str()
        ))
    })?;
    change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
        SyncError::CorruptState(format!(
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
///
/// `current_heads` are signed catch-up *targets*, not the local frontier to
/// publish during snapshot installation. The atomic base switch installs the
/// checkpoint snapshot and `checkpoint.frontier`; ordinary DAG sync then walks
/// forward until these current heads are actually present locally.
///
/// `previous_checkpoint_hash` is the signer's own immediately-preceding
/// checkpoint for this group at the moment it signed this manifest (`None`
/// only for a group's very first-ever checkpoint) — signed proof that this
/// checkpoint is a genuine, direct, one-hop extension of a *specific* prior
/// HistoryBase, not merely evidence of "more local compactions than
/// someone else." `install_rebootstrap_snapshot` requires this to equal the
/// receiver's own currently-installed `checkpoint_hash` before accepting an
/// advance (or requires the incoming checkpoint to equal what's already
/// installed, an idempotent no-op).
///
/// This is deliberately a hash-chain link, not a bare counter: an earlier
/// design used a per-signer monotonic integer, but that only proves "this
/// signer has locally compacted N times," not that checkpoint N is a causal
/// descendant of any *specific* prior state — two devices' local compaction
/// counts can diverge for a perfectly causally-connected lineage (ordinary
/// incremental DAG sync never touches this counter, only compaction/install
/// do), and an unrelated fork can trivially carry a higher count. Comparing
/// hashes for exact one-hop continuity closes both gaps: a receiver more
/// than one compaction behind must catch up with successive re-bootstrap
/// rounds rather than skipping ahead in one unverified jump.
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
    ) -> Result<Self, SyncError> {
        current_heads.sort();
        current_heads.dedup();
        if current_heads.len() > MAX_REBOOTSTRAP_HEADS {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap current-head count {} exceeds {}",
                current_heads.len(), MAX_REBOOTSTRAP_HEADS
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

    fn verify_with_key(&self, verifying_key: &VerifyingKey) -> Result<(), SyncError> {
        if self.group_id != self.checkpoint.group_id {
            return Err(SyncError::CorruptState(
                "snapshot manifest group does not match checkpoint group".into(),
            ));
        }
        if self.history_base != HistoryBase::from_checkpoint(&self.checkpoint) {
            return Err(SyncError::CorruptState(
                "snapshot manifest history base does not derive from its checkpoint".into(),
            ));
        }
        if self.checkpoint.frontier.len() > MAX_REBOOTSTRAP_HEADS
            || !self.checkpoint.frontier.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SyncError::CorruptState(
                "snapshot manifest checkpoint frontier is not canonical".into(),
            ));
        }
        if self.current_heads.len() > MAX_REBOOTSTRAP_HEADS
            || !self.current_heads.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SyncError::CorruptState(
                "snapshot manifest current heads are not canonical".into(),
            ));
        }
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifying_key.verify(&self.signing_bytes(), &signature).map_err(|_| {
            SyncError::CorruptState("snapshot manifest signature verification failed".into())
        })
    }

    pub fn verify<T: RebootstrapTrust + ?Sized>(&self, trust: &T) -> Result<(), SyncError> {
        let verifying_key = manifest_verifying_key(trust, &self.signer_device_id)?;
        self.verify_with_key(&verifying_key)
    }

    /// Full wire encoding: `signing_bytes()` (everything but the signature)
    /// followed by the signature itself. Unlike `signing_bytes()`, this round
    /// trips through `decode` — needed to transport a `SnapshotManifest` over
    /// the wire (embedded inside a `RebootstrapRequired`), not just to sign it.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
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

    pub fn verify<T: RebootstrapTrust + ?Sized>(&self, trust: &T) -> Result<(), SyncError> {
        let verifying_key = manifest_verifying_key(trust, &self.manifest.signer_device_id)?;
        self.manifest.verify_with_key(&verifying_key)?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.signature);
        verifying_key.verify(&self.signing_bytes(), &signature).map_err(|_| {
            SyncError::CorruptState("RebootstrapRequired signature verification failed".into())
        })
    }

    /// Full wire encoding, needed to transport a `RebootstrapRequired` over
    /// the wire. Distinct from `signing_bytes()`, which binds only the
    /// *hash* of the manifest into what gets signed — this instead embeds the
    /// manifest's own full `canonical_encoding()` so the whole object round
    /// trips through `decode`.
    pub fn canonical_encoding(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(REBOOTSTRAP_REQUIRED_DOMAIN);
        out.extend_from_slice(&self.requested_hash.0);
        put_len_bytes(&mut out, &self.manifest.canonical_encoding());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
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

/// Returns whether `head` is the checkpoint frontier itself or a retained
/// descendant of at least one checkpoint-frontier hash. A re-bootstrap manifest
/// must never sign an unrelated current head as a catch-up target under this
/// checkpoint's `HistoryBase`.
fn head_descends_from_checkpoint<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    checkpoint_frontier: &[ChangeHash],
    head: &ChangeHash,
) -> Result<bool, SyncError> {
    if checkpoint_frontier.contains(head) {
        return Ok(true);
    }
    if !store.contains_change(group, head)? {
        return Ok(false);
    }

    let frontier: HashSet<ChangeHash> = checkpoint_frontier.iter().copied().collect();
    let mut visited = HashSet::new();
    let mut stack = vec![*head];
    while let Some(hash) = stack.pop() {
        if !visited.insert(hash) {
            continue;
        }
        for parent in store.parents(group, &hash)? {
            if frontier.contains(&parent) {
                return Ok(true);
            }
            if store.contains_change(group, &parent)? {
                stack.push(parent);
            }
        }
    }
    Ok(false)
}

/// Builds a re-bootstrap response only when the store has exact local evidence
/// that the requested hash was intentionally pruned. Mere absence returns
/// `None`, preserving the unknown-vs-pruned boundary.
pub fn prepare_rebootstrap_required<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    requested_hash: &ChangeHash,
    signer_device_id: DeviceId,
    signing_key: &SigningKey,
) -> Result<Option<RebootstrapRequired>, SyncError> {
    if !store.was_pruned(group, requested_hash)? {
        return Ok(None);
    }
    let checkpoint = store.latest_checkpoint(group)?.ok_or_else(|| {
        SyncError::CorruptState(format!(
            "change {} is attested as pruned for group {} but no checkpoint exists",
            requested_hash.to_hex(),
            group.as_str()
        ))
    })?;
    if checkpoint.group_id != *group {
        return Err(SyncError::CorruptState(format!(
            "re-bootstrap checkpoint belongs to group {}, requested group {}",
            checkpoint.group_id.as_str(),
            group.as_str()
        )));
    }
    if checkpoint.frontier.is_empty() {
        return Err(SyncError::CorruptState(
            "cannot build re-bootstrap manifest from an empty checkpoint frontier".into(),
        ));
    }
    let current_heads = store.heads(group)?;
    if current_heads.is_empty() {
        return Err(SyncError::CorruptState(
            "cannot build re-bootstrap manifest for a pruned group with no retained heads".into(),
        ));
    }
    for head in &current_heads {
        if !head_descends_from_checkpoint(store, group, &checkpoint.frontier, head)? {
            return Err(SyncError::CorruptState(format!(
                "current head {} is not descended from checkpoint frontier for group {}",
                head.to_hex(),
                group.as_str()
            )));
        }
    }
    let previous_checkpoint_hash = store.history_base_previous_checkpoint_hash(group)?;
    let manifest = SnapshotManifest::new_signed(
        checkpoint,
        current_heads,
        previous_checkpoint_hash,
        signer_device_id,
        signing_key,
    )?;
    Ok(Some(RebootstrapRequired::new_signed(*requested_hash, manifest, signing_key)))
}

/// The sole mutation seam for applying a re-bootstrap. Implementations must
/// install the verified checkpoint snapshot, replace the group's DAG baseline
/// with `history_base`, and publish `manifest.checkpoint.frontier` as the new
/// retained baseline atomically. `manifest.current_heads` remain remote catch-up
/// targets and must not be claimed locally until their Change bodies have
/// actually been fetched and admitted. A crash must expose either the old
/// base+state or the new checkpoint-base+state, never a mixture.
pub trait AtomicRebootstrapInstaller {
    fn install_snapshot_and_switch_history_base(
        &self,
        manifest: &SnapshotManifest,
        snapshot_bytes: &[u8],
    ) -> Result<(), SyncError>;
}

/// Verifies both signed protocol objects and the snapshot content before
/// allowing the one atomic state transition. The signer key is resolved from the
/// manifest's own `signer_device_id` through `trust`; callers cannot accidentally
/// supply a valid but unrelated device key. `verify_snapshot` owns the
/// materialized snapshot encoding/hash rules, which intentionally remain above
/// this protocol-core module.
pub fn verify_and_install_rebootstrap<I, T, F>(
    installer: &I,
    required: &RebootstrapRequired,
    trust: &T,
    snapshot_bytes: &[u8],
    verify_snapshot: F,
) -> Result<(), SyncError>
where
    I: AtomicRebootstrapInstaller + ?Sized,
    T: RebootstrapTrust + ?Sized,
    F: FnOnce(&SnapshotManifest, &[u8]) -> Result<(), SyncError>,
{
    required.verify(trust)?;
    verify_snapshot(&required.manifest, snapshot_bytes)?;
    installer.install_snapshot_and_switch_history_base(&required.manifest, snapshot_bytes)
}

/// Explicit release gate. The protocol core exists, but compaction scheduling
/// must remain disabled until a production `AtomicRebootstrapInstaller`, wire
/// transport, and deterministic partition/restart coverage are wired.
pub const COMPACTION_SCHEDULING_READY: bool = false;

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

fn decode_err(message: &str) -> SyncError {
    SyncError::Chunking(format!("rebootstrap decode: {message}"))
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

    fn take(&mut self, count: usize) -> Result<&'a [u8], SyncError> {
        if self.remaining() < count {
            return Err(decode_err("unexpected end of input"));
        }
        let out = &self.buf[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, SyncError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], SyncError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn array64(&mut self) -> Result<[u8; 64], SyncError> {
        Ok(self.take(64)?.try_into().unwrap())
    }

    fn bounded_count(&mut self, min_entry_size: usize, max: usize) -> Result<usize, SyncError> {
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

    fn string(&mut self) -> Result<String, SyncError> {
        let count = self.u32()? as usize;
        let bytes = self.take(count)?.to_vec();
        String::from_utf8(bytes).map_err(|_| decode_err("string is not valid utf-8"))
    }

    fn expect_end(&self) -> Result<(), SyncError> {
        if self.remaining() != 0 {
            return Err(decode_err("trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
