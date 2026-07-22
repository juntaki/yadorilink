//! History compaction policy for the change DAG.
//!
//! The planner is conservative: a change is prunable only when every enrolled
//! device's acknowledged frontier dominates it. A committed prune replaces the
//! deleted prefix with a checkpoint. Re-bootstrap is intentionally stricter:
//! mere absence from the local store is never proof that a hash was pruned.
//! An offline device can legitimately return with a new hash this replica has
//! never seen, so unknown and locally-pruned identities remain distinct.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::change::{ChangeHash, DeviceId, FolderGroupId};
use crate::SyncError;

// --- Store trait surface ----------------------------------------------------

/// Read access to the retained DAG structure used by compaction.
pub trait CompactionDagStore {
    fn heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, SyncError>;

    fn parents(
        &self,
        group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<Vec<ChangeHash>, SyncError>;

    fn contains_change(
        &self,
        group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<bool, SyncError>;

    /// Exact local attestation that this replica itself intentionally pruned
    /// `change` in a committed checkpoint transaction.
    ///
    /// The default is deliberately `false`: implementations that have not yet
    /// wired their prune-proof store must fail closed. Treating an unknown hash
    /// as pruned is unsafe because it may be a legitimate offline-created head
    /// this replica has never observed.
    fn was_pruned(&self, _group: &FolderGroupId, _change: &ChangeHash) -> Result<bool, SyncError> {
        Ok(false)
    }
}

/// Persistence for each device's most recently acknowledged frontier.
pub trait DeviceFrontierStore {
    fn set_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), SyncError>;

    fn get_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<Vec<ChangeHash>, SyncError>;

    fn remove_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &DeviceId,
    ) -> Result<(), SyncError>;
}

/// Persistence for checkpoints and atomic prefix deletion.
pub trait CheckpointStore {
    fn latest_checkpoint(&self, group: &FolderGroupId) -> Result<Option<Checkpoint>, SyncError>;

    fn commit_prune(&self, checkpoint: &Checkpoint, pruned: &[ChangeHash])
        -> Result<(), SyncError>;

    /// The checkpoint hash that immediately preceded this store's own
    /// *current* HistoryBase for `group` — `None` if this store has never
    /// crossed a compaction/re-bootstrap boundary (its current checkpoint,
    /// if any, is the group's genesis). Embedded into every
    /// `SnapshotManifest` this store signs for the group as a signed
    /// hash-chain link, so a receiver can verify genuine one-hop forward
    /// continuity rather than trusting a bare counter. See
    /// `SnapshotManifest::previous_checkpoint_hash`'s doc comment.
    fn history_base_previous_checkpoint_hash(
        &self,
        group: &FolderGroupId,
    ) -> Result<Option<[u8; 32]>, SyncError>;
}

pub trait CompactionStore: CompactionDagStore + DeviceFrontierStore + CheckpointStore {}
impl<T: CompactionDagStore + DeviceFrontierStore + CheckpointStore> CompactionStore for T {}

// --- Checkpoint record ------------------------------------------------------

const CHECKPOINT_DOMAIN_TAG: &[u8; 8] = b"YLNKckp\x01";

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
    pub fn new(
        group_id: FolderGroupId,
        mut frontier: Vec<ChangeHash>,
        snapshot_hash: [u8; 32],
    ) -> Self {
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

    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
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

const MAX_FRONTIER: usize = 1024;

pub const CHECKPOINT_TABLE_MIGRATION: &str = "\
CREATE TABLE IF NOT EXISTS change_checkpoints (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot_hash   BLOB NOT NULL,
    encoded         BLOB NOT NULL,
    seq             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_checkpoints_group
    ON change_checkpoints(group_id, seq);
";

// --- Frontier bookkeeping --------------------------------------------------

pub fn record_acknowledged_frontier<S: DeviceFrontierStore>(
    store: &S,
    group: &FolderGroupId,
    device: &DeviceId,
    frontier: &[ChangeHash],
) -> Result<(), SyncError> {
    let mut normalized = frontier.to_vec();
    normalized.sort();
    normalized.dedup();
    store.set_device_frontier(group, device, &normalized)
}

fn ancestor_closure<S: CompactionDagStore>(
    store: &S,
    group: &FolderGroupId,
    frontier: &[ChangeHash],
) -> Result<HashSet<ChangeHash>, SyncError> {
    let mut seen = HashSet::new();
    let mut stack = frontier.to_vec();
    while let Some(hash) = stack.pop() {
        if !seen.insert(hash) {
            continue;
        }
        for parent in store.parents(group, &hash)? {
            if !seen.contains(&parent) {
                stack.push(parent);
            }
        }
    }
    Ok(seen)
}

pub fn frontier_dominates<S: CompactionDagStore>(
    store: &S,
    group: &FolderGroupId,
    frontier: &[ChangeHash],
    change: &ChangeHash,
) -> Result<bool, SyncError> {
    Ok(ancestor_closure(store, group, frontier)?.contains(change))
}

pub fn is_prunable<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    enrolled: &[DeviceId],
    change: &ChangeHash,
) -> Result<bool, SyncError> {
    if enrolled.is_empty() {
        return Ok(false);
    }
    for device in enrolled {
        let frontier = store.get_device_frontier(group, device)?;
        if frontier.is_empty() || !frontier_dominates(store, group, &frontier, change)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// --- Prune planning and execution -----------------------------------------

#[derive(Clone, Debug)]
pub struct PrunePlan {
    pub group_id: FolderGroupId,
    pub checkpoint_frontier: Vec<ChangeHash>,
    pub pruned: Vec<ChangeHash>,
    pub blocking_devices: Vec<DeviceId>,
}

impl PrunePlan {
    pub fn is_empty(&self) -> bool {
        self.pruned.is_empty()
    }

    fn nothing(group: &FolderGroupId, blocking_devices: Vec<DeviceId>) -> Self {
        Self {
            group_id: group.clone(),
            checkpoint_frontier: Vec::new(),
            pruned: Vec::new(),
            blocking_devices,
        }
    }
}

pub fn plan_prune<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    enrolled: &[DeviceId],
) -> Result<PrunePlan, SyncError> {
    if enrolled.is_empty() {
        return Ok(PrunePlan::nothing(group, Vec::new()));
    }

    let mut blocking_devices = Vec::new();
    let mut closures = Vec::with_capacity(enrolled.len());
    for device in enrolled {
        let frontier = store.get_device_frontier(group, device)?;
        if frontier.is_empty() {
            blocking_devices.push(device.clone());
        }
        closures.push(ancestor_closure(store, group, &frontier)?);
    }
    if !blocking_devices.is_empty() {
        return Ok(PrunePlan::nothing(group, blocking_devices));
    }

    let heads = store.heads(group)?;
    let reachable = ancestor_closure(store, group, &heads)?;
    let mut prunable = reachable.clone();
    for closure in &closures {
        prunable.retain(|hash| closure.contains(hash));
    }
    if prunable.is_empty() {
        return Ok(PrunePlan::nothing(group, Vec::new()));
    }

    let mut children: HashMap<ChangeHash, Vec<ChangeHash>> = HashMap::new();
    for change in &reachable {
        for parent in store.parents(group, change)? {
            children.entry(parent).or_default().push(*change);
        }
    }

    let mut checkpoint_frontier = Vec::new();
    let mut pruned = Vec::new();
    for change in &prunable {
        let is_maximal =
            children.get(change).is_none_or(|kids| !kids.iter().any(|kid| prunable.contains(kid)));
        if is_maximal {
            checkpoint_frontier.push(*change);
        } else {
            pruned.push(*change);
        }
    }
    checkpoint_frontier.sort();
    pruned.sort();

    Ok(PrunePlan {
        group_id: group.clone(),
        checkpoint_frontier,
        pruned,
        blocking_devices: Vec::new(),
    })
}

/// The mutation primitive behind compaction. Kept private so production callers
/// cannot bypass the R3.3 release gate; unit tests in this module exercise it
/// directly to keep planner/checkpoint behavior covered while scheduling is off.
fn execute_prune_unchecked<S: CompactionStore>(
    store: &S,
    plan: &PrunePlan,
    snapshot_hash: [u8; 32],
) -> Result<Option<Checkpoint>, SyncError> {
    if plan.pruned.is_empty() {
        return Ok(None);
    }
    let checkpoint =
        Checkpoint::new(plan.group_id.clone(), plan.checkpoint_frontier.clone(), snapshot_hash);
    store.commit_prune(&checkpoint, &plan.pruned)?;
    Ok(Some(checkpoint))
}

/// Executes a planned prune only after the complete R3.3 re-bootstrap pipeline
/// is production-ready. The readiness constant is deliberately false until
/// persisted `HistoryBase`, a production atomic snapshot installer, wire
/// negotiation/transfer, and partition+crash DST all exist. Keeping this guard
/// at the public mutation boundary means an accidental direct caller cannot turn
/// on destructive compaction merely by bypassing a scheduler that was supposed
/// to remain disabled.
pub fn execute_prune<S: CompactionStore>(
    store: &S,
    plan: &PrunePlan,
    snapshot_hash: [u8; 32],
) -> Result<Option<Checkpoint>, SyncError> {
    if plan.pruned.is_empty() {
        return Ok(None);
    }
    if !crate::rebootstrap::COMPACTION_SCHEDULING_READY {
        return Err(SyncError::CorruptState(
            "history compaction execution is disabled until the R3.3 re-bootstrap pipeline is production-ready"
                .into(),
        ));
    }
    execute_prune_unchecked(store, plan, snapshot_hash)
}

// --- Device removal --------------------------------------------------------

pub fn on_device_removed<S: DeviceFrontierStore>(
    store: &S,
    group: &FolderGroupId,
    device: &DeviceId,
) -> Result<(), SyncError> {
    store.remove_device_frontier(group, device)
}

pub fn replan_after_removal<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    removed: &DeviceId,
    remaining_enrolled: &[DeviceId],
) -> Result<PrunePlan, SyncError> {
    on_device_removed(store, group, removed)?;
    plan_prune(store, group, remaining_enrolled)
}

// --- Re-bootstrap classification ------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointSupersession {
    /// Exact checkpoint-frontier identity or an exact local prune attestation.
    SupersededByCheckpoint,
    /// The change body is still retained locally.
    StillPresent,
    /// No checkpoint exists for the group.
    NoCheckpoint,
    /// The hash is neither retained nor locally attested as pruned. It may be a
    /// legitimate offline-created change and must never be treated as compacted
    /// merely because this replica has not seen it.
    Unknown,
}

/// Classifies a hash against the local checkpoint/prune evidence.
///
/// Absence is deliberately not evidence. Until a concrete store overrides
/// [`CompactionDagStore::was_pruned`] with its exact prune-proof index, an
/// arbitrary missing hash returns [`CheckpointSupersession::Unknown`].
pub fn checkpoint_supersedes<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    change: &ChangeHash,
) -> Result<CheckpointSupersession, SyncError> {
    let checkpoint = match store.latest_checkpoint(group)? {
        Some(checkpoint) => checkpoint,
        None => return Ok(CheckpointSupersession::NoCheckpoint),
    };
    if checkpoint.frontier.contains(change) {
        return Ok(CheckpointSupersession::SupersededByCheckpoint);
    }
    if store.contains_change(group, change)? {
        return Ok(CheckpointSupersession::StillPresent);
    }
    if store.was_pruned(group, change)? {
        return Ok(CheckpointSupersession::SupersededByCheckpoint);
    }
    Ok(CheckpointSupersession::Unknown)
}

#[derive(Clone, Debug)]
pub struct ReBootstrapPlan {
    pub checkpoint: Checkpoint,
    pub current_heads: Vec<ChangeHash>,
}

/// Builds a re-bootstrap plan only when the returning frontier contains a hash
/// this replica can exactly attest it pruned. Unknown hashes do not trigger a
/// snapshot reset: they may be new offline history and require the R3.3
/// HistoryBase/RebootstrapRequired protocol to resolve safely.
pub fn plan_rebootstrap<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    returning_frontier: &[ChangeHash],
) -> Result<Option<ReBootstrapPlan>, SyncError> {
    let mut any_pruned = false;
    for head in returning_frontier {
        if store.was_pruned(group, head)? {
            any_pruned = true;
            break;
        }
    }
    if !any_pruned {
        return Ok(None);
    }

    match store.latest_checkpoint(group)? {
        Some(checkpoint) => {
            Ok(Some(ReBootstrapPlan { checkpoint, current_heads: store.heads(group)? }))
        }
        None => Err(SyncError::CorruptState(
            "local prune attestation exists but no checkpoint is retained".into(),
        )),
    }
}

// --- Canonical encoding primitives ----------------------------------------

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_len_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_len_bytes(buf, value.as_bytes());
}

fn decode_err(message: &str) -> SyncError {
    SyncError::Chunking(format!("checkpoint decode: {message}"))
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
        String::from_utf8(bytes).map_err(|_| decode_err("group id is not valid utf-8"))
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
