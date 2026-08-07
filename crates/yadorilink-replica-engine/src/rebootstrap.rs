//! R3.3 re-bootstrap protocol core.
//!
//! This module deliberately stops short of turning compaction scheduling on.
//! It provides the safety-critical objects and transition contract the wire
//! layer must use first: a deterministic `HistoryBase`, a signed snapshot
//! manifest, a signed `RebootstrapRequired` response bound to the exact hash a
//! returning peer requested, verification, and a single atomic installer seam.
//! Until the daemon wires snapshot transfer/install and DST covers that whole
//! transition, compaction scheduling remains disabled by design.
//!
//! # Move note (7D-9D)
//!
//! Moved verbatim out of `yadorilink-sync-core`, together with
//! [`crate::compaction`] in the same commit — see that module's own "move
//! note" for why the two-way reference between them is not a real
//! crate-dependency cycle (neither module ever touches `rusqlite`/
//! `Connection`; both are pure/generic over `crate::compaction`'s store
//! traits) and resolves cleanly once both land on this one crate together.

use std::collections::HashSet;

use ed25519_dalek::SigningKey;

#[cfg(test)]
use crate::compaction::Checkpoint;
use crate::compaction::CompactionStore;
use crate::error::ReplicaEngineError;
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};

// `HistoryBase`/`RebootstrapTrust`/`SnapshotManifest`/`RebootstrapRequired`
// moved to `yadorilink_replica_domain::rebootstrap` in Phase 7D-6 (pure
// sign/verify/encode/decode objects, needed directly by
// `yadorilink-peer-session` production code). What stays here needs
// `CompactionStore`, a SQL-backed capability this crate's own `SyncState`
// implements -- that coupling is why these functions did NOT move too.
pub use yadorilink_replica_domain::rebootstrap::{
    HistoryBase, RebootstrapRequired, RebootstrapTrust, SnapshotManifest,
};

/// Returns whether `head` is the checkpoint frontier itself or a retained
/// descendant of at least one checkpoint-frontier hash. A re-bootstrap manifest
/// must never sign an unrelated current head as a catch-up target under this
/// checkpoint's `HistoryBase`.
fn head_descends_from_checkpoint<S: CompactionStore>(
    store: &S,
    group: &FolderGroupId,
    checkpoint_frontier: &[ChangeHash],
    head: &ChangeHash,
) -> Result<bool, ReplicaEngineError> {
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
) -> Result<Option<RebootstrapRequired>, ReplicaEngineError> {
    if !store.was_pruned(group, requested_hash)? {
        return Ok(None);
    }
    let checkpoint = store.latest_checkpoint(group)?.ok_or_else(|| {
        ReplicaEngineError::CorruptState(format!(
            "change {} is attested as pruned for group {} but no checkpoint exists",
            requested_hash.to_hex(),
            group.as_str()
        ))
    })?;
    if checkpoint.group_id != *group {
        return Err(ReplicaEngineError::CorruptState(format!(
            "re-bootstrap checkpoint belongs to group {}, requested group {}",
            checkpoint.group_id.as_str(),
            group.as_str()
        )));
    }
    if checkpoint.frontier.is_empty() {
        return Err(ReplicaEngineError::CorruptState(
            "cannot build re-bootstrap manifest from an empty checkpoint frontier".into(),
        ));
    }
    let current_heads = store.heads(group)?;
    if current_heads.is_empty() {
        return Err(ReplicaEngineError::CorruptState(
            "cannot build re-bootstrap manifest for a pruned group with no retained heads".into(),
        ));
    }
    for head in &current_heads {
        if !head_descends_from_checkpoint(store, group, &checkpoint.frontier, head)? {
            return Err(ReplicaEngineError::CorruptState(format!(
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
    ) -> Result<(), ReplicaEngineError>;
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
) -> Result<(), ReplicaEngineError>
where
    I: AtomicRebootstrapInstaller + ?Sized,
    T: RebootstrapTrust + ?Sized,
    F: FnOnce(&SnapshotManifest, &[u8]) -> Result<(), ReplicaEngineError>,
{
    required.verify(trust)?;
    verify_snapshot(&required.manifest, snapshot_bytes)?;
    installer.install_snapshot_and_switch_history_base(&required.manifest, snapshot_bytes)
}

/// Explicit release gate. The protocol core exists, but compaction scheduling
/// must remain disabled until a production `AtomicRebootstrapInstaller`, wire
/// transport, and deterministic partition/restart coverage are wired.
pub const COMPACTION_SCHEDULING_READY: bool = false;

#[cfg(test)]
mod tests;
